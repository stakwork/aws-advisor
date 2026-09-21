/**
 * This month's bill, forecast from what is running now: month to date from Cost Explorer plus the remaining
 * days priced from the inventory, the commitments and the usage run rate (src/forecast_math.ts). Computed after
 * every spend refresh and on demand; one row per day in `forecasts` so the projection has a history.
 */
import { db } from "./db.js";
import { credentialGate } from "./gate.js";
import { computeReconciliation, getReconciliation, lastFullMonth, loadMonthInput } from "./reconcile.js";
import { Forecast, ForecastInput, computeForecast } from "./forecast_math.js";
import { daysInMonth, localDay } from "./localdate.js";
import { listCommitments } from "./commitments.js";
import { refreshSupportPlan } from "./support_plan.js";

db.exec(`create table if not exists forecasts (day text primary key, month text not null, computed_at text not null, json text not null)`);

export interface ResourceChange { kind: string; id: string; name: string | null; type: string | null; monthly_usd: number | null; at: string | null }
export type StoredForecast = Forecast & { new_resources: ResourceChange[]; gone_resources: ResourceChange[]; support_plan: string };

const round2 = (n: number) => Math.round(n * 100) / 100;
export const currentMonth = (today = localDay()) => today.slice(0, 7);

/** What the inventory holds right now, as the forecast's inventory leg needs it. */
export function inventoryNow(): ForecastInput["now"] {
  const one = (sql: string) => Number((db.prepare(sql).get() as any)?.v ?? 0) || 0;
  return {
    ec2_od_hourly: round2(one("select sum(monthly_usd) / 730.0 as v from inventory_ec2 where gone = 0 and state = 'running'") ),
    ec2_running: one("select count(*) as v from inventory_ec2 where gone = 0 and state = 'running'"),
    rds_od_hourly: round2(one("select sum(monthly_usd) / 730.0 as v from inventory_rds where gone = 0")),
    cache_od_hourly: round2(one("select sum(monthly_usd) / 730.0 as v from inventory_elasticache where gone = 0")),
    ...reservedHourly(),
    ebs_month: round2(one("select sum(monthly_usd) as v from inventory_ebs where gone = 0 and state = 'in-use'")),
    s3_month: round2(one("select sum(monthly_usd) as v from inventory_s3 where gone = 0")),
    lambda_month: round2(one("select sum(monthly_usd) as v from inventory_lambda where gone = 0")),
  };
}

/** On-demand value per hour that the reservations cover, from the commitment list ("db.r7g.large x1") and the inventory's price for that type. */
export function reservedHourly(): { rds_reserved_hourly: number | null; cache_reserved_hourly: number | null } {
  const rdsUnit = new Map((db.prepare("select class, avg(monthly_usd) / 730.0 as h from inventory_rds where gone = 0 and monthly_usd is not null group by class").all() as any[]).map((r) => [r.class, Number(r.h)]));
  const cacheUnit = new Map((db.prepare("select node_type, sum(monthly_usd) / sum(num_nodes) / 730.0 as h from inventory_elasticache where gone = 0 and monthly_usd is not null group by node_type").all() as any[]).map((r) => [r.node_type, Number(r.h)]));
  let commitments: { kind: string; detail: string }[] = [];
  try { commitments = listCommitments(); } catch { return { rds_reserved_hourly: null, cache_reserved_hourly: null }; }
  let rds = 0, cache = 0, seen = false;
  for (const c of commitments) {
    const m = /^(\S+)\s+x(\d+)/.exec(c.detail || ""); if (!m) continue;
    const [, type, n] = m; seen = true;
    if (c.kind === "rds_ri") rds += (rdsUnit.get(type) ?? 0) * Number(n);
    else if (c.kind === "elasticache_ri") cache += (cacheUnit.get(type) ?? 0) * Number(n);
  }
  return seen ? { rds_reserved_hourly: round2(rds), cache_reserved_hourly: round2(cache) } : { rds_reserved_hourly: null, cache_reserved_hourly: null };
}

/** Resources that appeared or disappeared this month, so a moved forecast has names behind it. */
export function resourceChanges(month: string): { new_resources: ResourceChange[]; gone_resources: ResourceChange[] } {
  const from = `${month}-01`;
  const rows = (sql: string, ...p: unknown[]) => db.prepare(sql).all(...p) as ResourceChange[];
  const new_resources = [
    ...rows("select 'ec2' as kind, instance_id as id, name, instance_type as type, monthly_usd, launch_time as at from inventory_ec2 where gone = 0 and state = 'running' and launch_time >= ? order by monthly_usd desc", from),
    ...rows("select 'rds' as kind, db_instance_identifier as id, null as name, class as type, monthly_usd, created as at from inventory_rds where gone = 0 and created >= ? order by monthly_usd desc", from),
    ...rows("select 'elasticache' as kind, cache_cluster_id as id, null as name, node_type as type, monthly_usd, created as at from inventory_elasticache where gone = 0 and created >= ? order by monthly_usd desc", from),
  ];
  const gone_resources = [
    ...rows("select 'ec2' as kind, instance_id as id, name, instance_type as type, monthly_usd, last_seen as at from inventory_ec2 where gone = 1 and last_seen >= ? order by monthly_usd desc", from),
    ...rows("select 'rds' as kind, db_instance_identifier as id, null as name, class as type, monthly_usd, last_seen as at from inventory_rds where gone = 1 and last_seen >= ? order by monthly_usd desc", from),
    ...rows("select 'elasticache' as kind, cache_cluster_id as id, null as name, node_type as type, monthly_usd, last_seen as at from inventory_elasticache where gone = 1 and last_seen >= ? order by monthly_usd desc", from),
  ];
  return { new_resources, gone_resources };
}

/** Complete days Cost Explorer has for the month: the latest stored day before today, else yesterday. */
export function elapsedDays(month: string, today = localDay()): number {
  const last = (db.prepare("select max(day) as d from spend_daily where day < ? and day >= ?").get(today, `${month}-01`) as { d: string | null }).d;
  const fallback = Number(today.slice(8, 10)) - 1;
  return Math.max(1, last ? Number(last.slice(8, 10)) : fallback);
}

export async function runForecast(onLog: (s: string) => void = () => {}, today = localDay()): Promise<StoredForecast> {
  const gate = await credentialGate("forecast");
  if (!gate.ok) throw new Error(gate.error || "credentials not working");
  const month = currentMonth(today);
  const input = await loadMonthInput(month, onLog);
  const priced = computeReconciliation(input);
  const lastMonth = getReconciliation(lastFullMonth(new Date(`${today}T12:00:00`)));
  const rate = lastMonth ? lastMonth.totals.sp_discount_rate / 100 : input.records.sp_covered_od > 0 ? 1 - input.records.sp_fee / input.records.sp_covered_od : 0;
  const last = lastMonth ? {
    total: lastMonth.totals.actual_net,
    services: { ...Object.fromEntries(lastMonth.services.map((s) => [s.service, s.actual_net])), "Savings Plans for AWS Compute usage": lastMonth.totals.sp_fee_actual, "AWS Support": lastMonth.totals.support_actual, Tax: lastMonth.totals.tax_actual },
  } : null;
  const plan = (await refreshSupportPlan(onLog)).plan;
  const f = computeForecast({ month, elapsed_days: elapsedDays(month, today), days_in_month: daysInMonth(`${month}-01`), lines: priced.lines, records: input.records, sp_hourly: input.sp_hourly, sp_discount_rate: rate, now: inventoryNow(), support_plan: plan, last_month: last });
  const stored: StoredForecast = { ...f, ...resourceChanges(month), support_plan: plan };
  db.prepare("insert into forecasts(day, month, computed_at, json) values (?, ?, ?, ?) on conflict(day) do update set month = excluded.month, computed_at = excluded.computed_at, json = excluded.json").run(today, month, f.computed_at, JSON.stringify(stored));
  onLog(`${month}: ${f.mtd_net} so far over ${f.elapsed_days} days, on track for ${f.forecast_net}${f.last_month_total != null ? ` (last month ${f.last_month_total}, ${f.delta_pct! >= 0 ? "+" : ""}${f.delta_pct} %)` : ""}`);
  return stored;
}

export function latestForecast(): StoredForecast | null {
  const row = db.prepare("select json from forecasts order by day desc limit 1").get() as { json: string } | undefined;
  return row ? (JSON.parse(row.json) as StoredForecast) : null;
}
/** The projection's history for a month: one point per day it was computed. */
export function forecastHistory(month: string): { day: string; mtd_net: number; forecast_net: number; elapsed_days: number }[] {
  return (db.prepare("select day, json from forecasts where month = ? order by day").all(month) as { day: string; json: string }[]).map((r) => { const j = JSON.parse(r.json) as Forecast; return { day: r.day, mtd_net: j.mtd_net, forecast_net: j.forecast_net, elapsed_days: j.elapsed_days }; });
}

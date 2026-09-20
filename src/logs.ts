/**
 * CloudWatch Logs as a cost source: every log group (retention, stored bytes, class) and, for the groups that
 * matter, ingestion per day from the AWS/Logs IncomingBytes metric. Ingestion is what the bill charges
 * (0.50 USD/GB); retention is the stored GB-months (0.03 USD/GB). Refreshed daily (LOGS_CRON) and on demand;
 * the review raises a step in a group's ingestion, the brief lists the top ingesters, and the agent reads it
 * through the log_groups tool. In the graph design this is the "ships logs to" edge with its rate and price.
 */
import { db } from "./db.js";
import { S, query } from "./steampipe.js";
import { credentialGate } from "./gate.js";
import { describeError } from "./permissions.js";
import { Point, buildBaseline } from "./baseline_math.js";

db.exec(`create table if not exists log_groups (
  name text primary key, region text, retention_days integer, stored_bytes real, log_class text, created_at text,
  ingest_bytes_day real, ingest_days integer, last_seen text not null
);
create table if not exists log_ingest_daily (
  name text not null, day text not null, bytes real not null,
  primary key (name, day)
)`);

export const LOG_INGEST_PRICE = 0.50, LOG_STORAGE_PRICE = 0.03;
const INGEST_DAYS = 14;
/** Groups with at least this much stored get their per-day ingestion metric fetched (one CloudWatch call each). */
const MIN_STORED_BYTES = 200 * 1024 * 1024;
const MAX_METRIC_GROUPS = 80;
const lit = (s: string) => `'${String(s).replace(/'/g, "''")}'`;

export interface LogsRefreshResult { groups: number; metered: number; total_gb_day: number | null; errors: string[]; took_ms: number }

export async function refreshLogs(onLog: (s: string) => void = () => {}): Promise<LogsRefreshResult> {
  const t0 = Date.now();
  const out: LogsRefreshResult = { groups: 0, metered: 0, total_gb_day: null, errors: [], took_ms: 0 };
  const gate = await credentialGate("logs");
  if (!gate.ok) { out.errors.push(gate.error || "credentials not working"); out.took_ms = Date.now() - t0; return out; }
  let groups: any[] = [];
  try {
    groups = await query(`select name, region, retention_in_days, stored_bytes, log_group_class, creation_time from ${S}.aws_cloudwatch_log_group`);
  } catch (e) { out.errors.push(describeError(e, "log groups (aws_cloudwatch_log_group)")); out.took_ms = Date.now() - t0; return out; }
  const now = new Date().toISOString();
  const up = db.prepare(`insert into log_groups(name, region, retention_days, stored_bytes, log_class, created_at, last_seen) values (?, ?, ?, ?, ?, ?, ?)
    on conflict(name) do update set region = excluded.region, retention_days = excluded.retention_days, stored_bytes = excluded.stored_bytes, log_class = excluded.log_class, created_at = excluded.created_at, last_seen = excluded.last_seen`);
  for (const g of groups) { up.run(g.name, g.region, g.retention_in_days ?? null, Number(g.stored_bytes ?? 0), g.log_group_class ?? null, g.creation_time ? new Date(g.creation_time).toISOString() : null, now); out.groups++; }
  // ingestion per day: the account total (no dimension) plus the biggest groups
  const upIngest = db.prepare("insert into log_ingest_daily(name, day, bytes) values (?, ?, ?) on conflict(name, day) do update set bytes = excluded.bytes");
  const fetchDaily = async (name: string, region: string, dims: string): Promise<Point[]> => {
    const rows = await query<{ timestamp: string; value: string | null }>(`select timestamp, sum as value from ${S}.aws_cloudwatch_metric_statistic_data_point
      where namespace = 'AWS/Logs' and metric_name = 'IncomingBytes' and dimensions = ${lit(dims)} and period = 86400 and region = ${lit(region)}
        and timestamp between now() - interval '${INGEST_DAYS + 1} days' and now() order by timestamp`);
    const pts: Point[] = [];
    for (const r of rows) { if (r.value == null) continue; const day = new Date(r.timestamp).toISOString().slice(0, 10); if (day >= now.slice(0, 10)) continue; upIngest.run(name, day, Number(r.value)); pts.push({ t: new Date(r.timestamp).getTime(), v: Number(r.value) }); }
    return pts;
  };
  const regions = [...new Set(groups.map((g) => g.region).filter(Boolean))];
  for (const region of regions) {
    try { const pts = await fetchDaily(`__total__/${region}`, region, "[]"); if (pts.length) out.total_gb_day = (out.total_gb_day ?? 0) + pts.slice(-7).reduce((s, p) => s + p.v, 0) / Math.min(7, pts.length) / 1e9; }
    catch (e) { out.errors.push(describeError(e, `log ingestion total ${region} (aws_cloudwatch_metric_statistic_data_point)`)); }
  }
  const big = groups.filter((g) => Number(g.stored_bytes ?? 0) >= MIN_STORED_BYTES).sort((a, b) => Number(b.stored_bytes) - Number(a.stored_bytes)).slice(0, MAX_METRIC_GROUPS);
  const setIngest = db.prepare("update log_groups set ingest_bytes_day = ?, ingest_days = ? where name = ?");
  const upBase = db.prepare(`insert into baselines(scope_kind, scope_id, metric, window_days, source, unit, samples, days, median, mad, p95, mean, max, min, by_hour, by_dow, computed_at)
    values ('loggroup', ?, 'ingest_bytes_day', ?, 'cloudwatch', 'bytes/day', ?, ?, ?, ?, ?, ?, ?, ?, '[]', '[]', datetime('now'))
    on conflict(scope_kind, scope_id, metric) do update set samples = excluded.samples, days = excluded.days, median = excluded.median, mad = excluded.mad, p95 = excluded.p95, mean = excluded.mean, max = excluded.max, min = excluded.min, computed_at = excluded.computed_at`);
  for (const g of big) {
    try {
      const pts = await fetchDaily(g.name, g.region, JSON.stringify([{ Name: "LogGroupName", Value: g.name }]));
      if (!pts.length) continue;
      const b = buildBaseline(pts, INGEST_DAYS, "cloudwatch", "bytes/day");
      setIngest.run(b.mean, pts.length, g.name);
      const n = (x: number) => (Number.isFinite(x) ? x : null);
      upBase.run(g.name, INGEST_DAYS, b.samples, b.days, n(b.median), n(b.mad), n(b.p95), n(b.mean), n(b.max), n(b.min));
      out.metered++;
    } catch (e) { out.errors.push(describeError(e, `log ingestion ${g.name}`)); if (out.errors.length > 5) break; }
  }
  db.prepare("delete from log_ingest_daily where day < date('now', '-400 days')").run();
  out.took_ms = Date.now() - t0;
  onLog(`${out.groups} groups, ${out.metered} metered, total ${out.total_gb_day?.toFixed(1) ?? "?"} GB/day, ${out.took_ms} ms${out.errors.length ? `, errors: ${out.errors.length}` : ""}`);
  return out;
}

export interface LogGroupRow { name: string; region: string; retention_days: number | null; stored_gb: number; ingest_gb_day: number | null; ingest_usd_month: number | null; storage_usd_month: number; log_class: string | null }

/** Groups by ingestion cost then by stored size; `limit` rows. */
export function topLogGroups(limit = 25): { refreshed_at: string | null; total_gb_day: number | null; total_stored_gb: number; groups: LogGroupRow[]; no_retention: number } {
  const refreshed = (db.prepare("select max(last_seen) as t from log_groups").get() as { t: string | null }).t;
  const rows = db.prepare("select * from log_groups order by coalesce(ingest_bytes_day, 0) desc, stored_bytes desc limit ?").all(limit) as any[];
  const totals = db.prepare("select sum(stored_bytes) as stored, sum(case when retention_days is null then 1 else 0 end) as never from log_groups").get() as { stored: number | null; never: number };
  const total = db.prepare("select avg(bytes) as b from (select day, sum(bytes) as bytes from log_ingest_daily where name like '__total__/%' and day >= date('now', '-7 days') group by day)").get() as { b: number | null };
  return {
    refreshed_at: refreshed, total_gb_day: total.b != null ? total.b / 1e9 : null, total_stored_gb: (totals.stored ?? 0) / 1e9, no_retention: totals.never,
    groups: rows.map((r) => ({ name: r.name, region: r.region, retention_days: r.retention_days, stored_gb: r.stored_bytes / 1e9, log_class: r.log_class,
      ingest_gb_day: r.ingest_bytes_day != null ? r.ingest_bytes_day / 1e9 : null, ingest_usd_month: r.ingest_bytes_day != null ? (r.ingest_bytes_day / 1e9) * 30 * LOG_INGEST_PRICE : null, storage_usd_month: (r.stored_bytes / 1e9) * LOG_STORAGE_PRICE })),
  };
}

/** The last `days` of ingestion for one group, for the review's step check. */
export function recentIngest(name: string, days = 3): number[] {
  return (db.prepare("select bytes from log_ingest_daily where name = ? order by day desc limit ?").all(name, days) as { bytes: number }[]).map((r) => r.bytes).reverse();
}

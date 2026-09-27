/**
 * Cost per swarm. A swarm is one EC2 box running a customer's stack (src/actions/swarm_park.ts judges the same
 * boxes for parking), so the box's bill is the customer's bill: the instance hours while it runs, its volumes
 * whether it runs or not, the public IPv4 address (0.005 USD/h since February 2024, attached or not) and the
 * standard-tier snapshots of its volumes. Everything is at list price from the inventory, not from Cost
 * Explorer: the figure says what the box costs to keep, which is what a pricing or parking conversation needs.
 *
 * One row per swarm per day (`swarm_cost_daily`), written by the daily refresh; the month-to-date report is the
 * mean of a month's daily totals stretched to the month, with the last use and idle days from the probe's daily
 * roll-ups (src/history.ts) and whether the executor has parked the box. The "nudge" flag marks the customers
 * to ask: running, idle for the parking threshold, not parked and not about to be (no open parking proposal).
 */
import { config } from "./config.js";
import { db } from "./db.js";
import { S, query } from "./steampipe.js";

db.exec(`create table if not exists swarm_cost_daily (
  day text not null, instance_id text not null, name text, state text, instance_type text,
  compute_usd real, ebs_usd real, snapshot_usd real, ip_usd real, total_usd real,
  last_use_at text, idle_days integer, parked integer not null default 0,
  primary key (day, instance_id)
);
create index if not exists swarm_cost_daily_instance on swarm_cost_daily(instance_id, day)`);

export const SWARM_NAME = /swarm/i;
/** A public IPv4 address, attached or not (us-east-1 list). */
export const PUBLIC_IPV4_USD_MONTH = 3.65;
export const SNAPSHOT_STANDARD_USD_GB_MONTH = 0.05;

export interface SwarmCostInput {
  state: string | null;
  monthly_usd: number | null;
  ebs_usd: number | null;
  snapshot_gb: number | null;
  public_ip: string | null;
}
export interface SwarmCost { compute_usd: number; ebs_usd: number; snapshot_usd: number | null; ip_usd: number; total_usd: number }

const r2 = (n: number) => Math.round(n * 100) / 100;

/** The monthly list cost of one swarm from its inventory facts: compute only while running, storage always. Pure. */
export function swarmCost(i: SwarmCostInput): SwarmCost {
  const compute = i.state === "running" ? Number(i.monthly_usd || 0) : 0;
  const ebs = Number(i.ebs_usd || 0);
  const snapshot = i.snapshot_gb == null ? null : r2(i.snapshot_gb * SNAPSHOT_STANDARD_USD_GB_MONTH);
  const ip = i.public_ip ? PUBLIC_IPV4_USD_MONTH : 0;
  return { compute_usd: r2(compute), ebs_usd: r2(ebs), snapshot_usd: snapshot, ip_usd: ip, total_usd: r2(compute + ebs + (snapshot ?? 0) + ip) };
}

/** Whole days since the last use signal; null when there is none. Pure. */
export function idleDays(lastUseAt: string | null, now = new Date()): number | null {
  if (!lastUseAt) return null;
  const t = new Date(lastUseAt.includes("T") ? lastUseAt : lastUseAt.replace(" ", "T") + "Z").getTime();
  if (!Number.isFinite(t)) return null;
  return Math.max(0, Math.floor((now.getTime() - t) / 86400000));
}

export interface NudgeInput { state: string | null; idle_days: number | null; parked: boolean; parking_proposed: boolean; idle_threshold: number }
/** The customers to ask: the box runs, nobody has used it for the parking threshold, and the executor is not handling it. Pure. */
export function shouldNudge(n: NudgeInput): boolean {
  return n.state === "running" && n.idle_days != null && n.idle_days >= n.idle_threshold && !n.parked && !n.parking_proposed;
}

interface InventoryRow { instance_id: string; name: string | null; state: string | null; instance_type: string | null; monthly_usd: number | null; public_ip: string | null }

/** Standard-tier snapshot GB per source volume, for the volumes given; null when Steampipe cannot answer. */
async function snapshotGbByVolume(volumeIds: string[]): Promise<Map<string, number> | null> {
  if (!volumeIds.length) return new Map();
  try {
    const lit = (s: string) => `'${s.replace(/'/g, "''")}'`;
    const rows = await query<{ volume_id: string; gb: string | number }>(
      `select volume_id, sum(volume_size) as gb from ${S}.aws_ebs_snapshot where owner_id = account_id and coalesce(storage_tier, 'standard') = 'standard' and volume_id in (${volumeIds.map(lit).join(", ")}) group by 1`);
    return new Map(rows.map((r) => [r.volume_id, Number(r.gb || 0)]));
  } catch { return null; }
}

export interface SwarmRefreshResult { swarms: number; total_usd: number; snapshots_known: boolean; took_ms: number }

/** One row per swarm for today: compute, volumes, snapshots, address; the probe's last use and the executor's parking state. */
export async function refreshSwarmCosts(onLog: (l: string) => void = () => {}): Promise<SwarmRefreshResult> {
  const t0 = Date.now();
  const swarms = (db.prepare("select instance_id, name, state, instance_type, monthly_usd, public_ip from inventory_ec2 where gone = 0 order by name").all() as InventoryRow[]).filter((r) => SWARM_NAME.test(r.name || ""));
  const out: SwarmRefreshResult = { swarms: swarms.length, total_usd: 0, snapshots_known: false, took_ms: 0 };
  if (!swarms.length) { out.took_ms = Date.now() - t0; return out; }
  const ebs = db.prepare("select volume_id, monthly_usd from inventory_ebs where instance_id = ? and gone = 0");
  const lastUse = db.prepare("select max(last_use_at) as last_use_at from instance_daily where instance_id = ?");
  const parkedRow = db.prepare("select status from actions where kind = 'swarm_park' and resource = ? and status in ('applied', 'verified', 'reverted', 'failed', 'stale') order by id desc limit 1");
  const volumesOf = new Map<string, { volume_id: string; monthly_usd: number | null }[]>();
  for (const s of swarms) volumesOf.set(s.instance_id, ebs.all(s.instance_id) as { volume_id: string; monthly_usd: number | null }[]);
  const snapGb = await snapshotGbByVolume([...volumesOf.values()].flat().map((v) => v.volume_id));
  out.snapshots_known = snapGb != null;
  const day = new Date().toISOString().slice(0, 10);
  const up = db.prepare(`insert into swarm_cost_daily(day, instance_id, name, state, instance_type, compute_usd, ebs_usd, snapshot_usd, ip_usd, total_usd, last_use_at, idle_days, parked)
    values (@day, @instance_id, @name, @state, @instance_type, @compute_usd, @ebs_usd, @snapshot_usd, @ip_usd, @total_usd, @last_use_at, @idle_days, @parked)
    on conflict(day, instance_id) do update set name = excluded.name, state = excluded.state, instance_type = excluded.instance_type, compute_usd = excluded.compute_usd, ebs_usd = excluded.ebs_usd,
      snapshot_usd = excluded.snapshot_usd, ip_usd = excluded.ip_usd, total_usd = excluded.total_usd, last_use_at = excluded.last_use_at, idle_days = excluded.idle_days, parked = excluded.parked`);
  db.transaction(() => {
    for (const s of swarms) {
      const vols = volumesOf.get(s.instance_id) || [];
      const ebsUsd = vols.reduce((a, v) => a + Number(v.monthly_usd || 0), 0);
      const gb = snapGb ? vols.reduce((a, v) => a + (snapGb.get(v.volume_id) ?? 0), 0) : null;
      const c = swarmCost({ state: s.state, monthly_usd: s.monthly_usd, ebs_usd: ebsUsd, snapshot_gb: gb, public_ip: s.public_ip });
      const lu = (lastUse.get(s.instance_id) as { last_use_at: string | null } | undefined)?.last_use_at ?? null;
      const park = parkedRow.get(s.instance_id) as { status: string } | undefined;
      const parked = park && ["applied", "verified"].includes(park.status) ? 1 : 0;
      up.run({ day, instance_id: s.instance_id, name: s.name, state: s.state, instance_type: s.instance_type, ...c, last_use_at: lu, idle_days: idleDays(lu), parked });
      out.total_usd += c.total_usd;
    }
  })();
  out.total_usd = r2(out.total_usd);
  out.took_ms = Date.now() - t0;
  onLog(`${out.swarms} swarm(s), ≈ ${out.total_usd.toFixed(2)} USD/month at list${out.snapshots_known ? "" : " (snapshots unknown: Steampipe did not answer)"}`);
  return out;
}

export interface SwarmCostRow {
  instance_id: string; name: string | null; state: string | null; instance_type: string | null; parked: boolean; parking_proposed: boolean;
  compute_usd: number; ebs_usd: number; snapshot_usd: number | null; ip_usd: number; total_usd: number;
  /** The month's daily mean stretched to the month: an estimate at list price. */
  month_usd: number; days_sampled: number;
  last_use_at: string | null; idle_days: number | null; nudge: boolean;
}
export interface SwarmCostReport {
  month: string; days_in_month: number; idle_threshold_days: number; estimate_note: string;
  swarms: SwarmCostRow[]; totals: { swarms: number; running: number; parked: number; nudge: number; month_usd: number; compute_usd: number; ebs_usd: number; snapshot_usd: number; ip_usd: number };
}

const daysInMonth = (month: string) => { const [y, m] = month.split("-").map(Number); return new Date(Date.UTC(y, m, 0)).getUTCDate(); };

/** Pure: the report from a month's daily rows (the latest row per swarm is the current state, the mean total is the month). */
export function buildReport(rows: { day: string; instance_id: string; name: string | null; state: string | null; instance_type: string | null; compute_usd: number | null; ebs_usd: number | null; snapshot_usd: number | null; ip_usd: number | null; total_usd: number | null; last_use_at: string | null; idle_days: number | null; parked: number }[], month: string, opts: { idleThreshold: number; parkingProposed: Set<string> }): SwarmCostReport {
  const dim = daysInMonth(month);
  const byId = new Map<string, typeof rows>();
  for (const r of rows) { if (!byId.has(r.instance_id)) byId.set(r.instance_id, []); byId.get(r.instance_id)!.push(r); }
  const swarms: SwarmCostRow[] = [];
  for (const [id, list] of byId) {
    list.sort((a, b) => a.day.localeCompare(b.day));
    const latest = list[list.length - 1];
    const mean = list.reduce((a, r) => a + Number(r.total_usd || 0), 0) / list.length;
    const parked = latest.parked === 1;
    const proposed = opts.parkingProposed.has(id);
    swarms.push({
      instance_id: id, name: latest.name, state: latest.state, instance_type: latest.instance_type, parked, parking_proposed: proposed,
      compute_usd: Number(latest.compute_usd || 0), ebs_usd: Number(latest.ebs_usd || 0), snapshot_usd: latest.snapshot_usd, ip_usd: Number(latest.ip_usd || 0), total_usd: Number(latest.total_usd || 0),
      month_usd: r2(mean), days_sampled: list.length, last_use_at: latest.last_use_at, idle_days: latest.idle_days,
      nudge: shouldNudge({ state: latest.state, idle_days: latest.idle_days, parked, parking_proposed: proposed, idle_threshold: opts.idleThreshold }),
    });
  }
  swarms.sort((a, b) => b.month_usd - a.month_usd || (a.name || "").localeCompare(b.name || ""));
  const sum = (f: (s: SwarmCostRow) => number) => r2(swarms.reduce((a, s) => a + f(s), 0));
  return {
    month, days_in_month: dim, idle_threshold_days: opts.idleThreshold,
    estimate_note: "List-price estimates from the inventory (instance hours while running, volumes, public IPv4, standard snapshots); a month is the mean of its daily figures, not the bill.",
    swarms,
    totals: { swarms: swarms.length, running: swarms.filter((s) => s.state === "running").length, parked: swarms.filter((s) => s.parked).length, nudge: swarms.filter((s) => s.nudge).length,
      month_usd: sum((s) => s.month_usd), compute_usd: sum((s) => s.compute_usd), ebs_usd: sum((s) => s.ebs_usd), snapshot_usd: sum((s) => s.snapshot_usd ?? 0), ip_usd: sum((s) => s.ip_usd) },
  };
}

/** The month's report (YYYY-MM, default the current month), from the daily rows; refreshes today's rows first when the month is the current one and none exist yet. */
export async function swarmCostReport(month?: string): Promise<SwarmCostReport> {
  const cur = new Date().toISOString().slice(0, 7);
  const m = month && /^\d{4}-\d{2}$/.test(month) ? month : cur;
  if (m === cur && !(db.prepare("select 1 from swarm_cost_daily where day = date('now') limit 1").get())) { try { await refreshSwarmCosts(); } catch { /* the report shows what is there */ } }
  const rows = db.prepare("select * from swarm_cost_daily where day like ? order by instance_id, day").all(`${m}-%`) as any[];
  const proposed = new Set((db.prepare("select resource from actions where kind = 'swarm_park' and status = 'proposed'").all() as { resource: string }[]).map((r) => r.resource));
  return buildReport(rows, m, { idleThreshold: Math.max(2, Math.round(config.actParkIdleDays)), parkingProposed: proposed });
}

/** The daily series of one swarm, oldest first (at most `days`). */
export function listSwarmCostHistory(instanceId: string, days = 120): any[] {
  return db.prepare("select * from swarm_cost_daily where instance_id = ? and day >= date('now', ?) order by day").all(instanceId, `-${Math.max(1, Math.floor(days))} days`);
}

/** The months that have rows, newest first, for the page's picker. */
export function swarmCostMonths(): string[] {
  return (db.prepare("select distinct substr(day, 1, 7) as month from swarm_cost_daily order by month desc").all() as { month: string }[]).map((r) => r.month);
}

/**
 * Baselines: what is typical for each thing the advisor watches, so a new value can be judged against the
 * system's own history instead of a fixed threshold. Sources: CloudWatch (NAT bytes per hour, EC2 CPU per hour,
 * 14 days), the hourly probes (memory, disk, load, containers, 30 days) and Cost Explorer (net spend per service
 * per day, 60 days). Refreshed daily (BASELINE_CRON) and on demand; the watcher reads the NAT baseline, the UI
 * shows the rest.
 */
import { db } from "./db.js";
import { S, query } from "./steampipe.js";
import { Baseline, Point, buildBaseline, scoreValue } from "./baseline_math.js";
import { credentialGate } from "./gate.js";
import { describeError } from "./permissions.js";

db.exec(`create table if not exists baselines (
  scope_kind text not null, scope_id text not null, metric text not null,
  window_days integer not null, source text not null, unit text,
  samples integer not null, days integer not null,
  median real, mad real, p95 real, mean real, max real, min real,
  by_hour text not null, by_dow text not null,
  computed_at text not null,
  primary key (scope_kind, scope_id, metric)
)`);

export type ScopeKind = "nat" | "instance" | "service" | "loggroup";
export interface StoredBaseline extends Baseline { scope_kind: ScopeKind; scope_id: string; metric: string; days: number; computed_at: string }

const NAT_DAYS = 14, CPU_DAYS = 14, PROBE_DAYS = 30, SPEND_DAYS = 60;
const lit = (s: string) => `'${String(s).replace(/'/g, "''")}'`;

const upsert = db.prepare(`insert into baselines(scope_kind, scope_id, metric, window_days, source, unit, samples, days, median, mad, p95, mean, max, min, by_hour, by_dow, computed_at)
  values (@scope_kind, @scope_id, @metric, @window_days, @source, @unit, @samples, @days, @median, @mad, @p95, @mean, @max, @min, @by_hour, @by_dow, datetime('now'))
  on conflict(scope_kind, scope_id, metric) do update set window_days = excluded.window_days, source = excluded.source, unit = excluded.unit, samples = excluded.samples, days = excluded.days,
    median = excluded.median, mad = excluded.mad, p95 = excluded.p95, mean = excluded.mean, max = excluded.max, min = excluded.min, by_hour = excluded.by_hour, by_dow = excluded.by_dow, computed_at = excluded.computed_at`);

function store(scope_kind: ScopeKind, scope_id: string, metric: string, points: Point[], window_days: number, source: string, unit: string | null): boolean {
  if (points.length < 3) return false;
  const b = buildBaseline(points, window_days, source, unit);
  const num = (x: number) => (Number.isFinite(x) ? x : null);
  upsert.run({ scope_kind, scope_id, metric, window_days, source, unit, samples: b.samples, days: b.days, median: num(b.median), mad: num(b.mad), p95: num(b.p95), mean: num(b.mean), max: num(b.max), min: num(b.min), by_hour: JSON.stringify(b.by_hour), by_dow: JSON.stringify(b.by_dow) });
  return true;
}

const rowToBaseline = (r: any): StoredBaseline => ({ scope_kind: r.scope_kind, scope_id: r.scope_id, metric: r.metric, window_days: r.window_days, source: r.source, unit: r.unit, samples: r.samples, days: r.days,
  median: r.median, mad: r.mad, p95: r.p95, mean: r.mean, max: r.max, min: r.min, by_hour: JSON.parse(r.by_hour), by_dow: JSON.parse(r.by_dow), computed_at: r.computed_at });

export function getBaseline(scope_kind: ScopeKind, scope_id: string, metric: string): StoredBaseline | null {
  const r = db.prepare("select * from baselines where scope_kind = ? and scope_id = ? and metric = ?").get(scope_kind, scope_id, metric);
  return r ? rowToBaseline(r) : null;
}
export function listBaselines(scope_kind?: ScopeKind, scope_id?: string): StoredBaseline[] {
  const where: string[] = []; const params: string[] = [];
  if (scope_kind) { where.push("scope_kind = ?"); params.push(scope_kind); }
  if (scope_id) { where.push("scope_id = ?"); params.push(scope_id); }
  return (db.prepare(`select * from baselines ${where.length ? `where ${where.join(" and ")}` : ""} order by scope_kind, scope_id, metric`).all(...params) as any[]).map(rowToBaseline);
}
export function baselineSummary(): { scope_kind: string; scopes: number; metrics: number; computed_at: string | null }[] {
  return db.prepare("select scope_kind, count(distinct scope_id) as scopes, count(*) as metrics, max(computed_at) as computed_at from baselines group by scope_kind").all() as any[];
}
export { scoreValue };

export interface BaselineRefreshResult { nat: number; cpu: number; probes: number; spend: number; errors: string[]; took_ms: number }

/** Recomputes every baseline. Four Cost Explorer / CloudWatch round trips plus one per NAT gateway metric. */
export async function refreshBaselines(onLog: (s: string) => void = () => {}): Promise<BaselineRefreshResult> {
  const t0 = Date.now();
  const out: BaselineRefreshResult = { nat: 0, cpu: 0, probes: 0, spend: 0, errors: [], took_ms: 0 };
  const gate = await credentialGate("baselines");
  if (!gate.ok) { out.errors.push(gate.error || "credentials not working"); out.took_ms = Date.now() - t0; return out; }

  // ---- NAT gateways: bytes per hour in each direction and in total, 14 days of hourly sums
  const gateways = db.prepare("select label, max(dims) as dims from watch_samples where key = 'nat_bytes_hour' group by label").all() as { label: string; dims: string | null }[];
  for (const g of gateways) {
    let region = "us-east-1";
    try { region = JSON.parse(g.dims || "{}").region || region; } catch { /* default */ }
    try {
      const series: Record<string, Map<number, number>> = { in: new Map(), out: new Map() };
      for (const [dir, metric] of [["in", "BytesOutToSource"], ["out", "BytesOutToDestination"]] as const) {
        const rows = await query<{ timestamp: string; value: string | null }>(`select timestamp, sum as value from ${S}.aws_cloudwatch_metric_statistic_data_point
          where namespace = 'AWS/NATGateway' and metric_name = ${lit(metric)} and dimensions = ${lit(JSON.stringify([{ Name: "NatGatewayId", Value: g.label }]))}
            and timestamp between now() - interval '${NAT_DAYS} days' and now() and period = 3600 and region = ${lit(region)} order by timestamp`);
        for (const r of rows) if (r.value != null) series[dir].set(new Date(r.timestamp).getTime(), Number(r.value));
      }
      const pts = (m: Map<number, number>): Point[] => [...m.entries()].map(([t, v]) => ({ t, v }));
      const total = new Map<number, number>();
      for (const [t, v] of series.in) total.set(t, v + (series.out.get(t) ?? 0));
      for (const [t, v] of series.out) if (!total.has(t)) total.set(t, v);
      if (store("nat", g.label, "bytes_hour", pts(total), NAT_DAYS, "cloudwatch", "bytes")) out.nat++;
      store("nat", g.label, "bytes_hour_in", pts(series.in), NAT_DAYS, "cloudwatch", "bytes");
      store("nat", g.label, "bytes_hour_out", pts(series.out), NAT_DAYS, "cloudwatch", "bytes");
    } catch (e) { out.errors.push(describeError(e, `nat baseline ${g.label} (aws_cloudwatch_metric_statistic_data_point)`)); }
  }
  onLog(`nat: ${out.nat} gateways`);

  // ---- EC2 CPU per hour, 14 days, every running instance the inventory knows
  const instances = (db.prepare("select instance_id from inventory_ec2 where gone = 0 and state = 'running'").all() as { instance_id: string }[]).map((r) => r.instance_id);
  if (instances.length) {
    try {
      const rows = await query<{ instance_id: string; timestamp: string; average: string | null; maximum: string | null }>(
        `select instance_id, timestamp, average, maximum from ${S}.aws_ec2_instance_metric_cpu_utilization_hourly
         where instance_id = any($1::text[]) and timestamp > now() - interval '${CPU_DAYS} days' order by instance_id, timestamp`, [instances]);
      const byId = new Map<string, { avg: Point[]; max: Point[] }>();
      for (const r of rows) {
        const e = byId.get(r.instance_id) || { avg: [], max: [] }; const t = new Date(r.timestamp).getTime();
        if (r.average != null) e.avg.push({ t, v: Number(r.average) });
        if (r.maximum != null) e.max.push({ t, v: Number(r.maximum) });
        byId.set(r.instance_id, e);
      }
      for (const [id, s] of byId) { if (store("instance", id, "cpu_pct", s.avg, CPU_DAYS, "cloudwatch", "%")) out.cpu++; store("instance", id, "cpu_pct_max", s.max, CPU_DAYS, "cloudwatch", "%"); }
    } catch (e) { out.errors.push(describeError(e, "cpu baselines (aws_ec2_instance_metric_cpu_utilization_hourly)")); }
  }
  onLog(`cpu: ${out.cpu} instances`);

  // ---- probes: memory, disk, load per core and running containers, 30 days, from our own samples
  const probes = db.prepare("select instance_id, collected_at, json from instance_metrics where datetime(collected_at) > datetime('now', ?) order by instance_id, collected_at").all(`-${PROBE_DAYS} days`) as { instance_id: string; collected_at: string; json: string }[];
  const perInstance = new Map<string, Record<string, Point[]>>();
  for (const r of probes) {
    let d: any; try { d = JSON.parse(r.json); } catch { continue; }
    const t = new Date(r.collected_at.endsWith("Z") ? r.collected_at : `${r.collected_at.replace(" ", "T")}Z`).getTime();
    const e = perInstance.get(r.instance_id) || { mem_pct: [], disk_pct: [], load_per_cpu: [], containers: [] };
    const mem = d.memory || {}; if (mem.total_bytes) e.mem_pct.push({ t, v: (100 * Number(mem.used_bytes)) / Number(mem.total_bytes) });
    const disks: any[] = Array.isArray(d.disks) ? d.disks : []; const root = disks.find((x) => x.mount === "/") || disks[0];
    if (root && root.used_pct != null) e.disk_pct.push({ t, v: Number(root.used_pct) });
    if (d.load?.["1m"] != null && Number(d.cpus) > 0) e.load_per_cpu.push({ t, v: (100 * Number(d.load["1m"])) / Number(d.cpus) });
    if (d.docker?.available) e.containers.push({ t, v: Number(d.docker.running ?? 0) });
    perInstance.set(r.instance_id, e);
  }
  for (const [id, m] of perInstance) {
    let any = false;
    for (const [metric, unit] of [["mem_pct", "%"], ["disk_pct", "%"], ["load_per_cpu", "% of cores"], ["containers", "containers"]] as const) any = store("instance", id, metric, m[metric], PROBE_DAYS, "probes", unit) || any;
    if (any) out.probes++;
  }
  onLog(`probes: ${out.probes} instances`);

  // ---- spend per service per day, 60 days (one Cost Explorer call)
  try {
    const rows = await query<{ service: string; day: string; net: string | null }>(`select service, to_char(period_start at time zone 'UTC', 'YYYY-MM-DD') as day, sum(net_unblended_cost_amount) as net
      from ${S}.aws_cost_by_service_daily where period_start >= now() - interval '${SPEND_DAYS} days' and period_start < date_trunc('day', now()) group by 1, 2 order by 1, 2`);
    const byService = new Map<string, Point[]>();
    for (const r of rows) { if (r.net == null) continue; byService.set(r.service, [...(byService.get(r.service) || []), { t: Date.parse(`${r.day}T12:00:00Z`), v: Number(r.net) }]); }
    for (const [service, pts] of byService) if (pts.length >= 7 && pts.some((p) => p.v > 0.5) && store("service", service, "net_usd_day", pts, SPEND_DAYS, "cost_explorer", "USD/day")) out.spend++;
  } catch (e) { out.errors.push(describeError(e, "spend baselines (aws_cost_by_service_daily)")); }
  onLog(`spend: ${out.spend} services`);
  out.took_ms = Date.now() - t0;
  return out;
}

import { CloudWatchClient, GetMetricDataCommand, type MetricDataQuery } from "@aws-sdk/client-cloudwatch";
import { DescribeDBClustersCommand, DescribeDBInstancesCommand, DescribeDBLogFilesCommand, DownloadDBLogFilePortionCommand, RDSClient } from "@aws-sdk/client-rds";
import { DescribeDimensionKeysCommand, PIClient } from "@aws-sdk/client-pi";
import { choice, noul } from "@typesafe-ai/sdk";
import { db } from "./db.js";
import { sdkCredentials } from "./steampipe.js";
import { askJev, jevEnabled } from "./jev.js";
import { describeError } from "./permissions.js";
import { config } from "./config.js";
import { createHash } from "node:crypto";

/**
 * The load profile of a database: what the advisor reads before it says how to act on an RDS or Aurora
 * recommendation. Fourteen days of CloudWatch at five-minute resolution (I/O, volume size, CPU, connections,
 * buffer cache hit ratio, and for Serverless v2 the ACU curve) plus three days at one minute for the burst
 * shape; the top statements from Performance Insights when it is enabled; the slow statements from the tail
 * of the engine log when durations are logged. The numbers are reduced deterministically (bursts, time at the
 * capacity ceiling, whether the database fits in its buffer cache) and Jev classifies the result: the shape,
 * what drives the I/O, whether the cap throttles it, whether the pattern is structural and which lever
 * matters. Everything lands in rds_load_profiles; src/resolve.ts hands it to the gate and the agent,
 * src/rules.ts cites it in the Aurora storage-tier recommendation, the MCP tool rds_load exposes it.
 */

export const LOAD_WINDOW_DAYS = 14;
export const BURST_WINDOW_DAYS = 3;
export const STATEMENT_WINDOW_DAYS = 7;
export const LOG_TAIL_LINES = 4000;
/** Aurora Serverless v2: about 2 GiB of memory per ACU, of which the engine gives roughly three quarters to the buffer cache. */
export const GIB_PER_ACU = 2;
export const CACHE_SHARE_OF_MEMORY = 0.75;
export const IO_USD_PER_MILLION = 0.20;

export interface LoadTarget {
  kind: "cluster" | "instance";
  id: string;
  region: string;
  engine: string | null;
  engine_version: string | null;
  storage_type: string | null;
  serverless: boolean;
  configured_min_acu: number | null;
  configured_max_acu: number | null;
  instance_class: string | null;
  members: number;
  writer: string | null;
  dbi_resource_id: string | null;
  performance_insights: boolean;
}

export interface Series { t: number[]; v: number[] }

export interface Burst { start: string; minutes: number; peak: number }

export interface LoadProfile {
  target: LoadTarget;
  collected_at: string;
  window_days: number;
  io: {
    reads_per_day: number | null; writes_per_day: number | null; read_write_ratio: number | null;
    ios_per_month: number | null; io_cost_standard_usd_month: number | null;
    storage_gb: number | null; buffer_cache_hit_pct_avg: number | null; buffer_cache_hit_pct_min: number | null; days_with_data: number;
  };
  capacity: null | {
    min_acu: number; avg_acu: number; max_acu: number; configured_min: number | null; configured_max: number | null; cap: number; floor: number;
    pct_time_at_cap: number; pct_time_at_floor: number;
    memory_gib_avg: number; cache_gib_avg: number; cache_gib_at_cap: number; db_fits_in_cache_at_avg: boolean | null; db_fits_in_cache_at_cap: boolean | null;
    bursts: { count: number; per_day: number; median_minutes: number | null; longest_minutes: number | null; median_gap_minutes: number | null; cadence: "hourly" | "daily" | "irregular" | null; top_start_minute: number | null; sample: Burst[] };
    sample_minutes: number;
  };
  cpu: { avg_pct: number | null; p95_pct: number | null; max_pct: number | null };
  connections: { avg: number | null; max: number | null };
  memory: { freeable_min_gib: number | null };
  daily: { day: string; reads: number | null; writes: number | null; avg_acu: number | null; cpu_avg: number | null }[];
  shape: LoadShape | "unknown";
  notes: string[];
}

export const LOAD_SHAPES = {
  steady: "the load is roughly the same all day: capacity and I/O move within a narrow band",
  scheduled_bursts: "the database idles at its floor and works in bursts that start on a fixed cadence (every hour, every day at the same time): a job, a report, a sync",
  irregular_bursts: "the database idles and works in bursts with no fixed cadence: user traffic or an event-driven producer",
  mostly_idle: "the database does almost nothing: at its floor with a handful of short bursts a day",
} as const;
export type LoadShape = keyof typeof LOAD_SHAPES;

export const IO_CAUSES = {
  cache_starved_reads: "the working set does not fit in the buffer cache, so the same pages are read from the storage layer again and again (reads far above writes, cache hit ratio below the high nineties, cache smaller than the database)",
  write_heavy: "writes and their log records make most of the I/O (writes comparable to or above reads)",
  scans_or_reporting: "large sequential scans or reporting queries read whole tables (few heavy statements dominate the load)",
  checkpoints_or_temp_files: "checkpoints, vacuum or temporary files spilling to disk drive the I/O rather than the application's reads",
  unknown: "the facts are not enough to say",
} as const;
export type IoCause = keyof typeof IO_CAUSES;

export const LEVERS = {
  io_optimized_storage: "switch the cluster to Aurora I/O-Optimized storage: the I/O charge disappears and the pattern itself is acceptable",
  raise_min_capacity: "raise the minimum capacity so the working set stays in the buffer cache between bursts",
  raise_max_capacity: "raise the maximum capacity: the bursts are held at the ceiling and would finish faster with more",
  fix_queries_or_indexes: "fix the few statements that make the load (an index, a rewrite, a bounded scan)",
  add_application_cache: "cache the hot reads in the application or a cache layer rather than in the database",
  nothing: "leave it: the load is small, steady and cheap enough as it is",
} as const;
export type Lever = keyof typeof LEVERS;

export interface LoadClassification {
  shape: LoadShape | "unknown";
  shape_confidence: number;
  io_cause: IoCause;
  io_cause_confidence: number;
  throttled_by_cap: number;
  structural: number;
  lever: Lever | "unknown";
  lever_confidence: number;
  model?: string;
  call_id?: number;
  latency_ms?: number;
  classified_at: string;
}

export interface StatementsResult { enabled: boolean; window_days: number; statements: { sql: string; load_avg: number; share_pct: number }[]; error?: string; note?: string }
export interface SlowLogResult {
  files: string[]; lines_scanned: number; duration_lines: number; temp_file_lines: number; checkpoint_lines: number;
  statements: { sql: string; count: number; total_ms: number; max_ms: number }[];
  error?: string; note?: string;
}

export interface RdsLoadRow { id: number; target_id: string; kind: "cluster" | "instance"; region: string | null; collected_at: string; profile: LoadProfile; statements: StatementsResult | null; slow_log: SlowLogResult | null; jev: LoadClassification | null; profile_hash: string | null; error: string | null }

// ---- the numbers ----------------------------------------------------------------------------------------------

const round = (v: number, d = 2) => Math.round(v * 10 ** d) / 10 ** d;
const mean = (vs: number[]) => (vs.length ? vs.reduce((a, b) => a + b, 0) / vs.length : null);
const median = (vs: number[]) => { if (!vs.length) return null; const s = [...vs].sort((a, b) => a - b); const m = Math.floor(s.length / 2); return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };
const quantile = (vs: number[], q: number) => { if (!vs.length) return null; const s = [...vs].sort((a, b) => a - b); return s[Math.min(s.length - 1, Math.floor(q * s.length))]; };
const dayOf = (ms: number) => new Date(ms).toISOString().slice(0, 10);

/** Bursts on a one-minute capacity series: runs above the midpoint between floor and cap, closed after three quiet minutes. */
export function detectBursts(s: Series, floor: number, cap: number): Burst[] {
  const out: Burst[] = [];
  if (!s.v.length || cap <= floor) return out;
  const thr = floor + 0.5 * (cap - floor);
  let start = -1, peak = 0, quiet = 0, active = 0, lastActive = -1;
  const close = (i: number) => { if (start >= 0) { out.push({ start: new Date(s.t[start]).toISOString(), minutes: Math.max(1, Math.round((s.t[lastActive] - s.t[start]) / 60000) + 1), peak: round(peak, 3) }); } start = -1; peak = 0; quiet = 0; active = 0; void i; };
  for (let i = 0; i < s.v.length; i++) {
    const v = s.v[i];
    if (v >= thr) { if (start < 0) start = i; peak = Math.max(peak, v); quiet = 0; active++; lastActive = i; }
    else if (start >= 0 && ++quiet >= 3) close(i);
  }
  close(s.v.length);
  return out;
}

/** The cadence of the bursts' start times: hourly when half of them start in the same five minutes of the hour, daily when most start in the same hour of the day. */
export function burstCadence(bursts: Burst[]): { cadence: "hourly" | "daily" | "irregular" | null; top_start_minute: number | null } {
  if (bursts.length < 3) return { cadence: null, top_start_minute: null };
  const byMinute = new Map<number, number>();
  const byHour = new Map<number, number>();
  for (const b of bursts) {
    const d = new Date(b.start);
    const m5 = Math.floor(d.getUTCMinutes() / 5) * 5;
    byMinute.set(m5, (byMinute.get(m5) || 0) + 1);
    byHour.set(d.getUTCHours(), (byHour.get(d.getUTCHours()) || 0) + 1);
  }
  const top = (m: Map<number, number>) => [...m.entries()].sort((a, b) => b[1] - a[1])[0];
  const tm = top(byMinute), th = top(byHour);
  if (bursts.length >= 6 && tm[1] / bursts.length >= 0.5) return { cadence: "hourly", top_start_minute: tm[0] };
  if (th[1] / bursts.length >= 0.6) return { cadence: "daily", top_start_minute: th[0] * 60 };
  return { cadence: "irregular", top_start_minute: null };
}

export function shapeOf(p: Pick<LoadProfile, "capacity" | "cpu">): LoadShape | "unknown" {
  const c = p.capacity;
  if (c) {
    if (c.sample_minutes < 60) return "unknown";
    if (c.pct_time_at_floor >= 0.9 && c.bursts.per_day < 1) return "mostly_idle";
    if (c.bursts.per_day >= 2 && (c.bursts.cadence === "hourly" || c.bursts.cadence === "daily")) return "scheduled_bursts";
    if (c.bursts.per_day >= 2) return "irregular_bursts";
    if (c.pct_time_at_cap >= 0.8 || c.pct_time_at_floor + c.pct_time_at_cap < 0.3) return "steady";
    return c.bursts.count ? "irregular_bursts" : "steady";
  }
  if (p.cpu.avg_pct == null) return "unknown";
  if (p.cpu.avg_pct < 5 && (p.cpu.p95_pct ?? 0) < 15) return "mostly_idle";
  if (p.cpu.p95_pct != null && p.cpu.avg_pct > 0 && p.cpu.p95_pct / p.cpu.avg_pct > 3) return "irregular_bursts";
  return "steady";
}

/** Reduces the fetched series to the profile. `series` keys: see the query list in fetchSeries. */
export function buildProfile(target: LoadTarget, series: Record<string, Series>, now = Date.now()): LoadProfile {
  const s = (k: string): Series => series[k] || { t: [], v: [] };
  const notes: string[] = [];
  const reads = s("reads"), writes = s("writes");
  const daysWithData = new Set(reads.t.map(dayOf)).size;
  const sumPerDay = (x: Series) => (x.v.length ? x.v.reduce((a, b) => a + b, 0) / Math.max(1, new Set(x.t.map(dayOf)).size) : null);
  // Aurora VolumeRead/WriteIOPs are counts per five minutes (sum); RDS Read/WriteIOPS are per second (average).
  const perDay = target.kind === "cluster"
    ? { reads: sumPerDay(reads), writes: sumPerDay(writes) }
    : { reads: mean(reads.v) != null ? mean(reads.v)! * 86400 : null, writes: mean(writes.v) != null ? mean(writes.v)! * 86400 : null };
  const iosPerMonth = perDay.reads != null && perDay.writes != null ? (perDay.reads + perDay.writes) * 30.4 : null;
  const storageBytes = s("storage").v.length ? Math.max(...s("storage").v) : null;
  const storageGb = storageBytes != null ? round(storageBytes / 1e9, 2) : null;
  const hit = s("cache_hit");
  const io: LoadProfile["io"] = {
    reads_per_day: perDay.reads != null ? Math.round(perDay.reads) : null,
    writes_per_day: perDay.writes != null ? Math.round(perDay.writes) : null,
    read_write_ratio: perDay.reads != null && perDay.writes ? round(perDay.reads / perDay.writes, 1) : null,
    ios_per_month: iosPerMonth != null ? Math.round(iosPerMonth) : null,
    io_cost_standard_usd_month: iosPerMonth != null ? round((iosPerMonth / 1e6) * IO_USD_PER_MILLION, 2) : null,
    storage_gb: storageGb,
    buffer_cache_hit_pct_avg: mean(hit.v) != null ? round(mean(hit.v)!, 1) : null,
    buffer_cache_hit_pct_min: hit.v.length ? round(Math.min(...hit.v), 1) : null,
    days_with_data: daysWithData,
  };
  const cpuAvg = s("cpu_avg"), cpuMax = s("cpu_max");
  const cpu = { avg_pct: mean(cpuAvg.v) != null ? round(mean(cpuAvg.v)!, 1) : null, p95_pct: quantile(cpuAvg.v, 0.95) != null ? round(quantile(cpuAvg.v, 0.95)!, 1) : null, max_pct: cpuMax.v.length ? round(Math.max(...cpuMax.v), 1) : null };
  const conn = { avg: mean(s("conn_avg").v) != null ? round(mean(s("conn_avg").v)!, 1) : null, max: s("conn_max").v.length ? Math.round(Math.max(...s("conn_max").v)) : null };
  const memory = { freeable_min_gib: s("mem_min").v.length ? round(Math.min(...s("mem_min").v) / 2 ** 30, 2) : null };

  let capacity: LoadProfile["capacity"] = null;
  const acu = s("acu_1m"), acu5 = s("acu_avg");
  if (target.serverless && (acu.v.length || acu5.v.length)) {
    const fine = acu.v.length ? acu : acu5;
    const minObs = Math.min(...fine.v), maxObs = Math.max(...fine.v);
    const floor = target.configured_min_acu ?? minObs, cap = target.configured_max_acu ?? maxObs;
    const atCap = fine.v.filter((v) => v >= cap * 0.975).length / fine.v.length;
    const atFloor = fine.v.filter((v) => v <= floor + 0.05).length / fine.v.length;
    const bursts = detectBursts(fine, floor, cap);
    const days = Math.max(1 / 24, (fine.t[fine.t.length - 1] - fine.t[0]) / 86400000);
    const gaps: number[] = [];
    for (let i = 1; i < bursts.length; i++) gaps.push(Math.round((new Date(bursts[i].start).getTime() - new Date(bursts[i - 1].start).getTime()) / 60000) - bursts[i - 1].minutes);
    const avg = mean(acu5.v.length ? acu5.v : fine.v)!;
    const memAvg = avg * GIB_PER_ACU, cacheAvg = memAvg * CACHE_SHARE_OF_MEMORY, cacheCap = cap * GIB_PER_ACU * CACHE_SHARE_OF_MEMORY;
    const dbGib = storageBytes != null ? storageBytes / 2 ** 30 : null;
    const { cadence, top_start_minute } = burstCadence(bursts);
    capacity = {
      min_acu: round(minObs, 2), avg_acu: round(avg, 2), max_acu: round(maxObs, 2), configured_min: target.configured_min_acu, configured_max: target.configured_max_acu, cap: round(cap, 2), floor: round(floor, 2),
      pct_time_at_cap: round(atCap, 3), pct_time_at_floor: round(atFloor, 3),
      memory_gib_avg: round(memAvg, 1), cache_gib_avg: round(cacheAvg, 1), cache_gib_at_cap: round(cacheCap, 1),
      db_fits_in_cache_at_avg: dbGib != null ? dbGib <= cacheAvg : null, db_fits_in_cache_at_cap: dbGib != null ? dbGib <= cacheCap : null,
      bursts: { count: bursts.length, per_day: round(bursts.length / days, 1), median_minutes: median(bursts.map((b) => b.minutes)), longest_minutes: bursts.length ? Math.max(...bursts.map((b) => b.minutes)) : null, median_gap_minutes: median(gaps), cadence, top_start_minute, sample: bursts.slice(-12) },
      sample_minutes: fine.v.length,
    };
    if (dbGib != null && capacity.db_fits_in_cache_at_avg === false) notes.push(`the database (${round(dbGib, 1)} GiB) is larger than the buffer cache at the average capacity (about ${round(cacheAvg, 1)} GiB at ${round(avg, 2)} ACU)${capacity.db_fits_in_cache_at_cap ? `; it would fit at the ceiling (${round(cacheCap, 1)} GiB at ${cap} ACU)` : `, and would not fit at the ceiling either (${round(cacheCap, 1)} GiB at ${cap} ACU)`}`);
    if (atCap >= 0.3) notes.push(`at the ${cap} ACU ceiling ${Math.round(atCap * 100)}% of the time`);
    if (bursts.length && cadence === "hourly") notes.push(`${bursts.length} bursts in ${round(days, 1)} days, most starting around minute ${top_start_minute} of the hour`);
    if (bursts.length && cadence === "daily") notes.push(`${bursts.length} bursts in ${round(days, 1)} days, most starting around ${String(Math.floor((top_start_minute || 0) / 60)).padStart(2, "0")}:00 UTC`);
  }
  if (io.read_write_ratio != null && io.read_write_ratio >= 20) notes.push(`reads outnumber writes ${io.read_write_ratio}:1`);
  if (io.buffer_cache_hit_pct_avg != null && io.buffer_cache_hit_pct_avg < 97) notes.push(`buffer cache hit ratio averages ${io.buffer_cache_hit_pct_avg}%`);

  // Per day: I/O counts and the average capacity / CPU, for the UI and the agent.
  const perDayMap = new Map<string, { reads: number[]; writes: number[]; acu: number[]; cpu: number[] }>();
  const bucket = (d: string) => { let b = perDayMap.get(d); if (!b) { b = { reads: [], writes: [], acu: [], cpu: [] }; perDayMap.set(d, b); } return b; };
  reads.t.forEach((t, i) => bucket(dayOf(t)).reads.push(reads.v[i]));
  writes.t.forEach((t, i) => bucket(dayOf(t)).writes.push(writes.v[i]));
  acu5.t.forEach((t, i) => bucket(dayOf(t)).acu.push(acu5.v[i]));
  cpuAvg.t.forEach((t, i) => bucket(dayOf(t)).cpu.push(cpuAvg.v[i]));
  const today = dayOf(now);
  const daily = [...perDayMap.entries()].sort(([a], [b]) => a.localeCompare(b)).filter(([d]) => d !== today).map(([day, b]) => ({
    day,
    reads: b.reads.length ? Math.round(target.kind === "cluster" ? b.reads.reduce((x, y) => x + y, 0) : mean(b.reads)! * 86400) : null,
    writes: b.writes.length ? Math.round(target.kind === "cluster" ? b.writes.reduce((x, y) => x + y, 0) : mean(b.writes)! * 86400) : null,
    avg_acu: b.acu.length ? round(mean(b.acu)!, 2) : null,
    cpu_avg: b.cpu.length ? round(mean(b.cpu)!, 1) : null,
  }));
  const profile: LoadProfile = { target, collected_at: new Date(now).toISOString(), window_days: LOAD_WINDOW_DAYS, io, capacity, cpu, connections: conn, memory, daily, shape: "unknown", notes };
  profile.shape = shapeOf(profile);
  return profile;
}

// ---- AWS ------------------------------------------------------------------------------------------------------

const clients = () => {
  const creds = sdkCredentials();
  return { creds, rds: (region: string) => new RDSClient({ region, credentials: creds.provider }), cw: (region: string) => new CloudWatchClient({ region, credentials: creds.provider }), pi: (region: string) => new PIClient({ region, credentials: creds.provider }) };
};

/** Which database the id names: the cluster or instance in the inventory first (its region), then RDS itself for the live configuration. */
export async function resolveTarget(id: string, opts: { region?: string } = {}): Promise<LoadTarget> {
  const inv = db.prepare("select db_instance_identifier, region, engine, engine_version, class, cluster, storage_type, snapshot from inventory_rds where db_instance_identifier = ? or cluster = ? order by db_instance_identifier").all(id, id) as any[];
  const c = clients();
  const region = opts.region || inv[0]?.region || c.creds.region;
  const rds = c.rds(region);
  const clusterFirst = !inv.length || inv.some((r) => r.cluster === id) || !inv.some((r) => r.db_instance_identifier === id);
  const instanceInfo = async (instanceId: string) => {
    const r = await rds.send(new DescribeDBInstancesCommand({ DBInstanceIdentifier: instanceId }));
    return r.DBInstances?.[0] ?? null;
  };
  if (clusterFirst) {
    try {
      const r = await rds.send(new DescribeDBClustersCommand({ DBClusterIdentifier: id }));
      const cl = r.DBClusters?.[0];
      if (cl) {
        const writer = cl.DBClusterMembers?.find((m) => m.IsClusterWriter)?.DBInstanceIdentifier ?? cl.DBClusterMembers?.[0]?.DBInstanceIdentifier ?? null;
        const w = writer ? await instanceInfo(writer).catch(() => null) : null;
        const sv2 = cl.ServerlessV2ScalingConfiguration;
        return {
          kind: "cluster", id, region, engine: cl.Engine ?? null, engine_version: cl.EngineVersion ?? null, storage_type: cl.StorageType ?? "aurora",
          serverless: Boolean(sv2) || w?.DBInstanceClass === "db.serverless", configured_min_acu: sv2?.MinCapacity ?? null, configured_max_acu: sv2?.MaxCapacity ?? null,
          instance_class: w?.DBInstanceClass ?? null, members: cl.DBClusterMembers?.length ?? 0, writer, dbi_resource_id: w?.DbiResourceId ?? null, performance_insights: Boolean(w?.PerformanceInsightsEnabled),
        };
      }
    } catch (e: any) {
      if (!/DBClusterNotFound/i.test(String(e?.name || e?.message || e))) throw e;
    }
  }
  const inst = await instanceInfo(id);
  if (!inst) throw Object.assign(new Error(`no RDS cluster or instance named ${id} in ${region}`), { code: "not_found" });
  return {
    kind: "instance", id, region, engine: inst.Engine ?? null, engine_version: inst.EngineVersion ?? null, storage_type: inst.StorageType ?? null,
    serverless: inst.DBInstanceClass === "db.serverless", configured_min_acu: null, configured_max_acu: null, instance_class: inst.DBInstanceClass ?? null, members: 1,
    writer: id, dbi_resource_id: inst.DbiResourceId ?? null, performance_insights: Boolean(inst.PerformanceInsightsEnabled),
  };
}

interface Spec { key: string; metric: string; stat: "Average" | "Maximum" | "Minimum" | "Sum"; period: number; days: number }

function specsFor(t: LoadTarget): Spec[] {
  const W = LOAD_WINDOW_DAYS, B = BURST_WINDOW_DAYS;
  const common: Spec[] = [
    { key: "cpu_avg", metric: "CPUUtilization", stat: "Average", period: 300, days: W },
    { key: "cpu_max", metric: "CPUUtilization", stat: "Maximum", period: 300, days: W },
    { key: "conn_avg", metric: "DatabaseConnections", stat: "Average", period: 300, days: W },
    { key: "conn_max", metric: "DatabaseConnections", stat: "Maximum", period: 300, days: W },
    { key: "mem_min", metric: "FreeableMemory", stat: "Minimum", period: 300, days: W },
    { key: "cache_hit", metric: "BufferCacheHitRatio", stat: "Average", period: 300, days: W },
  ];
  const io: Spec[] = t.kind === "cluster"
    ? [{ key: "reads", metric: "VolumeReadIOPs", stat: "Sum", period: 300, days: W }, { key: "writes", metric: "VolumeWriteIOPs", stat: "Sum", period: 300, days: W }, { key: "storage", metric: "VolumeBytesUsed", stat: "Maximum", period: 3600, days: W }]
    : [{ key: "reads", metric: "ReadIOPS", stat: "Average", period: 300, days: W }, { key: "writes", metric: "WriteIOPS", stat: "Average", period: 300, days: W }];
  const acu: Spec[] = t.serverless
    ? [{ key: "acu_avg", metric: "ServerlessDatabaseCapacity", stat: "Average", period: 300, days: W }, { key: "acu_1m", metric: "ServerlessDatabaseCapacity", stat: "Average", period: 60, days: B }, { key: "acu_util", metric: "ACUUtilization", stat: "Average", period: 300, days: W }]
    : [];
  return [...common, ...io, ...acu];
}

/** One GetMetricData for every series (paginated), keyed by spec key, ascending in time. */
export async function fetchSeries(t: LoadTarget, now = Date.now()): Promise<Record<string, Series>> {
  const cw = clients().cw(t.region);
  const specs = specsFor(t);
  const dim = t.kind === "cluster" ? { Name: "DBClusterIdentifier", Value: t.id } : { Name: "DBInstanceIdentifier", Value: t.id };
  const maxDays = Math.max(...specs.map((s) => s.days));
  const queries: MetricDataQuery[] = specs.map((s, i) => ({ Id: `q${i}`, MetricStat: { Metric: { Namespace: "AWS/RDS", MetricName: s.metric, Dimensions: [dim] }, Period: s.period, Stat: s.stat }, ReturnData: true }));
  const out: Record<string, Series> = {};
  for (const s of specs) out[s.key] = { t: [], v: [] };
  let NextToken: string | undefined;
  do {
    const r = await cw.send(new GetMetricDataCommand({ StartTime: new Date(now - maxDays * 86400000), EndTime: new Date(now), MetricDataQueries: queries, ScanBy: "TimestampAscending", NextToken }));
    for (const res of r.MetricDataResults ?? []) {
      const spec = specs[Number(String(res.Id).slice(1))]; if (!spec) continue;
      const from = now - spec.days * 86400000;
      (res.Timestamps ?? []).forEach((ts, i) => { const ms = new Date(ts).getTime(); if (ms >= from && res.Values?.[i] != null) { out[spec.key].t.push(ms); out[spec.key].v.push(res.Values[i]); } });
    }
    NextToken = r.NextToken;
  } while (NextToken);
  // Pagination can interleave pages; keep every series sorted.
  for (const k of Object.keys(out)) {
    const idx = out[k].t.map((_, i) => i).sort((a, b) => out[k].t[a] - out[k].t[b]);
    out[k] = { t: idx.map((i) => out[k].t[i]), v: idx.map((i) => out[k].v[i]) };
  }
  return out;
}

/** Top statements by database load from Performance Insights (7 days, the free retention), or why there are none. */
export async function topStatements(t: LoadTarget, now = Date.now()): Promise<StatementsResult> {
  const base = { enabled: t.performance_insights, window_days: STATEMENT_WINDOW_DAYS, statements: [] as StatementsResult["statements"] };
  if (!t.performance_insights || !t.dbi_resource_id) return { ...base, note: `Performance Insights is off on ${t.writer || t.id}: enable it (7 days of retention are free) to see which statements make the load` };
  try {
    const pi = clients().pi(t.region);
    const r = await pi.send(new DescribeDimensionKeysCommand({
      ServiceType: "RDS", Identifier: t.dbi_resource_id, StartTime: new Date(now - STATEMENT_WINDOW_DAYS * 86400000), EndTime: new Date(now),
      Metric: "db.load.avg", PeriodInSeconds: 3600, GroupBy: { Group: "db.sql_tokenized", Dimensions: ["db.sql_tokenized.statement"], Limit: 10 },
    }));
    const keys = (r.Keys ?? []).map((k) => ({ sql: String(k.Dimensions?.["db.sql_tokenized.statement"] || "").replace(/\s+/g, " ").trim().slice(0, 400), load_avg: Number(k.Total ?? 0) })).filter((k) => k.sql);
    const total = keys.reduce((a, k) => a + k.load_avg, 0) || 1;
    return { ...base, statements: keys.map((k) => ({ ...k, load_avg: round(k.load_avg, 3), share_pct: round((k.load_avg / total) * 100, 1) })) };
  } catch (e) {
    return { ...base, error: describeError(e, `performance insights ${t.writer || t.id} (pi:DescribeDimensionKeys)`) };
  }
}

const normaliseSql = (sql: string) => sql.replace(/\s+/g, " ").replace(/'[^']*'/g, "'?'").replace(/\b\d+(\.\d+)?\b/g, "?").replace(/\$\d+/g, "$?").trim().slice(0, 300);

/** Aggregates `duration: N ms  statement: ...` lines (Postgres) or `# Query_time:` blocks (MySQL) from log text. */
export function parseSlowLog(text: string): Omit<SlowLogResult, "files" | "error" | "note"> {
  const lines = text.split(/\r?\n/);
  const agg = new Map<string, { sql: string; count: number; total_ms: number; max_ms: number }>();
  const add = (sql: string, ms: number) => {
    const key = normaliseSql(sql); if (!key) return;
    const e = agg.get(key) || { sql: key, count: 0, total_ms: 0, max_ms: 0 };
    e.count++; e.total_ms += ms; e.max_ms = Math.max(e.max_ms, ms); agg.set(key, e);
  };
  let durationLines = 0, tempLines = 0, checkpointLines = 0;
  let pendingMysqlMs: number | null = null;
  for (const line of lines) {
    const pg = line.match(/duration:\s*([\d.]+)\s*ms\s+(?:statement|execute [^:]+):\s*(.+)$/);
    if (pg) { durationLines++; add(pg[2], Number(pg[1])); continue; }
    if (/temporary file:/.test(line)) tempLines++;
    else if (/checkpoint (starting|complete)/.test(line)) checkpointLines++;
    const my = line.match(/^# Query_time:\s*([\d.]+)/);
    if (my) { pendingMysqlMs = Number(my[1]) * 1000; continue; }
    if (pendingMysqlMs != null && !/^(#|SET timestamp|use )/i.test(line) && line.trim()) { durationLines++; add(line, pendingMysqlMs); pendingMysqlMs = null; }
  }
  const statements = [...agg.values()].sort((a, b) => b.total_ms - a.total_ms).slice(0, 10).map((s) => ({ ...s, total_ms: Math.round(s.total_ms), max_ms: Math.round(s.max_ms) }));
  return { lines_scanned: lines.length, duration_lines: durationLines, temp_file_lines: tempLines, checkpoint_lines: checkpointLines, statements };
}

/** The tail of the newest engine log on the writer: slow statements when durations are logged, plus temp-file and checkpoint counts. */
export async function slowLog(t: LoadTarget): Promise<SlowLogResult> {
  const empty: SlowLogResult = { files: [], lines_scanned: 0, duration_lines: 0, temp_file_lines: 0, checkpoint_lines: 0, statements: [] };
  const instance = t.writer || t.id;
  try {
    const rds = clients().rds(t.region);
    const list = await rds.send(new DescribeDBLogFilesCommand({ DBInstanceIdentifier: instance }));
    const files = (list.DescribeDBLogFiles ?? []).filter((f) => f.LogFileName && (f.Size ?? 0) > 0 && !/audit/i.test(f.LogFileName)).sort((a, b) => (b.LastWritten ?? 0) - (a.LastWritten ?? 0)).slice(0, 2);
    if (!files.length) return { ...empty, note: `no log files on ${instance}` };
    let text = "";
    for (const f of files) {
      const r = await rds.send(new DownloadDBLogFilePortionCommand({ DBInstanceIdentifier: instance, LogFileName: f.LogFileName!, NumberOfLines: LOG_TAIL_LINES }));
      text += (r.LogFileData || "") + "\n";
    }
    const parsed = parseSlowLog(text);
    const engine = String(t.engine || "");
    const note = parsed.duration_lines ? undefined
      : /postgres/i.test(engine) ? "no statement durations in the log: set log_min_duration_statement (for example 500) in the cluster parameter group to see the slow statements"
      : /mysql|mariadb/i.test(engine) ? "no slow-query entries in the log: set slow_query_log = 1 and long_query_time in the parameter group, with log_output = FILE" : undefined;
    return { ...parsed, files: files.map((f) => f.LogFileName!), note };
  } catch (e) {
    return { ...empty, error: describeError(e, `engine log ${instance} (rds:DescribeDBLogFiles, rds:DownloadDBLogFilePortion)`) };
  }
}

// ---- Jev --------------------------------------------------------------------------------------------------------

export const loadQuestions = () => ({
  shape: choice("What is the shape of this database's load over the window?", LOAD_SHAPES),
  io_cause: choice("What most likely drives the storage I/O?", IO_CAUSES),
  throttled_by_cap: noul("While it is working, the database is held at its capacity ceiling (the maximum ACU) rather than settling below it"),
  structural: noul("The I/O and capacity pattern is structural: the same shape across the whole window rather than a one-off event, so a storage tier or capacity decision based on it will hold"),
  lever: choice("Which single change would do most for the cost or the read pressure of this database?", LEVERS),
});

/** What Jev sees: the profile without the per-sample lists, the top statements and the slow-log summary. */
export function loadState(profile: LoadProfile, statements: StatementsResult | null, slow: SlowLogResult | null) {
  const { daily, capacity, ...rest } = profile;
  return {
    ...rest,
    capacity: capacity ? { ...capacity, bursts: { ...capacity.bursts, sample: capacity.bursts.sample.slice(-6) } } : null,
    daily: daily.slice(-7),
    top_statements: statements?.statements.slice(0, 6).map((s) => ({ share_pct: s.share_pct, sql: s.sql.slice(0, 200) })) ?? (statements?.note || statements?.error || "not collected"),
    slow_log: slow ? { duration_lines: slow.duration_lines, temp_file_lines: slow.temp_file_lines, checkpoint_lines: slow.checkpoint_lines, top: slow.statements.slice(0, 5).map((s) => ({ count: s.count, total_ms: s.total_ms, sql: s.sql.slice(0, 200) })), note: slow.note || slow.error } : "not collected",
  };
}

export function parseLoadAnswers(answers: any, meta: { model?: string; call_id?: number; latency_ms?: number } = {}): LoadClassification | null {
  const s = answers?.shape, c = answers?.io_cause, t = answers?.throttled_by_cap, st = answers?.structural, l = answers?.lever;
  if (s?.type !== "choice" || c?.type !== "choice" || t?.type !== "noul" || st?.type !== "noul" || l?.type !== "choice") return null;
  const pick = <K extends string>(v: unknown, keys: readonly K[], fallback: K | "unknown"): K | "unknown" => (keys.includes(v as K) ? (v as K) : fallback);
  return {
    shape: pick(s.choice, Object.keys(LOAD_SHAPES) as LoadShape[], "unknown"), shape_confidence: Number(s.confidence ?? 0),
    io_cause: pick(c.choice, Object.keys(IO_CAUSES) as IoCause[], "unknown") as IoCause, io_cause_confidence: Number(c.confidence ?? 0),
    throttled_by_cap: Number(t.noul), structural: Number(st.noul),
    lever: pick(l.choice, Object.keys(LEVERS) as Lever[], "unknown"), lever_confidence: Number(l.confidence ?? 0),
    ...meta, classified_at: new Date().toISOString(),
  };
}

// ---- storage and the flow -------------------------------------------------------------------------------------

const safeJson = (s: unknown) => { if (typeof s !== "string") return null; try { return JSON.parse(s); } catch { return null; } };
const rowToLoad = (r: any): RdsLoadRow => ({ id: r.id, target_id: r.target_id, kind: r.kind, region: r.region, collected_at: r.collected_at, profile: safeJson(r.profile), statements: safeJson(r.statements), slow_log: safeJson(r.slow_log), jev: safeJson(r.jev), profile_hash: r.profile_hash ?? null, error: r.error });

/** The latest stored profile for a cluster or instance id (also found through the instance's cluster). */
export function latestRdsLoad(id: string): RdsLoadRow | null {
  const row = db.prepare("select * from rds_load_profiles where target_id = ? order by id desc limit 1").get(id) as any;
  if (row) return rowToLoad(row);
  const cluster = (db.prepare("select cluster from inventory_rds where db_instance_identifier = ?").get(id) as { cluster: string | null } | undefined)?.cluster;
  if (!cluster) return null;
  const viaCluster = db.prepare("select * from rds_load_profiles where target_id = ? order by id desc limit 1").get(cluster) as any;
  return viaCluster ? rowToLoad(viaCluster) : null;
}

const ageHours = (iso: string) => (Date.now() - new Date(iso.replace(" ", "T") + (iso.endsWith("Z") ? "" : "Z")).getTime()) / 3600000;

/** What a classification depends on: the shape and the deciding numbers, coarsely rounded, so an hourly refresh reuses Jev's answer until the picture changes. */
export function profileHash(p: LoadProfile, statements: StatementsResult | null): string {
  const c = p.capacity;
  const coarse = (v: number | null, step: number) => (v == null ? null : Math.round(v / step) * step);
  // Counts on a log scale (buckets of x1.5), so a 10% drift in reads keeps the hash and a doubling changes it.
  const magnitude = (v: number | null) => (v == null || v <= 0 ? null : Math.round(Math.log(v) / Math.log(1.5)));
  const key = {
    shape: p.shape, reads: magnitude(p.io.reads_per_day), writes: magnitude(p.io.writes_per_day), hit: coarse(p.io.buffer_cache_hit_pct_avg, 2),
    cap: c ? { at_cap: coarse(c.pct_time_at_cap, 0.1), at_floor: coarse(c.pct_time_at_floor, 0.1), per_day: coarse(c.bursts.per_day, 2), cadence: c.bursts.cadence, fits_avg: c.db_fits_in_cache_at_avg, fits_cap: c.db_fits_in_cache_at_cap, configured: `${c.configured_min}-${c.configured_max}` } : null,
    cpu: coarse(p.cpu.avg_pct, 10), top: statements?.statements.slice(0, 3).map((s) => s.sql.slice(0, 80)) ?? [],
  };
  return createHash("sha1").update(JSON.stringify(key)).digest("hex").slice(0, 16);
}

export const JEV_REUSE_HOURS = 24;

/**
 * Collects the profile, the statements and the log, asks Jev, stores the row. Throws when the target cannot be
 * resolved or CloudWatch fails. jev "auto" (the hourly pass) reuses the previous classification while the
 * profile hash is unchanged and the answer is under a day old; true always asks; false never does.
 */
export async function refreshRdsLoad(id: string, opts: { region?: string; onLog?: (l: string) => void; jev?: boolean | "auto" } = {}): Promise<RdsLoadRow> {
  const log = opts.onLog || (() => {});
  const target = await resolveTarget(id, { region: opts.region });
  const series = await fetchSeries(target);
  const profile = buildProfile(target, series);
  const [statements, slow] = await Promise.all([topStatements(target), slowLog(target)]);
  log(`${target.kind} ${target.id}: ${profile.shape}${profile.capacity ? `, ${profile.capacity.avg_acu} ACU avg, at the cap ${Math.round(profile.capacity.pct_time_at_cap * 100)}%, ${profile.capacity.bursts.per_day} bursts/day` : ""}, ${profile.io.reads_per_day ?? "?"} reads/day, ${statements.statements.length} statements, ${slow.duration_lines} slow-log lines`);
  const hash = profileHash(profile, statements);
  const previous = latestRdsLoad(target.id);
  let jev: LoadClassification | null = null;
  const reuse = opts.jev === "auto" && previous?.jev && previous.profile_hash === hash && ageHours(previous.jev.classified_at) < JEV_REUSE_HOURS;
  if (reuse) { jev = previous!.jev; log(`  Jev: unchanged (${jev!.shape}, lever ${jev!.lever.replace(/_/g, " ")}); reused`); }
  else if (opts.jev !== false && jevEnabled()) {
    const res = await askJev(loadState(profile, statements, slow), loadQuestions(), { purpose: "rds_load" });
    jev = res ? parseLoadAnswers(res.answers, { model: res.model, call_id: res.call_id, latency_ms: res.latency_ms }) : null;
    if (jev) log(`  Jev: ${jev.shape} (${Math.round(jev.shape_confidence * 100)}%), I/O from ${jev.io_cause.replace(/_/g, " ")} (${Math.round(jev.io_cause_confidence * 100)}%), throttled ${Math.round(jev.throttled_by_cap * 100)}%, structural ${Math.round(jev.structural * 100)}%, lever ${jev.lever.replace(/_/g, " ")}`);
  }
  const rowId = Number(db.prepare("insert into rds_load_profiles(target_id, kind, region, profile, statements, slow_log, jev, profile_hash, error) values (?, ?, ?, ?, ?, ?, ?, ?, null)")
    .run(target.id, target.kind, target.region, JSON.stringify(profile), JSON.stringify(statements), JSON.stringify(slow), jev ? JSON.stringify(jev) : null, hash).lastInsertRowid);
  // One row per target is enough history for the UI; keep the last five.
  db.prepare("delete from rds_load_profiles where target_id = ? and id not in (select id from rds_load_profiles where target_id = ? order by id desc limit 5)").run(target.id, target.id);
  return rowToLoad(db.prepare("select * from rds_load_profiles where id = ?").get(rowId));
}

/** The stored profile when it is younger than maxAgeHours, else a fresh one; null (logged) when collection fails. */
export async function ensureRdsLoad(id: string, maxAgeHours: number, onLog: (l: string) => void = () => {}): Promise<RdsLoadRow | null> {
  const have = latestRdsLoad(id);
  if (have && ageHours(have.collected_at) < maxAgeHours) return have;
  try { return await refreshRdsLoad(id, { onLog }); }
  catch (e) { onLog(`${id}: load profile failed: ${describeError(e, `rds load ${id} (cloudwatch:GetMetricData, rds:DescribeDBClusters)`)}`); return have; }
}

/** The compact form the resolution facts and the rules carry: the numbers that decide, Jev's read, the top statements. */
export function loadSummary(row: RdsLoadRow | null) {
  if (!row?.profile) return null;
  const p = row.profile, c = p.capacity;
  return {
    collected_at: row.collected_at, window_days: p.window_days, shape: p.shape, notes: p.notes,
    io: p.io,
    capacity: c ? { configured: c.configured_min != null ? `${c.configured_min}-${c.configured_max} ACU` : null, avg_acu: c.avg_acu, pct_time_at_cap: c.pct_time_at_cap, pct_time_at_floor: c.pct_time_at_floor, bursts_per_day: c.bursts.per_day, burst_median_minutes: c.bursts.median_minutes, cadence: c.bursts.cadence, cache_gib_avg: c.cache_gib_avg, cache_gib_at_cap: c.cache_gib_at_cap, db_fits_in_cache_at_avg: c.db_fits_in_cache_at_avg, db_fits_in_cache_at_cap: c.db_fits_in_cache_at_cap } : null,
    cpu: p.cpu, connections: p.connections,
    jev: row.jev,
    top_statements: row.statements?.statements.slice(0, 5).map((s) => ({ share_pct: s.share_pct, sql: s.sql.slice(0, 160) })) ?? [],
    statements_note: row.statements?.note || row.statements?.error || null,
    slow_log: row.slow_log ? { duration_lines: row.slow_log.duration_lines, temp_file_lines: row.slow_log.temp_file_lines, top: row.slow_log.statements.slice(0, 3).map((s) => ({ count: s.count, total_ms: s.total_ms, sql: s.sql.slice(0, 160) })), note: row.slow_log.note || row.slow_log.error || null } : null,
  };
}
export type RdsLoadSummary = NonNullable<ReturnType<typeof loadSummary>>;

// ---- the hourly pass -------------------------------------------------------------------------------------------

export interface RdsLoadPassResult { candidates: number; refreshed: string[]; skipped: number; failed: { id: string; message: string }[]; took_ms: number }

/** Every database the inventory knows (a cluster once, standalone instances by id), skipping those profiled within the probe interval. */
export function rdsLoadTargets(minIntervalHours = config.probeMinIntervalHours): { id: string; region: string }[] {
  const rows = db.prepare("select db_instance_identifier, cluster, region from inventory_rds where gone = 0 order by cluster, db_instance_identifier").all() as { db_instance_identifier: string; cluster: string | null; region: string }[];
  const seen = new Map<string, string>();
  for (const r of rows) { const id = r.cluster || r.db_instance_identifier; if (!seen.has(id)) seen.set(id, r.region); }
  const windowMin = Math.max(1, Math.round(minIntervalHours * 60) - 5);
  const fresh = db.prepare("select 1 from rds_load_profiles where target_id = ? and datetime(collected_at) > datetime('now', ?) limit 1");
  return [...seen.entries()].filter(([id]) => !fresh.get(id, `-${windowMin} minutes`)).map(([id, region]) => ({ id, region }));
}

let passInFlight: Promise<RdsLoadPassResult> | null = null;

/**
 * The database half of the hourly probe pass: refreshes the load profile of every database in the inventory
 * (CloudWatch, Performance Insights, the log tail), with Jev re-asked only when the picture changed. A
 * permission failure stops the pass early; the rest is logged per database.
 */
export function rdsLoadPass(limit = 50): Promise<RdsLoadPassResult> {
  if (passInFlight) return passInFlight;
  passInFlight = (async () => {
    const t0 = Date.now();
    const targets = rdsLoadTargets().slice(0, limit);
    const result: RdsLoadPassResult = { candidates: targets.length, refreshed: [], skipped: 0, failed: [], took_ms: 0 };
    const queue = [...targets];
    const worker = async () => {
      for (let t = queue.shift(); t; t = queue.shift()) {
        try { await refreshRdsLoad(t.id, { region: t.region, jev: "auto", onLog: (l) => console.log(`[rds-load] ${l}`) }); result.refreshed.push(t.id); }
        catch (e: any) {
          const message = describeError(e, `rds load ${t.id} (cloudwatch:GetMetricData, rds:DescribeDBClusters)`, 200);
          result.failed.push({ id: t.id, message });
          if (/AccessDenied|not authorized|NoSdkCredentials|no AWS credentials/i.test(message)) { result.skipped += queue.length; queue.length = 0; }
        }
      }
    };
    await Promise.all([worker(), worker()]);
    result.took_ms = Date.now() - t0;
    console.log(`[rds-load] ${result.refreshed.length} database(s) profiled, ${result.failed.length} failed of ${result.candidates} due in ${result.took_ms} ms${result.failed[0] ? ` (first failure: ${result.failed[0].message})` : ""}`);
    return result;
  })().finally(() => { passInFlight = null; });
  return passInFlight;
}

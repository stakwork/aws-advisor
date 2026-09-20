/**
 * Pure analysis over the statistics the advisor collects (daily roll-ups, container days, baselines, spend per
 * service per day): sustained idleness, disk-fill forecasts, idle containers, memory pressure and spend step
 * changes. No I/O; src/review.ts feeds it and stores the results.
 */
export interface DailyRow { day: string; samples: number; mem_pct_avg: number | null; mem_pct_max: number | null; disk_pct_avg: number | null; disk_pct_max: number | null; load_per_cpu_avg: number | null; load_per_cpu_max: number | null; containers_running_avg: number | null }
export interface ContainerStat { name: string; image: string | null; days: number; running_share: number | null; cpu_pct_avg: number | null; cpu_pct_max: number | null; mem_bytes_avg: number | null }

export const REVIEW_MIN_DAYS = 5;
export const IDLE_MEM_AVG = 40, IDLE_MEM_MAX = 60, IDLE_LOAD_PER_CPU = 0.25, IDLE_CPU_P95 = 20;
export const PRESSURE_MEM_AVG = 85;
export const DISK_FULL_PCT = 90, DISK_HORIZON_DAYS = 60, DISK_URGENT_DAYS = 14;
export const CONTAINER_IDLE_CPU = 0.3;

const avg = (xs: number[]) => (xs.length ? xs.reduce((s, x) => s + x, 0) / xs.length : NaN);
const num = (v: unknown): number | null => (v == null || !Number.isFinite(Number(v)) ? null : Number(v));

export interface IdleVerdict { idle: boolean; days: number; mem_avg: number | null; mem_max: number | null; load_avg: number | null; load_max: number | null; cpu_p95: number | null; reasons: string[] }

/** Sustained idleness: memory low on average and at peak, load low relative to cores, CPU p95 low, over at least REVIEW_MIN_DAYS. */
export function sustainedIdle(rows: DailyRow[], cpuP95: number | null): IdleVerdict {
  const days = rows.length;
  const mem = rows.map((r) => num(r.mem_pct_avg)).filter((x): x is number => x != null);
  const memMax = rows.map((r) => num(r.mem_pct_max)).filter((x): x is number => x != null);
  const load = rows.map((r) => num(r.load_per_cpu_avg)).filter((x): x is number => x != null);
  const loadMax = rows.map((r) => num(r.load_per_cpu_max)).filter((x): x is number => x != null);
  const v: IdleVerdict = { idle: false, days, mem_avg: mem.length ? avg(mem) : null, mem_max: memMax.length ? Math.max(...memMax) : null, load_avg: load.length ? avg(load) : null, load_max: loadMax.length ? Math.max(...loadMax) : null, cpu_p95: cpuP95, reasons: [] };
  if (days < REVIEW_MIN_DAYS) { v.reasons.push(`only ${days} day${days === 1 ? "" : "s"} of probes`); return v; }
  if (v.mem_avg == null || v.load_avg == null) { v.reasons.push("no memory or load data"); return v; }
  const memIdle = v.mem_avg < IDLE_MEM_AVG && (v.mem_max ?? 0) < IDLE_MEM_MAX;
  const loadIdle = v.load_avg < IDLE_LOAD_PER_CPU && (v.load_max ?? 0) < 1;
  const cpuIdle = cpuP95 == null || cpuP95 < IDLE_CPU_P95;
  if (memIdle) v.reasons.push(`memory ${v.mem_avg.toFixed(0)}% on average, ${v.mem_max?.toFixed(0)}% at peak`);
  if (loadIdle) v.reasons.push(`load ${(v.load_avg * 100).toFixed(0)}% of cores on average, ${((v.load_max ?? 0) * 100).toFixed(0)}% at peak`);
  if (cpuIdle && cpuP95 != null) v.reasons.push(`CPU p95 ${cpuP95.toFixed(0)}% over 14 days`);
  v.idle = memIdle && loadIdle && cpuIdle;
  return v;
}

export interface DiskForecast { slope_pct_day: number; now_pct: number; days_to_full: number | null; r2: number; days: number }

/** Least-squares line through disk usage per day; days until DISK_FULL_PCT at the current rate, null when flat or falling. */
export function diskForecast(rows: DailyRow[]): DiskForecast | null {
  const pts = rows.map((r, i) => ({ x: i, y: num(r.disk_pct_avg) })).filter((p): p is { x: number; y: number } => p.y != null);
  if (pts.length < REVIEW_MIN_DAYS) return null;
  const n = pts.length; const mx = avg(pts.map((p) => p.x)); const my = avg(pts.map((p) => p.y));
  const sxx = pts.reduce((s, p) => s + (p.x - mx) ** 2, 0); const sxy = pts.reduce((s, p) => s + (p.x - mx) * (p.y - my), 0);
  const slope = sxx > 0 ? sxy / sxx : 0; const icept = my - slope * mx;
  const ssTot = pts.reduce((s, p) => s + (p.y - my) ** 2, 0); const ssRes = pts.reduce((s, p) => s + (p.y - (icept + slope * p.x)) ** 2, 0);
  const r2 = ssTot > 0 ? 1 - ssRes / ssTot : 1;
  const now = icept + slope * (n - 1);
  const daysToFull = slope > 0.05 ? (DISK_FULL_PCT - now) / slope : null;
  return { slope_pct_day: slope, now_pct: now, days_to_full: daysToFull != null && daysToFull > 0 ? daysToFull : daysToFull != null ? 0 : null, r2, days: n };
}

export function memoryPressure(rows: DailyRow[]): { pressure: boolean; days: number; mem_avg: number | null; mem_max: number | null } {
  const mem = rows.map((r) => num(r.mem_pct_avg)).filter((x): x is number => x != null);
  const memMax = rows.map((r) => num(r.mem_pct_max)).filter((x): x is number => x != null);
  const memAvg = mem.length ? avg(mem) : null;
  return { pressure: rows.length >= REVIEW_MIN_DAYS && memAvg != null && memAvg >= PRESSURE_MEM_AVG, days: rows.length, mem_avg: memAvg, mem_max: memMax.length ? Math.max(...memMax) : null };
}

/** Containers that ran most of the window and used almost no CPU: candidates to remove or to stop scheduling. */
export function idleContainers(stats: ContainerStat[], windowDays: number): ContainerStat[] {
  return stats.filter((c) => c.days >= Math.min(REVIEW_MIN_DAYS, windowDays) && (c.running_share ?? 0) >= 0.9 && c.cpu_pct_avg != null && c.cpu_pct_avg < CONTAINER_IDLE_CPU && (c.cpu_pct_max ?? 0) < 5);
}

export interface SpendStep { service: string; recent_avg: number; median: number; mad: number; ratio: number; recent_days: number; excess_per_day: number }

/** A service whose last complete days sit well above its 60-day median: more than 3 spreads and 30 % up, and at least 20 USD a day. The median of the recent days is used, so a one-off charge (a reservation purchase) on one day is not a step. */
export function spendStep(service: string, recent: number[], baseline: { median: number | null; mad: number | null } | null, minExcess = 20): SpendStep | null {
  if (!baseline || baseline.median == null || recent.length < 2) return null;
  const sorted = [...recent].sort((a, b) => a - b); const r = sorted.length % 2 ? sorted[(sorted.length - 1) / 2] : (sorted[sorted.length / 2 - 1] + sorted[sorted.length / 2]) / 2; const mad = baseline.mad ?? 0;
  const excess = r - baseline.median;
  if (excess < Math.max(3 * mad, minExcess) || r < 1.3 * baseline.median) return null;
  return { service, recent_avg: r, median: baseline.median, mad, ratio: baseline.median > 0 ? r / baseline.median : Infinity, recent_days: recent.length, excess_per_day: excess };
}

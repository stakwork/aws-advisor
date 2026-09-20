/**
 * Robust statistics for baselines: median and MAD instead of mean and standard deviation (a spike must not move
 * its own baseline), a seasonal profile by hour of day and by day of week when there is enough history, and a
 * score that says how far a new value sits from what is typical at that moment. Pure functions, no I/O.
 */
export interface Point { t: number; v: number }

export interface RobustStats { samples: number; median: number; mad: number; p95: number; mean: number; max: number; min: number }

export interface Seasonal {
  /** median per hour of day (UTC), null where fewer than MIN_PER_BUCKET samples */
  by_hour: (number | null)[];
  /** median per day of week (0 = Sunday, UTC) */
  by_dow: (number | null)[];
  /** distinct days the points span */
  days: number;
}

export interface Baseline extends RobustStats, Seasonal { window_days: number; source: string; unit: string | null; computed_at?: string }

export interface Score { expected: number; ratio: number | null; z: number | null; level: "normal" | "high" | "extreme"; basis: "hour" | "median" }

const MIN_PER_BUCKET = 5;
export const MIN_DAYS_FOR_SEASONAL = 7;

export function quantile(sorted: number[], q: number): number {
  if (!sorted.length) return NaN;
  const pos = (sorted.length - 1) * q; const lo = Math.floor(pos); const hi = Math.ceil(pos);
  return sorted[lo] + (sorted[hi] - sorted[lo]) * (pos - lo);
}
export const median = (values: number[]): number => quantile([...values].sort((a, b) => a - b), 0.5);

export function robustStats(values: number[]): RobustStats {
  const v = values.filter(Number.isFinite);
  if (!v.length) return { samples: 0, median: NaN, mad: NaN, p95: NaN, mean: NaN, max: NaN, min: NaN };
  const sorted = [...v].sort((a, b) => a - b);
  const med = quantile(sorted, 0.5);
  // 1.4826 makes the MAD comparable to a standard deviation for normal data
  const mad = 1.4826 * median(v.map((x) => Math.abs(x - med)));
  return { samples: v.length, median: med, mad, p95: quantile(sorted, 0.95), mean: v.reduce((s, x) => s + x, 0) / v.length, max: sorted[sorted.length - 1], min: sorted[0] };
}

export function seasonal(points: Point[]): Seasonal {
  const byHour: number[][] = Array.from({ length: 24 }, () => []);
  const byDow: number[][] = Array.from({ length: 7 }, () => []);
  const days = new Set<string>();
  for (const p of points) {
    if (!Number.isFinite(p.v)) continue;
    const d = new Date(p.t);
    byHour[d.getUTCHours()].push(p.v); byDow[d.getUTCDay()].push(p.v);
    days.add(d.toISOString().slice(0, 10));
  }
  const enough = days.size >= MIN_DAYS_FOR_SEASONAL;
  return {
    by_hour: byHour.map((b) => (enough && b.length >= MIN_PER_BUCKET ? median(b) : null)),
    by_dow: byDow.map((b) => (enough && b.length >= MIN_PER_BUCKET ? median(b) : null)),
    days: days.size,
  };
}

export function buildBaseline(points: Point[], window_days: number, source: string, unit: string | null): Baseline {
  return { ...robustStats(points.map((p) => p.v)), ...seasonal(points), window_days, source, unit };
}

/** How unusual is `value` at time `at`, given the baseline: the hour-of-day median when the profile exists, else the overall median. */
export function scoreValue(b: Pick<Baseline, "median" | "mad" | "by_hour" | "p95">, value: number, at: Date = new Date()): Score {
  const hourly = b.by_hour?.[at.getUTCHours()];
  const basis: Score["basis"] = hourly != null ? "hour" : "median";
  const expected = hourly ?? b.median;
  const ratio = expected > 0 ? value / expected : null;
  // spread is measured from what is expected NOW (the hour's median when there is a profile): a busy hour is not an anomaly
  const z = Number.isFinite(b.mad) && b.mad > 0 ? (value - expected) / b.mad : null;
  // extreme: far above the typical value for this hour AND far outside the spread; high: one of the two
  const far = ratio != null && ratio >= 2; const out = z != null && z >= 3;
  const level: Score["level"] = far && out && value > b.p95 ? "extreme" : far || out ? "high" : "normal";
  return { expected, ratio, z, level, basis };
}

import { db } from "./db.js";
import { credentialGate } from "./gate.js";
import { describeError } from "./permissions.js";
import { S, query } from "./steampipe.js";
import { addDays, localDay } from "./localdate.js";
import { SpendMetric, SpendRow, SpendSummary, summarizeSpend } from "./spend_math.js";

export type { SpendMetric, SpendRow, SpendSummary } from "./spend_math.js";
export { summarizeSpend } from "./spend_math.js";

/**
 * Daily spend from Cost Explorer (aws_cost_by_record_type_daily), kept in `spend_daily` so the Overview can
 * show today, the last 7 days, month to date with a projection and the previous month without a Cost Explorer
 * call per page view. One call per refresh, at most every 6 hours: every call is billed.
 */

export const SPEND_DAYS = 45;
export const SPEND_MIN_INTERVAL_MS = 6 * 3600_000;
/** Record types that are real usage (what the account consumed), as opposed to credits, refunds, tax, fees, support. */
export const USAGE_RECORD_TYPES = ["Usage", "SavingsPlanCoveredUsage", "DiscountedUsage"] as const;

export function spendRows(days = SPEND_DAYS, today = localDay()): SpendRow[] {
  return db.prepare("select day, net_unblended, unblended, amortized, usage_only, fetched_at from spend_daily where day >= ? order by day").all(addDays(today, -(days - 1))) as SpendRow[];
}

/** The summary over everything stored (the previous month needs rows older than the 45-day series). */
export function spendSummary(today = localDay(), metric: SpendMetric = "net_unblended"): SpendSummary {
  const rows = db.prepare("select day, net_unblended, unblended, amortized, usage_only, fetched_at from spend_daily order by day").all() as SpendRow[];
  return summarizeSpend(rows, today, metric);
}

export function lastSpendFetch(): string | null {
  return (db.prepare("select max(fetched_at) as at from spend_daily").get() as { at: string | null }).at;
}

export interface SpendRefreshResult { refreshed: boolean; days?: number; fetched_at?: string; skipped?: string; error?: string }

const upsert = db.prepare(`
  insert into spend_daily(day, net_unblended, unblended, amortized, usage_only, fetched_at) values (?, ?, ?, ?, ?, ?)
  on conflict(day) do update set net_unblended = excluded.net_unblended, unblended = excluded.unblended, amortized = excluded.amortized, usage_only = excluded.usage_only, fetched_at = excluded.fetched_at`);

/**
 * One Cost Explorer call: the last 45 days, or back to the first of the previous month when that is earlier
 * (so the previous month is complete), summed per day and record type class. Skipped while the last fetch is
 * younger than 6 hours unless forced, and while the credential gate is closed.
 */
export async function refreshSpend(opts: { force?: boolean; onLog?: (line: string) => void } = {}): Promise<SpendRefreshResult> {
  const log = opts.onLog || ((l: string) => console.log(`[spend] ${l}`));
  const last = lastSpendFetch();
  if (!opts.force && last && Date.now() - Date.parse(last.replace(" ", "T") + "Z") < SPEND_MIN_INTERVAL_MS) {
    return { refreshed: false, skipped: `last fetch at ${last} is younger than 6 hours` };
  }
  const gate = await credentialGate("spend");
  if (!gate.ok) return { refreshed: false, skipped: gate.error };
  const usage = USAGE_RECORD_TYPES.map((t) => `'${t}'`).join(", ");
  const sql = `
    select to_char(period_start at time zone 'UTC', 'YYYY-MM-DD') as day,
           sum(net_unblended_cost_amount) as net_unblended,
           sum(unblended_cost_amount) as unblended,
           sum(amortized_cost_amount) as amortized,
           sum(case when record_type in (${usage}) then amortized_cost_amount else 0 end) as usage_only
    from ${S}.aws_cost_by_record_type_daily
    where period_start >= least(now() - interval '${SPEND_DAYS} days', date_trunc('month', now() - interval '1 month'))
    group by 1 order by 1`;
  let rows: { day: string; net_unblended: string | null; unblended: string | null; amortized: string | null; usage_only: string | null }[];
  try {
    rows = await query(sql);
  } catch (e) {
    const error = describeError(e, "spend refresh (aws_cost_by_record_type_daily)");
    log(`refresh failed: ${error}`);
    return { refreshed: false, error };
  }
  const fetchedAt = new Date().toISOString().replace("T", " ").slice(0, 19);
  const num = (v: string | null) => (v == null ? null : Number(v));
  db.transaction(() => {
    for (const r of rows) upsert.run(r.day, num(r.net_unblended), num(r.unblended), num(r.amortized), num(r.usage_only), fetchedAt);
  })();
  log(`${rows.length} days stored (${rows[0]?.day ?? "—"} to ${rows[rows.length - 1]?.day ?? "—"})`);
  return { refreshed: true, days: rows.length, fetched_at: fetchedAt };
}

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

/** Member accounts (src/accounts.ts): the payer's Cost Explorer sees every linked account; kept per month here for the Bill page's "By account". */
db.exec(`create table if not exists spend_by_account_monthly (month text not null, account_id text not null, usd real not null, fetched_at text not null, primary key (month, account_id))`);
/** What each linked account's month is made of: unblended cost per service, the last three months (one more Cost Explorer call per refresh). */
db.exec(`create table if not exists spend_by_account_service_monthly (month text not null, account_id text not null, service text not null, usd real not null, fetched_at text not null, primary key (month, account_id, service))`);

export interface AccountServiceSpendRow { month: string; account_id: string; service: string; usd: number }
/** The last `months` months per linked account and service, biggest first within a month. */
export function servicesByAccount(months = 3): AccountServiceSpendRow[] {
  return db.prepare("select month, account_id, service, usd from spend_by_account_service_monthly where month >= ? order by month desc, account_id, usd desc").all(monthsAgo(months)) as AccountServiceSpendRow[];
}

/** One Cost Explorer call: unblended cost per linked account per service per month, the last three months (aws_cost_usage, LINKED_ACCOUNT × SERVICE). Errors are returned, not thrown. */
export async function refreshSpendByAccountService(log: (l: string) => void = () => {}): Promise<{ rows: number; error?: string }> {
  const sql = `select dimension_1 as account_id, dimension_2 as service, to_char(period_start at time zone 'UTC', 'YYYY-MM') as month, sum(unblended_cost_amount) as usd
    from ${S}.aws_cost_usage where granularity = 'MONTHLY' and dimension_type_1 = 'LINKED_ACCOUNT' and dimension_type_2 = 'SERVICE'
      and period_start >= date_trunc('month', now() - interval '2 months') group by 1, 2, 3 order by 3, 1, 4 desc`;
  let rows: { account_id: string | null; service: string | null; month: string; usd: string | null }[];
  try { rows = await query(sql); } catch (e) { const error = describeError(e, "spend by account and service (aws_cost_usage)"); log(`by account and service failed: ${error}`); return { rows: 0, error }; }
  const at = new Date().toISOString().replace("T", " ").slice(0, 19);
  const up = db.prepare("insert into spend_by_account_service_monthly(month, account_id, service, usd, fetched_at) values (?, ?, ?, ?, ?) on conflict(month, account_id, service) do update set usd = excluded.usd, fetched_at = excluded.fetched_at");
  let n = 0;
  db.transaction(() => {
    // a service that dropped to nothing since the last fetch would otherwise keep its old figure: the months fetched are rewritten whole
    const months = [...new Set(rows.map((r) => r.month))];
    for (const m of months) db.prepare("delete from spend_by_account_service_monthly where month = ?").run(m);
    for (const r of rows) { if (!r.account_id || !r.service) continue; const usd = Number(r.usd ?? 0); if (!usd) continue; up.run(r.month, String(r.account_id), String(r.service), usd, at); n++; }
  })();
  log(`${n} account × service rows stored for ${new Set(rows.map((r) => r.month)).size} month(s)`);
  return { rows: n };
}

export interface AccountSpendRow { month: string; account_id: string; usd: number }
/** The last `months` months per linked account, newest first. */
export function spendByAccount(months = 6): AccountSpendRow[] {
  return db.prepare("select month, account_id, usd from spend_by_account_monthly where month >= ? order by month desc, usd desc").all(monthsAgo(months)) as AccountSpendRow[];
}
const monthsAgo = (n: number) => { const d = new Date(); d.setUTCDate(1); d.setUTCMonth(d.getUTCMonth() - n); return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, "0")}`; };

/** One Cost Explorer call: unblended cost per linked account per month (aws_cost_by_account_monthly). Errors are returned, not thrown: a member's line is a nicety. */
export async function refreshSpendByAccount(log: (l: string) => void = () => {}): Promise<{ rows: number; error?: string }> {
  const sql = `select linked_account_id as account_id, to_char(period_start at time zone 'UTC', 'YYYY-MM') as month, sum(unblended_cost_amount) as usd
    from ${S}.aws_cost_by_account_monthly where period_start >= date_trunc('month', now() - interval '6 months') group by 1, 2 order by 2, 1`;
  let rows: { account_id: string | null; month: string; usd: string | null }[];
  try { rows = await query(sql); } catch (e) { const error = describeError(e, "spend by account (aws_cost_by_account_monthly)"); log(`by account failed: ${error}`); return { rows: 0, error }; }
  const at = new Date().toISOString().replace("T", " ").slice(0, 19);
  const up = db.prepare("insert into spend_by_account_monthly(month, account_id, usd, fetched_at) values (?, ?, ?, ?) on conflict(month, account_id) do update set usd = excluded.usd, fetched_at = excluded.fetched_at");
  let n = 0;
  db.transaction(() => { for (const r of rows) { if (!r.account_id) continue; up.run(r.month, String(r.account_id), Number(r.usd ?? 0), at); n++; } })();
  log(`${n} account-month rows stored`);
  return { rows: n };
}

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
  await refreshSpendByAccount(log);
  await refreshSpendByAccountService(log);
  return { refreshed: true, days: rows.length, fetched_at: fetchedAt };
}

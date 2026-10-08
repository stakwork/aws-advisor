import { db } from "../../db.js";
import { AWS, type AttentionItem, type ProviderCost } from "../types.js";

/**
 * The AWS adapter's money and attention for the general overview: Cost Explorer's months per linked account
 * (src/spend.ts), the month's forecast (src/forecast.ts, else the spend projection), the latest collection run's alarm
 * findings by control and the open alerts of the last week.
 */

const rows = (sql: string, ...p: unknown[]): any[] => { try { return db.prepare(sql).all(...p) as any[]; } catch { return []; } };
const n = (v: unknown) => Number(v || 0);

export const awsCost = (primary: () => string): ProviderCost => ({
  refresh: async (opts = {}) => {
    const { refreshSpend } = await import("../../spend.js");
    const r = await refreshSpend(opts);
    return { refreshed: r.refreshed, note: r.refreshed ? `${r.days} days stored` : (r.skipped || r.error || "skipped") };
  },
  lastBill: (account) => {
    const thisMonth = new Date().toISOString().slice(0, 7);
    const spend = rows("select month, account_id, usd from spend_by_account_monthly where provider = ? and account_id = ? order by month desc", AWS, account || primary());
    const r = spend.find((s) => String(s.month) < thisMonth) ?? spend[0];
    return r ? { month: String(r.month), usd: n(r.usd) } : { month: null, usd: null };
  },
  month: async () => {
    let projected: number | null = null; let mtd: number | null = null;
    try { const { latestForecast } = await import("../../forecast.js"); const f: any = latestForecast(); projected = f?.forecast_net ?? null; mtd = f?.mtd_net ?? null; } catch { /* no forecast */ }
    if (projected == null) { try { const { spendSummary } = await import("../../spend.js"); const sp: any = spendSummary(); projected = sp?.month_to_date?.projected_month_end ?? null; mtd = sp?.month_to_date?.usd ?? null; } catch { /* no spend */ } }
    return [{ key: "projected", label: "AWS projected", usd: projected, to_total: true, month_to_date_usd: mtd }];
  },
  // every linked account the payer's Cost Explorer bills (unblended), each projected at the payer's pace
  accounts: async (opts) => (await import("../../spend_compare.js")).awsAccountBilling(undefined, opts?.basis ?? "amortized"),
});

export async function awsAttention(primary: string): Promise<AttentionItem[]> {
  const out: AttentionItem[] = [];
  const latestRun = rows("select id from runs where provider = ? and status = 'completed' order by id desc limit 1", AWS)[0];
  if (latestRun) for (const r of rows("select control_id, control_title, count(*) as c, min(coalesce(account_id, '')) as acct from findings where run_id = ? and status = 'alarm' group by control_id, control_title order by c desc limit 12", latestRun.id))
    out.push({ account: String(r.acct) || primary, level: "warning", count: n(r.c), what: `${r.control_title || r.control_id}: ${r.c} resource${n(r.c) === 1 ? "" : "s"}`, link: `/findings?control_id=${encodeURIComponent(String(r.control_id))}` });
  for (const r of rows("select kind, message, account_id from alerts where provider = ? and acknowledged = 0 and datetime(created_at) > datetime('now', '-7 days') order by id desc limit 10", AWS))
    out.push({ account: r.account_id || primary, level: "alarm", what: `${r.kind}: ${String(r.message).slice(0, 160)}`, link: "/alerts" });
  return out;
}

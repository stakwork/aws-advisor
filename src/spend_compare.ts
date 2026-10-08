import { db } from "./db.js";
import { addDays, daysInMonth, localDay, monthEnd, monthStart } from "./localdate.js";
import { AWS } from "./adapters/types.js";
import type { SpendRow } from "./spend_math.js";

/**
 * This month against the previous one, for someone keeping costs in check (GET /api/spend/compare): the same days of
 * both months side by side (Cost Explorer's daily rows, so the first week is not compared with a whole month), the
 * month's projection against last month's bill, the daily average, the months before, and which services moved.
 * The payer's numbers come from its daily rows and the forecast (src/forecast.ts); one member account has only Cost
 * Explorer's monthly rows per account and service, so its month is projected with the payer's run rate.
 */

export interface MonthTotal { month: string; usd: number; partial: boolean; projected: number | null }
export interface Mover { service: string; last_month: number; projected: number; mtd: number | null; delta: number; delta_pct: number | null; status: "new" | "gone" | "up" | "down" }
export interface LikeForLike { days: number; this_from: string; this_to: string; this_usd: number; last_from: string; last_to: string; last_usd: number; delta_usd: number; delta_pct: number | null }
export interface MonthComparison {
  month: string; previous_month: string;
  /** whose numbers these are: the payer's consolidated bill, or one linked account's line in it */
  kind: "payer" | "account"; account: string | null;
  metric: "net unblended" | "unblended";
  like_for_like: LikeForLike | null;
  month_to_date: number | null;
  projected: { usd: number | null; basis: "forecast" | "run rate" | null; last_month_usd: number | null; last_month_complete: boolean; delta_usd: number | null; delta_pct: number | null };
  daily_avg: { this_month: number | null; this_days: number; last_month: number | null; last_days: number };
  months: MonthTotal[];
  movers: Mover[];
  /** the services that moved, summed: what explains the change */
  moved: { up_usd: number; down_usd: number };
}

const round2 = (v: number) => Math.round(v * 100) / 100;
const pct = (now: number | null, then: number | null) => (now == null || then == null || then === 0 ? null : Math.round(((now - then) / then) * 1000) / 10);
const monthOf = (day: string) => day.slice(0, 7);
const shiftMonth = (m: string, n: number) => { const d = new Date(Date.UTC(Number(m.slice(0, 4)), Number(m.slice(5, 7)) - 1 + n, 1)); return d.toISOString().slice(0, 7); };

/** Pure: the first `n` complete days of this month against the first `n` days of the previous one (both capped at what each has). */
export function likeForLike(rows: SpendRow[], today: string, metric: "net_unblended" | "unblended" = "net_unblended"): LikeForLike | null {
  const yesterday = addDays(today, -1);
  const mFrom = monthStart(today);
  const have = rows.filter((r) => r[metric] != null);
  const thisDays = have.filter((r) => r.day >= mFrom && r.day <= yesterday).sort((a, b) => a.day.localeCompare(b.day));
  if (!thisDays.length) return null;
  const lastTo = thisDays[thisDays.length - 1].day;
  const n = Number(lastTo.slice(8, 10));
  const pFrom = monthStart(addDays(mFrom, -1));
  const pEnd = monthEnd(pFrom);
  const pTo = [addDays(pFrom, n - 1), pEnd].sort()[0];
  const lastDays = have.filter((r) => r.day >= pFrom && r.day <= pTo);
  if (!lastDays.length) return null;
  const s = (xs: SpendRow[]) => round2(xs.reduce((t, r) => t + Number(r[metric]), 0));
  const thisUsd = s(thisDays); const lastUsd = s(lastDays);
  return { days: n, this_from: mFrom, this_to: lastTo, this_usd: thisUsd, last_from: pFrom, last_to: pTo, last_usd: lastUsd, delta_usd: round2(thisUsd - lastUsd), delta_pct: pct(thisUsd, lastUsd) };
}

/**
 * Pure: services this month (projected to its end) against last month, biggest moves first. A service only last month
 * is "gone", one only this month "new". Moves under `min` dollars are left out: they explain nothing.
 */
export function movers(services: { service: string; last_month: number | null; projected: number; mtd?: number | null }[], limit = 10, min = 5): Mover[] {
  return services
    .map((s) => {
      const last = Number(s.last_month || 0); const proj = Number(s.projected || 0); const delta = round2(proj - last);
      const status: Mover["status"] = last < 0.5 && proj >= 0.5 ? "new" : proj < 0.5 && last >= 0.5 ? "gone" : delta >= 0 ? "up" : "down";
      return { service: s.service, last_month: round2(last), projected: round2(proj), mtd: s.mtd != null ? round2(s.mtd) : null, delta, delta_pct: pct(proj, last), status };
    })
    .filter((m) => Math.abs(m.delta) >= min)
    .sort((a, b) => Math.abs(b.delta) - Math.abs(a.delta))
    .slice(0, limit);
}

/** Pure: how much to multiply a month-to-date figure by to reach the month's end, from the payer's own projection (a pure time scaling), else linear by the day of the month. */
export function projectionFactor(projected: number | null, mtd: number | null, today: string): number {
  if (projected != null && mtd != null && mtd > 0 && projected >= mtd) return projected / mtd;
  const elapsed = Math.max(1, Number(today.slice(8, 10)) - 1);
  return daysInMonth(today) / elapsed;
}

export interface Pace { month_to_date: number; projected: number; daily_rate: number; through: string; like_for_like: LikeForLike | null }

/**
 * Pure: one account's month from its own days: what it spent so far, plus its typical recent day (the median of the
 * last seven complete days) for every day left. A charge posted once on the 1st (support, a reservation's fee) counts
 * once instead of being multiplied by the month. Null when the account has no day this month.
 */
export function accountPace(days: { day: string; usd: number }[], today: string): Pace | null {
  const mFrom = monthStart(today);
  const mine = days.filter((d) => d.day >= mFrom && d.day <= today).sort((a, b) => a.day.localeCompare(b.day));
  if (!mine.length) return null;
  const through = mine[mine.length - 1].day;
  const mtd = mine.reduce((t, d) => t + Number(d.usd), 0);
  // the newest day is still filling in when it is yesterday or today
  const complete = mine.filter((d) => d.day < addDays(today, -1)).slice(-7).map((d) => Number(d.usd)).sort((a, b) => a - b);
  const rate = complete.length ? (complete.length % 2 ? complete[(complete.length - 1) / 2] : (complete[complete.length / 2 - 1] + complete[complete.length / 2]) / 2) : mtd / mine.length;
  const left = daysInMonth(today) - Number(through.slice(8, 10));
  const rows: SpendRow[] = days.map((d) => ({ day: d.day, net_unblended: null, unblended: d.usd, amortized: null, usage_only: null, fetched_at: "" }));
  return { month_to_date: round2(mtd), projected: round2(mtd + rate * left), daily_rate: round2(rate), through, like_for_like: likeForLike(rows, today, "unblended") };
}

/** The payer's projection for this month: the forecast when it is this month's, else the spend summary's run rate. */
export async function payerProjection(today = localDay()): Promise<{ usd: number | null; mtd: number | null; basis: "forecast" | "run rate" | null; forecast: any | null }> {
  try {
    const { latestForecast } = await import("./forecast.js");
    const f: any = latestForecast();
    if (f && f.month === monthOf(today) && f.forecast_net != null) return { usd: f.forecast_net, mtd: f.mtd_net ?? null, basis: "forecast", forecast: f };
  } catch { /* no forecast yet */ }
  const { spendSummary } = await import("./spend.js");
  const s = spendSummary(today);
  return { usd: s.month_to_date.projected_month_end, mtd: s.month_to_date.usd, basis: s.month_to_date.projected_month_end != null ? "run rate" : null, forecast: null };
}

const accountMonths = (account: string | null, since: string): { month: string; usd: number }[] =>
  db.prepare(`select month, sum(usd) as usd from spend_by_account_monthly where provider = ? and month >= ? ${account ? "and account_id = ?" : ""} group by month order by month`).all(...[AWS, since, ...(account ? [account] : [])]) as { month: string; usd: number }[];
const accountServices = (account: string | null, month: string): Record<string, number> => {
  const out: Record<string, number> = {};
  for (const r of db.prepare(`select service, sum(usd) as usd from spend_by_account_service_monthly where provider = ? and month = ? ${account ? "and account_id = ?" : ""} group by service`).all(...[AWS, month, ...(account ? [account] : [])]) as { service: string; usd: number }[]) out[r.service] = Number(r.usd);
  return out;
};

/** The comparison for the payer (account null) or one linked account. */
export async function monthComparison(account: string | null, today = localDay()): Promise<MonthComparison> {
  const month = monthOf(today);
  const prevMonth = monthOf(addDays(monthStart(today), -1));
  const since = shiftMonth(month, -5);
  const proj = await payerProjection(today);
  const factor = projectionFactor(proj.usd, proj.mtd, today);

  if (!account) {
    const { spendSummary } = await import("./spend.js");
    const rows = db.prepare("select day, net_unblended, unblended, amortized, usage_only, fetched_at from spend_daily where provider = ? order by day").all(AWS) as SpendRow[];
    const s = spendSummary(today);
    const lfl = likeForLike(rows, today);
    const last = s.previous_month.usd;
    // the months before, from the per-account rows summed (unblended: Cost Explorer's per-account view), this one projected
    const months: MonthTotal[] = accountMonths(null, since).map((m) => ({ month: m.month, usd: round2(m.usd), partial: m.month === month, projected: m.month === month ? round2(m.usd * factor) : null }));
    // which services moved: the forecast's own per-service lines when it is this month's (net, the projection's terms), else the per-account rows
    const f = proj.forecast;
    const svc = f?.services?.length
      ? (f.services as any[]).map((x) => ({ service: x.service, last_month: x.last_month, projected: x.forecast, mtd: x.mtd }))
      : servicesFromRows(null, month, prevMonth, factor);
    const mv = movers(svc);
    const basisDays = s.month_to_date.projection_basis.days;
    return {
      month, previous_month: prevMonth, kind: "payer", account: null, metric: "net unblended",
      like_for_like: lfl, month_to_date: s.month_to_date.usd,
      projected: { usd: proj.usd, basis: proj.basis, last_month_usd: last, last_month_complete: s.previous_month.complete, delta_usd: proj.usd != null && last != null ? round2(proj.usd - last) : null, delta_pct: pct(proj.usd, last) },
      daily_avg: { this_month: s.month_to_date.projection_basis.daily_avg, this_days: basisDays, last_month: last != null && s.previous_month.days ? round2(last / s.previous_month.days) : null, last_days: s.previous_month.days },
      months, movers: mv, moved: sumMoves(mv),
    };
  }

  // one linked account: its own days when they are stored (src/spend.ts), else Cost Explorer's monthly rows at the payer's pace
  const am = accountMonths(account, since);
  const { spendByAccountDaily } = await import("./spend.js");
  const pace = accountPace(spendByAccountDaily(`${prevMonth}-01`).filter((d) => d.account_id === account), today);
  const cur = pace?.month_to_date ?? am.find((m) => m.month === month)?.usd ?? null;
  const last = am.find((m) => m.month === prevMonth)?.usd ?? null;
  const projected = pace ? pace.projected : cur != null ? round2(cur * factor) : null;
  const ratio = cur && projected != null ? projected / cur : factor;
  const mv = movers(servicesFromRows(account, month, prevMonth, ratio));
  const prevDays = daysInMonth(`${prevMonth}-01`);
  return {
    month, previous_month: prevMonth, kind: "account", account, metric: "unblended",
    like_for_like: pace?.like_for_like ?? null, month_to_date: cur != null ? round2(cur) : null,
    projected: { usd: projected, basis: projected != null ? (pace ? "run rate" : proj.basis) : null, last_month_usd: last != null ? round2(last) : null, last_month_complete: true, delta_usd: projected != null && last != null ? round2(projected - last) : null, delta_pct: pct(projected, last) },
    daily_avg: { this_month: pace ? pace.daily_rate : projected != null ? round2(projected / daysInMonth(today)) : null, this_days: pace ? Number(pace.through.slice(8, 10)) : Math.max(1, Number(today.slice(8, 10)) - 1), last_month: last != null ? round2(last / prevDays) : null, last_days: prevDays },
    months: am.map((m) => ({ month: m.month, usd: round2(m.month === month && cur != null ? cur : m.usd), partial: m.month === month, projected: m.month === month ? projected : null })),
    movers: mv, moved: sumMoves(mv),
  };
}

function servicesFromRows(account: string | null, month: string, prevMonth: string, factor: number) {
  const now = accountServices(account, month); const before = accountServices(account, prevMonth);
  return [...new Set([...Object.keys(now), ...Object.keys(before)])].map((service) => ({ service, last_month: before[service] ?? 0, projected: (now[service] ?? 0) * factor, mtd: now[service] ?? 0 }));
}
const sumMoves = (mv: Mover[]) => ({ up_usd: round2(mv.filter((m) => m.delta > 0).reduce((t, m) => t + m.delta, 0)), down_usd: round2(mv.filter((m) => m.delta < 0).reduce((t, m) => t + m.delta, 0)) });

// ---- every account's line: this month so far, projected, and last month --------------------------------------------

export interface AccountBillingLine { provider: string; account: string; name: string | null; registered: boolean; month_to_date_usd: number | null; projected_usd: number | null; last_month_usd: number | null; last_month: string | null; delta_pct: number | null; note?: string }

/** Pure: the AWS linked accounts' lines: each projected from its own days when there are any, else its month to date times `factor`; every account the payer bills, added to the advisor or not. */
export function awsAccountLines(rows: { month: string; account_id: string; usd: number }[], days: { day: string; account_id: string; usd: number }[], today: string, factor: number): Omit<AccountBillingLine, "name" | "registered">[] {
  const month = monthOf(today); const prevMonth = monthOf(addDays(monthStart(today), -1));
  const ids = [...new Set([...rows.filter((r) => r.month === month || r.month === prevMonth).map((r) => r.account_id), ...days.filter((d) => d.day >= `${month}-01`).map((d) => d.account_id)])];
  return ids.map((account) => {
    const pace = accountPace(days.filter((d) => d.account_id === account), today);
    const cur = pace?.month_to_date ?? rows.find((r) => r.account_id === account && r.month === month)?.usd ?? 0;
    const last = rows.find((r) => r.account_id === account && r.month === prevMonth)?.usd ?? null;
    const projected = pace ? pace.projected : round2(cur * factor);
    return { provider: AWS, account, month_to_date_usd: round2(cur), projected_usd: projected, last_month_usd: last != null ? round2(last) : null, last_month: prevMonth, delta_pct: pct(projected, last) };
  }).sort((a, b) => Number(b.projected_usd ?? 0) - Number(a.projected_usd ?? 0));
}

/** The AWS lines for the general view: every linked account Cost Explorer bills this month or last. */
export async function awsAccountBilling(today = localDay()): Promise<Omit<AccountBillingLine, "name" | "registered">[]> {
  const month = monthOf(today); const prevMonth = monthOf(addDays(monthStart(today), -1));
  const proj = await payerProjection(today);
  const { spendByAccountDaily } = await import("./spend.js");
  const rows = db.prepare("select month, account_id, usd from spend_by_account_monthly where provider = ? and month in (?, ?)").all(AWS, month, prevMonth) as { month: string; account_id: string; usd: number }[];
  return awsAccountLines(rows, spendByAccountDaily(`${month}-01`), today, projectionFactor(proj.usd, proj.mtd, today));
}

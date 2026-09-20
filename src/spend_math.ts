import { addDays, daysInMonth, localDay, monthEnd, monthStart } from "./localdate.js";

/** The spend summary math, pure (no database) so it can be tested on fixture rows. Used by src/spend.ts. */

export interface SpendRow { day: string; net_unblended: number | null; unblended: number | null; amortized: number | null; usage_only: number | null; fetched_at: string }
export type SpendMetric = "net_unblended" | "unblended" | "amortized" | "usage_only";

export interface SpendSummary {
  metric: SpendMetric;
  /** The last day with data; Cost Explorer usually lags about a day. */
  as_of: string | null;
  today: { day: string; usd: number | null };
  /** The most recent day Cost Explorer has anything for: today when it is in, else yesterday (usually still filling in). */
  latest: { day: string; usd: number; partial: boolean } | null;
  /** The 7 complete days ending on the last complete day with data (yesterday at the latest). */
  last_7_days: { from: string; to: string; usd: number | null; days: number };
  month_to_date: { from: string; to: string; usd: number | null; days: number; projected_month_end: number | null; projection_basis: { days: number; daily_avg: number | null } };
  previous_month: { from: string; to: string; usd: number | null; days: number; complete: boolean };
  fetched_at: string | null;
}

const sum = (rows: SpendRow[], metric: SpendMetric, from: string, to: string) => {
  const inRange = rows.filter((r) => r.day >= from && r.day <= to && r[metric] != null);
  return { usd: inRange.length ? round(inRange.reduce((s, r) => s + Number(r[metric]), 0)) : null, days: inRange.length };
};
const round = (v: number) => Math.round(v * 100) / 100;

/** Pure: the summary for a set of daily rows as seen on `today` (local server date). */
export function summarizeSpend(rows: SpendRow[], today = localDay(), metric: SpendMetric = "net_unblended"): SpendSummary {
  const withData = rows.filter((r) => r[metric] != null).sort((a, b) => a.day.localeCompare(b.day));
  const asOf = withData.length ? withData[withData.length - 1].day : null;
  const yesterday = addDays(today, -1);
  const todayRow = withData.find((r) => r.day === today);

  const to7 = asOf && asOf < yesterday ? asOf : yesterday;
  const from7 = addDays(to7, -6);
  const last7 = sum(withData, metric, from7, to7);

  const mFrom = monthStart(today);
  const mtd = sum(withData, metric, mFrom, today);
  // Today is always a partial day in Cost Explorer, so the daily average is taken over the complete days of the
  // month; when today is the only day with data it is all there is.
  let basis = sum(withData, metric, mFrom, yesterday);
  if (!basis.days) basis = mtd;
  const dailyAvg = basis.days && basis.usd != null ? basis.usd / basis.days : null;
  const projected = dailyAvg == null ? null : round(dailyAvg * daysInMonth(today));

  const pFrom = monthStart(addDays(mFrom, -1));
  const pTo = monthEnd(pFrom);
  const prev = sum(withData, metric, pFrom, pTo);

  return {
    metric,
    as_of: asOf,
    today: { day: today, usd: todayRow ? round(Number(todayRow[metric])) : null },
    latest: asOf ? { day: asOf, usd: round(Number(withData.find((r) => r.day === asOf)![metric])), partial: asOf >= yesterday } : null,
    last_7_days: { from: from7, to: to7, ...last7 },
    month_to_date: { from: mFrom, to: today, ...mtd, projected_month_end: projected, projection_basis: { days: basis.days, daily_avg: dailyAvg == null ? null : round(dailyAvg) } },
    previous_month: { from: pFrom, to: pTo, ...prev, complete: prev.days === daysInMonth(pFrom) },
    fetched_at: rows.reduce<string | null>((m, r) => (m == null || r.fetched_at > m ? r.fetched_at : m), null),
  };
}

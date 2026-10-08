/**
 * The team's bill by month, from its invoices. Vercel bills in more than one stream: the subscription (seats, the
 * plan, add-ons, the infrastructure usage) on its cycle day, and the Marketplace (the stores) on the 1st. A month's
 * bill is every invoice issued in it, and this month is projected as what is already issued plus, for each stream
 * not issued yet, its last invoice: the seats, plan and add-ons as they are now, and the latest usage. Pure, so the
 * arithmetic is tested.
 */

export interface InvoiceLike { created_at: string | null; total: number | null; status: string | null; source: string | null; groups?: unknown }
export interface InvoiceMonths {
  /** complete months, newest first */
  months: { month: string; usd: number }[];
  /** every month with an invoice, this one included, newest first: its total and what each stream billed in it */
  by_month: { month: string; usd: number; streams: Record<string, number>; partial: boolean }[];
  month_to_date: number; projected: number | null;
  last_month: string; last_month_usd: number | null;
  /** each stream this month: issued already, or expected at its usual amount */
  streams: { stream: string; issued: number | null; expected: number | null; from: string | null; breakdown: { name: string; usd: number }[] }[];
}

const r2 = (v: number) => Math.round(v * 100) / 100;
const prevMonthOf = (m: string) => new Date(Date.UTC(Number(m.slice(0, 4)), Number(m.slice(5, 7)) - 2, 1)).toISOString().slice(0, 7);
/** An invoice's groups (Vercel platform, Infrastructure usage, …) with what is left (tax) as "other". */
export function breakdownOf(i: InvoiceLike): { name: string; usd: number }[] {
  let g: any = i.groups; if (typeof g === "string") { try { g = JSON.parse(g); } catch { g = []; } }
  const parts = (Array.isArray(g) ? g : []).filter((x: any) => typeof x?.total === "number").map((x: any) => ({ name: String(x.name || x.id), usd: r2(x.total) }));
  const rest = r2(Number(i.total || 0) - parts.reduce((t: number, x: { usd: number }) => t + x.usd, 0));
  return Math.abs(rest) >= 1 ? [...parts, { name: "other (tax, adjustments)", usd: rest }] : parts;
}
export const streamOf = (i: InvoiceLike) => (i.source === "subscription" ? "subscription" : "marketplace");
export const STREAM_LABEL: Record<string, string> = { subscription: "Subscription", marketplace: "Marketplace" };

export function invoiceMonths(invoices: InvoiceLike[], today: string): InvoiceMonths {
  const month = today.slice(0, 7); const prev = prevMonthOf(month);
  const billed = invoices.filter((i) => i.total != null && i.created_at && !/void|draft/i.test(String(i.status || "")));
  const byMonth = new Map<string, number>();
  for (const i of billed) { const m = String(i.created_at).slice(0, 7); byMonth.set(m, (byMonth.get(m) ?? 0) + Number(i.total)); }
  const split = new Map<string, Record<string, number>>();
  for (const i of billed) { const m = String(i.created_at).slice(0, 7); const x = split.get(m) ?? {}; x[streamOf(i)] = r2((x[streamOf(i)] ?? 0) + Number(i.total)); split.set(m, x); }
  const by_month = [...byMonth.entries()].sort((a, b) => b[0].localeCompare(a[0])).map(([m, usd]) => ({ month: m, usd: r2(usd), streams: split.get(m) ?? {}, partial: m === month }));
  const months = [...byMonth.entries()].filter(([m]) => m < month).sort((a, b) => b[0].localeCompare(a[0])).map(([m, usd]) => ({ month: m, usd: r2(usd) }));
  const mtd = byMonth.get(month) ?? 0;
  const streams: InvoiceMonths["streams"] = [];
  for (const s of [...new Set(billed.map(streamOf))]) {
    const mine = billed.filter((i) => streamOf(i) === s).sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
    const issued = mine.filter((i) => String(i.created_at).slice(0, 7) === month).reduce((t, i) => t + Number(i.total), 0);
    // a stream is expected this month when it billed last month (it runs monthly), at its last invoice
    const regular = mine.some((i) => String(i.created_at).slice(0, 7) === prev);
    const lastInv = mine.find((i) => String(i.created_at).slice(0, 7) < month);
    streams.push({ stream: s, issued: issued ? r2(issued) : null, expected: !issued && regular && lastInv ? r2(Number(lastInv.total)) : null, from: lastInv ? String(lastInv.created_at).slice(0, 10) : null, breakdown: lastInv ? breakdownOf(lastInv) : [] });
  }
  const projected = billed.length ? r2(mtd + streams.reduce((t, s) => t + (s.expected ?? 0), 0)) : null;
  return { months, by_month, month_to_date: r2(mtd), projected, last_month: prev, last_month_usd: byMonth.has(prev) ? r2(byMonth.get(prev)!) : null, streams };
}

/**
 * The team's bill by month, from its billed charges. Vercel bills in more than one stream: the subscription (seats,
 * the plan, add-ons, the infrastructure usage) and the Marketplace (the stores, e.g. Neon), which is invoiced after
 * the month it covers. A charge counts to the month of its USAGE (the invoice's period start, else its line items'
 * period, else the date it was issued), so the Marketplace invoice issued on Oct 5 for September is September's.
 * The charges are the invoices from `GET /v1/invoices` as they are, plus, for a month and stream with no invoice
 * there, the team's FOCUS charges (`GET /v1/billing/charges`), because /v1/invoices is not guaranteed to carry the
 * Marketplace invoices. This month is projected as what is already billed plus, for each stream not billed yet, its
 * last charge. Pure, so the arithmetic is tested.
 */

export interface InvoiceLike {
  created_at: string | null; total: number | null; status: string | null; source: string | null; groups?: unknown;
  /** set on a billed charge: subscription | marketplace (`source` then says invoice | focus) */
  stream?: string | null; period_start?: string | null; period_end?: string | null; issued_at?: string | null;
}
/** One stream's billed amount for one usage month, from an invoice or from the FOCUS charges. */
export interface BilledCharge {
  id: string; month: string; stream: "subscription" | "marketplace"; total: number; subtotal: number | null; tax: number | null; credits: number | null;
  invoice_id: string | null; number: string | null; period_start: string | null; period_end: string | null; status: string | null; created_at: string | null;
  source: "invoice" | "focus"; groups?: unknown;
}
/** A row of the FOCUS v1.3 charges (the fields used). */
export interface FocusRow { BilledCost?: number | string | null; ChargeCategory?: string | null; ChargePeriodStart?: string | null; ChargePeriodEnd?: string | null; ServiceProviderName?: string | null; ServiceName?: string | null }
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
export const streamOf = (i: InvoiceLike): "subscription" | "marketplace" => ((i.stream ?? i.source) === "subscription" ? "subscription" : "marketplace");
const cents = (v: unknown) => Math.round(Number(v) * 100);
/** The month (YYYY-MM) an invoice's usage belongs to: the period start, else the period end (exclusive, so the instant before it), else the issue or creation date. */
export function usageMonth(i: InvoiceLike): string | null {
  if (i.period_start && /^\d{4}-\d{2}/.test(i.period_start)) return i.period_start.slice(0, 7);
  const end = i.period_end ? Date.parse(i.period_end) : NaN;
  if (Number.isFinite(end)) return new Date(end - 1).toISOString().slice(0, 7);
  const d = i.issued_at || i.created_at; return d && /^\d{4}-\d{2}/.test(d) ? d.slice(0, 7) : null;
}
const isBilled = (i: InvoiceLike) => i.total != null && !/void|draft/i.test(String(i.status || "")) && usageMonth(i) != null;

/** The FOCUS charges folded to one charge per usage month (of ChargePeriodStart) and stream (provider Vercel = subscription, any other = Marketplace), summed in cents. */
export function focusCharges(rows: FocusRow[]): BilledCharge[] {
  const by = new Map<string, { month: string; stream: "subscription" | "marketplace"; total: number; tax: number; credits: number; start: string; end: string | null; last: string }>();
  for (const r of rows) {
    const start = String(r.ChargePeriodStart ?? ""); if (!/^\d{4}-\d{2}/.test(start) || r.BilledCost == null || !Number.isFinite(Number(r.BilledCost))) continue;
    const month = start.slice(0, 7); const stream = /^vercel$/i.test(String(r.ServiceProviderName ?? "Vercel").trim()) ? "subscription" : "marketplace";
    const cur = by.get(`${month}|${stream}`) ?? { month, stream, total: 0, tax: 0, credits: 0, start, end: null, last: start };
    const c = cents(r.BilledCost); const cat = String(r.ChargeCategory ?? "");
    cur.total += c; if (/^tax$/i.test(cat)) cur.tax += c; if (/^credit$/i.test(cat)) cur.credits += c;
    if (start < cur.start) cur.start = start; if (start > cur.last) cur.last = start;
    const end = r.ChargePeriodEnd ? String(r.ChargePeriodEnd) : null; if (end && (!cur.end || end > cur.end)) cur.end = end;
    by.set(`${month}|${stream}`, cur);
  }
  return [...by.values()].sort((a, b) => a.month.localeCompare(b.month) || a.stream.localeCompare(b.stream)).map((x) => ({
    id: `focus:${x.month}:${x.stream}`, month: x.month, stream: x.stream, total: x.total / 100, subtotal: (x.total - x.tax) / 100, tax: x.tax / 100, credits: x.credits / 100,
    invoice_id: null, number: null, period_start: x.start, period_end: x.end, status: null, created_at: x.last, source: "focus" as const,
  }));
}

/** The billed charges: every invoice as it is (void and draft left out), and a FOCUS charge only for a month and stream no invoice covers, so nothing is counted twice. */
export function billedCharges(invoices: (InvoiceLike & { id?: string; number?: string | null; subtotal?: number | null; tax?: number | null })[], focus: BilledCharge[]): BilledCharge[] {
  const out: BilledCharge[] = invoices.filter(isBilled).map((i) => {
    const groups: any[] = typeof i.groups === "string" ? (() => { try { return JSON.parse(i.groups as string); } catch { return []; } })() : Array.isArray(i.groups) ? i.groups : [];
    const credits = groups.filter((g) => typeof g?.total === "number" && g.total < 0).reduce((t, g) => t + cents(g.total), 0) / 100;
    return { id: `invoice:${i.id ?? `${usageMonth(i)}:${streamOf(i)}`}`, month: usageMonth(i)!, stream: streamOf(i), total: r2(Number(i.total)), subtotal: i.subtotal ?? null, tax: i.tax ?? null, credits: credits || null, invoice_id: i.id ?? null, number: i.number ?? null,
      period_start: i.period_start ?? null, period_end: i.period_end ?? null, status: i.status, created_at: i.issued_at || i.created_at, source: "invoice" as const, groups: i.groups };
  });
  const have = new Set(out.map((c) => `${c.month}|${c.stream}`));
  return [...out, ...focus.filter((f) => !have.has(`${f.month}|${f.stream}`))];
}

export const STREAM_LABEL: Record<string, string> = { subscription: "Subscription", marketplace: "Marketplace" };

export function invoiceMonths(invoices: InvoiceLike[], today: string): InvoiceMonths {
  const month = today.slice(0, 7); const prev = prevMonthOf(month);
  const billed = invoices.filter(isBilled).sort((a, b) => usageMonth(b)!.localeCompare(usageMonth(a)!) || String(b.created_at).localeCompare(String(a.created_at)));
  const mOf = (i: InvoiceLike) => usageMonth(i)!;
  // sums in whole cents, so $456.74 + $235.17 is exactly $691.91
  const byMonth = new Map<string, number>(); const split = new Map<string, Record<string, number>>();
  for (const i of billed) {
    const m = mOf(i); byMonth.set(m, (byMonth.get(m) ?? 0) + cents(i.total));
    const x = split.get(m) ?? {}; x[streamOf(i)] = (x[streamOf(i)] ?? 0) + cents(i.total); split.set(m, x);
  }
  const usd = (c: number) => c / 100;
  const by_month = [...byMonth.entries()].sort((a, b) => b[0].localeCompare(a[0])).map(([m, c]) => ({ month: m, usd: usd(c), streams: Object.fromEntries(Object.entries(split.get(m) ?? {}).map(([k, v]) => [k, usd(v)])), partial: m === month }));
  const months = [...byMonth.entries()].filter(([m]) => m < month).sort((a, b) => b[0].localeCompare(a[0])).map(([m, c]) => ({ month: m, usd: usd(c) }));
  const mtd = byMonth.get(month) ?? 0;
  const streams: InvoiceMonths["streams"] = []; let expectedSum = 0;
  for (const s of [...new Set(billed.map(streamOf))]) {
    const mine = billed.filter((i) => streamOf(i) === s);
    const issued = mine.filter((i) => mOf(i) === month).reduce((t, i) => t + cents(i.total), 0);
    // a stream is expected this month when it billed last month (it runs monthly), at its last charge
    const regular = mine.some((i) => mOf(i) === prev);
    const lastInv = mine.find((i) => mOf(i) < month);
    const expected = !issued && regular && lastInv ? cents(lastInv.total) : null; expectedSum += expected ?? 0;
    streams.push({ stream: s, issued: issued ? usd(issued) : null, expected: expected != null ? usd(expected) : null, from: lastInv ? String(lastInv.created_at ?? mOf(lastInv)).slice(0, 10) : null, breakdown: lastInv ? breakdownOf(lastInv) : [] });
  }
  const projected = billed.length ? usd(mtd + expectedSum) : null;
  return { months, by_month, month_to_date: usd(mtd), projected, last_month: prev, last_month_usd: byMonth.has(prev) ? usd(byMonth.get(prev)!) : null, streams };
}

import { test } from "node:test";
import assert from "node:assert";
import { billedCharges, focusCharges, invoiceMonths, usageMonth } from "../adapters/vercel/bill_months.js";
import { steadyBlend } from "../spend_compare.js";

const inv = (created_at: string, total: number, source: string | null = null) => ({ created_at, total, status: "paid", source });

test("a Vercel month is every invoice issued in it, and a stream not issued yet is expected at its last invoice", () => {
  const m = invoiceMonths([
    inv("2026-10-05T12:00:00Z", 235), { ...inv("2026-09-21T19:00:00Z", 457, "subscription"), groups: JSON.stringify([{ id: "devex", name: "Vercel platform", total: 260 }, { id: "managed-infra", name: "Infrastructure usage", total: 159 }]) }, inv("2026-09-05T02:00:00Z", 259),
    inv("2026-08-21T20:00:00Z", 592, "subscription"), inv("2026-08-02T22:00:00Z", 314), inv("2026-07-21T20:00:00Z", 656, "subscription"), inv("2026-07-03T07:00:00Z", 260),
  ], "2026-10-08");
  assert.equal(m.last_month, "2026-09"); assert.equal(m.last_month_usd, 716);
  assert.equal(m.month_to_date, 235);
  const sub = m.streams.find((s) => s.stream === "subscription")!;
  assert.equal(sub.expected, 457); assert.equal(sub.from, "2026-09-21");
  assert.deepEqual(sub.breakdown, [{ name: "Vercel platform", usd: 260 }, { name: "Infrastructure usage", usd: 159 }, { name: "other (tax, adjustments)", usd: 38 }]);
  assert.equal(m.projected, 235 + 457);
  assert.deepEqual(m.months.map((x) => x.month), ["2026-09", "2026-08", "2026-07"]);
});

test("a stream that did not bill last month is not expected", () => {
  const m = invoiceMonths([inv("2026-10-02T00:00:00Z", 100), inv("2026-07-21T00:00:00Z", 500, "subscription"), inv("2026-09-02T00:00:00Z", 100)], "2026-10-08");
  assert.equal(m.projected, 100);
});

test("steadyBlend leans on steady months and leaves moving ones alone", () => {
  const steady = [{ month: "2026-09", usd: 280 }, { month: "2026-08", usd: 260 }, { month: "2026-07", usd: 300 }];
  assert.deepEqual(steadyBlend(520, steady), { projected: 400, run_rate: 520, typical: 280, steady: true, blended: true });
  assert.equal(steadyBlend(290, steady).blended, false);
  const moving = [{ month: "2026-09", usd: 18000 }, { month: "2026-08", usd: 24000 }, { month: "2026-07", usd: 28000 }];
  assert.equal(steadyBlend(17000, moving).projected, 17000);
  assert.equal(steadyBlend(500, steady.slice(0, 2)).blended, false);
});

test("a charge counts to the month of its usage: period start, else period end (exclusive), else the issue date", () => {
  assert.equal(usageMonth({ created_at: "2026-10-05T00:00:00Z", total: 1, status: "paid", source: null, period_start: "2026-09-01T00:00:00Z", period_end: "2026-10-01T00:00:00Z" }), "2026-09");
  assert.equal(usageMonth({ created_at: "2026-10-05T00:00:00Z", total: 1, status: "paid", source: null, period_end: "2026-10-01T00:00:00Z" }), "2026-09");
  assert.equal(usageMonth({ created_at: "2026-10-05T00:00:00Z", issued_at: "2026-10-04T00:00:00Z", total: 1, status: "paid", source: null }), "2026-10");
});

const sep = [
  { id: "4DD31E2E-0033", number: "4DD31E2E-0033", created_at: "2026-09-21T19:00:00Z", total: 456.74, subtotal: 418.81, tax: 37.92, status: "paid", source: "subscription", period_start: "2026-09-01T00:00:00Z", period_end: "2026-10-01T00:00:00Z" },
  { id: "4DD31E2E-0034", number: "4DD31E2E-0034", created_at: "2026-10-05T12:00:00Z", total: 235.17, subtotal: 215.67, tax: 19.5, status: "paid", source: null, period_start: "2026-09-01T00:00:00Z", period_end: "2026-10-01T00:00:00Z" },
];
test("September 2026 is $691.91 exactly (cents, tax included) and October excludes both invoices", () => {
  const m = invoiceMonths(billedCharges(sep, []), "2026-10-08");
  assert.equal(m.months[0].month, "2026-09"); assert.equal(m.months[0].usd, 691.91);
  assert.equal(m.by_month.find((x) => x.month === "2026-10"), undefined); assert.equal(m.month_to_date, 0);
  assert.equal(m.last_month_usd, 691.91);
  // both streams ran in September, so both are projected for October at their last charge, as a projection and not as billed
  assert.equal(m.projected, 691.91); assert.deepEqual(m.streams.map((s) => [s.stream, s.issued, s.expected]).sort(), [["marketplace", null, 235.17], ["subscription", null, 456.74]]);
});

test("void and draft invoices are left out", () => {
  const m = invoiceMonths(billedCharges([...sep, { ...sep[1], id: "x", status: "void" }, { ...sep[0], id: "y", status: "draft" }], []), "2026-10-08");
  assert.equal(m.months[0].usd, 691.91);
});

const focusSep = focusCharges([
  { BilledCost: 260, ChargeCategory: "Purchase", ChargePeriodStart: "2026-09-01T00:00:00Z", ServiceProviderName: "Vercel" }, { BilledCost: 196.74, ChargeCategory: "Usage", ChargePeriodStart: "2026-09-12T00:00:00Z", ServiceProviderName: "Vercel" },
  { BilledCost: 215.67, ChargeCategory: "Usage", ChargePeriodStart: "2026-09-02T00:00:00Z", ServiceProviderName: "Neon" }, { BilledCost: 19.5, ChargeCategory: "Tax", ChargePeriodStart: "2026-09-30T00:00:00Z", ServiceProviderName: "Neon" },
]);
test("FOCUS charges group by month of ChargePeriodStart and provider (Vercel = subscription, others = Marketplace), summed in cents", () => {
  assert.deepEqual(focusSep.map((c) => [c.month, c.stream, c.total, c.tax, c.source]), [["2026-09", "marketplace", 235.17, 19.5, "focus"], ["2026-09", "subscription", 456.74, 0, "focus"]]);
  assert.equal(invoiceMonths(focusSep, "2026-10-08").months[0].usd, 691.91);
});

test("a FOCUS charge fills only a month and stream with no invoice: never double counted", () => {
  assert.equal(invoiceMonths(billedCharges(sep, focusSep), "2026-10-08").months[0].usd, 691.91);
  const only = billedCharges([sep[0]], focusSep);
  assert.deepEqual(only.map((c) => [c.stream, c.source]).sort(), [["marketplace", "focus"], ["subscription", "invoice"]]);
  assert.equal(invoiceMonths(only, "2026-10-08").months[0].usd, 691.91);
});

test("a stream already billed for the current month is not projected on top", () => {
  const oct = billedCharges([...sep, { id: "oct", created_at: "2026-10-03T00:00:00Z", total: 100, status: "paid", source: "subscription", period_start: "2026-10-01T00:00:00Z", period_end: "2026-11-01T00:00:00Z" }], []);
  const m = invoiceMonths(oct, "2026-10-08");
  assert.equal(m.month_to_date, 100); assert.equal(m.projected, 335.17);
});

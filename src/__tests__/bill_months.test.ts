import { test } from "node:test";
import assert from "node:assert";
import { invoiceMonths } from "../adapters/vercel/bill_months.js";
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

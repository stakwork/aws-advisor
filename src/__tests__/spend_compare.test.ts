import { test } from "node:test";
import assert from "node:assert";
import { accountPace, awsAccountLines, likeForLike, movers, projectionFactor } from "../spend_compare.js";
import type { SpendRow } from "../spend_math.js";

const row = (day: string, usd: number): SpendRow => ({ day, net_unblended: usd, unblended: usd, amortized: usd, usage_only: usd, fetched_at: "" });
const days = (from: string, n: number, usd: (i: number) => number) => Array.from({ length: n }, (_, i) => ({ day: `${from.slice(0, 8)}${String(Number(from.slice(8)) + i).padStart(2, "0")}`, usd: usd(i) }));

test("likeForLike compares the complete days of this month with the same days of the last one", () => {
  const rows = [...days("2026-09-01", 30, () => 10), ...days("2026-10-01", 8, () => 12)].map((d) => row(d.day, d.usd));
  const r = likeForLike(rows, "2026-10-08")!;
  // the 8th is today (partial): days 1 to 7 of both months
  assert.equal(r.days, 7);
  assert.equal(r.this_usd, 84); assert.equal(r.last_usd, 70);
  assert.equal(r.last_to, "2026-09-07");
  assert.equal(r.delta_pct, 20);
});

test("likeForLike caps the previous month at its own length", () => {
  const rows = [...days("2026-02-01", 28, () => 1), ...days("2026-03-01", 30, () => 1)].map((d) => row(d.day, d.usd));
  const r = likeForLike(rows, "2026-03-31")!;
  assert.equal(r.days, 30); assert.equal(r.last_to, "2026-02-28"); assert.equal(r.last_usd, 28);
});

test("movers ranks services by the size of the move and labels new and gone ones", () => {
  const m = movers([
    { service: "A", last_month: 100, projected: 103 },
    { service: "B", last_month: 0, projected: 50 },
    { service: "C", last_month: 200, projected: 0 },
    { service: "D", last_month: 300, projected: 380 },
  ]);
  assert.deepEqual(m.map((x) => [x.service, x.status]), [["C", "gone"], ["D", "up"], ["B", "new"]]);
});

test("accountPace counts a charge posted on the 1st once instead of multiplying it", () => {
  const d = days("2026-10-01", 7, (i) => (i === 0 ? 600 : 4));
  const p = accountPace(d, "2026-10-08")!;
  assert.equal(p.month_to_date, 624);
  assert.equal(p.daily_rate, 4);
  // 24 days left at 4 a day
  assert.equal(p.projected, 624 + 4 * 24);
});

test("awsAccountLines lists every billed account, falling back to the factor without daily rows", () => {
  const rows = [{ month: "2026-10", account_id: "111111111111", usd: 100 }, { month: "2026-09", account_id: "111111111111", usd: 400 }, { month: "2026-09", account_id: "222222222222", usd: 50 }];
  const lines = awsAccountLines(rows, days("2026-10-01", 7, () => 10).map((x) => ({ ...x, account_id: "333333333333" })), "2026-10-08", 4);
  const by = Object.fromEntries(lines.map((l) => [l.account, l]));
  assert.equal(by["111111111111"].projected_usd, 400);
  assert.equal(by["111111111111"].delta_pct, 0);
  assert.equal(by["222222222222"].month_to_date_usd, 0);
  assert.equal(by["333333333333"].projected_usd, 70 + 10 * 24);
});

test("projectionFactor follows the payer's projection, else the day of the month", () => {
  assert.equal(projectionFactor(300, 100, "2026-10-08"), 3);
  assert.equal(projectionFactor(null, null, "2026-10-11"), 31 / 10);
});

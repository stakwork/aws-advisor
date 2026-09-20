import { test } from "node:test";
import assert from "node:assert";
import { addDays, costScopeFor, verify } from "../verify_math.js";

const series = (from: string, days: number, usd: (i: number) => number) => Array.from({ length: days }, (_, i) => ({ day: addDays(from, i), usd: usd(i) }));

test("verification: a step down after the decision is realised; too few days is too early unless forced", () => {
  // 14 days at 100/day, decision on day 14, then 10 days at 60/day
  const rows = [...series("2026-09-01", 14, () => 100), ...series("2026-09-15", 10, () => 60)];
  const v = verify(rows, "2026-09-15", 1000, "2026-09-25");
  assert.equal(v.verdict, "realised");
  assert.equal(v.before_usd_day, 100); assert.equal(v.after_usd_day, 60);
  assert.equal(v.realised_usd_month, 1200); assert.equal(v.ratio, 1.2);
  assert.equal(v.days_after, 8, "the decision day and the next are skipped");
  const early = verify(rows, "2026-09-15", 1000, "2026-09-19");
  assert.equal(early.verdict, "too_early");
  assert.equal(verify(rows, "2026-09-15", 1000, "2026-09-19", { early: true }).verdict, "realised");
});

test("verification: partial, none and increase, and a one-day blip in the before window does not move the median", () => {
  const flat = [...series("2026-09-01", 14, (i) => (i === 5 ? 900 : 100)), ...series("2026-09-15", 10, () => 100)];
  assert.equal(verify(flat, "2026-09-15", 300, "2026-09-25").verdict, "none");
  const partial = [...series("2026-09-01", 14, () => 100), ...series("2026-09-15", 10, () => 90)];
  assert.equal(verify(partial, "2026-09-15", 1000, "2026-09-25").verdict, "partial");
  const up = [...series("2026-09-01", 14, () => 100), ...series("2026-09-15", 10, () => 140)];
  assert.equal(verify(up, "2026-09-15", 300, "2026-09-25").verdict, "increase");
  assert.equal(verify([], "2026-09-15", 300, "2026-09-25").verdict, "no_data");
});

test("cost scopes: every actionable type maps to the lines it moves; permissions and flow logs are not verifiable", () => {
  assert.equal(costScopeFor("aurora_set_storage_iopt")!.service, "Amazon Relational Database Service");
  assert.deepEqual(costScopeFor("rightsize_instance", { instance_type: "m6i.4xlarge" })!.usage_like, ["%BoxUsage:m6i.4xlarge"]);
  assert.equal(costScopeFor("add_pull_through_cache")!.usage_like[0], "%NatGateway-Bytes%");
  assert.equal(costScopeFor("enable_flow_logs"), null);
  assert.equal(costScopeFor("buy_reservation"), null);
});

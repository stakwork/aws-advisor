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

test("impactFor: the stored series and the medians for an actioned recommendation, the account total alongside; done counts like approved", async () => {
  const fs = await import("node:fs"); const os = await import("node:os"); const path = await import("node:path");
  process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "advisor-impact-test-"));
  const { db } = await import("../db.js");
  const { impactFor, latestVerification, verificationSummary, ACTIONED } = await import("../verify.js");
  assert.deepEqual([...ACTIONED], ["approved", "done"]);
  db.prepare("insert into runs(status, finished_at) values ('completed', datetime('now'))").run();
  const ins = db.prepare("insert into recommendations(fingerprint, run_id, source, rule, title, resource, action_type, est_monthly_saving, tier, confidence, rationale, evidence, status, decided_at, decided_by) values (?, 1, 'rules', ?, ?, ?, ?, ?, 'approve', 0.8, '', '{}', ?, ?, 'ui')");
  ins.run("aurora_storage_tier:c1", "aurora_storage_tier", "Move c1 to I/O-Optimized", "c1", "aurora_set_storage_iopt", 467, "done", "2026-09-10 12:00:00");
  ins.run("release_eip:e1", "eip_unattached", "Release 1.2.3.4", "e1", "release_eip", 3.65, "approved", "2026-09-20 12:00:00");
  // the agent proposed the same switch on the same cluster; one decision covered both
  ins.run("agent:aurora:c1", "aurora_storage_tier", "Switch c1 to I/O-Optimized storage", "arn:aws:rds:us-east-1:1:cluster:c1", "aurora_set_storage_iopt", 470, "done", "2026-09-10 12:00:00");
  const rows = [...series("2026-08-27", 14, () => 18), ...series("2026-09-10", 12, (i) => (i < 2 ? 12 : 1.4))];
  db.prepare(`insert into verifications(recommendation_id, decided_day, days_after, scope_service, scope_usage, scope_note, verdict, before_usd_day, after_usd_day, realised_usd_month, estimate_usd_month, ratio, applied, note, series)
    values (1, '2026-09-10', 12, 'Amazon Relational Database Service', '%Aurora:%', 'Aurora lines of the whole account', 'realised', 18, 1.4, 498, 467, 1.07, null, '14 days before at 18.00', ?)`).run(JSON.stringify(rows));
  for (const r of [...series("2026-08-27", 26, (i) => 95 - (i >= 16 ? 16 : 0))]) db.prepare("insert into spend_daily(day, net_unblended) values (?, ?)").run(r.day, r.usd);

  const i = impactFor(1)!;
  assert.equal(i.actioned, true);
  assert.equal(i.recommendation.status, "done");
  assert.equal(i.decided_day, "2026-09-10");
  assert.equal(i.after_from, "2026-09-12", "the decision day and the next are mixed");
  assert.equal(i.series.length, 26);
  assert.equal(i.series[0].day, "2026-08-27");
  assert.equal(i.verification.before_usd_day, 18);
  assert.equal(i.verification.after_usd_day, 1.4);
  assert.equal((i.verification as any).series, undefined, "the series travels beside the verdict, not inside it");
  assert.equal(i.total.length, 26);
  assert.equal(i.total[16].usd, 79);
  assert.equal(latestVerification(1).series, undefined);

  const none = impactFor(2)!;
  assert.equal(none.verification, null);
  assert.deepEqual(none.series, []);
  assert.equal(none.decided_day, "2026-09-20");
  assert.equal(impactFor(99), null);

  const sum = verificationSummary();
  assert.equal(sum.actioned, 2, "the duplicate is the same decision");
  assert.equal(sum.rows.map((r: any) => r.status).join(","), "approved,done");
  const aurora = sum.rows.find((r: any) => r.action_type === "aurora_set_storage_iopt");
  assert.equal(aurora.id, 3, "the higher estimate is primary");
  assert.deepEqual(aurora.merged_ids, [3, 1]);
  assert.equal(sum.claimed_usd_month, 474, "470 + 3.65, not 470 + 467 + 3.65");
  assert.equal(aurora.verdict, "realised", "the member that was checked lends the decision its verdict");
  assert.equal(aurora.verified_id, 1);
  assert.equal(sum.realised_usd_month, 498, "counted once");
  assert.equal(sum.pending, 1);
});

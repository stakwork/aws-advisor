import assert from "node:assert/strict";
import { test } from "node:test";
import { passDigest, gradePassReport, buildPassBrief, SPHINX_MAX_CHARS } from "../pass_report.js";
import type { ActionRow, PassResult } from "../executor.js";

const pass = (over: Partial<PassResult> = {}): PassResult => ({ mode: "dry_run", proposed: 2, fresh: 1, applied: 0, verified: 0, failed: 0, refused: 0, stale: 0, notes: ["ecr_lifecycle: 14 repository(ies) already have a lifecycle policy", "swarm_park: no running instance tagged advisor:park=auto"], errors: [], took_ms: 1234, ...over } as PassResult);
const row = (over: Partial<ActionRow> = {}): ActionRow => ({
  id: 7, kind: "ecr_lifecycle", resource: "repo-a", resource_name: "repo-a", region: "us-east-1", account_id: null, dedupe: "ecr_lifecycle:us-east-1:repo-a:30", status: "proposed", mode: "dry_run", trigger: "schedule",
  title: "repo-a: expire untagged images after 30 days (41 untagged, 3.20 GB)", reason: "no lifecycle policy; 41 untagged image(s) hold 3.20 GB", before: {}, after: {}, facts: {}, rollback: "delete the lifecycle policy", est_usd_month: 0.32, result: null, error: null,
  created_at: "2026-09-27 10:45:00", seen_at: "2026-09-27 10:45:00", applied_at: null, verified_at: null, reverted_at: null, notified_at: null, notify_result: null, ...over,
} as ActionRow);

test("pass digest: same outcome gives the same digest; a status change or a new error changes it; numbers in notes do not", () => {
  const a = passDigest(pass(), [row(), row({ id: 8 })]);
  assert.equal(a, passDigest(pass(), [row({ id: 8 }), row()]));
  assert.equal(a, passDigest(pass({ notes: ["ecr_lifecycle: 15 repository(ies) already have a lifecycle policy", "swarm_park: no running instance tagged advisor:park=auto"], took_ms: 99 }), [row(), row({ id: 8 })]));
  assert.notEqual(a, passDigest(pass(), [row(), row({ id: 8, status: "applied" })]));
  assert.notEqual(a, passDigest(pass({ errors: ["kms_key_retire plan: AccessDenied"] }), [row(), row({ id: 8 })]));
  assert.notEqual(a, passDigest(pass({ mode: "apply" }), [row(), row({ id: 8 })]));
  assert.notEqual(a, passDigest(pass(), [row(), row({ id: 8, facts: { jev: { verdict: "hold" } } })]));
});

test("pass brief: carries every row id, the notes grouped per module and the errors", () => {
  const brief = buildPassBrief(pass({ errors: ["efs_lifecycle plan: boom"] }), [row(), row({ id: 8, kind: "snapshot_delete", status: "applied", result: "DeleteSnapshot ok", applied_at: "2026-09-27 10:46:00" })], { passAt: "2026-09-27T10:45:00.000Z", trigger: "schedule" });
  assert.match(brief, /#7 \[proposed\] ecr_lifecycle/);
  assert.match(brief, /#8 \[applied\] snapshot_delete/);
  assert.match(brief, /### ecr_lifecycle \(1\)/);
  assert.match(brief, /### swarm_park \(1\)/);
  assert.match(brief, /efs_lifecycle plan: boom/);
  assert.match(brief, /mode dry_run/);
});

test("pass report rubric: unknown row ids, a deletion claimed in a dry run, a long sphinx and a numberless summary each fail their check", () => {
  const good = gradePassReport({ summary: "Dry run: 2 proposals, nothing changed. #7 waits for apply mode.", next: ["at :45 the same two rows are refreshed"], waiting: ["#7 ECR policy on repo-a"], left_alone: ["14 repositories already carry a policy"], concerns: [], sphinx: "Auto-actions dry run: 2 proposals (#7, #8), nothing changed. Next pass at :45." }, { row_ids: [7, 8], applied: 0, proposed: 2 });
  assert.equal(good.score, 1, JSON.stringify(good.checks.filter((c) => !c.pass)));
  const bad = gradePassReport({ summary: "Snapshots were deleted and repositories cleaned.", next: [], waiting: ["#99 waits"], left_alone: [], concerns: [], sphinx: "x".repeat(SPHINX_MAX_CHARS + 1) }, { row_ids: [7, 8], applied: 0, proposed: 2 });
  const failed = bad.checks.filter((c) => !c.pass).map((c) => c.check);
  assert.ok(failed.includes("row ids exist"), failed.join(", "));
  assert.ok(failed.includes("sphinx under 900 characters"), failed.join(", "));
  assert.ok(failed.includes("no applied claim when nothing was applied"), failed.join(", "));
  assert.ok(failed.includes("numbers present when the pass had proposals"), failed.join(", "));
  // a pass with no proposals may be summarised without a number, and a pass that applied may say so
  const quiet = gradePassReport({ summary: "Nothing to do.", next: [], waiting: [], left_alone: [], concerns: [], sphinx: "Auto-actions: nothing to do this hour." }, { row_ids: [], applied: 0, proposed: 0 });
  assert.equal(quiet.score, 1, JSON.stringify(quiet.checks.filter((c) => !c.pass)));
  const applied = gradePassReport({ summary: "1 snapshot deleted (#8).", next: [], waiting: [], left_alone: [], concerns: [], sphinx: "Auto-actions: snapshot #8 deleted." }, { row_ids: [8], applied: 1, proposed: 1 });
  assert.equal(applied.score, 1, JSON.stringify(applied.checks.filter((c) => !c.pass)));
});

test("pass brief: marks the rows the pass created or brought back, and leaves older open rows unmarked", () => {
  const brief = buildPassBrief(pass(), [
    row({ id: 7, created_at: "2026-09-27 09:45:00", seen_at: "2026-09-27 10:45:10" }),
    row({ id: 8, created_at: "2026-09-27 10:45:20", dedupe: "ecr_lifecycle:us-east-1:repo-new:30" }),
    row({ id: 9, created_at: "2026-09-20 10:45:00", revived_at: "2026-09-27 10:45:30", dedupe: "ecr_lifecycle:us-east-1:repo-back:30" }),
  ], { passAt: "2026-09-27T10:45:00.000Z" });
  assert.doesNotMatch(brief.split("\n").find((l) => l.startsWith("- #7 "))!, /NEW|AGAIN/);
  assert.match(brief, /#8 \[proposed\][^\n]*NEW this pass/);
  assert.match(brief, /#9 \[proposed\][^\n]*PROPOSED AGAIN this pass/);
});

test("pass report rubric: a stop the pass read back is not an invented change", () => {
  const answer = { summary: "#8 read back as stopped after a person pressed Stop.", sphinx: "#8 is stopped.", next: "", waiting: [], left_alone: [], concerns: [] };
  const check = (applied: number) => gradePassReport(answer, { row_ids: [8], applied, proposed: 0 }).checks.find((c) => c.check.startsWith("no applied claim"))!;
  assert.equal(check(0).pass, false);
  assert.equal(check(1).pass, true);
});

import assert from "node:assert/strict";
import { test } from "node:test";

test("action threads: one thread per ledger row, ever; none for a row that does not exist", async () => {
  const { db } = await import("../db.js");
  const { threadForAction, listThreads } = await import("../chat.js");
  db.exec("delete from actions");
  const id = Number(db.prepare("insert into actions(kind, resource, resource_name, region, dedupe, status, mode, trigger, title, reason, rollback) values ('ebs_iops_trim', 'vol-0abc', 'data', 'us-east-1', 'ebs_iops_trim:vol-0abc:3000', 'proposed', 'dry_run', 'test', 'vol-0abc: 6,000 → 3,000 IOPS', 'peak 900 IOPS', 'set the IOPS back to 6,000')").run().lastInsertRowid);
  assert.equal(threadForAction(id, false), null, "no thread before the first message");
  const t1 = threadForAction(id, true)!;
  assert.ok(t1 && t1.action_id === id && t1.recommendation_id === null);
  const t2 = threadForAction(id, true)!;
  assert.equal(t2.id, t1.id, "a second create finds the same thread");
  assert.equal(threadForAction(id, false)!.id, t1.id);
  assert.equal(threadForAction(id + 1000, true), null, "no thread for a missing row");
  assert.ok(!listThreads().some((t) => t.id === t1.id), "ledger threads stay off the Chat page's general list");
  db.exec("delete from chat_threads where action_id is not null");
  db.exec("delete from actions");
});

test("action threads: the brief carries the row, its undo, what else is known and the question", async () => {
  const { buildActionPrompt } = await import("../chat.js");
  const row: any = {
    id: 42, kind: "swarm_park", resource: "i-0123", resource_name: "swarm-acme", region: "us-east-1", account_id: null, dedupe: "swarm_park:i-0123", status: "proposed", mode: "apply", trigger: "schedule",
    title: "stop swarm-acme (t3.large): idle 7 days", reason: "no use signal for 7 days", before: { state: "running" }, after: { state: "stopped" }, facts: { idle_days: 7 },
    rollback: "start it again (Revert on the page)", est_usd_month: 61.5, result: null, error: null, created_at: "2026-09-27 10:00:00", seen_at: "2026-09-27 12:45:00", applied_at: null, verified_at: null, reverted_at: null, notified_at: null, notify_result: null,
    check: { verdict: "proceed", irreversible: 0.1 },
  };
  const ctx = { facts: { kind: "ec2", type: "t3.large" }, recommendations: [{ id: 7, rule: "idle_instance", title: "Stop swarm-acme", action_type: "stop_instance", tier: "approve", status: "approved", decided_by: "gonzalo", decision_reason: "customer churned" }], alerts: [], other_rows: [{ id: 41, kind: "swarm_park", status: "reverted", title: "stop swarm-acme", created_at: "2026-09-20", error: null }] };
  const p = buildActionPrompt(row, ctx, [], "why now?", false);
  for (const s of ["auto-action #42", "stop swarm-acme (t3.large): idle 7 days", "start it again (Revert on the page)", "no use signal for 7 days", "#7 idle_instance", "customer churned", "#41 swarm_park reverted", "Jev's second opinion", "aws_<name>", "why now?", "this is the first message"]) assert.ok(p.includes(s), `brief lacks "${s}"`);
  const followUp = buildActionPrompt(row, ctx, [], "and the revert?", true);
  assert.ok(followUp.includes("and the revert?") && !followUp.includes("Before → after"), "a resumed turn carries the message alone");
});

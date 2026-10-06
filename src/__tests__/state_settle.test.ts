import assert from "node:assert/strict";
import { test } from "node:test";

test("a read-back that still shows the old state right after StopInstances is in flight, not a failure; minutes later it is", async () => {
  const { db } = await import("../db.js");
  const { recordProposal, stillLanding, STATE_SETTLE_MS } = await import("../executor.js");
  await import("../actions/index.js"); // the ledger row takes its provider from the registered module
  type Proposal = import("../executor.js").Proposal;
  const id = "i-0f0000000000c0a11";
  const p: Proposal = {
    kind: "schedule_hours", resource: id, resource_name: "box", region: "us-east-1", account_id: null,
    dedupe: `schedule_hours:${id}:stop:manual:test`, title: "stop box", reason: "test",
    before: { state: "running" }, after: { state: "stopped" }, facts: { kind: "ec2", manual: true }, rollback: "start", est_usd_month: null,
  };
  db.prepare("delete from actions where dedupe = ?").run(p.dedupe);
  assert.equal(stillLanding(p, "running"), false, "nothing applied yet: a plain mismatch");
  const { row } = recordProposal(p, "apply", "manual");
  db.prepare("update actions set status = 'applied', applied_at = datetime('now') where id = ?").run(row.id);
  assert.equal(stillLanding(p, "running"), true, "the old state a second after the call is EC2 catching up");
  assert.equal(stillLanding(p, "stopped"), false, "the wanted state is not a mismatch at all");
  assert.equal(stillLanding(p, "terminated"), false, "a state that is neither old nor wanted is a real disagreement");
  db.prepare("update actions set applied_at = datetime('now', ?) where id = ?").run(`-${Math.round(STATE_SETTLE_MS / 1000) + 60} seconds`, row.id);
  assert.equal(stillLanding(p, "running"), false, "still running minutes later: the stop did not take");
  db.prepare("delete from actions where id = ?").run(row.id);
});

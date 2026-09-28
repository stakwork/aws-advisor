import assert from "node:assert/strict";
import { test } from "node:test";
import { beginPass, currentPass, endPass, eventsForAction, getPass, listExecutorLog, logEvent } from "../executor_log.js";
import type { PassResult } from "../executor.js";

const result = (over: Partial<PassResult> = {}): PassResult => ({ mode: "apply", proposed: 1, fresh: 1, applied: 1, verified: 1, failed: 0, refused: 0, held: 0, stale: 0, notes: ["efs_lifecycle: 1 file system without a policy"], errors: [], took_ms: 42, ...over });
/** A row id no other test run has used: the log is on the shared test database. */
const rowId = () => 900_000 + Math.floor(Math.random() * 1_000_000);

test("executor log: a pass keeps its counts, notes and lines, and the events raised inside it carry its trigger", () => {
  const aid = rowId();
  const id = beginPass("manual", "apply");
  assert.equal(currentPass()?.id, id);
  logEvent({ action_id: aid, kind: "efs_lifecycle", event: "apply", outcome: "applied", detail: "PutLifecycleConfiguration ok" });
  logEvent({ action_id: aid, kind: "efs_lifecycle", event: "verify", outcome: "verified", detail: "policy present" });
  endPass(id, result(), ["efs_lifecycle: 1 file system without a policy", `proposed #${aid} fs-1: move cold files to IA`, `applying #${aid}`]);
  assert.equal(currentPass(), null);
  const p = getPass(id)!;
  assert.equal(p.trigger, "manual");
  assert.equal(p.mode, "apply");
  assert.ok(p.finished_at);
  assert.deepEqual([p.proposed, p.applied, p.verified, p.took_ms], [1, 1, 1, 42]);
  assert.deepEqual(p.notes, ["efs_lifecycle: 1 file system without a policy"]);
  assert.equal(p.lines.length, 3);
  assert.deepEqual(p.events.map((e) => [e.event, e.outcome, e.trigger, e.pass_id]), [["apply", "applied", "manual", id], ["verify", "verified", "manual", id]]);
});

test("executor log: an event outside a pass is loose, names who made it, and the row's history reads oldest first", () => {
  const aid = rowId();
  const id = beginPass("schedule", "apply");
  logEvent({ action_id: aid, kind: "alarm_cleanup", event: "apply", outcome: "applied", detail: "DeleteAlarms ok" });
  endPass(id, result({ errors: ["kms_key_retire: AccessDenied"] }), []);
  const loose = logEvent({ action_id: aid, kind: "alarm_cleanup", event: "revert", outcome: "reverted", trigger: "page", detail: "x".repeat(700) });
  const log = listExecutorLog({ limit: 5 });
  assert.equal(log.passes[0].id, id);
  assert.deepEqual(log.passes[0].errors, ["kms_key_retire: AccessDenied"]);
  const e = log.loose.find((x) => x.id === loose)!;
  assert.equal(e.pass_id, null);
  assert.equal(e.trigger, "page");
  assert.equal(e.detail!.length, 500);
  assert.deepEqual(eventsForAction(aid).map((x) => x.event), ["apply", "revert"]);
});

test("executor log: a pass that ends with nothing done is still on record", () => {
  const id = beginPass("schedule", "off");
  endPass(id, result({ mode: "off", proposed: 0, fresh: 0, applied: 0, verified: 0, notes: ["mode off: nothing planned"], took_ms: 1 }), ["mode off: nothing planned"]);
  const p = getPass(id)!;
  assert.equal(p.mode, "off");
  assert.equal(p.events.length, 0);
  assert.deepEqual(p.lines, ["mode off: nothing planned"]);
});

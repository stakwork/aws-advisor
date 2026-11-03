import assert from "node:assert/strict";
import { test } from "node:test";
import { db } from "../db.js";
import { finishPass, finishRun, listPasses, listRuns, notePassSelection, probeHistoryOverview, startPass, startRun } from "../probe_log.js";
import { probeInstance } from "../ssm.js";

// History > Probes: every pass and every probe leaves a row saying what was sent where, from where, and how it ended.

test("probe log: a pass with its runs, listed by pass, by box, by outcome; the overview counts the last 24 hours", () => {
  db.exec("delete from probe_runs; delete from probe_passes");
  db.prepare("insert or replace into inventory_ec2(instance_id, name, state, snapshot) values ('i-0aaaaaaaaaaaaaaa1', 'web-1', 'running', '{}')").run();
  const pass = startPass("host", "cron");
  assert.ok(pass > 0);
  notePassSelection(pass, "2 candidate(s) of 3 running: left out 1 not SSM online; scope all, limit 100, interval 1 h, 3 at a time");
  const ok = startRun({ instanceId: "i-0aaaaaaaaaaaaaaa1", kind: "host", origin: "pass", passId: pass });
  finishRun(ok, { status: "ok", accountId: "123456789012", commandId: "cmd-1", document: "aws-advisor-probe-host", upload: "inline", metricsId: 42 });
  const bad = startRun({ instanceId: "i-0aaaaaaaaaaaaaaa2", kind: "host", origin: "pass", passId: pass });
  finishRun(bad, { status: "failed", code: "timeout", message: "SSM command cmd-2 did not finish within 90s", commandId: "cmd-2", document: "aws-advisor-probe-host" });
  finishPass(pass, { candidates: 2, probed: 1, failed: [{ code: "timeout" }], note: null });
  const manual = startRun({ instanceId: "i-0aaaaaaaaaaaaaaa1", kind: "software", origin: "manual" });
  finishRun(manual, { status: "ok", upload: "s3", metricsId: 43 });

  const [p] = listPasses({ kind: "host" });
  assert.equal(p!.id, pass); assert.equal(p!.origin, "cron"); assert.equal(p!.probed, 1); assert.equal(p!.failed, 1); assert.deepEqual(p!.failures, { timeout: 1 });
  assert.ok(p!.finished_at && p!.took_ms != null && p!.took_ms >= 0); assert.match(p!.selection!, /left out 1 not SSM online/);
  assert.deepEqual(listRuns({ passId: pass }).map((r) => [r.instance_id, r.status, r.code, r.instance_name]), [["i-0aaaaaaaaaaaaaaa2", "failed", "timeout", null], ["i-0aaaaaaaaaaaaaaa1", "ok", null, "web-1"]]);
  assert.deepEqual(listRuns({ instanceId: "web" }).map((r) => r.kind), ["software", "host"], "a box by its name, every origin");
  assert.deepEqual(listRuns({ status: "failed" }).map((r) => r.command_id), ["cmd-2"]);
  assert.equal(listRuns({ status: "ok", kind: "host" }).length, 1);
  assert.equal(listRuns({ passId: pass })[1]!.metrics_id, 42);
  const o = probeHistoryOverview();
  assert.deepEqual(o.map((x) => [x.kind, x.runs_24h, x.failed_24h, x.last_pass?.id ?? null, x.last_failure?.code ?? null]), [["host", 2, 1, pass, "timeout"], ["software", 1, 0, null, null]]);
  db.exec("delete from probe_runs; delete from probe_passes");
});

test("probe log: a probe that fails before anything is sent is still recorded, with its origin and code", async () => {
  db.exec("delete from probe_runs");
  await assert.rejects(probeInstance("not-an-instance", { kind: "host", origin: "agent" }), /not an EC2 instance id/);
  const [r] = listRuns({});
  assert.equal(r!.instance_id, "not-an-instance"); assert.equal(r!.origin, "agent"); assert.equal(r!.status, "failed"); assert.equal(r!.code, "not_managed");
  assert.match(r!.message!, /not an EC2 instance id/); assert.equal(r!.command_id, null); assert.ok(r!.finished_at);
  db.exec("delete from probe_runs");
});

import { test } from "node:test";
import assert from "node:assert";

test("findings prompt is a summary: counts and examples per control, drafts as a table, the diff kept", async () => {
  const { db } = await import("../db.js");
  const { buildPrompt } = await import("../agent.js");
  const runId = Number(db.prepare("insert into runs(trigger, status, started_at, finished_at) values ('test', 'completed', datetime('now'), datetime('now'))").run().lastInsertRowid);
  try {
  const insF = db.prepare("insert into findings(run_id, control_id, control_title, status, resource, reason, source, fingerprint) values (?, ?, ?, 'alarm', ?, ?, 'test', ?)");
  for (let i = 0; i < 120; i++) insF.run(runId, "aws_thrifty.control.ec2_instance_with_graviton", "EC2 instance is not on Graviton", `i-${String(i).padStart(17, "0")}`, `instance ${i} runs on x86 and could move to Graviton for a lower price`, `test:graviton:${i}`);
  const insR = db.prepare("insert into recommendations(fingerprint, run_id, source, rule, title, resource, action_type, est_monthly_saving, tier, confidence, rationale, evidence) values (?, ?, 'rules', ?, ?, ?, 'migrate_to_graviton', ?, 'approve', 0.7, ?, '{}')");
  for (let i = 0; i < 120; i++) insR.run(`graviton_test:${i}`, runId, "graviton_migration", `Move instance ${i} to Graviton`, `i-${String(i).padStart(17, "0")}`, 30 + i, "x".repeat(700));
    const p = buildPrompt(runId);
    assert.ok(p.length < 12000, `prompt is ${p.length} chars`);
    assert.match(p, /120 across 1 controls/);
    assert.match(p, /graviton_migration: 120 items/);
    assert.match(p, /aws_open_recommendations/);
    assert.ok(!p.includes("x".repeat(200)), "rationales are not inlined");
    assert.match(p, /largest drafts by claimed saving/);
  } finally {
    db.prepare("delete from recommendations where run_id = ?").run(runId);
    db.prepare("delete from findings where run_id = ?").run(runId);
    db.prepare("delete from runs where id = ?").run(runId);
  }
});

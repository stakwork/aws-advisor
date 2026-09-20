import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

// resolve.ts reads the inventory, roles and probes from the database: a scratch one, seeded below. No network:
// the concepts are passed in, Jev and the agent are never called.
process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "advisor-resolve-test-"));
process.env.TYPESAFE_API_KEY = "";
process.env.REPO2GRAPH_URL = "";

const { db } = await import("../db.js");
const { APPLIES_CLOSE_THRESHOLD, BLOCKER_CONFIDENCE_THRESHOLD, BLOCKERS, EFFORT_LEVELS, assembleContext, buildResolutionPrompt, filterConcepts, gateDecision, gateQuestions, gateState, parseGateAnswers, parseResolutionResult, resourceFacts } = await import("../resolve.js");
const { EC2_GRAVITON_CONTROL } = await import("../graviton.js");

const concepts = [
  { id: "c-generic-web", name: "web_or_api migrate_to_graviton rule", description: "Web boxes built from our packer template can move to Graviton; the template has an arm64 variant.", scope: "generic" as const },
  { id: "c-generic-chain", name: "blockchain_node rightsize_instance rule", description: "Never resize chain nodes without the node operator.", scope: "generic" as const },
  { id: "c-internal-web", name: "migrate_to_graviton example-web", description: "Rejected once: example-web runs a vendor binary (i-0abc000000000001) with no ARM build.", scope: "internal" as const },
  { id: "c-internal-other", name: "release_eip 1.2.3.4", description: "Keep this address, it is on a partner allow-list.", scope: "internal" as const },
];

function seed() {
  db.prepare("insert into runs(status, finished_at) values ('completed', datetime('now'))").run();
  db.prepare(`insert into inventory_ec2(instance_id, name, instance_type, state, region, launch_time, monthly_usd, cpu_30d, ssm_status, snapshot) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run("i-0abc000000000001", "example-web", "m5.xlarge", "running", "us-east-1", "2024-01-01T00:00:00Z", 140.16, 12.5, "Online",
      JSON.stringify({ tags: { Name: "example-web", env: "prod", "aws:cloudformation:stack-name": "x" }, storage: { volumes: [{ volume_id: "vol-1", size: 100, volume_type: "gp3", device: "/dev/xvda" }] } }));
  db.prepare("insert into resource_roles(resource_id, role, role_confidence, protected_prob, evidence, state_hash) values (?, ?, ?, ?, ?, ?)").run("i-0abc000000000001", "web_or_api", 0.99, 0.18, "{}", "h");
  db.prepare("insert into instance_metrics(instance_id, collected_at, json) values (?, ?, ?)").run("i-0abc000000000001", "2026-09-18T05:00:00Z",
    JSON.stringify({ top_cpu: [{ command: "node" }, { command: "nginx" }], top_mem: [{ command: "node" }, { command: "postgres" }], disks: [], memory_total_bytes: 1, memory_used_bytes: 1, load_1m: 0.1, cpus: 4 }));
  db.prepare("insert into findings(run_id, source, control_id, control_title, status, resource, reason, fingerprint) values (1, 'thrifty', ?, ?, 'alarm', ?, ?, 'fp1')")
    .run(EC2_GRAVITON_CONTROL, "EC2 instances without graviton processor should be reviewed", "arn:aws:ec2:us-east-1:1:instance/i-0abc000000000001", "example-web is not using Graviton processor.");
  const ins = db.prepare(`insert into recommendations(fingerprint, run_id, source, rule, title, resource, resource_name, action_type, est_monthly_saving, tier, confidence, rationale, evidence, status, decision_reason, decided_at) values (?, 1, 'rules', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
  ins.run("graviton_migration:i-0abc000000000001", "graviton_migration", "Move example-web from m5.xlarge to m7g.xlarge (Graviton)", "i-0abc000000000001", "example-web", "migrate_to_graviton", 21.02, "approve", 0.6, "m5.xlarge bills...",
    JSON.stringify({ playbook: EC2_GRAVITON_CONTROL, current_sku: "m5.xlarge", target_sku: "m7g.xlarge", prices: { current_hourly: 0.192, target_hourly: 0.1632 } }), "open", null, null);
  ins.run("idle_instance:i-0abc000000000001", "idle_instance", "Right-size or stop example-web", "i-0abc000000000001", "example-web", "rightsize_instance", null, "approve", 0.5, "…", "{}", "rejected", "it is the production API, leave it", "2026-09-01 00:00:00");
  ins.run("eip_unattached:eipalloc-1", "eip_unattached", "Release unattached Elastic IP 1.2.3.4", "eipalloc-1", "1.2.3.4", "release_eip", 3.65, "approve", 0.95, "…", "{}", "open", null, null);
}
seed();
const rec = (id: number) => db.prepare("select * from recommendations where id = ?").get(id) as any;

test("resourceFacts reads the inventory snapshot, the role and the probe's processes", () => {
  const f = resourceFacts(rec(1));
  assert.equal(f.kind, "ec2");
  assert.equal(f.id, "i-0abc000000000001");
  assert.equal(f.type, "m5.xlarge");
  assert.equal(f.role?.role, "web_or_api");
  assert.deepEqual(f.top_processes, ["node", "nginx", "postgres"]);
  assert.deepEqual(f.tags, { Name: "example-web", env: "prod" }); // aws:* tags dropped
  assert.deepEqual(f.volumes, [{ volume_id: "vol-1", size_gb: 100, type: "gp3", device: "/dev/xvda" }]);
  const eip = resourceFacts(rec(3));
  assert.equal(eip.kind, "other");
  assert.equal(eip.id, "eipalloc-1");
  assert.equal(eip.role, null);
  assert.equal(resourceFacts({ resource: "arn:aws:lambda:us-east-1:1:function:fn", resource_name: null, rule: "graviton_migration" }).kind, "lambda");
});

test("filterConcepts keeps what names the resource or its role, generic rules by role prefix only", () => {
  const kept = filterConcepts(concepts, { id: "i-0abc000000000001", name: "example-web", role: "web_or_api" });
  assert.deepEqual(kept.map((c) => c.id), ["c-generic-web", "c-internal-web"]);
  // an internal concept for another resource never leaks in, a generic rule for another role neither
  assert.deepEqual(filterConcepts(concepts, { id: "eipalloc-1", name: "1.2.3.4", role: null }).map((c) => c.id), ["c-internal-other"]);
  assert.deepEqual(filterConcepts(concepts, { id: "i-x", name: null, role: "blockchain_node" }).map((c) => c.id), ["c-generic-chain"]);
  assert.deepEqual(filterConcepts(concepts, { id: null, name: null, role: null }), []);
  assert.deepEqual(filterConcepts(concepts, { id: "i-", name: "pr", role: null }), []); // needles shorter than 3 characters are ignored
});

test("assembleContext: playbook from evidence, the resource, the filtered concepts, history without the recommendation itself", () => {
  const ctx = assembleContext(rec(1), concepts);
  assert.equal(ctx.control_id, EC2_GRAVITON_CONTROL);
  assert.equal(ctx.playbook?.title, "EC2 instance is not on Graviton");
  assert.equal(ctx.recommendation.id, 1);
  assert.deepEqual((ctx.recommendation.evidence as any).target_sku, "m7g.xlarge");
  assert.deepEqual(ctx.concepts.map((c) => c.id), ["c-generic-web", "c-internal-web"]);
  assert.deepEqual(ctx.history.recommendations.map((r) => r.id), [2]);
  assert.equal(ctx.history.recommendations[0].decision_reason, "it is the production API, leave it");
  assert.equal(ctx.history.findings.length, 1);
  assert.deepEqual(ctx.history.incidents, []);
  // a rule with no evidence.playbook maps through RULE_CONTROL
  const eip = assembleContext(rec(3), concepts);
  assert.equal(eip.control_id, "query.eip_unattached");
  assert.equal(eip.playbook?.tier, "approve");
  // what Jev sees is JSON-serialisable and carries the judgement calls, not the steps
  const state = gateState(ctx) as any;
  assert.equal(state.playbook.act_when, ctx.playbook!.act_when);
  assert.equal(state.playbook.steps, undefined);
  assert.equal(state.team_decisions.length, 2);
  assert.deepEqual(state.history.earlier_recommendations[0], { title: "Right-size or stop example-web", status: "rejected", decision_reason: "it is the production API, leave it" });
  JSON.stringify(state);
  const q = gateQuestions();
  assert.deepEqual(Object.keys(q), ["applies", "blocker", "effort"]);
  // the prompt names the resource, the concept ids and the playbook steps
  const prompt = buildResolutionPrompt(ctx, null);
  assert.match(prompt, /# Resolution for recommendation #1/);
  assert.match(prompt, /\[c-generic-web\]/);
  assert.match(prompt, /GENERIC rule for this role/);
  assert.match(prompt, /1\. List what runs on the box/);
  assert.match(prompt, /not available \(Jev is off\)/);
  assert.match(prompt, /recommendation #2 \[rejected\]/);
});

test("gate decision: only a confident specific blocker, or a confident 'does not apply', closes it; thin evidence goes to the agent as unsure", () => {
  const answers = (applies: number, blocker: string, effort: number, confidence = 0.8) => ({
    applies: { type: "noul", noul: applies },
    blocker: { type: "choice", choice: blocker, confidence, probabilities: { [blocker]: confidence } },
    effort: { type: "score", score: effort },
  });
  assert.equal(BLOCKER_CONFIDENCE_THRESHOLD, 0.7);
  assert.equal(APPLIES_CLOSE_THRESHOLD, 0.15);
  // confident specific blocker: closed, whatever `applies` says
  const g1 = parseGateAnswers(answers(0.12, "third_party_binary_without_arm_build", 2, 0.82), { model: "jev-x", call_id: 7 });
  assert.ok(g1);
  assert.equal(g1.effort_label, EFFORT_LEVELS[2]);
  const d1 = gateDecision(g1, { concepts: 0 });
  assert.equal(d1.decision, "not_applicable");
  assert.equal(d1.outcome, "blocked");
  assert.equal(d1.reason, `Closed: Jev is confident (82%) the blocker is third party binary without arm build (${BLOCKERS.third_party_binary_without_arm_build}); applies 12%. No team decisions or rules on record for this resource or its role yet.`);
  assert.equal(gateDecision(parseGateAnswers(answers(0.6, "retiring_soon", 0, 0.7))).outcome, "blocked"); // exactly at the threshold, high applies: still closed
  // the user's real case: applies 0.29, blocker none at 0.46 -> unsure, the agent decides
  const d2 = gateDecision(parseGateAnswers(answers(0.29, "none", 0, 0.46)), { concepts: 0 });
  assert.equal(d2.decision, "proceed");
  assert.equal(d2.outcome, "unsure");
  assert.equal(d2.reason, "Jev is unsure (applies 29%, no confident blocker), asking the agent. No team decisions or rules on record for this resource or its role yet.");
  // a specific blocker below 0.7 never closes
  const d3 = gateDecision(parseGateAnswers(answers(0.2, "retiring_soon", 1, 0.5)), { concepts: 2 });
  assert.equal(d3.outcome, "unsure");
  assert.match(d3.reason, /blocker retiring soon only at 50%/);
  assert.match(d3.reason, /2 team decisions or rules on record for it\.$/);
  // very low applies with a confident `none`: closed as not applying
  const d4 = gateDecision(parseGateAnswers(answers(0.1, "none", 0, 0.9)));
  assert.equal(d4.outcome, "blocked");
  assert.equal(d4.reason, "Closed: Jev is confident (90%) it does not apply (applies 10%) and nothing specific blocks it.");
  // very low applies with a confident `unknown`: Jev says the facts are missing, the agent can find them
  assert.equal(gateDecision(parseGateAnswers(answers(0.1, "unknown", 1, 0.95))).outcome, "unsure");
  // very low applies with a shaky `none`: unsure
  assert.equal(gateDecision(parseGateAnswers(answers(0.1, "none", 1, 0.5))).outcome, "unsure");
  // high applies: applies, with the possible blocker named when there is one
  const d5 = gateDecision(parseGateAnswers(answers(0.91, "none", 1, 0.6)), { concepts: 1 });
  assert.equal(d5.decision, "proceed");
  assert.equal(d5.outcome, "applies");
  assert.equal(d5.reason, "Jev thinks it applies (91%), effort a day; asking the agent for the plan. 1 team decision or rule on record for it.");
  assert.match(gateDecision(parseGateAnswers(answers(0.6, "stateful_data_migration", 2, 0.4))).reason, /^Jev thinks it applies \(60%\), possible blocker stateful data migration \(40%\)/);
  // Jev off / no answer
  const off = gateDecision(null, { concepts: 0 });
  assert.equal(off.decision, "proceed");
  assert.equal(off.outcome, "unsure");
  assert.match(off.reason, /not configured or did not answer; asking the agent\. No team decisions/);
  // malformed answers
  assert.equal(parseGateAnswers({ applies: { type: "noul", noul: 0.5 } }), null);
  assert.equal(parseGateAnswers(answers(0.5, "made_up_blocker", 1))?.blocker, "unknown");
  assert.equal(parseGateAnswers(answers(0.5, "none", 9))?.effort_label, EFFORT_LEVELS[2]);
});

test("parseResolutionResult validates the agent's plan and tolerates junk", () => {
  const plan = parseResolutionResult({
    applies: true, summary: "Rebuild from the arm64 packer template.", blockers: [], risk: "approve", est_monthly_saving: 21,
    plan: [{ step: "Build the arm64 AMI", command: "packer build -var arch=arm64 web.pkr.hcl", verify: "AMI is available" }, { step: "Launch", verify: "healthy" }, "junk", { nostep: 1 }],
    needs_from_human: ["a maintenance window"], concepts_used: ["c-generic-web", 42],
  });
  assert.ok(plan);
  assert.equal(plan.plan.length, 2);
  assert.equal(plan.plan[0].command, "packer build -var arch=arm64 web.pkr.hcl");
  assert.equal(plan.plan[1].command, undefined);
  assert.deepEqual(plan.concepts_used, ["c-generic-web", "42"]);
  assert.equal(plan.est_monthly_saving, 21);
  assert.equal(parseResolutionResult({ applies: false, summary: "no", plan: [], risk: "bogus", est_monthly_saving: "x" })?.risk, "approve");
  assert.equal(parseResolutionResult({ applies: false, summary: "no", plan: [], risk: "report", est_monthly_saving: "x" })?.est_monthly_saving, null);
  assert.equal(parseResolutionResult({ summary: "no plan array" }), null);
  assert.equal(parseResolutionResult("text"), null);
  assert.equal(parseResolutionResult(null), null);
});

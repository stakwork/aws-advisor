import assert from "node:assert/strict";
import { test } from "node:test";
import { SEVERITY_LEVELS, autoAckSuffix, severityLabel, triageDecision, triageQuestions } from "../triage.js";
import { NATURALLY_IDLE_ROLES, buildRecommendations, isProtected } from "../rules.js";
import { ROLE_OPTIONS, roleQuestions, roleState, roleStateHash } from "../roles.js";
import { applyTierCheck, tierQuestions, tightenTier } from "../tiercheck.js";

// Every test here uses fixture answers: no key, no network. src/jev.ts's askJev is a no-op without TYPESAFE_API_KEY.

test("triageDecision: routine and harmless -> acknowledge; unexpected or costly -> investigate; otherwise open", () => {
  assert.equal(triageDecision({ expected: 0.92, severity: 0.4 }), "acknowledge");
  assert.equal(triageDecision({ expected: 0.85, severity: 1 }), "acknowledge"); // both thresholds inclusive
  assert.equal(triageDecision({ expected: 0.92, severity: 1.3 }), "open"); // expected but not that harmless
  assert.equal(triageDecision({ expected: 0.2, severity: 0.5 }), "investigate"); // unexpected, even if cheap
  assert.equal(triageDecision({ expected: 0.4, severity: 0.5 }), "investigate"); // inclusive
  assert.equal(triageDecision({ expected: 0.7, severity: 2.4 }), "investigate"); // costly, even if plausible
  assert.equal(triageDecision({ expected: 0.6, severity: 1.1 }), "open");
  assert.equal(triageDecision({ expected: 0.55, severity: 1.02 }), "open"); // the real NAT alert in the fixture DB
});

test("severity labels and the auto-ack note", () => {
  assert.equal(SEVERITY_LEVELS.length, 4);
  assert.equal(severityLabel(0.3), "Noise");
  assert.equal(severityLabel(1.04), "Worth a look this week");
  assert.equal(severityLabel(1.68), "Should be looked at today");
  assert.equal(severityLabel(7), "Costing real money right now");
  assert.equal(autoAckSuffix({ kind: "cold_start_pulls", expected: 0.913 }), " Auto-acknowledged: cold_start_pulls (0.91)");
  const q = triageQuestions();
  assert.deepEqual(Object.keys(q), ["expected", "kind", "severity"]);
  assert.equal(q.kind.type, "choice");
  assert.equal(q.severity.type, "score");
  assert.equal((q.severity.criteria as readonly string[]).length, 4);
});

test("isProtected prefers Jev's answer and falls back to the name regex", () => {
  assert.deepEqual(isProtected("example-node-1 (do not delete)"), { protected: true, source: "regex" });
  assert.deepEqual(isProtected("example-dev"), { protected: false, source: "regex" });
  assert.deepEqual(isProtected("example-dev", { role: "dev_or_test", role_confidence: 0.9, protected_prob: 0.75 }), { protected: true, source: "jev" });
  // Jev's answer wins even when the regex would have matched
  assert.deepEqual(isProtected("keep-this", { role: "web_or_api", role_confidence: 0.9, protected_prob: 0.1 }), { protected: false, source: "jev" });
});

test("roles adjust the stopped-instance and idle-instance rules", () => {
  const stopped = [{ instance_id: "i-prot", name: "example-node-2", instance_type: "m6i.xlarge", stopped_on: "2026-01-01", ebs_gb: 100 },
    { instance_id: "i-dev", name: "example-dev", instance_type: "t3.large", stopped_on: "2026-01-01", ebs_gb: 30 },
    { instance_id: "i-plain", name: "example-node-3", instance_type: "m6i.xlarge", stopped_on: "2026-01-01", ebs_gb: 100 }];
  const idle = [{ instance_id: "i-btc", name: "Example Bitcoind", instance_type: "m5.large", avg_max_cpu: 4.1, days: 30 },
    { instance_id: "i-mqtt", name: "mqtt-broker-open", instance_type: "t2.micro", avg_max_cpu: 3, days: 30 },
    { instance_id: "i-unsure", name: "example-cache", instance_type: "t2.medium", avg_max_cpu: 3, days: 30 },
    { instance_id: "i-devidle", name: "swarm-test", instance_type: "m6i.xlarge", avg_max_cpu: 2, days: 30 },
    { instance_id: "i-none", name: "something", instance_type: "m6i.xlarge", avg_max_cpu: 2, days: 30 }];
  const roles = {
    "i-prot": { role: "unknown", role_confidence: 0.3, protected_prob: 0.75 },
    "i-dev": { role: "dev_or_test", role_confidence: 0.94, protected_prob: 0.07 },
    "i-btc": { role: "blockchain_node", role_confidence: 0.99, protected_prob: 0.16 },
    "i-mqtt": { role: "cache_or_queue", role_confidence: 1.0, protected_prob: 0.12 },
    "i-unsure": { role: "cache_or_queue", role_confidence: 0.55, protected_prob: 0.15 }, // below the 0.7 confidence bar
    "i-devidle": { role: "dev_or_test", role_confidence: 0.9, protected_prob: 0.2 },
  };
  const recs = buildRecommendations({ queryRows: { stopped_instance_ebs: stopped, idle_instances: idle }, aurora: [], roles });
  const by = Object.fromEntries(recs.map((r) => [r.resource, r]));

  assert.equal(by["i-prot"].tier, "report");
  assert.match(by["i-prot"].rationale, /deliberately kept \(0\.75\)/);
  assert.equal(by["i-dev"].tier, "approve");
  assert.match(by["i-dev"].rationale, /scheduler/);
  assert.equal(by["i-plain"].tier, "approve"); // no role on file: regex fallback, name is plain
  assert.doesNotMatch(by["i-plain"].rationale, /Jev/);

  assert.equal(by["i-btc"].confidence, 0.2);
  assert.match(by["i-btc"].rationale, /blockchain_node \(0\.99\).*naturally low on CPU/);
  assert.equal(by["i-mqtt"].confidence, 0.2);
  assert.equal(by["i-unsure"].confidence, 0.4); // low-confidence role changes nothing
  assert.equal(by["i-devidle"].tier, "approve");
  assert.equal(by["i-devidle"].confidence, 0.4);
  assert.match(by["i-devidle"].rationale, /parks it out of hours/);
  assert.equal(by["i-none"].confidence, 0.4);
  assert.deepEqual((by["i-btc"].evidence as any).role, roles["i-btc"]);
  assert.deepEqual(NATURALLY_IDLE_ROLES, ["blockchain_node", "cache_or_queue"]);
});

test("role questions are scoped per resource and the state hash follows name and tags", () => {
  const q = roleQuestions("r3");
  assert.deepEqual(Object.keys(q), ["r3_role", "r3_protected"]);
  assert.match(String((q.r3_role as any).instructions), /resources\.r3/);
  assert.deepEqual(Object.keys((q.r3_role as any).criteria), Object.keys(ROLE_OPTIONS));
  const facts = { resource_id: "i-1", kind: "ec2" as const, name: "Example VPN", tags: { backup: "enabled" }, instance_type: "t3a.small", platform: "Linux/UNIX", launch_time: "2024-09-24T14:03:28.000Z", state: "running", top_processes: ["pritunl", "mongod"], volume_sizes_gb: [8] };
  const h1 = roleStateHash(facts);
  assert.equal(h1, roleStateHash({ ...facts, top_processes: [], state: "stopped" })); // usage does not invalidate the cache
  assert.notEqual(h1, roleStateHash({ ...facts, tags: { backup: "enabled", Owner: "paul" } }));
  assert.notEqual(h1, roleStateHash({ ...facts, name: "Example VPN (do not delete)" }));
  const st = roleState(facts);
  assert.equal(st.kind, "EC2 instance");
  assert.deepEqual(st.top_processes, ["pritunl", "mongod"]);
  assert.equal(roleState({ ...facts, top_processes: [] }).top_processes, "no probe on file");
});

test("tightenTier only ever makes a tier stricter", () => {
  assert.equal(tightenTier("auto", { irreversible: 0.1, service_impact: 0.2 }), "auto");
  assert.equal(tightenTier("auto", { irreversible: 0.6, service_impact: 0.2 }), "approve");
  assert.equal(tightenTier("auto", { irreversible: 0.1, service_impact: 1.5 }), "approve");
  assert.equal(tightenTier("auto", { irreversible: 0.85, service_impact: 0 }), "report");
  assert.equal(tightenTier("approve", { irreversible: 0.84, service_impact: 2 }), "approve"); // just under the report bar
  assert.equal(tightenTier("approve", { irreversible: 0.9, service_impact: 0 }), "report");
  assert.equal(tightenTier("report", { irreversible: 0, service_impact: 0 }), "report"); // never loosened
  assert.equal(tightenTier("approve", { irreversible: 0, service_impact: 0 }), "approve");
});

test("applyTierCheck records the check in evidence.jev and explains a change in the rationale", () => {
  const rec = { rule: "agent:release_eip", title: "Release 3 unattached Elastic IPs", resource: "eipalloc-1", actionType: "release_eip", estMonthlySaving: 11, tier: "auto" as const, confidence: 0.9, rationale: "Unattached.", evidence: { title: "x" } };
  const out = applyTierCheck(rec, { irreversible: 0.84, service_impact: 0.14 }, "jev-test");
  assert.equal(out.tier, "approve");
  assert.match(out.rationale, /Jev tier check: auto -> approve \(irreversible 0\.84/);
  const jev = (out.evidence as any).jev;
  assert.equal((out.evidence as any).title, "x");
  assert.deepEqual([jev.tier_before, jev.tier_after, jev.service_impact_label, jev.model], ["auto", "approve", "No user-visible effect", "jev-test"]);
  const same = applyTierCheck({ ...rec, tier: "approve" }, { irreversible: 0.2, service_impact: 0.5 });
  assert.equal(same.tier, "approve");
  assert.equal(same.rationale, "Unattached."); // nothing changed, nothing appended
  assert.equal((same.evidence as any).jev.tier_after, "approve");
  // evidence that is not an object is kept under `original`
  assert.deepEqual((applyTierCheck({ ...rec, evidence: ["a"] }, { irreversible: 0, service_impact: 0 }).evidence as any).original, ["a"]);
  const q = tierQuestions("f2");
  assert.deepEqual(Object.keys(q), ["f2_irreversible", "f2_service_impact"]);
  assert.match(String((q.f2_service_impact as any).instructions), /proposed_changes\.f2/);
});

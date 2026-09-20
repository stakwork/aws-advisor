import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

// graph_mirror.ts reads the inventory, recommendations, alerts and concepts from the database: a scratch one,
// seeded below. The guard and the row-to-node mapping need no Neo4j; the live test at the end runs only when
// NEO4J_URI is set (the local dev graph), with its own account id so its cleanup is exact.
process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "advisor-graph-test-"));
process.env.TYPESAFE_API_KEY = "";
process.env.REPO2GRAPH_URL = "";

const TEST_ACCOUNT = "TEST-000000000000";
const LIVE = Boolean(process.env.NEO4J_URI);

const { db } = await import("../db.js");
await import("../concepts.js"); // creates the concepts table and the decision_scope column, as the app does at startup
const gm = await import("../graph_mirror.js");

// ---- the Cypher guard --------------------------------------------------------------------------------------------

test("guardReadCypher accepts read-only statements", () => {
  for (const q of [
    "MATCH (r:AdvisorResource {id: 'i-1'})-[e]-(x) RETURN r, e, x",
    "  optional match (r:AdvisorResource) return count(r);",
    "WITH 'set' AS word MATCH (n:AdvisorRole {name: word}) RETURN n",
    "CALL { MATCH (n:AdvisorAlert) RETURN n LIMIT 5 } RETURN n",
    "MATCH (n) WHERE n.title CONTAINS 'DELETE the snapshot' RETURN n // comment with MERGE",
    "MATCH (n:AdvisorRecommendation) WHERE n.status = \"created\" RETURN n.title",
    "MATCH (n) RETURN n.reset, n.startAt, n.created_at",
  ]) {
    const g = gm.guardReadCypher(q);
    assert.ok("cypher" in g, `${q} -> ${JSON.stringify(g)}`);
  }
  assert.equal((gm.guardReadCypher("MATCH (n) RETURN n;") as any).cypher, "MATCH (n) RETURN n");
});

test("guardReadCypher rejects writes, procedures and multiple statements", () => {
  const reject = (q: string, re: RegExp) => { const g = gm.guardReadCypher(q); assert.ok("error" in g, `${q} should be rejected`); assert.match((g as any).error, re); };
  reject("", /empty/);
  reject("CREATE (n:AdvisorResource {id: 'x'})", /must start with/);
  reject("RETURN 1", /must start with/);
  reject("MATCH (n) SET n.gone = true RETURN n", /SET/);
  reject("MATCH (n) DETACH DELETE n", /DETACH|DELETE/);
  reject("MATCH (n) REMOVE n.gone RETURN n", /REMOVE/);
  reject("MATCH (n) WITH n MERGE (m:X) RETURN m", /MERGE/);
  reject("MATCH (n) RETURN n; MATCH (m) DELETE m", /single statement/);
  reject("MATCH (n) CALL apoc.create.node(['X'], {}) YIELD node RETURN node", /apoc|CREATE/);
  reject("CALL { MATCH (n) RETURN n } CALL dbms.killConnections(['x']) RETURN 1", /dbms/);
  reject("WITH 1 AS x CALL db.createLabel('X') RETURN x", /procedures|CREATE/);
  reject("MATCH (n) FOREACH (x IN [1] | SET n.a = x) RETURN n", /FOREACH|SET/);
  reject("MATCH (n) WITH n LOAD CSV FROM 'file:///x' AS row RETURN row", /LOAD/);
  reject("MATCH (n) DROP CONSTRAINT x", /DROP/);
});

// ---- the row-to-node mapping ---------------------------------------------------------------------------------------

test("inventoryIdOf matches ids and ARN tails, and nothing else", () => {
  const ids = new Set(["i-1", "prod-db", "cache-1"]);
  assert.equal(gm.inventoryIdOf("i-1", ids), "i-1");
  assert.equal(gm.inventoryIdOf("arn:aws:ec2:us-east-1:1:instance/i-1", ids), "i-1");
  assert.equal(gm.inventoryIdOf("arn:aws:rds:us-east-1:1:db:prod-db", ids), "prod-db");
  assert.equal(gm.inventoryIdOf("arn:aws:rds:us-east-1:1:cluster:prod-db-cluster", ids), null);
  assert.equal(gm.inventoryIdOf("arn:aws:s3:::bucket", ids), null);
  assert.equal(gm.inventoryIdOf("vpc-1", ids), null);
  assert.equal(gm.inventoryIdOf(null, ids), null);
});

test("poolOf reads Karpenter, EKS and ASG tags and prefixes the cluster", () => {
  assert.equal(gm.poolOf(JSON.stringify({ tags: { "karpenter.sh/nodepool": "workspace", "eks:cluster-name": "prod" } })), "prod/workspace");
  assert.equal(gm.poolOf(JSON.stringify({ tags: { "eks:nodegroup-name": "ng-1" } })), "ng-1");
  assert.equal(gm.poolOf(JSON.stringify({ tags: { "aws:autoscaling:groupName": "asg-1", Name: "x" } })), "asg-1");
  assert.equal(gm.poolOf(JSON.stringify({ tags: { Name: "x" } })), null);
  assert.equal(gm.poolOf("not json"), null);
  assert.equal(gm.poolOf(null), null);
});

test("resource nodes carry the same shape for EC2, RDS and ElastiCache", () => {
  const roles = new Map([["i-1", { role: "web_or_api", role_confidence: 0.9, protected_prob: 0.1 }], ["prod-db", { role: "database", role_confidence: "0.8" as any, protected_prob: null }]]);
  const ec2 = gm.resourceFromEc2({ instance_id: "i-1", name: "web", instance_type: "m6i.large", state: "running", region: "us-east-1", monthly_usd: "70.08", cpu_30d: 12.5, ssm_status: "Online", gone: 0, first_seen: "2026-01-01 00:00:00", last_seen: "2026-09-19 00:00:00", snapshot: JSON.stringify({ tags: { "eks:nodegroup-name": "ng", "eks:cluster-name": "c" } }) }, roles);
  assert.deepEqual(ec2, { id: "i-1", kind: "ec2", name: "web", type: "m6i.large", state: "running", region: "us-east-1", role: "web_or_api", role_confidence: 0.9, protected_prob: 0.1, monthly_usd: 70.08, cpu_30d: 12.5, ssm_status: "Online", gone: false, first_seen: "2026-01-01 00:00:00", last_seen: "2026-09-19 00:00:00", pool: "c/ng" });
  const rds = gm.resourceFromRds({ db_instance_identifier: "prod-db", class: "db.r6g.large", status: "available", region: "us-east-1", monthly_usd: null, cpu_30d: null, gone: 1, first_seen: "a", last_seen: "b", snapshot: "{}" }, roles);
  assert.deepEqual(rds, { id: "prod-db", kind: "rds", name: "prod-db", type: "db.r6g.large", state: "available", region: "us-east-1", role: "database", role_confidence: 0.8, protected_prob: null, monthly_usd: null, cpu_30d: null, ssm_status: null, gone: true, first_seen: "a", last_seen: "b", pool: null });
  const cache = gm.resourceFromElasticache({ cache_cluster_id: "cache-1", node_type: "cache.t4g.small", status: "available", region: "eu-west-1", monthly_usd: 24.8, gone: 0, first_seen: "a", last_seen: "b", snapshot: "{}" });
  assert.equal(cache.kind, "elasticache");
  assert.equal(cache.role, null);
  assert.equal(cache.monthly_usd, 24.8);
  assert.deepEqual(Object.keys(cache).sort(), Object.keys(ec2).sort());
});

test("recommendation nodes resolve their target, concept, run and incident", () => {
  const inv = new Set(["i-1"]);
  const concepts = new Map([["idle_instance:i-1", "aws/cost-advisor/stop-instance-i-1"]]);
  const row = { id: 7, fingerprint: "idle_instance:i-1", title: "Stop i-1", action_type: "stop_instance", tier: "approve", status: "rejected", source: "rules", rule: "idle_instance", est_monthly_saving: "70.08", confidence: 0.6,
    decided_by: "ops", decided_at: "2026-09-18 10:00:00", decision_scope: "generic", created_at: "2026-09-01 00:00:00", run_id: 6, resource: "arn:aws:ec2:us-east-1:1:instance/i-1", evidence: "{}" };
  const n = gm.recommendationNode(row, inv, concepts);
  assert.equal(n.resource_id, "i-1");
  assert.equal(n.concept_id, "aws/cost-advisor/stop-instance-i-1");
  assert.equal(n.run_id, 6);
  assert.equal(n.incident_id, null);
  assert.equal(n.est_monthly_saving, 70.08);
  assert.equal(n.decision_scope, "generic");
  // an incident fix: run 0 (no run), evidence carries the incident, the VPC is not in the inventory -> a ResourceRef
  const fix = gm.recommendationNode({ ...row, id: 8, fingerprint: "incident:enable_flow_logs:vpc-1", rule: "incident:enable_flow_logs", run_id: 0, resource: "vpc-1", evidence: JSON.stringify({ incident_id: 3, alert_id: 23 }) }, inv, concepts);
  assert.equal(fix.resource_id, null);
  assert.equal(fix.resource, "vpc-1");
  assert.equal(fix.run_id, null);
  assert.equal(fix.incident_id, 3);
  assert.equal(fix.concept_id, null);
});

test("alert, incident and run nodes; flag edges only for inventory resources, one per control and resource", () => {
  const inv = new Set(["i-1", "i-2"]);
  const a = gm.alertNode({ id: 1, kind: "nat_traffic", resource: "nat-1", message: "x".repeat(600), created_at: "2026-09-19 00:00:00", acknowledged: 1, acknowledged_by: "jev" }, inv, "alarm");
  assert.equal(a.message.length, 500);
  assert.equal(a.acknowledged, true);
  assert.equal(a.resource_id, null);
  assert.equal(gm.alertNode({ id: 2, kind: "instance_state", resource: "i-2", message: "m", created_at: "t", acknowledged: 0 }, inv, "warning").resource_id, "i-2");
  const i = gm.incidentNode({ id: 3, alert_id: 1, status: "completed", cause: "pulls", confidence: "0.6", episode_cost_usd: 0.14, monthly_run_rate_usd: null, created_at: "t" });
  assert.deepEqual(i, { id: 3, alert_id: 1, status: "completed", cause: "pulls", confidence: 0.6, episode_cost_usd: 0.14, monthly_run_rate_usd: null, created_at: "t" });
  const r = gm.runNode({ id: 6, started_at: "s", finished_at: null, status: "running", trigger: "manual", findings_count: null, recommendations_count: 3 });
  assert.deepEqual(r, { id: 6, started_at: "s", finished_at: null, status: "running", trigger: "manual", findings_count: 0, recommendations_count: 3 });
  const edges = gm.flagEdges([
    { control_id: "c1", control_title: "C1", resource: "arn:aws:ec2:us-east-1:1:instance/i-1", reason: "r1" },
    { control_id: "c1", control_title: "C1", resource: "i-1", reason: "dup" },
    { control_id: "c1", control_title: "C1", resource: "arn:aws:s3:::bucket", reason: "skip" },
    { control_id: "c2", control_title: null, resource: "i-2", reason: null },
  ], inv, 6);
  assert.deepEqual(edges, [
    { control_id: "c1", control_title: "C1", resource_id: "i-1", run_id: 6, reason: "r1" },
    { control_id: "c2", control_title: null, resource_id: "i-2", run_id: 6, reason: null },
  ]);
});

test("graphUriForDisplay never shows credentials", () => {
  assert.equal(gm.graphUriForDisplay("bolt://neo4j:secret@neo4j.sphinx:7687"), "bolt://neo4j.sphinx:7687");
  assert.equal(gm.graphUriForDisplay("neo4j+s://host:7687"), "neo4j+s://host:7687");
  assert.equal(gm.graphUriForDisplay(""), null);
});

test("without NEO4J_URI every mirror function is a no-op", { skip: LIVE }, async () => {
  assert.equal(gm.enabled(), false);
  assert.equal(await gm.mirrorAll(), null);
  assert.deepEqual(await gm.mirrorResources(), { resources: 0 });
  assert.deepEqual(await gm.mirrorRecommendations([1]), { recommendations: 0 });
  assert.deepEqual(await gm.mirrorAlertsAndIncidents(), { alerts: 0, incidents: 0 });
  assert.deepEqual(await gm.mirrorRun(1), { run: null, flagged: 0 });
  assert.deepEqual(await gm.verifyConnection(), { connected: false, error: "NEO4J_URI is not set" });
  await assert.rejects(gm.readQuery("MATCH (n) RETURN n"), /not configured/);
});

// ---- live: the local dev Neo4j -------------------------------------------------------------------------------------------

function seed() {
  db.prepare("insert into runs(id, status, trigger, account_id, finished_at, findings_count, recommendations_count) values (1, 'completed', 'manual', ?, datetime('now'), 3, 2)").run(TEST_ACCOUNT);
  db.prepare("insert into runs(id, status, trigger, account_id) values (2, 'failed', 'cron', ?)").run(TEST_ACCOUNT);
  const ec2 = db.prepare("insert into inventory_ec2(instance_id, name, instance_type, state, region, monthly_usd, cpu_30d, ssm_status, gone, snapshot) values (?, ?, ?, ?, 'us-east-1', ?, ?, ?, ?, ?)");
  ec2.run("i-test1", "web-1", "m6i.large", "running", 70.08, 12.5, "Online", 0, JSON.stringify({ tags: { "karpenter.sh/nodepool": "workspace", "eks:cluster-name": "prod" } }));
  ec2.run("i-test2", "chain-1", "m5.xlarge", "running", 140.16, 3, null, 0, "{}");
  ec2.run("i-test3", "old-box", "t3.small", "stopped", null, null, null, 0, "{}");
  db.prepare("insert into inventory_rds(db_instance_identifier, class, engine, status, region, monthly_usd, gone, snapshot) values ('test-db', 'db.r6g.large', 'postgres', 'available', 'us-east-1', 200, 0, '{}')").run();
  db.prepare("insert into inventory_elasticache(cache_cluster_id, node_type, engine, status, region, num_nodes, monthly_usd, gone, snapshot) values ('test-cache', 'cache.t4g.small', 'redis', 'available', 'us-east-1', 1, 24.8, 0, '{}')").run();
  db.prepare("insert into resource_roles(resource_id, role, role_confidence, protected_prob, evidence, state_hash) values ('i-test2', 'blockchain_node', 0.84, 0.1, '{}', 'h'), ('test-db', 'database', 0.9, 0.5, '{}', 'h')").run();
  const rec = db.prepare("insert into recommendations(id, fingerprint, run_id, source, rule, title, resource, action_type, est_monthly_saving, tier, confidence, status, decided_by, decided_at, decision_scope, evidence) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
  rec.run(1, "idle_instance:i-test2", 1, "rules", "idle_instance", "Stop chain-1", "arn:aws:ec2:us-east-1:1:instance/i-test2", "stop_instance", 140.16, "approve", 0.6, "rejected", "test", "2026-09-18 10:00:00", "generic", "{}");
  rec.run(2, "graviton_migration:i-test1", 1, "rules", "graviton_migration", "Move web-1 to m7g", "i-test1", "migrate_to_graviton", 21, "approve", 0.7, "open", null, null, null, "{}");
  rec.run(3, "incident:enable_flow_logs:vpc-test", 0, "agent", "incident:enable_flow_logs", "Enable flow logs", "vpc-test", "enable_flow_logs", 0, "approve", 0.9, "open", null, null, null, JSON.stringify({ incident_id: 1, alert_id: 1 }));
  db.prepare("insert into alerts(id, kind, resource, message, acknowledged, acknowledged_by) values (1, 'nat_traffic', 'nat-test', 'NAT spike', 0, null), (2, 'instance_state', 'i-test1', 'web-1 went from stopped to running', 1, 'jev')").run();
  db.prepare("insert into incidents(id, alert_id, status, cause, confidence, episode_cost_usd, monthly_run_rate_usd) values (1, 1, 'completed', 'image pulls', 0.6, 0.14, 144)").run();
  const f = db.prepare("insert into findings(run_id, source, control_id, control_title, status, resource, reason, fingerprint) values (1, 'thrifty', ?, ?, 'alarm', ?, ?, ?)");
  f.run("aws_thrifty.control.ec2_instance_with_graviton", "EC2 instance is not on Graviton", "arn:aws:ec2:us-east-1:1:instance/i-test1", "web-1 is not using Graviton", "fp1");
  f.run("aws_thrifty.control.instances_with_low_utilization", "Low utilization", "arn:aws:ec2:us-east-1:1:instance/i-test2", "3% CPU", "fp2");
  f.run("aws_thrifty.control.buckets_with_no_lifecycle", "Bucket lifecycle", "arn:aws:s3:::some-bucket", "no lifecycle", "fp3");
}

test("live: mirrorAll into the local Neo4j, graphStats, DECIDED_AS to an existing Concept, resync idempotence, wipe", { skip: !LIVE }, async () => {
  seed();
  assert.equal(gm.accountId(), TEST_ACCOUNT);
  const conn = await gm.verifyConnection();
  assert.equal(conn.connected, true, conn.error);
  // Link recommendation 1 to whichever Concept the shared graph already has (MATCH only, never created here).
  const concept = (await gm.readQuery("MATCH (c:Concept) RETURN c.id AS id LIMIT 1", {}, { rowCap: 1 })).rows[0]?.id as string | undefined;
  if (concept) db.prepare("insert into concepts(fingerprint, concept_id, status, scope) values ('idle_instance:i-test2', ?, 'rejected', 'generic')").run(concept);
  db.prepare("insert into concepts(fingerprint, concept_id, status, scope) values ('graviton_migration:i-test1', 'aws/cost-advisor/does-not-exist-in-the-graph', 'open', 'internal')").run();
  try {
    await gm.wipeMirror(TEST_ACCOUNT);
    const counts = await gm.mirrorAll();
    assert.ok(counts);
    assert.equal(counts.account_id, TEST_ACCOUNT);
    assert.deepEqual([counts.resources, counts.recommendations, counts.runs, counts.alerts, counts.incidents], [5, 3, 2, 2, 1]);
    assert.equal(counts.flagged, 2, "the bucket finding is skipped, the two instances are flagged");
    assert.ok(counts.playbooks > 20);

    const stats = await gm.graphStats();
    const mine = await gm.readQuery("MATCH (n) WHERE any(l IN labels(n) WHERE l STARTS WITH 'Advisor') AND n.account_id = $a UNWIND labels(n) AS l WITH l, count(*) AS n WHERE l STARTS WITH 'Advisor' RETURN l AS label, n", { a: TEST_ACCOUNT }, { rowCap: 100 });
    const byLabel = Object.fromEntries(mine.rows.map((r) => [String(r.label), Number(r.n)]));
    assert.equal(byLabel.AdvisorAccount, 1);
    assert.equal(byLabel.AdvisorResource, 5);
    assert.equal(byLabel.AdvisorRecommendation, 3);
    assert.equal(byLabel.AdvisorRun, 2);
    assert.equal(byLabel.AdvisorAlert, 2);
    assert.equal(byLabel.AdvisorIncident, 1);
    assert.equal(byLabel.AdvisorResourceRef, 2, "vpc-test and nat-test");
    assert.equal(byLabel.AdvisorRole, 2);
    assert.equal(byLabel.AdvisorNodePool, 1);
    for (const [l, n] of Object.entries(byLabel)) assert.ok((stats.nodes[l] || 0) >= n, `${l} in graphStats`);

    const view = await gm.resourceView("i-test2");
    assert.ok(view);
    assert.equal(view.role, "blockchain_node");
    assert.equal(view.counts.recommendations, 1);
    assert.equal(view.counts.controls, 1);
    assert.equal(view.recommendations[0].concept?.id ?? null, concept ?? null, "DECIDED_AS only to a Concept that exists");
    const web = await gm.resourceView("i-test1");
    assert.equal(web?.pool, "prod/workspace");
    assert.equal(web?.counts.alerts, 1);
    assert.equal(web?.recommendations[0].concept, null, "a concept id the graph does not know draws no edge");
    const notGone = await gm.readQuery("MATCH (r:AdvisorResource {id: 'i-test3'}) RETURN r.gone AS gone", {}, { rowCap: 1 });
    assert.equal(notGone.rows[0].gone, false);
    const fix = await gm.readQuery("MATCH (rec:AdvisorRecommendation {id: 3})-[:FROM_INCIDENT]->(i:AdvisorIncident)-[:INVESTIGATES]->(a:AdvisorAlert)-[:ABOUT]->(x) RETURN i.id AS incident, a.id AS alert, labels(x) AS about", {}, { rowCap: 1 });
    assert.deepEqual(fix.rows[0], { incident: 1, alert: 1, about: ["AdvisorResourceRef"] });

    // Gone in the inventory, or vanished from it altogether, both mark the node gone; a decision changes the node in place; nothing duplicates.
    db.prepare("update inventory_ec2 set gone = 1 where instance_id = 'i-test1'").run();
    db.prepare("delete from inventory_ec2 where instance_id = 'i-test3'").run();
    db.prepare("update recommendations set status = 'approved', decided_by = 'test' where id = 2").run();
    await gm.mirrorResources();
    await gm.mirrorRecommendations([2]);
    const again = await gm.mirrorAll();
    assert.equal(again?.resources, 4);
    const after = await gm.readQuery("MATCH (r1:AdvisorResource {id: 'i-test1'}), (r3:AdvisorResource {id: 'i-test3'}), (rec:AdvisorRecommendation {id: 2}) RETURN r1.gone AS gone1, r3.gone AS gone3, rec.status AS status, count(*) AS n", {}, { rowCap: 1 });
    assert.deepEqual(after.rows[0], { gone1: true, gone3: true, status: "approved", n: 1 });
    const total = await gm.readQuery("MATCH (n) WHERE any(l IN labels(n) WHERE l STARTS WITH 'Advisor') AND n.account_id = $a RETURN count(n) AS n", { a: TEST_ACCOUNT }, { rowCap: 1 });
    assert.equal(Number(total.rows[0].n), Object.values(byLabel).reduce((s, n) => s + n, 0), "a resync creates no duplicates");

    // The read path: the guard plus a read transaction; a write is refused by the guard before it reaches the server.
    assert.ok("error" in gm.guardReadCypher("MATCH (n:AdvisorResource {account_id: 'x'}) DETACH DELETE n"));
  } finally {
    const { deleted } = await gm.wipeMirror(TEST_ACCOUNT);
    assert.ok(deleted > 0);
    const left = await gm.readQuery("MATCH (n) WHERE any(l IN labels(n) WHERE l STARTS WITH 'Advisor') AND n.account_id = $a RETURN count(n) AS n", { a: TEST_ACCOUNT }, { rowCap: 1 });
    assert.equal(Number(left.rows[0].n), 0, "every test node is gone");
    const concepts = await gm.readQuery("MATCH (c:Concept) RETURN count(c) AS n", {}, { rowCap: 1 });
    assert.ok(Number(concepts.rows[0].n) >= (concept ? 1 : 0), "Concept nodes untouched");
    await gm.closeGraph();
  }
});

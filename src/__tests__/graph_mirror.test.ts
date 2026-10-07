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
    "WITH 'set' AS word MATCH (n:KnArchetype {name: word}) RETURN n",
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
  assert.equal(gm.inventoryIdOf("arn:aws:s3:::bucket", ids), null, "no bucket in the inventory");
  assert.equal(gm.inventoryIdOf("arn:aws:s3:::bucket", new Set(["bucket"])), "bucket");
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

test("resource nodes carry the generic shape with the provider's word in native_type, for every inventory", () => {
  const roles = new Map([["i-1", { role: "web_or_api", role_confidence: 0.9, protected_prob: 0.1 }], ["prod-db", { role: "database", role_confidence: "0.8" as any, protected_prob: null }]]);
  const ec2 = gm.resourceFromEc2({ instance_id: "i-1", name: "web", instance_type: "m6i.large", state: "running", region: "us-east-1", az: "us-east-1a", monthly_usd: "70.08", cpu_30d: 12.5, cpu_days: 30, ssm_status: "Online", probe_at: "2026-09-19 01:00:00", gone: 0, first_seen: "2026-01-01 00:00:00", last_seen: "2026-09-19 00:00:00",
    snapshot: JSON.stringify({ tags: { "eks:nodegroup-name": "ng", "eks:cluster-name": "c" }, architecture: "arm64", network: { private_ip: "10.0.0.5", public_ip: "203.0.113.9", vpc_id: "vpc-1", subnet_id: "subnet-1", security_groups: [{ GroupId: "sg-1" }] } }) }, roles);
  assert.equal(ec2.id, "i-1"); assert.equal(ec2.label, "AdvisorCompute"); assert.equal(ec2.native_type, "ec2_instance");
  assert.equal(ec2.state, "running"); assert.equal(ec2.native_state, "running");
  assert.deepEqual([ec2.role, ec2.role_confidence, ec2.protected_prob, ec2.monthly_usd, ec2.gone], ["web_or_api", 0.9, 0.1, 70.08, false]);
  assert.equal(ec2.pool, "c/ng"); assert.equal(ec2.pool_kind, "node_group");
  assert.equal(ec2.props.type, "m6i.large"); assert.equal(ec2.props.arch, "arm64"); assert.equal(ec2.props.public_ip, "203.0.113.9"); assert.deepEqual(ec2.props.security_groups, ["sg-1"]); assert.equal(ec2.props.cpu_30d, 12.5);
  assert.deepEqual(ec2.observed.map((o) => [o.kind, o.status]), [["api", "ok"], ["metrics", "ok"], ["probe", "ok"]], "api, CloudWatch and the SSM probe cover it");
  // the pool kind the inventory recorded wins over the tag shape; an offline agent is an offline probe edge
  const asg = gm.resourceFromEc2({ instance_id: "i-2", name: "worker", instance_type: "c6g.large", state: "stopped", region: "us-east-1", pool: "web-asg", pool_kind: "asg", ssm_status: "ConnectionLost", gone: 0, snapshot: "{}" });
  assert.equal(asg.pool, "web-asg"); assert.equal(asg.pool_kind, "asg"); assert.equal(asg.state, "stopped");
  assert.deepEqual(asg.observed.map((o) => [o.kind, o.status, o.detail]), [["api", "ok", null], ["probe", "offline", "ConnectionLost"]]);
  const rds = gm.resourceFromRds({ db_instance_identifier: "prod-db", class: "db.r6g.large", engine: "postgres", engine_version: "15.4", status: "backing-up", region: "us-east-1", monthly_usd: null, cpu_30d: null, gone: 1, first_seen: "a", last_seen: "b", snapshot: JSON.stringify({ network: { endpoint: "prod-db.example.com", port: 5432, publicly_accessible: false }, storage_encrypted: true, backup_retention_period: 7 }) }, roles);
  assert.equal(rds.label, "AdvisorDatabase"); assert.equal(rds.native_type, "rds_instance"); assert.equal(rds.state, "pending"); assert.equal(rds.native_state, "backing-up");
  assert.deepEqual([rds.role, rds.role_confidence, rds.gone], ["database", 0.8, true]);
  assert.deepEqual([rds.props.engine, rds.props.engine_version, rds.props.endpoint_host, rds.props.port, rds.props.publicly_accessible, rds.props.encrypted, rds.props.backup_retention_days], ["postgres", "15.4", "prod-db.example.com", 5432, false, true, 7]);
  assert.deepEqual(rds.observed.map((o) => o.kind), ["api"], "no probe on a managed database");
  const cache = gm.resourceFromElasticache({ cache_cluster_id: "cache-1", node_type: "cache.t4g.small", engine: "redis", status: "available", region: "eu-west-1", num_nodes: 2, replication_group: "rg", monthly_usd: 24.8, gone: 0, first_seen: "a", last_seen: "b", snapshot: "{}" });
  assert.equal(cache.label, "AdvisorCache"); assert.equal(cache.role, null); assert.equal(cache.monthly_usd, 24.8); assert.equal(cache.props.nodes, 2); assert.equal(cache.props.group, "rg");
  const fn = gm.resourceFromLambda({ name: "hello", arn: null, region: "us-east-1", runtime: "nodejs20.x", memory_mb: 512, arm: 1, timeout_s: 30, invocations_30d: 1000, days: 30, monthly_usd: 0.2, gone: 0 }, "123456789012");
  assert.equal(fn.id, "arn:aws:lambda:us-east-1:123456789012:function:hello"); assert.equal(fn.label, "AdvisorFunction"); assert.equal(fn.props.runtime_version, "20"); assert.equal(fn.props.arch, "arm64"); assert.equal(fn.state, "available");
  const bucket = gm.resourceFromS3({ name: "my-bucket", region: "us-east-1", total_gb: 12.5, objects: 100, public: 1, versioning: 0, lifecycle_rules: 2, metric_day: "2026-09-18", gone: 0 });
  assert.equal(bucket.id, "my-bucket"); assert.equal(bucket.label, "AdvisorStorage"); assert.equal(bucket.native_type, "s3_bucket"); assert.equal(bucket.props.kind, "object"); assert.equal(bucket.props.public, true); assert.equal(bucket.props.versioning, false);
  const vol = gm.resourceFromEbs({ volume_id: "vol-1", region: "us-east-1", volume_type: "gp3", size_gb: 100, iops: 3000, state: "in-use", encrypted: 1, instance_id: "i-1", device: "/dev/xvda", read_iops_avg: 10, write_iops_avg: 5, metric_days: 14, gone: 0 });
  assert.equal(vol.label, "AdvisorStorage"); assert.equal(vol.native_type, "ebs_volume"); assert.equal(vol.props.kind, "block"); assert.equal(vol.props.class, "gp3"); assert.equal(vol.props.attached_to, "i-1"); assert.equal(vol.props.iops_30d, 15); assert.equal(vol.state, "available");
  const zone = gm.resourceFromZone({ zone_id: "Z1", name: "example.com.", private: 0, records: 12, gone: 0 });
  assert.equal(zone.label, "AdvisorDnsZone"); assert.equal(zone.props.records, 12);
  const rec = gm.resourceFromDnsRecord({ id: "Z1:api.example.com.:A", zone_id: "Z1", name: "API.example.com.", type: "A", ttl: 300, alias: 0, values: JSON.stringify(["203.0.113.9"]), link_state: "unmatched", gone: 0 });
  assert.equal(rec.label, "AdvisorDnsRecord"); assert.equal(rec.props.fqdn, "api.example.com"); assert.deepEqual(rec.props.values, ["203.0.113.9"]); assert.equal(rec.props.link_state, "dangling");
  for (const n of [ec2, rds, cache, fn, bucket, vol, zone, rec]) assert.deepEqual(Object.keys(n).sort(), Object.keys(ec2).sort(), `${n.label} has the shared shape`);
});

test("genericState maps every provider word onto the closed list", () => {
  assert.equal(gm.genericState("ec2_instance", "shutting-down"), "terminated");
  assert.equal(gm.genericState("ec2_instance", "stopping"), "stopped");
  assert.equal(gm.genericState("rds_instance", "storage-full"), "degraded");
  assert.equal(gm.genericState("elb_alb", "active"), "available");
  assert.equal(gm.genericState("elb_alb", "provisioning"), "pending");
  assert.equal(gm.genericState("elasticache_cluster", "deleting"), "terminated");
  assert.equal(gm.genericState("rds_instance", "something-new"), "unknown");
  assert.equal(gm.genericState("rds_instance", null), "unknown");
});

test("guessedType reads the id shape; actionVerb maps provider actions onto the generic verbs; controlFacts reads the id", () => {
  assert.equal(gm.guessedType("arn:aws:s3:::bucket"), "bucket");
  assert.equal(gm.guessedType("arn:aws:lambda:us-east-1:1:function:fn"), "function");
  assert.equal(gm.guessedType("arn:aws:ec2:us-east-1:1:snapshot/snap-1"), "snapshot");
  assert.equal(gm.guessedType("vpc-1"), "vpc");
  assert.equal(gm.guessedType("snap-1"), "snapshot");
  assert.equal(gm.guessedType("whisper-engine"), null);
  assert.equal(gm.actionVerb("stop_instance"), "stop");
  assert.equal(gm.actionVerb("migrate_graviton"), "migrate_arch");
  assert.equal(gm.actionVerb("aurora_set_storage_iopt"), "change_storage_tier");
  assert.equal(gm.actionVerb("security_fix"), "security_fix");
  assert.equal(gm.actionVerb("delete_old_amis"), "delete");
  assert.equal(gm.actionVerb("never_seen"), "other");
  assert.deepEqual(gm.controlFacts("aws_thrifty.control.ec2_instance_with_graviton"), { framework: "cost", category: "cost" });
  assert.deepEqual(gm.controlFacts("aws_compliance.control.cis_v300_2_1_1", "cis_v300"), { framework: "cis", category: "security" });
  assert.deepEqual(gm.controlFacts("aws_compliance.control.foundational_security_ec2_1", "foundational_security"), { framework: "foundational_security", category: "security" });
  assert.deepEqual(gm.controlFacts("query.sg_dormant_ipv6"), { framework: "advisor", category: "security" });
  assert.deepEqual(gm.controlFacts("query.idle_instance"), { framework: "advisor", category: "cost" });
  assert.equal(gm.healthOf("ok", "ok", "not-applicable"), "ok");
  assert.equal(gm.healthOf("ok", "impaired", "ok"), "impaired");
  assert.equal(gm.healthOf("initializing", "ok", "ok"), "initializing");
  assert.equal(gm.healthOf(null, null, null), "unknown");
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
  assert.equal(n.action, "stop"); assert.equal(n.native_action, "stop_instance");
  // an incident fix: run 0 (no run), evidence carries the incident, the VPC is not in the inventory -> a ResourceRef
  const fix = gm.recommendationNode({ ...row, id: 8, fingerprint: "incident:enable_flow_logs:vpc-1", rule: "incident:enable_flow_logs", action_type: "enable_flow_logs", run_id: 0, resource: "vpc-1", evidence: JSON.stringify({ incident_id: 3, alert_id: 23 }) }, inv, concepts);
  assert.equal(fix.resource_id, null);
  assert.equal(fix.resource, "vpc-1");
  assert.equal(fix.run_id, null);
  assert.equal(fix.incident_id, 3);
  assert.equal(fix.concept_id, null);
  assert.equal(fix.guessed_type, "vpc"); assert.equal(fix.action, "enable_logging");
});

test("alert, incident and run nodes; flag edges only for inventory resources, one per control and resource", () => {
  const inv = new Set(["i-1", "i-2"]);
  const a = gm.alertNode({ id: 1, kind: "nat_traffic", resource: "nat-1", message: "x".repeat(600), created_at: "2026-09-19 00:00:00", acknowledged: 1, acknowledged_by: "jev" }, inv, "alarm");
  assert.equal(a.message.length, 500);
  assert.equal(a.acknowledged, true);
  assert.equal(a.resource_id, null);
  assert.equal(gm.alertNode({ id: 2, kind: "instance_state", resource: "i-2", message: "m", created_at: "t", acknowledged: 0 }, inv, "warning").resource_id, "i-2");
  const caused = gm.alertNode({ id: 3, kind: "instance_state", resource: "i-2", message: "m", created_at: "t", acknowledged: 0, cause: JSON.stringify({ status: "found", summary: "retired by AWS", actor: "aws", actor_kind: "aws", via: "scheduled event", event_name: null, event_time: "t2" }) }, inv, "info");
  assert.equal(caused.cause_actor_kind, "provider", "the provider's own hand is 'provider', not the provider's name");
  assert.equal(caused.cause, "retired by AWS");
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
    assert.equal(byLabel.AdvisorCompute, 3);
    assert.equal(byLabel.AdvisorDatabase, 1);
    assert.equal(byLabel.AdvisorCache, 1);
    assert.equal(byLabel.AdvisorNodePool, 1);
    assert.equal(byLabel.AdvisorTelemetry, Object.keys(gm.TELEMETRY).length);
    const archetypes = await gm.readQuery("MATCH (r:AdvisorResource {account_id: $a})-[:HAS_ROLE]->(k:KnArchetype) RETURN count(DISTINCT k) AS n", { a: TEST_ACCOUNT }, { rowCap: 1 });
    assert.equal(Number(archetypes.rows[0].n), 2, "roles are KnArchetype nodes");
    const observed = await gm.readQuery("MATCH (r:AdvisorResource {id: 'i-test1'})-[o:OBSERVED_BY]->(t:AdvisorTelemetry) RETURN t.kind AS kind, o.status AS status ORDER BY kind", {}, { rowCap: 10 });
    assert.deepEqual(observed.rows.map((x) => [x.kind, x.status]), [["api", "ok"], ["metrics", "ok"], ["probe", "ok"]]);
    for (const [l, n] of Object.entries(byLabel)) assert.ok((stats.nodes[l] || 0) >= n, `${l} in graphStats`);

    const view = await gm.resourceView("i-test2");
    assert.ok(view);
    assert.equal(view.role, "blockchain_node");
    assert.deepEqual(view.labels, ["AdvisorCompute"]);
    assert.ok(view.observed.some((o) => o.kind === "api"));
    assert.equal(view.counts.recommendations, 1);
    assert.equal(view.counts.controls, 1);
    assert.equal(view.recommendations[0].concept?.id ?? null, concept ?? null, "DECIDED_AS only to a Concept that exists");
    const web = await gm.resourceView("i-test1");
    assert.equal(web?.pool, "prod/workspace");
    assert.equal(web?.counts.alerts, 1);
    assert.equal(web?.recommendations[0].concept, null, "a concept id the graph does not know draws no edge");
    const notGone = await gm.readQuery("MATCH (r:AdvisorResource {id: 'i-test3'}) RETURN r.gone AS gone", {}, { rowCap: 1 });
    assert.equal(notGone.rows[0].gone, false);
    const fix = await gm.readQuery("MATCH (rec:AdvisorRecommendation {id: 3})-[:FROM_INCIDENT]->(i:AdvisorIncident)-[:INVESTIGATES]->(a:AdvisorAlert)-[:ABOUT]->(x) RETURN i.id AS incident, a.id AS alert, labels(x) AS about, x.guessed_type AS guessed", {}, { rowCap: 1 });
    assert.deepEqual(fix.rows[0], { incident: 1, alert: 1, about: ["AdvisorResourceRef"], guessed: "nat_gateway" });

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

test("action nodes resolve their target and the recommendations they carry out", async () => {
  const { actionNode } = await import("../graph_mirror.js");
  const inv = new Set(["i-1", "hub"]);
  const a = actionNode({ id: 3, kind: "aurora_storage", status: "verified", mode: "apply", trigger: "schedule", title: "t", reason: "r", rollback: "back", est_usd_month: 351, result: "ok", error: null,
    resource: "hub", resource_name: "hub", region: "us-east-1", created_at: "2026-09-26 10:00:00", seen_at: "2026-09-26 11:00:00", applied_at: "2026-09-26 11:00:00", verified_at: "2026-09-26 11:01:00", reverted_at: null,
    facts_json: JSON.stringify({ recommendation_id: 77, recommendation_ids: [77, 63, 59], engine: "aurora-postgresql" }) }, inv);
  assert.equal(a.resource_id, "hub");
  assert.deepEqual(a.recommendation_ids, [77, 63, 59]);
  assert.equal(a.est_usd_month, 351);
  const b = actionNode({ id: 4, kind: "ecr_lifecycle", status: "proposed", mode: "dry_run", trigger: "manual", title: "t", reason: "r", resource: "whisper-engine", region: "us-east-1", created_at: "2026-09-26 10:00:00", facts_json: "{}" }, inv);
  assert.equal(b.resource_id, null);
  assert.deepEqual(b.recommendation_ids, []);
  assert.equal(b.rollback, null);
});

test("accountRows: a management account, its members PART_OF it, and a standalone team, with name, access and actuator", async () => {
  const gm = await import("../graph_mirror.js");
  const rows = gm.accountRows([
    { provider: "aws", id: "210987654321", native_type: "account", name: "parent", parent_id: null, access: "access key AKIA…TEST", actuator: true, enabled: true, last_test: { ok: true, detail: "connected", at: "2026-10-04T00:00:00Z" } },
    { provider: "aws", id: "210987654322", native_type: "account", name: "staging", parent_id: "210987654321", access: "role advisor-read from the parent", actuator: false, enabled: true, last_test: null },
    { provider: "vercel", id: "team_example123", native_type: "team", name: "Example", parent_id: null, access: "token vcp_…", actuator: false, enabled: true, last_test: null },
  ]);
  assert.deepEqual(rows.map((r) => [r.id, r.role, r.parent_id, r.kind, r.native_type]), [["210987654321", "management", null, "account", "account"], ["210987654322", "member", "210987654321", "account", "account"], ["team_example123", "standalone", null, "account", "team"]]);
  assert.equal(rows[0].last_test_ok, true); assert.equal(rows[1].last_test_ok, null); assert.equal(rows[0].actuator, true); assert.equal(rows[2].name, "Example");
});

test("accountId: the credentials' account first, the latest run's only when none is saved (runs are history after a re-point)", () => {
  db.prepare("insert or ignore into runs(id, status, trigger, account_id) values (1, 'completed', 'manual', ?)").run(TEST_ACCOUNT);
  db.prepare("insert or replace into settings(key, value) values ('aws_credentials_meta', ?)").run(JSON.stringify({ accountId: "TEST-111111111111" }));
  assert.equal(gm.accountId(), "TEST-111111111111");
  db.prepare("delete from settings where key = 'aws_credentials_meta'").run();
  assert.equal(gm.accountId(), TEST_ACCOUNT);
});

test("withRefIds: every node MERGE gets a ref_id on create, path merges and other clauses are left alone", () => {
  const out = gm.withRefIds(`UNWIND $rows AS row
MERGE (r:AdvisorResource {id: row.id}) ON CREATE SET r.first_seen = $now SET r.name = row.name
FOREACH (_ IN CASE WHEN row.vpc IS NULL THEN [] ELSE [1] END | MERGE (n:AdvisorNetwork {id: coalesce(row.vpc, '')}) MERGE (r)-[:IN]->(n))
MERGE (a:AdvisorAccount {id: row.account})-[:OWNS]->(r)
MATCH (x:AdvisorRun {id: $run}) MERGE (x)-[:SAW]->(r)`);
  assert.match(out, /MERGE \(r:AdvisorResource \{id: row\.id\}\) ON CREATE SET r\.ref_id = randomUUID\(\), r:Data_Bank:Domain_cloud ON CREATE SET r\.first_seen = \$now/);
  assert.match(out, /MERGE \(n:AdvisorNetwork \{id: coalesce\(row\.vpc, ''\)\}\) ON CREATE SET n\.ref_id = randomUUID\(\), n:Data_Bank:Domain_cloud MERGE \(r\)-\[:IN\]->\(n\)/);
  assert.equal((out.match(/ref_id/g) || []).length, 2, "a path merge and a MATCH are not rewritten");
  assert.equal(gm.withRefIds("MATCH (n:AdvisorResource) SET n.x = 1"), "MATCH (n:AdvisorResource) SET n.x = 1");
  // Jarvis's own Schema nodes get the ref_id but stay out of Data_Bank
  assert.equal(gm.withRefIds("MERGE (s:Schema {type: $t})"), "MERGE (s:Schema {type: $t}) ON CREATE SET s.ref_id = randomUUID()");
});

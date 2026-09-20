import { test } from "node:test";
import assert from "node:assert";
import { attributionContext, lambdaSystems, systemsFromInventory } from "../graph_knowledge.js";
import { attributeLogGroup } from "../log_attribution.js";

const ec2 = [
  { instance_id: "i-a1", name: "web-1", instance_type: "m6i.4xlarge", state: "running", region: "us-east-1", gone: 0, pool_kind: "asg", pool: "web-asg", ebs_gb: 100 },
  { instance_id: "i-a2", name: "web-2", instance_type: "m6i.4xlarge", state: "running", region: "us-east-1", gone: 0, pool_kind: "asg", pool: "web-asg", ebs_gb: 100 },
  { instance_id: "i-b1", name: "bitcoind", instance_type: "m5.large", state: "running", region: "us-east-1", gone: 0, pool_kind: null, pool: null, ebs_gb: 1000 },
  { instance_id: "i-s1", name: "old", instance_type: "t3.large", state: "stopped", region: "us-east-1", gone: 0, pool_kind: null, pool: null, ebs_gb: 30 },
];
const rds = [
  { db_instance_identifier: "prod-1", cluster: "prod", class: "db.r7g.xlarge", region: "us-east-1", gone: 0 },
  { db_instance_identifier: "prod-2", cluster: "prod", class: "db.r7g.xlarge", region: "us-east-1", gone: 0 },
  { db_instance_identifier: "senza", cluster: null, class: "db.r7g.large", region: "us-east-1", gone: 0 },
];
const cache = [{ cache_cluster_id: "sidekiq-001", replication_group: "sidekiq", node_type: "cache.m7g.large", region: "us-east-1", gone: 0 }, { cache_cluster_id: "sidekiq-002", replication_group: "sidekiq", node_type: "cache.m7g.large", region: "us-east-1", gone: 0 }];

test("systems: pools, clusters and groups collapse into one system each; standalone boxes stand alone; stopped instances are not members", () => {
  const systems = systemsFromInventory(ec2, rds, cache, new Map([["i-b1", "blockchain_node"]]), [{ id: "nat-1", region: "us-east-1" }]);
  const byId = Object.fromEntries(systems.map((s) => [s.id, s]));
  assert.deepEqual(Object.keys(byId).sort(), ["cache:sidekiq", "ec2:i-b1", "nat:nat-1", "pool:web-asg", "rds:prod", "rds:senza"]);
  assert.equal(byId["pool:web-asg"].members.length, 2);
  assert.equal(byId["pool:web-asg"].types[0].count, 2);
  assert.equal(byId["pool:web-asg"].archetype, "web_or_api");
  assert.equal(byId["pool:web-asg"].ebs_gb, 200);
  assert.equal(byId["ec2:i-b1"].archetype, "blockchain_node");
  assert.equal(byId["rds:prod"].members.length, 2);
  assert.equal(byId["cache:sidekiq"].types[0].sku, "cache.m7g.large");
  assert.equal(byId["nat:nat-1"].kind, "nat");
});

test("attribution context: cluster and beanstalk maps come from the members' tags, lambdas from findings", () => {
  const withTags = ec2.map((r) => ({ ...r, snapshot: JSON.stringify({ tags: r.pool === "web-asg" ? { "aws:eks:cluster-name": "prod-cluster", "elasticbeanstalk:environment-name": "web-env" } : {} }) }));
  const systems = [...systemsFromInventory(withTags, rds, cache, new Map()), ...lambdaSystems(["arn:aws:lambda:us-east-1:1:function:fn-a"])];
  const cluster = systems.find((s) => s.id === "eks:prod-cluster");
  assert.ok(cluster && cluster.members.length === 2, "cluster system with the pool's members");
  assert.equal(systems.find((s) => s.id === "pool:web-asg")!.parent, "eks:prod-cluster");
  const ctx = attributionContext(systems, withTags);
  assert.equal(attributeLogGroup("/aws/eks/prod-cluster/cluster", ctx).owner, "eks:prod-cluster");
  assert.equal(attributeLogGroup("/aws/elasticbeanstalk/web-env/nginx", ctx).owner, "pool:web-asg");
  assert.equal(attributeLogGroup("/aws/lambda/fn-a", ctx).owner, "lambda:fn-a");
  assert.equal(attributeLogGroup("/aws/rds/cluster/prod/error", ctx).owner, "rds:prod");
});

test("lambda cost from 30 days of metrics: GB-seconds at the architecture rate plus requests, scaled to a month", async () => {
  const { lambdaMonthlyCost } = await import("../lambda_inventory.js");
  // 1 GB function running 1,000 s a day for 30 days, one million invocations
  const c = lambdaMonthlyCost({ name: "f", region: "us-east-1", memory_mb: 1024, arm: false, invocations_30d: 1e6, duration_ms_30d: 30 * 1000 * 1000, days: 30 });
  assert.equal(c.gb_seconds_month, 30000);
  assert.equal(c.invocations_month, 1e6);
  assert.equal(c.usd_month, Math.round((30000 * 0.0000166667 + 0.2) * 100) / 100);
  assert.ok(lambdaMonthlyCost({ name: "f", region: "us-east-1", memory_mb: 1024, arm: true, invocations_30d: 0, duration_ms_30d: 30 * 1000 * 1000, days: 15 }).gb_seconds_month === 60000, "half the days seen: scaled up to a month");
});

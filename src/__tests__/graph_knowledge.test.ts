import { test } from "node:test";
import assert from "node:assert";
import { logGroupOwner, systemsFromInventory } from "../graph_knowledge.js";

const ec2 = [
  { instance_id: "i-a1", name: "web-1", instance_type: "m6i.4xlarge", state: "running", region: "us-east-1", gone: 0, pool_kind: "asg", pool: "web-asg", ebs_gb: 100 },
  { instance_id: "i-a2", name: "web-2", instance_type: "m6i.4xlarge", state: "running", region: "us-east-1", gone: 0, pool_kind: "asg", pool: "web-asg", ebs_gb: 100 },
  { instance_id: "i-b1", name: "bitcoind", instance_type: "m5.large", state: "running", region: "us-east-1", gone: 0, pool_kind: null, pool: null, ebs_gb: 1000 },
  { instance_id: "i-s1", name: "old", instance_type: "t3.large", state: "stopped", region: "us-east-1", gone: 0, pool_kind: null, pool: null, ebs_gb: 30 },
];
const rds = [
  { db_instance_identifier: "prod-1", cluster: "prod", class: "db.r7g.xlarge", region: "us-east-1", gone: 0 },
  { db_instance_identifier: "prod-2", cluster: "prod", class: "db.r7g.xlarge", region: "us-east-1", gone: 0 },
  { db_instance_identifier: "orion", cluster: null, class: "db.r7g.large", region: "us-east-1", gone: 0 },
];
const cache = [{ cache_cluster_id: "sidekiq-001", replication_group: "sidekiq", node_type: "cache.m7g.large", region: "us-east-1", gone: 0 }, { cache_cluster_id: "sidekiq-002", replication_group: "sidekiq", node_type: "cache.m7g.large", region: "us-east-1", gone: 0 }];

test("systems: pools, clusters and groups collapse into one system each; standalone boxes stand alone; stopped instances are not members", () => {
  const systems = systemsFromInventory(ec2, rds, cache, new Map([["i-b1", "blockchain_node"]]), [{ id: "nat-1", region: "us-east-1" }]);
  const byId = Object.fromEntries(systems.map((s) => [s.id, s]));
  assert.deepEqual(Object.keys(byId).sort(), ["cache:sidekiq", "ec2:i-b1", "nat:nat-1", "pool:web-asg", "rds:prod", "rds:orion"]);
  assert.equal(byId["pool:web-asg"].members.length, 2);
  assert.equal(byId["pool:web-asg"].types[0].count, 2);
  assert.equal(byId["pool:web-asg"].archetype, "web_or_api");
  assert.equal(byId["pool:web-asg"].ebs_gb, 200);
  assert.equal(byId["ec2:i-b1"].archetype, "blockchain_node");
  assert.equal(byId["rds:prod"].members.length, 2);
  assert.equal(byId["cache:sidekiq"].types[0].sku, "cache.m7g.large");
  assert.equal(byId["nat:nat-1"].kind, "nat");
});

test("log group owner: the longest system name, pool or member id inside the group name wins", () => {
  const systems = systemsFromInventory(ec2, rds, cache, new Map());
  assert.equal(logGroupOwner("/aws/rds/cluster/prod/postgresql", systems), "rds:prod");
  assert.equal(logGroupOwner("/web-asg/app", systems), "pool:web-asg");
  assert.equal(logGroupOwner("/aws/lambda/something-else", systems), null);
  assert.equal(logGroupOwner("/hosts/i-b1/syslog", systems), "ec2:i-b1");
});

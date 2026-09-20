import assert from "node:assert/strict";
import { test } from "node:test";
import { parseSort } from "../inventory.js";
import { chooseHourly, ec2OperatingSystem, elasticachePricingEngine, priceFilters, rdsPricingEngine } from "../prices.js";

test("parseSort only lets whitelisted columns reach the SQL", () => {
  const allowed = ["name", "monthly_usd"];
  assert.deepEqual(parseSort("-monthly_usd", allowed, "name"), { column: "monthly_usd", dir: "desc" });
  assert.deepEqual(parseSort("name", allowed, "name"), { column: "name", dir: "asc" });
  assert.deepEqual(parseSort("snapshot; drop table x", allowed, "name"), { column: "name", dir: "asc" });
  assert.deepEqual(parseSort(undefined, allowed, "name"), { column: "name", dir: "asc" });
});

test("resource attributes map to price-list names", () => {
  assert.equal(ec2OperatingSystem("", "Linux/UNIX"), "Linux");
  assert.equal(ec2OperatingSystem("windows", "Windows"), "Windows");
  assert.equal(ec2OperatingSystem("", "Red Hat Enterprise Linux"), "RHEL");
  assert.equal(rdsPricingEngine("postgres"), "PostgreSQL");
  assert.equal(rdsPricingEngine("aurora-postgresql"), "Aurora PostgreSQL");
  assert.equal(rdsPricingEngine("something-new"), null);
  assert.equal(elasticachePricingEngine("valkey"), "Valkey");
  assert.equal(elasticachePricingEngine("redis"), "Redis");
});

test("priceFilters builds the same filters the MCP tool used", () => {
  assert.deepEqual(priceFilters({ kind: "ec2", instance_type: "m6i.xlarge", region: "us-east-1" }),
    { service: "AmazonEC2", filters: { regionCode: "us-east-1", instanceType: "m6i.xlarge", operatingSystem: "Linux", tenancy: "Shared", preInstalledSw: "NA", capacitystatus: "Used" } });
  assert.deepEqual(priceFilters({ kind: "rds", instance_type: "db.t4g.medium", region: "us-east-1", engine: "PostgreSQL", deployment: "Multi-AZ" }),
    { service: "AmazonRDS", filters: { regionCode: "us-east-1", instanceType: "db.t4g.medium", deploymentOption: "Multi-AZ", databaseEngine: "PostgreSQL" } });
  assert.deepEqual(priceFilters({ kind: "elasticache", instance_type: "cache.t4g.small", region: "us-east-1", engine: "Valkey" }),
    { service: "AmazonElastiCache", filters: { regionCode: "us-east-1", instanceType: "cache.t4g.small", cacheEngine: "Valkey" } });
});

test("chooseHourly picks the Aurora rate that matches the storage tier", () => {
  const row = (hourly: number, usagetype: string) => ({ hourly_usd: hourly, monthly_usd: hourly * 730, unit: "Hrs", currency: "USD", description: "", attributes: { usagetype } });
  const rows = [row(0.553, "InstanceUsage:db.r7g.xl"), row(0.719, "InstanceUsageIOOptimized:db.r7g.xl")];
  const spec = { kind: "rds" as const, instance_type: "db.r7g.xlarge", region: "us-east-1", engine: "Aurora PostgreSQL" };
  assert.equal(chooseHourly(rows, { kind: "rds", sku: "db.r7g.xlarge", region: "us-east-1", engine: "Aurora PostgreSQL", spec }), 0.553);
  assert.equal(chooseHourly(rows, { kind: "rds", sku: "db.r7g.xlarge", region: "us-east-1", engine: "Aurora PostgreSQL IO-Optimized", ioOptimized: true, spec }), 0.719);
  assert.equal(chooseHourly([row(0.192, "BoxUsage:m6i.xlarge")], { kind: "ec2", sku: "m6i.xlarge", region: "us-east-1", engine: "Linux", spec: { kind: "ec2", instance_type: "m6i.xlarge", region: "us-east-1" } }), 0.192);
  assert.equal(chooseHourly([], { kind: "ec2", sku: "x", region: "us-east-1", engine: "Linux", spec: { kind: "ec2", instance_type: "x", region: "us-east-1" } }), null);
  // ElastiCache lists add-ons under the same filters; the node price is the plain NodeUsage row, even when it is not the cheapest.
  const cache = [row(0.0228, "USE1-SyncDurability-NodeUsage:cache.m7g.large"), row(0.1264, "NodeUsage:cache.m7g.large")];
  assert.equal(chooseHourly(cache, { kind: "elasticache", sku: "cache.m7g.large", region: "us-east-1", engine: "Valkey", spec: { kind: "elasticache", instance_type: "cache.m7g.large", region: "us-east-1", engine: "Valkey" } }), 0.1264);
});

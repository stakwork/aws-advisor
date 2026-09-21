import { test } from "node:test";
import assert from "node:assert";
import { categoryOf, computeForecast } from "../forecast_math.js";
import type { PricedLine } from "../reconcile.js";

const line = (service: string, usage_type: string, net: number, od = net): PricedLine => ({ service, usage_type, quantity: 1, unit: null, unblended: net, net, amortized: net, region: "us-east-1", rule: null, unit_price: null, modelled: null, actual_od: od, residual: null, covered: null, modelled_uncovered: null });

test("categoryOf sorts usage lines into the inventory legs", () => {
  assert.equal(categoryOf({ service: "Amazon Elastic Compute Cloud - Compute", usage_type: "BoxUsage:m6i.4xlarge", rule: "ec2_hours" }), "ec2_compute");
  assert.equal(categoryOf({ service: "EC2 - Other", usage_type: "EBS:VolumeUsage.gp3", rule: "ebs_gp3" }), "ebs");
  assert.equal(categoryOf({ service: "EC2 - Other", usage_type: "USW2-EBS:VolumeP-IOPS.gp3", rule: null }), "ebs");
  assert.equal(categoryOf({ service: "Amazon Simple Storage Service", usage_type: "TimedStorage-ByteHrs", rule: null }), "s3_storage");
  assert.equal(categoryOf({ service: "Amazon Relational Database Service", usage_type: "InstanceUsage:db.r7g.large", rule: null }), "rds_instances");
  assert.equal(categoryOf({ service: "Amazon ElastiCache", usage_type: "NodeUsage:cache.m7g.large", rule: null }), "cache_nodes");
  assert.equal(categoryOf({ service: "AWS Lambda", usage_type: "Lambda-GB-Second", rule: null }), "lambda");
  assert.equal(categoryOf({ service: "EC2 - Other", usage_type: "NatGateway-Bytes", rule: null }), null);
  assert.equal(categoryOf({ service: "Amazon Elastic Compute Cloud - Compute", usage_type: "SpotUsage:c6i.large", rule: null }), null);
});

test("computeForecast: month to date plus inventory, run rate and fixed legs", () => {
  // 10 of 30 days elapsed; the fleet costs 10 USD/h on demand, the Savings Plan (7.3 USD/h at 27 % off) covers 10 USD/h of it
  const lines = [
    line("Amazon Elastic Compute Cloud - Compute", "BoxUsage:m6i.large", 0, 2400),
    line("EC2 - Other", "EBS:VolumeUsage.gp3", 100),
    line("EC2 - Other", "NatGateway-Bytes", 50),
    line("Amazon Relational Database Service", "InstanceUsage:db.r7g.large", 120, 240),
    line("AmazonCloudWatch", "DataProcessing-Bytes", 200),
  ];
  const f = computeForecast({
    month: "2026-09", elapsed_days: 10, days_in_month: 30, lines,
    records: { usage_net: 470, sp_fee: 1752, sp_covered_od: 2400, ri_amortized: 100, support: 200, tax: 10, other: 0, net_total: 2532 },
    sp_hourly: 7.3, sp_discount_rate: 0.27,
    now: { ec2_od_hourly: 10, ec2_running: 5, rds_od_hourly: 1, cache_od_hourly: 0, rds_reserved_hourly: 0.5, cache_reserved_hourly: null, ebs_month: 300, s3_month: 0, lambda_month: 0 },
    last_month: { total: 8000, services: { "EC2 - Other": 500, AmazonCloudWatch: 300, "Savings Plans for AWS Compute usage": 5431, "AWS Support": 600 } },
  }, new Date("2026-09-11T00:00:00Z"));
  assert.equal(f.remaining_days, 20);
  const cat = (k: string) => f.categories.find((c) => c.key === k)!;
  assert.equal(cat("ec2_compute").per_day, 0, "the plan covers the whole fleet");
  assert.equal(cat("ebs").per_day, 10, "300 a month over 30 days");
  assert.equal(cat("rds_instances").per_day, 12, "1 USD/h on demand minus 0.5 reserved, times 24");
  assert.equal(cat("usage").per_day, 25, "(50 + 200) over 10 days");
  assert.equal(cat("sp_fee").remaining, 7.3 * 24 * 20);
  assert.equal(cat("reservations").remaining, 200);
  assert.ok(cat("support").remaining > 0);
  assert.ok(f.forecast_net > f.mtd_net && f.forecast_net === f.mtd_net + f.remaining_net);
  const sp = f.services.find((s) => s.service.startsWith("Savings Plans"))!;
  assert.equal(sp.basis, "fixed"); assert.equal(sp.last_month, 5431);
  const other = f.services.find((s) => s.service === "EC2 - Other")!;
  assert.equal(other.basis, "mixed"); assert.equal(other.forecast, 150 + 200 + 100);
  assert.ok(f.movers.some((m) => m.service === "AmazonCloudWatch"), "CloudWatch grew");
  assert.equal(f.basis_share.inventory_pct + f.basis_share.run_rate_pct + f.basis_share.fixed_pct > 99, true);
  assert.equal(f.delta_pct, Math.round(((f.forecast_net - 8000) / 8000) * 10000) / 100);
});

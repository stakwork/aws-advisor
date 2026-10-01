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
    sp_hourly: 7.3, sp_discount_rate: 0.27, support_plan: "business",
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

test("computeForecast: a cancelled support plan adds nothing after what was posted", () => {
  const base = {
    month: "2026-09", elapsed_days: 10, days_in_month: 30, lines: [line("AmazonCloudWatch", "DataProcessing-Bytes", 2000)],
    records: { usage_net: 2000, sp_fee: 0, sp_covered_od: 0, ri_amortized: 0, support: 426, tax: 0, other: 0, net_total: 2426 },
    sp_hourly: null, sp_discount_rate: 0, now: { ec2_od_hourly: 0, ec2_running: 0, rds_od_hourly: 0, cache_od_hourly: 0, rds_reserved_hourly: null, cache_reserved_hourly: null, ebs_month: 0, s3_month: 0, lambda_month: 0 }, last_month: null,
  };
  const basic = computeForecast({ ...base, support_plan: "basic" });
  assert.equal(basic.categories.find((c) => c.key === "support")!.remaining, 0);
  assert.equal(basic.support_forecast, 426);
  const business = computeForecast({ ...base, support_plan: "business" });
  assert.ok(business.categories.find((c) => c.key === "support")!.remaining > 0);
  const unknown = computeForecast({ ...base, support_plan: "unknown" });
  assert.equal(unknown.support_forecast, 426);
});

test("support plan from severity codes and the charge per plan", async () => {
  const { planFromSeverityCodes } = await import("../support_plan.js");
  const { supportCharge } = await import("../pricebook.js");
  assert.equal(planFromSeverityCodes(["low", "normal"]), "developer");
  assert.equal(planFromSeverityCodes(["low", "normal", "high", "urgent"]), "business");
  assert.equal(planFromSeverityCodes(["low", "normal", "high", "urgent", "critical"]), "enterprise");
  assert.equal(supportCharge("basic", 20_000), 0);
  assert.equal(supportCharge("developer", 500), 29);
  assert.equal(supportCharge("business", 20_000), 1000 + 700);
  assert.equal(supportCharge("enterprise", 20_000), 15_000);
  assert.equal(supportCharge("unknown", 20_000), null);
});

test("computeForecast: on the 1st, with nothing billed yet, the newest reconciled month stands in", () => {
  const prior = {
    month: "2026-08", days: 31, ri_amortized: 310, tax: 62,
    lines: [
      line("Amazon Relational Database Service", "InstanceUsage:db.r7g.large", 300, 1000),
      line("EC2 - Other", "NatGateway-Bytes", 620),
      line("AmazonCloudWatch", "DataProcessing-Bytes", 310),
    ],
  };
  const f = computeForecast({
    month: "2026-10", elapsed_days: 0, days_in_month: 31, lines: [],
    records: { usage_net: 0, sp_fee: 0, sp_covered_od: 0, ri_amortized: 0, support: 0, tax: 0, other: 0, net_total: 0 },
    sp_hourly: 7.3, sp_discount_rate: 0.27, support_plan: "basic",
    now: { ec2_od_hourly: 10, ec2_running: 5, rds_od_hourly: 1, cache_od_hourly: 0, rds_reserved_hourly: null, cache_reserved_hourly: null, ebs_month: 0, s3_month: 0, lambda_month: 0 },
    last_month: null, prior,
  }, new Date("2026-10-01T08:00:00Z"));
  const cat = (k: string) => f.categories.find((c) => c.key === k)!;
  assert.equal(f.elapsed_days, 0); assert.equal(f.remaining_days, 31, "the whole month is still ahead");
  assert.equal(cat("ec2_compute").per_day, 0, "the plan still covers the fleet");
  assert.equal(cat("rds_instances").per_day, 7.2, "1 USD/h at August's 30 % billed share, times 24");
  assert.equal(cat("usage").per_day, 30, "(620 + 310) over August's 31 days");
  assert.equal(cat("reservations").per_day, 10);
  assert.equal(cat("tax").per_day, 2);
  assert.equal(f.locked_in, Math.round((7.3 * 24 * 31 + 10 * 31) * 100) / 100);
  assert.ok(f.categories.every((c) => Number.isFinite(c.mtd_per_day)));
});

test("computeForecast: on the 1st the services table carries each leg, split by the reconciled month's lines", () => {
  const prior = { month: "2026-09", days: 30, ri_amortized: 0, tax: 0, lines: [
    line("EC2 - Other", "NatGateway-Bytes", 600), line("AmazonCloudWatch", "DataProcessing-Bytes", 300),
    line("Amazon Relational Database Service", "InstanceUsage:db.r7g.large", 300, 1000),
  ] };
  const f = computeForecast({
    month: "2026-10", elapsed_days: 0, days_in_month: 31, lines: [],
    records: { usage_net: 0, sp_fee: 0, sp_covered_od: 0, ri_amortized: 0, support: 0, tax: 0, other: 0, net_total: 0 },
    sp_hourly: null, sp_discount_rate: 0, support_plan: "basic",
    now: { ec2_od_hourly: 0, ec2_running: 0, rds_od_hourly: 1, cache_od_hourly: 0, rds_reserved_hourly: null, cache_reserved_hourly: null, ebs_month: 310, s3_month: 0, lambda_month: 0 },
    last_month: { total: 1200, services: { "EC2 - Other": 600, AmazonCloudWatch: 300, "Amazon Relational Database Service": 300 } }, prior,
  }, new Date("2026-10-01T08:00:00Z"));
  const svc = (s: string) => f.services.find((x) => x.service === s)!;
  assert.equal(svc("AmazonCloudWatch").forecast, 310, "10 a day for 31 days");
  assert.equal(svc("EC2 - Other").forecast, 620 + 310, "NAT at September's rate plus the volumes, which bill under EC2 - Other");
  assert.equal(svc("Amazon Relational Database Service").forecast, 223.2, "1 USD/h at September's 30 % share");
  assert.equal(Math.round(f.services.reduce((s, x) => s + x.forecast, 0) * 100) / 100, f.forecast_net, "the rows add up to the total");
});

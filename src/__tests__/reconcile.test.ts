import { test } from "node:test";
import assert from "node:assert";
import { businessSupport, hoursInMonth, priceRuleFor, splitUsageType } from "../pricebook.js";
import { computeReconciliation, lastFullMonth } from "../reconcile.js";

test("pricebook: usage types map to rules, instance hours to SKU rules, regions parse from the prefix", () => {
  assert.equal(splitUsageType("USE1-DataProcessing-Bytes").region, "us-east-1");
  assert.equal(splitUsageType("USW2-BoxUsage:t3.small").region, "us-west-2");
  assert.equal(splitUsageType("NatGateway-Bytes").name, "NatGateway-Bytes");
  assert.deepEqual(priceRuleFor("Amazon Elastic Compute Cloud - Compute", "BoxUsage:m6i.8xlarge"), { rule: "sku", kind: "ec2", sku: "m6i.8xlarge", spot: false });
  assert.equal((priceRuleFor("Amazon Relational Database Service", "InstanceUsageIOOptimized:db.r7g.xl") as any).sku, "db.r7g.xlarge", "CE abbreviates the class; the SKU is expanded");
  assert.equal((priceRuleFor("Amazon Relational Database Service", "InstanceUsage:db.r6g.2xl") as any).sku, "db.r6g.2xlarge");
  assert.equal((priceRuleFor("Amazon Relational Database Service", "InstanceUsageIOOptimized:db.r7g.xlarge") as any).ioOptimized, true);
  assert.equal((priceRuleFor("Amazon ElastiCache", "NodeUsage:cache.m7g.large") as any).kind, "elasticache");
  assert.equal((priceRuleFor("EC2 - Other", "NatGateway-Bytes") as any).unit_price, 0.045);
  assert.equal((priceRuleFor("AmazonCloudWatch", "USE1-DataProcessing-Bytes") as any).rule, "cw_logs_ingest");
  assert.equal((priceRuleFor("AmazonCloudWatch", "TimedStorage-ByteHrs") as any).rule, "cw_logs_storage");
  assert.equal((priceRuleFor("Amazon Simple Storage Service", "TimedStorage-ByteHrs") as any).rule, "storage_gb_month");
  assert.equal((priceRuleFor("Amazon Textract", "USE1-SyncFormsQueriesTablesPagesProcessed") as any).rule, "textract_forms_queries_tables");
  assert.equal(priceRuleFor("AWS Elemental MediaConvert", "IAD-B-NA-AUD-NA-NA-NTM"), null, "no rule yet: unpriced, named");
  assert.equal(hoursInMonth("2026-08"), 744);
  assert.equal(hoursInMonth("2026-02"), 672);
  assert.equal(businessSupport(22355.8), 1000 + 12355.8 * 0.07);
  assert.equal(businessSupport(500), 100);
  assert.equal(lastFullMonth(new Date("2026-09-20T10:00:00Z")), "2026-08");
  assert.equal(lastFullMonth(new Date("2026-01-03T10:00:00Z")), "2025-12");
});

test("reconciliation: prices lines, brings covered usage back to on-demand, rolls up per service and scores the eval", () => {
  const prices = new Map<string, number | null>([["ec2|m6i.8xlarge|us-east-1|Linux", 1.536], ["ec2|m5.large|us-east-1|Linux", 0.096]]);
  const r = computeReconciliation({
    month: "2026-08",
    lines: [
      // 1000 h covered by the Savings Plan at a 25 % discount: unblended 0, amortized 1152 (= 1536 × 0.75)
      { service: "Amazon Elastic Compute Cloud - Compute", usage_type: "BoxUsage:m6i.8xlarge", quantity: 1000, unit: "Hrs", unblended: 0, net: 0, amortized: 1152 },
      { service: "Amazon Elastic Compute Cloud - Compute", usage_type: "BoxUsage:m5.large", quantity: 100, unit: "Hrs", unblended: 9.6, net: 9.6, amortized: 9.6 },
      { service: "EC2 - Other", usage_type: "NatGateway-Bytes", quantity: 1000, unit: "GB", unblended: 45, net: 45, amortized: 45 },
      { service: "Amazon Textract", usage_type: "USE1-Pages", quantity: 10, unit: "Pages", unblended: 63, net: 63, amortized: 63 },
    ],
    records: { usage_net: 117.6, sp_fee: 1152, sp_covered_od: 1536, ri_amortized: 0, support: 0, tax: 0, other: 0, net_total: 1269.6 },
    sp_hourly: 1152 / 744,
    sku_prices: prices, sku_engines: new Map(),
  });
  const box = r.lines.find((l) => l.usage_type === "BoxUsage:m6i.8xlarge")!;
  assert.equal(box.modelled, 1536);
  assert.equal(box.actual_od, 1536, "covered usage brought back to on-demand with the implied discount");
  assert.equal(box.residual, 0);
  assert.equal(r.totals.sp_discount_rate, 25);
  assert.equal(r.totals.unpriced_actual, 63);
  const ec2 = r.services.find((s) => s.service.includes("Compute"))!;
  assert.equal(ec2.status, "pass");
  assert.equal(r.services.find((s) => s.service === "Amazon Textract")!.status, "named");
  // modelled net = list usage (1536 + 9.6 + 45) + unpriced 63 - covered 1536 + fee 1152 = 1269.6
  assert.equal(r.totals.modelled_net, 1269.6);
  assert.ok(r.eval.find((e) => e.criterion.startsWith("total"))!.pass);
  assert.ok(r.eval.find((e) => e.criterion.startsWith("commitments"))!.pass);
  assert.ok(r.eval.find((e) => e.criterion.startsWith("provenance"))!.pass);
  assert.equal(r.eval.find((e) => e.criterion.startsWith("priced share"))!.pass, true);
});

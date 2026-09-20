import assert from "node:assert/strict";
import { test } from "node:test";
import { FIX_ACTION_TYPES, INCIDENT_SCHEMA, parseIncidentResult } from "../investigate.js";
import { FLOW_LOG_ALERT_WINDOW_DAYS, flowLogRecommendation } from "../flowlogs.js";

test("parseIncidentResult keeps the schema shape and defaults unknown fix values", () => {
  const r = parseIncidentResult({
    cause: "Image pulls through the NAT gateway", confidence: 1.4, evidence: ["a", 2],
    episode_cost_usd: "0.35", monthly_run_rate_usd: null,
    fixes: [
      { title: "Enable flow logs", action_type: "enable_flow_logs", resource: "vpc-1", est_monthly_saving: 0, tier: "approve", confidence: 0.9, rationale: "r" },
      { title: "Something odd", action_type: "delete_everything", resource: "x", tier: "yolo", confidence: "n/a", rationale: "" },
      "not a fix",
    ],
  })!;
  assert.equal(r.cause, "Image pulls through the NAT gateway");
  assert.equal(r.confidence, 1); // clamped
  assert.deepEqual(r.evidence, ["a", "2"]);
  assert.equal(r.episode_cost_usd, 0.35);
  assert.equal(r.monthly_run_rate_usd, null);
  assert.equal(r.fixes.length, 2);
  assert.equal(r.fixes[0].action_type, "enable_flow_logs");
  assert.deepEqual([r.fixes[1].action_type, r.fixes[1].tier, r.fixes[1].confidence, r.fixes[1].est_monthly_saving], ["other", "approve", 0.5, 0]);
  assert.equal(parseIncidentResult({ recommendations: [] }), null);
  assert.equal(parseIncidentResult(null), null);
  // the schema's enum and the parser's whitelist are the same list
  assert.deepEqual((INCIDENT_SCHEMA.properties.fixes.items.properties.action_type as any).enum, [...FIX_ACTION_TYPES]);
});

test("flowLogRecommendation fires only for VPCs without a flow log and fingerprints by vpc", () => {
  const facts = { vpc_id: "vpc-1", vpc_name: "workspace-vpc", region: "us-east-1", nat_gateways: ["nat-1"], subnets: ["subnet-a", "subnet-b"], flow_logs: [] };
  const rec = flowLogRecommendation(facts, 2)!;
  assert.equal(rec.rule, "enable_flow_logs");
  assert.equal(rec.resource, "vpc-1");
  assert.equal(rec.actionType, "enable_flow_logs");
  assert.equal(rec.tier, "approve");
  assert.equal(rec.estMonthlySaving, null);
  assert.match(rec.rationale, /2 NAT traffic alerts in the last 7 days/);
  assert.match(rec.rationale, /few USD per month/);
  assert.match(rec.rationale, /does not enable flow logs itself/);
  assert.equal(FLOW_LOG_ALERT_WINDOW_DAYS, 7);
  const withLog = { ...facts, flow_logs: [{ flow_log_id: "fl-1", resource_id: "subnet-a", log_destination_type: "cloud-watch-logs", log_destination: null, max_aggregation_interval: 600, traffic_type: "ALL", flow_log_status: "ACTIVE" }] };
  assert.equal(flowLogRecommendation(withLog, 1), null);
});

import assert from "node:assert/strict";
import { test } from "node:test";
import { kmsUnusedVerdict, keyId, HARMLESS_EVENTS, MIN_AGE_DAYS as KMS_MIN_AGE, type KeyFacts, type KeyRefs } from "../actions/kms_key_retire.js";
import { elbIdleVerdict, metricDimension, monthlyUsd, MIN_AGE_DAYS as ELB_MIN_AGE } from "../actions/idle_load_balancer.js";

const NOW = Date.parse("2026-09-27T12:00:00Z");
const daysAgo = (d: number) => new Date(NOW - d * 86400000).toISOString();
const key = (over: Partial<KeyFacts> = {}): KeyFacts => ({ key_id: "k1", key_arn: "arn:aws:kms:us-east-1:1:key/k1", manager: "CUSTOMER", state: "Enabled", enabled: true, multi_region: false, created: daysAgo(400), hands_off: false, ...over });
const noRefs: KeyRefs = { volumes: 0, snapshots: 0, rds_instances: 0, rds_clusters: 0, log_groups: 0 };

test("kms: unused only when customer-managed, enabled, old, unreferenced and silent in CloudTrail", () => {
  assert.equal(kmsUnusedVerdict(key(), noRefs, [], NOW).unused, true);
  // metadata reads do not count as use
  assert.equal(kmsUnusedVerdict(key(), noRefs, ["DescribeKey", "GetKeyRotationStatus"], NOW).unused, true);
  const used = kmsUnusedVerdict(key(), noRefs, ["Decrypt"], NOW);
  assert.equal(used.unused, false); assert.match(used.reasons.join(";"), /CloudTrail shows Decrypt/);
  assert.ok(HARMLESS_EVENTS.has("DescribeKey") && !HARMLESS_EVENTS.has("GenerateDataKey"));
});

test("kms: references, AWS-managed, young, multi-region, hands-off and unreadable CloudTrail keep a key", () => {
  assert.match(kmsUnusedVerdict(key(), { ...noRefs, volumes: 2 }, [], NOW).reasons.join(";"), /encrypts 2 EBS volume/);
  assert.match(kmsUnusedVerdict(key({ manager: "AWS" }), noRefs, [], NOW).reasons.join(";"), /AWS-managed/);
  assert.match(kmsUnusedVerdict(key({ created: daysAgo(KMS_MIN_AGE - 1) }), noRefs, [], NOW).reasons.join(";"), /days old/);
  assert.match(kmsUnusedVerdict(key({ multi_region: true }), noRefs, [], NOW).reasons.join(";"), /multi-region/);
  assert.match(kmsUnusedVerdict(key({ hands_off: true }), noRefs, [], NOW).reasons.join(";"), /hands-off/);
  assert.match(kmsUnusedVerdict(key({ state: "Disabled", enabled: false }), noRefs, [], NOW).reasons.join(";"), /Disabled/);
  const unknown = kmsUnusedVerdict(key(), noRefs, null, NOW);
  assert.equal(unknown.unused, false); assert.match(unknown.reasons.join(";"), /unreadable/);
});

test("kms: a key ARN or a bare id both give the key id", () => {
  assert.equal(keyId("arn:aws:kms:us-east-1:1:key/abc-123"), "abc-123");
  assert.equal(keyId("abc-123"), "abc-123");
  assert.equal(keyId(null), null);
});

const lb = (over: Partial<{ type: string; created: string | null; state: string | null }> = {}) => ({ type: "application", created: daysAgo(90), state: "active", ...over });
const quiet = { healthy: 0, total: 1, unknown: false };
const open = { deletion_protection: false, hands_off: false };

test("elb: idle only when every metric is zero, no target is healthy, old enough, unprotected", () => {
  assert.equal(elbIdleVerdict(lb(), { RequestCount: 0, ProcessedBytes: 0 }, quiet, open, NOW).idle, true);
  assert.equal(elbIdleVerdict(lb({ type: "network" }), { ActiveFlowCount: 0, ProcessedBytes: 0 }, quiet, open, NOW).idle, true);
  assert.equal(elbIdleVerdict(lb({ type: "gateway" }), { ProcessedBytes: 0 }, quiet, open, NOW).idle, true);
  assert.match(elbIdleVerdict(lb(), { RequestCount: 12, ProcessedBytes: 0 }, quiet, open, NOW).reasons.join(";"), /RequestCount 12/);
  // a missing metric is unknown, so traffic
  assert.match(elbIdleVerdict(lb(), { RequestCount: 0 }, quiet, open, NOW).reasons.join(";"), /ProcessedBytes has no datapoints/);
  assert.match(elbIdleVerdict(lb(), { RequestCount: 0, ProcessedBytes: 0 }, { healthy: 1, total: 2, unknown: false }, open, NOW).reasons.join(";"), /1 healthy target/);
  assert.match(elbIdleVerdict(lb(), { RequestCount: 0, ProcessedBytes: 0 }, { ...quiet, unknown: true }, open, NOW).reasons.join(";"), /unreadable/);
  assert.match(elbIdleVerdict(lb({ created: daysAgo(ELB_MIN_AGE - 2) }), { RequestCount: 0, ProcessedBytes: 0 }, quiet, open, NOW).reasons.join(";"), /days old/);
  assert.match(elbIdleVerdict(lb(), { RequestCount: 0, ProcessedBytes: 0 }, quiet, { ...open, deletion_protection: true }, NOW).reasons.join(";"), /deletion protection/);
  assert.match(elbIdleVerdict(lb(), { RequestCount: 0, ProcessedBytes: 0 }, quiet, { ...open, hands_off: true }, NOW).reasons.join(";"), /hands-off/);
  assert.match(elbIdleVerdict(lb({ state: "provisioning" }), { RequestCount: 0, ProcessedBytes: 0 }, quiet, open, NOW).reasons.join(";"), /state provisioning/);
  assert.match(elbIdleVerdict(lb({ type: "classic" }), {}, quiet, open, NOW).reasons.join(";"), /not covered/);
});

test("elb: the CloudWatch dimension is the ARN tail, and the estimate is the hourly price over a month", () => {
  assert.equal(metricDimension("arn:aws:elasticloadbalancing:us-east-1:1:loadbalancer/app/web/50dc6c495c0c9188"), "app/web/50dc6c495c0c9188");
  assert.equal(monthlyUsd("application"), 16.43);
  assert.equal(monthlyUsd("network"), 16.43);
  assert.equal(monthlyUsd("gateway"), 9.13);
});

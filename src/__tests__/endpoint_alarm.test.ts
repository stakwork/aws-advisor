import assert from "node:assert/strict";
import { test } from "node:test";
import { pickRouteTables, resourceKind, serviceName, servicesOf } from "../actions/vpc_gateway_endpoint.js";
import { alarmCost, alarmDefinition, staleVerdict, type Dim } from "../actions/alarm_cleanup.js";

test("gateway endpoint: the fix's resource is a VPC, a NAT gateway or an instance", () => {
  assert.equal(resourceKind("vpc-0abc123"), "vpc");
  assert.equal(resourceKind("nat-0abc123def"), "nat");
  assert.equal(resourceKind("i-0123456789abcdef0"), "instance");
  assert.equal(resourceKind("my-nodegroup"), "unknown");
  assert.equal(serviceName("eu-west-1", "s3"), "com.amazonaws.eu-west-1.s3");
});

test("gateway endpoint: S3 unless the fix only talks about DynamoDB, both when it names both", () => {
  assert.deepEqual(servicesOf({ title: "Add an S3 gateway endpoint to vpc-1", evidence: { rationale: "the NAT carries S3 pulls" } }), ["s3"]);
  assert.deepEqual(servicesOf({ title: "Gateway endpoint for the VPC", evidence: {} }), ["s3"]);
  assert.deepEqual(servicesOf({ title: "Add a DynamoDB gateway endpoint", evidence: { rationale: "writes to DynamoDB go through the NAT" } }), ["dynamodb"]);
  assert.deepEqual(servicesOf({ title: "Gateway endpoints", evidence: { rationale: "S3 and DynamoDB traffic through nat-1" } }), ["s3", "dynamodb"]);
});

test("gateway endpoint: the route tables that send 0.0.0.0/0 through a NAT gateway, else all of them", () => {
  const tables = [
    { RouteTableId: "rtb-public", Tags: [{ Key: "Name", Value: "public" }], Routes: [{ DestinationCidrBlock: "0.0.0.0/0", GatewayId: "igw-1" }] },
    { RouteTableId: "rtb-private-a", Tags: [{ Key: "Name", Value: "private-a" }], Routes: [{ DestinationCidrBlock: "0.0.0.0/0", NatGatewayId: "nat-1" }] },
    { RouteTableId: "rtb-private-b", Routes: [{ DestinationCidrBlock: "10.0.0.0/16", GatewayId: "local" }, { DestinationCidrBlock: "0.0.0.0/0", NatGatewayId: "nat-2" }] },
  ];
  const pick = pickRouteTables(tables);
  assert.deepEqual(pick.ids, ["rtb-private-a", "rtb-private-b"]);
  assert.equal(pick.fallback, false);
  assert.deepEqual(pick.names, [{ id: "rtb-private-a", name: "private-a" }, { id: "rtb-private-b", name: null }]);
  const all = pickRouteTables([tables[0]]);
  assert.deepEqual(all.ids, ["rtb-public"]);
  assert.equal(all.fallback, true);
  assert.deepEqual(pickRouteTables([]).ids, []);
});

const day = 86400000;
const now = Date.parse("2026-09-27T12:00:00Z");
const alarm = (over: Record<string, unknown> = {}) => ({ AlarmName: "cpu-high", StateValue: "INSUFFICIENT_DATA", StateUpdatedTimestamp: new Date(now - 45 * day), Dimensions: [{ Name: "InstanceId", Value: "i-gone" }], ...over } as any);
const check = (map: Record<string, boolean | null>) => (d: Dim) => (d.value in map ? map[d.value] : null);

test("alarms: stale only when INSUFFICIENT_DATA long enough and a checkable dimension names a gone resource", () => {
  const v = staleVerdict(alarm(), check({ "i-gone": true }), 30, now);
  assert.equal(v.stale, true); assert.equal(v.age_days, 45); assert.deepEqual(v.dimension, { name: "InstanceId", value: "i-gone" });
  // still there
  const alive = staleVerdict(alarm(), check({ "i-gone": false }), 30, now);
  assert.equal(alive.stale, false); assert.match(alive.why, /still exists/);
  // cannot tell: never stale
  const unknown = staleVerdict(alarm(), check({}), 30, now);
  assert.equal(unknown.stale, false); assert.match(unknown.why, /could not be checked/);
  // too young
  assert.match(staleVerdict(alarm({ StateUpdatedTimestamp: new Date(now - 10 * day) }), check({ "i-gone": true }), 30, now).why, /10 days \(rule: 30\+\)/);
  // wrong state, no timestamp
  assert.equal(staleVerdict(alarm({ StateValue: "OK" }), check({ "i-gone": true }), 30, now).stale, false);
  assert.equal(staleVerdict(alarm({ StateUpdatedTimestamp: undefined }), check({ "i-gone": true }), 30, now).stale, false);
  // an uncheckable dimension kind is left alone even when old
  const lb = staleVerdict(alarm({ Dimensions: [{ Name: "LoadBalancer", Value: "app/x/1" }] }), () => true, 30, now);
  assert.equal(lb.stale, false); assert.match(lb.why, /cannot be checked/);
  assert.match(staleVerdict(alarm({ Dimensions: [] }), () => true, 30, now).why, /no dimension/);
  // one alive dimension outweighs nothing: gone wins when any checkable dimension is gone, alive wins over unknown
  const mixed = staleVerdict(alarm({ Dimensions: [{ Name: "InstanceId", Value: "i-alive" }, { Name: "VolumeId", Value: "vol-gone" }] }), check({ "i-alive": false, "vol-gone": true }), 30, now);
  assert.equal(mixed.stale, true); assert.equal(mixed.dimension?.value, "vol-gone");
  // math-expression alarms carry their dimensions under Metrics
  const math = staleVerdict(alarm({ Dimensions: undefined, Metrics: [{ Id: "m1", MetricStat: { Metric: { Namespace: "AWS/RDS", MetricName: "CPUUtilization", Dimensions: [{ Name: "DBInstanceIdentifier", Value: "db-gone" }] } } }] }), check({ "db-gone": true }), 30, now);
  assert.equal(math.stale, true);
});

test("alarms: the saved definition is what PutMetricAlarm takes, and the price follows the period", () => {
  const def = alarmDefinition({ AlarmName: "cpu-high", AlarmArn: "arn:aws:cloudwatch:us-east-1:1:alarm:cpu-high", StateValue: "INSUFFICIENT_DATA", StateReason: "x", MetricName: "CPUUtilization", Namespace: "AWS/EC2", Statistic: "Average", Dimensions: [{ Name: "InstanceId", Value: "i-1" }], Period: 300, EvaluationPeriods: 3, Threshold: 80, ComparisonOperator: "GreaterThanThreshold", AlarmActions: ["arn:sns"], OKActions: [], AlarmConfigurationUpdatedTimestamp: new Date() } as any);
  assert.deepEqual(Object.keys(def).sort(), ["AlarmActions", "AlarmName", "ComparisonOperator", "Dimensions", "EvaluationPeriods", "MetricName", "Namespace", "Period", "Statistic", "Threshold"]);
  assert.equal(alarmCost({ Period: 300 }), 0.10);
  assert.equal(alarmCost({ Period: 10 }), 0.30);
  assert.equal(alarmCost({}), 0.10);
});

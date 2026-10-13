import assert from "node:assert/strict";
import { test } from "node:test";
import {
  detectRegionCollisions, logGroupName, mapServicePrincipal, parseEventSourceMapping, parsePolicyStd, polledNativeKind, stripQualifier,
} from "../adapters/aws/functions.js";

test("mapServicePrincipal: the generic mapping table, with a fallback for anything unlisted", () => {
  assert.deepEqual(mapServicePrincipal("apigateway.amazonaws.com"), { kind: "http", via: "invoke_permission" });
  assert.deepEqual(mapServicePrincipal("elasticloadbalancing.amazonaws.com"), { kind: "http", via: "load_balancer" });
  assert.deepEqual(mapServicePrincipal("s3.amazonaws.com"), { kind: "event", via: "invoke_permission" });
  assert.deepEqual(mapServicePrincipal("sns.amazonaws.com"), { kind: "event", via: "invoke_permission" });
  assert.deepEqual(mapServicePrincipal("events.amazonaws.com"), { kind: "event", via: "invoke_permission" });
  assert.deepEqual(mapServicePrincipal("iot.amazonaws.com"), { kind: "event", via: "invoke_permission" });
});

test("parsePolicyStd: apigateway with a wildcard SourceArn", () => {
  const policy = { Statement: [{ Sid: "apigw", Effect: "Allow", Principal: { Service: "apigateway.amazonaws.com" }, Action: "lambda:InvokeFunction", Condition: { ArnLike: { "AWS:SourceArn": "arn:aws:execute-api:us-east-1:1:abc/*/GET/*" } } }] };
  const out = parsePolicyStd(policy);
  assert.equal(out.length, 1);
  assert.equal(out[0].kind, "http"); assert.equal(out[0].via, "invoke_permission"); assert.equal(out[0].native_kind, "apigateway");
  assert.equal(out[0].source, "arn:aws:execute-api:us-east-1:1:abc/*/GET/*");
  assert.ok(!out[0].public);
});

test("parsePolicyStd: eventbridge, s3, sns each come through as event/invoke_permission with their own native_kind", () => {
  for (const svc of ["events.amazonaws.com", "s3.amazonaws.com", "sns.amazonaws.com"]) {
    const out = parsePolicyStd({ Statement: [{ Effect: "Allow", Principal: { Service: svc }, Action: "lambda:InvokeFunction", Condition: { ArnLike: { "aws:sourcearn": "arn:aws:s3:::bucket" } } }] });
    assert.equal(out[0].kind, "event"); assert.equal(out[0].via, "invoke_permission"); assert.equal(out[0].native_kind, svc.split(".")[0]);
  }
});

test("parsePolicyStd: elasticloadbalancing gets http/load_balancer, an unlisted principal (iot) falls back to event/invoke_permission", () => {
  const elb = parsePolicyStd({ Statement: [{ Effect: "Allow", Principal: { Service: "elasticloadbalancing.amazonaws.com" }, Action: "lambda:InvokeFunction", Condition: { ArnLike: { "AWS:SourceArn": "arn:aws:elasticloadbalancing:us-east-1:1:targetgroup/tg/abc" } } }] });
  assert.equal(elb[0].kind, "http"); assert.equal(elb[0].via, "load_balancer");
  const iot = parsePolicyStd({ Statement: [{ Effect: "Allow", Principal: { Service: "iot.amazonaws.com" }, Action: "lambda:InvokeFunction", Condition: { ArnLike: { "AWS:SourceArn": "arn:aws:iot:us-east-1:1:topicrule/x" } } }] });
  assert.equal(iot[0].kind, "event"); assert.equal(iot[0].via, "invoke_permission"); assert.equal(iot[0].native_kind, "iot");
});

test("parsePolicyStd: cross-account principal carries source_account; no SourceArn and Principal '*' both set public", () => {
  const cross = parsePolicyStd({ Statement: [{ Effect: "Allow", Principal: { AWS: "arn:aws:iam::222222222222:root" }, Action: "lambda:InvokeFunction" }] });
  assert.equal(cross[0].source_account, "arn:aws:iam::222222222222:root");
  assert.ok(cross[0].public);
  const noArn = parsePolicyStd({ Statement: [{ Effect: "Allow", Principal: { Service: "s3.amazonaws.com" }, Action: "lambda:InvokeFunction" }] });
  assert.ok(noArn[0].public);
  const star = parsePolicyStd({ Statement: [{ Effect: "Allow", Principal: "*", Action: "lambda:InvokeFunction" }] });
  assert.ok(star[0].public);
});

test("parsePolicyStd: lambda:InvokeFunctionUrl with functionurlauthtype NONE is a function URL trigger needing no auth", () => {
  const none = parsePolicyStd({ Statement: [{ Effect: "Allow", Principal: "*", Action: "lambda:InvokeFunctionUrl", Condition: { StringEquals: { "lambda:FunctionUrlAuthType": "NONE" } } }] });
  assert.equal(none[0].native_kind, "function_url"); assert.equal(none[0].requires_auth, false);
  const iam = parsePolicyStd({ Statement: [{ Effect: "Allow", Principal: { AWS: "arn:aws:iam::1:role/x" }, Action: "lambda:InvokeFunctionUrl", Condition: { StringEquals: { "lambda:FunctionUrlAuthType": "AWS_IAM" } } }] });
  assert.equal(iam[0].requires_auth, true);
});

test("parsePolicyStd: array condition values and lower-cased condition keys are both accepted; no statement is ever dropped", () => {
  const out = parsePolicyStd({ Statement: [{ Effect: "Allow", Principal: { Service: "s3.amazonaws.com" }, Action: ["lambda:InvokeFunction"], Condition: { ArnLike: { "aws:sourcearn": ["arn:aws:s3:::a", "arn:aws:s3:::b"] } } }] });
  assert.equal(out.length, 1);
  assert.equal(out[0].source, "arn:aws:s3:::a");
});

test("stripQualifier: splits an alias or version off a function ARN", () => {
  assert.deepEqual(stripQualifier("arn:aws:lambda:us-east-1:1:function:name:live"), { arn: "arn:aws:lambda:us-east-1:1:function:name", target_version: "live" });
  assert.deepEqual(stripQualifier("arn:aws:lambda:us-east-1:1:function:name"), { arn: "arn:aws:lambda:us-east-1:1:function:name", target_version: null });
});

test("parseEventSourceMapping: SQS, a DynamoDB stream, Kinesis, a qualified ARN, and self-managed Kafka with no ARN", () => {
  const sqs = parseEventSourceMapping({ function_arn: "arn:aws:lambda:us-east-1:1:function:f", event_source_arn: "arn:aws:sqs:us-east-1:1:q", state: "Enabled", batch_size: 10 });
  assert.equal(sqs.native_kind, "sqs"); assert.equal(sqs.kind, "queue"); assert.equal(sqs.via, "polled"); assert.equal(sqs.batch_size, 10);
  const ddb = parseEventSourceMapping({ function_arn: "arn:aws:lambda:us-east-1:1:function:f", event_source_arn: "arn:aws:dynamodb:us-east-1:1:table/t/stream/2020", state: "Enabled" });
  assert.equal(ddb.native_kind, "dynamodb_stream");
  const kinesis = parseEventSourceMapping({ function_arn: "arn:aws:lambda:us-east-1:1:function:f", event_source_arn: "arn:aws:kinesis:us-east-1:1:stream/s" });
  assert.equal(kinesis.native_kind, "kinesis");
  const qualified = parseEventSourceMapping({ function_arn: "arn:aws:lambda:us-east-1:1:function:f:live", event_source_arn: "arn:aws:sqs:us-east-1:1:q" });
  assert.equal(qualified.target_version, "live");
  const kafka = parseEventSourceMapping({ function_arn: "arn:aws:lambda:us-east-1:1:function:f", event_source_arn: null, self_managed_event_source: { Endpoints: { KafkaBootstrapServers: ["b1:9092", "b2:9092"] } } });
  assert.equal(kafka.native_kind, "kafka"); assert.equal(kafka.source, "b1:9092,b2:9092");
  const noSource = parseEventSourceMapping({ function_arn: "arn:aws:lambda:us-east-1:1:function:f", event_source_arn: null });
  assert.equal(noSource.native_kind, "kafka"); assert.equal(noSource.source, null);
});

test("polledNativeKind: the source table's ARN decides the native kind", () => {
  assert.equal(polledNativeKind("arn:aws:sqs:us-east-1:1:q"), "sqs");
  assert.equal(polledNativeKind("arn:aws:kinesis:us-east-1:1:stream/s"), "kinesis");
  assert.equal(polledNativeKind("arn:aws:dynamodb:us-east-1:1:table/t/stream/2020"), "dynamodb_stream");
  assert.equal(polledNativeKind("arn:aws:kafka:us-east-1:1:cluster/x"), "kafka");
  assert.equal(polledNativeKind("arn:aws:mq:us-east-1:1:broker:b"), "mq");
  assert.equal(polledNativeKind(null), "kafka");
});

test("logGroupName: logging_config.LogGroup wins, else the AWS default", () => {
  assert.equal(logGroupName({ LogGroup: "/custom/group" }, "fn"), "/custom/group");
  assert.equal(logGroupName(null, "fn"), "/aws/lambda/fn");
  assert.equal(logGroupName(JSON.stringify({ LogGroup: "/custom/group" }), "fn"), "/custom/group");
});

test("detectRegionCollisions: one function name in several regions of one account, logged against the account+name key", () => {
  const rows = [
    { account_id: "1", name: "f", region: "us-east-1" },
    { account_id: "1", name: "f", region: "us-west-2" },
    { account_id: "1", name: "g", region: "us-east-1" },
    { account_id: "2", name: "f", region: "eu-west-1" },
  ];
  const collisions = detectRegionCollisions(rows);
  assert.deepEqual(collisions.get("1|f"), ["us-east-1", "us-west-2"]);
  assert.equal(collisions.get("1|g"), undefined);
  assert.equal(collisions.get("2|f"), undefined);
});

import { test } from "node:test";
import assert from "node:assert";
import { actorOf, causeSummary, channelOf, pickEvent, stateReasonCause, transitionTime } from "../alert_cause.js";

test("alert cause: the channel comes from the user agent or invokedBy", () => {
  assert.equal(channelOf("signin.amazonaws.com"), "the console");
  assert.equal(channelOf("AWS Internal"), "the console");
  assert.equal(channelOf("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"), "the console");
  assert.equal(channelOf("aws-cli/2.15.0 Python/3.11 Darwin/25"), "the AWS CLI");
  assert.equal(channelOf("APN/1.0 HashiCorp/1.0 Terraform/1.7.0 (+https://www.terraform.io) terraform-provider-aws/5.40.0"), "Terraform");
  assert.equal(channelOf("Boto3/1.34.0 md/Botocore#1.34.0"), "boto3");
  assert.equal(channelOf("aws-sdk-js/3.600.0 ua/2.0 exec-env/AWS_Lambda_nodejs20.x"), "a Lambda function");
  assert.equal(channelOf(null, "autoscaling.amazonaws.com"), "Auto Scaling");
  assert.equal(channelOf(null, null), null);
});

test("alert cause: who made the call", () => {
  const sso = { userIdentity: { type: "AssumedRole", arn: "arn:aws:sts::111122223333:assumed-role/AWSReservedSSO_AdministratorAccess_0123456789abcdef/gonzalo@example.com", sessionContext: { sessionIssuer: { userName: "AWSReservedSSO_AdministratorAccess_0123456789abcdef" } } }, userAgent: "signin.amazonaws.com" };
  assert.deepEqual(actorOf(sso, null), { actor: "gonzalo@example.com (AdministratorAccess)", kind: "person", principal_arn: sso.userIdentity.arn });
  const act = { userIdentity: { type: "AssumedRole", arn: "arn:aws:sts::1:assumed-role/advisor-actuator/aws-advisor-act", sessionContext: { sessionIssuer: { userName: "advisor-actuator" } } } };
  assert.equal(actorOf(act, "advisor-actuator").kind, "advisor");
  assert.equal(actorOf(act, null).kind, "advisor", "the session name alone says it is the advisor");
  const asg = { userIdentity: { type: "AssumedRole", arn: "arn:aws:sts::1:assumed-role/AWSServiceRoleForAutoScaling/AutoScaling", invokedBy: "autoscaling.amazonaws.com", sessionContext: { sessionIssuer: { userName: "AWSServiceRoleForAutoScaling" } } } };
  assert.deepEqual(actorOf(asg, null).kind, "aws");
  assert.deepEqual(actorOf({ userIdentity: { type: "IAMUser", userName: "alice", arn: "arn:aws:iam::1:user/alice" } }, null), { actor: "alice", kind: "person", principal_arn: "arn:aws:iam::1:user/alice" });
  assert.equal(actorOf({ userIdentity: { type: "IAMUser", userName: "github-deploy" } }, null).kind, "automation");
  const lambda = { userIdentity: { type: "AssumedRole", arn: "arn:aws:sts::1:assumed-role/scheduler-role/start-hive", sessionContext: { sessionIssuer: { userName: "scheduler-role" } } }, userAgent: "aws-sdk-js/3 exec-env/AWS_Lambda_nodejs20.x" };
  assert.deepEqual(actorOf(lambda, null), { actor: "start-hive (role scheduler-role)", kind: "automation", principal_arn: lambda.userIdentity.arn });
  assert.equal(actorOf({ userIdentity: { type: "Root", arn: "arn:aws:iam::1:root" } }, null).kind, "person");
});

test("alert cause: EC2's own reasons for changes without an API call", () => {
  assert.equal(stateReasonCause("Client.InstanceInitiatedShutdown", "Client.InstanceInitiatedShutdown: Instance initiated shutdown")?.kind, "automation");
  assert.equal(stateReasonCause("Server.SpotInstanceTermination", "")?.kind, "aws");
  assert.equal(stateReasonCause("Client.UserInitiatedShutdown", "User initiated shutdown"), null, "a user-initiated stop is a CloudTrail question");
  assert.equal(stateReasonCause(null, null), null);
  assert.equal(transitionTime("User initiated (2026-10-01 05:29:12 GMT)"), "2026-10-01T05:29:12.000Z");
  assert.equal(transitionTime(""), null);
});

test("alert cause: the event that explains the change wins, latest and successful first", () => {
  const ev = (event_name: string, event_time: string, error_code: string | null = null) => ({ event_name, event_time, error_code });
  const events = [ev("CreateTags", "2026-10-01T05:29:30Z"), ev("StopInstances", "2026-10-01T05:10:00Z"), ev("StartInstances", "2026-10-01T05:28:00Z", "UnauthorizedOperation"), ev("StartInstances", "2026-10-01T05:29:00Z")];
  assert.deepEqual(pickEvent(events, "running"), ev("StartInstances", "2026-10-01T05:29:00Z"));
  assert.deepEqual(pickEvent(events, "stopped"), ev("StopInstances", "2026-10-01T05:10:00Z"));
  assert.deepEqual(pickEvent([ev("TerminateInstances", "2026-10-01T05:00:00Z")], null), ev("TerminateInstances", "2026-10-01T05:00:00Z"));
  assert.equal(pickEvent([ev("CreateTags", "2026-10-01T05:29:30Z")], "running"), null);
});

test("alert cause: the Why sentence", () => {
  const base = { status: "found" as const, actor: null, actor_kind: "unknown" as const, via: null, event_name: null, event_time: null, source_ip: null, action_id: null, action_kind: null, state_reason: null, error_code: null, window: { from: "2026-10-01T05:00:00.000Z", to: "2026-10-01T05:35:00.000Z" } };
  assert.equal(causeSummary({ ...base, source: "cloudtrail", actor: "gonzalo@example.com (AdministratorAccess)", actor_kind: "person", via: "the console", event_name: "StartInstances", event_time: "2026-10-01T05:29:12.000Z", source_ip: "190.2.3.4" }),
    "Started by gonzalo@example.com (AdministratorAccess) via the console from 190.2.3.4 at 2026-10-01 05:29 UTC");
  assert.equal(causeSummary({ ...base, source: "ledger", actor: "the advisor", actor_kind: "advisor", action_id: 42, action_kind: "schedule_hours", event_name: "StartInstances", event_time: "2026-10-01T05:00:03.000Z" }),
    "Started by the advisor (ledger row #42, schedule_hours) at 2026-10-01 05:00 UTC");
  assert.match(causeSummary({ ...base, status: "pending", source: null }), /looking for the CloudTrail event/);
  assert.match(causeSummary({ ...base, status: "none", source: null, state_reason: "User initiated (2026-10-01 05:29:12 GMT)" }), /^no API call on the instance in CloudTrail between 2026-10-01 05:00 UTC and 2026-10-01 05:35 UTC; EC2 says/);
});

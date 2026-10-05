import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

// A denial is attributed to the account it was seen in (src/permissions.ts accountsIn), and the action's service prefix is kept lowercase.
process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "advisor-permacct-test-"));
process.env.NEO4J_URI = "";
const perms = await import("../permissions.js");

test("accountsIn: the caller's ARN, a member connection name, an 'account <id>' in the context; nothing from request ids", () => {
  assert.deepEqual(perms.accountsIn("User: arn:aws:sts::210987654321:assumed-role/aws-advisor-read/aws-advisor is not authorized to perform: s3:ListBucket"), ["210987654321"]);
  assert.deepEqual(perms.accountsIn("advisor_210987654322: operation error SNS: ListTopics, https response error StatusCode: 403, RequestID: 2279f35f-54f8-5da7-9de1-906217139800"), ["210987654322"]);
  assert.deepEqual(perms.accountsIn("s3 usage example-bucket account 210987654322 (s3:ListBucket) arn:aws:iam::210987654321:role/x").sort(), ["210987654321", "210987654322"]);
  assert.deepEqual(perms.accountsIn("compliance foundational_security sns_1"), []);
});

test("explainPermissionError: the SDK's 'operation error SNS: ListTopics' names sns:ListTopics in lowercase, and the issue carries the member account", () => {
  const issue = perms.explainPermissionError("advisor_210987654322: operation error SNS: ListTopics, https response error StatusCode: 403, RequestID: 2279f35f-54f8-5da7-9de1-906217139800, AuthorizationError", "compliance foundational_security foundational_security_sns_1");
  assert.ok(issue); assert.equal(issue.action, "sns:ListTopics"); assert.equal(issue.service, "sns");
  perms.recordPermissionIssue(issue);
  const row = perms.listPermissionIssues().find((r) => r.action === "sns:ListTopics");
  assert.ok(row); assert.deepEqual(row.accounts, ["210987654322"]); assert.deepEqual(row.contexts, ["compliance foundational_security foundational_security_sns_1"]);
  const again = perms.explainPermissionError("User: arn:aws:sts::210987654321:assumed-role/aws-advisor-read/x is not authorized to perform: sns:ListTopics on resource: arn:aws:sns:us-east-1:210987654321:*", "compliance foundational_security foundational_security_sns_2");
  perms.recordPermissionIssue(again!);
  const merged = perms.listPermissionIssues().find((r) => r.action === "sns:ListTopics")!;
  assert.deepEqual(merged.accounts.sort(), ["210987654321", "210987654322"]); assert.equal(merged.count, 2);
  perms.clearPermissionIssues(["sns:ListTopics"]);
  const policy = perms.recommendedPolicy("210987654321");
  const actions = new Set(policy.Statement.flatMap((s) => s.Action));
  // ViewOnlyAccess (attached next to the inline policy) grants sns:List*; the inline policy carries only the Get
  assert.ok(actions.has("sns:GetTopicAttributes"));
  for (const a of ["sns:ListTopics", "sns:ListSubscriptions"]) assert.ok(!actions.has(a), a);
  assert.equal(perms.VIEW_ONLY_POLICY_ARN, "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess");
});

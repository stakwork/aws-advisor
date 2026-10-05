import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

// The read-policy update row (src/actions/read_policy.ts): what identity the policy goes on, what is missing, the size guard and the merge of a fix.
process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "advisor-readpolicy-test-"));
process.env.NEO4J_URI = "";
const rp = await import("../actions/read_policy.js");
const { recommendedPolicy, ACTUATOR_NEEDS, PERSON_ONLY_ACTIONS } = await import("../permissions.js");
const { computeCapabilities } = await import("../executor.js");

test("targetOf: an assumed-role session maps to its role; roles and users with paths; anything else is null", () => {
  assert.deepEqual(rp.targetOf("arn:aws:sts::210987654321:assumed-role/aws-advisor-read/aws-sdk-js-1"), { kind: "role", name: "aws-advisor-read", account_id: "210987654321" });
  assert.deepEqual(rp.targetOf("arn:aws:iam::210987654321:role/service/aws-advisor-read"), { kind: "role", name: "aws-advisor-read", account_id: "210987654321" });
  assert.deepEqual(rp.targetOf("arn:aws:iam::210987654321:user/aws-advisor"), { kind: "user", name: "aws-advisor", account_id: "210987654321" });
  assert.equal(rp.targetOf("arn:aws:iam::210987654321:root"), null);
});

test("missingActions: named or covered by a wildcard counts as granted; the recommended policy against an older one names exactly the new actions", () => {
  const current = { Version: "2012-10-17" as const, Statement: [{ Sid: "Old", Effect: "Allow" as const, Action: ["ec2:Describe*", "s3:ListAllMyBuckets", "iam:ListUsers"], Resource: "*" }] };
  const wanted = { Version: "2012-10-17" as const, Statement: [{ Sid: "Read", Effect: "Allow" as const, Action: ["ec2:DescribeInstances", "s3:ListAllMyBuckets", "sso:ListInstances", "iam:GetRole"], Resource: "*" }, { Sid: "NoWrite", Effect: "Deny" as const, Action: ["iam:PutRolePolicy"], Resource: "*" }] };
  assert.deepEqual(rp.missingActions(current, wanted), ["iam:GetRole", "sso:ListInstances"]);
  assert.deepEqual(rp.missingActions(null, wanted), ["ec2:DescribeInstances", "iam:GetRole", "s3:ListAllMyBuckets", "sso:ListInstances"], "a Deny grants nothing; no policy lacks everything");
  assert.equal(rp.covers("s3:*", "s3:GetObject"), true); assert.equal(rp.covers("s3:Get*", "s3:ListBucket"), false); assert.equal(rp.covers("ec2:DescribeInstances", "ec2:DescribeInstanceStatus"), false);
  const full = recommendedPolicy("210987654321");
  const older = { ...full, Statement: full.Statement.map((s) => ({ ...s, Action: (Array.isArray(s.Action) ? s.Action : [s.Action]).filter((a) => !/^(sso|identitystore|notifications):/.test(a)) })) };
  const missing = rp.missingActions(older, full);
  assert.ok(missing.includes("sso:ListInstances") && missing.includes("notifications:ListManagedNotificationEvents") && missing.includes("identitystore:ListUsers"));
  assert.ok(missing.every((a) => /^(sso|identitystore|notifications):/.test(a)), missing.join(","));
});

test("the recommended policy fits a role's inline limit and not a user's; mergeFix adds only what is missing, under its own Sid", () => {
  const full = recommendedPolicy("210987654321");
  const chars = rp.policyChars(full);
  assert.ok(chars < rp.INLINE_LIMIT.role, `${chars} chars must fit a role's 10,240`);
  assert.ok(chars > rp.INLINE_LIMIT.user, "an IAM user's 2,048 cannot hold it: the row is refused there");
  const current = { Version: "2012-10-17" as const, Statement: [{ Sid: "AdvisorReadOnly", Effect: "Allow" as const, Action: ["ec2:Describe*"], Resource: "*" }] };
  const fix = { Version: "2012-10-17" as const, Statement: [{ Sid: "AdvisorFixSso", Effect: "Allow" as const, Action: ["sso:ListInstances", "ec2:Describe*"], Resource: "*" }, { Sid: "AdvisorFixEmpty", Effect: "Allow" as const, Action: ["ec2:Describe*"], Resource: "*" }] };
  const merged = rp.mergeFix(current, fix);
  assert.equal(merged.Statement.length, 2);
  assert.deepEqual(merged.Statement[1].Action, ["sso:ListInstances"]); assert.equal(merged.Statement[1].Sid, "AdvisorFixSsoFix1");
  assert.deepEqual(current.Statement[0].Action, ["ec2:Describe*"], "the current document is not mutated");
  assert.equal(rp.mergeFix(null, fix).Statement.length, 1);
});

test("the kind is a person's only: its needs are all person-only, so the actuator never has the capability and the pass leaves the row alone", () => {
  const needs = ACTUATOR_NEEDS.read_policy;
  assert.ok(needs);
  for (const a of [...needs.apply, ...needs.revert]) assert.ok(PERSON_ONLY_ACTIONS.has(a), a);
  const cap = computeCapabilities(new Set<string>(), {}).read_policy;
  assert.equal(cap.apply, false, "never the actuator's: the page offers run as me only");
  assert.ok(cap.missing.includes("iam:PutRolePolicy"));
  assert.equal(computeCapabilities(new Set(["ec2:CreateTags"]), {}).consent_tag.apply, null, "a mixed kind keeps the usual verdict");
});

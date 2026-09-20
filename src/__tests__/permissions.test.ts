import assert from "node:assert/strict";
import { test } from "node:test";
import { explainPermissionError, policyForIssues, remedyFor, statementFor, tablesIn } from "../permissions.js";
import { parseExport } from "../powerpipe.js";

test("Steampipe AccessDenied that names the action", () => {
  const msg = "rpc error: code = Unknown desc = operation error Cost Explorer: GetCostAndUsage, https response error StatusCode: 400, RequestID: 6f3e, api error AccessDeniedException: User: arn:aws:iam::123456789012:user/advisor is not authorized to perform: ce:GetCostAndUsage on resource: arn:aws:ce:us-east-1:123456789012:/GetCostAndUsage because no identity-based policy allows the ce:GetCostAndUsage action (SQLSTATE HV000)";
  const issue = explainPermissionError(new Error(msg), "query spend_by_record_type (aws_cost_by_record_type_monthly)");
  assert.ok(issue);
  assert.equal(issue.action, "ce:GetCostAndUsage");
  assert.equal(issue.service, "ce");
  assert.equal(issue.resource, "arn:aws:ce:us-east-1:123456789012:/GetCostAndUsage");
  assert.equal(issue.context, "query spend_by_record_type (aws_cost_by_record_type_monthly)");
  assert.deepEqual(issue.policy_statement, { Sid: "AdvisorCeGetCostAndUsage", Effect: "Allow", Action: ["ce:GetCostAndUsage"], Resource: "*" });
  assert.equal(remedyFor(issue), "Missing IAM permission ce:GetCostAndUsage; add it to the advisor's policy (see Settings > Permissions).");
});

test("UnauthorizedOperation without an action falls back to the table in the context", () => {
  const msg = "rpc error: code = Unknown desc = operation error EC2: DescribeVolumes, https response error StatusCode: 403, RequestID: abc, api error UnauthorizedOperation: You are not authorized to perform this operation. (SQLSTATE HV000)";
  // the SDK prefix names the operation
  const fromPrefix = explainPermissionError(new Error(msg), "watcher ebs (aws_ebs_volume)");
  assert.equal(fromPrefix?.action, "ec2:DescribeVolumes");
  // with no operation in the message at all, the table decides
  const bare = explainPermissionError(new Error("UnauthorizedOperation: You are not authorized to perform this operation."), "inventory ec2 (aws_ec2_instance, aws_ssm_managed_instance)");
  assert.equal(bare?.action, "ec2:DescribeInstances");
  // and a benchmark name is enough for a service-level read wildcard
  const bench = explainPermissionError(new Error("AccessDenied"), "benchmark rds");
  assert.equal(bench?.action, "rds:Describe*");
});

test("SSM SDK AccessDeniedException carries the action in its message; a bare one takes it from the context", () => {
  const e = Object.assign(new Error("User: arn:aws:iam::123456789012:user/advisor is not authorized to perform: ssm:SendCommand on resource: arn:aws:ssm:us-east-1::document/AWS-RunShellScript because no identity-based policy allows the ssm:SendCommand action"), { name: "AccessDeniedException", $fault: "client" });
  const issue = explainPermissionError(e, "ssm SendCommand i-0123456789abcdef0 (ssm:SendCommand)");
  assert.equal(issue?.action, "ssm:SendCommand");
  assert.equal(issue?.resource, "arn:aws:ssm:us-east-1::document/AWS-RunShellScript");
  // The generated fix never grants the stock document, even when the denial was about it: only the custom probe document.
  assert.deepEqual(issue?.policy_statement.Resource, ["arn:aws:ssm:*:*:document/AwsAdvisorProbe", "arn:aws:ec2:*:*:instance/*"]);
  const bare = explainPermissionError(Object.assign(new Error("Access denied"), { name: "AccessDeniedException" }), "ssm GetCommandInvocation i-0123456789abcdef0 (ssm:GetCommandInvocation)");
  assert.equal(bare?.action, "ssm:GetCommandInvocation");
});

test("Cost Explorer 'not authorized' and pricing AccessDenied are recognised", () => {
  const ce = explainPermissionError("User: arn:aws:iam::123456789012:user/x is not authorized to perform: ce:GetCostAndUsageWithResources", "mcp resource_cost_history (aws_cost_by_resource_daily)");
  assert.equal(ce?.action, "ce:GetCostAndUsageWithResources");
  const pricing = explainPermissionError(new Error("operation error Pricing: GetProducts, https response error StatusCode: 400, RequestID: x, api error AccessDeniedException: Access denied"), "price list (aws_pricing_product)");
  assert.equal(pricing?.action, "pricing:GetProducts");
  const deny = explainPermissionError(new Error("AccessDenied: ... with an explicit deny in an identity-based policy"), "mcp steampipe_query (aws_s3_bucket)");
  assert.equal(deny?.action, "s3:ListAllMyBuckets");
});

test("non-permission errors return null", () => {
  assert.equal(explainPermissionError(new Error('relation "advisor.aws_ec2_instance" does not exist'), "query x"), null);
  assert.equal(explainPermissionError(new Error("canceling statement due to statement timeout"), "mcp steampipe_query"), null);
  assert.equal(explainPermissionError(new Error("aws: please provide either owner_id, image_id or image_ids (SQLSTATE HV000)"), "benchmark eks control x"), null);
  // bad credentials are not a missing permission
  assert.equal(explainPermissionError(Object.assign(new Error("The security token included in the request is expired"), { name: "ExpiredTokenException" }), "ssm SendCommand"), null);
  assert.equal(explainPermissionError(null, "x"), null);
});

test("policyForIssues merges by service without duplicates and keeps SendCommand scoped", () => {
  const issues = [
    explainPermissionError("not authorized to perform: ec2:DescribeInstances", "a")!,
    explainPermissionError("not authorized to perform: ec2:DescribeVolumes", "b")!,
    explainPermissionError("not authorized to perform: ec2:DescribeInstances", "c")!,
    explainPermissionError("not authorized to perform: ce:GetCostAndUsage", "d")!,
    explainPermissionError("not authorized to perform: ssm:SendCommand", "e")!,
    { action: "unknown", service: "unknown" },
  ];
  const policy = policyForIssues(issues);
  assert.equal(policy.Version, "2012-10-17");
  assert.deepEqual(policy.Statement.map((s) => s.Sid), ["AdvisorCeRead", "AdvisorEc2Read", "AdvisorSsmSendCommand"]);
  assert.deepEqual(policy.Statement[1], { Sid: "AdvisorEc2Read", Effect: "Allow", Action: ["ec2:DescribeInstances", "ec2:DescribeVolumes"], Resource: "*" });
  assert.deepEqual(policy.Statement[2], statementFor("ssm:SendCommand"));
  assert.deepEqual(policyForIssues([]), { Version: "2012-10-17", Statement: [] });
});

test("tablesIn finds the schema tables in SQL", () => {
  assert.deepEqual(tablesIn("select 1 from advisor.aws_ec2_instance i join advisor.aws_ebs_volume v on true where x in (select 1 from advisor.aws_ec2_instance)"), ["aws_ec2_instance", "aws_ebs_volume"]);
});

test("parseExport surfaces control-level errors and errored results", () => {
  const root = { groups: [{ controls: [
    { control_id: "aws_thrifty.control.a", title: "A", run_status: 8, run_error: "operation error EC2: DescribeInstances, api error UnauthorizedOperation: You are not authorized to perform this operation.", results: [] },
    { control_id: "aws_thrifty.control.b", title: "B", run_status: 4, results: [
      { status: "alarm", resource: "i-1", reason: "idle", dimensions: [{ key: "region", value: "us-east-1" }] },
      { status: "error", resource: "i-2", reason: "CloudWatch metrics not available for i-2." },
      { status: "error", resource: "i-3", reason: "CloudWatch metrics not available for i-3." },
    ] },
  ] }] };
  const parsed = parseExport("ec2", root);
  assert.equal(parsed.findings.length, 3);
  assert.deepEqual(parsed.findings[0].dimensions, { region: "us-east-1" });
  assert.deepEqual(parsed.errors, [
    { controlId: "aws_thrifty.control.a", controlTitle: "A", kind: "run_error", message: "operation error EC2: DescribeInstances, api error UnauthorizedOperation: You are not authorized to perform this operation.", count: 1 },
    { controlId: "aws_thrifty.control.b", controlTitle: "B", kind: "error", message: "CloudWatch metrics not available for i-2.", count: 2 },
  ]);
  assert.equal(explainPermissionError(parsed.errors[0].message, "benchmark ec2 control aws_thrifty.control.a")?.action, "ec2:DescribeInstances");
  assert.equal(explainPermissionError(parsed.errors[1].message, "benchmark ec2 control aws_thrifty.control.b"), null);
});

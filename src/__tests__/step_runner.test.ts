import assert from "node:assert/strict";
import { test } from "node:test";
import { awsReadOnly, clipForNote, execute, parseCommand, runnable } from "../step_runner.js";

test("step runner: the parser yields chains of pipe stages and refuses what a shell would interpret", () => {
  const p = parseCommand(`aws ec2 describe-flow-logs --region us-east-1 --filter Name=resource-id,Values=subnet-1,subnet-2 --query 'FlowLogs[].[FlowLogId,FlowLogStatus]' | head -5`);
  assert.ok(p.ok);
  if (p.ok) {
    assert.equal(p.chains.length, 1);
    assert.deepEqual(p.chains[0].stages[0].slice(0, 4), ["aws", "ec2", "describe-flow-logs", "--region"]);
    assert.equal(p.chains[0].stages[0][8], "FlowLogs[].[FlowLogId,FlowLogStatus]");
    assert.deepEqual(p.chains[0].stages[1], ["head", "-5"]);
  }
  const two = parseCommand("aws s3 ls s3://b/ --recursive && aws sts get-caller-identity ; aws ec2 describe-route-tables --route-table-ids rtb-1");
  assert.ok(two.ok);
  if (two.ok) { assert.equal(two.chains.length, 3); assert.equal(two.chains[0].then, "&&"); assert.equal(two.chains[1].then, ";"); assert.equal(two.chains[2].then, null); }
  const multi = parseCommand("# comment\naws sts get-caller-identity\naws ec2 describe-vpcs\n");
  assert.ok(multi.ok && multi.chains.length === 2);
  const quoted = parseCommand(`aws athena start-query-execution --query-string "SELECT a, b FROM t WHERE x='y' | z"`);
  assert.ok(quoted.ok && quoted.chains[0].stages.length === 1, "a pipe inside quotes is text");
  for (const [cmd, why] of [
    ["aws s3 ls $(cat bucket.txt)", /substitution/],
    ["aws s3 ls `cat bucket.txt`", /backticks/],
    ["aws ec2 describe-vpcs > vpcs.json", /redirection/],
    ["aws ec2 describe-vpcs < in", /redirection/],
    ["aws ec2 describe-vpcs || true", /\|\|/],
    ["aws ec2 describe-vpcs &", /background/],
    ["aws ec2 describe-vpcs ${X}", /substitution/],
    ["aws ec2 describe-vpcs --query 'unbalanced", /quotes/],
  ] as [string, RegExp][]) { const r = parseCommand(cmd); assert.ok(!r.ok && why.test(r.reason), cmd); }
});

test("step runner: only aws read calls pass, s3 only ls, and nothing that hands out secrets or files", () => {
  const ok = ["aws ec2 describe-flow-logs --region us-east-1", "aws --region us-east-1 s3api get-bucket-lifecycle-configuration --bucket b", "aws athena get-query-execution --query-execution-id x", "aws s3 ls s3://b/AWSLogs/ --recursive", "aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=RunInstances", "aws logs filter-log-events --log-group-name g", "aws logs start-query --log-group-name g --query-string 'x'", "aws batch describe-job-definitions --status ACTIVE", "aws ecr describe-images --repository-name r", "aws sts get-caller-identity", "aws ce get-cost-and-usage --time-period Start=2026-09-01,End=2026-09-24 --granularity DAILY --metrics NetUnblendedCost", "aws iam simulate-principal-policy --policy-source-arn a --action-names s3:GetObject"];
  for (const c of ok) assert.equal(awsReadOnly(c.split(" ")).runnable, true, c);
  const no: [string, RegExp][] = [
    ["aws ec2 create-flow-logs --resource-type Subnet", /not a read call/],
    ["aws s3api create-bucket --bucket b", /not a read call/],
    ["aws s3api put-bucket-lifecycle-configuration --bucket b", /not a read call/],
    ["aws athena start-query-execution --query-string x", /not a read call/],
    ["aws ec2 delete-route --route-table-id r", /not a read call/],
    ["aws s3 cp s3://b/k ./k", /only ls/],
    ["aws s3 sync s3://b .", /only ls/],
    ["aws s3api get-object --bucket b --key k out.json", /credentials, secrets or files/],
    ["aws ecr get-login-password --region us-east-1", /credentials, secrets or files/],
    ["aws secretsmanager get-secret-value --secret-id s", /credentials, secrets or files/],
    ["aws ssm get-parameter --name p --with-decryption", /decrypted values|credentials, secrets or files/],
    ["aws ssm get-parameters-by-path --path /prod", /credentials, secrets or files/],
    ["aws sts assume-role --role-arn a --role-session-name s", /credentials, secrets or files/],
    ["aws --profile prod ec2 describe-vpcs", /--profile/],
    ["aws ec2 describe-vpcs --endpoint-url http://x", /--endpoint-url/],
    ["aws ec2 describe-instances --cli-input-json file://in.json", /local file|--cli-input-json/],
    ["docker pull alpine", /only aws/],
    ["kubectl get nodes", /only aws/],
  ];
  for (const [c, why] of no) { const v = awsReadOnly(c.split(" ")); assert.ok(!v.runnable && why.test(v.reason), `${c} → ${v.reason}`); }
});

test("step runner: the verdict for a whole command covers every chain and every filter", () => {
  assert.equal(runnable("aws ec2 describe-flow-logs --region us-east-1 | head -5").runnable, true);
  assert.equal(runnable("aws s3 ls s3://b/ --recursive | grep parquet | wc -l").runnable, true);
  assert.equal(runnable("aws ec2 describe-vpcs && aws ec2 describe-subnets").runnable, true);
  assert.match(runnable("aws ec2 describe-vpcs && aws ec2 create-tags --resources v --tags Key=a,Value=b").reason, /not a read call/);
  assert.match(runnable("aws ec2 describe-vpcs | python3 -c 'print(1)'").reason, /python3 is not a text filter/);
  assert.match(runnable("aws ec2 describe-vpcs | tee out.json").reason, /would write a file/);
  assert.match(runnable("aws ec2 describe-vpcs | sed -i s/a/b/ f").reason, /would write a file/);
  assert.equal(runnable("aws ec2 describe-vpcs | sed -n 1,5p").runnable, true);
  assert.equal(runnable("").runnable, false);
  assert.equal(runnable(undefined).runnable, false);
  // the three verify lines of the NAT study, as the agent wrote them
  assert.equal(runnable("aws s3api get-bucket-lifecycle-configuration --bucket stakwork-vpc-flowlogs-745666712914-us-east-1").runnable, true);
  assert.equal(runnable("aws ec2 describe-flow-logs --region us-east-1 --filter Name=resource-id,Values=subnet-1 --query 'FlowLogs[].[FlowLogId,ResourceId,FlowLogStatus,DeliverLogsStatus]'").runnable, true);
  assert.equal(runnable("aws ec2 describe-route-tables --route-table-ids rtb-0d3e848690a31239d").runnable, true);
});

test("step runner: execution pipes stages, keeps a transcript, and stops an && chain on failure", async () => {
  const env = { PATH: process.env.PATH };
  const p = parseCommand("printf 'b\\na\\nc\\n' | sort | head -2 && printf 'second'");
  assert.ok(p.ok);
  if (p.ok) {
    const r = await execute(p.chains, env);
    assert.equal(r.state, "worked");
    assert.equal(r.exit_code, 0);
    assert.match(r.output, /^\$ printf b\\na\\nc\\n \| sort \| head -2\na\nb\n\$ printf second\nsecond$/);
  }
  const f = parseCommand("false && printf 'never' ; printf 'still'");
  assert.ok(f.ok);
  if (f.ok) {
    const r = await execute(f.chains, env);
    assert.equal(r.state, "failed");
    assert.ok(!r.output.includes("never"), "the && chain stopped");
    assert.ok(!r.output.includes("still"), "a failure ends the run");
    assert.match(r.output, /\(exit 1\)/);
  }
  assert.equal(clipForNote("x".repeat(100), 100).length, 100);
  const clipped = clipForNote("a".repeat(500) + "b".repeat(500), 200);
  assert.ok(clipped.length <= 200 + 60 && clipped.includes("characters left out") && clipped.startsWith("aaa") && clipped.endsWith("bbb"));
});

import { formatRows, verdictFor } from "../step_runner.js";

test("step runner: a valid verify_sql wins over the command; a bad one falls back to the CLI rule", () => {
  const sql = verdictFor({ command: "aws ec2 create-flow-logs --resource-type Subnet", verify_sql: "select flow_log_id, flow_log_status from aws_vpc_flow_log where resource_id = 'subnet-1'" });
  assert.equal(sql.runnable, true); assert.equal(sql.via, "sql"); assert.match(sql.reason, /^steampipe: select flow_log_id/);
  const cli = verdictFor({ command: "aws ec2 describe-flow-logs --region us-east-1" });
  assert.equal(cli.runnable, true); assert.equal(cli.via, "cli");
  const bad = verdictFor({ command: "aws ec2 describe-flow-logs", verify_sql: "delete from aws_vpc_flow_log" });
  assert.equal(bad.via, "cli"); assert.equal(bad.runnable, true, "a bad SQL is ignored and the read-only command still runs");
  const none = verdictFor({ command: "aws s3api create-bucket --bucket b", verify_sql: "drop table x" });
  assert.equal(none.runnable, false); assert.equal(none.via, "cli");
  assert.equal(verdictFor({ verify_sql: "select 1" }).via, "sql");
  assert.equal(verdictFor({}).runnable, false);
});

test("step runner: a query transcript is the SQL, the columns, one JSON row per line and the count", () => {
  const t = formatRows("select a,\n  b from aws_x", ["a", "b"], [{ a: 1, b: "x" }, { a: 2, b: null }]);
  assert.deepEqual(t.split("\n"), ["-- select a, b from aws_x", "-- a, b", '{"a":1,"b":"x"}', '{"a":2,"b":null}', "(2 rows)"]);
  assert.match(formatRows("select 1", ["x"], []), /\(0 rows\)$/);
  assert.match(formatRows("select 1", ["x"], Array.from({ length: 5 }, (_, i) => ({ x: i })), 3), /\(3 of more than 3 rows\)$/);
});

import assert from "node:assert/strict";
import { test } from "node:test";
import { EC2Client, ModifyVolumeCommand } from "@aws-sdk/client-ec2";
import { STSClient } from "@aws-sdk/client-sts";
import { db } from "../db.js";
import { cliLine, iamAction, isReadOperation, kebab, recordCalls } from "../preview.js";
import { consentTagAction } from "../actions/consent_tag.js";
import type { Creds, Proposal } from "../executor.js";

const fake = async () => ({ accessKeyId: "ASIAPREVIEWTEST", secretAccessKey: "x", sessionToken: "y" });
const creds: Creds = { read: fake, act: () => fake, region: "us-east-1", accounts: [], forAccount: () => ({ account_id: "", name: "t", is_parent: true, read: fake, act: () => fake, region: "us-east-1" }) };

test("preview: operation names split into reads and writes, and render as CLI lines and IAM actions", () => {
  for (const op of ["DescribeVolumes", "ListTagsForResource", "GetQueryResults", "HeadBucket", "LookupEvents", "SimulatePrincipalPolicy"]) assert.equal(isReadOperation(op), true, op);
  for (const op of ["ModifyVolume", "CreateTags", "StartQuery", "UpdateEnvironment", "Delete", "Getaway"]) assert.equal(isReadOperation(op), false, op);
  assert.equal(kebab("DBClusterIdentifier"), "db-cluster-identifier");
  assert.equal(kebab("ModifyInstanceCreditSpecification"), "modify-instance-credit-specification");
  assert.equal(cliLine("EC2", "ModifyVolume", { VolumeId: "vol-1", VolumeType: "gp3", Iops: 3000 }, "us-east-1"), "aws ec2 modify-volume --volume-id vol-1 --volume-type gp3 --iops 3000 --region us-east-1");
  assert.equal(cliLine("RDS", "ModifyDBCluster", { DBClusterIdentifier: "c", ApplyImmediately: true }, null), "aws rds modify-db-cluster --db-cluster-identifier c --apply-immediately");
  assert.equal(cliLine("EC2", "CreateTags", { Resources: ["i-1"], Tags: [{ Key: "A", Value: "it's" }] }, "eu-west-1"),
    `aws ec2 create-tags --cli-input-json '{"Resources":["i-1"],"Tags":[{"Key":"A","Value":"it'\\''s"}]}' --region eu-west-1`);
  assert.equal(cliLine("Elastic Beanstalk", "UpdateEnvironment", { EnvironmentId: "e-1" }, null), "aws elasticbeanstalk update-environment --environment-id e-1");
  assert.equal(iamAction("S3", "PutBucketLifecycleConfiguration"), "s3:PutLifecycleConfiguration");
  assert.equal(iamAction("EFS", "PutLifecycleConfiguration"), "elasticfilesystem:PutLifecycleConfiguration");
  assert.equal(iamAction("Elastic Load Balancing v2", "DeleteLoadBalancer"), "elasticloadbalancing:DeleteLoadBalancer");
});

test("preview: every SDK client the actions use shares the one send the hook wraps", async () => {
  const base = Object.getPrototypeOf(STSClient.prototype);
  const pkgs = ["auto-scaling", "cloudtrail", "cloudwatch", "cloudwatch-logs", "dynamodb", "ec2", "ecr", "efs", "elastic-beanstalk", "elastic-load-balancing-v2", "iam", "kms", "lambda", "rds", "route-53", "s3", "ssm"];
  for (const p of pkgs) {
    const mod: Record<string, any> = await import(`@aws-sdk/client-${p}`);
    const client = Object.entries(mod).find(([k, v]) => /Client$/.test(k) && typeof v === "function" && v.prototype?.send)?.[1];
    assert.ok(client, p);
    assert.equal(Object.getPrototypeOf(client.prototype), base, p);
  }
});

test("preview: a write is recorded and never sent", async () => {
  const side = await recordCalls(async () => {
    const ec2 = new EC2Client({ region: "us-east-1", credentials: fake });
    try { await ec2.send(new ModifyVolumeCommand({ VolumeId: "vol-1", VolumeType: "gp3" })); return "ok"; } finally { ec2.destroy(); }
  });
  assert.equal(side.stopped, null);
  assert.equal(side.result, "ok");
  assert.deepEqual(side.writes.map((w) => [w.iam, w.cli]), [["ec2:ModifyVolume", "aws ec2 modify-volume --volume-id vol-1 --volume-type gp3 --region us-east-1"]]);
});

test("preview: the consent tag's own apply comes back as the CreateTags it would send", async () => {
  const p = { kind: "consent_tag", resource: "i-0abc", region: "us-east-1", dedupe: "d", title: "t", reason: "r", before: { AdvisorAutoPark: null }, after: { AdvisorAutoPark: "ON" }, facts: { kind: "ec2", tag: "AdvisorAutoPark" } } as unknown as Proposal;
  const side = await recordCalls(() => consentTagAction.apply(p, creds));
  assert.equal(side.stopped, null);
  assert.equal(side.writes.length, 1);
  assert.equal(side.writes[0].cli, `aws ec2 create-tags --cli-input-json '{"Resources":["i-0abc"],"Tags":[{"Key":"AdvisorAutoPark","Value":"ON"}]}' --region us-east-1`);
  assert.equal(side.writes[0].iam, "ec2:CreateTags");
});

test("preview: local bookkeeping is skipped inside a preview and runs outside it", async () => {
  db.exec("create table if not exists preview_probe (n integer)");
  db.prepare("delete from preview_probe").run();
  const side = await recordCalls(async () => { db.prepare("insert into preview_probe (n) values (1)").run(); return String((db.prepare("select count(*) as c from preview_probe").get() as any).c); });
  assert.equal(side.result, "0");
  assert.deepEqual(side.local, ["insert into preview_probe (n) values (1)"]);
  db.prepare("insert into preview_probe (n) values (2)").run();
  assert.equal((db.prepare("select count(*) as c from preview_probe").get() as any).c, 1);
  db.exec("drop table preview_probe");
});

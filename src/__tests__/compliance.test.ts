import assert from "node:assert/strict";
import { test } from "node:test";
import { Exposure, ScanFinding, cleanTitle, complianceRecommendations, formatScanMessage, itemOf, severityRank, shortId } from "../compliance.js";

const SG = "arn:aws:ec2:eu-west-1:111122223333:security-group/sg-00098653cb824afad";
const I = "arn:aws:ec2:us-east-1:111122223333:instance/i-0f00000000000a002";
const f = (control: string, severity: string | null, resource: string, title = "18 Security groups should only allow unrestricted incoming traffic for authorized ports"): ScanFinding =>
  ({ benchmark: "foundational_security", control_id: `aws_compliance.control.${control}`, control_title: title, severity, resource, reason: "open to the world", region: "eu-west-1", account_id: "111122223333" });
const reach = (exposed: boolean, name: string | null = "Hive"): Exposure => ({ exposed, summary: exposed ? "Reachable: Hive (i-1), public 1.2.3.4." : "none", open_ports: ["22"], instances: [{ id: "i-1", name, public_ip: exposed ? "1.2.3.4" : null, domains: [], ports: [] }] });

test("names: control item, short id, clean title, severity order", () => {
  assert.equal(itemOf("aws_compliance.control.foundational_security_ec2_18"), "ec2_18");
  assert.equal(itemOf("aws_compliance.control.cis_v300_5_2"), "cis_5_2");
  assert.equal(shortId(SG), "sg-00098653cb824afad");
  assert.equal(shortId(I), "i-0f00000000000a002");
  assert.equal(shortId("arn:aws:s3:::bucket"), "arn:aws:s3:::bucket");
  assert.equal(cleanTitle("18 Security groups should"), "Security groups should");
  assert.equal(cleanTitle("1.18 Ensure IAM roles"), "Ensure IAM roles");
  assert.ok(severityRank("critical") < severityRank("high") && severityRank("low") < severityRank(null));
});

test("a curated high control becomes a recommendation only when the resource is reachable", () => {
  const recs = complianceRecommendations([f("foundational_security_ec2_18", "high", SG)], () => reach(true));
  assert.equal(recs.length, 1);
  const r = recs[0];
  assert.equal(r.rule, "sec_ec2_18");
  assert.equal(r.resource, "sg-00098653cb824afad");
  assert.equal(r.actionType, "security_fix");
  assert.equal(r.estMonthlySaving, null);
  assert.equal(r.tier, "approve");
  assert.match(r.rationale, /Reachable: Hive/);
  assert.match(r.rationale, /Open to 0\.0\.0\.0\/0 on 22/);
  assert.deepEqual(complianceRecommendations([f("foundational_security_ec2_18", "high", SG)], () => reach(false)), []);
  assert.deepEqual(complianceRecommendations([f("foundational_security_ec2_18", "high", SG)], () => null), []);
});

test("critical controls always qualify, except the known noise; uncurated high and medium never do", () => {
  const recs = complianceRecommendations([
    f("foundational_security_rds_1", "critical", "arn:aws:rds:us-east-1:111122223333:snapshot:snap-1", "1 RDS snapshots should be private"),
    f("foundational_security_cloudfront_1", "critical", "arn:aws:cloudfront::111122223333:distribution/E1"),
    f("foundational_security_ecs_5", "high", "arn:aws:ecs:us-east-1:111122223333:task-definition/x:1"),
    f("foundational_security_ecr_2", "medium", "arn:aws:ecr:us-east-1:111122223333:repository/x"),
  ], () => { throw new Error("exposure is only looked up for sg and instance controls"); });
  assert.deepEqual(recs.map((r) => r.rule), ["sec_rds_1"]);
  assert.equal(recs[0].title, "RDS snapshots should be private: snap-1");
});

test("account-wide curated controls need no reach; an instance keeps its name; duplicates collapse", () => {
  const recs = complianceRecommendations([
    f("foundational_security_guardduty_1", "high", "arn:aws:::111122223333", "1 GuardDuty should be enabled"),
    f("foundational_security_ec2_8", "high", I, "8 EC2 instances should use IMDSv2"),
    f("foundational_security_ec2_8", "high", I, "8 EC2 instances should use IMDSv2"),
  ], (res) => (res === I ? reach(true, "Sphinx Wordpress") : null));
  assert.deepEqual(recs.map((r) => r.rule), ["sec_guardduty_1", "sec_ec2_8"]);
  assert.equal(recs[1].resource, "i-0f00000000000a002");
  assert.equal(recs[1].resourceName, "Sphinx Wordpress");
  assert.equal(recs[1].title, "EC2 instances should use IMDSv2: Sphinx Wordpress");
});

test("the chat message lists the worst first, caps at eight and links the new findings of the scan", () => {
  const fresh = Array.from({ length: 10 }, (_, i) => ({ ...f("foundational_security_ec2_18", "high", SG), resource: `${SG}${i}` }));
  const m = formatScanMessage(7, fresh, "https://advisor.example");
  assert.match(m.split("\n")[0], /10 new critical\/high findings in scan #7/);
  assert.match(m, /… 2 more/);
  assert.ok(m.endsWith("https://advisor.example/security?scan=7&new=1"));
});

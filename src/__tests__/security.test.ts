import { test } from "node:test";
import assert from "node:assert";
import { safeEqual } from "../auth.js";
import { prepareUserSql } from "../mcp.js";
import { agentRecommendations } from "../agent.js";
import { S } from "../steampipe.js";

test("safeEqual: equal strings only, never empty or non-string", () => {
  assert.ok(safeEqual("abc", "abc"));
  assert.ok(!safeEqual("abc", "abd"));
  assert.ok(!safeEqual("", ""));
  assert.ok(!safeEqual(undefined, "x"));
  assert.ok(!safeEqual(["x"], "x"));
});

test("steampipe_query guard: other connections and admin functions are refused, this schema and aliases pass", () => {
  const ok = prepareUserSql(`select i.instance_id, i.tags from ${S}.aws_ec2_instance i join aws_ebs_volume v on v.attachments::text like '%' || i.instance_id || '%' where i.region = 'us-east-1'`);
  assert.ok("sql" in ok, JSON.stringify(ok));
  assert.match((ok as any).sql, new RegExp(`join ${S}\\.aws_ebs_volume`));
  for (const bad of [
    "select * from aws_parent.aws_iam_user",
    "select * from aws.aws_ssm_parameter",
    "select * from aws_all.aws_ec2_instance",
    "select pg_sleep(30)",
    "select pg_terminate_backend(1)",
    "select pg_read_file('/etc/passwd')",
    "select * from steampipe_internal.steampipe_connection",
  ]) {
    const r = prepareUserSql(bad);
    assert.ok("error" in r, `should refuse: ${bad}`);
  }
});

test("agent recommendations are validated before import: unknown action types, tiers and confidences are normalised, junk is dropped", () => {
  const recs = agentRecommendations({ content: { recommendations: [
    { title: "Stop x", resource: "i-0123456789abcdef0", action_type: "stop_instance", tier: "auto", confidence: 7, est_monthly_saving: -3, rationale: "r" },
    { title: "Weird", resource: "vol-1", action_type: "delete_everything", tier: "yolo", confidence: "high", rationale: "x".repeat(10000) },
    { resource: "no title" },
    "not an object",
  ] } });
  assert.equal(recs.length, 2);
  assert.equal(recs[0].tier, "auto");
  assert.equal(recs[0].confidence, 1);
  assert.equal(recs[0].estMonthlySaving, 0);
  assert.equal(recs[1].actionType, "other");
  assert.equal(recs[1].rule, "agent:other");
  assert.equal(recs[1].tier, "approve");
  assert.equal(recs[1].confidence, 0.5);
  assert.equal(recs[1].rationale.length, 4000);
});

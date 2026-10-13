import assert from "node:assert/strict";
import { test } from "node:test";
import { prepareUserSql } from "../mcp.js";
import { S } from "../steampipe.js";

const ok = (sql: string) => { const r = prepareUserSql(sql); assert.ok("sql" in r, JSON.stringify(r)); return r.sql; };
const bad = (sql: string) => { const r = prepareUserSql(sql); assert.ok("error" in r, `expected rejection for ${sql}`); return r.error; };

test("qualifies bare aws_* tables and leaves qualified ones alone", () => {
  assert.equal(ok("select * from aws_ec2_instance i join aws_ebs_volume v on true"), `select * from ${S}.aws_ec2_instance i join ${S}.aws_ebs_volume v on true`);
  assert.equal(ok(`select 1 from ${S}.aws_vpc_endpoint;`), `select 1 from ${S}.aws_vpc_endpoint`);
  assert.ok("error" in prepareUserSql("select 1 from other.aws_account"), "another connection is refused, not passed through");
  assert.equal(ok("with x as (select 1 from aws_account) select * from x"), `with x as (select 1 from ${S}.aws_account) select * from x`);
});

test("rejects anything that is not a single read-only select", () => {
  assert.match(bad("delete from aws_ec2_instance"), /only SELECT/);
  assert.match(bad("select 1; select 2"), /single statement/);
  assert.match(bad("with x as (select 1) insert into t select * from x"), /insert/);
  assert.match(bad("select * into t from aws_account"), /into/);
  assert.match(bad(""), /empty/);
  // keywords inside literals are fine
  assert.doesNotThrow(() => ok("select 'drop table; insert' as note from aws_account -- update nothing"));
});

test("the vercel connection is readable, qualified like aws_* tables, minus the secret-bearing parts", () => {
  assert.equal(ok("select name, framework from vercel_project"), "select name, framework from vercel.vercel_project");
  ok("select name, sso_protection, password_protection from vercel.vercel_project where live");
  ok("select url, state from vercel.vercel_deployment where state = 'READY'");
  bad("select * from vercel.vercel_project");
  bad("select name, env from vercel_project");
  bad("select * from vercel.vercel_secret");
});

test("the raw-config guard blocks every known way to read environment_variables / template_body / parameters off aws_lambda_function, aws_lambda_version and aws_cloudformation_stack", () => {
  ok("select name, runtime, memory_size from aws_lambda_function"); // explicit columns still work
  ok("select name, status from aws_cloudformation_stack");
  bad("select name, environment_variables from aws_lambda_function");
  bad('select name, "environment_variables" from aws_lambda_function'); // quoted bypass
  bad("select f.* from aws_lambda_function f");
  bad("select * from aws_lambda_function");
  bad("select f from aws_lambda_function f"); // bare alias used as a value
  bad("select to_jsonb(f) from aws_lambda_function f");
  bad("select row_to_json(f) from aws_lambda_function f");
  bad("select json_agg(f) from aws_lambda_function f");
  bad('select * from "aws_lambda_function"'); // quoted table name
  bad("with x as (select f.* from aws_lambda_function f) select * from x");
  bad("select name, environment_variables from aws_lambda_version");
  bad("select name, template_body from aws_cloudformation_stack");
  bad("select name, parameters from aws_cloudformation_stack");
  bad("select * from aws_cloudformation_stack");
});

test("Cost Explorer tables are routed to the parent's connection once members exist; everything else stays on the aggregator", async () => {
  const { routeBillingTables } = await import("../steampipe.js");
  const sql = "select sum(unblended_cost_amount) from advisor.aws_cost_by_account_monthly c join advisor.aws_ec2_instance i on true where exists (select 1 from advisor.aws_cost_usage)";
  // no members: the billing schema is the schema itself and nothing changes
  assert.equal(routeBillingTables(sql, "advisor", "advisor"), sql);
  // members: every aws_cost_* reference moves to the parent's own connection, the inventory table does not
  const routed = routeBillingTables(sql, "advisor", "advisor_p");
  assert.match(routed, /from advisor_p\.aws_cost_by_account_monthly c/);
  assert.match(routed, /from advisor_p\.aws_cost_usage\)/);
  assert.match(routed, /join advisor\.aws_ec2_instance i/);
  // reservations and savings plans are owned per account: not routed
  assert.equal(routeBillingTables("select 1 from advisor.aws_savingsplans_savings_plan", "advisor", "advisor_p"), "select 1 from advisor.aws_savingsplans_savings_plan");
  // another schema's cost table is not ours to touch
  assert.equal(routeBillingTables("select 1 from other.aws_cost_usage", "advisor", "advisor_p"), "select 1 from other.aws_cost_usage");
});

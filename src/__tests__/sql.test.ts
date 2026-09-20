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

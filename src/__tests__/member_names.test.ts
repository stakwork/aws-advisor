import assert from "node:assert/strict";
import { test } from "node:test";

/**
 * Member accounts, phase 2: names that are unique per account only are two rows, not one; what the executor learnt
 * about one account's actuator role stays with that account; a check is pinned to the account's own connection.
 */

test("rekeyByAccount: a table keyed on a name alone becomes keyed on (account_id, name), once, keeping its rows and columns", async () => {
  const { db, rekeyByAccount } = await import("../db.js");
  db.exec("drop table if exists rekey_probe");
  db.exec("create table rekey_probe (name text primary key, region text, stored_bytes real not null default 0, last_seen text not null, first_seen text not null default (datetime('now')))");
  db.prepare("insert into rekey_probe (name, region, stored_bytes, last_seen) values ('a', 'us-east-1', 5, 't')").run();
  assert.equal(rekeyByAccount("rekey_probe", "name"), true, "rebuilt");
  assert.equal(rekeyByAccount("rekey_probe", "name"), false, "already keyed on the pair: left alone");
  const cols = db.pragma("table_info(rekey_probe)") as { name: string; pk: number; notnull: number; dflt_value: string | null }[];
  assert.deepEqual(cols.filter((c) => c.pk).map((c) => c.name).sort(), ["account_id", "name"]);
  assert.equal(cols.find((c) => c.name === "stored_bytes")!.dflt_value, "0", "a column's default is carried over");
  assert.equal(cols.find((c) => c.name === "last_seen")!.notnull, 1, "a not-null constraint is carried over");
  assert.equal(cols.find((c) => c.name === "first_seen")!.dflt_value, "datetime('now')", "a default expression is carried over");
  const legacy = db.prepare("select account_id, region from rekey_probe where name = 'a'").get() as { account_id: string; region: string };
  assert.deepEqual(legacy, { account_id: "", region: "us-east-1" }, "a row from before account ids reads as the primary account's ('')");
  // the same name in two member accounts: two rows, and an upsert on the pair updates the right one
  const up = db.prepare("insert into rekey_probe (account_id, name, region, last_seen) values (?, 'prod-db', ?, 'now') on conflict(account_id, name) do update set region = excluded.region");
  up.run("111111111111", "eu-west-1"); up.run("222222222222", "ap-south-1"); up.run("111111111111", "eu-central-1");
  const rows = db.prepare("select account_id, region from rekey_probe where name = 'prod-db' order by account_id").all();
  assert.deepEqual(rows, [{ account_id: "111111111111", region: "eu-central-1" }, { account_id: "222222222222", region: "ap-south-1" }]);
  db.exec("drop table rekey_probe");
});

test("the four name-keyed inventories are keyed on the account too, and the writers' upserts target the pair", async () => {
  await import("../logs.js"); await import("../lambda_inventory.js"); await import("../inventory.js");
  const { db } = await import("../db.js");
  for (const [table, key] of [["inventory_rds", "db_instance_identifier"], ["inventory_elasticache", "cache_cluster_id"], ["inventory_lambda", "name"], ["log_groups", "name"]] as const) {
    const pk = (db.pragma(`table_info(${table})`) as { name: string; pk: number }[]).filter((c) => c.pk).map((c) => c.name).sort();
    assert.deepEqual(pk, ["account_id", key], `${table} is keyed on (account_id, ${key})`);
  }
  db.prepare("delete from log_groups where name = '/aws/lambda/shared-name'").run();
  const up = db.prepare("insert into log_groups(account_id, name, region, stored_bytes, last_seen) values (?, '/aws/lambda/shared-name', ?, 1, 'now') on conflict(account_id, name) do update set region = excluded.region");
  up.run("111111111111", "us-east-1"); up.run("222222222222", "us-east-1");
  assert.equal((db.prepare("select count(*) as n from log_groups where name = '/aws/lambda/shared-name'").get() as { n: number }).n, 2, "two members, two rows");
  db.prepare("delete from log_groups where name = '/aws/lambda/shared-name'").run();
});

test("accountRank: the asked-for account's row sorts first, '' counts as the primary account's, any row otherwise", async () => {
  const { accountRank } = await import("../scope.js");
  const { db } = await import("../db.js");
  db.exec("drop table if exists rank_probe"); db.exec("create table rank_probe (account_id text, name text)");
  for (const a of ["", "111111111111", "222222222222"]) db.prepare("insert into rank_probe values (?, 'x')").run(a);
  const first = (acct: string | null) => { const r = accountRank(acct); return (db.prepare(`select account_id from rank_probe where name = 'x' order by ${r.sql}, account_id`).get(...r.params) as { account_id: string }).account_id; };
  assert.equal(first("222222222222"), "222222222222");
  assert.equal(first("111111111111"), "111111111111");
  assert.equal(first("333333333333"), "", "unknown account: whatever comes first, deterministically");
  // null = the primary account: its own id (none here) or the legacy '' rows first
  assert.equal(first(null), "");
  db.exec("drop table rank_probe");
});

test("learned denials are kept per account: the old flat store reads as the parent's, a member's denial never blocks the parent", async () => {
  const { denialsByAccount } = await import("../executor.js");
  const fresh = new Date().toISOString();
  const stale = new Date(Date.now() - 2 * 3600_000).toISOString();
  // the store written before member accounts: one flat map of action → denial
  const flat = { "logs:PutRetentionPolicy": { kind: "log_retention", last_seen: fresh, message: "m" }, "ecr:PutLifecyclePolicy": { kind: "ecr_lifecycle", last_seen: stale, message: "old" } };
  assert.deepEqual(denialsByAccount(flat), { "": { "logs:PutRetentionPolicy": flat["logs:PutRetentionPolicy"] } }, "flat store = the parent's; a denial older than an hour is retried");
  // the per-account store
  const byAccount = { "": { "logs:PutRetentionPolicy": flat["logs:PutRetentionPolicy"] }, "222233334444": { "rds:ModifyDBCluster": { kind: "acu_window", last_seen: fresh, message: "member" } } };
  const out = denialsByAccount(byAccount);
  assert.deepEqual(Object.keys(out).sort(), ["", "222233334444"]);
  assert.deepEqual(Object.keys(out[""]), ["logs:PutRetentionPolicy"], "the member's denial is not the parent's");
  assert.deepEqual(Object.keys(out["222233334444"]), ["rds:ModifyDBCluster"]);
  assert.deepEqual(denialsByAccount(null), {}); assert.deepEqual(denialsByAccount("junk"), {});
  // computeCapabilities takes one account's map: the member is blocked, the parent is not
  const { computeCapabilities } = await import("../executor.js");
  assert.equal(computeCapabilities(null, out["222233334444"]).acu_window.apply, false);
  assert.equal(computeCapabilities(null, out[""]).acu_window.apply, null);
});

test("the permission check is pinned to the account's own Steampipe connection", async () => {
  const { connectionSchemaFor } = await import("../permission_check.js");
  assert.equal(connectionSchemaFor("advisor", null, "111111111111", []), "advisor", "no members: the one connection");
  assert.equal(connectionSchemaFor("advisor", "111111111111", "111111111111", []), "advisor");
  assert.equal(connectionSchemaFor("advisor", null, "111111111111", ["222233334444"]), "advisor_p", "with members the schema is an aggregator: the parent is pinned to its own connection");
  assert.equal(connectionSchemaFor("advisor", "111111111111", "111111111111", ["222233334444"]), "advisor_p");
  assert.equal(connectionSchemaFor("advisor", "222233334444", "111111111111", ["222233334444"]), "advisor_222233334444", "a member goes through its own connection");
  assert.equal(connectionSchemaFor("advisor", "999999999999", "111111111111", ["222233334444"]), "advisor_p", "an unknown id is not a member: the parent's (checkTargetFor refuses it)");
});

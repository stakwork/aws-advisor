import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

// IAM users folded from the Steampipe rows (src/iam_inventory.ts) and the explicit parent change with its purge (src/purge.ts).
process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "advisor-iam-test-"));
process.env.NEO4J_URI = "";
const iam = await import("../iam_inventory.js");
const purge = await import("../purge.js");
const { db } = await import("../db.js");
await import("../concepts.js"); await import("../adapters/vercel/inventory.js"); // their tables, for the wipe tests

test("iamUserFrom: console access, MFA, admin by policy or inline wildcard, masked keys with age and last use, groups and policy names", () => {
  const now = Date.parse("2026-10-04T00:00:00Z");
  const u = iam.iamUserFrom({ arn: "arn:aws:iam::210987654321:user/alice", name: "alice", user_id: "AIDAEXAMPLE", account_id: "210987654321", path: "/", create_date: "2025-01-01T00:00:00Z", password_last_used: "2026-09-30T10:00:00Z", mfa_enabled: true, login_profile: { CreateDate: "2025-01-01T00:00:00Z" },
    groups: [{ GroupName: "admins" }], attached_policy_arns: ["arn:aws:iam::aws:policy/AdministratorAccess"], inline_policies: [], permissions_boundary_arn: null, tags: { team: "ops" } },
    [{ access_key_id: "AKIAEXAMPLE0000ABCD", status: "Active", create_date: "2026-01-01T00:00:00Z", access_key_last_used_date: "2026-10-01T00:00:00Z", access_key_last_used_service: "s3", access_key_last_used_region: "us-east-1" }, { access_key_id: "AKIAEXAMPLE0000WXYZ", status: "Inactive", create_date: "2024-01-01T00:00:00Z" }], now);
  assert.equal(u.console_access, true); assert.equal(u.mfa_enabled, true); assert.equal(u.admin, true); assert.deepEqual(u.groups, ["admins"]); assert.deepEqual(u.attached_policies, ["AdministratorAccess"]);
  assert.equal(u.keys_active, 1); assert.equal(u.oldest_key_days, 276); assert.equal(u.access_keys[0].id, "AKIA…ABCD"); assert.equal(u.access_keys[0].service, "s3"); assert.equal(u.last_used, "2026-10-01T00:00:00Z");
  assert.ok(!JSON.stringify(u).includes("AKIAEXAMPLE0000ABCD"), "the full key id never survives");
  const svc = iam.iamUserFrom({ arn: "arn:aws:iam::210987654321:user/ci", name: "ci", account_id: "210987654321", mfa_enabled: false, login_profile: null, attached_policy_arns: [], inline_policies: [{ PolicyName: "all", PolicyDocument: { Statement: [{ Effect: "Allow", Action: "*", Resource: "*" }] } }] }, [], now);
  assert.equal(svc.console_access, false); assert.equal(svc.admin, true, "an inline Allow * on * is admin"); assert.deepEqual(svc.inline_policies, ["all"]); assert.equal(svc.last_used, null);
  assert.equal(iam.isAdmin(["arn:aws:iam::aws:policy/ReadOnlyAccess"], []), false);
});

test("the inventory lists and summarises users per account, and the graph node carries the identity properties", async () => {
  const now = new Date().toISOString();
  const ins = db.prepare(`insert into inventory_iam_user(arn, name, user_id, account_id, path, created, password_last_used, console_access, mfa_enabled, groups, attached_policies, inline_policies, admin, access_keys, keys_active, oldest_key_days, last_used, tags, first_seen, last_seen, gone)
    values (?, ?, null, ?, '/', '2025-01-01T00:00:00Z', ?, ?, ?, '[]', ?, '[]', ?, ?, ?, ?, ?, '{}', ?, ?, 0)`);
  ins.run("arn:aws:iam::210987654321:user/alice", "alice", "210987654321", "2026-09-30T00:00:00Z", 1, 0, '["ReadOnlyAccess"]', 0, '[{"id":"AKIA…ABCD","status":"Active","age_days":200}]', 1, 200, "2026-09-30T00:00:00Z", now, now);
  ins.run("arn:aws:iam::210987654322:user/bob", "bob", "210987654322", null, 0, 0, '["AdministratorAccess"]', 1, "[]", 0, null, null, now, now);
  assert.equal(iam.listIamUsers().length, 2);
  assert.deepEqual(iam.listIamUsers({ scope: { id: "210987654322", primary: false } }).map((u) => u.name), ["bob"]);
  const sum = iam.iamSummary({ id: "210987654321", primary: true });
  assert.deepEqual(sum, { users: 1, console_without_mfa: 1, admins: 0, keys_active: 1, keys_over_90d: 1, unused_90d: 0 });
  const { resourceFromIamUser } = await import("../adapters/aws/resources.js");
  const node = resourceFromIamUser(iam.listIamUsers({ q: "alice" }).map((u) => ({ ...u, groups: JSON.stringify(u.groups), attached_policies: JSON.stringify(u.attached_policies), inline_policies: JSON.stringify(u.inline_policies), access_keys: JSON.stringify(u.access_keys), tags: JSON.stringify(u.tags) }))[0]);
  assert.equal(node.label, "AdvisorIdentity"); assert.equal(node.native_type, "iam_user"); assert.equal(node.props.kind, "user"); assert.equal(node.props.human, true); assert.equal(node.props.mfa, false); assert.equal(node.props.credentials, 1); assert.equal(node.props.credential_age_days, 200);
});

test("a parent change is recorded, previewed and purged explicitly; the new account's rows stay", async () => {
  assert.equal(purge.noteAccountChange("210987654321", "210987654321"), null, "same account: nothing pending");
  const c = purge.noteAccountChange("210987654321", "210987654399")!;
  assert.deepEqual([c.from, c.to], ["210987654321", "210987654399"]); assert.deepEqual(purge.pendingAccountChange()?.from, "210987654321");
  // rows of the old account across a few tables, and one recommendation attributed through the inventory
  const cols = (db.prepare("pragma table_info(inventory_ec2)").all() as any[]).filter((c) => c.notnull && c.dflt_value == null).map((c) => c.name);
  const row = (id: string, acct: string) => { const v: Record<string, unknown> = { instance_id: id, account_id: acct, name: id, state: "running", instance_type: "t3.micro", region: "us-east-1", first_seen: "now", last_seen: "now", gone: 0, snapshot: "{}" }; for (const c of cols) if (!(c in v)) v[c] = c.endsWith("_at") || c.endsWith("_seen") ? "now" : typeof c === "string" && /count|pct|gb|usd|days|hours/.test(c) ? 0 : ""; return v; };
  const put = (v: Record<string, unknown>) => db.prepare(`insert into inventory_ec2(${Object.keys(v).join(",")}) values (${Object.keys(v).map((k) => `@${k}`).join(",")})`).run(v);
  put(row("i-0aaa000000000001", "210987654321")); put(row("i-0bbb000000000002", "210987654399"));
  const run = Number(db.prepare("insert into runs(trigger, status, account_id, provider) values ('test', 'completed', '210987654321', 'aws')").run().lastInsertRowid);
  db.prepare("insert into findings(run_id, source, control_id, status, resource, account_id, fingerprint) values (?, 'test', 'c', 'alarm', 'i-0aaa000000000001', '210987654321', 'c:i-0aaa000000000001')").run(run);
  db.prepare("insert into recommendations(fingerprint, run_id, rule, title, resource, action_type) values ('r:i-0aaa000000000001', ?, 'r', 't', 'i-0aaa000000000001', 'stop')").run(run);
  db.prepare("insert into recommendations(fingerprint, run_id, rule, title, resource, action_type) values ('r:i-0bbb000000000002', ?, 'r', 't', 'i-0bbb000000000002', 'stop')").run(run);
  const preview = purge.purgePreview("210987654321");
  assert.equal(preview.tables.inventory_ec2, 1); assert.equal(preview.tables.runs, 1); assert.equal(preview.attributed.recommendations, 1);
  const r = await purge.purgeAccountData("210987654321", { graph: false });
  assert.equal(r.tables.inventory_ec2, 1); assert.equal(r.attributed.recommendations, 1);
  assert.equal((db.prepare("select count(*) as n from inventory_ec2").get() as any).n, 1, "the new account's row stays");
  assert.equal((db.prepare("select count(*) as n from recommendations").get() as any).n, 1);
  assert.equal((db.prepare("select count(*) as n from findings").get() as any).n, 0, "the old run's findings went with it");
  assert.equal(purge.pendingAccountChange(), null, "purging the old account closes the pending change");
  await assert.rejects(() => purge.purgeAccountData("nope"), /12-digit/);
});

test("a parent change stamps the rows that carried no account with the previous parent, so they do not become the new parent's", async () => {
  const cols = (db.prepare("pragma table_info(inventory_ec2)").all() as any[]).filter((c) => c.notnull && c.dflt_value == null).map((c) => c.name);
  const v: Record<string, unknown> = { instance_id: "i-0ccc000000000003", account_id: "", name: "legacy", state: "stopped", instance_type: "t3.micro", region: "us-east-1", first_seen: "now", last_seen: "now", gone: 1, snapshot: "{}" };
  for (const c of cols) if (!(c in v)) v[c] = c.endsWith("_at") || c.endsWith("_seen") ? "now" : /count|pct|gb|usd|days|hours/.test(c) ? 0 : "";
  db.prepare(`insert into inventory_ec2(${Object.keys(v).join(",")}) values (${Object.keys(v).map((k) => `@${k}`).join(",")})`).run(v);
  purge.noteAccountChange("210987654399", "210987654400");
  assert.equal((db.prepare("select account_id from inventory_ec2 where instance_id = 'i-0ccc000000000003'").get() as any).account_id, "210987654399");
  purge.dismissAccountChange();
});

test("scopedStmt narrows a summary query to the account: on its gone clause, with the table alias, after a bare where, or as the only condition", async () => {
  const { scopedStmt } = await import("../scope.js");
  const member = { id: "210987654399", primary: false };
  // the instance rows from the purge test above: one of 210987654399 left, none of the others
  assert.equal((scopedStmt(member, "select count(*) as n from inventory_ec2 where gone = 0").get() as any).n, 1);
  assert.equal((scopedStmt({ id: "210987654321", primary: true }, "select count(*) as n from inventory_ec2 where gone = 0").get() as any).n, 0);
  assert.equal((scopedStmt(null, "select count(*) as n from inventory_ec2 where gone = 0").get() as any).n, 1, "every account when the scope is null");
  assert.equal((scopedStmt(member, "select count(*) as n from inventory_ec2 v left join inventory_ec2 e on e.instance_id = v.instance_id where v.gone = 0").get() as any).n, 1, "the alias carries into the account column");
  assert.equal((scopedStmt(member, "select count(*) as n from inventory_ec2 where state = 'running'").get() as any).n, 1, "a where without gone");
  assert.equal((scopedStmt(member, "select count(*) as n from inventory_ec2").get() as any).n, 2, "no where at all: the live row and the stamped legacy one");
  assert.equal((scopedStmt({ id: "000000000000", primary: false }, "select count(*) as n from inventory_ec2").get() as any).n, 0);
});

test("rows that name a resource get the account they were made for, and rowInScope reads it first", async () => {
  const { rowInScope, stampRowAccounts } = await import("../scope.js");
  db.prepare("insert into recommendations(fingerprint, run_id, rule, title, resource, action_type) values ('x:i-0bbb000000000002', 0, 'x', 't', 'i-0bbb000000000002', 'stop')").run();
  db.prepare("insert into alerts(kind, resource, message, details) values ('vercel_test', 'prj_zzz', 'm', ?)").run(JSON.stringify({ team_id: "team_example999" }));
  db.prepare("insert into alerts(kind, resource, message, details) values ('quota', null, 'quota hit', '{}')").run();
  assert.ok(stampRowAccounts("recommendations") >= 1); assert.ok(stampRowAccounts("alerts") >= 1);
  assert.equal((db.prepare("select account_id from recommendations where fingerprint = 'x:i-0bbb000000000002'").get() as any).account_id, "210987654399", "from the inventory's id");
  assert.equal((db.prepare("select account_id from alerts where kind = 'vercel_test'").get() as any).account_id, "team_example999", "from the details a platform pass wrote");
  assert.equal((db.prepare("select account_id from alerts where kind = 'quota'").get() as any).account_id, null, "nothing to attribute: stays empty, the primary's");
  const member = rowInScope({ id: "210987654399", primary: false }); const primary = rowInScope({ id: "210987654321", primary: true });
  assert.equal(member({ account_id: "210987654399", resource: null }), true); assert.equal(primary({ account_id: "210987654399", resource: null }), false);
  assert.equal(primary({ account_id: null, resource: null }), true, "an unattributed row reads as the primary's"); assert.equal(member({ account_id: null, resource: null }), false);
  assert.equal(rowInScope(null)({ account_id: "whatever" }), true);
});

test("the full wipe clears collected data and state, keeps configuration, reference data and playbooks, and the Concepts when asked", async () => {
  const { setSetting, getSetting } = await import("../db.js");
  db.prepare("insert into inventory_ec2(instance_id, name, instance_type, state, region, account_id, first_seen, last_seen, gone, snapshot) values ('i-0ffffffffffffff01', 'box', 't3.micro', 'running', 'us-east-1', '210987654321', 'x', 'x', 0, '{}')").run();
  db.prepare("insert into alerts(kind, resource, message, details) values ('instance_state', 'i-0ffffffffffffff01', 'm', '{}')").run();
  db.prepare("insert into concepts(fingerprint, concept_id, status) values ('fp-1', 'c-1', 'ok')").run();
  db.prepare("insert into playbooks(control_id, title, meaning, act_when, ignore_when, steps, saving, references_, gaps, confidence, tier, effort, judged, sources, generated_at, generated_by) values ('x.test', 't', 'm', 'a', 'i', '[]', 's', '[]', '[]', 0.9, 'act', 'low', 'j', '[]', 'now', 'test')").run();
  setSetting("cfg:agentRunsPerDay", "120"); setSetting("inventory_refreshed_at", "2026-10-04"); setSetting("vercel_billing:team_test", "{}"); setSetting("accounts", "[]");
  const preview = purge.wipePreview(true);
  assert.equal(preview.tables.inventory_ec2 >= 1, true); assert.equal(preview.tables.concepts, undefined, "concepts are not listed when kept"); assert.ok(preview.kept.includes("playbooks") && preview.kept.includes("concepts"));
  const r = await purge.wipeAllData({ preserveConcepts: true, graph: false });
  assert.ok(r.tables.inventory_ec2 >= 1 && r.tables.alerts >= 1);
  assert.equal((db.prepare("select count(*) as n from inventory_ec2").get() as any).n, 0);
  assert.equal((db.prepare("select count(*) as n from concepts").get() as any).n, 1, "Concepts kept");
  assert.equal((db.prepare("select count(*) as n from playbooks where control_id = 'x.test'").get() as any).n, 1, "playbooks kept");
  assert.equal(getSetting("cfg:agentRunsPerDay"), "120"); assert.equal(getSetting("accounts"), "[]");
  assert.equal(getSetting("inventory_refreshed_at") || null, null, "collection state cleared"); assert.equal(getSetting("vercel_billing:team_test") || null, null);
  assert.ok(r.settings >= 2);
  await purge.wipeAllData({ preserveConcepts: false, graph: false });
  assert.equal((db.prepare("select count(*) as n from concepts").get() as any).n, 0, "Concepts cleared when not preserved");
});

test("a Vercel team is a purge target: its tables by team id, its attributed rows, its runs", async () => {
  db.prepare("insert into vercel_team(id, slug, name, plan, personal, fetched_at) values ('team_test01', 'slug', 'Test', 'pro', 0, 'now')").run();
  db.prepare("insert into vercel_projects(id, team_id, name, first_seen, last_seen) values ('prj_1', 'team_test01', 'site', 'now', 'now')").run();
  db.prepare("insert into runs(started_at, status, provider, account_id) values ('now', 'completed', 'vercel', 'team_test01')").run();
  const runId = (db.prepare("select max(id) as id from runs").get() as any).id;
  db.prepare("insert into recommendations(fingerprint, run_id, rule, title, action_type, resource, status, account_id) values ('fp-v-1', ?, 'vercel_x', 'r', 'review', 'prj_1', 'open', 'team_test01')").run(runId);
  const pv = purge.purgePreview("team_test01");
  assert.equal(pv.tables.vercel_projects, 1); assert.equal(pv.attributed.recommendations, 1);
  const r = await purge.purgeAccountData("team_test01", { graph: false });
  assert.equal(r.tables.vercel_team, 1); assert.equal(r.tables.vercel_projects, 1); assert.equal(r.attributed.recommendations, 1); assert.equal(r.tables.runs, 1);
  await assert.rejects(() => purge.purgeAccountData("nonsense", { graph: false }), /12-digit AWS account id or a Vercel team id/);
});

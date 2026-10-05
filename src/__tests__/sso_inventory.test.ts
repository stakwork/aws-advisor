import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

// IAM Identity Center folded from the SDK answers (src/sso_inventory.ts): assignments through groups, sign-ins from the trail, the role name of a permission set, the summary and the graph node.
process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "advisor-sso-test-"));
process.env.NEO4J_URI = "";
const sso = await import("../sso_inventory.js");
const { resourceFromSsoUser } = await import("../adapters/aws/resources.js");
const { db } = await import("../db.js");

const PS_ADMIN = "arn:aws:sso:::permissionSet/ssoins-0000example/ps-admin0000000001";
const PS_RO = "arn:aws:sso:::permissionSet/ssoins-0000example/ps-readonly0000001";

test("userAssignments: direct first, then through each group with the group named; duplicates folded; names resolved", () => {
  const names = new Map([[PS_ADMIN, "AdministratorAccess"], [PS_RO, "ReadOnly"]]);
  const groups = new Map([["ops", [{ AccountId: "210987654321", PermissionSetArn: PS_ADMIN }, { AccountId: "210987654322", PermissionSetArn: PS_RO }]], ["everyone", [{ AccountId: "210987654322", PermissionSetArn: PS_RO }]]]);
  const a = sso.userAssignments([{ AccountId: "210987654321", PermissionSetArn: PS_RO }], ["ops", "everyone"], groups, names);
  assert.deepEqual(a.map((x) => `${x.account_id} ${x.permission_set} ${x.via}`), ["210987654321 AdministratorAccess group ops", "210987654321 ReadOnly direct", "210987654322 ReadOnly group everyone", "210987654322 ReadOnly group ops"]);
  assert.deepEqual(sso.userAssignments([{ AccountId: "210987654321", PermissionSetArn: "arn:aws:sso:::permissionSet/x/ps-unknown" }], [], new Map(), names)[0].permission_set, "ps-unknown", "an unknown ARN keeps its last segment");
});

test("permissionSetOfRole and isAdminPermissionSet", () => {
  assert.equal(sso.permissionSetOfRole("AWSReservedSSO_AdministratorAccess_0123456789abcdef"), "AdministratorAccess");
  assert.equal(sso.permissionSetOfRole("AWSReservedSSO_Read_Only_0123456789abcdef"), "Read_Only");
  assert.equal(sso.permissionSetOfRole("aws-advisor-read"), null);
  assert.equal(sso.isAdminPermissionSet(["arn:aws:iam::aws:policy/AdministratorAccess"], null), true);
  assert.equal(sso.isAdminPermissionSet([], JSON.stringify({ Statement: [{ Effect: "Allow", Action: "*", Resource: "*" }] })), true);
  assert.equal(sso.isAdminPermissionSet(["arn:aws:iam::aws:policy/ReadOnlyAccess"], JSON.stringify({ Statement: [{ Effect: "Allow", Action: "s3:Get*", Resource: "*" }] })), false);
});

test("foldSignIns: matched by name or identity store id, the newest success is the last sign-in, 30-day counts split success and failure", () => {
  const now = Date.parse("2026-10-04T12:00:00Z");
  const users = [{ user_id: "u-alice", user_name: "Alice" }, { user_id: "u-bob", user_name: "bob" }];
  const facts = sso.foldSignIns([
    { name: "Authenticate", time: "2026-10-01T09:00:00Z", username: "alice", detail: { userIdentity: { type: "Unknown", userName: "alice" } } },
    { name: "Authenticate", time: "2026-10-03T09:00:00Z", username: null, detail: { userIdentity: { type: "Unknown", userName: "alice" }, errorCode: "AccessDenied" } },
    { name: "Federate", time: "2026-10-02T09:00:00Z", username: null, detail: { userIdentity: { type: "Unknown", onBehalfOf: { userId: "u-alice" } } } },
    { name: "UserAuthentication", time: "2026-08-01T09:00:00Z", username: null, detail: { userIdentity: { principalId: "u-bob" }, serviceEventDetails: { UserAuthentication: "Success" } } },
    { name: "ListApplications", time: "2026-10-03T10:00:00Z", username: "alice", detail: {} },
    { name: "Authenticate", time: "2026-10-03T10:00:00Z", username: "nobody", detail: { userIdentity: { userName: "nobody" } } },
  ], users, now);
  assert.deepEqual(facts.get("u-alice"), { last_sign_in: "2026-10-02T09:00:00Z", sign_ins_30d: 1, failed_30d: 1 }, "a failed Authenticate never moves the last sign-in; Federate does");
  assert.deepEqual(facts.get("u-bob"), { last_sign_in: "2026-08-01T09:00:00Z", sign_ins_30d: 0, failed_30d: 0 }, "older than 30 days: seen, not counted");
  assert.equal(facts.has("nobody"), false);
});

test("the inventory lists users per scope, summarises them, and the graph node carries the identity properties", () => {
  const now = new Date().toISOString();
  const ins = db.prepare(`insert into inventory_sso_user(user_id, identity_store_id, instance_arn, account_id, user_name, display_name, email, idp, groups, assignments, accounts, permission_sets, applications, admin, last_sign_in, sign_ins_30d, failed_30d, activity, first_seen, last_seen, gone)
    values (?, 'd-0000example', 'arn:aws:sso:::instance/ssoins-0000example', '210987654321', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`);
  const a = [{ account_id: "210987654321", permission_set: "AdministratorAccess", permission_set_arn: PS_ADMIN, via: "group ops" }, { account_id: "210987654322", permission_set: "ReadOnly", permission_set_arn: PS_RO, via: "direct" }];
  ins.run("u-alice", "alice", "Alice Example", "alice@example.com", "https://idp.example.com", JSON.stringify(["ops"]), JSON.stringify(a), 2, 2, JSON.stringify(["Grafana"]), 1, "2026-10-01T09:00:00Z", 3, 1, JSON.stringify({ "210987654322": "2026-10-02T08:00:00Z" }), now, now);
  ins.run("u-bob", "bob", null, null, null, "[]", JSON.stringify([a[1]]), 1, 1, "[]", 0, null, 0, 0, "{}", now, now);
  db.prepare(`insert into inventory_sso_permission_set(arn, instance_arn, account_id, name, description, session_duration, created, managed_policies, customer_managed, inline_policy, boundary, admin, accounts, last_used, users, first_seen, last_seen, gone)
    values (?, 'arn:aws:sso:::instance/ssoins-0000example', '210987654321', 'AdministratorAccess', null, 'PT8H', null, '["AdministratorAccess"]', '[]', null, null, 1, '["210987654321"]', '{"210987654321":"2026-10-01T00:00:00Z"}', 1, ?, ?, 0)`).run(PS_ADMIN, now, now);
  db.prepare("insert or replace into settings(key, value) values ('sso_meta', ?)").run(JSON.stringify({ configured: true, region: "us-east-1", owner_account_id: "210987654321", read_at: now, errors: [], notes: [] }));

  const all = sso.listSsoUsers();
  assert.deepEqual(all.map((u) => u.user_name), ["alice", "bob"], "administrators first");
  assert.equal(all[0].assignments.length, 2); assert.equal(all[0].admin, true); assert.deepEqual(all[0].applications, ["Grafana"]);
  assert.deepEqual(sso.listSsoUsers({ scope: { id: "210987654322", primary: false } }).map((u) => u.user_name), ["alice", "bob"], "both reach the member");
  assert.deepEqual(sso.listSsoUsers({ scope: { id: "210987654321", primary: false } }).map((u) => u.user_name), ["alice"], "only alice reaches the parent");
  assert.deepEqual(sso.listSsoPermissionSets({ scope: { id: "210987654322", primary: false } }), [], "the set is provisioned to the parent alone");
  const s = sso.ssoSummary();
  assert.equal(s.configured, true); assert.equal(s.users, 2); assert.equal(s.admins, 1); assert.equal(s.never_signed_in, 1); assert.equal(s.external, 1); assert.equal(s.accounts, 2); assert.equal(s.permission_sets, 1); assert.equal(s.admin_sets, 1); assert.equal(s.sign_ins_30d, 3); assert.equal(s.failed_30d, 1);

  const row = db.prepare("select * from inventory_sso_user where user_id = 'u-alice'").get() as any;
  const n = resourceFromSsoUser(row);
  assert.equal(n.label, "AdvisorIdentity"); assert.equal(n.native_type, "sso_user"); assert.equal(n.id, "u-alice"); assert.equal(n.name, "alice"); assert.equal(n.state, "available");
  assert.equal(n.props.kind, "user"); assert.equal(n.props.human, true); assert.equal(n.props.mfa, null); assert.equal(n.props.admin, true); assert.equal(n.props.last_used_at, "2026-10-01T09:00:00Z");
  assert.deepEqual(n.props.policies, ["AdministratorAccess", "ReadOnly"]); assert.deepEqual(n.props.accounts, ["210987654321", "210987654322"]); assert.deepEqual(n.props.assignments, ["210987654321 AdministratorAccess (group ops)", "210987654322 ReadOnly (direct)"]);
  assert.deepEqual(n.props.activity, ["210987654322 2026-10-02T08:00"]);
});

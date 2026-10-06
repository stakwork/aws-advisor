import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

// Who can get in (src/sign_ins.ts, src/sign_in_facts.ts): user agents as client and platform, sign-in and write events as fingerprints, the fold per actor, the credential report, the readers and the graph nodes.
process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "advisor-signins-test-"));
process.env.NEO4J_URI = "";
const f = await import("../sign_in_facts.js");
const s = await import("../sign_ins.js");
const { resourceFromRootUser, resourceFromIamUser, resourceFromSsoUser } = await import("../adapters/aws/resources.js");
const { db } = await import("../db.js");
await import("../trail.js");

const ACCT = "111122223333";
const MAC_CHROME = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36";
const IPHONE_SAFARI = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1";
const CLI_MAC = "aws-cli/2.17.0 md/awscrt#0.20.11 ua/2.0 os/macos#24.0.0 md/arch#arm64 lang/python#3.11.9 md/pyimpl#CPython cfg/retry-mode#standard md/installer#exe md/command#s3.cp";

test("parseUserAgent: browsers, the CLI, SDKs, infrastructure tools, AWS itself", () => {
  assert.deepEqual(f.parseUserAgent(MAC_CHROME), { client: "Chrome", platform: "macOS", channel: "console" });
  assert.deepEqual(f.parseUserAgent(IPHONE_SAFARI), { client: "Safari", platform: "iOS", channel: "console" });
  assert.deepEqual(f.parseUserAgent(CLI_MAC), { client: "aws-cli", platform: "macOS", channel: "cli" });
  assert.deepEqual(f.parseUserAgent("aws-cli/2.17.0 ua/2.0 os/linux#6.1 exec-env/CloudShell md/command#ec2.describe-instances"), { client: "aws-cli", platform: "CloudShell", channel: "cli" });
  assert.deepEqual(f.parseUserAgent("APN/1.0 HashiCorp/1.0 Terraform/1.9.5 (+https://www.terraform.io) terraform-provider-aws/5.70.0 aws-sdk-go-v2/1.30 os/linux"), { client: "Terraform", platform: "Linux", channel: "iac" });
  assert.deepEqual(f.parseUserAgent("aws-sdk-js/3.600.0 ua/2.1 os/linux#5.10 lang/js md/nodejs#20.15 exec-env/AWS_Lambda_nodejs20.x api/s3#3.600.0"), { client: "AWS SDK (js)", platform: "AWS Lambda", channel: "sdk" });
  assert.deepEqual(f.parseUserAgent("Boto3/1.35.0 md/Botocore#1.35.0 ua/2.0 os/windows#10 md/arch#amd64 lang/python#3.12"), { client: "boto3", platform: "Windows", channel: "sdk" });
  assert.equal(f.parseUserAgent("console.amazonaws.com").channel, "console");
  assert.equal(f.parseUserAgent("AWS Internal").channel, "aws");
  assert.equal(f.parseUserAgent("ec2.amazonaws.com").channel, "aws");
  assert.equal(f.parseUserAgent("Jersey/${project.version} (HttpUrlConnection 17.0.20.1)").channel, "aws", "the access portal federating into the console");
  assert.equal(f.parseUserAgent(null).channel, "unknown");
});

test("mfaTypeOf and factorOfCredentialType: device kinds", () => {
  assert.equal(f.mfaTypeOf(`arn:aws:iam::${ACCT}:mfa/phone`), "app");
  assert.equal(f.mfaTypeOf(`arn:aws:iam::${ACCT}:u2f/user/alice/default-AAAAEXAMPLE`), "passkey");
  assert.equal(f.mfaTypeOf("GAHT12345678"), "hardware");
  assert.equal(f.mfaTypeOf(null), null);
  assert.equal(f.factorOfCredentialType("PASSWORD"), "password");
  assert.equal(f.factorOfCredentialType("TOTP"), "app");
  assert.equal(f.factorOfCredentialType("WEBAUTHN"), "passkey");
  assert.equal(f.factorOfCredentialType(""), null);
});

const ev = (name: string, detail: any, id = `${name}-${Math.random()}`, time = new Date().toISOString()) => ({ id, name, time, region: "us-east-1", account_id: ACCT, detail });

test("signInFromEvent: a root console sign-in with a passkey, an IAM user without MFA, a failure, an SSO federated login", () => {
  const root = f.signInFromEvent(ev("ConsoleLogin", { userIdentity: { type: "Root", accountId: ACCT, arn: `arn:aws:iam::${ACCT}:root` }, userAgent: MAC_CHROME, sourceIPAddress: "192.0.2.10", responseElements: { ConsoleLogin: "Success" }, additionalEventData: { MFAUsed: "Yes", MFAIdentifier: `arn:aws:iam::${ACCT}:u2f/root/root-key-AAAAEXAMPLE` } }))!;
  assert.equal(root.actor_type, "root"); assert.equal(root.actor_id, `arn:aws:iam::${ACCT}:root`); assert.equal(root.factor, "passkey"); assert.equal(root.platform, "macOS"); assert.equal(root.failed, false); assert.equal(root.source_ip, "192.0.2.10");
  const bob = f.signInFromEvent(ev("ConsoleLogin", { userIdentity: { type: "IAMUser", userName: "bob", arn: `arn:aws:iam::${ACCT}:user/bob` }, userAgent: IPHONE_SAFARI, responseElements: { ConsoleLogin: "Success" }, additionalEventData: { MFAUsed: "No" } }))!;
  assert.equal(bob.actor, "bob"); assert.equal(bob.factor, "password"); assert.equal(bob.platform, "iOS");
  const failed = f.signInFromEvent(ev("ConsoleLogin", { userIdentity: { type: "IAMUser", userName: "bob" }, userAgent: MAC_CHROME, responseElements: { ConsoleLogin: "Failure" }, errorMessage: "Failed authentication" }))!;
  assert.equal(failed.failed, true);
  const sso = f.signInFromEvent(ev("ConsoleLogin", { userIdentity: { type: "AssumedRole", arn: `arn:aws:sts::${ACCT}:assumed-role/AWSReservedSSO_Admin_0123456789abcdef/alice` }, userAgent: MAC_CHROME, responseElements: { ConsoleLogin: "Success" } }))!;
  assert.equal(sso.actor_type, "sso_user"); assert.equal(sso.actor, "alice"); assert.equal(sso.factor, "federated");
});

test("signInFromEvent: Identity Center credential checks, aws sso login, unknown events", () => {
  const names = new Map([["9067-user-0001", "alice"]]);
  const totp = f.signInFromEvent(ev("CredentialVerification", { userIdentity: { type: "Unknown", onBehalfOf: { userId: "9067-user-0001" } }, userAgent: IPHONE_SAFARI, additionalEventData: { CredentialType: "TOTP" }, serviceEventDetails: { CredentialVerification: "Success" } }), names)!;
  assert.equal(totp.actor, "alice"); assert.equal(totp.factor, "app"); assert.equal(totp.channel, "portal"); assert.equal(totp.failed, false);
  const bad = f.signInFromEvent(ev("CredentialVerification", { userIdentity: { type: "Unknown", userName: "alice" }, userAgent: MAC_CHROME, additionalEventData: { CredentialType: "PASSWORD" }, serviceEventDetails: { CredentialVerification: "Failure" } }), names)!;
  assert.equal(bad.failed, true);
  const cli = f.signInFromEvent(ev("GetRoleCredentials", { userIdentity: { type: "Unknown", userName: "alice" }, userAgent: CLI_MAC, requestParameters: { accountId: "444455556666", roleName: "Admin" } }), names)!;
  assert.equal(cli.channel, "cli"); assert.equal(cli.platform, "macOS"); assert.equal(cli.factor, "sso"); assert.equal(cli.target, "444455556666 Admin");
  assert.equal(f.signInFromEvent(ev("DescribeInstances", { userIdentity: { type: "Root" } })), null);
  assert.equal(f.signInFromEvent(ev("GetRoleCredentials", { userIdentity: { type: "Unknown" }, userAgent: CLI_MAC })), null);
});

const write = (o: Partial<Parameters<typeof f.signInFromWrite>[0]>) => ({ event_id: `w-${Math.random()}`, account_id: ACCT, region: "us-east-1", event_time: new Date().toISOString(), event_name: "PutObject", username: null, user_agent: CLI_MAC, source_ip: "198.51.100.7", identity_type: "IAMUser", principal_arn: null, key_kind: "AKIA", key_tail: "WXYZ", error_code: null, ...o });

test("signInFromWrite: a long-lived key on a Mac, a console session, an SSO session; roles and AWS itself left out", () => {
  const key = f.signInFromWrite(write({ username: "deploy" }))!;
  assert.equal(key.actor, "deploy"); assert.equal(key.factor, "access_key"); assert.equal(key.target, "key …WXYZ"); assert.equal(key.platform, "macOS");
  assert.equal(f.signInFromWrite(write({ username: "bob", user_agent: MAC_CHROME, key_kind: "ASIA" }))!.factor, "console_session");
  const sso = f.signInFromWrite(write({ identity_type: "AssumedRole", principal_arn: `arn:aws:sts::${ACCT}:assumed-role/AWSReservedSSO_Admin_0123456789abcdef/alice`, key_kind: "ASIA" }))!;
  assert.equal(sso.actor_type, "sso_user"); assert.equal(sso.factor, "sso");
  assert.equal(f.signInFromWrite(write({ identity_type: "AssumedRole", principal_arn: `arn:aws:sts::${ACCT}:assumed-role/app-role/i-0123456789abcdef0` })), null);
  assert.equal(f.signInFromWrite(write({ user_agent: "AWS Internal" })), null);
  assert.equal(f.signInFromWrite(write({ user_agent: null })), null);
});

test("foldClients: one entry per client, factors from successes only, newest first, keys collected", () => {
  const t = (d: number) => new Date(Date.UTC(2026, 8, d)).toISOString();
  const base = { account_id: ACCT, region: "us-east-1", source: "signin" as const, actor_type: "sso_user" as const, actor: "alice", actor_id: null, target: null, source_ip: null };
  const out = f.foldClients([
    { ...base, event_id: "1", event_time: t(1), event_name: "CredentialVerification", channel: "portal", client: "Safari", platform: "iOS", factor: "password", failed: false },
    { ...base, event_id: "2", event_time: t(1), event_name: "CredentialVerification", channel: "portal", client: "Safari", platform: "iOS", factor: "app", failed: false },
    { ...base, event_id: "3", event_time: t(2), event_name: "CredentialVerification", channel: "portal", client: "Safari", platform: "iOS", factor: "passkey", failed: true },
    { ...base, event_id: "4", event_time: t(5), event_name: "GetRoleCredentials", source: "sso", channel: "cli", client: "aws-cli", platform: "macOS", factor: "sso", failed: false, source_ip: "203.0.113.5" },
  ]);
  const alice = out.get(f.actorKey("sso_user", "Alice", null))!;
  assert.equal(alice.length, 2);
  assert.equal(alice[0].client, "aws-cli"); assert.equal(alice[0].last_ip, "203.0.113.5");
  assert.deepEqual(alice[1].factors, ["password", "app"]); assert.equal(alice[1].events, 3); assert.equal(alice[1].failures, 1);
  assert.equal(f.strongestMfa(alice), "app");
  assert.match(f.clientLine(alice[1]), /^Safari on iOS · portal · password \+ authenticator app · 3× \(1 failed\) · last 2026-09-02/);
});

test("iamUserMfa: registered devices first, sign-ins second, none when neither", () => {
  assert.deepEqual(f.iamUserMfa(["app", "passkey"], true, []), { mfa: "passkey", mfa_source: "device" });
  assert.deepEqual(f.iamUserMfa([], false, [{ factors: ["app"] } as any]), { mfa: "app", mfa_source: "sign-in" });
  assert.deepEqual(f.iamUserMfa([], false, []), { mfa: "none", mfa_source: "device" });
});

test("rootFromCredentialReport: the root row's last uses, N/A ignored", () => {
  const csv = [
    "user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date",
    `<root_account>,arn:aws:iam::${ACCT}:root,2020-01-01T00:00:00+00:00,not_supported,2026-09-20T10:00:00+00:00,not_supported,not_supported,true,true,2021-01-01T00:00:00+00:00,2026-08-01T00:00:00+00:00,us-east-1,s3,false,N/A,N/A`,
    `bob,arn:aws:iam::${ACCT}:user/bob,2022-01-01T00:00:00+00:00,true,no_information,N/A,N/A,false,false,N/A,N/A,N/A,N/A,false,N/A,N/A`,
  ].join("\n");
  assert.deepEqual(f.rootFromCredentialReport(csv), { password_last_used: "2026-09-20T10:00:00+00:00", key_last_used: "2026-08-01T00:00:00+00:00", mfa_active: true, keys_active: 1 });
  assert.equal(f.rootFromCredentialReport("user,arn\n"), null);
});

test("readers and graph nodes: the root row, the fold onto identities, the summary", () => {
  const now = new Date().toISOString();
  db.prepare("insert into inventory_root_user(account_id, arn, mfa_enabled, mfa_kind, access_keys, first_seen, last_seen) values (?, ?, 1, 'passkey_or_hardware', 0, ?, ?)").run(ACCT, `arn:aws:iam::${ACCT}:root`, now, now);
  db.prepare(`insert into inventory_iam_user(arn, name, account_id, console_access, mfa_enabled, mfa_types, keys_active, first_seen, last_seen) values (?, 'deploy', ?, 0, 0, '[]', 1, ?, ?)`).run(`arn:aws:iam::${ACCT}:user/deploy`, ACCT, now, now);
  db.prepare(`insert into inventory_sso_user(user_id, identity_store_id, account_id, user_name, first_seen, last_seen) values ('9067-user-0001', 'd-0000example', ?, 'alice', ?, ?)`).run(ACCT, now, now);
  const ins = db.prepare(`insert into sign_in_events(event_id, account_id, region, event_time, event_name, source, actor_type, actor, actor_id, channel, client, platform, factor, failed, source_ip, target, fetched_at) values (?, ?, 'us-east-1', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, '192.0.2.1', null, ?)`);
  ins.run("e1", ACCT, now, "ConsoleLogin", "signin", "root", "root", `arn:aws:iam::${ACCT}:root`, "console", "Chrome", "macOS", "passkey", now);
  ins.run("e2", ACCT, now, "CredentialVerification", "signin", "sso_user", "alice", null, "portal", "Safari", "iOS", "app", now);
  db.prepare(`insert into trail_events(event_id, event_time, event_name, event_source, username, region, fetched_at, account_id, user_agent, identity_type, key_kind, key_tail) values ('t1', ?, 'PutObject', 's3.amazonaws.com', 'deploy', 'us-east-1', ?, ?, ?, 'IAMUser', 'AKIA', 'WXYZ')`).run(now, now, ACCT, CLI_MAC);
  s.foldOntoIdentities();

  const [root] = s.listRootUsers();
  assert.equal(root.mfa_kind, "passkey", "a passkey sign-in narrows passkey_or_hardware");
  const actors = s.listActors();
  assert.equal(actors.find((a) => a.kind === "sso_user")!.mfa, "app");
  assert.equal(actors.find((a) => a.kind === "iam_user")!.clients[0].keys[0], "WXYZ");
  const sum = s.accessSummary(null, actors);
  assert.equal(sum.accounts, 1); assert.equal(sum.roots_without_mfa, 0); assert.equal(sum.keys_on_desktops, 1); assert.equal(sum.people_app_only, 1);

  const rootNode = resourceFromRootUser(db.prepare("select * from inventory_root_user").get());
  assert.equal(rootNode.label, "AdvisorIdentity"); assert.equal(rootNode.native_type, "root_user"); assert.equal(rootNode.props.mfa_type, "passkey"); assert.deepEqual(rootNode.props.platforms, ["macOS"]);
  const ssoNode = resourceFromSsoUser(db.prepare("select * from inventory_sso_user").get());
  assert.equal(ssoNode.props.mfa, true); assert.equal(ssoNode.props.mfa_type, "app");
  const iamNode = resourceFromIamUser(db.prepare("select * from inventory_iam_user").get());
  assert.deepEqual(iamNode.props.factors, ["access_key"]); assert.match((iamNode.props.sign_in_clients as string[])[0], /^aws-cli on macOS · cli · access key \(…WXYZ\)/);
});

test("groupPeople: an IAM user and an Identity Center user of one name are one person; machines and roots apart", () => {
  const ids = [
    { kind: "sso_user", id: "u1", name: "gonzalo@example.com", email: "gonzalo@example.com", display_name: "Gonzalo Example", console: true },
    { kind: "iam_user", id: `arn:aws:iam::${ACCT}:user/gonzalo`, name: "gonzalo", console: true },
    { kind: "iam_user", id: "arn:aws:iam::444455556666:user/Gonzalo", name: "Gonzalo", console: false },
    { kind: "iam_user", id: `arn:aws:iam::${ACCT}:user/ci-deploy`, name: "ci-deploy", console: false },
    { kind: "sso_user", id: "u2", name: "pat@example.com", email: "pat@example.com", display_name: "Pat Example", console: true },
    { kind: "root", id: `arn:aws:iam::${ACCT}:root`, name: "root", console: true },
  ];
  const g = f.groupPeople(ids);
  assert.equal(g.length, 3, "gonzalo ×3, ci-deploy, pat; root left out");
  const gonzalo = g.find((x) => x.identities.length === 3)!;
  assert.equal(gonzalo.identities[0].kind, "sso_user", "the Identity Center user leads");
  assert.deepEqual(gonzalo.matched_by, ["gonzalo"]);
  assert.equal(g.find((x) => x.identities[0].name === "ci-deploy")!.machine, true);
  assert.equal(f.nameKey("Gonzalo.Example@example.com"), "gonzaloexample");
  assert.equal(f.nameKey("ab"), null, "too short to match on");
});

test("workflowMfa: one sign-in per workflow id, counted with MFA when any of its challenges was a second factor", () => {
  assert.deepEqual(f.workflowMfa([
    { workflow: "w1", factor: "password", failed: false }, { workflow: "w1", factor: "app", failed: false },
    { workflow: "w2", factor: "password", failed: false },
    { workflow: "w3", factor: "password", failed: true },
    { workflow: null, factor: "app", failed: false },
  ]), { sign_ins: 2, with_mfa: 1 });
});

test("signInFromEvent: the workflow id, and GetRoleCredentials from a browser is the access portal", () => {
  const c = f.signInFromEvent(ev("CredentialChallenge", { userIdentity: { type: "IdentityCenterUser" }, userAgent: MAC_CHROME, additionalEventData: { UserName: "alice", CredentialType: "PASSWORD", AuthWorkflowID: "wf-0001" }, serviceEventDetails: { CredentialChallenge: "Success" } }))!;
  assert.equal(c.actor, "alice"); assert.equal(c.workflow, "wf-0001");
  const portal = f.signInFromEvent(ev("GetRoleCredentials", { userIdentity: { type: "Unknown", userName: "alice" }, userAgent: MAC_CHROME }))!;
  assert.equal(portal.channel, "portal");
});

test("listActors and listPeople: a disabled Identity Center user is disabled, an IAM user with no console and no key has no way in", () => {
  db.prepare(`insert into inventory_sso_user(user_id, identity_store_id, account_id, user_name, status, first_seen, last_seen) values ('9067-user-0002', 'd-0000example', ?, 'gone-person@example.com', 'DISABLED', datetime('now'), datetime('now'))`).run(ACCT);
  db.prepare(`insert into inventory_iam_user(arn, name, account_id, console_access, mfa_enabled, mfa_types, keys_active, first_seen, last_seen) values (?, 'old-bot', ?, 0, 0, '[]', 0, datetime('now'), datetime('now'))`).run(`arn:aws:iam::${ACCT}:user/old-bot`, ACCT);
  const actors = s.listActors();
  assert.equal(actors.find((a) => a.name === "gone-person@example.com")!.status, "disabled");
  assert.equal(actors.find((a) => a.name === "old-bot")!.status, "no_access");
  const people = s.listPeople(actors);
  assert.equal(people.at(-1)!.status, "disabled", "disabled people sort last");
  assert.ok(s.accessSummary(null, actors).disabled >= 2);
});

test("directoryChange: an MFA device removed by an admin's session, reads dropped, unknown names humanised", () => {
  const names = new Map([["9067-user-0003", "pat@example.com"]]);
  const c = f.directoryChange({ id: "d1", name: "DeleteMfaDeviceForUser", time: "2026-09-14T16:36:08Z", detail: { userIdentity: { type: "AssumedRole", arn: `arn:aws:sts::${ACCT}:assumed-role/AWSReservedSSO_Admin_0123456789abcdef/alice@example.com` }, requestParameters: { user: { directoryId: "d-0000example", userId: "9067-user-0003" }, deviceId: "m-0000example" } } }, names)!;
  assert.equal(c.what, "MFA device removed"); assert.equal(c.target_name, "pat@example.com"); assert.equal(c.by, "alice@example.com"); assert.equal(c.failed, false);
  assert.equal(f.directoryChange({ id: "d2", name: "ListMfaDevicesForUser", time: "2026-10-05T00:00:00Z", detail: {} }), null);
  assert.equal(f.directoryChange({ id: "d3", name: "SomeNewThing", time: "2026-10-05T00:00:00Z", detail: {} })!.what, "some new thing");
});

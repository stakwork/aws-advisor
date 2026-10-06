import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

// Credentials, clients and source addresses as graph rows (src/graph_access.ts), and the per-address fold (src/sign_in_facts.ts).
process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "advisor-access-graph-test-"));
process.env.NEO4J_URI = "";
const g = await import("../graph_access.js");
const f = await import("../sign_in_facts.js");

const ACCT = "111122223333";
const now = "2026-10-05T12:00:00.000Z";
const client = (o: Partial<any>) => ({ account_id: ACCT, channel: "cli", client: "aws-cli", platform: "macOS", factors: [], events: 1, failures: 0, first_at: now, last_at: now, last_ip: null, keys: [], via: ["api"], ...o });
const actor = (o: Partial<any>) => ({ email: null, display_name: null, account_id: ACCT, admin: false, console: true, keys: 0, mfa: "unknown", mfa_source: null, last_seen_at: null, clients: [], sign_ins_90d: null, mfa_sign_ins_90d: null, status: "active", changes: [], ...o });

test("accessGraphRows: an IAM user's password, MFA device and key, each tied to the client it was used from", () => {
  const arn = `arn:aws:iam::${ACCT}:user/deploy`;
  const a = actor({ kind: "iam_user", id: arn, name: "deploy", keys: 1, mfa: "passkey", clients: [client({ factors: ["access_key"], keys: ["WXYZ"], events: 40 }), client({ channel: "console", client: "Chrome", factors: ["password", "passkey"], events: 3, via: ["sign-in"] })] });
  const x = { iam: new Map([[arn, { console: true, password_last_used: now, mfa_devices: [{ serial: `arn:aws:iam::${ACCT}:u2f/user/deploy/key-EXAMPLE`, kind: "passkey" as const, enabled_at: now }], access_keys: [{ id: "AKIA…WXYZ", status: "Active", created: now, last_used: now, service: "s3", region: "us-east-1", age_days: 3 }] }]]),
    root: new Map(), removed: [], tokens: [], ips: new Map([[arn, [{ ip: "198.51.100.7", events: 43, failures: 0, first_at: now, last_at: now, clients: ["aws-cli|macOS|cli"], accounts: [ACCT] }]]]) };
  const r = g.accessGraphRows([a as any], x);
  assert.deepEqual(r.credentials.map((c) => [c.kind, c.state]), [["password", "active"], ["passkey", "active"], ["access_key", "active"]]);
  assert.deepEqual(r.clients.map((c) => c.id).sort(), ["client:Chrome|macOS|console", "client:aws-cli|macOS|cli"]);
  const used = new Map(r.used_from.map((u) => [`${u.credential_id}>${u.client_id}`, u.events]));
  assert.equal(used.get(`${arn}#key:AKIA…WXYZ>client:aws-cli|macOS|cli`), 40, "the key is used from the CLI on macOS");
  assert.equal(used.get(`${arn}#password>client:Chrome|macOS|console`), 3);
  assert.equal(used.get(`arn:aws:iam::${ACCT}:u2f/user/deploy/key-EXAMPLE>client:Chrome|macOS|console`), 3);
  assert.deepEqual(r.ips.map((i) => [i.ip, i.private, i.events]), [["198.51.100.7", false, 43]]);
});

test("accessGraphRows: Identity Center factors are observed, a removed device is its own credential; Vercel 2FA and tokens", () => {
  const sso = actor({ kind: "sso_user", id: "9067-user-0001", name: "pat@example.com", clients: [client({ channel: "portal", client: "Safari", platform: "iOS", factors: ["password", "app"], via: ["sign-in"] })] });
  const member = actor({ kind: "vercel_member", id: "team_example/member/pat", name: "pat", mfa: "mfa", tokens: [{}] });
  const x = { iam: new Map(), root: new Map(), removed: [{ user_id: "9067-user-0001", device_id: "m-0000example", at: now, by: "admin@example.com" }],
    tokens: [{ member_id: "team_example/member/pat", id: "tok1", name: "ci", created_at: now, active_at: now, expires_at: null }], ips: new Map() };
  const r = g.accessGraphRows([sso as any, member as any], x);
  const by = new Map(r.credentials.map((c) => [c.id, c]));
  assert.equal(by.get("9067-user-0001#factor:app")!.observed, true);
  assert.equal(by.get("9067-user-0001#mfa:m-0000example")!.state, "removed"); assert.equal(by.get("9067-user-0001#mfa:m-0000example")!.removed_by, "admin@example.com");
  assert.equal(by.get("team_example/member/pat#2fa")!.provider, "vercel");
  assert.equal(by.get("team_example/token/tok1")!.kind, "api_token"); assert.equal(by.get("team_example/token/tok1")!.expires_at, null);
  assert.ok(r.used_from.some((u) => u.credential_id === "9067-user-0001#factor:app" && u.client_id === "client:Safari|iOS|portal"));
});

test("foldIps and isIpAddress: addresses per actor with their clients; service names and private ranges told apart", () => {
  const base = { account_id: ACCT, region: "us-east-1", source: "signin" as const, actor_type: "iam_user" as const, actor: "deploy", actor_id: null, target: null, event_name: "ConsoleLogin", factor: "password" as const };
  const m = f.foldIps([
    { ...base, event_id: "1", event_time: "2026-10-01T00:00:00Z", channel: "console", client: "Chrome", platform: "macOS", failed: false, source_ip: "203.0.113.5" },
    { ...base, event_id: "2", event_time: "2026-10-02T00:00:00Z", channel: "cli", client: "aws-cli", platform: "macOS", failed: true, source_ip: "203.0.113.5" },
    { ...base, event_id: "3", event_time: "2026-10-03T00:00:00Z", channel: "aws", client: "AWS service", platform: null, failed: false, source_ip: "ec2.amazonaws.com" },
  ]);
  const u = m.get(f.actorKey("iam_user", "deploy", ACCT))!;
  assert.equal(u.length, 1); assert.equal(u[0].events, 2); assert.equal(u[0].failures, 1); assert.deepEqual(u[0].clients, ["Chrome|macOS|console", "aws-cli|macOS|cli"]);
  assert.equal(f.isIpAddress("2001:db8::1"), true); assert.equal(f.isIpAddress("ec2.amazonaws.com"), false);
  assert.equal(f.isPrivateIp("10.0.0.5"), true); assert.equal(f.isPrivateIp("172.20.1.1"), true); assert.equal(f.isPrivateIp("198.51.100.7"), false);
});

test("personRows: one person across providers, keyed on the Identity Center user so a new identity keeps the id", async () => {
  const s = await import("../sign_ins.js");
  const sso = actor({ kind: "sso_user", id: "9067-user-0001", name: "pat.lee@example.com", display_name: "Pat Lee", email: "pat.lee@example.com", mfa: "app" });
  const iam = actor({ kind: "iam_user", id: `arn:aws:iam::${ACCT}:user/patlee`, name: "patlee", mfa: "none", keys: 1 });
  const bot = actor({ kind: "iam_user", id: `arn:aws:iam::${ACCT}:user/ci-deploy`, name: "ci-deploy", console: false, keys: 1 });
  const root = actor({ kind: "root", id: `arn:aws:iam::${ACCT}:root`, name: "root" });
  const alone = g.personRows(s.listPeople([sso as any]));
  const r = g.personRows(s.listPeople([sso, iam, bot, root] as any[]));
  assert.equal(r.persons.length, 2, "root users have no person");
  const pat = r.persons.find((p) => !p.machine)!;
  assert.equal(pat.id, alone.persons[0].id, "the IAM user joining does not move the id");
  assert.equal(pat.id, "person:patlee");
  assert.deepEqual([pat.identities, pat.mfa, pat.keys, pat.name], [2, "none", 1, "Pat Lee"]);
  assert.deepEqual(r.links.filter((l) => l.person_id === pat.id).map((l) => l.kind).sort(), ["iam_user", "sso_user"]);
  const machine = r.persons.find((p) => p.machine)!;
  assert.deepEqual([machine.id, machine.identities], ["person:cideploy", 1]);
});

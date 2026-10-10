import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { generateKeyPairSync, createVerify } from "node:crypto";
import { test } from "node:test";

// The GitHub adapter: the App's JWT and installation token, Link pagination, a refresh through a fake API where some
// sections are refused, the people as identities and actors (joined to a Vercel-style display name), the
// credentials, the rules (2FA, empty seats, write deploy keys, tokens without expiry, AWS keys in secrets) and the bill.
process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "advisor-github-test-"));
process.env.TYPESAFE_API_KEY = ""; process.env.REPO2GRAPH_URL = "";
const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048, privateKeyEncoding: { type: "pkcs1", format: "pem" }, publicKeyEncoding: { type: "spki", format: "pem" } });
process.env.GITHUB_ORG = "example-org"; process.env.GITHUB_APP_ID = "12345"; process.env.GITHUB_INSTALLATION_ID = "67890"; process.env.GITHUB_APP_PRIVATE_KEY = privateKey;

const client = await import("../adapters/github/client.js");
const inv = await import("../adapters/github/inventory.js");
const ad = await import("../adapters/github/index.js");
const rules = await import("../adapters/github/rules.js");
const changes = await import("../adapters/github/changes.js");
const actors = await import("../adapters/github/actors.js");
const reg = await import("../adapters/index.js");

const SSH = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl user@example.com";
const now = Date.now(); const daysAgo = (d: number) => new Date(now - d * 86_400_000).toISOString();
const ym = new Date().toISOString().slice(0, 7);

/** A fake api.github.com: routes by path; a few sections refuse the way GitHub does. */
function fakeGitHub() {
  const calls: string[] = [];
  const json = (body: unknown, headers: Record<string, string> = {}, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
  const f = async (input: any, init?: any) => {
    const u = new URL(String(input)); const p = u.pathname; calls.push(`${init?.method ?? "GET"} ${p}${u.search}`);
    if (p === "/app/installations/67890/access_tokens") { const jwt = String(init.headers.authorization).replace(/^Bearer /, ""); const [h, b, s] = jwt.split("."); const ok = createVerify("RSA-SHA256").update(`${h}.${b}`).verify(publicKey, Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64")); return ok ? json({ token: "ghs_test", expires_at: new Date(now + 3_600_000).toISOString() }) : json({ message: "bad jwt" }, {}, 401); }
    assert.equal(init.headers.authorization, "Bearer ghs_test");
    const o = "/orgs/example-org";
    if (p === o) return json({ id: 1, node_id: "O_test1", login: "example-org", name: "Example", plan: { name: "enterprise", seats: 29, filled_seats: 20, private_repos: 999999 }, two_factor_requirement_enabled: false, default_repository_permission: "read", created_at: "2020-01-01T00:00:00Z" });
    if (p === `${o}/members`) {
      if (u.searchParams.get("filter") === "2fa_disabled") return json([{ login: "bob-dev" }]);
      if (u.searchParams.get("role") === "admin") return json([{ login: "alice-ops", id: 11 }]);
      // two pages, joined by the Link header
      if (u.searchParams.get("page") === "2") return json([{ login: "carol", id: 13 }]);
      return json([{ login: "alice-ops", id: 11 }, { login: "bob-dev", id: 12 }], { link: `<https://api.github.com${o}/members?role=all&page=2>; rel="next"` });
    }
    if (p === `${o}/outside_collaborators`) return json(u.searchParams.get("filter") ? [] : [{ login: "dave-contractor", id: 14 }]);
    if (p.startsWith("/users/") && p.endsWith("/keys")) return json(p.includes("alice-ops") ? [{ id: 1, key: SSH }] : []);
    if (p.startsWith("/users/")) { const l = p.split("/")[2]; return json({ login: l, id: 1, name: l === "alice-ops" ? "Alice Example" : null, email: l === "alice-ops" ? "alice.example@example.com" : null, created_at: "2019-01-01T00:00:00Z" }); }
    if (p === `${o}/invitations`) return json([{ id: 5, login: "erin", email: null, role: "direct_member", created_at: daysAgo(10), inviter: { login: "alice-ops" } }]);
    if (p === `${o}/failed_invitations`) return json([]);
    if (p === `${o}/teams`) return json([{ id: 1, slug: "platform", name: "Platform", privacy: "closed" }]);
    if (p === `${o}/teams/platform/members`) return json(u.searchParams.get("role") === "maintainer" ? [{ login: "alice-ops" }] : [{ login: "alice-ops" }, { login: "carol" }]);
    if (p === `${o}/teams/platform/repos`) return json([{ full_name: "example-org/api", permissions: { admin: false, maintain: false, push: true, triage: true, pull: true } }]);
    if (p === `${o}/repos`) return json([{ id: 1, node_id: "R_1", name: "api", full_name: "example-org/api", private: true, visibility: "private", archived: false, fork: false, default_branch: "main", pushed_at: daysAgo(1), created_at: "2021-01-01T00:00:00Z", html_url: "https://github.com/example-org/api" }]);
    if (p === "/repos/example-org/api/collaborators") return json([{ login: "dave-contractor", permissions: { admin: true, push: true, pull: true }, role_name: "admin" }]);
    if (p === "/repos/example-org/api/keys") return json([{ id: 9, key: SSH, title: "deploy-bot", read_only: false, verified: true, added_by: "alice-ops", created_at: daysAgo(200), last_used: daysAgo(120), enabled: true }]);
    if (p === "/repos/example-org/api/actions/secrets") return json({ total_count: 1, secrets: [{ name: "AWS_ACCESS_KEY_ID", created_at: daysAgo(300), updated_at: daysAgo(300) }] });
    if (p === "/repos/example-org/api/environments") return json({ environments: [{ name: "production" }] });
    if (p === "/repos/example-org/api/environments/production/secrets") return json({ secrets: [{ name: "DB_PASSWORD", created_at: daysAgo(30), updated_at: daysAgo(30) }] });
    if (p === "/repos/example-org/api/hooks" || p === `${o}/hooks`) return json([]);
    if (p === `${o}/personal-access-tokens`) return json([{ id: 3, owner: { login: "bob-dev" }, repository_selection: "all", permissions: { repository: { contents: "write" } }, access_granted_at: daysAgo(100), token_id: 33, token_name: "ci", token_expired: false, token_expires_at: null, token_last_used_at: daysAgo(2) }]);
    if (p === `${o}/personal-access-token-requests`) return json([]);
    if (p === `${o}/credential-authorizations`) return json({ message: "Not Found" }, {}, 404);
    if (p === `${o}/installations`) return json({ total_count: 1, installations: [{ id: 67890, app_id: 12345, app_slug: "cloud-advisor-read", repository_selection: "all", permissions: { members: "read", metadata: "read" }, events: [], created_at: daysAgo(1) }] });
    if (p === `${o}/actions/secrets`) return json({ secrets: [] });
    if (p === `${o}/dependabot/secrets`) return json({ secrets: [] });
    if (p === `${o}/copilot/billing`) return json({ message: "Resource not accessible by integration" }, {}, 403);
    if (p === `${o}/audit-log`) return json([{ "@timestamp": now - 3_600_000, _document_id: "d1", action: "git.push", actor: "alice-ops", repo: "example-org/api", user_agent: "git/2.39.3 (Apple Git-145)" }, { "@timestamp": now - 7_200_000, _document_id: "d2", action: "repo.access", actor: "bob-dev", programmatic_access_type: "Fine-grained personal access token", hashed_token: "abc=" }]);
    if (p === "/organizations/example-org/settings/billing/usage") return json({ usageItems: Number(u.searchParams.get("month")) === new Date().getUTCMonth() + 1 ? [{ date: `${ym}-01T00:00:00Z`, product: "actions", sku: "actions_linux", quantity: 1000, unitType: "minutes", pricePerUnit: 0.008, grossAmount: 8, discountAmount: 8, netAmount: 0 }, { date: `${ym}-01T00:00:00Z`, product: "packages", sku: "packages_storage", quantity: 10, unitType: "GigabyteHours", pricePerUnit: 0.25, grossAmount: 2.5, discountAmount: 0, netAmount: 2.5 }] : [] });
    return json({ message: `no fake for ${p}` }, {}, 404);
  };
  return { f: f as typeof fetch, calls };
}

test("a private key squeezed onto one line is rebuilt; the JWT verifies with the public key", () => {
  const oneLine = privateKey.replace(/\n/g, " ");
  assert.equal(client.normalisePem(oneLine).trim(), privateKey.trim());
  const jwt = client.appJwt("12345", oneLine, 1_700_000_000_000); const [h, b, s] = jwt.split(".");
  assert.ok(createVerify("RSA-SHA256").update(`${h}.${b}`).verify(publicKey, Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64")));
  assert.equal(JSON.parse(Buffer.from(b, "base64").toString()).iss, "12345");
});

test("ssh fingerprints and permissions read as GitHub shows them", () => {
  assert.match(client.sshFingerprint(SSH)!, /^SHA256:[A-Za-z0-9+/]{43}$/);
  assert.equal(client.sshKind(SSH), "ed25519");
  assert.equal(client.permissionOf({ admin: false, maintain: false, push: true, pull: true }), "write");
  assert.equal(client.permissionOf(null, "admin"), "admin");
  assert.equal(client.emailKey("Alice.Example@example.com"), "aliceexample");
});

test("a refresh reads every section, records the refused ones, and the adapter emits people, teams, apps and secrets", async () => {
  const fake = fakeGitHub();
  const r = await inv.refreshGitHub(ad.githubClient(fake.f));
  assert.equal(r.org.node_id, "O_test1"); assert.equal(r.members, 3); assert.equal(r.collaborators, 1); assert.equal(r.repos, 1);
  const x = inv.githubExtras("O_test1");
  assert.equal(x.sections.credential_authorizations.ok, false); assert.equal(x.sections.credential_authorizations.status, 404);
  assert.equal(x.sections.copilot.ok, false); assert.equal(x.sections.copilot.status, 403);
  assert.equal(x.sections.members.ok, true); assert.equal(x.sections.audit_log.rows, 2);
  // the installation token was minted once and reused
  assert.equal(fake.calls.filter((c) => c.startsWith("POST /app/")).length, 1);
  const people = inv.listMembers("O_test1");
  assert.equal(people.find((p) => p.login === "bob-dev")!.mfa, false); assert.equal(people.find((p) => p.login === "alice-ops")!.mfa, true);
  assert.equal(people.find((p) => p.login === "alice-ops")!.email_key, "aliceexample");
  const nodes = ad.githubResources("O_test1");
  const alice = nodes.find((n) => n.id === ad.memberId("O_test1", "alice-ops"))!;
  assert.equal(alice.native_type, "github_member"); assert.equal(alice.props.admin, true); assert.deepEqual(alice.props.teams, ["platform"]);
  assert.ok(nodes.some((n) => n.native_type === "github_collaborator" && n.name === "dave-contractor"));
  assert.ok(nodes.some((n) => n.native_type === "github_team")); assert.ok(nodes.some((n) => n.native_type === "github_app"));
  assert.equal(nodes.filter((n) => n.label === "AdvisorSecret").length, 2);
  const creds = inv.listCredentials("O_test1");
  assert.deepEqual(creds.map((c) => c.kind).sort(), ["deploy_key", "pat", "ssh_key"]);
  assert.ok(reg.adapterFor("github")); assert.ok(ad.githubAdapter.owns("O_test1"));
});

test("people: actors carry 2FA, clients and credentials; the public name joins them to another provider's identity", () => {
  const a = actors.githubActors(null);
  const alice = a.find((x) => x.name === "alice-ops")!;
  assert.equal(alice.mfa, "mfa"); assert.equal(alice.admin, true); assert.equal(alice.display_name, "Alice Example"); assert.equal(alice.keys, 1);
  assert.equal(alice.clients[0].client, "git"); assert.equal(alice.clients[0].platform, "macOS");
  assert.equal(a.find((x) => x.name === "bob-dev")!.mfa, "none");
  assert.deepEqual(actors.githubActors("some-other-account"), []);
});

test("rules: 2FA, empty seats, outside admin, write deploy key unused, token without expiry, AWS key secret", () => {
  const f = rules.githubFindings(now);
  const ids = new Set(f.map((x) => x.control_id));
  for (const c of ["two_factor_not_required", "member_no_2fa", "seats_unused", "outside_collaborator_admin", "deploy_key_write", "deploy_key_unused", "pat_no_expiry", "invitation_stale", "static_aws_keys"]) assert.ok(ids.has(`github.control.${c}`), c);
  const seats = f.find((x) => x.control_id === "github.control.seats_unused")!;
  assert.equal(seats.dimensions.unused, 9); assert.equal(seats.dimensions.monthly_usd, 189);
  const recs = rules.githubRecommendations(f);
  assert.equal(recs.find((r) => r.rule === "github_seats_unused")!.estMonthlySaving, 189);
  for (const c of Object.keys(rules.CONTROLS)) assert.ok(rules.CONTROL_REFERENCES[c]?.length, `${c} has sources`);
});

test("the bill: seats at the plan price plus the metered usage, net of discounts", () => {
  const m = ad.githubMonth("O_test1");
  assert.equal(m.seats, 29); assert.equal(m.seat_line_usd, 609); assert.equal(m.unused_seats, 9);
  assert.equal(m.metered_usd, 2.5); assert.ok(m.projected_usd >= 609 + 2.5);
});

test("changes: a person leaving and a role changing are recorded against the previous snapshot", () => {
  assert.equal(changes.recordChanges("O_test1").changes, 0);
  const a = changes.takeSnapshot("O_test1"); const b = JSON.parse(JSON.stringify(a));
  delete b.people["carol"]; b.people["bob-dev"].role = "admin";
  const d = changes.diff(a, b);
  assert.ok(d.some((c) => c.kind === "removed" && c.subject_id === "carol"));
  assert.ok(d.some((c) => c.kind === "changed" && /bob-dev: member → admin/.test(c.what)));
});

test("Steampipe first: sections with a table are read through SQL, the rest through the API, and a failing table falls back", async () => {
  const sqlMod = await import("../adapters/github/sql.js");
  const seen: string[] = [];
  const q = async (sql: string, params: unknown[] = []) => {
    const table = sql.match(/from github\.(\w+)/)?.[1] ?? ""; seen.push(table);
    switch (table) {
      case "github_organization": return [{ login: "example-org", id: 1, node_id: "O_test1", name: "Example", plan_name: "enterprise", plan_seats: 29, plan_filled_seats: 20, two_factor_requirement_enabled: false, default_repo_permission: "READ" }];
      case "github_organization_member": return [{ login: "alice-ops", id: 11, role: "ADMIN", has_two_factor_enabled: true, name: "Alice Example", email: null }, { login: "bob-dev", id: 12, role: "MEMBER", has_two_factor_enabled: false }, { login: "carol", id: 13, role: "MEMBER", has_two_factor_enabled: true }];
      case "github_organization_collaborator": return [{ user_login: "dave-contractor", repository_name: "api", permission: "ADMIN" }];
      case "github_user": return [{ login: params[0], id: 14 }];
      case "github_organization_external_identity": return [{ user_login: "alice-ops", saml_identity: { name_id: "alice.example@example.com", emails: [{ value: "alice.example@example.com" }] } }];
      case "github_team": return [{ slug: "platform", name: "Platform", id: 1, privacy: "VISIBLE" }];
      case "github_team_member": return [{ login: "alice-ops", role: "MAINTAINER" }, { login: "carol", role: "MEMBER" }];
      case "github_team_repository": return [{ name_with_owner: "example-org/api", permission: "WRITE" }];
      case "github_search_repository": return [{ name: "api", name_with_owner: "example-org/api", id: 1, node_id: "R_1", is_private: true, visibility: "PRIVATE", is_archived: false, is_fork: false, default_branch_ref: { name: "main" }, pushed_at: daysAgo(1) }];
      case "github_repository_collaborator": throw new Error("rpc error: 403 Resource not accessible by integration");
      case "github_actions_repository_secret": return [{ name: "AWS_ACCESS_KEY_ID", created_at: daysAgo(300), updated_at: daysAgo(300) }];
      case "github_repository_environment": return [{ name: "production" }];
      case "github_audit_log": return [{ id: "d9", created_at: new Date(now - 60_000), action: "git.clone", actor: "carol", data: { user_agent: "git/2.43.0", programmatic_access_type: null } }];
      default: throw new Error(`no fake table ${table}`);
    }
  };
  const fake = fakeGitHub();
  const r = await inv.refreshGitHub(ad.githubClient(fake.f), { sql: new sqlMod.GitHubSql("example-org", q), full: true });
  const x = inv.githubExtras("O_test1").sections;
  for (const k of ["members", "members_2fa", "outside_collaborators", "teams", "repos", "repo_secrets", "audit_log", "saml_identities"]) assert.equal(x[k].via, "steampipe", k);
  for (const k of ["personal_access_tokens", "installations", "deploy_keys", "copilot"]) assert.equal(x[k].via, "api", k);
  // the collaborator table failed: that repository's collaborators came from the API
  assert.ok(fake.calls.some((c) => c.includes("/repos/example-org/api/collaborators")));
  // members never touched the API; the member table gave 2FA
  assert.ok(!fake.calls.some((c) => c.includes("/orgs/example-org/members")));
  assert.equal(inv.listMembers("O_test1").find((m) => m.login === "bob-dev")!.mfa, false);
  assert.equal(inv.listMembers("O_test1").find((m) => m.login === "alice-ops")!.saml_key, "aliceexample");
  assert.equal(inv.githubOrgRow()!.default_permission, "read");
  assert.equal(r.repos, 1);
  assert.equal(actors.githubActors(null).find((a) => a.name === "alice-ops")!.email, "aliceexample");
});

test("the Steampipe connection file names the App and the key's path", async () => {
  const sp = await import("../adapters/github/steampipe.js");
  const t = sp.githubSpcText("12345", "67890", "/tmp/example/github_app.pem");
  assert.match(t, /^# managed by cloud-advisor/); assert.match(t, /app_id\s+= "12345"/); assert.match(t, /app_installation_id = "67890"/); assert.match(t, /app_private_key\s+= "\/tmp\/example\/github_app.pem"/);
});

test("the plugin's own sample connection (no credentials) may be replaced; one with a token may not", async () => {
  const sp = await import("../adapters/github/steampipe.js");
  assert.equal(sp.isPluginSample('connection "github" {\n  plugin = "github"\n  # token = "ghp_x"\n}\n'), true);
  assert.equal(sp.isPluginSample('connection "github" {\n  plugin = "github"\n  token = "ghp_example"\n}\n'), false);
});

test("logins come out of the plugin's user objects; a dropped connection is retried", async () => {
  const sqlMod = await import("../adapters/github/sql.js");
  assert.equal(sqlMod.loginOf({ login: "dave-contractor", id: 14 }), "dave-contractor");
  assert.equal(sqlMod.loginOf('{"login":"carol"}'), "carol");
  assert.equal(sqlMod.loginOf("alice-ops"), "alice-ops");
  let n = 0;
  const flaky = (async () => { n++; if (n < 3) throw new TypeError("fetch failed"); return new Response("[]", { status: 200, headers: { "content-type": "application/json" } }); }) as unknown as typeof fetch;
  const c = new client.GitHubClient({ org: "example-org", token: "ghs_test", fetchImpl: flaky });
  assert.deepEqual(await c.get("/orgs/example-org/hooks"), []); assert.equal(n, 3);
});

test("a repeated request is conditional: GitHub's 304 answers from the cache", async () => {
  const store = new Map<string, { etag: string; body: string; next: string | null }>();
  let sent: string | null = null; let n = 0;
  const f = (async (_u: any, init: any) => { n++; sent = init.headers["if-none-match"] ?? null; return sent === '"v1"' ? new Response(null, { status: 304 }) : new Response(JSON.stringify([{ id: 1 }]), { status: 200, headers: { etag: '"v1"', "content-type": "application/json" } }); }) as unknown as typeof fetch;
  const c = new client.GitHubClient({ org: "example-org", token: "ghs_test", fetchImpl: f, cache: { get: (u) => store.get(u) ?? null, set: (u, v) => { store.set(u, v); } } });
  assert.deepEqual(await c.get("/orgs/example-org/hooks"), [{ id: 1 }]); assert.equal(c.not_modified, 0);
  assert.deepEqual(await c.get("/orgs/example-org/hooks"), [{ id: 1 }]); assert.equal(sent, '"v1"'); assert.equal(c.not_modified, 1); assert.equal(n, 2);
});

test("only new repositories and the ones the audit log shows changed are read again; the rest keep their rows", async () => {
  const repos = [{ full_name: "example-org/api", archived: false }, { full_name: "example-org/web", archived: false }, { full_name: "example-org/new", archived: false }];
  const known = new Map<string, string | null>([["example-org/api", daysAgo(1)], ["example-org/web", daysAgo(1)]]);
  assert.deepEqual([...inv.reposToRead({ repos, known, changed: new Set(["example-org/web"]), full: false })].sort(), ["example-org/new", "example-org/web"]);
  assert.equal(inv.reposToRead({ repos, known, changed: new Set(), full: true }).size, 3);
  assert.ok(inv.REPO_CHANGE_ACTION.test("repo.add_member")); assert.ok(inv.REPO_CHANGE_ACTION.test("public_key.create")); assert.ok(!inv.REPO_CHANGE_ACTION.test("git.push"));
  // a second collection with nothing changed: the repository's detail is not read, its collaborators and keys stay
  const before = inv.listRepoAccess("O_test1").length; const keys = inv.listCredentials("O_test1").filter((c) => c.kind === "deploy_key").length;
  const fake = fakeGitHub();
  const r = await inv.refreshGitHub(ad.githubClient(fake.f));
  assert.equal(r.full_sweep, false); assert.equal(r.repos_read, 0); assert.equal(r.repos_kept, 1);
  assert.ok(!fake.calls.some((c) => c.includes("/repos/example-org/api/keys")));
  assert.equal(inv.listRepoAccess("O_test1").length, before); assert.equal(inv.listCredentials("O_test1").filter((c) => c.kind === "deploy_key").length, keys);
  // forced: everything again
  const fake2 = fakeGitHub();
  const r2 = await inv.refreshGitHub(ad.githubClient(fake2.f), { full: true });
  assert.equal(r2.full_sweep, true); assert.ok(fake2.calls.some((c) => c.includes("/repos/example-org/api/keys")));
});

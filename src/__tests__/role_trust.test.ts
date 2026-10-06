import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

// The non-human ways in (src/role_trust.ts), how Vercel projects reach AWS (src/vercel_aws_links.ts), the Vercel
// client's team guards and tokens, and the identity recommendations (src/identity_rules.ts).
process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "advisor-roles-test-"));
process.env.NEO4J_URI = "";
const t = await import("../role_trust.js");
const links = await import("../vercel_aws_links.js");
const client = await import("../adapters/vercel/client.js");
const { resourceFromRole } = await import("../adapters/aws/resources.js");
const { db } = await import("../db.js");

const OWN = "111122223333"; const ORG = "444455556666"; const VENDOR = "777788889999";
const known = new Set([OWN, ORG]);
const policy = (...Statement: any[]) => JSON.stringify({ Version: "2012-10-17", Statement });

test("trustPrincipals: services, this account, the organisation, another company, anyone", () => {
  const ps = t.trustPrincipals(policy(
    { Effect: "Allow", Principal: { Service: "ec2.amazonaws.com" }, Action: "sts:AssumeRole" },
    { Effect: "Allow", Principal: { AWS: [`arn:aws:iam::${OWN}:role/deployer`, `arn:aws:iam::${ORG}:root`] }, Action: "sts:AssumeRole" },
    { Effect: "Allow", Principal: { AWS: VENDOR }, Action: "sts:AssumeRole" },
    { Effect: "Allow", Principal: { AWS: VENDOR }, Action: "sts:AssumeRole", Condition: { StringEquals: { "sts:ExternalId": "example-external-id" } } },
    { Effect: "Deny", Principal: { AWS: "*" }, Action: "sts:AssumeRole" },
  ), OWN, known);
  assert.deepEqual(ps.map((p) => p.kind), ["service", "same_account", "org_account", "external_account", "external_account"]);
  assert.equal(ps[3].risk, "warning", "another company's account without an external id");
  assert.equal(ps[4].risk, null); assert.equal(ps[4].external_id, true);
  assert.equal(t.trustSummary(ps), "cross_account");
  const star = t.trustPrincipals(policy({ Effect: "Allow", Principal: "*", Action: "sts:AssumeRole" }), OWN, known);
  assert.equal(star[0].kind, "public"); assert.equal(star[0].risk, "alarm");
  const orgOnly = t.trustPrincipals(policy({ Effect: "Allow", Principal: { AWS: "*" }, Action: "sts:AssumeRole", Condition: { StringEquals: { "aws:PrincipalOrgID": "o-example" } } }), OWN, known);
  assert.equal(orgOnly[0].risk, null); assert.equal(orgOnly[0].org_restricted, true);
});

test("federatedPrincipal: GitHub with and without a subject, Vercel per project, EKS, Cognito guests, Identity Center", () => {
  const gh = `arn:aws:iam::${OWN}:oidc-provider/token.actions.githubusercontent.com`;
  const scoped = t.federatedPrincipal(gh, { StringLike: { "token.actions.githubusercontent.com:sub": ["repo:example-org/web:*"] }, StringEquals: { "token.actions.githubusercontent.com:aud": "sts.amazonaws.com" } }, OWN);
  assert.equal(scoped.kind, "github_actions"); assert.deepEqual(scoped.scope, ["example-org/web:*"]); assert.equal(scoped.risk, null);
  assert.equal(t.federatedPrincipal(gh, { StringEquals: { "token.actions.githubusercontent.com:aud": "sts.amazonaws.com" } }, OWN).risk, "alarm", "no subject: any repository");
  assert.equal(t.federatedPrincipal(gh, { StringLike: { "token.actions.githubusercontent.com:sub": "*" } }, OWN).risk, "alarm");
  const v = t.federatedPrincipal(`arn:aws:iam::${OWN}:oidc-provider/oidc.vercel.com/example-team`, { StringLike: { "oidc.vercel.com/example-team:sub": ["owner:example-team:project:web:environment:production"] } }, OWN);
  assert.equal(v.kind, "vercel"); assert.equal(v.who, "Vercel team example-team"); assert.deepEqual(v.scope, ["project:web:environment:production"]); assert.equal(v.risk, null);
  assert.equal(t.federatedPrincipal(`arn:aws:iam::${OWN}:oidc-provider/oidc.vercel.com`, {}, OWN).risk, "alarm", "the global issuer with no subject");
  assert.equal(t.federatedPrincipal(`arn:aws:iam::${OWN}:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE0123456789`, { StringEquals: { "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE0123456789:sub": "system:serviceaccount:kube-system:karpenter" } }, OWN).kind, "eks");
  const guests = t.federatedPrincipal("cognito-identity.amazonaws.com", { StringEquals: { "cognito-identity.amazonaws.com:aud": "us-east-1:00000000-0000-0000-0000-000000000000" }, "ForAnyValue:StringLike": { "cognito-identity.amazonaws.com:amr": "unauthenticated" } }, OWN);
  assert.equal(guests.kind, "cognito"); assert.equal(guests.risk, "warning");
  assert.equal(t.federatedPrincipal(`arn:aws:iam::${OWN}:saml-provider/AWSSSO_0123456789abcdef_DO_NOT_DELETE`, {}, OWN).kind, "identity_center");
});

test("isOutsideTrust: EKS pods, services and Identity Center stay inside; GitHub and another account are outside", () => {
  const k = (kind: string) => ({ kind, who: "", account_id: null, scope: [], external_id: false, org_restricted: false, risk: null, risk_reason: null }) as any;
  assert.equal(t.isOutsideTrust([k("service"), k("eks"), k("identity_center"), k("same_account")]), false);
  assert.equal(t.isOutsideTrust([k("service"), k("github_actions")]), true);
  assert.equal(t.isOutsideTrust([k("org_account")]), true);
});

test("oidcLinksFrom: a role's Vercel subjects name the projects and environments; another team's issuer is ignored", () => {
  const roles = [
    { arn: `arn:aws:iam::${OWN}:role/vercel-web`, name: "vercel-web", account_id: OWN, principals: [{ kind: "vercel", who: "Vercel team example-team", scope: ["project:web:environment:production", "project:web:environment:preview"] }] },
    { arn: `arn:aws:iam::${OWN}:role/vercel-any`, name: "vercel-any", account_id: OWN, principals: [{ kind: "vercel", who: "Vercel team example-team", scope: ["project:api-*:environment:*"] }] },
    { arn: `arn:aws:iam::${OWN}:role/other-team`, name: "other-team", account_id: OWN, principals: [{ kind: "vercel", who: "Vercel team someone-else", scope: ["project:web:environment:production"] }] },
  ];
  const out = links.oidcLinksFrom(roles, [{ id: "prj_web", name: "web" }, { id: "prj_api", name: "api-gateway" }, { id: "prj_docs", name: "docs" }], "example-team");
  assert.deepEqual(out.map((l) => [l.project_name, l.role_name, l.environments]), [["web", "vercel-web", ["preview", "production"]], ["api-gateway", "vercel-any", ["*"]]]);
});

test("AWS_KEY_NAME and keyCandidates: key-pair names, and the active keys made just before the variable", () => {
  for (const n of ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "S3_ACCESS_KEY_ID", "MY_SECRET_ACCESS_KEY"]) assert.ok(links.AWS_KEY_NAME.test(n), n);
  for (const n of ["AWS_ROLE_ARN", "AWS_REGION", "DATABASE_URL"]) assert.ok(!links.AWS_KEY_NAME.test(n), n);
  const users = [{ name: "deploy", arn: `arn:aws:iam::${OWN}:user/deploy`, account_id: OWN, access_keys: [{ id: "AKIA…WXYZ", status: "Active", created: "2026-09-01T10:00:00Z" }, { id: "AKIA…OLD1", status: "Active", created: "2026-01-01T10:00:00Z" }, { id: "AKIA…OFF1", status: "Inactive", created: "2026-09-01T11:00:00Z" }] }];
  const c = links.keyCandidates("2026-09-01T12:30:00Z", users);
  assert.deepEqual(c.map((x) => [x.key, x.hours_before]), [["AKIA…WXYZ", 2.5]]);
  assert.deepEqual(links.keyCandidates(null, users), []);
});

test("Vercel client: team guards, tokens, a member's e-mail kept only as a match key", () => {
  const sec = client.teamSecurityFrom({ saml: { connection: { type: "OktaSAML" }, enforced: false }, sensitiveEnvironmentVariablePolicy: "on", membership: { role: "OWNER" } });
  assert.deepEqual(sec, { saml_connected: true, saml_enforced: false, saml_provider: "OktaSAML", directory_sync: false, mfa_required: null, sensitive_env_policy: "on", token_owner_role: "OWNER" });
  assert.equal(client.teamSecurityFrom({ mfaRequired: true }).mfa_required, true);
  const tok = client.tokenFrom({ id: "tok1", name: "ci", type: "token", origin: "manual", scopes: [{ type: "team", teamId: "team_example" }], activeAt: 1790000000000, createdAt: 1780000000000 });
  assert.deepEqual(tok.team_ids, ["team_example"]); assert.equal(tok.expires_at, null);
  const m = client.memberFrom({ uid: "u1", username: "pat", email: "Pat.Example@example.com", role: "MEMBER", confirmed: true, mfaEnabled: true, accessGroups: [{}], joinedFrom: { origin: "mail" } });
  assert.equal(m.email_key, "patexample"); assert.equal((m as any).email, undefined, "the address is not kept"); assert.equal(m.access_groups, 1);
});

test("resourceFromRole: trusted_by lines, the risk, services apart", () => {
  const node = resourceFromRole({ arn: `arn:aws:iam::${OWN}:role/ci`, name: "ci", account_id: OWN, admin: 1, trust: "federated", risk: "alarm", risk_reason: "GitHub Actions: no subject condition", policies: JSON.stringify(["AdministratorAccess"]), last_used: null, first_seen: "2026-10-01", last_seen: "2026-10-05", gone: 0,
    principals: JSON.stringify([{ kind: "service", who: "ec2.amazonaws.com", scope: [] }, { kind: "github_actions", who: "GitHub Actions", scope: ["example-org/web:*"], external_id: false }]) });
  assert.equal(node.native_type, "iam_role"); assert.equal(node.props.kind, "role");
  assert.deepEqual(node.props.trusted_by, ["github_actions: GitHub Actions [example-org/web:*]"]); assert.deepEqual(node.props.trusted_services, ["ec2.amazonaws.com"]); assert.equal(node.props.trust_risk, "alarm");
});

test("identityRecommendations: a wide role trust, an unused outside role, Cognito guests worded for their permissions", async () => {
  const now = new Date().toISOString(); const old = "2025-01-01T00:00:00Z";
  const ins = db.prepare(`insert into inventory_iam_role(arn, name, account_id, created, last_used, admin, policies, principals, trust, risk, risk_reason, first_seen, last_seen) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
  ins.run(`arn:aws:iam::${OWN}:role/ci-open`, "ci-open", OWN, old, now, 1, JSON.stringify(["AdministratorAccess"]), JSON.stringify([{ kind: "github_actions", who: "GitHub Actions", scope: [], risk: "alarm", risk_reason: "no subject condition" }]), "federated", "alarm", "GitHub Actions: no subject condition", now, now);
  ins.run(`arn:aws:iam::${OWN}:role/vendor-old`, "vendor-old", OWN, old, old, 0, "[]", JSON.stringify([{ kind: "external_account", who: `account ${VENDOR}`, account_id: VENDOR, scope: [], external_id: true }]), "cross_account", null, null, now, now);
  ins.run(`arn:aws:iam::${OWN}:role/guests`, "guests", OWN, old, now, 0, JSON.stringify(["guest-read"]), JSON.stringify([{ kind: "cognito", who: "Cognito guests (unauthenticated)", scope: ["us-east-1:00000000-0000-0000-0000-000000000000"], risk: "warning", risk_reason: "unauthenticated guests" }]), "federated", "warning", "Cognito guests (unauthenticated): unauthenticated guests", now, now);
  ins.run(`arn:aws:iam::${OWN}:role/OrganizationAccountAccessRole`, "OrganizationAccountAccessRole", OWN, old, null, 1, JSON.stringify(["AdministratorAccess"]), JSON.stringify([{ kind: "org_account", who: `account ${ORG}`, account_id: ORG, scope: [] }]), "cross_account", null, null, now, now);
  const { identityRecommendations } = await import("../identity_rules.js");
  const recs = identityRecommendations();
  const by = (rule: string) => recs.filter((r) => r.rule === rule).map((r) => r.resourceName);
  assert.deepEqual(by("identity_role_wide_trust").sort(), ["ci-open", "guests"]);
  assert.match(recs.find((r) => r.resourceName === "ci-open")!.rationale, /administrative/);
  assert.match(recs.find((r) => r.resourceName === "guests")!.title, /permissions minimal/);
  assert.deepEqual(by("identity_unused_outside_role"), ["vendor-old"], "a role only the organisation's own accounts may assume is not flagged as unused");
});

test("Vercel: team guards and tokens as findings, members joined to the same person's AWS identities, static keys flagged", async () => {
  const now = new Date().toISOString(); const TEAM = "team_example";
  await import("../adapters/vercel/inventory.js");
  db.prepare("insert or replace into vercel_team(id, slug, name, plan, personal, fetched_at) values (?, 'example-team', 'Example', 'pro', 0, ?)").run(TEAM, now);
  db.prepare("insert or replace into settings(key, value) values (?, ?)").run(`vercel_extras:${TEAM}`, JSON.stringify({
    members: [{ uid: "u1", username: "pat", role: "OWNER", confirmed: true, mfa: true, github: "pat-gh", joined_at: now, email_key: "patexample" }, { uid: "u2", username: "sam", role: "MEMBER", confirmed: true, mfa: false, github: null, joined_at: now, email_key: "sam" }],
    log_drains: [], tokens: [{ id: "tok1", name: "ci", type: "token", origin: "manual", team_ids: [TEAM], expires_at: null, active_at: "2025-01-01T00:00:00Z", created_at: "2024-12-01T00:00:00Z" }],
    token_owner: { uid: "u1", username: "pat" }, security: { saml_connected: false, saml_enforced: false, saml_provider: null, directory_sync: false, mfa_required: null, sensitive_env_policy: "default", token_owner_role: "OWNER" }, read_at: now,
  }));
  db.prepare("insert or replace into vercel_projects(id, team_id, name, protection, live, env_count, first_seen, last_seen, gone) values ('prj_web', ?, 'web', '{}', 1, 2, ?, ?, 0)").run(TEAM, now, now);
  db.prepare("insert or replace into vercel_env(project_id, key, targets, type, updated_at, created_at, first_seen, last_seen, gone) values ('prj_web', 'AWS_ACCESS_KEY_ID', '[\"production\"]', 'encrypted', ?, ?, ?, ?, 0)").run(now, now, now, now);
  const { vercelFindings } = await import("../adapters/vercel/rules.js");
  const ids = vercelFindings().map((f) => f.control_id);
  for (const c of ["vercel.control.team_2fa_not_enforced", "vercel.control.single_owner", "vercel.control.token_no_expiry", "vercel.control.token_unused", "vercel.control.static_aws_keys", "vercel.control.member_without_mfa"]) assert.ok(ids.includes(c), c);
  db.prepare(`insert into inventory_sso_user(user_id, identity_store_id, account_id, user_name, display_name, email, first_seen, last_seen) values ('9067-user-0009', 'd-0000example', ?, 'pat.example@example.com', 'Pat Example', 'pat.example@example.com', ?, ?)`).run(OWN, now, now);
  const s = await import("../sign_ins.js");
  const pat = s.listPeople(s.listActors(null)).find((p) => p.identities.some((i) => i.kind === "vercel_member" && i.name === "pat"))!;
  assert.deepEqual(pat.identities.map((i) => i.kind).sort(), ["sso_user", "vercel_member"]);
  assert.equal(pat.identities.find((i) => i.kind === "vercel_member")!.tokens!.length, 1, "the token owner's tokens sit on their member");
});

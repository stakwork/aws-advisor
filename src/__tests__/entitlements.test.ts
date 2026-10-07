import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

// What people may do: policy grading (src/policy_facts.ts), the service reference rows (src/service_reference.ts), the
// collector's pure parts (src/entitlements.ts) and the paths from a person to everything (src/access_paths.ts).
process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "advisor-entitlements-test-"));
process.env.NEO4J_URI = "";
const pf = await import("../policy_facts.js");
const sr = await import("../service_reference.js");
const ent = await import("../entitlements.js");
const ap = await import("../access_paths.js");
const ge = await import("../graph_entitlements.js");

const A = "111122223333"; const B = "444455556666";
// a small catalogue in the service reference's own shape
const file = (actions: [string, Record<string, boolean>][]) => ({ Actions: actions.map(([Name, p]) => ({ Name, Annotations: { Properties: p } })) });
const W = { IsWrite: true }; const L = { IsList: true }; const R = {}; const P = { IsWrite: true, IsPermissionManagement: true }; const T = { IsWrite: true, IsTaggingOnly: true };
const files: Record<string, any> = {
  ec2: file([["DescribeInstances", L], ["RunInstances", W], ["TerminateInstances", W], ["CreateTags", T], ["GetConsoleOutput", R]]),
  s3: file([["ListAllMyBuckets", L], ["GetObject", R], ["PutObject", W], ["PutBucketPolicy", P]]),
  iam: file([["ListUsers", L], ["GetRole", R], ["CreateUser", W], ["PutUserPolicy", P], ["AttachRolePolicy", P], ["PassRole", P], ["CreateServiceLinkedRole", W]]),
  sts: file([["AssumeRole", W], ["GetCallerIdentity", R]]),
  ssm: file([["StartSession", W], ["DescribeInstanceInformation", L]]),
};
const rows = Object.entries(files).flatMap(([svc, f]) => sr.actionRows(svc, f));
const by = new Map<string, Map<string, { name: string; level: any }>>();
for (const r of rows) { let m = by.get(r.service); if (!m) { m = new Map(); by.set(r.service, m); } m.set(r.action, { name: r.name, level: r.level }); }
const cat = { actions: (s: string) => by.get(s) ?? null };
const doc = (...Statement: any[]) => ({ Version: "2012-10-17", Statement });
const g = (...docs: any[]) => pf.grade(pf.permsOf(docs.map((d, i) => ({ doc: d, source: `p${i}` })), cat), cat);

test("levelOf reads the service reference's annotations the way the console does", () => {
  assert.equal(pf.levelOf(P), "permissions"); assert.equal(pf.levelOf(T), "tagging"); assert.equal(pf.levelOf(W), "write"); assert.equal(pf.levelOf(L), "list"); assert.equal(pf.levelOf(R), "read");
  assert.deepEqual(rows.find((r) => r.action === "putuserpolicy"), { service: "iam", action: "putuserpolicy", name: "PutUserPolicy", level: "permissions" });
  assert.deepEqual(sr.servicesNamed([doc({ Effect: "Allow", Action: ["ec2:Describe*", "S3:GetObject"], Resource: "*" }), JSON.stringify(doc({ Effect: "Allow", NotAction: "iam:*", Resource: "*" }))]).sort(), ["ec2", "iam", "s3"]);
});

test("grade: administrator, PowerUser's NotAction, wildcards per service, scoped resources, an unconditional Deny", () => {
  const admin = g(doc({ Effect: "Allow", Action: "*", Resource: "*" }));
  assert.equal(admin.admin, true); assert.equal(pf.gradeLine(admin), "Administrator (every action on every service)");
  const power = g(doc({ Effect: "Allow", NotAction: ["iam:*", "organizations:*", "account:*"], Resource: "*" }));
  assert.equal(power.admin, false); assert.equal(power.top, "write", "every service but IAM is write, not permissions management");
  const dev = g(doc({ Effect: "Allow", Action: ["ec2:*", "s3:Get*", "s3:List*"], Resource: "*" }, { Effect: "Allow", Action: "iam:PassRole", Resource: `arn:aws:iam::${A}:role/app` }));
  assert.deepEqual(dev.write_services, ["iam", "ec2"], "permissions management first");
  const iam = dev.services.find((s) => s.service === "iam")!;
  assert.equal(iam.top, "permissions"); assert.equal(iam.scoped, true); assert.deepEqual(iam.resources, [`arn:aws:iam::${A}:role/app`]);
  assert.deepEqual(dev.services.find((s) => s.service === "ec2")!.levels, ["list", "read", "tagging", "write"]);
  assert.deepEqual(pf.canEscalate(dev), ["iam:PassRole"]);
  const denied = g(doc({ Effect: "Allow", Action: "ec2:*", Resource: "*" }, { Effect: "Deny", Action: "ec2:TerminateInstances", Resource: "*" }, { Effect: "Deny", Action: "ec2:RunInstances", Resource: "*", Condition: { StringNotEquals: { "aws:RequestedRegion": "us-east-1" } } }));
  const ec2 = denied.services.find((s) => s.service === "ec2")!;
  assert.equal(ec2.actions, 4, "TerminateInstances is taken away"); assert.deepEqual(denied.conditional_denies, ["ec2:RunInstances"]);
  assert.equal(g(doc({ Effect: "Allow", Action: "s3:GetObject", Resource: "*" })).top, "read");
});

test("a logging set: a topic's resource policy is resource access, not IAM; a conditional IAM grant is labelled", () => {
  const files2 = { ...files, sns: file([["Publish", W], ["AddPermission", P], ["SetTopicAttributes", P]]) };
  const by2 = new Map<string, Map<string, { name: string; level: any }>>(); for (const r of Object.entries(files2).flatMap(([svc, f]) => sr.actionRows(svc, f))) { let m = by2.get(r.service); if (!m) { m = new Map(); by2.set(r.service, m); } m.set(r.action, { name: r.name, level: r.level }); }
  const cat2 = { actions: (x: string) => by2.get(x) ?? null };
  const gr = pf.grade(pf.permsOf([{ doc: doc({ Effect: "Allow", Action: "sns:*", Resource: "*" }, { Effect: "Allow", Action: "iam:CreateServiceLinkedRole", Resource: "*", Condition: { StringLike: { "iam:AWSServiceName": "events.amazonaws.com" } } }), source: "CloudWatchFullAccessV2" }], cat2), cat2);
  assert.equal(gr.top, "write", "resource policies do not make the set a permissions manager");
  assert.deepEqual(gr.resource_access_services, ["sns"]); assert.deepEqual(gr.permissions_services, []);
  assert.equal(pf.gradeLine(gr), "Write, and who may reach the data, on sns; Write on iam (under a condition)");
});

test("intersect: a permissions boundary and an SCP path keep only what both allow", () => {
  const own = pf.permsOf([{ doc: doc({ Effect: "Allow", Action: "*", Resource: "*" }), source: "admin" }], cat);
  const boundary = pf.permsOf([{ doc: doc({ Effect: "Allow", Action: ["ec2:*", "s3:GetObject"], Resource: "*" }), source: "b" }], cat);
  const both = pf.grade(pf.intersect(own, boundary, cat), cat);
  assert.equal(both.admin, false); assert.deepEqual(both.services.map((s) => s.service).sort(), ["ec2", "s3"]); assert.equal(both.services.find((s) => s.service === "s3")!.top, "read");
  const levels = [
    { target: "r-root", policies: [{ id: "p-full", name: "FullAWSAccess", doc: doc({ Effect: "Allow", Action: "*", Resource: "*" }) }] },
    { target: "ou-dev", policies: [{ id: "p-noiam", name: "DenyIam", doc: doc({ Effect: "Allow", Action: "*", Resource: "*" }, { Effect: "Deny", Action: "iam:*", Resource: "*" }) }] },
    { target: A, policies: [] },
  ];
  const scp = ent.scpPerms(levels, cat)!;
  const eff = pf.grade(pf.intersect(own, scp, cat), cat);
  assert.equal(eff.admin, false, "an SCP that denies IAM makes an administrator less than one");
  assert.ok(eff.every && eff.every.except.includes("iam:*"));
});

test("allows: one action on one resource, conditions and denies", () => {
  const docs = [{ doc: doc({ Effect: "Allow", Action: "sts:AssumeRole", Resource: `arn:aws:iam::${B}:role/*` }, { Effect: "Allow", Action: "ssm:StartSession", Resource: "*", Condition: { StringEquals: { "ssm:resourceTag/team": "web" } } }), source: "p" }];
  assert.equal(pf.allows(docs, "sts:AssumeRole", `arn:aws:iam::${B}:role/deployer`).decision, "allowed");
  assert.equal(pf.allows(docs, "sts:assumerole", `arn:aws:iam::${A}:role/deployer`).decision, "denied");
  assert.equal(pf.allows(docs, "ssm:StartSession", `arn:aws:ec2:us-east-1:${A}:instance/i-0example`).decision, "conditional");
  assert.equal(pf.allows([...docs, { doc: doc({ Effect: "Deny", Action: "sts:*", Resource: "*" }), source: "d" }], "sts:AssumeRole", `arn:aws:iam::${B}:role/deployer`).decision, "denied");
});

test("authorizationRows decodes URL-encoded documents; aws-auth's YAML becomes mappings", () => {
  const enc = encodeURIComponent(JSON.stringify(doc({ Effect: "Allow", Action: "s3:GetObject", Resource: "*" })));
  const x = ent.authorizationRows(A, [{ UserDetailList: [{ Arn: `arn:aws:iam::${A}:user/alice`, UserName: "alice", GroupList: ["devs"], UserPolicyList: [{ PolicyName: "read", PolicyDocument: enc }], AttachedManagedPolicies: [{ PolicyArn: "arn:aws:iam::aws:policy/ReadOnlyAccess" }] }],
    RoleDetailList: [{ Arn: `arn:aws:iam::${A}:role/web`, RoleName: "web", Path: "/", InstanceProfileList: [{ Arn: `arn:aws:iam::${A}:instance-profile/web` }] }], GroupDetailList: [], Policies: [] }]);
  assert.equal(x.principals[0].inline[0].doc.Statement[0].Action, "s3:GetObject");
  assert.deepEqual(x.principals[0].attached, ["arn:aws:iam::aws:policy/ReadOnlyAccess"]); assert.deepEqual(x.principals[1].instance_profiles, [`arn:aws:iam::${A}:instance-profile/web`]);
  const cm = { data: { mapRoles: `- rolearn: arn:aws:iam::${A}:role/nodes\n  username: system:node:{{EC2PrivateDNSName}}\n  groups:\n    - system:bootstrappers\n    - system:nodes\n- rolearn: arn:aws:iam::${A}:role/ops\n  username: ops\n  groups:\n    - system:masters\n`, mapUsers: `- userarn: arn:aws:iam::${A}:user/alice\n  username: alice\n  groups: []\n` } };
  const m = ent.awsAuthMappings(cm);
  assert.deepEqual(m.map((x) => [x.principal_arn.split("/").pop(), x.level]), [["nodes", "node"], ["ops", "cluster_admin"], ["alice", "none"]]);
  assert.equal(ent.eksPolicyLevel("arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"), "cluster_admin");
});

test("vercelCapability: team roles, and project roles for contributors", () => {
  assert.deepEqual(ap.vercelCapability("OWNER", null), { level: "owner", deploy: "production", env_vars: "write" });
  assert.equal(ap.vercelCapability("DEVELOPER", null)!.env_vars, "preview");
  assert.equal(ap.vercelCapability("VIEWER", null)!.deploy, "none");
  assert.equal(ap.vercelCapability("CONTRIBUTOR", null), null, "a contributor sees nothing without a project role");
  assert.equal(ap.vercelCapability("CONTRIBUTOR", "PROJECT_DEVELOPER")!.level, "project_developer");
});

test("reach: an Identity Center user, a role their set may assume, a shell to an instance with an admin profile, a Vercel project's OIDC role", () => {
  const P = (arn: string, kind: "user" | "role" | "group", name: string, account: string, extra: any = {}) => ({ arn, account_id: account, kind, name, path: "/", groups: [], attached: [], inline: [], boundary: null, instance_profiles: [], last_used: null, ...extra });
  const reserved = `arn:aws:iam::${A}:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Developer_0123456789abcdef`;
  const deployer = `arn:aws:iam::${B}:role/deployer`; const web = `arn:aws:iam::${A}:role/web`; const ci = `arn:aws:iam::${A}:role/vercel-ci`;
  const principals = [
    P(reserved, "role", "AWSReservedSSO_Developer_0123456789abcdef", A, { inline: [{ name: "dev", doc: doc({ Effect: "Allow", Action: ["ec2:Describe*", "ssm:StartSession"], Resource: "*" }, { Effect: "Allow", Action: "sts:AssumeRole", Resource: deployer }) }] }),
    P(deployer, "role", "deployer", B, { inline: [{ name: "deploy", doc: doc({ Effect: "Allow", Action: "s3:PutObject", Resource: "*" }) }] }),
    P(web, "role", "web", A, { attached: ["arn:aws:iam::aws:policy/AdministratorAccess"], instance_profiles: [`arn:aws:iam::${A}:instance-profile/web`] }),
    P(ci, "role", "vercel-ci", A, { inline: [{ name: "ci", doc: doc({ Effect: "Allow", Action: "s3:*", Resource: "*" }) }] }),
  ];
  const docs = new Map<string, any>([["arn:aws:iam::aws:policy/AdministratorAccess", doc({ Effect: "Allow", Action: "*", Resource: "*" })]]);
  const graded = ent.gradeAccount(principals.filter((p) => p.account_id === A), (a) => docs.get(a), null, cat).concat(ent.gradeAccount(principals.filter((p) => p.account_id === B), (a) => docs.get(a), null, cat));
  const entitlements = new Map(graded.map((e) => [e.arn, { ...e, top: e.grants.top, admin: e.grants.admin, updated_at: "2026-01-01T00:00:00Z" }]));
  const actor = (kind: any, id: string, name: string, account: string | null, extra: any = {}) => ({ kind, id, name, email: null, display_name: null, account_id: account, admin: false, console: true, keys: 0, mfa: "unknown", mfa_source: null, last_seen_at: null, clients: [], sign_ins_90d: null, mfa_sign_ins_90d: null, status: "active", changes: [], ...extra });
  const sso = actor("sso_user", "90000000-0000-0000-0000-000000000001", "alice", A);
  const member = actor("vercel_member", "team_example/member/alice", "alice", "team_example", { role: "DEVELOPER" });
  const w: any = {
    actors: [sso, member], principals, entitlements, docs,
    roles: [{ arn: deployer, name: "deployer", account_id: B, principals: [{ kind: "org_account", who: `account ${A}`, account_id: A, scope: [], external_id: false }] }],
    sso: [{ user_id: sso.id, user_name: "alice", assignments: [{ account_id: A, permission_set: "Developer", via: "group engineers" }] }],
    instances: [{ id: "i-0example0000000001", arn: `arn:aws:ec2:us-east-1:${A}:instance/i-0example0000000001`, account_id: A, region: "us-east-1", profile: `arn:aws:iam::${A}:instance-profile/web`, ssm: true, name: "web-1" }],
    cluster_access: [], used: new Map(), usage_read: new Set(),
    vercel: { team_id: "team_example", members: [{ id: member.id, uid: "u1", role: "DEVELOPER" }], project_roles: [], projects: [{ id: "prj_example", name: "site" }], oidc: [{ project_id: "prj_example", role_arn: ci, environments: ["production"] }], keys: [] },
  };
  const built = ap.accessEdges(w);
  assert.ok(built.edges.some((e) => e.kind === "CAN_ASSUME" && e.from === reserved && e.to === deployer), "the set's policy allows sts:AssumeRole and the deployer trusts the account");
  assert.ok(built.edges.some((e) => e.kind === "CAN_SHELL_INTO" && e.from === reserved && e.to === "i-0example0000000001"));
  assert.ok(built.edges.some((e) => e.kind === "RUNS_AS" && e.from === "i-0example0000000001" && e.to === web));
  const person = { key: "alice", name: "alice", email: null, machine: false, matched_by: ["name"], identities: [sso, member], admin: false, mfa: "unknown", platforms: [], channels: [], keys: 0, last_seen_at: null, status: "active", mfa_weakest_kind: null } as any;
  const touched = new Map([[sso.id, new Map([[A, new Set(["ec2"])]])]]);
  const r = ap.reach(person, w, built, touched);
  const a = r.accounts.find((x) => x.account_id === A)!;
  assert.equal(a.admin, true, "the shell on web-1 runs as an administrator role"); assert.equal(a.direct, true);
  assert.ok(a.paths.some((p) => p.steps.some((s) => /opens a shell on web-1/.test(s)) && p.steps.some((s) => /runs as web/.test(s))));
  const b = r.accounts.find((x) => x.account_id === B)!;
  assert.equal(b.direct, false); assert.equal(b.level, "write"); assert.deepEqual(b.write_services, ["s3"]);
  assert.match(b.line, /^Nothing of their own; through a path: Write on s3$/); assert.deepEqual(b.path_services, ["s3"]);
  assert.match(a.line, /through a path: Administrator/, "the admin comes from the shell, not the set");
  assert.ok(r.roles.some((x) => x.name === "vercel-ci"), "a developer deploys production, the project's OIDC role allows production");
  assert.deepEqual(r.projects.map((p) => [p.name, p.deploy]), [["site", "production"]]);
  assert.deepEqual(a.used_services, ["ec2"]);
});

test("trailIdentity: an IAM user, an Identity Center session by its user name, another role by account and name", () => {
  const sso = new Map([["alice@example.com", "sso-alice"], ["alice", "sso-alice"]]);
  const role = (acct: string | null, n: string) => (acct === A && n === "deployer" ? `arn:aws:iam::${A}:role/deployer` : null);
  assert.equal(ap.trailIdentity({ principal_arn: `arn:aws:iam::${A}:user/bob`, identity_type: "IAMUser", username: "bob", account_id: A }, sso, role), `arn:aws:iam::${A}:user/bob`);
  assert.equal(ap.trailIdentity({ principal_arn: `arn:aws:sts::${A}:assumed-role/AWSReservedSSO_Admin_0123456789abcdef/alice@example.com`, identity_type: "AssumedRole", username: null, account_id: A }, sso, role), "sso-alice");
  assert.equal(ap.trailIdentity({ principal_arn: `arn:aws:sts::${A}:assumed-role/deployer/gh-run-1`, identity_type: "AssumedRole", username: null, account_id: A }, sso, role), `arn:aws:iam::${A}:role/deployer`);
  assert.equal(ap.serviceOfSource("monitoring.amazonaws.com"), "cloudwatch");
});

test("policyUrl: AWS's reference page for an AWS-managed policy, the IAM console for ours", () => {
  assert.equal(ge.policyUrl({ kind: "aws_managed", name: "CloudWatchFullAccessV2" }), "https://docs.aws.amazon.com/aws-managed-policy/latest/reference/CloudWatchFullAccessV2.html");
  assert.equal(ge.policyUrl({ kind: "customer_managed", arn: `arn:aws:iam::${A}:policy/deployer`, name: "deployer" }), `https://us-east-1.console.aws.amazon.com/iam/home#/policies/details/arn%3Aaws%3Aiam%3A%3A${A}%3Apolicy%2Fdeployer?section=permissions`);
  assert.equal(ge.policyUrl({ kind: "inline", name: "read", holder: { kind: "user", name: "alice" } }), "https://us-east-1.console.aws.amazon.com/iam/home#/users/details/alice?section=permissions");
  assert.equal(ge.policyUrl({ kind: "inline", name: "ci", holder: { kind: "role", name: "vercel-ci" } }), "https://us-east-1.console.aws.amazon.com/iam/home#/roles/details/vercel-ci?section=permissions");
});

test("edgeProps: a path edge's facts as properties, empty ones left out", () => {
  assert.deepEqual(ge.edgeProps({}), {});
  assert.deepEqual(ge.edgeProps({ refs: "ref:refs/heads/main", environments: ["production"], names: [], note: null, account_id: A }), { refs: "ref:refs/heads/main", environments: ["production"], account_id: A });
});

test("accessProps: each kind of target keeps only its own fields", () => {
  const all = { level: "owner", admin: true, line: "x", write_services: [], deploy: "production", env_vars: "write", namespaces: [], direct: true, paths: ["team owner"], decision: "allowed", used_services: [], usage_days: 0 };
  assert.deepEqual(Object.keys(ge.accessProps("project", all)).sort(), ["admin", "decision", "deploy", "direct", "env_vars", "level", "line", "paths"]);
  assert.deepEqual(Object.keys(ge.accessProps("account", all)).sort(), ["admin", "decision", "direct", "level", "line", "paths", "write_services"]);
  assert.ok(!("namespaces" in ge.accessProps("cluster", all)), "an access entry for the whole cluster names no namespaces");
});

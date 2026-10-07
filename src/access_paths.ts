/**
 * What a person can touch, through every way the stored inventory shows: the grants their identities hold directly
 * and the paths from one principal to another.
 *
 * Direct, per identity and account (CAN_ACCESS): an IAM user's own grade (src/entitlements.ts), each Identity Center
 * assignment through the AWSReservedSSO_* role its permission set is provisioned as, the root user (everything), a
 * Vercel member's team role (or a project role, for contributors) on each project, an EKS access entry or aws-auth
 * mapping on a cluster.
 *
 * Paths (each a step the person can take, with how sure the inventory is: allowed, conditional, denied):
 * - CAN_ASSUME: a role's trust names the principal (or its account, and the principal's policies allow
 *   sts:AssumeRole on the role); an Identity Center user assumes the reserved role of each assignment; a GitHub
 *   repository's workflows assume a role whose trust names the repository (AdvisorRepository).
 * - CAN_SHELL_INTO: the principal's policies allow ssm:StartSession (or ec2-instance-connect:SendSSHPublicKey) on an
 *   instance; the instance RUNS_AS its instance profile's role, so a shell is that role's permissions.
 * - CAN_ACCESS a Vercel project with a role that deploys: the project RUNS_AS the role its OIDC trust names (src/vercel_aws_links.ts)
 *   and HOLDS_KEY_OF the IAM user whose static key sits in its environment variables.
 *
 * `reach` walks those from a person's identities and folds every principal reached into one grade per account:
 * the highest level, the services, administrator or not, and the paths that lead there. Pure over `AccessWorld`;
 * `accessWorld()` loads it from the database.
 */
import { db } from "./db.js";
import { allowsCompiled, compile, describeServices, LEVEL_RANK, weaker, type Decision, type Grants, type ServiceLevel, type Statement } from "./policy_facts.js";
import { entitlementsMeta, lastAccessedRead, listClusterAccess, listEntitlements, listPrincipals, policyDocs, principalDocs, usedServices, type PrincipalRow, type StoredEntitlement } from "./entitlements.js";
import { permissionSetOfRole } from "./sso_inventory.js";
import { listActors, listPeople, type Actor, type Person } from "./sign_ins.js";
import { oidcLinks, staticKeyVars } from "./vercel_aws_links.js";
import { teamExtras, vercelTeam } from "./adapters/vercel/inventory.js";
import { memberNodeId } from "./adapters/vercel/index.js";
import { personId as personIdOf } from "./graph_access.js";

export type EdgeKind = "CAN_ASSUME" | "CAN_SHELL_INTO" | "RUNS_AS" | "HOLDS_KEY_OF" | "CAN_ACCESS";
export interface PathEdge { from: string; to: string; kind: EdgeKind; via: string; decision: Decision; detail: Record<string, unknown> }
/** A direct grant: an identity on an account (through a principal's grade), a project, or a cluster. */
export interface Grant {
  identity: string; target: string; target_kind: "account" | "project" | "cluster"; via: string; decision: Decision;
  /** the principal whose grade applies (the IAM user, the reserved role); null for a project or cluster */
  principal: string | null; level: string; admin: boolean; line: string; write_services: string[]; permissions_services: string[]; every: boolean;
  /** each service's level, for folding several grants on one account into one line */
  services: ServiceLevel[]; resource_access_services: string[];
  /** Vercel: what the role lets the member do on the project */
  deploy?: "production" | "preview" | "none"; env_vars?: "write" | "preview" | "read" | "none";
  /** a cluster access entry limited to these namespaces */
  namespaces?: string[];
}

export interface InstanceRow { id: string; arn: string; account_id: string; region: string | null; profile: string | null; ssm: boolean; name: string | null }
export interface RoleTrustRow { arn: string; name: string; account_id: string | null; principals: { kind: string; who: string; account_id: string | null; scope: string[]; external_id: boolean }[] }
export interface AccessWorld {
  actors: Actor[]; principals: PrincipalRow[]; entitlements: Map<string, StoredEntitlement>; docs: Map<string, any>;
  roles: RoleTrustRow[]; sso: { user_id: string; user_name: string; assignments: { account_id: string; permission_set: string; via: string }[] }[];
  instances: InstanceRow[]; cluster_access: { cluster_arn: string; principal_arn: string; via: string; level: string; groups: string[]; namespaces: string[] }[];
  vercel: { team_id: string; members: { id: string; uid: string; role: string | null }[]; project_roles: { project_id: string; uid: string; role: string; via: string }[]; projects: { id: string; name: string }[];
    oidc: { project_id: string; role_arn: string; environments: string[] }[]; keys: { project_id: string; user_arn: string; names: string[]; targets: string[] }[] } | null;
  used: Map<string, Map<string, string>>; usage_read: Set<string>;
  /** the oldest stored CloudTrail write: how far back "changed nothing" holds */
  trail_since?: string | null;
}

// ---- Vercel roles (https://vercel.com/docs/rbac/access-roles) -----------------------------------------------------

/** What a team role or project role lets a member do on a project. Pure. */
export function vercelCapability(teamRole: string | null, projectRole: string | null): { level: string; deploy: "production" | "preview" | "none"; env_vars: "write" | "preview" | "read" | "none" } | null {
  const t = (teamRole ?? "").toUpperCase(); const p = (projectRole ?? "").toUpperCase();
  // owners and members act as project administrators everywhere; developers as project developers; billing, security and viewers as project viewers
  if (t === "OWNER" || t === "MEMBER" || p === "ADMIN" || p === "PROJECT_ADMIN") return { level: t === "OWNER" ? "owner" : "project_admin", deploy: "production", env_vars: "write" };
  if (t === "DEVELOPER" || p === "PROJECT_DEVELOPER") return { level: "project_developer", deploy: "production", env_vars: "preview" };
  if (["BILLING", "SECURITY", "VIEWER", "VIEWER_FOR_PLUS", "ENTERPRISE_VIEWER", "PRO_VIEWER"].includes(t) || p === "PROJECT_VIEWER") return { level: "project_viewer", deploy: "none", env_vars: "read" };
  return null; // a contributor with no role on the project cannot see it
}

// ---- the edges ---------------------------------------------------------------------------------------------------

const roleKey = (account: string | null, name: string) => `${account ?? ""}/${name.toLowerCase()}`;
const tail = (arn: string) => arn.split("/").pop() ?? arn;
const accountOfArn = (arn: string) => /^arn:aws[^:]*:(iam|sts|ec2)::?[^:]*:(\d{12}):/.exec(arn)?.[2] ?? /::(\d{12}):/.exec(arn)?.[1] ?? null;
const levelOrder = (l: string) => (LEVEL_RANK as Record<string, number>)[l] ?? (l === "admin" ? 6 : 0);
const writes = (g: Grants | null | undefined) => (g?.every ? ["*"] : g?.write_services ?? []);

/** The direct grants and the path edges of a world. Pure. */
export function accessEdges(w: AccessWorld): { grants: Grant[]; edges: PathEdge[]; repositories: { id: string; name: string }[] } {
  const grants: Grant[] = []; const edges: PathEdge[] = [];
  const byArn = new Map(w.principals.map((p) => [p.arn, p]));
  const groups = new Map<string, Map<string, PrincipalRow>>();
  for (const p of w.principals.filter((x) => x.kind === "group")) { let m = groups.get(p.account_id); if (!m) { m = new Map(); groups.set(p.account_id, m); } m.set(p.name, p); }
  const compiled = new Map<string, { sts: Statement[]; boundary: Statement[] | null }>();
  const statements = (p: PrincipalRow) => {
    let c = compiled.get(p.arn);
    if (!c) { c = { sts: compile(principalDocs(p, groups.get(p.account_id) ?? new Map(), (a) => w.docs.get(a) ?? null)), boundary: p.boundary ? compile([{ doc: w.docs.get(p.boundary) ?? null, source: "boundary" }]) : null }; compiled.set(p.arn, c); }
    return c;
  };
  const can = (p: PrincipalRow, action: string, resource: string): Decision => {
    const c = statements(p); const own = allowsCompiled(c.sts, action, resource).decision;
    return c.boundary ? weaker(own, allowsCompiled(c.boundary, action, resource).decision) : own;
  };
  const gradeOf = (arn: string, identity: string, target: string, via: string, decision: Decision = "allowed"): Grant | null => {
    const e = w.entitlements.get(arn); if (!e) return null;
    return { identity, target, target_kind: "account", via, decision, principal: arn, level: e.grants.admin ? "admin" : e.grants.top ?? "none", admin: e.grants.admin, line: e.line, write_services: writes(e.grants), permissions_services: e.grants.permissions_services ?? [], every: Boolean(e.grants.every),
      services: (e.grants.services ?? []).map((x) => ({ service: x.service, top: x.top, scoped: x.scoped, conditional: x.conditional })), resource_access_services: e.grants.resource_access_services ?? [] };
  };
  const roleByName = new Map<string, PrincipalRow>(); for (const p of w.principals.filter((x) => x.kind === "role")) roleByName.set(roleKey(p.account_id, p.name), p);
  // people's principals: users, and roles that are not service-linked (an instance's or function's role is reached through its RUNS_AS)
  const candidates = w.principals.filter((p) => p.kind === "user" || (p.kind === "role" && !/^\/aws-service-role\//.test(p.path ?? "")));

  // direct: IAM users on their account, roots on theirs, Identity Center users through each assignment's reserved role
  for (const a of w.actors) {
    if (a.kind === "iam_user" && a.account_id) { const g = gradeOf(a.id, a.id, a.account_id, "IAM user"); if (g) grants.push(g); }
    if (a.kind === "root" && a.account_id) grants.push({ identity: a.id, target: a.account_id, target_kind: "account", via: "root user", decision: "allowed", principal: null, level: "admin", admin: true, line: "Root user: every action, beyond any policy but SCPs", write_services: ["*"], permissions_services: ["*"], every: true, services: [], resource_access_services: [] });
  }
  // roles on their own account (an Identity Center role's grant reaches its users through their assignments)
  for (const e of w.entitlements.values()) if (e.kind === "role" && !/^AWSReservedSSO_/.test(e.name)) { const g = gradeOf(e.arn, e.arn, e.account_id, "role"); if (g) grants.push(g); }
  for (const u of w.sso) for (const s of u.assignments) {
    const role = w.principals.find((p) => p.kind === "role" && p.account_id === s.account_id && permissionSetOfRole(p.name) === s.permission_set);
    const via = `permission set ${s.permission_set} (${s.via})`;
    if (!role) { grants.push({ identity: u.user_id, target: s.account_id, target_kind: "account", via, decision: "allowed", principal: null, level: "unknown", admin: false, line: `${s.permission_set} (not graded yet: the account's IAM has not been read)`, write_services: [], permissions_services: [], every: false, services: [], resource_access_services: [] }); continue; }
    const g = gradeOf(role.arn, u.user_id, s.account_id, via); if (g) grants.push(g);
    edges.push({ from: u.user_id, to: role.arn, kind: "CAN_ASSUME", via, decision: "allowed", detail: { account_id: s.account_id, permission_set: s.permission_set } });
  }

  // roles: who their trust lets in, and whether those principals' own policies let them call sts:AssumeRole on it
  const repos = new Map<string, string>();
  for (const r of w.roles) {
    // a pipeline's way in needs only the trust; a principal's needs its own policies too, read with the account's IAM
    for (const t of r.principals) if (t.kind === "github_actions") for (const s of t.scope) { const repo = s.split(":")[0]; if (!repo) continue; const id = `github:${repo}`; repos.set(id, repo); edges.push({ from: id, to: r.arn, kind: "CAN_ASSUME", via: "GitHub Actions OIDC", decision: "allowed", detail: { refs: s.split(":").slice(1).join(":") || "*" } }); }
    const target = byArn.get(r.arn); if (!target) continue;
    for (const t of r.principals) {
      if (!["same_account", "org_account", "external_account"].includes(t.kind) || !t.account_id) continue;
      const cond = t.external_id ? "conditional" as const : "allowed" as const;
      const wholeAccount = /^account \d{12}$/.test(t.who);
      const named = wholeAccount ? null : `arn:aws:iam::${t.account_id}:${t.who}`;
      for (const p of candidates) {
        if (p.arn === r.arn || p.account_id !== t.account_id) continue;
        if (named && !(named === p.arn || named.replace(/:(user|role)\/.*\//, ":$1/") === p.arn.replace(/:(user|role)\/.*\//, ":$1/") || (/[*?]/.test(named) && new RegExp(`^${named.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*")}$`).test(p.arn)))) continue;
        // a trust that names the principal itself in the same account needs nothing more; otherwise its own policies must allow the call
        const own = named && p.account_id === target.account_id ? "allowed" : can(p, "sts:AssumeRole", r.arn);
        if (own === "denied") continue;
        edges.push({ from: p.arn, to: r.arn, kind: "CAN_ASSUME", via: named ? "trust names it" : `trust names account ${t.account_id}`, decision: weaker(own, cond), detail: { account_id: target.account_id } });
      }
    }
  }

  // instances: their role, and who may open a shell on them
  const byProfile = new Map<string, PrincipalRow>(); for (const p of w.principals) for (const ip of p.instance_profiles) byProfile.set(ip, p);
  for (const i of w.instances) {
    const role = i.profile ? byProfile.get(i.profile) : undefined;
    if (role) edges.push({ from: i.id, to: role.arn, kind: "RUNS_AS", via: "instance profile", decision: "allowed", detail: { profile: tail(i.profile!) } });
    for (const p of candidates) {
      if (p.account_id !== i.account_id) continue;
      const ssm = i.ssm ? can(p, "ssm:StartSession", i.arn) : "denied";
      const eic = can(p, "ec2-instance-connect:SendSSHPublicKey", i.arn);
      if (ssm !== "denied") edges.push({ from: p.arn, to: i.id, kind: "CAN_SHELL_INTO", via: "Session Manager", decision: ssm, detail: {} });
      else if (eic !== "denied") edges.push({ from: p.arn, to: i.id, kind: "CAN_SHELL_INTO", via: "EC2 Instance Connect", decision: eic === "allowed" ? "conditional" : eic, detail: { note: "needs a network path to port 22" } });
    }
  }

  // clusters: access entries and aws-auth name a role or user ARN; an Identity Center role is named without its path
  for (const c of w.cluster_access) {
    if (c.level === "none" || c.level === "node") continue;
    const acct = accountOfArn(c.principal_arn);
    const p = byArn.get(c.principal_arn) ?? (/:role\//.test(c.principal_arn) ? roleByName.get(roleKey(acct, tail(c.principal_arn))) : undefined) ?? w.principals.find((x) => x.kind === "user" && x.account_id === acct && x.name === tail(c.principal_arn));
    if (!p) continue;
    grants.push({ identity: p.arn, target: c.cluster_arn, target_kind: "cluster", via: c.via === "aws_auth" ? `aws-auth ${c.groups.join(", ") || "mapping"}` : `access entry${c.namespaces.length ? ` (${c.namespaces.join(", ")})` : ""}`, decision: "allowed", principal: null, level: c.level, admin: c.level === "cluster_admin", line: `${c.level.replace("_", " ")}${c.namespaces.length ? ` in ${c.namespaces.join(", ")}` : ""}`, write_services: [], permissions_services: [], every: false, services: [], resource_access_services: [], namespaces: c.namespaces });
  }

  // Vercel: each member's role on each project, the project's OIDC role and the IAM keys in its variables
  if (w.vercel) {
    const v = w.vercel;
    for (const m of v.members) for (const p of v.projects) {
      const pr = v.project_roles.find((x) => x.uid === m.uid && x.project_id === p.id);
      const c = vercelCapability(m.role, pr?.role ?? null); if (!c) continue;
      grants.push({ identity: m.id, target: p.id, target_kind: "project", via: pr ? `${pr.role.toLowerCase()} (${pr.via})` : `team ${String(m.role ?? "").toLowerCase()}`, decision: "allowed", principal: null, level: c.level, admin: c.level === "owner" || c.level === "project_admin", line: `${c.level.replace("_", " ")}: deploys ${c.deploy}, environment variables ${c.env_vars}`, write_services: [], permissions_services: [], every: false, services: [], resource_access_services: [], deploy: c.deploy, env_vars: c.env_vars });
    }
    for (const l of v.oidc) edges.push({ from: l.project_id, to: l.role_arn, kind: "RUNS_AS", via: "Vercel OIDC", decision: "allowed", detail: { environments: l.environments } });
    for (const k of v.keys) edges.push({ from: k.project_id, to: k.user_arn, kind: "HOLDS_KEY_OF", via: `environment variables ${k.names.join(", ")}`, decision: "conditional", detail: { names: k.names, targets: k.targets, note: "matched by when the key and the variable were created" } });
  }
  return { grants, edges, repositories: [...repos].map(([id, name]) => ({ id, name })) };
}

// ---- reach: from a person to everything -------------------------------------------------------------------------------

export interface ReachPath { steps: string[]; decision: Decision }
export interface AccountReach {
  account_id: string; level: string; admin: boolean; every: boolean;
  /** what the person's own assignments grant, then what only a path adds ("…; through a path: Write on ec2, s3") */
  line: string; write_services: string[]; permissions_services: string[]; resource_access_services: string[];
  /** the services only a path reaches (a role they may assume, an instance's role, a project's OIDC role), not their own grants */
  path_services: string[];
  /** the services the person's own sessions changed (CloudTrail) or authenticated to (last accessed: their IAM users, and an Identity Center role nobody else is assigned) */
  used_services: string[];
  /** granted write services unused in `usage_days` (null when nothing about their use is known) */
  unused_write_services: string[] | null; usage_days: number;
  direct: boolean; paths: ReachPath[]; principals: string[];
}
export interface PersonReach {
  person_id: string; accounts: AccountReach[];
  projects: { project_id: string; name: string; level: string; deploy: string; env_vars: string; via: string }[];
  clusters: { cluster_arn: string; level: string; via: string; paths: ReachPath[] }[];
  shells: { instance_id: string; name: string | null; account_id: string; via: string; decision: Decision; runs_as: string | null; paths: ReachPath[] }[];
  roles: { arn: string; name: string; account_id: string | null; admin: boolean; decision: Decision; paths: ReachPath[] }[];
  escalation: { principal: string; actions: string[] }[];
  read_at: string | null; notes: string[];
}

const label = (id: string, w: AccessWorld, names: Map<string, string>) => names.get(id) ?? (w.principals.find((p) => p.arn === id)?.name) ?? tail(id);

/**
 * Everything one person reaches: breadth first from their identities over the edges, at most four steps, keeping the
 * strongest path to each principal. Pure.
 */
export function reach(person: Person, w: AccessWorld, built = accessEdges(w), touched: Map<string, Map<string, Set<string>>> = new Map()): PersonReach {
  const names = new Map<string, string>(w.actors.map((a) => [a.id, a.kind === "sso_user" ? `${a.name} (Identity Center)` : a.kind === "vercel_member" ? `${a.name} (Vercel)` : a.kind === "root" ? `root of ${a.account_id}` : a.name]));
  for (const i of w.instances) names.set(i.id, i.name ? `${i.name} (${i.id})` : i.id);
  for (const p of w.vercel?.projects ?? []) names.set(p.id, `Vercel project ${p.name}`);
  const out = new Map<string, Map<string, PathEdge[]>>(); for (const e of built.edges) { let m = out.get(e.from); if (!m) { m = new Map(); out.set(e.from, m); } m.set(`${e.kind}>${e.to}`, [...(m.get(`${e.kind}>${e.to}`) ?? []), e]); }
  const grantsOf = new Map<string, Grant[]>(); for (const g of built.grants) grantsOf.set(g.identity, [...(grantsOf.get(g.identity) ?? []), g]);
  const rank = (d: Decision) => (d === "allowed" ? 2 : d === "conditional" ? 1 : 0);
  // the best path to every node: steps (labels) and the weakest decision along it
  const best = new Map<string, ReachPath>();
  const queue: { id: string; path: ReachPath; depth: number }[] = [];
  for (const i of person.identities) { const p = { steps: [label(i.id, w, names)], decision: "allowed" as Decision }; best.set(i.id, p); queue.push({ id: i.id, path: p, depth: 0 }); }
  // a project is entered only with a role that deploys; its OIDC role only for the environments that role reaches
  const projectEntry = new Map<string, Grant>();
  while (queue.length) {
    const { id, path, depth } = queue.shift()!;
    if (depth >= 4) continue;
    const next: { to: string; step: string; decision: Decision }[] = [];
    for (const [, es] of out.get(id) ?? []) for (const e of es) {
      if (e.kind === "RUNS_AS" && e.via === "Vercel OIDC") { const g = projectEntry.get(id); if (!g || g.deploy === "none") continue; const envs = (e.detail.environments as string[]) ?? []; if (g.deploy === "preview" && envs.every((x) => x === "production")) continue; }
      if (e.kind === "HOLDS_KEY_OF") { const g = projectEntry.get(id); if (!g || (g.deploy === "none" && g.env_vars === "none")) continue; }
      const verb = e.kind === "CAN_ASSUME" ? `assumes ${label(e.to, w, names)}` : e.kind === "CAN_SHELL_INTO" ? `opens a shell on ${label(e.to, w, names)} (${e.via})` : e.kind === "RUNS_AS" ? `runs as ${label(e.to, w, names)}` : e.kind === "HOLDS_KEY_OF" ? `holds the key of ${label(e.to, w, names)}` : label(e.to, w, names);
      next.push({ to: e.to, step: `${verb}${e.kind === "CAN_ASSUME" ? ` (${e.via})` : ""}`, decision: e.decision });
    }
    for (const g of grantsOf.get(id) ?? []) if (g.target_kind === "project" && (g.deploy !== "none" || g.env_vars !== "none")) { projectEntry.set(g.target, g); next.push({ to: g.target, step: `${g.level.replace("_", " ")} on ${label(g.target, w, names)}`, decision: "allowed" }); }
    for (const n of next) {
      const p: ReachPath = { steps: [...path.steps, n.step], decision: weaker(path.decision, n.decision) };
      const cur = best.get(n.to);
      if (p.decision === "denied" || (cur && (rank(cur.decision) > rank(p.decision) || (rank(cur.decision) === rank(p.decision) && cur.steps.length <= p.steps.length)))) continue;
      best.set(n.to, p); queue.push({ id: n.to, path: p, depth: depth + 1 });
    }
  }
  const own = new Set(person.identities.map((i) => i.id));
  // accounts: every account grant of every node reached, folded
  const accounts = new Map<string, AccountReach>();
  const fold = new Map<string, { own: Map<string, ServiceLevel>; path: Map<string, ServiceLevel>; ownLines: string[]; pathLines: string[] }>();
  const keep = (m: Map<string, ServiceLevel>, x: ServiceLevel) => { const c = m.get(x.service); m.set(x.service, !c ? { ...x } : { service: x.service, top: LEVEL_RANK[x.top] > LEVEL_RANK[c.top] ? x.top : c.top, scoped: c.scoped && x.scoped, conditional: c.conditional && x.conditional }); };
  for (const [id, path] of best) for (const g of grantsOf.get(id) ?? []) {
    if (g.target_kind !== "account") continue;
    const fresh = !accounts.has(g.target); const mine = own.has(id);
    const a = accounts.get(g.target) ?? { account_id: g.target, level: g.level, admin: false, every: false, line: "", write_services: [], permissions_services: [], resource_access_services: [], path_services: [], used_services: [], unused_write_services: null, usage_days: 0, direct: false, paths: [], principals: [] };
    const f = fold.get(g.target) ?? { own: new Map(), path: new Map(), ownLines: [], pathLines: [] }; fold.set(g.target, f);
    if (fresh || levelOrder(g.level) > levelOrder(a.level)) a.level = g.level;
    a.admin ||= g.admin; a.every ||= g.every; a.direct ||= mine;
    for (const x of g.services) keep(mine ? f.own : f.path, x);
    // a grant with no service list (the root user, every service, not graded yet) speaks for itself
    if (!g.services.length || g.every) (mine ? f.ownLines : f.pathLines).push(g.line);
    a.write_services = [...new Set([...a.write_services, ...g.write_services])].sort(); a.permissions_services = [...new Set([...a.permissions_services, ...g.permissions_services])].sort();
    a.resource_access_services = [...new Set([...a.resource_access_services, ...g.resource_access_services])].sort();
    if (g.principal && !a.principals.includes(g.principal)) a.principals.push(g.principal);
    const steps = mine ? [...path.steps, g.via] : path.steps;
    if (a.paths.length < 8 && !a.paths.some((x) => x.steps.join(">") === steps.join(">"))) a.paths.push({ steps, decision: path.decision });
    accounts.set(g.target, a);
  }
  for (const a of accounts.values()) {
    const f = fold.get(a.account_id)!;
    const onlyPath = [...f.path.values()].filter((x) => { const o = f.own.get(x.service); return !o || LEVEL_RANK[x.top] > LEVEL_RANK[o.top]; });
    a.path_services = onlyPath.filter((x) => LEVEL_RANK[x.top] >= LEVEL_RANK.write).map((x) => x.service).sort();
    const mine = [...new Set([...f.ownLines, describeServices([...f.own.values()])])].filter(Boolean).join("; ");
    const theirs = [...new Set([...f.pathLines, describeServices(onlyPath)])].filter(Boolean).join("; ");
    a.line = [mine || (a.direct ? "" : "Nothing of their own"), theirs ? `through a path: ${theirs}` : ""].filter(Boolean).join("; ");
  }
  // used: the services this person's own sessions changed (CloudTrail writes) and authenticated to (last accessed) — their
  // IAM users', and an Identity Center role's when nobody else is assigned its permission set in that account
  // people per (account, permission set): a user assigned directly and through a group is still one
  const holders = new Map<string, Set<string>>(); for (const u of w.sso) for (const s of u.assignments) { const k = `${s.account_id}|${s.permission_set}`; holders.set(k, (holders.get(k) ?? new Set()).add(u.user_id)); }
  const assignees = new Map([...holders].map(([k, v]) => [k, v.size]));
  const trailDays = w.trail_since ? Math.min(90, Math.floor((Date.now() - Date.parse(w.trail_since)) / 86_400_000)) : 0;
  for (const a of accounts.values()) {
    const used = new Set<string>(); let lastAccessed = false;
    for (const i of person.identities) {
      for (const s of touched.get(i.id)?.get(a.account_id) ?? []) used.add(s);
      if (i.kind === "iam_user" && i.account_id === a.account_id && w.usage_read.has(i.id)) { lastAccessed = true; for (const s of w.used.get(i.id)?.keys() ?? []) used.add(s); }
      if (i.kind === "sso_user") for (const s of w.sso.find((u) => u.user_id === i.id)?.assignments ?? []) {
        if (s.account_id !== a.account_id || assignees.get(`${s.account_id}|${s.permission_set}`) !== 1) continue;
        const role = w.principals.find((p) => p.kind === "role" && p.account_id === s.account_id && permissionSetOfRole(p.name) === s.permission_set);
        if (role && w.usage_read.has(role.arn)) { lastAccessed = true; for (const x of w.used.get(role.arn)?.keys() ?? []) used.add(x); }
      }
    }
    a.used_services = [...used].sort();
    a.usage_days = lastAccessed ? 90 : trailDays;
    a.unused_write_services = !a.usage_days ? null : a.every ? [] : a.write_services.filter((s) => s !== "*" && !used.has(s) && !a.path_services.includes(s));
  }
  const projects = (built.grants.filter((g) => g.target_kind === "project" && own.has(g.identity))).map((g) => ({ project_id: g.target, name: w.vercel?.projects.find((p) => p.id === g.target)?.name ?? g.target, level: g.level, deploy: g.deploy ?? "none", env_vars: g.env_vars ?? "none", via: g.via }));
  const clusters = new Map<string, PersonReach["clusters"][number]>();
  for (const [id, path] of best) for (const g of grantsOf.get(id) ?? []) if (g.target_kind === "cluster") { const c = clusters.get(g.target) ?? { cluster_arn: g.target, level: g.level, via: g.via, paths: [] }; if (levelOrder(g.level) > levelOrder(c.level)) { c.level = g.level; c.via = g.via; } if (c.paths.length < 5) c.paths.push(path); clusters.set(g.target, c); }
  const shells = w.instances.filter((i) => best.has(i.id)).map((i) => { const via = [...best.keys()].flatMap((k) => (out.get(k)?.get(`CAN_SHELL_INTO>${i.id}`) ?? [])).map((e) => e.via)[0] ?? "Session Manager"; const runs = built.edges.find((e) => e.from === i.id && e.kind === "RUNS_AS"); return { instance_id: i.id, name: i.name, account_id: i.account_id, via, decision: best.get(i.id)!.decision, runs_as: runs ? tail(runs.to) : null, paths: [best.get(i.id)!] }; });
  const roles = w.principals.filter((p) => p.kind === "role" && best.has(p.arn) && !own.has(p.arn)).map((p) => ({ arn: p.arn, name: p.name, account_id: p.account_id, admin: Boolean(w.entitlements.get(p.arn)?.grants.admin), decision: best.get(p.arn)!.decision, paths: [best.get(p.arn)!] }))
    .sort((a, b) => Number(b.admin) - Number(a.admin) || a.name.localeCompare(b.name));
  const escalation = [...best.keys()].map((id) => ({ principal: id, actions: w.entitlements.get(id)?.escalation ?? [] })).filter((x) => x.actions.length).map((x) => ({ principal: label(x.principal, w, names), actions: x.actions.slice(0, 12) }));
  const notes: string[] = [];
  if (!w.entitlements.size) notes.push("No IAM policies read yet: run the inventory (or Refresh) so each account's users, groups, roles and policies are graded.");
  if (!w.usage_read.size) notes.push("Service last-accessed data has not been read yet: unused permissions show once it has.");
  return { person_id: person.key, accounts: [...accounts.values()].sort((a, b) => levelOrder(b.level) - levelOrder(a.level) || a.account_id.localeCompare(b.account_id)), projects, clusters: [...clusters.values()], shells, roles, escalation, read_at: entitlementsMeta().read_at, notes };
}

// ---- loading ----------------------------------------------------------------------------------------------------------

const rows = (sql: string, ...p: unknown[]): any[] => { try { return db.prepare(sql).all(...p) as any[]; } catch { return []; } };
const parse = (s: unknown, d: any = null): any => { if (typeof s !== "string") return s ?? d; try { return JSON.parse(s); } catch { return d; } };

/** Everything `accessEdges` and `reach` read, from the stored inventory. */
export function accessWorld(actors: Actor[] = listActors(null)): AccessWorld {
  const principals = listPrincipals();
  const entitlements = new Map(listEntitlements(null).map((e) => [e.arn, e]));
  const roles = rows("select arn, name, account_id, principals from inventory_iam_role where gone = 0").map((r) => ({ arn: r.arn, name: r.name, account_id: r.account_id, principals: parse(r.principals, []) }));
  const sso = rows("select user_id, user_name, assignments from inventory_sso_user where gone = 0 and coalesce(status, 'ENABLED') <> 'DISABLED'").map((r) => ({ user_id: r.user_id, user_name: r.user_name, assignments: parse(r.assignments, []) }));
  const instances: InstanceRow[] = rows("select instance_id, account_id, region, name, ssm_status, snapshot from inventory_ec2 where gone = 0 and coalesce(state, '') not in ('terminated', 'shutting-down')").map((r) => {
    const snap = parse(r.snapshot, {}); const arn = snap?.identity?.arn ?? `arn:aws:ec2:${r.region}:${r.account_id}:instance/${r.instance_id}`;
    return { id: r.instance_id, arn, account_id: r.account_id ?? accountOfArn(arn) ?? "", region: r.region, profile: snap?.identity?.iam_instance_profile_arn ?? null, ssm: Boolean(r.ssm_status), name: r.name ?? null };
  });
  let vercel: AccessWorld["vercel"] = null;
  const team = vercelTeam();
  if (team) {
    const x = teamExtras(team.id);
    vercel = { team_id: team.id, members: x.members.filter((m) => m.confirmed).map((m) => ({ id: memberNodeId(team.id, m), uid: m.uid, role: m.role })), project_roles: x.project_roles ?? [],
      projects: rows("select id, name from vercel_projects where gone = 0"), oidc: oidcLinks().map((l) => ({ project_id: l.project_id, role_arn: l.role_arn, environments: l.environments })),
      keys: staticKeyVars().filter((k) => k.candidates[0]).map((k) => ({ project_id: k.project_id, user_arn: k.candidates[0].user_arn, names: k.names, targets: k.targets })) };
  }
  const trail_since = (rows("select min(event_time) as t from trail_events")[0]?.t as string | undefined) ?? null;
  return { actors, principals, entitlements, docs: policyDocs(), roles, sso, instances, cluster_access: listClusterAccess(), vercel, used: usedServices(90), usage_read: lastAccessedRead(), trail_since };
}

/** CloudTrail's event source as the IAM service prefix (most are the same; a few are not). Pure. */
export function serviceOfSource(source: string): string {
  const s = source.replace(/\.amazonaws\.com$/, "");
  return ({ monitoring: "cloudwatch", email: "ses", "elasticloadbalancing": "elasticloadbalancing", "es": "es", "sso-directory": "sso-directory", "signin": "signin" } as Record<string, string>)[s] ?? s;
}

/** Who made a stored CloudTrail write, as the identity node it belongs to. Pure given the lookups. */
export function trailIdentity(e: { principal_arn: string | null; identity_type: string | null; username: string | null; account_id: string | null }, ssoByName: Map<string, string>, roleArn: (account: string | null, name: string) => string | null): string | null {
  const arn = e.principal_arn ?? "";
  if (e.identity_type === "Root" || /:root$/.test(arn)) return arn || null;
  if (e.identity_type === "IAMUser" && /:user\//.test(arn)) return arn;
  const m = /^arn:aws[^:]*:sts::(\d{12}):assumed-role\/([^/]+)\/(.+)$/.exec(arn);
  if (m) {
    if (/^AWSReservedSSO_/.test(m[2])) { const u = ssoByName.get(m[3].toLowerCase()) ?? ssoByName.get((e.username ?? "").toLowerCase()); if (u) return u; }
    return roleArn(m[1], m[2]);
  }
  return null;
}

/** What each identity changed in the last `days`, from the stored CloudTrail writes: per identity, the resources (events, actions, last) and the services per account. */
export function touchedFromTrail(days = 90): { resources: { identity: string; resource: string; events: number; actions: string[]; last_at: string }[]; services: Map<string, Map<string, Set<string>>> } {
  const since = new Date(Date.now() - days * 86_400_000).toISOString();
  const ssoByName = new Map(rows("select user_id, user_name, email from inventory_sso_user where gone = 0").flatMap((r) => [[String(r.user_name).toLowerCase(), r.user_id], ...(r.email ? [[String(r.email).toLowerCase(), r.user_id]] : [])] as [string, string][]));
  const roles = new Map(rows("select arn, name, account_id from inventory_iam_role where gone = 0").map((r) => [roleKey(r.account_id, r.name), r.arn]));
  const per = new Map<string, { identity: string; resource: string; events: number; actions: Set<string>; last_at: string }>();
  const services = new Map<string, Map<string, Set<string>>>();
  for (const e of rows("select event_time, event_name, event_source, username, resource_name, account_id, principal_arn, identity_type from trail_events where event_time >= ? and coalesce(noise, 0) = 0 and error_code is null", since)) {
    const id = trailIdentity(e, ssoByName, (a, n) => roles.get(roleKey(a, n)) ?? null); if (!id) continue;
    const acct = e.account_id ?? accountOfArn(e.principal_arn ?? "");
    if (acct) { let m = services.get(id); if (!m) { m = new Map(); services.set(id, m); } let s = m.get(acct); if (!s) { s = new Set(); m.set(acct, s); } s.add(serviceOfSource(String(e.event_source))); }
    if (!e.resource_name) continue;
    const k = `${id}|${e.resource_name}`; const cur = per.get(k) ?? { identity: id, resource: String(e.resource_name), events: 0, actions: new Set<string>(), last_at: e.event_time };
    cur.events++; if (cur.actions.size < 12) cur.actions.add(String(e.event_name)); if (e.event_time > cur.last_at) cur.last_at = e.event_time; per.set(k, cur);
  }
  return { resources: [...per.values()].map((r) => ({ ...r, actions: [...r.actions].sort() })), services };
}

/** One person's reach, by node id (`person:<key>`) or the person's group key. */
export function personReach(personId: string): PersonReach | null {
  const actors = listActors(null); const people = listPeople(actors);
  // the page's key is its scoped grouping's (an account picked leaves out the Vercel member): any identity in it finds the person
  const ids = new Set(personId.split("|"));
  const hit = people.find((p) => personIdOf(p) === personId || p.key === personId) ?? people.find((p) => p.identities.some((i) => ids.has(i.id)));
  if (!hit) return null;
  const w = accessWorld(actors);
  return { ...reach(hit, w, accessEdges(w), touchedFromTrail(90).services), person_id: personIdOf(hit) ?? hit.key };
}

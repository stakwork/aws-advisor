/**
 * What every IAM principal may do, per account: the policy documents behind each user, group and role (one
 * iam:GetAccountAuthorizationDetails per account, the AWS-managed documents read once with iam:GetPolicyVersion and
 * shared), the organisation's service control policies along each account's path (organizations:DescribePolicy from
 * the management account), and the effective grade (src/policy_facts.ts): the principal's own and its groups'
 * policies, within its permissions boundary and the SCPs. Identity Center permission sets are graded through the
 * AWSReservedSSO_* role each one is provisioned as in an account, which carries exactly its policies there.
 *
 * Granted is not used: iam:GenerateServiceLastAccessedDetails says, per principal and service, when it last
 * authenticated there (AWS keeps 400 days), read once a day for the users and the roles people or pipelines assume.
 *
 * And the clusters: who an EKS cluster lets in (access entries with their access policies, eks:ListAccessEntries)
 * and what its aws-auth ConfigMap maps, read when the advisor can reach the cluster's API (src/k8s_client.ts).
 *
 * Tables: iam_principal, iam_policy_doc, entitlement, service_last_accessed, cluster_access. src/access_paths.ts
 * builds the paths between them; src/graph_entitlements.ts mirrors both.
 */
import { GenerateServiceLastAccessedDetailsCommand, GetAccountAuthorizationDetailsCommand, GetPolicyCommand, GetPolicyVersionCommand, GetServiceLastAccessedDetailsCommand, IAMClient } from "@aws-sdk/client-iam";
import { DescribePolicyCommand, ListParentsCommand, ListPoliciesCommand, ListTargetsForPolicyCommand, OrganizationsClient } from "@aws-sdk/client-organizations";
import { DescribeAccessEntryCommand, EKSClient, ListAccessEntriesCommand, ListAssociatedAccessPoliciesCommand } from "@aws-sdk/client-eks";
import { db, getJsonSetting, setSetting } from "./db.js";
import { accountCredentials, listAccounts } from "./accounts.js";
import { describeError, noteSuccess } from "./permissions.js";
import { ensureServices, servicesNamed, storedCatalogue } from "./service_reference.js";
import { canEscalate, docOf, grade, gradeLine, intersect, permsOf, type Catalogue, type Grants, type Perms } from "./policy_facts.js";
import { accountWhere, type AccountScope } from "./scope.js";

db.exec(`create table if not exists iam_principal (
  arn text primary key, account_id text, kind text not null, name text not null, path text, groups text not null default '[]', attached text not null default '[]', inline text not null default '[]',
  boundary text, instance_profiles text not null default '[]', last_used text, updated_at text not null, gone integer not null default 0
);
create index if not exists iam_principal_account on iam_principal(account_id, kind);
create table if not exists iam_policy_doc (
  arn text primary key, name text not null, aws_managed integer not null default 0, account_id text, version text, document text, attachments integer, fetched_at text not null
);
create table if not exists entitlement (
  arn text primary key, account_id text, kind text not null, name text not null, top text, admin integer not null default 0, line text, grants text not null default '{}', escalation text not null default '[]',
  policies text not null default '[]', boundary text, scp text not null default '[]', updated_at text not null
);
create table if not exists service_last_accessed (
  arn text not null, service text not null, service_name text, last_at text, last_entity text, last_region text, read_at text not null, primary key (arn, service)
);
create table if not exists cluster_access (
  cluster_arn text not null, principal_arn text not null, via text not null, level text not null, groups text not null default '[]', policies text not null default '[]', namespaces text not null default '[]', username text, read_at text not null,
  primary key (cluster_arn, principal_arn, via)
)`);

const META = "entitlements_meta";
export interface EntitlementsMeta { read_at: string | null; took_ms: number | null; accounts: number; principals: number; scp: { org: boolean; policies: number; note: string | null }; last_accessed_at: string | null; last_accessed: number; clusters_at: string | null; errors: string[]; unknown_services: string[]; retired_policies?: string[] }
export const entitlementsMeta = (): EntitlementsMeta => getJsonSetting<EntitlementsMeta>(META, { read_at: null, took_ms: null, accounts: 0, principals: 0, scp: { org: false, policies: 0, note: null }, last_accessed_at: null, last_accessed: 0, clusters_at: null, errors: [], unknown_services: [] });

const parse = (s: unknown, d: any = null): any => { if (typeof s !== "string") return s ?? d; try { return JSON.parse(s); } catch { return d; } };
const rows = (sql: string, ...p: unknown[]): any[] => { try { return db.prepare(sql).all(...p) as any[]; } catch { return []; } };
const iso = (v: unknown): string | null => (v == null ? null : v instanceof Date ? v.toISOString() : String(v));
const AWS_MANAGED = /^arn:aws[^:]*:iam::aws:policy\//;
const policyName = (arn: string) => arn.split("/").pop() ?? arn;

export interface InlinePolicy { name: string; doc: any }
export interface PrincipalRow { arn: string; account_id: string; kind: "user" | "group" | "role"; name: string; path: string | null; groups: string[]; attached: string[]; inline: InlinePolicy[]; boundary: string | null; instance_profiles: string[]; last_used: string | null }

/** One GetAccountAuthorizationDetails page set into principal rows and the account's own managed policies. Pure. */
export function authorizationRows(accountId: string, pages: any[]): { principals: PrincipalRow[]; policies: { arn: string; name: string; version: string | null; document: any; attachments: number | null }[] } {
  const principals: PrincipalRow[] = []; const policies: { arn: string; name: string; version: string | null; document: any; attachments: number | null }[] = [];
  const inline = (list: any[] | undefined) => (list ?? []).map((p) => ({ name: String(p.PolicyName), doc: docOf(p.PolicyDocument) }));
  const attached = (list: any[] | undefined) => (list ?? []).map((p) => String(p.PolicyArn)).filter(Boolean);
  for (const pg of pages) {
    for (const u of pg.UserDetailList ?? []) principals.push({ arn: String(u.Arn), account_id: accountId, kind: "user", name: String(u.UserName), path: u.Path ?? null, groups: (u.GroupList ?? []).map(String), attached: attached(u.AttachedManagedPolicies), inline: inline(u.UserPolicyList), boundary: u.PermissionsBoundary?.PermissionsBoundaryArn ?? null, instance_profiles: [], last_used: null });
    for (const g of pg.GroupDetailList ?? []) principals.push({ arn: String(g.Arn), account_id: accountId, kind: "group", name: String(g.GroupName), path: g.Path ?? null, groups: [], attached: attached(g.AttachedManagedPolicies), inline: inline(g.GroupPolicyList), boundary: null, instance_profiles: [], last_used: null });
    for (const r of pg.RoleDetailList ?? []) principals.push({ arn: String(r.Arn), account_id: accountId, kind: "role", name: String(r.RoleName), path: r.Path ?? null, groups: [], attached: attached(r.AttachedManagedPolicies), inline: inline(r.RolePolicyList), boundary: r.PermissionsBoundary?.PermissionsBoundaryArn ?? null,
      instance_profiles: (r.InstanceProfileList ?? []).map((p: any) => String(p.Arn)).filter(Boolean), last_used: iso(r.RoleLastUsed?.LastUsedDate) });
    for (const p of pg.Policies ?? []) { const v = (p.PolicyVersionList ?? []).find((x: any) => x.IsDefaultVersion); policies.push({ arn: String(p.Arn), name: String(p.PolicyName), version: v?.VersionId ?? p.DefaultVersionId ?? null, document: docOf(v?.Document), attachments: p.AttachmentCount ?? null }); }
  }
  return { principals, policies };
}

/** The SCP documents that apply to an account, per level of its path (root, each OU, the account): the account's effective SCP is what every level allows. */
export interface ScpLevel { target: string; policies: { id: string; name: string; doc: any }[] }

/** The effective SCP set of an account: the union within a level, the intersection across levels. Pure. */
export function scpPerms(levels: ScpLevel[], cat: Catalogue): Perms | null {
  let acc: Perms | null = null;
  for (const l of levels) {
    if (!l.policies.length) continue;
    const p = permsOf(l.policies.map((x) => ({ doc: x.doc, source: `SCP ${x.name}` })), cat);
    acc = acc ? intersect(acc, p, cat) : p;
  }
  return acc;
}

/** The documents of a principal: its inline and attached policies, and for a user each group's. Pure given the lookups. */
export function principalDocs(p: PrincipalRow, groupsByName: Map<string, PrincipalRow>, policyDoc: (arn: string) => any): { doc: any; source: string; arn: string | null; via: string }[] {
  const out: { doc: any; source: string; arn: string | null; via: string }[] = [];
  const add = (q: PrincipalRow, via: string) => {
    for (const i of q.inline) out.push({ doc: i.doc, source: `${q.kind === "group" ? `group ${q.name} ` : ""}inline ${i.name}`, arn: null, via });
    for (const a of q.attached) out.push({ doc: policyDoc(a), source: policyName(a), arn: a, via });
  };
  add(p, "direct");
  for (const g of p.groups) { const gr = groupsByName.get(g); if (gr) add(gr, `group ${g}`); }
  return out;
}

export interface EntitlementRow { arn: string; account_id: string; kind: string; name: string; grants: Grants; line: string; escalation: string[]; policies: { name: string; arn: string | null; via: string; inline: boolean }[]; boundary: string | null; scp: string[] }

/** Grades every principal of one account. Pure given the catalogue. */
export function gradeAccount(principals: PrincipalRow[], policyDoc: (arn: string) => any, scp: { perms: Perms | null; names: string[] } | null, cat: Catalogue): EntitlementRow[] {
  const groups = new Map(principals.filter((p) => p.kind === "group").map((g) => [g.name, g]));
  const out: EntitlementRow[] = [];
  for (const p of principals) {
    const docs = principalDocs(p, groups, policyDoc);
    let perms = permsOf(docs, cat);
    if (p.boundary) perms = intersect(perms, permsOf([{ doc: policyDoc(p.boundary), source: `boundary ${policyName(p.boundary)}` }], cat), cat);
    // SCPs never limit service-linked roles
    const scpApplies = scp?.perms && !(p.kind === "role" && /^\/aws-service-role\//.test(p.path ?? ""));
    if (scpApplies) perms = intersect(perms, scp!.perms!, cat);
    const g = grade(perms, cat);
    out.push({ arn: p.arn, account_id: p.account_id, kind: p.kind, name: p.name, grants: g, line: gradeLine(g), escalation: canEscalate(g), policies: docs.map((d) => ({ name: d.source, arn: d.arn, via: d.via, inline: !d.arn })), boundary: p.boundary ? policyName(p.boundary) : null, scp: scpApplies ? scp!.names : [] });
  }
  return out;
}

async function pagesOf<T>(fn: (marker: string | undefined) => Promise<{ items: T; next: string | undefined }>, max = 50): Promise<T[]> {
  const out: T[] = []; let m: string | undefined;
  for (let i = 0; i < max; i++) { const r = await fn(m); out.push(r.items); if (!r.next) break; m = r.next; }
  return out;
}

/** The organisation's SCPs per account, read from the management account; null when the credentials are not the management account (or SCPs are off). */
async function readScps(accountIds: string[], onError: (m: string) => void): Promise<{ byAccount: Map<string, ScpLevel[]>; policies: number; note: string | null } | null> {
  const parent = accountCredentials(null);
  const org = new OrganizationsClient({ region: "us-east-1", credentials: parent.provider });
  try {
    const list = (await pagesOf(async (t) => { const r = await org.send(new ListPoliciesCommand({ Filter: "SERVICE_CONTROL_POLICY", NextToken: t })); return { items: r.Policies ?? [], next: r.NextToken }; })).flat();
    const byTarget = new Map<string, { id: string; name: string; doc: any }[]>();
    for (const p of list) {
      if (!p.Id) continue;
      const d = await org.send(new DescribePolicyCommand({ PolicyId: p.Id }));
      const doc = docOf(d.Policy?.Content);
      const targets = (await pagesOf(async (t) => { const r = await org.send(new ListTargetsForPolicyCommand({ PolicyId: p.Id!, NextToken: t })); return { items: r.Targets ?? [], next: r.NextToken }; })).flat();
      for (const t of targets) if (t.TargetId) byTarget.set(t.TargetId, [...(byTarget.get(t.TargetId) ?? []), { id: p.Id, name: String(p.Name ?? p.Id), doc }]);
    }
    noteSuccess(["organizations:ListPolicies", "organizations:DescribePolicy", "organizations:ListTargetsForPolicy"], "entitlements");
    const byAccount = new Map<string, ScpLevel[]>();
    for (const id of accountIds) {
      // the path from the account up to the root: account, its OU, the OU's parent … root; the levels apply root first
      const path: string[] = [id]; let cur = id;
      for (let i = 0; i < 6; i++) { const r = await org.send(new ListParentsCommand({ ChildId: cur })); const p = r.Parents?.[0]; if (!p?.Id) break; path.push(p.Id); if (p.Type === "ROOT") break; cur = p.Id; }
      byAccount.set(id, path.reverse().map((t) => ({ target: t, policies: byTarget.get(t) ?? [] })));
    }
    return { byAccount, policies: list.length, note: null };
  } catch (e: any) {
    const m = String(e?.name || e?.message || e);
    if (/AWSOrganizationsNotInUse|AccessDenied|not authorized|PolicyTypeNotEnabled/i.test(m)) return null;
    onError(`service control policies: ${describeError(e, "organizations:DescribePolicy")}`); return null;
  }
}

/** Reads every account's IAM principals and policies, the SCPs, and stores each principal's effective grade. */
export async function refreshEntitlements(onError: (m: string) => void = () => {}, onLog: (l: string) => void = () => {}): Promise<{ accounts: number; principals: number; took_ms: number }> {
  const t0 = Date.now(); const now = new Date().toISOString(); const errors: string[] = [];
  const err = (m: string) => { errors.push(m); onError(m); };
  const accounts = listAccounts().filter((a) => a.account_id && (a.is_parent || a.enabled));
  const all: PrincipalRow[] = []; const read = new Set<string>();
  const upPolicy = db.prepare(`insert into iam_policy_doc(arn, name, aws_managed, account_id, version, document, attachments, fetched_at) values (?, ?, ?, ?, ?, ?, ?, ?)
    on conflict(arn) do update set name = excluded.name, version = excluded.version, document = excluded.document, attachments = excluded.attachments, fetched_at = excluded.fetched_at`);
  for (const a of accounts) {
    try {
      const iam = new IAMClient({ region: "us-east-1", credentials: accountCredentials(a.account_id).provider });
      const pages = await pagesOf(async (m) => { const r = await iam.send(new GetAccountAuthorizationDetailsCommand({ Filter: ["User", "Role", "Group", "LocalManagedPolicy"], MaxItems: 1000, Marker: m })); return { items: r, next: r.IsTruncated ? r.Marker : undefined }; });
      const x = authorizationRows(a.account_id, pages);
      all.push(...x.principals); read.add(a.account_id);
      db.transaction(() => { for (const p of x.policies) upPolicy.run(p.arn, p.name, 0, a.account_id, p.version, JSON.stringify(p.document), p.attachments, now); })();
      noteSuccess(["iam:GetAccountAuthorizationDetails"], "entitlements");
    } catch (e: any) { err(`IAM authorization details (${a.account_id}): ${describeError(e, "iam:GetAccountAuthorizationDetails")}`); }
  }
  // the AWS-managed documents the principals attach: one read each, refreshed weekly, shared by every account
  const managed = [...new Set(all.flatMap((p) => [...p.attached, ...(p.boundary ? [p.boundary] : [])]).filter((x) => AWS_MANAGED.test(x)))];
  const cached = new Map(rows("select arn, fetched_at from iam_policy_doc where aws_managed = 1").map((r) => [r.arn, r.fetched_at]));
  const stale = managed.filter((m) => !cached.has(m) || Date.now() - Date.parse(cached.get(m)) > 7 * 86_400_000);
  const retired: string[] = [];
  if (stale.length) {
    const iam = new IAMClient({ region: "us-east-1", credentials: accountCredentials(null).provider });
    for (let i = 0; i < stale.length; i += 5) await Promise.all(stale.slice(i, i + 5).map(async (arn) => {
      try {
        const p = await iam.send(new GetPolicyCommand({ PolicyArn: arn })); const v = p.Policy?.DefaultVersionId;
        const d = v ? await iam.send(new GetPolicyVersionCommand({ PolicyArn: arn, VersionId: v })) : null;
        upPolicy.run(arn, policyName(arn), 1, null, v ?? null, JSON.stringify(docOf(d?.PolicyVersion?.Document)), p.Policy?.AttachmentCount ?? null, now);
      } catch (e: any) {
        // AWS retires managed policies (AWSElasticBeanstalkFullAccess): still attached somewhere, no longer readable; graded as granting nothing
        if (/NoSuchEntity|was not found/i.test(String(e?.name) + String(e?.message))) { retired.push(policyName(arn)); return; }
        err(`managed policy ${policyName(arn)}: ${describeError(e, "iam:GetPolicy, iam:GetPolicyVersion")}`);
      }
    }));
  }
  const docs = new Map(rows("select arn, document from iam_policy_doc").map((r) => [r.arn, parse(r.document)]));
  const scps = accounts.length > 1 || accounts.some((a) => a.is_parent) ? await readScps([...read], err) : null;
  // the catalogue: every service a document names
  const named = servicesNamed([...all.flatMap((p) => p.inline.map((i) => i.doc)), ...docs.values(), ...[...(scps?.byAccount.values() ?? [])].flatMap((ls) => ls.flatMap((l) => l.policies.map((p) => p.doc)))]);
  const sr = await ensureServices(named);
  for (const e of sr.errors.slice(0, 3)) err(e);
  const cat = storedCatalogue();
  const parentId = accounts.find((a) => a.is_parent)?.account_id ?? null;
  const upP = db.prepare(`insert into iam_principal(arn, account_id, kind, name, path, groups, attached, inline, boundary, instance_profiles, last_used, updated_at, gone) values (@arn, @account_id, @kind, @name, @path, @groups, @attached, @inline, @boundary, @instance_profiles, @last_used, @now, 0)
    on conflict(arn) do update set account_id = excluded.account_id, kind = excluded.kind, name = excluded.name, path = excluded.path, groups = excluded.groups, attached = excluded.attached, inline = excluded.inline, boundary = excluded.boundary, instance_profiles = excluded.instance_profiles, last_used = coalesce(excluded.last_used, iam_principal.last_used), updated_at = excluded.updated_at, gone = 0`);
  const upE = db.prepare(`insert into entitlement(arn, account_id, kind, name, top, admin, line, grants, escalation, policies, boundary, scp, updated_at) values (@arn, @account_id, @kind, @name, @top, @admin, @line, @grants, @escalation, @policies, @boundary, @scp, @now)
    on conflict(arn) do update set account_id = excluded.account_id, kind = excluded.kind, name = excluded.name, top = excluded.top, admin = excluded.admin, line = excluded.line, grants = excluded.grants, escalation = excluded.escalation, policies = excluded.policies, boundary = excluded.boundary, scp = excluded.scp, updated_at = excluded.updated_at`);
  let graded = 0;
  for (const acct of read) {
    const ps = all.filter((p) => p.account_id === acct);
    // SCPs never apply to the management account itself
    const levels = acct !== parentId ? scps?.byAccount.get(acct) : undefined;
    const scp = levels ? { perms: scpPerms(levels, cat), names: [...new Set(levels.flatMap((l) => l.policies.map((p) => p.name)))] } : null;
    const es = gradeAccount(ps, (arn) => docs.get(arn) ?? null, scp, cat);
    db.transaction(() => {
      for (const p of ps) upP.run({ ...p, groups: JSON.stringify(p.groups), attached: JSON.stringify(p.attached), inline: JSON.stringify(p.inline), instance_profiles: JSON.stringify(p.instance_profiles), now });
      for (const e of es) upE.run({ arn: e.arn, account_id: e.account_id, kind: e.kind, name: e.name, top: e.grants.top, admin: e.grants.admin ? 1 : 0, line: e.line, grants: JSON.stringify(e.grants), escalation: JSON.stringify(e.escalation), policies: JSON.stringify(e.policies), boundary: e.boundary, scp: JSON.stringify(e.scp), now });
      db.prepare("update iam_principal set gone = 1 where account_id = ? and updated_at <> ?").run(acct, now);
      db.prepare("delete from entitlement where account_id = ? and updated_at <> ?").run(acct, now);
    })();
    graded += es.length;
  }
  const m = entitlementsMeta();
  setSetting(META, JSON.stringify({ ...m, read_at: now, took_ms: Date.now() - t0, accounts: read.size, principals: graded, scp: { org: Boolean(scps), policies: scps?.policies ?? 0, note: scps ? null : "service control policies not read: the credentials are not the organisation's management account, or the organisation does not use SCPs" }, errors, unknown_services: sr.unknown, retired_policies: retired }));
  onLog(`entitlements: ${graded} principals graded in ${read.size} account(s)${scps ? `, ${scps.policies} SCPs` : ""}${sr.fetched ? `, ${sr.fetched} service references fetched` : ""}`);
  return { accounts: read.size, principals: graded, took_ms: Date.now() - t0 };
}

/**
 * When each user and each role people or pipelines assume last used each service (iam:GenerateServiceLastAccessedDetails,
 * a job per principal, then its report). Once a day at most; `force` reads again.
 */
export async function refreshLastAccessed(onError: (m: string) => void = () => {}, onLog: (l: string) => void = () => {}, force = false): Promise<{ principals: number; services: number }> {
  const m = entitlementsMeta();
  if (!force && m.last_accessed > 0 && m.last_accessed_at && Date.now() - Date.parse(m.last_accessed_at) < 20 * 3600_000) return { principals: 0, services: 0 };
  const now = new Date().toISOString();
  // users, and roles that are not only a service's (an instance's, a function's): those a person, a pipeline or another account assumes
  const serviceOnly = new Set(rows("select arn from inventory_iam_role where gone = 0 and trust = 'service'").map((r) => r.arn));
  const targets = rows("select arn, account_id, kind, path from iam_principal where gone = 0 and kind in ('user', 'role')").filter((p) => p.kind === "user" || (!serviceOnly.has(p.arn) && !/^\/aws-service-role\//.test(p.path ?? "")));
  const put = db.prepare(`insert into service_last_accessed(arn, service, service_name, last_at, last_entity, last_region, read_at) values (?, ?, ?, ?, ?, ?, ?)
    on conflict(arn, service) do update set service_name = excluded.service_name, last_at = coalesce(excluded.last_at, service_last_accessed.last_at), last_entity = excluded.last_entity, last_region = excluded.last_region, read_at = excluded.read_at`);
  let services = 0; let done = 0; let failed = 0;
  const byAccount = new Map<string, any[]>(); for (const t of targets) byAccount.set(t.account_id, [...(byAccount.get(t.account_id) ?? []), t]);
  for (const [acct, list] of byAccount) {
    const iam = new IAMClient({ region: "us-east-1", credentials: accountCredentials(acct).provider, maxAttempts: 8 });
    for (let i = 0; i < list.length; i += 10) await Promise.all(list.slice(i, i + 10).map(async (p) => {
      try {
        const job = (await iam.send(new GenerateServiceLastAccessedDetailsCommand({ Arn: p.arn, Granularity: "SERVICE_LEVEL" }))).JobId;
        for (let k = 0; k < 30 && job; k++) {
          await new Promise((r) => setTimeout(r, 1000 + k * 250));
          const r = await iam.send(new GetServiceLastAccessedDetailsCommand({ JobId: job, MaxItems: 1000 }));
          if (r.JobStatus === "IN_PROGRESS") continue;
          if (r.JobStatus === "FAILED") throw new Error(r.Error?.Message ?? "job failed");
          db.transaction(() => { for (const s of r.ServicesLastAccessed ?? []) { put.run(p.arn, String(s.ServiceNamespace), s.ServiceName ?? null, iso(s.LastAuthenticated), s.LastAuthenticatedEntity ?? null, s.LastAuthenticatedRegion ?? null, now); services++; } })();
          done++; break;
        }
      } catch (e: any) { if (++failed <= 3) onError(`last accessed (${p.arn.split(":").pop()}): ${describeError(e, "iam:GenerateServiceLastAccessedDetails, iam:GetServiceLastAccessedDetails")}`); }
    }));
  }
  if (done) noteSuccess(["iam:GenerateServiceLastAccessedDetails", "iam:GetServiceLastAccessedDetails"], "entitlements");
  // a run that read nothing (no principals yet, or the permission missing) does not hold the next one back a day
  if (done) setSetting(META, JSON.stringify({ ...entitlementsMeta(), last_accessed_at: now, last_accessed: done }));
  onLog(`last accessed: ${done} of ${targets.length} principals, ${services} service rows${failed ? `, ${failed} failed` : ""}`);
  return { principals: done, services };
}

/** An EKS access policy as a level of access to the cluster. Pure. */
export function eksPolicyLevel(policyArn: string): "cluster_admin" | "admin" | "edit" | "view" | "other" {
  const n = policyArn.split("/").pop() ?? "";
  return n === "AmazonEKSClusterAdminPolicy" ? "cluster_admin" : n === "AmazonEKSAdminPolicy" ? "admin" : n === "AmazonEKSEditPolicy" ? "edit" : n === "AmazonEKSViewPolicy" ? "view" : "other";
}

/** The aws-auth ConfigMap's mapRoles and mapUsers as principal mappings; `system:masters` is cluster admin. Pure. */
export function awsAuthMappings(cm: any): { principal_arn: string; username: string | null; groups: string[]; level: string }[] {
  const out: { principal_arn: string; username: string | null; groups: string[]; level: string }[] = [];
  const parseList = (s: unknown): any[] => { if (typeof s !== "string") return []; return yamlList(s); };
  for (const [key, field] of [["mapRoles", "rolearn"], ["mapUsers", "userarn"]] as const) for (const m of parseList(cm?.data?.[key])) {
    const arn = m[field]; if (!arn) continue;
    const groups: string[] = Array.isArray(m.groups) ? m.groups.map(String) : [];
    out.push({ principal_arn: String(arn), username: m.username ? String(m.username) : null, groups, level: groups.includes("system:masters") ? "cluster_admin" : groups.some((g) => /^system:(nodes|bootstrappers)$/.test(g)) ? "node" : groups.length ? "groups" : "none" });
  }
  return out;
}

/** The flat YAML list aws-auth uses (`- rolearn: …` with `groups:` sub-lists), without a YAML library. Pure. */
export function yamlList(s: string): any[] {
  const out: Record<string, any>[] = []; let cur: Record<string, any> | null = null; let listKey: string | null = null; let itemIndent = -1;
  const unq = (v: string) => v.trim().replace(/^["']|["']$/g, "");
  for (const raw of s.split(/\r?\n/)) {
    if (!raw.trim() || /^\s*#/.test(raw)) continue;
    const dash = /^(\s*)-\s+(.*)$/.exec(raw);
    if (dash && (itemIndent < 0 || dash[1].length === itemIndent)) {
      // a new item: `- key: value` at the list's own indent
      itemIndent = dash[1].length; cur = {}; out.push(cur); listKey = null;
      const kv = /^([A-Za-z]+):\s*(.*)$/.exec(dash[2]); if (kv) { if (kv[2]) cur[kv[1]] = unq(kv[2]); else { listKey = kv[1]; cur[kv[1]] = []; } }
      continue;
    }
    if (!cur) continue;
    if (dash && listKey) { cur[listKey].push(unq(dash[2])); continue; }
    const kv = /^\s+([A-Za-z]+):\s*(.*)$/.exec(raw);
    if (kv) { if (kv[2]) { cur[kv[1]] = unq(kv[2]); listKey = null; } else { listKey = kv[1]; cur[kv[1]] = []; } }
  }
  return out;
}

/** Who each EKS cluster lets in: access entries (with access policies and Kubernetes groups) and, when the API is reachable, aws-auth. */
export async function refreshClusterAccess(onError: (m: string) => void = () => {}, onLog: (l: string) => void = () => {}): Promise<{ clusters: number; entries: number }> {
  const clusters = rows("select arn, name, region, account_id, endpoint, ca_data, authentication_mode from inventory_cluster where gone = 0 and kind = 'eks'");
  const now = new Date().toISOString(); let entries = 0;
  const put = db.prepare(`insert into cluster_access(cluster_arn, principal_arn, via, level, groups, policies, namespaces, username, read_at) values (?, ?, ?, ?, ?, ?, ?, ?, ?)
    on conflict(cluster_arn, principal_arn, via) do update set level = excluded.level, groups = excluded.groups, policies = excluded.policies, namespaces = excluded.namespaces, username = excluded.username, read_at = excluded.read_at`);
  const rank: Record<string, number> = { cluster_admin: 5, admin: 4, edit: 3, groups: 2, view: 1, other: 0, node: 0, none: 0 };
  for (const c of clusters) {
    const creds = accountCredentials(c.account_id);
    if (c.authentication_mode !== "CONFIG_MAP") {
      try {
        const eks = new EKSClient({ region: c.region, credentials: creds.provider });
        const arns = (await pagesOf(async (t) => { const r = await eks.send(new ListAccessEntriesCommand({ clusterName: c.name, nextToken: t })); return { items: r.accessEntries ?? [], next: r.nextToken }; })).flat();
        for (const arn of arns) {
          const d = (await eks.send(new DescribeAccessEntryCommand({ clusterName: c.name, principalArn: arn }))).accessEntry;
          const pols = (await eks.send(new ListAssociatedAccessPoliciesCommand({ clusterName: c.name, principalArn: arn }))).associatedAccessPolicies ?? [];
          const groups = d?.kubernetesGroups ?? [];
          const levels = pols.map((p) => eksPolicyLevel(String(p.policyArn)));
          const level = groups.includes("system:masters") ? "cluster_admin" : levels.sort((a, b) => rank[b] - rank[a])[0] ?? (groups.length ? "groups" : d?.type && d.type !== "STANDARD" ? "node" : "none");
          const ns = pols.flatMap((p) => (p.accessScope?.type === "namespace" ? p.accessScope.namespaces ?? [] : []));
          put.run(c.arn, arn, "access_entry", level, JSON.stringify(groups), JSON.stringify(pols.map((p) => String(p.policyArn).split("/").pop())), JSON.stringify(ns), d?.username ?? null, now); entries++;
        }
        noteSuccess(["eks:ListAccessEntries", "eks:DescribeAccessEntry", "eks:ListAssociatedAccessPolicies"], "entitlements");
      } catch (e: any) { onError(`EKS access entries (${c.name}): ${describeError(e, "eks:ListAccessEntries")}`); }
    }
    if (c.authentication_mode !== "API" && c.endpoint) {
      try {
        const { eksToken, k8sGet } = await import("./k8s_client.js");
        const cluster = { name: c.name, endpoint: c.endpoint, ca_data: c.ca_data, region: c.region };
        const cm = await k8sGet(cluster, "/api/v1/namespaces/kube-system/configmaps/aws-auth", await eksToken(cluster, creds));
        for (const m of awsAuthMappings(cm)) { put.run(c.arn, m.principal_arn, "aws_auth", m.level, JSON.stringify(m.groups), "[]", "[]", m.username, now); entries++; }
      } catch (e: any) { if (!/404|not found/i.test(String(e?.message))) onError(`aws-auth (${c.name}): ${String(e?.message || e).slice(0, 200)}`); }
    }
    db.prepare("delete from cluster_access where cluster_arn = ? and read_at <> ?").run(c.arn, now);
  }
  setSetting(META, JSON.stringify({ ...entitlementsMeta(), clusters_at: now }));
  if (clusters.length) onLog(`cluster access: ${entries} principals across ${clusters.length} EKS cluster(s)`);
  return { clusters: clusters.length, entries };
}

// ---- readers ----------------------------------------------------------------------------------------------------------

export interface StoredEntitlement extends EntitlementRow { top: string | null; admin: boolean; updated_at: string }
const toEntitlement = (r: any): StoredEntitlement => ({ ...r, grants: parse(r.grants, {}), escalation: parse(r.escalation, []), policies: parse(r.policies, []), scp: parse(r.scp, []), admin: Boolean(r.admin) });
export const listEntitlements = (scope?: AccountScope | null): StoredEntitlement[] => { const a = accountWhere(scope); return rows(`select * from entitlement where ${a.sql}`, ...a.params).map(toEntitlement); };
export const entitlementOf = (arn: string): StoredEntitlement | null => { const r = rows("select * from entitlement where arn = ?", arn)[0]; return r ? toEntitlement(r) : null; };
export const listPrincipals = (): PrincipalRow[] => rows("select * from iam_principal where gone = 0").map((r) => ({ ...r, groups: parse(r.groups, []), attached: parse(r.attached, []), inline: parse(r.inline, []), instance_profiles: parse(r.instance_profiles, []) }));
export const policyDocs = (): Map<string, any> => new Map(rows("select arn, document from iam_policy_doc").map((r) => [r.arn, parse(r.document)]));
export const policyRows = (): { arn: string; name: string; aws_managed: boolean; account_id: string | null; document: any }[] => rows("select arn, name, aws_managed, account_id, document from iam_policy_doc").map((r) => ({ ...r, aws_managed: Boolean(r.aws_managed), document: parse(r.document) }));
/** The services each principal used, with when, in the last `days`. */
export function usedServices(days = 90): Map<string, Map<string, string>> {
  const since = new Date(Date.now() - days * 86_400_000).toISOString(); const out = new Map<string, Map<string, string>>();
  for (const r of rows("select arn, service, last_at from service_last_accessed where last_at is not null and last_at >= ?", since)) { let m = out.get(r.arn); if (!m) { m = new Map(); out.set(r.arn, m); } m.set(r.service, r.last_at); }
  return out;
}
/** Whether a principal has a last-accessed report at all (no report is "unknown", not "unused"). */
export const lastAccessedRead = (): Set<string> => new Set(rows("select distinct arn from service_last_accessed").map((r) => r.arn));
export const listClusterAccess = (): { cluster_arn: string; principal_arn: string; via: string; level: string; groups: string[]; policies: string[]; namespaces: string[]; username: string | null }[] =>
  rows("select * from cluster_access").map((r) => ({ ...r, groups: parse(r.groups, []), policies: parse(r.policies, []), namespaces: parse(r.namespaces, []) }));

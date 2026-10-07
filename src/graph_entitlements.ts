/**
 * What people may do, in the graph (docs/cloud-ontology.md §What a person can touch), rebuilt on every pass from
 * src/entitlements.ts and src/access_paths.ts:
 *
 * - (:AdvisorPolicy {kind: aws_managed|customer_managed|inline, level, admin, line, url (where to read it; the document is not stored)}) and (identity|group)-[:GRANTED]->(policy);
 *   (:AdvisorGroup) an IAM group, (iam user)-[:IN_GROUP]->(group); (:AdvisorPermissionSet) with
 *   (sso user)-[:ASSIGNED {account_id, via}]->(set)-[:PROVISIONED_AS {account_id}]->(its AWSReservedSSO_ role).
 * - Each IAM user and role carries its effective grade: access_level, access_line, write_services, permissions_services, escalation.
 * - (identity)-[:CAN_ACCESS {level, admin, line, via, …}]->(account | Vercel project | cluster): the grants no node states: an Identity
 *   Center assignment, a Vercel project role, a cluster mapping (an IAM user's or role's grade is on its node, beside IN_ACCOUNT).
 * - (identity)-[:CAN_ASSUME {via, decision}]->(role), (:AdvisorRepository)-[:CAN_ASSUME]->(role) for a pipeline,
 *   (identity)-[:CAN_SHELL_INTO {via, decision}]->(instance), (instance)-[:RUNS_AS {via: 'instance profile'}]->(role),
 *   (Vercel project)-[:HOLDS_KEY_OF {names}]->(IAM user).
 * - (identity)-[:TOUCHED {events, actions, last_at}]->(resource): what it changed in 90 days of CloudTrail writes.
 * - (person)-[:REACHES {level, admin, line, write_services, permissions_services, used_services, unused_write_services, direct, paths}]->(account | project | cluster):
 *   everything the person reaches, directly or through the paths, folded per target. The one hop that answers
 *   "what can this person touch"; derived from the identities' edges, which hold the grants (CAN_ACCESS is only ever an identity's).
 */
import { accessEdges, accessWorld, reach, touchedFromTrail } from "./access_paths.js";
import { personId } from "./graph_access.js";
import { listPeople } from "./sign_ins.js";
import { listEntitlements, listPrincipals, policyRows } from "./entitlements.js";
import { storedCatalogue } from "./service_reference.js";
import { grade, gradeLine, permsOf } from "./policy_facts.js";
import { db } from "./db.js";
import { permissionSetOfRole } from "./sso_inventory.js";

const chunks = <T,>(items: T[], size = 250): T[][] => { const out: T[][] = []; for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size)); return out; };
const rows = (sql: string, ...p: unknown[]): any[] => { try { return db.prepare(sql).all(...p) as any[]; } catch { return []; } };
const parse = (s: unknown, d: any = null): any => { if (typeof s !== "string") return s ?? d; try { return JSON.parse(s); } catch { return d; } };
/**
 * Where a person reads a policy: AWS's reference page for an AWS-managed one; the IAM console for ours (the policy's page,
 * or for an inline policy the permissions tab of the user, role or group holding it), which needs a sign-in to that
 * account. The documents themselves stay out of the graph. Pure.
 */
export function policyUrl(p: { kind: "aws_managed" | "customer_managed" | "inline"; arn?: string; name: string; holder?: { kind: string; name: string } }): string {
  const iam = "https://us-east-1.console.aws.amazon.com/iam/home#";
  if (p.kind === "aws_managed") return `https://docs.aws.amazon.com/aws-managed-policy/latest/reference/${encodeURIComponent(p.name)}.html`;
  if (p.kind === "customer_managed") return `${iam}/policies/details/${encodeURIComponent(p.arn ?? "")}?section=permissions`;
  const page = p.holder?.kind === "user" ? "users" : p.holder?.kind === "group" ? "groups" : "roles";
  return `${iam}/${page}/details/${encodeURIComponent(p.holder?.name ?? "")}?section=permissions`;
}
/** The fields that apply to each kind of target; everything else (an AWS service list on a Vercel project) is left off. */
const ACCESS_FIELDS: Record<"account" | "project" | "cluster", string[]> = {
  account: ["level", "admin", "line", "write_services", "direct", "paths", "decision"],
  project: ["level", "admin", "line", "deploy", "env_vars", "direct", "paths", "decision"],
  cluster: ["level", "admin", "line", "namespaces", "direct", "paths", "decision"],
};
/** A CAN_ACCESS or REACHES edge's properties for its kind of target, the unset ones left out. Pure. */
export function accessProps(kind: "account" | "project" | "cluster", v: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const k of ACCESS_FIELDS[kind]) { const x = v[k]; if (x == null || (Array.isArray(x) && !x.length && k === "namespaces")) continue; out[k] = x; }
  return out;
}
/** A path edge's facts (refs, profile, environments, names, targets, note, account_id) as its own properties, the empty ones left out. Pure. */
export function edgeProps(detail: Record<string, unknown>): Record<string, string | number | boolean | string[]> {
  const out: Record<string, string | number | boolean | string[]> = {};
  for (const [k, v] of Object.entries(detail)) {
    if (v == null || v === "" || (Array.isArray(v) && !v.length)) continue;
    out[k] = Array.isArray(v) ? v.map(String) : typeof v === "object" ? JSON.stringify(v) : (v as string | number | boolean);
  }
  return out;
}
const pathLine = (p: { steps: string[]; decision: string }) => `${p.steps.join(" → ")}${p.decision === "conditional" ? " (under a condition)" : ""}`;

/** A target of any kind: an account, a resource (a project, a cluster, an instance, a role). */
const TARGET = (v: string, id: string) => `OPTIONAL MATCH (${v}_r:AdvisorResource {id: ${id}}) OPTIONAL MATCH (${v}_a:AdvisorAccount {id: ${id}}) WITH *, coalesce(${v}_r, ${v}_a) AS ${v} WHERE ${v} IS NOT NULL`;

const POLICY_CYPHER = `
UNWIND $rows AS row
MERGE (p:AdvisorPolicy {id: row.id}) ON CREATE SET p.first_seen = $now
SET p += {name: row.name, kind: row.kind, account_id: row.account_id, provider: 'aws', native_type: 'iam_policy', native_id: row.id, level: row.level, admin: row.admin, line: row.line, services: row.services, url: row.url, updated_at: $now}`;
const GROUP_CYPHER = `
UNWIND $rows AS row
MERGE (g:AdvisorGroup {id: row.id}) ON CREATE SET g.first_seen = $now
SET g += {name: row.name, account_id: row.account_id, provider: 'aws', native_type: 'iam_group', native_id: row.id, level: row.level, admin: row.admin, line: row.line, updated_at: $now}`;
const GRANTED_CYPHER = `
UNWIND $rows AS row
OPTIONAL MATCH (i:AdvisorResource {id: row.holder}) OPTIONAL MATCH (g:AdvisorGroup {id: row.holder})
WITH row, coalesce(i, g) AS h WHERE h IS NOT NULL
MATCH (p:AdvisorPolicy {id: row.policy})
MERGE (h)-[r:GRANTED]->(p) SET r += {via: row.via, updated_at: $now}`;
const IN_GROUP_CYPHER = `
UNWIND $rows AS row
MATCH (u:AdvisorResource {id: row.user}) MATCH (g:AdvisorGroup {id: row.group})
MERGE (u)-[r:IN_GROUP]->(g) SET r.updated_at = $now`;
const PERMISSION_SET_CYPHER = `
UNWIND $rows AS row
MERGE (s:AdvisorPermissionSet {id: row.id}) ON CREATE SET s.first_seen = $now
SET s += {name: row.name, account_id: row.account_id, provider: 'aws', native_type: 'permission_set', native_id: row.id, admin: row.admin, level: row.level, line: row.line, accounts: row.accounts, policies: row.policies, updated_at: $now}
WITH s, row
UNWIND row.roles AS ro
MATCH (r:AdvisorResource {id: ro.arn})
MERGE (s)-[x:PROVISIONED_AS]->(r) SET x += {account_id: ro.account_id, updated_at: $now}`;
const ASSIGNED_CYPHER = `
UNWIND $rows AS row
MATCH (u:AdvisorResource {id: row.user}) MATCH (s:AdvisorPermissionSet {id: row.set})
MERGE (u)-[x:ASSIGNED {account_id: row.account_id, via: row.via}]->(s) SET x.updated_at = $now`;
const GRADE_CYPHER = `
UNWIND $rows AS row
MATCH (i:AdvisorResource {id: row.arn})
SET i += {access_level: row.level, access_line: row.line, write_services: row.write_services, permissions_services: row.permissions_services, resource_access_services: row.resource_access_services, escalation: row.escalation, admin: coalesce(row.admin, i.admin)}`;
const CAN_ACCESS_CYPHER = `
UNWIND $rows AS row
MATCH (i:AdvisorResource {id: row.identity})
${TARGET("t", "row.target")}
MERGE (i)-[x:CAN_ACCESS {via: row.via}]->(t)
SET x = row.props SET x.via = row.via, x.updated_at = $now`;
const REPOSITORY_CYPHER = `
UNWIND $rows AS row
MERGE (r:AdvisorRepository {id: row.id}) ON CREATE SET r.first_seen = $now
SET r += {name: row.name, provider: 'github', native_type: 'repository', native_id: row.name, updated_at: $now}`;
const PATH_CYPHER = (rel: string) => `
UNWIND $rows AS row
OPTIONAL MATCH (f_r:AdvisorResource {id: row.from}) OPTIONAL MATCH (f_p:AdvisorRepository {id: row.from})
WITH row, coalesce(f_r, f_p) AS f WHERE f IS NOT NULL
MATCH (t:AdvisorResource {id: row.to})
MERGE (f)-[x:${rel} {via: row.via}]->(t) SET x += row.props SET x.decision = row.decision, x.updated_at = $now REMOVE x.detail`;
const TOUCHED_CYPHER = `
UNWIND $rows AS row
MATCH (i:AdvisorResource {id: row.identity})
OPTIONAL MATCH (a:AdvisorResource {id: row.resource}) OPTIONAL MATCH (b:AdvisorResource {id: row.tail})
WITH row, i, coalesce(a, b) AS r WHERE r IS NOT NULL AND r <> i
MERGE (i)-[x:TOUCHED]->(r) SET x += {events: row.events, actions: row.actions, last_at: row.last_at, updated_at: $now}`;
const PERSON_ACCESS_CYPHER = `
UNWIND $rows AS row
MATCH (p:AdvisorPerson {id: row.person})
${TARGET("t", "row.target")}
MERGE (p)-[x:REACHES]->(t)
SET x = row.props SET x.updated_at = $now`;

/** Writes policies, groups, permission sets, grants, paths, what each identity touched and what each person reaches; removes what this pass did not write. */
export async function mirrorEntitlements(stamp: string): Promise<Record<string, number>> {
  const { enabled, writeCypher } = await import("./graph_mirror.js");
  const cat = storedCatalogue();
  const principals = listPrincipals(); const ents = listEntitlements(null);
  const policyGrade = (doc: any) => { const g = grade(permsOf([{ doc, source: "p" }], cat), cat); return { level: g.admin ? "admin" : g.top, admin: g.admin, line: gradeLine(g), services: g.every ? ["*"] : g.services.map((s) => s.service).slice(0, 60) }; };
  // policies: the managed ones attached somewhere, and every inline one as its own node under its holder
  const attached = new Set(principals.flatMap((p) => [...p.attached, ...(p.boundary ? [p.boundary] : [])]));
  const policies: (ReturnType<typeof policyGrade> & { id: string; name: string; kind: "aws_managed" | "customer_managed" | "inline"; account_id: string | null; url: string })[] = policyRows().filter((p) => attached.has(p.arn)).map((p) => { const kind = p.aws_managed ? "aws_managed" as const : "customer_managed" as const; return { id: p.arn, name: p.name, kind, account_id: p.account_id, url: policyUrl({ kind, arn: p.arn, name: p.name }), ...policyGrade(p.document) }; });
  const holders: { holder: string; policy: string; via: string }[] = [];
  for (const p of principals) {
    for (const a of p.attached) holders.push({ holder: p.arn, policy: a, via: "attached" });
    if (p.boundary) holders.push({ holder: p.arn, policy: p.boundary, via: "permissions boundary" });
    for (const i of p.inline) { const id = `${p.arn}#inline:${i.name}`; policies.push({ id, name: i.name, kind: "inline", account_id: p.account_id, url: policyUrl({ kind: "inline", name: i.name, holder: { kind: p.kind, name: p.name } }), ...policyGrade(i.doc) }); holders.push({ holder: p.arn, policy: id, via: "inline" }); }
  }
  const entBy = new Map(ents.map((e) => [e.arn, e]));
  const groups = principals.filter((p) => p.kind === "group").map((g) => { const e = entBy.get(g.arn); return { id: g.arn, name: g.name, account_id: g.account_id, level: e?.grants.admin ? "admin" : e?.top ?? null, admin: Boolean(e?.admin), line: e?.line ?? null }; });
  const groupArn = new Map(principals.filter((p) => p.kind === "group").map((g) => [`${g.account_id}/${g.name}`, g.arn]));
  const inGroup = principals.filter((p) => p.kind === "user").flatMap((u) => u.groups.map((g) => ({ user: u.arn, group: groupArn.get(`${u.account_id}/${g}`) })).filter((x): x is { user: string; group: string } => Boolean(x.group)));
  const gradesRows = ents.filter((e) => e.kind !== "group").map((e) => ({ arn: e.arn, level: e.grants.admin ? "admin" : e.top, line: e.line, write_services: e.grants.every ? ["*"] : e.grants.write_services ?? [], permissions_services: e.grants.permissions_services ?? [], resource_access_services: e.grants.resource_access_services ?? [], escalation: e.escalation, admin: e.grants.admin || null }));
  // permission sets: the stored sets, each linked to the reserved role it is provisioned as in each account
  const reserved = principals.filter((p) => p.kind === "role" && permissionSetOfRole(p.name));
  const sets = rows("select arn, name, account_id, admin, accounts, managed_policies, customer_managed, inline_policy from inventory_sso_permission_set where gone = 0").map((s) => {
    const roles = reserved.filter((r) => permissionSetOfRole(r.name) === s.name).map((r) => ({ arn: r.arn, account_id: r.account_id }));
    const e = roles.map((r) => entBy.get(r.arn)).find(Boolean);
    return { id: s.arn, name: s.name, account_id: s.account_id, admin: Boolean(s.admin), level: e ? (e.grants.admin ? "admin" : e.top) : null, line: e?.line ?? null, accounts: parse(s.accounts, []), policies: [...parse(s.managed_policies, []), ...parse(s.customer_managed, []), ...(s.inline_policy ? ["inline"] : [])], roles };
  });
  const setByName = new Map(sets.map((s) => [s.name, s.id]));
  const assigned = rows("select user_id, assignments from inventory_sso_user where gone = 0").flatMap((u) => (parse(u.assignments, []) as any[]).map((a) => ({ user: u.user_id, set: a.permission_set_arn ?? setByName.get(a.permission_set), account_id: a.account_id, via: a.via })).filter((x) => x.set));

  const w = accessWorld(); const built = accessEdges(w);
  const touched = touchedFromTrail(90);
  // an IAM user's, a role's and the root user's grade is on its own node beside IN_ACCOUNT: an edge would only repeat it.
  // CAN_ACCESS carries what no node says: an Identity Center assignment, a Vercel project role, a cluster mapping
  const canAccess = built.grants.filter((g) => !(g.target_kind === "account" && ["IAM user", "role", "root user"].includes(g.via))).map((g) => ({ identity: g.identity, target: g.target, via: g.via, props: accessProps(g.target_kind, { level: g.level, admin: g.admin, line: g.line, write_services: g.write_services, deploy: g.deploy, env_vars: g.env_vars, namespaces: g.namespaces }) }));
  // inside its own account an administrator already does everything: its shells (every instance) and the roles it may
  // assume there say nothing "admin" does not. Only its steps into another account are written
  const adminArn = (arn: string) => Boolean(entBy.get(arn)?.grants.admin);
  const sameAccount = (a: string, b: string) => { const x = entBy.get(a)?.account_id; return Boolean(x) && x === entBy.get(b)?.account_id; };
  const adminNoise = (kind: string, e: { from: string; to: string }) => adminArn(e.from) && (kind === "CAN_SHELL_INTO" || (kind === "CAN_ASSUME" && sameAccount(e.from, e.to)));
  // an Identity Center user reaches its reserved role through ASSIGNED → PROVISIONED_AS: no shortcut edge beside it
  const viaSet = (kind: string, e: { via: string }) => kind === "CAN_ASSUME" && e.via.startsWith("permission set ");
  const paths = (kind: string) => built.edges.filter((e) => e.kind === kind && !(kind === "RUNS_AS" && e.via === "Vercel OIDC") && !adminNoise(kind, e) && !viaSet(kind, e)).map((e) => ({ from: e.from, to: e.to, via: e.via, decision: e.decision, props: edgeProps(e.detail) }));
  const people = listPeople(w.actors);
  const personAccess: any[] = [];
  for (const p of people) {
    const id = personId(p); if (!id) continue;
    const r = reach(p, w, built, touched.services);
    for (const a of r.accounts) personAccess.push({ person: id, target: a.account_id, props: accessProps("account", { level: a.level, admin: a.admin, line: a.line, write_services: a.write_services, direct: a.direct, paths: a.paths.map(pathLine), decision: a.paths.some((x) => x.decision === "allowed") ? "allowed" : "conditional" }) });
    for (const pr of r.projects) personAccess.push({ person: id, target: pr.project_id, props: accessProps("project", { level: pr.level, admin: pr.level === "owner" || pr.level === "project_admin", line: `deploys ${pr.deploy}, environment variables ${pr.env_vars}`, deploy: pr.deploy, env_vars: pr.env_vars, direct: true, paths: [pr.via], decision: "allowed" }) });
    for (const c of r.clusters) personAccess.push({ person: id, target: c.cluster_arn, props: accessProps("cluster", { level: c.level, admin: c.level === "cluster_admin", line: c.via, direct: false, paths: c.paths.map(pathLine), decision: c.paths.some((x) => x.decision === "allowed") ? "allowed" : "conditional" }) });
  }
  const touchedRows = touched.resources.map((t) => ({ ...t, tail: t.resource.split(/[/:]/).pop() ?? t.resource }));
  const counts = { policies: policies.length, groups: groups.length, permission_sets: sets.length, grants: canAccess.length, assume: paths("CAN_ASSUME").length, shell: paths("CAN_SHELL_INTO").length, touched: touchedRows.length, person_access: personAccess.length };
  if (!enabled()) return counts;
  for (const b of chunks(policies)) await writeCypher(POLICY_CYPHER, { rows: b, now: stamp });
  for (const b of chunks(groups)) await writeCypher(GROUP_CYPHER, { rows: b, now: stamp });
  for (const b of chunks(holders)) await writeCypher(GRANTED_CYPHER, { rows: b, now: stamp });
  for (const b of chunks(inGroup)) await writeCypher(IN_GROUP_CYPHER, { rows: b, now: stamp });
  for (const b of chunks(gradesRows)) await writeCypher(GRADE_CYPHER, { rows: b });
  for (const b of chunks(sets, 50)) await writeCypher(PERMISSION_SET_CYPHER, { rows: b, now: stamp });
  for (const b of chunks(assigned)) await writeCypher(ASSIGNED_CYPHER, { rows: b, now: stamp });
  for (const b of chunks(canAccess)) await writeCypher(CAN_ACCESS_CYPHER, { rows: b, now: stamp });
  for (const b of chunks(built.repositories)) await writeCypher(REPOSITORY_CYPHER, { rows: b, now: stamp });
  for (const kind of ["CAN_ASSUME", "CAN_SHELL_INTO", "RUNS_AS", "HOLDS_KEY_OF"]) for (const b of chunks(paths(kind))) await writeCypher(PATH_CYPHER(kind), { rows: b, now: stamp });
  for (const b of chunks(touchedRows)) await writeCypher(TOUCHED_CYPHER, { rows: b, now: stamp });
  for (const b of chunks(personAccess)) await writeCypher(PERSON_ACCESS_CYPHER, { rows: b, now: stamp });
  // what this pass did not write goes; RUNS_AS from Vercel OIDC is src/adapters/aws/edges.ts's
  await writeCypher("MATCH ()-[r:GRANTED|IN_GROUP|PROVISIONED_AS|ASSIGNED|CAN_ACCESS|REACHES|CAN_ASSUME|CAN_SHELL_INTO|HOLDS_KEY_OF|TOUCHED]->() WHERE r.updated_at IS NULL OR r.updated_at <> $now DELETE r", { now: stamp });
  await writeCypher("MATCH ()-[r:RUNS_AS]->() WHERE r.via <> 'vercel_oidc' AND (r.updated_at IS NULL OR r.updated_at <> $now) DELETE r", { now: stamp });
  await writeCypher("MATCH (n) WHERE (n:AdvisorPolicy OR n:AdvisorGroup OR n:AdvisorPermissionSet OR n:AdvisorRepository) AND (n.updated_at IS NULL OR n.updated_at <> $now) DETACH DELETE n", { now: stamp });
  return counts;
}

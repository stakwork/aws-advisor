/**
 * IAM Identity Center: the people who sign in once and reach the organisation's accounts through permission sets.
 * Read through the SDK from the parent's credentials (the directory lives in the management account or its
 * delegated administrator, in one home region): the instance, every user and group of the identity store, each
 * permission set with its policies, who is assigned where (directly or through a group), the applications, and
 * what the public API does not say and CloudTrail does: the last sign-in and the sign-ins of the last 30 days
 * (sso.amazonaws.com events in the home region, 90 days back at most), the last activity per account from the
 * stored write events (an SSO session is named after the user), and when each permission set's role was last used
 * in each account (aws_iam_role, the AWSReservedSSO_* roles). The user's status (ENABLED or DISABLED) comes with
 * ListUsers; MFA devices are not exposed by any API (src/sign_ins.ts reads the factors from the sign-ins). One row per user; a permission set row per set. In the graph each
 * user is an AdvisorIdentity {kind: user, native_type: sso_user} (docs/cloud-ontology.md §AdvisorIdentity).
 */
import { IdentitystoreClient, ListGroupMembershipsCommand, ListGroupsCommand, ListUsersCommand } from "@aws-sdk/client-identitystore";
import {
  DescribePermissionSetCommand, GetInlinePolicyForPermissionSetCommand, GetPermissionsBoundaryForPermissionSetCommand, ListAccountAssignmentsForPrincipalCommand, ListAccountsForProvisionedPermissionSetCommand,
  ListApplicationAssignmentsForPrincipalCommand, ListApplicationsCommand, ListCustomerManagedPolicyReferencesInPermissionSetCommand, ListInstancesCommand, ListManagedPoliciesInPermissionSetCommand, ListPermissionSetsCommand, SSOAdminClient,
} from "@aws-sdk/client-sso-admin";
import { CloudTrailClient, LookupEventsCommand } from "@aws-sdk/client-cloudtrail";
import { addColumn, db, getJsonSetting, setSetting } from "./db.js";
import { S, parentSchema, query, sdkCredentials } from "./steampipe.js";
import { describeError, noteSuccess } from "./permissions.js";
import { isAdmin } from "./iam_inventory.js";
import type { AccountScope } from "./scope.js";

db.exec(`create table if not exists inventory_sso_user (
  user_id text primary key, identity_store_id text not null, instance_arn text, account_id text, user_name text not null, display_name text, email text, idp text,
  groups text not null default '[]', assignments text not null default '[]', accounts integer not null default 0, permission_sets integer not null default 0, applications text not null default '[]', admin integer not null default 0,
  last_sign_in text, sign_ins_30d integer not null default 0, failed_30d integer not null default 0, activity text not null default '{}',
  first_seen text not null, last_seen text not null, gone integer not null default 0
)`);
db.exec(`create table if not exists inventory_sso_permission_set (
  arn text primary key, instance_arn text, account_id text, name text not null, description text, session_duration text, created text,
  managed_policies text not null default '[]', customer_managed text not null default '[]', inline_policy text, boundary text, admin integer not null default 0,
  accounts text not null default '[]', last_used text not null default '{}', users integer not null default 0,
  first_seen text not null, last_seen text not null, gone integer not null default 0
)`);
addColumn("inventory_sso_user", "created", "text");
addColumn("inventory_sso_user", "status", "text");
db.exec("create index if not exists inventory_sso_user_name on inventory_sso_user(user_name)");

const META = "sso_meta";
/** How far back CloudTrail answers LookupEvents, and so how far back a sign-in can be seen. */
export const SIGN_IN_WINDOW_DAYS = 90;
/** 50 events a page at 2 requests a second: 200 pages is 10,000 sign-in events in about 100 s. */
const MAX_SIGN_IN_PAGES = 200;

export interface SsoAssignment { account_id: string; permission_set: string; permission_set_arn: string; via: string }
export interface SsoUserRow {
  user_id: string; identity_store_id: string; instance_arn: string | null; account_id: string | null; user_name: string; display_name: string | null; email: string | null; idp: string | null; created: string | null; status: "ENABLED" | "DISABLED" | null;
  groups: string[]; assignments: SsoAssignment[]; accounts: number; permission_sets: number; applications: string[]; admin: boolean;
  last_sign_in: string | null; sign_ins_30d: number; failed_30d: number; activity: Record<string, string>; first_seen: string; last_seen: string; gone: boolean;
}
export interface SsoPermissionSetRow {
  arn: string; instance_arn: string | null; account_id: string | null; name: string; description: string | null; session_duration: string | null; created: string | null;
  managed_policies: string[]; customer_managed: string[]; inline_policy: string | null; boundary: string | null; admin: boolean; accounts: string[]; last_used: Record<string, string>; users: number; first_seen: string; last_seen: string; gone: boolean;
}
export interface SsoMeta {
  configured: boolean; instance_arn: string | null; identity_store_id: string | null; region: string | null; owner_account_id: string | null; name: string | null; status: string | null;
  read_at: string | null; took_ms: number | null; errors: string[]; notes: string[]; sign_ins_read: number;
}

const arr = (v: unknown): any[] => (Array.isArray(v) ? v : typeof v === "string" ? (() => { try { const p = JSON.parse(v); return Array.isArray(p) ? p : []; } catch { return []; } })() : []);
const obj = (v: unknown): any => (v && typeof v === "object" ? v : typeof v === "string" ? (() => { try { return JSON.parse(v); } catch { return null; } })() : null);
const iso = (v: unknown): string | null => (v == null ? null : v instanceof Date ? v.toISOString() : String(v));

/** The permission set a provisioned role stands for: AWSReservedSSO_<name>_<16 hex> → name; null for any other role. */
export const permissionSetOfRole = (roleName: string): string | null => { const m = /^AWSReservedSSO_(.+)_[0-9a-f]{16}$/.exec(roleName); return m ? m[1] : null; };

/** A permission set is administrative when it attaches AdministratorAccess or its inline policy allows * on *. */
export const isAdminPermissionSet = (managedArns: string[], inlinePolicy: string | null | undefined): boolean => isAdmin(managedArns, inlinePolicy ? [{ PolicyDocument: obj(inlinePolicy) }] : []);

/**
 * A user's assignments: the direct ones, then each group's with the group named as the path. Pure.
 * `names` maps a permission set ARN to its name (an ARN with no name keeps its last path segment).
 */
export function userAssignments(direct: { AccountId?: string; PermissionSetArn?: string }[], groups: string[], groupAssignments: Map<string, { AccountId?: string; PermissionSetArn?: string }[]>, names: Map<string, string>): SsoAssignment[] {
  const out: SsoAssignment[] = []; const seen = new Set<string>();
  const push = (a: { AccountId?: string; PermissionSetArn?: string }, via: string) => {
    if (!a.AccountId || !a.PermissionSetArn) return;
    const k = `${a.AccountId}|${a.PermissionSetArn}|${via}`; if (seen.has(k)) return; seen.add(k);
    out.push({ account_id: a.AccountId, permission_set: names.get(a.PermissionSetArn) ?? a.PermissionSetArn.split("/").pop() ?? a.PermissionSetArn, permission_set_arn: a.PermissionSetArn, via });
  };
  for (const a of direct) push(a, "direct");
  for (const g of groups) for (const a of groupAssignments.get(g) ?? []) push(a, `group ${g}`);
  return out.sort((a, b) => a.account_id.localeCompare(b.account_id) || a.permission_set.localeCompare(b.permission_set) || a.via.localeCompare(b.via));
}

export interface SignInEvent { name: string; time: string; username: string | null; detail: any }
export interface SignInFacts { last_sign_in: string | null; sign_ins_30d: number; failed_30d: number }
/** The sign-in events Identity Center writes to CloudTrail (sso.amazonaws.com): a portal sign-in, the credential check, opening an account or application. */
export const SIGN_IN_EVENTS = new Set(["Authenticate", "UserAuthentication", "CredentialVerification", "Federate"]);

/**
 * Folds the home region's sso.amazonaws.com events onto the users: the last sign-in (the newest of any sign-in
 * event), the sign-ins of the last 30 days (Authenticate and UserAuthentication) and the failed ones (an error code,
 * or a Failure in the service's own detail). A user is matched by name (case-insensitive) or by identity store id
 * (the principal, or who the call was made on behalf of). Pure.
 */
export function foldSignIns(events: SignInEvent[], users: { user_id: string; user_name: string }[], now = Date.now()): Map<string, SignInFacts> {
  const byName = new Map(users.map((u) => [u.user_name.toLowerCase(), u.user_id])); const ids = new Set(users.map((u) => u.user_id));
  const out = new Map<string, SignInFacts>();
  const since30 = now - 30 * 86_400_000;
  for (const ev of events) {
    if (!SIGN_IN_EVENTS.has(ev.name)) continue;
    const ui = ev.detail?.userIdentity ?? {};
    const candidates = [ui.userName, ev.username, ui.onBehalfOf?.userId, ui.principalId, ev.detail?.additionalEventData?.UserName];
    let id: string | null = null;
    for (const c of candidates) { if (!c) continue; const s = String(c); if (ids.has(s)) { id = s; break; } const n = byName.get(s.toLowerCase()); if (n) { id = n; break; } }
    if (!id) continue;
    const f = out.get(id) ?? { last_sign_in: null, sign_ins_30d: 0, failed_30d: 0 };
    const failed = Boolean(ev.detail?.errorCode) || /"(Failure|FAILURE|Failed|FAILED)"/.test(JSON.stringify(ev.detail?.serviceEventDetails ?? ev.detail?.responseElements ?? ""));
    const t = Date.parse(ev.time);
    if (!failed && (!f.last_sign_in || ev.time > f.last_sign_in)) f.last_sign_in = ev.time;
    if (Number.isFinite(t) && t >= since30 && (ev.name === "Authenticate" || ev.name === "UserAuthentication")) { if (failed) f.failed_30d++; else f.sign_ins_30d++; }
    out.set(id, f);
  }
  return out;
}

export const ssoMeta = (): SsoMeta => getJsonSetting<SsoMeta>(META, { configured: false, instance_arn: null, identity_store_id: null, region: null, owner_account_id: null, name: null, status: null, read_at: null, took_ms: null, errors: [], notes: [], sign_ins_read: 0 });

async function pages<T>(fn: (token: string | undefined) => Promise<{ items: T[] | undefined; next: string | undefined }>): Promise<T[]> {
  const out: T[] = []; let token: string | undefined; let n = 0;
  do { const r = await fn(token); out.push(...(r.items ?? [])); token = r.next; } while (token && ++n < 500);
  return out;
}

interface Instance { arn: string; identity_store_id: string; region: string; owner_account_id: string | null; name: string | null; status: string | null }

/** The instance: the saved home region first, then the default region, then every enabled region until one answers with an instance. */
async function findInstance(creds: ReturnType<typeof sdkCredentials>, onError: (m: string) => void): Promise<Instance | null> {
  const prev = ssoMeta();
  const regions: string[] = [];
  const add = (r: string | null | undefined) => { if (r && !regions.includes(r)) regions.push(r); };
  add(prev.region); add(creds.region);
  try { for (const r of await query<{ name: string }>(`select name from ${parentSchema()}.aws_region where opt_in_status <> 'not-opted-in' order by name`)) add(r.name); } catch { /* the default region alone */ }
  let lastErr: unknown = null;
  for (const region of regions) {
    const client = new SSOAdminClient({ region, credentials: creds.provider });
    try {
      const r = await client.send(new ListInstancesCommand({ MaxResults: 10 }));
      noteSuccess(["sso:ListInstances"], "identity center");
      const i = (r.Instances ?? []).find((x) => x.InstanceArn && x.IdentityStoreId);
      if (i) return { arn: String(i.InstanceArn), identity_store_id: String(i.IdentityStoreId), region, owner_account_id: i.OwnerAccountId ?? null, name: i.Name ?? null, status: i.Status ?? null };
    } catch (e) { lastErr = e; if (/AccessDenied|not authorized/i.test(String((e as any)?.message || e))) break; }
    finally { client.destroy(); }
  }
  if (lastErr) onError(describeError(lastErr, "identity center instance (sso:ListInstances)"));
  return null;
}

export interface SsoRefreshResult { configured: boolean; users: number; groups: number; permission_sets: number; gone: number; sign_ins: number; errors: string[]; took_ms: number }

export async function refreshSsoInventory(onError: (m: string) => void = () => {}, onLog: (l: string) => void = () => {}): Promise<SsoRefreshResult> {
  const t0 = Date.now(); const errors: string[] = []; const notes: string[] = [];
  const fail = (m: string) => { errors.push(m); onError(m); };
  const done = (meta: Partial<SsoMeta>, r: Omit<SsoRefreshResult, "errors" | "took_ms">): SsoRefreshResult => {
    setSetting(META, JSON.stringify({ ...ssoMeta(), ...meta, read_at: new Date().toISOString(), took_ms: Date.now() - t0, errors, notes }));
    onLog(`${r.configured ? `${r.users} users, ${r.groups} groups, ${r.permission_sets} permission sets, ${r.sign_ins} sign-in events${r.gone ? `, ${r.gone} gone` : ""}` : "no Identity Center instance"} in ${Date.now() - t0} ms${errors.length ? `; ${errors.join("; ")}` : ""}`);
    return { ...r, errors, took_ms: Date.now() - t0 };
  };
  let creds: ReturnType<typeof sdkCredentials>;
  try { creds = sdkCredentials(); } catch (e: any) { fail(String(e?.message || e)); return done({ configured: false }, { configured: false, users: 0, groups: 0, permission_sets: 0, gone: 0, sign_ins: 0 }); }
  const inst = await findInstance(creds, fail);
  if (!inst) return done({ configured: false, instance_arn: null, identity_store_id: null }, { configured: false, users: 0, groups: 0, permission_sets: 0, gone: 0, sign_ins: 0 });
  const { region } = inst;
  const sso = new SSOAdminClient({ region, credentials: creds.provider });
  const ids = new IdentitystoreClient({ region, credentials: creds.provider });
  const trail = new CloudTrailClient({ region, credentials: creds.provider });
  const now = new Date().toISOString();
  try {
    // --- the directory
    let users: any[] = []; let groups: any[] = [];
    try { users = await pages((t) => ids.send(new ListUsersCommand({ IdentityStoreId: inst.identity_store_id, MaxResults: 100, NextToken: t })).then((r) => ({ items: r.Users, next: r.NextToken }))); noteSuccess(["identitystore:ListUsers"], "identity center"); }
    catch (e) { fail(describeError(e, "identity center users (identitystore:ListUsers)")); }
    try { groups = await pages((t) => ids.send(new ListGroupsCommand({ IdentityStoreId: inst.identity_store_id, MaxResults: 100, NextToken: t })).then((r) => ({ items: r.Groups, next: r.NextToken }))); noteSuccess(["identitystore:ListGroups"], "identity center"); }
    catch (e) { fail(describeError(e, "identity center groups (identitystore:ListGroups)")); }
    const groupName = new Map(groups.map((g) => [String(g.GroupId), String(g.DisplayName || g.GroupId)]));
    const groupsOf = new Map<string, string[]>();
    try {
      for (const g of groups) {
        const ms = await pages((t) => ids.send(new ListGroupMembershipsCommand({ IdentityStoreId: inst.identity_store_id, GroupId: g.GroupId, MaxResults: 100, NextToken: t })).then((r) => ({ items: r.GroupMemberships, next: r.NextToken })));
        for (const m of ms) { const uid = m.MemberId?.UserId; if (uid) groupsOf.set(uid, [...(groupsOf.get(uid) ?? []), groupName.get(String(g.GroupId))!]); }
      }
      if (groups.length) noteSuccess(["identitystore:ListGroupMemberships"], "identity center");
    } catch (e) { fail(describeError(e, "identity center group members (identitystore:ListGroupMemberships)")); }

    // --- the permission sets, with their policies and the accounts they are provisioned to
    const sets: Omit<SsoPermissionSetRow, "first_seen" | "last_seen" | "gone" | "users" | "last_used">[] = [];
    try {
      const arns = await pages((t) => sso.send(new ListPermissionSetsCommand({ InstanceArn: inst.arn, MaxResults: 100, NextToken: t })).then((r) => ({ items: r.PermissionSets, next: r.NextToken })));
      noteSuccess(["sso:ListPermissionSets"], "identity center");
      for (const arn of arns) {
        const d = await sso.send(new DescribePermissionSetCommand({ InstanceArn: inst.arn, PermissionSetArn: arn }));
        const managed = await pages((t) => sso.send(new ListManagedPoliciesInPermissionSetCommand({ InstanceArn: inst.arn, PermissionSetArn: arn, MaxResults: 100, NextToken: t })).then((r) => ({ items: r.AttachedManagedPolicies, next: r.NextToken })));
        const customer = await pages((t) => sso.send(new ListCustomerManagedPolicyReferencesInPermissionSetCommand({ InstanceArn: inst.arn, PermissionSetArn: arn, MaxResults: 100, NextToken: t })).then((r) => ({ items: r.CustomerManagedPolicyReferences, next: r.NextToken })));
        const inline = (await sso.send(new GetInlinePolicyForPermissionSetCommand({ InstanceArn: inst.arn, PermissionSetArn: arn }))).InlinePolicy || null;
        let boundary: string | null = null;
        try { const b = (await sso.send(new GetPermissionsBoundaryForPermissionSetCommand({ InstanceArn: inst.arn, PermissionSetArn: arn }))).PermissionsBoundary; boundary = b?.ManagedPolicyArn?.split("/").pop() ?? b?.CustomerManagedPolicyReference?.Name ?? null; } catch { /* none set: the API answers with a not-found */ }
        const accounts = await pages((t) => sso.send(new ListAccountsForProvisionedPermissionSetCommand({ InstanceArn: inst.arn, PermissionSetArn: arn, MaxResults: 100, NextToken: t })).then((r) => ({ items: r.AccountIds, next: r.NextToken })));
        const managedArns = managed.map((m) => String(m.Arn || ""));
        sets.push({ arn, instance_arn: inst.arn, account_id: inst.owner_account_id, name: String(d.PermissionSet?.Name || arn.split("/").pop()), description: d.PermissionSet?.Description ?? null, session_duration: d.PermissionSet?.SessionDuration ?? null, created: iso(d.PermissionSet?.CreatedDate),
          managed_policies: managed.map((m) => String(m.Name || m.Arn)), customer_managed: customer.map((c) => String(c.Name)), inline_policy: inline, boundary, admin: isAdminPermissionSet(managedArns, inline), accounts: accounts.map(String).sort() });
      }
      noteSuccess(["sso:DescribePermissionSet", "sso:ListManagedPoliciesInPermissionSet", "sso:ListCustomerManagedPolicyReferencesInPermissionSet", "sso:GetInlinePolicyForPermissionSet", "sso:ListAccountsForProvisionedPermissionSet"], "identity center");
    } catch (e) { fail(describeError(e, "identity center permission sets (sso:ListPermissionSets, sso:DescribePermissionSet)")); }
    const setName = new Map(sets.map((s) => [s.arn, s.name])); const setAdmin = new Map(sets.map((s) => [s.arn, s.admin]));

    // --- who is assigned where: once per user and once per group, then folded
    const directOf = new Map<string, any[]>(); const groupAssign = new Map<string, any[]>();
    try {
      for (const u of users) directOf.set(String(u.UserId), await pages((t) => sso.send(new ListAccountAssignmentsForPrincipalCommand({ InstanceArn: inst.arn, PrincipalId: u.UserId, PrincipalType: "USER", MaxResults: 100, NextToken: t })).then((r) => ({ items: r.AccountAssignments, next: r.NextToken }))));
      for (const g of groups) groupAssign.set(groupName.get(String(g.GroupId))!, await pages((t) => sso.send(new ListAccountAssignmentsForPrincipalCommand({ InstanceArn: inst.arn, PrincipalId: g.GroupId, PrincipalType: "GROUP", MaxResults: 100, NextToken: t })).then((r) => ({ items: r.AccountAssignments, next: r.NextToken }))));
      if (users.length || groups.length) noteSuccess(["sso:ListAccountAssignmentsForPrincipal"], "identity center");
    } catch (e) { fail(describeError(e, "identity center assignments (sso:ListAccountAssignmentsForPrincipal)")); }

    // --- applications (an older instance has none and the API may refuse: a note, not an error)
    const appName = new Map<string, string>(); const appsOf = new Map<string, Set<string>>();
    try {
      const apps = await pages((t) => sso.send(new ListApplicationsCommand({ InstanceArn: inst.arn, MaxResults: 50, NextToken: t })).then((r) => ({ items: r.Applications, next: r.NextToken })));
      for (const a of apps) if (a.ApplicationArn) appName.set(a.ApplicationArn, String(a.Name || a.ApplicationArn.split("/").pop()));
      if (apps.length) {
        const give = (uids: string[], arn: string) => { for (const uid of uids) { const s = appsOf.get(uid) ?? new Set<string>(); s.add(appName.get(arn) ?? arn); appsOf.set(uid, s); } };
        const members = new Map<string, string[]>(); for (const [uid, gs] of groupsOf) for (const g of gs) members.set(g, [...(members.get(g) ?? []), uid]);
        for (const u of users) for (const a of await pages((t) => sso.send(new ListApplicationAssignmentsForPrincipalCommand({ InstanceArn: inst.arn, PrincipalId: u.UserId, PrincipalType: "USER", MaxResults: 100, NextToken: t })).then((r) => ({ items: r.ApplicationAssignments, next: r.NextToken })))) if (a.ApplicationArn) give([String(u.UserId)], a.ApplicationArn);
        for (const g of groups) for (const a of await pages((t) => sso.send(new ListApplicationAssignmentsForPrincipalCommand({ InstanceArn: inst.arn, PrincipalId: g.GroupId, PrincipalType: "GROUP", MaxResults: 100, NextToken: t })).then((r) => ({ items: r.ApplicationAssignments, next: r.NextToken })))) if (a.ApplicationArn) give(members.get(groupName.get(String(g.GroupId))!) ?? [], a.ApplicationArn);
      }
    } catch (e: any) { notes.push(`applications not read: ${String(e?.message || e).slice(0, 160)}`); }

    // --- sign-ins from the home region's trail
    let signIns = 0; let signInFacts = new Map<string, SignInFacts>();
    if (users.length) {
      const events: SignInEvent[] = [];
      try {
        let NextToken: string | undefined; let n = 0;
        const StartTime = new Date(Date.now() - SIGN_IN_WINDOW_DAYS * 86_400_000);
        do {
          const r = await trail.send(new LookupEventsCommand({ StartTime, EndTime: new Date(), LookupAttributes: [{ AttributeKey: "EventSource", AttributeValue: "sso.amazonaws.com" }], MaxResults: 50, NextToken }));
          for (const ev of r.Events ?? []) { if (!ev.EventName || !SIGN_IN_EVENTS.has(ev.EventName)) continue; let detail: any = {}; try { detail = ev.CloudTrailEvent ? JSON.parse(ev.CloudTrailEvent) : {}; } catch { /* keep going */ } events.push({ name: ev.EventName, time: (ev.EventTime ?? new Date()).toISOString(), username: ev.Username ?? null, detail }); }
          NextToken = r.NextToken; if (++n >= MAX_SIGN_IN_PAGES) { notes.push(`sign-ins: stopped after ${MAX_SIGN_IN_PAGES} pages`); break; }
        } while (NextToken);
        noteSuccess(["cloudtrail:LookupEvents"], `identity center sign-ins ${region}`);
      } catch (e) { fail(describeError(e, `identity center sign-ins ${region} (cloudtrail:LookupEvents)`)); }
      signIns = events.length;
      signInFacts = foldSignIns(events, users.map((u) => ({ user_id: String(u.UserId), user_name: String(u.UserName || "") })));
    }
    // --- the last write per account from the stored trail: an SSO session is named after the user
    const activity = new Map<string, Record<string, string>>();
    if (users.length) {
      const names = users.map((u) => String(u.UserName || "")).filter(Boolean);
      for (const chunk of [names.slice(0, 400)]) if (chunk.length) {
        const rows = db.prepare(`select username, coalesce(account_id, '') as account_id, max(event_time) as t from trail_events where username in (${chunk.map(() => "?").join(",")}) group by username, account_id`).all(...chunk) as { username: string; account_id: string; t: string }[];
        for (const r of rows) activity.set(r.username, { ...(activity.get(r.username) ?? {}), [r.account_id || (inst.owner_account_id ?? "")]: r.t });
      }
    }
    // --- when each permission set's role was last used, per account (the aggregator reaches every account the advisor has)
    const lastUsed = new Map<string, Record<string, string>>();
    if (sets.length) {
      try {
        const rows = await query<{ name: string; account_id: string; role_last_used_date: string | null }>(`select name, account_id, role_last_used_date from ${S}.aws_iam_role where name like 'AWSReservedSSO_%'`);
        for (const r of rows) { const ps = permissionSetOfRole(r.name); const t = iso(r.role_last_used_date); if (ps && t) lastUsed.set(ps, { ...(lastUsed.get(ps) ?? {}), [r.account_id]: t }); }
        noteSuccess(["iam:ListRoles", "iam:GetRole"], "identity center roles");
      } catch (e) { notes.push(describeError(e, "permission set roles (aws_iam_role, iam:ListRoles)")); }
    }

    // --- write
    const userRows = users.map((u) => {
      const uid = String(u.UserId); const gs = groupsOf.get(uid) ?? [];
      const assignments = userAssignments(directOf.get(uid) ?? [], gs, groupAssign, setName);
      const f = signInFacts.get(uid) ?? { last_sign_in: null, sign_ins_30d: 0, failed_30d: 0 };
      const email = (u.Emails ?? []).find((e: any) => e.Primary)?.Value ?? u.Emails?.[0]?.Value ?? null;
      return { user_id: uid, identity_store_id: inst.identity_store_id, instance_arn: inst.arn, account_id: inst.owner_account_id, user_name: String(u.UserName || uid), display_name: u.DisplayName ?? (u.Name ? [u.Name.GivenName, u.Name.FamilyName].filter(Boolean).join(" ") || null : null), email, idp: u.ExternalIds?.[0]?.Issuer ?? null, created: null, status: u.UserStatus ? String(u.UserStatus) : null,
        groups: JSON.stringify(gs), assignments: JSON.stringify(assignments), accounts: new Set(assignments.map((a) => a.account_id)).size, permission_sets: new Set(assignments.map((a) => a.permission_set_arn)).size, applications: JSON.stringify([...(appsOf.get(uid) ?? [])].sort()),
        admin: assignments.some((a) => setAdmin.get(a.permission_set_arn)) ? 1 : 0, last_sign_in: f.last_sign_in, sign_ins_30d: f.sign_ins_30d, failed_30d: f.failed_30d, activity: JSON.stringify(activity.get(String(u.UserName || "")) ?? {}), now };
    });
    const usersPerSet = new Map<string, number>();
    for (const r of userRows) for (const arn of new Set((JSON.parse(r.assignments) as SsoAssignment[]).map((a) => a.permission_set_arn))) usersPerSet.set(arn, (usersPerSet.get(arn) ?? 0) + 1);
    const upUser = db.prepare(`insert into inventory_sso_user(user_id, identity_store_id, instance_arn, account_id, user_name, display_name, email, idp, created, status, groups, assignments, accounts, permission_sets, applications, admin, last_sign_in, sign_ins_30d, failed_30d, activity, first_seen, last_seen, gone)
      values (@user_id, @identity_store_id, @instance_arn, @account_id, @user_name, @display_name, @email, @idp, @created, @status, @groups, @assignments, @accounts, @permission_sets, @applications, @admin, @last_sign_in, @sign_ins_30d, @failed_30d, @activity, @now, @now, 0)
      on conflict(user_id) do update set identity_store_id = excluded.identity_store_id, instance_arn = excluded.instance_arn, account_id = excluded.account_id, user_name = excluded.user_name, display_name = excluded.display_name, email = excluded.email, idp = excluded.idp, status = coalesce(excluded.status, inventory_sso_user.status), groups = excluded.groups, assignments = excluded.assignments,
        accounts = excluded.accounts, permission_sets = excluded.permission_sets, applications = excluded.applications, admin = excluded.admin, last_sign_in = coalesce(excluded.last_sign_in, inventory_sso_user.last_sign_in), sign_ins_30d = excluded.sign_ins_30d, failed_30d = excluded.failed_30d, activity = excluded.activity, last_seen = excluded.last_seen, gone = 0`);
    const upSet = db.prepare(`insert into inventory_sso_permission_set(arn, instance_arn, account_id, name, description, session_duration, created, managed_policies, customer_managed, inline_policy, boundary, admin, accounts, last_used, users, first_seen, last_seen, gone)
      values (@arn, @instance_arn, @account_id, @name, @description, @session_duration, @created, @managed_policies, @customer_managed, @inline_policy, @boundary, @admin, @accounts, @last_used, @users, @now, @now, 0)
      on conflict(arn) do update set instance_arn = excluded.instance_arn, account_id = excluded.account_id, name = excluded.name, description = excluded.description, session_duration = excluded.session_duration, created = excluded.created, managed_policies = excluded.managed_policies, customer_managed = excluded.customer_managed,
        inline_policy = excluded.inline_policy, boundary = excluded.boundary, admin = excluded.admin, accounts = excluded.accounts, last_used = excluded.last_used, users = excluded.users, last_seen = excluded.last_seen, gone = 0`);
    let gone = 0;
    db.transaction(() => {
      if (users.length) { for (const r of userRows) upUser.run(r); gone += db.prepare("update inventory_sso_user set gone = 1 where gone = 0 and identity_store_id = ? and last_seen < ?").run(inst.identity_store_id, now).changes; }
      if (sets.length) { for (const s of sets) upSet.run({ ...s, managed_policies: JSON.stringify(s.managed_policies), customer_managed: JSON.stringify(s.customer_managed), accounts: JSON.stringify(s.accounts), admin: s.admin ? 1 : 0, last_used: JSON.stringify(lastUsed.get(s.name) ?? {}), users: usersPerSet.get(s.arn) ?? 0, now }); gone += db.prepare("update inventory_sso_permission_set set gone = 1 where gone = 0 and instance_arn = ? and last_seen < ?").run(inst.arn, now).changes; }
    })();
    return done({ configured: true, instance_arn: inst.arn, identity_store_id: inst.identity_store_id, region, owner_account_id: inst.owner_account_id, name: inst.name, status: inst.status, sign_ins_read: signIns }, { configured: true, users: users.length, groups: groups.length, permission_sets: sets.length, gone, sign_ins: signIns });
  } finally { sso.destroy(); ids.destroy(); trail.destroy(); }
}

const parseUser = (r: any): SsoUserRow => ({ ...r, groups: arr(r.groups), assignments: arr(r.assignments), applications: arr(r.applications), admin: Boolean(r.admin), activity: obj(r.activity) ?? {}, gone: Boolean(r.gone) });
const parseSet = (r: any): SsoPermissionSetRow => ({ ...r, managed_policies: arr(r.managed_policies), customer_managed: arr(r.customer_managed), admin: Boolean(r.admin), accounts: arr(r.accounts), last_used: obj(r.last_used) ?? {}, gone: Boolean(r.gone) });

/** The users; under a member account's scope, those with an assignment there (the directory itself lives in the management account). */
export function listSsoUsers(f: { q?: string; sort?: string; gone?: boolean; scope?: AccountScope | null } = {}): SsoUserRow[] {
  const where: string[] = []; const params: unknown[] = [];
  if (!f.gone) where.push("gone = 0");
  if (f.q) { where.push("(user_name like ? or display_name like ? or email like ?)"); params.push(`%${f.q}%`, `%${f.q}%`, `%${f.q}%`); }
  const order = f.sort === "last_sign_in" ? "order by (coalesce(status, '') = 'DISABLED'), last_sign_in desc nulls last" : f.sort === "accounts" ? "order by (coalesce(status, '') = 'DISABLED'), accounts desc, user_name" : f.sort === "sign_ins" ? "order by (coalesce(status, '') = 'DISABLED'), sign_ins_30d desc, user_name" : "order by (coalesce(status, '') = 'DISABLED'), admin desc, last_sign_in desc nulls last, user_name";
  const rows = (db.prepare(`select * from inventory_sso_user ${where.length ? `where ${where.join(" and ")}` : ""} ${order} limit 2000`).all(...params) as any[]).map(parseUser);
  return f.scope && !f.scope.primary ? rows.filter((r) => r.assignments.some((a) => a.account_id === f.scope!.id)) : rows;
}

export function listSsoPermissionSets(f: { gone?: boolean; scope?: AccountScope | null } = {}): SsoPermissionSetRow[] {
  const rows = (db.prepare(`select * from inventory_sso_permission_set ${f.gone ? "" : "where gone = 0"} order by admin desc, users desc, name`).all() as any[]).map(parseSet);
  return f.scope && !f.scope.primary ? rows.filter((r) => r.accounts.includes(f.scope!.id)) : rows;
}

export interface SsoSummary { configured: boolean; users: number; disabled: number; admins: number; never_signed_in: number; stale_90d: number; external: number; groups: number; permission_sets: number; admin_sets: number; accounts: number; sign_ins_30d: number; failed_30d: number; read_at: string | null; region: string | null; owner_account_id: string | null; errors: string[]; notes: string[] }

export function ssoSummary(scope?: AccountScope | null): SsoSummary {
  const m = ssoMeta(); const all = listSsoUsers({ scope }); const users = all.filter((u) => u.status !== "DISABLED"); const sets = listSsoPermissionSets({ scope });
  const stale = (t: string | null) => !t || Date.now() - Date.parse(t) > 90 * 86_400_000;
  return {
    configured: m.configured, users: users.length, disabled: all.length - users.length, admins: users.filter((u) => u.admin).length, never_signed_in: users.filter((u) => !u.last_sign_in).length, stale_90d: users.filter((u) => u.last_sign_in && stale(u.last_sign_in)).length,
    external: users.filter((u) => u.idp).length, groups: new Set(users.flatMap((u) => u.groups)).size, permission_sets: sets.length, admin_sets: sets.filter((s) => s.admin).length,
    accounts: new Set(users.flatMap((u) => u.assignments.map((a) => a.account_id))).size, sign_ins_30d: users.reduce((n, u) => n + u.sign_ins_30d, 0), failed_30d: users.reduce((n, u) => n + u.failed_30d, 0),
    read_at: m.read_at, region: m.region, owner_account_id: m.owner_account_id, errors: m.errors, notes: m.notes,
  };
}

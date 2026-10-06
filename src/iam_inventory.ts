/**
 * IAM users: who can act in the account with a long-lived identity. Refreshed with the inventory from the
 * Steampipe tables aws_iam_user and aws_iam_access_key: name, when it was created and last signed in, whether it
 * has console access and MFA, its groups and policies (names only), whether any of them is administrative, and
 * the kind of each MFA device (authenticator app, passkey or security key, hardware token), and
 * its access keys with status, age and last use (the key id is kept masked to its last four characters; the
 * secret never exists here). One row per user per account, so a member's users carry the member's account id.
 * In the graph each user is an AdvisorIdentity {kind: user} (docs/cloud-ontology.md §AdvisorIdentity).
 */
import { addColumn, db } from "./db.js";
import { S, query } from "./steampipe.js";
import { describeError } from "./permissions.js";
import { accountWhere, type AccountScope } from "./scope.js";
import { mfaTypeOf } from "./sign_in_facts.js";

db.exec(`create table if not exists inventory_iam_user (
  arn text primary key, name text not null, user_id text, account_id text, path text, created text, password_last_used text,
  console_access integer not null default 0, mfa_enabled integer not null default 0, groups text not null default '[]', attached_policies text not null default '[]', inline_policies text not null default '[]',
  admin integer not null default 0, access_keys text not null default '[]', keys_active integer not null default 0, oldest_key_days integer, last_used text, tags text,
  first_seen text not null, last_seen text not null, gone integer not null default 0
)`);
addColumn("inventory_iam_user", "permissions_boundary", "text");
addColumn("inventory_iam_user", "mfa_types", "text");
addColumn("inventory_iam_user", "mfa_devices", "text");
db.exec("create index if not exists inventory_iam_user_name on inventory_iam_user(name)");

/** An MFA device registered to a user: its serial (an ARN for virtual and FIDO devices, a serial number for a hardware token; neither is a secret), its kind and when it was enabled. */
export interface MfaDeviceRow { serial: string; kind: "app" | "passkey" | "hardware"; enabled_at: string | null }
export interface AccessKeyRow { id: string; status: string | null; created: string | null; last_used: string | null; service: string | null; region: string | null; age_days: number | null }
export interface IamUserRow {
  arn: string; name: string; user_id: string | null; account_id: string | null; path: string | null; created: string | null; password_last_used: string | null;
  console_access: boolean; mfa_enabled: boolean; mfa_types: ("app" | "passkey" | "hardware")[]; mfa_devices: MfaDeviceRow[]; groups: string[]; attached_policies: string[]; inline_policies: string[]; admin: boolean; permissions_boundary: string | null;
  access_keys: AccessKeyRow[]; keys_active: number; oldest_key_days: number | null; last_used: string | null; tags: Record<string, string>; first_seen: string; last_seen: string; gone: boolean;
}

const arr = (v: unknown): any[] => (Array.isArray(v) ? v : typeof v === "string" ? (() => { try { const p = JSON.parse(v); return Array.isArray(p) ? p : []; } catch { return []; } })() : []);
const obj = (v: unknown): any => (v && typeof v === "object" ? v : typeof v === "string" ? (() => { try { return JSON.parse(v); } catch { return null; } })() : null);
const iso = (v: unknown): string | null => (v == null ? null : v instanceof Date ? v.toISOString() : String(v));
const days = (from: string | null, now = Date.now()): number | null => { if (!from) return null; const t = Date.parse(from); return Number.isFinite(t) ? Math.floor((now - t) / 86_400_000) : null; };
/** An access key id masked to its last four characters: enough to match it in the console, never a usable id. */
export const maskKeyId = (id: string) => (id.length > 4 ? `${id.slice(0, 4)}…${id.slice(-4)}` : id);
/** Policies that make a user an administrator: the AWS managed AdministratorAccess, or an inline statement with Action "*" on Resource "*". */
export function isAdmin(attachedArns: string[], inline: any[]): boolean {
  if (attachedArns.some((a) => /:policy\/AdministratorAccess$/.test(a))) return true;
  for (const p of inline) {
    const doc = obj(p?.PolicyDocument ?? p?.policy_document ?? p);
    const st = doc?.Statement; const list = Array.isArray(st) ? st : st ? [st] : [];
    for (const s of list) { const actions = Array.isArray(s?.Action) ? s.Action : [s?.Action]; const res = Array.isArray(s?.Resource) ? s.Resource : [s?.Resource]; if (s?.Effect === "Allow" && actions.includes("*") && res.includes("*")) return true; }
  }
  return false;
}

const policyName = (arn: string) => arn.split("/").pop() ?? arn;

/** Folds a Steampipe user row and its keys into the inventory row. Pure. */
export function iamUserFrom(u: any, keys: any[], now = Date.now()): Omit<IamUserRow, "first_seen" | "last_seen" | "gone"> {
  const attached = arr(u.attached_policy_arns).map(String);
  const inline = arr(u.inline_policies);
  const access_keys: AccessKeyRow[] = keys.map((k) => ({ id: maskKeyId(String(k.access_key_id ?? "")), status: k.status ?? null, created: iso(k.create_date), last_used: iso(k.access_key_last_used_date), service: k.access_key_last_used_service ?? null, region: k.access_key_last_used_region ?? null, age_days: days(iso(k.create_date), now) }));
  const active = access_keys.filter((k) => k.status === "Active");
  const lastUsed = [iso(u.password_last_used), ...access_keys.map((k) => k.last_used)].filter((x): x is string => Boolean(x)).sort().pop() ?? null;
  const groups = arr(u.groups).map((g) => String(g?.GroupName ?? g?.group_name ?? g?.name ?? g));
  return {
    arn: String(u.arn), name: String(u.name), user_id: u.user_id ?? null, account_id: u.account_id ? String(u.account_id) : null, path: u.path ?? null, created: iso(u.create_date), password_last_used: iso(u.password_last_used),
    console_access: Boolean(obj(u.login_profile)), mfa_enabled: Boolean(u.mfa_enabled), mfa_types: [...new Set(arr(u.mfa_devices).map((d) => mfaTypeOf(d?.SerialNumber ?? d?.serial_number ?? d)).filter((t): t is "app" | "passkey" | "hardware" => t != null))],
    mfa_devices: arr(u.mfa_devices).map((d) => { const serial = String(d?.SerialNumber ?? d?.serial_number ?? d ?? ""); const kind = mfaTypeOf(serial); return kind ? { serial, kind, enabled_at: iso(d?.EnableDate ?? d?.enable_date) } : null; }).filter((x): x is MfaDeviceRow => x != null), groups, attached_policies: attached.map(policyName), inline_policies: inline.map((p) => String(p?.PolicyName ?? p?.policy_name ?? "inline")), admin: isAdmin(attached, inline), permissions_boundary: u.permissions_boundary_arn ? policyName(String(u.permissions_boundary_arn)) : null,
    access_keys, keys_active: active.length, oldest_key_days: active.length ? Math.max(...active.map((k) => k.age_days ?? 0)) : null, last_used: lastUsed, tags: obj(u.tags) ?? {},
  };
}

const USERS_SQL = `select arn, name, user_id, account_id, path, create_date, password_last_used, mfa_enabled, mfa_devices, login_profile, groups, attached_policy_arns, inline_policies, permissions_boundary_arn, tags from ${S}.aws_iam_user`;
const KEYS_SQL = `select access_key_id, user_name, account_id, status, create_date, access_key_last_used_date, access_key_last_used_service, access_key_last_used_region from ${S}.aws_iam_access_key`;

export async function refreshIamInventory(onError: (m: string) => void, onLog: (l: string) => void = () => {}): Promise<{ users: number; gone: number }> {
  let users: any[] = []; let keys: any[] = [];
  try { users = await query(USERS_SQL); } catch (e: any) { onError(`IAM users: ${describeError(e, "iam users (aws_iam_user)")}`); return { users: 0, gone: 0 }; }
  try { keys = await query(KEYS_SQL); } catch (e: any) { onError(`IAM access keys: ${describeError(e, "iam access keys (aws_iam_access_key)")}`); }
  const now = new Date().toISOString();
  const byUser = new Map<string, any[]>();
  for (const k of keys) { const id = `${k.account_id ?? ""}/${k.user_name}`; byUser.set(id, [...(byUser.get(id) ?? []), k]); }
  const up = db.prepare(`insert into inventory_iam_user(arn, name, user_id, account_id, path, created, password_last_used, console_access, mfa_enabled, mfa_types, mfa_devices, groups, attached_policies, inline_policies, admin, permissions_boundary, access_keys, keys_active, oldest_key_days, last_used, tags, first_seen, last_seen, gone)
    values (@arn, @name, @user_id, @account_id, @path, @created, @password_last_used, @console_access, @mfa_enabled, @mfa_types, @mfa_devices, @groups, @attached_policies, @inline_policies, @admin, @permissions_boundary, @access_keys, @keys_active, @oldest_key_days, @last_used, @tags, @now, @now, 0)
    on conflict(arn) do update set name = excluded.name, user_id = excluded.user_id, account_id = excluded.account_id, path = excluded.path, created = excluded.created, password_last_used = excluded.password_last_used, console_access = excluded.console_access, mfa_enabled = excluded.mfa_enabled, mfa_types = excluded.mfa_types, mfa_devices = excluded.mfa_devices,
      groups = excluded.groups, attached_policies = excluded.attached_policies, inline_policies = excluded.inline_policies, admin = excluded.admin, permissions_boundary = excluded.permissions_boundary, access_keys = excluded.access_keys, keys_active = excluded.keys_active, oldest_key_days = excluded.oldest_key_days, last_used = excluded.last_used, tags = excluded.tags, last_seen = excluded.last_seen, gone = 0`);
  const seen: string[] = [];
  db.transaction(() => {
    for (const u of users) {
      const r = iamUserFrom(u, byUser.get(`${u.account_id ?? ""}/${u.name}`) ?? []);
      up.run({ ...r, console_access: r.console_access ? 1 : 0, mfa_enabled: r.mfa_enabled ? 1 : 0, mfa_types: JSON.stringify(r.mfa_types), mfa_devices: JSON.stringify(r.mfa_devices), admin: r.admin ? 1 : 0, groups: JSON.stringify(r.groups), attached_policies: JSON.stringify(r.attached_policies), inline_policies: JSON.stringify(r.inline_policies), access_keys: JSON.stringify(r.access_keys), tags: JSON.stringify(r.tags), now });
      seen.push(r.arn);
    }
  })();
  const gone = db.prepare(`update inventory_iam_user set gone = 1 where gone = 0 and last_seen < ?`).run(now).changes;
  onLog(`${users.length} IAM users, ${keys.length} access keys${gone ? `, ${gone} gone` : ""}`);
  return { users: users.length, gone };
}

const parseRow = (r: any): IamUserRow => ({ ...r, console_access: Boolean(r.console_access), mfa_enabled: Boolean(r.mfa_enabled), mfa_types: arr(r.mfa_types), mfa_devices: arr(r.mfa_devices), clients: arr(r.clients), admin: Boolean(r.admin), groups: arr(r.groups), attached_policies: arr(r.attached_policies), inline_policies: arr(r.inline_policies), access_keys: arr(r.access_keys), tags: obj(r.tags) ?? {}, gone: Boolean(r.gone) });

export function listIamUsers(f: { q?: string; sort?: string; gone?: boolean; scope?: AccountScope | null } = {}): IamUserRow[] {
  const where: string[] = []; const params: unknown[] = [];
  if (!f.gone) where.push("gone = 0");
  if (f.q) { where.push("(name like ? or arn like ?)"); params.push(`%${f.q}%`, `%${f.q}%`); }
  const a = accountWhere(f.scope); if (a.params.length) { where.push(a.sql); params.push(...a.params); }
  const order = f.sort === "created" ? "order by created desc" : f.sort === "keys" ? "order by oldest_key_days desc nulls last" : f.sort === "last_used" ? "order by last_used desc nulls last" : "order by admin desc, mfa_enabled asc, name";
  return (db.prepare(`select * from inventory_iam_user ${where.length ? `where ${where.join(" and ")}` : ""} ${order} limit 2000`).all(...params) as any[]).map(parseRow);
}

export function iamSummary(scope?: AccountScope | null): { users: number; console_without_mfa: number; admins: number; keys_active: number; keys_over_90d: number; unused_90d: number } {
  const rows = listIamUsers({ scope });
  const stale = (iso: string | null) => (days(iso) ?? Infinity) > 90;
  return {
    users: rows.length, console_without_mfa: rows.filter((r) => r.console_access && !r.mfa_enabled).length, admins: rows.filter((r) => r.admin).length,
    keys_active: rows.reduce((n, r) => n + r.keys_active, 0), keys_over_90d: rows.reduce((n, r) => n + r.access_keys.filter((k) => k.status === "Active" && (k.age_days ?? 0) > 90).length, 0),
    unused_90d: rows.filter((r) => (r.console_access || r.keys_active) && stale(r.last_used)).length,
  };
}

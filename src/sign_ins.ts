/**
 * Who can get in, and with what: the root user of every account and the device, client and factor each person or
 * key signs in or calls from. No API lists devices; CloudTrail says it event by event, and this module folds it.
 *
 * - Root, per account (parent with its own credentials, each enabled member through its read role): MFA on or off
 *   and the root access keys from iam:GetAccountSummary; an authenticator app when a virtual MFA device is assigned to
 *   the root ARN (iam:ListVirtualMFADevices), otherwise a passkey, security key or hardware token; the password and
 *   key last use from the credential report (iam:GenerateCredentialReport, iam:GetCredentialReport); and, from the
 *   parent, whether the organisation manages member roots centrally (iam:ListOrganizationsFeatures).
 * - Sign-ins (signin.amazonaws.com, us-east-1 and the account's default region, 90 days back at most): ConsoleLogin
 *   says root or IAM user, whether MFA was used and which device (MFAIdentifier: mfa/ is an app, u2f/ a passkey or
 *   security key, a bare serial a hardware token); Identity Center's CredentialChallenge, CredentialVerification and
 *   UserAuthentication carry the CredentialType (PASSWORD, TOTP, WEBAUTHN). In the directory's home region,
 *   sso.amazonaws.com Federate (opening an account in the browser) and GetRoleCredentials (`aws sso login`, the CLI or
 *   an SDK) say where a person works from.
 * - Calls (the stored write events of src/trail.ts): the user agent and the kind of key, so an access key used by
 *   the CLI on a Mac is told apart from Terraform in CI or a Lambda function.
 *
 * Each event is reduced to a fingerprint (actor, channel, client, platform, factor) and stored in sign_in_events; the
 * fold groups them per actor and writes the result to the identity rows (`clients`), so the graph mirror carries it
 * on each AdvisorIdentity. The user agent is parsed, never shown raw in the graph; the source IP stays in the store.
 */
import { CloudTrailClient, LookupEventsCommand, type LookupAttribute } from "@aws-sdk/client-cloudtrail";
import { GenerateCredentialReportCommand, GetAccountSummaryCommand, GetCredentialReportCommand, IAMClient, ListOrganizationsFeaturesCommand, ListVirtualMFADevicesCommand } from "@aws-sdk/client-iam";
import { addColumn, db, getJsonSetting, setSetting } from "./db.js";
import { credentialsMeta, sdkCredentials } from "./steampipe.js";
import { accountCredentials, listMembers } from "./accounts.js";
import { describeError, noteSuccess } from "./permissions.js";
import { ssoMeta } from "./sso_inventory.js";
import "./iam_inventory.js";
import { actorKey, directoryChange, foldClients, groupPeople, workflowMfa, type DirectoryChange, signInFromEvent, signInFromWrite, strongestMfa, iamUserMfa, rootFromCredentialReport, type ClientUse, type SignIn } from "./sign_in_facts.js";
import { accountWhere, type AccountScope } from "./scope.js";
import { teamExtras, vercelTeam } from "./adapters/vercel/inventory.js";
import { memberNodeId } from "./adapters/vercel/index.js";
import type { VercelToken } from "./adapters/vercel/client.js";

export * from "./sign_in_facts.js";

db.exec(`create table if not exists sign_in_events (
  event_id text primary key, account_id text, region text, event_time text not null, event_name text not null, source text not null,
  actor_type text not null, actor text not null, actor_id text, channel text not null, client text not null, platform text, factor text,
  failed integer not null default 0, source_ip text, target text, fetched_at text not null
)`);
db.exec("create index if not exists sign_in_events_actor on sign_in_events(actor_type, actor)");
addColumn("sign_in_events", "workflow", "text");
// changes to Identity Center users (MFA device removed, user disabled, password reset…) from the directory's own events
db.exec(`create table if not exists directory_changes (
  event_id text primary key, event_time text not null, event_name text not null, what text not null, target_user_id text, target_name text, by text, failed integer not null default 0, fetched_at text not null
)`);
addColumn("inventory_sso_user", "changes", "text");
addColumn("directory_changes", "device_id", "text");
db.exec(`create table if not exists inventory_root_user (
  account_id text primary key, arn text not null, mfa_enabled integer, mfa_kind text, access_keys integer, signing_certs integer,
  password_last_used text, key_last_used text, report_at text, centralized integer, root_sessions integer, clients text not null default '[]',
  first_seen text not null, last_seen text not null, gone integer not null default 0
)`);
addColumn("inventory_iam_user", "clients", "text");
addColumn("inventory_sso_user", "clients", "text");

const META = "sign_in_meta";
/** A new key reads the 90 days again once: v2 when events gained the Identity Center workflow id, v3 when directory changes gained the device id. */
const MARKS = "sign_in_marks_v3";
/** How far back CloudTrail answers LookupEvents. */
export const WINDOW_DAYS = 90;
/** 50 events a page at 2 requests a second: 100 pages is 5,000 events in about 50 s per query. */
const MAX_PAGES = 100;

export interface SignInMeta { read_at: string | null; took_ms: number | null; events_read: number; stored: number; accounts: number; errors: string[]; notes: string[]; centralized: boolean | null; root_sessions: boolean | null }
export const signInMeta = (): SignInMeta => getJsonSetting<SignInMeta>(META, { read_at: null, took_ms: null, events_read: 0, stored: 0, accounts: 0, errors: [], notes: [], centralized: null, root_sessions: null });

type Target = { account_id: string | null; is_parent: boolean; creds: { provider: any; region: string } };

function targets(errors: string[]): Target[] {
  const out: Target[] = [];
  try { const base = sdkCredentials(); out.push({ account_id: credentialsMeta()?.accountId ?? null, is_parent: true, creds: { provider: base.provider, region: base.region } }); } catch (e: any) { errors.push(String(e?.message || e)); return out; }
  for (const m of listMembers().filter((x) => x.enabled)) { try { const c = accountCredentials(m.account_id); out.push({ account_id: m.account_id, is_parent: false, creds: { provider: c.provider, region: c.region } }); } catch (e: any) { errors.push(`${m.account_id}: ${String(e?.message || e).slice(0, 120)}`); } }
  return out;
}

interface RootFacts { mfa_enabled: boolean | null; mfa_kind: string | null; access_keys: number | null; signing_certs: number | null; password_last_used: string | null; key_last_used: string | null; report_at: string | null }

async function readRoot(t: Target, fail: (m: string) => void, notes: string[]): Promise<RootFacts> {
  const iam = new IAMClient({ region: "us-east-1", credentials: t.creds.provider });
  const acct = t.account_id ?? "parent";
  const out: RootFacts = { mfa_enabled: null, mfa_kind: null, access_keys: null, signing_certs: null, password_last_used: null, key_last_used: null, report_at: null };
  try {
    try {
      const s = (await iam.send(new GetAccountSummaryCommand({}))).SummaryMap ?? {};
      out.mfa_enabled = s.AccountMFAEnabled != null ? s.AccountMFAEnabled === 1 : null; out.access_keys = s.AccountAccessKeysPresent ?? null; out.signing_certs = s.AccountSigningCertificatesPresent ?? null;
      noteSuccess(["iam:GetAccountSummary"], `root ${acct}`);
    } catch (e) { fail(describeError(e, `root user ${acct} (iam:GetAccountSummary)`)); }
    if (out.mfa_enabled) {
      try {
        let Marker: string | undefined; let virtual = false; let n = 0;
        do { const r = await iam.send(new ListVirtualMFADevicesCommand({ AssignmentStatus: "Assigned", Marker })); if ((r.VirtualMFADevices ?? []).some((v) => /:root$/.test(String(v.User?.Arn || "")))) virtual = true; Marker = r.IsTruncated ? r.Marker : undefined; } while (Marker && ++n < 20);
        out.mfa_kind = virtual ? "app" : "passkey_or_hardware";
        noteSuccess(["iam:ListVirtualMFADevices"], `root ${acct}`);
      } catch (e) { notes.push(describeError(e, `root MFA device ${acct} (iam:ListVirtualMFADevices)`)); }
    }
    try {
      let state = ""; let tries = 0;
      do { state = String((await iam.send(new GenerateCredentialReportCommand({}))).State || ""); if (state !== "COMPLETE") await new Promise((r) => setTimeout(r, 2000)); } while (state !== "COMPLETE" && ++tries < 8);
      if (state === "COMPLETE") {
        const r = await iam.send(new GetCredentialReportCommand({}));
        const root = r.Content ? rootFromCredentialReport(Buffer.from(r.Content).toString("utf8")) : null;
        if (root) { out.password_last_used = root.password_last_used; out.key_last_used = root.key_last_used; out.report_at = r.GeneratedTime ? r.GeneratedTime.toISOString() : null; if (out.mfa_enabled == null) out.mfa_enabled = root.mfa_active; if (out.access_keys == null) out.access_keys = root.keys_active; }
        noteSuccess(["iam:GenerateCredentialReport", "iam:GetCredentialReport"], `root ${acct}`);
      } else notes.push(`${acct}: the credential report was not ready after ${tries * 2} s`);
    } catch (e) { notes.push(describeError(e, `credential report ${acct} (iam:GenerateCredentialReport, iam:GetCredentialReport)`)); }
  } finally { iam.destroy(); }
  return out;
}

/** CloudTrail events for one lookup attribute since `since`, at most MAX_PAGES pages. */
async function lookup(client: CloudTrailClient, attr: LookupAttribute, since: Date, notes: string[], label: string): Promise<{ id: string; name: string; time: string; detail: any }[]> {
  const out: { id: string; name: string; time: string; detail: any }[] = [];
  let NextToken: string | undefined; let n = 0;
  // one window for every page: a page token is only valid for the request that produced it
  const EndTime = new Date();
  do {
    const r = await client.send(new LookupEventsCommand({ StartTime: since, EndTime, LookupAttributes: [attr], MaxResults: 50, NextToken }));
    for (const ev of r.Events ?? []) { if (!ev.EventId || !ev.EventName) continue; let detail: any = {}; try { detail = ev.CloudTrailEvent ? JSON.parse(ev.CloudTrailEvent) : {}; } catch { /* keep going */ } out.push({ id: ev.EventId, name: ev.EventName, time: (ev.EventTime ?? new Date()).toISOString(), detail }); }
    NextToken = r.NextToken; if (++n >= MAX_PAGES && NextToken) { notes.push(`${label}: stopped after ${MAX_PAGES} pages`); break; }
  } while (NextToken);
  return out;
}

export interface SignInRefreshResult { accounts: number; events_read: number; stored: number; roots: number; errors: string[]; took_ms: number }

/** Reads root posture and sign-in events for every account, stores the fingerprints and folds them onto the identity rows. */
export async function refreshSignIns(onError: (m: string) => void = () => {}, onLog: (l: string) => void = () => {}): Promise<SignInRefreshResult> {
  const t0 = Date.now(); const errors: string[] = []; const notes: string[] = [];
  const fail = (m: string) => { errors.push(m); onError(m); };
  const list = targets(errors);
  const marks = getJsonSetting<Record<string, string>>(MARKS, {});
  const floor = Date.now() - WINDOW_DAYS * 86_400_000;
  const ssoNames = new Map((db.prepare("select user_id, user_name from inventory_sso_user").all() as { user_id: string; user_name: string }[]).map((r) => [r.user_id, r.user_name]));
  const sso = ssoMeta();
  const ins = db.prepare(`insert into sign_in_events(event_id, account_id, region, event_time, event_name, source, actor_type, actor, actor_id, channel, client, platform, factor, failed, source_ip, target, workflow, fetched_at)
    values (@event_id, @account_id, @region, @event_time, @event_name, @source, @actor_type, @actor, @actor_id, @channel, @client, @platform, @factor, @failed, @source_ip, @target, @workflow, datetime('now'))
    on conflict(event_id) do update set channel = excluded.channel, workflow = coalesce(excluded.workflow, sign_in_events.workflow)`);
  const insChange = db.prepare(`insert into directory_changes(event_id, event_time, event_name, what, target_user_id, target_name, by, failed, device_id, fetched_at)
    values (@event_id, @event_time, @event_name, @what, @target_user_id, @target_name, @by, @failed, @device_id, datetime('now'))
    on conflict(event_id) do update set target_name = coalesce(excluded.target_name, directory_changes.target_name), device_id = coalesce(excluded.device_id, directory_changes.device_id)`);
  let read = 0; let stored = 0; let centralized: boolean | null = null; let rootSessions: boolean | null = null;
  const now = new Date().toISOString();
  const upRoot = db.prepare(`insert into inventory_root_user(account_id, arn, mfa_enabled, mfa_kind, access_keys, signing_certs, password_last_used, key_last_used, report_at, centralized, root_sessions, first_seen, last_seen, gone)
    values (@account_id, @arn, @mfa_enabled, @mfa_kind, @access_keys, @signing_certs, @password_last_used, @key_last_used, @report_at, @centralized, @root_sessions, @now, @now, 0)
    on conflict(account_id) do update set arn = excluded.arn, mfa_enabled = coalesce(excluded.mfa_enabled, inventory_root_user.mfa_enabled), mfa_kind = coalesce(excluded.mfa_kind, inventory_root_user.mfa_kind), access_keys = coalesce(excluded.access_keys, inventory_root_user.access_keys),
      signing_certs = coalesce(excluded.signing_certs, inventory_root_user.signing_certs), password_last_used = coalesce(excluded.password_last_used, inventory_root_user.password_last_used), key_last_used = coalesce(excluded.key_last_used, inventory_root_user.key_last_used),
      report_at = coalesce(excluded.report_at, inventory_root_user.report_at), centralized = excluded.centralized, root_sessions = excluded.root_sessions, last_seen = excluded.last_seen, gone = 0`);

  // whether the organisation manages member roots centrally: the management account answers, anywhere else the call is refused
  const parent = list.find((t) => t.is_parent);
  if (parent) {
    const iam = new IAMClient({ region: "us-east-1", credentials: parent.creds.provider });
    try { const r = await iam.send(new ListOrganizationsFeaturesCommand({})); const f = r.EnabledFeatures ?? []; centralized = f.includes("RootCredentialsManagement"); rootSessions = f.includes("RootSessions"); noteSuccess(["iam:ListOrganizationsFeatures"], "root access management"); }
    catch (e: any) {
      // the organisation has not enabled trusted access for IAM: central root access management is off, not unknown
      if (e?.name === "ServiceAccessNotEnabledException") { centralized = false; rootSessions = false; notes.push("central root access is off: trusted access for IAM is not enabled in the organisation"); }
      else notes.push(`centralized root access not read: ${String(e?.name || "")} ${String(e?.message || e).slice(0, 140)}`.trim());
    }
    finally { iam.destroy(); }
  }

  for (const t of list) {
    const acct = t.account_id ?? "";
    const root = await readRoot(t, fail, notes);
    upRoot.run({ account_id: acct, arn: `arn:aws:iam::${acct}:root`, ...root, mfa_enabled: root.mfa_enabled == null ? null : root.mfa_enabled ? 1 : 0, centralized: t.is_parent ? null : centralized == null ? null : centralized ? 1 : 0, root_sessions: t.is_parent ? null : rootSessions == null ? null : rootSessions ? 1 : 0, now });
    const regions = [...new Set(["us-east-1", t.creds.region, ...(t.is_parent && sso.region ? [sso.region] : [])].filter(Boolean))];
    for (const region of regions) {
      const client = new CloudTrailClient({ region, credentials: t.creds.provider });
      const queries: LookupAttribute[] = [{ AttributeKey: "EventSource", AttributeValue: "signin.amazonaws.com" }];
      if (t.is_parent && region === sso.region) queries.push({ AttributeKey: "EventName", AttributeValue: "GetRoleCredentials" }, { AttributeKey: "EventName", AttributeValue: "Federate" }, { AttributeKey: "EventSource", AttributeValue: "sso-directory.amazonaws.com" }, { AttributeKey: "EventSource", AttributeValue: "identitystore.amazonaws.com" });
      try {
        for (const q of queries) {
          const mk = `${acct}|${region}|${q.AttributeValue}`;
          const since = new Date(Math.max(floor, marks[mk] ? Date.parse(marks[mk]) - 3600_000 : floor));
          const evs = await lookup(client, q, since, notes, `${acct || "parent"} ${region} ${q.AttributeValue}`);
          read += evs.length;
          db.transaction(() => {
            for (const ev of evs) {
              if (/directory|identitystore/.test(String(q.AttributeValue))) { const c = directoryChange(ev, ssoNames); if (c) stored += insChange.run({ ...c, failed: c.failed ? 1 : 0, device_id: c.device_id ?? null }).changes; continue; }
              const s = signInFromEvent({ ...ev, region, account_id: t.account_id }, ssoNames); if (s) stored += ins.run({ ...s, failed: s.failed ? 1 : 0, workflow: s.workflow ?? null }).changes;
            }
          })();
          const newest = evs.map((e) => e.time).sort().pop(); if (newest) marks[mk] = newest;
        }
        noteSuccess(["cloudtrail:LookupEvents"], `sign-ins ${region}`);
      } catch (e) { fail(describeError(e, `sign-ins ${acct || "parent"} ${region} (cloudtrail:LookupEvents)`)); }
      finally { client.destroy(); }
    }
  }
  setSetting(MARKS, JSON.stringify(marks));
  db.prepare("delete from sign_in_events where event_time < ?").run(new Date(floor).toISOString());
  // directory changes are kept for a year: an MFA device removed in spring still explains an account without one in autumn
  db.prepare("delete from directory_changes where event_time < ?").run(new Date(Date.now() - 365 * 86_400_000).toISOString());
  db.prepare("update inventory_root_user set gone = 1 where gone = 0 and last_seen < ?").run(now);
  foldOntoIdentities();
  setSetting(META, JSON.stringify({ read_at: now, took_ms: Date.now() - t0, events_read: read, stored, accounts: list.length, errors, notes, centralized, root_sessions: rootSessions } satisfies SignInMeta));
  onLog(`${list.length} account(s): ${read} sign-in events read, ${stored} new${errors.length ? `; ${errors.join("; ")}` : ""} in ${Date.now() - t0} ms`);
  return { accounts: list.length, events_read: read, stored, roots: list.length, errors, took_ms: Date.now() - t0 };
}

const rowsOf = (sql: string, ...p: unknown[]): any[] => { try { return db.prepare(sql).all(...p) as any[]; } catch { return []; } };

/** Every fingerprint in the window: the stored sign-ins and the stored write events made by a person or a long-lived key. */
export function allFingerprints(): SignIn[] {
  const since = new Date(Date.now() - WINDOW_DAYS * 86_400_000).toISOString();
  const signIns = rowsOf("select * from sign_in_events where event_time >= ?", since).map((r) => ({ ...r, failed: Boolean(r.failed) })) as SignIn[];
  const writes = rowsOf(`select event_id, account_id, region, event_time, event_name, username, user_agent, source_ip, identity_type, principal_arn, key_kind, key_tail, error_code from trail_events
    where event_time >= ? and user_agent is not null and identity_type in ('Root', 'IAMUser', 'AssumedRole')`, since).map(signInFromWrite).filter((s): s is SignIn => s != null);
  return [...signIns, ...writes];
}

/** Writes each actor's clients to its identity row (root, IAM user, Identity Center user), where the graph mirror reads them. */
export function foldOntoIdentities(): void {
  const folded = foldClients(allFingerprints());
  db.transaction(() => {
    const iam = db.prepare("update inventory_iam_user set clients = ? where arn = ?");
    for (const u of rowsOf("select arn, name, account_id from inventory_iam_user")) iam.run(JSON.stringify(folded.get(actorKey("iam_user", u.name, u.account_id)) ?? []), u.arn);
    const sso = db.prepare("update inventory_sso_user set clients = ?, changes = ? where user_id = ?");
    const changes = new Map<string, DirectoryChange[]>();
    for (const c of listDirectoryChanges()) if (c.target_user_id) changes.set(c.target_user_id, [...(changes.get(c.target_user_id) ?? []), c]);
    for (const u of rowsOf("select user_id, user_name from inventory_sso_user")) sso.run(JSON.stringify(folded.get(actorKey("sso_user", u.user_name, null)) ?? []), JSON.stringify(changes.get(u.user_id) ?? []), u.user_id);
    const root = db.prepare("update inventory_root_user set clients = ? where account_id = ?");
    for (const r of rowsOf("select account_id from inventory_root_user")) root.run(JSON.stringify(folded.get(actorKey("root", "root", r.account_id)) ?? []), r.account_id);
  })();
}

/** The stored directory changes, newest first, each named after its user when the directory still has it. */
export function listDirectoryChanges(limit = 500): DirectoryChange[] {
  const names = new Map((rowsOf("select user_id, user_name from inventory_sso_user") as { user_id: string; user_name: string }[]).map((r) => [r.user_id, r.user_name]));
  return rowsOf("select * from directory_changes order by event_time desc limit ?", limit).map((r) => ({ ...r, target_name: r.target_name ?? (r.target_user_id ? names.get(r.target_user_id) ?? null : null), failed: Boolean(r.failed) }));
}

const arr = (v: unknown): any[] => { if (Array.isArray(v)) return v; try { const p = JSON.parse(String(v ?? "[]")); return Array.isArray(p) ? p : []; } catch { return []; } };

export interface RootRow { account_id: string; arn: string; mfa_enabled: boolean | null; mfa_kind: string | null; access_keys: number | null; signing_certs: number | null; password_last_used: string | null; key_last_used: string | null; report_at: string | null; centralized: boolean | null; root_sessions: boolean | null; clients: ClientUse[]; last_sign_in: string | null; first_seen: string; last_seen: string; gone: boolean }
const nb = (v: unknown) => (v == null ? null : Boolean(v));

export function listRootUsers(scope?: AccountScope | null): RootRow[] {
  const a = accountWhere(scope);
  return rowsOf(`select * from inventory_root_user where gone = 0 and ${a.sql} order by account_id`, ...a.params).map((r) => {
    const clients = arr(r.clients) as ClientUse[];
    const lastSignIn = clients.filter((c) => c.via.includes("sign-in")).map((c) => c.last_at).sort().pop() ?? null;
    // a sign-in with a passkey or hardware token says which kind the root's device is when the virtual device list could not
    const seen = strongestMfa(clients);
    return { ...r, mfa_enabled: nb(r.mfa_enabled), mfa_kind: r.mfa_kind === "passkey_or_hardware" && (seen === "passkey" || seen === "hardware") ? seen : r.mfa_kind, centralized: nb(r.centralized), root_sessions: nb(r.root_sessions), clients, last_sign_in: [lastSignIn, r.password_last_used].filter(Boolean).sort().pop() ?? null, gone: Boolean(r.gone) };
  });
}

/** A person or key that can get in, with its MFA and what it was seen using. */
export interface Actor {
  kind: "root" | "iam_user" | "sso_user" | "vercel_member"; id: string; name: string; email: string | null; display_name: string | null; account_id: string | null; admin: boolean; console: boolean; keys: number;
  mfa: "passkey" | "hardware" | "app" | "mfa" | "passkey_or_hardware" | "none" | "unknown"; mfa_source: "device" | "sign-in" | "account" | null;
  last_seen_at: string | null; clients: ClientUse[];
  /** Identity Center: sign-ins in the window and how many asked for a second factor (context-aware MFA skips a trusted browser) */
  sign_ins_90d: number | null; mfa_sign_ins_90d: number | null;
  /** disabled: Identity Center says so; no_access: an IAM user with neither a console password nor an active key */
  status: "active" | "disabled" | "no_access" | "invited";
  /** Vercel: the member's role on the team, and the tokens when the advisor's token is theirs (the API lists only the caller's) */
  role?: string | null; tokens?: VercelToken[];
  /** Identity Center: changes to this user in the directory (MFA device removed, disabled, password reset…), newest first */
  changes: DirectoryChange[];
}

export function listActors(scope?: AccountScope | null): Actor[] {
  const out: Actor[] = [];
  for (const r of listRootUsers(scope)) out.push({ kind: "root", id: r.arn, name: "root", email: null, display_name: null, account_id: r.account_id, admin: true, console: true, keys: r.access_keys ?? 0,
    mfa: r.mfa_enabled == null ? "unknown" : !r.mfa_enabled ? "none" : (r.mfa_kind as Actor["mfa"]) ?? "mfa", mfa_source: r.mfa_enabled == null ? null : "account", last_seen_at: r.last_sign_in ?? r.clients[0]?.last_at ?? null, clients: r.clients, sign_ins_90d: null, mfa_sign_ins_90d: null, status: "active", changes: [] });
  const a = accountWhere(scope);
  for (const u of rowsOf(`select arn, name, account_id, admin, console_access, keys_active, mfa_enabled, mfa_types, last_used, clients from inventory_iam_user where gone = 0 and ${a.sql}`, ...a.params)) {
    const clients = arr(u.clients) as ClientUse[];
    out.push({ kind: "iam_user", id: u.arn, name: u.name, email: null, display_name: null, account_id: u.account_id, admin: Boolean(u.admin), console: Boolean(u.console_access), keys: Number(u.keys_active || 0), ...iamUserMfa(arr(u.mfa_types), Boolean(u.mfa_enabled), clients), last_seen_at: u.last_used ?? clients[0]?.last_at ?? null, clients, sign_ins_90d: null, mfa_sign_ins_90d: null,
      status: !u.console_access && !Number(u.keys_active || 0) ? "no_access" : "active", changes: [] });
  }
  const ssoRows = rowsOf("select user_id, user_name, display_name, email, account_id, admin, assignments, last_sign_in, clients, status, changes from inventory_sso_user where gone = 0");
  const since = new Date(Date.now() - WINDOW_DAYS * 86_400_000).toISOString();
  const flows = new Map<string, { workflow: string | null; factor: string | null; failed: boolean }[]>();
  for (const e of rowsOf("select lower(actor) as actor, workflow, factor, failed from sign_in_events where actor_type = 'sso_user' and workflow is not null and event_time >= ?", since)) flows.set(e.actor, [...(flows.get(e.actor) ?? []), { workflow: e.workflow, factor: e.factor, failed: Boolean(e.failed) }]);
  for (const u of ssoRows) {
    if (scope && !scope.primary && !arr(u.assignments).some((x: any) => x.account_id === scope.id)) continue;
    const clients = arr(u.clients) as ClientUse[]; const seen = strongestMfa(clients);
    out.push({ kind: "sso_user", id: u.user_id, name: u.user_name, email: u.email ?? null, display_name: u.display_name ?? null, account_id: u.account_id, admin: Boolean(u.admin), console: true, keys: 0, mfa: seen ?? "unknown", mfa_source: seen ? "sign-in" : null, last_seen_at: u.last_sign_in ?? clients[0]?.last_at ?? null, clients,
      ...(() => { const w = workflowMfa((flows.get(String(u.user_name).toLowerCase()) ?? []) as any); return { sign_ins_90d: w.sign_ins, mfa_sign_ins_90d: w.with_mfa }; })(),
      status: u.status === "DISABLED" ? "disabled" : "active", changes: (arr(u.changes) as DirectoryChange[]).sort((x, y) => y.event_time.localeCompare(x.event_time)) });
  }
  // the Vercel team's members: under every-account scope or the team's own; matched to the AWS identities by username, e-mail local part or GitHub login
  const team = vercelTeam();
  if (team && (!scope || scope.id === team.id)) {
    const x = teamExtras(team.id);
    for (const m of x.members) {
      const own = x.token_owner?.uid === m.uid;
      out.push({ kind: "vercel_member", id: memberNodeId(team.id, m), name: m.username ?? m.uid, email: m.email_key ?? null, display_name: m.github ?? null, account_id: team.id, admin: /owner/i.test(m.role ?? ""), console: true,
        keys: own ? x.tokens.length : 0, mfa: m.mfa === true ? "mfa" : m.mfa === false ? "none" : "unknown", mfa_source: m.mfa == null ? null : "account", last_seen_at: null, clients: [], sign_ins_90d: null, mfa_sign_ins_90d: null,
        status: m.confirmed ? "active" : "invited", changes: [], role: m.role, tokens: own ? x.tokens : undefined });
    }
  }
  return out;
}

/** Weakest first: a person is as strong as the weakest way in among the identities that open a console. */
const MFA_RANK: Record<string, number> = { none: 0, unknown: 1, mfa: 2, app: 3, passkey_or_hardware: 4, hardware: 5, passkey: 6 };

/** One person (or machine) behind one or more identities, matched by name, email or display name (sign_in_facts groupPeople). */
export interface Person {
  key: string; name: string; email: string | null; machine: boolean; matched_by: string[]; identities: Actor[];
  admin: boolean; mfa: Actor["mfa"]; platforms: string[]; channels: string[]; keys: number; last_seen_at: string | null;
  /** which identity the weakest MFA belongs to, when the person has more than one */
  mfa_weakest_kind: Actor["kind"] | null;
  /** active when any identity still opens a way in; invited when the only ones are pending invitations; disabled otherwise */
  status: "active" | "disabled" | "invited";
}

/** The non-root identities as people, admins and the weakest MFA first; machines (no console anywhere) last. */
export function listPeople(actors: Actor[]): Person[] {
  return groupPeople(actors).map((g) => {
    const ids = g.identities; const sso = ids.find((i) => i.kind === "sso_user");
    const live = ids.filter((i) => i.status === "active");
    const gate = live.filter((i) => i.console); const pool = gate.length ? gate : live.length ? live : ids;
    const weakest = [...pool].sort((a, b) => (MFA_RANK[a.mfa] ?? 9) - (MFA_RANK[b.mfa] ?? 9))[0];
    const mfa = weakest?.mfa ?? "unknown";
    const clients = ids.flatMap((i) => i.clients);
    return {
      key: g.key, name: sso?.display_name || sso?.name || ids[0].name, email: sso?.email ?? null, machine: g.machine, matched_by: g.matched_by, identities: ids,
      mfa_weakest_kind: ids.length > 1 && weakest ? weakest.kind : null,
      status: live.length ? "active" as const : ids.some((i) => i.status === "invited") ? "invited" as const : "disabled" as const, admin: live.some((i) => i.admin), mfa, platforms: [...new Set(clients.map((c) => c.platform).filter((p): p is string => Boolean(p)))], channels: [...new Set(clients.map((c) => c.channel))],
      keys: ids.reduce((n, i) => n + i.keys, 0), last_seen_at: ids.map((i) => i.last_seen_at).filter((t): t is string => Boolean(t)).sort().pop() ?? null,
    };
  }).sort((a, b) => Number(a.status === "disabled") - Number(b.status === "disabled") || Number(a.machine) - Number(b.machine) || Number(b.admin) - Number(a.admin) || (MFA_RANK[a.mfa] ?? 9) - (MFA_RANK[b.mfa] ?? 9) || String(b.last_seen_at ?? "").localeCompare(String(a.last_seen_at ?? "")));
}

/** Desktop platforms: a long-lived key used from one sits on a laptop. */
const DESKTOP = new Set(["macOS", "Windows", "Linux"]);

export interface AccessSummary {
  accounts: number; roots_without_mfa: number; roots_with_keys: number; roots_signed_in_90d: number; roots_with_app_mfa: number; centralized: boolean | null; root_sessions: boolean | null;
  people: number; machines: number; disabled: number; people_passkey: number; people_app_only: number; people_no_mfa: number; people_unknown_mfa: number; keys_on_desktops: number;
  platforms: { platform: string; actors: number }[]; read_at: string | null; errors: string[]; notes: string[];
}

export function accessSummary(scope?: AccountScope | null, actors = listActors(scope)): AccessSummary {
  const m = signInMeta(); const roots = actors.filter((a) => a.kind === "root"); const everyone = listPeople(actors); const people = everyone.filter((p) => !p.machine && p.status === "active");
  const since = Date.now() - WINDOW_DAYS * 86_400_000;
  const plat = new Map<string, Set<string>>();
  for (const p of [...roots.map((r) => ({ key: r.id, identities: [r] })), ...everyone]) for (const c of p.identities.flatMap((i) => i.clients)) if (c.platform) { const s = plat.get(c.platform) ?? new Set<string>(); s.add(p.key); plat.set(c.platform, s); }
  return {
    accounts: roots.length, roots_without_mfa: roots.filter((r) => r.mfa === "none").length, roots_with_keys: roots.filter((r) => r.keys > 0).length, roots_with_app_mfa: roots.filter((r) => r.mfa === "app").length,
    roots_signed_in_90d: roots.filter((r) => r.last_seen_at && Date.parse(r.last_seen_at) >= since).length, centralized: m.centralized, root_sessions: m.root_sessions,
    people: people.length, people_passkey: people.filter((p) => p.mfa === "passkey" || p.mfa === "hardware").length, people_app_only: people.filter((p) => p.mfa === "app").length,
    people_no_mfa: people.filter((p) => p.mfa === "none").length, people_unknown_mfa: people.filter((p) => p.mfa === "unknown" || p.mfa === "mfa").length,
    machines: everyone.filter((p) => p.machine && p.status === "active").length, disabled: everyone.filter((p) => p.status === "disabled").length,
    keys_on_desktops: actors.filter((a) => a.clients.some((c) => c.factors.includes("access_key") && c.platform && DESKTOP.has(c.platform))).length,
    platforms: [...plat.entries()].map(([platform, s]) => ({ platform, actors: s.size })).sort((a, b) => b.actors - a.actors),
    read_at: m.read_at, errors: m.errors, notes: m.notes,
  };
}

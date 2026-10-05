/**
 * The pure half of src/sign_ins.ts: a CloudTrail user agent as client, platform and channel; a sign-in or write event
 * as a fingerprint (actor, channel, client, platform, factor); the fold of fingerprints per actor; the root row of a
 * credential report. No database, no SDK: the graph mapping (src/adapters/aws/resources.ts) and the tests use it.
 */

/** The kind of MFA device behind a serial: `:mfa/` a virtual device (authenticator app), `:u2f/` a passkey or security key, a bare serial a hardware token. Pure. */
export function mfaTypeOf(serial: unknown): "app" | "passkey" | "hardware" | null {
  const s = String(serial ?? "");
  if (!s) return null;
  return /:mfa\//.test(s) ? "app" : /:u2f\//.test(s) ? "passkey" : "hardware";
}

export type Channel = "console" | "portal" | "cli" | "sdk" | "iac" | "aws" | "unknown";
/** A factor: how the actor proved who it was on that event. app, passkey and hardware are second factors. */
export type Factor = "password" | "app" | "passkey" | "hardware" | "mfa" | "sso" | "federated" | "access_key" | "session" | "console_session";
export const MFA_FACTORS: ReadonlySet<string> = new Set(["app", "passkey", "hardware", "mfa"]);
export const FACTOR_WORDS: Record<string, string> = {
  password: "password", app: "authenticator app", passkey: "passkey or security key", hardware: "hardware token", mfa: "MFA (type not recorded)",
  sso: "Identity Center session", federated: "federated", access_key: "access key", session: "temporary credentials", console_session: "console session",
};

export interface ClientInfo { client: string; platform: string | null; channel: Channel }

/**
 * A CloudTrail user agent as the client, the platform it runs on and the channel. Browsers are the console; the
 * AWS CLI, SDKs and infrastructure tools name themselves and carry `os/<name>` and `exec-env/<where>`. Pure.
 */
export function parseUserAgent(ua: string | null | undefined): ClientInfo {
  const s = String(ua || "").trim();
  if (!s) return { client: "unknown", platform: null, channel: "unknown" };
  if (/^(console|signin)\.amazonaws\.com$/i.test(s)) return { client: "AWS console", platform: null, channel: "console" };
  if (s === "AWS Internal" || /^[a-z0-9-]+(\.[a-z0-9-]+)*\.amazonaws\.com$/i.test(s) || /^aws-internal\//i.test(s)) return { client: "AWS service", platform: null, channel: "aws" };
  const env = /exec-env\/([A-Za-z0-9_.-]+)/.exec(s)?.[1] ?? "";
  const os = (/\bos\/([A-Za-z0-9_]+)/.exec(s)?.[1] ?? "").toLowerCase();
  const platform = /CloudShell/i.test(env) ? "CloudShell" : /^AWS_Lambda/i.test(env) ? "AWS Lambda" : /^AWS_ECS/i.test(env) ? "AWS ECS" : /^AWS_EC2|^EC2/i.test(env) ? "AWS EC2"
    : os === "macos" || os === "darwin" ? "macOS" : os === "linux" ? "Linux" : os === "windows" || os === "win32" ? "Windows" : os === "ios" ? "iOS" : os === "android" ? "Android" : null;
  const browserOs = /iPhone/.test(s) ? "iOS" : /iPad/.test(s) ? "iPadOS" : /Android/.test(s) ? "Android" : /Macintosh|Mac OS X/.test(s) ? "macOS" : /Windows/.test(s) ? "Windows" : /CrOS/.test(s) ? "ChromeOS" : /Linux/.test(s) ? "Linux" : null;
  if (/console.?mobile|AWSConsoleMobile/i.test(s)) return { client: "AWS Console mobile app", platform: browserOs ?? platform, channel: "console" };
  if (/Terraform\/|terraform-provider-aws/i.test(s)) return { client: "Terraform", platform, channel: "iac" };
  if (/pulumi/i.test(s)) return { client: "Pulumi", platform, channel: "iac" };
  if (/aws-cdk|\bcdk\//i.test(s)) return { client: "AWS CDK", platform, channel: "iac" };
  if (/^aws-cli\/|\baws-cli\//i.test(s)) return { client: "aws-cli", platform, channel: "cli" };
  if (/^Boto3\//i.test(s)) return { client: "boto3", platform, channel: "sdk" };
  if (/^Botocore\//i.test(s)) return { client: "botocore", platform, channel: "sdk" };
  const sdk = /aws-sdk-(js|nodejs|go|java|ruby|dotnet|php|rust|cpp|kotlin|swift)/i.exec(s)?.[1]?.toLowerCase();
  if (sdk) return { client: `AWS SDK (${sdk === "nodejs" ? "js" : sdk})`, platform, channel: "sdk" };
  if (/^Mozilla\//.test(s)) {
    const browser = /Edg\//.test(s) ? "Edge" : /OPR\//.test(s) ? "Opera" : /Firefox\//.test(s) ? "Firefox" : /CriOS\/|Chrome\//.test(s) ? "Chrome" : /Safari\//.test(s) ? "Safari" : "browser";
    return { client: browser, platform: browserOs, channel: "console" };
  }
  return { client: s.split(/[\/\s]/)[0].slice(0, 40) || "unknown", platform, channel: "sdk" };
}

/** Identity Center's CredentialType as a factor. Pure. */
export function factorOfCredentialType(t: unknown): Factor | null {
  const s = String(t || "").toUpperCase();
  if (!s) return null;
  if (s === "PASSWORD") return "password";
  if (s.includes("TOTP")) return "app";
  if (s.includes("WEBAUTHN") || s.includes("FIDO") || s.includes("PASSKEY")) return "passkey";
  if (s.includes("EXTERNAL") || s.includes("IDP") || s.includes("SAML")) return "federated";
  return null;
}

export interface SignIn {
  event_id: string; account_id: string | null; region: string | null; event_time: string; event_name: string; source: "signin" | "sso" | "trail";
  actor_type: "root" | "iam_user" | "sso_user" | "role" | "unknown"; actor: string; actor_id: string | null;
  channel: Channel; client: string; platform: string | null; factor: Factor | null; failed: boolean; source_ip: string | null; target: string | null;
  /** Identity Center's AuthWorkflowID: one sign-in, across its password and second-factor challenges */
  workflow?: string | null;
}

const lastSegment = (arn: string) => arn.split("/").pop() ?? arn;
const SSO_ROLE = /:assumed-role\/AWSReservedSSO_[^/]+\/(.+)$/;

/** Who an event is about, from its userIdentity; an Identity Center user is named by its session or looked up by id. */
function actorOf(ui: any, account: string | null, extraName: unknown, ssoNames: Map<string, string>): Pick<SignIn, "actor_type" | "actor" | "actor_id"> {
  const type = String(ui?.type || "");
  const arn = ui?.arn ? String(ui.arn) : null;
  if (type === "Root") return { actor_type: "root", actor: "root", actor_id: `arn:aws:iam::${ui?.accountId || account || ""}:root` };
  if (type === "IAMUser") return { actor_type: "iam_user", actor: String(ui?.userName || (arn ? lastSegment(arn) : "?")), actor_id: arn };
  if (type === "AssumedRole" && arn) { const m = SSO_ROLE.exec(arn); if (m) return { actor_type: "sso_user", actor: m[1], actor_id: null }; return { actor_type: "role", actor: arn.split(":assumed-role/").pop() ?? arn, actor_id: arn }; }
  const name = ui?.userName ?? extraName ?? (ui?.onBehalfOf?.userId ? ssoNames.get(String(ui.onBehalfOf.userId)) : null) ?? (ui?.principalId ? ssoNames.get(String(ui.principalId)) : null);
  if (name && !/HIDDEN_DUE_TO_SECURITY_REASONS/.test(String(name))) return { actor_type: "sso_user", actor: String(name), actor_id: ui?.onBehalfOf?.userId ? String(ui.onBehalfOf.userId) : null };
  return { actor_type: "unknown", actor: "unknown", actor_id: null };
}

const IDC_EVENTS = new Set(["CredentialChallenge", "CredentialVerification", "UserAuthentication"]);

/**
 * One sign-in event (signin.amazonaws.com or sso.amazonaws.com) as a fingerprint; null for an event that says
 * nothing about who signed in or how. `ssoNames` maps an identity store user id to its user name. Pure.
 */
export function signInFromEvent(ev: { id: string; name: string; time: string; region: string | null; account_id: string | null; detail: any }, ssoNames: Map<string, string> = new Map()): SignIn | null {
  const d = ev.detail ?? {}; const ui = d.userIdentity ?? {}; const extra = d.additionalEventData ?? {};
  const ua = parseUserAgent(d.userAgent);
  const base = { event_id: ev.id, account_id: ev.account_id ?? (ui.accountId ? String(ui.accountId) : null), region: ev.region, event_time: ev.time, event_name: ev.name, source_ip: d.sourceIPAddress ? String(d.sourceIPAddress) : null, client: ua.client, platform: ua.platform };
  if (ev.name === "ConsoleLogin") {
    const who = actorOf(ui, base.account_id, null, ssoNames);
    const failed = d.responseElements?.ConsoleLogin === "Failure" || Boolean(d.errorMessage) || Boolean(d.errorCode);
    const used = extra.MFAUsed === "Yes";
    const factor: Factor = who.actor_type === "sso_user" || who.actor_type === "role" ? "federated" : (mfaTypeOf(extra.MFAIdentifier) ?? (used ? "mfa" : "password"));
    return { ...base, source: "signin", ...who, channel: ua.channel === "unknown" ? "console" : ua.channel, factor, failed, target: null };
  }
  if (IDC_EVENTS.has(ev.name)) {
    const who = actorOf(ui, base.account_id, extra.UserName, ssoNames);
    const details = JSON.stringify(d.serviceEventDetails ?? {});
    const failed = Boolean(d.errorCode) || /"(Failure|FAILURE|Failed|FAILED)"/.test(details);
    return { ...base, source: "signin", ...who, channel: "portal", factor: factorOfCredentialType(extra.CredentialType), failed, target: null, workflow: extra.AuthWorkflowID ? String(extra.AuthWorkflowID) : null };
  }
  if (ev.name === "GetRoleCredentials" || ev.name === "Federate") {
    const who = actorOf(ui, base.account_id, null, ssoNames);
    if (who.actor_type === "unknown") return null;
    const rp = d.requestParameters ?? {};
    const target = [rp.accountId, rp.roleName].filter(Boolean).join(" ") || null;
    // GetRoleCredentials from a browser is the portal's "Access keys": temporary keys copied out to a terminal
    const channel: Channel = ev.name === "Federate" ? "console" : ua.channel === "console" ? "portal" : ua.channel === "unknown" ? "cli" : ua.channel;
    return { ...base, source: "sso", ...who, actor_type: "sso_user", channel, factor: "sso", failed: Boolean(d.errorCode), target };
  }
  return null;
}

/**
 * A stored write event (src/trail.ts) as a fingerprint: who made it with which kind of credential from which
 * client. Root and IAM users always; an assumed role only when it is an Identity Center session (a person). Pure.
 */
export function signInFromWrite(r: { event_id: string; account_id: string | null; region: string | null; event_time: string; event_name: string; username: string | null; user_agent: string | null; source_ip: string | null; identity_type: string | null; principal_arn: string | null; key_kind: string | null; key_tail: string | null; error_code: string | null }): SignIn | null {
  if (!r.user_agent) return null;
  const ua = parseUserAgent(r.user_agent);
  if (ua.channel === "aws") return null;
  const who = actorOf({ type: r.identity_type, arn: r.principal_arn, userName: r.username, accountId: r.account_id }, r.account_id, null, new Map());
  if (who.actor_type === "role" || who.actor_type === "unknown") return null;
  const factor: Factor = ua.channel === "console" ? "console_session" : who.actor_type === "sso_user" ? "sso" : r.key_kind === "AKIA" ? "access_key" : "session";
  return { event_id: `trail:${r.event_id}`, account_id: r.account_id, region: r.region, event_time: r.event_time, event_name: r.event_name, source: "trail", ...who, channel: ua.channel, client: ua.client, platform: ua.platform, factor, failed: Boolean(r.error_code), source_ip: r.source_ip, target: factor === "access_key" && r.key_tail ? `key …${r.key_tail}` : null };
}

/** Identity Center sign-ins (one per AuthWorkflowID) and how many of them asked for a second factor. Pure. */
export function workflowMfa(events: Pick<SignIn, "workflow" | "factor" | "failed">[]): { sign_ins: number; with_mfa: number } {
  const all = new Set<string>(); const mfa = new Set<string>();
  for (const e of events) { if (!e.workflow || e.failed) continue; all.add(e.workflow); if (e.factor && MFA_FACTORS.has(e.factor)) mfa.add(e.workflow); }
  return { sign_ins: all.size, with_mfa: mfa.size };
}

/** What an actor was seen using: one entry per account, channel, client and platform. */
export interface ClientUse {
  account_id: string | null; channel: Channel; client: string; platform: string | null; factors: string[]; events: number; failures: number;
  first_at: string; last_at: string; last_ip: string | null; keys: string[]; via: ("sign-in" | "api")[];
}
export const actorKey = (type: string, name: string, account: string | null) => (type === "sso_user" ? `sso_user|${name.toLowerCase()}` : `${type}|${account ?? ""}|${name}`);

/** The fingerprints grouped per actor, newest use first in each. Pure. */
export function foldClients(events: SignIn[]): Map<string, ClientUse[]> {
  const byActor = new Map<string, Map<string, ClientUse>>();
  for (const e of [...events].sort((a, b) => a.event_time.localeCompare(b.event_time))) {
    const ak = actorKey(e.actor_type, e.actor, e.account_id);
    const ck = `${e.account_id ?? ""}|${e.channel}|${e.client}|${e.platform ?? ""}`;
    const m = byActor.get(ak) ?? new Map<string, ClientUse>(); byActor.set(ak, m);
    const c = m.get(ck) ?? { account_id: e.account_id, channel: e.channel, client: e.client, platform: e.platform, factors: [], events: 0, failures: 0, first_at: e.event_time, last_at: e.event_time, last_ip: null, keys: [], via: [] };
    c.events++; if (e.failed) c.failures++;
    if (!e.failed && e.factor && !c.factors.includes(e.factor)) c.factors.push(e.factor);
    if (e.event_time >= c.last_at) { c.last_at = e.event_time; if (e.source_ip) c.last_ip = e.source_ip; }
    const tail = e.target?.startsWith("key …") ? e.target.slice("key …".length) : null;
    if (tail && !c.keys.includes(tail)) c.keys.push(tail);
    const via = e.source === "trail" ? "api" : "sign-in"; if (!c.via.includes(via)) c.via.push(via);
    m.set(ck, c);
  }
  const out = new Map<string, ClientUse[]>();
  for (const [k, m] of byActor) out.set(k, [...m.values()].sort((a, b) => b.last_at.localeCompare(a.last_at)));
  return out;
}

/** The strongest second factor seen: a passkey beats a hardware token beats an app; null when none was seen. Pure. */
export function strongestMfa(clients: ClientUse[]): "passkey" | "hardware" | "app" | "mfa" | null {
  const f = new Set(clients.flatMap((c) => c.factors));
  return f.has("passkey") ? "passkey" : f.has("hardware") ? "hardware" : f.has("app") ? "app" : f.has("mfa") ? "mfa" : null;
}

/** One line per client for the graph and the agent: `aws-cli on macOS · cli · access key · 42× · last 2026-10-04`. Pure. */
export const clientLine = (c: ClientUse) => `${c.client}${c.platform ? ` on ${c.platform}` : ""} · ${c.channel}${c.factors.length ? ` · ${c.factors.map((f) => FACTOR_WORDS[f] ?? f).join(" + ")}` : ""}${c.keys.length ? ` (${c.keys.map((k) => `…${k}`).join(", ")})` : ""} · ${c.events}×${c.failures ? ` (${c.failures} failed)` : ""} · last ${c.last_at.slice(0, 10)}${c.account_id ? ` · ${c.account_id}` : ""}`;

/** The root row of a credential report (CSV): password and access key last use, MFA. Pure. */
export function rootFromCredentialReport(csv: string): { password_last_used: string | null; key_last_used: string | null; mfa_active: boolean | null; keys_active: number } | null {
  const lines = csv.split(/\r?\n/).filter(Boolean);
  if (lines.length < 2) return null;
  const head = lines[0].split(",");
  const row = lines.slice(1).map((l) => l.split(",")).find((c) => c[0] === "<root_account>");
  if (!row) return null;
  const get = (k: string) => { const i = head.indexOf(k); const v = i >= 0 ? row[i] : undefined; return v && !/^(N\/A|no_information|not_supported)$/i.test(v) ? v : null; };
  const k1 = get("access_key_1_active") === "true"; const k2 = get("access_key_2_active") === "true";
  const keyUse = [get("access_key_1_last_used_date"), get("access_key_2_last_used_date")].filter((x): x is string => Boolean(x)).sort().pop() ?? null;
  return { password_last_used: get("password_last_used"), key_last_used: keyUse, mfa_active: get("mfa_active") == null ? null : get("mfa_active") === "true", keys_active: (k1 ? 1 : 0) + (k2 ? 1 : 0) };
}

/** The MFA an IAM user has from its registered devices (the strongest), falling back to the sign-ins. Pure. */
export function iamUserMfa(mfaTypes: string[], enabled: boolean, clients: ClientUse[]): { mfa: "passkey" | "hardware" | "app" | "mfa" | "none"; mfa_source: "device" | "sign-in" } {
  const t = new Set(mfaTypes);
  if (t.has("passkey")) return { mfa: "passkey", mfa_source: "device" };
  if (t.has("hardware")) return { mfa: "hardware", mfa_source: "device" };
  if (t.has("app")) return { mfa: "app", mfa_source: "device" };
  const seen = strongestMfa(clients);
  if (seen) return { mfa: seen, mfa_source: "sign-in" };
  return enabled ? { mfa: "mfa", mfa_source: "device" } : { mfa: "none", mfa_source: "device" };
}

/** What an Identity Center directory change did, in words; null for a read (List, Describe, Search, Get). */
export const DIRECTORY_CHANGE_WORDS: Record<string, string> = {
  DeleteMfaDeviceForUser: "MFA device removed", CreateMfaDeviceForUser: "MFA device registered", RegisterMfaDeviceForUser: "MFA device registered", UpdateMfaDeviceForUser: "MFA device renamed",
  StartWebAuthnDeviceRegistration: "passkey registration started", CompleteWebAuthnDeviceRegistration: "passkey registered", EnableUser: "user enabled", DisableUser: "user disabled",
  DeleteUser: "user deleted", CreateUser: "user created", UpdateUser: "user updated", UpdatePassword: "password changed", ResetPassword: "password reset", CreateAlias: "directory alias set",
  AddMemberToGroup: "added to a group", RemoveMemberFromGroup: "removed from a group", CreateGroup: "group created", DeleteGroup: "group deleted",
  CreateGroupMembership: "added to a group", DeleteGroupMembership: "removed from a group",
};
export interface DirectoryChange { event_id: string; event_time: string; event_name: string; what: string; target_user_id: string | null; target_name: string | null; by: string | null; failed: boolean }

/**
 * An Identity Center directory event (sso-directory or identitystore) as a change to a user: what happened, to whom
 * (the user id from the request, named when the directory knows it) and by whom (the session name of an Identity
 * Center session, else the caller's ARN). Reads are dropped. Pure.
 */
export function directoryChange(ev: { id: string; name: string; time: string; detail: any }, names: Map<string, string> = new Map()): DirectoryChange | null {
  if (/^(List|Describe|Search|Get|Is|Batch(Get|Describe))/.test(ev.name)) return null;
  const d = ev.detail ?? {}; const rp = d.requestParameters ?? {};
  const target = String(rp.user?.userId ?? rp.userId ?? rp.UserId ?? rp.memberId?.userId ?? rp.MemberId?.UserId ?? "") || null;
  const arn = String(d.userIdentity?.arn ?? "");
  const by = SSO_ROLE.exec(arn)?.[1] ?? (d.userIdentity?.type === "Root" ? "root" : arn ? lastSegment(arn) : d.userIdentity?.userName ?? null);
  const what = DIRECTORY_CHANGE_WORDS[ev.name] ?? ev.name.replace(/([a-z])([A-Z])/g, "$1 $2").toLowerCase();
  return { event_id: ev.id, event_time: ev.time, event_name: ev.name, what, target_user_id: target, target_name: target ? names.get(target) ?? null : null, by: by ? String(by) : null, failed: Boolean(d.errorCode) };
}

/** What the person matching needs of an identity. */
export interface MatchableIdentity { kind: string; id: string; name: string; email?: string | null; display_name?: string | null; console: boolean }

/** A name reduced for matching: lower case, an email's local part, letters and digits only (`Gonzalo.Aune@example.com` → `gonzaloaune`). Pure. */
export const nameKey = (v: string | null | undefined): string | null => { const s = String(v ?? "").toLowerCase().split("@")[0].replace(/[^a-z0-9]/g, ""); return s.length >= 3 ? s : null; };

/** The keys an identity can be matched on: its name, an Identity Center user's email and display name, each reduced by nameKey. Pure. */
export function matchKeys(i: MatchableIdentity): string[] {
  return [...new Set([i.name, i.email, i.display_name].map(nameKey).filter((k): k is string => k != null))];
}

/**
 * The identities grouped into people: an IAM user and an Identity Center user (or IAM users of the same name in
 * several accounts) that share a match key are one person. Root users are left out (one per account, nobody's).
 * A group whose members all lack a console is a machine (a key used by a pipeline or an app). Pure.
 */
export function groupPeople<T extends MatchableIdentity>(identities: T[]): { key: string; matched_by: string[]; machine: boolean; identities: T[] }[] {
  const list = identities.filter((i) => i.kind !== "root");
  const parent = list.map((_, i) => i);
  const find = (i: number): number => (parent[i] === i ? i : (parent[i] = find(parent[i])));
  const owner = new Map<string, number>();
  list.forEach((ident, i) => {
    for (const k of matchKeys(ident)) {
      const j = owner.get(k);
      if (j == null) { owner.set(k, i); continue; }
      const a = find(i), b = find(j);
      if (a !== b) parent[a] = b;
    }
  });
  const groups = new Map<number, T[]>();
  list.forEach((ident, i) => { const r = find(i); groups.set(r, [...(groups.get(r) ?? []), ident]); });
  return [...groups.values()].map((ids) => {
    const sorted = [...ids].sort((a, b) => (a.kind === "sso_user" ? -1 : 0) - (b.kind === "sso_user" ? -1 : 0) || a.name.localeCompare(b.name));
    const counts = new Map<string, number>(); for (const x of ids) for (const k of matchKeys(x)) counts.set(k, (counts.get(k) ?? 0) + 1);
    const matched = [...counts.entries()].filter(([, n]) => n > 1).map(([k]) => k).sort();
    return { key: sorted.map((x) => x.id).join("|"), matched_by: matched, machine: ids.every((x) => !x.console), identities: sorted };
  });
}

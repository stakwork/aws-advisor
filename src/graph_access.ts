/**
 * Who can get in, as nodes of their own (docs/cloud-ontology.md §AdvisorCredential, §AdvisorClient):
 *
 * - (:AdvisorCredential) what an identity proves itself with: a password, an IAM access key (masked id), an MFA device
 *   (an IAM serial, a root device, an Identity Center device named by a directory event), a factor Identity Center
 *   was seen asking for when its devices cannot be listed (`observed: true`), Vercel 2FA, a Vercel token. Each with its
 *   own lifecycle: state, created, last used, expiry, removal. (identity)-[:HAS_CREDENTIAL]->(credential).
 * - (:AdvisorClient) a client on a platform through a channel (`aws-cli · macOS · cli`, `Chrome · iOS · console`),
 *   shared by everyone who uses it: not a device (CloudTrail names none). (identity)-[:SIGNS_IN_WITH {events,
 *   failures, first_at, last_at, accounts, factors}]->(client) and (credential)-[:USED_FROM {events, last_at}]->(client).
 * - (:AdvisorSource {kind: ip}) a source address sign-ins and calls came from: (identity)-[:SIGNED_IN_FROM {events,
 *   failures, first_at, last_at, clients}]->(source). Two identities from one address is a shared person or office.
 *
 * Rebuilt on every pass from the stored inventory (src/sign_ins.ts, src/iam_inventory.ts, the Vercel extras): edges not
 * written on the pass are removed, credentials not seen are marked gone, clients and addresses left with no edge go.
 */
import { db } from "./db.js";
import { allFingerprints, listActors, listDirectoryChanges, type Actor } from "./sign_ins.js";
import { actorKey, clientKey, foldIps, isPrivateIp, type ClientUse, type IpUse } from "./sign_in_facts.js";
import { teamExtras, vercelTeam } from "./adapters/vercel/inventory.js";
import type { MfaDeviceRow, AccessKeyRow } from "./iam_inventory.js";

export interface CredentialRow {
  id: string; identity_id: string; kind: "password" | "access_key" | "mfa_app" | "passkey" | "hardware_token" | "mfa" | "api_token"; provider: "aws" | "vercel"; name: string;
  state: "active" | "inactive" | "removed" | "expired" | "unknown"; observed: boolean; created_at: string | null; last_used_at: string | null; expires_at: string | null; removed_at: string | null; removed_by: string | null; detail: string | null;
}
export interface ClientRow { id: string; client: string; platform: string | null; channel: string }
export interface SignsInRow { identity_id: string; client_id: string; events: number; failures: number; first_at: string; last_at: string; accounts: string[]; factors: string[] }
export interface UsedFromRow { credential_id: string; client_id: string; events: number; last_at: string }
export interface IpRow { identity_id: string; ip: string; private: boolean; events: number; failures: number; first_at: string; last_at: string; clients: string[] }
export interface AccessGraph { credentials: CredentialRow[]; clients: ClientRow[]; signs_in: SignsInRow[]; used_from: UsedFromRow[]; ips: IpRow[] }

const MFA_KIND: Record<string, CredentialRow["kind"]> = { app: "mfa_app", passkey: "passkey", hardware: "hardware_token", mfa: "mfa", passkey_or_hardware: "mfa" };
export const clientNodeId = (c: { client: string; platform: string | null; channel: string }) => `client:${clientKey(c)}`;

/** Extra rows the builder needs beside the actors: each IAM user's devices and keys, each Identity Center user's removed devices, the Vercel tokens. */
export interface AccessExtras {
  iam: Map<string, { mfa_devices: MfaDeviceRow[]; access_keys: AccessKeyRow[]; password_last_used: string | null; console: boolean }>;
  root: Map<string, { password_last_used: string | null; key_last_used: string | null }>;
  removed: { user_id: string; device_id: string | null; at: string; by: string | null }[];
  tokens: { member_id: string; id: string; name: string | null; created_at: string | null; active_at: string | null; expires_at: string | null }[];
  ips: Map<string, IpUse[]>;
}

/** The credential, client and address rows for a set of identities. Pure. */
export function accessGraphRows(actors: Actor[], x: AccessExtras, now = Date.now()): AccessGraph {
  const credentials: CredentialRow[] = []; const clients = new Map<string, ClientRow>(); const signsIn: SignsInRow[] = []; const usedFrom = new Map<string, UsedFromRow>(); const ips: IpRow[] = [];
  const cred = (c: Omit<CredentialRow, "observed" | "removed_at" | "removed_by" | "detail" | "expires_at"> & Partial<CredentialRow>) => { credentials.push({ observed: false, removed_at: null, removed_by: null, detail: null, expires_at: null, ...c }); return c.id; };
  const use = (credentialId: string, c: ClientUse) => { const id = clientNodeId(c); const k = `${credentialId}>${id}`; const cur = usedFrom.get(k); usedFrom.set(k, { credential_id: credentialId, client_id: id, events: (cur?.events ?? 0) + c.events, last_at: !cur || c.last_at > cur.last_at ? c.last_at : cur.last_at }); };
  for (const a of actors) {
    // what the identity proves itself with, and which credential each factor of a client points at
    const byFactor = new Map<string, string[]>();
    const add = (factor: string, id: string) => byFactor.set(factor, [...(byFactor.get(factor) ?? []), id]);
    if (a.kind === "root") {
      const r = x.root.get(a.id);
      add("password", cred({ id: `${a.id}#password`, identity_id: a.id, kind: "password", provider: "aws", name: "root password", state: "active", created_at: null, last_used_at: r?.password_last_used ?? null }));
      if (a.mfa !== "none" && a.mfa !== "unknown") { const id = cred({ id: `${a.id}#mfa`, identity_id: a.id, kind: MFA_KIND[a.mfa] ?? "mfa", provider: "aws", name: "root MFA device", state: "active", created_at: null, last_used_at: null }); for (const f of ["app", "passkey", "hardware", "mfa"]) add(f, id); }
      if (a.keys > 0) add("access_key", cred({ id: `${a.id}#access-keys`, identity_id: a.id, kind: "access_key", provider: "aws", name: `root access key${a.keys === 1 ? "" : "s"} (${a.keys})`, state: "active", created_at: null, last_used_at: r?.key_last_used ?? null }));
    } else if (a.kind === "iam_user") {
      const u = x.iam.get(a.id);
      if (u?.console) add("password", cred({ id: `${a.id}#password`, identity_id: a.id, kind: "password", provider: "aws", name: `${a.name} console password`, state: "active", created_at: null, last_used_at: u.password_last_used }));
      for (const d of u?.mfa_devices ?? []) add(d.kind, cred({ id: d.serial, identity_id: a.id, kind: MFA_KIND[d.kind], provider: "aws", name: d.serial.split("/").pop() ?? d.serial, state: "active", created_at: d.enabled_at, last_used_at: null }));
      for (const k of u?.access_keys ?? []) {
        const id = cred({ id: `${a.id}#key:${k.id}`, identity_id: a.id, kind: "access_key", provider: "aws", name: k.id, state: k.status === "Active" ? "active" : "inactive", created_at: k.created, last_used_at: k.last_used, detail: k.service ? `last used by ${k.service}${k.region ? ` in ${k.region}` : ""}` : null });
        add(`key:${k.id.slice(-4)}`, id);
      }
    } else if (a.kind === "sso_user") {
      const pw = a.clients.filter((c) => c.factors.includes("password"));
      add("password", cred({ id: `${a.id}#password`, identity_id: a.id, kind: "password", provider: "aws", name: `${a.name} password`, state: a.status === "disabled" ? "inactive" : "active", created_at: null, last_used_at: pw.map((c) => c.last_at).sort().pop() ?? null }));
      // the devices cannot be listed: a factor seen at sign-in stands for them, marked observed
      for (const f of ["app", "passkey", "hardware"]) {
        const seen = a.clients.filter((c) => c.factors.includes(f)); if (!seen.length) continue;
        add(f, cred({ id: `${a.id}#factor:${f}`, identity_id: a.id, kind: MFA_KIND[f], provider: "aws", name: `${a.name} ${f === "app" ? "authenticator app" : f === "passkey" ? "passkey or security key" : "hardware token"}`, state: "active", observed: true, created_at: null, last_used_at: seen.map((c) => c.last_at).sort().pop() ?? null, detail: "seen at sign-in; Identity Center exposes no device list" }));
      }
      for (const r of x.removed.filter((d) => d.user_id === a.id)) cred({ id: `${a.id}#mfa:${r.device_id ?? r.at}`, identity_id: a.id, kind: "mfa", provider: "aws", name: `${a.name} MFA device${r.device_id ? ` ${r.device_id}` : ""}`, state: "removed", created_at: null, last_used_at: null, removed_at: r.at, removed_by: r.by });
    } else if (a.kind === "vercel_member") {
      if (a.mfa === "mfa") cred({ id: `${a.id}#2fa`, identity_id: a.id, kind: "mfa", provider: "vercel", name: `${a.name} two-factor authentication`, state: "active", created_at: null, last_used_at: null });
      for (const t of x.tokens.filter((t) => t.member_id === a.id)) cred({ id: `${a.id.split("/member/")[0]}/token/${t.id}`, identity_id: a.id, kind: "api_token", provider: "vercel", name: t.name ?? t.id, state: t.expires_at && Date.parse(t.expires_at) < now ? "expired" : "active", created_at: t.created_at, last_used_at: t.active_at, expires_at: t.expires_at });
    }
    // the clients, folded across accounts per identity, and the credential each was used with
    const per = new Map<string, SignsInRow>();
    for (const c of a.clients) {
      const id = clientNodeId(c); clients.set(id, { id, client: c.client, platform: c.platform, channel: c.channel });
      const cur = per.get(id) ?? { identity_id: a.id, client_id: id, events: 0, failures: 0, first_at: c.first_at, last_at: c.last_at, accounts: [], factors: [] };
      cur.events += c.events; cur.failures += c.failures; if (c.first_at < cur.first_at) cur.first_at = c.first_at; if (c.last_at > cur.last_at) cur.last_at = c.last_at;
      if (c.account_id && !cur.accounts.includes(c.account_id)) cur.accounts.push(c.account_id);
      for (const f of c.factors) if (!cur.factors.includes(f)) cur.factors.push(f);
      per.set(id, cur);
      for (const f of c.factors) for (const cid of byFactor.get(f) ?? []) use(cid, c);
      for (const k of c.keys) for (const cid of byFactor.get(`key:${k}`) ?? []) use(cid, c);
    }
    signsIn.push(...per.values());
    for (const u of x.ips.get(a.id) ?? []) ips.push({ identity_id: a.id, ip: u.ip, private: isPrivateIp(u.ip), events: u.events, failures: u.failures, first_at: u.first_at, last_at: u.last_at, clients: u.clients });
  }
  return { credentials, clients: [...clients.values()], signs_in: signsIn, used_from: [...usedFrom.values()], ips };
}

const rows = (sql: string, ...p: unknown[]): any[] => { try { return db.prepare(sql).all(...p) as any[]; } catch { return []; } };
const parse = (s: unknown): any => { if (typeof s !== "string") return s ?? null; try { return JSON.parse(s); } catch { return null; } };

/** The extras from the stored inventory, and each actor's addresses keyed by the actor's node id. */
export function accessExtras(actors: Actor[]): AccessExtras {
  const iam = new Map(rows("select arn, mfa_devices, access_keys, password_last_used, console_access from inventory_iam_user where gone = 0").map((r) => [r.arn, { mfa_devices: parse(r.mfa_devices) ?? [], access_keys: parse(r.access_keys) ?? [], password_last_used: r.password_last_used ?? null, console: Boolean(r.console_access) }]));
  const root = new Map(rows("select arn, password_last_used, key_last_used from inventory_root_user where gone = 0").map((r) => [r.arn, { password_last_used: r.password_last_used ?? null, key_last_used: r.key_last_used ?? null }]));
  const removed = listDirectoryChanges(1000).filter((c) => c.event_name === "DeleteMfaDeviceForUser" && !c.failed && c.target_user_id).map((c) => ({ user_id: c.target_user_id!, device_id: c.device_id ?? null, at: c.event_time, by: c.by }));
  const team = vercelTeam(); const tokens: AccessExtras["tokens"] = [];
  if (team) { const v = teamExtras(team.id); const owner = actors.find((a) => a.kind === "vercel_member" && v.token_owner && a.tokens); if (owner) for (const t of v.tokens) tokens.push({ member_id: owner.id, id: t.id, name: t.name, created_at: t.created_at, active_at: t.active_at, expires_at: t.expires_at }); }
  // the addresses are folded per actor key; the actors carry their node ids
  const byKey = foldIps(allFingerprints()); const ips = new Map<string, IpUse[]>();
  for (const a of actors) { const k = a.kind === "root" ? actorKey("root", "root", a.account_id) : a.kind === "iam_user" ? actorKey("iam_user", a.name, a.account_id) : a.kind === "sso_user" ? actorKey("sso_user", a.name, null) : null; const u = k ? byKey.get(k) : undefined; if (u) ips.set(a.id, u); }
  return { iam, root, removed, tokens, ips };
}

export const accessGraph = (): AccessGraph => { const actors = listActors(null); return accessGraphRows(actors, accessExtras(actors)); };

// ---- the graph ------------------------------------------------------------------------------------------------------

const CREDENTIAL_CYPHER = `
UNWIND $rows AS row
MATCH (i:AdvisorResource {id: row.identity_id})
MERGE (c:AdvisorCredential {id: row.id}) ON CREATE SET c.first_seen = $now
SET c += {kind: row.kind, provider: row.provider, name: row.name, state: row.state, observed: row.observed, created_at: row.created_at, last_used_at: row.last_used_at, expires_at: row.expires_at, removed_at: row.removed_at, removed_by: row.removed_by, detail: row.detail,
  identity_id: row.identity_id, native_type: 'credential', native_id: row.id, gone: false, last_seen: $now, updated_at: $now}
MERGE (i)-[h:HAS_CREDENTIAL]->(c) SET h.updated_at = $now`;

const CLIENT_CYPHER = `
UNWIND $rows AS row
MERGE (k:AdvisorClient {id: row.id}) ON CREATE SET k.first_seen = $now
SET k += {client: row.client, platform: row.platform, channel: row.channel, label: row.client + coalesce(' · ' + row.platform, '') + ' · ' + row.channel, native_type: 'client', native_id: row.id, updated_at: $now}`;

const SIGNS_IN_CYPHER = `
UNWIND $rows AS row
MATCH (i:AdvisorResource {id: row.identity_id}) MATCH (k:AdvisorClient {id: row.client_id})
MERGE (i)-[r:SIGNS_IN_WITH]->(k) SET r += {events: row.events, failures: row.failures, first_at: row.first_at, last_at: row.last_at, accounts: row.accounts, factors: row.factors, updated_at: $now}`;

const USED_FROM_CYPHER = `
UNWIND $rows AS row
MATCH (c:AdvisorCredential {id: row.credential_id}) MATCH (k:AdvisorClient {id: row.client_id})
MERGE (c)-[u:USED_FROM]->(k) SET u += {events: row.events, last_at: row.last_at, updated_at: $now}`;

const IP_CYPHER = `
UNWIND $rows AS row
MATCH (i:AdvisorResource {id: row.identity_id})
MERGE (s:AdvisorSource {id: 'ip:' + row.ip}) ON CREATE SET s.kind = 'ip', s.label = row.ip, s.cidr = row.ip + CASE WHEN row.ip CONTAINS ':' THEN '/128' ELSE '/32' END, s.private = row.private, s.native_type = 'source', s.native_id = 'ip:' + row.ip
MERGE (i)-[r:SIGNED_IN_FROM]->(s) SET r += {events: row.events, failures: row.failures, first_at: row.first_at, last_at: row.last_at, clients: row.clients, updated_at: $now}`;

const chunks = <T,>(items: T[], size = 250): T[][] => { const out: T[][] = []; for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size)); return out; };

/** Writes credentials, clients and addresses for every identity, then removes what this pass did not see. */
export async function mirrorAccess(stamp: string): Promise<{ credentials: number; clients: number; signs_in: number; used_from: number; ips: number }> {
  const { enabled, writeCypher } = await import("./graph_mirror.js");
  const g = accessGraph();
  if (!enabled()) return { credentials: g.credentials.length, clients: g.clients.length, signs_in: g.signs_in.length, used_from: g.used_from.length, ips: g.ips.length };
  for (const b of chunks(g.credentials)) await writeCypher(CREDENTIAL_CYPHER, { rows: b, now: stamp });
  for (const b of chunks(g.clients)) await writeCypher(CLIENT_CYPHER, { rows: b, now: stamp });
  for (const b of chunks(g.signs_in)) await writeCypher(SIGNS_IN_CYPHER, { rows: b, now: stamp });
  for (const b of chunks(g.used_from)) await writeCypher(USED_FROM_CYPHER, { rows: b, now: stamp });
  for (const b of chunks(g.ips)) await writeCypher(IP_CYPHER, { rows: b, now: stamp });
  await writeCypher("MATCH ()-[r:HAS_CREDENTIAL|SIGNS_IN_WITH|USED_FROM|SIGNED_IN_FROM]->() WHERE r.updated_at IS NULL OR r.updated_at <> $now DELETE r", { now: stamp });
  await writeCypher("MATCH (c:AdvisorCredential) WHERE c.updated_at IS NULL OR c.updated_at <> $now SET c.gone = true", { now: stamp });
  await writeCypher("MATCH (n) WHERE (n:AdvisorClient OR (n:AdvisorSource AND n.kind = 'ip')) AND NOT (n)--() DELETE n", {});
  // Vercel tokens were identities for a day before they became credentials: remove those nodes
  await writeCypher("MATCH (n:AdvisorIdentity {native_type: 'vercel_token'}) DETACH DELETE n", {});
  return { credentials: g.credentials.length, clients: g.clients.length, signs_in: g.signs_in.length, used_from: g.used_from.length, ips: g.ips.length };
}

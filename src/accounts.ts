/**
 * Member accounts: one parent (the credentials from Settings, usually the Organizations management or payer
 * account) and the children it reaches through a role. Two things make a child visible to the advisor:
 *
 * - Steampipe: a connection per member through a managed AWS profile that chains the member's read role onto the
 *   parent's identity, all joined by an aggregator that keeps the app's schema name (src/aws_config.ts), so every
 *   `S.aws_*` query, inventory, finding and rule spans the accounts as is; rows carry `account_id`.
 * - The SDK: `accountCredentials(id)` assumes the member's read role from the parent's provider for the calls
 *   Steampipe cannot make; the executor's `Creds.forAccount(id)` picks it per ledger row, and the member's own
 *   actuator role (`act_role_arn`, trusting the parent's read identity) is the only thing that changes a member.
 *
 * The registry is the `accounts` JSON setting; saving or removing a member rewrites the connection files.
 */
import { fromTemporaryCredentials } from "@aws-sdk/credential-providers";
import { GetCallerIdentityCommand, STSClient } from "@aws-sdk/client-sts";
import type { AwsCredentialIdentityProvider } from "@aws-sdk/types";
import { config } from "./config.js";
import { getJsonSetting, setSetting } from "./db.js";
import { ROLE_ARN_RE, type MemberConnection } from "./aws_config.js";
import { credentialsMeta, currentCredentialSettings, sdkCredentials, updateCredentialsMeta, writeConnection } from "./steampipe.js";

export interface MemberAccount {
  account_id: string;
  name: string;
  /** The read role in the member (same policy as the parent's read policy), trusting the parent's read identity. */
  role_arn: string;
  /** The member's actuator role (same policy as the parent's actuator role), trusting the parent's read identity; null = dry runs only there. */
  act_role_arn: string | null;
  regions: string[] | null;
  enabled: boolean;
  last_test?: { ok: boolean; arn?: string; error?: string; at: string } | null;
}

export interface AccountView extends MemberAccount { is_parent: boolean }

const KEY = "accounts";
const ACCOUNT_ID_RE = /^\d{12}$/;
const REGION_RE = /^[a-z0-9*-]+$/;

export const listMembers = (): MemberAccount[] => getJsonSetting<MemberAccount[]>(KEY, []).filter((m) => m && ACCOUNT_ID_RE.test(String(m.account_id)));
const saveMembers = (list: MemberAccount[]) => setSetting(KEY, JSON.stringify(list));

/** The parent as the registry sees it: from the saved credentials' meta (account id learnt by the connection test). */
export function parentAccount(): AccountView {
  const meta = credentialsMeta();
  return { account_id: meta?.accountId || "", name: "parent", role_arn: meta?.roleArn || "", act_role_arn: config.actRoleArn || null, regions: meta?.regions?.length ? meta.regions : null, enabled: true, is_parent: true, last_test: null };
}

/** Every account: the parent first, then the members as saved (disabled ones included; callers filter). */
export function listAccounts(): AccountView[] {
  return [parentAccount(), ...listMembers().map((m) => ({ ...m, is_parent: false }))];
}

/** The enabled members, as the Steampipe writer wants them. */
export const memberConnections = (): MemberConnection[] =>
  listMembers().filter((m) => m.enabled).map((m) => ({ account_id: m.account_id, role_arn: m.role_arn, ...(m.regions?.length ? { regions: m.regions } : {}) }));

/** Checks and normalises a member from the API. Throws with a user-facing message on the first problem. */
export function validateAccount(input: any): MemberAccount {
  const str = (v: unknown) => (typeof v === "string" ? v.trim() : "");
  const account_id = str(input?.account_id);
  if (!ACCOUNT_ID_RE.test(account_id)) throw new Error(`account_id must be the 12-digit account number, got "${account_id}"`);
  const parent = credentialsMeta()?.accountId;
  if (parent && parent === account_id) throw new Error(`${account_id} is the parent account (the credentials in Settings); add the children only`);
  const role_arn = str(input?.role_arn);
  if (!ROLE_ARN_RE.test(role_arn) || /\s/.test(role_arn)) throw new Error(`role_arn must look like arn:aws:iam::${account_id}:role/name, got "${role_arn}"`);
  if (!role_arn.includes(`:${account_id}:`)) throw new Error(`role_arn belongs to another account than ${account_id}`);
  const act = str(input?.act_role_arn);
  if (act && (!ROLE_ARN_RE.test(act) || /\s/.test(act))) throw new Error(`act_role_arn must be a role ARN or empty, got "${act}"`);
  if (act && !act.includes(`:${account_id}:`)) throw new Error(`act_role_arn belongs to another account than ${account_id}`);
  const rawRegions = Array.isArray(input?.regions) ? input.regions : String(input?.regions ?? "").split(",");
  const regions = rawRegions.map((r: unknown) => str(r)).filter(Boolean);
  for (const r of regions) if (!REGION_RE.test(r)) throw new Error(`"${r}" is not a region name`);
  const name = str(input?.name).slice(0, 80) || account_id;
  const enabled = input?.enabled === undefined ? true : Boolean(input.enabled) && !/^(false|0|no|off)$/i.test(String(input.enabled));
  return { account_id, name, role_arn, act_role_arn: act || null, regions: regions.length ? regions : null, enabled };
}

/** Rewrites the Steampipe connection and the managed AWS profiles for the current parent settings plus the members. Returns false when the parent has no saved credentials. */
export function rewriteConnectionFiles(): boolean {
  const settings = currentCredentialSettings();
  if (!settings) return false;
  // the credentials are unchanged: the account they resolve to stays known (a rewrite is not a new credential test)
  const accountId = credentialsMeta()?.accountId;
  writeConnection(settings, memberConnections());
  if (accountId) updateCredentialsMeta({ accountId });
  return true;
}

/** Adds or replaces a member (by account id), keeping its last test result, and rewrites the connection files. */
export function saveAccount(a: MemberAccount): { account: MemberAccount; files_rewritten: boolean } {
  const list = listMembers();
  const i = list.findIndex((m) => m.account_id === a.account_id);
  const next = { ...a, last_test: i >= 0 ? list[i].last_test ?? null : null };
  if (i >= 0) list[i] = next; else list.push(next);
  saveMembers(list);
  providers.delete(a.account_id);
  return { account: next, files_rewritten: rewriteConnectionFiles() };
}

export function removeAccount(accountId: string): { removed: boolean; files_rewritten: boolean } {
  const list = listMembers();
  const next = list.filter((m) => m.account_id !== accountId);
  if (next.length === list.length) return { removed: false, files_rewritten: false };
  saveMembers(next);
  providers.delete(accountId);
  return { removed: true, files_rewritten: rewriteConnectionFiles() };
}

export function recordAccountTest(accountId: string, result: { ok: boolean; arn?: string; error?: string }): void {
  const list = listMembers();
  const m = list.find((x) => x.account_id === accountId); if (!m) return;
  m.last_test = { ...result, at: new Date().toISOString() };
  saveMembers(list);
}

const providers = new Map<string, AwsCredentialIdentityProvider>();

/**
 * The SDK provider for an account: the parent's own provider for the parent (or an unknown id), else the
 * parent's provider assuming the member's read role (cached per account; the SDK refreshes the session itself).
 */
export function accountCredentials(accountId: string | null | undefined): { provider: AwsCredentialIdentityProvider; region: string; account_id: string; is_parent: boolean } {
  const base = sdkCredentials();
  const parentId = credentialsMeta()?.accountId || "";
  const m = accountId && accountId !== parentId ? listMembers().find((x) => x.account_id === accountId) : undefined;
  if (!m) return { provider: base.provider, region: base.region, account_id: parentId, is_parent: true };
  let p = providers.get(m.account_id);
  if (!p) {
    p = fromTemporaryCredentials({ masterCredentials: base.provider, params: { RoleArn: m.role_arn, RoleSessionName: "aws-advisor", DurationSeconds: 3600 }, clientConfig: { region: base.region } });
    providers.set(m.account_id, p);
  }
  return { provider: p, region: m.regions?.[0] && m.regions[0] !== "*" ? m.regions[0] : base.region, account_id: m.account_id, is_parent: false };
}

/** The actuator role for an account: the member's own, or the parent's setting; empty when a member has none (dry runs only there). */
export function actuatorRoleFor(accountId: string | null | undefined): string {
  const parentId = credentialsMeta()?.accountId || "";
  if (!accountId || accountId === parentId) return config.actRoleArn;
  return listMembers().find((x) => x.account_id === accountId)?.act_role_arn || "";
}

/** sts:GetCallerIdentity through the member's read role: proves the parent may assume it. Records the result on the member. */
export async function testAccount(accountId: string, timeoutMs = 15_000): Promise<{ ok: true; arn: string; account_id: string } | { ok: false; error: string }> {
  const m = listMembers().find((x) => x.account_id === accountId);
  if (!m) return { ok: false, error: `no member account ${accountId}` };
  let creds: ReturnType<typeof accountCredentials>;
  try { providers.delete(accountId); creds = accountCredentials(accountId); } catch (e: any) { return { ok: false, error: e?.message || String(e) }; }
  const client = new STSClient({ region: creds.region, credentials: creds.provider });
  try {
    const timer = new Promise<never>((_, reject) => setTimeout(() => reject(new Error(`sts:GetCallerIdentity did not answer within ${Math.round(timeoutMs / 1000)}s`)), timeoutMs).unref());
    const r = await Promise.race([client.send(new GetCallerIdentityCommand({})), timer]);
    const out = { ok: true as const, arn: r.Arn || "", account_id: r.Account || accountId };
    recordAccountTest(accountId, { ok: true, arn: out.arn });
    if (r.Account && r.Account !== accountId) { const err = `the role answered from account ${r.Account}, not ${accountId}`; recordAccountTest(accountId, { ok: false, error: err }); return { ok: false, error: err }; }
    return out;
  } catch (e: any) {
    const msg = String(e?.message || e);
    const error = /AccessDenied|not authorized to perform: sts:AssumeRole/i.test(msg)
      ? `${msg}. The parent's read identity is not allowed to assume ${m.role_arn}: put it in that role's trust policy (Settings › Member accounts shows the JSON).`
      : msg;
    recordAccountTest(accountId, { ok: false, error });
    return { ok: false, error };
  } finally { client.destroy(); }
}

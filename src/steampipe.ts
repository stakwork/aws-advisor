import fs from "node:fs";
import path from "node:path";
import pg from "pg";
import { GetCallerIdentityCommand, STSClient } from "@aws-sdk/client-sts";
import { config } from "./config.js";
import { getSetting, setSetting } from "./db.js";
import { describeError } from "./permissions.js";
import {
  CredentialMode, CredentialPaths, CredentialSettings, CredentialSource, DEFAULT_CREDENTIAL_SOURCE, NoSdkCredentials, ProviderKind, SdkCredentials,
  credentialRemedy, describeSettings, readStaticKeys, removeCredentialFiles, sdkCredentialsFor, writeCredentialFiles,
} from "./aws_config.js";

/** Schema (= Steampipe connection name) every query is qualified with. */
export const S = config.schema;

const pool = new pg.Pool({ connectionString: config.steampipeUrl, max: 4, statement_timeout: 600_000 });

export async function query<T = any>(sql: string, params: unknown[] = []): Promise<T[]> {
  const res = await pool.query(sql, params);
  return res.rows as T[];
}

/**
 * Runs one statement inside a READ ONLY transaction with its own statement timeout, for SQL that
 * does not come from this codebase (the MCP steampipe_query tool). Returns column names and rows.
 */
export async function queryReadOnly<T = any>(sql: string, opts: { timeoutMs: number }): Promise<{ rows: T[]; columns: string[] }> {
  const client = await pool.connect();
  try {
    await client.query("begin read only");
    // the transaction sees only this app's connection: an unqualified aws_* name can never resolve to another one
    await client.query(`set local search_path = "${S}", pg_catalog`);
    await client.query(`set local statement_timeout = ${Math.max(1000, Math.floor(opts.timeoutMs))}`);
    const res = await client.query(sql);
    await client.query("rollback");
    return { rows: res.rows as T[], columns: res.fields.map((f) => f.name) };
  } catch (e) {
    try { await client.query("rollback"); } catch { /* connection may be gone */ }
    throw e;
  } finally {
    client.release();
  }
}

export type { CredentialMode, CredentialSettings, CredentialSource } from "./aws_config.js";

/** What the UI and the API may know about the saved credentials: the mode and its identifiers, never a secret. */
export interface CredentialsMeta {
  /** Older rows (before modes) have no mode: they were pasted keys. */
  mode: CredentialMode;
  /** keys mode: the masked access key id. */
  accessKeyMasked?: string;
  /** profile mode: the user's profile name. */
  profile?: string;
  /** Role assumed on top of the base identity, when any. */
  roleArn?: string;
  /** chain mode with a role: the credential_source of the managed profile. */
  credentialSource?: CredentialSource;
  /** The profile the .spc points at (the user's, or the managed one when a role is assumed); null when it carries keys / nothing. */
  spcProfile: string | null;
  /** Whether the base credentials expire on their own (pasted temporary keys, an SSO session). */
  temporary: boolean;
  /** One line for the sidebar: "access key AKIA…1234 assuming arn:…". */
  label: string;
  regions: string[];
  defaultRegion: string;
  savedAt: string;
  accountId?: string;
}

const spcPath = () => path.join(config.steampipeConfigDir, `${S}.spc`);
const mask = (k: string) => (k.length > 8 ? `${k.slice(0, 4)}…${k.slice(-4)}` : "****");

/** Where the connection file and the managed AWS profile sections are written (see src/aws_config.ts). */
export const credentialPaths = (): CredentialPaths => ({
  spcFile: spcPath(),
  awsConfigFile: config.awsConfigFile,
  awsCredentialsFile: config.awsSharedCredentialsFile,
  managedProfile: config.advisorAwsProfile,
  connection: S,
});

/**
 * Writes the Steampipe connection file for the settings and, when a role is assumed, the managed profile
 * sections in the AWS shared config / credentials files. Steampipe watches its config dir and picks the
 * connection up within seconds. Returns the meta (no secrets) that is kept in settings.
 */
export function writeConnection(c: CredentialSettings): CredentialsMeta {
  const written = writeCredentialFiles(c, credentialPaths());
  const base = {
    ...(c.mode === "keys" ? { accessKeyMasked: mask(c.accessKey) } : {}),
    ...(c.mode === "profile" ? { profile: c.profile } : {}),
    ...(c.roleArn ? { roleArn: c.roleArn } : {}),
    ...(c.mode === "chain" && c.roleArn ? { credentialSource: c.credentialSource || DEFAULT_CREDENTIAL_SOURCE } : {}),
  };
  const meta: CredentialsMeta = {
    mode: c.mode,
    ...base,
    spcProfile: written.spcProfile,
    temporary: c.mode === "keys" ? Boolean(c.sessionToken) : c.mode === "profile",
    label: describeSettings({ mode: c.mode, ...base }),
    regions: c.regions?.length ? c.regions : ["*"],
    defaultRegion: c.defaultRegion || "us-east-1",
    savedAt: new Date().toISOString(),
  };
  setSetting("aws_credentials_meta", JSON.stringify(meta));
  return meta;
}

/** Removes the connection file and the managed sections of the AWS files; the rest of those files is untouched. */
export function clearConnection() {
  removeCredentialFiles(credentialPaths());
  setSetting("aws_credentials_meta", "");
}

export function credentialsMeta(): CredentialsMeta | null {
  const v = getSetting("aws_credentials_meta");
  if (!v) return null;
  try {
    const m = JSON.parse(v) as Partial<CredentialsMeta> & { accessKeyMasked?: string };
    // Rows written before credential modes existed were pasted keys.
    const mode: CredentialMode = m.mode || "keys";
    return { spcProfile: null, temporary: false, regions: ["*"], defaultRegion: "us-east-1", savedAt: "", ...m, mode, label: m.label || describeSettings({ mode, ...m }) };
  } catch { return null; }
}

export function updateCredentialsMeta(patch: Partial<CredentialsMeta>) {
  const cur = credentialsMeta();
  if (cur) setSetting("aws_credentials_meta", JSON.stringify({ ...cur, ...patch }));
}

export const hasConnectionFile = () => fs.existsSync(spcPath());

/**
 * The AWS SDK v3 credential provider that matches the saved mode (static keys, the profile, the default
 * chain, or STS AssumeRole on top of one of them), for the calls Steampipe cannot make (SSM Run Command,
 * the identity check). Throws NoSdkCredentials when nothing is configured. Never log the provider's output.
 */
export function sdkCredentials(): SdkCredentials & { region: string } {
  const meta = credentialsMeta();
  if (!meta || !hasConnectionFile()) throw new NoSdkCredentials(`no AWS credentials are configured (no "${S}" connection file); save them in Settings`);
  const p = credentialPaths();
  const keys = meta.mode === "keys" ? readStaticKeys(p) : null;
  const region = meta.defaultRegion && meta.defaultRegion !== "*" ? meta.defaultRegion : "us-east-1";
  return { ...sdkCredentialsFor(meta, p, keys), region };
}

/**
 * sts:GetCallerIdentity through the SDK provider: proves the SDK side can resolve credentials (a profile
 * that needs `aws sso login`, a host without an instance role, a role that refuses the assumption) and
 * says who the advisor is. Failures come back as a message with the remedy.
 */
export async function sdkIdentity(timeoutMs = 15_000): Promise<{ ok: true; arn: string; accountId: string; kind: ProviderKind; describe: string } | { ok: false; error: string; kind?: ProviderKind; describe?: string }> {
  let creds: ReturnType<typeof sdkCredentials>;
  try { creds = sdkCredentials(); } catch (e: any) { return { ok: false, error: e?.message || String(e) }; }
  const meta = credentialsMeta()!;
  const client = new STSClient({ region: creds.region, credentials: creds.provider });
  try {
    const timer = new Promise<never>((_, reject) => setTimeout(() => reject(new Error(`sts:GetCallerIdentity did not answer within ${Math.round(timeoutMs / 1000)}s`)), timeoutMs).unref());
    const r = await Promise.race([client.send(new GetCallerIdentityCommand({})), timer]);
    return { ok: true, arn: r.Arn || "", accountId: r.Account || "", kind: creds.kind, describe: creds.describe };
  } catch (e) {
    return { ok: false, error: credentialRemedy(e, meta), kind: creds.kind, describe: creds.describe };
  } finally {
    client.destroy();
  }
}

/** Polls until the schema answers, so a freshly written connection has time to load. */
export async function testConnection(timeoutMs = 45_000): Promise<{ ok: boolean; accountId?: string; error?: string }> {
  const deadline = Date.now() + timeoutMs;
  let lastError: unknown = "";
  while (Date.now() < deadline) {
    try {
      const rows = await query<{ account_id: string }>(`select account_id from ${S}.aws_account`);
      if (rows[0]?.account_id) return { ok: true, accountId: rows[0].account_id };
      lastError = "query returned no rows";
    } catch (e: any) {
      lastError = e;
    }
    await new Promise((r) => setTimeout(r, 2000));
  }
  // Recorded once, at the end: a denial on aws_account (sts:GetCallerIdentity / iam:ListAccountAliases) gets its remedy here.
  return { ok: false, error: describeError(lastError, "connection test (aws_account)") };
}

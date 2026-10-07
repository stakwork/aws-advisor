import fs from "node:fs";
import path from "node:path";
import pg from "pg";
import { GetCallerIdentityCommand, STSClient } from "@aws-sdk/client-sts";
import { config } from "./config.js";
import { getSetting, setSetting } from "./db.js";
import { describeError, hasOpenIssues, noteSuccessForTables, tablesIn } from "./permissions.js";
import {
  CredentialMode, CredentialPaths, CredentialSettings, CredentialSource, DEFAULT_CREDENTIAL_SOURCE, MemberConnection, NoSdkCredentials, ProviderKind, SdkCredentials,
  credentialRemedy, describeSettings, parentConnectionName, readStaticKeys, removeCredentialFiles, sdkCredentialsFor, writeCredentialFiles,
} from "./aws_config.js";

/** Schema (= Steampipe connection name) every query is qualified with. */
export const S = config.schema;

/** The enabled member accounts (src/accounts.ts), read from the setting here so this module stays import-free of accounts.ts. */
const memberIds = (): string[] => {
  try { return (JSON.parse(getSetting("accounts") || "[]") as { account_id?: unknown; enabled?: boolean }[]).filter((m) => m && m.enabled !== false && /^\d{12}$/.test(String(m.account_id))).map((m) => String(m.account_id)); }
  catch { return []; }
};

/**
 * The parent's own connection: `<schema>_p` once members are registered (the schema itself is then an aggregator that
 * answers once per account), the schema itself otherwise. What must come from the parent alone reads through it: which
 * account the credentials resolve to (`aws_account` over the aggregator is one row per member, in no particular order)
 * and Cost Explorer.
 */
export const parentSchema = (): string => (memberIds().length ? parentConnectionName(S) : S);

/**
 * The connection Cost Explorer is read through: the parent's. The aggregator runs a query once per connection, and a
 * member's role sees its own spend through Cost Explorer too, so a sum over `aws_cost_*` through the aggregator counts
 * every member twice (the parent's organisation view already carries a row per linked account). Savings Plans and
 * reservations are not routed: each account owns its own.
 */
export const billingSchema = parentSchema;

/** Rewrites `<schema>.aws_cost_*` references to the billing connection. Pure given the two schemas; a no-op when they are the same. */
export function routeBillingTables(sql: string, schema = S, billing = billingSchema()): string {
  if (billing === schema) return sql;
  return sql.replace(new RegExp(`\\b${schema.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\.(aws_cost_[a-z0-9_]+)\\b`, "g"), `${billing}.$1`);
}

/**
 * Makes the Steampipe service pick up new credential files. The connection watcher reloads a changed .spc, but the AWS
 * config file next to it (the managed profile with the role to assume) is not watched and the plugin keeps the session
 * it already opened, so a saved role change kept answering as the old identity until the container was restarted. A
 * credential save therefore restarts the service when it runs next to the app (`STEAMPIPE_RELOAD=auto`: the database
 * URL points at localhost and the `steampipe` binary is on the path; `on` forces it, `off` never). Takes a few seconds;
 * the connection test that follows retries through it. Never throws: the outcome is returned and logged.
 */
export async function reloadSteampipeService(why: string): Promise<{ restarted: boolean; note: string }> {
  const mode = config.steampipeReload;
  const local = /@(127\.0\.0\.1|localhost|\[::1\])(:|\/)/.test(config.steampipeUrl);
  if (mode === "off" || (mode === "auto" && !local)) return { restarted: false, note: mode === "off" ? "STEAMPIPE_RELOAD=off" : `the Steampipe service is not local (${config.steampipeUrl.replace(/\/\/.*@/, "//")}): restart it yourself so it reads the new credentials` };
  const { execFile } = await import("node:child_process");
  const t0 = Date.now();
  return new Promise((resolve) => {
    execFile(config.steampipeBin, ["service", "restart"], { timeout: 120_000, env: { ...process.env, STEAMPIPE_UPDATE_CHECK: "false" } }, (err, stdout, stderr) => {
      if (err) {
        const note = `steampipe service restart failed after ${Date.now() - t0} ms: ${String(stderr || err.message).trim().slice(0, 300)}`;
        console.error(`[steampipe] ${why}: ${note}`);
        return resolve({ restarted: false, note });
      }
      const note = `Steampipe service restarted in ${Math.round((Date.now() - t0) / 1000)} s so it reads the new credentials`;
      console.log(`[steampipe] ${why}: ${note}${stdout ? ` (${String(stdout).trim().split("\n").pop()})` : ""}`);
      resolve({ restarted: true, note });
    });
  });
}

const pool = new pg.Pool({ connectionString: config.steampipeUrl, max: 4, statement_timeout: 600_000 });
// An idle connection the Steampipe service drops (a plugin panic, a restart) surfaces here; without a listener
// Node treats it as fatal and the daemon dies. The pool discards the client and the next query reconnects.
pool.on("error", (e) => console.error(`[steampipe] connection dropped: ${e.message}`));

export async function query<T = any>(sql: string, params: unknown[] = []): Promise<T[]> {
  const res = await pool.query(routeBillingTables(sql), params);
  if (hasOpenIssues()) noteSuccessForTables(tablesIn(sql), "query");
    return res.rows as T[];
}

/**
 * Runs one statement inside a READ ONLY transaction with its own statement timeout, for SQL that
 * does not come from this codebase (the MCP steampipe_query tool). Returns column names and rows.
 */
export async function queryReadOnly<T = any>(sql: string, opts: { timeoutMs: number; freshData?: boolean }): Promise<{ rows: T[]; columns: string[] }> {
  const client = await pool.connect();
  // A verify right after a change must not read Steampipe's cache: the cache switch is per session, so it is turned
  // off on this connection before the transaction and back on after (a failure to switch is logged, not fatal).
  const cache = async (op: "cache_off" | "cache_on") => { try { await client.query("insert into steampipe_command.cache (operation) values ($1)", [op]); } catch (e: any) { console.warn(`[steampipe] ${op} not applied: ${e?.message || e}`); } };
  if (opts.freshData) await cache("cache_off");
  try {
    await client.query("begin read only");
    // the transaction sees only this app's connection: an unqualified aws_* name can never resolve to another one
    await client.query(`set local search_path = "${S}", pg_catalog`);
    await client.query(`set local statement_timeout = ${Math.max(1000, Math.floor(opts.timeoutMs))}`);
    const res = await client.query(routeBillingTables(sql));
    await client.query("rollback");
    if (hasOpenIssues()) noteSuccessForTables(tablesIn(sql), "query");
    return { rows: res.rows as T[], columns: res.fields.map((f) => f.name) };
  } catch (e) {
    try { await client.query("rollback"); } catch { /* connection may be gone */ }
    throw e;
  } finally {
    if (opts.freshData) await cache("cache_on");
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
export function writeConnection(c: CredentialSettings, members: MemberConnection[] = []): CredentialsMeta {
  const written = writeCredentialFiles(c, credentialPaths(), members);
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

/**
 * The saved settings rebuilt from the meta and the files the writer left (the keys are read back from the .spc
 * or the credentials file), so the connection can be rewritten when member accounts change. Null when nothing is
 * configured or the keys cannot be read back.
 */
export function currentCredentialSettings(): CredentialSettings | null {
  const meta = credentialsMeta();
  if (!meta || !hasConnectionFile()) return null;
  const common = { regions: meta.regions?.length ? meta.regions : ["*"], defaultRegion: meta.defaultRegion || "us-east-1", ...(meta.roleArn ? { roleArn: meta.roleArn } : {}) };
  if (meta.mode === "keys") { const k = readStaticKeys(credentialPaths()); return k ? { mode: "keys", ...k, ...common } : null; }
  if (meta.mode === "profile") return meta.profile ? { mode: "profile", profile: meta.profile, ...common } : null;
  return { mode: "chain", credentialSource: meta.credentialSource || DEFAULT_CREDENTIAL_SOURCE, ...common };
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

/**
 * One query on its own connection, cut off after `ms` on both sides (statement_timeout for the server, closing the
 * socket for the client). The shared pool's 600 s statement timeout would let a plugin stuck retrying new credentials
 * hold a connection test, and the request waiting on it, for ten minutes.
 */
async function boundedQuery<T>(sql: string, ms: number): Promise<T[]> {
  const client = new pg.Client({ connectionString: config.steampipeUrl, statement_timeout: ms, query_timeout: ms + 2000, connectionTimeoutMillis: Math.min(ms, 10_000) });
  client.on("error", () => { /* surfaced by the query below */ });
  try {
    await client.connect();
    return (await client.query(sql)).rows as T[];
  } finally {
    client.end().catch(() => {});
  }
}

/** Polls until the schema answers, so a freshly written connection has time to load. */
export async function testConnection(timeoutMs = 45_000): Promise<{ ok: boolean; accountId?: string; error?: string }> {
  const first = await pollAccount(timeoutMs);
  if (first.ok || !first.missingSchema) return first;
  // The schema is not there at all. Steampipe either has not read the connection yet or is holding it in error.
  const state = await connectionState(parentSchema());
  if (state?.error) return { ok: false, error: `Steampipe connection "${parentSchema()}" failed to load: ${state.error}` };
  if (state || !hasConnectionFile() || !mayRestartForMissingSchema()) return first;
  // Not listed although the file names it: the running service missed the change (seen after a settings import that
  // added the member connections, cured by a container restart). Restart it once and look again.
  const reload = await reloadSteampipeService(`connection "${parentSchema()}" missing from the running service`);
  if (!reload.restarted) return { ok: false, error: `${first.error} (${reload.note})` };
  return pollAccount(timeoutMs);
}

async function pollAccount(timeoutMs: number): Promise<{ ok: boolean; accountId?: string; error?: string; missingSchema?: boolean }> {
  const deadline = Date.now() + timeoutMs;
  let lastError: unknown = "";
  while (Date.now() < deadline) {
    try {
      // the parent's connection: over the aggregator this is one row per account and the first could be a member's
      const rows = await boundedQuery<{ account_id: string }>(`select account_id from ${parentSchema()}.aws_account`, Math.max(1000, deadline - Date.now()));
      if (rows[0]?.account_id) return { ok: true, accountId: rows[0].account_id };
      lastError = "query returned no rows";
    } catch (e: any) {
      lastError = e;
    }
    await new Promise((r) => setTimeout(r, 2000));
  }
  // Recorded once, at the end: a denial on aws_account (sts:GetCallerIdentity / iam:ListAccountAliases) gets its remedy here.
  const missingSchema = /relation "[^"]+\.aws_account" does not exist/.test(String((lastError as any)?.message ?? lastError));
  return { ok: false, error: describeError(lastError, "connection test (aws_account)"), missingSchema };
}

/** What the running service says about one connection; null when it does not list it (or cannot be asked). */
async function connectionState(name: string): Promise<{ state: string; error: string | null } | null> {
  try {
    const rows = await boundedQuery<{ state: string; error: string | null }>(`select state, error from steampipe_connection where name = '${name.replace(/'/g, "''")}'`, 10_000);
    return rows[0] ?? null;
  } catch { return null; }
}

/** At most one self-restart per ten minutes, so a connection that never loads does not restart the service on every test. */
let lastSchemaRestart = 0;
function mayRestartForMissingSchema(): boolean {
  if (Date.now() - lastSchemaRestart < 600_000) return false;
  lastSchemaRestart = Date.now();
  return true;
}

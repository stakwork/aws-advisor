/**
 * Settings export and import: moves the configuration of one advisor to another (a new production host) without
 * any of its data. The bundle carries the runtime settings (the secrets in clear inside it), the AWS credentials
 * as saved (static keys included), the member accounts, the benchmarks, and the prompt and probe-script
 * overrides. No inventory, run, finding or graph node travels: the new host collects its own with a run.
 *
 * The file is sealed with a passphrase (scrypt + AES-256-GCM), so a bundle left in a Downloads folder is not a
 * pile of keys. Importing applies everything through the same setters the Settings page uses, then rewrites the
 * Steampipe connection and tests it.
 */
import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from "node:crypto";
import { RUNTIME_SETTINGS, config, isSecretSetting, runtimeRaw } from "./config.js";
import { db, getJsonSetting, setSetting } from "./db.js";
import { setRuntimeSetting } from "./runtime_settings.js";
import { listMembers, validateAccount, type MemberAccount } from "./accounts.js";
import { validateSettings, type CredentialSettings } from "./aws_config.js";
import { credentialsMeta, currentCredentialSettings, reloadSteampipeService, sdkIdentity, testConnection, updateCredentialsMeta, writeConnection } from "./steampipe.js";
import { noteAccountChange } from "./purge.js";
import { ALL_BENCHMARKS, DEFAULT_BENCHMARKS } from "./powerpipe.js";
import { PROMPT_KINDS, setPromptOverride, type PromptKind } from "./prompts.js";
import { PROBE_KINDS, setProbeScriptOverride, type ProbeKind } from "./probes.js";

export const BUNDLE_FORMAT = "cloud-advisor-settings";
const VERSION = 1;
const MIN_PASSPHRASE = 10;

export interface SettingsPayload {
  runtime: { key: string; value: string; source: "setting" | "env" }[];
  aws: CredentialSettings | null;
  aws_account_id: string | null;
  members: Omit<MemberAccount, "last_test">[];
  benchmarks: string[] | null;
  compliance_benchmarks: string[] | null;
  prompts: Partial<Record<PromptKind, string>>;
  probe_scripts: Partial<Record<ProbeKind, string>>;
}

export interface SealedBundle {
  format: typeof BUNDLE_FORMAT;
  version: number;
  exported_at: string;
  /** Readable without the passphrase, so a person can tell bundles apart. Never a secret. */
  from: { account_id: string | null; public_url: string; aws_mode: string | null; members: number; runtime: number };
  kdf: { name: "scrypt"; N: number; r: number; p: number; salt: string };
  cipher: { name: "aes-256-gcm"; iv: string; tag: string; data: string };
}

const KDF = { N: 1 << 15, r: 8, p: 1 };
const deriveKey = (passphrase: string, salt: Buffer, k = KDF) => scryptSync(passphrase, salt, 32, { N: k.N, r: k.r, p: k.p, maxmem: 128 * k.N * k.r * 2 });

export function sealPayload(payload: SettingsPayload, passphrase: string): SealedBundle {
  if (typeof passphrase !== "string" || passphrase.length < MIN_PASSPHRASE) throw new Error(`the passphrase must be at least ${MIN_PASSPHRASE} characters`);
  const salt = randomBytes(16), iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", deriveKey(passphrase, salt), iv);
  const data = Buffer.concat([c.update(JSON.stringify(payload), "utf8"), c.final()]);
  return {
    format: BUNDLE_FORMAT, version: VERSION, exported_at: new Date().toISOString(),
    from: { account_id: payload.aws_account_id, public_url: config.publicUrl, aws_mode: payload.aws?.mode ?? null, members: payload.members.length, runtime: payload.runtime.length },
    kdf: { name: "scrypt", ...KDF, salt: salt.toString("base64") },
    cipher: { name: "aes-256-gcm", iv: iv.toString("base64"), tag: c.getAuthTag().toString("base64"), data: data.toString("base64") },
  };
}

export function openBundle(bundle: any, passphrase: string): SettingsPayload {
  if (!bundle || bundle.format !== BUNDLE_FORMAT) throw new Error("this is not a Cloud Advisor settings export");
  if (bundle.version !== VERSION) throw new Error(`settings export version ${bundle.version} is not supported here (expected ${VERSION})`);
  const { kdf, cipher } = bundle;
  if (kdf?.name !== "scrypt" || cipher?.name !== "aes-256-gcm") throw new Error("unknown encryption in the export");
  if (![kdf.N, kdf.r, kdf.p].every((n) => Number.isInteger(n) && n > 0) || kdf.N > 1 << 20) throw new Error("the export's key parameters are out of range");
  let text: string;
  try {
    const d = createDecipheriv("aes-256-gcm", deriveKey(String(passphrase ?? ""), Buffer.from(kdf.salt, "base64"), kdf), Buffer.from(cipher.iv, "base64"));
    d.setAuthTag(Buffer.from(cipher.tag, "base64"));
    text = Buffer.concat([d.update(Buffer.from(cipher.data, "base64")), d.final()]).toString("utf8");
  } catch { throw new Error("wrong passphrase, or the file was changed"); }
  const p = JSON.parse(text) as Partial<SettingsPayload>;
  return { runtime: [], aws: null, aws_account_id: null, members: [], benchmarks: null, compliance_benchmarks: null, prompts: {}, probe_scripts: {}, ...p };
}

/** What this advisor would export: saved runtime values and the env-provided ones (both with their secrets), credentials, members, overrides. */
export function buildPayload(): SettingsPayload {
  const runtime: SettingsPayload["runtime"] = [];
  for (const s of RUNTIME_SETTINGS) {
    const { value, source } = runtimeRaw(s.key);
    if (source !== "default" && value !== "") runtime.push({ key: s.key, value, source });
  }
  const setting = (key: string) => (db.prepare("select value from settings where key = ?").get(key) as { value: string } | undefined)?.value ?? null;
  const prompts: SettingsPayload["prompts"] = {};
  for (const k of PROMPT_KINDS) { const v = setting(`prompt:${k}`); if (v) prompts[k] = v; }
  const probe_scripts: SettingsPayload["probe_scripts"] = {};
  for (const k of PROBE_KINDS) { const v = setting(`probe_script:${k}`); if (v) probe_scripts[k] = v; }
  return {
    runtime,
    aws: currentCredentialSettings(),
    aws_account_id: credentialsMeta()?.accountId ?? null,
    members: listMembers().map(({ last_test, ...m }) => m),
    benchmarks: setting("benchmarks") != null ? getJsonSetting<string[]>("benchmarks", DEFAULT_BENCHMARKS) : null,
    compliance_benchmarks: setting("compliance_benchmarks") != null ? getJsonSetting<string[]>("compliance_benchmarks", []) : null,
    prompts, probe_scripts,
  };
}

export interface ImportPlanRow { key: string; label: string; group: string; secret: boolean; from_source: "setting" | "env"; current_source: "setting" | "env" | "default"; same: boolean; selected: boolean }
export interface ImportPlan {
  runtime: ImportPlanRow[];
  aws: { mode: string; label: string; account_id: string | null; replaces: string | null; warning: string | null } | null;
  members: { account_id: string; name: string; enabled: boolean }[];
  benchmarks: boolean; compliance_benchmarks: boolean;
  prompts: string[]; probe_scripts: string[];
}

/**
 * What an import would change. A runtime value saved on the source is selected by default; one the source got
 * from its environment is selected only when this host has nothing for it (its own env or saved value wins).
 */
export function planImport(p: SettingsPayload): ImportPlan {
  const known = new Map(RUNTIME_SETTINGS.map((s) => [s.key, s]));
  const runtime = p.runtime.filter((r) => known.has(r.key)).map((r) => {
    const s = known.get(r.key)!; const cur = runtimeRaw(r.key);
    return { key: r.key, label: s.label, group: s.group, secret: isSecretSetting(r.key), from_source: r.source, current_source: cur.source, same: cur.value === r.value, selected: r.source === "setting" || cur.source === "default" };
  });
  const meta = credentialsMeta();
  const aws = p.aws ? {
    mode: p.aws.mode,
    label: p.aws.mode === "keys" ? `access key …${p.aws.accessKey.slice(-4)}${p.aws.roleArn ? ` assuming ${p.aws.roleArn}` : ""}` : p.aws.mode === "profile" ? `profile ${p.aws.profile}` : `default chain (${p.aws.credentialSource || "Ec2InstanceMetadata"})${p.aws.roleArn ? ` assuming ${p.aws.roleArn}` : ""}`,
    account_id: p.aws_account_id,
    replaces: meta ? meta.label + (meta.accountId ? ` (${meta.accountId})` : "") : null,
    warning: p.aws.mode === "profile" ? `the profile "${p.aws.profile}" must exist in this host's AWS config files` : p.aws.mode === "chain" ? "the default chain uses this host's own identity (instance role, env); it may resolve to another principal than the source's" : null,
  } : null;
  return {
    runtime, aws,
    members: p.members.map((m) => ({ account_id: m.account_id, name: m.name, enabled: m.enabled })),
    benchmarks: p.benchmarks != null, compliance_benchmarks: p.compliance_benchmarks != null,
    prompts: Object.keys(p.prompts), probe_scripts: Object.keys(p.probe_scripts),
  };
}

export interface ImportResult { runtime: { applied: string[]; skipped: string[]; failed: { key: string; error: string }[] }; members: number; overrides: string[]; aws: any }

/**
 * Applies a bundle. `runtimeKeys` picks the runtime settings (default: the plan's selection). Validation happens
 * before anything is written for the credentials and the members; a bad runtime value is reported and skipped.
 * `connect` (default true) writes the Steampipe/AWS files and tests them; tests pass false.
 */
export async function applyImport(p: SettingsPayload, opts: { runtimeKeys?: string[]; connect?: boolean } = {}): Promise<ImportResult> {
  const plan = planImport(p);
  const aws = p.aws ? validateSettings(p.aws) : null;
  const parentId = p.aws_account_id ?? credentialsMeta()?.accountId;
  const members = p.members.map((m) => ({ ...validateAccount(m, parentId), last_test: null }));

  const pick = new Set(opts.runtimeKeys ?? plan.runtime.filter((r) => r.selected).map((r) => r.key));
  const out: ImportResult = { runtime: { applied: [], skipped: [], failed: [] }, members: members.length, overrides: [], aws: null };
  for (const r of p.runtime) {
    if (!plan.runtime.some((x) => x.key === r.key) || !pick.has(r.key)) { out.runtime.skipped.push(r.key); continue; }
    try { setRuntimeSetting(r.key, r.value); out.runtime.applied.push(r.key); }
    catch (e: any) { out.runtime.failed.push({ key: r.key, error: e?.message || String(e) }); }
  }
  if (p.benchmarks) { setSetting("benchmarks", JSON.stringify(p.benchmarks.filter((b) => ALL_BENCHMARKS.includes(b)))); out.overrides.push("benchmarks"); }
  if (p.compliance_benchmarks) { setSetting("compliance_benchmarks", JSON.stringify(p.compliance_benchmarks)); out.overrides.push("compliance benchmarks"); }
  for (const [k, v] of Object.entries(p.prompts)) if (v && (PROMPT_KINDS as string[]).includes(k)) { setPromptOverride(k as PromptKind, v); out.overrides.push(`prompt ${k}`); }
  for (const [k, v] of Object.entries(p.probe_scripts)) if (v && (PROBE_KINDS as readonly string[]).includes(k)) {
    try { setProbeScriptOverride(k as ProbeKind, v); out.overrides.push(`probe script ${k}`); }
    catch (e: any) { out.runtime.failed.push({ key: `probe_script:${k}`, error: e?.message || String(e) }); }
  }
  setSetting("accounts", JSON.stringify(members));

  if (opts.connect === false) return out;
  if (aws) {
    const previous = credentialsMeta()?.accountId ?? null;
    writeConnection(aws, members.filter((m) => m.enabled).map((m) => ({ account_id: m.account_id, role_arn: m.role_arn, ...(m.regions?.length ? { regions: m.regions } : {}) })));
    const reload = await reloadSteampipeService("settings imported");
    const [test, sdk] = await Promise.all([testConnection(45_000), sdkIdentity(20_000)]);
    const now = test.ok ? test.accountId : sdk.ok ? sdk.accountId : null;
    if (now) updateCredentialsMeta({ accountId: now });
    out.aws = { test, sdk, steampipe_reload: reload, account_change: noteAccountChange(previous, now ?? null) };
  } else {
    const { rewriteConnectionFiles } = await import("./accounts.js");
    out.aws = { files_rewritten: rewriteConnectionFiles() };
  }
  if (pick.has("vercelToken") || pick.has("vercelTeamId")) {
    try { const { ensureVercelConnection } = await import("./adapters/vercel/steampipe.js"); ensureVercelConnection(); } catch (e: any) { console.error(`[settings import] vercel connection: ${e?.message || e}`); }
  }
  return out;
}

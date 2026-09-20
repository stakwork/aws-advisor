import fs from "node:fs";
import path from "node:path";
import { fromIni, fromNodeProviderChain, fromTemporaryCredentials } from "@aws-sdk/credential-providers";
import type { AwsCredentialIdentity, AwsCredentialIdentityProvider } from "@aws-sdk/types";

/**
 * How the advisor authenticates to AWS, for Steampipe and for its own SDK calls alike. Three modes:
 *
 * - keys:    pasted access key + secret (+ session token). Without a role they go straight into the Steampipe
 *            connection file. With a role, the Steampipe AWS plugin can only assume it through an AWS config
 *            profile, so the keys go into the shared credentials file under `[<managed>-source]` and a managed
 *            `[profile <managed>]` with role_arn + source_profile is written into the shared config file; the
 *            .spc then says `profile = "<managed>"`.
 * - profile: a profile the user already has (SSO, keys, anything). `.spc` gets `profile = "<name>"`; with a
 *            role, a managed profile chains role_arn + source_profile = <name>.
 * - chain:   nothing in the .spc; the plugin and the SDK fall back to the default chain (env, instance
 *            profile, container credentials). With a role, a managed profile with role_arn + credential_source.
 *
 * Managed sections are delimited by marker lines and are the only bytes this module ever changes in the
 * user's AWS files. This module has no database dependency so the writers can be unit-tested on a temp dir.
 */

export type CredentialMode = "keys" | "profile" | "chain";
export type CredentialSource = "Ec2InstanceMetadata" | "EcsContainer" | "Environment";
export const CREDENTIAL_SOURCES: CredentialSource[] = ["Ec2InstanceMetadata", "EcsContainer", "Environment"];
export const DEFAULT_CREDENTIAL_SOURCE: CredentialSource = "Ec2InstanceMetadata";

interface CommonSettings {
  regions?: string[];
  defaultRegion?: string;
  roleArn?: string;
}
export interface KeysSettings extends CommonSettings { mode: "keys"; accessKey: string; secretKey: string; sessionToken?: string }
export interface ProfileSettings extends CommonSettings { mode: "profile"; profile: string }
export interface ChainSettings extends CommonSettings { mode: "chain"; credentialSource?: CredentialSource }
export type CredentialSettings = KeysSettings | ProfileSettings | ChainSettings;

/** Where the files live; steampipe.ts fills this from config, tests point it at a temp dir. */
export interface CredentialPaths {
  /** The Steampipe connection file (<schema>.spc). */
  spcFile: string;
  /** AWS shared config file (AWS_CONFIG_FILE or ~/.aws/config). */
  awsConfigFile: string;
  /** AWS shared credentials file (AWS_SHARED_CREDENTIALS_FILE or ~/.aws/credentials). */
  awsCredentialsFile: string;
  /** Name of the managed profile (ADVISOR_AWS_PROFILE, default aws-advisor); the keys profile is `<name>-source`. */
  managedProfile: string;
  /** Steampipe connection name. */
  connection: string;
}

export const MANAGED_BEGIN = "# >>> aws-advisor managed";
export const MANAGED_END = "# <<< aws-advisor managed";

export const PROFILE_NAME_RE = /^[A-Za-z0-9_.-]+$/;
export const ROLE_ARN_RE = /^arn:aws:iam::\d{12}:role\/.+$/;
const REGION_RE = /^[a-z0-9*-]+$/;
const KEY_RE = /^[A-Za-z0-9+/=_-]+$/;

export const sourceProfileName = (managed: string) => `${managed}-source`;

/**
 * Checks and normalises a settings object from the API (unknown shape in, typed settings out).
 * Throws an Error with a user-facing message on the first problem.
 */
export function validateSettings(input: any): CredentialSettings {
  const mode: string = input?.mode ?? "keys";
  if (!["keys", "profile", "chain"].includes(mode)) throw new Error(`mode must be keys, profile or chain, got "${mode}"`);
  const str = (v: unknown) => (typeof v === "string" ? v.trim() : "");
  const roleArn = str(input?.roleArn) || undefined;
  if (roleArn && !ROLE_ARN_RE.test(roleArn)) throw new Error(`roleArn must look like arn:aws:iam::123456789012:role/name, got "${roleArn}"`);
  if (roleArn && /\s/.test(roleArn)) throw new Error("roleArn must not contain whitespace");
  const rawRegions = Array.isArray(input?.regions) ? input.regions : String(input?.regions ?? "*").split(",");
  const regions = rawRegions.map((r: unknown) => str(r)).filter(Boolean);
  for (const r of regions) if (!REGION_RE.test(r)) throw new Error(`"${r}" is not a region name`);
  const defaultRegion = str(input?.defaultRegion) || "us-east-1";
  if (!REGION_RE.test(defaultRegion) || defaultRegion === "*") throw new Error(`"${defaultRegion}" is not a region name`);
  const common: CommonSettings = { regions: regions.length ? regions : ["*"], defaultRegion, ...(roleArn ? { roleArn } : {}) };
  if (mode === "keys") {
    const accessKey = str(input?.accessKey);
    const secretKey = str(input?.secretKey);
    const sessionToken = str(input?.sessionToken) || undefined;
    if (!accessKey || !secretKey) throw new Error("accessKey and secretKey are required");
    if (!KEY_RE.test(accessKey) || !KEY_RE.test(secretKey) || (sessionToken && !KEY_RE.test(sessionToken))) throw new Error("access key, secret key and session token must not contain whitespace or quotes");
    return { mode, accessKey, secretKey, ...(sessionToken ? { sessionToken } : {}), ...common };
  }
  if (mode === "profile") {
    const profile = str(input?.profile);
    if (!profile) throw new Error("profile is required");
    if (!PROFILE_NAME_RE.test(profile)) throw new Error(`profile must match ${PROFILE_NAME_RE.source}, got "${profile}"`);
    return { mode, profile, ...common };
  }
  const credentialSource = str(input?.credentialSource) || DEFAULT_CREDENTIAL_SOURCE;
  if (!CREDENTIAL_SOURCES.includes(credentialSource as CredentialSource)) throw new Error(`credentialSource must be one of ${CREDENTIAL_SOURCES.join(", ")}, got "${credentialSource}"`);
  return { mode: "chain", credentialSource: credentialSource as CredentialSource, ...common };
}

const lit = (s: string) => JSON.stringify(s); // HCL accepts double-quoted strings with JSON-style escapes

/** The profile name the .spc points at, or null when it carries keys / nothing. */
export function spcProfile(s: CredentialSettings, managedProfile: string): string | null {
  if (s.roleArn) return managedProfile;
  if (s.mode === "profile") return s.profile;
  return null;
}

/** The Steampipe connection file for the settings. */
export function renderSpc(s: CredentialSettings, p: Pick<CredentialPaths, "connection" | "managedProfile">): string {
  const regions = s.regions?.length ? s.regions : ["*"];
  const defaultRegion = s.defaultRegion || "us-east-1";
  const lines = [
    `# Managed by aws-advisor. Edit through the Settings page, not by hand.`,
    `connection ${lit(p.connection)} {`,
    `  plugin         = "aws"`,
    `  regions        = [${regions.map(lit).join(", ")}]`,
    `  default_region = ${lit(defaultRegion)}`,
  ];
  const profile = spcProfile(s, p.managedProfile);
  if (profile) {
    lines.push(`  profile        = ${lit(profile)}`);
  } else if (s.mode === "keys") {
    lines.push(`  access_key     = ${lit(s.accessKey)}`, `  secret_key     = ${lit(s.secretKey)}`);
    if (s.sessionToken) lines.push(`  session_token  = ${lit(s.sessionToken)}`);
  } else {
    lines.push(`  # no credentials: the plugin uses the default chain (environment, instance profile, container)`);
  }
  lines.push(`}`, ``);
  return lines.join("\n");
}

/** The managed profile section(s) for the AWS shared config file, or null when none is needed. */
export function renderManagedConfig(s: CredentialSettings, p: Pick<CredentialPaths, "managedProfile">): string | null {
  if (!s.roleArn) return null;
  const region = s.defaultRegion || "us-east-1";
  const lines = [`[profile ${p.managedProfile}]`, `role_arn = ${s.roleArn}`, `role_session_name = aws-advisor`];
  if (s.mode === "keys") lines.push(`source_profile = ${sourceProfileName(p.managedProfile)}`);
  else if (s.mode === "profile") lines.push(`source_profile = ${s.profile}`);
  else lines.push(`credential_source = ${s.credentialSource || DEFAULT_CREDENTIAL_SOURCE}`);
  lines.push(`region = ${region}`);
  if (s.mode === "keys") lines.push(``, `[profile ${sourceProfileName(p.managedProfile)}]`, `region = ${region}`);
  return lines.join("\n");
}

/** The managed section for the AWS shared credentials file (keys chained into a role), or null. */
export function renderManagedCredentials(s: CredentialSettings, p: Pick<CredentialPaths, "managedProfile">): string | null {
  if (s.mode !== "keys" || !s.roleArn) return null;
  const lines = [`[${sourceProfileName(p.managedProfile)}]`, `aws_access_key_id = ${s.accessKey}`, `aws_secret_access_key = ${s.secretKey}`];
  if (s.sessionToken) lines.push(`aws_session_token = ${s.sessionToken}`);
  return lines.join("\n");
}

const managedBlock = (body: string) => `${MANAGED_BEGIN}\n${body}\n${MANAGED_END}\n`;
const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
/** The whole block (with the newline that precedes it, when any); group 1 is the body between the markers. */
const MANAGED_RE = new RegExp(`\\n?${escapeRe(MANAGED_BEGIN)}\\n([\\s\\S]*?)\\n${escapeRe(MANAGED_END)}\\n?`);

/**
 * Returns `text` with its managed section replaced by `body` (or removed when body is null). Everything
 * outside the marker lines is returned byte-for-byte; a first section is appended after one blank line.
 */
export function replaceManagedSection(text: string, body: string | null): string {
  const m = MANAGED_RE.exec(text);
  if (m) {
    const before = text.slice(0, m.index);
    const after = text.slice(m.index + m[0].length);
    if (body === null) return before + after;
    // keep the newline that separated the block from what precedes it
    const sep = m[0].startsWith("\n") ? "\n" : "";
    return before + sep + managedBlock(body) + after;
  }
  if (body === null) return text;
  if (text === "") return managedBlock(body);
  return text + (text.endsWith("\n") ? "\n" : "\n\n") + managedBlock(body);
}

/** Reads the managed section's body from a file (between the markers), or null. */
export function readManagedSection(file: string): string | null {
  let text: string;
  try { text = fs.readFileSync(file, "utf8"); } catch { return null; }
  const m = MANAGED_RE.exec(text);
  return m ? m[1] : null;
}

/** Rewrites only the managed section of an INI file (creating the file when needed), mode 0600. */
export function writeManagedSection(file: string, body: string | null): void {
  let existing: string | null = null;
  try { existing = fs.readFileSync(file, "utf8"); } catch { existing = null; }
  if (existing === null && body === null) return;
  const next = replaceManagedSection(existing ?? "", body);
  if (existing !== null && next === existing) { try { fs.chmodSync(file, 0o600); } catch { /* not ours to fix */ } return; }
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, next, { mode: 0o600 });
  fs.chmodSync(file, 0o600);
}

/** What writeCredentialFiles produced, for the meta and for tests. */
export interface WrittenFiles {
  spc: string;
  managedConfig: string | null;
  managedCredentials: string | null;
  spcProfile: string | null;
}

/** Writes the .spc and the managed sections for the settings (removing managed sections the mode does not use). */
export function writeCredentialFiles(s: CredentialSettings, p: CredentialPaths): WrittenFiles {
  const spc = renderSpc(s, p);
  const managedConfig = renderManagedConfig(s, p);
  const managedCredentials = renderManagedCredentials(s, p);
  fs.mkdirSync(path.dirname(p.spcFile), { recursive: true });
  fs.writeFileSync(p.spcFile, spc, { mode: 0o600 });
  fs.chmodSync(p.spcFile, 0o600);
  writeManagedSection(p.awsCredentialsFile, managedCredentials);
  writeManagedSection(p.awsConfigFile, managedConfig);
  return { spc, managedConfig, managedCredentials, spcProfile: spcProfile(s, p.managedProfile) };
}

/** Removes the .spc and both managed sections. */
export function removeCredentialFiles(p: CredentialPaths): void {
  try { fs.unlinkSync(p.spcFile); } catch { /* already gone */ }
  writeManagedSection(p.awsCredentialsFile, null);
  writeManagedSection(p.awsConfigFile, null);
}

/** Static keys read back from where the writer put them: the .spc (keys, no role) or the credentials file's managed section (keys + role). */
export function readStaticKeys(p: CredentialPaths): { accessKey: string; secretKey: string; sessionToken?: string } | null {
  const fromSpc = (): ReturnType<typeof readStaticKeys> => {
    let text: string;
    try { text = fs.readFileSync(p.spcFile, "utf8"); } catch { return null; }
    const field = (name: string): string | undefined => {
      const m = text.match(new RegExp(`^\\s*${name}\\s*=\\s*("(?:[^"\\\\]|\\\\.)*")\\s*$`, "m"));
      if (!m) return undefined;
      try { return JSON.parse(m[1]) as string; } catch { return undefined; }
    };
    const accessKey = field("access_key");
    const secretKey = field("secret_key");
    if (!accessKey || !secretKey) return null;
    const sessionToken = field("session_token");
    return { accessKey, secretKey, ...(sessionToken ? { sessionToken } : {}) };
  };
  const fromIniSection = (): ReturnType<typeof readStaticKeys> => {
    const body = readManagedSection(p.awsCredentialsFile);
    if (!body) return null;
    const field = (name: string) => body.match(new RegExp(`^${name}\\s*=\\s*(\\S+)\\s*$`, "m"))?.[1];
    const accessKey = field("aws_access_key_id");
    const secretKey = field("aws_secret_access_key");
    if (!accessKey || !secretKey) return null;
    const sessionToken = field("aws_session_token");
    return { accessKey, secretKey, ...(sessionToken ? { sessionToken } : {}) };
  };
  return fromSpc() ?? fromIniSection();
}

// ---- AWS SDK v3 credential provider matching the mode -------------------------------------------------------------

export type ProviderKind = "static" | "ini" | "chain" | "assume-role";

export interface SdkCredentials {
  kind: ProviderKind;
  /** Human-readable description of what the provider does (no secrets). */
  describe: string;
  provider: AwsCredentialIdentityProvider;
}

/** The SDK constructors, injectable so tests can assert the selection without any network. */
export interface ProviderFactory {
  fromIni: typeof fromIni;
  fromNodeProviderChain: typeof fromNodeProviderChain;
  fromTemporaryCredentials: typeof fromTemporaryCredentials;
}
export const defaultProviderFactory: ProviderFactory = { fromIni, fromNodeProviderChain, fromTemporaryCredentials };

/** Description of the settings for the SDK side (what identity the provider starts from), also the meta's `mode` line. */
export function describeSettings(s: { mode: CredentialMode; profile?: string; roleArn?: string; credentialSource?: string; accessKeyMasked?: string }): string {
  const base = s.mode === "keys" ? `access key ${s.accessKeyMasked || "(pasted)"}` : s.mode === "profile" ? `AWS profile ${s.profile}` : `default credential chain${s.roleArn ? ` (${s.credentialSource || DEFAULT_CREDENTIAL_SOURCE})` : ""}`;
  return s.roleArn ? `${base} assuming ${s.roleArn}` : base;
}

/**
 * Picks the AWS SDK credential provider for the settings:
 * - keys, no role: the static keys (read back from the .spc);
 * - keys + role: STS AssumeRole with the static keys as master credentials (read back from the credentials file);
 * - profile (with or without role): fromIni on the user's profile or on the managed profile that chains the role;
 * - chain, no role: the default Node provider chain; chain + role: AssumeRole on top of that chain.
 * `keys` is only consulted for the keys mode; pass what readStaticKeys returned.
 */
export function sdkCredentialsFor(
  s: { mode: CredentialMode; profile?: string; roleArn?: string; credentialSource?: string; defaultRegion?: string },
  p: Pick<CredentialPaths, "awsConfigFile" | "awsCredentialsFile" | "managedProfile">,
  keys: { accessKey: string; secretKey: string; sessionToken?: string } | null,
  factory: ProviderFactory = defaultProviderFactory,
): SdkCredentials {
  const region = s.defaultRegion && s.defaultRegion !== "*" ? s.defaultRegion : "us-east-1";
  const ini = { filepath: p.awsCredentialsFile, configFilepath: p.awsConfigFile, ignoreCache: true };
  if (s.mode === "profile") {
    const profile = s.roleArn ? p.managedProfile : s.profile!;
    return { kind: "ini", describe: `profile ${profile}${s.roleArn ? ` (${s.profile} assuming ${s.roleArn})` : ""}`, provider: factory.fromIni({ profile, ...ini }) };
  }
  if (s.mode === "chain") {
    const chain = factory.fromNodeProviderChain({ ...ini });
    if (!s.roleArn) return { kind: "chain", describe: "default credential chain", provider: chain };
    return { kind: "assume-role", describe: `default credential chain assuming ${s.roleArn}`, provider: factory.fromTemporaryCredentials({ masterCredentials: chain, params: { RoleArn: s.roleArn, RoleSessionName: "aws-advisor" }, clientConfig: { region } }) };
  }
  if (!keys) throw new NoSdkCredentials("the saved access key could not be read back; save the credentials again in Settings");
  const master: AwsCredentialIdentity = { accessKeyId: keys.accessKey, secretAccessKey: keys.secretKey, ...(keys.sessionToken ? { sessionToken: keys.sessionToken } : {}) };
  if (!s.roleArn) return { kind: "static", describe: "static access key", provider: async () => master };
  return { kind: "assume-role", describe: `static access key assuming ${s.roleArn}`, provider: factory.fromTemporaryCredentials({ masterCredentials: master, params: { RoleArn: s.roleArn, RoleSessionName: "aws-advisor" }, clientConfig: { region } }) };
}

export class NoSdkCredentials extends Error {
  constructor(message: string) { super(message); this.name = "NoSdkCredentials"; }
}

/**
 * Turns a credential-resolution failure (SSO session expired, profile missing, no instance role, the role
 * refusing the assumption) into a message with the remedy. Returns the original message otherwise.
 */
export function credentialRemedy(err: unknown, s: { mode: CredentialMode; profile?: string; roleArn?: string; credentialSource?: string }): string {
  const e = err as any;
  const name = String(e?.name || e?.Code || "");
  const msg = String(e?.message || err || "").replace(/\s+/g, " ").trim().replace(/[.\s]+$/, "");
  const text = `${name} ${msg}`;
  const sso = /sso|Token is expired|session .*expired|refresh token/i.test(text);
  if (s.mode === "profile" && (sso || /login/i.test(text))) return `${msg}. The profile ${s.profile} needs a fresh SSO session: run \`aws sso login --profile ${s.profile}\` on the machine running the advisor and the Steampipe service, then test again.`;
  if (/Profile .* (could not be found|not found)|no profile/i.test(text)) return `${msg}. Check the profile name and that the AWS config file the advisor and Steampipe read (AWS_CONFIG_FILE or ~/.aws/config of the user running them) defines it.`;
  if (/Could not load credentials from any providers|CredentialsProviderError|EC2 Metadata|169\.254\.169\.254|ECONNREFUSED|ETIMEDOUT/i.test(text) && s.mode === "chain") {
    return `${msg}. The default credential chain found nothing: on an EC2 host attach an instance profile (${s.credentialSource || DEFAULT_CREDENTIAL_SOURCE}), in a container set the task role, or export AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY in the advisor's and Steampipe's environment.`;
  }
  if (s.roleArn && /AccessDenied|not authorized to perform: sts:AssumeRole/i.test(text)) return `${msg}. The identity is not allowed to assume ${s.roleArn}: add it to the role's trust policy (see README, "Onboarding") and give it sts:AssumeRole.`;
  if (/ExpiredToken|InvalidClientTokenId|UnrecognizedClient|InvalidSignature|SignatureDoesNotMatch|InvalidAccessKeyId/i.test(text)) return `${msg}. The credentials were rejected (${name || "expired or invalid"}); ${s.mode === "keys" ? "save a valid key in Settings" : s.mode === "profile" ? `refresh the profile (\`aws sso login --profile ${s.profile}\` for SSO, or new keys in its credentials file)` : "the instance or environment credentials are stale"}.`;
  return msg;
}

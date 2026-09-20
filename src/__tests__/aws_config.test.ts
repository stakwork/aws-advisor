import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import {
  CredentialPaths, MANAGED_BEGIN, MANAGED_END, ProviderFactory, credentialRemedy, readManagedSection, readStaticKeys, removeCredentialFiles,
  renderManagedConfig, renderManagedCredentials, renderSpc, replaceManagedSection, sdkCredentialsFor, validateSettings, writeCredentialFiles,
} from "../aws_config.js";

const ROLE = "arn:aws:iam::123456789012:role/aws-advisor-read";
const KEYS = { accessKey: "AKIAEXAMPLEKEY000001", secretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" };

function tmpPaths(): CredentialPaths {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "advisor-cred-"));
  return { spcFile: path.join(dir, "spc", "advtest.spc"), awsConfigFile: path.join(dir, "aws", "config"), awsCredentialsFile: path.join(dir, "aws", "credentials"), managedProfile: "aws-advisor", connection: "advtest" };
}
const mode = (f: string) => fs.statSync(f).mode & 0o777;
const read = (f: string) => fs.readFileSync(f, "utf8");

const PRE_CONFIG = `[default]\nregion = eu-west-1\noutput = json\n\n[profile example-sso]\nsso_session = example\nsso_account_id = 123456789012\nsso_role_name = ReadOnly\nregion = us-east-1\n\n[sso-session stakwork]\nsso_start_url = https://stakwork.awsapps.com/start\nsso_region = us-east-1\n`;
const PRE_CREDS = `[default]\naws_access_key_id = AKIADEFAULT000000001\naws_secret_access_key = defaultsecret\n`;

// ---- .spc rendering -------------------------------------------------------------------------------------------------

test("keys without a role: the .spc carries the keys and no managed sections are needed", () => {
  const s = validateSettings({ mode: "keys", ...KEYS, sessionToken: "FwoGZXIvYXdzEBYaDExample", regions: "us-east-1, eu-west-1", defaultRegion: "us-east-1" });
  assert.equal(renderSpc(s, { connection: "advtest", managedProfile: "aws-advisor" }), [
    `# Managed by aws-advisor. Edit through the Settings page, not by hand.`,
    `connection "advtest" {`,
    `  plugin         = "aws"`,
    `  regions        = ["us-east-1", "eu-west-1"]`,
    `  default_region = "us-east-1"`,
    `  access_key     = "AKIAEXAMPLEKEY000001"`,
    `  secret_key     = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`,
    `  session_token  = "FwoGZXIvYXdzEBYaDExample"`,
    `}`,
    ``,
  ].join("\n"));
  assert.equal(renderManagedConfig(s, { managedProfile: "aws-advisor" }), null);
  assert.equal(renderManagedCredentials(s, { managedProfile: "aws-advisor" }), null);
});

test("keys with a role: keys go to the credentials file, the .spc points at the managed profile chaining the role", () => {
  const s = validateSettings({ mode: "keys", ...KEYS, roleArn: ROLE });
  assert.equal(renderSpc(s, { connection: "advtest", managedProfile: "aws-advisor" }), [
    `# Managed by aws-advisor. Edit through the Settings page, not by hand.`,
    `connection "advtest" {`,
    `  plugin         = "aws"`,
    `  regions        = ["*"]`,
    `  default_region = "us-east-1"`,
    `  profile        = "aws-advisor"`,
    `}`,
    ``,
  ].join("\n"));
  assert.equal(renderManagedConfig(s, { managedProfile: "aws-advisor" }), [
    `[profile aws-advisor]`, `role_arn = ${ROLE}`, `role_session_name = aws-advisor`, `source_profile = aws-advisor-source`, `region = us-east-1`, ``,
    `[profile aws-advisor-source]`, `region = us-east-1`,
  ].join("\n"));
  assert.equal(renderManagedCredentials(s, { managedProfile: "aws-advisor" }), [`[aws-advisor-source]`, `aws_access_key_id = ${KEYS.accessKey}`, `aws_secret_access_key = ${KEYS.secretKey}`].join("\n"));
});

test("profile mode: the user's profile directly, or the managed profile chaining the role onto it", () => {
  const plain = validateSettings({ mode: "profile", profile: "example-sso", defaultRegion: "eu-west-1" });
  assert.match(renderSpc(plain, { connection: "advtest", managedProfile: "aws-advisor" }), /^  profile {8}= "example-sso"$/m);
  assert.doesNotMatch(renderSpc(plain, { connection: "advtest", managedProfile: "aws-advisor" }), /access_key|secret_key/);
  assert.equal(renderManagedConfig(plain, { managedProfile: "aws-advisor" }), null);
  const withRole = validateSettings({ mode: "profile", profile: "example-sso", roleArn: ROLE, defaultRegion: "eu-west-1" });
  assert.match(renderSpc(withRole, { connection: "advtest", managedProfile: "aws-advisor" }), /^  profile {8}= "aws-advisor"$/m);
  assert.equal(renderManagedConfig(withRole, { managedProfile: "aws-advisor" }), [`[profile aws-advisor]`, `role_arn = ${ROLE}`, `role_session_name = aws-advisor`, `source_profile = example-sso`, `region = eu-west-1`].join("\n"));
  assert.equal(renderManagedCredentials(withRole, { managedProfile: "aws-advisor" }), null);
});

test("chain mode: no credentials in the .spc; with a role, credential_source in the managed profile", () => {
  const plain = validateSettings({ mode: "chain" });
  const spc = renderSpc(plain, { connection: "advtest", managedProfile: "aws-advisor" });
  assert.doesNotMatch(spc, /access_key|secret_key|profile {2,}=/);
  assert.match(spc, /regions {8}= \["\*"\]/);
  assert.match(spc, /default_region = "us-east-1"/);
  assert.equal(renderManagedConfig(plain, { managedProfile: "aws-advisor" }), null);
  const ec2 = validateSettings({ mode: "chain", roleArn: ROLE });
  assert.equal(renderManagedConfig(ec2, { managedProfile: "aws-advisor" }), [`[profile aws-advisor]`, `role_arn = ${ROLE}`, `role_session_name = aws-advisor`, `credential_source = Ec2InstanceMetadata`, `region = us-east-1`].join("\n"));
  const ecs = validateSettings({ mode: "chain", roleArn: ROLE, credentialSource: "EcsContainer" });
  assert.match(renderManagedConfig(ecs, { managedProfile: "aws-advisor" })!, /^credential_source = EcsContainer$/m);
  const custom = renderManagedConfig(ec2, { managedProfile: "advisor-prod" });
  assert.match(custom!, /^\[profile advisor-prod\]$/m);
});

// ---- managed sections --------------------------------------------------------------------------------------------------

test("replaceManagedSection appends, replaces and removes without touching the rest", () => {
  const added = replaceManagedSection(PRE_CONFIG, "[profile aws-advisor]\nrole_arn = x");
  assert.equal(added, `${PRE_CONFIG}\n${MANAGED_BEGIN}\n[profile aws-advisor]\nrole_arn = x\n${MANAGED_END}\n`);
  const replaced = replaceManagedSection(added, "[profile aws-advisor]\nrole_arn = y");
  assert.equal(replaced, `${PRE_CONFIG}\n${MANAGED_BEGIN}\n[profile aws-advisor]\nrole_arn = y\n${MANAGED_END}\n`);
  assert.equal(replaceManagedSection(replaced, null), PRE_CONFIG);
  assert.equal(replaceManagedSection(PRE_CONFIG, null), PRE_CONFIG);
  // a section in the middle of the file keeps what follows it
  const middle = `${MANAGED_BEGIN}\nold\n${MANAGED_END}\n\n[profile after]\nregion = us-west-2\n`;
  assert.equal(replaceManagedSection(middle, "new"), `${MANAGED_BEGIN}\nnew\n${MANAGED_END}\n\n[profile after]\nregion = us-west-2\n`);
  assert.equal(replaceManagedSection(middle, null), `\n[profile after]\nregion = us-west-2\n`);
  // a file without a trailing newline gets one before the block
  assert.equal(replaceManagedSection("[default]\nregion = us-east-1", "body"), `[default]\nregion = us-east-1\n\n${MANAGED_BEGIN}\nbody\n${MANAGED_END}\n`);
  assert.equal(replaceManagedSection("", "body"), `${MANAGED_BEGIN}\nbody\n${MANAGED_END}\n`);
});

test("writeCredentialFiles: keys + role writes all three files with 0600 and preserves the user's sections byte for byte", () => {
  const p = tmpPaths();
  fs.mkdirSync(path.dirname(p.awsConfigFile), { recursive: true });
  fs.writeFileSync(p.awsConfigFile, PRE_CONFIG, { mode: 0o644 });
  fs.writeFileSync(p.awsCredentialsFile, PRE_CREDS, { mode: 0o644 });
  const s = validateSettings({ mode: "keys", ...KEYS, roleArn: ROLE });
  const w = writeCredentialFiles(s, p);
  assert.equal(w.spcProfile, "aws-advisor");
  assert.equal(read(p.spcFile), w.spc);
  assert.equal(read(p.awsConfigFile), `${PRE_CONFIG}\n${MANAGED_BEGIN}\n${w.managedConfig}\n${MANAGED_END}\n`);
  assert.equal(read(p.awsCredentialsFile), `${PRE_CREDS}\n${MANAGED_BEGIN}\n${w.managedCredentials}\n${MANAGED_END}\n`);
  assert.ok(read(p.awsConfigFile).startsWith(PRE_CONFIG));
  assert.ok(read(p.awsCredentialsFile).startsWith(PRE_CREDS));
  assert.doesNotMatch(read(p.awsConfigFile), /aws_secret_access_key/, "secrets never go into the config file");
  for (const f of [p.spcFile, p.awsConfigFile, p.awsCredentialsFile]) assert.equal(mode(f), 0o600, `${f} should be 0600`);
  // the keys can be read back for the SDK's master credentials
  assert.deepEqual(readStaticKeys(p), KEYS);
  assert.equal(readManagedSection(p.awsConfigFile), w.managedConfig);

  // switching to a mode without a role removes the managed sections and restores the files exactly
  writeCredentialFiles(validateSettings({ mode: "profile", profile: "example-sso" }), p);
  assert.equal(read(p.awsConfigFile), PRE_CONFIG);
  assert.equal(read(p.awsCredentialsFile), PRE_CREDS);
  assert.match(read(p.spcFile), /profile {8}= "example-sso"/);
  assert.equal(readStaticKeys(p), null);

  // and back to a role: sections come back; then remove everything
  writeCredentialFiles(validateSettings({ mode: "chain", roleArn: ROLE }), p);
  assert.match(read(p.awsConfigFile), /credential_source = Ec2InstanceMetadata/);
  assert.equal(read(p.awsCredentialsFile), PRE_CREDS);
  removeCredentialFiles(p);
  assert.equal(fs.existsSync(p.spcFile), false);
  assert.equal(read(p.awsConfigFile), PRE_CONFIG);
  assert.equal(read(p.awsCredentialsFile), PRE_CREDS);
});

test("writeCredentialFiles: keys without a role reads the keys back from the .spc and creates no AWS files", () => {
  const p = tmpPaths();
  writeCredentialFiles(validateSettings({ mode: "keys", ...KEYS, sessionToken: "tok" }), p);
  assert.equal(mode(p.spcFile), 0o600);
  assert.equal(fs.existsSync(p.awsConfigFile), false);
  assert.equal(fs.existsSync(p.awsCredentialsFile), false);
  assert.deepEqual(readStaticKeys(p), { ...KEYS, sessionToken: "tok" });
  removeCredentialFiles(p);
  assert.equal(fs.existsSync(p.spcFile), false);
  assert.equal(fs.existsSync(p.awsConfigFile), false, "removal never creates the AWS files");
});

test("writeCredentialFiles creates a missing AWS config file with only the managed section, mode 0600", () => {
  const p = tmpPaths();
  const w = writeCredentialFiles(validateSettings({ mode: "profile", profile: "example-sso", roleArn: ROLE }), p);
  assert.equal(read(p.awsConfigFile), `${MANAGED_BEGIN}\n${w.managedConfig}\n${MANAGED_END}\n`);
  assert.equal(mode(p.awsConfigFile), 0o600);
  assert.equal(fs.existsSync(p.awsCredentialsFile), false);
});

// ---- validation -----------------------------------------------------------------------------------------------------------

test("validateSettings enforces profile names, role ARNs, credential sources and key shapes", () => {
  assert.equal(validateSettings({ mode: "profile", profile: "my.profile_1-x" }).mode, "profile");
  for (const bad of ["", "has space", "semi;colon", "new\nline", "[inject]", "a/b"]) assert.throws(() => validateSettings({ mode: "profile", profile: bad }), /profile/, `profile "${bad}"`);
  assert.equal(validateSettings({ mode: "chain", roleArn: ROLE }).roleArn, ROLE);
  for (const bad of ["arn:aws:iam::12345:role/x", "arn:aws:iam::123456789012:user/x", "role/x", "arn:aws:iam::123456789012:role/", `${ROLE}\n[profile x]`, "arn:aws:iam::123456789012:role/x y"]) {
    assert.throws(() => validateSettings({ mode: "chain", roleArn: bad }), /roleArn/, `roleArn "${bad}"`);
  }
  assert.throws(() => validateSettings({ mode: "chain", credentialSource: "Magic" }), /credentialSource/);
  assert.equal((validateSettings({ mode: "chain" }) as { credentialSource?: string }).credentialSource, "Ec2InstanceMetadata");
  assert.throws(() => validateSettings({ mode: "keys", accessKey: "AKIA", secretKey: "" }), /accessKey and secretKey/);
  assert.throws(() => validateSettings({ mode: "keys", accessKey: "AKIA\"x", secretKey: "s" }), /whitespace or quotes/);
  assert.throws(() => validateSettings({ mode: "other" }), /mode/);
  assert.throws(() => validateSettings({ mode: "chain", defaultRegion: "us east" }), /region/);
  // a body without a mode is the old shape: pasted keys
  const legacy = validateSettings({ ...KEYS, regions: "us-east-1", defaultRegion: "us-east-1" });
  assert.equal(legacy.mode, "keys");
  assert.deepEqual(legacy.regions, ["us-east-1"]);
});

// ---- SDK provider selection -----------------------------------------------------------------------------------------------

function stubFactory() {
  const calls: { fn: string; args: any }[] = [];
  const mk = (fn: string) => (args: any) => { calls.push({ fn, args }); return Object.assign(async () => ({ accessKeyId: fn, secretAccessKey: fn }), { kind: fn }); };
  const factory = { fromIni: mk("fromIni"), fromNodeProviderChain: mk("fromNodeProviderChain"), fromTemporaryCredentials: mk("fromTemporaryCredentials") } as unknown as ProviderFactory;
  return { factory, calls };
}
const P = { awsConfigFile: "/x/config", awsCredentialsFile: "/x/credentials", managedProfile: "aws-advisor" };

test("sdkCredentialsFor picks the provider by mode without touching the network", async () => {
  // keys, no role: static
  let f = stubFactory();
  const st = sdkCredentialsFor({ mode: "keys" }, P, { ...KEYS, sessionToken: "tok" }, f.factory);
  assert.equal(st.kind, "static");
  assert.deepEqual(await st.provider(), { accessKeyId: KEYS.accessKey, secretAccessKey: KEYS.secretKey, sessionToken: "tok" });
  assert.equal(f.calls.length, 0);
  assert.throws(() => sdkCredentialsFor({ mode: "keys" }, P, null, f.factory), /could not be read back/);

  // keys + role: AssumeRole with the static keys as master credentials
  f = stubFactory();
  const kr = sdkCredentialsFor({ mode: "keys", roleArn: ROLE, defaultRegion: "eu-west-1" }, P, KEYS, f.factory);
  assert.equal(kr.kind, "assume-role");
  assert.equal(f.calls.length, 1);
  assert.equal(f.calls[0].fn, "fromTemporaryCredentials");
  assert.deepEqual(f.calls[0].args.params, { RoleArn: ROLE, RoleSessionName: "aws-advisor" });
  assert.deepEqual(f.calls[0].args.masterCredentials, { accessKeyId: KEYS.accessKey, secretAccessKey: KEYS.secretKey });
  assert.deepEqual(f.calls[0].args.clientConfig, { region: "eu-west-1" });

  // profile: fromIni on the user's profile, with the files the app manages
  f = stubFactory();
  const pr = sdkCredentialsFor({ mode: "profile", profile: "example-sso" }, P, null, f.factory);
  assert.equal(pr.kind, "ini");
  assert.deepEqual(f.calls.map((c) => c.fn), ["fromIni"]);
  assert.equal(f.calls[0].args.profile, "example-sso");
  assert.equal(f.calls[0].args.configFilepath, "/x/config");
  assert.equal(f.calls[0].args.filepath, "/x/credentials");

  // profile + role: fromIni on the managed profile (role_arn + source_profile live in the config file)
  f = stubFactory();
  const prr = sdkCredentialsFor({ mode: "profile", profile: "example-sso", roleArn: ROLE }, P, null, f.factory);
  assert.equal(prr.kind, "ini");
  assert.equal(f.calls[0].args.profile, "aws-advisor");
  assert.match(prr.describe, /example-sso assuming/);

  // chain: the default provider chain; chain + role: AssumeRole on top of it
  f = stubFactory();
  assert.equal(sdkCredentialsFor({ mode: "chain" }, P, null, f.factory).kind, "chain");
  assert.deepEqual(f.calls.map((c) => c.fn), ["fromNodeProviderChain"]);
  f = stubFactory();
  const cr = sdkCredentialsFor({ mode: "chain", roleArn: ROLE, credentialSource: "EcsContainer" }, P, null, f.factory);
  assert.equal(cr.kind, "assume-role");
  assert.deepEqual(f.calls.map((c) => c.fn), ["fromNodeProviderChain", "fromTemporaryCredentials"]);
  assert.equal(f.calls[1].args.masterCredentials.kind, "fromNodeProviderChain");
  assert.equal(f.calls[1].args.params.RoleArn, ROLE);
});

test("credentialRemedy names the fix for the usual failures", () => {
  assert.match(credentialRemedy(new Error("Token is expired. To refresh this SSO session run aws sso login"), { mode: "profile", profile: "example-sso" }), /aws sso login --profile example-sso/);
  assert.match(credentialRemedy(Object.assign(new Error("Could not load credentials from any providers"), { name: "CredentialsProviderError" }), { mode: "chain" }), /attach an instance profile/);
  assert.match(credentialRemedy(Object.assign(new Error("User: arn:aws:iam::123456789012:user/aws-advisor is not authorized to perform: sts:AssumeRole on resource: " + ROLE), { name: "AccessDenied" }), { mode: "keys", roleArn: ROLE }), /trust policy/);
  assert.match(credentialRemedy(Object.assign(new Error("The security token included in the request is expired"), { name: "ExpiredToken" }), { mode: "keys" }), /save a valid key/);
  assert.equal(credentialRemedy(new Error("something else"), { mode: "chain" }), "something else");
});

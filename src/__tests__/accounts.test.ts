import assert from "node:assert/strict";
import { test } from "node:test";
import { renderManagedConfig, renderManagedCredentials, renderSpc, type MemberConnection } from "../aws_config.js";
import type { Creds } from "../executor.js";

const P = { connection: "advisor", managedProfile: "aws-advisor" };
const KEYS = { mode: "keys" as const, accessKey: "AKIAEXAMPLEKEY000001", secretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", regions: ["us-east-1"], defaultRegion: "us-east-1" };
const CHILD: MemberConnection = { account_id: "222233334444", role_arn: "arn:aws:iam::222233334444:role/aws-advisor-read" };

test("members: without any, the .spc is the single connection it always was", () => {
  const spc = renderSpc(KEYS, P);
  assert.match(spc, /^connection "advisor" \{/m);
  assert.doesNotMatch(spc, /aggregator|advisor_p|advisor_2222/);
  assert.equal(renderManagedConfig(KEYS, P), null);
  assert.equal(renderManagedCredentials(KEYS, P), null);
});

test("members: the schema name becomes an aggregator over the parent and one connection per member", () => {
  const spc = renderSpc(KEYS, P, [CHILD]);
  assert.match(spc, /connection "advisor" \{\n  plugin {6}= "aws"\n  type {8}= "aggregator"\n  connections = \["advisor_p", "advisor_222233334444"\]/);
  // the parent keeps its own settings under the _p name
  assert.match(spc, /connection "advisor_p" \{[\s\S]*access_key {5}= "AKIAEXAMPLEKEY000001"/);
  // the member goes through its managed profile, with the parent's regions unless it has its own
  assert.match(spc, /connection "advisor_222233334444" \{\n  plugin {9}= "aws"\n  regions {8}= \["us-east-1"\]\n  default_region = "us-east-1"\n  profile {8}= "aws-advisor-222233334444"/);
  const own = renderSpc(KEYS, P, [{ ...CHILD, regions: ["eu-west-1", "eu-central-1"], default_region: "eu-west-1" }]);
  assert.match(own, /advisor_222233334444" \{\n  plugin {9}= "aws"\n  regions {8}= \["eu-west-1", "eu-central-1"\]\n  default_region = "eu-west-1"/);
});

test("members: the managed profile chains the member role onto the parent's identity, whatever the parent's mode", () => {
  // keys without a role: the keys get a source profile so the member profile has something to chain onto
  const keys = renderManagedConfig(KEYS, P, [CHILD])!;
  assert.match(keys, /^\[profile aws-advisor-source\]\nregion = us-east-1/);
  assert.match(keys, /\[profile aws-advisor-222233334444\]\nrole_arn = arn:aws:iam::222233334444:role\/aws-advisor-read\nrole_session_name = aws-advisor\nsource_profile = aws-advisor-source\nregion = us-east-1/);
  assert.match(renderManagedCredentials(KEYS, P, [CHILD])!, /^\[aws-advisor-source\]\naws_access_key_id = AKIAEXAMPLEKEY000001/);
  // keys with a role: the member chains onto the managed (assumed-role) profile, i.e. the parent's effective identity
  const withRole = renderManagedConfig({ ...KEYS, roleArn: "arn:aws:iam::111122223333:role/aws-advisor-read" }, P, [CHILD])!;
  assert.match(withRole, /\[profile aws-advisor\]\nrole_arn = arn:aws:iam::111122223333:role\/aws-advisor-read/);
  assert.match(withRole, /\[profile aws-advisor-222233334444\][\s\S]*source_profile = aws-advisor\n/);
  // the user's own profile
  const prof = renderManagedConfig({ mode: "profile", profile: "example-sso", defaultRegion: "eu-west-1" }, P, [CHILD])!;
  assert.match(prof, /\[profile aws-advisor-222233334444\][\s\S]*source_profile = example-sso\nregion = eu-west-1/);
  assert.doesNotMatch(prof, /\[profile aws-advisor\]\n/);
  // the default chain: credential_source instead of a source profile
  const chain = renderManagedConfig({ mode: "chain", credentialSource: "EcsContainer" }, P, [CHILD])!;
  assert.match(chain, /\[profile aws-advisor-222233334444\][\s\S]*credential_source = EcsContainer/);
  assert.doesNotMatch(chain, /source_profile/);
});

test("members: validateAccount checks the id, the ARNs' account and the regions", async () => {
  const { validateAccount } = await import("../accounts.js");
  const ok = validateAccount({ account_id: "222233334444", name: " production ", role_arn: CHILD.role_arn, act_role_arn: "", regions: "eu-west-1, us-east-1" });
  assert.deepEqual(ok, { account_id: "222233334444", name: "production", role_arn: CHILD.role_arn, act_role_arn: null, regions: ["eu-west-1", "us-east-1"], enabled: true });
  assert.equal(validateAccount({ account_id: "222233334444", role_arn: CHILD.role_arn, enabled: "false" }).enabled, false);
  assert.equal(validateAccount({ account_id: "222233334444", role_arn: CHILD.role_arn }).name, "222233334444");
  assert.throws(() => validateAccount({ account_id: "12345", role_arn: CHILD.role_arn }), /12-digit/);
  assert.throws(() => validateAccount({ account_id: "222233334444", role_arn: "arn:aws:iam::999988887777:role/x" }), /another account/);
  assert.throws(() => validateAccount({ account_id: "222233334444", role_arn: CHILD.role_arn, act_role_arn: "not-an-arn" }), /act_role_arn/);
  assert.throws(() => validateAccount({ account_id: "222233334444", role_arn: CHILD.role_arn, regions: "eu west" }), /not a region/);
});

test("members: credsForAccount switches read/act/region to the member and falls back to the parent", async () => {
  const { credsForAccount } = await import("../executor.js");
  const prov = (tag: string) => Object.assign(async () => ({ accessKeyId: tag, secretAccessKey: "s" }), { tag });
  const parent = { account_id: "111122223333", name: "parent", is_parent: true, read: prov("p-read"), act: () => prov("p-act"), region: "us-east-1" };
  const child = { account_id: "222233334444", name: "prod", is_parent: false, read: prov("c-read"), act: () => prov("c-act"), region: "eu-west-1" };
  const accounts = [parent, child];
  const creds: Creds = { read: parent.read, act: parent.act, region: parent.region, accounts, forAccount: (id: string | null | undefined) => (id ? accounts.find((a) => a.account_id === id) : undefined) ?? parent };
  const c = credsForAccount(creds, "222233334444");
  assert.equal((c.read as any).tag, "c-read"); assert.equal((c.act() as any).tag, "c-act"); assert.equal(c.region, "eu-west-1");
  assert.equal(c.accounts.length, 2);
  for (const id of [null, undefined, "999999999999", "111122223333"]) { const p = credsForAccount(creds, id); assert.equal((p.read as any).tag, "p-read"); assert.equal(p.region, "us-east-1"); }
});

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { PROFILE_NAME_RE } from "../aws_config.js";
import { recommendedPolicy } from "../permissions.js";
import { probeDocument } from "../probes.js";
import {
  SETUP_DEFAULTS, SETUP_NAME_RE, SetupOptions, renderSetupPlan, renderSetupScript, setupCommands, setupQuery, validateSetupOptions,
} from "../setup_script.js";

const CTX = { managedProfile: "aws-advisor-managed", advisorUrl: "http://localhost:9034" };
const laptop = (extra: Record<string, unknown> = {}) => validateSetupOptions({ path: "laptop-key", ...extra }, CTX);
const ec2 = (extra: Record<string, unknown> = {}) => validateSetupOptions({ path: "ec2-role", ...extra }, CTX);

const bashN = (script: string) => spawnSync("bash", ["-n"], { input: script, encoding: "utf8" });

// ---- a fake toolchain: `aws` records every call and answers per FAKE_MODE (exists | fresh); `curl` plays the advisor ----

const FAKE_AWS = `#!/usr/bin/env bash
if [ "\${1:-}" = --profile ]; then echo "profile=$2" >> "$FAKE_LOG"; shift 2; fi
echo "$*" >> "$FAKE_LOG"
a="$*"
case "$a" in
  "sts get-caller-identity --output text --query [Account,Arn]") printf '123456789012\\tarn:aws:iam::123456789012:user/admin\\n'; exit 0 ;;
  "sts get-caller-identity --profile "*) printf 'arn:aws:sts::123456789012:assumed-role/aws-advisor-read/botocore-session-1\\n'; exit 0 ;;
  "configure get "*) if [ "$FAKE_MODE" = exists ]; then echo AKIAEXISTING000000001; exit 0; else exit 1; fi ;;
  "configure set "*) exit 0 ;;
  "iam create-access-key "*) printf 'AKIAFAKE000000000001\\tSECRETFAKEwJalrXUtnFEMIK7MDENG\\n'; exit 0 ;;
  "iam create-role "*) if [ -n "\${FAKE_PRINCIPAL_LAG:-}" ] && [ ! -f "$FAKE_LOG.lag" ]; then touch "$FAKE_LOG.lag"; echo "An error occurred (MalformedPolicyDocument) when calling the CreateRole operation: Invalid principal in policy" >&2; exit 254; fi; exit 0 ;;
esac
if [ "$FAKE_MODE" = fresh ]; then
  case "$a" in
    "iam get-user "*|"iam get-role "*|"iam get-instance-profile "*|"ssm describe-document "*) echo "An error occurred (NoSuchEntity) when calling the operation: not found" >&2; exit 254 ;;
    "ec2 describe-instances "*) echo 1; exit 0 ;;
    *"list-access-keys"*) echo 0; exit 0 ;;
    *) exit 0 ;;
  esac
fi
case "$a" in
  "iam get-role --role-name aws-advisor-read --query Role.AssumeRolePolicyDocument --output json")
    echo '{"Version":"2012-10-17","Statement":[{"Sid":"AdvisorUser","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:user/aws-advisor"},"Action":"sts:AssumeRole"}]}' ;;
  "iam get-instance-profile "*"--query InstanceProfile.Roles[].RoleName"*) echo aws-advisor-host ;;
  "iam list-attached-role-policies "*) echo arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore ;;
  "iam list-user-policies "*) printf 'aws-advisor-assume\\taws-advisor-read\\n' ;;
  "iam list-attached-user-policies "*) echo arn:aws:iam::aws:policy/ReadOnlyAccess ;;
  *"list-access-keys"*) echo 1 ;;
  "ssm get-document "*) echo '{"schemaVersion":"2.2","description":"older"}' ;;
  "ssm update-document "*) echo "An error occurred (DuplicateDocumentContent) when calling the UpdateDocument operation" >&2; exit 254 ;;
  "ec2 describe-iam-instance-profile-associations "*) echo arn:aws:iam::123456789012:instance-profile/aws-advisor-host ;;
  "ec2 describe-instances "*) echo 2 ;;
esac
exit 0
`;

const FAKE_CURL = `#!/usr/bin/env bash
echo "curl $*" >> "$FAKE_LOG"
case "$*" in
  *"/health"*) exit 0 ;;
  *"/api/settings/aws"*) printf '%s\\n200' '{"saved":{},"test":{"ok":true,"accountId":"123456789012"},"sdk":{"ok":true,"arn":"arn:aws:sts::123456789012:assumed-role/aws-advisor-read/aws-advisor"}}'; exit 0 ;;
  *"/api/accounts"*) printf '%s\n200' '{"saved":{"account_id":"123456789012","name":"staging"},"test":{"ok":true,"arn":"arn:aws:sts::123456789012:assumed-role/aws-advisor-read/advisor"},"accounts":[]}'; exit 0 ;;
  *"/api/permissions/check"*) printf '%s\\n200' '{"account_id":"123456789012","region":"us-east-1","results":[{"id":"a","label":"A","status":"ok"},{"id":"b","label":"B","status":"skipped","message":"x"}],"missing":[],"took_ms":12}'; exit 0 ;;
esac
exit 1
`;

function runWithFakes(script: string, mode: "exists" | "fresh", args: string[] = [], env: Record<string, string> = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "advisor-setup-"));
  const bin = path.join(dir, "bin");
  fs.mkdirSync(bin);
  fs.writeFileSync(path.join(bin, "aws"), FAKE_AWS, { mode: 0o755 });
  fs.writeFileSync(path.join(bin, "curl"), FAKE_CURL, { mode: 0o755 });
  const log = path.join(dir, "calls.log");
  fs.writeFileSync(log, "");
  const file = path.join(dir, "setup.sh");
  fs.writeFileSync(file, script);
  const r = spawnSync("bash", [file, ...args], { encoding: "utf8", env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, FAKE_LOG: log, FAKE_MODE: mode, TMPDIR: dir, ...env } });
  const calls = fs.readFileSync(log, "utf8").split("\n").filter(Boolean);
  fs.rmSync(dir, { recursive: true, force: true });
  return { ...r, out: `${r.stdout}\n${r.stderr}`, calls };
}
const hasPython = spawnSync("python3", ["--version"]).status === 0;

// ---- rendering ----------------------------------------------------------------------------------------------------

test("laptop-key: the script passes bash -n and embeds the account detection, the policy, the trust and the profile writes", () => {
  const o = laptop();
  const s = renderSetupScript(o);
  assert.equal(bashN(s).status, 0, bashN(s).stderr);
  assert.match(s, /^#!\/usr\/bin\/env bash\n/);
  assert.match(s, /^set -euo pipefail$/m);
  assert.ok(s.includes("aws_admin sts get-caller-identity --output text --query '[Account,Arn]'"));
  assert.ok(s.includes(JSON.stringify(recommendedPolicy("<ACCOUNT_ID>"), null, 2)), "the recommended policy JSON is embedded verbatim");
  for (const kind of ["host", "docker", "apps", "software"] as const) assert.ok(s.includes(JSON.stringify(probeDocument(kind), null, 2)), `the ${kind} probe document is embedded verbatim`);
  assert.ok(s.includes('"AWS": "arn:aws:iam::<ACCOUNT_ID>:user/aws-advisor"'), "the trust policy names the user");
  assert.ok(!s.includes("role/aws-advisor-host"), "the laptop path does not mention the instance role");
  assert.ok(s.includes('sed "s/<ACCOUNT_ID>/$ACCOUNT_ID/g"'), "the placeholder is substituted at run time");
  assert.ok(s.includes('aws configure set --profile "$SOURCE_PROFILE" aws_access_key_id "$key_id"'));
  assert.ok(s.includes('aws configure set --profile "$SOURCE_PROFILE" aws_secret_access_key "$key_secret"'));
  assert.ok(s.includes('configure_set "$PROFILE_NAME" role_arn "$ROLE_ARN"'));
  assert.ok(s.includes('configure_set "$PROFILE_NAME" source_profile "$SOURCE_PROFILE"'));
  assert.ok(s.includes('configure_set "$PROFILE_NAME" region "$REGION"'));
  assert.doesNotMatch(s, /(echo|printf|note|warn|die)[^\n]*\$\{?key_secret/, "the secret key is never echoed");
  assert.ok(s.includes('"mode":"profile","profile":"\'"$PROFILE_NAME"\'"'), "PUT /api/settings/aws with the profile");
  assert.ok(s.includes("/api/permissions/check"));
  assert.ok(s.includes("DRY_RUN=0"));
  assert.ok(s.includes("TOTAL_STEPS=11"));
});

test("ec2-role: the trust names the instance role, the host gets SSM-managed and the instance steps are guarded by instanceId", () => {
  const withInstance = renderSetupScript(ec2({ instanceId: "i-0123456789abcdef0", adminProfile: "admin" }));
  assert.equal(bashN(withInstance).status, 0);
  assert.ok(withInstance.includes('"AWS": "arn:aws:iam::<ACCOUNT_ID>:role/aws-advisor-host"'));
  assert.ok(withInstance.includes('"Service": "ec2.amazonaws.com"'));
  assert.ok(withInstance.includes("AmazonSSMManagedInstanceCore"));
  assert.ok(withInstance.includes("associate-iam-instance-profile"));
  assert.ok(withInstance.includes('modify-instance-metadata-options --region "$REGION" --instance-id "$INSTANCE_ID" --http-put-response-hop-limit 2'));
  assert.ok(withInstance.includes('"mode":"chain","credentialSource":"Ec2InstanceMetadata"'));
  assert.ok(withInstance.includes("ADMIN_PROFILE='admin'"));
  assert.ok(withInstance.includes("TOTAL_STEPS=11"));
  const without = renderSetupScript(ec2());
  assert.equal(bashN(without).status, 0);
  assert.ok(!without.includes("associate-iam-instance-profile --region"));
  assert.ok(!without.includes("modify-instance-metadata-options --region"));
  assert.ok(without.includes("TOTAL_STEPS=9"));
  assert.ok(!without.includes("user/aws-advisor"), "no IAM user on the EC2 path");
});

test("dry run: every command is printed with a + prefix, nothing is called and no key appears", () => {
  const s = renderSetupScript(laptop({ dryRun: "1", adminProfile: "admin" }));
  assert.ok(s.includes("DRY_RUN=1"));
  assert.match(s, /THIS COPY IS A DRY RUN/);
  const r = runWithFakes(s, "fresh");
  assert.equal(r.status, 0, r.out);
  for (let i = 1; i <= 11; i++) assert.ok(r.out.includes(`==> step ${i}/11: `), `step ${i} printed`);
  assert.ok(r.out.includes("    + aws --profile admin iam create-user --user-name aws-advisor"));
  assert.ok(r.out.includes("    + aws --profile admin iam create-role --role-name aws-advisor-read"));
  assert.ok(r.out.includes("    + aws --profile admin iam put-role-policy --role-name aws-advisor-read"));
  assert.ok(r.out.includes("    + aws --profile admin iam create-access-key --user-name aws-advisor"));
  assert.ok(r.out.includes("    + aws configure set --profile aws-advisor-user aws_secret_access_key <SecretAccessKey>"));
  assert.ok(r.out.includes("    + aws configure set --profile aws-advisor role_arn arn:aws:iam::123456789012:role/aws-advisor-read"));
  for (const k of ["host", "docker", "apps", "software"]) assert.ok(r.out.includes(`    + aws --profile admin ssm create-document --name AwsAdvisorProbe-${k}`), `dry run prints the ${k} document creation`);
  assert.ok(r.out.includes("    + curl -fsS -X PUT 'http://localhost:9034/api/settings/aws'"));
  assert.ok(r.out.includes("Dry run complete: nothing was changed"));
  assert.deepEqual(r.calls, [], "a dry run makes no aws or curl call at all");
  assert.ok(!r.out.includes("AKIA"));
  // --dry-run on a real copy behaves the same
  const real = runWithFakes(renderSetupScript(laptop()), "fresh", ["--dry-run"]);
  assert.equal(real.status, 0, real.out);
  assert.deepEqual(real.calls, []);
  assert.ok(real.out.includes("    + aws iam create-user --user-name aws-advisor"));
});

test("real run, everything already exists: every step is skipped or refreshed, nothing is created (idempotent)", () => {
  const r = runWithFakes(renderSetupScript(laptop()), "exists");
  assert.equal(r.status, 0, r.out);
  assert.ok(r.out.includes("account 123456789012, running as arn:aws:iam::123456789012:user/admin"));
  assert.ok(r.out.includes("user aws-advisor exists: kept"));
  assert.ok(r.out.includes("trust policy of aws-advisor-read already allows arn:aws:iam::123456789012:user/aws-advisor"));
  assert.ok(r.out.includes("removed inline policy aws-advisor-read from aws-advisor"));
  assert.ok(r.out.includes("detached managed policy arn:aws:iam::aws:policy/ReadOnlyAccess from aws-advisor"));
  assert.ok(r.out.includes("aws-advisor already has 1 access key(s): none created"));
  assert.ok(r.out.includes("[aws-advisor-user] on this machine already holds a key: kept"));
  assert.ok(r.out.includes("ok: arn:aws:sts::123456789012:assumed-role/aws-advisor-read/botocore-session-1"));
  for (const k of ["host", "docker", "apps", "software"]) assert.ok(r.out.includes(`already up to date (aws-advisor/2.0 ${k}): arn:aws:ssm:us-east-1:123456789012:document/AwsAdvisorProbe-${k}`), `${k} document already up to date`);
  if (hasPython) {
    assert.ok(r.out.includes("Steampipe: connected to account 123456789012"));
    assert.ok(r.out.includes("1 ok, 0 missing, 0 error, 1 skipped"));
  }
  assert.ok(r.out.includes("Done. The advisor at http://localhost:9034 uses profile aws-advisor (account 123456789012)"));
  assert.ok(!r.calls.some((c) => /^iam create-(user|role|access-key)/.test(c) || /^ssm create-document/.test(c)), `no create call: ${r.calls.join(" | ")}`);
  assert.ok(r.calls.includes("iam put-role-policy --role-name aws-advisor-read --policy-name aws-advisor-read --policy-document file://" + r.calls.find((c) => c.startsWith("iam put-role-policy"))!.split("file://")[1]));
  assert.ok(r.calls.includes("iam attach-role-policy --role-name aws-advisor-read --policy-arn arn:aws:iam::aws:policy/ViewOnlyAccess"), "ViewOnlyAccess goes on the read role next to the inline policy");
  assert.ok(r.calls.includes("iam delete-user-policy --user-name aws-advisor --policy-name aws-advisor-read"));
  assert.ok(r.calls.some((c) => c.startsWith("curl") && c.includes("-X PUT http://localhost:9034/api/settings/aws")));
  assert.ok(r.calls.some((c) => c.startsWith("curl") && c.includes("-X POST http://localhost:9034/api/permissions/check")));
  assert.ok(!r.calls.some((c) => c.includes("--profile admin")), "no admin profile when none was given");
});

test("real run from scratch: creates everything, writes the key with aws configure set and never prints the secret", () => {
  const r = runWithFakes(renderSetupScript(laptop()), "fresh", ["--api-token", "tok123"]);
  assert.equal(r.status, 0, r.out);
  assert.ok(r.calls.includes("iam create-user --user-name aws-advisor --tags Key=app,Value=aws-advisor"));
  assert.ok(r.calls.some((c) => c.startsWith("iam create-role --role-name aws-advisor-read --assume-role-policy-document file://")));
  assert.ok(r.calls.includes("iam create-access-key --user-name aws-advisor --query AccessKey.[AccessKeyId,SecretAccessKey] --output text"));
  assert.ok(r.calls.includes("configure set --profile aws-advisor-user aws_access_key_id AKIAFAKE000000000001"));
  assert.ok(r.calls.includes("configure set --profile aws-advisor-user aws_secret_access_key SECRETFAKEwJalrXUtnFEMIK7MDENG"), "the secret goes to aws configure set");
  assert.ok(r.calls.includes("configure set --profile aws-advisor role_arn arn:aws:iam::123456789012:role/aws-advisor-read"));
  assert.ok(r.calls.includes("configure set --profile aws-advisor source_profile aws-advisor-user"));
  assert.ok(r.calls.includes("configure set --profile aws-advisor region us-east-1"));
  for (const k of ["host", "docker", "apps", "software"]) assert.ok(r.calls.some((c) => c.startsWith(`ssm create-document --name AwsAdvisorProbe-${k} --document-type Command --document-format JSON --content file://`)), `${k} document created`);
  assert.ok(!r.out.includes("SECRETFAKE"), "the secret never reaches the terminal");
  assert.ok(r.out.includes("created key AKIAFAKE000000000001 and wrote it to [aws-advisor-user]"));
  assert.ok(r.calls.some((c) => c.startsWith("curl") && c.includes("x-api-token: tok123")), "--api-token is sent to the advisor");
});

test("ec2-role real run with an instance already set up: association and hop limit are left alone", () => {
  const r = runWithFakes(renderSetupScript(ec2({ instanceId: "i-0123456789abcdef0" })), "exists");
  assert.equal(r.status, 0, r.out);
  assert.ok(r.out.includes("instance profile aws-advisor-host exists and carries the role"));
  assert.ok(r.out.includes("already attached"));
  assert.ok(r.out.includes("i-0123456789abcdef0 already uses instance profile aws-advisor-host"));
  assert.ok(r.out.includes("hop limit is already 2"));
  assert.ok(r.out.includes("role to assume:     arn:aws:iam::123456789012:role/aws-advisor-read"));
  assert.ok(!r.calls.some((c) => /^(iam create-|ec2 associate|ec2 modify)/.test(c)));
  assert.ok(r.calls.includes("iam put-role-policy --role-name aws-advisor-host --policy-name aws-advisor-assume --policy-document file://" + r.calls.find((c) => c.startsWith("iam put-role-policy --role-name aws-advisor-host"))!.split("file://")[1]));
});

test("a failing aws call aborts with the command and its error", () => {
  const s = renderSetupScript(laptop());
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "advisor-setup-fail-"));
  const bin = path.join(dir, "bin"); fs.mkdirSync(bin);
  fs.writeFileSync(path.join(bin, "aws"), `#!/usr/bin/env bash\ncase "$*" in *get-caller-identity*) printf '123456789012\\tarn:aws:iam::123456789012:user/admin\\n';; *get-user*) exit 0;; *get-role*) echo '{"Statement":[{"Sid":"AdvisorUser","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:user/aws-advisor"},"Action":"sts:AssumeRole"}]}';; *) echo "An error occurred (AccessDenied): nope" >&2; exit 254;; esac\n`, { mode: 0o755 });
  fs.writeFileSync(path.join(bin, "curl"), "#!/usr/bin/env bash\nexit 0\n", { mode: 0o755 });
  const r = spawnSync("bash", ["-c", s], { encoding: "utf8", env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, TMPDIR: dir } });
  fs.rmSync(dir, { recursive: true, force: true });
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /ERROR: aws iam put-role-policy --role-name aws-advisor-read [^\n]* failed: An error occurred \(AccessDenied\): nope/);
  assert.ok(r.stdout.includes("trust policy of aws-advisor-read already allows"));
  assert.ok(!r.stdout.includes("==> step 5/11"), "the script stops at the failing step");
});

// ---- the plan -------------------------------------------------------------------------------------------------------

test("the plan has the expected steps per path and names the probe document", () => {
  const lp = renderSetupPlan(laptop());
  assert.equal(lp.length, 11);
  assert.deepEqual(lp.map((s) => s.title), [
    "Detect the AWS account and the admin identity",
    "Create the IAM user aws-advisor",
    "Create the read-only role aws-advisor-read trusted by user aws-advisor",
    "Put the read-only policy on aws-advisor-read and attach ViewOnlyAccess",
    "Leave aws-advisor with exactly one permission: assuming aws-advisor-read",
    "Create an access key for aws-advisor and store it under [aws-advisor-user]",
    "Write the [profile aws-advisor] that assumes the role",
    "Verify that the profile answers as aws-advisor-read",
    "Create the read-only SSM probe documents (AwsAdvisorProbe-host, AwsAdvisorProbe-docker, AwsAdvisorProbe-apps, AwsAdvisorProbe-software) in us-east-1",
    "Point the advisor (http://localhost:9034) at profile aws-advisor and test it",
    "Run the advisor's permission check",
  ]);
  assert.ok(lp.every((s) => s.detail.length > 20));
  assert.equal(renderSetupPlan(ec2()).length, 9);
  const ep = renderSetupPlan(ec2({ instanceId: "i-0123456789abcdef0" }));
  assert.equal(ep.length, 11);
  assert.ok(ep.some((s) => s.title === "Associate the instance profile with i-0123456789abcdef0"));
  assert.ok(ep.some((s) => s.title.startsWith("IMDS hop limit 2 on i-0123456789abcdef0")));
  assert.ok(ep.some((s) => s.title.startsWith("Create the read-only SSM probe documents (AwsAdvisorProbe-host")));
  assert.ok(ep.some((s) => s.title === "Create the read-only role aws-advisor-read trusted by instance role aws-advisor-host"));
  // the script prints the same numbering
  const s = renderSetupScript(ec2({ instanceId: "i-0123456789abcdef0" }));
  ep.forEach((st, i) => assert.ok(s.includes(`#   ${i + 1}. ${st.title}`)));
});

// ---- validation and the command --------------------------------------------------------------------------------------

test("validation reuses the profile regex and rejects bad names, regions, ids and URLs", () => {
  assert.equal(SETUP_NAME_RE, PROFILE_NAME_RE);
  const d = validateSetupOptions({}, CTX);
  assert.deepEqual(d, { path: "laptop-key", userName: SETUP_DEFAULTS.userName, roleName: SETUP_DEFAULTS.roleName, profileName: SETUP_DEFAULTS.profileName, region: SETUP_DEFAULTS.region, instanceRoleName: SETUP_DEFAULTS.instanceRoleName, advisorUrl: "http://localhost:9034", dryRun: false } satisfies SetupOptions);
  assert.throws(() => laptop({ user: "bad name" }), /user must match/);
  assert.throws(() => laptop({ role: "x;rm -rf /" }), /role must match/);
  assert.throws(() => laptop({ profile: "a'b" }), /profile must match/);
  assert.throws(() => laptop({ profile: "aws-advisor-managed" }), /manages itself/);
  assert.throws(() => laptop({ user: "x", profile: "x-user" }), /collides/);
  assert.throws(() => laptop({ region: "US" }), /not a region name/);
  assert.throws(() => laptop({ region: "*" }), /not a region name/);
  assert.throws(() => ec2({ instanceId: "i-xyz" }), /not an EC2 instance id/);
  assert.throws(() => ec2({ instanceRole: "aws-advisor-read" }), /different names/);
  assert.throws(() => laptop({ adminProfile: "a b" }), /adminProfile must match/);
  assert.throws(() => laptop({ advisorUrl: "http://x/'; rm" }), /advisorUrl/);
  assert.throws(() => laptop({ advisorUrl: "ftp://x" }), /advisorUrl/);
  assert.throws(() => validateSetupOptions({ path: "other" }, CTX), /path must be/);
  const o = ec2({ instanceId: " i-0123456789abcdef0 ", region: "eu-west-1", dryRun: "true", advisorUrl: "http://10.0.0.5:9034/" });
  assert.equal(o.instanceId, "i-0123456789abcdef0");
  assert.equal(o.region, "eu-west-1");
  assert.equal(o.dryRun, true);
  assert.equal(o.advisorUrl, "http://10.0.0.5:9034");
  // the query-string spellings the UI sends
  assert.equal(validateSetupOptions({ path: "ec2-role", instanceRole: "swarm-host", dry_run: "1" }, CTX).instanceRoleName, "swarm-host");
});

test("the one-liners: download-read-run, the piped variant, and the token when the API is protected", () => {
  const plain = setupCommands(laptop());
  assert.equal(plain.scriptUrl, "http://localhost:9034/api/setup/script?path=laptop-key");
  assert.equal(plain.command, 'curl -fsSL "http://localhost:9034/api/setup/script?path=laptop-key" -o aws-advisor-setup.sh && less aws-advisor-setup.sh && bash aws-advisor-setup.sh');
  assert.equal(plain.piped, 'curl -fsSL "http://localhost:9034/api/setup/script?path=laptop-key" | bash');
  const full = setupCommands(ec2({ instanceRole: "swarm-host", instanceId: "i-0123456789abcdef0", region: "eu-west-1", adminProfile: "admin", dryRun: "1" }), "jwt.token");
  assert.equal(full.scriptUrl, "http://localhost:9034/api/setup/script?path=ec2-role&region=eu-west-1&instanceRole=swarm-host&instanceId=i-0123456789abcdef0&adminProfile=admin&dryRun=1&token=jwt.token");
  assert.ok(full.command.endsWith("&& ADVISOR_API_TOKEN='jwt.token' bash aws-advisor-setup.sh"));
  assert.ok(full.piped.endsWith("| ADVISOR_API_TOKEN='jwt.token' bash"));
});


test("member-role: the child's read role trusts the parent's identity, the policy is applied, the documents created and the child registered; rerun merges the trust and creates nothing", () => {
  assert.throws(() => validateSetupOptions({ path: "member-role" }, CTX), /trustArn/);
  assert.throws(() => validateSetupOptions({ path: "member-role", trustArn: "not-an-arn" }, CTX), /trustArn must be/);
  const o = validateSetupOptions({ path: "member-role", trustArn: "arn:aws:iam::210987654321:role/aws-advisor-read", memberName: "staging" }, CTX);
  assert.deepEqual(renderSetupPlan(o).map((s) => s.title.split(" ").slice(0, 4).join(" ")), ["Detect the AWS account", "Create the read-only role", "Put the read-only policy", "Create the read-only SSM", "Register this account with"]);
  assert.ok(setupQuery(o).includes("trustArn=arn%3Aaws%3Aiam%3A%3A210987654321%3Arole%2Faws-advisor-read") && setupQuery(o).includes("memberName=staging"));
  const script = renderSetupScript(o);
  assert.ok(script.includes('"AWS": "arn:aws:iam::210987654321:role/aws-advisor-read"'), "the trust document names the parent's identity");
  assert.ok(script.includes("PRINCIPAL_SID='AdvisorParent'") && !script.includes("create-user"), "no user, no key: the parent assumes the role");
  const fresh = runWithFakes(script, "fresh");
  assert.equal(fresh.status, 0, fresh.out);
  assert.ok(fresh.calls.some((c) => c.includes("iam create-role --role-name aws-advisor-read")), fresh.calls.join("\n"));
  assert.ok(fresh.calls.some((c) => c.includes("iam put-role-policy --role-name aws-advisor-read")));
  assert.ok(fresh.out.includes("saved as member 123456789012") && fresh.out.includes("role assumed from the parent: ok"), fresh.out);
  const again = runWithFakes(script, "exists");
  assert.equal(again.status, 0, again.out);
  assert.ok(again.out.includes("role aws-advisor-read exists") && again.out.includes("added arn:aws:iam::210987654321:role/aws-advisor-read to the trust policy of aws-advisor-read (existing principals kept)"), again.out);
  assert.ok(again.calls.some((c) => c.includes("iam update-assume-role-policy --role-name aws-advisor-read")), "the merged trust policy is written");
  assert.ok(!again.calls.some((c) => c.includes("create-role")), "nothing created on a rerun");
});

test("the parent's read policy lets its identity assume the members' read roles (both sides of a cross-account assumption)", () => {
  const st = (recommendedPolicy("123456789012") as any).Statement.find((x: any) => x.Sid === "AdvisorAssumeMembers");
  assert.deepEqual(st, { Sid: "AdvisorAssumeMembers", Effect: "Allow", Action: ["sts:AssumeRole"], Resource: ["arn:aws:iam::*:role/aws-advisor-read"] });
  assert.deepEqual((recommendedPolicy("123456789012", "advisor-ro") as any).Statement.find((x: any) => x.Sid === "AdvisorAssumeMembers").Resource, ["arn:aws:iam::*:role/advisor-ro"]);
});

test("a principal created seconds ago is retried until IAM resolves it: the first create-role answers Invalid principal, the second succeeds", () => {
  const script = renderSetupScript(laptop()).replace("sleep 5; continue", "continue");
  const r = runWithFakes(script, "fresh", [], { FAKE_PRINCIPAL_LAG: "1" });
  assert.equal(r.status, 0, r.out);
  assert.ok(r.out.includes("not visible to IAM yet"), r.out);
  assert.equal(r.calls.filter((c) => c.includes("iam create-role --role-name aws-advisor-read")).length, 2, "one failed attempt, one that created it");
  assert.ok(r.out.includes("created arn:aws:iam::123456789012:role/aws-advisor-read"));
});

test("principalArnOf: an STS assumed-role session is its IAM role; users and roles are themselves", async () => {
  const { principalArnOf } = await import("../routes/accounts.js");
  assert.equal(principalArnOf("arn:aws:sts::210987654321:assumed-role/aws-advisor-read/aws-sdk-js-1234"), "arn:aws:iam::210987654321:role/aws-advisor-read");
  assert.equal(principalArnOf("arn:aws:iam::210987654321:user/aws-advisor"), "arn:aws:iam::210987654321:user/aws-advisor");
  assert.equal(principalArnOf("arn:aws:iam::210987654321:role/x"), "arn:aws:iam::210987654321:role/x");
});

test("member-role refuses to run in the parent: credentials that resolve to the trusted identity's account stop at step 1 with nothing changed", () => {
  // the fake toolchain's caller is account 123456789012; a trust ARN in that same account means the terminal is the parent's
  const o = validateSetupOptions({ path: "member-role", trustArn: "arn:aws:iam::123456789012:role/aws-advisor-read" }, CTX);
  const r = runWithFakes(renderSetupScript(o), "fresh");
  assert.notEqual(r.status, 0);
  assert.ok(r.out.includes("which is the PARENT"), r.out);
  assert.ok(!r.calls.some((c) => c.includes("create-role") || c.includes("put-role-policy")), "nothing was created");
});

test("an EC2 host in a member account: ec2-host makes the instance role assume the parent's read role; ec2-role with hostRoleArn makes the parent's read role trust that instance role and creates nothing for the host", () => {
  const host = validateSetupOptions({ path: "ec2-host", assumeArn: "arn:aws:iam::210987654321:role/aws-advisor-read" }, CTX);
  assert.deepEqual(renderSetupPlan(host).map((s) => s.title.split(" ").slice(0, 3).join(" ")), ["Detect the AWS", "Instance role aws-advisor-host", "Attach AmazonSSMManagedInstanceCore to", "Let aws-advisor-host assume"]);
  const hs = renderSetupScript(host);
  assert.ok(hs.includes('"Resource": "arn:aws:iam::210987654321:role/aws-advisor-read"'), "the assume policy names the parent's read role");
  assert.ok(!hs.includes("POLICY_JSON=$(cat") || !renderSetupPlan(host).some((s) => /read-only policy/.test(s.title)), "no read role here");
  const hr = runWithFakes(hs, "fresh");
  assert.equal(hr.status, 0, hr.out);
  assert.ok(hr.calls.some((c) => c.includes("iam create-role --role-name aws-advisor-host")) && hr.calls.some((c) => c.includes("put-role-policy --role-name aws-advisor-host --policy-name aws-advisor-assume")));
  assert.ok(!hr.calls.some((c) => c.includes("create-role --role-name aws-advisor-read")), "the read role is the parent's business");
  assert.ok(hr.out.includes("may assume the parent's read role arn:aws:iam::210987654321:role/aws-advisor-read"), hr.out);
  assert.throws(() => validateSetupOptions({ path: "ec2-host" }, CTX), /assumeArn/);

  const parent = validateSetupOptions({ path: "ec2-role", hostRoleArn: "arn:aws:iam::123456789012:role/aws-advisor-host" }, CTX);
  assert.deepEqual(renderSetupPlan(parent).map((s) => s.title.split(" ").slice(0, 3).join(" ")), ["Detect the AWS", "Create the read-only", "Put the read-only", "Create the read-only", "Advisor settings: Instance", "Run the advisor's"]);
  const ps = renderSetupScript(parent);
  assert.ok(ps.includes('"AWS": "arn:aws:iam::123456789012:role/aws-advisor-host"'), "the trust names the host's instance role, in its own account");
  const pr = runWithFakes(ps, "fresh");
  assert.equal(pr.status, 0, pr.out);
  assert.ok(!pr.calls.some((c) => c.includes("create-role --role-name aws-advisor-host")) && !pr.calls.some((c) => c.includes("create-instance-profile")), "nothing is made for the host in the parent");
  assert.ok(setupQuery(parent).includes("hostRoleArn=") && setupQuery(host).includes("assumeArn="));
  assert.throws(() => validateSetupOptions({ path: "laptop-key", hostRoleArn: "arn:aws:iam::123456789012:role/x" }, CTX), /goes with path ec2-role/);
});

test("the member path's closing text is the member's, not the EC2 host's", () => {
  const o = validateSetupOptions({ path: "member-role", trustArn: "arn:aws:iam::210987654321:role/aws-advisor-read" }, CTX);
  const r = runWithFakes(renderSetupScript(o), "fresh");
  assert.ok(r.out.includes("is a member: its read role") && !r.out.includes("trusts instance role"), r.out);
});

import { PROFILE_NAME_RE } from "./aws_config.js";
import { config } from "./config.js";
import { policyProbeDocument, recommendedPolicy } from "./permissions.js";
import { PROBE_VERSION, probeDocument } from "./ssm.js";

/**
 * The one-command onboarding: a self-contained bash script that performs the README's "Onboarding" steps end to
 * end, idempotently, with the admin credentials of whoever runs it (the advisor never sees them). Two paths:
 *
 * - laptop-key: a dedicated IAM user whose only permission is assuming the read-only role, the role with the
 *   recommended policy, an access key written straight into `~/.aws/credentials` (never printed), a profile
 *   that assumes the role, the SSM probe document, then the advisor is pointed at the profile and checked.
 * - ec2-role: the read-only role trusting an instance role (created with its instance profile when missing,
 *   SSM-managed through AmazonSSMManagedInstanceCore), the probe document, optionally the instance profile
 *   associated with an instance and its IMDS hop limit raised for containers, then the advisor's chain-mode
 *   settings are printed and, when the advisor is reachable, saved and checked.
 *
 * Every step checks what exists and skips or updates it, so rerunning is safe. `dryRun` prints every command
 * instead of running it (no AWS call at all: every check is assumed to find nothing). The same step list also
 * renders as a human-readable plan for the Settings wizard (GET /api/setup/plan).
 */

export type SetupPath = "laptop-key" | "ec2-role";
export const SETUP_PATHS: SetupPath[] = ["laptop-key", "ec2-role"];

export interface SetupOptions {
  path: SetupPath;
  /** IAM user (laptop-key). */
  userName: string;
  /** The read-only role both paths create. */
  roleName: string;
  /** The `[profile <name>]` that assumes the role (laptop-key); the key itself goes under `[<userName>-user]`. */
  profileName: string;
  region: string;
  /** ec2-role: the instance role the read-only role trusts; created (with an instance profile) when missing. */
  instanceRoleName: string;
  /** ec2-role, optional: associate the instance profile with this instance and raise its IMDS hop limit. */
  instanceId?: string;
  /** Where the script PUTs the settings and runs the permission check. */
  advisorUrl: string;
  /** `--profile` for every admin `aws` call (never for `aws configure`, which targets the profiles it writes). */
  adminProfile?: string;
  /** Print the commands instead of running them. */
  dryRun: boolean;
}

export const SETUP_DEFAULTS = {
  userName: "aws-advisor",
  roleName: "aws-advisor-read",
  profileName: "aws-advisor",
  region: "us-east-1",
  instanceRoleName: "aws-advisor-host",
  advisorUrl: "http://localhost:9034",
};

/** IAM user / role / profile names: the profile regex from aws_config.ts (IAM allows a few more characters; these are enough). */
export const SETUP_NAME_RE = PROFILE_NAME_RE;
export const SETUP_REGION_RE = /^[a-z]{2}(-[a-z0-9]+)+$/;
export const SETUP_INSTANCE_ID_RE = /^i-[0-9a-f]{8,17}$/;
/** No quotes, backslashes, backticks, `$` or whitespace: the URL is embedded in the script inside single quotes. */
export const SETUP_URL_RE = /^https?:\/\/[A-Za-z0-9._~:/?#@!&()*+,;=%[\]-]+$/;

/**
 * Checks and normalises the query parameters (or any loose object) into SetupOptions. Throws an Error with a
 * user-facing message on the first problem. `managedProfile` is the name the app writes itself (the script must
 * not collide with it).
 */
export function validateSetupOptions(input: Record<string, unknown>, ctx: { advisorUrl?: string; managedProfile?: string } = {}): SetupOptions {
  const str = (v: unknown) => (typeof v === "string" ? v.trim() : Array.isArray(v) ? String(v[0] ?? "").trim() : "");
  const pick = (...keys: string[]) => { for (const k of keys) { const v = str(input[k]); if (v) return v; } return ""; };
  const path = pick("path") || "laptop-key";
  if (!SETUP_PATHS.includes(path as SetupPath)) throw new Error(`path must be ${SETUP_PATHS.join(" or ")}, got "${path}"`);
  const name = (label: string, value: string) => {
    if (!SETUP_NAME_RE.test(value)) throw new Error(`${label} must match ${SETUP_NAME_RE.source}, got "${value}"`);
    if (value.length > 64) throw new Error(`${label} must be at most 64 characters`);
    return value;
  };
  const userName = name("user", pick("user", "userName") || SETUP_DEFAULTS.userName);
  const roleName = name("role", pick("role", "roleName") || SETUP_DEFAULTS.roleName);
  const profileName = name("profile", pick("profile", "profileName") || SETUP_DEFAULTS.profileName);
  const instanceRoleName = name("instanceRole", pick("instanceRole", "instanceRoleName") || SETUP_DEFAULTS.instanceRoleName);
  const region = pick("region") || SETUP_DEFAULTS.region;
  if (!SETUP_REGION_RE.test(region)) throw new Error(`"${region}" is not a region name (e.g. us-east-1)`);
  const instanceId = pick("instanceId", "instance_id") || undefined;
  if (instanceId && !SETUP_INSTANCE_ID_RE.test(instanceId)) throw new Error(`"${instanceId}" is not an EC2 instance id`);
  const adminProfile = pick("adminProfile", "admin_profile") || undefined;
  if (adminProfile) name("adminProfile", adminProfile);
  const advisorUrl = (pick("advisorUrl", "advisor_url") || ctx.advisorUrl || SETUP_DEFAULTS.advisorUrl).replace(/\/+$/, "");
  if (!SETUP_URL_RE.test(advisorUrl)) throw new Error(`advisorUrl must be an http(s) URL without quotes or spaces, got "${advisorUrl}"`);
  const dryRaw = str(input.dryRun ?? input.dry_run);
  const dryRun = dryRaw === "1" || dryRaw === "true" || input.dryRun === true;
  const managed = ctx.managedProfile ?? config.advisorAwsProfile;
  if (profileName === managed || `${userName}-user` === managed) throw new Error(`"${managed}" is the profile the advisor manages itself (ADVISOR_AWS_PROFILE); pick another name`);
  if (`${userName}-user` === profileName) throw new Error(`the profile "${profileName}" collides with the key profile "${userName}-user"; pick another profile name`);
  if (path === "ec2-role" && instanceRoleName === roleName) throw new Error("the instance role and the read-only role must have different names");
  return { path: path as SetupPath, userName, roleName, profileName, region, instanceRoleName, ...(instanceId ? { instanceId } : {}), advisorUrl, ...(adminProfile ? { adminProfile } : {}), dryRun };
}

export interface SetupStep {
  title: string;
  detail: string;
  /** The bash for the step (not part of the plan). */
  bash: string;
}

/** The placeholder the embedded policy carries; the script substitutes the detected account id. */
const ACCOUNT_PLACEHOLDER = "<ACCOUNT_ID>";

/** What the script embeds; injectable so tests do not depend on the environment. */
export interface SetupDocuments {
  policy: object;
  probeDocument: object;
  probeDocumentName: string;
  probeVersion: string;
}

export const defaultSetupDocuments = (): SetupDocuments => ({
  policy: recommendedPolicy(ACCOUNT_PLACEHOLDER),
  probeDocument: probeDocument(),
  // The document the recommended policy scopes ssm:SendCommand to: PROBE_DOCUMENT, or AwsAdvisorProbe when the unsafe
  // stock document is opted in (it is still created, so reverting the opt-in is one env change).
  probeDocumentName: policyProbeDocument(),
  probeVersion: PROBE_VERSION,
});

const sq = (s: string) => `'${s.replace(/'/g, "'\\''")}'`;

// ---- steps ------------------------------------------------------------------------------------------------------------

function detectStep(o: SetupOptions): SetupStep {
  return {
    title: "Detect the AWS account and the admin identity",
    detail: `aws sts get-caller-identity${o.adminProfile ? ` --profile ${o.adminProfile}` : ""}: the 12-digit account id fills the policy and the ARNs; the caller must be an admin of that account.`,
    bash: `
for tool in aws curl; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    if [ "$DRY_RUN" = 1 ]; then warn "$tool is not installed (a dry run does not need it; the real run does)"; else die "$tool is not installed$([ "$tool" = aws ] && printf ' (https://aws.amazon.com/cli/)')"; fi
  fi
done
if [ "$DRY_RUN" = 1 ]; then
  ACCOUNT_ID="123456789012"
  CALLER_ARN="arn:aws:iam::123456789012:user/<you>"
  note "dry run: no AWS call is made, every check is assumed to find nothing, the account id is a placeholder"
else
  identity=$(aws_admin sts get-caller-identity --output text --query '[Account,Arn]' 2>"$WORK/err") || die "aws sts get-caller-identity failed (are admin credentials configured in this terminal?): $(cat "$WORK/err")"
  read -r ACCOUNT_ID CALLER_ARN <<< "$identity"
  case "$ACCOUNT_ID" in [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]) ;; *) die "unexpected account id: $ACCOUNT_ID" ;; esac
fi
ROLE_ARN="arn:aws:iam::$ACCOUNT_ID:role/$ROLE_NAME"
write_documents
note "account $ACCOUNT_ID, running as $CALLER_ARN"`,
  };
}

function userStep(o: SetupOptions): SetupStep {
  return {
    title: `Create the IAM user ${o.userName}`,
    detail: "aws iam create-user, skipped when the user exists. It gets no permissions of its own except assuming the role (step 5).",
    bash: `
if exists iam get-user --user-name "$USER_NAME"; then
  note "user $USER_NAME exists: kept"
else
  run iam create-user --user-name "$USER_NAME" --tags Key=app,Value=aws-advisor
  note "created arn:aws:iam::$ACCOUNT_ID:user/$USER_NAME"
fi`,
  };
}

function readRoleStep(o: SetupOptions): SetupStep {
  const principal = o.path === "laptop-key" ? `user ${o.userName}` : `instance role ${o.instanceRoleName}`;
  return {
    title: `Create the read-only role ${o.roleName} trusted by ${principal}`,
    detail: `aws iam create-role with a trust policy whose principal is the ${principal}. When the role exists, the principal is added to its trust policy if missing (other principals are kept, so a laptop and an EC2 host can share the role).`,
    bash: `
if exists iam get-role --role-name "$ROLE_NAME"; then
  note "role $ROLE_NAME exists"
  ensure_trust "$ROLE_NAME" "$PRINCIPAL_ARN" "$PRINCIPAL_SID"
else
  run iam create-role --role-name "$ROLE_NAME" --assume-role-policy-document "file://$WORK/trust.json" --description "aws-advisor read-only" --tags Key=app,Value=aws-advisor
  note "created $ROLE_ARN trusting $PRINCIPAL_ARN"
fi`,
  };
}

function rolePolicyStep(o: SetupOptions): SetupStep {
  return {
    title: `Put the read-only policy on ${o.roleName}`,
    detail: "aws iam put-role-policy with the advisor's recommended policy (embedded in the script, account id filled in). put-role-policy overwrites, so a rerun refreshes it.",
    bash: `
run iam put-role-policy --role-name "$ROLE_NAME" --policy-name "$ROLE_NAME" --policy-document "file://$WORK/policy.json"
note "inline policy $ROLE_NAME on $ROLE_ARN is the recommended read-only policy (ssm:SendCommand only on document $PROBE_DOCUMENT)"`,
  };
}

function userPolicyStep(o: SetupOptions): SetupStep {
  return {
    title: `Leave ${o.userName} with exactly one permission: assuming ${o.roleName}`,
    detail: `aws iam put-user-policy ${o.userName}-assume (sts:AssumeRole on the role only) and removal of every other inline or attached policy from the user, so the long-lived key can read nothing on its own.`,
    bash: `
run iam put-user-policy --user-name "$USER_NAME" --policy-name "$ASSUME_POLICY_NAME" --policy-document "file://$WORK/assume.json"
note "inline policy $ASSUME_POLICY_NAME: sts:AssumeRole on $ROLE_ARN"
inline=$(query iam list-user-policies --user-name "$USER_NAME" --query 'PolicyNames[]' --output text) || die "list-user-policies failed"
for p in $inline; do
  [ "$p" = "$ASSUME_POLICY_NAME" ] && continue
  run iam delete-user-policy --user-name "$USER_NAME" --policy-name "$p"
  note "removed inline policy $p from $USER_NAME"
done
attached=$(query iam list-attached-user-policies --user-name "$USER_NAME" --query 'AttachedPolicies[].PolicyArn' --output text) || die "list-attached-user-policies failed"
for p in $attached; do
  run iam detach-user-policy --user-name "$USER_NAME" --policy-arn "$p"
  note "detached managed policy $p from $USER_NAME"
done
[ "$DRY_RUN" = 1 ] && note "(a rerun on an existing user also deletes/detaches any other policy it carries)"
true`,
  };
}

function accessKeyStep(o: SetupOptions): SetupStep {
  return {
    title: `Create an access key for ${o.userName} and store it under [${o.userName}-user]`,
    detail: `aws iam create-access-key only when the user has no key yet; the key goes straight into ~/.aws/credentials through aws configure set (the secret is never printed). AWS allows at most 2 keys per user.`,
    bash: `
n=$(query iam list-access-keys --user-name "$USER_NAME" --query 'length(AccessKeyMetadata)' --output text) || die "list-access-keys failed"
n=\${n:-0}
if [ "$n" = "0" ] || [ "$n" = "None" ]; then
  if [ "$DRY_RUN" = 1 ]; then
    printf '    + %s\\n' "$(fmt_admin iam create-access-key --user-name "$USER_NAME" --query 'AccessKey.[AccessKeyId,SecretAccessKey]' --output text)"
    printf '    + %s\\n' "aws configure set --profile $SOURCE_PROFILE aws_access_key_id <AccessKeyId>"
    printf '    + %s\\n' "aws configure set --profile $SOURCE_PROFILE aws_secret_access_key <SecretAccessKey>   (never printed)"
  else
    key=$(aws_admin iam create-access-key --user-name "$USER_NAME" --query 'AccessKey.[AccessKeyId,SecretAccessKey]' --output text 2>"$WORK/err") || die "create-access-key failed: $(cat "$WORK/err")"
    read -r key_id key_secret <<< "$key"
    aws configure set --profile "$SOURCE_PROFILE" aws_access_key_id "$key_id"
    aws configure set --profile "$SOURCE_PROFILE" aws_secret_access_key "$key_secret"
    unset key key_secret
    note "created key $key_id and wrote it to [$SOURCE_PROFILE] in \${AWS_SHARED_CREDENTIALS_FILE:-~/.aws/credentials} (the secret was not printed; it exists nowhere else)"
  fi
else
  note "$USER_NAME already has $n access key(s): none created (AWS allows at most 2 per user; rotate with aws iam create-access-key / delete-access-key)"
  if aws configure get aws_access_key_id --profile "$SOURCE_PROFILE" >/dev/null 2>&1; then
    note "[$SOURCE_PROFILE] on this machine already holds a key: kept"
  else
    die "no [$SOURCE_PROFILE] profile on this machine holds one of them. Either put the existing key there (aws configure --profile $SOURCE_PROFILE) or delete a key you no longer use (aws iam list-access-keys --user-name $USER_NAME; aws iam delete-access-key --user-name $USER_NAME --access-key-id AKIA...) and rerun this script."
  fi
fi`,
  };
}

function profileStep(o: SetupOptions): SetupStep {
  return {
    title: `Write the [profile ${o.profileName}] that assumes the role`,
    detail: `aws configure set --profile ${o.profileName}: role_arn, source_profile = ${o.userName}-user, region = ${o.region} in ~/.aws/config. The advisor and the Steampipe service must read the same file (same user).`,
    bash: `
configure_set "$PROFILE_NAME" role_arn "$ROLE_ARN"
configure_set "$PROFILE_NAME" source_profile "$SOURCE_PROFILE"
configure_set "$PROFILE_NAME" region "$REGION"
note "[profile $PROFILE_NAME] in \${AWS_CONFIG_FILE:-~/.aws/config}: role_arn = $ROLE_ARN, source_profile = $SOURCE_PROFILE, region = $REGION"`,
  };
}

function verifyStep(o: SetupOptions): SetupStep {
  return {
    title: `Verify that the profile answers as ${o.roleName}`,
    detail: `aws sts get-caller-identity --profile ${o.profileName} must show arn:aws:sts::<account>:assumed-role/${o.roleName}/...; IAM changes take a few seconds to propagate, so this retries.`,
    bash: `
if [ "$DRY_RUN" = 1 ]; then
  printf '    + %s\\n' "aws sts get-caller-identity --profile $PROFILE_NAME   (expected: arn:aws:sts::$ACCOUNT_ID:assumed-role/$ROLE_NAME/...)"
else
  arn=""
  for attempt in 1 2 3 4 5 6 7 8 9 10 11 12; do
    if arn=$(aws sts get-caller-identity --profile "$PROFILE_NAME" --query Arn --output text 2>"$WORK/err"); then break; fi
    arn=""
    if [ "$attempt" = 12 ]; then break; fi
    note "not yet (IAM propagation, attempt $attempt/12): retrying in 5 s"
    sleep 5
  done
  [ -n "$arn" ] || die "aws sts get-caller-identity --profile $PROFILE_NAME failed: $(cat "$WORK/err")"
  case "$arn" in
    *":assumed-role/$ROLE_NAME/"*) note "ok: $arn" ;;
    *) die "expected an assumed-role/$ROLE_NAME identity, got $arn" ;;
  esac
fi`,
  };
}

function instanceRoleStep(o: SetupOptions): SetupStep {
  return {
    title: `Instance role ${o.instanceRoleName} with its instance profile`,
    detail: "aws iam create-role with the EC2 service trust plus create-instance-profile / add-role-to-instance-profile, each skipped when it exists. This is the role the EC2 host runs with; it gets no permissions except assuming the read-only role (step 6) and being SSM-managed (step 3).",
    bash: `
if exists iam get-role --role-name "$INSTANCE_ROLE_NAME"; then
  note "role $INSTANCE_ROLE_NAME exists: kept (its trust policy is not touched)"
else
  run iam create-role --role-name "$INSTANCE_ROLE_NAME" --assume-role-policy-document "file://$WORK/ec2-trust.json" --description "aws-advisor host instance role" --tags Key=app,Value=aws-advisor
  note "created arn:aws:iam::$ACCOUNT_ID:role/$INSTANCE_ROLE_NAME (trusts ec2.amazonaws.com)"
fi
if exists iam get-instance-profile --instance-profile-name "$INSTANCE_ROLE_NAME"; then
  roles=$(query iam get-instance-profile --instance-profile-name "$INSTANCE_ROLE_NAME" --query 'InstanceProfile.Roles[].RoleName' --output text) || die "get-instance-profile failed"
  case " $roles " in
    *" $INSTANCE_ROLE_NAME "*) note "instance profile $INSTANCE_ROLE_NAME exists and carries the role" ;;
    *) run iam add-role-to-instance-profile --instance-profile-name "$INSTANCE_ROLE_NAME" --role-name "$INSTANCE_ROLE_NAME"; note "added the role to the existing instance profile $INSTANCE_ROLE_NAME" ;;
  esac
else
  run iam create-instance-profile --instance-profile-name "$INSTANCE_ROLE_NAME"
  run iam add-role-to-instance-profile --instance-profile-name "$INSTANCE_ROLE_NAME" --role-name "$INSTANCE_ROLE_NAME"
  note "created instance profile $INSTANCE_ROLE_NAME with the role"
fi`,
  };
}

function ssmCoreStep(o: SetupOptions): SetupStep {
  return {
    title: `Attach AmazonSSMManagedInstanceCore to ${o.instanceRoleName}`,
    detail: "aws iam attach-role-policy (skipped when attached): the host itself registers with Systems Manager, so the advisor can probe it like any other instance.",
    bash: `
attached=$(query iam list-attached-role-policies --role-name "$INSTANCE_ROLE_NAME" --query 'AttachedPolicies[].PolicyArn' --output text) || die "list-attached-role-policies failed"
case "$attached" in
  *"$SSM_CORE_POLICY"*) note "already attached" ;;
  *) run iam attach-role-policy --role-name "$INSTANCE_ROLE_NAME" --policy-arn "$SSM_CORE_POLICY"; note "attached $SSM_CORE_POLICY" ;;
esac`,
  };
}

function instanceAssumeStep(o: SetupOptions): SetupStep {
  return {
    title: `Let ${o.instanceRoleName} assume ${o.roleName}`,
    detail: `aws iam put-role-policy ${o.instanceRoleName} aws-advisor-assume: sts:AssumeRole on the read-only role and nothing else (put overwrites, so a rerun refreshes it).`,
    bash: `
run iam put-role-policy --role-name "$INSTANCE_ROLE_NAME" --policy-name "$ASSUME_POLICY_NAME" --policy-document "file://$WORK/assume.json"
note "inline policy $ASSUME_POLICY_NAME on $INSTANCE_ROLE_NAME: sts:AssumeRole on $ROLE_ARN"`,
  };
}

function associateStep(o: SetupOptions): SetupStep {
  return {
    title: `Associate the instance profile with ${o.instanceId}`,
    detail: `aws ec2 associate-iam-instance-profile in ${o.region}, only when the instance has no instance profile; an existing different one is reported, never replaced. No reboot is needed.`,
    bash: `
assoc=$(query ec2 describe-iam-instance-profile-associations --region "$REGION" --filters "Name=instance-id,Values=$INSTANCE_ID" "Name=state,Values=associated,associating" --query 'IamInstanceProfileAssociations[].IamInstanceProfile.Arn' --output text) || die "describe-iam-instance-profile-associations failed (is $INSTANCE_ID in $REGION?)"
case "$assoc" in
  ""|None)
    run ec2 associate-iam-instance-profile --region "$REGION" --instance-id "$INSTANCE_ID" --iam-instance-profile "Name=$INSTANCE_ROLE_NAME"
    note "associated instance profile $INSTANCE_ROLE_NAME with $INSTANCE_ID (no reboot needed; the SSM agent registers within a few minutes)" ;;
  *":instance-profile/$INSTANCE_ROLE_NAME")
    note "$INSTANCE_ID already uses instance profile $INSTANCE_ROLE_NAME" ;;
  *)
    warn "$INSTANCE_ID already has another instance profile ($assoc): left as is."
    warn "either rerun this script with instanceRole=<the role of that profile> so THAT role may assume $ROLE_NAME, or replace it:"
    warn "aws ec2 replace-iam-instance-profile-association --region $REGION --association-id <id> --iam-instance-profile Name=$INSTANCE_ROLE_NAME" ;;
esac`,
  };
}

function hopLimitStep(o: SetupOptions): SetupStep {
  return {
    title: `IMDS hop limit 2 on ${o.instanceId} (the advisor runs in a container)`,
    detail: "aws ec2 modify-instance-metadata-options --http-put-response-hop-limit 2, skipped when already 2 or more: a container on the host cannot reach the instance credentials with the default limit of 1.",
    bash: `
hops=$(query ec2 describe-instances --region "$REGION" --instance-ids "$INSTANCE_ID" --query 'Reservations[0].Instances[0].MetadataOptions.HttpPutResponseHopLimit' --output text) || die "describe-instances failed"
if [ -n "$hops" ] && [ "$hops" != None ] && [ "$hops" -ge 2 ] 2>/dev/null; then
  note "hop limit is already $hops"
else
  run ec2 modify-instance-metadata-options --region "$REGION" --instance-id "$INSTANCE_ID" --http-put-response-hop-limit 2 --http-endpoint enabled
  note "hop limit set to 2 (only needed when the advisor runs in a container on the host; harmless otherwise)"
fi`,
  };
}

function probeDocumentStep(o: SetupOptions, d: SetupDocuments): SetupStep {
  return {
    title: `Create the read-only SSM probe document ${d.probeDocumentName} in ${o.region}`,
    detail: `aws ssm create-document from the embedded probe (${d.probeVersion}), or update-document when the content differs. ssm:SendCommand in the policy is granted on this document only, never on AWS-RunShellScript. SSM documents are regional: rerun with another region for instances elsewhere.`,
    bash: `
DOC_ARN="arn:aws:ssm:$REGION:$ACCOUNT_ID:document/$PROBE_DOCUMENT"
if exists ssm describe-document --name "$PROBE_DOCUMENT" --region "$REGION"; then
  current=$(query ssm get-document --name "$PROBE_DOCUMENT" --document-format JSON --region "$REGION" --query Content --output text) || die "get-document failed"
  if [ "$(printf '%s' "$current" | squeeze)" = "$(squeeze < "$WORK/probe-document.json")" ]; then
    note "up to date ($PROBE_VERSION): $DOC_ARN"
  elif aws_admin ssm update-document --name "$PROBE_DOCUMENT" --content "file://$WORK/probe-document.json" --document-version '$LATEST' --document-format JSON --region "$REGION" >/dev/null 2>"$WORK/err"; then
    latest=$(aws_admin ssm describe-document --name "$PROBE_DOCUMENT" --region "$REGION" --query Document.LatestVersion --output text)
    aws_admin ssm update-document-default-version --name "$PROBE_DOCUMENT" --document-version "$latest" --region "$REGION" >/dev/null
    note "updated to version $latest ($PROBE_VERSION): $DOC_ARN"
  elif grep -q DuplicateDocumentContent "$WORK/err"; then
    note "already up to date ($PROBE_VERSION): $DOC_ARN"
  else
    die "update-document failed: $(cat "$WORK/err")"
  fi
else
  run ssm create-document --name "$PROBE_DOCUMENT" --document-type Command --document-format JSON --content "file://$WORK/probe-document.json" --region "$REGION" --tags Key=app,Value=aws-advisor
  note "created $DOC_ARN ($PROBE_VERSION)"
fi`,
  };
}

function advisorSettingsStep(o: SetupOptions): SetupStep {
  if (o.path === "laptop-key") {
    return {
      title: `Point the advisor (${o.advisorUrl}) at profile ${o.profileName} and test it`,
      detail: `PUT /api/settings/aws { mode: "profile", profile: "${o.profileName}", regions: ["*"], defaultRegion: "${o.region}" }: the advisor writes profile = "${o.profileName}" into its Steampipe connection and tests both Steampipe and its own SDK identity. No key is ever sent to it.`,
      bash: `
BODY='{"mode":"profile","profile":"'"$PROFILE_NAME"'","regions":["*"],"defaultRegion":"'"$REGION"'"}'
note "settings: mode AWS profile, profile $PROFILE_NAME, regions *, default region $REGION"
if [ "$DRY_RUN" = 1 ]; then
  printf '    + %s\\n' "curl -fsS -X PUT '$ADVISOR_URL/api/settings/aws' -H 'content-type: application/json' $TOKEN_HINT-d '$BODY'"
else
  advisor_reachable || die "the advisor at $ADVISOR_URL does not answer. Start it, or open Settings > AWS credentials > AWS profile and enter: profile $PROFILE_NAME, regions *, default region $REGION."
  resp=$(advisor_call PUT /api/settings/aws "$BODY") || die "PUT $ADVISOR_URL/api/settings/aws failed: $resp"
  if ! summarize_settings "$resp"; then
    die "the advisor saved the settings but the connection test failed (see above). Fix the cause and rerun this script (it is safe to rerun)."
  fi
  ADVISOR_OK=1
fi`,
    };
  }
  return {
    title: "Advisor settings: Instance / default chain assuming the role",
    detail: `The values for Settings > AWS credentials on the host: mode Instance / default chain, role arn:aws:iam::<account>:role/${o.roleName}, credential source Ec2InstanceMetadata, default region ${o.region}. When ${o.advisorUrl} is reachable they are saved and tested through PUT /api/settings/aws.`,
    bash: `
BODY='{"mode":"chain","credentialSource":"Ec2InstanceMetadata","roleArn":"'"$ROLE_ARN"'","regions":["*"],"defaultRegion":"'"$REGION"'"}'
note "settings for Settings > AWS credentials > Instance / default chain:"
note "  role to assume:     $ROLE_ARN"
note "  credential source:  Ec2InstanceMetadata"
note "  regions / default:  * / $REGION"
note "chain mode only works when the advisor runs ON the instance: its base credentials come from the instance metadata service."
if [ "$DRY_RUN" = 1 ]; then
  printf '    + %s\\n' "curl -fsS -X PUT '$ADVISOR_URL/api/settings/aws' -H 'content-type: application/json' $TOKEN_HINT-d '$BODY'"
elif advisor_reachable; then
  resp=$(advisor_call PUT /api/settings/aws "$BODY") || die "PUT $ADVISOR_URL/api/settings/aws failed: $resp"
  if summarize_settings "$resp"; then
    ADVISOR_OK=1
  else
    warn "the settings are saved but the test failed. If the advisor at $ADVISOR_URL is not running on $INSTANCE_LABEL that is expected: chain mode needs the instance credentials. Run the advisor there and press 'Test again' in Settings."
  fi
else
  note "the advisor at $ADVISOR_URL is not reachable from here: enter the values above in Settings on the host, or run there:"
  printf '    %s\\n' "curl -fsS -X PUT '$ADVISOR_URL/api/settings/aws' -H 'content-type: application/json' $TOKEN_HINT-d '$BODY'"
fi`,
  };
}

function permissionCheckStep(o: SetupOptions): SetupStep {
  return {
    title: "Run the advisor's permission check",
    detail: "POST /api/permissions/check: one cheap probe per capability with the new identity; prints ok/missing counts and any missing action (takes up to a minute).",
    bash: `
if [ "$DRY_RUN" = 1 ]; then
  printf '    + %s\\n' "curl -fsS -X POST '$ADVISOR_URL/api/permissions/check' -H 'content-type: application/json' $TOKEN_HINT-d '{}'"
elif [ "$ADVISOR_OK" = 1 ]; then
  note "checking (up to a minute)..."
  resp=$(advisor_call POST /api/permissions/check '{}') || die "POST $ADVISOR_URL/api/permissions/check failed: $resp"
  summarize_check "$resp" || warn "some capabilities are not ok: see Settings > Permissions for the detail and the policy that fixes it"
else
  note "skipped: the advisor was not configured from here (see the previous step)${o.path === "ec2-role" ? "; on the host, Settings > Permissions > Check permissions does the same" : ""}"
fi`,
  };
}

/** The ordered steps for the options (the plan and the script share them). */
export function setupSteps(o: SetupOptions, d: SetupDocuments = defaultSetupDocuments()): SetupStep[] {
  if (o.path === "laptop-key") {
    return [detectStep(o), userStep(o), readRoleStep(o), rolePolicyStep(o), userPolicyStep(o), accessKeyStep(o), profileStep(o), verifyStep(o), probeDocumentStep(o, d), advisorSettingsStep(o), permissionCheckStep(o)];
  }
  return [
    detectStep(o), instanceRoleStep(o), ssmCoreStep(o), readRoleStep(o), rolePolicyStep(o), instanceAssumeStep(o),
    ...(o.instanceId ? [associateStep(o), hopLimitStep(o)] : []),
    probeDocumentStep(o, d), advisorSettingsStep(o), permissionCheckStep(o),
  ];
}

/** The human-readable plan: step titles and one-line explanations, numbered as the script prints them. */
export function renderSetupPlan(o: SetupOptions, d: SetupDocuments = defaultSetupDocuments()): { title: string; detail: string }[] {
  return setupSteps(o, d).map(({ title, detail }) => ({ title, detail }));
}

// ---- the script ---------------------------------------------------------------------------------------------------

function embeddedDocuments(o: SetupOptions, d: SetupDocuments): string {
  const principalArn = o.path === "laptop-key" ? `arn:aws:iam::${ACCOUNT_PLACEHOLDER}:user/${o.userName}` : `arn:aws:iam::${ACCOUNT_PLACEHOLDER}:role/${o.instanceRoleName}`;
  const trust = { Version: "2012-10-17", Statement: [{ Sid: o.path === "laptop-key" ? "AdvisorUser" : "AdvisorHost", Effect: "Allow", Principal: { AWS: principalArn }, Action: "sts:AssumeRole" }] };
  const assume = { Version: "2012-10-17", Statement: [{ Effect: "Allow", Action: "sts:AssumeRole", Resource: `arn:aws:iam::${ACCOUNT_PLACEHOLDER}:role/${o.roleName}` }] };
  const ec2Trust = { Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: { Service: "ec2.amazonaws.com" }, Action: "sts:AssumeRole" }] };
  const heredoc = (name: string, obj: object) => `${name}=$(cat <<'JSON'\n${JSON.stringify(obj, null, 2)}\nJSON\n)`;
  return [
    `# The advisor's recommended read-only policy (GET /api/permissions -> recommended_policy); ${ACCOUNT_PLACEHOLDER} is filled in at run time.`,
    heredoc("POLICY_JSON", d.policy),
    "",
    "# Trust policy of the read-only role: who may assume it.",
    heredoc("TRUST_JSON", trust),
    "",
    "# The assume-only policy: the single permission the key (or the instance role) holds.",
    heredoc("ASSUME_JSON", assume),
    ...(o.path === "ec2-role" ? ["", "# Trust policy of the instance role: EC2 itself.", heredoc("EC2_TRUST_JSON", ec2Trust)] : []),
    "",
    `# The SSM Command document that embeds the fixed probe script (GET /api/probe/document, ${d.probeVersion}).`,
    heredoc("PROBE_DOCUMENT_JSON", d.probeDocument),
  ].join("\n");
}

const HELPERS = `
# ---- helpers ------------------------------------------------------------------------------------------------------
note() { printf '    %s\\n' "$*"; }
warn() { printf '    WARNING: %s\\n' "$*" >&2; }
die()  { printf '\\nERROR: %s\\n' "$*" >&2; exit 1; }
STEP=0
step() { STEP=$((STEP + 1)); printf '\\n==> step %d/%d: %s\\n' "$STEP" "$TOTAL_STEPS" "$1"; }

# Prints its arguments shell-quoted, for the dry-run lines.
fmt() {
  local out="" a
  for a in "$@"; do
    case "$a" in
      *[!A-Za-z0-9_./:=@,+-]*|"") out="$out '$(printf '%s' "$a" | sed "s/'/'\\\\''/g")'" ;;
      *) out="$out $a" ;;
    esac
  done
  printf '%s' "\${out# }"
}

# aws with the admin profile. Never used for \`aws configure\`, whose --profile is the profile being written.
aws_admin() {
  if [ -n "$ADMIN_PROFILE" ]; then aws --profile "$ADMIN_PROFILE" "$@"; else aws "$@"; fi
}
# The same call as one printable line, for the dry run.
fmt_admin() {
  if [ -n "$ADMIN_PROFILE" ]; then fmt aws --profile "$ADMIN_PROFILE" "$@"; else fmt aws "$@"; fi
}
# A command that changes something: run (stdout discarded), or printed in a dry run.
run() {
  if [ "$DRY_RUN" = 1 ]; then printf '    + %s\\n' "$(fmt_admin "$@")"; return 0; fi
  if aws_admin "$@" >/dev/null 2>"$WORK/err"; then return 0; fi
  die "$(fmt_admin "$@") failed: $(cat "$WORK/err")"
}
# A read-only call whose output the script needs. Dry run: printed (to stderr, so it is not captured), outputs nothing.
query() {
  if [ "$DRY_RUN" = 1 ]; then printf '    + (query) %s\\n' "$(fmt_admin "$@")" >&2; return 0; fi
  aws_admin "$@"
}
# exists <aws args>: 0 when the resource exists, 1 when AWS says it does not, abort on any other error. Dry run: 1.
exists() {
  if [ "$DRY_RUN" = 1 ]; then printf '    + (check) %s\\n' "$(fmt_admin "$@")"; return 1; fi
  if aws_admin "$@" >/dev/null 2>"$WORK/err"; then return 0; fi
  case "$(cat "$WORK/err")" in
    *NoSuchEntity*|*InvalidDocument*|*NotFound*|*"does not exist"*|*InvalidInstanceID*) return 1 ;;
  esac
  die "$(fmt_admin "$@") failed: $(cat "$WORK/err")"
}
# aws configure set on the profile the script writes (no admin profile here).
configure_set() {
  if [ "$DRY_RUN" = 1 ]; then printf '    + %s\\n' "$(fmt aws configure set --profile "$1" "$2" "$3")"; return 0; fi
  aws configure set --profile "$1" "$2" "$3"
}
# Whitespace-insensitive comparison of two JSON documents.
squeeze() { tr -d ' \\t\\r\\n'; }

# Writes the embedded documents with the account id filled in.
write_documents() {
  printf '%s\\n' "$POLICY_JSON" | sed "s/<ACCOUNT_ID>/$ACCOUNT_ID/g" > "$WORK/policy.json"
  printf '%s\\n' "$TRUST_JSON" | sed "s/<ACCOUNT_ID>/$ACCOUNT_ID/g" > "$WORK/trust.json"
  printf '%s\\n' "$ASSUME_JSON" | sed "s/<ACCOUNT_ID>/$ACCOUNT_ID/g" > "$WORK/assume.json"
  [ -z "\${EC2_TRUST_JSON:-}" ] || printf '%s\\n' "$EC2_TRUST_JSON" > "$WORK/ec2-trust.json"
  printf '%s\\n' "$PROBE_DOCUMENT_JSON" > "$WORK/probe-document.json"
  PRINCIPAL_ARN=$(printf '%s' "$PRINCIPAL_ARN" | sed "s/<ACCOUNT_ID>/$ACCOUNT_ID/g")
  [ "$DRY_RUN" = 1 ] && note "documents written to $WORK (policy.json, trust.json, assume.json, probe-document.json); kept after the dry run for inspection"
  true
}

# ensure_trust ROLE PRINCIPAL_ARN SID: the role's trust policy gets a statement letting PRINCIPAL_ARN assume it,
# unless it already names that principal. Existing statements are kept (one with the same Sid is replaced).
ensure_trust() {
  local role="$1" principal="$2" sid="$3" current
  current=$(query iam get-role --role-name "$role" --query Role.AssumeRolePolicyDocument --output json) || die "get-role $role failed"
  [ "$DRY_RUN" = 1 ] || [ -n "$current" ] || die "get-role $role returned no trust policy"
  if [ "$DRY_RUN" = 1 ]; then
    printf '    + %s\\n' "$(fmt_admin iam update-assume-role-policy --role-name "$role" --policy-document "file://$WORK/trust-$role.json")   (only if $principal is not trusted yet)"
    return 0
  fi
  if printf '%s' "$current" | grep -q "\\"$principal\\""; then
    note "trust policy of $role already allows $principal"
    return 0
  fi
  command -v python3 >/dev/null 2>&1 || die "python3 is needed to merge $principal into the existing trust policy of $role. Add this statement by hand and rerun: {\\"Sid\\":\\"$sid\\",\\"Effect\\":\\"Allow\\",\\"Principal\\":{\\"AWS\\":\\"$principal\\"},\\"Action\\":\\"sts:AssumeRole\\"}"
  printf '%s' "$current" | python3 -c '
import json, sys
doc = json.load(sys.stdin)
principal, sid = sys.argv[1], sys.argv[2]
st = doc.get("Statement", [])
if isinstance(st, dict): st = [st]
st = [s for s in st if s.get("Sid") != sid]
st.append({"Sid": sid, "Effect": "Allow", "Principal": {"AWS": principal}, "Action": "sts:AssumeRole"})
doc["Statement"] = st
json.dump(doc, sys.stdout, indent=2)
' "$principal" "$sid" > "$WORK/trust-$role.json"
  run iam update-assume-role-policy --role-name "$role" --policy-document "file://$WORK/trust-$role.json"
  note "added $principal to the trust policy of $role (existing principals kept)"
}

# ---- the advisor's API ----------------------------------------------------------------------------------------------
advisor_reachable() { curl -fsS -m 10 "$ADVISOR_URL/health" >/dev/null 2>&1; }
# advisor_call METHOD PATH BODY: prints the response body; fails (printing the body) on an HTTP error.
advisor_call() {
  local method="$1" path="$2" body="$3" out code
  local -a hdr=()
  if [ -n "$API_TOKEN" ]; then hdr=(-H "x-api-token: $API_TOKEN" -H "authorization: Bearer $API_TOKEN"); fi
  out=$(curl -sS -m 180 -X "$method" "$ADVISOR_URL$path" -H 'content-type: application/json' \${hdr[@]+"\${hdr[@]}"} --data "$body" -w '\\n%{http_code}') || { printf '%s' "$out"; return 1; }
  code=\${out##*$'\\n'}
  out=\${out%$'\\n'*}
  printf '%s' "$out"
  case "$code" in 2*) return 0 ;; esac
  return 1
}
# The PUT /api/settings/aws answer: what Steampipe and the SDK said. Fails when the test failed.
summarize_settings() {
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$1" <<'PY'
import json, sys
r = json.loads(sys.argv[1])
t, s = r.get("test") or {}, r.get("sdk") or {}
print("    Steampipe: " + ("connected to account %s" % t.get("accountId") if t.get("ok") else "FAILED: %s" % t.get("error")))
print("    SDK:       " + (("%s" % s.get("arn")) if s.get("ok") else "FAILED: %s" % s.get("error")))
sys.exit(0 if t.get("ok") and s.get("ok", True) else 1)
PY
  else
    printf '    %s\\n' "$1"
    case "$1" in *'"test":{"ok":true'*) return 0 ;; esac
    return 1
  fi
}
# The POST /api/permissions/check answer: counts per status and the missing actions. Fails when anything is missing.
summarize_check() {
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$1" <<'PY'
import json, sys
r = json.loads(sys.argv[1])
res = r.get("results") or []
counts = {}
for x in res: counts[x.get("status")] = counts.get(x.get("status"), 0) + 1
print("    account %s, region %s: %d ok, %d missing, %d error, %d skipped (%s ms)" % (r.get("account_id"), r.get("region"), counts.get("ok", 0), counts.get("missing", 0), counts.get("error", 0), counts.get("skipped", 0), r.get("took_ms")))
if r.get("credentials_error"): print("    credentials: %s" % r["credentials_error"])
for x in res:
    if x.get("status") in ("missing", "error"): print("    %s %s: %s" % (x["status"], x.get("label"), (x.get("message") or "")[:200]))
if r.get("missing"): print("    missing actions: %s" % ", ".join(r["missing"]))
sys.exit(1 if r.get("missing") or r.get("credentials_error") else 0)
PY
  else
    printf '    %s\\n' "$1"
    case "$1" in *'"missing":[]'*) return 0 ;; esac
    return 1
  fi
}
`;

/** The complete script for the options. */
export function renderSetupScript(o: SetupOptions, d: SetupDocuments = defaultSetupDocuments()): string {
  const steps = setupSteps(o, d);
  const plan = steps.map((s, i) => `#   ${i + 1}. ${s.title}`).join("\n");
  const sourceProfile = `${o.userName}-user`;
  const principalArn = o.path === "laptop-key" ? `arn:aws:iam::${ACCOUNT_PLACEHOLDER}:user/${o.userName}` : `arn:aws:iam::${ACCOUNT_PLACEHOLDER}:role/${o.instanceRoleName}`;
  const header = `#!/usr/bin/env bash
# aws-advisor setup (${o.path === "laptop-key" ? "laptop / server with a long-lived key" : "EC2 host with an instance role"}), generated by ${o.advisorUrl} on ${new Date().toISOString().slice(0, 10)}.
#
# Runs the README's onboarding end to end with the admin credentials of THIS terminal (the advisor never gets
# them): it only ever receives the profile name / role ARN through its API. Every step checks what exists and
# skips or updates it, so rerunning is safe.${o.dryRun ? "\n#\n# THIS COPY IS A DRY RUN: it prints every command instead of running it (no AWS call is made). Fetch it\n# without dryRun=1, or run it with --dry-run removed, to apply." : ""}
#
# What it does:
${plan}
#
# Options: --dry-run (print the commands, change nothing), --api-token TOKEN (or ADVISOR_API_TOKEN in the
# environment: the advisor's API_TOKEN or a token minted by it, when the API is protected), --advisor-url URL.
# Needs: aws (v2), curl; python3 for the trust-policy merge and readable summaries (optional otherwise).
set -euo pipefail

PATH_KIND=${sq(o.path)}
USER_NAME=${sq(o.userName)}
ROLE_NAME=${sq(o.roleName)}
PROFILE_NAME=${sq(o.profileName)}
SOURCE_PROFILE=${sq(sourceProfile)}
REGION=${sq(o.region)}
INSTANCE_ROLE_NAME=${sq(o.instanceRoleName)}
INSTANCE_ID=${sq(o.instanceId || "")}
INSTANCE_LABEL=${sq(o.instanceId || "the EC2 host")}
ADVISOR_URL=${sq(o.advisorUrl)}
ADMIN_PROFILE=${sq(o.adminProfile || "")}
PROBE_DOCUMENT=${sq(d.probeDocumentName)}
PROBE_VERSION=${sq(d.probeVersion)}
ASSUME_POLICY_NAME=${sq(o.path === "laptop-key" ? `${o.userName}-assume` : "aws-advisor-assume")}
PRINCIPAL_ARN=${sq(principalArn)}
PRINCIPAL_SID=${sq(o.path === "laptop-key" ? "AdvisorUser" : "AdvisorHost")}
SSM_CORE_POLICY='arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore'
TOTAL_STEPS=${steps.length}
DRY_RUN=${o.dryRun ? 1 : 0}
API_TOKEN="\${ADVISOR_API_TOKEN:-}"
ADVISOR_OK=0
ACCOUNT_ID=""
CALLER_ARN=""
ROLE_ARN=""

usage() {
  sed -n '2,/^set -euo/p' "$0" | grep '^#' | sed 's/^# \\{0,1\\}//'
}
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    --api-token) shift; API_TOKEN="\${1:-}" ;;
    --api-token=*) API_TOKEN="\${1#--api-token=}" ;;
    --advisor-url) shift; ADVISOR_URL="\${1:-}" ;;
    --advisor-url=*) ADVISOR_URL="\${1#--advisor-url=}" ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'unknown option: %s\\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done
ADVISOR_URL="\${ADVISOR_URL%/}"
TOKEN_HINT=""
[ -z "$API_TOKEN" ] || TOKEN_HINT="-H 'x-api-token: ***' "

tmpbase="\${TMPDIR:-/tmp}"
WORK=$(mktemp -d "\${tmpbase%/}/aws-advisor-setup.XXXXXX")
cleanup() { [ "$DRY_RUN" = 1 ] || rm -rf "$WORK"; }
trap cleanup EXIT
`;

  const body = steps.map((s) => `step ${sq(s.title)}${s.bash.replace(/^\n/, "\n")}`).join("\n\n");
  const footer = o.path === "laptop-key"
    ? `
printf '\\n'
if [ "$DRY_RUN" = 1 ]; then
  printf '%s\\n' "Dry run complete: nothing was changed. Run the script without --dry-run (or fetch it without dryRun=1) to apply."
else
  printf '%s\\n' "Done. The advisor at $ADVISOR_URL uses profile $PROFILE_NAME (account $ACCOUNT_ID), which assumes $ROLE_ARN with the key stored under [$SOURCE_PROFILE]."
  printf '%s\\n' "The key can do nothing on its own; cut it off any time with: aws iam update-assume-role-policy --role-name $ROLE_NAME (without the user) or aws iam delete-access-key --user-name $USER_NAME --access-key-id <id>."
fi
`
    : `
printf '\\n'
if [ "$DRY_RUN" = 1 ]; then
  printf '%s\\n' "Dry run complete: nothing was changed. Run the script without --dry-run (or fetch it without dryRun=1) to apply."
else
  printf '%s\\n' "Done. Role $ROLE_ARN trusts instance role $INSTANCE_ROLE_NAME; a host running with instance profile $INSTANCE_ROLE_NAME assumes it with no secret anywhere."
  printf '%s\\n' "On the host: Settings > AWS credentials > Instance / default chain, role $ROLE_ARN, credential source Ec2InstanceMetadata (the script did this when $ADVISOR_URL was reachable)."
  [ -n "$INSTANCE_ID" ] || printf '%s\\n' "To attach the instance profile to an instance and set its IMDS hop limit, rerun with instanceId=i-... or: aws ec2 associate-iam-instance-profile --instance-id i-... --iam-instance-profile Name=$INSTANCE_ROLE_NAME; aws ec2 modify-instance-metadata-options --instance-id i-... --http-put-response-hop-limit 2"
fi
`;
  return `${header}\n${embeddedDocuments(o, d)}\n${HELPERS}\n# ---- steps ----------------------------------------------------------------------------------------------------------\n${body}\n${footer}`;
}

/** The query string the wizard's command and download link carry (only what differs from the defaults, plus path). */
export function setupQuery(o: SetupOptions, extra: Record<string, string | undefined> = {}): string {
  const q = new URLSearchParams();
  q.set("path", o.path);
  if (o.userName !== SETUP_DEFAULTS.userName) q.set("user", o.userName);
  if (o.roleName !== SETUP_DEFAULTS.roleName) q.set("role", o.roleName);
  if (o.path === "laptop-key" && o.profileName !== SETUP_DEFAULTS.profileName) q.set("profile", o.profileName);
  if (o.region !== SETUP_DEFAULTS.region) q.set("region", o.region);
  if (o.path === "ec2-role" && o.instanceRoleName !== SETUP_DEFAULTS.instanceRoleName) q.set("instanceRole", o.instanceRoleName);
  if (o.path === "ec2-role" && o.instanceId) q.set("instanceId", o.instanceId);
  if (o.adminProfile) q.set("adminProfile", o.adminProfile);
  if (o.dryRun) q.set("dryRun", "1");
  for (const [k, v] of Object.entries(extra)) if (v) q.set(k, v);
  return q.toString();
}

/** The one-liners the wizard shows: download-read-run, and the piped variant. */
export function setupCommands(o: SetupOptions, token?: string): { command: string; piped: string; scriptUrl: string } {
  // The advisor URL in the query only when it is not the one the script is fetched from (it defaults to the request's origin).
  const scriptUrl = `${o.advisorUrl}/api/setup/script?${setupQuery(o, { token })}`;
  const env = token ? `ADVISOR_API_TOKEN=${sq(token)} ` : "";
  return {
    scriptUrl,
    command: `curl -fsSL "${scriptUrl}" -o aws-advisor-setup.sh && less aws-advisor-setup.sh && ${env}bash aws-advisor-setup.sh`,
    piped: `curl -fsSL "${scriptUrl}" | ${env}bash`,
  };
}

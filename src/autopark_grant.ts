/**
 * Auto-park grants: the actuator role may stop and start an EC2 instance only when a person said so, for that one
 * instance. Switching Auto-park on is done with the person's own credentials ("Run as me"): it writes the
 * AdvisorAutoPark tag and adds the instance to a customer-managed policy attached to the actuator role,
 * /aws-advisor/AdvisorAutoParkInstances (created and attached on the first grant):
 *
 *   AutoParkStartStop  ec2:StartInstances, ec2:StopInstances  on exactly the granted instances
 *
 * A managed policy, not an inline one: a role's inline policies share 10,240 characters and the actuator policy
 * itself, pasted inline, already uses about 9,000 of them. A managed policy has 6,144 of its own; each instance is
 * one ARN with the region as `*` (instance ids do not repeat; the account stays fixed), so it holds about 100. A
 * grant that would not fit is refused before AWS refuses it. Every change is a new default version; AWS keeps five,
 * so the oldest is deleted first. The parked marker (advisor:parked) is in the static actuator policy: a label, it
 * opens nothing.
 *
 * Switching it off (or reverting the row) removes the instance; with none left the policy is detached and deleted.
 * The actuator has no IAM write right, so it can never grant itself an instance, and no tag it can write opens a stop
 * or a start. Whether an instance is granted is read with iam:SimulatePrincipalPolicy, which the advisor's read
 * identity already holds, so the answer covers every policy on the role, not only this one.
 */
import {
  AttachRolePolicyCommand, CreatePolicyCommand, CreatePolicyVersionCommand, DeletePolicyCommand, DeletePolicyVersionCommand, DetachRolePolicyCommand,
  GetPolicyCommand, GetPolicyVersionCommand, IAMClient, ListPolicyVersionsCommand, SimulatePrincipalPolicyCommand,
} from "@aws-sdk/client-iam";
import type { AwsCredentialIdentityProvider } from "@aws-sdk/types";

export const AUTOPARK_POLICY = "AdvisorAutoParkInstances";
export const PARKED_MARKER = "advisor:parked";

/** The instance's ARN as AWS names it (what IAM is asked about). */
export const instanceArn = (region: string, account: string, instanceId: string) => `arn:aws:ec2:${region}:${account}:instance/${instanceId}`;
/** The same instance as the policy lists it: any region, its account. Pure. */
export const grantArn = (arn: string) => { const m = /^arn:(aws[a-z-]*):ec2:[^:]*:(\d{12}):instance\/(i-[0-9a-f]+)$/.exec(arn); return m ? `arn:${m[1]}:ec2:*:${m[2]}:instance/${m[3]}` : arn; };
/** A managed policy's size limit (AWS: 6,144 characters, whitespace not counted), and the margin kept under it. */
export const MANAGED_POLICY_LIMIT = 6_144;
export const LIMIT_MARGIN = 128;
export const POLICY_PATH = "/aws-advisor/";
/** The grant policy's ARN in an account. */
export const grantPolicyArn = (account: string) => `arn:aws:iam::${account}:policy${POLICY_PATH}${AUTOPARK_POLICY}`;
/** AWS keeps at most five versions of a managed policy. */
export const MAX_VERSIONS = 5;
export const roleNameOf = (roleArn: string) => roleArn.split("/").pop() || roleArn;
export const accountOfArn = (arn: string) => arn.split(":")[4] || "";

/** The inline policy for these instance ARNs, or null when there are none (the policy is then deleted). Pure. */
export function grantDocument(arns: string[]): Record<string, unknown> | null {
  const list = [...new Set(arns.map(grantArn))].sort();
  if (!list.length) return null;
  return { Version: "2012-10-17", Statement: [{ Sid: "AutoParkStartStop", Effect: "Allow", Action: ["ec2:StartInstances", "ec2:StopInstances"], Resource: list }] };
}

/** How many characters a policy document counts for (AWS ignores whitespace; compact JSON has none). Pure. */
export const policySize = (doc: unknown) => (doc ? JSON.stringify(doc).length : 0);

/** The instance ARNs an existing policy document grants. Pure. */
export function grantedArnsOf(doc: any): string[] {
  const st = (Array.isArray(doc?.Statement) ? doc.Statement : [doc?.Statement]).find((s: any) => s?.Sid === "AutoParkStartStop");
  const r = st?.Resource;
  return (Array.isArray(r) ? r : r ? [r] : []).map(String).filter((x: string) => /^arn:aws[a-z-]*:ec2:[^:]*:\d{12}:instance\/i-[0-9a-f]+$/.test(x)).map(grantArn);
}

/** The policy after adding or removing one ARN. Pure. */
export function withArn(current: string[], arn: string, on: boolean): string[] {
  const set = new Set(current.map(grantArn));
  if (on) set.add(grantArn(arn)); else set.delete(grantArn(arn));
  return [...set].sort();
}

/** Why a grant document cannot be the policy's new version; null when it fits. Pure. */
export function sizeProblem(doc: unknown, instances: number): string | null {
  const size = policySize(doc);
  if (size <= MANAGED_POLICY_LIMIT - LIMIT_MARGIN) return null;
  return `the grant would be ${size} characters for ${instances} instances, and a managed policy holds ${MANAGED_POLICY_LIMIT}: switch Auto-park off on an instance that no longer needs it first`;
}

/** The versions to delete before adding one, oldest first, never the default. Pure. */
export function versionsToPrune(versions: { VersionId?: string; IsDefaultVersion?: boolean; CreateDate?: Date }[], max = MAX_VERSIONS): string[] {
  const old = versions.filter((v) => !v.IsDefaultVersion && v.VersionId).sort((a, b) => (a.CreateDate?.getTime() ?? 0) - (b.CreateDate?.getTime() ?? 0));
  const excess = versions.length - (max - 1);
  return excess > 0 ? old.slice(0, excess).map((v) => v.VersionId!) : [];
}

const iamClient = (credentials: AwsCredentialIdentityProvider) => new IAMClient({ region: "us-east-1", credentials });

const notFound = (e: any) => e?.name === "NoSuchEntityException" || e?.name === "NoSuchEntity";

/** The instances the policy grants now (its default version), or null when the policy does not exist. */
async function readGrant(iam: IAMClient, policyArn: string): Promise<string[] | null> {
  try {
    const p = (await iam.send(new GetPolicyCommand({ PolicyArn: policyArn }))).Policy;
    if (!p?.DefaultVersionId) return [];
    const v = (await iam.send(new GetPolicyVersionCommand({ PolicyArn: policyArn, VersionId: p.DefaultVersionId }))).PolicyVersion;
    return grantedArnsOf(JSON.parse(decodeURIComponent(v?.Document || "{}")));
  } catch (e: any) { if (notFound(e)) return null; throw e; }
}

/**
 * Adds (on) or removes one instance from the actuator role's grant, with the credentials given (a person's: the
 * actuator cannot). Returns a line for the ledger.
 */
export async function setGrant(credentials: AwsCredentialIdentityProvider, roleArn: string, arn: string, on: boolean): Promise<string> {
  const role = roleNameOf(roleArn);
  const policyArn = grantPolicyArn(accountOfArn(roleArn));
  const iam = iamClient(credentials);
  const id = arn.split("/").pop();
  try {
    const existing = await readGrant(iam, policyArn);
    const before = existing ?? [];
    const after = withArn(before, arn, on);
    const same = after.length === before.length && after.every((x, i) => x === before[i]);
    if (same && (existing != null || !on)) {
      // the policy may exist without being attached (a half-done earlier run): attaching is idempotent
      if (on && after.length) await iam.send(new AttachRolePolicyCommand({ RoleName: role, PolicyArn: policyArn }));
      return `${AUTOPARK_POLICY}: ${on ? "already grants" : "did not grant"} ${id}`;
    }
    const doc = grantDocument(after);
    if (!doc) {
      // the last instance left: detach, delete the old versions, delete the policy
      try { await iam.send(new DetachRolePolicyCommand({ RoleName: role, PolicyArn: policyArn })); } catch (e: any) { if (!notFound(e)) throw e; }
      const versions = (await iam.send(new ListPolicyVersionsCommand({ PolicyArn: policyArn }))).Versions ?? [];
      for (const v of versions) if (!v.IsDefaultVersion && v.VersionId) await iam.send(new DeletePolicyVersionCommand({ PolicyArn: policyArn, VersionId: v.VersionId }));
      await iam.send(new DeletePolicyCommand({ PolicyArn: policyArn }));
      return `${AUTOPARK_POLICY}: revoked stop/start on ${id}; no instance left, the policy is detached from ${role} and deleted`;
    }
    const problem = on ? sizeProblem(doc, after.length) : null;
    if (problem) throw new Error(`not granted: ${problem}`);
    if (existing == null) {
      await iam.send(new CreatePolicyCommand({ PolicyName: AUTOPARK_POLICY, Path: POLICY_PATH, PolicyDocument: JSON.stringify(doc), Description: "aws-advisor: the instances a person switched Auto-park on for; the actuator may stop and start these and no others" }));
    } else {
      const versions = (await iam.send(new ListPolicyVersionsCommand({ PolicyArn: policyArn }))).Versions ?? [];
      for (const v of versionsToPrune(versions)) await iam.send(new DeletePolicyVersionCommand({ PolicyArn: policyArn, VersionId: v }));
      await iam.send(new CreatePolicyVersionCommand({ PolicyArn: policyArn, PolicyDocument: JSON.stringify(doc), SetAsDefault: true }));
    }
    await iam.send(new AttachRolePolicyCommand({ RoleName: role, PolicyArn: policyArn }));
    return `${AUTOPARK_POLICY}: ${on ? "granted" : "revoked"} stop/start on ${id} (${after.length} instance${after.length === 1 ? "" : "s"} granted, attached to ${role})`;
  } finally { iam.destroy(); }
}

export interface GrantCheck { granted: boolean | null; detail: string }

/** Whether the actuator role may stop and start this instance, as IAM sees every policy on the role (null: could not tell). */
export async function checkGrant(credentials: AwsCredentialIdentityProvider, roleArn: string, arn: string): Promise<GrantCheck> {
  if (!roleArn) return { granted: null, detail: "no actuator role configured for this account" };
  const iam = iamClient(credentials);
  try {
    const r = await iam.send(new SimulatePrincipalPolicyCommand({ PolicySourceArn: roleArn, ActionNames: ["ec2:StopInstances", "ec2:StartInstances"], ResourceArns: [arn] }));
    const results = r.EvaluationResults ?? [];
    const allowed = results.filter((x) => x.EvalDecision === "allowed").length;
    return { granted: allowed === 2, detail: allowed === 2 ? "the actuator may stop and start it" : allowed === 1 ? "the actuator may only do one of stop and start" : "the actuator may not stop or start it" };
  } catch (e: any) { return { granted: null, detail: `could not ask IAM (${e?.name || "error"}: ${String(e?.message || e).slice(0, 120)})` }; }
  finally { iam.destroy(); }
}

/** A refused stop or start explained: the instance has no grant yet. */
export function explainRefusal(e: any, instanceId: string): Error {
  const m = String(e?.message || e);
  if (/UnauthorizedOperation|AccessDenied|not authorized/i.test(`${e?.name} ${m}`)) return new Error(`the actuator role may not stop or start ${instanceId}: switch Auto-park on with "Run as me", which grants this one instance (${m.slice(0, 160)})`);
  return e instanceof Error ? e : new Error(m);
}

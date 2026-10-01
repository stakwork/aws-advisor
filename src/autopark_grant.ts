/**
 * Auto-park grants: the actuator role may stop and start an EC2 instance only when a person said so, for that one
 * instance. Switching Auto-park on is done with the person's own credentials ("Run as me"): it writes the
 * AdvisorAutoPark tag and adds the instance's ARN to an inline policy on the actuator role, AUTOPARK_POLICY:
 *
 *   AutoParkStartStop  ec2:StartInstances, ec2:StopInstances           on exactly the granted instances
 *   AutoParkMarker     ec2:CreateTags, ec2:DeleteTags (advisor:parked)  on the same instances
 *
 * Switching it off (or reverting the row) removes the ARN, and the policy itself when it is empty. The actuator has no
 * IAM write rights, so it can never grant itself an instance, and no tag it can write opens a stop or a start (the
 * tag-conditioned statements are gone from src/permissions.ts actuatorPolicy). Whether an instance is granted is read
 * with iam:SimulatePrincipalPolicy, which the advisor's read identity already holds, so the answer covers every policy
 * on the role, not only this one.
 */
import { DeleteRolePolicyCommand, GetRolePolicyCommand, IAMClient, PutRolePolicyCommand, SimulatePrincipalPolicyCommand } from "@aws-sdk/client-iam";
import type { AwsCredentialIdentityProvider } from "@aws-sdk/types";

export const AUTOPARK_POLICY = "AdvisorAutoParkInstances";
export const PARKED_MARKER = "advisor:parked";

export const instanceArn = (region: string, account: string, instanceId: string) => `arn:aws:ec2:${region}:${account}:instance/${instanceId}`;
export const roleNameOf = (roleArn: string) => roleArn.split("/").pop() || roleArn;
export const accountOfArn = (arn: string) => arn.split(":")[4] || "";

/** The inline policy for these instance ARNs, or null when there are none (the policy is then deleted). Pure. */
export function grantDocument(arns: string[]): Record<string, unknown> | null {
  const list = [...new Set(arns)].sort();
  if (!list.length) return null;
  return {
    Version: "2012-10-17",
    Statement: [
      { Sid: "AutoParkStartStop", Effect: "Allow", Action: ["ec2:StartInstances", "ec2:StopInstances"], Resource: list },
      { Sid: "AutoParkMarker", Effect: "Allow", Action: ["ec2:CreateTags", "ec2:DeleteTags"], Resource: list, Condition: { "ForAllValues:StringEquals": { "aws:TagKeys": [PARKED_MARKER] } } },
    ],
  };
}

/** The instance ARNs an existing policy document grants. Pure. */
export function grantedArnsOf(doc: any): string[] {
  const st = (Array.isArray(doc?.Statement) ? doc.Statement : [doc?.Statement]).find((s: any) => s?.Sid === "AutoParkStartStop");
  const r = st?.Resource;
  return (Array.isArray(r) ? r : r ? [r] : []).map(String).filter((x: string) => /^arn:aws[a-z-]*:ec2:[^:]*:\d{12}:instance\/i-[0-9a-f]+$/.test(x));
}

/** The policy after adding or removing one ARN. Pure. */
export function withArn(current: string[], arn: string, on: boolean): string[] {
  const set = new Set(current);
  if (on) set.add(arn); else set.delete(arn);
  return [...set].sort();
}

const iamClient = (credentials: AwsCredentialIdentityProvider) => new IAMClient({ region: "us-east-1", credentials });

async function readGrant(iam: IAMClient, roleName: string): Promise<string[]> {
  try {
    const r = await iam.send(new GetRolePolicyCommand({ RoleName: roleName, PolicyName: AUTOPARK_POLICY }));
    return grantedArnsOf(JSON.parse(decodeURIComponent(r.PolicyDocument || "{}")));
  } catch (e: any) { if (e?.name === "NoSuchEntityException" || e?.name === "NoSuchEntity") return []; throw e; }
}

/**
 * Adds (on) or removes one instance from the actuator role's grant, with the credentials given (a person's: the
 * actuator cannot). Returns a line for the ledger.
 */
export async function setGrant(credentials: AwsCredentialIdentityProvider, roleArn: string, arn: string, on: boolean): Promise<string> {
  const role = roleNameOf(roleArn);
  const iam = iamClient(credentials);
  try {
    const before = await readGrant(iam, role);
    const after = withArn(before, arn, on);
    if (after.length === before.length && after.every((x, i) => x === before[i])) return `${role}/${AUTOPARK_POLICY}: ${on ? "already grants" : "did not grant"} ${arn.split("/").pop()}`;
    const doc = grantDocument(after);
    if (doc) await iam.send(new PutRolePolicyCommand({ RoleName: role, PolicyName: AUTOPARK_POLICY, PolicyDocument: JSON.stringify(doc) }));
    else await iam.send(new DeleteRolePolicyCommand({ RoleName: role, PolicyName: AUTOPARK_POLICY }));
    return `${role}/${AUTOPARK_POLICY}: ${on ? "granted" : "revoked"} stop/start on ${arn.split("/").pop()} (${after.length} instance${after.length === 1 ? "" : "s"} granted)`;
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

/**
 * Auto-park grants: the actuator role may stop and start an EC2 instance only when a person said so, for that one
 * instance. Switching Auto-park on is done with the person's own credentials ("Run as me"): it writes the
 * AdvisorAutoPark tag and adds the instance to a customer-managed policy attached to the actuator role,
 * /aws-advisor/AdvisorAutoParkInstances (created and attached on the first grant):
 *
 *   AutoParkStartStop      ec2:StartInstances, ec2:StopInstances  on exactly the granted instances
 *   AutoParkDns<instance>  route53:ChangeResourceRecordSets      on the zones of that instance's A records, limited by
 *                          condition to UPSERT of A records with exactly those names (a start without an Elastic IP
 *                          re-points them; the hibernation relaunch moves them too). No standing DNS right elsewhere.
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

/** The A records one instance's grant lets the actuator re-point: their hosted zones and names (lowercase, no trailing dot). */
export interface DnsGrant { zones: string[]; names: string[] }
/** DNS grants by instance id. */
export type DnsGrants = Record<string, DnsGrant>;
const DNS_SID = "AutoParkDns";
/** The statement id for an instance's DNS grant (Sids are alphanumeric: the dash of the id goes). Pure. */
export const dnsSid = (instanceId: string) => `${DNS_SID}${instanceId.replace(/[^A-Za-z0-9]/g, "")}`;
const instanceOfSid = (sid: string): string | null => { const m = new RegExp(`^${DNS_SID}i([0-9a-f]{8,17})$`).exec(sid); return m ? `i-${m[1]}` : null; };
export const zoneArn = (zoneId: string) => `arn:aws:route53:::hostedzone/${zoneId.replace(/^\/hostedzone\//, "")}`;
/** A record name as the route53:ChangeResourceRecordSetsNormalizedRecordNames key sees it. Pure. */
export const normalizeName = (name: string) => name.trim().toLowerCase().replace(/\.$/, "");
const statementsOf = (doc: any): any[] => (Array.isArray(doc?.Statement) ? doc.Statement : doc?.Statement ? [doc.Statement] : []);
const uniq = (xs: string[]) => [...new Set(xs)].sort();
/** A DNS grant with its zones and names normalised and sorted, or null when it names nothing. Pure. */
export const normalDns = (g: DnsGrant | null | undefined): DnsGrant | null => {
  const zones = uniq((g?.zones ?? []).map((z) => z.replace(/^\/hostedzone\//, "")).filter(Boolean)), names = uniq((g?.names ?? []).map(normalizeName).filter(Boolean));
  return zones.length && names.length ? { zones, names } : null;
};

/** The policy for these instance ARNs and their DNS grants, or null when there are no instances (the policy is then deleted). Pure. */
export function grantDocument(arns: string[], dns: DnsGrants = {}): Record<string, unknown> | null {
  const list = uniq(arns.map(grantArn));
  if (!list.length) return null;
  const granted = new Set(list.map((a) => a.split("/").pop()!));
  const Statement: Record<string, unknown>[] = [{ Sid: "AutoParkStartStop", Effect: "Allow", Action: ["ec2:StartInstances", "ec2:StopInstances"], Resource: list }];
  for (const id of Object.keys(dns).sort()) {
    const g = normalDns(dns[id]);
    if (!g || !granted.has(id)) continue;
    Statement.push({
      Sid: dnsSid(id), Effect: "Allow", Action: ["route53:ChangeResourceRecordSets"], Resource: g.zones.map(zoneArn),
      Condition: { "ForAllValues:StringEquals": { "route53:ChangeResourceRecordSetsNormalizedRecordNames": g.names, "route53:ChangeResourceRecordSetsRecordTypes": ["A"], "route53:ChangeResourceRecordSetsActions": ["UPSERT"] } },
    });
  }
  return { Version: "2012-10-17", Statement };
}

/** The DNS grants an existing policy document carries, by instance id. Pure. */
export function dnsGrantsOf(doc: any): DnsGrants {
  const out: DnsGrants = {};
  for (const s of statementsOf(doc)) {
    const id = instanceOfSid(String(s?.Sid ?? ""));
    if (!id) continue;
    const r = s.Resource; const names = s?.Condition?.["ForAllValues:StringEquals"]?.["route53:ChangeResourceRecordSetsNormalizedRecordNames"];
    const g = normalDns({ zones: (Array.isArray(r) ? r : r ? [r] : []).map((a: unknown) => String(a).split("/").pop() || ""), names: (Array.isArray(names) ? names : names ? [names] : []).map(String) });
    if (g) out[id] = g;
  }
  return out;
}

/** The DNS grants after setting (or, with null, removing) one instance's. Pure. */
export function withDns(current: DnsGrants, instanceId: string, dns: DnsGrant | null): DnsGrants {
  const out: DnsGrants = {};
  for (const [id, g] of Object.entries(current)) { const n = normalDns(g); if (n && id !== instanceId) out[id] = n; }
  const n = normalDns(dns);
  if (n) out[instanceId] = n;
  return out;
}
const sameDns = (a: DnsGrants, b: DnsGrants) => JSON.stringify(Object.keys(a).sort().map((k) => [k, a[k]])) === JSON.stringify(Object.keys(b).sort().map((k) => [k, b[k]]));

/** How many characters a policy document counts for (AWS ignores whitespace; compact JSON has none). Pure. */
export const policySize = (doc: unknown) => (doc ? JSON.stringify(doc).length : 0);

/** The instance ARNs an existing policy document grants. Pure. */
export function grantedArnsOf(doc: any): string[] {
  const st = statementsOf(doc).find((s: any) => s?.Sid === "AutoParkStartStop");
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

/** What the policy grants now (its default version), or null when the policy does not exist. */
async function readGrant(iam: IAMClient, policyArn: string): Promise<{ arns: string[]; dns: DnsGrants } | null> {
  try {
    const p = (await iam.send(new GetPolicyCommand({ PolicyArn: policyArn }))).Policy;
    if (!p?.DefaultVersionId) return { arns: [], dns: {} };
    const v = (await iam.send(new GetPolicyVersionCommand({ PolicyArn: policyArn, VersionId: p.DefaultVersionId }))).PolicyVersion;
    const doc = JSON.parse(decodeURIComponent(v?.Document || "{}"));
    return { arns: grantedArnsOf(doc), dns: dnsGrantsOf(doc) };
  } catch (e: any) { if (notFound(e)) return null; throw e; }
}

/**
 * Adds (on) or removes one instance from the actuator role's grant, with the credentials given (a person's: the
 * actuator cannot). `dns` is what the instance's DNS statement should say (null: none). Returns a line for the ledger.
 */
export async function setGrant(credentials: AwsCredentialIdentityProvider, roleArn: string, arn: string, on: boolean, dns: DnsGrant | null = null): Promise<string> {
  const role = roleNameOf(roleArn);
  const policyArn = grantPolicyArn(accountOfArn(roleArn));
  const iam = iamClient(credentials);
  const id = arn.split("/").pop()!;
  const dnsLine = on && normalDns(dns) ? ` and A-record UPSERT of ${normalDns(dns)!.names.join(", ")}` : "";
  try {
    const existing = await readGrant(iam, policyArn);
    const before = existing?.arns ?? [];
    const after = withArn(before, arn, on);
    const dnsAfter = withDns(existing?.dns ?? {}, id, on ? dns : null);
    const same = after.length === before.length && after.every((x, i) => x === before[i]) && sameDns(dnsAfter, existing?.dns ?? {});
    if (same && (existing != null || !on)) {
      // the policy may exist without being attached (a half-done earlier run): attaching is idempotent
      if (on && after.length) await iam.send(new AttachRolePolicyCommand({ RoleName: role, PolicyArn: policyArn }));
      return `${AUTOPARK_POLICY}: ${on ? "already grants" : "did not grant"} ${id}${dnsLine}`;
    }
    const doc = grantDocument(after, dnsAfter);
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
      await iam.send(new CreatePolicyCommand({ PolicyName: AUTOPARK_POLICY, Path: POLICY_PATH, PolicyDocument: JSON.stringify(doc), Description: "aws-advisor: the instances a person switched Auto-park on for; the actuator may stop and start these and no others, and re-point their A records after a start" }));
    } else {
      const versions = (await iam.send(new ListPolicyVersionsCommand({ PolicyArn: policyArn }))).Versions ?? [];
      for (const v of versionsToPrune(versions)) await iam.send(new DeletePolicyVersionCommand({ PolicyArn: policyArn, VersionId: v }));
      await iam.send(new CreatePolicyVersionCommand({ PolicyArn: policyArn, PolicyDocument: JSON.stringify(doc), SetAsDefault: true }));
    }
    await iam.send(new AttachRolePolicyCommand({ RoleName: role, PolicyArn: policyArn }));
    return `${AUTOPARK_POLICY}: ${on ? "granted" : "revoked"} stop/start${dnsLine} on ${id} (${after.length} instance${after.length === 1 ? "" : "s"} granted, attached to ${role})`;
  } finally { iam.destroy(); }
}

export interface GrantCheck { granted: boolean | null; detail: string }

/**
 * Whether the actuator role may stop and start this instance, and re-point the A records in `dns` (the ones that
 * lead to it now), as IAM sees every policy on the role (null: could not tell). A grant whose names no longer match
 * the records reads as not granted, so the page offers to grant it again.
 */
export async function checkGrant(credentials: AwsCredentialIdentityProvider, roleArn: string, arn: string, dns: DnsGrant | null = null): Promise<GrantCheck> {
  if (!roleArn) return { granted: null, detail: "no actuator role configured for this account" };
  const iam = iamClient(credentials);
  try {
    const r = await iam.send(new SimulatePrincipalPolicyCommand({ PolicySourceArn: roleArn, ActionNames: ["ec2:StopInstances", "ec2:StartInstances"], ResourceArns: [arn] }));
    const results = r.EvaluationResults ?? [];
    const allowed = results.filter((x) => x.EvalDecision === "allowed").length;
    if (allowed !== 2) return { granted: false, detail: allowed === 1 ? "the actuator may only do one of stop and start" : "the actuator may not stop or start it" };
    const want = normalDns(dns);
    if (!want) return { granted: true, detail: "the actuator may stop and start it" };
    const d = await iam.send(new SimulatePrincipalPolicyCommand({
      PolicySourceArn: roleArn, ActionNames: ["route53:ChangeResourceRecordSets"], ResourceArns: want.zones.map(zoneArn),
      ContextEntries: [
        { ContextKeyName: "route53:ChangeResourceRecordSetsNormalizedRecordNames", ContextKeyValues: want.names, ContextKeyType: "stringList" },
        { ContextKeyName: "route53:ChangeResourceRecordSetsRecordTypes", ContextKeyValues: ["A"], ContextKeyType: "stringList" },
        { ContextKeyName: "route53:ChangeResourceRecordSetsActions", ContextKeyValues: ["UPSERT"], ContextKeyType: "stringList" },
      ],
    }));
    const ok = (d.EvaluationResults ?? []).every((e) => (e.ResourceSpecificResults?.length ? e.ResourceSpecificResults.every((x) => x.EvalResourceDecision === "allowed") : e.EvalDecision === "allowed"));
    const names = want.names.join(", ");
    return ok ? { granted: true, detail: `the actuator may stop and start it and re-point ${names}` } : { granted: false, detail: `the actuator may stop and start it but not re-point ${names} (the records changed since the grant, or it predates DNS grants)` };
  } catch (e: any) { return { granted: null, detail: `could not ask IAM (${e?.name || "error"}: ${String(e?.message || e).slice(0, 120)})` }; }
  finally { iam.destroy(); }
}

/** A refused stop or start explained: the instance has no grant yet. */
export function explainRefusal(e: any, instanceId: string): Error {
  const m = String(e?.message || e);
  if (/UnauthorizedOperation|AccessDenied|not authorized/i.test(`${e?.name} ${m}`)) return new Error(`the actuator role may not stop or start ${instanceId}: switch Auto-park on with "Run as me", which grants this one instance (${m.slice(0, 160)})`);
  return e instanceof Error ? e : new Error(m);
}

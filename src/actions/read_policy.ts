/**
 * The advisor's own read policy, updated from the page with a person's credentials ("Run as me"). The read role and
 * the actuator hold no IAM write right on purpose: neither may widen what it is allowed to do, so the update is a
 * ledger row a person applies with temporary credentials of their own, one row per account (the parent's read
 * identity, each member's read role), previewed first like every other row and recorded with who did it.
 *
 * A row is proposed only where something is missing: the account's current inline policy is read with the advisor's
 * credentials and compared, action by action, with the policy wanted (the recommended one, or the current one plus
 * the fix for the permissions recorded as missing). The document goes inline on the role under the setup script's
 * name (the role's own name), which holds 10,240 characters; an IAM user's inline policy holds 2,048, and a document
 * that would not fit is refused before IAM refuses it. Revert puts the previous document back, or removes the
 * policy when there was none.
 */
import { DeleteRolePolicyCommand, DeleteUserPolicyCommand, GetRolePolicyCommand, GetUserPolicyCommand, IAMClient, ListRolePoliciesCommand, ListUserPoliciesCommand, PutRolePolicyCommand, PutUserPolicyCommand } from "@aws-sdk/client-iam";
import type { AwsCredentialIdentityProvider } from "@aws-sdk/types";
import { config } from "../config.js";
import type { ActionModule, ActionRow, Creds, Proposal } from "../executor.js";
import { recordProposal } from "../executor.js";
import { accountCredentials, listMembers } from "../accounts.js";
import { credentialsMeta, sdkCredentials, sdkIdentity } from "../steampipe.js";
import { listPermissionIssues, policyForIssues, recommendedPolicy, type IamPolicy, type IamStatement } from "../permissions.js";

export const KIND = "read_policy" as const;
/** IAM is global; every call goes to the one partition endpoint. */
export const IAM_REGION = "us-east-1";
/** What an inline policy may hold, whitespace not counted (AWS IAM quotas). */
export const INLINE_LIMIT: Record<"role" | "user", number> = { role: 10_240, user: 2_048 };

export interface PolicyTarget { kind: "role" | "user"; name: string; account_id: string }

/** The IAM role or user an identity ARN names: an assumed-role session ARN maps to its role. Pure. */
export function targetOf(arn: string): PolicyTarget | null {
  let m = /^arn:aws:sts::(\d{12}):assumed-role\/([^/]+)\/.+$/.exec(arn);
  if (m) return { kind: "role", name: m[2], account_id: m[1] };
  m = /^arn:aws:iam::(\d{12}):role\/(?:[^/]+\/)*([^/]+)$/.exec(arn);
  if (m) return { kind: "role", name: m[2], account_id: m[1] };
  m = /^arn:aws:iam::(\d{12}):user\/(?:[^/]+\/)*([^/]+)$/.exec(arn);
  if (m) return { kind: "user", name: m[2], account_id: m[1] };
  return null;
}

const list = (v: unknown): string[] => (Array.isArray(v) ? v.map(String) : v == null ? [] : [String(v)]);
/** Every action an Allow statement grants (Resource and Condition left aside: the compare is "named at all"). Pure. */
export function allowedActions(doc: IamPolicy | null | undefined): Set<string> {
  const out = new Set<string>();
  for (const s of (doc?.Statement ?? []) as IamStatement[]) if (s.Effect === "Allow") for (const a of list(s.Action)) out.add(a);
  return out;
}
/** A wildcard action (`ec2:Describe*`, `s3:*`) covers an action when the pattern matches it. Pure. */
export const covers = (pattern: string, action: string): boolean => pattern === action || (pattern.includes("*") && new RegExp(`^${pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*")}$`, "i").test(action));
/** The wanted actions the current document does not grant, by name or by a wildcard that covers them. Pure. */
export function missingActions(current: IamPolicy | null | undefined, wanted: IamPolicy): string[] {
  const have = [...allowedActions(current)];
  return [...allowedActions(wanted)].filter((a) => !have.some((h) => covers(h, a))).sort();
}
/** The document's size as IAM counts it: characters with whitespace left out. Pure. */
export const policyChars = (doc: IamPolicy): number => JSON.stringify(doc).replace(/\s/g, "").length;
/** The current document plus the fix's statements (the fix carries only what was missing). Pure. */
export function mergeFix(current: IamPolicy | null, fix: IamPolicy): IamPolicy {
  const base: IamPolicy = current ? JSON.parse(JSON.stringify(current)) : { Version: "2012-10-17", Statement: [] };
  const have = allowedActions(base);
  for (const s of fix.Statement) {
    const actions = list(s.Action).filter((a) => !have.has(a));
    if (!actions.length) continue;
    base.Statement.push({ ...s, Sid: s.Sid ? `${s.Sid}Fix${base.Statement.length}` : `AdvisorFix${base.Statement.length}`, Action: actions });
    for (const a of actions) have.add(a);
  }
  return base;
}

const decodeDoc = (s: string | undefined): IamPolicy | null => { if (!s) return null; try { return JSON.parse(decodeURIComponent(s)); } catch { try { return JSON.parse(s); } catch { return null; } } };

/** The inline policy on the target: the one named after it, else the first one there. Reads with the given credentials. */
export async function readInlinePolicy(provider: AwsCredentialIdentityProvider, t: PolicyTarget, preferredName = t.name): Promise<{ policy_name: string | null; document: IamPolicy | null; names: string[] }> {
  const iam = new IAMClient({ region: IAM_REGION, credentials: provider });
  try {
    const names = t.kind === "role" ? (await iam.send(new ListRolePoliciesCommand({ RoleName: t.name }))).PolicyNames ?? [] : (await iam.send(new ListUserPoliciesCommand({ UserName: t.name }))).PolicyNames ?? [];
    const name = names.includes(preferredName) ? preferredName : names[0] ?? null;
    if (!name) return { policy_name: null, document: null, names };
    const doc = t.kind === "role" ? (await iam.send(new GetRolePolicyCommand({ RoleName: t.name, PolicyName: name }))).PolicyDocument : (await iam.send(new GetUserPolicyCommand({ UserName: t.name, PolicyName: name }))).PolicyDocument;
    return { policy_name: name, document: decodeDoc(doc), names };
  } finally { iam.destroy(); }
}

export interface ProposeResult { account_id: string; name: string; is_parent: boolean; target: PolicyTarget | null; status: "proposed" | "up_to_date" | "refused" | "error"; detail: string; missing: string[]; chars: number | null; row: ActionRow | null }

/**
 * One row per account whose read policy lacks something: the parent's identity and every enabled member's read role.
 * `fixOnly` wants the current document plus the recorded fixes; otherwise the whole recommended policy. Nothing is
 * written here; the rows wait for "Run as me".
 */
export async function proposeReadPolicyUpdates(opts: { fixOnly?: boolean; by?: string } = {}): Promise<{ results: ProposeResult[]; fix_only: boolean; issues: string[] }> {
  const issues = listPermissionIssues();
  const fixOnly = Boolean(opts.fixOnly) && issues.length > 0;
  // the fix for one account: the denials seen there, plus those no account was named for
  const fixFor = (accountId: string) => policyForIssues(issues.filter((i) => !i.accounts?.length || i.accounts.includes(accountId)));
  const by = opts.by || "a person";
  const results: ProposeResult[] = [];
  const targets: { account_id: string; name: string; is_parent: boolean; arn: string | null; provider: AwsCredentialIdentityProvider; error?: string }[] = [];
  try {
    const base = sdkCredentials(); const me = await sdkIdentity();
    const parentId = credentialsMeta()?.accountId ?? (me.ok ? me.accountId : "");
    targets.push({ account_id: parentId, name: "parent", is_parent: true, arn: me.ok ? me.arn : null, provider: base.provider, error: me.ok ? undefined : me.error });
  } catch (e: any) { results.push({ account_id: "", name: "parent", is_parent: true, target: null, status: "error", detail: String(e?.message || e).slice(0, 200), missing: [], chars: null, row: null }); }
  for (const m of listMembers().filter((x) => x.enabled)) {
    try { targets.push({ account_id: m.account_id, name: m.name, is_parent: false, arn: m.role_arn, provider: accountCredentials(m.account_id).provider }); }
    catch (e: any) { results.push({ account_id: m.account_id, name: m.name, is_parent: false, target: null, status: "error", detail: String(e?.message || e).slice(0, 200), missing: [], chars: null, row: null }); }
  }
  for (const t of targets) {
    const target = t.arn ? targetOf(t.arn) : null;
    const base = { account_id: t.account_id, name: t.name, is_parent: t.is_parent, target, missing: [] as string[], chars: null as number | null, row: null as ActionRow | null };
    if (!target) { results.push({ ...base, status: "error", detail: t.error || `the identity ${t.arn ?? "(unknown)"} is not an IAM role or user the policy can go on` }); continue; }
    let current: Awaited<ReturnType<typeof readInlinePolicy>>; let readRefused = false;
    try { current = await readInlinePolicy(t.provider, target); }
    catch (e: any) {
      // not readable (iam:ListRolePolicies and iam:GetRolePolicy are themselves part of the update): the row proposes the whole document and says so
      current = { policy_name: null, document: null, names: [] }; readRefused = true;
      const msg = String(e?.message || e);
      if (!/AccessDenied|not authorized/i.test(msg)) { results.push({ ...base, status: "error", detail: `could not read the current policy: ${msg.slice(0, 200)}` }); continue; }
    }
    const wanted = fixOnly ? mergeFix(current.document, fixFor(t.account_id)) : recommendedPolicy(t.account_id || "*");
    const missing = missingActions(current.document, wanted);
    const chars = policyChars(wanted);
    if (!missing.length) { results.push({ ...base, status: "up_to_date", detail: `${current.policy_name ?? "the policy"} already grants everything${fixOnly ? " the fix names" : " recommended"}`, chars }); continue; }
    const limit = INLINE_LIMIT[target.kind];
    if (chars > limit) {
      results.push({ ...base, status: "refused", detail: `the document is ${chars.toLocaleString()} characters and an inline policy on ${target.kind === "user" ? "an IAM user" : "a role"} holds ${limit.toLocaleString()}${target.kind === "user" ? "; move the advisor to a role (the setup script does) or attach the policy as a customer managed one" : ""}`, missing, chars });
      continue;
    }
    const policyName = current.policy_name ?? target.name;
    const p: Proposal = {
      kind: KIND, resource: t.arn ? (target.kind === "role" ? `arn:aws:iam::${target.account_id}:role/${target.name}` : `arn:aws:iam::${target.account_id}:user/${target.name}`) : target.name, resource_name: `${target.name} (${t.is_parent ? "parent" : t.name})`,
      region: IAM_REGION, account_id: t.is_parent ? null : t.account_id,
      dedupe: `${KIND}:${target.account_id}:${target.kind}:${target.name}`,
      title: `${target.name}: read policy ${policyName} + ${missing.length} action${missing.length === 1 ? "" : "s"}${fixOnly ? " (the recorded fixes)" : " (the recommended policy)"}`,
      reason: `${by} asked from Settings › Permissions to bring the advisor's read policy in ${t.is_parent ? "the parent" : `member ${t.name}`} (${target.account_id}) up to date: ${missing.length} action${missing.length === 1 ? " is" : "s are"} missing${current.document ? "" : readRefused ? " (the advisor may not read its own policy yet, so the whole document is written and every action counts as missing)" : current.names.length ? ` (the current ${current.names.join(", ")} could not be read)` : " (no inline policy there yet)"}: ${missing.slice(0, 12).join(", ")}${missing.length > 12 ? `, +${missing.length - 12}` : ""}. The advisor's own identities hold no IAM write right, so this is done with your own credentials ("Run as me"), as one Put${target.kind === "role" ? "RolePolicy" : "UserPolicy"} of ${chars.toLocaleString()} characters.`,
      before: { policy_name: current.policy_name, document: current.document }, after: { policy_name: policyName, document: wanted },
      facts: { target_kind: target.kind, name: target.name, policy_name: policyName, account_id: target.account_id, chars, fix_only: fixOnly, missing, by, read_refused: readRefused },
      rollback: current.document ? `Put${target.kind === "role" ? "RolePolicy" : "UserPolicy"} ${policyName} back to the previous document` : readRefused ? "none: the previous document could not be read, so there is nothing to put back (a revert is refused rather than deleting the policy)" : `Delete${target.kind === "role" ? "RolePolicy" : "UserPolicy"} ${policyName}`,
      est_usd_month: null,
    };
    const row = recordProposal(p, config.actMode, "manual").row;
    results.push({ ...base, status: "proposed", detail: `#${row.id} waits for your credentials${readRefused ? " (the current policy could not be read, so the whole document is written)" : ""}`, missing, chars, row });
  }
  return { results, fix_only: fixOnly, issues: issues.map((i) => i.action) };
}

const factsOf = (p: Proposal) => ({ kind: (p.facts.target_kind === "user" ? "user" : "role") as "role" | "user", name: String(p.facts.name), policy_name: String(p.facts.policy_name) });

async function put(provider: AwsCredentialIdentityProvider, t: { kind: "role" | "user"; name: string; policy_name: string }, doc: IamPolicy | null): Promise<string> {
  const iam = new IAMClient({ region: IAM_REGION, credentials: provider });
  try {
    if (!doc) {
      if (t.kind === "role") await iam.send(new DeleteRolePolicyCommand({ RoleName: t.name, PolicyName: t.policy_name })); else await iam.send(new DeleteUserPolicyCommand({ UserName: t.name, PolicyName: t.policy_name }));
      return `Delete${t.kind === "role" ? "RolePolicy" : "UserPolicy"} ${t.policy_name} on ${t.name}`;
    }
    const PolicyDocument = JSON.stringify(doc);
    if (t.kind === "role") await iam.send(new PutRolePolicyCommand({ RoleName: t.name, PolicyName: t.policy_name, PolicyDocument })); else await iam.send(new PutUserPolicyCommand({ UserName: t.name, PolicyName: t.policy_name, PolicyDocument }));
    return `Put${t.kind === "role" ? "RolePolicy" : "UserPolicy"} ${t.policy_name} on ${t.name}: ${allowedActions(doc).size} actions, ${policyChars(doc).toLocaleString()} characters`;
  } finally { iam.destroy(); }
}

export const readPolicyAction: ActionModule = {
  kind: KIND,
  label: "The advisor's read policy brought up to date from Settings › Permissions, with a person's own credentials",
  async plan() { return { proposals: [], notes: ["proposed from Settings › Permissions, never planned"] }; },
  async apply(p, creds: Creds) {
    const t = factsOf(p);
    const r = await put(creds.act(), t, (p.after.document as IamPolicy) ?? null);
    return `${r} (+${(p.facts.missing as string[] | undefined)?.length ?? "?"} missing)`;
  },
  async verify(p, creds: Creds) {
    const t = factsOf(p);
    let current: Awaited<ReturnType<typeof readInlinePolicy>>;
    try { current = await readInlinePolicy(creds.read, { kind: t.kind, name: t.name, account_id: String(p.facts.account_id ?? "") }, t.policy_name); }
    catch (e: any) { return { ok: null, note: `the policy could not be read back with the advisor's credentials (${String(e?.message || e).slice(0, 120)}); the next permission check tells` }; }
    const missing = missingActions(current.document, p.after.document as IamPolicy);
    return missing.length ? { ok: false, note: `${t.policy_name} still lacks ${missing.length} action${missing.length === 1 ? "" : "s"}: ${missing.slice(0, 8).join(", ")}` } : { ok: true, note: `read back: ${t.policy_name} grants every action wanted` };
  },
  async revert(p, creds: Creds) {
    // the previous document was never seen: deleting the policy would take the advisor's access away, not put anything back
    if (p.before.document == null && p.facts.read_refused) throw new Error(`the policy before this change was not readable, so there is nothing to put back; a revert would delete ${String(p.facts.policy_name)} and leave the advisor without access`);
    const t = { ...factsOf(p), policy_name: String(p.before.policy_name ?? p.facts.policy_name) };
    return `${await put(creds.act(), t, (p.before.document as IamPolicy | null) ?? null)} (back to how it was)`;
  },
};

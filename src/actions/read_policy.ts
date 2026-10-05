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
 * that would not fit is refused before IAM refuses it. The AWS-managed ViewOnlyAccess goes on next to it (the inline
 * document holds only what that policy leaves out), attached by the same row when it is not there yet. Revert puts the
 * previous document back, or removes the policy when there was none, and detaches ViewOnlyAccess when this row attached it.
 */
import { AttachRolePolicyCommand, AttachUserPolicyCommand, DeleteRolePolicyCommand, DeleteUserPolicyCommand, DetachRolePolicyCommand, DetachUserPolicyCommand, GetRolePolicyCommand, GetUserPolicyCommand, IAMClient, ListAttachedRolePoliciesCommand, ListAttachedUserPoliciesCommand, ListRolePoliciesCommand, ListUserPoliciesCommand, PutRolePolicyCommand, PutUserPolicyCommand } from "@aws-sdk/client-iam";
import type { AwsCredentialIdentityProvider } from "@aws-sdk/types";
import { config } from "../config.js";
import type { ActionModule, ActionRow, Creds, Proposal } from "../executor.js";
import { recordProposal } from "../executor.js";
import { accountCredentials, listMembers } from "../accounts.js";
import { credentialsMeta, sdkCredentials, sdkIdentity } from "../steampipe.js";
import { listPermissionIssues, policyForIssues, recommendedPolicy, VIEW_ONLY_POLICY_ARN, type IamPolicy, type IamStatement } from "../permissions.js";

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

/** The managed policies attached to the target, or null when the advisor may not list them. */
export async function readAttachedPolicies(provider: AwsCredentialIdentityProvider, t: PolicyTarget): Promise<string[] | null> {
  const iam = new IAMClient({ region: IAM_REGION, credentials: provider });
  try {
    const out: string[] = []; let Marker: string | undefined;
    do {
      const r = t.kind === "role" ? await iam.send(new ListAttachedRolePoliciesCommand({ RoleName: t.name, Marker })) : await iam.send(new ListAttachedUserPoliciesCommand({ UserName: t.name, Marker }));
      for (const a of r.AttachedPolicies ?? []) if (a.PolicyArn) out.push(a.PolicyArn);
      Marker = r.IsTruncated ? r.Marker : undefined;
    } while (Marker);
    return out;
  } catch (e: any) {
    if (/AccessDenied|not authorized/i.test(String(e?.message || e))) return null;
    throw e;
  } finally { iam.destroy(); }
}

export interface ProposeResult { account_id: string; name: string; is_parent: boolean; target: PolicyTarget | null; status: "proposed" | "up_to_date" | "refused" | "error"; detail: string; missing: string[]; attach_view_only?: boolean; chars: number | null; row: ActionRow | null }

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
    // ViewOnlyAccess: attached unless it is seen to be there already (attaching twice is a no-op in IAM)
    let attached: string[] | null = null;
    try { attached = await readAttachedPolicies(t.provider, target); } catch (e: any) { results.push({ ...base, status: "error", detail: `could not list the attached policies: ${String(e?.message || e).slice(0, 200)}` }); continue; }
    const attachViewOnly = !attached?.includes(VIEW_ONLY_POLICY_ARN);
    if (!missing.length && !attachViewOnly) { results.push({ ...base, status: "up_to_date", detail: `${current.policy_name ?? "the policy"} already grants everything${fixOnly ? " the fix names" : " recommended"} and ViewOnlyAccess is attached`, chars }); continue; }
    const limit = INLINE_LIMIT[target.kind];
    if (missing.length && chars > limit) {
      results.push({ ...base, status: "refused", detail: `the document is ${chars.toLocaleString()} characters and an inline policy on ${target.kind === "user" ? "an IAM user" : "a role"} holds ${limit.toLocaleString()}${target.kind === "user" ? "; move the advisor to a role (the setup script does) or attach the policy as a customer managed one" : ""}`, missing, attach_view_only: attachViewOnly, chars });
      continue;
    }
    const policyName = current.policy_name ?? target.name;
    const verb = target.kind === "role" ? "Role" : "User";
    const steps = [missing.length ? `one Put${verb}Policy of ${chars.toLocaleString()} characters` : "", attachViewOnly ? `Attach${verb}Policy ${VIEW_ONLY_POLICY_ARN}` : ""].filter(Boolean).join(" and ");
    const p: Proposal = {
      kind: KIND, resource: t.arn ? (target.kind === "role" ? `arn:aws:iam::${target.account_id}:role/${target.name}` : `arn:aws:iam::${target.account_id}:user/${target.name}`) : target.name, resource_name: `${target.name} (${t.is_parent ? "parent" : t.name})`,
      region: IAM_REGION, account_id: t.is_parent ? null : t.account_id,
      dedupe: `${KIND}:${target.account_id}:${target.kind}:${target.name}`,
      title: `${target.name}: ${[missing.length ? `read policy ${policyName} + ${missing.length} action${missing.length === 1 ? "" : "s"}` : "", attachViewOnly ? "attach ViewOnlyAccess" : ""].filter(Boolean).join(", ")}${fixOnly ? " (the recorded fixes)" : " (the recommended policy)"}`,
      reason: `${by} asked from Settings › Permissions to bring the advisor's read policy in ${t.is_parent ? "the parent" : `member ${t.name}`} (${target.account_id}) up to date: ${missing.length ? `${missing.length} action${missing.length === 1 ? " is" : "s are"} missing` : "the inline policy is complete"}${attachViewOnly ? `, and the AWS-managed ViewOnlyAccess (every list and describe call, no data reads) is ${attached ? "not attached" : "not known to be attached (the advisor may not list its attached policies)"}` : ""}${!missing.length ? "" : current.document ? "" : readRefused ? " (the advisor may not read its own policy yet, so the whole document is written and every action counts as missing)" : current.names.length ? ` (the current ${current.names.join(", ")} could not be read)` : " (no inline policy there yet)"}${missing.length ? `: ${missing.slice(0, 12).join(", ")}${missing.length > 12 ? `, +${missing.length - 12}` : ""}` : ""}. The advisor's own identities hold no IAM write right, so this is done with your own credentials ("Run as me"), as ${steps}.`,
      before: { policy_name: current.policy_name, document: current.document, attached }, after: { policy_name: policyName, document: wanted, attached: attachViewOnly ? [...(attached ?? []), VIEW_ONLY_POLICY_ARN] : attached },
      // view_only_was_attached: false when seen absent (Revert detaches it), null when the list was not readable (Revert leaves it)
      facts: { target_kind: target.kind, name: target.name, policy_name: policyName, account_id: target.account_id, chars, fix_only: fixOnly, missing, by, read_refused: readRefused, put_inline: missing.length > 0, attach_view_only: attachViewOnly, view_only_was_attached: attached ? !attachViewOnly : null },
      rollback: [
        !missing.length ? "" : current.document ? `Put${verb}Policy ${policyName} back to the previous document` : readRefused ? "the inline policy: none, the previous document could not be read, so there is nothing to put back (a revert is refused rather than deleting the policy)" : `Delete${verb}Policy ${policyName}`,
        attachViewOnly && attached ? `Detach${verb}Policy ${VIEW_ONLY_POLICY_ARN}` : attachViewOnly ? "ViewOnlyAccess stays attached (whether it was there before could not be read)" : "",
      ].filter(Boolean).join("; "),
      est_usd_month: null,
    };
    const row = recordProposal(p, config.actMode, "manual").row;
    results.push({ ...base, status: "proposed", detail: `#${row.id} waits for your credentials${readRefused && missing.length ? " (the current policy could not be read, so the whole document is written)" : ""}`, missing, attach_view_only: attachViewOnly, chars, row });
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

async function attachViewOnly(provider: AwsCredentialIdentityProvider, t: { kind: "role" | "user"; name: string }, on: boolean): Promise<string> {
  const iam = new IAMClient({ region: IAM_REGION, credentials: provider });
  try {
    if (t.kind === "role") await iam.send(on ? new AttachRolePolicyCommand({ RoleName: t.name, PolicyArn: VIEW_ONLY_POLICY_ARN }) : new DetachRolePolicyCommand({ RoleName: t.name, PolicyArn: VIEW_ONLY_POLICY_ARN }));
    else await iam.send(on ? new AttachUserPolicyCommand({ UserName: t.name, PolicyArn: VIEW_ONLY_POLICY_ARN }) : new DetachUserPolicyCommand({ UserName: t.name, PolicyArn: VIEW_ONLY_POLICY_ARN }));
    return `${on ? "Attach" : "Detach"}${t.kind === "role" ? "Role" : "User"}Policy ViewOnlyAccess on ${t.name}`;
  } finally { iam.destroy(); }
}
/** Rows recorded before ViewOnlyAccess existed carry no put_inline fact: they always put the document. */
const putsInline = (p: Proposal) => p.facts.put_inline !== false;

export const readPolicyAction: ActionModule = {
  kind: KIND,
  label: "The advisor's read policy brought up to date from Settings › Permissions, with a person's own credentials",
  async plan() { return { proposals: [], notes: ["proposed from Settings › Permissions, never planned"] }; },
  async apply(p, creds: Creds) {
    const t = factsOf(p);
    const done: string[] = [];
    if (putsInline(p)) done.push(`${await put(creds.act(), t, (p.after.document as IamPolicy) ?? null)} (+${(p.facts.missing as string[] | undefined)?.length ?? "?"} missing)`);
    if (p.facts.attach_view_only) done.push(await attachViewOnly(creds.act(), t, true));
    return done.join("; ");
  },
  async verify(p, creds: Creds) {
    const t = factsOf(p);
    let current: Awaited<ReturnType<typeof readInlinePolicy>>;
    try { current = await readInlinePolicy(creds.read, { kind: t.kind, name: t.name, account_id: String(p.facts.account_id ?? "") }, t.policy_name); }
    catch (e: any) { return { ok: null, note: `the policy could not be read back with the advisor's credentials (${String(e?.message || e).slice(0, 120)}); the next permission check tells` }; }
    const missing = missingActions(current.document, p.after.document as IamPolicy);
    if (missing.length) return { ok: false, note: `${t.policy_name} still lacks ${missing.length} action${missing.length === 1 ? "" : "s"}: ${missing.slice(0, 8).join(", ")}` };
    if (p.facts.attach_view_only) {
      let attached: string[] | null = null;
      try { attached = await readAttachedPolicies(creds.read, { kind: t.kind, name: t.name, account_id: String(p.facts.account_id ?? "") }); } catch { /* reported below as unknown */ }
      if (attached === null) return { ok: null, note: `read back: ${t.policy_name} grants every action wanted; whether ViewOnlyAccess is attached could not be listed` };
      if (!attached.includes(VIEW_ONLY_POLICY_ARN)) return { ok: false, note: `${t.policy_name} grants every action wanted, but ViewOnlyAccess is not attached` };
    }
    return { ok: true, note: `read back: ${t.policy_name} grants every action wanted${p.facts.attach_view_only ? " and ViewOnlyAccess is attached" : ""}` };
  },
  async revert(p, creds: Creds) {
    // the previous document was never seen: deleting the policy would take the advisor's access away, not put anything back
    if (putsInline(p) && p.before.document == null && p.facts.read_refused) throw new Error(`the policy before this change was not readable, so there is nothing to put back; a revert would delete ${String(p.facts.policy_name)} and leave the advisor without access`);
    const t = { ...factsOf(p), policy_name: String(p.before.policy_name ?? p.facts.policy_name) };
    const done: string[] = [];
    if (putsInline(p)) done.push(`${await put(creds.act(), t, (p.before.document as IamPolicy | null) ?? null)} (back to how it was)`);
    // detached only when it was seen absent before this row attached it
    if (p.facts.attach_view_only && p.facts.view_only_was_attached === false) done.push(await attachViewOnly(creds.act(), t, false));
    return done.join("; ") || "nothing to put back";
  },
};

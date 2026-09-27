/**
 * The executor: the one place in the advisor that changes AWS, and only through a separate actuator role.
 *
 * Every action module (src/actions/*) has the same four verbs. `plan` reads the facts with the advisor's read
 * credentials and proposes changes, each with its before, its after, the numbers that justify it and how to undo
 * it. `apply` makes one change under the actuator role. `verify` reads back, with the read credentials, that the
 * change landed. `revert` undoes it. Every proposal is a row in `actions`, the ledger the Auto-actions page shows,
 * whatever the mode: in `dry_run` (the default) the rows say what would have happened; in `apply` the pass applies
 * them up to the per-pass cap; `off` runs nothing. A human can apply or revert any row from the page in any mode
 * but `off`. Applied, failed and reverted rows are posted to Sphinx (quiet hours respected).
 *
 * The actuator role is assumed from the read credentials only inside `apply` and `revert`; the read identity
 * itself never gains a write permission (src/permissions.ts actuatorPolicy). A resource tagged
 * `advisor:hands-off` is skipped by every plan and, belt and braces, denied by the policy.
 */
import { fromTemporaryCredentials } from "@aws-sdk/credential-providers";
import { GetCallerIdentityCommand, STSClient } from "@aws-sdk/client-sts";
import { IAMClient, SimulatePrincipalPolicyCommand } from "@aws-sdk/client-iam";
import type { AwsCredentialIdentityProvider } from "@aws-sdk/types";
import { config } from "./config.js";
import { addColumn, db, getJsonSetting, setSetting } from "./db.js";
import { credentialsMeta, sdkCredentials } from "./steampipe.js";
import { accountCredentials, listMembers } from "./accounts.js";
import { ACTUATOR_NEEDS, describeError, explainPermissionError } from "./permissions.js";
import { configured as notifyConfigured, inQuietHours, noteDecision, sendSphinx } from "./notify.js";
import { canonicalResource } from "./resource_id.js";
import { mirrorActionsInBackground, mirrorRecommendationsInBackground } from "./graph_mirror.js";
import { syncDecisionConceptInBackground } from "./concepts.js";
import { checkLine, checkProposals, parseCheck, reusableCheck, type ProposalCheck } from "./proposal_check.js";

db.exec(`create table if not exists actions (
  id integer primary key autoincrement,
  kind text not null,
  resource text not null,
  resource_name text,
  region text,
  dedupe text not null,
  status text not null,
  mode text not null,
  trigger text not null,
  title text not null,
  reason text not null,
  before_json text,
  after_json text,
  facts_json text,
  rollback text,
  est_usd_month real,
  result text,
  error text,
  created_at text not null default (datetime('now')),
  seen_at text not null default (datetime('now')),
  applied_at text,
  verified_at text,
  reverted_at text,
  notified_at text,
  notify_result text
);
create index if not exists actions_dedupe on actions(dedupe, status);
create index if not exists actions_status on actions(status, created_at)`);
// Member accounts (src/accounts.ts): the account a row's resource lives in; null = the parent (rows from before there were members).
addColumn("actions", "account_id", "text");
// Jev's second opinion on the proposal (src/proposal_check.ts): verdict, scores and reason, asked once per change.
addColumn("actions", "check_json", "text");

export type ActionKind = "acu_window" | "snapshot_archive" | "ebs_iops_trim" | "log_retention" | "s3_request_metrics" | "aurora_storage" | "s3_lifecycle" | "ebs_gp3_migrate" | "ecr_lifecycle" | "swarm_park"
  | "eip_release" | "vpc_gateway_endpoint" | "kms_key_retire" | "dynamodb_capacity_mode" | "snapshot_delete" | "idle_load_balancer" | "schedule_hours" | "ebs_throughput_trim" | "cpu_credit_spec" | "efs_lifecycle" | "alarm_cleanup" | "log_retention_tune" | "s3_multipart_abort" | "lambda_memory";
/** proposed: planned, nothing done (a dry-run row, or waiting for apply); applied: the call succeeded, read-back pending or inconclusive; verified: read back; failed; refused: the pre-check said no at apply time; reverted; stale: the proposal no longer applies. */
export type ActionStatus = "proposed" | "applied" | "verified" | "failed" | "refused" | "reverted" | "stale";

export interface Proposal {
  kind: ActionKind;
  resource: string;
  resource_name?: string | null;
  region: string;
  /** Same dedupe = same change on the same resource; an open proposed row is refreshed rather than duplicated. */
  dedupe: string;
  /** One line: what changes. */
  title: string;
  /** Why, with the numbers. */
  reason: string;
  before: Record<string, unknown>;
  after: Record<string, unknown>;
  facts: Record<string, unknown>;
  /** How to undo, in words (the revert verb does it). */
  rollback: string;
  est_usd_month?: number | null;
  /** The member account the resource lives in (src/accounts.ts); null or absent = the parent. Apply, verify and revert run under that account's credentials. */
  account_id?: string | null;
}

export interface ActionRow {
  id: number; kind: ActionKind; resource: string; resource_name: string | null; region: string | null; account_id: string | null; dedupe: string; status: ActionStatus; mode: string; trigger: string;
  title: string; reason: string; before: any; after: any; facts: any; rollback: string | null; est_usd_month: number | null; result: string | null; error: string | null;
  created_at: string; seen_at: string; applied_at: string | null; verified_at: string | null; reverted_at: string | null; notified_at: string | null; notify_result: string | null;
  /** Jev's second opinion on the proposal; null while unchecked (no key, no answer, or the check is off). */
  check: ProposalCheck | null;
}

/** One account's credentials: the read provider and the actuator role assumed from it. */
export interface AccountCreds {
  account_id: string;
  name: string;
  is_parent: boolean;
  /** The account's read credentials: every plan and verify. */
  read: AwsCredentialIdentityProvider;
  /** The account's actuator role, assumed from its read credentials; throws NoActuator when none is configured. */
  act: () => AwsCredentialIdentityProvider;
  region: string;
}

/**
 * What a module gets: `read`, `act` and `region` are the account the call is for (the parent in plan; the row's
 * account in apply, verify and revert, see `credsForAccount`). `accounts` lists every enabled account so a plan
 * that discovers with the SDK can loop over them, and `forAccount(id)` picks one (unknown or null = the parent).
 */
export interface Creds extends Pick<AccountCreds, "read" | "act" | "region"> {
  accounts: AccountCreds[];
  forAccount(accountId: string | null | undefined): AccountCreds;
}

/** The same Creds with `read`, `act` and `region` switched to one account: what a row's apply, verify and revert run under. */
export function credsForAccount(creds: Creds, accountId: string | null | undefined): Creds {
  const a = creds.forAccount(accountId);
  return { ...creds, read: a.read, act: a.act, region: a.region };
}

export interface PlanResult { proposals: Proposal[]; notes: string[] }

export interface ActionModule {
  kind: ActionKind;
  label: string;
  /** What the action would change now, from the facts (read credentials only). Notes explain what it left alone. */
  plan(creds: Creds, log: (l: string) => void): Promise<PlanResult>;
  /** Makes the change; returns a one-line result. Throws on failure. */
  apply(p: Proposal, creds: Creds): Promise<string>;
  /** Reads the change back. `ok: null` means inconclusive (the change is still in flight). */
  verify(p: Proposal, creds: Creds): Promise<{ ok: boolean | null; note: string }>;
  /** Undoes the change; returns a one-line result. */
  revert(p: Proposal, creds: Creds): Promise<string>;
  /** The pass leaves a fresh proposal alone for this long (hours) so a person can object; a click on Apply does not wait. */
  grace_hours?: () => number;
  /** A fresh proposal is posted to Sphinx when first made (with the grace period), not only once applied. */
  announce?: boolean;
}

export class NoActuator extends Error { constructor(m: string) { super(m); this.name = "NoActuator"; } }

const modules = new Map<ActionKind, ActionModule>();
export function registerAction(m: ActionModule): void { modules.set(m.kind, m); }
export const actionModules = () => [...modules.values()];

/** Pricing the estimates use (us-east-1 list): what the ledger's "≈ USD/month" column means. */
export const ACU_USD_HOUR = 0.12;
export const SNAPSHOT_STANDARD_USD_GB_MONTH = 0.05;
export const SNAPSHOT_ARCHIVE_USD_GB_MONTH = 0.0125;

/**
 * An approved recommendation of tier `auto` on a resource is the go-ahead for the matching action, whatever the
 * action's own thresholds say; the row cites it, and a verified change marks the recommendation done.
 */
export function approvedFor(rules: string[], resource: string): { id: number; title: string; decided_by: string | null } | null {
  if (!rules.length) return null;
  return (db.prepare(`select id, title, decided_by from recommendations where status = 'approved' and tier = 'auto' and resource = ? and rule in (${rules.map(() => "?").join(", ")}) order by id desc limit 1`).get(resource, ...rules) as any) ?? null;
}

/**
 * A recommendation a person approved is the go-ahead for the action that carries it out, whatever its tier: the
 * approval is the decision. Resources are matched on the bare id (`rds:foo`, an ARN and `foo` are one thing) and,
 * for cluster-level actions, on the cluster a member instance belongs to. Newest approval first.
 */
export function approvedRecs(actionTypes: string[], opts: { rules?: string[] } = {}): { id: number; title: string; decided_by: string | null; resource: string; resource_name: string | null; action_type: string; rule: string; est_monthly_saving: number | null; evidence: any }[] {
  const where = ["status = 'approved'"]; const args: unknown[] = [];
  if (actionTypes.length) { where.push(`action_type in (${actionTypes.map(() => "?").join(", ")})`); args.push(...actionTypes); }
  if (opts.rules?.length) { where.push(`rule in (${opts.rules.map(() => "?").join(", ")})`); args.push(...opts.rules); }
  const rows = db.prepare(`select id, title, decided_by, resource, resource_name, action_type, rule, est_monthly_saving, evidence from recommendations where ${where.join(" and ")} order by id desc`).all(...args) as any[];
  return rows.map((r) => ({ ...r, resource: canonicalResource(r.resource, r.action_type) ?? String(r.resource ?? ""), evidence: (() => { try { return r.evidence ? JSON.parse(r.evidence) : null; } catch { return null; } })() })).filter((r) => r.resource);
}

/** Approved recommendations whose change is already in place when the executor looks (someone did it by hand): closed as done, with the reason. */
export function markRecommendationsDone(ids: number[], reason: string): number {
  let n = 0;
  for (const recId of ids) {
    const r = db.prepare("update recommendations set status = 'done', decided_at = datetime('now'), decided_by = 'executor', decision_reason = ?, updated_at = datetime('now') where id = ? and status = 'approved'").run(reason, recId);
    if (r.changes) { n++; console.log(`[executor] recommendation #${recId} marked done: ${reason}`); try { noteDecision(recId, "done", "executor"); } catch { /* notification only */ } decisionHooks(recId); }
  }
  return n;
}

/** What a decision from the page also does (src/routes/browse.ts): the decision Concept in repo2graph and the recommendation node in the graph. */
function decisionHooks(recId: number): void { syncDecisionConceptInBackground(recId); mirrorRecommendationsInBackground([recId]); }

function closeRecommendation(row: ActionRow): void {
  const ids = [Number(row.facts?.recommendation_id), ...(Array.isArray(row.facts?.recommendation_ids) ? row.facts.recommendation_ids.map(Number) : [])].filter((n, i, a) => n > 0 && a.indexOf(n) === i);
  for (const recId of ids) {
    const r = db.prepare("update recommendations set status = 'done', decided_at = datetime('now'), decided_by = 'executor', decision_reason = ?, updated_at = datetime('now') where id = ? and status = 'approved'")
      .run(`applied by the executor: auto-action #${row.id} (${row.title})`, recId);
    if (r.changes) { console.log(`[executor] recommendation #${recId} marked done by #${row.id}`); try { noteDecision(recId, "done", "executor"); } catch { /* notification only */ } decisionHooks(recId); }
  }
}

// ---- credentials ------------------------------------------------------------------------------------------------

/** An account's actuator: its role assumed from its read provider, once. */
function accountCreds(a: { account_id: string; name: string; is_parent: boolean; read: AwsCredentialIdentityProvider; region: string; act_role_arn: string }): AccountCreds {
  let actProvider: AwsCredentialIdentityProvider | null = null;
  return {
    account_id: a.account_id, name: a.name, is_parent: a.is_parent, read: a.read, region: a.region,
    act: () => {
      if (!a.act_role_arn) throw new NoActuator(a.is_parent ? "no actuator role is configured (Settings > Auto-actions > Actuator role ARN); nothing can be applied" : `member account ${a.name} (${a.account_id}) has no actuator role (Settings > Member accounts); dry runs only there`);
      if (!actProvider) actProvider = fromTemporaryCredentials({ masterCredentials: a.read, params: { RoleArn: a.act_role_arn, RoleSessionName: "aws-advisor-act", DurationSeconds: 900 }, clientConfig: { region: a.region } });
      return actProvider;
    },
  };
}

/**
 * The parent's credentials plus every enabled member's (src/accounts.ts): `read`/`act`/`region` are the parent's,
 * so a module that knows nothing about accounts behaves as before. Note that `actuatorCapabilities` simulates the
 * parent's actuator role only; a member role narrower than the policy is learnt from denied applies.
 */
export function executorCreds(): Creds {
  const base = sdkCredentials();
  const parentId = credentialsMeta()?.accountId || "";
  const parent = accountCreds({ account_id: parentId, name: "parent", is_parent: true, read: base.provider, region: base.region, act_role_arn: config.actRoleArn });
  const accounts: AccountCreds[] = [parent];
  for (const m of listMembers()) {
    if (!m.enabled) continue;
    try { const c = accountCredentials(m.account_id); accounts.push(accountCreds({ account_id: m.account_id, name: m.name, is_parent: false, read: c.provider, region: c.region, act_role_arn: m.act_role_arn || "" })); }
    catch (e: any) { console.error(`[executor] member ${m.account_id}: ${e?.message || e}`); }
  }
  return {
    read: parent.read, region: parent.region, act: parent.act, accounts,
    forAccount: (id) => (id ? accounts.find((a) => a.account_id === id) : undefined) ?? parent,
  };
}

/** Who the executor would act as: sts:GetCallerIdentity under the actuator role, with the remedy on failure. */
export async function actuatorIdentity(timeoutMs = 15_000): Promise<{ ok: true; arn: string } | { ok: false; error: string }> {
  let creds: Creds;
  try { creds = executorCreds(); } catch (e: any) { return { ok: false, error: e?.message || String(e) }; }
  if (!config.actRoleArn) return { ok: false, error: "no actuator role configured" };
  const client = new STSClient({ region: creds.region, credentials: creds.act() });
  try {
    const timer = new Promise<never>((_, reject) => setTimeout(() => reject(new Error(`sts:GetCallerIdentity did not answer within ${Math.round(timeoutMs / 1000)}s`)), timeoutMs).unref());
    const r = await Promise.race([client.send(new GetCallerIdentityCommand({})), timer]);
    return { ok: true, arn: r.Arn || "" };
  } catch (e: any) {
    const msg = String(e?.message || e);
    if (/AccessDenied|not authorized to perform: sts:AssumeRole/i.test(msg)) return { ok: false, error: `${msg}. The advisor's read identity is not allowed to assume ${config.actRoleArn}: put it in the role's trust policy (Auto-actions page shows the JSON).` };
    return { ok: false, error: msg };
  } finally { client.destroy(); }
}

// ---- what the role may do ---------------------------------------------------------------------------------------------

export interface Capability { apply: boolean | null; revert: boolean | null; missing: string[]; source: "simulated" | "learned" | "unknown"; note?: string }
type Learned = Record<string, { kind: string; last_seen: string; message: string }>;
const DENIALS_KEY = "act:denials";
const CAP_TTL_MS = 10 * 60_000;

const learnedDenials = (): Learned => getJsonSetting<Learned>(DENIALS_KEY, {});
function learnDenial(action: string, kind: string, message: string): void {
  const d = learnedDenials(); d[action] = { kind, last_seen: new Date().toISOString(), message: message.slice(0, 200) }; setSetting(DENIALS_KEY, JSON.stringify(d)); capCache = null;
}
function forgetDenials(actions: string[]): void {
  const d = learnedDenials(); let changed = false;
  for (const a of actions) if (d[a]) { delete d[a]; changed = true; }
  if (changed) { setSetting(DENIALS_KEY, JSON.stringify(d)); capCache = null; }
}

/** Per kind, from what the simulation allowed (null when it could not run) and what denied applies taught. Pure. */
export function computeCapabilities(allowed: Set<string> | null, learned: Learned, needs = ACTUATOR_NEEDS): Record<string, Capability> {
  const out: Record<string, Capability> = {};
  for (const [kind, n] of Object.entries(needs)) {
    const missing = (list: string[]) => list.filter((a) => (allowed ? !allowed.has(a) : false) || Boolean(learned[a]));
    const ma = missing(n.apply), mr = missing(n.revert);
    const all = [...new Set([...ma, ...mr])];
    const source: Capability["source"] = allowed ? "simulated" : all.length ? "learned" : "unknown";
    out[kind] = { apply: allowed || ma.length ? ma.length === 0 : null, revert: allowed || mr.length ? mr.length === 0 : null, missing: all, source };
  }
  return out;
}

let capCache: { role: string; at: number; caps: Record<string, Capability>; note?: string } | null = null;

/**
 * What the actuator role can actually do, per action kind: iam:SimulatePrincipalPolicy on the role from the read
 * identity (cached ten minutes), overlaid with denials learned from failed applies. Without the simulate permission
 * only the learned denials are known and the rest is "unknown", which the page treats as allowed.
 */
export async function actuatorCapabilities(force = false): Promise<{ caps: Record<string, Capability>; note?: string }> {
  const role = config.actRoleArn;
  if (!role) return { caps: computeCapabilities(null, {}), note: "no actuator role configured" };
  if (!force && capCache && capCache.role === role && Date.now() - capCache.at < CAP_TTL_MS) return { caps: capCache.caps, note: capCache.note };
  const actions = [...new Set(Object.values(ACTUATOR_NEEDS).flatMap((n) => [...n.apply, ...n.revert]))];
  let allowed: Set<string> | null = null; let note: string | undefined;
  try {
    const base = sdkCredentials();
    const iam = new IAMClient({ region: base.region, credentials: base.provider });
    try {
      const r = await iam.send(new SimulatePrincipalPolicyCommand({ PolicySourceArn: role, ActionNames: actions, MaxItems: 200,
        ContextEntries: [{ ContextKeyName: "aws:ResourceTag/advisor:park", ContextKeyValues: ["auto"], ContextKeyType: "string" }, { ContextKeyName: "aws:ResourceTag/advisor:schedule", ContextKeyValues: ["weekdays 08-20"], ContextKeyType: "string" }] }));
      allowed = new Set((r.EvaluationResults ?? []).filter((e) => e.EvalDecision === "allowed").map((e) => String(e.EvalActionName)));
      const learned = learnedDenials();
      forgetDenials(Object.keys(learned).filter((a) => allowed!.has(a)));
    } finally { iam.destroy(); }
  } catch (e: any) {
    const m = String(e?.message || e);
    note = /AccessDenied|not authorized/i.test(m) ? "the read identity may not simulate the role's policy (iam:SimulatePrincipalPolicy): what the role lacks is learned from denied applies instead" : `policy simulation failed: ${m.slice(0, 160)}`;
  }
  const caps = computeCapabilities(allowed, learnedDenials());
  capCache = { role, at: Date.now(), caps, note };
  return { caps, note };
}

/** The message a denied apply or revert leaves on the row, and what it teaches. */
function actuatorDenied(e: unknown, kind: string, verb: "apply" | "revert"): string | null {
  const issue = explainPermissionError(e, `${kind} ${verb}`);
  if (!issue) return null;
  const action = issue.action !== "unknown" ? issue.action : (ACTUATOR_NEEDS[kind]?.[verb] ?? [])[0] ?? "unknown";
  if (action !== "unknown") learnDenial(action, kind, String((e as any)?.message || e));
  return `the actuator role is not allowed ${action}: add it to the role's policy (the Auto-actions page prints the full policy), or leave this action to a person`;
}

// ---- the kill switch ----------------------------------------------------------------------------------------------

export interface PauseState { paused: boolean; by?: string; at?: string; reason?: string; until?: string }
const PAUSE_KEY = "act:paused";

/**
 * "pause auto-actions": the executor plans and applies nothing until someone resumes it (the page, the API or the
 * chat). A pause with an `until` in the past counts as resumed. Revert stays allowed while paused: undoing a
 * change is the safety valve a pause exists for.
 */
export function pauseState(now = Date.now()): PauseState {
  const p = getJsonSetting<PauseState | null>(PAUSE_KEY, null);
  if (!p || !p.paused) return { paused: false };
  if (p.until && new Date(p.until).getTime() <= now) return { paused: false };
  return p;
}

const pauseLine = (p: PauseState) => `paused by ${p.by || "someone"} since ${(p.at || "").slice(0, 16).replace("T", " ")} UTC${p.reason ? `: ${p.reason}` : ""}${p.until ? ` (until ${p.until.slice(0, 16).replace("T", " ")} UTC)` : ""}`;

async function announcePause(line: string): Promise<void> {
  // A pause is urgent, so quiet hours are not respected here.
  if (!notifyConfigured() || config.notifyLevel === "off") return;
  try { await sendSphinx(line); } catch (e: any) { console.log(`[executor] pause notice failed: ${e?.message || e}`); }
}

export function pauseActions(by: string, reason: string, untilIso?: string): PauseState {
  if (untilIso && !Number.isFinite(new Date(untilIso).getTime())) throw new Error(`"${untilIso}" is not a date`);
  const p: PauseState = { paused: true, by: by || "unknown", at: new Date().toISOString(), reason: (reason || "").slice(0, 300), ...(untilIso ? { until: new Date(untilIso).toISOString() } : {}) };
  setSetting(PAUSE_KEY, JSON.stringify(p));
  console.log(`[executor] ${pauseLine(p)}`);
  announcePause(`⏸️ Auto-actions ${pauseLine(p)}. Nothing is planned or applied until someone resumes (page, API or "resume auto-actions" in the chat). Revert still works.\n${config.notifyLinkUrl}/actions`).catch(() => {});
  return p;
}

export function resumeActions(by: string): PauseState {
  const was = pauseState();
  setSetting(PAUSE_KEY, JSON.stringify({ paused: false }));
  if (was.paused) {
    console.log(`[executor] resumed by ${by} (was ${pauseLine(was)})`);
    announcePause(`▶️ Auto-actions resumed by ${by || "someone"} (were ${pauseLine(was)}). The next pass runs on schedule.\n${config.notifyLinkUrl}/actions`).catch(() => {});
  }
  return { paused: false };
}

// ---- the ledger ---------------------------------------------------------------------------------------------------

const safeJson = (s: string | null) => { if (!s) return null; try { return JSON.parse(s); } catch { return null; } };
const rowOf = (r: any): ActionRow => ({ ...r, before: safeJson(r.before_json), after: safeJson(r.after_json), facts: safeJson(r.facts_json), check: parseCheck(r.check_json), before_json: undefined, after_json: undefined, facts_json: undefined, check_json: undefined });

// ---- the second opinion --------------------------------------------------------------------------------------------

/** Writes Jev's verdict on a row. */
export function setCheck(id: number, check: ProposalCheck): void {
  db.prepare("update actions set check_json = ? where id = ?").run(JSON.stringify(check), id);
}

/** Kinds the executor cannot undo: no revert call, or a grace period (the deletes that are announced first). */
const irreversibleKinds = () => new Set([...modules.values()].filter((m) => !(ACTUATOR_NEEDS[m.kind]?.revert ?? []).length || m.grace_hours).map((m) => m.kind));

/**
 * Jev's second opinion for the rows of one module in one pass: the rows still unchecked get a verdict, first from
 * an earlier row for the same change (same dedupe, account and target state, within 30 days: no call), else
 * from one Jev call for the whole batch. Returns the rows that changed, re-read. Never throws.
 */
async function secondOpinion(rows: ActionRow[], mod: ActionModule, mode: string, note: (n: string) => void): Promise<Map<number, ActionRow>> {
  const changed = new Map<number, ActionRow>();
  const setting = config.actJevCheck;
  if (setting === "off") return changed;
  const unchecked = rows.filter((r) => !r.check && r.status === "proposed");
  if (!unchecked.length) return changed;
  const ask: ActionRow[] = [];
  for (const r of unchecked) {
    const earlier = db.prepare("select id, dedupe, account_id, after_json, check_json from actions where dedupe = ? and check_json is not null and id != ? order by id desc limit 20").all(r.dedupe, r.id) as { id: number; dedupe: string; account_id: string | null; after_json: string | null; check_json: string }[];
    const reuse = reusableCheck(earlier.map((e) => ({ ...e, check: parseCheck(e.check_json) })), { id: r.id, dedupe: r.dedupe, account_id: r.account_id, after_json: JSON.stringify(r.after ?? {}) });
    if (reuse) { setCheck(r.id, reuse.check); changed.set(r.id, getAction(r.id)!); continue; }
    ask.push(r);
  }
  if (!ask.length) return changed;
  // In dry run the verdict is for the page; only what is new gets asked so the same change is never asked twice.
  try {
    const { checks, note: n } = await checkProposals(ask, { irreversibleKinds: irreversibleKinds(), mode: setting });
    if (n) note(n);
    for (const [id, c] of checks) { setCheck(id, c); changed.set(id, getAction(id)!); }
    if (mode !== "apply" && checks.size) note(`${checks.size} proposal(s) checked by Jev (dry run: recorded on the rows)`);
  } catch (e: any) { note(`Jev check failed: ${String(e?.message || e).slice(0, 160)}; proposals left unchecked`); }
  void mod;
  return changed;
}

export function getAction(id: number): ActionRow | null {
  const r = db.prepare("select * from actions where id = ?").get(id);
  return r ? rowOf(r) : null;
}

export interface ActionPage { actions: ActionRow[]; total: number; page: number; page_size: number; counts: Record<string, number>; kinds: Record<string, number> }

/**
 * The ledger, newest first, one page at a time. `counts` is per status over the whole ledger (the status chips);
 * `kinds` is per kind within the status filter, before the kind filter, so the picked kind stays listed with the
 * others. `id` without `page` lands on the page that holds that row (a deep link from Sphinx); an id outside the
 * filter gives page 1.
 */
export function listActions(opts: { status?: string; kind?: string; page?: number; page_size?: number; id?: number } = {}): ActionPage {
  const page_size = Math.min(200, Math.max(1, Math.floor(opts.page_size || 25)));
  const where: string[] = []; const args: unknown[] = [];
  if (opts.status && opts.status !== "all") { where.push("status = ?"); args.push(opts.status); }
  const scope = where.length ? `where ${where.join(" and ")}` : "";
  const kinds: Record<string, number> = {};
  for (const k of db.prepare(`select kind, count(*) as n from actions ${scope} group by kind order by n desc, kind`).all(...args) as { kind: string; n: number }[]) kinds[k.kind] = k.n;
  if (opts.kind) { where.push("kind = ?"); args.push(opts.kind); }
  const filter = where.length ? `where ${where.join(" and ")}` : "";
  const total = (db.prepare(`select count(*) as n from actions ${filter}`).get(...args) as { n: number }).n;
  let page = Math.max(1, Math.floor(opts.page || 0) || 1);
  if (!opts.page && opts.id != null) {
    // Rows are ordered by id desc, so the row's position is the number of matching rows with a higher id.
    const above = (db.prepare(`select count(*) as n from actions ${filter}${filter ? " and" : " where"} id > ?`).get(...args, opts.id) as { n: number }).n;
    const there = (db.prepare(`select count(*) as n from actions ${filter}${filter ? " and" : " where"} id = ?`).get(...args, opts.id) as { n: number }).n;
    page = there ? Math.floor(above / page_size) + 1 : 1;
  }
  const rows = db.prepare(`select * from actions ${filter} order by id desc limit ? offset ?`).all(...args, page_size, (page - 1) * page_size);
  const counts: Record<string, number> = {};
  for (const c of db.prepare("select status, count(*) as n from actions group by status").all() as { status: string; n: number }[]) counts[c.status] = c.n;
  return { actions: rows.map(rowOf), total, page, page_size, counts, kinds };
}

const proposalOf = (r: ActionRow): Proposal => ({ kind: r.kind, resource: r.resource, resource_name: r.resource_name, region: r.region || "us-east-1", account_id: r.account_id ?? null, dedupe: r.dedupe, title: r.title, reason: r.reason, before: r.before || {}, after: r.after || {}, facts: r.facts || {}, rollback: r.rollback || "", est_usd_month: r.est_usd_month });

const FAILURES_BEFORE_REFUSING = 3;

/** Records a proposal: refreshes the open row with the same dedupe, else inserts one. Returns the row and whether it is new. */
function recordProposal(p: Proposal, mode: string, trigger: string): { row: ActionRow; fresh: boolean } {
  // Same dedupe in another member account is another change: names (repositories, log groups) are unique only per account.
  const open = db.prepare("select id from actions where dedupe = ? and coalesce(account_id, '') = coalesce(?, '') and status = 'proposed' order by id desc limit 1").get(p.dedupe, p.account_id ?? null) as { id: number } | undefined;
  const json = { before: JSON.stringify(p.before), after: JSON.stringify(p.after), facts: JSON.stringify(p.facts) };
  if (open) {
    db.prepare("update actions set title = ?, reason = ?, before_json = ?, after_json = ?, facts_json = ?, rollback = ?, est_usd_month = ?, resource_name = ?, account_id = coalesce(?, account_id), seen_at = datetime('now'), mode = ? where id = ?")
      .run(p.title, p.reason, json.before, json.after, json.facts, p.rollback, p.est_usd_month ?? null, p.resource_name ?? null, p.account_id ?? null, mode, open.id);
    return { row: getAction(open.id)!, fresh: false };
  }
  const id = Number(db.prepare(`insert into actions(kind, resource, resource_name, region, account_id, dedupe, status, mode, trigger, title, reason, before_json, after_json, facts_json, rollback, est_usd_month)
    values (?, ?, ?, ?, ?, ?, 'proposed', ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(p.kind, p.resource, p.resource_name ?? null, p.region, p.account_id ?? null, p.dedupe, mode, trigger, p.title, p.reason, json.before, json.after, json.facts, p.rollback, p.est_usd_month ?? null).lastInsertRowid);
  return { row: getAction(id)!, fresh: true };
}

/** Open proposals of a kind that this pass did not propose again no longer apply (the hour moved on, the snapshot is gone). */
/** The key a pass keeps open proposals by: the dedupe, per account. */
export const keepKey = (dedupe: string, accountId: string | null | undefined) => `${accountId ?? ""}|${dedupe}`;

function closeStale(kind: ActionKind, keep: Set<string>): number[] {
  const open = db.prepare("select id, dedupe, account_id from actions where kind = ? and status = 'proposed'").all(kind) as { id: number; dedupe: string; account_id: string | null }[];
  const ids: number[] = [];
  for (const o of open) if (!keep.has(keepKey(o.dedupe, o.account_id))) { db.prepare("update actions set status = 'stale', result = 'no longer proposed by the latest pass' where id = ?").run(o.id); ids.push(o.id); }
  return ids;
}

const recentFailures = (dedupe: string) => (db.prepare("select count(*) as n from actions where dedupe = ? and status = 'failed' and datetime(created_at) > datetime('now', '-1 day')").get(dedupe) as { n: number }).n;

// ---- apply / verify / revert ------------------------------------------------------------------------------------

/**
 * Applies one ledger row: the change under the actuator role, then the read-back. The row's status tells what
 * happened; the function never throws for an AWS failure (that is a `failed` row), only for a bad id or state.
 */
export async function applyAction(id: number, trigger = "manual"): Promise<ActionRow> {
  const row = await applyActionInner(id, trigger);
  mirrorActionsInBackground([id]);
  return row;
}

async function applyActionInner(id: number, trigger: string): Promise<ActionRow> {
  const row = getAction(id); if (!row) throw new Error(`no action #${id}`);
  if (row.status !== "proposed") throw new Error(`action #${id} is ${row.status}, not proposed`);
  if (config.actMode === "off") throw new Error("auto-actions are off (Settings > Auto-actions > Mode)");
  const paused = pauseState();
  if (paused.paused) throw new Error(`auto-actions are paused by ${paused.by}${paused.reason ? ` (${paused.reason})` : ""}; resume from the page or the chat`);
  const mod = modules.get(row.kind); if (!mod) throw new Error(`no module for ${row.kind}`);
  if (recentFailures(row.dedupe) >= FAILURES_BEFORE_REFUSING) {
    db.prepare("update actions set status = 'refused', error = ?, trigger = ? where id = ?").run(`failed ${FAILURES_BEFORE_REFUSING} times in the last day; not retried until tomorrow`, trigger, id);
    return getAction(id)!;
  }
  const cap = (await actuatorCapabilities()).caps[row.kind];
  if (cap?.apply === false) throw new Error(`the actuator role is not allowed ${cap.missing.join(", ")}; #${id} can only be done by a person (or widen the role's policy)`);
  const p = proposalOf(row);
  let creds: Creds;
  try { creds = credsForAccount(executorCreds(), row.account_id); creds.act(); }
  catch (e: any) { db.prepare("update actions set status = 'refused', error = ?, trigger = ? where id = ?").run(e?.message || String(e), trigger, id); return getAction(id)!; }
  console.log(`[executor] applying #${id} ${row.kind} ${row.resource}${row.account_id ? ` (account ${row.account_id})` : ""}: ${row.title}`);
  // A person's Apply overrides a Jev hold (that is the human decision); the objection stays on record with the result.
  const overrode = row.check?.verdict === "hold" ? ` · applied by ${trigger} over Jev's hold: ${row.check.reason}` : "";
  try {
    const result = (await mod.apply(p, creds)) + overrode;
    forgetDenials(ACTUATOR_NEEDS[row.kind]?.apply ?? []);
    db.prepare("update actions set status = 'applied', mode = 'apply', trigger = ?, result = ?, error = null, applied_at = datetime('now') where id = ?").run(trigger, result, id);
  } catch (e) {
    const error = actuatorDenied(e, row.kind, "apply") ?? describeError(e, `${row.kind} ${row.resource}`);
    db.prepare("update actions set status = 'failed', mode = 'apply', trigger = ?, error = ?, applied_at = datetime('now') where id = ?").run(trigger, error, id);
    console.error(`[executor] #${id} failed: ${error}`);
    return getAction(id)!;
  }
  await verifyAction(id, creds);
  return getAction(id)!;
}

/** Reads an applied row back; `verified` when the change is in place, left `applied` while it is still in flight. */
export async function verifyAction(id: number, creds?: Creds): Promise<ActionRow> {
  const row = getAction(id); if (!row) throw new Error(`no action #${id}`);
  if (row.status !== "applied") return row;
  const mod = modules.get(row.kind); if (!mod) return row;
  try { return await verifyInner(row, mod, creds); } finally { mirrorActionsInBackground([id]); }
}

async function verifyInner(row: ActionRow, mod: ActionModule, creds?: Creds): Promise<ActionRow> {
  const id = row.id;
  try {
    const v = await mod.verify(proposalOf(row), credsForAccount(creds || executorCreds(), row.account_id));
    if (v.ok === true) { db.prepare("update actions set status = 'verified', verified_at = datetime('now'), result = coalesce(result, '') || ' · ' || ? where id = ?").run(v.note, id); closeRecommendation(getAction(id)!); }
    else if (v.ok === false) db.prepare("update actions set status = 'failed', error = ? where id = ?").run(`read-back disagrees: ${v.note}`, id);
    else db.prepare("update actions set result = coalesce(result, '') || ' · ' || ? where id = ?").run(v.note, id);
  } catch (e) {
    db.prepare("update actions set result = coalesce(result, '') || ' · read-back failed: ' || ? where id = ?").run(describeError(e, `${row.kind} verify ${row.resource}`, 200), id);
  }
  return getAction(id)!;
}

export async function revertAction(id: number, by = "manual"): Promise<ActionRow> {
  const row = getAction(id); if (!row) throw new Error(`no action #${id}`);
  if (!["applied", "verified"].includes(row.status)) throw new Error(`action #${id} is ${row.status}; only an applied or verified change can be reverted`);
  if (config.actMode === "off") throw new Error("auto-actions are off (Settings > Auto-actions > Mode)");
  // Deliberately not checked here: a pause (pauseState) stops planning and applying, never undoing. Revert is the safety valve.
  const mod = modules.get(row.kind); if (!mod) throw new Error(`no module for ${row.kind}`);
  const cap = (await actuatorCapabilities()).caps[row.kind];
  if (cap?.revert === false) throw new Error(`the actuator role is not allowed ${cap.missing.join(", ")}; #${id} can only be undone by a person (or widen the role's policy)`);
  const creds = credsForAccount(executorCreds(), row.account_id); creds.act();
  console.log(`[executor] reverting #${id} ${row.kind} ${row.resource}${row.account_id ? ` (account ${row.account_id})` : ""} (${by})`);
  try {
    const result = await mod.revert(proposalOf(row), creds);
    forgetDenials(ACTUATOR_NEEDS[row.kind]?.revert ?? []);
    db.prepare("update actions set status = 'reverted', reverted_at = datetime('now'), result = coalesce(result, '') || ' · reverted: ' || ?, notified_at = null, notify_result = null where id = ?").run(result, id);
  } catch (e) {
    const error = actuatorDenied(e, row.kind, "revert") ?? describeError(e, `${row.kind} revert ${row.resource}`);
    db.prepare("update actions set error = ? where id = ?").run(`revert failed: ${error}`, id);
    throw new Error(error);
  } finally { mirrorActionsInBackground([id]); }
  return getAction(id)!;
}

// ---- the pass -----------------------------------------------------------------------------------------------------

export interface PassResult { mode: string; proposed: number; fresh: number; applied: number; verified: number; failed: number; refused: number; held: number; stale: number; notes: string[]; errors: string[]; took_ms: number }

let passInFlight: Promise<PassResult> | null = null;

/** One executor pass: every module plans, the ledger is updated, and in apply mode the proposals are applied up to the cap. */
export function runExecutorPass(trigger = "schedule"): Promise<PassResult> {
  if (passInFlight) return passInFlight;
  passInFlight = (async () => {
    const t0 = Date.now();
    const mode = config.actMode;
    const out: PassResult = { mode, proposed: 0, fresh: 0, applied: 0, verified: 0, failed: 0, refused: 0, held: 0, stale: 0, notes: [], errors: [], took_ms: 0 };
    const log = (l: string) => console.log(`[executor] ${l}`);
    if (mode === "off") { out.notes.push("mode off: nothing planned"); out.took_ms = Date.now() - t0; return out; }
    const paused = pauseState();
    if (paused.paused) { const n = `${pauseLine(paused)}; nothing planned or applied`; out.notes.push(n); log(n); out.took_ms = Date.now() - t0; return out; }
    let creds: Creds;
    try { creds = executorCreds(); } catch (e: any) { out.errors.push(e?.message || String(e)); out.took_ms = Date.now() - t0; return out; }
    // Rows applied earlier and still unverified (a snapshot still archiving) get read back first.
    for (const r of db.prepare("select id from actions where status = 'applied' order by id").all() as { id: number }[]) { const v = await verifyAction(r.id, creds); if (v.status === "verified") out.verified++; }
    const budget = { left: Math.max(1, config.actMaxPerPass) };
    const touched = new Set<number>();
    const caps = mode === "apply" ? (await actuatorCapabilities()).caps : {};
    for (const mod of modules.values()) {
      const blocked = caps[mod.kind]?.apply === false ? caps[mod.kind].missing : null;
      let plan: PlanResult;
      try { plan = await mod.plan(creds, (l) => log(`${mod.kind}: ${l}`)); }
      catch (e) { const m = describeError(e, `${mod.kind} plan`); out.errors.push(`${mod.kind}: ${m}`); log(`${mod.kind}: plan failed: ${m}`); continue; }
      out.notes.push(...plan.notes.map((n) => `${mod.kind}: ${n}`));
      const keep = new Set<string>();
      // Record first, then one Jev call for the module's unchecked rows, then the apply decisions: the second
      // opinion (src/proposal_check.ts) is on the row before anything is applied and is asked once per change.
      const recorded: { row: ActionRow; fresh: boolean; p: Proposal }[] = [];
      for (const p of plan.proposals) {
        keep.add(keepKey(p.dedupe, p.account_id));
        const { row, fresh } = recordProposal(p, mode, trigger);
        touched.add(row.id);
        out.proposed++; if (fresh) out.fresh++;
        log(`${fresh ? "proposed" : "still proposed"} #${row.id} ${p.title}${p.est_usd_month != null ? ` (≈ ${p.est_usd_month.toFixed(2)} USD/month)` : ""}`);
        recorded.push({ row, fresh, p });
      }
      const checked = await secondOpinion(recorded.map((r) => r.row), mod, mode, (n) => { out.notes.push(`${mod.kind}: ${n}`); log(`${mod.kind}: ${n}`); });
      for (const r of recorded) if (checked.has(r.row.id)) r.row = checked.get(r.row.id)!;
      for (const { row, fresh } of recorded) {
        if (fresh && mod.announce) announceProposal(row, mod.grace_hours?.() ?? 0, mode).catch(() => {});
        if (mode !== "apply") continue;
        if (blocked) { if (fresh) out.notes.push(`${mod.kind}: #${row.id} left for a person: the actuator role is not allowed ${blocked.join(", ")}`); continue; }
        if (row.check?.verdict === "hold" && config.actJevCheck === "hold") { const n = `#${row.id} held by Jev: ${row.check.reason} (Apply on the page proceeds)`; out.notes.push(`${mod.kind}: ${n}`); log(n); out.held++; continue; }
        const wait = graceLeftMs(row, mod.grace_hours?.() ?? 0);
        if (wait > 0) { const n = `#${row.id} waits ${Math.ceil(wait / 3600000)} h more (grace period; Apply on the page skips it)`; out.notes.push(`${mod.kind}: ${n}`); log(n); continue; }
        if (budget.left <= 0) { log(`cap of ${config.actMaxPerPass} changes per pass reached; #${row.id} waits`); continue; }
        budget.left--;
        const done = await applyAction(row.id, trigger);
        if (done.status === "verified") { out.applied++; out.verified++; }
        else if (done.status === "applied") out.applied++;
        else if (done.status === "failed") out.failed++;
        else if (done.status === "refused") out.refused++;
      }
      const stale = closeStale(mod.kind, keep);
      out.stale += stale.length; for (const id of stale) touched.add(id);
    }
    if (touched.size) mirrorActionsInBackground([...touched]);
    out.took_ms = Date.now() - t0;
    log(`${mode}: ${out.proposed} proposed (${out.fresh} new), ${out.applied} applied, ${out.verified} verified, ${out.failed} failed, ${out.refused} refused, ${out.held} held by Jev, ${out.stale} stale in ${out.took_ms} ms${out.errors.length ? `; errors: ${out.errors.join("; ")}` : ""}`);
    // The narrated pass (src/pass_report.ts): the agent writes the short version once per distinct outcome. Dynamic import: that module imports this one.
    import("./pass_report.js").then(({ narratePass }) => narratePass(out, trigger)).then((r) => { if (r && "skipped" in r) log(`narrate: ${r.skipped}`); }).catch((e: any) => log(`narrate: ${e?.message || e}`));
    return out;
  })().finally(() => { passInFlight = null; });
  return passInFlight;
}

/** What the pass would propose right now, without touching the ledger. */
export async function previewActions(): Promise<{ proposals: Proposal[]; notes: string[]; errors: string[] }> {
  const out = { proposals: [] as Proposal[], notes: [] as string[], errors: [] as string[] };
  let creds: Creds;
  try { creds = executorCreds(); } catch (e: any) { out.errors.push(e?.message || String(e)); return out; }
  for (const mod of modules.values()) {
    try { const p = await mod.plan(creds, () => {}); out.proposals.push(...p.proposals); out.notes.push(...p.notes.map((n) => `${mod.kind}: ${n}`)); }
    catch (e) { out.errors.push(`${mod.kind}: ${describeError(e, `${mod.kind} plan`)}`); }
  }
  return out;
}

// ---- Sphinx ---------------------------------------------------------------------------------------------------------

/** How long a fresh proposal still has to wait before the pass may apply it (0 when the module has no grace period). */
export function graceLeftMs(row: Pick<ActionRow, "created_at">, graceHours: number, now = Date.now()): number {
  if (!graceHours) return 0;
  const created = new Date(row.created_at.includes("T") ? row.created_at : row.created_at.replace(" ", "T") + "Z").getTime();
  return Math.max(0, created + graceHours * 3600000 - now);
}

export function formatProposalMessage(r: Pick<ActionRow, "id" | "title" | "reason" | "rollback" | "est_usd_month"> & { check?: ProposalCheck | null }, graceHours: number, mode: string, publicUrl: string): string {
  const lines = [`📋 Auto-action planned · ${r.title}`, r.reason];
  if (r.est_usd_month != null && r.est_usd_month > 0) lines.push(`≈ ${r.est_usd_month.toFixed(2)} USD/month`);
  const jev = checkLine(r.check); if (jev) lines.push(jev);
  lines.push(mode === "apply" ? `It happens in about ${graceHours} h unless someone objects: tag the resource advisor:hands-off, or say so here.` : `Dry run: nothing happens unless someone presses Apply on the page.`);
  if (r.rollback) lines.push(`Undo afterwards: ${r.rollback}`);
  lines.push(`${publicUrl}/actions?id=${r.id}`);
  return lines.join("\n");
}

async function announceProposal(row: ActionRow, graceHours: number, mode: string): Promise<void> {
  if (!notifyConfigured() || config.notifyLevel === "off") return;
  try { const res = await sendSphinx(formatProposalMessage(row, graceHours, mode, config.notifyLinkUrl)); console.log(`[executor] announced #${row.id}: ${res.ok ? "sent" : `${res.status} ${res.body.slice(0, 80)}`}`); }
  catch (e: any) { console.log(`[executor] announce #${row.id} failed: ${e?.message || e}`); }
}

const ICON: Record<string, string> = { applied: "⚙️", verified: "✅", failed: "❌", reverted: "↩️" };

export function formatActionMessage(r: Pick<ActionRow, "id" | "status" | "kind" | "title" | "reason" | "rollback" | "result" | "error" | "est_usd_month"> & { check?: ProposalCheck | null }, publicUrl: string): string {
  const head = r.status === "failed" ? "Auto-action failed" : r.status === "reverted" ? "Auto-action reverted" : r.status === "verified" ? "Auto-action applied and verified" : "Auto-action applied";
  const lines = [`${ICON[r.status] || "⚙️"} ${head} · ${r.title}`, r.reason];
  if (r.est_usd_month != null && r.est_usd_month > 0) lines.push(`≈ ${r.est_usd_month.toFixed(2)} USD/month`);
  const jev = checkLine(r.check); if (jev) lines.push(jev);
  if (r.status === "failed" && r.error) lines.push(`Error: ${r.error}`);
  else if (r.rollback && r.status !== "reverted") lines.push(`Undo: ${r.rollback} (button on the page)`);
  lines.push(`${publicUrl}/actions?id=${r.id}`);
  return lines.join("\n");
}

/** Posts every applied, verified, failed or reverted row that has no receipt yet; waits through quiet hours. */
export async function dispatchActionNotifications(): Promise<{ sent: number; skipped: number; failed: number; waiting: number }> {
  const out = { sent: 0, skipped: 0, failed: 0, waiting: 0 };
  const rows = db.prepare("select * from actions where status in ('applied', 'verified', 'failed', 'reverted') and notified_at is null order by id").all().map(rowOf);
  if (!rows.length) return out;
  const mark = (id: number, result: string) => db.prepare("update actions set notified_at = datetime('now'), notify_result = ? where id = ?").run(result, id);
  if (!notifyConfigured()) { for (const r of rows) { mark(r.id, "skipped: Sphinx bot not configured"); out.skipped++; } return out; }
  if (config.notifyLevel === "off") { for (const r of rows) { mark(r.id, "skipped: notifications off"); out.skipped++; } return out; }
  if (inQuietHours(config.notifyQuietHours, new Date().getHours())) { out.waiting = rows.length; return out; }
  for (const r of rows) {
    try {
      const res = await sendSphinx(formatActionMessage(r, config.notifyLinkUrl));
      if (res.ok) { mark(r.id, "sent"); out.sent++; } else { mark(r.id, `failed: ${res.status} ${res.body.slice(0, 120)}`); out.failed++; }
    } catch (e: any) { mark(r.id, `failed: ${e?.message || e}`.slice(0, 200)); out.failed++; }
  }
  return out;
}

/** The Auto-actions page header: mode, role, who it acts as, the modules and their labels. */
export async function executorStatus(): Promise<{ mode: string; role_arn: string; cron: string; identity: { ok: boolean; arn?: string; error?: string }; modules: { kind: string; label: string }[]; counts: Record<string, number>; capabilities: Record<string, Capability>; capabilities_note?: string; paused: PauseState }> {
  const identity = config.actRoleArn ? await actuatorIdentity() : { ok: false as const, error: "no actuator role configured: dry runs only" };
  const cap = identity.ok ? await actuatorCapabilities() : { caps: computeCapabilities(null, learnedDenials()), note: undefined };
  return { mode: config.actMode, role_arn: config.actRoleArn, cron: config.actCron, identity, modules: actionModules().map((m) => ({ kind: m.kind, label: m.label })), counts: listActions({ page_size: 1 }).counts, capabilities: cap.caps, capabilities_note: cap.note, paused: pauseState() };
}

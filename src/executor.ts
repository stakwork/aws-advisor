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
import type { AwsCredentialIdentityProvider } from "@aws-sdk/types";
import { config } from "./config.js";
import { db } from "./db.js";
import { sdkCredentials } from "./steampipe.js";
import { describeError } from "./permissions.js";
import { configured as notifyConfigured, inQuietHours, noteDecision, sendSphinx } from "./notify.js";
import { canonicalResource } from "./resource_id.js";

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

export type ActionKind = "acu_window" | "snapshot_archive" | "ebs_iops_trim" | "log_retention" | "s3_request_metrics" | "aurora_storage" | "s3_lifecycle" | "ebs_gp3_migrate" | "ecr_lifecycle" | "swarm_park";
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
}

export interface ActionRow {
  id: number; kind: ActionKind; resource: string; resource_name: string | null; region: string | null; dedupe: string; status: ActionStatus; mode: string; trigger: string;
  title: string; reason: string; before: any; after: any; facts: any; rollback: string | null; est_usd_month: number | null; result: string | null; error: string | null;
  created_at: string; seen_at: string; applied_at: string | null; verified_at: string | null; reverted_at: string | null; notified_at: string | null; notify_result: string | null;
}

export interface Creds {
  /** The advisor's read credentials: every plan and verify. */
  read: AwsCredentialIdentityProvider;
  /** The actuator role, assumed from the read credentials; throws NoActuator when none is configured. */
  act: () => AwsCredentialIdentityProvider;
  region: string;
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
    if (r.changes) { n++; console.log(`[executor] recommendation #${recId} marked done: ${reason}`); try { noteDecision(recId, "done", "executor"); } catch { /* notification only */ } }
  }
  return n;
}

function closeRecommendation(row: ActionRow): void {
  const ids = [Number(row.facts?.recommendation_id), ...(Array.isArray(row.facts?.recommendation_ids) ? row.facts.recommendation_ids.map(Number) : [])].filter((n, i, a) => n > 0 && a.indexOf(n) === i);
  for (const recId of ids) {
    const r = db.prepare("update recommendations set status = 'done', decided_at = datetime('now'), decided_by = 'executor', decision_reason = ?, updated_at = datetime('now') where id = ? and status = 'approved'")
      .run(`applied by the executor: auto-action #${row.id} (${row.title})`, recId);
    if (r.changes) { console.log(`[executor] recommendation #${recId} marked done by #${row.id}`); try { noteDecision(recId, "done", "executor"); } catch { /* notification only */ } }
  }
}

// ---- credentials ------------------------------------------------------------------------------------------------

export function executorCreds(): Creds {
  const base = sdkCredentials();
  const roleArn = config.actRoleArn;
  let actProvider: AwsCredentialIdentityProvider | null = null;
  return {
    read: base.provider,
    region: base.region,
    act: () => {
      if (!roleArn) throw new NoActuator("no actuator role is configured (Settings > Auto-actions > Actuator role ARN); nothing can be applied");
      if (!actProvider) actProvider = fromTemporaryCredentials({ masterCredentials: base.provider, params: { RoleArn: roleArn, RoleSessionName: "aws-advisor-act", DurationSeconds: 900 }, clientConfig: { region: base.region } });
      return actProvider;
    },
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

// ---- the ledger ---------------------------------------------------------------------------------------------------

const safeJson = (s: string | null) => { if (!s) return null; try { return JSON.parse(s); } catch { return null; } };
const rowOf = (r: any): ActionRow => ({ ...r, before: safeJson(r.before_json), after: safeJson(r.after_json), facts: safeJson(r.facts_json), before_json: undefined, after_json: undefined, facts_json: undefined });

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

const proposalOf = (r: ActionRow): Proposal => ({ kind: r.kind, resource: r.resource, resource_name: r.resource_name, region: r.region || "us-east-1", dedupe: r.dedupe, title: r.title, reason: r.reason, before: r.before || {}, after: r.after || {}, facts: r.facts || {}, rollback: r.rollback || "", est_usd_month: r.est_usd_month });

const FAILURES_BEFORE_REFUSING = 3;

/** Records a proposal: refreshes the open row with the same dedupe, else inserts one. Returns the row and whether it is new. */
function recordProposal(p: Proposal, mode: string, trigger: string): { row: ActionRow; fresh: boolean } {
  const open = db.prepare("select id from actions where dedupe = ? and status = 'proposed' order by id desc limit 1").get(p.dedupe) as { id: number } | undefined;
  const json = { before: JSON.stringify(p.before), after: JSON.stringify(p.after), facts: JSON.stringify(p.facts) };
  if (open) {
    db.prepare("update actions set title = ?, reason = ?, before_json = ?, after_json = ?, facts_json = ?, rollback = ?, est_usd_month = ?, resource_name = ?, seen_at = datetime('now'), mode = ? where id = ?")
      .run(p.title, p.reason, json.before, json.after, json.facts, p.rollback, p.est_usd_month ?? null, p.resource_name ?? null, mode, open.id);
    return { row: getAction(open.id)!, fresh: false };
  }
  const id = Number(db.prepare(`insert into actions(kind, resource, resource_name, region, dedupe, status, mode, trigger, title, reason, before_json, after_json, facts_json, rollback, est_usd_month)
    values (?, ?, ?, ?, ?, 'proposed', ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(p.kind, p.resource, p.resource_name ?? null, p.region, p.dedupe, mode, trigger, p.title, p.reason, json.before, json.after, json.facts, p.rollback, p.est_usd_month ?? null).lastInsertRowid);
  return { row: getAction(id)!, fresh: true };
}

/** Open proposals of a kind that this pass did not propose again no longer apply (the hour moved on, the snapshot is gone). */
function closeStale(kind: ActionKind, keep: Set<string>): number {
  const open = db.prepare("select id, dedupe from actions where kind = ? and status = 'proposed'").all(kind) as { id: number; dedupe: string }[];
  let n = 0;
  for (const o of open) if (!keep.has(o.dedupe)) { db.prepare("update actions set status = 'stale', result = 'no longer proposed by the latest pass' where id = ?").run(o.id); n++; }
  return n;
}

const recentFailures = (dedupe: string) => (db.prepare("select count(*) as n from actions where dedupe = ? and status = 'failed' and datetime(created_at) > datetime('now', '-1 day')").get(dedupe) as { n: number }).n;

// ---- apply / verify / revert ------------------------------------------------------------------------------------

/**
 * Applies one ledger row: the change under the actuator role, then the read-back. The row's status tells what
 * happened; the function never throws for an AWS failure (that is a `failed` row), only for a bad id or state.
 */
export async function applyAction(id: number, trigger = "manual"): Promise<ActionRow> {
  const row = getAction(id); if (!row) throw new Error(`no action #${id}`);
  if (row.status !== "proposed") throw new Error(`action #${id} is ${row.status}, not proposed`);
  if (config.actMode === "off") throw new Error("auto-actions are off (Settings > Auto-actions > Mode)");
  const mod = modules.get(row.kind); if (!mod) throw new Error(`no module for ${row.kind}`);
  if (recentFailures(row.dedupe) >= FAILURES_BEFORE_REFUSING) {
    db.prepare("update actions set status = 'refused', error = ?, trigger = ? where id = ?").run(`failed ${FAILURES_BEFORE_REFUSING} times in the last day; not retried until tomorrow`, trigger, id);
    return getAction(id)!;
  }
  const p = proposalOf(row);
  let creds: Creds;
  try { creds = executorCreds(); creds.act(); }
  catch (e: any) { db.prepare("update actions set status = 'refused', error = ?, trigger = ? where id = ?").run(e?.message || String(e), trigger, id); return getAction(id)!; }
  console.log(`[executor] applying #${id} ${row.kind} ${row.resource}: ${row.title}`);
  try {
    const result = await mod.apply(p, creds);
    db.prepare("update actions set status = 'applied', mode = 'apply', trigger = ?, result = ?, error = null, applied_at = datetime('now') where id = ?").run(trigger, result, id);
  } catch (e) {
    const error = describeError(e, `${row.kind} ${row.resource}`);
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
  try {
    const v = await mod.verify(proposalOf(row), creds || executorCreds());
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
  const mod = modules.get(row.kind); if (!mod) throw new Error(`no module for ${row.kind}`);
  const creds = executorCreds(); creds.act();
  console.log(`[executor] reverting #${id} ${row.kind} ${row.resource} (${by})`);
  try {
    const result = await mod.revert(proposalOf(row), creds);
    db.prepare("update actions set status = 'reverted', reverted_at = datetime('now'), result = coalesce(result, '') || ' · reverted: ' || ?, notified_at = null, notify_result = null where id = ?").run(result, id);
  } catch (e) {
    const error = describeError(e, `${row.kind} revert ${row.resource}`);
    db.prepare("update actions set error = ? where id = ?").run(`revert failed: ${error}`, id);
    throw new Error(error);
  }
  return getAction(id)!;
}

// ---- the pass -----------------------------------------------------------------------------------------------------

export interface PassResult { mode: string; proposed: number; fresh: number; applied: number; verified: number; failed: number; refused: number; stale: number; notes: string[]; errors: string[]; took_ms: number }

let passInFlight: Promise<PassResult> | null = null;

/** One executor pass: every module plans, the ledger is updated, and in apply mode the proposals are applied up to the cap. */
export function runExecutorPass(trigger = "schedule"): Promise<PassResult> {
  if (passInFlight) return passInFlight;
  passInFlight = (async () => {
    const t0 = Date.now();
    const mode = config.actMode;
    const out: PassResult = { mode, proposed: 0, fresh: 0, applied: 0, verified: 0, failed: 0, refused: 0, stale: 0, notes: [], errors: [], took_ms: 0 };
    const log = (l: string) => console.log(`[executor] ${l}`);
    if (mode === "off") { out.notes.push("mode off: nothing planned"); out.took_ms = Date.now() - t0; return out; }
    let creds: Creds;
    try { creds = executorCreds(); } catch (e: any) { out.errors.push(e?.message || String(e)); out.took_ms = Date.now() - t0; return out; }
    // Rows applied earlier and still unverified (a snapshot still archiving) get read back first.
    for (const r of db.prepare("select id from actions where status = 'applied' order by id").all() as { id: number }[]) { const v = await verifyAction(r.id, creds); if (v.status === "verified") out.verified++; }
    const budget = { left: Math.max(1, config.actMaxPerPass) };
    for (const mod of modules.values()) {
      let plan: PlanResult;
      try { plan = await mod.plan(creds, (l) => log(`${mod.kind}: ${l}`)); }
      catch (e) { const m = describeError(e, `${mod.kind} plan`); out.errors.push(`${mod.kind}: ${m}`); log(`${mod.kind}: plan failed: ${m}`); continue; }
      out.notes.push(...plan.notes.map((n) => `${mod.kind}: ${n}`));
      const keep = new Set<string>();
      for (const p of plan.proposals) {
        keep.add(p.dedupe);
        const { row, fresh } = recordProposal(p, mode, trigger);
        out.proposed++; if (fresh) out.fresh++;
        log(`${fresh ? "proposed" : "still proposed"} #${row.id} ${p.title}${p.est_usd_month != null ? ` (≈ ${p.est_usd_month.toFixed(2)} USD/month)` : ""}`);
        if (fresh && mod.announce) announceProposal(row, mod.grace_hours?.() ?? 0, mode).catch(() => {});
        if (mode !== "apply") continue;
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
      out.stale += closeStale(mod.kind, keep);
    }
    out.took_ms = Date.now() - t0;
    log(`${mode}: ${out.proposed} proposed (${out.fresh} new), ${out.applied} applied, ${out.verified} verified, ${out.failed} failed, ${out.refused} refused, ${out.stale} stale in ${out.took_ms} ms${out.errors.length ? `; errors: ${out.errors.join("; ")}` : ""}`);
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

export function formatProposalMessage(r: Pick<ActionRow, "id" | "title" | "reason" | "rollback" | "est_usd_month">, graceHours: number, mode: string, publicUrl: string): string {
  const lines = [`📋 Auto-action planned · ${r.title}`, r.reason];
  if (r.est_usd_month != null && r.est_usd_month > 0) lines.push(`≈ ${r.est_usd_month.toFixed(2)} USD/month`);
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

export function formatActionMessage(r: Pick<ActionRow, "id" | "status" | "kind" | "title" | "reason" | "rollback" | "result" | "error" | "est_usd_month">, publicUrl: string): string {
  const head = r.status === "failed" ? "Auto-action failed" : r.status === "reverted" ? "Auto-action reverted" : r.status === "verified" ? "Auto-action applied and verified" : "Auto-action applied";
  const lines = [`${ICON[r.status] || "⚙️"} ${head} · ${r.title}`, r.reason];
  if (r.est_usd_month != null && r.est_usd_month > 0) lines.push(`≈ ${r.est_usd_month.toFixed(2)} USD/month`);
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
export async function executorStatus(): Promise<{ mode: string; role_arn: string; cron: string; identity: { ok: boolean; arn?: string; error?: string }; modules: { kind: string; label: string }[]; counts: Record<string, number> }> {
  const identity = config.actRoleArn ? await actuatorIdentity() : { ok: false as const, error: "no actuator role configured: dry runs only" };
  return { mode: config.actMode, role_arn: config.actRoleArn, cron: config.actCron, identity, modules: actionModules().map((m) => ({ kind: m.kind, label: m.label })), counts: listActions({ page_size: 1 }).counts };
}

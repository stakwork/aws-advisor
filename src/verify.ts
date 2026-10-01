/**
 * Seven days after a decision, was the saving real? For every actioned recommendation (approved, or marked done)
 * the job pulls the daily cost of the lines its action moves (src/verify_math.ts) from Cost Explorer, compares
 * before and after, and stores the verdict together with the daily series, so the bill's shape around the
 * decision can be shown (impactFor). It also asks the inventory whether the action was applied where that is observable (an
 * instance gone, a type changed). Re-checked daily until 30 days after the decision; the latest row wins.
 */
import { db } from "./db.js";
import { S, query } from "./steampipe.js";
import { credentialGate } from "./gate.js";
import { describeError } from "./permissions.js";
import { mergeRecommendations } from "./paging.js";
import { CostScope, DAYS_BEFORE, DailyCost, MIN_DAYS_AFTER, SKIP_DAYS_AFTER_DECISION, Verification, actionCostScope, addDays, costScopeFor, verify } from "./verify_math.js";
import { queueRecommendationEvent } from "./notify.js";
import { mirrorActionsInBackground } from "./graph_mirror.js";

db.exec(`create table if not exists verifications (
  id integer primary key autoincrement,
  recommendation_id integer not null,
  checked_at text not null default (datetime('now')),
  decided_day text not null, days_after integer not null,
  scope_service text, scope_usage text, scope_note text,
  verdict text not null, before_usd_day real, after_usd_day real, realised_usd_month real, estimate_usd_month real, ratio real,
  applied text, note text
);
create index if not exists verifications_rec on verifications(recommendation_id, id)`);
// the daily series behind the verdict arrived with the impact chart; older databases get the column here
if (!(db.pragma("table_info(verifications)") as { name: string }[]).some((c) => c.name === "series")) db.exec("alter table verifications add column series text");

// The executor's changes (src/executor.ts) measured the same way: one row per action kind and resource, keyed
// `kind:resource`, the decision day being the first time the executor applied it.
db.exec(`create table if not exists action_verifications (
  id integer primary key autoincrement,
  action_key text not null, action_id integer not null,
  checked_at text not null default (datetime('now')),
  decided_day text not null, days_after integer not null,
  scope_service text, scope_usage text, scope_note text,
  verdict text not null, before_usd_day real, after_usd_day real, realised_usd_month real, estimate_usd_month real, ratio real,
  note text, series text
);
create index if not exists action_verifications_key on action_verifications(action_key, id)`);

/** Statuses that mean the team acted on the recommendation, so the bill should show it. */
export const ACTIONED = ["approved", "done"] as const;

const MAX_DAYS_AFTER = 30;
const lit = (s: string) => `'${String(s).replace(/'/g, "''")}'`;

export interface VerifyResult { checked: number; verified: number; too_early: number; skipped: number; errors: string[]; took_ms: number }

/** Whether the inventory shows the action done: gone, stopped, retyped. null = not observable. */
function appliedFromInventory(rec: any): string | null {
  const ec2 = db.prepare("select state, gone, instance_type from inventory_ec2 where instance_id = ?").get(rec.resource) as any;
  switch (rec.action_type) {
    case "terminate_stopped_instance": return ec2 ? (ec2.gone ? "yes: instance gone" : `no: instance still ${ec2.state}`) : null;
    case "stop_instance": return ec2 ? (ec2.state === "stopped" || ec2.gone ? `yes: ${ec2.gone ? "gone" : "stopped"}` : `no: still ${ec2.state}`) : null;
    case "rightsize_instance": case "migrate_to_graviton": {
      if (!ec2) return null;
      let ev: any = {}; try { ev = JSON.parse(rec.evidence || "{}"); } catch { /* ignore */ }
      const was = ev.instance_type || ev.current_sku || null;
      return was ? (ec2.instance_type !== was ? `yes: ${was} -> ${ec2.instance_type}` : `no: still ${was}`) : null;
    }
    default: return null;
  }
}

/** Ledger kinds that change no cost line by themselves: a tag, a setting, a relaunch. They are not listed as impact. */
const NO_IMPACT_KINDS = new Set(["consent_tag", "usage_schedule", "s3_request_metrics", "ec2_hibernate_migrate"]);

/** One auto-action as a decision: every applied ledger row of one kind on one resource, from its first application. */
export interface ActionDecision {
  key: string; kind: string; resource: string; resource_name: string | null; title: string; action_id: number; applies: number;
  first_applied: string; last_status: string; est_usd_month: number | null; instance_type: string | null; recommendation_ids: number[];
}

/** The executor's applied changes, grouped by kind and resource; the latest row names the group. */
export function actionDecisions(): ActionDecision[] {
  // the ledger is created by src/executor.ts; a process that never loaded it has nothing to measure
  if (!db.prepare("select 1 from sqlite_master where type = 'table' and name = 'actions'").get()) return [];
  const rows = db.prepare(`select a.id, a.kind, a.resource, a.resource_name, a.title, a.status, a.est_usd_month, a.applied_at, a.facts_json, i.instance_type as inv_type
    from actions a left join inventory_ec2 i on i.instance_id = a.resource where a.applied_at is not null order by a.id`).all() as any[];
  const out = new Map<string, ActionDecision>();
  for (const r of rows) {
    if (NO_IMPACT_KINDS.has(r.kind)) continue;
    let facts: any = {}; try { facts = JSON.parse(r.facts_json || "{}"); } catch { /* none */ }
    const key = `${r.kind}:${r.resource}`;
    const recIds = [Number(facts.recommendation_id), ...(Array.isArray(facts.recommendation_ids) ? facts.recommendation_ids.map(Number) : [])].filter((n) => n > 0);
    const g = out.get(key);
    if (!g) { out.set(key, { key, kind: r.kind, resource: r.resource, resource_name: r.resource_name ?? null, title: r.title, action_id: r.id, applies: 1, first_applied: r.applied_at, last_status: r.status, est_usd_month: r.est_usd_month ?? null, instance_type: facts.instance_type ?? r.inv_type ?? null, recommendation_ids: recIds }); continue; }
    g.applies++; g.action_id = r.id; g.title = r.title; g.last_status = r.status; g.resource_name = r.resource_name ?? g.resource_name;
    if (r.est_usd_month != null) g.est_usd_month = r.est_usd_month;
    for (const id of recIds) if (!g.recommendation_ids.includes(id)) g.recommendation_ids.push(id);
  }
  return [...out.values()];
}

export async function runVerifications(opts: { force?: boolean; ids?: number[]; onLog?: (s: string) => void } = {}): Promise<VerifyResult> {
  const t0 = Date.now(); const log = opts.onLog || (() => {});
  const out: VerifyResult = { checked: 0, verified: 0, too_early: 0, skipped: 0, errors: [], took_ms: 0 };
  const gate = await credentialGate("verify");
  if (!gate.ok) { out.errors.push(gate.error || "credentials not working"); out.took_ms = Date.now() - t0; return out; }
  const today = new Date().toISOString().slice(0, 10);
  const recs = db.prepare(`select r.*, i.instance_type as inv_type, i.region as inv_region from recommendations r left join inventory_ec2 i on i.instance_id = r.resource
    where r.status in ('approved', 'done') and r.decided_at is not null and r.action_type <> 'security_fix' ${opts.ids?.length ? `and r.id in (${opts.ids.map(() => "?").join(",")})` : ""} order by r.decided_at`).all(...(opts.ids || [])) as any[];
  const ins = db.prepare(`insert into verifications(recommendation_id, decided_day, days_after, scope_service, scope_usage, scope_note, verdict, before_usd_day, after_usd_day, realised_usd_month, estimate_usd_month, ratio, applied, note, series)
    values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
  const cache = new Map<string, DailyCost[]>();
  for (const rec of recs) {
    const decidedDay = String(rec.decided_at).slice(0, 10);
    const daysAfter = Math.max(0, Math.round((Date.parse(`${today}T00:00:00Z`) - Date.parse(`${decidedDay}T00:00:00Z`)) / 86400e3));
    if (daysAfter > MAX_DAYS_AFTER && !opts.force) { out.skipped++; continue; }
    out.checked++;
    const scope = costScopeFor(rec.action_type, { instance_type: rec.inv_type });
    const applied = appliedFromInventory(rec);
    if (!scope) {
      ins.run(rec.id, decidedDay, daysAfter, null, null, null, "not_verifiable", null, null, null, rec.est_monthly_saving, null, applied, `no cost line moves for ${rec.action_type}`, null);
      out.skipped++; continue;
    }
    let rows: DailyCost[];
    try { rows = await costRows(scope, cache); }
    catch (e) { out.errors.push(describeError(e, `verification of #${rec.id} (aws_cost_by_service_usage_type_daily)`)); continue; }
    const v: Verification = verify(rows, decidedDay, rec.est_monthly_saving, today, { early: opts.force });
    const series = rows.filter((r) => r.day >= addDays(decidedDay, -DAYS_BEFORE));
    ins.run(rec.id, decidedDay, daysAfter, scope.service, scope.usage_like.join(","), scope.note, v.verdict, v.before_usd_day, v.after_usd_day, v.realised_usd_month, v.estimate_usd_month, v.ratio, applied, v.note, JSON.stringify(series));
    if (v.verdict === "too_early") out.too_early++; else out.verified++;
    // A measured verdict goes to the Sphinx chat once per verdict (src/notify.ts); the same verdict tomorrow stays quiet.
    if (["realised", "partial", "none", "increase"].includes(v.verdict)) queueRecommendationEvent(rec.id, "verified", { verdict: { verdict: v.verdict, realised_usd_month: v.realised_usd_month, estimate_usd_month: v.estimate_usd_month, ratio: v.ratio, days_after: daysAfter, note: v.note }, dedupe: `verified:${rec.id}:${v.verdict}` });
    log(`#${rec.id} ${rec.action_type} ${rec.resource}: ${v.verdict}${v.realised_usd_month != null ? ` ${v.realised_usd_month} USD/mo of ${rec.est_monthly_saving ?? "?"}` : ""}${applied ? ` · applied ${applied}` : ""}`);
  }
  // The executor's changes: the same before/after reading of the bill, from the first time each was applied. One
  // that carries out an approved recommendation is measured there already and is not counted twice.
  if (!opts.ids?.length) {
    const actioned = new Set((db.prepare("select id from recommendations where status in ('approved', 'done')").all() as { id: number }[]).map((r) => r.id));
    const insA = db.prepare(`insert into action_verifications(action_key, action_id, decided_day, days_after, scope_service, scope_usage, scope_note, verdict, before_usd_day, after_usd_day, realised_usd_month, estimate_usd_month, ratio, note, series)
      values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
    const measuredActionIds: number[] = [];
    for (const a of actionDecisions()) {
      if (a.recommendation_ids.some((id) => actioned.has(id))) continue;
      const decidedDay = String(a.first_applied).slice(0, 10);
      const daysAfter = Math.max(0, Math.round((Date.parse(`${today}T00:00:00Z`) - Date.parse(`${decidedDay}T00:00:00Z`)) / 86400e3));
      if (daysAfter > MAX_DAYS_AFTER && !opts.force) { out.skipped++; continue; }
      out.checked++;
      const scope = actionCostScope(a.kind, { instance_type: a.instance_type });
      if (!scope) { insA.run(a.key, a.action_id, decidedDay, daysAfter, null, null, null, "not_verifiable", null, null, null, a.est_usd_month, null, `no cost line moves for ${a.kind}`, null); out.skipped++; continue; }
      let rows: DailyCost[];
      try { rows = await costRows(scope, cache); }
      catch (e) { out.errors.push(describeError(e, `verification of auto-action ${a.key} (aws_cost_by_service_usage_type_daily)`)); continue; }
      const v: Verification = verify(rows, decidedDay, a.est_usd_month, today, { early: opts.force });
      const series = rows.filter((r) => r.day >= addDays(decidedDay, -DAYS_BEFORE));
      insA.run(a.key, a.action_id, decidedDay, daysAfter, scope.service, scope.usage_like.join(","), scope.note, v.verdict, v.before_usd_day, v.after_usd_day, v.realised_usd_month, v.estimate_usd_month, v.ratio, a.last_status === "reverted" ? `${v.note ? `${v.note}; ` : ""}reverted since` : v.note, JSON.stringify(series));
      if (v.verdict === "too_early") out.too_early++; else { out.verified++; measuredActionIds.push(a.action_id); }
      log(`auto ${a.key}: ${v.verdict}${v.realised_usd_month != null ? ` ${v.realised_usd_month} USD/mo of ${a.est_usd_month ?? "?"}` : ""}`);
    }
    db.prepare("delete from action_verifications where id not in (select max(id) from action_verifications group by action_key, date(checked_at))").run();
    // the verdicts ride on the AdvisorAction nodes (bill_verdict, realised_usd_month)
    if (measuredActionIds.length) mirrorActionsInBackground(measuredActionIds);
  }
  // keep one row per recommendation per day
  db.prepare("delete from verifications where id not in (select max(id) from verifications group by recommendation_id, date(checked_at))").run();
  out.took_ms = Date.now() - t0;
  log(`${out.checked} checked: ${out.verified} verified, ${out.too_early} too early, ${out.skipped} skipped, ${out.took_ms} ms`);
  return out;
}

/** The daily cost of one scope over the verification window, read once per scope per run. */
async function costRows(scope: CostScope, cache: Map<string, DailyCost[]>): Promise<DailyCost[]> {
  const key = `${scope.service}|${scope.usage_like.join(",")}`;
  const hit = cache.get(key);
  if (hit) return hit;
  const q = await query<{ day: string; usd: string | null }>(`select to_char(period_start at time zone 'UTC', 'YYYY-MM-DD') as day, sum(net_unblended_cost_amount) as usd
    from ${S}.aws_cost_by_service_usage_type_daily where service = ${lit(scope.service)} and (${scope.usage_like.map((u) => `usage_type like ${lit(u)}`).join(" or ")})
      and period_start >= now() - interval '${MAX_DAYS_AFTER + 20} days' and period_start < date_trunc('day', now()) group by 1 order by 1`);
  const rows = q.map((r) => ({ day: r.day, usd: Number(r.usd || 0) }));
  cache.set(key, rows);
  return rows;
}

export function latestVerification(recommendationId: number) {
  const row = db.prepare("select * from verifications where recommendation_id = ? order by id desc limit 1").get(recommendationId) as any | null;
  if (row) { const { series, ...rest } = row; return rest; }
  return row;
}

/**
 * The bill around one decision: the daily cost of the lines the action moves (the verification's scope) from
 * fourteen days before the decision to the latest complete day, with the before and after medians the verdict
 * came from, and the account's total daily spend over the same days for context. Null until the verification
 * has run; a scope-less action (a permission, a flow log) carries no series.
 */
export function impactFor(recommendationId: number) {
  const rec = db.prepare("select id, title, status, action_type, resource, resource_name, est_monthly_saving, decided_at, decided_by from recommendations where id = ?").get(recommendationId) as any;
  if (!rec) return null;
  const v = db.prepare("select * from verifications where recommendation_id = ? order by id desc limit 1").get(recommendationId) as any | null;
  if (!v) return { recommendation: rec, verification: null, series: [], total: [], decided_day: rec.decided_at ? String(rec.decided_at).slice(0, 10) : null, after_from: null, actioned: (ACTIONED as readonly string[]).includes(rec.status) };
  let series: DailyCost[] = []; try { series = JSON.parse(v.series || "[]"); } catch { /* an older row without a series */ }
  const from = addDays(v.decided_day, -DAYS_BEFORE);
  const total = db.prepare("select day, net_unblended as usd from spend_daily where day >= ? order by day").all(from) as DailyCost[];
  const { series: _s, ...verification } = v;
  return { recommendation: rec, verification, series, total, decided_day: v.decided_day, after_from: addDays(v.decided_day, SKIP_DAYS_AFTER_DECISION), actioned: (ACTIONED as readonly string[]).includes(rec.status) };
}

/**
 * Every decision (approved or done) with its latest verdict, plus totals of claimed vs realised. Rows that propose
 * the same action on the same resource were one decision (the list merges them and Approve covers all of them),
 * so they are one row here too, with the primary's estimate; the others are listed under `merged`.
 */
export function verificationSummary() {
  const all = db.prepare(`select r.id, r.title, r.status, r.source, r.rule, r.action_type, r.resource, r.resource_name, r.est_monthly_saving, r.confidence, r.updated_at, r.decided_at, v.verdict, v.realised_usd_month, v.before_usd_day, v.after_usd_day, v.ratio, v.applied, v.days_after, v.note, v.checked_at, v.scope_note
    from recommendations r left join verifications v on v.id = (select max(id) from verifications where recommendation_id = r.id)
    where r.status in ('approved', 'done') order by r.decided_at desc`).all() as any[];
  const VERDICT_FIELDS = ["verdict", "realised_usd_month", "before_usd_day", "after_usd_day", "ratio", "applied", "days_after", "note", "checked_at", "scope_note"] as const;
  const byId = new Map(all.map((r) => [r.id, r]));
  // The members share one cost scope, so any member's verdict is the decision's verdict; prefer the primary's when it has one.
  const rows = mergeRecommendations(all).map((r) => {
    if (r.verdict) return r;
    const checked = r.merged_ids.map((id: number) => byId.get(id)).find((m: any) => m?.verdict);
    return checked ? { ...r, ...Object.fromEntries(VERDICT_FIELDS.map((f) => [f, checked[f]])), verified_id: checked.id } : r;
  }).sort((a, b) => String(b.decided_at).localeCompare(String(a.decided_at)));
  const decisions = rows.map((r) => ({ ...r, origin: "decision" as const }));
  const auto = autoImpactRows(new Set(decisions.filter((r: any) => r.status === "approved" || r.status === "done").map((r: any) => r.id)));
  const all2 = [...decisions, ...auto].sort((a: any, b: any) => String(b.decided_at).localeCompare(String(a.decided_at)));
  const measured = (r: any) => ["realised", "partial", "none", "increase"].includes(r.verdict);
  const live = (r: any) => r.origin === "decision" || r.status !== "reverted";
  const claimed = all2.filter(live).reduce((s, r: any) => s + (Number(r.est_monthly_saving) || 0), 0);
  const realised = all2.filter(measured).reduce((s, r: any) => s + (Number(r.realised_usd_month) || 0), 0);
  return {
    approved: decisions.length, auto: auto.length, actioned: all2.length, verified: all2.filter(measured).length,
    pending: all2.filter((r: any) => !r.verdict || r.verdict === "too_early").length,
    claimed_usd_month: Math.round(claimed), realised_usd_month: Math.round(realised),
    decision_claimed_usd_month: Math.round(decisions.reduce((s, r: any) => s + (Number(r.est_monthly_saving) || 0), 0)),
    decision_realised_usd_month: Math.round(decisions.filter(measured).reduce((s, r: any) => s + (Number(r.realised_usd_month) || 0), 0)),
    auto_claimed_usd_month: Math.round(auto.filter(live).reduce((s, r: any) => s + (Number(r.est_monthly_saving) || 0), 0)),
    auto_realised_usd_month: Math.round(auto.filter(measured).reduce((s, r: any) => s + (Number(r.realised_usd_month) || 0), 0)),
    rows: all2, min_days_after: MIN_DAYS_AFTER,
  };
}
/** The executor's changes as impact rows, with their latest verdict; one carrying out an actioned recommendation is that recommendation's row. */
export function autoImpactRows(actionedRecIds: Set<number>) {
  const latest = db.prepare("select * from action_verifications where action_key = ? order by id desc limit 1");
  return actionDecisions().filter((a) => !a.recommendation_ids.some((id) => actionedRecIds.has(id))).map((a) => {
    const v = latest.get(a.key) as any | undefined;
    return {
      origin: "auto" as const, id: a.action_id, key: a.key, kind: a.kind, title: a.title, status: a.last_status, resource: a.resource, resource_name: a.resource_name,
      est_monthly_saving: a.est_usd_month, decided_at: a.first_applied, applies: a.applies,
      verdict: v?.verdict ?? null, realised_usd_month: v?.realised_usd_month ?? null, before_usd_day: v?.before_usd_day ?? null, after_usd_day: v?.after_usd_day ?? null,
      ratio: v?.ratio ?? null, days_after: v?.days_after ?? null, note: v?.note ?? null, checked_at: v?.checked_at ?? null, scope_note: v?.scope_note ?? null,
    };
  });
}

export { addDays };

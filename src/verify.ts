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
import { DAYS_BEFORE, DailyCost, MIN_DAYS_AFTER, SKIP_DAYS_AFTER_DECISION, Verification, addDays, costScopeFor, verify } from "./verify_math.js";

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

export async function runVerifications(opts: { force?: boolean; ids?: number[]; onLog?: (s: string) => void } = {}): Promise<VerifyResult> {
  const t0 = Date.now(); const log = opts.onLog || (() => {});
  const out: VerifyResult = { checked: 0, verified: 0, too_early: 0, skipped: 0, errors: [], took_ms: 0 };
  const gate = await credentialGate("verify");
  if (!gate.ok) { out.errors.push(gate.error || "credentials not working"); out.took_ms = Date.now() - t0; return out; }
  const today = new Date().toISOString().slice(0, 10);
  const recs = db.prepare(`select r.*, i.instance_type as inv_type, i.region as inv_region from recommendations r left join inventory_ec2 i on i.instance_id = r.resource
    where r.status in ('approved', 'done') and r.decided_at is not null ${opts.ids?.length ? `and r.id in (${opts.ids.map(() => "?").join(",")})` : ""} order by r.decided_at`).all(...(opts.ids || [])) as any[];
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
    const key = `${scope.service}|${scope.usage_like.join(",")}`;
    let rows = cache.get(key);
    if (!rows) {
      try {
        const q = await query<{ day: string; usd: string | null }>(`select to_char(period_start at time zone 'UTC', 'YYYY-MM-DD') as day, sum(net_unblended_cost_amount) as usd
          from ${S}.aws_cost_by_service_usage_type_daily where service = ${lit(scope.service)} and (${scope.usage_like.map((u) => `usage_type like ${lit(u)}`).join(" or ")})
            and period_start >= now() - interval '${MAX_DAYS_AFTER + 20} days' and period_start < date_trunc('day', now()) group by 1 order by 1`);
        rows = q.map((r) => ({ day: r.day, usd: Number(r.usd || 0) }));
        cache.set(key, rows);
      } catch (e) { out.errors.push(describeError(e, `verification of #${rec.id} (aws_cost_by_service_usage_type_daily)`)); continue; }
    }
    const v: Verification = verify(rows, decidedDay, rec.est_monthly_saving, today, { early: opts.force });
    const series = rows.filter((r) => r.day >= addDays(decidedDay, -DAYS_BEFORE));
    ins.run(rec.id, decidedDay, daysAfter, scope.service, scope.usage_like.join(","), scope.note, v.verdict, v.before_usd_day, v.after_usd_day, v.realised_usd_month, v.estimate_usd_month, v.ratio, applied, v.note, JSON.stringify(series));
    if (v.verdict === "too_early") out.too_early++; else out.verified++;
    log(`#${rec.id} ${rec.action_type} ${rec.resource}: ${v.verdict}${v.realised_usd_month != null ? ` ${v.realised_usd_month} USD/mo of ${rec.est_monthly_saving ?? "?"}` : ""}${applied ? ` · applied ${applied}` : ""}`);
  }
  // keep one row per recommendation per day
  db.prepare("delete from verifications where id not in (select max(id) from verifications group by recommendation_id, date(checked_at))").run();
  out.took_ms = Date.now() - t0;
  log(`${out.checked} checked: ${out.verified} verified, ${out.too_early} too early, ${out.skipped} skipped, ${out.took_ms} ms`);
  return out;
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

/** Every actioned recommendation (approved or done) with its latest verdict, plus totals of claimed vs realised. */
export function verificationSummary() {
  const rows = db.prepare(`select r.id, r.title, r.status, r.action_type, r.resource, r.resource_name, r.est_monthly_saving, r.decided_at, v.verdict, v.realised_usd_month, v.before_usd_day, v.after_usd_day, v.ratio, v.applied, v.days_after, v.note, v.checked_at, v.scope_note
    from recommendations r left join verifications v on v.id = (select max(id) from verifications where recommendation_id = r.id)
    where r.status in ('approved', 'done') order by r.decided_at desc`).all() as any[];
  const claimed = rows.reduce((s, r) => s + (Number(r.est_monthly_saving) || 0), 0);
  const realised = rows.filter((r) => ["realised", "partial", "none", "increase"].includes(r.verdict)).reduce((s, r) => s + (Number(r.realised_usd_month) || 0), 0);
  const verified = rows.filter((r) => ["realised", "partial", "none", "increase"].includes(r.verdict)).length;
  return { approved: rows.length, actioned: rows.length, verified, pending: rows.filter((r) => !r.verdict || r.verdict === "too_early").length, claimed_usd_month: Math.round(claimed), realised_usd_month: Math.round(realised), rows, min_days_after: MIN_DAYS_AFTER };
}
export { addDays };

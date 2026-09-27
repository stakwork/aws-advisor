/**
 * A second opinion on every executor proposal, from Jev (purpose proposal_check), before the pass applies it.
 * Three typed questions per proposal: could it destroy something that cannot be recovered, what would users
 * notice, and does it contradict what the team decided or is doing (a rejected recommendation for the same
 * change, an open alert on the resource, another action already on it). The verdict lands on the ledger row
 * (`check_json`) and, in hold mode, a proposal Jev objects to waits for a person: Apply on the page still works,
 * that is the human decision, and the Jev reason goes on record with it.
 *
 * Jev is asked once per distinct change: a proposal refreshed pass after pass keeps its first verdict, and a
 * new row for the same dedupe, account and target state reuses a verdict from the last 30 days (src/executor.ts
 * reusableCheck). Without a key, or when Jev does not answer, the row stays unchecked and the pass proceeds as
 * it always did; the pass notes say so.
 */
import { noul, score } from "@typesafe-ai/sdk";
import { askJev, chunk, jevEnabled } from "./jev.js";
import { db } from "./db.js";
import { SERVICE_IMPACT_LEVELS, TIER_APPROVE_IRREVERSIBLE, TIER_APPROVE_SERVICE_IMPACT } from "./tiercheck.js";
import { resourceRole } from "./roles.js";
import type { ActionRow } from "./executor.js";

export const CHECK_BATCH_SIZE = 20;
export const HOLD_IRREVERSIBLE = TIER_APPROVE_IRREVERSIBLE;
export const HOLD_SERVICE_IMPACT = TIER_APPROVE_SERVICE_IMPACT;
export const HOLD_FITS_RECORD = 0.6;
/** A verdict this old is asked for again rather than reused. */
export const REUSE_DAYS = 30;

export interface ProposalCheck {
  verdict: "proceed" | "hold";
  irreversible: number;
  service_impact: number;
  service_impact_label: string;
  fits_record: number;
  reason: string;
  model: string;
  checked_at: string;
  /** The earlier row this verdict was copied from, when it was not asked for afresh. */
  reused_from?: number;
}

export interface CheckContext {
  /** Kinds whose change cannot be undone by the executor (no revert call, or a grace period because it is a delete). */
  irreversibleKinds: Set<string>;
  /** off = never called; advise = record only; hold = a hold verdict stops the pass from applying the row. */
  mode: "off" | "advise" | "hold";
}

const label = (impact: number) => SERVICE_IMPACT_LEVELS[Math.max(0, Math.min(2, Math.round(impact)))];

/** The policy, pure: which answer makes the verdict a hold, and the one-sentence reason naming the trigger. */
export function verdictFrom(a: { irreversible: number; service_impact: number; fits_record: number }, opts: { irreversibleKind: boolean; mode: "advise" | "hold"; model?: string; now?: Date }): ProposalCheck {
  const triggers: string[] = [];
  if (opts.irreversibleKind && a.irreversible >= HOLD_IRREVERSIBLE) triggers.push(`could destroy something that cannot be recovered (${a.irreversible.toFixed(2)})`);
  if (a.service_impact >= HOLD_SERVICE_IMPACT) triggers.push(`users would notice: ${label(a.service_impact)} (${a.service_impact.toFixed(1)})`);
  if (a.fits_record >= HOLD_FITS_RECORD) triggers.push(`contradicts what the team decided or is doing (${a.fits_record.toFixed(2)})`);
  const hold = triggers.length > 0;
  const reason = hold
    ? `Jev ${opts.mode === "hold" ? "holds" : "advises against"} it: ${triggers.join("; ")}.`
    : `Jev sees no objection (irreversible ${a.irreversible.toFixed(2)}, ${label(a.service_impact).toLowerCase()}, fits the record ${(1 - a.fits_record).toFixed(2)}).`;
  return {
    verdict: hold ? "hold" : "proceed",
    irreversible: a.irreversible, service_impact: a.service_impact, service_impact_label: label(a.service_impact), fits_record: a.fits_record,
    reason, model: opts.model ?? "fixture", checked_at: (opts.now ?? new Date()).toISOString(),
  };
}

/**
 * Picks an earlier verdict a new row may reuse instead of asking Jev again: same dedupe, same account, same
 * target state (after_json), checked within REUSE_DAYS. Newest first. Pure.
 */
export function reusableCheck<T extends { id: number; dedupe: string; account_id: string | null; after_json: string | null; check: ProposalCheck | null }>(
  candidates: T[], row: { id: number; dedupe: string; account_id: string | null; after_json: string | null }, now = Date.now(),
): { from: T; check: ProposalCheck } | null {
  const cutoff = now - REUSE_DAYS * 86400000;
  const same = candidates
    .filter((c) => c.id !== row.id && c.check && c.dedupe === row.dedupe && (c.account_id ?? "") === (row.account_id ?? "") && (c.after_json ?? "") === (row.after_json ?? ""))
    .filter((c) => new Date(c.check!.checked_at).getTime() >= cutoff)
    .sort((a, b) => b.id - a.id);
  if (!same.length) return null;
  const from = same[0];
  const original = from.check!.reused_from ?? from.id;
  return { from, check: { ...from.check!, reused_from: original, reason: `same change as #${original}: ${from.check!.reason.replace(/^same change as #\d+: /, "")}` } };
}

/** Questions for one proposal of a batch; each names its key in the state so Jev answers per proposal. */
export const checkQuestions = (prefix: string) => ({
  [`${prefix}_irreversible`]: noul(`Consider only the change under proposals.${prefix} (ignore the others). Carrying it out could destroy data, an address or a resource that cannot be recovered`),
  [`${prefix}_service_impact`]: score(`Consider only the change under proposals.${prefix} (ignore the others). If it were carried out as described, what would users of the service notice?`, SERVICE_IMPACT_LEVELS),
  [`${prefix}_fits_record`]: noul(`Consider only the change under proposals.${prefix} (ignore the others). Given its context (the team's decisions on this resource, open alerts, other changes in flight), carrying it out contradicts what the team decided or is doing`),
});

const safe = (s: unknown) => { if (typeof s !== "string" || !s) return null; try { return JSON.parse(s); } catch { return s; } };

/** What Jev sees per proposal: the row, and the record around its resource. Cheap reads, every one tolerant of a missing table. */
export function proposalState(r: ActionRow): Record<string, unknown> {
  const q = <T>(f: () => T, fallback: T): T => { try { return f(); } catch { return fallback; } };
  const role = q(() => resourceRole(r.resource), null);
  const alerts = q(() => db.prepare("select id, kind, message, created_at from alerts where resource = ? and acknowledged = 0 order by id desc limit 5").all(r.resource) as any[], []);
  const recs = q(() => db.prepare("select id, rule, title, action_type, status, decided_by, decision_reason from recommendations where resource = ? and status in ('approved', 'rejected', 'pending') order by id desc limit 8").all(r.resource) as any[], []);
  const others = q(() => db.prepare("select id, kind, status, title from actions where resource = ? and kind != ? and status in ('proposed', 'applied', 'verified') and id != ? order by id desc limit 5").all(r.resource, r.kind, r.id) as any[], []);
  return {
    action: r.kind, title: r.title, resource: r.resource, resource_name: r.resource_name, region: r.region, account_id: r.account_id,
    reason: String(r.reason || "").slice(0, 1500), before: r.before, after: r.after, facts: JSON.parse(JSON.stringify(r.facts ?? null, (_k, v) => (typeof v === "string" && v.length > 300 ? v.slice(0, 300) : v))),
    est_monthly_saving_usd: r.est_usd_month, rollback: r.rollback,
    resource_role: role ? { role: role.role, confidence: role.role_confidence, protected_prob: role.protected_prob } : null,
    open_alerts: alerts.map((a) => ({ id: a.id, kind: a.kind, message: String(a.message).slice(0, 200), at: a.created_at })),
    team_decisions_on_resource: recs.map((x) => ({ id: x.id, rule: x.rule, action_type: x.action_type, status: x.status, by: x.decided_by, reason: x.decision_reason ? String(x.decision_reason).slice(0, 300) : null, title: String(x.title).slice(0, 160) })),
    other_changes_on_resource: others.map((o) => ({ id: o.id, action: o.kind, status: o.status, title: String(o.title).slice(0, 160) })),
  };
}

/**
 * Asks Jev about a batch of rows, up to CHECK_BATCH_SIZE per call, and returns a verdict per row id. Rows Jev
 * could not answer for are absent from the map (left unchecked). Never throws; never called when disabled.
 */
export async function checkProposals(rows: ActionRow[], ctx: CheckContext): Promise<{ checks: Map<number, ProposalCheck>; note: string | null }> {
  const checks = new Map<number, ProposalCheck>();
  if (ctx.mode === "off" || !rows.length) return { checks, note: null };
  if (!jevEnabled()) return { checks, note: "Jev is not configured (Settings › Jev): proposals go unchecked" };
  let unanswered = 0;
  for (const batch of chunk(rows, CHECK_BATCH_SIZE)) {
    const state: Record<string, unknown> = {};
    let questions: Record<string, ReturnType<typeof checkQuestions>[string]> = {};
    batch.forEach((r, i) => { state[`p${i}`] = proposalState(r); questions = { ...questions, ...checkQuestions(`p${i}`) }; });
    const res = await askJev({ proposals: state }, questions, { purpose: "proposal_check" });
    if (!res) { unanswered += batch.length; continue; }
    batch.forEach((r, i) => {
      const irr = res.answers[`p${i}_irreversible`] as any, imp = res.answers[`p${i}_service_impact`] as any, fit = res.answers[`p${i}_fits_record`] as any;
      if (irr?.type !== "noul" || imp?.type !== "score" || fit?.type !== "noul") { unanswered++; return; }
      checks.set(r.id, verdictFrom({ irreversible: irr.noul, service_impact: imp.score, fits_record: fit.noul }, { irreversibleKind: ctx.irreversibleKinds.has(r.kind), mode: ctx.mode === "hold" ? "hold" : "advise", model: res.model }));
    });
    console.log(`[jev] proposal_check: ${batch.length} proposal(s) checked, ${[...checks.values()].filter((c) => c.verdict === "hold").length} hold so far (${res.latency_ms} ms, ${res.usage.input_tokens}+${res.usage.output_tokens} tokens)`);
  }
  return { checks, note: unanswered ? `Jev did not answer for ${unanswered} proposal(s): left unchecked` : null };
}

/** The Sphinx line for a checked row. */
export const checkLine = (c: ProposalCheck | null | undefined): string | null => (c ? (c.verdict === "hold" ? `Jev: hold, ${c.reason}` : "Jev: proceed") : null);

/** Safe parse of a stored check_json. */
export const parseCheck = (s: unknown): ProposalCheck | null => { const v = safe(s); return v && typeof v === "object" && (v as any).verdict ? (v as ProposalCheck) : null; };

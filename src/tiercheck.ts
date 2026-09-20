import { noul, score } from "@typesafe-ai/sdk";
import { askJev, chunk, jevEnabled } from "./jev.js";
import { RecInput, Tier } from "./rules.js";

/**
 * Tier safety check with Jev (purpose tier_check) on every recommendation imported from the agent: the
 * findings batch (src/agent.ts) and an incident's fixes (src/investigate.ts). Two questions per fix, could it
 * destroy data or an address that cannot be recovered, and how visible the service impact would be. The
 * answers can only make the tier stricter (auto -> approve -> report), never looser, and are recorded in the
 * recommendation's evidence under `jev`. Without a key the recommendations pass through untouched.
 */

export const SERVICE_IMPACT_LEVELS = ["No user-visible effect", "Brief or degraded", "Outage possible"] as const;
export const TIER_APPROVE_IRREVERSIBLE = 0.6;
export const TIER_APPROVE_SERVICE_IMPACT = 1.5;
export const TIER_REPORT_IRREVERSIBLE = 0.85;
export const TIER_BATCH_SIZE = 40;

const TIER_RANK: Record<Tier, number> = { auto: 0, approve: 1, report: 2 };
const stricter = (a: Tier, b: Tier): Tier => (TIER_RANK[a] >= TIER_RANK[b] ? a : b);

export interface TierCheck {
  irreversible: number;
  service_impact: number;
  service_impact_label: string;
  tier_before: Tier;
  tier_after: Tier;
  model: string;
  checked_at: string;
}

/** The policy: irreversible >= 0.6 or service impact >= 1.5 means at least approve; irreversible >= 0.85 means report. Never loosens. */
export function tightenTier(tier: Tier, a: { irreversible: number; service_impact: number }): Tier {
  let t = tier;
  if (a.irreversible >= TIER_APPROVE_IRREVERSIBLE || a.service_impact >= TIER_APPROVE_SERVICE_IMPACT) t = stricter(t, "approve");
  if (a.irreversible >= TIER_REPORT_IRREVERSIBLE) t = stricter(t, "report");
  return t;
}

/** Questions for one fix of a batch. Each names its key in the state: unscoped questions make Jev answer the batch as a whole. */
export const tierQuestions = (prefix: string) => ({
  [`${prefix}_irreversible`]: noul(`Consider only the change under proposed_changes.${prefix} (ignore the others). Carrying it out could destroy data or an address that cannot be recovered`),
  [`${prefix}_service_impact`]: score(`Consider only the change under proposed_changes.${prefix} (ignore the others). If it were carried out as described, what would users of the service notice?`, SERVICE_IMPACT_LEVELS),
});

/** What Jev sees per fix: the proposal as the agent wrote it, plus the tier it chose. */
export const fixState = (r: RecInput) => ({
  title: r.title, action_type: r.actionType, resource: r.resource, resource_name: r.resourceName ?? null,
  proposed_tier: r.tier, est_monthly_saving_usd: r.estMonthlySaving, rationale: r.rationale.slice(0, 1200),
});

/** Applies a tier check answer to one recommendation: the tier can only get stricter; the check lands in evidence.jev. */
export function applyTierCheck(r: RecInput, a: { irreversible: number; service_impact: number }, model = "fixture"): RecInput {
  const after = tightenTier(r.tier, a);
  const check: TierCheck = { irreversible: a.irreversible, service_impact: a.service_impact, service_impact_label: SERVICE_IMPACT_LEVELS[Math.max(0, Math.min(2, Math.round(a.service_impact)))], tier_before: r.tier, tier_after: after, model, checked_at: new Date().toISOString() };
  const evidence = r.evidence && typeof r.evidence === "object" && !Array.isArray(r.evidence) ? { ...(r.evidence as object), jev: check } : { original: r.evidence, jev: check };
  const note = after !== r.tier ? ` Jev tier check: ${r.tier} -> ${after} (irreversible ${a.irreversible.toFixed(2)}, service impact ${a.service_impact.toFixed(1)}: ${check.service_impact_label}).` : "";
  return { ...r, tier: after, rationale: r.rationale + note, evidence };
}

/**
 * Checks a batch of agent recommendations with Jev, up to 40 per call. Recommendations Jev could not answer
 * for come back unchanged. Returns the (possibly tightened) list in the same order plus how many tiers moved.
 */
export async function checkTiers(recs: RecInput[]): Promise<{ recs: RecInput[]; changed: number; checked: number }> {
  if (!jevEnabled() || !recs.length) return { recs, changed: 0, checked: 0 };
  const out = [...recs];
  let changed = 0, checked = 0;
  let offset = 0;
  for (const batch of chunk(recs, TIER_BATCH_SIZE)) {
    const state: Record<string, unknown> = {};
    let questions: Record<string, ReturnType<typeof tierQuestions>[string]> = {};
    batch.forEach((r, i) => { state[`f${i}`] = fixState(r); questions = { ...questions, ...tierQuestions(`f${i}`) }; });
    const res = await askJev({ proposed_changes: state }, questions, { purpose: "tier_check" });
    if (res) {
      batch.forEach((r, i) => {
        const irr = res.answers[`f${i}_irreversible`] as any;
        const imp = res.answers[`f${i}_service_impact`] as any;
        if (irr?.type !== "noul" || imp?.type !== "score") return;
        const next = applyTierCheck(r, { irreversible: irr.noul, service_impact: imp.score }, res.model);
        if (next.tier !== r.tier) changed++;
        checked++;
        out[offset + i] = next;
      });
      console.log(`[jev] tier_check: ${batch.length} fixes checked, ${changed} tier(s) tightened so far (${res.latency_ms} ms, ${res.usage.input_tokens}+${res.usage.output_tokens} tokens)`);
    }
    offset += batch.length;
  }
  return { recs: out, changed, checked };
}

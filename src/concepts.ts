/**
 * Mirrors every human decision on a recommendation into repo2graph's Concept graph, under the
 * namespace `aws/cost-advisor` with one parent concept ("AWS Cost Decisions") and one child concept
 * per recommendation. The agent reads Concepts natively (list_concepts / learn_concept), and the
 * advisor also lists them into the prompt at dispatch time, so past decisions steer future runs.
 *
 * Source of truth stays in SQLite; this is a one-way export. A concept is deleted and recreated on
 * every decision so its description (which carries the current decision) and embedding stay fresh;
 * the id is a deterministic slug of the name, so it never changes.
 */
import { config } from "./config.js";
import { db } from "./db.js";
import { mirrorRecommendationsInBackground } from "./graph_mirror.js";

export const CONCEPT_NAMESPACE = process.env.CONCEPT_NAMESPACE || "aws/cost-advisor";

/**
 * Two kinds of concept, under two parents:
 *  - internal: a decision about one specific resource in this account ("keep example-node-1, the founder's node").
 *  - generic: reusable knowledge that transfers to any account ("bitcoind nodes are idle on CPU by design;
 *    never treat them as right-size candidates"). Generic concepts are named by role + action, not resource id.
 */
export type ConceptScope = "internal" | "generic";
const PARENTS: Record<ConceptScope, { name: string; id: string; description: string; documentation: string }> = {
  internal: {
    name: "AWS Cost Decisions",
    id: `${CONCEPT_NAMESPACE}/aws-cost-decisions`,
    description: "Decisions the team has taken on specific AWS cost recommendations in this account",
    documentation: "# AWS Cost Decisions\n\nOne child concept per recommendation the team approved, rejected, snoozed or completed. Each is about one specific resource in this account. When a new recommendation resembles one of these, respect the recorded decision unless the situation has changed.",
  },
  generic: {
    name: "AWS Cost Knowledge",
    id: `${CONCEPT_NAMESPACE}/aws-cost-knowledge`,
    description: "Reusable rules learned from cost decisions that apply to any account, e.g. which workload types are idle on CPU by design",
    documentation: "# AWS Cost Knowledge\n\nGeneric rules distilled from team decisions, phrased so they apply to any resource of the same kind in any account. Apply them before proposing anything similar.",
  },
};

db.exec(`
create table if not exists concepts (
  fingerprint text primary key,
  concept_id text not null,
  status text not null,
  synced_at text not null default (datetime('now')),
  error text
);`);
try { db.exec("alter table concepts add column scope text not null default 'internal'"); } catch { /* exists */ }
try { db.exec("alter table recommendations add column decision_scope text"); } catch { /* exists */ }

const enabled = () => Boolean(config.repo2graphUrl);
const headers = () => ({ "content-type": "application/json", "x-api-token": config.repo2graphToken });
const enc = (id: string) => encodeURIComponent(id);
const usd = (v: number | null | undefined) => (v == null ? "unknown" : `${Math.round(Number(v))} USD/month`);
const pct = (v: number | null | undefined) => (v == null ? "unknown" : `${Math.round(Number(v) * 100)}%`);

interface RecRow {
  id: number; fingerprint: string; source: string; rule: string; title: string; resource: string | null;
  resource_name: string | null; action_type: string; est_monthly_saving: number | null; tier: string;
  confidence: number | null; rationale: string | null; evidence: string | null; status: string;
  decided_at: string | null; decided_by: string | null; decision_reason: string | null; run_id: number; updated_at: string;
  decision_scope?: ConceptScope | null;
}

function roleOf(resource: string | null): string | null {
  if (!resource) return null;
  try {
    const row = db.prepare("select role, role_confidence from resource_roles where resource_id = ?").get(resource) as { role: string; role_confidence: number } | undefined;
    return row && row.role_confidence >= 0.6 ? row.role : null;
  } catch { return null; }
}

/** Generic concepts are named by what they teach, never by a resource id. */
export function genericConceptName(rec: Pick<RecRow, "action_type" | "resource">): string {
  const role = roleOf(rec.resource) || "resource";
  return `${role} ${rec.action_type} rule`.slice(0, 120);
}

export const scopeOf = (rec: Pick<RecRow, "decision_scope">): ConceptScope => (rec.decision_scope === "generic" ? "generic" : "internal");

async function ensureParent(scope: ConceptScope): Promise<void> {
  const parent = PARENTS[scope];
  const r = await fetch(`${config.repo2graphUrl}/gitree/concepts/${enc(parent.id)}`, { headers: headers() });
  if (r.ok) return;
  const c = await fetch(`${config.repo2graphUrl}/gitree/create-concept-direct`, {
    method: "POST", headers: headers(),
    body: JSON.stringify({ name: parent.name, repo: CONCEPT_NAMESPACE, description: parent.description, documentation: parent.documentation }),
  });
  if (!c.ok && c.status !== 409) throw new Error(`parent concept create failed: ${c.status} ${(await c.text()).slice(0, 200)}`);
}

/** Named by the canonical resource id, not its display name, so merged recommendations map to one concept. */
export function conceptNameFor(rec: Pick<RecRow, "action_type" | "resource_name" | "resource">): string {
  return `${rec.action_type} ${rec.resource || rec.resource_name || ""}`.trim().slice(0, 120);
}

function genericDocumentation(rec: RecRow): string {
  const role = roleOf(rec.resource) || "this kind of resource";
  return [
    `# ${genericConceptName(rec)}`,
    ``,
    `A reusable rule distilled from a team decision. It is about workloads of type **${role}** and the action **${rec.action_type}**, not about one resource.`,
    ``,
    `## Rule`,
    rec.decision_reason || rec.rationale || "(no reason recorded)",
    ``,
    `## How it was learned`,
    `Decision **${rec.status}**${rec.decided_by ? ` by ${rec.decided_by}` : ""}${rec.decided_at ? ` on ${rec.decided_at}` : ""} on "${rec.title}" (${usd(rec.est_monthly_saving)}).`,
    ``,
    `## Guidance for future runs`,
    rec.status === "rejected"
      ? `Do not propose ${rec.action_type} for ${role} workloads on these grounds again, in this account or any other, unless the facts differ from the rule above.`
      : `Treat ${rec.action_type} on ${role} workloads as ${rec.status === "approved" || rec.status === "pending" || rec.status === "done" ? "acceptable when the same conditions hold" : "case by case"}.`,
  ].join("\n");
}

function documentationFor(rec: RecRow): string {
  let evidence = "";
  try { evidence = JSON.stringify(JSON.parse(rec.evidence || "{}")); } catch { evidence = rec.evidence || ""; }
  if (evidence.length > 1500) evidence = evidence.slice(0, 1500) + " …";
  const lines = [
    `# ${rec.title}`,
    ``,
    `- Resource: \`${rec.resource}\`${rec.resource_name ? ` (${rec.resource_name})` : ""}`,
    `- Action: ${rec.action_type} · tier ${rec.tier} · confidence ${pct(rec.confidence)}`,
    `- Estimated saving: ${usd(rec.est_monthly_saving)}`,
    `- Proposed by: ${rec.source} (${rec.rule}), last seen in run #${rec.run_id}`,
    ``,
    `## Decision`,
    `**${rec.status}**${rec.decided_by ? ` by ${rec.decided_by}` : ""}${rec.decided_at ? ` on ${rec.decided_at}` : ""}`,
    rec.decision_reason ? `\nReason: ${rec.decision_reason}` : ``,
    ``,
    `## Guidance for future runs`,
    guidanceFor(rec),
    ``,
    `## Advisor rationale`,
    rec.rationale || "",
    ``,
    `## Evidence`,
    "```json",
    evidence,
    "```",
  ];
  return lines.join("\n");
}

function guidanceFor(rec: RecRow): string {
  switch (rec.status) {
    case "rejected": return `Do not propose this again for this resource unless the facts changed. The team's reason: ${rec.decision_reason || "not given"}. Apply the same reasoning to similar resources.`;
    case "approved": return `The team wants this done. If it still shows up in findings, it is pending execution, not a new discovery.`;
    case "done": return `This was carried out. If the resource reappears in findings, treat it as a regression worth flagging.`;
    case "pending": return `Being worked on: some steps are done and the rest wait on something (data to accumulate, a change window). If it still shows up in findings, it is in progress, not a new discovery.`;
    case "snoozed": return `Deferred, not refused. It can be proposed again later, ideally with new evidence.`;
    case "resolved": return `The finding disappeared on its own (resource gone or fixed outside the advisor).`;
    default: return `Open, no decision yet.`;
  }
}

function descriptionFor(rec: RecRow): string {
  if (scopeOf(rec) === "generic") {
    const role = roleOf(rec.resource) || "resource";
    return `Generic rule (${role}, ${rec.action_type}): ${rec.decision_reason || rec.rationale || rec.title}`.slice(0, 300);
  }
  const d = `Decision: ${rec.status}${rec.decision_reason ? ` — ${rec.decision_reason}` : ""}. ${rec.title} (${usd(rec.est_monthly_saving)})`;
  return d.slice(0, 300);
}

/** Creates or replaces the concept for one recommendation. Safe to call often; throws on transport errors. */
export async function syncDecisionConcept(recommendationId: number): Promise<{ conceptId: string } | null> {
  if (!enabled()) return null;
  const rec = db.prepare("select * from recommendations where id = ?").get(recommendationId) as RecRow | undefined;
  if (!rec) return null;
  const prev = db.prepare("select concept_id from concepts where fingerprint = ?").get(rec.fingerprint) as { concept_id: string } | undefined;
  const scope = scopeOf(rec);
  try {
    await ensureParent(scope);
    if (prev) {
      await fetch(`${config.repo2graphUrl}/gitree/concepts/${enc(prev.concept_id)}`, { method: "DELETE", headers: headers() }).catch(() => {});
    }
    const body = {
      name: scope === "generic" ? genericConceptName(rec) : conceptNameFor(rec),
      repo: CONCEPT_NAMESPACE, parent: PARENTS[scope].id,
      description: descriptionFor(rec),
      documentation: scope === "generic" ? genericDocumentation(rec) : documentationFor(rec),
    };
    let res = await fetch(`${config.repo2graphUrl}/gitree/create-concept-direct`, { method: "POST", headers: headers(), body: JSON.stringify(body) });
    let conceptId: string | undefined;
    if (res.status === 409) {
      // Same slug already exists (e.g. created outside our table): replace it.
      const err = (await res.json().catch(() => ({}))) as { conceptId?: string };
      conceptId = err.conceptId;
      if (conceptId) {
        await fetch(`${config.repo2graphUrl}/gitree/concepts/${enc(conceptId)}`, { method: "DELETE", headers: headers() }).catch(() => {});
        res = await fetch(`${config.repo2graphUrl}/gitree/create-concept-direct`, { method: "POST", headers: headers(), body: JSON.stringify(body) });
      }
    }
    if (!res.ok) throw new Error(`create concept failed: ${res.status} ${(await res.text()).slice(0, 200)}`);
    const data = (await res.json()) as { concept: { id: string } };
    conceptId = data.concept.id;
    db.prepare(`insert into concepts(fingerprint, concept_id, status, scope, synced_at, error) values (?, ?, ?, ?, datetime('now'), null)
      on conflict(fingerprint) do update set concept_id = excluded.concept_id, status = excluded.status, scope = excluded.scope, synced_at = excluded.synced_at, error = null`)
      .run(rec.fingerprint, conceptId, rec.status, scope);
    // Now that the fingerprint maps to a concept id, the Neo4j mirror can draw the DECIDED_AS edge (src/graph_mirror.ts).
    mirrorRecommendationsInBackground([rec.id]);
    return { conceptId };
  } catch (e: any) {
    db.prepare(`insert into concepts(fingerprint, concept_id, status, synced_at, error) values (?, ?, ?, datetime('now'), ?)
      on conflict(fingerprint) do update set status = excluded.status, synced_at = excluded.synced_at, error = excluded.error`)
      .run(rec.fingerprint, prev?.concept_id || "", rec.status, String(e.message || e).slice(0, 300));
    throw e;
  }
}

/** Fire-and-forget variant for request handlers. */
export function syncDecisionConceptInBackground(recommendationId: number): void {
  if (!enabled()) return;
  void syncDecisionConcept(recommendationId).catch((e) => console.error(`[concepts] sync failed for recommendation ${recommendationId}: ${e.message || e}`));
}

export interface DecisionConcept { id: string; name: string; description: string; scope: ConceptScope }

/** Concepts currently in the graph (parents excluded), generic knowledge first, for the agent prompt. */
export async function listDecisionConcepts(limit = 60): Promise<DecisionConcept[]> {
  if (!enabled()) return [];
  try {
    const r = await fetch(`${config.repo2graphUrl}/gitree/concepts?repo=${encodeURIComponent(CONCEPT_NAMESPACE)}`, { headers: headers() });
    if (!r.ok) return [];
    const data = (await r.json()) as { concepts?: Omit<DecisionConcept, "scope">[] } | Omit<DecisionConcept, "scope">[];
    const items = Array.isArray(data) ? data : data.concepts || [];
    const parents = new Set(Object.values(PARENTS).map((p) => p.id));
    const scopes = new Map((db.prepare("select concept_id, scope from concepts").all() as { concept_id: string; scope: ConceptScope }[]).map((r) => [r.concept_id, r.scope]));
    return items
      .filter((c) => !parents.has(c.id))
      .map((c) => ({ id: c.id, name: c.name, description: c.description, scope: scopes.get(c.id) || "internal" }))
      .sort((a, b) => (a.scope === b.scope ? 0 : a.scope === "generic" ? -1 : 1))
      .slice(0, limit);
  } catch {
    return [];
  }
}

/**
 * Suggests whether a decision is generic knowledge or an internal, resource-specific call, using Jev when
 * available. Returns null when Jev is off or unsure, so the UI falls back to "internal".
 */
export async function suggestDecisionScope(rec: { title: string; resource: string | null; action_type: string; decision_reason: string | null; rationale: string | null }): Promise<{ scope: ConceptScope; confidence: number } | null> {
  try {
    const { askJev, jevEnabled } = await import("./jev.js");
    if (!jevEnabled() || !rec.decision_reason) return null;
    const res = await askJev(
      { decision: { reason: rec.decision_reason, recommendation: rec.title, action: rec.action_type, resource_role: roleOf(rec.resource) || "unknown", advisor_rationale: rec.rationale || "" } },
      { scope: { type: "choice", instructions: "Considering only the decision under `decision`: does the reason express a reusable rule about a kind of workload or action that would hold in any AWS account, or a fact about this one specific resource, team or account?", criteria: { generic: "A rule about a kind of workload or action that transfers to other accounts (e.g. 'bitcoind nodes are idle on CPU by design')", internal: "Specific to this resource, owner, project or account (e.g. 'keep this one, the founder needs it')" } } },
      { purpose: "decision_scope" },
    );
    const a: any = res?.answers?.scope;
    if (!a || typeof a.confidence !== "number") return null;
    return { scope: a.choice === "generic" ? "generic" : "internal", confidence: a.confidence };
  } catch {
    return null;
  }
}

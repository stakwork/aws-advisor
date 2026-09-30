/**
 * Mirrors every human decision on a recommendation into repo2graph's Concept graph, under the
 * namespace `aws/cost-advisor` with one parent concept per scope and one child concept per
 * recommendation. The agent reads Concepts natively (list_concepts / learn_concept), and the
 * advisor also lists them into the prompt at dispatch time, so past decisions steer future runs.
 *
 * For decisions the source of truth stays in SQLite; this is a one-way export. A concept is deleted and
 * recreated on every decision so its description (which carries the current decision) and embedding stay
 * fresh; the id is a deterministic slug of the name, so it never changes.
 *
 * The operational patterns (the rules every agent prompt carries: pool members are not candidates, the
 * advisor is the monitor, ...) are Concepts only. The code holds a seed for each, written once when the
 * Concept is missing and never rewritten, so the graph is their record: edit or retire one there and the
 * prompts follow at the next dispatch (`systemPromptFor`).
 */
import { config } from "./config.js";
import { db } from "./db.js";
import { mirrorRecommendationsInBackground } from "./graph_mirror.js";
import { PromptKind, getPrompt } from "./prompts.js";

export const CONCEPT_NAMESPACE = process.env.CONCEPT_NAMESPACE || "aws/cost-advisor";

/**
 * Three kinds of concept, under three parents:
 *  - internal: a decision about one specific resource in this account ("keep example-node-1, the founder's node").
 *  - generic: reusable knowledge that transfers to any account ("bitcoind nodes are idle on CPU by design;
 *    never treat them as right-size candidates"). Generic concepts are named by role + action, not resource id.
 *  - pattern: an operational rule the advisor's own prompts carry (seeded from OPERATIONAL_PATTERN_SEEDS, then
 *    owned by the graph). The description is the rule as the prompts read it.
 */
export type ConceptScope = "internal" | "generic" | "pattern";
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
  pattern: {
    name: "AWS Operational Patterns",
    id: `${CONCEPT_NAMESPACE}/aws-operational-patterns`,
    description: "Operational rules every advisor agent run respects: facts about how this fleet behaves, not guesses",
    documentation: "# AWS Operational Patterns\n\nOne child concept per rule. Each description is a rule the advisor appends to every agent system prompt (findings, incident, resolution, observation) at dispatch time, so what is written here is what the agents are told. Edit a rule here to change what they are told; delete one to retire it.",
  },
};

/**
 * The operational patterns as first written. Each becomes a Concept under "AWS Operational Patterns" the first
 * time the advisor finds it missing from the graph and its own `concepts` table; after that the graph owns the
 * text and this list is only the seed for a fresh graph. Add a rule here with a new key; change an existing
 * rule in the graph, not here.
 */
export const OPERATIONAL_PATTERN_SEEDS: { key: string; name: string; rule: string }[] = [
  {
    key: "pool_members_not_candidates",
    name: "Pool members are not individual candidates",
    rule: "Pool members are not individual candidates. Instances with a pool (batch = AWS Batch compute environment, karpenter, eks = managed node group, asg) are launched and terminated by their controller. A Batch worker exists only while a job runs: its appearance, its short life, its idle CPU between jobs and a late SSM registration are all expected. Recommend changes to the compute environment, NodePool, node group, launch template or job definition, never \"stop\", \"right-size\" or \"migrate\" one member.",
  },
  {
    key: "ssm_registration_delay",
    name: "New instances register late with Systems Manager",
    rule: "New instances take a few minutes to register with Systems Manager; \"not managed\" on an instance younger than fifteen minutes is not a finding.",
  },
  {
    key: "autoscaling_churn_is_normal",
    name: "Autoscaling churn is normal",
    rule: "Autoscaling churn (nodes appearing and disappearing) is normal; only a change in the pool's size over days is.",
  },
  {
    key: "capacity_pattern_learned_minimum",
    name: "The learned hourly minimum of a Beanstalk group",
    rule: "A Beanstalk group with AdvisorAutoScale=ON and an AdvisorScaleBand=<floor>-<ceiling> is sized by its learned week, not by hand: for each hour of the week the executor sets MinSize to the capacity the group's trigger needed at that hour (p95 across the weeks seen), never below the floor (the bare minimum a person set) and never above the ceiling. An hour the group spent pinned at its ceiling with high CPU is a pressure event: the ceiling goes up by one at once (within the band) and that hour's minimum is raised for the following weeks. A MinSize set by hand holds for a day, then the pattern resumes. The pattern, its revisions and the pressure events are on the group's AdvisorNodePool node in the graph; a review of the group's capacity starts from them, and a persistent pressure at the ceiling means the band is too narrow, not that the executor should be overridden.",
  },
  {
    key: "advisor_is_the_monitor",
    name: "The advisor is the monitor for SSM-managed instances",
    rule: "The advisor is the monitor for SSM-managed instances. It probes memory, disk, load, reboots and containers itself, keeps daily roll-ups, raises disk_high, disk_full and disk_fill (days until full at the current rate), memory and load alerts, and reviews the statistics every day. Never recommend installing the CloudWatch agent, creating CloudWatch alarms or adding external monitoring for these; a monitoring gap (an instance the advisor does not probe, a threshold, a figure it does not compute) goes under needs_from_human or in the rationale, not in a recommendation or a fix.",
  },
];
export const patternFingerprint = (key: string) => `pattern:${key}`;

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

function patternDocumentation(seed: { name: string; rule: string }): string {
  return [
    `# ${seed.name}`,
    ``,
    `An operational pattern: a fact about how this fleet behaves that every advisor agent run is told to respect. The concept's description is the rule exactly as the agents read it, appended to the system prompt at dispatch time.`,
    ``,
    `## Rule`,
    seed.rule,
    ``,
    `## Maintaining it`,
    `Edit the description to change what the agents are told; delete the concept to retire the rule. The advisor seeds it once and never rewrites it.`,
  ].join("\n");
}

/**
 * Creates the operational-pattern Concepts the graph does not have yet. A pattern already recorded in the
 * `concepts` table is left alone even when it no longer exists in the graph (the team retired it there); one
 * that exists in the graph but not in the table (created by hand, or a fresh database) is adopted. Throws on
 * transport errors; the memoised wrapper below retries on the next call.
 */
export async function seedOperationalPatterns(): Promise<{ created: string[]; adopted: string[] }> {
  const out = { created: [] as string[], adopted: [] as string[] };
  if (!enabled()) return out;
  await ensureParent("pattern");
  const known = new Set((db.prepare("select fingerprint from concepts where scope = 'pattern' and concept_id <> ''").all() as { fingerprint: string }[]).map((r) => r.fingerprint));
  const record = db.prepare(`insert into concepts(fingerprint, concept_id, status, scope, synced_at, error) values (?, ?, 'seeded', 'pattern', datetime('now'), null)
    on conflict(fingerprint) do update set concept_id = excluded.concept_id, status = excluded.status, scope = excluded.scope, synced_at = excluded.synced_at, error = null`);
  for (const seed of OPERATIONAL_PATTERN_SEEDS) {
    const fp = patternFingerprint(seed.key);
    if (known.has(fp)) continue;
    const body = { name: seed.name, repo: CONCEPT_NAMESPACE, parent: PARENTS.pattern.id, description: seed.rule, documentation: patternDocumentation(seed) };
    const res = await fetch(`${config.repo2graphUrl}/gitree/create-concept-direct`, { method: "POST", headers: headers(), body: JSON.stringify(body) });
    if (res.status === 409) {
      const err = (await res.json().catch(() => ({}))) as { conceptId?: string };
      if (!err.conceptId) throw new Error(`pattern ${seed.key} exists but repo2graph returned no id`);
      record.run(fp, err.conceptId);
      out.adopted.push(err.conceptId);
      continue;
    }
    if (!res.ok) throw new Error(`create pattern concept failed: ${res.status} ${(await res.text()).slice(0, 200)}`);
    const data = (await res.json()) as { concept: { id: string } };
    record.run(fp, data.concept.id);
    out.created.push(data.concept.id);
  }
  return out;
}

let seeding: Promise<void> | null = null;
/** Seeds once per process; a failed attempt is forgotten so the next caller tries again. */
export function ensureOperationalPatterns(): Promise<void> {
  if (!enabled()) return Promise.resolve();
  if (!seeding) {
    seeding = seedOperationalPatterns().then((r) => {
      if (r.created.length || r.adopted.length) console.log(`[concepts] operational patterns: ${r.created.length} created, ${r.adopted.length} adopted`);
    }).catch((e) => { seeding = null; console.error(`[concepts] seeding operational patterns failed: ${e.message || e}`); });
  }
  return seeding;
}

export interface DecisionConcept { id: string; name: string; description: string; scope: ConceptScope }

/** The block every agent system prompt ends with: the pattern Concepts, one rule per line with its id so a plan can cite it. */
export function operationalPatternsBlock(concepts: DecisionConcept[]): string {
  const patterns = concepts.filter((c) => c.scope === "pattern");
  if (!patterns.length) return "";
  return "Operational patterns to respect (facts, not guesses):\n" + patterns.map((c) => `- [${c.id}] ${c.description}`).join("\n");
}

/** The kinds whose system prompt carries the operational patterns; chat and the pass report never did. */
export const PATTERN_PROMPT_KINDS: ReadonlySet<PromptKind> = new Set<PromptKind>(["findings", "incident", "resolution", "observe"]);

/** The system prompt actually sent: the editable prompt for the kind plus, for the kinds that carry them, the operational patterns from the graph. */
export async function systemPromptFor(kind: PromptKind, concepts?: DecisionConcept[]): Promise<string> {
  if (!PATTERN_PROMPT_KINDS.has(kind)) return getPrompt(kind);
  const block = operationalPatternsBlock(concepts ?? (await listDecisionConcepts()));
  const base = getPrompt(kind);
  return block ? `${base}\n${block}` : base;
}

const SCOPE_ORDER: Record<ConceptScope, number> = { pattern: 0, generic: 1, internal: 2 };

/** Concepts currently in the graph (parents excluded): operational patterns, then generic knowledge, then internal decisions. */
export async function listDecisionConcepts(limit = 60): Promise<DecisionConcept[]> {
  if (!enabled()) return [];
  await ensureOperationalPatterns();
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
      .sort((a, b) => SCOPE_ORDER[a.scope] - SCOPE_ORDER[b.scope])
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

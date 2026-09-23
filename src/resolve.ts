import { choice, noul, score } from "@typesafe-ai/sdk";
import { config } from "./config.js";
import { getPrompt, registerDefaultPrompt } from "./prompts.js";
import { OPERATIONAL_PATTERNS } from "./pools.js";
import { credentialGate } from "./gate.js";
import { db } from "./db.js";
import { askJev, jevEnabled } from "./jev.js";
import { DecisionConcept, listDecisionConcepts } from "./concepts.js";
import { Playbook, controlForRecommendation, playbookFor } from "./playbooks.js";
import { AgentRunRow, postAgentRequest } from "./agent.js";
import { latestProbe } from "./ssm.js";
import { shortResourceId } from "./resource_id.js";
import { Tier } from "./rules.js";
import { RdsLoadSummary, ensureRdsLoad, latestRdsLoad, loadSummary } from "./rds_load.js";

/**
 * Tailored resolutions. A playbook (src/playbooks.ts) says how a kind of finding is acted on in general; a
 * resolution says how *this* recommendation is acted on, for *this* resource, given what the team decided
 * before. On request the advisor assembles a context pack (the playbook, the resource's inventory snapshot,
 * its role and latest probe, the decision concepts in repo2graph's graph that mention the resource or its
 * role, earlier recommendations and incidents on it), asks Jev whether the playbook applies at all and what
 * blocks it, and, unless Jev is confident it does not apply, hands the pack to repo2graph's agent with the MCP
 * fact tools to produce a step-by-step plan with commands, checks and what it still needs from a human. The
 * answer lands in `resolutions`; the callback routes on agent_runs.kind = resolution.
 */

export const BLOCKERS = {
  none: "nothing blocks it: the playbook can be followed as written",
  third_party_binary_without_arm_build: "the workload depends on a third-party binary or image that has no ARM build",
  stateful_data_migration: "carrying it out means moving or converting stateful data (a database, a chain state, volumes) with real downtime risk",
  protected_or_owner_says_keep: "the name, tags or a recorded team decision say the resource is deliberately kept as it is",
  retiring_soon: "the resource is about to be retired or replaced, so the work would be wasted",
  unknown: "the facts are not enough to say",
} as const;
export type Blocker = keyof typeof BLOCKERS;
export const EFFORT_LEVELS = ["an hour", "a day", "a week or more"] as const;

const safeJson = (s: unknown) => { if (typeof s !== "string") return s ?? null; try { return JSON.parse(s); } catch { return null; } };

// ---- context pack ------------------------------------------------------------------------------------------------

export interface RecRow { id: number; rule: string; source: string; title: string; resource: string | null; resource_name: string | null; action_type: string; est_monthly_saving: number | null; tier: Tier; confidence: number | null; rationale: string | null; evidence: string | null; status: string; decision_reason: string | null; decision_scope?: string | null }

export interface ResourceFacts {
  id: string | null;
  kind: "ec2" | "rds" | "elasticache" | "lambda" | "other";
  name: string | null;
  type: string | null;
  state: string | null;
  region: string | null;
  launched: string | null;
  monthly_usd: number | null;
  cpu_30d: number | null;
  ssm_status: string | null;
  tags: Record<string, string>;
  role: { role: string; role_confidence: number; protected_prob: number; updated_at: string } | null;
  top_processes: string[];
  probe_at: string | null;
  volumes: { volume_id: string; size_gb: number | null; type: string | null; device: string | null }[];
  engine: string | null;
  /** RDS and Aurora only: the load profile from the hourly pass (src/rds_load.ts) with Jev's read of it. */
  load?: RdsLoadSummary | null;
  cluster?: { id: string; members: string[]; storage_type: string | null } | null;
}

const clusterMembers = (cluster: string) => (db.prepare("select db_instance_identifier from inventory_rds where cluster = ? and gone = 0 order by db_instance_identifier").all(cluster) as { db_instance_identifier: string }[]).map((m) => m.db_instance_identifier);

/** What the inventory, the roles cache and the latest probe know about the recommendation's resource. */
export function resourceFacts(rec: Pick<RecRow, "resource" | "resource_name" | "rule">): ResourceFacts {
  const id = shortResourceId(rec.resource);
  const base: ResourceFacts = { id, kind: "other", name: rec.resource_name ?? null, type: null, state: null, region: null, launched: null, monthly_usd: null, cpu_30d: null, ssm_status: null, tags: {}, role: null, top_processes: [], probe_at: null, volumes: [], engine: null };
  if (!id) return base;
  const role = db.prepare("select role, role_confidence, protected_prob, updated_at from resource_roles where resource_id = ?").get(id) as ResourceFacts["role"] | undefined;
  if (role) base.role = role;
  const ec2 = db.prepare("select * from inventory_ec2 where instance_id = ?").get(id) as any;
  if (ec2) {
    const snap = safeJson(ec2.snapshot) || {};
    const probe = latestProbe(id);
    // Kernel threads say nothing about the workload; keep the user-space processes.
    const kernel = /^(kthreadd|kworker|ksoftirqd|migration|rcu_|mm_percpu|cpuhp|kcompactd|khugepaged|kswapd|watchdog|idle_inject|systemd(-[a-z]+)?$|init$)/;
    const procs = probe ? [...new Set([...(probe.data.top_cpu || []), ...(probe.data.top_mem || [])].map((p: any) => String(p.command)))].filter((c) => !kernel.test(c)).slice(0, 8) : [];
    return { ...base, kind: "ec2", name: ec2.name ?? base.name, type: ec2.instance_type, state: ec2.state, region: ec2.region, launched: ec2.launch_time, monthly_usd: ec2.monthly_usd, cpu_30d: ec2.cpu_30d, ssm_status: ec2.ssm_status,
      tags: Object.fromEntries(Object.entries(snap.tags || {}).filter(([k]) => !/^aws:/.test(k)).slice(0, 20)) as Record<string, string>,
      top_processes: procs, probe_at: probe?.collected_at ?? null,
      volumes: ((snap.storage?.volumes || []) as any[]).map((v) => ({ volume_id: v.volume_id, size_gb: v.size != null ? Number(v.size) : null, type: v.volume_type ?? v.type ?? null, device: v.device ?? null })) };
  }
  const rds = db.prepare("select * from inventory_rds where db_instance_identifier = ?").get(id) as any;
  if (rds) {
    const snap = safeJson(rds.snapshot) || {};
    return { ...base, kind: "rds", name: id, type: rds.class, state: rds.status, region: rds.region, launched: rds.created, monthly_usd: rds.monthly_usd, cpu_30d: rds.cpu_30d, engine: `${rds.engine} ${rds.engine_version || ""}`.trim(),
      tags: (snap.tags || {}) as Record<string, string>, volumes: rds.storage_gb ? [{ volume_id: "storage", size_gb: rds.storage_gb, type: rds.storage_type, device: null }] : [],
      cluster: rds.cluster ? { id: rds.cluster, members: clusterMembers(rds.cluster), storage_type: rds.storage_type } : null, load: loadSummary(latestRdsLoad(id)) };
  }
  // An Aurora recommendation names the cluster; its facts are the writer's inventory row plus the cluster's load profile.
  const members = db.prepare("select * from inventory_rds where cluster = ? and gone = 0 order by db_instance_identifier").all(id) as any[];
  if (members.length) {
    const w = members[0];
    const snap = safeJson(w.snapshot) || {};
    const tags = Object.assign({}, ...members.map((m) => (safeJson(m.snapshot) || {}).tags || {}), snap.tags || {}) as Record<string, string>;
    return { ...base, kind: "rds", name: id, type: members.map((m) => m.class).join(", "), state: w.status, region: w.region, launched: w.created,
      monthly_usd: members.reduce((s, m) => s + (m.monthly_usd || 0), 0) || null, cpu_30d: w.cpu_30d, engine: `${w.engine} ${w.engine_version || ""}`.trim(), tags,
      volumes: w.storage_gb ? [{ volume_id: "cluster volume", size_gb: w.storage_gb, type: w.storage_type, device: null }] : [],
      cluster: { id, members: members.map((m) => m.db_instance_identifier), storage_type: w.storage_type }, load: loadSummary(latestRdsLoad(id)) };
  }
  const cache = db.prepare("select * from inventory_elasticache where cache_cluster_id = ?").get(id) as any;
  if (cache) return { ...base, kind: "elasticache", name: id, type: cache.node_type, state: cache.status, region: cache.region, launched: cache.created, monthly_usd: cache.monthly_usd, engine: `${cache.engine} ${cache.engine_version || ""}`.trim() };
  if (/^arn:aws:lambda:/.test(rec.resource || "") || /lambda/i.test(rec.rule)) return { ...base, kind: "lambda", name: id, region: rec.resource?.split(":")[3] ?? null };
  return base;
}

/**
 * The decision concepts that matter for this resource: internal ones that name the resource id or name, and
 * generic rules whose name starts with the resource's role (see src/concepts.ts genericConceptName).
 */
export function filterConcepts(concepts: DecisionConcept[], resource: { id: string | null; name: string | null; role: string | null }): DecisionConcept[] {
  const needles = [resource.id, resource.name].filter((s): s is string => Boolean(s && s.length >= 3)).map((s) => s.toLowerCase());
  const role = resource.role?.toLowerCase();
  return concepts.filter((c) => {
    const text = `${c.name} ${c.description}`.toLowerCase();
    if (needles.some((n) => text.includes(n))) return true;
    if (c.scope === "generic" && role && c.name.toLowerCase().startsWith(role)) return true;
    return false;
  });
}

/** Earlier recommendations on the resource (the MCP recommendation_history logic) and incidents whose fixes named it. */
export function resourceHistory(resource: { id: string | null; name: string | null }, excludeId: number) {
  if (!resource.id) return { recommendations: [], incidents: [], findings: [] };
  const like = `%${resource.id}%`;
  const recommendations = db.prepare(`
    select id, rule, source, title, action_type, est_monthly_saving, tier, status, decided_at, decided_by, decision_reason, decision_scope, updated_at
    from recommendations where id <> ? and (resource = ? or resource_name = ? or resource like ?) order by updated_at desc limit 20`).all(excludeId, resource.id, resource.id, like) as any[];
  const incidents = db.prepare(`
    select i.id, i.status, i.cause, i.confidence, i.monthly_run_rate_usd, i.created_at, a.kind as alert_kind, a.resource as alert_resource
    from incidents i join alerts a on a.id = i.alert_id
    where a.resource = ? or i.fixes like ? or i.evidence like ? order by i.id desc limit 5`).all(resource.id, like, like) as any[];
  const latest = (db.prepare("select id from runs where status = 'completed' order by id desc limit 1").get() as { id: number } | undefined)?.id;
  const findings = latest
    ? db.prepare("select control_id, control_title, reason from findings where run_id = ? and status = 'alarm' and (resource = ? or resource like ?) order by control_id limit 20").all(latest, resource.id, like) as any[]
    : [];
  return { recommendations, incidents, findings };
}

export interface ResolutionContext {
  recommendation: { id: number; rule: string; source: string; title: string; resource: string | null; action_type: string; est_monthly_saving: number | null; tier: Tier; confidence: number | null; rationale: string | null; evidence: unknown; status: string; decision_reason: string | null };
  control_id: string | null;
  playbook: Playbook | null;
  resource: ResourceFacts;
  concepts: DecisionConcept[];
  history: ReturnType<typeof resourceHistory>;
}

/** Builds the context pack from a recommendation row and the graph's concepts (no network here; pass [] when the graph is off). */
export function assembleContext(rec: RecRow, concepts: DecisionConcept[]): ResolutionContext {
  const resource = resourceFacts(rec);
  const control_id = controlForRecommendation(rec);
  return {
    recommendation: { id: rec.id, rule: rec.rule, source: rec.source, title: rec.title, resource: rec.resource, action_type: rec.action_type, est_monthly_saving: rec.est_monthly_saving, tier: rec.tier, confidence: rec.confidence, rationale: rec.rationale, evidence: safeJson(rec.evidence), status: rec.status, decision_reason: rec.decision_reason },
    control_id,
    playbook: playbookFor(control_id),
    resource,
    concepts: filterConcepts(concepts, { id: resource.id, name: resource.name, role: resource.role?.role ?? null }),
    history: resourceHistory(resource, rec.id),
  };
}

// ---- the Jev gate --------------------------------------------------------------------------------------------------

export const gateQuestions = () => ({
  applies: noul("Given the resource facts and the graph context, the playbook actually applies to this resource: following it would produce the saving the recommendation claims without breaking the workload"),
  blocker: choice("What most likely blocks carrying the playbook out on this resource?", BLOCKERS),
  effort: score("How much engineering effort would carrying the playbook out on this resource take?", EFFORT_LEVELS),
});

/** What Jev sees: the recommendation, the playbook's judgement calls, the resource facts and the team's decisions; no plan yet. */
export function gateState(ctx: ResolutionContext) {
  return {
    recommendation: { title: ctx.recommendation.title, action_type: ctx.recommendation.action_type, est_monthly_saving_usd: ctx.recommendation.est_monthly_saving, tier: ctx.recommendation.tier, rationale: (ctx.recommendation.rationale || "").slice(0, 1500) },
    playbook: ctx.playbook ? { title: ctx.playbook.title, meaning: ctx.playbook.meaning, act_when: ctx.playbook.act_when, ignore_when: ctx.playbook.ignore_when } : "no playbook for this rule",
    resource: { ...ctx.resource, volumes: ctx.resource.volumes.slice(0, 10) },
    team_decisions: ctx.concepts.map((c) => ({ scope: c.scope, name: c.name, description: c.description.slice(0, 300) })),
    history: {
      earlier_recommendations: ctx.history.recommendations.slice(0, 10).map((r) => ({ title: r.title, status: r.status, decision_reason: r.decision_reason })),
      incidents: ctx.history.incidents.map((i) => ({ cause: i.cause, status: i.status })),
      other_findings_on_it: ctx.history.findings.map((f) => f.control_title || f.control_id),
    },
  };
}

export interface GateAnswer {
  applies: number;
  blocker: Blocker;
  blocker_confidence: number;
  blocker_probabilities?: Record<string, number>;
  effort: number;
  effort_label: string;
  model?: string;
  call_id?: number;
  latency_ms?: number;
}

export const effortLabel = (v: number) => EFFORT_LEVELS[Math.max(0, Math.min(EFFORT_LEVELS.length - 1, Math.round(v)))];

/** Reads Jev's three answers; null when any is missing or of the wrong type. */
export function parseGateAnswers(answers: any, meta: { model?: string; call_id?: number; latency_ms?: number } = {}): GateAnswer | null {
  const a = answers?.applies, b = answers?.blocker, e = answers?.effort;
  if (a?.type !== "noul" || b?.type !== "choice" || e?.type !== "score") return null;
  const blocker = (Object.keys(BLOCKERS) as Blocker[]).includes(b.choice) ? (b.choice as Blocker) : "unknown";
  return { applies: Number(a.noul), blocker, blocker_confidence: Number(b.confidence ?? 0), blocker_probabilities: b.probabilities, effort: Number(e.score), effort_label: effortLabel(Number(e.score)), ...meta };
}

export type GateOutcome = "applies" | "unsure" | "blocked";
/** A blocker answer below this confidence never closes a resolution. */
export const BLOCKER_CONFIDENCE_THRESHOLD = 0.7;
/** Below this `applies` probability, a confident blocker answer (even `none`) closes it. */
export const APPLIES_CLOSE_THRESHOLD = 0.15;

const pct = (v: number) => `${Math.round(v * 100)}%`;
const conceptsNote = (n: number | undefined) => (n == null ? "" : n === 0 ? " No team decisions or rules on record for this resource or its role yet." : ` ${n} team decision${n === 1 ? "" : "s"} or rule${n === 1 ? "" : "s"} on record for it.`);

/**
 * The policy. Close (`blocked`) only when Jev names a specific blocker (not `none`, not `unknown`) with
 * confidence >= 0.7, or when `applies` <= 0.15 and the blocker answer (anything but `unknown`) has
 * confidence >= 0.7. A low `applies` with `none` / `unknown` or a shaky blocker is `unsure` and goes to the
 * agent, which can gather the facts Jev lacked; `applies` >= 0.5 without a confident blocker is `applies`.
 */
export function gateDecision(g: GateAnswer | null, info: { concepts?: number } = {}): { decision: "proceed" | "not_applicable"; outcome: GateOutcome; reason: string } {
  const note = conceptsNote(info.concepts);
  if (!g) return { decision: "proceed", outcome: "unsure", reason: `Jev is not configured or did not answer; asking the agent.${note}` };
  const specific = g.blocker !== "none" && g.blocker !== "unknown";
  const confident = g.blocker_confidence >= BLOCKER_CONFIDENCE_THRESHOLD;
  const blockerText = g.blocker.replace(/_/g, " ");
  if (specific && confident) {
    return { decision: "not_applicable", outcome: "blocked", reason: `Closed: Jev is confident (${pct(g.blocker_confidence)}) the blocker is ${blockerText} (${BLOCKERS[g.blocker]}); applies ${pct(g.applies)}.${note}` };
  }
  if (g.applies <= APPLIES_CLOSE_THRESHOLD && confident && g.blocker !== "unknown") {
    return { decision: "not_applicable", outcome: "blocked", reason: `Closed: Jev is confident (${pct(g.blocker_confidence)}) it does not apply (applies ${pct(g.applies)}) and nothing specific blocks it.${note}` };
  }
  if (g.applies >= 0.5) {
    const maybe = specific ? `, possible blocker ${blockerText} (${pct(g.blocker_confidence)})` : "";
    return { decision: "proceed", outcome: "applies", reason: `Jev thinks it applies (${pct(g.applies)})${maybe}, effort ${g.effort_label}; asking the agent for the plan.${note}` };
  }
  const why = specific ? `blocker ${blockerText} only at ${pct(g.blocker_confidence)}` : "no confident blocker";
  return { decision: "proceed", outcome: "unsure", reason: `Jev is unsure (applies ${pct(g.applies)}, ${why}), asking the agent.${note}` };
}

// ---- the agent -----------------------------------------------------------------------------------------------------

export const RESOLUTION_SCHEMA = {
  type: "object",
  properties: {
    applies: { type: "boolean", description: "whether the playbook applies to this resource after checking the facts" },
    summary: { type: "string", description: "what to do and why it is safe (or why not): two to four short sentences, in short paragraphs separated by a blank line (one idea per paragraph, never one long block)" },
    blockers: { type: "array", items: { type: "string" }, description: "what stands in the way, verified, one per entry, each a short paragraph; empty when nothing does" },
    plan: {
      type: "array",
      items: {
        type: "object",
        properties: {
          step: { type: "string", description: "what to do, specific to this resource (names, ids, sizes); a blank line between paragraphs when a step needs more than one" },
          command: { type: "string", description: "the aws CLI / kubectl / shell command when there is one, with the real ids filled in" },
          verify: { type: "string", description: "how to check the step worked before moving on" },
        },
        required: ["step", "verify"],
        additionalProperties: false,
      },
    },
    risk: { type: "string", enum: ["auto", "approve", "report"], description: "auto = reversible, approve = needs a human, report = never automate" },
    est_monthly_saving: { type: "number", description: "USD per month after checking real prices; 0 if unknown" },
    needs_from_human: { type: "array", items: { type: "string" }, description: "decisions or facts only the team can supply (owner confirmation, a maintenance window, a build of a binary)" },
    concepts_used: { type: "array", items: { type: "string" }, description: "ids of the team decision concepts from the prompt that shaped this answer" },
  },
  required: ["applies", "summary", "blockers", "plan", "risk", "est_monthly_saving", "needs_from_human", "concepts_used"],
  additionalProperties: false,
};

const RESOLUTION_SYSTEM = `You are a senior AWS engineer writing the resolution for one cost recommendation in a single AWS account, for a
colleague who will carry it out by hand. You get the recommendation, the generic playbook for its kind of finding, the
facts the advisor holds about the resource (inventory, role, probe, volumes), the team's earlier decisions from the
knowledge graph (Concepts: generic rules and internal decisions, each with an id), the resource's history in the
advisor, and a first opinion from Jev (a classifier) on whether the playbook applies and what blocks it.
Verify before you write: aws_steampipe_query for the resource's current state (type, AMI, architecture, tags, attached
volumes, security groups, what depends on it), aws_instance_history for a month of daily memory, disk, load and
containers (the evidence that it is really idle or really busy), aws_baseline for what is typical, aws_cloudtrail_changes
for who touched the resource recently (a plan must not fight an ongoing change), aws_log_groups when the finding is
about logs, aws_price_lookup for the real on-demand prices of the current and the
target SKU, aws_instance_probe or aws_instance_inventory for what runs on an instance, aws_resource_cost_history and
aws_findings_for_resource and aws_recommendation_history for history, learn_concept for the full text of a concept id.
For an RDS or Aurora resource the facts carry "load": fourteen days of I/O, capacity (ACU floor, ceiling, time at
the ceiling, bursts and their cadence, whether the database fits in the buffer cache), the top statements from
Performance Insights, the slow statements from the log and Jev's classification (shape, what drives the I/O,
throttled by the cap, structural, first lever); aws_rds_load returns the full profile. Reason from it: a storage
tier change is about the I/O charge, a capacity change is about the buffer cache and the bursts, and a query fix
is about the statements; say which of these the plan is and why the others are not it (or are a separate task).
Aurora storage: a cluster can switch to I/O-Optimized once every 30 days and back to Standard at any time.
Write the plan for THIS resource: real ids, names, sizes and regions in every step and command; one verify line per
step; the rollback where a step is not reversible. Respect the team's decisions: a generic rule for this role applies
unless the facts say otherwise; a rejection on this resource means say why this time is different or set applies to
false. Be honest about what only a human can decide and list it under needs_from_human. Keep the plan under ten steps.
Write for a screen, not a report: in summary, steps, blockers and needs_from_human keep paragraphs short (one idea,
one to three sentences) and separate them with a blank line; the UI keeps the blank lines and shows nothing else as
a paragraph break. Never run several ideas together into one long block.
Emit the JSON object first, then any commentary.`;
registerDefaultPrompt("resolution", `${RESOLUTION_SYSTEM}\n${OPERATIONAL_PATTERNS}`);

const money = (v: number | null | undefined) => (v == null ? "unknown" : `${Number(v).toFixed(2)} USD/month`);

export function buildResolutionPrompt(ctx: ResolutionContext, gate: GateAnswer | null): string {
  const r = ctx.recommendation, p = ctx.playbook, x = ctx.resource;
  const lines: string[] = [
    `# Resolution for recommendation #${r.id}: ${r.title}`,
    `Rule ${r.rule} (source ${r.source}), action ${r.action_type}, tier ${r.tier}, confidence ${r.confidence ?? "?"}, estimated saving ${money(r.est_monthly_saving)}, status ${r.status}${r.decision_reason ? `, decision reason: "${r.decision_reason}"` : ""}.`,
    `Resource: ${r.resource ?? "unknown"}`,
    "", "## Rationale from the rule", r.rationale || "(none)",
    "", "## Evidence", "```json", JSON.stringify(r.evidence ?? {}, null, 1).slice(0, 4000), "```",
  ];
  if (p) {
    lines.push("", `## Playbook: ${p.title} (${ctx.control_id})`, `Meaning: ${p.meaning}`, `Act when: ${p.act_when}`, `Ignore when: ${p.ignore_when}`, `Saving: ${p.saving}`, `Tier ${p.tier}, effort ${p.effort}.`, "Generic steps:");
    p.steps.forEach((s, i) => lines.push(`${i + 1}. ${s}`));
  } else lines.push("", "## Playbook", "No playbook exists for this rule; derive the steps from the rationale and the facts.");
  lines.push("", "## Resource facts (advisor inventory)", "```json", JSON.stringify(x, null, 1).slice(0, 6000), "```");
  lines.push("", "## Team decisions on record (Concepts) that mention this resource or its role");
  if (!ctx.concepts.length) lines.push("- none");
  for (const c of ctx.concepts) lines.push(`- (${c.scope === "generic" ? "GENERIC rule for this role" : "internal, this resource"}) [${c.id}] ${c.name}: ${c.description}`);
  lines.push("", "## History on this resource");
  if (!ctx.history.recommendations.length && !ctx.history.incidents.length && !ctx.history.findings.length) lines.push("- none");
  for (const h of ctx.history.recommendations) lines.push(`- recommendation #${h.id} [${h.status}] ${h.title}${h.decision_reason ? ` — "${h.decision_reason}"` : ""}`);
  for (const i of ctx.history.incidents) lines.push(`- incident #${i.id} (${i.status}): ${i.cause ?? "no cause"}`);
  for (const f of ctx.history.findings) lines.push(`- finding ${f.control_id}: ${f.reason}`);
  lines.push("", "## Jev's first opinion");
  if (gate) lines.push(`- applies: ${gate.applies.toFixed(2)}`, `- blocker: ${gate.blocker} (confidence ${gate.blocker_confidence.toFixed(2)})`, `- effort: ${gate.effort_label}`, "Check these against the facts; they are a prior, not a verdict.");
  else lines.push("- not available (Jev is off)");
  lines.push("", "Answer with the JSON object described by the schema: applies, summary, blockers, plan (step, command, verify), risk, est_monthly_saving, needs_from_human, concepts_used.");
  return lines.join("\n");
}

export interface ResolutionPlan { applies: boolean; summary: string; blockers: string[]; plan: { step: string; command?: string; verify: string }[]; risk: Tier; est_monthly_saving: number | null; needs_from_human: string[]; concepts_used: string[] }

/** Validates the agent's answer into the stored plan; null when it is not a resolution object. */
export function parseResolutionResult(content: unknown): ResolutionPlan | null {
  const c = content as any;
  if (!c || typeof c !== "object" || typeof c.summary !== "string" || !Array.isArray(c.plan)) return null;
  const strs = (v: unknown) => (Array.isArray(v) ? v.map((s) => String(s)).filter(Boolean) : []);
  const n = Number(c.est_monthly_saving);
  return {
    applies: c.applies !== false,
    summary: c.summary,
    blockers: strs(c.blockers),
    plan: c.plan.filter((s: any) => s && typeof s === "object" && typeof s.step === "string").map((s: any) => ({ step: String(s.step), ...(s.command ? { command: String(s.command) } : {}), verify: String(s.verify || "") })),
    risk: (["auto", "approve", "report"].includes(c.risk) ? c.risk : "approve") as Tier,
    est_monthly_saving: Number.isFinite(n) ? n : null,
    needs_from_human: strs(c.needs_from_human),
    concepts_used: strs(c.concepts_used),
  };
}

// ---- the flow -------------------------------------------------------------------------------------------------------

export interface ResolveResult { resolutionId: number; status: "pending" | "not_applicable" | "failed"; requestId?: string }

/**
 * Starts (or closes at the gate) a resolution for a recommendation. Refuses with code "pending" while one is
 * in flight unless force is set. The credential gate runs first like every other dispatch: the agent verifies
 * facts against the live account, which is pointless on dead credentials.
 */
export async function resolveRecommendation(recId: number, opts: { force?: boolean } = {}): Promise<ResolveResult> {
  const rec = db.prepare("select * from recommendations where id = ?").get(recId) as RecRow | undefined;
  if (!rec) { const e: any = new Error(`unknown recommendation ${recId}`); e.code = "not_found"; throw e; }
  const pending = db.prepare("select id, request_id from resolutions where recommendation_id = ? and status = 'pending' order by id desc limit 1").get(recId) as { id: number; request_id: string | null } | undefined;
  if (pending && !opts.force) { const e: any = new Error(`resolution ${pending.id} for recommendation ${recId} is still pending${pending.request_id ? ` (request ${pending.request_id})` : ""}`); e.code = "pending"; throw e; }
  if (!(await credentialGate("resolve")).ok) throw new Error("AWS credentials are not working; fix them in Settings before resolving");

  const concepts = await listDecisionConcepts(200);
  // A database's facts are only as good as its load profile: refresh one older than a day before the gate reads it.
  const pre = resourceFacts(rec);
  if (pre.kind === "rds" && pre.id) await ensureRdsLoad(pre.id, 24, (l) => console.log(`[resolve] ${l}`));
  const ctx = assembleContext(rec, concepts);
  const resolutionId = Number(db.prepare("insert into resolutions(recommendation_id, context) values (?, ?)").run(recId, JSON.stringify(ctx)).lastInsertRowid);
  try {
    let gate: GateAnswer | null = null;
    if (jevEnabled()) {
      const res = await askJev(gateState(ctx), gateQuestions(), { purpose: "resolution_gate" });
      gate = res ? parseGateAnswers(res.answers, { model: res.model, call_id: res.call_id, latency_ms: res.latency_ms }) : null;
    }
    const verdict = gateDecision(gate, { concepts: ctx.concepts.length });
    if (gate) (gate as any).outcome = verdict.outcome;
    if (gate) (gate as any).reason = verdict.reason;
    const gateJson = JSON.stringify({ ...(gate ?? {}), enabled: jevEnabled(), concepts: ctx.concepts.length, decision: verdict.decision, outcome: verdict.outcome, reason: verdict.reason });
    if (verdict.decision === "not_applicable") {
      db.prepare("update resolutions set status = 'not_applicable', gate = ?, gate_outcome = ?, error = ?, finished_at = datetime('now') where id = ?").run(gateJson, verdict.outcome, verdict.reason, resolutionId);
      console.log(`[resolve] recommendation ${recId}: closed at the gate (${gate?.blocker} ${gate?.blocker_confidence?.toFixed(2)}, applies ${gate?.applies?.toFixed(2)})`);
      return { resolutionId, status: "not_applicable" };
    }
    if (!config.repo2graphUrl) {
      const msg = "REPO2GRAPH_URL is not configured: the gate ran but no agent can write the tailored plan; the static playbook applies";
      db.prepare("update resolutions set status = 'failed', gate = ?, gate_outcome = ?, error = ?, finished_at = datetime('now') where id = ?").run(gateJson, verdict.outcome, msg, resolutionId);
      return { resolutionId, status: "failed" };
    }
    db.prepare("update resolutions set gate = ?, gate_outcome = ? where id = ?").run(gateJson, verdict.outcome, resolutionId);
    const { requestId } = await postAgentRequest({
      prompt: buildResolutionPrompt(ctx, gate),
      systemOverride: getPrompt("resolution"),
      sessionId: `aws-advisor-resolution-${resolutionId}-${Date.now().toString(36)}`,
      agentName: "aws-resolution-writer",
      metadata: { recommendationId: recId, resolutionId, rule: rec.rule },
      link: { kind: "resolution", recommendationId: recId },
    });
    db.prepare("update resolutions set request_id = ? where id = ?").run(requestId, resolutionId);
    console.log(`[resolve] recommendation ${recId} -> resolution ${resolutionId}, request ${requestId}`);
    return { resolutionId, status: "pending", requestId };
  } catch (e: any) {
    db.prepare("update resolutions set status = 'failed', error = ?, finished_at = datetime('now') where id = ?").run(String(e?.message || e).slice(0, 500), resolutionId);
    throw e;
  }
}

/** Completes a resolution from the agent's terminal payload (called by handleAgentResult for kind resolution). */
export function completeResolution(run: AgentRunRow, payload: { status: string; result?: any; error?: any }): void {
  const row = (db.prepare("select id from resolutions where request_id = ? order by id desc limit 1").get(run.request_id)
    ?? (run.recommendation_id ? db.prepare("select id from resolutions where recommendation_id = ? and status = 'pending' order by id desc limit 1").get(run.recommendation_id) : undefined)) as { id: number } | undefined;
  if (!row) { console.error(`[resolve] no resolution for agent request ${run.request_id}`); return; }
  if (payload.status !== "completed") {
    db.prepare("update resolutions set status = 'failed', error = ?, finished_at = datetime('now') where id = ?").run(JSON.stringify(payload.error ?? payload).slice(0, 2000), row.id);
    return;
  }
  const plan = parseResolutionResult(payload.result?.content);
  if (!plan) {
    db.prepare("update resolutions set status = 'failed', error = 'the agent returned no resolution object', finished_at = datetime('now') where id = ?").run(row.id);
    return;
  }
  db.prepare("update resolutions set status = 'completed', plan = ?, error = null, finished_at = datetime('now') where id = ?").run(JSON.stringify(plan), row.id);
  console.log(`[resolve] resolution ${row.id} completed: ${plan.plan.length} steps, applies=${plan.applies}`);
}

/** The latest resolution for a recommendation, parsed, with graph links for the concepts the plan used. */
export function resolutionFor(recId: number) {
  const row = db.prepare("select * from resolutions where recommendation_id = ? order by id desc limit 1").get(recId) as any;
  if (!row) return null;
  const ctx = safeJson(row.context) as ResolutionContext | null;
  const plan = safeJson(row.plan) as ResolutionPlan | null;
  const known = new Map((ctx?.concepts || []).map((c) => [c.id, c]));
  const conceptLink = (id: string) => ({ id, name: known.get(id)?.name ?? null, scope: known.get(id)?.scope ?? null, graph_url: config.repo2graphUrl ? `${config.repo2graphUrl}/gitree/concepts/${encodeURIComponent(id)}` : null });
  return {
    id: row.id, recommendation_id: row.recommendation_id, request_id: row.request_id, status: row.status, gate_outcome: row.gate_outcome ?? null, error: row.error, created_at: row.created_at, finished_at: row.finished_at,
    gate: safeJson(row.gate),
    plan: plan ? { ...plan, concepts_used: plan.concepts_used.map(conceptLink) } : null,
    context: ctx ? { control_id: ctx.control_id, playbook: ctx.playbook, resource: ctx.resource, concepts: ctx.concepts.map((c) => conceptLink(c.id)), history: ctx.history } : null,
  };
}

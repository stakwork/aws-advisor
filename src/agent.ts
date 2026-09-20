import { config } from "./config.js";
import { getPrompt, registerDefaultPrompt } from "./prompts.js";
import { OPERATIONAL_PATTERNS } from "./pools.js";
import { canonicalResource } from "./resource_id.js";
import { credentialGate } from "./gate.js";
import { db } from "./db.js";
import { RecInput } from "./rules.js";
import { changeSummaryText } from "./changes.js";
import { listDecisionConcepts } from "./concepts.js";
import { checkTiers } from "./tiercheck.js";

/**
 * repo2graph client. The advisor posts a findings batch to POST /repo/agent, gets a request id back
 * immediately, and receives the schema-shaped answer on the webhook (with GET /progress as fallback).
 */

const ACTION_TYPES = [
  "terminate_stopped_instance", "delete_snapshot", "release_eip", "set_log_retention", "rightsize_instance",
  "stop_instance", "aurora_set_storage_standard", "aurora_set_storage_iopt", "delete_volume", "buy_reservation",
  "change_storage_class", "other",
];

export const RECOMMENDATION_SCHEMA = {
  type: "object",
  properties: {
    recommendations: {
      type: "array",
      items: {
        type: "object",
        properties: {
          title: { type: "string" },
          resource: { type: "string", description: "resource id or ARN exactly as it appears in the findings" },
          resource_name: { type: "string" },
          action_type: { type: "string", enum: ACTION_TYPES },
          est_monthly_saving: { type: "number", description: "USD per month, 0 if unknown" },
          tier: { type: "string", enum: ["auto", "approve", "report"] },
          confidence: { type: "number", description: "0 to 1" },
          rationale: { type: "string" },
        },
        required: ["title", "resource", "action_type", "est_monthly_saving", "tier", "confidence", "rationale"],
        additionalProperties: false,
      },
    },
  },
  required: ["recommendations"],
  additionalProperties: false,
};

const SYSTEM = `You are an AWS cost optimisation advisor for a single AWS account. You receive a batch of findings
(from Powerpipe's AWS Thrifty benchmarks and custom queries) plus draft recommendations produced by fixed rules.
Your job: deduplicate and correlate the findings, drop false positives, rank by real monthly saving, and return
concrete recommendations with an estimated saving, a risk tier (auto = reversible, approve = needs a human,
report = never automate) and a short rationale a busy engineer can act on. Prefer fewer, larger, well-evidenced
items over long lists. Before recommending, verify facts with the aws_* tools (they are read-only and query the
live account): aws_steampipe_query for existing resources such as VPC endpoints or attached volumes, aws_price_lookup
for real on-demand prices, aws_cloudwatch_metric for utilisation, aws_resource_cost_history and aws_findings_for_resource
for history, aws_recommendation_history for what the team already decided, aws_instance_inventory for the fleet (which
instances run, their SSM status, CPU, EBS and list price), and aws_instance_probe for memory, disk and processes on an
SSM-managed instance. Do not guess a price or assume a resource is missing without checking.
Past team decisions are stored as Concepts under the namespace aws/cost-advisor; call learn_concept with a concept id
from the prompt when you need the full record before proposing something similar.
Emit the JSON object first, then any commentary.`;
registerDefaultPrompt("findings", `${SYSTEM}\n${OPERATIONAL_PATTERNS}`);

function buildPrompt(runId: number): string {
  const findings = db.prepare("select control_id, control_title, status, resource, reason from findings where run_id = ? and status = 'alarm' order by control_id").all(runId) as any[];
  const byControl = new Map<string, any[]>();
  for (const f of findings) byControl.set(f.control_id, [...(byControl.get(f.control_id) || []), f]);
  const lines: string[] = ["## Findings (alarm) grouped by control"];
  for (const [control, rows] of byControl) {
    lines.push(`\n### ${control} — ${rows[0].control_title} (${rows.length})`);
    for (const r of rows.slice(0, 40)) lines.push(`- ${r.resource}: ${r.reason}`);
    if (rows.length > 40) lines.push(`- … ${rows.length - 40} more`);
  }
  const recs = db.prepare("select rule, title, est_monthly_saving, tier, confidence, rationale from recommendations where run_id = ? and source = 'rules' and status = 'open'").all(runId) as any[];
  lines.push("\n## Draft recommendations from fixed rules");
  for (const r of recs) lines.push(`- [${r.rule}] ${r.title} — est ${r.est_monthly_saving ?? "?"} USD/mo, tier ${r.tier}, confidence ${r.confidence}. ${r.rationale}`);
  const rejected = db.prepare("select title, decision_reason from recommendations where status = 'rejected' and decision_reason is not null order by decided_at desc limit 30").all() as any[];
  if (rejected.length) {
    lines.push("\n## Previously rejected by the team (do not propose again unless something changed)");
    for (const r of rejected) lines.push(`- ${r.title}: ${r.decision_reason}`);
  }
  const metrics = db.prepare("select key, label, value from metrics where run_id = ? order by key, value desc").all(runId) as any[];
  lines.push("\n## Last full month cost context");
  for (const m of metrics) lines.push(`- ${m.key} / ${m.label}: ${m.value}`);
  const changes = changeSummaryText(runId);
  if (changes) lines.push("", changes);
  return lines.join("\n");
}

export interface AgentRequest {
  prompt: string;
  systemOverride: string;
  jsonSchema: unknown;
  sessionId: string;
  agentName: string;
  metadata?: Record<string, unknown>;
  maxTurns?: number;
  /** Which advisor flow owns the answer; the callback routes on it. */
  link: { kind: "findings"; runId: number } | { kind: "incident"; alertId: number } | { kind: "resolution"; recommendationId: number };
}

export interface AgentAccepted { requestId: string; sessionId: string; eventsToken: string }

/**
 * Posts one request to repo2graph's agent and records it in agent_runs. Shared by the findings dispatch
 * and the alert investigations: same model, same tool config, the advisor's MCP fact server and the
 * webhook back to /api/agent-callback; only prompt, system prompt, schema and metadata differ.
 */
export async function postAgentRequest(req: AgentRequest): Promise<AgentAccepted> {
  if (!config.repo2graphUrl) throw new Error("REPO2GRAPH_URL is not configured");
  const body = {
    prompt: req.prompt,
    systemOverride: req.systemOverride,
    ignoreRepoInfo: true,
    model: config.agentModel,
    ...(config.agentApiKey ? { apiKey: config.agentApiKey } : {}),
    toolsConfig: { bash: false, create_pr: false, web_search: config.agentWebSearch },
    // The advisor's own read-only fact server; tools arrive at the agent as aws_<tool>.
    mcpServers: [{ name: "aws", url: `${config.publicUrl}/mcp`, ...(config.mcpToken ? { token: config.mcpToken } : {}) }],
    jsonSchema: req.jsonSchema,
    // Unique per dispatch: repo2graph aborts an in-flight run when a new request reuses its sessionId.
    sessionId: req.sessionId,
    agentName: req.agentName,
    _metadata: req.metadata ?? {},
    maxTurns: req.maxTurns ?? 60,
    webhookUrl: `${config.publicUrl}/api/agent-callback${config.callbackSecret ? `?key=${encodeURIComponent(config.callbackSecret)}` : ""}`,
  };
  const res = await fetch(`${config.repo2graphUrl}/repo/agent`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-api-token": config.repo2graphToken },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`repo2graph responded ${res.status}: ${(await res.text()).slice(0, 300)}`);
  const data = (await res.json()) as { request_id: string; sessionId: string; events_token: string };
  db.prepare("insert into agent_runs(kind, run_id, alert_id, recommendation_id, request_id, session_id, events_token) values (?, ?, ?, ?, ?, ?, ?)")
    .run(req.link.kind, req.link.kind === "findings" ? req.link.runId : null, req.link.kind === "incident" ? req.link.alertId : null, req.link.kind === "resolution" ? req.link.recommendationId : null, data.request_id, data.sessionId, data.events_token);
  return { requestId: data.request_id, sessionId: data.sessionId, eventsToken: data.events_token };
}

export async function dispatchToAgent(runId: number): Promise<{ requestId: string }> {
  if (!(await credentialGate("agent-dispatch")).ok) throw new Error("AWS credentials are not working; fix them in Settings before sending findings to the agent");
  if (!config.repo2graphUrl) throw new Error("REPO2GRAPH_URL is not configured");
  let prompt = buildPrompt(runId);
  // Decisions mirrored into repo2graph's Concept graph; the agent can learn_concept any of them for the full record.
  const concepts = await listDecisionConcepts();
  if (concepts.length) {
    prompt += "\n\n## Team decisions on record (Concepts): generic rules first, then internal decisions\n" + concepts.map((c) => `- (${c.scope === "generic" ? "GENERIC rule, applies to any account" : "internal, this resource only"}) [${c.id}] ${c.name}: ${c.description}`).join("\n");
  }
  const { requestId } = await postAgentRequest({
    prompt,
    systemOverride: getPrompt("findings"),
    jsonSchema: RECOMMENDATION_SCHEMA,
    sessionId: `aws-advisor-run-${runId}-${Date.now().toString(36)}`,
    agentName: "aws-cost-advisor",
    metadata: { runId },
    link: { kind: "findings", runId },
  });
  return { requestId };
}

/** Fallback when the webhook is missed: read repo2graph's on-disk request record and import it. */
export async function pollAgentResult(requestId: string): Promise<{ status: string; imported?: number }> {
  const res = await fetch(`${config.repo2graphUrl}/progress?request_id=${encodeURIComponent(requestId)}`, {
    headers: { "x-api-token": config.repo2graphToken },
  });
  if (!res.ok) throw new Error(`repo2graph responded ${res.status}`);
  const rec = (await res.json()) as { status: string; result?: any; error?: any; retryable?: boolean };
  if (rec.status === "completed" || rec.status === "failed") {
    const r = await handleAgentResult(requestId, rec);
    return { status: rec.status, imported: r.imported };
  }
  return { status: rec.status };
}

/** Opens repo2graph's SSE event stream for a request, using the per-run events token. */
export async function openAgentEvents(requestId: string): Promise<Response> {
  const row = db.prepare("select events_token from agent_runs where request_id = ?").get(requestId) as { events_token: string } | undefined;
  if (!row) throw new Error(`unknown agent request ${requestId}`);
  const res = await fetch(`${config.repo2graphUrl}/events/${encodeURIComponent(requestId)}?token=${encodeURIComponent(row.events_token)}`, {
    headers: { accept: "text/event-stream" },
  });
  if (!res.ok || !res.body) throw new Error(`repo2graph events responded ${res.status}`);
  return res;
}

export interface AgentRunRow { id: number; kind: "findings" | "incident" | "resolution"; run_id: number | null; alert_id: number | null; recommendation_id?: number | null; request_id: string }

/**
 * Handles the terminal webhook from repo2graph (also usable with a polled /progress record). Routes on the
 * agent_runs row's kind: a findings batch imports recommendations, an incident completes the investigation, a
 * resolution completes the tailored plan for one recommendation (src/resolve.ts).
 * Async because every imported recommendation first goes through Jev's tier check (src/tiercheck.ts).
 */
export async function handleAgentResult(requestId: string, payload: { status: string; result?: any; error?: any }): Promise<{ kind: string; imported: number }> {
  const run = db.prepare("select id, kind, run_id, alert_id, recommendation_id, request_id, status from agent_runs where request_id = ?").get(requestId) as (AgentRunRow & { status?: string }) | undefined;
  if (!run) throw new Error(`unknown agent request ${requestId}`);
  // one result per dispatch: a second callback (a replay, or a forged one after the real result) changes nothing
  if (run.status && run.status !== "pending") throw new Error(`agent request ${requestId} is already ${run.status}`);
  if (payload.status !== "completed") {
    db.prepare("update agent_runs set status = 'failed', error = ?, finished_at = datetime('now') where id = ?").run(JSON.stringify(payload.error ?? payload), run.id);
    if (run.kind === "incident") await completeIncident(run, payload);
    if (run.kind === "resolution") completeResolution(run, payload);
    return { kind: run.kind, imported: 0 };
  }
  db.prepare("update agent_runs set status = 'completed', result = ?, finished_at = datetime('now') where id = ?").run(JSON.stringify(payload.result), run.id);
  if (run.kind === "incident") return { kind: run.kind, imported: (await completeIncident(run, payload)).imported };
  if (run.kind === "resolution") { completeResolution(run, payload); return { kind: run.kind, imported: 0 }; }
  return { kind: run.kind, imported: await importFindingsResult(run, payload.result) };
}

/** The agent's recommendations as RecInputs (rule agent:<action_type>, evidence = the item as returned). Exported for the tier check script and tests. */
export function agentRecommendations(result: any): RecInput[] {
  const content = result?.content;
  const items: any[] = Array.isArray(content?.recommendations) ? content.recommendations : [];
  // The schema is enforced by repo2graph, not by us: re-check here so a forged or malformed result cannot
  // smuggle an unknown action type, an "auto" tier the rules would not give, or oversized text into the table.
  const text = (v: unknown, max: number) => (typeof v === "string" ? v.slice(0, max) : "");
  return items
    .filter((r) => r && typeof r === "object" && text(r.title, 300) && text(r.resource, 500))
    .map((r) => {
      const actionType = ACTION_TYPES.includes(r.action_type) ? r.action_type : "other";
      const tier: "auto" | "approve" | "report" = r.tier === "report" ? "report" : r.tier === "auto" ? "auto" : "approve";
      const confidence = Number.isFinite(r.confidence) ? Math.min(1, Math.max(0, Number(r.confidence))) : 0.5;
      return {
        rule: `agent:${actionType}`,
        title: text(r.title, 300),
        resource: canonicalResource(text(r.resource, 500), actionType) ?? text(r.resource, 500),
        resourceName: text(r.resource_name, 300) || undefined,
        actionType,
        estMonthlySaving: Number.isFinite(r.est_monthly_saving) ? Math.max(0, Number(r.est_monthly_saving)) : null,
        tier,
        confidence,
        rationale: text(r.rationale, 4000),
        evidence: r,
      };
    });
}

async function importFindingsResult(run: AgentRunRow, result: any): Promise<number> {
  // Jev's tier check can only make a tier stricter; the answers land in evidence.jev. No-op without a key.
  const { recs, changed, checked } = await checkTiers(agentRecommendations(result));
  if (checked) console.log(`[agent] tier check: ${checked} recommendations checked, ${changed} tier(s) tightened`);
  // lazy import to avoid a cycle at module load
  const { upsertRecommendations } = require_collector();
  upsertRecommendations(run.run_id ?? 0, recs, "agent", run.request_id);
  return recs.length;
}

// collector imports agent (dispatch); agent needs collector's upsert at call time only. The same holds for
// investigate (it posts through postAgentRequest; the callback hands its answer back here).
import * as collectorModule from "./collector.js";
import { completeIncident } from "./investigate.js";
import { completeResolution } from "./resolve.js";
function require_collector() { return collectorModule; }

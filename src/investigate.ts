import { config } from "./config.js";
import { getPrompt, registerDefaultPrompt } from "./prompts.js";
import { OPERATIONAL_PATTERNS, Pool, poolOf } from "./pools.js";
import { credentialGate } from "./gate.js";
import { db } from "./db.js";
import { S, query } from "./steampipe.js";
import { RecInput, Tier } from "./rules.js";
import { AgentRunRow, postAgentRequest } from "./agent.js";
import { upsertRecommendations } from "./collector.js";
import { canonicalResource } from "./resource_id.js";
import { NatReceiver, attributeNatTraffic } from "./watcher.js";
import { flowLogRecommendations, vpcFlowLogFacts } from "./flowlogs.js";
import { checkTiers } from "./tiercheck.js";
import { mirrorAlertsInBackground, mirrorRecommendationsInBackground } from "./graph_mirror.js";

/**
 * Alert-triggered investigations. A watcher alert (a NAT traffic spike, an instance that changed state) is
 * turned into a focused prompt: the alert and its attribution, the gateway's VPC and whether it has flow
 * logs, the last 24 hours of watcher samples, the instances involved with their inventory snapshot, and any
 * earlier incident on the same resource. repo2graph's agent investigates with the MCP tools and answers with a
 * cause, its confidence, evidence, what the episode cost, the run-rate if it persists, and concrete fixes.
 * The answer is stored in `incidents`; each fix becomes a recommendation (source agent, rule incident:<action>).
 */

export const FIX_ACTION_TYPES = ["enable_flow_logs", "add_vpc_endpoint", "add_pull_through_cache", "move_workload", "reschedule_job", "rightsize_instance", "stop_instance", "other"] as const;

/** NAT gateway pricing in us-east-1, USD; the prompt states them so the agent's cost figures are grounded. */
export const NAT_PRICE = { perGbProcessed: 0.045, perHour: 0.045 };

export const INCIDENT_SCHEMA = {
  type: "object",
  properties: {
    cause: { type: "string", description: "one or two sentences: what most likely caused the alert" },
    confidence: { type: "number", description: "0 to 1, how sure you are about the cause" },
    evidence: { type: "array", items: { type: "string" }, description: "facts you verified, one per entry, with numbers" },
    episode_cost_usd: { type: "number", description: "USD this episode cost so far (e.g. extra NAT GB x 0.045)" },
    monthly_run_rate_usd: { type: "number", description: "USD per month if the observed level persists" },
    fixes: {
      type: "array",
      items: {
        type: "object",
        properties: {
          title: { type: "string" },
          action_type: { type: "string", enum: [...FIX_ACTION_TYPES] },
          resource: { type: "string", description: "the id the fix applies to: vpc id, instance id, nat gateway id, nodegroup or repository name" },
          resource_name: { type: "string" },
          est_monthly_saving: { type: "number", description: "USD per month, 0 if unknown" },
          tier: { type: "string", enum: ["auto", "approve", "report"] },
          confidence: { type: "number", description: "0 to 1" },
          rationale: { type: "string" },
        },
        required: ["title", "action_type", "resource", "est_monthly_saving", "tier", "confidence", "rationale"],
        additionalProperties: false,
      },
    },
  },
  required: ["cause", "confidence", "evidence", "episode_cost_usd", "monthly_run_rate_usd", "fixes"],
  additionalProperties: false,
};

const INCIDENT_SYSTEM = `You are an incident investigator for a single AWS account, working for a cost advisor. A watcher raised an
alert; your job is to find the most likely cause, say how sure you are, show the evidence, put a price on the episode and
on its run-rate, and propose fixes an engineer can act on. Be concrete and numeric; prefer one well-supported cause over
a list of possibilities.
Investigate with the read-only aws_* tools before answering: aws_alert_context (the alert with its details and watcher
samples), aws_nat_attribution (instances in a NAT gateway's VPC ranked by network bytes over N hours; upper bound per
instance, ranking is what matters), aws_cloudwatch_metric (NetworkIn/NetworkOut per instance or BytesOutToDestination of
the gateway over days, to see whether the spike is periodic or new), aws_steampipe_query (VPC endpoints, flow logs, ECR
repositories, EKS node groups, security groups, anything in the account), aws_instance_inventory and aws_instance_probe
(what runs on an instance), aws_resource_cost_history and aws_findings_for_resource, aws_cloudtrail_changes (who changed
what in the account in the last days: a deploy, a scaling change or a new job often explains a traffic or cost move),
aws_log_groups (which log groups ingest the most and what they cost), aws_baseline (what is typical for the gateway or
instance, and a value scored against it) and aws_instance_history (a month of daily memory, disk, load and containers).
Limits you must respect: attribution is at instance level. Without VPC flow logs nobody can name the destination or the
pod, so do not claim to. If flow logs are missing, say so in the evidence and include an enable_flow_logs fix (tier
approve); the advisor never enables them itself. Do not propose Kubernetes-level changes as if they were verified.
Cost grounding: NAT gateway data processing costs ${NAT_PRICE.perGbProcessed} USD per GB in us-east-1 (plus
${NAT_PRICE.perHour} USD per gateway-hour, which does not change with traffic). Episode cost = GB above the baseline x
${NAT_PRICE.perGbProcessed}; run-rate = the observed hourly excess x 730 if it persisted, or x the hours per month a
recurring job would run. Data through a gateway VPC endpoint (S3, DynamoDB) is free; an ECR pull-through cache or an
interface endpoint replaces NAT processing with cheaper endpoint hours.
Fix action types: enable_flow_logs, add_vpc_endpoint, add_pull_through_cache, move_workload, reschedule_job,
rightsize_instance, stop_instance, other. Tier: auto = reversible, approve = needs a human, report = never automate.
Emit the JSON object first, then any commentary.`;
registerDefaultPrompt("incident", `${INCIDENT_SYSTEM}\n${OPERATIONAL_PATTERNS}`);

const gb = (b: number) => `${(b / 1e9).toFixed(2)} GB`;
const safeJson = (s: unknown) => { if (typeof s !== "string") return s ?? null; try { return JSON.parse(s); } catch { return s; } };
const cutoffIso = (hours: number) => new Date(Date.now() - hours * 3600_000).toISOString();

export interface AlertRow { id: number; created_at: string; kind: string; resource: string | null; message: string; details: string | null; acknowledged: number; acknowledged_by?: string | null; triage?: string | null; triage_at?: string | null }

export function getAlert(alertId: number): AlertRow | undefined {
  return db.prepare("select * from alerts where id = ?").get(alertId) as AlertRow | undefined;
}

/** Watcher samples that belong to an alert: NAT bytes for a nat_traffic alert, state codes for an instance_state alert. */
export function alertWatchSamples(alert: Pick<AlertRow, "kind" | "resource">, hours = 24) {
  if (!alert.resource) return [];
  const key = alert.kind === "nat_traffic" ? "nat_bytes_hour" : alert.kind === "instance_state" ? "instance_state" : null;
  if (!key) return [];
  const rows = db.prepare("select sample_id, collected_at, value, dims from watch_samples where key = ? and label = ? and collected_at > ? order by sample_id")
    .all(key, alert.resource, cutoffIso(hours)) as { sample_id: number; collected_at: string; value: number; dims: string | null }[];
  return rows.map((r) => ({ ...r, dims: safeJson(r.dims) }));
}

/** Everything the MCP alert_context tool and the prompt share about one alert. */
export function alertContext(alertId: number, hours = 24) {
  const alert = getAlert(alertId);
  if (!alert) return null;
  const incidents = db.prepare("select id, status, cause, confidence, episode_cost_usd, monthly_run_rate_usd, created_at, finished_at, error from incidents where alert_id = ? order by id desc").all(alertId);
  return { alert: { ...alert, details: safeJson(alert.details), triage: safeJson(alert.triage) }, watch_samples: alertWatchSamples(alert, hours), incidents };
}

interface InstanceFacts { instance_id: string; name: string | null; instance_type: string | null; state: string | null; launch_time: string | null; monthly_usd: number | null; cpu_30d: number | null; ssm_status: string | null; nodegroup: string | null; cluster: string | null; pool: Pool | null; vpc_id: string | null; subnet_id: string | null; tags: Record<string, string> }

function instanceFacts(ids: string[]): InstanceFacts[] {
  if (!ids.length) return [];
  const rows = db.prepare(`select instance_id, name, instance_type, state, launch_time, monthly_usd, cpu_30d, ssm_status, snapshot from inventory_ec2 where instance_id in (${ids.map(() => "?").join(",")})`).all(...ids) as any[];
  return rows.map((r) => {
    const snap = safeJson(r.snapshot) || {};
    const tags: Record<string, string> = snap.tags || {};
    const nodegroup = tags["eks:nodegroup-name"] || tags["alpha.eksctl.io/nodegroup-name"] || tags["aws:eks:nodegroup-name"] || null;
    const cluster = tags["eks:cluster-name"] || tags["alpha.eksctl.io/cluster-name"] || Object.keys(tags).find((k) => k.startsWith("kubernetes.io/cluster/"))?.slice("kubernetes.io/cluster/".length) || null;
    return { instance_id: r.instance_id, name: r.name, instance_type: r.instance_type, state: r.state, launch_time: r.launch_time, monthly_usd: r.monthly_usd, cpu_30d: r.cpu_30d,
      ssm_status: r.ssm_status, nodegroup, cluster, pool: poolOf(tags), vpc_id: snap.network?.vpc_id ?? null, subnet_id: snap.network?.subnet_id ?? null, tags };
  });
}

function earlierIncidents(alert: AlertRow, excludeIncidentId: number) {
  return db.prepare(`
    select i.id, i.status, i.cause, i.confidence, i.episode_cost_usd, i.monthly_run_rate_usd, i.fixes, i.created_at, a.id as alert_id, a.message
    from incidents i join alerts a on a.id = i.alert_id
    where a.resource = ? and i.id <> ? order by i.id desc limit 5`).all(alert.resource, excludeIncidentId) as any[];
}

/** Builds the investigation prompt. Steampipe lookups that fail are reported as such rather than aborting the dispatch. */
export async function buildIncidentPrompt(alert: AlertRow, incidentId: number): Promise<string> {
  const details = (safeJson(alert.details) || {}) as Record<string, any>;
  const lines: string[] = [
    `# Alert #${alert.id} (${alert.kind}) raised ${alert.created_at} UTC`,
    `Resource: ${alert.resource ?? "unknown"}`,
    `Message: ${alert.message}`,
    "",
    "## Alert details",
    "```json", JSON.stringify(details, null, 1), "```",
  ];
  const note = (what: string, e: any) => lines.push(`- ${what}: lookup failed (${String(e?.message || e).slice(0, 160)})`);
  const instanceIds = new Set<string>();

  if (alert.kind === "nat_traffic" && alert.resource) {
    const nat = alert.resource;
    lines.push("", "## NAT gateway and VPC");
    let vpcId: string | null = details.vpc_id ?? null;
    try {
      const gw = (await query<{ vpc_id: string; subnet_id: string; region: string; name: string | null; state: string }>(
        `select vpc_id, subnet_id, region, tags ->> 'Name' as name, state from ${S}.aws_vpc_nat_gateway where nat_gateway_id = $1`, [nat]))[0];
      if (gw) {
        vpcId = gw.vpc_id;
        lines.push(`- ${nat}${gw.name ? ` (${gw.name})` : ""}: VPC ${gw.vpc_id}, subnet ${gw.subnet_id}, region ${gw.region}, ${gw.state}`);
      } else lines.push(`- ${nat}: not found in the account any more`);
    } catch (e) { note("NAT gateway", e); }

    // Attribution: reuse what the watcher stored, or attribute now for an alert that predates attribution.
    let receivers: NatReceiver[] = Array.isArray(details.top_receivers) ? details.top_receivers : [];
    if (!receivers.length) {
      try {
        const att = await attributeNatTraffic(nat, 1, 10);
        receivers = att.receivers;
        vpcId = vpcId || att.vpc_id;
        if (receivers.length) db.prepare("update alerts set details = ? where id = ?").run(JSON.stringify({ ...details, vpc_id: att.vpc_id, top_receivers: receivers }), alert.id);
      } catch (e) { note("attribution", e); }
    }
    lines.push("", "## Top receivers in the alert hour (instance NetworkIn/NetworkOut, upper bound per instance; the ranking is what matters)");
    if (!receivers.length) lines.push("- none above 100 MB, or attribution was not possible");
    for (const r of receivers) { instanceIds.add(r.instance_id); lines.push(`- ${r.instance_id}${r.name ? ` (${r.name})` : ""}${r.private_ip ? ` ${r.private_ip}` : ""}: ${gb(r.bytes_in)} in, ${gb(r.bytes_out)} out`); }

    if (vpcId) {
      try {
        const v = await vpcFlowLogFacts(vpcId);
        lines.push("", `## VPC flow logs on ${vpcId}${v.vpc_name ? ` (${v.vpc_name})` : ""}`);
        if (!v.flow_logs.length) lines.push(`- NONE on the VPC or its ${v.subnets.length} subnets: destinations cannot be named; attribution stays at instance level. Include an enable_flow_logs fix (tier approve). The advisor never enables them itself.`);
        for (const f of v.flow_logs) lines.push(`- ${f.flow_log_id} on ${f.resource_id}: ${f.traffic_type || "ALL"} to ${f.log_destination_type || "?"} ${f.log_destination || ""}, aggregation ${f.max_aggregation_interval ?? "?"} s, ${f.flow_log_status || ""}`);
      } catch (e) { note("flow logs", e); }
      try {
        const eps = await query<{ service_name: string; vpc_endpoint_type: string; state: string }>(`select service_name, vpc_endpoint_type, state from ${S}.aws_vpc_endpoint where vpc_id = $1`, [vpcId]);
        lines.push("", `## VPC endpoints on ${vpcId}`);
        if (!eps.length) lines.push("- none: every byte to S3, ECR, DynamoDB, CloudWatch etc. from private subnets goes through the NAT gateway");
        for (const e of eps) lines.push(`- ${e.service_name} (${e.vpc_endpoint_type}, ${e.state})`);
      } catch (e) { note("VPC endpoints", e); }
    }

    const samples = alertWatchSamples(alert, 24);
    lines.push("", "## Watcher samples for this gateway, last 24 h (bytes in + out over the hour before each sample)");
    if (!samples.length) lines.push("- none");
    for (const s of samples) { const d = (s.dims || {}) as any; lines.push(`- ${s.collected_at}: ${gb(Number(s.value))}${d.in != null ? ` (in ${gb(Number(d.in))}, out ${gb(Number(d.out))})` : ""}`); }
    if (details.bytes_hour != null && details.baseline_avg != null) {
      const excess = Math.max(0, Number(details.bytes_hour) - Number(details.baseline_avg));
      lines.push("", `## Cost grounding (us-east-1)`,
        `- NAT data processing ${NAT_PRICE.perGbProcessed} USD/GB; the alert hour moved ${gb(Number(details.bytes_hour))} against a baseline of ${gb(Number(details.baseline_avg))} (${details.baseline_samples ?? "?"} samples), so the excess of ${gb(excess)} cost about ${(excess / 1e9 * NAT_PRICE.perGbProcessed).toFixed(2)} USD in that hour.`,
        `- If the level persisted: ${(excess / 1e9 * NAT_PRICE.perGbProcessed * 730).toFixed(0)} USD/month; verify with the samples and CloudWatch whether it is a one-off, recurring, or the new normal.`);
    }
  }

  if (alert.kind === "instance_state" && alert.resource) {
    instanceIds.add(alert.resource);
    const samples = alertWatchSamples(alert, 24);
    lines.push("", "## Watcher state samples for this instance, last 24 h");
    if (!samples.length) lines.push("- none");
    for (const s of samples) lines.push(`- ${s.collected_at}: ${(s.dims as any)?.state ?? s.value}`);
  }

  const facts = instanceFacts([...instanceIds]);
  if (facts.length) {
    lines.push("", "## Instances involved (inventory snapshot)");
    for (const i of facts) {
      lines.push(`- ${i.instance_id}${i.name ? ` (${i.name})` : ""}: ${i.instance_type}, ${i.state}, launched ${i.launch_time ?? "?"}, list price ${i.monthly_usd != null ? `${i.monthly_usd} USD/month` : "unknown"}, 30-day max CPU ${i.cpu_30d ?? "?"}%, SSM ${i.ssm_status ?? "not managed"}` +
        `${i.cluster ? `, EKS cluster ${i.cluster}` : ""}${i.nodegroup ? `, nodegroup ${i.nodegroup}` : ""}${i.vpc_id ? `, ${i.vpc_id}/${i.subnet_id}` : ""}`);
      if (i.pool) lines.push(`  pool: ${i.pool.kind} ${i.pool.name}. ${i.pool.note}`);
      const tags = Object.entries(i.tags).filter(([k]) => !/^aws:/.test(k)).slice(0, 12).map(([k, v]) => `${k}=${v}`).join(", ");
      if (tags) lines.push(`  tags: ${tags}`);
    }
  }

  const earlier = earlierIncidents(alert, incidentId);
  if (earlier.length) {
    lines.push("", "## Earlier incidents on the same resource");
    for (const e of earlier) {
      const fixes = (safeJson(e.fixes) || []) as any[];
      lines.push(`- incident #${e.id} (${e.status}, ${e.created_at}) for alert #${e.alert_id} "${e.message.slice(0, 120)}": ${e.cause ?? "no cause"}${e.confidence != null ? ` (confidence ${e.confidence})` : ""}${fixes.length ? `; fixes proposed: ${fixes.map((f) => f.action_type).join(", ")}` : ""}`);
    }
    lines.push("If the same cause recurs, say so and raise your confidence; if a proposed fix was not applied, repeat it.");
  }

  const openRecs = db.prepare("select title, status, rule from recommendations where rule like 'incident:%' or rule = 'enable_flow_logs' order by updated_at desc limit 10").all() as any[];
  if (openRecs.length) {
    lines.push("", "## Related recommendations already on file (do not duplicate; refine if you have better evidence)");
    for (const r of openRecs) lines.push(`- [${r.status}] ${r.title}`);
  }

  lines.push("", "Answer with the JSON object described by the schema: cause, confidence, evidence, episode_cost_usd, monthly_run_rate_usd, fixes.");
  return lines.join("\n");
}

export const shouldAutoInvestigate = (kind: string) => config.alertInvestigate === "auto" && Boolean(config.repo2graphUrl) && kind === "nat_traffic";

export interface InvestigateResult { incidentId: number; requestId: string }

/**
 * Starts an investigation for an alert: inserts the incident row, builds the prompt and dispatches it through
 * the shared agent client. The webhook (or a poll) completes it via completeIncident. Refuses while an earlier
 * investigation of the same alert is pending unless force is set.
 */
export async function investigateAlert(alertId: number, opts: { force?: boolean } = {}): Promise<InvestigateResult> {
  if (!(await credentialGate("investigate")).ok) throw new Error("AWS credentials are not working; fix them in Settings before investigating");
  if (config.alertInvestigate === "off") throw new Error("investigations are disabled (ALERT_INVESTIGATE=off)");
  if (!config.repo2graphUrl) throw new Error("REPO2GRAPH_URL is not configured");
  const alert = getAlert(alertId);
  if (!alert) throw new Error(`unknown alert ${alertId}`);
  const pending = db.prepare("select id, request_id from incidents where alert_id = ? and status = 'pending' order by id desc limit 1").get(alertId) as { id: number; request_id: string | null } | undefined;
  if (pending && !opts.force) {
    const err: any = new Error(`incident ${pending.id} for alert ${alertId} is still pending${pending.request_id ? ` (request ${pending.request_id})` : ""}; poll it or pass force`);
    err.code = "pending";
    throw err;
  }
  const incidentId = Number(db.prepare("insert into incidents(alert_id) values (?)").run(alertId).lastInsertRowid);
  try {
    const prompt = await buildIncidentPrompt(alert, incidentId);
    const { requestId } = await postAgentRequest({
      prompt,
      systemOverride: getPrompt("incident"),
      jsonSchema: INCIDENT_SCHEMA,
      sessionId: `aws-advisor-incident-${incidentId}-${Date.now().toString(36)}`,
      agentName: "aws-incident-investigator",
      metadata: { alertId, incidentId, kind: alert.kind },
      maxTurns: 40,
      link: { kind: "incident", alertId },
    });
    db.prepare("update incidents set request_id = ? where id = ?").run(requestId, incidentId);
    console.log(`[investigate] alert ${alertId} -> incident ${incidentId}, request ${requestId}`);
    return { incidentId, requestId };
  } catch (e: any) {
    db.prepare("update incidents set status = 'failed', error = ?, finished_at = datetime('now') where id = ?").run(String(e?.message || e).slice(0, 500), incidentId);
    throw e;
  }
}

/** Fire-and-forget variant for the watcher. */
export function investigateAlertInBackground(alertId: number): void {
  void investigateAlert(alertId).catch((e) => console.error(`[investigate] alert ${alertId} failed: ${e?.message || e}`));
}

export interface IncidentFix { title: string; action_type: string; resource: string; resource_name?: string; est_monthly_saving: number; tier: Tier; confidence: number; rationale: string; recommendation_id?: number }

/** Validates the agent's answer into the shape stored on the incident; null when it is not an incident object. */
export function parseIncidentResult(content: unknown): { cause: string; confidence: number | null; evidence: string[]; episode_cost_usd: number | null; monthly_run_rate_usd: number | null; fixes: IncidentFix[] } | null {
  const c = content as any;
  if (!c || typeof c !== "object" || typeof c.cause !== "string") return null;
  const num = (v: unknown) => (Number.isFinite(Number(v)) && v !== null && v !== "" ? Number(v) : null);
  const fixes: IncidentFix[] = (Array.isArray(c.fixes) ? c.fixes : [])
    .filter((f: any) => f && typeof f === "object" && typeof f.title === "string")
    .map((f: any) => ({
      title: String(f.title),
      action_type: (FIX_ACTION_TYPES as readonly string[]).includes(f.action_type) ? f.action_type : "other",
      resource: String(f.resource || ""),
      resource_name: f.resource_name ? String(f.resource_name) : undefined,
      est_monthly_saving: num(f.est_monthly_saving) ?? 0,
      tier: (["auto", "approve", "report"].includes(f.tier) ? f.tier : "approve") as Tier,
      confidence: Math.max(0, Math.min(1, num(f.confidence) ?? 0.5)),
      rationale: String(f.rationale || ""),
    }));
  return {
    cause: c.cause,
    confidence: num(c.confidence) == null ? null : Math.max(0, Math.min(1, num(c.confidence)!)),
    evidence: Array.isArray(c.evidence) ? c.evidence.map((e: unknown) => String(e)) : [],
    episode_cost_usd: num(c.episode_cost_usd),
    monthly_run_rate_usd: num(c.monthly_run_rate_usd),
    fixes,
  };
}

/**
 * Completes an incident from the agent's terminal payload: stores cause, confidence, evidence, costs and fixes,
 * and imports every fix as a recommendation (source agent, rule incident:<action_type>, evidence carrying the
 * incident and alert ids). Called by handleAgentResult for agent_runs of kind incident.
 */
export async function completeIncident(run: AgentRunRow, payload: { status: string; result?: any; error?: any }): Promise<{ imported: number }> {
  const incident = (db.prepare("select id, alert_id from incidents where request_id = ? order by id desc limit 1").get(run.request_id)
    ?? db.prepare("select id, alert_id from incidents where alert_id = ? and status = 'pending' order by id desc limit 1").get(run.alert_id)) as { id: number; alert_id: number } | undefined;
  if (!incident) { console.error(`[investigate] no incident for agent request ${run.request_id}`); return { imported: 0 }; }
  if (payload.status !== "completed") {
    db.prepare("update incidents set status = 'failed', error = ?, raw_result = ?, finished_at = datetime('now') where id = ?")
      .run(JSON.stringify(payload.error ?? payload).slice(0, 2000), payload.result ? JSON.stringify(payload.result) : null, incident.id);
    mirrorAlertsInBackground();
    return { imported: 0 };
  }
  const parsed = parseIncidentResult(payload.result?.content);
  if (!parsed) {
    db.prepare("update incidents set status = 'failed', error = 'the agent returned no incident object', raw_result = ?, finished_at = datetime('now') where id = ?")
      .run(JSON.stringify(payload.result), incident.id);
    mirrorAlertsInBackground();
    return { imported: 0 };
  }
  const alert = getAlert(incident.alert_id);
  const drafts: RecInput[] = parsed.fixes.map((f) => ({
    rule: `incident:${f.action_type}`,
    title: f.title,
    resource: canonicalResource(f.resource, f.action_type) || alert?.resource || `alert-${incident.alert_id}`,
    resourceName: f.resource_name,
    actionType: f.action_type,
    estMonthlySaving: f.est_monthly_saving,
    tier: f.tier,
    confidence: f.confidence,
    rationale: f.rationale,
    evidence: { incident_id: incident.id, alert_id: incident.alert_id, ...f },
  }));
  // Jev's tier check (src/tiercheck.ts) can only tighten a fix's tier; the fix stored on the incident carries the checked tier too.
  const { recs, changed } = await checkTiers(drafts);
  if (changed) console.log(`[investigate] incident ${incident.id}: Jev tightened ${changed} fix tier(s)`);
  const runId = (db.prepare("select id from runs order by id desc limit 1").get() as { id: number } | undefined)?.id ?? 0;
  upsertRecommendations(runId, recs, "agent", run.request_id, { reconcile: false });
  const fixes = parsed.fixes.map((f, i) => {
    const rec = db.prepare("select id from recommendations where fingerprint = ?").get(`${recs[i].rule}:${recs[i].resource}`) as { id: number } | undefined;
    return { ...f, tier: recs[i].tier, resource: recs[i].resource, recommendation_id: rec?.id };
  });
  db.prepare(`update incidents set status = 'completed', cause = ?, confidence = ?, evidence = ?, episode_cost_usd = ?, monthly_run_rate_usd = ?, fixes = ?, raw_result = ?, error = null, finished_at = datetime('now') where id = ?`)
    .run(parsed.cause, parsed.confidence, JSON.stringify(parsed.evidence), parsed.episode_cost_usd, parsed.monthly_run_rate_usd, JSON.stringify(fixes), JSON.stringify(payload.result), incident.id);
  console.log(`[investigate] incident ${incident.id} completed: ${parsed.fixes.length} fixes imported`);
  // The incident, its alert and the fixes (FROM_INCIDENT edges) go to the Neo4j mirror; fire-and-forget.
  mirrorAlertsInBackground();
  mirrorRecommendationsInBackground(fixes.map((f) => f.recommendation_id).filter((v): v is number => Number.isInteger(v)));
  return { imported: recs.length };
}

// ---- readers ----------------------------------------------------------------------------------------

const parseIncident = (r: any) => (r ? { ...r, evidence: safeJson(r.evidence) ?? [], fixes: safeJson(r.fixes) ?? [], raw_result: undefined } : null);

/** The latest incident for an alert, with its fixes and the recommendations they became. */
export function incidentForAlert(alertId: number) {
  const row = db.prepare("select * from incidents where alert_id = ? order by id desc limit 1").get(alertId) as any;
  return row ? withRecommendations(parseIncident(row)) : null;
}

export function getIncident(id: number) {
  const row = db.prepare("select * from incidents where id = ?").get(id) as any;
  return row ? withRecommendations(parseIncident(row)) : null;
}

function withRecommendations(incident: any) {
  const recommendations = db.prepare("select id, rule, title, resource, action_type, est_monthly_saving, tier, confidence, status from recommendations where source = 'agent' and json_extract(evidence, '$.incident_id') = ? order by coalesce(est_monthly_saving, -1) desc").all(incident.id);
  return { ...incident, recommendations };
}

export function listIncidents(limit = 100) {
  const rows = db.prepare(`
    select i.*, a.kind as alert_kind, a.resource as alert_resource, a.message as alert_message, a.created_at as alert_created_at, a.acknowledged as alert_acknowledged
    from incidents i join alerts a on a.id = i.alert_id order by i.id desc limit ?`).all(limit) as any[];
  return rows.map(parseIncident);
}

/** Alerts with their latest incident's id and status (and the completed summary the Overview card shows). */
export function listAlerts(filter: "open" | "acknowledged" | "all", limit = 200) {
  const where = filter === "open" ? "where a.acknowledged = 0" : filter === "acknowledged" ? "where a.acknowledged = 1" : "";
  const rows = db.prepare(`
    select a.*, i.id as incident_id, i.status as incident_status, i.cause as incident_cause, i.confidence as incident_confidence,
           i.episode_cost_usd as incident_episode_cost_usd, i.monthly_run_rate_usd as incident_monthly_run_rate_usd, i.fixes as incident_fixes, i.error as incident_error
    from alerts a left join incidents i on i.id = (select id from incidents where alert_id = a.id order by id desc limit 1)
    ${where} order by a.id desc limit ?`).all(limit) as any[];
  return rows.map((r) => ({ ...r, triage: safeJson(r.triage), incident_fixes: withCurrentStatus(safeJson(r.incident_fixes) ?? (r.incident_id ? [] : null)) }));
}

/** Fixes are stored as proposed; the recommendation's live status and decision are what the UI must show. */
export function withCurrentStatus(fixes: any[] | null): any[] | null {
  if (!fixes || fixes.length === 0) return fixes;
  const ids = fixes.map((f) => f.recommendation_id).filter((v) => Number.isInteger(v));
  if (ids.length === 0) return fixes;
  const rows = db.prepare(`select id, status, decided_by, decided_at, decision_scope from recommendations where id in (${ids.map(() => "?").join(",")})`).all(...ids) as any[];
  const by = new Map(rows.map((r) => [r.id, r]));
  return fixes.map((f) => {
    const rec = by.get(f.recommendation_id);
    return rec ? { ...f, status: rec.status, decided_by: rec.decided_by, decided_at: rec.decided_at, decision_scope: rec.decision_scope } : f;
  });
}

/** Refreshes the deterministic flow-logs recommendation for the VPCs behind fresh NAT alerts (watcher path, no reconcile). */
export async function refreshFlowLogRecommendations(vpcIds?: string[]): Promise<number> {
  const errors: string[] = [];
  const recs = await flowLogRecommendations({ vpcIds, onError: (m) => errors.push(m) });
  for (const e of errors) console.error(`[flowlogs] ${e}`);
  if (!recs.length) return 0;
  const runId = (db.prepare("select id from runs order by id desc limit 1").get() as { id: number } | undefined)?.id ?? 0;
  upsertRecommendations(runId, recs, "rules", undefined, { reconcile: false });
  return recs.length;
}

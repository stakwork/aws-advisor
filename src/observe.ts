/**
 * The observe task: every morning, after the review, the agent gets what changed in the last day (review
 * findings, new alerts, spend against baseline, pools, the latest run's changes) and answers with a short
 * assessment: what changed, why, what deserves attention, what it proposes. The answer is graded against the
 * numbers it was given (src/observe_grade.ts) and stored; the Overview shows it. This is the first task of the
 * runner design: a fixed brief, a schema, a rubric, a score per run.
 */
import { config } from "./config.js";
import { db } from "./db.js";
import { credentialGate } from "./gate.js";
import { getPrompt, registerDefaultPrompt } from "./prompts.js";
import { OPERATIONAL_PATTERNS } from "./pools.js";
import { latestReview } from "./review.js";
import { spendSummary } from "./spend.js";
import { getBaseline } from "./baselines.js";
import { poolSummary } from "./inventory.js";
import { changeSummaryText } from "./changes.js";
import { BriefFacts, gradeObservation } from "./observe_grade.js";
import { postAgentRequest, type AgentRunRow } from "./agent.js";
import { topLogGroups } from "./logs.js";
import { trailSummary } from "./trail.js";

db.exec(`create table if not exists observations (
  id integer primary key autoincrement,
  day text not null, request_id text, status text not null default 'pending',
  brief text not null, result text, error text, score real, grade text,
  created_at text not null default (datetime('now')), finished_at text
)`);

export const OBSERVE_SCHEMA = {
  type: "object",
  properties: {
    summary: { type: "string", description: "three sentences at most: the state of the account today" },
    changes: { type: "array", items: { type: "object", properties: {
      what: { type: "string" }, why: { type: "string", description: "the most likely cause, or 'unknown'" },
      evidence: { type: "string", description: "the numbers and the tool or fact they come from" },
      resource: { type: "string" }, expected: { type: "boolean", description: "routine for this environment" },
      confidence: { type: "number" },
    }, required: ["what", "why", "evidence", "expected", "confidence"] } },
    attention: { type: "array", items: { type: "object", properties: { item: { type: "string" }, reason: { type: "string" }, resource: { type: "string" }, urgency: { type: "string", enum: ["today", "this week", "when convenient"] } }, required: ["item", "reason", "urgency"] } },
    proposals: { type: "array", items: { type: "object", properties: { action: { type: "string" }, resource: { type: "string" }, est_monthly_saving: { type: "number" }, tier: { type: "string", enum: ["auto", "approve", "report"] }, rationale: { type: "string" } }, required: ["action", "rationale", "tier"] } },
    nothing_to_report: { type: "boolean" },
  },
  required: ["summary", "changes", "attention", "proposals", "nothing_to_report"],
};

const OBSERVE_SYSTEM = `You are the observing agent of an AWS cost advisor, writing the morning note for the team that runs a single AWS
account. You get what changed in the last day: the review's observations (idle instances, memory pressure, disks
filling, idle containers, spend steps), new alerts, spend against its baselines, the pools and their churn, and the
latest run's changes. Say what changed, why (verify with the tools before you name a cause), what deserves attention
today and what you propose. Be short and numeric: every change cites its numbers and where they come from; every
proposal names the resource and a tier (auto = reversible, approve = needs a human, report = never automate).
Verify with the read-only aws_* tools: aws_baseline (what is typical, and to score a value), aws_instance_history
(a month of daily memory, disk, load and containers per instance), aws_review_findings, aws_bill (the month priced
from our own knowledge, per service), aws_pools, aws_log_groups (ingestion and retention per log group),
aws_cloudtrail_changes (who changed what, the first place to look for the cause of a cost move), aws_instance_inventory, aws_steampipe_query, aws_cloudwatch_metric,
aws_recommendation_history (what the team already decided). A spend step that matches a decision the team approved
is expected, say so. A routine thing is not worth a sentence. If nothing changed, say so in one line and set
nothing_to_report. Emit the JSON object first, then any commentary.`;
registerDefaultPrompt("observe", `${OBSERVE_SYSTEM}\n${OPERATIONAL_PATTERNS}`);

const usd = (v: number | null | undefined) => (v == null ? "?" : `${Math.round(v)} USD`);

/** The day's brief: everything the agent is asked to look at, as text. Exported for the grader and the UI. */
export function buildObserveBrief(day: string): { text: string; facts: BriefFacts } {
  const review = latestReview();
  // open alerts of the last day in full; acknowledged ones (Jev or a person already judged them) and routine
  // instance state changes only as counts, so the brief stays about what is still open
  const allAlerts = db.prepare("select id, kind, resource, message, created_at, acknowledged from alerts where datetime(created_at) > datetime('now', '-1 day') order by id desc limit 200").all() as any[];
  const alerts = allAlerts.filter((a) => !a.acknowledged && a.kind !== "instance_state");
  const stateChanges = allAlerts.filter((a) => a.kind === "instance_state");
  const acked = allAlerts.filter((a) => a.acknowledged && a.kind !== "instance_state");
  const spend = spendSummary();
  const pools = poolSummary();
  const latestRun = db.prepare("select id, finished_at from runs where status = 'completed' order by id desc limit 1").get() as { id: number; finished_at: string } | undefined;
  const changes = latestRun ? changeSummaryText(latestRun.id) : "";
  const openRecs = db.prepare("select count(*) as n, coalesce(sum(est_monthly_saving), 0) as saving from recommendations where status = 'open'").get() as { n: number; saving: number };
  const decided = db.prepare("select id, title, status, decided_at from recommendations where datetime(decided_at) > datetime('now', '-1 day') order by decided_at desc limit 20").all() as any[];
  const lines: string[] = [`# Morning observation for ${day}`, ""];
  lines.push(`## Spend (Cost Explorer, net)`, `- latest day with data ${spend.latest?.day ?? "?"}: ${usd(spend.latest?.usd)}${spend.latest?.partial ? " (still filling in)" : ""}`, `- last 7 complete days: ${usd(spend.last_7_days.usd)}; month to date ${usd(spend.month_to_date.usd)}, projected ${usd(spend.month_to_date.projected_month_end)}; previous month ${usd(spend.previous_month.usd)}`);
  const topServices = db.prepare("select scope_id, median, p95 from baselines where scope_kind = 'service' order by median desc limit 8").all() as any[];
  if (topServices.length) lines.push(`- typical per day by service (60-day median, p95): ${topServices.map((s) => `${s.scope_id} ${Math.round(s.median)} (${Math.round(s.p95)})`).join("; ")}`);
  lines.push("", `## Review of the collected statistics (${review.day ?? "not run"}): ${review.findings.length} observation${review.findings.length === 1 ? "" : "s"}`);
  for (const f of review.findings.slice(0, 40)) lines.push(`- [${f.severity}] ${f.kind} ${f.resource}${f.resource_name && f.resource_name !== f.resource ? ` (${f.resource_name})` : ""}: ${f.message}`);
  lines.push("", `## Alerts still open from the last 24 hours: ${alerts.length}${acked.length ? ` (${acked.length} more already acknowledged)` : ""}`);
  for (const a of alerts) lines.push(`- #${a.id} ${a.kind} ${a.resource ?? ""}: ${String(a.message).slice(0, 260)}`);
  if (stateChanges.length) lines.push(`- instance state changes in the last day: ${stateChanges.length} (${stateChanges.filter((a) => /is running|New instance/.test(a.message)).length} started, ${stateChanges.filter((a) => /stopped/.test(a.message)).length} stopped, ${stateChanges.filter((a) => /is gone/.test(a.message)).length} gone; ${stateChanges.filter((a) => a.acknowledged).length} acknowledged); use aws_alert_context or aws_instance_inventory for one of them`);
  lines.push("", `## Pools (running members, list price per month)`);
  for (const p of pools.pools) lines.push(`- ${p.kind} ${p.name}: ${p.members} × ${p.instance_types.join("/")} ≈ ${usd(p.monthly_usd_list)}${p.launched_24h ? `, ${p.launched_24h} launched in 24 h` : ""}${p.churn_today ? `, churn today ${p.churn_today.launched} up / ${p.churn_today.terminated} down` : ""}`);
  lines.push(`- standalone: ${pools.standalone.members} instances ≈ ${usd(pools.standalone.monthly_usd_list)}`);
  lines.push("", `## Recommendations: ${openRecs.n} open (≈ ${usd(openRecs.saving)}/month claimed)`);
  for (const d of decided) lines.push(`- decided in the last day: #${d.id} ${d.status}: ${d.title}`);
  if (changes) lines.push("", `## Changes in the latest collection run (#${latestRun!.id})`, changes);
  const logs = topLogGroups(8);
  if (logs.refreshed_at) {
    lines.push("", `## CloudWatch Logs: ${logs.total_gb_day != null ? `${logs.total_gb_day.toFixed(1)} GB/day ingested (≈ ${Math.round(logs.total_gb_day * 30 * 0.5)} USD/month)` : "ingestion total unknown"}, ${logs.total_stored_gb.toFixed(0)} GB stored, ${logs.no_retention} groups without retention`);
    for (const g of logs.groups.slice(0, 8)) lines.push(`- ${g.name}: ${g.ingest_gb_day != null ? `${g.ingest_gb_day.toFixed(2)} GB/day` : "ingestion not metered"}, ${g.stored_gb.toFixed(1)} GB stored, retention ${g.retention_days ?? "never"}`);
  }
  const trail = trailSummary(24);
  lines.push("", `## Changes made in the account in the last 24 h (CloudTrail write events): ${trail.last_fetch ? `${trail.events} by people or deployments (${trail.noise} machine heartbeats left out)` : "not available (cloudtrail:LookupEvents not granted or not collected yet)"}`);
  for (const t of trail.by_action.slice(0, 15)) lines.push(`- ${t.n} × ${t.event_source} ${t.event_name} by ${t.username ?? "?"}${t.resources.length ? ` on ${t.resources.slice(0, 4).join(", ")}${t.resources.length > 4 ? ", …" : ""}` : ""}${t.errors ? ` (${t.errors} failed)` : ""}`);
  const natBase = (db.prepare("select scope_id, median, p95, days from baselines where scope_kind = 'nat' and metric = 'bytes_hour'").all() as any[]).map((b) => `${b.scope_id} median ${(b.median / 1e9).toFixed(2)} GB/h, p95 ${(b.p95 / 1e9).toFixed(2)} (${b.days} d)`);
  if (natBase.length) lines.push("", `## NAT baselines`, ...natBase.map((s) => `- ${s}`));
  const facts = { review_resources: review.findings.map((f: any) => f.resource), alert_ids: alerts.map((a) => a.id), alert_resources: alerts.map((a) => a.resource).filter(Boolean), review_count: review.findings.length, alert_count: alerts.length, pools: pools.pools.map((p) => p.name) };
  return { text: lines.join("\n"), facts };
}

export async function dispatchObservation(day = new Date().toISOString().slice(0, 10), opts: { force?: boolean } = {}): Promise<{ id: number; requestId: string }> {
  if (!config.repo2graphUrl) throw new Error("REPO2GRAPH_URL is not configured");
  if (!(await credentialGate("observe")).ok) throw new Error("AWS credentials are not working; the observation needs live facts");
  const existing = db.prepare("select id, status from observations where day = ? order by id desc limit 1").get(day) as { id: number; status: string } | undefined;
  if (existing && existing.status === "pending" && !opts.force) throw new Error(`an observation for ${day} is already running`);
  const brief = buildObserveBrief(day);
  const id = Number(db.prepare("insert into observations(day, brief) values (?, ?)").run(day, brief.text).lastInsertRowid);
  const { requestId } = await postAgentRequest({
    prompt: brief.text,
    systemOverride: getPrompt("observe"),
    jsonSchema: OBSERVE_SCHEMA,
    sessionId: `aws-advisor-observe-${day}-${Date.now().toString(36)}`,
    agentName: "aws-observer",
    metadata: { day, observationId: id },
    maxTurns: 40,
    link: { kind: "observe", day },
  });
  db.prepare("update observations set request_id = ? where id = ?").run(requestId, id);
  return { id, requestId };
}

export function completeObservation(run: AgentRunRow, payload: { status: string; result?: any; error?: any }): void {
  const row = db.prepare("select id, day, brief from observations where request_id = ? order by id desc limit 1").get(run.request_id) as { id: number; day: string; brief: string } | undefined;
  if (!row) return;
  if (payload.status !== "completed") {
    db.prepare("update observations set status = 'failed', error = ?, finished_at = datetime('now') where id = ?").run(JSON.stringify(payload.error ?? payload).slice(0, 2000), row.id);
    return;
  }
  const content = payload.result?.content ?? payload.result;
  const grade = gradeObservation(content, buildObserveBrief(row.day).facts);
  db.prepare("update observations set status = 'completed', result = ?, score = ?, grade = ?, finished_at = datetime('now') where id = ?").run(JSON.stringify(content), grade.score, JSON.stringify(grade), row.id);
  console.log(`[observe] ${row.day}: score ${grade.score.toFixed(2)} (${grade.checks.filter((c) => c.pass).length}/${grade.checks.length})`);
}

export function latestObservation() {
  const row = db.prepare("select * from observations order by id desc limit 1").get() as any;
  if (!row) return null;
  const safe = (s: string | null) => { if (!s) return null; try { return JSON.parse(s); } catch { return s; } };
  return { ...row, result: safe(row.result), grade: safe(row.grade) };
}
export function listObservations(limit = 30) {
  return (db.prepare("select id, day, status, score, created_at, finished_at from observations order by id desc limit ?").all(limit) as any[]);
}

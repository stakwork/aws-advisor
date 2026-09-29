/**
 * The usage investigation: a real agent run for the boxes the typed review is not sure about.
 *
 * Jev's daily review (src/usage_review.ts) answers from a fixed brief. When it is unsure of its pick, or in two
 * minds about whether the quiet windows are real, the box is handed to the agent (task `usage`, tasks/usage/),
 * which can go and look: the probes and activity signals, the containers and what they log, the peers behind
 * the connections, CloudWatch metrics, the log groups, the balancers and DNS in front, the graph, the executor
 * ledger. It answers with a typed verdict (confirm / adjust / keep_running), the window, its confidence, the
 * reasoning, the evidence and, per busy stretch, what caused it and whether that was people. The answer is
 * graded by the task's rubric, stored in `usage_investigations`, and written into `usage_reviews` as the box's
 * decision (model `agent:<model>`), so the office-hours action follows it for a box tagged `AdvisorAutoPark=ON`.
 *
 * Once a day after the review, at most `USAGE_AGENT_MAX_PER_DAY` boxes are sent, the least recently investigated
 * first, none twice within a week; "investigate with the agent" on a profile sends one box now.
 */
import { db } from "./db.js";
import { config } from "./config.js";
import { credentialGate } from "./gate.js";
import { postAgentRequest, type AgentRunRow } from "./agent.js";
import { systemPromptFor } from "./concepts.js";
import { taskFor } from "./tasks.js";
import { belowBar, gradeByRubric } from "./rubric.js";
import { latestProfile, listProfiles, type Profile } from "./usage_profile.js";
import { candidateSchedules, latestReview, reviewState, type UsageReview } from "./usage_review.js";
import { parseSchedule, offHoursPerWeek, HOURS_PER_WEEK } from "./actions/schedule_hours.js";

db.exec(`create table if not exists usage_investigations (
  id integer primary key autoincrement,
  subject text not null, request_id text, status text not null default 'pending',
  brief text not null, result text, error text, score real, grade text,
  created_at text not null default (datetime('now')), finished_at text
);
create index if not exists usage_investigations_subject on usage_investigations(subject, id)`);

/** Jev's pick under this confidence is "not sure". */
export const UNSURE_CONFIDENCE = 0.75;
/** A quiet_is_real answer inside this band is "in two minds". */
export const UNSURE_QUIET_BAND: [number, number] = [0.3, 0.7];
/** A box is not sent to the agent again within this many days. */
export const INVESTIGATE_COOLDOWN_DAYS = 7;

export interface UsageInvestigation { id: number; subject: string; request_id: string | null; status: string; result: any; error: string | null; score: number | null; grade: any; created_at: string; finished_at: string | null; below_bar: string[] | null }

/** Whether a box's review leaves room for doubt, and why. Pure. */
export function isUnsure(review: UsageReview | null, profile: Pick<Profile, "suggested_schedule" | "confidence" | "quiet_hours_week">): { unsure: boolean; why: string } {
  if (!review) return profile.suggested_schedule || profile.quiet_hours_week >= 20 ? { unsure: true, why: "no review yet" } : { unsure: false, why: "no quiet hours worth a look" };
  if (review.verdict !== "keep_running" && review.confidence < UNSURE_CONFIDENCE) return { unsure: true, why: `Jev picked ${review.schedule} at only ${review.confidence}` };
  if (review.quiet_is_real != null && review.quiet_is_real >= UNSURE_QUIET_BAND[0] && review.quiet_is_real <= UNSURE_QUIET_BAND[1]) return { unsure: true, why: `Jev is in two minds about the quiet windows (${review.quiet_is_real})` };
  if (review.verdict === "keep_running" && (profile.suggested_schedule || profile.quiet_hours_week >= 40) && review.confidence < UNSURE_CONFIDENCE) return { unsure: true, why: `kept running at only ${review.confidence} with ${profile.quiet_hours_week} quiet hours a week` };
  return { unsure: false, why: review.verdict === "keep_running" ? "Jev is sure it should keep running" : `Jev is sure of ${review.schedule}` };
}

/** The brief the agent receives: the same state Jev saw, the candidate windows, Jev's verdict, and what to check. */
export function buildUsageBrief(p: Profile): { text: string; facts: Record<string, unknown> } {
  const state = reviewState(p);
  const options = candidateSchedules(p);
  const review = latestReview(p.subject);
  const facts = { state, candidate_schedules: options, typed_review: review ? { verdict: review.verdict, schedule: review.schedule, confidence: review.confidence, quiet_is_real: review.quiet_is_real, busy_is_machine: review.busy_is_machine, reason: review.reason } : null };
  const text = [
    `Decide when the EC2 instance ${p.name ? `${p.name} (${p.subject})` : p.subject} is used and whether the executor may stop it outside a window. The box is tagged for auto-park or is a candidate for it; a wrong stop is what users notice, a missed stop only costs money.`,
    "",
    "What the advisor already knows is below as JSON: the usage profile (28 days folded into the hours of the week; quiet = every week quiet on CPU, network, connections, use signals, logins, container CPU and the shipped logs; busy = any week busy, with what tripped it), the latest activity with the peers behind the connections, two weeks of daily roll-ups, the containers and their logs, the role, the tags, the executor ledger, the team's decisions, the candidate windows, and the typed review Jev gave and why it was not sure.",
    "",
    "Go and look before answering, with the aws_* tools: aws_instance_apps and aws_activity_signals (what runs, what the logs say, which lines are use and which are heartbeat), aws_instance_history (a month of memory, disk, load, containers, activity), aws_cloudwatch_metric (CPU, NetworkIn/NetworkOut by the hour over a week or two), aws_instance_probe (a fresh probe now: connections and their peers, logins, front door), aws_log_groups (what it ships), aws_domain_inventory and aws_load_balancer_inventory (who reaches it), aws_recommendation_history and aws_auto_actions (what was decided and done on it), aws_graph_query (the graph around it). Memory use is not a usage signal: on a box running containers it is what Docker was given. External connections include relay peers, the swarm checker and health checkers as well as people; look at the peers and the ports before calling a connection use.",
    "",
    "Answer with the JSON object of the schema: verdict (confirm the profile's window, adjust to one of the candidates or a window of your own in the same form '<days> HH-HH UTC', or keep_running), the schedule (null for keep_running), confidence 0..1, reasoning, evidence with numbers and the tool they came from, and per busy stretch what caused it and whether that was people.",
    "",
    "```json",
    JSON.stringify(facts, null, 1),
    "```",
  ].join("\n");
  return { text, facts };
}

export interface InvestigateResult { id: number; requestId: string }

/** Sends one box to the agent. Refuses while an earlier investigation of it is pending unless forced. */
export async function investigateUsage(subject: string, opts: { force?: boolean } = {}): Promise<InvestigateResult> {
  if (!config.repo2graphUrl) throw new Error("REPO2GRAPH_URL is not configured (Settings › Agent)");
  if (!(await credentialGate("usage-investigate")).ok) throw new Error("AWS credentials are not working; the investigation needs live facts");
  const p = latestProfile(subject);
  if (!p || p.kind !== "ec2") throw new Error(`no usage profile for ${subject} yet: profile it first`);
  const pending = db.prepare("select id, request_id from usage_investigations where subject = ? and status = 'pending' order by id desc limit 1").get(subject) as { id: number; request_id: string | null } | undefined;
  if (pending && !opts.force) { const err: any = new Error(`investigation #${pending.id} of ${subject} is still running`); err.code = "pending"; throw err; }
  const brief = buildUsageBrief(p);
  const id = Number(db.prepare("insert into usage_investigations(subject, brief) values (?, ?)").run(subject, brief.text).lastInsertRowid);
  try {
    const { requestId } = await postAgentRequest({
      prompt: brief.text,
      systemOverride: await systemPromptFor("usage"),
      sessionId: `aws-advisor-usage-${subject}-${Date.now().toString(36)}`,
      agentName: "aws-usage-investigator",
      metadata: { subject, investigationId: id },
      link: { kind: "usage", subject },
    });
    db.prepare("update usage_investigations set request_id = ? where id = ?").run(requestId, id);
    console.log(`[usage-agent] ${subject} -> investigation ${id}, request ${requestId}`);
    return { id, requestId };
  } catch (e: any) {
    db.prepare("update usage_investigations set status = 'failed', error = ?, finished_at = datetime('now') where id = ?").run(String(e?.message || e).slice(0, 500), id);
    throw e;
  }
}

export interface ParsedUsageResult { verdict: "confirm" | "adjust" | "keep_running"; schedule: string | null; confidence: number; reasoning: string; evidence: string[]; busy_hours_explained: { when: string; cause: string; is_people: boolean }[] }

/** The agent's answer validated: an unknown verdict or a window that does not parse becomes keep_running, and the reason says so. Pure. */
export function parseUsageResult(content: unknown, suggested: string | null): ParsedUsageResult | null {
  const c = content as any;
  if (!c || typeof c !== "object" || typeof c.verdict !== "string") return null;
  const num = (v: unknown) => (Number.isFinite(Number(v)) && v !== null && v !== "" ? Number(v) : null);
  let verdict: ParsedUsageResult["verdict"] = ["confirm", "adjust", "keep_running"].includes(c.verdict) ? c.verdict : "keep_running";
  let schedule: string | null = typeof c.schedule === "string" && c.schedule.trim() ? c.schedule.trim().replace(/\s+/g, " ") : null;
  let reasoning = String(c.reasoning || "").slice(0, 2000);
  if (verdict !== "keep_running") {
    if (!schedule) { verdict = "keep_running"; reasoning = `${reasoning} [no window given: kept running]`.trim(); }
    else { const parsed = parseSchedule(schedule); if ("error" in parsed) { verdict = "keep_running"; reasoning = `${reasoning} [window "${schedule}" not understood: ${parsed.error}; kept running]`.trim(); schedule = null; } }
  } else schedule = null;
  if (verdict === "adjust" && schedule === suggested) verdict = "confirm";
  if (verdict === "confirm" && schedule !== suggested) verdict = "adjust";
  return {
    verdict, schedule, confidence: Math.max(0, Math.min(1, num(c.confidence) ?? 0.5)), reasoning,
    evidence: Array.isArray(c.evidence) ? c.evidence.map((e: unknown) => String(e)).slice(0, 20) : [],
    busy_hours_explained: (Array.isArray(c.busy_hours_explained) ? c.busy_hours_explained : []).filter((x: any) => x && typeof x === "object").map((x: any) => ({ when: String(x.when || ""), cause: String(x.cause || ""), is_people: Boolean(x.is_people) })).slice(0, 30),
  };
}

const upsertReview = db.prepare(`insert into usage_reviews(subject, reviewed_at, verdict, schedule, off_hours_week, est_usd_month, confidence, quiet_is_real, busy_is_machine, reason, options, state, model, call_id)
  values (@subject, @reviewed_at, @verdict, @schedule, @off_hours_week, @est_usd_month, @confidence, null, null, @reason, '{}', null, @model, null)
  on conflict(subject) do update set reviewed_at = excluded.reviewed_at, verdict = excluded.verdict, schedule = excluded.schedule, off_hours_week = excluded.off_hours_week, est_usd_month = excluded.est_usd_month, confidence = excluded.confidence,
    quiet_is_real = null, busy_is_machine = null, reason = excluded.reason, options = '{}', state = null, model = excluded.model, call_id = null`);

/** Stores the agent's answer, grades it, and makes it the box's decision. Called by handleAgentResult for agent_runs of kind usage. */
export function completeUsageInvestigation(run: AgentRunRow, payload: { status: string; result?: any; error?: any }): void {
  const row = db.prepare("select id, subject from usage_investigations where request_id = ? order by id desc limit 1").get(run.request_id) as { id: number; subject: string } | undefined;
  if (!row) { console.error(`[usage-agent] no investigation for agent request ${run.request_id}`); return; }
  if (payload.status !== "completed") {
    db.prepare("update usage_investigations set status = 'failed', error = ?, finished_at = datetime('now') where id = ?").run(JSON.stringify(payload.error ?? payload).slice(0, 2000), row.id);
    return;
  }
  const content = payload.result?.content ?? payload.result;
  const grade = gradeByRubric(content, taskFor("usage").rubric);
  const p = latestProfile(row.subject);
  const parsed = parseUsageResult(content, p?.suggested_schedule ?? null);
  db.prepare("update usage_investigations set status = ?, result = ?, score = ?, grade = ?, finished_at = datetime('now') where id = ?").run(parsed ? "completed" : "failed", JSON.stringify(content), grade.score, JSON.stringify(grade), row.id);
  if (!parsed) { console.error(`[usage-agent] ${row.subject}: the answer is not a usage verdict`); return; }
  const inv = db.prepare("select monthly_usd from inventory_ec2 where instance_id = ?").get(row.subject) as { monthly_usd: number | null } | undefined;
  const parsedSchedule = parsed.schedule ? parseSchedule(parsed.schedule) : null;
  const off = parsedSchedule && !("error" in parsedSchedule) ? offHoursPerWeek(parsedSchedule) : null;
  const est = off != null && inv?.monthly_usd ? Math.round(inv.monthly_usd * (off / HOURS_PER_WEEK) * 100) / 100 : null;
  const held = belowBar(grade, taskFor("usage").retry.on_score_below);
  const reason = `${held ? `[answer below the bar: ${held.join(", ")}; kept running] ` : ""}${parsed.reasoning || "(no reasoning given)"}`.slice(0, 1500);
  upsertReview.run({ subject: row.subject, reviewed_at: new Date().toISOString(), verdict: held ? "keep_running" : parsed.verdict, schedule: held ? null : parsed.schedule, off_hours_week: held ? null : off, est_usd_month: held ? null : est, confidence: parsed.confidence, reason, model: `agent:${payload.result?.model || config.agentModel || "agent"}` });
  console.log(`[usage-agent] ${row.subject}: ${held ? "below the bar" : parsed.verdict}${parsed.schedule ? ` ${parsed.schedule}` : ""} (score ${grade.score.toFixed(2)})`);
  import("./graph_mirror.js").then((m) => m.mirrorUsageProfilesInBackground()).catch(() => { /* graph optional */ });
}

export function latestInvestigation(subject: string): UsageInvestigation | null {
  const r = db.prepare("select * from usage_investigations where subject = ? order by id desc limit 1").get(subject) as any;
  if (!r) return null;
  const safe = (s: string | null) => { if (!s) return null; try { return JSON.parse(s); } catch { return s; } };
  const grade = safe(r.grade);
  return { id: r.id, subject: r.subject, request_id: r.request_id, status: r.status, result: safe(r.result), error: r.error, score: r.score, grade, created_at: r.created_at, finished_at: r.finished_at, below_bar: belowBar(grade, taskFor("usage").retry.on_score_below) };
}

export interface InvestigationPassResult { candidates: number; dispatched: number; skipped: { sure: number; cooling: number; pending: number }; sent: string[]; errors: string[] }

/** The daily pass: every EC2 profile whose review is unsure, least recently investigated first, up to the day's cap. */
export async function usageInvestigationPass(onLog: (s: string) => void = () => {}, opts: { max?: number } = {}): Promise<InvestigationPassResult> {
  const out: InvestigationPassResult = { candidates: 0, dispatched: 0, skipped: { sure: 0, cooling: 0, pending: 0 }, sent: [], errors: [] };
  const max = opts.max ?? Math.max(0, Math.round(config.usageAgentMaxPerDay));
  if (!config.repo2graphUrl) { out.errors.push("REPO2GRAPH_URL is not configured: no agent investigation"); return out; }
  if (!max) { out.errors.push("USAGE_AGENT_MAX_PER_DAY is 0: no agent investigation"); return out; }
  const queue: { subject: string; last: string | null; why: string }[] = [];
  for (const p of listProfiles("ec2")) {
    const full = latestProfile(p.subject); if (!full) continue;
    const u = isUnsure(latestReview(p.subject), full);
    if (!u.unsure) { out.skipped.sure++; continue; }
    out.candidates++;
    const last = latestInvestigation(p.subject);
    if (last?.status === "pending") { out.skipped.pending++; continue; }
    if (last && Date.now() - new Date(last.created_at.replace(" ", "T") + "Z").getTime() < INVESTIGATE_COOLDOWN_DAYS * 86400000) { out.skipped.cooling++; continue; }
    queue.push({ subject: p.subject, last: last?.created_at ?? null, why: u.why });
  }
  queue.sort((a, b) => (a.last || "").localeCompare(b.last || ""));
  for (const q of queue.slice(0, max)) {
    try { const r = await investigateUsage(q.subject); out.dispatched++; out.sent.push(q.subject); onLog(`${q.subject}: sent to the agent (${q.why}) as investigation #${r.id}`); }
    catch (e: any) { out.errors.push(`${q.subject}: ${String(e?.message || e).slice(0, 160)}`); if (e?.name === "QuotaError") break; }
  }
  return out;
}

/**
 * Threads with the agent. On a recommendation: the engineer carrying out the plan and the agent, back and forth,
 * with the recommendation, its latest tailored plan, what happened to each step (src/progress.ts outcomes) and the
 * thread so far as the brief. Account-wide (recommendation_id null, one thread): the same, with the morning
 * observation brief (src/observe.ts: spend, review, alerts, pools, changes, logs) and the open recommendations as
 * the context instead of one plan. Each message the person writes becomes one agent request (kind chat,
 * tasks/chat); the answer lands as the next message through the webhook (completeChat) or the poll. The agent may
 * hand back corrected steps (`step_fixes`) and say a new plan is due (`suggest_replan`); both stay on the message.
 */
import { config } from "./config.js";
import { db } from "./db.js";
import { AgentRunRow, postAgentRequest } from "./agent.js";
import { getPrompt } from "./prompts.js";
import { Progress, outcomesText, parseProgress } from "./progress.js";
import { ResolutionPlan, RecRow, resourceFacts } from "./resolve.js";

db.exec(`create table if not exists recommendation_messages (
  id integer primary key autoincrement,
  recommendation_id integer references recommendations(id) on delete cascade,
  role text not null,
  author text,
  content text not null default '',
  extra text,
  request_id text,
  status text not null default 'completed',
  error text,
  created_at text not null default (datetime('now')),
  finished_at text
);
create index if not exists recommendation_messages_rec on recommendation_messages(recommendation_id, id)`);
// A database created by the first cut of this table had recommendation_id NOT NULL; the account-wide thread needs null.
if ((db.pragma("table_info(recommendation_messages)") as { name: string; notnull: number }[]).some((c) => c.name === "recommendation_id" && c.notnull)) {
  db.exec(`alter table recommendation_messages rename to recommendation_messages_old;
    create table recommendation_messages (id integer primary key autoincrement, recommendation_id integer references recommendations(id) on delete cascade, role text not null, author text, content text not null default '', extra text, request_id text, status text not null default 'completed', error text, created_at text not null default (datetime('now')), finished_at text);
    insert into recommendation_messages select * from recommendation_messages_old;
    drop table recommendation_messages_old;
    create index if not exists recommendation_messages_rec on recommendation_messages(recommendation_id, id)`);
}

export const MAX_MESSAGE = 8000;
export const THREAD_CONTEXT = 12;

export interface Message { id: number; recommendation_id: number | null; role: "user" | "agent"; author: string | null; content: string; extra: { suggest_replan?: boolean; step_fixes?: { step: number; step_text: string; command?: string; verify?: string }[] } | null; request_id: string | null; status: "pending" | "completed" | "failed"; error: string | null; created_at: string; finished_at: string | null }

const safeJson = (s: unknown) => { if (typeof s !== "string" || !s) return null; try { return JSON.parse(s); } catch { return null; } };

/** The messages of one thread: a recommendation's, or the account-wide one (`recId` null), oldest first. */
export function listMessages(recId: number | null, limit = 200): Message[] {
  const rows = recId == null
    ? db.prepare("select * from recommendation_messages where recommendation_id is null order by id limit ?").all(limit)
    : db.prepare("select * from recommendation_messages where recommendation_id = ? order by id limit ?").all(recId, limit);
  return (rows as any[]).map((m) => ({ ...m, extra: safeJson(m.extra) }));
}

/** The account-wide brief: today's observation text (what the advisor knows now) and the open recommendations. Pure given its inputs. */
export function buildAccountPrompt(observation: string, openRecs: { id: number; title: string; status: string; est_monthly_saving: number | null; resource: string | null }[], thread: Pick<Message, "role" | "author" | "content" | "status">[], message: string): string {
  const lines: string[] = ["# Thread with the team about this AWS account", "", "## What the advisor knows today", observation.replace(/^# .*\n/, "").trim() || "(no observation yet: no collection run has completed)"];
  lines.push("", `## Open recommendations (${openRecs.length}${openRecs.length >= 30 ? ", top 30 by saving" : ""})`);
  if (!openRecs.length) lines.push("- none");
  for (const r of openRecs) lines.push(`- #${r.id} [${r.status}] ${r.title}${r.est_monthly_saving != null ? ` (≈ ${Math.round(r.est_monthly_saving)} USD/month)` : ""}${r.resource ? ` on ${r.resource}` : ""}`);
  lines.push("", "## The conversation so far");
  const past = thread.filter((m) => m.status === "completed" && m.content).slice(-THREAD_CONTEXT);
  if (!past.length) lines.push("- this is the first message");
  for (const m of past) lines.push(`**${m.role === "agent" ? "advisor" : m.author || "engineer"}:** ${m.content.slice(0, 2500)}`, "");
  lines.push("## The new message to answer", message, "", "Answer with the JSON object described by the schema: reply (step_fixes and suggest_replan stay empty here; there is no plan).");
  return lines.join("\n");
}

/** The latest completed tailored plan for the recommendation, if any. */
export function latestPlan(recId: number): { resolutionId: number; plan: ResolutionPlan } | null {
  const row = db.prepare("select id, plan from resolutions where recommendation_id = ? and status = 'completed' order by id desc limit 1").get(recId) as { id: number; plan: string | null } | undefined;
  const plan = row ? (safeJson(row.plan) as ResolutionPlan | null) : null;
  return row && plan ? { resolutionId: row.id, plan } : null;
}

/** The brief for one turn: the recommendation, the plan, what happened, the thread, then the new message. Pure. */
export function buildChatPrompt(rec: RecRow, facts: unknown, plan: { resolutionId: number; plan: ResolutionPlan } | null, progress: Progress | null, thread: Pick<Message, "role" | "author" | "content" | "status">[], message: string): string {
  const lines: string[] = [
    `# Thread on recommendation #${rec.id}: ${rec.title}`,
    `Rule ${rec.rule} (source ${rec.source}), action ${rec.action_type}, tier ${rec.tier}, estimated saving ${rec.est_monthly_saving != null ? `${Math.round(rec.est_monthly_saving)} USD/month` : "unknown"}, status ${rec.status}${rec.decision_reason ? `, decision reason: "${rec.decision_reason}"` : ""}.`,
    `Resource: ${rec.resource ?? "unknown"}${rec.resource_name && rec.resource_name !== rec.resource ? ` (${rec.resource_name})` : ""}`,
    "", "## Rationale", rec.rationale || "(none)",
    "", "## Resource facts (advisor inventory)", "```json", JSON.stringify(facts ?? {}, null, 1).slice(0, 4000), "```",
  ];
  if (plan) {
    lines.push("", `## The current tailored plan (resolution ${plan.resolutionId})`, plan.plan.summary || "");
    plan.plan.plan.forEach((s, i) => { lines.push(`${i + 1}. ${s.step}`); if (s.command) lines.push("```", s.command, "```"); if (s.verify) lines.push(`   verify: ${s.verify}`); });
    if (plan.plan.needs_from_human.length) lines.push("Needs from a human:", ...plan.plan.needs_from_human.map((n) => `- ${n}`));
  } else lines.push("", "## Plan", "No tailored plan has been written yet; the person is working from the rationale or the generic playbook.");
  const tried = plan && progress?.plan === `resolution:${plan.resolutionId}` ? outcomesText(plan.plan.plan, progress) : "";
  lines.push("", "## What happened when the steps were tried", tried || "- nothing recorded yet");
  lines.push("", "## The conversation so far");
  const past = thread.filter((m) => m.status === "completed" && m.content).slice(-THREAD_CONTEXT);
  if (!past.length) lines.push("- this is the first message");
  for (const m of past) lines.push(`**${m.role === "agent" ? "advisor" : m.author || "engineer"}:** ${m.content.slice(0, 2500)}`, "");
  lines.push("## The new message to answer", message, "", "Answer with the JSON object described by the schema: reply, suggest_replan, step_fixes.");
  return lines.join("\n");
}

/** Records the person's message and asks the agent; the answer arrives through the webhook. `recId` null = the account-wide thread. */
export async function askAboutRecommendation(recId: number | null, message: string, author: string | null): Promise<{ user: Message; agent: Message }> {
  const rec = recId == null ? null : (db.prepare("select * from recommendations where id = ?").get(recId) as RecRow | undefined);
  if (recId != null && !rec) { const e: any = new Error("not found"); e.code = "not_found"; throw e; }
  const text = String(message || "").trim().slice(0, MAX_MESSAGE);
  if (!text) throw new Error("the message is empty");
  const pending = recId == null
    ? db.prepare("select id from recommendation_messages where recommendation_id is null and status = 'pending' limit 1").get()
    : db.prepare("select id from recommendation_messages where recommendation_id = ? and status = 'pending' limit 1").get(recId);
  if (pending) { const e: any = new Error("the agent is still answering the previous message"); e.code = "pending"; throw e; }
  if (!config.repo2graphUrl) throw new Error("REPO2GRAPH_URL is not configured: no agent can answer");
  const thread = listMessages(recId);
  const userId = Number(db.prepare("insert into recommendation_messages(recommendation_id, role, author, content, status) values (?, 'user', ?, ?, 'completed')").run(recId, author, text).lastInsertRowid);
  const agentId = Number(db.prepare("insert into recommendation_messages(recommendation_id, role, status) values (?, 'agent', 'pending')").run(recId).lastInsertRowid);
  try {
    let prompt: string;
    if (rec) prompt = buildChatPrompt(rec, resourceFacts(rec), latestPlan(rec.id), parseProgress((rec as any).progress), thread, text);
    else {
      const { buildObserveBrief } = await import("./observe.js");
      let observation = "";
      try { observation = buildObserveBrief(new Date().toISOString().slice(0, 10)).text; } catch (e: any) { observation = `(the observation brief could not be built: ${e?.message || e})`; }
      const open = db.prepare("select id, title, status, est_monthly_saving, resource from recommendations where status in ('open', 'pending', 'approved') order by coalesce(est_monthly_saving, -1) desc limit 30").all() as any[];
      prompt = buildAccountPrompt(observation, open, thread, text);
    }
    const { requestId } = await postAgentRequest({
      prompt,
      systemOverride: getPrompt("chat"),
      sessionId: `aws-advisor-chat-${recId ?? "account"}-${agentId}-${Date.now().toString(36)}`,
      agentName: rec ? "aws-resolution-chat" : "aws-account-chat",
      metadata: { recommendationId: recId, messageId: agentId },
      link: { kind: "chat", recommendationId: recId },
    });
    db.prepare("update recommendation_messages set request_id = ? where id = ?").run(requestId, agentId);
  } catch (e: any) {
    db.prepare("update recommendation_messages set status = 'failed', error = ?, finished_at = datetime('now') where id = ?").run(String(e?.message || e).slice(0, 500), agentId);
    throw e;
  }
  const rows = listMessages(recId);
  return { user: rows.find((m) => m.id === userId)!, agent: rows.find((m) => m.id === agentId)! };
}

/** Completes the pending agent message from the agent's terminal payload (called by handleAgentResult for kind chat). */
export function completeChat(run: AgentRunRow, payload: { status: string; result?: any; error?: any }): void {
  const row = (db.prepare("select id from recommendation_messages where request_id = ? order by id desc limit 1").get(run.request_id)
    ?? (run.recommendation_id ? db.prepare("select id from recommendation_messages where recommendation_id = ? and status = 'pending' order by id desc limit 1").get(run.recommendation_id)
      : db.prepare("select id from recommendation_messages where recommendation_id is null and status = 'pending' order by id desc limit 1").get())) as { id: number } | undefined;
  if (!row) { console.error(`[chat] no message for agent request ${run.request_id}`); return; }
  if (payload.status !== "completed") {
    db.prepare("update recommendation_messages set status = 'failed', error = ?, finished_at = datetime('now') where id = ?").run(JSON.stringify(payload.error ?? payload).slice(0, 2000), row.id);
    return;
  }
  const c = payload.result?.content;
  const obj = typeof c === "string" ? safeJson(c) : c;
  const reply = obj && typeof obj.reply === "string" ? obj.reply : typeof c === "string" ? c : null;
  if (!reply) {
    db.prepare("update recommendation_messages set status = 'failed', error = 'the agent returned no reply', finished_at = datetime('now') where id = ?").run(row.id);
    return;
  }
  const extra = obj && typeof obj === "object" ? { suggest_replan: Boolean(obj.suggest_replan), step_fixes: Array.isArray(obj.step_fixes) ? obj.step_fixes.filter((f: any) => f && Number.isInteger(f.step) && typeof f.step_text === "string").slice(0, 10) : [] } : null;
  db.prepare("update recommendation_messages set status = 'completed', content = ?, extra = ?, error = null, finished_at = datetime('now') where id = ?").run(reply.slice(0, 20000), extra ? JSON.stringify(extra) : null, row.id);
  console.log(`[chat] ${run.recommendation_id ? `recommendation ${run.recommendation_id}` : "account thread"}: reply of ${reply.length} chars${extra?.step_fixes?.length ? `, ${extra.step_fixes.length} step fix(es)` : ""}${extra?.suggest_replan ? ", suggests a re-plan" : ""}`);
}

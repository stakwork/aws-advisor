/**
 * Threads with the agent. On a recommendation (one thread each): the engineer carrying out the plan and the agent,
 * back and forth, with the recommendation, its latest tailored plan, what happened to each step (src/progress.ts
 * outcomes) and the thread so far as the brief. General threads (as many as the team opens, on the Chat page): a
 * short header of the account (spend, alerts, open recommendations), the index of the advisor's fact tools and the
 * conversation; the agent fetches what the question needs with the tools rather than being handed everything.
 * Each message the person writes becomes one agent request (kind chat, tasks/chat); the answer lands as the next
 * message through the webhook (completeChat) or the poll. On a recommendation the agent may hand back corrected
 * steps (`step_fixes`) and say a new plan is due (`suggest_replan`); both stay on the message.
 *
 * One repo2graph session per thread. The first message of a thread opens it with the full brief; every later
 * message is posted with the same sessionId, which makes repo2graph replay the stored conversation (our messages,
 * the agent's answers and its tool calls) in front of the new one, so the follow-up brief carries only what is
 * new: the message, and on a recommendation the plan or the step outcomes when they changed since the last turn.
 * The prompt prefix stays byte-identical across turns, so the model's prompt cache is hit instead of paid for
 * again. When the session is gone on repo2graph's side (its sessions live on its disk; GET /api/sessions/:id
 * answers 404), or the previous turn on the thread failed, a fresh session is opened with the full brief and the
 * last THREAD_CONTEXT messages, exactly as before.
 */
import { config } from "./config.js";
import { db } from "./db.js";
import { AgentRunRow, postAgentRequest } from "./agent.js";
import { getPrompt } from "./prompts.js";
import { Progress, outcomesText, parseProgress } from "./progress.js";
import { ResolutionPlan, RecRow, resourceFacts } from "./resolve.js";
import { spendSummary } from "./spend.js";
import { credentialsMeta } from "./steampipe.js";

db.exec(`create table if not exists chat_threads (
  id integer primary key autoincrement,
  recommendation_id integer references recommendations(id) on delete cascade,
  title text,
  created_by text,
  created_at text not null default (datetime('now')),
  updated_at text not null default (datetime('now'))
);
create unique index if not exists chat_threads_rec on chat_threads(recommendation_id) where recommendation_id is not null;
create table if not exists recommendation_messages (
  id integer primary key autoincrement,
  recommendation_id integer references recommendations(id) on delete cascade,
  thread_id integer references chat_threads(id) on delete cascade,
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
// The first cut (PR #8) had no threads and recommendation_id NOT NULL: give every message a thread, once.
{
  const cols = db.pragma("table_info(recommendation_messages)") as { name: string; notnull: number }[];
  if (cols.some((c) => c.name === "recommendation_id" && c.notnull)) {
    db.exec(`alter table recommendation_messages rename to recommendation_messages_old;
      create table recommendation_messages (id integer primary key autoincrement, recommendation_id integer references recommendations(id) on delete cascade, thread_id integer references chat_threads(id) on delete cascade, role text not null, author text, content text not null default '', extra text, request_id text, status text not null default 'completed', error text, created_at text not null default (datetime('now')), finished_at text);
      insert into recommendation_messages(id, recommendation_id, role, author, content, extra, request_id, status, error, created_at, finished_at) select id, recommendation_id, role, author, content, extra, request_id, status, error, created_at, finished_at from recommendation_messages_old;
      drop table recommendation_messages_old;
      create index if not exists recommendation_messages_rec on recommendation_messages(recommendation_id, id)`);
  } else if (!cols.some((c) => c.name === "thread_id")) db.exec("alter table recommendation_messages add column thread_id integer references chat_threads(id) on delete cascade");
  const orphans = db.prepare("select distinct recommendation_id from recommendation_messages where thread_id is null").all() as { recommendation_id: number | null }[];
  for (const o of orphans) {
    const id = o.recommendation_id == null
      ? Number(db.prepare("insert into chat_threads(title, created_by) values ('General', 'migration')").run().lastInsertRowid)
      : Number((db.prepare("select id from chat_threads where recommendation_id = ?").get(o.recommendation_id) as { id: number } | undefined)?.id ?? db.prepare("insert into chat_threads(recommendation_id) values (?)").run(o.recommendation_id).lastInsertRowid);
    if (o.recommendation_id == null) db.prepare("update recommendation_messages set thread_id = ? where thread_id is null and recommendation_id is null").run(id);
    else db.prepare("update recommendation_messages set thread_id = ? where thread_id is null and recommendation_id = ?").run(id, o.recommendation_id);
  }
}
db.exec("create index if not exists recommendation_messages_thread on recommendation_messages(thread_id, id)");
// The repo2graph session a thread talks in, and what its brief last carried (older threads have neither
// and open a session on their next message).
{
  const cols = (db.pragma("table_info(chat_threads)") as { name: string }[]).map((c) => c.name);
  if (!cols.includes("session_id")) db.exec("alter table chat_threads add column session_id text");
  if (!cols.includes("session_state")) db.exec("alter table chat_threads add column session_state text");
}

export const MAX_MESSAGE = 8000;
export const THREAD_CONTEXT = 12;

export interface Message { id: number; recommendation_id: number | null; thread_id: number; role: "user" | "agent"; author: string | null; content: string; extra: { suggest_replan?: boolean; step_fixes?: { step: number; step_text: string; command?: string; verify?: string }[] } | null; request_id: string | null; status: "pending" | "completed" | "failed"; error: string | null; created_at: string; finished_at: string | null }
export interface Thread { id: number; recommendation_id: number | null; title: string | null; created_by: string | null; created_at: string; updated_at: string; session_id: string | null; session_state: SessionState | null; messages: number; last_at: string | null; pending: boolean }
/** What the session has already been told, so a follow-up turn repeats none of it: the plan's resolution id and the step outcomes text. */
export interface SessionState { resolutionId: number | null; outcomes: string }

const safeJson = (s: unknown) => { if (typeof s !== "string" || !s) return null; try { return JSON.parse(s); } catch { return null; } };

const threadRow = db.prepare(`select t.*, (select count(*) from recommendation_messages m where m.thread_id = t.id) as messages,
  (select max(coalesce(m.finished_at, m.created_at)) from recommendation_messages m where m.thread_id = t.id) as last_at,
  exists(select 1 from recommendation_messages m where m.thread_id = t.id and m.status = 'pending') as pending from chat_threads t`);
const asThread = (r: any): Thread => ({ ...r, session_state: safeJson(r.session_state), pending: Boolean(r.pending) });

/** The general threads (no recommendation), most recently active first. */
export function listThreads(): Thread[] {
  return (db.prepare(`${threadRow.source} where t.recommendation_id is null order by coalesce(last_at, t.created_at) desc, t.id desc`).all() as any[]).map(asThread);
}
export function getThread(id: number): Thread | null {
  const r = db.prepare(`${threadRow.source} where t.id = ?`).get(id);
  return r ? asThread(r) : null;
}
export function createThread(title: string | null, by: string | null): Thread {
  const id = Number(db.prepare("insert into chat_threads(title, created_by) values (?, ?)").run(title?.trim().slice(0, 120) || null, by).lastInsertRowid);
  return getThread(id)!;
}
export function renameThread(id: number, title: string): Thread | null {
  const r = db.prepare("update chat_threads set title = ?, updated_at = datetime('now') where id = ?").run(title.trim().slice(0, 120) || null, id);
  return r.changes ? getThread(id) : null;
}
export function deleteThread(id: number): boolean {
  return db.prepare("delete from chat_threads where id = ? and recommendation_id is null").run(id).changes > 0;
}
/** A recommendation's own thread, made on first use when `create` is set. */
export function threadForRecommendation(recId: number, create: boolean): Thread | null {
  const r = db.prepare("select id from chat_threads where recommendation_id = ?").get(recId) as { id: number } | undefined;
  if (r) return getThread(r.id);
  if (!create) return null;
  if (!db.prepare("select 1 from recommendations where id = ?").get(recId)) return null;
  return getThread(Number(db.prepare("insert into chat_threads(recommendation_id) values (?)").run(recId).lastInsertRowid));
}

/** The messages of one thread, oldest first. */
export function listMessages(threadId: number, limit = 300): Message[] {
  return (db.prepare("select * from recommendation_messages where thread_id = ? order by id limit ?").all(threadId, limit) as any[]).map((m) => ({ ...m, extra: safeJson(m.extra) }));
}

/** What the agent can look up (the advisor's MCP fact server, arriving as aws_<name>); listed in every general brief so it pulls what the question needs. */
export const FACT_TOOLS: [name: string, what: string][] = [
  ["bill", "a month's bill by service and usage type, priced from the advisor's own knowledge"],
  ["forecast", "this month's bill forecast from what is running now"],
  ["baseline", "what is typical (median, p95) for a NAT gateway, an instance or a service"],
  ["resource_cost_history", "daily cost of one resource"],
  ["instance_inventory", "EC2 inventory: type, state, role, tags, what runs on it"],
  ["instance_history", "daily history of one instance (CPU, network, state)"],
  ["pools", "instance pools (ASG, Karpenter, Beanstalk, Batch) and their members"],
  ["rds_load", "load profile of an RDS or Aurora database: I/O, capacity, top statements"],
  ["domain_inventory", "Route 53 records and what they point at"],
  ["log_groups", "CloudWatch log groups: ingestion, retention, cost"],
  ["nat_attribution", "who is behind a NAT gateway's traffic"],
  ["cloudwatch_metric", "any CloudWatch metric series"],
  ["cloudtrail_changes", "what changed in the account (write events, who, when)"],
  ["open_recommendations", "open recommendations with full rationale and evidence; filter by rule, resource, id or saving"],
  ["recommendation_history", "past recommendations and the team's decisions with reasons"],
  ["findings_for_resource", "benchmark findings on one resource"],
  ["review_findings", "the daily review's observations"],
  ["alert_context", "a watcher alert with its context"],
  ["price_lookup", "on-demand price of an instance or database SKU"],
  ["instance_probe", "probe an instance over SSM: processes, disks, memory"],
  ["activity_signals", "is anyone using this box: per container the use-signal patterns matched with sample lines, connections, front door, logins"],
  ["propose_signal_rule", "propose that a use-signal kind is noise (or real) for an image; a person confirms"],
  ["s3_usage", "how a bucket is used: bytes by age and class, prefixes, versions, reads per day, and the lifecycle rules that fit"],
  ["graph_systems", "our systems from the knowledge graph"],
  ["graph_system", "one system and everything linked to it"],
  ["graph_bill", "the bill as the graph explains it, per system"],
  ["graph_query", "Cypher over the advisor's graph mirror"],
  ["steampipe_query", "SQL over the live AWS account through Steampipe, for anything the tools above do not cover"],
];

export interface AccountHeader { account: string | null; latest_run: string | null; spend_7d: number | null; month_to_date: number | null; projected: number | null; open_alerts: number; open_recs: number; open_saving: number }

/** The header of a general brief: a few numbers the agent should not have to fetch. */
export function accountHeader(): AccountHeader {
  const h: AccountHeader = { account: null, latest_run: null, spend_7d: null, month_to_date: null, projected: null, open_alerts: 0, open_recs: 0, open_saving: 0 };
  try { h.account = credentialsMeta()?.accountId ?? null; } catch { /* no credentials yet */ }
  try { const r = db.prepare("select finished_at from runs where status = 'completed' order by id desc limit 1").get() as { finished_at: string } | undefined; h.latest_run = r?.finished_at ?? null; } catch { /* no runs table rows */ }
  try { const s = spendSummary(); h.spend_7d = s.last_7_days.usd ?? null; h.month_to_date = s.month_to_date.usd ?? null; h.projected = s.month_to_date.projected_month_end ?? null; } catch { /* no spend yet */ }
  try { h.open_alerts = (db.prepare("select count(*) as n from alerts where acknowledged = 0 and datetime(created_at) > datetime('now', '-7 days')").get() as { n: number }).n; } catch { /* */ }
  try { const r = db.prepare("select count(*) as n, coalesce(sum(est_monthly_saving), 0) as saving from recommendations where status in ('open', 'pending', 'approved')").get() as { n: number; saving: number }; h.open_recs = r.n; h.open_saving = r.saving; } catch { /* */ }
  return h;
}

/**
 * The general brief: the header, the tool index, the thread and the new message. Pure given its inputs.
 * With `resumed` (the thread's session is being continued) the brief is the new message alone: repo2graph replays
 * the conversation, and the header and tool index are already in it.
 */
export function buildAccountPrompt(header: AccountHeader, tools: [string, string][], thread: Pick<Message, "role" | "author" | "content" | "status">[], message: string, threadTitle?: string | null, resumed = false): string {
  if (resumed) return ["## The new message to answer (the thread so far is in front of you; the account numbers may have moved since, fetch them if they matter)", message, "", "Answer with the JSON object described by the schema: reply (step_fixes and suggest_replan stay empty here; there is no plan)."].join("\n");
  const usd = (n: number | null) => (n == null ? "unknown" : `${Math.round(n)} USD`);
  const lines: string[] = [`# Thread with the team about the AWS account${threadTitle ? `: ${threadTitle}` : ""}`, "",
    "## The account in a few numbers (fetch anything else with the tools)",
    `- account ${header.account ?? "unknown"}; latest collection run ${header.latest_run ?? "none yet"}`,
    `- spend: last 7 complete days ${usd(header.spend_7d)}; month to date ${usd(header.month_to_date)}, projected ${usd(header.projected)}`,
    `- ${header.open_alerts} unacknowledged alert${header.open_alerts === 1 ? "" : "s"} in the last 7 days; ${header.open_recs} open/pending/approved recommendation${header.open_recs === 1 ? "" : "s"} claiming ≈ ${usd(header.open_saving)}/month`,
    "", "## What you can look up (tools arrive as aws_<name>); pull what the question needs, say what you fetched"];
  for (const [n, w] of tools) lines.push(`- ${n}: ${w}`);
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

/** The step outcomes as the brief shows them: empty when there is no plan or the progress belongs to another plan. */
export const outcomesForPlan = (plan: { resolutionId: number; plan: ResolutionPlan } | null, progress: Progress | null): string =>
  plan && progress?.plan === `resolution:${plan.resolutionId}` ? outcomesText(plan.plan.plan, progress) : "";

/** What a brief tells the session about the plan and the outcomes; stored on the thread so the next turn repeats neither. */
export const sessionStateFor = (plan: { resolutionId: number; plan: ResolutionPlan } | null, progress: Progress | null): SessionState => ({ resolutionId: plan?.resolutionId ?? null, outcomes: outcomesForPlan(plan, progress) });

/**
 * The brief for one turn: the recommendation, the plan, what happened, the thread, then the new message. Pure.
 * With `resumed` (what the thread's session was last told) the brief carries the new message, the recommendation's
 * status line, and the plan or the outcomes only when they differ from what the session already has; the rest is
 * replayed by repo2graph from the session.
 */
export function buildChatPrompt(rec: RecRow, facts: unknown, plan: { resolutionId: number; plan: ResolutionPlan } | null, progress: Progress | null, thread: Pick<Message, "role" | "author" | "content" | "status">[], message: string, resumed: SessionState | null = null): string {
  const status = `Rule ${rec.rule} (source ${rec.source}), action ${rec.action_type}, tier ${rec.tier}, estimated saving ${rec.est_monthly_saving != null ? `${Math.round(rec.est_monthly_saving)} USD/month` : "unknown"}, status ${rec.status}${rec.decision_reason ? `, decision reason: "${rec.decision_reason}"` : ""}.`;
  const planLines = (): string[] => {
    if (!plan) return ["", "## Plan", "No tailored plan has been written yet; the person is working from the rationale or the generic playbook."];
    const out = ["", `## The current tailored plan (resolution ${plan.resolutionId})`, plan.plan.summary || ""];
    plan.plan.plan.forEach((s, i) => { out.push(`${i + 1}. ${s.step}`); if (s.command) out.push("```", s.command, "```"); if (s.verify) out.push(`   verify: ${s.verify}`); });
    if (plan.plan.needs_from_human.length) out.push("Needs from a human:", ...plan.plan.needs_from_human.map((n) => `- ${n}`));
    return out;
  };
  const tried = outcomesForPlan(plan, progress);
  const answer = ["", "Answer with the JSON object described by the schema: reply, suggest_replan, step_fixes."];
  if (resumed) {
    const lines: string[] = [`# Follow-up on recommendation #${rec.id} (the thread so far is in front of you)`, status];
    const planChanged = (plan?.resolutionId ?? null) !== resumed.resolutionId;
    if (planChanged) lines.push(...planLines().map((l, i) => (i === 1 && plan ? `${l}, replacing the one you saw` : l)));
    if (planChanged || tried !== resumed.outcomes) lines.push("", `## What happened when the steps were tried${planChanged ? "" : " (changed since your last answer)"}`, tried || "- nothing recorded yet");
    lines.push("", "## The new message to answer", message, ...answer);
    return lines.join("\n");
  }
  const lines: string[] = [
    `# Thread on recommendation #${rec.id}: ${rec.title}`, status,
    `Resource: ${rec.resource ?? "unknown"}${rec.resource_name && rec.resource_name !== rec.resource ? ` (${rec.resource_name})` : ""}`,
    "", "## Rationale", rec.rationale || "(none)",
    "", "## Resource facts (advisor inventory)", "```json", JSON.stringify(facts ?? {}, null, 1).slice(0, 4000), "```",
    ...planLines(),
    "", "## What happened when the steps were tried", tried || "- nothing recorded yet",
    "", "## The conversation so far",
  ];
  const past = thread.filter((m) => m.status === "completed" && m.content).slice(-THREAD_CONTEXT);
  if (!past.length) lines.push("- this is the first message");
  for (const m of past) lines.push(`**${m.role === "agent" ? "advisor" : m.author || "engineer"}:** ${m.content.slice(0, 2500)}`, "");
  lines.push("## The new message to answer", message, ...answer);
  return lines.join("\n");
}

/**
 * Whether repo2graph still holds a session (its sessions are files on its disk; GET /api/sessions/:id answers 404
 * once one is gone). Anything but a 200 counts as gone: the thread then opens a new session with the full brief,
 * which costs tokens but never an answer given without the conversation.
 */
export async function sessionAlive(sessionId: string): Promise<boolean> {
  try {
    const res = await fetch(`${config.repo2graphUrl}/api/sessions/${encodeURIComponent(sessionId)}`, { headers: { "x-api-token": config.repo2graphToken } });
    return res.ok;
  } catch { return false; }
}

/** The session a thread's next message goes in: the existing one when it is alive and the last turn worked, else a new one. */
export async function sessionFor(thread: Thread, past: Message[]): Promise<{ sessionId: string; resumed: boolean }> {
  const last = [...past].reverse().find((m) => m.role === "agent");
  if (thread.session_id && last?.status === "completed" && (await sessionAlive(thread.session_id))) return { sessionId: thread.session_id, resumed: true };
  return { sessionId: `aws-advisor-chat-${thread.id}-${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`, resumed: false };
}

/** Records the person's message in a thread and asks the agent; the answer arrives through the webhook. */
export async function ask(threadId: number, message: string, author: string | null): Promise<{ user: Message; agent: Message }> {
  const thread = getThread(threadId);
  if (!thread) { const e: any = new Error("not found"); e.code = "not_found"; throw e; }
  const rec = thread.recommendation_id == null ? null : (db.prepare("select * from recommendations where id = ?").get(thread.recommendation_id) as RecRow | undefined) ?? null;
  const text = String(message || "").trim().slice(0, MAX_MESSAGE);
  if (!text) throw new Error("the message is empty");
  if (thread.pending) { const e: any = new Error("the agent is still answering the previous message"); e.code = "pending"; throw e; }
  if (!config.repo2graphUrl) throw new Error("REPO2GRAPH_URL is not configured: no agent can answer");
  const past = listMessages(threadId);
  // Same session as the thread's earlier turns when repo2graph still has it: it replays the conversation, so the
  // brief carries only what is new and the cached prompt prefix is reused. Decided before the rows are written so
  // a lost session is found out while there is nothing to undo.
  const session = await sessionFor(thread, past);
  const userId = Number(db.prepare("insert into recommendation_messages(recommendation_id, thread_id, role, author, content, status) values (?, ?, 'user', ?, ?, 'completed')").run(thread.recommendation_id, threadId, author, text).lastInsertRowid);
  const agentId = Number(db.prepare("insert into recommendation_messages(recommendation_id, thread_id, role, status) values (?, ?, 'agent', 'pending')").run(thread.recommendation_id, threadId).lastInsertRowid);
  // a general thread without a name takes its first message as the title
  if (!rec && !thread.title) db.prepare("update chat_threads set title = ? where id = ?").run(text.split("\n")[0].slice(0, 80), threadId);
  db.prepare("update chat_threads set updated_at = datetime('now') where id = ?").run(threadId);
  try {
    const plan = rec ? latestPlan(rec.id) : null;
    const progress = rec ? parseProgress((rec as any).progress) : null;
    const prompt = rec
      ? buildChatPrompt(rec, resourceFacts(rec), plan, progress, past, text, session.resumed ? thread.session_state ?? { resolutionId: null, outcomes: "" } : null)
      : buildAccountPrompt(accountHeader(), FACT_TOOLS, past, text, thread.title, session.resumed);
    const { requestId } = await postAgentRequest({
      prompt,
      systemOverride: getPrompt("chat"),
      sessionId: session.sessionId,
      agentName: rec ? "aws-resolution-chat" : "aws-account-chat",
      metadata: { threadId, recommendationId: thread.recommendation_id, messageId: agentId },
      link: { kind: "chat", recommendationId: thread.recommendation_id },
    });
    db.prepare("update recommendation_messages set request_id = ? where id = ?").run(requestId, agentId);
    db.prepare("update chat_threads set session_id = ?, session_state = ? where id = ?").run(session.sessionId, JSON.stringify(sessionStateFor(plan, progress)), threadId);
    if (!session.resumed && thread.session_id) console.log(`[chat] thread ${threadId}: session ${thread.session_id} not resumable, opened ${session.sessionId} with the full brief`);
  } catch (e: any) {
    db.prepare("update recommendation_messages set status = 'failed', error = ?, finished_at = datetime('now') where id = ?").run(String(e?.message || e).slice(0, 500), agentId);
    throw e;
  }
  const rows = listMessages(threadId);
  return { user: rows.find((m) => m.id === userId)!, agent: rows.find((m) => m.id === agentId)! };
}

/** The recommendation routes: its thread is made on the first message. */
export async function askAboutRecommendation(recId: number, message: string, author: string | null) {
  const t = threadForRecommendation(recId, true);
  if (!t) { const e: any = new Error("not found"); e.code = "not_found"; throw e; }
  return ask(t.id, message, author);
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
  console.log(`[chat] ${run.recommendation_id ? `recommendation ${run.recommendation_id}` : "general thread"}: reply of ${reply.length} chars${extra?.step_fixes?.length ? `, ${extra.step_fixes.length} step fix(es)` : ""}${extra?.suggest_replan ? ", suggests a re-plan" : ""}`);
}

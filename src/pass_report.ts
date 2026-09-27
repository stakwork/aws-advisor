/**
 * The narrated pass: after an executor pass (src/executor.ts runExecutorPass) the agent gets the complete record
 * of what the pass did, every module's notes and the errors, and writes the short version for the team chat and
 * the Auto-actions page: what happened, what comes at the next pass, what waits on a person, what was left alone
 * and why, and anything that looks wrong. Same shape as the morning observation (src/observe.ts): a fixed brief, a
 * task with a schema and a rubric (tasks/pass_report/), the answer through the webhook, graded, stored.
 *
 * The agent is asked once per distinct outcome: the pass is digested (the rows it touched with their status and
 * check verdict, the errors, the module notes with their numbers stripped) and a pass whose digest equals the last
 * narrated one is not sent (ACT_NARRATE=changes, the default). `always` narrates every pass anyway; `off` never.
 */
import { createHash } from "node:crypto";
import { config } from "./config.js";
import { db } from "./db.js";
import { credentialGate } from "./gate.js";
import { getPrompt } from "./prompts.js";
import { gradeByRubric, belowBar, type Grade } from "./rubric.js";
import { taskFor } from "./tasks.js";
import { postAgentRequest, type AgentRunRow } from "./agent.js";
import { configured as notifyConfigured, inQuietHours, sendSphinx } from "./notify.js";
import { getAction, graceLeftMs, pauseState, actionModules, type ActionRow, type PassResult } from "./executor.js";

db.exec(`create table if not exists pass_reports (
  id integer primary key autoincrement,
  pass_at text not null, trigger text not null, mode text not null,
  digest text not null, brief text not null,
  request_id text, status text not null default 'pending',
  result text, error text, score real, grade text,
  sphinx_sent_at text, sphinx_result text,
  created_at text not null default (datetime('now')), finished_at text
);
create index if not exists pass_reports_status on pass_reports(status, id)`);

export const SPHINX_MAX_CHARS = 900;
/** Past-tense claims a narration may only make when the pass actually applied something. */
const APPLIED_CLAIMS = /\b(deleted|released|terminated|stopped|archived|trimmed|switched|scheduled for deletion)\b/i;

export interface PassReportRow {
  id: number; pass_at: string; trigger: string; mode: string; digest: string; brief: string; request_id: string | null; status: string;
  result: any; error: string | null; score: number | null; grade: Grade | null; sphinx_sent_at: string | null; sphinx_result: string | null; created_at: string; finished_at: string | null;
  held_back: string[] | null;
}

const safe = (s: string | null) => { if (!s) return null; try { return JSON.parse(s); } catch { return s; } };
const rowOf = (r: any): PassReportRow => { const grade = safe(r.grade); return { ...r, result: safe(r.result), grade, held_back: belowBar(grade, taskFor("pass_report").retry.on_score_below) }; };

/** The rows a pass touched: proposed or refreshed (seen_at), applied (applied_at) or closed (stale) since it started, plus every open proposal for context. */
export function rowsOfPass(passAt: string): ActionRow[] {
  const ids = db.prepare(`select id from actions where datetime(seen_at) >= datetime(?) or datetime(applied_at) >= datetime(?) or datetime(verified_at) >= datetime(?) or status = 'proposed' order by id`).all(passAt, passAt, passAt) as { id: number }[];
  return ids.map((r) => getAction(r.id)).filter((r): r is ActionRow => Boolean(r));
}

const stripNumbers = (s: string) => s.replace(/[\d.,]+/g, "#");

/** The identity of a pass's outcome: which rows, in which state, with which check verdict; the errors; the notes without their numbers. Pure. */
export function passDigest(result: Pick<PassResult, "mode" | "notes" | "errors">, rows: Pick<ActionRow, "id" | "status" | "facts">[]): string {
  const rowKeys = rows.map((r) => `${r.id}:${r.status}:${String((r as any).check?.verdict ?? r.facts?.jev?.verdict ?? "")}`).sort();
  const notes = [...new Set(result.notes.map(stripNumbers))].sort();
  const errors = [...new Set(result.errors.map(stripNumbers))].sort();
  return createHash("sha1").update(JSON.stringify({ mode: result.mode, rowKeys, notes, errors })).digest("hex").slice(0, 20);
}

const usd = (v: number | null | undefined) => (v == null ? "" : ` ≈ ${v.toFixed(2)} USD/month`);
const hours = (ms: number) => `${Math.ceil(ms / 3600000)} h`;

/** The brief: the whole pass as text. Exported for the page and the tests. */
export function buildPassBrief(result: PassResult, rows: ActionRow[], opts: { passAt?: string; trigger?: string; previous?: PassReportRow | null } = {}): string {
  const now = opts.passAt ?? new Date().toISOString();
  const grace = new Map(actionModules().map((m) => [m.kind, m.grace_hours?.() ?? 0]));
  const paused = pauseState();
  const lines: string[] = [
    `# Executor pass at ${now.slice(0, 16).replace("T", " ")} UTC (${opts.trigger ?? "schedule"}, mode ${result.mode})`,
    "",
    `Mode ${result.mode}: ${result.mode === "dry_run" ? "every proposal is recorded and nothing is changed; a person can still press Apply on a row." : result.mode === "apply" ? `proposals are applied up to ${config.actMaxPerPass} per pass once their grace period, if any, has passed.` : "nothing runs."}`,
    `Counts: ${result.proposed} proposed (${result.fresh} new this pass), ${result.applied} applied, ${result.verified} verified, ${result.failed} failed, ${result.refused} refused, ${result.stale} closed as stale, in ${result.took_ms} ms.`,
    paused.paused ? `PAUSED by ${paused.by ?? "?"} since ${paused.at ?? "?"}: ${paused.reason ?? ""}. Nothing is planned or applied while paused; Revert still works.` : "Not paused.",
    `The next pass runs on the cron "${config.actCron}" (hourly at :45 by default).`,
  ];
  const touched = rows.filter((r) => r.status !== "proposed" || true);
  lines.push("", `## Ledger rows this pass (${touched.length})`);
  if (!touched.length) lines.push("- none: every module left things alone (see the notes)");
  for (const r of touched) {
    const g = grace.get(r.kind) ?? 0;
    const left = r.status === "proposed" && g ? graceLeftMs(r, g) : 0;
    const check = (r as any).check ?? r.facts?.jev ?? null;
    const bits = [
      `#${r.id} [${r.status}] ${r.kind}: ${r.title}${usd(r.est_usd_month)}`,
      r.account_id ? `account ${r.account_id}` : "",
      r.status === "proposed" ? (left > 0 ? `grace: waits ${hours(left)} more before the pass may apply it` : g ? "grace period over" : "") : "",
      check ? `Jev check: ${check.verdict ?? "?"}${check.reason ? ` (${String(check.reason).slice(0, 160)})` : ""}` : "",
      r.facts?.recommendation_id ? `carries approved recommendation #${r.facts.recommendation_id}` : "",
      r.error ? `error: ${String(r.error).slice(0, 200)}` : "",
      r.result ? `result: ${String(r.result).slice(0, 160)}` : "",
    ].filter(Boolean);
    lines.push(`- ${bits.join("; ")}`);
    lines.push(`  why: ${String(r.reason).slice(0, 400)}`);
  }
  const byModule = new Map<string, string[]>();
  for (const n of result.notes) { const [k, ...rest] = n.split(": "); const key = rest.length ? k : "pass"; if (!byModule.has(key)) byModule.set(key, []); byModule.get(key)!.push(rest.length ? rest.join(": ") : n); }
  lines.push("", `## What each module looked at and why it left things alone (${result.notes.length} notes)`);
  if (!result.notes.length) lines.push("- no notes");
  for (const [k, notes] of byModule) {
    lines.push(`### ${k} (${notes.length})`);
    for (const n of notes.slice(0, 25)) lines.push(`- ${n.slice(0, 300)}`);
    if (notes.length > 25) lines.push(`- … ${notes.length - 25} more of the same kind`);
  }
  lines.push("", `## Errors (${result.errors.length})`);
  for (const e of result.errors) lines.push(`- ${e.slice(0, 300)}`);
  if (!result.errors.length) lines.push("- none");
  if (opts.previous?.result?.summary) lines.push("", `## The previous narrated pass (${opts.previous.pass_at.slice(0, 16).replace("T", " ")} UTC) said`, String(opts.previous.result.summary).slice(0, 800), "Say what changed since then; do not repeat what has not.");
  lines.push("", "## Answer", "The JSON object of the schema: summary, next, waiting, left_alone, concerns, sphinx.");
  return lines.join("\n");
}

/** The checks beyond the task's rubric: row ids that exist, no past-tense claim a dry run cannot make, the Sphinx length, numbers when there were proposals. Pure. */
export function gradePassReport(result: any, facts: { row_ids: number[]; applied: number; proposed: number }): Grade {
  const base = gradeByRubric(result, taskFor("pass_report").rubric);
  if (!result || typeof result !== "object") return base;
  const text = JSON.stringify(result);
  const mentioned = [...new Set([...text.matchAll(/#(\d+)/g)].map((m) => Number(m[1])))];
  const unknown = mentioned.filter((id) => !facts.row_ids.includes(id));
  const checks = [...base.checks];
  checks.push({ check: "row ids exist", pass: unknown.length === 0, detail: unknown.length ? `unknown rows #${unknown.join(", #")}` : `${mentioned.length} cited` });
  const sphinx = String(result.sphinx ?? "");
  checks.push({ check: "sphinx under 900 characters", pass: sphinx.length <= SPHINX_MAX_CHARS, detail: `${sphinx.length} chars` });
  const claims = facts.applied === 0 && APPLIED_CLAIMS.test(`${result.summary ?? ""} ${sphinx}`);
  checks.push({ check: "no applied claim when nothing was applied", pass: !claims, detail: claims ? "past-tense change claimed in a pass that applied nothing" : "ok" });
  const numeric = facts.proposed === 0 || /\d/.test(`${result.summary ?? ""} ${sphinx}`);
  checks.push({ check: "numbers present when the pass had proposals", pass: numeric, detail: numeric ? "ok" : "no number in summary or sphinx" });
  const score = checks.length ? checks.filter((c) => c.pass).length / checks.length : 1;
  return { score: Math.round(score * 100) / 100, checks };
}

export function latestPassReport(): PassReportRow | null {
  const r = db.prepare("select * from pass_reports order by id desc limit 1").get();
  return r ? rowOf(r) : null;
}
export function listPassReports(limit = 20): PassReportRow[] {
  return (db.prepare("select * from pass_reports order by id desc limit ?").all(Math.min(200, Math.max(1, limit))) as any[]).map(rowOf);
}
export function getPassReport(id: number): PassReportRow | null {
  const r = db.prepare("select * from pass_reports where id = ?").get(id);
  return r ? rowOf(r) : null;
}

/**
 * Sends a finished pass to the agent when the mode allows it and the outcome is new. Returns why it did not when
 * it did not. Never throws for a skipped narration; a failed dispatch is recorded on the report row and rethrown.
 */
export async function narratePass(result: PassResult, trigger: string, opts: { force?: boolean } = {}): Promise<{ id: number; requestId: string } | { skipped: string }> {
  const mode = config.actNarrate;
  if (mode === "off" && !opts.force) return { skipped: "ACT_NARRATE is off" };
  if (result.mode === "off") return { skipped: "executor mode off" };
  if (!config.repo2graphUrl) return { skipped: "REPO2GRAPH_URL is not configured" };
  const passAt = new Date(Date.now() - (result.took_ms || 0)).toISOString();
  const rows = rowsOfPass(passAt);
  const digest = passDigest(result, rows);
  const previous = latestPassReport();
  const lastNarrated = db.prepare("select digest from pass_reports where status in ('pending', 'completed') order by id desc limit 1").get() as { digest: string } | undefined;
  if (!opts.force && mode !== "always" && lastNarrated?.digest === digest) return { skipped: `same outcome as the last narrated pass (${digest}); not sent to the agent` };
  if (previous?.status === "pending" && !opts.force) return { skipped: `report #${previous.id} is still being written` };
  const gate = await credentialGate("pass-report");
  if (!gate.ok) return { skipped: gate.error || "credentials not working" };
  const brief = buildPassBrief(result, rows, { passAt, trigger, previous: previous?.status === "completed" ? previous : null });
  const id = Number(db.prepare("insert into pass_reports(pass_at, trigger, mode, digest, brief) values (?, ?, ?, ?, ?)").run(passAt, trigger, result.mode, digest, brief).lastInsertRowid);
  try {
    const { requestId } = await postAgentRequest({
      prompt: brief,
      systemOverride: getPrompt("pass_report"),
      sessionId: `aws-advisor-pass-${id}-${Date.now().toString(36)}`,
      agentName: "aws-pass-narrator",
      metadata: { reportId: id, trigger },
      link: { kind: "pass_report", reportId: id },
    });
    db.prepare("update pass_reports set request_id = ? where id = ?").run(requestId, id);
    console.log(`[pass-report] #${id} sent to the agent (${requestId}); ${rows.length} row(s), ${result.notes.length} note(s)`);
    return { id, requestId };
  } catch (e: any) {
    db.prepare("update pass_reports set status = 'failed', error = ?, finished_at = datetime('now') where id = ?").run(String(e?.message || e).slice(0, 500), id);
    throw e;
  }
}

/** Completes a report from the agent's terminal payload (handleAgentResult, kind pass_report); posts to Sphinx when the grade allows and the hour is not quiet. */
export function completePassReport(run: AgentRunRow, payload: { status: string; result?: any; error?: any }): void {
  const row = db.prepare("select id, pass_at from pass_reports where request_id = ? order by id desc limit 1").get(run.request_id) as { id: number; pass_at: string } | undefined;
  if (!row) { console.error(`[pass-report] no report for agent request ${run.request_id}`); return; }
  if (payload.status !== "completed") {
    db.prepare("update pass_reports set status = 'failed', error = ?, finished_at = datetime('now') where id = ?").run(JSON.stringify(payload.error ?? payload).slice(0, 2000), row.id);
    return;
  }
  const c = payload.result?.content ?? payload.result;
  const content = typeof c === "string" ? safe(c) : c;
  const rows = rowsOfPass(row.pass_at);
  const counts = db.prepare("select sum(status in ('applied', 'verified') and datetime(applied_at) >= datetime(?)) as applied, count(*) as proposed from actions where datetime(seen_at) >= datetime(?)").get(row.pass_at, row.pass_at) as { applied: number | null; proposed: number };
  const grade = gradePassReport(content, { row_ids: rows.map((r) => r.id), applied: counts.applied ?? 0, proposed: counts.proposed });
  db.prepare("update pass_reports set status = 'completed', result = ?, error = null, score = ?, grade = ?, finished_at = datetime('now') where id = ?").run(JSON.stringify(content), grade.score, JSON.stringify(grade), row.id);
  const held = belowBar(grade, taskFor("pass_report").retry.on_score_below);
  console.log(`[pass-report] #${row.id}: score ${grade.score.toFixed(2)} (${grade.checks.filter((x) => x.pass).length}/${grade.checks.length})${held ? `; held back from Sphinx: ${held.join(", ")}` : ""}`);
  if (held) { db.prepare("update pass_reports set sphinx_result = ? where id = ?").run(`held back: ${held.join(", ")}`, row.id); return; }
  dispatchPassReports().catch((e: any) => console.error(`[pass-report] sphinx: ${e?.message || e}`));
}

/** Posts every completed report whose message has not gone out, unless the hour is quiet (then it waits for the next call). */
export async function dispatchPassReports(): Promise<{ sent: number; skipped: number; failed: number; waiting: number }> {
  const out = { sent: 0, skipped: 0, failed: 0, waiting: 0 };
  const rows = db.prepare("select id, result from pass_reports where status = 'completed' and sphinx_sent_at is null and (sphinx_result is null or sphinx_result not like 'held back%') and (sphinx_result is null or sphinx_result not like 'skipped%') order by id").all() as { id: number; result: string }[];
  if (!rows.length) return out;
  const mark = (id: number, r: string, sent: boolean) => db.prepare(`update pass_reports set sphinx_result = ?${sent ? ", sphinx_sent_at = datetime('now')" : ""} where id = ?`).run(r, id);
  if (!notifyConfigured()) { for (const r of rows) { mark(r.id, "skipped: Sphinx bot not configured", false); out.skipped++; } return out; }
  if (config.notifyLevel === "off") { for (const r of rows) { mark(r.id, "skipped: notifications off", false); out.skipped++; } return out; }
  if (inQuietHours(config.notifyQuietHours, new Date().getHours())) { out.waiting = rows.length; return out; }
  // Only the newest report is worth posting after a quiet night; the older ones are superseded.
  const newest = rows[rows.length - 1];
  for (const r of rows) {
    if (r.id !== newest.id) { mark(r.id, "skipped: superseded by a newer report", false); out.skipped++; continue; }
    const content = safe(r.result);
    const text = String(content?.sphinx ?? "").trim();
    if (!text) { mark(r.id, "skipped: no sphinx text in the answer", false); out.skipped++; continue; }
    try {
      const res = await sendSphinx(`🗒️ Auto-actions pass\n${text.slice(0, SPHINX_MAX_CHARS)}\n${config.notifyLinkUrl}/actions`);
      if (res.ok) { mark(r.id, "sent", true); out.sent++; } else { mark(r.id, `failed: ${res.status} ${res.body.slice(0, 120)}`, false); out.failed++; }
    } catch (e: any) { mark(r.id, `failed: ${e?.message || e}`.slice(0, 200), false); out.failed++; }
  }
  return out;
}

/** Re-posts one report's message (the page's Resend), whatever its earlier result. */
export async function resendPassReport(id: number): Promise<string> {
  const r = getPassReport(id);
  if (!r) throw new Error(`no pass report #${id}`);
  if (r.status !== "completed" || !r.result?.sphinx) throw new Error(`report #${id} has no message to send (${r.status})`);
  if (!notifyConfigured()) throw new Error("Sphinx bot not configured");
  const res = await sendSphinx(`🗒️ Auto-actions pass\n${String(r.result.sphinx).slice(0, SPHINX_MAX_CHARS)}\n${config.notifyLinkUrl}/actions`);
  const result = res.ok ? "sent" : `failed: ${res.status} ${res.body.slice(0, 120)}`;
  db.prepare(`update pass_reports set sphinx_result = ?${res.ok ? ", sphinx_sent_at = datetime('now')" : ""} where id = ?`).run(result, id);
  return result;
}

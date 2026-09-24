import { Router } from "express";
import { authMiddleware } from "../auth.js";
import { config } from "../config.js";
import { db } from "../db.js";
import { hasConnectionFile } from "../steampipe.js";
import { listAlerts } from "../investigate.js";
import { postRejectionLearning } from "../learnings.js";
import { ConceptScope, suggestDecisionScope, syncDecisionConceptInBackground } from "../concepts.js";
import { SPEND_DAYS, SPEND_MIN_INTERVAL_MS, lastSpendFetch, refreshSpend, spendRows, spendSummary } from "../spend.js";
import { dedupeFindings, levelCounts, mergeRecommendations, orderAlerts, pageParams, paginate, parseRecQuery, recMatches } from "../paging.js";
import { statusAfterProgress, validateProgress } from "../progress.js";
import { noteDecision } from "../notify.js";
import { askAboutRecommendation, listMessages } from "../chat.js";
import { Conflict, blockerLinks, blockersFor, distinctSaving, findConflicts, liveRows, makesCycle, systemMap } from "../related.js";
import { listPlaybooks, playbookFor, playbookSummary } from "../playbooks.js";
import { resolutionFor, resolveRecommendation } from "../resolve.js";
import { mirrorRecommendationsInBackground } from "../graph_mirror.js";

/**
 * Browsing routes: spend, and the paginated, deduplicated views of alerts, findings and recommendations.
 * Mounted on /api before src/routes/api.ts, so the paths here take precedence over the older unpaginated ones.
 * The auth guard is per route (not `browse.use`) so unmatched paths, /api/agent-callback in particular, fall
 * through untouched.
 */
export const browse = Router();
const auth = authMiddleware;

const str = (v: unknown) => (typeof v === "string" && v ? v : undefined);
const DAY_RE = /^\d{4}-\d{2}-\d{2}$/;

// ---- spend ------------------------------------------------------------------------------------------------
// Summary (today, last 7 days, month to date with projection, previous month) plus the daily series of the last 45 days.
browse.get("/spend", auth, (req, res) => {
  const metric = str(req.query.metric);
  const summary = spendSummary(undefined, metric === "unblended" || metric === "amortized" || metric === "usage_only" ? metric : "net_unblended");
  res.json({ ...summary, series: spendRows(SPEND_DAYS), last_fetch: lastSpendFetch(), min_interval_hours: SPEND_MIN_INTERVAL_MS / 3600_000, days: SPEND_DAYS });
});

// One Cost Explorer call. Skipped while the last fetch is younger than 6 hours unless ?force=1 (or body.force).
browse.post("/spend/refresh", auth, async (req, res) => {
  if (!hasConnectionFile()) return res.status(400).json({ error: "AWS credentials are not configured" });
  const force = req.query.force === "1" || req.query.force === "true" || req.body?.force === true;
  try {
    const r = await refreshSpend({ force });
    res.status(r.error ? 502 : 200).json({ ...r, summary: spendSummary() });
  } catch (e: any) {
    res.status(502).json({ error: e.message });
  }
});

// ---- alerts -----------------------------------------------------------------------------------------------
// ?status=open (default) | acknowledged | all, ?page (1-based), ?page_size (default 10, max 50), ?day=YYYY-MM-DD (local server date).
// Today's alerts first, then older days; within a day alarms, warnings, info; newest first. Same columns as before (incident_*, triage).
browse.get("/alerts", auth, (req, res) => {
  const status = req.query.status === "acknowledged" ? "acknowledged" : req.query.status === "all" || req.query.all === "1" || req.query.all === "true" ? "all" : "open";
  const day = str(req.query.day);
  if (day && !DAY_RE.test(day)) return res.status(400).json({ error: "day must be YYYY-MM-DD" });
  const ordered = orderAlerts(listAlerts(status, 100_000));
  const rows = day ? ordered.filter((a) => a.day === day) : ordered;
  const p = paginate(rows, pageParams(req.query as Record<string, unknown>, { size: 10, max: 50 }));
  res.json({ total: p.total, page: p.page, page_size: p.page_size, status, day: day ?? null, counts: levelCounts(rows), alerts: p.items });
});

// ---- findings ---------------------------------------------------------------------------------------------
// ?run_id (default: last completed run), ?control_id, ?status, ?q, ?page, ?page_size (default 50, max 200).
// One row per fingerprint and per (control, resource) within the run; the first by id is kept.
browse.get("/findings", auth, (req, res) => {
  const runId = req.query.run_id ? Number(req.query.run_id) : (db.prepare("select id from runs where status = 'completed' order by id desc limit 1").get() as { id: number } | undefined)?.id;
  const p = pageParams(req.query as Record<string, unknown>, { size: 50, max: 200 });
  if (!runId) return res.json({ total: 0, page: p.page, page_size: p.page_size, run_id: null, controls: [], findings: [] });
  const where: string[] = ["run_id = ?"]; const params: unknown[] = [runId];
  if (req.query.control_id) { where.push("control_id = ?"); params.push(req.query.control_id); }
  if (req.query.status) { where.push("status = ?"); params.push(req.query.status); }
  if (req.query.q) { where.push("(resource like ? or reason like ?)"); params.push(`%${req.query.q}%`, `%${req.query.q}%`); }
  const rows = dedupeFindings(db.prepare(`select id, source, benchmark, control_id, control_title, status, resource, reason, account_id, region, dimensions, fingerprint from findings where ${where.join(" and ")} order by id`).all(...params) as any[])
    .sort((a, b) => String(a.control_id).localeCompare(String(b.control_id)) || String(a.resource ?? "").localeCompare(String(b.resource ?? "")) || a.id - b.id);
  // Control counts over the whole run, deduplicated the same way, so the dropdown numbers match the list.
  const all = dedupeFindings(db.prepare("select id, control_id, control_title, status, resource, fingerprint from findings where run_id = ? order by id").all(runId) as any[]);
  const byControl = new Map<string, { control_id: string; control_title: string | null; status: string; n: number }>();
  for (const f of all) {
    const k = `${f.control_id}|${f.status}`;
    const c = byControl.get(k);
    if (c) c.n++; else byControl.set(k, { control_id: f.control_id, control_title: f.control_title, status: f.status, n: 1 });
  }
  // Each control carries its playbook's title, tier and effort (src/playbooks.ts) so the UI can offer "How to act".
  const controls = [...byControl.values()].sort((a, b) => b.n - a.n).map((c) => { const pb = playbookFor(c.control_id); return { ...c, playbook: pb ? playbookSummary(pb) : null }; });
  const page = paginate(rows, p);
  res.json({ total: page.total, page: page.page, page_size: page.page_size, run_id: runId, controls, findings: page.items });
});

// ---- playbooks --------------------------------------------------------------------------------------------
// Every playbook, with how many alarms of the run (?run_id, default the last completed one) each control raised.
browse.get("/playbooks", auth, (req, res) => {
  const runId = req.query.run_id ? Number(req.query.run_id) : (db.prepare("select id from runs where status = 'completed' order by id desc limit 1").get() as { id: number } | undefined)?.id;
  const counts = new Map<string, number>();
  if (runId) {
    const all = dedupeFindings(db.prepare("select id, control_id, status, resource, fingerprint from findings where run_id = ? and status = 'alarm' order by id").all(runId) as any[]);
    for (const f of all) counts.set(f.control_id, (counts.get(f.control_id) || 0) + 1);
  }
  const playbooks = listPlaybooks().map((p) => ({ ...p, findings: counts.get(p.control_id) || 0 })).sort((a, b) => b.findings - a.findings || a.title.localeCompare(b.title));
  res.json({ run_id: runId ?? null, count: playbooks.length, playbooks });
});

browse.get("/playbooks/:controlId", auth, (req, res) => {
  const controlId = String(req.params.controlId);
  const pb = playbookFor(controlId);
  if (!pb) return res.status(404).json({ error: `no playbook for ${controlId}` });
  res.json(pb);
});

// ---- recommendations ------------------------------------------------------------------------------------------
/** The conflicts of a merged entry: those of any member, once each, never a member of the entry itself. */
function conflictsOf(memberIds: number[], conflicts: Map<number, Conflict[]>): Conflict[] {
  const out: Conflict[] = [];
  for (const id of memberIds) for (const c of conflicts.get(id) || []) if (!memberIds.includes(c.id) && !out.some((x) => x.id === c.id)) out.push(c);
  return out;
}

// ?status=open (default) | pending | approved | ... | all, ?q (title, resource, resource name, or "#123" for an id),
// ?page, ?page_size (default 50, max 200). An id query looks across every status, so "#123" always finds the row
// whatever list is showing; the row carries its own status for the UI to flag. Rows proposing the same action on
// the same resource are one entry: the highest estimate is primary, the rest under `merged`.
browse.get("/recommendations", auth, (req, res) => {
  const status = str(req.query.status) || "open";
  const q = parseRecQuery(str(req.query.q) || "");
  const rows = (status === "all" || q.id != null
    ? db.prepare("select * from recommendations order by coalesce(est_monthly_saving, -1) desc, updated_at desc").all()
    : db.prepare("select * from recommendations where status = ? order by coalesce(est_monthly_saving, -1) desc, updated_at desc").all(status)) as any[];
  const shown = q.text ? rows.filter((r) => recMatches(r, q) && (status === "all" || r.status === status || r.id === q.id)) : rows;
  // Members of a pool, an RDS cluster or a cache group are one entry per (system, action): the decision is about the system.
  const systems = systemMap();
  const merged = mergeRecommendations(shown, (rid) => systems.get(rid));
  // Conflicts are found among every live row, not just this page or status: an approved stop conflicts with an open Graviton move.
  const conflicts = findConflicts(liveRows());
  const blockers = blockersFor(merged.map((r) => r.blocked_by));
  const p = paginate(merged, pageParams(req.query as Record<string, unknown>, { size: 50, max: 200 }));
  const saving = distinctSaving(merged);
  res.json({ total: p.total, page: p.page, page_size: p.page_size, status, total_saving: saving.total, total_saving_distinct: saving.distinct, overlap_usd: saving.overlap,
    recommendations: p.items.map((r) => ({ ...r, conflicts: conflictsOf(r.merged_ids, conflicts), blocker: r.blocked_by ? blockers.get(r.blocked_by) ?? null : null })) });
});

// Jev's view of whether a reason is reusable knowledge ("generic") or about this one resource ("internal").
// ?reason= is the text being typed in the UI (not stored yet); without it the stored decision reason is used.
browse.get("/recommendations/:id/scope-suggestion", auth, async (req, res) => {
  const row = db.prepare("select title, resource, action_type, decision_reason, rationale from recommendations where id = ?").get(req.params.id) as any;
  if (!row) return res.status(404).json({ error: "not found" });
  const reason = str(req.query.reason);
  try { res.json({ suggestion: await suggestDecisionScope({ ...row, decision_reason: reason || row.decision_reason || null }) }); }
  catch (e: any) { res.status(502).json({ error: e.message }); }
});

// ---- tailored resolutions (src/resolve.ts) --------------------------------------------------------------------
// 202 with the resolution id when the gate passed and the agent was dispatched (or the gate closed it as not
// applicable, reported in `status`); 409 while an earlier resolution is pending unless ?force=1.
browse.post("/recommendations/:id/resolve", auth, async (req, res) => {
  const force = req.query.force === "1" || req.body?.force === true;
  try {
    const r = await resolveRecommendation(Number(req.params.id), { force });
    res.status(202).json({ ...r, resolution: resolutionFor(Number(req.params.id)) });
  } catch (e: any) {
    const status = e.code === "pending" ? 409 : e.code === "not_found" ? 404 : 502;
    res.status(status).json({ error: e.message, resolution: resolutionFor(Number(req.params.id)) });
  }
});

browse.get("/recommendations/:id/resolution", auth, (req, res) => {
  const r = resolutionFor(Number(req.params.id));
  if (!r) return res.status(404).json({ error: "no resolution yet" });
  res.json(r);
});

// "pending" is work in progress: someone started the steps and is waiting on something (a week of flow logs, a
// change window) before the rest; the step checklist below keeps where they got to.
const DECISIONS = ["approved", "rejected", "snoozed", "pending", "open", "done"];
const parseScope = (v: unknown): ConceptScope | null => (v === undefined || v === null || v === "" || v === "internal" ? "internal" : v === "generic" ? "generic" : null);

/**
 * The same steps as the older POST /recommendations/:id/decision in api.ts, plus the decision scope:
 * "internal" (about this one resource or account, the default) or "generic" (reusable knowledge, mirrored as a
 * role-based concept, see src/concepts.ts). Returns the row or null when unknown.
 */
function decide(id: number, status: string, reason: string | undefined, by: string, scope: ConceptScope): any | null {
  const r = db.prepare("update recommendations set status = ?, decided_at = datetime('now'), decided_by = ?, decision_reason = ?, decision_scope = ?, updated_at = datetime('now') where id = ?")
    .run(status, by, reason || null, scope, id);
  if (!r.changes) return null;
  const rec = db.prepare("select * from recommendations where id = ?").get(id) as any;
  // A rejection with a reason becomes a repo2graph learning; fire-and-forget so the UI never waits on it.
  if (status === "rejected" && config.repo2graphUrl) postRejectionLearning({ id: rec.id, fingerprint: rec.fingerprint, title: rec.title, rule: rec.rule, resource: rec.resource, decision_reason: String(reason) });
  // Every decision is mirrored into repo2graph's Concept graph (see src/concepts.ts); also fire-and-forget.
  syncDecisionConceptInBackground(id);
  // Approvals, rejections and done land in the Sphinx chat (src/notify.ts); queued here, posted in the background.
  noteDecision(id, status, by);
  return rec;
}

function validateDecision(body: any): { error: string } | { status: string; reason: string | undefined; who: string; scope: ConceptScope } {
  const { status, reason, by, scope } = body || {};
  if (!DECISIONS.includes(status)) return { error: "bad status" };
  if (status === "rejected" && !reason) return { error: "a reason is required to reject; it feeds the agent's memory" };
  const parsed = parseScope(scope);
  if (!parsed) return { error: 'scope must be "internal" or "generic"' };
  return { status, reason: typeof reason === "string" && reason ? reason : undefined, who: typeof by === "string" && by ? by : "ui", scope: parsed };
}

// Body: { status, reason?, by?, scope?: "internal" | "generic" (default internal) }. Supersedes the route in api.ts.
browse.post("/recommendations/:id/decision", auth, (req, res) => {
  const v = validateDecision(req.body);
  if ("error" in v) return res.status(400).json({ error: v.error });
  const rec = decide(Number(req.params.id), v.status, v.reason, v.who, v.scope);
  if (!rec) return res.status(404).json({ error: "not found" });
  // The decision also lands in the Neo4j mirror (status, decided_by, scope); fire-and-forget like the concept sync.
  mirrorRecommendationsInBackground([rec.id]);
  res.json(rec);
});

// Body: { plan: "resolution:<id>" | "playbook:<control id>", total, done: number[], follow_up?: "YYYY-MM-DD" }.
// The whole checklist every time. Ticking the first step of an open or snoozed item moves it to "pending".
browse.post("/recommendations/:id/progress", auth, (req, res) => {
  const v = validateProgress(req.body);
  if ("error" in v) return res.status(400).json({ error: v.error });
  const id = Number(req.params.id);
  const row = db.prepare("select id, status from recommendations where id = ?").get(id) as { id: number; status: string } | undefined;
  if (!row) return res.status(404).json({ error: "not found" });
  const next = statusAfterProgress(row.status, v.progress);
  if (next) db.prepare("update recommendations set status = ?, decided_at = datetime('now'), decided_by = ?, progress = ?, updated_at = datetime('now') where id = ?")
    .run(next, typeof req.body?.by === "string" && req.body.by ? req.body.by : "ui", JSON.stringify(v.progress), id);
  else db.prepare("update recommendations set progress = ?, updated_at = datetime('now') where id = ?").run(JSON.stringify(v.progress), id);
  const rec = db.prepare("select * from recommendations where id = ?").get(id) as any;
  if (next) { syncDecisionConceptInBackground(id); mirrorRecommendationsInBackground([id]); }
  res.json(rec);
});

// A new tailored plan written from what happened to the current one: the step outcomes and an optional note go
// back to the agent (src/resolve.ts buildFeedbackSection). Body: { note?: string }. Same answer shape as /resolve.
browse.post("/recommendations/:id/replan", auth, async (req, res) => {
  const note = typeof req.body?.note === "string" ? req.body.note.slice(0, 4000) : null;
  try {
    const r = await resolveRecommendation(Number(req.params.id), { replan: { note } });
    res.status(r.status === "pending" ? 202 : 200).json({ ...r, resolution: resolutionFor(Number(req.params.id)) });
  } catch (e: any) { res.status(e.code === "not_found" ? 404 : e.code === "pending" ? 409 : 500).json({ error: e.message }); }
});

// The thread on a recommendation (src/chat.ts): every message, oldest first.
browse.get("/recommendations/:id/messages", auth, (req, res) => res.json(listMessages(Number(req.params.id))));
// Body: { message, by? }. Records the message and asks the agent; the answer lands through the webhook (202 while pending).
browse.post("/recommendations/:id/messages", auth, async (req, res) => {
  try {
    const r = await askAboutRecommendation(Number(req.params.id), String(req.body?.message ?? ""), typeof req.body?.by === "string" && req.body.by ? req.body.by : "ui");
    res.status(202).json(r);
  } catch (e: any) { res.status(e.code === "not_found" ? 404 : e.code === "pending" ? 409 : /empty/.test(e.message) ? 400 : 500).json({ error: e.message }); }
});

// The account-wide thread (src/chat.ts, recommendation_id null): the team and the agent about the account as a whole.
browse.get("/chat/messages", auth, (_req, res) => res.json(listMessages(null)));
browse.post("/chat/messages", auth, async (req, res) => {
  try {
    const r = await askAboutRecommendation(null, String(req.body?.message ?? ""), typeof req.body?.by === "string" && req.body.by ? req.body.by : "ui");
    res.status(202).json(r);
  } catch (e: any) { res.status(e.code === "pending" ? 409 : /empty/.test(e.message) ? 400 : 500).json({ error: e.message }); }
});

// Body: { id: number | null }: what this item waits on (another recommendation), or nothing. Refuses self and loops.
browse.post("/recommendations/:id/blocked-by", auth, (req, res) => {
  const id = Number(req.params.id);
  const raw = req.body?.id;
  const blocker = raw === null || raw === undefined || raw === "" ? null : Number(raw);
  if (blocker !== null && (!Number.isInteger(blocker) || blocker <= 0)) return res.status(400).json({ error: "id must be a recommendation id or null" });
  const row = db.prepare("select id from recommendations where id = ?").get(id);
  if (!row) return res.status(404).json({ error: "not found" });
  if (blocker !== null) {
    if (blocker === id) return res.status(400).json({ error: "an item cannot block itself" });
    if (!db.prepare("select id from recommendations where id = ?").get(blocker)) return res.status(404).json({ error: `no recommendation #${blocker}` });
    const blockedByOf = (x: number) => (db.prepare("select blocked_by from recommendations where id = ?").get(x) as { blocked_by: number | null } | undefined)?.blocked_by ?? null;
    if (makesCycle(id, blocker, blockedByOf)) return res.status(400).json({ error: `#${blocker} already waits on #${id} (directly or through others)` });
  }
  db.prepare("update recommendations set blocked_by = ?, updated_at = datetime('now') where id = ?").run(blocker, id);
  const rec = db.prepare("select * from recommendations where id = ?").get(id) as any;
  res.json({ ...rec, ...blockerLinks(id, rec.blocked_by) });
});

// Body: { ids: number[], status, reason?, by?, scope? }. One decision for every id of a merged entry (up to 100).
browse.post("/recommendations/decision-batch", auth, (req, res) => {
  const { ids } = req.body || {};
  if (!Array.isArray(ids) || !ids.length || !ids.every((v) => Number.isInteger(Number(v)) && Number(v) > 0)) return res.status(400).json({ error: "ids must be a non-empty list of recommendation ids" });
  if (ids.length > 100) return res.status(400).json({ error: "at most 100 ids per batch" });
  const v = validateDecision(req.body);
  if ("error" in v) return res.status(400).json({ error: v.error });
  const unique = [...new Set(ids.map(Number))];
  const updated: any[] = []; const missing: number[] = [];
  for (const id of unique) {
    const rec = decide(id, v.status, v.reason, v.who, v.scope);
    if (rec) updated.push(rec); else missing.push(id);
  }
  if (!updated.length) return res.status(404).json({ error: "not found", missing });
  mirrorRecommendationsInBackground(updated.map((r) => Number(r.id)));
  res.json({ updated: updated.length, missing, recommendations: updated });
});

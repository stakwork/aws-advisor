import { noul, score } from "@typesafe-ai/sdk";
import { postAgentRequest, type AgentRunRow } from "./agent.js";
import { systemPromptFor } from "./concepts.js";
import { config } from "./config.js";
import { db } from "./db.js";
import { CONTROL_REFERENCES } from "./adapters/vercel/rules.js";
import { askJev, jevEnabled } from "./jev.js";
import { EFFORT_LEVELS } from "./resolve.js";
import { CONTROL_SOURCES, type Playbook, type PlaybookEffort, type PlaybookTier } from "./playbooks.js";
import { gradeByRubric } from "./rubric.js";
import { modControl, refreshModSources, sourcesFor, type SourceRow } from "./sources.js";
import { taskFor } from "./tasks.js";
import { SERVICE_IMPACT_LEVELS, tierQuestions, tightenTier } from "./tiercheck.js";

/**
 * Playbooks from sources (docs/cloud-ontology.md §8 step 5, KnPlaybook): the agent writes a control's playbook from
 * the control's own definition and documentation (src/sources.ts) and the provider pages they reference, in batches
 * of a few controls per repo2graph run (tasks/playbook). The answer is validated, then judged: the tier the way
 * recommendations are (Jev: could the steps destroy data, what would users notice; stricter only), the effort by the
 * same scale the resolution gate uses, and, where the hand-written catalogue (src/playbooks.ts, now the seed and the
 * eval set) has an entry, whether the generated playbook says at least what the seed says. A playbook below that bar
 * is kept but not published: the seed stays in force and the row says why. Every playbook records the sources and
 * their hashes it was built from, so a changed source or a fixed age makes it due again.
 */

db.exec(`create table if not exists playbook_jobs (
  id integer primary key autoincrement, request_id text, control_ids text not null, trigger text not null, status text not null default 'pending',
  result text, error text, created_at text not null default (datetime('now')), finished_at text
)`);

export const BATCH_SIZE = 4;
// the hand-written seeds were once stored as sources (origin seed); nothing is hand-written any more
try { db.prepare("delete from sources where origin = 'seed'").run(); } catch { /* table not yet there */ }
export const STALE_DAYS = 90;
/** Below this, a generated playbook with a seed to compare against is not published. */
export const PUBLISH_COVERS_MIN = 0.6;
/** Without a seed, the agent's own confidence has to reach this. */
export const PUBLISH_CONFIDENCE_MIN = 0.5;
const SOURCE_CHARS = 14_000;
const PROMPT_CHARS = 70_000;

export interface GeneratedStep { text: string; source: string | null }
export interface GeneratedPlaybook { control_id: string; title: string; meaning: string; act_when: string; ignore_when: string; steps: GeneratedStep[]; saving: string; references: string[]; gaps: string[]; confidence: number }

// ---- the prompt --------------------------------------------------------------------------------------------------------

/** What the agent gets for one control: the mod's text and the referenced pages, each under its source id. */

/** Where a control's documentation lives: the catalogue's official pages for the AWS controls, the control table's for a platform provider; the benchmark mod's own text is read as well. */
export function referencesFor(controlId: string): string[] {
  if (controlId.startsWith("vercel.control.")) return CONTROL_REFERENCES[controlId] ?? [];
  return CONTROL_SOURCES[controlId] ?? [];
}

/** Whether the generator knows a control: the mod defines it, or sources are listed for it. */
export const knownForGeneration = (controlId: string): boolean => Boolean(modControl(controlId)) || controlId in CONTROL_SOURCES || controlId in CONTROL_REFERENCES;

export function controlSection(controlId: string, sources: SourceRow[], unread: string[]): string {
  const lines = [`## Control ${controlId}`];
  for (const s of sources) lines.push("", `### Source ${s.id}${s.title ? ` — ${s.title}` : ""}${s.origin === "web" ? " (provider page)" : " (benchmark mod)"}`, "", s.text.slice(0, SOURCE_CHARS));
  if (unread.length) lines.push("", `References listed but not read (cite only if you fetched them): ${unread.join(", ")}`);
  return lines.join("\n");
}

export function buildPlaybookPrompt(sections: string[]): string {
  const head = [
    `Write one playbook per control below (${sections.length} controls). Use only the sources given under each control; name the source id on every step.`,
    "Answer with the JSON object described by the schema: playbooks[] with control_id, title, meaning, act_when, ignore_when, steps[{text, source}], saving, references, gaps, confidence.",
    "",
  ];
  let body = sections.join("\n\n---\n\n");
  if (body.length > PROMPT_CHARS) body = body.slice(0, PROMPT_CHARS) + "\n\n[sources truncated here]";
  return head.join("\n") + body;
}

// ---- dispatch ------------------------------------------------------------------------------------------------------------

export interface GenerateResult { jobs: { id: number; request_id: string; control_ids: string[] }[]; skipped: { control_id: string; reason: string }[] }

/**
 * Generates (or rebuilds) playbooks for the given controls: refreshes the mod sources, gathers each control's sources
 * (fetching referenced pages when due), and posts one agent request per batch. Unknown controls are skipped with
 * the reason. The agent quota applies per request, as everywhere.
 */
export async function generatePlaybooks(controlIds: string[], opts: { trigger?: string } = {}): Promise<GenerateResult> {
  if (!config.repo2graphUrl) throw new Error("REPO2GRAPH_URL is not configured: playbooks are written by the agent");
  refreshModSources();
  const sections: { control_id: string; text: string; sources: SourceRow[] }[] = []; const skipped: GenerateResult["skipped"] = [];
  for (const id of [...new Set(controlIds)]) {
    if (!knownForGeneration(id)) { skipped.push({ control_id: id, reason: "not a control of an installed mod, and no sources listed for it" }); continue; }
    const { sources, unread } = await sourcesFor(id, referencesFor(id));
    if (!sources.length) { skipped.push({ control_id: id, reason: "no source text" }); continue; }
    sections.push({ control_id: id, text: controlSection(id, sources, unread), sources });
  }
  const jobs: GenerateResult["jobs"] = [];
  for (let i = 0; i < sections.length; i += BATCH_SIZE) {
    const batch = sections.slice(i, i + BATCH_SIZE); const ids = batch.map((b) => b.control_id);
    const jobId = Number(db.prepare("insert into playbook_jobs(control_ids, trigger) values (?, ?)").run(JSON.stringify(ids), opts.trigger ?? "manual").lastInsertRowid);
    try {
      const { requestId } = await postAgentRequest({ prompt: buildPlaybookPrompt(batch.map((b) => b.text)), systemOverride: await systemPromptFor("playbook"), sessionId: `aws-advisor-playbook-${jobId}-${Date.now().toString(36)}`, agentName: "aws-playbook-writer", metadata: { jobId, controls: ids }, link: { kind: "playbook", jobId } });
      db.prepare("update playbook_jobs set request_id = ? where id = ?").run(requestId, jobId);
      for (const b of batch) db.prepare("update playbooks set status = 'pending', job_id = ? where control_id = ?").run(jobId, b.control_id);
      jobs.push({ id: jobId, request_id: requestId, control_ids: ids });
    } catch (e: any) {
      db.prepare("update playbook_jobs set status = 'failed', error = ?, finished_at = datetime('now') where id = ?").run(String(e?.message || e).slice(0, 500), jobId);
      throw e;
    }
  }
  return { jobs, skipped };
}

// ---- completion: validate, judge, compare, store -----------------------------------------------------------------------

const str = (v: unknown, n = 2000): string => String(v ?? "").trim().slice(0, n);
/** The agent's confidence as a number in 0..1; a word (low, medium, high) is folded; anything else is 0.5. */
export const confidenceOf = (v: unknown): number => { const n = Number(v); if (Number.isFinite(n) && String(v).trim() !== "") return Math.max(0, Math.min(1, n > 1 ? n / 100 : n)); const w = String(v ?? "").toLowerCase(); return w.startsWith("high") ? 0.85 : w.startsWith("med") ? 0.6 : w.startsWith("low") ? 0.3 : 0.5; };

/** The agent's answer as playbooks; entries without the required parts are dropped (the rubric already lowered the score). */
export function parsePlaybookResult(content: unknown): GeneratedPlaybook[] {
  const raw = (content as any)?.playbooks; if (!Array.isArray(raw)) return [];
  const out: GeneratedPlaybook[] = [];
  for (const p of raw) {
    if (!p || typeof p !== "object") continue;
    const steps: GeneratedStep[] = (Array.isArray(p.steps) ? p.steps : []).map((s: any) => (typeof s === "string" ? { text: str(s, 1000), source: null } : { text: str(s?.text, 1000), source: s?.source ? str(s.source, 300) : null })).filter((s: GeneratedStep) => s.text);
    const control_id = str(p.control_id, 200);
    if (!control_id || !str(p.meaning) || !str(p.act_when) || !str(p.ignore_when) || steps.length < 2) continue;
    const gaps = Array.isArray(p.gaps) ? p.gaps : typeof p.gaps === "string" && p.gaps.trim() ? [p.gaps] : [];
    out.push({ control_id, title: str(p.title, 200) || control_id, meaning: str(p.meaning), act_when: str(p.act_when), ignore_when: str(p.ignore_when), steps: steps.slice(0, 10), saving: str(p.saving, 600) || "unknown", references: (Array.isArray(p.references) ? p.references : []).map((r: unknown) => str(r, 300)).filter((r: string) => /^https?:\/\//.test(r)).slice(0, 12), gaps: gaps.map((g: unknown) => str(g, 400)).filter(Boolean).slice(0, 8), confidence: confidenceOf(p.confidence) });
  }
  return out;
}

export interface Judgement { tier: PlaybookTier; effort: PlaybookEffort; irreversible: number | null; service_impact: number | null; effort_score: number | null; covers: number | null; model: string | null; call_id: number | null; judged: boolean }

/** Jev's three answers on one generated playbook: tier (stricter only from "approve"), effort, and coverage of the seed when there is one. */
export async function judgePlaybook(p: GeneratedPlaybook, seed: Playbook | null): Promise<Judgement> {
  const fallback: Judgement = { tier: seed?.tier ?? "approve", effort: seed?.effort ?? "medium", irreversible: null, service_impact: null, effort_score: null, covers: null, model: null, call_id: null, judged: false };
  if (!jevEnabled()) return fallback;
  const state: Record<string, unknown> = {
    proposed_changes: { pb: { title: p.title, meaning: p.meaning, steps: p.steps.map((s) => s.text), saving: p.saving } },
    generated_playbook: { title: p.title, meaning: p.meaning, act_when: p.act_when, ignore_when: p.ignore_when, steps: p.steps.map((s) => s.text), saving: p.saving },
    ...(seed ? { reference_playbook: { title: seed.title, meaning: seed.meaning, act_when: seed.act_when, ignore_when: seed.ignore_when, steps: seed.steps, saving: seed.saving } } : {}),
  };
  const questions = {
    ...tierQuestions("pb"),
    pb_effort: score("How much engineering effort would carrying out generated_playbook.steps take on a typical resource?", EFFORT_LEVELS),
    ...(seed ? { pb_covers: noul("generated_playbook says at least what reference_playbook says: the same meaning of the alarm, the same conditions to act and to leave it alone, and steps that reach the same outcome (wording and order may differ)") } : {}),
  };
  const a = await askJev(state, questions as any, { purpose: "playbook_check" });
  if (!a) return fallback;
  return readJudgement(a.answers, fallback, { model: a.model ?? null, call_id: a.call_id ?? null });
}

/** Jev's answers are typed objects ({type: "noul", noul: 0.7}, {type: "score", score: 1.2}); the numbers out of them, the fallback where one is missing. */
export function readJudgement(answers: unknown, fallback: Judgement, meta: { model: string | null; call_id: number | null } = { model: null, call_id: null }): Judgement {
  const ans = (answers ?? {}) as Record<string, any>;
  const num = (v: any, key: "noul" | "score"): number | null => (typeof v === "number" ? v : v && typeof v === "object" && typeof v[key] === "number" ? v[key] : null);
  const irreversible = num(ans.pb_irreversible, "noul");
  const service_impact = num(ans.pb_service_impact, "score");
  const effort_score = num(ans.pb_effort, "score");
  const covers = num(ans.pb_covers, "noul");
  const tier = irreversible != null && service_impact != null ? tightenTier("approve", { irreversible, service_impact }) : fallback.tier;
  // the effort scale is the resolution gate's (an hour, a day, a week or more); the playbook's word for each
  const effort = effort_score != null ? ((["low", "medium", "high"] as const)[Math.max(0, Math.min(2, Math.round(effort_score)))] as PlaybookEffort) : fallback.effort;
  return { tier, effort, irreversible, service_impact, effort_score, covers, model: meta.model, call_id: meta.call_id, judged: irreversible != null || covers != null || effort_score != null };
}

/** Whether a judged playbook goes live: covers the seed when there is one, else the agent's own confidence suffices. */
export function publishDecision(p: GeneratedPlaybook, j: Judgement, hasSeed: boolean): { published: boolean; review_status: string; reason: string } {
  if (hasSeed) {
    if (j.covers == null) return { published: false, review_status: "unjudged", reason: "Jev could not compare it with the seed; the seed stays until a person reviews it" };
    if (j.covers < PUBLISH_COVERS_MIN) return { published: false, review_status: "below_reference", reason: `covers ${Math.round(j.covers * 100)}% of what the seed says (needs ${Math.round(PUBLISH_COVERS_MIN * 100)}%)` };
    return { published: true, review_status: "generated", reason: `covers ${Math.round(j.covers * 100)}% of the seed` };
  }
  if (p.confidence < PUBLISH_CONFIDENCE_MIN) return { published: false, review_status: "low_confidence", reason: `the agent's confidence is ${p.confidence.toFixed(2)} (needs ${PUBLISH_CONFIDENCE_MIN})` };
  return { published: true, review_status: "generated", reason: "no seed to compare with; the agent's confidence suffices" };
}

const upsertPlaybook = db.prepare(`insert into playbooks(control_id, title, meaning, act_when, ignore_when, steps, saving, references_, gaps, confidence, tier, effort, judged, sources, generated_at, generated_by, stale_after, review_status, published, reason, job_id, status)
  values (@control_id, @title, @meaning, @act_when, @ignore_when, @steps, @saving, @references_, @gaps, @confidence, @tier, @effort, @judged, @sources, @generated_at, @generated_by, @stale_after, @review_status, @published, @reason, @job_id, 'completed')
  on conflict(control_id) do update set title = excluded.title, meaning = excluded.meaning, act_when = excluded.act_when, ignore_when = excluded.ignore_when, steps = excluded.steps, saving = excluded.saving, references_ = excluded.references_, gaps = excluded.gaps,
  confidence = excluded.confidence, tier = excluded.tier, effort = excluded.effort, judged = excluded.judged, sources = excluded.sources, generated_at = excluded.generated_at, generated_by = excluded.generated_by, stale_after = excluded.stale_after,
  review_status = case when playbooks.review_status = 'reviewed' and playbooks.published = 1 then 'reviewed' else excluded.review_status end, published = excluded.published, reason = excluded.reason, job_id = excluded.job_id, status = 'completed'`);

/** The webhook's answer for one job: parse, judge each playbook, decide, store; the job row records the outcome. */
export async function completePlaybooks(run: AgentRunRow, payload: { status: string; result?: any; error?: any }): Promise<{ stored: number; published: number }> {
  const job = db.prepare("select id, control_ids from playbook_jobs where request_id = ? order by id desc limit 1").get(run.request_id) as { id: number; control_ids: string } | undefined;
  if (!job) { console.error(`[playbooks] no job for agent request ${run.request_id}`); return { stored: 0, published: 0 }; }
  const ids: string[] = JSON.parse(job.control_ids || "[]");
  if (payload.status !== "completed") {
    db.prepare("update playbook_jobs set status = 'failed', error = ?, finished_at = datetime('now') where id = ?").run(JSON.stringify(payload.error ?? payload).slice(0, 2000), job.id);
    db.prepare(`update playbooks set status = 'failed' where job_id = ? and status = 'pending'`).run(job.id);
    return { stored: 0, published: 0 };
  }
  const content = payload.result?.content ?? payload.result;
  const grade = gradeByRubric(content, taskFor("playbook").rubric);
  const parsed = parsePlaybookResult(content).filter((p) => ids.includes(p.control_id));
  let stored = 0, published = 0; const now = new Date().toISOString();
  for (const p of parsed) {
    const j = await judgePlaybook(p, null);
    const d = publishDecision(p, j, false);
    const { sources } = await sourcesFor(p.control_id, referencesFor(p.control_id));
    upsertPlaybook.run({ control_id: p.control_id, title: p.title, meaning: p.meaning, act_when: p.act_when, ignore_when: p.ignore_when, steps: JSON.stringify(p.steps), saving: p.saving, references_: JSON.stringify(p.references), gaps: JSON.stringify(p.gaps), confidence: p.confidence,
      tier: j.tier, effort: j.effort, judged: JSON.stringify({ ...j, rubric_score: grade.score }), sources: JSON.stringify(sources.map((s) => ({ id: s.id, hash: s.hash, title: s.title, origin: s.origin }))), generated_at: now, generated_by: `${config.agentModel} via repo2graph (${run.request_id})`,
      stale_after: new Date(Date.now() + STALE_DAYS * 86_400_000).toISOString(), review_status: d.review_status, published: d.published ? 1 : 0, reason: d.reason, job_id: job.id });
    stored++; if (d.published) published++;
    console.log(`[playbooks] ${p.control_id}: ${d.published ? "published" : "held"} (${d.reason}); tier ${j.tier}, effort ${j.effort}${j.judged ? "" : " (Jev off: seed's or defaults)"}`);
  }
  const missing = ids.filter((id) => !parsed.some((p) => p.control_id === id));
  if (missing.length) db.prepare(`update playbooks set status = 'failed' where job_id = ? and status = 'pending'`).run(job.id);
  db.prepare("update playbook_jobs set status = 'completed', result = ?, finished_at = datetime('now'), error = ? where id = ?").run(JSON.stringify({ stored, published, rubric: grade.score, missing }), missing.length ? `no playbook returned for: ${missing.join(", ")}` : null, job.id);
  try { const { mirrorPlaybooks } = await import("./graph_mirror.js"); await mirrorPlaybooks(); } catch (e: any) { console.error(`[graph] playbooks: ${e?.message || e}`); }
  return { stored, published };
}

// ---- what is due ------------------------------------------------------------------------------------------------------

export interface DueControl { control_id: string; why: string }

/**
 * The controls whose playbook should be (re)built: controls with findings in the latest run and no generated
 * playbook yet, seeds not yet generated, playbooks past stale_after, and playbooks whose sources changed since.
 */
export function controlsDue(opts: { limit?: number } = {}): DueControl[] {
  const out = new Map<string, string>();
  const gen = new Map((db.prepare("select control_id, sources, stale_after, status, published from playbooks").all() as any[]).map((r) => [r.control_id, r]));
  const runId = (db.prepare("select id from runs where provider = 'aws' and status = 'completed' order by id desc limit 1").get() as { id: number } | undefined)?.id;
  const flagged = runId ? (db.prepare("select distinct control_id from findings where run_id = ? and status = 'alarm'").all(runId) as { control_id: string }[]).map((r) => r.control_id) : [];
  for (const id of flagged) if (!gen.has(id)) out.set(id, "flagged in the latest run, no generated playbook yet");
  for (const r of db.prepare("select id from runs where provider <> 'aws' and status = 'completed' and id in (select max(id) from runs where provider <> 'aws' and status = 'completed' group by account_id)").all() as { id: number }[])
    // every finding of the pass, info ones too: each is a control a person reads about, and the info ones carry recommendations as well
    for (const f of db.prepare("select distinct control_id from findings where run_id = ?").all(r.id) as { control_id: string }[]) if (!gen.has(f.control_id) && referencesFor(f.control_id).length) out.set(f.control_id, "raised in the account's latest rules pass, no generated playbook yet");
  for (const id of Object.keys(CONTROL_SOURCES)) if (!gen.has(id)) out.set(id, "sources listed, no generated playbook yet");
  const nowIso = new Date().toISOString();
  for (const [id, r] of gen) {
    if (r.status === "pending") continue;
    if (r.stale_after && r.stale_after < nowIso) { out.set(id, `older than ${STALE_DAYS} days`); continue; }
    let srcs: { id: string; hash: string }[] = []; try { srcs = JSON.parse(r.sources || "[]"); } catch { srcs = []; }
    for (const s of srcs) { const cur = db.prepare("select hash from sources where id = ?").get(s.id) as { hash: string } | undefined; if (cur && cur.hash !== s.hash) { out.set(id, `source changed: ${s.id}`); break; } }
  }
  const list = [...out].map(([control_id, why]) => ({ control_id, why }));
  return opts.limit ? list.slice(0, opts.limit) : list;
}

/** Judges again every generated playbook that is not published (Jev was down, or the bar moved); publishes what now passes. */
export async function rejudgeHeld(): Promise<{ judged: number; published: number }> {
  const rows = db.prepare("select * from playbooks where status = 'completed' and published = 0 and review_status <> 'disputed'").all() as any[];
  let judged = 0, published = 0;
  for (const r of rows) {
    const p: GeneratedPlaybook = { control_id: r.control_id, title: r.title, meaning: r.meaning, act_when: r.act_when, ignore_when: r.ignore_when, steps: JSON.parse(r.steps || "[]"), saving: r.saving ?? "", references: JSON.parse(r.references_ || "[]"), gaps: JSON.parse(r.gaps || "[]"), confidence: Number(r.confidence ?? 0.5) };
    const j = await judgePlaybook(p, null); if (!j.judged) continue;
    const d = publishDecision(p, j, false);
    let prev: any = {}; try { prev = JSON.parse(r.judged || "{}"); } catch { prev = {}; }
    db.prepare("update playbooks set tier = ?, effort = ?, judged = ?, review_status = ?, published = ?, reason = ? where control_id = ?").run(j.tier, j.effort, JSON.stringify({ ...j, rubric_score: prev.rubric_score ?? null }), d.review_status, d.published ? 1 : 0, d.reason, p.control_id);
    judged++; if (d.published) published++;
    console.log(`[playbooks] ${p.control_id}: re-judged, ${d.published ? "published" : "held"} (${d.reason}); tier ${j.tier}, effort ${j.effort}`);
  }
  if (published) { try { const { mirrorPlaybooks } = await import("./graph_mirror.js"); await mirrorPlaybooks(); } catch (e: any) { console.error(`[graph] playbooks: ${e?.message || e}`); } }
  return { judged, published };
}

export const listPlaybookJobs = (limit = 20) => db.prepare("select id, request_id, control_ids, trigger, status, result, error, created_at, finished_at from playbook_jobs order by id desc limit ?").all(limit).map((r: any) => ({ ...r, control_ids: JSON.parse(r.control_ids || "[]"), result: r.result ? JSON.parse(r.result) : null }));
export const playbookJobBusy = () => Boolean(db.prepare("select 1 from playbook_jobs where status = 'pending' and created_at > datetime('now', '-30 minutes') limit 1").get());

/** A person's verdict on a generated playbook: reviewed pins it (published) until its sources change; disputed unpublishes it. */
export function reviewPlaybook(controlId: string, status: "reviewed" | "disputed" | "generated"): boolean {
  const r = db.prepare("update playbooks set review_status = ?, published = ? where control_id = ?").run(status, status === "disputed" ? 0 : 1, controlId);
  return r.changes > 0;
}

export { SERVICE_IMPACT_LEVELS };

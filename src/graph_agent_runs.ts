import { db } from "./db.js";
import { accountId, enabled, ensureSchema, inBackground, writeCypher } from "./graph_mirror.js";
import { PROMPT_LABELS, type PromptKind } from "./prompts.js";
import { AWS } from "./adapters/types.js";

/**
 * Every request the advisor sent to repo2graph's agent (src/agent.ts, table agent_runs) as an entry in the graph:
 * the findings batch after a run, the morning observation, incident investigations, tailored resolutions, chat
 * turns, usage investigations, playbook batches and narrated passes. (:AdvisorAgentRun {id: <request id>}) carries
 * the task, the agent and model, the status, the rubric score and a short excerpt of the answer, and links to what
 * it was about: -[:ABOUT]-> the run, alert, recommendation, action, controls or box; -[:PRODUCED]-> the
 * recommendations a findings answer imported; -[:RETRY_OF]-> the request a low-scoring answer was retried from;
 * -[:CONTINUES]-> the previous turn of the same session (a chat thread). Written when the request is sent and again
 * when its answer arrives; the full sync rewrites them all.
 */

export interface AgentRunOwner { runs: number[]; alerts: number[]; recommendations: number[]; actions: number[]; controls: string[]; resources: string[]; pools: string[]; day: string | null; pass_at: string | null; thread_id: number | null }

export interface AgentRunNode {
  id: string;
  props: Record<string, string | number | boolean | null>;
  about: AgentRunOwner;
  produced: number[];
  retry_of: string | null;
  continues: string | null;
}

const json = (v: unknown): any => { if (v == null || typeof v !== "string") return v ?? null; try { return JSON.parse(v); } catch { return null; } };
const clip = (v: unknown, n: number): string | null => { const s = String(v ?? "").replace(/\s+/g, " ").trim(); return s ? (s.length > n ? `${s.slice(0, n - 1)}…` : s) : null; };
const num = (v: unknown): number | null => (v == null || v === "" || !Number.isFinite(Number(v)) ? null : Number(v));

/** A line saying what the answer was, from the shapes the tasks answer in (src/tasks.ts). Pure. */
export function answerExcerpt(result: unknown): string | null {
  const r = json(result);
  const c = r?.content ?? r;
  if (c == null) return null;
  if (typeof c === "string") return clip(c, 500);
  if (Array.isArray(c.recommendations)) return `${c.recommendations.length} recommendation${c.recommendations.length === 1 ? "" : "s"}${c.recommendations.length ? `: ${c.recommendations.slice(0, 3).map((x: any) => clip(x?.title, 80)).filter(Boolean).join("; ")}` : ""}`;
  for (const k of ["summary", "cause", "reply", "answer", "message", "narration", "verdict"]) if (typeof c[k] === "string" && c[k].trim()) return clip(c[k], 500);
  if (Array.isArray(c.playbooks)) return `${c.playbooks.length} playbook${c.playbooks.length === 1 ? "" : "s"}`;
  return null;
}

/** What the request was about, from the link stored with it, the metadata, and (rows from before those were stored) the owning tables. Pure but for `lookup`. */
export function ownerOf(row: any, lookup: { day?: string | null; subject?: string | null; controls?: string[] | null; pass_at?: string | null; thread_id?: number | null } = {}): AgentRunOwner {
  const link = json(row.link) ?? {};
  const meta = json(row.metadata) ?? {};
  const o: AgentRunOwner = { runs: [], alerts: [], recommendations: [], actions: [], controls: [], resources: [], pools: [], day: null, pass_at: lookup.pass_at ?? null, thread_id: num(meta.threadId) ?? lookup.thread_id ?? null };
  const run = num(link.runId ?? row.run_id); if (run) o.runs.push(run);
  const alert = num(link.alertId ?? row.alert_id); if (alert) o.alerts.push(alert);
  const rec = num(link.recommendationId ?? row.recommendation_id); if (rec) o.recommendations.push(rec);
  const action = num(meta.actionId); if (action) o.actions.push(action);
  const controls: unknown = Array.isArray(meta.controls) ? meta.controls : lookup.controls;
  if (Array.isArray(controls)) o.controls.push(...controls.filter((c): c is string => typeof c === "string"));
  const subject = typeof link.subject === "string" ? link.subject : lookup.subject ?? null;
  if (subject) { if (subject.startsWith("asg:")) o.pools.push(subject.slice(4)); else o.resources.push(subject); }
  o.day = typeof link.day === "string" ? link.day : lookup.day ?? null;
  return o;
}

/** The entry's title: the task and what it was about. Pure. */
export function agentRunName(kind: string, o: AgentRunOwner, createdAt: string | null): string {
  const task = PROMPT_LABELS[kind as PromptKind]?.title ?? kind;
  const on = kind === "observe" ? (o.day ?? createdAt?.slice(0, 10)) : o.runs.length ? `run #${o.runs[0]}` : o.alerts.length ? `alert #${o.alerts[0]}` : o.recommendations.length ? `recommendation #${o.recommendations[0]}`
    : o.actions.length ? `action #${o.actions[0]}` : o.resources[0] ?? o.pools[0] ?? (o.controls.length ? `${o.controls.length} control${o.controls.length === 1 ? "" : "s"}` : kind === "chat" ? "account" : null);
  return [task, on].filter(Boolean).join(" · ");
}

/** One agent_runs row as its graph entry. Pure. Exported for the tests. */
export function agentRunNode(row: any, owner: AgentRunOwner, produced: number[] = [], continues: string | null = null): AgentRunNode {
  const created = row.created_at ?? null, finished = row.finished_at ?? null;
  const took = created && finished ? Math.round((Date.parse(`${finished}Z`) - Date.parse(`${created}Z`)) / 1000) : null;
  const err = json(row.error);
  return {
    id: row.request_id,
    props: {
      name: agentRunName(row.kind, owner, created),
      row_id: row.id, kind: row.kind, task: PROMPT_LABELS[row.kind as PromptKind]?.title ?? row.kind,
      agent_name: row.agent_name ?? null, model: row.model ?? null, status: row.status ?? "pending",
      score: num(row.score), session_id: row.session_id ?? null,
      created_at: created, finished_at: finished, took_s: Number.isFinite(took) ? took : null,
      retried_by: row.retried_by ?? null,
      error: clip(typeof err === "string" ? err : err?.message ?? (err ? JSON.stringify(err) : row.error), 300),
      answer: answerExcerpt(row.result),
      prompt_chars: row.prompt ? String(row.prompt).length : null,
      day: owner.day, pass_at: owner.pass_at, thread_id: owner.thread_id,
    },
    about: owner,
    produced,
    retry_of: row.retry_of ?? null,
    continues,
  };
}

// ids are the advisor's own (one database), so no account filter: a recommendation on a member account still links; a pool is matched by name within the provider
const ABOUT = (label: string, field: string, key = "id") => `
CALL { WITH n, row UNWIND row.about.${field} AS x MATCH (t:${label} {${key}: x}) WHERE t.provider IS NULL OR t.provider = $provider MERGE (n)-[:ABOUT]->(t) }`;

const AGENT_RUN_CYPHER = `
UNWIND $rows AS row
MERGE (n:AdvisorAgentRun {id: row.id})
SET n += row.props, n.provider = $provider, n.account_id = $account, n.native_type = 'agent_run', n.native_id = row.id, n.updated_at = $now
WITH n, row
OPTIONAL MATCH (n)-[old:ABOUT|PRODUCED|RETRY_OF|CONTINUES]->() DELETE old
WITH DISTINCT n, row
OPTIONAL MATCH (acc:AdvisorAccount {id: $account})
FOREACH (_ IN CASE WHEN acc IS NULL THEN [] ELSE [1] END | MERGE (n)-[:IN_ACCOUNT]->(acc))
WITH DISTINCT n, row
${ABOUT("AdvisorRun", "runs")}
${ABOUT("AdvisorAlert", "alerts")}
${ABOUT("AdvisorRecommendation", "recommendations")}
${ABOUT("AdvisorAction", "actions")}
${ABOUT("AdvisorControl", "controls")}
${ABOUT("AdvisorResource", "resources")}
${ABOUT("AdvisorNodePool", "pools", "name")}
CALL { WITH n, row UNWIND row.produced AS x MATCH (r:AdvisorRecommendation {id: x}) MERGE (n)-[:PRODUCED]->(r) }
CALL { WITH n, row WITH n, row WHERE row.retry_of IS NOT NULL MERGE (p:AdvisorAgentRun {id: row.retry_of}) MERGE (n)-[:RETRY_OF]->(p) }
CALL { WITH n, row WITH n, row WHERE row.continues IS NOT NULL MERGE (p:AdvisorAgentRun {id: row.continues}) MERGE (n)-[:CONTINUES]->(p) }`;

const tableHas = (name: string) => Boolean(db.prepare("select 1 from sqlite_master where type = 'table' and name = ?").get(name));
const one = (sql: string, ...args: unknown[]): any => { try { return db.prepare(sql).get(...args); } catch { return undefined; } };

/** The owning rows of a request sent before the link was stored, found by its request id. */
function legacyLookup(row: any): Parameters<typeof ownerOf>[1] {
  if (row.link) return {};
  const rid = row.request_id;
  if (row.kind === "observe" && tableHas("observations")) return { day: one("select day from observations where request_id = ? order by id desc limit 1", rid)?.day ?? null };
  if (row.kind === "usage" && tableHas("usage_investigations")) return { subject: one("select subject from usage_investigations where request_id = ? order by id desc limit 1", rid)?.subject ?? null };
  if (row.kind === "playbook" && tableHas("playbook_jobs")) return { controls: json(one("select control_ids from playbook_jobs where request_id = ? order by id desc limit 1", rid)?.control_ids) };
  if (row.kind === "pass_report" && tableHas("pass_reports")) return { pass_at: one("select pass_at from pass_reports where request_id = ? order by id desc limit 1", rid)?.pass_at ?? null };
  if (row.kind === "chat" && tableHas("recommendation_messages")) return { thread_id: num(one("select thread_id from recommendation_messages where request_id = ? order by id desc limit 1", rid)?.thread_id) };
  return {};
}

/** The graph entries of the given requests (all when none are given), from agent_runs. */
export function agentRunNodes(requestIds?: string[]): AgentRunNode[] {
  const rows = (requestIds
    ? db.prepare(`select * from agent_runs where request_id in (${requestIds.map(() => "?").join(",")})`).all(...requestIds)
    : db.prepare("select * from agent_runs where request_id is not null order by id").all()) as any[];
  return nodesOf(rows);
}

function nodesOf(rows: any[]): AgentRunNode[] {
  return rows.map((r) => {
    const produced = r.kind === "findings" && r.status === "completed" ? (db.prepare("select id from recommendations where agent_request_id = ?").all(r.request_id) as { id: number }[]).map((x) => x.id) : [];
    const prev = r.session_id ? one("select request_id from agent_runs where session_id = ? and id < ? and request_id is not null order by id desc limit 1", r.session_id, r.id)?.request_id ?? null : null;
    return agentRunNode(r, ownerOf(r, legacyLookup(r)), produced, prev);
  });
}

export interface AgentRunListing {
  /** the entry's props, plus its request id, what it was about, how many recommendations it imported, and the retry and session links */
  rows: Record<string, unknown>[];
  total: number; page: number; page_size: number;
  kinds: Record<string, number>; statuses: Record<string, number>;
}

/** The Agent page (ui/src/pages/Agent.tsx): the same entries as the graph, newest first, filtered by kind and status, a page at a time. */
export function listAgentRuns(opts: { kind?: string; status?: string; page?: number; pageSize?: number } = {}): AgentRunListing {
  const page = Math.max(1, Math.floor(Number(opts.page) || 1));
  const size = Math.min(200, Math.max(5, Math.floor(Number(opts.pageSize) || 50)));
  const where: string[] = ["request_id is not null"]; const args: unknown[] = [];
  if (opts.kind) { where.push("kind = ?"); args.push(opts.kind); }
  if (opts.status) { where.push("status = ?"); args.push(opts.status); }
  const w = where.join(" and ");
  const total = Number((db.prepare(`select count(*) as n from agent_runs where ${w}`).get(...args) as { n: number }).n);
  const rows = db.prepare(`select * from agent_runs where ${w} order by id desc limit ? offset ?`).all(...args, size, (page - 1) * size) as any[];
  const tally = (col: string) => Object.fromEntries((db.prepare(`select ${col} as k, count(*) as n from agent_runs where request_id is not null group by 1`).all() as { k: string; n: number }[]).map((x) => [x.k, x.n]));
  return {
    rows: nodesOf(rows).map((n) => ({ ...n.props, request_id: n.id, about: n.about, produced: n.produced.length, retry_of: n.retry_of, continues: n.continues })),
    total, page, page_size: size, kinds: tally("kind"), statuses: tally("status"),
  };
}

/** Writes the entries of the given requests (all when none are given). */
export async function mirrorAgentRuns(requestIds?: string[]): Promise<{ agent_runs: number }> {
  if (!enabled()) return { agent_runs: 0 };
  if (requestIds && !requestIds.length) return { agent_runs: 0 };
  await ensureSchema();
  const nodes = agentRunNodes(requestIds);
  const stamp = new Date().toISOString();
  for (let i = 0; i < nodes.length; i += 200) await writeCypher(AGENT_RUN_CYPHER, { rows: nodes.slice(i, i + 200), account: accountId(), provider: AWS, now: stamp });
  return { agent_runs: nodes.length };
}

export const mirrorAgentRunInBackground = (requestId: string) => inBackground(`agent run ${requestId}`, () => mirrorAgentRuns([requestId]));

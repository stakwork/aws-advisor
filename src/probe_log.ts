/**
 * The record of every probe and every pass, for History > Probes: what was sent to which box, when, from where (a
 * scheduled pass, a pass run by hand, a click on a box's page, the agent, a permission check), and how it ended (stored,
 * or the failure's code and message, the SSM command id to look it up in the console). A pass row carries its counts,
 * the selection line (how many boxes and why the rest was left out) and its failures by code. Rows outlive the raw probe
 * results (instance_metrics, 30 days): runs are kept 60 days, passes 180. Nothing here throws into a probe: a record that
 * cannot be written is logged and the probe goes on.
 */
import { db } from "./db.js";
import type { ProbeKind } from "./probes.js";

export type ProbeOrigin = "pass" | "manual" | "agent" | "check";
export type PassOrigin = "cron" | "manual";

db.exec(`
create table if not exists probe_passes (
  id integer primary key autoincrement, kind text not null, origin text not null, started_at text not null, finished_at text, took_ms integer,
  candidates integer not null default 0, probed integer not null default 0, failed integer not null default 0,
  failures text, selection text, note text
);
create index if not exists probe_passes_started on probe_passes(started_at);
create table if not exists probe_runs (
  id integer primary key autoincrement, pass_id integer, instance_id text not null, account_id text, kind text not null, origin text not null,
  started_at text not null, finished_at text, took_ms integer, status text not null default 'running', code text, message text,
  command_id text, document text, upload text, metrics_id integer
);
create index if not exists probe_runs_started on probe_runs(started_at);
create index if not exists probe_runs_instance on probe_runs(instance_id, started_at);
create index if not exists probe_runs_pass on probe_runs(pass_id);
-- what was running when the process last stopped never finished: say so rather than show it running forever
update probe_runs set status = 'lost', code = 'lost', message = 'the advisor stopped while this ran', finished_at = coalesce(finished_at, started_at) where status = 'running';
update probe_passes set note = coalesce(note, 'the advisor stopped while this pass ran'), finished_at = coalesce(finished_at, started_at) where finished_at is null;
`);

const RUNS_DAYS = 60, PASSES_DAYS = 180;
const safe = <T>(what: string, f: () => T, fallback: T): T => { try { return f(); } catch (e: any) { console.error(`[probe-log] ${what} not recorded: ${e?.message || e}`); return fallback; } };

/** Starts a pass row; returns its id (0 when it could not be written). Old rows go here, once per pass. */
export function startPass(kind: ProbeKind, origin: PassOrigin, selection?: string | null): number {
  return safe("pass", () => {
    db.prepare("delete from probe_runs where datetime(started_at) < datetime('now', ?)").run(`-${RUNS_DAYS} days`);
    db.prepare("delete from probe_passes where datetime(started_at) < datetime('now', ?)").run(`-${PASSES_DAYS} days`);
    return Number(db.prepare("insert into probe_passes(kind, origin, started_at, selection) values (?, ?, ?, ?)").run(kind, origin, new Date().toISOString(), selection ?? null).lastInsertRowid);
  }, 0);
}
/** The selection line, once the pass knows it (the candidates and why the rest was left out). */
export function notePassSelection(id: number, selection: string): void {
  if (id) safe("pass selection", () => db.prepare("update probe_passes set selection = ? where id = ?").run(selection.slice(0, 600), id), undefined);
}
export function finishPass(id: number, r: { candidates: number; probed: number; failed: { code: string }[]; note?: string | null }): void {
  if (!id) return;
  const byCode: Record<string, number> = {}; for (const f of r.failed) byCode[f.code] = (byCode[f.code] || 0) + 1;
  safe("pass end", () => db.prepare("update probe_passes set finished_at = ?, took_ms = cast((julianday(?) - julianday(started_at)) * 86400000 as integer), candidates = ?, probed = ?, failed = ?, failures = ?, note = ? where id = ?")
    .run(new Date().toISOString(), new Date().toISOString(), r.candidates, r.probed, r.failed.length, JSON.stringify(byCode), r.note?.slice(0, 600) ?? null, id), undefined);
}

/** Starts a run row for one probe of one box; returns its id (0 when it could not be written). */
export function startRun(r: { instanceId: string; kind: ProbeKind; origin: ProbeOrigin; passId?: number | null }): number {
  return safe("run", () => Number(db.prepare("insert into probe_runs(pass_id, instance_id, kind, origin, started_at) values (?, ?, ?, ?, ?)").run(r.passId || null, r.instanceId, r.kind, r.origin, new Date().toISOString()).lastInsertRowid), 0);
}
export interface RunOutcome { status: "ok" | "failed"; code?: string | null; message?: string | null; accountId?: string | null; commandId?: string | null; document?: string | null; upload?: string | null; metricsId?: number | null }
export function finishRun(id: number, o: RunOutcome): void {
  if (!id) return;
  const now = new Date().toISOString();
  safe("run end", () => db.prepare("update probe_runs set finished_at = ?, took_ms = cast((julianday(?) - julianday(started_at)) * 86400000 as integer), status = ?, code = ?, message = ?, account_id = ?, command_id = ?, document = ?, upload = ?, metrics_id = ? where id = ?")
    .run(now, now, o.status, o.code ?? null, o.message?.slice(0, 600) ?? null, o.accountId ?? null, o.commandId ?? null, o.document ?? null, o.upload ?? null, o.metricsId ?? null, id), undefined);
}

export interface PassRow { id: number; kind: string; origin: string; started_at: string; finished_at: string | null; took_ms: number | null; candidates: number; probed: number; failed: number; failures: Record<string, number>; selection: string | null; note: string | null }
export interface RunRow { id: number; pass_id: number | null; instance_id: string; instance_name: string | null; account_id: string | null; kind: string; origin: string; started_at: string; finished_at: string | null; took_ms: number | null; status: string; code: string | null; message: string | null; command_id: string | null; document: string | null; upload: string | null; metrics_id: number | null }

const clampLimit = (n: unknown, def: number, max: number) => Math.max(1, Math.min(max, Number(n) || def));

/** Passes, newest first. */
export function listPasses(q: { kind?: string | null; limit?: unknown } = {}): PassRow[] {
  const rows = db.prepare(`select * from probe_passes where 1=1${q.kind ? " and kind = ?" : ""} order by id desc limit ?`).all(...(q.kind ? [q.kind] : []), clampLimit(q.limit, 50, 500)) as any[];
  return rows.map((r) => ({ ...r, failures: (() => { try { return JSON.parse(r.failures || "{}"); } catch { return {}; } })() }));
}
/** Runs, newest first, with the box's name; by pass, by box, by kind, by outcome (ok | failed, where lost counts as failed) or by code. */
export function listRuns(q: { passId?: unknown; instanceId?: string | null; kind?: string | null; status?: string | null; code?: string | null; limit?: unknown } = {}): RunRow[] {
  const where: string[] = []; const args: unknown[] = [];
  if (Number(q.passId)) { where.push("r.pass_id = ?"); args.push(Number(q.passId)); }
  if (q.instanceId) { where.push("(r.instance_id = ? or lower(i.name) like ?)"); args.push(q.instanceId, `%${q.instanceId.toLowerCase()}%`); }
  if (q.kind) { where.push("r.kind = ?"); args.push(q.kind); }
  if (q.status === "ok") where.push("r.status = 'ok'"); else if (q.status === "failed") where.push("r.status <> 'ok'");
  if (q.code) { where.push("r.code = ?"); args.push(q.code); }
  return db.prepare(`select r.*, i.name as instance_name from probe_runs r left join inventory_ec2 i on i.instance_id = r.instance_id${where.length ? ` where ${where.join(" and ")}` : ""} order by r.id desc limit ?`).all(...args, clampLimit(q.limit, 200, 1000)) as RunRow[];
}
/** Per kind: the last pass and the last 24 hours of runs (every origin), for the page's header. */
export function probeHistoryOverview(): { kind: string; last_pass: PassRow | null; runs_24h: number; failed_24h: number; last_failure: RunRow | null }[] {
  const kinds = db.prepare("select kind from (select kind, max(id) as m from probe_runs group by kind union select kind, max(id) from probe_passes group by kind) group by kind order by kind").all() as { kind: string }[];
  return kinds.map(({ kind }) => {
    const c = db.prepare("select count(*) as n, sum(case when status <> 'ok' then 1 else 0 end) as f from probe_runs where kind = ? and datetime(started_at) > datetime('now', '-24 hours')").get(kind) as { n: number; f: number | null };
    const lf = db.prepare("select r.*, i.name as instance_name from probe_runs r left join inventory_ec2 i on i.instance_id = r.instance_id where r.kind = ? and r.status <> 'ok' order by r.id desc limit 1").get(kind) as RunRow | undefined;
    return { kind, last_pass: listPasses({ kind, limit: 1 })[0] ?? null, runs_24h: c.n, failed_24h: c.f ?? 0, last_failure: lf ?? null };
  });
}

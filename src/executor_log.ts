/**
 * The executor's activity log: what the actuator did, in order. The ledger (src/executor.ts, `actions`) holds what
 * each proposal became; this holds every pass, scheduled or manual, including the ones that did nothing because the
 * mode was off or the executor was paused, with the lines the pass printed (what every module looked at, what it
 * proposed, what waited on the cap, the grace period or Jev), and every apply, read-back and revert on a ledger row
 * with its outcome, whoever triggered it, inside a pass or from the page and the chat. A person reads a day of the
 * actuator here (Auto-actions › Activity, GET /actions/log) instead of the server's stdout. Passes older than
 * LOG_KEEP_DAYS are pruned when a new one starts; the ledger rows themselves stay.
 */
import { db } from "./db.js";
import type { PassResult } from "./executor.js";

db.exec(`create table if not exists executor_passes (
  id integer primary key autoincrement,
  started_at text not null default (datetime('now')),
  finished_at text,
  trigger text not null,
  mode text not null,
  proposed integer not null default 0, fresh integer not null default 0, applied integer not null default 0, verified integer not null default 0,
  failed integer not null default 0, refused integer not null default 0, held integer not null default 0, stale integer not null default 0,
  took_ms integer,
  notes_json text, errors_json text, lines_json text
);
create table if not exists executor_events (
  id integer primary key autoincrement,
  at text not null default (datetime('now')),
  pass_id integer,
  action_id integer not null,
  kind text not null,
  event text not null,
  trigger text not null,
  outcome text not null,
  detail text
);
create index if not exists executor_events_pass on executor_events(pass_id, id);
create index if not exists executor_events_action on executor_events(action_id, id)`);

export const LOG_KEEP_DAYS = 90;
/** How much of a result or error a line keeps: enough to read, never the whole stack. */
const DETAIL_MAX = 500;

/** apply: the change under the actuator role; verify: the read-back; revert: the undo. */
export type ExecutorEventName = "apply" | "verify" | "revert";
/** The row's status after the event, or `pending` when a read-back could not tell yet, `error` when the read-back itself failed. */
export type ExecutorEventOutcome = "applied" | "verified" | "failed" | "refused" | "reverted" | "pending" | "error";

export interface ExecutorEvent { id: number; at: string; pass_id: number | null; action_id: number; kind: string; event: ExecutorEventName; trigger: string; outcome: ExecutorEventOutcome; detail: string | null }
export interface ExecutorPass {
  id: number; started_at: string; finished_at: string | null; trigger: string; mode: string;
  proposed: number; fresh: number; applied: number; verified: number; failed: number; refused: number; held: number; stale: number; took_ms: number | null;
  notes: string[]; errors: string[]; lines: string[]; events: ExecutorEvent[];
}

let current: { id: number; trigger: string } | null = null;
/** The pass in flight, so an event raised inside it is filed under it (passes never overlap: runExecutorPass serialises them). */
export const currentPass = () => current;

/** Opens a pass record and makes it current; prunes the old ones. */
export function beginPass(trigger: string, mode: string): number {
  db.prepare("delete from executor_events where pass_id in (select id from executor_passes where started_at < datetime('now', ?))").run(`-${LOG_KEEP_DAYS} days`);
  db.prepare("delete from executor_passes where started_at < datetime('now', ?)").run(`-${LOG_KEEP_DAYS} days`);
  const id = Number(db.prepare("insert into executor_passes (trigger, mode) values (?, ?)").run(trigger, mode).lastInsertRowid);
  current = { id, trigger };
  return id;
}

/** Closes the pass record with its counts, notes, errors and printed lines. */
export function endPass(id: number, out: PassResult, lines: string[]): void {
  db.prepare(`update executor_passes set finished_at = datetime('now'), mode = ?, proposed = ?, fresh = ?, applied = ?, verified = ?, failed = ?, refused = ?, held = ?, stale = ?, took_ms = ?,
    notes_json = ?, errors_json = ?, lines_json = ? where id = ?`)
    .run(out.mode, out.proposed, out.fresh, out.applied, out.verified, out.failed, out.refused, out.held ?? 0, out.stale, out.took_ms,
      JSON.stringify(out.notes), JSON.stringify(out.errors), JSON.stringify(lines.slice(-2000)), id);
  if (current?.id === id) current = null;
}

/** Files one apply, read-back or revert with its outcome; under the pass in flight when there is one. */
export function logEvent(e: { action_id: number; kind: string; event: ExecutorEventName; outcome: ExecutorEventOutcome; trigger?: string; detail?: string | null }): number {
  const pass = current;
  const detail = e.detail ? String(e.detail).slice(0, DETAIL_MAX) : null;
  return Number(db.prepare("insert into executor_events (pass_id, action_id, kind, event, trigger, outcome, detail) values (?, ?, ?, ?, ?, ?, ?)")
    .run(pass?.id ?? null, e.action_id, e.kind, e.event, e.trigger || pass?.trigger || "manual", e.outcome, detail).lastInsertRowid);
}

const safeList = (s: string | null): string[] => { if (!s) return []; try { const v = JSON.parse(s); return Array.isArray(v) ? v.map(String) : []; } catch { return []; } };
const passOf = (r: any, events: ExecutorEvent[]): ExecutorPass => ({
  id: r.id, started_at: r.started_at, finished_at: r.finished_at, trigger: r.trigger, mode: r.mode,
  proposed: r.proposed, fresh: r.fresh, applied: r.applied, verified: r.verified, failed: r.failed, refused: r.refused, held: r.held, stale: r.stale, took_ms: r.took_ms,
  notes: safeList(r.notes_json), errors: safeList(r.errors_json), lines: safeList(r.lines_json), events,
});

/** The newest passes with their events, and the events that happened outside any pass (Apply, Check and Revert from the page or the chat). */
export function listExecutorLog(opts: { limit?: number } = {}): { passes: ExecutorPass[]; loose: ExecutorEvent[] } {
  const limit = Math.min(200, Math.max(1, opts.limit || 30));
  const passes = db.prepare("select * from executor_passes order by id desc limit ?").all(limit) as any[];
  const byPass = new Map<number, ExecutorEvent[]>();
  if (passes.length) {
    const ids = passes.map((p) => p.id);
    for (const e of db.prepare(`select * from executor_events where pass_id in (${ids.map(() => "?").join(",")}) order by id`).all(...ids) as ExecutorEvent[]) {
      if (!byPass.has(e.pass_id!)) byPass.set(e.pass_id!, []);
      byPass.get(e.pass_id!)!.push(e);
    }
  }
  const loose = db.prepare("select * from executor_events where pass_id is null order by id desc limit ?").all(limit) as ExecutorEvent[];
  return { passes: passes.map((p) => passOf(p, byPass.get(p.id) || [])), loose };
}

/** Everything that happened to one ledger row, oldest first: the row's own history for its expanded view and the agent. */
export function eventsForAction(actionId: number): ExecutorEvent[] {
  return db.prepare("select * from executor_events where action_id = ? order by id").all(actionId) as ExecutorEvent[];
}

/** One pass with its events, for the graph mirror. */
export function getPass(id: number): ExecutorPass | null {
  const r = db.prepare("select * from executor_passes where id = ?").get(id) as any;
  if (!r) return null;
  return passOf(r, db.prepare("select * from executor_events where pass_id = ? order by id").all(id) as ExecutorEvent[]);
}

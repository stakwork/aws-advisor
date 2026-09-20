import { AlertLevel, LEVEL_RANK, alertLevel } from "./alert_level.js";
import { localDay } from "./localdate.js";

/** Pure helpers behind src/routes/browse.ts: paging, alert ordering, findings dedupe, recommendation merging. */

export interface PageParams { page: number; page_size: number }

export function pageParams(q: Record<string, unknown>, defaults: { size: number; max: number }): PageParams {
  const page = Math.max(1, Math.floor(Number(q.page)) || 1);
  const size = Math.floor(Number(q.page_size));
  return { page, page_size: Number.isFinite(size) && size > 0 ? Math.min(defaults.max, size) : defaults.size };
}

export function paginate<T>(rows: T[], p: PageParams): { total: number; page: number; page_size: number; items: T[] } {
  const start = (p.page - 1) * p.page_size;
  return { total: rows.length, page: p.page, page_size: p.page_size, items: rows.slice(start, start + p.page_size) };
}

// ---- alerts -----------------------------------------------------------------------------------------------

/** created_at is SQLite's datetime('now') (UTC, "YYYY-MM-DD HH:MM:SS"); the day is the server's local date. */
export function alertDay(createdAt: string): string {
  const iso = createdAt.includes("T") ? createdAt : createdAt.replace(" ", "T");
  return localDay(new Date(/Z$|[+-]\d\d:\d\d$/.test(iso) ? iso : iso + "Z"));
}

export interface AlertLike { id: number; created_at: string; kind: string; triage?: unknown }
export type LeveledAlert<T extends AlertLike> = T & { level: AlertLevel; day: string };

/** Today's alerts before older days; within a day alarms, then warnings, then info; newest first within a level. */
export function orderAlerts<T extends AlertLike>(rows: T[]): LeveledAlert<T>[] {
  return rows
    .map((r) => ({ ...r, level: alertLevel(r), day: alertDay(r.created_at) }))
    .sort((a, b) => b.day.localeCompare(a.day) || LEVEL_RANK[a.level] - LEVEL_RANK[b.level] || b.created_at.localeCompare(a.created_at) || b.id - a.id);
}

export function levelCounts(rows: { level: AlertLevel }[]): Record<AlertLevel, number> {
  const c: Record<AlertLevel, number> = { alarm: 0, warning: 0, info: 0 };
  for (const r of rows) c[r.level]++;
  return c;
}

// ---- findings ---------------------------------------------------------------------------------------------

export interface FindingLike { id: number; fingerprint: string; control_id: string; resource: string | null }

/**
 * One row per fingerprint (a resource can be reported by several regions or controls with the same fingerprint)
 * and, on top, one row per (control_id, resource): the first by id wins. Rows without a resource are kept as is.
 */
export function dedupeFindings<T extends FindingLike>(rows: T[]): T[] {
  const byFp = new Set<string>();
  const byKey = new Set<string>();
  const out: T[] = [];
  for (const r of [...rows].sort((a, b) => a.id - b.id)) {
    if (byFp.has(r.fingerprint)) continue;
    const key = r.resource == null ? null : `${r.control_id}|${r.resource}`;
    if (key && byKey.has(key)) continue;
    byFp.add(r.fingerprint);
    if (key) byKey.add(key);
    out.push(r);
  }
  return out;
}

// ---- recommendations --------------------------------------------------------------------------------------

export interface RecLike { id: number; source: string; rule: string; resource: string | null; action_type: string; status: string; est_monthly_saving: number | null; confidence: number | null; updated_at: string }
export interface MergedRef { id: number; source: string; rule: string; est_monthly_saving: number | null; confidence: number | null }
export type MergedRec<T extends RecLike> = T & { merged: MergedRef[]; sources: string[]; merged_ids: number[] };

const saving = (r: { est_monthly_saving: number | null }) => (r.est_monthly_saving == null ? -Infinity : Number(r.est_monthly_saving));
const SOURCE_ORDER = ["rules", "agent"];
const bySource = (a: string, b: string) => (SOURCE_ORDER.indexOf(a) + 1 || 99) - (SOURCE_ORDER.indexOf(b) + 1 || 99) || a.localeCompare(b);

/**
 * Rows that propose the same action on the same resource (in the same status) become one entry: the one with the
 * highest saving estimate is primary, the others are listed under `merged`. Sorted by saving desc, nulls last.
 */
export function mergeRecommendations<T extends RecLike>(rows: T[]): MergedRec<T>[] {
  const groups = new Map<string, T[]>();
  for (const r of rows) {
    // Sources name the same thing differently (ARN vs id); merge on the last segment so they meet.
    const rid = r.resource ? (r.resource.startsWith("arn:") ? (r.resource.split(":").slice(5).join(":").split("/").pop() || r.resource).replace(/^(db|cluster|instance|volume|snapshot|function):/, "") : r.resource) : null;
    const key = rid ? `${r.status}|${r.action_type}|${rid}` : `id:${r.id}`;
    const g = groups.get(key);
    if (g) g.push(r); else groups.set(key, [r]);
  }
  const out: MergedRec<T>[] = [];
  for (const g of groups.values()) {
    g.sort((a, b) => saving(b) - saving(a) || b.updated_at.localeCompare(a.updated_at) || a.id - b.id);
    const [primary, ...rest] = g;
    const sources = [...new Set(g.map((r) => r.source))].sort(bySource);
    out.push({
      ...primary,
      merged: rest.map((r) => ({ id: r.id, source: r.source, rule: r.rule, est_monthly_saving: r.est_monthly_saving, confidence: r.confidence })),
      sources,
      merged_ids: g.map((r) => r.id),
    });
  }
  return out.sort((a, b) => saving(b) - saving(a) || b.updated_at.localeCompare(a.updated_at) || a.id - b.id);
}

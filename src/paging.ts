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

/** The 1-based page on which the row with this id sits in the ordered list, or null when it is not in the list. */
export function pageOf(rows: { id: number }[], id: number, pageSize: number): number | null {
  const i = rows.findIndex((r) => r.id === id);
  return i < 0 ? null : Math.floor(i / pageSize) + 1;
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

/**
 * The recommendations search box: "#123" or "123" is an id (the row itself or one merged into it), anything else
 * is matched against title, resource and resource name. An id query is exact: "12" does not match "#120".
 */
export function parseRecQuery(q: string): { id: number | null; text: string } {
  const t = q.trim();
  const m = /^#?(\d{1,12})$/.exec(t);
  return { id: m ? Number(m[1]) : null, text: t.toLowerCase() };
}

export function recMatches(r: { id: number; title: string | null; resource: string | null; resource_name: string | null }, q: { id: number | null; text: string }): boolean {
  if (!q.text) return true;
  if (q.id != null && r.id === q.id) return true;
  return [r.title, r.resource, r.resource_name].some((v) => String(v || "").toLowerCase().includes(q.text));
}

/**
 * ARN, path or prefixed id → the bare identifier every source can agree on: `arn:aws:rds:…:cluster:foo`,
 * `rds:foo`, `cluster:foo` and `foo` are all `foo`. The agent writes ARNs and `kind:id` forms, the rules use the
 * short Steampipe identifier; they must meet in one recommendation, one decision and one impact row.
 */
const KIND_PREFIX = /^(db|cluster|instance|volume|snapshot|function|log-group|rds|ec2|elasticache|lambda):/;
export function shortResourceId(resource: string | null | undefined): string | null {
  if (!resource) return null;
  const r = resource.trim();
  if (!r.startsWith("arn:")) return r.replace(KIND_PREFIX, "") || r;
  const tail = r.split(":").slice(5).join(":");
  const seg = tail.split("/").pop() || tail;
  return seg.replace(KIND_PREFIX, "") || r;
}

export interface RecLike { id: number; source: string; rule: string; resource: string | null; action_type: string; status: string; est_monthly_saving: number | null; confidence: number | null; updated_at: string }
export interface MergedRef { id: number; source: string; rule: string; est_monthly_saving: number | null; confidence: number | null }
export interface SystemRef { kind: "pool" | "rds_cluster" | "cache_group"; id: string; members: string[] }
export type MergedRec<T extends RecLike> = T & { merged: MergedRef[]; sources: string[]; merged_ids: number[]; system: SystemRef | null };
export type SystemOf = (resourceId: string) => { kind: SystemRef["kind"]; id: string } | null | undefined;

const saving = (r: { est_monthly_saving: number | null }) => (r.est_monthly_saving == null ? -Infinity : Number(r.est_monthly_saving));
const SOURCE_ORDER = ["rules", "agent"];
const bySource = (a: string, b: string) => (SOURCE_ORDER.indexOf(a) + 1 || 99) - (SOURCE_ORDER.indexOf(b) + 1 || 99) || a.localeCompare(b);

/**
 * Rows that propose the same action on the same resource (in the same status) become one entry: the one with the
 * highest saving estimate is primary, the others are listed under `merged`. Sorted by saving desc, nulls last.
 */
export function mergeRecommendations<T extends RecLike>(rows: T[], systemOf?: SystemOf): MergedRec<T>[] {
  const groups = new Map<string, T[]>();
  const systems = new Map<string, SystemRef>();
  for (const r of rows) {
    // Sources name the same thing differently (ARN, `rds:id`, bare id); merge on the bare id so they meet.
    const rid = shortResourceId(r.resource);
    // A member of an autoscaled pool, an RDS cluster or a cache group is decided with its system: one entry per (system, action).
    const sys = rid ? systemOf?.(rid) : null;
    const key = sys ? `${r.status}|${r.action_type}|${sys.kind}:${sys.id}` : rid ? `${r.status}|${r.action_type}|${rid}` : `id:${r.id}`;
    if (sys) {
      const s = systems.get(key) || { kind: sys.kind, id: sys.id, members: [] };
      if (rid && !s.members.includes(rid)) s.members.push(rid);
      systems.set(key, s);
    }
    const g = groups.get(key);
    if (g) g.push(r); else groups.set(key, [r]);
  }
  const out: MergedRec<T>[] = [];
  for (const [key, g] of groups) {
    g.sort((a, b) => saving(b) - saving(a) || b.updated_at.localeCompare(a.updated_at) || a.id - b.id);
    const [primary, ...rest] = g;
    const sources = [...new Set(g.map((r) => r.source))].sort(bySource);
    out.push({
      ...primary,
      merged: rest.map((r) => ({ id: r.id, source: r.source, rule: r.rule, est_monthly_saving: r.est_monthly_saving, confidence: r.confidence })),
      sources,
      merged_ids: g.map((r) => r.id),
      system: systems.get(key) ?? null,
    });
  }
  return out.sort((a, b) => saving(b) - saving(a) || b.updated_at.localeCompare(a.updated_at) || a.id - b.id);
}

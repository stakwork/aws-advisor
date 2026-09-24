/**
 * How recommendations relate through the resources they share.
 *
 * Conflicts: two live items (open, pending, approved, snoozed) proposing different actions on one resource
 * cannot both be worth doing ("stop this instance" and "move it to Graviton"); the list flags the pair and a
 * decision on one offers to close the other. Overlap: the "if all applied" total adds every claim, so such pairs
 * inflate it; the distinct total counts one claim per resource, the largest. Blocked-by: one item waits on
 * another (NAT attribution waits on flow logs); the link is a column, checked here for cycles.
 */
import { db } from "./db.js";
import { splitResourceList } from "./affected.js";
import { shortResourceId } from "./paging.js";

export const LIVE = ["open", "pending", "approved", "snoozed"] as const;
/** Actions that change or remove the resource: two of them on one resource are a conflict; a report-only pair is not. */
const CHANGES_RESOURCE = /stop|terminate|rightsize|resize|downsize|migrat|graviton|delete|release|modify|switch|set_|convert|upgrade|move|retire|reserv|buy/i;

export interface RecKeyed { id: number; resource: string | null; resource_name?: string | null; action_type: string; status: string; title?: string; est_monthly_saving?: number | null }

/** The bare ids an item touches: every entry of its resource column, ARNs and `kind:id` forms reduced. */
export function resourceKeys(rec: Pick<RecKeyed, "resource" | "resource_name">): string[] {
  return [...new Set(splitResourceList(rec.resource, rec.resource_name ?? null).map((r) => shortResourceId(r.id) || r.id).filter((k) => k && !/\s/.test(k)))];
}

export interface Conflict { id: number; action_type: string; status: string; title: string; est_monthly_saving: number | null; on: string }

/** For every row, the other live rows proposing a different resource-changing action on a resource it shares. */
export function findConflicts<T extends RecKeyed>(rows: T[]): Map<number, Conflict[]> {
  const byKey = new Map<string, T[]>();
  const keysOf = new Map<number, string[]>();
  for (const r of rows) {
    if (!(LIVE as readonly string[]).includes(r.status) || !CHANGES_RESOURCE.test(r.action_type)) continue;
    const keys = resourceKeys(r);
    keysOf.set(r.id, keys);
    for (const k of keys) { const g = byKey.get(k); if (g) g.push(r); else byKey.set(k, [r]); }
  }
  const out = new Map<number, Conflict[]>();
  for (const [id, keys] of keysOf) {
    const seen = new Set<number>();
    const list: Conflict[] = [];
    for (const k of keys) for (const o of byKey.get(k) || []) {
      if (o.id === id || seen.has(o.id)) continue;
      const me = rows.find((r) => r.id === id)!;
      if (o.action_type === me.action_type) continue;   // the same action twice merges; it is not a conflict
      seen.add(o.id);
      list.push({ id: o.id, action_type: o.action_type, status: o.status, title: o.title || "", est_monthly_saving: o.est_monthly_saving ?? null, on: k });
    }
    if (list.length) out.set(id, list.sort((a, b) => a.id - b.id));
  }
  return out;
}

/**
 * The claims added up once per resource: entries in saving order, each counted in full unless every resource it
 * names was already claimed by a larger entry. Entries with no resource always count.
 */
export function distinctSaving(entries: Pick<RecKeyed, "resource" | "resource_name" | "est_monthly_saving">[]): { total: number; distinct: number; overlap: number } {
  const sorted = [...entries].sort((a, b) => (Number(b.est_monthly_saving) || 0) - (Number(a.est_monthly_saving) || 0));
  const claimed = new Set<string>();
  let total = 0, distinct = 0;
  for (const e of sorted) {
    const v = Number(e.est_monthly_saving) || 0;
    total += v;
    const keys = resourceKeys(e);
    const fresh = keys.length === 0 || keys.some((k) => !claimed.has(k));
    if (fresh) distinct += v;
    for (const k of keys) claimed.add(k);
  }
  const r2 = (n: number) => Math.round(n * 100) / 100;
  return { total: r2(total), distinct: r2(distinct), overlap: r2(total - distinct) };
}

/** Would setting `blocker` as what `id` waits on close a loop? Walks the chain from the blocker up (bounded). */
export function makesCycle(id: number, blocker: number, blockedByOf: (id: number) => number | null): boolean {
  let cur: number | null = blocker;
  for (let i = 0; i < 50 && cur != null; i++) { if (cur === id) return true; cur = blockedByOf(cur); }
  return false;
}

export interface BlockerRef { id: number; title: string; status: string; follow_up: string | null; done: boolean }

const followUpOf = (progress: string | null): string | null => { try { return progress ? JSON.parse(progress).follow_up || null : null; } catch { return null; } };

/** What an item waits on, and the items waiting on it. */
export function blockerLinks(id: number, blockedBy: number | null): { blocker: BlockerRef | null; blocks: BlockerRef[] } {
  const ref = (r: any): BlockerRef => ({ id: r.id, title: r.title, status: r.status, follow_up: followUpOf(r.progress), done: r.status === "done" || r.status === "resolved" });
  const blocker = blockedBy ? (db.prepare("select id, title, status, progress from recommendations where id = ?").get(blockedBy) as any) : null;
  const blocks = db.prepare("select id, title, status, progress from recommendations where blocked_by = ? order by id").all(id) as any[];
  return { blocker: blocker ? ref(blocker) : null, blocks: blocks.map(ref) };
}

/** Blocker refs for many rows at once (the list): id → ref. */
export function blockersFor(ids: (number | null | undefined)[]): Map<number, BlockerRef> {
  const want = [...new Set(ids.filter((v): v is number => Number.isInteger(v)))];
  const out = new Map<number, BlockerRef>();
  if (!want.length) return out;
  for (const r of db.prepare(`select id, title, status, progress from recommendations where id in (${want.map(() => "?").join(",")})`).all(...want) as any[]) {
    out.set(r.id, { id: r.id, title: r.title, status: r.status, follow_up: followUpOf(r.progress), done: r.status === "done" || r.status === "resolved" });
  }
  return out;
}

/** The live rows, for conflict detection: everything not rejected, done or resolved, with what conflicts need. */
export function liveRows(): RecKeyed[] {
  return db.prepare(`select id, resource, resource_name, action_type, status, title, est_monthly_saving from recommendations where status in (${LIVE.map((s) => `'${s}'`).join(",")})`).all() as RecKeyed[];
}

/**
 * The system a resource belongs to, when a decision is really about the system: an autoscaled EC2 pool (its
 * controller replaces members), an RDS cluster, an ElastiCache replication group. Bare id → "kind:id".
 */
export function systemMap(): Map<string, { kind: "pool" | "rds_cluster" | "cache_group"; id: string }> {
  const out = new Map<string, { kind: "pool" | "rds_cluster" | "cache_group"; id: string }>();
  const rows = (sql: string) => { try { return db.prepare(sql).all() as { id: string; sys: string }[]; } catch { return []; } };
  for (const r of rows("select instance_id as id, pool as sys from inventory_ec2 where pool is not null and pool != ''")) out.set(r.id, { kind: "pool", id: r.sys });
  for (const r of rows("select db_instance_identifier as id, cluster as sys from inventory_rds where cluster is not null and cluster != ''")) out.set(r.id, { kind: "rds_cluster", id: r.sys });
  for (const r of rows("select cache_cluster_id as id, replication_group as sys from inventory_elasticache where replication_group is not null and replication_group != ''")) out.set(r.id, { kind: "cache_group", id: r.sys });
  return out;
}

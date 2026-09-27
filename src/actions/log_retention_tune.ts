/**
 * Log group retention shortened where nobody queries, and only where the executor set the retention itself.
 *
 * The log_retention action puts a long default (90 days) on groups that had none, because at that point nothing
 * is known about who reads them. This action learns: every pass records the Logs Insights query history
 * (DescribeQueries, which only keeps recent queries, so the history accumulates in `log_query_history`) and the
 * date recording began. Once that history covers ACT_LOG_QUIET_DAYS (90), a group whose retention is exactly
 * what a verified log_retention row set, that nobody queried in that window and that feeds no subscription
 * filter (a subscription is a reader) drops to ACT_LOG_QUIET_RETENTION_DAYS (30). A retention a person set, or
 * one the owner changed after the executor set it, is never touched. Lowering purges events past the new
 * retention, which the row says; the revert puts the old retention back for what is left.
 */
import { CloudWatchLogsClient, DescribeLogGroupsCommand, DescribeQueriesCommand, DescribeSubscriptionFiltersCommand, ListTagsForResourceCommand, PutRetentionPolicyCommand } from "@aws-sdk/client-cloudwatch-logs";
import { db, getJsonSetting, setSetting } from "../db.js";
import { config } from "../config.js";
import type { ActionModule, Creds, Proposal } from "../executor.js";
import { LOG_STORAGE_USD_GB_MONTH, snapRetention } from "./log_retention.js";

export const KIND = "log_retention_tune" as const;
export const HISTORY_SINCE_KEY = "act:log_query_history_since";
const MAX_QUERY_PAGES = 5;
const MAX_PER_PLAN = 40;

db.exec(`create table if not exists log_query_history (
  query_id text primary key, log_group text, status text, create_time text, region text
);
create index if not exists log_query_history_group on log_query_history(log_group, create_time)`);

export interface QuietInput { historySince: string | null; quietDays: number; lastQueryAt: string | null; hasSubscription: boolean; now?: Date }
export interface QuietVerdict { quiet: boolean; reason: string; days_to_go: number }

/** Quiet only when the recorded history is long enough, no query fell inside the window and nothing subscribes to the group. Pure. */
export function quietVerdict(i: QuietInput): QuietVerdict {
  const now = i.now ?? new Date();
  const windowStart = new Date(now.getTime() - i.quietDays * 86400000);
  if (!i.historySince) return { quiet: false, reason: "no query history recorded yet", days_to_go: i.quietDays };
  const since = new Date(i.historySince);
  if (since.getTime() > windowStart.getTime()) {
    const toGo = Math.ceil((since.getTime() - windowStart.getTime()) / 86400000);
    return { quiet: false, reason: `query history since ${i.historySince.slice(0, 10)}, ${toGo} day(s) to go before ${i.quietDays} days are covered`, days_to_go: toGo };
  }
  if (i.hasSubscription) return { quiet: false, reason: "a subscription filter reads the group", days_to_go: 0 };
  if (i.lastQueryAt && new Date(i.lastQueryAt).getTime() >= windowStart.getTime()) return { quiet: false, reason: `queried ${i.lastQueryAt.slice(0, 16).replace("T", " ")} UTC`, days_to_go: 0 };
  return { quiet: true, reason: `no Logs Insights query in ${i.quietDays} days of recorded history, no subscription filter`, days_to_go: 0 };
}

/** Records the recent Logs Insights queries of a region; returns how many were new. */
async function recordQueries(logs: CloudWatchLogsClient, region: string): Promise<number> {
  const ins = db.prepare("insert or ignore into log_query_history(query_id, log_group, status, create_time, region) values (?, ?, ?, ?, ?)");
  let n = 0; let nextToken: string | undefined; let pages = 0;
  do {
    const r = await logs.send(new DescribeQueriesCommand({ maxResults: 1000, nextToken }));
    for (const q of r.queries ?? []) {
      if (!q.queryId) continue;
      const at = q.createTime ? new Date(q.createTime).toISOString() : new Date().toISOString();
      if (ins.run(q.queryId, q.logGroupName ?? null, q.status ?? null, at, region).changes) n++;
    }
    nextToken = r.nextToken; pages++;
  } while (nextToken && pages < MAX_QUERY_PAGES);
  return n;
}

/** The newest query the history holds for a group (a query over several groups records the one DescribeQueries names). */
export function lastQueryAt(group: string): string | null {
  return (db.prepare("select max(create_time) as at from log_query_history where log_group = ?").get(group) as { at: string | null }).at ?? null;
}

interface Candidate { name: string; region: string; retention_days: number; stored_bytes: number; ingest_bytes_day: number | null; set_by: { id: number; days: number } }

/** Groups whose current retention is exactly what a verified log_retention row set and above the target. */
export function candidates(target: number): Candidate[] {
  const rows = db.prepare(`select g.name, g.region, g.retention_days, g.stored_bytes, g.ingest_bytes_day, a.id as action_id, a.after_json
    from log_groups g join actions a on a.kind = 'log_retention' and a.resource = g.name and a.status = 'verified'
    where g.retention_days is not null and g.retention_days > ? order by g.stored_bytes desc`).all(target) as any[];
  const out: Candidate[] = []; const seen = new Set<string>();
  for (const r of rows) {
    if (seen.has(r.name)) continue;
    let setDays: number | null = null;
    try { setDays = Number(JSON.parse(r.after_json || "{}").retention_days); } catch { /* malformed row */ }
    if (setDays == null || !Number.isFinite(setDays) || setDays !== Number(r.retention_days)) continue;
    seen.add(r.name);
    out.push({ name: r.name, region: r.region, retention_days: Number(r.retention_days), stored_bytes: Number(r.stored_bytes || 0), ingest_bytes_day: r.ingest_bytes_day != null ? Number(r.ingest_bytes_day) : null, set_by: { id: Number(r.action_id), days: setDays } });
  }
  return out;
}

export const logRetentionTuneAction: ActionModule = {
  kind: KIND,
  label: "Log retention shortened where nobody queries",

  async plan(creds, log) {
    const proposals: Proposal[] = []; const notes: string[] = [];
    const quietDays = Math.max(30, Math.round(config.actLogQuietDays));
    const target = snapRetention(config.actLogQuietRetentionDays);
    const cands = candidates(target);
    const regions = [...new Set([creds.region, ...cands.map((c) => c.region).filter(Boolean)])];
    let since = getJsonSetting<string | null>(HISTORY_SINCE_KEY, null);
    if (!since) { since = new Date().toISOString(); setSetting(HISTORY_SINCE_KEY, JSON.stringify(since)); }
    let recorded = 0;
    for (const region of regions) {
      const logs = new CloudWatchLogsClient({ region, credentials: creds.read });
      try { recorded += await recordQueries(logs, region); }
      catch (e: any) { const m = String(e?.message || e); notes.push(`${region}: DescribeQueries: ${m.slice(0, 160)}`); log(`${region}: DescribeQueries: ${m}`); }
      finally { logs.destroy(); }
    }
    if (recorded) log(`${recorded} new Logs Insights query(ies) recorded`);
    if (!cands.length) { notes.push(`no group whose retention the executor set is above ${target} days`); return { proposals, notes }; }
    const probe = quietVerdict({ historySince: since, quietDays, lastQueryAt: null, hasSubscription: false });
    if (!probe.quiet) { notes.push(`${cands.length} candidate group(s) wait: ${probe.reason}`); return { proposals, notes }; }
    const byRegion = new Map<string, Candidate[]>();
    for (const c of cands.slice(0, MAX_PER_PLAN)) { const region = c.region || creds.region; if (!byRegion.has(region)) byRegion.set(region, []); byRegion.get(region)!.push(c); }
    for (const [region, list] of byRegion) {
      const logs = new CloudWatchLogsClient({ region, credentials: creds.read });
      try {
        for (const c of list) {
          const skip = (why: string) => { notes.push(`${c.name}: ${why}`); log(`${c.name}: ${why}`); };
          const g = (await logs.send(new DescribeLogGroupsCommand({ logGroupNamePrefix: c.name, limit: 5 }))).logGroups?.find((x) => x.logGroupName === c.name);
          if (!g) { skip("no longer exists"); continue; }
          if (g.retentionInDays !== c.retention_days) { skip(`retention reads ${g.retentionInDays ?? "none"} now, not the ${c.retention_days} the executor set: someone changed it, left alone`); continue; }
          if (g.arn) {
            try { const tags = (await logs.send(new ListTagsForResourceCommand({ resourceArn: g.arn.replace(/:\*$/, "") }))).tags ?? {}; if ("advisor:hands-off" in tags) { skip("tagged advisor:hands-off"); continue; } }
            catch { /* tags unreadable: the policy's Deny still protects a tagged group */ }
          }
          let hasSubscription = false;
          try { hasSubscription = ((await logs.send(new DescribeSubscriptionFiltersCommand({ logGroupName: c.name, limit: 1 }))).subscriptionFilters?.length ?? 0) > 0; }
          catch (e: any) { skip(`DescribeSubscriptionFilters: ${String(e?.message || e).slice(0, 120)}; not lowered without knowing who reads it`); continue; }
          const last = lastQueryAt(c.name);
          const v = quietVerdict({ historySince: since, quietDays, lastQueryAt: last, hasSubscription });
          if (!v.quiet) { skip(v.reason); continue; }
          const stored = g.storedBytes ?? c.stored_bytes;
          const gb = stored / 1e9;
          proposals.push({
            kind: KIND, resource: c.name, resource_name: c.name, region,
            dedupe: `${KIND}:${c.name}:${target}`,
            title: `${c.name}: retention ${c.retention_days} → ${target} days (${gb.toFixed(2)} GB stored, unqueried for ${quietDays} days)`,
            reason: `the executor set ${c.retention_days} days (auto-action #${c.set_by.id}) when nothing was known about who reads the group; ${v.reason} (history since ${since.slice(0, 10)}). ${gb.toFixed(2)} GB stored${c.ingest_bytes_day != null ? `, ${(c.ingest_bytes_day / 1e6).toFixed(1)} MB/day ingested` : ""}; events older than ${target} days are purged from then on.`,
            before: { retention_days: c.retention_days }, after: { retention_days: target },
            facts: { set_by_action_id: c.set_by.id, history_since: since, last_query_at: last, has_subscription: hasSubscription, stored_bytes: stored, ingest_bytes_day: c.ingest_bytes_day },
            rollback: `PutRetentionPolicy back to ${c.retention_days} days (events already purged do not come back)`,
            est_usd_month: c.ingest_bytes_day != null && c.ingest_bytes_day > 0 ? Math.round(Math.max(0, gb - (c.ingest_bytes_day * target) / 1e9) * LOG_STORAGE_USD_GB_MONTH * 100) / 100 : null,
          });
        }
      } finally { logs.destroy(); }
    }
    return { proposals, notes };
  },

  async apply(p, creds) {
    const logs = new CloudWatchLogsClient({ region: p.region, credentials: creds.act() });
    try { await logs.send(new PutRetentionPolicyCommand({ logGroupName: p.resource, retentionInDays: Number(p.after.retention_days) })); return `PutRetentionPolicy: ${p.before.retention_days} → ${p.after.retention_days} days`; }
    finally { logs.destroy(); }
  },

  async verify(p, creds) {
    const logs = new CloudWatchLogsClient({ region: p.region, credentials: creds.read });
    try {
      const g = (await logs.send(new DescribeLogGroupsCommand({ logGroupNamePrefix: p.resource, limit: 5 }))).logGroups?.find((x) => x.logGroupName === p.resource);
      if (!g) return { ok: false, note: "group not found on read-back" };
      return g.retentionInDays === Number(p.after.retention_days) ? { ok: true, note: `read back: ${g.retentionInDays} days` } : { ok: false, note: `retention reads ${g.retentionInDays ?? "none"}` };
    } finally { logs.destroy(); }
  },

  async revert(p, creds) {
    const logs = new CloudWatchLogsClient({ region: p.region, credentials: creds.act() });
    try { await logs.send(new PutRetentionPolicyCommand({ logGroupName: p.resource, retentionInDays: Number(p.before.retention_days) })); return `retention back to ${p.before.retention_days} days; events purged meanwhile are gone`; }
    finally { logs.destroy(); }
  },
};

/**
 * CloudWatch log groups with no retention keep everything forever at 0.03 USD per GB-month. The executor puts
 * the configured retention (Settings › Auto-actions, 90 days by default) on every group that has none, and
 * never lowers a retention someone set. This is the one "auto" action in the playbooks that is not fully
 * reversible: lifting the policy afterwards keeps what is left, but the events already purged do not come back,
 * which is why the default is a long one and the Sphinx message says what it did. An approved recommendation
 * of the log_group_no_retention rule counts as the go-ahead for its group whatever its size.
 */
import { CloudWatchLogsClient, DeleteRetentionPolicyCommand, DescribeLogGroupsCommand, ListTagsForResourceCommand, PutRetentionPolicyCommand } from "@aws-sdk/client-cloudwatch-logs";
import { db } from "../db.js";
import { config } from "../config.js";
import { approvedFor, type ActionModule, type Creds, type Proposal } from "../executor.js";

export const KIND = "log_retention" as const;
export const LOG_STORAGE_USD_GB_MONTH = 0.03;
/** The values CloudWatch Logs accepts. */
export const RETENTION_DAYS = [1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653];
/** The accepted value at or above the requested one. */
export const snapRetention = (days: number) => RETENTION_DAYS.find((d) => d >= days) ?? RETENTION_DAYS[RETENTION_DAYS.length - 1];
/** Groups under this much stored are left alone unless a recommendation was approved: not worth a row. */
export const MIN_STORED_BYTES = 100 * 1024 * 1024;
const MAX_PER_PLAN = 40;

export const logRetentionAction: ActionModule = {
  kind: KIND,
  label: "Log groups with no retention get one",

  async plan(creds, log) {
    const proposals: Proposal[] = []; const notes: string[] = [];
    const days = snapRetention(config.actLogRetentionDays);
    const rows = db.prepare("select name, region, stored_bytes, ingest_bytes_day from log_groups where retention_days is null order by stored_bytes desc").all() as { name: string; region: string; stored_bytes: number; ingest_bytes_day: number | null }[];
    if (!rows.length) { notes.push("every log group has a retention policy"); return { proposals, notes }; }
    const cands = rows.map((r) => ({ ...r, approved: approvedFor(["log_group_no_retention"], r.name) })).filter((r) => r.stored_bytes >= MIN_STORED_BYTES || r.approved);
    const small = rows.length - cands.length;
    if (small) notes.push(`${small} group(s) with no retention under 100 MB left alone`);
    const byRegion = new Map<string, typeof cands>();
    for (const c of cands.slice(0, MAX_PER_PLAN)) { if (!byRegion.has(c.region)) byRegion.set(c.region, []); byRegion.get(c.region)!.push(c); }
    for (const [region, list] of byRegion) {
      const logs = new CloudWatchLogsClient({ region, credentials: creds.read });
      try {
        for (const c of list) {
          const skip = (why: string) => { notes.push(`${c.name}: ${why}`); log(`${c.name}: ${why}`); };
          const g = (await logs.send(new DescribeLogGroupsCommand({ logGroupNamePrefix: c.name, limit: 5 }))).logGroups?.find((x) => x.logGroupName === c.name);
          if (!g) { skip("no longer exists"); continue; }
          if (g.retentionInDays != null) { skip(`has ${g.retentionInDays} days now`); continue; }
          if (g.arn) {
            try { const tags = (await logs.send(new ListTagsForResourceCommand({ resourceArn: g.arn.replace(/:\*$/, "") }))).tags ?? {}; if ("advisor:hands-off" in tags) { skip("tagged advisor:hands-off"); continue; } }
            catch { /* tags unreadable: the policy's Deny still protects a tagged group */ }
          }
          const gb = (g.storedBytes ?? c.stored_bytes) / 1e9;
          proposals.push({
            kind: KIND, resource: c.name, resource_name: c.name, region,
            dedupe: `${KIND}:${c.name}:${days}`,
            title: `${c.name}: retention none → ${days} days (${gb.toFixed(2)} GB stored)`,
            reason: `no retention policy, ${gb.toFixed(2)} GB stored${c.ingest_bytes_day != null ? `, ${(c.ingest_bytes_day / 1e6).toFixed(1)} MB/day ingested` : ""}; events older than ${days} days are purged from then on, storage stops growing past ${days} days of ingestion.${c.approved ? ` Approved as recommendation #${c.approved.id}${c.approved.decided_by ? ` by ${c.approved.decided_by}` : ""}.` : ""}`,
            before: { retention_days: null }, after: { retention_days: days },
            facts: { stored_bytes: g.storedBytes ?? c.stored_bytes, ingest_bytes_day: c.ingest_bytes_day, recommendation_id: c.approved?.id ?? null },
            rollback: "remove the retention policy (what was already purged does not come back)",
            est_usd_month: c.ingest_bytes_day != null && c.ingest_bytes_day > 0 ? Math.round(Math.max(0, gb - (c.ingest_bytes_day * days) / 1e9) * LOG_STORAGE_USD_GB_MONTH * 100) / 100 : null,
          });
        }
      } finally { logs.destroy(); }
    }
    return { proposals, notes };
  },

  async apply(p, creds) {
    const logs = new CloudWatchLogsClient({ region: p.region, credentials: creds.act() });
    try { await logs.send(new PutRetentionPolicyCommand({ logGroupName: p.resource, retentionInDays: Number(p.after.retention_days) })); return `PutRetentionPolicy: ${p.after.retention_days} days`; }
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
    try { await logs.send(new DeleteRetentionPolicyCommand({ logGroupName: p.resource })); return "retention policy removed; events purged meanwhile are gone"; }
    finally { logs.destroy(); }
  },
};

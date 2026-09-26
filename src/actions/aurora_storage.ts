/**
 * Aurora cluster storage type, once a person approved the recommendation. The review's aurora_storage_tier rule
 * (and the agent) say when I/O-Optimized pays for a cluster or has stopped paying; the recommendation is tier
 * approve because the switch changes the shape of the bill. Approving it is the decision; the executor makes the
 * change: ModifyDBCluster with the new storage type, applied immediately, online, no failover. AWS allows a
 * switch to I/O-Optimized once every 30 days (DescribeDBClusters says when the next one is allowed) and back to
 * Standard at any time. The estimate is the approved recommendation's own figure; every approved recommendation
 * for the cluster is marked done once the change is read back.
 */
import { DescribeDBClustersCommand, ModifyDBClusterCommand, RDSClient, type DBCluster } from "@aws-sdk/client-rds";
import { db } from "../db.js";
import { approvedRecs, markRecommendationsDone, type ActionModule, type Creds, type Proposal } from "../executor.js";

export const KIND = "aurora_storage" as const;
export const ACTION_TYPES = ["aurora_set_storage_iopt", "aurora_set_storage_standard"];
export const STORAGE_OF: Record<string, string> = { aurora_set_storage_iopt: "aurora-iopt1", aurora_set_storage_standard: "aurora" };
export const LABEL: Record<string, string> = { "aurora-iopt1": "I/O-Optimized", aurora: "Standard" };
const label = (t: string | undefined) => LABEL[t || ""] || t || "?";

interface Target { cluster: string; target: string; region: string; recs: ReturnType<typeof approvedRecs>; conflict: string | null }

/** One target per cluster: the newest approval wins; older approvals for the same cluster ride along and close with it. */
export function targetsFrom(recs: ReturnType<typeof approvedRecs>, defaultRegion: string): Target[] {
  const byCluster = new Map<string, Target>();
  for (const r of recs) {
    const target = STORAGE_OF[r.action_type]; if (!target) continue;
    const t = byCluster.get(r.resource);
    if (!t) { byCluster.set(r.resource, { cluster: r.resource, target, region: String(r.evidence?.region || defaultRegion), recs: [r], conflict: null }); continue; }
    if (t.target === target) t.recs.push(r);
    else t.conflict = `#${r.id} (older) asks for ${label(target)}; the newer approval #${t.recs[0].id} for ${label(t.target)} wins`;
  }
  return [...byCluster.values()];
}

async function describe(rds: RDSClient, cluster: string): Promise<DBCluster | null> {
  try { return (await rds.send(new DescribeDBClustersCommand({ DBClusterIdentifier: cluster }))).DBClusters?.[0] ?? null; }
  catch (e: any) { if (/DBClusterNotFound/i.test(String(e?.name || e?.message))) return null; throw e; }
}

export const auroraStorageAction: ActionModule = {
  kind: KIND,
  label: "Aurora storage type, once approved",

  async plan(creds, log) {
    const proposals: Proposal[] = []; const notes: string[] = [];
    const targets = targetsFrom(approvedRecs(ACTION_TYPES), creds.region);
    if (!targets.length) { notes.push("no approved recommendation to change an Aurora cluster's storage type"); return { proposals, notes }; }
    for (const t of targets) {
      const skip = (why: string) => { notes.push(`${t.cluster}: ${why}`); log(`${t.cluster}: ${why}`); };
      if (t.conflict) notes.push(`${t.cluster}: ${t.conflict}`);
      const rds = new RDSClient({ region: t.region, credentials: creds.read });
      try {
        const c = await describe(rds, t.cluster);
        if (!c) { skip("no such cluster (DescribeDBClusters)"); continue; }
        if (c.TagList?.some((x) => x.Key === "advisor:hands-off")) { skip("tagged advisor:hands-off"); continue; }
        const current = c.StorageType || "aurora";
        if (current === t.target) {
          const n = markRecommendationsDone(t.recs.map((r) => r.id), `already on ${label(current)} storage when the executor checked (done by hand); recommendation closed`);
          skip(`already on ${label(current)} storage; ${n} approved recommendation(s) marked done`); continue;
        }
        if (c.Status !== "available") { skip(`cluster is ${c.Status}, not available`); continue; }
        const next = (c as any).IOOptimizedNextAllowedModificationTime as Date | undefined;
        if (t.target === "aurora-iopt1" && next && new Date(next).getTime() > Date.now()) { skip(`a switch to I/O-Optimized is allowed again on ${new Date(next).toISOString().slice(0, 10)} (once every 30 days)`); continue; }
        const lead = t.recs[0];
        const inv = db.prepare("select count(*) as n from inventory_rds where cluster = ? and gone = 0").get(t.cluster) as { n: number };
        const members = c.DBClusterMembers?.length ?? inv.n;
        proposals.push({
          kind: KIND, resource: t.cluster, resource_name: t.cluster, region: t.region,
          dedupe: `${KIND}:${t.cluster}:${t.target}`,
          title: `${t.cluster}: storage ${label(current)} → ${label(t.target)} (${c.Engine || "aurora"}, ${members} instance${members === 1 ? "" : "s"})`,
          reason: `${lead.title}. Approved as recommendation #${lead.id}${lead.decided_by ? ` by ${lead.decided_by}` : ""}${t.recs.length > 1 ? ` (and #${t.recs.slice(1).map((r) => r.id).join(", #")})` : ""}. ModifyDBCluster applied immediately: online, no failover, the bill changes from the next hour.${t.target === "aurora-iopt1" ? " Switching back to Standard is allowed at any time; another switch to I/O-Optimized only after 30 days." : " Switching back to I/O-Optimized is allowed once every 30 days."}`,
          before: { storage_type: current }, after: { storage_type: t.target },
          facts: { recommendation_id: lead.id, recommendation_ids: t.recs.map((r) => r.id), engine: c.Engine, engine_version: c.EngineVersion, members, cluster_arn: c.DBClusterArn, allocated_gb: c.AllocatedStorage ?? null },
          rollback: `set the storage type back to ${label(current)}${current === "aurora-iopt1" ? " (allowed once every 30 days)" : ""}`,
          est_usd_month: lead.est_monthly_saving,
        });
      } catch (e: any) { skip(String(e?.message || e).slice(0, 200)); }
      finally { rds.destroy(); }
    }
    return { proposals, notes };
  },

  async apply(p, creds) {
    const rds = new RDSClient({ region: p.region, credentials: creds.act() });
    try {
      const r = await rds.send(new ModifyDBClusterCommand({ DBClusterIdentifier: p.resource, StorageType: String(p.after.storage_type), ApplyImmediately: true }));
      return `ModifyDBCluster: storage ${label(String(p.before.storage_type))} → ${label(String(p.after.storage_type))}, cluster ${r.DBCluster?.Status || "modifying"}`;
    } finally { rds.destroy(); }
  },

  async verify(p, creds) {
    const rds = new RDSClient({ region: p.region, credentials: creds.read });
    try {
      const c = await describe(rds, p.resource);
      if (!c) return { ok: false, note: "cluster not found on read-back" };
      const want = String(p.after.storage_type);
      if ((c.StorageType || "aurora") === want) return c.Status === "available" ? { ok: true, note: `read back: ${label(want)} storage, cluster available` } : { ok: null, note: `storage reads ${label(want)}, cluster ${c.Status}` };
      if (c.Status !== "available") return { ok: null, note: `cluster ${c.Status}, storage still reads ${label(c.StorageType)}` };
      return { ok: false, note: `storage reads ${label(c.StorageType)}` };
    } finally { rds.destroy(); }
  },

  async revert(p, creds) {
    const rds = new RDSClient({ region: p.region, credentials: creds.act() });
    try {
      await rds.send(new ModifyDBClusterCommand({ DBClusterIdentifier: p.resource, StorageType: String(p.before.storage_type), ApplyImmediately: true }));
      return `storage back to ${label(String(p.before.storage_type))}`;
    } catch (e: any) {
      if (/30 days|IOOptimized|not allowed/i.test(String(e?.message || e))) throw new Error(`RDS refuses another switch to I/O-Optimized within 30 days of the last one: ${String(e?.message || e).slice(0, 160)}`);
      throw e;
    } finally { rds.destroy(); }
  },
};

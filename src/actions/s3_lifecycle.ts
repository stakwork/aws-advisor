/**
 * S3 lifecycle rules, once a person approved them. The usage analysis (src/s3_usage.ts) proposes the rules that
 * fit a bucket and files them as a tier-approve recommendation (review_s3_lifecycle) whose evidence carries the
 * exact rule JSON: transitions carry minimum-storage and retrieval charges, so a human confirms. Approving it is
 * the decision; the executor puts the rules on the bucket, merged with the rules already there (an existing rule
 * with the same id is replaced, every other one is kept as is). The revert restores the previous configuration
 * exactly; objects a transition already moved stay in their class (a lifecycle rule never moves them back).
 */
import { DeleteBucketLifecycleCommand, GetBucketLifecycleConfigurationCommand, GetBucketTaggingCommand, PutBucketLifecycleConfigurationCommand, S3Client, type LifecycleRule } from "@aws-sdk/client-s3";
import { db } from "../db.js";
import { approvedRecs, markRecommendationsDone, type ActionModule, type Creds, type Proposal } from "../executor.js";

export const KIND = "s3_lifecycle" as const;
export const RULE = "review_s3_lifecycle";

/** The existing rules with ours merged in: same id replaces, the rest is kept in order, ours appended. */
export function mergeRules(existing: LifecycleRule[], add: LifecycleRule[]): LifecycleRule[] {
  const ids = new Set(add.map((r) => r.ID));
  return [...existing.filter((r) => !ids.has(r.ID)), ...add];
}

async function currentRules(s3: S3Client, bucket: string): Promise<LifecycleRule[]> {
  try { return (await s3.send(new GetBucketLifecycleConfigurationCommand({ Bucket: bucket }))).Rules ?? []; }
  catch (e: any) { if (/NoSuchLifecycleConfiguration/i.test(String(e?.name || e?.message))) return []; throw e; }
}

async function handsOff(s3: S3Client, bucket: string): Promise<boolean> {
  try { return ((await s3.send(new GetBucketTaggingCommand({ Bucket: bucket }))).TagSet ?? []).some((t) => t.Key === "advisor:hands-off"); }
  catch { return false; }
}

const ruleId = (r: LifecycleRule) => r.ID || "(no id)";

export const s3LifecycleAction: ActionModule = {
  kind: KIND,
  label: "S3 lifecycle rules, once approved",

  async plan(creds, log) {
    const proposals: Proposal[] = []; const notes: string[] = [];
    const recs = approvedRecs([], { rules: [RULE] });
    if (!recs.length) { notes.push("no approved lifecycle recommendation (Inventory › S3 proposes them; approving one is the go-ahead)"); return { proposals, notes }; }
    const seen = new Set<string>();
    for (const rec of recs) {
      const bucket = rec.resource;
      if (seen.has(bucket)) continue; seen.add(bucket);
      const skip = (why: string) => { notes.push(`${bucket}: ${why}`); log(`${bucket}: ${why}`); };
      const add = (Array.isArray(rec.evidence?.rules) ? rec.evidence.rules : []).map((r: any) => r?.rule).filter((r: any) => r && typeof r === "object" && r.ID) as LifecycleRule[];
      if (!add.length) { skip(`recommendation #${rec.id} carries no rule JSON`); continue; }
      const inv = db.prepare("select region, total_gb, gone from inventory_s3 where name = ?").get(bucket) as { region: string | null; total_gb: number | null; gone: number } | undefined;
      if (inv?.gone) { skip("bucket is gone from the inventory"); continue; }
      const region = inv?.region || creds.region;
      const s3 = new S3Client({ region, credentials: creds.read });
      try {
        if (await handsOff(s3, bucket)) { skip("tagged advisor:hands-off"); continue; }
        const existing = await currentRules(s3, bucket);
        const missing = add.filter((r) => !existing.some((e) => e.ID === r.ID && e.Status === "Enabled"));
        if (!missing.length) { markRecommendationsDone([rec.id], "every rule was already on the bucket when the executor checked (done by hand); recommendation closed"); skip(`every rule of recommendation #${rec.id} is already on the bucket; marked done`); continue; }
        const merged = mergeRules(existing, add);
        proposals.push({
          kind: KIND, resource: bucket, resource_name: bucket, region,
          dedupe: `${KIND}:${bucket}:${add.map(ruleId).sort().join(",")}`,
          title: `${bucket}: lifecycle ${add.map((r) => ruleId(r).replace(/^aws-advisor-/, "")).join(", ")}${inv?.total_gb != null ? ` (${inv.total_gb.toFixed(1)} GB)` : ""}`,
          reason: `${rec.title}. Approved as recommendation #${rec.id}${rec.decided_by ? ` by ${rec.decided_by}` : ""}. ${existing.length ? `${existing.length} existing rule(s) kept as they are (${existing.map(ruleId).join(", ")}). ` : ""}Transitions take effect from the next lifecycle run (within a day); a transition carries the class's minimum-storage and retrieval terms.`,
          before: { rule_ids: existing.map(ruleId) }, after: { rule_ids: merged.map(ruleId) },
          facts: { recommendation_id: rec.id, before_rules: existing, add_rules: add, total_gb: inv?.total_gb ?? null },
          rollback: existing.length ? "restore the previous lifecycle configuration exactly (objects already transitioned stay in their class)" : "delete the lifecycle configuration (objects already transitioned stay in their class)",
          est_usd_month: rec.est_monthly_saving,
        });
      } catch (e: any) { skip(String(e?.message || e).slice(0, 200)); }
      finally { s3.destroy(); }
    }
    return { proposals, notes };
  },

  async apply(p, creds) {
    const s3 = new S3Client({ region: p.region, credentials: creds.act() });
    try {
      const existing = await currentRules(s3, p.resource);
      const rules = mergeRules(existing, (p.facts.add_rules as LifecycleRule[]) || []);
      await s3.send(new PutBucketLifecycleConfigurationCommand({ Bucket: p.resource, LifecycleConfiguration: { Rules: rules } }));
      return `PutBucketLifecycleConfiguration: ${rules.length} rule(s) (${rules.map(ruleId).join(", ")})`;
    } finally { s3.destroy(); }
  },

  async verify(p, creds) {
    const s3 = new S3Client({ region: p.region, credentials: creds.read });
    try {
      const now = await currentRules(s3, p.resource);
      const want = ((p.facts.add_rules as LifecycleRule[]) || []).map(ruleId);
      const missing = want.filter((id) => !now.some((r) => r.ID === id && r.Status === "Enabled"));
      return missing.length ? { ok: false, note: `rule(s) not on the bucket: ${missing.join(", ")}` } : { ok: true, note: `read back: ${want.join(", ")} enabled` };
    } finally { s3.destroy(); }
  },

  async revert(p, creds) {
    const s3 = new S3Client({ region: p.region, credentials: creds.act() });
    try {
      const before = (p.facts.before_rules as LifecycleRule[]) || [];
      if (!before.length) { await s3.send(new DeleteBucketLifecycleCommand({ Bucket: p.resource })); return "lifecycle configuration deleted; objects already transitioned stay in their class"; }
      await s3.send(new PutBucketLifecycleConfigurationCommand({ Bucket: p.resource, LifecycleConfiguration: { Rules: before } }));
      return `previous ${before.length} rule(s) restored; objects already transitioned stay in their class`;
    } finally { s3.destroy(); }
  },
};

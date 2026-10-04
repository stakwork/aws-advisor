/**
 * Incomplete multipart uploads aborted on every bucket. A multipart upload that never completed keeps its parts
 * billed as Standard storage, invisible to any listing, forever: nothing reads them, nothing lists them, only the
 * bill counts them. The executor puts one lifecycle rule on every bucket that has none covering the whole bucket:
 * abort uploads not completed within ACT_MULTIPART_DAYS (7). The rule id is the one the usage analysis
 * (src/s3_usage.ts) proposes inside its approval-gated lifecycle recommendation, `aws-advisor-abort-incomplete-multipart`,
 * so the two never fight: the same id replaces itself, and once this action has run that part of the
 * recommendation is moot (its transitions still need the approval). Existing rules are kept as they are.
 *
 * Risk-free by construction: a completed object is never touched, a transition is never added, and an upload that
 * really is still in progress past the window is the one thing aborted, hence the setting's help says to keep it
 * longer than the slowest upload. Revert puts the previous configuration back; a bucket that had none gets the
 * rule back Disabled, because S3 refuses an empty configuration and the actuator role may not delete one.
 */
import { GetBucketLifecycleConfigurationCommand, GetBucketLocationCommand, GetBucketTaggingCommand, PutBucketLifecycleConfigurationCommand, S3Client, type LifecycleRule } from "@aws-sdk/client-s3";
import { db } from "../db.js";
import { config } from "../config.js";
import type { ActionModule, Creds, Proposal } from "../executor.js";
import { mergeRules } from "./s3_lifecycle.js";

export const KIND = "s3_multipart_abort" as const;
export const RULE_ID = "aws-advisor-abort-incomplete-multipart";
export const S3_STANDARD_USD_GB_MONTH = 0.023;
const MAX_PER_PLAN = 100;

/** The rule this action puts on a bucket. */
export const abortRule = (days: number, status: "Enabled" | "Disabled" = "Enabled"): LifecycleRule => ({ ID: RULE_ID, Status: status, Filter: { Prefix: "" }, AbortIncompleteMultipartUpload: { DaysAfterInitiation: Math.max(1, Math.round(days)) } });

/** A rule covers the whole bucket when it has no filter, an empty prefix filter, or the legacy empty Prefix. */
export function coversWholeBucket(r: LifecycleRule): boolean {
  if (r.Prefix != null && r.Prefix !== "") return false;
  const f = r.Filter;
  if (!f) return true;
  if (f.Prefix != null && f.Prefix !== "") return false;
  if (f.Tag || f.ObjectSizeGreaterThan != null || f.ObjectSizeLessThan != null) return false;
  if (f.And) {
    if (f.And.Prefix != null && f.And.Prefix !== "") return false;
    if (f.And.Tags?.length || f.And.ObjectSizeGreaterThan != null || f.And.ObjectSizeLessThan != null) return false;
  }
  return true;
}

/** The enabled whole-bucket abort rule already there, if any: nothing to add then. */
export function existingAbort(rules: LifecycleRule[]): { id: string; days: number } | null {
  for (const r of rules) {
    const d = r.AbortIncompleteMultipartUpload?.DaysAfterInitiation;
    if (d != null && r.Status === "Enabled" && coversWholeBucket(r)) return { id: r.ID || "(no id)", days: d };
  }
  return null;
}

/** Incomplete parts are billed as Standard: the estimate when the bytes are known, else null. Pure. */
export const abortSaving = (bytes: number | null | undefined) => (bytes != null && bytes > 0 ? Math.round((bytes / 1e9) * S3_STANDARD_USD_GB_MONTH * 100) / 100 : null);

async function currentRules(s3: S3Client, bucket: string): Promise<{ rules: LifecycleRule[]; had: boolean }> {
  try { return { rules: (await s3.send(new GetBucketLifecycleConfigurationCommand({ Bucket: bucket }))).Rules ?? [], had: true }; }
  catch (e: any) { if (/NoSuchLifecycleConfiguration/i.test(String(e?.name || e?.message))) return { rules: [], had: false }; throw e; }
}

async function handsOff(s3: S3Client, bucket: string): Promise<boolean> {
  try { return ((await s3.send(new GetBucketTaggingCommand({ Bucket: bucket }))).TagSet ?? []).some((t) => t.Key === "advisor:hands-off"); }
  catch { return false; }
}

const isRedirect = (e: any) => /PermanentRedirect|AuthorizationHeaderMalformed|301/i.test(String(e?.name || e?.message || e?.$metadata?.httpStatusCode));

async function bucketRegion(creds: Pick<Creds, "region" | "read">, bucket: string): Promise<string> {
  const s3 = new S3Client({ region: creds.region, credentials: creds.read });
  try { return (await s3.send(new GetBucketLocationCommand({ Bucket: bucket }))).LocationConstraint || "us-east-1"; }
  finally { s3.destroy(); }
}

function latestMultipart(bucket: string): { uploads: number; oldest_at: string | null; collected_at: string } | null {
  const r = db.prepare("select json, collected_at from s3_usage where bucket = ? and error is null").get(bucket) as { json: string; collected_at: string } | undefined;
  if (!r) return null;
  try { const u = JSON.parse(r.json); return u?.multipart ? { uploads: Number(u.multipart.uploads || 0), oldest_at: u.multipart.oldest_at ?? null, collected_at: r.collected_at } : null; } catch { return null; }
}

const ruleId = (r: LifecycleRule) => r.ID || "(no id)";

export const s3MultipartAbortAction: ActionModule = {
  kind: KIND,
  label: "Incomplete multipart uploads aborted on every bucket",

  async plan(creds, log) {
    const proposals: Proposal[] = []; const notes: string[] = [];
    const days = Math.max(1, Math.round(config.actMultipartDays));
    const rows = db.prepare("select name, region, total_gb, account_id from inventory_s3 where gone = 0 order by coalesce(total_gb, 0) desc").all() as { name: string; region: string | null; total_gb: number | null; account_id: string | null }[];
    if (!rows.length) { notes.push("no bucket in the inventory"); return { proposals, notes }; }
    let covered = 0;
    for (const b of rows.slice(0, MAX_PER_PLAN)) {
      const skip = (why: string) => { notes.push(`${b.name}: ${why}`); log(`${b.name}: ${why}`); };
      // the bucket's own account (src/accounts.ts): a member's bucket is read, and later changed, through its roles
      const acct = creds.forAccount(b.account_id || null);
      let region = b.region || acct.region;
      let s3 = new S3Client({ region, credentials: acct.read });
      try {
        let cur: { rules: LifecycleRule[]; had: boolean };
        try { cur = await currentRules(s3, b.name); }
        catch (e: any) {
          if (!isRedirect(e)) throw e;
          s3.destroy(); region = await bucketRegion(acct, b.name); s3 = new S3Client({ region, credentials: acct.read });
          cur = await currentRules(s3, b.name);
        }
        const have = existingAbort(cur.rules);
        if (have) { covered++; continue; }
        if (await handsOff(s3, b.name)) { skip("tagged advisor:hands-off"); continue; }
        const mp = latestMultipart(b.name);
        const merged = mergeRules(cur.rules, [abortRule(days)]);
        const analysed = mp ? `${mp.uploads.toLocaleString()}${mp.uploads >= 1000 ? "+" : ""} incomplete upload(s) seen on ${mp.collected_at.slice(0, 10)}${mp.oldest_at ? `, the oldest from ${mp.oldest_at.slice(0, 10)}` : ""}` : "not analysed yet (Inventory › S3 counts the incomplete uploads for buckets above the threshold), so the parts' size is unknown";
        proposals.push({
          kind: KIND, resource: b.name, resource_name: b.name, region, account_id: acct.is_parent ? null : acct.account_id,
          dedupe: `${KIND}:${b.name}:${days}`,
          title: `${b.name}: abort incomplete multipart uploads after ${days} days${b.total_gb != null ? ` (${b.total_gb.toFixed(1)} GB)` : ""}`,
          reason: `no lifecycle rule aborts incomplete multipart uploads on the whole bucket; ${analysed}. Their parts bill as Standard storage and never appear in a listing. ${cur.rules.length ? `${cur.rules.length} existing rule(s) kept as they are (${cur.rules.map(ruleId).join(", ")}). ` : ""}Completed objects are never touched; an upload still running past ${days} days is aborted too.`,
          before: { rule_ids: cur.rules.map(ruleId), abort_days: null }, after: { rule_ids: merged.map(ruleId), abort_days: days },
          facts: { days, had_configuration: cur.had, existing_configuration: cur.rules, multipart: mp, total_gb: b.total_gb },
          rollback: cur.had ? "put the previous lifecycle configuration back (parts already aborted are gone, which is the point)" : "the bucket had no lifecycle configuration: the rule is put back disabled (S3 refuses an empty configuration; parts already aborted are gone)",
          est_usd_month: abortSaving(null),
        });
      } catch (e: any) { skip(String(e?.message || e).slice(0, 200)); }
      finally { s3.destroy(); }
    }
    if (covered) notes.push(`${covered} bucket(s) already abort incomplete multipart uploads`);
    if (rows.length > MAX_PER_PLAN) notes.push(`${rows.length - MAX_PER_PLAN} bucket(s) wait for a later pass`);
    return { proposals, notes };
  },

  async apply(p, creds) {
    const s3 = new S3Client({ region: p.region, credentials: creds.act() });
    try {
      const cur = await currentRules(s3, p.resource);
      const rules = mergeRules(cur.rules, [abortRule(Number(p.facts.days))]);
      await s3.send(new PutBucketLifecycleConfigurationCommand({ Bucket: p.resource, LifecycleConfiguration: { Rules: rules } }));
      return `PutBucketLifecycleConfiguration: abort incomplete multipart uploads after ${p.facts.days} days (${rules.length} rule(s): ${rules.map(ruleId).join(", ")})`;
    } finally { s3.destroy(); }
  },

  async verify(p, creds) {
    const s3 = new S3Client({ region: p.region, credentials: creds.read });
    try {
      const cur = await currentRules(s3, p.resource);
      const r = cur.rules.find((x) => x.ID === RULE_ID);
      if (!r) return { ok: false, note: "the rule is not on the bucket" };
      if (r.Status !== "Enabled") return { ok: false, note: "the rule reads Disabled" };
      const d = r.AbortIncompleteMultipartUpload?.DaysAfterInitiation;
      return d === Number(p.facts.days) ? { ok: true, note: `read back: abort after ${d} days` } : { ok: false, note: `the rule reads ${d ?? "no"} days` };
    } finally { s3.destroy(); }
  },

  async revert(p, creds) {
    const s3 = new S3Client({ region: p.region, credentials: creds.act() });
    try {
      const before = (p.facts.existing_configuration as LifecycleRule[]) || [];
      if (p.facts.had_configuration && before.length) {
        await s3.send(new PutBucketLifecycleConfigurationCommand({ Bucket: p.resource, LifecycleConfiguration: { Rules: before } }));
        return `previous ${before.length} rule(s) restored; parts already aborted are gone`;
      }
      await s3.send(new PutBucketLifecycleConfigurationCommand({ Bucket: p.resource, LifecycleConfiguration: { Rules: [abortRule(Number(p.facts.days), "Disabled")] } }));
      return "the bucket had no lifecycle configuration before: the rule is left in place Disabled (S3 refuses an empty configuration); parts already aborted are gone";
    } finally { s3.destroy(); }
  },
};

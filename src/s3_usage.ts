/**
 * S3 lifecycle rules from how a bucket is actually used, not from the fact that it has none.
 *
 * For each bucket above the size threshold the analysis samples the object listing (up to ten pages of a
 * thousand keys, flat, so a prefix breakdown falls out of the keys), which gives bytes by age and by storage
 * class and the share of small objects; the multipart uploads left incomplete; a sample of noncurrent versions
 * when versioning is on; the lifecycle rules already there; and, once request metrics exist on the bucket
 * (src/actions/s3_request_metrics.ts), the reads per day from CloudWatch. `proposeLifecycle` turns that into
 * the rules that fit, each with its reason and its estimate at the class prices, and the exact
 * put-bucket-lifecycle-configuration JSON becomes the plan step of a tier-`approve` recommendation
 * (`review_s3_lifecycle`): transitions carry minimum-storage and retrieval charges, so a person confirms.
 * Everything here is read-only; it runs after the S3 inventory in the logs job and on demand.
 */
import { CloudWatchClient, GetMetricDataCommand } from "@aws-sdk/client-cloudwatch";
import { GetBucketLifecycleConfigurationCommand, ListMultipartUploadsCommand, ListObjectVersionsCommand, ListObjectsV2Command, S3Client, type LifecycleRule } from "@aws-sdk/client-s3";
import { db } from "./db.js";
import { config } from "./config.js";
import { sdkCredentials } from "./steampipe.js";
import { describeError } from "./permissions.js";
import { upsertRecommendations } from "./collector.js";
import type { RecInput } from "./rules.js";
import { entireBucketMetrics } from "./actions/s3_request_metrics.js";

db.exec(`create table if not exists s3_usage (
  bucket text primary key, region text, collected_at text not null, json text not null, error text
)`);

export const MAX_PAGES = 10;
export const MAX_VERSION_PAGES = 5;
export const AGE_BUCKETS = ["0-30", "30-90", "90-365", "365+"] as const;
export type AgeBucket = (typeof AGE_BUCKETS)[number];
/** Below this an IA class bills the full 128 KB anyway. */
export const SMALL_OBJECT_BYTES = 128 * 1024;
export const PRICE = { standard: 0.023, ia: 0.0125, glacier_ir: 0.004, it_frequent: 0.023, it_infrequent: 0.0125, it_monitoring_per_1000: 0.0025 };
export const REQUEST_DAYS = 14;

export interface Tally { objects: number; bytes: number }
export interface PrefixTally extends Tally { prefix: string; old_bytes: number; standard_bytes: number }
export interface S3Usage {
  bucket: string; region: string; collected_at: string;
  sample: { objects: number; bytes: number; truncated: boolean; pages: number };
  by_age: Record<AgeBucket, Tally>;
  standard_by_age: Record<AgeBucket, Tally>;
  by_class: Record<string, Tally>;
  by_prefix: PrefixTally[];
  small_objects_bytes_share: number;
  multipart: { uploads: number; oldest_at: string | null };
  versioning: boolean;
  noncurrent: { versions: number; bytes: number; sampled: boolean } | null;
  lifecycle: { id: string; status: string; prefix: string | null; transitions: { days: number | null; storage_class: string }[]; expiration_days: number | null; noncurrent_expiration_days: number | null; abort_multipart_days: number | null }[] | null;
  requests: { days: number; get_per_day: number | null; put_per_day: number | null; bytes_downloaded_per_day: number | null; metrics_id: string } | null;
  inventory: { total_gb: number | null; standard_gb: number | null; objects: number | null };
}

const empty = (): Record<AgeBucket, Tally> => ({ "0-30": { objects: 0, bytes: 0 }, "30-90": { objects: 0, bytes: 0 }, "90-365": { objects: 0, bytes: 0 }, "365+": { objects: 0, bytes: 0 } });
const ageBucket = (ageDays: number): AgeBucket => (ageDays < 30 ? "0-30" : ageDays < 90 ? "30-90" : ageDays < 365 ? "90-365" : "365+");
const gb = (b: number) => Math.round((b / 1e9) * 100) / 100;

/** Reduces a listing to the tallies: pure, so the shape can be tested without S3. */
export function tallyObjects(objects: { Key?: string; Size?: number; LastModified?: Date; StorageClass?: string }[], now = Date.now()) {
  const by_age = empty(), standard_by_age = empty();
  const by_class: Record<string, Tally> = {};
  const prefixes = new Map<string, PrefixTally>();
  let small = 0, bytes = 0;
  for (const o of objects) {
    const size = o.Size ?? 0, cls = o.StorageClass || "STANDARD";
    const age = o.LastModified ? (now - new Date(o.LastModified).getTime()) / 86400000 : 0;
    const ab = ageBucket(age);
    bytes += size;
    by_age[ab].objects++; by_age[ab].bytes += size;
    if (cls === "STANDARD") { standard_by_age[ab].objects++; standard_by_age[ab].bytes += size; }
    by_class[cls] = by_class[cls] || { objects: 0, bytes: 0 }; by_class[cls].objects++; by_class[cls].bytes += size;
    if (size < SMALL_OBJECT_BYTES) small += size;
    const key = o.Key || ""; const slash = key.indexOf("/");
    const prefix = slash > 0 ? key.slice(0, slash + 1) : "(root)";
    const p = prefixes.get(prefix) || { prefix, objects: 0, bytes: 0, old_bytes: 0, standard_bytes: 0 };
    p.objects++; p.bytes += size; if (ab === "365+") p.old_bytes += size; if (cls === "STANDARD") p.standard_bytes += size;
    prefixes.set(prefix, p);
  }
  return { by_age, standard_by_age, by_class, by_prefix: [...prefixes.values()].sort((a, b) => b.bytes - a.bytes).slice(0, 12), small_objects_bytes_share: bytes ? Math.round((small / bytes) * 1000) / 1000 : 0, bytes, objects: objects.length };
}

const ruleSummary = (r: LifecycleRule) => ({
  id: r.ID || "", status: r.Status || "", prefix: r.Filter?.Prefix ?? r.Prefix ?? (r.Filter?.And?.Prefix ?? null),
  transitions: (r.Transitions ?? []).map((t) => ({ days: t.Days ?? null, storage_class: String(t.StorageClass || "") })),
  expiration_days: r.Expiration?.Days ?? null, noncurrent_expiration_days: r.NoncurrentVersionExpiration?.NoncurrentDays ?? null, abort_multipart_days: r.AbortIncompleteMultipartUpload?.DaysAfterInitiation ?? null,
});

/** The full read of one bucket. Throws on the listing; the optional parts (versions, multipart, lifecycle, metrics) degrade to null. */
export async function analyseBucket(bucket: string, opts: { region?: string; onLog?: (l: string) => void } = {}): Promise<S3Usage> {
  const log = opts.onLog || (() => {});
  const inv = db.prepare("select region, versioning, total_gb, standard_gb, objects from inventory_s3 where name = ?").get(bucket) as { region: string | null; versioning: number | null; total_gb: number | null; standard_gb: number | null; objects: number | null } | undefined;
  const creds = sdkCredentials();
  const region = opts.region || inv?.region || creds.region;
  const s3 = new S3Client({ region, credentials: creds.provider });
  const cw = new CloudWatchClient({ region, credentials: creds.provider });
  try {
    const objects: { Key?: string; Size?: number; LastModified?: Date; StorageClass?: string }[] = [];
    let token: string | undefined; let pages = 0; let truncated = false;
    do {
      const r = await s3.send(new ListObjectsV2Command({ Bucket: bucket, MaxKeys: 1000, ContinuationToken: token }));
      objects.push(...(r.Contents ?? [])); pages++;
      token = r.IsTruncated ? r.NextContinuationToken : undefined;
      if (token && pages >= MAX_PAGES) { truncated = true; token = undefined; }
    } while (token);
    const t = tallyObjects(objects);
    const out: S3Usage = {
      bucket, region, collected_at: new Date().toISOString(),
      sample: { objects: t.objects, bytes: t.bytes, truncated, pages },
      by_age: t.by_age, standard_by_age: t.standard_by_age, by_class: t.by_class, by_prefix: t.by_prefix, small_objects_bytes_share: t.small_objects_bytes_share,
      multipart: { uploads: 0, oldest_at: null }, versioning: Boolean(inv?.versioning), noncurrent: null, lifecycle: null, requests: null,
      inventory: { total_gb: inv?.total_gb ?? null, standard_gb: inv?.standard_gb ?? null, objects: inv?.objects ?? null },
    };
    try {
      const m = await s3.send(new ListMultipartUploadsCommand({ Bucket: bucket, MaxUploads: 1000 }));
      const ups = m.Uploads ?? [];
      out.multipart = { uploads: ups.length + (m.IsTruncated ? 1000 : 0), oldest_at: ups.length ? new Date(Math.min(...ups.map((u) => new Date(u.Initiated!).getTime()))).toISOString() : null };
    } catch (e) { log(`${bucket}: multipart uploads: ${describeError(e, `s3 ListMultipartUploads ${bucket}`, 160)}`); }
    if (out.versioning) {
      try {
        let versions = 0, bytes = 0, vpages = 0, keyMarker: string | undefined, idMarker: string | undefined, more = false;
        do {
          const r = await s3.send(new ListObjectVersionsCommand({ Bucket: bucket, MaxKeys: 1000, KeyMarker: keyMarker, VersionIdMarker: idMarker }));
          for (const v of r.Versions ?? []) if (!v.IsLatest) { versions++; bytes += v.Size ?? 0; }
          vpages++; more = Boolean(r.IsTruncated); keyMarker = r.NextKeyMarker; idMarker = r.NextVersionIdMarker;
        } while (more && vpages < MAX_VERSION_PAGES);
        out.noncurrent = { versions, bytes, sampled: more };
      } catch (e) { log(`${bucket}: versions: ${describeError(e, `s3 ListObjectVersions ${bucket}`, 160)}`); }
    }
    try { const l = await s3.send(new GetBucketLifecycleConfigurationCommand({ Bucket: bucket })); out.lifecycle = (l.Rules ?? []).map(ruleSummary); }
    catch (e: any) { if (/NoSuchLifecycleConfiguration/i.test(String(e?.name || e?.message))) out.lifecycle = []; else log(`${bucket}: lifecycle: ${describeError(e, `s3 GetBucketLifecycleConfiguration ${bucket}`, 160)}`); }
    try {
      const id = await entireBucketMetrics(s3, bucket);
      if (id) {
        const now = Date.now();
        const q = (name: string, i: number) => ({ Id: `m${i}`, MetricStat: { Metric: { Namespace: "AWS/S3", MetricName: name, Dimensions: [{ Name: "BucketName", Value: bucket }, { Name: "FilterId", Value: id }] }, Period: 86400, Stat: "Sum" }, ReturnData: true });
        const r = await cw.send(new GetMetricDataCommand({ StartTime: new Date(now - REQUEST_DAYS * 86400000), EndTime: new Date(now), MetricDataQueries: [q("GetRequests", 0), q("PutRequests", 1), q("BytesDownloaded", 2)] }));
        const perDay = (i: number) => { const v = r.MetricDataResults?.[i]?.Values ?? []; return v.length ? Math.round((v.reduce((a, b) => a + b, 0) / v.length) * 10) / 10 : null; };
        const days = Math.max(...(r.MetricDataResults ?? []).map((x) => x.Values?.length ?? 0), 0);
        out.requests = { days, get_per_day: perDay(0), put_per_day: perDay(1), bytes_downloaded_per_day: perDay(2), metrics_id: id };
      }
    } catch (e) { log(`${bucket}: request metrics: ${describeError(e, `s3 request metrics ${bucket} (s3:GetMetricsConfiguration, cloudwatch:GetMetricData)`, 160)}`); }
    return out;
  } finally { s3.destroy(); cw.destroy(); }
}

// ---- the rules that fit ---------------------------------------------------------------------------------------------

export interface ProposedRule { id: string; why: string; est_usd_month: number; rule: Record<string, unknown> }
export interface LifecycleProposal { rules: ProposedRule[]; lifecycle: { Rules: Record<string, unknown>[] } | null; est_usd_month: number; notes: string[] }

/** Scales a sampled byte count to the bucket: the inventory's standard GB over the sample's, when the listing was truncated. */
function scale(u: S3Usage): number {
  if (!u.sample.truncated || !u.inventory.total_gb || !u.sample.bytes) return 1;
  return Math.max(1, (u.inventory.total_gb * 1e9) / u.sample.bytes);
}

export function proposeLifecycle(u: S3Usage): LifecycleProposal {
  const rules: ProposedRule[] = []; const notes: string[] = [];
  const k = scale(u);
  const existing = u.lifecycle ?? [];
  const has = (f: (r: NonNullable<S3Usage["lifecycle"]>[number]) => boolean) => existing.some((r) => r.status === "Enabled" && f(r));
  if (existing.length) notes.push(`${existing.length} lifecycle rule(s) already on the bucket: ${existing.map((r) => `${r.id || "(no id)"}${r.transitions.length ? ` → ${r.transitions.map((t) => `${t.storage_class}@${t.days}d`).join(", ")}` : ""}${r.expiration_days ? ` expire@${r.expiration_days}d` : ""}`).join("; ")}`);
  if (u.sample.truncated) notes.push(`the listing was sampled (${u.sample.objects.toLocaleString()} of about ${u.inventory.objects ? Math.round(u.inventory.objects).toLocaleString() : "?"} objects); bytes are scaled to the bucket`);

  if (u.multipart.uploads > 0 && !has((r) => r.abort_multipart_days != null)) {
    rules.push({ id: "aws-advisor-abort-incomplete-multipart", why: `${u.multipart.uploads} incomplete multipart upload(s)${u.multipart.oldest_at ? `, the oldest from ${u.multipart.oldest_at.slice(0, 10)}` : ""}: their parts are billed as Standard storage and never listed`, est_usd_month: 0,
      rule: { ID: "aws-advisor-abort-incomplete-multipart", Status: "Enabled", Filter: { Prefix: "" }, AbortIncompleteMultipartUpload: { DaysAfterInitiation: 7 } } });
  }
  if (u.versioning && u.noncurrent && u.noncurrent.bytes * k >= 1e9 && !has((r) => r.noncurrent_expiration_days != null)) {
    const ncGb = gb(u.noncurrent.bytes * k);
    rules.push({ id: "aws-advisor-expire-noncurrent", why: `versioning keeps ${u.noncurrent.versions.toLocaleString()}${u.noncurrent.sampled ? "+" : ""} noncurrent versions, about ${ncGb} GB billed at Standard; keep 90 days of them`, est_usd_month: Math.round(ncGb * PRICE.standard * 0.7 * 100) / 100,
      rule: { ID: "aws-advisor-expire-noncurrent", Status: "Enabled", Filter: { Prefix: "" }, NoncurrentVersionExpiration: { NoncurrentDays: 90 } } });
  }
  const oldStd = u.standard_by_age["365+"].bytes * k, midStd = (u.standard_by_age["90-365"].bytes + u.standard_by_age["30-90"].bytes) * k;
  const coldStd = oldStd + midStd;
  const alreadyTiers = has((r) => r.transitions.length > 0);
  if (coldStd >= 1e9 && !alreadyTiers) {
    const top = u.by_prefix.find((p) => p.old_bytes > 0 && p.old_bytes >= 0.8 * (u.standard_by_age["365+"].bytes || 1) && p.prefix !== "(root)");
    const filter = top ? { Prefix: top.prefix } : { Prefix: "" };
    const scope = top ? ` under ${top.prefix}` : "";
    const small = u.small_objects_bytes_share >= 0.5 ? " Over half the bytes sit in objects under 128 KB, which an IA class bills as 128 KB each: Intelligent-Tiering carries no such penalty." : "";
    const r = u.requests;
    const objs = u.inventory.objects || u.sample.objects || 1;
    if (r && r.get_per_day != null && r.days >= 7 && r.get_per_day <= Math.max(10, 0.001 * objs)) {
      rules.push({ id: "aws-advisor-glacier-ir-90", why: `${gb(coldStd)} GB of Standard older than 30 days${scope}, about ${gb(oldStd)} GB older than a year, and ${r.get_per_day} GET/day over ${r.days} days on ${Math.round(objs).toLocaleString()} objects: almost nothing is read. Glacier Instant Retrieval keeps millisecond access at a sixth of the price (90-day minimum, retrieval charged per GB).${small}`,
        est_usd_month: Math.round(gb(coldStd) * (PRICE.standard - PRICE.glacier_ir) * 100) / 100,
        rule: { ID: "aws-advisor-glacier-ir-90", Status: "Enabled", Filter: filter, Transitions: [{ Days: 90, StorageClass: "GLACIER_IR" }] } });
    } else if (r && r.get_per_day != null && r.days >= 7) {
      rules.push({ id: "aws-advisor-standard-ia-30", why: `${gb(coldStd)} GB of Standard older than 30 days${scope} with ${r.get_per_day} GET/day over ${r.days} days: read, but not enough to keep at Standard. Standard-IA halves the storage price; each read costs 0.01 USD/GB.${small}`,
        est_usd_month: Math.round(gb(coldStd) * (PRICE.standard - PRICE.ia) * 100) / 100,
        rule: { ID: "aws-advisor-standard-ia-30", Status: "Enabled", Filter: filter, Transitions: [{ Days: 30, StorageClass: "STANDARD_IA" }] } });
    } else {
      rules.push({ id: "aws-advisor-intelligent-tiering", why: `${gb(coldStd)} GB of Standard older than 30 days${scope} and no request metrics yet, so how much of it is read is unknown. Intelligent-Tiering moves what is not touched for 30 days to the infrequent tier by itself, no retrieval charge, 0.0025 USD per 1,000 objects a month. Enabling request metrics (the executor does it) would let the next analysis pick a sharper class.${small}`,
        est_usd_month: Math.round(gb(coldStd) * (PRICE.standard - PRICE.it_infrequent) * 0.5 * 100) / 100,
        rule: { ID: "aws-advisor-intelligent-tiering", Status: "Enabled", Filter: filter, Transitions: [{ Days: 0, StorageClass: "INTELLIGENT_TIERING" }] } });
    }
  } else if (coldStd >= 1e9 && alreadyTiers) notes.push("bytes older than 30 days are already covered by a transition rule");
  else notes.push(`only ${gb(coldStd)} GB of Standard older than 30 days: not worth a transition`);
  const est = Math.round(rules.reduce((s, r) => s + r.est_usd_month, 0) * 100) / 100;
  return { rules, lifecycle: rules.length ? { Rules: [...existing.filter((r) => r.status === "Enabled").map((r) => ({ ID: r.id, Status: r.status, note: "existing rule: keep as is (the JSON must carry every rule; fetch the current configuration and merge)" })), ...rules.map((r) => r.rule)] } : null, est_usd_month: est, notes };
}

// ---- storage, the recommendation, the pass ----------------------------------------------------------------------------

export function latestS3Usage(bucket: string): (S3Usage & { proposal: LifecycleProposal }) | null {
  const r = db.prepare("select json from s3_usage where bucket = ?").get(bucket) as { json: string } | undefined;
  if (!r) return null;
  try { const u = JSON.parse(r.json) as S3Usage; return { ...u, proposal: proposeLifecycle(u) }; } catch { return null; }
}

/** Analyses one bucket, stores it, and refreshes its recommendation. */
export async function refreshS3Usage(bucket: string, onLog: (l: string) => void = () => {}): Promise<S3Usage & { proposal: LifecycleProposal }> {
  const u = await analyseBucket(bucket, { onLog });
  db.prepare("insert into s3_usage(bucket, region, collected_at, json, error) values (?, ?, ?, ?, null) on conflict(bucket) do update set region = excluded.region, collected_at = excluded.collected_at, json = excluded.json, error = null").run(bucket, u.region, u.collected_at, JSON.stringify(u));
  const proposal = proposeLifecycle(u);
  onLog(`${bucket}: ${u.sample.objects} objects sampled${u.sample.truncated ? " (truncated)" : ""}, ${gb(u.standard_by_age["365+"].bytes)} GB Standard older than a year, ${u.multipart.uploads} multipart, ${u.requests ? `${u.requests.get_per_day} GET/day` : "no request metrics"}: ${proposal.rules.length} rule(s), ≈ ${proposal.est_usd_month} USD/month`);
  if (proposal.rules.length) {
    const runId = (db.prepare("select id from runs order by id desc limit 1").get() as { id: number } | undefined)?.id ?? 0;
    const rec: RecInput = {
      rule: "review_s3_lifecycle", title: `Lifecycle rules for ${bucket}: ${proposal.rules.map((r) => r.id.replace(/^aws-advisor-/, "")).join(", ")}`, resource: bucket, resourceName: bucket, actionType: "other",
      estMonthlySaving: proposal.est_usd_month, tier: "approve", confidence: u.requests ? 0.8 : 0.6,
      rationale: `${proposal.rules.map((r) => `${r.id.replace(/^aws-advisor-/, "")}: ${r.why}`).join(" ")}${proposal.notes.length ? ` ${proposal.notes.join(". ")}.` : ""} Apply with put-bucket-lifecycle-configuration using the JSON in the evidence (merge with the existing rules).`,
      evidence: { lifecycle: proposal.lifecycle, rules: proposal.rules, usage: { collected_at: u.collected_at, sample: u.sample, standard_by_age_gb: Object.fromEntries(AGE_BUCKETS.map((a) => [a, gb(u.standard_by_age[a].bytes)])), by_class_gb: Object.fromEntries(Object.entries(u.by_class).map(([c, t]) => [c, gb(t.bytes)])), top_prefixes: u.by_prefix.slice(0, 5).map((p) => ({ prefix: p.prefix, gb: gb(p.bytes), old_gb: gb(p.old_bytes) })), multipart: u.multipart, noncurrent: u.noncurrent, requests: u.requests, small_objects_bytes_share: u.small_objects_bytes_share }, playbook: "aws_thrifty.control.buckets_with_no_lifecycle" },
    };
    upsertRecommendations(runId, [rec], "rules", undefined, { reconcile: false });
  }
  return { ...u, proposal };
}

export interface S3UsagePassResult { candidates: number; analysed: string[]; skipped: number; failed: { bucket: string; message: string }[]; took_ms: number }

/** Every bucket at or above the threshold not analysed in the last six days, largest first, at most `limit` per pass. */
export async function s3UsagePass(onLog: (l: string) => void = () => {}, limit = 15): Promise<S3UsagePassResult> {
  const t0 = Date.now();
  const rows = db.prepare(`select i.name from inventory_s3 i left join s3_usage u on u.bucket = i.name
    where i.gone = 0 and i.total_gb >= ? and (u.collected_at is null or datetime(u.collected_at) < datetime('now', '-6 days')) order by i.total_gb desc`).all(config.actS3MinGb) as { name: string }[];
  const out: S3UsagePassResult = { candidates: rows.length, analysed: [], skipped: Math.max(0, rows.length - limit), failed: [], took_ms: 0 };
  for (const r of rows.slice(0, limit)) {
    try { await refreshS3Usage(r.name, onLog); out.analysed.push(r.name); }
    catch (e) {
      const message = describeError(e, `s3 usage ${r.name} (s3:ListBucket)`, 200);
      out.failed.push({ bucket: r.name, message });
      db.prepare("insert into s3_usage(bucket, region, collected_at, json, error) values (?, null, datetime('now'), '{}', ?) on conflict(bucket) do update set error = excluded.error").run(r.name, message);
      if (/AccessDenied|not authorized|NoSdkCredentials/i.test(message)) { out.skipped += rows.length - out.analysed.length - out.failed.length; break; }
    }
  }
  out.took_ms = Date.now() - t0;
  onLog(`${out.analysed.length} bucket(s) analysed, ${out.failed.length} failed, ${out.skipped} waiting of ${out.candidates} due in ${out.took_ms} ms`);
  return out;
}

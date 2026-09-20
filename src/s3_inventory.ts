/**
 * S3 per bucket: every bucket with its size per storage class and its object count (CloudWatch's daily storage
 * metrics, one call per bucket and class, so this runs daily with the logs job rather than with every inventory
 * refresh), lifecycle and versioning, and the monthly storage cost at the class's list price. The review flags
 * big buckets that keep everything in Standard with no lifecycle rule.
 */
import { db } from "./db.js";
import { S, query } from "./steampipe.js";
import { describeError } from "./permissions.js";

db.exec(`create table if not exists inventory_s3 (
  name text primary key, region text, created text, versioning integer, lifecycle_rules integer, public integer,
  sizes text, total_gb real, objects real, standard_gb real, monthly_usd real, metric_day text,
  first_seen text not null, last_seen text not null, gone integer not null default 0
)`);

/** USD per GB-month per CloudWatch storage type (us-east-1 list). */
export const S3_CLASS_PRICE: Record<string, number> = {
  StandardStorage: 0.023, StandardIAStorage: 0.0125, StandardIASizeOverhead: 0.0125, OneZoneIAStorage: 0.01, ReducedRedundancyStorage: 0.023,
  IntelligentTieringFAStorage: 0.023, IntelligentTieringIAStorage: 0.0125, IntelligentTieringAAStorage: 0.004, IntelligentTieringAIAStorage: 0.004, IntelligentTieringDAAStorage: 0.00099,
  GlacierInstantRetrievalStorage: 0.004, GlacierStorage: 0.0036, GlacierStagingStorage: 0.0036, GlacierObjectOverhead: 0.0036, DeepArchiveStorage: 0.00099, DeepArchiveObjectOverhead: 0.00099, ExpressOneZone: 0.16,
};
const CLASSES = Object.keys(S3_CLASS_PRICE).filter((c) => !/Overhead|Staging|ExpressOneZone/.test(c));
export function s3MonthlyCost(sizesGb: Record<string, number>): number { return Math.round(Object.entries(sizesGb).reduce((s, [c, gb]) => s + gb * (S3_CLASS_PRICE[c] ?? 0.023), 0) * 100) / 100; }

import { CloudWatchClient, ListMetricsCommand, GetMetricDataCommand } from "@aws-sdk/client-cloudwatch";
import { sdkCredentials } from "./steampipe.js";

/** One ListMetrics per region finds which (bucket, storage class) pairs exist, then GetMetricData fetches them
 *  500 at a time: 56 buckets cost 2 or 3 CloudWatch calls instead of 15 Steampipe queries each. */
export async function s3StorageMetrics(regions: string[], onLog: (s: string) => void): Promise<Map<string, { sizes: Record<string, number>; objects: number | null }>> {
  const out = new Map<string, { sizes: Record<string, number>; objects: number | null }>();
  const creds = sdkCredentials();
  const end = new Date(); const start = new Date(end.getTime() - 3 * 86400e3);
  for (const region of regions) {
    const client = new CloudWatchClient({ region, credentials: creds.provider });
    const found: Array<{ bucket: string; storageType: string; metric: string }> = [];
    for (const metric of ["BucketSizeBytes", "NumberOfObjects"]) {
      let NextToken: string | undefined;
      do {
        const r = await client.send(new ListMetricsCommand({ Namespace: "AWS/S3", MetricName: metric, NextToken }));
        for (const m of r.Metrics ?? []) {
          const bucket = m.Dimensions?.find((d) => d.Name === "BucketName")?.Value; const storageType = m.Dimensions?.find((d) => d.Name === "StorageType")?.Value;
          if (bucket && storageType) found.push({ bucket, storageType, metric });
        }
        NextToken = r.NextToken;
      } while (NextToken);
    }
    for (let i = 0; i < found.length; i += 500) {
      const chunk = found.slice(i, i + 500);
      const r = await client.send(new GetMetricDataCommand({
        StartTime: start, EndTime: end, ScanBy: "TimestampDescending",
        MetricDataQueries: chunk.map((f, j) => ({ Id: `q${j}`, MetricStat: { Metric: { Namespace: "AWS/S3", MetricName: f.metric, Dimensions: [{ Name: "BucketName", Value: f.bucket }, { Name: "StorageType", Value: f.storageType }] }, Period: 86400, Stat: "Maximum" } })),
      }));
      for (const res of r.MetricDataResults ?? []) {
        const f = chunk[Number(String(res.Id).slice(1))]; const v = res.Values?.[0]; if (!f || v == null) continue;
        const e = out.get(f.bucket) ?? { sizes: {}, objects: null }; out.set(f.bucket, e);
        if (f.metric === "NumberOfObjects") { if (f.storageType === "AllStorageTypes") e.objects = v; }
        else if (v > 0 && CLASSES.includes(f.storageType)) e.sizes[f.storageType] = Math.round((v / 1e9) * 1000) / 1000;
      }
    }
    onLog(`s3 metrics ${region}: ${found.length} series, ${out.size} buckets so far`);
  }
  return out;
}


export async function refreshS3Inventory(onLog: (s: string) => void = () => {}): Promise<{ buckets: number; metered: number; errors: string[] }> {
  const out = { buckets: 0, metered: 0, errors: [] as string[] };
  let buckets: any[];
  // Every hydrated column is a separate S3 call with its own permission; a denied one fails the whole scan,
  // so drop the column that needs the missing action and retry, reporting what is unknown.
  const optional: Array<[col: string, action: string]> = [["bucket_policy_is_public", "s3:GetBucketPolicyStatus"], ["versioning_enabled", "s3:GetBucketVersioning"], ["lifecycle_rules", "s3:GetLifecycleConfiguration"]];
  let cols = ["name", "region", "creation_date", ...optional.map((o) => o[0])];
  const missing: string[] = [];
  for (;;) {
    try { buckets = await query<any>(`select ${cols.join(", ")} from ${S}.aws_s3_bucket`); break; }
    catch (e) {
      const m = /not authorized to perform: (s3:\w+)/.exec(String((e as any)?.message ?? e));
      const hit = m && optional.find((o) => o[1] === m[1] && cols.includes(o[0]));
      if (!hit) { out.errors.push(describeError(e, "s3 inventory (aws_s3_bucket)")); return out; }
      cols = cols.filter((c) => c !== hit[0]); missing.push(hit[1]);
      onLog(`s3: no ${hit[1]} permission, ${hit[0]} unknown`);
    }
  }
  if (missing.length) out.errors.push(`S3 columns skipped, missing IAM permission ${missing.join(", ")}; add them to the advisor's policy (see Settings > Permissions)`);
  const known = (col: string) => cols.includes(col);
  const now = new Date().toISOString();
  const up = db.prepare(`insert into inventory_s3(name, region, created, versioning, lifecycle_rules, public, sizes, total_gb, objects, standard_gb, monthly_usd, metric_day, first_seen, last_seen, gone)
    values (@name, @region, @created, @versioning, @lifecycle_rules, @public, @sizes, @total_gb, @objects, @standard_gb, @monthly_usd, @metric_day, @now, @now, 0)
    on conflict(name) do update set region = excluded.region, created = excluded.created, versioning = excluded.versioning, lifecycle_rules = excluded.lifecycle_rules, public = excluded.public,
      sizes = excluded.sizes, total_gb = excluded.total_gb, objects = excluded.objects, standard_gb = excluded.standard_gb, monthly_usd = excluded.monthly_usd, metric_day = excluded.metric_day, last_seen = excluded.last_seen, gone = 0`);
  // storage metrics are published once a day per bucket and class; the newest point of the last 3 days is the size
  let metrics = new Map<string, { sizes: Record<string, number>; objects: number | null }>();
  try { metrics = await s3StorageMetrics([...new Set(buckets.map((b) => b.region || "us-east-1"))], onLog); }
  catch (e) { out.errors.push(describeError(e, "s3 storage metrics (cloudwatch:ListMetrics, cloudwatch:GetMetricData)")); }
  const worker = (b: any) => {
    const region = b.region || "us-east-1";
    const m = metrics.get(b.name); const sizes = m?.sizes ?? {}; const objects = m?.objects ?? null;
    const total = Object.values(sizes).reduce((s, x) => s + x, 0);
    let rules: number | null = 0; if (!known("lifecycle_rules")) rules = null; else try { const lr = typeof b.lifecycle_rules === "string" ? JSON.parse(b.lifecycle_rules) : b.lifecycle_rules; rules = Array.isArray(lr) ? lr.length : 0; } catch { rules = 0; }
    up.run({ name: b.name, region, created: b.creation_date ? new Date(b.creation_date).toISOString() : null, versioning: known("versioning_enabled") ? (b.versioning_enabled ? 1 : 0) : null, lifecycle_rules: rules, public: known("bucket_policy_is_public") ? (b.bucket_policy_is_public ? 1 : 0) : null,
      sizes: JSON.stringify(sizes), total_gb: Math.round(total * 1000) / 1000, objects, standard_gb: sizes.StandardStorage ?? 0, monthly_usd: s3MonthlyCost(sizes), metric_day: now.slice(0, 10), now });
    out.buckets++; if (Object.keys(sizes).length) out.metered++;
  };
  for (const b of buckets) worker(b);
  db.prepare("update inventory_s3 set gone = 1 where last_seen <> ?").run(now);
  onLog(`${out.buckets} buckets, ${out.metered} with storage metrics`);
  return out;
}

const SORTS = ["name", "region", "total_gb", "objects", "standard_gb", "monthly_usd", "lifecycle_rules", "created"];
export function listS3(f: { q?: string; sort?: string; gone?: boolean } = {}) {
  const where: string[] = []; const params: unknown[] = [];
  if (!f.gone) where.push("gone = 0");
  if (f.q) { where.push("(name like ? or region like ?)"); params.push(`%${f.q}%`, `%${f.q}%`); }
  const desc = f.sort?.startsWith("-"); const col = (f.sort || "").replace(/^-/, "");
  const order = SORTS.includes(col) ? `order by ${col} ${desc ? "desc" : "asc"} nulls last` : "order by monthly_usd desc, total_gb desc";
  return (db.prepare(`select * from inventory_s3 ${where.length ? `where ${where.join(" and ")}` : ""} ${order} limit 1000`).all(...params) as any[]).map((r) => ({ ...r, sizes: (() => { try { return JSON.parse(r.sizes || "{}"); } catch { return {}; } })() }));
}
export function s3Summary() {
  const r = db.prepare("select count(*) as total, coalesce(sum(total_gb), 0) as gb, coalesce(sum(monthly_usd), 0) as monthly_usd, coalesce(sum(lifecycle_rules = 0 and total_gb > 5), 0) as big_no_lifecycle, coalesce(sum(public), 0) as public, coalesce(sum(public is null), 0) as public_unknown, coalesce(sum(standard_gb), 0) as standard_gb from inventory_s3 where gone = 0").get() as any;
  return { ...r, gone: (db.prepare("select count(*) as n from inventory_s3 where gone = 1").get() as any).n };
}

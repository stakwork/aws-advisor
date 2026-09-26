/**
 * S3 request metrics on the buckets worth analysing. CloudWatch publishes GetRequests, PutRequests and
 * BytesDownloaded per bucket only once a metrics configuration exists on it; without them the lifecycle
 * analysis (src/s3_usage.ts) knows how old the bytes are but not whether anyone reads them. The executor puts
 * an entire-bucket configuration on every bucket above the size threshold (Settings › Auto-actions) that has
 * none. Reversible in one call (DeleteBucketMetricsConfiguration); it costs CloudWatch custom-metric money (a
 * few USD per bucket per month), which the row says.
 */
import { DeleteBucketMetricsConfigurationCommand, GetBucketMetricsConfigurationCommand, ListBucketMetricsConfigurationsCommand, PutBucketMetricsConfigurationCommand, S3Client } from "@aws-sdk/client-s3";
import { db } from "../db.js";
import { config } from "../config.js";
import type { ActionModule, Creds, Proposal } from "../executor.js";

export const KIND = "s3_request_metrics" as const;
export const METRICS_ID = "aws-advisor-entire-bucket";
/** What CloudWatch charges for the request metrics of one bucket, roughly: 16 metrics at custom-metric price. */
export const METRICS_USD_MONTH = 5;

/** The entire-bucket configuration on a bucket, if any (its id, ours or someone else's). */
export async function entireBucketMetrics(s3: S3Client, bucket: string): Promise<string | null> {
  const r = await s3.send(new ListBucketMetricsConfigurationsCommand({ Bucket: bucket }));
  const whole = (r.MetricsConfigurationList ?? []).find((m) => !m.Filter);
  return whole?.Id ?? null;
}

export const s3RequestMetricsAction: ActionModule = {
  kind: KIND,
  label: "S3 request metrics on the big buckets",

  async plan(creds, log) {
    const proposals: Proposal[] = []; const notes: string[] = [];
    const minGb = config.actS3MinGb;
    const rows = db.prepare("select name, region, total_gb, objects from inventory_s3 where gone = 0 and total_gb >= ? order by total_gb desc").all(minGb) as { name: string; region: string; total_gb: number; objects: number | null }[];
    if (!rows.length) { notes.push(`no bucket at or above ${minGb} GB`); return { proposals, notes }; }
    for (const b of rows) {
      const s3 = new S3Client({ region: b.region || creds.region, credentials: creds.read });
      try {
        const have = await entireBucketMetrics(s3, b.name);
        if (have) { notes.push(`${b.name}: request metrics on (${have})`); continue; }
        proposals.push({
          kind: KIND, resource: b.name, resource_name: b.name, region: b.region || creds.region,
          dedupe: `${KIND}:${b.name}`,
          title: `${b.name}: enable request metrics (${b.total_gb.toFixed(1)} GB${b.objects ? `, ${Math.round(b.objects).toLocaleString()} objects` : ""})`,
          reason: `no metrics configuration on the bucket, so CloudWatch has no GetRequests or BytesDownloaded for it and the lifecycle analysis cannot tell what is read. Costs about ${METRICS_USD_MONTH} USD/month in CloudWatch metrics; the analysis needs 14 days of them.`,
          before: { metrics_configuration: null }, after: { metrics_configuration: METRICS_ID },
          facts: { total_gb: b.total_gb, objects: b.objects, cost_usd_month: METRICS_USD_MONTH },
          rollback: "delete the metrics configuration (the metrics stop; nothing else changes)",
          est_usd_month: null,
        });
      } catch (e: any) { const m = String(e?.message || e); notes.push(`${b.name}: ${m.slice(0, 160)}`); log(`${b.name}: ${m}`); if (/AccessDenied|not authorized/i.test(m)) break; }
      finally { s3.destroy(); }
    }
    return { proposals, notes };
  },

  async apply(p, creds) {
    const s3 = new S3Client({ region: p.region, credentials: creds.act() });
    try { await s3.send(new PutBucketMetricsConfigurationCommand({ Bucket: p.resource, Id: METRICS_ID, MetricsConfiguration: { Id: METRICS_ID } })); return `PutBucketMetricsConfiguration ${METRICS_ID}: entire bucket`; }
    finally { s3.destroy(); }
  },

  async verify(p, creds) {
    const s3 = new S3Client({ region: p.region, credentials: creds.read });
    try { const r = await s3.send(new GetBucketMetricsConfigurationCommand({ Bucket: p.resource, Id: METRICS_ID })); return r.MetricsConfiguration ? { ok: true, note: "configuration read back; metrics start within 15 minutes" } : { ok: false, note: "no configuration on read-back" }; }
    catch (e: any) { return /NoSuchConfiguration/i.test(String(e?.name || e?.message)) ? { ok: false, note: "no configuration on read-back" } : { ok: null, note: String(e?.message || e).slice(0, 120) }; }
    finally { s3.destroy(); }
  },

  async revert(p, creds) {
    const s3 = new S3Client({ region: p.region, credentials: creds.act() });
    try { await s3.send(new DeleteBucketMetricsConfigurationCommand({ Bucket: p.resource, Id: METRICS_ID })); return "metrics configuration deleted"; }
    finally { s3.destroy(); }
  },
};

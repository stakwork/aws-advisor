/**
 * S3 request metrics on the buckets where they would change a decision. CloudWatch publishes GetRequests,
 * PutRequests and BytesDownloaded per bucket only once a metrics configuration exists on it; without them the
 * lifecycle analysis (src/s3_usage.ts) knows how old the bytes are but not whether anyone reads them, and falls
 * back to Intelligent-Tiering instead of picking Glacier Instant Retrieval or Standard-IA. The metrics cost a
 * few USD per bucket per month for as long as they stay on, so the executor proposes them only when the stored
 * usage analysis says the sharper class could pay for them: enough cold Standard bytes, no expiration rule that
 * drops objects before they get old, no transition rule already covering them (`requestMetricsCase`). Every
 * bucket left alone goes into the plan's notes with the gate that stopped it. Reversible in one call
 * (DeleteBucketMetricsConfiguration).
 */
import { DeleteBucketMetricsConfigurationCommand, GetBucketMetricsConfigurationCommand, ListBucketMetricsConfigurationsCommand, PutBucketMetricsConfigurationCommand, S3Client } from "@aws-sdk/client-s3";
import { db } from "../db.js";
import { config } from "../config.js";
import type { ActionModule, Creds, Proposal } from "../executor.js";
import type { S3Usage } from "../s3_usage.js";

export const KIND = "s3_request_metrics" as const;
export const METRICS_ID = "aws-advisor-entire-bucket";
/** What CloudWatch charges for the request metrics of one bucket, roughly: 16 metrics at custom-metric price. */
export const METRICS_USD_MONTH = 5;
/** The saving a sharper class could reach must be this many times the metrics price before they are worth turning on. */
export const METRICS_PAYBACK = 2;
/** Standard minus Glacier Instant Retrieval, USD per GB-month: the most a sharper class can save on a cold byte (mirrors PRICE in src/s3_usage.ts). */
export const MAX_SAVING_PER_GB = 0.023 - 0.004;
/** A whole-bucket expiration at or under this many days means nothing lives long enough for a transition. */
export const SHORT_EXPIRY_DAYS = 30;

/** The entire-bucket configuration on a bucket, if any (its id, ours or someone else's). */
export async function entireBucketMetrics(s3: S3Client, bucket: string): Promise<string | null> {
  const r = await s3.send(new ListBucketMetricsConfigurationsCommand({ Bucket: bucket }));
  const whole = (r.MetricsConfigurationList ?? []).find((m) => !m.Filter);
  return whole?.Id ?? null;
}

export interface MetricsCase {
  /** Whether turning the metrics on could change the lifecycle decision by more than they cost. */
  worth: boolean;
  /** One line: the gate that decided, with its numbers. */
  why: string;
  /** Standard bytes older than 30 days, scaled to the bucket, in GB. */
  cold_gb: number;
  /** The most a sharper class could save on those bytes, USD/month. */
  ceiling_usd_month: number;
}

const gb = (b: number) => Math.round((b / 1e9) * 100) / 100;
const usd = (n: number) => Math.round(n * 100) / 100;

/**
 * Whether request metrics on a bucket are worth their price, from the stored usage analysis. Pure, so it is
 * testable: `null` means the bucket has not been analysed yet, and the metrics wait for the analysis.
 */
export function requestMetricsCase(u: S3Usage | null | undefined): MetricsCase {
  const none = (why: string, cold_gb = 0, ceiling = 0): MetricsCase => ({ worth: false, why, cold_gb, ceiling_usd_month: usd(ceiling) });
  if (!u || !u.standard_by_age || !u.sample) return none("no usage analysis stored yet: the analysis runs first and says whether the metrics would change anything");
  const enabled = (u.lifecycle ?? []).filter((r) => r.status === "Enabled");
  const wholeBucket = (r: NonNullable<S3Usage["lifecycle"]>[number]) => !r.prefix;
  const expiry = enabled.find((r) => wholeBucket(r) && r.expiration_days != null && r.expiration_days <= SHORT_EXPIRY_DAYS);
  if (expiry) return none(`lifecycle rule ${expiry.id || "(no id)"} expires every object after ${expiry.expiration_days} days, so nothing gets old enough for a transition and read metrics would decide nothing`);
  const tiered = enabled.find((r) => r.transitions.length > 0);
  if (tiered) return none(`lifecycle rule ${tiered.id || "(no id)"} already moves ${tiered.prefix ? `${tiered.prefix} ` : ""}objects to ${tiered.transitions.map((t) => t.storage_class).join(", ")}: the class is decided`);
  const k = u.sample.truncated && u.inventory?.total_gb && u.sample.bytes ? Math.max(1, (u.inventory.total_gb * 1e9) / u.sample.bytes) : 1;
  const cold = (u.standard_by_age["30-90"].bytes + u.standard_by_age["90-365"].bytes + u.standard_by_age["365+"].bytes) * k;
  const coldGb = gb(cold), ceiling = coldGb * MAX_SAVING_PER_GB;
  if (cold < 1e9) return none(`only ${coldGb} GB of Standard older than 30 days: not worth a transition, so not worth metrics either`, coldGb, ceiling);
  if (ceiling < METRICS_USD_MONTH * METRICS_PAYBACK) return none(`${coldGb} GB of Standard older than 30 days: a sharper class could save at most ${usd(ceiling)} USD/month against ${METRICS_USD_MONTH} USD/month of metrics`, coldGb, ceiling);
  return { worth: true, why: `${coldGb} GB of Standard older than 30 days and no read metrics: the analysis fell back to Intelligent-Tiering, while Glacier Instant Retrieval or Standard-IA could save up to ${usd(ceiling)} USD/month once 14 days of reads say which fits`, cold_gb: coldGb, ceiling_usd_month: usd(ceiling) };
}

/** The stored usage analysis of a bucket, or null when it has not run (or failed) — read straight from the table so this module does not import src/s3_usage.ts at runtime. */
function storedUsage(bucket: string): S3Usage | null {
  const r = db.prepare("select json, error from s3_usage where bucket = ?").get(bucket) as { json: string; error: string | null } | undefined;
  if (!r || r.error) return null;
  try { const u = JSON.parse(r.json) as S3Usage; return u && u.standard_by_age ? u : null; } catch { return null; }
}

export const s3RequestMetricsAction: ActionModule = {
  kind: KIND,
  label: "S3 request metrics where they would change a lifecycle decision",

  async plan(creds, log) {
    const proposals: Proposal[] = []; const notes: string[] = [];
    const minGb = config.actS3MinGb;
    const rows = db.prepare("select name, account_id, region, total_gb, objects from inventory_s3 where gone = 0 and total_gb >= ? order by total_gb desc").all(minGb) as { name: string; account_id: string | null; region: string; total_gb: number; objects: number | null }[];
    if (!rows.length) { notes.push(`no bucket at or above ${minGb} GB`); return { proposals, notes }; }
    for (const b of rows) {
      const c = requestMetricsCase(storedUsage(b.name));
      if (!c.worth) { notes.push(`${b.name}: left alone: ${c.why}`); continue; }
      const s3 = new S3Client({ region: b.region || creds.region, credentials: creds.forAccount(b.account_id).read });
      try {
        const have = await entireBucketMetrics(s3, b.name);
        if (have) { notes.push(`${b.name}: request metrics on (${have})`); continue; }
        proposals.push({
          kind: KIND, resource: b.name, resource_name: b.name, region: b.region || creds.region, account_id: b.account_id ?? null,
          dedupe: `${KIND}:${b.name}`,
          title: `${b.name}: enable request metrics (${b.total_gb.toFixed(1)} GB${b.objects ? `, ${Math.round(b.objects).toLocaleString()} objects` : ""})`,
          reason: `no metrics configuration on the bucket, so CloudWatch has no GetRequests or BytesDownloaded for it. ${c.why}. Costs about ${METRICS_USD_MONTH} USD/month in CloudWatch metrics; the analysis needs 14 days of them.`,
          before: { metrics_configuration: null }, after: { metrics_configuration: METRICS_ID },
          facts: { total_gb: b.total_gb, objects: b.objects, cost_usd_month: METRICS_USD_MONTH, cold_standard_gb: c.cold_gb, saving_ceiling_usd_month: c.ceiling_usd_month },
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

/**
 * Athena workgroups as AdvisorAnalytics {kind: query_engine}: the engine version, whether the workgroup's settings are
 * enforced, the per-query scan cutoff, where results go (WRITES_TO the bucket) and whether they are encrypted, and 30
 * days of bytes scanned from CloudWatch where the workgroup publishes metrics. Priced at list: 5 USD per TB scanned;
 * a workgroup that publishes no metrics is not priced (its scans are in the bill, not here).
 */
import { iso, metricsByGroup, num, round2, str, type CollectContext, type CollectResult, type ServiceCollector, type ServiceRow } from "../service_inventory.js";

export const ATHENA_USD_PER_TB = 5;

/** The bucket of an s3:// location. Pure. */
export const bucketOf = (loc: unknown): string | null => { const m = /^s3a?:\/\/([^/]+)/.exec(String(loc || "")); return m ? m[1] : null; };

export function athenaRow(w: any, scanned?: { sum: number; days: number }): ServiceRow {
  const account = str(w.account_id) ?? ""; const region = str(w.region) ?? "";
  const arn = `arn:aws:athena:${region}:${account}:workgroup/${w.name}`;
  const published = Boolean(w.publish_cloudwatch_metrics_enabled);
  const bytes = published && scanned && scanned.days > 0 ? scanned.sum * (30 / scanned.days) : published && scanned ? 0 : null;
  const bucket = bucketOf(w.output_location);
  return {
    native_type: "athena_workgroup", id: arn, arn, account_id: account, region, name: str(w.name), state: str(w.state), created: iso(w.creation_time), tags: null,
    monthly_usd: bytes == null ? null : round2((bytes / 1e12) * ATHENA_USD_PER_TB),
    props: {
      kind: "query_engine", engine: "athena", engine_version: str(w.effective_engine_version) ?? str(w.selected_engine_version), enforce_config: w.enforce_workgroup_configuration == null ? null : Boolean(w.enforce_workgroup_configuration),
      scan_limit_gb: num(w.bytes_scanned_cutoff_per_query) == null ? null : round2(Number(w.bytes_scanned_cutoff_per_query) / 1e9), output_location: str(w.output_location), output_encrypted: w.encryption_option ? true : bucket ? false : null,
      encryption: str(w.encryption_option), metrics_published: published, scanned_gb_30d: bytes == null ? null : round2(bytes / 1e9), requester_pays: w.requester_pays_enabled == null ? null : Boolean(w.requester_pays_enabled), description: str(w.description),
    },
    links: bucket ? [{ rel: "WRITES_TO", other: bucket, dir: "out" }] : [],
  };
}

export const athenaCollector: ServiceCollector = {
  name: "Athena workgroups",
  async collect(ctx: CollectContext): Promise<CollectResult> {
    const wgs = await ctx.select("aws_athena_workgroup", ["name", "description", "creation_time", "state", "effective_engine_version", "selected_engine_version", "enforce_workgroup_configuration", "bytes_scanned_cutoff_per_query", "publish_cloudwatch_metrics_enabled", "requester_pays_enabled", "output_location", "encryption_option", "region", "account_id"], { required: ["name"] });
    if (!wgs) return { rows: [], complete: [] };
    const key = (w: any) => `${w.account_id}|${w.region}|${w.name}`;
    // ProcessedBytes carries QueryState and QueryType besides WorkGroup: a SEARCH sums every combination
    const m = await metricsByGroup(ctx, "athena", wgs.filter((w) => w.publish_cloudwatch_metrics_enabled), (w) => [{ key: key(w), expression: `SUM(SEARCH('{AWS/Athena,QueryState,QueryType,WorkGroup} MetricName="ProcessedBytes" WorkGroup="${String(w.name).replace(/["'\\]/g, "")}"', 'Sum', 86400))` }]);
    return { rows: wgs.map((w) => athenaRow(w, m.get(key(w)))), complete: ["athena_workgroup"] };
  },
};

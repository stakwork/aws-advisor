/**
 * The pricebook: list prices for the AWS usage types this account is billed for, keyed by the usage-type names
 * Cost Explorer uses. This is the seed of the "system types with list pricing" branch of the general area of the
 * graph: every entry is public knowledge (true in any account), carries its unit and a source note, and is
 * dated. Instance hours (EC2, RDS, ElastiCache) are not listed here: they come from the price cache filled by
 * the Pricing API (src/prices.ts), one SKU at a time.
 *
 * Account-specific pricing (the Savings Plan, reservations, support tier) is an overlay applied on top of these
 * numbers by src/reconcile.ts; it never lives in the pricebook.
 */
export const PRICEBOOK_DATE = "2026-09-20";
export const PRICEBOOK_REGION = "us-east-1";

export interface PriceRule {
  /** short name shown next to every priced line */
  rule: string;
  /** USD per unit of the usage quantity Cost Explorer reports */
  unit_price: number;
  unit: string;
  /** where the number comes from or what it simplifies */
  note?: string;
}

/** A usage type that is priced per instance hour from the price cache, not from the pricebook. */
export interface SkuRule { rule: "sku"; kind: "ec2" | "rds" | "elasticache"; sku: string; ioOptimized?: boolean; multiAz?: boolean; spot?: boolean }

type Matcher = { re: RegExp; price: PriceRule | ((m: RegExpMatchArray) => PriceRule) };

const PER_GB_MONTH = "GB-Month";
const RULES: Matcher[] = [
  // NAT and transfer
  { re: /^NatGateway-Bytes$/, price: { rule: "nat_processing", unit_price: 0.045, unit: "GB", note: "NAT gateway data processing" } },
  { re: /^NatGateway-Hours$/, price: { rule: "nat_hours", unit_price: 0.045, unit: "Hrs" } },
  { re: /^DataTransfer-Regional-Bytes$/, price: { rule: "transfer_regional", unit_price: 0.01, unit: "GB", note: "cross-AZ and cross-VPC within the region, charged per direction" } },
  { re: /^DataTransfer-Out-Bytes$/, price: { rule: "transfer_out", unit_price: 0.09, unit: "GB", note: "internet egress, first 10 TB tier; the free 100 GB per month is ignored" } },
  { re: /^DataTransfer-In-Bytes$/, price: { rule: "transfer_in", unit_price: 0, unit: "GB" } },
  { re: /-AWS-(Out|In)-Bytes$/, price: { rule: "transfer_interregion", unit_price: 0.02, unit: "GB", note: "inter-region transfer" } },
  { re: /^VpcEndpoint-Hours$/, price: { rule: "vpce_hours", unit_price: 0.01, unit: "Hrs", note: "per interface endpoint per AZ" } },
  { re: /^VpcEndpoint-Bytes$/, price: { rule: "vpce_bytes", unit_price: 0.01, unit: "GB" } },
  { re: /^PublicIPv4:(InUseAddress|IdleAddress)$/, price: { rule: "public_ipv4", unit_price: 0.005, unit: "Hrs" } },
  // EBS
  { re: /^EBS:VolumeUsage\.gp3$/, price: { rule: "ebs_gp3", unit_price: 0.08, unit: PER_GB_MONTH } },
  { re: /^EBS:VolumeUsage$/, price: { rule: "ebs_gp2", unit_price: 0.10, unit: PER_GB_MONTH } },
  { re: /^EBS:VolumeUsage\.(io1|io2)$/, price: { rule: "ebs_io", unit_price: 0.125, unit: PER_GB_MONTH, note: "storage only; provisioned IOPS billed separately" } },
  { re: /^EBS:VolumeUsage\.st1$/, price: { rule: "ebs_st1", unit_price: 0.045, unit: PER_GB_MONTH } },
  { re: /^EBS:VolumeUsage\.sc1$/, price: { rule: "ebs_sc1", unit_price: 0.015, unit: PER_GB_MONTH } },
  { re: /^EBS:VolumeP-IOPS\.gp3$/, price: { rule: "ebs_gp3_iops", unit_price: 0.005, unit: "IOPS-Mo", note: "above the 3,000 included" } },
  { re: /^EBS:VolumeP-Throughput\.gp3$/, price: { rule: "ebs_gp3_throughput", unit_price: 0.04, unit: "MiBps-Mo", note: "above the 125 MiB/s included" } },
  { re: /^EBS:VolumeP-IOPS\.(io1|io2)$/, price: { rule: "ebs_io_iops", unit_price: 0.065, unit: "IOPS-Mo" } },
  { re: /^EBS:SnapshotUsage$/, price: { rule: "ebs_snapshot", unit_price: 0.05, unit: PER_GB_MONTH } },
  { re: /^CPUCredits:t4g$/, price: { rule: "cpu_credits", unit_price: 0.04, unit: "vCPU-Hours" } },
  { re: /^CPUCredits:t[23a]*$/, price: { rule: "cpu_credits", unit_price: 0.05, unit: "vCPU-Hours" } },
  // CloudWatch
  { re: /^DataProcessing-Bytes$/, price: { rule: "cw_logs_ingest", unit_price: 0.50, unit: "GB", note: "CloudWatch Logs ingestion (Standard class)" } },
  { re: /^VendedLog-Bytes$/, price: { rule: "cw_vended_logs", unit_price: 0.50, unit: "GB" } },
  { re: /^DataScanned-Bytes$/, price: { rule: "cw_logs_insights", unit_price: 0.005, unit: "GB", note: "Logs Insights queries" } },
  { re: /^TimedStorage-ByteHrs$/, price: (_m) => ({ rule: "storage_gb_month", unit_price: 0.023, unit: PER_GB_MONTH, note: "S3 Standard rate; CloudWatch Logs storage (0.03) and ECR (0.10) are matched by service below" }) },
  { re: /^CW:MetricMonitorUsage$/, price: { rule: "cw_custom_metrics", unit_price: 0.30, unit: "Metrics", note: "first 10,000 metrics tier" } },
  { re: /^CW:AlarmMonitorUsage$/, price: { rule: "cw_alarms", unit_price: 0.10, unit: "Alarms" } },
  { re: /^CW:Requests$/, price: { rule: "cw_api_requests", unit_price: 0.01 / 1000, unit: "Requests" } },
  { re: /^CW:GMD-Metrics$/, price: { rule: "cw_getmetricdata", unit_price: 0.01 / 1000, unit: "Metrics" } },
  // S3
  { re: /^TimedStorage-GIR-ByteHrs$/, price: { rule: "s3_glacier_ir", unit_price: 0.004, unit: PER_GB_MONTH } },
  { re: /^TimedStorage-SIA-ByteHrs$/, price: { rule: "s3_standard_ia", unit_price: 0.0125, unit: PER_GB_MONTH } },
  { re: /^TimedStorage-GlacierByteHrs$/, price: { rule: "s3_glacier_flexible", unit_price: 0.0036, unit: PER_GB_MONTH } },
  { re: /^TimedStorage-INT-(FA|IA)-ByteHrs$/, price: { rule: "s3_intelligent_tiering", unit_price: 0.0125, unit: PER_GB_MONTH, note: "IA tier rate used for both tiers" } },
  { re: /^Requests-Tier1$/, price: { rule: "s3_requests_put", unit_price: 0.005 / 1000, unit: "Requests" } },
  { re: /^Requests-Tier2$/, price: { rule: "s3_requests_get", unit_price: 0.0004 / 1000, unit: "Requests" } },
  // RDS and Aurora storage / IO
  { re: /^Aurora:IO-OptimizedStorageUsage$/, price: { rule: "aurora_iopt_storage", unit_price: 0.225, unit: PER_GB_MONTH } },
  { re: /^Aurora:StorageUsage$/, price: { rule: "aurora_std_storage", unit_price: 0.10, unit: PER_GB_MONTH } },
  { re: /^Aurora:StorageIOUsage$/, price: { rule: "aurora_io", unit_price: 0.20 / 1e6, unit: "IOs" } },
  { re: /^Aurora:ServerlessV2Usage$/, price: { rule: "aurora_serverless_v2", unit_price: 0.12, unit: "ACU-Hr" } },
  { re: /^Aurora:ServerlessV2IOOptimizedUsage$/, price: { rule: "aurora_serverless_v2_iopt", unit_price: 0.16, unit: "ACU-Hr" } },
  { re: /^Aurora:BackupUsage$/, price: { rule: "aurora_backup", unit_price: 0.021, unit: PER_GB_MONTH } },
  { re: /^RDS:(GP2|GP3)-Storage$/, price: { rule: "rds_gp_storage", unit_price: 0.115, unit: PER_GB_MONTH } },
  { re: /^RDS:ChargedBackupUsage$/, price: { rule: "rds_backup", unit_price: 0.095, unit: PER_GB_MONTH } },
  { re: /^RDS:(GP2|GP3)-Storage-IOPS$/, price: { rule: "rds_gp3_iops", unit_price: 0.02, unit: "IOPS-Mo" } },
  // Lambda, SQS, ELB, EKS, ECR, EFS
  { re: /^Lambda-GB-Second$/, price: { rule: "lambda_gb_second", unit_price: 0.0000166667, unit: "Lambda-GB-Second" } },
  { re: /^Lambda-GB-Second-ARM$/, price: { rule: "lambda_gb_second_arm", unit_price: 0.0000133334, unit: "Lambda-GB-Second" } },
  { re: /^Request$/, price: { rule: "lambda_requests", unit_price: 0.20 / 1e6, unit: "Requests" } },
  { re: /^Requests-RBP$/, price: { rule: "sqs_requests", unit_price: 0.40 / 1e6, unit: "Requests", note: "the free first million is ignored" } },
  { re: /^LoadBalancerUsage$/, price: { rule: "alb_hours", unit_price: 0.0225, unit: "Hrs" } },
  { re: /^LCUUsage$/, price: { rule: "alb_lcu", unit_price: 0.008, unit: "LCU-Hrs" } },
  { re: /^AmazonEKS-Hours:perCluster$/, price: { rule: "eks_cluster", unit_price: 0.10, unit: "Hrs" } },
  { re: /^AmazonEKS-Hours:extendedSupport$/, price: { rule: "eks_extended_support", unit_price: 0.50, unit: "Hrs", note: "extended Kubernetes version support, per cluster" } },
  { re: /^InsightsEvents$/, price: { rule: "cloudtrail_insights", unit_price: 0.35 / 100_000, unit: "Events" } },
  { re: /^AccessFinding-Monitored-IAM-Resources$/, price: { rule: "access_analyzer", unit_price: 0.20, unit: "Resources" } },
  { re: /^EBS:SnapshotArchiveStorage$/, price: { rule: "ebs_snapshot_archive", unit_price: 0.0125, unit: PER_GB_MONTH } },
  { re: /^KMS-Keys$/, price: { rule: "kms_keys", unit_price: 1.0, unit: "Keys" } },
  { re: /^EFS:TimedStorage-ByteHrs$|^TimedStorage-ByteHrs$/, price: { rule: "storage_gb_month", unit_price: 0.023, unit: PER_GB_MONTH } },
];

/** Service-specific overrides for usage types whose name is shared between services. */
const BY_SERVICE: { service: RegExp; usage: RegExp; price: PriceRule }[] = [
  { service: /CloudWatch/, usage: /^TimedStorage-ByteHrs$/, price: { rule: "cw_logs_storage", unit_price: 0.03, unit: PER_GB_MONTH } },
  { service: /Container Registry/, usage: /^TimedStorage-ByteHrs$/, price: { rule: "ecr_storage", unit_price: 0.10, unit: PER_GB_MONTH } },
  { service: /Elastic File System/, usage: /^TimedStorage-ByteHrs$/, price: { rule: "efs_standard", unit_price: 0.30, unit: PER_GB_MONTH } },
  { service: /Textract/, usage: /FormsQueriesTablesPagesProcessed$/, price: { rule: "textract_forms_queries_tables", unit_price: 0.07, unit: "Pages", note: "forms + queries + tables, first million pages" } },
];

/** Every distinct pricebook rule, for seeding the graph's system types (one node per rule). */
export function pricebookCatalog(): PriceRule[] {
  const seen = new Map<string, PriceRule>();
  for (const r of RULES) { const pr = typeof r.price === "function" ? r.price([""] as unknown as RegExpMatchArray) : r.price; if (!seen.has(pr.rule)) seen.set(pr.rule, pr); }
  for (const o of BY_SERVICE) if (!seen.has(o.price.rule)) seen.set(o.price.rule, o.price);
  return [...seen.values()];
}

const REGION_PREFIX: Record<string, string> = {
  USE1: "us-east-1", USE2: "us-east-2", USW1: "us-west-1", USW2: "us-west-2", CAN1: "ca-central-1", SAE1: "sa-east-1",
  EU: "eu-west-1", EUW2: "eu-west-2", EUW3: "eu-west-3", EUC1: "eu-central-1", EUN1: "eu-north-1",
  APN1: "ap-northeast-1", APN2: "ap-northeast-2", APS1: "ap-southeast-1", APS2: "ap-southeast-2", APS3: "ap-south-1",
};

/** "USE1-DataProcessing-Bytes" -> { region: us-east-1, name: DataProcessing-Bytes }; no prefix means us-east-1. */
export function splitUsageType(usageType: string): { region: string; name: string; prefixed: boolean } {
  const full = /^([a-z]{2}-[a-z]+-\d)-(.+)$/.exec(usageType);
  if (full) return { region: full[1], name: full[2], prefixed: true };
  const m = /^([A-Z]{2,4}\d?)-(.+)$/.exec(usageType);
  if (m && REGION_PREFIX[m[1]]) return { region: REGION_PREFIX[m[1]], name: m[2], prefixed: true };
  return { region: PRICEBOOK_REGION, name: usageType, prefixed: false };
}

/** Cost Explorer abbreviates sizes in RDS usage types ("db.r7g.xl", "db.r6g.2xl"); the Pricing API wants the full class. */
export function expandClass(sku: string): string {
  return sku.replace(/\.(\d*)xl$/i, (_m, n: string) => `.${n}xlarge`);
}

/** The pricebook rule for a usage type, a SKU rule for instance hours, or null when nothing prices it yet. */
export function priceRuleFor(service: string, usageType: string): PriceRule | SkuRule | null {
  const { name } = splitUsageType(usageType);
  let m: RegExpMatchArray | null;
  if ((m = /^(BoxUsage|SpotUsage|DedicatedUsage|UnusedBox):([a-z0-9]+\.[a-z0-9]+)$/i.exec(name))) return { rule: "sku", kind: "ec2", sku: m[2], spot: m[1] === "SpotUsage" };
  if ((m = /^(InstanceUsage|InstanceUsageIOOptimized|Multi-AZUsage|Multi-AZUsageIOOptimized):(db\.[a-z0-9]+\.[a-z0-9]+)$/i.exec(name))) {
    return { rule: "sku", kind: "rds", sku: expandClass(m[2]), ioOptimized: /IOOptimized/.test(m[1]), multiAz: /^Multi-AZ/.test(m[1]) };
  }
  if ((m = /^NodeUsage:(cache\.[a-z0-9]+\.[a-z0-9]+)$/i.exec(name))) return { rule: "sku", kind: "elasticache", sku: m[1] };
  for (const o of BY_SERVICE) if (o.service.test(service) && o.usage.test(name)) return o.price;
  for (const r of RULES) { const mm = r.re.exec(name); if (mm) return typeof r.price === "function" ? r.price(mm) : r.price; }
  return null;
}

/**
 * AWS Business Support: 10 % of the first 10k of monthly charges, 7 % of the next 70k, 5 % to 250k, 3 % above,
 * minimum 100 USD. Cost Explorer's "Dollar" quantity on the support line is the base it was applied to.
 */
export function businessSupport(base: number): number {
  if (base <= 0) return 0;
  const tiers: [number, number][] = [[10_000, 0.10], [70_000, 0.07], [170_000, 0.05], [Infinity, 0.03]];
  let left = base, total = 0;
  for (const [size, rate] of tiers) { const slice = Math.min(left, size); total += slice * rate; left -= slice; if (left <= 0) break; }
  return Math.max(100, total);
}

/** The month's support charge for a plan on a base of charges: Developer 3 % (min 29), Business the tiers above
 *  (min 100), Enterprise 10/7/5/3 % on larger tiers (min 15,000), Basic nothing. Unknown plans use what was billed. */
export function supportCharge(plan: "basic" | "developer" | "business" | "enterprise" | "unknown", base: number): number | null {
  if (plan === "basic") return 0;
  if (plan === "developer") return base <= 0 ? 0 : Math.max(29, base * 0.03);
  if (plan === "business") return businessSupport(base);
  if (plan === "enterprise") {
    if (base <= 0) return 0;
    const tiers: [number, number][] = [[150_000, 0.10], [350_000, 0.07], [500_000, 0.05], [Infinity, 0.03]];
    let left = base, total = 0;
    for (const [size, rate] of tiers) { const slice = Math.min(left, size); total += slice * rate; left -= slice; if (left <= 0) break; }
    return Math.max(15_000, total);
  }
  return null;
}

/** Hours in a calendar month, for the Savings Plan fee (commitment is per hour). */
export function hoursInMonth(month: string): number {
  const [y, m] = month.split("-").map(Number);
  return new Date(Date.UTC(y, m, 0)).getUTCDate() * 24;
}

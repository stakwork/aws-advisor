/**
 * Realised-saving verification, the pure part: which cost lines an approved action moves, and how a before /
 * after comparison of those lines turns into a verdict. Median daily cost over the window before the decision
 * against the median over the days after it (skipping the decision day and the next, which are mixed), scaled
 * to a month and compared with what was claimed.
 */
export interface CostScope { service: string; usage_like: string[]; note: string }

/** Cost Explorer lines an action is expected to move; null = not verifiable from the bill (a permission, a flow log). */
export function costScopeFor(actionType: string, resource: { instance_type?: string | null; region?: string | null } = {}): CostScope | null {
  const t = resource.instance_type ? `%BoxUsage:${resource.instance_type}` : "%BoxUsage:%";
  switch (actionType) {
    case "aurora_set_storage_iopt": case "aurora_set_storage_standard": return { service: "Amazon Relational Database Service", usage_like: ["%Aurora:%", "%InstanceUsageIOOptimized:%"], note: "Aurora storage, I/O and I/O-Optimized instance lines of the whole account (resource-level cost data is not enabled)" };
    case "terminate_stopped_instance": case "delete_volume": return { service: "EC2 - Other", usage_like: ["%EBS:VolumeUsage%"], note: "EBS volume GB-months of the whole account" };
    case "delete_snapshot": return { service: "EC2 - Other", usage_like: ["%EBS:SnapshotUsage%"], note: "EBS snapshot storage" };
    case "release_eip": return { service: "Amazon Virtual Private Cloud", usage_like: ["%PublicIPv4:IdleAddress%"], note: "idle public IPv4 hours" };
    case "set_log_retention": return { service: "AmazonCloudWatch", usage_like: ["%TimedStorage-ByteHrs%"], note: "CloudWatch Logs storage" };
    case "rightsize_instance": case "stop_instance": case "migrate_to_graviton": return { service: "Amazon Elastic Compute Cloud - Compute", usage_like: [t], note: resource.instance_type ? `on-demand hours of ${resource.instance_type}` : "on-demand instance hours" };
    case "add_pull_through_cache": case "add_vpc_endpoint": case "move_workload": case "reschedule_job": return { service: "EC2 - Other", usage_like: ["%NatGateway-Bytes%"], note: "NAT gateway data processing of the whole account" };
    case "change_storage_class": return { service: "Amazon Simple Storage Service", usage_like: ["%TimedStorage%"], note: "S3 storage by class" };
    default: return null;
  }
}

export interface DailyCost { day: string; usd: number }
export type Verdict = "realised" | "partial" | "none" | "increase" | "too_early" | "no_data" | "not_verifiable";
export interface Verification { verdict: Verdict; before_usd_day: number | null; after_usd_day: number | null; realised_usd_month: number | null; estimate_usd_month: number | null; ratio: number | null; days_before: number; days_after: number; note: string }

export const MIN_DAYS_AFTER = 7, SKIP_DAYS_AFTER_DECISION = 2, DAYS_BEFORE = 14;
const median = (xs: number[]) => { const s = [...xs].sort((a, b) => a - b); return s.length ? (s.length % 2 ? s[(s.length - 1) / 2] : (s[s.length / 2 - 1] + s[s.length / 2]) / 2) : NaN; };

/** Compares the scope's daily cost before and after `decidedDay` (YYYY-MM-DD). `today` bounds the after window. */
export function verify(rows: DailyCost[], decidedDay: string, estimate: number | null, today: string, opts: { early?: boolean } = {}): Verification {
  const afterFrom = addDays(decidedDay, SKIP_DAYS_AFTER_DECISION);
  const before = rows.filter((r) => r.day < decidedDay && r.day >= addDays(decidedDay, -DAYS_BEFORE)).map((r) => r.usd);
  const after = rows.filter((r) => r.day >= afterFrom && r.day < today).map((r) => r.usd);
  const base: Verification = { verdict: "no_data", before_usd_day: before.length ? median(before) : null, after_usd_day: after.length ? median(after) : null, realised_usd_month: null, estimate_usd_month: estimate, ratio: null, days_before: before.length, days_after: after.length, note: "" };
  if (!before.length) return { ...base, note: "no cost data before the decision" };
  if (after.length < MIN_DAYS_AFTER && !opts.early) return { ...base, verdict: "too_early", note: `${after.length} of ${MIN_DAYS_AFTER} days after the decision; checked again daily` };
  if (!after.length) return { ...base, verdict: "too_early", note: "no complete day after the decision yet" };
  const realised = (base.before_usd_day! - base.after_usd_day!) * 30;
  const ratio = estimate && estimate > 0 ? realised / estimate : null;
  let verdict: Verdict = "none";
  if (realised < -Math.max(5, 0.1 * (base.before_usd_day! * 30))) verdict = "increase";
  else if (ratio != null ? ratio >= 0.6 : realised > 5) verdict = "realised";
  else if (ratio != null ? ratio >= 0.2 : realised > 0) verdict = "partial";
  const note = `${before.length} days before at ${base.before_usd_day!.toFixed(2)} USD/day, ${after.length} day${after.length === 1 ? "" : "s"} after at ${base.after_usd_day!.toFixed(2)}${opts.early && after.length < MIN_DAYS_AFTER ? " (early read)" : ""}`;
  return { ...base, verdict, realised_usd_month: Math.round(realised * 100) / 100, ratio: ratio != null ? Math.round(ratio * 100) / 100 : null, note };
}

export function addDays(day: string, n: number): string {
  const d = new Date(`${day}T00:00:00Z`); d.setUTCDate(d.getUTCDate() + n); return d.toISOString().slice(0, 10);
}

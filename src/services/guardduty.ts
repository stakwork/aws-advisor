/**
 * GuardDuty: detectors as AdvisorDetector {kind: threat_detection} (status, protections on and off, how often findings
 * are published, the administrator account) and their findings as AdvisorThreatFinding events (src/graph_services.ts):
 * type, generic severity, the resource it is about (ABOUT), how often it was seen, archived or not. Findings are kept
 * 90 days like GuardDuty keeps them. Detectors are billed by events analysed, which the inventory cannot see: unpriced.
 */
import { iso, json, num, str, tagsOf, type CollectContext, type CollectResult, type ServiceCollector, type ServiceRow, type ThreatFinding } from "../service_inventory.js";

/** GuardDuty's 1-10 score in the generic words: low below 4, medium below 7, high below 9, critical from 9. Pure. */
export const severityLabel = (s: number | null): string | null => (s == null ? null : s >= 9 ? "critical" : s >= 7 ? "high" : s >= 4 ? "medium" : "low");

/** What a finding is about, from its Resource block: the id the graph uses for that kind of resource (an instance id, a bucket name, an ARN). Pure. */
export function findingResource(r: any, region: string, account: string): { type: string | null; id: string | null; name: string | null } {
  const res = json(r) || {}; const type = str(res.ResourceType);
  switch (type) {
    case "Instance": return { type, id: str(res.InstanceDetails?.InstanceId), name: str((res.InstanceDetails?.Tags || []).find((t: any) => t.Key === "Name")?.Value) };
    case "AccessKey": return { type, id: res.AccessKeyDetails?.UserName ? `arn:aws:iam::${account}:user/${res.AccessKeyDetails.UserName}` : null, name: str(res.AccessKeyDetails?.UserName) };
    case "S3Bucket": return { type, id: str(res.S3BucketDetails?.[0]?.Name), name: str(res.S3BucketDetails?.[0]?.Name) };
    case "Lambda": return { type, id: str(res.LambdaDetails?.FunctionArn), name: str(res.LambdaDetails?.FunctionName) };
    case "RDSDBInstance": return { type, id: str(res.RdsDbInstanceDetails?.DbInstanceIdentifier), name: str(res.RdsDbInstanceDetails?.DbInstanceIdentifier) };
    case "EKSCluster": return { type, id: res.EksClusterDetails?.Arn ? String(res.EksClusterDetails.Arn) : res.EksClusterDetails?.Name ? `arn:aws:eks:${region}:${account}:cluster/${res.EksClusterDetails.Name}` : null, name: str(res.EksClusterDetails?.Name) };
    case "ECSCluster": return { type, id: str(res.EcsClusterDetails?.Arn), name: str(res.EcsClusterDetails?.Name) };
    default: return { type, id: null, name: null };
  }
}

export function findingRow(f: any, detectorArn: (id: string, account: string, region: string) => string): ThreatFinding {
  const account = str(f.account_id) ?? ""; const region = str(f.region) ?? "";
  const svc = json(f.service) || {}; const sev = num(f.severity); const res = findingResource(f.resource, region, account);
  return {
    id: str(f.arn) || `arn:aws:guardduty:${region}:${account}:detector/${f.detector_id}/finding/${f.id}`, account_id: account, region, detector_id: str(f.detector_id), detector_arn: f.detector_id ? detectorArn(String(f.detector_id), account, region) : null,
    type: str(f.type), title: str(f.title), description: str(f.description), severity: sev, severity_label: severityLabel(sev), confidence: num(f.confidence),
    resource_type: res.type, resource_id: res.id, resource_name: res.name, count: num(svc.Count), first_seen_at: iso(svc.EventFirstSeen), last_seen_at: iso(svc.EventLastSeen) ?? iso(f.updated_at),
    created_at: iso(f.created_at), updated_at: iso(f.updated_at), archived: Boolean(svc.Archived),
  };
}

export function detectorRow(d: any, findings: ThreatFinding[]): ServiceRow {
  const account = str(d.account_id) ?? ""; const region = str(d.region) ?? "";
  const arn = str(d.arn) || `arn:aws:guardduty:${region}:${account}:detector/${d.detector_id}`;
  const features: any[] = Array.isArray(json(d.features)) ? json(d.features) : [];
  const open = findings.filter((f) => !f.archived);
  const admin = json(d.master_account)?.AccountId ?? json(d.master_account)?.accountId ?? null;
  return {
    native_type: "guardduty_detector", id: arn, arn, account_id: account, region, name: `GuardDuty ${region}`, state: str(d.status), created: iso(d.created_at), tags: tagsOf(d.tags), monthly_usd: null,
    props: {
      kind: "threat_detection", engine: "guardduty", detector_id: str(d.detector_id), enabled: String(d.status).toUpperCase() === "ENABLED",
      protections_on: features.filter((x) => String(x.Status).toUpperCase() === "ENABLED").map((x) => String(x.Name).toLowerCase()), protections_off: features.filter((x) => String(x.Status).toUpperCase() !== "ENABLED").map((x) => String(x.Name).toLowerCase()),
      publishing_frequency: str(d.finding_publishing_frequency), administrator: admin ? String(admin) : null,
      findings_open: open.length, findings_critical: open.filter((f) => f.severity_label === "critical").length, findings_high: open.filter((f) => f.severity_label === "high").length,
      last_finding_at: open.map((f) => f.last_seen_at).filter((x): x is string => Boolean(x)).sort().pop() ?? null,
    },
    links: [],
  };
}

export const guarddutyCollector: ServiceCollector = {
  name: "GuardDuty",
  async collect(ctx: CollectContext): Promise<CollectResult> {
    const detectors = await ctx.select("aws_guardduty_detector", ["detector_id", "arn", "status", "created_at", "finding_publishing_frequency", "features", "master_account", "tags", "region", "account_id"], { required: ["detector_id"] });
    if (!detectors) return { rows: [], complete: [], findings: null };
    const arnOf = new Map(detectors.map((d) => [`${d.account_id}|${d.region}|${d.detector_id}`, str(d.arn) || `arn:aws:guardduty:${d.region}:${d.account_id}:detector/${d.detector_id}`]));
    const detectorArn = (id: string, account: string, region: string) => arnOf.get(`${account}|${region}|${id}`) ?? `arn:aws:guardduty:${region}:${account}:detector/${id}`;
    const raw = detectors.length ? await ctx.select("aws_guardduty_finding", ["id", "arn", "detector_id", "severity", "type", "title", "description", "created_at", "updated_at", "confidence", "resource", "service", "region", "account_id"], { required: ["id", "detector_id"] }) : [];
    const findings = raw ? raw.map((f) => findingRow(f, detectorArn)) : null;
    const rows = detectors.map((d) => detectorRow(d, (findings ?? []).filter((f) => f.detector_id === d.detector_id && f.account_id === String(d.account_id ?? "") && f.region === String(d.region ?? ""))));
    return { rows, complete: ["guardduty_detector"], findings };
  },
};

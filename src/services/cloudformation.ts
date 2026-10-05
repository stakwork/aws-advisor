/**
 * CloudFormation stacks as AdvisorStack {tool: cloudformation}: status in the generic words, drift, termination
 * protection, nesting (PART_OF the parent stack) and what it manages: MANAGES edges to the resources the graph knows
 * (instances, volumes, databases, balancers, functions, buckets, tables, topics, keys, file systems, certificates,
 * workgroups, security groups, networks and subnets), with the rest counted by type. Stacks cost nothing.
 */
import { countList, iso, str, tagsOf, type CollectContext, type CollectResult, type ServiceCollector, type ServiceLink, type ServiceRow } from "../service_inventory.js";

/**
 * The node id a stack resource's physical id stands for, by its type, or null for a type the graph has no node for.
 * Network nodes come back with their label (they are not resources). Pure.
 */
export function managedTarget(type: string, physical: string, region: string, account: string): { id: string; label?: "AdvisorFilter" | "AdvisorNetwork" | "AdvisorSegment" } | null {
  if (!physical) return null;
  switch (type) {
    case "AWS::EC2::Instance": case "AWS::EC2::Volume": case "AWS::RDS::DBInstance": case "AWS::ElastiCache::CacheCluster": case "AWS::S3::Bucket": return { id: physical };
    case "AWS::ElasticLoadBalancingV2::LoadBalancer": case "AWS::SNS::Topic": case "AWS::CertificateManager::Certificate": return physical.startsWith("arn:") ? { id: physical } : null;
    case "AWS::Lambda::Function": return { id: physical.startsWith("arn:") ? physical : `arn:aws:lambda:${region}:${account}:function:${physical}` };
    case "AWS::DynamoDB::Table": return { id: physical.startsWith("arn:") ? physical : `arn:aws:dynamodb:${region}:${account}:table/${physical}` };
    case "AWS::KMS::Key": return { id: physical.startsWith("arn:") ? physical : `arn:aws:kms:${region}:${account}:key/${physical}` };
    case "AWS::EFS::FileSystem": return { id: physical.startsWith("arn:") ? physical : `arn:aws:elasticfilesystem:${region}:${account}:file-system/${physical}` };
    case "AWS::Athena::WorkGroup": return { id: `arn:aws:athena:${region}:${account}:workgroup/${physical}` };
    case "AWS::Backup::BackupVault": return { id: physical.startsWith("arn:") ? physical : `arn:aws:backup:${region}:${account}:backup-vault:${physical}` };
    case "AWS::EC2::SecurityGroup": return /^sg-/.test(physical) ? { id: physical, label: "AdvisorFilter" } : null;
    case "AWS::EC2::VPC": return { id: physical, label: "AdvisorNetwork" };
    case "AWS::EC2::Subnet": return { id: physical, label: "AdvisorSegment" };
    default: return null;
  }
}

const DRIFT: Record<string, string> = { IN_SYNC: "in_sync", DRIFTED: "drifted", NOT_CHECKED: "unknown", UNKNOWN: "unknown" };

export function stackRow(s: any, resources: any[]): ServiceRow {
  const arn = String(s.id); const account = str(s.account_id) ?? ""; const region = str(s.region) ?? "";
  const links: ServiceLink[] = [];
  if (s.parent_id) links.push({ rel: "PART_OF", other: String(s.parent_id), dir: "out" });
  let mapped = 0;
  for (const r of resources) {
    const t = managedTarget(String(r.resource_type), String(r.physical_resource_id || ""), region, account);
    if (!t || /DELETE_COMPLETE/.test(String(r.resource_status))) continue;
    mapped++;
    links.push({ rel: "MANAGES", other: t.id, dir: "out", ...(t.label ? { label: t.label } : { known_only: true }), props: { logical_id: str(r.logical_resource_id), resource_type: str(r.resource_type) } });
  }
  return {
    native_type: "cloudformation_stack", id: arn, arn, account_id: account, region, name: str(s.name), state: str(s.status), created: iso(s.creation_time), tags: tagsOf(s.tags), monthly_usd: 0,
    props: {
      tool: "cloudformation", resources: resources.length, mapped_resources: mapped, resource_types: countList(resources.map((r) => str(r.resource_type)?.replace(/^AWS::/, "") ?? null)).slice(0, 12),
      failed_resources: resources.filter((r) => /FAILED/.test(String(r.resource_status))).length, drift: DRIFT[String(s.stack_drift_status)] ?? (s.stack_drift_status ? String(s.stack_drift_status).toLowerCase() : null),
      termination_protection: s.enable_termination_protection == null ? null : Boolean(s.enable_termination_protection), nested: Boolean(s.parent_id), root_id: str(s.root_id) && s.root_id !== s.id ? str(s.root_id) : null,
      status_reason: str(s.stack_status_reason), role_arn: str(s.role_arn), description: str(s.description), updated_at: iso(s.last_updated_time),
    },
    links,
  };
}

export const cloudformationCollector: ServiceCollector = {
  name: "CloudFormation stacks",
  async collect(ctx: CollectContext): Promise<CollectResult> {
    const stacks = await ctx.select("aws_cloudformation_stack", ["id", "name", "status", "stack_status_reason", "creation_time", "last_updated_time", "parent_id", "root_id", "role_arn", "description", "enable_termination_protection", "stack_drift_status", "tags", "region", "account_id"], { required: ["id"], optional: { DescribeStackDriftDetectionStatus: ["stack_drift_status"] } });
    if (!stacks) return { rows: [], complete: [] };
    const res = stacks.length ? ((await ctx.select("aws_cloudformation_stack_resource", ["stack_id", "logical_resource_id", "physical_resource_id", "resource_type", "resource_status", "region", "account_id"], { required: ["stack_id"] })) ?? []) : [];
    const byStack = new Map<string, any[]>(); for (const r of res) { const k = String(r.stack_id); if (!byStack.has(k)) byStack.set(k, []); byStack.get(k)!.push(r); }
    return { rows: stacks.filter((s) => s.status !== "DELETE_COMPLETE").map((s) => stackRow(s, byStack.get(String(s.id)) ?? [])), complete: ["cloudformation_stack"] };
  },
};

/**
 * Inventory export: the rows the inventory sync would persist, without persisting them. Every entry of the registry
 * runs the SAME collect step the sync uses (collectXxx in src/*_inventory.ts, role_trust.ts, ...; the core SQL of
 * src/inventory.ts) and nothing here writes SQLite or Neo4j. Served by src/routes/inventory_export.ts.
 */
import { CORE_SQL, attemptInto, collectStats } from "./inventory.js";
import { collectLambdaInventory } from "./lambda_inventory.js";
import { collectDynamodbInventory } from "./dynamodb_inventory.js";
import { collectEbsInventory } from "./ebs_inventory.js";
import { collectElbInventory } from "./elb_inventory.js";
import { collectS3Inventory } from "./s3_inventory.js";
import { collectRoute53Inventory } from "./route53_inventory.js";
import { collectIamUsers } from "./iam_inventory.js";
import { collectRoleTrust } from "./role_trust.js";
import { collectSsoInventory } from "./sso_inventory.js";
import { collectNetworkInventory, gatewayRows } from "./network_inventory.js";
import { collectClusters } from "./cluster_inventory.js";
import { collectServiceInventory } from "./service_inventory.js";
import { credentialsMeta } from "./steampipe.js";

export type ExportRow = Record<string, any>;
export interface CollectOut { rows: ExportRow[]; errors: string[] }
export interface ExportType { type: string; description: string; collect: () => Promise<CollectOut> }

const msg = (e: any) => String(e?.message || e).slice(0, 300);
type Attempt = ReturnType<typeof attemptInto>;

/** Runs a collector with an error sink: a throw becomes an entry in `errors`, as do the collector's own onError calls. */
async function run(fn: (onError: (m: string) => void, attempt: Attempt) => Promise<ExportRow[]>): Promise<CollectOut> {
  const errors: string[] = [];
  try { return { rows: await fn((m) => errors.push(m), attemptInto(errors)), errors }; }
  catch (e: any) { errors.push(msg(e)); return { rows: [], errors }; }
}

const tagged = (kind: string, rows: ExportRow[] | undefined | null): ExportRow[] => (rows ?? []).map((r) => ({ resource_kind: kind, ...r }));
const q = (attempt: Attempt, key: keyof typeof CORE_SQL) => attempt(key, CORE_SQL[key]);
const by = (rows: any[] | undefined, key: string) => new Map((rows ?? []).map((r: any) => [r[key], r]));

/** A stable identity for a row: its ARN, else its natural id. Kind-prefixed for the multi-kind types. */
export function idOf(r: ExportRow): string {
  const own = r.arn ?? r.id ?? r.instance_id ?? r.volume_id ?? r.db_instance_identifier ?? r.cache_cluster_id ?? r.group_id ?? r.vpc_id ?? r.eni_id ?? r.acl_id ?? r.user_id ?? r.name;
  if (own != null && own !== "") return r.resource_kind && !String(own).startsWith("arn:") ? `${r.resource_kind}:${own}` : String(own);
  const k = Object.keys(r).find((x) => x.endsWith("_id") && r[x] != null);
  return `${r.resource_kind ?? "row"}:${k ? r[k] : JSON.stringify(r).slice(0, 120)}`;
}

const simple = (key: keyof typeof CORE_SQL) => () => run(async (_e, a) => (await q(a, key)) ?? []);

export const EXPORT_TYPES: ExportType[] = [
  { type: "ec2", description: "EC2 instances with SSM status, attached EBS volumes and 30-day CPU", collect: () => run(async (_e, attempt) => {
    const [ec2, ebs, cpu] = await Promise.all([q(attempt, "ec2"), q(attempt, "ebs"), q(attempt, "ec2_cpu")]);
    const ebsBy = by(ebs, "instance_id"), cpuBy = by(cpu, "instance_id");
    return (ec2 ?? []).map((r: any) => ({ ...r, ebs: ebsBy.get(r.instance_id) ?? null, cpu_30d: cpuBy.get(r.instance_id) ?? null }));
  }) },
  { type: "rds", description: "RDS database instances with CPU, connections, IOPS and freeable memory", collect: () => run(async (_e, attempt) => {
    const [rds, cpu, conn, iops] = await Promise.all([q(attempt, "rds"), q(attempt, "rds_cpu"), q(attempt, "rds_conn"), q(attempt, "rds_iops")]);
    const { rdsMem } = await collectStats(rds, undefined);
    const c = by(cpu, "db_instance_identifier"), n = by(conn, "db_instance_identifier"), i = by(iops, "db_instance_identifier");
    return (rds ?? []).map((r: any) => { const id = r.db_instance_identifier; return { ...r, cpu_30d: c.get(id) ?? null, connections_30d: n.get(id) ?? null, iops_30d: i.get(id) ?? null, freeable_memory_min_bytes: rdsMem.get(id) ?? null }; });
  }) },
  { type: "elasticache", description: "ElastiCache clusters with CPU, memory, evictions and connections", collect: () => run(async (_e, attempt) => {
    const [cache, cpu] = await Promise.all([q(attempt, "elasticache"), q(attempt, "cache_cpu")]);
    const { cacheMem, cacheEvict, cacheConn } = await collectStats(undefined, cache);
    const c = by(cpu, "cache_cluster_id");
    return (cache ?? []).map((r: any) => { const id = r.cache_cluster_id; return { ...r, cpu_30d: c.get(id) ?? null, memory_pct_max: cacheMem.get(id) ?? null, evictions_30d: cacheEvict.get(id) ?? null, connections_max: cacheConn.get(id) ?? null }; });
  }) },
  { type: "security_groups", description: "VPC security groups", collect: simple("sgs") },
  { type: "security_group_rules", description: "Ingress rules of every security group", collect: simple("sg_rules") },
  { type: "vpcs", description: "VPCs with their IPv6 block count", collect: simple("vpcs") },
  { type: "network_interfaces", description: "Network interfaces with the security groups they wear", collect: simple("enis") },
  { type: "network_acls", description: "Network ACLs with entries and subnets", collect: simple("nacls") },
  { type: "network", description: "Reachability objects: subnets, route tables, gateways, EIPs, interfaces, egress rules (resource_kind says which)", collect: () => run(async (_e, attempt) => {
    const parts = await collectNetworkInventory(attempt);
    const folded = ["internet_gateways", "egress_only_gateways", "nat_gateways", "peerings", "endpoints"];
    const out: ExportRow[] = [];
    for (const [k, rows] of Object.entries(parts)) if (!folded.includes(k)) out.push(...tagged(k, rows));
    out.push(...tagged("gateway", gatewayRows(parts) as ExportRow[]));
    return out;
  }) },
  { type: "clusters", description: "EKS/ECS clusters, their workloads, services, ingresses, policies and nodes (resource_kind says which)", collect: () => run(async (onError, attempt) => {
    const c: any = await collectClusters(attempt);
    for (const e of c.errors ?? []) onError(`clusters: ${e}`);
    return [...tagged("cluster", c.clusters), ...tagged("workload", c.workloads), ...tagged("service", c.services), ...tagged("ingress", c.ingresses), ...tagged("policy", c.policies), ...tagged("node", c.nodes)];
  }) },
  { type: "lambda", description: "Lambda functions with usage, config, triggers and tags", collect: () => run((e) => collectLambdaInventory(e)) },
  { type: "ebs", description: "EBS volumes with IOPS usage and attachments", collect: () => run((e) => collectEbsInventory(e)) },
  { type: "dynamodb", description: "DynamoDB tables with capacity, size and consumed units", collect: () => run((e) => collectDynamodbInventory(e)) },
  { type: "elb", description: "Load balancers (ALB/NLB/GWLB/CLB) with listeners, target groups and traffic", collect: () => run(async (e, attempt) => {
    const lookup = ((await q(attempt, "ec2")) ?? []).map((r: any) => ({ instance_id: String(r.instance_id), name: r.name ?? null, private_ip: r.private_ip ?? null }));
    return collectElbInventory(e, undefined, lookup);
  }) },
  { type: "s3", description: "S3 buckets with storage metrics", collect: () => run((e) => collectS3Inventory(e)) },
  { type: "iam", description: "IAM users with MFA, groups, policies and access keys (key ids masked)", collect: () => run((e) => collectIamUsers(e) as Promise<ExportRow[]>) },
  { type: "role_trust", description: "IAM roles with who may assume them and trust risk", collect: () => run((e) => collectRoleTrust(e)) },
  { type: "sso", description: "Identity Center users, groups and permission sets (resource_kind says which)", collect: () => run(async (e) => {
    const c: any = await collectSsoInventory(e);
    return [...tagged("user", c.users), ...tagged("group", (c.groups ?? []).map((g: any) => ({ ...g, id: g.group_id }))), ...tagged("permission_set", c.permission_sets)];
  }) },
  { type: "route53", description: "Route 53 hosted zones, records and query counts (resource_kind says which)", collect: () => run(async (e) => {
    const c: any = await collectRoute53Inventory(e);
    const rid = (r: any) => `${r.zone_id}/${r.name}/${r.type}${r.set_identifier ? `/${r.set_identifier}` : ""}`;
    return [...tagged("zone", c.zones), ...tagged("record", (c.records ?? []).map((r: any) => ({ ...r, id: rid(r) }))), ...tagged("zone_queries", (c.queries ?? []).map((r: any) => ({ ...r, id: r.zone_id })))];
  }) },
  { type: "services", description: "Certificates, topics, keys, file systems, backups, Athena workgroups, web ACLs, stacks, CloudFront, GuardDuty (resource_kind says which)", collect: () => run(async (e) => {
    const c = await collectServiceInventory(e, undefined, null);
    return Object.entries(c).flatMap(([k, rows]) => tagged(k, rows as ExportRow[]));
  }) },
];

// ---- paging -------------------------------------------------------------------------------------------------

export const DEFAULT_LIMIT = 1000;
export const MAX_LIMIT = 5000;
export class BadRequest extends Error {}

export const encodeCursor = (offset: number) => Buffer.from(JSON.stringify({ o: offset })).toString("base64url");
export function decodeCursor(c: unknown): number {
  if (c == null || c === "") return 0;
  try {
    const o = JSON.parse(Buffer.from(String(c), "base64url").toString("utf8"))?.o;
    if (Number.isInteger(o) && o >= 0) return o;
  } catch { /* fall through */ }
  throw new BadRequest("invalid cursor");
}
export function parseLimit(l: unknown): number {
  if (l == null || l === "") return DEFAULT_LIMIT;
  const n = Number(l);
  if (!Number.isInteger(n) || n < 1) throw new BadRequest("limit must be a positive integer");
  return Math.min(n, MAX_LIMIT);
}

const text = (v: unknown) => (v == null ? "" : String(v));
const cmp = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);
/** Rows with no account id belong to the primary account. */
export function inAccount(r: ExportRow, account: string, primary: string | null): boolean {
  return r.account_id ? String(r.account_id) === account : account === primary;
}

/** `complete` is false when any collector reported an error: the rows are then what could be read, not everything. */
export interface ExportResult { type: string; account: string | null; rows: ExportRow[]; nextCursor: string | null; complete: boolean; errors: string[] }

export async function exportPage(
  p: { type: unknown; account?: unknown; cursor?: unknown; limit?: unknown },
  types: ExportType[] = EXPORT_TYPES,
  primary: () => string | null = () => { try { return credentialsMeta()?.accountId ?? null; } catch { return null; } },
): Promise<ExportResult> {
  const t = types.find((x) => x.type === p.type);
  if (!t) throw new BadRequest(`unknown type ${JSON.stringify(p.type ?? null)}; valid types: ${types.map((x) => x.type).join(", ")}`);
  const offset = decodeCursor(p.cursor);
  const limit = parseLimit(p.limit);
  const account = p.account ? String(p.account) : null;
  if (account && !/^\d{12}$/.test(account)) throw new BadRequest("account must be a 12-digit account id");
  const { rows: raw, errors } = await t.collect();
  const pri = account ? primary() : null;
  const all = raw.filter((r) => !account || inAccount(r, account, pri)).map((r): ExportRow => ({ ...r, id: idOf(r) }))
    .sort((a, b) => cmp(a.id, b.id) || cmp(text(a.account_id), text(b.account_id)) || cmp(text(a.region), text(b.region)));
  const rows = all.slice(offset, offset + limit);
  const nextCursor = offset + limit < all.length ? encodeCursor(offset + limit) : null;
  return { type: t.type, account, rows, nextCursor, complete: errors.length === 0, errors };
}

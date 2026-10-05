import { db, getSetting, setSetting } from "./db.js";
import { clusterSummary } from "./cluster_inventory.js";
import { S, credentialsMeta, query } from "./steampipe.js";
import { ProbeSummary, instanceMetrics, latestProbeSummaries, summarizeProbe } from "./ssm.js";
import { PriceWant, ec2OperatingSystem, elasticachePricingEngine, ensurePrices, priceKey, rdsPricingEngine } from "./prices.js";
import { describeError, tablesIn } from "./permissions.js";
import { poolOf } from "./pools.js";
import { lambdaSummary, refreshLambdaInventory } from "./lambda_inventory.js";
import { dynamodbSummary, refreshDynamodbInventory } from "./dynamodb_inventory.js";
import { accountWhere, scopedStmt, type AccountScope } from "./scope.js";
import { ebsSummary, refreshEbsInventory } from "./ebs_inventory.js";
import { refreshS3Inventory, s3Summary } from "./s3_inventory.js";
import { refreshRoute53Inventory, route53Summary } from "./route53_inventory.js";
import { elbSummary, refreshElbInventory } from "./elb_inventory.js";
import { refreshIamInventory } from "./iam_inventory.js";
import { refreshSsoInventory } from "./sso_inventory.js";
import { refreshServiceInventory, serviceSummary } from "./service_inventory.js";

/**
 * Inventory: a snapshot of EC2 instances (with their SSM status, EBS, CPU, latest probe and list price),
 * RDS instances and ElastiCache clusters, kept in SQLite so the UI and the agent can answer "what do we
 * run, and which of it can we actually manage" without the AWS console. A handful of Steampipe queries,
 * refreshed at the end of every collection run and on every watcher sample. Rows a refresh no longer sees
 * keep their last_seen and get gone = 1, so terminated resources stay visible as history.
 */

export interface RefreshResult {
  refreshed_at: string;
  ec2: number;
  rds: number;
  elasticache: number; lambda: number; ebs: number; elb: number; s3?: number; services?: Record<string, number>; route53: { zones: number; records: number; linked: number; unmatched: number } | null;
  clusters?: { total: number; eks: number; ecs: number; readable: number; nodes: number; workloads: number };
  prices_fetched: number;
  errors: string[];
  took_ms: number;
}

const num = (v: unknown): number | null => (v == null || v === "" ? null : Number.isFinite(Number(v)) ? Number(v) : null);
const iso = (v: unknown): string | null => (v == null ? null : v instanceof Date ? v.toISOString() : String(v));
/** Same shape as SQLite's datetime('now'), so the UI's `when()` treats it as UTC. */
const sqliteNow = () => new Date().toISOString().replace("T", " ").slice(0, 19);

// ---- Steampipe queries ------------------------------------------------------------------------------

/** Security groups, VPCs (whether they have IPv6) and the network interfaces wearing each group (src/security_groups.ts). */
const SG_SQL = `select group_id, group_name, description, vpc_id, region, account_id from ${S}.aws_vpc_security_group`;
const VPC_SQL = `
  select vpc_id, region, account_id, cidr_block, is_default,
         (select count(*) from jsonb_array_elements(coalesce(ipv6_cidr_block_association_set, '[]'::jsonb)) a
           where coalesce(a -> 'Ipv6CidrBlockState' ->> 'State', 'associated') = 'associated') as ipv6_blocks
  from ${S}.aws_vpc`;
const ENI_SQL = `
  select network_interface_id as eni_id, interface_type, description, attached_instance_id as instance_id,
         coalesce((select jsonb_agg(g ->> 'GroupId') from jsonb_array_elements(coalesce(groups, '[]'::jsonb)) g), '[]'::jsonb) as group_ids
  from ${S}.aws_ec2_network_interface`;

/** The network ACLs (entries and the subnets they cover), so a port the security groups let in can still be "blocked by network ACL". */
const NACL_SQL = `
  select network_acl_id as acl_id, vpc_id, region, is_default,
         coalesce((select jsonb_agg(a ->> 'SubnetId') from jsonb_array_elements(coalesce(associations, '[]'::jsonb)) a), '[]'::jsonb) as subnets,
         coalesce(entries, '[]'::jsonb) as entries
  from ${S}.aws_vpc_network_acl`;

/** Probe 1.8: the ingress rules of every security group, so a listening port can be told internet-facing from closed (src/instance_apps.ts exposureOf). */
const SG_RULES_SQL = `
  select group_id, region, ip_protocol, from_port, to_port, cidr_ipv4, cidr_ipv6, referenced_group_id, prefix_list_id, security_group_rule_id, description
  from ${S}.aws_vpc_security_group_rule where type = 'ingress'`;

const EC2_SQL = `
  select i.instance_id, i.account_id, i.arn, i.tags ->> 'Name' as name, i.tags, i.instance_type, i.instance_state as state, i.region,
         i.placement_availability_zone as az, i.launch_time, i.private_ip_address as private_ip, i.public_ip_address as public_ip,
         i.private_dns_name as private_dns, i.public_dns_name as public_dns, i.platform, i.platform_details, i.architecture,
         i.iam_instance_profile_arn, i.vpc_id, i.subnet_id, i.root_device_name, i.root_device_type, i.image_id, i.key_name,
         i.instance_lifecycle, i.ebs_optimized, i.monitoring_state, i.state_transition_time, i.state_transition_reason,
         i.cpu_options_core_count as cpu_cores, i.cpu_options_threads_per_core as threads_per_core, i.security_groups,
         (select coalesce(jsonb_agg(a ->> 'Ipv6Address'), '[]'::jsonb) from jsonb_array_elements(coalesce(i.network_interfaces, '[]'::jsonb)) n,
            jsonb_array_elements(coalesce(n -> 'Ipv6Addresses', '[]'::jsonb)) a) as ipv6,
         s.ping_status as ssm_status, s.platform_name as ssm_platform_name, s.platform_type as ssm_platform_type,
         s.platform_version as ssm_platform_version, s.agent_version as ssm_agent_version, s.is_latest_version as ssm_agent_latest,
         s.last_ping_date_time as ssm_last_ping, s.iam_role as ssm_iam_role, s.computer_name as ssm_computer_name
  from ${S}.aws_ec2_instance i
  left join ${S}.aws_ssm_managed_instance s on s.instance_id = i.instance_id`;

const EBS_SQL = `
  select a ->> 'InstanceId' as instance_id, sum(v.size) as gb, count(*) as n,
         jsonb_agg(jsonb_build_object('volume_id', v.volume_id, 'size', v.size, 'type', v.volume_type, 'device', a ->> 'Device',
           'iops', v.iops, 'throughput', v.throughput, 'encrypted', v.encrypted, 'state', v.state,
           'delete_on_termination', a -> 'DeleteOnTermination') order by a ->> 'Device') as volumes
  from ${S}.aws_ebs_volume v, jsonb_array_elements(v.attachments) a
  where a ->> 'InstanceId' is not null
  group by 1`;

const EC2_CPU_SQL = `
  select instance_id, round(avg(maximum)::numeric, 1) as avg_max, round(avg(average)::numeric, 1) as avg, count(*) as days
  from ${S}.aws_ec2_instance_metric_cpu_utilization_daily
  where timestamp > now() - interval '30 days'
  group by 1`;

const RDS_SQL = `
  select db_instance_identifier, account_id, arn, class, engine, engine_version, multi_az, storage_type, allocated_storage, max_allocated_storage,
         iops, storage_throughput, status, region, availability_zone, create_time, db_cluster_identifier, license_model,
         endpoint_address, endpoint_port, publicly_accessible, storage_encrypted, backup_retention_period, deletion_protection,
         performance_insights_enabled, vpc_id, read_replica_source_db_instance_identifier, vpc_security_groups, tags
  from ${S}.aws_rds_db_instance`;

// RDS connections and I/O per day (30 days), from the daily metric tables; freeable memory through the generic
// statistic table (one query per instance, in the refresh below). ElastiCache: engine CPU per day, then memory
// usage, evictions and connections per cluster through the generic table.
const RDS_CONN_SQL = `
  select db_instance_identifier, round(avg(average)::numeric, 1) as avg, round(max(maximum)::numeric, 0) as max
  from ${S}.aws_rds_db_instance_metric_connections_daily where timestamp > now() - interval '30 days' group by 1`;
const RDS_IOPS_SQL = `
  select r.db_instance_identifier, round(avg(r.average)::numeric, 0) as read_avg, round(avg(w.average)::numeric, 0) as write_avg
  from ${S}.aws_rds_db_instance_metric_read_iops_daily r
  join ${S}.aws_rds_db_instance_metric_write_iops_daily w on w.db_instance_identifier = r.db_instance_identifier and w.timestamp = r.timestamp
  where r.timestamp > now() - interval '30 days' group by 1`;
const CACHE_CPU_SQL = `
  select cache_cluster_id, round(avg(maximum)::numeric, 1) as avg_max, round(avg(average)::numeric, 1) as avg, count(*) as days
  from ${S}.aws_elasticache_redis_metric_engine_cpu_utilization_daily where timestamp > now() - interval '30 days' group by 1`;
const cwStat = (namespace: string, metric: string, dimName: string, dimValue: string, region: string, stat: "Maximum" | "Minimum" | "Sum" | "Average") => `
  select ${stat.toLowerCase()} as v, timestamp from ${S}.aws_cloudwatch_metric_statistic_data_point
  where namespace = '${namespace}' and metric_name = '${metric}' and dimensions = '[{"Name":"${dimName}","Value":"${dimValue.replace(/'/g, "''")}"}]'
    and timestamp between now() - interval '30 days' and now() and period = 86400 and region = '${region.replace(/'/g, "''")}'`;

const RDS_CPU_SQL = `
  select db_instance_identifier, round(avg(maximum)::numeric, 1) as avg_max, round(avg(average)::numeric, 1) as avg, count(*) as days
  from ${S}.aws_rds_db_instance_metric_cpu_utilization_daily
  where timestamp > now() - interval '30 days'
  group by 1`;

const ELASTICACHE_SQL = `
  select cache_cluster_id, account_id, arn, cache_node_type, engine, engine_version, num_cache_nodes, cache_cluster_status, replication_group_id,
         preferred_availability_zone, region, cache_cluster_create_time, cache_subnet_group_name, transit_encryption_enabled,
         at_rest_encryption_enabled, auto_minor_version_upgrade, snapshot_retention_limit, security_groups, tags
  from ${S}.aws_elasticache_cluster`;

// ---- SQLite statements ------------------------------------------------------------------------------

const upsertEc2 = db.prepare(`
  insert into inventory_ec2(instance_id, name, instance_type, state, region, az, launch_time, private_ip, public_ip, platform, ssm_status, ssm_platform,
    ebs_gb, volumes, cpu_30d, cpu_days, probe_mem_pct, probe_at, monthly_usd, open_recs, findings, first_seen, last_seen, gone, snapshot, pool_kind, pool)
  values (@instance_id, @name, @instance_type, @state, @region, @az, @launch_time, @private_ip, @public_ip, @platform, @ssm_status, @ssm_platform,
    @ebs_gb, @volumes, @cpu_30d, @cpu_days, @probe_mem_pct, @probe_at, @monthly_usd, @open_recs, @findings, @now, @now, 0, @snapshot, @pool_kind, @pool)
  on conflict(instance_id) do update set name = excluded.name, instance_type = excluded.instance_type, state = excluded.state, region = excluded.region,
    az = excluded.az, launch_time = excluded.launch_time, private_ip = excluded.private_ip, public_ip = excluded.public_ip, platform = excluded.platform,
    ssm_status = excluded.ssm_status, ssm_platform = excluded.ssm_platform, ebs_gb = excluded.ebs_gb, volumes = excluded.volumes, cpu_30d = excluded.cpu_30d,
    cpu_days = excluded.cpu_days, probe_mem_pct = excluded.probe_mem_pct, probe_at = excluded.probe_at, monthly_usd = excluded.monthly_usd,
    open_recs = excluded.open_recs, findings = excluded.findings, last_seen = excluded.last_seen, gone = 0, snapshot = excluded.snapshot,
    pool_kind = excluded.pool_kind, pool = excluded.pool`);
/**
 * Marks the rows this refresh did not return as gone, but only in the accounts it returned rows for. An account that
 * answered with nothing is one the credentials could not see (a parent switch, a member not registered yet, a role
 * that stopped resolving), not an emptied account: its rows keep their state. Rows without an account id are the
 * primary's and follow it. Exported for the tests.
 */
export function markGone(table: "inventory_ec2" | "inventory_rds" | "inventory_elasticache", now: string, rows: { account_id?: unknown }[], onLog: (l: string) => void = () => {}, primary: string | null = primaryAccountIdOf()): number {
  const accounts = new Set(rows.map((r) => (r.account_id ? String(r.account_id) : "")));
  if (primary && accounts.has(primary)) accounts.add("");
  const list = [...accounts];
  const kept = list.length
    ? (db.prepare(`select count(*) as n from ${table} where gone = 0 and last_seen <> ? and coalesce(account_id, '') not in (${list.map(() => "?").join(",")})`).get(now, ...list) as { n: number }).n
    : (db.prepare(`select count(*) as n from ${table} where gone = 0 and last_seen <> ?`).get(now) as { n: number }).n;
  if (kept) onLog(`${table}: ${kept} row${kept === 1 ? "" : "s"} in accounts this refresh could not see, kept as they were`);
  if (!list.length) return 0;
  return db.prepare(`update ${table} set gone = 1 where last_seen <> ? and coalesce(account_id, '') in (${list.map(() => "?").join(",")})`).run(now, ...list).changes;
}
const primaryAccountIdOf = (): string | null => { try { return credentialsMeta()?.accountId ?? null; } catch { return null; } };
// Member accounts (src/accounts.ts): which account a row came from. Instance ids are unique everywhere, so EC2 keeps its
// id key and the account is written next to the upsert; RDS identifiers and cache cluster ids are unique per account
// only, so those tables are keyed on (account_id, id) (rekeyByAccount in src/db.ts) and the account is part of the upsert.
const setAccount = { ec2: db.prepare("update inventory_ec2 set account_id = ? where instance_id = ?") };
const accountOf = (r: { account_id?: unknown }): string => (r.account_id ? String(r.account_id) : "");

const upsertRds = db.prepare(`
  insert into inventory_rds(account_id, db_instance_identifier, class, engine, engine_version, multi_az, storage_type, storage_gb, status, region, created, cluster,
    cpu_30d, cpu_days, monthly_usd, open_recs, findings, first_seen, last_seen, gone, snapshot)
  values (@account_id, @db_instance_identifier, @class, @engine, @engine_version, @multi_az, @storage_type, @storage_gb, @status, @region, @created, @cluster,
    @cpu_30d, @cpu_days, @monthly_usd, @open_recs, @findings, @now, @now, 0, @snapshot)
  on conflict(account_id, db_instance_identifier) do update set class = excluded.class, engine = excluded.engine, engine_version = excluded.engine_version,
    multi_az = excluded.multi_az, storage_type = excluded.storage_type, storage_gb = excluded.storage_gb, status = excluded.status, region = excluded.region,
    created = excluded.created, cluster = excluded.cluster, cpu_30d = excluded.cpu_30d, cpu_days = excluded.cpu_days, monthly_usd = excluded.monthly_usd,
    open_recs = excluded.open_recs, findings = excluded.findings, last_seen = excluded.last_seen, gone = 0, snapshot = excluded.snapshot`);

const upsertElasticache = db.prepare(`
  insert into inventory_elasticache(account_id, cache_cluster_id, node_type, engine, engine_version, num_nodes, status, region, created, replication_group,
    monthly_usd, open_recs, findings, first_seen, last_seen, gone, snapshot)
  values (@account_id, @cache_cluster_id, @node_type, @engine, @engine_version, @num_nodes, @status, @region, @created, @replication_group,
    @monthly_usd, @open_recs, @findings, @now, @now, 0, @snapshot)
  on conflict(account_id, cache_cluster_id) do update set node_type = excluded.node_type, engine = excluded.engine, engine_version = excluded.engine_version,
    num_nodes = excluded.num_nodes, status = excluded.status, region = excluded.region, created = excluded.created, replication_group = excluded.replication_group,
    monthly_usd = excluded.monthly_usd, open_recs = excluded.open_recs, findings = excluded.findings, last_seen = excluded.last_seen, gone = 0, snapshot = excluded.snapshot`);

/** Alarm findings of the latest completed run and open recommendations, counted per resource id (exact or contained, as the MCP tools match). */
function resourceCounters() {
  const latest = db.prepare("select id from runs where provider = 'aws' and status = 'completed' order by id desc limit 1").get() as { id: number } | undefined;
  const findings = latest ? (db.prepare("select resource from findings where run_id = ? and status = 'alarm' and resource is not null").all(latest.id) as { resource: string }[]).map((r) => r.resource) : [];
  const recs = (db.prepare("select resource from recommendations where status = 'open' and resource is not null").all() as { resource: string }[]).map((r) => r.resource);
  const count = (list: string[], id: string) => list.filter((r) => r === id || r.includes(id)).length;
  return { findings: (id: string) => count(findings, id), recs: (id: string) => count(recs, id) };
}

// ---- refresh ----------------------------------------------------------------------------------------

let inflight: Promise<RefreshResult> | null = null;

/**
 * Snapshots EC2, RDS and ElastiCache into the inventory tables. Concurrent calls share one refresh. `dns` also
 * refreshes the Route 53 links (every hosted zone's records plus a dozen lookups, and one API call per Lambda
 * function for its URL): the collection run and the Refresh button ask for it, the half-hourly watcher does not.
 */
export function refreshInventory(opts: { dns?: boolean } = {}): Promise<RefreshResult> {
  if (!inflight) inflight = doRefresh(opts).finally(() => { inflight = null; });
  return inflight;
}

async function doRefresh(opts: { dns?: boolean }): Promise<RefreshResult> {
  const t0 = Date.now();
  const now = sqliteNow();
  const errors: string[] = [];
  const attempt = async (what: string, sql: string): Promise<any[] | undefined> => {
    try { return await query<any>(sql); } catch (e: any) { errors.push(`${what}: ${describeError(e, `inventory ${what} (${tablesIn(sql).join(", ")})`, 300)}`); return undefined; }
  };

  const [ec2Rows, ebsRows, ec2Cpu, rdsRows, rdsCpu, cacheRows, rdsConn, rdsIops, cacheCpu, sgRules, nacls, sgRows, vpcRows, eniRows] = await Promise.all([
    attempt("ec2", EC2_SQL),
    attempt("ebs", EBS_SQL),
    attempt("ec2 cpu", EC2_CPU_SQL),
    attempt("rds", RDS_SQL),
    attempt("rds cpu", RDS_CPU_SQL),
    attempt("elasticache", ELASTICACHE_SQL),
    attempt("rds connections", RDS_CONN_SQL),
    attempt("rds iops", RDS_IOPS_SQL),
    attempt("elasticache cpu", CACHE_CPU_SQL),
    attempt("security group rules", SG_RULES_SQL),
    attempt("network ACLs", NACL_SQL),
    attempt("security groups", SG_SQL),
    attempt("VPCs", VPC_SQL),
    attempt("network interfaces", ENI_SQL),
  ]);
  if (sgRules) { try { const { replaceIngressRules } = await import("./instance_apps.js"); replaceIngressRules(sgRules.map((r: any) => ({ group_id: String(r.group_id), region: r.region ?? null, ip_protocol: r.ip_protocol ?? null, from_port: r.from_port == null ? null : Number(r.from_port), to_port: r.to_port == null ? null : Number(r.to_port), cidr_ipv4: r.cidr_ipv4 ?? null, cidr_ipv6: r.cidr_ipv6 ?? null, referenced_group_id: r.referenced_group_id ?? null, prefix_list_id: r.prefix_list_id ?? null, rule_id: r.security_group_rule_id ?? null, description: r.description || null }))); } catch (e: any) { errors.push(`security group rules: ${e?.message || e}`); } }
  if (nacls) { try { const { replaceNacls } = await import("./instance_apps.js"); replaceNacls(nacls.map((r: any) => ({ acl_id: String(r.acl_id), vpc_id: r.vpc_id ?? null, region: r.region ?? null, is_default: Boolean(r.is_default), subnets: Array.isArray(r.subnets) ? r.subnets.filter(Boolean).map(String) : [], entries: Array.isArray(r.entries) ? r.entries : [] }))); } catch (e: any) { errors.push(`network ACLs: ${String(e?.message || e).slice(0, 200)}`); } }
  if (sgRows || vpcRows || eniRows) {
    try {
      const { replaceSecurityGroups, syncSecurityGroupRecommendations } = await import("./security_groups.js");
      replaceSecurityGroups(
        sgRows ? sgRows.map((r: any) => ({ group_id: String(r.group_id), group_name: r.group_name ?? null, description: r.description ?? null, vpc_id: r.vpc_id ?? null, region: r.region ?? null, account_id: r.account_id ?? null })) : null,
        vpcRows ? vpcRows.map((r: any) => ({ vpc_id: String(r.vpc_id), region: r.region ?? null, account_id: r.account_id ?? null, cidr_block: r.cidr_block ?? null, is_default: Boolean(r.is_default), ipv6_blocks: Number(r.ipv6_blocks ?? 0) })) : null,
        eniRows ? eniRows.map((r: any) => ({ eni_id: String(r.eni_id), interface_type: r.interface_type ?? null, description: r.description ?? null, instance_id: r.instance_id ?? null, group_ids: Array.isArray(r.group_ids) ? r.group_ids.filter(Boolean).map(String) : [] })) : null,
      );
      // after the ports' rules and the VPCs are both in: a dormant IPv6 rule is a recommendation (rule sg_dormant_ipv6)
      if (sgRules && vpcRows && sgRows) syncSecurityGroupRecommendations();
    } catch (e: any) { errors.push(`security groups: ${String(e?.message || e).slice(0, 200)}`); }
  }
  // the network objects behind reachability (src/network_inventory.ts): subnets, route tables, gateways, EIPs, interfaces, egress rules
  try { const { refreshNetworkInventory } = await import("./network_inventory.js"); await refreshNetworkInventory(attempt); }
  catch (e: any) { errors.push(`network inventory: ${String(e?.message || e).slice(0, 200)}`); }
  // the clusters and the workloads inside them (src/cluster_inventory.ts): EKS through the cluster API, ECS through Steampipe
  try { const { refreshClusters } = await import("./cluster_inventory.js"); const c = await refreshClusters(attempt); if (c.errors.length) errors.push(`clusters: ${c.errors.join("; ").slice(0, 300)}`); }
  catch (e: any) { errors.push(`clusters: ${String(e?.message || e).slice(0, 200)}`); }
  // per-resource CloudWatch statistics the daily tables do not cover (a handful of resources, one call each)
  const rdsMem = new Map<string, number>(); const cacheMem = new Map<string, number>(); const cacheEvict = new Map<string, number>(); const cacheConn = new Map<string, number>();
  const stat = async (sql: string, reduce: (vs: number[]) => number): Promise<number | null> => { try { const rows = await query<{ v: string | null }>(sql); const vs = rows.map((r) => Number(r.v)).filter(Number.isFinite); return vs.length ? reduce(vs) : null; } catch { return null; } };
  const minOf = (vs: number[]) => Math.min(...vs), maxOf = (vs: number[]) => Math.max(...vs), sumOf = (vs: number[]) => vs.reduce((a, b) => a + b, 0);
  await Promise.all([
    ...(rdsRows || []).map(async (r: any) => { const v = await stat(cwStat("AWS/RDS", "FreeableMemory", "DBInstanceIdentifier", r.db_instance_identifier, r.region, "Minimum"), minOf); if (v != null) rdsMem.set(r.db_instance_identifier, v); }),
    ...(cacheRows || []).map(async (r: any) => {
      const [m, e, c] = await Promise.all([
        stat(cwStat("AWS/ElastiCache", "DatabaseMemoryUsagePercentage", "CacheClusterId", r.cache_cluster_id, r.region, "Maximum"), maxOf),
        stat(cwStat("AWS/ElastiCache", "Evictions", "CacheClusterId", r.cache_cluster_id, r.region, "Sum"), sumOf),
        stat(cwStat("AWS/ElastiCache", "CurrConnections", "CacheClusterId", r.cache_cluster_id, r.region, "Maximum"), maxOf),
      ]);
      if (m != null) cacheMem.set(r.cache_cluster_id, m); if (e != null) cacheEvict.set(r.cache_cluster_id, e); if (c != null) cacheConn.set(r.cache_cluster_id, c);
    }),
  ]);
  const rdsConnById = new Map<string, any>((rdsConn || []).map((r: any) => [r.db_instance_identifier, r]));
  const rdsIopsById = new Map<string, any>((rdsIops || []).map((r: any) => [r.db_instance_identifier, r]));
  const cacheCpuById = new Map<string, any>((cacheCpu || []).map((r: any) => [r.cache_cluster_id, r]));

  // Prices: one distinct SKU at a time, cache first.
  const wants: PriceWant[] = [];
  const ec2Want = (r: any): PriceWant => {
    const os = ec2OperatingSystem(r.platform, r.platform_details);
    return { kind: "ec2", sku: r.instance_type, region: r.region, engine: os, spec: { kind: "ec2", instance_type: r.instance_type, region: r.region, operating_system: os } };
  };
  const rdsWant = (r: any): PriceWant | null => {
    const engine = rdsPricingEngine(r.engine);
    if (!engine) return null;
    const aurora = /^aurora/i.test(String(r.engine));
    const deployment = r.multi_az && !aurora ? "Multi-AZ" : "Single-AZ";
    const ioOptimized = aurora && r.storage_type === "aurora-iopt1";
    return { kind: "rds", sku: r.class, region: r.region, engine: `${engine}${deployment === "Multi-AZ" ? " Multi-AZ" : ""}${ioOptimized ? " IO-Optimized" : ""}`, ioOptimized,
      spec: { kind: "rds", instance_type: r.class, region: r.region, engine, deployment } };
  };
  const cacheWant = (r: any): PriceWant | null => {
    const engine = elasticachePricingEngine(r.engine);
    if (!engine) return null;
    return { kind: "elasticache", sku: r.cache_node_type, region: r.region, engine, spec: { kind: "elasticache", instance_type: r.cache_node_type, region: r.region, engine } };
  };
  for (const r of ec2Rows || []) if (r.instance_type && r.region) wants.push(ec2Want(r));
  for (const r of rdsRows || []) { const w = rdsWant(r); if (w) wants.push(w); }
  for (const r of cacheRows || []) { const w = cacheWant(r); if (w) wants.push(w); }
  const { prices, fetched } = await ensurePrices(wants, (m) => errors.push(m));
  const priceOf = (w: PriceWant | null) => (w ? prices.get(priceKey(w)) ?? null : null);

  const counters = resourceCounters();
  const probes = latestProbeSummaries();
  const ebsByInstance = new Map<string, any>((ebsRows || []).map((r: any) => [r.instance_id, r]));
  const ec2CpuById = new Map<string, any>((ec2Cpu || []).map((r: any) => [r.instance_id, r]));
  const rdsCpuById = new Map<string, any>((rdsCpu || []).map((r: any) => [r.db_instance_identifier, r]));

  let ec2 = 0, rds = 0, elasticache = 0;
  db.transaction(() => {
    if (ec2Rows) {
      for (const r of ec2Rows) {
        const ebs = ebsByInstance.get(r.instance_id);
        const cpu = ec2CpuById.get(r.instance_id);
        const probe: ProbeSummary | undefined = probes[r.instance_id];
        const want = ec2Want(r);
        const price = priceOf(want);
        const pool = poolOf(r.tags || {});
        const snapshot = {
          identity: { instance_id: r.instance_id, arn: r.arn, name: r.name, instance_type: r.instance_type, state: r.state, region: r.region, az: r.az, launch_time: iso(r.launch_time),
            platform: r.platform || null, platform_details: r.platform_details, architecture: r.architecture, image_id: r.image_id, key_name: r.key_name, instance_lifecycle: r.instance_lifecycle || "on-demand",
            ebs_optimized: r.ebs_optimized, monitoring_state: r.monitoring_state, state_transition_time: iso(r.state_transition_time), state_transition_reason: r.state_transition_reason || null,
            cpu_cores: num(r.cpu_cores), threads_per_core: num(r.threads_per_core), iam_instance_profile_arn: r.iam_instance_profile_arn },
          network: { private_ip: r.private_ip, public_ip: r.public_ip, ipv6: Array.isArray(r.ipv6) ? r.ipv6.filter(Boolean) : [], private_dns: r.private_dns, public_dns: r.public_dns, vpc_id: r.vpc_id, subnet_id: r.subnet_id, security_groups: r.security_groups || [] },
          storage: { root_device_name: r.root_device_name, root_device_type: r.root_device_type, ebs_gb: num(ebs?.gb) ?? 0, volumes: ebs?.volumes || [] },
          ssm: r.ssm_status ? { ping_status: r.ssm_status, platform_name: r.ssm_platform_name, platform_type: r.ssm_platform_type, platform_version: r.ssm_platform_version, agent_version: r.ssm_agent_version,
            agent_latest: r.ssm_agent_latest, last_ping: iso(r.ssm_last_ping), iam_role: r.ssm_iam_role, computer_name: r.ssm_computer_name } : null,
          tags: r.tags || {},
          pool,
          utilisation: { cpu_30d_avg_max: num(cpu?.avg_max), cpu_30d_avg: num(cpu?.avg), cpu_days: num(cpu?.days) ?? 0, probe: probe || null },
          price: price ? { hourly: price.hourly, monthly: price.monthly, operating_system: want.engine, fetched_at: price.fetched_at } : null,
        };
        upsertEc2.run({
          instance_id: r.instance_id, name: r.name || null, instance_type: r.instance_type, state: r.state, region: r.region, az: r.az, launch_time: iso(r.launch_time),
          private_ip: r.private_ip || null, public_ip: r.public_ip || null, platform: r.platform_details || r.platform || null,
          ssm_status: r.ssm_status || null, ssm_platform: r.ssm_status ? [r.ssm_platform_name, r.ssm_platform_version].filter(Boolean).join(" ") || r.ssm_platform_type || null : null,
          ebs_gb: num(ebs?.gb) ?? 0, volumes: num(ebs?.n) ?? 0, cpu_30d: num(cpu?.avg_max), cpu_days: num(cpu?.days) ?? 0,
          probe_mem_pct: probe?.memory_used_pct ?? null, probe_at: probe?.collected_at ?? null, monthly_usd: price?.monthly ?? null,
          open_recs: counters.recs(r.instance_id), findings: counters.findings(r.instance_id), now, snapshot: JSON.stringify(snapshot),
          pool_kind: pool?.kind ?? null, pool: pool?.name ?? null,
        });
        if (r.account_id) setAccount.ec2.run(String(r.account_id), r.instance_id);
        ec2++;
      }
      markGone("inventory_ec2", now, ec2Rows, (l) => console.log(`[inventory] ${l}`));
    }
    if (rdsRows) {
      for (const r of rdsRows) {
        const cpu = rdsCpuById.get(r.db_instance_identifier);
        const want = rdsWant(r);
        const price = priceOf(want);
        const id = r.db_instance_identifier;
        const snapshot = {
          identity: { db_instance_identifier: id, arn: r.arn, class: r.class, engine: r.engine, engine_version: r.engine_version, status: r.status, region: r.region, availability_zone: r.availability_zone,
            multi_az: r.multi_az, created: iso(r.create_time), cluster: r.db_cluster_identifier, license_model: r.license_model, read_replica_source: r.read_replica_source_db_instance_identifier,
            deletion_protection: r.deletion_protection, backup_retention_days: num(r.backup_retention_period), performance_insights: r.performance_insights_enabled },
          storage: { storage_type: r.storage_type, allocated_gb: num(r.allocated_storage), max_allocated_gb: num(r.max_allocated_storage), iops: num(r.iops), throughput: num(r.storage_throughput), encrypted: r.storage_encrypted },
          network: { endpoint: r.endpoint_address, port: num(r.endpoint_port), publicly_accessible: r.publicly_accessible, vpc_id: r.vpc_id,
            security_groups: (Array.isArray(r.vpc_security_groups) ? r.vpc_security_groups : []).map((g: any) => String(g?.VpcSecurityGroupId ?? g?.vpc_security_group_id ?? g ?? "")).filter((g: string) => /^sg-/.test(g)) },
          tags: r.tags || {},
          utilisation: { cpu_30d_avg_max: num(cpu?.avg_max), cpu_30d_avg: num(cpu?.avg), cpu_days: num(cpu?.days) ?? 0,
            connections_avg: num(rdsConnById.get(id)?.avg), connections_max: num(rdsConnById.get(id)?.max),
            read_iops_avg: num(rdsIopsById.get(id)?.read_avg), write_iops_avg: num(rdsIopsById.get(id)?.write_avg),
            freeable_memory_min_gb: rdsMem.has(id) ? Math.round((rdsMem.get(id)! / 1e9) * 100) / 100 : null },
          price: price ? { hourly: price.hourly, monthly: price.monthly, pricing_engine: want!.engine, fetched_at: price.fetched_at } : null,
        };
        upsertRds.run({
          account_id: accountOf(r), db_instance_identifier: id, class: r.class, engine: r.engine, engine_version: r.engine_version, multi_az: r.multi_az ? 1 : 0, storage_type: r.storage_type,
          storage_gb: num(r.allocated_storage), status: r.status, region: r.region, created: iso(r.create_time), cluster: r.db_cluster_identifier || null,
          cpu_30d: num(cpu?.avg_max), cpu_days: num(cpu?.days) ?? 0, monthly_usd: price?.monthly ?? null,
          open_recs: counters.recs(id), findings: counters.findings(id), now, snapshot: JSON.stringify(snapshot),
        });
        rds++;
      }
      markGone("inventory_rds", now, rdsRows, (l) => console.log(`[inventory] ${l}`));
    }
    if (cacheRows) {
      for (const r of cacheRows) {
        const want = cacheWant(r);
        const price = priceOf(want);
        const nodes = num(r.num_cache_nodes) ?? 1;
        const monthly = price?.monthly == null ? null : Math.round(price.monthly * nodes * 100) / 100;
        const id = r.cache_cluster_id;
        const ccpu = cacheCpuById.get(id);
        const snapshot = {
          utilisation: { cpu_30d_avg_max: num(ccpu?.avg_max), cpu_30d_avg: num(ccpu?.avg), cpu_days: num(ccpu?.days) ?? 0, memory_pct_max: cacheMem.has(id) ? Math.round(cacheMem.get(id)! * 10) / 10 : null, evictions_30d: cacheEvict.has(id) ? cacheEvict.get(id)! : null, connections_max: cacheConn.has(id) ? cacheConn.get(id)! : null },
          identity: { cache_cluster_id: id, arn: r.arn, node_type: r.cache_node_type, engine: r.engine, engine_version: r.engine_version, num_nodes: nodes, status: r.cache_cluster_status,
            replication_group: r.replication_group_id, region: r.region, availability_zone: r.preferred_availability_zone, created: iso(r.cache_cluster_create_time),
            subnet_group: r.cache_subnet_group_name, transit_encryption: r.transit_encryption_enabled, at_rest_encryption: r.at_rest_encryption_enabled,
            auto_minor_version_upgrade: r.auto_minor_version_upgrade, snapshot_retention_days: num(r.snapshot_retention_limit) },
          network: { security_groups: (Array.isArray(r.security_groups) ? r.security_groups : []).map((g: any) => String(g?.SecurityGroupId ?? g?.security_group_id ?? g ?? "")).filter((g: string) => /^sg-/.test(g)) },
          tags: r.tags || {},
          price: price ? { hourly_per_node: price.hourly, monthly_per_node: price.monthly, monthly: monthly, pricing_engine: want!.engine, fetched_at: price.fetched_at } : null,
        };
        upsertElasticache.run({
          account_id: accountOf(r), cache_cluster_id: id, node_type: r.cache_node_type, engine: r.engine, engine_version: r.engine_version, num_nodes: nodes, status: r.cache_cluster_status,
          region: r.region, created: iso(r.cache_cluster_create_time), replication_group: r.replication_group_id || null, monthly_usd: monthly,
          open_recs: counters.recs(id), findings: counters.findings(id), now, snapshot: JSON.stringify(snapshot),
        });
        elasticache++;
      }
      markGone("inventory_elasticache", now, cacheRows, (l) => console.log(`[inventory] ${l}`));
      // memory pressure on a cache is an alert: at 90 % of DatabaseMemoryUsagePercentage keys start being evicted
      const openCache = db.prepare("select id from alerts where kind = 'cache_memory_high' and resource = ? and acknowledged = 0 limit 1");
      const insCache = db.prepare("insert into alerts(kind, resource, message, details) values ('cache_memory_high', ?, ?, ?)");
      const ackCache = db.prepare("update alerts set acknowledged = 1, acknowledged_by = 'system' where kind = 'cache_memory_high' and resource = ? and acknowledged = 0");
      // an RDS instance whose freeable memory touched half a gigabyte is one query away from swapping
      const openRds = db.prepare("select id from alerts where kind = 'rds_memory_low' and resource = ? and acknowledged = 0 limit 1");
      const insRds = db.prepare("insert into alerts(kind, resource, message, details) values ('rds_memory_low', ?, ?, ?)");
      const ackRds = db.prepare("update alerts set acknowledged = 1, acknowledged_by = 'system' where kind = 'rds_memory_low' and resource = ? and acknowledged = 0");
      for (const [id, bytes] of rdsMem) {
        const gbFree = bytes / 1e9; const open = openRds.get(id);
        const low = gbFree < 0.5 || (open && gbFree < 1);
        if (low && !open) { const msg = `${id}: freeable memory fell to ${gbFree.toFixed(2)} GB in the last 30 days; the instance swaps or refuses connections when it runs out`; insRds.run(id, msg, JSON.stringify({ summary: msg, db_instance_identifier: id, freeable_memory_min_gb: gbFree })); }
        if (!low && open) ackRds.run(id);
      }
      for (const [id, m] of cacheMem) {
        const open = openCache.get(id); const evictions = cacheEvict.get(id) ?? 0;
        const high = m >= 90 || (open && m >= 85);
        if (high && !open) { const msg = `${id}: cache memory peaked at ${m.toFixed(0)}% in the last 30 days${evictions ? `, ${Math.round(evictions).toLocaleString()} evictions` : ""}`; insCache.run(id, msg, JSON.stringify({ summary: msg, cache_cluster_id: id, memory_pct_max: m, evictions_30d: evictions })); }
        if (!high && open) ackCache.run(id);
      }
    }
  })();

  const lambda = await refreshLambdaInventory((m) => errors.push(m));
  const dynamodb = await refreshDynamodbInventory((m) => errors.push(m), (l) => console.log(`[inventory] ${l}`));
  console.log(`[inventory] dynamodb: ${dynamodb} table(s)`);
  const ebsVolumes = await refreshEbsInventory((m) => errors.push(m));
  // after EC2, so instance and IP targets resolve against the rows just written
  const elb = await refreshElbInventory((m) => errors.push(m), (l) => console.log(`[inventory] ${l}`));
  await refreshIamInventory((m) => errors.push(m), (l) => console.log(`[inventory] ${l}`));
  // Identity Center from the parent's credentials: a few dozen calls and the home region's sign-in events; after the trail so the per-account activity reads the stored writes
  try { await refreshSsoInventory((m) => errors.push(m), (l) => console.log(`[identity-center] ${l}`)); } catch (e: any) { errors.push(`Identity Center: ${e?.message || e}`); }
  // the buckets too (the storage metrics are a few CloudWatch calls per region and account), so an account registered
  // today shows its buckets after this refresh rather than after the next nightly job
  let s3 = 0;
  try { const r = await refreshS3Inventory((l) => console.log(`[inventory] ${l}`)); s3 = r.buckets; errors.push(...r.errors); } catch (e: any) { errors.push(`S3 buckets: ${e?.message || e}`); }
  // certificates, topics, keys, file systems, backups, workgroups, web ACLs, stacks and detectors (src/services/): after the
  // balancers, buckets and functions, so their links land on rows this refresh wrote
  let services: Record<string, number> = {};
  try { services = await refreshServiceInventory((m) => errors.push(m), (l) => console.log(`[inventory] ${l}`), primaryAccountIdOf()); console.log(`[inventory] services: ${Object.entries(services).map(([k, v]) => `${v} ${k}`).join(", ") || "none"}`); }
  catch (e: any) { errors.push(`services: ${e?.message || e}`); }
  // last, so the DNS links read the EC2, RDS, S3 and Lambda rows just written
  let route53: RefreshResult["route53"] = null;
  if (opts.dns) { const r53 = await refreshRoute53Inventory(); errors.push(...r53.errors); route53 = { zones: r53.zones, records: r53.records, linked: r53.linked, unmatched: r53.unmatched }; }
  if (ec2Rows || rdsRows || cacheRows) setSetting("inventory_refreshed_at", now);
  return { refreshed_at: now, ec2, rds, elasticache, lambda, ebs: ebsVolumes, elb, s3, services, route53, prices_fetched: fetched, errors, took_ms: Date.now() - t0 };
}

export const inventoryRefreshedAt = () => getSetting("inventory_refreshed_at");

// ---- readers ----------------------------------------------------------------------------------------

export type SsmFilter = "online" | "lost" | "unmanaged" | "managed";

export interface Ec2Filter { state?: string; ssm?: string; q?: string; sort?: string; gone?: boolean; limit?: number; scope?: AccountScope | null }

const EC2_SORTS = ["name", "instance_id", "instance_type", "state", "ssm_status", "pool_kind", "cpu_30d", "probe_mem_pct", "ebs_gb", "monthly_usd", "launch_time", "open_recs", "findings", "last_seen", "first_seen", "region"];
const RDS_SORTS = ["db_instance_identifier", "class", "engine", "status", "storage_gb", "cpu_30d", "monthly_usd", "created", "open_recs", "findings", "last_seen"];
const CACHE_SORTS = ["cache_cluster_id", "node_type", "engine", "status", "num_nodes", "monthly_usd", "created", "open_recs", "findings", "last_seen"];

/** "-monthly_usd" → monthly_usd desc; unknown columns fall back to the default so nothing user-supplied reaches the SQL. */
export function parseSort(sort: string | undefined, allowed: string[], fallback: string): { column: string; dir: "asc" | "desc" } {
  const s = (sort || "").trim();
  const desc = s.startsWith("-");
  const column = desc ? s.slice(1) : s;
  if (allowed.includes(column)) return { column, dir: desc ? "desc" : "asc" };
  return { column: fallback, dir: "asc" };
}

const orderBy = (sort: string | undefined, allowed: string[], fallback: string, tiebreak: string) => {
  const { column, dir } = parseSort(sort, allowed, fallback);
  return `order by ${column} is null, ${column} ${dir}, ${tiebreak}`;
};

const SSM_WHERE: Record<SsmFilter, string> = {
  online: "ssm_status = 'Online'",
  lost: "ssm_status is not null and ssm_status <> 'Online'",
  unmanaged: "ssm_status is null",
  managed: "ssm_status is not null",
};

const EC2_COLUMNS = "instance_id, name, instance_type, state, region, az, launch_time, private_ip, public_ip, platform, ssm_status, ssm_platform, ebs_gb, volumes, cpu_30d, cpu_days, probe_mem_pct, probe_at, monthly_usd, open_recs, findings, first_seen, last_seen, gone, pool_kind, pool";

/** Pools with their running members, for the agent and the observe task. */
export function poolSummary() {
  const rows = db.prepare(`select coalesce(pool_kind, '') as pool_kind, coalesce(pool, '') as pool, count(*) as members, group_concat(distinct instance_type) as types,
      round(sum(coalesce(monthly_usd, 0))) as monthly_usd, sum(case when datetime(launch_time) > datetime('now', '-1 day') then 1 else 0 end) as launched_24h
    from inventory_ec2 where gone = 0 and state = 'running' group by 1, 2 order by monthly_usd desc`).all() as any[];
  const churn = db.prepare("select resource as pool, details from alerts where kind = 'node_churn' and date(created_at) = date('now')").all() as { pool: string; details: string }[];
  const churnByPool = new Map(churn.map((c) => { let d: any = {}; try { d = JSON.parse(c.details); } catch { /* ignore */ } return [c.pool, { launched: d.launched ?? null, terminated: d.terminated ?? null }]; }));
  const pools = rows.filter((r) => r.pool_kind).map((r) => ({ kind: r.pool_kind, name: r.pool, members: r.members, instance_types: String(r.types || "").split(","), monthly_usd_list: r.monthly_usd, launched_24h: r.launched_24h, churn_today: [...churnByPool.entries()].find(([k]) => k.endsWith(r.pool))?.[1] ?? null }));
  const standalone = rows.find((r) => !r.pool_kind);
  return { refreshed_at: inventoryRefreshedAt(), pools, standalone: standalone ? { members: standalone.members, monthly_usd_list: standalone.monthly_usd } : { members: 0, monthly_usd_list: 0 } };
}

export function listEc2(f: Ec2Filter = {}) {
  const where: string[] = []; const params: unknown[] = [];
  if (f.scope) { const a = accountWhere(f.scope); where.push(a.sql); params.push(...a.params); }
  if (!f.gone) where.push("gone = 0");
  if (f.state) { where.push("state = ?"); params.push(f.state); }
  if (f.ssm && f.ssm in SSM_WHERE) where.push(SSM_WHERE[f.ssm as SsmFilter]);
  if (f.q) { where.push("(name like ? or instance_id like ? or instance_type like ? or private_ip like ? or public_ip like ?)"); params.push(...Array(5).fill(`%${f.q}%`)); }
  const order = f.sort ? orderBy(f.sort, EC2_SORTS, "name", "instance_id") : "order by gone, case state when 'running' then 0 when 'stopped' then 1 else 2 end, name, instance_id";
  const limit = Math.min(5000, Math.max(1, f.limit || 5000));
  return db.prepare(`select ${EC2_COLUMNS} from inventory_ec2 ${where.length ? `where ${where.join(" and ")}` : ""} ${order} limit ?`).all(...params, limit) as Record<string, unknown>[];
}

const safeJson = (s: unknown) => { if (typeof s !== "string") return s; try { return JSON.parse(s); } catch { return s; } };

/** One instance with its full snapshot, the findings that mention it, its recommendations and probe history. */
export function ec2Detail(instanceId: string) {
  const row = db.prepare("select * from inventory_ec2 where instance_id = ?").get(instanceId) as Record<string, unknown> | undefined;
  if (!row) return null;
  const latest = db.prepare("select id from runs where provider = 'aws' and status = 'completed' order by id desc limit 1").get() as { id: number } | undefined;
  const findings = latest
    ? db.prepare("select id, run_id, source, benchmark, control_id, control_title, status, resource, reason, region from findings where run_id = ? and (resource = ? or resource like ?) order by control_id").all(latest.id, instanceId, `%${instanceId}%`)
    : [];
  const recommendations = db.prepare("select id, rule, source, title, action_type, est_monthly_saving, tier, confidence, status, decided_at, decided_by, decision_reason, run_id, updated_at from recommendations where resource = ? or resource like ? order by updated_at desc")
    .all(instanceId, `%${instanceId}%`);
  const probes = instanceMetrics(instanceId, 20).map((p) => ({ id: p.id, collected_at: p.collected_at, summary: summarizeProbe(p.data), data: p.data }));
  // used and free per attached volume, as the latest probe credited them (src/ebs_inventory.ts)
  const volume_usage = Object.fromEntries((db.prepare("select volume_id, total_bytes, used_bytes, used_pct, usage_at from inventory_ebs where instance_id = ? and used_pct is not null").all(instanceId) as any[]).map((v) => [v.volume_id, v]));
  return { ...row, findings_count: row.findings, snapshot: safeJson(row.snapshot), findings_run_id: latest?.id ?? null, findings, recommendations, probes, volume_usage };
}

/**
 * Mirrors a tag the advisor just wrote on an instance (src/actions/consent_tag.ts: AdvisorAutoPark, advisor:hibernate)
 * into the stored snapshot, so the page reads it back at once instead of after the next collection, which reads the
 * live tags from EC2 anyway. null removes the tag. False when the instance is not in the inventory.
 */
export function patchEc2Tag(instanceId: string, key: string, value: string | null): boolean {
  const row = db.prepare("select snapshot from inventory_ec2 where instance_id = ?").get(instanceId) as { snapshot: string } | undefined;
  if (!row) return false;
  let snapshot: Record<string, unknown>;
  try { snapshot = JSON.parse(row.snapshot); } catch { return false; }
  if (!snapshot || typeof snapshot !== "object") return false;
  const tags: Record<string, string> = { ...((snapshot.tags as Record<string, string>) || {}) };
  if (value == null) delete tags[key]; else tags[key] = value;
  db.prepare("update inventory_ec2 set snapshot = ? where instance_id = ?").run(JSON.stringify({ ...snapshot, tags }), instanceId);
  return true;
}

/** Mirrors an instance's state, and its addresses when known, as just read from EC2 into the stored row and snapshot: the page follows a stop or a start at once. */
export function patchEc2State(instanceId: string, state: string, publicIp?: string | null, privateIp?: string | null): boolean {
  const row = db.prepare("select snapshot from inventory_ec2 where instance_id = ?").get(instanceId) as { snapshot: string } | undefined;
  if (!row) return false;
  let snapshot: Record<string, any>;
  try { snapshot = JSON.parse(row.snapshot); } catch { return false; }
  if (!snapshot || typeof snapshot !== "object") return false;
  const identity = { ...(snapshot.identity || {}), state };
  const network = { ...(snapshot.network || {}), ...(publicIp ? { public_ip: publicIp } : {}), ...(privateIp ? { private_ip: privateIp } : {}) };
  db.prepare("update inventory_ec2 set state = ?, public_ip = coalesce(?, public_ip), private_ip = coalesce(?, private_ip), snapshot = ? where instance_id = ?")
    .run(state, publicIp || null, privateIp || null, JSON.stringify({ ...snapshot, identity, network }), instanceId);
  return true;
}

export interface SimpleFilter { q?: string; sort?: string; gone?: boolean; scope?: AccountScope | null }

export function listRds(f: SimpleFilter = {}) {
  const where: string[] = []; const params: unknown[] = [];
  if (f.scope) { const a = accountWhere(f.scope); where.push(a.sql); params.push(...a.params); }
  if (!f.gone) where.push("gone = 0");
  if (f.q) { where.push("(db_instance_identifier like ? or class like ? or engine like ? or cluster like ?)"); params.push(...Array(4).fill(`%${f.q}%`)); }
  const order = orderBy(f.sort, RDS_SORTS, "db_instance_identifier", "db_instance_identifier");
  const rows = db.prepare(`select * from inventory_rds ${where.length ? `where ${where.join(" and ")}` : ""} ${order}`).all(...params) as Record<string, unknown>[];
  return rows.map((r) => ({ ...r, snapshot: safeJson(r.snapshot) }));
}

export function listElasticache(f: SimpleFilter = {}) {
  const where: string[] = []; const params: unknown[] = [];
  if (f.scope) { const a = accountWhere(f.scope); where.push(a.sql); params.push(...a.params); }
  if (!f.gone) where.push("gone = 0");
  if (f.q) { where.push("(cache_cluster_id like ? or node_type like ? or engine like ? or replication_group like ?)"); params.push(...Array(4).fill(`%${f.q}%`)); }
  const order = orderBy(f.sort, CACHE_SORTS, "cache_cluster_id", "cache_cluster_id");
  const rows = db.prepare(`select * from inventory_elasticache ${where.length ? `where ${where.join(" and ")}` : ""} ${order}`).all(...params) as Record<string, unknown>[];
  return rows.map((r) => ({ ...r, snapshot: safeJson(r.snapshot) }));
}

/** Counts for the tiles: running/stopped, SSM coverage of running instances, list price of what runs, EBS GB; RDS and ElastiCache alongside. */
export function inventorySummary(scope?: AccountScope | null) {
  const ec2 = scopedStmt(scope, `
    select count(*) as total,
           coalesce(sum(state = 'running'), 0) as running,
           coalesce(sum(state = 'stopped'), 0) as stopped,
           coalesce(sum(state = 'running' and ssm_status = 'Online'), 0) as ssm_online,
           coalesce(sum(state = 'running' and ssm_status is not null and ssm_status <> 'Online'), 0) as ssm_lost,
           coalesce(sum(state = 'running' and ssm_status is null), 0) as ssm_unmanaged,
           coalesce(sum(case when state = 'running' then monthly_usd end), 0) as monthly_usd_running,
           coalesce(sum(state = 'running' and monthly_usd is null), 0) as running_unpriced,
           coalesce(sum(ebs_gb), 0) as ebs_gb,
           coalesce(sum(open_recs), 0) as open_recs,
           coalesce(sum(findings), 0) as findings
    from inventory_ec2 where gone = 0`).get() as Record<string, number>;
  const ec2Gone = (scopedStmt(scope, "select count(*) as n from inventory_ec2 where gone = 1").get() as { n: number }).n;
  const rds = scopedStmt(scope, `
    select count(*) as total, coalesce(sum(status = 'available'), 0) as available, coalesce(sum(monthly_usd), 0) as monthly_usd,
           coalesce(sum(monthly_usd is null), 0) as unpriced, coalesce(sum(storage_gb), 0) as storage_gb,
           coalesce(sum(open_recs), 0) as open_recs, coalesce(sum(findings), 0) as findings
    from inventory_rds where gone = 0`).get() as Record<string, number>;
  const rdsGone = (scopedStmt(scope, "select count(*) as n from inventory_rds where gone = 1").get() as { n: number }).n;
  const cache = scopedStmt(scope, `
    select count(*) as total, coalesce(sum(num_nodes), 0) as nodes, coalesce(sum(monthly_usd), 0) as monthly_usd, coalesce(sum(monthly_usd is null), 0) as unpriced,
           coalesce(sum(open_recs), 0) as open_recs, coalesce(sum(findings), 0) as findings
    from inventory_elasticache where gone = 0`).get() as Record<string, number>;
  const cacheGone = (scopedStmt(scope, "select count(*) as n from inventory_elasticache where gone = 1").get() as { n: number }).n;
  const r1 = (o: Record<string, number>) => Object.fromEntries(Object.entries(o).map(([k, v]) => [k, typeof v === "number" ? Math.round(v * 100) / 100 : v]));
  return { refreshed_at: inventoryRefreshedAt(), ec2: { ...r1(ec2), gone: ec2Gone }, rds: { ...r1(rds), gone: rdsGone }, elasticache: { ...r1(cache), gone: cacheGone }, lambda: lambdaSummary(scope), dynamodb: dynamodbSummary(scope), ebs: ebsSummary(scope), elb: elbSummary(scope), s3: s3Summary(scope), route53: route53Summary(scope), services: serviceSummary(scope), clusters: (() => { try { return clusterSummary(scope); } catch { return undefined; } })() };
}

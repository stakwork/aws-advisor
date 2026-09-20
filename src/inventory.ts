import { db, getSetting, setSetting } from "./db.js";
import { S, query } from "./steampipe.js";
import { ProbeSummary, instanceMetrics, latestProbeSummaries, summarizeProbe } from "./ssm.js";
import { PriceWant, ec2OperatingSystem, elasticachePricingEngine, ensurePrices, priceKey, rdsPricingEngine } from "./prices.js";
import { describeError, tablesIn } from "./permissions.js";
import { poolOf } from "./pools.js";

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
  elasticache: number;
  prices_fetched: number;
  errors: string[];
  took_ms: number;
}

const num = (v: unknown): number | null => (v == null || v === "" ? null : Number.isFinite(Number(v)) ? Number(v) : null);
const iso = (v: unknown): string | null => (v == null ? null : v instanceof Date ? v.toISOString() : String(v));
/** Same shape as SQLite's datetime('now'), so the UI's `when()` treats it as UTC. */
const sqliteNow = () => new Date().toISOString().replace("T", " ").slice(0, 19);

// ---- Steampipe queries ------------------------------------------------------------------------------

const EC2_SQL = `
  select i.instance_id, i.arn, i.tags ->> 'Name' as name, i.tags, i.instance_type, i.instance_state as state, i.region,
         i.placement_availability_zone as az, i.launch_time, i.private_ip_address as private_ip, i.public_ip_address as public_ip,
         i.private_dns_name as private_dns, i.public_dns_name as public_dns, i.platform, i.platform_details, i.architecture,
         i.iam_instance_profile_arn, i.vpc_id, i.subnet_id, i.root_device_name, i.root_device_type, i.image_id, i.key_name,
         i.instance_lifecycle, i.ebs_optimized, i.monitoring_state, i.state_transition_time, i.state_transition_reason,
         i.cpu_options_core_count as cpu_cores, i.cpu_options_threads_per_core as threads_per_core, i.security_groups,
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
  select db_instance_identifier, arn, class, engine, engine_version, multi_az, storage_type, allocated_storage, max_allocated_storage,
         iops, storage_throughput, status, region, availability_zone, create_time, db_cluster_identifier, license_model,
         endpoint_address, endpoint_port, publicly_accessible, storage_encrypted, backup_retention_period, deletion_protection,
         performance_insights_enabled, vpc_id, read_replica_source_db_instance_identifier, tags
  from ${S}.aws_rds_db_instance`;

const RDS_CPU_SQL = `
  select db_instance_identifier, round(avg(maximum)::numeric, 1) as avg_max, round(avg(average)::numeric, 1) as avg, count(*) as days
  from ${S}.aws_rds_db_instance_metric_cpu_utilization_daily
  where timestamp > now() - interval '30 days'
  group by 1`;

const ELASTICACHE_SQL = `
  select cache_cluster_id, arn, cache_node_type, engine, engine_version, num_cache_nodes, cache_cluster_status, replication_group_id,
         preferred_availability_zone, region, cache_cluster_create_time, cache_subnet_group_name, transit_encryption_enabled,
         at_rest_encryption_enabled, auto_minor_version_upgrade, snapshot_retention_limit, tags
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
const goneEc2 = db.prepare("update inventory_ec2 set gone = 1 where last_seen <> ?");

const upsertRds = db.prepare(`
  insert into inventory_rds(db_instance_identifier, class, engine, engine_version, multi_az, storage_type, storage_gb, status, region, created, cluster,
    cpu_30d, cpu_days, monthly_usd, open_recs, findings, first_seen, last_seen, gone, snapshot)
  values (@db_instance_identifier, @class, @engine, @engine_version, @multi_az, @storage_type, @storage_gb, @status, @region, @created, @cluster,
    @cpu_30d, @cpu_days, @monthly_usd, @open_recs, @findings, @now, @now, 0, @snapshot)
  on conflict(db_instance_identifier) do update set class = excluded.class, engine = excluded.engine, engine_version = excluded.engine_version,
    multi_az = excluded.multi_az, storage_type = excluded.storage_type, storage_gb = excluded.storage_gb, status = excluded.status, region = excluded.region,
    created = excluded.created, cluster = excluded.cluster, cpu_30d = excluded.cpu_30d, cpu_days = excluded.cpu_days, monthly_usd = excluded.monthly_usd,
    open_recs = excluded.open_recs, findings = excluded.findings, last_seen = excluded.last_seen, gone = 0, snapshot = excluded.snapshot`);
const goneRds = db.prepare("update inventory_rds set gone = 1 where last_seen <> ?");

const upsertElasticache = db.prepare(`
  insert into inventory_elasticache(cache_cluster_id, node_type, engine, engine_version, num_nodes, status, region, created, replication_group,
    monthly_usd, open_recs, findings, first_seen, last_seen, gone, snapshot)
  values (@cache_cluster_id, @node_type, @engine, @engine_version, @num_nodes, @status, @region, @created, @replication_group,
    @monthly_usd, @open_recs, @findings, @now, @now, 0, @snapshot)
  on conflict(cache_cluster_id) do update set node_type = excluded.node_type, engine = excluded.engine, engine_version = excluded.engine_version,
    num_nodes = excluded.num_nodes, status = excluded.status, region = excluded.region, created = excluded.created, replication_group = excluded.replication_group,
    monthly_usd = excluded.monthly_usd, open_recs = excluded.open_recs, findings = excluded.findings, last_seen = excluded.last_seen, gone = 0, snapshot = excluded.snapshot`);
const goneElasticache = db.prepare("update inventory_elasticache set gone = 1 where last_seen <> ?");

/** Alarm findings of the latest completed run and open recommendations, counted per resource id (exact or contained, as the MCP tools match). */
function resourceCounters() {
  const latest = db.prepare("select id from runs where status = 'completed' order by id desc limit 1").get() as { id: number } | undefined;
  const findings = latest ? (db.prepare("select resource from findings where run_id = ? and status = 'alarm' and resource is not null").all(latest.id) as { resource: string }[]).map((r) => r.resource) : [];
  const recs = (db.prepare("select resource from recommendations where status = 'open' and resource is not null").all() as { resource: string }[]).map((r) => r.resource);
  const count = (list: string[], id: string) => list.filter((r) => r === id || r.includes(id)).length;
  return { findings: (id: string) => count(findings, id), recs: (id: string) => count(recs, id) };
}

// ---- refresh ----------------------------------------------------------------------------------------

let inflight: Promise<RefreshResult> | null = null;

/** Snapshots EC2, RDS and ElastiCache into the inventory tables. Concurrent calls share one refresh. */
export function refreshInventory(): Promise<RefreshResult> {
  if (!inflight) inflight = doRefresh().finally(() => { inflight = null; });
  return inflight;
}

async function doRefresh(): Promise<RefreshResult> {
  const t0 = Date.now();
  const now = sqliteNow();
  const errors: string[] = [];
  const attempt = async (what: string, sql: string): Promise<any[] | undefined> => {
    try { return await query<any>(sql); } catch (e: any) { errors.push(`${what}: ${describeError(e, `inventory ${what} (${tablesIn(sql).join(", ")})`, 300)}`); return undefined; }
  };

  const [ec2Rows, ebsRows, ec2Cpu, rdsRows, rdsCpu, cacheRows] = await Promise.all([
    attempt("ec2", EC2_SQL),
    attempt("ebs", EBS_SQL),
    attempt("ec2 cpu", EC2_CPU_SQL),
    attempt("rds", RDS_SQL),
    attempt("rds cpu", RDS_CPU_SQL),
    attempt("elasticache", ELASTICACHE_SQL),
  ]);

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
          network: { private_ip: r.private_ip, public_ip: r.public_ip, private_dns: r.private_dns, public_dns: r.public_dns, vpc_id: r.vpc_id, subnet_id: r.subnet_id, security_groups: r.security_groups || [] },
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
        ec2++;
      }
      goneEc2.run(now);
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
          network: { endpoint: r.endpoint_address, port: num(r.endpoint_port), publicly_accessible: r.publicly_accessible, vpc_id: r.vpc_id },
          tags: r.tags || {},
          utilisation: { cpu_30d_avg_max: num(cpu?.avg_max), cpu_30d_avg: num(cpu?.avg), cpu_days: num(cpu?.days) ?? 0 },
          price: price ? { hourly: price.hourly, monthly: price.monthly, pricing_engine: want!.engine, fetched_at: price.fetched_at } : null,
        };
        upsertRds.run({
          db_instance_identifier: id, class: r.class, engine: r.engine, engine_version: r.engine_version, multi_az: r.multi_az ? 1 : 0, storage_type: r.storage_type,
          storage_gb: num(r.allocated_storage), status: r.status, region: r.region, created: iso(r.create_time), cluster: r.db_cluster_identifier || null,
          cpu_30d: num(cpu?.avg_max), cpu_days: num(cpu?.days) ?? 0, monthly_usd: price?.monthly ?? null,
          open_recs: counters.recs(id), findings: counters.findings(id), now, snapshot: JSON.stringify(snapshot),
        });
        rds++;
      }
      goneRds.run(now);
    }
    if (cacheRows) {
      for (const r of cacheRows) {
        const want = cacheWant(r);
        const price = priceOf(want);
        const nodes = num(r.num_cache_nodes) ?? 1;
        const monthly = price?.monthly == null ? null : Math.round(price.monthly * nodes * 100) / 100;
        const id = r.cache_cluster_id;
        const snapshot = {
          identity: { cache_cluster_id: id, arn: r.arn, node_type: r.cache_node_type, engine: r.engine, engine_version: r.engine_version, num_nodes: nodes, status: r.cache_cluster_status,
            replication_group: r.replication_group_id, region: r.region, availability_zone: r.preferred_availability_zone, created: iso(r.cache_cluster_create_time),
            subnet_group: r.cache_subnet_group_name, transit_encryption: r.transit_encryption_enabled, at_rest_encryption: r.at_rest_encryption_enabled,
            auto_minor_version_upgrade: r.auto_minor_version_upgrade, snapshot_retention_days: num(r.snapshot_retention_limit) },
          tags: r.tags || {},
          price: price ? { hourly_per_node: price.hourly, monthly_per_node: price.monthly, monthly: monthly, pricing_engine: want!.engine, fetched_at: price.fetched_at } : null,
        };
        upsertElasticache.run({
          cache_cluster_id: id, node_type: r.cache_node_type, engine: r.engine, engine_version: r.engine_version, num_nodes: nodes, status: r.cache_cluster_status,
          region: r.region, created: iso(r.cache_cluster_create_time), replication_group: r.replication_group_id || null, monthly_usd: monthly,
          open_recs: counters.recs(id), findings: counters.findings(id), now, snapshot: JSON.stringify(snapshot),
        });
        elasticache++;
      }
      goneElasticache.run(now);
    }
  })();

  if (ec2Rows || rdsRows || cacheRows) setSetting("inventory_refreshed_at", now);
  return { refreshed_at: now, ec2, rds, elasticache, prices_fetched: fetched, errors, took_ms: Date.now() - t0 };
}

export const inventoryRefreshedAt = () => getSetting("inventory_refreshed_at");

// ---- readers ----------------------------------------------------------------------------------------

export type SsmFilter = "online" | "lost" | "unmanaged" | "managed";

export interface Ec2Filter { state?: string; ssm?: string; q?: string; sort?: string; gone?: boolean; limit?: number }

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

export function listEc2(f: Ec2Filter = {}) {
  const where: string[] = []; const params: unknown[] = [];
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
  const latest = db.prepare("select id from runs where status = 'completed' order by id desc limit 1").get() as { id: number } | undefined;
  const findings = latest
    ? db.prepare("select id, run_id, source, benchmark, control_id, control_title, status, resource, reason, region from findings where run_id = ? and (resource = ? or resource like ?) order by control_id").all(latest.id, instanceId, `%${instanceId}%`)
    : [];
  const recommendations = db.prepare("select id, rule, source, title, action_type, est_monthly_saving, tier, confidence, status, decided_at, decided_by, decision_reason, run_id, updated_at from recommendations where resource = ? or resource like ? order by updated_at desc")
    .all(instanceId, `%${instanceId}%`);
  const probes = instanceMetrics(instanceId, 20).map((p) => ({ id: p.id, collected_at: p.collected_at, summary: summarizeProbe(p.data), data: p.data }));
  return { ...row, findings_count: row.findings, snapshot: safeJson(row.snapshot), findings_run_id: latest?.id ?? null, findings, recommendations, probes };
}

export interface SimpleFilter { q?: string; sort?: string; gone?: boolean }

export function listRds(f: SimpleFilter = {}) {
  const where: string[] = []; const params: unknown[] = [];
  if (!f.gone) where.push("gone = 0");
  if (f.q) { where.push("(db_instance_identifier like ? or class like ? or engine like ? or cluster like ?)"); params.push(...Array(4).fill(`%${f.q}%`)); }
  const order = orderBy(f.sort, RDS_SORTS, "db_instance_identifier", "db_instance_identifier");
  const rows = db.prepare(`select * from inventory_rds ${where.length ? `where ${where.join(" and ")}` : ""} ${order}`).all(...params) as Record<string, unknown>[];
  return rows.map((r) => ({ ...r, snapshot: safeJson(r.snapshot) }));
}

export function listElasticache(f: SimpleFilter = {}) {
  const where: string[] = []; const params: unknown[] = [];
  if (!f.gone) where.push("gone = 0");
  if (f.q) { where.push("(cache_cluster_id like ? or node_type like ? or engine like ? or replication_group like ?)"); params.push(...Array(4).fill(`%${f.q}%`)); }
  const order = orderBy(f.sort, CACHE_SORTS, "cache_cluster_id", "cache_cluster_id");
  const rows = db.prepare(`select * from inventory_elasticache ${where.length ? `where ${where.join(" and ")}` : ""} ${order}`).all(...params) as Record<string, unknown>[];
  return rows.map((r) => ({ ...r, snapshot: safeJson(r.snapshot) }));
}

/** Counts for the tiles: running/stopped, SSM coverage of running instances, list price of what runs, EBS GB; RDS and ElastiCache alongside. */
export function inventorySummary() {
  const ec2 = db.prepare(`
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
  const ec2Gone = (db.prepare("select count(*) as n from inventory_ec2 where gone = 1").get() as { n: number }).n;
  const rds = db.prepare(`
    select count(*) as total, coalesce(sum(status = 'available'), 0) as available, coalesce(sum(monthly_usd), 0) as monthly_usd,
           coalesce(sum(monthly_usd is null), 0) as unpriced, coalesce(sum(storage_gb), 0) as storage_gb,
           coalesce(sum(open_recs), 0) as open_recs, coalesce(sum(findings), 0) as findings
    from inventory_rds where gone = 0`).get() as Record<string, number>;
  const rdsGone = (db.prepare("select count(*) as n from inventory_rds where gone = 1").get() as { n: number }).n;
  const cache = db.prepare(`
    select count(*) as total, coalesce(sum(num_nodes), 0) as nodes, coalesce(sum(monthly_usd), 0) as monthly_usd, coalesce(sum(monthly_usd is null), 0) as unpriced,
           coalesce(sum(open_recs), 0) as open_recs, coalesce(sum(findings), 0) as findings
    from inventory_elasticache where gone = 0`).get() as Record<string, number>;
  const cacheGone = (db.prepare("select count(*) as n from inventory_elasticache where gone = 1").get() as { n: number }).n;
  const r1 = (o: Record<string, number>) => Object.fromEntries(Object.entries(o).map(([k, v]) => [k, typeof v === "number" ? Math.round(v * 100) / 100 : v]));
  return { refreshed_at: inventoryRefreshedAt(), ec2: { ...r1(ec2), gone: ec2Gone }, rds: { ...r1(rds), gone: rdsGone }, elasticache: { ...r1(cache), gone: cacheGone } };
}

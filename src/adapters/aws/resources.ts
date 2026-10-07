import { config } from "../../config.js";
import { AWS, type GenericState, type ResourceLabel, type ResourceNode, type TelemetryKind } from "../types.js";
import { clientLine, iamUserMfa, strongestMfa, type ClientUse } from "../../sign_in_facts.js";

/**
 * The AWS adapter's mapping of its storage (the inventory_* tables Steampipe fills) onto the generic model of
 * docs/cloud-ontology.md: one ResourceNode per row, the provider's lifecycle word folded into the generic state, the
 * role the classifier judged, the telemetry that covers it, the pool a node belongs to, the balancer's listeners and
 * targets as edges, and the words for resources the inventory has no row for (refs). Pure functions, exported for
 * tests; src/graph_mirror.ts writes what they emit.
 */

const PROVIDER = AWS;
const num = (v: unknown): number | null => (v == null || v === "" || !Number.isFinite(Number(v)) ? null : Number(v));
const str = (v: unknown): string | null => (v == null ? null : String(v));
const bool = (v: unknown): boolean | null => (v == null ? null : Boolean(Number(v)));
const safeJson = (s: unknown): any => { if (typeof s !== "string") return s ?? null; try { return JSON.parse(s); } catch { return null; } };

/** The provider's lifecycle word mapped onto the generic state; the provider's word stays in native_state. */
export function genericState(nativeType: string, state: string | null | undefined): GenericState {
  const s = String(state || "").toLowerCase();
  if (!s) return "unknown";
  if (nativeType === "ec2_instance") {
    if (s === "running") return "running";
    if (s === "stopped" || s === "stopping") return "stopped";
    if (s === "pending") return "pending";
    if (s === "terminated" || s === "shutting-down") return "terminated";
    return "unknown";
  }
  if (nativeType === "cloudformation_stack") {
    if (/_in_progress$/.test(s)) return "pending";
    if (s === "delete_complete") return "terminated";
    if (/_failed$/.test(s) || s === "rollback_complete" || s === "import_rollback_complete") return "degraded";
    return /_complete$/.test(s) ? "available" : "unknown";
  }
  if (nativeType === "kms_key") return s === "enabled" ? "available" : s === "disabled" || s === "pendingdeletion" || s === "pendingreplicadeletion" ? "stopped" : s === "unavailable" ? "degraded" : /^(creating|updating|pendingimport)$/.test(s) ? "pending" : "unknown";
  if (nativeType === "acm_certificate") return s === "issued" ? "available" : s === "pending_validation" ? "pending" : /^(expired|revoked|failed|validation_timed_out)$/.test(s) ? "degraded" : s === "inactive" ? "stopped" : "unknown";
  if (/^(available|active|in-use|issued|insync|ok|enabled)$/.test(s)) return "available";
  if (s === "disabled") return "stopped";
  if (/^(stopped|stopping)$/.test(s)) return "stopped";
  if (/^(creating|modifying|provisioning|pending|backing-up|starting|rebooting|upgrading|renaming|configuring-enhanced-monitoring|snapshotting|maintenance|resetting-master-credentials)$/.test(s)) return "pending";
  if (/^(deleting|deleted|terminated)$/.test(s)) return "terminated";
  if (/^(failed|storage-full|incompatible-.*|inaccessible-encryption-credentials|active_impaired|error|insufficient-capacity)$/.test(s)) return "degraded";
  return "unknown";
}

export interface RoleRow { role: string; role_confidence: number | null; protected_prob: number | null }
export type RoleMap = Map<string, RoleRow>;


/** The AWS adapter's sources, one AdvisorTelemetry node each per account. */
export const TELEMETRY: Record<TelemetryKind, { native: string }> = { api: { native: "steampipe" }, metrics: { native: "cloudwatch" }, probe: { native: "ssm_probe" }, logs: { native: "cloudwatch_logs" }, audit: { native: "cloudtrail" }, bill: { native: "cost_explorer" } };
export const telemetryId = (account: string, kind: TelemetryKind) => `${PROVIDER}:${account}:telemetry:${kind}`;

/** The autoscaling pool an EC2 instance belongs to (Karpenter node pool, EKS node group or ASG), from its snapshot tags; the EKS cluster prefixes the name like the watcher does. */
export function poolOf(snapshot: unknown): string | null {
  const tags = (safeJson(snapshot)?.tags || {}) as Record<string, string>;
  const pool = tags["karpenter.sh/nodepool"] || tags["eks:nodegroup-name"] || tags["aws:autoscaling:groupName"];
  if (!pool) return null;
  const cluster = tags["eks:cluster-name"];
  return cluster ? `${cluster}/${pool}` : pool;
}

/** The pool kind as the inventory records it (src/pools.ts) mapped onto the generic AdvisorNodePool.kind. */
export const POOL_KIND: Record<string, string> = { karpenter: "karpenter", eks: "node_group", asg: "asg", batch: "batch" };
export const poolId = (account: string, name: string) => `${PROVIDER}:${account}:pool:${name}`;

const withRole = (id: string, roles: RoleMap) => { const r = roles.get(id); return { role: r?.role ?? null, role_confidence: num(r?.role_confidence), protected_prob: num(r?.protected_prob) }; };

const base = (id: string, label: ResourceLabel, nativeType: string, row: any, name: string | null, state: string | null, region: string | null, roles: RoleMap, props: Record<string, unknown>, observed: ResourceNode["observed"]): ResourceNode => ({
  id, label, native_type: nativeType, name, state: genericState(nativeType, state), native_state: str(state), region, ...withRole(id, roles), monthly_usd: num(row.monthly_usd),
  gone: Boolean(row.gone), first_seen: str(row.first_seen), last_seen: str(row.last_seen), pool: null, pool_kind: null, props, observed,
});

const apiObserved = (row: any): ResourceNode["observed"][number] => ({ kind: "api", status: row.gone ? "stale" : "ok", last_at: str(row.last_seen), detail: null });

export function resourceFromEc2(row: any, roles: RoleMap = new Map()): ResourceNode {
  const snap = safeJson(row.snapshot) || {};
  const net = snap.network || {};
  const observed: ResourceNode["observed"] = [apiObserved(row)];
  if (row.cpu_30d != null || Number(row.cpu_days) > 0) observed.push({ kind: "metrics", status: "ok", last_at: str(row.last_seen), detail: `cpu over ${num(row.cpu_days) ?? "?"} days` });
  if (row.ssm_status != null || row.probe_at != null) observed.push({ kind: "probe", status: row.ssm_status === "Online" ? "ok" : row.probe_at && !row.ssm_status ? "stale" : "offline", last_at: str(row.probe_at), detail: str(row.ssm_status) });
  const platform = str(row.platform) || (snap.platform_details ? String(snap.platform_details).toLowerCase().includes("windows") ? "windows" : "linux" : null);
  const n = base(String(row.instance_id), "AdvisorBox", "ec2_instance", row, str(row.name), str(row.state), str(row.region), roles, {
    kind: "vm", type: str(row.instance_type), arch: str(snap.architecture), platform, image_id: str(snap.image_id),
    private_ips: net.private_ip ? [String(net.private_ip)] : [], public_ip: str(net.public_ip), ipv6: Array.isArray(net.ipv6) ? net.ipv6.map(String) : [], hostname: str(net.public_dns) || str(net.private_dns),
    zone: str(row.az), lifecycle: snap.instance_lifecycle === "spot" ? "spot" : "on_demand", launch_time: str(row.launch_time), cpu_30d: num(row.cpu_30d), ebs_gb: num(row.ebs_gb), volumes: num(row.volumes),
    probe_at: str(row.probe_at), probe_mem_pct: num(row.probe_mem_pct), vpc_id: str(net.vpc_id), subnet_id: str(net.subnet_id), security_groups: Array.isArray(net.security_groups) ? net.security_groups.map((g: any) => String(g?.GroupId ?? g?.group_id ?? g)) : [],
  }, observed);
  // the operating system as the API knows it; the software probe adds the distribution, version and kernel (src/graph_software.ts)
  n.compute = { platform, arch: str(snap.architecture), agent_kind: row.ssm_status != null ? "ssm" : null, os: str(row.ssm_platform), opaque: false };
  n.pool = row.pool ? String(row.pool) : poolOf(row.snapshot);
  n.pool_kind = row.pool_kind ? POOL_KIND[String(row.pool_kind)] ?? String(row.pool_kind) : n.pool ? (n.pool.includes("/") ? "node_group" : "asg") : null;
  return n;
}

export function resourceFromRds(row: any, roles: RoleMap = new Map()): ResourceNode {
  const snap = safeJson(row.snapshot) || {};
  const net = snap.network || {};
  const observed: ResourceNode["observed"] = [apiObserved(row)];
  if (row.cpu_30d != null || Number(row.cpu_days) > 0) observed.push({ kind: "metrics", status: "ok", last_at: str(row.last_seen), detail: `cpu over ${num(row.cpu_days) ?? "?"} days` });
  return base(String(row.db_instance_identifier), "AdvisorDatabase", "rds_instance", row, str(row.db_instance_identifier), str(row.status), str(row.region), roles, {
    engine: str(row.engine), engine_version: str(row.engine_version), type: str(row.class), cluster: str(row.cluster), cluster_role: row.cluster ? "member" : "standalone",
    storage_gb: num(row.storage_gb), storage_type: str(row.storage_type), multi_az: bool(row.multi_az), publicly_accessible: net.publicly_accessible == null ? null : Boolean(net.publicly_accessible),
    encrypted: snap.storage_encrypted == null ? null : Boolean(snap.storage_encrypted), backup_retention_days: num(snap.backup_retention_period), deletion_protection: snap.deletion_protection == null ? null : Boolean(snap.deletion_protection),
    endpoint_host: str(net.endpoint), port: num(net.port), vpc_id: str(net.vpc_id), security_groups: Array.isArray(net.security_groups) ? net.security_groups.map(String) : [], cpu_30d: num(row.cpu_30d), created_at: str(row.created),
  }, observed);
}

export function resourceFromElasticache(row: any, roles: RoleMap = new Map()): ResourceNode {
  const net = (safeJson(row.snapshot) || {}).network || {};
  return base(String(row.cache_cluster_id), "AdvisorCache", "elasticache_cluster", row, str(row.cache_cluster_id), str(row.status), str(row.region), roles, {
    engine: str(row.engine), engine_version: str(row.engine_version), type: str(row.node_type), nodes: num(row.num_nodes), group: str(row.replication_group), created_at: str(row.created),
    security_groups: Array.isArray(net.security_groups) ? net.security_groups.map(String) : [],
  }, [apiObserved(row)]);
}

const LB_KIND: Record<string, string> = { alb: "application", nlb: "network", gwlb: "gateway", clb: "classic" };

/** A load balancer: the ARN is the id (what recommendations and alerts name), the name is the name. */
export function resourceFromElb(row: any, roles: RoleMap = new Map()): ResourceNode {
  const observed: ResourceNode["observed"] = [apiObserved(row)];
  if (Number(row.metric_days) > 0) observed.push({ kind: "metrics", status: "ok", last_at: str(row.last_seen), detail: `requests over ${num(row.metric_days)} days` });
  return base(String(row.arn), "AdvisorLoadBalancer", `elb_${row.kind || "alb"}`, row, str(row.name), str(row.state), str(row.region), roles, {
    kind: LB_KIND[String(row.kind)] ?? str(row.kind), type: str(row.kind), scheme: row.scheme === "internet-facing" ? "public" : row.scheme ? "internal" : null, native_scheme: str(row.scheme), dns_name: str(row.dns_name),
    targets: Number(row.targets || 0), healthy: Number(row.healthy || 0), unhealthy: Number(row.unhealthy || 0), requests_30d: num(row.requests_30d), gb_30d: num(row.gb_30d),
    asgs: safeJson(row.asgs) || [], ecs_services: safeJson(row.ecs_services) || [], platform_owner: str(row.beanstalk_env), vpc_id: str(row.vpc_id), created_at: str(row.created),
  }, observed);
}

export const lambdaArn = (row: any, account: string) => str(row.arn) || `arn:aws:lambda:${row.region}:${account}:function:${row.name}`;

export function resourceFromLambda(row: any, account: string, roles: RoleMap = new Map()): ResourceNode {
  const observed: ResourceNode["observed"] = [apiObserved(row)];
  if (Number(row.days) > 0) observed.push({ kind: "metrics", status: "ok", last_at: str(row.last_seen), detail: `invocations over ${num(row.days)} days` });
  const runtime = str(row.runtime);
  const version = runtime ? (/^(?:[a-z]+?)(\d+(?:\.\d+)*)/.exec(runtime)?.[1] ?? null) : null;
  return base(lambdaArn(row, account), "AdvisorFunction", "lambda_function", row, str(row.name), "available", str(row.region), roles, {
    runtime, runtime_version: version, memory_mb: num(row.memory_mb), timeout_s: num(row.timeout_s), arch: Number(row.arm) ? "arm64" : "x86_64", kind: "serverless",
    invocations_30d: num(row.invocations_30d), errors_30d: num(row.errors_30d), duration_avg_ms: num(row.avg_duration_ms), invocations_month: num(row.invocations_month), gb_seconds_month: num(row.gb_seconds_month),
  }, observed);
}

/** A DynamoDB table as the generic database node: a serverless key-value engine, its capacity mode where RDS has an instance class. */
export function resourceFromDynamodb(row: any, account: string, roles: RoleMap = new Map()): ResourceNode {
  const observed: ResourceNode["observed"] = [apiObserved(row)];
  if (Number(row.metric_days) > 0) observed.push({ kind: "metrics", status: "ok", last_at: str(row.last_seen), detail: `consumed units over ${num(row.metric_days)} days` });
  const onDemand = row.billing_mode === "PAY_PER_REQUEST";
  const id = str(row.arn) || `arn:aws:dynamodb:${row.region}:${row.account_id || account}:table/${row.name}`;
  return base(id, "AdvisorDatabase", "dynamodb_table", row, str(row.name), str(row.status), str(row.region), roles, {
    engine: "dynamodb", engine_version: null, type: onDemand ? "on-demand" : `provisioned ${num(row.read_capacity)} RCU / ${num(row.write_capacity)} WCU`, kind: "key_value", serverless: true,
    cluster: null, cluster_role: "standalone", billing_mode: onDemand ? "on_demand" : "provisioned", read_capacity: num(row.read_capacity), write_capacity: num(row.write_capacity),
    indexes: num(row.gsi_count), storage_gb: row.size_bytes == null ? null : Math.round((Number(row.size_bytes) / 1e9) * 100) / 100, storage_type: str(row.table_class), items: num(row.item_count),
    backup_retention_days: Number(row.pitr) ? 35 : 0, point_in_time_recovery: Boolean(Number(row.pitr)), streams: Boolean(Number(row.stream)), publicly_accessible: null, encrypted: true,
    reads_30d: num(row.read_units_30d), writes_30d: num(row.write_units_30d), created_at: str(row.created),
  }, observed);
}

export function resourceFromS3(row: any, roles: RoleMap = new Map()): ResourceNode {
  const observed: ResourceNode["observed"] = [apiObserved(row)];
  if (row.metric_day) observed.push({ kind: "metrics", status: "ok", last_at: str(row.metric_day), detail: "storage metrics" });
  return base(String(row.name), "AdvisorStorage", "s3_bucket", row, str(row.name), "available", str(row.region), roles, {
    kind: "object", size_gb: num(row.total_gb), objects: num(row.objects), class: null, standard_gb: num(row.standard_gb), versioning: bool(row.versioning), lifecycle_rules: num(row.lifecycle_rules), public: bool(row.public), created_at: str(row.created),
  }, observed);
}

export function resourceFromEbs(row: any, roles: RoleMap = new Map()): ResourceNode {
  const observed: ResourceNode["observed"] = [apiObserved(row)];
  if (Number(row.metric_days) > 0) observed.push({ kind: "metrics", status: "ok", last_at: str(row.last_seen), detail: `iops over ${num(row.metric_days)} days` });
  return base(String(row.volume_id), "AdvisorStorage", "ebs_volume", row, str(row.name), str(row.state), str(row.region), roles, {
    kind: "block", size_gb: num(row.size_gb), class: str(row.volume_type), iops: num(row.iops), throughput_mibps: num(row.throughput_mibps), encrypted: bool(row.encrypted), attached_to: str(row.instance_id), device: str(row.device),
    iops_30d: row.read_iops_avg == null && row.write_iops_avg == null ? null : (num(row.read_iops_avg) ?? 0) + (num(row.write_iops_avg) ?? 0), iops_max: num(row.iops_max), used_pct: num(row.used_pct), created_at: str(row.created),
  }, observed);
}

export function resourceFromZone(row: any): ResourceNode {
  return base(String(row.zone_id), "AdvisorDnsZone", "route53_zone", row, str(row.name), "available", null, new Map(), {
    private: Boolean(row.private), records: num(row.records) ?? 0, linked: num(row.linked), external: num(row.external), unmatched: num(row.unmatched), queries_30d: num(row.queries_30d), comment: str(row.comment),
  }, [apiObserved(row)]);
}

export function resourceFromDnsRecord(row: any): ResourceNode {
  let values: string[] = []; try { const v = JSON.parse(row.values || "[]"); values = Array.isArray(v) ? v.map(String) : []; } catch { values = []; }
  return base(String(row.id), "AdvisorDnsRecord", "route53_record", row, str(row.name), "available", null, new Map(), {
    fqdn: String(row.name).replace(/\.$/, "").toLowerCase(), type: str(row.type), ttl: num(row.ttl), values, alias: Boolean(row.alias), alias_target: str(row.alias_target), routing: str(row.routing) || "simple",
    link_state: row.link_state === "linked" ? "resource" : row.link_state === "unmatched" ? "dangling" : str(row.link_state) || "unknown", native_link_state: str(row.link_state), summary: str(row.summary), zone_id: str(row.zone_id),
  }, [apiObserved(row)]);
}

export interface ElbEdges { id: string; listeners: { id: string; protocol: string | null; port: number | null; tls: boolean; certificates: number }[]; ec2_edges: { listener: string | null; target: string; port: number | null; target_group: string; health: string | null }[]; ref_edges: { listener: string | null; target: string; target_group: string; port: number | null; health: string | null }[] }

const listenerId = (arn: string, protocol: string | null, port: number | null) => `${arn}:listener:${(protocol || "tcp").toLowerCase()}:${port ?? 0}`;

/**
 * What a balancer exposes and routes to: one listener endpoint per listener, and from the listener (or the balancer
 * when it has none) FORWARDS_TO edges to the instance ports behind its target groups, or to a Lambda ref.
 */
export function elbEdges(row: any): ElbEdges {
  const arn = String(row.arn);
  const listeners = ((safeJson(row.listeners) || []) as any[]).map((l) => ({ id: listenerId(arn, str(l?.protocol), num(l?.port)), protocol: l?.protocol ? String(l.protocol).toLowerCase() : null, port: num(l?.port), tls: /^(https|tls)$/i.test(String(l?.protocol || "")), certificates: Number(l?.certificates || 0) }));
  const groups = safeJson(row.target_groups) || [];
  const ec2_edges: ElbEdges["ec2_edges"] = []; const ref_edges: ElbEdges["ref_edges"] = [];
  // a listener's default action names its target group when the inventory recorded it; else every listener forwards to every group (one listener is the common case)
  const listenerFor = (groupName: string): string | null => {
    const named = ((safeJson(row.listeners) || []) as any[]).find((l) => typeof l?.default_action === "string" && l.default_action.includes(groupName));
    if (named) return listenerId(arn, str(named.protocol), num(named.port));
    return listeners.length === 1 ? listeners[0].id : null;
  };
  for (const g of Array.isArray(groups) ? groups : []) for (const t of g?.targets || []) {
    const e = { listener: listenerFor(String(g.name || "")), target_group: String(g.name || ""), port: num(t.port) ?? num(g.port), health: str(t.health) };
    if (t.instance_id) ec2_edges.push({ target: String(t.instance_id), ...e });
    else if (t.lambda || String(t.id || "").startsWith("arn:")) ref_edges.push({ target: String(t.id), ...e });
  }
  return { id: arn, listeners, ec2_edges, ref_edges };
}

/**
 * The inventory id a resource reference points at: the id itself, or the last segment of an ARN
 * (`arn:aws:ec2:us-east-1:1:instance/i-abc` → `i-abc`, `arn:aws:rds:...:db:name` → `name`, `arn:aws:s3:::bucket`
 * → `bucket`); null when the inventory does not know it (a VPC, a snapshot, an alarm...).
 */
export function inventoryIdOf(resource: string | null | undefined, inventoryIds: Set<string>): string | null {
  if (!resource) return null;
  if (inventoryIds.has(resource)) return resource;
  const tail = resource.split(/[/:]/).pop();
  return tail && inventoryIds.has(tail) ? tail : null;
}

/** What a resource string that is not in the inventory probably is, from its shape, so a ref says what it points at. */
export function guessedType(resource: string): string | null {
  const r = resource;
  if (/^vol-/.test(r)) return "volume";
  if (/^snap-/.test(r)) return "snapshot";
  if (/^vpc-/.test(r)) return "vpc";
  if (/^subnet-/.test(r)) return "subnet";
  if (/^sg-/.test(r)) return "security_group";
  if (/^eni-/.test(r)) return "interface";
  if (/^eipalloc-|^\d+\.\d+\.\d+\.\d+$/.test(r)) return "public_ip";
  if (/^nat-/.test(r)) return "nat_gateway";
  if (/^i-/.test(r)) return "instance";
  if (/^ami-/.test(r)) return "image";
  const m = /^arn:aws:([a-z0-9-]+):/.exec(r);
  if (m) {
    const svc = m[1];
    if (svc === "s3") return "bucket";
    if (svc === "lambda") return "function";
    if (svc === "rds") return /:cluster:/.test(r) ? "database_cluster" : "database";
    if (svc === "dynamodb") return "database";
    if (svc === "ecr") return "repository";
    if (svc === "elasticfilesystem") return "file_system";
    if (svc === "kms") return /:alias\//.test(r) ? "key_alias" : "key";
    if (svc === "acm") return "certificate";
    if (svc === "sns") return "topic";
    if (svc === "sqs") return "queue";
    if (svc === "firehose") return "stream";
    if (svc === "backup") return /:backup-plan:/.test(r) ? "backup_plan" : "backup_vault";
    if (svc === "athena") return "workgroup";
    if (svc === "cloudformation") return "stack";
    if (svc === "wafv2") return "web_acl";
    if (svc === "guardduty") return "detector";
    if (svc === "cloudfront") return "cdn_distribution";
    if (svc === "apigateway") return "api";
    if (svc === "iam") return "identity";
    if (svc === "eks" || svc === "ecs") return "cluster";
    if (svc === "cloudwatch") return "alarm";
    if (svc === "logs") return "log_group";
    if (svc === "elasticloadbalancing") return "load_balancer";
    if (svc === "ec2") return /:snapshot\//.test(r) ? "snapshot" : /:volume\//.test(r) ? "volume" : /:instance\//.test(r) ? "instance" : "ec2";
    return svc;
  }
  return null;
}

/** The generic label each platform service row lands on (src/service_inventory.ts); WAF is a filter the provider bills. */
export const SERVICE_LABEL: Record<string, ResourceLabel> = {
  acm_certificate: "AdvisorCertificate", sns_topic: "AdvisorMessaging", kms_key: "AdvisorSecret", efs_file_system: "AdvisorStorage", backup_vault: "AdvisorStorage", backup_plan: "AdvisorBackupPlan",
  athena_workgroup: "AdvisorAnalytics", cloudformation_stack: "AdvisorStack", wafv2_web_acl: "AdvisorFilter", guardduty_detector: "AdvisorDetector",
};

/** Neo4j holds primitives and lists of primitives only: a nested object or list of objects becomes its JSON text. Pure. */
export function flatProps(props: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(props)) {
    if (v == null || typeof v !== "object") out[k] = v ?? null;
    else if (Array.isArray(v)) out[k] = v.every((x) => x == null || typeof x !== "object") ? v.filter((x) => x != null) : JSON.stringify(v);
    else out[k] = JSON.stringify(v);
  }
  return out;
}

/** A platform service row (certificate, topic, key, file system, vault, plan, workgroup, stack, web ACL, detector) as its generic node; the collector already wrote the props in the ontology's words. */
export function resourceFromService(row: any, roles: RoleMap = new Map()): ResourceNode | null {
  const label = SERVICE_LABEL[String(row.native_type)];
  if (!label) return null;
  const props = safeJson(row.props) || {};
  const observed: ResourceNode["observed"] = [apiObserved(row)];
  const metric = props.messages_30d ?? props.requests_30d ?? props.scanned_gb_30d;
  if (metric != null) observed.push({ kind: "metrics", status: "ok", last_at: str(row.last_seen), detail: props.messages_30d != null ? "publishes over 30 days" : props.requests_30d != null ? "requests over 30 days" : "bytes scanned over 30 days" });
  const tags = safeJson(row.tags);
  return base(String(row.id), label, String(row.native_type), row, str(row.name), str(row.state), str(row.region) || null, roles, {
    ...flatProps(props), created_at: str(row.created), tags: tags && Object.keys(tags).length ? JSON.stringify(tags) : null,
  }, observed);
}

/**
 * What an identity was seen signing in or calling with (src/sign_ins.ts): one line per client, the platforms, the
 * channels and the factors, and the strongest second factor seen.
 */
function clientProps(raw: unknown): { sign_in_clients: string[]; platforms: string[]; channels: string[]; factors: string[] } {
  const clients: ClientUse[] = safeJson(raw) || [];
  return { sign_in_clients: clients.map(clientLine), platforms: [...new Set(clients.map((c) => c.platform).filter((p): p is string => Boolean(p)))], channels: [...new Set(clients.map((c) => c.channel))], factors: [...new Set(clients.flatMap((c) => c.factors))] };
}

/**
 * An IAM role as an AdvisorIdentity {kind: role}: who may assume it (`trust` in the ontology's words, `trusted_by` one
 * line per principal with what its conditions narrow it to), whether it is administrative, when it was last used, and
 * the widest-trust risk the collector raised (src/role_trust.ts).
 */
export function resourceFromRole(row: any): ResourceNode {
  const ps: any[] = safeJson(row.principals) || [];
  return base(String(row.arn), "AdvisorIdentity", "iam_role", row, str(row.name), Boolean(row.gone) ? "terminated" : "available", null, new Map(), {
    kind: "role", human: false, trust: str(row.trust), admin: Boolean(row.admin), last_used_at: str(row.last_used), last_used_region: str(row.last_used_region), policies: safeJson(row.policies) || [], path: str(row.path), description: str(row.description), created_at: str(row.created),
    trusted_by: ps.filter((p) => p.kind !== "service").map((p) => `${p.kind}: ${p.who}${p.scope?.length ? ` [${p.scope.join(", ")}]` : ""}${p.external_id ? " (external id)" : ""}`),
    trusted_services: ps.filter((p) => p.kind === "service").map((p) => String(p.who)), trust_kinds: [...new Set(ps.map((p) => String(p.kind)))],
    trust_risk: str(row.risk), trust_risk_reason: str(row.risk_reason), max_session_hours: num(row.max_session_hours),
  }, [apiObserved(row)]);
}

/** The root user of an account as an AdvisorIdentity {native_type: root_user}: a person, administrator of everything, MFA and its kind, root keys, last sign-in. */
export function resourceFromRootUser(row: any): ResourceNode {
  const clients: ClientUse[] = safeJson(row.clients) || [];
  const seen = strongestMfa(clients);
  const kind = row.mfa_kind === "passkey_or_hardware" && (seen === "passkey" || seen === "hardware") ? seen : str(row.mfa_kind);
  const lastSignIn = [...clients.filter((c) => (c.via || []).includes("sign-in")).map((c) => c.last_at), str(row.password_last_used)].filter(Boolean).sort().pop() ?? null;
  return base(String(row.arn), "AdvisorIdentity", "root_user", row, "root", Boolean(row.gone) ? "terminated" : "available", null, new Map(), {
    kind: "user", human: true, admin: true, mfa: bool(row.mfa_enabled), mfa_type: row.mfa_enabled ? kind : null, credentials: num(row.access_keys) ?? 0, signing_certificates: num(row.signing_certs),
    last_used_at: lastSignIn, password_last_used: str(row.password_last_used), key_last_used: str(row.key_last_used), centralized_root_access: bool(row.centralized), root_sessions: bool(row.root_sessions),
    ...clientProps(row.clients),
  }, [apiObserved(row)]);
}

/** An IAM user as an AdvisorIdentity {kind: user}: human when it has console access, with MFA, admin, credentials and last use as the ontology names them. */
/** An Identity Center user as an AdvisorIdentity {kind: user, native_type: sso_user}: always a person, MFA unknown to the API, admin through an administrative permission set, last_used_at the last portal sign-in. */
export function resourceFromSsoUser(row: any): ResourceNode {
  const assignments: any[] = safeJson(row.assignments) || [];
  const activity = safeJson(row.activity) || {};
  const seen = strongestMfa(safeJson(row.clients) || []);
  return base(String(row.user_id), "AdvisorIdentity", "sso_user", row, str(row.user_name), Boolean(row.gone) ? "terminated" : row.status === "DISABLED" ? "disabled" : "available", null, new Map(), {
    kind: "user", human: true, enabled: row.status == null ? null : row.status !== "DISABLED", mfa: seen ? true : null, mfa_type: seen, ...clientProps(row.clients),
    directory_changes: ((safeJson(row.changes) || []) as any[]).map((c) => `${String(c.event_time).slice(0, 10)} ${c.what}${c.by ? ` by ${c.by}` : ""}${c.failed ? " (failed)" : ""}`), admin: Boolean(row.admin), credentials: 0, credential_age_days: null, last_used_at: str(row.last_sign_in), display_name: str(row.display_name), email: str(row.email), identity_provider: str(row.idp),
    groups: safeJson(row.groups) || [], policies: [...new Set(assignments.map((a) => String(a.permission_set)))], accounts: [...new Set(assignments.map((a) => String(a.account_id)))], assignments: assignments.map((a) => `${a.account_id} ${a.permission_set} (${a.via})`),
    applications: safeJson(row.applications) || [], sign_ins_30d: num(row.sign_ins_30d), failed_sign_ins_30d: num(row.failed_30d), activity: Object.entries(activity).map(([acct, t]) => `${acct} ${String(t).slice(0, 16)}`), identity_store_id: str(row.identity_store_id),
  }, [apiObserved(row)]);
}

export function resourceFromIamUser(row: any): ResourceNode {
  const keys = safeJson(row.access_keys) || [];
  const mfa = iamUserMfa(safeJson(row.mfa_types) || [], Boolean(row.mfa_enabled), safeJson(row.clients) || []);
  return base(String(row.arn), "AdvisorIdentity", "iam_user", row, str(row.name), Boolean(row.gone) ? "terminated" : "available", null, new Map(), {
    kind: "user", human: Boolean(row.console_access), console_access: Boolean(row.console_access), mfa: Boolean(row.mfa_enabled), mfa_type: mfa.mfa === "none" ? null : mfa.mfa, mfa_devices: safeJson(row.mfa_types) || [], ...clientProps(row.clients), admin: Boolean(row.admin), credentials: Number(row.keys_active || 0), credential_age_days: num(row.oldest_key_days),
    last_used_at: str(row.last_used), password_last_used: str(row.password_last_used), groups: safeJson(row.groups) || [], policies: [...(safeJson(row.attached_policies) || []), ...(safeJson(row.inline_policies) || [])], permissions_boundary: str(row.permissions_boundary),
    access_keys: keys.map((k: any) => `${k.id} ${k.status}${k.age_days != null ? ` ${k.age_days}d` : ""}${k.last_used ? ` used ${String(k.last_used).slice(0, 10)}` : " never used"}`), created_at: str(row.created), user_id: str(row.user_id),
  }, [apiObserved(row)]);
}

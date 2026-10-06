import { listAccounts } from "../../accounts.js";
import { config } from "../../config.js";
import { db } from "../../db.js";
import { credentialsMeta, hasConnectionFile } from "../../steampipe.js";
import { AWS, type AccountRecord, type ProviderAdapter, type ResourceNode } from "../types.js";
import { cachedResourceIndex, resourceIndexFor } from "../../resource_index.js";
import { AWS_JOBS } from "./jobs.js";
import { awsAttention, awsCost } from "./overview.js";
import { awsOnboarding } from "./onboarding.js";
import { ALL_BENCHMARKS, DEFAULT_BENCHMARKS } from "../../powerpipe.js";
import { CONTROL_SOURCES } from "../../playbooks.js";
import { TELEMETRY, lambdaArn, resourceFromDnsRecord, resourceFromDynamodb, resourceFromEbs, resourceFromEc2, resourceFromElasticache, resourceFromElb, resourceFromIamUser, resourceFromLambda, resourceFromRole, resourceFromRootUser, resourceFromSsoUser, resourceFromRds, resourceFromS3, resourceFromService, resourceFromZone, type RoleMap } from "./resources.js";

/**
 * The AWS adapter: Steampipe and the SDK behind the generic model. Credentials and the parent/member registry are
 * src/steampipe.ts and src/accounts.ts; collection is src/inventory.ts and the modules it calls; the storage is the
 * inventory_* and instance_* tables plus the network, cluster, software and advisory tables listed under `storage`.
 * The mapping onto the generic model is ./resources.ts; the graph layers beyond resources are the mirror modules
 * this adapter wires in order. A second provider implements the same shape (src/adapters/types.ts) with its own
 * credentials, storage and layers; nothing above the boundary names AWS.
 */

const rows = (sql: string): any[] => { try { return db.prepare(sql).all() as any[]; } catch { return []; } };

/** The roles the classifier judged, by resource id, for the resource rows. */
function roleMap(): RoleMap {
  const out: RoleMap = new Map();
  for (const r of rows("select resource_id, role, role_confidence, protected_prob from resource_roles")) out.set(String(r.resource_id), { role: String(r.role), role_confidence: r.role_confidence == null ? null : Number(r.role_confidence), protected_prob: r.protected_prob == null ? null : Number(r.protected_prob) });
  return out;
}

const accessWords = (): string => {
  const m = credentialsMeta();
  if (!m) return "not configured";
  const base = m.mode === "profile" ? `profile ${m.profile}` : m.mode === "chain" ? "instance / default chain" : `access key ${m.accessKeyMasked || ""}`.trim();
  return m.roleArn ? `${base}, assuming ${String(m.roleArn).split("/").pop()}` : base;
};

const AWS_LAYERS: ProviderAdapter["layers"] = [
    { name: "containers", mirror: async () => (await import("../../graph_containers.js")).mirrorContainers() },
    { name: "apps and ports", mirror: async () => (await import("../../graph_mirror.js")).mirrorApps() },
    { name: "status checks", mirror: async () => (await import("../../graph_mirror.js")).mirrorStatusChecks() },
    { name: "usage profiles", mirror: async () => (await import("../../graph_mirror.js")).mirrorUsageProfiles() },
    { name: "capacity patterns", mirror: async () => (await import("../../graph_mirror.js")).mirrorCapacityPatterns() },
    { name: "network", after_run: true, mirror: async () => (await import("../../graph_network.js")).mirrorNetwork() },
    { name: "clusters", after_run: true, mirror: async () => (await import("../../graph_clusters.js")).mirrorClusters() },
    { name: "threat findings", mirror: async () => (await import("../../graph_services.js")).mirrorThreatFindings() },
    { name: "notifications", mirror: async () => (await import("../../graph_mirror.js")).mirrorCloudNotifications() },
    { name: "software", mirror: async () => (await import("../../graph_software.js")).mirrorSoftware() },
    { name: "security scan", mirror: async () => { const scan = db.prepare("select id from compliance_scans where status = 'completed' order by id desc limit 1").get() as { id: number } | undefined; return scan ? (await import("../../graph_mirror.js")).mirrorComplianceScan(scan.id) : null; } },
];

export const awsAdapter: ProviderAdapter = {
  id: AWS,
  label: "AWS",
  flow: { boundary: "account", credentials: "a role to assume from the advisor's identity (read role, optional actuator role), or keys / a profile for the first one; the one-command setup creates them", children: "member accounts reached through a role from the parent; the Organizations management account can list them" },
  capabilities: { probes: true, metrics: true, executor: true, compliance: true, cost: true, bill: true, findings: true, changes: true, alerts: true, clusters: true, software: true, network: true },
  storage: ["inventory_ec2", "inventory_rds", "inventory_elasticache", "inventory_elb", "inventory_lambda", "inventory_dynamodb", "inventory_s3", "inventory_ebs", "inventory_route53_zone", "inventory_route53_record", "inventory_route53_link", "inventory_service", "threat_findings", "inventory_subnet", "inventory_route_table", "inventory_gateway", "inventory_eip", "inventory_eni", "inventory_cluster",
    "sg_ingress", "sg_egress", "instance_metrics", "instance_apps", "instance_ports", "instance_containers", "instance_os", "instance_packages", "instance_binaries", "instance_images", "package_changes", "cluster_workloads", "cluster_services", "cluster_ingresses", "cluster_network_policies", "alas_advisories", "alas_packages", "status_checks", "capacity_patterns"],
  telemetry: TELEMETRY,
  configured: () => hasConnectionFile(),
  primaryAccountId: () => {
    // the account the credentials resolve to now; the latest run only when no credential test has said yet (runs are history: after a re-point they name the previous parent)
    const meta = credentialsMeta()?.accountId;
    if (meta) return meta;
    const run = db.prepare("select account_id from runs where provider = 'aws' and account_id is not null and account_id <> '' order by id desc limit 1").get() as { account_id: string } | undefined;
    return run?.account_id || "unknown";
  },
  async accounts(): Promise<AccountRecord[]> {
    if (!hasConnectionFile()) return [];
    const all = listAccounts();
    const parent = all.find((a) => a.is_parent); const parentId = parent?.account_id || awsAdapter.primaryAccountId();
    return all.map((a) => ({
      provider: AWS, id: a.is_parent ? parentId : a.account_id, native_type: "account", name: a.name, parent_id: a.is_parent ? null : parentId,
      access: a.is_parent ? accessWords() : `role ${a.role_arn.split("/").pop()} from the parent`,
      actuator: a.is_parent ? Boolean(config.actRoleArn) : Boolean(a.act_role_arn), enabled: a.enabled,
      last_test: a.is_parent ? (credentialsMeta()?.savedAt ? { ok: Boolean(parentId && parentId !== "unknown"), detail: parentId && parentId !== "unknown" ? `connected as account ${parentId}` : "saved, not tested yet", at: credentialsMeta()?.savedAt ?? null } : null)
        : a.last_test ? { ok: a.last_test.ok, detail: a.last_test.ok ? a.last_test.arn ?? null : a.last_test.error ?? null, at: a.last_test.at } : null,
    }));
  },
  async collect(opts = {}) {
    const { refreshInventory } = await import("../../inventory.js");
    const r = await refreshInventory({ dns: opts.full !== false });
    return { errors: (r as any).errors ?? [] };
  },
  resources(account: string): ResourceNode[] {
    const roles = roleMap();
    // each row carries the account it was collected from (a member account's rows carry the member's id); the mirror attaches it to that node
    const own = resourceIndexFor(AWS, account);
    return [...rawResources(account, roles)].map((n) => ({ ...n, account_id: own.of(n.id) ?? account }));
  },
  resourceIds: (account) => inventoryIds(account),
  edges: async (account, stamp) => (await import("./edges.js")).mirrorAwsEdges(account, stamp),
  layers: AWS_LAYERS,
  legacy_blank_account: true,
  // every AWS account id is twelve digits, and nothing else's is
  owns: (id) => ACCOUNT_ID.test(id),
  accountOf(resource, details) {
    const idx = cachedResourceIndex(AWS, awsAdapter.primaryAccountId());
    const d = (details ?? {}) as Record<string, any>;
    const explicit = [d.account_id, d.run_account_id].find((x) => typeof x === "string" && ACCOUNT_ID.test(x)) as string | undefined;
    // the resource first, then an account the row states, then whatever the details name that the inventories know (an instance, a pool, a log group, a network)
    return idx.of(resource) ?? explicit ?? idx.of(d.instance_id) ?? idx.of(d.pool) ?? idx.of(d.log_group) ?? idx.of(d.vpc_id) ?? idx.of(d.nat_gateway_id)
      ?? (Array.isArray(d.events) ? d.events.map((e: any) => idx.of(e?.instance_id)).find(Boolean) ?? null : null);
  },
  onStart() {
    // the EC2 status checks of the running fleet, read now rather than at the watcher's next cycle: an impaired box alerts within a minute of a deploy
    setTimeout(() => import("../../status_checks.js").then((m) => m.refreshStatusChecks((l) => console.log(`[status-checks] ${l}`))).catch((e) => console.error(`[status-checks] at start: ${e?.message || e}`)), 20_000).unref();
    // the fleet's latest probes, judged now: a disk that filled while the advisor was down alerts at once
    import("../../disk_alerts.js").then((m) => { const r = m.checkAllDiskLevels(); if (r.raised) console.log(`[disk] ${r.raised} disk alert(s) from the latest probes of ${r.instances} instances`); }).catch((e) => console.error(`[disk] startup check failed: ${e?.message || e}`));
    import("../../host_alerts.js").then((m) => { const r = m.checkAllHostLevels(); if (r.raised) console.log(`[host] ${r.raised} host alert(s) from the latest probes of ${r.instances} instances`); }).catch((e) => console.error(`[host] startup check failed: ${e?.message || e}`));
  },
  jobs: AWS_JOBS,
  onboarding: awsOnboarding,
  agentNote: () => { const id = credentialsMeta()?.accountId; return id ? `AWS account ${id} (the default for every aws_* table and tool)` : null; },
  // the AWS-only pages' APIs: security scans, probes, clusters, vulnerabilities, Identity Center, AWS notifications, swarms, tags
  routes: async () => [(await import("../../routes/swarms.js")).swarms, (await import("../../routes/tags.js")).tags, (await import("../../routes/security.js")).security, (await import("../../routes/probes.js")).probes,
    (await import("../../routes/clusters.js")).clusters, (await import("../../routes/vulnerabilities.js")).vulnerabilities, (await import("../../routes/identity_center.js")).identityCenter, (await import("../../routes/cloud_notifications.js")).cloudNotifications],
  cost: awsCost(() => awsAdapter.primaryAccountId()),
  attention: () => awsAttention(awsAdapter.primaryAccountId()),
  // the collection run (src/collector.ts): Powerpipe's Thrifty benchmarks, the fact queries and the rules (src/rules.ts); the security scan (src/compliance.ts) has its own scans table
  rules: {
    latestRunId: () => (db.prepare("select id from runs where provider = 'aws' and status = 'completed' order by id desc limit 1").get() as { id: number } | undefined)?.id,
    benchmarks: () => ({ all: [...ALL_BENCHMARKS], defaults: [...DEFAULT_BENCHMARKS] }),
    start: async (trigger) => {
      const { isBusy, startRun } = await import("../../collector.js");
      if (isBusy()) return { run_id: null, note: "a run is already in progress" };
      return { run_id: startRun(trigger), note: "started" };
    },
    run_native_type: "collection_run",
    control_prefixes: ["aws_", "query.", "rule."],
    controlFacts(controlId, benchmark) {
      const id = controlId.toLowerCase(); const b = String(benchmark || "").toLowerCase();
      if (id.startsWith("aws_compliance.") || b) return { framework: b.includes("cis") || id.includes("cis_") ? "cis" : b.includes("foundational") || id.includes("foundational") ? "foundational_security" : "compliance", category: "security" };
      if (id.startsWith("aws_thrifty.")) return { framework: "cost", category: "cost" };
      return null;
    },
    controlSources: () => CONTROL_SOURCES,
    playbooks_from: "alarm",
    seed_playbooks: true,
  },
  // the executor's AWS modules (src/actions/), run under the parent's and each enabled member's read and actuator roles
  actions: {
    register: async () => { await import("../../actions/index.js"); },
    credentials: async () => (await import("../../executor.js")).executorCreds(),
  },
  ui: {
    overview: "aws.overview", bill: "aws.bill", changes: "aws.changes",
    inventory: [
      { tab: "ec2", view: "aws.table", label: "EC2 instances" }, { tab: "rds", view: "aws.table", label: "RDS" }, { tab: "elasticache", view: "aws.table", label: "ElastiCache" }, { tab: "lambda", view: "aws.table", label: "Lambda" },
      { tab: "dynamodb", view: "aws.table", label: "DynamoDB" }, { tab: "elb", view: "aws.table", label: "ELB" }, { tab: "ebs", view: "aws.table", label: "EBS" }, { tab: "s3", view: "aws.table", label: "S3 buckets" },
      { tab: "route53", view: "aws.table", label: "Route 53" }, { tab: "clusters", view: "aws.table", label: "EKS, ECS" }, { tab: "identities", view: "aws.table", label: "IAM users · IAM Identity Center" }, { tab: "sg", view: "aws.table", label: "security groups" },
      { tab: "tags", view: "aws.table", label: "AWS tags" }, { tab: "certificates", view: "aws.table", label: "ACM" }, { tab: "messaging", view: "aws.table", label: "SNS" }, { tab: "keys", view: "aws.table", label: "KMS" },
      { tab: "files", view: "aws.table", label: "EFS" }, { tab: "backups", view: "aws.table", label: "AWS Backup vaults and plans" }, { tab: "analytics", view: "aws.table", label: "Athena workgroups" }, { tab: "stacks", view: "aws.table", label: "CloudFormation" },
      { tab: "threats", view: "aws.table", label: "GuardDuty" },
    ],
    settings: [{ id: "access", label: "Access", view: "aws.access" }, { id: "permissions", label: "Permissions", view: "aws.permissions" }, { id: "probes", label: "Probes", view: "aws.probes" }, { id: "benchmarks", label: "Benchmarks", view: "aws.benchmarks" }, { id: "members", label: "Member accounts", view: "aws.members" }],
  },
};

const ACCOUNT_ID = /^\d{12}$/;

/** Every id the mirror writes a resource node for, so references in records (recommendations, alerts, actions) can be matched to nodes; cheaper than building the nodes. */
function inventoryIds(account: string): Set<string> {
  const ids = new Set<string>();
  for (const r of rows("select instance_id as id from inventory_ec2")) ids.add(r.id);
  for (const r of rows("select db_instance_identifier as id from inventory_rds")) ids.add(r.id);
  for (const r of rows("select cache_cluster_id as id from inventory_elasticache")) ids.add(r.id);
  for (const r of rows("select arn as id from inventory_elb")) ids.add(r.id);
  for (const r of rows("select name, arn, region from inventory_lambda")) ids.add(lambdaArn(r, account));
  for (const r of rows("select name as id from inventory_s3")) ids.add(r.id);
  for (const r of rows("select volume_id as id from inventory_ebs")) ids.add(r.id);
  for (const r of rows("select zone_id as id from inventory_route53_zone")) ids.add(r.id);
  for (const r of rows("select arn as id from inventory_dynamodb where arn is not null")) ids.add(r.id);
  for (const r of rows("select arn as id from inventory_iam_user")) ids.add(r.id);
  for (const r of rows("select arn as id from inventory_root_user")) ids.add(r.id);
  for (const r of rows("select arn as id from inventory_iam_role")) ids.add(r.id);
  // certificates, topics, keys, file systems, vaults, plans, workgroups, stacks, web ACLs, detectors (src/service_inventory.ts)
  for (const r of rows("select id from inventory_service")) ids.add(r.id);
  return ids;
}

function rawResources(account: string, roles: ReturnType<typeof roleMap>): ResourceNode[] {
    return [
      ...rows("select * from inventory_ec2").map((r) => resourceFromEc2(r, roles)),
      ...rows("select * from inventory_rds").map((r) => resourceFromRds(r, roles)),
      ...rows("select * from inventory_elasticache").map((r) => resourceFromElasticache(r, roles)),
      ...rows("select * from inventory_elb").map((r) => resourceFromElb(r, roles)),
      ...rows("select * from inventory_lambda").map((r) => resourceFromLambda(r, account, roles)),
      ...rows("select * from inventory_dynamodb").map((r) => resourceFromDynamodb(r, account, roles)),
      ...rows("select * from inventory_s3").map((r) => resourceFromS3(r, roles)),
      ...rows("select * from inventory_ebs").map((r) => resourceFromEbs(r, roles)),
      ...rows("select * from inventory_route53_zone").map(resourceFromZone),
      ...rows("select * from inventory_route53_record").map(resourceFromDnsRecord),
      ...rows("select * from inventory_iam_user").map(resourceFromIamUser),
      ...rows("select * from inventory_sso_user").map(resourceFromSsoUser),
      ...rows("select * from inventory_root_user").map(resourceFromRootUser),
      // roles a person, another account, a pipeline or a pod may assume; service-linked and pure service roles stay out of the graph
      ...rows("select * from inventory_iam_role where coalesce(path, '') not like '/aws-service-role/%' and coalesce(trust, 'service') not in ('service', 'none')").map(resourceFromRole),
      ...rows("select * from inventory_service").map((r) => resourceFromService(r, roles)).filter((n): n is ResourceNode => n != null),
    ];
}

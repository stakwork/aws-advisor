import { listAccounts } from "../../accounts.js";
import { config } from "../../config.js";
import { db } from "../../db.js";
import { credentialsMeta, hasConnectionFile } from "../../steampipe.js";
import { AWS, type AccountRecord, type ProviderAdapter, type ResourceNode } from "../types.js";
import { resourceAccountIndex } from "../../resource_index.js";
import { TELEMETRY, resourceFromDnsRecord, resourceFromDynamodb, resourceFromEbs, resourceFromEc2, resourceFromElasticache, resourceFromElb, resourceFromIamUser, resourceFromLambda, resourceFromRds, resourceFromS3, resourceFromZone, type RoleMap } from "./resources.js";

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
    { name: "apps and ports", mirror: async () => (await import("../../graph_mirror.js")).mirrorApps() },
    { name: "status checks", mirror: async () => (await import("../../graph_mirror.js")).mirrorStatusChecks() },
    { name: "usage profiles", mirror: async () => (await import("../../graph_mirror.js")).mirrorUsageProfiles() },
    { name: "capacity patterns", mirror: async () => (await import("../../graph_mirror.js")).mirrorCapacityPatterns() },
    { name: "network", mirror: async () => (await import("../../graph_network.js")).mirrorNetwork() },
    { name: "clusters", mirror: async () => (await import("../../graph_clusters.js")).mirrorClusters() },
    { name: "software", mirror: async () => (await import("../../graph_software.js")).mirrorSoftware() },
];

export const awsAdapter: ProviderAdapter = {
  id: AWS,
  label: "AWS",
  flow: { boundary: "account", credentials: "a role to assume from the advisor's identity (read role, optional actuator role), or keys / a profile for the first one; the one-command setup creates them", children: "member accounts reached through a role from the parent; the Organizations management account can list them" },
  capabilities: { probes: true, metrics: true, executor: true, compliance: true, cost: true, bill: true, findings: true, changes: true, alerts: true, clusters: true, software: true, network: true },
  sections: [{ id: "access", label: "Access" }, { id: "permissions", label: "Permissions" }, { id: "probes", label: "Probes" }, { id: "benchmarks", label: "Benchmarks" }, { id: "members", label: "Member accounts" }],
  storage: ["inventory_ec2", "inventory_rds", "inventory_elasticache", "inventory_elb", "inventory_lambda", "inventory_dynamodb", "inventory_s3", "inventory_ebs", "inventory_route53_zone", "inventory_route53_record", "inventory_route53_link", "inventory_subnet", "inventory_route_table", "inventory_gateway", "inventory_eip", "inventory_eni", "inventory_cluster",
    "sg_ingress", "sg_egress", "instance_metrics", "instance_apps", "instance_ports", "instance_os", "instance_packages", "instance_binaries", "instance_images", "package_changes", "cluster_workloads", "cluster_services", "cluster_ingresses", "cluster_network_policies", "alas_advisories", "alas_packages", "status_checks", "capacity_patterns"],
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
    const own = resourceAccountIndex(account);
    return [...rawResources(account, roles)].map((n) => ({ ...n, account_id: own.of(n.id) ?? account }));
  },
  edges: async (account, stamp) => (await import("./edges.js")).mirrorAwsEdges(account, stamp),
  layers: AWS_LAYERS,
};

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
    ];
}

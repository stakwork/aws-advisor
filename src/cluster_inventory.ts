import { db } from "./db.js";
import { S } from "./steampipe.js";
import { K8sError, type K8sCluster, eksToken, k8sListAll } from "./k8s_client.js";
import { accountWhere, scopedStmt, type AccountScope } from "./scope.js";

/**
 * Clusters and the workloads inside them (docs/cloud-ontology.md §8 step 4): EKS clusters with their Kubernetes
 * Deployments, StatefulSets, DaemonSets, Jobs, CronJobs, Services, Ingresses and NetworkPolicies read from the
 * cluster API (src/k8s_client.ts), and ECS clusters with their services and task definitions read from Steampipe.
 * Every workload is one row with its containers and images, its replicas, where its pods run, and what exposes it,
 * so the graph can draw `AdvisorDeployment` nodes inside `AdvisorCluster` with endpoints and reachability. A cluster
 * the advisor cannot read keeps its row with `access_status` and the reason, and the page shows how to grant access.
 */

db.exec(`create table if not exists inventory_cluster (
  arn text primary key, kind text not null, name text not null, region text, account_id text, version text, platform_version text, status text,
  endpoint text, endpoint_public integer, public_cidrs text not null default '[]', endpoint_private integer, vpc_id text, security_groups text not null default '[]', subnets text not null default '[]',
  authentication_mode text, oidc_issuer text, ca_data text, nodes integer, workloads integer not null default 0, namespaces text not null default '[]',
  access_status text, access_error text, access_checked_at text, first_seen text not null, last_seen text not null, gone integer not null default 0
);
create table if not exists cluster_workloads (
  id text primary key, cluster_arn text not null, namespace text, kind text not null, name text not null, uid text,
  replicas_desired integer, replicas_ready integer, containers text not null default '[]', images text not null default '[]', labels text not null default '{}', selector text not null default '{}',
  service_account text, created text, revision text, nodes text not null default '[]', pods_running integer, strategy text, schedule text,
  first_seen text not null, last_seen text not null, gone integer not null default 0
);
create index if not exists cluster_workloads_cluster on cluster_workloads(cluster_arn, gone);
create table if not exists cluster_services (
  id text primary key, cluster_arn text not null, namespace text, name text, type text, cluster_ip text, ports text not null default '[]', selector text not null default '{}', lb_hostnames text not null default '[]',
  first_seen text not null, last_seen text not null, gone integer not null default 0
);
create table if not exists cluster_ingresses (
  id text primary key, cluster_arn text not null, namespace text, name text, class text, hosts text not null default '[]', rules text not null default '[]', lb_hostnames text not null default '[]', tls integer not null default 0,
  first_seen text not null, last_seen text not null, gone integer not null default 0
);
create table if not exists cluster_network_policies (
  id text primary key, cluster_arn text not null, namespace text, name text, pod_selector text not null default '{}', policy_types text not null default '[]', ingress text not null default '[]', egress text not null default '[]',
  first_seen text not null, last_seen text not null, gone integer not null default 0
)`);

export const CLUSTER_SQL = {
  eks: `select name, arn, region, account_id, version, platform_version, status, endpoint, resources_vpc_config, access_config, identity, certificate_authority, tags from ${S}.aws_eks_cluster`,
  eks_nodes: `select cluster_name, nodegroup_name, status, instance_types, scaling_config, resources from ${S}.aws_eks_node_group`,
  ecs: `select cluster_arn, cluster_name, region, account_id, status, active_services_count, running_tasks_count, registered_container_instances_count, capacity_providers from ${S}.aws_ecs_cluster`,
  ecs_services: `select service_name, arn, cluster_arn, task_definition, desired_count, running_count, launch_type, status, load_balancers, network_configuration, created_at, region from ${S}.aws_ecs_service`,
  ecs_task_definitions: `select task_definition_arn, family, revision, cpu, memory, network_mode, container_definitions from ${S}.aws_ecs_task_definition where status = 'ACTIVE'`,
  ecs_tasks: `select task_arn, cluster_arn, task_definition_arn, last_status, launch_type, container_instance_arn, service_name, containers, started_at from ${S}.aws_ecs_task where last_status = 'RUNNING'`,
  ecs_container_instances: `select arn, ec2_instance_id, cluster_arn from ${S}.aws_ecs_container_instance`,
} as const;

const arr = (v: unknown): any[] => (Array.isArray(v) ? v : typeof v === "string" ? (() => { try { const x = JSON.parse(v); return Array.isArray(x) ? x : []; } catch { return []; } })() : []);
const obj = (v: unknown): any => (v && typeof v === "object" && !Array.isArray(v) ? v : typeof v === "string" ? (() => { try { const x = JSON.parse(v); return x && typeof x === "object" ? x : {}; } catch { return {}; } })() : {});
const str = (v: unknown): string | null => (v == null ? null : String(v));
const num = (v: unknown): number | null => (v == null || v === "" || !Number.isFinite(Number(v)) ? null : Number(v));
const json = (v: unknown) => JSON.stringify(v ?? null);
const now = () => new Date().toISOString();

// ---- pure mapping: Kubernetes objects into workload rows ---------------------------------------------------------------------

export interface WorkloadRow { id: string; cluster_arn: string; namespace: string | null; kind: string; name: string; uid: string | null; replicas_desired: number | null; replicas_ready: number | null; containers: { name: string; image: string; ports: { port: number; protocol: string; name?: string | null }[] }[]; images: string[]; labels: Record<string, string>; selector: Record<string, string>; service_account: string | null; created: string | null; revision: string | null; nodes: string[]; pods_running: number | null; strategy: string | null; schedule: string | null }

const WORKLOAD_KINDS: Record<string, string> = { Deployment: "deployment", StatefulSet: "statefulset", DaemonSet: "daemonset", Job: "job", CronJob: "cronjob" };

/** One Kubernetes workload object (apps/v1 or batch/v1) as a row; pods give the nodes it runs on. Pure. */
export function workloadFromK8s(clusterArn: string, o: any, pods: any[] = []): WorkloadRow {
  const kind = String(o.kind || "");
  const meta = o.metadata || {}; const spec = o.spec || {}; const status = o.status || {};
  const template = kind === "CronJob" ? spec.jobTemplate?.spec?.template?.spec : spec.template?.spec;
  const containers = [...(template?.containers || []), ...(template?.initContainers || [])].map((c: any) => ({ name: String(c.name || ""), image: String(c.image || ""), ports: (c.ports || []).map((p: any) => ({ port: Number(p.containerPort), protocol: String(p.protocol || "TCP").toLowerCase(), name: p.name ?? null })).filter((p: any) => Number.isFinite(p.port)) }));
  const selector = spec.selector?.matchLabels || (kind === "CronJob" ? {} : spec.selector || {});
  const mine = pods.filter((p) => p.metadata?.namespace === meta.namespace && ownedBy(p, o));
  const nodes: string[] = [...new Set<string>(mine.map((p) => p.spec?.nodeName).filter(Boolean).map(String))];
  const running = mine.filter((p) => p.status?.phase === "Running").length;
  return {
    id: `${clusterArn}/${meta.namespace || "_"}/${kind}/${meta.name}`, cluster_arn: clusterArn, namespace: str(meta.namespace), kind: WORKLOAD_KINDS[kind] || kind.toLowerCase(), name: String(meta.name || ""), uid: str(meta.uid),
    replicas_desired: kind === "DaemonSet" ? num(status.desiredNumberScheduled) : kind === "CronJob" || kind === "Job" ? num(spec.parallelism ?? 1) : num(spec.replicas ?? 1),
    replicas_ready: kind === "DaemonSet" ? num(status.numberReady) : kind === "Job" ? num(status.succeeded) : kind === "CronJob" ? num(status.active?.length ?? 0) : num(status.readyReplicas ?? 0),
    containers, images: [...new Set(containers.map((c) => c.image).filter(Boolean))], labels: meta.labels || {}, selector: selector || {}, service_account: str(template?.serviceAccountName),
    created: str(meta.creationTimestamp), revision: str(meta.annotations?.["deployment.kubernetes.io/revision"] ?? meta.labels?.["app.kubernetes.io/version"] ?? null),
    nodes, pods_running: mine.length ? running : null, strategy: str(spec.strategy?.type ?? spec.updateStrategy?.type ?? null), schedule: str(spec.schedule),
  };
}

/** Whether a pod belongs to a workload: through its ReplicaSet (Deployment), directly (StatefulSet, DaemonSet, Job), or through a Job (CronJob); by labels when the owner chain is not loaded. */
function ownedBy(pod: any, o: any): boolean {
  const owners: any[] = pod.metadata?.ownerReferences || [];
  const kind = String(o.kind); const name = String(o.metadata?.name);
  if (owners.some((r) => r.kind === kind && r.name === name)) return true;
  if (kind === "Deployment" && owners.some((r) => r.kind === "ReplicaSet" && String(r.name).startsWith(`${name}-`))) return true;
  if (kind === "CronJob" && owners.some((r) => r.kind === "Job" && String(r.name).startsWith(`${name}-`))) return true;
  const sel = o.spec?.selector?.matchLabels; const labels = pod.metadata?.labels || {};
  return Boolean(sel && Object.keys(sel).length && Object.entries(sel).every(([k, v]) => labels[k] === v) && !owners.length);
}

export interface ServiceRow { id: string; cluster_arn: string; namespace: string | null; name: string; type: string; cluster_ip: string | null; ports: { port: number; target_port: string | number | null; node_port: number | null; protocol: string; name: string | null }[]; selector: Record<string, string>; lb_hostnames: string[] }
export function serviceFromK8s(clusterArn: string, o: any): ServiceRow {
  const meta = o.metadata || {}; const spec = o.spec || {};
  return { id: `${clusterArn}/${meta.namespace || "_"}/Service/${meta.name}`, cluster_arn: clusterArn, namespace: str(meta.namespace), name: String(meta.name || ""), type: String(spec.type || "ClusterIP"), cluster_ip: spec.clusterIP === "None" ? null : str(spec.clusterIP),
    ports: (spec.ports || []).map((p: any) => ({ port: Number(p.port), target_port: p.targetPort ?? null, node_port: num(p.nodePort), protocol: String(p.protocol || "TCP").toLowerCase(), name: p.name ?? null })).filter((p: any) => Number.isFinite(p.port)),
    selector: spec.selector || {}, lb_hostnames: (o.status?.loadBalancer?.ingress || []).map((i: any) => i.hostname || i.ip).filter(Boolean).map(String) };
}

export interface IngressRow { id: string; cluster_arn: string; namespace: string | null; name: string; class: string | null; hosts: string[]; rules: { host: string | null; path: string; service: string | null; port: number | string | null }[]; lb_hostnames: string[]; tls: boolean }
export function ingressFromK8s(clusterArn: string, o: any): IngressRow {
  const meta = o.metadata || {}; const spec = o.spec || {};
  const rules: IngressRow["rules"] = [];
  for (const r of spec.rules || []) for (const p of r.http?.paths || []) rules.push({ host: r.host ?? null, path: String(p.path || "/"), service: p.backend?.service?.name ?? null, port: p.backend?.service?.port?.number ?? p.backend?.service?.port?.name ?? null });
  if (spec.defaultBackend?.service) rules.push({ host: null, path: "/*", service: spec.defaultBackend.service.name ?? null, port: spec.defaultBackend.service.port?.number ?? null });
  return { id: `${clusterArn}/${meta.namespace || "_"}/Ingress/${meta.name}`, cluster_arn: clusterArn, namespace: str(meta.namespace), name: String(meta.name || ""), class: str(spec.ingressClassName ?? meta.annotations?.["kubernetes.io/ingress.class"] ?? null),
    hosts: [...new Set<string>((spec.rules || []).map((r: any) => r.host).filter(Boolean).map(String))], rules, lb_hostnames: (o.status?.loadBalancer?.ingress || []).map((i: any) => i.hostname || i.ip).filter(Boolean).map(String), tls: Boolean((spec.tls || []).length) };
}

export interface NetworkPolicyRow { id: string; cluster_arn: string; namespace: string | null; name: string; pod_selector: Record<string, string>; policy_types: string[]; ingress: any[]; egress: any[] }
export function policyFromK8s(clusterArn: string, o: any): NetworkPolicyRow {
  const meta = o.metadata || {}; const spec = o.spec || {};
  return { id: `${clusterArn}/${meta.namespace || "_"}/NetworkPolicy/${meta.name}`, cluster_arn: clusterArn, namespace: str(meta.namespace), name: String(meta.name || ""), pod_selector: spec.podSelector?.matchLabels || {}, policy_types: spec.policyTypes || (spec.egress ? ["Ingress", "Egress"] : ["Ingress"]), ingress: spec.ingress || [], egress: spec.egress || [] };
}

/** An ECS service as a workload: containers from its task definition, nodes from its running tasks' container instances. Pure. */
export function workloadFromEcs(service: any, taskDef: any | undefined, tasks: any[], instanceByCi: Map<string, string>): WorkloadRow {
  const defs = arr(taskDef?.container_definitions);
  const containers = defs.map((c: any) => ({ name: String(c.name || c.Name || ""), image: String(c.image || c.Image || ""), ports: arr(c.portMappings ?? c.PortMappings).map((p: any) => ({ port: Number(p.containerPort ?? p.ContainerPort), protocol: String(p.protocol ?? p.Protocol ?? "tcp").toLowerCase(), name: null })).filter((p: any) => Number.isFinite(p.port)) }));
  const mine = tasks.filter((t) => t.service_name === service.service_name || String(t.group || "") === `service:${service.service_name}`);
  const nodes: string[] = [...new Set<string>(mine.map((t) => (t.container_instance_arn ? instanceByCi.get(String(t.container_instance_arn)) ?? null : null)).filter((x): x is string => Boolean(x)))];
  const clusterName = String(service.cluster_arn || "").split("/").pop();
  return { id: `${service.cluster_arn}/${clusterName}/ecs_service/${service.service_name}`, cluster_arn: String(service.cluster_arn), namespace: clusterName ?? null, kind: "ecs_service", name: String(service.service_name), uid: str(service.arn),
    replicas_desired: num(service.desired_count), replicas_ready: num(service.running_count), containers, images: [...new Set(containers.map((c) => c.image).filter(Boolean))], labels: {}, selector: {}, service_account: null,
    created: str(service.created_at), revision: taskDef ? `${taskDef.family}:${taskDef.revision}` : str(service.task_definition), nodes, pods_running: mine.length || null, strategy: str(service.launch_type), schedule: null };
}

// ---- refresh ----------------------------------------------------------------------------------------------------------------

export interface ClusterRefreshResult { clusters: number; workloads: number; services: number; ingresses: number; policies: number; access: Record<string, string>; errors: string[]; took_ms: number }

const upsertCluster = db.prepare(`insert into inventory_cluster(arn, kind, name, region, account_id, version, platform_version, status, endpoint, endpoint_public, public_cidrs, endpoint_private, vpc_id, security_groups, subnets, authentication_mode, oidc_issuer, ca_data, nodes, workloads, namespaces, access_status, access_error, access_checked_at, first_seen, last_seen, gone)
  values (@arn, @kind, @name, @region, @account_id, @version, @platform_version, @status, @endpoint, @endpoint_public, @public_cidrs, @endpoint_private, @vpc_id, @security_groups, @subnets, @authentication_mode, @oidc_issuer, @ca_data, @nodes, @workloads, @namespaces, @access_status, @access_error, @access_checked_at, @now, @now, 0)
  on conflict(arn) do update set kind = excluded.kind, name = excluded.name, region = excluded.region, account_id = excluded.account_id, version = excluded.version, platform_version = excluded.platform_version, status = excluded.status, endpoint = excluded.endpoint, endpoint_public = excluded.endpoint_public, public_cidrs = excluded.public_cidrs, endpoint_private = excluded.endpoint_private,
    vpc_id = excluded.vpc_id, security_groups = excluded.security_groups, subnets = excluded.subnets, authentication_mode = excluded.authentication_mode, oidc_issuer = excluded.oidc_issuer, ca_data = coalesce(excluded.ca_data, ca_data), nodes = excluded.nodes, workloads = excluded.workloads, namespaces = excluded.namespaces,
    access_status = excluded.access_status, access_error = excluded.access_error, access_checked_at = excluded.access_checked_at, last_seen = excluded.last_seen, gone = 0`);
const upsertWorkload = db.prepare(`insert into cluster_workloads(id, cluster_arn, namespace, kind, name, uid, replicas_desired, replicas_ready, containers, images, labels, selector, service_account, created, revision, nodes, pods_running, strategy, schedule, first_seen, last_seen, gone)
  values (@id, @cluster_arn, @namespace, @kind, @name, @uid, @replicas_desired, @replicas_ready, @containers, @images, @labels, @selector, @service_account, @created, @revision, @nodes, @pods_running, @strategy, @schedule, @now, @now, 0)
  on conflict(id) do update set uid = excluded.uid, replicas_desired = excluded.replicas_desired, replicas_ready = excluded.replicas_ready, containers = excluded.containers, images = excluded.images, labels = excluded.labels, selector = excluded.selector, service_account = excluded.service_account, created = excluded.created, revision = excluded.revision, nodes = excluded.nodes, pods_running = excluded.pods_running, strategy = excluded.strategy, schedule = excluded.schedule, last_seen = excluded.last_seen, gone = 0`);
const upsertService = db.prepare(`insert into cluster_services(id, cluster_arn, namespace, name, type, cluster_ip, ports, selector, lb_hostnames, first_seen, last_seen, gone) values (@id, @cluster_arn, @namespace, @name, @type, @cluster_ip, @ports, @selector, @lb_hostnames, @now, @now, 0)
  on conflict(id) do update set type = excluded.type, cluster_ip = excluded.cluster_ip, ports = excluded.ports, selector = excluded.selector, lb_hostnames = excluded.lb_hostnames, last_seen = excluded.last_seen, gone = 0`);
const upsertIngress = db.prepare(`insert into cluster_ingresses(id, cluster_arn, namespace, name, class, hosts, rules, lb_hostnames, tls, first_seen, last_seen, gone) values (@id, @cluster_arn, @namespace, @name, @class, @hosts, @rules, @lb_hostnames, @tls, @now, @now, 0)
  on conflict(id) do update set class = excluded.class, hosts = excluded.hosts, rules = excluded.rules, lb_hostnames = excluded.lb_hostnames, tls = excluded.tls, last_seen = excluded.last_seen, gone = 0`);
const upsertPolicy = db.prepare(`insert into cluster_network_policies(id, cluster_arn, namespace, name, pod_selector, policy_types, ingress, egress, first_seen, last_seen, gone) values (@id, @cluster_arn, @namespace, @name, @pod_selector, @policy_types, @ingress, @egress, @now, @now, 0)
  on conflict(id) do update set pod_selector = excluded.pod_selector, policy_types = excluded.policy_types, ingress = excluded.ingress, egress = excluded.egress, last_seen = excluded.last_seen, gone = 0`);

function markGone(table: string, clusterArn: string, keep: string[], at: string): void {
  db.prepare(`update ${table} set gone = 1 where cluster_arn = ? and gone = 0${keep.length ? ` and id not in (${keep.map(() => "?").join(",")})` : ""}`).run(clusterArn, ...keep);
  void at;
}

/** Reads every cluster and what runs in it; `attempt` is the inventory's Steampipe runner (records a failure, returns undefined). */
export async function refreshClusters(attempt: (what: string, sql: string) => Promise<any[] | undefined>): Promise<ClusterRefreshResult> {
  const t0 = Date.now(); const at = now();
  const res: ClusterRefreshResult = { clusters: 0, workloads: 0, services: 0, ingresses: 0, policies: 0, access: {}, errors: [], took_ms: 0 };
  const [eks, nodeGroups, ecs, ecsServices, taskDefs, tasks, cis] = await Promise.all([attempt("EKS clusters", CLUSTER_SQL.eks), attempt("EKS node groups", CLUSTER_SQL.eks_nodes), attempt("ECS clusters", CLUSTER_SQL.ecs), attempt("ECS services", CLUSTER_SQL.ecs_services), attempt("ECS task definitions", CLUSTER_SQL.ecs_task_definitions), attempt("ECS tasks", CLUSTER_SQL.ecs_tasks), attempt("ECS container instances", CLUSTER_SQL.ecs_container_instances)]);
  const seenClusters: string[] = [];
  // EKS: the cluster from Steampipe, the workloads from the cluster API
  for (const c of eks ?? []) {
    const vpc = obj(c.resources_vpc_config); const ca = obj(c.certificate_authority);
    const cluster: K8sCluster = { name: String(c.name), endpoint: String(c.endpoint || ""), ca_data: str(ca.Data ?? ca.data), region: String(c.region) };
    const ng = (nodeGroups ?? []).filter((g: any) => g.cluster_name === c.name);
    const nodes = ng.reduce((s: number, g: any) => s + Number(obj(g.scaling_config).DesiredSize ?? obj(g.scaling_config).desiredSize ?? 0), 0);
    let access = "unknown"; let accessError: string | null = null; let workloads = 0; const namespaces = new Set<string>();
    if (cluster.endpoint) {
      try {
        const token = await eksToken(cluster);
        const [deploys, statefuls, daemons, jobs, cronjobs, services, ingresses, policies, pods] = await Promise.all([
          k8sListAll(cluster, "/apis/apps/v1/deployments", token), k8sListAll(cluster, "/apis/apps/v1/statefulsets", token), k8sListAll(cluster, "/apis/apps/v1/daemonsets", token),
          k8sListAll(cluster, "/apis/batch/v1/jobs", token), k8sListAll(cluster, "/apis/batch/v1/cronjobs", token), k8sListAll(cluster, "/api/v1/services", token),
          k8sListAll(cluster, "/apis/networking.k8s.io/v1/ingresses", token), k8sListAll(cluster, "/apis/networking.k8s.io/v1/networkpolicies", token), k8sListAll(cluster, "/api/v1/pods", token),
        ]);
        const kinds: [any[], string][] = [[deploys, "Deployment"], [statefuls, "StatefulSet"], [daemons, "DaemonSet"], [jobs, "Job"], [cronjobs, "CronJob"]];
        const rows: WorkloadRow[] = [];
        for (const [list, kind] of kinds) for (const o of list) { if (kind === "Job" && (o.metadata?.ownerReferences || []).some((r: any) => r.kind === "CronJob")) continue; rows.push(workloadFromK8s(String(c.arn), { ...o, kind }, pods)); }
        const svcRows = services.map((o) => serviceFromK8s(String(c.arn), o)); const ingRows = ingresses.map((o) => ingressFromK8s(String(c.arn), o)); const polRows = policies.map((o) => policyFromK8s(String(c.arn), o));
        db.transaction(() => {
          for (const w of rows) { upsertWorkload.run({ ...w, containers: json(w.containers), images: json(w.images), labels: json(w.labels), selector: json(w.selector), nodes: json(w.nodes), now: at }); if (w.namespace) namespaces.add(w.namespace); }
          for (const s of svcRows) upsertService.run({ ...s, ports: json(s.ports), selector: json(s.selector), lb_hostnames: json(s.lb_hostnames), now: at });
          for (const i of ingRows) upsertIngress.run({ ...i, hosts: json(i.hosts), rules: json(i.rules), lb_hostnames: json(i.lb_hostnames), tls: i.tls ? 1 : 0, now: at });
          for (const p of polRows) upsertPolicy.run({ ...p, pod_selector: json(p.pod_selector), policy_types: json(p.policy_types), ingress: json(p.ingress), egress: json(p.egress), now: at });
          markGone("cluster_workloads", String(c.arn), rows.map((r) => r.id), at); markGone("cluster_services", String(c.arn), svcRows.map((r) => r.id), at); markGone("cluster_ingresses", String(c.arn), ingRows.map((r) => r.id), at); markGone("cluster_network_policies", String(c.arn), polRows.map((r) => r.id), at);
        })();
        workloads = rows.length; res.workloads += rows.length; res.services += svcRows.length; res.ingresses += ingRows.length; res.policies += polRows.length;
        access = "ok";
      } catch (e: any) {
        access = e instanceof K8sError ? e.code : "error"; accessError = String(e?.message || e).slice(0, 300);
        res.errors.push(`${c.name}: ${accessError}`);
        workloads = Number((db.prepare("select count(*) as n from cluster_workloads where cluster_arn = ? and gone = 0").get(String(c.arn)) as any)?.n || 0);
      }
    } else { access = "unreachable"; accessError = "no endpoint"; }
    res.access[String(c.name)] = access;
    upsertCluster.run({ arn: String(c.arn), kind: "eks", name: String(c.name), region: str(c.region), account_id: str(c.account_id), version: str(c.version), platform_version: str(c.platform_version), status: str(c.status), endpoint: str(c.endpoint),
      endpoint_public: vpc.EndpointPublicAccess == null ? null : vpc.EndpointPublicAccess ? 1 : 0, public_cidrs: json(vpc.PublicAccessCidrs ?? []), endpoint_private: vpc.EndpointPrivateAccess == null ? null : vpc.EndpointPrivateAccess ? 1 : 0, vpc_id: str(vpc.VpcId),
      security_groups: json([...(vpc.SecurityGroupIds ?? []), ...(vpc.ClusterSecurityGroupId ? [vpc.ClusterSecurityGroupId] : [])]), subnets: json(vpc.SubnetIds ?? []), authentication_mode: str(obj(c.access_config).authenticationMode ?? obj(c.access_config).AuthenticationMode) || "CONFIG_MAP",
      oidc_issuer: str(obj(c.identity).oidc?.issuer ?? obj(c.identity).Oidc?.Issuer), ca_data: cluster.ca_data, nodes, workloads, namespaces: json([...namespaces].sort()), access_status: access, access_error: accessError, access_checked_at: at, now: at });
    seenClusters.push(String(c.arn)); res.clusters++;
  }
  // ECS: everything from Steampipe
  const tdByArn = new Map((taskDefs ?? []).map((t: any) => [String(t.task_definition_arn), t]));
  const ciToInstance = new Map((cis ?? []).map((ci: any) => [String(ci.arn), String(ci.ec2_instance_id || "")]));
  for (const c of ecs ?? []) {
    const services = (ecsServices ?? []).filter((s: any) => s.cluster_arn === c.cluster_arn);
    const rows = services.map((s: any) => workloadFromEcs(s, tdByArn.get(String(s.task_definition)), (tasks ?? []).filter((t: any) => t.cluster_arn === c.cluster_arn), ciToInstance));
    db.transaction(() => {
      for (const w of rows) upsertWorkload.run({ ...w, containers: json(w.containers), images: json(w.images), labels: json(w.labels), selector: json(w.selector), nodes: json(w.nodes), now: at });
      markGone("cluster_workloads", String(c.cluster_arn), rows.map((r) => r.id), at);
    })();
    upsertCluster.run({ arn: String(c.cluster_arn), kind: "ecs", name: String(c.cluster_name), region: str(c.region), account_id: str(c.account_id), version: null, platform_version: null, status: str(c.status), endpoint: null, endpoint_public: null, public_cidrs: "[]", endpoint_private: null, vpc_id: null, security_groups: "[]", subnets: "[]",
      authentication_mode: null, oidc_issuer: null, ca_data: null, nodes: num(c.registered_container_instances_count), workloads: rows.length, namespaces: "[]", access_status: "ok", access_error: null, access_checked_at: at, now: at });
    seenClusters.push(String(c.cluster_arn)); res.clusters++; res.workloads += rows.length;
  }
  if (eks && ecs) db.prepare(`update inventory_cluster set gone = 1 where gone = 0${seenClusters.length ? ` and arn not in (${seenClusters.map(() => "?").join(",")})` : ""}`).run(...seenClusters);
  res.took_ms = Date.now() - t0;
  return res;
}

// ---- reading -----------------------------------------------------------------------------------------------------------------

const parse = <T,>(s: unknown, fb: T): T => { if (typeof s !== "string") return fb; try { return JSON.parse(s) as T; } catch { return fb; } };
const rows = (sql: string, ...p: unknown[]): any[] => { try { return db.prepare(sql).all(...p) as any[]; } catch { return []; } };

export function listClusters(scope?: AccountScope | null): any[] {
  const a = accountWhere(scope);
  return rows(`select * from inventory_cluster where ${a.sql} order by gone, kind, name`, ...a.params).map((c) => ({ ...c, public_cidrs: parse<string[]>(c.public_cidrs, []), security_groups: parse<string[]>(c.security_groups, []), subnets: parse<string[]>(c.subnets, []), namespaces: parse<string[]>(c.namespaces, []), endpoint_public: c.endpoint_public == null ? null : Boolean(c.endpoint_public), endpoint_private: c.endpoint_private == null ? null : Boolean(c.endpoint_private), gone: Boolean(c.gone), ca_data: undefined, has_ca: Boolean(c.ca_data) }));
}
export const listWorkloads = (clusterArn?: string, includeGone = false): WorkloadRow[] =>
  rows(`select * from cluster_workloads where 1 = 1${clusterArn ? " and cluster_arn = ?" : ""}${includeGone ? "" : " and gone = 0"} order by namespace, kind, name`, ...(clusterArn ? [clusterArn] : [])).map((w) => ({ ...w, containers: parse(w.containers, []), images: parse(w.images, []), labels: parse(w.labels, {}), selector: parse(w.selector, {}), nodes: parse(w.nodes, []), gone: Boolean(w.gone) }));
export const listServices = (clusterArn?: string): ServiceRow[] => rows(`select * from cluster_services where gone = 0${clusterArn ? " and cluster_arn = ?" : ""}`, ...(clusterArn ? [clusterArn] : [])).map((s) => ({ ...s, ports: parse(s.ports, []), selector: parse(s.selector, {}), lb_hostnames: parse(s.lb_hostnames, []) }));
export const listIngresses = (clusterArn?: string): IngressRow[] => rows(`select * from cluster_ingresses where gone = 0${clusterArn ? " and cluster_arn = ?" : ""}`, ...(clusterArn ? [clusterArn] : [])).map((i) => ({ ...i, hosts: parse(i.hosts, []), rules: parse(i.rules, []), lb_hostnames: parse(i.lb_hostnames, []), tls: Boolean(i.tls) }));
export const listNetworkPolicies = (clusterArn?: string): NetworkPolicyRow[] => rows(`select * from cluster_network_policies where gone = 0${clusterArn ? " and cluster_arn = ?" : ""}`, ...(clusterArn ? [clusterArn] : [])).map((p) => ({ ...p, pod_selector: parse(p.pod_selector, {}), policy_types: parse(p.policy_types, []), ingress: parse(p.ingress, []), egress: parse(p.egress, []) }));

/** Whether a workload's labels satisfy a selector (matchLabels equality). Pure. */
export const selects = (selector: Record<string, string>, labels: Record<string, string>): boolean => Object.keys(selector).length > 0 && Object.entries(selector).every(([k, v]) => labels[k] === v);

export function clusterSummary(scope?: AccountScope | null) {
  const c = scopedStmt(scope, "select count(*) as total, sum(kind = 'eks') as eks, sum(kind = 'ecs') as ecs, sum(access_status = 'ok') as readable, sum(nodes) as nodes, sum(workloads) as workloads from inventory_cluster where gone = 0").get() as any;
  return { total: Number(c?.total || 0), eks: Number(c?.eks || 0), ecs: Number(c?.ecs || 0), readable: Number(c?.readable || 0), nodes: Number(c?.nodes || 0), workloads: Number(c?.workloads || 0) };
}

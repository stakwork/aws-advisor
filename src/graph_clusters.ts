import { db } from "./db.js";
import { PROVIDER, accountId, enabled, writeCypher } from "./graph_mirror.js";
import { listClusters, listIngresses, listNetworkPolicies, listServices, listWorkloads, selects } from "./cluster_inventory.js";

/**
 * Clusters and workloads in the graph (docs/cloud-ontology.md §1 AdvisorCluster / AdvisorDeployment, §8 step 4): one
 * AdvisorCluster per EKS or ECS cluster, one AdvisorDeployment per Kubernetes workload or ECS service with RUNS_IN to
 * its cluster, BUILT_FROM one AdvisorImage per container image, SCHEDULED_ON the compute nodes its pods run on, and
 * EXPOSES endpoints: a Service port (service_endpoint), an Ingress host and path (url). An Ingress or a Service of type
 * LoadBalancer names the balancer AWS created for it; that balancer's listener FORWARDS_TO the endpoint, so the
 * listener's reachability verdicts flow onto it. NetworkPolicies become AdvisorFilter {kind: network_policy} guarding
 * the workloads their podSelector matches. Node pools of the cluster are PART_OF it. Rebuilt with the resources.
 */

const str = (v: unknown): string | null => (v == null ? null : String(v));
const chunks = <T,>(items: T[], size = 200): T[][] => { const out: T[][] = []; for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size)); return out; };
const now = () => new Date().toISOString();
const rows = (sql: string, ...p: unknown[]): any[] => { try { return db.prepare(sql).all(...p) as any[]; } catch { return []; } };

const CLUSTER_CYPHER = `
UNWIND $rows AS row
MERGE (c:AdvisorResource {id: row.id})
ON CREATE SET c.first_seen = row.first_seen
SET c:AdvisorCluster
SET c += {name: row.name, kind: row.kind, version: row.version, platform_version: row.platform_version, state: row.state, native_state: row.native_state, region: row.region, endpoint_public: row.endpoint_public, public_cidrs: row.public_cidrs, endpoint_private: row.endpoint_private,
  authentication_mode: row.authentication_mode, access_status: row.access_status, access_error: row.access_error, nodes: row.nodes, workloads: row.workloads, namespaces: row.namespaces, vpc_id: row.vpc_id, security_groups: row.security_groups,
  provider: $provider, account_id: coalesce(row.account_id, $account), native_type: row.native_type, native_id: row.id, gone: row.gone, last_seen: row.last_seen, updated_at: $now}
WITH c, row
MERGE (a:AdvisorAccount {id: coalesce(row.account_id, $account)}) ON CREATE SET a.provider = $provider, a.native_type = 'account', a.kind = 'account', a.native_id = coalesce(row.account_id, $account), a.account_id = coalesce(row.account_id, $account) MERGE (c)-[:IN_ACCOUNT]->(a)
WITH c, row
FOREACH (_ IN CASE WHEN row.vpc_id IS NULL THEN [] ELSE [1] END | MERGE (n:AdvisorNetwork {id: row.vpc_id}) MERGE (c)-[:IN_NETWORK]->(n))
FOREACH (sg IN row.security_groups | MERGE (f:AdvisorFilter {id: sg}) MERGE (c)-[:GUARDED_BY]->(f))
FOREACH (p IN row.pool_ids | MERGE (np:AdvisorNodePool {id: p}) MERGE (np)-[:PART_OF]->(c))
FOREACH (_ IN CASE WHEN row.endpoint IS NULL THEN [] ELSE [1] END |
  MERGE (e:AdvisorEndpoint {id: row.id + ':api'}) ON CREATE SET e.first_seen = $now
  SET e += {kind: 'api', protocol: 'https', port: 443, hostname: row.endpoint_host, url: row.endpoint, tls: true, exposure: CASE WHEN row.endpoint_public AND row.world THEN 'internet' WHEN row.endpoint_public THEN 'network' ELSE 'network' END, reach_reason: row.endpoint_reason, resource_id: row.id, provider: $provider, account_id: coalesce(row.account_id, $account), native_type: 'eks_api_endpoint', native_id: row.id + ':api', gone: row.gone, last_seen: $now, updated_at: $now}
  MERGE (c)-[x:EXPOSES]->(e) SET x.gone = row.gone, x.updated_at = $now
  FOREACH (cidr IN row.public_cidrs |
    MERGE (s:AdvisorSource {id: CASE WHEN cidr IN ['0.0.0.0/0', '::/0'] THEN 'internet' ELSE 'cidr:' + cidr END}) ON CREATE SET s.kind = CASE WHEN cidr IN ['0.0.0.0/0', '::/0'] THEN 'internet' ELSE 'cidr' END, s.label = CASE WHEN cidr IN ['0.0.0.0/0', '::/0'] THEN 'internet' ELSE cidr END, s.cidr = CASE WHEN cidr IN ['0.0.0.0/0', '::/0'] THEN null ELSE cidr END, s.native_type = 'source', s.native_id = s.id
    MERGE (e)-[v:REACHABLE_FROM]->(s) SET v.protocol = 'https', v.port = 443, v.through = ['eks:public-access-cidrs'], v.note = 'the control plane endpoint; the cluster authenticates every request', v.requires_auth = true, v.computed_at = $now))`;

const WORKLOAD_CYPHER = `
UNWIND $rows AS row
MERGE (d:AdvisorResource {id: row.id})
ON CREATE SET d.first_seen = row.first_seen
SET d:AdvisorDeployment
SET d += {name: row.name, platform: row.platform, workload_kind: row.kind, namespace: row.namespace, environment: row.environment, containers: row.container_count, images: row.images, replicas_desired: row.replicas_desired, replicas_ready: row.replicas_ready,
  health: CASE WHEN row.replicas_desired IS NULL THEN 'unknown' WHEN row.replicas_ready >= row.replicas_desired THEN 'ok' WHEN row.replicas_ready > 0 THEN 'degraded' ELSE 'severe' END, state: CASE WHEN row.gone THEN 'terminated' ELSE 'running' END,
  revision: row.revision, strategy: row.strategy, schedule: row.schedule, service_account: row.service_account, labels: row.labels_kv, region: row.region, created_at: row.created, pods_running: row.pods_running,
  provider: $provider, account_id: coalesce(row.account_id, $account), native_type: row.native_type, native_id: row.uid, gone: row.gone, last_seen: row.last_seen, updated_at: $now}
WITH d, row
MERGE (a:AdvisorAccount {id: coalesce(row.account_id, $account)}) ON CREATE SET a.provider = $provider, a.native_type = 'account', a.kind = 'account', a.native_id = coalesce(row.account_id, $account), a.account_id = coalesce(row.account_id, $account) MERGE (d)-[:IN_ACCOUNT]->(a)
WITH d, row
MERGE (c:AdvisorResource {id: row.cluster_arn}) MERGE (d)-[:RUNS_IN]->(c)
WITH d, row
OPTIONAL MATCH (d)-[old:BUILT_FROM|SCHEDULED_ON|GUARDED_BY]->() DELETE old
WITH DISTINCT d, row
FOREACH (img IN row.images |
  MERGE (i:AdvisorResource {id: 'image:' + img}) ON CREATE SET i.first_seen = $now
  SET i:AdvisorImage, i += {name: img, kind: 'container', repository: split(img, ':')[0], tag: CASE WHEN img CONTAINS '@' THEN null WHEN size(split(img, ':')) > 1 THEN split(img, ':')[-1] ELSE 'latest' END, provider: $provider, account_id: coalesce(row.account_id, $account), native_type: 'container_image', native_id: img, gone: false, last_seen: $now, updated_at: $now}
  MERGE (d)-[:BUILT_FROM]->(i))
FOREACH (node IN row.nodes |
  MERGE (n:AdvisorResource {id: node})
  MERGE (d)-[s:SCHEDULED_ON]->(n) SET s.pods = row.pods_running, s.updated_at = $now)
FOREACH (pol IN row.policy_ids |
  MERGE (f:AdvisorFilter {id: pol}) MERGE (d)-[:GUARDED_BY]->(f))`;

const ENDPOINT_CYPHER = `
UNWIND $rows AS row
MERGE (d:AdvisorResource {id: row.workload_id})
MERGE (e:AdvisorEndpoint {id: row.id}) ON CREATE SET e.first_seen = $now
SET e += {kind: row.kind, protocol: row.protocol, port: row.port, hostname: row.hostname, path: row.path, url: row.url, tls: row.tls, service: row.service, service_type: row.service_type, exposure: row.exposure, reach_reason: row.reason, resource_id: row.workload_id, provider: $provider, account_id: coalesce(row.account_id, $account), native_type: row.native_type, native_id: row.id, gone: false, last_seen: $now, updated_at: $now}
MERGE (d)-[x:EXPOSES]->(e) SET x.gone = false, x.updated_at = $now
WITH e, row
OPTIONAL MATCH (e)-[old:FORWARDS_TO]->() DELETE old
WITH DISTINCT e, row
FOREACH (t IN row.forwards_to | MERGE (te:AdvisorEndpoint {id: t}) MERGE (e)-[f:FORWARDS_TO]->(te) SET f.updated_at = $now)
FOREACH (lbh IN row.lb_hostnames |
  MERGE (lb:AdvisorResource {id: lbh}) ON CREATE SET lb:AdvisorResourceRef, lb.guessed_type = 'load_balancer', lb.named_by = 'cluster', lb.first_named_at = $now, lb.account_id = coalesce(row.account_id, $account), lb.provider = $provider, lb.native_type = 'ref', lb.native_id = lbh
  FOREACH (_ IN CASE WHEN lb:AdvisorLoadBalancer THEN [1] ELSE [] END |
    MERGE (lb)-[:EXPOSES]->(l:AdvisorEndpoint {kind: 'listener'})
    MERGE (l)-[f:FORWARDS_TO]->(e) SET f.via = 'ingress_controller', f.updated_at = $now
    MERGE (e)-[fb:FRONTED_BY]->(lb) SET fb.updated_at = $now)
  FOREACH (_ IN CASE WHEN lb:AdvisorLoadBalancer THEN [] ELSE [1] END | MERGE (e)-[fb:FRONTED_BY]->(lb) SET fb.updated_at = $now))`;

/** A url or service endpoint behind a balancer inherits the internet verdict of the listeners that forward to it; the cluster authenticates nothing on the way, so requires_auth stays false. */
const INHERIT_VERDICT_CYPHER = `
MATCH (l:AdvisorEndpoint {kind: 'listener'})-[:FORWARDS_TO]->(e:AdvisorEndpoint)<-[:EXPOSES]-(:AdvisorDeployment {provider: $provider})
MATCH (l)-[v:REACHABLE_FROM]->(s)
MERGE (e)-[w:REACHABLE_FROM]->(s) SET w.protocol = e.protocol, w.port = e.port, w.through = coalesce(v.through, []) + [l.id], w.note = coalesce(v.note, '') + ' (through the balancer listener)', w.requires_auth = false, w.computed_at = $now
WITH e, collect(s.id) AS srcs
SET e.exposure = CASE WHEN 'internet' IN srcs THEN 'internet' ELSE e.exposure END, e.reach_computed_at = $now`;

const POLICY_CYPHER = `
UNWIND $rows AS row
MERGE (f:AdvisorFilter {id: row.id}) ON CREATE SET f.first_seen = $now
SET f += {kind: 'network_policy', stateful: true, default_action: 'deny', default: false, name: row.name, namespace: row.namespace, description: row.description, rules: row.rule_count, attached: row.attached, policy_types: row.policy_types, provider: $provider, account_id: coalesce(row.account_id, $account), native_type: 'kubernetes_network_policy', native_id: row.id, gone: false, last_seen: $now, updated_at: $now}
WITH f, row
MERGE (c:AdvisorResource {id: row.cluster_arn}) MERGE (f)-[:IN_CLUSTER]->(c)
WITH f, row
OPTIONAL MATCH (f)-[:HAS_RULE]->(old:AdvisorFilterRule) DETACH DELETE old
WITH DISTINCT f, row
FOREACH (r IN row.rules |
  MERGE (fr:AdvisorFilterRule {id: r.id}) SET fr += {direction: r.direction, action: 'allow', protocol: r.protocol, from_port: r.from_port, to_port: r.to_port, priority: null, source_kind: r.source_kind, source: r.source, description: r.description, dormant: false, filter_id: row.id, provider: $provider, account_id: coalesce(row.account_id, $account), native_type: 'network_policy_rule', native_id: r.id, updated_at: $now}
  MERGE (f)-[:HAS_RULE]->(fr)
  FOREACH (cidr IN CASE WHEN r.cidr IS NULL THEN [] ELSE [r.cidr] END |
    MERGE (s:AdvisorSource {id: CASE WHEN cidr IN ['0.0.0.0/0', '::/0'] THEN 'internet' ELSE 'cidr:' + cidr END}) ON CREATE SET s.kind = CASE WHEN cidr IN ['0.0.0.0/0', '::/0'] THEN 'internet' ELSE 'cidr' END, s.label = cidr, s.cidr = cidr, s.native_type = 'source', s.native_id = s.id
    MERGE (fr)-[:FROM]->(s)))`;

export interface ClusterGraphCounts { clusters: number; workloads: number; endpoints: number; policies: number; images: number; took_ms: number }

/** Everything the cluster inventory holds, into the graph; idempotent. */
export async function mirrorClusters(): Promise<ClusterGraphCounts | null> {
  if (!enabled()) return null;
  const t0 = Date.now(); const account = accountId(); const stamp = now();
  const w = (cypher: string, batch: any[]) => writeCypher(cypher, { rows: batch, account, provider: PROVIDER, now: stamp });
  for (const l of ["AdvisorCluster", "AdvisorDeployment", "AdvisorImage"]) await writeCypher(`CREATE CONSTRAINT ${l.toLowerCase()}_id IF NOT EXISTS FOR (n:${l}) REQUIRE n.id IS UNIQUE`);
  const clusters = listClusters();
  // node pools of an EKS cluster: the pools of the instances whose tags name the cluster (managed node groups and Karpenter alike); ECS container instances have no pool
  const poolIdsOf = (c: any) => c.kind === "eks" ? rows(`select distinct pool from inventory_ec2 where gone = 0 and pool is not null and (json_extract(snapshot, '$.tags."eks:cluster-name"') = ? or json_extract(snapshot, '$.tags."aws:eks:cluster-name"') = ? or json_extract(snapshot, '$.tags."alpha.eksctl.io/cluster-name"') = ? or json_extract(snapshot, '$.tags."kubernetes.io/cluster/' || ? || '"') is not null)`, c.name, c.name, c.name, c.name).map((r) => `${PROVIDER}:${account}:pool:${r.pool}`) : [];
  // Member accounts (src/accounts.ts): a cluster's row carries its account; everything inside the cluster follows it
  const clusterAccount = new Map(clusters.map((c) => [c.arn, (c as any).account_id ? String((c as any).account_id) : null]));
  const clusterRows = clusters.map((c) => {
    const endpointHost = c.endpoint ? String(c.endpoint).replace(/^https?:\/\//, "").replace(/\/.*$/, "") : null;
    const world = (c.public_cidrs as string[]).some((x) => x === "0.0.0.0/0" || x === "::/0");
    return { id: c.arn, account_id: clusterAccount.get(c.arn) ?? null, name: c.name, kind: c.kind === "eks" ? "kubernetes" : "ecs", native_type: c.kind === "eks" ? "eks_cluster" : "ecs_cluster", version: c.version, platform_version: c.platform_version, state: c.status === "ACTIVE" ? "available" : c.status === "CREATING" || c.status === "UPDATING" ? "pending" : c.status === "DELETING" ? "terminated" : c.status === "FAILED" ? "degraded" : "unknown", native_state: c.status,
      region: c.region, endpoint: c.endpoint, endpoint_host: endpointHost, endpoint_public: c.endpoint_public, public_cidrs: c.public_cidrs, world, endpoint_private: c.endpoint_private, authentication_mode: c.authentication_mode, access_status: c.access_status, access_error: c.access_error, nodes: c.nodes, workloads: c.workloads, namespaces: c.namespaces, vpc_id: c.vpc_id, security_groups: c.security_groups, pool_ids: poolIdsOf(c),
      endpoint_reason: c.endpoint_public ? (world ? "the Kubernetes API is reachable from any address; every request still needs a valid token" : `the Kubernetes API is reachable from ${(c.public_cidrs as string[]).join(", ")} only`) : "the Kubernetes API endpoint is private: reachable from inside the VPC only", gone: c.gone, first_seen: c.first_seen, last_seen: c.last_seen };
  });
  for (const b of chunks(clusterRows)) await w(CLUSTER_CYPHER, b);

  const policies = listNetworkPolicies();
  const workloads = listWorkloads(undefined, true);
  const platformOf = (clusterArn: string) => clusters.find((c) => c.arn === clusterArn)?.kind === "ecs" ? "ecs" : "eks";
  const workloadRows = workloads.map((wl) => ({
    id: wl.id, account_id: clusterAccount.get(wl.cluster_arn) ?? null, cluster_arn: wl.cluster_arn, name: wl.name, kind: wl.kind, namespace: wl.namespace, platform: platformOf(wl.cluster_arn), native_type: wl.kind === "ecs_service" ? "ecs_service" : `kubernetes_${wl.kind}`, uid: wl.uid ?? wl.id,
    environment: /prod/i.test(`${wl.namespace} ${wl.name}`) ? "production" : /stag/i.test(`${wl.namespace} ${wl.name}`) ? "staging" : /dev|test/i.test(`${wl.namespace} ${wl.name}`) ? "development" : null,
    container_count: wl.containers.length, images: wl.images, replicas_desired: wl.replicas_desired, replicas_ready: wl.replicas_ready, revision: wl.revision, strategy: wl.strategy, schedule: wl.schedule, service_account: wl.service_account,
    labels_kv: Object.entries(wl.labels).map(([k, v]) => `${k}=${v}`), region: clusters.find((c) => c.arn === wl.cluster_arn)?.region ?? null, created: wl.created, pods_running: wl.pods_running, nodes: wl.nodes,
    policy_ids: policies.filter((p) => p.cluster_arn === wl.cluster_arn && p.namespace === wl.namespace && selects(p.pod_selector, wl.labels)).map((p) => p.id),
    gone: (wl as any).gone ?? false, first_seen: (wl as any).first_seen ?? stamp, last_seen: (wl as any).last_seen ?? stamp,
  }));
  for (const b of chunks(workloadRows)) await w(WORKLOAD_CYPHER, b);

  // endpoints: Service ports on the workloads a Service selects; Ingress host+path forwarding to the Service endpoint
  const services = listServices(); const ingresses = listIngresses();
  const lbByDns = new Map(rows("select arn, dns_name from inventory_elb where gone = 0 and dns_name is not null").map((r) => [String(r.dns_name).toLowerCase(), String(r.arn)]));
  const resolveLb = (hosts: string[]) => hosts.map((h) => lbByDns.get(String(h).toLowerCase()) ?? h);
  const endpointRows: any[] = [];
  const serviceEndpointId = (svc: any, port: number) => `${svc.id}:${port}`;
  for (const svc of services) {
    const targets = workloads.filter((wl) => wl.cluster_arn === svc.cluster_arn && wl.namespace === svc.namespace && selects(svc.selector, wl.labels) && !(wl as any).gone);
    if (!targets.length) continue;
    for (const p of svc.ports) for (const wl of targets) {
      const external = svc.type === "LoadBalancer" || svc.type === "NodePort";
      endpointRows.push({ id: serviceEndpointId(svc, p.port), account_id: clusterAccount.get(svc.cluster_arn) ?? null, workload_id: wl.id, kind: "service_endpoint", protocol: p.protocol, port: p.port, hostname: `${svc.name}.${svc.namespace}.svc`, path: null, url: null, tls: null, service: svc.name, service_type: svc.type, native_type: "kubernetes_service_port",
        exposure: svc.type === "LoadBalancer" ? "network" : "network", reason: svc.type === "LoadBalancer" ? `Service ${svc.name} of type LoadBalancer: the balancer in front decides who reaches it` : svc.type === "NodePort" ? `Service ${svc.name} of type NodePort (${p.node_port}): reachable on every node's address, the nodes' security groups decide` : `Service ${svc.name}: reachable inside the cluster network only`,
        forwards_to: [], lb_hostnames: svc.type === "LoadBalancer" ? resolveLb(svc.lb_hostnames) : [], external });
    }
  }
  for (const ing of ingresses) {
    for (const r of ing.rules) {
      const svc = services.find((s) => s.cluster_arn === ing.cluster_arn && s.namespace === ing.namespace && s.name === r.service);
      const port = svc ? (typeof r.port === "number" ? r.port : svc.ports.find((p) => p.name === r.port)?.port ?? svc.ports[0]?.port) : null;
      const targets = svc ? workloads.filter((wl) => wl.cluster_arn === svc.cluster_arn && wl.namespace === svc.namespace && selects(svc.selector, wl.labels) && !(wl as any).gone) : [];
      const host = r.host || ing.hosts[0] || null;
      for (const wl of targets.length ? targets : [null]) {
        endpointRows.push({ id: `${ing.id}:${host || "*"}${r.path}`, account_id: clusterAccount.get(ing.cluster_arn) ?? null, workload_id: wl ? wl.id : ing.cluster_arn, kind: "url", protocol: ing.tls ? "https" : "http", port: ing.tls ? 443 : 80, hostname: host, path: r.path, url: host ? `${ing.tls ? "https" : "http"}://${host}${r.path === "/*" ? "/" : r.path}` : null, tls: ing.tls, service: r.service, service_type: "ingress", native_type: "kubernetes_ingress_path",
          exposure: ing.lb_hostnames.length ? "network" : "closed", reason: ing.lb_hostnames.length ? `Ingress ${ing.name} (${ing.class || "default class"}): the balancer ${ing.lb_hostnames[0]} decides who reaches it` : `Ingress ${ing.name} has no balancer yet`,
          forwards_to: svc && port != null ? [serviceEndpointId(svc, port)] : [], lb_hostnames: resolveLb(ing.lb_hostnames), external: true });
      }
    }
  }
  for (const b of chunks(endpointRows)) await w(ENDPOINT_CYPHER, b);
  await writeCypher(INHERIT_VERDICT_CYPHER, { provider: PROVIDER, now: stamp });

  const policyRows = policies.map((p) => {
    const rules: any[] = [];
    const push = (direction: "ingress" | "egress", list: any[]) => list.forEach((r, i) => {
      const ports = (r.ports || []).length ? r.ports : [{}];
      const peers = (direction === "ingress" ? r.from : r.to) || [];
      const peerList = peers.length ? peers : [{}];
      for (const [pi, port] of ports.entries()) for (const [qi, peer] of peerList.entries()) {
        const cidr = peer.ipBlock?.cidr ?? null;
        const sourceKind = cidr ? (cidr === "0.0.0.0/0" ? "internet" : "cidr") : peer.podSelector || peer.namespaceSelector ? "filter" : "any";
        const source = cidr ?? (peer.podSelector ? `pods ${JSON.stringify(peer.podSelector.matchLabels || {})}` : peer.namespaceSelector ? `namespaces ${JSON.stringify(peer.namespaceSelector.matchLabels || {})}` : "any");
        rules.push({ id: `${p.id}:${direction}:${i}:${pi}:${qi}`, direction, protocol: String(port.protocol || "tcp").toLowerCase(), from_port: port.port == null ? null : Number(port.port) || null, to_port: port.endPort == null ? (port.port == null ? null : Number(port.port) || null) : Number(port.endPort), source_kind: sourceKind, source, cidr, description: peer.ipBlock?.except?.length ? `except ${peer.ipBlock.except.join(", ")}` : null });
      }
    });
    if (p.policy_types.includes("Ingress")) push("ingress", p.ingress); if (p.policy_types.includes("Egress")) push("egress", p.egress);
    const attached = workloads.filter((wl) => wl.cluster_arn === p.cluster_arn && wl.namespace === p.namespace && selects(p.pod_selector, wl.labels)).length;
    return { id: p.id, account_id: clusterAccount.get(p.cluster_arn) ?? null, cluster_arn: p.cluster_arn, name: p.name, namespace: p.namespace, description: `pods ${JSON.stringify(p.pod_selector)} in ${p.namespace}`, rule_count: rules.length, attached, policy_types: p.policy_types, rules };
  });
  for (const b of chunks(policyRows)) await w(POLICY_CYPHER, b);
  return { clusters: clusterRows.length, workloads: workloadRows.length, endpoints: endpointRows.length, policies: policyRows.length, images: new Set(workloads.flatMap((wl) => wl.images)).size, took_ms: Date.now() - t0 };
}

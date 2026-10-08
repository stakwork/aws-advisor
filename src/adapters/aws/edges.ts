import { db } from "../../db.js";
import { COMPUTE_OF, OURS, REF_MERGE } from "../../graph_cypher.js";
import { inventoryIdsOf, tableExistsIn, writeCypher } from "../../graph_mirror.js";
import { AWS } from "../types.js";
import { elbEdges, lambdaArn, poolId } from "./resources.js";

/**
 * The AWS adapter's own edges, written after the mirror core has the resource nodes: a balancer's listeners and what
 * they forward to, a database's endpoint, a volume's attachment, the DNS records' targets, and the Beanstalk
 * environments as AdvisorDeployment nodes (extra nodes the core must not mark gone: their ids go back to it). The
 * core knows nothing of these tables; a second provider writes its own (src/adapters/vercel/graph.ts).
 */

const PROVIDER = AWS;
const BATCH = 250;
const chunks = <T,>(items: T[], size = BATCH): T[][] => { const out: T[][] = []; for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size)); return out; };
const rowsOf = (sql: string, ...params: unknown[]): any[] => { try { return db.prepare(sql).all(...params) as any[]; } catch { return []; } };
const num = (v: unknown): number | null => (v == null || v === "" || !Number.isFinite(Number(v)) ? null : Number(v));
const str = (v: unknown): string | null => (v == null ? null : String(v));
const safeJson = (s: unknown): any => { if (typeof s !== "string") return s ?? null; try { return JSON.parse(s); } catch { return null; } };
const write = (cypher: string, params: Record<string, unknown>) => writeCypher(cypher, params);
const tableExists = (name: string) => tableExistsIn(name);
const inventoryIds = (account: string) => inventoryIdsOf(account);

/**
 * A balancer's listeners, and what each forwards to: old edges go, the current ones come back. A target port or
 * function endpoint belongs to the account of the resource that exposes it (the balancer's when the graph does not
 * know the target yet), set on every pass so a rebuild corrects what an earlier pass attributed to the default account.
 */
const ELB_CYPHER = `
UNWIND $rows AS row
MATCH (lb:AdvisorResource {id: row.id})
OPTIONAL MATCH (lb)-[:EXPOSES]->(old:AdvisorEndpoint {kind: 'listener'})
OPTIONAL MATCH (old)-[f:FORWARDS_TO]->() DELETE f
WITH DISTINCT lb, row
FOREACH (l IN row.listeners |
  MERGE (e:AdvisorEndpoint {id: l.id}) ON CREATE SET e.first_seen = $now
  SET e += {kind: 'listener', protocol: l.protocol, port: l.port, tls: l.tls, certificates: l.certificates, hostname: lb.dns_name, exposure: CASE WHEN lb.scheme = 'public' THEN 'internet' ELSE 'network' END, resource_id: lb.id, account_id: coalesce(row.account_id, $account), provider: $provider, native_type: 'elb_listener', gone: false, last_seen: $now, updated_at: $now}
  MERGE (lb)-[x:EXPOSES]->(e) SET x.gone = false, x.updated_at = $now)
WITH lb, row
FOREACH (e IN row.ec2_edges |
  MERGE (i:AdvisorResource {id: e.target})
  MERGE (t:AdvisorEndpoint {id: e.target + ':tcp:' + toString(coalesce(e.port, 0))})
    ON CREATE SET t.kind = 'port', t.protocol = 'tcp', t.port = e.port, t.resource_id = e.target, t.provider = $provider, t.native_type = 'instance_port', t.first_seen = $now, t.gone = false
  SET t.last_seen = $now, t.updated_at = $now, t.account_id = coalesce(i.account_id, row.account_id, $account)
  MERGE (i)-[ix:EXPOSES]->(t) ON CREATE SET ix.gone = false
  FOREACH (lid IN CASE WHEN e.listener IS NULL THEN [] ELSE [e.listener] END |
    MERGE (l:AdvisorEndpoint {id: lid})
    MERGE (l)-[f:FORWARDS_TO]->(t) SET f += {target_group: e.target_group, health: e.health, updated_at: $now})
  FOREACH (_ IN CASE WHEN e.listener IS NULL THEN [1] ELSE [] END |
    MERGE (lb)-[f:FORWARDS_TO]->(t) SET f += {target_group: e.target_group, health: e.health, updated_at: $now}))
FOREACH (e IN row.ref_edges |
  MERGE (fn:AdvisorResource {id: e.target})
  MERGE (t:AdvisorEndpoint {id: e.target + ':invoke'})
    ON CREATE SET t.kind = 'url', t.protocol = 'https', t.resource_id = e.target, t.provider = $provider, t.native_type = 'lambda_invoke', t.first_seen = $now, t.gone = false
  SET t.last_seen = $now, t.updated_at = $now, t.account_id = coalesce(fn.account_id, row.account_id, $account)
  MERGE (fn)-[fx:EXPOSES]->(t) ON CREATE SET fx.gone = false
  FOREACH (lid IN CASE WHEN e.listener IS NULL THEN [] ELSE [e.listener] END |
    MERGE (l:AdvisorEndpoint {id: lid})
    MERGE (l)-[f:FORWARDS_TO]->(t) SET f += {target_group: e.target_group, health: e.health, updated_at: $now})
  FOREACH (_ IN CASE WHEN e.listener IS NULL THEN [1] ELSE [] END |
    MERGE (lb)-[f:FORWARDS_TO]->(t) SET f += {target_group: e.target_group, health: e.health, updated_at: $now}))`;

/** A database's connection endpoint as a service endpoint the database EXPOSES. */
const DB_ENDPOINT_CYPHER = `
UNWIND $rows AS row
MATCH (d:AdvisorResource {id: row.id})
MERGE (e:AdvisorEndpoint {id: row.endpoint_id})
ON CREATE SET e.first_seen = $now
SET e += {kind: 'service_endpoint', protocol: 'tcp', port: row.port, hostname: row.host, exposure: CASE WHEN row.publicly_accessible THEN 'internet' ELSE 'network' END, resource_id: row.id, account_id: coalesce(row.account_id, $account), provider: $provider, native_type: 'rds_endpoint', gone: false, last_seen: $now, updated_at: $now}
MERGE (d)-[x:EXPOSES]->(e) SET x.gone = false, x.updated_at = $now`;

/** A volume's attachment: the instance STORES_ON it. */
const VOLUME_CYPHER = `
UNWIND $rows AS row
MATCH (v:AdvisorResource {id: row.id})
OPTIONAL MATCH (old)-[s:STORES_ON]->(v) WHERE row.instance_id IS NULL OR old.id <> row.instance_id DELETE s
WITH DISTINCT v, row WHERE row.instance_id IS NOT NULL
MERGE (i:AdvisorResource {id: row.instance_id})
MERGE (i)-[s:STORES_ON]->(v) SET s.device = row.device, s.updated_at = $now`;

/** DNS: records in their zone, pointing at what the resolver linked them to (a node when the inventory has it, else a ref). */
const DNS_CYPHER = `
UNWIND $rows AS row
MATCH (r:AdvisorResource {id: row.id})
MERGE (z:AdvisorResource {id: row.zone_id})
MERGE (r)-[:IN_ZONE]->(z)
WITH r, row
OPTIONAL MATCH (r)-[old:POINTS_TO]->() DELETE old
WITH DISTINCT r, row
FOREACH (t IN [x IN row.targets WHERE x.resource_id IS NOT NULL] |
  MERGE (res:AdvisorResource {id: t.resource_id})
  MERGE (r)-[p:POINTS_TO]->(res) SET p.hop = t.hop, p.via = t.kind, p.updated_at = $now)
FOREACH (t IN [x IN row.targets WHERE x.resource_id IS NULL] |
  ${REF_MERGE("ref", "t.ref_id", "t.guessed_type", "dns_record")}
  MERGE (r)-[p:POINTS_TO]->(ref) SET p.hop = t.hop, p.via = t.kind, p.updated_at = $now)`;

/** Beanstalk environments as deployments: the group they scale and the balancer in front of them. */
const DEPLOYMENT_CYPHER = `
UNWIND $rows AS row
MERGE (d:AdvisorResource {id: row.id})
ON CREATE SET d.first_seen = $now
SET d:AdvisorDeployment
SET d += {name: row.name, platform: 'beanstalk', workload_kind: 'environment', state: 'available', region: row.region, environment: row.environment, gone: false, provider: $provider, account_id: coalesce(row.account_id, $account), native_type: 'beanstalk_environment', native_id: row.env_id, last_seen: $now, updated_at: $now}
WITH d, row
OPTIONAL MATCH (d)-[oldAcc:IN_ACCOUNT]->(oa:AdvisorAccount) WHERE oa.id <> coalesce(row.account_id, $account) DELETE oldAcc
WITH DISTINCT d, row
MERGE (a:AdvisorAccount {id: coalesce(row.account_id, $account)}) ON CREATE SET a.provider = $provider, a.native_type = 'account', a.kind = 'account', a.account_id = coalesce(row.account_id, $account) MERGE (d)-[:IN_ACCOUNT]->(a)
WITH d, row
FOREACH (_ IN CASE WHEN row.pool_id IS NULL THEN [] ELSE [1] END |
  MERGE (p:AdvisorNodePool {id: row.pool_id}) SET p.name = row.asg, p.kind = coalesce(p.kind, 'asg'), p.platform = 'beanstalk', p.account_id = coalesce(row.account_id, $account), p.provider = $provider, p.native_type = 'autoscaling_pool', p.native_id = row.asg, p.updated_at = $now
  MERGE (d)-[:RUNS_ON_POOL]->(p))
FOREACH (lb IN row.lbs |
  MERGE (b:AdvisorResource {id: lb})
  MERGE (d)-[:BACKED_BY]->(b))`;


/**
 * A Beanstalk environment RUNS_ON the operating system of every live box in the group it scales: the same edge a
 * cluster workload has to its nodes and a Vercel project to the team's runtime. Rebuilt from the IN_POOL edges the
 * resource pass just wrote, so a box that left the group leaves the environment too.
 */
const DEPLOYMENT_RUNS_ON_CYPHER = `
UNWIND $ids AS id
MATCH (d:AdvisorDeployment {id: id})
OPTIONAL MATCH (d)-[old:RUNS_ON]->() DELETE old
WITH DISTINCT d
MATCH (d)-[:RUNS_ON_POOL]->(:AdvisorNodePool)<-[:IN_POOL]-(b:AdvisorBox) WHERE coalesce(b.gone, false) = false
${COMPUTE_OF("b", "os")}
MERGE (d)-[x:RUNS_ON]->(os) SET x.via = 'beanstalk', x.updated_at = $now`;

/** The resolver's links (src/route53_inventory.ts) as POINTS_TO edges: ec2, balancers, functions and buckets to their nodes; addresses, interfaces, gateways and CloudFront to refs. */
export async function mirrorDnsLinks(records: any[], account: string, stamp: string): Promise<void> {
  if (!records.length || !tableExists("inventory_route53_link")) return;
  const lbByName = new Map(rowsOf("select arn, name from inventory_elb").map((r) => [String(r.name), String(r.arn)]));
  const fnByName = new Map(rowsOf("select name, arn, region from inventory_lambda").map((r) => [String(r.name), lambdaArn(r, account)]));
  const inv = inventoryIds(account);
  const links = rowsOf("select record_id, resource_kind, resource_id, hop from inventory_route53_link");
  const byRecord = new Map<string, any[]>();
  for (const l of links) {
    const kind = String(l.resource_kind);
    let resourceId: string | null = null; let refId = `${kind}:${l.resource_id}`; let guessed: string | null = kind;
    if (kind === "ec2" && inv.has(String(l.resource_id))) resourceId = String(l.resource_id);
    else if (kind === "lb") { const arn = lbByName.get(String(l.resource_id)); if (arn) resourceId = arn; else guessed = "load_balancer"; }
    else if (kind === "lambda") { const arn = fnByName.get(String(l.resource_id)); if (arn) resourceId = arn; else guessed = "function"; }
    else if (kind === "s3" && inv.has(String(l.resource_id))) resourceId = String(l.resource_id);
    else if (kind === "eip") { refId = String(l.resource_id); guessed = "public_ip"; }
    else if (kind === "eni") { refId = String(l.resource_id); guessed = "interface"; }
    else if (kind === "nat") { refId = String(l.resource_id); guessed = "nat_gateway"; }
    else if (kind === "cloudfront") { refId = String(l.resource_id); guessed = "cdn_distribution"; }
    else if (kind === "ec2") { refId = String(l.resource_id); guessed = "instance"; }
    const list = byRecord.get(String(l.record_id)) || []; list.push({ kind, hop: num(l.hop) ?? 1, resource_id: resourceId, ref_id: refId, guessed_type: guessed }); byRecord.set(String(l.record_id), list);
  }
  const rows = records.map((r) => ({ id: String(r.id), zone_id: String(r.zone_id), targets: byRecord.get(String(r.id)) || [] }));
  for (const batch of chunks(rows)) await write(DNS_CYPHER, { rows: batch, account, provider: PROVIDER, now: stamp });
}

/** Beanstalk environments the advisor knows (from the capacity patterns and the balancers' owner tag) as AdvisorDeployment nodes. */
export async function mirrorDeployments(elbRows: any[], account: string, stamp: string): Promise<string[]> {
  const envs = new Map<string, { id: string; env_id: string; name: string; region: string | null; asg: string | null; lbs: string[]; account_id: string | null }>();
  for (const p of rowsOf("select env_id, env_name, asg, region, account_id from capacity_patterns")) envs.set(String(p.env_name || p.env_id), { id: `${PROVIDER}:${p.account_id || account}:beanstalk:${p.env_name || p.env_id}`, env_id: String(p.env_id), name: String(p.env_name || p.env_id), region: str(p.region), asg: str(p.asg), account_id: str(p.account_id), lbs: [] });
  for (const lb of elbRows) {
    if (!lb.beanstalk_env || lb.gone) continue;
    const name = String(lb.beanstalk_env);
    const e = envs.get(name) || { id: `${PROVIDER}:${lb.account_id || account}:beanstalk:${name}`, env_id: str(lb.beanstalk_env_id) || name, name, region: str(lb.region), asg: null, lbs: [], account_id: str(lb.account_id) };
    e.lbs.push(String(lb.arn));
    if (!e.asg) { const asgs = safeJson(lb.asgs); if (Array.isArray(asgs) && asgs.length === 1) e.asg = String(asgs[0]); }
    envs.set(name, e);
  }
  const rows = [...envs.values()].map((e) => ({ ...e, pool_id: e.asg ? poolId(e.account_id ?? account, e.asg) : null, environment: /prod/i.test(e.name) ? "production" : /stag/i.test(e.name) ? "staging" : /dev|test/i.test(e.name) ? "development" : null }));
  for (const batch of chunks(rows)) await write(DEPLOYMENT_CYPHER, { rows: batch, account, provider: PROVIDER, now: stamp });
  for (const batch of chunks(rows.map((e) => e.id))) await write(DEPLOYMENT_RUNS_ON_CYPHER, { ids: batch, now: stamp });
  return rows.map((e) => e.id);
}

/**
 * Vercel OIDC federation (src/vercel_aws_links.ts): the project RUNS_AS the role whose trust names it, with the
 * environments the subject allows. Written from both adapters' passes (whichever runs second finds both nodes); a
 * link no longer in a trust policy is removed.
 */
const VERCEL_RUNS_AS_CYPHER = `
UNWIND $rows AS row
MATCH (d:AdvisorResource {id: row.project_id}) MATCH (r:AdvisorResource {id: row.role_arn})
MERGE (d)-[x:RUNS_AS]->(r) SET x.via = 'vercel_oidc', x.environments = row.environments, x.subjects = row.subjects, x.updated_at = $now`;

export async function mirrorVercelRoleLinks(stamp: string): Promise<void> {
  const { oidcLinks } = await import("../../vercel_aws_links.js");
  const rows = oidcLinks();
  for (const batch of chunks(rows)) await write(VERCEL_RUNS_AS_CYPHER, { rows: batch, now: stamp });
  await write(`MATCH (s)-[x:RUNS_AS]->() WHERE ${OURS("s")} AND x.via = 'vercel_oidc' AND (x.updated_at IS NULL OR x.updated_at <> $now) DELETE x`, { now: stamp });
}

/** Everything above, in order; returns the ids of the nodes written here beyond the resources (the deployments), so the core keeps them. */
export async function mirrorAwsEdges(account: string, stamp: string): Promise<string[]> {
  const elbRows = rowsOf("select * from inventory_elb");
  const ebsRows = rowsOf("select * from inventory_ebs");
  const rdsRows = rowsOf("select * from inventory_rds");
  const recordRows = rowsOf("select * from inventory_route53_record");
  // Member accounts (src/accounts.ts): a balancer's listeners and targets, a database's endpoint and an environment are stamped with the row's account
  for (const batch of chunks(elbRows.map((r) => ({ ...elbEdges(r), account_id: str(r.account_id) })))) await write(ELB_CYPHER, { rows: batch, account, provider: PROVIDER, now: stamp });
  const dbEndpoints = rdsRows.map((r) => { const net = (safeJson(r.snapshot) || {}).network || {}; return net.endpoint ? { id: String(r.db_instance_identifier), account_id: str(r.account_id), endpoint_id: `${r.db_instance_identifier}:tcp:${num(net.port) ?? 0}`, host: String(net.endpoint), port: num(net.port), publicly_accessible: Boolean(net.publicly_accessible) } : null; }).filter(Boolean);
  for (const batch of chunks(dbEndpoints)) await write(DB_ENDPOINT_CYPHER, { rows: batch, account, provider: PROVIDER, now: stamp });
  for (const batch of chunks(ebsRows.map((r) => ({ id: String(r.volume_id), instance_id: r.gone ? null : str(r.instance_id), device: str(r.device) })))) await write(VOLUME_CYPHER, { rows: batch, now: stamp });
  await mirrorDnsLinks(recordRows, account, stamp);
  await mirrorVercelRoleLinks(stamp);
  // credentials, clients and source addresses of every identity (src/graph_access.ts)
  await (await import("../../graph_access.js")).mirrorAccess(stamp);
  // the platform services' own edges (certificates, keys, topics, file systems, backups, workgroups, stacks, web ACLs)
  await (await import("../../graph_services.js")).mirrorServiceLinks(account, stamp);
  return mirrorDeployments(elbRows, account, stamp);
}

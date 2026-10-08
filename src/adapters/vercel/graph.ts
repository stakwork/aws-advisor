import { enabled, neoParams, writeCypher } from "../../graph_mirror.js";
import { listProjects, listStores } from "./inventory.js";
import { VERCEL, projectEndpoints, runtimeBoxId, storeEndpoints, vercelAdapter } from "./index.js";

/**
 * The Vercel adapter's graph layer, on top of the AdvisorDeployment nodes the mirror core writes from
 * `vercelAdapter.resources()`: one AdvisorEndpoint per URL the project serves (production URL, domains, latest
 * deployment URL), EXPOSED by the project and REACHABLE_FROM the internet, the verdict carrying `requires_auth` and
 * the protection that enforces it; the Node runtime as an AdvisorPackage INSTALLED_ON the project; every project
 * RUNS_ON the team's opaque runtime (an AdvisorBox and its AdvisorCompute: Vercel never shows the machines). The same shapes
 * as the AWS layers, so "which deployments can the internet open without logging in" is one query across providers.
 */

const ENDPOINT_CYPHER = `
UNWIND $rows AS row
MATCH (d:AdvisorResource {id: row.project_id})
MERGE (e:AdvisorEndpoint {id: row.id}) ON CREATE SET e.first_seen = $now
SET e += {kind: 'url', resource_id: row.project_id, protocol: 'https', port: 443, hostname: row.hostname, url: row.url, target: row.target, scope: 'all', exposure: 'internet', tls: true, requires_auth: row.requires_auth, protection: row.via, custom_domain: row.domain, gone: false, last_seen: $now, provider: $provider, account_id: $account, native_type: 'vercel_url', native_id: row.hostname, updated_at: $now}
MERGE (d)-[x:EXPOSES]->(e) SET x.gone = false, x.updated_at = $now
WITH e, row
MERGE (s:AdvisorSource {id: 'internet'}) ON CREATE SET s.kind = 'internet', s.label = 'the internet', s.cidr = '0.0.0.0/0', s.private = false, s.native_type = 'source'
MERGE (e)-[v:REACHABLE_FROM]->(s) SET v.protocol = 'https', v.port = 443, v.via_rule = null, v.through = ['vercel-edge'], v.note = CASE WHEN row.requires_auth THEN 'served by the Vercel edge; ' + row.via + ' protection asks for authentication first' ELSE 'served by the Vercel edge to anyone' END, v.requires_auth = row.requires_auth, v.computed_at = $now`;

/** A store's network endpoint as the partner reports it (Neon compute host, Redis Cloud public endpoint): the same AdvisorEndpoint + REACHABLE_FROM shape a port on a box gets, with requires_auth and, when the partner limits source addresses, restricted_to. */
const STORE_ENDPOINT_CYPHER = `
UNWIND $rows AS row
MATCH (d:AdvisorResource {id: row.resource_id})
MERGE (e:AdvisorEndpoint {id: row.id}) ON CREATE SET e.first_seen = $now
SET e += {kind: 'service_endpoint', resource_id: row.resource_id, protocol: row.protocol, port: row.port, hostname: row.hostname, scope: 'all', exposure: CASE WHEN size(row.restricted_to) > 0 THEN 'network' ELSE 'internet' END, tls: true, requires_auth: row.requires_auth, via: row.via, restricted_to: row.restricted_to, provider: $provider, account_id: $account, native_type: 'endpoint', last_seen: $now, gone: false, updated_at: $now}
MERGE (d)-[x:EXPOSES]->(e) SET x.gone = false, x.updated_at = $now
WITH e, row
MERGE (s:AdvisorSource {id: 'internet'}) ON CREATE SET s.kind = 'internet', s.label = 'the internet', s.cidr = '0.0.0.0/0', s.private = false, s.native_type = 'source'
MERGE (e)-[v:REACHABLE_FROM]->(s) SET v.protocol = row.protocol, v.port = row.port, v.via_rule = null, v.through = [], v.requires_auth = row.requires_auth, v.note = row.note, v.updated_at = $now`;

const STALE_ENDPOINTS = `
MATCH (d:AdvisorResource {provider: $provider, account_id: $account})-[:EXPOSES]->(e:AdvisorEndpoint)
WHERE (e.kind = 'url' OR e.kind = 'service_endpoint') AND NOT e.id IN $ids
SET e.gone = true, e.updated_at = $now`;

const RUNTIME_CYPHER = `
UNWIND $rows AS row
MATCH (d:AdvisorResource {id: row.project_id})
MERGE (p:AdvisorPackage {id: row.id}) ON CREATE SET p.first_seen = $now
SET p += {name: row.name, version: row.version, ecosystem: 'runtime', source_name: row.name, source_kind: 'deployment_metadata', advisory_ecosystem: null, scope: 'service', native_type: 'package', provider: $provider, account_id: $account, updated_at: $now}
MERGE (p)-[r:INSTALLED_ON]->(d) SET r += {first_seen: coalesce(r.first_seen, $now), last_seen: $now, gone: false, updated_at: $now}`;

const USES_CYPHER = `
UNWIND $rows AS row
MATCH (d:AdvisorResource {id: row.project_id}) MATCH (s:AdvisorResource {id: row.store_id})
MERGE (d)-[u:USES]->(s) SET u.environments = row.environments, u.gone = false, u.updated_at = $now`;

/**
 * Secure Compute: the project's functions run inside the AWS VPC the account owns. The AWS adapter already mirrored
 * the security group (AdvisorFilter) and the subnets (AdvisorSegment); the edges only MATCH them, so a project attached
 * to a network the advisor does not know stays unlinked and the row says so. GUARDED_BY and IN_SEGMENT are the same
 * edges an EC2 instance has, so "what can reach the database from the Vercel functions" is the same walk.
 */
const CONNECT_CYPHER = `
UNWIND $rows AS row
MATCH (d:AdvisorResource {id: row.project_id})
OPTIONAL MATCH (f:AdvisorFilter {id: row.security_group})
FOREACH (_ IN CASE WHEN f IS NULL THEN [] ELSE [1] END | MERGE (d)-[g:GUARDED_BY]->(f) SET g.via = 'vercel_secure_compute', g.environments = row.environments, g.dc = row.dc, g.updated_at = $now)
WITH d, row
UNWIND row.subnets AS subnet
OPTIONAL MATCH (s:AdvisorSegment {id: subnet})
FOREACH (_ IN CASE WHEN s IS NULL THEN [] ELSE [1] END | MERGE (d)-[i:IN_SEGMENT]->(s) SET i.via = 'vercel_secure_compute', i.environments = row.environments, i.updated_at = $now)`;

/** Every live project RUNS_ON the team's runtime (the opaque box and compute the resource pass wrote, ./index.ts runtimeBox). */
const RUNS_ON_CYPHER = `
MATCH (d:AdvisorDeployment {provider: $provider, account_id: $account})
OPTIONAL MATCH (d)-[old:RUNS_ON]->() DELETE old
WITH DISTINCT d WHERE coalesce(d.gone, false) = false
MATCH (:AdvisorBox {id: $box})-[:HOSTS]->(c:AdvisorCompute)
MERGE (d)-[x:RUNS_ON]->(c) SET x.via = 'vercel_functions', x.updated_at = $now`;

export interface VercelGraphCounts { projects: number; endpoints: number; runtimes: number; uses: number; connects: number }

export async function mirrorVercel(): Promise<VercelGraphCounts> {
  if (!enabled() || !vercelAdapter.configured()) return { projects: 0, endpoints: 0, runtimes: 0, uses: 0, connects: 0 };
  const now = new Date().toISOString(); const account = vercelAdapter.primaryAccountId();
  const projects = listProjects();
  const endpoints = projects.flatMap(projectEndpoints);
  for (let i = 0; i < endpoints.length; i += 250) await writeCypher(ENDPOINT_CYPHER, neoParams({ rows: endpoints.slice(i, i + 250), now, provider: VERCEL, account }));
  await writeCypher(RUNS_ON_CYPHER, { provider: VERCEL, account, box: runtimeBoxId(account), now });
  const storeEps = listStores().flatMap(storeEndpoints);
  for (let i = 0; i < storeEps.length; i += 250) await writeCypher(STORE_ENDPOINT_CYPHER, neoParams({ rows: storeEps.slice(i, i + 250), now, provider: VERCEL, account }));
  await writeCypher(STALE_ENDPOINTS, { ids: [...endpoints.map((e) => e.id), ...storeEps.map((e) => e.id)], now, provider: VERCEL, account });
  const runtimes = projects.filter((p) => p.node_version).map((p) => ({ project_id: p.id, id: `pkg:runtime:node:${p.node_version}`, name: "node", version: p.node_version }));
  for (let i = 0; i < runtimes.length; i += 250) await writeCypher(RUNTIME_CYPHER, { rows: runtimes.slice(i, i + 250), now, provider: VERCEL, account });
  // the stores a project is connected to (its data dependencies): deployment USES database / cache / storage
  const uses = listStores().flatMap((st) => st.projects.map((p) => ({ project_id: p.project_id, store_id: st.id, environments: p.environments })));
  await writeCypher("MATCH (d:AdvisorResource {provider: $provider, account_id: $account})-[u:USES]->() DELETE u", { provider: VERCEL, account });
  for (let i = 0; i < uses.length; i += 250) await writeCypher(USES_CYPHER, { rows: uses.slice(i, i + 250), now });
  // Secure Compute attachments, one row per (project, connect configuration) with the environments folded
  const connects: { project_id: string; security_group: string | null; subnets: string[]; environments: string[]; dc: string | null }[] = [];
  for (const p of projects) { const by = new Map<string, (typeof connects)[number]>(); for (const c of p.connect) { const k = `${c.id}|${c.security_group}`; const cur = by.get(k) ?? { project_id: p.id, security_group: c.security_group, subnets: c.subnets, environments: [], dc: c.dc }; if (!cur.environments.includes(c.env)) cur.environments.push(c.env); by.set(k, cur); } connects.push(...by.values()); }
  await writeCypher("MATCH (d:AdvisorResource {provider: $provider, account_id: $account})-[r:GUARDED_BY|IN_SEGMENT]->() WHERE r.via = 'vercel_secure_compute' DELETE r", { provider: VERCEL, account });
  for (let i = 0; i < connects.length; i += 100) await writeCypher(CONNECT_CYPHER, { rows: connects.slice(i, i + 100), now });
  // the AWS roles the projects assume through OIDC, and the people behind the team members (both need the AWS nodes, so the AWS pass writes them too)
  try { const edges = await import("../aws/edges.js"); await edges.mirrorVercelRoleLinks(now); await (await import("../../graph_access.js")).mirrorAccess(now); } catch (e: any) { console.error(`[graph] vercel ↔ aws links: ${e?.message || e}`); }
  return { projects: projects.length, endpoints: endpoints.length + storeEps.length, runtimes: runtimes.length, uses: uses.length, connects: connects.length };
}

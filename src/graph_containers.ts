import { db } from "./db.js";
import { accountId, enabled, ensureSchema, inBackground, neoParams, writeCypher } from "./graph_mirror.js";
import { imageRef } from "./graph_software.js";
import { rowToContainer } from "./container_inventory.js";
import { AWS } from "./adapters/types.js";

/**
 * The containers of the graph (docs/cloud-ontology.md §2) for the AWS adapter, from src/container_inventory.ts:
 * (:AdvisorResource)-[:RUNS]->(:AdvisorContainer {id: container:<instance>:<name>}) for each container a box runs or
 * ran (gone ones kept so history stays walkable), -[:BUILT_FROM]->(:AdvisorImage) the image it runs now (the same
 * image nodes the software probe and the cluster workloads use, which also take the source repository and revision
 * the image's labels name), -[:SERVES]->(:AdvisorEndpoint) the ports it publishes, and -[:SHIPS_LOGS_TO]->(:KnLogGroup)
 * when its log driver writes to CloudWatch. A container is not an AdvisorResource: it costs nothing on its own.
 */

const CONTAINER_CYPHER = `
UNWIND $rows AS row
MATCH (r:AdvisorResource {id: row.instance_id})
MERGE (c:AdvisorContainer {id: row.id}) ON CREATE SET c.first_seen = row.first_seen
SET c += {name: row.name, container_id: row.container_id, image: row.image, image_id: row.image_id, state: row.state, health: row.health, exit_code: row.exit_code, oom_killed: row.oom_killed,
  created_at: row.created, started_at: row.started_at, finished_at: row.finished_at, restarts: row.restarts, restart_policy: row.restart_policy, privileged: row.privileged, network_mode: row.network_mode,
  user: row.user, entrypoint: row.entrypoint, networks: row.networks, ports: row.ports, mounts: row.mounts, source_url: row.source_url, revision: row.revision, image_version: row.image_version,
  compose_project: row.compose_project, compose_service: row.compose_service, compose_dir: row.compose_dir, cpu_pct: row.cpu_pct, mem_bytes: row.mem_bytes,
  last_seen: row.last_seen, probes: row.probes, gone: row.gone, resource_id: row.instance_id, provider: $provider, account_id: coalesce(r.account_id, $account), native_type: 'docker_container', native_id: coalesce(row.container_id, row.name), updated_at: $now}
MERGE (r)-[e:RUNS]->(c) SET e += {first_seen: row.first_seen, last_seen: row.last_seen, gone: row.gone, updated_at: $now}
WITH c, r, row
OPTIONAL MATCH (c)-[old:BUILT_FROM]->(o) WHERE o.id <> row.image_node DELETE old
WITH DISTINCT c, r, row WHERE row.image_node IS NOT NULL
MERGE (i:AdvisorResource {id: row.image_node}) ON CREATE SET i.first_seen = $now, i += {name: row.image, kind: 'container', repository: row.repository, tag: row.tag, native_type: 'container_image', native_id: row.image, provider: $provider, account_id: coalesce(r.account_id, $account)}
SET i:AdvisorImage, i.source_url = coalesce(row.source_url, i.source_url), i.revision = coalesce(row.revision, i.revision), i.version = coalesce(row.image_version, i.version), i.title = coalesce(row.image_title, i.title), i.built_at = coalesce(row.image_built, i.built_at), i.updated_at = $now
MERGE (c)-[b:BUILT_FROM]->(i) SET b += {image_id: row.image_id, revision: row.revision, updated_at: $now}`;

// the ports it publishes (probe 1.8 names the container on the port) and the log groups its log driver writes (probe 1.6)
const WIRING_CYPHER = `
UNWIND $rows AS row
MATCH (r:AdvisorResource {id: row.instance_id}) MATCH (c:AdvisorContainer {id: row.id})
OPTIONAL MATCH (r)-[:EXPOSES]->(p:AdvisorEndpoint {container: row.name})
FOREACH (_ IN CASE WHEN p IS NULL THEN [] ELSE [1] END | MERGE (c)-[s:SERVES]->(p) SET s.gone = coalesce(p.gone, false), s.updated_at = $now)
WITH DISTINCT r, c, row
OPTIONAL MATCH (r)-[l:SHIPS_LOGS_TO]->(g:KnLogGroup) WHERE l.via = 'docker:' + row.name
FOREACH (_ IN CASE WHEN g IS NULL THEN [] ELSE [1] END | MERGE (c)-[s:SHIPS_LOGS_TO]->(g) SET s.via = 'log driver', s.source = l.source, s.observed_at = l.observed_at, s.attributed_by = 'observed')`;

const chunks = <T,>(items: T[], size = 250): T[][] => { const out: T[][] = []; for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size)); return out; };

/** The graph row of one stored container. Lists are flattened to strings Neo4j can hold: ports as 8080->80/tcp, mounts as type source:destination (ro). */
export function containerGraphRow(r: any) {
  const c = rowToContainer(r);
  const ref = c.image ? imageRef(c.image) : null;
  return {
    instance_id: c.instance_id, id: `container:${c.instance_id}:${c.name}`, name: c.name, container_id: c.container_id, image: c.image, image_id: c.image_id, state: c.state, health: c.health, exit_code: c.exit_code, oom_killed: c.oom_killed,
    created: c.created, started_at: c.started_at, finished_at: c.finished_at, restarts: c.restarts, restart_policy: c.restart_policy, privileged: c.privileged, network_mode: c.network_mode, user: c.user, entrypoint: c.entrypoint,
    networks: c.networks, ports: c.ports.map((p) => `${p.host_port != null ? `${p.host_ip && p.host_ip !== "0.0.0.0" && p.host_ip !== "::" ? `${p.host_ip}:` : ""}${p.host_port}->` : ""}${p.container_port}/${p.proto}`),
    mounts: c.mounts.map((m) => `${m.type} ${m.name ?? m.source ?? ""}:${m.destination}${m.rw ? "" : " (ro)"}`),
    source_url: c.source_url, revision: c.revision, image_version: c.image_version, image_title: c.image_title, image_built: c.image_built,
    compose_project: c.compose_project, compose_service: c.compose_service, compose_dir: c.compose_dir, cpu_pct: c.cpu_pct, mem_bytes: c.mem_bytes,
    first_seen: c.first_seen, last_seen: c.last_seen, probes: c.probes, gone: c.gone,
    image_node: ref?.id ?? null, repository: ref?.repository ?? null, tag: ref?.tag ?? null,
  };
}

/** Every stored container of the given instances (or all) as AdvisorContainer nodes with their image, ports and log groups. */
export async function mirrorContainers(instanceIds?: string[]): Promise<{ containers: number } | null> {
  if (!enabled()) return null;
  if (instanceIds && !instanceIds.length) return null;
  await ensureSchema();
  let raw: any[] = [];
  try { raw = instanceIds ? db.prepare(`select * from instance_containers where instance_id in (${instanceIds.map(() => "?").join(",")})`).all(...instanceIds) : db.prepare("select * from instance_containers").all(); }
  catch { return { containers: 0 }; /* the table is created by src/container_inventory.ts on first load */ }
  const rows = raw.map(containerGraphRow);
  const now = new Date().toISOString();
  for (const b of chunks(rows)) {
    await writeCypher(CONTAINER_CYPHER, neoParams({ rows: b, now, provider: AWS, account: accountId() }));
    await writeCypher(WIRING_CYPHER, neoParams({ rows: b, now }));
  }
  return { containers: rows.length };
}

export const mirrorContainersInBackground = (instanceIds?: string[]) => inBackground(`container mirror${instanceIds ? ` (${instanceIds.join(", ")})` : ""}`, () => mirrorContainers(instanceIds));

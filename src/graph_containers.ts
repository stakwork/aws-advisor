import { db } from "./db.js";
import { accountId, enabled, ensureSchema, inBackground, neoParams, readQuery, writeCypher } from "./graph_mirror.js";
import { imageNodeResolver, imageRef, type ContainerImageRef } from "./graph_software.js";
import { rowToContainer } from "./container_inventory.js";
import { repoIdResolver } from "./function_facts.js";
import { resolveRepoCasing } from "./graph_functions.js";
import { linkCodeRepositoriesQuietly } from "./graph_repositories.js";
import { AWS } from "./adapters/types.js";
import { COMPUTE_OF } from "./graph_cypher.js";

/**
 * The containers of the graph (docs/cloud-ontology.md §2) for the AWS adapter, from src/container_inventory.ts:
 * (:AdvisorCompute)-[:RUNS]->(:AdvisorContainer {id: container:<instance>:<name>}) for each container a box's OS runs or
 * ran (gone ones kept so history stays walkable), -[:BUILT_FROM]->(:AdvisorImage) the image it runs now (the same
 * image nodes the software probe and the cluster workloads use, which also take the source repository and revision
 * the image's labels name), -[:SERVES]->(:AdvisorEndpoint) the ports it publishes, and -[:SHIPS_LOGS_TO]->(:KnLogGroup)
 * when its log driver writes to CloudWatch. A container is not an AdvisorResource: it costs nothing on its own.
 * The image node is the one the software layer uses (src/graph_software.ts imageNodeId through imageNodeResolver, 2026-11-03):
 * keyed by the digest the box's instance_images row recorded, so a container, the box's RUNS_IMAGE, the scanner's CONTAINS
 * and the container's own running executables (EXECUTES from the container, CONTAINS from the image) meet on one node;
 * the bare reference only while the software probe has not listed the image on that box. A tag-keyed node nothing points
 * at any more is removed after each sync.
 *
 * Then the image's own source: (:AdvisorImage)-[:BUILT_FROM {via: 'image_label', source_url, revision, asserted_by: 'label',
 * verified: false}]->(:AdvisorRepository) when its `org.opencontainers.image.source` (or `org.label-schema.vcs-url`) label
 * names a GitHub repository the advisor can resolve (src/function_facts.ts repoIdFromTagValue: the same rule and casing
 * as a function's repository tag, so an image and the function built from the same code meet on one node). The
 * repository node is the GitHub org adapter's when it has read it; else a stub `named_by: 'image_label'` that goes once
 * no image names it. A label is the builder's word, not a verified provenance: `verified: false`, as the tag edge.
 */

const CONTAINER_CYPHER = `
UNWIND $rows AS row
MATCH (r:AdvisorResource {id: row.instance_id})
${COMPUTE_OF("r", "os")}
MERGE (c:AdvisorContainer {id: row.id}) ON CREATE SET c.first_seen = row.first_seen
SET c += {name: row.name, container_id: row.container_id, image: row.image, image_id: row.image_id, state: row.state, health: row.health, exit_code: row.exit_code, oom_killed: row.oom_killed,
  created_at: row.created, started_at: row.started_at, finished_at: row.finished_at, restarts: row.restarts, restart_policy: row.restart_policy, privileged: row.privileged, network_mode: row.network_mode,
  user: row.user, entrypoint: row.entrypoint, networks: row.networks, ports: row.ports, mounts: row.mounts, source_url: row.source_url, revision: row.revision, image_version: row.image_version,
  compose_project: row.compose_project, compose_service: row.compose_service, compose_dir: row.compose_dir, cpu_pct: row.cpu_pct, mem_bytes: row.mem_bytes,
  last_seen: row.last_seen, probes: row.probes, gone: row.gone, resource_id: row.instance_id, provider: $provider, account_id: coalesce(r.account_id, $account), native_type: 'docker_container', native_id: coalesce(row.container_id, row.name), updated_at: $now}
MERGE (os)-[e:RUNS]->(c) SET e += {first_seen: row.first_seen, last_seen: row.last_seen, gone: row.gone, updated_at: $now}
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

// ---- the image's source repository, from its label (new nodes only: an existing node's source is never overwritten) --------------
const REPO_NODE_CYPHER = `
UNWIND $rows AS row
MERGE (r:AdvisorRepository {id: row.id})
ON CREATE SET r.first_seen = $now, r.source = 'derived', r.named_by = 'image_label', r.provider = 'github', r.native_type = 'repository', r.native_id = row.native_id, r.name = row.name
SET r.updated_at = $now`;

const IMAGE_REPO_CYPHER = `
UNWIND $rows AS row
MATCH (i:AdvisorImage {id: row.image_node}) MATCH (r:AdvisorRepository {id: row.repo_id})
OPTIONAL MATCH (i)-[old:BUILT_FROM]->(o:AdvisorRepository) WHERE o.id <> r.id DELETE old
WITH DISTINCT i, r, row
MERGE (i)-[x:BUILT_FROM]->(r)
SET x += {via: 'image_label', source_url: row.source_url, revision: row.revision, asserted_by: 'label', verified: false, updated_at: $now}`;

const chunks = <T,>(items: T[], size = 250): T[][] => { const out: T[][] = []; for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size)); return out; };

/** The repository nodes to create and the image -> repository edges to draw for the given container rows: one edge per image whose
 *  source label resolves to a GitHub repository id (`resolve`: src/function_facts.ts repoIdResolver), on an existing AdvisorRepository
 *  node's casing when one matches case-insensitively (`existing`), else on the label's own casing, created as a stub. A container
 *  with no image node or no source label contributes nothing; the first row of an image wins (the caller passes the latest seen first),
 *  a later one only filling in a missing revision. Pure. */
export function imageRepositoryRows(rows: { image_node: string | null; source_url: string | null; revision: string | null }[], resolve: (raw: string | null) => string | null, existing: string[]): { nodes: { id: string; native_id: string; name: string }[]; edges: { image_node: string; repo_id: string; source_url: string; revision: string | null }[] } {
  const byImage = new Map<string, { source_url: string; repo_id: string; revision: string | null }>();
  for (const r of rows) {
    if (!r.image_node || !r.source_url) continue;
    const id = resolve(r.source_url);
    if (!id) continue;
    const prev = byImage.get(r.image_node);
    if (!prev || (!prev.revision && r.revision)) byImage.set(r.image_node, { source_url: r.source_url, repo_id: id, revision: r.revision ?? prev?.revision ?? null });
  }
  const casing = resolveRepoCasing([...new Set([...byImage.values()].map((v) => v.repo_id))], existing);
  const edges = [...byImage].map(([image_node, v]) => ({ image_node, repo_id: casing.get(v.repo_id) ?? v.repo_id, source_url: v.source_url, revision: v.revision }));
  const have = new Set(existing);
  const nodes = [...new Set(edges.map((e) => e.repo_id))].filter((id) => !have.has(id)).map((id) => { const m = /^github:([^/]+)\/(.+)$/.exec(id); return { id, native_id: m ? `${m[1]}/${m[2]}` : id, name: m ? m[2] : id }; });
  return { nodes, edges };
}

/** The graph row of one stored container. Lists are flattened to strings Neo4j can hold: ports as 8080->80/tcp, mounts as type source:destination (ro). */
export function containerGraphRow(r: any, imageNodeOf?: (instanceId: string, image: string | null | undefined, imageId?: string | null) => ContainerImageRef | null) {
  const c = rowToContainer(r);
  const ref = c.image ? imageRef(c.image) : null;
  const node = c.image ? imageNodeOf?.(c.instance_id, c.image, c.image_id) ?? null : null;
  return {
    instance_id: c.instance_id, id: `container:${c.instance_id}:${c.name}`, name: c.name, container_id: c.container_id, image: c.image, image_id: c.image_id, state: c.state, health: c.health, exit_code: c.exit_code, oom_killed: c.oom_killed,
    created: c.created, started_at: c.started_at, finished_at: c.finished_at, restarts: c.restarts, restart_policy: c.restart_policy, privileged: c.privileged, network_mode: c.network_mode, user: c.user, entrypoint: c.entrypoint,
    networks: c.networks, ports: c.ports.map((p) => `${p.host_port != null ? `${p.host_ip && p.host_ip !== "0.0.0.0" && p.host_ip !== "::" ? `${p.host_ip}:` : ""}${p.host_port}->` : ""}${p.container_port}/${p.proto}`),
    mounts: c.mounts.map((m) => `${m.type} ${m.name ?? m.source ?? ""}:${m.destination}${m.rw ? "" : " (ro)"}`),
    source_url: c.source_url, revision: c.revision, image_version: c.image_version, image_title: c.image_title, image_built: c.image_built,
    compose_project: c.compose_project, compose_service: c.compose_service, compose_dir: c.compose_dir, cpu_pct: c.cpu_pct, mem_bytes: c.mem_bytes,
    first_seen: c.first_seen, last_seen: c.last_seen, probes: c.probes, gone: c.gone,
    image_node: node?.image_id ?? ref?.id ?? null, repository: ref?.repository ?? null, tag: ref?.tag ?? null,
  };
}

/** Every stored container of the given instances (or all) as AdvisorContainer nodes with their image, ports and log groups. */
export async function mirrorContainers(instanceIds?: string[]): Promise<{ containers: number; repositories: number } | null> {
  if (!enabled()) return null;
  if (instanceIds && !instanceIds.length) return null;
  await ensureSchema();
  let raw: any[] = [];
  try { raw = instanceIds ? db.prepare(`select * from instance_containers where instance_id in (${instanceIds.map(() => "?").join(",")})`).all(...instanceIds) : db.prepare("select * from instance_containers").all(); }
  catch { return { containers: 0, repositories: 0 }; /* the table is created by src/container_inventory.ts on first load */ }
  // the image node by the box's digest, so the container meets the node the software layer writes (graph_software.ts imageNodeResolver)
  let images: any[] = [];
  try { images = instanceIds ? db.prepare(`select instance_id, image, image_id, digest from instance_images where gone = 0 and instance_id in (${instanceIds.map(() => "?").join(",")})`).all(...instanceIds) : db.prepare("select instance_id, image, image_id, digest from instance_images where gone = 0").all(); } catch { /* no software probe yet */ }
  const imageNodeOf = imageNodeResolver(images);
  const rows = raw.map((r) => containerGraphRow(r, imageNodeOf));
  const now = new Date().toISOString();
  for (const b of chunks(rows)) {
    await writeCypher(CONTAINER_CYPHER, neoParams({ rows: b, now, provider: AWS, account: accountId() }));
    await writeCypher(WIRING_CYPHER, neoParams({ rows: b, now }));
  }
  // the image's source repository, from its label: the same resolver as a function's repository tag
  let repositories = 0;
  if (rows.some((r) => r.image_node && r.source_url)) {
    const existing = (await readQuery("MATCH (r:AdvisorRepository) RETURN r.id AS id", {}, { rowCap: 10_000 })).rows.map((r) => String(r.id));
    const latestFirst = [...rows].sort((a, b) => String(b.last_seen ?? "").localeCompare(String(a.last_seen ?? "")));
    const { nodes, edges } = imageRepositoryRows(latestFirst, repoIdResolver(), existing);
    for (const b of chunks(nodes)) await writeCypher(REPO_NODE_CYPHER, { rows: b, now });
    for (const b of chunks(edges)) await writeCypher(IMAGE_REPO_CYPHER, { rows: b, now });
    repositories = edges.length;
  }
  // an image whose label this pass no longer resolves loses its edge (one that resolved to another repository was moved above); a stub no image names any more goes
  await writeCypher(`MATCH (i:AdvisorImage)-[x:BUILT_FROM {via: 'image_label'}]->(:AdvisorRepository) WHERE i.id IN $images AND (x.updated_at IS NULL OR x.updated_at <> $now) DELETE x`, { images: rows.map((r) => r.image_node).filter((id): id is string => id != null), now });
  await writeCypher("MATCH (n:AdvisorRepository {named_by: 'image_label'}) WHERE NOT (n)--() DELETE n", {});
  // an image node nothing reaches any more (a container moved from the tag-keyed node to the digest one; its own BUILT_FROM to a repository does not keep it)
  await writeCypher("MATCH (n:AdvisorImage) WHERE NOT (n)<--() AND NOT (n)-[:CONTAINS]->() DETACH DELETE n", {});
  if (repositories) await linkCodeRepositoriesQuietly(now);
  return { containers: rows.length, repositories };
}

export const mirrorContainersInBackground = (instanceIds?: string[]) => inBackground(`container mirror${instanceIds ? ` (${instanceIds.join(", ")})` : ""}`, () => mirrorContainers(instanceIds));

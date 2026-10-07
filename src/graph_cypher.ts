/** Cypher fragments shared by the mirror core and the adapters' edge writers (kept apart so the adapter modules need nothing from the core at load time). */

/** A ref for a resource string the inventory has no node for: created on demand by the records that name it. */
export const REF_MERGE = (alias: string, idExpr: string, typeExpr: string, namedBy: string) =>
  `MERGE (${alias}:AdvisorResourceRef {id: ${idExpr}}) ON CREATE SET ${alias}.first_named_at = $now, ${alias}.named_by = '${namedBy}' SET ${alias}.account_id = $account, ${alias}.provider = $provider, ${alias}.native_type = 'ref', ${alias}.native_id = ${idExpr}, ${alias}.guessed_type = ${typeExpr}, ${alias}.updated_at = $now`;

/**
 * Links `from` to the node each id in a list names: the resource, network gateway or account of ours with that id when
 * the graph has one, else an AdvisorResourceRef made on demand. Never a bare AdvisorResource: a node with nothing but
 * an id (no provider, account or native type) is a stub nothing describes, and the graph's schema then reported
 * provider and account_id as optional on every resource. A unit subquery over `list` (each item `li`; nulls skipped),
 * so it follows any WITH that carries `from` and the `carry` variables; `id` reads the id off `li`, `key` is the
 * edge's merge key, `set` a SET clause on the edge `e`; `reverse` points the edge from the target to `from`.
 */
export const LINK_BY_ID = (o: { from: string; carry?: string[]; list: string; id?: string; rel: string; reverse?: boolean; key?: string; set?: string; namedBy: string; guessed?: string }) => {
  const id = o.id ?? "li";
  const vars = [o.from, ...(o.carry ?? [])].join(", ");
  const edge = (to: string) => o.reverse ? `MERGE (${to})-[e:${o.rel}${o.key ? ` ${o.key}` : ""}]->(${o.from})` : `MERGE (${o.from})-[e:${o.rel}${o.key ? ` ${o.key}` : ""}]->(${to})`;
  const set = o.set ? ` SET ${o.set}` : "";
  // Cypher wants a WITH between a FOREACH and a CALL; it carries only `from` and `carry`, which is all any caller uses after
  return `WITH ${vars}
CALL {
  WITH ${vars}
  UNWIND ${o.list} AS li
  WITH ${vars}, li WHERE ${id} IS NOT NULL
  OPTIONAL MATCH (l_res:AdvisorResource {id: ${id}})
  OPTIONAL MATCH (l_gw:AdvisorGateway {id: ${id}})
  OPTIONAL MATCH (l_acc:AdvisorAccount {id: ${id}})
  WITH ${vars}, li, coalesce(l_res, l_gw, l_acc) AS l_hit
  FOREACH (_ IN CASE WHEN l_hit IS NULL THEN [] ELSE [1] END | ${edge("l_hit")}${set})
  FOREACH (_ IN CASE WHEN l_hit IS NULL THEN [1] ELSE [] END | ${REF_MERGE("l_ref", id, o.guessed ?? "null", o.namedBy)} ${edge("l_ref")}${set})
}`;
};

/** True when `alias` is one of our nodes: sweeps over relationship types the wider graph may also use (ASSIGNED, GRANTED, ...) start from ours only. */
export const OURS = (alias: string) => `any(l IN labels(${alias}) WHERE l STARTS WITH 'Advisor')`;

/** The id of the AdvisorCompute (the operating system) an AdvisorBox hosts: one per box, keyed by the box's id. */
export const computeId = (boxId: string) => `compute:${boxId}`;

/**
 * The AdvisorCompute the box `box` hosts, made on demand with its HOSTS edge, as `alias`: the node the software layers
 * (programs, containers, packages, images, vulnerabilities) and the deployments that run on the box attach to. The
 * resource mirror writes it with the box (src/graph_mirror.ts); this keeps a layer that runs first from losing a row.
 */
export const COMPUTE_OF = (box: string, alias: string) =>
  `MERGE (${alias}:AdvisorCompute {id: 'compute:' + ${box}.id}) ON CREATE SET ${alias}.first_seen = $now, ${alias}.name = ${box}.name, ${alias}.provider = ${box}.provider, ${alias}.account_id = ${box}.account_id, ${alias}.native_type = 'operating_system', ${alias}.native_id = ${box}.id, ${alias}.box_id = ${box}.id
MERGE (${box})-[:HOSTS]->(${alias})`;

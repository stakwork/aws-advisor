/** Cypher fragments shared by the mirror core and the adapters' edge writers (kept apart so the adapter modules need nothing from the core at load time). */

/** A ref for a resource string the inventory has no node for: created on demand by the records that name it. */
export const REF_MERGE = (alias: string, idExpr: string, typeExpr: string, namedBy: string) =>
  `MERGE (${alias}:AdvisorResourceRef {id: ${idExpr}}) ON CREATE SET ${alias}.first_named_at = $now, ${alias}.named_by = '${namedBy}' SET ${alias}.account_id = $account, ${alias}.provider = $provider, ${alias}.native_type = 'ref', ${alias}.native_id = ${idExpr}, ${alias}.guessed_type = ${typeExpr}, ${alias}.updated_at = $now`;

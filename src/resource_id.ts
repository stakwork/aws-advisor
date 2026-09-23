/**
 * One identity per resource, whatever the source wrote. The agent tends to return ARNs and instance ids,
 * the rules use the short identifier the Steampipe tables expose; both must merge into one recommendation.
 */
import { db } from "./db.js";
import { shortResourceId } from "./paging.js";

/** ARN, path or `kind:id` → the bare id; the pure helper lives in src/paging.ts so the list merge uses the same one. */
export { shortResourceId };

/** Cluster-level actions must be keyed by the cluster even when the source named a member instance. */
export function canonicalResource(resource: string | null | undefined, actionType: string): string | null {
  const id = shortResourceId(resource);
  if (!id) return null;
  if (/^aurora_/.test(actionType)) {
    try {
      const row = db.prepare("select cluster from inventory_rds where db_instance_identifier = ? and cluster is not null").get(id) as { cluster: string } | undefined;
      if (row?.cluster) return row.cluster;
    } catch { /* inventory not available yet */ }
  }
  return id;
}

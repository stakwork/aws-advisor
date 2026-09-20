/**
 * One identity per resource, whatever the source wrote. The agent tends to return ARNs and instance ids,
 * the rules use the short identifier the Steampipe tables expose; both must merge into one recommendation.
 */
import { db } from "./db.js";

/** ARN or path → the last segment (`arn:aws:rds:us-east-1:1234:db:foo` → `foo`, `arn:...:instance/i-1` → `i-1`). */
export function shortResourceId(resource: string | null | undefined): string | null {
  if (!resource) return null;
  const r = resource.trim();
  if (!r.startsWith("arn:")) return r;
  const tail = r.split(":").slice(5).join(":");
  const seg = tail.split("/").pop() || tail;
  return seg.replace(/^(db|cluster|instance|volume|snapshot|function|log-group):/, "") || r;
}

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

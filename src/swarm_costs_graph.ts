/**
 * The graph is the record: the swarm cost figures land on the instance's AdvisorBox node (src/graph_mirror.ts
 * keys it by instance id; a swarm is one customer's environment, so the node carries tenant = true), so a graph query about a customer's box sees what it costs, when it was last used and
 * whether it is parked next to its role, pool and recommendations.
 */
import { enabled, writeCypher } from "./graph_mirror.js";
import { swarmCostReport } from "./swarm_costs.js";

const CYPHER = `
UNWIND $rows AS row
MATCH (r:AdvisorResource {id: row.instance_id})
SET r.tenant = true, r.tenant_kind = 'swarm', r.cost_month_usd = row.month_usd, r.cost_compute_usd = row.compute_usd, r.cost_storage_usd = row.ebs_usd, r.cost_snapshot_usd = row.snapshot_usd, r.cost_ip_usd = row.ip_usd,
    r.last_use_at = row.last_use_at, r.idle_days = row.idle_days, r.parked = row.parked, r.nudge = row.nudge, r.cost_month = $month, r.cost_updated_at = $now`;

/** Writes the current month's per-swarm figures onto the resource nodes; a no-op without a graph. */
export async function mirrorSwarmCosts(): Promise<{ swarms: number }> {
  if (!enabled()) return { swarms: 0 };
  const r = await swarmCostReport();
  if (!r.swarms.length) return { swarms: 0 };
  const rows = r.swarms.map((s) => ({ instance_id: s.instance_id, month_usd: s.month_usd, compute_usd: s.compute_usd, ebs_usd: s.ebs_usd, snapshot_usd: s.snapshot_usd, ip_usd: s.ip_usd, last_use_at: s.last_use_at, idle_days: s.idle_days, parked: s.parked, nudge: s.nudge }));
  await writeCypher(CYPHER, { rows, month: r.month, now: new Date().toISOString() });
  return { swarms: rows.length };
}

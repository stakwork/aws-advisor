import { accountId, enabled, inBackground, neoParams, writeCypher } from "./graph_mirror.js";
import { sourceOf, type SourceNode } from "./graph_network.js";
import { resourceAccountIndex } from "./resource_index.js";
import { AWS } from "./adapters/types.js";
import { chainTypeOf, instanceFirewalls, isGraphRule, rulesetAttachments, rulesetById, type FwRule, type FwRuleset } from "./host_firewall.js";

/**
 * The host firewalls of the graph (docs/cloud-ontology.md §3 AdvisorFilter {kind: host_firewall}), from src/host_firewall.ts:
 * one (:AdvisorFilter {id: 'hostfw:<sha256 of the normalized rules>'}) per distinct ruleset (iptables, nftables, or both on
 * one box), shared by every box that runs it (the same pattern as an AdvisorImage keyed by digest), -[:HAS_RULE]->
 * (:AdvisorFilterRule {native_type: iptables_rule | nftables_rule}) for every rule of a filter chain and every DNAT/REDIRECT
 * rule of a nat chain, -[:FROM]->(:AdvisorSource) the CIDR or the internet a rule names (the same shared source nodes the
 * security group rules use), and (box)-[:GUARDED_BY {via: 'iptables' | 'nftables'}]->(filter).
 * A box that moves to another ruleset re-points its edge; a filter no box wears any more is marked is_deleted (its rules
 * too) and comes back when a box wears it again, as the software layer does with a package version. Rule ids are a
 * function of the filter id, so a filter's rules never change once written: nothing to prune per filter.
 * Per instance after an apps probe (mirrorApps), for the fleet on the full sync. The port verdicts (REACHABLE_FROM,
 * BLOCKED_BY) do not read these rules yet.
 */

const chunks = <T,>(items: T[], size = 250): T[][] => { const out: T[][] = []; for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size)); return out; };
const LABELS = ["AdvisorFilter", "AdvisorFilterRule", "AdvisorSource"] as const;

export interface FirewallFilterRow { id: string; account_id: string | null; kind: "host_firewall"; stateful: true; default_action: "allow" | "deny"; default: false; name: string; description: string; backend: string | null; input_policy: string | null; forward_policy: string | null; output_policy: string | null; rules: number; rule_total: number; chains: string[]; tables: string[]; truncated: boolean; attached: number; native_type: "iptables" | "nftables" }
export interface FirewallRuleRow { id: string; filter_id: string; account_id: string | null; native_id: string; native_type: "iptables_rule" | "nftables_rule"; direction: FwRule["direction"]; action: FwRule["action"]; protocol: string; from_port: number | null; to_port: number | null; ports: string | null; source_ports: string | null; priority: number; source_kind: "internet" | "cidr" | "any"; source: string | null; source_negated: boolean; destination: string | null; destination_negated: boolean; in_interface: string | null; out_interface: string | null; states: string[]; target: string; target_args: string | null; table: string; chain: string; family: string; comment: string | null; description: string | null; raw: string; source_meta: SourceNode | null }

/** The filter node of a ruleset, with how many boxes wear it. Pure. */
export function firewallFilterRow(rs: FwRuleset, attached: number, account: string | null): FirewallFilterRow {
  const chains = [...new Set(rs.chains.filter((c) => chainTypeOf(c) === "filter").map((c) => c.name))];
  const nft = rs.backend === "nftables";
  const policies = [[nft ? "input" : "INPUT", rs.input_policy], [nft ? "forward" : "FORWARD", rs.forward_policy], [nft ? "output" : "OUTPUT", rs.output_policy]].filter(([, p]) => p).map(([n, p]) => `${n} ${p}`).join(", ");
  const description = `${nft ? "nftables" : "iptables"}${policies ? `: ${policies}` : ""}; ${rs.rule_count} rule${rs.rule_count === 1 ? "" : "s"}${chains.length ? ` in ${chains.length} filter chain${chains.length === 1 ? "" : "s"} (${chains.slice(0, 12).join(", ")}${chains.length > 12 ? ", ..." : ""})` : ""}${rs.truncated ? "; truncated by the probe" : ""}`;
  return {
    id: rs.id, account_id: account, kind: "host_firewall", stateful: true, default_action: rs.default_action, default: false, name: `host firewall ${rs.id.slice(7, 19)}`, description,
    backend: rs.backend, input_policy: rs.input_policy, forward_policy: rs.forward_policy, output_policy: rs.output_policy, rules: rs.graph_rules, rule_total: rs.rule_count, chains, tables: Object.keys(rs.tables).sort(),
    truncated: rs.truncated, attached, native_type: rs.backend === "nftables" ? "nftables" : "iptables",
  };
}

/** The rule nodes of a ruleset: the FROM peer is the rule's source (its destination for an egress rule), when it names an address and is not negated. Pure. */
export function firewallRuleRows(rs: FwRuleset, account: string | null): FirewallRuleRow[] {
  return rs.rules.filter(isGraphRule).map((r) => {
    const peer = r.direction === "egress" ? r.destination : r.source;
    const negated = r.direction === "egress" ? r.destination_negated : r.source_negated;
    // one address with its mask (nft can name a list, a range or a set the text did not carry: no source node for those)
    const meta = peer && !negated && /^[0-9a-f.:]+\/\d+$/i.test(peer) ? sourceOf(peer) : null;
    const source_meta = meta && (meta.kind === "internet" || meta.kind === "cidr") ? meta : null;
    return {
      id: `${rs.id}:${r.family}:${r.table}:${r.chain}:${r.index}`, filter_id: rs.id, account_id: account, native_id: `${r.family} ${r.table} ${r.chain} #${r.index + 1}`, native_type: r.engine === "nft" ? "nftables_rule" : "iptables_rule",
      direction: r.direction, action: r.action, protocol: r.protocol, from_port: r.from_port, to_port: r.to_port, ports: r.ports, source_ports: r.source_ports, priority: r.index,
      source_kind: source_meta ? source_meta.kind as "internet" | "cidr" : "any", source: peer ? `${negated ? "!" : ""}${peer}` : null, source_negated: Boolean(negated),
      destination: r.destination, destination_negated: r.destination_negated, in_interface: r.in_interface, out_interface: r.out_interface, states: r.states, target: r.target, target_args: r.target_args,
      table: r.table, chain: r.chain, family: r.family, comment: r.comment, description: r.comment, raw: r.raw, source_meta,
    };
  });
}

const FILTER_CYPHER = `
UNWIND $rows AS row
MERGE (f:AdvisorFilter {id: row.id})
ON CREATE SET f.first_seen = $now
SET f += {kind: 'host_firewall', stateful: true, default_action: row.default_action, default: false, name: row.name, description: row.description, backend: row.backend,
  input_policy: row.input_policy, forward_policy: row.forward_policy, output_policy: row.output_policy, rules: row.rules, rule_total: row.rule_total, chains: row.chains, tables: row.tables,
  truncated: row.truncated, attached: row.attached, provider: $provider, account_id: coalesce(row.account_id, f.account_id, $account), native_type: row.native_type, native_id: row.id,
  gone: false, is_deleted: false, deleted_at: null, last_seen: $now, updated_at: $now}`;

const RULE_CYPHER = `
UNWIND $rows AS row
MERGE (r:AdvisorFilterRule {id: row.id})
ON CREATE SET r.first_seen = $now
SET r += {direction: row.direction, action: row.action, protocol: row.protocol, from_port: row.from_port, to_port: row.to_port, ports: row.ports, source_ports: row.source_ports, priority: row.priority,
  source_kind: row.source_kind, source: row.source, source_negated: row.source_negated, destination: row.destination, destination_negated: row.destination_negated,
  in_interface: row.in_interface, out_interface: row.out_interface, states: row.states, target: row.target, target_args: row.target_args, table: row.table, chain: row.chain, family: row.family,
  comment: row.comment, description: row.description, raw: row.raw, dormant: false, filter_id: row.filter_id, provider: $provider, account_id: coalesce(row.account_id, r.account_id, $account),
  native_type: row.native_type, native_id: row.native_id, gone: false, is_deleted: false, deleted_at: null, last_seen: $now, updated_at: $now}
WITH r, row
MATCH (f:AdvisorFilter {id: row.filter_id})
MERGE (f)-[:HAS_RULE]->(r)
WITH r, row
OPTIONAL MATCH (r)-[o:FROM]->() DELETE o
WITH DISTINCT r, row
FOREACH (s IN CASE WHEN row.source_meta IS NULL THEN [] ELSE [row.source_meta] END |
  MERGE (src:AdvisorSource {id: s.id}) SET src.kind = s.kind, src.label = s.label, src.cidr = s.cidr, src.private = s.private, src.native_type = 'source', src.updated_at = $now
  MERGE (r)-[:FROM]->(src))`;

/** The box wears its current ruleset and no other host firewall: the previous edge goes (the box's history is in instance_app_events). */
const GUARD_CYPHER = `
UNWIND $rows AS row
MATCH (b:AdvisorResource {id: row.instance_id}) MATCH (f:AdvisorFilter {id: row.filter_id})
OPTIONAL MATCH (b)-[old:GUARDED_BY]->(o:AdvisorFilter {kind: 'host_firewall'}) WHERE o.id <> f.id DELETE old
WITH DISTINCT b, f, row
MERGE (b)-[g:GUARDED_BY]->(f) SET g.via = row.via, g.backend = row.backend, g.collected_at = row.collected_at, g.updated_at = $now`;

/** A box whose probe found no packet filter wears none. */
const UNGUARD_CYPHER = `
UNWIND $ids AS id
MATCH (:AdvisorResource {id: id})-[old:GUARDED_BY]->(:AdvisorFilter {kind: 'host_firewall'}) DELETE old`;

/** A ruleset no box wears any more is history, its rules with it; one a box wears again is back. */
const ORPHAN_CYPHER = `
MATCH (f:AdvisorFilter {kind: 'host_firewall'}) WHERE coalesce(f.is_deleted, false) = false AND NOT (f)<-[:GUARDED_BY]-()
SET f.is_deleted = true, f.deleted_at = $now, f.attached = 0
WITH f OPTIONAL MATCH (f)-[:HAS_RULE]->(r) SET r.is_deleted = true, r.deleted_at = $now`;
const REVIVE_CYPHER = `
MATCH (f:AdvisorFilter {kind: 'host_firewall'}) WHERE f.is_deleted = true AND (f)<-[:GUARDED_BY]-()
SET f.is_deleted = false, f.deleted_at = null
WITH f OPTIONAL MATCH (f)-[:HAS_RULE]->(r) SET r.is_deleted = false, r.deleted_at = null`;

export interface HostFirewallCounts { filters: number; rules: number; boxes: number }

/** The host firewalls of the given boxes (or every box's): the shared filter nodes, their rules, and which box wears which. */
export async function mirrorHostFirewalls(instanceIds?: string[]): Promise<HostFirewallCounts | null> {
  if (!enabled()) return null;
  if (instanceIds && !instanceIds.length) return null;
  let boxes: ReturnType<typeof instanceFirewalls> = [];
  try { boxes = instanceFirewalls(instanceIds); } catch { return { filters: 0, rules: 0, boxes: 0 }; }
  const account = accountId();
  const now = new Date().toISOString();
  for (const l of LABELS) await writeCypher(`CREATE CONSTRAINT ${l.toLowerCase()}_id IF NOT EXISTS FOR (n:${l}) REQUIRE n.id IS UNIQUE`);
  const attached = rulesetAttachments();
  const idx = resourceAccountIndex(account);
  // the filter's account is its first wearer's (by instance id), as a shared package version takes the account of a box that has it
  const firstWearer = new Map<string, string>();
  for (const b of [...boxes].sort((a, c) => a.instance_id.localeCompare(c.instance_id))) if (b.ruleset_id && !firstWearer.has(b.ruleset_id)) firstWearer.set(b.ruleset_id, b.instance_id);
  const rulesets = [...firstWearer.keys()].map((id) => rulesetById(id)).filter((r): r is FwRuleset => r != null);
  const filterRows = rulesets.map((rs) => firewallFilterRow(rs, attached.get(rs.id) ?? 0, idx.of(firstWearer.get(rs.id)!) ?? null));
  const ruleRows = rulesets.flatMap((rs) => firewallRuleRows(rs, idx.of(firstWearer.get(rs.id)!) ?? null));
  // via: the tool that read the rules: iptables (nft too, where the box has both), or nftables alone
  const guardRows = boxes.filter((b) => b.ruleset_id).map((b) => ({ instance_id: b.instance_id, filter_id: b.ruleset_id!, backend: b.backend, via: b.backend === "nftables" ? "nftables" : "iptables", collected_at: b.collected_at }));
  const unguard = boxes.filter((b) => !b.ruleset_id).map((b) => b.instance_id);
  for (const b of chunks(filterRows)) await writeCypher(FILTER_CYPHER, neoParams({ rows: b, now, provider: AWS, account }));
  for (const b of chunks(ruleRows, 100)) await writeCypher(RULE_CYPHER, neoParams({ rows: b, now, provider: AWS, account }));
  for (const b of chunks(guardRows)) await writeCypher(GUARD_CYPHER, { rows: b, now });
  for (const b of chunks(unguard)) await writeCypher(UNGUARD_CYPHER, { ids: b });
  await writeCypher(REVIVE_CYPHER, { now });
  await writeCypher(ORPHAN_CYPHER, { now });
  return { filters: filterRows.length, rules: ruleRows.length, boxes: guardRows.length };
}

export const mirrorHostFirewallsInBackground = (instanceIds?: string[]) => inBackground(`host firewall mirror${instanceIds ? ` (${instanceIds.join(", ")})` : ""}`, () => mirrorHostFirewalls(instanceIds));


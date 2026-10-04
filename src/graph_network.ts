import { db } from "./db.js";
import { PROVIDER, accountId, enabled, writeCypher } from "./graph_mirror.js";
import { ingressRulesFor, naclVerdict, reachOf, type IngressRule, type NaclEntry, type PortReach, type ReachContext, type RuleRef } from "./instance_apps.js";
import { vpcHasIpv6 } from "./security_groups.js";
import { allEgressRules, eniOwner, isPublicSubnet, listEips, listEnis, listGateways, listRouteTables, listSubnets, routeTableOf, routeTarget, type EniRow, type GatewayRow, type RouteTableRow, type SubnetRow } from "./network_inventory.js";

/**
 * The network layer of the graph (docs/cloud-ontology.md §3) for the AWS adapter: networks (VPCs), segments
 * (subnets), route tables and gateways, interfaces and public addresses, filters (security groups, network ACLs) with
 * their rules, and the sources rules let in. On top of it the verdicts an agent reads without re-implementing any of
 * it: for every endpoint, `REACHABLE_FROM` the sources that can reach it, `ALLOWED_BY` the rules that let them in and
 * `BLOCKED_BY` what stops a source a rule would otherwise admit. The verdicts come from the same code that gives a
 * port its `exposure` word (src/instance_apps.ts reachOf, naclVerdict), applied to instance ports, balancer
 * listeners and database endpoints. Rebuilt wholesale on every resource mirror; per instance after a probe.
 */

export const NETWORK_LABELS = ["AdvisorNetwork", "AdvisorSegment", "AdvisorRouteTable", "AdvisorGateway", "AdvisorInterface", "AdvisorPublicIp", "AdvisorFilter", "AdvisorFilterRule", "AdvisorSource"] as const;

const str = (v: unknown): string | null => (v == null ? null : String(v));
const safeJson = (s: unknown): any => { if (typeof s !== "string") return s ?? null; try { return JSON.parse(s); } catch { return null; } };
const rows = (sql: string, ...params: unknown[]): any[] => { try { return db.prepare(sql).all(...params) as any[]; } catch { return []; } };
const chunks = <T,>(items: T[], size = 250): T[][] => { const out: T[][] = []; for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size)); return out; };
const now = () => new Date().toISOString();

// ---- pure mapping -------------------------------------------------------------------------------------------------------

/** The protocol word of a rule: AWS writes -1, 6, 17, 1 or the name. */
export const protocolWord = (p: string | null | undefined): string => (p == null || p === "-1" ? "any" : p === "6" ? "tcp" : p === "17" ? "udp" : p === "1" ? "icmp" : p === "58" ? "icmpv6" : String(p).toLowerCase());

export interface SourceNode { id: string; kind: "internet" | "cidr" | "prefix_list"; label: string; cidr: string | null; private: boolean }
const isPrivate = (cidr: string) => /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|fc|fd|169\.254\.|127\.)/i.test(cidr);

/** The AdvisorSource a CIDR or prefix list stands for; the internet for the world ranges. Pure. */
export function sourceOf(cidr: string | null | undefined, prefixList?: string | null): SourceNode | null {
  if (cidr === "0.0.0.0/0" || cidr === "::/0") return { id: "internet", kind: "internet", label: "internet", cidr: null, private: false };
  if (cidr) return { id: `cidr:${cidr}`, kind: "cidr", label: cidr, cidr, private: isPrivate(cidr) };
  if (prefixList) return { id: `prefix:${prefixList}`, kind: "prefix_list", label: `prefix list ${prefixList}`, cidr: null, private: true };
  return null;
}

export interface FilterRuleNode {
  id: string; filter_id: string; direction: "ingress" | "egress"; action: "allow" | "deny"; protocol: string; from_port: number | null; to_port: number | null; priority: number | null;
  source_kind: "internet" | "cidr" | "filter" | "prefix_list" | "any"; source: string | null; description: string | null; dormant: boolean; native_id: string | null;
  /** Where the FROM edge goes: an AdvisorSource id or (for a group reference) an AdvisorFilter id. */
  source_node: { label: "AdvisorSource" | "AdvisorFilter"; id: string } | null; source_meta: SourceNode | null;
}

/** A security group rule row as an AdvisorFilterRule. `dormant` = an IPv6-only rule in a network without IPv6. Pure. */
export function sgRuleNode(r: IngressRule, direction: "ingress" | "egress", vpcIpv6: boolean | null): FilterRuleNode {
  const src = sourceOf(r.cidr_ipv4 || r.cidr_ipv6, r.prefix_list_id);
  const sourceKind: FilterRuleNode["source_kind"] = r.referenced_group_id ? "filter" : src?.kind === "internet" ? "internet" : src?.kind === "cidr" ? "cidr" : src?.kind === "prefix_list" ? "prefix_list" : "any";
  const key = r.rule_id || `${r.group_id}:${direction}:${protocolWord(r.ip_protocol)}:${r.from_port ?? "*"}-${r.to_port ?? "*"}:${r.cidr_ipv4 || r.cidr_ipv6 || r.referenced_group_id || r.prefix_list_id || "any"}`;
  const allPorts = r.from_port == null || r.from_port === -1 || (r.from_port === 0 && r.to_port === 65535);
  return {
    id: key, filter_id: r.group_id, direction, action: "allow", protocol: protocolWord(r.ip_protocol), from_port: allPorts ? null : r.from_port ?? null, to_port: allPorts ? null : r.to_port ?? null, priority: null,
    source_kind: sourceKind, source: r.referenced_group_id || r.cidr_ipv4 || r.cidr_ipv6 || r.prefix_list_id || null, description: r.description ?? null,
    dormant: Boolean(r.cidr_ipv6) && !r.cidr_ipv4 && !r.referenced_group_id && !r.prefix_list_id && vpcIpv6 === false, native_id: r.rule_id ?? null,
    source_node: r.referenced_group_id ? { label: "AdvisorFilter", id: r.referenced_group_id } : src ? { label: "AdvisorSource", id: src.id } : null, source_meta: src,
  };
}

/** A network ACL entry as an AdvisorFilterRule: ordered by RuleNumber, allow or deny. Pure. */
export function naclRuleNode(aclId: string, e: NaclEntry): FilterRuleNode {
  const cidr = e.CidrBlock ?? e.Ipv6CidrBlock ?? null;
  const src = sourceOf(cidr);
  return {
    id: naclRuleId(aclId, e), filter_id: aclId, direction: e.Egress ? "egress" : "ingress", action: e.RuleAction === "allow" ? "allow" : "deny", protocol: protocolWord(String(e.Protocol)),
    from_port: e.PortRange?.From ?? null, to_port: e.PortRange?.To ?? null, priority: e.RuleNumber, source_kind: src?.kind === "internet" ? "internet" : src ? "cidr" : "any", source: cidr, description: null, dormant: false,
    native_id: String(e.RuleNumber), source_node: src ? { label: "AdvisorSource", id: src.id } : null, source_meta: src,
  };
}
export const naclRuleId = (aclId: string, e: Pick<NaclEntry, "Egress" | "RuleNumber">) => `${aclId}:${e.Egress ? "out" : "in"}:${e.RuleNumber}`;

export interface VerdictEdges {
  exposure: PortReach["exposure"]; reason: string;
  reachable_from: { label: "AdvisorSource" | "AdvisorFilter"; id: string; via_rule: string | null; through: string[]; note: string | null; source_meta: SourceNode | null }[];
  allowed_by: { rule_id: string; source: string }[];
  blocked_by: { label: "AdvisorFilterRule" | "AdvisorFilter"; id: string; source: string; reason: string }[];
}

/**
 * The verdict edges for one endpoint from its security group rules and context: who can reach it (one edge per
 * distinct source, the rule that lets it in and the ACL entry it passed), and what blocks a source a rule admits
 * (the network ACL entry, or the implicit deny; the security groups themselves when no rule matches). Pure.
 */
export interface Listener { proto: "tcp" | "udp"; port: number; scope: "all" | "loopback" | "address"; bind: string }
export function verdictEdges(l: Listener, rules: IngressRule[], ctx: ReachContext, groupIds: string[]): VerdictEdges {
  const reach = reachOf(l, rules, ctx);
  const out: VerdictEdges = { exposure: reach.exposure, reason: reach.reason, reachable_from: [], allowed_by: [], blocked_by: [] };
  if (reach.exposure === "local") return out;
  const seen = new Set<string>();
  const ruleFor = (ref: RuleRef): IngressRule | undefined => rules.find((r) => (ref.rule_id && r.rule_id === ref.rule_id) || (!ref.rule_id && r.group_id === ref.group_id && (r.cidr_ipv4 === ref.source || r.cidr_ipv6 === ref.source || r.referenced_group_id === ref.source.split(" ").pop() || (r.prefix_list_id && ref.source.endsWith(r.prefix_list_id)))));
  for (const ref of reach.allowed_by) {
    const r = ruleFor(ref);
    const node = r ? sgRuleNode(r, "ingress", null) : null;
    const target = node?.source_node ?? (ref.world ? { label: "AdvisorSource" as const, id: "internet" } : null);
    if (!target) continue;
    const through: string[] = node ? [node.id] : [];
    let note: string | null = null;
    // the ACL entry it passed, when the source has an address and the subnet has an ACL
    const cidr = r?.cidr_ipv4 || r?.cidr_ipv6;
    if (ctx.nacl && cidr) {
      const v = naclVerdict(ctx.nacl.entries, l.proto, l.port, cidr);
      if (v.entry) through.push(naclRuleId(ctx.nacl.acl_id, v.entry));
      if (v.verdict === "narrow") note = `the network ACL ${ctx.nacl.acl_id} lets in only ${v.cidrs.join(", ")} of it`;
      else if (v.partial_reply) note = `the network ACL ${ctx.nacl.acl_id} drops replies to some client ports`;
    }
    if (ref.world && ctx.public_ip === null && !r?.cidr_ipv6) note = note ? `${note}; no public address, reachable from inside the network only` : "a world rule, but no public address: reachable from inside the network only";
    if (node) out.allowed_by.push({ rule_id: node.id, source: target.id });
    if (seen.has(target.id)) continue;
    seen.add(target.id);
    out.reachable_from.push({ ...target, via_rule: node?.id ?? null, through, note, source_meta: node?.source_meta ?? (ref.world ? sourceOf("0.0.0.0/0") : null) });
  }
  // what the ACL stops: every CIDR rule that matches the port but whose source the ACL denies or whose replies it drops
  if (ctx.nacl) {
    for (const r of rules) {
      const node = sgRuleNode(r, "ingress", null);
      const cidr = r.cidr_ipv4 || r.cidr_ipv6;
      if (!cidr || !matches(r, l)) continue;
      const v = naclVerdict(ctx.nacl.entries, l.proto, l.port, cidr);
      const src = node.source_node?.id ?? cidr;
      if (v.verdict === "deny") out.blocked_by.push(v.entry ? { label: "AdvisorFilterRule", id: naclRuleId(ctx.nacl.acl_id, v.entry), source: src, reason: `${ctx.nacl.acl_id} rule #${v.entry.RuleNumber} denies it` } : { label: "AdvisorFilter", id: ctx.nacl.acl_id, source: src, reason: `${ctx.nacl.acl_id}: no entry allows it (the implicit deny)` });
      else if (v.verdict === "no_reply") out.blocked_by.push(v.reply_entry ? { label: "AdvisorFilterRule", id: naclRuleId(ctx.nacl.acl_id, v.reply_entry), source: src, reason: `${ctx.nacl.acl_id} rule #${v.reply_entry.RuleNumber} drops the replies` } : { label: "AdvisorFilter", id: ctx.nacl.acl_id, source: src, reason: `${ctx.nacl.acl_id} lets it in but no outbound entry allows the replies` });
    }
  }
  if (reach.exposure === "closed" && reach.blocked_by === "security_group") for (const g of groupIds) out.blocked_by.push({ label: "AdvisorFilter", id: g, source: "any", reason: rules.length ? `no rule in ${g} lets ${l.port}/${l.proto} in` : "no rules known for this group yet" });
  return out;
}
const matches = (r: IngressRule, l: { proto: string; port: number }) => (r.ip_protocol == null || r.ip_protocol === "-1" || r.ip_protocol.toLowerCase() === l.proto || (r.ip_protocol === "6" && l.proto === "tcp") || (r.ip_protocol === "17" && l.proto === "udp")) && ((r.from_port == null && r.to_port == null) || r.from_port === -1 || ((r.from_port ?? 0) <= l.port && l.port <= (r.to_port ?? 65535)));

// ---- Cypher -------------------------------------------------------------------------------------------------------------

const NETWORK_CYPHER = `
UNWIND $rows AS row
MERGE (n:AdvisorNetwork {id: row.id})
ON CREATE SET n.first_seen = $now
SET n += {cidr_blocks: row.cidr_blocks, ipv6_blocks: row.ipv6_blocks, default: row.default, flat: false, name: row.name, region: row.region, provider: $provider, account_id: coalesce(row.account_id, $account), native_type: 'vpc', native_id: row.id, gone: false, last_seen: $now, updated_at: $now}
WITH n, row MATCH (a:AdvisorAccount {id: coalesce(row.account_id, $account)}) MERGE (n)-[:IN_ACCOUNT]->(a)`;

const SEGMENT_CYPHER = `
UNWIND $rows AS row
MERGE (s:AdvisorSegment {id: row.id})
ON CREATE SET s.first_seen = $now
SET s += {cidr: row.cidr, ipv6_cidr: row.ipv6_cidr, zone: row.zone, public: row.public, auto_public_ip: row.auto_public_ip, available_ips: row.available_ips, default: row.default, name: row.name, region: row.region, provider: $provider, account_id: coalesce(row.account_id, $account), native_type: 'subnet', native_id: row.id, gone: false, last_seen: $now, updated_at: $now}
WITH s, row
OPTIONAL MATCH (s)-[o1:IN_NETWORK]->() DELETE o1
WITH DISTINCT s, row
OPTIONAL MATCH (s)-[o2:USES_ROUTE_TABLE]->() DELETE o2
WITH DISTINCT s, row
OPTIONAL MATCH (s)-[o3:GUARDED_BY]->() DELETE o3
WITH DISTINCT s, row
FOREACH (_ IN CASE WHEN row.vpc_id IS NULL THEN [] ELSE [1] END | MERGE (n:AdvisorNetwork {id: row.vpc_id}) MERGE (s)-[:IN_NETWORK]->(n))
FOREACH (_ IN CASE WHEN row.route_table_id IS NULL THEN [] ELSE [1] END | MERGE (t:AdvisorRouteTable {id: row.route_table_id}) MERGE (s)-[:USES_ROUTE_TABLE]->(t))
FOREACH (_ IN CASE WHEN row.nacl_id IS NULL THEN [] ELSE [1] END | MERGE (f:AdvisorFilter {id: row.nacl_id}) MERGE (s)-[:GUARDED_BY]->(f))`;

const ROUTE_TABLE_CYPHER = `
UNWIND $rows AS row
MERGE (t:AdvisorRouteTable {id: row.id})
ON CREATE SET t.first_seen = $now
SET t += {main: row.main, routes: row.route_count, name: row.name, region: row.region, provider: $provider, account_id: coalesce(row.account_id, $account), native_type: 'route_table', native_id: row.id, gone: false, last_seen: $now, updated_at: $now}
WITH t, row
OPTIONAL MATCH (t)-[o:ROUTES]->() DELETE o
WITH DISTINCT t, row
OPTIONAL MATCH (t)-[o2:IN_NETWORK]->() DELETE o2
WITH DISTINCT t, row
FOREACH (_ IN CASE WHEN row.vpc_id IS NULL THEN [] ELSE [1] END | MERGE (n:AdvisorNetwork {id: row.vpc_id}) MERGE (t)-[:IN_NETWORK]->(n))
FOREACH (r IN [x IN row.routes WHERE x.label = 'AdvisorGateway'] |
  MERGE (g:AdvisorGateway {id: r.id}) ON CREATE SET g.kind = r.kind, g.provider = $provider, g.account_id = coalesce(row.account_id, $account), g.native_type = r.kind, g.native_id = r.id, g.first_seen = $now, g.updated_at = $now
  MERGE (t)-[e:ROUTES {destination: r.destination}]->(g) SET e.state = r.state, e.origin = r.origin, e.updated_at = $now)
FOREACH (r IN [x IN row.routes WHERE x.label = 'AdvisorInterface'] |
  MERGE (i:AdvisorInterface {id: r.id}) MERGE (t)-[e:ROUTES {destination: r.destination}]->(i) SET e.state = r.state, e.origin = r.origin, e.updated_at = $now)
FOREACH (r IN [x IN row.routes WHERE x.label = 'AdvisorResource'] |
  MERGE (i:AdvisorResource {id: r.id}) MERGE (t)-[e:ROUTES {destination: r.destination}]->(i) SET e.state = r.state, e.origin = r.origin, e.updated_at = $now)`;

const GATEWAY_CYPHER = `
UNWIND $rows AS row
MERGE (g:AdvisorGateway {id: row.id})
ON CREATE SET g.first_seen = $now
SET g += {kind: row.kind, state: row.state, public_ip: row.public_ip, public_ips: row.public_ips, private_ip: row.private_ip, service: row.service, endpoint_type: row.endpoint_type, peer_network_id: row.peer_vpc_id, peer_account_id: row.peer_account_id, name: row.name, region: row.region, provider: $provider, account_id: coalesce(row.account_id, $account), native_type: row.native_type, native_id: row.id, gone: false, last_seen: $now, updated_at: $now}
WITH g, row
OPTIONAL MATCH (g)-[o:IN_NETWORK]->() DELETE o
WITH DISTINCT g, row
FOREACH (_ IN CASE WHEN row.vpc_id IS NULL THEN [] ELSE [1] END | MERGE (n:AdvisorNetwork {id: row.vpc_id}) MERGE (g)-[:IN_NETWORK]->(n))
FOREACH (_ IN CASE WHEN row.subnet_id IS NULL THEN [] ELSE [1] END | MERGE (s:AdvisorSegment {id: row.subnet_id}) MERGE (g)-[:IN_SEGMENT]->(s))
FOREACH (_ IN CASE WHEN row.kind = 'peering' AND row.vpc_id IS NOT NULL AND row.peer_vpc_id IS NOT NULL THEN [1] ELSE [] END |
  MERGE (a:AdvisorNetwork {id: row.vpc_id}) MERGE (b:AdvisorNetwork {id: row.peer_vpc_id}) ON CREATE SET b.provider = $provider, b.native_type = 'vpc', b.native_id = row.peer_vpc_id, b.account_id = coalesce(row.peer_account_id, $account), b.foreign = row.peer_account_id IS NOT NULL AND row.peer_account_id <> $account
  MERGE (a)-[p:PEERS_WITH]->(b) SET p.state = row.state, p.cidrs = row.peer_cidrs, p.via = row.id, p.updated_at = $now
  MERGE (b)-[q:PEERS_WITH]->(a) SET q.state = row.state, q.cidrs = row.cidrs, q.via = row.id, q.updated_at = $now)
FOREACH (_ IN CASE WHEN row.kind = 'nat' THEN [1] ELSE [] END | MERGE (sys:KnSystem {id: 'nat:' + row.id}) MERGE (g)-[:MEMBER_OF]->(sys))
FOREACH (sg IN row.groups | MERGE (f:AdvisorFilter {id: sg}) MERGE (g)-[:GUARDED_BY]->(f))`;

const INTERFACE_CYPHER = `
UNWIND $rows AS row
MERGE (i:AdvisorInterface {id: row.id})
ON CREATE SET i.first_seen = $now
SET i += {private_ips: row.private_ips, public_ip: row.public_ip, ipv6: row.ipv6, mac: row.mac, interface_type: row.interface_type, owner_kind: row.owner_kind, description: row.description, status: row.status, source_dest_check: row.source_dest_check, primary: row.primary, region: row.region, provider: $provider, account_id: coalesce(row.account_id, $account), native_type: 'network_interface', native_id: row.id, gone: false, last_seen: $now, updated_at: $now}
WITH i, row
OPTIONAL MATCH (i)-[o:ATTACHED_TO|IN_SEGMENT|IN_NETWORK|WEARS]->() DELETE o
WITH DISTINCT i, row
FOREACH (_ IN CASE WHEN row.vpc_id IS NULL THEN [] ELSE [1] END | MERGE (n:AdvisorNetwork {id: row.vpc_id}) MERGE (i)-[:IN_NETWORK]->(n))
FOREACH (_ IN CASE WHEN row.subnet_id IS NULL THEN [] ELSE [1] END | MERGE (s:AdvisorSegment {id: row.subnet_id}) MERGE (i)-[:IN_SEGMENT]->(s))
FOREACH (sg IN row.groups | MERGE (f:AdvisorFilter {id: sg}) MERGE (i)-[:WEARS]->(f))
FOREACH (_ IN CASE WHEN row.resource_id IS NULL THEN [] ELSE [1] END | MERGE (r:AdvisorResource {id: row.resource_id}) MERGE (i)-[:ATTACHED_TO]->(r))
FOREACH (_ IN CASE WHEN row.gateway_id IS NULL THEN [] ELSE [1] END | MERGE (g:AdvisorGateway {id: row.gateway_id}) MERGE (i)-[:ATTACHED_TO]->(g))`;

const PUBLIC_IP_CYPHER = `
UNWIND $rows AS row
MERGE (p:AdvisorPublicIp {id: row.id})
ON CREATE SET p.first_seen = $now
SET p += {ip: row.ip, kind: 'static', associated: row.associated, allocation_id: row.allocation_id, region: row.region, provider: $provider, account_id: coalesce(row.account_id, $account), native_type: 'elastic_ip', native_id: row.id, gone: false, last_seen: $now, updated_at: $now}
WITH p, row
OPTIONAL MATCH (p)-[o:ASSIGNED]->() DELETE o
WITH DISTINCT p, row
FOREACH (_ IN CASE WHEN row.eni_id IS NULL THEN [] ELSE [1] END | MERGE (i:AdvisorInterface {id: row.eni_id}) MERGE (p)-[:ASSIGNED]->(i))
FOREACH (_ IN CASE WHEN row.gateway_id IS NULL THEN [] ELSE [1] END | MERGE (g:AdvisorGateway {id: row.gateway_id}) MERGE (p)-[:ASSIGNED]->(g))`;

const FILTER_CYPHER = `
UNWIND $rows AS row
MERGE (f:AdvisorFilter {id: row.id})
ON CREATE SET f.first_seen = $now
SET f += {kind: row.kind, stateful: row.stateful, default_action: 'deny', default: row.default, name: row.name, description: row.description, rules: row.rules, attached: row.attached, region: row.region, provider: $provider, account_id: coalesce(row.account_id, $account), native_type: row.native_type, native_id: row.id, gone: false, last_seen: $now, updated_at: $now}
WITH f, row
OPTIONAL MATCH (f)-[o:IN_NETWORK]->() DELETE o
WITH DISTINCT f, row
FOREACH (_ IN CASE WHEN row.vpc_id IS NULL THEN [] ELSE [1] END | MERGE (n:AdvisorNetwork {id: row.vpc_id}) MERGE (f)-[:IN_NETWORK]->(n))`;

const RULE_CYPHER = `
UNWIND $rows AS row
MERGE (r:AdvisorFilterRule {id: row.id})
ON CREATE SET r.first_seen = $now
SET r += {direction: row.direction, action: row.action, protocol: row.protocol, from_port: row.from_port, to_port: row.to_port, priority: row.priority, source_kind: row.source_kind, source: row.source, description: row.description, dormant: row.dormant, filter_id: row.filter_id, provider: $provider, account_id: coalesce(row.account_id, $account), native_type: row.native_type, native_id: coalesce(row.native_id, row.id), gone: false, last_seen: $now, updated_at: $now}
WITH r, row
MERGE (f:AdvisorFilter {id: row.filter_id})
MERGE (f)-[:HAS_RULE]->(r)
WITH r, row
OPTIONAL MATCH (r)-[o:FROM]->() DELETE o
WITH DISTINCT r, row
FOREACH (s IN CASE WHEN row.source_label = 'AdvisorSource' THEN [row.source_meta] ELSE [] END |
  MERGE (src:AdvisorSource {id: s.id}) SET src.kind = s.kind, src.label = s.label, src.cidr = s.cidr, src.private = s.private, src.native_type = 'source', src.native_id = s.id, src.updated_at = $now
  MERGE (r)-[:FROM]->(src))
FOREACH (_ IN CASE WHEN row.source_label = 'AdvisorFilter' THEN [1] ELSE [] END |
  MERGE (g:AdvisorFilter {id: row.source_id}) MERGE (r)-[:FROM]->(g))`;

/** Resources that wear filters directly (databases, caches, balancers, and compute without an interface row). */
const GUARDED_CYPHER = `
UNWIND $rows AS row
MATCH (r:AdvisorResource {id: row.id})
OPTIONAL MATCH (r)-[o:GUARDED_BY]->() DELETE o
WITH DISTINCT r, row
FOREACH (sg IN row.groups | MERGE (f:AdvisorFilter {id: sg}) MERGE (r)-[:GUARDED_BY]->(f))
FOREACH (_ IN CASE WHEN row.vpc_id IS NULL THEN [] ELSE [1] END | MERGE (n:AdvisorNetwork {id: row.vpc_id}) MERGE (r)-[:IN_NETWORK]->(n))
FOREACH (_ IN CASE WHEN row.subnet_id IS NULL THEN [] ELSE [1] END | MERGE (s:AdvisorSegment {id: row.subnet_id}) MERGE (r)-[:IN_SEGMENT]->(s))`;

const VERDICT_CLEAR_CYPHER = `
UNWIND $ids AS id
MATCH (e:AdvisorEndpoint {id: id})-[v:REACHABLE_FROM|ALLOWED_BY|BLOCKED_BY]->()
DELETE v`;

const VERDICT_CYPHER = `
UNWIND $rows AS row
MATCH (e:AdvisorEndpoint {id: row.id})
SET e.exposure = row.exposure, e.reach_reason = row.reason, e.reach_computed_at = $now
WITH e, row
FOREACH (x IN [y IN row.reachable_from WHERE y.label = 'AdvisorSource'] |
  MERGE (s:AdvisorSource {id: x.id}) ON CREATE SET s.kind = x.source_meta.kind, s.label = x.source_meta.label, s.cidr = x.source_meta.cidr, s.private = x.source_meta.private, s.native_type = 'source', s.native_id = x.id
  MERGE (e)-[v:REACHABLE_FROM]->(s) SET v.protocol = row.protocol, v.port = row.port, v.via_rule = x.via_rule, v.through = x.through, v.note = x.note, v.requires_auth = false, v.computed_at = $now)
FOREACH (x IN [y IN row.reachable_from WHERE y.label = 'AdvisorFilter'] |
  MERGE (f:AdvisorFilter {id: x.id})
  MERGE (e)-[v:REACHABLE_FROM]->(f) SET v.protocol = row.protocol, v.port = row.port, v.via_rule = x.via_rule, v.through = x.through, v.note = x.note, v.requires_auth = false, v.computed_at = $now)
FOREACH (x IN row.allowed_by |
  MERGE (r:AdvisorFilterRule {id: x.rule_id})
  MERGE (e)-[v:ALLOWED_BY]->(r) SET v.source = x.source, v.computed_at = $now)
FOREACH (x IN [y IN row.blocked_by WHERE y.label = 'AdvisorFilterRule'] |
  MERGE (r:AdvisorFilterRule {id: x.id})
  MERGE (e)-[v:BLOCKED_BY]->(r) SET v.source = x.source, v.reason = x.reason, v.computed_at = $now)
FOREACH (x IN [y IN row.blocked_by WHERE y.label = 'AdvisorFilter'] |
  MERGE (f:AdvisorFilter {id: x.id})
  MERGE (e)-[v:BLOCKED_BY]->(f) SET v.source = x.source, v.reason = x.reason, v.computed_at = $now)`;

// ---- the mirror ---------------------------------------------------------------------------------------------------------

export interface NetworkCounts { networks: number; segments: number; route_tables: number; gateways: number; interfaces: number; public_ips: number; filters: number; rules: number; endpoints_judged: number; took_ms: number }

/** The whole network layer and every endpoint's verdicts; idempotent. */
export async function mirrorNetwork(): Promise<NetworkCounts | null> {
  if (!enabled()) return null;
  const t0 = Date.now();
  const account = accountId();
  const stamp = now();
  const w = (cypher: string, batch: any[]) => writeCypher(cypher, { rows: batch, account, provider: PROVIDER, now: stamp });
  for (const l of NETWORK_LABELS) await writeCypher(`CREATE CONSTRAINT ${l.toLowerCase()}_id IF NOT EXISTS FOR (n:${l}) REQUIRE n.id IS UNIQUE`);

  const vpcs = rows("select vpc_id, region, account_id, cidr_block, is_default, ipv6_blocks from inventory_vpc");
  // Member accounts (src/accounts.ts): every node carries the account its VPC lives in (the inventories stamp VPCs, subnets and
  // groups from Steampipe's own column; route tables, interfaces, addresses and ACLs follow their VPC, an address its interface or box).
  const vpcAccountMap = new Map(vpcs.map((v) => [String(v.vpc_id), v.account_id ? String(v.account_id) : null]));
  const vpcAccount = (vpcId: string | null | undefined): string | null => (vpcId ? vpcAccountMap.get(vpcId) ?? null : null);
  const instanceAccountMap = new Map(rows("select instance_id, account_id from inventory_ec2 where account_id is not null and account_id <> ''").map((r) => [String(r.instance_id), String(r.account_id)]));
  const subnets = listSubnets(); const tables = listRouteTables(); const gateways = listGateways(); const enis = listEnis(); const eips = listEips();
  const nacls = rows("select acl_id, vpc_id, region, is_default, subnets, entries from nacls").map((n) => ({ ...n, subnets: safeJson(n.subnets) || [], entries: (safeJson(n.entries) || []) as NaclEntry[] }));
  const sgs = rows("select group_id, group_name, description, vpc_id, region, account_id from inventory_sg");
  const sgAccount = new Map(sgs.map((g) => [String(g.group_id), g.account_id ? String(g.account_id) : vpcAccount(str(g.vpc_id))]));
  const ingress = rows("select group_id, ip_protocol, from_port, to_port, cidr_ipv4, cidr_ipv6, referenced_group_id, prefix_list_id, rule_id, description from sg_ingress") as IngressRule[];
  const egress = allEgressRules();

  // networks
  const subnetsByVpc = new Map<string, string[]>();
  for (const s of subnets) if (s.vpc_id) subnetsByVpc.set(s.vpc_id, [...(subnetsByVpc.get(s.vpc_id) || []), s.subnet_id]);
  const vpcRows = vpcs.map((v) => ({ id: String(v.vpc_id), account_id: v.account_id ? String(v.account_id) : null, cidr_blocks: v.cidr_block ? [String(v.cidr_block)] : [], ipv6_blocks: Number(v.ipv6_blocks || 0), default: Boolean(v.is_default), name: null, region: str(v.region) }));
  for (const b of chunks(vpcRows)) await w(NETWORK_CYPHER, b);

  // segments: public from the route table, guarded by the subnet's ACL (or the VPC's default)
  const naclFor = (subnetId: string, vpcId: string | null) => nacls.find((n) => (n.subnets as string[]).includes(subnetId))?.acl_id ?? nacls.find((n) => n.is_default && n.vpc_id === vpcId)?.acl_id ?? null;
  const segRows = subnets.map((s: SubnetRow) => { const t = routeTableOf(s.subnet_id, s.vpc_id, tables); return { id: s.subnet_id, account_id: s.account_id ?? vpcAccount(s.vpc_id), vpc_id: s.vpc_id, cidr: s.cidr_block, ipv6_cidr: s.ipv6_cidrs[0] ?? null, zone: s.az, public: isPublicSubnet(t), auto_public_ip: s.map_public_ip, available_ips: s.available_ips, default: s.default_for_az, name: s.name, region: s.region, route_table_id: t?.route_table_id ?? null, nacl_id: naclFor(s.subnet_id, s.vpc_id) }; });
  for (const b of chunks(segRows)) await w(SEGMENT_CYPHER, b);

  // gateways (known ones), then route tables whose routes may name gateways the inventory does not list (transit, VPN): those are created bare
  const gwRows = gateways.map((g: GatewayRow) => ({ id: g.gateway_id, account_id: (g as any).account_id ? String((g as any).account_id) : vpcAccount(g.vpc_id), kind: g.kind, state: g.state, public_ip: g.public_ips[0] ?? null, public_ips: g.public_ips, private_ip: g.private_ip, service: g.service, endpoint_type: g.endpoint_type, peer_vpc_id: g.peer_vpc_id, peer_account_id: g.peer_account_id, cidrs: g.cidrs, peer_cidrs: g.peer_cidrs, groups: g.groups, name: g.name, region: g.region, vpc_id: g.vpc_id, subnet_id: g.subnet_id, native_type: g.kind === "internet" ? "internet_gateway" : g.kind === "nat" ? "nat_gateway" : g.kind === "egress_only" ? "egress_only_internet_gateway" : g.kind === "peering" ? "vpc_peering_connection" : "vpc_endpoint" }));
  for (const b of chunks(gwRows)) await w(GATEWAY_CYPHER, b);
  const GW_KIND: Record<string, string> = { internet_gateway: "internet", nat_gateway: "nat", egress_only_gateway: "egress_only", transit_gateway: "transit", peering: "peering", vpc_endpoint: "endpoint", virtual_private_gateway: "vpn", local_gateway: "local_gateway", carrier_gateway: "carrier" };
  const rtRows = tables.map((t: RouteTableRow) => ({ id: t.route_table_id, account_id: vpcAccount(t.vpc_id), vpc_id: t.vpc_id, main: t.main, name: t.name, region: t.region, route_count: t.routes.length,
    routes: t.routes.map((r) => { const x = routeTarget(r); return { ...x, label: x.kind === "interface" ? "AdvisorInterface" : x.kind === "instance" ? "AdvisorResource" : x.kind === "local" || x.kind === "unknown" || !x.id ? null : "AdvisorGateway", kind: GW_KIND[x.kind] ?? x.kind, state: r.State ?? "active", origin: r.Origin ?? null }; }).filter((r) => r.label && r.destination) }));
  for (const b of chunks(rtRows)) await w(ROUTE_TABLE_CYPHER, b);

  // interfaces: whose they are, where they sit, what they wear
  const lbByName = new Map(rows("select arn, name from inventory_elb").map((r) => [String(r.name), String(r.arn)]));
  const fnByName = new Map(rows("select name, arn, region from inventory_lambda").map((r) => [String(r.name), r.arn ? String(r.arn) : `arn:aws:lambda:${r.region}:${account}:function:${r.name}`]));
  const eniRows = enis.map((e: EniRow) => { const o = eniOwner(e); const resource = o.kind === "instance" ? o.name : o.kind === "load_balancer" && o.name ? lbByName.get(o.name) ?? null : o.kind === "function" && o.name ? fnByName.get(o.name) ?? null : null; const gateway = (o.kind === "nat_gateway" || o.kind === "vpc_endpoint") ? o.name : null;
    return { id: e.eni_id, account_id: vpcAccount(e.vpc_id) ?? (e.instance_id ? instanceAccountMap.get(e.instance_id) ?? null : null), vpc_id: e.vpc_id, subnet_id: e.subnet_id, region: e.region, private_ips: e.private_ips, public_ip: e.public_ip, ipv6: e.ipv6, mac: e.mac, interface_type: e.interface_type, owner_kind: o.kind, description: e.description, status: e.status, source_dest_check: e.source_dest_check, primary: e.interface_type === "interface" && Boolean(e.instance_id), groups: e.groups, resource_id: resource, gateway_id: gateway }; });
  for (const b of chunks(eniRows)) await w(INTERFACE_CYPHER, b);

  // public addresses: EIPs on interfaces, NAT addresses on gateways
  const natByIp = new Map<string, string>(); for (const g of gateways) for (const ip of g.public_ips) natByIp.set(ip, g.gateway_id);
  const eniAccount = new Map(enis.map((e: EniRow) => [e.eni_id, vpcAccount(e.vpc_id)]));
  const ipRows = eips.map((e) => ({ id: e.id, account_id: (e.network_interface_id ? eniAccount.get(e.network_interface_id) : null) ?? (e.instance_id ? instanceAccountMap.get(e.instance_id) : null) ?? null, ip: e.public_ip, allocation_id: e.allocation_id, associated: Boolean(e.network_interface_id || e.instance_id), eni_id: e.network_interface_id, gateway_id: natByIp.get(e.public_ip) ?? null, region: e.region }));
  for (const b of chunks(ipRows)) await w(PUBLIC_IP_CYPHER, b);

  // filters: security groups and ACLs, with their rules
  const wearers = new Map<string, number>(); for (const e of enis) for (const g of e.groups) wearers.set(g, (wearers.get(g) || 0) + 1);
  const ruleCount = new Map<string, number>(); for (const r of [...ingress, ...egress]) ruleCount.set(r.group_id, (ruleCount.get(r.group_id) || 0) + 1);
  const filterRows = [
    ...sgs.map((g) => ({ id: String(g.group_id), account_id: sgAccount.get(String(g.group_id)) ?? null, kind: "security_group", stateful: true, default: g.group_name === "default", name: str(g.group_name), description: str(g.description), rules: ruleCount.get(String(g.group_id)) || 0, attached: wearers.get(String(g.group_id)) || 0, region: str(g.region), vpc_id: str(g.vpc_id), native_type: "security_group" })),
    ...nacls.map((n) => ({ id: String(n.acl_id), account_id: vpcAccount(str(n.vpc_id)), kind: "network_acl", stateful: false, default: Boolean(n.is_default), name: null, description: null, rules: n.entries.length, attached: (n.subnets as string[]).length, region: str(n.region), vpc_id: str(n.vpc_id), native_type: "network_acl" })),
  ];
  for (const b of chunks(filterRows)) await w(FILTER_CYPHER, b);
  const vpcOfGroup = new Map(sgs.map((g) => [String(g.group_id), str(g.vpc_id)]));
  const ruleRows = [
    ...ingress.map((r) => sgRuleNode(r, "ingress", vpcHasIpv6(vpcOfGroup.get(r.group_id)))),
    ...egress.map((r) => sgRuleNode(r, "egress", vpcHasIpv6(vpcOfGroup.get(r.group_id)))),
    ...nacls.flatMap((n) => (n.entries as NaclEntry[]).filter((e) => e.RuleNumber !== 32767).map((e) => naclRuleNode(String(n.acl_id), e))),
  ].map((r) => ({ ...r, account_id: r.priority == null ? sgAccount.get(r.filter_id) ?? null : vpcAccount(str(nacls.find((n) => String(n.acl_id) === r.filter_id)?.vpc_id)), native_type: r.priority == null ? "security_group_rule" : "network_acl_entry", source_label: r.source_node?.label ?? null, source_id: r.source_node?.id ?? null }));
  for (const b of chunks(ruleRows)) await w(RULE_CYPHER, b);

  // resources that wear groups directly: databases, caches, balancers; compute joins through its interfaces but also gets the direct edge for one-hop reads
  const guarded: { id: string; groups: string[]; vpc_id: string | null; subnet_id: string | null }[] = [];
  for (const r of rows("select instance_id, snapshot from inventory_ec2 where gone = 0")) { const net = (safeJson(r.snapshot) || {}).network || {}; guarded.push({ id: String(r.instance_id), groups: (Array.isArray(net.security_groups) ? net.security_groups : []).map((g: any) => String(g?.GroupId ?? g?.group_id ?? g)).filter((g: string) => /^sg-/.test(g)), vpc_id: str(net.vpc_id), subnet_id: str(net.subnet_id) }); }
  for (const r of rows("select db_instance_identifier as id, snapshot from inventory_rds where gone = 0")) { const net = (safeJson(r.snapshot) || {}).network || {}; guarded.push({ id: String(r.id), groups: Array.isArray(net.security_groups) ? net.security_groups.map(String) : [], vpc_id: str(net.vpc_id), subnet_id: null }); }
  for (const r of rows("select cache_cluster_id as id, snapshot from inventory_elasticache where gone = 0")) { const net = (safeJson(r.snapshot) || {}).network || {}; guarded.push({ id: String(r.id), groups: Array.isArray(net.security_groups) ? net.security_groups.map(String) : [], vpc_id: null, subnet_id: null }); }
  for (const r of rows("select arn as id, security_groups, vpc_id from inventory_elb where gone = 0")) guarded.push({ id: String(r.id), groups: (safeJson(r.security_groups) || []).map(String), vpc_id: str(r.vpc_id), subnet_id: null });
  for (const b of chunks(guarded)) await w(GUARDED_CYPHER, b);

  const judged = await mirrorReachability();
  return { networks: vpcRows.length, segments: segRows.length, route_tables: rtRows.length, gateways: gwRows.length, interfaces: eniRows.length, public_ips: ipRows.length, filters: filterRows.length, rules: ruleRows.length, endpoints_judged: judged.endpoints, took_ms: Date.now() - t0 };
}

/**
 * The verdict edges of every endpoint (or those of the given instances): instance ports with the box's groups, public
 * address and subnet ACL; balancer listeners with the balancer's groups (a balancer without groups admits what its
 * scheme allows); database endpoints with the database's groups and its publicly-accessible flag.
 */
export async function mirrorReachability(instanceIds?: string[]): Promise<{ endpoints: number }> {
  if (!enabled()) return { endpoints: 0 };
  if (instanceIds && !instanceIds.length) return { endpoints: 0 };
  const { reachContextOf, securityGroupsOf } = await import("./instance_apps.js");
  const account = accountId();
  const stamp = now();
  const out: any[] = [];
  const judge = (id: string, l: Listener, rules: IngressRule[], ctx: ReachContext, groups: string[]) => {
    const v = verdictEdges(l, rules, ctx, groups);
    out.push({ id, protocol: l.proto, port: l.port, exposure: v.exposure, reason: v.reason, reachable_from: v.reachable_from, allowed_by: v.allowed_by, blocked_by: v.blocked_by });
  };
  // instance ports
  const ports = instanceIds ? rows(`select instance_id, proto, port, bind, scope from instance_ports where gone = 0 and instance_id in (${instanceIds.map(() => "?").join(",")})`, ...instanceIds) : rows("select instance_id, proto, port, bind, scope from instance_ports where gone = 0");
  const byInstance = new Map<string, any[]>(); for (const p of ports) byInstance.set(String(p.instance_id), [...(byInstance.get(String(p.instance_id)) || []), p]);
  for (const [instanceId, list] of byInstance) {
    const groups = securityGroupsOf(instanceId); const rules = ingressRulesFor(groups); const ctx = reachContextOf(instanceId);
    for (const p of list) judge(`${instanceId}:${p.proto}:${p.port}`, { proto: p.proto === "udp" ? "udp" : "tcp", port: Number(p.port), scope: p.scope, bind: String(p.bind || "") }, rules, ctx, groups);
  }
  // ports a balancer forwards to: judged like probed ports, with the instance's groups, so a target port has a verdict even before a probe saw it listening
  const judgedPorts = new Set(out.map((r) => r.id));
  for (const lb of rows("select target_groups from inventory_elb where gone = 0")) {
    for (const g of (safeJson(lb.target_groups) || []) as any[]) for (const t of g?.targets || []) {
      if (!t?.instance_id || (instanceIds && !instanceIds.includes(String(t.instance_id)))) continue;
      const port = Number(t.port ?? g.port ?? 0); const id = `${t.instance_id}:tcp:${port}`;
      if (!port || judgedPorts.has(id)) continue;
      judgedPorts.add(id);
      const groups = securityGroupsOf(String(t.instance_id));
      judge(id, { proto: "tcp", port, scope: "all", bind: "" }, ingressRulesFor(groups), reachContextOf(String(t.instance_id)), groups);
    }
  }
  if (!instanceIds) {
    // balancer listeners
    for (const lb of rows("select arn, scheme, listeners, security_groups from inventory_elb where gone = 0")) {
      const groups: string[] = (safeJson(lb.security_groups) || []).map(String); const rules = ingressRulesFor(groups);
      const pub = lb.scheme === "internet-facing";
      for (const l of (safeJson(lb.listeners) || []) as any[]) {
        if (l?.port == null) continue;
        const id = `${lb.arn}:listener:${String(l.protocol || "tcp").toLowerCase()}:${l.port}`;
        if (!groups.length) { out.push({ id, protocol: "tcp", port: Number(l.port), exposure: pub ? "internet" : "network", reason: pub ? "an internet-facing balancer with no security groups: open to the internet" : "an internal balancer with no security groups: reachable from inside its network", reachable_from: [{ label: "AdvisorSource", id: pub ? "internet" : `cidr:${vpcCidrOf(lb.arn) ?? "0.0.0.0/8"}`, via_rule: null, through: [], note: "no security groups on this balancer", source_meta: pub ? sourceOf("0.0.0.0/0") : sourceOf(vpcCidrOf(lb.arn) ?? "0.0.0.0/8") }], allowed_by: [], blocked_by: [] }); continue; }
        judge(id, { proto: "tcp", port: Number(l.port), scope: "all", bind: "" }, rules, { public_ip: pub ? "public" : null, ipv6: [], nacl: null, group_names: {} }, groups);
      }
    }
    // database endpoints
    for (const d of rows("select db_instance_identifier as id, snapshot from inventory_rds where gone = 0")) {
      const net = (safeJson(d.snapshot) || {}).network || {};
      if (!net.endpoint) continue;
      const groups: string[] = Array.isArray(net.security_groups) ? net.security_groups.map(String) : []; const rules = ingressRulesFor(groups);
      judge(`${d.id}:tcp:${Number(net.port) || 0}`, { proto: "tcp", port: Number(net.port) || 0, scope: "all", bind: "" }, rules, { public_ip: net.publicly_accessible ? "public" : null, ipv6: [], nacl: null, group_names: {} }, groups);
    }
  }
  for (const b of chunks(out.map((r) => r.id), 500)) await writeCypher(VERDICT_CLEAR_CYPHER, { ids: b });
  for (const b of chunks(out, 100)) await writeCypher(VERDICT_CYPHER, { rows: b, account, provider: PROVIDER, now: stamp });
  return { endpoints: out.length };
}

const vpcCidrOf = (lbArn: string): string | null => { const lb = rows("select vpc_id from inventory_elb where arn = ?", lbArn)[0]; const v = lb?.vpc_id ? rows("select cidr_block from inventory_vpc where vpc_id = ?", lb.vpc_id)[0] : null; return v?.cidr_block ? String(v.cidr_block) : null; };

// ---- reading it back (the Network page, src/routes/graph.ts) ------------------------------------------------------------------

import { readQuery } from "./graph_mirror.js";

/** The network layer at a glance: every network with what sits in it, the exposed endpoints, the filters, the blocks. */
export async function networkOverview(account: string = accountId()) {
  const networks = await readQuery(`MATCH (n:AdvisorNetwork {account_id: $account})
    OPTIONAL MATCH (s:AdvisorSegment)-[:IN_NETWORK]->(n)
    WITH n, count(s) AS segments, sum(CASE WHEN s.public THEN 1 ELSE 0 END) AS public_segments
    OPTIONAL MATCH (g:AdvisorGateway)-[:IN_NETWORK]->(n)
    WITH n, segments, public_segments, collect(DISTINCT g.kind) AS gateway_kinds, count(DISTINCT g) AS gateways
    OPTIONAL MATCH (f:AdvisorFilter)-[:IN_NETWORK]->(n)
    WITH n, segments, public_segments, gateway_kinds, gateways, count(DISTINCT f) AS filters
    OPTIONAL MATCH (r:AdvisorResource)-[:IN_NETWORK]->(n) WHERE coalesce(r.gone, false) = false
    WITH n, segments, public_segments, gateway_kinds, gateways, filters, count(DISTINCT r) AS resources
    OPTIONAL MATCH (n)-[p:PEERS_WITH]->(peer:AdvisorNetwork)
    WITH n, segments, public_segments, gateway_kinds, gateways, filters, resources, collect(DISTINCT peer.id) AS peers
    OPTIONAL MATCH (r2:AdvisorResource)-[:IN_NETWORK]->(n), (r2)-[:EXPOSES]->(e:AdvisorEndpoint)-[:REACHABLE_FROM]->(:AdvisorSource {id: 'internet'})
    WHERE coalesce(e.gone, false) = false
    RETURN n.id AS id, n.name AS name, n.region AS region, n.cidr_blocks AS cidr_blocks, n.ipv6_blocks AS ipv6_blocks, n.default AS is_default, segments, public_segments, gateway_kinds, gateways, filters, resources, peers, count(DISTINCT e) AS internet_endpoints
    ORDER BY resources DESC, n.id`, { account }, { rowCap: 200, timeoutMs: 30_000 });
  const exposed = await readQuery(`MATCH (r:AdvisorResource)-[:EXPOSES]->(e:AdvisorEndpoint)-[v:REACHABLE_FROM]->(:AdvisorSource {id: 'internet'})
    WHERE e.account_id = $account AND coalesce(e.gone, false) = false
    OPTIONAL MATCH (a:AdvisorApp)-[:SERVES]->(e)
    OPTIONAL MATCH (e)-[:ALLOWED_BY]->(rule:AdvisorFilterRule)<-[:HAS_RULE]-(f:AdvisorFilter)
    RETURN r.id AS resource_id, r.name AS resource_name, [l IN labels(r) WHERE l <> 'AdvisorResource'][0] AS resource_label, e.id AS endpoint_id, e.kind AS kind, e.protocol AS protocol, e.port AS port, e.hostname AS hostname,
      coalesce(a.name, e.process) AS program, e.container AS container, v.note AS note, e.reach_reason AS reason,
      collect(DISTINCT CASE WHEN rule IS NULL THEN null ELSE {rule: rule.id, filter: f.id, filter_name: f.name, description: rule.description, ports: CASE WHEN rule.from_port IS NULL THEN 'all' WHEN rule.from_port = rule.to_port THEN toString(rule.from_port) ELSE toString(rule.from_port) + '-' + toString(rule.to_port) END} END) AS rules
    ORDER BY e.port, r.name`, { account }, { rowCap: 3000, timeoutMs: 30_000 });
  const blocked = await readQuery(`MATCH (r:AdvisorResource)-[:EXPOSES]->(e:AdvisorEndpoint)-[b:BLOCKED_BY]->(x)
    WHERE e.account_id = $account AND coalesce(e.gone, false) = false
    OPTIONAL MATCH (a:AdvisorApp)-[:SERVES]->(e)
    RETURN r.id AS resource_id, r.name AS resource_name, e.id AS endpoint_id, e.protocol AS protocol, e.port AS port, coalesce(a.name, e.process) AS program, e.exposure AS exposure, b.source AS source, b.reason AS reason, labels(x)[0] AS by_label, x.id AS by_id, x.name AS by_name
    ORDER BY e.port, r.name`, { account }, { rowCap: 3000, timeoutMs: 30_000 });
  const filters = await readQuery(`MATCH (f:AdvisorFilter {account_id: $account})
    OPTIONAL MATCH (f)-[:HAS_RULE]->(rule:AdvisorFilterRule)-[:FROM]->(src:AdvisorSource {id: 'internet'}) WHERE rule.direction = 'ingress'
    WITH f, count(rule) AS internet_rules, collect(DISTINCT CASE WHEN rule.from_port IS NULL THEN 'all' WHEN rule.from_port = rule.to_port THEN toString(rule.from_port) ELSE toString(rule.from_port) + '-' + toString(rule.to_port) END)[..8] AS internet_ports
    OPTIONAL MATCH (f)<-[:GUARDED_BY]-(r:AdvisorResource) WHERE coalesce(r.gone, false) = false
    WITH f, internet_rules, internet_ports, count(DISTINCT r) AS guarded
    OPTIONAL MATCH (f)<-[:WEARS]-(i:AdvisorInterface)
    WITH f, internet_rules, internet_ports, guarded, count(DISTINCT i) AS interfaces
    OPTIONAL MATCH (f)-[:IN_NETWORK]->(n:AdvisorNetwork)
    RETURN f.id AS id, f.kind AS kind, f.name AS name, f.description AS description, f.rules AS rules, f.default AS is_default, n.id AS network, internet_rules, internet_ports, guarded, interfaces
    ORDER BY internet_rules DESC, guarded DESC, f.kind, f.name`, { account }, { rowCap: 1000, timeoutMs: 30_000 });
  const totals = await readQuery(`MATCH (e:AdvisorEndpoint {account_id: $account}) WHERE coalesce(e.gone, false) = false
    RETURN e.exposure AS exposure, count(*) AS n`, { account }, { rowCap: 20 });
  const gateways = await readQuery(`MATCH (g:AdvisorGateway {account_id: $account}) RETURN g.kind AS kind, count(*) AS n ORDER BY n DESC`, { account }, { rowCap: 20 });
  return { account_id: account, networks: networks.rows, exposed: exposed.rows.map((r) => ({ ...r, rules: (r.rules as any[]).filter(Boolean) })), blocked: blocked.rows, filters: filters.rows,
    exposure_totals: Object.fromEntries(totals.rows.map((r) => [String(r.exposure ?? "unjudged"), Number(r.n)])), gateway_totals: Object.fromEntries(gateways.rows.map((r) => [String(r.kind), Number(r.n)])) };
}

/** One network: its segments with routing and ACL, its gateways and peers, its interfaces by owner, its filters. */
export async function networkDetail(id: string, account: string = accountId()) {
  const net = await readQuery(`MATCH (n:AdvisorNetwork {id: $id}) RETURN properties(n) AS network`, { id }, { rowCap: 1 });
  if (!net.rows[0]) return null;
  const segments = await readQuery(`MATCH (s:AdvisorSegment)-[:IN_NETWORK]->(:AdvisorNetwork {id: $id})
    OPTIONAL MATCH (s)-[:USES_ROUTE_TABLE]->(t:AdvisorRouteTable)
    OPTIONAL MATCH (t)-[r:ROUTES]->(g:AdvisorGateway)
    WITH s, t, collect(DISTINCT CASE WHEN g IS NULL THEN null ELSE {destination: r.destination, kind: g.kind, id: g.id} END) AS routes
    OPTIONAL MATCH (s)-[:GUARDED_BY]->(acl:AdvisorFilter {kind: 'network_acl'})
    OPTIONAL MATCH (i:AdvisorInterface)-[:IN_SEGMENT]->(s)
    WITH s, t, routes, acl, count(DISTINCT i) AS interfaces
    OPTIONAL MATCH (c:AdvisorCompute)-[:IN_SEGMENT]->(s) WHERE coalesce(c.gone, false) = false
    RETURN s.id AS id, s.name AS name, s.cidr AS cidr, s.ipv6_cidr AS ipv6_cidr, s.zone AS zone, s.public AS is_public, s.auto_public_ip AS auto_public_ip, s.available_ips AS available_ips, t.id AS route_table, t.main AS main_table, routes, acl.id AS acl, acl.default AS acl_default, interfaces, count(DISTINCT c) AS instances
    ORDER BY s.public DESC, s.zone, s.cidr`, { id }, { rowCap: 500, timeoutMs: 30_000 });
  const gateways = await readQuery(`MATCH (g:AdvisorGateway)-[:IN_NETWORK]->(:AdvisorNetwork {id: $id})
    OPTIONAL MATCH (p:AdvisorPublicIp)-[:ASSIGNED]->(g)
    RETURN g.id AS id, g.kind AS kind, g.state AS state, g.name AS name, g.service AS service, g.endpoint_type AS endpoint_type, g.peer_network_id AS peer_network_id, coalesce(g.public_ip, p.ip) AS public_ip
    ORDER BY g.kind, g.id`, { id }, { rowCap: 200 });
  const peers = await readQuery(`MATCH (:AdvisorNetwork {id: $id})-[p:PEERS_WITH]->(b:AdvisorNetwork) RETURN b.id AS id, b.account_id AS account_id, b.foreign AS foreign, p.state AS state, p.cidrs AS cidrs, p.via AS via`, { id }, { rowCap: 50 });
  const interfaces = await readQuery(`MATCH (i:AdvisorInterface)-[:IN_NETWORK]->(:AdvisorNetwork {id: $id})
    OPTIONAL MATCH (i)-[:ATTACHED_TO]->(x)
    RETURN i.owner_kind AS owner, count(*) AS n, count(x) AS attached, sum(CASE WHEN i.public_ip IS NULL THEN 0 ELSE 1 END) AS with_public_ip
    ORDER BY n DESC`, { id }, { rowCap: 20 });
  const filters = await readQuery(`MATCH (f:AdvisorFilter)-[:IN_NETWORK]->(:AdvisorNetwork {id: $id})
    OPTIONAL MATCH (f)<-[:GUARDED_BY]-(r:AdvisorResource) WHERE coalesce(r.gone, false) = false
    RETURN f.id AS id, f.kind AS kind, f.name AS name, f.rules AS rules, f.default AS is_default, count(DISTINCT r) AS guarded ORDER BY f.kind, guarded DESC, f.name`, { id }, { rowCap: 500 });
  return { network: net.rows[0].network, segments: segments.rows.map((s) => ({ ...s, routes: (s.routes as any[]).filter(Boolean) })), gateways: gateways.rows, peers: peers.rows, interfaces: interfaces.rows, filters: filters.rows };
}

/** One filter with its rules, where each lets traffic in from, what wears it and what each rule opens that listens. */
export async function filterDetail(id: string) {
  const f = await readQuery(`MATCH (f:AdvisorFilter {id: $id}) OPTIONAL MATCH (f)-[:IN_NETWORK]->(n:AdvisorNetwork) RETURN properties(f) AS filter, n.id AS network`, { id }, { rowCap: 1 });
  if (!f.rows[0]) return null;
  const rules = await readQuery(`MATCH (:AdvisorFilter {id: $id})-[:HAS_RULE]->(r:AdvisorFilterRule)
    OPTIONAL MATCH (r)-[:FROM]->(src)
    OPTIONAL MATCH (e:AdvisorEndpoint)-[:ALLOWED_BY]->(r) WHERE coalesce(e.gone, false) = false
    RETURN r.id AS id, r.direction AS direction, r.action AS action, r.protocol AS protocol, r.from_port AS from_port, r.to_port AS to_port, r.priority AS priority, r.source_kind AS source_kind, r.source AS source, r.description AS description, r.dormant AS dormant,
      CASE WHEN src:AdvisorFilter THEN 'AdvisorFilter' WHEN src IS NULL THEN null ELSE 'AdvisorSource' END AS source_label, src.id AS source_id, coalesce(src.label, src.name, src.id) AS source_name, count(DISTINCT e) AS endpoints_let_in
    ORDER BY r.direction, coalesce(r.priority, 0), r.from_port`, { id }, { rowCap: 500 });
  const wearers = await readQuery(`MATCH (f:AdvisorFilter {id: $id})
    OPTIONAL MATCH (r:AdvisorResource)-[:GUARDED_BY]->(f) WHERE coalesce(r.gone, false) = false
    WITH f, collect(DISTINCT {id: r.id, name: r.name, label: [l IN labels(r) WHERE l <> 'AdvisorResource'][0]}) AS resources
    OPTIONAL MATCH (s:AdvisorSegment)-[:GUARDED_BY]->(f)
    RETURN resources, collect(DISTINCT {id: s.id, name: s.name, cidr: s.cidr}) AS segments`, { id }, { rowCap: 1 });
  const w = wearers.rows[0] || { resources: [], segments: [] };
  return { ...f.rows[0], rules: rules.rows, resources: (w.resources as any[]).filter((x) => x?.id), segments: (w.segments as any[]).filter((x) => x?.id) };
}

/** Every segment across the account's networks, with routing, ACL and what sits in it (the Segments tab). */
export async function listSegments(account: string = accountId()) {
  const r = await readQuery(`MATCH (s:AdvisorSegment {account_id: $account})
    OPTIONAL MATCH (s)-[:IN_NETWORK]->(n:AdvisorNetwork)
    OPTIONAL MATCH (s)-[:USES_ROUTE_TABLE]->(t:AdvisorRouteTable)
    OPTIONAL MATCH (t)-[r:ROUTES]->(g:AdvisorGateway)
    WITH s, n, t, collect(DISTINCT CASE WHEN g IS NULL THEN null ELSE {destination: r.destination, kind: g.kind, id: g.id} END) AS routes
    OPTIONAL MATCH (s)-[:GUARDED_BY]->(acl:AdvisorFilter {kind: 'network_acl'})
    OPTIONAL MATCH (i:AdvisorInterface)-[:IN_SEGMENT]->(s)
    WITH s, n, t, routes, acl, count(DISTINCT i) AS interfaces
    OPTIONAL MATCH (c:AdvisorCompute)-[:IN_SEGMENT]->(s) WHERE coalesce(c.gone, false) = false
    RETURN s.id AS id, s.name AS name, n.id AS network, s.cidr AS cidr, s.ipv6_cidr AS ipv6_cidr, s.zone AS zone, s.region AS region, s.public AS is_public, s.auto_public_ip AS auto_public_ip, s.available_ips AS available_ips, s.default AS is_default,
      t.id AS route_table, t.main AS main_table, routes, acl.id AS acl, acl.default AS acl_default, interfaces, count(DISTINCT c) AS instances
    ORDER BY s.public DESC, n.id, s.zone, s.cidr`, { account }, { rowCap: 2000, timeoutMs: 30_000 });
  return r.rows.map((s) => ({ ...s, routes: (s.routes as any[]).filter(Boolean) }));
}

/** Every gateway node: internet, NAT, egress-only, peering, endpoint, and the bare transit or VPN ones routes name (the Gateways tab). */
export async function listGatewayNodes(account: string = accountId()) {
  const r = await readQuery(`MATCH (g:AdvisorGateway {account_id: $account})
    OPTIONAL MATCH (g)-[:IN_NETWORK]->(n:AdvisorNetwork)
    OPTIONAL MATCH (g)-[:IN_SEGMENT]->(s:AdvisorSegment)
    OPTIONAL MATCH (p:AdvisorPublicIp)-[:ASSIGNED]->(g)
    OPTIONAL MATCH (t:AdvisorRouteTable)-[r:ROUTES]->(g)
    WITH g, n, s, collect(DISTINCT p.ip) AS eips, count(DISTINCT t) AS route_tables, collect(DISTINCT r.destination)[..6] AS destinations
    OPTIONAL MATCH (g)-[:MEMBER_OF]->(sys:KnSystem)
    OPTIONAL MATCH (sys)-[tr:TRANSFERS_TO]->(:KnDestination {id: 'internet'})
    RETURN g.id AS id, g.kind AS kind, g.name AS name, g.state AS state, n.id AS network, s.id AS segment, g.region AS region, coalesce(g.public_ip, eips[0]) AS public_ip, g.private_ip AS private_ip,
      g.service AS service, g.endpoint_type AS endpoint_type, g.peer_network_id AS peer_network_id, g.peer_account_id AS peer_account_id, route_tables, destinations, tr.gb_day AS gb_day, tr.usd_month AS usd_month
    ORDER BY g.kind, n.id, g.id`, { account }, { rowCap: 1000, timeoutMs: 30_000 });
  return r.rows;
}

/** Every network interface with whose it is, where it sits and what it wears (the Interfaces tab). */
export async function listInterfaces(account: string = accountId()) {
  const r = await readQuery(`MATCH (i:AdvisorInterface {account_id: $account})
    OPTIONAL MATCH (i)-[:ATTACHED_TO]->(x)
    OPTIONAL MATCH (i)-[:IN_SEGMENT]->(s:AdvisorSegment)
    OPTIONAL MATCH (i)-[:IN_NETWORK]->(n:AdvisorNetwork)
    OPTIONAL MATCH (i)-[:WEARS]->(f:AdvisorFilter)
    OPTIONAL MATCH (p:AdvisorPublicIp)-[:ASSIGNED]->(i)
    RETURN i.id AS id, i.owner_kind AS owner_kind, i.interface_type AS interface_type, i.description AS description, i.status AS status, i.private_ips AS private_ips, coalesce(i.public_ip, p.ip) AS public_ip, p.id AS eip, i.ipv6 AS ipv6, i.source_dest_check AS source_dest_check,
      x.id AS attached_id, x.name AS attached_name, CASE WHEN x IS NULL THEN null WHEN x:AdvisorGateway THEN 'AdvisorGateway' ELSE [l IN labels(x) WHERE l <> 'AdvisorResource'][0] END AS attached_label,
      s.id AS segment, s.public AS segment_public, n.id AS network, i.region AS region, collect(DISTINCT {id: f.id, name: f.name}) AS filters
    ORDER BY i.owner_kind, n.id, i.id`, { account }, { rowCap: 3000, timeoutMs: 30_000 });
  return r.rows.map((i) => ({ ...i, filters: (i.filters as any[]).filter((f) => f?.id) }));
}

/** Every static public address and what it is assigned to (the Public IPs tab). */
export async function listPublicIps(account: string = accountId()) {
  const r = await readQuery(`MATCH (p:AdvisorPublicIp {account_id: $account})
    OPTIONAL MATCH (p)-[:ASSIGNED]->(x)
    OPTIONAL MATCH (x)-[:ATTACHED_TO]->(owner)
    OPTIONAL MATCH (d:AdvisorDnsRecord)-[:POINTS_TO]->(y) WHERE y.id = x.id OR y.id = owner.id OR (y:AdvisorResourceRef AND y.id = p.ip)
    RETURN p.id AS id, p.ip AS ip, p.associated AS associated, p.region AS region,
      x.id AS assigned_id, CASE WHEN x IS NULL THEN null WHEN x:AdvisorGateway THEN 'gateway' WHEN x:AdvisorInterface THEN 'interface' ELSE 'balancer' END AS assigned_kind, x.owner_kind AS interface_owner,
      owner.id AS owner_id, owner.name AS owner_name, CASE WHEN owner IS NULL THEN null WHEN owner:AdvisorGateway THEN 'AdvisorGateway' ELSE [l IN labels(owner) WHERE l <> 'AdvisorResource'][0] END AS owner_label,
      collect(DISTINCT d.fqdn)[..4] AS domains
    ORDER BY p.associated, owner.name, p.ip`, { account }, { rowCap: 2000, timeoutMs: 30_000 });
  return r.rows;
}

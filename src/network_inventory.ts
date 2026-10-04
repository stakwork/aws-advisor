import { db } from "./db.js";
import { S } from "./steampipe.js";
import type { IngressRule } from "./instance_apps.js";

/**
 * The network objects behind reachability (docs/cloud-ontology.md §3): subnets, route tables, gateways (internet,
 * NAT, egress-only, peering, VPC endpoints), Elastic IPs, every network interface with its addresses and groups, and
 * the security groups' egress rules. Read from Steampipe on every inventory refresh (src/inventory.ts) next to the
 * security groups, VPCs and network ACLs that were already read, replaced wholesale each time. The graph
 * (src/graph_network.ts) draws the network layer from these tables and the ingress rules in `sg_ingress`.
 *
 * Nothing here judges anything; the pure helpers at the bottom (which subnet is public, what a route points at, whose
 * interface an ENI is) are what the graph and the tests use.
 */

db.exec(`create table if not exists inventory_subnet (
  subnet_id text primary key, vpc_id text, region text, account_id text, cidr_block text, ipv6_cidrs text not null default '[]', az text,
  available_ips integer, map_public_ip integer not null default 0, default_for_az integer not null default 0, name text, refreshed_at text not null
);
create table if not exists inventory_route_table (
  route_table_id text primary key, vpc_id text, region text, main integer not null default 0, subnets text not null default '[]', routes text not null default '[]', name text, refreshed_at text not null
);
create table if not exists inventory_gateway (
  gateway_id text primary key, kind text not null, vpc_id text, region text, state text, public_ips text not null default '[]', private_ip text, subnet_id text,
  service text, endpoint_type text, peer_vpc_id text, peer_account_id text, cidrs text not null default '[]', peer_cidrs text not null default '[]', route_table_ids text not null default '[]', subnet_ids text not null default '[]', groups text not null default '[]', name text, refreshed_at text not null
);
create table if not exists inventory_eip (
  id text primary key, allocation_id text, public_ip text not null, instance_id text, network_interface_id text, private_ip text, region text, refreshed_at text not null
);
create table if not exists inventory_eni (
  eni_id text primary key, vpc_id text, subnet_id text, region text, private_ips text not null default '[]', public_ip text, ipv6 text not null default '[]', mac text,
  interface_type text, description text, status text, instance_id text, source_dest_check integer, groups text not null default '[]', refreshed_at text not null
);
create index if not exists inventory_eni_instance on inventory_eni(instance_id);
create table if not exists sg_egress (
  group_id text not null, region text, ip_protocol text, from_port integer, to_port integer, cidr_ipv4 text, cidr_ipv6 text, referenced_group_id text, prefix_list_id text, rule_id text, description text, refreshed_at text not null
);
create index if not exists sg_egress_group on sg_egress(group_id)`);

// ---- Steampipe queries ------------------------------------------------------------------------------------------------

export const NETWORK_SQL = {
  subnets: `select subnet_id, vpc_id, region, account_id, cidr_block, ipv6_cidr_block_association_set, availability_zone, available_ip_address_count, map_public_ip_on_launch, default_for_az, tags ->> 'Name' as name from ${S}.aws_vpc_subnet`,
  route_tables: `select route_table_id, vpc_id, region, associations, routes, tags ->> 'Name' as name from ${S}.aws_vpc_route_table`,
  internet_gateways: `select internet_gateway_id, region, attachments, tags ->> 'Name' as name from ${S}.aws_vpc_internet_gateway`,
  egress_only_gateways: `select id, region, attachments from ${S}.aws_vpc_egress_only_internet_gateway`,
  nat_gateways: `select nat_gateway_id, vpc_id, subnet_id, region, state, nat_gateway_addresses, tags ->> 'Name' as name from ${S}.aws_vpc_nat_gateway`,
  peerings: `select id, region, requester_vpc_id, accepter_vpc_id, requester_cidr_block, accepter_cidr_block, requester_owner_id, accepter_owner_id, status_code, tags ->> 'Name' as name from ${S}.aws_vpc_peering_connection`,
  endpoints: `select vpc_endpoint_id, vpc_id, region, service_name, vpc_endpoint_type, state, subnet_ids, route_table_ids, groups, network_interface_ids from ${S}.aws_vpc_endpoint`,
  eips: `select allocation_id, public_ip, instance_id, network_interface_id, private_ip_address, region from ${S}.aws_vpc_eip`,
  enis: `select network_interface_id, vpc_id, subnet_id, region, private_ip_address, private_ip_addresses, association_public_ip, ipv6_addresses, mac_address, interface_type, description, status, attached_instance_id, source_dest_check, groups from ${S}.aws_ec2_network_interface`,
  egress_rules: `select group_id, region, ip_protocol, from_port, to_port, cidr_ipv4, cidr_ipv6, referenced_group_id, prefix_list_id, security_group_rule_id, description from ${S}.aws_vpc_security_group_rule where type = 'egress'`,
} as const;
export type NetworkPart = keyof typeof NETWORK_SQL;

const arr = (v: unknown): any[] => (Array.isArray(v) ? v : typeof v === "string" ? (() => { try { const x = JSON.parse(v); return Array.isArray(x) ? x : []; } catch { return []; } })() : []);
const str = (v: unknown): string | null => (v == null ? null : String(v));
const num = (v: unknown): number | null => (v == null || v === "" || !Number.isFinite(Number(v)) ? null : Number(v));
const json = (v: unknown) => JSON.stringify(v ?? []);

export interface GatewayRow { gateway_id: string; kind: "internet" | "nat" | "egress_only" | "peering" | "endpoint"; vpc_id: string | null; region: string | null; state: string | null; public_ips: string[]; private_ip: string | null; subnet_id: string | null; service: string | null; endpoint_type: string | null; peer_vpc_id: string | null; peer_account_id: string | null; cidrs: string[]; peer_cidrs: string[]; route_table_ids: string[]; subnet_ids: string[]; groups: string[]; name: string | null }

/** Steampipe's rows for the gateway tables folded into one shape; peering connections carry both sides. Pure. */
export function gatewayRows(parts: { internet_gateways?: any[]; egress_only_gateways?: any[]; nat_gateways?: any[]; peerings?: any[]; endpoints?: any[] }): GatewayRow[] {
  const out: GatewayRow[] = [];
  const empty = { public_ips: [] as string[], private_ip: null, subnet_id: null, service: null, endpoint_type: null, peer_vpc_id: null, peer_account_id: null, cidrs: [] as string[], peer_cidrs: [] as string[], route_table_ids: [] as string[], subnet_ids: [] as string[], groups: [] as string[] };
  for (const g of parts.internet_gateways ?? []) {
    const att = arr(g.attachments)[0];
    out.push({ ...empty, gateway_id: String(g.internet_gateway_id), kind: "internet", vpc_id: str(att?.VpcId), region: str(g.region), state: str(att?.State) ?? "detached", name: str(g.name) });
  }
  for (const g of parts.egress_only_gateways ?? []) {
    const att = arr(g.attachments)[0];
    out.push({ ...empty, gateway_id: String(g.id), kind: "egress_only", vpc_id: str(att?.VpcId), region: str(g.region), state: str(att?.State) ?? "detached", name: null });
  }
  for (const g of parts.nat_gateways ?? []) {
    const addrs = arr(g.nat_gateway_addresses);
    out.push({ ...empty, gateway_id: String(g.nat_gateway_id), kind: "nat", vpc_id: str(g.vpc_id), region: str(g.region), state: str(g.state), subnet_id: str(g.subnet_id), name: str(g.name),
      public_ips: addrs.map((a: any) => str(a?.PublicIp)).filter(Boolean) as string[], private_ip: str(addrs[0]?.PrivateIp), service: addrs.some((a: any) => a?.PublicIp) ? null : "private" });
  }
  for (const p of parts.peerings ?? []) {
    out.push({ ...empty, gateway_id: String(p.id), kind: "peering", vpc_id: str(p.requester_vpc_id), region: str(p.region), state: str(p.status_code), name: str(p.name),
      peer_vpc_id: str(p.accepter_vpc_id), peer_account_id: str(p.accepter_owner_id), cidrs: p.requester_cidr_block ? [String(p.requester_cidr_block)] : [], peer_cidrs: p.accepter_cidr_block ? [String(p.accepter_cidr_block)] : [] });
  }
  for (const e of parts.endpoints ?? []) {
    out.push({ ...empty, gateway_id: String(e.vpc_endpoint_id), kind: "endpoint", vpc_id: str(e.vpc_id), region: str(e.region), state: str(e.state), name: null,
      service: str(e.service_name), endpoint_type: str(e.vpc_endpoint_type)?.toLowerCase() ?? null, route_table_ids: arr(e.route_table_ids).map(String), subnet_ids: arr(e.subnet_ids).map(String),
      groups: arr(e.groups).map((g: any) => String(g?.GroupId ?? g)).filter(Boolean) });
  }
  return out;
}

/** Writes whatever parts were read (an undefined part keeps its table as it was). */
export function replaceNetwork(parts: Partial<Record<NetworkPart, any[] | undefined>>): Record<string, number> {
  const at = new Date().toISOString();
  const counts: Record<string, number> = {};
  db.transaction(() => {
    if (parts.subnets) {
      db.prepare("delete from inventory_subnet").run();
      const ins = db.prepare("insert or replace into inventory_subnet(subnet_id, vpc_id, region, account_id, cidr_block, ipv6_cidrs, az, available_ips, map_public_ip, default_for_az, name, refreshed_at) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
      for (const s of parts.subnets) ins.run(String(s.subnet_id), str(s.vpc_id), str(s.region), str(s.account_id), str(s.cidr_block), json(arr(s.ipv6_cidr_block_association_set).map((a: any) => a?.Ipv6CidrBlock).filter(Boolean)), str(s.availability_zone), num(s.available_ip_address_count), s.map_public_ip_on_launch ? 1 : 0, s.default_for_az ? 1 : 0, str(s.name), at);
      counts.subnets = parts.subnets.length;
    }
    if (parts.route_tables) {
      db.prepare("delete from inventory_route_table").run();
      const ins = db.prepare("insert or replace into inventory_route_table(route_table_id, vpc_id, region, main, subnets, routes, name, refreshed_at) values (?, ?, ?, ?, ?, ?, ?, ?)");
      for (const r of parts.route_tables) {
        const assoc = arr(r.associations);
        ins.run(String(r.route_table_id), str(r.vpc_id), str(r.region), assoc.some((a: any) => a?.Main) ? 1 : 0, json(assoc.map((a: any) => a?.SubnetId).filter(Boolean)), json(arr(r.routes)), str(r.name), at);
      }
      counts.route_tables = parts.route_tables.length;
    }
    const gw = gatewayRows(parts);
    if (parts.internet_gateways || parts.egress_only_gateways || parts.nat_gateways || parts.peerings || parts.endpoints) {
      const kinds = ([["internet_gateways", "internet"], ["egress_only_gateways", "egress_only"], ["nat_gateways", "nat"], ["peerings", "peering"], ["endpoints", "endpoint"]] as const).filter(([part]) => parts[part]).map(([, kind]) => kind);
      db.prepare(`delete from inventory_gateway where kind in (${kinds.map(() => "?").join(",")})`).run(...kinds);
      const ins = db.prepare("insert or replace into inventory_gateway(gateway_id, kind, vpc_id, region, state, public_ips, private_ip, subnet_id, service, endpoint_type, peer_vpc_id, peer_account_id, cidrs, peer_cidrs, route_table_ids, subnet_ids, groups, name, refreshed_at) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
      for (const g of gw) ins.run(g.gateway_id, g.kind, g.vpc_id, g.region, g.state, json(g.public_ips), g.private_ip, g.subnet_id, g.service, g.endpoint_type, g.peer_vpc_id, g.peer_account_id, json(g.cidrs), json(g.peer_cidrs), json(g.route_table_ids), json(g.subnet_ids), json(g.groups), g.name, at);
      counts.gateways = gw.length;
    }
    if (parts.eips) {
      db.prepare("delete from inventory_eip").run();
      const ins = db.prepare("insert or replace into inventory_eip(id, allocation_id, public_ip, instance_id, network_interface_id, private_ip, region, refreshed_at) values (?, ?, ?, ?, ?, ?, ?, ?)");
      for (const e of parts.eips) if (e.public_ip) ins.run(String(e.allocation_id || e.public_ip), str(e.allocation_id), String(e.public_ip), str(e.instance_id), str(e.network_interface_id), str(e.private_ip_address), str(e.region), at);
      counts.eips = parts.eips.length;
    }
    if (parts.enis) {
      db.prepare("delete from inventory_eni").run();
      const ins = db.prepare("insert or replace into inventory_eni(eni_id, vpc_id, subnet_id, region, private_ips, public_ip, ipv6, mac, interface_type, description, status, instance_id, source_dest_check, groups, refreshed_at) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
      for (const e of parts.enis) {
        const ips = [str(e.private_ip_address), ...arr(e.private_ip_addresses).map((p: any) => str(p?.PrivateIpAddress))].filter((x, i, a): x is string => Boolean(x) && a.indexOf(x) === i);
        ins.run(String(e.network_interface_id), str(e.vpc_id), str(e.subnet_id), str(e.region), json(ips), str(e.association_public_ip), json(arr(e.ipv6_addresses).map((a: any) => str(a?.Ipv6Address ?? a)).filter(Boolean)), str(e.mac_address), str(e.interface_type), str(e.description), str(e.status), str(e.attached_instance_id), e.source_dest_check == null ? null : e.source_dest_check ? 1 : 0, json(arr(e.groups).map((g: any) => str(g?.GroupId ?? g)).filter(Boolean)), at);
      }
      counts.enis = parts.enis.length;
    }
    if (parts.egress_rules) {
      db.prepare("delete from sg_egress").run();
      const ins = db.prepare("insert into sg_egress(group_id, region, ip_protocol, from_port, to_port, cidr_ipv4, cidr_ipv6, referenced_group_id, prefix_list_id, rule_id, description, refreshed_at) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
      for (const r of parts.egress_rules) ins.run(String(r.group_id), str(r.region), str(r.ip_protocol), num(r.from_port), num(r.to_port), str(r.cidr_ipv4), str(r.cidr_ipv6), str(r.referenced_group_id), str(r.prefix_list_id), str(r.security_group_rule_id), str(r.description), at);
      counts.egress_rules = parts.egress_rules.length;
    }
  })();
  return counts;
}

/** Runs every network query through the inventory's `attempt` (which records a failure and returns undefined) and writes what came back. */
export async function refreshNetworkInventory(attempt: (what: string, sql: string) => Promise<any[] | undefined>): Promise<Record<string, number>> {
  const names = Object.keys(NETWORK_SQL) as NetworkPart[];
  const results = await Promise.all(names.map((n) => attempt(n.replace(/_/g, " "), NETWORK_SQL[n])));
  const parts: Partial<Record<NetworkPart, any[] | undefined>> = {};
  names.forEach((n, i) => { parts[n] = results[i]; });
  return replaceNetwork(parts);
}

// ---- reading -------------------------------------------------------------------------------------------------------------

const rows = (sql: string, ...params: unknown[]): any[] => { try { return db.prepare(sql).all(...params) as any[]; } catch { return []; } };
const parse = <T,>(s: unknown, fallback: T): T => { if (typeof s !== "string") return fallback; try { return JSON.parse(s) as T; } catch { return fallback; } };

export interface SubnetRow { subnet_id: string; vpc_id: string | null; region: string | null; account_id: string | null; cidr_block: string | null; ipv6_cidrs: string[]; az: string | null; available_ips: number | null; map_public_ip: boolean; default_for_az: boolean; name: string | null }
export interface RouteTableRow { route_table_id: string; vpc_id: string | null; region: string | null; main: boolean; subnets: string[]; routes: Route[]; name: string | null }
/** One route as EC2 describes it (Steampipe aws_vpc_route_table.routes). */
export interface Route { DestinationCidrBlock?: string | null; DestinationIpv6CidrBlock?: string | null; DestinationPrefixListId?: string | null; GatewayId?: string | null; NatGatewayId?: string | null; TransitGatewayId?: string | null; VpcPeeringConnectionId?: string | null; NetworkInterfaceId?: string | null; InstanceId?: string | null; EgressOnlyInternetGatewayId?: string | null; LocalGatewayId?: string | null; CarrierGatewayId?: string | null; State?: string | null; Origin?: string | null }
export interface EipRow { id: string; allocation_id: string | null; public_ip: string; instance_id: string | null; network_interface_id: string | null; private_ip: string | null; region: string | null }
export interface EniRow { eni_id: string; vpc_id: string | null; subnet_id: string | null; region: string | null; private_ips: string[]; public_ip: string | null; ipv6: string[]; mac: string | null; interface_type: string | null; description: string | null; status: string | null; instance_id: string | null; source_dest_check: boolean | null; groups: string[] }

export const listSubnets = (): SubnetRow[] => rows("select * from inventory_subnet").map((s) => ({ ...s, ipv6_cidrs: parse<string[]>(s.ipv6_cidrs, []), map_public_ip: Boolean(s.map_public_ip), default_for_az: Boolean(s.default_for_az) }));
export const listRouteTables = (): RouteTableRow[] => rows("select * from inventory_route_table").map((r) => ({ ...r, main: Boolean(r.main), subnets: parse<string[]>(r.subnets, []), routes: parse<Route[]>(r.routes, []) }));
export const listGateways = (): GatewayRow[] => rows("select * from inventory_gateway").map((g) => ({ ...g, public_ips: parse<string[]>(g.public_ips, []), cidrs: parse<string[]>(g.cidrs, []), peer_cidrs: parse<string[]>(g.peer_cidrs, []), route_table_ids: parse<string[]>(g.route_table_ids, []), subnet_ids: parse<string[]>(g.subnet_ids, []), groups: parse<string[]>(g.groups, []) }));
export const listEips = (): EipRow[] => rows("select * from inventory_eip");
export const listEnis = (): EniRow[] => rows("select * from inventory_eni").map((e) => ({ ...e, private_ips: parse<string[]>(e.private_ips, []), ipv6: parse<string[]>(e.ipv6, []), source_dest_check: e.source_dest_check == null ? null : Boolean(e.source_dest_check), groups: parse<string[]>(e.groups, []) }));
export const egressRulesFor = (groupIds: string[]): IngressRule[] => (groupIds.length ? rows(`select group_id, ip_protocol, from_port, to_port, cidr_ipv4, cidr_ipv6, referenced_group_id, prefix_list_id, rule_id, description from sg_egress where group_id in (${groupIds.map(() => "?").join(",")})`, ...groupIds) : []);
export const allEgressRules = (): IngressRule[] => rows("select group_id, ip_protocol, from_port, to_port, cidr_ipv4, cidr_ipv6, referenced_group_id, prefix_list_id, rule_id, description from sg_egress");

// ---- pure helpers --------------------------------------------------------------------------------------------------------

export type RouteTargetKind = "local" | "internet_gateway" | "nat_gateway" | "egress_only_gateway" | "transit_gateway" | "peering" | "vpc_endpoint" | "interface" | "instance" | "virtual_private_gateway" | "local_gateway" | "carrier_gateway" | "unknown";

/** What a route sends traffic to, and where. Pure. */
export function routeTarget(r: Route): { kind: RouteTargetKind; id: string | null; destination: string | null } {
  const destination = r.DestinationCidrBlock ?? r.DestinationIpv6CidrBlock ?? r.DestinationPrefixListId ?? null;
  const g = r.GatewayId ?? null;
  if (g === "local") return { kind: "local", id: null, destination };
  if (g?.startsWith("igw-")) return { kind: "internet_gateway", id: g, destination };
  if (g?.startsWith("vgw-")) return { kind: "virtual_private_gateway", id: g, destination };
  if (g?.startsWith("vpce-")) return { kind: "vpc_endpoint", id: g, destination };
  if (r.NatGatewayId) return { kind: "nat_gateway", id: r.NatGatewayId, destination };
  if (r.EgressOnlyInternetGatewayId) return { kind: "egress_only_gateway", id: r.EgressOnlyInternetGatewayId, destination };
  if (r.TransitGatewayId) return { kind: "transit_gateway", id: r.TransitGatewayId, destination };
  if (r.VpcPeeringConnectionId) return { kind: "peering", id: r.VpcPeeringConnectionId, destination };
  if (r.NetworkInterfaceId) return { kind: "interface", id: r.NetworkInterfaceId, destination };
  if (r.InstanceId) return { kind: "instance", id: r.InstanceId, destination };
  if (r.LocalGatewayId) return { kind: "local_gateway", id: r.LocalGatewayId, destination };
  if (r.CarrierGatewayId) return { kind: "carrier_gateway", id: r.CarrierGatewayId, destination };
  return { kind: "unknown", id: g, destination };
}

const isDefaultRoute = (d: string | null) => d === "0.0.0.0/0" || d === "::/0";

/** The route table a subnet uses: the one associated with it, else the VPC's main table. Pure. */
export function routeTableOf(subnetId: string, vpcId: string | null, tables: RouteTableRow[]): RouteTableRow | null {
  return tables.find((t) => t.subnets.includes(subnetId)) ?? tables.find((t) => t.main && t.vpc_id === vpcId) ?? null;
}

/** A subnet is public when its route table sends the default route to an internet gateway (active routes only). Pure. */
export function isPublicSubnet(table: RouteTableRow | null): boolean {
  if (!table) return false;
  return table.routes.some((r) => { const t = routeTarget(r); return t.kind === "internet_gateway" && isDefaultRoute(t.destination) && (r.State ?? "active") === "active"; });
}

/** Whose interface an ENI is, from its attachment or its description: the instance, a balancer by name, a function by name, a NAT gateway, an endpoint, a database, a cache. Pure. */
export function eniOwner(e: Pick<EniRow, "interface_type" | "description" | "instance_id">): { kind: "instance" | "load_balancer" | "function" | "nat_gateway" | "vpc_endpoint" | "database" | "cache" | "transit_gateway" | "efs" | "other"; name: string | null } {
  if (e.instance_id) return { kind: "instance", name: e.instance_id };
  const d = e.description ?? ""; const t = (e.interface_type ?? "").toLowerCase();
  let m: RegExpExecArray | null;
  if ((m = /^ELB (?:app|net|gwy)\/([^/]+)\/[0-9a-f]+$/.exec(d))) return { kind: "load_balancer", name: m[1] };
  if ((m = /^ELB (.+)$/.exec(d))) return { kind: "load_balancer", name: m[1] };
  if ((m = /^AWS Lambda VPC ENI-(.+)-[0-9a-f-]{36}$/.exec(d)) || (m = /^AWS Lambda VPC ENI-(.+)$/.exec(d))) return { kind: "function", name: m[1] };
  if (t === "nat_gateway" || (m = /NAT Gateway (nat-[0-9a-f]+)/.exec(d))) return { kind: "nat_gateway", name: /nat-[0-9a-f]+/.exec(d)?.[0] ?? null };
  if (t === "vpc_endpoint" || (m = /VPC Endpoint Interface (vpce-[0-9a-f]+)/.exec(d))) return { kind: "vpc_endpoint", name: /vpce-[0-9a-f]+/.exec(d)?.[0] ?? null };
  if (t === "transit_gateway") return { kind: "transit_gateway", name: null };
  if (/RDSNetworkInterface/i.test(d)) return { kind: "database", name: null };
  if (/ElastiCache/i.test(d)) return { kind: "cache", name: null };
  if (/^EFS mount target/i.test(d)) return { kind: "efs", name: null };
  return { kind: "other", name: null };
}

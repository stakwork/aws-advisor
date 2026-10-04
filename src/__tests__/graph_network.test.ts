import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

// The network layer's pure parts: the inventory helpers (which subnet is public, what a route points at, whose
// interface an ENI is, how Steampipe's gateway rows fold) and the verdict edges built on reachOf/naclVerdict.
process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "advisor-network-test-"));
process.env.TYPESAFE_API_KEY = "";
process.env.REPO2GRAPH_URL = "";

const ni = await import("../network_inventory.js");
const gn = await import("../graph_network.js");
const { db } = await import("../db.js");

const WORLD_SSH = { group_id: "sg-web", ip_protocol: "tcp", from_port: 22, to_port: 22, cidr_ipv4: "0.0.0.0/0", cidr_ipv6: null, referenced_group_id: null, prefix_list_id: null, rule_id: "sgr-ssh", description: "ssh" };
const OFFICE_5432 = { group_id: "sg-db", ip_protocol: "tcp", from_port: 5432, to_port: 5432, cidr_ipv4: "203.0.113.0/24", cidr_ipv6: null, referenced_group_id: null, prefix_list_id: null, rule_id: "sgr-pg", description: null };
const FROM_WEB = { group_id: "sg-db", ip_protocol: "tcp", from_port: 5432, to_port: 5432, cidr_ipv4: null, cidr_ipv6: null, referenced_group_id: "sg-web", prefix_list_id: null, rule_id: "sgr-pg-web", description: null };
const V6_ONLY = { group_id: "sg-web", ip_protocol: "tcp", from_port: 443, to_port: 443, cidr_ipv4: null, cidr_ipv6: "::/0", referenced_group_id: null, prefix_list_id: null, rule_id: "sgr-v6", description: null };

test("routeTarget and isPublicSubnet: a default route to an internet gateway makes the subnet public, a NAT route does not", () => {
  assert.deepEqual(ni.routeTarget({ DestinationCidrBlock: "10.0.0.0/16", GatewayId: "local" }), { kind: "local", id: null, destination: "10.0.0.0/16" });
  assert.deepEqual(ni.routeTarget({ DestinationCidrBlock: "0.0.0.0/0", GatewayId: "igw-1" }), { kind: "internet_gateway", id: "igw-1", destination: "0.0.0.0/0" });
  assert.deepEqual(ni.routeTarget({ DestinationCidrBlock: "0.0.0.0/0", NatGatewayId: "nat-1" }), { kind: "nat_gateway", id: "nat-1", destination: "0.0.0.0/0" });
  assert.deepEqual(ni.routeTarget({ DestinationPrefixListId: "pl-1", GatewayId: "vpce-1" }), { kind: "vpc_endpoint", id: "vpce-1", destination: "pl-1" });
  assert.deepEqual(ni.routeTarget({ DestinationCidrBlock: "10.1.0.0/16", VpcPeeringConnectionId: "pcx-1" }), { kind: "peering", id: "pcx-1", destination: "10.1.0.0/16" });
  assert.equal(ni.routeTarget({ DestinationCidrBlock: "10.2.0.0/16", TransitGatewayId: "tgw-1" }).kind, "transit_gateway");
  const tables = [
    { route_table_id: "rtb-main", vpc_id: "vpc-1", region: "us-east-1", main: true, subnets: [], routes: [{ DestinationCidrBlock: "10.0.0.0/16", GatewayId: "local" }, { DestinationCidrBlock: "0.0.0.0/0", NatGatewayId: "nat-1", State: "active" }], name: null },
    { route_table_id: "rtb-public", vpc_id: "vpc-1", region: "us-east-1", main: false, subnets: ["subnet-pub"], routes: [{ DestinationCidrBlock: "0.0.0.0/0", GatewayId: "igw-1", State: "active" }], name: "public" },
    { route_table_id: "rtb-dead", vpc_id: "vpc-1", region: "us-east-1", main: false, subnets: ["subnet-dead"], routes: [{ DestinationCidrBlock: "0.0.0.0/0", GatewayId: "igw-1", State: "blackhole" }], name: null },
  ];
  assert.equal(ni.routeTableOf("subnet-pub", "vpc-1", tables)?.route_table_id, "rtb-public");
  assert.equal(ni.routeTableOf("subnet-priv", "vpc-1", tables)?.route_table_id, "rtb-main", "no association: the main table");
  assert.equal(ni.isPublicSubnet(ni.routeTableOf("subnet-pub", "vpc-1", tables)), true);
  assert.equal(ni.isPublicSubnet(ni.routeTableOf("subnet-priv", "vpc-1", tables)), false, "NAT is not public");
  assert.equal(ni.isPublicSubnet(ni.routeTableOf("subnet-dead", "vpc-1", tables)), false, "a blackholed route does not count");
  assert.equal(ni.isPublicSubnet(null), false);
});

test("eniOwner reads the attachment or the description", () => {
  assert.deepEqual(ni.eniOwner({ interface_type: "interface", description: "", instance_id: "i-1" }), { kind: "instance", name: "i-1" });
  assert.deepEqual(ni.eniOwner({ interface_type: "interface", description: "ELB app/web-prod/50dc6c495c0c9188", instance_id: null }), { kind: "load_balancer", name: "web-prod" });
  assert.deepEqual(ni.eniOwner({ interface_type: "interface", description: "ELB classic-lb", instance_id: null }), { kind: "load_balancer", name: "classic-lb" });
  assert.deepEqual(ni.eniOwner({ interface_type: "lambda", description: "AWS Lambda VPC ENI-my-fn-0f4e1d7e-5b7e-4b7f-9b3a-1234567890ab", instance_id: null }), { kind: "function", name: "my-fn" });
  assert.deepEqual(ni.eniOwner({ interface_type: "nat_gateway", description: "Interface for NAT Gateway nat-0abc", instance_id: null }), { kind: "nat_gateway", name: "nat-0abc" });
  assert.deepEqual(ni.eniOwner({ interface_type: "vpc_endpoint", description: "VPC Endpoint Interface vpce-0abc", instance_id: null }), { kind: "vpc_endpoint", name: "vpce-0abc" });
  assert.deepEqual(ni.eniOwner({ interface_type: "interface", description: "RDSNetworkInterface", instance_id: null }), { kind: "database", name: null });
  assert.deepEqual(ni.eniOwner({ interface_type: "interface", description: "ElastiCache sidekiq-001", instance_id: null }), { kind: "cache", name: null });
  assert.deepEqual(ni.eniOwner({ interface_type: "interface", description: "something else", instance_id: null }), { kind: "other", name: null });
});

test("gatewayRows folds Steampipe's five gateway tables into one shape and replaceNetwork writes what was read", () => {
  const gws = ni.gatewayRows({
    internet_gateways: [{ internet_gateway_id: "igw-1", region: "us-east-1", attachments: [{ VpcId: "vpc-1", State: "available" }], name: "main" }],
    nat_gateways: [{ nat_gateway_id: "nat-1", vpc_id: "vpc-1", subnet_id: "subnet-pub", region: "us-east-1", state: "available", nat_gateway_addresses: [{ PublicIp: "198.51.100.7", PrivateIp: "10.0.1.9" }], connectivity_type: "public" }],
    peerings: [{ id: "pcx-1", region: "us-east-1", requester_vpc_id: "vpc-1", accepter_vpc_id: "vpc-2", requester_cidr_block: "10.0.0.0/16", accepter_cidr_block: "10.1.0.0/16", requester_owner_id: "111111111111", accepter_owner_id: "222222222222", status_code: "active" }],
    endpoints: [{ vpc_endpoint_id: "vpce-1", vpc_id: "vpc-1", region: "us-east-1", service_name: "com.amazonaws.us-east-1.s3", vpc_endpoint_type: "Gateway", state: "available", subnet_ids: [], route_table_ids: ["rtb-main"], groups: [], network_interface_ids: [] }],
  });
  assert.deepEqual(gws.map((g) => [g.gateway_id, g.kind, g.vpc_id]), [["igw-1", "internet", "vpc-1"], ["nat-1", "nat", "vpc-1"], ["pcx-1", "peering", "vpc-1"], ["vpce-1", "endpoint", "vpc-1"]]);
  assert.deepEqual(gws[1].public_ips, ["198.51.100.7"]);
  assert.equal(gws[2].peer_vpc_id, "vpc-2"); assert.deepEqual(gws[2].peer_cidrs, ["10.1.0.0/16"]);
  assert.equal(gws[3].endpoint_type, "gateway"); assert.deepEqual(gws[3].route_table_ids, ["rtb-main"]);

  const counts = ni.replaceNetwork({
    subnets: [{ subnet_id: "subnet-pub", vpc_id: "vpc-1", region: "us-east-1", account_id: "111111111111", cidr_block: "10.0.1.0/24", ipv6_cidr_block_association_set: [{ Ipv6CidrBlock: "2001:db8::/64" }], availability_zone: "us-east-1a", available_ip_address_count: 200, map_public_ip_on_launch: true, default_for_az: false, name: "public-a" }],
    route_tables: [{ route_table_id: "rtb-public", vpc_id: "vpc-1", region: "us-east-1", associations: [{ SubnetId: "subnet-pub", Main: false }], routes: [{ DestinationCidrBlock: "0.0.0.0/0", GatewayId: "igw-1", State: "active" }], name: "public" }],
    internet_gateways: [{ internet_gateway_id: "igw-1", region: "us-east-1", attachments: [{ VpcId: "vpc-1", State: "available" }] }],
    eips: [{ allocation_id: "eipalloc-1", public_ip: "198.51.100.9", instance_id: "i-1", network_interface_id: "eni-1", private_ip_address: "10.0.1.5", region: "us-east-1" }],
    enis: [{ network_interface_id: "eni-1", vpc_id: "vpc-1", subnet_id: "subnet-pub", region: "us-east-1", private_ip_address: "10.0.1.5", private_ip_addresses: [{ PrivateIpAddress: "10.0.1.5" }, { PrivateIpAddress: "10.0.1.6" }], association_public_ip: "198.51.100.9", ipv6_addresses: [], mac_address: "0a:00:00:00:00:01", interface_type: "interface", description: "", status: "in-use", attached_instance_id: "i-1", source_dest_check: true, groups: [{ GroupId: "sg-web", GroupName: "web" }] }],
    egress_rules: [{ group_id: "sg-web", region: "us-east-1", ip_protocol: "-1", from_port: null, to_port: null, cidr_ipv4: "0.0.0.0/0", cidr_ipv6: null, referenced_group_id: null, prefix_list_id: null, security_group_rule_id: "sgr-out", description: null }],
  });
  assert.deepEqual(counts, { subnets: 1, route_tables: 1, gateways: 1, eips: 1, enis: 1, egress_rules: 1 });
  const s = ni.listSubnets()[0];
  assert.equal(s.map_public_ip, true); assert.deepEqual(s.ipv6_cidrs, ["2001:db8::/64"]); assert.equal(s.name, "public-a");
  assert.equal(ni.listRouteTables()[0].subnets[0], "subnet-pub");
  const e = ni.listEnis()[0];
  assert.deepEqual(e.private_ips, ["10.0.1.5", "10.0.1.6"]); assert.deepEqual(e.groups, ["sg-web"]); assert.equal(e.source_dest_check, true);
  assert.equal(ni.listEips()[0].id, "eipalloc-1");
  assert.equal(ni.egressRulesFor(["sg-web"])[0].rule_id, "sgr-out");
  // a part that was not read keeps its table
  ni.replaceNetwork({ subnets: [] });
  assert.equal(ni.listSubnets().length, 0); assert.equal(ni.listEnis().length, 1);
  db.prepare("delete from inventory_eni").run(); db.prepare("delete from inventory_route_table").run(); db.prepare("delete from inventory_gateway").run(); db.prepare("delete from inventory_eip").run(); db.prepare("delete from sg_egress").run();
});

test("rule nodes: security group rules and ACL entries become AdvisorFilterRule rows with a FROM target", () => {
  const ssh = gn.sgRuleNode(WORLD_SSH, "ingress", true);
  assert.equal(ssh.id, "sgr-ssh"); assert.equal(ssh.protocol, "tcp"); assert.equal(ssh.from_port, 22); assert.equal(ssh.source_kind, "internet"); assert.deepEqual(ssh.source_node, { label: "AdvisorSource", id: "internet" }); assert.equal(ssh.dormant, false);
  const fromWeb = gn.sgRuleNode(FROM_WEB, "ingress", true);
  assert.equal(fromWeb.source_kind, "filter"); assert.deepEqual(fromWeb.source_node, { label: "AdvisorFilter", id: "sg-web" });
  const office = gn.sgRuleNode(OFFICE_5432, "ingress", true);
  assert.deepEqual(office.source_node, { label: "AdvisorSource", id: "cidr:203.0.113.0/24" }); assert.equal(office.source_meta?.private, false);
  assert.equal(gn.sgRuleNode(V6_ONLY, "ingress", false).dormant, true, "an IPv6 rule in a network without IPv6");
  assert.equal(gn.sgRuleNode(V6_ONLY, "ingress", true).dormant, false);
  const all = gn.sgRuleNode({ group_id: "sg-x", ip_protocol: "-1", from_port: null, to_port: null, cidr_ipv4: "10.0.0.0/8", cidr_ipv6: null, referenced_group_id: null, prefix_list_id: null, rule_id: null, description: null }, "egress", null);
  assert.equal(all.protocol, "any"); assert.equal(all.from_port, null); assert.equal(all.direction, "egress"); assert.ok(all.id.startsWith("sg-x:egress:any"), "no rule id: a synthesized key");
  assert.equal(all.source_meta?.private, true);
  const entry = gn.naclRuleNode("acl-1", { RuleNumber: 100, RuleAction: "deny", Egress: false, Protocol: "6", CidrBlock: "0.0.0.0/0", PortRange: { From: 22, To: 22 } });
  assert.equal(entry.id, "acl-1:in:100"); assert.equal(entry.action, "deny"); assert.equal(entry.priority, 100); assert.equal(entry.protocol, "tcp"); assert.deepEqual(entry.source_node, { label: "AdvisorSource", id: "internet" });
});

test("verdict edges: an internet-open port, one behind a NACL deny, one with no rule, one without a public address, one on loopback", () => {
  const l22 = { proto: "tcp" as const, port: 22, scope: "all" as const, bind: "0.0.0.0" };
  // open: reachable from the internet through the ssh rule
  const open = gn.verdictEdges(l22, [WORLD_SSH], { public_ip: "198.51.100.9", ipv6: [], group_names: { "sg-web": "web" } }, ["sg-web"]);
  assert.equal(open.exposure, "internet");
  assert.deepEqual(open.reachable_from.map((r) => [r.label, r.id, r.via_rule]), [["AdvisorSource", "internet", "sgr-ssh"]]);
  assert.deepEqual(open.allowed_by, [{ rule_id: "sgr-ssh", source: "internet" }]);
  assert.equal(open.blocked_by.length, 0);
  // the subnet's ACL denies 22 from the world: the group rule admits it, the ACL entry blocks it
  const acl = { acl_id: "acl-1", entries: [
    { RuleNumber: 90, RuleAction: "deny", Egress: false, Protocol: "6", CidrBlock: "0.0.0.0/0", PortRange: { From: 22, To: 22 } },
    { RuleNumber: 100, RuleAction: "allow", Egress: false, Protocol: "-1", CidrBlock: "0.0.0.0/0" },
    { RuleNumber: 100, RuleAction: "allow", Egress: true, Protocol: "-1", CidrBlock: "0.0.0.0/0" },
  ] };
  const blocked = gn.verdictEdges(l22, [WORLD_SSH], { public_ip: "198.51.100.9", ipv6: [], nacl: acl }, ["sg-web"]);
  assert.equal(blocked.exposure, "closed");
  assert.equal(blocked.reachable_from.length, 0);
  assert.deepEqual(blocked.blocked_by, [{ label: "AdvisorFilterRule", id: "acl-1:in:90", source: "internet", reason: "acl-1 rule #90 denies it" }]);
  // the same ACL lets 443 through: the entry it passed is in `through`
  const https = gn.verdictEdges({ ...l22, port: 443 }, [{ ...WORLD_SSH, from_port: 443, to_port: 443, rule_id: "sgr-https" }], { public_ip: "198.51.100.9", ipv6: [], nacl: acl }, ["sg-web"]);
  assert.equal(https.exposure, "internet");
  assert.deepEqual(https.reachable_from[0].through, ["sgr-https", "acl-1:in:100"]);
  // no rule matches: blocked by the groups themselves
  const closed = gn.verdictEdges({ ...l22, port: 8080 }, [WORLD_SSH], { public_ip: "198.51.100.9", ipv6: [] }, ["sg-web"]);
  assert.equal(closed.exposure, "closed");
  assert.deepEqual(closed.blocked_by, [{ label: "AdvisorFilter", id: "sg-web", source: "any", reason: "no rule in sg-web lets 8080/tcp in" }]);
  // a world rule on a box without a public address: reachable from the network, and the edge says why
  const priv = gn.verdictEdges(l22, [WORLD_SSH], { public_ip: null, ipv6: [] }, ["sg-web"]);
  assert.equal(priv.exposure, "network");
  assert.equal(priv.reachable_from[0].id, "internet");
  assert.match(priv.reachable_from[0].note ?? "", /no public address/);
  // a database port from an office range and from the web group: two sources, two rules
  const pg = gn.verdictEdges({ proto: "tcp", port: 5432, scope: "all", bind: "" }, [OFFICE_5432, FROM_WEB], { public_ip: null, ipv6: [], group_names: { "sg-web": "web" } }, ["sg-db"]);
  assert.equal(pg.exposure, "network");
  assert.deepEqual(pg.reachable_from.map((r) => r.id).sort(), ["cidr:203.0.113.0/24", "sg-web"]);
  assert.deepEqual(pg.allowed_by.map((a) => a.rule_id).sort(), ["sgr-pg", "sgr-pg-web"]);
  // loopback: nothing to say
  const local = gn.verdictEdges({ ...l22, scope: "loopback", bind: "127.0.0.1" }, [WORLD_SSH], { public_ip: "198.51.100.9" }, ["sg-web"]);
  assert.equal(local.exposure, "local"); assert.equal(local.reachable_from.length, 0); assert.equal(local.blocked_by.length, 0);
});

test("without NEO4J_URI the network mirror is a no-op", async () => {
  assert.equal(await gn.mirrorNetwork(), null);
  assert.deepEqual(await gn.mirrorReachability(), { endpoints: 0 });
});

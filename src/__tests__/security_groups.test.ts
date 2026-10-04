import { test } from "node:test";
import assert from "node:assert";

const rule = (o: Partial<import("../instance_apps.js").IngressRule>): import("../instance_apps.js").IngressRule =>
  ({ group_id: "sg-0test00000000001", ip_protocol: "tcp", from_port: null, to_port: null, cidr_ipv4: null, cidr_ipv6: null, referenced_group_id: null, prefix_list_id: null, rule_id: null, description: null, ...o });

test("dormant IPv6: only in a VPC without IPv6, only broad rules or ports IPv4 keeps closed", async () => {
  const { dormantIpv6Rules } = await import("../security_groups.js");
  const allV6 = rule({ ip_protocol: "-1", cidr_ipv6: "::/0", rule_id: "sgr-0test1" });
  const https4 = rule({ from_port: 443, to_port: 443, cidr_ipv4: "0.0.0.0/0" });
  const https6 = rule({ from_port: 443, to_port: 443, cidr_ipv6: "::/0" });
  const pg6 = rule({ from_port: 5432, to_port: 5432, cidr_ipv6: "::/0" });
  const rules = [allV6, https4, https6, pg6];
  const d = dormantIpv6Rules(rules, false, { "sg-0test00000000001": "web-sg" });
  assert.deepEqual(d.map((x) => [x.ref.ports, x.why]), [["all traffic", "broad"], ["tcp 5432", "no_ipv4_twin"]], "443 mirrors a deliberate IPv4 rule and is left alone");
  assert.deepEqual(dormantIpv6Rules(rules, true), [], "with IPv6 in the VPC the rules are live, and the port view shows them");
  assert.deepEqual(dormantIpv6Rules(rules, null), [], "a VPC not read yet says nothing");
  const range4 = rule({ from_port: 8000, to_port: 9000, cidr_ipv4: "0.0.0.0/0" });
  assert.deepEqual(dormantIpv6Rules([range4, rule({ from_port: 8080, to_port: 8080, cidr_ipv6: "::/0" })], false), [], "covered by a wider IPv4 range");
});

test("security groups: members, rules behind listeners, flags, and a dormant-IPv6 recommendation that resolves when the rule goes", async () => {
  const { db } = await import("../db.js");
  const { recordPorts } = await import("../instance_apps.js");
  const { replaceSecurityGroups, listSecurityGroups, securityGroupDetail, syncSecurityGroupRecommendations, DORMANT_RULE } = await import("../security_groups.js");
  const G = "sg-0test00000000001", G2 = "sg-0test00000000002", I = "i-0f0000000000b0001", V = "vpc-0f0000000000b0001";
  // only this test's rows: the files run in parallel on one database, and replaceIngressRules empties the table
  const setRules = (rows: any[]) => {
    db.prepare("delete from sg_ingress where group_id in (?, ?)").run(G, G2);
    const ins = db.prepare("insert into sg_ingress(group_id, region, ip_protocol, from_port, to_port, cidr_ipv4, cidr_ipv6, referenced_group_id, prefix_list_id, rule_id, description, refreshed_at) values (?, 'us-east-1', ?, ?, ?, ?, ?, null, null, ?, null, 't')");
    for (const r of rows) ins.run(r.group_id, r.ip_protocol, r.from_port, r.to_port, r.cidr_ipv4, r.cidr_ipv6, r.rule_id ?? null);
  };
  db.prepare("delete from recommendations where rule = ?").run(DORMANT_RULE);
  db.prepare("delete from instance_ports where instance_id = ?").run(I);
  db.prepare("insert or replace into inventory_ec2(instance_id, name, state, region, snapshot, gone) values (?, 'box-1', 'running', 'us-east-1', ?, 0)")
    .run(I, JSON.stringify({ network: { public_ip: "203.0.113.20", ipv6: [], vpc_id: V, subnet_id: "subnet-0f0000000000b0001", security_groups: [{ GroupId: G, GroupName: "web-sg" }] } }));
  replaceSecurityGroups(
    [{ group_id: G, group_name: "web-sg", description: "web", vpc_id: V, region: "us-east-1", account_id: "123456789012" }, { group_id: G2, group_name: "old-sg", description: null, vpc_id: V, region: "us-east-1", account_id: "123456789012" }],
    [{ vpc_id: V, region: "us-east-1", account_id: "123456789012", cidr_block: "10.9.0.0/16", is_default: false, ipv6_blocks: 0 }],
    [{ eni_id: "eni-0f0000000000b0001", interface_type: "interface", description: "Primary network interface", instance_id: I, group_ids: [G] }],
  );
  setRules([
    { group_id: G, ip_protocol: "tcp", from_port: 443, to_port: 443, cidr_ipv4: "0.0.0.0/0", cidr_ipv6: null, referenced_group_id: null, prefix_list_id: null },
    { group_id: G, ip_protocol: "-1", from_port: null, to_port: null, cidr_ipv4: null, cidr_ipv6: "::/0", referenced_group_id: null, prefix_list_id: null, rule_id: "sgr-0test1" },
  ]);
  const l = (port: number, process: string) => ({ proto: "tcp" as const, port, bind: "0.0.0.0", scope: "all" as const, process, pid: 1, container: null, container_port: null });
  recordPorts(I, "2026-10-01T10:00:00Z", { listeners: [l(443, "nginx"), l(6379, "redis-server")], processes: [] }, "box-1");

  const list = listSecurityGroups();
  const web = list.find((g) => g.group_id === G)!;
  // the account scope narrows the list (the Filters tab of one account never shows another account's groups)
  assert.ok(listSecurityGroups({ id: "123456789012", primary: false }).some((g) => g.group_id === G));
  assert.equal(listSecurityGroups({ id: "999999999999", primary: false }).some((g) => g.group_id === G || g.group_id === G2), false);
  assert.equal(web.vpc_ipv6, false);
  assert.equal(web.instances, 1); assert.equal(web.running, 1);
  assert.equal(web.listening_open, 1, "443 is open; 6379 only through the dormant IPv6 rule");
  assert.equal(web.broad_world, false, "an IPv6 all-traffic rule in a VPC without IPv6 is not a live broad rule");
  assert.equal(web.dormant_ipv6, 1);
  assert.equal(list.find((g) => g.group_id === G2)!.unattached, true);

  const d = securityGroupDetail(G)!;
  const v6 = d.rules.find((r) => r.ports === "all traffic")!;
  assert.equal(v6.inert, true); assert.equal(v6.dormant, true);
  assert.deepEqual(d.rules.find((r) => r.ports === "tcp 443")!.listeners.map((h) => h.port), [443]);

  assert.deepEqual(syncSecurityGroupRecommendations(), { warranted: 1, resolved: 0 });
  const rec = db.prepare("select title, rationale, action_type, status from recommendations where rule = ? and resource = ?").get(DORMANT_RULE, G) as any;
  assert.equal(rec.title, "Dormant IPv6 rule opens all traffic: web-sg");
  assert.equal(rec.action_type, "security_fix");
  assert.match(rec.rationale, /6379\/tcp redis-server on box-1/, "names what would open");
  assert.match(rec.rationale, /--security-group-rule-ids sgr-0test1/);

  // the rule is revoked: the recommendation resolves
  setRules([{ group_id: G, ip_protocol: "tcp", from_port: 443, to_port: 443, cidr_ipv4: "0.0.0.0/0", cidr_ipv6: null, referenced_group_id: null, prefix_list_id: null }]);
  assert.deepEqual(syncSecurityGroupRecommendations(), { warranted: 0, resolved: 1 });
  assert.equal((db.prepare("select status from recommendations where rule = ? and resource = ?").get(DORMANT_RULE, G) as any).status, "resolved");

  // leave nothing behind: other files count the fleet's open ports on the same database
  db.prepare("delete from sg_ingress where group_id in (?, ?)").run(G, G2);
  db.prepare("delete from instance_ports where instance_id = ?").run(I); db.prepare("delete from instance_app_events where instance_id = ?").run(I);
  db.prepare("delete from alerts where resource = ?").run(I); db.prepare("delete from inventory_ec2 where instance_id = ?").run(I);
  db.prepare("delete from recommendations where rule = ?").run(DORMANT_RULE);
});

test("ports: an IPv6 rule cannot open anything on a box in a VPC without IPv6, even before the snapshot records the box's addresses", async () => {
  const { db } = await import("../db.js");
  const { reachContextOf } = await import("../instance_apps.js");
  const { replaceSecurityGroups } = await import("../security_groups.js");
  const I = "i-0f0000000000b0002", V = "vpc-0f0000000000b0002";
  db.prepare("insert or replace into inventory_ec2(instance_id, name, state, region, snapshot, gone) values (?, 'box-2', 'running', 'us-east-1', ?, 0)")
    .run(I, JSON.stringify({ network: { public_ip: "203.0.113.21", vpc_id: V, security_groups: [] } }));
  replaceSecurityGroups(null, [{ vpc_id: V, region: "us-east-1", account_id: "123456789012", cidr_block: "10.8.0.0/16", is_default: false, ipv6_blocks: 0 }], null);
  assert.deepEqual(reachContextOf(I).ipv6, []);
  db.prepare("delete from inventory_ec2 where instance_id = ?").run(I);
});

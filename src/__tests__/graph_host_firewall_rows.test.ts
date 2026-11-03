import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "advisor-graph-firewall-test-"));
process.env.TYPESAFE_API_KEY = "";
process.env.REPO2GRAPH_URL = "";
const hf = await import("../host_firewall.js");
const g = await import("../graph_host_firewall.js");

const V4 = ["*filter", ":INPUT DROP [0:0]", ":FORWARD ACCEPT [0:0]", ":OUTPUT ACCEPT [0:0]", ":DOCKER - [0:0]",
  "-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
  "-A INPUT -s 0.0.0.0/0 -p tcp -m tcp --dport 22 -j ACCEPT",
  "-A INPUT -s 203.0.113.0/24 -p tcp -m multiport --dports 80,443 -j ACCEPT",
  "-A INPUT ! -s 10.0.0.0/8 -p tcp -m tcp --dport 5432 -j DROP",
  "-A INPUT -s 10.1.0.0/16 -j DOCKER",
  "-A OUTPUT -d 198.51.100.7/32 -p udp -m udp --dport 53 -j ACCEPT",
  "-A DOCKER -d 172.17.0.2/32 -p tcp -m tcp --dport 80 -j ACCEPT",
  "COMMIT", "*nat", ":PREROUTING ACCEPT [0:0]", "-A PREROUTING -p tcp -m tcp --dport 8080 -j DNAT --to-destination 172.17.0.2:80", "-A PREROUTING -j MASQUERADE", "COMMIT"];
const rs = hf.rulesetOf({ available: true, backend: "legacy", v4: V4, v6: [], nft: [], v4_lines: V4.length, v6_lines: 0, nft_lines: 0, oversize: false })!;

test("firewallFilterRow: one shared AdvisorFilter {kind: host_firewall} per ruleset, named by its hash, with its policies, counts and wearers", () => {
  const f = g.firewallFilterRow(rs, 3, "123456789012");
  assert.equal(f.id, rs.id); assert.equal(f.kind, "host_firewall"); assert.equal(f.native_type, "iptables"); assert.equal(f.stateful, true); assert.equal(f.default, false);
  assert.equal(f.name, `host firewall ${rs.id.slice(7, 19)}`);
  assert.equal(f.default_action, "deny"); assert.equal(f.input_policy, "DROP"); assert.equal(f.output_policy, "ACCEPT");
  assert.equal(f.rules, 8, "the rule nodes: filter rules and the DNAT"); assert.equal(f.rule_total, 9, "every rule, the MASQUERADE too");
  assert.deepEqual(f.chains, ["INPUT", "FORWARD", "OUTPUT", "DOCKER"]); assert.deepEqual(f.tables, ["filter", "nat"]);
  assert.equal(f.attached, 3); assert.equal(f.account_id, "123456789012"); assert.equal(f.truncated, false);
  assert.ok(f.description.startsWith("iptables: INPUT DROP, FORWARD ACCEPT, OUTPUT ACCEPT; 9 rules in 4 filter chains"), f.description);
  assert.equal(g.firewallFilterRow({ ...rs, backend: "nftables", rules: [], chains: [] }, 0, null).native_type, "nftables");
});

test("firewallRuleRows: ids hang off the filter id by family, table, chain and position; the FROM peer is the shared AdvisorSource of the source (the destination on egress), none when negated or absent", () => {
  const rows = g.firewallRuleRows(rs, "123456789012");
  assert.equal(rows.length, 8, "the MASQUERADE is not a node");
  assert.deepEqual(rows.map((r) => r.id), [0, 1, 2, 3, 4].map((i) => `${rs.id}:ipv4:filter:INPUT:${i}`).concat([`${rs.id}:ipv4:filter:OUTPUT:0`, `${rs.id}:ipv4:filter:DOCKER:0`, `${rs.id}:ipv4:nat:PREROUTING:0`]));
  const [est, ssh, web, pg, jump, dns, docker, dnat] = rows;
  assert.equal(est.source_kind, "any"); assert.equal(est.source_meta, null); assert.equal(est.source, null); assert.deepEqual(est.states, ["RELATED", "ESTABLISHED"]); assert.equal(est.priority, 0);
  assert.equal(ssh.source_kind, "internet"); assert.deepEqual(ssh.source_meta, { id: "internet", kind: "internet", label: "internet", cidr: null, private: false }); assert.equal(ssh.from_port, 22);
  assert.equal(web.source_kind, "cidr"); assert.equal(web.source_meta?.id, "cidr:203.0.113.0/24"); assert.equal(web.source_meta?.private, false); assert.equal(web.ports, "80,443"); assert.equal(web.from_port, 80); assert.equal(web.to_port, 80);
  assert.equal(pg.source_kind, "any", "a negated source names what is let in only by exclusion: no FROM edge"); assert.equal(pg.source_meta, null); assert.equal(pg.source, "!10.0.0.0/8"); assert.equal(pg.source_negated, true); assert.equal(pg.action, "deny");
  assert.equal(jump.action, "jump"); assert.equal(jump.target, "DOCKER"); assert.equal(jump.source_meta?.private, true);
  assert.equal(dns.direction, "egress"); assert.equal(dns.source, "198.51.100.7/32", "on egress the peer is the destination"); assert.equal(dns.source_meta?.id, "cidr:198.51.100.7/32"); assert.equal(dns.destination, "198.51.100.7/32");
  assert.equal(docker.direction, "ingress", "jumped to from INPUT only"); assert.equal(docker.destination, "172.17.0.2/32"); assert.equal(docker.source_meta, null);
  assert.equal(dnat.table, "nat"); assert.equal(dnat.action, "nat"); assert.equal(dnat.target_args, "--to-destination 172.17.0.2:80"); assert.equal(dnat.native_id, "ipv4 nat PREROUTING #1");
  for (const r of rows) { assert.equal(r.filter_id, rs.id); assert.equal(r.account_id, "123456789012"); assert.equal(r.description, r.comment); assert.ok(r.raw.startsWith("-A ")); assert.equal(r.native_type, "iptables_rule"); }
});

test("firewallRuleRows for an nft ruleset: nftables_rule nodes under the same id scheme, a FROM edge for one address, none for a list or a range; the filter row names the nft chains and policies", () => {
  const nft = ["table inet filter {", "set office {", "type ipv4_addr", "elements = { 10.0.0.0/8, 192.168.1.0/24 }", "}", "chain input {", "type filter hook input priority 0; policy drop;",
    "ct state { established, related } accept", "ip saddr 203.0.113.0/24 tcp dport { 80, 443 } accept", "ip saddr @office tcp dport 22 accept", "ip saddr 10.0.0.1-10.0.0.9 drop", "ip daddr 10.1.2.3 jump web", "}",
    "chain output {", "type filter hook output priority 0; policy accept;", "ip daddr 198.51.100.7 udp dport 53 accept", "}", "chain web {", "tcp dport 8080 accept", "}",
    "chain pre {", "type nat hook prerouting priority -100; policy accept;", "tcp dport 8080 dnat to 172.17.0.2:80", "}", "}"];
  const r = hf.rulesetOf({ available: true, backend: "nftables", v4: [], v6: [], nft, v4_lines: 0, v6_lines: 0, nft_lines: nft.length, oversize: false })!;
  const f = g.firewallFilterRow(r, 2, null);
  assert.equal(f.native_type, "nftables"); assert.equal(f.default_action, "deny"); assert.equal(f.input_policy, "drop"); assert.equal(f.output_policy, "accept");
  assert.deepEqual(f.chains, ["input", "output", "web"], "the filter chains: the two hooks and the chain reached from input"); assert.deepEqual(f.tables, ["filter"]);
  assert.equal(f.rules, 8); assert.equal(f.rule_total, 8); assert.ok(f.description.startsWith("nftables: input drop, output accept; 8 rules in 3 filter chains (input, output, web)"), f.description);
  const rows = g.firewallRuleRows(r, null);
  assert.deepEqual(rows.map((x) => x.id), [0, 1, 2, 3, 4].map((i) => `${r.id}:inet:filter:input:${i}`).concat([`${r.id}:inet:filter:output:0`, `${r.id}:inet:filter:web:0`, `${r.id}:inet:filter:pre:0`]));
  const [est, web, office, range, jump, dns, web2, dnat] = rows;
  for (const x of rows) assert.equal(x.native_type, "nftables_rule");
  assert.equal(est.source_kind, "any"); assert.deepEqual(est.states, ["ESTABLISHED", "RELATED"]);
  assert.equal(web.source_kind, "cidr"); assert.equal(web.source_meta?.id, "cidr:203.0.113.0/24"); assert.equal(web.ports, "80,443"); assert.equal(web.from_port, 80);
  assert.equal(office.source, "10.0.0.0/8,192.168.1.0/24", "the set's elements"); assert.equal(office.source_kind, "any", "a list is not one source node"); assert.equal(office.source_meta, null);
  assert.equal(range.source, "10.0.0.1-10.0.0.9"); assert.equal(range.source_kind, "any"); assert.equal(range.action, "deny");
  assert.equal(jump.action, "jump"); assert.equal(jump.target, "web"); assert.equal(jump.destination, "10.1.2.3/32");
  assert.equal(dns.direction, "egress"); assert.equal(dns.source, "198.51.100.7/32", "on egress the peer is the destination"); assert.equal(dns.source_meta?.id, "cidr:198.51.100.7/32");
  assert.equal(web2.direction, "ingress"); assert.equal(web2.from_port, 8080); assert.equal(web2.native_id, "inet filter web #1");
  assert.equal(dnat.action, "nat"); assert.equal(dnat.target, "dnat"); assert.equal(dnat.target_args, "to 172.17.0.2:80"); assert.equal(dnat.table, "filter"); assert.equal(dnat.chain, "pre");
  for (const x of rows) { assert.equal(x.filter_id, r.id); assert.equal(x.family, "inet"); assert.ok(!x.raw.startsWith("-A ")); }
});

test("without NEO4J_URI the host firewall mirror is a no-op", async () => {
  assert.equal(await g.mirrorHostFirewalls(), null);
  assert.equal(await g.mirrorHostFirewalls([]), null);
});

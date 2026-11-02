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
  for (const r of rows) { assert.equal(r.filter_id, rs.id); assert.equal(r.account_id, "123456789012"); assert.equal(r.description, r.comment); assert.ok(r.raw.startsWith("-A ")); }
});

test("without NEO4J_URI the host firewall mirror is a no-op", async () => {
  assert.equal(await g.mirrorHostFirewalls(), null);
  assert.equal(await g.mirrorHostFirewalls([]), null);
});

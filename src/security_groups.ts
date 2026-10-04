/**
 * Security groups as things of their own: what each one lets in, who wears it (instances, and the other network
 * interfaces: databases, load balancers, Lambdas, endpoints), which of its rules something actually listens behind,
 * and which rules are trouble. Read by the inventory on every refresh (src/inventory.ts) next to the ingress rules
 * (`sg_ingress`, src/instance_apps.ts) and the network ACLs.
 *
 * One trouble is flagged as a recommendation (rule `sg_dormant_ipv6`, action `security_fix`, no saving): an IPv6
 * rule from anywhere in a VPC that has no IPv6. It lets nothing in today, which is why nobody notices it; the day
 * someone adds an IPv6 block to the VPC and a subnet hands out addresses, it opens at once. Only the dangerous
 * ones count: all traffic or a range wider than BROAD_RANGE, or a port the group does not open to the world over
 * IPv4 either (a mirror of a deliberate IPv4 rule, like 443 or a Lightning port, is not flagged).
 */
import { db } from "./db.js";
import { accountWhere, type AccountScope } from "./scope.js";
import { BROAD_RANGE, ingressRulesFor, ruleRef, type IngressRule, type RuleRef } from "./instance_apps.js";
import { upsertRecommendations } from "./collector.js";
import type { RecInput } from "./rules.js";

db.exec(`create table if not exists inventory_sg (
  group_id text primary key, group_name text, description text, vpc_id text, region text, account_id text, refreshed_at text not null
);
create table if not exists inventory_vpc (
  vpc_id text primary key, region text, account_id text, cidr_block text, is_default integer not null default 0, ipv6_blocks integer not null default 0, refreshed_at text not null
);
create table if not exists sg_eni (
  group_id text not null, eni_id text not null, interface_type text, description text, instance_id text, primary key (group_id, eni_id)
);`);

export const DORMANT_RULE = "sg_dormant_ipv6";

export interface SgRow { group_id: string; group_name: string | null; description: string | null; vpc_id: string | null; region: string | null; account_id: string | null }
export interface VpcRow { vpc_id: string; region: string | null; account_id: string | null; cidr_block: string | null; is_default: boolean; ipv6_blocks: number }
export interface EniRow { eni_id: string; interface_type: string | null; description: string | null; instance_id: string | null; group_ids: string[] }

/** Replaces the groups, VPCs and interfaces the inventory read; each list only when it was read (null = that query failed). */
export function replaceSecurityGroups(groups: SgRow[] | null, vpcs: VpcRow[] | null, enis: EniRow[] | null): void {
  const at = new Date().toISOString();
  db.transaction(() => {
    if (groups) {
      db.prepare("delete from inventory_sg").run();
      const ins = db.prepare("insert into inventory_sg(group_id, group_name, description, vpc_id, region, account_id, refreshed_at) values (?, ?, ?, ?, ?, ?, ?)");
      for (const g of groups) ins.run(g.group_id, g.group_name, g.description, g.vpc_id, g.region, g.account_id, at);
    }
    if (vpcs) {
      db.prepare("delete from inventory_vpc").run();
      const ins = db.prepare("insert into inventory_vpc(vpc_id, region, account_id, cidr_block, is_default, ipv6_blocks, refreshed_at) values (?, ?, ?, ?, ?, ?, ?)");
      for (const v of vpcs) ins.run(v.vpc_id, v.region, v.account_id, v.cidr_block, v.is_default ? 1 : 0, v.ipv6_blocks, at);
    }
    if (enis) {
      db.prepare("delete from sg_eni").run();
      const ins = db.prepare("insert or ignore into sg_eni(group_id, eni_id, interface_type, description, instance_id) values (?, ?, ?, ?, ?)");
      for (const e of enis) for (const g of e.group_ids) ins.run(g, e.eni_id, e.interface_type, e.description, e.instance_id);
    }
  })();
}

/** Whether a VPC has an IPv6 block: true, false, or null when the VPC has not been read. */
export function vpcHasIpv6(vpcId: string | null | undefined): boolean | null {
  if (!vpcId) return null;
  const r = db.prepare("select ipv6_blocks from inventory_vpc where vpc_id = ?").get(vpcId) as { ipv6_blocks: number } | undefined;
  return r ? r.ipv6_blocks > 0 : null;
}

const protoOf = (p: string | null) => (p === "6" ? "tcp" : p === "17" ? "udp" : p);
const portsCovered = (outer: IngressRule, inner: IngressRule) => {
  const all = (r: IngressRule) => r.ip_protocol == null || r.ip_protocol === "-1";
  if (all(outer)) return true;
  if (all(inner) || protoOf(outer.ip_protocol) !== protoOf(inner.ip_protocol)) return false;
  const lo = (r: IngressRule) => (r.from_port == null || r.from_port === -1 ? 0 : r.from_port), hi = (r: IngressRule) => (r.to_port == null || r.to_port === -1 ? 65535 : r.to_port);
  return lo(outer) <= lo(inner) && hi(inner) <= hi(outer);
};

export interface DormantRule { ref: RuleRef; why: "broad" | "no_ipv4_twin" }

/**
 * The IPv6-from-anywhere rules of one group that would open something nobody chose the day the VPC gets IPv6: the
 * broad ones, and the ones whose ports the group does not also open to 0.0.0.0/0. Only for a VPC known to have no
 * IPv6 (in one that has it, the rule is live and the port view shows it as open). Pure.
 */
export function dormantIpv6Rules(rules: IngressRule[], vpcIpv6: boolean | null, names: Record<string, string> = {}): DormantRule[] {
  if (vpcIpv6 !== false) return [];
  const worldV4 = rules.filter((r) => r.cidr_ipv4 === "0.0.0.0/0");
  const out: DormantRule[] = [];
  for (const r of rules) {
    if (r.cidr_ipv6 !== "::/0") continue;
    const ref = ruleRef(r, names);
    if (ref.broad) out.push({ ref, why: "broad" });
    else if (!worldV4.some((v) => portsCovered(v, r))) out.push({ ref, why: "no_ipv4_twin" });
  }
  return out;
}

interface Member { instance_id: string; name: string | null; state: string | null }

function membersOf(groupId: string): { instances: Member[]; others: { eni_id: string; interface_type: string | null; description: string | null }[] } {
  const instances: Member[] = [];
  for (const r of db.prepare("select instance_id, name, state, snapshot from inventory_ec2 where gone = 0").all() as { instance_id: string; name: string | null; state: string | null; snapshot: string | null }[]) {
    try {
      const sgs = JSON.parse(r.snapshot || "{}")?.network?.security_groups ?? [];
      if ((Array.isArray(sgs) ? sgs : []).some((g: any) => (g?.GroupId ?? g) === groupId)) instances.push({ instance_id: r.instance_id, name: r.name, state: r.state });
    } catch { /* no snapshot */ }
  }
  const others = (db.prepare("select eni_id, interface_type, description from sg_eni where group_id = ? and (instance_id is null or instance_id = '')").all(groupId) as { eni_id: string; interface_type: string | null; description: string | null }[]);
  return { instances, others };
}

/** What each rule of a group lets reach: the listening ports behind it on the group's instances. */
function listenersBehind(rules: IngressRule[], instances: Member[]) {
  if (!instances.length) return new Map<number, { instance_id: string; name: string | null; port: number; proto: string; app: string | null; exposure: string }[]>();
  const ports = db.prepare(`select p.instance_id, p.port, p.proto, p.app_name, p.exposure, p.scope from instance_ports p where p.gone = 0 and p.instance_id in (${instances.map(() => "?").join(",")})`)
    .all(...instances.map((i) => i.instance_id)) as { instance_id: string; port: number; proto: string; app_name: string | null; exposure: string; scope: string }[];
  const name = new Map(instances.map((i) => [i.instance_id, i.name]));
  const out = new Map<number, { instance_id: string; name: string | null; port: number; proto: string; app: string | null; exposure: string }[]>();
  rules.forEach((r, i) => {
    const hits = ports.filter((p) => p.scope !== "loopback" && portsCovered(r, { ...r, ip_protocol: p.proto, from_port: p.port, to_port: p.port }));
    out.set(i, hits.map((p) => ({ instance_id: p.instance_id, name: name.get(p.instance_id) ?? null, port: p.port, proto: p.proto, app: p.app_name, exposure: p.exposure })));
  });
  return out;
}

export interface SgSummary {
  group_id: string; group_name: string | null; description: string | null; vpc_id: string | null; region: string | null; account_id: string | null;
  vpc_ipv6: boolean | null; rules: number; world_rules: number; broad_world: boolean; dormant_ipv6: number;
  instances: number; running: number; others: number; unattached: boolean; listening_open: number; recommendation_id: number | null;
}

/** Every security group of the scope (every account when null), the troubled ones first. */
export function listSecurityGroups(scope?: AccountScope | null): SgSummary[] {
  const a = accountWhere(scope);
  const groups = db.prepare(`select * from inventory_sg where ${a.sql}`).all(...a.params) as SgRow[];
  const recs = new Map((db.prepare("select resource, id from recommendations where rule = ? and status in ('open', 'approved', 'pending')").all(DORMANT_RULE) as { resource: string; id: number }[]).map((r) => [r.resource, r.id]));
  const out = groups.map((g) => {
    const rules = ingressRulesFor([g.group_id]);
    const names = { [g.group_id]: g.group_name ?? g.group_id };
    const refs = rules.map((r) => ruleRef(r, names));
    const vpcIpv6 = vpcHasIpv6(g.vpc_id);
    const m = membersOf(g.group_id);
    const behind = listenersBehind(rules, m.instances);
    const listeningOpen = new Set<string>();
    rules.forEach((r, i) => { if (r.cidr_ipv4 === "0.0.0.0/0" || (r.cidr_ipv6 === "::/0" && vpcIpv6 !== false)) for (const h of behind.get(i) ?? []) if (h.exposure === "internet") listeningOpen.add(`${h.instance_id}:${h.proto}:${h.port}`); });
    return {
      ...g, vpc_ipv6: vpcIpv6, rules: rules.length,
      world_rules: refs.filter((r) => r.world).length,
      broad_world: refs.some((r, i) => r.broad && (rules[i].cidr_ipv4 === "0.0.0.0/0" || vpcIpv6 !== false)),
      dormant_ipv6: dormantIpv6Rules(rules, vpcIpv6, names).length,
      instances: m.instances.length, running: m.instances.filter((i) => i.state === "running").length, others: m.others.length,
      unattached: m.instances.length === 0 && m.others.length === 0,
      listening_open: listeningOpen.size, recommendation_id: recs.get(g.group_id) ?? null,
    };
  });
  const score = (s: SgSummary) => (s.broad_world ? 8 : 0) + (s.dormant_ipv6 ? 4 : 0) + (s.listening_open ? 2 : 0) + (s.unattached ? 1 : 0);
  return out.sort((a, b) => score(b) - score(a) || b.listening_open - a.listening_open || String(a.group_name).localeCompare(String(b.group_name)));
}

/** One group: its rules in words with what listens behind each, its dormant IPv6 rules, and who wears it. */
export function securityGroupDetail(groupId: string) {
  const g = db.prepare("select * from inventory_sg where group_id = ?").get(groupId) as SgRow | undefined;
  const rules = ingressRulesFor([groupId]);
  if (!g && !rules.length) return null;
  const names: Record<string, string> = Object.fromEntries((db.prepare("select group_id, group_name from inventory_sg").all() as { group_id: string; group_name: string | null }[]).map((r) => [r.group_id, r.group_name ?? r.group_id]));
  const vpcIpv6 = vpcHasIpv6(g?.vpc_id);
  const m = membersOf(groupId);
  const behind = listenersBehind(rules, m.instances);
  const dormant = dormantIpv6Rules(rules, vpcIpv6, names);
  const dormantKey = new Set(dormant.map((d) => `${d.ref.ports}|${d.ref.source}`));
  const rows = rules.map((r, i) => {
    const ref = ruleRef(r, names);
    const v6 = Boolean(r.cidr_ipv6) && !r.cidr_ipv4;
    return { ...ref, ip_protocol: r.ip_protocol, from_port: r.from_port, to_port: r.to_port, ipv6: v6, inert: v6 && vpcIpv6 === false, dormant: dormantKey.has(`${ref.ports}|${ref.source}`),
      referenced_group_id: r.referenced_group_id, prefix_list_id: r.prefix_list_id, listeners: behind.get(i) ?? [] };
  }).sort((a, b) => Number(b.world) - Number(a.world) || Number(b.broad) - Number(a.broad) || a.ports.localeCompare(b.ports, undefined, { numeric: true }));
  const rec = db.prepare("select id, status from recommendations where rule = ? and resource = ? order by id desc limit 1").get(DORMANT_RULE, groupId) as { id: number; status: string } | undefined;
  return { group: g ?? { group_id: groupId, group_name: null, description: null, vpc_id: null, region: null, account_id: null }, vpc_ipv6: vpcIpv6, rules: rows, dormant, instances: m.instances, others: m.others, recommendation: rec ?? null };
}

/** The dormant-IPv6 recommendations the current groups warrant. */
export function dormantIpv6Recommendations(): RecInput[] {
  const out: RecInput[] = [];
  for (const g of db.prepare("select * from inventory_sg").all() as SgRow[]) {
    const rules = ingressRulesFor([g.group_id]);
    const names = { [g.group_id]: g.group_name ?? g.group_id };
    const dormant = dormantIpv6Rules(rules, vpcHasIpv6(g.vpc_id), names);
    if (!dormant.length) continue;
    const m = membersOf(g.group_id);
    // what would open: the ports something listens on behind the dormant rules, closed over IPv4 today
    const ids = m.instances.map((i) => i.instance_id);
    const listening = ids.length ? db.prepare(`select instance_id, port, proto, app_name, exposure from instance_ports where gone = 0 and scope <> 'loopback' and instance_id in (${ids.map(() => "?").join(",")})`).all(...ids) as { instance_id: string; port: number; proto: string; app_name: string | null; exposure: string }[] : [];
    const dormantRules = rules.filter((r) => dormant.some((d) => d.ref.rule_id ? d.ref.rule_id === r.rule_id : d.ref.ports === ruleRef(r, names).ports && r.cidr_ipv6 === "::/0"));
    const wouldOpen = listening.filter((p) => p.exposure !== "internet" && dormantRules.some((r) => portsCovered(r, { ...r, ip_protocol: p.proto, from_port: p.port, to_port: p.port })));
    const nameOf = new Map(m.instances.map((i) => [i.instance_id, i.name ?? i.instance_id]));
    const list = dormant.map((d) => `${d.ref.ports} from anywhere over IPv6${d.ref.rule_id ? ` (${d.ref.rule_id})` : ""}`).join("; ");
    const broad = dormant.some((d) => d.why === "broad");
    out.push({
      rule: DORMANT_RULE,
      title: `Dormant IPv6 rule ${broad ? "opens all traffic" : "opens a port IPv4 keeps closed"}: ${g.group_name ?? g.group_id}`,
      resource: g.group_id,
      resourceName: g.group_name ?? undefined,
      actionType: "security_fix",
      estMonthlySaving: null,
      tier: "approve",
      confidence: broad ? 0.9 : 0.75,
      rationale: [
        `${g.group_name ?? g.group_id} (${g.group_id}) allows ${list}.`,
        `The VPC${g.vpc_id ? ` ${g.vpc_id}` : ""} has no IPv6 block, so these rules let nothing in today and the port view shows the ports as closed.`,
        `The day IPv6 is added to the VPC and a subnet hands out addresses, they open at once${m.instances.length || m.others.length ? ` on everything that wears the group (${[m.instances.length ? `${m.instances.length} instance${m.instances.length === 1 ? "" : "s"}` : null, m.others.length ? `${m.others.length} other interface${m.others.length === 1 ? "" : "s"}` : null].filter(Boolean).join(", ")})` : ""}.`,
        wouldOpen.length ? `Listening now and closed over IPv4, so opened by them: ${wouldOpen.slice(0, 12).map((p) => `${p.port}/${p.proto}${p.app_name ? ` ${p.app_name}` : ""} on ${nameOf.get(p.instance_id)}`).join(", ")}${wouldOpen.length > 12 ? ` and ${wouldOpen.length - 12} more` : ""}.` : null,
        `Revoke ${dormant.length === 1 ? "the rule" : "the rules"} (aws ec2 revoke-security-group-ingress --group-id ${g.group_id} --security-group-rule-ids ${dormant.map((d) => d.ref.rule_id ?? "<rule id>").join(" ")}), or replace ${dormant.length === 1 ? "it" : "them"} with IPv6 rules for the ports meant to be public. If the group is created by a template, fix the template too or the rule comes back.`,
      ].filter(Boolean).join(" "),
      evidence: { group_id: g.group_id, group_name: g.group_name, vpc_id: g.vpc_id, region: g.region, account_id: g.account_id, rules: dormant.map((d) => ({ ...d.ref, why: d.why })), instances: m.instances, others: m.others.length, would_open: wouldOpen },
    });
  }
  return out;
}

/** Files the dormant-IPv6 recommendations and resolves the ones whose rule is gone. Called after every inventory refresh. */
export function syncSecurityGroupRecommendations(): { warranted: number; resolved: number } {
  if (!(db.prepare("select count(*) as n from inventory_vpc").get() as { n: number }).n) return { warranted: 0, resolved: 0 };
  const recs = dormantIpv6Recommendations();
  upsertRecommendations(0, recs, "rules", undefined, { reconcile: false });
  const seen = new Set(recs.map((r) => `${r.rule}:${r.resource}`));
  const open = db.prepare("select id, fingerprint from recommendations where status = 'open' and rule = ?").all(DORMANT_RULE) as { id: number; fingerprint: string }[];
  const gone = open.filter((r) => !seen.has(r.fingerprint));
  const upd = db.prepare("update recommendations set status = 'resolved', updated_at = datetime('now') where id = ?");
  db.transaction(() => { for (const r of gone) upd.run(r.id); })();
  return { warranted: recs.length, resolved: gone.length };
}

export { BROAD_RANGE };

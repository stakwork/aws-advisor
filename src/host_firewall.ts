import { createHash } from "node:crypto";
import { db } from "./db.js";
import type { ProbeFirewall, ProbeResult } from "./ssm.js";

/**
 * The host's own packet filter (apps probe 2.1): what `iptables-save` / `ip6tables-save` printed on the box, parsed here
 * into chains and rules, hashed into a ruleset id, and kept in two tables: `firewall_rulesets` (one row per distinct
 * ruleset, shared by every box that runs it) and `instance_firewall` (one row per box: which ruleset it runs now).
 * The graph mirrors a ruleset as one `AdvisorFilter {kind: 'host_firewall', id: 'hostfw:<sha256>'}` with its rules
 * (src/graph_host_firewall.ts), so two boxes with the same rules meet on one node and a box's ruleset change is a
 * `firewall_changed` instance app event.
 *
 * What goes into the hash (and becomes rule nodes): every rule of the `filter` table and the DNAT/REDIRECT rules of the
 * `nat` table (port publishing); `mangle`, `raw` and `security` are counted only. Comments and counters are not part of
 * it. Docker's container addresses are: they sit in the `filter` DOCKER chain as much as in nat, so two Docker boxes share
 * a ruleset only when their bridge addresses and published ports agree.
 */

export type FwFamily = "ipv4" | "ipv6";
export type FwDirection = "ingress" | "egress" | "forward" | "chain";
export type FwAction = "allow" | "deny" | "jump" | "return" | "nat" | "log" | "other";

export interface FwChain { family: FwFamily; table: string; name: string; policy: string | null; builtin: boolean; rules: number }
export interface FwRule {
  family: FwFamily; table: string; chain: string;
  /** 0-based position in its chain: the evaluation order. */
  index: number;
  /** INPUT and PREROUTING rules are ingress, OUTPUT and POSTROUTING egress, FORWARD forward; a user chain inherits the one direction that jumps to it, else `chain`. */
  direction: FwDirection;
  action: FwAction;
  target: string; target_args: string | null;
  /** tcp | udp | icmp | icmpv6 | any | the word as written (`!tcp` when negated). */
  protocol: string;
  from_port: number | null; to_port: number | null;
  /** A multiport list as written (`80,443,8000:8100`); from_port/to_port hold its first range. */
  ports: string | null; source_ports: string | null;
  source: string | null; source_negated: boolean;
  destination: string | null; destination_negated: boolean;
  in_interface: string | null; out_interface: string | null;
  states: string[];
  comment: string | null;
  /** The `-A` line as printed, the comment module removed. */
  raw: string;
}
export interface FwRuleset {
  id: string; backend: ProbeFirewall["backend"]; chains: FwChain[]; rules: FwRule[];
  /** Rules per table, every table. */
  tables: Record<string, number>;
  rule_count: number; graph_rules: number; truncated: boolean;
  /** What happens to an inbound packet no rule matched: the INPUT policy, or a trailing catch-all deny. */
  default_action: "allow" | "deny";
  input_policy: string | null; forward_policy: string | null; output_policy: string | null;
}

const BUILTIN_DIRECTION: Record<string, FwDirection> = { INPUT: "ingress", PREROUTING: "ingress", OUTPUT: "egress", POSTROUTING: "egress", FORWARD: "forward" };
const HASHED_TABLES = ["filter", "nat"];

/** Splits an iptables-save line on spaces, keeping a quoted argument (`--comment "a b"`) whole and unquoted. Pure. */
export function tokenize(line: string): string[] {
  const out: string[] = []; let cur = ""; let quoted = false; let has = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quoted) {
      if (c === "\\" && i + 1 < line.length) { cur += line[++i]; continue; }
      if (c === '"') { quoted = false; continue; }
      cur += c; continue;
    }
    if (c === '"') { quoted = true; has = true; continue; }
    if (c === " " || c === "\t") { if (cur || has) { out.push(cur); cur = ""; has = false; } continue; }
    cur += c;
  }
  if (cur || has) out.push(cur);
  return out;
}

const COMMENT_RE = /\s-m comment --comment (?:"(?:[^"\\]|\\.)*"|\S+)/g;
const portRange = (v: string): { from: number | null; to: number | null } => {
  const m = /^(\d+)(?::(\d+))?$/.exec(v.split(",")[0] ?? "");
  if (!m) return { from: null, to: null };
  return { from: Number(m[1]), to: Number(m[2] ?? m[1]) };
};
const actionOf = (target: string): FwAction => target === "ACCEPT" ? "allow" : target === "DROP" || target === "REJECT" ? "deny" : target === "RETURN" ? "return"
  : ["DNAT", "SNAT", "REDIRECT", "MASQUERADE", "NETMAP"].includes(target) ? "nat" : ["LOG", "NFLOG", "ULOG"].includes(target) ? "log" : "other";

/** One rule line (`-A CHAIN …`) parsed; `known` are the table's declared chains (a jump to one of them is `jump`). Pure. */
function parseRule(tokens: string[], raw: string, family: FwFamily, table: string, index: number, known: Set<string>): FwRule {
  const chain = tokens[1];
  const r: FwRule = { family, table, chain, index, direction: BUILTIN_DIRECTION[chain] ?? "chain", action: "other", target: "", target_args: null, protocol: "any", from_port: null, to_port: null, ports: null, source_ports: null,
    source: null, source_negated: false, destination: null, destination_negated: false, in_interface: null, out_interface: null, states: [], comment: null, raw };
  let neg = false;
  for (let i = 2; i < tokens.length; i++) {
    const t = tokens[i];
    if (t === "!") { neg = true; continue; }
    const next = tokens[i + 1];
    // the old inline negation: `-s ! 10.0.0.0/8`
    const val = (): string => { if (next === "!" && tokens[i + 2] !== undefined) { neg = true; i += 2; return tokens[i]; } i++; return next ?? ""; };
    switch (t) {
      case "-p": case "--protocol": { const p = val().toLowerCase(); r.protocol = (neg ? "!" : "") + (p === "all" ? "any" : p); break; }
      case "-s": case "--source": case "--src": r.source = val(); r.source_negated = neg; break;
      case "-d": case "--destination": case "--dst": r.destination = val(); r.destination_negated = neg; break;
      case "-i": case "--in-interface": r.in_interface = (neg ? "!" : "") + val(); break;
      case "-o": case "--out-interface": r.out_interface = (neg ? "!" : "") + val(); break;
      case "--dport": case "--destination-port": { const v = val(); const pr = portRange(v); r.from_port = pr.from; r.to_port = pr.to; break; }
      case "--dports": { const v = val(); r.ports = v; const pr = portRange(v); r.from_port = pr.from; r.to_port = pr.to; break; }
      case "--sport": case "--source-port": case "--sports": r.source_ports = val(); break;
      case "--ctstate": case "--state": r.states = val().split(",").map((s) => s.trim().toUpperCase()).filter(Boolean); break;
      case "--comment": r.comment = val(); break;
      case "-j": case "--jump": case "-g": case "--goto": {
        r.target = next ?? ""; const args = tokens.slice(i + 2);
        r.target_args = args.length ? args.join(" ") : null;
        r.action = known.has(r.target) ? "jump" : actionOf(r.target);
        i = tokens.length; break;
      }
      case "-m": case "--match": val(); break;
      default: if (next !== undefined && !next.startsWith("-") && next !== "!") i++; // an option with a value we do not read
    }
    neg = false;
  }
  return r;
}

/** iptables-save text (one family) as chains and rules: `*table`, `:CHAIN POLICY [counters]`, `-A CHAIN …`, `COMMIT`. Pure. */
export function parseIptablesSave(lines: string[], family: FwFamily): { chains: FwChain[]; rules: FwRule[] } {
  const chains: FwChain[] = []; const rules: FwRule[] = [];
  let table: string | null = null; let known = new Set<string>(); let pending: { tokens: string[]; raw: string }[] = [];
  const flush = () => {
    if (!table) { pending = []; return; }
    const perChain = new Map<string, number>();
    for (const p of pending) {
      const chain = p.tokens[1]; if (!chain) continue;
      const index = perChain.get(chain) ?? 0; perChain.set(chain, index + 1);
      rules.push(parseRule(p.tokens, p.raw, family, table, index, known));
    }
    for (const c of chains) if (c.table === table && c.family === family) c.rules = perChain.get(c.name) ?? 0;
    pending = [];
  };
  for (const line of lines) {
    const l = line.trim();
    if (!l || l.startsWith("#")) continue;
    if (l.startsWith("*")) { flush(); table = l.slice(1).trim().split(/\s+/)[0] || null; known = new Set(); continue; }
    if (l === "COMMIT") { flush(); table = null; continue; }
    if (!table) continue;
    if (l.startsWith(":")) {
      const t = l.slice(1).split(/\s+/); const name = t[0]; if (!name) continue;
      const policy = t[1] && t[1] !== "-" ? t[1] : null;
      known.add(name); chains.push({ family, table, name, policy, builtin: policy !== null, rules: 0 }); continue;
    }
    if (l.startsWith("-N ")) { const name = l.slice(3).trim().split(/\s+/)[0]; if (name && !known.has(name)) { known.add(name); chains.push({ family, table, name, policy: null, builtin: false, rules: 0 }); } continue; }
    if (l.startsWith("-A ") || l.startsWith("-I ")) {
      const raw = ("-A" + l.slice(2)).replace(COMMENT_RE, "").replace(/\s+/g, " ").trim();
      pending.push({ tokens: tokenize(l), raw }); continue;
    }
  }
  flush();
  inheritDirections(rules, chains);
  return { chains, rules };
}

/** A user chain takes the direction of the builtin chains that jump to it, when they agree; `chain` otherwise. Pure, in place. */
export function inheritDirections(rules: FwRule[], chains: FwChain[]): void {
  const key = (f: string, t: string) => `${f}|${t}`;
  type Group = { dirs: Map<string, Set<FwDirection>>; rules: FwRule[] };
  const groups = new Map<string, Group>();
  const groupOf = (k: string): Group => { let g = groups.get(k); if (!g) { g = { dirs: new Map(), rules: [] }; groups.set(k, g); } return g; };
  for (const c of chains) { const g = groupOf(key(c.family, c.table)); if (BUILTIN_DIRECTION[c.name]) g.dirs.set(c.name, new Set([BUILTIN_DIRECTION[c.name]])); }
  for (const r of rules) { const g = groupOf(key(r.family, r.table)); g.rules.push(r); if (BUILTIN_DIRECTION[r.chain] && !g.dirs.has(r.chain)) g.dirs.set(r.chain, new Set([BUILTIN_DIRECTION[r.chain]])); }
  for (const g of groups.values()) {
    let changed = true; let guard = 0;
    while (changed && guard++ < 100) {
      changed = false;
      for (const r of g.rules) {
        if (r.action !== "jump") continue;
        const from = g.dirs.get(r.chain); if (!from) continue;
        const to = g.dirs.get(r.target) ?? new Set<FwDirection>(); g.dirs.set(r.target, to);
        for (const d of from) if (!to.has(d)) { to.add(d); changed = true; }
      }
    }
    for (const r of g.rules) { if (BUILTIN_DIRECTION[r.chain]) continue; const d = g.dirs.get(r.chain); r.direction = d && d.size === 1 ? [...d][0] : "chain"; }
  }
}

/** Whether a rule becomes a node (and part of the ruleset hash): every filter rule, and the nat rules that publish a port. Pure. */
export const isGraphRule = (r: Pick<FwRule, "table" | "target">): boolean => r.table === "filter" || (r.table === "nat" && (r.target === "DNAT" || r.target === "REDIRECT"));

/** The text the ruleset id is the hash of: builtin policies then the graph rules, family by family, table by table, in order. Pure. */
export function normalizedText(chains: FwChain[], rules: FwRule[]): string {
  const out: string[] = [];
  for (const family of ["ipv4", "ipv6"] as const) for (const table of HASHED_TABLES) {
    for (const c of chains) if (c.family === family && c.table === table && c.builtin) out.push(`${family} ${table} :${c.name} ${c.policy}`);
    for (const r of rules) if (r.family === family && r.table === table && isGraphRule(r)) out.push(`${family} ${table} ${r.raw}`);
  }
  return out.join("\n");
}
export const rulesetId = (normalized: string): string => `hostfw:${createHash("sha256").update(normalized).digest("hex")}`;

const hasMatch = (r: FwRule) => r.protocol !== "any" || r.source != null || r.destination != null || r.in_interface != null || r.out_interface != null || r.from_port != null || r.ports != null || r.source_ports != null || r.states.length > 0;
const policyOf = (chains: FwChain[], name: string): string | null => (chains.find((c) => c.table === "filter" && c.name === name && c.family === "ipv4") ?? chains.find((c) => c.table === "filter" && c.name === name))?.policy ?? null;

/** What an inbound packet gets when nothing matches: a DROP/REJECT INPUT policy, or a trailing catch-all deny rule (the RHEL style). Pure. */
export function effectiveDefault(chains: FwChain[], rules: FwRule[]): "allow" | "deny" {
  const policy = policyOf(chains, "INPUT");
  if (policy === "DROP" || policy === "REJECT") return "deny";
  const input = rules.filter((r) => r.table === "filter" && r.chain === "INPUT" && r.family === "ipv4");
  const last = input[input.length - 1];
  return last && last.action === "deny" && !hasMatch(last) ? "deny" : "allow";
}

/** The probe's firewall section as a ruleset, or null when the box has no packet filter to speak of (no tool, or a tool with no tables loaded). Pure. */
export function rulesetOf(fw: ProbeFirewall): FwRuleset | null {
  if (!fw.available) return null;
  if (!fw.v4.length && !fw.v6.length && !fw.nft.length) return null;
  const v4 = parseIptablesSave(fw.v4, "ipv4"); const v6 = parseIptablesSave(fw.v6, "ipv6");
  const chains = [...v4.chains, ...v6.chains]; const rules = [...v4.rules, ...v6.rules];
  // an nft-only box (no iptables-save): the raw ruleset is hashed so the box still wears a filter node; its rules wait for an nft parser
  const normalized = chains.length ? normalizedText(chains, rules) : fw.nft.map((l) => `nft ${l.trim()}`).join("\n");
  const tables: Record<string, number> = {};
  for (const r of rules) tables[r.table] = (tables[r.table] ?? 0) + 1;
  return {
    id: rulesetId(normalized), backend: fw.backend, chains, rules, tables, rule_count: rules.length, graph_rules: rules.filter(isGraphRule).length,
    truncated: fw.oversize || fw.v4.length < fw.v4_lines || fw.v6.length < fw.v6_lines || fw.nft.length < fw.nft_lines,
    default_action: chains.length ? effectiveDefault(chains, rules) : "allow",
    input_policy: policyOf(chains, "INPUT"), forward_policy: policyOf(chains, "FORWARD"), output_policy: policyOf(chains, "OUTPUT"),
  };
}

// ---- storage ------------------------------------------------------------------------------------------------------------

db.exec(`create table if not exists firewall_rulesets (
  id text primary key, backend text, rules_json text not null, chains_json text not null, tables_json text not null,
  rule_count integer not null, graph_rules integer not null, default_action text not null, truncated integer not null default 0,
  input_policy text, forward_policy text, output_policy text,
  first_seen text not null, last_seen text not null
);
create table if not exists instance_firewall (
  instance_id text primary key, ruleset_id text, available integer not null default 0, backend text, truncated integer not null default 0,
  v4_lines integer, v6_lines integer, nft_lines integer, raw_v4 text, raw_v6 text, raw_nft text,
  collected_at text not null, first_seen text not null, changed_at text, probes integer not null default 1
);
create index if not exists instance_firewall_ruleset on instance_firewall(ruleset_id);
create table if not exists instance_app_events (
  id integer primary key autoincrement, instance_id text not null, name text not null, user text not null,
  event text not null, at text not null, details text
);
create index if not exists instance_app_events_instance on instance_app_events(instance_id, at);
create index if not exists instance_app_events_at on instance_app_events(at);`);

const upsertRuleset = db.prepare(`insert into firewall_rulesets(id, backend, rules_json, chains_json, tables_json, rule_count, graph_rules, default_action, truncated, input_policy, forward_policy, output_policy, first_seen, last_seen)
  values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  on conflict(id) do update set backend = coalesce(excluded.backend, backend), truncated = excluded.truncated, last_seen = excluded.last_seen`);
const upsertInstance = db.prepare(`insert into instance_firewall(instance_id, ruleset_id, available, backend, truncated, v4_lines, v6_lines, nft_lines, raw_v4, raw_v6, raw_nft, collected_at, first_seen, changed_at, probes)
  values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, null, 1)
  on conflict(instance_id) do update set changed_at = case when coalesce(ruleset_id, '') <> coalesce(excluded.ruleset_id, '') then excluded.collected_at else changed_at end,
    ruleset_id = excluded.ruleset_id, available = excluded.available, backend = excluded.backend, truncated = excluded.truncated, v4_lines = excluded.v4_lines, v6_lines = excluded.v6_lines, nft_lines = excluded.nft_lines,
    raw_v4 = excluded.raw_v4, raw_v6 = excluded.raw_v6, raw_nft = excluded.raw_nft, collected_at = excluded.collected_at, probes = probes + 1`);
const insertEvent = db.prepare("insert into instance_app_events(instance_id, name, user, event, at, details) values (?, ?, ?, ?, ?, ?)");

export interface RecordFirewallResult { available: boolean; ruleset_id: string | null; rules: number; graph_rules: number; changed: boolean; previous: string | null; truncated: boolean }

/**
 * Called for every stored probe that carries the firewall section (apps 2.1; an older document's row returns null). The
 * ruleset row is shared by every box with the same rules; the box's row says which one it runs. The first probe of a box
 * is silent; from the second on, a different ruleset id (a rule added or removed, the filter gone or back) is a
 * `firewall_changed` event under the name `firewall`. No alert: a Docker restart alone can change a box's ruleset.
 */
export function recordHostFirewall(instanceId: string, collectedAt: string, data: Pick<ProbeResult, "firewall">, _instanceName: string | null = null): RecordFirewallResult | null {
  const fw = data.firewall;
  if (!fw) return null;
  const rs = rulesetOf(fw);
  const res: RecordFirewallResult = { available: fw.available, ruleset_id: rs?.id ?? null, rules: rs?.rule_count ?? 0, graph_rules: rs?.graph_rules ?? 0, changed: false, previous: null, truncated: rs?.truncated ?? false };
  db.transaction(() => {
    const prev = db.prepare("select f.ruleset_id, r.rule_count from instance_firewall f left join firewall_rulesets r on r.id = f.ruleset_id where f.instance_id = ?").get(instanceId) as { ruleset_id: string | null; rule_count: number | null } | undefined;
    if (rs) upsertRuleset.run(rs.id, rs.backend, JSON.stringify(rs.rules), JSON.stringify(rs.chains), JSON.stringify(rs.tables), rs.rule_count, rs.graph_rules, rs.default_action, rs.truncated ? 1 : 0, rs.input_policy, rs.forward_policy, rs.output_policy, collectedAt, collectedAt);
    upsertInstance.run(instanceId, rs?.id ?? null, fw.available ? 1 : 0, fw.backend, rs?.truncated ? 1 : 0, fw.v4_lines, fw.v6_lines, fw.nft_lines, fw.v4.join("\n") || null, fw.v6.join("\n") || null, fw.nft.join("\n") || null, collectedAt, collectedAt);
    if (prev && (prev.ruleset_id ?? null) !== (rs?.id ?? null)) {
      res.changed = true; res.previous = prev.ruleset_id ?? null;
      insertEvent.run(instanceId, "firewall", "host", "firewall_changed", collectedAt, JSON.stringify({ from: prev.ruleset_id ?? null, to: rs?.id ?? null, rules_from: prev.rule_count ?? 0, rules_to: rs?.rule_count ?? 0, available: fw.available, backend: fw.backend }));
    }
    db.prepare("delete from firewall_rulesets where last_seen < datetime('now', '-180 days') and id not in (select ruleset_id from instance_firewall where ruleset_id is not null)").run();
  })();
  return res;
}

export interface StoredFirewall { instance_id: string; ruleset_id: string | null; available: boolean; backend: string | null; truncated: boolean; v4_lines: number; v6_lines: number; nft_lines: number; collected_at: string; first_seen: string; changed_at: string | null; probes: number }
const rowToStored = (r: any): StoredFirewall => ({ instance_id: String(r.instance_id), ruleset_id: r.ruleset_id ?? null, available: Boolean(r.available), backend: r.backend ?? null, truncated: Boolean(r.truncated), v4_lines: Number(r.v4_lines ?? 0), v6_lines: Number(r.v6_lines ?? 0), nft_lines: Number(r.nft_lines ?? 0), collected_at: String(r.collected_at), first_seen: String(r.first_seen), changed_at: r.changed_at ?? null, probes: Number(r.probes ?? 1) });

/** The firewall rows of the given boxes, or every box's. */
export function instanceFirewalls(instanceIds?: string[]): StoredFirewall[] {
  const rows = instanceIds ? db.prepare(`select * from instance_firewall where instance_id in (${instanceIds.map(() => "?").join(",")})`).all(...instanceIds) : db.prepare("select * from instance_firewall").all();
  return (rows as any[]).map(rowToStored);
}
/** One box's firewall row, with the raw text the probe printed. */
export function firewallOn(instanceId: string): (StoredFirewall & { raw_v4: string | null; raw_v6: string | null; raw_nft: string | null; ruleset: FwRuleset | null }) | null {
  const r = db.prepare("select * from instance_firewall where instance_id = ?").get(instanceId) as any;
  if (!r) return null;
  return { ...rowToStored(r), raw_v4: r.raw_v4 ?? null, raw_v6: r.raw_v6 ?? null, raw_nft: r.raw_nft ?? null, ruleset: r.ruleset_id ? rulesetById(r.ruleset_id) : null };
}
/** A stored ruleset, parsed rules and all. */
export function rulesetById(id: string): FwRuleset | null {
  const r = db.prepare("select * from firewall_rulesets where id = ?").get(id) as any;
  if (!r) return null;
  const json = (s: unknown, fallback: unknown) => { try { return typeof s === "string" ? JSON.parse(s) : fallback; } catch { return fallback; } };
  return { id: String(r.id), backend: r.backend ?? null, chains: json(r.chains_json, []), rules: json(r.rules_json, []), tables: json(r.tables_json, {}), rule_count: Number(r.rule_count ?? 0), graph_rules: Number(r.graph_rules ?? 0),
    truncated: Boolean(r.truncated), default_action: r.default_action === "deny" ? "deny" : "allow", input_policy: r.input_policy ?? null, forward_policy: r.forward_policy ?? null, output_policy: r.output_policy ?? null };
}
/** How many boxes run each ruleset now. */
export function rulesetAttachments(): Map<string, number> {
  return new Map((db.prepare("select ruleset_id, count(*) as n from instance_firewall where ruleset_id is not null group by ruleset_id").all() as { ruleset_id: string; n: number }[]).map((r) => [r.ruleset_id, Number(r.n)]));
}

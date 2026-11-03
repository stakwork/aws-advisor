import { createHash } from "node:crypto";
import { db } from "./db.js";
import type { ProbeFirewall, ProbeResult } from "./ssm.js";

/**
 * The host's own packet filter (apps probe 2.1): what `iptables-save` / `ip6tables-save` and `nft list ruleset` printed on
 * the box, parsed here into chains and rules (one shape for both), hashed into a ruleset id, and kept in two tables:
 * `firewall_rulesets` (one row per distinct ruleset, shared by every box that runs it) and `instance_firewall` (one row
 * per box: which ruleset it runs now). The graph mirrors a ruleset as one `AdvisorFilter {kind: 'host_firewall',
 * id: 'hostfw:<sha256>'}` with its rules (src/graph_host_firewall.ts), so two boxes with the same rules meet on one node
 * and a box's ruleset change is a `firewall_changed` instance app event.
 *
 * What goes into the hash (and becomes rule nodes): every rule of a filter chain (the iptables `filter` table; an nft
 * chain hooked with `type filter`, or reached from one) and the DNAT/REDIRECT rules of the nat chains (port publishing);
 * `mangle`, `raw`, `security` and the rest are counted only. Comments and counters are not part of it. Docker's container
 * addresses are: they sit in the `filter` DOCKER chain as much as in nat, so two Docker boxes share a ruleset only when
 * their bridge addresses and published ports agree.
 *
 * nftables: a box whose iptables is the nf_tables flavour keeps its tables in nf_tables too, so `nft list ruleset` prints
 * them again (`table ip filter` with the INPUT/FORWARD/OUTPUT chains); a table iptables-save already printed for the same
 * family is dropped from the nft text, and what remains (firewalld's `inet firewalld`, a hand-written `inet filter`, an
 * `inet` table beside Docker's ip ones) is parsed with its own chains. An nft rule is read for the same fields an
 * iptables rule gives: addresses (`ip saddr`, `ip6 daddr`, a `{ set }` or a named `@set` expanded to its elements),
 * ports (`tcp dport`, `th dport`), the protocol (`meta l4proto`, `ip protocol`, the header a port match names),
 * interfaces, conntrack states, the comment, and the verdict (accept, drop, reject, jump/goto, return, the nat
 * statements, log); whatever else a rule says stays in `raw`.
 */

/** `ip` is ipv4 and `ip6` ipv6 (the iptables families); `inet` is an nft table that sees both at once; the rest as nft names them. */
export type FwFamily = "ipv4" | "ipv6" | "inet" | "arp" | "bridge" | "netdev";
export type FwDirection = "ingress" | "egress" | "forward" | "chain";
export type FwAction = "allow" | "deny" | "jump" | "return" | "nat" | "log" | "other";
export type FwEngine = "iptables" | "nft";

export interface FwChain {
  family: FwFamily; table: string; name: string; policy: string | null; builtin: boolean; rules: number;
  /** The netfilter hook of a base chain (input, output, forward, prerouting, postrouting, ingress, egress), null for a user/regular chain. */
  hook: string | null;
  /** What the chain is for: the iptables table name (filter, nat, mangle ...), or the nft base chain type (filter, nat, route); a regular nft chain takes the type of the chains that jump to it. */
  type: string | null;
  engine: FwEngine;
}
export interface FwRule {
  family: FwFamily; table: string; chain: string;
  /** 0-based position in its chain: the evaluation order. */
  index: number;
  /** INPUT and PREROUTING rules are ingress, OUTPUT and POSTROUTING egress, FORWARD forward; a user chain inherits the one direction that jumps to it, else `chain`. */
  direction: FwDirection;
  action: FwAction;
  /** The iptables target (ACCEPT, DROP, a user chain, DNAT ...) or the nft verdict as written (accept, drop, reject, a chain name, dnat ...). */
  target: string; target_args: string | null;
  /** tcp | udp | icmp | icmpv6 | any | the word as written (`!tcp` when negated; `tcp,udp` for an nft set). */
  protocol: string;
  from_port: number | null; to_port: number | null;
  /** A multiport list as written (`80,443,8000:8100`; nft: `80,443,8000-8100`); from_port/to_port hold its first range. */
  ports: string | null; source_ports: string | null;
  source: string | null; source_negated: boolean;
  destination: string | null; destination_negated: boolean;
  in_interface: string | null; out_interface: string | null;
  states: string[];
  comment: string | null;
  /** The `-A` line as printed, the comment module removed; for nft the rule as `nft list ruleset` printed it, the comment statement removed. */
  raw: string;
  engine: FwEngine;
  /** The chain's type (see FwChain.type): what decides whether the rule is a filter rule, a nat rule or something else. */
  chain_type: string | null;
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
const BUILTIN_HOOK: Record<string, string> = { INPUT: "input", PREROUTING: "prerouting", OUTPUT: "output", POSTROUTING: "postrouting", FORWARD: "forward" };
/** The direction a netfilter hook gives the rules of its base chain (nft: `type filter hook input`; iptables: the builtin chain of that name). */
const HOOK_DIRECTION: Record<string, FwDirection> = { input: "ingress", prerouting: "ingress", ingress: "ingress", output: "egress", postrouting: "egress", egress: "egress", forward: "forward" };
const HASHED_TABLES = ["filter", "nat"];
/** The chain's type: the iptables table or the nft chain type (stored rows from before nft parsing have none: the table says). */
export const chainTypeOf = (c: Pick<FwChain, "table"> & { type?: string | null }): string => c.type ?? c.table;
const ruleTypeOf = (r: Pick<FwRule, "table"> & { chain_type?: string | null }): string => r.chain_type ?? r.table;

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
    source: null, source_negated: false, destination: null, destination_negated: false, in_interface: null, out_interface: null, states: [], comment: null, raw, engine: "iptables", chain_type: table };
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
      known.add(name); chains.push({ family, table, name, policy, builtin: policy !== null, rules: 0, hook: policy !== null ? BUILTIN_HOOK[name] ?? null : null, type: table, engine: "iptables" }); continue;
    }
    if (l.startsWith("-N ")) { const name = l.slice(3).trim().split(/\s+/)[0]; if (name && !known.has(name)) { known.add(name); chains.push({ family, table, name, policy: null, builtin: false, rules: 0, hook: null, type: table, engine: "iptables" }); } continue; }
    if (l.startsWith("-A ") || l.startsWith("-I ")) {
      const raw = ("-A" + l.slice(2)).replace(COMMENT_RE, "").replace(/\s+/g, " ").trim();
      pending.push({ tokens: tokenize(l), raw }); continue;
    }
  }
  flush();
  inheritDirections(rules, chains);
  return { chains, rules };
}

/** The direction a chain's hook gives it, for a base chain; the iptables builtin name when the chain was never declared (a truncated text). */
const baseDirection = (c: Pick<FwChain, "name" | "hook">): FwDirection | null => (c.hook ? HOOK_DIRECTION[c.hook] : undefined) ?? BUILTIN_DIRECTION[c.name] ?? null;

/** A user (regular) chain takes the direction of the base chains that jump to it, when they agree; `chain` otherwise. Pure, in place. */
export function inheritDirections(rules: FwRule[], chains: FwChain[]): void {
  const key = (f: string, t: string) => `${f}|${t}`;
  type Group = { dirs: Map<string, Set<FwDirection>>; base: Set<string>; rules: FwRule[] };
  const groups = new Map<string, Group>();
  const groupOf = (k: string): Group => { let g = groups.get(k); if (!g) { g = { dirs: new Map(), base: new Set(), rules: [] }; groups.set(k, g); } return g; };
  for (const c of chains) { const g = groupOf(key(c.family, c.table)); const d = baseDirection(c); if (d) { g.dirs.set(c.name, new Set([d])); g.base.add(c.name); } }
  for (const r of rules) { const g = groupOf(key(r.family, r.table)); g.rules.push(r); if (!g.dirs.has(r.chain) && BUILTIN_DIRECTION[r.chain]) { g.dirs.set(r.chain, new Set([BUILTIN_DIRECTION[r.chain]])); g.base.add(r.chain); } }
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
    for (const r of g.rules) { if (g.base.has(r.chain)) { r.direction = [...g.dirs.get(r.chain)!][0]; continue; } const d = g.dirs.get(r.chain); r.direction = d && d.size === 1 ? [...d][0] : "chain"; }
  }
}

/** An nft regular chain is a filter chain when a filter base chain jumps to it, a nat chain when a nat one does (the first to reach it wins). Pure, in place. */
export function inheritChainTypes(rules: FwRule[], chains: FwChain[]): void {
  const key = (f: string, t: string) => `${f}|${t}`;
  const types = new Map<string, string>();
  for (const c of chains) if (c.hook && c.type) types.set(`${key(c.family, c.table)}|${c.name}`, c.type);
  let changed = true; let guard = 0;
  while (changed && guard++ < 100) {
    changed = false;
    for (const r of rules) {
      if (r.action !== "jump") continue;
      const from = types.get(`${key(r.family, r.table)}|${r.chain}`); const tk = `${key(r.family, r.table)}|${r.target}`;
      if (from && !types.has(tk)) { types.set(tk, from); changed = true; }
    }
  }
  for (const c of chains) if (!c.hook) c.type = types.get(`${key(c.family, c.table)}|${c.name}`) ?? null;
  for (const r of rules) r.chain_type = types.get(`${key(r.family, r.table)}|${r.chain}`) ?? null;
}

const NAT_PUBLISH = new Set(["DNAT", "REDIRECT", "dnat", "redirect"]);
/** Whether a rule becomes a node (and part of the ruleset hash): every filter rule, and the nat rules that publish a port. Pure. */
export const isGraphRule = (r: Pick<FwRule, "table" | "target"> & { chain_type?: string | null }): boolean => { const t = ruleTypeOf(r); return t === "filter" || (t === "nat" && NAT_PUBLISH.has(r.target)); };

const FAMILY_ORDER: FwFamily[] = ["ipv4", "ipv6", "inet", "arp", "bridge", "netdev"];
/**
 * The text the ruleset id is the hash of: the iptables tables first (builtin policies then the graph rules, ipv4 then ipv6, filter then
 * nat, rules in order), then every nft table sorted by family and name (base chains with their hook and policy, then the graph rules chain
 * by chain, chains by name: `nft list ruleset` prints tables and chains in creation order, which two boxes with the same rules need not share).
 * An iptables-only ruleset hashes exactly as it did before nft parsing. Pure.
 */
export function normalizedText(chains: FwChain[], rules: FwRule[]): string {
  const out: string[] = [];
  for (const family of ["ipv4", "ipv6"] as const) for (const table of HASHED_TABLES) {
    for (const c of chains) if (c.engine !== "nft" && c.family === family && c.table === table && c.builtin) out.push(`${family} ${table} :${c.name} ${c.policy}`);
    for (const r of rules) if (r.engine !== "nft" && r.family === family && r.table === table && isGraphRule(r)) out.push(`${family} ${table} ${r.raw}`);
  }
  const nftTables = [...new Set(chains.filter((c) => c.engine === "nft").map((c) => `${c.family}|${c.table}`))]
    .sort((a, b) => FAMILY_ORDER.indexOf(a.split("|")[0] as FwFamily) - FAMILY_ORDER.indexOf(b.split("|")[0] as FwFamily) || a.localeCompare(b));
  for (const key of nftTables) {
    const [family, table] = key.split("|");
    const tchains = chains.filter((c) => c.engine === "nft" && c.family === family && c.table === table).sort((a, b) => a.name.localeCompare(b.name));
    for (const c of tchains) if (c.hook) out.push(`nft ${family} ${table} :${c.name} ${c.type} ${c.hook} ${c.policy ?? "-"}`);
    for (const c of tchains) for (const r of rules) if (r.engine === "nft" && r.family === family && r.table === table && r.chain === c.name && isGraphRule(r)) out.push(`nft ${family} ${table} ${c.name} ${r.raw}`);
  }
  return out.join("\n");
}
export const rulesetId = (normalized: string): string => `hostfw:${createHash("sha256").update(normalized).digest("hex")}`;

const hasMatch = (r: FwRule) => r.protocol !== "any" || r.source != null || r.destination != null || r.in_interface != null || r.out_interface != null || r.from_port != null || r.ports != null || r.source_ports != null || r.states.length > 0;
const familyRank = (f: FwFamily) => (f === "ipv4" ? 0 : f === "inet" ? 1 : f === "ipv6" ? 2 : 3);
/** The filter base chains on a hook, the ipv4 one first, then inet (an nft table that sees both families), then ipv6. */
const hookChains = (chains: FwChain[], hook: string): FwChain[] => chains.filter((c) => chainTypeOf(c) === "filter" && (c.hook ?? BUILTIN_HOOK[c.name]) === hook).sort((a, b) => familyRank(a.family) - familyRank(b.family));
const policyOf = (chains: FwChain[], hook: string): string | null => hookChains(chains, hook)[0]?.policy ?? null;
const denies = (policy: string | null) => policy === "DROP" || policy === "REJECT" || policy === "drop" || policy === "reject";

/**
 * What an inbound IPv4 packet gets when nothing matches: deny when an input filter chain it passes (the iptables INPUT, an nft `inet` or
 * `ip` input hook: with both, a packet must satisfy each) has a DROP/REJECT policy or ends in a catch-all deny rule (the RHEL style). Pure.
 */
export function effectiveDefault(chains: FwChain[], rules: FwRule[]): "allow" | "deny" {
  const input = hookChains(chains, "input"); const v4 = input.filter((c) => c.family !== "ipv6");
  for (const c of v4.length ? v4 : input) {
    if (denies(c.policy)) return "deny";
    const own = rules.filter((r) => r.family === c.family && r.table === c.table && r.chain === c.name);
    const last = own[own.length - 1];
    if (last && last.action === "deny" && !hasMatch(last)) return "deny";
  }
  return "allow";
}

/** The probe's firewall section as a ruleset, or null when the box has no packet filter to speak of (no tool, or a tool with no tables loaded). Pure. */
export function rulesetOf(fw: ProbeFirewall): FwRuleset | null {
  if (!fw.available) return null;
  if (!fw.v4.length && !fw.v6.length && !fw.nft.length) return null;
  const v4 = parseIptablesSave(fw.v4, "ipv4"); const v6 = parseIptablesSave(fw.v6, "ipv6");
  const nft = parseNftRuleset(fw.nft);
  // iptables-nft keeps its tables in nf_tables, so `nft list ruleset` prints them again (`table ip filter` ...): a table iptables-save already printed is read once
  const printed = new Set([...v4.chains, ...v6.chains].map((c) => `${c.family}|${c.table}`));
  const own = (x: { family: FwFamily; table: string }) => !printed.has(`${x.family}|${x.table}`);
  const chains = [...v4.chains, ...v6.chains, ...nft.chains.filter(own)]; const rules = [...v4.rules, ...v6.rules, ...nft.rules.filter(own)];
  // an nft text no chain could be read from (a cut too early, a format this parser does not know): the raw lines are hashed so the box still wears a filter node
  const normalized = chains.length ? normalizedText(chains, rules) : fw.nft.map((l) => `nft ${l.trim()}`).join("\n");
  const tables: Record<string, number> = {};
  for (const r of rules) tables[r.table] = (tables[r.table] ?? 0) + 1;
  return {
    id: rulesetId(normalized), backend: fw.backend, chains, rules, tables, rule_count: rules.length, graph_rules: rules.filter(isGraphRule).length,
    truncated: fw.oversize || fw.v4.length < fw.v4_lines || fw.v6.length < fw.v6_lines || fw.nft.length < fw.nft_lines,
    default_action: chains.length ? effectiveDefault(chains, rules) : "allow",
    input_policy: policyOf(chains, "input"), forward_policy: policyOf(chains, "forward"), output_policy: policyOf(chains, "output"),
  };
}

// ---- nftables -----------------------------------------------------------------------------------------------------------

const NFT_FAMILY: Record<string, FwFamily> = { ip: "ipv4", ip6: "ipv6", inet: "inet", arp: "arp", bridge: "bridge", netdev: "netdev" };
const NFT_OPS = new Set(["!=", "==", "<", ">", "<=", ">=", "eq", "ne", "lt", "gt", "le", "ge"]);
const NFT_COMMENT_RE = /\s*\bcomment (?:"(?:[^"\\]|\\.)*"|\S+)/g;
const NFT_NOISE_RE = /\s*counter packets \d+ bytes \d+|\s*# (?:handle \d+|progname \S+)\s*$/g;
/** What a rule does with a packet, by its last verdict statement. */
const nftActionOf = (verdict: string): FwAction => verdict === "accept" ? "allow" : verdict === "drop" || verdict === "reject" ? "deny" : verdict === "return" ? "return"
  : verdict === "jump" || verdict === "goto" ? "jump" : ["dnat", "snat", "redirect", "masquerade"].includes(verdict) ? "nat" : "other";

/** Braces outside quotes: how much deeper the line leaves the text (a multi-line set, a chain body). Pure. */
function braceDelta(line: string): number {
  let d = 0; let q = false;
  for (let i = 0; i < line.length; i++) { const c = line[i]; if (q) { if (c === "\\") i++; else if (c === '"') q = false; continue; } if (c === '"') q = true; else if (c === "{") d++; else if (c === "}") d--; }
  return d;
}

/** An nft rule's tokens: quoted strings whole and unquoted, a `{ a, b }` set one token `{a,b}` (`{ 80 : accept, 22 : jump x }` keeps its `:`). Pure. */
export function tokenizeNft(line: string): string[] {
  const t = tokenize(line); const out: string[] = [];
  for (let i = 0; i < t.length; i++) {
    if (t[i] !== "{") { out.push(t[i]); continue; }
    const inner: string[] = []; let depth = 1; let j = i + 1;
    for (; j < t.length; j++) { if (t[j] === "{") depth++; else if (t[j] === "}" && --depth === 0) break; inner.push(t[j]); }
    out.push(`{${inner.join(" ").replace(/\s*,\s*/g, ",").replace(/ \. /g, ".").replace(/ : /g, ":").trim()}}`); i = j;
  }
  return out;
}

const nftPortRange = (v: string): { from: number | null; to: number | null } => {
  const m = /^(\d+)(?:-(\d+))?$/.exec(v.split(",")[0] ?? "");
  return m ? { from: Number(m[1]), to: Number(m[2] ?? m[1]) } : { from: null, to: null };
};
/** nft prints a host address bare; the graph's sources are CIDRs, so it gets its full mask. */
const withMask = (v: string): string => /^\d+\.\d+\.\d+\.\d+$/.test(v) ? `${v}/32` : /^[0-9a-f:]*:[0-9a-f:]*$/i.test(v) ? `${v}/128` : v;
const addrList = (v: string): string => v.split(",").map((a) => withMask(a.trim())).join(",");

type NftValue = { v: string; neg: boolean; next: number; map: boolean };

/** One nft rule (the body of a line inside a chain) read for the fields an iptables rule gives; what it does not read stays in `raw`. Pure. */
export function parseNftRule(tokens: string[], raw: string, chain: FwChain, index: number): FwRule {
  const r: FwRule = { family: chain.family, table: chain.table, chain: chain.name, index, direction: baseDirection(chain) ?? "chain", action: "other", target: "", target_args: null, protocol: "any",
    from_port: null, to_port: null, ports: null, source_ports: null, source: null, source_negated: false, destination: null, destination_negated: false, in_interface: null, out_interface: null,
    states: [], comment: null, raw, engine: "nft", chain_type: chain.hook ? chain.type : null };
  // nft prints the comment last: it is read here and the rule ends before it, so a terminal statement (reject, dnat) keeps nothing of it
  const ci = tokens.lastIndexOf("comment"); if (ci >= 0) { r.comment = tokens[ci + 1] ?? null; tokens = tokens.slice(0, ci); }
  const n = tokens.length;
  // the value a match compares with, after an optional operator: `22`, `!= 22`, `{80,443}` (braces dropped), `@set`, `& (syn|rst) == syn`; `vmap {...}` and `map {...}` are flagged
  const value = (i: number): NftValue | null => {
    let j = i; let neg = false;
    if (j < n && tokens[j] === "&") { while (j < n && !NFT_OPS.has(tokens[j])) j++; }
    if (j < n && NFT_OPS.has(tokens[j])) { neg = tokens[j] === "!=" || tokens[j] === "ne"; j++; }
    if (j >= n) return null;
    const map = tokens[j] === "vmap" || tokens[j] === "map";
    if (map) j++;
    if (j >= n) return null;
    let v = tokens[j];
    if (v.startsWith("{") && v.endsWith("}")) v = v.slice(1, -1);
    return { v, neg, next: j + 1, map };
  };
  let verdict: string | null = null; let sawLog = false; let lastStatement: string | null = null;
  const mapVerdict = (x: NftValue) => { verdict = "vmap"; r.target = "vmap"; r.target_args = x.v || null; };
  const matched = (i: number, apply: (x: NftValue) => void, skip: number): number => { const x = value(i); if (!x) return skip; if (x.map) mapVerdict(x); else apply(x); return x.next; };
  const sign = (x: NftValue) => (x.neg ? "!" : "");
  const rest = (from: number): string | null => (from < n ? tokens.slice(from).join(" ") : null);
  let i = 0;
  while (i < n) {
    const t = tokens[i]; const k = tokens[i + 1];
    switch (t) {
      case "ip": case "ip6":
        if (k === "saddr") i = matched(i + 2, (x) => { r.source = addrList(x.v); r.source_negated = x.neg; }, i + 2);
        else if (k === "daddr") i = matched(i + 2, (x) => { r.destination = addrList(x.v); r.destination_negated = x.neg; }, i + 2);
        else if (k === "protocol" || k === "nexthdr") i = matched(i + 2, (x) => { r.protocol = sign(x) + x.v; }, i + 2);
        else i = matched(i + 2, () => {}, i + 2); // ip ttl, ip6 hoplimit, ip length, ip dscp ... (a `set` statement would be caught below as a word)
        break;
      case "tcp": case "udp": case "udplite": case "sctp": case "dccp": case "th":
        if (t !== "th" && r.protocol === "any") r.protocol = t;
        if (k === "dport") i = matched(i + 2, (x) => { if (x.neg) { r.ports = "!" + x.v; } else { const pr = nftPortRange(x.v); r.from_port = pr.from; r.to_port = pr.to; if (x.v.includes(",") || pr.from == null) r.ports = x.v; } }, i + 2);
        else if (k === "sport") i = matched(i + 2, (x) => { r.source_ports = sign(x) + x.v; }, i + 2);
        else if (k === "option" && tokens[i + 2]) i = matched(i + 3, () => {}, i + 3); // tcp option maxseg size 1460
        else i = matched(i + 2, () => {}, i + 2); // tcp flags syn
        break;
      case "icmp": case "icmpv6":
        if (r.protocol === "any") r.protocol = t;
        i = matched(i + 2, () => {}, i + 2); // icmp type echo-request, icmpv6 code ...
        break;
      case "meta":
        if (tokens[i + 2] === "set") { lastStatement = "meta"; i += 4; break; }
        if (k === "l4proto") i = matched(i + 2, (x) => { r.protocol = sign(x) + x.v; }, i + 2);
        else if (k === "iifname" || k === "iif") i = matched(i + 2, (x) => { r.in_interface = sign(x) + x.v; }, i + 2);
        else if (k === "oifname" || k === "oif") i = matched(i + 2, (x) => { r.out_interface = sign(x) + x.v; }, i + 2);
        else i = matched(i + 2, () => {}, i + 2); // meta nfproto ipv4, meta mark, meta pkttype, meta skuid ...
        break;
      case "iif": case "iifname": i = matched(i + 1, (x) => { r.in_interface = sign(x) + x.v; }, i + 1); break;
      case "oif": case "oifname": i = matched(i + 1, (x) => { r.out_interface = sign(x) + x.v; }, i + 1); break;
      case "ct":
        if (tokens[i + 2] === "set") { lastStatement = "ct"; i += 4; break; } // ct mark set 0x1, ct helper set "ftp", ct zone set 1
        if (k === "state") i = matched(i + 2, (x) => { r.states = x.v.split(",").map((s) => (x.neg ? "!" : "") + s.trim().toUpperCase()).filter((s) => s && s !== "!"); }, i + 2);
        else i = matched(i + 2, () => {}, i + 2); // ct status dnat, ct mark, ct direction, ct helper "ftp" ...
        break;
      case "fib": { // fib daddr type local, fib saddr . iif oif missing
        let j = i + 1; while (j < n && (tokens[j] === "." || ["saddr", "daddr", "mark", "iif", "oif", "type", "oifname", "check"].includes(tokens[j]))) j++;
        i = matched(j, () => {}, j); break;
      }
      case "ether": case "arp": case "vlan": case "rt": case "ipsec": case "exthdr": case "osf": case "socket": case "ah": case "esp": case "comp": case "frag": case "dst": case "hbh": case "mh":
        i = matched(i + 2, () => {}, i + 2); break; // ether saddr aa:bb:..., vlan id 10, arp operation request
      case "limit": { // limit rate [over] N/second [burst N packets]
        let j = i + 1; if (tokens[j] === "rate") j++; if (tokens[j] === "over") j++; j++; if (tokens[j] === "burst") j += 3;
        lastStatement = "limit"; i = j; break;
      }
      case "log": case "nflog": {
        sawLog = true; lastStatement = t; let j = i + 1;
        while (j < n && ["prefix", "level", "group", "snaplen", "queue-threshold", "flags"].includes(tokens[j])) j += 2;
        i = j; break;
      }
      case "counter": { let j = i + 1; if (tokens[j] === "name") j += 2; else { if (tokens[j] === "packets") j += 2; if (tokens[j] === "bytes") j += 2; } lastStatement ??= "counter"; i = j; break; }
      case "comment": r.comment = k ?? null; i += 2; break;
      case "xt": i += 3; break; // `xt match "x"`, `xt target "X"`: an iptables-nft match nft has no words for
      case "accept": case "drop": case "continue": case "return": verdict = t; r.target = t; r.target_args = null; i += 1; break;
      case "reject": verdict = t; r.target = t; r.target_args = rest(i + 1); i = n; break; // reject with icmp type host-prohibited: terminal
      case "jump": case "goto": verdict = t; r.target = k ?? ""; r.target_args = t === "goto" ? "goto" : null; i += 2; break;
      case "dnat": case "snat": case "redirect": case "masquerade": verdict = t; r.target = t; r.target_args = rest(i + 1); i = n; break; // dnat to 172.17.0.2:80: terminal
      case "vmap": case "map": i = matched(i, () => {}, i + 1); break;
      case "queue": case "dup": case "fwd": case "tproxy": case "synproxy": case "notrack": case "flow": case "set": case "update": case "add": case "delete": case "secmark":
        lastStatement ??= t; i += 1; break;
      default: lastStatement ??= t; i += 1;
    }
  }
  if (verdict) r.action = nftActionOf(verdict);
  else { r.action = sawLog ? "log" : "other"; r.target = sawLog ? "log" : lastStatement ?? ""; }
  return r;
}

/** The elements of a set or map block (`elements = { a, b, c }`, over one line or many), each without its comment or timeout. Pure. */
export function nftSetElements(blockText: string): string[] {
  const m = /elements = \{([^}]*)\}/.exec(blockText);
  if (!m) return [];
  return m[1].split(",").map((e) => e.replace(/\bcomment (?:"(?:[^"\\]|\\.)*"|\S+)/, "").replace(/\b(?:timeout|expires) \S+/g, "").replace(/\s+/g, " ").trim()).filter(Boolean);
}

/**
 * `nft list ruleset` text as chains and rules: `table <family> <name> {`, `chain <name> {` with its `type <t> hook <h> ... priority <p>; policy <p>;`
 * line, the rules, and the set/map/flowtable/counter blocks (sets kept, to expand the `@name` a rule points at). Tolerates the counters and
 * handles the probe strips, a text cut mid-block, and statements it has no reading for (they stay in the rule's `raw`). Pure.
 */
export function parseNftRuleset(lines: string[]): { chains: FwChain[]; rules: FwRule[]; sets: Map<string, string[]> } {
  const chains: FwChain[] = []; const rules: FwRule[] = []; const sets = new Map<string, string[]>();
  let depth = 0; let table: { family: FwFamily; name: string } | null = null; let chain: FwChain | null = null; let index = 0;
  let block: { until: number; set: string | null; text: string[] } | null = null;
  const BLOCK_RE = /^(set|map|flowtable|counter|quota|limit|ct helper|ct timeout|ct expectation|secmark|synproxy) (\S+)\s*\{/;
  for (const line of lines) {
    const l = line.replace(NFT_NOISE_RE, "").trim();
    if (!l || l.startsWith("#")) continue;
    const d = braceDelta(l);
    if (block) {
      block.text.push(l); depth = Math.max(0, depth + d);
      if (depth <= block.until) { if (block.set && table) sets.set(`${table.family}|${table.name}|${block.set}`, nftSetElements(block.text.join(" "))); block = null; }
      continue;
    }
    if (depth === 0 || !table) {
      const m = /^table (\S+) (\S+)\s*\{/.exec(l);
      if (m) { table = { family: NFT_FAMILY[m[1]] ?? (m[1] as FwFamily), name: m[2] }; chain = null; depth = 1; continue; }
      depth = Math.max(0, depth + d); continue;
    }
    if (depth === 1) {
      let m: RegExpExecArray | null;
      if ((m = /^chain (\S+)\s*\{/.exec(l))) {
        chain = { family: table.family, table: table.name, name: m[1], policy: null, builtin: false, rules: 0, hook: null, type: null, engine: "nft" }; chains.push(chain); index = 0;
        depth = Math.max(0, depth + d); if (depth < 2) chain = null; continue;
      }
      if ((m = BLOCK_RE.exec(l))) { block = { until: 1, set: m[1] === "set" || m[1] === "map" ? m[2] : null, text: [l] }; depth = Math.max(0, depth + d); if (depth <= 1) { if (block.set) sets.set(`${table.family}|${table.name}|${block.set}`, nftSetElements(l)); block = null; } continue; }
      depth = Math.max(0, depth + d); if (depth === 0) table = null; continue; // `}` closing the table; `comment "..."`, `flags dormant;`
    }
    if (depth === 2 && chain) {
      let m: RegExpExecArray | null;
      if ((m = /^type (\S+) hook (\S+)/.exec(l))) { chain.type = m[1]; chain.hook = m[2]; chain.builtin = true; const p = /\bpolicy (\w+)/.exec(l); if (p) chain.policy = p[1]; depth = Math.max(0, depth + d); continue; }
      if ((m = /^policy (\w+)/.exec(l))) { chain.policy = m[1]; continue; }
      if (/^(flags|comment|devices?) /.test(l)) continue;
      if (d < 0) { depth = Math.max(0, depth + d); chain = null; continue; } // `}` closing the chain
      const raw = l.replace(NFT_COMMENT_RE, "").replace(/\s+/g, " ").trim();
      rules.push(parseNftRule(tokenizeNft(l), raw, chain, index++)); chain.rules = index;
      depth = Math.max(0, depth + d); continue;
    }
    depth = Math.max(0, depth + d);
  }
  // a rule that names a set (`tcp dport @ports`, `ip saddr @office`) gets its elements, when the text carried them
  for (const r of rules) {
    const expand = (v: string | null): string | null => { if (!v) return v; const m = /^(!?)@(\S+)$/.exec(v); if (!m) return v; const els = sets.get(`${r.family}|${r.table}|${m[2]}`); return els?.length ? m[1] + els.join(",") : v; };
    const src = expand(r.source); if (src !== r.source) r.source = addrList(src!);
    const dst = expand(r.destination); if (dst !== r.destination) r.destination = addrList(dst!);
    const ports = expand(r.ports); if (ports !== r.ports && ports && !ports.startsWith("!")) { r.ports = ports; const pr = nftPortRange(ports); r.from_port = pr.from; r.to_port = pr.to; } else if (ports !== r.ports) r.ports = ports;
    r.source_ports = expand(r.source_ports);
    if (r.protocol.startsWith("@") || r.protocol.startsWith("!@")) r.protocol = expand(r.protocol) ?? r.protocol;
  }
  inheritChainTypes(rules, chains);
  inheritDirections(rules, chains);
  return { chains, rules, sets };
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

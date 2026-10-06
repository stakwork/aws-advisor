import { Fragment, useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../api";
import { Badge, Button, Card, Empty, Pager, Stat, Td, Th } from "../components/ui";

/**
 * The network layer as the graph holds it (docs/cloud-ontology.md §3, src/graph_network.ts), laid out like the
 * Inventory: one tab per category. Exposed and Blocked are the verdicts (the same REACHABLE_FROM / ALLOWED_BY /
 * BLOCKED_BY edges the agent's graph_query tool reads); Networks, Segments, Gateways, Interfaces, Public IPs and
 * Filters are the objects they are computed from. Everything is read from Neo4j.
 */

const TABS = ["exposed", "blocked", "networks", "segments", "gateways", "filters", "interfaces", "ips"] as const;
type Tab = (typeof TABS)[number];
const TAB_LABEL: Record<Tab, string> = { exposed: "Exposed", blocked: "Blocked", networks: "Networks", segments: "Segments", gateways: "Gateways", filters: "Filters", interfaces: "Interfaces", ips: "Public IPs" };
const PAGE = 50;

const short = (id: string | null | undefined, n = 28) => { const s = String(id ?? ""); return s.length > n ? `${s.slice(0, n)}…` : s; };
const exposureTone: Record<string, string> = { internet: "text-red-300", network: "text-amber-300", group: "text-amber-200", closed: "text-zinc-400", local: "text-zinc-500" };
const portsOf = (r: { from_port: number | null; to_port: number | null; protocol: string }) => r.from_port == null ? `all ${r.protocol}` : r.from_port === r.to_port ? `${r.protocol} ${r.from_port}` : `${r.protocol} ${r.from_port}-${r.to_port}`;
const INVENTORY_TAB: Record<string, string> = { AdvisorCompute: "ec2", AdvisorDatabase: "rds", AdvisorCache: "elasticache", AdvisorLoadBalancer: "elb", AdvisorFunction: "lambda", AdvisorStorage: "s3", AdvisorDeployment: "deployments" };
/** A resource by name, linked into the Inventory tab that holds it. */
function Res({ id, name, label }: { id: string | null | undefined; name?: string | null; label?: string | null }) {
  if (!id) return <span className="text-zinc-600">—</span>;
  const tab = label ? INVENTORY_TAB[label] : undefined;
  const text = name || short(id, 40);
  return tab ? <Link className="underline" to={`/inventory?tab=${tab}&id=${encodeURIComponent(id)}`}>{text}</Link> : <span>{text}</span>;
}
const kindWord = (label: string | null | undefined) => String(label || "").replace("Advisor", "").replace(/([a-z])([A-Z])/g, "$1 $2").toLowerCase();

/** One filter's rules, where each lets traffic in from, and what wears it; fetched when a filter row opens. */
function FilterPanel({ id }: { id: string }) {
  const [d, setD] = useState<any>(null);
  useEffect(() => { setD(null); api(`/graph/filter/${encodeURIComponent(id)}`).then(setD).catch((e) => setD({ error: e.message })); }, [id]);
  if (!d) return <div className="text-xs text-zinc-500">Loading the rules…</div>;
  if (d.error) return <div className="text-xs text-red-300">{d.error}</div>;
  const f = d.filter;
  return (
    <div className="space-y-2 text-xs">
      <div className="text-zinc-400">{f.kind === "network_acl" ? "Network ACL" : "Security group"}{f.description ? ` · ${f.description}` : ""} · {f.stateful ? "stateful (replies allowed)" : "stateless (replies need their own rule)"} · default {f.default_action}{d.network ? <> · network <span className="font-mono">{d.network}</span></> : null}</div>
      {d.resources.length > 0 && <div className="text-zinc-400">Guards: {d.resources.slice(0, 12).map((r: any) => <span key={r.id} className="mr-2"><Res id={r.id} name={r.name} label={r.label} /></span>)}{d.resources.length > 12 && <span className="text-zinc-600">and {d.resources.length - 12} more</span>}</div>}
      {d.segments.length > 0 && <div className="text-zinc-400">Segments: {d.segments.map((s: any) => <span key={s.id} className="mr-2 font-mono">{s.name || s.id} {s.cidr}</span>)}</div>}
      <table className="w-full border-collapse">
        <thead><tr><Th>Direction</Th>{f.kind === "network_acl" && <Th className="text-right">#</Th>}<Th>Action</Th><Th>Ports</Th><Th>From / to</Th><Th>Description</Th><Th className="text-right">Endpoints let in</Th></tr></thead>
        <tbody>
          {d.rules.map((r: any) => (
            <tr key={r.id} className={`border-t border-zinc-800 ${r.dormant ? "text-zinc-600" : ""}`}>
              <Td>{r.direction}</Td>
              {f.kind === "network_acl" && <Td className="text-right font-mono">{r.priority}</Td>}
              <Td className={r.action === "deny" ? "text-red-300" : ""}>{r.action}</Td>
              <Td className="font-mono">{portsOf(r)}</Td>
              <Td><span className={r.source_kind === "internet" ? "text-red-300" : ""}>{r.source_label === "AdvisorFilter" ? `group ${r.source_name || r.source_id}` : r.source_name || r.source || "any"}</span>{r.dormant && <span className="ml-1 text-zinc-600">(dormant: no IPv6 in this network)</span>}</Td>
              <Td className="text-zinc-400">{r.description || "—"}</Td>
              <Td className="text-right">{r.endpoints_let_in || <span className="text-zinc-600">0</span>}</Td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** One network's gateways, peers and interfaces by owner; fetched when a network row opens (its segments are in the Segments tab). */
function NetworkPanel({ id, onSegments }: { id: string; onSegments: () => void }) {
  const [d, setD] = useState<any>(null);
  useEffect(() => { setD(null); api(`/graph/network/${encodeURIComponent(id)}`).then(setD).catch((e) => setD({ error: e.message })); }, [id]);
  if (!d) return <div className="text-xs text-zinc-500">Loading the network…</div>;
  if (d.error) return <div className="text-xs text-red-300">{d.error}</div>;
  return (
    <div className="space-y-2 text-xs">
      <div className="text-zinc-400">Gateways: {d.gateways.length ? d.gateways.map((g: any) => <span key={g.id} className="mr-3"><span className="text-zinc-300">{g.kind}</span> <span className="font-mono">{g.name || g.id}</span>{g.public_ip ? <span className="font-mono text-zinc-500"> {g.public_ip}</span> : null}{g.service ? <span className="text-zinc-500"> {String(g.service).replace(/^com\.amazonaws\.[a-z0-9-]+\./, "")}</span> : null}</span>) : "none"}</div>
      {d.peers.length > 0 && <div className="text-zinc-400">Peers: {d.peers.map((p: any) => <span key={p.id} className="mr-3 font-mono">{p.id}{p.foreign ? <span className="text-amber-300"> (another account)</span> : null} <span className="text-zinc-500">{p.state}{p.cidrs?.length ? ` · ${p.cidrs.join(", ")}` : ""}</span></span>)}</div>}
      <div className="text-zinc-400">Interfaces: {d.interfaces.map((i: any) => <span key={i.owner} className="mr-3">{String(i.owner).replace(/_/g, " ")} <span className="text-zinc-200">{i.n}</span>{i.with_public_ip ? <span className="text-zinc-500"> ({i.with_public_ip} public)</span> : null}</span>)}</div>
      <div className="text-zinc-400">{d.segments.length} segments ({d.segments.filter((s: any) => s.is_public).length} public) · <button type="button" className="underline" onClick={onSegments}>open the Segments tab for this network</button> · {d.filters.filter((f: any) => f.kind === "security_group").length} security groups, {d.filters.filter((f: any) => f.kind === "network_acl").length} network ACLs</div>
    </div>
  );
}

const Tabular = ({ head, children }: { head: React.ReactNode; children: React.ReactNode }) => (
  <table className="w-full border-collapse text-xs"><thead><tr>{head}</tr></thead><tbody>{children}</tbody></table>
);

export default function Network() {
  const [params, setParams] = useSearchParams();
  const tab = (TABS.includes(params.get("tab") as Tab) ? params.get("tab") : "exposed") as Tab;
  const network = params.get("network") || "";
  const q = (params.get("q") || "").toLowerCase();
  const open = params.get("id");
  const set = (patch: Record<string, string | null>) => { const next = new URLSearchParams(params); for (const [k, v] of Object.entries(patch)) { if (v == null || v === "") next.delete(k); else next.set(k, v); } setParams(next, { replace: true }); };

  const [overview, setOverview] = useState<any>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const [lists, setLists] = useState<Record<string, any[] | null>>({});
  const [page, setPage] = useState(1);
  const [filterKind, setFilterKind] = useState<"internet" | "security_group" | "network_acl" | "all">("internet");
  const loadOverview = () => api("/graph/network").then((x) => { setOverview(x); setErr(""); }).catch((e) => setErr(e.message));
  useEffect(() => { loadOverview(); }, []);
  // the object tabs load on first visit; the overview carries exposed, blocked, networks and filters
  useEffect(() => {
    const ep: Partial<Record<Tab, [string, string]>> = { segments: ["/graph/network-segments", "segments"], gateways: ["/graph/network-gateways", "gateways"], interfaces: ["/graph/network-interfaces", "interfaces"], ips: ["/graph/network-public-ips", "public_ips"] };
    const want = ep[tab];
    if (want && lists[tab] === undefined) { setLists((l) => ({ ...l, [tab]: null })); api(want[0]).then((r) => setLists((l) => ({ ...l, [tab]: r[want[1]] }))).catch((e) => { setErr(e.message); setLists((l) => ({ ...l, [tab]: [] })); }); }
  }, [tab]);
  useEffect(() => { setPage(1); }, [tab, network, q, filterKind]);
  const rebuild = async () => { setBusy(true); try { await api("/graph/network/sync", { method: "POST", body: "{}" }); setLists({}); await loadOverview(); } catch (e: any) { setErr(e.message); } finally { setBusy(false); } };

  if (err && !overview) return <div className="space-y-4"><h1 className="text-xl font-semibold text-zinc-100">Network</h1><Card><div className="text-sm text-zinc-400">{err}</div><div className="mt-2 text-xs text-zinc-500">The network layer lives in the Neo4j mirror: configure it under Settings › Graph mirror, then resync from the Knowledge page.</div></Card></div>;
  if (!overview) return err ? <div className="text-sm text-red-300">The network layer could not be read: {err}</div> : <div className="text-sm text-zinc-500">Loading the network layer…</div>;

  const totals = overview.exposure_totals as Record<string, number>;
  const judged = Object.entries(totals).filter(([k]) => k !== "unjudged").reduce((s, [, n]) => s + n, 0);
  const inNet = (row: any) => !network || row.network === network || row.id === network;
  const match = (row: any) => !q || JSON.stringify(row).toLowerCase().includes(q);
  const counts: Record<Tab, number> = {
    exposed: overview.exposed.length, blocked: overview.blocked.length, networks: overview.networks.length, segments: lists.segments?.length ?? overview.networks.reduce((s: number, n: any) => s + Number(n.segments || 0), 0),
    gateways: lists.gateways?.length ?? Object.values(overview.gateway_totals as Record<string, number>).reduce((s, n) => s + n, 0), filters: overview.filters.length, interfaces: lists.interfaces?.length ?? 0, ips: lists.ips?.length ?? 0,
  };
  const rowsFor = (): any[] => {
    if (tab === "exposed") return (overview.exposed as any[]).filter(match);
    if (tab === "blocked") return (overview.blocked as any[]).filter(match);
    if (tab === "networks") return (overview.networks as any[]).filter(match);
    if (tab === "filters") return (overview.filters as any[]).filter((f) => filterKind === "all" || (filterKind === "internet" ? f.internet_rules > 0 : f.kind === filterKind)).filter(inNet).filter(match);
    return ((lists[tab] as any[] | null) ?? []).filter(inNet).filter(match);
  };
  const rows = rowsFor();
  const slice = rows.slice((page - 1) * PAGE, page * PAGE);
  const loading = ["segments", "gateways", "interfaces", "ips"].includes(tab) && lists[tab] === null;
  const toFilter = (id: string) => { setFilterKind("all"); set({ tab: "filters", id, q: null }); };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h1 className="text-xl font-semibold text-zinc-100">Network</h1>
          <div className="text-sm text-zinc-500">Who can reach what, from where, through which rule: the network layer and the reachability verdicts as the graph holds them, the same edges the agent reads. Rebuilt after every collection and, per box, after every probe.</div>
        </div>
        <span className="flex gap-2"><Button variant="ghost" onClick={rebuild} disabled={busy} title="Rebuild the network layer and every endpoint's verdicts from the current inventory">{busy ? "Rebuilding…" : "Rebuild now"}</Button></span>
      </div>
      {err && <div className="text-sm text-red-300">{err}</div>}

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
        <Stat label="Open to the internet" value={<span className={totals.internet ? "text-red-300" : ""}>{totals.internet || 0}</span>} hint={`of ${judged} judged endpoints`} />
        <Stat label="Reachable from the network" value={(totals.network || 0) + (totals.group || 0)} hint="a private range or other groups only" />
        <Stat label="Closed or local" value={(totals.closed || 0) + (totals.local || 0)} hint={`${totals.closed || 0} blocked, ${totals.local || 0} loopback`} />
        <Stat label="Networks" value={overview.networks.length} hint={`${(overview.networks as any[]).reduce((s, n) => s + Number(n.public_segments || 0), 0)} public of ${(overview.networks as any[]).reduce((s, n) => s + Number(n.segments || 0), 0)} segments`} />
        <Stat label="Filters" value={overview.filters.length} hint={`${(overview.filters as any[]).filter((f) => f.internet_rules > 0).length} admit the internet`} />
      </div>

      <div className="flex gap-1 border-b border-zinc-800">
        {TABS.map((t) => (
          <button key={t} onClick={() => set({ tab: t, id: null })} className={`-mb-px border-b-2 px-3 py-1.5 text-sm ${tab === t ? "border-zinc-100 text-zinc-100" : "border-transparent text-zinc-400 hover:text-zinc-200"}`}>
            {TAB_LABEL[t]}<span className="ml-1 text-xs text-zinc-500">{counts[t]}</span>
          </button>
        ))}
      </div>

      <div className="flex flex-wrap items-center gap-2 text-xs">
        <input value={params.get("q") || ""} onChange={(e) => set({ q: e.target.value || null })} placeholder="filter rows…" className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-zinc-200 placeholder:text-zinc-600" />
        {["segments", "gateways", "filters", "interfaces"].includes(tab) && (
          <select value={network} onChange={(e) => set({ network: e.target.value || null })} className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-zinc-200">
            <option value="">every network</option>
            {(overview.networks as any[]).map((n) => <option key={n.id} value={n.id}>{n.id}{n.cidr_blocks?.length ? ` · ${n.cidr_blocks[0]}` : ""}</option>)}
          </select>
        )}
        {tab === "filters" && ([["internet", "admit the internet"], ["security_group", "security groups"], ["network_acl", "network ACLs"], ["all", "all"]] as const).map(([k, l]) => <button key={k} type="button" onClick={() => setFilterKind(k)} className={`rounded border px-2 py-0.5 ${filterKind === k ? "border-zinc-500 bg-zinc-800 text-zinc-100" : "border-zinc-800 text-zinc-400"}`}>{l}</button>)}
        <span className="text-zinc-500">{rows.length} rows</span>
      </div>

      <Card>
        {loading ? <div className="text-sm text-zinc-500">Loading…</div> : rows.length === 0 ? <Empty>{tab === "exposed" ? "No endpoint is reachable from the internet, or none has been judged yet: instance ports come from the probe, listeners from the balancer inventory, database endpoints from RDS." : tab === "blocked" ? "Nothing is admitted by a rule and then stopped: every rule that opens a port is effective, or no closed port has been judged yet." : "Nothing here yet: run a collection (the inventory reads VPCs, subnets, route tables, gateways, interfaces and rules) and rebuild."}</Empty> : (
          <>
            {tab === "exposed" && (
              <Tabular head={<><Th>Resource</Th><Th>Endpoint</Th><Th>Program</Th><Th>Let in by</Th><Th>Note</Th></>}>
                {slice.map((e) => (
                  <tr key={e.endpoint_id} className="border-t border-zinc-800">
                    <Td><Res id={e.resource_id} name={e.resource_name} label={e.resource_label} /><div className="text-[11px] text-zinc-500">{kindWord(e.resource_label)}</div></Td>
                    <Td className="font-mono">{e.kind === "listener" ? "listener " : ""}{e.port ?? "—"}/{e.protocol}{e.hostname ? <div className="text-[11px] text-zinc-500">{short(e.hostname, 40)}</div> : null}</Td>
                    <Td>{e.program || <span className="text-zinc-600">—</span>}{e.container ? <div className="text-[11px] text-zinc-500">{e.container}</div> : null}</Td>
                    <Td>{e.rules.length ? e.rules.map((r: any) => <div key={r.rule}><button type="button" className="underline" onClick={() => toFilter(r.filter)}>{r.filter_name || r.filter}</button> <span className="text-zinc-500">{r.ports}{r.description ? ` · ${r.description}` : ""}</span></div>) : <span className="text-zinc-500">{e.reason}</span>}</Td>
                    <Td className="text-zinc-500">{e.note || ""}</Td>
                  </tr>
                ))}
              </Tabular>
            )}
            {tab === "blocked" && (
              <Tabular head={<><Th>Resource</Th><Th>Endpoint</Th><Th>Program</Th><Th>Reach</Th><Th>Blocked by</Th><Th>Why</Th></>}>
                {slice.map((b, i) => (
                  <tr key={`${b.endpoint_id}|${b.by_id}|${i}`} className="border-t border-zinc-800">
                    <Td><Res id={b.resource_id} name={b.resource_name} label={b.resource_label} /></Td>
                    <Td className="font-mono">{b.port}/{b.protocol}</Td>
                    <Td>{b.program || <span className="text-zinc-600">—</span>}</Td>
                    <Td className={exposureTone[b.exposure] || ""}>{b.exposure}</Td>
                    <Td><button type="button" className="underline" onClick={() => toFilter(b.by_label === "AdvisorFilterRule" ? String(b.by_id).split(":")[0] : b.by_id)}>{b.by_name || short(b.by_id, 30)}</button><div className="text-[11px] text-zinc-500">{b.by_label === "AdvisorFilterRule" ? "ACL entry" : "filter"} · source {b.source}</div></Td>
                    <Td className="text-zinc-400">{b.reason}</Td>
                  </tr>
                ))}
              </Tabular>
            )}
            {tab === "networks" && (
              <Tabular head={<><Th>Network</Th><Th>CIDR</Th><Th>Region</Th><Th className="text-right">Segments</Th><Th>Gateways</Th><Th className="text-right">Resources</Th><Th className="text-right">Filters</Th><Th className="text-right">Internet endpoints</Th><Th>Peers</Th></>}>
                {slice.map((n) => (
                  <Fragment key={n.id}>
                    <tr className="cursor-pointer border-t border-zinc-800 hover:bg-zinc-900/60" onClick={() => set({ id: open === n.id ? null : n.id })}>
                      <Td><span className="font-mono text-zinc-200">{n.id}</span>{n.is_default ? <span className="ml-1"><Badge>default</Badge></span> : null}</Td>
                      <Td className="font-mono text-zinc-400">{(n.cidr_blocks || []).join(", ")}{n.ipv6_blocks ? <span className="text-zinc-600"> +IPv6</span> : null}</Td>
                      <Td className="text-zinc-400">{n.region}</Td>
                      <Td className="text-right">{n.segments}<span className="text-zinc-500"> ({n.public_segments} public)</span></Td>
                      <Td className="text-zinc-400">{(n.gateway_kinds || []).filter(Boolean).join(", ") || "—"}</Td>
                      <Td className="text-right">{n.resources}</Td><Td className="text-right">{n.filters}</Td>
                      <Td className={`text-right ${n.internet_endpoints ? "text-red-300" : ""}`}>{n.internet_endpoints}</Td>
                      <Td className="font-mono text-zinc-500">{(n.peers || []).map((p: string) => short(p, 14)).join(", ") || "—"}</Td>
                    </tr>
                    {open === n.id && <tr className="border-t border-zinc-800 bg-zinc-900/40"><td colSpan={9} className="p-3"><NetworkPanel id={n.id} onSegments={() => set({ tab: "segments", network: n.id, id: null })} /></td></tr>}
                  </Fragment>
                ))}
              </Tabular>
            )}
            {tab === "segments" && (
              <Tabular head={<><Th>Segment</Th><Th>Network</Th><Th>CIDR</Th><Th>Zone</Th><Th>Public</Th><Th>Routes</Th><Th>ACL</Th><Th className="text-right">Interfaces</Th><Th className="text-right">Instances</Th><Th className="text-right">Free IPs</Th></>}>
                {slice.map((s) => (
                  <tr key={s.id} className="border-t border-zinc-800">
                    <Td><div className="text-zinc-200">{s.name || "—"}</div><div className="font-mono text-[11px] text-zinc-500">{s.id}</div></Td>
                    <Td className="font-mono text-zinc-500">{short(s.network, 16)}</Td>
                    <Td className="font-mono">{s.cidr}{s.ipv6_cidr ? <div className="text-zinc-500">{s.ipv6_cidr}</div> : null}</Td>
                    <Td className="text-zinc-400">{s.zone}</Td>
                    <Td>{s.is_public ? <span className="text-amber-300">public{s.auto_public_ip ? ", auto IP" : ""}</span> : <span className="text-zinc-400">private</span>}</Td>
                    <Td className="text-zinc-400">{s.routes.length ? s.routes.map((r: any) => <div key={`${r.destination}|${r.id}`} className="font-mono">{r.destination} → {r.kind} <span className="text-zinc-600">{short(r.id, 18)}</span></div>) : <span className="text-zinc-600">local only</span>}{s.main_table ? <div className="text-zinc-600">main table</div> : null}</Td>
                    <Td className="font-mono text-zinc-400">{s.acl ? <button type="button" className="underline" onClick={() => toFilter(s.acl)}>{short(s.acl, 18)}{s.acl_default ? " (default)" : ""}</button> : "—"}</Td>
                    <Td className="text-right">{s.interfaces}</Td><Td className="text-right">{s.instances}</Td><Td className="text-right text-zinc-400">{s.available_ips ?? "—"}</Td>
                  </tr>
                ))}
              </Tabular>
            )}
            {tab === "gateways" && (
              <Tabular head={<><Th>Gateway</Th><Th>Kind</Th><Th>Network</Th><Th>State</Th><Th>Address</Th><Th>Service / peer</Th><Th>Routed destinations</Th><Th className="text-right">Traffic</Th></>}>
                {slice.map((g) => (
                  <tr key={g.id} className="border-t border-zinc-800">
                    <Td><div className="text-zinc-200">{g.name || "—"}</div><div className="font-mono text-[11px] text-zinc-500">{g.id}</div></Td>
                    <Td className="text-zinc-400">{String(g.kind).replace(/_/g, " ")}</Td>
                    <Td className="font-mono text-zinc-500">{short(g.network, 16) || "—"}</Td>
                    <Td className={g.state && g.state !== "available" && g.state !== "active" && g.state !== "attached" ? "text-amber-300" : "text-zinc-400"}>{g.state || "—"}</Td>
                    <Td className="font-mono">{g.public_ip || "—"}{g.private_ip ? <div className="text-zinc-500">{g.private_ip}</div> : null}</Td>
                    <Td className="text-zinc-400">{g.service ? String(g.service).replace(/^com\.amazonaws\.[a-z0-9-]+\./, "") : g.peer_network_id ? <span className="font-mono">{g.peer_network_id}{g.peer_account_id ? <span className="text-zinc-600"> · {g.peer_account_id}</span> : null}</span> : "—"}{g.endpoint_type ? <span className="text-zinc-600"> ({g.endpoint_type})</span> : null}</Td>
                    <Td className="font-mono text-zinc-400">{(g.destinations || []).filter(Boolean).join(", ") || "—"}{g.route_tables ? <div className="text-[11px] text-zinc-600">{g.route_tables} route table{g.route_tables === 1 ? "" : "s"}</div> : null}</Td>
                    <Td className="text-right text-zinc-400">{g.gb_day != null ? `${Number(g.gb_day).toFixed(1)} GB/day` : "—"}{g.usd_month != null ? <div className="text-[11px] text-zinc-500">${Math.round(Number(g.usd_month))}/mo</div> : null}</Td>
                  </tr>
                ))}
              </Tabular>
            )}
            {tab === "filters" && (
              <Tabular head={<><Th>Filter</Th><Th>Kind</Th><Th>Network</Th><Th className="text-right">Rules</Th><Th>Open to the internet</Th><Th className="text-right">Guards</Th><Th className="text-right">Interfaces</Th></>}>
                {slice.map((f) => (
                  <Fragment key={f.id}>
                    <tr className="cursor-pointer border-t border-zinc-800 hover:bg-zinc-900/60" onClick={() => set({ id: open === f.id ? null : f.id })}>
                      <Td><div className="text-zinc-200">{f.name || "—"}</div><div className="font-mono text-[11px] text-zinc-500">{f.id}</div></Td>
                      <Td className="text-zinc-400">{f.kind === "network_acl" ? "network ACL" : "security group"}{f.is_default ? <span className="ml-1"><Badge>default</Badge></span> : null}</Td>
                      <Td className="font-mono text-zinc-500">{short(f.network, 16) || "—"}</Td>
                      <Td className="text-right">{f.rules ?? 0}</Td>
                      <Td className={f.internet_rules ? "text-red-300" : "text-zinc-600"}>{f.internet_rules ? `${f.internet_rules} rule${f.internet_rules === 1 ? "" : "s"}: ${(f.internet_ports || []).join(", ")}` : "no"}</Td>
                      <Td className="text-right">{f.guarded}</Td><Td className="text-right text-zinc-400">{f.interfaces}</Td>
                    </tr>
                    {open === f.id && <tr className="border-t border-zinc-800 bg-zinc-900/40"><td colSpan={7} className="p-3"><FilterPanel id={f.id} /></td></tr>}
                  </Fragment>
                ))}
              </Tabular>
            )}
            {tab === "interfaces" && (
              <Tabular head={<><Th>Interface</Th><Th>Belongs to</Th><Th>Addresses</Th><Th>Segment</Th><Th>Wears</Th><Th>Status</Th></>}>
                {slice.map((i) => (
                  <tr key={i.id} className="border-t border-zinc-800">
                    <Td><div className="font-mono text-zinc-200">{i.id}</div><div className="text-[11px] text-zinc-500">{String(i.owner_kind).replace(/_/g, " ")}{i.description ? ` · ${short(i.description, 50)}` : ""}</div></Td>
                    <Td>{i.attached_id ? <Res id={i.attached_id} name={i.attached_name} label={i.attached_label} /> : <span className="text-zinc-600">not resolved</span>}</Td>
                    <Td className="font-mono">{(i.private_ips || []).join(", ") || "—"}{i.public_ip ? <div className="text-amber-200">{i.public_ip}{i.eip ? <span className="text-zinc-500"> (EIP)</span> : null}</div> : null}{(i.ipv6 || []).length ? <div className="text-zinc-500">{i.ipv6.join(", ")}</div> : null}</Td>
                    <Td className="font-mono text-zinc-400">{short(i.segment, 18) || "—"}{i.segment_public ? <span className="text-amber-300"> public</span> : null}</Td>
                    <Td>{(i.filters || []).length ? i.filters.map((f: any) => <button key={f.id} type="button" className="mr-1 underline" onClick={() => toFilter(f.id)}>{f.name || short(f.id, 14)}</button>) : <span className="text-zinc-600">—</span>}</Td>
                    <Td className="text-zinc-400">{i.status || "—"}{i.source_dest_check === false ? <div className="text-[11px] text-amber-300">source/dest check off</div> : null}</Td>
                  </tr>
                ))}
              </Tabular>
            )}
            {tab === "ips" && (
              <Tabular head={<><Th>Address</Th><Th>Assigned to</Th><Th>Owner</Th><Th>Domains</Th><Th>Region</Th></>}>
                {slice.map((p) => (
                  <tr key={p.id} className="border-t border-zinc-800">
                    <Td className="font-mono text-zinc-200">{p.ip}{!p.associated ? <span className="ml-1 text-amber-300">unassociated</span> : null}</Td>
                    <Td className="text-zinc-400">{p.assigned_kind ? `${p.assigned_kind}${p.interface_owner ? ` (${String(p.interface_owner).replace(/_/g, " ")})` : ""}` : "—"}<div className="font-mono text-[11px] text-zinc-600">{short(p.assigned_id, 24)}</div></Td>
                    <Td>{p.owner_id ? <Res id={p.owner_id} name={p.owner_name} label={p.owner_label} /> : <span className="text-zinc-600">—</span>}</Td>
                    <Td className="text-zinc-400">{(p.domains || []).filter(Boolean).join(", ") || "—"}</Td>
                    <Td className="text-zinc-500">{p.region}</Td>
                  </tr>
                ))}
              </Tabular>
            )}
            <Pager page={page} pageSize={PAGE} total={rows.length} onPage={setPage} />
          </>
        )}
      </Card>

      <div className="text-xs text-zinc-500">Verdicts cover instance ports (groups, public address, subnet ACL; probed ports and the ports balancers forward to), balancer listeners (groups and scheme) and RDS endpoints (groups and public accessibility). Gateways in the graph: {Object.entries(overview.gateway_totals as Record<string, number>).map(([k, n]) => `${n} ${k}`).join(", ") || "none"}.</div>
    </div>
  );
}

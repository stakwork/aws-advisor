import { Fragment, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, when } from "../api";
import { Empty, Td, Th } from "./ui";

/**
 * Ports and security groups (src/instance_apps.ts reachOf, src/security_groups.ts): the Ports tab of an instance, what
 * it listens on and how far each port can be reached, with the rule that lets it in or what blocks it; and the
 * Security groups tab of the inventory, every group with what it opens, who wears it and its trouble.
 */

const REACH: Record<string, { word: string; tone: string }> = {
  internet: { word: "open to the internet", tone: "bg-red-950/60 text-red-300 border-red-900/60" },
  network: { word: "reachable from the network", tone: "bg-amber-950/40 text-amber-300 border-amber-900/50" },
  group: { word: "from other groups", tone: "bg-sky-950/40 text-sky-300 border-sky-900/50" },
  closed: { word: "blocked by security group", tone: "bg-emerald-950/40 text-emerald-300 border-emerald-900/50" },
  nacl: { word: "blocked by network ACL", tone: "bg-emerald-950/40 text-emerald-300 border-emerald-900/50" },
  local: { word: "this box only", tone: "bg-zinc-900 text-zinc-400 border-zinc-800" },
};
const reachKey = (p: any) => (p.exposure === "closed" && p.blocked_by === "network_acl" ? "nacl" : p.exposure);

export function ReachBadge({ p }: { p: any }) {
  const r = REACH[reachKey(p)] ?? { word: p.exposure, tone: "bg-zinc-900 text-zinc-400 border-zinc-800" };
  return <span className={`inline-block whitespace-nowrap rounded border px-1.5 py-px text-[11px] ${r.tone}`} title={p.reason || undefined}>{r.word}</span>;
}

export const sgLink = (groupId: string) => `/inventory?tab=sg&id=${encodeURIComponent(groupId)}`;

export function GroupLink({ id, name }: { id: string; name?: string | null }) {
  return <Link to={sgLink(id)} className="text-sky-300 hover:underline" onClick={(e) => e.stopPropagation()} title={id}>{name || id}</Link>;
}

const ruleWords = (r: any) => `${r.ports} from ${r.source}`;

/** The Ports tab of an EC2 instance. `groups` are the box's own security groups (from its snapshot), named for the "no rule in" case. */
export function PortsPanel({ instanceId, probedAt, groups }: { instanceId: string; probedAt?: string | null; groups: { GroupId: string; GroupName?: string }[] }) {
  const [d, setD] = useState<any>(null);
  const [gone, setGone] = useState(false);
  useEffect(() => { setD(null); api(`/instances/${encodeURIComponent(instanceId)}/apps${gone ? "?gone=1" : ""}`).then(setD).catch(() => setD({ ports: [] })); }, [instanceId, probedAt, gone]);
  if (!d) return <div className="mt-3 text-sm text-zinc-500">Loading…</div>;
  if (d.has_listeners === false && !d.ports?.length) return <div className="mt-3 text-sm text-zinc-500">No port list yet: this probe predates 1.8 (update the SSM document, Settings › Permissions) or the box has not been probed since.</div>;
  const ports: any[] = (d.ports || []).filter((p: any) => !p.gone);
  const old: any[] = (d.ports || []).filter((p: any) => p.gone);
  if (!ports.length && !old.length) return <div className="mt-3 text-sm text-zinc-500">The last probe saw no listening port.</div>;
  const counts = Object.entries(REACH).map(([k, v]) => [v.word, ports.filter((p) => reachKey(p) === k).length] as const).filter(([, n]) => n > 0);
  const broad = ports.flatMap((p) => (p.allowed_by ?? []).filter((r: any) => r.broad && r.world)).find(Boolean);
  const publicOnlyByBroad = broad ? ports.filter((p) => p.exposure === "internet" && (p.allowed_by ?? []).every((r: any) => !r.world || r.broad)) : [];
  return (
    <div className="mt-3 space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2 text-sm">
        <div className="text-zinc-400">{ports.length} listening port{ports.length === 1 ? "" : "s"}{counts.length ? ": " : ""}{counts.map(([w, n], i) => <span key={w}>{i ? ", " : ""}<span className="text-zinc-200">{n}</span> {w}</span>)}</div>
        <div className="flex items-center gap-3 text-xs text-zinc-500">
          <span>groups: {groups.length ? groups.map((g, i) => <Fragment key={g.GroupId}>{i ? ", " : ""}<GroupLink id={g.GroupId} name={g.GroupName} /></Fragment>) : "none known"}</span>
          <label className="flex items-center gap-1"><input type="checkbox" checked={gone} onChange={(e) => setGone(e.target.checked)} /> include closed</label>
        </div>
      </div>
      {broad && (
        <div className="rounded border border-red-900/60 bg-red-950/30 px-3 py-2 text-sm text-red-200">
          <GroupLink id={broad.group_id} name={broad.group_name} /> lets <b>{broad.ports}</b> in from {broad.source}, so {broad.ports === "all traffic" ? "every port this box listens on is public" : "everything this box listens on in that range is public"}.
          {publicOnlyByBroad.length > 0 && <> Public only because of it: {publicOnlyByBroad.slice(0, 14).map((p) => `${p.port}/${p.proto}${p.app_name ? ` ${p.app_name}` : ""}`).join(", ")}{publicOnlyByBroad.length > 14 ? ` and ${publicOnlyByBroad.length - 14} more` : ""}.</>}
          <span className="text-red-300/70"> Replace it with rules for the ports that should be public.</span>
        </div>
      )}
      <div className="overflow-x-auto rounded-lg border border-zinc-800">
        <table className="w-full text-sm">
          <thead className="bg-zinc-900"><tr><Th>Port</Th><Th>Served by</Th><Th>Listens on</Th><Th>Reach</Th><Th>Why</Th><Th>Seen</Th></tr></thead>
          <tbody>
            {[...ports, ...old].map((p) => {
              const top = p.allowed_by?.[0];
              return (
                <tr key={`${p.proto}:${p.port}`} className={`border-t border-zinc-800/70 align-top ${p.gone ? "text-zinc-600" : ""}`}>
                  <Td className="whitespace-nowrap font-mono">{p.port}<span className="text-zinc-500">/{p.proto}</span></Td>
                  <Td>{p.container ? <><span className="text-zinc-500">container </span><span className="font-mono">{p.container}</span>{p.container_port && p.container_port !== p.port ? <span className="text-zinc-500"> :{p.container_port}</span> : null}</> : p.app_name ? <span className="font-mono">{p.app_name}</span> : p.process ? <span className="font-mono">{p.process}</span> : <span className="text-zinc-600">unknown owner</span>}</Td>
                  <Td className="whitespace-nowrap font-mono text-xs text-zinc-400">{p.scope === "all" ? "all interfaces" : p.bind || p.scope}</Td>
                  <Td>{p.gone ? <span className="text-xs">closed {when(p.last_seen)}</span> : <ReachBadge p={p} />}</Td>
                  <Td className="text-xs text-zinc-400">
                    {p.gone ? null
                      : p.exposure === "local" ? "loopback only: nothing outside the box can reach it"
                      : p.exposure === "closed" && p.blocked_by === "network_acl" ? (p.reason || "").replace(/^blocked by network ACL: /, "")
                      : p.exposure === "closed" ? <>{/no IPv6 address/.test(p.reason || "") ? <>{(p.reason || "").replace(/^blocked by the security groups: /, "")}</> : <>no rule in {groups.map((g, i) => <Fragment key={g.GroupId}>{i ? ", " : ""}<GroupLink id={g.GroupId} name={g.GroupName} /></Fragment>)} lets it in</>}</>
                      : top ? <>
                          <GroupLink id={top.group_id} name={top.group_name} /> · {ruleWords(top)}{top.description ? <span className="text-zinc-500"> “{top.description}”</span> : null}
                          {top.broad && <span className="ml-1 rounded bg-red-950/60 px-1 text-[10px] uppercase text-red-300">broad</span>}
                          {p.allowed_by.length > 1 && <span className="text-zinc-500"> +{p.allowed_by.length - 1} more</span>}
                          {p.exposure === "network" && top.world && <div className="text-zinc-500">the rule says anywhere, but the box has no public address</div>}
                          {p.nacl_note && <div className="text-amber-300/80">{p.nacl_note}</div>}
                        </>
                      : null}
                  </Td>
                  <Td className="whitespace-nowrap text-xs text-zinc-500">{when(p.first_seen)}{p.probes > 1 ? ` · ${p.probes} probes` : ""}</Td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {d.unused_rules?.length > 0 && (
        <div>
          <div className="mb-1 text-sm text-zinc-300">Rules that open nothing on this box <span className="text-xs text-zinc-500">({d.unused_rules.length}) nothing listens behind them; if nothing should, the rule can go</span></div>
          <div className="overflow-x-auto rounded-lg border border-zinc-800">
            <table className="w-full text-sm">
              <thead className="bg-zinc-900"><tr><Th>Group</Th><Th>Ports</Th><Th>From</Th><Th>Note</Th></tr></thead>
              <tbody>
                {d.unused_rules.map((r: any) => (
                  <tr key={`${r.group_id}|${r.ports}|${r.source}`} className="border-t border-zinc-800/70">
                    <Td><GroupLink id={r.group_id} name={r.group_name} /></Td>
                    <Td className="font-mono text-xs">{r.ports}</Td>
                    <Td className={r.world && !r.unreachable ? "text-amber-300/90" : "text-zinc-400"}>{r.source}</Td>
                    <Td className="text-xs text-zinc-500">{r.unreachable ? "IPv6 only, and this VPC has no IPv6: it lets nothing in" : r.description ? `“${r.description}”` : ""}</Td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

const Chip = ({ tone, children, title }: { tone: string; children: React.ReactNode; title?: string }) => <span title={title} className={`whitespace-nowrap rounded border px-1.5 py-px text-[11px] ${tone}`}>{children}</span>;

function Flags({ g }: { g: any }) {
  return (
    <span className="flex flex-wrap gap-1">
      {g.broad_world && <Chip tone="border-red-900/60 bg-red-950/60 text-red-300" title="A rule from anywhere opens all traffic or more than 1,000 ports">broad rule</Chip>}
      {g.listening_open > 0 && <Chip tone="border-red-900/40 bg-red-950/30 text-red-300/90" title="Listening ports on its instances that it opens to the internet">{g.listening_open} open to the internet</Chip>}
      {g.dormant_ipv6 > 0 && <Chip tone="border-amber-900/50 bg-amber-950/40 text-amber-300" title="IPv6 rules from anywhere in a VPC without IPv6: nothing today, open the day IPv6 is turned on">dormant IPv6</Chip>}
      {g.unattached && <Chip tone="border-zinc-700 bg-zinc-900 text-zinc-400" title="No instance and no network interface wears it">unattached</Chip>}
    </span>
  );
}

/** The Security groups tab of the inventory. `selected` is the group in the URL (?id=sg-…), opened and scrolled to. */
export function SecurityGroupsPanel({ selected, onSelect }: { selected: string | null; onSelect: (id: string | null) => void }) {
  const [rows, setRows] = useState<any[] | null>(null);
  const [err, setErr] = useState("");
  const [q, setQ] = useState("");
  const [flagged, setFlagged] = useState(false);
  useEffect(() => { api("/security-groups").then((r) => setRows(r.groups)).catch((e) => { setErr(e.message); setRows([]); }); }, []);
  useEffect(() => { if (selected && rows) document.getElementById(`sg-${selected}`)?.scrollIntoView({ block: "center" }); }, [selected, rows]);
  if (!rows) return <div className="text-sm text-zinc-500">Loading…</div>;
  const needle = q.trim().toLowerCase();
  const shown = rows.filter((g) => (!flagged || g.broad_world || g.dormant_ipv6 || g.listening_open || g.unattached || g.group_id === selected)
    && (!needle || [g.group_id, g.group_name, g.description, g.vpc_id].some((x) => String(x || "").toLowerCase().includes(needle))));
  const n = (f: (g: any) => boolean) => rows.filter(f).length;
  return (
    <div className="space-y-3">
      {err && <div className="text-sm text-red-300">{err}</div>}
      <div className="grid grid-cols-2 gap-3 text-sm lg:grid-cols-5">
        {[["Groups", rows.length], ["With a broad rule", n((g) => g.broad_world)], ["Open listening ports", rows.reduce((s, g) => s + g.listening_open, 0)], ["Dormant IPv6", n((g) => g.dormant_ipv6 > 0)], ["Unattached", n((g) => g.unattached)]].map(([l, v]) => (
          <div key={String(l)} className="rounded-lg border border-zinc-800 bg-zinc-900/40 px-3 py-2"><div className="text-xs text-zinc-500">{l}</div><div className="text-lg text-zinc-100">{v}</div></div>
        ))}
      </div>
      <div className="flex flex-wrap items-center gap-3">
        <input id="sg-search" placeholder="search name, id, description or VPC" value={q} onChange={(e) => setQ(e.target.value)} className="w-72" />
        <label className="flex items-center gap-1 text-sm text-zinc-400"><input type="checkbox" checked={flagged} onChange={(e) => setFlagged(e.target.checked)} /> only flagged</label>
      </div>
      {shown.length === 0 ? <Empty>No security groups{rows.length ? " match" : " read yet: they come with the next inventory refresh"}.</Empty> : (
        <div className="overflow-x-auto rounded-lg border border-zinc-800">
          <table className="w-full text-sm">
            <thead className="bg-zinc-900"><tr><Th>Group</Th><Th>VPC</Th><Th className="text-right">Rules</Th><Th>Used by</Th><Th>Flags</Th></tr></thead>
            <tbody>
              {shown.map((g) => {
                const open = g.group_id === selected;
                return (
                  <Fragment key={g.group_id}>
                    <tr id={`sg-${g.group_id}`} onClick={() => onSelect(open ? null : g.group_id)} className={`cursor-pointer border-t border-zinc-800 hover:bg-zinc-900/60 ${open ? "bg-zinc-900" : ""}`}>
                      <Td><div className="text-zinc-100">{g.group_name || g.group_id}</div><div className="font-mono text-xs text-zinc-500">{g.group_id}{g.description && g.description !== g.group_name ? <span className="font-sans"> · {g.description}</span> : null}</div></Td>
                      <Td className="text-xs"><div className="font-mono text-zinc-400">{g.vpc_id || "—"}</div><div className={g.vpc_ipv6 ? "text-zinc-300" : "text-zinc-500"}>{g.vpc_ipv6 == null ? "" : g.vpc_ipv6 ? "IPv6 on" : "no IPv6"}{g.region ? ` · ${g.region}` : ""}</div></Td>
                      <Td className="text-right">{g.rules}{g.world_rules ? <div className="text-xs text-zinc-500">{g.world_rules} from anywhere</div> : null}</Td>
                      <Td className="text-xs text-zinc-400">{g.instances ? `${g.running} running of ${g.instances} instance${g.instances === 1 ? "" : "s"}` : ""}{g.instances && g.others ? " · " : ""}{g.others ? `${g.others} other interface${g.others === 1 ? "" : "s"}` : ""}{!g.instances && !g.others ? <span className="text-zinc-600">nothing</span> : null}</Td>
                      <Td><Flags g={g} /></Td>
                    </tr>
                    {open && <tr className="border-t border-zinc-800/60 bg-zinc-950/40"><td colSpan={5} className="max-w-0 p-3"><SecurityGroupDetail id={g.group_id} /></td></tr>}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function SecurityGroupDetail({ id }: { id: string }) {
  const [d, setD] = useState<any>(undefined);
  useEffect(() => { setD(undefined); api(`/security-groups/${encodeURIComponent(id)}`).then(setD).catch(() => setD(null)); }, [id]);
  if (d === undefined) return <div className="text-sm text-zinc-500">Loading…</div>;
  if (!d) return <div className="text-sm text-zinc-500">Not found.</div>;
  return (
    <div className="space-y-3 text-sm">
      {d.dormant?.length > 0 && (
        <div className="rounded border border-amber-900/50 bg-amber-950/30 px-3 py-2 text-amber-200">
          {d.dormant.length === 1 ? "One IPv6 rule" : `${d.dormant.length} IPv6 rules`} from anywhere ({d.dormant.map((x: any) => x.ref.ports).join(", ")}) in a VPC without IPv6: {d.dormant.length === 1 ? "it lets" : "they let"} nothing in today and open the day IPv6 is turned on.
          {d.recommendation && <> <Link className="underline" to={`/recommendations?status=${d.recommendation.status}&id=${d.recommendation.id}`}>Recommendation #{d.recommendation.id}</Link> ({d.recommendation.status}).</>}
        </div>
      )}
      <div className="overflow-x-auto rounded-lg border border-zinc-800">
        <table className="w-full text-sm">
          <thead className="bg-zinc-900"><tr><Th>Inbound rule</Th><Th>From</Th><Th>Description</Th><Th>Listening behind it</Th></tr></thead>
          <tbody>
            {d.rules.map((r: any, i: number) => (
              <tr key={`${r.rule_id || i}`} className={`border-t border-zinc-800/70 align-top ${r.inert ? "text-zinc-500" : ""}`}>
                <Td className="whitespace-nowrap font-mono text-xs">{r.ports}{r.broad && !r.inert && <span className="ml-1 rounded bg-red-950/60 px-1 font-sans text-[10px] uppercase text-red-300">broad</span>}{r.dormant && <span className="ml-1 rounded bg-amber-950/60 px-1 font-sans text-[10px] uppercase text-amber-300">dormant</span>}</Td>
                <Td className={r.world && !r.inert ? "text-red-300/90" : ""}>{r.referenced_group_id ? <GroupLink id={r.referenced_group_id} name={r.source.replace(` ${r.referenced_group_id}`, "")} /> : r.source}{r.inert && <div className="text-xs">no IPv6 in this VPC: lets nothing in</div>}</Td>
                <Td className="text-xs text-zinc-400">{r.description || ""}</Td>
                <Td className="text-xs">{r.listeners.length ? r.listeners.slice(0, 8).map((h: any, j: number) => <span key={j} className="mr-2 inline-block"><Link className="text-sky-300 hover:underline" to={`/inventory?tab=ec2&id=${encodeURIComponent(h.instance_id)}`}>{h.name || h.instance_id}</Link> <span className="font-mono text-zinc-400">{h.port}/{h.proto}</span>{h.app ? <span className="text-zinc-500"> {h.app}</span> : null}</span>) : <span className="text-zinc-600">nothing</span>}{r.listeners.length > 8 ? <span className="text-zinc-500"> +{r.listeners.length - 8}</span> : null}</Td>
              </tr>
            ))}
            {!d.rules.length && <tr><td colSpan={4} className="px-3 py-2 text-zinc-500">No inbound rules: nothing gets in through this group.</td></tr>}
          </tbody>
        </table>
      </div>
      <div className="grid gap-3 lg:grid-cols-2">
        <div>
          <div className="mb-1 text-zinc-300">Instances <span className="text-xs text-zinc-500">({d.instances.length})</span></div>
          {d.instances.length ? <ul className="space-y-0.5 text-xs">{d.instances.map((i: any) => <li key={i.instance_id}><Link className="text-sky-300 hover:underline" to={`/inventory?tab=ec2&id=${encodeURIComponent(i.instance_id)}`}>{i.name || i.instance_id}</Link> <span className="font-mono text-zinc-500">{i.instance_id}</span> <span className="text-zinc-500">· {i.state}</span></li>)}</ul> : <div className="text-xs text-zinc-600">none</div>}
        </div>
        <div>
          <div className="mb-1 text-zinc-300">Other network interfaces <span className="text-xs text-zinc-500">({d.others.length}: databases, load balancers, Lambdas, endpoints)</span></div>
          {d.others.length ? <ul className="space-y-0.5 text-xs text-zinc-400">{d.others.slice(0, 20).map((o: any) => <li key={o.eni_id}><span className="font-mono text-zinc-500">{o.eni_id}</span> · {o.interface_type || "interface"}{o.description ? ` · ${o.description}` : ""}</li>)}</ul> : <div className="text-xs text-zinc-600">none</div>}
        </div>
      </div>
    </div>
  );
}

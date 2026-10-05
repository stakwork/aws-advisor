import { Fragment, useEffect, useRef, useState, type ReactNode } from "react";
import { useNavigate, Link, useSearchParams } from "react-router-dom";
import { api, cachedProviders, currentScope, currentScopeProvider, realProcesses, rememberProviders, setScope, usd, when } from "../api";
import { ClustersPanel } from "../components/clusters";
import { Timeline } from "../components/timeline";
import { WatchToggle } from "../components/watch";
import { Badge, Button, Card, Code, CopyButton, DetailCell, Empty, Stat, Td, Th } from "../components/ui";
import { RoleLine } from "../components/jev";
import { InstanceCharts } from "../components/instanceCharts";
import { UsageProfile } from "../components/usageProfile";
import { AutoParkSwitch, AutoScaleSwitch } from "../components/consent";
import { GroupLink, PortsPanel, SecurityGroupsPanel } from "../components/securityGroups";
import { SoftwarePanel } from "../components/software";
import { VercelMembers, VercelProjects } from "../components/vercel";
import { IdentityCenter } from "../components/identityCenter";
import { Access } from "../components/access";
import { VercelStores } from "../components/vercelStores";
import { WakeProfilePanel } from "../components/wakeProfile";
import { ServicesPanel, type ServiceTab } from "../components/services";

/** Probe 1.4: the use signals beyond CPU, memory and disk, and the one line they add up to. `last_lines` is text from the box: shown, never interpreted. */
/** One chip per matched use-signal kind; click marks it noise for this image (or lifts the rule), so the count stops fooling the last-use line. */
function SignalChips({ image, act, rules, onChange }: { image: string; act: any; rules: any[]; onChange: () => void }) {
  const [busy, setBusy] = useState("");
  const key = String(image || "").replace(/@sha256:[0-9a-f]+$/i, "").replace(/:[^/]+$/, "");
  const kinds = Object.entries(act.signal_kinds || {}) as [string, number][];
  if (!kinds.length) return null;
  const ruleFor = (kind: string) => rules.find((r) => r.kind === kind && r.status === "confirmed" && (r.image_pattern === key || image.includes(r.image_pattern) || key.includes(r.image_pattern)));
  const toggle = async (kind: string) => {
    const r = ruleFor(kind); setBusy(kind);
    try {
      if (r && r.verdict === "noise") await api(`/signal-rules/${r.id}`, { method: "DELETE" });
      else { const note = window.prompt(`Mark "${kind}" as noise for every container of ${key}? Say why (optional):`, ""); if (note === null) return; await api("/signal-rules", { method: "PUT", body: JSON.stringify({ image_pattern: key, kind, verdict: "noise", note }) }); }
      onChange();
    } catch (e: any) { alert(e.message); } finally { setBusy(""); }
  };
  return (
    <span className="flex flex-wrap gap-1">
      {kinds.sort((x, y) => y[1] - x[1]).map(([k, n]) => { const r = ruleFor(k); const noise = r?.verdict === "noise"; return (
        <button key={k} type="button" onClick={() => toggle(k)} disabled={busy === k} title={noise ? `ruled noise for ${r.image_pattern}${r.note ? `: ${r.note}` : ""} (${r.decided_by}); click to lift` : `${n} lines matched "${k}" in 24 h; click to mark as noise for ${key}`}
          className={`rounded border px-1.5 py-0 text-[11px] ${noise ? "border-zinc-800 text-zinc-600 line-through" : "border-emerald-900/60 text-emerald-300/80 hover:border-emerald-700"}`}>{k} {n}</button>
      ); })}
      {act.signal_samples?.length > 0 && <details className="inline"><summary className="cursor-pointer text-[11px] text-zinc-500">lines</summary><ul className="mt-0.5 space-y-0.5 font-mono text-[11px] text-zinc-500">{act.signal_samples.map((x: string, i: number) => <li key={i} className="truncate" title={x}>{x}</li>)}</ul></details>}
    </span>
  );
}

/** Probe 1.6: what runs on the box (the OS set aside), its appear/disappear events and where its log agents ship. Reloads when a new probe lands. */
/** One containers table: the latest probe (state, CPU and memory now, logs and use signals) joined by name with 30 days of daily roll-ups (CPU and memory average and maximum). */
function ContainersPanel({ instanceId, latest, rules, onRules }: { instanceId: string; latest: any; rules: any[]; onRules: () => void }) {
  const [hist, setHist] = useState<any[] | null>(null);
  useEffect(() => { setHist(null); api(`/instances/${encodeURIComponent(instanceId)}/history?days=30`).then((h) => setHist(h.containers || [])).catch(() => setHist([])); }, [instanceId, latest?.collected_at]);
  const byName = new Map<string, any>((hist || []).map((c) => [c.name, c]));
  const now: any[] = latest.data.containers || [];
  const seen = new Set(now.map((c) => c.name));
  const gone = (hist || []).filter((c) => !seen.has(c.name));
  const mb = (b: number | null | undefined) => (b == null ? "—" : b >= 1e9 ? `${(b / 1e9).toFixed(1)} GB` : `${Math.round(b / 1048576)} MB`);
  const p1 = (v: number | null | undefined) => (v == null ? "—" : `${Number(v).toFixed(1)}%`);
  return (
    <Group title={`Containers · ${latest.data.docker.running} running of ${latest.data.docker.total}${hist?.length ? ` · ${hist[0]?.days ?? ""} days of roll-ups` : ""}`}>
      <div className="overflow-x-auto"><table className="w-full border-collapse text-xs">
        <thead className="text-zinc-500"><tr><th className="py-1 text-left font-normal">Container</th><th className="text-left font-normal">Image</th><th className="text-left font-normal">State</th><th className="text-right font-normal">CPU now</th><th className="text-right font-normal">CPU 30 d avg / max</th><th className="text-right font-normal">Memory now</th><th className="text-right font-normal">Memory 30 d avg / max</th><th className="text-left font-normal">Logs, 24 h</th><th className="text-left font-normal">Use signals</th></tr></thead>
        <tbody>
          {now.map((c: any) => {
            const a = latest.data.activity?.containers?.find((x: any) => x.name === c.name);
            const h = byName.get(c.name);
            return (
              <tr key={c.name} className="border-t border-zinc-800/70 align-top">
                <td className={`py-1 pr-2 font-mono ${c.state === "running" ? "text-zinc-200" : "text-zinc-500"}`}>{c.name}</td>
                <td className="max-w-48 truncate pr-2 text-zinc-500" title={c.image}>{c.image}</td>
                <td className="pr-2 text-zinc-400">{c.state}{h?.running_share != null && h.running_share < 0.99 ? <span className="text-zinc-600"> · up {Math.round(h.running_share * 100)}% of 30 d</span> : null}</td>
                <td className="pr-2 text-right">{c.cpu_pct != null ? `${c.cpu_pct}%` : "—"}</td>
                <td className={`pr-2 text-right ${h?.cpu_pct_max >= 50 ? "text-amber-300/80" : "text-zinc-400"}`}>{h ? `${p1(h.cpu_pct_avg)} / ${p1(h.cpu_pct_max)}` : "—"}</td>
                <td className="pr-2 text-right">{c.mem_bytes ? `${mb(c.mem_bytes)}${c.mem_pct != null ? ` (${c.mem_pct}%)` : ""}` : "—"}</td>
                <td className="pr-2 text-right text-zinc-400">{h ? `${mb(h.mem_bytes_avg)} / ${mb(h.mem_bytes_max)}` : "—"}</td>
                <td className="pr-2 text-zinc-400" title={a?.last_lines?.length ? `last lines:\n${a.last_lines.join("\n")}` : undefined}>{a ? <>{a.log_lines} lines{a.last_log_at ? `, last ${when(a.last_log_at)}` : ""}{a.errors > 0 ? <span className="text-amber-300/80"> · {a.errors} errors</span> : null}{a.restarts >= 10 ? <span className="text-red-300"> · {a.restarts} restarts</span> : null}</> : "—"}</td>
                <td>{a ? <span className="flex flex-wrap items-center gap-1">{a.signal_lines > 0 ? <span className="text-emerald-300/80">{a.signal_lines}, last {when(a.last_signal_at)}</span> : <span className="text-zinc-600">none</span>}<SignalChips image={c.image} act={a} rules={rules} onChange={onRules} /></span> : "—"}</td>
              </tr>
            );
          })}
          {gone.map((h: any) => (
            <tr key={`gone-${h.name}`} className="border-t border-zinc-800/70 align-top text-zinc-600">
              <td className="py-1 pr-2 font-mono line-through">{h.name}</td><td className="max-w-48 truncate pr-2" title={h.image}>{h.image}</td><td className="pr-2">not in the latest probe · last {h.last_day}</td><td className="pr-2 text-right">—</td><td className="pr-2 text-right">{p1(h.cpu_pct_avg)} / {p1(h.cpu_pct_max)}</td><td className="pr-2 text-right">—</td><td className="pr-2 text-right">{mb(h.mem_bytes_avg)} / {mb(h.mem_bytes_max)}</td><td className="pr-2">—</td><td>—</td>
            </tr>
          ))}
        </tbody>
      </table></div>
      {hist === null && <div className="mt-1 text-[11px] text-zinc-600">loading the 30-day roll-ups…</div>}
    </Group>
  );
}

/** GET /api/instances/:id/logs: the groups the box ships to (probe 1.6), with what the logs refresh knows about each. */
function LogsBlock({ instanceId }: { instanceId: string }) {
  const [d, setD] = useState<any>(undefined);
  useEffect(() => { setD(undefined); api(`/instances/${encodeURIComponent(instanceId)}/logs`).then(setD).catch(() => setD(null)); }, [instanceId]);
  if (d === undefined) return <div className="mt-3 text-sm text-zinc-500">Loading…</div>;
  if (!d) return <div className="mt-3 text-sm text-zinc-500">Could not read the log shipping for this instance.</div>;
  const groups: any[] = d.groups || [];
  const byVia = new Map<string, any[]>(); for (const g of groups) byVia.set(g.via, [...(byVia.get(g.via) || []), g]);
  const via = (v: string) => v.startsWith("docker:") ? `container ${v.slice(7)}` : v === "cloudwatch-agent" ? "CloudWatch agent" : v;
  const usd = (n: number | null) => (n == null ? "—" : `$${n.toFixed(2)}`);
  const totalIngest = groups.reduce((s, g) => s + (g.ingest_usd_month || 0), 0), totalStore = groups.reduce((s, g) => s + (g.storage_usd_month || 0), 0);
  return (
    <Group title={`Ships logs to · ${groups.length} group${groups.length === 1 ? "" : "s"}${d.probed_at ? ` · probed ${when(d.probed_at)}` : ""}`}>
      {!d.probe_has_section ? <div className="text-sm text-zinc-500">No log shipping section on the latest probe: the box has not been probed since probe 1.6, or has never been probed.</div>
        : !groups.length ? <div className="text-sm text-zinc-500">The probe found no agent or container shipping logs to CloudWatch from this box.</div>
        : (
          <>
            {(totalIngest || totalStore) ? <div className="mb-2 text-xs text-zinc-400">At list: {usd(totalIngest)} / month of ingestion and {usd(totalStore)} / month of storage across the groups the logs refresh knows.</div> : null}
            <div className="overflow-x-auto"><table className="w-full border-collapse text-xs">
              <thead className="text-zinc-500"><tr><th className="py-1 text-left font-normal">Log group</th><th className="text-left font-normal">Shipped by</th><th className="text-left font-normal">Source</th><th className="text-right font-normal">Retention</th><th className="text-right font-normal">Stored</th><th className="text-right font-normal">Ingest / day</th><th className="text-right font-normal">$ / month</th></tr></thead>
              <tbody>{groups.map((g) => (
                <tr key={`${g.group}|${g.via}`} className="border-t border-zinc-800/70">
                  <td className="py-1 pr-2 font-mono text-zinc-200">{g.group}</td>
                  <td className="pr-2 text-zinc-400">{via(g.via)}</td>
                  <td className="max-w-56 truncate pr-2 text-zinc-500" title={g.source || undefined}>{g.source || "—"}</td>
                  <td className="pr-2 text-right text-zinc-400">{!g.known ? <span className="text-zinc-600" title="not seen by the daily logs refresh yet, or in another account">unknown</span> : g.retention_days ? `${g.retention_days} d` : <span className="text-amber-300/80">never expires</span>}</td>
                  <td className="pr-2 text-right">{g.stored_gb != null ? `${g.stored_gb} GB` : "—"}</td>
                  <td className="pr-2 text-right">{g.ingest_gb_day != null ? `${g.ingest_gb_day} GB` : "—"}</td>
                  <td className="text-right">{g.ingest_usd_month != null || g.storage_usd_month != null ? usd((g.ingest_usd_month || 0) + (g.storage_usd_month || 0)) : "—"}</td>
                </tr>
              ))}</tbody>
            </table></div>
            <div className="mt-1 text-[11px] text-zinc-600">{[...byVia.keys()].map(via).join(" · ")}. Retention, size and ingestion come from the daily logs refresh; "unknown" means that refresh has not seen the group.</div>
          </>
        )}
    </Group>
  );
}

function AppsBlock({ instanceId, probedAt }: { instanceId: string; probedAt: string }) {
  const [d, setD] = useState<any>(null);
  const [all, setAll] = useState(false);
  useEffect(() => { api(`/instances/${encodeURIComponent(instanceId)}/apps${all ? "?gone=1" : ""}`).then(setD).catch(() => setD(null)); }, [instanceId, probedAt, all]);
  if (!d) return null;
  const st = d.status;
  const tone = (s: string | null) => (s === "ok" ? "text-emerald-300/80" : s === "impaired" ? "text-red-300" : "text-zinc-500");
  const statusLine = st ? (
    <div className="mt-1 text-xs text-zinc-400">
      Status checks <span className="text-zinc-600">({when(st.checked_at)})</span>: system <span className={tone(st.system_status)}>{st.system_status ?? "?"}</span> · instance <span className={tone(st.instance_status)}>{st.instance_status ?? "?"}</span>{st.ebs_status ? <> · EBS <span className={tone(st.ebs_status)}>{st.ebs_status}</span></> : null}
      {st.events?.length > 0 && <div className="text-amber-300/80">AWS scheduled: {st.events.map((e: any) => `${e.code}${e.not_before ? ` from ${when(e.not_before)}` : ""}`).join("; ")}</div>}
      {d.status_events?.length > 0 && <details className="mt-0.5"><summary className="cursor-pointer text-zinc-500">Status changes ({d.status_events.length})</summary>
        <ul className="mt-0.5 space-y-0.5">{d.status_events.map((e: any) => <li key={e.id} className={e.to_status === "impaired" ? "text-red-300" : "text-zinc-400"}>{when(e.at)} · {e.field.replace("_status", "")} {e.from_status ?? "—"} → {e.to_status}</li>)}</ul></details>}
    </div>
  ) : null;
  if (!d.has_processes && !d.apps?.length) return <>{statusLine}<div className="mt-1 text-xs text-zinc-600">No process list yet: this probe predates 1.6 (update the SSM document, Settings › Permissions) or the box has not been probed since.</div></>;
  const age = (s: number) => (s >= 86400 ? `${Math.round(s / 86400)} d` : s >= 3600 ? `${Math.round(s / 3600)} h` : `${Math.max(1, Math.round(s / 60))} min`);
  const apps = (d.apps || []).filter((a: any) => a.kind === "app"); const infra = (d.apps || []).filter((a: any) => a.kind === "infra");
  const gone = (d.apps || []).filter((a: any) => a.gone);
  return (<>
    {statusLine}
    <div className="mt-1 text-xs text-zinc-400">
      <div className="flex items-center gap-2">Runs: <span className="text-zinc-500">{apps.filter((a: any) => !a.gone).length} apps, {infra.filter((a: any) => !a.gone).length} infra</span>
        <button className="text-sky-300 hover:underline" onClick={() => setAll(!all)}>{all ? "current only" : "include what left"}</button></div>
      {apps.length + infra.length === 0 && <div className="text-zinc-600">Only the operating system is running.</div>}
      <ul className="mt-0.5 space-y-0.5">
        {[...apps, ...infra].slice(0, 40).map((a: any) => (
          <li key={`${a.name}|${a.user}`} className={`flex flex-wrap gap-x-2 ${a.gone ? "text-zinc-600 line-through" : a.kind === "infra" ? "text-zinc-500" : "text-zinc-200"}`} title={a.command}>
            <span className="font-mono">{a.name}</span>
            <span className="text-zinc-500">{a.user}{a.count > 1 ? ` · ${a.count} procs` : ""} · {Math.round(a.rss_bytes / 1048576)} MB{a.cpu_pct >= 0.5 ? ` · cpu ${Number(a.cpu_pct).toFixed(0)}%` : ""} · up {age(a.oldest_seconds)}{a.probes > 1 ? ` · seen since ${when(a.first_seen)}` : ""}{a.gone ? ` · gone since ${when(a.last_seen)}` : ""}</span>
          </li>
        ))}
      </ul>
      {gone.length > 0 && !all && <div className="text-zinc-600">{gone.length} left the box</div>}
      {d.ports?.some((p: any) => !p.gone) && <div className="mt-1.5 text-zinc-500">Listens on {d.ports.filter((p: any) => !p.gone).length} ports: see the Ports tab.</div>}
      {d.events?.length > 0 && <details className="mt-0.5"><summary className="cursor-pointer text-zinc-500">App events ({d.events.length})</summary>
        <ul className="mt-0.5 space-y-0.5">{d.events.slice(0, 20).map((e: any) => <li key={e.id} className={e.event === "disappeared" ? "text-amber-300/80" : "text-zinc-400"}>{when(e.at)} · {e.event} <span className="font-mono">{e.name}</span>{e.details?.oldest_seconds ? ` (had run ${age(e.details.oldest_seconds)})` : ""}</li>)}</ul></details>}
    </div>
  </>);
}

function ActivityBlock({ activity, summary, collectedAt, previous, instanceId, rules, onRules }: { activity: any; summary: any; collectedAt: string; previous?: { collected_at: string; data: any } | null; instanceId: string; rules: any[]; onRules: () => void }) {
  const a = activity; const c = a.connections; const f = a.front_door; const l = a.logins;
  const navigate = useNavigate();
  const [asking, setAsking] = useState<string>("");
  const images = new Set<string>((activity.containers || []).map((x: any) => x.image || ""));
  const proposed = rules.filter((r) => r.status === "proposed");
  const askAgent = async () => {
    setAsking("asking…");
    try { const r = await api(`/instances/${instanceId}/signals/review`, { method: "POST", body: "{}" }); navigate(`/chat?t=${r.thread_id}`); }
    catch (e: any) { setAsking(e.message); }
  };
  const decide = async (r: any, ok: boolean) => { try { if (ok) await api(`/signal-rules/${r.id}/confirm`, { method: "POST", body: "{}" }); else await api(`/signal-rules/${r.id}`, { method: "DELETE" }); onRules(); } catch (e: any) { alert(e.message); } };
  const ports = c ? Object.entries(c.by_port || {}).sort((x: any, y: any) => y[1] - x[1]).slice(0, 6).map(([p, n]) => `${p}: ${n}`).join(", ") : "";
  const peerLine = (t: any) => `${t.ip} → :${t.port}${c?.port_map?.[String(t.port)] ? ` (${c.port_map[String(t.port)]})` : ""}${t.flows > 1 ? ` ×${t.flows}` : ""}`;
  const peers = c?.top_peers?.length ? c.top_peers.slice(0, 4).map(peerLine).join(", ") + (c.top_peers.length > 4 ? ", …" : "") : "";
  // traffic since the previous probe: the host counters are cumulative since boot, so only the difference means anything
  let traffic: string | null = null;
  const prevNet = previous?.data?.activity?.net;
  if (a.net && prevNet && previous) {
    const hours = (new Date(collectedAt.endsWith("Z") ? collectedAt : collectedAt + "Z").getTime() - new Date(previous.collected_at.endsWith("Z") ? previous.collected_at : previous.collected_at + "Z").getTime()) / 3600000;
    const delta = a.net.rx_bytes + a.net.tx_bytes - (prevNet.rx_bytes + prevNet.tx_bytes);
    if (hours > 0.05 && delta >= 0) traffic = `${delta < 1048576 ? `${Math.round(delta / 1024)} KB` : `${Math.round(delta / 1048576)} MB`} in the ${hours < 1.5 ? `${Math.round(hours * 60)} min` : `${hours.toFixed(1)} h`} since the previous probe`;
    else if (delta < 0) traffic = "counters reset since the previous probe (rebooted)";
  }
  const kind: Record<string, string> = { signal_line: "a container logged real use", request: "a request on the front door", login: "a login", external_connection: "an external client connected" };
  const restarting = (a.containers || []).filter((x: any) => x.restarts >= 10);
  return (
    <div className="mt-2 rounded border border-zinc-800 bg-zinc-950/60 p-2 text-xs">
      <div className="text-zinc-300">
        {summary?.last_use_at ? <>Last real use <span className="text-zinc-100">{when(summary.last_use_at)}</span> <span className="text-zinc-500">({kind[summary.last_use_kind] || summary.last_use_kind}; probe {when(collectedAt)})</span></>
          : <>No sign of real use in this probe's window <span className="text-zinc-500">(24 h of container logs, the front door, logins, external connections; probe {when(collectedAt)})</span></>}
      </div>
      <div className="mt-1 flex flex-wrap gap-x-4 gap-y-0.5 text-zinc-400">
        {c ? <span title={`source: ${c.source}${ports ? `; by port ${ports}` : ""}`}>connections <span className="text-zinc-200">{c.external}</span> external · {c.internal} internal · {c.ssh} ssh{peers && <span className="text-zinc-500"> · {peers}</span>}</span> : <span>connections: not readable</span>}
        <span title={f.source ? `source: ${f.source}, window: ${f.window}` : "no proxy container or access log found"}>front door {f.source ? <><span className="text-zinc-200">{f.requests}</span> requests · {f.health} health checks{f.last_request_at ? ` · last ${when(f.last_request_at)}` : f.last_request_raw ? ` · last ${f.last_request_raw}` : ""}</> : "none found"}</span>
        <span>logins {l.users_now} now{l.last_login_at ? ` · last ${l.last_login_user || "?"} ${when(l.last_login_at)}` : " · none on record"}</span>
        {traffic ? <span title="from the host's interface counters, loopback and docker bridges excluded">traffic {traffic}</span> : a.net ? <span className="text-zinc-600" title="the counters are cumulative; the next probe gives the rate">traffic: from the next probe on</span> : null}
      </div>
      {restarting.length > 0 && <div className="mt-1 text-amber-300">Restart loops: {restarting.map((x: any) => `${x.name} (${x.restarts})`).join(", ")}</div>}
      {proposed.length > 0 && (
        <div className="mt-2 rounded border border-sky-900/60 bg-sky-950/30 p-1.5">
          <div className="text-sky-200">The agent proposes {proposed.length} use-signal rule{proposed.length > 1 ? "s" : ""}:</div>
          <ul className="mt-0.5 space-y-0.5">{proposed.map((r) => <li key={r.id} className="flex flex-wrap items-center gap-2"><span className="font-mono text-zinc-300">{r.image_pattern}</span><span>{r.kind} is <span className={r.verdict === "noise" ? "text-zinc-400" : "text-emerald-300"}>{r.verdict}</span></span>{r.note && <span className="text-zinc-500">{r.note}</span>}<Button className="!px-1.5 !py-0 !text-[11px]" onClick={() => decide(r, true)}>Confirm</Button><Button variant="ghost" className="!px-1.5 !py-0 !text-[11px]" onClick={() => decide(r, false)}>Reject</Button></li>)}</ul>
        </div>
      )}
      <div className="mt-1.5 flex flex-wrap items-center gap-2 text-zinc-500">
        <span>Use-signal chips on each container: click one to rule it noise for that image (every instance running it), click again to lift.</span>
        <Button variant="ghost" className="!px-1.5 !py-0 !text-[11px]" onClick={askAgent} disabled={asking === "asking…"} title="opens a chat thread: the agent reads the samples with activity_signals and proposes rules for you to confirm">{asking === "asking…" ? "Asking…" : "Ask the agent to review the signals"}</Button>
        {asking && asking !== "asking…" && <span className="text-red-300">{asking}</span>}
      </div>
    </div>
  );
}
import { RdsLoadPanel } from "../components/rdsLoad";
import { metricLabel } from "./Knowledge";

/**
 * One tab per generic kind (the words of docs/cloud-ontology.md), with the provider's own word as the hint; the tab
 * ids stay the historical ones so links from other pages keep working. Which tabs show depends on the account the
 * sidebar looks at: an AWS account has the AWS kinds, a Vercel team its deployments; "all accounts" shows every tab
 * that has a configured provider behind it.
 */
const TABS = ["ec2", "rds", "elasticache", "lambda", "dynamodb", "elb", "ebs", "s3", "route53", "deployments", "clusters", "identities", "sg", "tags",
  "certificates", "messaging", "keys", "files", "backups", "analytics", "stacks", "threats"] as const;
type Tab = (typeof TABS)[number];
const TAB_LABEL: Record<Tab, string> = { ec2: "Compute", rds: "Databases", elasticache: "Caches", lambda: "Functions", dynamodb: "Tables", elb: "Load balancers", ebs: "Volumes", s3: "Object storage", route53: "DNS", deployments: "Deployments", clusters: "Clusters", sg: "Filters", tags: "Tags", identities: "Identities",
  certificates: "Certificates", messaging: "Messaging", keys: "Keys", files: "File systems", backups: "Backups", analytics: "Analytics", stacks: "Stacks", threats: "Threat detection" };
const TAB_NATIVE: Record<Tab, string> = { ec2: "EC2 instances", rds: "RDS · Vercel stores (Neon, …)", elasticache: "ElastiCache · Vercel stores (Redis, KV)", lambda: "Lambda", dynamodb: "DynamoDB", elb: "ELB", ebs: "EBS", s3: "S3 buckets · Vercel Blob", route53: "Route 53", deployments: "Vercel projects", clusters: "EKS, ECS", sg: "security groups", tags: "AWS tags", identities: "IAM users · IAM Identity Center · Vercel team members" ,
  certificates: "ACM", messaging: "SNS", keys: "KMS", files: "EFS", backups: "AWS Backup vaults and plans", analytics: "Athena workgroups", stacks: "CloudFormation", threats: "GuardDuty" };
/** Which providers each tab draws from; a tab shows when the scope's provider (or, for all accounts, any configured provider) is among them. */
const TAB_PROVIDERS: Record<Tab, string[]> = { ec2: ["aws"], rds: ["aws", "vercel"], elasticache: ["aws", "vercel"], lambda: ["aws"], dynamodb: ["aws"], elb: ["aws"], ebs: ["aws"], s3: ["aws", "vercel"], route53: ["aws"], deployments: ["vercel"], clusters: ["aws"], sg: ["aws"], tags: ["aws"], identities: ["aws", "vercel"] , certificates: ["aws"], messaging: ["aws"], keys: ["aws"], files: ["aws"], backups: ["aws"], analytics: ["aws"], stacks: ["aws"], threats: ["aws"] };
const ID_COLUMN: Record<Tab, string> = { ec2: "instance_id", rds: "db_instance_identifier", elasticache: "cache_cluster_id", lambda: "name", dynamodb: "name", elb: "name", ebs: "volume_id", s3: "name", route53: "id", deployments: "id", clusters: "arn", sg: "group_id", tags: "resource", identities: "arn" , certificates: "id", messaging: "id", keys: "id", files: "id", backups: "id", analytics: "id", stacks: "id", threats: "id" };

/** The platform-service tabs: rendered by ServicesPanel from /inventory/services/:tab, not by the table below. */
const SERVICE_TABS: readonly Tab[] = ["certificates", "messaging", "keys", "files", "backups", "analytics", "stacks", "threats"];
const isServiceTab = (t: Tab): t is Tab & ServiceTab => SERVICE_TABS.includes(t);
/** The tabs grouped in sections: the top row picks a section, the second row its kinds; the URL keeps the kind (?tab=), so links stay as they were. */
const SECTIONS: { id: string; label: string; tabs: Tab[] }[] = [
  { id: "compute", label: "Compute", tabs: ["ec2", "lambda", "deployments", "clusters"] },
  { id: "data", label: "Data", tabs: ["rds", "dynamodb", "elasticache", "s3", "ebs", "files", "backups", "analytics", "messaging"] },
  { id: "network", label: "Network", tabs: ["elb", "route53", "sg", "certificates"] },
  { id: "security", label: "Security", tabs: ["identities", "keys", "threats"] },
  { id: "operations", label: "Operations", tabs: ["stacks", "tags"] },
];
const sectionOf = (t: Tab) => SECTIONS.find((x) => x.tabs.includes(t)) ?? SECTIONS[0];

const pct = (v: number | null | undefined) => (v == null ? "—" : `${Math.round(Number(v))}%`);
const bytes = (b: number | null | undefined) => (b == null ? "—" : Number(b) >= 1e12 ? `${(Number(b) / 1e12).toFixed(2)} TB` : Number(b) >= 1e9 ? `${(Number(b) / 1e9).toFixed(1)} GB` : `${Math.round(Number(b) / 1e6)} MB`);
// Disk levels use the same lines as the disk alerts (80 % warning, 90 % alarm by default).
const usedTone = (p: number) => (p >= 90 ? "text-red-300" : p >= 80 ? "text-amber-300" : "");
const UsedBar = ({ used_pct, used_bytes, total_bytes, usage_at, empty }: { used_pct: number | null; used_bytes?: number | null; total_bytes?: number | null; usage_at?: string | null; empty: string }) => {
  if (used_pct == null) return <span className="text-zinc-600" title={empty}>—</span>;
  const p = Number(used_pct);
  return (
    <span className="inline-flex items-center gap-2" title={total_bytes != null ? `${bytes(used_bytes)} used · ${bytes(Number(total_bytes) - Number(used_bytes))} free of ${bytes(total_bytes)}${usage_at ? ` · probed ${when(usage_at)}` : ""}` : undefined}>
      <span className="h-1.5 w-12 overflow-hidden rounded bg-zinc-800"><span className={`block h-full ${p >= 90 ? "bg-red-400" : p >= 80 ? "bg-amber-400" : "bg-emerald-500"}`} style={{ width: `${Math.min(100, Math.max(2, p))}%` }} /></span>
      <span className={usedTone(p)}>{pct(p)}</span>
    </span>
  );
};
const gb = (v: number | null | undefined) => (v == null ? "—" : `${Number(v).toLocaleString()} GB`);
const day = (iso: string | null | undefined) => (iso ? new Date(iso).toLocaleDateString() : "—");
const yesNo = (v: unknown) => (v == null ? null : v ? "yes" : "no");

/** Rows of a definition list; entries whose value is null/undefined/"" are skipped. */
const Dl = ({ rows }: { rows: [string, ReactNode][] }) => (
  <dl className="grid grid-cols-[9.5rem_1fr] gap-x-3 gap-y-0.5 text-sm">
    {rows.filter(([, v]) => v != null && v !== "").map(([k, v]) => <Fragment key={k}><dt className="text-zinc-500">{k}</dt><dd className="min-w-0 break-words">{v}</dd></Fragment>)}
  </dl>
);

const Group = ({ title, children, action }: { title: string; children: ReactNode; action?: ReactNode }) => (
  <div className="mt-4 break-inside-avoid">
    <div className="mb-1 flex items-center justify-between text-xs uppercase tracking-wide text-zinc-500"><span>{title}</span>{action}</div>
    {children}
  </div>
);

const Mono = ({ children }: { children: ReactNode }) => <span className="font-mono text-xs">{children}</span>;

const SsmBadge = ({ status, platform }: { status: string | null; platform?: string | null }) => (
  <span className="inline-flex flex-wrap items-center gap-1"><Badge>{status || "unmanaged"}</Badge>{status && platform && <span className="text-xs text-zinc-500">{platform}</span>}</span>
);

const POOL_LABEL: Record<string, string> = { batch: "Batch", karpenter: "Karpenter", eks: "EKS", asg: "ASG" };
/** A member of a pool its controller scales: the advisor reasons about the pool, not the instance. */
const PoolBadge = ({ kind, name }: { kind: string; name?: string | null }) => (
  <span title={name ? `${POOL_LABEL[kind] || kind} pool ${name}` : undefined} className="inline-block rounded border border-sky-500/30 bg-sky-500/10 px-1.5 py-0.5 text-[11px] font-medium text-sky-300">{POOL_LABEL[kind] || kind}</span>
);

const Tags = ({ tags }: { tags: Record<string, string> | null | undefined }) => {
  const entries = Object.entries(tags || {});
  if (!entries.length) return <div className="text-sm text-zinc-500">No tags.</div>;
  return (
    <table className="w-full text-xs">
      <tbody>{entries.sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => <tr key={k} className="border-t border-zinc-800/60"><td className="py-0.5 pr-2 text-zinc-500">{k}</td><td className="break-all py-0.5">{String(v)}</td></tr>)}</tbody>
    </table>
  );
};

/** Where a Route 53 link lands in the inventory: the tab and id, or nothing for kinds the inventory does not hold (distributions, NAT gateways). */
const LINK_TAB: Record<string, Tab> = { ec2: "ec2", rds: "rds", elasticache: "elasticache", s3: "s3", lambda: "lambda", dynamodb: "dynamodb", alb: "elb", nlb: "elb", clb: "elb", lb: "elb" };
const LINK_KIND: Record<string, string> = { ec2: "instance", rds: "RDS", rds_cluster: "RDS cluster", elasticache: "ElastiCache", elasticache_group: "ElastiCache group", s3: "S3 bucket", lambda: "Lambda", alb: "ALB", nlb: "NLB", clb: "classic LB", lb: "load balancer", cloudfront: "CloudFront", nat: "NAT gateway", eip: "Elastic IP", eni: "interface", apigw: "API Gateway", beanstalk: "Beanstalk" };
const ResourceLink = ({ l }: { l: { kind: string; id: string; name?: string | null; state?: string | null } }) => {
  const tab = LINK_TAB[l.kind]; const label = l.name && l.name !== l.id ? `${l.name} (${l.id})` : l.id;
  const stateNote = l.state && !["running", "available", "active", "Deployed", "in-use"].includes(l.state) ? <span className="ml-1 text-amber-300">{l.state}</span> : null;
  return <span className="inline-flex items-center gap-1 text-sm"><span className="text-xs text-zinc-500">{LINK_KIND[l.kind] || l.kind}</span>{tab ? <Link className="hover:underline" to={`/inventory?tab=${tab}&id=${encodeURIComponent(l.id)}`}>{label}</Link> : <span>{label}</span>}{stateNote}</span>;
};

/** The Route 53 records that reach one resource, directly (hop 1) or through a load balancer or distribution (hop 2+). */
const Domains = ({ list, empty = "No Route 53 record in this account points here." }: { list: any[] | null | undefined; empty?: string }) => (
  <Group title="Domains">
    {!list?.length ? <div className="text-sm text-zinc-500">{empty}</div> : (
      <ul className="space-y-0.5 text-sm">
        {list.map((d: any, i: number) => <li key={`${d.name}-${d.type}-${i}`} className="flex flex-wrap items-center gap-2"><Link className="font-mono text-xs hover:underline" to={`/inventory?tab=route53&zone=${encodeURIComponent(d.zone_id || d.zone_name)}&id=${encodeURIComponent(d.id)}`}>{d.name}</Link><span className="text-xs text-zinc-500">{d.type}{d.alias ? " alias" : ""}</span>{d.hop > 1 ? <span className="text-xs text-zinc-500">via {d.summary?.split(" → ")[0] || "a load balancer"}</span> : null}</li>)}
      </ul>
    )}
  </Group>
);

/** The first few Route 53 names that lead to a row, for the list; the detail's Domains group has them all with how they get there. */
const DomainLine = ({ list, max = 3 }: { list?: any[] | null; max?: number }) => {
  if (!list?.length) return null;
  const names = [...new Set(list.map((d: any) => String(d.name)))];
  return <div className="text-xs text-sky-300/80" title={names.join("\n")}>{names.slice(0, max).join(" · ")}{names.length > max ? <span className="text-zinc-500"> +{names.length - max} more</span> : null}</div>;
};

/** Links to the Findings and Recommendations pages filtered on one resource, with the counts the inventory stored. */
const Related = ({ id, recs, findings, list }: { id: string; recs: number; findings: number; list?: any[] }) => (
  <Group title="Findings and recommendations">
    <div className="flex flex-wrap gap-3 text-sm">
      <Link className="underline" to={`/findings?q=${encodeURIComponent(id)}`}>{findings} finding{findings === 1 ? "" : "s"} in the last run</Link>
      <Link className="underline" to={`/recommendations?status=all&q=${encodeURIComponent(id)}`}>{recs} open recommendation{recs === 1 ? "" : "s"}</Link>
    </div>
    {list && list.length > 0 && (
      <ul className="mt-1 space-y-0.5 text-sm">
        {list.map((r: any) => <li key={r.id} className="flex items-center justify-between gap-2"><Link className="truncate hover:underline" to={`/recommendations?status=${r.status}&id=${r.id}`}>{r.title}</Link><span className="flex shrink-0 items-center gap-1"><Badge>{r.status}</Badge><span className="w-16 text-right text-zinc-300">{usd(r.est_monthly_saving)}</span></span></li>)}
      </ul>
    )}
  </Group>
);

export default function Inventory() {
  const [params, setParams] = useSearchParams();
  // which kinds to show: the scope's provider (remembered with the scope, so the first paint is right), or every configured provider
  const [providersUp, setProvidersUp] = useState<string[] | null>(cachedProviders()); // the configured providers, by id
  const [scopeProvider, setScopeProvider] = useState<string | null>(currentScope() === "all" ? null : currentScopeProvider());
  const [scopeKnown, setScopeKnown] = useState(currentScope() === "all" || currentScopeProvider() !== null);
  useEffect(() => {
    api("/providers").then((d) => { const ids = (d.providers || []).filter((p: any) => p.configured).map((p: any) => p.id); rememberProviders(ids); setProvidersUp(ids); }).catch(() => setProvidersUp((p) => p ?? ["aws"]));
    const scope = currentScope();
    if (scope === "all") { setScopeProvider(null); setScopeKnown(true); }
    else api("/accounts").then((d) => { const prov = (d.records || []).find((r: any) => r.id === scope)?.provider ?? null; setScopeProvider(prov); setScopeKnown(true); if (prov) setScope(scope, prov); }).catch(() => setScopeKnown(true));
  }, []);
  const ready = scopeKnown && (scopeProvider !== null || providersUp !== null);
  const awsView = scopeProvider !== "vercel"; // the AWS lists, stats and search only when the scope is AWS or every account
  const visibleTabs = TABS.filter((t) => (scopeProvider ? TAB_PROVIDERS[t].includes(scopeProvider) : TAB_PROVIDERS[t].some((p) => (providersUp ?? ["aws"]).includes(p))));
  const requested = params.get("tab") as Tab;
  const tab = (TABS.includes(requested) && visibleTabs.includes(requested) ? requested : visibleTabs[0] ?? "ec2") as Tab;
  const selectedId = params.get("id");
  const state = params.get("state") || "";
  const ssm = params.get("ssm") || "";
  const sort = params.get("sort") || "";
  const gone = params.get("gone") === "1";
  const zone = params.get("zone") || "";
  const link = params.get("link") || "";
  const [q, setQ] = useState(params.get("q") || "");
  const [zones, setZones] = useState<any[]>([]);
  const [summary, setSummary] = useState<any>(null);
  // The rows are kept with the tab they were fetched for: a tab switch renders "Loading…" until its own rows arrive,
  // never the previous tab's rows under the new tab's row renderer (an EC2 row has no `groups` for the identities row).
  const [rowsState, setRowsState] = useState<{ tab: Tab; list: any[] } | null>(null);
  const rows = rowsState && rowsState.tab === tab ? rowsState.list : null;
  const setRows = (list: any[] | null) => setRowsState(list ? { tab, list } : null);
  const [detail, setDetail] = useState<any>(null);
  const [err, setErr] = useState("");
  const [refreshing, setRefreshing] = useState(false);
  const [probe, setProbe] = useState<{ busy: boolean; error: string }>({ busy: false, error: "" });

  const set = (patch: Record<string, string | null>) => {
    const p = new URLSearchParams(params);
    for (const [k, v] of Object.entries(patch)) v ? p.set(k, v) : p.delete(k);
    setParams(p);
  };
  // A row opens its detail under itself; clicking the open row again closes it.
  const pick = (id: string) => set({ id: selectedId === id ? null : id });

  const loadSummary = () => api("/inventory/summary").then(setSummary).catch((e) => setErr(e.message));
  // A tab switch clears the table at once and ignores a slower response from the previous tab, so EC2 rows can
  // never sit under the Lambda header (or stick when a request fails).
  const rowsRequest = useRef(0);
  // The table's last height: while the next tab loads, the placeholder keeps it, so the page does not get shorter
  // than the scroll position and jump up.
  const tableRef = useRef<HTMLDivElement>(null);
  const tableHeight = useRef(0);
  const loadRows = () => {
    const seq = ++rowsRequest.current;
    if (tableRef.current) tableHeight.current = tableRef.current.offsetHeight;
    setRows(null);
    // The Tags tab is its own report (src/tag_hygiene.ts): nothing to fetch here.
    // So is Security groups (src/security_groups.ts): its panel fetches its own rows.
    if (tab === "tags" || tab === "sg" || tab === "clusters" || tab === "deployments" || isServiceTab(tab) || scopeProvider === "vercel") { setRows([]); return Promise.resolve(); }
    const qs = new URLSearchParams();
    if (tab === "ec2") { if (state) qs.set("state", state); if (ssm) qs.set("ssm", ssm); }
    if (tab === "ebs" && state) qs.set("state", state);
    if (tab === "elb" && state) qs.set("kind", state);
    if (tab === "route53") { if (zone) qs.set("zone", zone); if (link) qs.set("link", link); }
    if (params.get("q")) qs.set("q", params.get("q")!);
    if (sort) qs.set("sort", sort);
    if (gone) qs.set("gone", "1");
    return api(`/inventory/${tab === "identities" ? "iam" : tab}?${qs}`).then((r) => { if (seq === rowsRequest.current) setRows(r); }).catch((e) => { if (seq === rowsRequest.current) { setErr(e.message); setRows([]); } });
  };
  const loadDetail = () => {
    if (!selectedId) { setDetail(null); return Promise.resolve(); }
    if (tab === "ec2") return api(`/inventory/ec2/${selectedId}`).then(setDetail).catch(() => setDetail(null));
    setDetail((rows || []).find((r) => r[ID_COLUMN[tab]] === selectedId) || null);
    return Promise.resolve();
  };

  useEffect(() => { loadSummary(); }, []);
  useEffect(() => { if (tab === "route53") api("/inventory/route53/zones").then(setZones).catch(() => setZones([])); }, [tab, summary?.refreshed_at]);
  useEffect(() => { loadRows(); }, [tab, state, ssm, sort, gone, zone, link, params.get("q")]);
  useEffect(() => { loadDetail(); setProbe({ busy: false, error: "" }); }, [tab, selectedId, rows]);

  const [usageBusy, setUsageBusy] = useState(false);
  const [usageMsg, setUsageMsg] = useState("");
  const [agentBusy, setAgentBusy] = useState(false);
  const sendToAgent = async () => {
    setAgentBusy(true); setUsageMsg(""); setErr("");
    try {
      const r = await api("/usage/investigate", { method: "POST", body: "{}" });
      setUsageMsg(`${r.dispatched} box${r.dispatched === 1 ? "" : "es"} sent to the agent of ${r.candidates} unsure${r.skipped?.cooling ? ` (${r.skipped.cooling} looked at within the last week)` : ""}${r.skipped?.pending ? ` (${r.skipped.pending} still running)` : ""}${r.sent?.length ? `: ${r.sent.join(", ")}` : ""}${r.errors?.length ? ` · ${r.errors[0]}` : ""}. Each verdict lands on its box's profile when the run finishes, usually a few minutes.`);
    } catch (e: any) { setErr(e.message); }
    finally { setAgentBusy(false); }
  };
  const recomputeUsage = async () => {
    setUsageBusy(true); setUsageMsg(""); setErr("");
    try {
      const r = await api("/usage/recompute", { method: "POST", body: "{}" });
      const v = r.review?.verdicts || {};
      setUsageMsg(`${r.profiles.profiled} profiles recomputed, ${r.profiles.recommendations} schedule recommendation(s); Jev (typed, not the Claude agent) reviewed ${r.review.reviewed} (${["confirm", "adjust", "keep_running"].filter((k) => v[k]).map((k) => `${v[k]} ${k.replace("_", " ")}`).join(", ") || "none"})${r.review.errors?.length ? ` · ${r.review.errors[0]}` : ""}${r.profiles.errors?.length ? ` · ${r.profiles.errors[0]}` : ""}`);
      if (selectedId) loadDetail();
    } catch (e: any) { setErr(e.message); }
    finally { setUsageBusy(false); }
  };
  const refresh = async () => {
    setRefreshing(true); setErr("");
    try {
      const r = await api("/inventory/refresh", { method: "POST" });
      if (r.errors?.length) setErr(`Refresh finished with errors: ${r.errors.join("; ")}`);
      await Promise.all([loadSummary(), loadRows()]);
    } catch (e: any) { setErr(e.message); }
    finally { setRefreshing(false); }
  };

  const runProbe = async (id: string, kind?: string) => {
    setProbe({ busy: true, error: "" });
    try { const r = await api(`/instances/${id}/probe${kind ? `?kind=${kind}` : ""}`, { method: "POST" }); await refresh(); if (r?.failed?.length) setProbe({ busy: false, error: `${r.failed.map((f: any) => `${f.kind}: ${f.message}`).join("; ")}` }); else setProbe({ busy: false, error: "" }); return; }
    catch (e: any) { setProbe({ busy: false, error: e.message }); return; }
  };

  const toggleSort = (col: string) => set({ sort: sort === col ? `-${col}` : sort === `-${col}` ? null : col });
  const SortTh = ({ col, children, className = "" }: { col: string; children: ReactNode; className?: string }) => (
    <Th className={className}><button className="uppercase hover:text-zinc-300" onClick={() => toggleSort(col)}>{children}{sort === col ? " ↑" : sort === `-${col}` ? " ↓" : ""}</button></Th>
  );

  const s = summary;
  const inv = awsView ? s?.[tab] : null;

  if (!ready) return <div className="space-y-4"><h1 className="text-xl font-semibold text-zinc-100">Inventory</h1><Empty>Loading…</Empty></div>;
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h1 className="text-xl font-semibold text-zinc-100">Inventory</h1>
          <div className="text-sm text-zinc-500">{s?.refreshed_at ? <>Snapshot from {when(s.refreshed_at)} · {tab === "route53" ? "DNS links refreshed after every run and by Refresh now (not by the watcher)" : "refreshed after every run and every watcher sample"}</> : "No snapshot yet: start a run, or refresh now."}</div>
        </div>
        <span className="flex gap-2">{tab === "ec2" && <Button variant="ghost" onClick={recomputeUsage} disabled={usageBusy || agentBusy} title="Recompute every usage profile (28 days of CloudWatch, probes and shipped logs) and have Jev, the typed decision engine, decide each window. No Claude agent run.">{usageBusy ? "Profiling and asking Jev…" : "Recompute usage + ask Jev"}</Button>}{tab === "ec2" && <Button variant="ghost" onClick={sendToAgent} disabled={usageBusy || agentBusy} title="Send every box Jev was not sure about to the Claude agent (one agent run each, under the agent quota and the daily cap). The verdicts land on the profiles as they finish.">{agentBusy ? "Sending to the agent…" : "Send unsure boxes to the agent"}</Button>}<Button variant="ghost" onClick={refresh} disabled={refreshing}>{refreshing ? "Refreshing…" : "Refresh now"}</Button></span>
      </div>
      {usageMsg && <div className="text-sm text-zinc-400">{usageMsg}</div>}
      {err && <div className="text-sm text-red-300">{err}</div>}

      <div className="space-y-1">
        <div className="flex flex-wrap gap-1">
          {SECTIONS.filter((x) => x.tabs.some((t) => visibleTabs.includes(t))).map((x) => {
            const first = x.tabs.find((t) => visibleTabs.includes(t))!;
            const count = awsView ? x.tabs.filter((t) => visibleTabs.includes(t)).reduce((a, t) => a + (tabCount(s, t) ?? 0), 0) : 0;
            return (
              <button key={x.id} onClick={() => sectionOf(tab).id !== x.id && set({ tab: first, id: null, sort: null, state: null })} className={`rounded px-3 py-1 text-sm ${sectionOf(tab).id === x.id ? "bg-zinc-800 text-zinc-100" : "text-zinc-400 hover:bg-zinc-900 hover:text-zinc-200"}`}>
                {x.label}{count > 0 && <span className="ml-1 text-xs text-zinc-500">{count}</span>}
              </button>
            );
          })}
        </div>
        <div className="flex flex-wrap gap-1 border-b border-zinc-800">
          {sectionOf(tab).tabs.filter((t) => visibleTabs.includes(t)).map((t) => (
            <button key={t} onClick={() => set({ tab: t, id: null, sort: null, state: null })} title={TAB_NATIVE[t]} className={`-mb-px border-b-2 px-3 py-1.5 text-sm ${tab === t ? "border-zinc-100 text-zinc-100" : "border-transparent text-zinc-400 hover:text-zinc-200"}`}>
              {TAB_LABEL[t]}{awsView && tabCount(s, t) != null && <span className="ml-1 text-xs text-zinc-500">{tabCount(s, t)}</span>}
            </button>
          ))}
          <span className="ml-auto self-center pr-1 text-[11px] text-zinc-600">{TAB_NATIVE[tab]}</span>
        </div>
      </div>

      {tab === "deployments" && <VercelProjects />}
      {scopeProvider === "vercel" && tab === "identities" && <VercelMembers />}
      {awsView && tab === "identities" && <Access />}
      {awsView && tab === "identities" && <IdentityCenter />}
      {scopeProvider === "vercel" && tab === "rds" && <VercelStores kind="database" />}
      {scopeProvider === "vercel" && tab === "elasticache" && <VercelStores kind="cache" />}
      {scopeProvider === "vercel" && tab === "s3" && <VercelStores kind="storage" />}
      {tab === "tags" && <TagsPanel />}
      {tab === "sg" && <SecurityGroupsPanel selected={selectedId} onSelect={(id) => set({ id })} />}
      {awsView && tab === "sg" && <ServicesPanel tab="waf" summary={s?.services?.waf} selected={selectedId} onSelect={(id) => set({ id })} q="" gone={false} />}
      {tab === "clusters" && <ClustersPanel selected={selectedId} onSelect={(id) => set({ id })} />}

      {tab === "ec2" && inv && (
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-6">
          <Stat label="Running" value={inv.running} hint={`${inv.total} instances seen`} />
          <Stat label="Stopped" value={inv.stopped} hint={inv.gone ? `${inv.gone} gone` : undefined} />
          <Stat label="SSM online" value={inv.ssm_online} hint={`of ${inv.running} running${inv.ssm_lost ? ` · ${inv.ssm_lost} connection lost` : ""}`} />
          <Stat label="SSM not managed" value={inv.ssm_unmanaged} hint="running, no SSM registration" />
          <Stat label="On-demand / month" value={usd(inv.monthly_usd_running)} hint={`list price of running${inv.running_unpriced ? ` · ${inv.running_unpriced} unpriced` : ""}`} />
          <Stat label="EBS attached" value={gb(inv.ebs_gb)} hint="all instances" />
        </div>
      )}
      {tab === "rds" && inv && (
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          <Stat label="Instances" value={inv.total} hint={`${inv.available} available${inv.gone ? ` · ${inv.gone} gone` : ""}`} />
          <Stat label="On-demand / month" value={usd(inv.monthly_usd)} hint={inv.unpriced ? `${inv.unpriced} unpriced (serverless or unknown engine)` : "instance hours only, no storage or I/O"} />
          <Stat label="Allocated storage" value={gb(inv.storage_gb)} />
          <Stat label="Open recs · findings" value={`${inv.open_recs} · ${inv.findings}`} />
        </div>
      )}
      {tab === "elasticache" && inv && (
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          <Stat label="Clusters" value={inv.total} hint={`${inv.nodes} nodes${inv.gone ? ` · ${inv.gone} gone` : ""}`} />
          <Stat label="On-demand / month" value={usd(inv.monthly_usd)} hint={inv.unpriced ? `${inv.unpriced} unpriced` : "node price × nodes"} />
          <Stat label="Open recs · findings" value={`${inv.open_recs} · ${inv.findings}`} />
        </div>
      )}

      {tab === "ebs" && inv && (
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
          <Stat label="Volumes" value={inv.total} hint={`${Number(inv.gb).toLocaleString()} GB${inv.probed ? ` · used / free known for ${inv.probed}${inv.high ? `, ${inv.high} over 80 %` : ""}` : " · probe an instance to see used / free"}${inv.gone ? ` · ${inv.gone} gone` : ""}`} />
          <Stat label="At list / month" value={usd(inv.monthly_usd)} hint="storage plus provisioned IOPS and throughput" />
          <Stat label="Unattached" value={inv.unattached} hint={inv.unattached ? `${usd(inv.unattached_usd)}/month for nothing` : "none"} />
          <Stat label="On stopped instances" value={inv.on_stopped} hint={inv.on_stopped ? `${usd(inv.on_stopped_usd)}/month: AWS says in-use, but the instance is not running` : "every attached volume is on a running instance"} />
          <Stat label="Still gp2" value={inv.gp2} hint={inv.gp2 ? "gp3 is 20 % cheaper for the same size" : "all gp3 or better"} />
        </div>
      )}
      {tab === "s3" && inv && (
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          <Stat label="Buckets" value={inv.total} hint={`${Number(inv.gb).toLocaleString(undefined, { maximumFractionDigits: 0 })} GB${inv.gone ? ` · ${inv.gone} gone` : ""}`} />
          <Stat label="At list / month" value={usd(inv.monthly_usd)} hint={`${Number(inv.standard_gb).toLocaleString(undefined, { maximumFractionDigits: 0 })} GB in Standard`} />
          <Stat label="Big, no lifecycle" value={inv.big_no_lifecycle} hint="over 5 GB with no lifecycle rule" />
          <Stat label="Public" value={inv.public_unknown && !inv.public ? "?" : inv.public} hint={inv.public ? "bucket policy allows public access" : inv.public_unknown ? "unknown: grant s3:GetBucketPolicyStatus" : "none"} />
        </div>
      )}
      {tab === "elb" && inv && (
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
          <Stat label="Load balancers" value={inv.total} hint={`${inv.alb} ALB · ${inv.nlb} NLB · ${inv.clb} classic${inv.gwlb ? ` · ${inv.gwlb} gateway` : ""}${inv.gone ? ` · ${inv.gone} gone` : ""}`} />
          <Stat label="Internet-facing" value={inv.internet_facing} hint={`${inv.total - inv.internet_facing} internal`} />
          <Stat label="Targets" value={`${inv.healthy} / ${inv.targets}`} hint={`healthy / registered${inv.unhealthy ? ` · ${inv.unhealthy} unhealthy` : ""}${inv.no_healthy_target ? ` · ${inv.no_healthy_target} balancer${inv.no_healthy_target === 1 ? "" : "s"} with no healthy target` : ""}`} />
          <Stat label="Traffic, 30 days" value={`${(Number(inv.requests_30d) / 1e6).toFixed(2)}M req`} hint={`${Number(inv.gb_30d).toLocaleString(undefined, { maximumFractionDigits: 1 })} GB processed${inv.beanstalk ? ` · ${inv.beanstalk} made by Beanstalk` : ""}`} />
          <Stat label="Fixed price / month" value={usd(inv.monthly_usd)} hint="hourly list price × 730; LCU-hours (ALB, NLB) and per-GB (classic) come on top" />
        </div>
      )}
      {tab === "identities" && inv?.iam && (
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
          <Stat label="IAM users" value={inv.iam.users} hint={`${inv.iam.admins} administrator${inv.iam.admins === 1 ? "" : "s"}`} />
          <Stat label="Console without MFA" value={<span className={inv.iam.console_without_mfa ? "text-orange-300" : "text-emerald-300"}>{inv.iam.console_without_mfa}</span>} hint="a password alone opens the console" />
          <Stat label="Active access keys" value={inv.iam.keys_active} hint={`${inv.iam.keys_over_90d} older than 90 days`} />
          <Stat label="Unused 90 days" value={inv.iam.unused_90d} hint="console or key, no sign-in or call in 90 days" />
        </div>
      )}
      {tab === "route53" && inv && (
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
          <Stat label="Hosted zones" value={inv.zones} hint={`${inv.private_zones ? `${inv.private_zones} private · ` : ""}${inv.total} records${inv.gone ? ` · ${inv.gone} gone` : ""}`} />
          <Stat label="Linked" value={inv.linked} hint="lead to a resource in this account" />
          <Stat label="Unmatched" value={inv.unmatched} hint={inv.unmatched ? "AWS-hosted names this account does not have: deleted (dangling) or another account's" : "no dangling records"} />
          <Stat label="Outside AWS" value={inv.external} hint={`${inv.none} name nothing (NS, SOA, TXT, MX…)`} />
          <Stat label="At list / month" value={usd(inv.monthly_usd, 2)} hint={`0.50 per zone${inv.queries_30d ? ` · ${(Number(inv.queries_30d) / 1e6).toFixed(2)}M queries in 30 days` : ""}${inv.empty_zones ? ` · ${inv.empty_zones} zone${inv.empty_zones === 1 ? "" : "s"} with no records` : ""}`} />
        </div>
      )}
      {tab === "lambda" && inv && (
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          <Stat label="Functions" value={inv.total} hint={`${inv.active} invoked in 30 days${inv.gone ? ` · ${inv.gone} gone` : ""} · ${inv.arm} on arm64`} />
          <Stat label="At list / month" value={usd(inv.monthly_usd)} hint="GB-seconds and requests from 30 days of metrics, before the Savings Plan and the free tier" />
          <Stat label="Invocations / month" value={Number(inv.invocations_month).toLocaleString()} hint={`${(Number(inv.gb_seconds_month) / 1e6).toFixed(2)}M GB-seconds`} />
          <Stat label="Open recs · findings" value={`${inv.open_recs} · ${inv.findings}`} />
        </div>
      )}

      {tab === "dynamodb" && inv && (
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          <Stat label="Tables" value={inv.total} hint={`${inv.on_demand} on demand · ${inv.total - inv.on_demand} provisioned · ${inv.active} read or written in 30 days${inv.gone ? ` · ${inv.gone} gone` : ""}`} />
          <Stat label="At list / month" value={usd(inv.monthly_usd)} hint={`${usd(inv.storage_usd)} storage · ${usd(inv.capacity_usd)} capacity (provisioned units by the hour, on-demand request units from 30 days of metrics)`} />
          <Stat label="Stored" value={`${Number(inv.gb).toFixed(1)} GB`} hint={`${Number(inv.items).toLocaleString()} items`} />
          <Stat label="Open recs · findings" value={`${inv.open_recs} · ${inv.findings}`} />
        </div>
      )}

      {awsView && tab !== "tags" && tab !== "sg" && <div className="flex flex-wrap items-center gap-2">
        {tab === "ec2" && (
          <>
            <select value={state} onChange={(e) => set({ state: e.target.value })}>
              <option value="">All states</option><option value="running">running</option><option value="stopped">stopped</option><option value="terminated">terminated</option><option value="pending">pending</option><option value="stopping">stopping</option>
            </select>
            <select value={ssm} onChange={(e) => set({ ssm: e.target.value })}>
              <option value="">Any SSM status</option><option value="online">SSM online</option><option value="lost">SSM connection lost</option><option value="unmanaged">not managed by SSM</option><option value="managed">managed (any status)</option>
            </select>
          </>
        )}
        {tab === "elb" && (
          <select value={state} onChange={(e) => set({ state: e.target.value, id: null })}>
            <option value="">All kinds</option><option value="alb">ALB</option><option value="nlb">NLB</option><option value="clb">classic</option><option value="gwlb">gateway</option>
          </select>
        )}
        {tab === "ebs" && (
          <select value={state} onChange={(e) => set({ state: e.target.value, id: null })}>
            <option value="">All volumes</option><option value="in-use">attached (in-use)</option><option value="stopped">on a stopped instance</option><option value="available">unattached (available)</option>
          </select>
        )}
        {tab === "route53" && (
          <>
            <select value={zone} onChange={(e) => set({ zone: e.target.value, id: null })}>
              <option value="">All zones</option>{zones.map((z: any) => <option key={z.zone_id} value={z.zone_id}>{z.name}{z.private ? " (private)" : ""} · {z.records}</option>)}
            </select>
            <select value={link} onChange={(e) => set({ link: e.target.value, id: null })}>
              <option value="">Any target</option><option value="linked">linked to a resource here</option><option value="unmatched">unmatched (dangling?)</option><option value="external">outside AWS</option><option value="none">names nothing</option>
            </select>
          </>
        )}
        <form onSubmit={(e) => { e.preventDefault(); set({ q }); }}><input placeholder={tab === "ec2" ? "search name, id, type or IP" : tab === "route53" ? "search name, target or resource" : "search"} value={q} onChange={(e) => setQ(e.target.value)} className="w-64" /></form>
        <label className="flex items-center gap-1 text-sm text-zinc-400"><input type="checkbox" checked={gone} onChange={(e) => set({ gone: e.target.checked ? "1" : null })} /> include gone</label>
        {rows && !isServiceTab(tab) && <span className="text-sm text-zinc-500">{rows.length} rows</span>}
      </div>}

      {awsView && isServiceTab(tab) && <ServicesPanel tab={tab} summary={s?.services?.[tab]} selected={selectedId} onSelect={(id) => set({ id })} q={params.get("q") || ""} gone={gone} />}

      {awsView && tab !== "tags" && tab !== "sg" && !isServiceTab(tab) && <div ref={tableRef} style={!rows ? { minHeight: tableHeight.current } : undefined}>
        {!rows ? <Empty>Loading…</Empty> : rows.length === 0 ? <Empty>{s?.refreshed_at ? "Nothing matches." : "No snapshot yet."}</Empty> : (
          <div className="min-w-0 overflow-x-auto self-start">
            <table className="w-full border-collapse overflow-hidden rounded-lg border border-zinc-800">
              {tab === "ec2" && (
                <thead className="bg-zinc-900"><tr>
                  <SortTh col="name">Name</SortTh><SortTh col="instance_type">Type</SortTh><SortTh col="state">State</SortTh><SortTh col="ssm_status">SSM</SortTh>
                  <SortTh col="cpu_30d" className="text-right">CPU 30d</SortTh><SortTh col="probe_mem_pct" className="text-right">Mem</SortTh><SortTh col="ebs_gb" className="text-right">EBS</SortTh>
                  <SortTh col="monthly_usd" className="text-right">$ / mo</SortTh><SortTh col="launch_time">Launched</SortTh><SortTh col="open_recs" className="text-right">Recs</SortTh><SortTh col="findings" className="text-right">Findings</SortTh>
                </tr></thead>
              )}
              {tab === "rds" && (
                <thead className="bg-zinc-900"><tr>
                  <SortTh col="db_instance_identifier">Identifier</SortTh><SortTh col="class">Class</SortTh><SortTh col="engine">Engine</SortTh><SortTh col="status">Status</SortTh>
                  <SortTh col="storage_gb" className="text-right">Storage</SortTh><SortTh col="cpu_30d" className="text-right">CPU 30d</SortTh><SortTh col="monthly_usd" className="text-right">$ / mo</SortTh>
                  <SortTh col="created">Created</SortTh><SortTh col="open_recs" className="text-right">Recs</SortTh><SortTh col="findings" className="text-right">Findings</SortTh>
                </tr></thead>
              )}
              {tab === "ebs" && (
                <thead className="bg-zinc-900"><tr>
                  <SortTh col="volume_id">Volume</SortTh><SortTh col="volume_type">Type</SortTh><SortTh col="size_gb" className="text-right">Size</SortTh><SortTh col="used_pct" className="text-right">Used</SortTh><SortTh col="iops" className="text-right">IOPS prov.</SortTh>
                  <SortTh col="iops_max" className="text-right">IOPS peak 30d</SortTh><SortTh col="state">State</SortTh><SortTh col="instance_id">Attached to</SortTh><SortTh col="monthly_usd" className="text-right">$ / mo</SortTh><SortTh col="created">Created</SortTh>
                </tr></thead>
              )}
              {tab === "s3" && (
                <thead className="bg-zinc-900"><tr>
                  <SortTh col="name">Bucket</SortTh><SortTh col="region">Region</SortTh><SortTh col="total_gb" className="text-right">Size</SortTh><SortTh col="standard_gb" className="text-right">In Standard</SortTh>
                  <SortTh col="objects" className="text-right">Objects</SortTh><SortTh col="lifecycle_rules" className="text-right">Lifecycle</SortTh><SortTh col="monthly_usd" className="text-right">$ / mo</SortTh><SortTh col="created">Created</SortTh>
                </tr></thead>
              )}
              {tab === "route53" && (
                <thead className="bg-zinc-900"><tr>
                  <SortTh col="name">Record</SortTh><SortTh col="type">Type</SortTh><SortTh col="target">Value</SortTh><SortTh col="link_state">Leads to</SortTh><SortTh col="zone_name">Zone</SortTh><SortTh col="ttl" className="text-right">TTL</SortTh>
                </tr></thead>
              )}
              {tab === "elb" && (
                <thead className="bg-zinc-900"><tr>
                  <SortTh col="name">Load balancer</SortTh><SortTh col="kind">Kind</SortTh><SortTh col="state">State</SortTh><Th>Fronts</Th><SortTh col="healthy" className="text-right">Targets</SortTh>
                  <SortTh col="requests_30d" className="text-right">Requests 30d</SortTh><SortTh col="gb_30d" className="text-right">GB 30d</SortTh><SortTh col="monthly_usd" className="text-right">$ / mo</SortTh><SortTh col="created">Created</SortTh>
                </tr></thead>
              )}
              {tab === "identities" && (
                <thead className="bg-zinc-900"><tr>
                  <SortTh col="name">User</SortTh><Th>Console</Th><Th>MFA</Th><Th>Admin</Th><Th>Groups · policies</Th><SortTh col="keys">Access keys</SortTh><SortTh col="last_used">Last used</SortTh><SortTh col="created">Created</SortTh>
                </tr></thead>
              )}
              {tab === "lambda" && (
                <thead className="bg-zinc-900"><tr>
                  <SortTh col="name">Function</SortTh><SortTh col="runtime">Runtime</SortTh><SortTh col="memory_mb" className="text-right">Memory</SortTh><SortTh col="invocations_month" className="text-right">Invocations / mo</SortTh>
                  <SortTh col="avg_duration_ms" className="text-right">Avg ms</SortTh><SortTh col="gb_seconds_month" className="text-right">GB-s / mo</SortTh><SortTh col="errors_30d" className="text-right">Errors 30d</SortTh><SortTh col="monthly_usd" className="text-right">$ / mo</SortTh><SortTh col="open_recs" className="text-right">Recs</SortTh><SortTh col="findings" className="text-right">Findings</SortTh>
                </tr></thead>
              )}
              {tab === "dynamodb" && (
                <thead className="bg-zinc-900"><tr>
                  <SortTh col="name">Table</SortTh><SortTh col="billing_mode">Mode</SortTh><SortTh col="read_capacity" className="text-right">RCU / WCU</SortTh><SortTh col="size_bytes" className="text-right">Size</SortTh><SortTh col="item_count" className="text-right">Items</SortTh>
                  <SortTh col="read_units_30d" className="text-right">Reads 30d</SortTh><SortTh col="write_units_30d" className="text-right">Writes 30d</SortTh><SortTh col="monthly_usd" className="text-right">$ / mo</SortTh><SortTh col="open_recs" className="text-right">Recs</SortTh>
                </tr></thead>
              )}
              {tab === "elasticache" && (
                <thead className="bg-zinc-900"><tr>
                  <SortTh col="cache_cluster_id">Cluster</SortTh><SortTh col="node_type">Node type</SortTh><SortTh col="engine">Engine</SortTh><SortTh col="num_nodes" className="text-right">Nodes</SortTh><SortTh col="status">Status</SortTh>
                  <SortTh col="monthly_usd" className="text-right">$ / mo</SortTh><SortTh col="created">Created</SortTh><SortTh col="open_recs" className="text-right">Recs</SortTh><SortTh col="findings" className="text-right">Findings</SortTh>
                </tr></thead>
              )}
              <tbody>
                {rows.map((r) => {
                  const id = r[ID_COLUMN[tab]] as string;
                  const cls = `cursor-pointer border-t border-zinc-800 hover:bg-zinc-900/60 ${selectedId === id ? "bg-zinc-900" : ""} ${r.gone ? "text-zinc-500" : ""}`;
                  // The detail expands full width right under the selected row (same pattern as alerts and playbooks).
                  const detailRow = selectedId === id ? (
                    <tr className="border-t border-zinc-800 bg-zinc-950/40"><td colSpan={COLUMNS[tab]} className="max-w-0 p-3"><DetailCell onClose={() => set({ id: null })} id={id}><div className={tab === "ec2" ? "" : "lg:columns-2 lg:gap-8"}>
                      {!detail ? <div className="text-sm text-zinc-500">{rows ? "Not in the snapshot." : "Loading…"}</div>
                        : tab === "ec2" ? <Ec2Detail d={detail} probe={probe} onProbe={(kind?: string) => runProbe(detail.instance_id, kind)} />
                        : tab === "rds" ? <RdsDetail d={detail} />
                        : tab === "lambda" ? <LambdaDetail d={detail} />
                        : tab === "dynamodb" ? <DynamoDetail d={detail} />
                        : tab === "elb" ? <ElbDetail d={detail} />
                        : tab === "ebs" ? <EbsDetail d={detail} />
                        : tab === "s3" ? <S3Detail d={detail} />
                        : tab === "route53" ? <Route53Detail d={detail} />
                        : <CacheDetail d={detail} />}
                    </div></DetailCell></td></tr>
                  ) : null;
                  if (tab === "ec2") return (<Fragment key={id}>
                    <tr key={id} onClick={() => pick(id)} className={cls}>
                      <Td><div className="flex items-center gap-2"><span className="font-medium text-zinc-100">{r.name || <span className="text-zinc-500">(no name)</span>}</span>{r.pool_kind ? <PoolBadge kind={r.pool_kind} name={r.pool} /> : null}{r.gone ? <Badge>gone</Badge> : null}</div><div className="font-mono text-xs text-zinc-500">{id}{r.private_ip ? ` · ${r.private_ip}` : ""}</div><DomainLine list={r.domains} /></Td>
                      <Td className="whitespace-nowrap">{r.instance_type}</Td>
                      <Td><Badge>{r.state}</Badge></Td>
                      <Td><SsmBadge status={r.ssm_status} platform={r.ssm_platform} /></Td>
                      <Td className="text-right">{r.cpu_days ? <span title={`${r.cpu_days} days of data`}>{pct(r.cpu_30d)}</span> : "—"}</Td>
                      <Td className="text-right">{r.probe_mem_pct != null ? <span title={`probed ${when(r.probe_at)}`}>{pct(r.probe_mem_pct)}</span> : r.state === "running" && r.ssm_status === "Online" ? <button className="text-xs text-sky-300 hover:underline" onClick={(e) => { e.stopPropagation(); set({ id }); runProbe(id); }}>probe</button> : "—"}</Td>
                      <Td className="text-right whitespace-nowrap">{r.ebs_gb ? gb(r.ebs_gb) : "—"}</Td>
                      <Td className="text-right font-medium text-zinc-100">{usd(r.monthly_usd)}</Td>
                      <Td className="whitespace-nowrap text-zinc-400">{day(r.launch_time)}</Td>
                      <Td className="text-right">{r.open_recs || "—"}</Td>
                      <Td className="text-right">{r.findings || "—"}</Td>
                    </tr>{detailRow}
                  </Fragment>);
                  if (tab === "rds") return (<Fragment key={id}>
                    <tr onClick={() => pick(id)} className={cls}>
                      <Td><div className="flex items-center gap-2"><span className="font-medium text-zinc-100">{id}</span>{r.gone ? <Badge>gone</Badge> : null}</div>{r.cluster && <div className="text-xs text-zinc-500">cluster {r.cluster}</div>}</Td>
                      <Td className="whitespace-nowrap">{r.class}{r.multi_az ? <span className="text-xs text-zinc-500"> multi-AZ</span> : null}</Td>
                      <Td>{r.engine} <span className="text-xs text-zinc-500">{r.engine_version}</span></Td>
                      <Td><Badge>{r.status}</Badge></Td>
                      <Td className="text-right whitespace-nowrap">{gb(r.storage_gb)} <span className="text-xs text-zinc-500">{r.storage_type}</span></Td>
                      <Td className="text-right">{r.cpu_days ? pct(r.cpu_30d) : "—"}</Td>
                      <Td className="text-right font-medium text-zinc-100">{usd(r.monthly_usd)}</Td>
                      <Td className="whitespace-nowrap text-zinc-400">{day(r.created)}</Td>
                      <Td className="text-right">{r.open_recs || "—"}</Td>
                      <Td className="text-right">{r.findings || "—"}</Td>
                    </tr>{detailRow}
                  </Fragment>);
                  if (tab === "identities") return (<Fragment key={id}>
                    <tr className={cls}>
                      <Td><div className="flex items-center gap-2"><span className="font-medium text-zinc-100">{r.name}</span>{!r.console_access && !r.keys_active ? <span title="no console password and no active access key" className="rounded bg-zinc-800 px-1.5 py-0.5 text-[11px] text-zinc-400">no way in</span> : null}{r.gone ? <Badge>gone</Badge> : null}</div><div className="font-mono text-[11px] text-zinc-500">{r.arn}</div></Td>
                      <Td className="text-xs">{r.console_access ? <span className="text-zinc-200">yes</span> : <span className="text-zinc-500">no</span>}</Td>
                      <Td className="text-xs">{r.mfa_enabled ? <span className={(r.mfa_types || []).some((t: string) => t === "passkey" || t === "hardware") ? "text-emerald-300" : "text-amber-300"} title="registered MFA devices">{(r.mfa_types || []).map((t: string) => (t === "app" ? "app" : t === "passkey" ? "passkey" : "hardware")).join(", ") || "on"}</span> : r.console_access ? <span className="text-orange-300">off</span> : <span className="text-zinc-500">—</span>}</Td>
                      <Td className="text-xs">{r.admin ? <span className="text-orange-300">admin</span> : <span className="text-zinc-500">—</span>}</Td>
                      <Td className="max-w-xs text-xs text-zinc-400">{[...(r.groups || []).map((g: string) => `group ${g}`), ...(r.attached_policies || []), ...(r.inline_policies || []).map((p: string) => `inline ${p}`)].join(" · ") || "—"}{r.permissions_boundary ? <div className="text-zinc-500">boundary {r.permissions_boundary}</div> : null}</Td>
                      <Td className="text-xs">{r.access_keys?.length ? r.access_keys.map((k: any) => <div key={k.id} className={k.status === "Active" && (k.age_days ?? 0) > 90 ? "text-orange-300" : "text-zinc-300"}><span className="font-mono">{k.id}</span> {k.status}{k.age_days != null ? ` · ${k.age_days} d` : ""}{k.last_used ? ` · used ${day(k.last_used)}${k.service ? ` (${k.service})` : ""}` : " · never used"}</div>) : <span className="text-zinc-500">none</span>}</Td>
                      <Td className="whitespace-nowrap text-xs text-zinc-400">{r.last_used ? day(r.last_used) : <span className="text-zinc-500">never</span>}</Td>
                      <Td className="whitespace-nowrap text-zinc-400">{day(r.created)}</Td>
                    </tr>
                  </Fragment>);
                  if (tab === "ebs") return (<Fragment key={id}>
                    <tr onClick={() => pick(id)} className={cls}>
                      <Td><div className="flex items-center gap-2"><span className="font-mono text-xs text-zinc-100">{id}</span>{r.gone ? <Badge>gone</Badge> : null}</div>{r.name && <div className="text-xs text-zinc-500">{r.name}</div>}</Td>
                      <Td>{r.volume_type}{r.encrypted ? " 🔒" : ""}</Td>
                      <Td className="text-right">{r.size_gb} GB</Td>
                      <Td className="text-right"><UsedBar used_pct={r.used_pct} used_bytes={r.used_bytes} total_bytes={r.total_bytes} usage_at={r.usage_at} empty={r.instance_id ? "no probe of the instance yet" : "unattached: nothing can read it"} /></Td>
                      <Td className="text-right">{r.provisioned_iops != null ? Number(r.provisioned_iops).toLocaleString() : "—"}</Td>
                      <Td className={`text-right ${r.iops_max != null && r.provisioned_iops && r.iops_max < 0.3 * r.provisioned_iops && r.iops > 3000 ? "text-amber-300" : ""}`}>{r.iops_max != null ? Number(r.iops_max).toLocaleString() : <span className="text-zinc-600">—</span>}</Td>
                      <Td><div className="flex items-center gap-1.5"><Badge>{r.state}</Badge>{r.instance_id && r.instance_state && r.instance_state !== "running" ? <span className="text-xs text-amber-300" title="attached, so AWS says in-use, but the instance is not running: the volume is billed all the same">instance {r.instance_state}</span> : null}</div></Td>
                      <Td className="text-xs">{r.instance_id ? <Link className="hover:underline" to={`/inventory?tab=ec2&id=${r.instance_id}`}>{r.instance_name || r.instance_id}<span className="text-zinc-500"> {r.device}</span></Link> : <span className="text-amber-300">unattached</span>}</Td>
                      <Td className="text-right font-medium text-zinc-100">{usd(r.monthly_usd, 2)}</Td>
                      <Td className="whitespace-nowrap text-zinc-400">{day(r.created)}</Td>
                    </tr>{detailRow}
                  </Fragment>);
                  if (tab === "s3") return (<Fragment key={id}>
                    <tr onClick={() => pick(id)} className={cls}>
                      <Td><div className="flex items-center gap-2"><span className="font-medium text-zinc-100">{id}</span>{r.public ? <Badge>public</Badge> : null}{r.versioning ? <Badge>versioned</Badge> : null}{r.gone ? <Badge>gone</Badge> : null}</div></Td>
                      <Td className="text-zinc-400">{r.region}</Td>
                      <Td className="text-right">{r.total_gb >= 1 ? `${Number(r.total_gb).toLocaleString(undefined, { maximumFractionDigits: 1 })} GB` : r.total_gb > 0 ? `${Math.round(r.total_gb * 1000)} MB` : <span className="text-zinc-600">empty</span>}</Td>
                      <Td className="text-right">{r.standard_gb >= 1 ? `${Number(r.standard_gb).toLocaleString(undefined, { maximumFractionDigits: 1 })} GB` : "—"}</Td>
                      <Td className="text-right">{r.objects != null ? Number(r.objects).toLocaleString() : "—"}</Td>
                      <Td className={`text-right ${!r.lifecycle_rules && r.total_gb > 5 ? "text-amber-300" : ""}`}>{r.lifecycle_rules ? `${r.lifecycle_rules} rule${r.lifecycle_rules === 1 ? "" : "s"}` : "none"}</Td>
                      <Td className="text-right font-medium text-zinc-100">{r.monthly_usd ? usd(r.monthly_usd, 2) : <span className="text-zinc-600">$0.00</span>}</Td>
                      <Td className="whitespace-nowrap text-zinc-400">{day(r.created)}</Td>
                    </tr>{detailRow}
                  </Fragment>);
                  if (tab === "route53") {
                    const first = (r.links || []).find((l: any) => l.hop === 1) || r.links?.[0];
                    return (<Fragment key={id}>
                      <tr onClick={() => pick(id)} className={cls}>
                        <Td><div className="flex items-center gap-2"><span className="font-mono text-xs text-zinc-100">{r.name}</span>{r.gone ? <Badge>gone</Badge> : null}{r.routing?.set_identifier ? <span className="text-xs text-zinc-500">{r.routing.set_identifier}</span> : null}</div></Td>
                        <Td className="whitespace-nowrap text-xs">{r.type}{r.alias ? <span className="text-zinc-500"> alias</span> : null}</Td>
                        <Td className="max-w-xs"><div className="truncate font-mono text-xs text-zinc-400" title={r.alias ? r.alias_target : (r.values || []).join("\n")}>{r.alias ? r.alias_target : (r.values || []).slice(0, 2).join(", ")}{!r.alias && (r.values || []).length > 2 ? ` +${r.values.length - 2}` : ""}</div></Td>
                        <Td className="max-w-md"><div className="flex items-center gap-2"><Badge>{r.link_state}</Badge><span className={`min-w-0 truncate text-xs ${r.link_state === "unmatched" ? "text-red-300" : r.link_state === "linked" ? "text-zinc-200" : "text-zinc-500"}`} title={r.summary}>{first && LINK_TAB[first.kind] ? <Link className="hover:underline" onClick={(e) => e.stopPropagation()} to={`/inventory?tab=${LINK_TAB[first.kind]}&id=${encodeURIComponent(first.id)}`}>{r.summary}</Link> : r.summary}</span></div></Td>
                        <Td className="whitespace-nowrap text-xs text-zinc-400">{r.zone_name}</Td>
                        <Td className="text-right text-xs text-zinc-400">{r.alias ? "—" : r.ttl}</Td>
                      </tr>{detailRow}
                    </Fragment>);
                  }
                  if (tab === "elb") return (<Fragment key={id}>
                    <tr onClick={() => pick(id)} className={cls}>
                      <Td><div className="flex items-center gap-2"><span className="font-medium text-zinc-100">{r.name}</span>{r.scheme === "internet-facing" ? <Badge>public</Badge> : r.scheme ? <Badge>internal</Badge> : null}{r.gone ? <Badge>gone</Badge> : null}</div><div className="truncate font-mono text-xs text-zinc-500" title={r.dns_name}>{r.dns_name || r.region}</div></Td>
                      <Td className="whitespace-nowrap uppercase text-zinc-400">{r.kind === "clb" ? "classic" : r.kind}</Td>
                      <Td><Badge>{r.state || "?"}</Badge></Td>
                      <Td className="max-w-sm"><ElbFronts r={r} /></Td>
                      <Td className={`text-right ${r.targets && !r.healthy ? "text-red-300" : r.unhealthy ? "text-amber-300" : ""}`}>{r.targets ? `${r.healthy} / ${r.targets}` : <span className="text-zinc-600">none</span>}</Td>
                      <Td className="text-right">{r.requests_30d != null ? Number(r.requests_30d).toLocaleString(undefined, { maximumFractionDigits: 0 }) : r.flows_30d != null ? <span title="peak active flows (NLB)">{Number(r.flows_30d).toLocaleString()} flows</span> : <span className="text-zinc-600">—</span>}</Td>
                      <Td className="text-right text-zinc-400">{r.gb_30d != null ? Number(r.gb_30d).toLocaleString(undefined, { maximumFractionDigits: 1 }) : "—"}</Td>
                      <Td className="text-right font-medium text-zinc-100">{usd(r.monthly_usd, 2)}</Td>
                      <Td className="whitespace-nowrap text-zinc-400">{day(r.created)}</Td>
                    </tr>{detailRow}
                  </Fragment>);
                  if (tab === "dynamodb") return (<Fragment key={id}>
                    <tr onClick={() => pick(id)} className={cls}>
                      <Td><div className="flex items-center gap-2"><span className="font-medium text-zinc-100">{id}</span>{r.gone ? <Badge>gone</Badge> : null}{r.status && r.status !== "ACTIVE" ? <Badge>{r.status}</Badge> : null}</div><div className="font-mono text-xs text-zinc-500">{r.region}{r.table_class && r.table_class !== "STANDARD" ? ` · ${r.table_class}` : ""}</div></Td>
                      <Td className="whitespace-nowrap text-zinc-400">{r.billing_mode === "PAY_PER_REQUEST" ? "on demand" : "provisioned"}</Td>
                      <Td className="text-right text-zinc-400">{r.billing_mode === "PAY_PER_REQUEST" ? "—" : `${r.read_capacity + (r.gsi_read_capacity || 0)} / ${r.write_capacity + (r.gsi_write_capacity || 0)}`}</Td>
                      <Td className="text-right">{r.size_bytes >= 1e9 ? `${(r.size_bytes / 1e9).toFixed(1)} GB` : `${Math.round(r.size_bytes / 1e6)} MB`}</Td>
                      <Td className="text-right text-zinc-400">{Number(r.item_count || 0).toLocaleString()}</Td>
                      <Td className="text-right">{r.read_units_30d ? Number(Math.round(r.read_units_30d)).toLocaleString() : <span className="text-zinc-600">0</span>}</Td>
                      <Td className="text-right">{r.write_units_30d ? Number(Math.round(r.write_units_30d)).toLocaleString() : <span className="text-zinc-600">0</span>}</Td>
                      <Td className="text-right font-medium text-zinc-100">{r.monthly_usd ? usd(r.monthly_usd, 2) : <span className="text-zinc-600">$0.00</span>}</Td>
                      <Td className="text-right">{r.open_recs || "—"}</Td>
                    </tr>{detailRow}
                  </Fragment>);
                  if (tab === "lambda") return (<Fragment key={id}>
                    <tr onClick={() => pick(id)} className={cls}>
                      <Td><div className="flex items-center gap-2"><span className="font-medium text-zinc-100">{id}</span>{r.arm ? <Badge>arm64</Badge> : null}{r.gone ? <Badge>gone</Badge> : null}</div><div className="font-mono text-xs text-zinc-500">{r.region}</div></Td>
                      <Td className="whitespace-nowrap text-zinc-400">{r.runtime || "—"}</Td>
                      <Td className="text-right">{r.memory_mb} MB</Td>
                      <Td className="text-right">{r.invocations_month ? Number(r.invocations_month).toLocaleString() : <span className="text-zinc-600">0</span>}</Td>
                      <Td className="text-right text-zinc-400">{r.avg_duration_ms != null ? Number(r.avg_duration_ms).toLocaleString() : "—"}</Td>
                      <Td className="text-right">{r.gb_seconds_month ? Number(r.gb_seconds_month).toLocaleString() : "—"}</Td>
                      <Td className={`text-right ${r.errors_30d ? "text-amber-300" : "text-zinc-500"}`}>{r.errors_30d ? Number(r.errors_30d).toLocaleString() : "0"}</Td>
                      <Td className="text-right font-medium text-zinc-100">{r.monthly_usd ? usd(r.monthly_usd, 2) : <span className="text-zinc-600">$0.00</span>}</Td>
                      <Td className="text-right">{r.open_recs || "—"}</Td>
                      <Td className="text-right">{r.findings || "—"}</Td>
                    </tr>{detailRow}
                  </Fragment>);
                  return (<Fragment key={id}>
                    <tr onClick={() => pick(id)} className={cls}>
                      <Td><div className="flex items-center gap-2"><span className="font-medium text-zinc-100">{id}</span>{r.gone ? <Badge>gone</Badge> : null}</div>{r.replication_group && <div className="text-xs text-zinc-500">group {r.replication_group}</div>}</Td>
                      <Td className="whitespace-nowrap">{r.node_type}</Td>
                      <Td>{r.engine} <span className="text-xs text-zinc-500">{r.engine_version}</span></Td>
                      <Td className="text-right">{r.num_nodes}</Td>
                      <Td><Badge>{r.status}</Badge></Td>
                      <Td className="text-right font-medium text-zinc-100">{usd(r.monthly_usd)}</Td>
                      <Td className="whitespace-nowrap text-zinc-400">{day(r.created)}</Td>
                      <Td className="text-right">{r.open_recs || "—"}</Td>
                      <Td className="text-right">{r.findings || "—"}</Td>
                    </tr>{detailRow}
                  </Fragment>);
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>}
    </div>
  );
}

/** The count next to a tab's label: the summary's total for the kind; the identities tab counts IAM users (the summary keeps them under iam). */
const tabCount = (s: any, t: Tab): number | null => { const v = t === "identities" ? s?.iam?.users : SERVICE_TABS.includes(t) ? s?.services?.[t]?.total : s?.[t]?.total; return typeof v === "number" ? v : null; };

const COLUMNS: Record<Tab, number> = { ec2: 11, rds: 10, elasticache: 9, lambda: 10, dynamodb: 9, elb: 9, ebs: 10, s3: 8, route53: 6, deployments: 6, clusters: 8, identities: 8, sg: 5, tags: 5,
  certificates: 8, messaging: 9, keys: 8, files: 9, backups: 8, analytics: 8, stacks: 8, threats: 7 };

/** What a balancer fronts, in one line: the instances (linked), Lambda targets, the Beanstalk environment, ASGs and ECS services. */
function ElbFronts({ r }: { r: any }) {
  const targets = (r.target_groups || []).flatMap((g: any) => g.targets || []);
  const instances = new Map<string, any>(); for (const t of targets) if (t.instance_id && !instances.has(t.instance_id)) instances.set(t.instance_id, t);
  const lambdas: string[] = [...new Set<string>(targets.filter((t: any) => t.lambda).map((t: any) => String(t.lambda)))];
  const others = targets.filter((t: any) => !t.instance_id && !t.lambda).length;
  const parts: ReactNode[] = [];
  for (const [id, t] of [...instances].slice(0, 4)) parts.push(<Link key={id} className={`hover:underline ${t.health === "unhealthy" ? "text-red-300" : ""}`} to={`/inventory?tab=ec2&id=${encodeURIComponent(id)}`} title={`${id}${t.health ? ` · ${t.health}` : ""}`}>{t.name || id}</Link>);
  if (instances.size > 4) parts.push(<span key="more-i" className="text-zinc-500">+{instances.size - 4} more</span>);
  for (const l of lambdas.slice(0, 2)) parts.push(<Link key={`l-${l}`} className="hover:underline" to={`/inventory?tab=lambda&id=${encodeURIComponent(l)}`}>λ {l}</Link>);
  if (others) parts.push(<span key="others" className="text-zinc-500">{others} other target{others === 1 ? "" : "s"}</span>);
  if (r.beanstalk_env) parts.push(<span key="eb" className="text-xs text-emerald-300" title="Elastic Beanstalk environment">EB {r.beanstalk_env}</span>);
  for (const a of r.asgs || []) parts.push(<span key={`a-${a}`} className="text-xs text-sky-300" title="autoscaling group">ASG {a}</span>);
  for (const s of r.ecs_services || []) parts.push(<span key={`s-${s}`} className="text-xs text-violet-300" title="ECS service">ECS {s}</span>);
  if (!parts.length) return <span className="text-zinc-600">nothing registered</span>;
  return <div className="flex flex-wrap gap-x-2 gap-y-0.5 text-sm">{parts}</div>;
}

function ElbDetail({ d }: { d: any }) {
  const kindLabel = d.kind === "clb" ? "classic load balancer" : d.kind === "gwlb" ? "gateway load balancer" : String(d.kind).toUpperCase();
  return (
    <>
      <h2 className="text-base font-medium text-zinc-100">{d.name}</h2>
      <div className="mt-1 flex flex-wrap items-center gap-2 text-xs"><Badge>{kindLabel}</Badge>{d.scheme && <Badge>{d.scheme}</Badge>}<Badge>{d.state || "?"}</Badge>{d.gone ? <Badge>gone</Badge> : null}<Mono>{d.arn}</Mono></div>
      <div className="mt-1 text-xs text-zinc-500">first seen {when(d.first_seen)} · last seen {when(d.last_seen)}</div>
      <Group title="Network">
        <Dl rows={[["DNS name", d.dns_name && <Mono>{d.dns_name}</Mono>], ["Region", d.region], ["VPC", d.vpc_id && <Mono>{d.vpc_id}</Mono>], ["Availability zones", d.azs || null], ["Security groups", d.security_groups?.length ? d.security_groups.join(", ") : null], ["Created", day(d.created)]]} />
      </Group>
      <Group title={`Listeners · ${(d.listeners || []).length}`}>
        {(d.listeners || []).length ? <ul className="space-y-0.5 text-sm">{d.listeners.map((l: any, i: number) => <li key={i}><Mono>{l.protocol}:{l.port}</Mono>{l.certificates ? <span className="ml-2 text-xs text-zinc-500">{l.certificates} certificate{l.certificates === 1 ? "" : "s"}</span> : null}{l.default_action && <span className="ml-2 text-zinc-400">{l.default_action}</span>}</li>)}</ul> : <div className="text-sm text-zinc-500">No listener: nothing can reach the targets through this balancer.</div>}
      </Group>
      <Group title={`Target groups · ${(d.target_groups || []).length}`}>
        {(d.target_groups || []).length ? d.target_groups.map((g: any) => (
          <div key={g.arn} className="mb-2 text-sm">
            <div className="flex flex-wrap items-center gap-2"><span className="font-medium text-zinc-200">{g.name}</span><span className="text-xs text-zinc-500">{[g.target_type, g.protocol && g.port != null ? `${g.protocol}:${g.port}` : null, g.health_check && `health check ${g.health_check}`].filter(Boolean).join(" · ")}</span>{(g.asgs || []).map((a: string) => <span key={a} className="text-xs text-sky-300">ASG {a}</span>)}{(g.ecs_services || []).map((s: string) => <span key={s} className="text-xs text-violet-300">ECS {s}</span>)}</div>
            {g.targets?.length ? <ul className="mt-0.5 space-y-0.5 pl-3">{g.targets.map((t: any, i: number) => <li key={`${t.id}-${i}`} className="flex flex-wrap items-center gap-2">
              {t.instance_id ? <Link className="hover:underline" to={`/inventory?tab=ec2&id=${encodeURIComponent(t.instance_id)}`}>{t.name || t.instance_id}</Link> : t.lambda ? <Link className="hover:underline" to={`/inventory?tab=lambda&id=${encodeURIComponent(t.lambda)}`}>λ {t.lambda}</Link> : <span>{t.name || t.id}</span>}
              {t.instance_id && t.instance_id !== t.id ? <Mono>{t.id}</Mono> : t.instance_id ? <Mono>{t.instance_id}</Mono> : null}{t.port != null && <span className="text-xs text-zinc-500">:{t.port}</span>}
              {t.health && <span className={`text-xs ${t.health === "healthy" ? "text-emerald-300" : t.health === "unhealthy" ? "text-red-300" : "text-zinc-500"}`} title={t.reason || undefined}>{t.health}</span>}
            </li>)}</ul> : <div className="pl-3 text-xs text-zinc-500">no registered target</div>}
          </div>
        )) : <div className="text-sm text-zinc-500">No target group: the balancer fronts nothing.</div>}
      </Group>
      {(d.beanstalk_env || d.asgs?.length || d.ecs_services?.length) ? <Group title="Owned by">
        <Dl rows={[["Elastic Beanstalk", d.beanstalk_env && <span>environment <span className="font-medium">{d.beanstalk_env}</span> (Beanstalk owns this balancer; change it through the environment's configuration)</span>], ["Autoscaling groups", d.asgs?.length ? d.asgs.join(", ") : null], ["ECS services", d.ecs_services?.length ? d.ecs_services.join(", ") : null]]} />
        {d.beanstalk_env && <AutoScaleSwitch env={d.beanstalk_env} region={d.region} accountId={d.account_id} />}
      </Group> : null}
      {(d.asgs || []).map((a: string) => <Group key={a} title={`Usage of group ${a}`}><UsageProfile subject={a} running={!d.gone} /></Group>)}
      <Group title="Traffic, last 30 days">
        <Dl rows={[
          ["Requests", d.requests_30d != null ? `${Number(d.requests_30d).toLocaleString(undefined, { maximumFractionDigits: 0 })} over ${d.metric_days} day${d.metric_days === 1 ? "" : "s"} with data` : d.kind === "alb" || d.kind === "clb" ? "no RequestCount datapoint: nothing came through, or the metric is missing" : null],
          ["Peak active flows", d.flows_30d != null ? Number(d.flows_30d).toLocaleString() : null],
          ["Processed", d.gb_30d != null ? `${Number(d.gb_30d).toLocaleString(undefined, { maximumFractionDigits: 2 })} GB` : null],
        ]} />
      </Group>
      <Group title="Price">
        <Dl rows={[["Fixed, at list", `${usd(d.monthly_usd, 2)} / month (hourly × 730)`], ["On top", d.kind === "clb" ? "0.008 USD per GB processed" : d.kind === "gwlb" ? "GLCU-hours" : `${d.kind === "alb" ? "LCU" : "NLCU"}-hours at ${d.kind === "alb" ? "0.008" : "0.006"} USD, from new connections, active connections, bytes and rule evaluations`]]} />
      </Group>
      <Domains list={d.domains} empty="No Route 53 record in this account points at this balancer." />
      <Group title="Tags"><Tags tags={d.tags} /></Group>
      <Timeline kind="elb" id={d.name} />
    </>
  );
}

/**
 * Tag hygiene (src/tag_hygiene.ts): which resources lack the required tags (owner and env by default), the value the
 * advisor would suggest from the name and the tags there, the CLI to set them, and the EC2 instances that could
 * opt into parking or office hours but carry no tag. The advisor never writes a tag: the person copies the command.
 */
function TagsPanel() {
  const [report, setReport] = useState<any>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const [kind, setKind] = useState("");
  const load = () => api("/tags/hygiene").then(setReport).catch((e) => setErr(e.message));
  useEffect(() => { load(); }, []);
  const refresh = async () => {
    setBusy(true); setErr("");
    try { const r = await api("/tags/hygiene/refresh", { method: "POST" }); setReport(r.report); if (r.errors?.length) setErr(`Some tables could not be read: ${r.errors.join("; ")}`); }
    catch (e: any) { setErr(e.message); }
    finally { setBusy(false); }
  };
  if (!report) return <Empty>{err || "Loading…"}</Empty>;
  const rows: any[] = kind ? report.rows.filter((r: any) => r.kind === kind) : report.rows;
  const parks = report.opt_in.filter((o: any) => o.opt === "park"), schedules = report.opt_in.filter((o: any) => o.opt === "schedule");
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="text-sm text-zinc-500">Required tags: {report.required.map((k: string) => <Code key={k} className="mr-1">{k}</Code>)} (aliases such as Environment or team count) · {report.checked_at ? `checked ${when(report.checked_at)}` : "never checked: press Refresh"}</div>
        <Button variant="ghost" onClick={refresh} disabled={busy}>{busy ? "Reading tags…" : "Refresh tags"}</Button>
      </div>
      {err && <div className="text-sm text-red-300">{err}</div>}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Stat label="Missing a required tag" value={report.total_missing} hint={`${report.kinds.length} resource kind${report.kinds.length === 1 ? "" : "s"}`} />
        {report.required.map((k: string) => <Stat key={k} label={`Without ${k}`} value={report.kinds.reduce((n: number, x: any) => n + (x.by_key[k] || 0), 0)} />)}
        <Stat label="Opt-in candidates" value={report.opt_in.length} hint={`${parks.length} for parking · ${schedules.length} for office hours`} />
      </div>
      {report.opt_in.length > 0 && (
        <Card title="Could opt into the executor, once tagged">
          <div className="text-xs text-zinc-500">Swarm-named instances without <Code>advisor:park</Code> are parking candidates (stopped after 7 idle days, never terminated); running dev, staging and test boxes without <Code>advisor:schedule</Code> could keep office hours. The tag is the consent: nothing happens until someone adds it.</div>
          <div className="mt-2 overflow-x-auto"><table className="w-full border-collapse rounded-lg border border-zinc-800"><thead className="bg-zinc-900"><tr><Th>Instance</Th><Th>State</Th><Th>Opt-in</Th><Th>Tag to add</Th><Th></Th></tr></thead><tbody>
            {report.opt_in.map((o: any) => <tr key={o.resource} className="border-t border-zinc-800"><Td><span className="font-medium text-zinc-100">{o.name || o.resource}</span> <span className="text-xs text-zinc-500">{o.resource}</span></Td><Td><Badge>{o.state || "?"}</Badge></Td><Td>{o.opt === "park" ? "parking" : "office hours"}</Td><Td><Code>{o.tag}</Code></Td><Td><CopyButton text={o.cli} label="Copy CLI" /></Td></tr>)}
          </tbody></table></div>
        </Card>
      )}
      <div className="flex flex-wrap items-center gap-2">
        <select value={kind} onChange={(e) => setKind(e.target.value)}><option value="">All kinds</option>{report.kinds.map((k: any) => <option key={k.kind} value={k.kind}>{k.label} · {k.missing}</option>)}</select>
        <span className="text-sm text-zinc-500">{rows.length} of {report.total_missing} shown{report.total_missing > report.rows.length ? ` (first ${report.rows.length})` : ""}</span>
      </div>
      {rows.length === 0 ? <Empty>{report.checked_at ? "Every resource carries the required tags." : "No report yet."}</Empty> : (
        <div className="min-w-0 overflow-x-auto"><table className="w-full border-collapse overflow-hidden rounded-lg border border-zinc-800">
          <thead className="bg-zinc-900"><tr><Th>Resource</Th><Th>Kind</Th><Th>Missing</Th><Th>Suggested</Th><Th>Tag it</Th></tr></thead>
          <tbody>{rows.map((r: any) => (
            <tr key={r.resource} className="border-t border-zinc-800">
              <Td><span className="font-medium text-zinc-100">{r.name || r.id}</span>{r.name && r.name !== r.id && <span className="ml-1 text-xs text-zinc-500">{r.id}</span>}{r.region && <span className="ml-1 text-xs text-zinc-500">{r.region}</span>}</Td>
              <Td className="whitespace-nowrap text-zinc-400">{r.kind}</Td>
              <Td>{r.missing.map((m: string) => <Badge key={m}>{m}</Badge>)}</Td>
              <Td className="text-xs">{Object.keys(r.suggested).length ? Object.entries(r.suggested).map(([k, v]) => <div key={k}><span className="text-zinc-500">{k}=</span>{String(v)}</div>) : <span className="text-zinc-500">nothing in the name or tags</span>}</Td>
              <Td><CopyButton text={r.cli} label="Copy CLI" /></Td>
            </tr>
          ))}</tbody>
        </table></div>
      )}
    </div>
  );
}

/** The expanded detail under a row: scrolls into view when it opens, lays its groups out in two columns on wide screens. */
/** The instance's baselines: median and p95 per metric, from 14 days of CloudWatch CPU and the probe history. */
function TypicalLine({ instanceId }: { instanceId: string }) {
  const [b, setB] = useState<any[] | null>(null);
  useEffect(() => { setB(null); api(`/baselines?scope_kind=instance&scope_id=${instanceId}`).then((d) => setB(d.baselines)).catch(() => setB([])); }, [instanceId]);
  if (!b || !b.length) return null;
  const order = ["cpu_pct", "mem_pct", "disk_pct", "load_per_cpu", "containers"];
  const rows = b.filter((x) => order.includes(x.metric)).sort((x, y) => order.indexOf(x.metric) - order.indexOf(y.metric));
  const u = (x: any, v: number) => `${Math.round(v)}${x.unit === "%" ? "%" : ""}`;
  return (
    <div className="grid grid-cols-[1fr_auto_auto_auto] gap-x-4 gap-y-0.5 text-xs">
      <div className="text-zinc-500">Typical</div><div className="text-right text-zinc-500">median</div><div className="text-right text-zinc-500">p95</div><div className="text-right text-zinc-500">days</div>
      {rows.map((x) => <Fragment key={x.metric}><div className="text-zinc-400">{metricLabel(x.metric)}{x.by_hour.some((h: number | null) => h != null) ? <span className="text-zinc-600"> · hourly profile</span> : null}</div><div className="text-right text-zinc-200">{u(x, x.median)}</div><div className="text-right text-zinc-300">{u(x, x.p95)}</div><div className="text-right text-zinc-500">{x.days}</div></Fragment>)}
    </div>
  );
}

/** Cypher that pulls one resource with everything linked to it, for Neo4j Browser or the agent's graph_query tool. */
const resourceCypher = (id: string) => `MATCH (r:AdvisorResource {id: '${id}'})\nOPTIONAL MATCH (r)-[e]-(x)\nOPTIONAL MATCH (x)-[d:DECIDED_AS]->(c:Concept)\nRETURN r, e, x, d, c`;

/** What the Neo4j mirror holds for one resource: counts of what is linked, or why there is nothing. */
function GraphLine({ id }: { id: string }) {
  const [g, setG] = useState<{ state: "loading" | "off" | "missing" | "error" | "ok"; view?: any; error?: string }>({ state: "loading" });
  useEffect(() => {
    let live = true;
    setG({ state: "loading" });
    api(`/graph/resource/${encodeURIComponent(id)}`)
      .then((view) => live && setG({ state: "ok", view }))
      .catch((e) => { if (!live) return; const m = String(e.message || ""); setG({ state: /not configured/i.test(m) ? "off" : /not in the graph/i.test(m) ? "missing" : "error", error: m }); });
    return () => { live = false; };
  }, [id]);
  const c = g.view?.counts;
  return (
    <Group title="Graph" action={g.state !== "off" ? <span className="normal-case tracking-normal"><CopyButton text={resourceCypher(id)} label="Copy Cypher" /></span> : null}>
      <div className="text-sm text-zinc-400">
        {g.state === "loading" ? "…"
          : g.state === "off" ? "The Neo4j mirror is not configured (NEO4J_URI)."
          : g.state === "missing" ? "Not in the graph yet: resync from Knowledge, or wait for the next run."
          : g.state === "error" ? <span className="text-red-300">{g.error}</span>
          : <>{c.recommendations} recommendation{c.recommendations === 1 ? "" : "s"} · {c.alerts} alert{c.alerts === 1 ? "" : "s"} · {c.incidents} incident{c.incidents === 1 ? "" : "s"} · {c.controls} control{c.controls === 1 ? "" : "s"} flagged · {c.log_groups} log group{c.log_groups === 1 ? "" : "s"}{g.view.role ? ` · role ${g.view.role}` : ""}{g.view.pool ? ` · pool ${g.view.pool}`: ""}{g.view.recommendations.filter((r: any) => r.concept).length ? ` · ${g.view.recommendations.filter((r: any) => r.concept).length} decided as a Concept` : ""}</>}
      </div>
      {g.state === "ok" && g.view.log_groups?.length > 0 && (
        <div className="mt-1 text-xs text-zinc-400">
          <div className="text-zinc-500">Log groups it writes <span className="text-zinc-600">(observed on the box, or attributed to its system by name, tag or Jev)</span></div>
          <ul className="mt-0.5 space-y-0.5">
            {g.view.log_groups.slice(0, 10).map((l: any) => (
              <li key={l.name} className="flex flex-wrap gap-x-2">
                <span className="font-mono text-zinc-300">{l.name}</span>
                <span className="text-zinc-500">{l.ingest_gb_day != null ? `${Number(l.ingest_gb_day).toFixed(2)} GB/day, ${usd(l.ingest_usd_month)}/mo` : "not metered"} · retention {l.retention_days ?? "never"}</span>
                <span className={l.how === "observed" ? "text-emerald-300/80" : "text-zinc-600"}>{l.how === "observed" ? `seen in ${l.via}` : `${l.how}${l.source ? ` (system ${l.source})` : ""}`}</span>
              </li>
            ))}
          </ul>
          {g.view.log_groups.length > 10 && <div className="text-zinc-600">and {g.view.log_groups.length - 10} more</div>}
        </div>
      )}
      {g.state === "ok" && !g.view.log_groups?.length && <div className="mt-1 text-xs text-zinc-600">No log group attributed to this box or its system yet: the knowledge layer refreshes after each run, and a probe with the 1.6 document adds what the box's own log agents ship.</div>}
    </Group>
  );
}

/** A compact tile for the glance strip at the top of the EC2 detail. */
const Glance = ({ label, value, hint, tone }: { label: string; value: ReactNode; hint?: ReactNode; tone?: string }) => (
  <div className="min-w-[7rem] rounded-md border border-zinc-800 bg-zinc-900/50 px-2.5 py-1.5">
    <div className="text-[10px] uppercase tracking-wide text-zinc-500">{label}</div>
    <div className={`text-sm font-medium ${tone || "text-zinc-100"}`}>{value}</div>
    {hint && <div className="text-[11px] text-zinc-500">{hint}</div>}
  </div>
);

type Ec2Tab = "overview" | "usage" | "ports" | "ondemand" | "running" | "software" | "logs" | "links";
const EC2_TABS: [Ec2Tab, string][] = [["overview", "Overview"], ["usage", "Usage"], ["ports", "Ports"], ["ondemand", "On-demand"], ["running", "What runs"], ["software", "Software"], ["logs", "Logs"], ["links", "Links & history"]];

/**
 * The EC2 detail in four tabs, every fact once: a header with what identifies the box and the two switches, a glance
 * strip with the numbers people look for first (price, CPU, memory, disk, last real use, quiet hours), then
 * Overview (identity, network, storage, SSM, role, tags), Usage (the hour-of-week profile, the charts, the probes),
 * What runs (apps, activity, containers, the process and disk lines) and Links & history (DNS, balancers,
 * recommendations, findings, the graph, the timeline).
 */
function Ec2Detail({ d, probe, onProbe }: { d: any; probe: { busy: boolean; error: string }; onProbe: (kind?: string) => void }) {
  const [rules, setRules] = useState<any[]>([]);
  const [tab, setTab] = useState<Ec2Tab>("overview");
  const [usage, setUsage] = useState<any>(null);
  // AdvisorAutoPark as the switch last wrote it, until the detail is read again (the stored snapshot carries it from then on)
  const [autoParkTag, setAutoParkTag] = useState<string | null | undefined>(undefined);
  const [liveState, setLiveState] = useState<string | null>(null);
  const loadRules = () => api("/signal-rules").then((r) => setRules(r.rules)).catch(() => setRules([]));
  useEffect(() => { loadRules(); setTab("overview"); setUsage(null); api(`/instances/${encodeURIComponent(d.instance_id)}/usage`).then(setUsage).catch(() => setUsage(null)); }, [d.instance_id]);
  useEffect(() => { setAutoParkTag(undefined); setLiveState(null); }, [d]);
  const s = d.snapshot || {};
  const autoPark = /^(on|true|yes|1)$/i.test(String((autoParkTag === undefined ? s.tags?.AdvisorAutoPark : autoParkTag) ?? ""));
  const id = s.identity || {}; const net = s.network || {}; const st = s.storage || {}; const ssm = s.ssm; const ut = s.utilisation || {}; const price = s.price;
  const latest = d.probes?.[0];
  const canProbe = d.state === "running" && d.ssm_status === "Online" && (!ssm?.platform_type || ssm.platform_type === "Linux");
  const diskMax = latest?.data?.disks?.length ? Math.max(...latest.data.disks.map((x: any) => Number(x.used_pct) || 0)) : null;
  const lastUse = latest?.summary?.last_use_at ?? null;
  const recs = d.open_recs || 0, findings = d.findings_count ?? 0, domains = d.domains?.length || 0, behind = d.load_balancers?.length || 0;
  const probesAt: Record<string, string> = latest?.data?.probes_at || {};
  const probeButton = canProbe ? (
    <span className="inline-flex items-center gap-1">
      <Button variant="ghost" className="!px-2 !py-1 !text-xs normal-case tracking-normal" onClick={() => onProbe()} disabled={probe.busy} title="Run every probe: host, containers, programs and ports, installed software">{probe.busy ? "Probing…" : latest ? "Probe again" : "Probe now"}</Button>
      <select className="rounded border border-zinc-700 bg-zinc-900 px-1 py-1 text-xs text-zinc-300" value="" disabled={probe.busy} onChange={(e) => { if (e.target.value) onProbe(e.target.value); }} title="Run one probe only">
        <option value="">one probe…</option>
        {[["host", "host: memory, load, disks"], ["docker", "containers and activity"], ["apps", "programs, ports, log shipping"], ["software", "installed software"]].map(([k, l]) => <option key={k} value={k}>{l}{probesAt[k] ? ` (last ${when(probesAt[k])})` : " (never)"}</option>)}
      </select>
    </span>) : null;
  return (
    <>
      <div className="flex flex-wrap items-start justify-between gap-x-4 gap-y-1">
        <div>
          <h2 className="text-base font-medium text-zinc-100">{d.name || d.instance_id}</h2>
          <div className="mt-1 flex flex-wrap items-center gap-2 text-xs"><Badge>{liveState ?? d.state}</Badge><SsmBadge status={d.ssm_status} platform={d.ssm_platform} />{s.pool ? <PoolBadge kind={s.pool.kind} name={s.pool.name} /> : null}{d.gone ? <Badge>gone</Badge> : null}<Mono>{d.instance_id}</Mono><span className="text-zinc-500">{id.instance_type} · {id.region}{id.az ? ` / ${id.az}` : ""}{id.launch_time ? ` · launched ${day(id.launch_time)}` : ""}</span></div>
          <div className="mt-1 text-xs text-zinc-500">first seen {when(d.first_seen)} · last seen {when(d.last_seen)}{d.role?.role ? <> · <RoleLine role={d.role} /></> : null}</div>
        </div>
        <div className="flex flex-wrap items-center gap-2"><WatchToggle kind="ec2" id={d.instance_id} /></div>
      </div>
      <AutoParkSwitch instanceId={d.instance_id} name={d.name} state={d.state} tags={s.tags} poolKind={d.pool_kind} onValue={setAutoParkTag} onState={setLiveState} />

      <div className="mt-3 flex flex-wrap gap-2">
        <Glance label="At list" value={price?.monthly != null ? `${usd(price.monthly)} / mo` : "—"} hint={price ? `${usd(price.hourly, 4)} / h · ${price.operating_system}` : `no price for ${d.instance_type}`} />
        <Glance label="CPU, 30 days" value={ut.cpu_days ? pct(ut.cpu_30d_avg_max) : "—"} hint={ut.cpu_days ? `avg daily peak · ${pct(ut.cpu_30d_avg)} avg · ${ut.cpu_days} d` : "no CloudWatch data"} />
        <Glance label="Memory" value={latest ? `${latest.summary.memory_used_pct}%` : "—"} hint={latest ? `${latest.summary.memory_used_gb} of ${latest.summary.memory_total_gb} GB · load ${latest.summary.load_1m} / ${latest.summary.cpus} vCPU` : canProbe ? "not probed yet" : "no probe (SSM offline)"} tone={latest && latest.summary.memory_used_pct >= 90 ? "text-red-300" : undefined} />
        <Glance label="Disk, fullest" value={diskMax != null ? `${Math.round(diskMax)}%` : "—"} hint={latest?.data?.disks?.length ? latest.data.disks.map((x: any) => `${x.mount} ${x.used_pct}%`).slice(0, 3).join(" · ") : "from the probe"} tone={diskMax != null ? usedTone(diskMax) : undefined} />
        <Glance label="Last real use" value={lastUse ? when(lastUse) : latest?.data?.activity ? "none seen" : "—"} hint={latest?.summary?.last_use_kind ? String(latest.summary.last_use_kind).replace(/_/g, " ") : latest ? `probed ${when(latest.collected_at)}` : "needs a probe"} />
        <Glance label="Quiet hours / week" value={usage ? `${usage.quiet_hours_week} of 168` : "—"} hint={usage ? `confidence ${usage.confidence}${usage.suggested_schedule ? ` · ${usage.suggested_schedule}` : ""}` : "no usage profile yet"} tone={usage && usage.quiet_hours_week >= 100 ? "text-emerald-300" : undefined} />
        <Glance label="Storage" value={gb(st.ebs_gb)} hint={`${st.volumes?.length || 0} volume${st.volumes?.length === 1 ? "" : "s"}`} />
      </div>

      <div className="mt-3 flex gap-1 border-b border-zinc-800">
        {EC2_TABS.map(([k, label]) => {
          const n = k === "links" ? recs + findings + domains + behind : k === "running" ? (latest?.data?.docker?.available ? latest.data.docker.running : 0) : 0;
          return <button key={k} onClick={() => setTab(k)} className={`-mb-px border-b-2 px-3 py-1 text-sm ${tab === k ? "border-zinc-100 text-zinc-100" : "border-transparent text-zinc-400 hover:text-zinc-200"}`}>{label}{n ? <span className="ml-1 text-xs text-zinc-500">{n}</span> : null}</button>;
        })}
      </div>

      {tab === "overview" && (
        <div className="lg:columns-2 lg:gap-8">
          <Group title="Identity">
            <Dl rows={[
              ["Type", <>{id.instance_type}{id.cpu_cores ? <span className="text-zinc-500"> · {id.cpu_cores} cores × {id.threads_per_core} threads</span> : null}</>],
              ["State since", id.state_transition_time ? `${when(id.state_transition_time)}${id.state_transition_reason ? ` (${id.state_transition_reason})` : ""}` : null],
              ["Platform", [id.platform_details, id.architecture].filter(Boolean).join(" · ")],
              ["Lifecycle", id.instance_lifecycle],
              ["Pool", s.pool ? <><span className="font-mono text-xs">{s.pool.name}</span><div className="mt-1 text-xs text-zinc-400">{s.pool.note}</div></> : null],
              ["AMI", id.image_id && <Mono>{id.image_id}</Mono>],
              ["Key pair", id.key_name],
              ["Instance profile", id.iam_instance_profile_arn && <Mono>{id.iam_instance_profile_arn}</Mono>],
              ["Monitoring", id.monitoring_state === "enabled" ? "detailed" : id.monitoring_state],
              ["EBS optimized", yesNo(id.ebs_optimized)],
              ["Price fetched", price?.fetched_at ? when(price.fetched_at) : null],
            ]} />
          </Group>
          <Group title="Network">
            <Dl rows={[
              ["Private IP", net.private_ip && <Mono>{net.private_ip}{net.private_dns ? <span className="text-zinc-500"> · {net.private_dns}</span> : null}</Mono>],
              ["Public IP", net.public_ip ? <Mono>{net.public_ip}{net.public_dns ? <span className="text-zinc-500"> · {net.public_dns}</span> : null}</Mono> : <span className="text-zinc-500">none</span>],
              ["VPC / subnet", (net.vpc_id || net.subnet_id) && <Mono>{net.vpc_id} / {net.subnet_id}</Mono>],
              ["Security groups", net.security_groups?.length ? <>{net.security_groups.map((g: any, k: number) => <Fragment key={g.GroupId}>{k ? ", " : ""}<GroupLink id={g.GroupId} name={g.GroupName} /></Fragment>)}</> : null],
              ["DNS and balancers", (domains || behind) ? <button className="text-sky-300 hover:underline" onClick={() => setTab("links")}>{[domains ? `${domains} record${domains === 1 ? "" : "s"}` : null, behind ? `behind ${behind} balancer${behind === 1 ? "" : "s"}` : null].filter(Boolean).join(", ")}</button> : "none reach it"],
            ]} />
          </Group>
          <Group title={`Storage · ${gb(st.ebs_gb)}`}>
            <Dl rows={[["Root device", st.root_device_name && `${st.root_device_name} (${st.root_device_type})`]]} />
            {st.volumes?.length > 0 && (
              <table className="mt-1 w-full text-xs">
                <thead><tr className="text-zinc-500"><th className="text-left font-normal">Volume</th><th className="text-left font-normal">Device</th><th className="text-left font-normal">Type</th><th className="text-right font-normal">GB</th><th className="text-right font-normal">Used</th><th className="text-right font-normal">IOPS</th><th className="text-right font-normal">MiB/s</th></tr></thead>
                <tbody>{st.volumes.map((v: any) => { const u = d.volume_usage?.[v.volume_id]; return <tr key={v.volume_id} className="border-t border-zinc-800/60"><td className="py-0.5 font-mono"><Link className="hover:underline" to={`/inventory?tab=ebs&id=${v.volume_id}`}>{v.volume_id}</Link></td><td>{v.device}</td><td>{v.type}{v.encrypted ? "" : <span className="ml-1 text-amber-300/80" title="not encrypted">⚠</span>}</td><td className="text-right">{v.size}</td><td className="text-right"><UsedBar used_pct={u?.used_pct ?? null} used_bytes={u?.used_bytes} total_bytes={u?.total_bytes} usage_at={u?.usage_at} empty="no probe usage for this volume" /></td><td className="text-right">{v.iops ?? "—"}</td><td className="text-right">{v.throughput ?? "—"}</td></tr>; })}</tbody>
              </table>
            )}
          </Group>
          <Group title="Systems Manager">
            {ssm ? (
              <Dl rows={[
                ["Agent", ssm.agent_version && `${ssm.agent_version}${ssm.agent_latest === false ? " (update available)" : ssm.agent_latest ? " (latest)" : ""} · ${[ssm.platform_name, ssm.platform_version].filter(Boolean).join(" ") || ssm.platform_type}`],
                ["Last ping", when(ssm.last_ping)],
                ["IAM role", ssm.iam_role],
                ["Computer name", ssm.computer_name],
              ]} />
            ) : <div className="text-sm text-zinc-400">Not registered with Systems Manager: no SSM agent, no instance profile with the SSM policy, or outside the connection's regions. It cannot be probed or managed through Run Command.</div>}
          </Group>
          <Group title="Role (Jev)"><div className="text-sm"><RoleLine role={d.role} />{d.role?.updated_at && <span className="ml-2 text-xs text-zinc-500">classified {when(d.role.updated_at)}</span>}</div></Group>
          <Group title="Tags"><Tags tags={s.tags} /></Group>
        </div>
      )}

      {tab === "usage" && (
        <div className="grid grid-cols-1 gap-x-8 lg:grid-cols-[7fr_5fr]">
          <div className="min-w-0">
            <Group title="When it is used">
              <UsageProfile subject={d.instance_id} running={d.state === "running"} />
            </Group>
            {latest?.data?.activity && <Group title="Activity: is anyone using it?"><ActivityBlock activity={latest.data.activity} summary={latest.summary} collectedAt={latest.collected_at} previous={d.probes?.[1] ?? null} instanceId={d.instance_id} rules={rules} onRules={loadRules} /></Group>}
          </div>
          <div className="min-w-0">
            <Group title="Trends"><TypicalLine instanceId={d.instance_id} /><div className="mt-2"><InstanceCharts instanceId={d.instance_id} /></div></Group>
            <Group title={`Probes${d.probes?.length ? ` · ${d.probes.length}` : ""}`} action={probeButton}>
              {probe.error && <div className="mb-1 text-xs text-red-300">{probe.error}</div>}
              {latest ? <ul className="space-y-0.5 text-xs text-zinc-400">{d.probes.slice(0, 24).map((p: any) => <li key={p.id}>{when(p.collected_at)} · memory {p.summary.memory_used_pct}% · load {p.summary.load_1m}{p.summary.top_process ? ` · busiest ${p.summary.top_process}` : ""}{p.summary.last_use_at ? ` · last use ${when(p.summary.last_use_at)}` : ""}</li>)}</ul>
                : <div className="text-sm text-zinc-500">{canProbe ? "Not probed yet: Probe now reads memory, load, disks, processes, containers and activity over SSM." : d.state !== "running" ? "Not running: nothing to probe." : "The SSM agent is not online, so the probe cannot run."}</div>}
            </Group>
          </div>
        </div>
      )}

      {tab === "ports" && <PortsPanel instanceId={d.instance_id} probedAt={latest?.collected_at ?? null} groups={Array.isArray(net.security_groups) ? net.security_groups.filter((g: any) => g?.GroupId) : []} />}

      {tab === "ondemand" && <WakeProfilePanel instanceId={d.instance_id} autoPark={autoPark} />}

      {tab === "running" && (
        <>
          {!latest && <div className="mt-3 text-sm text-zinc-500">{canProbe ? <>No probe yet. {probeButton}</> : "No probe: what runs here is unknown until the SSM agent is online."}</div>}
          {latest && <Group title={`Processes · probed ${when(latest.collected_at)}`} action={probeButton}>
            <Dl rows={[
              ["Top CPU", realProcesses<any>(latest.data?.top_cpu).length ? realProcesses<any>(latest.data.top_cpu).slice(0, 5).map((p: any) => `${p.command} ${p.cpu_pct}%`).join(", ") : null],
              ["Top memory", realProcesses<any>(latest.data?.top_mem).length ? realProcesses<any>(latest.data.top_mem).slice(0, 5).map((p: any) => `${p.command} ${Math.round(p.rss_bytes / 1048576)} MB`).join(", ") : null],
              ["Disks", latest.data?.disks?.length ? latest.data.disks.map((x: any) => `${x.mount} ${x.used_pct}%`).join(", ") : null],
            ]} />
            <AppsBlock instanceId={d.instance_id} probedAt={latest.collected_at} />
          </Group>}
          {latest?.data?.docker?.available && <ContainersPanel instanceId={d.instance_id} latest={latest} rules={rules} onRules={loadRules} />}
          {latest?.data?.docker && !latest.data.docker.available && <div className="mt-2 text-xs text-zinc-600">No Docker daemon on this instance.</div>}
        </>
      )}

      {tab === "software" && <SoftwarePanel instanceId={d.instance_id} canProbe={canProbe} busy={probe.busy} onProbe={() => onProbe("software")} />}

      {tab === "logs" && <LogsBlock instanceId={d.instance_id} />}

      {tab === "links" && (
        <>
          <div className="grid grid-cols-1 gap-x-8 lg:grid-cols-2">
            <div className="min-w-0">
            <Domains list={d.domains} empty={d.public_ip || net.public_dns ? "No Route 53 record in this account points at this instance, its Elastic IP or a load balancer in front of it." : "No Route 53 record in this account reaches this instance (no public address; check the load balancers)."} />
            <Group title="Behind">
              {d.load_balancers?.length ? <ul className="space-y-0.5 text-sm">{d.load_balancers.map((lb: any, i: number) => <li key={`${lb.arn}-${i}`} className="flex flex-wrap items-center gap-2"><Link className="hover:underline" to={`/inventory?tab=elb&id=${encodeURIComponent(lb.name)}`}>{lb.name}</Link><span className="text-xs uppercase text-zinc-500">{lb.kind === "clb" ? "classic" : lb.kind}</span><span className="text-xs text-zinc-500">{lb.target_group}{lb.port != null ? `:${lb.port}` : ""}</span>{lb.health && <span className={`text-xs ${lb.health === "healthy" ? "text-emerald-300" : lb.health === "unhealthy" ? "text-red-300" : "text-zinc-500"}`}>{lb.health}</span>}</li>)}</ul> : <div className="text-sm text-zinc-500">No load balancer in this account has this instance as a target.</div>}
            </Group>
            </div>
            <div className="min-w-0">
            <Related id={d.instance_id} recs={d.open_recs} findings={d.findings_count ?? 0} list={d.recommendations} />
            {d.findings_run_id && d.findings?.length > 0 && (
              <Group title={`Findings in the last run · ${d.findings.length}`}>
                <ul className="space-y-0.5 text-sm">{d.findings.map((f: any) => <li key={f.id} className="flex gap-2"><Badge>{f.status}</Badge><span className="min-w-0 truncate" title={f.reason || ""}>{f.control_title || f.control_id}{f.reason ? `: ${f.reason}` : ""}</span></li>)}</ul>
              </Group>
            )}
            </div>
          </div>
          <GraphLine id={d.instance_id} />
          <Timeline kind="ec2" id={d.instance_id} />
        </>
      )}
    </>
  );
}

function RdsDetail({ d }: { d: any }) {
  const s = d.snapshot || {};
  const id = s.identity || {}; const st = s.storage || {}; const net = s.network || {}; const ut = s.utilisation || {}; const price = s.price;
  return (
    <>
      <h2 className="text-base font-medium text-zinc-100">{d.db_instance_identifier}</h2>
      <div className="mt-1 flex flex-wrap items-center gap-2 text-xs"><Badge>{d.status}</Badge>{d.gone ? <Badge>gone</Badge> : null}<span className="text-zinc-500">{d.engine} {d.engine_version}</span></div>
      <div className="mt-1 text-xs text-zinc-500">first seen {when(d.first_seen)} · last seen {when(d.last_seen)}</div>
      <WatchToggle kind="rds" id={d.db_instance_identifier} />
      <Group title="Identity">
        <Dl rows={[
          ["Class", `${id.class}${id.multi_az ? " · Multi-AZ" : ""}`],
          ["Region / AZ", `${id.region} / ${id.availability_zone}`],
          ["Created", when(id.created)],
          ["Cluster", id.cluster],
          ["Replica of", id.read_replica_source],
          ["Licence", id.license_model],
          ["Deletion protection", yesNo(id.deletion_protection)],
          ["Backup retention", id.backup_retention_days != null ? `${id.backup_retention_days} days` : null],
          ["Performance Insights", yesNo(id.performance_insights)],
          ["ARN", id.arn && <Mono>{id.arn}</Mono>],
        ]} />
      </Group>
      <Group title="Storage">
        <Dl rows={[
          ["Type", st.storage_type],
          ["Allocated", st.allocated_gb != null ? `${gb(st.allocated_gb)}${st.max_allocated_gb ? ` (autoscaling to ${gb(st.max_allocated_gb)})` : ""}` : null],
          ["IOPS / throughput", st.iops || st.throughput ? `${st.iops ?? "—"} / ${st.throughput ?? "—"} MB/s` : null],
          ["Encrypted", yesNo(st.encrypted)],
        ]} />
      </Group>
      <Group title="Network">
        <Dl rows={[["Endpoint", net.endpoint && <Mono>{net.endpoint}:{net.port}</Mono>], ["Publicly accessible", yesNo(net.publicly_accessible)], ["VPC", net.vpc_id && <Mono>{net.vpc_id}</Mono>]]} />
      </Group>
      <Group title="Utilisation, 30 days">
        <Dl rows={[
          ["CPU", ut.cpu_days ? `${pct(ut.cpu_30d_avg_max)} avg daily peak · ${pct(ut.cpu_30d_avg)} avg · ${ut.cpu_days} days of data` : "no CloudWatch data"],
          ["Connections", ut.connections_avg != null ? `${ut.connections_avg} avg · ${ut.connections_max} peak` : null],
          ["I/O", ut.read_iops_avg != null ? `${ut.read_iops_avg} read + ${ut.write_iops_avg} write IOPS avg` : null],
          ["Freeable memory, minimum", ut.freeable_memory_min_gb != null ? `${ut.freeable_memory_min_gb} GB` : null],
        ]} />
      </Group>
      <Group title="Price">
        {price?.monthly != null ? <Dl rows={[["On-demand", `${usd(price.monthly, 2)} / month · ${usd(price.hourly, 4)} / hour (${price.pricing_engine}; instance hours only, storage and I/O not included)`], ["Price fetched", when(price.fetched_at)]]} />
          : <div className="text-sm text-zinc-500">No instance price for {d.class} ({d.engine}){d.class === "db.serverless" ? ": Aurora Serverless bills per ACU-hour" : ""}.</div>}
      </Group>
      <Group title="Role (Jev)">
        <div className="text-sm"><RoleLine role={d.role} />{d.role?.updated_at && <span className="ml-2 text-xs text-zinc-500">classified {when(d.role.updated_at)}</span>}</div>
      </Group>
      <Group title="Tags"><Tags tags={s.tags} /></Group>
      <Domains list={d.domains} empty="No Route 53 record names this endpoint (applications use the RDS endpoint directly)." />
      <Group title={`Load${id.cluster ? ` · cluster ${id.cluster}` : ""}`}><RdsLoadPanel id={id.cluster || d.db_instance_identifier} compact /></Group>
      <Related id={d.db_instance_identifier} recs={d.open_recs} findings={d.findings} />
      <Timeline kind="rds" id={d.db_instance_identifier} />
    </>
  );
}

function EbsDetail({ d }: { d: any }) {
  const used = Math.max(Number(d.iops_max || 0), Number(d.read_iops_avg || 0) + Number(d.write_iops_avg || 0));
  const stopped = Boolean(d.instance_id && d.instance_state && d.instance_state !== "running");
  return (
    <>
      <h2 className="text-base font-medium text-zinc-100">{d.name || d.volume_id}</h2>
      <div className="mt-1 flex flex-wrap items-center gap-2 text-xs"><Badge>{d.state}</Badge>{stopped ? <span className="text-amber-300">instance {d.instance_state}</span> : null}<Badge>{d.volume_type}</Badge>{d.encrypted ? <Badge>encrypted</Badge> : null}<Mono>{d.volume_id}</Mono></div>
      <Group title="Volume">
        <Dl rows={[["Size", `${d.size_gb} GB`], ["Provisioned", d.provisioned_iops != null ? `${Number(d.provisioned_iops).toLocaleString()} IOPS${d.throughput_mibps ? ` · ${d.throughput_mibps} MiB/s` : ""}` : null],
          ["Attached to", d.instance_id ? <span><Link className="underline" to={`/inventory?tab=ec2&id=${d.instance_id}`}>{d.instance_name || d.instance_id} {d.device}</Link>{stopped ? <span className="ml-2 text-amber-300">instance {d.instance_state}: AWS still says in-use, and bills the volume in full</span> : d.instance_state ? <span className="ml-2 text-zinc-500">instance {d.instance_state}</span> : null}</span> : "nothing: unattached volumes cost the same as attached ones"],
          ["Region", d.region], ["Created", when(d.created)]]} />
      </Group>
      <Group title={d.used_pct != null ? `Disk usage · ${pct(d.used_pct)} used` : "Disk usage"}>
        {d.used_pct != null ? (
          <>
            <Dl rows={[["Used / free", <span className={usedTone(Number(d.used_pct))}>{bytes(d.used_bytes)} used · {bytes(Number(d.total_bytes) - Number(d.used_bytes))} free of {bytes(d.total_bytes)}</span>],
              ["Filesystem vs volume", Number(d.total_bytes) < 0.85 * Number(d.size_gb) * 1073741824 ? <span className="text-amber-300">the filesystem covers {bytes(d.total_bytes)} of a {d.size_gb} GB volume: the rest is unpartitioned or not grown into (paid for, unusable until it is)</span> : null],
              ["Probed", `${when(d.usage_at)}${stopped ? " (before the instance stopped)" : ""}`]]} />
            {d.mounts?.length > 0 && (
              <table className="mt-1 w-full text-xs">
                <thead><tr className="text-zinc-500"><th className="text-left font-normal">Mount</th><th className="text-left font-normal">Filesystem</th><th className="text-right font-normal">Used</th><th className="text-right font-normal">Free</th><th className="text-right font-normal">Size</th><th className="text-right font-normal">%</th></tr></thead>
                <tbody>{d.mounts.map((m: any) => <tr key={m.mount} className="border-t border-zinc-800/60"><td className="py-0.5 font-mono">{m.mount}</td><td className="font-mono text-zinc-400">{m.filesystem}</td><td className="text-right">{bytes(m.used_bytes)}</td><td className="text-right">{bytes(m.total_bytes - m.used_bytes)}</td><td className="text-right">{bytes(m.total_bytes)}</td><td className={`text-right ${usedTone(m.used_pct)}`}>{pct(m.used_pct)}</td></tr>)}</tbody>
              </table>
            )}
          </>
        ) : <div className="text-sm text-zinc-500">{!d.instance_id ? "Unattached: no instance can read the filesystem. The volume costs the same full or empty." : stopped ? "No probe of the instance from before it stopped, so used and free are unknown until it runs again and is probed." : "No probe of the instance yet. Probe it from the EC2 tab (Systems Manager, Linux) to see used and free."}</div>}
      </Group>
      <Group title="Usage, 30 days">
        <Dl rows={[["Read / write", d.read_iops_avg != null ? `${d.read_iops_avg} / ${d.write_iops_avg} IOPS average` : "no metrics"], ["Peak", d.iops_max != null ? `${Number(d.iops_max).toLocaleString()} IOPS peak sample (30 d)` : null], ["Provisioned used", d.provisioned_iops ? <span className={used < 0.3 * d.provisioned_iops && d.iops > 3000 ? "text-amber-300" : ""}>{Math.round((100 * used) / d.provisioned_iops)} % of {Number(d.provisioned_iops).toLocaleString()}{used < 0.3 * d.provisioned_iops && d.iops > 3000 ? " (over-provisioned)" : ""}</span> : null]]} />
      </Group>
      <Group title="Price">
        <Dl rows={[["At list", `${usd(d.monthly_usd, 2)} / month`], ["gp3 instead", d.volume_type === "gp2" ? `${usd(d.size_gb * 0.08, 2)} / month for the same size and 3,000 IOPS included` : null]]} />
      </Group>
      <Timeline kind="ebs" id={d.volume_id} />
    </>
  );
}

/** The lifecycle rules already on a bucket: a one-line tally, the table folded away when there are many. */
function LifecycleRules({ rules }: { rules: any[] }) {
  const days = (d: number | null | undefined) => (d != null ? `${d} d` : "—");
  const enabled = rules.filter((r) => r.status === "Enabled").length;
  const tally = [
    `${rules.length} rule${rules.length > 1 ? "s" : ""} on the bucket${enabled < rules.length ? ` (${enabled} enabled)` : ""}`,
    rules.some((r) => r.abort_multipart_days != null) && "aborts incomplete uploads",
    rules.filter((r) => r.transitions.length).length && `${rules.filter((r) => r.transitions.length).length} tier`,
    rules.filter((r) => r.expiration_days != null).length && `${rules.filter((r) => r.expiration_days != null).length} expire`,
  ].filter(Boolean).join(" · ");
  return (
    <details className="text-xs" open={rules.length <= 6}>
      <summary className="cursor-pointer text-zinc-400">{tally}</summary>
      <div className="mt-1 max-h-72 overflow-auto">
        <table className="w-full"><thead className="sticky top-0 bg-zinc-900"><tr className="text-zinc-500"><th className="text-left font-normal">Rule</th><th className="text-left font-normal">Prefix</th><th className="text-left font-normal">Tiers</th><th className="text-right font-normal">Expire</th><th className="text-right font-normal">Noncurrent</th><th className="text-right font-normal">Abort uploads</th></tr></thead>
          <tbody>{rules.map((r, i) => (
            <tr key={`${r.id}-${i}`} className={`border-t border-zinc-800/60 ${r.status === "Enabled" ? "" : "text-zinc-600"}`}>
              <td className="py-0.5 font-mono text-zinc-300">{r.id || "(no id)"}{r.status !== "Enabled" && <span className="ml-1 text-zinc-500">{r.status.toLowerCase()}</span>}</td>
              <td className="font-mono text-zinc-400">{r.prefix || "(all)"}</td>
              <td className="text-zinc-400">{r.transitions.length ? r.transitions.map((t: any) => `${t.storage_class} @ ${t.days ?? "?"} d`).join(", ") : "—"}</td>
              <td className="text-right">{days(r.expiration_days)}</td>
              <td className="text-right">{days(r.noncurrent_expiration_days)}</td>
              <td className="text-right">{days(r.abort_multipart_days)}</td>
            </tr>
          ))}</tbody></table>
      </div>
    </details>
  );
}

/** The usage analysis: bytes by age, what is read, and the lifecycle rules the advisor proposes (src/s3_usage.ts). */
function S3UsageBlock({ name }: { name: string }) {
  const [u, setU] = useState<any>(null);
  const [state, setState] = useState<"loading" | "none" | "ok" | "error">("loading");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const load = () => { setState("loading"); api(`/inventory/s3/${encodeURIComponent(name)}/usage`).then((x) => { setU(x); setState("ok"); }).catch((e) => { setState(/not analysed/.test(e.message) ? "none" : "error"); setErr(e.message); }); };
  useEffect(() => { load(); }, [name]);
  const refresh = async () => { setBusy(true); setErr(""); try { setU(await api(`/inventory/s3/${encodeURIComponent(name)}/usage/refresh`, { method: "POST", body: "{}" })); setState("ok"); } catch (e: any) { setErr(e.message); } finally { setBusy(false); } };
  const gbOf = (b: number) => (b / 1e9).toFixed(2);
  // the rules table already lists what is on the bucket; the note that repeats it is for the recommendation text
  const notes: string[] = (u?.proposal?.notes ?? []).filter((n: string) => !(u?.lifecycle?.length && /lifecycle rule\(s\) already on the bucket/.test(n)));
  return (
    <Group title="Usage and lifecycle" action={<Button variant="ghost" className="!px-2 !py-1 !text-xs normal-case tracking-normal" onClick={refresh} disabled={busy} title="list up to ten thousand keys, the multipart uploads, the versions, the rules and the request metrics">{busy ? "Analysing…" : u ? "Analyse again" : "Analyse"}</Button>}>
      {state === "loading" ? <div className="text-sm text-zinc-500">…</div>
        : state === "none" ? <div className="text-sm text-zinc-500">Not analysed yet. Buckets above the size threshold (Settings › Auto-actions) are analysed after the daily S3 inventory; press Analyse for this one now.</div>
        : state === "error" ? <div className="text-sm text-red-300">{err}</div>
        : (
          <div className="space-y-2 text-sm">
            <div className="flex flex-wrap gap-x-4 gap-y-0.5 text-xs text-zinc-400">
              <span>sampled <span className="text-zinc-200">{u.sample.objects.toLocaleString()}</span> objects{u.sample.truncated ? " (truncated, scaled to the bucket)" : ""} on {when(u.collected_at)}</span>
              <span>multipart left incomplete <span className="text-zinc-200">{u.multipart.uploads}</span></span>
              {u.noncurrent && <span>noncurrent versions <span className="text-zinc-200">{u.noncurrent.versions.toLocaleString()}</span> ({gbOf(u.noncurrent.bytes)} GB)</span>}
              <span>reads {u.requests ? <><span className="text-zinc-200">{u.requests.get_per_day ?? "?"}</span> GET/day over {u.requests.days} days</> : <span title="the executor's S3 request metrics action enables them">unknown: no request metrics</span>}</span>
              {u.small_objects_bytes_share >= 0.5 && <span>{Math.round(u.small_objects_bytes_share * 100)}% of bytes in objects under 128 KB</span>}
            </div>
            <table className="w-full text-xs"><thead><tr className="text-zinc-500"><th className="text-left font-normal">Standard bytes by age</th>{["0-30", "30-90", "90-365", "365+"].map((a) => <th key={a} className="text-right font-normal">{a} days</th>)}</tr></thead>
              <tbody><tr className="border-t border-zinc-800/60"><td className="py-0.5 text-zinc-400">GB</td>{["0-30", "30-90", "90-365", "365+"].map((a) => <td key={a} className="text-right">{gbOf(u.standard_by_age[a].bytes)}</td>)}</tr></tbody></table>
            {u.by_prefix?.length > 1 && (
              <table className="w-full text-xs"><thead><tr className="text-zinc-500"><th className="text-left font-normal">Top prefixes</th><th className="text-right font-normal">GB</th><th className="text-right font-normal">older than 30 days</th></tr></thead>
                <tbody>{u.by_prefix.slice(0, 5).map((p: any) => <tr key={p.prefix} className="border-t border-zinc-800/60"><td className="py-0.5 font-mono text-zinc-300">{p.prefix}</td><td className="text-right">{gbOf(p.bytes)}</td><td className="text-right text-zinc-400">{p.old_bytes ? gbOf(p.old_bytes) : "—"}</td></tr>)}</tbody></table>
            )}
            {u.lifecycle?.length > 0 && <LifecycleRules rules={u.lifecycle} />}
            {u.proposal.rules.length ? (
              <div className="rounded border border-zinc-800 bg-zinc-950/60 p-2">
                <div className="text-zinc-200">Proposed: {u.proposal.rules.length} rule{u.proposal.rules.length > 1 ? "s" : ""}{u.proposal.est_usd_month ? <span className="ml-2 text-emerald-300">≈ {usd(u.proposal.est_usd_month, 2)}/mo</span> : null} <span className="text-zinc-500">· also a recommendation (tier approve)</span></div>
                <ul className="mt-1 space-y-1 text-xs">{u.proposal.rules.map((r: any) => <li key={r.id}><span className="font-mono text-zinc-300">{r.id.replace(/^aws-advisor-/, "")}</span>{r.est_usd_month ? <span className="ml-1 text-emerald-300">≈ {usd(r.est_usd_month, 2)}/mo</span> : null}<div className="text-zinc-500">{r.why}</div></li>)}</ul>
                <details className="mt-1 text-xs"><summary className="cursor-pointer text-zinc-500">put-bucket-lifecycle-configuration JSON <CopyButton text={JSON.stringify(u.proposal.lifecycle, null, 2)} /></summary><Code className="max-h-64 overflow-auto">{JSON.stringify(u.proposal.lifecycle, null, 2)}</Code></details>
              </div>
            ) : <div className="text-xs text-zinc-500">Nothing to propose.</div>}
            {notes.length > 0 && <ul className="list-disc space-y-0.5 pl-4 text-xs text-zinc-500">{notes.map((n: string) => <li key={n}>{n}</li>)}</ul>}
            {err && <div className="text-xs text-red-300">{err}</div>}
          </div>
        )}
    </Group>
  );
}

function S3Detail({ d }: { d: any }) {
  const sizes: Record<string, number> = d.sizes || {};
  const PRICE: Record<string, number> = { StandardStorage: 0.023, StandardIAStorage: 0.0125, OneZoneIAStorage: 0.01, IntelligentTieringFAStorage: 0.023, IntelligentTieringIAStorage: 0.0125, IntelligentTieringAAStorage: 0.004, IntelligentTieringAIAStorage: 0.004, IntelligentTieringDAAStorage: 0.00099, GlacierInstantRetrievalStorage: 0.004, GlacierStorage: 0.0036, DeepArchiveStorage: 0.00099, ReducedRedundancyStorage: 0.023 };
  return (
    <>
      <h2 className="text-base font-medium text-zinc-100">{d.name}</h2>
      <div className="mt-1 flex flex-wrap items-center gap-2 text-xs"><Badge>{d.region}</Badge>{d.public ? <Badge>public</Badge> : null}{d.versioning ? <Badge>versioned</Badge> : null}<span className="text-zinc-500">created {when(d.created)}</span></div>
      <S3UsageBlock name={d.name} />
      <Group title="Storage by class">
        {Object.keys(sizes).length === 0 ? <div className="text-sm text-zinc-500">No storage metrics yet (CloudWatch publishes bucket sizes once a day; empty buckets have none).</div> : (
          <table className="w-full text-sm"><thead><tr className="text-zinc-500"><th className="text-left font-normal">Class</th><th className="text-right font-normal">GB</th><th className="text-right font-normal">$ / GB-mo</th><th className="text-right font-normal">$ / mo</th></tr></thead>
            <tbody>{Object.entries(sizes).sort((a, b) => b[1] - a[1]).map(([c, gb]) => <tr key={c} className="border-t border-zinc-800/60"><td className="py-0.5">{c.replace(/Storage$/, "")}</td><td className="text-right">{gb.toLocaleString(undefined, { maximumFractionDigits: 2 })}</td><td className="text-right font-mono text-xs">{PRICE[c] ?? "—"}</td><td className="text-right">{usd(gb * (PRICE[c] ?? 0.023), 2)}</td></tr>)}</tbody></table>
        )}
      </Group>
      <Domains list={d.domains} empty="No Route 53 record serves this bucket as a website or a CloudFront origin." />
      <Group title="Lifecycle">
        <Dl rows={[["Rules", d.lifecycle_rules ? `${d.lifecycle_rules}` : <span className={d.standard_gb > 20 ? "text-amber-300" : ""}>none{d.standard_gb > 20 ? `: ${Number(d.standard_gb).toFixed(0)} GB sit in Standard; a transition to Infrequent Access after 30 days would save about ${usd(d.standard_gb * (0.023 - 0.0125))}/month if rarely read` : ""}</span>], ["Objects", d.objects != null ? Number(d.objects).toLocaleString() : null], ["Metrics day", d.metric_day]]} />
      </Group>
      <Timeline kind="s3" id={d.name} />
    </>
  );
}

function Route53Detail({ d }: { d: any }) {
  const links: any[] = d.links || []; const routing = d.routing || {};
  const routingRows: [string, ReactNode][] = Object.entries(routing).map(([k, v]) => [k.replace(/_/g, " "), typeof v === "object" ? JSON.stringify(v) : String(v)]);
  return (
    <>
      <h2 className="break-all font-mono text-base font-medium text-zinc-100">{d.name}</h2>
      <div className="mt-1 flex flex-wrap items-center gap-2 text-xs"><Badge>{d.type}</Badge>{d.alias ? <Badge>alias</Badge> : null}<Badge>{d.link_state}</Badge>{d.gone ? <Badge>gone</Badge> : null}<span className="text-zinc-500">zone {d.zone_name}</span></div>
      <div className="mt-1 text-xs text-zinc-500">first seen {when(d.first_seen)} · last seen {when(d.last_seen)}</div>
      <Group title="Record">
        <Dl rows={[
          ["Alias target", d.alias ? <Mono>{d.alias_target}</Mono> : null],
          ["Values", !d.alias && d.values?.length ? <ul className="space-y-0.5">{d.values.map((v: string, i: number) => <li key={i} className="break-all font-mono text-xs">{v}</li>)}</ul> : null],
          ["TTL", d.alias ? "alias records take the target's TTL" : d.ttl != null ? `${d.ttl} s` : null],
          ["Health check", d.health_check_id && <Mono>{d.health_check_id}</Mono>],
          ...routingRows,
        ]} />
      </Group>
      <Group title="Leads to">
        <div className={`text-sm ${d.link_state === "unmatched" ? "text-red-300" : "text-zinc-200"}`}>{d.summary}</div>
        {d.link_state === "unmatched" && <div className="mt-1 text-xs text-zinc-400">A record that names an AWS resource this account no longer has serves nothing, and an S3 website or ELB name can be claimed by a stranger (subdomain takeover). Delete the record, or recreate the resource. If the target lives in another AWS account, that is fine: the advisor only sees this one.</div>}
        {d.link_state === "external" && <div className="mt-1 text-xs text-zinc-400">Points outside AWS: nothing in this account serves it, so no AWS cost follows from it beyond the zone.</div>}
        {links.length > 0 && (
          <ul className="mt-2 space-y-1">
            {links.map((l: any, i: number) => <li key={`${l.kind}:${l.id}:${i}`} className={l.hop > 1 ? "ml-4" : ""}><ResourceLink l={l} />{l.via && l.hop > 1 ? <span className="ml-2 text-xs text-zinc-500">via {l.via}</span> : null}</li>)}
          </ul>
        )}
      </Group>
    </>
  );
}

function DynamoDetail({ d }: { d: any }) {
  const onDemand = d.billing_mode === "PAY_PER_REQUEST";
  const scale = d.metric_days > 0 ? 30 / d.metric_days : 0;
  return (
    <>
      <h2 className="text-base font-medium text-zinc-100">{d.name}</h2>
      <div className="mt-1 flex flex-wrap items-center gap-2 text-xs"><Badge>{onDemand ? "on demand" : "provisioned"}</Badge>{d.table_class && d.table_class !== "STANDARD" ? <Badge>{d.table_class}</Badge> : null}{d.status && d.status !== "ACTIVE" ? <Badge>{d.status}</Badge> : null}{d.gone ? <Badge>gone</Badge> : null}<Mono>{d.arn}</Mono></div>
      <div className="mt-1 text-xs text-zinc-500">created {day(d.created)} · first seen {when(d.first_seen)} · last seen {when(d.last_seen)}</div>
      <Group title="Capacity">
        <Dl rows={[
          ["Mode", onDemand ? "on demand (pay per request)" : `provisioned: ${d.read_capacity} RCU, ${d.write_capacity} WCU`],
          ["Indexes", d.gsi_count ? `${d.gsi_count} global secondary${onDemand ? "" : ` (${d.gsi_read_capacity} RCU, ${d.gsi_write_capacity} WCU provisioned)`}` : "none"],
          ["Point-in-time recovery", d.pitr ? "enabled" : "off"], ["Streams", d.stream ? "enabled" : "off"], ["Region", d.region],
        ]} />
      </Group>
      <Group title="Usage, last 30 days">
        <Dl rows={[
          ["Stored", `${(Number(d.size_bytes) / 1e9).toFixed(2)} GB · ${Number(d.item_count || 0).toLocaleString()} items`],
          ["Consumed", d.metric_days ? `${Math.round(d.read_units_30d).toLocaleString()} read units · ${Math.round(d.write_units_30d).toLocaleString()} write units over ${d.metric_days} day${d.metric_days === 1 ? "" : "s"} with data` : "no CloudWatch data yet"],
          ["Per month", onDemand ? `≈ ${Math.round(d.read_units_30d * scale).toLocaleString()} reads · ${Math.round(d.write_units_30d * scale).toLocaleString()} writes` : `provisioned units are billed whether used or not: ${Math.round(((d.read_capacity + (d.gsi_read_capacity || 0)) * 3600 * 730) ? (100 * d.read_units_30d * scale) / ((d.read_capacity + (d.gsi_read_capacity || 0)) * 3600 * 730) : 0)} % of the read units, ${Math.round(((d.write_capacity + (d.gsi_write_capacity || 0)) * 3600 * 730) ? (100 * d.write_units_30d * scale) / ((d.write_capacity + (d.gsi_write_capacity || 0)) * 3600 * 730) : 0)} % of the write units used`],
        ]} />
      </Group>
      <Group title="At list, per month">
        <Dl rows={[["Storage", usd(d.storage_usd, 2)], ["Capacity", `${usd(d.capacity_usd, 2)} (${onDemand ? "request units at the on-demand rates" : "provisioned units by the hour"})`], ["Total", usd(d.monthly_usd, 2)]]} />
        <p className="mt-1 text-xs text-zinc-500">us-east-1 standard-class rates, before reservations and the free tier; the capacity-mode action compares both modes on the same metrics and files a recommendation when the other is cheaper.</p>
      </Group>
      {Object.keys(d.tags || {}).length > 0 && <Group title="Tags"><Dl rows={Object.entries(d.tags).map(([k, v]) => [k, String(v)] as [string, ReactNode])} /></Group>}
      <Timeline kind="dynamodb" id={d.name} />
    </>
  );
}

function LambdaDetail({ d }: { d: any }) {
  const rate = d.arm ? 0.0000133334 : 0.0000166667;
  return (
    <>
      <h2 className="text-base font-medium text-zinc-100">{d.name}</h2>
      <div className="mt-1 flex flex-wrap items-center gap-2 text-xs"><Badge>{d.runtime || "runtime ?"}</Badge><Badge>{d.arm ? "arm64" : "x86_64"}</Badge>{d.gone ? <Badge>gone</Badge> : null}<Mono>{d.arn}</Mono></div>
      <div className="mt-1 text-xs text-zinc-500">first seen {when(d.first_seen)} · last seen {when(d.last_seen)}</div>
      <Group title="Configuration">
        <Dl rows={[["Memory", `${d.memory_mb} MB`], ["Timeout", d.timeout_s != null ? `${d.timeout_s} s` : null], ["Region", d.region]]} />
      </Group>
      <Group title="Usage, last 30 days">
        <Dl rows={[
          ["Invocations", `${Number(d.invocations_30d).toLocaleString()} over ${d.days} day${d.days === 1 ? "" : "s"} with data`],
          ["Average duration", d.avg_duration_ms != null ? `${Number(d.avg_duration_ms).toLocaleString()} ms` : "—"],
          ["Errors", Number(d.errors_30d).toLocaleString()],
          ["Compute", `${Number(d.gb_seconds_month).toLocaleString()} GB-seconds / month (duration × ${d.memory_mb / 1024} GB)`],
        ]} />
      </Group>
      <Group title="Price">
        <Dl rows={[
          ["At list", <>{usd(d.monthly_usd, 2)} / month = {Number(d.gb_seconds_month).toLocaleString()} GB-s × {rate} + {Number(d.invocations_month).toLocaleString()} requests × 0.0000002</>],
          ["What the bill applies", "the Compute Savings Plan discount and the free tier (400,000 GB-s and one million requests a month across the account), so the net line is lower"],
          ["Graviton", d.arm ? "already on arm64" : `arm64 would cost ${usd(Number(d.gb_seconds_month) * 0.0000133334 + Number(d.invocations_month) * 0.0000002, 2)} / month at list (20 % less on compute); needs an arm64 build of the function`],
        ]} />
      </Group>
      <Domains list={d.domains} empty="No Route 53 record reaches this function (a function URL, an API Gateway domain or a load balancer target would)." />
      <Group title="Findings and recommendations">
        <div className="text-sm text-zinc-400">{d.findings ? <Link className="underline" to={`/findings?q=${encodeURIComponent(d.name)}`}>{d.findings} finding{d.findings === 1 ? "" : "s"}</Link> : "no findings"} · {d.open_recs ? <Link className="underline" to={`/recommendations?q=${encodeURIComponent(d.name)}`}>{d.open_recs} open recommendation{d.open_recs === 1 ? "" : "s"}</Link> : "no open recommendations"}</div>
      </Group>
      <Timeline kind="lambda" id={d.name} />
    </>
  );
}

function CacheDetail({ d }: { d: any }) {
  const s = d.snapshot || {};
  const id = s.identity || {}; const price = s.price; const ut = s.utilisation || {};
  return (
    <>
      <h2 className="text-base font-medium text-zinc-100">{d.cache_cluster_id}</h2>
      <div className="mt-1 flex flex-wrap items-center gap-2 text-xs"><Badge>{d.status}</Badge>{d.gone ? <Badge>gone</Badge> : null}<span className="text-zinc-500">{d.engine} {d.engine_version}</span></div>
      <div className="mt-1 text-xs text-zinc-500">first seen {when(d.first_seen)} · last seen {when(d.last_seen)}</div>
      <WatchToggle kind="elasticache" id={d.cache_cluster_id} />
      <Group title="Identity">
        <Dl rows={[
          ["Node type", `${id.node_type} × ${id.num_nodes}`],
          ["Replication group", id.replication_group],
          ["Region / AZ", `${id.region} / ${id.availability_zone || "—"}`],
          ["Created", when(id.created)],
          ["Subnet group", id.subnet_group],
          ["Encryption", `in transit ${yesNo(id.transit_encryption) ?? "—"} · at rest ${yesNo(id.at_rest_encryption) ?? "—"}`],
          ["Auto minor upgrade", yesNo(id.auto_minor_version_upgrade)],
          ["Snapshot retention", id.snapshot_retention_days != null ? `${id.snapshot_retention_days} days` : null],
          ["ARN", id.arn && <Mono>{id.arn}</Mono>],
        ]} />
      </Group>
      <Group title="Utilisation, 30 days">
        <Dl rows={[
          ["Engine CPU", ut.cpu_days ? `${pct(ut.cpu_30d_avg_max)} avg daily peak · ${pct(ut.cpu_30d_avg)} avg · ${ut.cpu_days} days of data` : "no CloudWatch data"],
          ["Memory, peak", ut.memory_pct_max != null ? <span className={ut.memory_pct_max >= 90 ? "text-amber-300" : ""}>{ut.memory_pct_max}% of the node's memory</span> : null],
          ["Evictions", ut.evictions_30d != null ? (ut.evictions_30d ? <span className="text-amber-300">{Number(ut.evictions_30d).toLocaleString()} keys evicted: the cache is too small for its working set</span> : "none") : null],
          ["Connections, peak", ut.connections_max != null ? String(ut.connections_max) : null],
        ]} />
      </Group>
      <Group title="Price">
        {price?.monthly != null ? <Dl rows={[["On-demand", `${usd(price.monthly, 2)} / month (${usd(price.monthly_per_node, 2)} per node × ${id.num_nodes}; ${usd(price.hourly_per_node, 4)} / node-hour, ${price.pricing_engine})`], ["Price fetched", when(price.fetched_at)]]} />
          : <div className="text-sm text-zinc-500">No on-demand price found for {d.node_type} ({d.engine}).</div>}
      </Group>
      <Group title="Tags"><Tags tags={s.tags} /></Group>
      <Domains list={d.domains} empty="No Route 53 record names this cluster's endpoints." />
      <Related id={d.cache_cluster_id} recs={d.open_recs} findings={d.findings} />
      <Timeline kind="elasticache" id={d.cache_cluster_id} />
    </>
  );
}

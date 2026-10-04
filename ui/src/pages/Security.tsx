import { Fragment, useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../api";
import { Badge, Button, Card, Empty, Pager, Stat, Td, Th } from "../components/ui";
import { VulnerabilitiesCard } from "../components/vulnerabilities";

const PAGE_SIZE = 50;
const SEVERITIES = ["critical", "high", "medium", "low"] as const;
const when = (s: string | null | undefined) => (s ? String(s).slice(0, 16).replace("T", " ") : "—");
const short = (r: string | null | undefined) => {
  const m = /:(?:instance|security-group|volume|snapshot|vpc|subnet)\/(.+)$/.exec(String(r || ""));
  return m ? m[1] : String(r || "");
};

/** Who can reach a flagged group or instance, fetched when its row opens. */
function ExposurePanel({ resource }: { resource: string }) {
  const [data, setData] = useState<any>(null);
  useEffect(() => { api(`/security/exposure?resource=${encodeURIComponent(resource)}`).then(setData).catch(() => setData({ exposure: null })); }, [resource]);
  if (!data) return <div className="text-xs text-zinc-500">Looking up who can reach it…</div>;
  const ex = data.exposure;
  if (!ex) return <div className="text-xs text-zinc-500">Reach is worked out for security groups and instances only.</div>;
  return (
    <div className="space-y-2 text-xs">
      <div className={ex.exposed ? "text-red-300" : "text-zinc-400"}>{ex.summary}</div>
      {ex.open_ports.length > 0 && <div className="text-zinc-400">Open to 0.0.0.0/0 on <span className="font-mono">{ex.open_ports.join(", ")}</span></div>}
      {ex.instances.length > 0 && (
        <table className="w-full border-collapse">
          <thead><tr><Th>Instance</Th><Th>Public address</Th><Th>Listening, open to the internet</Th><Th>Domains</Th></tr></thead>
          <tbody>
            {ex.instances.map((i: any) => (
              <tr key={i.id} className="border-t border-zinc-800">
                <Td><Link className="underline" to={`/inventory?tab=ec2&id=${i.id}`}>{i.name || i.id}</Link>{i.name && <div className="font-mono text-[11px] text-zinc-500">{i.id}</div>}</Td>
                <Td className="font-mono">{i.public_ip || "—"}</Td>
                <Td>{i.ports.length ? i.ports.map((p: any) => `${p.port}${p.app ? ` ${p.app}` : ""}`).join(", ") : <span className="text-zinc-600">none seen by the probe</span>}</Td>
                <Td>{i.domains.length ? i.domains.join(", ") : "—"}</Td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

export default function Security() {
  const [params, setParams] = useSearchParams();
  const [summary, setSummary] = useState<any>(null);
  const [data, setData] = useState<any>(null);
  const [msg, setMsg] = useState("");
  const [q, setQ] = useState(params.get("q") || "");
  const [openRow, setOpenRow] = useState<number | null>(null);
  const [logOf, setLogOf] = useState<any>(null);
  const scan = params.get("scan") || "";
  const severity = params.get("severity") || "";
  const control = params.get("control_id") || "";
  const onlyNew = params.get("new") === "1";
  const page = Math.max(1, Number(params.get("page")) || 1);

  const loadSummary = () => api("/security/summary").then(setSummary).catch((e) => setMsg(e.message));
  useEffect(() => { loadSummary(); }, []);
  // a scan in flight: poll until it finishes, then reload the list
  useEffect(() => {
    if (!summary?.busy) return;
    const t = setInterval(() => api("/security/summary").then((s) => { setSummary(s); if (!s.busy) setParams(new URLSearchParams(params)); }), 5000);
    return () => clearInterval(t);
  }, [summary?.busy]);
  useEffect(() => {
    const qs = new URLSearchParams();
    if (scan) qs.set("scan_id", scan);
    if (severity) qs.set("severity", severity);
    if (control) qs.set("control_id", control);
    if (onlyNew) qs.set("new", "1");
    if (params.get("q")) qs.set("q", params.get("q")!);
    qs.set("page", String(page));
    qs.set("page_size", String(PAGE_SIZE));
    api(`/security/findings?${qs}`).then(setData).catch(() => setData({ findings: [], controls: [], total: 0, page: 1, page_size: PAGE_SIZE }));
  }, [scan, severity, control, onlyNew, params.get("q"), page, summary?.latest?.id]);

  const set = (k: string, v: string) => { const p = new URLSearchParams(params); v ? p.set(k, v) : p.delete(k); if (k !== "page") p.delete("page"); setParams(p); setOpenRow(null); };
  const scanNow = async () => { setMsg(""); try { await api("/security/scan", { method: "POST", body: "{}" }); await loadSummary(); } catch (e: any) { setMsg(e.message); } };
  const toggleBenchmark = async (id: string) => {
    const on: string[] = summary.benchmarks.enabled;
    const enabled = on.includes(id) ? on.filter((b) => b !== id) : [...on, id];
    try { await api("/security/benchmarks", { method: "PUT", body: JSON.stringify({ enabled }) }); await loadSummary(); } catch (e: any) { setMsg(e.message); }
  };

  const latest = summary?.latest;
  // under one account's scope the cards count that account's findings of the latest scan; the scan's own counts are organisation-wide
  const counts = summary?.scope?.counts ?? latest?.counts ?? {};
  const prev = summary?.scope ? null : summary?.previous?.counts || null;
  const delta = (s: string) => {
    if (!prev) return null;
    const d = (counts[s] || 0) - (prev[s] || 0);
    return d === 0 ? "same as the scan before" : `${d > 0 ? "+" : ""}${d} since scan #${summary.previous.id}`;
  };
  const recs: any[] = summary?.open_recommendations ?? [];

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-xl font-semibold text-zinc-100">Security {latest && <span className="text-sm font-normal text-zinc-500">scan #{latest.id} · {when(latest.finished_at)} UTC · {summary?.scope ? <>{summary.scope.alarms} findings in account {summary.scope.account} ({summary.scope.critical} critical, {summary.scope.high} high) of {latest.alarms} across the organisation</> : <>{latest.alarms} findings</>}</span>}</h1>
        <div className="flex items-center gap-2">
          {summary?.benchmarks?.all.map((b: any) => (
            <label key={b.id} className="flex items-center gap-1 text-xs text-zinc-400" title={b.title}>
              <input type="checkbox" checked={summary.benchmarks.enabled.includes(b.id)} onChange={() => toggleBenchmark(b.id)} />{b.id === "foundational_security" ? "FSBP" : "CIS v3"}
            </label>
          ))}
          <Button onClick={scanNow} disabled={!summary || summary.busy}>{summary?.busy ? "Scanning…" : "Scan now"}</Button>
        </div>
      </div>
      {msg && <div className="text-sm text-red-300">{msg}</div>}
      <p className="text-xs text-zinc-500">
        Turbot's aws_compliance benchmarks, run daily apart from the cost runs. Every finding is listed here. Critical ones become recommendations, and so do a few high ones when the
        resource is reachable: a security group on a running instance with a public address, an instance a domain resolves to. Security recommendations carry no saving and the executor never acts on them.
        A control the role may not read shows up as an error in the scan log and in Settings › Permissions, not as a finding.
      </p>

      <VulnerabilitiesCard />

      {!summary ? <Empty>Loading…</Empty> : !latest ? (
        <Empty>{summary.busy ? "The first scan is running; it takes about a minute." : "No security scan yet. Press Scan now, or wait for the daily one (COMPLIANCE_CRON)."}</Empty>
      ) : (
        <>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
            {SEVERITIES.map((s) => (
              <button key={s} type="button" className="text-left" onClick={() => set("severity", severity === s ? "" : s)}>
                <Stat label={s} value={<span className={s === "critical" ? "text-red-300" : s === "high" ? "text-orange-300" : undefined}>{counts[s] || 0}</span>} hint={delta(s)} />
              </button>
            ))}
            <button type="button" className="text-left" onClick={() => set("new", onlyNew ? "" : "1")}>
              <Stat label="New in this scan" value={latest.new_alarms} hint={`${latest.resolved} resolved${latest.errors ? ` · ${latest.errors} control errors` : ""}`} />
            </button>
          </div>

          <Card title={<span>Security recommendations <span className="font-normal text-zinc-500">· open, pending and approved; decided on the Recommendations page like any other</span></span>}>
            {!recs.length ? <div className="text-sm text-zinc-500">None open. Critical findings and reachable high ones land here.</div> : (
              <table className="w-full border-collapse">
                <thead><tr><Th>Severity</Th><Th>Recommendation</Th><Th>Reach</Th><Th>Status</Th></tr></thead>
                <tbody>
                  {recs.map((r) => (
                    <tr key={r.id} className="border-t border-zinc-800 hover:bg-zinc-900/60">
                      <Td><Badge>{r.severity || "unrated"}</Badge></Td>
                      <Td><Link className="hover:underline" to={`/recommendations?status=all&id=${r.id}`}>#{r.id} {r.title}</Link></Td>
                      <Td className={`max-w-md text-xs ${r.exposed ? "text-red-300" : "text-zinc-500"}`}>{r.summary || "—"}</Td>
                      <Td><Badge>{r.status}</Badge></Td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Card>

          <div className="flex flex-wrap items-center gap-2">
            <select value={severity} onChange={(e) => set("severity", e.target.value)}>
              <option value="">All severities</option>
              {[...SEVERITIES, "unrated"].map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
            <select value={control} onChange={(e) => set("control_id", e.target.value)} className="max-w-md">
              <option value="">All controls</option>
              {(data?.controls ?? []).map((c: any) => <option key={c.control_id} value={c.control_id}>{c.severity ? `[${c.severity}] ` : ""}{c.control_title || c.control_id} ({c.n})</option>)}
            </select>
            <label className="flex items-center gap-1 text-sm text-zinc-400"><input type="checkbox" checked={onlyNew} onChange={() => set("new", onlyNew ? "" : "1")} />new only</label>
            <form onSubmit={(e) => { e.preventDefault(); set("q", q); }}><input placeholder="search resource, reason or control" value={q} onChange={(e) => setQ(e.target.value)} className="w-72" /></form>
          </div>

          {!data ? <Empty>Loading…</Empty> : data.findings.length === 0 ? <Empty>No findings match.</Empty> : (
            <>
              <table className="w-full border-collapse overflow-hidden rounded-lg border border-zinc-800">
                <thead className="bg-zinc-900"><tr><Th>Severity</Th><Th>Control</Th><Th>Resource</Th><Th>Reason</Th><Th>Region</Th><Th>First seen</Th></tr></thead>
                <tbody>
                  {data.findings.map((f: any) => {
                    const isNew = f.first_seen_scan === data.scan_id && latest.new_alarms > 0;
                    const reachable = /:(instance|security-group)\//.test(String(f.resource));
                    return (
                      <Fragment key={f.id}>
                        <tr className={`border-t border-zinc-800 hover:bg-zinc-900/60 ${openRow === f.id ? "bg-zinc-900/40" : ""} ${reachable ? "cursor-pointer" : ""}`} onClick={() => reachable && setOpenRow(openRow === f.id ? null : f.id)}>
                          <Td><Badge>{f.severity || "unrated"}</Badge></Td>
                          <Td className="max-w-72">
                            <div className="truncate" title={f.control_title}>{String(f.control_title || f.control_id).replace(/^\d+(\.\d+)*\s+/, "")}</div>
                            <div className="text-xs text-zinc-500">{f.control_id.replace(/^aws_compliance\.control\./, "")}{f.service ? ` · ${f.service}` : ""}</div>
                          </Td>
                          <Td className="max-w-72 break-all font-mono text-xs"><span title={f.resource}>{short(f.resource)}</span>{reachable && <div className="font-sans text-[11px] text-sky-300">{openRow === f.id ? "hide reach" : "who can reach it"}</div>}</Td>
                          <Td className="text-sm">{f.reason}</Td>
                          <Td className="text-zinc-500">{f.region || "—"}</Td>
                          <Td className="whitespace-nowrap text-xs text-zinc-500">{isNew ? <Badge>new</Badge> : when(f.first_seen_at)}</Td>
                        </tr>
                        {openRow === f.id && <tr className="border-t border-zinc-800 bg-zinc-950/40"><td colSpan={6} className="p-3"><ExposurePanel resource={f.resource} /></td></tr>}
                      </Fragment>
                    );
                  })}
                </tbody>
              </table>
              <Pager page={data.page} pageSize={data.page_size} total={data.total} onPage={(p) => set("page", String(p))} />
            </>
          )}
        </>
      )}

      {summary?.scans?.length > 0 && (
        <Card title="Scans">
          <table className="w-full border-collapse">
            <thead><tr><Th>Scan</Th><Th>Started</Th><Th>Status</Th><Th>Benchmarks</Th><Th className="text-right">Findings</Th><Th className="text-right">New</Th><Th className="text-right">Resolved</Th><Th className="text-right">Errors</Th><Th /></tr></thead>
            <tbody>
              {summary.scans.map((s: any) => (
                <Fragment key={s.id}>
                  <tr className="border-t border-zinc-800">
                    <Td>{s.status === "completed" ? <button type="button" className="underline" onClick={() => set("scan", scan === String(s.id) ? "" : String(s.id))}>#{s.id}</button> : `#${s.id}`}{scan === String(s.id) && <span className="ml-1 text-xs text-sky-300">shown</span>}</Td>
                    <Td className="text-xs text-zinc-400">{when(s.started_at)} · {s.trigger}</Td>
                    <Td><Badge>{s.status}</Badge>{s.error && <div className="text-xs text-red-300">{s.error}</div>}</Td>
                    <Td className="text-xs text-zinc-400">{s.benchmarks.join(", ")}</Td>
                    <Td className="text-right">{s.alarms}</Td>
                    <Td className="text-right">{s.new_alarms}</Td>
                    <Td className="text-right">{s.resolved}</Td>
                    <Td className="text-right">{s.errors}</Td>
                    <Td className="text-right"><button type="button" className="text-xs text-sky-300" onClick={() => logOf?.id === s.id ? setLogOf(null) : api(`/security/scans/${s.id}`).then(setLogOf).catch((e) => setMsg(e.message))}>{logOf?.id === s.id ? "hide log" : "log"}</button></Td>
                  </tr>
                  {logOf?.id === s.id && <tr><td colSpan={9} className="p-2"><pre className="max-h-80 overflow-auto whitespace-pre-wrap rounded bg-zinc-950 p-2 text-[11px] text-zinc-400">{logOf.log || "(empty)"}</pre></td></tr>}
                </Fragment>
              ))}
            </tbody>
          </table>
        </Card>
      )}
    </div>
  );
}

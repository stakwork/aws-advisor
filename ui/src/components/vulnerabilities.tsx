import { Fragment, useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../api";
import { Badge, Button, Card, Empty, Pager, Stat, Td, Th } from "./ui";

/**
 * The vulnerability posture on the Security page: the installed software (software probe) matched against the
 * distribution advisories (OSV for Ubuntu, Debian, Alpine, Rocky, AlmaLinux; the Amazon Linux updateinfo feed),
 * grouped by advisory with the advisor's verdict: critical when the affected program listens on a port the internet
 * reaches, exposed when the network does, mitigated when the groups or ACL block it, local_only when nothing outside
 * the box can, affected when it is installed with no listening program of its own (a library, the kernel, a tool).
 */

const CRITICALITIES = ["critical", "exposed", "mitigated", "affected", "local_only"] as const;
const WORDS: Record<string, string> = { critical: "internet can reach the affected program", exposed: "the network or another group can reach it", mitigated: "listens, but blocked by the groups or the ACL", affected: "installed; no listening program of its own (library, kernel, tool)", local_only: "loopback only, or the attack needs local access" };
const when = (s: string | null | undefined) => (s ? String(s).slice(0, 16).replace("T", " ") : "—");
const tone = (c: string) => (c === "critical" ? "text-red-300" : c === "exposed" ? "text-orange-300" : c === "mitigated" ? "text-sky-300" : "text-zinc-300");
const sevTone = (s: string | null) => (s === "critical" ? "text-red-300" : s === "high" ? "text-orange-300" : s === "medium" ? "text-yellow-200" : "text-zinc-400");

export function VulnerabilitiesCard() {
  const [data, setData] = useState<any>(null);
  const [msg, setMsg] = useState("");
  const [criticality, setCriticality] = useState("");
  const [severity, setSeverity] = useState("");
  const [params] = useSearchParams();
  const initial = params.get("vuln") || ""; // a link from a box's Software tab lands on that advisory
  const [q, setQ] = useState(initial); const [qApplied, setQApplied] = useState(initial);
  const [page, setPage] = useState(1);
  const [open, setOpen] = useState<string | null>(initial || null);
  const [logOf, setLogOf] = useState<any>(null);
  const [showScans, setShowScans] = useState(false);

  const load = () => {
    const qs = new URLSearchParams({ page: String(page) });
    if (criticality) qs.set("criticality", criticality); if (severity) qs.set("severity", severity); if (qApplied) qs.set("q", qApplied);
    return api(`/security/vulnerabilities?${qs}`).then((d) => { setData(d); setMsg(""); }).catch((e) => setMsg(e.message));
  };
  useEffect(() => { load(); }, [criticality, severity, qApplied, page]);
  useEffect(() => { if (!data?.summary?.running) return; const t = setInterval(load, 5000); return () => clearInterval(t); }, [data?.summary?.running]);

  const scan = (force = false) => api(`/security/vulnerabilities/scan${force ? "?force=1" : ""}`, { method: "POST" }).then(() => setTimeout(load, 800)).catch((e) => setMsg(e.message));
  const s = data?.summary;
  const title = <span>Vulnerabilities <span className="font-normal text-zinc-500">· installed software matched against the distribution advisories (OSV, Amazon Linux), judged by what can reach the affected program</span></span>;

  if (!data && !msg) return <Card title={title}><Empty>Loading…</Empty></Card>;
  return (
    <Card title={title}>
      {msg && <div className="mb-2 text-sm text-red-300">{msg}</div>}
      {s && (
        <>
          <div className="mb-3 grid grid-cols-2 gap-3 md:grid-cols-6">
            {CRITICALITIES.map((c) => (
              <button key={c} type="button" className="text-left" onClick={() => { setCriticality(criticality === c ? "" : c); setPage(1); }} title={WORDS[c]}>
                <Stat label={c.replace("_", " ")} value={<span className={tone(c)}>{s.by_criticality[c] || 0}</span>} hint={c === criticality ? "filtering" : undefined} />
              </button>
            ))}
            <Stat label="Boxes affected" value={`${s.boxes_affected} / ${s.boxes_with_inventory}`} hint={`${s.vulns} advisories · ${s.matches} matches`} />
          </div>
          <div className="mb-3 flex flex-wrap items-center gap-2 text-xs text-zinc-400">
            <span>
              {s.last_scan ? <>Last match {when(s.last_scan.finished_at || s.last_scan.started_at)} · {s.last_scan.status}{s.last_scan.error ? ` · ${s.last_scan.error}` : ""} · {s.last_scan.queries} versions asked, {s.last_scan.fetched} advisories read</> : "Never matched yet: the first run asks OSV about every installed version (a few minutes for a fleet)."}
              {s.feeds.alas.length > 0 && <> · Amazon Linux feed: {s.feeds.alas.map((a: any) => `AL${a.release} ${a.advisories} advisories (${when(a.fetched_at)})`).join(", ")}</>}
            </span>
            <span className="grow" />
            <Button variant="ghost" onClick={() => scan(false)} disabled={s.running}>{s.running ? "Matching…" : "Match now"}</Button>
            <Button variant="ghost" onClick={() => scan(true)} disabled={s.running} title="Re-ask about every version, not only the ones not asked about recently">Re-match everything</Button>
          </div>
          {s.boxes_with_inventory === 0 && <div className="mb-3 rounded border border-zinc-800 bg-zinc-900/40 p-2 text-xs text-zinc-400">No box has a software inventory yet: the software probe (Settings › Probes) has not run. Its SSM document has to exist in the account first.</div>}
          {s.unsupported.length > 0 && (
            <div className="mb-3 rounded border border-zinc-800 bg-zinc-900/40 p-2 text-xs text-zinc-400">
              Not matchable yet: {s.unsupported.map((u: any) => <span key={u.os} className="mr-2" title={u.reason}>{u.os} ({u.instances} {u.instances === 1 ? "box" : "boxes"})</span>)}
              <span className="text-zinc-500">· hover for why</span>
            </div>
          )}
        </>
      )}
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <select value={criticality} onChange={(e) => { setCriticality(e.target.value); setPage(1); }}>
          <option value="">All verdicts</option>
          {CRITICALITIES.map((c) => <option key={c} value={c}>{c.replace("_", " ")}</option>)}
        </select>
        <select value={severity} onChange={(e) => { setSeverity(e.target.value); setPage(1); }}>
          <option value="">All severities</option>
          {["critical", "high", "medium", "low", "unrated"].map((x) => <option key={x} value={x}>{x}</option>)}
        </select>
        <form onSubmit={(e) => { e.preventDefault(); setQApplied(q); setPage(1); }}><input placeholder="advisory, CVE, package, process or box" value={q} onChange={(e) => setQ(e.target.value)} className="w-72" /></form>
        <span className="grow" />
        {data?.scans?.length > 0 && <button type="button" className="text-xs text-sky-300" onClick={() => setShowScans(!showScans)}>{showScans ? "Hide scans" : `Scans (${data.scans.length})`}</button>}
      </div>
      {!data?.items?.length ? <Empty>{s?.matches ? "Nothing matches the filter." : s?.boxes_with_inventory ? "No known vulnerability matches the installed software." : "Nothing to match yet."}</Empty> : (
        <>
          <table className="w-full border-collapse overflow-hidden rounded-lg border border-zinc-800">
            <thead className="bg-zinc-900"><tr><Th>Verdict</Th><Th>Advisory</Th><Th>Severity</Th><Th>Package</Th><Th>Fixed in</Th><Th className="text-right">Boxes</Th><Th>Published</Th></tr></thead>
            <tbody>
              {data.items.map((g: any) => (
                <Fragment key={g.vuln_id}>
                  <tr className={`cursor-pointer border-t border-zinc-800 hover:bg-zinc-900/60 ${open === g.vuln_id ? "bg-zinc-900/40" : ""}`} onClick={() => setOpen(open === g.vuln_id ? null : g.vuln_id)}>
                    <Td><span className={`text-xs ${tone(g.criticality)}`} title={WORDS[g.criticality]}>{g.criticality.replace("_", " ")}</span></Td>
                    <Td className="max-w-md">
                      <div className="font-mono text-xs">{g.vuln_id}{g.cves.length ? <span className="text-zinc-500"> · {g.cves.slice(0, 3).join(", ")}{g.cves.length > 3 ? ` +${g.cves.length - 3}` : ""}</span> : null}</div>
                      <div className="truncate text-xs text-zinc-400" title={g.summary || ""}>{g.summary || "—"}</div>
                    </Td>
                    <Td><span className={`text-xs ${sevTone(g.severity)}`}>{g.severity || "unrated"}{g.score != null ? ` ${g.score}` : ""}</span>{g.attack_vector && <div className="text-[11px] text-zinc-500">{g.attack_vector}</div>}</Td>
                    <Td className="font-mono text-xs">{g.packages.join(", ")}</Td>
                    <Td className="font-mono text-xs text-zinc-400">{g.fixed_versions.length ? g.fixed_versions.join(", ") : <span className="text-zinc-600" title="the advisory names no fixed version for this release yet">no fix yet</span>}</Td>
                    <Td className="text-right">{g.boxes}</Td>
                    <Td className="whitespace-nowrap text-xs text-zinc-500">{when(g.published)}</Td>
                  </tr>
                  {open === g.vuln_id && (
                    <tr className="border-t border-zinc-800 bg-zinc-950/40"><td colSpan={7} className="p-3">
                      <div className="mb-2 text-xs text-zinc-400">
                        <a className="text-sky-300 underline" href={g.source === "alas" ? `https://alas.aws.amazon.com/${g.vuln_id.startsWith("ALAS2023") ? "AL2023/" : "AL2/"}${g.vuln_id}.html` : `https://osv.dev/vulnerability/${g.vuln_id}`} target="_blank" rel="noreferrer">{g.vuln_id} at {g.source === "alas" ? "alas.aws.amazon.com" : "osv.dev"}</a>
                        {g.cves.length > 0 && <> · {g.cves.map((c: string) => <a key={c} className="mr-1 underline" href={`https://nvd.nist.gov/vuln/detail/${c}`} target="_blank" rel="noreferrer">{c}</a>)}</>}
                      </div>
                      <table className="w-full border-collapse text-xs">
                        <thead><tr><Th>Box</Th><Th>Installed</Th><Th>Program</Th><Th>Listening</Th><Th>Verdict</Th></tr></thead>
                        <tbody>
                          {g.matches.map((m: any) => (
                            <tr key={`${m.instance_id}-${m.package}`} className="border-t border-zinc-800">
                              <Td><Link className="underline" to={`/inventory?tab=ec2&id=${m.instance_id}`}>{m.instance_name || m.instance_id}</Link>{m.instance_name && <div className="font-mono text-[11px] text-zinc-500">{m.instance_id}</div>}</Td>
                              <Td className="font-mono">{m.packages.join(", ")} {m.version}<div className="text-[11px] text-zinc-500">{m.ecosystem}{m.fixed_version ? ` · fixed in ${m.fixed_version}` : ""}</div></Td>
                              <Td>{m.process || <span className="text-zinc-500">{m.scope}</span>}</Td>
                              <Td>{m.port != null ? <span className="font-mono">{m.proto}/{m.port} <span className="text-zinc-500">{m.exposure}</span></span> : <span className="text-zinc-600">not listening</span>}</Td>
                              <Td><span className={tone(m.criticality)}>{m.criticality.replace("_", " ")}</span> <span className="text-zinc-500">· {WORDS[m.criticality]}</span></Td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </td></tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
          <Pager page={data.page} pageSize={data.page_size} total={data.total} onPage={setPage} />
        </>
      )}
      {showScans && data?.scans?.length > 0 && (
        <table className="mt-3 w-full border-collapse text-xs">
          <thead><tr><Th>Scan</Th><Th>Started</Th><Th>Status</Th><Th className="text-right">Versions asked</Th><Th className="text-right">Advisories read</Th><Th className="text-right">Matches</Th><Th></Th></tr></thead>
          <tbody>
            {data.scans.map((sc: any) => (
              <Fragment key={sc.id}>
                <tr className="border-t border-zinc-800">
                  <Td>#{sc.id}</Td><Td className="text-zinc-400">{when(sc.started_at)} · {sc.trigger}</Td><Td><Badge>{sc.status}</Badge>{sc.error && <div className="text-red-300">{sc.error}</div>}</Td>
                  <Td className="text-right">{sc.queries}</Td><Td className="text-right">{sc.fetched}</Td><Td className="text-right">{sc.matches}</Td>
                  <Td className="text-right"><button type="button" className="text-sky-300" onClick={() => logOf?.id === sc.id ? setLogOf(null) : api(`/security/vulnerabilities/scans/${sc.id}`).then(setLogOf).catch(() => setLogOf(null))}>{logOf?.id === sc.id ? "Hide log" : "Log"}</button></Td>
                </tr>
                {logOf?.id === sc.id && <tr><td colSpan={7} className="p-2"><pre className="max-h-60 overflow-auto whitespace-pre-wrap rounded bg-zinc-950 p-2 text-[11px] text-zinc-400">{logOf.log || "(empty)"}</pre></td></tr>}
              </Fragment>
            ))}
          </tbody>
        </table>
      )}
    </Card>
  );
}

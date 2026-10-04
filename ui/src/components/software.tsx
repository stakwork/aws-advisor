import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, when } from "../api";
import { Button, Td, Th } from "./ui";

/**
 * Inventory › EC2 › Software: what the software probe found on one box (src/software_inventory.ts): the OS and
 * kernel, every installed package with its version and source package, the versions read from well-known binaries,
 * the images behind its containers, the recent version changes, and the advisories matched against it with the
 * advisor's verdict (src/software_vulns.ts). The package list is searchable; a search also matches the source.
 */

const tone = (c: string) => (c === "critical" ? "text-red-300" : c === "exposed" ? "text-orange-300" : c === "mitigated" ? "text-sky-300" : "text-zinc-300");
const sevTone = (s: string | null) => (s === "critical" ? "text-red-300" : s === "high" ? "text-orange-300" : s === "medium" ? "text-yellow-200" : "text-zinc-400");
const Section = ({ title, children, action }: { title: string; children: React.ReactNode; action?: React.ReactNode }) => (
  <div className="mt-4"><div className="mb-1 flex items-center justify-between text-xs uppercase tracking-wide text-zinc-500"><span>{title}</span>{action}</div>{children}</div>
);

export function SoftwarePanel({ instanceId, canProbe, onProbe, busy }: { instanceId: string; canProbe: boolean; onProbe: () => void; busy: boolean }) {
  const [d, setD] = useState<any>(null);
  const [vulns, setVulns] = useState<any[] | null>(null);
  const [q, setQ] = useState(""); const [qApplied, setQApplied] = useState("");
  const [gone, setGone] = useState(false);
  const [err, setErr] = useState("");
  const load = () => {
    const qs = new URLSearchParams(); if (qApplied) qs.set("q", qApplied); if (gone) qs.set("gone", "1"); qs.set("limit", "500");
    api(`/instances/${encodeURIComponent(instanceId)}/software?${qs}`).then((r) => { setD(r); setErr(""); }).catch((e) => setErr(e.message));
    api(`/instances/${encodeURIComponent(instanceId)}/vulnerabilities`).then((r) => setVulns(r.matches)).catch(() => setVulns([]));
  };
  useEffect(() => { load(); }, [instanceId, qApplied, gone, busy]);
  if (err) return <div className="mt-3 text-sm text-red-300">{err}</div>;
  if (!d) return <div className="mt-3 text-sm text-zinc-500">Loading…</div>;
  const probeButton = <Button variant="ghost" className="!px-2 !py-1 !text-xs normal-case tracking-normal" onClick={onProbe} disabled={busy || !canProbe} title="Run the software probe now (its SSM document has to exist in the account)">{busy ? "Probing…" : "Probe software now"}</Button>;
  if (!d.os) return <div className="mt-3 text-sm text-zinc-500">No software inventory yet: the software probe has not run on this box. {canProbe ? probeButton : "It needs the SSM agent online."}</div>;
  const os = d.os;
  return (
    <>
      <Section title={`Operating system · probed ${when(os.collected_at)}`} action={probeButton}>
        <dl className="grid grid-cols-[9.5rem_1fr] gap-x-3 gap-y-0.5 text-sm">
          <dt className="text-zinc-500">OS</dt><dd>{os.os_name || `${os.os_id ?? "?"} ${os.os_version ?? ""}`} <span className="text-zinc-500">({os.os_id} {os.os_version})</span></dd>
          <dt className="text-zinc-500">Kernel</dt><dd className="font-mono text-xs">{os.kernel || "—"} <span className="font-sans text-zinc-500">{os.arch || ""}</span></dd>
          <dt className="text-zinc-500">Packages</dt><dd>{os.packages} installed via {os.package_manager || "?"}{d.changes?.length ? <span className="text-zinc-500"> · {d.changes.length} recent version changes</span> : null}</dd>
        </dl>
      </Section>

      <Section title={`Vulnerabilities · ${(vulns ?? []).length}`}>
        {vulns == null ? <div className="text-xs text-zinc-500">Loading…</div> : !vulns.length ? <div className="text-xs text-zinc-500">No known advisory matches this box's packages (or no vulnerability match has run yet: Security › Vulnerabilities › Match now).</div> : (
          <table className="w-full border-collapse text-xs">
            <thead><tr><Th>Verdict</Th><Th>Advisory</Th><Th>Severity</Th><Th>Package</Th><Th>Fixed in</Th><Th>Listening</Th></tr></thead>
            <tbody>
              {vulns.slice(0, 60).map((m: any) => (
                <tr key={`${m.vuln_id}-${m.package}`} className="border-t border-zinc-800">
                  <Td><span className={tone(m.criticality)}>{m.criticality.replace("_", " ")}</span></Td>
                  <Td className="max-w-xs"><Link className="font-mono hover:underline" to={`/security?vuln=${encodeURIComponent(m.vuln_id)}`}>{m.vuln_id}</Link><div className="truncate text-zinc-500" title={m.summary || ""}>{m.summary || ""}</div></Td>
                  <Td><span className={sevTone(m.severity)}>{m.severity || "unrated"}{m.score != null ? ` ${m.score}` : ""}</span></Td>
                  <Td className="font-mono">{m.packages.join(", ")} {m.version}</Td>
                  <Td className="font-mono text-zinc-400">{m.fixed_version || <span className="text-zinc-600" title="the advisory names no fixed version for this release yet">no fix yet</span>}</Td>
                  <Td>{m.port != null ? <span className="font-mono">{m.process} {m.proto}/{m.port} <span className="text-zinc-500">{m.exposure}</span></span> : <span className="text-zinc-600">{m.scope}</span>}</Td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {(vulns ?? []).length > 60 && <div className="mt-1 text-xs text-zinc-500">{vulns!.length - 60} more on the Security page.</div>}
      </Section>

      <Section title={`Packages · ${d.packages.length}${d.packages.length >= 500 ? "+" : ""}`} action={
        <span className="flex items-center gap-2 normal-case tracking-normal">
          <form onSubmit={(e) => { e.preventDefault(); setQApplied(q); }}><input className="w-48 !py-0.5 text-xs" placeholder="search name or source" value={q} onChange={(e) => setQ(e.target.value)} /></form>
          <label className="flex items-center gap-1 text-xs text-zinc-400"><input type="checkbox" checked={gone} onChange={() => setGone(!gone)} /> include removed</label>
        </span>}>
        {!d.packages.length ? <div className="text-xs text-zinc-500">Nothing matches.</div> : (
          <div className="max-h-96 overflow-auto rounded border border-zinc-800">
            <table className="w-full border-collapse text-xs">
              <thead className="sticky top-0 bg-zinc-900"><tr><Th>Package</Th><Th>Version</Th><Th>Source</Th><Th>Arch</Th><Th>Since</Th></tr></thead>
              <tbody>
                {d.packages.map((p: any) => (
                  <tr key={`${p.ecosystem}-${p.name}`} className={`border-t border-zinc-800/60 ${p.gone ? "text-zinc-600 line-through" : ""}`}>
                    <Td className="font-mono">{p.name}</Td><Td className="font-mono text-zinc-300">{p.version}</Td><Td className="font-mono text-zinc-500">{p.source || ""}</Td><Td className="text-zinc-500">{p.arch || ""}</Td><Td className="whitespace-nowrap text-zinc-500">{when(p.first_seen)}</Td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>

      {d.binaries?.length > 0 && (
        <Section title={`Programs by version flag · ${d.binaries.length}`}>
          <ul className="grid grid-cols-1 gap-x-4 gap-y-0.5 text-xs md:grid-cols-2">
            {d.binaries.map((b: any) => <li key={b.name} className={b.gone ? "text-zinc-600 line-through" : "text-zinc-300"} title={b.path || ""}><span className="font-mono">{b.name}</span> <span className="text-zinc-500">{b.version}</span></li>)}
          </ul>
        </Section>
      )}

      {d.images?.length > 0 && (
        <Section title={`Container images running · ${d.images.length}`}>
          <ul className="space-y-0.5 text-xs">
            {d.images.map((i: any) => <li key={i.image} className={i.gone ? "text-zinc-600 line-through" : "text-zinc-300"}><span className="font-mono">{i.image}</span>{i.created ? <span className="text-zinc-500"> · built {when(i.created)}</span> : null}{i.platform ? <span className="text-zinc-500"> · {i.platform}</span> : null}{i.digest ? <span className="text-zinc-600"> · {String(i.digest).replace(/^.*@/, "").slice(0, 19)}…</span> : null}</li>)}
          </ul>
        </Section>
      )}

      {d.changes?.length > 0 && (
        <Section title={`Version changes · ${d.changes.length}`}>
          <ul className="space-y-0.5 text-xs text-zinc-400">
            {d.changes.slice(0, 30).map((c: any, i: number) => <li key={i}>{when(c.at)} · <span className="font-mono text-zinc-300">{c.name}</span> {c.from_version} → {c.to_version}</li>)}
          </ul>
        </Section>
      )}
    </>
  );
}

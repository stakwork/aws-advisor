import { useEffect, useState } from "react";
import { api, when } from "../api";
import { Button, Td, Th } from "./ui";

/**
 * Inventory › EC2 › Software: what the software probe found on one box (src/software_inventory.ts): the OS and
 * kernel, every installed package with its version and source package, the versions read from well-known binaries,
 * the images behind its containers, what syft read inside those images and on the filesystem (the sbom probe, when syft is
 * installed on the box), and the recent version changes and removals. The package list is searchable; a search also
 * matches the source. Vulnerability verdicts are the strut workflows' (the graph), not shown here.
 */

const Section = ({ title, children, action }: { title: string; children: React.ReactNode; action?: React.ReactNode }) => (
  <div className="mt-4"><div className="mb-1 flex items-center justify-between text-xs uppercase tracking-wide text-zinc-500"><span>{title}</span>{action}</div>{children}</div>
);

export function SoftwarePanel({ instanceId, canProbe, onProbe, busy }: { instanceId: string; canProbe: boolean; onProbe: () => void; busy: boolean }) {
  const [d, setD] = useState<any>(null);
  const [q, setQ] = useState(""); const [qApplied, setQApplied] = useState("");
  const [err, setErr] = useState("");
  const load = () => {
    const qs = new URLSearchParams(); if (qApplied) qs.set("q", qApplied); qs.set("limit", "500");
    api(`/instances/${encodeURIComponent(instanceId)}/software?${qs}`).then((r) => { setD(r); setErr(""); }).catch((e) => setErr(e.message));
  };
  useEffect(() => { load(); }, [instanceId, qApplied, busy]);
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
          <dt className="text-zinc-500">Packages</dt><dd>{os.packages} installed via {os.package_manager || "?"}{d.changes?.length ? <span className="text-zinc-500"> · {d.changes.length} recent changes</span> : null}</dd>
        </dl>
      </Section>

      <Section title={`Packages · ${d.packages.length}${d.packages.length >= 500 ? "+" : ""}`} action={
        <span className="flex items-center gap-2 normal-case tracking-normal">
          <form onSubmit={(e) => { e.preventDefault(); setQApplied(q); }}><input className="w-48 !py-0.5 text-xs" placeholder="search name or source" value={q} onChange={(e) => setQ(e.target.value)} /></form>
        </span>}>
        {!d.packages.length ? <div className="text-xs text-zinc-500">Nothing matches.</div> : (
          <div className="max-h-96 overflow-auto rounded border border-zinc-800">
            <table className="w-full border-collapse text-xs">
              <thead className="sticky top-0 bg-zinc-900"><tr><Th>Package</Th><Th>Version</Th><Th>Source</Th><Th>Arch</Th><Th>Since</Th></tr></thead>
              <tbody>
                {d.packages.map((p: any) => (
                  <tr key={`${p.ecosystem}-${p.name}`} className="border-t border-zinc-800/60">
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
            {d.binaries.map((b: any) => <li key={b.name} className="text-zinc-300" title={b.path || ""}><span className="font-mono">{b.name}</span> <span className="text-zinc-500">{b.version}</span></li>)}
          </ul>
        </Section>
      )}

      {d.images?.length > 0 && (
        <Section title={`Container images running · ${d.images.length}`}>
          <ul className="space-y-0.5 text-xs">
            {d.images.map((i: any) => <li key={i.image} className="text-zinc-300"><span className="font-mono">{i.image}</span>{i.created ? <span className="text-zinc-500"> · built {when(i.created)}</span> : null}{i.platform ? <span className="text-zinc-500"> · {i.platform}</span> : null}{i.digest ? <span className="text-zinc-600"> · {String(i.digest).replace(/^.*@/, "").slice(0, 19)}…</span> : null}</li>)}
          </ul>
        </Section>
      )}

      {d.sbom?.scan && (
        <Section title={`Software bill of materials (syft) · ${d.sbom.packages.length}${d.sbom.packages.length >= 500 ? "+" : ""}`}>
          {!d.sbom.scan.available ? (
            <div className="text-xs text-zinc-500">syft is not on this box (probed {when(d.sbom.scan.collected_at)}{d.sbom.scan.note ? `: ${d.sbom.scan.note}` : ""}), so what its images and filesystem contain beyond the OS packages is not read. The probe installs it when Settings › Probe pass › Install syft where missing is on and the box can reach GitHub; by hand: <code className="text-zinc-400">curl -sSfL https://get.anchore.io/syft | sudo sh -s -- -b /usr/local/bin</code>.</div>
          ) : (
            <>
              <ul className="mb-1 space-y-0.5 text-xs text-zinc-500">
                {d.sbom.sources.map((s: any) => <li key={`${s.source}-${s.ref}`}><span className="font-mono text-zinc-400">{s.source === "dir" ? "filesystem /" : s.ref}</span>{s.digest ? <span className="font-mono text-zinc-600" title={s.digest}> @{String(s.digest).replace(/^sha256:/, "").slice(0, 12)}</span> : null}{s.platform ? <span className="text-zinc-600"> {s.platform}</span> : null} · {s.status === "ok" ? <>{s.listed}{s.total > s.listed ? ` of ${s.total} (trimmed to the probe's output cap)` : ""} packages</> : s.status === "pending" ? <span className="text-zinc-500">not read yet{d.sbom.scan.images_mode === "local" ? " (the image scanner's turn)" : ""}</span> : <span className="text-orange-300">{s.status === "skipped" ? "skipped" : s.status === "timeout" ? "timed out" : "failed"}{s.note ? `: ${s.note}` : ""}{s.listed ? `, ${s.listed} from the last good scan` : ""}</span>}{s.source === "image" && s.via === "scanner" ? <span title={`read on the image scanner ${s.scanned_on}`}> · by the scanner</span> : null} · {when(s.collected_at)}</li>)}
              </ul>
              {d.sbom.scan.images_mode === "local" && <div className="mb-1 text-xs text-zinc-600">This box scanned only the images it built itself; the images pulled from a registry are read once for the whole fleet on the image scanner instance (Settings › Probe pass).</div>}
              {!d.sbom.packages.length ? <div className="text-xs text-zinc-500">Nothing matches.</div> : (
                <div className="max-h-96 overflow-auto rounded border border-zinc-800">
                  <table className="w-full border-collapse text-xs">
                    <thead className="sticky top-0 bg-zinc-900"><tr><Th>Package</Th><Th>Version</Th><Th>Type</Th><Th>In</Th></tr></thead>
                    <tbody>
                      {d.sbom.packages.map((p: any) => (
                        <tr key={`${p.source}-${p.ref}-${p.purl}`} className="border-t border-zinc-800/60" title={p.purl}>
                          <Td className="font-mono">{p.name}</Td><Td className="font-mono text-zinc-300">{p.version || ""}</Td><Td className="text-zinc-500">{p.type}</Td><Td className="font-mono text-zinc-500">{p.source === "dir" ? "/" : p.ref}</Td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </>
          )}
        </Section>
      )}

      {d.changes?.length > 0 && (
        <Section title={`Changes · ${d.changes.length}`}>
          <ul className="space-y-0.5 text-xs text-zinc-400">
            {d.changes.slice(0, 30).map((c: any, i: number) => <li key={i}>{when(c.at)} · <span className="font-mono text-zinc-300">{c.name}</span> {c.to_version == null ? <span className="text-zinc-500">{c.from_version} removed</span> : <>{c.from_version} → {c.to_version}</>}</li>)}
          </ul>
        </Section>
      )}
    </>
  );
}

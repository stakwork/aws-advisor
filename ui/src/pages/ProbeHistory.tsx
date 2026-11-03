import { useEffect, useState } from "react";
import { api, when } from "../api";
import { Button, Card, CopyButton, Empty, Td, Th } from "../components/ui";

type Pass = { id: number; kind: string; origin: string; started_at: string; finished_at: string | null; took_ms: number | null; candidates: number; probed: number; failed: number; failures: Record<string, number>; selection: string | null; note: string | null };
type Run = { id: number; pass_id: number | null; instance_id: string; instance_name: string | null; account_id: string | null; kind: string; origin: string; started_at: string; finished_at: string | null; took_ms: number | null; status: string; code: string | null; message: string | null; command_id: string | null; document: string | null; upload: string | null; metrics_id: number | null };
type Overview = { kind: string; last_pass: Pass | null; runs_24h: number; failed_24h: number; last_failure: Run | null };

const KINDS = ["host", "docker", "apps", "software", "sbom", "images"];
const secs = (ms: number | null | undefined) => (ms == null ? "—" : ms < 1000 ? `${ms} ms` : ms < 120_000 ? `${Math.round(ms / 1000)} s` : `${Math.round(ms / 60_000)} min`);
const ORIGIN: Record<string, string> = { cron: "scheduled", manual: "by hand", pass: "pass", agent: "agent", check: "permission check" };

const StatusPill = ({ run }: { run: Run }) => {
  const cls = run.status === "ok" ? "bg-emerald-900/50 text-emerald-300" : run.status === "running" ? "bg-sky-900/50 text-sky-300" : "bg-rose-900/50 text-rose-300";
  return <span className={`rounded px-1.5 py-0.5 text-xs ${cls}`}>{run.status === "ok" ? "stored" : run.status === "running" ? "running" : run.code || "failed"}</span>;
};

/** History > Probes: every pass and every probe the advisor sent, with how it ended, so a box that stops answering or a pass that stops short can be read here rather than in the log. */
export default function ProbeHistory() {
  const [overview, setOverview] = useState<Overview[] | null>(null);
  const [passes, setPasses] = useState<Pass[] | null>(null);
  const [runs, setRuns] = useState<Run[] | null>(null);
  const [kind, setKind] = useState("");
  const [pass, setPass] = useState<number | null>(null);
  const [status, setStatus] = useState<"" | "ok" | "failed">("");
  const [box, setBox] = useState("");
  const [open, setOpen] = useState<number | null>(null);
  const [tick, setTick] = useState(0);

  useEffect(() => { api("/probes/history").then(setOverview).catch(() => setOverview([])); }, [tick]);
  useEffect(() => { api(`/probes/history/passes?limit=100${kind ? `&kind=${kind}` : ""}`).then(setPasses).catch(() => setPasses([])); }, [kind, tick]);
  useEffect(() => {
    const q = new URLSearchParams({ limit: "500" });
    if (pass) q.set("pass_id", String(pass)); else if (kind) q.set("kind", kind);
    if (status) q.set("status", status); if (box.trim()) q.set("instance", box.trim());
    api(`/probes/history/runs?${q}`).then(setRuns).catch(() => setRuns([]));
  }, [pass, kind, status, box, tick]);
  useEffect(() => { const t = setInterval(() => setTick((n) => n + 1), 60_000); return () => clearInterval(t); }, []);

  const selected = passes?.find((p) => p.id === pass) ?? null;
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h1 className="text-xl font-semibold text-zinc-100">Probes</h1>
        <Button variant="ghost" onClick={() => setTick((n) => n + 1)}>Refresh</Button>
      </div>
      <p className="max-w-3xl text-sm text-zinc-400">Every pass and every probe sent to a box, with how it ended: stored, or the failure and its SSM command id. A pass is a scheduled or hand-run sweep of one kind; a probe can also come from a box's page, the agent or a permission check. Runs are kept 60 days, passes 180.</p>

      <Card title="Last 24 hours, per kind">
        {overview === null ? <div className="text-sm text-zinc-500">Loading…</div> : !overview.length ? <Empty>No probe has run yet.</Empty> : (
          <table className="w-full text-sm">
            <thead><tr><Th>Kind</Th><Th>Probes</Th><Th>Failed</Th><Th>Last pass</Th><Th>Last failure</Th></tr></thead>
            <tbody>
              {overview.map((o) => (
                <tr key={o.kind} className="border-t border-zinc-800">
                  <Td><button className="text-zinc-200 hover:underline" onClick={() => { setKind(o.kind); setPass(null); }}>{o.kind}</button></Td>
                  <Td>{o.runs_24h}</Td>
                  <Td className={o.failed_24h ? "text-rose-300" : ""}>{o.failed_24h}</Td>
                  <Td>{o.last_pass ? <button className="hover:underline" onClick={() => { setKind(o.kind); setPass(o.last_pass!.id); }}>{when(o.last_pass.started_at)} · {o.last_pass.probed} of {o.last_pass.candidates}{o.last_pass.failed ? <span className="text-rose-300">, {o.last_pass.failed} failed</span> : null}</button> : "—"}</Td>
                  <Td className="max-w-md text-zinc-400"><div className="truncate" title={o.last_failure?.message || ""}>{o.last_failure ? `${when(o.last_failure.started_at)} · ${o.last_failure.instance_name || o.last_failure.instance_id} · ${o.last_failure.code || "failed"}` : "—"}</div></Td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      <Card title={<span className="flex flex-wrap items-center justify-between gap-2"><span>Passes</span>
        <span className="flex items-center gap-1 text-xs">
          <button onClick={() => { setKind(""); setPass(null); }} className={`rounded border px-1.5 py-0.5 ${!kind ? "border-zinc-400 text-zinc-100" : "border-zinc-700 text-zinc-400"}`}>all</button>
          {KINDS.map((k) => <button key={k} onClick={() => { setKind(k); setPass(null); }} className={`rounded border px-1.5 py-0.5 ${k === kind ? "border-zinc-400 text-zinc-100" : "border-zinc-700 text-zinc-400"}`}>{k}</button>)}
        </span></span>}>
        {passes === null ? <div className="text-sm text-zinc-500">Loading…</div> : !passes.length ? <Empty>No pass yet{kind ? ` of kind ${kind}` : ""}.</Empty> : (
          <div className="max-h-80 overflow-auto">
            <table className="w-full text-sm">
              <thead><tr><Th>Started</Th><Th>Kind</Th><Th>From</Th><Th>Candidates</Th><Th>Probed</Th><Th>Failed</Th><Th>Took</Th><Th>Selection</Th></tr></thead>
              <tbody>
                {passes.map((p) => (
                  <tr key={p.id} onClick={() => setPass(pass === p.id ? null : p.id)} className={`cursor-pointer border-t border-zinc-800 ${pass === p.id ? "bg-zinc-800/60" : "hover:bg-zinc-900"}`}>
                    <Td>{when(p.started_at)}{!p.finished_at ? <span className="ml-1 text-xs text-sky-300">running</span> : null}</Td>
                    <Td>{p.kind}</Td>
                    <Td>{ORIGIN[p.origin] || p.origin}</Td>
                    <Td>{p.candidates}</Td>
                    <Td>{p.probed}</Td>
                    <Td className={p.failed ? "text-rose-300" : ""}>{p.failed}{p.failed ? <span className="ml-1 text-xs text-zinc-500">{Object.entries(p.failures).map(([c, n]) => `${c} ${n}`).join(", ")}</span> : null}</Td>
                    <Td>{secs(p.took_ms)}</Td>
                    <Td className="max-w-md text-zinc-400"><div className="truncate" title={[p.selection, p.note].filter(Boolean).join("\n")}>{p.selection || p.note || "—"}</div></Td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {selected && (selected.selection || selected.note) ? <div className="mt-2 space-y-0.5 text-xs text-zinc-400">{selected.selection ? <div>{selected.selection}</div> : null}{selected.note ? <div>{selected.note}</div> : null}</div> : null}
      </Card>

      <Card title={<span className="flex flex-wrap items-center justify-between gap-2"><span>Probes{selected ? ` of the ${selected.kind} pass started ${when(selected.started_at)}` : kind ? ` · ${kind}` : ""}{selected ? <button className="ml-2 text-xs font-normal text-zinc-400 hover:underline" onClick={() => setPass(null)}>every pass</button> : null}</span>
        <span className="flex items-center gap-2 text-xs">
          <input value={box} onChange={(e) => setBox(e.target.value)} placeholder="box id or name" className="w-40 rounded border border-zinc-700 bg-zinc-900 px-2 py-0.5 text-zinc-200" />
          {(["", "failed", "ok"] as const).map((s) => <button key={s} onClick={() => setStatus(s)} className={`rounded border px-1.5 py-0.5 ${s === status ? "border-zinc-400 text-zinc-100" : "border-zinc-700 text-zinc-400"}`}>{s || "all"}</button>)}
        </span></span>}>
        {runs === null ? <div className="text-sm text-zinc-500">Loading…</div> : !runs.length ? <Empty>No probe matches.</Empty> : (
          <div className="max-h-[32rem] overflow-auto">
            <table className="w-full text-sm">
              <thead><tr><Th>Started</Th><Th>Box</Th><Th>Kind</Th><Th>From</Th><Th>Outcome</Th><Th>Took</Th><Th>Result</Th><Th>Detail</Th></tr></thead>
              <tbody>
                {runs.map((r) => (
                  <tr key={r.id} className="border-t border-zinc-800 align-top">
                    <Td className="whitespace-nowrap">{when(r.started_at)}</Td>
                    <Td><div className="text-zinc-200">{r.instance_name || r.instance_id}</div>{r.instance_name ? <div className="text-xs text-zinc-500">{r.instance_id}</div> : null}</Td>
                    <Td>{r.kind}</Td>
                    <Td>{ORIGIN[r.origin] || r.origin}{r.pass_id && r.pass_id !== pass ? <button className="ml-1 text-xs text-zinc-500 hover:underline" onClick={() => setPass(r.pass_id)}>#{r.pass_id}</button> : null}</Td>
                    <Td><StatusPill run={r} /></Td>
                    <Td className="whitespace-nowrap">{secs(r.took_ms)}</Td>
                    <Td className="text-xs text-zinc-400">{r.upload === "s3" ? "from S3" : r.upload === "inline" ? "inline" : "—"}</Td>
                    <Td className="max-w-lg">
                      {r.message ? <div className={`text-xs text-zinc-300 ${open === r.id ? "whitespace-pre-wrap break-words" : "truncate"}`} title={open === r.id ? "" : r.message}>{r.message}</div> : null}
                      <div className="mt-0.5 flex flex-wrap items-center gap-2 text-xs text-zinc-500">
                        {r.command_id ? <span className="flex items-center gap-1">command {r.command_id.slice(0, 8)}… <CopyButton text={r.command_id} label="copy id" /></span> : <span>no command sent</span>}
                        {r.document ? <span>{r.document}</span> : null}
                        {r.account_id ? <span>account {r.account_id}</span> : null}
                        {r.message && r.message.length > 80 ? <button className="hover:underline" onClick={() => setOpen(open === r.id ? null : r.id)}>{open === r.id ? "less" : "more"}</button> : null}
                      </div>
                    </Td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}

import { useEffect, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, stream, usd, when } from "../api";
import { Badge, Button, Card, Empty, Td, Th } from "../components/ui";

export default function RunDetail() {
  const { id } = useParams();
  const [run, setRun] = useState<any>(null);
  const [lines, setLines] = useState<string[]>([]);
  const [live, setLive] = useState(false);
  const box = useRef<HTMLPreElement>(null);
  const [agentCfg, setAgentCfg] = useState<any>(null);
  const [agentEvents, setAgentEvents] = useState<string[]>([]);
  const [watching, setWatching] = useState<string | null>(null);
  const [err, setErr] = useState("");
  const [changes, setChanges] = useState<any>(null);

  useEffect(() => { api("/settings").then((s) => setAgentCfg(s.agent)).catch(() => {}); }, []);
  useEffect(() => { if (run?.status === "completed") api(`/runs/${id}/changes`).then(setChanges).catch((e) => setChanges({ error: e.message })); }, [id, run?.status]);

  const sendToAgent = async () => {
    setErr("");
    try { await api(`/runs/${id}/agent`, { method: "POST" }); load(); } catch (e: any) { setErr(e.message); }
  };
  const poll = async (requestId: string) => {
    setErr("");
    try { const r = await api(`/agent-runs/${requestId}/poll`, { method: "POST" }); setErr(`status: ${r.status}${r.imported != null ? `, imported ${r.imported} recommendations` : ""}`); load(); } catch (e: any) { setErr(e.message); }
  };
  useEffect(() => {
    if (!watching) return;
    setAgentEvents([]);
    const es = stream(`/agent-runs/${watching}/events`);
    es.onmessage = (m) => {
      try {
        const ev = JSON.parse(m.data);
        const line = ev.type === "tool_call" ? `tool: ${ev.tool || ev.name || ""} ${JSON.stringify(ev.input || ev.args || "").slice(0, 200)}`
          : ev.type === "text" ? String(ev.text || ev.content || "").slice(0, 400)
          : ev.type === "done" ? "done" : ev.type === "error" ? `error: ${JSON.stringify(ev.error || ev)}` : m.data.slice(0, 300);
        setAgentEvents((l) => [...l, line]);
        if (ev.type === "done" || ev.type === "error") { es.close(); load(); }
      } catch { setAgentEvents((l) => [...l, m.data.slice(0, 300)]); }
    };
    es.onerror = () => es.close();
    return () => es.close();
  }, [watching]);

  const load = () => api(`/runs/${id}`).then(setRun).catch(() => {});
  useEffect(() => { load(); }, [id]);
  useEffect(() => {
    if (!run?.agent?.some((a: any) => a.status === "pending")) return;
    const t = setInterval(load, 10000);
    return () => clearInterval(t);
  }, [run]);

  useEffect(() => {
    setLines([]);
    const es = stream(`/runs/${id}/stream`);
    setLive(true);
    es.onmessage = (m) => {
      const ev = JSON.parse(m.data);
      if (ev.type === "log") setLines((l) => [...l, ev.line]);
      if (ev.type === "done") { setLive(false); es.close(); load(); }
    };
    es.onerror = () => { setLive(false); es.close(); };
    return () => es.close();
  }, [id]);

  useEffect(() => { box.current?.scrollTo({ top: box.current.scrollHeight }); }, [lines]);

  if (!run) return <Empty>Loading…</Empty>;
  return (
    <div className="space-y-4">
      <div>
        <Link to="/runs" className="text-xs text-zinc-500 hover:underline">← Runs</Link>
        <h1 className="flex items-center gap-3 text-xl font-semibold text-zinc-100">Run #{run.id} <Badge>{run.status}</Badge>{live && <span className="text-xs text-sky-300">live</span>}</h1>
        <div className="text-sm text-zinc-500">Started {when(run.started_at)} · finished {when(run.finished_at)} · account {run.account_id || "—"} · {run.findings_count} findings · {run.recommendations_count} open recommendations</div>
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Log">
          <pre ref={box} className="max-h-[32rem] overflow-auto whitespace-pre-wrap rounded bg-zinc-950 p-3 text-xs leading-5 text-zinc-300">{lines.join("\n") || "…"}</pre>
        </Card>
        <Card title="Findings by control">
          {run.byControl.length === 0 ? <Empty>Nothing yet.</Empty> : (
            <table className="w-full">
              <thead><tr><Th>Control</Th><Th>Status</Th><Th className="text-right">Count</Th></tr></thead>
              <tbody>
                {run.byControl.map((c: any) => (
                  <tr key={c.control_id + c.status} className="border-t border-zinc-800">
                    <Td><Link className="hover:underline" to={`/findings?run_id=${run.id}&control_id=${encodeURIComponent(c.control_id)}`}>{c.control_title || c.control_id}</Link><div className="text-xs text-zinc-500">{c.control_id}</div></Td>
                    <Td><Badge>{c.status}</Badge></Td><Td className="text-right">{c.n}</Td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      </div>
      {run.status === "completed" && (
        <Card title={`What changed${changes?.prev_run_id ? ` since run #${changes.prev_run_id}` : ""}`}>
          {!changes ? <div className="text-sm text-zinc-500">Loading…</div> : changes.error ? <div className="text-sm text-zinc-500">Not available: {changes.error}</div> : changes.prev_run_id == null ? <div className="text-sm text-zinc-500">No earlier completed run to compare with.</div> : (
            <div className="grid gap-4 lg:grid-cols-3">
              <div>
                <div className="mb-1 text-xs uppercase tracking-wide text-zinc-500">Cost metrics that moved ({changes.flagged.length} flagged)</div>
                {changes.metrics.filter((m: any) => m.delta !== 0).length === 0 ? <div className="text-sm text-zinc-500">No metric moved.</div> : (
                  <ul className="space-y-1 text-sm">
                    {changes.metrics.filter((m: any) => m.delta !== 0).slice(0, 12).map((m: any) => (
                      <li key={m.key + m.label} className="flex justify-between gap-2">
                        <span className="truncate text-zinc-300" title={`${m.key} / ${m.label}`}>{m.label}<span className="text-xs text-zinc-500"> · {m.key}</span></span>
                        <span className={`shrink-0 ${m.flagged ? (m.delta > 0 ? "text-amber-300" : "text-emerald-300") : "text-zinc-400"}`}>
                          {usd(m.prev_value)} → {usd(m.value)} ({m.delta > 0 ? "+" : ""}{usd(m.delta)}{m.pct != null ? `, ${m.pct > 0 ? "+" : ""}${m.pct}%` : ""})
                        </span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
              <div>
                <div className="mb-1 text-xs uppercase tracking-wide text-zinc-500">New findings ({changes.findings.new.length})</div>
                {changes.findings.new.length === 0 ? <div className="text-sm text-zinc-500">None.</div> : (
                  <ul className="space-y-1 text-sm">
                    {changes.findings.new.slice(0, 12).map((f: any, i: number) => <li key={i} className="truncate" title={f.reason || ""}><span className="text-zinc-500">{f.control_id}</span> <span className="font-mono text-xs">{f.resource}</span></li>)}
                    {changes.findings.new.length > 12 && <li className="text-xs text-zinc-500">… {changes.findings.new.length - 12} more</li>}
                  </ul>
                )}
              </div>
              <div>
                <div className="mb-1 text-xs uppercase tracking-wide text-zinc-500">Resolved findings ({changes.findings.resolved.length})</div>
                {changes.findings.resolved.length === 0 ? <div className="text-sm text-zinc-500">None.</div> : (
                  <ul className="space-y-1 text-sm">
                    {changes.findings.resolved.slice(0, 12).map((f: any, i: number) => <li key={i} className="truncate" title={f.reason || ""}><span className="text-zinc-500">{f.control_id}</span> <span className="font-mono text-xs">{f.resource}</span></li>)}
                    {changes.findings.resolved.length > 12 && <li className="text-xs text-zinc-500">… {changes.findings.resolved.length - 12} more</li>}
                  </ul>
                )}
              </div>
            </div>
          )}
        </Card>
      )}
      <Card title={<span className="flex items-center justify-between">Agent (repo2graph) {agentCfg?.configured && run.status === "completed" && <Button variant="ghost" onClick={sendToAgent} disabled={run.agent?.some((a: any) => a.status === "pending")}>{run.agent?.some((a: any) => a.status === "pending") ? "Agent run in progress…" : "Send findings to agent"}</Button>}</span>}>
        {!agentCfg?.configured ? <div className="text-sm text-zinc-500">Not configured (REPO2GRAPH_URL / REPO2GRAPH_TOKEN).</div> : run.agent?.length === 0 ? <div className="text-sm text-zinc-500">No agent run for this collection yet.</div> : (
          <div className="space-y-2 text-sm">
            {run.agent.map((a: any) => (
              <div key={a.request_id} className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-xs">{a.request_id}</span><Badge>{a.status}</Badge>{a.below_bar && <span className="text-xs text-amber-300" title="the answer failed the task's quality checks (tasks/<kind>/task.json)">quality check failed: {a.below_bar.join(", ")}</span>}{a.retry_of && <span className="text-xs text-zinc-500">retry with critique</span>}{a.retried_by && <span className="text-xs text-zinc-500">retried as {String(a.retried_by).slice(0, 8)}…</span>}
                <span className="text-xs text-zinc-500">{when(a.created_at)}</span>
                {a.status === "pending" && <Button variant="ghost" onClick={() => setWatching(a.request_id)}>Watch</Button>}
                <Button variant="ghost" onClick={() => poll(a.request_id)}>Poll result</Button>
                {a.error && <span className="text-xs text-red-300">{String(a.error).slice(0, 200)}</span>}
              </div>
            ))}
          </div>
        )}
        {err && <div className="mt-2 text-xs text-zinc-400">{err}</div>}
        {watching && <pre className="mt-3 max-h-80 overflow-auto whitespace-pre-wrap rounded bg-zinc-950 p-3 text-xs leading-5 text-zinc-300">{agentEvents.join("\n") || "connected — the first event usually arrives after 30 to 90 seconds, once the agent makes its first tool call"}</pre>}
      </Card>
    </div>
  );
}

import { Fragment, useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, when } from "../api";
import { Badge, Code, DetailCell, Empty, Pager, Td, Th } from "../components/ui";

const KIND_LABEL: Record<string, string> = {
  findings: "Findings batch", observe: "Daily observation", incident: "Incident", resolution: "Resolution", chat: "Chat",
  usage: "Usage", playbook: "Playbooks", pass_report: "Pass narration",
};

const pretty = (v: unknown): string => {
  if (v == null || v === "") return "";
  if (typeof v !== "string") return JSON.stringify(v, null, 2);
  try { return JSON.stringify(JSON.parse(v), null, 2); } catch { return v; }
};
const parsed = (v: unknown): any => { if (typeof v !== "string") return v ?? null; try { return JSON.parse(v); } catch { return null; } };
const secs = (s: number | null) => (s == null ? "—" : s < 90 ? `${s} s` : `${Math.round(s / 60)} min`);

/** Where in the app the thing a request was about lives. */
function AboutLinks({ a }: { a: any }) {
  const links: { to: string; label: string }[] = [
    ...a.runs.map((id: number) => ({ to: `/runs/${id}`, label: `run #${id}` })),
    ...a.alerts.map((id: number) => ({ to: `/alerts`, label: `alert #${id}` })),
    ...a.recommendations.map((id: number) => ({ to: `/recommendations?id=${id}`, label: `recommendation #${id}` })),
    ...a.actions.map((id: number) => ({ to: `/actions?id=${id}`, label: `action #${id}` })),
    ...a.resources.map((id: string) => ({ to: `/inventory?tab=ec2&id=${encodeURIComponent(id)}`, label: id })),
    ...a.pools.map((name: string) => ({ to: `/inventory?tab=ec2`, label: `group ${name}` })),
  ];
  const extra = [a.controls.length ? `${a.controls.length} control${a.controls.length === 1 ? "" : "s"}: ${a.controls.slice(0, 4).join(", ")}${a.controls.length > 4 ? ", …" : ""}` : null, a.day ? `day ${a.day}` : null, a.thread_id ? `thread #${a.thread_id}` : null].filter(Boolean);
  if (!links.length && !extra.length) return <span className="text-zinc-500">—</span>;
  return <span className="space-x-2">{links.map((l) => <Link key={l.label} to={l.to} className="text-sky-300 hover:underline">{l.label}</Link>)}{extra.map((t) => <span key={t} className="text-zinc-400">{t}</span>)}</span>;
}

function RunDetail({ row, onClose }: { row: any; onClose: () => void }) {
  const [full, setFull] = useState<any>(null);
  const [err, setErr] = useState("");
  useEffect(() => { setFull(null); api(`/agent-runs/${encodeURIComponent(row.request_id)}`).then(setFull).catch((e) => setErr(e.message)); }, [row.request_id]);
  const grade = parsed(full?.grade);
  const result = parsed(full?.result);
  return (
    <DetailCell id={row.request_id} onClose={onClose} title={<span>{row.name}</span>}>
      <div className="space-y-3 text-xs">
        <div className="grid grid-cols-2 gap-x-6 gap-y-1 text-zinc-400 md:grid-cols-3">
          <div>request <span className="font-mono text-zinc-300">{row.request_id}</span></div>
          <div>session <span className="font-mono text-zinc-300">{row.session_id || "—"}</span></div>
          <div>agent <span className="text-zinc-300">{row.agent_name || "—"}</span>{row.model ? <> · <span className="text-zinc-300">{row.model}</span></> : null}</div>
          <div>sent {when(row.created_at)}</div>
          <div>answered {when(row.finished_at)} ({secs(row.took_s)})</div>
          <div>about <AboutLinks a={row.about} /></div>
          {row.produced > 0 && <div>imported {row.produced} recommendation{row.produced === 1 ? "" : "s"}</div>}
          {row.retry_of && <div>retry of <span className="font-mono text-zinc-300">{row.retry_of}</span></div>}
          {row.retried_by && <div>retried as <span className="font-mono text-zinc-300">{row.retried_by}</span></div>}
          {row.continues && <div>follows <span className="font-mono text-zinc-300">{row.continues}</span> in the session</div>}
        </div>
        {err && <div className="text-red-300">{err}</div>}
        {row.error && <div className="text-red-300">{row.error}</div>}
        {grade?.checks?.length ? (
          <div>
            <div className="mb-1 uppercase tracking-wide text-zinc-500">Rubric {Math.round(Number(grade.score) * 100)} %</div>
            <ul className="space-y-0.5">{grade.checks.map((c: any, i: number) => <li key={i} className={c.pass ? "text-zinc-400" : "text-amber-300"}>{c.pass ? "✓" : "✗"} {c.check}{c.detail ? `: ${c.detail}` : ""}</li>)}</ul>
          </div>
        ) : null}
        {!full && !err ? <div className="text-zinc-500">Loading…</div> : full && (
          <>
            <div><div className="mb-1 uppercase tracking-wide text-zinc-500">Answer</div>{result != null ? <Code>{pretty(result?.content ?? result)}</Code> : <div className="text-zinc-500">{full.status === "pending" ? "Waiting for the agent." : "No answer."}</div>}</div>
            {full.prompt && <div><div className="mb-1 uppercase tracking-wide text-zinc-500">Prompt ({String(full.prompt).length.toLocaleString()} characters)</div><Code>{full.prompt}</Code></div>}
          </>
        )}
      </div>
    </DetailCell>
  );
}

/** Every request the advisor sent to repo2graph's agent: the review of each run, the morning observation, investigations, chat turns. */
export default function Agent() {
  const [params, setParams] = useSearchParams();
  const kind = params.get("kind") || "", status = params.get("status") || "", page = Number(params.get("page") || 1);
  const [open, setOpen] = useState<string | null>(params.get("id"));
  const [d, setD] = useState<any>(null);
  const [err, setErr] = useState("");
  const set = (patch: Record<string, string | null>) => { const p = new URLSearchParams(params); for (const [k, v] of Object.entries(patch)) { if (v) p.set(k, v); else p.delete(k); } setParams(p, { replace: true }); };
  useEffect(() => {
    let alive = true;
    const load = () => api(`/agent-runs?${new URLSearchParams({ ...(kind ? { kind } : {}), ...(status ? { status } : {}), page: String(page) })}`).then((x) => { if (alive) { setD(x); setErr(""); } }).catch((e) => alive && setErr(e.message));
    load();
    const t = setInterval(load, 10_000);
    return () => { alive = false; clearInterval(t); };
  }, [kind, status, page]);
  const chip = (active: boolean, label: string, onClick: () => void) => (
    <button onClick={onClick} className={`rounded border px-2 py-0.5 text-xs ${active ? "border-zinc-500 bg-zinc-800 text-zinc-100" : "border-zinc-800 text-zinc-400 hover:bg-zinc-900"}`}>{label}</button>
  );
  const allKinds = d ? Object.values(d.kinds as Record<string, number>).reduce((s, n) => s + n, 0) : 0;
  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-semibold text-zinc-100">Agent</h1>
        <div className="text-sm text-zinc-500">Every request sent to the repo2graph agent, newest first: what it was about, how it scored and what it answered. The same entries are in the graph as AdvisorAgentRun nodes.</div>
      </div>
      {err && <div className="text-sm text-red-300">{err}</div>}
      {d && (
        <div className="space-y-2">
          <div className="flex flex-wrap gap-1.5">
            {chip(!kind, `All ${allKinds}`, () => set({ kind: null, page: null }))}
            {Object.entries(d.kinds as Record<string, number>).sort((a, b) => b[1] - a[1]).map(([k, n]) => <Fragment key={k}>{chip(kind === k, `${KIND_LABEL[k] || k} ${n}`, () => set({ kind: k, page: null }))}</Fragment>)}
          </div>
          <div className="flex flex-wrap gap-1.5">
            {chip(!status, "Any status", () => set({ status: null, page: null }))}
            {Object.entries(d.statuses as Record<string, number>).map(([k, n]) => <Fragment key={k}>{chip(status === k, `${k} ${n}`, () => set({ status: k, page: null }))}</Fragment>)}
          </div>
        </div>
      )}
      {!d ? <Empty>Loading…</Empty> : d.rows.length === 0 ? <Empty>No agent requests{kind || status ? " match these filters" : " yet"}.</Empty> : (
        <>
          <table className="w-full table-fixed border-collapse overflow-hidden rounded-lg border border-zinc-800">
            <thead className="bg-zinc-900"><tr><Th className="w-40">Sent</Th><Th className="w-72">Request</Th><Th className="w-28">Status</Th><Th className="w-16 text-right">Score</Th><Th className="w-20 text-right">Took</Th><Th>Answer</Th></tr></thead>
            <tbody>
              {d.rows.map((r: any) => (
                <Fragment key={r.request_id}>
                  <tr className="cursor-pointer border-t border-zinc-800 hover:bg-zinc-900/60" onClick={() => { const next = open === r.request_id ? null : r.request_id; setOpen(next); set({ id: next }); }}>
                    <Td className="text-zinc-400">{when(r.created_at)}</Td>
                    <Td><div className="truncate text-zinc-100" title={r.name}>{r.name}</div><div className="truncate text-[11px] text-zinc-500">{r.agent_name || r.kind}{r.retry_of ? " · retry" : ""}</div></Td>
                    <Td><Badge>{r.status}</Badge></Td>
                    <Td className="text-right">{r.score == null ? "—" : `${Math.round(r.score * 100)} %`}</Td>
                    <Td className="text-right text-zinc-400">{secs(r.took_s)}</Td>
                    <Td><div className={`truncate ${r.error ? "text-red-300" : "text-zinc-400"}`} title={r.error || r.answer || ""}>{r.error || r.answer || "—"}</div></Td>
                  </tr>
                  {open === r.request_id && <tr className="border-t border-zinc-800 bg-zinc-950/40"><td colSpan={6} className="max-w-0 p-3"><RunDetail row={r} onClose={() => { setOpen(null); set({ id: null }); }} /></td></tr>}
                </Fragment>
              ))}
            </tbody>
          </table>
          <Pager page={d.page} pageSize={d.page_size} total={d.total} onPage={(p) => set({ page: String(p) })} />
        </>
      )}
    </div>
  );
}

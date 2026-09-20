import { Fragment, useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Info } from "lucide-react";
import { api } from "../api";
import { Badge, Card, Empty, Pager, Td, Th } from "../components/ui";
import { EffortBadge, Playbook, PlaybookPanel } from "../components/playbook";

const PAGE_SIZE = 50;

export default function Findings() {
  const [params, setParams] = useSearchParams();
  const [data, setData] = useState<any>(null);
  const [playbooks, setPlaybooks] = useState<{ run_id: number | null; count: number; playbooks: Playbook[] } | null>(null);
  const [q, setQ] = useState(params.get("q") || "");
  const control = params.get("control_id") || "";
  const runId = params.get("run_id") || "";
  const page = Math.max(1, Number(params.get("page")) || 1);
  // The control whose playbook is open in the side panel ("How to act").
  const howto = params.get("howto") || "";
  // The row that opened the panel ("f:<finding id>", "p:<control id>" or "" for the filter bar /
  // a deep link): the panel expands full width right under that row, where the eye already is.
  const [openRow, setOpenRow] = useState("");

  useEffect(() => {
    const qs = new URLSearchParams();
    if (runId) qs.set("run_id", runId);
    if (control) qs.set("control_id", control);
    if (params.get("q")) qs.set("q", params.get("q")!);
    qs.set("page", String(page));
    qs.set("page_size", String(PAGE_SIZE));
    api(`/findings?${qs}`).then(setData).catch(() => setData({ findings: [], controls: [], total: 0, page: 1, page_size: PAGE_SIZE }));
  }, [runId, control, params.get("q"), page]);
  useEffect(() => { api(`/playbooks${runId ? `?run_id=${runId}` : ""}`).then(setPlaybooks).catch(() => setPlaybooks(null)); }, [runId]);

  // A filter change starts again from page 1; only "page" and "howto" keep the rest.
  const set = (k: string, v: string) => { const p = new URLSearchParams(params); v ? p.set(k, v) : p.delete(k); if (k !== "page" && k !== "howto") p.delete("page"); setParams(p); };
  const toggleHowto = (id: string, row = "") => {
    const close = howto === id && openRow === row;
    setOpenRow(close ? "" : row);
    set("howto", close ? "" : id);
  };
  const closeHowto = () => { setOpenRow(""); set("howto", ""); };
  const panel = (row: string) => howto && openRow === row ? <PlaybookPanel controlId={howto} findings={countFor(howto)} onClose={closeHowto} /> : null;
  const controls: any[] = data?.controls ?? [];
  const countFor = (id: string) => controls.filter((c) => c.control_id === id).reduce((s, c) => s + c.n, 0);
  const playbookOf = (id: string) => controls.find((c) => c.control_id === id)?.playbook ?? null;
  const HowTo = ({ id, row = "", label }: { id: string; row?: string; label?: string }) => (
    <button type="button" title="How to act on this control" onClick={() => toggleHowto(id, row)} className={`inline-flex items-center gap-1 text-xs ${howto === id && openRow === row ? "text-zinc-100" : "text-zinc-500 hover:text-zinc-200"}`}>
      <Info size={13} />{label}
    </button>
  );

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold text-zinc-100">Findings {data?.run_id && <span className="text-sm font-normal text-zinc-500">run #{data.run_id} · {data.total} unique</span>}</h1>
      <div className="flex flex-wrap items-center gap-2">
        <select value={control} onChange={(e) => set("control_id", e.target.value)}>
          <option value="">All controls</option>
          {controls.map((c: any) => <option key={c.control_id + c.status} value={c.control_id}>{c.control_title || c.control_id} ({c.n}){c.playbook ? ` · ${c.playbook.tier}, effort ${c.playbook.effort}` : ""}</option>)}
        </select>
        {control && <HowTo id={control} label="How to act" />}
        <form onSubmit={(e) => { e.preventDefault(); set("q", q); }}><input placeholder="search resource or reason" value={q} onChange={(e) => setQ(e.target.value)} className="w-72" /></form>
      </div>
      {panel("")}
      <div>
        <div className="min-w-0 space-y-3">
          {!data ? <Empty>Loading…</Empty> : data.findings.length === 0 ? <Empty>No findings match.</Empty> : (
            <>
              <table className="w-full border-collapse overflow-hidden rounded-lg border border-zinc-800">
                <thead className="bg-zinc-900"><tr><Th>Status</Th><Th>Control</Th><Th>Resource</Th><Th>Reason</Th><Th>Region</Th></tr></thead>
                <tbody>
                  {data.findings.map((f: any) => {
                    const pb = playbookOf(f.control_id);
                    const row = `f:${f.id}`;
                    const open = howto === f.control_id && openRow === row;
                    return (
                      <Fragment key={f.id}>
                      <tr className={`border-t border-zinc-800 hover:bg-zinc-900/60 ${open ? "bg-zinc-900/40" : ""}`}>
                        <Td><Badge>{f.status}</Badge></Td>
                        <Td className="max-w-56">
                          <button type="button" className="block max-w-full truncate text-left hover:underline" title={`${f.control_id}\nclick: how to act`} onClick={() => toggleHowto(f.control_id, row)}>{f.control_title || f.control_id}</button>
                          <div className="flex items-center gap-2 text-xs text-zinc-500">{f.source}{f.benchmark ? ` · ${f.benchmark}` : ""}{pb && <HowTo id={f.control_id} row={row} label={`${pb.tier} · ${pb.effort}`} />}</div>
                        </Td>
                        <Td className="max-w-72 break-all font-mono text-xs">{f.resource}</Td>
                        <Td>{f.reason}</Td>
                        <Td className="text-zinc-500">{f.region || "—"}</Td>
                      </tr>
                      {open && <tr className="border-t border-zinc-800 bg-zinc-950/40"><td colSpan={5} className="p-3">{panel(row)}</td></tr>}
                      </Fragment>
                    );
                  })}
                </tbody>
              </table>
              <Pager page={data.page} pageSize={data.page_size} total={data.total} onPage={(p) => set("page", String(p))} />
            </>
          )}
        </div>
      </div>

      <div id="playbooks" />
      <Card title={<span>Playbooks {playbooks && <span className="font-normal text-zinc-500">· {playbooks.count} controls, counts from run #{playbooks.run_id ?? "—"}</span>}</span>}>
        {!playbooks ? <div className="text-sm text-zinc-500">Loading…</div> : (
          <table className="w-full border-collapse">
            <thead><tr><Th>Playbook</Th><Th>Tier</Th><Th>Effort</Th><Th className="text-right">Findings</Th></tr></thead>
            <tbody>
              {playbooks.playbooks.map((p) => {
                const row = `p:${p.control_id}`;
                const open = howto === p.control_id && openRow === row;
                return (
                  <Fragment key={p.control_id}>
                  <tr className={`border-t border-zinc-800 hover:bg-zinc-900/60 ${open ? "bg-zinc-900/40" : ""}`}>
                    <Td>
                      <button type="button" className="text-left hover:underline" onClick={() => toggleHowto(p.control_id, row)}>{p.title}</button>
                      <div className="font-mono text-[11px] text-zinc-600">{p.control_id}</div>
                    </Td>
                    <Td><Badge>{p.tier}</Badge></Td>
                    <Td><EffortBadge effort={p.effort} /></Td>
                    <Td className="text-right">{p.findings ? <button type="button" className="underline" onClick={() => set("control_id", p.control_id)}>{p.findings}</button> : <span className="text-zinc-600">0</span>}</Td>
                  </tr>
                  {open && <tr className="border-t border-zinc-800 bg-zinc-950/40"><td colSpan={4} className="p-3">{panel(row)}</td></tr>}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}

import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, usd, when } from "../api";
import { Badge, Button, Card, Empty, Pager, Td, Th } from "../components/ui";
import { RoleLine } from "../components/jev";
import { pct } from "../components/incident";
import { EffortBadge, PlaybookBody, Prose, usePlaybook } from "../components/playbook";

const STATUSES = ["open", "approved", "rejected", "snoozed", "resolved", "done", "all"];
const PAGE_SIZE = 50;
type Scope = "internal" | "generic";

export default function Recommendations() {
  const [params, setParams] = useSearchParams();
  const status = params.get("status") || "open";
  const q = params.get("q") || "";
  const page = Math.max(1, Number(params.get("page")) || 1);
  const selectedId = params.get("id");
  const [data, setData] = useState<{ total: number; page: number; page_size: number; total_saving: number; recommendations: any[] } | null>(null);
  const [sel, setSel] = useState<any>(null);
  const [reason, setReason] = useState("");
  const [scope, setScope] = useState<Scope>("internal");
  const [scopeTouched, setScopeTouched] = useState(false);
  const [suggestion, setSuggestion] = useState<{ scope: Scope; confidence: number } | null>(null);
  const [err, setErr] = useState("");
  const [probe, setProbe] = useState<{ busy: boolean; result: any; error: string }>({ busy: false, result: null, error: "" });
  // Tailored resolution (src/resolve.ts): the latest one for the selected recommendation, polled while pending.
  const [resolution, setResolution] = useState<any>(null);
  const [resolving, setResolving] = useState(false);
  const rows = data?.recommendations ?? [];

  const load = () => api(`/recommendations?status=${status}&q=${encodeURIComponent(q)}&page=${page}&page_size=${PAGE_SIZE}`).then(setData).catch((e) => setErr(e.message));
  useEffect(() => { const t = setTimeout(load, q ? 250 : 0); return () => clearTimeout(t); }, [status, q, page]);
  useEffect(() => { if (selectedId) api(`/recommendations/${selectedId}`).then(setSel).catch(() => setSel(null)); else setSel(null); }, [selectedId]);
  const loadResolution = (id: number) => api(`/recommendations/${id}/resolution`).then(setResolution).catch(() => setResolution(null));
  useEffect(() => { setResolution(null); if (sel?.id) loadResolution(sel.id); }, [sel?.id]);
  useEffect(() => {
    if (resolution?.status !== "pending" || !sel?.id) return;
    const t = setInterval(() => {
      // The webhook completes it; the poll is the fallback when the webhook is missed.
      if (resolution.request_id) api(`/agent-runs/${resolution.request_id}/poll`, { method: "POST" }).catch(() => {});
      loadResolution(sel.id);
    }, 10_000);
    return () => clearInterval(t);
  }, [resolution?.status, resolution?.request_id, sel?.id]);
  const resolve = async () => {
    if (!sel) return;
    setResolving(true); setErr("");
    try { const r = await api(`/recommendations/${sel.id}/resolve`, { method: "POST", body: JSON.stringify({}) }); setResolution(r.resolution); }
    catch (e: any) { setErr(e.message); loadResolution(sel.id); }
    finally { setResolving(false); }
  };
  // The playbook behind the recommendation: the graviton rule names it in evidence.playbook; other rules map through the server.
  const evidenceObj = (() => { try { return JSON.parse(sel?.evidence || "{}"); } catch { return {}; } })();
  const playbookId: string | null = evidenceObj.playbook || resolution?.context?.control_id || null;
  const playbook = usePlaybook(playbookId);
  // Idle-instance recommendations can be probed over SSM; show the latest probe if there is one.
  useEffect(() => {
    setProbe({ busy: false, result: null, error: "" });
    setReason(""); setScope("internal"); setScopeTouched(false); setSuggestion(null);
    if (sel?.rule === "idle_instance" && sel.resource) api(`/instances/${sel.resource}/metrics?limit=1`).then((rows) => { if (rows[0]) setProbe((p) => ({ ...p, result: rows[0] })); }).catch(() => {});
  }, [sel?.id]);
  // Jev's scope suggestion for the reason being typed, 600 ms after typing stops; pre-selects the scope unless the user picked one.
  useEffect(() => {
    if (!sel || !reason.trim()) { setSuggestion(null); return; }
    const id = sel.id;
    const t = setTimeout(() => {
      api(`/recommendations/${id}/scope-suggestion?reason=${encodeURIComponent(reason.trim())}`)
        .then((r) => { if (id !== sel.id) return; setSuggestion(r.suggestion || null); if (r.suggestion && !scopeTouched) setScope(r.suggestion.scope); })
        .catch(() => setSuggestion(null));
    }, 600);
    return () => clearTimeout(t);
  }, [reason, sel?.id]);

  const runProbe = async () => {
    if (!sel) return;
    setProbe({ busy: true, result: probe.result, error: "" });
    try { const r = await api(`/instances/${sel.resource}/probe`, { method: "POST" }); setProbe({ busy: false, result: r, error: "" }); }
    catch (e: any) { setProbe((p) => ({ busy: false, result: p.result, error: e.message })); }
  };

  // The list entry the selected row belongs to: itself, or the primary it was merged into.
  const entry = sel ? rows.find((r) => r.id === sel.id || (r.merged_ids || []).includes(sel.id)) : undefined;
  const mergedIds: number[] = entry?.merged_ids?.length > 1 ? entry.merged_ids : [];

  const decide = async (s: string) => {
    if (!sel) return;
    setErr("");
    try {
      if (mergedIds.length) {
        // One decision for every row merged into this entry (same resource and action, several proposers).
        const r = await api("/recommendations/decision-batch", { method: "POST", body: JSON.stringify({ ids: mergedIds, status: s, reason, scope }) });
        setSel(r.recommendations.find((x: any) => x.id === sel.id) || r.recommendations[0]);
      } else {
        setSel(await api(`/recommendations/${sel.id}/decision`, { method: "POST", body: JSON.stringify({ status: s, reason, scope }) }));
      }
      setReason(""); load();
    } catch (e: any) { setErr(e.message); }
  };
  const open = (id: number) => { const p = new URLSearchParams(params); p.set("id", String(id)); setParams(p); };
  const setParam = (k: string, v: string) => { const p = new URLSearchParams(params); v ? p.set(k, v) : p.delete(k); if (k !== "page") p.delete("page"); if (k === "status") p.delete("id"); setParams(p); };

  // A fix proposed by an alert investigation carries the incident and alert ids in its evidence.
  const origin = (() => { try { const e = JSON.parse(sel?.evidence || "{}"); return e.incident_id ? { incident_id: e.incident_id, alert_id: e.alert_id } : null; } catch { return null; } })();
  // Jev's tier check on agent recommendations lands in evidence.jev (see src/tiercheck.ts).
  const tierCheck = (() => { try { return JSON.parse(sel?.evidence || "{}").jev || null; } catch { return null; } })();
  const otherSources = (r: any) => (r.sources || []).filter((s: string) => s !== r.source);
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h1 className="text-xl font-semibold text-zinc-100">Recommendations <span className="text-sm font-normal text-zinc-500">{data ? <>{data.total} · ≈ {usd(data.total_saving)} / month</> : "…"}</span></h1>
        <div className="flex gap-2">
          <input placeholder="search title or resource" value={q} onChange={(e) => setParam("q", e.target.value)} className="w-56" />
          <select value={status} onChange={(e) => setParam("status", e.target.value)}>
            {STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>
      </div>
      {err && <div className="text-sm text-red-300">{err}</div>}
      <div className={`grid gap-4 ${sel ? "lg:grid-cols-[1fr_28rem]" : ""}`}>
        <div className="space-y-3 self-start">
          {!data ? <Empty>Loading…</Empty> : rows.length === 0 ? <Empty>Nothing here.</Empty> : (
            <table className="w-full border-collapse overflow-hidden rounded-lg border border-zinc-800">
              <thead className="bg-zinc-900"><tr><Th>Recommendation</Th><Th>Tier</Th><Th>Source</Th><Th className="text-right">Saving / mo</Th><Th className="text-right">Conf.</Th></tr></thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.id} onClick={() => open(r.id)} className={`cursor-pointer border-t border-zinc-800 hover:bg-zinc-900/60 ${entry?.id === r.id ? "bg-zinc-900" : ""}`}>
                    <Td>
                      <div>{r.title}</div>
                      <div className="text-xs text-zinc-500">{r.action_type} · {r.resource}</div>
                      {r.merged?.length > 0 && <div className="text-xs text-violet-300">also proposed by {otherSources(r).length ? otherSources(r).join(", ") : r.source} ({r.merged.length} more)</div>}
                    </Td>
                    <Td><Badge>{r.tier}</Badge></Td><Td><Badge>{r.source}</Badge></Td>
                    <Td className="text-right font-medium text-zinc-100">{usd(r.est_monthly_saving)}</Td>
                    <Td className="text-right text-zinc-400">{r.confidence != null ? Math.round(r.confidence * 100) + "%" : "—"}</Td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {data && <Pager page={data.page} pageSize={data.page_size} total={data.total} onPage={(p) => setParam("page", String(p))} />}
        </div>
        {sel && (
          <Card className="sticky top-4 self-start max-h-[calc(100vh-2rem)] overflow-y-auto" title={<span className="flex items-center justify-between">Detail <button className="text-zinc-500" onClick={() => { const p = new URLSearchParams(params); p.delete("id"); setParams(p); }}>close</button></span>}>
            <h2 className="text-base font-medium text-zinc-100">{sel.title}</h2>
            <div className="mt-1 flex flex-wrap gap-2 text-xs"><Badge>{sel.status}</Badge><Badge>{sel.tier}</Badge><Badge>{sel.source}</Badge><span className="text-zinc-500">{sel.action_type}</span></div>
            <dl className="mt-3 grid grid-cols-2 gap-x-4 gap-y-1 text-sm">
              <dt className="text-zinc-500">Estimated saving</dt><dd>{usd(sel.est_monthly_saving)} / month</dd>
              <dt className="text-zinc-500">Confidence</dt><dd>{sel.confidence != null ? Math.round(sel.confidence * 100) + "%" : "—"}</dd>
              <dt className="text-zinc-500">Resource</dt><dd className="break-all font-mono text-xs">{sel.resource}</dd>
              <dt className="text-zinc-500">Last seen in run</dt><dd>#{sel.run_id} · {when(sel.updated_at)}</dd>
              {sel.decided_at && <><dt className="text-zinc-500">Decision</dt><dd>{sel.status} by {sel.decided_by} at {when(sel.decided_at)}{sel.decision_scope && <span className="text-zinc-400"> · {sel.decision_scope === "generic" ? "generic: all resources of this kind" : "internal: this resource only"}</span>}{sel.decision_reason && <div className="text-zinc-400">“{sel.decision_reason}”</div>}</dd></>}
              {origin && <><dt className="text-zinc-500">Origin</dt><dd><Link className="underline" to={`/alerts?status=all&id=${origin.alert_id}`}>incident #{origin.incident_id} on alert #{origin.alert_id}</Link></dd></>}
              {(sel.resource_role || /^(idle_instance|stopped_instance_ebs)$/.test(sel.rule)) && <><dt className="text-zinc-500">Role (Jev)</dt><dd className="text-xs"><RoleLine role={sel.resource_role} /></dd></>}
              {tierCheck && <><dt className="text-zinc-500">Tier check (Jev)</dt><dd className="text-xs">irreversible <span className="text-zinc-200">{pct(tierCheck.irreversible)}</span> · service impact <span className="text-zinc-200">{tierCheck.service_impact_label}</span> ({Number(tierCheck.service_impact).toFixed(1)}){tierCheck.tier_before !== tierCheck.tier_after ? <span className="text-amber-300"> · tightened {tierCheck.tier_before} → {tierCheck.tier_after}</span> : <span className="text-zinc-500"> · tier {tierCheck.tier_after} kept</span>}</dd></>}
              {mergedIds.length > 0 && entry && <>
                <dt className="text-zinc-500">Merged with</dt>
                <dd className="text-xs">
                  <div className="text-zinc-400">same action on the same resource; a decision applies to all {mergedIds.length}</div>
                  <ul className="mt-0.5 space-y-0.5">
                    {[entry, ...entry.merged].filter((m: any) => m.id !== sel.id).map((m: any) => (
                      <li key={m.id}><button className="underline" onClick={() => open(m.id)}>#{m.id}</button> <Badge>{m.source}</Badge> <span className="text-zinc-500">{m.rule}</span> · {usd(m.est_monthly_saving)}{m.confidence != null ? ` · ${Math.round(m.confidence * 100)}%` : ""}</li>
                    ))}
                  </ul>
                </dd>
              </>}
            </dl>
            <p className="mt-3 text-sm text-zinc-300">{sel.rationale}</p>
            {sel.rule === "idle_instance" && (
              <div className="mt-3 rounded border border-zinc-800 bg-zinc-950/60 p-2 text-xs">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-zinc-400">SSM probe{probe.result ? ` · ${when(probe.result.collected_at)}` : ""}</span>
                  <Button variant="ghost" className="!px-2 !py-1 !text-xs" onClick={runProbe} disabled={probe.busy}>{probe.busy ? "Probing…" : probe.result ? "Probe again" : "Probe"}</Button>
                </div>
                {probe.error && <div className="mt-1 text-red-300">{probe.error}</div>}
                {probe.result?.summary && (
                  <div className="mt-1 space-y-0.5 text-zinc-300">
                    <div>Memory {probe.result.summary.memory_used_pct}% used ({probe.result.summary.memory_used_gb} of {probe.result.summary.memory_total_gb} GB) · load {probe.result.summary.load_1m} on {probe.result.summary.cpus} vCPU</div>
                    {probe.result.data?.disks?.length > 0 && <div>Disks: {probe.result.data.disks.map((d: any) => `${d.mount} ${d.used_pct}%`).join(", ")}</div>}
                    {probe.result.data?.top_cpu?.length > 0 && <div>Top CPU: {probe.result.data.top_cpu.slice(0, 3).map((p: any) => `${p.command} ${p.cpu_pct}%`).join(", ")}</div>}
                    {probe.result.data?.top_mem?.length > 0 && <div>Top memory: {probe.result.data.top_mem.slice(0, 3).map((p: any) => `${p.command} ${Math.round(p.rss_bytes / 1048576)} MB`).join(", ")}</div>}
                  </div>
                )}
                {!probe.result && !probe.error && <div className="mt-1 text-zinc-500">Runs a fixed read-only script through SSM Run Command (memory, disks, load, top processes). Needs an SSM-managed instance and ssm:SendCommand permission.</div>}
              </div>
            )}
            <div className="mt-4 rounded border border-zinc-800 bg-zinc-950/60 p-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-sm font-medium text-zinc-200">Tailored resolution</span>
                <div className="flex items-center gap-2">
                  {resolution && <Badge>{resolution.status === "not_applicable" ? "blocked" : resolution.status === "completed" ? "done" : resolution.status === "pending" ? "running" : resolution.status}</Badge>}
                  <Button variant="ghost" className="!px-2 !py-1 !text-xs" onClick={resolve} disabled={resolving || resolution?.status === "pending"}>{resolving ? "Starting…" : resolution?.status === "pending" ? "Resolving…" : resolution ? "Resolve again" : "Resolve"}</Button>
                </div>
              </div>
              {!resolution && <div className="mt-1 text-xs text-zinc-500">Assembles this resource's facts, the team's decisions in the graph and its history, asks Jev whether the playbook applies, then has the agent write a plan for this resource with real ids and commands.</div>}
              {resolution?.gate && (
                <div className="mt-2 text-xs text-zinc-400">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-zinc-500">Jev gate</span>
                    {resolution.gate.outcome && <span className={`inline-block rounded border px-1.5 py-0.5 text-[11px] font-medium ${resolution.gate.outcome === "blocked" ? "border-amber-500/30 bg-amber-500/15 text-amber-300" : resolution.gate.outcome === "applies" ? "border-emerald-500/30 bg-emerald-500/15 text-emerald-300" : "border-zinc-500/30 bg-zinc-500/15 text-zinc-300"}`}>{resolution.gate.outcome}</span>}
                    <span className={resolution.gate.outcome === "blocked" ? "text-amber-300" : "text-zinc-300"}>{resolution.gate.reason}</span>
                  </div>
                  {resolution.gate.enabled !== false && resolution.gate.applies != null && (
                    <div className="mt-0.5 text-zinc-500">applies {pct(resolution.gate.applies)} · blocker {String(resolution.gate.blocker).replace(/_/g, " ")} ({pct(resolution.gate.blocker_confidence)}) · effort {resolution.gate.effort_label}{resolution.gate.concepts != null && <> · {resolution.gate.concepts} concept{resolution.gate.concepts === 1 ? "" : "s"} in the context pack</>}</div>
                  )}
                </div>
              )}
              {resolution?.status === "not_applicable" && <div className="mt-2 text-xs text-amber-300">Closed at the gate: no agent call was made; the static playbook below still describes the generic path.</div>}
              {resolution?.status === "failed" && <div className="mt-2 text-xs text-red-300">{resolution.error}</div>}
              {resolution?.status === "pending" && <div className="mt-2 text-xs text-zinc-500">The agent is verifying the facts and writing the plan (request {resolution.request_id}); this panel refreshes every 10 s.</div>}
              {resolution?.plan && (
                <div className="mt-3 space-y-3 text-sm text-zinc-300">
                  <div className="flex flex-wrap items-center gap-2 text-xs"><Badge>{resolution.plan.risk}</Badge>{!resolution.plan.applies && <span className="text-amber-300">the agent says the playbook does not apply</span>}{resolution.plan.est_monthly_saving != null && <span className="text-zinc-400">≈ {usd(resolution.plan.est_monthly_saving)} / month verified</span>}</div>
                  <p><Prose text={resolution.plan.summary} /></p>
                  {resolution.plan.blockers.length > 0 && <div><div className="text-[11px] uppercase tracking-wide text-red-300">Blockers</div><ul className="list-disc pl-5">{resolution.plan.blockers.map((b: string, i: number) => <li key={i}><Prose text={b} /></li>)}</ul></div>}
                  {resolution.plan.plan.length > 0 && (
                    <div>
                      <div className="text-[11px] uppercase tracking-wide text-zinc-500">Plan</div>
                      <ol className="list-decimal space-y-2 pl-5">
                        {resolution.plan.plan.map((s: any, i: number) => (
                          <li key={i}>
                            <div><Prose text={s.step} /></div>
                            {s.command && <pre className="mt-1 overflow-x-auto whitespace-pre-wrap rounded bg-zinc-950 p-2 font-mono text-[11px] leading-5 text-zinc-200">{s.command}</pre>}
                            {s.verify && <div className="mt-0.5 text-xs text-emerald-300/90">verify: <Prose text={s.verify} /></div>}
                          </li>
                        ))}
                      </ol>
                    </div>
                  )}
                  {resolution.plan.needs_from_human.length > 0 && <div><div className="text-[11px] uppercase tracking-wide text-amber-300">Needs from a human</div><ul className="list-disc pl-5">{resolution.plan.needs_from_human.map((b: string, i: number) => <li key={i}><Prose text={b} /></li>)}</ul></div>}
                  {resolution.plan.concepts_used.length > 0 && (
                    <div className="text-xs text-zinc-400"><span className="text-[11px] uppercase tracking-wide text-zinc-500">Concepts used</span>{" "}
                      {resolution.plan.concepts_used.map((c: any) => <span key={c.id} className="mr-2">{c.graph_url ? <a className="underline" href={c.graph_url} target="_blank" rel="noreferrer">{c.name || c.id}</a> : (c.name || c.id)}{c.scope && <span className="text-zinc-600"> ({c.scope})</span>}</span>)}
                    </div>
                  )}
                </div>
              )}
              {resolution?.context && (resolution.context.concepts?.length > 0 || resolution.context.history?.recommendations?.length > 0) && (
                <details className="mt-2 text-xs"><summary className="cursor-pointer text-zinc-500">Context used ({resolution.context.concepts?.length || 0} concepts, {resolution.context.history?.recommendations?.length || 0} earlier recommendations, {resolution.context.history?.incidents?.length || 0} incidents)</summary>
                  <ul className="mt-1 space-y-0.5 text-zinc-400">
                    {resolution.context.concepts.map((c: any) => <li key={c.id}>{c.graph_url ? <a className="underline" href={c.graph_url} target="_blank" rel="noreferrer">{c.name || c.id}</a> : (c.name || c.id)} <span className="text-zinc-600">({c.scope})</span></li>)}
                    {resolution.context.history.recommendations.map((r: any) => <li key={r.id}>#{r.id} [{r.status}] {r.title}{r.decision_reason ? ` — “${r.decision_reason}”` : ""}</li>)}
                  </ul>
                </details>
              )}
            </div>
            {playbook ? (
              <details className="mt-3 rounded border border-zinc-800 bg-zinc-950/40 p-3 text-sm" open={!resolution?.plan}>
                <summary className="cursor-pointer text-zinc-200">How to do it <span className="text-zinc-500">· playbook: {playbook.title}</span> <Badge>{playbook.tier}</Badge> <EffortBadge effort={playbook.effort} /></summary>
                <div className="mt-2"><PlaybookBody pb={playbook} compact /></div>
                <div className="mt-2 text-xs">
                  <Link className="text-sky-300 hover:underline" to={`/findings?howto=${encodeURIComponent(playbook.control_id)}`}>Open the full playbook and the findings it covers →</Link>
                </div>
              </details>
            ) : (
              <div className="mt-3 text-xs text-zinc-500">No playbook is mapped to this recommendation's action type yet. <Link className="text-sky-300 hover:underline" to="/findings#playbooks">Browse the playbooks →</Link></div>
            )}
            <details className="mt-3 text-xs"><summary className="cursor-pointer text-zinc-500">Evidence</summary><pre className="mt-1 max-h-64 overflow-auto rounded bg-zinc-950 p-2">{JSON.stringify(JSON.parse(sel.evidence || "{}"), null, 2)}</pre></details>
            <div className="mt-4 space-y-2 border-t border-zinc-800 pt-3">
              <input className="w-full" placeholder="reason (required to reject; it teaches the agent)" value={reason} onChange={(e) => setReason(e.target.value)} />
              <div className="text-xs text-zinc-400">
                <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                  <span className="text-zinc-500">This decision applies to</span>
                  <label className="flex items-center gap-1"><input type="radio" name="scope" className="!w-auto" checked={scope === "internal"} onChange={() => { setScope("internal"); setScopeTouched(true); }} /> this resource only (internal)</label>
                  <label className="flex items-center gap-1"><input type="radio" name="scope" className="!w-auto" checked={scope === "generic"} onChange={() => { setScope("generic"); setScopeTouched(true); }} /> all resources of this kind (generic)</label>
                  {suggestion && <span className="text-violet-300">Jev suggests {suggestion.scope} ({suggestion.confidence.toFixed(2)})</span>}
                </div>
                <div className="mt-0.5 text-zinc-500">{scope === "generic" ? "Recorded as reusable knowledge (a role-based rule the agent applies to any account)." : "Recorded as a decision about this one resource in this account."}</div>
              </div>
              <div className="flex flex-wrap gap-2">
                <Button onClick={() => decide("approved")} disabled={sel.status === "approved"}>Approve{mergedIds.length ? ` (${mergedIds.length})` : ""}</Button>
                <Button variant="ghost" onClick={() => decide("rejected")} disabled={!reason}>Reject{mergedIds.length ? ` (${mergedIds.length})` : ""}</Button>
                <Button variant="ghost" onClick={() => decide("snoozed")}>Snooze</Button>
                <Button variant="ghost" onClick={() => decide("done")}>Mark done</Button>
                {sel.status !== "open" && <Button variant="ghost" onClick={() => decide("open")}>Reopen</Button>}
              </div>
            </div>
          </Card>
        )}
      </div>
    </div>
  );
}

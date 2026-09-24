import { Fragment, useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, usd, when } from "../api";
import { Badge, Button, DetailCell, Empty, Pager, Td, Th } from "../components/ui";
import { RoleLine } from "../components/jev";
import { pct } from "../components/incident";
import { EffortBadge, PlaybookBody, Prose, Step, StepChecks, StepOutcome, usePlaybook } from "../components/playbook";
import { RdsLoadPanel } from "../components/rdsLoad";
import { Thread } from "../components/thread";
import { ImpactChart } from "../components/impact";

const STATUSES = ["open", "pending", "approved", "rejected", "snoozed", "resolved", "done", "all"];
const PAGE_SIZE = 50;
type Scope = "internal" | "generic";

/** recommendations.progress (src/progress.ts): the ticked steps of one plan and the day to look again. */
interface Progress { plan: string; total: number; done: number[]; follow_up: string | null; outcomes: StepOutcome[]; updated_at: string }
const parseProgress = (raw: unknown): Progress | null => { try { const p = typeof raw === "string" && raw ? JSON.parse(raw) : null; return p && typeof p.plan === "string" && Array.isArray(p.done) ? { ...p, follow_up: p.follow_up || null, outcomes: Array.isArray(p.outcomes) ? p.outcomes : [] } : null; } catch { return null; } };
const today = () => { const d = new Date(); return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`; };
/** "2 of 6 steps · check again 2026-09-30" for a list row; due once the day has come. */
function progressLine(raw: unknown): { text: string; due: boolean } | null {
  const p = parseProgress(raw);
  if (!p) return null;
  const parts: string[] = [];
  if (p.total > 0) parts.push(`${p.done.length} of ${p.total} steps`);
  const due = Boolean(p.follow_up && p.follow_up <= today());
  if (p.follow_up) parts.push(due ? `check again: due ${p.follow_up}` : `check again ${p.follow_up}`);
  return parts.length ? { text: parts.join(" · "), due } : null;
}

/** One affected resource: a link into its Inventory tab in a new tab when there is one, the bare id otherwise. */
function ResourceLink({ r }: { r: { id: string; name: string | null; kind: string; tab: string | null; found: boolean } }) {
  const label = <><span className="font-mono">{r.id}</span>{r.name && r.name !== r.id ? <span className="text-zinc-400"> {r.name}</span> : null}</>;
  return (
    <span className="break-all">
      {r.tab && r.found ? <a className="text-sky-300 hover:underline" href={`/inventory?tab=${r.tab}&id=${encodeURIComponent(r.id)}`} target="_blank" rel="noreferrer" title="Open in the inventory (new tab)">{label} ↗</a> : label}
      <span className="text-zinc-600"> · {r.kind}{!r.found && r.kind !== "other" ? ", not in the inventory" : ""}</span>
    </span>
  );
}

export default function Recommendations() {
  const [params, setParams] = useSearchParams();
  const status = params.get("status") || "open";
  const q = params.get("q") || "";
  const page = Math.max(1, Number(params.get("page")) || 1);
  const selectedId = params.get("id");
  const [data, setData] = useState<{ total: number; page: number; page_size: number; total_saving: number; total_saving_distinct?: number; overlap_usd?: number; recommendations: any[] } | null>(null);
  const [sel, setSel] = useState<any>(null);
  const [reason, setReason] = useState("");
  const [scope, setScope] = useState<Scope>("internal");
  const [scopeTouched, setScopeTouched] = useState(false);
  const [suggestion, setSuggestion] = useState<{ scope: Scope; confidence: number } | null>(null);
  const [err, setErr] = useState("");
  // Whether the Sphinx bot is set up (src/notify.ts); the "Send to Sphinx" button shows only then.
  const [notify, setNotify] = useState<any>(null);
  useEffect(() => { api("/notify/status").then(setNotify).catch(() => setNotify(null)); }, []);
  const [shareResult, setShareResult] = useState<{ id: number; result: string } | null>(null);
  const [sharing, setSharing] = useState(false);
  // Posts the selected recommendation to the Sphinx chat now, whatever the rules say (POST /api/recommendations/:id/notify).
  const share = async () => {
    if (!sel) return;
    setSharing(true); setShareResult(null);
    try { const r = await api(`/recommendations/${sel.id}/notify`, { method: "POST", body: "{}" }); setShareResult({ id: sel.id, result: r.result }); }
    catch (e: any) { setShareResult({ id: sel.id, result: e.message }); }
    finally { setSharing(false); }
  };
  const [probe, setProbe] = useState<{ busy: boolean; result: any; error: string }>({ busy: false, result: null, error: "" });
  // Tailored resolution (src/resolve.ts): the latest one for the selected recommendation, polled while pending.
  const [resolution, setResolution] = useState<any>(null);
  const [verification, setVerification] = useState<any>(null);
  const [resolving, setResolving] = useState(false);
  const [progressBusy, setProgressBusy] = useState(false);
  const [blockerInput, setBlockerInput] = useState("");
  const [linkBusy, setLinkBusy] = useState(false);
  const rows = data?.recommendations ?? [];

  const load = () => api(`/recommendations?status=${status}&q=${encodeURIComponent(q)}&page=${page}&page_size=${PAGE_SIZE}`).then(setData).catch((e) => setErr(e.message));
  useEffect(() => { const t = setTimeout(load, q ? 250 : 0); return () => clearTimeout(t); }, [status, q, page]);
  // The old detail goes away at once, so it never sits under the wrong row while the new one loads.
  useEffect(() => { setSel(null); if (selectedId) api(`/recommendations/${selectedId}`).then(setSel).catch(() => setSel(null)); }, [selectedId]);
  const loadResolution = (id: number) => api(`/recommendations/${id}/resolution`).then(setResolution).catch(() => setResolution(null));
  useEffect(() => { setResolution(null); if (sel?.id) loadResolution(sel.id); }, [sel?.id]);
  useEffect(() => { setVerification(null); if (sel?.id && /^(approved|done)$/.test(sel.status)) api(`/verifications/${sel.id}`).then((d) => setVerification(d.verification)).catch(() => setVerification(null)); }, [sel?.id, sel?.status]);
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
  // Step progress: the checklist follows the tailored plan when there is one, else the playbook's generic steps.
  // The stored progress names the plan it was ticked on, so a new resolution does not inherit ticks from the old one.
  const progress = parseProgress(sel?.progress);
  const planKey = resolution?.plan?.plan?.length ? `resolution:${resolution.id}` : playbook?.steps?.length ? `playbook:${playbook.control_id}` : null;
  const planTotal = resolution?.plan?.plan?.length ? resolution.plan.plan.length : playbook?.steps?.length || 0;
  const onThisPlan = progress?.plan === planKey;
  const doneSet = new Set<number>(onThisPlan ? progress!.done : []);
  const outcomeMap = new Map<number, StepOutcome>((onThisPlan ? progress!.outcomes : []).map((o) => [o.step, o]));
  const saveProgress = async (done: Set<number>, followUp: string | null, outcomes: Map<number, StepOutcome> = outcomeMap) => {
    if (!sel || !planKey) return;
    setProgressBusy(true); setErr("");
    try {
      const r = await api(`/recommendations/${sel.id}/progress`, { method: "POST", body: JSON.stringify({ plan: planKey, total: planTotal, done: [...done], follow_up: followUp, outcomes: [...outcomes.values()] }) });
      setSel((prev: any) => ({ ...prev, ...r })); load();
    } catch (e: any) { setErr(e.message); }
    finally { setProgressBusy(false); }
  };
  // A tick means the step worked; "failed" records the outcome with what was seen. Either replaces the other.
  const checks: StepChecks | undefined = planKey ? {
    done: doneSet, busy: progressBusy, outcomes: outcomeMap,
    toggle: (i) => { const next = new Set(doneSet); const outs = new Map(outcomeMap); if (next.has(i)) { next.delete(i); outs.delete(i); } else { next.add(i); outs.set(i, { step: i, state: "worked", note: "", at: "" }); } saveProgress(next, onThisPlan ? progress!.follow_up : null, outs); },
    setOutcome: (i, state, note) => { const outs = new Map(outcomeMap); const next = new Set(doneSet); if (!state) outs.delete(i); else { outs.set(i, { step: i, state, note, at: "" }); if (state === "failed") next.delete(i); } saveProgress(next, onThisPlan ? progress!.follow_up : null, outs); },
  } : undefined;
  const failedSteps = [...outcomeMap.values()].filter((o) => o.state === "failed").length;
  // A new plan written from what happened to this one (POST /recommendations/:id/replan); the note goes to the agent with the outcomes.
  const [replanNote, setReplanNote] = useState("");
  const [replanning, setReplanning] = useState(false);
  const replan = async () => {
    if (!sel) return;
    setReplanning(true); setErr("");
    try { const r = await api(`/recommendations/${sel.id}/replan`, { method: "POST", body: JSON.stringify({ note: replanNote || null }) }); setResolution(r.resolution); setReplanNote(""); }
    catch (e: any) { setErr(e.message); loadResolution(sel.id); }
    finally { setReplanning(false); }
  };
  const followUp = onThisPlan ? progress!.follow_up : null;
  const reloadSel = () => sel && api(`/recommendations/${sel.id}`).then(setSel).catch(() => {});
  // What this item waits on: another recommendation by id; the server refuses self and loops.
  const setBlockedBy = async (id: number | null) => {
    if (!sel) return;
    setLinkBusy(true); setErr("");
    try { const r = await api(`/recommendations/${sel.id}/blocked-by`, { method: "POST", body: JSON.stringify({ id }) }); setSel((prev: any) => ({ ...prev, ...r })); setBlockerInput(""); load(); }
    catch (e: any) { setErr(e.message); }
    finally { setLinkBusy(false); }
  };
  // A conflicting item is closed as a rejection with the reason on record: the agent learns not to propose both.
  const supersede = async (c: any) => {
    if (!sel) return;
    setLinkBusy(true); setErr("");
    try { await api(`/recommendations/${c.id}/decision`, { method: "POST", body: JSON.stringify({ status: "rejected", reason: `superseded by #${sel.id} (${sel.action_type}): ${sel.title}`, scope: "internal" }) }); await reloadSel(); load(); }
    catch (e: any) { setErr(e.message); }
    finally { setLinkBusy(false); }
  };
  useEffect(() => { setBlockerInput(""); }, [sel?.id]);
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
  const close = () => { const p = new URLSearchParams(params); p.delete("id"); setParams(p); };
  // The detail opens under the row you click; clicking the open row again closes it.
  const toggle = (r: any) => (entry?.id === r.id ? close() : open(r.id));
  const setParam = (k: string, v: string) => { const p = new URLSearchParams(params); v ? p.set(k, v) : p.delete(k); if (k !== "page") p.delete("page"); if (k === "status") p.delete("id"); setParams(p); };

  // A fix proposed by an alert investigation carries the incident and alert ids in its evidence.
  const origin = (() => { try { const e = JSON.parse(sel?.evidence || "{}"); return e.incident_id ? { incident_id: e.incident_id, alert_id: e.alert_id } : null; } catch { return null; } })();
  // Jev's tier check on agent recommendations lands in evidence.jev (see src/tiercheck.ts).
  const tierCheck = (() => { try { return JSON.parse(sel?.evidence || "{}").jev || null; } catch { return null; } })();
  const otherSources = (r: any) => (r.sources || []).filter((s: string) => s !== r.source);
  // A database recommendation (Aurora storage tier, an RDS class change, an RDS fix from an incident) shows the load profile the hourly pass keeps.
  const dbResource = sel && (/aurora|rds/i.test(`${sel.rule} ${sel.action_type}`) || resolution?.context?.resource?.kind === "rds") ? String(sel.resource || "").replace(/^arn:aws:rds:[^:]*:[^:]*:(cluster|db):/, "") : null;

  // The detail: facts and the decision on the left, the tailored resolution and the playbook on the right.
  const detail = sel && (
    <DetailCell id={String(sel.id)} onClose={close} title={<span>Detail <span className="font-mono font-normal text-zinc-400">#{sel.id}</span>{!entry && data ? <span className="font-normal text-zinc-500"> · not in the current list</span> : null}</span>}>
      <div className="grid gap-4 lg:grid-cols-[minmax(0,2fr)_minmax(0,3fr)]">
        <div className="min-w-0">
          <h2 className="text-base font-medium text-zinc-100">{sel.title}</h2>
          <div className="mt-1 flex flex-wrap gap-2 text-xs"><Badge>{sel.status}</Badge><Badge>{sel.tier}</Badge><Badge>{sel.source}</Badge><span className="text-zinc-500">{sel.action_type}</span></div>
          <dl className="mt-3 grid grid-cols-[9.5rem_1fr] gap-x-4 gap-y-1 text-sm">
            <dt className="text-zinc-500">Estimated saving</dt><dd>{usd(sel.est_monthly_saving)} / month</dd>
            <dt className="text-zinc-500">Confidence</dt><dd>{sel.confidence != null ? Math.round(sel.confidence * 100) + "%" : "—"}</dd>
            {/^(approved|done)$/.test(sel.status) && <><dt className="text-zinc-500">Realised</dt><dd className="text-xs">{!verification ? <span className="text-zinc-500">not checked yet; the daily verification starts seven days after the decision</span>
              : verification.verdict === "too_early" ? <span className="text-zinc-500">too early: {verification.note}</span>
              : verification.verdict === "not_verifiable" ? <span className="text-zinc-500">{verification.note}</span>
              : <><span className={verification.verdict === "realised" ? "text-emerald-300" : verification.verdict === "increase" ? "text-red-300" : "text-amber-300"}>{verification.verdict}</span> · {usd(verification.realised_usd_month)} / month{verification.ratio != null ? ` (${Math.round(verification.ratio * 100)} % of the estimate)` : ""} <span className="text-zinc-500">· {verification.note}{verification.scope_note ? ` · measured on ${verification.scope_note}` : ""}</span></>}
              {verification?.applied && <div className="text-zinc-500">inventory: applied {verification.applied}</div>}</dd></>}
            <dt className="text-zinc-500">Affected resources</dt>
            <dd className="text-xs">
              {sel.affected?.resources?.length ? <ul className="space-y-0.5">{sel.affected.resources.map((r: any) => <li key={r.id}><ResourceLink r={r} /></li>)}</ul> : <span className="break-all font-mono">{sel.resource || "—"}</span>}
              {sel.affected?.mentioned?.length > 0 && (
                <div className="mt-1.5">
                  <div className="text-zinc-500">Also named in the title or rationale <span className="text-zinc-600">· includes what the agent ruled out, so read the text</span></div>
                  <ul className="mt-0.5 space-y-0.5">{sel.affected.mentioned.map((r: any) => <li key={r.id}><ResourceLink r={r} /></li>)}</ul>
                </div>
              )}
            </dd>
            <dt className="text-zinc-500">Last seen in run</dt><dd>#{sel.run_id} · {when(sel.updated_at)}</dd>
            {sel.decided_at && <><dt className="text-zinc-500">Decision</dt><dd>{sel.status} by {sel.decided_by} at {when(sel.decided_at)}{sel.decision_scope && <span className="text-zinc-400"> · {sel.decision_scope === "generic" ? "generic: all resources of this kind" : "internal: this resource only"}</span>}{sel.decision_reason && <div className="text-zinc-400">“{sel.decision_reason}”</div>}</dd></>}
            {entry?.system && <><dt className="text-zinc-500">System</dt><dd className="text-xs">{entry.system.members.length} member{entry.system.members.length === 1 ? "" : "s"} of {entry.system.kind.replace("_", " ")} <span className="font-mono">{entry.system.id}</span> <span className="text-zinc-500">· members are managed by their controller; one decision covers all {entry.merged_ids.length}</span></dd></>}
            {sel.conflicts?.length > 0 && <>
              <dt className="text-amber-300">Conflicts with</dt>
              <dd className="text-xs">
                <div className="text-zinc-500">another action on the same resource; both cannot be worth doing</div>
                <ul className="mt-0.5 space-y-0.5">
                  {sel.conflicts.map((c: any) => (
                    <li key={c.id} className="flex flex-wrap items-center gap-2">
                      <button className="underline" onClick={() => open(c.id)}>#{c.id}</button><Badge>{c.status}</Badge><span className="text-zinc-300">{c.action_type}</span><span className="text-zinc-500">on {c.on} · {usd(c.est_monthly_saving)}</span>
                      {/^(open|snoozed|pending)$/.test(c.status) && <button className="text-zinc-400 hover:text-zinc-200" disabled={linkBusy} title={`Reject #${c.id} with the reason "superseded by #${sel.id}"`} onClick={() => supersede(c)}>close as superseded by this one</button>}
                    </li>
                  ))}
                </ul>
              </dd>
            </>}
            <dt className="text-zinc-500">Blocked by</dt>
            <dd className="text-xs">
              {sel.blocker ? (
                <div className="flex flex-wrap items-center gap-2">
                  <button className="underline" onClick={() => open(sel.blocker.id)}>#{sel.blocker.id}</button><Badge>{sel.blocker.status}</Badge>
                  <span className={sel.blocker.done ? "text-emerald-300" : "text-zinc-300"}>{sel.blocker.title}</span>
                  {sel.blocker.done ? <span className="text-emerald-300">· done, this one is unblocked</span> : sel.blocker.follow_up ? <span className="text-zinc-500">· check again {sel.blocker.follow_up}</span> : null}
                  <button className="text-zinc-500 hover:text-zinc-300" disabled={linkBusy} onClick={() => setBlockedBy(null)}>clear</button>
                </div>
              ) : (
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-zinc-500">nothing; waiting on another recommendation?</span>
                  <input className="w-24 !py-0.5 !text-xs" placeholder="#id" value={blockerInput} onChange={(e) => setBlockerInput(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter" && /^#?\d+$/.test(blockerInput.trim())) setBlockedBy(Number(blockerInput.trim().replace("#", ""))); }} />
                  <button className="text-zinc-400 hover:text-zinc-200" disabled={linkBusy || !/^#?\d+$/.test(blockerInput.trim())} onClick={() => setBlockedBy(Number(blockerInput.trim().replace("#", "")))}>link</button>
                </div>
              )}
              {sel.blocks?.length > 0 && <div className="mt-0.5 text-zinc-500">Blocks {sel.blocks.map((b: any, i: number) => <span key={b.id}>{i > 0 ? ", " : ""}<button className="underline" onClick={() => open(b.id)}>#{b.id}</button> ({b.status})</span>)}</div>}
            </dd>
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
          <p className="mt-3 text-sm text-zinc-300"><Prose text={sel.rationale || ""} /></p>
          {/^(approved|done)$/.test(sel.status) && <div className="mt-3"><ImpactChart recId={sel.id} compact /></div>}
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
          {dbResource && <div className="mt-3"><RdsLoadPanel id={dbResource} compact /></div>}
          <details className="mt-3 text-xs"><summary className="cursor-pointer text-zinc-500">Evidence</summary><pre className="mt-1 max-h-64 overflow-auto rounded bg-zinc-950 p-2">{JSON.stringify(JSON.parse(sel.evidence || "{}"), null, 2)}</pre></details>
          {sel.exposure?.resources?.some((r: any) => r.domains.length || r.volumes.length || r.open_alerts.length || r.pool || r.cluster) && (
            <div className={`mt-3 rounded border p-2 text-xs ${sel.exposure.disruptive && sel.exposure.resources.some((r: any) => r.domains.length || r.open_alerts.length) ? "border-amber-500/40 bg-amber-500/5" : "border-zinc-800 bg-zinc-950/60"}`}>
              <div className="mb-1 text-[11px] uppercase tracking-wide text-zinc-400">Before you act</div>
              <ul className="space-y-1.5">
                {sel.exposure.resources.map((r: any) => (
                  <li key={r.id}>
                    <div className="font-mono text-zinc-300">{r.id}{r.name && r.name !== r.id ? <span className="font-sans text-zinc-500"> {r.name}</span> : null}</div>
                    {r.domains.length > 0 && <div className={sel.exposure.disruptive ? "text-amber-300" : "text-zinc-400"}>{r.domains.length} Route 53 record{r.domains.length === 1 ? "" : "s"} still point{r.domains.length === 1 ? "s" : ""} here{sel.exposure.disruptive ? "; a stop, a replacement or a new address breaks them unless they move" : ""}: {r.domains.map((d: any) => <span key={`${d.name}-${d.type}`} className="mr-1.5 font-mono text-[11px]">{d.name} <span className="text-zinc-500">({d.type}{d.hop > 1 ? " via LB" : ""})</span></span>)}</div>}
                    {r.open_alerts.length > 0 && <div className="text-amber-300">{r.open_alerts.length} open alert{r.open_alerts.length === 1 ? "" : "s"}: {r.open_alerts.slice(0, 3).map((a: any) => <Link key={a.id} className="mr-1.5 underline" to={`/alerts?status=all&id=${a.id}`}>{a.kind}</Link>)}</div>}
                    {r.volumes.length > 0 && <div className="text-zinc-400">{r.volumes.length} volume{r.volumes.length === 1 ? "" : "s"} attached ({r.volumes.reduce((s: number, v: any) => s + (Number(v.size_gb) || 0), 0)} GB){/terminate|delete/i.test(sel.action_type) ? "; they go with the instance unless kept or snapshotted" : ""}</div>}
                    {r.pool && <div className="text-zinc-400">member of {r.pool.kind} pool <span className="font-mono">{r.pool.name}</span>: its controller replaces it; act on the pool, not the member</div>}
                    {r.cluster && <div className="text-zinc-400">member of RDS cluster <span className="font-mono">{r.cluster}</span></div>}
                  </li>
                ))}
              </ul>
            </div>
          )}
          <div className="mt-4 space-y-2 border-t border-zinc-800 pt-3">
            <input className="w-full" placeholder="reason (required to reject; it teaches the agent; for pending: what you are waiting on)" value={reason} onChange={(e) => setReason(e.target.value)} />
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
              <Button variant="ghost" onClick={() => decide("pending")} disabled={sel.status === "pending"} title="Work in progress: some steps done, the rest waiting on something">Mark pending</Button>
              <Button variant="ghost" onClick={() => decide("snoozed")}>Snooze</Button>
              <Button variant="ghost" onClick={() => decide("done")}>Mark done</Button>
              {sel.status !== "open" && <Button variant="ghost" onClick={() => decide("open")}>Reopen</Button>}
              {notify?.configured && <Button variant="ghost" onClick={share} disabled={sharing} title="Post this recommendation to the Sphinx chat now">{sharing ? "Sending…" : "Send to Sphinx"}</Button>}
            </div>
            {shareResult && shareResult.id === sel.id && <div className={`mt-1 text-xs ${shareResult.result === "sent" ? "text-emerald-300" : "text-red-300"}`}>{shareResult.result === "sent" ? "sent to Sphinx" : shareResult.result}</div>}
          </div>
        </div>
        <div className="min-w-0">
          {planKey && (
            <div className={`mb-3 rounded border p-3 text-xs ${progressLine(sel.progress)?.due ? "border-amber-500/40 bg-amber-500/5" : "border-zinc-800 bg-zinc-950/60"}`}>
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-sm font-medium text-zinc-200">Progress <span className="font-normal text-zinc-500">· {doneSet.size} of {planTotal} steps{planKey.startsWith("playbook:") ? " of the playbook" : " of the tailored plan"}</span></span>
                <label className="flex items-center gap-2 text-zinc-400">check again on
                  <input type="date" className="!py-1 !text-xs" value={followUp || ""} min={today()} disabled={progressBusy} onChange={(e) => saveProgress(doneSet, e.target.value || null)} />
                  {followUp && <button className="text-zinc-500 hover:text-zinc-300" onClick={() => saveProgress(doneSet, null)} disabled={progressBusy}>clear</button>}
                </label>
              </div>
              <div className="mt-1 text-zinc-500">
                {planTotal > 0 && doneSet.size === 0 && !followUp && <>Tick the steps below as you do them; the first tick moves an open item to <Badge>pending</Badge> so it sits in that list until you mark it done.</>}
                {doneSet.size > 0 && doneSet.size < planTotal && <>Next: step {([...Array(planTotal).keys()].find((i) => !doneSet.has(i)) ?? 0) + 1}.{sel.status === "pending" && sel.decision_reason ? <> Waiting on: “{sel.decision_reason}”.</> : null}</>}
                {planTotal > 0 && doneSet.size === planTotal && <>Every step is ticked{sel.status !== "done" ? <>; mark it done when the saving is in place.</> : "."}</>}
                {followUp && progressLine(sel.progress)?.due && <span className="text-amber-300"> The follow-up day has come.</span>}
                {progress && !onThisPlan && <div className="mt-0.5 text-amber-300">Earlier progress ({progress.done.length} of {progress.total} steps{progress.follow_up ? `, check again ${progress.follow_up}` : ""}) was on {progress.plan.startsWith("playbook:") ? "the playbook" : "an earlier tailored plan"}; ticking here starts over on this one.</div>}
              </div>
              {planKey.startsWith("resolution:") && (failedSteps > 0 || doneSet.size > 0) && (
                <div className="mt-2 flex flex-wrap items-center gap-2 border-t border-zinc-800 pt-2">
                  <span className={failedSteps ? "text-red-300" : "text-zinc-500"}>{failedSteps ? `${failedSteps} step${failedSteps === 1 ? "" : "s"} failed.` : "Steps done so far."}</span>
                  <input className="!py-1 !text-xs min-w-[16rem] flex-1" placeholder="note for the agent (optional): what you know that the plan did not" value={replanNote} onChange={(e) => setReplanNote(e.target.value)} disabled={replanning || resolution?.status === "pending"} />
                  <Button variant="ghost" className="!px-2 !py-1 !text-xs" onClick={replan} disabled={replanning || resolution?.status === "pending"} title="Ask the agent for a new plan written from these outcomes: what worked stays, what failed is replaced">{replanning ? "Starting…" : "Re-plan from here"}</Button>
                </div>
              )}
            </div>
          )}
          <div className="rounded border border-zinc-800 bg-zinc-950/60 p-3">
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
              <div className="mt-3 space-y-4 text-sm leading-relaxed text-zinc-300">
                <div className="flex flex-wrap items-center gap-2 text-xs"><Badge>{resolution.plan.risk}</Badge>{!resolution.plan.applies && <span className="text-amber-300">the agent says the playbook does not apply</span>}{resolution.plan.est_monthly_saving != null && <span className="text-zinc-400">≈ {usd(resolution.plan.est_monthly_saving)} / month verified</span>}</div>
                <p className="text-zinc-200"><Prose text={resolution.plan.summary} /></p>
                {resolution.plan.blockers.length > 0 && <div><div className="mb-1 text-[11px] uppercase tracking-wide text-red-300">Blockers</div><ul className="list-disc space-y-2 pl-5">{resolution.plan.blockers.map((b: string, i: number) => <li key={i}><Prose text={b} /></li>)}</ul></div>}
                {resolution.plan.plan.length > 0 && (
                  <div>
                    <div className="mb-1 text-[11px] uppercase tracking-wide text-zinc-500">Plan</div>
                    <ol className="list-decimal space-y-3 pl-5">
                      {resolution.plan.plan.map((s: any, i: number) => (
                        <Step key={i} i={i} checks={planKey?.startsWith("resolution:") ? checks : undefined}>
                          <div><Prose text={s.step} /></div>
                          {s.command && <pre className="mt-1.5 overflow-x-auto whitespace-pre-wrap rounded bg-zinc-950 p-2 font-mono text-[11px] leading-5 text-zinc-200">{s.command}</pre>}
                          {s.verify && <div className="mt-1 text-xs text-emerald-300/90">verify: <Prose text={s.verify} /></div>}
                        </Step>
                      ))}
                    </ol>
                  </div>
                )}
                {resolution.plan.needs_from_human.length > 0 && <div><div className="mb-1 text-[11px] uppercase tracking-wide text-amber-300">Needs from a human</div><ul className="list-disc space-y-2 pl-5">{resolution.plan.needs_from_human.map((b: string, i: number) => <li key={i}><Prose text={b} /></li>)}</ul></div>}
                {resolution.plan.concepts_used.length > 0 && (
                  <div className="text-xs text-zinc-400"><span className="text-[11px] uppercase tracking-wide text-zinc-500">Concepts used</span>{" "}
                    {resolution.plan.concepts_used.map((c: any) => <span key={c.id} className="mr-2">{c.graph_url ? <a className="underline" href={c.graph_url} target="_blank" rel="noreferrer">{c.name || c.id}</a> : (c.name || c.id)}{c.scope && <span className="text-zinc-600"> ({c.scope})</span>}</span>)}
                  </div>
                )}
              </div>
            )}
            {resolution?.context?.feedback && (
              <details className="mt-2 text-xs"><summary className="cursor-pointer text-zinc-500">Written from what happened to the previous plan</summary>
                <pre className="mt-1 max-h-64 overflow-auto whitespace-pre-wrap rounded bg-zinc-950 p-2 font-mono text-[11px] leading-4 text-zinc-400">{resolution.context.feedback}</pre>
              </details>
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
          <Thread recId={sel.id} onReplan={replan} replanBusy={replanning || resolution?.status === "pending"} />
          {playbook ? (
            <details className="mt-3 rounded border border-zinc-800 bg-zinc-950/40 p-3 text-sm" open={!resolution?.plan}>
              <summary className="cursor-pointer text-zinc-200">How to do it <span className="text-zinc-500">· playbook: {playbook.title}</span> <Badge>{playbook.tier}</Badge> <EffortBadge effort={playbook.effort} /></summary>
              <div className="mt-2"><PlaybookBody pb={playbook} compact checks={planKey?.startsWith("playbook:") ? checks : undefined} /></div>
              <div className="mt-2 text-xs">
                <Link className="text-sky-300 hover:underline" to={`/findings?howto=${encodeURIComponent(playbook.control_id)}`}>Open the full playbook and the findings it covers →</Link>
              </div>
            </details>
          ) : (
            <div className="mt-3 text-xs text-zinc-500">No playbook is mapped to this recommendation's action type yet. <Link className="text-sky-300 hover:underline" to="/findings#playbooks">Browse the playbooks →</Link></div>
          )}
        </div>
      </div>
    </DetailCell>
  );

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h1 className="text-xl font-semibold text-zinc-100">Recommendations <span className="text-sm font-normal text-zinc-500">{data ? <>{data.total} · ≈ {usd(data.total_saving_distinct ?? data.total_saving)} / month{(data.overlap_usd ?? 0) > 0 && <span className="text-zinc-600" title="Several entries claim the same resource: only the largest claim per resource is counted here"> · {usd(data.overlap_usd)} claimed twice</span>}</> : "…"}</span></h1>
        <div className="flex gap-2">
          <input placeholder="search title, resource or #id" value={q} onChange={(e) => setParam("q", e.target.value)} className="w-56" />
          <select value={status} onChange={(e) => setParam("status", e.target.value)}>
            {STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>
      </div>
      {err && <div className="text-sm text-red-300">{err}</div>}
      {/* A deep link to a recommendation that is not in this list (another status, page or search) still opens it, above the table. */}
      {sel && data && !entry && detail}
      <div className="space-y-3">
        {!data ? <Empty>Loading…</Empty> : rows.length === 0 ? <Empty>Nothing here.</Empty> : (
          <table className="w-full border-collapse overflow-hidden rounded-lg border border-zinc-800">
            <thead className="bg-zinc-900"><tr><Th>Recommendation</Th><Th>Tier</Th><Th>Source</Th><Th className="text-right">Saving / mo</Th><Th className="text-right">Conf.</Th></tr></thead>
            <tbody>
              {rows.map((r) => {
                const isOpen = entry?.id === r.id;
                return (
                  <Fragment key={r.id}>
                    <tr onClick={() => toggle(r)} className={`cursor-pointer border-t border-zinc-800 hover:bg-zinc-900/60 ${isOpen ? "bg-zinc-900" : ""}`}>
                      <Td>
                        <div>{r.title}</div>
                        <div className="text-xs text-zinc-500"><span className="font-mono text-zinc-400">#{r.id}</span>{r.status !== status && <> · <Badge>{r.status}</Badge></>} · {r.action_type} · {r.resource}</div>
                        {(() => { const p = progressLine(r.progress); return p ? <div className={`text-xs ${p.due ? "text-amber-300" : "text-indigo-300"}`}>{p.text}</div> : null; })()}
                        {r.system && <div className="text-xs text-sky-300">{r.system.members.length} member{r.system.members.length === 1 ? "" : "s"} of {r.system.kind.replace("_", " ")} {r.system.id} · one decision for all {r.merged_ids.length}</div>}
                        {r.conflicts?.length > 0 && <div className="text-xs text-amber-300">conflicts with {r.conflicts.map((c: any, i: number) => <span key={c.id}>{i > 0 ? ", " : ""}#{c.id} ({c.action_type}{c.status !== r.status ? `, ${c.status}` : ""})</span>)}</div>}
                        {r.blocker && <div className={`text-xs ${r.blocker.done ? "text-emerald-300" : "text-zinc-400"}`}>{r.blocker.done ? `unblocked: #${r.blocker.id} is ${r.blocker.status}` : `blocked by #${r.blocker.id} (${r.blocker.status}${r.blocker.follow_up ? `, check again ${r.blocker.follow_up}` : ""})`}</div>}
                        {r.merged?.length > 0 && <div className="text-xs text-violet-300">also proposed by {otherSources(r).length ? otherSources(r).join(", ") : r.source} ({r.merged.length} more)</div>}
                      </Td>
                      <Td><Badge>{r.tier}</Badge></Td><Td><Badge>{r.source}</Badge></Td>
                      <Td className="text-right font-medium text-zinc-100">{usd(r.est_monthly_saving)}</Td>
                      <Td className="text-right text-zinc-400">{r.confidence != null ? Math.round(r.confidence * 100) + "%" : "—"}</Td>
                    </tr>
                    {isOpen && <tr className="border-t border-zinc-800 bg-zinc-950/40"><td colSpan={5} className="max-w-0 p-3">{detail}</td></tr>}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        )}
        {data && <Pager page={data.page} pageSize={data.page_size} total={data.total} onPage={(p) => setParam("page", String(p))} />}
      </div>
    </div>
  );
}

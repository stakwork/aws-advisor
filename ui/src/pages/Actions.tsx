import React, { Fragment, useEffect, useState } from "react";
import { NavLink, useSearchParams } from "react-router-dom";
import { api, usd, when } from "../api";
import { Badge, Button, Card, Code, CopyButton, Empty, Pager, Td, Th } from "../components/ui";
import { Thread } from "../components/thread";
import { RunAsMe } from "../components/consent";

const FILTERS = ["proposed", "applied", "verified", "failed", "refused", "reverted", "stale", "all"];
const PAGE_SIZE = 25;
const KIND_LABEL: Record<string, string> = { acu_window: "Serverless v2 minimum", snapshot_archive: "Snapshot → Archive", ebs_iops_trim: "gp3 IOPS trim", log_retention: "Log retention", s3_request_metrics: "S3 request metrics", aurora_storage: "Aurora storage type", s3_lifecycle: "S3 lifecycle rules", ebs_gp3_migrate: "gp2 → gp3", ecr_lifecycle: "ECR lifecycle policy", swarm_park: "Park idle swarm", eip_release: "EIP release", vpc_gateway_endpoint: "Gateway endpoint", kms_key_retire: "KMS key retire", dynamodb_capacity_mode: "DynamoDB capacity mode", snapshot_delete: "Snapshot delete", idle_load_balancer: "Idle load balancer", schedule_hours: "Office hours", ebs_throughput_trim: "gp3 throughput trim", cpu_credit_spec: "Credit specification", efs_lifecycle: "EFS lifecycle", alarm_cleanup: "Stale alarms", log_retention_tune: "Log retention tune", s3_multipart_abort: "Multipart abort", lambda_memory: "Lambda memory", beanstalk_pressure: "Beanstalk ceiling (pressure now)", beanstalk_scale: "Beanstalk capacity", usage_schedule: "Usage schedule tag", consent_tag: "Consent switch" };
const STATUS_CLASS: Record<string, string> = { proposed: "text-sky-300", applied: "text-amber-300", verified: "text-emerald-300", failed: "text-red-300", refused: "text-red-200", reverted: "text-zinc-300", stale: "text-zinc-500" };

/** The auto-actions page: what the executor may do (mode, role, identity), what it proposed and what it did, with apply and revert per row. */
export default function Actions() {
  const [params, setParams] = useSearchParams();
  const filter = FILTERS.includes(params.get("status") || "") ? params.get("status")! : "all";
  const kind = params.get("kind") || "";
  const page = Math.max(1, Number(params.get("page")) || 1);
  const selectedId = params.get("id");
  // A deep link carries an id and no page: the server answers with the page that holds that row.
  const pageQuery = params.get("page") ? `page=${page}` : selectedId ? `id=${encodeURIComponent(selectedId)}` : "page=1";
  const [status, setStatus] = useState<any>(null);
  const [data, setData] = useState<{ actions: any[]; total: number; page: number; page_size: number; counts: Record<string, number>; kinds: Record<string, number> } | null>(null);
  const [preview, setPreview] = useState<any>(null);
  const [busy, setBusy] = useState("");
  const [msg, setMsg] = useState("");
  const [lastPass, setLastPass] = useState<any>(null);
  // The narrated pass (src/pass_report.ts): the newest report; polled every 5 s while the agent is still writing it.
  const [report, setReport] = useState<any>(null);
  const loadReport = () => api("/actions/pass-reports?limit=1").then((r) => setReport(Array.isArray(r) ? r[0] ?? null : null)).catch(() => {});
  useEffect(() => { loadReport(); }, [lastPass]);
  useEffect(() => { if (report?.status !== "pending") return; const t = setInterval(loadReport, 5000); return () => clearInterval(t); }, [report?.status, report?.id]);
  const [showPolicy, setShowPolicy] = useState(false);
  const [showNarrow, setShowNarrow] = useState(false);
  // The activity log (src/executor_log.ts): every pass with its lines and events, loaded only once shown, refreshed with the ledger.
  const [showLog, setShowLog] = useState(false);
  const [log, setLog] = useState<{ passes: any[]; loose: any[] } | null>(null);
  const [openPass, setOpenPass] = useState<number | null>(null);
  useEffect(() => { if (showLog) api("/actions/log?limit=40").then(setLog).catch((e) => setMsg(e.message)); }, [showLog, lastPass, data]);
  const [open, setOpen] = useState<number | null>(selectedId ? Number(selectedId) : null);
  // The row whose thread with the agent is open ("why this?"); one at a time, one thread per row on the server.
  const [asking, setAsking] = useState<number | null>(null);

  const load = () => { api(`/actions?status=${filter}${kind ? `&kind=${encodeURIComponent(kind)}` : ""}&${pageQuery}&page_size=${PAGE_SIZE}`).then(setData).catch((e) => setMsg(e.message)); };
  useEffect(() => { api("/actions/status").then(setStatus).catch((e) => setMsg(e.message)); }, []);
  useEffect(() => { load(); }, [filter, kind, pageQuery]);
  // Status and kind reset the page; page leaves the rest alone.
  const set = (k: string, v: string | null) => { const p = new URLSearchParams(params); v ? p.set(k, v) : p.delete(k); if (k !== "page") { p.delete("page"); p.delete("id"); } setParams(p); };
  // Expands or collapses a row. Once the page was resolved from a deep link's id, it is written to the URL here, so
  // collapsing the linked row (or a refresh after that) stays on this page instead of falling back to page 1.
  const toggle = (id: number) => {
    setOpen(open === id ? null : id);
    const p = new URLSearchParams(params);
    p.delete("id");
    if (!p.get("page") && data) p.set("page", String(data.page));
    setParams(p, { replace: true });
  };
  // The kinds in scope (the status filter, before the kind filter), so the picked kind stays listed with the others.
  const kinds = Object.entries(data?.kinds || {});
  if (kind && !kinds.some(([k]) => k === kind)) kinds.push([kind, 0]);

  const run = async (path: string, key: string, after?: (r: any) => void) => {
    setBusy(key); setMsg("");
    try { const r = await api(path, { method: "POST", body: "{}" }); after?.(r); load(); }
    catch (e: any) { setMsg(e.message); }
    finally { setBusy(""); }
  };
  const doPreview = async () => { setBusy("preview"); setMsg(""); try { setPreview(await api("/actions/preview")); } catch (e: any) { setMsg(e.message); } finally { setBusy(""); } };

  const mode = status?.mode || "…";
  const paused = status?.paused?.paused ? status.paused : null;
  const reloadStatus = () => api("/actions/status").then(setStatus).catch((e) => setMsg(e.message));
  const doPause = async () => {
    const reason = window.prompt("Pause auto-actions: nothing is planned or applied until someone resumes (Revert keeps working). Why?", "");
    if (reason === null) return;
    setBusy("pause"); setMsg("");
    try { await api("/actions/pause", { method: "POST", body: JSON.stringify({ reason }) }); await reloadStatus(); } catch (e: any) { setMsg(e.message); } finally { setBusy(""); }
  };
  const doResume = async () => { setBusy("resume"); setMsg(""); try { await api("/actions/resume", { method: "POST", body: "{}" }); await reloadStatus(); } catch (e: any) { setMsg(e.message); } finally { setBusy(""); } };
  return (
    <div className="space-y-4">
      {paused && (
        <div className="flex flex-wrap items-center gap-3 rounded border border-amber-700 bg-amber-950/40 px-3 py-2 text-sm text-amber-200">
          <span>⏸ Auto-actions paused by <span className="font-mono">{paused.by}</span> since {String(paused.at || "").slice(0, 16).replace("T", " ")} UTC{paused.reason ? `: ${paused.reason}` : ""}{paused.until ? ` (resumes ${String(paused.until).slice(0, 16).replace("T", " ")} UTC)` : ""}. Nothing is planned or applied; Revert still works.</span>
          <Button onClick={doResume} disabled={busy === "resume"} title="lift the pause; the next pass runs on schedule">{busy === "resume" ? "Resuming…" : "Resume"}</Button>
        </div>
      )}
      <Card title={<span>Auto-actions <span className="font-normal text-zinc-500">· the executor: micro-adjustments the agent makes on a schedule, ledgered and reversible</span></span>}>
        <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm">
          <span>mode <span className={`font-mono ${mode === "apply" ? "text-emerald-300" : mode === "off" ? "text-red-300" : "text-amber-300"}`}>{mode}</span></span>
          <span>pass <span className="font-mono text-zinc-300">{status?.cron || "…"}</span></span>
          <span>acts as {status?.identity?.ok ? <span className="font-mono text-emerald-300" title={status.identity.arn}>{String(status.identity.arn).split(":").pop()}</span> : <span className="text-amber-300" title={status?.identity?.error}>{status?.identity?.error || "…"}</span>}</span>
          <span className="ml-auto flex gap-2">
            {!paused && <Button variant="ghost" onClick={doPause} disabled={busy === "pause" || mode === "off"} title="the kill switch: the executor plans and applies nothing until someone resumes (page, API or chat); Revert keeps working">{busy === "pause" ? "Pausing…" : "Pause"}</Button>}
            <Button variant="ghost" onClick={doPreview} disabled={busy === "preview"} title="what the pass would propose now, without recording it">{busy === "preview" ? "Planning…" : "Preview plan"}</Button>
            <Button onClick={() => run("/actions/run", "run", (r) => { setLastPass(r); setMsg(""); })} disabled={busy === "run" || mode === "off"} title="run the pass now, as the cron would (dry_run records, apply acts)">{busy === "run" ? "Running…" : "Run pass now"}</Button>
          </span>
        </div>
        <div className="mt-2 text-xs text-zinc-500">
          {mode === "off" ? "Off: nothing is planned or applied. " : mode === "dry_run" ? "Dry run: every pass records what it would change; nothing is touched unless you press Apply on a row. " : "Apply: the pass makes the changes under the actuator role, up to the per-pass cap. "}
          Settings for mode, role, floor and cap are under <NavLink to="/settings" className="text-sky-300">Settings › Auto-actions</NavLink>. The actuator role is the only identity that changes AWS; tag a resource <span className="font-mono">advisor:hands-off</span> to fence it off.
          <button className="ml-2 text-sky-300" onClick={() => setShowPolicy((s) => !s)}>{showPolicy ? "hide" : "show"} the actuator policy</button>
        </div>
        {showPolicy && status && (
          <div className="mt-3 grid gap-3 md:grid-cols-2">
            <div><div className="mb-1 text-xs text-zinc-400">Permissions policy for the actuator role <CopyButton text={JSON.stringify(status.policy, null, 2)} /></div><Code className="max-h-72 overflow-auto">{JSON.stringify(status.policy, null, 2)}</Code></div>
            <div><div className="mb-1 text-xs text-zinc-400">Trust policy (the advisor's read identity{status.read_identity ? "" : ", once configured"} may assume it) <CopyButton text={JSON.stringify(status.trust_policy, null, 2)} /></div><Code className="max-h-72 overflow-auto">{JSON.stringify(status.trust_policy, null, 2)}</Code>
              <div className="mt-2 text-xs text-zinc-500">Create the role with these two documents, then paste its ARN into Settings › Auto-actions › Actuator role ARN. "Acts as" above turns green when the assumption works.</div></div>
          </div>
        )}
        {status?.modules && <div className="mt-2 text-xs text-zinc-500">Actions: {status.modules.map((m: any) => m.label).join(" · ")}</div>}
        {status?.capabilities && Object.values(status.capabilities).some((c: any) => c.apply === false || c.revert === false) && (() => {
          const narrow = Object.entries(status.capabilities).filter(([, c]: any) => c.apply === false || c.revert === false);
          return (
            <div className="mt-1 text-xs text-amber-300">
              The role is narrower than the policy, so {narrow.length} action{narrow.length === 1 ? " stays" : "s stay"} with a person.
              <button className="ml-2 text-sky-300" onClick={() => setShowNarrow((s) => !s)}>{showNarrow ? "hide" : "show"} which</button>
              {showNarrow && (
                <ul className="mt-1 space-y-0.5 text-amber-200/80">
                  {narrow.map(([k, c]: any) => (
                    <li key={k}>· {KIND_LABEL[k] || k} <span className="text-zinc-500">({c.apply === false ? "apply" : "revert"}: <span className="font-mono">{c.missing.join(", ")}</span>)</span></li>
                  ))}
                </ul>
              )}
            </div>
          );
        })()}
        {status?.capabilities_note && <div className="mt-1 text-xs text-zinc-500">{status.capabilities_note}</div>}
        {status?.role_arn && (
          <div className="mt-1 text-xs text-zinc-500">
            <button className="text-sky-300 hover:underline disabled:opacity-50" disabled={busy === "recheck"} title="drop the denials learned from failed applies (after the role's policy was widened) and simulate the role again"
              onClick={() => { setBusy("recheck"); setMsg(""); api("/actions/capabilities/recheck", { method: "POST", body: "{}" }).then(() => reloadStatus()).catch((e) => setMsg(e.message)).finally(() => setBusy("")); }}>
              {busy === "recheck" ? "re-checking the role…" : "re-check the role"}
            </button>
            <span className="ml-1">after widening its policy: what it was refused before is forgotten and tried again.</span>
          </div>
        )}
        {msg && <div className="mt-2 text-xs text-amber-300">{msg}</div>}
        {lastPass && (
          <div className="mt-3 rounded border border-zinc-800 bg-zinc-950/60 p-2 text-xs">
            <div className="text-zinc-200">Pass finished ({lastPass.mode}, {lastPass.took_ms} ms): {lastPass.proposed} proposed{lastPass.fresh ? ` (${lastPass.fresh} new)` : ""}, {lastPass.applied} applied, {lastPass.verified} verified, {lastPass.failed} failed, {lastPass.refused} refused, {lastPass.stale} stale.</div>
            {lastPass.proposed === 0 && <div className="mt-1 text-zinc-400">Nothing to change right now. What each action looked at and why it left things alone:</div>}
            {lastPass.notes?.length > 0 && <ul className="mt-1 space-y-0.5 text-zinc-400">{lastPass.notes.map((n: string, i: number) => <li key={i}>· {n}</li>)}</ul>}
            {lastPass.errors?.length > 0 && <ul className="mt-1 space-y-0.5 text-red-300">{lastPass.errors.map((n: string, i: number) => <li key={i}>· {n}</li>)}</ul>}
          </div>
        )}
        {report && (
          <div className="mt-3 rounded border border-zinc-800 bg-zinc-950/60 p-2 text-xs" title="the agent's narration of the last pass whose outcome was new (Settings › Auto-actions › Narrate the pass)">
            <div className="flex flex-wrap items-center gap-2 text-zinc-200">
              <span>Last narrated pass</span>
              <span className="text-zinc-500">{when(report.pass_at)} · {report.trigger} · {report.mode}</span>
              {report.status === "pending" && <span className="text-amber-300">the agent is writing…</span>}
              {report.status === "failed" && <span className="text-red-300">failed</span>}
              {report.status === "completed" && report.score != null && <span className="text-zinc-500" title={(report.grade?.checks || []).map((c: any) => `${c.pass ? "✓" : "✗"} ${c.check}: ${c.detail}`).join("\n")}>grade {Math.round(report.score * 100)} %</span>}
              {report.sphinx_sent_at ? <span className="text-emerald-300">posted to Sphinx {when(report.sphinx_sent_at)}</span> : report.sphinx_result ? <span className="text-zinc-500">{report.sphinx_result}</span> : null}
              {report.status === "completed" && <Button variant="ghost" onClick={() => api(`/actions/pass-reports/${report.id}/resend`, { method: "POST", body: "{}" }).then(loadReport).catch((e: any) => setMsg(e.message))}>Resend</Button>}
            </div>
            {report.status === "failed" && report.error && <div className="mt-1 text-red-300">{String(report.error).slice(0, 300)}</div>}
            {report.held_back?.length > 0 && <div className="mt-1 text-amber-300">Held back from Sphinx: {report.held_back.join(", ")}</div>}
            {report.result?.summary && <div className="mt-1 text-zinc-300">{report.result.summary}</div>}
            {(["next", "waiting", "left_alone", "concerns"] as const).map((k) => Array.isArray(report.result?.[k]) && report.result[k].length > 0 && (
              <div key={k} className="mt-1">
                <div className={k === "concerns" ? "text-amber-300" : "text-zinc-400"}>{k === "next" ? "Next" : k === "waiting" ? "Waiting on a person" : k === "left_alone" ? "Left alone" : "Concerns"}</div>
                <ul className="space-y-0.5 text-zinc-400">{report.result[k].map((n: string, i: number) => <li key={i}>· {n}</li>)}</ul>
              </div>
            ))}
          </div>
        )}
      </Card>

      <Card title={<span className="flex flex-wrap items-center justify-between gap-2"><span>Activity <span className="font-normal text-zinc-500">· what the actuator did, pass by pass: every plan, apply, read-back and revert</span></span><button className="text-xs text-sky-300" onClick={() => setShowLog((s) => !s)}>{showLog ? "hide" : "show"}</button></span>}>
        {!showLog ? <div className="text-xs text-zinc-500">Every pass (scheduled or manual, including the ones that did nothing) with the lines it printed, and every Apply, Check and Revert from the page or the chat. Click show.</div>
        : !log ? <div className="text-sm text-zinc-500">Loading…</div>
        : !log.passes.length && !log.loose.length ? <Empty>No activity yet. The first pass, or the first Apply, writes the first entry.</Empty>
        : (
          <div className="space-y-1 text-xs">
            {[...log.passes.map((p) => ({ t: p.started_at, pass: p })), ...log.loose.map((e) => ({ t: e.at, ev: e }))].sort((a, b) => (a.t < b.t ? 1 : a.t > b.t ? -1 : 0)).map((it: any) => it.pass ? (
              <div key={`p${it.pass.id}`} className="rounded border border-zinc-800/60">
                <div className="flex cursor-pointer flex-wrap items-center gap-x-3 gap-y-1 px-2 py-1.5 hover:bg-zinc-900/40" onClick={() => setOpenPass(openPass === it.pass.id ? null : it.pass.id)}>
                  <span className="whitespace-nowrap text-zinc-400">{when(it.pass.started_at)}</span>
                  <span className="text-zinc-500">pass #{it.pass.id} · {it.pass.trigger}</span>
                  <span className={`font-mono ${it.pass.mode === "apply" ? "text-emerald-300" : it.pass.mode === "off" ? "text-red-300" : "text-amber-300"}`}>{it.pass.mode}</span>
                  {!it.pass.finished_at ? <span className="text-amber-300">running…</span> : (
                    <span className="text-zinc-300">{it.pass.proposed} proposed{it.pass.fresh ? ` (${it.pass.fresh} new)` : ""}, {it.pass.applied} applied, {it.pass.verified} verified{it.pass.failed ? <span className="text-red-300">, {it.pass.failed} failed</span> : null}{it.pass.refused ? <span className="text-red-200">, {it.pass.refused} refused</span> : null}{it.pass.held ? `, ${it.pass.held} held` : ""}{it.pass.stale ? `, ${it.pass.stale} stale` : ""}</span>
                  )}
                  {it.pass.errors.length > 0 && <span className="text-red-300">{it.pass.errors.length} error{it.pass.errors.length === 1 ? "" : "s"}</span>}
                  {it.pass.took_ms != null && <span className="ml-auto text-zinc-600">{(it.pass.took_ms / 1000).toFixed(1)} s · {it.pass.lines.length} lines</span>}
                </div>
                {openPass === it.pass.id && (
                  <div className="space-y-2 border-t border-zinc-800/40 bg-zinc-950/60 p-2">
                    {it.pass.errors.length > 0 && <ul className="space-y-0.5 text-red-300">{it.pass.errors.map((n: string, i: number) => <li key={i}>· {n}</li>)}</ul>}
                    {it.pass.events.length > 0 && (
                      <div>
                        <div className="mb-1 text-zinc-400">Changes made in this pass</div>
                        <ul className="space-y-0.5">{it.pass.events.map((e: any) => <li key={e.id}><span className="text-zinc-500">{when(e.at)}</span> <span className="text-zinc-300">{e.event}</span> <span className="text-sky-300 cursor-pointer" onClick={() => set("id", String(e.action_id))}>#{e.action_id}</span> <span className="text-zinc-400">{KIND_LABEL[e.kind] || e.kind}</span> → <span className={STATUS_CLASS[e.outcome] || "text-zinc-300"}>{e.outcome}</span>{e.detail && <span className="text-zinc-500">: {e.detail}</span>}</li>)}</ul>
                      </div>
                    )}
                    <div>
                      <div className="mb-1 text-zinc-400">What the pass printed</div>
                      {it.pass.lines.length ? <Code className="max-h-80 overflow-auto whitespace-pre-wrap">{it.pass.lines.join("\n")}</Code> : <div className="text-zinc-500">nothing</div>}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div key={`e${it.ev.id}`} className="flex flex-wrap items-center gap-x-3 gap-y-1 rounded border border-zinc-800/60 px-2 py-1.5">
                <span className="whitespace-nowrap text-zinc-400">{when(it.ev.at)}</span>
                <span className="text-zinc-500">{it.ev.trigger}</span>
                <span className="text-zinc-300">{it.ev.event}</span>
                <span className="cursor-pointer text-sky-300" onClick={() => set("id", String(it.ev.action_id))}>#{it.ev.action_id}</span>
                <span className="text-zinc-400">{KIND_LABEL[it.ev.kind] || it.ev.kind}</span>
                <span>→ <span className={STATUS_CLASS[it.ev.outcome] || "text-zinc-300"}>{it.ev.outcome}</span></span>
                {it.ev.detail && <span className="text-zinc-500">{it.ev.detail}</span>}
              </div>
            ))}
            <div className="pt-1 text-zinc-500">A pass is one run of every action's plan; the rows inside it are what that pass applied, read back or reverted. An entry outside a pass is an Apply, Check or Revert someone made from the page or the chat. The log keeps 90 days.</div>
          </div>
        )}
      </Card>

      {preview && (
        <Card title={<span>Preview <span className="font-normal text-zinc-500">· {preview.proposals.length} change(s) the pass would propose now</span></span>}>
          {preview.proposals.length ? (
            <ul className="space-y-1 text-sm">{preview.proposals.map((p: any) => <li key={p.dedupe}><span className="text-zinc-200">{p.title}</span>{p.est_usd_month != null && <span className="ml-2 text-emerald-300">≈ {usd(p.est_usd_month, 2)}/mo</span>}<div className="text-xs text-zinc-500">{p.reason}</div></li>)}</ul>
          ) : <Empty>Nothing to change right now.</Empty>}
          {preview.notes?.length > 0 && <div className="mt-2 text-xs text-zinc-500">{preview.notes.map((n: string, i: number) => <div key={i}>{n}</div>)}</div>}
          {preview.errors?.length > 0 && <div className="mt-2 text-xs text-red-300">{preview.errors.join(" · ")}</div>}
          <div className="mt-2"><Button variant="ghost" onClick={() => setPreview(null)}>Close</Button></div>
        </Card>
      )}

      <Card title={<span>Ledger <span className="font-normal text-zinc-500">· every proposal and what became of it</span></span>}>
        <div className="mb-3 flex flex-wrap items-center gap-1 text-xs">
          {FILTERS.map((f) => <button key={f} onClick={() => set("status", f)} className={`rounded px-2 py-1 ${filter === f ? "bg-zinc-800 text-zinc-100" : "text-zinc-400 hover:text-zinc-200"}`}>{f}{data?.counts && f !== "all" && data.counts[f] ? ` (${data.counts[f]})` : ""}</button>)}
          <select value={kind} onChange={(e) => set("kind", e.target.value || null)} className="ml-auto rounded border border-zinc-800 bg-zinc-950 px-2 py-1 text-zinc-300" title="only this action's rows">
            <option value="">all actions</option>
            {kinds.map(([k, n]) => <option key={k} value={k}>{KIND_LABEL[k] || k} · {n}</option>)}
          </select>
        </div>
        {!data ? <div className="text-sm text-zinc-500">Loading…</div> : !data.actions.length ? <Empty>No {filter === "all" ? "" : filter + " "}{kind ? `${KIND_LABEL[kind] || kind} ` : ""}actions yet. {mode === "off" ? "The executor is off." : lastPass ? "The last pass found nothing to change; its notes above say why." : "Run a pass, or Preview plan, to see what it proposes and why."}</Empty> : (
          <table className="w-full text-sm">
            <thead><tr><Th>When</Th><Th>Action</Th><Th>Change</Th><Th className="text-right">≈ USD/mo</Th><Th>Status</Th><Th></Th></tr></thead>
            <tbody>
              {data.actions.map((a) => (
                <Fragment key={a.id}>
                  <tr className={`cursor-pointer border-t border-zinc-800/60 ${open === a.id ? "bg-zinc-900/60" : "hover:bg-zinc-900/40"}`} onClick={() => toggle(a.id)}>
                    <Td className="whitespace-nowrap text-xs text-zinc-400"><span title={`proposed ${when(a.created_at)} · last seen by a pass ${when(a.seen_at)}${a.revived_at ? ` · proposed again ${when(a.revived_at)}` : ""}`}>{when(a.applied_at || a.created_at)}</span><div className="text-[11px] text-zinc-600">#{a.id} · {a.trigger}{a.status === "proposed" && a.seen_at !== a.created_at && <span> · seen {when(a.seen_at)}</span>}</div></Td>
                    <Td className="text-xs text-zinc-300">{KIND_LABEL[a.kind] || a.kind}</Td>
                    <Td>{a.title}<div className="text-xs text-zinc-500">{a.reason}</div></Td>
                    <Td className="text-right text-emerald-300">{a.est_usd_month != null ? usd(a.est_usd_month, 2) : "—"}</Td>
                    <Td className={`text-xs ${STATUS_CLASS[a.status] || ""}`}>{a.status}{a.check?.verdict === "hold" && <div className="text-[11px] text-amber-300" title={a.check.reason}>held by Jev</div>}{a.check?.verdict === "proceed" && <div className="text-[11px] text-zinc-500" title={a.check.reason}>Jev ok</div>}{a.notify_result && <div className="text-[11px] text-zinc-600" title={a.notify_result}>sphinx: {a.notify_result.split(":")[0]}</div>}</Td>
                    <td className="whitespace-nowrap px-2 py-2 text-right align-top" onClick={(e: React.MouseEvent) => e.stopPropagation()}>
                      {a.status === "proposed" && (status?.capabilities?.[a.kind]?.apply === false
                        ? <span className="text-[11px] text-amber-300" title={`the actuator role is not allowed ${status.capabilities[a.kind].missing.join(", ")}; do it by hand, or widen the role`}>by hand: role lacks {status.capabilities[a.kind].missing.join(", ")}</span>
                        : <Button className="!px-2 !py-1 !text-xs" onClick={() => run(`/actions/${a.id}/apply`, `apply-${a.id}`)} disabled={busy === `apply-${a.id}` || mode === "off" || !status?.identity?.ok} title={!status?.identity?.ok ? "the actuator role is not usable yet" : "make this change now under the actuator role"}>{busy === `apply-${a.id}` ? "Applying…" : "Apply"}</Button>)}
                      {a.status === "applied" && <Button variant="ghost" className="!px-2 !py-1 !text-xs" onClick={() => run(`/actions/${a.id}/verify`, `verify-${a.id}`)} disabled={busy === `verify-${a.id}`}>Check</Button>}
                      {(a.status === "applied" || a.status === "verified") && (status?.capabilities?.[a.kind]?.revert === false
                        ? <span className="ml-1 text-[11px] text-amber-300" title={`the actuator role is not allowed ${status.capabilities[a.kind].missing.join(", ")}`}>undo by hand: role lacks {status.capabilities[a.kind].missing.join(", ")}</span>
                        : <Button variant="danger" className="ml-1 !px-2 !py-1 !text-xs" onClick={() => run(`/actions/${a.id}/revert`, `revert-${a.id}`)} disabled={busy === `revert-${a.id}` || mode === "off"} title={a.rollback}>{busy === `revert-${a.id}` ? "Reverting…" : "Revert"}</Button>)}
                      <Button variant="ghost" className="ml-1 !px-2 !py-1 !text-xs" onClick={() => setAsking(asking === a.id ? null : a.id)} title="ask the advisor about this row: why this change, what happens if it is applied, what the revert does">{asking === a.id ? "Close" : "Ask"}</Button>
                    </td>
                  </tr>
                  {asking === a.id && (
                    <tr className="border-t border-zinc-800/40 bg-zinc-900/40"><td colSpan={6} className="p-3">
                      <Thread base={`/actions/${a.id}/messages`} general title={`Ask the advisor about #${a.id}`} hint="why this change, what happens if it is applied, what the revert does; the agent gets the row's facts, the resource and its history" />
                    </td></tr>
                  )}
                  {open === a.id && (
                    <tr className="border-t border-zinc-800/40 bg-zinc-900/40"><td colSpan={6} className="p-3">
                      <div className="grid gap-3 text-xs md:grid-cols-3">
                        <div><div className="mb-1 text-zinc-400">Before → after</div><Code>{JSON.stringify(a.before, null, 1)}</Code><div className="my-1 text-center text-zinc-600">↓</div><Code>{JSON.stringify(a.after, null, 1)}</Code></div>
                        <div><div className="mb-1 text-zinc-400">Facts the decision was made on</div><Code className="max-h-64 overflow-auto">{JSON.stringify(a.facts, null, 1)}</Code></div>
                        <div className="space-y-2">
                          <div><div className="text-zinc-400">Resource</div><div className="font-mono text-zinc-200">{a.resource}{a.region ? ` · ${a.region}` : ""}</div></div>
                          <div><div className="text-zinc-400">Undo</div><div className="text-zinc-200">{a.rollback}</div></div>
                          {a.result && <div><div className="text-zinc-400">Result</div><div className="text-zinc-200">{a.result}</div></div>}
                          {a.kind === "consent_tag" && (a.status === "proposed" || a.status === "failed") && <div><div className="text-zinc-400">With your own credentials</div><RunAsMe actionId={a.id} onDone={() => load()} /></div>}
                          {a.kind === "consent_tag" && (a.status === "applied" || a.status === "verified") && String(a.trigger || "").startsWith("person:") && <div><div className="text-zinc-400">Done by a person; undo the same way</div><RunAsMe actionId={a.id} verb="revert" onDone={() => load()} /></div>}
                          {a.error && <div><div className="text-zinc-400">Error</div><div className="text-red-300">{a.error}</div></div>}
                          <div className="text-zinc-500">proposed {when(a.created_at)}{a.revived_at && ` · went stale, proposed again ${when(a.revived_at)}`} · last seen {when(a.seen_at)}{a.applied_at && ` · applied ${when(a.applied_at)}`}{a.verified_at && ` · verified ${when(a.verified_at)}`}{a.reverted_at && ` · reverted ${when(a.reverted_at)}`} · mode {a.mode}</div>
                        </div>
                      </div>
                    </td></tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        )}
        {data && <Pager className="mt-3" page={data.page} pageSize={data.page_size} total={data.total} onPage={(p) => set("page", String(p))} />}
        <div className="mt-3 text-xs text-zinc-500">A <Badge>proposed</Badge> row waits for the next apply pass or your Apply; <Badge>applied</Badge> means the call succeeded and the read-back is pending (a snapshot takes hours to archive); <Badge>verified</Badge> means it was read back; <Badge>stale</Badge> means the latest pass no longer proposes it (the hour moved on).</div>
      </Card>
    </div>
  );
}

import React, { Fragment, useEffect, useState } from "react";
import { NavLink, useSearchParams } from "react-router-dom";
import { api, usd, when } from "../api";
import { Badge, Button, Card, Code, CopyButton, Empty, Pager, Td, Th } from "../components/ui";

const FILTERS = ["proposed", "applied", "verified", "failed", "refused", "reverted", "stale", "all"];
const PAGE_SIZE = 25;
const KIND_LABEL: Record<string, string> = { acu_window: "Serverless v2 minimum", snapshot_archive: "Snapshot → Archive", ebs_iops_trim: "gp3 IOPS trim", log_retention: "Log retention", s3_request_metrics: "S3 request metrics", aurora_storage: "Aurora storage type", s3_lifecycle: "S3 lifecycle rules", ebs_gp3_migrate: "gp2 → gp3", ecr_lifecycle: "ECR lifecycle policy", swarm_park: "Park idle swarm" };
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
  const [showPolicy, setShowPolicy] = useState(false);
  const [open, setOpen] = useState<number | null>(selectedId ? Number(selectedId) : null);

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
  return (
    <div className="space-y-4">
      <Card title={<span>Auto-actions <span className="font-normal text-zinc-500">· the executor: micro-adjustments the agent makes on a schedule, ledgered and reversible</span></span>}>
        <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm">
          <span>mode <span className={`font-mono ${mode === "apply" ? "text-emerald-300" : mode === "off" ? "text-red-300" : "text-amber-300"}`}>{mode}</span></span>
          <span>pass <span className="font-mono text-zinc-300">{status?.cron || "…"}</span></span>
          <span>acts as {status?.identity?.ok ? <span className="font-mono text-emerald-300" title={status.identity.arn}>{String(status.identity.arn).split(":").pop()}</span> : <span className="text-amber-300" title={status?.identity?.error}>{status?.identity?.error || "…"}</span>}</span>
          <span className="ml-auto flex gap-2">
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
        {msg && <div className="mt-2 text-xs text-amber-300">{msg}</div>}
        {lastPass && (
          <div className="mt-3 rounded border border-zinc-800 bg-zinc-950/60 p-2 text-xs">
            <div className="text-zinc-200">Pass finished ({lastPass.mode}, {lastPass.took_ms} ms): {lastPass.proposed} proposed{lastPass.fresh ? ` (${lastPass.fresh} new)` : ""}, {lastPass.applied} applied, {lastPass.verified} verified, {lastPass.failed} failed, {lastPass.refused} refused, {lastPass.stale} stale.</div>
            {lastPass.proposed === 0 && <div className="mt-1 text-zinc-400">Nothing to change right now. What each action looked at and why it left things alone:</div>}
            {lastPass.notes?.length > 0 && <ul className="mt-1 space-y-0.5 text-zinc-400">{lastPass.notes.map((n: string, i: number) => <li key={i}>· {n}</li>)}</ul>}
            {lastPass.errors?.length > 0 && <ul className="mt-1 space-y-0.5 text-red-300">{lastPass.errors.map((n: string, i: number) => <li key={i}>· {n}</li>)}</ul>}
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
                    <Td className="whitespace-nowrap text-xs text-zinc-400">{when(a.applied_at || a.seen_at)}<div className="text-[11px] text-zinc-600">#{a.id} · {a.trigger}</div></Td>
                    <Td className="text-xs text-zinc-300">{KIND_LABEL[a.kind] || a.kind}</Td>
                    <Td>{a.title}<div className="text-xs text-zinc-500">{a.reason}</div></Td>
                    <Td className="text-right text-emerald-300">{a.est_usd_month != null ? usd(a.est_usd_month, 2) : "—"}</Td>
                    <Td className={`text-xs ${STATUS_CLASS[a.status] || ""}`}>{a.status}{a.notify_result && <div className="text-[11px] text-zinc-600" title={a.notify_result}>sphinx: {a.notify_result.split(":")[0]}</div>}</Td>
                    <td className="whitespace-nowrap px-2 py-2 text-right align-top" onClick={(e: React.MouseEvent) => e.stopPropagation()}>
                      {a.status === "proposed" && <Button className="!px-2 !py-1 !text-xs" onClick={() => run(`/actions/${a.id}/apply`, `apply-${a.id}`)} disabled={busy === `apply-${a.id}` || mode === "off" || !status?.identity?.ok} title={!status?.identity?.ok ? "the actuator role is not usable yet" : "make this change now under the actuator role"}>{busy === `apply-${a.id}` ? "Applying…" : "Apply"}</Button>}
                      {a.status === "applied" && <Button variant="ghost" className="!px-2 !py-1 !text-xs" onClick={() => run(`/actions/${a.id}/verify`, `verify-${a.id}`)} disabled={busy === `verify-${a.id}`}>Check</Button>}
                      {(a.status === "applied" || a.status === "verified") && <Button variant="danger" className="ml-1 !px-2 !py-1 !text-xs" onClick={() => run(`/actions/${a.id}/revert`, `revert-${a.id}`)} disabled={busy === `revert-${a.id}` || mode === "off"} title={a.rollback}>{busy === `revert-${a.id}` ? "Reverting…" : "Revert"}</Button>}
                    </td>
                  </tr>
                  {open === a.id && (
                    <tr className="border-t border-zinc-800/40 bg-zinc-900/40"><td colSpan={6} className="p-3">
                      <div className="grid gap-3 text-xs md:grid-cols-3">
                        <div><div className="mb-1 text-zinc-400">Before → after</div><Code>{JSON.stringify(a.before, null, 1)}</Code><div className="my-1 text-center text-zinc-600">↓</div><Code>{JSON.stringify(a.after, null, 1)}</Code></div>
                        <div><div className="mb-1 text-zinc-400">Facts the decision was made on</div><Code className="max-h-64 overflow-auto">{JSON.stringify(a.facts, null, 1)}</Code></div>
                        <div className="space-y-2">
                          <div><div className="text-zinc-400">Resource</div><div className="font-mono text-zinc-200">{a.resource}{a.region ? ` · ${a.region}` : ""}</div></div>
                          <div><div className="text-zinc-400">Undo</div><div className="text-zinc-200">{a.rollback}</div></div>
                          {a.result && <div><div className="text-zinc-400">Result</div><div className="text-zinc-200">{a.result}</div></div>}
                          {a.error && <div><div className="text-zinc-400">Error</div><div className="text-red-300">{a.error}</div></div>}
                          <div className="text-zinc-500">proposed {when(a.created_at)} · last seen {when(a.seen_at)}{a.applied_at && ` · applied ${when(a.applied_at)}`}{a.verified_at && ` · verified ${when(a.verified_at)}`}{a.reverted_at && ` · reverted ${when(a.reverted_at)}`} · mode {a.mode}</div>
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

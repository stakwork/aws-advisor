import { useState } from "react";
import { Link } from "react-router-dom";
import { api, usd } from "../api";
import { Badge, Button } from "./ui";

/** What the Overview card and the Alerts page show about an alert's investigation. */
export interface IncidentSummary {
  id: number;
  status: string;
  cause: string | null;
  confidence: number | null;
  episode_cost_usd: number | null;
  monthly_run_rate_usd: number | null;
  fixes: { title: string; action_type: string; recommendation_id?: number; est_monthly_saving?: number; tier?: string; status?: string; decided_by?: string | null; decision_scope?: string | null }[];
  error?: string | null;
}

/** GET /api/alerts rows carry the latest incident as incident_* columns; null when the alert was never investigated. */
export function incidentOfAlertRow(a: any): IncidentSummary | null {
  if (!a?.incident_id) return null;
  return { id: a.incident_id, status: a.incident_status, cause: a.incident_cause, confidence: a.incident_confidence, episode_cost_usd: a.incident_episode_cost_usd,
    monthly_run_rate_usd: a.incident_monthly_run_rate_usd, fixes: Array.isArray(a.incident_fixes) ? a.incident_fixes : [], error: a.incident_error };
}

/** Break the agent's cause into readable paragraphs: blank lines first; a single long block is cut every two sentences. */
export function paragraphs(text: string, sentencesPer = 2): string[] {
  const blocks = text.split(/\n\s*\n/).map((b) => b.trim()).filter(Boolean);
  if (blocks.length > 1 || text.length < 320) return blocks;
  // Lossless: split only on whitespace that follows a sentence end and precedes a capital, digit or bracket,
  // so "m6g.xlarge", "2.1 GB" and "e.g." stay whole.
  const sentences = text.split(/(?<=[.!?])\s+(?=[A-Z0-9("'\[])/).map((x) => x.trim()).filter(Boolean);
  const out: string[] = [];
  for (let i = 0; i < sentences.length; i += sentencesPer) out.push(sentences.slice(i, i + sentencesPer).join(" "));
  return out;
}

export const pct = (v: number | null | undefined) => (v == null ? "—" : `${Math.round(Number(v) * 100)}%`);

/** Cause, confidence, costs and the fixes as links to their recommendations; pending and failed states inline. */
export function IncidentView({ incident, compact = false }: { incident: IncidentSummary; compact?: boolean }) {
  if (incident.status === "pending") return <div className="text-xs text-zinc-500"><Badge>running</Badge> the agent is investigating; the result arrives on the webhook, usually within a few minutes.</div>;
  if (incident.status !== "completed") return <div className="text-xs text-red-300"><Badge>failed</Badge> {String(incident.error || "the investigation failed").slice(0, 300)}</div>;
  return (
    <div className={`space-y-2 ${compact ? "text-xs" : "text-sm"}`}>
      <div className="space-y-2 leading-relaxed text-zinc-200">{paragraphs(incident.cause || "").map((p, i) => <p key={i}>{p}</p>)}</div>
      <div className="flex flex-wrap gap-x-4 gap-y-0.5 text-xs text-zinc-400">
        <span>confidence <span className="text-zinc-200">{pct(incident.confidence)}</span></span>
        <span>episode <span className="text-zinc-200">{usd(incident.episode_cost_usd, 2)}</span></span>
        <span>run-rate <span className="text-zinc-200">{usd(incident.monthly_run_rate_usd)}</span> / month if it persists</span>
      </div>
      {incident.fixes.length > 0 && (
        <ul className="space-y-1 text-xs">
          {incident.fixes.map((f, i) => <FixRow key={i} fix={f} />)}
        </ul>
      )}
    </div>
  );
}

/** The action for an alert: Investigate when nothing ran yet, the status otherwise (with "again" once finished). */
export function InvestigateButton({ incident, enabled, busy, onClick }: { incident: IncidentSummary | null; enabled: boolean; busy: boolean; onClick: () => void }) {
  if (!enabled) return null;
  if (incident?.status === "pending") return <Badge>investigating</Badge>;
  return <Button variant="ghost" className="!px-2 !py-1 !text-xs" onClick={onClick} disabled={busy}>{busy ? "Starting…" : incident ? "Investigate again" : "Investigate"}</Button>;
}


const TIER_HELP: Record<string, string> = {
  auto: "tier auto: reversible, the executor may run it without a human (not yet implemented)",
  approve: "tier approve: needs a human decision before anything happens",
  report: "tier report: never automated; for a human to consider",
};

/** One proposed fix: title links to its recommendation; Approve/Reject act on it in place. */
function FixRow({ fix }: { fix: IncidentSummary["fixes"][number] }) {
  // decided already (from the API's live status) or decided just now in this view
  const [status, setStatus] = useState<string | null>(fix.status && fix.status !== "open" ? fix.status : null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const decide = async (s: "approved" | "rejected") => {
    if (!fix.recommendation_id) return;
    const reason = s === "rejected" ? window.prompt("Why reject? (it teaches the agent)") : null;
    if (s === "rejected" && !reason) return;
    setBusy(true); setErr("");
    try { await api(`/recommendations/${fix.recommendation_id}/decision`, { method: "POST", body: JSON.stringify({ status: s, reason, by: "ui" }) }); setStatus(s); }
    catch (e: any) { setErr(e.message); }
    finally { setBusy(false); }
  };
  return (
    <li className="flex flex-wrap items-center justify-between gap-2">
      <span className="flex min-w-0 items-center gap-2">
        {fix.recommendation_id
          ? <Link className="truncate hover:underline" to={`/recommendations?status=all&id=${fix.recommendation_id}`}>{fix.title}</Link>
          : <span className="truncate text-zinc-300">{fix.title}</span>}
        {fix.est_monthly_saving ? <span className="shrink-0 text-zinc-300">{usd(fix.est_monthly_saving)}/mo</span> : null}
      </span>
      <span className="flex shrink-0 items-center gap-1.5">
        {fix.tier && <span title={TIER_HELP[fix.tier] || `tier ${fix.tier}`}><Badge>{fix.tier}</Badge></span>}
        <span className="text-zinc-500">{fix.action_type}</span>
        {fix.recommendation_id && (status
          ? <span className="flex items-center gap-1"><Badge>{status}</Badge>{fix.decided_by && <span className="text-[11px] text-zinc-500">by {fix.decided_by}{fix.decision_scope ? ` · ${fix.decision_scope}` : ""}</span>}<Link className="text-[11px] text-sky-300 hover:underline" to={`/recommendations?status=all&id=${fix.recommendation_id}`}>open</Link></span>
          : <>
              <Button variant="ghost" className="!px-2 !py-0.5 !text-[11px]" disabled={busy} onClick={() => decide("approved")}>Approve</Button>
              <Button variant="ghost" className="!px-2 !py-0.5 !text-[11px]" disabled={busy} onClick={() => decide("rejected")}>Reject</Button>
              <Link className="text-[11px] text-sky-300 hover:underline" to={`/recommendations?status=all&id=${fix.recommendation_id}`}>open</Link>
            </>)}
        {err && <span className="text-[11px] text-red-300">{err}</span>}
      </span>
    </li>
  );
}

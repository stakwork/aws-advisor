import { useEffect, useState } from "react";
import { api } from "../api";

/** GET /api/instances/:id/usage (src/usage_profile.ts): the hours of the week, quiet or busy, and the schedule that fits. */
type Bucket = { day: number; hour: number; seen: number; quiet: number; verdict: "quiet" | "busy" | "unknown"; cpu_avg: number | null; cpu_max: number | null; net_mb: number | null; requests: number | null; probes: number; busy_cpu?: number; busy_net?: number; busy_requests?: number; busy_probe?: number; busy_logs?: number; log_signals?: number | null; busy_probe_kinds?: Record<string, number>; ext_conn: number; signals: number; requests_seen: number; logins: number; logs: number; busy_containers: number };
type Window = { label: string; hours: number; effective_hours: number; confidence: number; probe_coverage: number };
type Review = { reviewed_at: string; verdict: "confirm" | "adjust" | "keep_running"; schedule: string | null; off_hours_week: number | null; est_usd_month: number | null; confidence: number; quiet_is_real: number | null; busy_is_machine: number | null; reason: string; options: Record<string, string> };
type Investigation = { id: number; status: string; result: any; error: string | null; score: number | null; created_at: string; finished_at: string | null; below_bar: string[] | null };
type Profile = { investigation?: Investigation | null; review?: Review | null; follows?: { schedule: string | null; source: "review" | "profile" | null; note: string } | null; subject: string; kind: string; computed_at: string; window_days: number; signals: { cloudwatch_hours: number; probes: number; requests: boolean; log_hours?: number }; hours: Bucket[]; quiet_windows: Window[]; busiest: { label: string; cpu_avg: number; net_mb: number | null }[]; quiet_hours_week: number; confidence: number; suggested_schedule: string | null; off_hours_week: number | null; est_usd_month: number | null; summary: string };

const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const KIND_LABEL: Record<string, string> = { ext_conn: "external connections", users: "users on the box", signals: "use-signal lines", requests: "front-door requests", logins: "logins", containers: "busy container" };


function cellClass(b: Bucket): string {
  if (b.verdict === "quiet") return "bg-emerald-500/60";
  if (b.verdict === "unknown") return b.seen ? "bg-zinc-600/50" : "bg-zinc-800/60";
  const cpu = b.cpu_avg ?? 0;
  return cpu >= 40 ? "bg-amber-400" : cpu >= 15 ? "bg-amber-500/80" : "bg-amber-600/50";
}

function cellTitle(b: Bucket): string {
  const parts = [`${DAYS[b.day]} ${String(b.hour).padStart(2, "0")}:00 UTC · ${b.verdict}${b.seen ? ` (${b.quiet}/${b.seen} weeks quiet)` : " (not seen)"}`];
  if (b.cpu_avg != null) parts.push(`CPU avg ${b.cpu_avg} %, max ${b.cpu_max != null ? Math.round(b.cpu_max * 10) / 10 : "?"} %`);
  if (b.net_mb != null) parts.push(`${b.net_mb} MB/h`);
  if (b.requests != null) parts.push(`${b.requests} requests/h`);
  if (b.log_signals != null) parts.push(`${b.log_signals} use-signal lines/h in the shipped logs`);
  if (b.verdict === "busy") parts.push(`busy because of: ${[b.busy_net ? `network (${b.busy_net}×)` : null, b.busy_cpu ? `CPU (${b.busy_cpu}×)` : null, b.busy_requests ? `requests (${b.busy_requests}×)` : null, b.busy_logs ? `shipped logs (${b.busy_logs}×)` : null, b.busy_probe ? `probe signals (${b.busy_probe}×${(() => { const k = Object.entries(b.busy_probe_kinds || {}).filter(([, n]) => n).map(([k, n]) => `${KIND_LABEL[k] || k} ${n}`).join(", "); return k ? `: ${k}` : ""; })()})` : null].filter(Boolean).join(", ") || "?"}`);
  if (b.probes) parts.push(`${b.probes} probe${b.probes === 1 ? "" : "s"}: ${[b.ext_conn ? `${b.ext_conn} external conn` : null, b.signals ? `${b.signals}× use signal` : null, b.requests_seen ? `${b.requests_seen}× request` : null, b.logins ? `${b.logins}× login` : null, b.busy_containers ? `${b.busy_containers}× busy container` : null, b.logs ? `${b.logs}× logs` : null].filter(Boolean).join(", ") || "nothing"}`);
  return parts.join("\n");
}

/** The chips above the grid: how many hours are busy and which signal tripped them, per signal, hot when it did. */
function WhyBusy({ hours }: { hours: Bucket[] }) {
  const busy = hours.filter((b) => b.verdict === "busy");
  if (!busy.length) return null;
  const sum = (k: keyof Bucket) => busy.reduce((s, b) => s + (Number(b[k]) || 0), 0);
  const kinds: Record<string, number> = {};
  for (const b of busy) for (const [k, n] of Object.entries(b.busy_probe_kinds || {})) kinds[k] = (kinds[k] || 0) + n;
  const chip = (label: string, n: number, always = false) => (!n && !always) ? null : <span key={label} className={`rounded-md border px-2 py-0.5 text-xs ${n ? "border-amber-700/50 bg-amber-950/40 text-amber-200" : "border-zinc-800 bg-zinc-900 text-zinc-500"}`}>{label} · {n}</span>;
  return (
    <div className="mt-2 flex flex-wrap gap-1.5">
      <span className="rounded-md border border-zinc-800 bg-zinc-900 px-2 py-0.5 text-xs text-zinc-200">{busy.length} busy hours a week</span>
      {chip("network over 5 MB/h", sum("busy_net"), true)}
      {chip("CPU over 10 %", sum("busy_cpu"), true)}
      {chip("balancer requests", sum("busy_requests"))}
      {chip("use-signal lines in shipped logs", sum("busy_logs"))}
      {Object.entries(kinds).map(([k, n]) => chip(`probe: ${KIND_LABEL[k] || k}`, n))}
    </div>
  );
}

export function UsageProfile({ subject, running }: { subject: string; running: boolean }) {
  const [p, setP] = useState<Profile | null | undefined>(undefined);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const load = () => api(`/instances/${encodeURIComponent(subject)}/usage`).then(setP).catch((e) => { setP(null); setErr(e.message); });
  useEffect(() => { setP(undefined); setErr(""); load(); }, [subject]);
  const refresh = () => { setBusy(true); setErr(""); api(`/instances/${encodeURIComponent(subject)}/usage/refresh`, { method: "POST" }).then(() => load()).catch((e) => setErr(e.message)).finally(() => setBusy(false)); };
  const [asking, setAsking] = useState(false);
  const ask = () => { setAsking(true); setErr(""); api(`/instances/${encodeURIComponent(subject)}/usage/review`, { method: "POST", body: "{}" }).then(() => load()).catch((e) => setErr(e.message)).finally(() => setAsking(false)); };
  const [sending, setSending] = useState(false);
  const investigate = () => { setSending(true); setErr(""); api(`/instances/${encodeURIComponent(subject)}/usage/investigate`, { method: "POST", body: "{}" }).then(() => load()).catch((e) => setErr(e.message)).finally(() => setSending(false)); };
  // a pending investigation: poll until it lands
  useEffect(() => { if (p?.investigation?.status !== "pending") return; const t = setInterval(() => load(), 20000); return () => clearInterval(t); }, [p?.investigation?.status, subject]);
  const head = (
    <div className="flex items-center justify-between text-[11px] uppercase tracking-wide text-zinc-500">
      <span>Usage by hour of the week{p ? ` · ${p.window_days} days, computed ${new Date(p.computed_at).toLocaleString()}` : ""}</span>
      <span className="flex gap-3">{running && p?.kind === "ec2" && <button className="text-xs normal-case tracking-normal text-sky-300 hover:underline disabled:text-zinc-600" disabled={asking || busy} onClick={ask}>{asking ? "asking Jev…" : p?.review ? "ask Jev again" : "ask Jev"}</button>}{running && p?.kind === "ec2" && <button className="text-xs normal-case tracking-normal text-sky-300 hover:underline disabled:text-zinc-600" disabled={sending || p?.investigation?.status === "pending"} onClick={investigate} title="Send this box to the agent: it reads the probes, logs, metrics and peers with the tools and decides">{sending ? "sending…" : p?.investigation?.status === "pending" ? "agent looking…" : "investigate with the agent"}</button>}{running && <button className="text-xs normal-case tracking-normal text-sky-300 hover:underline disabled:text-zinc-600" disabled={busy || asking} onClick={refresh}>{busy ? "profiling…" : p ? "recompute" : "profile now"}</button>}</span>
    </div>
  );
  if (p === undefined) return <div>{head}<div className="mt-1 text-xs text-zinc-500">Loading…</div></div>;
  if (!p) return <div>{head}<div className="mt-1 text-xs text-zinc-500">{err || "No usage profile yet: the daily logs job builds one for every running standalone instance."}</div></div>;
  return (
    <div>
      {head}
      <ul className="mt-1 space-y-0.5 text-sm text-zinc-300">
        {p.summary.replace(/ \d+ busy hours of the week; what tripped them[^.]*\.(?= |$)/, "").split(/\. (?=[a-z])/).map((s) => s.replace(/\.$/, "")).filter(Boolean).map((s, i) => <li key={i} className="flex gap-2"><span className="text-zinc-600">·</span><span>{s.charAt(0).toUpperCase() + s.slice(1)}</span></li>)}
      </ul>
      <WhyBusy hours={p.hours} />
      {p.kind === "ec2" && (
        <div className={`mt-2 rounded-md border px-2.5 py-2 text-xs ${p.review ? (p.review.verdict === "keep_running" ? "border-zinc-700 bg-zinc-900/60" : "border-emerald-700/40 bg-emerald-950/30") : "border-zinc-800 bg-zinc-900/40"}`}>
          {p.review ? (
            <>
              <div className="flex flex-wrap items-center gap-2"><span className="font-medium text-zinc-200">{String((p.review as any).model || "").startsWith("agent") ? "Agent's decision (investigation)" : "Jev's decision"}</span><span className={`rounded-full border px-2 py-0.5 ${p.review.verdict === "keep_running" ? "border-zinc-600 text-zinc-300" : "border-emerald-600/50 text-emerald-300"}`}>{p.review.verdict === "confirm" ? "confirms the window" : p.review.verdict === "adjust" ? "sets a different window" : "keep it running"}</span>{p.review.schedule && <span className="font-mono text-zinc-200">advisor:schedule={p.review.schedule}</span>}{p.review.off_hours_week != null && <span className="text-zinc-500">off {p.review.off_hours_week} h/week{p.review.est_usd_month ? ` · ≈ ${p.review.est_usd_month} USD/month` : ""}</span>}<span className="text-zinc-500">· {new Date(p.review.reviewed_at).toLocaleString()}</span></div>
              <div className="mt-1 text-zinc-400">{p.review.reason}</div>
              {p.follows && <div className="mt-1 text-zinc-500">With AdvisorAutoPark=ON the executor {p.follows.schedule ? <>follows <span className="font-mono text-zinc-300">{p.follows.schedule}</span></> : "leaves the box running"}{p.follows.source === "review" ? " (Jev's decision)" : p.follows.source === "profile" ? " (the profile's own window; no Jev configured)" : ""}.</div>}
            </>
          ) : (
            <div className="text-zinc-500">No decision yet: Jev reviews every profile once a day with the activity, the peers, the containers and the role, and picks the window the executor follows for a box tagged AdvisorAutoPark=ON. {p.follows?.note}</div>
          )}
          {p.investigation && (
            <div className="mt-2 border-t border-zinc-800 pt-2">
              <div className="flex flex-wrap items-center gap-2 text-zinc-300"><span className="font-medium">Agent investigation #{p.investigation.id}</span><span className={`rounded-full border px-2 py-0.5 ${p.investigation.status === "completed" ? "border-emerald-600/50 text-emerald-300" : p.investigation.status === "pending" ? "border-sky-600/50 text-sky-300" : "border-red-600/50 text-red-300"}`}>{p.investigation.status === "pending" ? "looking at the box now" : p.investigation.status}</span>{p.investigation.score != null && <span className="text-zinc-500">score {p.investigation.score.toFixed(2)}{p.investigation.below_bar ? ` · below the bar: ${p.investigation.below_bar.join(", ")}` : ""}</span>}<span className="text-zinc-500">· {new Date(p.investigation.created_at.replace(" ", "T") + "Z").toLocaleString()}</span></div>
              {p.investigation.status === "pending" && <div className="mt-1 text-zinc-500">The agent reads the probes, the container logs, the metrics, the peers, the balancers and the ledger with its tools, usually a few minutes. This refreshes by itself.</div>}
              {p.investigation.status === "failed" && p.investigation.error && <div className="mt-1 text-red-300">{p.investigation.error}</div>}
              {p.investigation.status === "completed" && p.investigation.result && (
                <div className="mt-1 space-y-1 text-zinc-400">
                  {(() => { const ws: any[] = p.investigation!.result.safe_off_windows || p.investigation!.result.downsize_windows || []; return ws.length ? <div className="flex flex-wrap gap-1.5">{ws.map((w: any, i: number) => <span key={i} title={w.why || ""} className={`rounded-md border px-2 py-0.5 ${w.certain ? "border-emerald-700/50 bg-emerald-950/40 text-emerald-200" : "border-zinc-700 bg-zinc-900 text-zinc-500 line-through"}`}>{p.investigation!.result.downsize_windows ? "run small" : "safe off"} {w.days} {String(w.start).padStart(2, "0")}-{String(w.end).padStart(2, "0")} UTC{w.certain ? "" : " (not certain)"}</span>)}</div> : null; })()}
                  {(p.investigation.result.group_min_size != null || p.investigation.result.group_max_size != null) && <div className="text-zinc-300">Group bounds the agent asks for: {p.investigation.result.group_min_size != null ? `minimum ${p.investigation.result.group_min_size}` : "minimum unchanged"}{p.investigation.result.group_max_size != null ? `, maximum ${p.investigation.result.group_max_size}` : ""}</div>}
                  {p.investigation.result.min_off_hours != null && <div className="text-zinc-500">Shortest stop worth making for this box, per the agent: {p.investigation.result.min_off_hours} h</div>}
                  {p.investigation.result.reasoning && <div>{p.investigation.result.reasoning}</div>}
                  {Array.isArray(p.investigation.result.evidence) && p.investigation.result.evidence.length > 0 && <ul className="list-disc space-y-0.5 pl-4">{p.investigation.result.evidence.map((e: string, i: number) => <li key={i}>{e}</li>)}</ul>}
                  {Array.isArray(p.investigation.result.busy_hours_explained) && p.investigation.result.busy_hours_explained.length > 0 && <div><span className="text-zinc-500">Busy hours: </span>{p.investigation.result.busy_hours_explained.map((b: any, i: number) => <span key={i} className={`mr-2 ${b.is_people ? "text-amber-200" : "text-zinc-400"}`}>{b.when}: {b.cause}{b.is_people ? " (people)" : " (machine)"}</span>)}</div>}
                </div>
              )}
            </div>
          )}
        </div>
      )}
      {p.suggested_schedule && <div className="mt-1 text-xs text-zinc-400">Suggested tag: <span className="font-mono text-zinc-200">advisor:schedule={p.suggested_schedule}</span>{p.off_hours_week != null ? ` · off ${p.off_hours_week} h/week` : ""}{p.est_usd_month ? ` · ≈ ${p.est_usd_month} USD/month` : ""} · confidence {p.confidence}{p.kind === "asg" ? (p.confidence >= 0.85 ? " (the capacity action drops the minimum to the floor in these windows once the environment is tagged)" : " (under 0.85: no window scheduling until more weeks back it)") : p.confidence >= 0.85 ? " (a recommendation is filed; approving it puts the tag on)" : " (under 0.85: no recommendation until more weeks or probes back it)"}</div>}
      <div className="mt-2 overflow-x-auto">
        <div className="inline-grid gap-px" style={{ gridTemplateColumns: "2.2rem repeat(24, minmax(0.9rem, 1fr))" }}>
          <div />
          {Array.from({ length: 24 }, (_, h) => <div key={h} className="text-center text-[9px] text-zinc-600">{h % 3 === 0 ? String(h).padStart(2, "0") : ""}</div>)}
          {DAYS.map((d, di) => (
            <>
              <div key={`l${d}`} className="pr-1 text-right text-[10px] text-zinc-500">{d}</div>
              {p.hours.filter((b) => b.day === di).map((b) => <div key={`${di}-${b.hour}`} title={cellTitle(b)} className={`h-3.5 rounded-sm ${cellClass(b)}`} />)}
            </>
          ))}
        </div>
      </div>
      <div className="mt-1 flex flex-wrap gap-3 text-[10px] text-zinc-500">
        <span><span className="mr-1 inline-block h-2 w-2 rounded-sm bg-emerald-500/60" />quiet every week</span>
        <span><span className="mr-1 inline-block h-2 w-2 rounded-sm bg-amber-500/80" />busy in some week (darker = more CPU)</span>
        <span><span className="mr-1 inline-block h-2 w-2 rounded-sm bg-zinc-600/50" />too few weeks</span>
        <span><span className="mr-1 inline-block h-2 w-2 rounded-sm bg-zinc-800/60" />not seen (off)</span>
        <span>· {p.signals.cloudwatch_hours} CloudWatch hours{p.kind === "asg" ? " of the group" : ""}, {p.signals.probes} probes{p.signals.requests ? ", balancer requests" : ""}{p.signals.log_hours ? `, ${p.signals.log_hours} h of shipped logs scanned` : ""}{p.kind === "asg" ? " · members come and go; the group is what is measured" : ""}</span>
      </div>
      {p.quiet_windows.length > 0 && <ul className="mt-1 text-xs text-zinc-400">{p.quiet_windows.slice(0, 5).map((w) => <li key={w.label}>{w.label}: {w.effective_hours} h off ({w.hours} h quiet, margins taken) · confidence {w.confidence} · probes in {Math.round(w.probe_coverage * 100)} %</li>)}</ul>}
      {err && <div className="mt-1 text-xs text-red-300">{err}</div>}
    </div>
  );
}

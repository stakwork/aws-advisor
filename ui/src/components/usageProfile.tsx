import { useEffect, useState } from "react";
import { api } from "../api";

/** GET /api/instances/:id/usage (src/usage_profile.ts): the hours of the week, quiet or busy, and the schedule that fits. */
type Bucket = { day: number; hour: number; seen: number; quiet: number; verdict: "quiet" | "busy" | "unknown"; cpu_avg: number | null; cpu_max: number | null; net_mb: number | null; requests: number | null; probes: number; busy_cpu?: number; busy_net?: number; busy_requests?: number; busy_probe?: number; ext_conn: number; signals: number; requests_seen: number; logins: number; logs: number; busy_containers: number };
type Window = { label: string; hours: number; effective_hours: number; confidence: number; probe_coverage: number };
type Profile = { subject: string; kind: string; computed_at: string; window_days: number; signals: { cloudwatch_hours: number; probes: number; requests: boolean }; hours: Bucket[]; quiet_windows: Window[]; busiest: { label: string; cpu_avg: number; net_mb: number | null }[]; quiet_hours_week: number; confidence: number; suggested_schedule: string | null; off_hours_week: number | null; est_usd_month: number | null; summary: string };

const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

function cellClass(b: Bucket): string {
  if (b.verdict === "quiet") return "bg-emerald-500/60";
  if (b.verdict === "unknown") return b.seen ? "bg-zinc-600/50" : "bg-zinc-800/60";
  const cpu = b.cpu_avg ?? 0;
  return cpu >= 40 ? "bg-amber-400" : cpu >= 15 ? "bg-amber-500/80" : "bg-amber-600/50";
}

function cellTitle(b: Bucket): string {
  const parts = [`${DAYS[b.day]} ${String(b.hour).padStart(2, "0")}:00 UTC · ${b.verdict}${b.seen ? ` (${b.quiet}/${b.seen} weeks quiet)` : " (not seen)"}`];
  if (b.cpu_avg != null) parts.push(`CPU avg ${b.cpu_avg} %, max ${b.cpu_max ?? "?"} %`);
  if (b.net_mb != null) parts.push(`${b.net_mb} MB/h`);
  if (b.requests != null) parts.push(`${b.requests} requests/h`);
  if (b.verdict === "busy") parts.push(`busy because of: ${[b.busy_net ? `network (${b.busy_net}×)` : null, b.busy_cpu ? `CPU (${b.busy_cpu}×)` : null, b.busy_requests ? `requests (${b.busy_requests}×)` : null, b.busy_probe ? `probe signals (${b.busy_probe}×)` : null].filter(Boolean).join(", ") || "?"}`);
  if (b.probes) parts.push(`${b.probes} probe${b.probes === 1 ? "" : "s"}: ${[b.ext_conn ? `${b.ext_conn} external conn` : null, b.signals ? `${b.signals}× use signal` : null, b.requests_seen ? `${b.requests_seen}× request` : null, b.logins ? `${b.logins}× login` : null, b.busy_containers ? `${b.busy_containers}× busy container` : null, b.logs ? `${b.logs}× logs` : null].filter(Boolean).join(", ") || "nothing"}`);
  return parts.join("\n");
}

export function UsageProfile({ subject, running }: { subject: string; running: boolean }) {
  const [p, setP] = useState<Profile | null | undefined>(undefined);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const load = () => api(`/instances/${encodeURIComponent(subject)}/usage`).then(setP).catch((e) => { setP(null); setErr(e.message); });
  useEffect(() => { setP(undefined); setErr(""); load(); }, [subject]);
  const refresh = () => { setBusy(true); setErr(""); api(`/instances/${encodeURIComponent(subject)}/usage/refresh`, { method: "POST" }).then((r) => setP(r)).catch((e) => setErr(e.message)).finally(() => setBusy(false)); };
  const head = (
    <div className="flex items-center justify-between text-[11px] uppercase tracking-wide text-zinc-500">
      <span>Usage by hour of the week{p ? ` · ${p.window_days} days, computed ${new Date(p.computed_at).toLocaleString()}` : ""}</span>
      {running && <button className="text-xs normal-case tracking-normal text-sky-300 hover:underline disabled:text-zinc-600" disabled={busy} onClick={refresh}>{busy ? "profiling…" : p ? "recompute" : "profile now"}</button>}
    </div>
  );
  if (p === undefined) return <div>{head}<div className="mt-1 text-xs text-zinc-500">Loading…</div></div>;
  if (!p) return <div>{head}<div className="mt-1 text-xs text-zinc-500">{err || "No usage profile yet: the daily logs job builds one for every running standalone instance."}</div></div>;
  return (
    <div>
      {head}
      <div className="mt-1 text-sm text-zinc-300">{p.summary}</div>
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
        <span>· {p.signals.cloudwatch_hours} CloudWatch hours{p.kind === "asg" ? " of the group" : ""}, {p.signals.probes} probes{p.signals.requests ? ", balancer requests" : ""}{p.kind === "asg" ? " · members come and go; the group is what is measured" : ""}</span>
      </div>
      {p.quiet_windows.length > 0 && <ul className="mt-1 text-xs text-zinc-400">{p.quiet_windows.slice(0, 5).map((w) => <li key={w.label}>{w.label}: {w.effective_hours} h off ({w.hours} h quiet, margins taken) · confidence {w.confidence} · probes in {Math.round(w.probe_coverage * 100)} %</li>)}</ul>}
      {err && <div className="mt-1 text-xs text-red-300">{err}</div>}
    </div>
  );
}

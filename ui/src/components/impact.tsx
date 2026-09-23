import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api, usd, when } from "../api";
import { Badge, Button } from "./ui";

/**
 * How a decision moved the bill (GET /api/verifications/:id/impact, src/verify.ts impactFor): the daily cost of
 * the lines the action moves, fourteen days before the decision to the latest complete day, the before and
 * after medians the verdict came from, and the account's total spend for context.
 */
const W = 720, H = 150, PL = 44, PR = 8, PT = 10, PB = 22;

const dayMs = (d: string) => Date.parse(`${d}T00:00:00Z`);
const short = (d: string) => d.slice(5);
const verdictTone: Record<string, string> = { realised: "text-emerald-300", partial: "text-amber-300", none: "text-zinc-400", increase: "text-red-300" };

export function ImpactChart({ recId, compact = false }: { recId: number; compact?: boolean }) {
  const [d, setD] = useState<any | null | undefined>(undefined);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const [hover, setHover] = useState<string | null>(null);
  const load = () => api(`/verifications/${recId}/impact`).then(setD).catch((e) => { setErr(e.message); setD(null); });
  useEffect(() => { setD(undefined); setErr(""); load(); }, [recId]);
  const check = async () => {
    setBusy(true); setErr("");
    try { await api(`/verifications/run?id=${recId}&force=1`, { method: "POST" }); await load(); }
    catch (e: any) { setErr(e.message); }
    finally { setBusy(false); }
  };

  const model = useMemo(() => {
    if (!d?.series?.length) return null;
    const series: { day: string; usd: number }[] = d.series;
    const days = series.map((r) => r.day);
    const first = days[0], last = days[days.length - 1];
    const n = Math.max(1, Math.round((dayMs(last) - dayMs(first)) / 86400e3) + 1);
    const slot = (W - PL - PR) / n;
    const x = (day: string) => PL + ((dayMs(day) - dayMs(first)) / 86400e3) * slot;
    const max = Math.max(1, ...series.map((r) => r.usd)) * 1.15;
    const innerH = H - PT - PB;
    const y = (v: number) => PT + innerH - (innerH * Math.max(0, v)) / max;
    const v = d.verification;
    const total: { day: string; usd: number }[] = (d.total || []).filter((r: any) => r.day >= first && r.day <= last);
    const tmax = Math.max(1, ...total.map((r) => r.usd)) * 1.15;
    const ty = (val: number) => PT + innerH - (innerH * Math.max(0, val)) / tmax;
    return { series, first, last, n, slot, x, y, max, innerH, v, total, ty, tmax };
  }, [d]);

  const v = d?.verification;
  const cls = compact ? "text-xs" : "text-sm";
  return (
    <div className={`rounded border border-zinc-800 bg-zinc-950/60 p-3 ${cls}`}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="font-medium text-zinc-200">Effect on the bill{v?.scope_note ? <span className="font-normal text-zinc-500"> · {v.scope_note}</span> : null}</span>
        <div className="flex items-center gap-2">
          {v?.verdict && <Badge>{v.verdict === "too_early" ? "info" : v.verdict === "realised" ? "done" : v.verdict === "increase" ? "failed" : v.verdict === "partial" ? "warning" : v.verdict === "none" ? "open" : "info"}</Badge>}
          <Button variant="ghost" className="!px-2 !py-1 !text-xs" onClick={check} disabled={busy}>{busy ? "Checking…" : v ? "Check again" : "Check now"}</Button>
        </div>
      </div>
      {err && <div className="mt-1 text-red-300">{err}</div>}
      {d === undefined && !err && <div className="mt-1 text-zinc-500">Loading…</div>}
      {d && !v && <div className="mt-1 text-zinc-500">Not checked yet. The daily verification compares the lines this action moves before and after {d.decided_day ? `the decision on ${d.decided_day}` : "the decision"}, from seven days after it; Check now reads the bill as it is today.</div>}
      {v && (
        <div className="mt-1 text-zinc-300">
          {v.verdict === "not_verifiable" ? <span className="text-zinc-500">{v.note}</span>
            : v.verdict === "too_early" || v.verdict === "no_data" ? <span className="text-zinc-500">{v.note}</span>
            : <>
              <span className={verdictTone[v.verdict] || "text-zinc-300"}>{v.verdict === "increase" ? "cost went up" : v.verdict === "none" ? "no change" : v.verdict}</span>
              {v.realised_usd_month != null && <> · <span className="text-zinc-100">{v.realised_usd_month >= 0 ? "saving" : "extra"} {usd(Math.abs(v.realised_usd_month))} / month</span></>}
              {v.estimate_usd_month != null && <span className="text-zinc-500"> of {usd(v.estimate_usd_month)} claimed{v.ratio != null ? ` (${Math.round(v.ratio * 100)}%)` : ""}</span>}
              {v.before_usd_day != null && v.after_usd_day != null && <div className="text-zinc-500">{v.before_usd_day.toFixed(2)} USD/day before → {v.after_usd_day.toFixed(2)} USD/day after (medians) · {v.days_after} day{v.days_after === 1 ? "" : "s"} since the decision · checked {when(v.checked_at)}</div>}
              {v.applied && <div className="text-zinc-500">inventory: applied {v.applied}</div>}
            </>}
        </div>
      )}
      {model && (
        <div className="mt-2">
          <svg viewBox={`0 0 ${W} ${H}`} className="w-full" onMouseLeave={() => setHover(null)}
            onMouseMove={(e) => { const r = (e.currentTarget as SVGSVGElement).getBoundingClientRect(); const px = ((e.clientX - r.left) / r.width) * W; const i = Math.floor((px - PL) / model.slot); const day = i >= 0 && i < model.n ? new Date(dayMs(model.first) + i * 86400e3).toISOString().slice(0, 10) : null; setHover(day); }}>
            {[0, model.max / 2, model.max].map((tick) => (
              <g key={tick}>
                <line x1={PL} x2={W - PR} y1={model.y(tick)} y2={model.y(tick)} stroke="currentColor" strokeOpacity={tick === 0 ? 0.4 : 0.12} />
                <text x={PL - 6} y={model.y(tick) + 3.5} textAnchor="end" fontSize="10" fill="currentColor" fillOpacity="0.55">{Math.round(tick)}</text>
              </g>
            ))}
            {model.series.map((r) => {
              const after = r.day >= (d.after_from || d.decided_day); const mixed = r.day >= d.decided_day && r.day < (d.after_from || d.decided_day);
              return <rect key={r.day} x={model.x(r.day) + 1} y={model.y(r.usd)} width={Math.max(1, model.slot - 2)} height={model.y(0) - model.y(r.usd)} fill={mixed ? "#71717a" : after ? "#34d399" : "#f97316"} fillOpacity={hover === r.day ? 1 : 0.75} />;
            })}
            {model.v?.before_usd_day != null && <line x1={PL} x2={model.x(d.decided_day)} y1={model.y(model.v.before_usd_day)} y2={model.y(model.v.before_usd_day)} stroke="#f97316" strokeDasharray="4 3" strokeWidth="1.5" />}
            {model.v?.after_usd_day != null && <line x1={model.x(d.after_from || d.decided_day)} x2={W - PR} y1={model.y(model.v.after_usd_day)} y2={model.y(model.v.after_usd_day)} stroke="#34d399" strokeDasharray="4 3" strokeWidth="1.5" />}
            {d.decided_day && d.decided_day >= model.first && <><line x1={model.x(d.decided_day)} x2={model.x(d.decided_day)} y1={PT} y2={model.y(0)} stroke="#e4e4e7" strokeOpacity="0.7" strokeWidth="1.5" /><text x={model.x(d.decided_day) + 3} y={PT + 9} fontSize="10" fill="currentColor" fillOpacity="0.7">decision {short(d.decided_day)}</text></>}
            {model.total.length > 1 && <path d={model.total.map((r, i) => `${i ? "L" : "M"}${(model.x(r.day) + model.slot / 2).toFixed(1)},${model.ty(r.usd).toFixed(1)}`).join(" ")} fill="none" stroke="#a1a1aa" strokeOpacity="0.5" strokeWidth="1.5" />}
            {[model.first, model.last].map((day) => <text key={day} x={model.x(day) + model.slot / 2} y={H - 6} textAnchor="middle" fontSize="10" fill="currentColor" fillOpacity="0.55">{short(day)}</text>)}
          </svg>
          <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] text-zinc-500">
            <span><span className="text-orange-400">■</span> before · <span className="text-emerald-400">■</span> after · <span className="text-zinc-400">■</span> decision day and the next (mixed, not counted) · <span className="text-zinc-400">—</span> whole bill, own scale</span>
            <span className="text-zinc-300">{hover ? (() => { const r = model.series.find((s) => s.day === hover); const t = model.total.find((s) => s.day === hover); return `${hover}: ${r ? usd(r.usd, 2) : "—"} on these lines${t ? ` · bill ${usd(t.usd)}` : ""}`; })() : `${model.series.length} days`}</span>
          </div>
        </div>
      )}
    </div>
  );
}

/** Every actioned recommendation with what it claimed and what the bill shows, for the Overview. */
export function ImpactList({ limit = 8 }: { limit?: number }) {
  const [v, setV] = useState<any>(null);
  useEffect(() => { api("/verifications").then(setV).catch(() => setV(null)); }, []);
  if (!v) return <div className="text-sm text-zinc-500">Loading…</div>;
  if (!v.rows?.length) return <div className="text-sm text-zinc-500">Nothing actioned yet. Approve a recommendation or mark one done and, seven days later, this shows what the bill did.</div>;
  const rows = v.rows.slice(0, limit);
  return (
    <div className="space-y-2">
      <div className="text-xs text-zinc-500">{v.actioned} actioned · claimed {usd(v.claimed_usd_month)}/mo · realised {usd(v.realised_usd_month)}/mo{v.pending ? ` · ${v.pending} awaiting ${v.min_days_after} days` : ""}</div>
      <ul className="divide-y divide-zinc-800">
        {rows.map((r: any) => (
          <li key={r.id} className="flex items-center justify-between gap-3 py-2 text-sm">
            <div className="min-w-0">
              <Link to={`/recommendations?status=${r.status}&id=${r.id}`} className="block truncate hover:underline">{r.title}</Link>
              <div className="text-xs text-zinc-500">{r.status} {when(r.decided_at)}{r.merged?.length ? ` · one decision for #${r.merged_ids.join(", #")}` : ""}{r.verdict && r.verdict !== "too_early" && r.verdict !== "not_verifiable" && r.before_usd_day != null ? ` · ${r.before_usd_day.toFixed(2)} → ${r.after_usd_day?.toFixed(2)} USD/day` : r.verdict === "too_early" ? ` · ${r.days_after} of ${v.min_days_after} days` : r.verdict === "not_verifiable" ? " · not measurable on the bill" : " · not checked yet"}</div>
            </div>
            <span className="flex shrink-0 items-center gap-2 text-right">
              {r.verdict && !["too_early", "not_verifiable", "no_data"].includes(r.verdict) && <span className={`w-20 font-medium ${verdictTone[r.verdict] || "text-zinc-300"}`}>{r.realised_usd_month != null ? `${r.realised_usd_month < 0 ? "+" : ""}${usd(Math.abs(r.realised_usd_month))}` : "—"}</span>}
              <span className="w-16 text-xs text-zinc-500">of {usd(r.est_monthly_saving)}</span>
            </span>
          </li>
        ))}
      </ul>
      {v.rows.length > limit && <Link to="/recommendations?status=approved" className="text-xs text-zinc-500 hover:text-zinc-300">and {v.rows.length - limit} more →</Link>}
    </div>
  );
}

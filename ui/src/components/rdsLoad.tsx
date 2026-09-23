import { useEffect, useState } from "react";
import { api, when } from "../api";
import { Badge, Button } from "./ui";

/**
 * The load profile of a database (GET /api/inventory/rds/:id/load, src/rds_load.ts): what the hourly pass read
 * from CloudWatch, Performance Insights and the log, and Jev's classification of it. Inventory shows it under
 * an RDS row; Recommendations shows it under an Aurora or RDS recommendation.
 */
export function useRdsLoad(id: string | null | undefined) {
  const [row, setRow] = useState<any | null | undefined>(undefined);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const load = (target: string) => api(`/inventory/rds/${encodeURIComponent(target)}/load`).then(setRow).catch(() => setRow(null));
  useEffect(() => { setRow(undefined); setError(""); if (id) load(id); else setRow(null); }, [id]);
  const refresh = async () => {
    if (!id) return;
    setBusy(true); setError("");
    try { setRow(await api(`/inventory/rds/${encodeURIComponent(id)}/load/refresh`, { method: "POST" })); }
    catch (e: any) { setError(e.message); }
    finally { setBusy(false); }
  };
  return { row, busy, error, refresh };
}

const pct = (v: number | null | undefined) => (v == null ? "—" : `${Math.round(v * 100)}%`);
const m = (v: number | null | undefined, d = 1) => (v == null ? "—" : `${(v / 1e6).toFixed(d)}M`);
const words = (s: string | null | undefined) => (s || "").replace(/_/g, " ");
const Row = ({ k, children }: { k: string; children: React.ReactNode }) => (children == null || children === "" ? null : <><dt className="text-zinc-500">{k}</dt><dd className="min-w-0 break-words">{children}</dd></>);

export function RdsLoadPanel({ id, compact = false }: { id: string | null | undefined; compact?: boolean }) {
  const { row, busy, error, refresh } = useRdsLoad(id);
  const p = row?.profile; const c = p?.capacity; const j = row?.jev; const st = row?.statements; const sl = row?.slow_log;
  return (
    <div className={`rounded border border-zinc-800 bg-zinc-950/60 p-3 ${compact ? "text-xs" : "text-sm"}`}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="font-medium text-zinc-200">Load profile{p ? <span className="font-normal text-zinc-500"> · {p.window_days} days · collected {when(row.collected_at)}</span> : null}</span>
        <div className="flex items-center gap-2">
          {p && <Badge>{p.shape === "unknown" ? "info" : p.shape}</Badge>}
          <Button variant="ghost" className="!px-2 !py-1 !text-xs" onClick={refresh} disabled={busy || !id}>{busy ? "Collecting…" : row ? "Refresh" : "Collect now"}</Button>
        </div>
      </div>
      {error && <div className="mt-1 text-red-300">{error}</div>}
      {row === undefined && !error && <div className="mt-1 text-zinc-500">Loading…</div>}
      {row === null && !error && <div className="mt-1 text-zinc-500">No load profile yet. The hourly probe pass collects one for every database in the inventory (CloudWatch, Performance Insights, the log tail) and Jev classifies it; Collect now does it here.</div>}
      {p && (
        <div className="mt-2 space-y-3">
          {j && (
            <div className="rounded border border-violet-500/20 bg-violet-500/5 p-2">
              <div className="text-[11px] uppercase tracking-wide text-violet-300">Jev's read</div>
              <div className="mt-1 text-zinc-200">{words(j.shape)} ({pct(j.shape_confidence)}) · I/O driven by <span className="text-zinc-100">{words(j.io_cause)}</span> ({pct(j.io_cause_confidence)})</div>
              <div className="mt-0.5 text-zinc-400">throttled by the capacity ceiling {pct(j.throttled_by_cap)} · structural {pct(j.structural)} · first lever <span className="text-zinc-200">{words(j.lever)}</span> ({pct(j.lever_confidence)})<span className="text-zinc-600"> · {when(j.classified_at)}</span></div>
            </div>
          )}
          {p.notes?.length > 0 && <ul className="list-disc space-y-0.5 pl-5 text-zinc-300">{p.notes.map((n: string, i: number) => <li key={i}>{n}</li>)}</ul>}
          <dl className="grid grid-cols-[9.5rem_1fr] gap-x-3 gap-y-0.5">
            <Row k="I/O per day">{p.io.reads_per_day != null ? <>{m(p.io.reads_per_day)} reads · {m(p.io.writes_per_day, 2)} writes{p.io.read_write_ratio != null ? ` · ${p.io.read_write_ratio}:1` : ""}{p.io.io_cost_standard_usd_month != null ? <span className="text-zinc-500"> · ≈ {Math.round(p.io.io_cost_standard_usd_month)} USD/month on Standard storage</span> : null}</> : null}</Row>
            <Row k="Volume">{p.io.storage_gb != null ? `${p.io.storage_gb} GB` : null}</Row>
            <Row k="Buffer cache hit">{p.io.buffer_cache_hit_pct_avg != null ? `${p.io.buffer_cache_hit_pct_avg}% avg · ${p.io.buffer_cache_hit_pct_min}% min` : null}</Row>
            {c && <>
              <Row k="Capacity">{c.configured_min != null ? `${c.configured_min} to ${c.configured_max} ACU configured · ` : ""}{c.avg_acu} ACU avg · {c.min_acu} to {c.max_acu} observed</Row>
              <Row k="Time at the cap">{pct(c.pct_time_at_cap)}<span className="text-zinc-500"> · at the floor {pct(c.pct_time_at_floor)}</span></Row>
              <Row k="Bursts">{c.bursts.count ? <>{c.bursts.per_day} a day · median {c.bursts.median_minutes} min, longest {c.bursts.longest_minutes} min{c.bursts.cadence ? ` · ${c.bursts.cadence}${c.bursts.cadence === "hourly" && c.bursts.top_start_minute != null ? ` around minute ${c.bursts.top_start_minute}` : ""}` : ""}</> : "none"}</Row>
              <Row k="Buffer cache">{`≈ ${c.cache_gib_avg} GiB at the average capacity, ${c.cache_gib_at_cap} GiB at the cap`}{c.db_fits_in_cache_at_avg != null ? <span className={c.db_fits_in_cache_at_avg ? "text-emerald-300" : "text-amber-300"}> · the database {c.db_fits_in_cache_at_avg ? "fits" : "does not fit"} at the average{!c.db_fits_in_cache_at_avg && c.db_fits_in_cache_at_cap ? ", fits at the cap" : ""}</span> : null}</Row>
            </>}
            <Row k="CPU">{p.cpu.avg_pct != null ? `${p.cpu.avg_pct}% avg · p95 ${p.cpu.p95_pct}% · max ${p.cpu.max_pct}%` : null}</Row>
            <Row k="Connections">{p.connections.avg != null ? `${p.connections.avg} avg · ${p.connections.max} max` : null}</Row>
          </dl>
          <div>
            <div className="text-[11px] uppercase tracking-wide text-zinc-500">Top statements (Performance Insights, {st?.window_days ?? 7} days)</div>
            {st?.statements?.length ? <ol className="mt-1 list-decimal space-y-1 pl-5 font-mono text-[11px] text-zinc-300">{st.statements.slice(0, 8).map((s: any, i: number) => <li key={i}><span className="text-zinc-500">{s.share_pct}% </span>{s.sql}</li>)}</ol>
              : <div className="mt-0.5 text-zinc-500">{st?.error || st?.note || "none"}</div>}
          </div>
          <div>
            <div className="text-[11px] uppercase tracking-wide text-zinc-500">Slow statements (engine log tail{sl?.files?.length ? `: ${sl.files.join(", ")}` : ""})</div>
            {sl?.statements?.length ? <ol className="mt-1 list-decimal space-y-1 pl-5 font-mono text-[11px] text-zinc-300">{sl.statements.slice(0, 8).map((s: any, i: number) => <li key={i}><span className="text-zinc-500">{s.count}× · {Math.round(s.total_ms / 1000)} s total · max {s.max_ms} ms </span>{s.sql}</li>)}</ol>
              : <div className="mt-0.5 text-zinc-500">{sl?.error || sl?.note || (sl ? `${sl.lines_scanned} lines, no statement durations` : "none")}</div>}
            {sl && (sl.temp_file_lines > 0 || sl.checkpoint_lines > 0) && <div className="mt-0.5 text-zinc-500">{sl.temp_file_lines} temp-file lines · {sl.checkpoint_lines} checkpoint lines in the tail</div>}
          </div>
          {p.daily?.length > 0 && (
            <details>
              <summary className="cursor-pointer text-zinc-500">Per day</summary>
              <table className="mt-1 w-full text-[11px]"><thead><tr className="text-zinc-500"><th className="text-left font-normal">Day</th><th className="text-right font-normal">Reads</th><th className="text-right font-normal">Writes</th>{c && <th className="text-right font-normal">Avg ACU</th>}<th className="text-right font-normal">CPU avg</th></tr></thead>
                <tbody>{p.daily.map((d: any) => <tr key={d.day} className="border-t border-zinc-800/60"><td className="py-0.5">{d.day}</td><td className="text-right">{m(d.reads)}</td><td className="text-right">{m(d.writes, 2)}</td>{c && <td className="text-right">{d.avg_acu ?? "—"}</td>}<td className="text-right">{d.cpu_avg != null ? `${d.cpu_avg}%` : "—"}</td></tr>)}</tbody></table>
            </details>
          )}
        </div>
      )}
    </div>
  );
}

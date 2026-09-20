import { useEffect, useMemo, useState } from "react";
import { api } from "../api";

type ProbePt = { t: string; mem_pct: number | null; mem_used_gb: number | null; disk_pct: number | null; disk_mount: string | null; load1: number | null; load_per_cpu: number | null; cpus: number | null; top_process: string | null };
type CpuPt = { t: string; avg: number; max: number };

const W = 720, H = 92, PL = 40, PR = 8, PT = 8, PB = 18;

function Series({ title, unit, points, points2, max, x, hoverT, onHover, color = "#f97316", color2 }:
  { title: string; unit: string; points: { t: number; v: number }[]; points2?: { t: number; v: number }[]; max: number; x: (t: number) => number; hoverT: number | null; onHover: (t: number | null) => void; color?: string; color2?: string }) {
  const innerH = H - PT - PB;
  const y = (v: number) => PT + innerH - (innerH * Math.min(max, Math.max(0, v))) / max;
  const path = (pts: { t: number; v: number }[]) => pts.map((p, i) => `${i ? "L" : "M"}${x(p.t).toFixed(1)},${y(p.v).toFixed(1)}`).join(" ");
  const nearest = hoverT != null && points.length ? points.reduce((a, b) => (Math.abs(b.t - hoverT) < Math.abs(a.t - hoverT) ? b : a)) : null;
  const nearest2 = hoverT != null && points2?.length ? points2.reduce((a, b) => (Math.abs(b.t - hoverT) < Math.abs(a.t - hoverT) ? b : a)) : null;
  return (
    <div>
      <div className="flex items-baseline justify-between text-[11px] text-zinc-500">
        <span>{title}</span>
        <span className="text-zinc-300">{nearest ? `${nearest.v}${unit}${nearest2 ? ` · max ${nearest2.v}${unit}` : ""}` : points.length ? `latest ${points[points.length - 1].v}${unit}` : "no data"}</span>
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full" onMouseLeave={() => onHover(null)}
        onMouseMove={(e) => { const r = (e.currentTarget as SVGSVGElement).getBoundingClientRect(); const px = ((e.clientX - r.left) / r.width) * W; onHover(px < PL || px > W - PR ? null : (px - PL)); }}>
        {[0, max / 2, max].map((tick) => (
          <g key={tick}>
            <line x1={PL} x2={W - PR} y1={y(tick)} y2={y(tick)} stroke="currentColor" strokeOpacity={tick === 0 ? 0.4 : 0.12} />
            <text x={PL - 6} y={y(tick) + 3.5} textAnchor="end" fontSize="10" fill="currentColor" fillOpacity="0.55">{tick}{unit}</text>
          </g>
        ))}
        {points2 && points2.length > 1 && <path d={path(points2)} fill="none" stroke={color2 || color} strokeOpacity="0.45" strokeWidth="1.5" />}
        {points.length > 1 && <path d={path(points)} fill="none" stroke={color} strokeWidth="2" />}
        {points.map((p) => <circle key={p.t} cx={x(p.t)} cy={y(p.v)} r={points.length > 60 ? 1.5 : 2.5} fill={color} />)}
        {nearest && <><line x1={x(nearest.t)} x2={x(nearest.t)} y1={PT} y2={PT + innerH} stroke="currentColor" strokeOpacity="0.35" /><circle cx={x(nearest.t)} cy={y(nearest.v)} r="4" fill={color} stroke="#18181b" strokeWidth="1.5" /></>}
      </svg>
    </div>
  );
}

type DailyPt = { day: string; samples: number; mem_pct_avg: number | null; mem_pct_max: number | null; disk_pct_avg: number | null; disk_pct_max: number | null; load_per_cpu_avg: number | null; load_per_cpu_max: number | null; containers_running_avg: number | null };
type ContainerStat = { name: string; image: string; days: number; running_share: number | null; cpu_pct_avg: number | null; cpu_pct_max: number | null; mem_bytes_avg: number | null; mem_bytes_max: number | null; first_day: string; last_day: string };
type ContainerNow = { name: string; image: string; state: string; running_for: string; cpu_pct: number | null; mem_bytes: number; mem_pct: number | null };

const WINDOWS: { label: string; hours?: number; days?: number }[] = [{ label: "24h", hours: 24 }, { label: "48h", hours: 48 }, { label: "7d", hours: 168 }, { label: "30d", days: 30 }, { label: "90d", days: 90 }];
const gb = (b: number | null | undefined) => (b == null ? "—" : b >= 1e9 ? `${(b / 1e9).toFixed(1)} GB` : `${Math.round(b / 1e6)} MB`);
const pct = (v: number | null | undefined, d = 0) => (v == null ? "—" : `${Number(v).toFixed(d)}%`);

/** Memory, disk, load and CPU for one instance: hourly from the SSM probes and CloudWatch, or daily roll-ups for 30/90 days. */
export function InstanceCharts({ instanceId }: { instanceId: string }) {
  const [win, setWin] = useState(1);
  const w = WINDOWS[win];
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-end gap-1 text-xs">
        {WINDOWS.map((o, i) => <button key={o.label} onClick={() => setWin(i)} className={`rounded border px-1.5 py-0.5 ${i === win ? "border-zinc-400 text-zinc-100" : "border-zinc-700 text-zinc-400 hover:bg-zinc-800"}`}>{o.label}</button>)}
      </div>
      {w.hours ? <HourlyCharts instanceId={instanceId} hours={w.hours} /> : <DailyCharts instanceId={instanceId} days={w.days!} />}
      <ContainersTable instanceId={instanceId} days={w.days ?? 30} />
    </div>
  );
}

function HourlyCharts({ instanceId, hours }: { instanceId: string; hours: number }) {
  const [d, setD] = useState<any>(null);
  const [err, setErr] = useState("");
  const [hoverPx, setHoverPx] = useState<number | null>(null);
  useEffect(() => { setD(null); api(`/instances/${instanceId}/timeseries?hours=${hours}`).then(setD).catch((e) => setErr(e.message)); }, [instanceId, hours]);

  const model = useMemo(() => {
    if (!d) return null;
    const probes: ProbePt[] = d.probes || []; const cpu: CpuPt[] = d.cpu || [];
    const end = Date.now(); const start = end - hours * 3600 * 1000;
    const x = (t: number) => PL + ((W - PL - PR) * (t - start)) / (end - start);
    const ts = (s: string) => new Date(s).getTime();
    const pick = (k: keyof ProbePt) => probes.filter((p) => p[k] != null && ts(p.t) >= start).map((p) => ({ t: ts(p.t), v: Number(p[k]) }));
    return {
      start, end, x,
      mem: pick("mem_pct"), disk: pick("disk_pct"), load: pick("load_per_cpu").map((p) => ({ t: p.t, v: Math.round(p.v * 100) })),
      cpuAvg: cpu.filter((c) => ts(c.t) >= start).map((c) => ({ t: ts(c.t), v: c.avg })),
      cpuMax: cpu.filter((c) => ts(c.t) >= start).map((c) => ({ t: ts(c.t), v: c.max })),
      diskMount: probes.find((p) => p.disk_mount)?.disk_mount || "/",
      cpus: probes.find((p) => p.cpus)?.cpus || null,
      probeAt: (t: number) => probes.reduce((a: ProbePt | null, p) => (!a || Math.abs(ts(p.t) - t) < Math.abs(ts(a.t) - t) ? p : a), null),
    };
  }, [d, hours]);

  if (err) return <div className="text-xs text-red-300">{err}</div>;
  if (!d || !model) return <div className="text-xs text-zinc-500">loading hourly data…</div>;
  const hoverT = hoverPx != null ? model.start + ((model.end - model.start) * hoverPx) / (W - PL - PR) : null;
  const near = hoverT != null ? model.probeAt(hoverT) : null;
  const ticks: number[] = []; for (let t = Math.ceil(model.start / (6 * 3600e3)) * 6 * 3600e3; t <= model.end; t += 6 * 3600e3) ticks.push(t);
  const fmt = (t: number) => { const dt = new Date(t); return dt.getHours() === 0 ? dt.toLocaleDateString(undefined, { month: "short", day: "numeric" }) : dt.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" }); };
  const noProbes = model.mem.length === 0;
  return (
    <div className="space-y-2">
      <div className="text-xs text-zinc-500">Hourly · {d.probes.length} probes{d.cpu.length ? ` · ${d.cpu.length} CloudWatch hours` : ""}{model.cpus ? ` · ${model.cpus} vCPU` : ""}</div>
      {noProbes && <div className="text-xs text-zinc-500">No probe samples in this window yet; the hourly pass fills it in. CPU below comes from CloudWatch.</div>}
      <Series title="Memory used" unit="%" points={model.mem} max={100} x={model.x} hoverT={hoverT} onHover={setHoverPx} />
      <Series title={`Disk used (${model.diskMount})`} unit="%" points={model.disk} max={100} x={model.x} hoverT={hoverT} onHover={setHoverPx} color="#eab308" />
      <Series title="Load (1 min, % of cores)" unit="%" points={model.load} max={Math.max(100, ...model.load.map((p) => p.v))} x={model.x} hoverT={hoverT} onHover={setHoverPx} color="#a78bfa" />
      <Series title="CPU (CloudWatch, avg and max)" unit="%" points={model.cpuAvg} points2={model.cpuMax} max={100} x={model.x} hoverT={hoverT} onHover={setHoverPx} color="#38bdf8" color2="#38bdf8" />
      {d.cpu_error && <div className="text-[11px] text-zinc-500">CPU series unavailable: {d.cpu_error}</div>}
      <div className="flex justify-between text-[10px] text-zinc-500">{ticks.filter((_, i) => i % Math.max(1, Math.round(ticks.length / 6)) === 0).map((t) => <span key={t}>{fmt(t)}</span>)}</div>
      {near && hoverT != null && (
        <div className="rounded border border-zinc-800 bg-zinc-950/70 px-2 py-1 text-[11px] text-zinc-300">
          {new Date(near.t).toLocaleString()} · memory {near.mem_pct}% ({near.mem_used_gb} GB) · disk {near.disk_pct}% · load {near.load1}{near.top_process ? ` · top: ${near.top_process}` : ""}
        </div>
      )}
    </div>
  );
}

/** Daily averages (line) and daily maxima (faint line) from instance_daily, rolled up after each probe pass. */
function DailyCharts({ instanceId, days }: { instanceId: string; days: number }) {
  const [d, setD] = useState<any>(null);
  const [err, setErr] = useState("");
  const [hoverPx, setHoverPx] = useState<number | null>(null);
  useEffect(() => { setD(null); api(`/instances/${instanceId}/history?days=${days}`).then(setD).catch((e) => setErr(e.message)); }, [instanceId, days]);

  const model = useMemo(() => {
    if (!d) return null;
    const rows: DailyPt[] = d.daily || [];
    const end = Date.now(); const start = end - days * 86400e3;
    const x = (t: number) => PL + ((W - PL - PR) * (t - start)) / (end - start);
    const ts = (day: string) => Date.parse(`${day}T12:00:00Z`);
    const pick = (k: keyof DailyPt, scale = 1) => rows.filter((r) => r[k] != null).map((r) => ({ t: ts(r.day), v: Math.round(Number(r[k]) * scale) }));
    return {
      start, end, x, rows,
      memAvg: pick("mem_pct_avg"), memMax: pick("mem_pct_max"),
      diskAvg: pick("disk_pct_avg"), diskMax: pick("disk_pct_max"),
      loadAvg: pick("load_per_cpu_avg", 100), loadMax: pick("load_per_cpu_max", 100),
      containers: pick("containers_running_avg"),
      rowAt: (t: number) => rows.reduce((a: DailyPt | null, r) => (!a || Math.abs(ts(r.day) - t) < Math.abs(ts(a.day) - t) ? r : a), null),
    };
  }, [d, days]);

  if (err) return <div className="text-xs text-red-300">{err}</div>;
  if (!d || !model) return <div className="text-xs text-zinc-500">loading daily roll-ups…</div>;
  const hoverT = hoverPx != null ? model.start + ((model.end - model.start) * hoverPx) / (W - PL - PR) : null;
  const near = hoverT != null ? model.rowAt(hoverT) : null;
  const ticks: number[] = []; const step = days > 45 ? 14 : 7;
  for (let t = model.end - Math.floor(days / step) * step * 86400e3; t <= model.end; t += step * 86400e3) ticks.push(t);
  const fmt = (t: number) => new Date(t).toLocaleDateString(undefined, { month: "short", day: "numeric" });
  const loadMax = Math.max(100, ...model.loadMax.map((p) => p.v));
  return (
    <div className="space-y-2">
      <div className="text-xs text-zinc-500">Daily · {model.rows.length} day{model.rows.length === 1 ? "" : "s"} rolled up · line = daily average, faint line = daily max</div>
      {model.rows.length === 0 && <div className="text-xs text-zinc-500">No daily roll-ups yet. They are built from the hourly probes at the end of each probe pass (today's row included and updated every pass).</div>}
      <Series title="Memory used" unit="%" points={model.memAvg} points2={model.memMax} max={100} x={model.x} hoverT={hoverT} onHover={setHoverPx} />
      <Series title="Disk used" unit="%" points={model.diskAvg} points2={model.diskMax} max={100} x={model.x} hoverT={hoverT} onHover={setHoverPx} color="#eab308" />
      <Series title="Load (1 min, % of cores)" unit="%" points={model.loadAvg} points2={model.loadMax} max={loadMax} x={model.x} hoverT={hoverT} onHover={setHoverPx} color="#a78bfa" />
      <Series title="Containers running" unit="" points={model.containers} max={Math.max(4, ...model.containers.map((p) => p.v))} x={model.x} hoverT={hoverT} onHover={setHoverPx} color="#38bdf8" />
      <div className="flex justify-between text-[10px] text-zinc-500">{ticks.map((t) => <span key={t}>{fmt(t)}</span>)}</div>
      {near && hoverT != null && (
        <div className="rounded border border-zinc-800 bg-zinc-950/70 px-2 py-1 text-[11px] text-zinc-300">
          {near.day} · {near.samples} probes · memory avg {pct(near.mem_pct_avg)} max {pct(near.mem_pct_max)} · disk avg {pct(near.disk_pct_avg)} · load avg {near.load_per_cpu_avg == null ? "—" : Math.round(near.load_per_cpu_avg * 100)}% of cores{near.containers_running_avg != null ? ` · ${near.containers_running_avg.toFixed(1)} containers` : ""}
        </div>
      )}
    </div>
  );
}

/** Per-container statistics over the window (from container_daily), with the latest probe's containers as a fallback before the first roll-up. */
function ContainersTable({ instanceId, days }: { instanceId: string; days: number }) {
  const [d, setD] = useState<{ containers: ContainerStat[]; containers_now: ContainerNow[] } | null>(null);
  useEffect(() => { setD(null); api(`/instances/${instanceId}/history?days=${days}`).then(setD).catch(() => setD({ containers: [], containers_now: [] })); }, [instanceId, days]);
  if (!d) return null;
  const stats = d.containers || []; const now = d.containers_now || [];
  if (!stats.length && !now.length) return <div className="text-[11px] text-zinc-500">No containers reported by the probe (Docker not present, or the SSM document predates the container section).</div>;
  return (
    <div>
      <div className="mb-1 text-[11px] text-zinc-500">Containers · {stats.length ? `${stats.length} seen over ${days} days · averages and maxima across daily roll-ups` : `${now.length} from the latest probe (daily roll-ups appear after the next probe pass)`}</div>
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-[11px]">
          <thead className="text-zinc-500"><tr><th className="py-1 text-left font-normal">Container</th><th className="text-left font-normal">Image</th><th className="text-right font-normal">Running</th><th className="text-right font-normal">CPU avg / max</th><th className="text-right font-normal">Memory avg / max</th><th className="text-right font-normal">{stats.length ? "Days" : "Up for"}</th></tr></thead>
          <tbody>
            {stats.length ? stats.map((c) => (
              <tr key={c.name} className="border-t border-zinc-800/70">
                <td className="py-1 pr-2 font-mono text-zinc-200">{c.name}</td>
                <td className="max-w-56 truncate pr-2 text-zinc-400" title={c.image}>{c.image}</td>
                <td className="text-right">{c.running_share == null ? "—" : `${Math.round(c.running_share * 100)}%`}</td>
                <td className="text-right">{pct(c.cpu_pct_avg, 1)} / {pct(c.cpu_pct_max, 1)}</td>
                <td className="text-right">{gb(c.mem_bytes_avg)} / {gb(c.mem_bytes_max)}</td>
                <td className="text-right text-zinc-400">{c.days}</td>
              </tr>
            )) : now.map((c) => (
              <tr key={c.name} className="border-t border-zinc-800/70">
                <td className="py-1 pr-2 font-mono text-zinc-200">{c.name}</td>
                <td className="max-w-56 truncate pr-2 text-zinc-400" title={c.image}>{c.image}</td>
                <td className="text-right">{c.state}</td>
                <td className="text-right">{pct(c.cpu_pct, 1)}</td>
                <td className="text-right">{gb(c.mem_bytes)}{c.mem_pct != null ? ` (${pct(c.mem_pct, 1)})` : ""}</td>
                <td className="text-right text-zinc-400">{c.running_for || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/**
 * Host alerts from every probe, beside the disk levels: memory used, swap in use, load per core sustained over
 * an hour, and a reboot (uptime lower than the previous probe's). One open alert per instance and kind, closed
 * by the system when the level falls under its threshold minus a margin. Thresholds are runtime settings.
 */
import { config } from "./config.js";
import { db } from "./db.js";

export type HostKind = "memory_high" | "memory_full" | "swap_in_use" | "load_high" | "reboot";
export interface HostSample { collected_at: string; cpus: number; mem_used_pct: number | null; swap_used_pct: number | null; load1: number | null; load5: number | null; load15: number | null; uptime_seconds: number | null }

/** Pure: which host alerts the sample warrants, given what is open and the previous sample. */
export function hostVerdicts(s: HostSample, prev: HostSample | null, t: { memWarn: number; memAlarm: number; swapWarn: number; loadPerCore: number }, open: Set<HostKind>): { raise: { kind: HostKind; message: string; details: Record<string, unknown> }[]; close: HostKind[] } {
  const raise: { kind: HostKind; message: string; details: Record<string, unknown> }[] = []; const close: HostKind[] = [];
  const m = s.mem_used_pct;
  if (m != null) {
    const full = m >= t.memAlarm || (open.has("memory_full") && m >= t.memAlarm - 5);
    const high = !full && (m >= t.memWarn || (open.has("memory_high") && m >= t.memWarn - 5));
    if (full && !open.has("memory_full")) { raise.push({ kind: "memory_full", message: `memory ${m.toFixed(0)}% used; the kernel starts killing processes when it runs out`, details: { mem_used_pct: m } }); if (open.has("memory_high")) close.push("memory_high"); }
    else if (high && !open.has("memory_high")) { raise.push({ kind: "memory_high", message: `memory ${m.toFixed(0)}% used`, details: { mem_used_pct: m } }); if (open.has("memory_full")) close.push("memory_full"); }
    else if (!full && !high) { if (open.has("memory_full")) close.push("memory_full"); if (open.has("memory_high")) close.push("memory_high"); }
  }
  const sw = s.swap_used_pct;
  if (sw != null) {
    const on = sw >= t.swapWarn || (open.has("swap_in_use") && sw >= Math.max(1, t.swapWarn - 5));
    if (on && !open.has("swap_in_use")) raise.push({ kind: "swap_in_use", message: `swap ${sw.toFixed(0)}% in use: memory is short and the box is paging`, details: { swap_used_pct: sw, mem_used_pct: m } });
    if (!on && open.has("swap_in_use")) close.push("swap_in_use");
  }
  // load: the 15-minute average over the threshold per core is a sustained saturation, not a spike
  if (s.load15 != null && s.cpus > 0) {
    const perCore = s.load15 / s.cpus;
    const on = perCore >= t.loadPerCore || (open.has("load_high") && perCore >= t.loadPerCore * 0.8);
    if (on && !open.has("load_high")) raise.push({ kind: "load_high", message: `load ${s.load15.toFixed(2)} over 15 minutes on ${s.cpus} vCPU (${perCore.toFixed(2)} per core): the box is saturated`, details: { load15: s.load15, load5: s.load5, load1: s.load1, cpus: s.cpus, per_core: perCore } });
    if (!on && open.has("load_high")) close.push("load_high");
  }
  // reboot: uptime went down between two probes (a restart), allowing for the interval between them
  if (prev && s.uptime_seconds != null && prev.uptime_seconds != null && s.uptime_seconds < prev.uptime_seconds) {
    const at = new Date(Date.parse(s.collected_at) - s.uptime_seconds * 1000);
    raise.push({ kind: "reboot", message: `rebooted at about ${at.toISOString().replace("T", " ").slice(0, 16)} UTC (uptime was ${Math.round(prev.uptime_seconds / 3600)} h, now ${Math.round(s.uptime_seconds / 60)} min)`, details: { rebooted_at: at.toISOString(), uptime_before_s: prev.uptime_seconds, uptime_now_s: s.uptime_seconds } });
  }
  return { raise, close };
}

export function sampleFromProbe(collectedAt: string, d: any): HostSample {
  const mem = d?.memory || {};
  return {
    collected_at: collectedAt, cpus: Number(d?.cpus || 0),
    mem_used_pct: mem.total_bytes ? (100 * Number(mem.used_bytes)) / Number(mem.total_bytes) : null,
    swap_used_pct: mem.swap_total_bytes ? (100 * Number(mem.swap_used_bytes || 0)) / Number(mem.swap_total_bytes) : null,
    load1: d?.load?.["1m"] != null ? Number(d.load["1m"]) : null, load5: d?.load?.["5m"] != null ? Number(d.load["5m"]) : null, load15: d?.load?.["15m"] != null ? Number(d.load["15m"]) : null,
    uptime_seconds: d?.uptime_seconds != null ? Number(d.uptime_seconds) : null,
  };
}

const openKinds = db.prepare("select id, kind from alerts where kind in ('memory_high', 'memory_full', 'swap_in_use', 'load_high') and resource = ? and acknowledged = 0");
const insert = db.prepare("insert into alerts(kind, resource, message, details) values (?, ?, ?, ?)");
const ackKind = db.prepare("update alerts set acknowledged = 1, acknowledged_by = 'system' where resource = ? and kind = ? and acknowledged = 0");
const prevProbe = db.prepare("select collected_at, json from instance_metrics where instance_id = ? and id < ? order by id desc limit 1");

/** Applies the verdicts for one probe (called right after it is stored). Returns the alerts raised. */
export function checkHostLevels(instanceId: string, name: string | null, probeRowId: number, collectedAt: string, data: any): number {
  const t = { memWarn: config.memWarnPct, memAlarm: config.memAlarmPct, swapWarn: config.swapWarnPct, loadPerCore: config.loadPerCore };
  const s = sampleFromProbe(collectedAt, data);
  const p = prevProbe.get(instanceId, probeRowId) as { collected_at: string; json: string } | undefined;
  let prev: HostSample | null = null; if (p) { try { prev = sampleFromProbe(p.collected_at, JSON.parse(p.json)); } catch { prev = null; } }
  const open = new Set((openKinds.all(instanceId) as { kind: HostKind }[]).map((r) => r.kind));
  const { raise, close } = hostVerdicts(s, prev, t, open);
  for (const k of close) ackKind.run(instanceId, k);
  const label = name || instanceId;
  for (const r of raise) insert.run(r.kind, instanceId, `${label}: ${r.message}`, JSON.stringify({ summary: `${label}: ${r.message}`, instance_id: instanceId, name: label, probed_at: collectedAt, ...r.details }));
  return raise.length;
}

/** Judges the latest probe of every running instance against its previous one (startup, after a probe pass). */
export function checkAllHostLevels(): { instances: number; raised: number } {
  const rows = db.prepare(`select m.id, m.instance_id, m.collected_at, m.json, i.name from instance_metrics m join inventory_ec2 i on i.instance_id = m.instance_id
    where m.id in (select max(id) from instance_metrics group by instance_id) and i.gone = 0 and i.state = 'running'`).all() as { id: number; instance_id: string; collected_at: string; json: string; name: string | null }[];
  let raised = 0;
  for (const r of rows) { let d: any; try { d = JSON.parse(r.json); } catch { continue; } raised += checkHostLevels(r.instance_id, r.name, r.id, r.collected_at, d); }
  return { instances: rows.length, raised };
}

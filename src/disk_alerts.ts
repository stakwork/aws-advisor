/**
 * Disk level alerts: an absolute check on every mount the probe reports, run after each probe and over the
 * latest probe of every instance at startup. Two thresholds (runtime settings): `disk_high` warning at
 * DISK_WARN_PCT, `disk_full` alarm at DISK_ALARM_PCT. One open alert per instance and mount; it is acknowledged
 * by the system when the level falls five points under the threshold, so a disk hovering at the line does not
 * flap. This is the level today; the daily review's `disk_fill` is the trend (days until full).
 */
import { config } from "./config.js";
import { db } from "./db.js";

export interface DiskLevel { mount: string; used_pct: number; total_bytes?: number | null; used_bytes?: number | null }
export type DiskVerdict = "full" | "high" | "ok";

/** Pure: the verdict for a mount, with hysteresis against the alert currently open for it. */
export function diskVerdict(usedPct: number, thresholds: { warn: number; alarm: number }, open: DiskVerdict | null = null): DiskVerdict {
  if (usedPct >= thresholds.alarm) return "full";
  if (open === "full" && usedPct >= thresholds.alarm - 5) return "full";
  if (usedPct >= thresholds.warn) return "high";
  if (open === "high" && usedPct >= thresholds.warn - 5) return "high";
  return "ok";
}

const gb = (b: number | null | undefined) => (b == null ? null : Math.round((b / 1e9) * 10) / 10);
const openFor = db.prepare("select id, kind from alerts where kind in ('disk_full', 'disk_high') and resource = ? and acknowledged = 0 order by id desc limit 1");
const insert = db.prepare("insert into alerts(kind, resource, message, details) values (?, ?, ?, ?)");
const ack = db.prepare("update alerts set acknowledged = 1, acknowledged_by = 'system' where id = ?");

/** Applies the verdicts for one instance's mounts. Returns the number of alerts raised. */
export function checkDiskLevels(instanceId: string, name: string | null, disks: DiskLevel[], collectedAt: string): number {
  const thresholds = { warn: config.diskWarnPct, alarm: config.diskAlarmPct };
  let raised = 0;
  for (const d of disks) {
    if (!d.mount || !Number.isFinite(Number(d.used_pct))) continue;
    const resource = `${instanceId}:${d.mount}`;
    const open = openFor.get(resource) as { id: number; kind: string } | undefined;
    const openVerdict: DiskVerdict | null = open ? (open.kind === "disk_full" ? "full" : "high") : null;
    const v = diskVerdict(Number(d.used_pct), thresholds, openVerdict);
    const label = name || instanceId;
    const free = d.total_bytes != null && d.used_bytes != null ? gb(d.total_bytes - d.used_bytes) : null;
    if (v === "ok") { if (open) ack.run(open.id); continue; }
    const kind = v === "full" ? "disk_full" : "disk_high";
    if (open && open.kind === kind) continue;
    if (open) ack.run(open.id); // escalation or de-escalation: close the old one, open the new
    const msg = `${label}: ${d.mount} is ${Number(d.used_pct).toFixed(0)}% full${free != null ? ` (${free} GB free of ${gb(d.total_bytes)} GB)` : ""}${v === "full" ? `; ${d.mount === "/" ? "services fail when the root disk fills" : "whatever writes there fails when it fills"}` : ""}`;
    insert.run(kind, resource, msg, JSON.stringify({ summary: msg, instance_id: instanceId, name: label, mount: d.mount, used_pct: Number(d.used_pct), size_gb: gb(d.total_bytes), free_gb: free, threshold: v === "full" ? thresholds.alarm : thresholds.warn, probed_at: collectedAt }));
    raised++;
  }
  return raised;
}

/** Evaluates the latest probe of every running instance (startup, and after a probe pass). */
export function checkAllDiskLevels(): { instances: number; raised: number } {
  const rows = db.prepare(`select m.instance_id, m.collected_at, m.json, i.name from instance_metrics m join inventory_ec2 i on i.instance_id = m.instance_id
    where m.id in (select max(id) from instance_metrics group by instance_id) and i.gone = 0 and i.state = 'running'`).all() as { instance_id: string; collected_at: string; json: string; name: string | null }[];
  let raised = 0;
  for (const r of rows) {
    let d: any; try { d = JSON.parse(r.json); } catch { continue; }
    raised += checkDiskLevels(r.instance_id, r.name, Array.isArray(d.disks) ? d.disks : [], r.collected_at);
  }
  return { instances: rows.length, raised };
}

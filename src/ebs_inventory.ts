/**
 * EBS per volume: every volume with its type, size, provisioned IOPS and throughput, state and attachment,
 * 30 days of read and write IOPS from the daily metric tables, the monthly cost at list (storage plus the
 * provisioned IOPS and throughput above what gp3 includes) and, once the instance has been probed, how full
 * the filesystems on it are. Refreshed with the inventory. The review flags volumes whose provisioned IOPS
 * sit far above what is used.
 *
 * "in-use" is AWS's word for attached, and a volume stays attached to a stopped instance, so the listing
 * carries the instance's state next to the volume's, and the summary counts what sits on stopped instances
 * (billed exactly like the rest).
 *
 * Disk usage comes from the SSM probe (src/ssm.ts): df on every mount, with the whole disk it sits on and, on
 * Nitro, the EBS volume id read from the NVMe serial. A mount is credited to its volume by that id, or on Xen
 * by the device name (/dev/sda1 as attached, /dev/xvda1 in the guest: the same disk). Partitions of one volume
 * are summed. The figures are refreshed after every probe and re-credited after every inventory refresh.
 */
import { db } from "./db.js";
import { S, query } from "./steampipe.js";
import { describeError } from "./permissions.js";

db.exec(`create table if not exists inventory_ebs (
  volume_id text primary key, region text, volume_type text, size_gb integer, iops integer, throughput_mibps integer, state text, encrypted integer,
  instance_id text, device text, created text, name text,
  read_iops_avg real, write_iops_avg real, iops_max real, metric_days integer,
  monthly_usd real, first_seen text not null, last_seen text not null, gone integer not null default 0
)`);
for (const [column, type] of [["total_bytes", "real"], ["used_bytes", "real"], ["used_pct", "real"], ["mounts", "text"], ["usage_at", "text"]]) {
  try { db.exec(`alter table inventory_ebs add column ${column} ${type}`); } catch { /* exists */ }
}

export const EBS_PRICE: Record<string, number> = { gp3: 0.08, gp2: 0.10, io1: 0.125, io2: 0.125, st1: 0.045, sc1: 0.015, standard: 0.05 };
/** Monthly cost at list for one volume: storage, plus gp3 IOPS above 3,000 and throughput above 125 MiB/s, plus io1/io2 IOPS. Pure. */
export function ebsMonthlyCost(v: { volume_type: string; size_gb: number; iops: number | null; throughput_mibps: number | null }): number {
  const storage = v.size_gb * (EBS_PRICE[v.volume_type] ?? 0.08);
  let extra = 0;
  if (v.volume_type === "gp3") { extra += Math.max(0, (v.iops ?? 3000) - 3000) * 0.005 + Math.max(0, (v.throughput_mibps ?? 125) - 125) * 0.04; }
  if (v.volume_type === "io1" || v.volume_type === "io2") extra += (v.iops ?? 0) * 0.065;
  return Math.round((storage + extra) * 100) / 100;
}
/** Included or provisioned IOPS the volume can deliver, for the utilisation ratio. Pure. */
export function ebsProvisionedIops(v: { volume_type: string; size_gb: number; iops: number | null }): number | null {
  if (v.volume_type === "gp3") return v.iops ?? 3000;
  if (v.volume_type === "gp2") return Math.min(16000, Math.max(100, v.size_gb * 3));
  if (v.volume_type === "io1" || v.volume_type === "io2") return v.iops ?? null;
  return null;
}

// ---- disk usage from the probe ----------------------------------------------------------------------

/**
 * The whole disk a device name refers to, so the attachment's /dev/sda1, the Xen guest's /dev/xvda1 and the
 * probe's xvda all agree; an NVMe partition (nvme0n1p1) folds into its disk (nvme0n1). Pure.
 */
export function deviceKey(dev: string | null | undefined): string | null {
  if (!dev) return null;
  let d = String(dev).replace(/^\/dev\//, "");
  if (/^sd[a-z]/.test(d)) d = `xvd${d.slice(2)}`;
  if (/^nvme\d+n\d+/.test(d)) return d.replace(/p\d+$/, "");
  return d.replace(/\d+$/, "") || null;
}

export interface MountUsage { mount: string; filesystem: string; total_bytes: number; used_bytes: number; used_pct: number }
/** One df line as the probe reports it (src/ssm.ts ProbeDisk, or the raw JSON of a stored probe). */
export interface DiskLike { mount?: unknown; filesystem?: unknown; device?: unknown; volume_id?: unknown; total_bytes?: unknown; used_bytes?: unknown; used_pct?: unknown }
export interface VolumeUsage { total_bytes: number; used_bytes: number; used_pct: number; mounts: MountUsage[] }

/**
 * Credits each probed mount to the attached volume it lives on: by the volume id the probe read from the NVMe
 * serial, else by device name (a probe before 1.3 has no device, so its filesystem name stands in: enough on
 * Xen, never on Nitro). Mounts on no known volume (instance store, EFS, LVM over several disks) are left out.
 * Pure.
 */
export function matchDisksToVolumes(disks: DiskLike[], volumes: Array<{ volume_id: string; device: string | null }>): Map<string, VolumeUsage> {
  const ids = new Set(volumes.map((v) => v.volume_id));
  const byDevice = new Map<string, string>();
  for (const v of volumes) { const k = deviceKey(v.device); if (k && !byDevice.has(k)) byDevice.set(k, v.volume_id); }
  const out = new Map<string, VolumeUsage>();
  for (const d of disks) {
    const claimed = d.volume_id ? String(d.volume_id) : null;
    const id = (claimed && ids.has(claimed) ? claimed : null) ?? byDevice.get(deviceKey((d.device ?? d.filesystem) as string) ?? "") ?? null;
    if (!id) continue;
    const total = Number(d.total_bytes || 0), used = Number(d.used_bytes || 0);
    const u = out.get(id) || { total_bytes: 0, used_bytes: 0, used_pct: 0, mounts: [] };
    u.total_bytes += total; u.used_bytes += used;
    u.mounts.push({ mount: String(d.mount ?? ""), filesystem: String(d.filesystem ?? ""), total_bytes: total, used_bytes: used, used_pct: Number(d.used_pct || 0) });
    out.set(id, u);
  }
  for (const u of out.values()) u.used_pct = u.total_bytes > 0 ? Math.round((1000 * u.used_bytes) / u.total_bytes) / 10 : 0;
  return out;
}

/** Records what one probe of an instance saw against the volumes attached to it. Returns how many volumes got a figure. */
export function applyProbeDisks(instanceId: string, disks: DiskLike[], collectedAt: string): number {
  const vols = db.prepare("select volume_id, device from inventory_ebs where instance_id = ? and gone = 0").all(instanceId) as Array<{ volume_id: string; device: string | null }>;
  if (!vols.length) return 0;
  const usage = matchDisksToVolumes(disks, vols);
  const set = db.prepare("update inventory_ebs set total_bytes = ?, used_bytes = ?, used_pct = ?, mounts = ?, usage_at = ? where volume_id = ?");
  db.transaction(() => { for (const [id, u] of usage) set.run(u.total_bytes, u.used_bytes, u.used_pct, JSON.stringify(u.mounts), collectedAt, id); })();
  return usage.size;
}

/** Re-credits the latest probe of every instance, for volumes that arrived or moved since it ran. */
function applyLatestProbes(): number {
  const rows = db.prepare("select instance_id, collected_at, json from instance_metrics where id in (select max(id) from instance_metrics group by instance_id)").all() as Array<{ instance_id: string; collected_at: string; json: string }>;
  let n = 0;
  for (const r of rows) {
    try { const d = JSON.parse(r.json); n += applyProbeDisks(r.instance_id, Array.isArray(d.disks) ? d.disks : [], r.collected_at); } catch { /* malformed probe */ }
  }
  return n;
}

// ---- refresh ------------------------------------------------------------------------------------------

export async function refreshEbsInventory(onError: (m: string) => void = () => {}): Promise<number> {
  let vols: any[];
  try { vols = await query<any>(`select volume_id, region, volume_type, size, iops, throughput, state, encrypted, attachments, create_time, tags ->> 'Name' as name from ${S}.aws_ebs_volume`); }
  catch (e) { onError(describeError(e, "ebs inventory (aws_ebs_volume)")); return 0; }
  const agg = async (table: string) => { try { return new Map((await query<any>(`select volume_id, sum(sum) as total, max(maximum * sample_count / 86400.0) as peak_ps, count(*) as days from ${S}.${table} where timestamp > now() - interval '30 days' group by 1`)).map((r) => [r.volume_id, r])); } catch (e) { onError(describeError(e, `ebs metrics (${table})`)); return new Map<string, any>(); } };
  const [reads, writes] = await Promise.all([agg("aws_ebs_volume_metric_read_ops_daily"), agg("aws_ebs_volume_metric_write_ops_daily")]);
  const now = new Date().toISOString();
  // The usage columns survive a refresh only while the volume stays on the same instance; a detached or moved
  // volume forgets what the old host saw until the new one is probed.
  const up = db.prepare(`insert into inventory_ebs(volume_id, region, volume_type, size_gb, iops, throughput_mibps, state, encrypted, instance_id, device, created, name, read_iops_avg, write_iops_avg, iops_max, metric_days, monthly_usd, first_seen, last_seen, gone)
    values (@volume_id, @region, @volume_type, @size_gb, @iops, @throughput_mibps, @state, @encrypted, @instance_id, @device, @created, @name, @read_iops_avg, @write_iops_avg, @iops_max, @metric_days, @monthly_usd, @now, @now, 0)
    on conflict(volume_id) do update set region = excluded.region, volume_type = excluded.volume_type, size_gb = excluded.size_gb, iops = excluded.iops, throughput_mibps = excluded.throughput_mibps, state = excluded.state, encrypted = excluded.encrypted,
      instance_id = excluded.instance_id, device = excluded.device, created = excluded.created, name = excluded.name, read_iops_avg = excluded.read_iops_avg, write_iops_avg = excluded.write_iops_avg, iops_max = excluded.iops_max, metric_days = excluded.metric_days, monthly_usd = excluded.monthly_usd, last_seen = excluded.last_seen, gone = 0,
      total_bytes = case when excluded.instance_id is inventory_ebs.instance_id then inventory_ebs.total_bytes end,
      used_bytes = case when excluded.instance_id is inventory_ebs.instance_id then inventory_ebs.used_bytes end,
      used_pct = case when excluded.instance_id is inventory_ebs.instance_id then inventory_ebs.used_pct end,
      mounts = case when excluded.instance_id is inventory_ebs.instance_id then inventory_ebs.mounts end,
      usage_at = case when excluded.instance_id is inventory_ebs.instance_id then inventory_ebs.usage_at end`);
  let n = 0;
  db.transaction(() => {
    for (const v of vols) {
      const att = Array.isArray(v.attachments) ? v.attachments[0] : (() => { try { return JSON.parse(v.attachments || "[]")[0]; } catch { return null; } })();
      // VolumeRead/WriteOps is a count per sample; the daily table's sum is the day's total (avg IOPS = total / seconds)
      // and its maximum the busiest single sample, so peak IOPS = maximum / (86400 / sample_count)
      const r = reads.get(v.volume_id), w = writes.get(v.volume_id);
      const perSec = (x: any) => (x && Number(x.days) > 0 ? Number(x.total) / (Number(x.days) * 86400) : null);
      const rAvg = perSec(r), wAvg = perSec(w);
      const iopsMax = r || w ? Math.max(r ? Number(r.peak_ps) : 0, w ? Number(w.peak_ps) : 0) : null;
      const row = { volume_id: v.volume_id, region: v.region, volume_type: v.volume_type, size_gb: Number(v.size || 0), iops: v.iops != null ? Number(v.iops) : null, throughput_mibps: v.throughput != null ? Number(v.throughput) : null, state: v.state, encrypted: v.encrypted ? 1 : 0,
        instance_id: att?.InstanceId ?? null, device: att?.Device ?? null, created: v.create_time ? new Date(v.create_time).toISOString() : null, name: v.name ?? null,
        read_iops_avg: rAvg != null ? Math.round(rAvg * 10) / 10 : null, write_iops_avg: wAvg != null ? Math.round(wAvg * 10) / 10 : null, iops_max: iopsMax != null ? Math.round(iopsMax * 10) / 10 : null, metric_days: Number(r?.days || w?.days || 0),
        monthly_usd: ebsMonthlyCost({ volume_type: v.volume_type, size_gb: Number(v.size || 0), iops: v.iops != null ? Number(v.iops) : null, throughput_mibps: v.throughput != null ? Number(v.throughput) : null }), now };
      up.run(row); n++;
    }
    db.prepare("update inventory_ebs set gone = 1 where last_seen <> ?").run(now);
  })();
  applyLatestProbes();
  return n;
}

// ---- readers ------------------------------------------------------------------------------------------

const SORTS: Record<string, string> = {
  volume_id: "v.volume_id", volume_type: "v.volume_type", size_gb: "v.size_gb", iops: "v.iops", state: "v.state", instance_id: "v.instance_id", instance_state: "i.state",
  read_iops_avg: "v.read_iops_avg", write_iops_avg: "v.write_iops_avg", iops_max: "v.iops_max", monthly_usd: "v.monthly_usd", created: "v.created", name: "v.name", used_pct: "v.used_pct",
};
/** Volumes on an instance that is not running: attached, so "in-use" to AWS, and billed, but doing nothing. */
const ON_STOPPED = "v.instance_id is not null and i.state is not null and i.state <> 'running'";
const LIST_SQL = "select v.*, i.state as instance_state, i.name as instance_name from inventory_ebs v left join inventory_ec2 i on i.instance_id = v.instance_id";

/** state filters on the volume's own state (in-use, available), or "stopped" for volumes attached to an instance that is not running. */
export function listEbs(f: { q?: string; sort?: string; gone?: boolean; state?: string } = {}) {
  const where: string[] = []; const params: unknown[] = [];
  if (!f.gone) where.push("v.gone = 0");
  if (f.state === "stopped") where.push(ON_STOPPED);
  else if (f.state === "in-use" || f.state === "available") { where.push("v.state = ?"); params.push(f.state); }
  if (f.q) { where.push("(v.volume_id like ? or v.name like ? or v.instance_id like ? or i.name like ? or v.volume_type like ?)"); params.push(`%${f.q}%`, `%${f.q}%`, `%${f.q}%`, `%${f.q}%`, `%${f.q}%`); }
  const desc = f.sort?.startsWith("-"); const col = SORTS[(f.sort || "").replace(/^-/, "")];
  const order = col ? `order by ${col} ${desc ? "desc" : "asc"} nulls last` : "order by v.monthly_usd desc";
  return (db.prepare(`${LIST_SQL} ${where.length ? `where ${where.join(" and ")}` : ""} ${order} limit 2000`).all(...params) as any[]).map(ebsRow);
}
function ebsRow(r: any) {
  let mounts: MountUsage[] = [];
  try { mounts = r.mounts ? JSON.parse(r.mounts) : []; } catch { /* not json */ }
  return { ...r, provisioned_iops: ebsProvisionedIops(r), mounts };
}

export function ebsSummary() {
  const r = db.prepare(`select count(*) as total, coalesce(sum(v.size_gb), 0) as gb, coalesce(sum(v.monthly_usd), 0) as monthly_usd,
      coalesce(sum(v.state = 'available'), 0) as unattached, coalesce(sum(case when v.state = 'available' then v.monthly_usd else 0 end), 0) as unattached_usd,
      coalesce(sum(${ON_STOPPED}), 0) as on_stopped, coalesce(sum(case when ${ON_STOPPED} then v.monthly_usd else 0 end), 0) as on_stopped_usd,
      coalesce(sum(v.volume_type = 'gp2'), 0) as gp2, coalesce(sum(v.used_pct is not null), 0) as probed, coalesce(sum(v.used_pct >= 80), 0) as high
    from inventory_ebs v left join inventory_ec2 i on i.instance_id = v.instance_id where v.gone = 0`).get() as any;
  return { ...r, gone: (db.prepare("select count(*) as n from inventory_ebs where gone = 1").get() as any).n };
}

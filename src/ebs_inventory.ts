/**
 * EBS per volume: every volume with its type, size, provisioned IOPS and throughput, state and attachment,
 * 30 days of read and write IOPS from the daily metric tables, and the monthly cost at list (storage plus the
 * provisioned IOPS and throughput above what gp3 includes). Refreshed with the inventory. The review flags
 * volumes whose provisioned IOPS sit far above what is used.
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

export async function refreshEbsInventory(onError: (m: string) => void = () => {}): Promise<number> {
  let vols: any[];
  try { vols = await query<any>(`select volume_id, region, volume_type, size, iops, throughput, state, encrypted, attachments, create_time, tags ->> 'Name' as name from ${S}.aws_ebs_volume`); }
  catch (e) { onError(describeError(e, "ebs inventory (aws_ebs_volume)")); return 0; }
  const agg = async (table: string) => { try { return new Map((await query<any>(`select volume_id, sum(sum) as total, max(maximum * sample_count / 86400.0) as peak_ps, count(*) as days from ${S}.${table} where timestamp > now() - interval '30 days' group by 1`)).map((r) => [r.volume_id, r])); } catch (e) { onError(describeError(e, `ebs metrics (${table})`)); return new Map<string, any>(); } };
  const [reads, writes] = await Promise.all([agg("aws_ebs_volume_metric_read_ops_daily"), agg("aws_ebs_volume_metric_write_ops_daily")]);
  const now = new Date().toISOString();
  const up = db.prepare(`insert into inventory_ebs(volume_id, region, volume_type, size_gb, iops, throughput_mibps, state, encrypted, instance_id, device, created, name, read_iops_avg, write_iops_avg, iops_max, metric_days, monthly_usd, first_seen, last_seen, gone)
    values (@volume_id, @region, @volume_type, @size_gb, @iops, @throughput_mibps, @state, @encrypted, @instance_id, @device, @created, @name, @read_iops_avg, @write_iops_avg, @iops_max, @metric_days, @monthly_usd, @now, @now, 0)
    on conflict(volume_id) do update set region = excluded.region, volume_type = excluded.volume_type, size_gb = excluded.size_gb, iops = excluded.iops, throughput_mibps = excluded.throughput_mibps, state = excluded.state, encrypted = excluded.encrypted,
      instance_id = excluded.instance_id, device = excluded.device, created = excluded.created, name = excluded.name, read_iops_avg = excluded.read_iops_avg, write_iops_avg = excluded.write_iops_avg, iops_max = excluded.iops_max, metric_days = excluded.metric_days, monthly_usd = excluded.monthly_usd, last_seen = excluded.last_seen, gone = 0`);
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
  return n;
}

const SORTS = ["volume_id", "volume_type", "size_gb", "iops", "state", "instance_id", "read_iops_avg", "write_iops_avg", "iops_max", "monthly_usd", "created", "name"];
export function listEbs(f: { q?: string; sort?: string; gone?: boolean; state?: string } = {}) {
  const where: string[] = []; const params: unknown[] = [];
  if (!f.gone) where.push("gone = 0");
  if (f.state) { where.push("state = ?"); params.push(f.state); }
  if (f.q) { where.push("(volume_id like ? or name like ? or instance_id like ? or volume_type like ?)"); params.push(`%${f.q}%`, `%${f.q}%`, `%${f.q}%`, `%${f.q}%`); }
  const desc = f.sort?.startsWith("-"); const col = (f.sort || "").replace(/^-/, "");
  const order = SORTS.includes(col) ? `order by ${col} ${desc ? "desc" : "asc"} nulls last` : "order by monthly_usd desc";
  return (db.prepare(`select * from inventory_ebs ${where.length ? `where ${where.join(" and ")}` : ""} ${order} limit 2000`).all(...params) as any[]).map((r) => ({ ...r, provisioned_iops: ebsProvisionedIops(r), instance_name: r.instance_id ? (db.prepare("select name from inventory_ec2 where instance_id = ?").get(r.instance_id) as any)?.name ?? null : null }));
}
export function ebsSummary() {
  const r = db.prepare("select count(*) as total, coalesce(sum(size_gb), 0) as gb, coalesce(sum(monthly_usd), 0) as monthly_usd, coalesce(sum(state = 'available'), 0) as unattached, coalesce(sum(case when state = 'available' then monthly_usd else 0 end), 0) as unattached_usd, coalesce(sum(volume_type = 'gp2'), 0) as gp2 from inventory_ebs where gone = 0").get() as any;
  return { ...r, gone: (db.prepare("select count(*) as n from inventory_ebs where gone = 1").get() as any).n };
}

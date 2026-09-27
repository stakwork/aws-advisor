/**
 * gp3 volumes provisioned far above the throughput they use: trim it to the 30-day peak with headroom.
 *
 * The EBS inventory carries each gp3 volume's provisioned throughput but no throughput metrics, so the plan reads
 * them itself: VolumeReadBytes + VolumeWriteBytes per five minutes over 30 days (CloudWatch GetMetricData, 500
 * queries a call), the peak being the busiest period in MiB/s. A volume above the 125 MiB/s gp3 baseline whose
 * peak stays under 30 % of what is provisioned gets `ModifyVolume` to twice the peak rounded up to 25 MiB/s,
 * never under the free 125, never above 1,000 and never above a quarter of its IOPS (the gp3 ratio limit).
 * Online, no downtime, 0.04 USD per provisioned MiB/s-month back. EBS allows one modification per volume every
 * six hours, so a volume modified recently waits, an open IOPS trim on the same volume goes first, and the revert
 * says so when it hits the same limit.
 */
import { DescribeVolumesCommand, DescribeVolumesModificationsCommand, EC2Client, ModifyVolumeCommand } from "@aws-sdk/client-ec2";
import { CloudWatchClient, GetMetricDataCommand, type MetricDataQuery } from "@aws-sdk/client-cloudwatch";
import { db } from "../db.js";
import type { ActionModule, Creds, Proposal } from "../executor.js";

export const KIND = "ebs_throughput_trim" as const;
export const GP3_BASELINE_MIBPS = 125;
export const GP3_MAX_MIBPS = 1000;
export const GP3_THROUGHPUT_USD_MIBPS_MONTH = 0.04;
/** gp3 allows at most this much throughput per provisioned IOPS. */
export const MIBPS_PER_IOPS = 0.25;
/** Trim only when the 30-day peak stays under this share of what is provisioned. */
export const PEAK_SHARE = 0.3;
export const MIN_METRIC_DAYS = 5;
export const MODIFY_COOLDOWN_HOURS = 6;
const PERIOD_S = 300;
const METRIC_DAYS = 30;
const QUERIES_PER_CALL = 500;

/** The throughput to provision for a peak: twice the peak rounded up to 25, within [125, min(1000, IOPS/4)]. */
export function targetThroughput(peakMibps: number, iops: number): number {
  const cap = Math.min(GP3_MAX_MIBPS, Math.floor(Math.max(0, iops) * MIBPS_PER_IOPS));
  const wanted = Math.ceil((Math.max(0, peakMibps) * 2) / 25) * 25;
  return Math.max(GP3_BASELINE_MIBPS, Math.min(wanted, Math.max(GP3_BASELINE_MIBPS, cap)));
}
export const throughputSaving = (from: number, to: number) => Math.round(Math.max(0, from - to) * GP3_THROUGHPUT_USD_MIBPS_MONTH * 100) / 100;

export interface ThroughputPeak { peak_mibps: number; metric_days: number }

/** Peak MiB/s per volume over the last 30 days from the read and write byte sums per five-minute period. Pure over the fetched series. */
export function peakFromSeries(read: { ts: number[]; values: number[] }, write: { ts: number[]; values: number[] }): ThroughputPeak {
  const sum = new Map<number, number>();
  const add = (s: { ts: number[]; values: number[] }) => { for (let i = 0; i < s.ts.length; i++) sum.set(s.ts[i], (sum.get(s.ts[i]) ?? 0) + (s.values[i] ?? 0)); };
  add(read); add(write);
  let peak = 0; const days = new Set<string>();
  for (const [ts, bytes] of sum) { peak = Math.max(peak, bytes / PERIOD_S / 1048576); days.add(new Date(ts).toISOString().slice(0, 10)); }
  return { peak_mibps: Math.round(peak * 100) / 100, metric_days: days.size };
}

async function fetchPeaks(cw: CloudWatchClient, volumeIds: string[], now = Date.now()): Promise<Map<string, ThroughputPeak>> {
  const out = new Map<string, ThroughputPeak>();
  const idOf = (i: number, m: string) => `v${i}_${m}`;
  for (let start = 0; start < volumeIds.length; start += QUERIES_PER_CALL / 2) {
    const slice = volumeIds.slice(start, start + QUERIES_PER_CALL / 2);
    const queries: MetricDataQuery[] = [];
    slice.forEach((v, i) => { for (const m of ["VolumeReadBytes", "VolumeWriteBytes"]) queries.push({ Id: idOf(start + i, m === "VolumeReadBytes" ? "r" : "w"), MetricStat: { Metric: { Namespace: "AWS/EBS", MetricName: m, Dimensions: [{ Name: "VolumeId", Value: v }] }, Period: PERIOD_S, Stat: "Sum" }, ReturnData: true }); });
    const series = new Map<string, { ts: number[]; values: number[] }>();
    let NextToken: string | undefined;
    do {
      const r = await cw.send(new GetMetricDataCommand({ StartTime: new Date(now - METRIC_DAYS * 86400000), EndTime: new Date(now), MetricDataQueries: queries, ScanBy: "TimestampAscending", NextToken }));
      for (const res of r.MetricDataResults ?? []) {
        const s = series.get(res.Id!) ?? { ts: [], values: [] };
        (res.Timestamps ?? []).forEach((t, i) => { s.ts.push(new Date(t).getTime()); s.values.push(res.Values?.[i] ?? 0); });
        series.set(res.Id!, s);
      }
      NextToken = r.NextToken;
    } while (NextToken);
    slice.forEach((v, i) => out.set(v, peakFromSeries(series.get(idOf(start + i, "r")) ?? { ts: [], values: [] }, series.get(idOf(start + i, "w")) ?? { ts: [], values: [] })));
  }
  return out;
}

interface Candidate { volume_id: string; region: string; name: string | null; instance_id: string | null; iops: number; throughput_mibps: number }

export const ebsThroughputTrimAction: ActionModule = {
  kind: KIND,
  label: "gp3 throughput trimmed to the 30-day peak",

  async plan(creds, log) {
    const proposals: Proposal[] = []; const notes: string[] = [];
    const cands = db.prepare("select volume_id, region, name, instance_id, iops, throughput_mibps from inventory_ebs where gone = 0 and volume_type = 'gp3' and throughput_mibps > ? order by throughput_mibps desc").all(GP3_BASELINE_MIBPS) as Candidate[];
    if (!cands.length) { notes.push(`no gp3 volume above the ${GP3_BASELINE_MIBPS} MiB/s baseline`); return { proposals, notes }; }
    const byRegion = new Map<string, Candidate[]>();
    for (const c of cands) { const region = c.region || creds.region; if (!byRegion.has(region)) byRegion.set(region, []); byRegion.get(region)!.push(c); }
    for (const [region, list] of byRegion) {
      const ec2 = new EC2Client({ region, credentials: creds.read });
      const cw = new CloudWatchClient({ region, credentials: creds.read });
      try {
        const ids = list.map((c) => c.volume_id);
        const live = new Map((await ec2.send(new DescribeVolumesCommand({ VolumeIds: ids }))).Volumes?.map((v) => [v.VolumeId!, v]) ?? []);
        const mods = new Map((await ec2.send(new DescribeVolumesModificationsCommand({ VolumeIds: ids }))).VolumesModifications?.map((m) => [m.VolumeId!, m]) ?? []);
        const peaks = await fetchPeaks(cw, ids);
        for (const c of list) {
          const skip = (why: string) => { notes.push(`${c.volume_id}: ${why}`); log(`${c.volume_id}: ${why}`); };
          const v = live.get(c.volume_id);
          if (!v) { skip("not found by DescribeVolumes"); continue; }
          if (v.VolumeType !== "gp3") { skip(`is ${v.VolumeType} now`); continue; }
          if (v.Tags?.some((t) => t.Key === "advisor:hands-off")) { skip("tagged advisor:hands-off"); continue; }
          if (!["in-use", "available"].includes(v.State || "")) { skip(`state ${v.State}`); continue; }
          const current = v.Throughput ?? c.throughput_mibps;
          const iops = v.Iops ?? c.iops;
          const p = peaks.get(c.volume_id) ?? { peak_mibps: 0, metric_days: 0 };
          if (p.metric_days < MIN_METRIC_DAYS) { skip(`${p.metric_days} day(s) of throughput metrics, ${MIN_METRIC_DAYS} needed`); continue; }
          if (p.peak_mibps >= PEAK_SHARE * current) { skip(`30-day peak ${p.peak_mibps} MiB/s is ${Math.round((p.peak_mibps / current) * 100)} % of the provisioned ${current}: in use`); continue; }
          const target = targetThroughput(p.peak_mibps, iops);
          if (target >= current) { skip(`provisioned ${current} MiB/s is already at or under the target ${target}`); continue; }
          const m = mods.get(c.volume_id);
          if (m && ["modifying", "optimizing"].includes(m.ModificationState || "")) { skip(`a modification is ${m.ModificationState}`); continue; }
          if (m?.EndTime && Date.now() - new Date(m.EndTime).getTime() < MODIFY_COOLDOWN_HOURS * 3600000) { skip(`modified ${Math.round((Date.now() - new Date(m.EndTime).getTime()) / 3600000)} h ago; EBS allows one change per ${MODIFY_COOLDOWN_HOURS} h`); continue; }
          const iopsTrim = db.prepare("select id from actions where kind = 'ebs_iops_trim' and resource = ? and status = 'proposed' limit 1").get(c.volume_id) as { id: number } | undefined;
          if (iopsTrim) { skip(`IOPS trim #${iopsTrim.id} goes first; one modification per ${MODIFY_COOLDOWN_HOURS} hours`); continue; }
          proposals.push({
            kind: KIND, resource: c.volume_id, resource_name: c.name, region,
            dedupe: `${KIND}:${c.volume_id}:${target}`,
            title: `${c.volume_id}${c.name ? ` (${c.name})` : ""}: ${current} → ${target} MiB/s provisioned throughput`,
            reason: `30-day peak ${p.peak_mibps} MiB/s over ${p.metric_days} days of metrics (${Math.round((p.peak_mibps / current) * 100)} % of what is provisioned); target is twice the peak rounded up to 25, never under the free ${GP3_BASELINE_MIBPS}, never above a quarter of the ${iops.toLocaleString()} IOPS. Online, no downtime.`,
            before: { iops, throughput_mibps: current }, after: { iops, throughput_mibps: target },
            facts: { peak_mibps: p.peak_mibps, metric_days: p.metric_days, instance_id: c.instance_id, size_gb: v.Size },
            rollback: `set the provisioned throughput back to ${current} MiB/s (EBS allows one modification per ${MODIFY_COOLDOWN_HOURS} hours)`,
            est_usd_month: throughputSaving(current, target),
          });
        }
      } catch (e: any) { const m = String(e?.message || e); notes.push(`${region}: ${m.slice(0, 160)}`); log(`${region}: ${m}`); }
      finally { ec2.destroy(); cw.destroy(); }
    }
    return { proposals, notes };
  },

  async apply(p, creds) {
    const ec2 = new EC2Client({ region: p.region, credentials: creds.act() });
    try {
      const r = await ec2.send(new ModifyVolumeCommand({ VolumeId: p.resource, Throughput: Number(p.after.throughput_mibps) }));
      return `ModifyVolume: ${p.before.throughput_mibps} → ${p.after.throughput_mibps} MiB/s, modification ${r.VolumeModification?.ModificationState || "requested"}`;
    } finally { ec2.destroy(); }
  },

  async verify(p, creds) {
    const ec2 = new EC2Client({ region: p.region, credentials: creds.read });
    try {
      const m = (await ec2.send(new DescribeVolumesModificationsCommand({ VolumeIds: [p.resource] }))).VolumesModifications?.[0];
      if (!m) return { ok: null, note: "no modification record yet" };
      if (m.TargetThroughput !== Number(p.after.throughput_mibps)) return { ok: false, note: `the latest modification targets ${m.TargetThroughput} MiB/s, not ${p.after.throughput_mibps}` };
      if (m.ModificationState === "completed") return { ok: true, note: `modification completed${m.EndTime ? ` ${new Date(m.EndTime).toISOString()}` : ""}` };
      if (m.ModificationState === "failed") return { ok: false, note: `modification failed: ${m.StatusMessage || ""}` };
      return { ok: null, note: `modification ${m.ModificationState}${m.Progress != null ? ` ${m.Progress}%` : ""}` };
    } finally { ec2.destroy(); }
  },

  async revert(p, creds) {
    const ec2 = new EC2Client({ region: p.region, credentials: creds.act() });
    try {
      await ec2.send(new ModifyVolumeCommand({ VolumeId: p.resource, Throughput: Number(p.before.throughput_mibps) }));
      return `throughput back to ${p.before.throughput_mibps} MiB/s`;
    } catch (e: any) {
      if (/VolumeModificationRateExceeded|rate exceeded|6 hours/i.test(String(e?.message || e))) throw new Error(`EBS refuses a second modification within ${MODIFY_COOLDOWN_HOURS} hours of the last one; revert again later`);
      throw e;
    } finally { ec2.destroy(); }
  },
};

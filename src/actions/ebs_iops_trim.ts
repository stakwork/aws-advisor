/**
 * gp3 volumes provisioned far above what they use: trim the IOPS to the 30-day peak with headroom.
 *
 * The EBS inventory carries each volume's provisioned IOPS and its 30-day peak from CloudWatch; the review flags
 * gp3 volumes above the 3,000 baseline whose peak stays under 30 % of it (`ebs_overprovisioned_iops`). The
 * executor does the trim: `ModifyVolume` to max(3,000, twice the peak rounded up to 500), online, no downtime,
 * 0.005 USD per provisioned IOPS-month back. EBS allows one modification per volume every six hours, so a volume
 * modified recently waits, and the revert says so when it hits the same limit. Throughput is left alone: the
 * inventory has no throughput metrics yet.
 */
import { DescribeVolumesCommand, DescribeVolumesModificationsCommand, EC2Client, ModifyVolumeCommand } from "@aws-sdk/client-ec2";
import { db } from "../db.js";
import { approvedFor, type ActionModule, type Creds, type Proposal } from "../executor.js";

export const KIND = "ebs_iops_trim" as const;
export const GP3_BASELINE_IOPS = 3000;
export const GP3_IOPS_USD_MONTH = 0.005;
/** Trim only when the 30-day peak stays under this share of what is provisioned (the review's rule). */
export const PEAK_SHARE = 0.3;
export const MIN_METRIC_DAYS = 5;
export const MODIFY_COOLDOWN_HOURS = 6;

/** The IOPS to provision for a peak: twice the peak, rounded up to 500, never under the free baseline. */
export const targetIops = (peak: number) => Math.max(GP3_BASELINE_IOPS, Math.ceil((peak * 2) / 500) * 500);
export const iopsSaving = (from: number, to: number) => Math.round(Math.max(0, from - to) * GP3_IOPS_USD_MONTH * 100) / 100;

interface Candidate { volume_id: string; region: string; name: string | null; instance_id: string | null; iops: number; iops_max: number; metric_days: number; approved: { id: number; title: string; decided_by: string | null } | null }

function candidates(): Candidate[] {
  const rows = db.prepare("select volume_id, region, name, instance_id, iops, iops_max, metric_days from inventory_ebs where gone = 0 and volume_type = 'gp3' and iops > ? order by iops desc").all(GP3_BASELINE_IOPS) as any[];
  const out: Candidate[] = [];
  for (const r of rows) {
    const approved = approvedFor(["review_ebs_iops", "ebs_overprovisioned_iops"], r.volume_id);
    const qualifies = r.metric_days >= MIN_METRIC_DAYS && r.iops_max != null && r.iops_max < PEAK_SHARE * r.iops;
    if (qualifies || approved) out.push({ ...r, approved });
  }
  return out;
}

export const ebsIopsTrimAction: ActionModule = {
  kind: KIND,
  label: "gp3 IOPS trimmed to the 30-day peak",

  async plan(creds, log) {
    const proposals: Proposal[] = []; const notes: string[] = [];
    const cands = candidates();
    if (!cands.length) { notes.push("no gp3 volume above 3,000 IOPS whose 30-day peak stays under 30 % of it"); return { proposals, notes }; }
    const byRegion = new Map<string, Candidate[]>();
    for (const c of cands) { if (!byRegion.has(c.region)) byRegion.set(c.region, []); byRegion.get(c.region)!.push(c); }
    for (const [region, list] of byRegion) {
      const ec2 = new EC2Client({ region, credentials: creds.read });
      try {
        const ids = list.map((c) => c.volume_id);
        const live = new Map((await ec2.send(new DescribeVolumesCommand({ VolumeIds: ids }))).Volumes?.map((v) => [v.VolumeId!, v]) ?? []);
        const mods = new Map((await ec2.send(new DescribeVolumesModificationsCommand({ VolumeIds: ids }))).VolumesModifications?.map((m) => [m.VolumeId!, m]) ?? []);
        for (const c of list) {
          const skip = (why: string) => { notes.push(`${c.volume_id}: ${why}`); log(`${c.volume_id}: ${why}`); };
          const v = live.get(c.volume_id);
          if (!v) { skip("not found by DescribeVolumes"); continue; }
          if (v.VolumeType !== "gp3") { skip(`is ${v.VolumeType} now`); continue; }
          if (v.Tags?.some((t) => t.Key === "advisor:hands-off")) { skip("tagged advisor:hands-off"); continue; }
          if (!["in-use", "available"].includes(v.State || "")) { skip(`state ${v.State}`); continue; }
          const target = c.approved && c.iops_max == null ? GP3_BASELINE_IOPS : targetIops(c.iops_max);
          const current = v.Iops ?? c.iops;
          if (target >= current) { skip(`provisioned ${current} IOPS is already at or under the target ${target}`); continue; }
          const m = mods.get(c.volume_id);
          if (m && ["modifying", "optimizing"].includes(m.ModificationState || "")) { skip(`a modification is ${m.ModificationState}`); continue; }
          if (m?.EndTime && Date.now() - new Date(m.EndTime).getTime() < MODIFY_COOLDOWN_HOURS * 3600000) { skip(`modified ${Math.round((Date.now() - new Date(m.EndTime).getTime()) / 3600000)} h ago; EBS allows one change per ${MODIFY_COOLDOWN_HOURS} h`); continue; }
          proposals.push({
            kind: KIND, resource: c.volume_id, resource_name: c.name, region,
            dedupe: `${KIND}:${c.volume_id}:${target}`,
            title: `${c.volume_id}${c.name ? ` (${c.name})` : ""}: ${current.toLocaleString()} → ${target.toLocaleString()} provisioned IOPS`,
            reason: `${c.iops_max != null ? `30-day peak ${Math.round(c.iops_max).toLocaleString()} IOPS over ${c.metric_days} days of metrics (${Math.round((c.iops_max / current) * 100)} % of what is provisioned)` : "no IOPS metrics"}; target is twice the peak rounded up to 500, never under the free 3,000. Online, no downtime.${c.approved ? ` Approved as recommendation #${c.approved.id}${c.approved.decided_by ? ` by ${c.approved.decided_by}` : ""}.` : ""}`,
            before: { iops: current, throughput_mibps: v.Throughput ?? null }, after: { iops: target, throughput_mibps: v.Throughput ?? null },
            facts: { iops_max: c.iops_max, metric_days: c.metric_days, instance_id: c.instance_id, size_gb: v.Size, recommendation_id: c.approved?.id ?? null },
            rollback: `set the provisioned IOPS back to ${current.toLocaleString()} (EBS allows one modification per ${MODIFY_COOLDOWN_HOURS} hours)`,
            est_usd_month: iopsSaving(current, target),
          });
        }
      } finally { ec2.destroy(); }
    }
    return { proposals, notes };
  },

  async apply(p, creds) {
    const ec2 = new EC2Client({ region: p.region, credentials: creds.act() });
    try {
      const r = await ec2.send(new ModifyVolumeCommand({ VolumeId: p.resource, Iops: Number(p.after.iops) }));
      return `ModifyVolume: ${p.before.iops} → ${p.after.iops} IOPS, modification ${r.VolumeModification?.ModificationState || "requested"}`;
    } finally { ec2.destroy(); }
  },

  async verify(p, creds) {
    const ec2 = new EC2Client({ region: p.region, credentials: creds.read });
    try {
      const m = (await ec2.send(new DescribeVolumesModificationsCommand({ VolumeIds: [p.resource] }))).VolumesModifications?.[0];
      if (!m) return { ok: null, note: "no modification record yet" };
      if (m.TargetIops !== Number(p.after.iops)) return { ok: false, note: `the latest modification targets ${m.TargetIops} IOPS, not ${p.after.iops}` };
      if (m.ModificationState === "completed") return { ok: true, note: `modification completed${m.EndTime ? ` ${new Date(m.EndTime).toISOString()}` : ""}` };
      if (m.ModificationState === "failed") return { ok: false, note: `modification failed: ${m.StatusMessage || ""}` };
      return { ok: null, note: `modification ${m.ModificationState}${m.Progress != null ? ` ${m.Progress}%` : ""}` };
    } finally { ec2.destroy(); }
  },

  async revert(p, creds) {
    const ec2 = new EC2Client({ region: p.region, credentials: creds.act() });
    try {
      await ec2.send(new ModifyVolumeCommand({ VolumeId: p.resource, Iops: Number(p.before.iops) }));
      return `IOPS back to ${p.before.iops}`;
    } catch (e: any) {
      if (/VolumeModificationRateExceeded|rate exceeded|6 hours/i.test(String(e?.message || e))) throw new Error(`EBS refuses a second modification within ${MODIFY_COOLDOWN_HOURS} hours of the last one; revert again later`);
      throw e;
    } finally { ec2.destroy(); }
  },
};

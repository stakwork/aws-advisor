/**
 * gp2 volumes moved to gp3: the same durability and a fifth less per GB, online, no downtime, reversible. gp3
 * starts at 3,000 IOPS and 125 MiB/s whatever the size; a gp2 volume's baseline is three IOPS per GiB (never
 * under 100, never over 16,000) and up to 250 MiB/s, so the target provisions at least what gp2 gave: IOPS at
 * three per GiB when that is above 3,000, throughput 250 MiB/s from 170 GiB up. The estimate is the per-GB
 * difference minus what the extra IOPS and throughput cost; a volume where that is not positive is left alone.
 * EBS allows one modification per volume every six hours, so a recently modified volume waits, and the revert
 * (back to gp2) says so when it hits the same limit.
 */
import { DescribeVolumesCommand, DescribeVolumesModificationsCommand, EC2Client, ModifyVolumeCommand } from "@aws-sdk/client-ec2";
import { db } from "../db.js";
import type { ActionModule, Creds, Proposal } from "../executor.js";
import { GP3_BASELINE_IOPS, GP3_IOPS_USD_MONTH, MODIFY_COOLDOWN_HOURS } from "./ebs_iops_trim.js";

export const KIND = "ebs_gp3_migrate" as const;
export const GP2_USD_GB_MONTH = 0.10;
export const GP3_USD_GB_MONTH = 0.08;
export const GP3_BASELINE_MIBPS = 125;
export const GP3_MIBPS_USD_MONTH = 0.04;
const MAX_PER_PLAN = 40;

/** What gp3 must provision so the volume performs at least as it did on gp2. */
export const gp3Target = (sizeGb: number) => ({ iops: Math.min(16000, Math.max(GP3_BASELINE_IOPS, 3 * sizeGb)), throughput_mibps: sizeGb >= 170 ? 250 : GP3_BASELINE_MIBPS });
/** USD/month saved by the move, after the extra IOPS and throughput gp3 bills above its baseline. */
export function gp3Saving(sizeGb: number): number {
  const t = gp3Target(sizeGb);
  const s = sizeGb * (GP2_USD_GB_MONTH - GP3_USD_GB_MONTH) - Math.max(0, t.iops - GP3_BASELINE_IOPS) * GP3_IOPS_USD_MONTH - Math.max(0, t.throughput_mibps - GP3_BASELINE_MIBPS) * GP3_MIBPS_USD_MONTH;
  return Math.round(s * 100) / 100;
}

interface Candidate { volume_id: string; region: string; name: string | null; instance_id: string | null; size_gb: number }

export const ebsGp3MigrateAction: ActionModule = {
  kind: KIND,
  label: "gp2 volumes moved to gp3",

  async plan(creds, log) {
    const proposals: Proposal[] = []; const notes: string[] = [];
    const rows = db.prepare("select volume_id, region, name, instance_id, size_gb from inventory_ebs where gone = 0 and volume_type = 'gp2' order by size_gb desc").all() as Candidate[];
    if (!rows.length) { notes.push("no gp2 volume in the inventory"); return { proposals, notes }; }
    if (rows.length > MAX_PER_PLAN) notes.push(`${rows.length - MAX_PER_PLAN} gp2 volume(s) wait for a later pass`);
    const byRegion = new Map<string, Candidate[]>();
    for (const c of rows.slice(0, MAX_PER_PLAN)) { if (!byRegion.has(c.region)) byRegion.set(c.region, []); byRegion.get(c.region)!.push(c); }
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
          if (v.VolumeType !== "gp2") { skip(`is ${v.VolumeType} now`); continue; }
          if (v.Tags?.some((t) => t.Key === "advisor:hands-off")) { skip("tagged advisor:hands-off"); continue; }
          if (!["in-use", "available"].includes(v.State || "")) { skip(`state ${v.State}`); continue; }
          const m = mods.get(c.volume_id);
          if (m && ["modifying", "optimizing"].includes(m.ModificationState || "")) { skip(`a modification is ${m.ModificationState}`); continue; }
          if (m?.EndTime && Date.now() - new Date(m.EndTime).getTime() < MODIFY_COOLDOWN_HOURS * 3600000) { skip(`modified ${Math.round((Date.now() - new Date(m.EndTime).getTime()) / 3600000)} h ago; EBS allows one change per ${MODIFY_COOLDOWN_HOURS} h`); continue; }
          const size = v.Size ?? c.size_gb;
          const target = gp3Target(size); const saving = gp3Saving(size);
          if (saving <= 0) { skip(`${size} GiB: gp3 with matching performance would not be cheaper`); continue; }
          proposals.push({
            kind: KIND, resource: c.volume_id, resource_name: c.name, region,
            dedupe: `${KIND}:${c.volume_id}`,
            title: `${c.volume_id}${c.name ? ` (${c.name})` : ""}: gp2 → gp3, ${size} GiB, ${target.iops.toLocaleString()} IOPS, ${target.throughput_mibps} MiB/s`,
            reason: `gp2 bills ${GP2_USD_GB_MONTH} USD/GB-month, gp3 ${GP3_USD_GB_MONTH}; the target provisions at least what gp2 gave (three IOPS per GiB above the 3,000 baseline, 250 MiB/s from 170 GiB). Online, no downtime, ${c.instance_id ? `attached to ${c.instance_id}` : "not attached"}.`,
            before: { volume_type: "gp2", iops: v.Iops ?? null, throughput_mibps: null }, after: { volume_type: "gp3", iops: target.iops, throughput_mibps: target.throughput_mibps },
            facts: { size_gb: size, instance_id: c.instance_id, device: v.Attachments?.[0]?.Device ?? null },
            rollback: `modify the volume back to gp2 (EBS allows one modification per ${MODIFY_COOLDOWN_HOURS} hours)`,
            est_usd_month: saving,
          });
        }
      } finally { ec2.destroy(); }
    }
    return { proposals, notes };
  },

  async apply(p, creds) {
    const ec2 = new EC2Client({ region: p.region, credentials: creds.act() });
    try {
      const r = await ec2.send(new ModifyVolumeCommand({ VolumeId: p.resource, VolumeType: "gp3", Iops: Number(p.after.iops), Throughput: Number(p.after.throughput_mibps) }));
      return `ModifyVolume: gp2 → gp3 (${p.after.iops} IOPS, ${p.after.throughput_mibps} MiB/s), modification ${r.VolumeModification?.ModificationState || "requested"}`;
    } finally { ec2.destroy(); }
  },

  async verify(p, creds) {
    const ec2 = new EC2Client({ region: p.region, credentials: creds.read });
    try {
      const m = (await ec2.send(new DescribeVolumesModificationsCommand({ VolumeIds: [p.resource] }))).VolumesModifications?.[0];
      if (!m) return { ok: null, note: "no modification record yet" };
      if (m.TargetVolumeType !== "gp3") return { ok: false, note: `the latest modification targets ${m.TargetVolumeType}, not gp3` };
      if (m.ModificationState === "completed") return { ok: true, note: `modification completed${m.EndTime ? ` ${new Date(m.EndTime).toISOString()}` : ""}` };
      if (m.ModificationState === "failed") return { ok: false, note: `modification failed: ${m.StatusMessage || ""}` };
      return { ok: null, note: `modification ${m.ModificationState}${m.Progress != null ? ` ${m.Progress}%` : ""}` };
    } finally { ec2.destroy(); }
  },

  async revert(p, creds) {
    const ec2 = new EC2Client({ region: p.region, credentials: creds.act() });
    try { await ec2.send(new ModifyVolumeCommand({ VolumeId: p.resource, VolumeType: "gp2" })); return "volume back to gp2"; }
    catch (e: any) {
      if (/VolumeModificationRateExceeded|rate exceeded|6 hours/i.test(String(e?.message || e))) throw new Error(`EBS refuses a second modification within ${MODIFY_COOLDOWN_HOURS} hours of the last one; revert again later`);
      throw e;
    } finally { ec2.destroy(); }
  },
};

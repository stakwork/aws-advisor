/**
 * EBS snapshots deleted, once a person approved the recommendation. The old_snapshot rule files one per snapshot
 * older than 90 days (0.05 USD per GB-month in the standard tier, 0.0125 archived); the recommendation is tier
 * approve because a deleted snapshot cannot be recovered and only a person knows whether anything restores from
 * it. Approving it is the decision; the executor deletes it, but only after announcing it in the Sphinx chat and
 * waiting ACT_DELETE_GRACE_HOURS, and only while the snapshot still qualifies when the pass looks: not behind an
 * AMI (the delete would fail anyway), not managed by AWS Backup or DLM (their schedules own it), not tagged
 * `advisor:hands-off`, completed, and not in the middle of an archive by the snapshot_archive action. There is
 * no revert: the row and the Sphinx message say so.
 */
import { DeleteSnapshotCommand, DescribeImagesCommand, DescribeSnapshotsCommand, EC2Client, type Snapshot } from "@aws-sdk/client-ec2";
import { db } from "../db.js";
import { config } from "../config.js";
import { approvedRecs, markRecommendationsDone, SNAPSHOT_ARCHIVE_USD_GB_MONTH, SNAPSHOT_STANDARD_USD_GB_MONTH, type ActionModule, type Creds, type Proposal } from "../executor.js";
import { MANAGED_TAG_PREFIXES, NO_VOLUME } from "./snapshot_archive.js";

export const KIND = "snapshot_delete" as const;
export const ACTION_TYPES = ["delete_snapshot"];

export interface DeleteFacts {
  snapshot_id: string; volume_id: string | null; size_gb: number; started: string | null; state: string | null; tier: string | null;
  description: string | null; name: string | null; ami_ids: string[]; managed_by: string | null; hands_off: boolean; archive_in_flight: boolean;
}

const tagOf = (s: Snapshot, key: string) => s.Tags?.find((t) => t.Key === key)?.Value ?? null;

/** One described snapshot as facts, given the AMIs that reference it and whether an archive of it is open. Pure. */
export function deleteFacts(s: Snapshot, amiIds: string[], archiveInFlight: boolean): DeleteFacts {
  return {
    snapshot_id: s.SnapshotId || "", volume_id: s.VolumeId && s.VolumeId !== NO_VOLUME ? s.VolumeId : null, size_gb: Number(s.VolumeSize ?? 0),
    started: s.StartTime ? new Date(s.StartTime).toISOString() : null, state: (s.State as string | undefined) ?? null, tier: (s.StorageTier as string | undefined) ?? null,
    description: s.Description ?? null, name: tagOf(s, "Name"), ami_ids: amiIds,
    managed_by: s.Tags?.find((t) => MANAGED_TAG_PREFIXES.some((p) => (t.Key || "").startsWith(p)))?.Key ?? null,
    hands_off: tagOf(s, "advisor:hands-off") != null, archive_in_flight: archiveInFlight,
  };
}

/** Why an approved snapshot is left alone this pass, or null when it can be deleted. Pure. */
export function deleteSkipReason(f: DeleteFacts): string | null {
  if (f.ami_ids.length) return `behind AMI ${f.ami_ids.join(", ")}: deregister the image first`;
  if (f.managed_by) return `managed by ${f.managed_by}: its schedule owns it`;
  if (f.hands_off) return "tagged advisor:hands-off";
  if (f.state && f.state !== "completed") return `state ${f.state}, not completed`;
  if (f.archive_in_flight) return "archive in flight (snapshot_archive): waits for it";
  return null;
}

/** What deleting saves a month: the tier's price over the volume size (a snapshot bills used blocks only, so a ceiling). Pure. */
export const deleteSaving = (sizeGb: number, tier: string | null) => Math.round(sizeGb * (tier === "archive" ? SNAPSHOT_ARCHIVE_USD_GB_MONTH : SNAPSHOT_STANDARD_USD_GB_MONTH) * 100) / 100;

const notFound = (e: any) => /InvalidSnapshot\.NotFound/i.test(String(e?.name || e?.message));

export const snapshotDeleteAction: ActionModule = {
  kind: KIND,
  label: "EBS snapshots deleted, once approved",
  grace_hours: () => config.actDeleteGraceHours,
  announce: true,

  async plan(creds, log) {
    const proposals: Proposal[] = []; const notes: string[] = [];
    const recs = approvedRecs(ACTION_TYPES);
    if (!recs.length) { notes.push("no approved recommendation to delete a snapshot"); return { proposals, notes }; }
    const byRegion = new Map<string, typeof recs>();
    // Grouped per (account, region): the finding row behind the recommendation carries the account it came from.
    for (const r of recs) { const key = `${r.evidence?.account_id || ""}|${String(r.evidence?.region || creds.region)}`; if (!byRegion.has(key)) byRegion.set(key, []); byRegion.get(key)!.push(r); }
    for (const [key, list] of byRegion) {
      const [account, region] = key.split("|");
      const acct = creds.forAccount(account || null);
      const ec2 = new EC2Client({ region, credentials: acct.read });
      try {
        const seen = new Set<string>();
        for (const rec of list) {
          if (seen.has(rec.resource)) continue; seen.add(rec.resource);
          const skip = (why: string) => { notes.push(`${rec.resource}: ${why}`); log(`${rec.resource}: ${why}`); };
          const done = () => { const n = markRecommendationsDone([rec.id], "already deleted when the executor checked (done by hand); recommendation closed"); skip(`already deleted; ${n} approved recommendation(s) marked done`); };
          let s: Snapshot | undefined;
          try { s = (await ec2.send(new DescribeSnapshotsCommand({ SnapshotIds: [rec.resource] }))).Snapshots?.[0]; }
          catch (e: any) { if (notFound(e)) { done(); continue; } skip(String(e?.message || e).slice(0, 200)); continue; }
          if (!s) { done(); continue; }
          let amiIds: string[] = [];
          try { amiIds = ((await ec2.send(new DescribeImagesCommand({ Owners: ["self"], Filters: [{ Name: "block-device-mapping.snapshot-id", Values: [rec.resource] }] }))).Images ?? []).map((i) => i.ImageId!).filter(Boolean); }
          catch (e: any) { skip(`DescribeImages: ${String(e?.message || e).slice(0, 120)}; nothing is deleted without knowing about the AMIs`); continue; }
          const archiving = (db.prepare("select count(*) as n from actions where kind = 'snapshot_archive' and resource = ? and status in ('proposed', 'applied')").get(rec.resource) as { n: number }).n > 0;
          const f = deleteFacts(s, amiIds, archiving);
          const why = deleteSkipReason(f);
          if (why) { skip(why); continue; }
          const tierLabel = f.tier === "archive" ? "archived" : "standard tier";
          proposals.push({
            kind: KIND, resource: f.snapshot_id, resource_name: f.name || f.description || f.snapshot_id, region, account_id: acct.is_parent ? null : acct.account_id,
            dedupe: `${KIND}:${f.snapshot_id}`,
            title: `delete snapshot ${f.snapshot_id}${f.name ? ` (${f.name})` : ""}: ${f.size_gb} GB, ${tierLabel}${f.started ? `, from ${f.started.slice(0, 10)}` : ""}`,
            reason: `${rec.title}. Approved as recommendation #${rec.id}${rec.decided_by ? ` by ${rec.decided_by}` : ""}. Not behind an AMI, not managed by Backup or DLM, ${f.volume_id ? `source volume ${f.volume_id}` : "source volume gone"}. A deleted snapshot cannot be recovered${f.tier === "archive" ? "; an archived one still bills its 90-day minimum" : ""}.`,
            before: { exists: true, tier: f.tier, size_gb: f.size_gb }, after: { exists: false },
            facts: { recommendation_id: rec.id, volume_id: f.volume_id, started: f.started, description: f.description, tier: f.tier },
            rollback: "none: a deleted snapshot cannot be recovered",
            est_usd_month: rec.est_monthly_saving ?? deleteSaving(f.size_gb, f.tier),
          });
        }
      } catch (e: any) { const m = String(e?.message || e); notes.push(`${region}: ${m.slice(0, 160)}`); log(`${region}: ${m}`); }
      finally { ec2.destroy(); }
    }
    return { proposals, notes };
  },

  async apply(p, creds) {
    const ec2 = new EC2Client({ region: p.region, credentials: creds.act() });
    try { await ec2.send(new DeleteSnapshotCommand({ SnapshotId: p.resource })); return `DeleteSnapshot: ${p.resource} deleted (${p.before.size_gb} GB)`; }
    finally { ec2.destroy(); }
  },

  async verify(p, creds) {
    const ec2 = new EC2Client({ region: p.region, credentials: creds.read });
    try {
      const s = (await ec2.send(new DescribeSnapshotsCommand({ SnapshotIds: [p.resource] }))).Snapshots?.[0];
      return s ? { ok: false, note: `${p.resource} still exists on read-back (${s.State})` } : { ok: true, note: "read back: snapshot gone" };
    } catch (e: any) { return notFound(e) ? { ok: true, note: "read back: snapshot gone" } : { ok: null, note: String(e?.message || e).slice(0, 120) }; }
    finally { ec2.destroy(); }
  },

  async revert() {
    throw new Error("a deleted snapshot cannot be recovered; nothing to revert");
  },
};

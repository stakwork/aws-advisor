/**
 * EBS snapshots to the Archive tier.
 *
 * A snapshot in the standard tier costs 0.05 USD per GB-month; archived, 0.0125, restorable in 24 to 72 hours
 * and billed for at least 90 days. Nobody moves snapshots by hand: the age rule, the lineage rule (an archived
 * snapshot becomes a full copy, so archiving one that later snapshots still reference saves nothing) and the
 * AMI rule (a snapshot behind an image cannot be archived) are exactly the bookkeeping people skip. The executor
 * applies them every pass: a snapshot older than the configured age, in the standard tier, not behind an AMI,
 * not managed by AWS Backup or DLM, not tagged `advisor:hands-off`, that is either the newest remaining standard
 * snapshot of a volume that no longer exists (the next pass takes the next one, so a dead volume's whole chain
 * drains) or the only snapshot of a volume that still exists. One `ModifySnapshotTier` each; the read-back is
 * the tiering status.
 */
import { DescribeImagesCommand, DescribeSnapshotTierStatusCommand, DescribeSnapshotsCommand, DescribeVolumesCommand, EC2Client, ModifySnapshotTierCommand, RestoreSnapshotTierCommand, type Snapshot } from "@aws-sdk/client-ec2";
import { db } from "../db.js";
import { config } from "../config.js";
import { SNAPSHOT_ARCHIVE_USD_GB_MONTH, SNAPSHOT_STANDARD_USD_GB_MONTH, type ActionModule, type Creds, type Proposal } from "../executor.js";

export const KIND = "snapshot_archive" as const;
/** Snapshots copied in from elsewhere carry this placeholder volume id: no lineage to worry about. */
export const NO_VOLUME = "vol-ffffffff";
export const MANAGED_TAG_PREFIXES = ["aws:backup", "dlm:", "aws:dlm"];

export interface SnapshotFacts {
  snapshot_id: string; volume_id: string | null; size_gb: number; started: string; age_days: number; tier: string | null;
  description: string | null; name: string | null; ami_backed: boolean; managed_by: string | null; hands_off: boolean; volume_exists: boolean | null;
}

export interface SnapshotPick extends SnapshotFacts { rule: "orphan_newest" | "only_snapshot"; }

/** The pure selection: which of an account's standard-tier snapshots to archive this pass, and why. */
export function pickSnapshots(all: SnapshotFacts[], minAgeDays: number): { picks: SnapshotPick[]; left: Record<string, number> } {
  const left: Record<string, number> = {};
  const count = (k: string) => { left[k] = (left[k] || 0) + 1; };
  const byVolume = new Map<string, SnapshotFacts[]>();
  for (const s of all) { const v = s.volume_id && s.volume_id !== NO_VOLUME ? s.volume_id : `${NO_VOLUME}:${s.snapshot_id}`; if (!byVolume.has(v)) byVolume.set(v, []); byVolume.get(v)!.push(s); }
  const picks: SnapshotPick[] = [];
  for (const s of all) {
    if (s.tier && s.tier !== "standard") { count("already archived or in transition"); continue; }
    if (!s.tier) { count("storage tier unknown"); continue; }
    if (s.age_days < minAgeDays) { count(`younger than ${minAgeDays} days`); continue; }
    if (s.hands_off) { count("tagged advisor:hands-off"); continue; }
    if (s.managed_by) { count(`managed by ${s.managed_by}`); continue; }
    if (s.ami_backed) { count("behind an AMI"); continue; }
    const siblings = byVolume.get(s.volume_id && s.volume_id !== NO_VOLUME ? s.volume_id : `${NO_VOLUME}:${s.snapshot_id}`) || [s];
    const standard = siblings.filter((x) => x.tier === "standard");
    if (s.volume_exists === false || !s.volume_id || s.volume_id === NO_VOLUME) {
      const newest = [...standard].sort((a, b) => b.started.localeCompare(a.started))[0];
      if (newest?.snapshot_id !== s.snapshot_id) { count("older sibling of a gone volume: waits for the newer one"); continue; }
      picks.push({ ...s, rule: "orphan_newest" });
    } else if (s.volume_exists === true) {
      if (siblings.length !== 1) { count("one of several snapshots of a live volume"); continue; }
      picks.push({ ...s, rule: "only_snapshot" });
    } else count("volume existence unknown");
  }
  picks.sort((a, b) => b.size_gb - a.size_gb);
  return { picks, left };
}

/** What archiving saves per month, at most: the tier difference over the volume size (a standard snapshot holds only used blocks, so this is a ceiling). */
export const archiveSaving = (sizeGb: number) => Math.round(sizeGb * (SNAPSHOT_STANDARD_USD_GB_MONTH - SNAPSHOT_ARCHIVE_USD_GB_MONTH) * 100) / 100;

function regions(creds: Creds): string[] {
  const rows = db.prepare("select region from inventory_ebs where gone = 0 union select region from inventory_ec2 where gone = 0").all() as { region: string | null }[];
  const set = new Set<string>(rows.map((r) => r.region).filter((r): r is string => Boolean(r)));
  set.add(creds.region);
  return [...set].sort();
}

const tagOf = (s: Snapshot, key: string) => s.Tags?.find((t) => t.Key === key)?.Value ?? null;

/** Every completed snapshot the account owns in a region, as facts: AMI references, volume existence and tags resolved. */
export async function snapshotFacts(ec2: EC2Client, now = Date.now()): Promise<SnapshotFacts[]> {
  const snaps: Snapshot[] = [];
  let NextToken: string | undefined;
  do {
    const r = await ec2.send(new DescribeSnapshotsCommand({ OwnerIds: ["self"], Filters: [{ Name: "status", Values: ["completed"] }], MaxResults: 1000, NextToken }));
    snaps.push(...(r.Snapshots ?? []));
    NextToken = r.NextToken;
  } while (NextToken);
  if (!snaps.length) return [];
  const amiSnaps = new Set<string>();
  const images = await ec2.send(new DescribeImagesCommand({ Owners: ["self"] }));
  for (const i of images.Images ?? []) for (const m of i.BlockDeviceMappings ?? []) if (m.Ebs?.SnapshotId) amiSnaps.add(m.Ebs.SnapshotId);
  const volumeIds = [...new Set(snaps.map((s) => s.VolumeId).filter((v): v is string => Boolean(v) && v !== NO_VOLUME))];
  const existing = new Set<string>();
  for (let i = 0; i < volumeIds.length; i += 200) {
    const r = await ec2.send(new DescribeVolumesCommand({ Filters: [{ Name: "volume-id", Values: volumeIds.slice(i, i + 200) }] }));
    for (const v of r.Volumes ?? []) if (v.VolumeId) existing.add(v.VolumeId);
  }
  return snaps.filter((s) => s.SnapshotId).map((s) => {
    const started = s.StartTime ? new Date(s.StartTime).toISOString() : new Date(0).toISOString();
    const managed = s.Tags?.find((t) => MANAGED_TAG_PREFIXES.some((p) => (t.Key || "").startsWith(p)))?.Key ?? null;
    return {
      snapshot_id: s.SnapshotId!, volume_id: s.VolumeId ?? null, size_gb: Number(s.VolumeSize ?? 0), started, age_days: Math.floor((now - new Date(started).getTime()) / 86400000),
      tier: (s.StorageTier as string | undefined) ?? null, description: s.Description ?? null, name: tagOf(s, "Name"), ami_backed: amiSnaps.has(s.SnapshotId!),
      managed_by: managed, hands_off: tagOf(s, "advisor:hands-off") != null,
      volume_exists: s.VolumeId && s.VolumeId !== NO_VOLUME ? existing.has(s.VolumeId) : null,
    };
  });
}

export const snapshotArchiveAction: ActionModule = {
  kind: KIND,
  label: "EBS snapshots to the Archive tier",

  async plan(creds, log) {
    const proposals: Proposal[] = []; const notes: string[] = [];
    const minAge = config.actSnapshotMinAgeDays;
    for (const region of regions(creds)) {
      const ec2 = new EC2Client({ region, credentials: creds.read });
      let facts: SnapshotFacts[];
      try { facts = await snapshotFacts(ec2); } finally { ec2.destroy(); }
      const { picks, left } = pickSnapshots(facts, minAge);
      const leftLine = Object.entries(left).map(([k, n]) => `${n} ${k}`).join(", ");
      log(`${region}: ${facts.length} snapshot(s), ${picks.length} to archive${leftLine ? `; left alone: ${leftLine}` : ""}`);
      if (facts.length) notes.push(`${region}: ${picks.length} of ${facts.length} snapshot(s) qualify${leftLine ? ` (${leftLine})` : ""}`);
      for (const s of picks) {
        const why = s.rule === "orphan_newest" ? `its volume ${s.volume_id && s.volume_id !== NO_VOLUME ? s.volume_id : "(none)"} no longer exists and this is its newest standard snapshot` : `the only snapshot of ${s.volume_id}, which still exists`;
        proposals.push({
          kind: KIND, resource: s.snapshot_id, resource_name: s.name || s.description?.slice(0, 80) || null, region,
          dedupe: `${KIND}:${s.snapshot_id}`,
          title: `${s.snapshot_id}${s.name ? ` (${s.name})` : ""}: ${s.size_gb} GB snapshot, ${s.age_days} days old, standard → archive`,
          reason: `${s.age_days} days old (rule: ${minAge}+), ${why}, not behind an AMI, not managed by Backup or DLM. Archive costs a quarter of standard; restoring takes 24 to 72 hours.`,
          before: { storage_tier: "standard" }, after: { storage_tier: "archive" },
          facts: { ...s },
          rollback: "restore the snapshot to the standard tier permanently (RestoreSnapshotTier; 24 to 72 hours, billed for the archive's 90-day minimum)",
          est_usd_month: archiveSaving(s.size_gb),
        });
      }
    }
    return { proposals, notes };
  },

  async apply(p, creds) {
    const ec2 = new EC2Client({ region: p.region, credentials: creds.act() });
    try {
      const r = await ec2.send(new ModifySnapshotTierCommand({ SnapshotId: p.resource, StorageTier: "archive" }));
      return `ModifySnapshotTier: archive${r.TieringStartTime ? `, tiering started ${new Date(r.TieringStartTime).toISOString()}` : ""}`;
    } finally { ec2.destroy(); }
  },

  async verify(p, creds) {
    const ec2 = new EC2Client({ region: p.region, credentials: creds.read });
    try {
      const r = await ec2.send(new DescribeSnapshotTierStatusCommand({ Filters: [{ Name: "snapshot-id", Values: [p.resource] }] }));
      const st = r.SnapshotTierStatuses?.[0];
      if (!st) return { ok: null, note: "no tier status yet" };
      const status = String(st.LastTieringOperationStatus || "");
      if (st.StorageTier === "archive" || /archival-completed/.test(status)) return { ok: true, note: `tier ${st.StorageTier}${st.ArchivalCompleteTime ? `, completed ${new Date(st.ArchivalCompleteTime).toISOString()}` : ""}` };
      if (/failed/.test(status)) return { ok: false, note: `tiering ${status}: ${st.LastTieringOperationStatusDetail || ""}` };
      return { ok: null, note: `tiering ${status || "in progress"}${st.LastTieringProgress != null ? ` ${st.LastTieringProgress}%` : ""}` };
    } finally { ec2.destroy(); }
  },

  async revert(p, creds) {
    const ec2 = new EC2Client({ region: p.region, credentials: creds.act() });
    try {
      await ec2.send(new RestoreSnapshotTierCommand({ SnapshotId: p.resource, PermanentRestore: true }));
      return "RestoreSnapshotTier started (permanent); the snapshot is back in the standard tier in 24 to 72 hours";
    } finally { ec2.destroy(); }
  },
};

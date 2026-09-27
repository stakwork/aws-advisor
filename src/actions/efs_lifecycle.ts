/**
 * EFS file systems with no lifecycle policy keep every file in Standard at 0.30 USD per GB-month; most of what a
 * file system holds is not read for weeks. The executor puts one policy on every file system that has none:
 * files not accessed for ACT_EFS_IA_DAYS (30) move to Infrequent Access (0.016 USD per GB-month) and come back
 * to Standard on their first read (TransitionToPrimaryStorageClass AFTER_1_ACCESS), so a working set never pays
 * IA access charges twice. A file system that already has a policy, whatever it says, is left alone. Reverting
 * puts an empty policy back: files already in IA stay there until read. The estimate is a ceiling, since how
 * much of the Standard bytes is cold is unknown until the policy has run.
 */
import { DescribeFileSystemsCommand, DescribeLifecycleConfigurationCommand, EFSClient, PutLifecycleConfigurationCommand, type FileSystemDescription, type LifecyclePolicy, type TransitionToIARules } from "@aws-sdk/client-efs";
import { db } from "../db.js";
import { config } from "../config.js";
import type { ActionModule, Creds, Proposal } from "../executor.js";

export const KIND = "efs_lifecycle" as const;
export const EFS_STANDARD_USD_GB_MONTH = 0.30;
export const EFS_IA_USD_GB_MONTH = 0.016;
export const MIN_STANDARD_BYTES = 1024 ** 3;
/** The transition ages EFS accepts. */
export const EFS_IA_DAYS = [1, 7, 14, 30, 60, 90, 180, 270, 365] as const;
/** The accepted age at or above the requested one. */
export const snapEfsDays = (days: number): number => EFS_IA_DAYS.find((d) => d >= days) ?? EFS_IA_DAYS[EFS_IA_DAYS.length - 1];
export const iaRule = (days: number): TransitionToIARules => (days === 1 ? "AFTER_1_DAY" : `AFTER_${snapEfsDays(days)}_DAYS`) as TransitionToIARules;
/** The policy: to IA after `days` without a read, back to Standard on the first read. */
export const lifecyclePolicies = (days: number): LifecyclePolicy[] => [{ TransitionToIA: iaRule(days) }, { TransitionToPrimaryStorageClass: "AFTER_1_ACCESS" }];
/** A ceiling: half the Standard bytes turn out cold and move. */
export const efsSavingCeiling = (standardBytes: number) => Math.round((standardBytes / 1e9) * (EFS_STANDARD_USD_GB_MONTH - EFS_IA_USD_GB_MONTH) * 0.5 * 100) / 100;

function regions(defaultRegion: string): string[] {
  const rows = db.prepare("select distinct region from inventory_ec2 where gone = 0 and region is not null").all() as { region: string }[];
  return [...new Set([defaultRegion, ...rows.map((r) => r.region)])];
}

async function policies(efs: EFSClient, id: string): Promise<LifecyclePolicy[]> {
  return (await efs.send(new DescribeLifecycleConfigurationCommand({ FileSystemId: id }))).LifecyclePolicies ?? [];
}

export const efsLifecycleAction: ActionModule = {
  kind: KIND,
  label: "EFS file systems without a lifecycle policy get one",

  async plan(creds, log) {
    const proposals: Proposal[] = []; const notes: string[] = [];
    const days = snapEfsDays(config.actEfsIaDays);
    let scanned = 0, withPolicy = 0, small = 0;
    for (const region of regions(creds.region)) {
      const efs = new EFSClient({ region, credentials: creds.read });
      try {
        const systems: FileSystemDescription[] = [];
        let Marker: string | undefined;
        do { const r = await efs.send(new DescribeFileSystemsCommand({ MaxItems: 100, Marker })); systems.push(...(r.FileSystems ?? [])); Marker = r.NextMarker; } while (Marker);
        for (const fs of systems) {
          const id = fs.FileSystemId!;
          const name = fs.Name || fs.Tags?.find((t) => t.Key === "Name")?.Value || id;
          scanned++;
          const skip = (why: string) => { notes.push(`${name}: ${why}`); log(`${name}: ${why}`); };
          try {
            if (fs.LifeCycleState !== "available") { skip(`state ${fs.LifeCycleState}`); continue; }
            if (fs.Tags?.some((t) => t.Key === "advisor:hands-off")) { skip("tagged advisor:hands-off"); continue; }
            if ((await policies(efs, id)).length) { withPolicy++; continue; }
            const standard = fs.SizeInBytes?.ValueInStandard ?? fs.SizeInBytes?.Value ?? 0;
            if (standard < MIN_STANDARD_BYTES) { small++; continue; }
            const gb = standard / 1e9;
            proposals.push({
              kind: KIND, resource: id, resource_name: name, region,
              dedupe: `${KIND}:${region}:${id}:${days}`,
              title: `${name}: files unread for ${days} days move to Infrequent Access (${gb.toFixed(1)} GB in Standard)`,
              reason: `no lifecycle policy; ${gb.toFixed(1)} GB sit in Standard at ${EFS_STANDARD_USD_GB_MONTH} USD/GB-month. Files not read for ${days} days move to IA (${EFS_IA_USD_GB_MONTH} USD/GB-month) and come back to Standard on their first read, so nothing pays IA access charges twice. The estimate is a ceiling (half the bytes turning out cold): how much is cold is unknown until the policy has run.`,
              before: { lifecycle_policies: [] }, after: { lifecycle_policies: lifecyclePolicies(days) },
              facts: { days, standard_bytes: standard, ia_bytes: fs.SizeInBytes?.ValueInIA ?? 0, performance_mode: fs.PerformanceMode ?? null, throughput_mode: fs.ThroughputMode ?? null, file_system_arn: fs.FileSystemArn ?? null },
              rollback: "put an empty lifecycle configuration back (files already in IA stay there until read)",
              est_usd_month: efsSavingCeiling(standard),
            });
          } catch (e: any) { const m = String(e?.message || e); skip(m.slice(0, 160)); if (/AccessDenied|not authorized/i.test(m)) break; }
        }
      } catch (e: any) { const m = String(e?.message || e); notes.push(`${region}: ${m.slice(0, 160)}`); log(`${region}: ${m}`); }
      finally { efs.destroy(); }
    }
    if (!scanned) notes.push("no EFS file system found");
    if (withPolicy) notes.push(`${withPolicy} file system(s) already have a lifecycle policy`);
    if (small) notes.push(`${small} file system(s) without a policy hold under 1 GiB in Standard: left alone`);
    return { proposals, notes };
  },

  async apply(p, creds) {
    const efs = new EFSClient({ region: p.region, credentials: creds.act() });
    try { await efs.send(new PutLifecycleConfigurationCommand({ FileSystemId: p.resource, LifecyclePolicies: lifecyclePolicies(Number(p.facts.days)) })); return `PutLifecycleConfiguration: to IA after ${p.facts.days} days, back to Standard on first read`; }
    finally { efs.destroy(); }
  },

  async verify(p, creds) {
    const efs = new EFSClient({ region: p.region, credentials: creds.read });
    try {
      const list = await policies(efs, p.resource);
      return list.some((x) => x.TransitionToIA) ? { ok: true, note: `policy read back: ${list.map((x) => x.TransitionToIA || x.TransitionToPrimaryStorageClass).join(", ")}` } : { ok: false, note: "no TransitionToIA rule on read-back" };
    } catch (e: any) { return /FileSystemNotFound/i.test(String(e?.name || e?.message)) ? { ok: false, note: "file system not found on read-back" } : { ok: null, note: String(e?.message || e).slice(0, 120) }; }
    finally { efs.destroy(); }
  },

  async revert(p, creds) {
    const efs = new EFSClient({ region: p.region, credentials: creds.act() });
    try { await efs.send(new PutLifecycleConfigurationCommand({ FileSystemId: p.resource, LifecyclePolicies: [] })); return "lifecycle configuration emptied; files already in IA stay there until read"; }
    finally { efs.destroy(); }
  },
};

/**
 * EFS file systems as AdvisorStorage {kind: file}: metered size by storage class, one-zone or regional, performance
 * and throughput modes, encryption (ENCRYPTS from its key), and where it can be mounted: IN_NETWORK, IN_SEGMENT per
 * mount target's subnet and GUARDED_BY the security groups on the mount targets. Priced at list on storage by class
 * plus provisioned throughput; elastic throughput is billed per GB transferred and left out.
 */
import { EFS_IA_USD_GB_MONTH, EFS_STANDARD_USD_GB_MONTH } from "../actions/efs_lifecycle.js";
import { gb, iso, json, num, round2, str, tagsOf, type CollectContext, type CollectResult, type ServiceCollector, type ServiceLink, type ServiceRow } from "../service_inventory.js";

/** USD per GB-month (us-east-1); the regional Standard and IA rates are the lifecycle action's. */
export const EFS_PRICE = { standard: EFS_STANDARD_USD_GB_MONTH, ia: EFS_IA_USD_GB_MONTH, archive: 0.008, one_zone_standard: 0.16, one_zone_ia: 0.0133, provisioned_mibps_month: 6.0 };

export function efsMonthlyCost(f: { standard_bytes: number; ia_bytes: number; archive_bytes: number; one_zone: boolean; provisioned_mibps: number | null }): number {
  const p = EFS_PRICE;
  const storage = (f.standard_bytes / 1e9) * (f.one_zone ? p.one_zone_standard : p.standard) + (f.ia_bytes / 1e9) * (f.one_zone ? p.one_zone_ia : p.ia) + (f.archive_bytes / 1e9) * p.archive;
  return round2(storage + (f.provisioned_mibps ?? 0) * p.provisioned_mibps_month);
}

export function efsRow(f: any, mounts: any[]): ServiceRow {
  const size = json(f.size_in_bytes) || {};
  const standard = num(size.ValueInStandard) ?? num(size.Value) ?? 0; const ia = num(size.ValueInIA) ?? 0; const archive = num(size.ValueInArchive) ?? 0;
  const oneZone = Boolean(f.availability_zone_name);
  const provisioned = String(f.throughput_mode) === "provisioned" ? num(f.provisioned_throughput_in_mibps) : null;
  const arn = str(f.arn) || `arn:aws:elasticfilesystem:${f.region}:${f.account_id}:file-system/${f.file_system_id}`;
  const links: ServiceLink[] = [];
  if (f.kms_key_id) links.push({ rel: "ENCRYPTS", other: String(f.kms_key_id), dir: "in", resolve: "kms_key" });
  const vpcs = new Set<string>(); const subnets = new Set<string>(); const groups = new Set<string>();
  for (const m of mounts) { if (m.vpc_id) vpcs.add(String(m.vpc_id)); if (m.subnet_id) subnets.add(String(m.subnet_id)); for (const g of Array.isArray(json(m.security_groups)) ? json(m.security_groups) : []) groups.add(String(g)); }
  for (const v of vpcs) links.push({ rel: "IN_NETWORK", other: v, dir: "out", label: "AdvisorNetwork" });
  for (const s of subnets) links.push({ rel: "IN_SEGMENT", other: s, dir: "out", label: "AdvisorSegment" });
  for (const g of groups) links.push({ rel: "GUARDED_BY", other: g, dir: "out", label: "AdvisorFilter" });
  return {
    native_type: "efs_file_system", id: arn, arn, account_id: str(f.account_id) ?? "", region: str(f.region) ?? "", name: str(f.name) || str(f.file_system_id), state: str(f.life_cycle_state), created: iso(f.creation_time), tags: tagsOf(f.tags),
    monthly_usd: efsMonthlyCost({ standard_bytes: standard, ia_bytes: ia, archive_bytes: archive, one_zone: oneZone, provisioned_mibps: provisioned }),
    props: {
      kind: "file", file_system_id: str(f.file_system_id), size_gb: gb(num(size.Value) ?? standard + ia + archive), standard_gb: gb(standard), ia_gb: gb(ia), archive_gb: gb(archive),
      class: oneZone ? "one_zone" : "regional", zone: str(f.availability_zone_name), performance_mode: str(f.performance_mode), throughput_mode: str(f.throughput_mode), provisioned_mibps: provisioned,
      encrypted: f.encrypted == null ? null : Boolean(f.encrypted), mount_targets: num(f.number_of_mount_targets) ?? mounts.length, zones: [...new Set(mounts.map((m) => str(m.availability_zone_name)).filter(Boolean))],
      automatic_backups: f.automatic_backups == null ? null : String(f.automatic_backups).toLowerCase() === "enabled", vpc_id: [...vpcs][0] ?? null, security_groups: [...groups],
    },
    links,
  };
}

export const efsCollector: ServiceCollector = {
  name: "EFS file systems",
  async collect(ctx: CollectContext): Promise<CollectResult> {
    const fs = await ctx.select("aws_efs_file_system", ["file_system_id", "arn", "name", "life_cycle_state", "creation_time", "number_of_mount_targets", "performance_mode", "throughput_mode", "provisioned_throughput_in_mibps", "encrypted", "kms_key_id", "size_in_bytes", "automatic_backups", "availability_zone_name", "tags", "region", "account_id"], { required: ["file_system_id"], optional: { DescribeBackupPolicy: ["automatic_backups"] } });
    if (!fs) return { rows: [], complete: [] };
    const mounts = fs.length ? (await ctx.select("aws_efs_mount_target", ["file_system_id", "mount_target_id", "subnet_id", "vpc_id", "security_groups", "availability_zone_name", "region", "account_id"], { required: ["file_system_id"] })) ?? [] : [];
    const byFs = new Map<string, any[]>(); for (const m of mounts) { const k = String(m.file_system_id); if (!byFs.has(k)) byFs.set(k, []); byFs.get(k)!.push(m); }
    return { rows: fs.map((f) => efsRow(f, byFs.get(String(f.file_system_id)) ?? [])), complete: ["efs_file_system"] };
  },
};

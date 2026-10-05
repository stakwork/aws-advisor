/**
 * AWS Backup: vaults as AdvisorStorage {kind: backup} and plans as AdvisorBackupPlan. A vault carries its recovery
 * points (count, size by warm and cold storage, by resource type, oldest and newest), its lock and retention bounds,
 * the key that encrypts it (ENCRYPTS), and BACKED_UP_TO edges from every resource whose last backup landed in it. A
 * plan carries its rules (schedule, retention, cold storage), STORES_IN the vaults its rules target, and PROTECTS the
 * resources its selections name by ARN; tag and wildcard selections are kept as words, since what they match is
 * decided by AWS at backup time. Vaults are priced at list on stored GB by resource type; plans cost nothing.
 */
import { countList, gb, iso, json, num, round2, str, tagsOf, type CollectContext, type CollectResult, type ServiceCollector, type ServiceLink, type ServiceRow } from "../service_inventory.js";

/** Warm storage USD per GB-month by Backup's resource type (us-east-1); cold storage 0.01. */
export const BACKUP_WARM_USD_GB: Record<string, number> = { EBS: 0.05, EC2: 0.05, EFS: 0.05, RDS: 0.095, Aurora: 0.021, DynamoDB: 0.1, S3: 0.05, DocumentDB: 0.021, Neptune: 0.021, FSx: 0.05, default: 0.05 };
export const BACKUP_COLD_USD_GB = 0.01;

export interface PointGroup { backup_vault_arn: string; resource_type: string | null; storage_class: string | null; n: number; bytes: number; oldest: string | null; newest: string | null }

export function vaultRow(v: any, points: PointGroup[], protectedRes: any[]): ServiceRow {
  const arn = String(v.arn);
  const cold = points.filter((p) => String(p.storage_class).toUpperCase() === "COLD");
  const warm = points.filter((p) => String(p.storage_class).toUpperCase() !== "COLD");
  const sum = (ps: PointGroup[]) => ps.reduce((t, p) => t + (Number(p.bytes) || 0), 0);
  const cost = warm.reduce((t, p) => t + ((Number(p.bytes) || 0) / 1e9) * (BACKUP_WARM_USD_GB[String(p.resource_type)] ?? BACKUP_WARM_USD_GB.default), 0) + (sum(cold) / 1e9) * BACKUP_COLD_USD_GB;
  const dates = (k: "oldest" | "newest") => points.map((p) => iso(p[k])).filter((d): d is string => Boolean(d)).sort();
  const links: ServiceLink[] = protectedRes.filter((r) => r.resource_arn).map((r) => ({ rel: "BACKED_UP_TO", other: String(r.resource_arn), dir: "in", props: { last_backup_at: iso(r.last_backup_time), resource_type: str(r.resource_type) } }));
  if (v.encryption_key_arn) links.push({ rel: "ENCRYPTS", other: String(v.encryption_key_arn), dir: "in", resolve: "kms_key" });
  const byType = new Map<string, number>(); for (const p of points) byType.set(String(p.resource_type || "other"), (byType.get(String(p.resource_type || "other")) ?? 0) + Number(p.n || 0));
  return {
    native_type: "backup_vault", id: arn, arn, account_id: str(v.account_id) ?? "", region: str(v.region) ?? "", name: str(v.name), state: "available", created: iso(v.creation_date), tags: tagsOf(v.tags),
    monthly_usd: points.length ? round2(cost) : num(v.number_of_recovery_points) ? null : 0,
    props: {
      kind: "backup", recovery_points: num(v.number_of_recovery_points) ?? points.reduce((t, p) => t + Number(p.n || 0), 0), size_gb: gb(sum(points)), warm_gb: gb(sum(warm)), cold_gb: gb(sum(cold)),
      by_type: [...byType.entries()].sort((a, b) => b[1] - a[1]).map(([t, n]) => `${t} ${n}`), oldest_at: dates("oldest")[0] ?? null, newest_at: dates("newest").pop() ?? null,
      locked: v.locked == null ? null : Boolean(v.locked), min_retention_days: num(v.min_retention_days), max_retention_days: num(v.max_retention_days), encrypted: true, protected_resources: protectedRes.length,
      protected_types: countList(protectedRes.map((r) => str(r.resource_type))),
    },
    links,
  };
}

const isWildcard = (a: string) => /\*/.test(a);

export function planRow(p: any, selections: any[], vaultArn: (name: string) => string | null): ServiceRow {
  const arn = String(p.arn);
  const doc = json(p.backup_plan) || {};
  const rules: any[] = Array.isArray(doc.Rules) ? doc.Rules : [];
  const links: ServiceLink[] = [];
  for (const name of new Set(rules.map((r) => String(r.TargetBackupVaultName || "")).filter(Boolean))) { const v = vaultArn(name); if (v) links.push({ rel: "STORES_IN", other: v, dir: "out" }); }
  const explicit = new Set<string>(); const words: string[] = [];
  for (const s of selections) {
    const res: string[] = (Array.isArray(json(s.resources)) ? json(s.resources) : []).map(String);
    const tags: any[] = Array.isArray(json(s.list_of_tags)) ? json(s.list_of_tags) : [];
    const cond = json(s.conditions) || {};
    const condTags = ["StringEquals", "StringLike"].flatMap((k) => (Array.isArray(cond[k]) ? cond[k] : []).map((c: any) => `${String(c.ConditionKey || "").replace(/^aws:ResourceTag\//, "")}=${c.ConditionValue}`));
    for (const r of res) if (!isWildcard(r)) explicit.add(r);
    const wild = res.filter(isWildcard);
    words.push(`${s.selection_name}: ${[res.length - wild.length ? `${res.length - wild.length} by ARN` : null, wild.length ? wild.map((w) => (w === "*" ? "every supported resource" : w)).join(", ") : null, tags.length ? `tags ${tags.map((t) => `${t.ConditionKey}=${t.ConditionValue}`).join(", ")}` : null, condTags.length ? `tags ${condTags.join(", ")}` : null].filter(Boolean).join("; ") || "nothing"}`);
  }
  for (const r of explicit) links.push({ rel: "PROTECTS", other: r, dir: "out" });
  const retention = rules.map((r) => num(r?.Lifecycle?.DeleteAfterDays)).filter((d): d is number => d != null);
  return {
    native_type: "backup_plan", id: arn, arn, account_id: str(p.account_id) ?? "", region: str(p.region) ?? "", name: str(p.name), state: p.deletion_date ? "deleted" : "available", created: iso(p.creation_date), tags: tagsOf(p.tags), monthly_usd: 0,
    props: {
      rules: rules.length, schedules: rules.map((r) => `${r.RuleName}: ${r.ScheduleExpression || "on demand"}${r.Lifecycle?.DeleteAfterDays ? `, kept ${r.Lifecycle.DeleteAfterDays}d` : ", kept forever"}${r.Lifecycle?.MoveToColdStorageAfterDays ? `, cold after ${r.Lifecycle.MoveToColdStorageAfterDays}d` : ""}${r.CopyActions?.length ? `, ${r.CopyActions.length} cop${r.CopyActions.length === 1 ? "y" : "ies"}` : ""}`),
      retention_days: retention.length ? Math.max(...retention) : null, keeps_forever: rules.some((r) => !r?.Lifecycle?.DeleteAfterDays), cold_after_days: Math.min(...rules.map((r) => num(r?.Lifecycle?.MoveToColdStorageAfterDays) ?? Infinity)) === Infinity ? null : Math.min(...rules.map((r) => num(r?.Lifecycle?.MoveToColdStorageAfterDays) ?? Infinity)),
      copies: rules.some((r) => r?.CopyActions?.length), vaults: [...new Set(rules.map((r) => String(r.TargetBackupVaultName || "")).filter(Boolean))], selections: words, selected_by_arn: explicit.size,
      selects_all: selections.some((s) => (Array.isArray(json(s.resources)) ? json(s.resources) : []).includes("*")), last_run_at: iso(p.last_execution_date), plan_id: str(p.backup_plan_id),
    },
    links,
  };
}

export const backupCollector: ServiceCollector = {
  name: "AWS Backup",
  async collect(ctx: CollectContext): Promise<CollectResult> {
    const rows: ServiceRow[] = []; const complete: CollectResult["complete"] = [];
    const vaults = await ctx.select("aws_backup_vault", ["name", "arn", "creation_date", "number_of_recovery_points", "encryption_key_arn", "locked", "min_retention_days", "max_retention_days", "tags", "region", "account_id"], { required: ["arn"] });
    if (vaults) {
      const points = vaults.length ? ((await ctx.select("aws_backup_recovery_point", ["backup_vault_arn", "resource_type", "storage_class", "backup_size_in_bytes", "creation_date", "region", "account_id"], { required: ["backup_vault_arn"] })) ?? []) : [];
      // grouped here rather than in SQL: the vault is the plugin's parent key and grouping across it is not pushed down
      const groups = new Map<string, PointGroup>();
      for (const p of points) {
        const k = `${p.backup_vault_arn}|${p.resource_type}|${p.storage_class}`;
        const g = groups.get(k) ?? { backup_vault_arn: String(p.backup_vault_arn), resource_type: str(p.resource_type), storage_class: str(p.storage_class), n: 0, bytes: 0, oldest: null, newest: null };
        g.n++; g.bytes += Number(p.backup_size_in_bytes) || 0; const at = iso(p.creation_date);
        if (at && (!g.oldest || at < g.oldest)) g.oldest = at; if (at && (!g.newest || at > g.newest)) g.newest = at;
        groups.set(k, g);
      }
      const prot = vaults.length ? ((await ctx.select("aws_backup_protected_resource", ["resource_arn", "resource_type", "resource_name", "last_backup_time", "last_backup_vault_arn", "region", "account_id"], { required: ["resource_arn"] })) ?? []) : [];
      for (const v of vaults) rows.push(vaultRow(v, [...groups.values()].filter((g) => g.backup_vault_arn === v.arn), prot.filter((r) => r.last_backup_vault_arn === v.arn)));
      complete.push("backup_vault");
    }
    const plans = await ctx.select("aws_backup_plan", ["name", "arn", "backup_plan_id", "creation_date", "deletion_date", "last_execution_date", "backup_plan", "tags", "region", "account_id"], { required: ["arn"] });
    if (plans) {
      const sels = plans.length ? ((await ctx.select("aws_backup_selection", ["selection_name", "backup_plan_id", "resources", "not_resources", "list_of_tags", "conditions", "region", "account_id"], { required: ["backup_plan_id"] })) ?? []) : [];
      const vaultIndex = new Map((vaults ?? []).map((v) => [`${v.account_id}|${v.region}|${v.name}`, String(v.arn)]));
      for (const p of plans.filter((x) => !x.deletion_date)) rows.push(planRow(p, sels.filter((s) => s.backup_plan_id === p.backup_plan_id && s.account_id === p.account_id),
        (name) => vaultIndex.get(`${p.account_id}|${p.region}|${name}`) ?? `arn:aws:backup:${p.region}:${p.account_id}:backup-vault:${name}`));
      complete.push("backup_plan");
    }
    return { rows, complete };
  },
};

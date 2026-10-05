/**
 * KMS keys as AdvisorSecret {kind: kms_key}: who manages it (AWS or the account), its state, usage and spec, rotation,
 * aliases, and when a scheduled deletion lands. ENCRYPTS edges come from the rows that name a key (a file system, a
 * topic, a backup vault), resolved to the key's ARN by the refresh. A customer key is 1 USD a month at list; an
 * AWS-managed key costs nothing; a key pending deletion is left unpriced at 0 (it is going).
 */
import { KMS_KEY_USD_MONTH } from "../actions/kms_key_retire.js";
import { iso, json, str, tagsOf, type CollectContext, type CollectResult, type ServiceCollector, type ServiceRow } from "../service_inventory.js";

const KEY_STATE: Record<string, string> = { Enabled: "enabled", Disabled: "disabled", PendingDeletion: "pending_deletion", PendingImport: "pending_import", PendingReplicaDeletion: "pending_deletion", Unavailable: "unavailable", Creating: "creating", Updating: "updating" };

export function kmsRow(k: any): ServiceRow {
  const arn = String(k.arn);
  const aliases: string[] = (Array.isArray(json(k.aliases)) ? json(k.aliases) : []).map((a: any) => String(a?.AliasName ?? a)).filter((a: string) => a.startsWith("alias/"));
  const managed = String(k.key_manager || "").toUpperCase() === "AWS";
  const state = KEY_STATE[String(k.key_state)] ?? str(k.key_state)?.toLowerCase() ?? null;
  return {
    native_type: "kms_key", id: arn, arn, account_id: str(k.account_id) ?? "", region: str(k.region) ?? "", name: aliases[0]?.replace(/^alias\//, "") ?? str(k.id), state: str(k.key_state), created: iso(k.creation_date), tags: tagsOf(k.tags),
    monthly_usd: managed || state === "pending_deletion" ? 0 : KMS_KEY_USD_MONTH,
    props: {
      kind: "kms_key", key_id: str(k.id), managed, key_state: state, encrypted: true, usage: str(k.key_usage)?.toLowerCase() ?? null, spec: str(k.customer_master_key_spec), origin: str(k.origin)?.toLowerCase() ?? null,
      rotation_enabled: k.key_rotation_enabled == null ? null : Boolean(k.key_rotation_enabled), aliases, multi_region: k.multi_region == null ? null : Boolean(k.multi_region), deletion_at: iso(k.deletion_date), description: str(k.description),
    },
    links: [],
  };
}

export const kmsCollector: ServiceCollector = {
  name: "KMS keys",
  async collect(ctx: CollectContext): Promise<CollectResult> {
    const raw = await ctx.select("aws_kms_key", ["id", "arn", "key_manager", "key_state", "description", "creation_date", "deletion_date", "key_usage", "customer_master_key_spec", "origin", "aliases", "key_rotation_enabled", "multi_region", "tags", "region", "account_id"], { required: ["arn"], optional: { GetKeyRotationStatus: ["key_rotation_enabled"], ListAliases: ["aliases"] } });
    if (!raw) return { rows: [], complete: [] };
    return { rows: raw.map(kmsRow), complete: ["kms_key"] };
  },
};

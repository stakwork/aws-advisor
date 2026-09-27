/**
 * Customer-managed KMS keys nobody uses: 1 USD a month each, forever, and nobody audits them. The plan finds the
 * candidates (customer-managed, enabled, older than 90 days, not a multi-region key, not tagged
 * `advisor:hands-off`), checks that nothing the advisor can see references the key (EBS volumes and snapshots,
 * RDS instances and clusters, CloudWatch log groups) and that CloudTrail shows no cryptographic call against it
 * in the last 90 days (LookupEvents by resource name; a DescribeKey or a tag read does not count as use), and
 * files a tier-approve recommendation (`kms_key_unused`) for each one: a key that is still needed by something
 * the advisor cannot see is exactly what a person catches. Approving it is the decision; the executor never
 * deletes outright: `ScheduleKeyDeletion` with the configured waiting period (Settings › Auto-actions, 30 days
 * by default), during which Revert (`CancelKeyDeletion` then `EnableKey`) brings the key back intact.
 *
 * Usage unknown is usage: when CloudTrail cannot be read, nothing is filed. CloudTrail's lookup rate is low
 * (two calls a second), so a pass looks at 25 keys and the rest wait for the next one.
 */
import { DescribeKeyCommand, KMSClient, ListAliasesCommand, ListKeysCommand, ListResourceTagsCommand, ScheduleKeyDeletionCommand, CancelKeyDeletionCommand, EnableKeyCommand, type KeyMetadata } from "@aws-sdk/client-kms";
import { CloudTrailClient, LookupEventsCommand } from "@aws-sdk/client-cloudtrail";
import { DescribeSnapshotsCommand, DescribeVolumesCommand, EC2Client } from "@aws-sdk/client-ec2";
import { DescribeDBClustersCommand, DescribeDBInstancesCommand, RDSClient } from "@aws-sdk/client-rds";
import { CloudWatchLogsClient, DescribeLogGroupsCommand } from "@aws-sdk/client-cloudwatch-logs";
import { db } from "../db.js";
import { config } from "../config.js";
import { upsertRecommendations } from "../collector.js";
import type { RecInput } from "../rules.js";
import { credsForAccount, approvedRecs, type ActionModule, type Creds, type Proposal } from "../executor.js";

export const KIND = "kms_key_retire" as const;
export const ACTION_TYPE = "retire_kms_key";
export const RULE = "kms_key_unused";
export const KMS_KEY_USD_MONTH = 1.0;
export const MIN_AGE_DAYS = 90;
export const LOOKBACK_DAYS = 90;
export const MAX_LOOKUPS_PER_PASS = 25;
const LOOKUP_PAUSE_MS = 600;
/** Reads of the key's own metadata: seeing them in CloudTrail does not make the key used. */
export const HARMLESS_EVENTS = new Set(["DescribeKey", "ListResourceTags", "GetKeyRotationStatus", "GetKeyPolicy", "ListAliases", "ListKeyPolicies", "ListGrants", "GetPublicKey"]);

export interface KeyFacts { key_id: string; key_arn: string; manager: string; state: string; enabled: boolean; multi_region: boolean; created: string | null; hands_off: boolean }
export interface KeyRefs { volumes: number; snapshots: number; rds_instances: number; rds_clusters: number; log_groups: number }
export interface KeyVerdict { unused: boolean; reasons: string[]; refs: number }

/** Unused only when the key qualifies, nothing references it, and CloudTrail shows no real call. `events` = null means CloudTrail could not be read: alive. */
export function kmsUnusedVerdict(key: KeyFacts, refs: KeyRefs, events: string[] | null, now = Date.now()): KeyVerdict {
  const reasons: string[] = [];
  if (key.manager !== "CUSTOMER") reasons.push("AWS-managed key");
  if (!key.enabled || key.state !== "Enabled") reasons.push(`key state ${key.state}${key.enabled ? "" : " (disabled)"}`);
  if (key.multi_region) reasons.push("multi-region key");
  if (key.hands_off) reasons.push("tagged advisor:hands-off");
  const ageDays = key.created ? (now - new Date(key.created).getTime()) / 86400000 : null;
  if (ageDays == null) reasons.push("creation date unknown");
  else if (ageDays < MIN_AGE_DAYS) reasons.push(`${Math.floor(ageDays)} days old (${MIN_AGE_DAYS} needed)`);
  const refList = [refs.volumes && `${refs.volumes} EBS volume(s)`, refs.snapshots && `${refs.snapshots} snapshot(s)`, refs.rds_instances && `${refs.rds_instances} RDS instance(s)`, refs.rds_clusters && `${refs.rds_clusters} RDS cluster(s)`, refs.log_groups && `${refs.log_groups} log group(s)`].filter(Boolean) as string[];
  const total = refs.volumes + refs.snapshots + refs.rds_instances + refs.rds_clusters + refs.log_groups;
  if (refList.length) reasons.push(`encrypts ${refList.join(", ")}`);
  if (events == null) reasons.push("CloudTrail history unreadable: usage unknown counts as used");
  else { const real = events.filter((e) => !HARMLESS_EVENTS.has(e)); if (real.length) reasons.push(`CloudTrail shows ${[...new Set(real)].slice(0, 3).join(", ")} in the last ${LOOKBACK_DAYS} days`); }
  return { unused: reasons.length === 0, reasons, refs: total };
}

export const keyId = (arnOrId: string | null | undefined): string | null => { if (!arnOrId) return null; const s = String(arnOrId); return s.startsWith("arn:") ? s.split("/").pop() || s : s; };

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function regions(defaultRegion: string): string[] {
  const rows = [
    ...(db.prepare("select distinct region from inventory_ec2 where gone = 0 and region is not null").all() as { region: string }[]),
    ...(db.prepare("select distinct region from inventory_rds where gone = 0 and region is not null").all() as { region: string }[]),
  ];
  return [...new Set([defaultRegion, ...rows.map((r) => r.region)])];
}

/** Every key id referenced as KmsKeyId by what the read credentials can describe in the region, counted per kind. */
async function referencedKeys(creds: Creds, region: string, log: (l: string) => void): Promise<Map<string, KeyRefs>> {
  const out = new Map<string, KeyRefs>();
  const bump = (arnOrId: string | null | undefined, kind: keyof KeyRefs) => { const id = keyId(arnOrId); if (!id) return; const row: KeyRefs = out.get(id) ?? { volumes: 0, snapshots: 0, rds_instances: 0, rds_clusters: 0, log_groups: 0 }; row[kind]++; out.set(id, row); };
  const ec2 = new EC2Client({ region, credentials: creds.read });
  try {
    let token: string | undefined;
    do { const page = await ec2.send(new DescribeVolumesCommand({ MaxResults: 500, NextToken: token })); for (const v of page.Volumes ?? []) bump(v.KmsKeyId, "volumes"); token = page.NextToken; } while (token);
    let snapToken: string | undefined;
    do { const page = await ec2.send(new DescribeSnapshotsCommand({ OwnerIds: ["self"], MaxResults: 1000, NextToken: snapToken })); for (const s of page.Snapshots ?? []) bump(s.KmsKeyId, "snapshots"); snapToken = page.NextToken; } while (snapToken);
  } catch (e: any) { log(`${region}: EC2 references unreadable: ${String(e?.message || e).slice(0, 120)}`); throw e; }
  finally { ec2.destroy(); }
  const rds = new RDSClient({ region, credentials: creds.read });
  try {
    let marker: string | undefined;
    do { const page = await rds.send(new DescribeDBInstancesCommand({ Marker: marker })); for (const i of page.DBInstances ?? []) { bump(i.KmsKeyId, "rds_instances"); bump(i.PerformanceInsightsKMSKeyId, "rds_instances"); } marker = page.Marker; } while (marker);
    let clusterMarker: string | undefined;
    do { const page = await rds.send(new DescribeDBClustersCommand({ Marker: clusterMarker })); for (const c of page.DBClusters ?? []) bump(c.KmsKeyId, "rds_clusters"); clusterMarker = page.Marker; } while (clusterMarker);
  } catch (e: any) { log(`${region}: RDS references unreadable: ${String(e?.message || e).slice(0, 120)}`); throw e; }
  finally { rds.destroy(); }
  const logs = new CloudWatchLogsClient({ region, credentials: creds.read });
  try {
    let token: string | undefined;
    do { const page = await logs.send(new DescribeLogGroupsCommand({ limit: 50, nextToken: token })); for (const g of page.logGroups ?? []) bump(g.kmsKeyId, "log_groups"); token = page.nextToken; } while (token);
  } catch (e: any) { log(`${region}: log group references unreadable: ${String(e?.message || e).slice(0, 120)}`); throw e; }
  finally { logs.destroy(); }
  return out;
}

/** Event names CloudTrail holds for the key in the lookback window (a sample: the first page is enough to tell use from silence); null when the lookup is denied. */
async function keyEvents(trail: CloudTrailClient, keyArn: string, now: number): Promise<{ events: string[]; last: string | null } | null> {
  try {
    const r = await trail.send(new LookupEventsCommand({ LookupAttributes: [{ AttributeKey: "ResourceName", AttributeValue: keyArn }], StartTime: new Date(now - LOOKBACK_DAYS * 86400000), EndTime: new Date(now), MaxResults: 20 }));
    const evs = r.Events ?? [];
    return { events: evs.map((e) => String(e.EventName || "")), last: evs.find((e) => !HARMLESS_EVENTS.has(String(e.EventName)))?.EventTime?.toISOString() ?? null };
  } catch (e: any) { if (/AccessDenied|not authorized/i.test(String(e?.message || e))) return null; throw e; }
}

const factsOf = (m: KeyMetadata, handsOff: boolean): KeyFacts => ({ key_id: m.KeyId!, key_arn: m.Arn || m.KeyId!, manager: m.KeyManager || "?", state: m.KeyState || "?", enabled: Boolean(m.Enabled), multi_region: Boolean(m.MultiRegion), created: m.CreationDate ? new Date(m.CreationDate).toISOString() : null, hands_off: handsOff });

export const kmsKeyRetireAction: ActionModule = {
  kind: KIND,
  label: "Unused KMS keys scheduled for deletion, once approved",
  grace_hours: () => config.actDeleteGraceHours,
  announce: true,

  async plan(creds, log) {
    const proposals: Proposal[] = []; const notes: string[] = [];
    const now = Date.now();
    const runId = (db.prepare("select id from runs order by id desc limit 1").get() as { id: number } | undefined)?.id ?? 0;
    const approved = approvedRecs([ACTION_TYPE]);
    let lookups = 0, seen = 0, filed = 0, unread = false;
    for (const acct of creds.accounts) for (const region of regions(acct.region)) {
      const ac = credsForAccount(creds, acct.account_id);
      const kms = new KMSClient({ region, credentials: ac.read });
      const trail = new CloudTrailClient({ region, credentials: ac.read });
      try {
        const ids: string[] = [];
        let marker: string | undefined;
        do { const r = await kms.send(new ListKeysCommand({ Limit: 1000, Marker: marker })); ids.push(...(r.Keys ?? []).map((k) => k.KeyId!)); marker = r.Truncated ? r.NextMarker : undefined; } while (marker);
        if (!ids.length) continue;
        const aliases = new Map<string, string[]>();
        let aliasMarker: string | undefined;
        do { const r = await kms.send(new ListAliasesCommand({ Limit: 100, Marker: aliasMarker })); for (const a of r.Aliases ?? []) if (a.TargetKeyId && a.AliasName) aliases.set(a.TargetKeyId, [...(aliases.get(a.TargetKeyId) ?? []), a.AliasName]); aliasMarker = r.Truncated ? r.NextMarker : undefined; } while (aliasMarker);
        let refs: Map<string, KeyRefs>;
        try { refs = await referencedKeys(ac, region, log); } catch (e: any) { notes.push(`${region}: references unreadable (${String(e?.message || e).slice(0, 100)}); nothing filed`); continue; }
        const recs: RecInput[] = [];
        for (const id of ids) {
          seen++;
          const name = aliases.get(id)?.[0] ?? id;
          const skip = (why: string) => { log(`${name}: ${why}`); };
          let meta: KeyMetadata | undefined;
          try { meta = (await kms.send(new DescribeKeyCommand({ KeyId: id }))).KeyMetadata; } catch (e: any) { skip(`DescribeKey: ${String(e?.message || e).slice(0, 100)}`); continue; }
          if (!meta) continue;
          const approval = approved.find((a) => a.resource === id) ?? null;
          if (approval) {
            // the decision is made: verify the key is still there to retire, and propose
            if (meta.KeyState === "PendingDeletion") { skip("already pending deletion"); continue; }
            if (meta.KeyState !== "Enabled" && meta.KeyState !== "Disabled") { skip(`key state ${meta.KeyState}`); continue; }
            let handsOff = false;
            try { handsOff = ((await kms.send(new ListResourceTagsCommand({ KeyId: id }))).Tags ?? []).some((t) => t.TagKey === "advisor:hands-off"); } catch { /* the policy's Deny still protects a tagged key */ }
            if (handsOff) { notes.push(`${name}: tagged advisor:hands-off`); continue; }
            const days = Math.min(30, Math.max(7, Math.round(config.actKmsPendingDays)));
            proposals.push({
              kind: KIND, resource: id, resource_name: name, region, account_id: acct.is_parent ? null : acct.account_id,
              dedupe: `${KIND}:${region}:${id}`,
              title: `${name}: schedule KMS key deletion (${days}-day waiting period)`,
              reason: `${approval.title}. Approved as recommendation #${approval.id}${approval.decided_by ? ` by ${approval.decided_by}` : ""}. ScheduleKeyDeletion, never an outright delete: the key is unusable from now and gone after ${days} days; until then CancelKeyDeletion brings it back with every grant and policy intact. Anything still encrypted under it becomes unreadable once the key is gone.`,
              before: { key_state: meta.KeyState }, after: { key_state: "PendingDeletion", pending_days: days },
              facts: { recommendation_id: approval.id, key_arn: meta.Arn, aliases: aliases.get(id) ?? [], created: meta.CreationDate ? new Date(meta.CreationDate).toISOString() : null, last_event: approval.evidence?.last_event ?? null, refs: approval.evidence?.refs ?? null },
              rollback: "CancelKeyDeletion then EnableKey: the key comes back intact any time within the waiting period",
              est_usd_month: KMS_KEY_USD_MONTH,
            });
            continue;
          }
          // discovery: cheap checks first, CloudTrail last and rationed
          if (meta.KeyManager !== "CUSTOMER" || meta.KeyState !== "Enabled" || meta.MultiRegion) continue;
          const ageDays = meta.CreationDate ? (now - new Date(meta.CreationDate).getTime()) / 86400000 : null;
          if (ageDays == null || ageDays < MIN_AGE_DAYS) continue;
          const keyRefs: KeyRefs = refs.get(id) ?? { volumes: 0, snapshots: 0, rds_instances: 0, rds_clusters: 0, log_groups: 0 };
          if (Object.values(keyRefs).some((n) => n > 0)) continue;
          let handsOff = false;
          try { handsOff = ((await kms.send(new ListResourceTagsCommand({ KeyId: id }))).Tags ?? []).some((t) => t.TagKey === "advisor:hands-off"); } catch { /* unreadable tags: treat as not tagged; the Deny still applies */ }
          if (handsOff) { skip("tagged advisor:hands-off"); continue; }
          if (lookups >= MAX_LOOKUPS_PER_PASS) { skip("CloudTrail lookups for this pass used up; next pass"); continue; }
          if (lookups) await sleep(LOOKUP_PAUSE_MS);
          lookups++;
          const ev = await keyEvents(trail, meta.Arn || id, now);
          if (ev == null) { unread = true; skip("CloudTrail LookupEvents denied: usage unknown, nothing filed"); break; }
          const v = kmsUnusedVerdict(factsOf(meta, handsOff), keyRefs, ev.events, now);
          if (!v.unused) { skip(`in use: ${v.reasons.join("; ")}`); continue; }
          filed++;
          recs.push({
            rule: RULE, title: `Retire unused KMS key ${name}${name !== id ? ` (${id})` : ""}`, resource: id, resourceName: name, actionType: ACTION_TYPE,
            estMonthlySaving: KMS_KEY_USD_MONTH, tier: "approve", confidence: 0.6,
            rationale: `Customer-managed key created ${new Date(meta.CreationDate!).toISOString().slice(0, 10)}${aliases.get(id)?.length ? ` (alias ${aliases.get(id)!.join(", ")})` : ", no alias"}: no EBS volume or snapshot, RDS instance or cluster, or CloudWatch log group in ${region} is encrypted with it, and CloudTrail shows no cryptographic call against it in the last ${LOOKBACK_DAYS} days${ev.events.length ? ` (only ${[...new Set(ev.events)].join(", ")})` : ""}. The advisor cannot see S3 default encryption, Secrets Manager, Lambda environment or application-level use, so confirm nothing else holds ciphertext under it. Approving schedules deletion with a ${Math.round(config.actKmsPendingDays)}-day waiting period (cancelable); 1 USD/month per key.`,
            evidence: { region, key_arn: meta.Arn, aliases: aliases.get(id) ?? [], created: meta.CreationDate ? new Date(meta.CreationDate).toISOString() : null, events: ev.events, last_event: ev.last, refs: keyRefs, lookback_days: LOOKBACK_DAYS },
          });
        }
        if (recs.length) upsertRecommendations(runId, recs, "rules", undefined, { reconcile: false });
      } catch (e: any) { const m = String(e?.message || e); notes.push(`${region}: ${m.slice(0, 160)}`); log(`${region}: ${m}`); }
      finally { kms.destroy(); trail.destroy(); }
    }
    if (!seen) notes.push("no KMS key found");
    else notes.push(`${seen} key(s) seen, ${lookups} checked against CloudTrail, ${filed} recommendation(s) filed or refreshed${unread ? "; CloudTrail LookupEvents is denied, so usage is unknown and nothing more is filed" : ""}`);
    if (!approved.length) notes.push("no approved recommendation to retire a key");
    return { proposals, notes };
  },

  async apply(p, creds) {
    const kms = new KMSClient({ region: p.region, credentials: creds.act() });
    try {
      const r = await kms.send(new ScheduleKeyDeletionCommand({ KeyId: p.resource, PendingWindowInDays: Number(p.after.pending_days) }));
      return `ScheduleKeyDeletion: ${r.KeyState || "PendingDeletion"}, deleted on ${r.DeletionDate ? new Date(r.DeletionDate).toISOString().slice(0, 10) : `+${p.after.pending_days} days`} unless cancelled`;
    } finally { kms.destroy(); }
  },

  async verify(p, creds) {
    const kms = new KMSClient({ region: p.region, credentials: creds.read });
    try {
      const m = (await kms.send(new DescribeKeyCommand({ KeyId: p.resource }))).KeyMetadata;
      if (!m) return { ok: false, note: "key not found on read-back" };
      if (m.KeyState === "PendingDeletion") return { ok: true, note: `read back: pending deletion${m.DeletionDate ? ` until ${new Date(m.DeletionDate).toISOString().slice(0, 10)}` : ""}` };
      return { ok: false, note: `key state reads ${m.KeyState}` };
    } catch (e: any) { return /NotFoundException/i.test(String(e?.name || e?.message)) ? { ok: false, note: "key not found on read-back" } : { ok: null, note: String(e?.message || e).slice(0, 120) }; }
    finally { kms.destroy(); }
  },

  async revert(p, creds) {
    const kms = new KMSClient({ region: p.region, credentials: creds.act() });
    try {
      await kms.send(new CancelKeyDeletionCommand({ KeyId: p.resource }));
      try { await kms.send(new EnableKeyCommand({ KeyId: p.resource })); return "CancelKeyDeletion and EnableKey: the key is enabled again"; }
      catch (e: any) { return `CancelKeyDeletion done; EnableKey failed (${String(e?.message || e).slice(0, 100)}): the key is back but disabled, enable it by hand`; }
    } catch (e: any) {
      if (/NotFoundException/i.test(String(e?.name || e?.message))) throw new Error("the key no longer exists: the waiting period has passed");
      throw e;
    } finally { kms.destroy(); }
  },
};

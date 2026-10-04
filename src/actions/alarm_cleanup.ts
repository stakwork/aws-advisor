/**
 * CloudWatch alarms left behind by resources that no longer exist. An alarm on a terminated instance, a deleted
 * volume, a dropped database, a removed function or a deleted NAT gateway sits in INSUFFICIENT_DATA forever and
 * bills 0.10 USD a month (0.30 for a high-resolution one); nobody goes back to delete them. The executor deletes a
 * metric alarm when it has had no data for ACT_ALARM_STALE_DAYS (30) and the resource its dimensions name is gone
 * for certain: a describe call that no longer returns it. Alarms whose dimensions name something the executor
 * cannot check (a load balancer, a custom namespace, a queue) are left alone and counted; composite alarms and
 * alarms tagged `advisor:hands-off` too. The full alarm definition goes on the row, so Revert recreates it with
 * PutMetricAlarm exactly as it was (its state history does not come back, which is the only thing lost).
 */
import { CloudWatchClient, DeleteAlarmsCommand, DescribeAlarmsCommand, ListTagsForResourceCommand, PutMetricAlarmCommand, type MetricAlarm } from "@aws-sdk/client-cloudwatch";
import { DescribeInstancesCommand, DescribeNatGatewaysCommand, DescribeVolumesCommand, EC2Client } from "@aws-sdk/client-ec2";
import { DescribeDBClustersCommand, DescribeDBInstancesCommand, RDSClient } from "@aws-sdk/client-rds";
import { db } from "../db.js";
import { config } from "../config.js";
import type { ActionModule, Creds, Proposal } from "../executor.js";
import { credsForAccount } from "../executor.js";
import { accountWhere, type AccountScope } from "../scope.js";

export const KIND = "alarm_cleanup" as const;
export const ALARM_USD_MONTH = 0.10;
export const HIGH_RES_ALARM_USD_MONTH = 0.30;
const MAX_ALARMS_PER_REGION = 500;
const MAX_PER_PLAN = 50;

/** The dimension names whose resource the executor can check, and how the check reads (per region). */
export const CHECKABLE_DIMENSIONS = ["InstanceId", "VolumeId", "DBInstanceIdentifier", "DBClusterIdentifier", "FunctionName", "NatGatewayId"] as const;
export type CheckableDimension = typeof CHECKABLE_DIMENSIONS[number];
export interface Dim { name: string; value: string }

/** true = gone for certain, false = still there, null = cannot tell (unknown dimension kind, or the check failed). */
export type GoneCheck = (dim: Dim) => boolean | null;

export interface StaleVerdict { stale: boolean; why: string; dimension: Dim | null; age_days: number | null }

/**
 * An alarm is stale when it is a metric alarm in INSUFFICIENT_DATA for at least `staleDays`, and one of its
 * dimensions names a resource the check says is gone. A dimension the check cannot judge never makes it stale.
 * Pure: the check is injected.
 */
export function staleVerdict(alarm: Pick<MetricAlarm, "AlarmName" | "StateValue" | "StateUpdatedTimestamp" | "Dimensions" | "Metrics">, gone: GoneCheck, staleDays: number, now = Date.now()): StaleVerdict {
  if (alarm.StateValue !== "INSUFFICIENT_DATA") return { stale: false, why: `state ${alarm.StateValue || "unknown"}`, dimension: null, age_days: null };
  const since = alarm.StateUpdatedTimestamp ? new Date(alarm.StateUpdatedTimestamp).getTime() : null;
  const ageDays = since != null ? Math.floor((now - since) / 86400000) : null;
  if (ageDays == null) return { stale: false, why: "no state timestamp", dimension: null, age_days: null };
  if (ageDays < staleDays) return { stale: false, why: `no data for ${ageDays} days (rule: ${staleDays}+)`, dimension: null, age_days: ageDays };
  const dims: Dim[] = [
    ...(alarm.Dimensions ?? []).map((d) => ({ name: String(d.Name || ""), value: String(d.Value || "") })),
    ...(alarm.Metrics ?? []).flatMap((m) => (m.MetricStat?.Metric?.Dimensions ?? []).map((d) => ({ name: String(d.Name || ""), value: String(d.Value || "") }))),
  ].filter((d) => d.name && d.value);
  const checkable = dims.filter((d) => (CHECKABLE_DIMENSIONS as readonly string[]).includes(d.name));
  if (!checkable.length) return { stale: false, why: dims.length ? `dimensions ${dims.map((d) => d.name).join(", ")} cannot be checked` : "no dimension to check", dimension: null, age_days: ageDays };
  let alive: Dim | null = null; let unknown: Dim | null = null;
  for (const d of checkable) {
    const g = gone(d);
    if (g === true) return { stale: true, why: `${d.name} ${d.value} no longer exists; no data for ${ageDays} days`, dimension: d, age_days: ageDays };
    if (g === false) alive = alive ?? d; else unknown = unknown ?? d;
  }
  if (alive) return { stale: false, why: `${alive.name} ${alive.value} still exists`, dimension: alive, age_days: ageDays };
  return { stale: false, why: `${unknown!.name} ${unknown!.value} could not be checked`, dimension: unknown, age_days: ageDays };
}

/** The fields PutMetricAlarm accepts, taken from a DescribeAlarms row, so the revert recreates the alarm as it was. Pure. */
export function alarmDefinition(a: MetricAlarm): Record<string, unknown> {
  const keys = ["AlarmName", "AlarmDescription", "ActionsEnabled", "OKActions", "AlarmActions", "InsufficientDataActions", "MetricName", "Namespace", "Statistic", "ExtendedStatistic", "Dimensions", "Period", "Unit", "EvaluationPeriods", "DatapointsToAlarm", "Threshold", "ComparisonOperator", "TreatMissingData", "EvaluateLowSampleCountPercentile", "Metrics", "ThresholdMetricId"] as const;
  const out: Record<string, unknown> = {};
  for (const k of keys) { const v = (a as any)[k]; if (v !== undefined && v !== null && !(Array.isArray(v) && v.length === 0)) out[k] = v; }
  return out;
}

export const alarmCost = (a: Pick<MetricAlarm, "Period">) => (a.Period != null && a.Period < 60 ? HIGH_RES_ALARM_USD_MONTH : ALARM_USD_MONTH);

function regions(creds: Creds): string[] {
  const rows = db.prepare("select region from inventory_ec2 where gone = 0 union select region from inventory_rds where gone = 0").all() as { region: string | null }[];
  const set = new Set<string>(rows.map((r) => r.region).filter((r): r is string => Boolean(r)));
  set.add(creds.region);
  return [...set].sort();
}

/** Existence checks per region, each memoised; a failed describe answers null (cannot tell), never true. */
function goneChecker(region: string, creds: Creds, scope: AccountScope | null = null): { gone: GoneCheck; resolve: (dims: Dim[]) => Promise<void>; destroy: () => void } {
  const ec2 = new EC2Client({ region, credentials: creds.read });
  const rds = new RDSClient({ region, credentials: creds.read });
  const known = new Map<string, boolean | null>();
  const key = (d: Dim) => `${d.name}:${d.value}`;
  const notFound = (e: any) => /NotFound|does not exist|Malformed/i.test(String(e?.name || e?.message || e));
  const check = async (d: Dim): Promise<boolean | null> => {
    try {
      switch (d.name as CheckableDimension) {
        case "InstanceId": {
          const i = (await ec2.send(new DescribeInstancesCommand({ InstanceIds: [d.value] }))).Reservations?.flatMap((r) => r.Instances ?? [])[0];
          return !i || i.State?.Name === "terminated";
        }
        case "VolumeId": return !(await ec2.send(new DescribeVolumesCommand({ VolumeIds: [d.value] }))).Volumes?.length;
        case "NatGatewayId": {
          const g = (await ec2.send(new DescribeNatGatewaysCommand({ NatGatewayIds: [d.value] }))).NatGateways?.[0];
          return !g || g.State === "deleted";
        }
        case "DBInstanceIdentifier": return !(await rds.send(new DescribeDBInstancesCommand({ DBInstanceIdentifier: d.value }))).DBInstances?.length;
        case "DBClusterIdentifier": return !(await rds.send(new DescribeDBClustersCommand({ DBClusterIdentifier: d.value }))).DBClusters?.length;
        case "FunctionName": {
          // The Lambda inventory is the record: a function it has never seen cannot be called gone. Names are unique per account only.
          const w = accountWhere(scope);
          const row = db.prepare(`select gone from inventory_lambda where name = ? and (region = ? or region is null) and ${w.sql}`).get(d.value, region, ...w.params) as { gone: number } | undefined;
          return row ? row.gone === 1 : null;
        }
        default: return null;
      }
    } catch (e) { return notFound(e) ? true : null; }
  };
  return {
    gone: (d) => known.get(key(d)) ?? null,
    resolve: async (dims) => { for (const d of dims) if (!known.has(key(d)) && (CHECKABLE_DIMENSIONS as readonly string[]).includes(d.name)) known.set(key(d), await check(d)); },
    destroy: () => { ec2.destroy(); rds.destroy(); },
  };
}

const dimsOf = (a: MetricAlarm): Dim[] => [
  ...(a.Dimensions ?? []).map((d) => ({ name: String(d.Name || ""), value: String(d.Value || "") })),
  ...(a.Metrics ?? []).flatMap((m) => (m.MetricStat?.Metric?.Dimensions ?? []).map((d) => ({ name: String(d.Name || ""), value: String(d.Value || "") }))),
].filter((d) => d.name && d.value);

export const alarmCleanupAction: ActionModule = {
  kind: KIND,
  label: "Stale alarms on gone resources deleted",

  async plan(creds, log) {
    const proposals: Proposal[] = []; const notes: string[] = [];
    const staleDays = Math.max(7, Math.round(config.actAlarmStaleDays));
    let scanned = 0, insufficient = 0, uncheckable = 0, alive = 0, young = 0;
    for (const acct of creds.accounts) for (const region of regions(credsForAccount(creds, acct.account_id))) {
      const ac = credsForAccount(creds, acct.account_id);
      if (proposals.length >= MAX_PER_PLAN) { notes.push(`${MAX_PER_PLAN} proposals is enough for one pass; ${region} waits`); continue; }
      const cw = new CloudWatchClient({ region, credentials: ac.read });
      const checker = goneChecker(region, ac, { id: acct.account_id, primary: acct.is_parent });
      try {
        const alarms: MetricAlarm[] = [];
        let NextToken: string | undefined;
        do {
          const r = await cw.send(new DescribeAlarmsCommand({ AlarmTypes: ["MetricAlarm"], StateValue: "INSUFFICIENT_DATA", MaxRecords: 100, NextToken }));
          alarms.push(...(r.MetricAlarms ?? [])); NextToken = r.NextToken;
        } while (NextToken && alarms.length < MAX_ALARMS_PER_REGION);
        scanned += alarms.length; insufficient += alarms.length;
        if (NextToken) notes.push(`${region}: more than ${MAX_ALARMS_PER_REGION} alarms in INSUFFICIENT_DATA; the rest wait for a later pass`);
        // Only alarms old enough are worth a describe call.
        const old = alarms.filter((a) => a.StateUpdatedTimestamp && Date.now() - new Date(a.StateUpdatedTimestamp).getTime() >= staleDays * 86400000);
        young += alarms.length - old.length;
        await checker.resolve(old.flatMap(dimsOf));
        for (const a of old) {
          if (proposals.length >= MAX_PER_PLAN) break;
          const name = a.AlarmName!;
          const v = staleVerdict(a, checker.gone, staleDays);
          if (!v.stale) { if (/cannot be checked|no dimension|could not be checked/.test(v.why)) uncheckable++; else if (/still exists/.test(v.why)) alive++; log(`${name}: ${v.why}`); continue; }
          const skip = (why: string) => { notes.push(`${name}: ${why}`); log(`${name}: ${why}`); };
          if (a.AlarmArn) {
            try { if ((await cw.send(new ListTagsForResourceCommand({ ResourceARN: a.AlarmArn }))).Tags?.some((t) => t.Key === "advisor:hands-off")) { skip("tagged advisor:hands-off"); continue; } }
            catch { /* tags unreadable: the policy's Deny still protects a tagged alarm */ }
          }
          const cost = alarmCost(a);
          proposals.push({
            kind: KIND, resource: name, resource_name: name, region, account_id: acct.is_parent ? null : acct.account_id,
            dedupe: `${KIND}:${region}:${name}`,
            title: `delete alarm ${name}: ${v.dimension!.name} ${v.dimension!.value} is gone, no data for ${v.age_days} days`,
            reason: `${a.Namespace || "?"}/${a.MetricName || (a.Metrics?.length ? "math expression" : "?")} on ${v.dimension!.name} ${v.dimension!.value}, which no longer exists; in INSUFFICIENT_DATA since ${a.StateUpdatedTimestamp ? new Date(a.StateUpdatedTimestamp).toISOString().slice(0, 10) : "?"} (${v.age_days} days, rule: ${staleDays}+). It can never fire again and bills ${cost.toFixed(2)} USD a month${(a.AlarmActions?.length ?? 0) > 0 ? `; its ${a.AlarmActions!.length} action(s) are kept on the row` : ""}. The definition is saved on the row, so Revert recreates it as it was.`,
            before: { alarm: "present", state: a.StateValue }, after: { alarm: "deleted" },
            facts: { definition: alarmDefinition(a), alarm_arn: a.AlarmArn ?? null, gone_dimension: v.dimension, state_since: a.StateUpdatedTimestamp ? new Date(a.StateUpdatedTimestamp).toISOString() : null, age_days: v.age_days, actions: a.AlarmActions ?? [] },
            rollback: "recreate the alarm from its saved definition (PutMetricAlarm); its state history does not come back",
            est_usd_month: cost,
          });
        }
      } catch (e: any) { const m = String(e?.message || e); notes.push(`${region}: ${m.slice(0, 160)}`); log(`${region}: ${m}`); }
      finally { cw.destroy(); checker.destroy(); }
    }
    if (!scanned) notes.push("no metric alarm in INSUFFICIENT_DATA");
    else {
      const parts = [`${insufficient} alarm(s) in INSUFFICIENT_DATA`];
      if (young) parts.push(`${young} under ${staleDays} days`);
      if (alive) parts.push(`${alive} on resources that still exist`);
      if (uncheckable) parts.push(`${uncheckable} on dimensions the executor cannot check (left alone)`);
      notes.push(parts.join("; "));
    }
    return { proposals, notes };
  },

  async apply(p, creds) {
    const cw = new CloudWatchClient({ region: p.region, credentials: creds.act() });
    try { await cw.send(new DeleteAlarmsCommand({ AlarmNames: [p.resource] })); return `DeleteAlarms: ${p.resource} deleted`; }
    finally { cw.destroy(); }
  },

  async verify(p, creds) {
    const cw = new CloudWatchClient({ region: p.region, credentials: creds.read });
    try {
      const r = await cw.send(new DescribeAlarmsCommand({ AlarmNames: [p.resource], AlarmTypes: ["MetricAlarm"] }));
      return r.MetricAlarms?.length ? { ok: false, note: "the alarm is still there on read-back" } : { ok: true, note: "read back: alarm gone" };
    } finally { cw.destroy(); }
  },

  async revert(p, creds) {
    const def = p.facts?.definition as Record<string, any> | undefined;
    if (!def?.AlarmName) throw new Error("no saved alarm definition on the row; recreate the alarm by hand");
    const cw = new CloudWatchClient({ region: p.region, credentials: creds.act() });
    try { await cw.send(new PutMetricAlarmCommand(def as any)); return `PutMetricAlarm: ${def.AlarmName} recreated from the saved definition`; }
    finally { cw.destroy(); }
  },
};

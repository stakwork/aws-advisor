/**
 * DynamoDB capacity mode from the 30-day load, once a person approved it. A provisioned table bills for every
 * unit it reserves whether or not anyone reads; an on-demand table bills per request. The plan reads thirty
 * days of consumed and provisioned units from CloudWatch, prices the table both ways at list, and files a
 * tier-approve recommendation where the other mode is at least 20 % and 5 USD a month cheaper: the switch
 * changes the shape of the bill and the throttling behaviour, so a human confirms. Approving it is the
 * decision; the executor makes the change with UpdateTable, online, no downtime. Going to provisioned, the
 * units are set to the hourly peak consumed plus 30 % headroom, per table and per index. AWS allows one switch
 * to on-demand per table every 24 hours; a table with application auto scaling, a global table, a table that is
 * not ACTIVE, one with fewer than 14 days of metrics or one tagged `advisor:hands-off` is left alone.
 */
import { CloudWatchClient, GetMetricDataCommand, type MetricDataQuery } from "@aws-sdk/client-cloudwatch";
import { DescribeTableCommand, DynamoDBClient, ListTablesCommand, ListTagsOfResourceCommand, UpdateTableCommand, type TableDescription, type UpdateTableCommandInput } from "@aws-sdk/client-dynamodb";
import { db } from "../db.js";
import { query, S } from "../steampipe.js";
import { upsertRecommendations } from "../collector.js";
import type { RecInput } from "../rules.js";
import { approvedRecs, type ActionModule, type Creds, type Proposal } from "../executor.js";

export const KIND = "dynamodb_capacity_mode" as const;
export const ACTION_TYPE = "set_dynamodb_capacity_mode";
export const RULE = "dynamodb_capacity_mode";
/** us-east-1 list prices. */
export const RCU_USD_HOUR = 0.00013;
export const WCU_USD_HOUR = 0.00065;
export const HOURS_MONTH = 730;
export const ON_DEMAND_READ_USD_PER_MILLION = 0.125;
export const ON_DEMAND_WRITE_USD_PER_MILLION = 0.625;
export const MIN_SAVING_SHARE = 0.2;
export const MIN_SAVING_USD = 5;
export const MIN_METRIC_DAYS = 14;
export const HEADROOM = 1.3;
export const SWITCH_COOLDOWN_HOURS = 24;
const METRIC_DAYS = 30;
const MAX_TABLES_PER_PLAN = 100;

export type BillingMode = "PROVISIONED" | "PAY_PER_REQUEST";
export interface GsiUnits { name: string; read: number; write: number }
export interface TableFacts { name: string; billing_mode: BillingMode; read_units: number; write_units: number; gsis: GsiUnits[] }
export interface TableMetrics {
  /** Consumed units over the window, table and indexes together. */
  read_consumed: number; write_consumed: number;
  /** Busiest hour's consumed units (table alone). */
  read_peak_hour: number; write_peak_hour: number;
  /** Busiest hour per index, by index name. */
  gsi_peak_hour: Record<string, { read: number; write: number }>;
  days: number;
}
export interface Verdict {
  current_mode: BillingMode; target_mode: BillingMode | null; cost_now: number; cost_other: number; reason: string;
  /** Units to provision when the target is PROVISIONED. */
  provision?: { read_units: number; write_units: number; gsis: GsiUnits[] };
}

const round2 = (n: number) => Math.round(n * 100) / 100;
const usd = (n: number) => `${round2(n).toFixed(2)} USD/month`;

/** What the table costs a month provisioned as it is (or would be), table plus indexes. */
export const provisionedCost = (read: number, write: number, gsis: GsiUnits[]) =>
  round2((read + gsis.reduce((s, g) => s + g.read, 0)) * RCU_USD_HOUR * HOURS_MONTH + (write + gsis.reduce((s, g) => s + g.write, 0)) * WCU_USD_HOUR * HOURS_MONTH);

/** What the window's consumption would cost on demand, scaled to a 30-day month (consumed units ≈ request units). */
export const onDemandCost = (m: Pick<TableMetrics, "read_consumed" | "write_consumed" | "days">) => {
  const scale = m.days > 0 ? 30 / m.days : 0;
  return round2(((m.read_consumed * ON_DEMAND_READ_USD_PER_MILLION + m.write_consumed * ON_DEMAND_WRITE_USD_PER_MILLION) / 1e6) * scale);
};

/** Units for a peak hour: the per-second rate plus headroom, never under one. */
export const unitsForPeak = (peakHour: number) => Math.max(1, Math.ceil((peakHour / 3600) * HEADROOM));

/** The verdict for one table: pure. */
export function capacityVerdict(t: TableFacts, m: TableMetrics): Verdict {
  const current = t.billing_mode;
  if (m.days < MIN_METRIC_DAYS) return { current_mode: current, target_mode: null, cost_now: 0, cost_other: 0, reason: `${m.days} days of metrics, ${MIN_METRIC_DAYS} needed` };
  if (current === "PROVISIONED") {
    const now = provisionedCost(t.read_units, t.write_units, t.gsis);
    const other = onDemandCost(m);
    const saving = now - other;
    if (saving >= MIN_SAVING_USD && saving >= MIN_SAVING_SHARE * now) {
      return { current_mode: current, target_mode: "PAY_PER_REQUEST", cost_now: now, cost_other: other, reason: `provisioned ${t.read_units} RCU / ${t.write_units} WCU${t.gsis.length ? ` plus ${t.gsis.length} index(es)` : ""} costs ${usd(now)}; the last ${m.days} days' consumption (${Math.round(m.read_consumed).toLocaleString()} reads, ${Math.round(m.write_consumed).toLocaleString()} writes) would cost ${usd(other)} on demand` };
    }
    return { current_mode: current, target_mode: null, cost_now: now, cost_other: other, reason: `provisioned costs ${usd(now)}, on demand would cost ${usd(other)}: ${saving > 0 ? "not enough to switch" : "provisioned is cheaper"}` };
  }
  const now = onDemandCost(m);
  const provision = {
    read_units: unitsForPeak(m.read_peak_hour), write_units: unitsForPeak(m.write_peak_hour),
    gsis: t.gsis.map((g) => ({ name: g.name, read: unitsForPeak(m.gsi_peak_hour[g.name]?.read ?? 0), write: unitsForPeak(m.gsi_peak_hour[g.name]?.write ?? 0) })),
  };
  const other = provisionedCost(provision.read_units, provision.write_units, provision.gsis);
  const saving = now - other;
  if (saving >= MIN_SAVING_USD && saving >= MIN_SAVING_SHARE * now) {
    return { current_mode: current, target_mode: "PROVISIONED", cost_now: now, cost_other: other, provision, reason: `on demand costs ${usd(now)} at the last ${m.days} days' rate; ${provision.read_units} RCU / ${provision.write_units} WCU (the busiest hour plus 30 %) would cost ${usd(other)} provisioned` };
  }
  return { current_mode: current, target_mode: null, cost_now: now, cost_other: other, reason: `on demand costs ${usd(now)}, provisioned for the peak would cost ${usd(other)}: ${saving > 0 ? "not enough to switch" : "on demand is cheaper"}` };
}

export function tableFacts(d: TableDescription): TableFacts {
  const mode: BillingMode = d.BillingModeSummary?.BillingMode === "PAY_PER_REQUEST" ? "PAY_PER_REQUEST" : "PROVISIONED";
  return {
    name: d.TableName!, billing_mode: mode,
    read_units: Number(d.ProvisionedThroughput?.ReadCapacityUnits ?? 0), write_units: Number(d.ProvisionedThroughput?.WriteCapacityUnits ?? 0),
    gsis: (d.GlobalSecondaryIndexes ?? []).map((g) => ({ name: g.IndexName!, read: Number(g.ProvisionedThroughput?.ReadCapacityUnits ?? 0), write: Number(g.ProvisionedThroughput?.WriteCapacityUnits ?? 0) })),
  };
}

const mid = (s: string) => s.replace(/[^a-z0-9]/gi, "_").toLowerCase().slice(0, 200);

/** Thirty days of consumption for a batch of tables, one GetMetricData per region. */
async function tableMetrics(cw: CloudWatchClient, tables: TableFacts[], now = Date.now()): Promise<Map<string, TableMetrics>> {
  const queries: MetricDataQuery[] = [];
  for (const t of tables) {
    for (const [k, mn] of [["r", "ConsumedReadCapacityUnits"], ["w", "ConsumedWriteCapacityUnits"]] as const) {
      queries.push({ Id: `${k}_${mid(t.name)}`, MetricStat: { Metric: { Namespace: "AWS/DynamoDB", MetricName: mn, Dimensions: [{ Name: "TableName", Value: t.name }] }, Period: 3600, Stat: "Sum" }, ReturnData: true });
      for (const g of t.gsis) queries.push({ Id: `${k}_${mid(t.name)}__${mid(g.name)}`, MetricStat: { Metric: { Namespace: "AWS/DynamoDB", MetricName: mn, Dimensions: [{ Name: "TableName", Value: t.name }, { Name: "GlobalSecondaryIndexName", Value: g.name }] }, Period: 3600, Stat: "Sum" }, ReturnData: true });
    }
  }
  const series = new Map<string, { sum: number; peak: number; days: Set<string> }>();
  for (let i = 0; i < queries.length; i += 500) {
    let NextToken: string | undefined;
    do {
      const r = await cw.send(new GetMetricDataCommand({ StartTime: new Date(now - METRIC_DAYS * 86400000), EndTime: new Date(now), MetricDataQueries: queries.slice(i, i + 500), ScanBy: "TimestampAscending", NextToken }));
      for (const res of r.MetricDataResults ?? []) {
        const s = series.get(res.Id!) ?? { sum: 0, peak: 0, days: new Set<string>() };
        (res.Values ?? []).forEach((v, j) => { s.sum += v; if (v > s.peak) s.peak = v; const ts = res.Timestamps?.[j]; if (ts) s.days.add(new Date(ts).toISOString().slice(0, 10)); });
        series.set(res.Id!, s);
      }
      NextToken = r.NextToken;
    } while (NextToken);
  }
  const out = new Map<string, TableMetrics>();
  for (const t of tables) {
    const r = series.get(`r_${mid(t.name)}`), w = series.get(`w_${mid(t.name)}`);
    const m: TableMetrics = { read_consumed: r?.sum ?? 0, write_consumed: w?.sum ?? 0, read_peak_hour: r?.peak ?? 0, write_peak_hour: w?.peak ?? 0, gsi_peak_hour: {}, days: new Set([...(r?.days ?? []), ...(w?.days ?? [])]).size };
    for (const g of t.gsis) {
      const gr = series.get(`r_${mid(t.name)}__${mid(g.name)}`), gw = series.get(`w_${mid(t.name)}__${mid(g.name)}`);
      m.read_consumed += gr?.sum ?? 0; m.write_consumed += gw?.sum ?? 0;
      m.gsi_peak_hour[g.name] = { read: gr?.peak ?? 0, write: gw?.peak ?? 0 };
    }
    out.set(t.name, m);
  }
  return out;
}

/** Tables with an application auto scaling target, from Steampipe; null when the table cannot be read (then nothing goes to on-demand). */
async function autoscaledTables(region: string): Promise<Set<string> | null> {
  try {
    const rows = await query<{ resource_id: string }>(`select resource_id from ${S}.aws_appautoscaling_target where service_namespace = 'dynamodb' and region = '${region.replace(/'/g, "")}'`);
    return new Set(rows.map((r) => String(r.resource_id).replace(/^table\//, "").replace(/\/index\/.*$/, "")));
  } catch { return null; }
}

function regions(defaultRegion: string): string[] {
  const rows = db.prepare("select distinct region from inventory_ec2 where gone = 0 and region is not null").all() as { region: string }[];
  return [...new Set([defaultRegion, ...rows.map((r) => r.region)])];
}

async function describe(ddb: DynamoDBClient, name: string): Promise<TableDescription | null> {
  try { return (await ddb.send(new DescribeTableCommand({ TableName: name }))).Table ?? null; }
  catch (e: any) { if (/ResourceNotFoundException/i.test(String(e?.name || e?.message))) return null; throw e; }
}

const hoursSince = (d: Date | undefined) => (d ? (Date.now() - new Date(d).getTime()) / 3600000 : Infinity);

export const dynamodbCapacityModeAction: ActionModule = {
  kind: KIND,
  label: "DynamoDB capacity mode from the 30-day load, once approved",

  async plan(creds, log) {
    const proposals: Proposal[] = []; const notes: string[] = [];
    const runId = (db.prepare("select id from runs where provider = 'aws' order by id desc limit 1").get() as { id: number } | undefined)?.id ?? 0;
    const approved = approvedRecs([ACTION_TYPE]);
    let scanned = 0, filed = 0;
    for (const acct of creds.accounts) for (const region of regions(acct.region)) {
      const ddb = new DynamoDBClient({ region, credentials: acct.read });
      const cw = new CloudWatchClient({ region, credentials: acct.read });
      try {
        const names: string[] = [];
        let token: string | undefined;
        do { const r = await ddb.send(new ListTablesCommand({ Limit: 100, ExclusiveStartTableName: token })); names.push(...(r.TableNames ?? [])); token = r.LastEvaluatedTableName; } while (token && names.length < MAX_TABLES_PER_PLAN);
        if (!names.length) continue;
        const described: { d: TableDescription; f: TableFacts; arn: string | undefined }[] = [];
        for (const name of names.slice(0, MAX_TABLES_PER_PLAN)) {
          scanned++;
          const d = await describe(ddb, name); if (!d) continue;
          described.push({ d, f: tableFacts(d), arn: d.TableArn });
        }
        if (names.length > MAX_TABLES_PER_PLAN) notes.push(`${region}: ${names.length - MAX_TABLES_PER_PLAN} table(s) wait for a later pass`);
        const metrics = await tableMetrics(cw, described.map((x) => x.f));
        const autoscaled = await autoscaledTables(region);
        if (autoscaled === null) notes.push(`${region}: application auto scaling targets unreadable (aws_appautoscaling_target); no table goes to on-demand this pass`);
        const recs: RecInput[] = [];
        for (const { d, f, arn } of described) {
          const skip = (why: string) => { notes.push(`${f.name}: ${why}`); log(`${f.name}: ${why}`); };
          const m = metrics.get(f.name)!;
          // DynamoDB publishes nothing for an hour with no requests, so a table nobody uses has no datapoints at all: its age is the window then.
          if (m.days === 0 && d.CreationDateTime) m.days = Math.min(METRIC_DAYS, Math.floor((Date.now() - new Date(d.CreationDateTime).getTime()) / 86400000));
          const v = capacityVerdict(f, m);
          if (!v.target_mode) { log(`${f.name}: ${v.reason}`); continue; }
          if (d.TableStatus !== "ACTIVE") { skip(`table is ${d.TableStatus}`); continue; }
          if (d.Replicas?.length) { skip("a global table: its replicas share the mode; left to a person"); continue; }
          if (v.target_mode === "PAY_PER_REQUEST" && (autoscaled === null || autoscaled.has(f.name))) { skip(autoscaled === null ? "autoscaling unknown" : "autoscaling is on; remove it first"); continue; }
          let handsOff = false;
          if (arn) { try { handsOff = ((await ddb.send(new ListTagsOfResourceCommand({ ResourceArn: arn }))).Tags ?? []).some((t) => t.Key === "advisor:hands-off"); } catch { /* the policy's Deny still protects a tagged table */ } }
          if (handsOff) { skip("tagged advisor:hands-off"); continue; }
          const saving = round2(v.cost_now - v.cost_other);
          recs.push({
            rule: RULE, title: `${f.name}: ${v.current_mode === "PROVISIONED" ? "provisioned → on-demand" : "on-demand → provisioned"} capacity (≈ ${saving.toFixed(2)} USD/month)`,
            resource: f.name, resourceName: f.name, actionType: ACTION_TYPE, estMonthlySaving: saving, tier: "approve", confidence: m.days >= 28 ? 0.8 : 0.65,
            rationale: `${v.reason}. UpdateTable is online with no downtime; on demand never throttles for capacity, provisioned throttles above its units${v.provision ? ` (set to the busiest hour plus 30 %: ${v.provision.read_units} RCU / ${v.provision.write_units} WCU)` : ""}. A switch to on-demand is allowed once per 24 hours per table.`,
            evidence: { region, current: f, target_mode: v.target_mode, provision: v.provision ?? null, cost_now: v.cost_now, cost_other: v.cost_other, metrics: m },
          });
          const rec = approved.find((a) => a.resource === f.name);
          if (!rec) { log(`${f.name}: recommendation filed, waiting for approval`); continue; }
          const target = String(rec.evidence?.target_mode || v.target_mode) as BillingMode;
          if (f.billing_mode === target) { skip(`already ${target}`); continue; }
          if (target === "PAY_PER_REQUEST" && hoursSince(d.BillingModeSummary?.LastUpdateToPayPerRequestDateTime) < SWITCH_COOLDOWN_HOURS) { skip(`switched to on-demand less than ${SWITCH_COOLDOWN_HOURS} h ago; AWS allows one per day`); continue; }
          const provision = target === "PROVISIONED" ? (v.provision ?? rec.evidence?.provision) : null;
          if (target === "PROVISIONED" && !provision) { skip("no provisioned units to set"); continue; }
          const after = target === "PROVISIONED" ? { billing_mode: target, read_units: provision.read_units, write_units: provision.write_units, gsis: provision.gsis } : { billing_mode: target };
          proposals.push({
            kind: KIND, resource: f.name, resource_name: f.name, region, account_id: acct.is_parent ? null : acct.account_id,
            dedupe: `${KIND}:${region}:${f.name}:${target}`,
            title: `${f.name}: ${f.billing_mode === "PROVISIONED" ? "provisioned" : "on-demand"} → ${target === "PROVISIONED" ? `provisioned ${provision.read_units} RCU / ${provision.write_units} WCU` : "on-demand"}`,
            reason: `${v.reason}. Approved as recommendation #${rec.id}${rec.decided_by ? ` by ${rec.decided_by}` : ""}. UpdateTable: online, no downtime.`,
            before: { billing_mode: f.billing_mode, read_units: f.read_units, write_units: f.write_units, gsis: f.gsis },
            after,
            facts: { recommendation_id: rec.id, region, cost_now: v.cost_now, cost_other: v.cost_other, metrics: { days: m.days, read_consumed: Math.round(m.read_consumed), write_consumed: Math.round(m.write_consumed), read_peak_hour: Math.round(m.read_peak_hour), write_peak_hour: Math.round(m.write_peak_hour) }, table_arn: arn ?? null },
            rollback: "UpdateTable back to the previous mode with the previous units (a switch to on-demand is allowed once per 24 h)",
            est_usd_month: rec.est_monthly_saving ?? saving,
          });
        }
        if (recs.length) { upsertRecommendations(runId, recs, "rules", undefined, { reconcile: false }); filed += recs.length; }
      } catch (e: any) { const m = String(e?.message || e); notes.push(`${region}: ${m.slice(0, 160)}`); log(`${region}: ${m}`); }
      finally { ddb.destroy(); cw.destroy(); }
    }
    if (!scanned) notes.push("no DynamoDB table found");
    else if (!filed) notes.push(`${scanned} table(s) priced both ways: none is 20 % and 5 USD/month cheaper the other way`);
    else notes.push(`${filed} capacity-mode recommendation(s) filed or refreshed; the executor acts once one is approved`);
    return { proposals, notes };
  },

  async apply(p, creds) {
    const ddb = new DynamoDBClient({ region: p.region, credentials: creds.act() });
    try {
      const r = await ddb.send(new UpdateTableCommand(updateInput(p.resource, p.after)));
      return `UpdateTable: ${p.before.billing_mode} → ${p.after.billing_mode}, table ${r.TableDescription?.TableStatus || "UPDATING"}`;
    } finally { ddb.destroy(); }
  },

  async verify(p, creds) {
    const ddb = new DynamoDBClient({ region: p.region, credentials: creds.read });
    try {
      const d = await describe(ddb, p.resource);
      if (!d) return { ok: false, note: "table not found on read-back" };
      const f = tableFacts(d);
      if (f.billing_mode !== p.after.billing_mode) return d.TableStatus === "UPDATING" ? { ok: null, note: `table UPDATING, mode still reads ${f.billing_mode}` } : { ok: false, note: `mode reads ${f.billing_mode}` };
      return d.TableStatus === "ACTIVE" ? { ok: true, note: `read back: ${f.billing_mode}${f.billing_mode === "PROVISIONED" ? ` ${f.read_units} RCU / ${f.write_units} WCU` : ""}, table ACTIVE` } : { ok: null, note: `mode reads ${f.billing_mode}, table ${d.TableStatus}` };
    } finally { ddb.destroy(); }
  },

  async revert(p, creds) {
    const ddb = new DynamoDBClient({ region: p.region, credentials: creds.act() });
    try { await ddb.send(new UpdateTableCommand(updateInput(p.resource, p.before))); return `mode back to ${p.before.billing_mode}`; }
    catch (e: any) {
      if (/once (per|every) (24 hours|day)|PAY_PER_REQUEST.*24/i.test(String(e?.message || e))) throw new Error(`DynamoDB refuses another switch to on-demand within 24 hours of the last one: ${String(e?.message || e).slice(0, 160)}`);
      throw e;
    } finally { ddb.destroy(); }
  },
};

/** The UpdateTable input for a mode: units for provisioned (table and every index), the mode alone for on-demand. */
export function updateInput(table: string, want: Record<string, unknown>): UpdateTableCommandInput {
  const mode = String(want.billing_mode) as BillingMode;
  if (mode === "PAY_PER_REQUEST") return { TableName: table, BillingMode: mode };
  const gsis = Array.isArray(want.gsis) ? (want.gsis as GsiUnits[]) : [];
  return {
    TableName: table, BillingMode: mode,
    ProvisionedThroughput: { ReadCapacityUnits: Math.max(1, Number(want.read_units) || 1), WriteCapacityUnits: Math.max(1, Number(want.write_units) || 1) },
    ...(gsis.length ? { GlobalSecondaryIndexUpdates: gsis.map((g) => ({ Update: { IndexName: g.name, ProvisionedThroughput: { ReadCapacityUnits: Math.max(1, g.read || 1), WriteCapacityUnits: Math.max(1, g.write || 1) } } })) } : {}),
  };
}

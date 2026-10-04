/**
 * T-family credit specification from the 30-day credit usage, once a person approved it. A burstable instance
 * in `unlimited` mode keeps running past its baseline and bills the surplus credits at 0.05 USD per vCPU-hour
 * (0.04 on Graviton); one in `standard` mode is throttled to the baseline instead. Neither is wrong, so the
 * executor only files a tier-approve recommendation from thirty days of CloudWatch: `unlimited` → `standard`
 * where the surplus charges are real money (at least 5 USD and a tenth of the instance price) while the
 * average CPU sits under the baseline, so the bursts are occasional and throttling them costs nothing on the
 * bill; `standard` → `unlimited` where the credit balance hit zero on three or more days, so the instance was
 * throttled and a burst would have been worth the price. Approving is the decision; the change is one
 * ModifyInstanceCreditSpecification, online, no restart, exactly reversible. Pool members, instances with under
 * 14 days of metrics and anything tagged `advisor:hands-off` are left alone.
 */
import { CloudWatchClient, GetMetricDataCommand, type MetricDataQuery } from "@aws-sdk/client-cloudwatch";
import { DescribeInstanceCreditSpecificationsCommand, DescribeInstancesCommand, EC2Client, ModifyInstanceCreditSpecificationCommand, type Instance } from "@aws-sdk/client-ec2";
import { db } from "../db.js";
import { upsertRecommendations } from "../collector.js";
import type { RecInput } from "../rules.js";
import { approvedRecs, type ActionModule, type Creds, type Proposal } from "../executor.js";

export const KIND = "cpu_credit_spec" as const;
export const ACTION_TYPE = "set_credit_specification";
export const RULE = "cpu_credit_spec";
export const SURPLUS_USD_VCPU_HOUR: Record<string, number> = { t2: 0.05, t3: 0.05, t3a: 0.05, t4g: 0.04 };
export const MIN_SURPLUS_USD = 5;
export const MIN_SURPLUS_SHARE = 0.1;
export const MIN_THROTTLED_DAYS = 3;
export const MIN_METRIC_DAYS = 14;
const METRIC_DAYS = 30;
export const BURSTABLE = /^t[234][a-z]?\./;

/** Baseline CPU utilisation per size (percent of the whole instance): what standard mode throttles to. t3a and t4g share t3's table. */
const BASELINE: Record<string, Record<string, number>> = {
  t3: { nano: 5, micro: 10, small: 20, medium: 20, large: 30, xlarge: 40, "2xlarge": 40 },
  t2: { nano: 5, micro: 10, small: 20, medium: 20, large: 30, xlarge: 22.5, "2xlarge": 17 },
};
export function baselinePct(instanceType: string): number | null {
  const m = /^(t[234][a-z]?)\.(\w+)$/.exec(instanceType); if (!m) return null;
  const fam = m[1] === "t2" ? "t2" : "t3";
  return BASELINE[fam][m[2]] ?? null;
}
export const surplusPrice = (instanceType: string) => SURPLUS_USD_VCPU_HOUR[instanceType.split(".")[0]] ?? 0.05;

export type CreditSpec = "standard" | "unlimited";
export interface CreditMetrics {
  /** Sum of CPUSurplusCreditsCharged over the window (credits; one credit is one vCPU-minute at 100 %, billed per vCPU-hour = 60 credits). */
  surplus_credits: number;
  /** Days on which the CPUCreditBalance minimum was zero. */
  balance_zero_days: number;
  cpu_avg: number | null;
  days: number;
}
export interface Verdict { current: CreditSpec; target: CreditSpec | null; surplus_usd_30d: number; reason: string }

/** Surplus credits are billed per vCPU-hour: 60 credits make one. */
export const surplusUsd = (credits: number, instanceType: string) => Math.round((credits / 60) * surplusPrice(instanceType) * 100) / 100;

/** The verdict for one instance: pure. */
export function creditVerdict(spec: CreditSpec, m: CreditMetrics, instanceType: string, monthlyUsd: number | null): Verdict {
  const usd = surplusUsd(m.surplus_credits, instanceType) * (m.days > 0 ? 30 / m.days : 0);
  const surplus_usd_30d = Math.round(usd * 100) / 100;
  if (m.days < MIN_METRIC_DAYS) return { current: spec, target: null, surplus_usd_30d, reason: `${m.days} days of metrics, ${MIN_METRIC_DAYS} needed` };
  const baseline = baselinePct(instanceType);
  if (spec === "unlimited") {
    const enough = surplus_usd_30d >= MIN_SURPLUS_USD && (monthlyUsd == null || monthlyUsd <= 0 || surplus_usd_30d >= MIN_SURPLUS_SHARE * monthlyUsd);
    const quiet = baseline != null && m.cpu_avg != null && m.cpu_avg < baseline;
    if (enough && quiet) return { current: spec, target: "standard", surplus_usd_30d, reason: `unlimited mode billed ${surplus_usd_30d.toFixed(2)} USD of surplus credits over the last ${m.days} days${monthlyUsd ? ` (${Math.round((surplus_usd_30d / monthlyUsd) * 100)} % of the instance's ${monthlyUsd.toFixed(2)} USD/month)` : ""} while the CPU averaged ${m.cpu_avg!.toFixed(1)} % against a ${baseline} % baseline: the bursts are occasional, and standard mode throttles them to the baseline instead of billing them` };
    return { current: spec, target: null, surplus_usd_30d, reason: !enough ? `surplus credits cost ${surplus_usd_30d.toFixed(2)} USD over ${m.days} days: not worth a change` : `CPU averages ${m.cpu_avg?.toFixed(1) ?? "?"} % against a ${baseline ?? "?"} % baseline: it works above baseline for real, standard mode would throttle it` };
  }
  if (m.balance_zero_days >= MIN_THROTTLED_DAYS) return { current: spec, target: "unlimited", surplus_usd_30d, reason: `the credit balance hit zero on ${m.balance_zero_days} of the last ${m.days} days, so the instance was throttled to its ${baseline ?? "?"} % baseline; unlimited mode lets it burst at up to ${surplusPrice(instanceType).toFixed(2)} USD per vCPU-hour of burst` };
  return { current: spec, target: null, surplus_usd_30d, reason: m.balance_zero_days ? `the credit balance hit zero on ${m.balance_zero_days} day(s): under the ${MIN_THROTTLED_DAYS} that would call for unlimited` : "never ran out of credits" };
}

const mid = (s: string) => s.replace(/[^a-z0-9]/gi, "_").toLowerCase();

async function creditMetrics(cw: CloudWatchClient, ids: string[], now = Date.now()): Promise<Map<string, CreditMetrics>> {
  const queries: MetricDataQuery[] = [];
  for (const id of ids) {
    const q = (k: string, MetricName: string, Stat: string): MetricDataQuery => ({ Id: `${k}_${mid(id)}`, MetricStat: { Metric: { Namespace: "AWS/EC2", MetricName, Dimensions: [{ Name: "InstanceId", Value: id }] }, Period: 3600, Stat }, ReturnData: true });
    queries.push(q("s", "CPUSurplusCreditsCharged", "Sum"), q("b", "CPUCreditBalance", "Minimum"), q("c", "CPUUtilization", "Average"));
  }
  const series = new Map<string, { values: number[]; days: Map<string, number> }>();
  for (let i = 0; i < queries.length; i += 500) {
    let NextToken: string | undefined;
    do {
      const r = await cw.send(new GetMetricDataCommand({ StartTime: new Date(now - METRIC_DAYS * 86400000), EndTime: new Date(now), MetricDataQueries: queries.slice(i, i + 500), ScanBy: "TimestampAscending", NextToken }));
      for (const res of r.MetricDataResults ?? []) {
        const s = series.get(res.Id!) ?? { values: [], days: new Map<string, number>() };
        (res.Values ?? []).forEach((v, j) => { s.values.push(v); const day = res.Timestamps?.[j] ? new Date(res.Timestamps[j]).toISOString().slice(0, 10) : "?"; s.days.set(day, Math.min(s.days.get(day) ?? Infinity, v)); });
        series.set(res.Id!, s);
      }
      NextToken = r.NextToken;
    } while (NextToken);
  }
  const out = new Map<string, CreditMetrics>();
  for (const id of ids) {
    const s = series.get(`s_${mid(id)}`), b = series.get(`b_${mid(id)}`), c = series.get(`c_${mid(id)}`);
    const cpu = c?.values.length ? c.values.reduce((a, v) => a + v, 0) / c.values.length : null;
    out.set(id, { surplus_credits: s?.values.reduce((a, v) => a + v, 0) ?? 0, balance_zero_days: [...(b?.days.values() ?? [])].filter((v) => v <= 0).length, cpu_avg: cpu != null ? Math.round(cpu * 10) / 10 : null, days: new Set([...(c?.days.keys() ?? []), ...(b?.days.keys() ?? [])]).size });
  }
  return out;
}

interface Candidate { instance_id: string; account_id?: string | null; name: string | null; instance_type: string; region: string; monthly_usd: number | null; pool_kind: string | null }

export const cpuCreditSpecAction: ActionModule = {
  kind: KIND,
  label: "T-family credit specification from the 30-day credit usage, once approved",

  async plan(creds, log) {
    const proposals: Proposal[] = []; const notes: string[] = [];
    const rows = (db.prepare("select instance_id, account_id, name, instance_type, region, monthly_usd, pool_kind from inventory_ec2 where gone = 0 and state = 'running' and instance_type is not null order by name").all() as Candidate[]).filter((r) => BURSTABLE.test(r.instance_type));
    if (!rows.length) { notes.push("no running burstable (t2/t3/t3a/t4g) instance in the inventory"); return { proposals, notes }; }
    const runId = (db.prepare("select id from runs where provider = 'aws' order by id desc limit 1").get() as { id: number } | undefined)?.id ?? 0;
    const approved = approvedRecs([ACTION_TYPE]);
    const byRegion = new Map<string, Candidate[]>();
    for (const r of rows) { const key = `${r.account_id || ""}|${r.region || creds.region}`; if (!byRegion.has(key)) byRegion.set(key, []); byRegion.get(key)!.push(r); }
    let filed = 0;
    for (const [key, list] of byRegion) {
      const [account, region] = key.split("|");
      const read = creds.forAccount(account || null).read;
      const ec2 = new EC2Client({ region, credentials: read });
      const cw = new CloudWatchClient({ region, credentials: read });
      try {
        const ids = list.map((r) => r.instance_id);
        const specs = new Map<string, CreditSpec>();
        const live = new Map<string, Instance>();
        for (let i = 0; i < ids.length; i += 100) {
          const batch = ids.slice(i, i + 100);
          for (const s of (await ec2.send(new DescribeInstanceCreditSpecificationsCommand({ InstanceIds: batch }))).InstanceCreditSpecifications ?? []) specs.set(s.InstanceId!, (s.CpuCredits as CreditSpec) || "standard");
          for (const res of (await ec2.send(new DescribeInstancesCommand({ InstanceIds: batch }))).Reservations ?? []) for (const inst of res.Instances ?? []) live.set(inst.InstanceId!, inst);
        }
        const metrics = await creditMetrics(cw, ids);
        const recs: RecInput[] = [];
        for (const r of list) {
          const name = r.name || r.instance_id;
          const skip = (why: string) => { notes.push(`${name}: ${why}`); log(`${name}: ${why}`); };
          const inst = live.get(r.instance_id); const spec = specs.get(r.instance_id);
          if (!inst || !spec) { skip("not found by DescribeInstances"); continue; }
          if (inst.State?.Name !== "running") { skip(`state ${inst.State?.Name}`); continue; }
          if (r.pool_kind) { skip(`member of a ${r.pool_kind} pool: its launch template decides`); continue; }
          if (inst.Tags?.some((t) => t.Key === "advisor:hands-off")) { skip("tagged advisor:hands-off"); continue; }
          const m = metrics.get(r.instance_id)!;
          const type = inst.InstanceType || r.instance_type;
          const v = creditVerdict(spec, m, type, r.monthly_usd);
          if (!v.target) { log(`${name}: ${v.reason}`); continue; }
          const vcpus = (inst.CpuOptions?.CoreCount ?? 1) * (inst.CpuOptions?.ThreadsPerCore ?? 1);
          const saving = v.target === "standard" ? v.surplus_usd_30d : null;
          recs.push({
            rule: RULE, title: `${name} (${type}): credit specification ${spec} → ${v.target}${saving ? ` (≈ ${saving.toFixed(2)} USD/month)` : ""}`,
            resource: r.instance_id, resourceName: name, actionType: ACTION_TYPE, estMonthlySaving: saving, tier: "approve", confidence: m.days >= 28 ? 0.75 : 0.6,
            rationale: `${v.reason}. ModifyInstanceCreditSpecification is online, no restart, and exactly reversible.${v.target === "unlimited" ? ` This adds cost rather than saving it: at most ${surplusPrice(type).toFixed(2)} USD per vCPU-hour spent above the baseline (${vcpus} vCPU${vcpus === 1 ? "" : "s"}).` : ""}`,
            evidence: { region, instance_type: type, current: spec, target: v.target, vcpus, metrics: m, surplus_usd_30d: v.surplus_usd_30d },
          });
          const rec = approved.find((a) => a.resource === r.instance_id);
          if (!rec) { log(`${name}: recommendation filed, waiting for approval`); continue; }
          const target = (String(rec.evidence?.target || v.target) as CreditSpec);
          if (spec === target) { skip(`already ${target}`); continue; }
          proposals.push({
            kind: KIND, resource: r.instance_id, resource_name: r.name, region, account_id: r.account_id ?? null,
            dedupe: `${KIND}:${r.instance_id}:${target}`,
            title: `${name} (${type}): credit specification ${spec} → ${target}`,
            reason: `${v.reason}. Approved as recommendation #${rec.id}${rec.decided_by ? ` by ${rec.decided_by}` : ""}. Online, no restart.`,
            before: { cpu_credits: spec }, after: { cpu_credits: target },
            facts: { recommendation_id: rec.id, surplus_usd_30d: v.surplus_usd_30d, min_balance_zero_days: m.balance_zero_days, cpu_avg: m.cpu_avg, vcpus, instance_type: type, metric_days: m.days },
            rollback: `ModifyInstanceCreditSpecification back to ${spec}: online, no restart`,
            est_usd_month: target === "standard" ? (rec.est_monthly_saving ?? v.surplus_usd_30d) : null,
          });
        }
        if (recs.length) { upsertRecommendations(runId, recs, "rules", undefined, { reconcile: false }); filed += recs.length; }
      } catch (e: any) { const m = String(e?.message || e); notes.push(`${region}: ${m.slice(0, 160)}`); log(`${region}: ${m}`); }
      finally { ec2.destroy(); cw.destroy(); }
    }
    if (!filed) notes.push(`${rows.length} burstable instance(s) checked: no surplus charges worth throttling and nobody throttled for lack of credits`);
    else notes.push(`${filed} credit-specification recommendation(s) filed or refreshed; the executor acts once one is approved`);
    return { proposals, notes };
  },

  async apply(p, creds) {
    const ec2 = new EC2Client({ region: p.region, credentials: creds.act() });
    try {
      const r = await ec2.send(new ModifyInstanceCreditSpecificationCommand({ InstanceCreditSpecifications: [{ InstanceId: p.resource, CpuCredits: String(p.after.cpu_credits) }] }));
      const bad = r.UnsuccessfulInstanceCreditSpecifications?.[0];
      if (bad) throw new Error(`${bad.Error?.Code || "error"}: ${bad.Error?.Message || "not modified"}`);
      return `ModifyInstanceCreditSpecification: ${p.before.cpu_credits} → ${p.after.cpu_credits}`;
    } finally { ec2.destroy(); }
  },

  async verify(p, creds) {
    const ec2 = new EC2Client({ region: p.region, credentials: creds.read });
    try {
      const s = (await ec2.send(new DescribeInstanceCreditSpecificationsCommand({ InstanceIds: [p.resource] }))).InstanceCreditSpecifications?.[0];
      if (!s) return { ok: false, note: "instance not found on read-back" };
      return s.CpuCredits === p.after.cpu_credits ? { ok: true, note: `read back: ${s.CpuCredits}` } : { ok: false, note: `credit specification reads ${s.CpuCredits}` };
    } finally { ec2.destroy(); }
  },

  async revert(p, creds) {
    const ec2 = new EC2Client({ region: p.region, credentials: creds.act() });
    try {
      const r = await ec2.send(new ModifyInstanceCreditSpecificationCommand({ InstanceCreditSpecifications: [{ InstanceId: p.resource, CpuCredits: String(p.before.cpu_credits) }] }));
      const bad = r.UnsuccessfulInstanceCreditSpecifications?.[0];
      if (bad) throw new Error(`${bad.Error?.Code || "error"}: ${bad.Error?.Message || "not modified"}`);
      return `credit specification back to ${p.before.cpu_credits}`;
    } finally { ec2.destroy(); }
  },
};

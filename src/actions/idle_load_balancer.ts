/**
 * Load balancers nobody sends traffic to: an ALB or NLB bills 0.0225 USD an hour (about 16 USD a month) whether
 * or not a single request arrives, and a stack that was torn down by hand tends to leave its balancer behind.
 * The plan looks at every ALB, NLB and gateway load balancer older than 30 days (classic ELBs are not covered),
 * reads 30 days of CloudWatch (ALB: RequestCount and ProcessedBytes; NLB: ActiveFlowCount and ProcessedBytes;
 * GWLB: ProcessedBytes) and every target group's health, and files a tier-approve recommendation (`elb_idle`)
 * for the ones where every metric summed to zero and no target is healthy. Missing metrics count as traffic,
 * never as silence. Approving it is the decision; the executor deletes the balancer, having saved its listeners,
 * target groups and attributes on the row so a person can recreate it. Deletion protection, and the
 * `advisor:hands-off` tag, are respected. There is no automatic revert: a deleted load balancer is gone.
 */
import { CloudWatchClient, GetMetricDataCommand, type MetricDataQuery } from "@aws-sdk/client-cloudwatch";
import { DeleteLoadBalancerCommand, DescribeListenersCommand, DescribeLoadBalancerAttributesCommand, DescribeLoadBalancersCommand, DescribeTagsCommand, DescribeTargetGroupsCommand, DescribeTargetHealthCommand, ElasticLoadBalancingV2Client, type LoadBalancer } from "@aws-sdk/client-elastic-load-balancing-v2";
import { db } from "../db.js";
import { config } from "../config.js";
import { upsertRecommendations } from "../collector.js";
import type { RecInput } from "../rules.js";
import { approvedRecs, type ActionModule, type Creds, type Proposal } from "../executor.js";

export const KIND = "idle_load_balancer" as const;
export const ACTION_TYPE = "delete_load_balancer";
export const RULE = "elb_idle";
export const MIN_AGE_DAYS = 30;
export const METRIC_DAYS = 30;
const HOURS_MONTH = 730;
export const USD_HOUR: Record<string, number> = { application: 0.0225, network: 0.0225, gateway: 0.0125 };
export const monthlyUsd = (type: string) => Math.round((USD_HOUR[type] ?? 0.0225) * HOURS_MONTH * 100) / 100;

export interface LbMetrics { [name: string]: number | null }
export interface LbVerdict { idle: boolean; reasons: string[] }

/** The metrics that must all be zero for a type: what CloudWatch publishes for it. */
export const METRICS_FOR: Record<string, { namespace: string; names: string[] }> = {
  application: { namespace: "AWS/ApplicationELB", names: ["RequestCount", "ProcessedBytes"] },
  network: { namespace: "AWS/NetworkELB", names: ["ActiveFlowCount", "ProcessedBytes"] },
  gateway: { namespace: "AWS/GatewayELB", names: ["ProcessedBytes"] },
};

/** The dimension value CloudWatch uses: the ARN's tail after `loadbalancer/` (e.g. `app/name/id`). */
export const metricDimension = (arn: string) => arn.split(":loadbalancer/")[1] ?? arn;

/**
 * Idle only when the balancer is old enough, every metric it publishes summed to zero over the window (a missing
 * metric is unknown, so traffic), no target is healthy, deletion protection is off and it is not tagged hands-off.
 */
export function elbIdleVerdict(lb: { type: string; created: string | null; state: string | null }, metrics: LbMetrics, targets: { healthy: number; total: number; unknown: boolean }, attrs: { deletion_protection: boolean; hands_off: boolean }, now = Date.now()): LbVerdict {
  const reasons: string[] = [];
  const spec = METRICS_FOR[lb.type];
  if (!spec) reasons.push(`type ${lb.type} not covered`);
  if (lb.state && lb.state !== "active") reasons.push(`state ${lb.state}`);
  const age = lb.created ? (now - new Date(lb.created).getTime()) / 86400000 : null;
  if (age == null) reasons.push("creation date unknown");
  else if (age < MIN_AGE_DAYS) reasons.push(`${Math.floor(age)} days old (${MIN_AGE_DAYS} needed)`);
  for (const name of spec?.names ?? []) {
    const v = metrics[name];
    if (v == null) reasons.push(`${name} has no datapoints (unknown counts as traffic)`);
    else if (v > 0) reasons.push(`${name} ${Math.round(v).toLocaleString()} over ${METRIC_DAYS} days`);
  }
  if (targets.unknown) reasons.push("target health unreadable");
  else if (targets.healthy > 0) reasons.push(`${targets.healthy} healthy target(s)`);
  if (attrs.deletion_protection) reasons.push("deletion protection on");
  if (attrs.hands_off) reasons.push("tagged advisor:hands-off");
  return { idle: reasons.length === 0, reasons };
}

async function metricsFor(cw: CloudWatchClient, lbs: { arn: string; type: string }[], now: number): Promise<Map<string, LbMetrics>> {
  const out = new Map<string, LbMetrics>();
  const queries: MetricDataQuery[] = []; const key: { arn: string; name: string }[] = [];
  lbs.forEach((lb, i) => {
    const spec = METRICS_FOR[lb.type]; if (!spec) return;
    spec.names.forEach((name, j) => {
      queries.push({ Id: `m${i}_${j}`, MetricStat: { Metric: { Namespace: spec.namespace, MetricName: name, Dimensions: [{ Name: "LoadBalancer", Value: metricDimension(lb.arn) }] }, Period: 86400, Stat: name === "ActiveFlowCount" ? "Maximum" : "Sum" }, ReturnData: true });
      key.push({ arn: lb.arn, name });
    });
    out.set(lb.arn, Object.fromEntries(spec.names.map((n) => [n, null])));
  });
  for (let i = 0; i < queries.length; i += 100) {
    const slice = queries.slice(i, i + 100);
    let token: string | undefined;
    const sums = new Map<string, number>();
    do {
      const r = await cw.send(new GetMetricDataCommand({ MetricDataQueries: slice, StartTime: new Date(now - METRIC_DAYS * 86400000), EndTime: new Date(now), NextToken: token, ScanBy: "TimestampDescending" }));
      for (const m of r.MetricDataResults ?? []) { if (!m.Values?.length) continue; sums.set(m.Id!, (sums.get(m.Id!) ?? 0) + m.Values.reduce((a, b) => a + b, 0)); }
      token = r.NextToken;
    } while (token);
    for (const [id, total] of sums) { const k = key[Number(id.slice(1).split("_")[0])]; const n = k.name; const row = out.get(k.arn)!; row[n] = total; }
  }
  return out;
}

function regions(defaultRegion: string): string[] {
  const rows = db.prepare("select distinct region from inventory_ec2 where gone = 0 and region is not null").all() as { region: string }[];
  return [...new Set([defaultRegion, ...rows.map((r) => r.region)])];
}

export const idleLoadBalancerAction: ActionModule = {
  kind: KIND,
  label: "Idle load balancers deleted, once approved",
  grace_hours: () => config.actDeleteGraceHours,
  announce: true,

  async plan(creds, log) {
    const proposals: Proposal[] = []; const notes: string[] = [];
    const now = Date.now();
    const runId = (db.prepare("select id from runs order by id desc limit 1").get() as { id: number } | undefined)?.id ?? 0;
    const approved = approvedRecs([ACTION_TYPE]);
    let seen = 0, filed = 0;
    for (const region of regions(creds.region)) {
      const elb = new ElasticLoadBalancingV2Client({ region, credentials: creds.read });
      const cw = new CloudWatchClient({ region, credentials: creds.read });
      try {
        const lbs: LoadBalancer[] = [];
        let marker: string | undefined;
        do { const r = await elb.send(new DescribeLoadBalancersCommand({ Marker: marker, PageSize: 400 })); lbs.push(...(r.LoadBalancers ?? [])); marker = r.NextMarker; } while (marker);
        if (!lbs.length) continue;
        seen += lbs.length;
        const metrics = await metricsFor(cw, lbs.map((l) => ({ arn: l.LoadBalancerArn!, type: l.Type || "application" })), now);
        const recs: RecInput[] = [];
        for (const lb of lbs) {
          const name = lb.LoadBalancerName!; const arn = lb.LoadBalancerArn!; const type = lb.Type || "application";
          const skip = (why: string) => { log(`${name}: ${why}`); };
          const approval = approved.find((a) => a.resource === name) ?? null;
          // facts everybody needs: attributes, tags, target groups and health
          let deletionProtection = false, handsOff = false;
          try { deletionProtection = ((await elb.send(new DescribeLoadBalancerAttributesCommand({ LoadBalancerArn: arn }))).Attributes ?? []).some((a) => a.Key === "deletion_protection.enabled" && a.Value === "true"); } catch { /* unknown: the verdict below treats it as off; DeleteLoadBalancer refuses anyway */ }
          try { handsOff = ((await elb.send(new DescribeTagsCommand({ ResourceArns: [arn] }))).TagDescriptions?.[0]?.Tags ?? []).some((t) => t.Key === "advisor:hands-off"); } catch { /* the policy's Deny still protects a tagged balancer */ }
          const tgs = (await elb.send(new DescribeTargetGroupsCommand({ LoadBalancerArn: arn }))).TargetGroups ?? [];
          const targets = { healthy: 0, total: 0, unknown: false };
          for (const tg of tgs) {
            try { for (const t of (await elb.send(new DescribeTargetHealthCommand({ TargetGroupArn: tg.TargetGroupArn }))).TargetHealthDescriptions ?? []) { targets.total++; if (t.TargetHealth?.State === "healthy") targets.healthy++; } }
            catch { targets.unknown = true; }
          }
          const v = elbIdleVerdict({ type, created: lb.CreatedTime ? new Date(lb.CreatedTime).toISOString() : null, state: lb.State?.Code ?? null }, metrics.get(arn) ?? {}, targets, { deletion_protection: deletionProtection, hands_off: handsOff }, now);
          if (approval) {
            if (deletionProtection) { notes.push(`${name}: deletion protection is on; turn it off to let the executor delete it`); continue; }
            if (handsOff) { notes.push(`${name}: tagged advisor:hands-off`); continue; }
            if (!v.idle) { notes.push(`${name}: approved as #${approval.id} but not idle any more (${v.reasons.join("; ")}); left alone`); continue; }
            const listeners = (await elb.send(new DescribeListenersCommand({ LoadBalancerArn: arn }))).Listeners ?? [];
            proposals.push({
              kind: KIND, resource: name, resource_name: name, region,
              dedupe: `${KIND}:${region}:${name}`,
              title: `delete ${type} load balancer ${name}: no traffic for ${METRIC_DAYS} days`,
              reason: `${approval.title}. Approved as recommendation #${approval.id}${approval.decided_by ? ` by ${approval.decided_by}` : ""}. Every CloudWatch metric summed to zero over ${METRIC_DAYS} days and none of its ${targets.total} target(s) is healthy. The balancer's listeners, target groups and attributes are saved on this row; the target groups themselves are not deleted. DNS names pointing at it stop resolving.`,
              before: { state: "active", dns_name: lb.DNSName ?? null }, after: { deleted: true },
              facts: { recommendation_id: approval.id, load_balancer_arn: arn, load_balancer: lb, listeners, target_groups: tgs, deletion_protection: deletionProtection, targets, metrics: metrics.get(arn) ?? {} },
              rollback: "none automatic: the saved listeners and target groups in the row's facts describe how to recreate it",
              est_usd_month: approval.est_monthly_saving ?? monthlyUsd(type),
            });
            continue;
          }
          if (!v.idle) { skip(`alive: ${v.reasons.join("; ")}`); continue; }
          filed++;
          recs.push({
            rule: RULE, title: `Delete idle ${type} load balancer ${name}`, resource: name, resourceName: name, actionType: ACTION_TYPE,
            estMonthlySaving: monthlyUsd(type), tier: "approve", confidence: 0.8,
            rationale: `${type} load balancer created ${lb.CreatedTime ? new Date(lb.CreatedTime).toISOString().slice(0, 10) : "?"} in ${region}: ${METRICS_FOR[type].names.join(" and ")} summed to zero over the last ${METRIC_DAYS} days and none of its ${targets.total} registered target(s) is healthy. It still bills ${USD_HOUR[type]} USD an hour. Deleting it is permanent (its DNS name ${lb.DNSName ?? ""} stops resolving); the executor saves its listeners and target groups on the action row first.`,
            evidence: { region, load_balancer_arn: arn, type, dns_name: lb.DNSName ?? null, created: lb.CreatedTime ? new Date(lb.CreatedTime).toISOString() : null, metrics: metrics.get(arn) ?? {}, targets, target_groups: tgs.map((t) => t.TargetGroupName), metric_days: METRIC_DAYS },
          });
        }
        if (recs.length) upsertRecommendations(runId, recs, "rules", undefined, { reconcile: false });
      } catch (e: any) { const m = String(e?.message || e); notes.push(`${region}: ${m.slice(0, 160)}`); log(`${region}: ${m}`); }
      finally { elb.destroy(); cw.destroy(); }
    }
    if (!seen) notes.push("no application, network or gateway load balancer found (classic ELBs are not covered)");
    else notes.push(`${seen} load balancer(s) seen, ${filed} idle recommendation(s) filed or refreshed; classic ELBs are not covered`);
    if (!approved.length) notes.push("no approved recommendation to delete a load balancer");
    return { proposals, notes };
  },

  async apply(p, creds) {
    const elb = new ElasticLoadBalancingV2Client({ region: p.region, credentials: creds.act() });
    try { await elb.send(new DeleteLoadBalancerCommand({ LoadBalancerArn: String(p.facts.load_balancer_arn) })); return `DeleteLoadBalancer: ${p.resource} deleted; ${Array.isArray(p.facts.listeners) ? p.facts.listeners.length : 0} listener(s) and ${Array.isArray(p.facts.target_groups) ? p.facts.target_groups.length : 0} target group(s) saved on this row`; }
    finally { elb.destroy(); }
  },

  async verify(p, creds) {
    const elb = new ElasticLoadBalancingV2Client({ region: p.region, credentials: creds.read });
    try {
      const r = await elb.send(new DescribeLoadBalancersCommand({ LoadBalancerArns: [String(p.facts.load_balancer_arn)] }));
      const lb = r.LoadBalancers?.[0];
      if (!lb) return { ok: true, note: "read back: gone" };
      return { ok: null, note: `still ${lb.State?.Code || "listed"}` };
    } catch (e: any) { return /LoadBalancerNotFound/i.test(String(e?.name || e?.message)) ? { ok: true, note: "read back: gone" } : { ok: null, note: String(e?.message || e).slice(0, 120) }; }
    finally { elb.destroy(); }
  },

  async revert() {
    throw new Error("a deleted load balancer cannot be recreated automatically; the row's facts hold its listeners and target groups");
  },
};

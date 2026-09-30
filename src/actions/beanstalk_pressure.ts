/**
 * The reactive ceiling raise: an Elastic Beanstalk group pinned at its MaxSize with high CPU right now gets one
 * more instance at the top, at once, within the band a person set.
 *
 * Beanstalk's trigger scales the group between MinSize and MaxSize on its own; what it cannot do is go past the
 * ceiling. The capacity action (src/actions/beanstalk_scale.ts) raises the ceiling from fourteen days of
 * history, one step a day: right for drift, useless for the afternoon the group runs out. So this check runs on
 * its own short cadence (Settings › Auto-actions › Pressure check, every ten minutes by default) over the
 * environments tagged `AdvisorAutoScale=ON` with an `AdvisorScaleBand=<floor>-<ceiling>`, reads the group's
 * desired capacity and the last `LOOKBACK_MINUTES` of its average CPU, and when the group is at its maximum, every
 * member in service, and the CPU at or above the pressure threshold (`ACT_EB_HIGH_CPU`), proposes MaxSize + 1 up
 * to the band's ceiling. It is urgent: the pass applies it in the same breath, Jev's opinion recorded as advice
 * rather than a hold, because the ceiling is the person's number and one step toward it is the smallest change
 * that answers the pressure. One raise per environment per `COOLDOWN_MINUTES`; never while the environment is
 * not Ready. At the ceiling already, the pass says so in its notes (raise the band, or the group is undersized).
 *
 * Every pressure it sees is recorded as a pressure event (src/capacity_pattern.ts) whether or not a raise was
 * possible: the learned week lifts that hour's minimum so next week the capacity is there before the load.
 * Apply, verify and revert are the capacity action's own (one UpdateEnvironment on aws:autoscaling:asg).
 */
import { AutoScalingClient, DescribeAutoScalingGroupsCommand } from "@aws-sdk/client-auto-scaling";
import { CloudWatchClient, GetMetricDataCommand } from "@aws-sdk/client-cloudwatch";
import { DescribeEnvironmentsCommand, ElasticBeanstalkClient } from "@aws-sdk/client-elastic-beanstalk";
import { db } from "../db.js";
import { config } from "../config.js";
import type { ActionModule, Proposal } from "../executor.js";
import { AUTO_SCALE_TAG, SCALE_BAND_TAG, isOff, isOn } from "../consent.js";
import { beanstalkScaleAction, environmentFacts, parseBand, regions, SCALE_TAG } from "./beanstalk_scale.js";
import { recordPressure } from "../capacity_pattern.js";

export const KIND = "beanstalk_pressure" as const;
export const LOOKBACK_MINUTES = 10;
export const COOLDOWN_MINUTES = 30;

export interface PressureInput { min: number; max: number; desired: number; in_service: number; cpu_avg: number | null; high_cpu: number; ceiling: number | null; env_status: string }
export interface PressureVerdict { pressure: boolean; raise: number | null; reason: string }

/** Whether the group is under pressure now and whether the ceiling can answer it. Pure. */
export function pressureVerdict(i: PressureInput): PressureVerdict {
  const cpu = i.cpu_avg == null ? "unknown" : `${i.cpu_avg.toFixed(1)} %`;
  if (i.desired < i.max) return { pressure: false, raise: null, reason: `desired ${i.desired} of a maximum ${i.max}: the trigger still has room (CPU ${cpu})` };
  if (i.in_service < i.max) return { pressure: false, raise: null, reason: `at the maximum of ${i.max} but only ${i.in_service} in service: the group is still launching (CPU ${cpu})` };
  if (i.cpu_avg == null) return { pressure: false, raise: null, reason: `at the maximum of ${i.max} but no CPU metric for the last ${LOOKBACK_MINUTES} minutes` };
  if (i.cpu_avg < i.high_cpu) return { pressure: false, raise: null, reason: `at the maximum of ${i.max} with CPU ${cpu}, under the ${i.high_cpu} % pressure line` };
  const why = `pinned at the maximum of ${i.max}, every member in service, average CPU ${cpu} over the last ${LOOKBACK_MINUTES} minutes (pressure line ${i.high_cpu} %)`;
  if (i.env_status !== "Ready") return { pressure: true, raise: null, reason: `${why}, but the environment is ${i.env_status}` };
  if (i.ceiling == null) return { pressure: true, raise: null, reason: `${why}, and no band on the environment: the ceiling cannot move (set ${SCALE_BAND_TAG}=<floor>-<ceiling>)` };
  if (i.max >= i.ceiling) return { pressure: true, raise: null, reason: `${why}, and ${i.max} is the band's ceiling: raise the band, or the group is undersized` };
  return { pressure: true, raise: i.max + 1, reason: `${why}: one more at the top (the band allows up to ${i.ceiling})` };
}

async function recentCpu(cw: CloudWatchClient, asg: string, now: number): Promise<number | null> {
  const r = await cw.send(new GetMetricDataCommand({ StartTime: new Date(now - LOOKBACK_MINUTES * 60000), EndTime: new Date(now), MetricDataQueries: [{ Id: "cpu", MetricStat: { Metric: { Namespace: "AWS/EC2", MetricName: "CPUUtilization", Dimensions: [{ Name: "AutoScalingGroupName", Value: asg }] }, Period: 60, Stat: "Average" }, ReturnData: true }] }));
  const v = r.MetricDataResults?.[0]?.Values ?? [];
  return v.length ? Math.round((v.reduce((a, b) => a + b, 0) / v.length) * 10) / 10 : null;
}

export const beanstalkPressureAction: ActionModule = {
  kind: KIND,
  label: "Elastic Beanstalk ceiling raise under pressure now",
  urgent: true,

  async plan(creds, log) {
    const proposals: Proposal[] = []; const notes: string[] = [];
    const now = Date.now();
    let tagged = 0;
    for (const acct of creds.accounts) for (const region of regions(acct.region)) {
      const eb = new ElasticBeanstalkClient({ region, credentials: acct.read });
      const as = new AutoScalingClient({ region, credentials: acct.read });
      const cw = new CloudWatchClient({ region, credentials: acct.read });
      try {
        const envs = (await eb.send(new DescribeEnvironmentsCommand({ IncludeDeleted: false }))).Environments ?? [];
        for (const env of envs) {
          const name = env.EnvironmentName || env.EnvironmentId || "?";
          let f;
          try { f = await environmentFacts(eb, env); } catch (e: any) { log(`${name}: describe failed: ${String(e?.message || e).slice(0, 160)}`); continue; }
          if (f.tags["advisor:hands-off"] != null || isOff(f.tags[AUTO_SCALE_TAG])) continue;
          const tag = isOn(f.tags[AUTO_SCALE_TAG]) ? (f.tags[SCALE_BAND_TAG] || "auto") : f.tags[SCALE_TAG];
          if (tag == null || !f.asg) continue;
          tagged++;
          const band = parseBand(tag);
          if ("error" in band) { log(`${name}: tag ${band.error}`); continue; }
          const group = (await as.send(new DescribeAutoScalingGroupsCommand({ AutoScalingGroupNames: [f.asg] }))).AutoScalingGroups?.[0];
          if (!group) { log(`${name}: group ${f.asg} not found`); continue; }
          const max = group.MaxSize ?? f.cfg.max ?? 0, min = group.MinSize ?? f.cfg.min ?? 0, desired = group.DesiredCapacity ?? 0;
          const inService = (group.Instances ?? []).filter((x) => x.LifecycleState === "InService").length;
          const cpu = desired >= max ? await recentCpu(cw, f.asg, now).catch(() => null) : null;
          const v = pressureVerdict({ min, max, desired, in_service: inService, cpu_avg: cpu, high_cpu: config.actEbHighCpu, ceiling: band.ceiling, env_status: env.Status ?? "?" });
          if (!v.pressure) { log(`${name}: ${v.reason}`); continue; }
          const ev = recordPressure({ env_id: env.EnvironmentId!, env_name: env.EnvironmentName ?? null, asg: f.asg, at: now, desired, max_size: max, cpu_avg: cpu, note: v.reason });
          if (ev.fresh) log(`${name}: pressure event #${ev.id} recorded for the learned week`);
          if (v.raise == null) { notes.push(`${name}: ${v.reason}`); continue; }
          const recent = db.prepare("select id, applied_at from actions where kind in (?, ?) and resource = ? and status in ('applied', 'verified') and datetime(applied_at) > datetime('now', ?) order by id desc limit 1").get(KIND, beanstalkScaleAction.kind, env.EnvironmentId, `-${COOLDOWN_MINUTES} minutes`) as { id: number; applied_at: string } | undefined;
          if (recent) { log(`${name}: ${v.reason}; #${recent.id} changed the bounds at ${recent.applied_at}, so this waits ${COOLDOWN_MINUTES} minutes`); continue; }
          if (f.cfg.max != null && f.cfg.max !== max) { notes.push(`${name}: ${v.reason}, but the live group's maximum (${max}) and the configuration (${f.cfg.max}) disagree: sort that out first`); continue; }
          const opsRole = env.OperationsRole || null;
          if (!opsRole) notes.push(`${name}: no operations role on the environment, so UpdateEnvironment runs with the actuator's own permissions (see the README)`);
          proposals.push({
            kind: KIND, resource: env.EnvironmentId!, resource_name: env.EnvironmentName ?? null, region, account_id: acct.account_id ?? null,
            dedupe: `${KIND}:${env.EnvironmentId}:${v.raise}`,
            title: `${name}: MaxSize ${max} → ${v.raise} (pressure now)`,
            reason: `${v.reason}. Band ${SCALE_BAND_TAG}=${band.text}. Applied at once: the trigger launches the extra instance as soon as the environment update is through (a minute or two). This adds cost rather than saving it; the learned week keeps this hour's minimum higher from next week.`,
            before: { MaxSize: max, MinSize: min }, after: { MaxSize: v.raise },
            facts: { pressure: true, event_id: ev.id, application: env.ApplicationName, asg: f.asg, desired_now: desired, in_service: inService, cpu_avg: cpu, high_cpu: config.actEbHighCpu, band: band.text, ceiling: band.ceiling, operations_role: opsRole, health: env.HealthStatus ?? null },
            rollback: `UpdateEnvironment MaxSize back to ${max}`,
            est_usd_month: null,
          });
        }
      } catch (e: any) { const m = String(e?.message || e); notes.push(`${region}: ${m.slice(0, 160)}`); log(`${region}: ${m}`); }
      finally { eb.destroy(); as.destroy(); cw.destroy(); }
    }
    if (!tagged) notes.push(`no environment tagged ${AUTO_SCALE_TAG}=ON with a group: nothing to watch`);
    else if (!proposals.length && !notes.length) notes.push(`${tagged} environment(s) watched: no pressure at the ceiling`);
    return { proposals, notes };
  },

  apply: (p, creds) => beanstalkScaleAction.apply(p, creds),
  verify: (p, creds) => beanstalkScaleAction.verify(p, creds),
  revert: (p, creds) => beanstalkScaleAction.revert(p, creds),
};

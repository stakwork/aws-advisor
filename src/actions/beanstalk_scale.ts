/**
 * Elastic Beanstalk capacity from the fleet's own usage.
 *
 * Beanstalk owns its Auto Scaling group: a size set on the group directly is overwritten by the next
 * configuration change, and the environment's own trigger scales the group back to what its configuration
 * says. So the executor moves the environment's configured bounds (`aws:autoscaling:asg` MinSize and MaxSize,
 * one UpdateEnvironment) and leaves the minute-to-minute reaction to Beanstalk's trigger. Two moves, from
 * fourteen days of CloudWatch on the group (CPUUtilization by AutoScalingGroupName, hourly) and the group's
 * scaling activities (whose causes say "changing the desired capacity from 2 to 3", so the desired capacity
 * can be replayed hour by hour):
 *
 *  - the floor comes down by one when the group sat at its minimum for at least `FLOOR_SHARE` of the window
 *    and the p95 of the hourly average CPU while there stayed under `ACT_EB_LOW_CPU` (30 %): one instance
 *    fewer keeps that p95 under twice the threshold. The group scales in to the new floor when Beanstalk's
 *    scale-in alarm next fires (the row says whether it is in ALARM already). Estimate: one member's list price.
 *  - the ceiling goes up by one when the group spent `ACT_EB_PRESSURE_HOURS` (3) or more hours pinned at its
 *    maximum with the average CPU at or above `ACT_EB_HIGH_CPU` (70 %): the trigger wanted more and the cap
 *    said no. This adds cost rather than saving it, and the row says so.
 *
 * A tag on the environment is the consent and the guard rail: `advisor:scale=<floor>-<ceiling>` (e.g. `2-8`)
 * is the band the executor may move the bounds within; `advisor:scale=auto` means floor 1 and the ceiling
 * where it is (the floor may come down, the ceiling never moves). The actuator policy allows UpdateEnvironment
 * only on an environment carrying the tag. One step (the agent's bounds, the idle-floor trim, the ceiling raise) per
 * environment per `MIN_HOURS_BETWEEN_CHANGES`; the learned week and the quiet windows below move MinSize hour by
 * hour by design, so they neither wait on that step nor count as one. Never
 * while the environment is not Ready, never a floor cut while its health is Degraded or Severe, never when the
 * live group disagrees with the configuration (someone edited the group directly), never on a single-instance
 * environment, and never on `advisor:hands-off`. Revert puts the previous bounds back.
 *
 * The third move follows the group's day. The usage profile of the autoscaling group (src/usage_profile.ts,
 * subject `asg:<name>`: the group's CPU and the balancer's requests folded into the hours of the week) gives the
 * quiet windows; where they are confident, the pass fifteen minutes before a quiet hour sets MinSize to the
 * band's floor and the pass before a working hour puts the configured minimum back, one UpdateEnvironment each,
 * the way the Serverless v2 action moves an Aurora minimum. The configured minimum follows the owner: a value
 * that is neither the floor, nor the one recorded, nor what the executor set last is a human change and becomes
 * the new baseline (kept in the settings table under `act:eb:<environment id>`). While a windowed schedule is in
 * force the idle-floor trim is skipped (the window already captures the idle hours); the ceiling raise still runs.
 *
 * The fourth move is the learned week (src/capacity_pattern.ts). Once the environment carries a band
 * (`AdvisorScaleBand=<floor>-<ceiling>`, the bare minimum and the ceiling a person set) and the pattern is
 * confident, the pass sets MinSize for the coming hour to the minimum the group needed at that hour of the
 * week, clamped to the band, and the windowed schedule and the idle-floor trim step aside: the pattern already
 * says where the quiet hours are and what the busy ones need. Every pass recomputes the pattern from 28 days of
 * the group's hours and the pressure events (src/actions/beanstalk_pressure.ts), stores it and mirrors it to
 * the graph. A MinSize set by hand holds for a day before the pattern resumes.
 *
 * Which identity does the work: with an operations role on the environment, Beanstalk does the CloudFormation
 * and Auto Scaling calls under that role and the actuator needs `elasticbeanstalk:UpdateEnvironment` only.
 * Without one, Beanstalk uses the caller's permissions, and the actuator would need the CloudFormation and
 * Auto Scaling rights the update makes; the pass notes say so per environment (the README shows the command).
 */
import { AutoScalingClient, DescribeAutoScalingGroupsCommand, DescribeScalingActivitiesCommand, type Activity } from "@aws-sdk/client-auto-scaling";
import { DescribeLoadBalancersCommand, DescribeTagsCommand, DescribeTargetGroupsCommand, ElasticLoadBalancingV2Client } from "@aws-sdk/client-elastic-load-balancing-v2";
import { DescribeInstanceTypesCommand, DescribeSecurityGroupsCommand, EC2Client, type _InstanceType } from "@aws-sdk/client-ec2";
import { CloudWatchClient, DescribeAlarmsCommand, GetMetricDataCommand } from "@aws-sdk/client-cloudwatch";
import { DescribeConfigurationSettingsCommand, DescribeEnvironmentResourcesCommand, DescribeEnvironmentsCommand, ElasticBeanstalkClient, ListTagsForResourceCommand, UpdateEnvironmentCommand, type EnvironmentDescription } from "@aws-sdk/client-elastic-beanstalk";
import { db, getJsonSetting, setSetting } from "../db.js";
import { config } from "../config.js";
import type { ActionModule, Creds, Proposal } from "../executor.js";
import { CONFIDENT, latestProfile, ringIndex, type QuietWindow } from "../usage_profile.js";
import { latestReview, windowsFromSchedule } from "../usage_review.js";
import { AUTO_SCALE_TAG, SCALE_BAND_TAG, isOff, isOn } from "../consent.js";
import { decidePattern, learnPattern, pressureEvents, savePattern, PATTERN_DAYS } from "../capacity_pattern.js";
import { describeSignals, groupSignalsByHour, needByHour, NET_TARGET, netBytesPerMemberHour, signalModel } from "../capacity_signals.js";
import { metricDimension } from "../elb_inventory.js";

export const KIND = "beanstalk_scale" as const;
export const SCALE_TAG = "advisor:scale";
export const METRIC_DAYS = 14;
export const MIN_METRIC_DAYS = 7;
/** The group must have sat at its floor for this share of the window's hours before the floor comes down. */
export const FLOOR_SHARE = 0.9;
export const MIN_HOURS_BETWEEN_CHANGES = 24;
export const ASG_NAMESPACE = "aws:autoscaling:asg";
const MAX_PER_PLAN = 20;
/** A windowed schedule needs at least this many quiet hours a week before it is worth two updates a day. */
export const MIN_WINDOW_HOURS_WEEK = 20;

export interface EnvState { baseline_min: number; last_set: number | null; since: string; /** when a MinSize that is not the executor's was first seen (the pattern waits a day) */ hand_set_at?: string | null }
const stateKey = (envId: string) => `act:eb:${envId}`;
export const envState = (envId: string) => getJsonSetting<EnvState | null>(stateKey(envId), null);
export const saveEnvState = (envId: string, s: EnvState) => setSetting(stateKey(envId), JSON.stringify(s));

export interface WindowInput { windows: QuietWindow[]; confidence: number; current_min: number; floor: number; baseline_min: number; last_set: number | null; /** the ring index (0 = Sunday 00:00 UTC) of the coming hour */ next: number }
export interface WindowDecision { wanted: number | null; baseline_min: number; quiet_hours_week: number; active: boolean; reason: string }
const inWindow = (w: QuietWindow, i: number) => { const n = 168; const s = w.effective_start % n, e = w.effective_end % n; const x = ((i % n) + n) % n; return w.effective_hours >= n ? true : s < e ? x >= s && x < e : x >= s || x < e; };

/**
 * The pure decision for the coming hour from the group's quiet windows: the floor before two quiet hours, the
 * baseline back before a working hour, nothing otherwise. `active` says whether the profile is good enough to
 * schedule from at all (confident windows, enough quiet hours a week). Pure.
 */
export function decideWindow(i: WindowInput): WindowDecision {
  let baseline = i.baseline_min;
  if (i.current_min !== i.floor && i.current_min !== baseline && i.current_min !== i.last_set) baseline = i.current_min;
  const windows = i.windows.filter((w) => w.confidence >= CONFIDENT && w.effective_hours >= 2);
  const quietHours = windows.reduce((s, w) => s + w.effective_hours, 0);
  const base = { baseline_min: baseline, quiet_hours_week: quietHours };
  if (!windows.length || quietHours < MIN_WINDOW_HOURS_WEEK) return { ...base, active: false, wanted: null, reason: windows.length ? `${quietHours} confident quiet hour(s) a week (needs ${MIN_WINDOW_HOURS_WEEK}) in the group's profile` : `no confident quiet window in the group's profile (confidence ${i.confidence})` };
  if (baseline <= i.floor) return { ...base, active: true, wanted: null, reason: `the configured minimum (${baseline}) is already the tag's floor` };
  const quiet = (h: number) => windows.some((w) => inWindow(w, h));
  const next = i.next, after = i.next + 1;
  if (quiet(next) && quiet(after)) {
    if (i.current_min === i.floor) return { ...base, active: true, wanted: null, reason: "the coming hour is quiet and the minimum is already at the floor" };
    return { ...base, active: true, wanted: i.floor, reason: `the coming two hours are quiet on every week of the group's profile (${quietHours} quiet hours a week): MinSize ${i.current_min} → ${i.floor} for the quiet hours` };
  }
  if (!quiet(next)) {
    if (i.current_min === baseline) return { ...base, active: true, wanted: null, reason: "the coming hour is a working hour and the minimum is at the configured value" };
    if (i.current_min > baseline) return { ...base, active: true, wanted: null, reason: `the minimum (${i.current_min}) is above the configured ${baseline}; not ours to lower` };
    return { ...base, active: true, wanted: baseline, reason: `the coming hour is a working hour in the group's profile: MinSize ${i.current_min} → ${baseline} before it starts` };
  }
  return { ...base, active: true, wanted: null, reason: "the coming hour is quiet but the one after is not; not worth a change for one hour" };
}

export interface Band { floor: number; ceiling: number | null; text: string }
export type { Bounds as GroupBounds };
/** `<floor>-<ceiling>` (both whole numbers, floor at least 1, ceiling above the floor) or `auto` (floor 1, the ceiling stays where it is). Pure. */
export function parseBand(tag: string): Band | { error: string } {
  const text = String(tag ?? "").trim().toLowerCase();
  if (text === "auto") return { floor: 1, ceiling: null, text };
  const m = /^(\d{1,3})\s*-\s*(\d{1,3})$/.exec(text);
  if (!m) return { error: `"${text}": expected "<floor>-<ceiling>" (e.g. 2-8) or "auto"` };
  const floor = Number(m[1]), ceiling = Number(m[2]);
  if (floor < 1) return { error: `"${text}": the floor is at least 1` };
  if (ceiling <= floor) return { error: `"${text}": the ceiling must be above the floor` };
  return { floor, ceiling, text };
}

const CAUSE_RE = /changing the desired capacity from (\d+) to (\d+)/gi;
/** Every "from X to Y" change an activity's cause records, oldest first within the activity. Pure. */
export function desiredChanges(activities: Pick<Activity, "StartTime" | "Cause">[]): { at: number; from: number; to: number }[] {
  const out: { at: number; from: number; to: number }[] = [];
  for (const a of activities) {
    const at = a.StartTime ? new Date(a.StartTime).getTime() : NaN; if (!Number.isFinite(at)) continue;
    for (const m of String(a.Cause || "").matchAll(CAUSE_RE)) out.push({ at, from: Number(m[1]), to: Number(m[2]) });
  }
  return out.sort((x, y) => x.at - y.at);
}

/**
 * The desired capacity at each hour of the window, replayed backwards from what the group wants now through the
 * changes its activities record: an hour is stamped with the capacity in force at its start. Pure.
 */
export function desiredByHour(hours: number[], desiredNow: number, changes: { at: number; from: number; to: number }[]): Map<number, number> {
  const out = new Map<number, number>();
  const sorted = [...changes].sort((x, y) => y.at - x.at); // newest first
  for (const h of [...hours].sort((a, b) => b - a)) {
    let d = desiredNow;
    for (const c of sorted) { if (c.at > h) d = c.from; else break; }
    out.set(h, d);
  }
  return out;
}

export interface UsageHour { at: number; cpu_avg: number; desired: number }
export interface Bounds { min: number; max: number; desired: number }
export interface VerdictInput { bounds: Bounds; band: Band; hours: UsageHour[]; days: number; low_cpu: number; high_cpu: number; pressure_hours: number; health_ok: boolean }
export interface Verdict { move: "floor_down" | "ceiling_up" | null; option: "MinSize" | "MaxSize" | null; from: number; to: number; reason: string; floor_hours: number; floor_share: number; floor_p95: number | null; pressure_hours: number }

const p95 = (xs: number[]) => { if (!xs.length) return null; const s = [...xs].sort((a, b) => a - b); return s[Math.min(s.length - 1, Math.floor(0.95 * (s.length - 1)))]; };
const pct = (x: number) => `${x.toFixed(1)} %`;

/** The verdict for one environment: pure. Pressure at the ceiling wins over an idle floor (it is the one users notice). */
export function scaleVerdict(i: VerdictInput): Verdict {
  const { bounds: b, band, hours } = i;
  const none = (reason: string, extra: Partial<Verdict> = {}): Verdict => ({ move: null, option: null, from: 0, to: 0, reason, floor_hours: 0, floor_share: 0, floor_p95: null, pressure_hours: 0, ...extra });
  if (i.days < MIN_METRIC_DAYS) return none(`${i.days} day(s) of metrics, ${MIN_METRIC_DAYS} needed`);
  if (!hours.length) return none("no CPU metrics for the group");
  const pressure = hours.filter((h) => h.desired >= b.max && h.cpu_avg >= i.high_cpu).length;
  const atFloor = hours.filter((h) => h.desired <= b.min);
  const floorShare = atFloor.length / hours.length;
  const floorP95 = p95(atFloor.map((h) => h.cpu_avg));
  const facts = { floor_hours: atFloor.length, floor_share: Math.round(floorShare * 100) / 100, floor_p95: floorP95 == null ? null : Math.round(floorP95 * 10) / 10, pressure_hours: pressure };
  if (pressure >= i.pressure_hours) {
    if (band.ceiling == null) return none(`pinned at the maximum of ${b.max} with CPU ≥ ${pct(i.high_cpu)} for ${pressure} h of the last ${i.days} days, but the tag says "auto": the ceiling stays; set ${SCALE_TAG}=<floor>-<ceiling> to let it grow`, facts);
    if (b.max >= band.ceiling) return none(`pinned at the maximum of ${b.max} with CPU ≥ ${pct(i.high_cpu)} for ${pressure} h of the last ${i.days} days, and ${b.max} is the tag's ceiling`, facts);
    return { move: "ceiling_up", option: "MaxSize", from: b.max, to: b.max + 1, reason: `the group spent ${pressure} h of the last ${i.days} days pinned at its maximum of ${b.max} with the average CPU at or above ${pct(i.high_cpu)}: the trigger wanted more and the cap said no. One more instance at the top (the tag allows up to ${band.ceiling})`, ...facts };
  }
  if (b.min <= band.floor) return none(`minimum ${b.min} is already the tag's floor${floorP95 != null ? ` (p95 CPU at the floor ${pct(floorP95)})` : ""}`, facts);
  if (floorShare < FLOOR_SHARE) return none(`at its minimum of ${b.min} for ${Math.round(floorShare * 100)} % of the window (${Math.round(FLOOR_SHARE * 100)} % needed): it scales out for real`, facts);
  if (floorP95 == null || floorP95 >= i.low_cpu) return none(`at its minimum of ${b.min} but the p95 CPU there is ${floorP95 == null ? "unknown" : pct(floorP95)} (under ${pct(i.low_cpu)} needed)`, facts);
  if (!i.health_ok) return none(`the floor could come down (p95 CPU ${pct(floorP95)} at ${b.min}) but the environment's health is not Ok: nothing is cut while it struggles`, facts);
  const projected = Math.round((floorP95 * b.min) / (b.min - 1) * 10) / 10;
  return { move: "floor_down", option: "MinSize", from: b.min, to: b.min - 1, reason: `the group sat at its minimum of ${b.min} for ${Math.round(floorShare * 100)} % of the last ${i.days} days with the hourly average CPU under ${pct(floorP95)} (p95): ${b.min - 1} instance${b.min - 1 === 1 ? "" : "s"} would have run at about ${pct(projected)}. The group scales in to the new floor when Beanstalk's scale-in trigger next fires`, ...facts };
}

export interface EnvFacts { env: EnvironmentDescription; tags: Record<string, string>; asg: string | null; instances: string[]; cfg: { min: number | null; max: number | null }; load_balancers: string[] }

const num = (v: string | undefined) => { const n = Number(v); return v != null && v !== "" && Number.isFinite(n) ? n : null; };
export const hourStart = (t: number) => Math.floor(t / 3600000) * 3600000;

/**
 * The executor's last hourly MinSize row for the environment when it failed or was refused and the minimum still
 * reads what that row started from: the change never took, so the minimum is not a person's. Null otherwise.
 */
export function changeThatDidNotTake(envId: string, lastSet: number | null, currentMin: number): { id: number; status: string } | null {
  if (lastSet == null || lastSet === currentMin) return null;
  const r = db.prepare(`select id, status, before_json, after_json from actions where kind = ? and resource = ?
    and (coalesce(json_extract(facts_json, '$.pattern'), 0) = 1 or coalesce(json_extract(facts_json, '$.window'), 0) = 1)
    and json_extract(after_json, '$.MinSize') is not null and status not in ('proposed', 'stale') order by id desc limit 1`).get(KIND, envId) as { id: number; status: string; before_json: string; after_json: string } | undefined;
  if (!r || !["failed", "refused"].includes(r.status)) return null;
  try {
    const before = Number(JSON.parse(r.before_json).MinSize), after = Number(JSON.parse(r.after_json).MinSize);
    return after === lastSet && before === currentMin ? { id: r.id, status: r.status } : null;
  } catch { return null; }
}

const bandwidthCache = new Map<string, number | null>();
/** The instance type's baseline network bandwidth in Gbps (the first network card), null when AWS does not say. Cached per region and type. */
async function baselineGbps(region: string, credentials: any, type: string | undefined): Promise<number | null> {
  if (!type) return null;
  const key = `${region}|${type}`;
  if (bandwidthCache.has(key)) return bandwidthCache.get(key)!;
  const ec2 = new EC2Client({ region, credentials });
  try {
    const r = await ec2.send(new DescribeInstanceTypesCommand({ InstanceTypes: [type as _InstanceType] }));
    const v = r.InstanceTypes?.[0]?.NetworkInfo?.NetworkCards?.[0]?.BaselineBandwidthInGbps ?? null;
    bandwidthCache.set(key, v); return v;
  } catch { return null; } finally { ec2.destroy(); }
}

async function scalingActivities(as: AutoScalingClient, asg: string, since: number): Promise<Activity[]> {
  const out: Activity[] = [];
  let NextToken: string | undefined;
  do {
    const r = await as.send(new DescribeScalingActivitiesCommand({ AutoScalingGroupName: asg, MaxRecords: 100, NextToken }));
    for (const a of r.Activities ?? []) { if (a.StartTime && new Date(a.StartTime).getTime() < since) return out; out.push(a); }
    NextToken = r.NextToken;
  } while (NextToken);
  return out;
}

/** The scale-in and scale-out alarms Beanstalk made for the environment (awseb-e-<id>-stack-AWSEBCloudwatchAlarmLow/High-…), by state. */
async function triggerAlarms(cw: CloudWatchClient, envId: string): Promise<{ low: string | null; high: string | null }> {
  const r = await cw.send(new DescribeAlarmsCommand({ AlarmNamePrefix: `awseb-${envId}-stack-AWSEBCloudwatchAlarm`, MaxRecords: 20 }));
  const find = (part: string) => r.MetricAlarms?.find((a) => a.AlarmName?.includes(part))?.StateValue ?? null;
  return { low: find("AlarmLow"), high: find("AlarmHigh") };
}

export function regions(defaultRegion: string): string[] {
  const rows = db.prepare("select distinct region from inventory_ec2 where gone = 0 and region is not null").all() as { region: string }[];
  return [...new Set([defaultRegion, ...rows.map((r) => r.region)])];
}

/** One member's list price, from the inventory (the estimate of a floor cut). */
export function memberPrice(instanceIds: string[]): number | null {
  for (const id of instanceIds) {
    const r = db.prepare("select monthly_usd from inventory_ec2 where instance_id = ?").get(id) as { monthly_usd: number | null } | undefined;
    if (r?.monthly_usd) return r.monthly_usd;
  }
  return null;
}

/**
 * Whether the environment's stack resources carry Beanstalk's own tags (`elasticbeanstalk:environment-id` and the
 * like). AWS's managed policy for an operations role allows the calls a stack update makes (re-tagging the balancer's
 * security group, modifying the target group) only on resources that carry them; an older environment's resources
 * do not, so its first update under the operations role fails and leaves the stack in rollback. Pure.
 */
export function untaggedResources(resources: { id: string; kind: "security_group" | "target_group"; tag_keys: string[] }[]): { id: string; kind: string }[] {
  return resources.filter((r) => !r.tag_keys.some((k) => k.startsWith("elasticbeanstalk:"))).map((r) => ({ id: r.id, kind: r.kind }));
}

/** The remedy the pass notes point at when the resources are untagged: the Beanstalk-scoped admin policy on the operations role (the README says why). */
export const OPS_ROLE_INLINE_POLICY_NOTE = "attach AdministratorAccess-AWSElasticBeanstalk to the operations role (README, Elastic Beanstalk environments)";

/** Reads the balancer's security groups and target groups of an environment and their tag keys; a missing permission means no verdict (null). */
export async function environmentTagGaps(region: string, credentials: any, lbArns: string[]): Promise<{ id: string; kind: string }[] | null> {
  if (!lbArns.length) return [];
  const elb = new ElasticLoadBalancingV2Client({ region, credentials });
  const ec2 = new EC2Client({ region, credentials });
  try {
    const lbs = (await elb.send(new DescribeLoadBalancersCommand({ LoadBalancerArns: lbArns }))).LoadBalancers ?? [];
    const sgIds = [...new Set(lbs.flatMap((l) => l.SecurityGroups ?? []))];
    const tgs = (await Promise.all(lbArns.map((a) => elb.send(new DescribeTargetGroupsCommand({ LoadBalancerArn: a })).then((r) => r.TargetGroups ?? [])))).flat();
    const tgArns = tgs.map((t) => t.TargetGroupArn!).filter(Boolean);
    const out: { id: string; kind: "security_group" | "target_group"; tag_keys: string[] }[] = [];
    if (sgIds.length) for (const g of (await ec2.send(new DescribeSecurityGroupsCommand({ GroupIds: sgIds }))).SecurityGroups ?? []) out.push({ id: g.GroupId!, kind: "security_group", tag_keys: (g.Tags ?? []).map((t) => t.Key!).filter(Boolean) });
    if (tgArns.length) for (const d of (await elb.send(new DescribeTagsCommand({ ResourceArns: tgArns }))).TagDescriptions ?? []) out.push({ id: d.ResourceArn!.split("/").slice(-2).join("/"), kind: "target_group", tag_keys: (d.Tags ?? []).map((t) => t.Key!).filter(Boolean) });
    return untaggedResources(out);
  } catch { return null; }
  finally { elb.destroy(); ec2.destroy(); }
}

export async function environmentFacts(eb: ElasticBeanstalkClient, env: EnvironmentDescription): Promise<EnvFacts> {
  const tags: Record<string, string> = {};
  if (env.EnvironmentArn) for (const t of (await eb.send(new ListTagsForResourceCommand({ ResourceArn: env.EnvironmentArn }))).ResourceTags ?? []) if (t.Key) tags[t.Key] = t.Value ?? "";
  const res = (await eb.send(new DescribeEnvironmentResourcesCommand({ EnvironmentId: env.EnvironmentId }))).EnvironmentResources;
  const asg = res?.AutoScalingGroups?.[0]?.Name ?? null;
  const instances = (res?.Instances ?? []).map((i) => i.Id!).filter(Boolean);
  // an application or network balancer is named by its ARN here; a classic one by its name (no target groups: nothing to check)
  const load_balancers = (res?.LoadBalancers ?? []).map((l) => l.Name!).filter((n) => n && n.startsWith("arn:"));
  const cfg = { min: null as number | null, max: null as number | null };
  const settings = (await eb.send(new DescribeConfigurationSettingsCommand({ ApplicationName: env.ApplicationName, EnvironmentName: env.EnvironmentName }))).ConfigurationSettings?.[0]?.OptionSettings ?? [];
  for (const o of settings) if (o.Namespace === ASG_NAMESPACE) { if (o.OptionName === "MinSize") cfg.min = num(o.Value); if (o.OptionName === "MaxSize") cfg.max = num(o.Value); }
  return { env, tags, asg, instances, cfg, load_balancers };
}

export const beanstalkScaleAction: ActionModule = {
  kind: KIND,
  label: "Elastic Beanstalk capacity bounds from the group's 14-day usage",

  async plan(creds, log) {
    const proposals: Proposal[] = []; const notes: string[] = [];
    const now = Date.now();
    let seen = 0, tagged = 0, patterns = 0;
    for (const acct of creds.accounts) for (const region of regions(acct.region)) {
      const eb = new ElasticBeanstalkClient({ region, credentials: acct.read });
      const as = new AutoScalingClient({ region, credentials: acct.read });
      const cw = new CloudWatchClient({ region, credentials: acct.read });
      try {
        const envs = (await eb.send(new DescribeEnvironmentsCommand({ IncludeDeleted: false }))).Environments ?? [];
        for (const env of envs) {
          if (proposals.length >= MAX_PER_PLAN) { notes.push(`${MAX_PER_PLAN} proposals is enough for one pass; the rest waits`); break; }
          seen++;
          const name = env.EnvironmentName || env.EnvironmentId || "?";
          const skip = (why: string) => { notes.push(`${name}: ${why}`); log(`${name}: ${why}`); };
          let f: EnvFacts;
          try { f = await environmentFacts(eb, env); } catch (e: any) { skip(`describe failed: ${String(e?.message || e).slice(0, 160)}`); continue; }
          if (f.tags["advisor:hands-off"] != null) { log(`${name}: tagged advisor:hands-off`); continue; }
          if (isOff(f.tags[AUTO_SCALE_TAG])) { log(`${name}: ${AUTO_SCALE_TAG}=${f.tags[AUTO_SCALE_TAG]}`); continue; }
          // AdvisorAutoScale=ON is the consent (band from AdvisorScaleBand, else floor 1 and the ceiling where it is); advisor:scale=<band> the older spelling
          const tag = isOn(f.tags[AUTO_SCALE_TAG]) ? (f.tags[SCALE_BAND_TAG] || "auto") : f.tags[SCALE_TAG];
          if (tag == null) { log(`${name}: not tagged ${AUTO_SCALE_TAG}=ON (or ${SCALE_TAG})`); continue; }
          tagged++;
          const band = parseBand(tag);
          if ("error" in band) { skip(`tag ${SCALE_TAG} ${band.error}`); continue; }
          if (!f.asg) { skip("single-instance environment (no Auto Scaling group): nothing to scale"); continue; }
          if (env.OperationsRole) {
            const gaps = await environmentTagGaps(region, acct.read, f.load_balancers);
            if (gaps?.length) notes.push(`${name}: ${gaps.map((g) => `${g.kind.replace("_", " ")} ${g.id}`).join(" and ")} carry no elasticbeanstalk:* tags, so the operations role's managed policy will not match them and a stack update fails on the first try (the stack is then left in rollback): ${OPS_ROLE_INLINE_POLICY_NOTE}`);
          }
          if (env.Status !== "Ready") { skip(`environment is ${env.Status}`); continue; }
          if (f.cfg.min == null || f.cfg.max == null) { skip("MinSize/MaxSize not readable from the configuration"); continue; }
          // the last step, not the hourly moves: a pattern or window row neither blocks a step nor is blocked by one
          const recent = db.prepare(`select id, status, applied_at from actions where kind = ? and resource = ? and status in ('applied', 'verified') and datetime(applied_at) > datetime('now', ?)
            and coalesce(json_extract(facts_json, '$.pattern'), 0) = 0 and coalesce(json_extract(facts_json, '$.window'), 0) = 0 order by id desc limit 1`).get(KIND, env.EnvironmentId, `-${MIN_HOURS_BETWEEN_CHANGES} hours`) as { id: number; status: string; applied_at: string } | undefined;
          const stepHeld = recent ? `changed by #${recent.id} at ${recent.applied_at} (one step per ${MIN_HOURS_BETWEEN_CHANGES} h)` : null;
          const group = (await as.send(new DescribeAutoScalingGroupsCommand({ AutoScalingGroupNames: [f.asg] }))).AutoScalingGroups?.[0];
          if (!group) { skip(`group ${f.asg} not found`); continue; }
          const bounds: Bounds = { min: group.MinSize ?? f.cfg.min, max: group.MaxSize ?? f.cfg.max, desired: group.DesiredCapacity ?? 0 };
          if (bounds.min !== f.cfg.min || bounds.max !== f.cfg.max) { skip(`the live group is ${bounds.min}-${bounds.max} but the configuration says ${f.cfg.min}-${f.cfg.max} (edited directly?): sort that out first`); continue; }
          // 28 days of hours feed the learned week; the verdict below reads the last 14 of them
          // every signal of the group (CPU, memory, disk, requests, network, latency, 5xx) sizes the learned week
          const sig = await groupSignalsByHour(cw, { asg: f.asg, lb_dimensions: f.load_balancers.map(metricDimension).filter((d) => d.startsWith("app/")), now, days: PATTERN_DAYS });
          const cpu = new Map([...sig.hours].flatMap(([h, v]) => (v.cpu != null ? [[h, v.cpu] as [number, number]] : [])));
          const allHours = [...sig.hours.keys()].sort((a, b) => a - b);
          const changes = desiredChanges(await scalingActivities(as, f.asg, hourStart(now) - PATTERN_DAYS * 86400000));
          const desiredAll = desiredByHour(allHours, bounds.desired, changes);
          const gbps = await baselineGbps(region, acct.read, group.Instances?.[0]?.InstanceType);
          const targets = { cpu: config.actEbTargetCpu, mem: config.actEbTargetMem, disk: config.actEbHighDisk, net_bytes_per_member: netBytesPerMemberHour(gbps) };
          sig.notes.push(gbps ? `network capacity: ${gbps} Gbps baseline of ${group.Instances?.[0]?.InstanceType} at ${Math.round(NET_TARGET * 100)} % per member` : `no baseline bandwidth for ${group.Instances?.[0]?.InstanceType ?? "the members' type"}: network capacity is the busiest healthy hour`);
          const sigHours = allHours.map((h) => ({ at: h, desired: desiredAll.get(h) ?? bounds.desired, ...sig.hours.get(h) }));
          const model = signalModel(sigHours, targets);
          const needs = new Map(needByHour(sigHours, targets, model).map((n) => [n.at, n]));
          for (const n of sig.notes) log(`${name}: ${n}`);
          const hoursList = allHours.filter((h) => cpu.has(h) && h >= hourStart(now) - METRIC_DAYS * 86400000);
          const hours: UsageHour[] = hoursList.map((h) => ({ at: h, cpu_avg: cpu.get(h)!, desired: desiredAll.get(h) ?? bounds.desired }));
          const days = new Set(hoursList.map((h) => new Date(h).toISOString().slice(0, 10))).size;
          const pattern = learnPattern({
            hours: allHours.map((h) => ({ at: h, desired: desiredAll.get(h) ?? bounds.desired, cpu_avg: cpu.get(h) ?? null, need: needs.get(h)?.need, binding: needs.get(h)?.binding })),
            pressure: pressureEvents(env.EnvironmentId!), floor: band.floor, ceiling: band.ceiling, now,
            signals: { summary: describeSignals(model, sig.sources), notes: sig.notes, mem_idle: model.mem_idle, requests_per_member: model.requests_per_member, net_in_per_member: model.net_in_per_member, net_out_per_member: model.net_out_per_member, latency_median: model.latency_median, healthy_hours: model.healthy_hours, targets },
          });
          savePattern({ env_id: env.EnvironmentId!, env_name: env.EnvironmentName ?? null, asg: f.asg, region, account_id: acct.account_id ?? null, pattern });
          patterns++;
          const healthOk = !env.HealthStatus || ["Ok", "Info", "Pending", "Unknown"].includes(env.HealthStatus) || env.Health === "Green";
          // the windowed minimum from the group's usage profile, decided for the coming hour
          const profile = latestProfile(`asg:${f.asg}`);
          const groupReview = latestReview(`asg:${f.asg}`);
          const state = envState(env.EnvironmentId!) ?? { baseline_min: f.cfg.min, last_set: null, since: new Date().toISOString() };
          // the agent's bounds: fewer machines that still do the job (a new configured minimum), a ceiling it needs; within the tag's band
          const ceiling = band.ceiling ?? bounds.max;
          const agentMin = groupReview?.group_min != null && groupReview.group_min >= band.floor && groupReview.group_min <= ceiling ? groupReview.group_min : null;
          const agentMax = groupReview?.group_max != null && groupReview.group_max >= (agentMin ?? bounds.min) && groupReview.group_max <= ceiling ? groupReview.group_max : null;
          if (agentMin != null && agentMin !== state.baseline_min && agentMin !== bounds.min) {
            if (stepHeld) { skip(`the agent's MinSize ${agentMin} waits: ${stepHeld}`); continue; }
            const price = memberPrice(f.instances);
            proposals.push({
              kind: KIND, resource: env.EnvironmentId!, resource_name: env.EnvironmentName ?? null, region, account_id: acct.account_id ?? null,
              dedupe: `${KIND}:${env.EnvironmentId}:agent-min:${agentMin}`,
              title: `${name}: MinSize ${bounds.min} → ${agentMin} (the agent: ${agentMin < bounds.min ? "fewer machines do the job" : "more machines are needed"})`,
              reason: `${groupReview!.reason.slice(0, 400)} Tag ${SCALE_TAG}=${band.text}; the agent's minimum becomes the configured minimum the windows return to.${agentMin < bounds.min ? " The group scales in when Beanstalk's scale-in alarm next fires." : ""}`,
              before: { MinSize: bounds.min, MaxSize: bounds.max }, after: { MinSize: agentMin },
              facts: { agent_bounds: true, application: env.ApplicationName, asg: f.asg, desired_now: bounds.desired, band: band.text, baseline_min: state.baseline_min, group_min: agentMin, group_max: groupReview!.group_max ?? null, operations_role: env.OperationsRole || null, member_usd_month: price },
              rollback: `UpdateEnvironment MinSize back to ${bounds.min}`,
              est_usd_month: agentMin < bounds.min && price ? Math.round((bounds.min - agentMin) * price * 100) / 100 : null,
            });
            continue;
          }
          if (agentMax != null && agentMax !== bounds.max) {
            if (stepHeld) { skip(`the agent's MaxSize ${agentMax} waits: ${stepHeld}`); continue; }
            proposals.push({
              kind: KIND, resource: env.EnvironmentId!, resource_name: env.EnvironmentName ?? null, region, account_id: acct.account_id ?? null,
              dedupe: `${KIND}:${env.EnvironmentId}:agent-max:${agentMax}`,
              title: `${name}: MaxSize ${bounds.max} → ${agentMax} (the agent's ceiling)`,
              reason: `${groupReview!.reason.slice(0, 400)} Tag ${SCALE_TAG}=${band.text}.`,
              before: { MinSize: bounds.min, MaxSize: bounds.max }, after: { MaxSize: agentMax },
              facts: { agent_bounds: true, application: env.ApplicationName, asg: f.asg, desired_now: bounds.desired, band: band.text, group_min: groupReview!.group_min ?? null, group_max: agentMax, operations_role: env.OperationsRole || null },
              rollback: `UpdateEnvironment MaxSize back to ${bounds.max}`,
              est_usd_month: null,
            });
            continue;
          }
          // the learned week, once a person set the band and the pattern is confident: MinSize for the coming hour
          if (band.ceiling != null) {
            const undone = changeThatDidNotTake(env.EnvironmentId!, state.last_set, bounds.min);
            if (undone) { log(`${name}: MinSize ${state.last_set} from #${undone.id} did not take (${undone.status}); ${bounds.min} is still the executor's, not a hand-set`); state.last_set = bounds.min; state.hand_set_at = null; saveEnvState(env.EnvironmentId!, state); }
            const handSet = state.last_set != null && bounds.min !== state.last_set;
            if (handSet && !state.hand_set_at) { state.hand_set_at = new Date().toISOString(); saveEnvState(env.EnvironmentId!, state); }
            if (!handSet && state.hand_set_at) { state.hand_set_at = null; saveEnvState(env.EnvironmentId!, state); }
            const d = decidePattern({ pattern, next: ringIndex(hourStart(now) + 3600000), current_min: bounds.min, last_set: state.last_set, hand_set_at: state.hand_set_at ?? null, now });
            if (d.active) {
              log(`${name}: pattern: ${d.reason}`);
              if (d.wanted != null && d.wanted !== bounds.min) {
                const price = memberPrice(f.instances);
                const lowering = d.wanted < bounds.min;
                const hoursAtOrBelow = pattern.learned.filter((x) => x <= d.wanted!).length;
                proposals.push({
                  kind: KIND, resource: env.EnvironmentId!, resource_name: env.EnvironmentName ?? null, region, account_id: acct.account_id ?? null,
                  dedupe: `${KIND}:${env.EnvironmentId}:pattern:${d.wanted}:${new Date(hourStart(now) + 3600000).toISOString().slice(0, 13)}`,
                  title: `${name}: MinSize ${bounds.min} → ${d.wanted} (the learned week)`,
                  reason: `${d.reason}. Band ${SCALE_BAND_TAG}=${band.text}: never below ${band.floor}, never above ${band.ceiling}. The environment updates for a minute or two; ${lowering ? "the group scales in when Beanstalk's scale-in alarm next fires" : "the group launches what the new minimum needs before the hour"}.`,
                  before: { MinSize: bounds.min, MaxSize: bounds.max }, after: { MinSize: d.wanted },
                  facts: { pattern: true, application: env.ApplicationName, asg: f.asg, desired_now: bounds.desired, band: band.text, floor: band.floor, ceiling: band.ceiling, weeks: pattern.weeks, coverage: pattern.coverage, pressure_events: pattern.pressure_events, learned_week: pattern.summary, hours_at_or_below: hoursAtOrBelow, operations_role: env.OperationsRole || null, member_usd_month: price },
                  rollback: `UpdateEnvironment MinSize back to ${bounds.min}`,
                  est_usd_month: lowering && price ? Math.round((bounds.min - d.wanted) * price * (hoursAtOrBelow / 168) * 100) / 100 : null,
                });
                if (!env.OperationsRole) notes.push(`${name}: no operations role on the environment, so UpdateEnvironment runs with the actuator's own permissions (see the README)`);
                continue;
              }
              // the pattern owns the minimum: no windowed schedule and no idle-floor trim on top of it; the ceiling raise still runs
              const v = scaleVerdict({ bounds, band, hours, days, low_cpu: config.actEbLowCpu, high_cpu: config.actEbHighCpu, pressure_hours: config.actEbPressureHours, health_ok: healthOk });
              if (v.move !== "ceiling_up" || !v.option) { log(`${name}: ${v.move === "floor_down" ? "the learned week owns the minimum; the idle-floor trim is skipped" : v.reason}`); continue; }
              if (stepHeld) { log(`${name}: the ceiling raise waits: ${stepHeld}`); continue; }
              const opsRole = env.OperationsRole || null;
              if (!opsRole) notes.push(`${name}: no operations role on the environment, so UpdateEnvironment runs with the actuator's own permissions and needs the CloudFormation and Auto Scaling rights it makes (associate-environment-operations-role fixes that; see the README)`);
              proposals.push({
                kind: KIND, resource: env.EnvironmentId!, resource_name: env.EnvironmentName ?? null, region, account_id: acct.account_id ?? null,
                dedupe: `${KIND}:${env.EnvironmentId}:${v.option}:${v.to}`,
                title: `${name}: ${v.option} ${v.from} → ${v.to} (pinned at the ceiling)`,
                reason: `${v.reason}. Band ${SCALE_BAND_TAG}=${band.text}. This adds cost rather than saving it: one more instance whenever the trigger asks for it.${opsRole ? "" : " No operations role on the environment: the actuator's own rights do the update."}`,
                before: { [v.option]: v.from, MinSize: bounds.min, MaxSize: bounds.max }, after: { [v.option]: v.to },
                facts: { application: env.ApplicationName, asg: f.asg, desired_now: bounds.desired, band: band.text, metric_days: days, pressure_hours: v.pressure_hours, high_cpu: config.actEbHighCpu, operations_role: opsRole, health: env.HealthStatus ?? null, learned_week: pattern.summary },
                rollback: `UpdateEnvironment ${v.option} back to ${v.from} (the environment updates for a minute or two, no instance is replaced)`,
                est_usd_month: null,
              });
              continue;
            }
            log(`${name}: pattern: ${d.reason}`);
          }
          // the agent's downsize windows, when it decided for this group, win over the profile's own quiet windows
          const agentWindows = groupReview && groupReview.verdict !== "keep_running" ? windowsFromSchedule(groupReview.schedule) : [];
          const windows = agentWindows.length ? agentWindows : groupReview?.verdict === "keep_running" ? [] : (profile?.quiet_windows ?? []);
          const nextIdx = ringIndex(hourStart(now) + 3600000);
          const w = decideWindow({ windows, confidence: agentWindows.length ? 1 : profile?.confidence ?? 0, current_min: bounds.min, floor: band.floor, baseline_min: state.baseline_min, last_set: state.last_set, next: nextIdx });
          if (groupReview?.verdict === "keep_running" && !agentWindows.length) log(`${name}: the agent keeps the group at its configured minimum: ${groupReview.reason.slice(0, 200)}`);
          if (w.baseline_min !== state.baseline_min || !envState(env.EnvironmentId!)) saveEnvState(env.EnvironmentId!, { ...state, baseline_min: w.baseline_min, since: new Date().toISOString() });
          if (w.active && w.wanted != null && w.wanted !== bounds.min) {
            const price = memberPrice(f.instances);
            const lowering = w.wanted < bounds.min;
            proposals.push({
              kind: KIND, resource: env.EnvironmentId!, resource_name: env.EnvironmentName ?? null, region, account_id: acct.account_id ?? null,
              dedupe: `${KIND}:${env.EnvironmentId}:window:${w.wanted}:${new Date(hourStart(now) + 3600000).toISOString().slice(0, 13)}`,
              title: `${name}: MinSize ${bounds.min} → ${w.wanted} (${lowering ? "quiet hours" : "before the working hours"})`,
              reason: `${w.reason}. Tag ${SCALE_TAG}=${band.text}; ${agentWindows.length ? `the agent decided the downsize windows (${groupReview!.schedule}): ${groupReview!.reason.slice(0, 300)}` : `the group's usage profile (${profile?.window_days ?? 28} days, confidence ${profile?.confidence ?? "?"}) has ${w.quiet_hours_week} confident quiet hours a week`}. The environment updates for a minute or two; no instance is replaced${lowering ? ", and the group scales in when Beanstalk's scale-in alarm next fires" : ""}.`,
              before: { MinSize: bounds.min, MaxSize: bounds.max }, after: { MinSize: w.wanted },
              facts: { window: true, application: env.ApplicationName, asg: f.asg, desired_now: bounds.desired, band: band.text, baseline_min: w.baseline_min, floor: band.floor, quiet_hours_week: w.quiet_hours_week, profile_confidence: profile?.confidence ?? null, decided_by: agentWindows.length ? "agent" : "profile", downsize_windows: windows.map((x) => x.label), operations_role: env.OperationsRole || null, member_usd_month: price },
              rollback: `UpdateEnvironment MinSize back to ${bounds.min}`,
              est_usd_month: lowering && price ? Math.round((bounds.min - w.wanted) * price * (w.quiet_hours_week / 168) * 100) / 100 : null,
            });
            if (!env.OperationsRole) notes.push(`${name}: no operations role on the environment, so UpdateEnvironment runs with the actuator's own permissions (see the README)`);
            continue;
          }
          if (w.active) log(`${name}: window: ${w.reason}`);
          const v = scaleVerdict({ bounds: w.active ? { ...bounds, min: Math.max(bounds.min, w.baseline_min) } : bounds, band, hours, days, low_cpu: config.actEbLowCpu, high_cpu: config.actEbHighCpu, pressure_hours: config.actEbPressureHours, health_ok: healthOk });
          if (w.active && v.move === "floor_down") { log(`${name}: a windowed schedule is in force; the idle-floor trim is skipped`); continue; }
          if (!v.move || !v.option) { log(`${name}: ${v.reason}`); continue; }
          if (stepHeld) { skip(`${v.move === "floor_down" ? "the idle-floor trim" : "the ceiling raise"} waits: ${stepHeld}`); continue; }
          const alarms = await triggerAlarms(cw, env.EnvironmentId!).catch(() => ({ low: null, high: null }));
          const price = v.move === "floor_down" ? memberPrice(f.instances) : null;
          const opsRole = env.OperationsRole || null;
          if (!opsRole) notes.push(`${name}: no operations role on the environment, so UpdateEnvironment runs with the actuator's own permissions and needs the CloudFormation and Auto Scaling rights it makes (associate-environment-operations-role fixes that; see the README)`);
          const after = { [v.option]: v.to };
          proposals.push({
            kind: KIND, resource: env.EnvironmentId!, resource_name: env.EnvironmentName ?? null, region, account_id: acct.account_id ?? null,
            dedupe: `${KIND}:${env.EnvironmentId}:${v.option}:${v.to}`,
            title: `${name}: ${v.option} ${v.from} → ${v.to} (${v.move === "floor_down" ? "idle at the floor" : "pinned at the ceiling"})`,
            reason: `${v.reason}. Tag ${SCALE_TAG}=${band.text}. ${v.move === "floor_down" ? `Scale-in alarm is ${alarms.low ?? "unknown"} right now${alarms.low === "ALARM" ? ", so the group scales in as soon as the floor drops" : ""}.` : "This adds cost rather than saving it: one more instance whenever the trigger asks for it."}${opsRole ? "" : " No operations role on the environment: the actuator needs CloudFormation and Auto Scaling rights for the update (see the pass notes)."}`,
            before: { [v.option]: v.from, MinSize: bounds.min, MaxSize: bounds.max },
            after,
            facts: { application: env.ApplicationName, asg: f.asg, desired_now: bounds.desired, band: band.text, metric_days: days, floor_hours: v.floor_hours, floor_share: v.floor_share, floor_p95_cpu: v.floor_p95, pressure_hours: v.pressure_hours, low_cpu: config.actEbLowCpu, high_cpu: config.actEbHighCpu, alarm_low: alarms.low, alarm_high: alarms.high, operations_role: opsRole, health: env.HealthStatus ?? env.Health ?? null, member_usd_month: price },
            rollback: `UpdateEnvironment ${v.option} back to ${v.from} (the environment updates for a minute or two, no instance is replaced)`,
            est_usd_month: price,
          });
        }
      } catch (e: any) { const m = String(e?.message || e); notes.push(`${region}: ${m.slice(0, 160)}`); log(`${region}: ${m}`); }
      finally { eb.destroy(); as.destroy(); cw.destroy(); }
    }
    if (patterns) import("../graph_mirror.js").then((m) => m.mirrorCapacityPatternsInBackground()).catch(() => { /* graph optional */ });
    if (!seen) notes.push("no Elastic Beanstalk environment in any region the inventory knows");
    else if (!tagged) notes.push(`${seen} environment(s) seen, none tagged ${AUTO_SCALE_TAG}=ON (or ${SCALE_TAG}=2-8): nothing is scaled without the tag`);
    else if (!proposals.length) notes.push(`${tagged} tagged environment(s) checked: bounds fit the last ${METRIC_DAYS} days`);
    return { proposals, notes };
  },

  async apply(p, creds) {
    const eb = new ElasticBeanstalkClient({ region: p.region, credentials: creds.act() });
    try {
      const [option, value] = Object.entries(p.after)[0];
      const r = await eb.send(new UpdateEnvironmentCommand({ EnvironmentId: p.resource, OptionSettings: [{ Namespace: ASG_NAMESPACE, OptionName: option, Value: String(value) }] }));
      if (p.facts.window && option === "MinSize") { const s = envState(p.resource) ?? { baseline_min: Number(p.facts.baseline_min ?? p.before.MinSize), last_set: null, since: new Date().toISOString() }; saveEnvState(p.resource, { ...s, last_set: Number(value) }); }
      if (p.facts.pattern && option === "MinSize") { const s = envState(p.resource) ?? { baseline_min: Number(p.before.MinSize), last_set: null, since: new Date().toISOString() }; saveEnvState(p.resource, { ...s, last_set: Number(value), hand_set_at: null }); }
      if (p.facts.agent_bounds && option === "MinSize") { const s = envState(p.resource) ?? { baseline_min: Number(value), last_set: null, since: new Date().toISOString() }; saveEnvState(p.resource, { ...s, baseline_min: Number(value), last_set: Number(value), since: new Date().toISOString() }); }
      return `UpdateEnvironment: ${option} ${p.before[option]} → ${value} (environment ${r.Status ?? "Updating"})`;
    } finally { eb.destroy(); }
  },

  async verify(p, creds) {
    const eb = new ElasticBeanstalkClient({ region: p.region, credentials: creds.read });
    const as = new AutoScalingClient({ region: p.region, credentials: creds.read });
    try {
      const env = (await eb.send(new DescribeEnvironmentsCommand({ EnvironmentIds: [p.resource], IncludeDeleted: false }))).Environments?.[0];
      if (!env) return { ok: false, note: "environment not found on read-back" };
      if (env.Status !== "Ready") return { ok: null, note: `environment ${env.Status}` };
      const f = await environmentFacts(eb, env);
      const [option, value] = Object.entries(p.after)[0];
      const got = option === "MinSize" ? f.cfg.min : f.cfg.max;
      if (got !== Number(value)) {
        // the update did not take: the minimum the executor remembers setting is the one still there, not a person's
        if ((p.facts.window || p.facts.pattern) && option === "MinSize" && got === Number(p.before.MinSize)) { const s = envState(p.resource); if (s && s.last_set === Number(value)) saveEnvState(p.resource, { ...s, last_set: got, hand_set_at: null }); }
        return { ok: false, note: `${option} reads ${got}` };
      }
      const group = f.asg ? (await as.send(new DescribeAutoScalingGroupsCommand({ AutoScalingGroupNames: [f.asg] }))).AutoScalingGroups?.[0] : null;
      const live = group ? (option === "MinSize" ? group.MinSize : group.MaxSize) : null;
      if (group && live !== Number(value)) return { ok: null, note: `configuration says ${option} ${value}, the group still ${live}` };
      return { ok: true, note: `read back: ${option} ${value}${group ? `, desired ${group.DesiredCapacity}, ${group.Instances?.length ?? 0} in the group` : ""}` };
    } finally { eb.destroy(); as.destroy(); }
  },

  async revert(p, creds) {
    const eb = new ElasticBeanstalkClient({ region: p.region, credentials: creds.act() });
    try {
      const [option] = Object.entries(p.after)[0];
      const value = p.before[option];
      await eb.send(new UpdateEnvironmentCommand({ EnvironmentId: p.resource, OptionSettings: [{ Namespace: ASG_NAMESPACE, OptionName: option, Value: String(value) }] }));
      if ((p.facts.window || p.facts.pattern) && option === "MinSize") { const s = envState(p.resource); if (s) saveEnvState(p.resource, { ...s, last_set: Number(value), hand_set_at: null }); }
      return `${option} back to ${value}`;
    } finally { eb.destroy(); }
  },
};

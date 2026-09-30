/**
 * What an Elastic Beanstalk group needed, hour by hour, from everything it did: CPU, memory, requests, network in
 * and out, disk, and how the balancer answered.
 *
 * The learned week (src/capacity_pattern.ts) used to learn the desired capacity the group's trigger asked for.
 * That can never come down: the trigger cannot ask for less than the MinSize in force, so a group held at 6 for a
 * month learns 6 for every hour. This module asks instead how many members each hour would have needed to run
 * at the targets a person set, one estimate per signal, and takes the largest:
 *
 *  - **CPU** spreads over the members: `ceil(members × cpu / ACT_EB_TARGET_CPU)`.
 *  - **Memory** spreads only above the members' idle footprint (the 5th percentile of the group's memory over
 *    the window, what the app and the agents hold with no load): `ceil(members × (mem − idle) / (target − idle))`.
 *    A footprint within ten points of the target leaves nothing to spread, and the hour keeps its members.
 *  - **Requests** and **network in / out** have no percentage to aim at, so their capacity per member is learned:
 *    the p95 of the per-member rate over the healthy hours (CPU and memory under target, latency and 5xx normal).
 *    The group is never assumed to serve more per member than it has been seen to serve well; as quiet hours run
 *    on fewer members the proven rate rises by itself.
 *  - **Disk** does not spread (another member does not empty this one's disk) but fewer members concentrate what
 *    fills it: an hour whose fullest member disk is at or above `ACT_EB_HIGH_DISK` keeps the members it ran.
 *  - **Health**: an hour whose latency ran over twice the healthy median, or whose 5xx were 1 % of requests or
 *    more, was not proven fine at what it ran and keeps its members too.
 *  - An hour with no signal at all falls back to the members the trigger ran (the old behaviour).
 *
 * Sources: CPU and network from AWS/EC2 by AutoScalingGroupName; requests, TargetResponseTime and
 * HTTPCode_Target_5XX_Count from the environment's application load balancer; memory and disk from the
 * CloudWatch agent (CWAgent mem_used_percent, disk_used_percent, by the group or by its members) and, failing
 * that, from the probe history of the members (instance_metrics). The model is pure; the fetch is below it.
 */
import { CloudWatchClient, GetMetricDataCommand, type MetricDataQuery } from "@aws-sdk/client-cloudwatch";
import { db } from "./db.js";

const H = 3600000;
const hourOf = (t: number) => Math.floor(t / H) * H;

export type SignalName = "cpu" | "memory" | "requests" | "network_in" | "network_out" | "disk" | "health" | "trigger";
export const SIGNAL_ORDER: SignalName[] = ["cpu", "memory", "requests", "network_in", "network_out", "disk", "health", "trigger"];
export const SIGNAL_LABEL: Record<SignalName, string> = { cpu: "CPU", memory: "memory", requests: "requests", network_in: "network in", network_out: "network out", disk: "disk", health: "latency / 5xx", trigger: "the trigger (no signal)" };

/** One hour of the group: members running (the trigger's desired capacity) and what they did. Rates are hourly totals for the group; percentages are member averages (disk: the fullest member). */
export interface SignalHour {
  at: number; desired: number;
  cpu?: number | null; mem?: number | null; disk?: number | null;
  requests?: number | null; net_in?: number | null; net_out?: number | null;
  latency?: number | null; errors_5xx?: number | null;
}
export interface SignalTargets { cpu: number; mem: number; disk: number }
export interface SignalModel {
  /** the members' memory with no load (p5 over the window), when memory is known */ mem_idle: number | null;
  /** proven hourly capacity per member (p95 over healthy hours), null when too few healthy hours */
  requests_per_member: number | null; net_in_per_member: number | null; net_out_per_member: number | null;
  /** median latency (s) over the hours with requests */ latency_median: number | null;
  healthy_hours: number;
  /** share of the hours with each signal */ coverage: Partial<Record<SignalName, number>>;
}
export interface HourNeed { at: number; desired: number; need: number; binding: SignalName; by: Partial<Record<SignalName, number>> }

/** Fewer healthy hours than this and a learned per-member capacity is not trusted. */
export const MIN_HEALTHY_HOURS = 24;
/** Memory whose idle footprint is this close to the target has nothing left to spread. */
export const MEM_SPREAD_MIN = 10;
export const LATENCY_FACTOR = 2;
export const ERROR_SHARE = 0.01;

const pct = (xs: number[], q: number) => { if (!xs.length) return null; const s = [...xs].sort((a, b) => a - b); return s[Math.min(s.length - 1, Math.floor(q * (s.length - 1)))]; };
const known = (v: number | null | undefined): v is number => v != null && Number.isFinite(v);
const up = (x: number) => Math.ceil(x - 1e-9);

function unhealthy(h: SignalHour, latencyMedian: number | null): string | null {
  if (known(h.latency) && latencyMedian != null && latencyMedian > 0 && h.latency > LATENCY_FACTOR * latencyMedian) return "latency";
  if (known(h.errors_5xx) && known(h.requests) && h.requests > 0 && h.errors_5xx / h.requests >= ERROR_SHARE) return "5xx";
  return null;
}

/** The model the hours are sized with: idle memory, proven per-member rates, the healthy latency. Pure. */
export function signalModel(hours: SignalHour[], t: SignalTargets): SignalModel {
  const n = hours.length || 1;
  const cov = (f: (h: SignalHour) => unknown) => Math.round((hours.filter((h) => known(f(h) as any)).length / n) * 100) / 100;
  const coverage: SignalModel["coverage"] = { cpu: cov((h) => h.cpu), memory: cov((h) => h.mem), requests: cov((h) => h.requests), network_in: cov((h) => h.net_in), network_out: cov((h) => h.net_out), disk: cov((h) => h.disk), health: cov((h) => h.latency) };
  const mems = hours.map((h) => h.mem).filter(known);
  const mem_idle = mems.length >= MIN_HEALTHY_HOURS ? pct(mems, 0.05) : null;
  const latency_median = pct(hours.filter((h) => known(h.latency) && known(h.requests) && h.requests! > 0).map((h) => h.latency!), 0.5);
  const healthy = hours.filter((h) => h.desired > 0 && known(h.cpu) && h.cpu < t.cpu && (!known(h.mem) || h.mem < t.mem) && !unhealthy(h, latency_median));
  const rate = (f: (h: SignalHour) => number | null | undefined) => {
    const xs = healthy.filter((h) => known(f(h)) && f(h)! > 0).map((h) => f(h)! / h.desired);
    return xs.length >= MIN_HEALTHY_HOURS ? pct(xs, 0.95) : null;
  };
  return { mem_idle, requests_per_member: rate((h) => h.requests), net_in_per_member: rate((h) => h.net_in), net_out_per_member: rate((h) => h.net_out), latency_median, healthy_hours: healthy.length, coverage };
}

/** Members each hour needed, and the signal that said so. Pure. */
export function needByHour(hours: SignalHour[], t: SignalTargets, model = signalModel(hours, t)): HourNeed[] {
  return hours.map((h) => {
    const d = Math.max(0, h.desired);
    const by: Partial<Record<SignalName, number>> = {};
    if (known(h.cpu)) by.cpu = up((d * h.cpu) / t.cpu);
    if (known(h.mem) && model.mem_idle != null) {
      const room = t.mem - model.mem_idle;
      by.memory = room < MEM_SPREAD_MIN ? d : h.mem <= model.mem_idle ? 1 : up((d * (h.mem - model.mem_idle)) / room);
    }
    if (known(h.requests) && model.requests_per_member) by.requests = up(h.requests / model.requests_per_member);
    if (known(h.net_in) && model.net_in_per_member) by.network_in = up(h.net_in / model.net_in_per_member);
    if (known(h.net_out) && model.net_out_per_member) by.network_out = up(h.net_out / model.net_out_per_member);
    if (known(h.disk) && h.disk >= t.disk) by.disk = d;
    if (unhealthy(h, model.latency_median)) by.health = d;
    if (!Object.keys(by).length) by.trigger = d;
    const have = SIGNAL_ORDER.filter((s) => by[s] != null);
    const need = Math.max(1, ...have.map((s) => by[s]!));
    // on a tie a hold (disk, health) names the hour: it is the reason the hour did not come down
    const binding = (["disk", "health"] as SignalName[]).find((s) => by[s] === need) ?? have.find((s) => by[s] === need) ?? have[0] ?? "trigger";
    return { at: h.at, desired: d, need, binding, by };
  });
}

/** "CPU 100 %, memory 96 % (CloudWatch agent), requests 100 %, …": which signals the model had. Pure. */
export function describeSignals(m: SignalModel, sources: Partial<Record<SignalName, string>>): string {
  return (["cpu", "memory", "disk", "requests", "network_in", "network_out", "health"] as SignalName[]).map((s) => {
    const c = m.coverage[s] ?? 0;
    return c > 0 ? `${SIGNAL_LABEL[s]} ${Math.round(c * 100)} %${sources[s] ? ` (${sources[s]})` : ""}` : `${SIGNAL_LABEL[s]} none`;
  }).join(", ");
}

// ---- the fetch -----------------------------------------------------------------------------------------------------

export interface GroupSignals { hours: Map<number, Omit<SignalHour, "at" | "desired">>; sources: Partial<Record<SignalName, string>>; notes: string[] }

/** The group's members over the window, current and gone, from the inventory (pool = the group's name). */
export function groupMembers(asg: string, days: number): string[] {
  return (db.prepare("select instance_id from inventory_ec2 where pool = ? and datetime(last_seen) > datetime('now', ?) order by last_seen desc limit 40").all(asg, `-${days} days`) as { instance_id: string }[]).map((r) => r.instance_id);
}

const quote = (v: string) => `"${v.replace(/["\\]/g, "")}"`;

async function metricData(cw: CloudWatchClient, queries: MetricDataQuery[], start: number, end: number): Promise<Map<string, Map<number, number>>> {
  const out = new Map<string, Map<number, number>>();
  for (let i = 0; i < queries.length; i += 100) {
    let NextToken: string | undefined;
    do {
      const r = await cw.send(new GetMetricDataCommand({ StartTime: new Date(start), EndTime: new Date(end), ScanBy: "TimestampAscending", NextToken, MetricDataQueries: queries.slice(i, i + 100) }));
      for (const m of r.MetricDataResults ?? []) {
        const per = out.get(m.Id!) ?? new Map<number, number>(); out.set(m.Id!, per);
        (m.Values ?? []).forEach((v, j) => { const ts = m.Timestamps?.[j]; if (ts) per.set(hourOf(new Date(ts).getTime()), v); });
      }
      NextToken = r.NextToken;
    } while (NextToken);
  }
  return out;
}

/** Memory and disk per hour from the members' probes: the average memory across members, the fullest disk. */
export function probeSignals(members: string[], since: number): Map<number, { mem?: number; disk?: number }> {
  const out = new Map<number, { memSum: number; memN: number; disk: number | null }>();
  if (!members.length) return new Map();
  const rows = db.prepare(`select instance_id, collected_at, json from instance_metrics where instance_id in (${members.map(() => "?").join(",")}) and datetime(collected_at) > datetime(?)`).all(...members, new Date(since).toISOString()) as { collected_at: string; json: string }[];
  for (const r of rows) {
    let p: any; try { p = JSON.parse(r.json); } catch { continue; }
    const at = hourOf(new Date(r.collected_at.replace(" ", "T") + (/[zZ]|[+-]\d\d:?\d\d$/.test(r.collected_at) ? "" : "Z")).getTime());
    if (!Number.isFinite(at)) continue;
    const e = out.get(at) ?? { memSum: 0, memN: 0, disk: null }; out.set(at, e);
    const tot = Number(p?.memory?.total_bytes), used = Number(p?.memory?.used_bytes);
    if (tot > 0 && Number.isFinite(used)) { e.memSum += (100 * used) / tot; e.memN++; }
    for (const d of Array.isArray(p?.disks) ? p.disks : []) { const u = Number(d?.used_pct); if (Number.isFinite(u)) e.disk = Math.max(e.disk ?? 0, u); }
  }
  const res = new Map<number, { mem?: number; disk?: number }>();
  for (const [at, e] of out) res.set(at, { ...(e.memN ? { mem: e.memSum / e.memN } : {}), ...(e.disk != null ? { disk: e.disk } : {}) });
  return res;
}

/**
 * Every signal of the group by the hour over `days`: one GetMetricData round for the group and its balancers,
 * the CloudWatch agent searched by the group and then by its members, the probes for whatever the agent lacks.
 */
export async function groupSignalsByHour(cw: CloudWatchClient, o: { asg: string; lb_dimensions: string[]; now: number; days: number }): Promise<GroupSignals> {
  const end = hourOf(o.now), start = end - o.days * 86400000;
  const asgDim = [{ Name: "AutoScalingGroupName", Value: o.asg }];
  const q: MetricDataQuery[] = [
    { Id: "cpu", MetricStat: { Metric: { Namespace: "AWS/EC2", MetricName: "CPUUtilization", Dimensions: asgDim }, Period: 3600, Stat: "Average" } },
    { Id: "net_in", MetricStat: { Metric: { Namespace: "AWS/EC2", MetricName: "NetworkIn", Dimensions: asgDim }, Period: 3600, Stat: "Sum" } },
    { Id: "net_out", MetricStat: { Metric: { Namespace: "AWS/EC2", MetricName: "NetworkOut", Dimensions: asgDim }, Period: 3600, Stat: "Sum" } },
  ];
  o.lb_dimensions.forEach((lb, k) => {
    const dims = [{ Name: "LoadBalancer", Value: lb }];
    q.push({ Id: `req${k}`, MetricStat: { Metric: { Namespace: "AWS/ApplicationELB", MetricName: "RequestCount", Dimensions: dims }, Period: 3600, Stat: "Sum" } });
    q.push({ Id: `lat${k}`, MetricStat: { Metric: { Namespace: "AWS/ApplicationELB", MetricName: "TargetResponseTime", Dimensions: dims }, Period: 3600, Stat: "Average" } });
    q.push({ Id: `err${k}`, MetricStat: { Metric: { Namespace: "AWS/ApplicationELB", MetricName: "HTTPCode_Target_5XX_Count", Dimensions: dims }, Period: 3600, Stat: "Sum" } });
  });
  const data = await metricData(cw, q, start, end);
  const notes: string[] = []; const sources: GroupSignals["sources"] = { cpu: "CloudWatch", network_in: "CloudWatch", network_out: "CloudWatch" };
  const hours = new Map<number, Omit<SignalHour, "at" | "desired">>();
  const put = (id: string, key: keyof Omit<SignalHour, "at" | "desired">, add = false) => {
    for (const [at, v] of data.get(id) ?? []) { const e = hours.get(at) ?? {}; e[key] = add && e[key] != null ? (e[key] as number) + v : v; hours.set(at, e); }
  };
  put("cpu", "cpu"); put("net_in", "net_in"); put("net_out", "net_out");
  o.lb_dimensions.forEach((_, k) => { put(`req${k}`, "requests", true); put(`err${k}`, "errors_5xx", true); put(`lat${k}`, "latency"); });
  if (o.lb_dimensions.length) { sources.requests = "load balancer"; sources.health = "load balancer"; }
  else notes.push("no application load balancer on the environment: requests, latency and 5xx do not size the hours");

  // memory and disk: the CloudWatch agent by the group, else by its members, else the probes
  const members = groupMembers(o.asg, o.days);
  const agent = async (filter: string) => {
    const r = await metricData(cw, [
      { Id: "mem", Expression: `AVG(SEARCH('Namespace="CWAgent" MetricName="mem_used_percent" ${filter}', 'Average', 3600))`, Period: 3600 },
      { Id: "disk", Expression: `MAX(SEARCH('Namespace="CWAgent" MetricName="disk_used_percent" ${filter}', 'Maximum', 3600))`, Period: 3600 },
    ], start, end);
    return { mem: r.get("mem") ?? new Map(), disk: r.get("disk") ?? new Map() };
  };
  let cwa = { mem: new Map<number, number>(), disk: new Map<number, number>() };
  try {
    cwa = await agent(`AutoScalingGroupName=${quote(o.asg)}`);
    if (!cwa.mem.size && !cwa.disk.size && members.length) cwa = await agent(`(${members.slice(0, 20).map((m) => `InstanceId=${quote(m)}`).join(" OR ")})`);
  } catch (e: any) { notes.push(`CloudWatch agent search failed: ${String(e?.message || e).slice(0, 120)}`); }
  for (const [at, v] of cwa.mem) { const e = hours.get(at) ?? {}; e.mem = v; hours.set(at, e); }
  for (const [at, v] of cwa.disk) { const e = hours.get(at) ?? {}; e.disk = v; hours.set(at, e); }
  if (cwa.mem.size) sources.memory = "CloudWatch agent";
  if (cwa.disk.size) sources.disk = "CloudWatch agent";
  if (!cwa.mem.size || !cwa.disk.size) {
    const probes = probeSignals(members, start);
    let mem = 0, disk = 0;
    for (const [at, p] of probes) {
      if (at < start || at >= end) continue;
      const e = hours.get(at) ?? {};
      if (!cwa.mem.size && p.mem != null) { e.mem = p.mem; mem++; }
      if (!cwa.disk.size && p.disk != null) { e.disk = p.disk; disk++; }
      hours.set(at, e);
    }
    if (mem) sources.memory = "probes"; if (disk) sources.disk = "probes";
    if (!cwa.mem.size && !mem) notes.push("no memory for the members (no CloudWatch agent mem_used_percent, no probes): memory does not size the hours; install the agent or set Probe scope to all");
    if (!cwa.disk.size && !disk) notes.push("no disk for the members (no CloudWatch agent disk_used_percent, no probes): disk does not hold any hour");
  }
  return { hours, sources, notes };
}

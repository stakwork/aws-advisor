/**
 * Aurora Serverless v2: move a cluster's minimum capacity with its own day.
 *
 * The load profile (src/rds_load.ts) keeps the capacity per UTC hour of day over fourteen days. Where the database
 * sits at its floor for whole stretches of the day and works in others, the executor sets the minimum to the
 * configured floor (Settings > Auto-actions) for the quiet hours and back to the minimum the owner configured
 * before the busy ones, one `ModifyDBCluster` at a time, fifteen minutes before the hour. The maximum is never
 * touched and the minimum never leaves the band [floor, owner's minimum]: when the owner raises or lowers their
 * minimum, that becomes the new band. A cluster tagged `advisor:hands-off`, one without a profile, one that never
 * idles, or one whose bursts come every hour is left alone and the plan says why.
 *
 * Why it is worth doing: the minimum is what the cluster bills for while idle (0.12 USD per ACU-hour). Nobody
 * retunes it by hand every evening and every morning; the executor does, from the last two weeks of the curve.
 */
import { CloudWatchClient, GetMetricDataCommand } from "@aws-sdk/client-cloudwatch";
import { DescribeDBClustersCommand, ModifyDBClusterCommand, RDSClient } from "@aws-sdk/client-rds";
import { db, getJsonSetting, setSetting } from "../db.js";
import { config } from "../config.js";
import { latestRdsLoad, type HourProfile } from "../rds_load.js";
import { ACU_USD_HOUR, type ActionModule, type Creds, type Proposal } from "../executor.js";

export const KIND = "acu_window" as const;
/** Above the floor by this much in an hour's p95 and the hour counts as working. */
export const WORKING_MARGIN_ACU = 0.25;
/** A cluster needs at least this many quiet hours a day to be worth scheduling. */
export const MIN_QUIET_HOURS = 4;
/** A profile older than this is not trusted to schedule from (the hourly probe pass refreshes it). */
export const MAX_PROFILE_AGE_HOURS = 30;

export interface ClusterState { baseline_min: number; last_set: number | null; since: string }
const stateKey = (cluster: string) => `act:acu:${cluster}`;
export const clusterState = (cluster: string) => getJsonSetting<ClusterState | null>(stateKey(cluster), null);
export const saveClusterState = (cluster: string, s: ClusterState) => setSetting(stateKey(cluster), JSON.stringify(s));

export interface AcuDecisionInput {
  cluster: string;
  by_hour: HourProfile;
  /** The minimum configured on the cluster right now. */
  current_min: number;
  current_max: number;
  /** The band the executor moves within. */
  floor: number;
  baseline_min: number;
  /** The last minimum the executor set, null before it ever did. */
  last_set: number | null;
  /** Average capacity over the last fifteen minutes, null when unknown. */
  acu_now: number | null;
  cadence: "hourly" | "daily" | "irregular" | null;
  /** The minute of the day (UTC) the daily bursts start at, when the cadence is daily. */
  burst_start_minute: number | null;
  /** The UTC hour the decision is for (the coming hour). */
  hour: number;
}

export interface AcuDecision {
  /** null = leave it; else the minimum to set. */
  wanted: number | null;
  /** The band after the human's own changes are accounted for. */
  baseline_min: number;
  quiet_hours: number[];
  reason: string;
}

const half = (v: number) => Math.round(v * 2) / 2;
const hh = (h: number) => `${String(h).padStart(2, "0")}:00`;

/** The hours of the day (UTC) in which the p95 of the capacity stays at the floor: the hours the minimum can drop. */
export function quietHours(by_hour: HourProfile, floor: number): number[] {
  return by_hour.p95.map((p, h) => (p <= floor + WORKING_MARGIN_ACU ? h : -1)).filter((h) => h >= 0);
}

/**
 * The pure decision: what the minimum should be for the coming hour. The band follows the owner: a current minimum
 * that is neither the floor, nor the baseline, nor what the executor set last is a human change and becomes the
 * new baseline. Lowering needs two quiet hours ahead (no flapping at a single quiet hour) and a quiet database now;
 * raising needs one working hour ahead. Hourly bursts mean the database never idles for an hour: nothing to do.
 */
export function decideAcuWindow(i: AcuDecisionInput): AcuDecision {
  let baseline = i.baseline_min;
  if (i.current_min !== i.floor && i.current_min !== baseline && i.current_min !== i.last_set) baseline = i.current_min;
  const floor = Math.min(half(i.floor), baseline);
  const quiet = quietHours(i.by_hour, floor);
  const base = { baseline_min: baseline, quiet_hours: quiet };
  if (baseline <= floor) return { ...base, wanted: null, reason: `the configured minimum (${baseline} ACU) is already at the floor` };
  if (i.cadence === "hourly") return { ...base, wanted: null, reason: "bursts every hour: the database never idles for a whole hour" };
  if (quiet.length < MIN_QUIET_HOURS) return { ...base, wanted: null, reason: `only ${quiet.length} quiet hour(s) a day in the profile (needs ${MIN_QUIET_HOURS}); the database works around the clock` };
  const isQuiet = (h: number) => quiet.includes(((h % 24) + 24) % 24) && !(i.cadence === "daily" && i.burst_start_minute != null && Math.floor(i.burst_start_minute / 60) === ((h % 24) + 24) % 24);
  const next = i.hour % 24, after = (i.hour + 1) % 24;
  if (isQuiet(next) && isQuiet(after)) {
    if (i.acu_now != null && i.acu_now > floor + WORKING_MARGIN_ACU) return { ...base, wanted: null, reason: `${hh(next)} and ${hh(after)} are usually quiet but the cluster is at ${i.acu_now} ACU right now; leaving the minimum at ${i.current_min}` };
    if (i.current_min === floor) return { ...base, wanted: null, reason: `${hh(next)} is quiet and the minimum is already at the floor (${floor} ACU)` };
    return { ...base, wanted: floor, reason: `${hh(next)} and ${hh(after)} UTC are quiet on a typical day (p95 ${i.by_hour.p95[next]} and ${i.by_hour.p95[after]} ACU over ${i.by_hour.days} days; ${quiet.length} quiet hours a day): minimum ${i.current_min} → ${floor} ACU until the next working hour` };
  }
  if (!isQuiet(next)) {
    if (i.current_min === baseline) return { ...base, wanted: null, reason: `${hh(next)} is a working hour and the minimum is at the configured ${baseline} ACU` };
    if (i.current_min > baseline) return { ...base, wanted: null, reason: `the minimum (${i.current_min} ACU) is above the configured ${baseline}; not ours to lower` };
    const why = i.cadence === "daily" && i.burst_start_minute != null && Math.floor(i.burst_start_minute / 60) === next ? `the daily burst starts around ${hh(next)}` : `p95 ${i.by_hour.p95[next]} ACU at ${hh(next)} over ${i.by_hour.days} days`;
    return { ...base, wanted: baseline, reason: `${hh(next)} UTC is a working hour (${why}): minimum ${i.current_min} → ${baseline} ACU before it starts` };
  }
  return { ...base, wanted: null, reason: `${hh(next)} is quiet but ${hh(after)} is not; not worth a change for one hour` };
}

/** What a quiet-hour floor saves per month: the band times the quiet hours, at the ACU-hour price. */
export const acuWindowSaving = (baseline: number, floor: number, quietHoursPerDay: number) => Math.round((baseline - floor) * ACU_USD_HOUR * quietHoursPerDay * 30.4 * 100) / 100;

const clients = (creds: Creds, region: string) => ({
  rds: new RDSClient({ region, credentials: creds.read }),
  cw: new CloudWatchClient({ region, credentials: creds.read }),
});

async function describeCluster(rds: RDSClient, id: string) {
  const r = await rds.send(new DescribeDBClustersCommand({ DBClusterIdentifier: id }));
  const c = r.DBClusters?.[0];
  if (!c) return null;
  const tags: Record<string, string> = {};
  for (const t of c.TagList ?? []) if (t.Key) tags[t.Key] = t.Value ?? "";
  return { status: c.Status ?? "unknown", min: c.ServerlessV2ScalingConfiguration?.MinCapacity ?? null, max: c.ServerlessV2ScalingConfiguration?.MaxCapacity ?? null, tags, arn: c.DBClusterArn ?? null };
}

async function acuNow(cw: CloudWatchClient, cluster: string, now = Date.now()): Promise<number | null> {
  try {
    const r = await cw.send(new GetMetricDataCommand({
      StartTime: new Date(now - 20 * 60000), EndTime: new Date(now), ScanBy: "TimestampDescending",
      MetricDataQueries: [{ Id: "acu", MetricStat: { Metric: { Namespace: "AWS/RDS", MetricName: "ServerlessDatabaseCapacity", Dimensions: [{ Name: "DBClusterIdentifier", Value: cluster }] }, Period: 300, Stat: "Average" }, ReturnData: true }],
    }));
    const vs = (r.MetricDataResults?.[0]?.Values ?? []).slice(0, 3);
    return vs.length ? Math.round((vs.reduce((a, b) => a + b, 0) / vs.length) * 100) / 100 : null;
  } catch { return null; }
}

/** Every Serverless v2 cluster the inventory knows, once. */
function serverlessClusters(): { cluster: string; region: string }[] {
  const rows = db.prepare("select cluster, region from inventory_rds where gone = 0 and class = 'db.serverless' and cluster is not null group by cluster order by cluster").all() as { cluster: string; region: string }[];
  return rows;
}

export const acuWindowAction: ActionModule = {
  kind: KIND,
  label: "Serverless v2 minimum capacity by hour of day",

  async plan(creds, log) {
    const proposals: Proposal[] = []; const notes: string[] = [];
    const targets = serverlessClusters();
    if (!targets.length) { notes.push("no Aurora Serverless v2 cluster in the inventory"); return { proposals, notes }; }
    const floor = Math.max(0.5, half(config.actAcuFloor));
    const hour = (new Date().getUTCHours() + 1) % 24;
    for (const t of targets) {
      const skip = (why: string) => { notes.push(`${t.cluster}: ${why}`); log(`${t.cluster}: ${why}`); };
      const load = latestRdsLoad(t.cluster);
      const cap = load?.profile?.capacity;
      if (!load || !cap) { skip("no load profile yet (the probe pass collects it)"); continue; }
      const ageH = (Date.now() - new Date(load.collected_at.endsWith("Z") ? load.collected_at : load.collected_at + "Z").getTime()) / 3600000;
      if (ageH > MAX_PROFILE_AGE_HOURS) { skip(`load profile is ${Math.round(ageH)} h old; waiting for a fresh one`); continue; }
      if (!cap.by_hour) { skip(`fewer than seven days of capacity data (${load.profile.window_days}-day window not filled yet)`); continue; }
      const { rds, cw } = clients(creds, t.region);
      let live: Awaited<ReturnType<typeof describeCluster>>;
      try { live = await describeCluster(rds, t.cluster); } finally { rds.destroy(); }
      if (!live) { skip("cluster not found by DescribeDBClusters"); continue; }
      if (live.min == null || live.max == null) { skip("no Serverless v2 scaling configuration on the cluster"); continue; }
      if ("advisor:hands-off" in live.tags) { skip("tagged advisor:hands-off"); continue; }
      if (live.status !== "available") { skip(`cluster is ${live.status}`); continue; }
      const state = clusterState(t.cluster) ?? { baseline_min: live.min, last_set: null, since: new Date().toISOString() };
      const now = await acuNow(cw, t.cluster); cw.destroy();
      const d = decideAcuWindow({ cluster: t.cluster, by_hour: cap.by_hour, current_min: live.min, current_max: live.max, floor, baseline_min: state.baseline_min, last_set: state.last_set, acu_now: now, cadence: cap.bursts.cadence, burst_start_minute: cap.bursts.top_start_minute, hour });
      if (d.baseline_min !== state.baseline_min || !clusterState(t.cluster)) saveClusterState(t.cluster, { ...state, baseline_min: d.baseline_min, since: new Date().toISOString() });
      if (d.wanted == null) { skip(d.reason); continue; }
      const lowering = d.wanted < live.min;
      proposals.push({
        kind: KIND, resource: t.cluster, resource_name: t.cluster, region: t.region,
        dedupe: `${KIND}:${t.cluster}:${d.wanted}`,
        title: `${t.cluster}: minimum capacity ${live.min} → ${d.wanted} ACU${lowering ? " for the quiet hours" : " before the working hours"}`,
        reason: d.reason,
        before: { min_acu: live.min, max_acu: live.max }, after: { min_acu: d.wanted, max_acu: live.max },
        facts: { hour_utc: hour, quiet_hours: d.quiet_hours, baseline_min: d.baseline_min, floor, acu_now: now, p95_by_hour: cap.by_hour.p95, profile_days: cap.by_hour.days, cadence: cap.bursts.cadence, burst_start_minute: cap.bursts.top_start_minute, profile_at: load.collected_at },
        rollback: `set the minimum capacity back to ${live.min} ACU (the maximum stays ${live.max})`,
        est_usd_month: lowering ? acuWindowSaving(d.baseline_min, d.wanted, d.quiet_hours.length) : null,
      });
    }
    return { proposals, notes };
  },

  async apply(p, creds) {
    const rds = new RDSClient({ region: p.region, credentials: creds.act() });
    try {
      const min = Number(p.after.min_acu), max = Number(p.after.max_acu);
      await rds.send(new ModifyDBClusterCommand({ DBClusterIdentifier: p.resource, ServerlessV2ScalingConfiguration: { MinCapacity: min, MaxCapacity: max }, ApplyImmediately: true }));
      const state = clusterState(p.resource) ?? { baseline_min: Number(p.facts.baseline_min ?? p.before.min_acu), last_set: null, since: new Date().toISOString() };
      saveClusterState(p.resource, { ...state, last_set: min });
      return `ModifyDBCluster: minimum ${p.before.min_acu} → ${min} ACU, maximum ${max}, applied immediately`;
    } finally { rds.destroy(); }
  },

  async verify(p, creds) {
    await new Promise((r) => setTimeout(r, 5000));
    const rds = new RDSClient({ region: p.region, credentials: creds.read });
    try {
      const live = await describeCluster(rds, p.resource);
      if (!live) return { ok: false, note: "cluster not found on read-back" };
      const want = Number(p.after.min_acu);
      if (live.min === want) return { ok: true, note: `read back: minimum ${live.min} ACU, maximum ${live.max}, status ${live.status}` };
      if (live.status !== "available") return { ok: null, note: `cluster is ${live.status}; minimum reads ${live.min}, expected ${want}` };
      return { ok: false, note: `minimum reads ${live.min} ACU, expected ${want}` };
    } finally { rds.destroy(); }
  },

  async revert(p, creds) {
    const rds = new RDSClient({ region: p.region, credentials: creds.act() });
    try {
      const min = Number(p.before.min_acu), max = Number(p.before.max_acu);
      await rds.send(new ModifyDBClusterCommand({ DBClusterIdentifier: p.resource, ServerlessV2ScalingConfiguration: { MinCapacity: min, MaxCapacity: max }, ApplyImmediately: true }));
      const state = clusterState(p.resource);
      if (state) saveClusterState(p.resource, { ...state, last_set: min });
      return `minimum back to ${min} ACU`;
    } finally { rds.destroy(); }
  },
};

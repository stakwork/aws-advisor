/**
 * Parking idle swarms: stop, never terminate (docs/park-swarms-plan.md). A customer swarm is one EC2 box running
 * a stack of containers; when nobody has used it for ACT_PARK_IDLE_DAYS consecutive days the executor stops the
 * instance, and Revert (or "wake" in the chat) starts it again. Nothing else is touched: the volumes and the
 * data stay, the Elastic IP keeps the address, the saving is the instance hours.
 *
 * "Used" comes from the probe's daily roll-ups (instance_daily, container_daily: src/history.ts): the last use
 * signal (a signal line in a container log after the use-signal rules, a front-door request, a login, an
 * external connection), connections and requests per day, bytes out per day and container CPU. Every signal
 * must be quiet for the whole window; a signal that is missing (no probe that day, no front-door log, no
 * activity section) counts as alive, never as idle: the failure mode is "kept running", not "stopped by mistake".
 *
 * Scope is opt-in: only an instance tagged advisor:park=auto can be stopped, and the actuator policy says the
 * same (the condition on StopInstances). Swarm-named instances that would qualify but are not tagged are listed
 * in the pass notes so the tag can be added knowingly. A proposal is announced in the Sphinx chat when first
 * made and the pass waits ACT_PARK_GRACE_HOURS before stopping, so anyone can object; a swarm parked or woken
 * in the last 48 hours waits, and one woken twice in a week is left alone (somebody uses it irregularly).
 */
import { CreateTagsCommand, DeleteTagsCommand, DescribeAddressesCommand, DescribeInstancesCommand, EC2Client, StartInstancesCommand, StopInstancesCommand, type Instance } from "@aws-sdk/client-ec2";
import { db } from "../db.js";
import { config } from "../config.js";
import { approvedRecs, type ActionModule, type Creds, type Proposal } from "../executor.js";

export const KIND = "swarm_park" as const;
export const PARK_TAG = "advisor:park";
export const PARKED_TAG = "advisor:parked";
export const COOLDOWN_HOURS = 48;
export const FLAP_WAKES_PER_WEEK = 2;
export const MAX_NET_BYTES_DAY = 50e6;
export const MAX_CONTAINER_CPU_AVG = 1;
export const MAX_CONTAINER_CPU_MAX = 5;
const SWARM_NAME = /swarm/i;

export interface DayUse {
  day: string; samples: number; last_use_at: string | null;
  external_connections_max: number | null; requests_24h_avg: number | null; signal_lines_24h_avg: number | null; net_bytes_day: number | null;
  /** Over the day's containers: the highest average CPU and the highest peak; null when no container row exists. */
  container_cpu_avg_max: number | null; container_cpu_max: number | null;
}
export interface Verdict { idle: boolean; reasons: string[]; days_seen: number; probes: number; last_use_at: string | null; window_start: string }

/** Idle only when every signal was quiet on every day of the window and the probe was there to see it. */
export function idleVerdict(days: DayUse[], opts: { idleDays: number; minProbes: number; now?: Date }): Verdict {
  const now = opts.now ?? new Date();
  const windowStart = new Date(now.getTime() - opts.idleDays * 86400000).toISOString();
  const startDay = windowStart.slice(0, 10);
  const inWindow = days.filter((d) => d.day >= startDay && d.samples > 0);
  const reasons: string[] = [];
  const probes = inWindow.reduce((s, d) => s + d.samples, 0);
  const seen = new Set(inWindow.map((d) => d.day)).size;
  if (seen < opts.idleDays) reasons.push(`probe data for ${seen} of the last ${opts.idleDays} days`);
  if (probes < opts.minProbes) reasons.push(`${probes} probes in the window, ${opts.minProbes} needed`);
  const lastUse = inWindow.map((d) => d.last_use_at).filter((x): x is string => !!x).sort().pop() ?? null;
  if (lastUse && lastUse >= windowStart) reasons.push(`last use ${lastUse.slice(0, 16).replace("T", " ")} UTC`);
  const bad = (label: string, f: (d: DayUse) => boolean) => { const n = inWindow.filter(f).length; if (n) reasons.push(`${label} on ${n} day(s)`); };
  bad("external connections seen or unknown", (d) => d.external_connections_max == null || d.external_connections_max > 0);
  bad("front-door requests seen or no access log", (d) => d.requests_24h_avg == null || d.requests_24h_avg > 0);
  bad("use-signal lines in container logs or none counted", (d) => d.signal_lines_24h_avg == null || d.signal_lines_24h_avg > 0);
  bad(`more than ${Math.round(MAX_NET_BYTES_DAY / 1e6)} MB/day out, or unknown`, (d) => d.net_bytes_day == null || d.net_bytes_day > MAX_NET_BYTES_DAY);
  bad("container CPU above the idle band, or no container stats", (d) => d.container_cpu_avg_max == null || d.container_cpu_max == null || d.container_cpu_avg_max >= MAX_CONTAINER_CPU_AVG || d.container_cpu_max >= MAX_CONTAINER_CPU_MAX);
  return { idle: reasons.length === 0, reasons, days_seen: seen, probes, last_use_at: lastUse, window_start: windowStart };
}

function dayUse(instanceId: string, idleDays: number): DayUse[] {
  return db.prepare(`select i.day, i.samples, i.last_use_at, i.external_connections_max, i.requests_24h_avg, i.signal_lines_24h_avg, i.net_bytes_day,
      (select max(c.cpu_pct_avg) from container_daily c where c.instance_id = i.instance_id and c.day = i.day) as container_cpu_avg_max,
      (select max(c.cpu_pct_max) from container_daily c where c.instance_id = i.instance_id and c.day = i.day) as container_cpu_max
    from instance_daily i where i.instance_id = ? and i.day >= date('now', ?) order by i.day`).all(instanceId, `-${idleDays + 1} days`) as DayUse[];
}

const tag = (i: Instance, key: string) => i.Tags?.find((t) => t.Key === key)?.Value ?? null;
const hours = (iso: string | null) => (iso ? (Date.now() - new Date(iso.includes("T") ? iso : iso.replace(" ", "T") + "Z").getTime()) / 3600000 : Infinity);

export const swarmParkAction: ActionModule = {
  kind: KIND,
  label: "Idle swarms parked (stopped, never terminated)",
  grace_hours: () => config.actParkGraceHours,
  announce: true,

  async plan(creds, log) {
    const proposals: Proposal[] = []; const notes: string[] = [];
    const idleDays = Math.max(2, Math.round(config.actParkIdleDays));
    const minProbes = Math.max(5, idleDays);
    const rows = db.prepare("select instance_id, name, instance_type, region, monthly_usd, pool_kind from inventory_ec2 where gone = 0 and state = 'running' order by name").all() as { instance_id: string; name: string | null; instance_type: string | null; region: string | null; monthly_usd: number | null; pool_kind: string | null }[];
    const byRegion = new Map<string, typeof rows>();
    for (const r of rows) { const region = r.region || creds.region; if (!byRegion.has(region)) byRegion.set(region, []); byRegion.get(region)!.push(r); }
    let tagged = 0, swarmNamed = 0;
    const aliveWhy = new Map<string, number>();
    for (const [region, list] of byRegion) {
      const ec2 = new EC2Client({ region, credentials: creds.read });
      try {
        // Tags come from EC2 itself: the opt-in tag is the scope, and the inventory does not carry tags.
        const live = new Map<string, Instance>();
        for (let i = 0; i < list.length; i += 100) {
          const r = await ec2.send(new DescribeInstancesCommand({ InstanceIds: list.slice(i, i + 100).map((x) => x.instance_id) }));
          for (const res of r.Reservations ?? []) for (const inst of res.Instances ?? []) live.set(inst.InstanceId!, inst);
        }
        const inScope = list.filter((r) => { const i = live.get(r.instance_id); return i && (tag(i, PARK_TAG) === "auto" || SWARM_NAME.test(r.name || "")); });
        if (!inScope.length) continue;
        const eips = new Set<string>();
        try { for (const a of (await ec2.send(new DescribeAddressesCommand({ Filters: [{ Name: "instance-id", Values: inScope.map((r) => r.instance_id) }] }))).Addresses ?? []) if (a.InstanceId) eips.add(a.InstanceId); }
        catch (e: any) { notes.push(`${region}: DescribeAddresses: ${String(e?.message || e).slice(0, 120)}; nothing is parked without knowing about the Elastic IPs`); continue; }
        for (const r of inScope) {
          const inst = live.get(r.instance_id)!;
          const name = r.name || r.instance_id;
          const optIn = tag(inst, PARK_TAG) === "auto";
          if (optIn) tagged++; else swarmNamed++;
          const skip = (why: string) => { notes.push(`${name}: ${why}`); log(`${name}: ${why}`); };
          const v = idleVerdict(dayUse(r.instance_id, idleDays), { idleDays, minProbes });
          if (!v.idle) {
            if (optIn) skip(`alive: ${v.reasons.join("; ")}`);
            else for (const why of v.reasons) { const k = why.replace(/ on \d+ day\(s\)$/, "").replace(/^last use .*/, "a use signal in the window").replace(/^probe data for .*/, "probe data missing for some days").replace(/^\d+ probes in the window.*/, "too few probes"); aliveWhy.set(k, (aliveWhy.get(k) ?? 0) + 1); }
            continue;
          }
          if (!optIn) { skip(`idle for ${idleDays} days${v.last_use_at ? ` (last use ${v.last_use_at.slice(0, 10)})` : ""} but not tagged ${PARK_TAG}=auto: tag it to let the executor park it`); continue; }
          if (tag(inst, PARK_TAG) === "never" || tag(inst, "advisor:hands-off") != null) { skip("tagged to be left alone"); continue; }
          if (inst.State?.Name !== "running") { skip(`state ${inst.State?.Name}`); continue; }
          if (r.pool_kind) { skip(`member of a ${r.pool_kind} pool: its controller decides`); continue; }
          if (!eips.has(r.instance_id)) { skip("no Elastic IP: a stop and start would change the public address and break what points at it"); continue; }
          const openAlert = db.prepare("select kind from alerts where resource = ? and acknowledged = 0 order by id desc limit 1").get(r.instance_id) as { kind: string } | undefined;
          if (openAlert) { skip(`an open ${openAlert.kind} alert on it`); continue; }
          const recent = db.prepare("select status, applied_at, reverted_at from actions where kind = ? and resource = ? and status in ('applied', 'verified', 'reverted') order by id desc limit 1").get(KIND, r.instance_id) as { status: string; applied_at: string | null; reverted_at: string | null } | undefined;
          if (recent && Math.min(hours(recent.applied_at), hours(recent.reverted_at)) < COOLDOWN_HOURS) { skip(`parked or woken less than ${COOLDOWN_HOURS} h ago`); continue; }
          const wakes = (db.prepare("select count(*) as n from actions where kind = ? and resource = ? and status = 'reverted' and datetime(reverted_at) > datetime('now', '-7 days')").get(KIND, r.instance_id) as { n: number }).n;
          if (wakes >= FLAP_WAKES_PER_WEEK) { skip(`woken ${wakes} times this week: somebody uses it irregularly`); continue; }
          const approved = approvedRecs(["stop_instance"]).find((a) => a.resource === r.instance_id) ?? null;
          const containers = (db.prepare("select containers_running_avg from instance_daily where instance_id = ? order by day desc limit 1").get(r.instance_id) as { containers_running_avg: number | null } | undefined)?.containers_running_avg ?? null;
          proposals.push({
            kind: KIND, resource: r.instance_id, resource_name: r.name, region,
            dedupe: `${KIND}:${r.instance_id}`,
            title: `stop ${name} (${r.instance_type || inst.InstanceType}): idle ${idleDays} days`,
            reason: `${v.last_use_at ? `last use ${v.last_use_at.slice(0, 16).replace("T", " ")} UTC` : "no use signal recorded"}; over ${v.days_seen} days and ${v.probes} probes: no external connection, no front-door request, no use-signal line in any container log, under ${Math.round(MAX_NET_BYTES_DAY / 1e6)} MB/day out, every container under ${MAX_CONTAINER_CPU_AVG} % CPU. Stop only: volumes, data and the Elastic IP stay; nothing is terminated.${approved ? ` Approved as recommendation #${approved.id}${approved.decided_by ? ` by ${approved.decided_by}` : ""}.` : ""}`,
            before: { state: "running" }, after: { state: "stopped", tag: `${PARKED_TAG}=<time>` },
            facts: { idle_days: idleDays, window_start: v.window_start, last_use_at: v.last_use_at, probes: v.probes, containers_running_avg: containers, elastic_ip: true, instance_type: r.instance_type || inst.InstanceType, recommendation_id: approved?.id ?? null },
            rollback: `start it again (Revert on the page, or "wake ${name}" in the chat); the Elastic IP keeps the address, the containers come back with the box`,
            est_usd_month: r.monthly_usd,
          });
        }
      } catch (e: any) { const m = String(e?.message || e); notes.push(`${region}: ${m.slice(0, 160)}`); log(`${region}: ${m}`); }
      finally { ec2.destroy(); }
    }
    if (!tagged && !swarmNamed) notes.push(`no running instance tagged ${PARK_TAG}=auto and none named like a swarm`);
    else if (!tagged) notes.push(`no running instance tagged ${PARK_TAG}=auto (${swarmNamed} swarm-named instance(s) watched; tag one to opt it in)`);
    if (aliveWhy.size) notes.push(`why the untagged swarm-named instances count as alive: ${[...aliveWhy.entries()].sort((a, b) => b[1] - a[1]).map(([k, n]) => `${k} (${n})`).join("; ")}`);
    return { proposals, notes };
  },

  async apply(p, creds) {
    const ec2 = new EC2Client({ region: p.region, credentials: creds.act() });
    try {
      const r = await ec2.send(new StopInstancesCommand({ InstanceIds: [p.resource] }));
      const state = r.StoppingInstances?.[0]?.CurrentState?.Name || "stopping";
      let marker = "";
      try { await ec2.send(new CreateTagsCommand({ Resources: [p.resource], Tags: [{ Key: PARKED_TAG, Value: new Date().toISOString() }] })); marker = `, tagged ${PARKED_TAG}`; }
      catch (e: any) { marker = `, tag ${PARKED_TAG} not written (${String(e?.message || e).slice(0, 80)})`; }
      return `StopInstances: ${state}${marker}`;
    } finally { ec2.destroy(); }
  },

  async verify(p, creds) {
    const ec2 = new EC2Client({ region: p.region, credentials: creds.read });
    try {
      const inst = (await ec2.send(new DescribeInstancesCommand({ InstanceIds: [p.resource] }))).Reservations?.[0]?.Instances?.[0];
      const state = inst?.State?.Name;
      if (!inst) return { ok: false, note: "instance not found on read-back" };
      if (state === "stopped") return { ok: true, note: "read back: stopped" };
      if (state === "stopping") return { ok: null, note: "still stopping" };
      return { ok: false, note: `state reads ${state}` };
    } finally { ec2.destroy(); }
  },

  async revert(p, creds) {
    const ec2 = new EC2Client({ region: p.region, credentials: creds.act() });
    try {
      const r = await ec2.send(new StartInstancesCommand({ InstanceIds: [p.resource] }));
      try { await ec2.send(new DeleteTagsCommand({ Resources: [p.resource], Tags: [{ Key: PARKED_TAG }] })); } catch { /* the marker is informational */ }
      return `StartInstances: ${r.StartingInstances?.[0]?.CurrentState?.Name || "pending"}; the Elastic IP keeps the address, containers come back with the box (a minute or two)`;
    } finally { ec2.destroy(); }
  },
};

/**
 * Office hours: instances and databases that only need to run when people do.
 *
 * A dev box, a staging database, a demo swarm: a tag `advisor:schedule` on the resource says when it should be
 * running (`weekdays 08-20`, `mon-fri 08:00-20:00 Europe/Madrid`, `daily 07-23 America/Argentina/Buenos_Aires`,
 * `mon,tue,wed 09-18`; the time zone defaults to UTC, an overnight window like `22-06` is fine). The tag is the
 * consent: no grace period, no announcement. The pass runs fifteen minutes before the hour and decides for the
 * top of the coming hour: running outside the window → stop, stopped inside it → start. EC2 instances
 * (StopInstances / StartInstances), RDS instances (StopDBInstance / StartDBInstance) and Aurora clusters
 * (StopDBCluster / StartDBCluster) are all in scope; the actuator policy allows the calls only on a resource
 * carrying the tag. Nothing is terminated and nothing else is touched.
 *
 * What a stop saves is the instance hours outside the window. A box without an Elastic IP gets a new public
 * address on start, so the stop row records the A records in the account's zones that name the old address and
 * the start points them at the new one (`route53:ChangeResourceRecordSets`, UPSERT of A records only) once the
 * instance reports its address; the row and the read-back say which names were moved. A stopped RDS instance is started by AWS after
 * seven days whatever the schedule says: the next scheduled stop takes it down again, so a weekly schedule holds.
 * A resource the executor stopped that a person then started by hand (Revert on the row, or "wake" in the chat)
 * is left running until the window closes again, so nobody fights the executor for a box they need right now.
 */
import { DescribeAddressesCommand, DescribeInstancesCommand, EC2Client, StartInstancesCommand, StopInstancesCommand, type Instance } from "@aws-sdk/client-ec2";
import { DescribeDBClustersCommand, DescribeDBInstancesCommand, RDSClient, type DescribeDBClustersCommandOutput, type DescribeDBInstancesCommandOutput, StartDBClusterCommand, StartDBInstanceCommand, StopDBClusterCommand, StopDBInstanceCommand, type DBCluster, type DBInstance } from "@aws-sdk/client-rds";
import { ChangeResourceRecordSetsCommand, ListResourceRecordSetsCommand, Route53Client, type Change, type ResourceRecordSet } from "@aws-sdk/client-route-53";
import { db } from "../db.js";
import type { ActionModule, Creds, Proposal } from "../executor.js";
import { AUTO_PARK_TAG, isOff, isOn } from "../consent.js";

export const KIND = "schedule_hours" as const;
export const SCHEDULE_TAG = "advisor:schedule";
/** A stop the executor made that a person undid this recently means "I need it now": the pass leaves it until the window closes. */
export const WOKEN_BY_HAND_HOURS = 12;
export const HOURS_PER_WEEK = 168;
/** How long a start waits for the new public address before giving up on the DNS update (the next pass does not retry; the row says so). */
export const IP_WAIT_MS = 150_000;

/** An A record that names an instance's public address, as stored by the Route 53 inventory. */
export interface DnsRecord { zone_id: string; name: string; ttl: number | null; values: string[]; routing: Record<string, unknown> | null; old_ip: string }
const jsonArr = (v: unknown): string[] => { try { const p = typeof v === "string" ? JSON.parse(v) : v; return Array.isArray(p) ? p.map(String) : []; } catch { return []; } };
const jsonObj = (v: unknown): Record<string, unknown> | null => { try { const p = typeof v === "string" ? JSON.parse(v) : v; return p && typeof p === "object" ? p : null; } catch { return null; } };
/** The A records (no alias) in the account's zones whose values carry this address. */
export function recordsNamingIp(ip: string | null | undefined): DnsRecord[] {
  if (!ip) return [];
  try {
    return (db.prepare(`select zone_id, name, ttl, "values", routing from inventory_route53_record where gone = 0 and alias = 0 and type = 'A' and "values" like ?`).all(`%"${ip}"%`) as any[])
      .map((r) => ({ zone_id: r.zone_id, name: r.name, ttl: r.ttl ?? null, values: jsonArr(r.values), routing: jsonObj(r.routing), old_ip: ip })).filter((r) => r.values.includes(ip));
  } catch { return []; }
}
/** The records to move on a start: what the last stop of this box recorded, else the A records the Route 53 links still tie to it. */
export function recordsForStart(instanceId: string): DnsRecord[] {
  const last = db.prepare("select facts_json from actions where kind = ? and resource = ? and json_extract(after_json, '$.state') = 'stopped' and status in ('applied', 'verified', 'reverted') order by id desc limit 1").get(KIND, instanceId) as { facts_json: string } | undefined;
  try { const recs = last ? JSON.parse(last.facts_json)?.dns_records : null; if (Array.isArray(recs) && recs.length) return recs; } catch { /* fall through */ }
  try {
    return (db.prepare(`select r.zone_id, r.name, r.ttl, r."values", r.routing from inventory_route53_link l join inventory_route53_record r on r.id = l.record_id where l.resource_kind = 'ec2' and l.resource_id = ? and l.hop = 1 and r.gone = 0 and r.alias = 0 and r.type = 'A'`).all(instanceId) as any[])
      .map((r) => { const values = jsonArr(r.values); return { zone_id: r.zone_id, name: r.name, ttl: r.ttl ?? null, values, routing: jsonObj(r.routing), old_ip: values.find((v) => /^\d+\.\d+\.\d+\.\d+$/.test(v)) || "" }; }).filter((r) => r.old_ip);
  } catch { return []; }
}
/** The record set an UPSERT sends: the old address swapped for the new one, the routing kept. Pure. */
export function upsertChange(r: DnsRecord, newIp: string): Change & { ResourceRecordSet: ResourceRecordSet } {
  const routing = (r.routing || {}) as Record<string, any>;
  const set: ResourceRecordSet = { Name: r.name, Type: "A", TTL: r.ttl ?? 300, ResourceRecords: [...new Set(r.values.map((v) => (v === r.old_ip ? newIp : v)))].map((Value) => ({ Value })) };
  if (routing.set_identifier) set.SetIdentifier = String(routing.set_identifier);
  if (routing.weight != null) set.Weight = Number(routing.weight);
  if (routing.failover) set.Failover = routing.failover;
  if (routing.multi_value_answer) set.MultiValueAnswer = true;
  if (routing.region) set.Region = routing.region;
  if (routing.geo_location) set.GeoLocation = routing.geo_location;
  return { Action: "UPSERT", ResourceRecordSet: set };
}

export interface Schedule { days: Set<number>; start: number; end: number; tz: string; text: string }
export type ResourceKind = "ec2" | "rds_instance" | "rds_cluster";

const DAY_INDEX: Record<string, number> = { sun: 0, mon: 1, tue: 2, wed: 3, thu: 4, fri: 5, sat: 6 };
const DAY_NAMES = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];

const validTz = (tz: string) => { try { new Intl.DateTimeFormat("en-US", { timeZone: tz }); return true; } catch { return false; } };

/** `<days> <HH[:MM]>-<HH[:MM]> [tz]`: days are `daily`, `weekdays`, `weekends`, a range `mon-fri`, or a list `mon,tue,wed`. Pure. */
export function parseSchedule(tag: string): Schedule | { error: string } {
  const text = String(tag ?? "").trim();
  const parts = text.split(/\s+/).filter(Boolean);
  if (parts.length < 2 || parts.length > 3) return { error: `"${text}": expected "<days> <HH>-<HH> [time zone]", e.g. "weekdays 08-20 Europe/Madrid"` };
  const [daysPart, hoursPart, tzPart] = parts;
  const days = new Set<number>();
  const d = daysPart.toLowerCase();
  if (d === "daily" || d === "everyday" || d === "all") for (let i = 0; i < 7; i++) days.add(i);
  else if (d === "weekdays") for (let i = 1; i <= 5; i++) days.add(i);
  else if (d === "weekends") { days.add(0); days.add(6); }
  else {
    for (const token of d.split(",")) {
      const m = token.match(/^([a-z]{3})[a-z]*(?:-([a-z]{3})[a-z]*)?$/);
      if (!m || !(m[1] in DAY_INDEX) || (m[2] && !(m[2] in DAY_INDEX))) return { error: `"${daysPart}": days are daily, weekdays, weekends, mon-fri or mon,tue,wed` };
      const from = DAY_INDEX[m[1]], to = m[2] ? DAY_INDEX[m[2]] : from;
      for (let i = from; ; i = (i + 1) % 7) { days.add(i); if (i === to) break; }
    }
  }
  const h = hoursPart.match(/^(\d{1,2})(?::(\d{2}))?-(\d{1,2})(?::(\d{2}))?$/);
  if (!h) return { error: `"${hoursPart}": hours are HH-HH on a 24-hour clock, e.g. 08-20` };
  if (h[2] && h[2] !== "00" || h[4] && h[4] !== "00") return { error: `"${hoursPart}": whole hours only (the pass runs once an hour)` };
  const start = Number(h[1]), end = Number(h[3]);
  if (start > 23 || end > 24 || (start === end)) return { error: `"${hoursPart}": start 00-23, end 01-24, and not the same hour` };
  const tz = tzPart || "UTC";
  if (!validTz(tz)) return { error: `"${tzPart}": not an IANA time zone (e.g. Europe/Madrid, America/New_York)` };
  return { days, start, end: end === 24 ? 0 : end, tz, text };
}

/** Weekday (0 = Sunday) and hour of `at` in the schedule's time zone. */
export function localClock(at: Date, tz: string): { day: number; hour: number } {
  const parts = new Intl.DateTimeFormat("en-US", { timeZone: tz, weekday: "short", hour: "numeric", hour12: false }).formatToParts(at);
  const day = DAY_INDEX[(parts.find((p) => p.type === "weekday")?.value || "sun").toLowerCase().slice(0, 3)] ?? 0;
  const hour = Number(parts.find((p) => p.type === "hour")?.value || 0) % 24;
  return { day, hour };
}

/** Whether the schedule wants the resource running at `at`. An overnight window (22-06) belongs to the day it starts on. Pure. */
export function wantedState(s: Schedule, at: Date): "running" | "stopped" {
  const { day, hour } = localClock(at, s.tz);
  if (s.start < s.end) return s.days.has(day) && hour >= s.start && hour < s.end ? "running" : "stopped";
  // overnight: the evening part belongs to today, the morning part to the day before
  if (hour >= s.start) return s.days.has(day) ? "running" : "stopped";
  if (hour < s.end) return s.days.has((day + 6) % 7) ? "running" : "stopped";
  return "stopped";
}

/** The top of the coming hour (a pass at :45 decides for :00). */
export function nextHour(now: Date): Date {
  const d = new Date(now.getTime());
  d.setUTCMinutes(0, 0, 0);
  return new Date(d.getTime() + 3600000);
}

/** Hours per week the schedule keeps the resource off: what a stop saves. Pure. */
export function offHoursPerWeek(s: Schedule): number {
  const span = s.start < s.end ? s.end - s.start : 24 - s.start + s.end;
  return HOURS_PER_WEEK - s.days.size * span;
}

export const describeSchedule = (s: Schedule) => {
  const days = s.days.size === 7 ? "daily" : [1, 2, 3, 4, 5].every((d) => s.days.has(d)) && s.days.size === 5 ? "weekdays" : [...s.days].sort().map((d) => DAY_NAMES[d]).join(",");
  const hh = (h: number) => `${String(h).padStart(2, "0")}:00`;
  return `${days} ${hh(s.start)}-${hh(s.end === 0 ? 24 : s.end)} ${s.tz}`;
};

export interface Decision { action: "stop" | "start" | null; reason: string; target: Date; wanted: "running" | "stopped" }
/** The pure decision for the coming hour from the schedule and the state now. */
export function decideSchedule(s: Schedule, currentState: string, now: Date): Decision {
  const target = nextHour(now);
  const wanted = wantedState(s, target);
  const { day, hour } = localClock(target, s.tz);
  const when = `${DAY_NAMES[day]} ${String(hour).padStart(2, "0")}:00 ${s.tz}`;
  if (currentState === "running" && wanted === "stopped") return { action: "stop", reason: `${when} is outside the schedule ${describeSchedule(s)}`, target, wanted };
  if (currentState === "stopped" && wanted === "running") return { action: "start", reason: `${when} is inside the schedule ${describeSchedule(s)}`, target, wanted };
  if (currentState !== "running" && currentState !== "stopped") return { action: null, reason: `state ${currentState}: waiting for it to settle`, target, wanted };
  return { action: null, reason: `${currentState} and ${when} wants it ${wanted}: nothing to do`, target, wanted };
}

const hourKey = (d: Date) => d.toISOString().slice(0, 13);
const tagOf = (tags: { Key?: string; Value?: string }[] | undefined, key: string) => tags?.find((t) => t.Key === key)?.Value ?? null;

/** A stop the executor made that a person reverted recently: the person wants the box now. */
function wokenByHand(resource: string): boolean {
  const r = db.prepare(`select count(*) as n from actions where kind = ? and resource = ? and status = 'reverted' and json_extract(after_json, '$.state') = 'stopped' and datetime(reverted_at) > datetime('now', ?)`)
    .get(KIND, resource, `-${WOKEN_BY_HAND_HOURS} hours`) as { n: number };
  return r.n > 0;
}

interface Target { kind: ResourceKind; resource: string; name: string | null; region: string; account_id?: string | null; state: string; tag: string; monthly_usd: number | null; elastic_ip?: boolean; public_ip?: string | null; detail: string }

function propose(t: Target, s: Schedule, d: Decision, notes: string[], log: (l: string) => void): Proposal | null {
  const name = t.name && t.name !== t.resource ? `${t.name} (${t.resource})` : t.resource;
  const skip = (why: string) => { notes.push(`${name}: ${why}`); log(`${name}: ${why}`); return null; };
  if (!d.action) return skip(d.reason);
  if (d.action === "stop" && wokenByHand(t.resource)) return skip(`woken by hand in the last ${WOKEN_BY_HAND_HOURS} h; left until the window closes`);
  const dns = t.kind === "ec2" && t.elastic_ip === false ? (d.action === "stop" ? recordsNamingIp(t.public_ip) : recordsForStart(t.resource)) : [];
  const names = [...new Set(dns.map((r) => r.name))];
  const ipNote = t.kind === "ec2" && d.action === "start" && t.elastic_ip === false ? ` No Elastic IP: the public address changes on start${names.length ? `; ${names.join(", ")} will be pointed at the new one` : "; no A record in the account's zones names the old one"}.` : t.kind === "ec2" && d.action === "stop" && t.elastic_ip === false ? ` No Elastic IP: the public address changes when it starts again${names.length ? `; the start re-points ${names.join(", ")}` : ""}.` : "";
  const rdsNote = t.kind !== "ec2" && d.action === "stop" ? " AWS starts a stopped database again after seven days; the next scheduled stop takes it down again." : "";
  const off = offHoursPerWeek(s);
  const est = d.action === "stop" && t.monthly_usd != null ? Math.round(t.monthly_usd * (off / HOURS_PER_WEEK) * 100) / 100 : null;
  const verb = d.action === "stop" ? "stop" : "start";
  const after = d.action === "stop" ? "stopped" : "running";
  return {
    kind: KIND, resource: t.resource, resource_name: t.name, region: t.region, account_id: t.account_id ?? null,
    dedupe: `${KIND}:${t.resource}:${d.action}:${hourKey(d.target)}`,
    title: `${verb} ${name} (${t.detail}): ${d.reason}`,
    reason: `Tagged ${SCHEDULE_TAG}=${s.text}. ${d.reason}; off ${off} of ${HOURS_PER_WEEK} hours a week.${ipNote}${rdsNote}`,
    before: { state: t.state }, after: { state: after },
    facts: { schedule: s.text, tz: s.tz, target_hour: d.target.toISOString(), kind: t.kind, elastic_ip: t.elastic_ip ?? null, public_ip: t.public_ip ?? null, dns_records: dns.length ? dns : null, off_hours_per_week: off, monthly_usd: t.monthly_usd },
    rollback: `the opposite call (${d.action === "stop" ? "start" : "stop"}); the next pass follows the schedule again`,
    est_usd_month: est,
  };
}

const ec2State = (i: Instance) => i.State?.Name || "unknown";
const rdsInstanceState = (i: DBInstance) => i.DBInstanceStatus || "unknown";
const rdsClusterState = (c: DBCluster) => c.Status || "unknown";

export const scheduleHoursAction: ActionModule = {
  kind: KIND,
  label: "Office-hours schedules for tagged instances and databases",

  async plan(creds, log) {
    const proposals: Proposal[] = []; const notes: string[] = [];
    const now = new Date();
    let tagged = 0;
    const consider = (t: Target) => {
      tagged++;
      const name = t.name && t.name !== t.resource ? `${t.name} (${t.resource})` : t.resource;
      const s = parseSchedule(t.tag);
      if ("error" in s) { notes.push(`${name}: tag ${SCHEDULE_TAG} not understood: ${s.error}`); log(`${name}: bad schedule tag: ${s.error}`); return; }
      const p = propose(t, s, decideSchedule(s, t.state, now), notes, log);
      if (p) proposals.push(p);
    };

    // EC2: the inventory lists the instances, EC2 itself carries the tags and the state of the moment.
    const ec2Rows = db.prepare("select instance_id, account_id, name, instance_type, region, monthly_usd, pool_kind from inventory_ec2 where gone = 0 and state in ('running', 'stopped', 'pending', 'stopping') order by name")
      .all() as { instance_id: string; account_id: string | null; name: string | null; instance_type: string | null; region: string | null; monthly_usd: number | null; pool_kind: string | null }[];
    // Grouped per (account, region): a member account's instances are read through its own credentials.
    const byRegion = new Map<string, typeof ec2Rows>();
    for (const r of ec2Rows) { const key = `${r.account_id || ""}|${r.region || creds.region}`; if (!byRegion.has(key)) byRegion.set(key, []); byRegion.get(key)!.push(r); }
    for (const [key, list] of byRegion) {
      const [account, region] = key.split("|");
      const ec2 = new EC2Client({ region, credentials: creds.forAccount(account || null).read });
      try {
        const live: Instance[] = [];
        for (let i = 0; i < list.length; i += 100) {
          const r = await ec2.send(new DescribeInstancesCommand({ InstanceIds: list.slice(i, i + 100).map((x) => x.instance_id) }));
          for (const res of r.Reservations ?? []) live.push(...(res.Instances ?? []));
        }
        const inScope = live.filter((i) => tagOf(i.Tags, SCHEDULE_TAG) != null || isOn(tagOf(i.Tags, AUTO_PARK_TAG)));
        if (!inScope.length) continue;
        const { scheduleFor } = await import("../usage_review.js");
        let eips: Set<string> | null = new Set<string>();
        try { for (const a of (await ec2.send(new DescribeAddressesCommand({ Filters: [{ Name: "instance-id", Values: inScope.map((i) => i.InstanceId!) }] }))).Addresses ?? []) if (a.InstanceId) eips.add(a.InstanceId); }
        catch { eips = null; }
        for (const inst of inScope) {
          const row = list.find((x) => x.instance_id === inst.InstanceId)!;
          const name = row.name || inst.InstanceId!;
          if (tagOf(inst.Tags, "advisor:hands-off") != null) { notes.push(`${name}: tagged advisor:hands-off`); continue; }
          if (isOff(tagOf(inst.Tags, AUTO_PARK_TAG))) { notes.push(`${name}: ${AUTO_PARK_TAG}=${tagOf(inst.Tags, AUTO_PARK_TAG)}: never stopped or started`); continue; }
          if (row.pool_kind) { notes.push(`${name}: member of a ${row.pool_kind} pool: its controller decides`); continue; }
          // the tag's own window first; with AdvisorAutoPark=ON and no window, the usage profile's confident schedule is the window
          let scheduleText = tagOf(inst.Tags, SCHEDULE_TAG);
          if (scheduleText == null) {
            const f = scheduleFor(inst.InstanceId!);
            if (!f.schedule) { notes.push(`${name}: ${AUTO_PARK_TAG}=ON, no window to follow: ${f.note}`); continue; }
            scheduleText = f.schedule;
            log(`${name}: ${AUTO_PARK_TAG}=ON, following ${f.source === "review" ? "Jev's" : "the profile's"} window ${f.schedule}`);
            tagged++;
          }
          consider({ kind: "ec2", resource: inst.InstanceId!, name: row.name, region, account_id: row.account_id ?? null, state: ec2State(inst), tag: scheduleText, monthly_usd: row.monthly_usd, elastic_ip: eips ? eips.has(inst.InstanceId!) : undefined, public_ip: inst.PublicIpAddress ?? null, detail: row.instance_type || inst.InstanceType || "ec2" });
        }
      } catch (e: any) { const m = String(e?.message || e); notes.push(`${region}: ${m.slice(0, 160)}`); log(`${region}: ${m}`); }
      finally { ec2.destroy(); }
    }

    // RDS: instances and clusters, per region the inventory knows plus the configured one.
    // Per account, per region the inventory knows plus the configured one.
    const rdsScopes = new Set<string>();
    for (const a of creds.accounts) rdsScopes.add(`${a.account_id}|${a.region}`);
    try { for (const r of db.prepare("select distinct account_id, region from inventory_rds where gone = 0 and region is not null").all() as { account_id: string | null; region: string }[]) rdsScopes.add(`${r.account_id || creds.accounts[0]?.account_id || ""}|${r.region}`); } catch { /* older inventory without a region column */ }
    for (const scope of rdsScopes) {
      const [account, region] = scope.split("|");
      const acct = creds.forAccount(account || null);
      const rds = new RDSClient({ region, credentials: acct.read });
      try {
        const instances: DBInstance[] = [];
        let marker: string | undefined;
        do { const r: DescribeDBInstancesCommandOutput = await rds.send(new DescribeDBInstancesCommand({ Marker: marker })); instances.push(...(r.DBInstances ?? [])); marker = r.Marker; } while (marker);
        const clusters: DBCluster[] = [];
        marker = undefined;
        do { const r: DescribeDBClustersCommandOutput = await rds.send(new DescribeDBClustersCommand({ Marker: marker })); clusters.push(...(r.DBClusters ?? [])); marker = r.Marker; } while (marker);
        const monthly = (id: string) => (db.prepare("select monthly_usd from inventory_rds where db_instance_identifier = ?").get(id) as { monthly_usd: number | null } | undefined)?.monthly_usd ?? null;
        for (const i of instances) {
          const tag = tagOf(i.TagList, SCHEDULE_TAG); if (tag == null) continue;
          const id = i.DBInstanceIdentifier!;
          if (tagOf(i.TagList, "advisor:hands-off") != null) { notes.push(`${id}: tagged advisor:hands-off`); continue; }
          if (i.DBClusterIdentifier) { notes.push(`${id}: member of cluster ${i.DBClusterIdentifier}; tag the cluster instead`); continue; }
          if (i.ReadReplicaSourceDBInstanceIdentifier || i.ReadReplicaSourceDBClusterIdentifier) { notes.push(`${id}: a read replica cannot be stopped`); continue; }
          if (i.ReadReplicaDBInstanceIdentifiers?.length || i.ReadReplicaDBClusterIdentifiers?.length) { notes.push(`${id}: has read replicas, so it cannot be stopped`); continue; }
          if (/sqlserver/i.test(i.Engine || "") && i.MultiAZ) { notes.push(`${id}: a Multi-AZ SQL Server instance cannot be stopped`); continue; }
          consider({ kind: "rds_instance", resource: id, name: id, region, account_id: acct.is_parent ? null : acct.account_id, state: rdsInstanceState(i), tag, monthly_usd: monthly(id), detail: `${i.Engine || "rds"} ${i.DBInstanceClass || ""}`.trim() });
        }
        for (const c of clusters) {
          const tag = tagOf(c.TagList, SCHEDULE_TAG); if (tag == null) continue;
          const id = c.DBClusterIdentifier!;
          if (tagOf(c.TagList, "advisor:hands-off") != null) { notes.push(`${id}: tagged advisor:hands-off`); continue; }
          if (c.ReplicationSourceIdentifier) { notes.push(`${id}: a replica cluster cannot be stopped`); continue; }
          const members = c.DBClusterMembers ?? [];
          const memberStates = instances.filter((i) => members.some((m) => m.DBInstanceIdentifier === i.DBInstanceIdentifier)).map((i) => rdsInstanceState(i));
          const state = rdsClusterState(c);
          if (state === "available" && memberStates.some((s) => s !== "available")) { notes.push(`${id}: members are ${memberStates.join(", ")}; waiting until all are available`); continue; }
          const usd = members.reduce((s, m) => s + (monthly(m.DBInstanceIdentifier || "") ?? 0), 0);
          consider({ kind: "rds_cluster", resource: id, name: id, region, account_id: acct.is_parent ? null : acct.account_id, state, tag, monthly_usd: members.length && usd > 0 ? usd : null, detail: `${c.Engine || "aurora"}, ${members.length} instance${members.length === 1 ? "" : "s"}` });
        }
      } catch (e: any) { const m = String(e?.message || e); notes.push(`${region} (RDS): ${m.slice(0, 160)}`); log(`${region}: ${m}`); }
      finally { rds.destroy(); }
    }
    if (!tagged) notes.push(`nothing tagged ${SCHEDULE_TAG} (e.g. "weekdays 08-20 Europe/Madrid" on a dev instance or database) or ${AUTO_PARK_TAG}=ON with a confident usage profile`);
    return { proposals, notes };
  },

  async apply(p, creds) { return transition(p, creds, String(p.after.state) === "stopped" ? "stop" : "start"); },

  async verify(p, creds) {
    const want = String(p.after.state);
    const kind = String(p.facts.kind) as ResourceKind;
    const state = await currentState(kind, p.resource, p.region, creds);
    if (state == null) return { ok: false, note: "not found on read-back" };
    if (state === want) {
      if (kind === "ec2" && want === "running" && Array.isArray(p.facts.dns_records) && p.facts.dns_records.length) return { ok: true, note: `read back: running; ${await dnsReadBack(p, creds)}` };
      return { ok: true, note: `read back: ${state}` };
    }
    if (["stopping", "pending", "starting", "modifying", "configuring-enhanced-monitoring", "backing-up"].includes(state)) return { ok: null, note: `still ${state}` };
    return { ok: false, note: `state reads ${state}` };
  },

  async revert(p, creds) { return transition(p, creds, String(p.after.state) === "stopped" ? "start" : "stop"); },
};

/** Waits for the started instance's public address, then points every recorded A record at it. Never throws: the start already happened, so the outcome is reported on the row. */
export async function reattachDns(p: Proposal, creds: Creds, records: DnsRecord[]): Promise<string> {
  const ec2 = new EC2Client({ region: p.region, credentials: creds.read });
  let ip: string | null = null;
  try {
    const until = Date.now() + IP_WAIT_MS;
    while (!ip && Date.now() < until) {
      await new Promise((r) => setTimeout(r, 5000));
      try { ip = (await ec2.send(new DescribeInstancesCommand({ InstanceIds: [p.resource] }))).Reservations?.[0]?.Instances?.[0]?.PublicIpAddress ?? null; } catch { /* keep waiting */ }
    }
  } finally { ec2.destroy(); }
  const names = [...new Set(records.map((r) => r.name))].join(", ");
  if (!ip) return `no public address after ${Math.round(IP_WAIT_MS / 1000)} s: ${names} still name ${records[0].old_ip} (update by hand or Revert and start again)`;
  if (records.every((r) => r.old_ip === ip)) return `public address ${ip} unchanged; ${names} already point at it`;
  const r53 = new Route53Client({ region: "us-east-1", credentials: creds.act() });
  const done: string[] = []; const failed: string[] = [];
  try {
    const byZone = new Map<string, DnsRecord[]>();
    for (const r of records) byZone.set(r.zone_id, [...(byZone.get(r.zone_id) || []), r]);
    for (const [zone, recs] of byZone) {
      try {
        await r53.send(new ChangeResourceRecordSetsCommand({ HostedZoneId: zone, ChangeBatch: { Comment: `aws-advisor office hours: ${p.resource} started, ${recs[0].old_ip} → ${ip}`, Changes: recs.map((r) => upsertChange(r, ip!)) } }));
        done.push(...recs.map((r) => r.name));
      } catch (e: any) { failed.push(`${recs.map((r) => r.name).join(", ")}: ${String(e?.message || e).slice(0, 120)}`); }
    }
  } finally { r53.destroy(); }
  return `public address ${records[0].old_ip} → ${ip}${done.length ? `; DNS updated: ${[...new Set(done)].join(", ")}` : ""}${failed.length ? `; DNS NOT updated (${failed.join("; ")}): fix the records by hand` : ""}`;
}

/** Whether the recorded A records now name the instance's public address (read credentials only). */
async function dnsReadBack(p: Proposal, creds: Creds): Promise<string> {
  const records = p.facts.dns_records as DnsRecord[];
  const ec2 = new EC2Client({ region: p.region, credentials: creds.read });
  let ip: string | null = null;
  try { ip = (await ec2.send(new DescribeInstancesCommand({ InstanceIds: [p.resource] }))).Reservations?.[0]?.Instances?.[0]?.PublicIpAddress ?? null; } finally { ec2.destroy(); }
  if (!ip) return "no public address yet; DNS not checked";
  const r53 = new Route53Client({ region: "us-east-1", credentials: creds.read });
  const ok: string[] = []; const stale: string[] = [];
  try {
    for (const r of records) {
      try {
        const sets = (await r53.send(new ListResourceRecordSetsCommand({ HostedZoneId: r.zone_id, StartRecordName: r.name, StartRecordType: "A", MaxItems: 5 }))).ResourceRecordSets ?? [];
        const set = sets.find((s) => s.Name?.replace(/\.$/, "") === r.name.replace(/\.$/, "") && s.Type === "A" && (!r.routing?.set_identifier || s.SetIdentifier === r.routing.set_identifier));
        (set?.ResourceRecords?.some((v) => v.Value === ip) ? ok : stale).push(r.name);
      } catch (e: any) { stale.push(`${r.name} (${String(e?.message || e).slice(0, 80)})`); }
    }
  } finally { r53.destroy(); }
  return `${ok.length ? `DNS ${[...new Set(ok)].join(", ")} → ${ip}` : ""}${ok.length && stale.length ? "; " : ""}${stale.length ? `DNS NOT updated: ${[...new Set(stale)].join(", ")} do not name ${ip}` : ""}`;
}

async function currentState(kind: ResourceKind, id: string, region: string, creds: Creds): Promise<string | null> {
  if (kind === "ec2") {
    const ec2 = new EC2Client({ region, credentials: creds.read });
    try { const i: Instance | undefined = (await ec2.send(new DescribeInstancesCommand({ InstanceIds: [id] }))).Reservations?.[0]?.Instances?.[0]; return i ? ec2State(i) : null; }
    finally { ec2.destroy(); }
  }
  const rds = new RDSClient({ region, credentials: creds.read });
  try {
    if (kind === "rds_cluster") { const c: DBCluster | undefined = (await rds.send(new DescribeDBClustersCommand({ DBClusterIdentifier: id }))).DBClusters?.[0]; return c ? rdsClusterState(c) : null; }
    const i: DBInstance | undefined = (await rds.send(new DescribeDBInstancesCommand({ DBInstanceIdentifier: id }))).DBInstances?.[0]; return i ? rdsInstanceState(i) : null;
  } catch (e: any) { if (/NotFound/i.test(String(e?.name || e?.message))) return null; throw e; }
  finally { rds.destroy(); }
}

async function transition(p: Proposal, creds: Creds, action: "stop" | "start"): Promise<string> {
  const kind = String(p.facts.kind) as ResourceKind;
  if (kind === "ec2") {
    const ec2 = new EC2Client({ region: p.region, credentials: creds.act() });
    try {
      if (action === "stop") { const r = await ec2.send(new StopInstancesCommand({ InstanceIds: [p.resource] })); return `StopInstances: ${r.StoppingInstances?.[0]?.CurrentState?.Name || "stopping"}`; }
      const r = await ec2.send(new StartInstancesCommand({ InstanceIds: [p.resource] }));
      const line = `StartInstances: ${r.StartingInstances?.[0]?.CurrentState?.Name || "pending"}`;
      if (p.facts.elastic_ip !== false) return line;
      const records = Array.isArray(p.facts.dns_records) ? (p.facts.dns_records as DnsRecord[]) : [];
      if (!records.length) return `${line} (no Elastic IP: the public address changed; no A record named the old one)`;
      return `${line}; ${await reattachDns(p, creds, records)}`;
    } finally { ec2.destroy(); }
  }
  const rds = new RDSClient({ region: p.region, credentials: creds.act() });
  try {
    if (kind === "rds_cluster") {
      if (action === "stop") { const r = await rds.send(new StopDBClusterCommand({ DBClusterIdentifier: p.resource })); return `StopDBCluster: ${r.DBCluster?.Status || "stopping"}`; }
      const r = await rds.send(new StartDBClusterCommand({ DBClusterIdentifier: p.resource })); return `StartDBCluster: ${r.DBCluster?.Status || "starting"}`;
    }
    if (action === "stop") { const r = await rds.send(new StopDBInstanceCommand({ DBInstanceIdentifier: p.resource })); return `StopDBInstance: ${r.DBInstance?.DBInstanceStatus || "stopping"} (AWS starts it again after seven days; the schedule stops it again)`; }
    const r = await rds.send(new StartDBInstanceCommand({ DBInstanceIdentifier: p.resource })); return `StartDBInstance: ${r.DBInstance?.DBInstanceStatus || "starting"}`;
  } finally { rds.destroy(); }
}

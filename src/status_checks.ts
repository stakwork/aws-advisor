/**
 * EC2 status checks, read for every running instance on the watcher's cadence: the system check (the hardware and
 * network under the box), the instance check (the OS is reachable) and the attached-EBS check (volumes complete
 * I/O), each ok | impaired | insufficient-data | initializing | not-applicable, plus the events AWS has scheduled
 * for the box (retirement, reboot, maintenance). All of it is free and comes with every instance
 * (DescribeInstanceStatus). Every change of a status is an event; a box whose checks fail raises
 * `status_check_failed`, closed by the system when the checks pass again. The graph carries the statuses on the
 * resource node. The application-level checks AWS added in 2026 are deliberately not used: they bill a managed
 * network interface per subnet and security group combination, which on this fleet would be hundreds of dollars a month.
 */
import { DescribeInstanceStatusCommand, EC2Client } from "@aws-sdk/client-ec2";
import { db } from "./db.js";
import { accountCredentials } from "./accounts.js";
import { credentialGate } from "./gate.js";
import { describeError } from "./permissions.js";
import { alertInsert } from "./alert_store.js";
import { AWS } from "./adapters/types.js";

db.exec(`
create table if not exists instance_status (
  instance_id text primary key, account_id text, region text, system_status text, instance_status text, ebs_status text,
  app_status text, app_status_since text, app_details text, events text, checked_at text not null
);
create table if not exists instance_status_events (
  id integer primary key autoincrement, instance_id text not null, field text not null, from_status text, to_status text not null, at text not null, details text
);
create index if not exists instance_status_events_instance on instance_status_events(instance_id, at);
create index if not exists instance_status_events_at on instance_status_events(at);
drop table if exists status_check_defs;`);

export type HostStatus = "ok" | "impaired" | "insufficient-data" | "not-applicable" | "initializing" | string;
export interface ScheduledEvent { code: string | null; description: string | null; not_before: string | null; not_after: string | null }
export interface InstanceStatusRow {
  instance_id: string; account_id: string | null; region: string | null;
  system_status: HostStatus | null; instance_status: HostStatus | null; ebs_status: HostStatus | null;
  events: ScheduledEvent[]; checked_at: string;
}

// ---- pure: what changed, what it warrants -----------------------------------------------------------------------------

export type StatusField = "system_status" | "instance_status" | "ebs_status";
export const STATUS_FIELDS: StatusField[] = ["system_status", "instance_status", "ebs_status"];
export interface Transition { field: StatusField; from: string | null; to: string }

/** The status fields that changed between two readings; a first reading is a transition from null for every known field. */
export function statusTransitions(prev: Partial<InstanceStatusRow> | null, next: InstanceStatusRow): Transition[] {
  const out: Transition[] = [];
  for (const f of STATUS_FIELDS) {
    const to = next[f]; if (to == null) continue;
    const from = prev?.[f] ?? null;
    if (from !== to) out.push({ field: f, from, to });
  }
  return out;
}

const FIELD_NAMES: Record<StatusField, string> = { system_status: "system", instance_status: "instance", ebs_status: "attached EBS" };
const FIELD_MEANING: Record<StatusField, string> = {
  system_status: "AWS-side: hardware or network under the box; a stop/start moves it to another host",
  instance_status: "the OS is not reachable: kernel, network config or exhausted memory; a reboot usually clears it",
  ebs_status: "an attached volume cannot complete I/O",
};

/** The scheduled events as short phrases: "system-reboot from 2026-09-29 02:00 UTC". */
export const describeEvents = (events: ScheduledEvent[]) => events.filter((e) => e.code).map((e) => `${e.code}${e.not_before ? ` from ${e.not_before.slice(0, 16).replace("T", " ")} UTC` : ""}`);

/**
 * Which alert a reading warrants given what is open: one `status_check_failed` per box while any of the three checks
 * is impaired, closed when they pass again. Insufficient data and initializing are neither: nothing is raised or closed.
 */
export function statusVerdicts(next: InstanceStatusRow, open: boolean): { raise: { message: string; details: Record<string, unknown> } | null; close: boolean } {
  const failing = STATUS_FIELDS.filter((f) => next[f] === "impaired");
  if (failing.length) {
    if (open) return { raise: null, close: false };
    const events = describeEvents(next.events);
    const message = `${failing.map((f) => FIELD_NAMES[f]).join(" and ")} status check${failing.length > 1 ? "s" : ""} failing (${FIELD_MEANING[failing[0]]})${events.length ? `; AWS scheduled: ${events.join(", ")}` : ""}`;
    return { raise: { message, details: { system_status: next.system_status, instance_status: next.instance_status, ebs_status: next.ebs_status, events: next.events, checked_at: next.checked_at } }, close: false };
  }
  return { raise: null, close: open && STATUS_FIELDS.some((f) => next[f] === "ok") };
}

// ---- storage -------------------------------------------------------------------------------------------------------------

const safeJson = (s: unknown, fallback: any) => { if (typeof s !== "string") return s ?? fallback; try { return JSON.parse(s); } catch { return fallback; } };
const rowToStatus = (r: any): InstanceStatusRow => ({ instance_id: r.instance_id, account_id: r.account_id ?? null, region: r.region ?? null, system_status: r.system_status ?? null, instance_status: r.instance_status ?? null, ebs_status: r.ebs_status ?? null, events: safeJson(r.events, []), checked_at: r.checked_at });

const upsertStatus = db.prepare(`insert into instance_status(instance_id, account_id, region, system_status, instance_status, ebs_status, events, checked_at) values (?, ?, ?, ?, ?, ?, ?, ?)
  on conflict(instance_id) do update set account_id = excluded.account_id, region = excluded.region, system_status = excluded.system_status, instance_status = excluded.instance_status, ebs_status = excluded.ebs_status, events = excluded.events, checked_at = excluded.checked_at`);
const insertEvent = db.prepare("insert into instance_status_events(instance_id, field, from_status, to_status, at, details) values (?, ?, ?, ?, ?, ?)");
const isOpen = db.prepare("select 1 from alerts where kind = 'status_check_failed' and resource = ? and acknowledged = 0 limit 1");
const insertAlert = alertInsert(AWS);
const ack = db.prepare("update alerts set acknowledged = 1, acknowledged_by = 'system' where resource = ? and kind = 'status_check_failed' and acknowledged = 0");

/** Stores one reading, records the transitions and applies the alert verdict. Returns what happened; the transport is elsewhere so this is testable. */
export function recordInstanceStatus(next: InstanceStatusRow, name: string | null): { transitions: Transition[]; raised: boolean; closed: boolean } {
  const label = name ? `${name} (${next.instance_id})` : next.instance_id;
  return db.transaction(() => {
    const prevRow = db.prepare("select * from instance_status where instance_id = ?").get(next.instance_id) as any;
    const prev = prevRow ? rowToStatus(prevRow) : null;
    const transitions = statusTransitions(prev, next);
    upsertStatus.run(next.instance_id, next.account_id, next.region, next.system_status, next.instance_status, next.ebs_status, JSON.stringify(next.events), next.checked_at);
    // a first reading that is clean is not an event worth keeping; anything not ok is, and so is every later change
    for (const t of transitions) if (prev || !["ok", "not-applicable"].includes(t.to)) insertEvent.run(next.instance_id, t.field, t.from, t.to, next.checked_at, next.events.length ? JSON.stringify(next.events) : null);
    const open = Boolean(isOpen.get(next.instance_id));
    const { raise, close } = statusVerdicts(next, open);
    if (close) ack.run(next.instance_id);
    if (raise) insertAlert.run("status_check_failed", next.instance_id, `${label}: ${raise.message}`, JSON.stringify({ summary: `${label}: ${raise.message}`, instance_id: next.instance_id, name, ...raise.details }));
    return { transitions, raised: Boolean(raise), closed: close };
  })();
}

// ---- the pass -------------------------------------------------------------------------------------------------------------

export interface StatusRefreshResult { groups: number; instances: number; impaired: number; scheduled_events: number; raised: number; closed: number; errors: string[]; took_ms: number }

const chunks = <T,>(xs: T[], n: number): T[][] => { const out: T[][] = []; for (let i = 0; i < xs.length; i += n) out.push(xs.slice(i, i + n)); return out; };
const iso = (d: Date | string | null | undefined) => (d ? new Date(d).toISOString() : null);

/** Every running instance's status checks, per account and region, on the watcher's cadence. */
export async function refreshStatusChecks(onLog: (s: string) => void = () => {}): Promise<StatusRefreshResult> {
  const t0 = Date.now();
  const out: StatusRefreshResult = { groups: 0, instances: 0, impaired: 0, scheduled_events: 0, raised: 0, closed: 0, errors: [], took_ms: 0 };
  const gate = await credentialGate("status-checks");
  if (!gate.ok) { out.errors.push(gate.error || "credentials not working"); out.took_ms = Date.now() - t0; return out; }
  const running = db.prepare("select instance_id, name, account_id, region from inventory_ec2 where gone = 0 and state = 'running' and region is not null").all() as { instance_id: string; name: string | null; account_id: string | null; region: string }[];
  const groups = new Map<string, typeof running>();
  for (const r of running) { const k = `${r.account_id || ""}|${r.region}`; groups.set(k, [...(groups.get(k) || []), r]); }
  const now = new Date().toISOString();
  for (const [key, list] of groups) {
    const [account, region] = key.split("|");
    out.groups++;
    let creds: ReturnType<typeof accountCredentials>;
    try { creds = accountCredentials(account || null); } catch (e) { out.errors.push(describeError(e, `credentials for account ${account || "parent"}`)); continue; }
    const ec2 = new EC2Client({ region, credentials: creds.provider });
    for (const batch of chunks(list, 100)) {
      const ids = batch.map((r) => r.instance_id);
      const rows = new Map<string, InstanceStatusRow>(batch.map((r) => [r.instance_id, { instance_id: r.instance_id, account_id: creds.account_id || account || null, region, system_status: null, instance_status: null, ebs_status: null, events: [], checked_at: now }]));
      try {
        let token: string | undefined;
        do {
          const res = await ec2.send(new DescribeInstanceStatusCommand({ InstanceIds: ids, IncludeAllInstances: true, MaxResults: 100, NextToken: token }));
          for (const s of res.InstanceStatuses ?? []) {
            const row = s.InstanceId ? rows.get(s.InstanceId) : undefined; if (!row) continue;
            row.system_status = s.SystemStatus?.Status ?? null; row.instance_status = s.InstanceStatus?.Status ?? null; row.ebs_status = s.AttachedEbsStatus?.Status ?? null;
            row.events = (s.Events ?? []).filter((e) => !e.Description?.startsWith("[Completed]")).map((e) => ({ code: e.Code ?? null, description: e.Description ?? null, not_before: iso(e.NotBefore), not_after: iso(e.NotAfter) }));
          }
          token = res.NextToken;
        } while (token);
      } catch (e) { out.errors.push(describeError(e, `instance status in ${region} (ec2:DescribeInstanceStatus)`)); continue; }
      for (const r of batch) {
        const row = rows.get(r.instance_id)!;
        if (row.system_status == null && row.instance_status == null) continue; // nothing came back for it
        const res = recordInstanceStatus(row, r.name);
        out.instances++; if (res.raised) out.raised++; if (res.closed) out.closed++;
        if (STATUS_FIELDS.some((f) => row[f] === "impaired")) out.impaired++;
        if (row.events.length) out.scheduled_events++;
      }
    }
    ec2.destroy();
  }
  db.prepare("delete from instance_status where instance_id not in (select instance_id from inventory_ec2 where gone = 0 and state = 'running')").run();
  db.prepare("delete from instance_status_events where at < datetime('now', '-180 days')").run();
  out.took_ms = Date.now() - t0;
  onLog(`${out.instances} instances in ${out.groups} account/region groups, ${out.impaired} impaired, ${out.scheduled_events} with a scheduled event, ${out.raised} raised, ${out.closed} closed, ${out.took_ms} ms${out.errors.length ? `, errors: ${out.errors.length}` : ""}`);
  try { const { mirrorStatusChecksInBackground } = await import("./graph_mirror.js"); mirrorStatusChecksInBackground(); } catch { /* graph off */ }
  return out;
}

// ---- reading it back ------------------------------------------------------------------------------------------------------

export function instanceStatusOf(instanceId: string): InstanceStatusRow | null {
  const r = db.prepare("select * from instance_status where instance_id = ?").get(instanceId); return r ? rowToStatus(r) : null;
}
export function statusEvents(opts: { instance_id?: string; since?: string; limit?: number } = {}) {
  const where: string[] = []; const args: unknown[] = [];
  if (opts.instance_id) { where.push("instance_id = ?"); args.push(opts.instance_id); }
  if (opts.since) { where.push("at >= ?"); args.push(opts.since); }
  args.push(Math.min(Math.max(opts.limit ?? 100, 1), 1000));
  return (db.prepare(`select * from instance_status_events ${where.length ? `where ${where.join(" and ")}` : ""} order by at desc, id desc limit ?`).all(...args) as any[]).map((e) => ({ ...e, details: safeJson(e.details, null) }));
}

export interface StatusSummary { checked_at: string | null; instances: number; ok: number; impaired: number; insufficient: number; scheduled_events: number; open_alerts: number }

export function statusSummary(): StatusSummary {
  const a = db.prepare(`select max(checked_at) as at, count(*) as n,
      sum(case when system_status = 'ok' and instance_status = 'ok' and coalesce(ebs_status, 'ok') in ('ok', 'not-applicable') then 1 else 0 end) as ok,
      sum(case when 'impaired' in (system_status, instance_status, coalesce(ebs_status, '')) then 1 else 0 end) as impaired,
      sum(case when system_status in ('insufficient-data', 'initializing') or instance_status in ('insufficient-data', 'initializing') then 1 else 0 end) as insufficient,
      sum(case when events <> '[]' then 1 else 0 end) as ev from instance_status`).get() as any;
  const alerts = (db.prepare("select count(*) as n from alerts where kind = 'status_check_failed' and acknowledged = 0").get() as { n: number }).n;
  return { checked_at: a?.at ?? null, instances: Number(a?.n ?? 0), ok: Number(a?.ok ?? 0), impaired: Number(a?.impaired ?? 0), insufficient: Number(a?.insufficient ?? 0), scheduled_events: Number(a?.ev ?? 0), open_alerts: alerts };
}

/** Every instance's reading with its name; `only` narrows to the ones worth looking at. */
export function listInstanceStatus(only: "all" | "impaired" | "events" = "all"): (InstanceStatusRow & { name: string | null })[] {
  const where = only === "impaired" ? "where 'impaired' in (s.system_status, s.instance_status, coalesce(s.ebs_status, ''))" : only === "events" ? "where s.events <> '[]'" : "";
  return (db.prepare(`select s.*, i.name from instance_status s left join inventory_ec2 i on i.instance_id = s.instance_id ${where}
    order by case when 'impaired' in (s.system_status, s.instance_status, coalesce(s.ebs_status, '')) then 0 when s.events <> '[]' then 1 else 2 end, i.name`).all() as any[]).map((r) => ({ ...rowToStatus(r), name: r.name ?? null }));
}

/**
 * Why an instance changed state: the alert says "Hive went from stopped to running", this says who did it, how
 * and from where. Three sources, cheapest first:
 *
 *  1. the advisor's own ledger: an executor row (office hours, parking, a wake, a Revert, the Stop / Start
 *     buttons) that touched the instance in the window is the cause, with its row id;
 *  2. EC2's own reason (DescribeInstances `StateTransitionReason`, `StateReason`): immediate, and the only
 *     source for changes that make no API call: a shutdown from inside the OS, a Spot interruption, an AWS
 *     scheduled event;
 *  3. CloudTrail (LookupEvents by the instance id) between the watcher sample before the change and the alert:
 *     the identity (person, role and session), the channel (console, CLI, Terraform, an SDK, Auto Scaling, a
 *     Lambda) and the source IP.
 *
 * CloudTrail delivers events 5 to 15 minutes late, so an alert raised by the 30-minute watcher usually comes
 * before its event. Such an alert is left `pending` and `attributePendingAlerts` looks again (every watcher
 * sample and every ten minutes) until the event shows up or `PENDING_HOURS` have passed. The verdict is stored
 * on the alert (`alerts.cause`) and, once, as a "Why:" sentence on its message, so the Sphinx message, the graph
 * mirror, Jev's triage and the agent's investigation all carry it.
 */
import { DescribeInstancesCommand, EC2Client } from "@aws-sdk/client-ec2";
import { CloudTrailClient, LookupEventsCommand } from "@aws-sdk/client-cloudtrail";
import { TRAIL_RETRY } from "./trail.js";
import { db } from "./db.js";
import { config } from "./config.js";
import { executorCreds } from "./executor.js";
import { describeError } from "./permissions.js";
import { configured as sphinxConfigured, sendSphinx } from "./notify.js";

try { db.exec("alter table alerts add column cause text"); } catch { /* exists */ }
try { db.exec("alter table alerts add column cause_at text"); } catch { /* exists */ }
try { db.exec("alter table alerts add column cause_notified_at text"); } catch { /* exists */ }

/** Alert kinds that carry an instance state change and can be explained. */
export const CAUSE_KINDS = ["instance_state"] as const;
/** How long a missing CloudTrail event is waited for before the verdict becomes final. */
export const PENDING_HOURS = 2;
/** Slack on both sides of the window: clocks, and the watcher's own sampling time. */
const SLACK_MS = 5 * 60_000;
/** When no earlier sample is found, how far back the window reaches. */
const DEFAULT_LOOKBACK_MS = 60 * 60_000;
/** The furthest back a window reaches, however old the previous sample (the watcher was off, or the database was restored). */
const MAX_LOOKBACK_MS = 6 * 60 * 60_000;

/** The API calls that move an instance between states, by the state it ends in. */
const EVENTS_TO: Record<string, string[]> = {
  running: ["StartInstances", "RunInstances", "RebootInstances"],
  pending: ["StartInstances", "RunInstances"],
  stopped: ["StopInstances"],
  stopping: ["StopInstances"],
  terminated: ["TerminateInstances"],
  "shutting-down": ["TerminateInstances"],
  gone: ["TerminateInstances"],
};
const STATE_EVENTS = new Set(Object.values(EVENTS_TO).flat());

export type ActorKind = "person" | "advisor" | "automation" | "aws" | "unknown";

export interface AlertCause {
  /** found: a source named the cause; pending: waiting for CloudTrail; none: nothing found within PENDING_HOURS. */
  status: "found" | "pending" | "none";
  /** Where the verdict came from. */
  source: "ledger" | "cloudtrail" | "state_reason" | null;
  actor: string | null;
  actor_kind: ActorKind;
  /** console, AWS CLI, Terraform, an SDK, Auto Scaling, a Lambda function... */
  via: string | null;
  event_name: string | null;
  event_time: string | null;
  event_id: string | null;
  source_ip: string | null;
  user_agent: string | null;
  principal_arn: string | null;
  error_code: string | null;
  /** The executor's ledger row, when the advisor did it. */
  action_id: number | null;
  action_kind: string | null;
  /** EC2's own words: StateTransitionReason and StateReason. */
  state_reason: string | null;
  state_reason_code: string | null;
  window: { from: string; to: string };
  summary: string;
  checked_at: string;
  tries: number;
}

// ---- pure ------------------------------------------------------------------------------------------------------

/** The channel a call came through, from its user agent and invokedBy. Pure. */
export function channelOf(userAgent: string | null | undefined, invokedBy?: string | null): string | null {
  const ua = String(userAgent || "");
  const by = String(invokedBy || "");
  if (/autoscaling/i.test(by) || /autoscaling\.amazonaws\.com/i.test(ua)) return "Auto Scaling";
  if (/ssm\.amazonaws\.com/i.test(by) || /ssm\.amazonaws\.com/i.test(ua)) return "Systems Manager";
  if (/scheduler\.amazonaws\.com|events\.amazonaws\.com/i.test(by + ua)) return "EventBridge";
  if (/elasticbeanstalk/i.test(by + ua)) return "Elastic Beanstalk";
  if (/cloudformation/i.test(by + ua)) return "CloudFormation";
  if (/AWS_Lambda|lambda\.amazonaws\.com/i.test(ua + by)) return "a Lambda function";
  if (/console\.(aws\.)?amazonaws\.com|signin\.amazonaws\.com|^AWS Internal$|console\.ec2/i.test(ua) || /^Mozilla\//.test(ua)) return "the console";
  if (/Terraform/i.test(ua)) return "Terraform";
  if (/Pulumi/i.test(ua)) return "Pulumi";
  if (/aws-cli\//i.test(ua)) return "the AWS CLI";
  if (/aws-sdk-js|@aws-sdk/i.test(ua)) return "the JavaScript SDK";
  if (/Boto3|botocore/i.test(ua)) return "boto3";
  if (/aws-sdk-go/i.test(ua)) return "the Go SDK";
  if (/aws-sdk-java/i.test(ua)) return "the Java SDK";
  if (by) return by.replace(/\.amazonaws\.com$/, "");
  return ua ? ua.split(/[\s/]/)[0].slice(0, 40) || null : null;
}

/** Who made a call, from a CloudTrail record's userIdentity. Pure. */
export function actorOf(ev: any, actRoleName: string | null): { actor: string | null; kind: ActorKind; principal_arn: string | null } {
  const u = ev?.userIdentity ?? {};
  const arn: string | null = u.arn ?? null;
  const invokedBy = String(u.invokedBy || "");
  if (u.type === "Root") return { actor: "the root user", kind: "person", principal_arn: arn };
  if (u.type === "IAMUser") return { actor: u.userName || arn, kind: /^(ci|deploy|bot|svc|service|github|gitlab|terraform)/i.test(u.userName || "") ? "automation" : "person", principal_arn: arn };
  if (u.type === "AWSService") return { actor: invokedBy || "an AWS service", kind: "aws", principal_arn: arn };
  if (u.type === "AssumedRole" || u.type === "FederatedUser") {
    const role: string = u.sessionContext?.sessionIssuer?.userName || (arn?.split("/")[1] ?? "");
    const session: string = arn?.split("/").slice(2).join("/") || "";
    if ((actRoleName && role === actRoleName) || /^aws-advisor/.test(session)) return { actor: "the advisor's actuator role", kind: "advisor", principal_arn: arn };
    if (/^AWSServiceRoleFor|^aws-service-role/i.test(role) || invokedBy) return { actor: invokedBy ? invokedBy.replace(/\.amazonaws\.com$/, "") : role, kind: "aws", principal_arn: arn };
    // Identity Center (AWSReservedSSO_*) and console sessions are people; the session name is usually their email
    if (/^AWSReservedSSO_/.test(role) || /@/.test(session)) return { actor: `${session || "someone"} (${role.replace(/^AWSReservedSSO_/, "").replace(/_[0-9a-f]{12,}$/, "")})`, kind: "person", principal_arn: arn };
    if (/^i-[0-9a-f]{8,17}$/.test(session)) return { actor: `instance ${session} (role ${role})`, kind: "automation", principal_arn: arn };
    const ua = String(ev?.userAgent || "");
    const kind: ActorKind = /console|signin|AWS Internal/i.test(ua) ? "person" : "automation";
    return { actor: session && session !== role ? `${session} (role ${role})` : `role ${role}`, kind, principal_arn: arn };
  }
  return { actor: u.userName || u.principalId || null, kind: "unknown", principal_arn: arn };
}

/** What EC2's own state reason says, when it explains a change without an API call. Pure. */
export function stateReasonCause(code: string | null | undefined, message: string | null | undefined): { actor: string; kind: ActorKind; summary: string } | null {
  const c = String(code || "");
  const m = String(message || "");
  if (c === "Client.InstanceInitiatedShutdown") return { actor: "the instance itself", kind: "automation", summary: "shut down from inside the instance (an OS shutdown or halt), not through the API" };
  if (/^Server\.SpotInstance/.test(c)) return { actor: "AWS (Spot)", kind: "aws", summary: "interrupted by AWS: Spot capacity reclaimed" };
  if (c === "Server.ScheduledStop") return { actor: "AWS (scheduled event)", kind: "aws", summary: "stopped by AWS for a scheduled event (retirement or maintenance)" };
  if (c === "Server.InternalError" || c === "Server.InsufficientInstanceCapacity") return { actor: "AWS", kind: "aws", summary: `stopped by AWS (${c})` };
  if (c === "Client.VolumeLimitExceeded" || c === "Client.InternalError" || c === "Client.InvalidSnapshot.NotFound") return { actor: "AWS", kind: "aws", summary: `failed to start (${c}: ${m.slice(0, 80)})` };
  return null;
}

/** "User initiated (2026-10-01 05:29:12 GMT)" → the time, as ISO. Pure. */
export function transitionTime(reason: string | null | undefined): string | null {
  const m = /\((\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}) GMT\)/.exec(String(reason || ""));
  return m ? `${m[1]}T${m[2]}.000Z` : null;
}

/** Among the window's events, the one that best explains a change to `to`: the right call, latest first, successful before failed. Pure. */
export function pickEvent<T extends { event_name: string; event_time: string; error_code?: string | null }>(events: T[], to: string | null): T | null {
  const want = new Set(EVENTS_TO[to ?? "gone"] ?? []);
  const rank = (e: T) => (want.has(e.event_name) ? 2 : STATE_EVENTS.has(e.event_name) ? 1 : 0) * 2 + (e.error_code ? 0 : 1);
  const cands = events.filter((e) => STATE_EVENTS.has(e.event_name));
  cands.sort((a, b) => rank(b) - rank(a) || b.event_time.localeCompare(a.event_time));
  return cands[0] ?? null;
}

const VERB: Record<string, string> = { StartInstances: "Started", StopInstances: "Stopped", RunInstances: "Launched", TerminateInstances: "Terminated", RebootInstances: "Rebooted" };
const hhmm = (iso: string | null) => (iso ? `${iso.slice(0, 16).replace("T", " ")} UTC` : "");

/** The one sentence shown as "Why:". Pure. */
export function causeSummary(c: Pick<AlertCause, "status" | "source" | "actor" | "actor_kind" | "via" | "event_name" | "event_time" | "source_ip" | "action_id" | "action_kind" | "state_reason" | "error_code" | "window">): string {
  if (c.source === "ledger") return `${c.event_name ? `${VERB[c.event_name] ?? c.event_name} by` : "Done by"} the advisor (ledger row #${c.action_id}, ${c.action_kind})${c.event_time ? ` at ${hhmm(c.event_time)}` : ""}`;
  if (c.source === "cloudtrail") {
    const ip = c.source_ip && !/amazonaws\.com$|^AWS Internal$/.test(c.source_ip) ? ` from ${c.source_ip}` : "";
    const via = c.via ? ` via ${c.via}` : "";
    return `${VERB[c.event_name ?? ""] ?? c.event_name} by ${c.actor ?? "an unknown identity"}${via}${ip} at ${hhmm(c.event_time)}${c.error_code ? ` (the call failed: ${c.error_code})` : ""}`;
  }
  if (c.source === "state_reason") return `${c.actor ? `${c.actor}: ` : ""}${c.state_reason}`;
  if (c.status === "pending") return `looking for the CloudTrail event (it can take 15 minutes to arrive)${c.state_reason ? `; EC2 says "${c.state_reason}"` : ""}`;
  return `no API call on the instance in CloudTrail between ${hhmm(c.window.from)} and ${hhmm(c.window.to)}${c.state_reason ? `; EC2 says "${c.state_reason}"` : ""}`;
}

// ---- lookups ---------------------------------------------------------------------------------------------------

interface AlertLite { id: number; created_at: string; kind: string; resource: string | null; message: string; details: string | null; cause: string | null }

const iso = (sqlTime: string) => (sqlTime.includes("T") ? sqlTime : sqlTime.replace(" ", "T") + "Z");

/** The window the change happened in: from the last watcher sample before the alert's to the alert. */
function windowOf(a: AlertLite): { from: Date; to: Date } {
  const to = new Date(new Date(iso(a.created_at)).getTime() + SLACK_MS);
  const created = iso(a.created_at);
  // the alert's own sample is written a moment before the alert; the one before it is the last known state.
  // collected_at is ISO (with the T), so the cutoff is computed here, not with SQLite's datetime()
  const cutoff = new Date(new Date(created).getTime() - 2 * 60_000).toISOString();
  const prev = db.prepare("select max(collected_at) as t from watch_samples where key = 'instance_state' and collected_at < ?").get(cutoff) as { t: string | null } | undefined;
  const prevAt = prev?.t ? new Date(prev.t).getTime() : NaN;
  const createdMs = new Date(created).getTime();
  const start = Number.isFinite(prevAt) ? Math.max(prevAt, createdMs - MAX_LOOKBACK_MS) : createdMs - DEFAULT_LOOKBACK_MS;
  const from = new Date(start - SLACK_MS);
  return { from, to };
}

function ledgerMatch(instanceId: string, from: Date, to: Date): { id: number; kind: string; at: string; event: string | null } | null {
  const rows = db.prepare(`select id, kind, title, applied_at, reverted_at from actions where resource = ? and (
      (applied_at is not null and datetime(applied_at) between datetime(?) and datetime(?)) or
      (reverted_at is not null and datetime(reverted_at) between datetime(?) and datetime(?))) order by id desc limit 1`)
    .all(instanceId, from.toISOString(), to.toISOString(), from.toISOString(), to.toISOString()) as { id: number; kind: string; title: string; applied_at: string | null; reverted_at: string | null }[];
  const r = rows[0];
  if (!r) return null;
  const reverted = r.reverted_at && new Date(iso(r.reverted_at)) >= from;
  const at = iso((reverted ? r.reverted_at : r.applied_at) as string);
  const t = `${r.title}`.toLowerCase();
  const event = /\bstart|wake/.test(t) ? "StartInstances" : /\bstop|park/.test(t) ? (reverted ? "StartInstances" : "StopInstances") : null;
  return { id: r.id, kind: r.kind, at, event };
}

/** Works out (or re-checks) the cause of one alert and stores it. Returns null for kinds it does not explain. */
export async function attributeAlert(alertId: number): Promise<AlertCause | null> {
  const a = db.prepare("select id, created_at, kind, resource, message, details, cause from alerts where id = ?").get(alertId) as AlertLite | undefined;
  if (!a || !a.resource || !(CAUSE_KINDS as readonly string[]).includes(a.kind) || !/^i-[0-9a-f]{8,17}$/.test(a.resource)) return null;
  const prevCause: AlertCause | null = a.cause ? safeJson(a.cause) : null;
  if (prevCause && prevCause.status !== "pending") return prevCause;
  let d: any = {};
  try { d = JSON.parse(a.details || "{}"); } catch { /* none */ }
  const to: string | null = d.to ?? null;
  const { from, to: until } = windowOf(a);
  const inv = db.prepare("select account_id, region from inventory_ec2 where instance_id = ?").get(a.resource) as { account_id: string | null; region: string | null } | undefined;
  const creds = executorCreds();
  const acct = creds.forAccount(inv?.account_id || null);
  const region = d.region || inv?.region || acct.region || creds.region;
  const actRoleName = config.actRoleArn ? config.actRoleArn.split("/").pop() || null : null;

  const c: AlertCause = {
    status: "pending", source: null, actor: null, actor_kind: "unknown", via: null, event_name: null, event_time: null, event_id: null, source_ip: null, user_agent: null,
    principal_arn: null, error_code: null, action_id: null, action_kind: null, state_reason: null, state_reason_code: null,
    window: { from: from.toISOString(), to: until.toISOString() }, summary: "", checked_at: new Date().toISOString(), tries: (prevCause?.tries ?? 0) + 1,
  };
  const errors: string[] = [];

  // 2 first, because it is cheap and also tells the ledger and CloudTrail branches what EC2 thinks
  const ec2 = new EC2Client({ region, credentials: acct.read });
  try {
    const inst = (await ec2.send(new DescribeInstancesCommand({ InstanceIds: [a.resource] }))).Reservations?.[0]?.Instances?.[0];
    c.state_reason = inst?.StateTransitionReason || inst?.StateReason?.Message || null;
    c.state_reason_code = inst?.StateReason?.Code ?? null;
  } catch (e) { if (!/InvalidInstanceID/.test(String((e as any)?.name || (e as any)?.message))) errors.push(describeError(e, `cause ${a.resource} (ec2:DescribeInstances)`, 160)); }
  finally { ec2.destroy(); }

  // 1. the advisor's own ledger
  const led = ledgerMatch(a.resource, from, until);
  if (led) Object.assign(c, { status: "found", source: "ledger", actor: "the advisor", actor_kind: "advisor", via: led.kind, action_id: led.id, action_kind: led.kind, event_time: led.at, event_name: led.event });

  // 3. CloudTrail, also when the ledger matched: the event adds the time and confirms the call went through
  const ct = new CloudTrailClient({ region, credentials: acct.read, ...TRAIL_RETRY });
  try {
    const events: { event_name: string; event_time: string; error_code: string | null; raw: any; id: string }[] = [];
    let NextToken: string | undefined; let pages = 0;
    do {
      const res = await ct.send(new LookupEventsCommand({ LookupAttributes: [{ AttributeKey: "ResourceName", AttributeValue: a.resource }], StartTime: from, EndTime: until, MaxResults: 50, NextToken }));
      for (const ev of res.Events ?? []) {
        let raw: any = {}; try { raw = ev.CloudTrailEvent ? JSON.parse(ev.CloudTrailEvent) : {}; } catch { /* keep going */ }
        events.push({ id: ev.EventId ?? "", event_name: ev.EventName ?? "", event_time: (ev.EventTime ?? new Date()).toISOString(), error_code: raw.errorCode ?? null, raw });
      }
      NextToken = res.NextToken; pages++;
    } while (NextToken && pages < 5);
    const best = pickEvent(events, to);
    if (best) {
      const who = actorOf(best.raw, actRoleName);
      if (c.source !== "ledger" || who.kind === "advisor") {
        Object.assign(c, {
          status: "found", source: c.source === "ledger" ? "ledger" : "cloudtrail",
          actor: c.source === "ledger" ? c.actor : who.actor, actor_kind: c.source === "ledger" ? "advisor" : who.kind,
          via: c.source === "ledger" ? c.via : channelOf(best.raw.userAgent, best.raw.userIdentity?.invokedBy),
          event_name: best.event_name, event_time: best.event_time, event_id: best.id, source_ip: best.raw.sourceIPAddress ?? null,
          user_agent: best.raw.userAgent ? String(best.raw.userAgent).slice(0, 200) : null, principal_arn: who.principal_arn, error_code: best.error_code,
        });
      }
    }
  } catch (e) { errors.push(describeError(e, `cause ${a.resource} (cloudtrail:LookupEvents)`, 160)); }
  finally { ct.destroy(); }

  // 2. what EC2 says, when nothing called the API
  if (c.status !== "found") {
    const sr = stateReasonCause(c.state_reason_code, c.state_reason);
    if (sr) Object.assign(c, { status: "found", source: "state_reason", actor: sr.actor, actor_kind: sr.kind, state_reason: sr.summary, event_time: transitionTime(c.state_reason) });
    else if (Date.now() - new Date(iso(a.created_at)).getTime() > PENDING_HOURS * 3600_000) c.status = "none";
  }
  c.summary = causeSummary(c);
  if (errors.length && c.status !== "found") c.summary += ` (lookup errors: ${errors.join("; ").slice(0, 200)})`;

  db.transaction(() => {
    db.prepare("update alerts set cause = ?, cause_at = datetime('now') where id = ?").run(JSON.stringify(c), a.id);
    // once, the way NAT attribution adds its receivers: everything that reads the message gets the why
    if (c.status === "found" && !/ · Why: /.test(a.message)) db.prepare("update alerts set message = message || ? where id = ?").run(` · Why: ${c.summary}`, a.id);
  })();
  return c;
}

/** Explains a batch of fresh alerts; failures are logged, never thrown. */
export async function attributeAlerts(ids: number[], log: (s: string) => void = (s) => console.log(`[cause] ${s}`)): Promise<number> {
  let found = 0;
  for (const id of ids) {
    try { const c = await attributeAlert(id); if (c) { log(`alert ${id}: ${c.status}: ${c.summary}`); if (c.status === "found") found++; } }
    catch (e: any) { log(`alert ${id}: ${String(e?.message || e).slice(0, 200)}`); }
  }
  return found;
}

let running = false;
/** Looks again at every alert still waiting for its CloudTrail event (and older unexplained ones from before this existed, for a day). */
export async function attributePendingAlerts(): Promise<{ checked: number; found: number }> {
  if (running) return { checked: 0, found: 0 };
  running = true;
  try {
    const ids = (db.prepare(`select id from alerts where kind in (${CAUSE_KINDS.map(() => "?").join(",")}) and resource like 'i-%'
        and (cause is null or json_extract(cause, '$.status') = 'pending') and datetime(created_at) > datetime('now', '-1 day')
        and (cause_at is null or datetime(cause_at) < datetime('now', '-8 minutes')) order by id limit 40`).all(...CAUSE_KINDS) as { id: number }[]).map((r) => r.id);
    if (!ids.length) return { checked: 0, found: 0 };
    const found = await attributeAlerts(ids);
    if (found) await followUp(ids).catch((e: any) => console.error(`[cause] follow-up failed: ${e?.message || e}`));
    return { checked: ids.length, found };
  } finally { running = false; }
}

/** An alert that already went to Sphinx before its cause was known gets the "Why:" as a short reply, once. */
async function followUp(ids: number[]): Promise<void> {
  if (!sphinxConfigured()) return;
  const rows = db.prepare(`select id, resource, cause, details from alerts where id in (${ids.map(() => "?").join(",")}) and notify_result = 'sent' and cause_notified_at is null
      and json_extract(cause, '$.status') = 'found'`).all(...ids) as { id: number; resource: string; cause: string; details: string | null }[];
  for (const r of rows) {
    const c = causeOf(r);
    if (!c) continue;
    let name = r.resource;
    try { const d = JSON.parse(r.details || "{}"); if (d.name) name = `${d.name} (${r.resource})`; } catch { /* id only */ }
    const res = await sendSphinx(`↳ Alert #${r.id}, ${name}. Why: ${c.summary}\n${config.notifyLinkUrl}/alerts?status=all&id=${r.id}`);
    if (res.ok) db.prepare("update alerts set cause_notified_at = datetime('now') where id = ?").run(r.id);
  }
}

/** The stored cause of an alert, parsed. */
export function causeOf(row: { cause?: string | null } | null | undefined): AlertCause | null {
  return row?.cause ? safeJson(row.cause) : null;
}

function safeJson(s: string): any { try { return JSON.parse(s); } catch { return null; } }

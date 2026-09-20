/**
 * CloudTrail write events: what changed in the account in the last day, by who. The observing agent's "what
 * changed" feed and the explanation for many cost moves. Read through aws_cloudtrail_lookup_event (LookupEvents,
 * read_only = false) through the SDK, which needs cloudtrail:LookupEvents; when the permission is missing the job records the
 * issue (Settings > Permissions) and the brief says so. The advisor's own SSM probes are filtered out.
 */
import { db } from "./db.js";
import { sdkCredentials } from "./steampipe.js";
import { CloudTrailClient, LookupEventsCommand } from "@aws-sdk/client-cloudtrail";
import { config } from "./config.js";
import { credentialGate } from "./gate.js";
import { describeError } from "./permissions.js";

db.exec(`create table if not exists trail_events (
  event_id text primary key, event_time text not null, event_name text not null, event_source text not null,
  username text, resource_name text, resource_type text, region text, error_code text, fetched_at text not null
)`);
try { db.exec("alter table trail_events add column noise integer not null default 0"); } catch { /* exists */ }

/** Machine heartbeat that CloudTrail files as writes: agents checking in, log streams being opened, Batch and EKS running their own tasks. Stored, counted, never shown as a change. */
const NOISE_EVENTS = new Set(["UpdateInstanceInformation", "CreateLogStream", "PutLogEvents", "StartTask", "SubmitTaskStateChange", "SubmitContainerStateChange", "RegisterContainerInstance", "DeregisterContainerInstance", "AssumeRole", "AssumeRoleWithWebIdentity", "GetSessionToken", "UpdateInstanceAssociationStatus", "PutInventory", "UpdateInstanceAssociation", "CreateGrant", "Decrypt", "GenerateDataKey", "Encrypt", "SendHeartbeat", "RecordLifecycleActionHeartbeat", "PutMetricData", "PutConfigurePackageResult", "RetireGrant", "CreateNetworkInterfacePermission", "DeleteNetworkInterfacePermission", "CreatePlatformEndpoint", "SetEndpointAttributes", "DeleteEndpoint"]);
/** Controllers and machines: AWS services, instance roles (username = instance id), Batch, autoscaling, botocore sessions. What they write is the system running, not a person changing it. */
const NOISE_USERS = /^(aws-batch|AmazonEKS|AutoScaling|ecs-service-scheduler|AWSServiceRoleFor|Amazon[A-Z]|AWS[A-Z]|i-[0-9a-f]{8,17}$|botocore-session-|[A-Za-z]+Service$)/;
export const isNoise = (eventName: string, username: string | null | undefined) => NOISE_EVENTS.has(eventName) || NOISE_USERS.test(username || "") || (!username && /^(RetireGrant|Decrypt|Encrypt)$/.test(eventName));

/** Re-marks stored rows with the current noise rules (after a rule change). */
export function remarkNoise(): number {
  const rows = db.prepare("select event_id, event_name, username from trail_events").all() as { event_id: string; event_name: string; username: string | null }[];
  const set = db.prepare("update trail_events set noise = ? where event_id = ?");
  let n = 0; for (const r of rows) { const v = isNoise(r.event_name, r.username) ? 1 : 0; set.run(v, r.event_id); n += v; } return n;
}

export interface TrailRefreshResult { events: number; stored: number; errors: string[]; took_ms: number }

const OWN_EVENTS = new Set(["SendCommand", "GetCommandInvocation", "StartSession"]);
/** 50 events per page at 2 requests per second: 400 pages is 20,000 events and about 200 s, more than a day of this account. */
const MAX_PAGES = 900;

export async function refreshTrail(hours = 26, onLog: (s: string) => void = () => {}): Promise<TrailRefreshResult> {
  const t0 = Date.now();
  const out: TrailRefreshResult = { events: 0, stored: 0, errors: [], took_ms: 0 };
  const gate = await credentialGate("cloudtrail");
  if (!gate.ok) { out.errors.push(gate.error || "credentials not working"); out.took_ms = Date.now() - t0; return out; }
  // The SDK, not Steampipe: aws_cloudtrail_lookup_event does not push the time window down to LookupEvents, so
  // even a one-hour query pages through the whole 90-day trail at the API's 2 requests per second.
  let creds: ReturnType<typeof sdkCredentials>;
  try { creds = sdkCredentials(); } catch (e: any) { out.errors.push(String(e?.message || e)); out.took_ms = Date.now() - t0; return out; }
  const regions = (db.prepare("select distinct region from inventory_ec2 where gone = 0 and region is not null").all() as { region: string }[]).map((r) => r.region);
  if (!regions.length) regions.push(creds.region || "us-east-1");
  const up = db.prepare(`insert into trail_events(event_id, event_time, event_name, event_source, username, resource_name, resource_type, region, error_code, fetched_at, noise)
    values (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), ?) on conflict(event_id) do nothing`);
  const StartTime = new Date(Date.now() - Math.max(1, Math.min(168, hours)) * 3600_000);
  const own = config.advisorAwsProfile.replace(/-managed$/, "");
  for (const region of regions) {
    const client = new CloudTrailClient({ region, credentials: creds.provider });
    try {
      let NextToken: string | undefined; let pages = 0;
      do {
        const res = await client.send(new LookupEventsCommand({ StartTime, EndTime: new Date(), LookupAttributes: [{ AttributeKey: "ReadOnly", AttributeValue: "false" }], MaxResults: 50, NextToken }));
        for (const ev of res.Events || []) {
          out.events++;
          if (!ev.EventId || !ev.EventName) continue;
          if (OWN_EVENTS.has(ev.EventName) && (!ev.Username || ev.Username.includes(own))) continue;
          let detail: any = {}; try { detail = ev.CloudTrailEvent ? JSON.parse(ev.CloudTrailEvent) : {}; } catch { /* keep going */ }
          const r0 = ev.Resources?.[0];
          const res2 = up.run(ev.EventId, (ev.EventTime ?? new Date()).toISOString(), ev.EventName, ev.EventSource ?? "", ev.Username ?? null, r0?.ResourceName ?? null, r0?.ResourceType ?? null, region, detail.errorCode ?? null, isNoise(ev.EventName, ev.Username) ? 1 : 0);
          if (res2.changes) out.stored++;
        }
        NextToken = res.NextToken; pages++;
        if (pages >= MAX_PAGES) { out.errors.push(`${region}: stopped after ${MAX_PAGES} pages (${out.events} events); narrow the window`); break; }
      } while (NextToken);
    } catch (e) { out.errors.push(describeError(e, `cloudtrail changes ${region} (cloudtrail:LookupEvents)`)); }
    finally { client.destroy(); }
  }
  db.prepare("delete from trail_events where event_time < datetime('now', '-90 days')").run();
  out.took_ms = Date.now() - t0;
  onLog(`${out.events} write events read, ${out.stored} new stored, ${out.took_ms} ms${out.errors.length ? `; ${out.errors.join("; ")}` : ""}`);
  return out;
}

export interface TrailSummary { since: string; events: number; noise: number; by_action: { event_name: string; event_source: string; username: string | null; n: number; resources: string[]; errors: number }[]; by_user: { username: string | null; n: number }[]; last_fetch: string | null }

/** The last `hours` of stored write events, grouped by action and user, with sample resources. */
export function trailSummary(hours = 24): TrailSummary {
  const since = new Date(Date.now() - hours * 3600_000).toISOString();
  const rows = db.prepare("select event_name, event_source, username, resource_name, error_code from trail_events where event_time >= ? and noise = 0 order by event_time desc").all(since) as any[];
  const noise = (db.prepare("select count(*) as n from trail_events where event_time >= ? and noise = 1").get(since) as { n: number }).n;
  const groups = new Map<string, { event_name: string; event_source: string; username: string | null; n: number; resources: Set<string>; errors: number }>();
  for (const r of rows) {
    const k = `${r.event_source}|${r.event_name}|${r.username ?? ""}`;
    const g = groups.get(k) || { event_name: r.event_name, event_source: String(r.event_source).replace(/\.amazonaws\.com$/, ""), username: r.username ?? null, n: 0, resources: new Set<string>(), errors: 0 };
    g.n++; if (r.resource_name) g.resources.add(String(r.resource_name)); if (r.error_code) g.errors++;
    groups.set(k, g);
  }
  const byUser = new Map<string | null, number>();
  for (const r of rows) byUser.set(r.username ?? null, (byUser.get(r.username ?? null) || 0) + 1);
  const lastFetch = (db.prepare("select max(fetched_at) as t from trail_events").get() as { t: string | null }).t;
  return {
    since, events: rows.length, noise, last_fetch: lastFetch,
    by_action: [...groups.values()].sort((a, b) => b.n - a.n).map((g) => ({ ...g, resources: [...g.resources].slice(0, 8) })),
    by_user: [...byUser.entries()].map(([username, n]) => ({ username, n })).sort((a, b) => b.n - a.n),
  };
}

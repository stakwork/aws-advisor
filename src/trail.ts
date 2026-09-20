/**
 * CloudTrail write events: what changed in the account in the last day, by who. The observing agent's "what
 * changed" feed and the explanation for many cost moves. Read through aws_cloudtrail_lookup_event (LookupEvents,
 * read_only = false), which needs cloudtrail:LookupEvents; when the permission is missing the job records the
 * issue (Settings > Permissions) and the brief says so. The advisor's own SSM probes are filtered out.
 */
import { db } from "./db.js";
import { S, query } from "./steampipe.js";
import { config } from "./config.js";
import { credentialGate } from "./gate.js";
import { describeError } from "./permissions.js";

db.exec(`create table if not exists trail_events (
  event_id text primary key, event_time text not null, event_name text not null, event_source text not null,
  username text, resource_name text, resource_type text, region text, error_code text, fetched_at text not null
)`);

export interface TrailRefreshResult { events: number; stored: number; errors: string[]; took_ms: number }

const OWN_EVENTS = new Set(["SendCommand", "GetCommandInvocation", "StartSession"]);

export async function refreshTrail(hours = 26, onLog: (s: string) => void = () => {}): Promise<TrailRefreshResult> {
  const t0 = Date.now();
  const out: TrailRefreshResult = { events: 0, stored: 0, errors: [], took_ms: 0 };
  const gate = await credentialGate("cloudtrail");
  if (!gate.ok) { out.errors.push(gate.error || "credentials not working"); out.took_ms = Date.now() - t0; return out; }
  const regions = (db.prepare("select distinct region from inventory_ec2 where gone = 0 and region is not null").all() as { region: string }[]).map((r) => r.region);
  if (!regions.length) regions.push("us-east-1");
  const up = db.prepare(`insert into trail_events(event_id, event_time, event_name, event_source, username, resource_name, resource_type, region, error_code, fetched_at)
    values (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now')) on conflict(event_id) do nothing`);
  for (const region of regions) {
    try {
      const rows = await query<any>(`select event_id, event_time, event_name, event_source, username, resource_name, resource_type, cloud_trail_event ->> 'errorCode' as error_code
        from ${S}.aws_cloudtrail_lookup_event where region = '${region.replace(/'/g, "")}' and read_only = 'false' and event_time > now() - interval '${Math.max(1, Math.min(168, Math.floor(hours)))} hours' order by event_time`);
      for (const r of rows) {
        out.events++;
        if (OWN_EVENTS.has(r.event_name) && String(r.username || "").includes(config.advisorAwsProfile.replace(/-managed$/, ""))) continue;
        if (OWN_EVENTS.has(r.event_name)) continue;
        const res = up.run(r.event_id, new Date(r.event_time).toISOString(), r.event_name, r.event_source, r.username ?? null, r.resource_name ?? null, r.resource_type ?? null, region, r.error_code ?? null);
        if (res.changes) out.stored++;
      }
    } catch (e) { out.errors.push(describeError(e, `cloudtrail changes ${region} (aws_cloudtrail_lookup_event)`)); }
  }
  db.prepare("delete from trail_events where event_time < datetime('now', '-90 days')").run();
  out.took_ms = Date.now() - t0;
  onLog(`${out.events} write events read, ${out.stored} new stored, ${out.took_ms} ms${out.errors.length ? `; ${out.errors.join("; ")}` : ""}`);
  return out;
}

export interface TrailSummary { since: string; events: number; by_action: { event_name: string; event_source: string; username: string | null; n: number; resources: string[]; errors: number }[]; by_user: { username: string | null; n: number }[]; last_fetch: string | null }

/** The last `hours` of stored write events, grouped by action and user, with sample resources. */
export function trailSummary(hours = 24): TrailSummary {
  const since = new Date(Date.now() - hours * 3600_000).toISOString();
  const rows = db.prepare("select event_name, event_source, username, resource_name, error_code from trail_events where event_time >= ? order by event_time desc").all(since) as any[];
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
    since, events: rows.length, last_fetch: lastFetch,
    by_action: [...groups.values()].sort((a, b) => b.n - a.n).map((g) => ({ ...g, resources: [...g.resources].slice(0, 8) })),
    by_user: [...byUser.entries()].map(([username, n]) => ({ username, n })).sort((a, b) => b.n - a.n),
  };
}

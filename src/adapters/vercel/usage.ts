import { db } from "../../db.js";
import type { VercelClient, UsageDay, UsageType } from "./client.js";

/**
 * The metered side of a Vercel team (`/v2/usage`): one row per day and usage type with Vercel's own metric names
 * (requests hit and miss, bandwidth in and out, function invocations by outcome and their GB-hours, builds and
 * their seconds, blob size and requests, cron invocations, data cache bytes, log volume) and the per-project
 * breakdown in percent. Refreshed with the collection, thirty days back; the readers fold it into what the Overview
 * shows and what the project nodes carry (requests, invocations, errors and bandwidth over the last week).
 */

db.exec(`create table if not exists vercel_usage (
  team_id text not null, project_id text not null default '', day text not null, type text not null, metrics text not null default '{}', breakdown text not null default '{}', fetched_at text not null,
  primary key (team_id, project_id, day, type)
)`);
// the first version keyed on (team, day, type) only; rebuild it with the project column
if (!(db.prepare("pragma table_info(vercel_usage)").all() as { name: string }[]).some((c) => c.name === "project_id")) db.exec(`drop table vercel_usage; create table vercel_usage (
  team_id text not null, project_id text not null default '', day text not null, type text not null, metrics text not null default '{}', breakdown text not null default '{}', fetched_at text not null,
  primary key (team_id, project_id, day, type))`);

export const USAGE_DAYS = 30;
export const REFRESH_TYPES: UsageType[] = ["requests", "builds", "storage_blob", "storage_postgres", "storage_redis", "cron_jobs", "data_cache", "log_drains", "edge"];

/** The types read per project as well as for the team (one call per project and type: exact numbers, where the team breakdown is whole percent). */
export const PROJECT_TYPES: UsageType[] = ["requests", "builds"];

/** Reads every usage type for the last USAGE_DAYS days, team-wide and per project for the main types; today's row is partial and is rewritten each time. */
export async function refreshUsage(client: VercelClient, teamId: string, projectIds: string[] = [], days = USAGE_DAYS): Promise<{ types: number; days: number; projects: number }> {
  const to = new Date(); const from = new Date(to.getTime() - days * 86_400_000); const now = to.toISOString();
  const up = db.prepare("insert into vercel_usage(team_id, project_id, day, type, metrics, breakdown, fetched_at) values (?, ?, ?, ?, ?, ?, ?) on conflict(team_id, project_id, day, type) do update set metrics = excluded.metrics, breakdown = excluded.breakdown, fetched_at = excluded.fetched_at");
  let rows = 0; let types = 0; let projects = 0;
  for (const type of REFRESH_TYPES) {
    const data = await client.usage(type, from, to);
    if (!data.length) continue;
    types++;
    db.transaction(() => { for (const d of data) { up.run(teamId, "", d.date, type, JSON.stringify(d.metrics), JSON.stringify(d.breakdown), now); rows++; } })();
  }
  for (const pid of projectIds) {
    let any = false;
    for (const type of PROJECT_TYPES) { const data = await client.usage(type, from, to, pid); if (!data.length) continue; any = true; db.transaction(() => { for (const d of data) { up.run(teamId, pid, d.date, type, JSON.stringify(d.metrics), "{}", now); rows++; } })(); }
    if (any) projects++;
  }
  return { types, days: rows, projects };
}

const parse = <T,>(s: unknown, d: T): T => { if (typeof s !== "string") return d; try { return JSON.parse(s) as T; } catch { return d; } };
export const usageRows = (teamId: string, type: UsageType, days: number, projectId = "", since?: string): UsageDay[] => (db.prepare("select day, metrics, breakdown from vercel_usage where team_id = ? and project_id = ? and type = ? and day >= ? order by day").all(teamId, projectId, type, since ?? new Date(Date.now() - days * 86_400_000).toISOString().slice(0, 10)) as any[]).map((r) => ({ date: r.day, metrics: parse(r.metrics, {}), breakdown: parse(r.breakdown, {}) }));

const sum = (rows: UsageDay[], key: string) => rows.reduce((n, r) => n + (Number(r.metrics[key]) || 0), 0);
const last = (rows: UsageDay[], key: string) => { for (let i = rows.length - 1; i >= 0; i--) { const v = rows[i].metrics[key]; if (typeof v === "number") return v; } return null; };

export interface UsageTotals {
  days: number; requests: number; cache_hit_pct: number | null; bandwidth_out_gb: number; bandwidth_in_gb: number;
  invocations: number; invocation_errors: number; invocation_throttles: number; invocation_timeouts: number; error_pct: number | null; gb_hours: number;
  builds: number; builds_failed: number; build_minutes: number; cron_invocations: number; blob_gb: number | null; blob_requests: number; data_cache_gb: number; log_gb: number;
}

/** The team's (or one project's) numbers over the last `days` days, or since a date, in the units a person reads (GB, minutes, percent). */
export function usageTotals(teamId: string, days: number, projectId = "", since?: string): UsageTotals {
  const req = usageRows(teamId, "requests", days, projectId, since); const builds = usageRows(teamId, "builds", days, projectId, since); const blob = usageRows(teamId, "storage_blob", days, projectId, since); const cron = usageRows(teamId, "cron_jobs", days, projectId, since); const cache = usageRows(teamId, "data_cache", days, projectId, since); const logs = usageRows(teamId, "log_drains", days, projectId, since);
  const hits = sum(req, "request_hit_count"), misses = sum(req, "request_miss_count"); const requests = hits + misses;
  const inv = sum(req, "function_invocation_successful_count") + sum(req, "function_invocation_error_count") + sum(req, "function_invocation_throttle_count") + sum(req, "function_invocation_timeout_count");
  const errors = sum(req, "function_invocation_error_count");
  const gb = (b: number) => Math.round((b / 1e9) * 100) / 100;
  return {
    days, requests, cache_hit_pct: requests ? Math.round((hits / requests) * 1000) / 10 : null, bandwidth_out_gb: gb(sum(req, "bandwidth_outgoing_bytes")), bandwidth_in_gb: gb(sum(req, "bandwidth_incoming_bytes")),
    invocations: inv, invocation_errors: errors, invocation_throttles: sum(req, "function_invocation_throttle_count"), invocation_timeouts: sum(req, "function_invocation_timeout_count"), error_pct: inv ? Math.round((errors / inv) * 10000) / 100 : null,
    gb_hours: Math.round((sum(req, "function_execution_successful_gb_hours") + sum(req, "function_execution_error_gb_hours") + sum(req, "function_execution_timeout_gb_hours")) * 10) / 10,
    builds: sum(builds, "build_completed_count") + sum(builds, "build_failed_count"), builds_failed: sum(builds, "build_failed_count"), build_minutes: Math.round(sum(builds, "build_build_seconds") / 60),
    cron_invocations: sum(cron, "cron_job_invocations"), blob_gb: last(blob, "blob_size_in_bytes") != null ? gb(last(blob, "blob_size_in_bytes")!) : null, blob_requests: sum(blob, "blob_simple_request_count") + sum(blob, "blob_advanced_request_count"),
    data_cache_gb: gb(sum(cache, "data_cache_total_sent_bytes") + sum(cache, "data_cache_total_received_bytes")), log_gb: gb(sum(logs, "log_volume")),
  };
}

/** The daily series the Overview draws: requests, invocations, errors, bandwidth out and builds per day. */
export function usageSeries(teamId: string, days: number, projectId = "", since?: string): { day: string; requests: number; invocations: number; errors: number; bandwidth_out_gb: number; builds: number }[] {
  const req = new Map(usageRows(teamId, "requests", days, projectId, since).map((r) => [r.date, r.metrics])); const builds = new Map(usageRows(teamId, "builds", days, projectId, since).map((r) => [r.date, r.metrics]));
  const daysList = [...new Set([...req.keys(), ...builds.keys()])].sort();
  return daysList.map((day) => { const m = req.get(day) || {}; const b = builds.get(day) || {}; return { day, requests: (m.request_hit_count || 0) + (m.request_miss_count || 0), invocations: (m.function_invocation_successful_count || 0) + (m.function_invocation_error_count || 0) + (m.function_invocation_throttle_count || 0) + (m.function_invocation_timeout_count || 0), errors: m.function_invocation_error_count || 0, bandwidth_out_gb: Math.round(((m.bandwidth_outgoing_bytes || 0) / 1e9) * 100) / 100, builds: (b.build_completed_count || 0) + (b.build_failed_count || 0) }; });
}

export interface ProjectUsage { project_id: string; name: string; requests: number; invocations: number; bandwidth_out_gb: number; gb_hours: number; builds: number }

/** Per project over the last `days` days, from the daily breakdown percentages applied to the day's totals (an estimate at the precision Vercel gives, whole percent). */
export function usageByProject(teamId: string, days: number, since?: string): ProjectUsage[] {
  const out = new Map<string, ProjectUsage>();
  const add = (id: string, name: string, key: keyof Omit<ProjectUsage, "project_id" | "name">, v: number) => { const p = out.get(id) ?? { project_id: id, name, requests: 0, invocations: 0, bandwidth_out_gb: 0, gb_hours: 0, builds: 0 }; p[key] += v; out.set(id, p); };
  for (const r of usageRows(teamId, "requests", days, "", since)) {
    const total = { requests: (r.metrics.request_hit_count || 0) + (r.metrics.request_miss_count || 0), invocations: (r.metrics.function_invocation_successful_count || 0) + (r.metrics.function_invocation_error_count || 0), bandwidth: r.metrics.bandwidth_outgoing_bytes || 0, gb_hours: (r.metrics.function_execution_successful_gb_hours || 0) + (r.metrics.function_execution_error_gb_hours || 0) };
    for (const b of r.breakdown.requests || []) add(b.id, b.name, "requests", (total.requests * b.percent) / 100);
    for (const b of r.breakdown.function_invocations || []) add(b.id, b.name, "invocations", (total.invocations * b.percent) / 100);
    for (const b of r.breakdown.bandwidth || []) add(b.id, b.name, "bandwidth_out_gb", (total.bandwidth * b.percent) / 100 / 1e9);
    for (const b of r.breakdown.function_execution || []) add(b.id, b.name, "gb_hours", (total.gb_hours * b.percent) / 100);
  }
  for (const r of usageRows(teamId, "builds", days, "", since)) { const total = (r.metrics.build_completed_count || 0) + (r.metrics.build_failed_count || 0); for (const b of r.breakdown.build_count || []) add(b.id, b.name, "builds", (total * b.percent) / 100); }
  return [...out.values()].map((p) => ({ ...p, requests: Math.round(p.requests), invocations: Math.round(p.invocations), bandwidth_out_gb: Math.round(p.bandwidth_out_gb * 100) / 100, gb_hours: Math.round(p.gb_hours * 10) / 10, builds: Math.round(p.builds) })).sort((a, b) => b.requests - a.requests);
}

export interface StoreUsageDay { day: string; size_gb: number | null; objects: number | null; simple_requests: number; advanced_requests: number }
/**
 * One Blob store's daily numbers from the team's `storage_blob` rows: Vercel breaks size, object count and requests
 * down per store in whole percent, applied here to the day's totals. Marketplace stores (Neon, Redis) are not in
 * these rows; their period usage comes with the store object itself.
 */
export function storeUsageSeries(teamId: string, storeId: string, days: number): StoreUsageDay[] {
  const pct = (b: any, key: string) => { const row = (b?.[key] || []).find((x: any) => x.id === storeId); return row ? Number(row.percent) / 100 : null; };
  return usageRows(teamId, "storage_blob", days).map((r) => {
    const m = r.metrics; const b = r.breakdown;
    const size = pct(b, "blob_size_in_bytes"); const objs = pct(b, "blob_object_count"); const simple = pct(b, "blob_simple_request_count") ?? 0; const adv = pct(b, "blob_advanced_request_count") ?? 0;
    return { day: r.date, size_gb: size != null && m.blob_size_in_bytes != null ? Math.round(((m.blob_size_in_bytes * size) / 1e9) * 100) / 100 : null, objects: objs != null && m.blob_object_count != null ? Math.round(m.blob_object_count * objs) : null, simple_requests: Math.round((m.blob_simple_request_count || 0) * simple), advanced_requests: Math.round((m.blob_advanced_request_count || 0) * adv) };
  }).filter((d) => d.size_gb != null || d.objects != null || d.simple_requests || d.advanced_requests);
}

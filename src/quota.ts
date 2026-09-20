/**
 * Ceilings on what costs money or touches instances without a person watching: agent dispatches per hour and
 * per day, SSM probes per hour. Counted from the tables (agent_runs, instance_metrics) plus an in-memory record of
 * probe attempts that failed before storing anything, so a loop cannot spend through a quota by failing. A hit
 * raises one open `quota` alert and refuses the call with a message that says when it frees up. The limits are
 * runtime settings (Settings page); the probe pass's own per-pass cap stays.
 */
import { config } from "./config.js";
import { db } from "./db.js";

export class QuotaError extends Error { constructor(public quota: string, message: string) { super(message); this.name = "QuotaError"; } }

const probeAttempts: number[] = [];
const noteProbeAttempt = () => { const now = Date.now(); probeAttempts.push(now); while (probeAttempts.length && probeAttempts[0] < now - 3600e3) probeAttempts.shift(); };

export interface QuotaStatus { quota: "agent_runs_hour" | "agent_runs_day" | "probes_hour"; used: number; limit: number; window: string; resets_in_min: number | null }

function agentRuns(sinceMinutes: number): { n: number; oldest: string | null } {
  const r = db.prepare("select count(*) as n, min(created_at) as oldest from agent_runs where datetime(created_at) > datetime('now', ?)").get(`-${sinceMinutes} minutes`) as { n: number; oldest: string | null };
  return r;
}
function probesLastHour(): number {
  const stored = (db.prepare("select count(*) as n from instance_metrics where datetime(collected_at) > datetime('now', '-60 minutes')").get() as { n: number }).n;
  const now = Date.now(); const failed = probeAttempts.filter((t) => t > now - 3600e3).length;
  return Math.max(stored, failed);
}
const minutesUntil = (oldest: string | null, windowMin: number) => (oldest ? Math.max(1, Math.ceil(windowMin - (Date.now() - Date.parse(`${oldest.replace(" ", "T")}Z`)) / 60000)) : null);

export function quotaStatus(): QuotaStatus[] {
  const h = agentRuns(60), d = agentRuns(1440);
  return [
    { quota: "agent_runs_hour", used: h.n, limit: config.agentRunsPerHour, window: "last 60 minutes", resets_in_min: h.n >= config.agentRunsPerHour ? minutesUntil(h.oldest, 60) : null },
    { quota: "agent_runs_day", used: d.n, limit: config.agentRunsPerDay, window: "last 24 hours", resets_in_min: d.n >= config.agentRunsPerDay ? minutesUntil(d.oldest, 1440) : null },
    { quota: "probes_hour", used: probesLastHour(), limit: config.probesPerHour, window: "last 60 minutes", resets_in_min: null },
  ];
}

function raise(quota: string, message: string): never {
  const open = db.prepare("select id from alerts where kind = 'quota' and resource = ? and acknowledged = 0 limit 1").get(quota);
  if (!open) db.prepare("insert into alerts(kind, resource, message, details) values ('quota', ?, ?, ?)").run(quota, message, JSON.stringify({ summary: message, quota, status: quotaStatus() }));
  console.warn(`[quota] ${message}`);
  throw new QuotaError(quota, message);
}

/** Call before posting an agent request. */
export function checkAgentQuota(what: string): void {
  const [h, d] = quotaStatus();
  if (h.used >= h.limit) raise("agent_runs_hour", `${what} refused: ${h.used} agent runs in the last hour, the limit is ${h.limit} (Settings > Quotas); frees up in about ${h.resets_in_min} min`);
  if (d.used >= d.limit) raise("agent_runs_day", `${what} refused: ${d.used} agent runs in the last 24 hours, the limit is ${d.limit} (Settings > Quotas); frees up in about ${d.resets_in_min} min`);
}
/** Call before sending a probe; counts the attempt. */
export function checkProbeQuota(instanceId: string): void {
  const used = probesLastHour();
  if (used >= config.probesPerHour) raise("probes_hour", `probe of ${instanceId} refused: ${used} probes in the last hour, the limit is ${config.probesPerHour} (Settings > Quotas)`);
  noteProbeAttempt();
}

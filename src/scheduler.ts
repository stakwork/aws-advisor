import cron from "node-cron";
import { dispatchNotifications } from "./notify.js";
import { dispatchActionNotifications } from "./executor.js";
import { dispatchPassReports } from "./pass_report.js";
import { cronOff } from "./cron_off.js";
import { adapters } from "./adapters/index.js";
import type { ProviderJob } from "./adapters/types.js";

export { cronOff };
export { priceCheckAndForecast } from "./adapters/aws/jobs.js";

/**
 * One loop over every registered provider's jobs (src/adapters/types.ts ProviderJob): each adapter declares its
 * collection, scans and passes with their crons, and the scheduler runs them all the same way. No job is named
 * here; a new provider's jobs are scheduled by registering its adapter.
 */

const tasks: { stop: () => void }[] = [];

function schedule(name: string, expr: string, fn: () => void): string | null {
  if (cronOff(expr)) { console.log(`${name} disabled`); return null; }
  if (!cron.validate(expr)) { console.error(`${name}: "${expr}" is not a valid cron expression; disabled`); return null; }
  // every firing is logged, so "did the cron run" is always answerable from the log
  tasks.push(cron.schedule(expr, () => { console.log(`[cron] ${name} fired ("${expr}")`); fn(); }));
  console.log(`${name}: "${expr}"`);
  return expr;
}

/** Stops every scheduled task and starts them again from the current settings (after a cron was changed in Settings). */
export function restartScheduler(): ReturnType<typeof startScheduler> {
  for (const t of tasks.splice(0)) { try { t.stop(); } catch { /* already stopped */ } }
  console.log("[scheduler] restarting on the current settings");
  return startScheduler();
}

/** Every provider's jobs by their settings key, with the provider that owns each. */
export function allJobs(): Record<string, ProviderJob & { provider: string }> {
  const out: Record<string, ProviderJob & { provider: string }> = {};
  for (const a of adapters()) for (const j of a.jobs) out[j.key] = { ...j, provider: a.id };
  return out;
}

const jobInFlight = new Set<string>();

/** Runs one job now, as the cron would, and reports what it did or why it did nothing. The provider's own check (credentials) is the same. */
export async function runJobNow(key: string, trigger = "manual"): Promise<string> {
  const job = allJobs()[key]; if (!job) throw new Error(`no job for ${key}`);
  const t = job.tag || key;
  const blocked = job.blocked?.() ?? null;
  if (blocked) { console.log(`[${t}] ${blocked}`); return blocked; }
  if (jobInFlight.has(key)) { const m = "skipped: already running"; console.log(`[${t}] ${m}`); return m; }
  jobInFlight.add(key);
  console.log(`[${t}] started (${trigger})`);
  try { const m = await job.run(); console.log(`[${t}] ${m}`); return m; }
  catch (e: any) { console.error(`[${t}] failed: ${e?.message || e}`); throw e; }
  finally {
    jobInFlight.delete(key);
    // Whatever the job raised goes out now (src/notify.ts); a failure there is logged, never the job's.
    dispatchNotifications().catch((e: any) => console.error(`[notify] dispatch failed: ${e?.message || e}`));
    dispatchActionNotifications().catch((e: any) => console.error(`[executor] notify failed: ${e?.message || e}`));
    dispatchPassReports().catch((e: any) => console.error(`[pass-report] notify failed: ${e?.message || e}`));
  }
}

export function startScheduler(): Record<string, string | null> {
  const out: Record<string, string | null> = {};
  for (const [key, job] of Object.entries(allJobs())) {
    const off = job.disabled?.() ?? null;
    if (off) { console.log(`${job.schedule_name} disabled: ${off}`); out[key] = null; continue; }
    out[key] = schedule(job.schedule_name, job.cron(), () => { runJobNow(key, "cron").catch(() => { /* logged */ }); });
  }
  return out;
}

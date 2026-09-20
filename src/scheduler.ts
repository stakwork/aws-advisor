import cron from "node-cron";
import { config } from "./config.js";
import { isBusy, startRun } from "./collector.js";
import { hasConnectionFile } from "./steampipe.js";
import { watchOnce } from "./watcher.js";
import { probePass } from "./probe_pass.js";
import { credentialGate } from "./gate.js";
import { refreshSpend } from "./spend.js";
import { refreshBaselines } from "./baselines.js";
import { runReview } from "./review.js";
import { dispatchObservation } from "./observe.js";
import { refreshLogs } from "./logs.js";
import { refreshTrail } from "./trail.js";

export const cronOff = (expr: string) => !expr || /^(off|none|false|0)$/i.test(expr);

function schedule(name: string, expr: string, fn: () => void): string | null {
  if (cronOff(expr)) { console.log(`${name} disabled`); return null; }
  if (!cron.validate(expr)) { console.error(`${name}: "${expr}" is not a valid cron expression; disabled`); return null; }
  cron.schedule(expr, fn);
  console.log(`${name}: "${expr}"`);
  return expr;
}

let watching = false;

/** Starts the scheduled full run (RUN_CRON) and the lightweight watcher (WATCH_CRON). */
export function startScheduler(): { run: string | null; watch: string | null; probe: string | null; spend: string | null; baselines: string | null; review: string | null; observe: string | null; logs: string | null } {
  const run = schedule("Scheduler (RUN_CRON)", config.runCron, async () => {
    if (isBusy()) { console.log("[scheduler] skipped: a run is already in progress"); return; }
    if (!hasConnectionFile()) { console.log("[scheduler] skipped: AWS credentials are not configured"); return; }
    if (!(await credentialGate("scheduler")).ok) return;
    try {
      const id = startRun("schedule");
      console.log(`[scheduler] started run #${id}`);
    } catch (e: any) {
      console.error(`[scheduler] could not start a run: ${e?.message || e}`);
    }
  });
  const watch = schedule("Watcher (WATCH_CRON)", config.watchCron, () => {
    if (watching) { console.log("[watcher] skipped: previous sample still collecting"); return; }
    if (!hasConnectionFile()) return;
    watching = true;
    watchOnce()
      .then((r) => console.log(`[watcher] sample ${r.sample_id}: ${r.samples} values, ${r.alerts} alerts${r.errors.length ? `, errors: ${r.errors.join("; ")}` : ""}`))
      .catch((e: any) => console.error(`[watcher] failed: ${e?.message || e}`))
      .finally(() => { watching = false; });
  });
  const probe = schedule("Probe pass (PROBE_CRON)", config.probeCron, () => {
    if (!hasConnectionFile()) return;
    probePass().catch((e: any) => console.error(`[probe-pass] failed: ${e?.message || e}`));
  });
  // refreshSpend runs the credential gate itself and skips when the last fetch is younger than 6 hours.
  const spend = schedule("Spend refresh (SPEND_CRON)", config.spendCron, () => {
    if (!hasConnectionFile()) return;
    refreshSpend()
      .then((r) => console.log(`[spend] ${r.refreshed ? `${r.days} days stored` : `skipped: ${r.skipped || r.error}`}`))
      .catch((e: any) => console.error(`[spend] failed: ${e?.message || e}`));
  });
  const baselines = schedule("Baselines (BASELINE_CRON)", config.baselineCron, () => {
    if (!hasConnectionFile()) return;
    refreshBaselines((l) => console.log(`[baselines] ${l}`))
      .then((r) => console.log(`[baselines] nat ${r.nat}, cpu ${r.cpu}, probes ${r.probes}, spend ${r.spend} in ${r.took_ms} ms${r.errors.length ? `; errors: ${r.errors.join("; ")}` : ""}`))
      .catch((e: any) => console.error(`[baselines] failed: ${e?.message || e}`));
  });
  const review = schedule("Daily review (REVIEW_CRON)", config.reviewCron, () => {
    runReview((l) => console.log(`[review] ${l}`)).catch((e: any) => console.error(`[review] failed: ${e?.message || e}`));
  });
  const observe = config.repo2graphUrl ? schedule("Observation (OBSERVE_CRON)", config.observeCron, () => {
    dispatchObservation().then((r) => console.log(`[observe] dispatched ${r.requestId}`)).catch((e: any) => console.error(`[observe] not dispatched: ${e?.message || e}`));
  }) : null;
  const logs = schedule("Logs and CloudTrail (LOGS_CRON)", config.logsCron, () => {
    if (!hasConnectionFile()) return;
    refreshLogs((l) => console.log(`[logs] ${l}`)).catch((e: any) => console.error(`[logs] failed: ${e?.message || e}`))
      .then(() => refreshTrail(26, (l) => console.log(`[cloudtrail] ${l}`))).catch((e: any) => console.error(`[cloudtrail] failed: ${e?.message || e}`));
  });
  return { run, watch, probe, spend, baselines, review, observe, logs };
}

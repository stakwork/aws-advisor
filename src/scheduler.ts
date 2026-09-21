import cron from "node-cron";
import { config } from "./config.js";
import { isBusy, startRun } from "./collector.js";
import { hasConnectionFile } from "./steampipe.js";
import { watchOnce } from "./watcher.js";
import { probePass } from "./probe_pass.js";
import { credentialGate } from "./gate.js";
import { refreshSpend } from "./spend.js";
import { getReconciliation, lastFullMonth, reconcileMonth } from "./reconcile.js";
import { runForecast } from "./forecast.js";
import { localDay } from "./localdate.js";
import { refreshBaselines } from "./baselines.js";
import { runReview } from "./review.js";
import { dispatchObservation } from "./observe.js";
import { refreshLogs } from "./logs.js";
import { refreshTrail } from "./trail.js";
import { runVerifications } from "./verify.js";
import { refreshCommitments } from "./commitments.js";
import { refreshS3Inventory } from "./s3_inventory.js";

export const cronOff = (expr: string) => !expr || /^(off|none|false|0)$/i.test(expr);

const tasks: { stop: () => void }[] = [];

function schedule(name: string, expr: string, fn: () => void): string | null {
  if (cronOff(expr)) { console.log(`${name} disabled`); return null; }
  if (!cron.validate(expr)) { console.error(`${name}: "${expr}" is not a valid cron expression; disabled`); return null; }
  tasks.push(cron.schedule(expr, fn));
  console.log(`${name}: "${expr}"`);
  return expr;
}

/** Stops every scheduled task and starts them again from the current settings (after a cron was changed in Settings). */
export function restartScheduler(): ReturnType<typeof startScheduler> {
  for (const t of tasks.splice(0)) { try { t.stop(); } catch { /* already stopped */ } }
  console.log("[scheduler] restarting on the current settings");
  return startScheduler();
}

let watching = false;

/** Starts the scheduled full run (RUN_CRON) and the lightweight watcher (WATCH_CRON). */
/** The month's forecast after every spend refresh; the last full month's price check once, from the 3rd, when it is missing. */
export async function priceCheckAndForecast(): Promise<void> {
  const last = lastFullMonth();
  if (!getReconciliation(last) && Number(localDay().slice(8, 10)) >= 3) {
    try { const r = await reconcileMonth(last, (l) => console.log(`[price-check] ${l}`)); if (!r.eval.every((e) => e.pass)) console.warn(`[price-check] ${last}: ${r.eval.filter((e) => !e.pass).map((e) => e.criterion).join("; ")}`); }
    catch (e: any) { console.error(`[price-check] failed: ${e?.message || e}`); }
  }
  await runForecast((l) => console.log(`[forecast] ${l}`));
}

export function startScheduler(): { run: string | null; watch: string | null; probe: string | null; spend: string | null; baselines: string | null; review: string | null; observe: string | null; logs: string | null; verify: string | null } {
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
      .catch((e: any) => console.error(`[spend] failed: ${e?.message || e}`))
      .then(() => refreshCommitments((l) => console.log(`[commitments] ${l}`)))
      .catch((e: any) => console.error(`[commitments] failed: ${e?.message || e}`))
      .then(() => priceCheckAndForecast())
      .catch((e: any) => console.error(`[forecast] failed: ${e?.message || e}`));
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
      .then(() => refreshTrail(26, (l) => console.log(`[cloudtrail] ${l}`))).catch((e: any) => console.error(`[cloudtrail] failed: ${e?.message || e}`))
      .then(() => refreshS3Inventory((l) => console.log(`[s3] ${l}`))).catch((e: any) => console.error(`[s3] failed: ${e?.message || e}`));
  });
  const verify = schedule("Saving verification (VERIFY_CRON)", config.verifyCron, () => {
    if (!hasConnectionFile()) return;
    runVerifications({ onLog: (l) => console.log(`[verify] ${l}`) }).catch((e: any) => console.error(`[verify] failed: ${e?.message || e}`));
  });
  return { run, watch, probe, spend, baselines, review, observe, logs, verify };
}

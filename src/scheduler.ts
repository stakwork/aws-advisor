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
import { s3UsagePass } from "./s3_usage.js";
import { usageProfilePass } from "./usage_profile.js";
import { usageReviewPass } from "./usage_review.js";
import { usageInvestigationPass } from "./usage_agent.js";
import { dispatchNotifications } from "./notify.js";
import { dispatchActionNotifications, runExecutorPass } from "./executor.js";
import { dispatchPassReports } from "./pass_report.js";
import { refreshSwarmCosts } from "./swarm_costs.js";
import { refreshTagHygiene } from "./tag_hygiene.js";
import { mirrorSwarmCosts } from "./swarm_costs_graph.js";
import { mirrorKnowledgeInBackground } from "./graph_mirror.js";
import { refreshStatusChecks } from "./status_checks.js";

export const cronOff = (expr: string) => !expr || /^(off|none|false|0)$/i.test(expr);

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

/** Every cron job by its settings key: the same function runs on schedule and from "Run now" on the Settings page. */
export const JOBS: Record<string, { label: string; run: () => Promise<string> }> = {
  runCron: { label: "Collection run", run: async () => {
    if (isBusy()) return "skipped: a run is already in progress";
    if (!(await credentialGate("scheduler")).ok) return "skipped: AWS credentials are not working";
    const id = startRun("schedule");
    return `started run #${id}`;
  } },
  watchCron: { label: "Watcher", run: async () => {
    if (watching) return "skipped: previous sample still collecting";
    watching = true;
    try {
      const r = await watchOnce();
      // the EC2 status checks (system, instance, EBS) on the same cadence: an alert when a box is impaired
      let status = "";
      try { const s = await refreshStatusChecks((l) => console.log(`[status-checks] ${l}`)); status = `; status checks: ${s.instances} instances, ${s.impaired} impaired, ${s.raised} raised${s.errors.length ? `, errors: ${s.errors.length}` : ""}`; }
      catch (e: any) { console.error(`[status-checks] failed: ${e?.message || e}`); status = `; status checks failed: ${e?.message || e}`; }
      return `sample ${r.sample_id}: ${r.samples} values, ${r.alerts} alerts${r.errors.length ? `, errors: ${r.errors.join("; ")}` : ""}${status}`;
    }
    finally { watching = false; }
  } },
  probeCron: { label: "Probe pass", run: async () => { const r = await probePass(); return `${r.probed.length} probed, ${r.failed.length} failed of ${r.candidates} candidates${r.databases ? `; ${r.databases.refreshed.length} database(s) profiled${r.databases.failed.length ? `, ${r.databases.failed.length} failed` : ""}` : ""}`; } },
  spendCron: { label: "Spend refresh", run: async () => {
    const r = await refreshSpend();
    console.log(`[spend] ${r.refreshed ? `${r.days} days stored` : `skipped: ${r.skipped || r.error}`}`);
    try { await refreshCommitments((l) => console.log(`[commitments] ${l}`)); } catch (e: any) { console.error(`[commitments] failed: ${e?.message || e}`); }
    try { await priceCheckAndForecast(); } catch (e: any) { console.error(`[forecast] failed: ${e?.message || e}`); }
    return r.refreshed ? `${r.days} days stored, commitments and forecast refreshed` : `spend skipped: ${r.skipped || r.error}; commitments and forecast refreshed`;
  } },
  baselineCron: { label: "Baselines", run: async () => {
    const r = await refreshBaselines((l) => console.log(`[baselines] ${l}`));
    return `nat ${r.nat}, cpu ${r.cpu}, probes ${r.probes}, spend ${r.spend} in ${r.took_ms} ms${r.errors.length ? `; errors: ${r.errors.join("; ")}` : ""}`;
  } },
  reviewCron: { label: "Daily review", run: async () => { const r: any = await runReview((l) => console.log(`[review] ${l}`)); return `${r?.instances ?? "?"} instances reviewed, ${r?.recommendations ?? 0} recommendations, ${r?.alerts ?? 0} alerts`; } },
  swarmCostCron: { label: "Cost per swarm", run: async () => { const r = await refreshSwarmCosts((l) => console.log(`[swarms] ${l}`)); mirrorSwarmCosts().catch((e: any) => console.error(`[graph] swarm costs: ${e?.message || e}`)); return `${r.swarms} swarm(s), ≈ ${r.total_usd.toFixed(2)} USD/month${r.snapshots_known ? "" : " (snapshots unknown)"}`; } },
  observeCron: { label: "Morning observation", run: async () => {
    if (!config.repo2graphUrl) return "skipped: no repo2graph URL (Settings > Agent)";
    const r = await dispatchObservation();
    return `dispatched ${r.requestId}`;
  } },
  logsCron: { label: "Logs and CloudTrail", run: async () => {
    const out: string[] = [];
    try { await refreshLogs((l) => console.log(`[logs] ${l}`)); out.push("logs"); mirrorKnowledgeInBackground("logs refresh"); } catch (e: any) { console.error(`[logs] failed: ${e?.message || e}`); out.push(`logs failed: ${e?.message || e}`); }
    try { await refreshTrail(26, (l) => console.log(`[cloudtrail] ${l}`)); out.push("cloudtrail"); } catch (e: any) { console.error(`[cloudtrail] failed: ${e?.message || e}`); out.push(`cloudtrail failed: ${e?.message || e}`); }
    try { await refreshS3Inventory((l) => console.log(`[s3] ${l}`)); out.push("s3"); } catch (e: any) { console.error(`[s3] failed: ${e?.message || e}`); out.push(`s3 failed: ${e?.message || e}`); }
    try { const r = await s3UsagePass((l) => console.log(`[s3-usage] ${l}`)); out.push(`s3 usage ${r.analysed.length}/${r.candidates}`); } catch (e: any) { console.error(`[s3-usage] failed: ${e?.message || e}`); out.push(`s3 usage failed: ${e?.message || e}`); }
    try { const r = await usageProfilePass((l) => console.log(`[usage] ${l}`)); out.push(`usage profiles ${r.profiled}, ${r.recommendations} schedule recommendation(s)`); } catch (e: any) { console.error(`[usage] failed: ${e?.message || e}`); out.push(`usage failed: ${e?.message || e}`); }
    try { const r = await usageReviewPass((l) => console.log(`[usage-review] ${l}`)); out.push(`usage review ${r.reviewed} reviewed${r.errors.length ? ` (${r.errors[0]})` : ""}`); } catch (e: any) { console.error(`[usage-review] failed: ${e?.message || e}`); out.push(`usage review failed: ${e?.message || e}`); }
    try { const r = await usageInvestigationPass((l) => console.log(`[usage-agent] ${l}`)); out.push(`usage investigations ${r.dispatched} sent of ${r.candidates} unsure`); } catch (e: any) { console.error(`[usage-agent] failed: ${e?.message || e}`); out.push(`usage investigations failed: ${e?.message || e}`); }
    try { const r = await refreshTagHygiene((l) => console.log(`[tags] ${l}`)); out.push(`tags ${r.missing} missing, ${r.opt_in} opt-in`); } catch (e: any) { console.error(`[tags] failed: ${e?.message || e}`); out.push(`tags failed: ${e?.message || e}`); }
    return out.join(", ");
  } },
  actCron: { label: "Auto-actions pass", run: async () => {
    const r = await runExecutorPass("schedule");
    return `${r.mode}: ${r.proposed} proposed (${r.fresh} new), ${r.applied} applied, ${r.verified} verified, ${r.failed} failed, ${r.refused} refused, ${r.stale} stale${r.errors.length ? `; errors: ${r.errors.join("; ")}` : ""}`;
  } },
  pressureCron: { label: "Pressure check", run: async () => {
    const r = await runExecutorPass("pressure", { kinds: ["beanstalk_pressure"] });
    return `${r.mode}: ${r.proposed} proposed, ${r.applied} applied, ${r.failed} failed${r.notes.length ? `; ${r.notes.slice(0, 3).join("; ")}` : ""}${r.errors.length ? `; errors: ${r.errors.join("; ")}` : ""}`;
  } },
  verifyCron: { label: "Saving verification", run: async () => { const r: any = await runVerifications({ onLog: (l) => console.log(`[verify] ${l}`) }); return typeof r === "object" && r ? JSON.stringify(r).slice(0, 200) : "done"; } },
};

const tag: Record<string, string> = { swarmCostCron: "swarms", runCron: "scheduler", watchCron: "watcher", probeCron: "probe-pass", spendCron: "spend", baselineCron: "baselines", reviewCron: "review", observeCron: "observe", logsCron: "logs", verifyCron: "verify", actCron: "executor", pressureCron: "pressure" };
const jobInFlight = new Set<string>();

/** Runs one job now, as the cron would, and reports what it did or why it did nothing. The credential check is the same. */
export async function runJobNow(key: string, trigger = "manual"): Promise<string> {
  const job = JOBS[key]; if (!job) throw new Error(`no job for ${key}`);
  const t = tag[key] || key;
  if (key !== "reviewCron" && !hasConnectionFile()) { const m = "skipped: AWS credentials are not configured (Settings > AWS access)"; console.log(`[${t}] ${m}`); return m; }
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
  const crons: Record<string, string> = { swarmCostCron: config.reviewCron, runCron: config.runCron, watchCron: config.watchCron, probeCron: config.probeCron, spendCron: config.spendCron, baselineCron: config.baselineCron, reviewCron: config.reviewCron, observeCron: config.observeCron, logsCron: config.logsCron, verifyCron: config.verifyCron, actCron: config.actCron, pressureCron: config.actPressureCron };
  const names: Record<string, string> = { swarmCostCron: "Cost per swarm (REVIEW_CRON)", runCron: "Scheduler (RUN_CRON)", watchCron: "Watcher (WATCH_CRON)", probeCron: "Probe pass (PROBE_CRON)", spendCron: "Spend refresh (SPEND_CRON)", baselineCron: "Baselines (BASELINE_CRON)", reviewCron: "Daily review (REVIEW_CRON)", observeCron: "Observation (OBSERVE_CRON)", logsCron: "Logs and CloudTrail (LOGS_CRON)", verifyCron: "Saving verification (VERIFY_CRON)", actCron: "Auto-actions pass (ACT_CRON)", pressureCron: "Pressure check (ACT_PRESSURE_CRON)" };
  for (const key of Object.keys(JOBS)) {
    if (key === "observeCron" && !config.repo2graphUrl) { console.log("Observation (OBSERVE_CRON) disabled: no repo2graph URL (Settings > Agent)"); out[key] = null; continue; }
    out[key] = schedule(names[key], crons[key], () => { runJobNow(key, "cron").catch(() => { /* logged */ }); });
  }
  return out;
}

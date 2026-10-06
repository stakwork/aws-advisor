import { config } from "../../config.js";
import { hasConnectionFile } from "../../steampipe.js";
import type { ProviderJob } from "../types.js";
import { cronOff } from "../../cron_off.js";

/**
 * The AWS adapter's scheduled jobs: the collection run, the security scan, the watcher, the probe passes, spend,
 * baselines, the review, logs and CloudTrail, the executor's passes and the rest. Each one is the same function on
 * its cron and behind "Run now" (src/scheduler.ts runs every adapter's jobs). Everything but the daily review needs
 * the AWS credentials; the observation needs the agent's URL to be scheduled at all.
 */

let watching = false;

/** The month's forecast after every spend refresh; the last full month's price check once, from the 3rd, when it is missing. */
export async function priceCheckAndForecast(): Promise<void> {
  const last = (await import("../../reconcile.js")).lastFullMonth();
  if (!(await import("../../reconcile.js")).getReconciliation(last) && Number((await import("../../localdate.js")).localDay().slice(8, 10)) >= 3) {
    try { const r = await (await import("../../reconcile.js")).reconcileMonth(last, (l) => console.log(`[price-check] ${l}`)); if (!r.eval.every((e) => e.pass)) console.warn(`[price-check] ${last}: ${r.eval.filter((e) => !e.pass).map((e) => e.criterion).join("; ")}`); }
    catch (e: any) { console.error(`[price-check] failed: ${e?.message || e}`); }
  }
  await (await import("../../forecast.js")).runForecast((l) => console.log(`[forecast] ${l}`));
}

/** Every cron job by its settings key: the same function runs on schedule and from "Run now" on the Settings page. */
const BODIES: Record<string, { label: string; run: () => Promise<string> }> = {
  runCron: { label: "Collection run", run: async () => {
    if ((await import("../../collector.js")).isBusy()) return "skipped: a run is already in progress";
    if (!(await (await import("../../gate.js")).credentialGate("scheduler")).ok) return "skipped: AWS credentials are not working";
    const id = (await import("../../collector.js")).startRun("schedule");
    return `started run #${id}`;
  } },
  complianceCron: { label: "Security scan", run: async () => {
    if ((await import("../../compliance.js")).complianceBusy()) return "skipped: a scan is already in progress";
    if (!(await (await import("../../gate.js")).credentialGate("compliance")).ok) return "skipped: AWS credentials are not working";
    return `started security scan #${(await import("../../compliance.js")).startComplianceScan("schedule")}`;
  } },
  watchCron: { label: "Watcher", run: async () => {
    if (watching) return "skipped: previous sample still collecting";
    watching = true;
    try {
      const r = await (await import("../../watcher.js")).watchOnce();
      // the EC2 status checks (system, instance, EBS) on the same cadence: an alert when a box is impaired
      let status = "";
      try { const s = await (await import("../../status_checks.js")).refreshStatusChecks((l) => console.log(`[status-checks] ${l}`)); status = `; status checks: ${s.instances} instances, ${s.impaired} impaired, ${s.raised} raised${s.errors.length ? `, errors: ${s.errors.length}` : ""}`; }
      catch (e: any) { console.error(`[status-checks] failed: ${e?.message || e}`); status = `; status checks failed: ${e?.message || e}`; }
      return `sample ${r.sample_id}: ${r.samples} values, ${r.alerts} alerts${r.errors.length ? `, errors: ${r.errors.join("; ")}` : ""}${status}`;
    }
    finally { watching = false; }
  } },
  probeCron: { label: "Probe pass: host", run: async () => { const r = await (await import("../../probe_pass.js")).probePass("host"); return `${r.probed.length} probed, ${r.failed.length} failed of ${r.candidates} candidates${r.databases ? `; ${r.databases.refreshed.length} database(s) profiled${r.databases.failed.length ? `, ${r.databases.failed.length} failed` : ""}` : ""}`; } },
  probeDockerCron: { label: "Probe pass: containers and activity", run: async () => { const r = await (await import("../../probe_pass.js")).probePass("docker"); return `${r.probed.length} probed, ${r.failed.length} failed of ${r.candidates} candidates`; } },
  probeAppsCron: { label: "Probe pass: programs and ports", run: async () => { const r = await (await import("../../probe_pass.js")).probePass("apps"); return `${r.probed.length} probed, ${r.failed.length} failed of ${r.candidates} candidates`; } },
  probeSoftwareCron: { label: "Probe pass: installed software", run: async () => { const r = await (await import("../../probe_pass.js")).probePass("software"); return `${r.probed.length} probed, ${r.failed.length} failed of ${r.candidates} candidates`; } },
  vulnCron: { label: "Vulnerability match", run: async () => {
    const { scanVulnerabilities } = await import("../../software_vulns.js");
    const r = await scanVulnerabilities({ trigger: "cron" });
    try { const { mirrorSoftware } = await import("../../graph_software.js"); await mirrorSoftware(); } catch (e: any) { console.error(`[graph] software: ${e?.message || e}`); }
    return `${r.asked} of ${r.queries} package versions asked, ${r.fetched} advisories read, ${r.matches} matches (${r.vulns} advisories)${r.unsupported.length ? `; not matchable: ${r.unsupported.map((u) => `${u.os} (${u.instances})`).join(", ")}` : ""}`;
  } },
  playbookCron: { label: "Playbooks from sources", run: async () => {
    const { controlsDue, generatePlaybooks } = await import("../../playbook_gen.js");
    if (!config.repo2graphUrl) return "skipped: no repo2graph URL (Settings > Agent)";
    const due = controlsDue({ limit: 12 });
    if (!due.length) return "nothing due: every playbook is current";
    const r = await generatePlaybooks(due.map((d) => d.control_id), { trigger: "cron" });
    return `${r.jobs.length} agent run(s) for ${r.jobs.reduce((n, j) => n + j.control_ids.length, 0)} controls (${due.slice(0, 3).map((d) => `${d.control_id.replace(/^aws_\w+\.control\./, "")}: ${d.why}`).join("; ")}${due.length > 3 ? "; ..." : ""})${r.skipped.length ? `; skipped ${r.skipped.length}` : ""}`;
  } },
  spendCron: { label: "Spend refresh", run: async () => {
    const r = await (await import("../../spend.js")).refreshSpend();
    console.log(`[spend] ${r.refreshed ? `${r.days} days stored` : `skipped: ${r.skipped || r.error}`}`);
    try { await (await import("../../commitments.js")).refreshCommitments((l) => console.log(`[commitments] ${l}`)); } catch (e: any) { console.error(`[commitments] failed: ${e?.message || e}`); }
    try { await priceCheckAndForecast(); } catch (e: any) { console.error(`[forecast] failed: ${e?.message || e}`); }
    return r.refreshed ? `${r.days} days stored, commitments and forecast refreshed` : `spend skipped: ${r.skipped || r.error}; commitments and forecast refreshed`;
  } },
  baselineCron: { label: "Baselines", run: async () => {
    const r = await (await import("../../baselines.js")).refreshBaselines((l) => console.log(`[baselines] ${l}`));
    return `nat ${r.nat}, cpu ${r.cpu}, probes ${r.probes}, spend ${r.spend} in ${r.took_ms} ms${r.errors.length ? `; errors: ${r.errors.join("; ")}` : ""}`;
  } },
  reviewCron: { label: "Daily review", run: async () => { const r: any = await (await import("../../review.js")).runReview((l) => console.log(`[review] ${l}`)); return `${r?.instances ?? "?"} instances reviewed, ${r?.recommendations ?? 0} recommendations, ${r?.alerts ?? 0} alerts`; } },
  swarmCostCron: { label: "Cost per swarm", run: async () => { const r = await (await import("../../swarm_costs.js")).refreshSwarmCosts((l) => console.log(`[swarms] ${l}`)); (await import("../../swarm_costs_graph.js")).mirrorSwarmCosts().catch((e: any) => console.error(`[graph] swarm costs: ${e?.message || e}`)); return `${r.swarms} swarm(s), ≈ ${r.total_usd.toFixed(2)} USD/month${r.snapshots_known ? "" : " (snapshots unknown)"}`; } },
  observeCron: { label: "Morning observation", run: async () => {
    if (!config.repo2graphUrl) return "skipped: no repo2graph URL (Settings > Agent)";
    const r = await (await import("../../observe.js")).dispatchObservation();
    return `dispatched ${r.requestId}`;
  } },
  logsCron: { label: "Logs and CloudTrail", run: async () => {
    const out: string[] = [];
    try { await (await import("../../logs.js")).refreshLogs((l) => console.log(`[logs] ${l}`)); out.push("logs"); (await import("../../graph_mirror.js")).mirrorKnowledgeInBackground("logs refresh"); } catch (e: any) { console.error(`[logs] failed: ${e?.message || e}`); out.push(`logs failed: ${e?.message || e}`); }
    try { await (await import("../../trail.js")).refreshTrail(26, (l) => console.log(`[cloudtrail] ${l}`)); out.push("cloudtrail"); } catch (e: any) { console.error(`[cloudtrail] failed: ${e?.message || e}`); out.push(`cloudtrail failed: ${e?.message || e}`); }
    try { const r = await (await import("../../cloud_notifications.js")).refreshCloudNotifications(undefined, (l) => console.log(`[notifications] ${l}`)); out.push(`notifications ${r.events}`); } catch (e: any) { console.error(`[notifications] failed: ${e?.message || e}`); out.push(`notifications failed: ${e?.message || e}`); }
    try { await (await import("../../s3_inventory.js")).refreshS3Inventory((l) => console.log(`[s3] ${l}`)); out.push("s3"); } catch (e: any) { console.error(`[s3] failed: ${e?.message || e}`); out.push(`s3 failed: ${e?.message || e}`); }
    try { const r = await (await import("../../s3_usage.js")).s3UsagePass((l) => console.log(`[s3-usage] ${l}`)); out.push(`s3 usage ${r.analysed.length}/${r.candidates}`); } catch (e: any) { console.error(`[s3-usage] failed: ${e?.message || e}`); out.push(`s3 usage failed: ${e?.message || e}`); }
    try { const r = await (await import("../../usage_profile.js")).usageProfilePass((l) => console.log(`[usage] ${l}`)); out.push(`usage profiles ${r.profiled}, ${r.recommendations} schedule recommendation(s)`); } catch (e: any) { console.error(`[usage] failed: ${e?.message || e}`); out.push(`usage failed: ${e?.message || e}`); }
    try { const r = await (await import("../../usage_review.js")).usageReviewPass((l) => console.log(`[usage-review] ${l}`)); out.push(`usage review ${r.reviewed} reviewed${r.errors.length ? ` (${r.errors[0]})` : ""}`); } catch (e: any) { console.error(`[usage-review] failed: ${e?.message || e}`); out.push(`usage review failed: ${e?.message || e}`); }
    try { const r = await (await import("../../usage_agent.js")).usageInvestigationPass((l) => console.log(`[usage-agent] ${l}`)); out.push(`usage investigations ${r.dispatched} sent of ${r.candidates} unsure`); } catch (e: any) { console.error(`[usage-agent] failed: ${e?.message || e}`); out.push(`usage investigations failed: ${e?.message || e}`); }
    try { const r = await (await import("../../tag_hygiene.js")).refreshTagHygiene((l) => console.log(`[tags] ${l}`)); out.push(`tags ${r.missing} missing, ${r.opt_in} opt-in`); } catch (e: any) { console.error(`[tags] failed: ${e?.message || e}`); out.push(`tags failed: ${e?.message || e}`); }
    return out.join(", ");
  } },
  actCron: { label: "Auto-actions pass", run: async () => {
    const r = await (await import("../../executor.js")).runExecutorPass("schedule");
    return `${r.mode}: ${r.proposed} proposed (${r.fresh} new), ${r.applied} applied, ${r.verified} verified, ${r.failed} failed, ${r.refused} refused, ${r.stale} stale${r.errors.length ? `; errors: ${r.errors.join("; ")}` : ""}`;
  } },
  pressureCron: { label: "Pressure check", run: async () => {
    const r = await (await import("../../executor.js")).runExecutorPass("pressure", { kinds: ["beanstalk_pressure"] });
    return `${r.mode}: ${r.proposed} proposed, ${r.applied} applied, ${r.failed} failed${r.notes.length ? `; ${r.notes.slice(0, 3).join("; ")}` : ""}${r.errors.length ? `; errors: ${r.errors.join("; ")}` : ""}`;
  } },
  // CloudTrail delivers 5 to 15 minutes late: alerts still waiting for their event are looked at again between
  // watcher samples (src/alert_cause.ts), and the ones explained go out with their "Why:" (the dispatch after every job).
  alertCauses: { label: "Alert causes", run: async () => {
    const r = await (await import("../../alert_cause.js")).attributePendingAlerts();
    if (r.found) (await import("../../graph_mirror.js")).mirrorAlertsInBackground();
    return `${r.found} alert cause(s) found`;
  } },
  verifyCron: { label: "Saving verification", run: async () => { const r: any = await (await import("../../verify.js")).runVerifications({ onLog: (l) => console.log(`[verify] ${l}`) }); return typeof r === "object" && r ? JSON.stringify(r).slice(0, 200) : "done"; } },
};

const CRONS: Record<string, () => string> = { alertCauses: () => (cronOff(config.watchCron) ? "" : "*/10 * * * *"), swarmCostCron: () => config.reviewCron, runCron: () => config.runCron, complianceCron: () => config.complianceCron, watchCron: () => config.watchCron, probeCron: () => config.probeCron, probeDockerCron: () => config.probeDockerCron, probeAppsCron: () => config.probeAppsCron, probeSoftwareCron: () => config.probeSoftwareCron, vulnCron: () => config.vulnCron, playbookCron: () => config.playbookCron, spendCron: () => config.spendCron, baselineCron: () => config.baselineCron, reviewCron: () => config.reviewCron, observeCron: () => config.observeCron, logsCron: () => config.logsCron, verifyCron: () => config.verifyCron, actCron: () => config.actCron, pressureCron: () => config.actPressureCron };
const NAMES: Record<string, string> = { alertCauses: "Alert causes (every 10 minutes)", swarmCostCron: "Cost per swarm (REVIEW_CRON)", runCron: "Scheduler (RUN_CRON)", complianceCron: "Security scan (COMPLIANCE_CRON)", watchCron: "Watcher (WATCH_CRON)", probeCron: "Probe pass: host (PROBE_CRON)", probeDockerCron: "Probe pass: containers (PROBE_DOCKER_CRON)", probeAppsCron: "Probe pass: programs and ports (PROBE_APPS_CRON)", probeSoftwareCron: "Probe pass: installed software (PROBE_SOFTWARE_CRON)", vulnCron: "Vulnerability match (VULN_CRON)", playbookCron: "Playbooks from sources (PLAYBOOK_CRON)", spendCron: "Spend refresh (SPEND_CRON)", baselineCron: "Baselines (BASELINE_CRON)", reviewCron: "Daily review (REVIEW_CRON)", observeCron: "Observation (OBSERVE_CRON)", logsCron: "Logs and CloudTrail (LOGS_CRON)", verifyCron: "Saving verification (VERIFY_CRON)", actCron: "Auto-actions pass (ACT_CRON)", pressureCron: "Pressure check (ACT_PRESSURE_CRON)" };
const TAGS: Record<string, string> = { alertCauses: "cause", swarmCostCron: "swarms", runCron: "scheduler", complianceCron: "compliance", watchCron: "watcher", probeCron: "probe-pass:host", probeDockerCron: "probe-pass:docker", probeAppsCron: "probe-pass:apps", probeSoftwareCron: "probe-pass:software", vulnCron: "vulns", playbookCron: "playbooks", spendCron: "spend", baselineCron: "baselines", reviewCron: "review", observeCron: "observe", logsCron: "logs", verifyCron: "verify", actCron: "executor", pressureCron: "pressure" };

const awsBlocked = () => (hasConnectionFile() ? null : "skipped: AWS credentials are not configured (Settings > AWS access)");

export const AWS_JOBS: ProviderJob[] = Object.entries(BODIES).map(([key, j]) => ({
  key, label: j.label, schedule_name: NAMES[key] ?? key, tag: TAGS[key] ?? key, cron: CRONS[key] ?? (() => ""), run: j.run,
  // the review reads what is stored and runs without credentials; the observation is not scheduled without the agent
  blocked: key === "reviewCron" || key === "alertCauses" ? undefined : awsBlocked,
  disabled: key === "observeCron" ? () => (config.repo2graphUrl ? null : "no repo2graph URL (Settings > Agent)") : undefined,
}));

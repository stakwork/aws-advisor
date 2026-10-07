import { allJobs, runJobNow } from "../scheduler.js";
import { listAgentRuns } from "../graph_agent_runs.js";
import { adapters } from "../adapters/index.js";
import { belowBar } from "../rubric.js";
import { taskFor } from "../tasks.js";
import { Router, type Request } from "express";
import { authMiddleware, signToken } from "../auth.js";
import { config } from "../config.js";
import { db, getJsonSetting, setSetting } from "../db.js";
import { isBusy, runEvents, startRun } from "../collector.js";
import { ALL_BENCHMARKS, DEFAULT_BENCHMARKS } from "../powerpipe.js";
import { clearConnection, credentialsMeta, hasConnectionFile, reloadSteampipeService, sdkIdentity, testConnection, updateCredentialsMeta, writeConnection } from "../steampipe.js";
import { CREDENTIAL_SOURCES, DEFAULT_CREDENTIAL_SOURCE, PROFILE_NAME_RE, ROLE_ARN_RE, validateSettings } from "../aws_config.js";
import { listAccounts, memberConnections } from "../accounts.js";
import { dispatchToAgent, handleAgentResult, openAgentEvents, pollAgentResult } from "../agent.js";
import { getRunChanges } from "../changes.js";
import { listIamUsers, iamSummary } from "../iam_inventory.js";
import { ssoSummary } from "../sso_inventory.js";
import { proposeReadPolicyUpdates } from "../actions/read_policy.js";
import { isAccountTarget, dismissAccountChange, noteAccountChange, pendingAccountChange, purgeAccountData, purgePreview, wipeAllData, wipePreview } from "../purge.js";
import { postRejectionLearning } from "../learnings.js";
import { PROBE_KINDS, type ProbeKind, ProbeError, instanceMetrics, latestProbe, probeDocument, probeDocumentInfo, probeDocumentsInfo, probeErrorStatus, probeInstance, probeInstanceAll, summarizeProbe } from "../ssm.js";
import { clearPermissionIssues, listPermissionIssues, policyForIssues, recommendedPolicy, VIEW_ONLY_POLICY_ARN } from "../permissions.js";
import { checkPermissions, lastPermissionCheck, permissionCheckSummary } from "../permission_check.js";
import { defaultSetupDocuments, renderSetupPlan, renderSetupScript, setupCommands, validateSetupOptions } from "../setup_script.js";
import { latestWatchSummary, watchOnce } from "../watcher.js";
import { cronOff } from "../scheduler.js";
import { listRuntimeSettings, setRuntimeSetting } from "../runtime_settings.js";
import { applyImport, buildPayload, openBundle, planImport, sealPayload } from "../settings_transfer.js";
import { quotaStatus } from "../quota.js";
import { ec2Detail, inventorySummary, listEc2, listElasticache, listRds, refreshInventory } from "../inventory.js";
import { listLambda } from "../lambda_inventory.js";
import { listDynamodb } from "../dynamodb_inventory.js";
import { SERVICE_TABS, listServices, listThreatFindings, type ServiceTab } from "../service_inventory.js";
import { listEbs } from "../ebs_inventory.js";
import { listS3, refreshS3Inventory } from "../s3_inventory.js";
import { elbsForInstance, listElb } from "../elb_inventory.js";
import { latestProfile, listProfiles, usageProfilePass, whyNoProfile } from "../usage_profile.js";
import { decidedOffHours, latestReview, scheduleFor, usageReviewPass } from "../usage_review.js";
import { investigateUsage, latestInvestigation, usageInvestigationPass } from "../usage_agent.js";
import { beanstalkConsent, consentErrorStatus, manualPower, normaliseConsent, requestConsent, requestScaleBand } from "../consent.js";
import { dispatchActionNotifications, listActions } from "../executor.js";
import { domainsByResource, domainsFor, listRoute53, listRoute53Zones, refreshRoute53Inventory } from "../route53_inventory.js";
import { syncDecisionConceptInBackground } from "../concepts.js";
import { incidentForAlert, investigateAlert, listAlerts, listIncidents } from "../investigate.js";
import { jevStats, listJevCalls } from "../jev.js";
import { reopenAlert } from "../triage.js";
import { mirrorAlertsInBackground } from "../graph_mirror.js";
import { resourceRole } from "../roles.js";
import { affectedResources } from "../affected.js";
import { blockerLinks, distinctSaving, findConflicts, liveRows } from "../related.js";
import { exposureFor } from "../exposure.js";
import { TIMELINE_KINDS, timelineFor } from "../timeline.js";
import { cli } from "../step_runner.js";
import { dispatchNotifications, noteDecision, notifyAlert, notifyStatus, queueRecommendationEvent, resendNotification, sendSphinx, setWatch, watchState } from "../notify.js";
import { latestRdsLoad, refreshRdsLoad } from "../rds_load.js";
import { confirmRule, deleteRule, listRules, signalKinds, upsertRule } from "../signal_rules.js";
import { latestS3Usage, refreshS3Usage, s3UsagePass } from "../s3_usage.js";
import { ask, createThread } from "../chat.js";
import { describeError } from "../permissions.js";
import { accountRank, accountScope, accountWhere, latestRunIdFor, resourceInScope, rowInScope, stampRowAccounts } from "../scope.js";

export const api = Router();

// The agent webhook lives in src/routes/callback.ts, mounted before every authenticated router.

api.use(authMiddleware);

// ---- settings -------------------------------------------------------------
api.get("/settings", (_req, res) => {
  res.json({
    account_change: pendingAccountChange(),
    aws: {
      configured: hasConnectionFile(),
      ...(credentialsMeta() || {}),
      // What the mode picker needs: the managed profile name, where the managed sections go, the accepted shapes.
      managedProfile: config.advisorAwsProfile,
      awsConfigFile: config.awsConfigFile,
      awsSharedCredentialsFile: config.awsSharedCredentialsFile,
      credentialSources: CREDENTIAL_SOURCES,
      defaultCredentialSource: DEFAULT_CREDENTIAL_SOURCE,
      validation: { profile: PROFILE_NAME_RE.source, roleArn: ROLE_ARN_RE.source },
    },
    benchmarks: { all: ALL_BENCHMARKS, enabled: getJsonSetting<string[]>("benchmarks", DEFAULT_BENCHMARKS) },
    agent: { configured: Boolean(config.repo2graphUrl), url: config.repo2graphUrl || null, model: config.agentModel },
    schema: config.schema,
    mcp: { url: `${config.publicUrl}/mcp`, protected: Boolean(config.mcpToken) },
    schedule: { runCron: cronOff(config.runCron) ? null : config.runCron, watchCron: cronOff(config.watchCron) ? null : config.watchCron, agentAutoDispatch: config.agentAutoDispatch, alertInvestigate: config.alertInvestigate },
    probeDocument: probeDocumentInfo(), probeDocuments: probeDocumentsInfo(),
    jev: jevStats(),
  });
});

// ---- Jev (TypeSafe) audit trail: every systemOne call with its questions and answers ---------------------
api.get("/jev/calls", (req, res) => {
  const limit = Number(req.query.limit) || 50;
  res.json(listJevCalls({ limit: Number.isFinite(limit) ? limit : 50, purpose: typeof req.query.purpose === "string" ? req.query.purpose : undefined }));
});

// ---- permissions -------------------------------------------------------------
// Issues seen anywhere in the app (benchmarks, queries, watcher, inventory, probe, MCP tools), the merged policy that
// fixes them, the last capability check, and the complete read-only policy the advisor recommends.
// ?account=<12 digits> reads a member's last check and the policy with its id (src/accounts.ts); default: the parent. `accounts`
// is one line per account (the parent first) with its last check, for the card's account picker.
api.get("/permissions", (req, res) => {
  const issues = listPermissionIssues();
  const accountId = typeof req.query.account === "string" && /^\d{12}$/.test(req.query.account) ? req.query.account : null;
  const last = lastPermissionCheck(accountId);
  let accounts: ReturnType<typeof permissionCheckSummary> = [];
  try { accounts = permissionCheckSummary(); } catch { /* no credentials yet */ }
  res.json({
    issues,
    policy: policyForIssues(issues),
    checked_at: last?.checked_at ?? null,
    last_check: last,
    account_id: accountId || credentialsMeta()?.accountId || null,
    accounts,
    recommended_policy: recommendedPolicy(accountId || credentialsMeta()?.accountId || "*"),
    managed_policies: [VIEW_ONLY_POLICY_ARN],
    probe_document: probeDocumentInfo(), probe_documents: probeDocumentsInfo(),
    // the ledger rows that update the read policy itself (src/actions/read_policy.ts): open ones wait for "Run as me"
    policy_rows: listActions({ kind: "read_policy", page_size: 50 }).actions.filter((r) => r.status !== "stale"),
  });
});
// One ledger row per account whose read policy lacks something (src/actions/read_policy.ts); body.fix_only wants the recorded fixes alone. Nothing is written: each row is applied with "Run as me".
api.post("/permissions/propose", async (req, res) => {
  if (!hasConnectionFile()) return res.status(400).json({ error: "AWS credentials are not configured" });
  try { res.json(await proposeReadPolicyUpdates({ fixOnly: req.body?.fix_only === true, by: typeof req.body?.by === "string" && req.body.by.trim() ? req.body.by.trim().slice(0, 80) : "a person" })); }
  catch (e: any) { res.status(502).json({ error: e?.message || String(e) }); }
});

// One cheap probe per capability; body.instance_id (an SSM-online Linux instance) also runs the real SSM probe once.
// A person dismisses a recorded issue (it also clears itself the next time the call works, and Check permissions re-verifies it).
api.delete("/permissions/issues/:action", (req, res) => {
  const action = String(req.params.action);
  if (!/^[a-z0-9-]+:[A-Za-z0-9*]+$/.test(action)) return res.status(400).json({ error: "an IAM action is expected" });
  clearPermissionIssues([action]);
  res.json({ ok: true, issues: listPermissionIssues() });
});

// body.account_id (12 digits) checks a registered member through its read role and its own Steampipe connection; default: the parent.
api.post("/permissions/check", async (req, res) => {
  if (!hasConnectionFile()) return res.status(400).json({ error: "AWS credentials are not configured" });
  const instanceId = typeof req.body?.instance_id === "string" && req.body.instance_id.trim() ? req.body.instance_id.trim() : undefined;
  if (instanceId && !/^i-[0-9a-f]{8,17}$/.test(instanceId)) return res.status(400).json({ error: `"${instanceId}" is not an EC2 instance id` });
  const accountId = typeof req.body?.account_id === "string" && req.body.account_id.trim() ? req.body.account_id.trim() : null;
  if (accountId && !/^\d{12}$/.test(accountId)) return res.status(400).json({ error: `"${accountId}" is not a 12-digit AWS account id` });
  try { res.json(await checkPermissions({ instanceId, accountId })); }
  catch (e: any) { res.status(/not a registered/.test(String(e?.message)) ? 400 : 502).json({ error: e.message }); }
});

// The host probe's SSM document, for compatibility; every kind is at GET /api/probes/:kind/document (src/routes/probes.ts).
api.get("/probe/document", (req, res) => { const k = String(req.query.kind || "host"); res.json(probeDocument((PROBE_KINDS as readonly string[]).includes(k) ? (k as ProbeKind) : "host")); });

// ---- one-command setup (Settings > Set up AWS access) -----------------------------------------------------------------
// The plan (what the script will do, numbered as the script prints it) and the script itself, from the same options:
// ?path=laptop-key|ec2-role&user&role&profile&region&instanceRole&instanceId&adminProfile&advisorUrl&dryRun=1.
// Public only when API_TOKEN is unset (authMiddleware lets everything through then); otherwise the command carries a
// one-hour ?token= for the curl and ADVISOR_API_TOKEN for the script's own calls back to the advisor.
const setupOptionsFrom = (req: Request) => validateSetupOptions(req.query as Record<string, unknown>, { advisorUrl: `${req.protocol}://${req.get("host")}` });

api.get("/setup/plan", (req, res) => {
  let opts;
  try { opts = setupOptionsFrom(req); } catch (e: any) { return res.status(400).json({ error: e.message }); }
  const token = config.apiToken ? signToken("1h") : undefined;
  const { command, piped, scriptUrl } = setupCommands(opts, token);
  res.json({ options: opts, steps: renderSetupPlan(opts), command, piped, scriptUrl, protected: Boolean(config.apiToken), probeDocument: defaultSetupDocuments().probeDocumentName });
});

api.get("/setup/script", (req, res) => {
  let opts;
  try { opts = setupOptionsFrom(req); } catch (e: any) { return res.status(400).json({ error: e.message }); }
  res.set("content-disposition", 'attachment; filename="aws-advisor-setup.sh"').set("cache-control", "no-store").type("text/x-shellscript").send(renderSetupScript(opts));
});

// Body: { mode: "keys" | "profile" | "chain" (default keys), accessKey, secretKey, sessionToken?, profile, credentialSource?, roleArn?, regions, defaultRegion }.
// Writes the Steampipe connection (and the managed AWS profile when a role is assumed), then tests Steampipe and the SDK side.
api.put("/settings/aws", async (req, res) => {
  let settings;
  try { settings = validateSettings(req.body || {}); }
  catch (e: any) { return res.status(400).json({ error: e.message }); }
  const previous = credentialsMeta()?.accountId ?? null;
  const meta = writeConnection(settings, memberConnections());
  // the plugin keeps the session it opened under the previous files: restart the service (when it is local) before testing
  const reload = await reloadSteampipeService("credentials saved");
  const [test, sdk] = await Promise.all([testConnection(45_000), sdkIdentity(20_000)]);
  if (test.ok) updateCredentialsMeta({ accountId: test.accountId });
  else if (sdk.ok && sdk.accountId) updateCredentialsMeta({ accountId: sdk.accountId });
  const account_change = noteAccountChange(previous, test.ok ? test.accountId : sdk.ok ? sdk.accountId : null);
  res.json({ saved: meta, test, sdk, account_change, steampipe_reload: reload });
});

// Tests the saved credentials both ways: the Steampipe schema (aws_account) and the advisor's own SDK provider (sts:GetCallerIdentity).
api.post("/settings/aws/test", async (_req, res) => {
  if (!hasConnectionFile()) return res.status(400).json({ error: "AWS credentials are not configured" });
  const previous = credentialsMeta()?.accountId ?? null;
  const [test, sdk] = await Promise.all([testConnection(15_000), sdkIdentity(15_000)]);
  if (test.ok) updateCredentialsMeta({ accountId: test.accountId });
  else if (sdk.ok && sdk.accountId) updateCredentialsMeta({ accountId: sdk.accountId });
  const account_change = noteAccountChange(previous, test.ok ? test.accountId : sdk.ok ? sdk.accountId : null);
  res.json({ ...test, sdk, account_change });
});

api.delete("/settings/aws", (_req, res) => { clearConnection(); res.json({ ok: true }); });

// The parent changed: what is still stored about the previous account, and the three ways out (keep, purge, make it a member).
api.get("/settings/aws/change", (_req, res) => { const c = pendingAccountChange(); res.json({ change: c, preview: c ? purgePreview(c.from) : null }); });
api.delete("/settings/aws/change", (_req, res) => { dismissAccountChange(); res.json({ ok: true }); });
// ---- wiping data (Settings › Accounts › Data) ---------------------------------------------------------------
// ?target=all | <AWS account id> | <Vercel team id>, &preserve_concepts=1 for the full wipe's Concept switch.
api.get("/settings/data/preview", (req, res) => {
  const target = String(req.query.target || "all").trim();
  if (target === "all") return res.json({ target, ...wipePreview(req.query.preserve_concepts === "1") });
  if (!isAccountTarget(target)) return res.status(400).json({ error: "target must be all or the id of an account a provider knows (an AWS account id, a Vercel team id, ...)" });
  res.json({ target, ...purgePreview(target) });
});
// Body: { target: "all" | <account id>, confirm: <"WIPE" for all, the id typed again otherwise>, preserve_concepts?: boolean }. Irreversible; refused while a run is collecting.
api.post("/settings/data/wipe", async (req, res) => {
  const target = String(req.body?.target || "").trim(); const confirm = String(req.body?.confirm || "").trim();
  if (isBusy()) return res.status(409).json({ error: "a collection run is in progress; wait for it to finish" });
  try {
    if (target === "all") {
      if (confirm !== "WIPE") return res.status(400).json({ error: "type WIPE under confirm" });
      return res.json(await wipeAllData({ preserveConcepts: Boolean(req.body?.preserve_concepts) }));
    }
    if (!isAccountTarget(target)) return res.status(400).json({ error: "target must be all or the id of an account a provider knows (an AWS account id, a Vercel team id, ...)" });
    if (confirm !== target) return res.status(400).json({ error: "type the account id again under confirm" });
    res.json(await purgeAccountData(target));
  } catch (e: any) { res.status(500).json({ error: e.message }); }
});
// Body: { account, confirm: "<the account id typed again>" }. Removes every row and graph node attributed to that account. Irreversible.
api.post("/settings/aws/purge", async (req, res) => {
  const account = String(req.body?.account || "").trim();
  if (!/^\d{12}$/.test(account)) return res.status(400).json({ error: "account must be a 12-digit AWS account id" });
  if (String(req.body?.confirm || "").trim() !== account) return res.status(400).json({ error: "type the account id again under confirm" });
  if (account === (credentialsMeta()?.accountId ?? "")) return res.status(400).json({ error: "that is the account the credentials resolve to now; point the advisor elsewhere first" });
  if (listAccounts().some((a) => a.account_id === account && !a.is_parent)) return res.status(400).json({ error: "that account is a registered member; remove it under Member accounts first" });
  try { res.json(await purgeAccountData(account)); } catch (e: any) { res.status(500).json({ error: e.message }); }
});

// Runtime settings: the agent, Jev, the graph, the schedules, the probe pass. Saved values win over the env.
api.get("/settings/runtime", (_req, res) => res.json({ settings: listRuntimeSettings() }));
api.get("/quotas", (_req, res) => res.json({ quotas: quotaStatus() }));
api.post("/settings/runtime/:key/run", async (req, res) => {
  const key = String(req.params.key);
  const job = allJobs()[key];
  if (!job) return res.status(404).json({ error: `no job for ${key}` });
  try { res.json({ key, label: job.label, result: await runJobNow(key) }); }
  catch (e: any) { res.status(500).json({ error: e?.message || String(e) }); }
});
api.put("/settings/runtime", (req, res) => {
  const { key, value } = req.body || {};
  if (typeof key !== "string") return res.status(400).json({ error: "key required" });
  try { res.json({ setting: setRuntimeSetting(key, value == null ? null : String(value)) }); }
  catch (e: any) { res.status(400).json({ error: e.message }); }
});

// ---- settings export / import (Settings › Other) -----------------------------------------------------------------
// Configuration only: runtime settings with their secrets, the AWS credentials (keys included), member accounts, benchmarks,
// prompt and probe-script overrides. No data and no graph: the new host collects its own with a run. Sealed with a passphrase.
api.post("/settings/export", (req, res) => {
  try { res.set("content-disposition", `attachment; filename="cloud-advisor-settings-${new Date().toISOString().slice(0, 10)}.json"`).set("cache-control", "no-store").json(sealPayload(buildPayload(), req.body?.passphrase)); }
  catch (e: any) { res.status(400).json({ error: e.message }); }
});
// Body: { bundle, passphrase }. What the import would change; nothing is written.
api.post("/settings/import/preview", (req, res) => {
  try { res.json(planImport(openBundle(req.body?.bundle, req.body?.passphrase))); }
  catch (e: any) { res.status(400).json({ error: e.message }); }
});
// Body: { bundle, passphrase, runtime_keys?: string[] }. Applies it, rewrites the Steampipe connection and tests it.
api.post("/settings/import", async (req, res) => {
  if (isBusy()) return res.status(409).json({ error: "a collection run is in progress; wait for it to finish" });
  let payload;
  try { payload = openBundle(req.body?.bundle, req.body?.passphrase); } catch (e: any) { return res.status(400).json({ error: e.message }); }
  const keys = Array.isArray(req.body?.runtime_keys) ? req.body.runtime_keys.map(String) : undefined;
  try { res.json(await applyImport(payload, { runtimeKeys: keys })); }
  catch (e: any) { res.status(400).json({ error: e.message }); }
});

api.put("/settings/benchmarks", (req, res) => {
  const enabled = (req.body?.enabled || []).filter((b: string) => ALL_BENCHMARKS.includes(b));
  setSetting("benchmarks", JSON.stringify(enabled));
  res.json({ enabled });
});

// ---- runs -----------------------------------------------------------------
api.get("/runs", (req, res) => {
  // the scope's provider's runs (every account: the first provider with rules); the account's own runs when it has any, else the provider's (a member is covered by its parent's runs)
  const scope = accountScope(req.query as any);
  const provider = scope?.provider ?? adapters().find((a) => a.rules)?.id ?? null;
  if (!provider) return res.json([]);
  const own = scope && db.prepare("select 1 from runs where provider = ? and account_id = ? limit 1").get(provider, scope.id);
  const cols = "id, started_at, finished_at, status, trigger, account_id, findings_count, recommendations_count, error, provider";
  res.json(own ? db.prepare(`select ${cols} from runs where provider = ? and account_id = ? order by id desc limit 100`).all(provider, scope!.id)
    : db.prepare(`select ${cols} from runs where provider = ? order by id desc limit 100`).all(provider));
});

api.post("/runs", (_req, res) => {
  if (!hasConnectionFile()) return res.status(400).json({ error: "AWS credentials are not configured" });
  try { res.status(202).json({ id: startRun("manual") }); }
  catch (e: any) { res.status(409).json({ error: e.message }); }
});

api.get("/runs/:id", (req, res) => {
  const run = db.prepare("select * from runs where id = ?").get(req.params.id);
  if (!run) return res.status(404).json({ error: "not found" });
  const byControl = db.prepare("select source, benchmark, control_id, control_title, status, count(*) as n from findings where run_id = ? group by 1,2,3,4,5 order by n desc").all(req.params.id);
  const agent = (db.prepare("select request_id, session_id, status, error, created_at, finished_at, kind, grade, retry_of, retried_by from agent_runs where run_id = ? order by id desc").all(req.params.id) as any[])
    .map(({ grade, kind, ...a }) => { let g = null; try { g = grade ? JSON.parse(grade) : null; } catch { g = null; } return { ...a, below_bar: belowBar(g, taskFor(kind || "findings").retry.on_score_below) }; });
  res.json({ ...(run as object), byControl, agent });
});

api.get("/runs/:id/stream", (req, res) => {
  const id = Number(req.params.id);
  const run = db.prepare("select status, log from runs where id = ?").get(id) as { status: string; log: string } | undefined;
  if (!run) return res.status(404).end();
  res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache", connection: "keep-alive" });
  const send = (ev: unknown) => res.write(`data: ${JSON.stringify(ev)}\n\n`);
  for (const line of run.log.split("\n").filter(Boolean)) send({ type: "log", line, replay: true });
  if (run.status !== "running") { send({ type: "done", status: run.status }); return res.end(); }
  const listener = (ev: any) => { send(ev); if (ev.type === "done") res.end(); };
  runEvents.on(`run:${id}`, listener);
  const ping = setInterval(() => res.write(": ping\n\n"), 15000);
  req.on("close", () => { runEvents.off(`run:${id}`, listener); clearInterval(ping); });
});

api.get("/runs/:id/changes", (req, res) => {
  const run = db.prepare("select id from runs where id = ?").get(req.params.id) as { id: number } | undefined;
  if (!run) return res.status(404).json({ error: "not found" });
  res.json(getRunChanges(run.id));
});

api.post("/runs/:id/agent", async (req, res) => {
  const run = db.prepare("select id, status from runs where id = ?").get(req.params.id) as { id: number; status: string } | undefined;
  if (!run) return res.status(404).json({ error: "not found" });
  if (run.status !== "completed") return res.status(400).json({ error: "run has not completed" });
  const inflight = db.prepare("select request_id from agent_runs where run_id = ? and status = 'pending'").get(run.id) as { request_id: string } | undefined;
  if (inflight && !req.query.force) return res.status(409).json({ error: `agent run ${inflight.request_id} is still pending; poll it or pass ?force=1 to start another` });
  try { res.status(202).json(await dispatchToAgent(run.id)); }
  catch (e: any) { res.status(502).json({ error: e.message }); }
});

// every request to the agent, the same entries the graph holds (src/graph_agent_runs.ts)
api.get("/agent-runs", (req, res) => {
  const q = req.query as Record<string, string | undefined>;
  res.json(listAgentRuns({ kind: q.kind || undefined, status: q.status || undefined, page: Number(q.page) || 1, pageSize: Number(q.page_size) || 50 }));
});

api.get("/agent-runs/:requestId", (req, res) => {
  const row = db.prepare("select * from agent_runs where request_id = ?").get(req.params.requestId);
  if (!row) return res.status(404).json({ error: "not found" });
  res.json(row);
});

api.post("/agent-runs/:requestId/poll", async (req, res) => {
  try { res.json(await pollAgentResult(req.params.requestId)); }
  catch (e: any) { res.status(502).json({ error: e.message }); }
});

// Proxies repo2graph's SSE stream so the browser never needs repo2graph credentials.
api.get("/agent-runs/:requestId/events", async (req, res) => {
  let upstream: Response;
  try { upstream = await openAgentEvents(req.params.requestId); }
  catch (e: any) { return res.status(502).json({ error: e.message }); }
  res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache", connection: "keep-alive" });
  const reader = upstream.body!.getReader();
  req.on("close", () => reader.cancel().catch(() => {}));
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      res.write(Buffer.from(value));
    }
  } catch { /* upstream closed */ }
  res.end();
});

// Runs the scheduled probe pass on demand (idle candidates only, see src/probe_pass.ts).
api.post("/probe-pass", async (_req, res) => {
  const { probePass } = await import("../probe_pass.js");
  try { res.json(await probePass()); } catch (e: any) { res.status(500).json({ error: e.message }); }
});
api.get("/probe-pass/targets", async (_req, res) => {
  const { probeTargets } = await import("../probe_pass.js");
  res.json(probeTargets());
});

// Who is behind a NAT gateway's traffic: instances in its VPC ranked by network bytes over the last N hours.
api.get("/nat/:id/attribution", async (req, res) => {
  const { attributeNatTraffic } = await import("../watcher.js");
  const hours = Number(req.query.hours || 1);
  try { res.json(await attributeNatTraffic(req.params.id, Number.isFinite(hours) ? hours : 1, Number(req.query.limit || 10))); }
  catch (e: any) { res.status(502).json({ error: e.message }); }
});

// ---- recommendations ------------------------------------------------------
api.get("/recommendations/:id", (req, res) => {
  const row = db.prepare("select * from recommendations where id = ?").get(req.params.id) as { resource: string | null; resource_name: string | null; title: string | null; rationale: string | null } | undefined;
  if (!row) return res.status(404).json({ error: "not found" });
  // Jev's role for the resource (see src/roles.ts), when it has one on file; the resources it touches as
  // inventory links (src/affected.ts): the resource column split up, and what the text names besides.
  const id = Number(req.params.id);
  res.json({ ...row, resource_role: row.resource ? resourceRole(row.resource) : null, affected: affectedResources(row), exposure: exposureFor(row as any), conflicts: findConflicts(liveRows()).get(id) || [], ...blockerLinks(id, (row as any).blocked_by ?? null) });
});

api.post("/recommendations/:id/decision", (req, res) => {
  const { status, reason, by } = req.body || {};
  if (!["approved", "rejected", "snoozed", "pending", "open", "done"].includes(status)) return res.status(400).json({ error: "bad status" });
  if (status === "rejected" && !reason) return res.status(400).json({ error: "a reason is required to reject; it feeds the agent's memory" });
  const r = db.prepare("update recommendations set status = ?, decided_at = datetime('now'), decided_by = ?, decision_reason = ?, updated_at = datetime('now') where id = ?")
    .run(status, by || "ui", reason || null, req.params.id);
  if (!r.changes) return res.status(404).json({ error: "not found" });
  const rec = db.prepare("select * from recommendations where id = ?").get(req.params.id) as any;
  // A rejection with a reason becomes a repo2graph learning; fire-and-forget so the UI never waits on it.
  if (status === "rejected" && config.repo2graphUrl) postRejectionLearning({ id: rec.id, fingerprint: rec.fingerprint, title: rec.title, rule: rec.rule, resource: rec.resource, decision_reason: String(reason) });
  // Every decision is mirrored into repo2graph's Concept graph (see src/concepts.ts); also fire-and-forget.
  syncDecisionConceptInBackground(Number(req.params.id));
  // Approvals, rejections and done land in the Sphinx chat (src/notify.ts); queued here, posted in the background.
  noteDecision(Number(req.params.id), status, by || "ui");
  res.json(rec);
});

api.get("/learnings", (_req, res) => {
  res.json(db.prepare("select * from learnings order by id desc limit 100").all());
});

// ---- instances (SSM probe) -------------------------------------------------
const probeInFlight = new Set<string>();

// ?kind=host|docker|apps|software runs one probe; without it every kind runs in turn and the merged view comes back.
api.post("/instances/:id/probe", async (req, res) => {
  const id = String(req.params.id);
  const kind = typeof req.query.kind === "string" ? req.query.kind : typeof req.body?.kind === "string" ? req.body.kind : "";
  if (kind && !(PROBE_KINDS as readonly string[]).includes(kind)) return res.status(400).json({ error: `kind must be one of ${PROBE_KINDS.join(", ")}` });
  if (probeInFlight.has(id)) return res.status(409).json({ error: `a probe of ${id} is already running` });
  probeInFlight.add(id);
  try {
    if (kind) { const p = await probeInstance(id, { kind: kind as ProbeKind }); const merged = latestProbe(id); return res.json({ ...p, merged: merged?.data ?? null, summary: merged ? summarizeProbe(merged.data) : summarizeProbe(p.data) }); }
    const r = await probeInstanceAll(id);
    if (!r.probe) { const f = r.failed[0]; return res.status(f && ["no_credentials", "not_managed", "permission"].includes(f.code) ? 400 : 502).json({ error: f?.message || "no probe succeeded", code: f?.code || "failed", failed: r.failed }); }
    res.json({ ...r.probe, summary: summarizeProbe(r.probe.data), ran: r.ran, failed: r.failed });
  } catch (e: any) {
    if (e instanceof ProbeError) return res.status(probeErrorStatus(e)).json({ error: e.message, code: e.code });
    res.status(502).json({ error: e?.message || String(e), code: "failed" });
  } finally {
    probeInFlight.delete(id);
  }
});

// ---- use signals: which log patterns count as a person using the service, per image (src/signal_rules.ts) ----
api.get("/signal-rules", (_req, res) => res.json({ rules: listRules(), kinds: signalKinds() }));
api.put("/signal-rules", (req, res) => {
  try { res.json({ rule: upsertRule({ image_pattern: req.body?.image_pattern, kind: req.body?.kind, verdict: req.body?.verdict, note: req.body?.note ?? null, decided_by: typeof req.body?.by === "string" && req.body.by ? req.body.by : "ui", status: "confirmed" }) }); }
  catch (e: any) { res.status(400).json({ error: e?.message || String(e) }); }
});
api.post("/signal-rules/:id/confirm", (req, res) => { const r = confirmRule(Number(req.params.id), typeof req.body?.by === "string" ? req.body.by : null); r ? res.json({ rule: r }) : res.status(404).json({ error: "no such rule" }); });
api.delete("/signal-rules/:id", (req, res) => (deleteRule(Number(req.params.id)) ? res.status(204).end() : res.status(404).json({ error: "no such rule" })));
/** Opens a chat thread asking the agent to judge the instance's use signals; the answer arrives in the thread (Chat page). */
api.post("/instances/:id/signals/review", async (req, res) => {
  const id = String(req.params.id);
  if (!/^i-[0-9a-f]{8,17}$/.test(id)) return res.status(400).json({ error: "instance id expected" });
  if (!config.repo2graphUrl) return res.status(400).json({ error: "no repo2graph URL (Settings > Agent): the agent is not configured" });
  const name = (db.prepare("select name from inventory_ec2 where instance_id = ?").get(id) as { name: string | null } | undefined)?.name;
  const by = typeof req.body?.by === "string" && req.body.by ? req.body.by : "ui";
  try {
    const thread = createThread(`Use signals on ${name || id}`, by);
    const message = `Review the use signals on ${name ? `${name} (${id})` : id} with the activity_signals tool. For each container say which matched kinds show a person using the service and which are machine chatter (health checkers, token checks, internal sync), citing the sample lines. Then call propose_signal_rule for every kind that is noise for that image, with the reason in the note, and tell me what you proposed so I can confirm it in the drawer.`;
    const r = await ask(thread.id, message, by);
    res.status(201).json({ thread_id: thread.id, agent_message_id: r.agent.id });
  } catch (e: any) { res.status(500).json({ error: e?.message || String(e) }); }
});

// ---- consent switches and manual stop/start (src/consent.ts) -----------------------------------------------------
const by = (req: any) => (typeof req.body?.by === "string" && req.body.by ? req.body.by : "ui");
api.post("/inventory/ec2/:id/consent", async (req, res) => {
  try { const a = await requestConsent({ kind: "ec2", id: String(req.params.id), value: normaliseConsent(req.body?.value), by: by(req) }); dispatchActionNotifications().catch(() => {}); res.json(a); }
  catch (e: any) { res.status(consentErrorStatus(e)).json({ error: e?.message || String(e) }); }
});
// Whether the actuator role may stop and start this instance (src/autopark_grant.ts), as IAM simulates every policy on it.
api.get("/inventory/ec2/:id/autopark-grant", async (req, res) => {
  const { checkGrant, instanceArn, accountOfArn } = await import("../autopark_grant.js");
  const { dnsGrantFor } = await import("../actions/schedule_hours.js");
  const { actuatorRoleFor } = await import("../accounts.js");
  const { executorCreds } = await import("../executor.js");
  const id = String(req.params.id);
  const row = db.prepare("select account_id, region, public_ip, private_ip from inventory_ec2 where instance_id = ?").get(id) as { account_id: string | null; region: string | null; public_ip: string | null; private_ip: string | null } | undefined;
  if (!row) return res.status(404).json({ error: "not in the inventory" });
  const creds = executorCreds();
  const role = actuatorRoleFor(row.account_id);
  if (!role) return res.json({ granted: null, detail: "no actuator role configured for this account", role_arn: null });
  const arn = instanceArn(row.region || creds.region, accountOfArn(role), id);
  // the A records that lead to the box now: the grant must name them, or a start cannot re-point them
  const dns = dnsGrantFor(id, row.public_ip, row.private_ip);
  res.json({ ...(await checkGrant(creds.forAccount(row.account_id || null).read, role, arn, dns)), role_arn: role, instance_arn: arn, dns });
});
// The instance's state as EC2 reports it now, mirrored into the inventory: the Auto-park row polls it after Stop and Start.
api.get("/inventory/ec2/:id/state", async (req, res) => {
  const { DescribeInstancesCommand, EC2Client } = await import("@aws-sdk/client-ec2");
  const { executorCreds } = await import("../executor.js");
  const { patchEc2State } = await import("../inventory.js");
  const id = String(req.params.id);
  const row = db.prepare("select account_id, region from inventory_ec2 where instance_id = ?").get(id) as { account_id: string | null; region: string | null } | undefined;
  if (!row) return res.status(404).json({ error: "not in the inventory" });
  const creds = executorCreds();
  const acct = creds.forAccount(row.account_id || null);
  const ec2 = new EC2Client({ region: row.region || acct.region || creds.region, credentials: acct.read });
  try {
    const inst = (await ec2.send(new DescribeInstancesCommand({ InstanceIds: [id] }))).Reservations?.[0]?.Instances?.[0];
    if (!inst) return res.status(404).json({ error: "not found by DescribeInstances" });
    const state = inst.State?.Name || "unknown";
    patchEc2State(id, state, inst.PublicIpAddress ?? null, inst.PrivateIpAddress ?? null);
    res.json({ instance_id: id, state, public_ip: inst.PublicIpAddress ?? null, private_ip: inst.PrivateIpAddress ?? null, checked_at: new Date().toISOString() });
  } catch (e: any) { res.status(500).json({ error: describeError(e, `state of ${id} (ec2:DescribeInstances)`) }); }
  finally { ec2.destroy(); }
});
// Hibernation on the Auto-park row (src/hibernation.ts): ready or not and why, and the owner's choice as advisor:hibernate.
api.get("/inventory/ec2/:id/hibernation", async (req, res) => {
  const { hibernationStatus } = await import("../hibernation.js");
  try { const st = await hibernationStatus(String(req.params.id), { fresh: req.query.fresh === "1" }); if (!st) return res.status(404).json({ error: "not found" }); res.json(st); }
  // 500, not 502: the UI retries a 502 for minutes as "the advisor is unreachable"; an AWS error is final and the note shows it with Retry
  catch (e: any) { res.status(500).json({ error: describeError(e, `hibernation of ${req.params.id} (ec2:DescribeInstances, ec2:DescribeInstanceTypes)`) }); }
});
api.post("/inventory/ec2/:id/hibernation", async (req, res) => {
  const { requestHibernateChoice } = await import("../consent.js");
  const v = req.body?.value;
  const value = v === "stop" || v === "live" || v === "no" ? v : v == null || v === "" || v === "none" ? null : "invalid";
  try { const a = await requestHibernateChoice(String(req.params.id), value as any, by(req)); dispatchActionNotifications().catch(() => {}); res.json(a); }
  catch (e: any) { res.status(consentErrorStatus(e)).json({ error: e?.message || String(e) }); }
});
api.post("/inventory/ec2/:id/power", async (req, res) => {
  const action = req.body?.action === "stop" ? "stop" : req.body?.action === "start" ? "start" : null;
  if (!action) return res.status(400).json({ error: "action is stop or start" });
  try { const a = await manualPower(String(req.params.id), action, by(req)); dispatchActionNotifications().catch(() => {}); res.json(a); }
  catch (e: any) { res.status(consentErrorStatus(e)).json({ error: e?.message || String(e) }); }
});
api.get("/inventory/beanstalk/:env/consent", async (req, res) => {
  try { res.json(await beanstalkConsent(String(req.params.env), str(req.query.region), str(req.query.account_id))); }
  catch (e: any) { res.status(consentErrorStatus(e)).json({ error: describeError(e, `beanstalk ${req.params.env} (elasticbeanstalk:DescribeEnvironments, elasticbeanstalk:ListTagsForResource)`) }); }
});
api.post("/inventory/beanstalk/:env/band", async (req, res) => {
  const n = (v: unknown) => (v == null || v === "" ? null : Number(v));
  try { const a = await requestScaleBand({ id: String(req.params.env), floor: n(req.body?.floor), ceiling: n(req.body?.ceiling), by: by(req), region: str(req.body?.region), account_id: str(req.body?.account_id) }); dispatchActionNotifications().catch(() => {}); res.json(a); }
  catch (e: any) { res.status(consentErrorStatus(e)).json({ error: e?.message || String(e) }); }
});
api.post("/inventory/beanstalk/:env/consent", async (req, res) => {
  try { const a = await requestConsent({ kind: "beanstalk", id: String(req.params.env), value: normaliseConsent(req.body?.value), by: by(req), region: str(req.body?.region), account_id: str(req.body?.account_id) }); dispatchActionNotifications().catch(() => {}); res.json(a); }
  catch (e: any) { res.status(consentErrorStatus(e)).json({ error: e?.message || String(e) }); }
});

// ---- usage profiles (src/usage_profile.ts): when a box is used, by hour of the week ----------------------------
api.get("/usage", (req, res) => res.json({ profiles: listProfiles(req.query.kind === "asg" ? "asg" : req.query.kind === "ec2" ? "ec2" : undefined) }));
api.post("/usage/run", async (_req, res) => {
  if (!hasConnectionFile()) return res.status(400).json({ error: "AWS credentials are not configured" });
  try { res.json(await usageProfilePass((l) => console.log(`[usage] ${l}`))); } catch (e: any) { res.status(502).json({ error: describeError(e, "usage profiles (cloudwatch:GetMetricData)") }); }
});
api.get("/instances/:id/usage", (req, res) => {
  const p = latestProfile(String(req.params.id)) ?? latestProfile(`asg:${req.params.id}`);
  p ? res.json({ ...p, review: latestReview(p.subject), investigation: latestInvestigation(p.subject), follows: (() => { const f = scheduleFor(p.subject); return { ...f, off_hours: decidedOffHours(f.schedule) }; })() }) : res.status(404).json({ error: whyNoProfile(String(req.params.id)) });
});
// The usage review: Jev reads every profile with its context and decides the window (src/usage_review.ts). All boxes, or one; force asks again even when the verdict is fresh.
api.post("/usage/review", async (req, res) => {
  try { res.json(await usageReviewPass((l) => console.log(`[usage-review] ${l}`), { force: req.body?.force !== false })); } catch (e: any) { res.status(502).json({ error: e?.message || String(e) }); }
});
api.post("/usage/recompute", async (_req, res) => {
  if (!hasConnectionFile()) return res.status(400).json({ error: "AWS credentials are not configured" });
  try { const profiles = await usageProfilePass((l) => console.log(`[usage] ${l}`)); const review = await usageReviewPass((l) => console.log(`[usage-review] ${l}`), { force: true }); res.json({ profiles, review }); }
  catch (e: any) { res.status(502).json({ error: describeError(e, "usage profiles (cloudwatch:GetMetricData)") }); }
});
// The agent investigation of a box's usage (src/usage_agent.ts): every unsure box, or one on demand.
api.post("/usage/investigate", async (_req, res) => {
  try { res.json(await usageInvestigationPass((l) => console.log(`[usage-agent] ${l}`))); } catch (e: any) { res.status(502).json({ error: e?.message || String(e) }); }
});
api.post("/instances/:id/usage/investigate", async (req, res) => {
  try { res.status(202).json(await investigateUsage(String(req.params.id), { force: req.body?.force !== false })); }
  catch (e: any) { res.status(e?.code === "pending" ? 409 : /not configured|no usage profile/i.test(String(e?.message)) ? 400 : 502).json({ error: e?.message || String(e) }); }
});
api.post("/instances/:id/usage/review", async (req, res) => {
  const id = String(req.params.id);
  try {
    const r = await usageReviewPass((l) => console.log(`[usage-review] ${l}`), { only: [id], force: true });
    const review = latestReview(id);
    review ? res.json({ ...review, follows: scheduleFor(id), pass: r }) : res.status(r.errors.length ? 400 : 502).json({ error: r.errors[0] || (r.skipped ? "no usage profile for this instance yet: profile it first" : "Jev did not answer") });
  } catch (e: any) { res.status(502).json({ error: e?.message || String(e) }); }
});
api.post("/instances/:id/usage/refresh", async (req, res) => {
  if (!hasConnectionFile()) return res.status(400).json({ error: "AWS credentials are not configured" });
  try { const r = await usageProfilePass((l) => console.log(`[usage] ${l}`), { only: [String(req.params.id)] }); const p = latestProfile(String(req.params.id)) ?? latestProfile(`asg:${req.params.id}`); p ? res.json({ ...p, pass: r }) : res.status(404).json({ error: r.errors[0] || "not a running standalone instance or a balanced autoscaling group" }); }
  catch (e: any) { res.status(502).json({ error: describeError(e, `usage profile ${req.params.id} (cloudwatch:GetMetricData)`) }); }
});

// The log groups an instance ships to (probe 1.6's log_shipping on the latest probe), joined with what the daily logs refresh knows about each group.
api.get("/instances/:id/logs", (req, res) => {
  const id = String(req.params.id);
  const latest = latestProbe(id);
  const shipping: { group: string; via: string; source: string | null }[] = Array.isArray(latest?.data?.log_shipping) ? latest!.data.log_shipping.filter((s: any) => s && typeof s.group === "string").map((s: any) => ({ group: String(s.group), via: String(s.via || "unknown"), source: s.source == null ? null : String(s.source) })) : [];
  // log group names are unique per account only: the group in the instance's own account first
  const rank = accountRank((db.prepare("select account_id from inventory_ec2 where instance_id = ?").get(id) as { account_id: string | null } | undefined)?.account_id);
  const groupRow = db.prepare(`select name, region, retention_days, stored_bytes, ingest_bytes_day, ingest_days, last_seen from log_groups where name = ? order by ${rank.sql} limit 1`);
  const seen = new Set<string>();
  const groups = shipping.filter((s) => { const k = `${s.group}|${s.via}`; if (seen.has(k)) return false; seen.add(k); return true; }).map((s) => {
    const g = groupRow.get(s.group, ...rank.params) as any;
    return { ...s, known: Boolean(g), region: g?.region ?? null, retention_days: g?.retention_days ?? null, stored_gb: g?.stored_bytes != null ? Math.round((g.stored_bytes / 1e9) * 100) / 100 : null, ingest_gb_day: g?.ingest_bytes_day != null ? Math.round((g.ingest_bytes_day / 1e9) * 1000) / 1000 : null, ingest_usd_month: g?.ingest_bytes_day != null ? Math.round((g.ingest_bytes_day / 1e9) * 30.4 * 0.5 * 100) / 100 : null, storage_usd_month: g?.stored_bytes != null ? Math.round((g.stored_bytes / 1e9) * 0.03 * 100) / 100 : null, last_seen: g?.last_seen ?? null };
  });
  res.json({ instance_id: id, probed_at: latest?.collected_at ?? null, probe_has_section: Array.isArray(latest?.data?.log_shipping), groups });
});

api.get("/instances/:id/metrics", (req, res) => {
  const limit = Math.min(100, Math.max(1, Number(req.query.limit) || 20));
  res.json(instanceMetrics(String(req.params.id), limit).map((p) => ({ ...p, summary: summarizeProbe(p.data) })));
});

// ---- wake profiles (src/wake_profiles.ts) and the doorman's view of them (src/doorman.ts) --------------------------------
api.get("/wake-profiles", async (_req, res) => {
  const { listProfiles } = await import("../wake_profiles.js");
  res.json({ profiles: listProfiles() });
});
api.get("/wake-profiles/:id", async (req, res) => {
  const { getProfile, suggestProfile } = await import("../wake_profiles.js");
  const { expectedWakeSeconds } = await import("../doorman.js");
  const { config: c } = await import("../config.js");
  const id = String(req.params.id);
  const saved = getProfile(id);
  const events = db.prepare("select id, at, by, path, outcome, detail, ready_after_s, action_id from wake_events where instance_id = ? order by id desc limit 20").all(id);
  res.json({ profile: saved, suggested: saved ? null : suggestProfile(id), doorman_port: c.doormanPort || null, test_path: `/__wake/test/${id}`, expected_wake_s: expectedWakeSeconds(id), events });
});
api.put("/wake-profiles/:id", async (req, res) => {
  const { saveProfile } = await import("../wake_profiles.js");
  try { res.json(saveProfile(String(req.params.id), req.body ?? {}, by(req))); }
  catch (e: any) { res.status(e?.status || 400).json({ error: e?.message || String(e), errors: e?.errors ?? [] }); }
});
api.delete("/wake-profiles/:id", async (req, res) => {
  const { deleteProfile } = await import("../wake_profiles.js");
  res.json({ deleted: deleteProfile(String(req.params.id)) });
});
api.get("/wake-profiles/:id/status", async (req, res) => {
  const { getProfile } = await import("../wake_profiles.js");
  const { statusOf } = await import("../doorman.js");
  const p = getProfile(String(req.params.id));
  if (!p) return res.status(404).json({ error: "no wake profile" });
  res.json(await statusOf(p));
});

// ---- security groups (src/security_groups.ts): every group with its trouble flags, and one group in full ---------------
api.get("/security-groups", async (req, res) => {
  const { listSecurityGroups } = await import("../security_groups.js");
  res.json({ groups: listSecurityGroups(accountScope(req.query as any)) });
});
api.get("/security-groups/:id", async (req, res) => {
  const { securityGroupDetail } = await import("../security_groups.js");
  const d = securityGroupDetail(String(req.params.id));
  if (!d) return res.status(404).json({ error: "not found" });
  res.json(d);
});

// ---- what runs on the instances (probe 1.6, src/instance_apps.ts) ------------------------------------------------
// One instance: its apps (current, and with ?gone=1 the ones that left), its recent appear/disappear events and where its agents ship logs.
api.get("/instances/:id/apps", async (req, res) => {
  const { appsOn, appEvents, portsOn, unusedRulesOn } = await import("../instance_apps.js");
  const { instanceStatusOf, statusEvents } = await import("../status_checks.js");
  const id = String(req.params.id);
  const latest = latestProbe(id);
  res.json({ instance_id: id, probed_at: latest?.collected_at ?? null, has_processes: Array.isArray(latest?.data.processes), has_listeners: Array.isArray(latest?.data.listeners), apps: appsOn(id, req.query.gone === "1"), ports: portsOn(id, req.query.gone === "1"), unused_rules: unusedRulesOn(id), events: appEvents({ instance_id: id, limit: 50 }), log_shipping: latest?.data.log_shipping ?? [],
    status: instanceStatusOf(id), status_events: statusEvents({ instance_id: id, limit: 20 }) });
});

// ---- EC2 status checks: system, instance and attached EBS (src/status_checks.ts) -------------------------------------------
// ?only=impaired|events|all; the summary and the recent status changes come along.
api.get("/status-checks", async (req, res) => {
  const { statusSummary, listInstanceStatus, statusEvents } = await import("../status_checks.js");
  const only = req.query.only === "impaired" || req.query.only === "events" ? req.query.only : "all";
  res.json({ summary: statusSummary(), instances: listInstanceStatus(only), recent_events: statusEvents({ limit: 50 }) });
});
api.post("/status-checks/refresh", async (_req, res) => {
  const { refreshStatusChecks } = await import("../status_checks.js");
  try { res.json(await refreshStatusChecks((l) => console.log(`[status-checks] ${l}`))); } catch (e: any) { res.status(500).json({ error: e?.message || String(e) }); }
});
// The fleet: every program running anywhere (?kind=app|infra), or where one program runs (?name=), or the counts.
api.get("/apps", async (req, res) => {
  const { fleetApps, whereRuns, appsSummary } = await import("../instance_apps.js");
  const name = typeof req.query.name === "string" ? req.query.name.trim() : "";
  const kind = req.query.kind === "app" || req.query.kind === "infra" ? req.query.kind : undefined;
  res.json({ summary: appsSummary(), ...(name ? { where: whereRuns(name) } : { apps: fleetApps(kind) }) });
});
// The fleet's open ports (probe 1.8): every port anywhere with how far it can be reached, or where one port is open (?port=443&proto=tcp).
api.get("/ports", async (req, res) => {
  const { fleetPorts, whereListens, portsSummary } = await import("../instance_apps.js");
  const port = Number(req.query.port);
  const proto = req.query.proto === "tcp" || req.query.proto === "udp" ? req.query.proto : undefined;
  res.json({ summary: portsSummary(), ...(Number.isInteger(port) && port > 0 ? { port, where: whereListens(port, proto) } : { ports: fleetPorts() }) });
});
api.get("/apps/events", async (req, res) => {
  const { appEvents } = await import("../instance_apps.js");
  res.json({ events: appEvents({ instance_id: typeof req.query.instance === "string" ? req.query.instance : undefined, name: typeof req.query.name === "string" ? req.query.name : undefined, since: typeof req.query.since === "string" ? req.query.since : undefined, limit: Number(req.query.limit) || 100 }) });
});

// ---- inventory --------------------------------------------------------------
const str = (v: unknown) => (typeof v === "string" && v ? v : undefined);
const flag = (v: unknown) => v === "1" || v === "true";

api.post("/inventory/refresh", async (_req, res) => {
  if (!hasConnectionFile()) return res.status(400).json({ error: "AWS credentials are not configured" });
  try { res.json(await refreshInventory({ dns: true })); }
  catch (e: any) { res.status(502).json({ error: e.message }); }
});

api.get("/inventory/summary", (req, res) => { const scope = accountScope(req.query as any); res.json({ ...inventorySummary(scope), iam: iamSummary(scope), sso: ssoSummary(scope) }); });

api.get("/inventory/ec2", (req, res) => {
  res.json(withDomains(listEc2({ scope: accountScope(req.query as any), state: str(req.query.state), ssm: str(req.query.ssm), q: str(req.query.q), sort: str(req.query.sort), gone: flag(req.query.gone) }), ["ec2", "instance_id"]));
});

api.get("/inventory/ec2/:id", (req, res) => {
  const d = ec2Detail(String(req.params.id));
  if (!d) return res.status(404).json({ error: "not found" });
  res.json({ ...d, role: resourceRole(String(req.params.id)), domains: domainsFor("ec2", String(req.params.id)), load_balancers: elbsForInstance(String(req.params.id)) });
});

// Every list row carries the Route 53 records that lead to it (directly, or through a load balancer or distribution).
// A second (kind, column) pair adds the records that name the row's parent: an RDS instance's cluster, a cache node's replication group.
const withDomains = <T extends Record<string, any>>(rows: T[], ...by: Array<[kind: string, idCol: string]>) => {
  const maps = by.map(([kind, idCol]) => [domainsByResource(kind), idCol] as const);
  return rows.map((r) => ({ ...r, domains: maps.flatMap(([m, idCol]) => (r[idCol] ? m.get(String(r[idCol])) || [] : [])) }));
};
api.get("/inventory/rds", (req, res) => res.json(withDomains(listRds({ scope: accountScope(req.query as any), q: str(req.query.q), sort: str(req.query.sort), gone: flag(req.query.gone) }).map((r: any) => ({ ...r, role: resourceRole(String(r.db_instance_identifier)) })), ["rds", "db_instance_identifier"], ["rds_cluster", "cluster"])));
// The load profile behind a database (cluster or instance id): the hourly pass keeps it; refresh collects it again now.
api.get("/inventory/rds/:id/load", (req, res) => {
  const row = latestRdsLoad(String(req.params.id));
  if (!row) return res.status(404).json({ error: "no load profile yet: the hourly probe pass collects one for every database; use Refresh to collect it now" });
  res.json(row);
});
const loadInFlight = new Set<string>();
api.post("/inventory/rds/:id/load/refresh", async (req, res) => {
  const id = String(req.params.id);
  if (!hasConnectionFile()) return res.status(400).json({ error: "AWS credentials are not configured" });
  if (loadInFlight.has(id)) return res.status(409).json({ error: `a load profile of ${id} is already being collected` });
  loadInFlight.add(id);
  try { res.json(await refreshRdsLoad(id, { jev: true })); }
  catch (e: any) { res.status(e?.code === "not_found" ? 404 : 502).json({ error: describeError(e, `rds load ${id} (cloudwatch:GetMetricData, rds:DescribeDBClusters)`) }); }
  finally { loadInFlight.delete(id); }
});
api.get("/inventory/elasticache", (req, res) => res.json(withDomains(listElasticache({ scope: accountScope(req.query as any), q: str(req.query.q), sort: str(req.query.sort), gone: flag(req.query.gone) }), ["elasticache", "cache_cluster_id"], ["elasticache_group", "replication_group"])));
// the platform services, one generic kind per tab (src/service_inventory.ts); `type` narrows a tab with two kinds (backups: backup_vault | backup_plan)
api.get("/inventory/services/:tab", (req, res) => {
  const tab = String(req.params.tab) as ServiceTab;
  if (!(tab in SERVICE_TABS)) { res.status(404).json({ error: `unknown kind ${tab}` }); return; }
  res.json(listServices(tab, { scope: accountScope(req.query as any), q: str(req.query.q), gone: flag(req.query.gone), type: str(req.query.type) }));
});
api.get("/inventory/threat-findings", (req, res) => res.json(listThreatFindings({ scope: accountScope(req.query as any), q: str(req.query.q), gone: flag(req.query.gone), archived: flag(req.query.archived), detector: str(req.query.detector) })));
api.get("/inventory/dynamodb", (req, res) => res.json(listDynamodb({ scope: accountScope(req.query as any), q: str(req.query.q), sort: str(req.query.sort), gone: flag(req.query.gone) })));
api.get("/inventory/lambda", (req, res) => res.json(withDomains(listLambda({ scope: accountScope(req.query as any), q: str(req.query.q), sort: str(req.query.sort), gone: flag(req.query.gone) }), ["lambda", "name"])));
// Load balancers with their targets resolved; the Route 53 records that lead to each (kinds alb/nlb/clb from the resolver, lb when only an interface named it).
api.get("/inventory/iam", (req, res) => res.json(listIamUsers({ scope: accountScope(req.query as any), q: str(req.query.q), sort: str(req.query.sort), gone: flag(req.query.gone) })));
api.get("/inventory/elb", (req, res) => res.json(withDomains(listElb({ scope: accountScope(req.query as any), q: str(req.query.q), sort: str(req.query.sort), gone: flag(req.query.gone), kind: str(req.query.kind), scheme: str(req.query.scheme) }), ["alb", "name"], ["nlb", "name"], ["clb", "name"], ["lb", "name"])));
api.get("/inventory/ebs", (req, res) => res.json(listEbs({ scope: accountScope(req.query as any), q: str(req.query.q), sort: str(req.query.sort), gone: flag(req.query.gone), state: str(req.query.state) })));
api.get("/inventory/s3", (req, res) => res.json(withDomains(listS3({ scope: accountScope(req.query as any), q: str(req.query.q), sort: str(req.query.sort), gone: flag(req.query.gone) }), ["s3", "name"])));
api.post("/inventory/s3/refresh", async (_req, res) => { try { res.json(await refreshS3Inventory()); } catch (e: any) { res.status(500).json({ error: e.message }); } });
// the usage analysis and the lifecycle rules that fit (src/s3_usage.ts)
api.get("/inventory/s3/:name/usage", (req, res) => { const u = latestS3Usage(String(req.params.name)); u ? res.json(u) : res.status(404).json({ error: "not analysed yet" }); });
api.post("/inventory/s3/:name/usage/refresh", async (req, res) => { try { res.json(await refreshS3Usage(String(req.params.name), (l) => console.log(`[s3-usage] ${l}`))); } catch (e: any) { res.status(500).json({ error: describeError(e, `s3 usage ${req.params.name} (s3:ListBucket)`) }); } });
api.post("/inventory/s3/usage/run", async (_req, res) => { try { res.json(await s3UsagePass((l) => console.log(`[s3-usage] ${l}`))); } catch (e: any) { res.status(500).json({ error: e.message }); } });
api.get("/inventory/route53", (req, res) => res.json(listRoute53({ scope: accountScope(req.query as any), q: str(req.query.q), sort: str(req.query.sort), gone: flag(req.query.gone), zone: str(req.query.zone), link: str(req.query.link), type: str(req.query.type) })));
api.get("/inventory/route53/zones", (req, res) => res.json(listRoute53Zones(flag(req.query.gone), accountScope(req.query as any))));
api.get("/inventory/route53/resource/:kind/:id", (req, res) => res.json(domainsFor(String(req.params.kind), String(req.params.id))));

// Everything recorded about one resource, newest first (src/timeline.ts): seen, findings, recommendations and
// decisions, resolutions, verifications, alerts, incidents, probes.
api.get("/inventory/:kind/:id/timeline", (req, res) => {
  const kind = String(req.params.kind);
  if (!TIMELINE_KINDS.includes(kind)) return res.status(400).json({ error: `kind must be one of ${TIMELINE_KINDS.join(", ")}` });
  res.json(timelineFor(kind, String(req.params.id)));
});
api.post("/inventory/route53/refresh", async (_req, res) => {
  if (!hasConnectionFile()) return res.status(400).json({ error: "AWS credentials are not configured" });
  try { res.json(await refreshRoute53Inventory()); } catch (e: any) { res.status(502).json({ error: e.message }); }
});

// ---- watcher and alerts -----------------------------------------------------
let watchInFlight = false;
api.post("/watch", async (_req, res) => {
  if (!hasConnectionFile()) return res.status(400).json({ error: "AWS credentials are not configured" });
  if (watchInFlight) return res.status(409).json({ error: "a watch sample is already being collected" });
  watchInFlight = true;
  try { res.json(await watchOnce()); }
  catch (e: any) { res.status(502).json({ error: e.message }); }
  finally { watchInFlight = false; }
});

api.get("/watch", (_req, res) => res.json(latestWatchSummary()));

api.post("/alerts/:id/ack", (req, res) => {
  const r = db.prepare("update alerts set acknowledged = 1, acknowledged_by = ? where id = ?").run(typeof req.body?.by === "string" && req.body.by ? req.body.by : "ui", req.params.id);
  if (!r.changes) return res.status(404).json({ error: "not found" });
  mirrorAlertsInBackground();
  res.json(db.prepare("select * from alerts where id = ?").get(req.params.id));
});

// Undo of an acknowledgement, Jev's or a person's: the alert is open again (the triage stays on record).
// Sends this alert to the Sphinx chat now, whatever the rules say; the receipt lands on the row.
api.post("/alerts/:id/notify", async (req, res) => {
  try { const result = await notifyAlert(Number(req.params.id), { force: true }); res.status(result === "sent" ? 200 : 502).json({ result, alert: db.prepare("select * from alerts where id = ?").get(req.params.id) }); }
  catch (e: any) { res.status(e.message === "not found" ? 404 : 500).json({ error: e.message }); }
});

// ---- notifications (src/notify.ts) ------------------------------------------
api.get("/notify/status", (_req, res) => res.json(notifyStatus()));
// Whether plan steps can be run from this host (src/step_runner.ts): the CLI's presence and version.
api.get("/run/status", (_req, res) => res.json(cli ?? { present: null, version: null }));
api.post("/notify/test", async (_req, res) => {
  const r = await sendSphinx(`✅ aws-advisor test message · ${new Date().toISOString().slice(0, 16).replace("T", " ")} UTC · ${config.notifyLinkUrl}`);
  res.status(r.ok ? 200 : 502).json(r);
});
api.post("/notify/dispatch", async (_req, res) => res.json(await dispatchNotifications()));
// Recommendation events posted (or waiting) with their receipts, newest first; `?recommendation=<id>` narrows to one.
api.get("/notifications", (req, res) => {
  const rid = Number(req.query.recommendation);
  const limit = Math.min(200, Math.max(1, Number(req.query.limit) || 50));
  res.json(rid ? db.prepare("select * from notifications where subject = 'recommendation' and subject_id = ? order by id desc limit ?").all(rid, limit)
    : db.prepare("select * from notifications order by id desc limit ?").all(limit));
});
api.post("/notifications/:id/resend", async (req, res) => {
  try { const result = await resendNotification(Number(req.params.id)); res.status(result === "sent" ? 200 : 502).json({ result }); }
  catch (e: any) { res.status(e.message === "not found" ? 404 : 500).json({ error: e.message }); }
});
// Shares a recommendation in the chat now, whatever the rules say: { by?: string }.
api.post("/recommendations/:id/notify", async (req, res) => {
  const id = Number(req.params.id);
  const rowId = queueRecommendationEvent(id, "shared", { by: typeof req.body?.by === "string" && req.body.by ? req.body.by : "ui", dedupe: null, force: true });
  if (!rowId) return res.status(404).json({ error: "not found" });
  // the queue posts in the background; wait for this row's receipt so the button can say what happened
  for (let i = 0; i < 40; i++) {
    const row = db.prepare("select result from notifications where id = ?").get(rowId) as { result: string | null };
    if (row.result) return res.status(row.result === "sent" ? 200 : 502).json({ result: row.result, notification_id: rowId });
    await new Promise((r) => setTimeout(r, 250));
  }
  res.status(202).json({ result: "pending", notification_id: rowId });
});
// Whether a resource is paged about: { watch: true | false | null } (null = back to the automatic rule).
api.get("/inventory/:kind/:id/watch", (req, res) => res.json(watchState(String(req.params.kind), String(req.params.id))));
api.post("/inventory/:kind/:id/watch", (req, res) => {
  const v = req.body?.watch;
  if (v !== true && v !== false && v !== null) return res.status(400).json({ error: "watch must be true, false or null" });
  try { res.json(setWatch(String(req.params.kind), String(req.params.id), v === null ? null : v ? 1 : 0)); }
  catch (e: any) { res.status(e.message === "not in the inventory" ? 404 : 400).json({ error: e.message }); }
});

api.post("/alerts/:id/reopen", (req, res) => {
  if (!reopenAlert(Number(req.params.id))) return res.status(404).json({ error: "not found" });
  mirrorAlertsInBackground();
  res.json(db.prepare("select * from alerts where id = ?").get(req.params.id));
});

// ---- incidents (alert investigations by the agent, see src/investigate.ts) -----------------------------
api.post("/alerts/:id/investigate", async (req, res) => {
  if (config.alertInvestigate === "off") return res.status(400).json({ error: "investigations are disabled (ALERT_INVESTIGATE=off)" });
  if (!config.repo2graphUrl) return res.status(400).json({ error: "REPO2GRAPH_URL is not configured" });
  const alert = db.prepare("select id from alerts where id = ?").get(req.params.id) as { id: number } | undefined;
  if (!alert) return res.status(404).json({ error: "not found" });
  try { res.status(202).json(await investigateAlert(alert.id, { force: Boolean(req.query.force) })); }
  catch (e: any) { res.status(e.code === "pending" ? 409 : 502).json({ error: e.message }); }
});

api.get("/alerts/:id/incident", (req, res) => {
  const alert = db.prepare("select id from alerts where id = ?").get(req.params.id) as { id: number } | undefined;
  if (!alert) return res.status(404).json({ error: "not found" });
  const incident = incidentForAlert(alert.id);
  if (!incident) return res.status(404).json({ error: "no incident for this alert yet" });
  res.json(incident);
});

api.get("/incidents", (_req, res) => res.json(listIncidents()));

// ---- overview -------------------------------------------------------------
api.get("/overview", (req, res) => {
  // One account or every account: recommendations, alerts and the inventory narrow to the scope; the cost metrics
  // come from the payer's Cost Explorer and stay organisation-wide (the scope block names the account's own months).
  const scope = accountScope(req.query as any);
  const inScope = rowInScope(scope);
  // the latest completed run that produced cost metrics: an interrupted or empty run must not blank the cards
  const latest = db.prepare("select * from runs where provider = 'aws' and status = 'completed' and id in (select run_id from metrics) order by id desc limit 1").get() as any;
  const running = db.prepare("select id, started_at from runs where provider = 'aws' and status = 'running' order by id desc limit 1").get() as any;
  const metrics = latest ? db.prepare("select key, label, value, dims from metrics where run_id = ? order by key, value desc").all(latest.id) as any[] : [];
  if (scope) stampRowAccounts("recommendations");
  const recRows = (db.prepare("select id, title, status, resource, resource_name, est_monthly_saving, tier, confidence, source, account_id from recommendations").all() as any[]).filter(inScope);
  const recs = Object.values(recRows.reduce((acc, r) => { const a = (acc[r.status] ??= { status: r.status, n: 0, saving: 0 }); a.n++; a.saving += Number(r.est_monthly_saving) || 0; return acc; }, {} as Record<string, { status: string; n: number; saving: number }>));
  const openRecs = recRows.filter((r) => r.status === "open");
  // The open total counted once per resource (src/related.ts): two actions on one box do not both happen.
  const openSaving = distinctSaving(openRecs);
  const top = [...openRecs].sort((a, b) => (b.est_monthly_saving ?? -1) - (a.est_monthly_saving ?? -1)).slice(0, 8).map(({ id, title, est_monthly_saving, tier, confidence, source }) => ({ id, title, est_monthly_saving, tier, confidence, source }));
  const commitments = latest ? db.prepare("select reason, dimensions from findings where run_id = ? and control_id = 'query.commitments' order by id").all(latest.id) : [];
  if (scope) stampRowAccounts("alerts");
  const alerts = listAlerts("open", 50).filter((a: any) => inScope(a));
  // the scope's own numbers: its findings in the latest run, and its months from Cost Explorer's per-account view
  const latestRunId = latestRunIdFor(scope);
  const aw = accountWhere(scope);
  const findings = latestRunId != null ? (db.prepare(`select count(*) as n from findings where run_id = ? and ${aw.sql}`).get(latestRunId, ...aw.params) as { n: number }).n : null;
  const scopeBlock = scope ? {
    account: scope.id, findings, latest_run_id: latestRunId ?? null,
    consolidated: listAccounts().length > 1,
    spend: db.prepare("select month, usd from spend_by_account_monthly where account_id = ? order by month desc limit 6").all(scope.id) as { month: string; usd: number }[],
  } : null;
  res.json({ latestRun: latest || null, running: running || null, busy: isBusy(), awsConfigured: hasConnectionFile(), aws: credentialsMeta(), metrics, recommendations: recs, open_saving: openSaving, top, commitments, alerts,
    agentConfigured: Boolean(config.repo2graphUrl), alertInvestigate: config.alertInvestigate, inventory: inventorySummary(scope), scope: scopeBlock });
});

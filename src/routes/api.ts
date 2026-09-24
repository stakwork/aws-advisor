import { JOBS, runJobNow } from "../scheduler.js";
import { belowBar } from "../rubric.js";
import { taskFor } from "../tasks.js";
import { Router, type Request } from "express";
import { authMiddleware, signToken } from "../auth.js";
import { config } from "../config.js";
import { db, getJsonSetting, setSetting } from "../db.js";
import { isBusy, runEvents, startRun } from "../collector.js";
import { ALL_BENCHMARKS, DEFAULT_BENCHMARKS } from "../powerpipe.js";
import { clearConnection, credentialsMeta, hasConnectionFile, sdkIdentity, testConnection, updateCredentialsMeta, writeConnection } from "../steampipe.js";
import { CREDENTIAL_SOURCES, DEFAULT_CREDENTIAL_SOURCE, PROFILE_NAME_RE, ROLE_ARN_RE, validateSettings } from "../aws_config.js";
import { dispatchToAgent, handleAgentResult, openAgentEvents, pollAgentResult } from "../agent.js";
import { getRunChanges } from "../changes.js";
import { postRejectionLearning } from "../learnings.js";
import { ProbeError, instanceMetrics, probeDocument, probeDocumentInfo, probeErrorStatus, probeInstance, summarizeProbe } from "../ssm.js";
import { clearPermissionIssues, listPermissionIssues, policyForIssues, recommendedPolicy } from "../permissions.js";
import { checkPermissions, lastPermissionCheck } from "../permission_check.js";
import { defaultSetupDocuments, renderSetupPlan, renderSetupScript, setupCommands, validateSetupOptions } from "../setup_script.js";
import { latestWatchSummary, watchOnce } from "../watcher.js";
import { cronOff } from "../scheduler.js";
import { listRuntimeSettings, setRuntimeSetting } from "../runtime_settings.js";
import { quotaStatus } from "../quota.js";
import { ec2Detail, inventorySummary, listEc2, listElasticache, listRds, refreshInventory } from "../inventory.js";
import { listLambda } from "../lambda_inventory.js";
import { listEbs } from "../ebs_inventory.js";
import { listS3, refreshS3Inventory } from "../s3_inventory.js";
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
import { latestRdsLoad, refreshRdsLoad } from "../rds_load.js";
import { describeError } from "../permissions.js";

export const api = Router();

// The agent webhook lives in src/routes/callback.ts, mounted before every authenticated router.

api.use(authMiddleware);

// ---- settings -------------------------------------------------------------
api.get("/settings", (_req, res) => {
  res.json({
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
    probeDocument: probeDocumentInfo(),
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
api.get("/permissions", (_req, res) => {
  const issues = listPermissionIssues();
  const last = lastPermissionCheck();
  res.json({
    issues,
    policy: policyForIssues(issues),
    checked_at: last?.checked_at ?? null,
    last_check: last,
    recommended_policy: recommendedPolicy(credentialsMeta()?.accountId || "*"),
    probe_document: probeDocumentInfo(),
  });
});

// One cheap probe per capability; body.instance_id (an SSM-online Linux instance) also runs the real SSM probe once.
// A person dismisses a recorded issue (it also clears itself the next time the call works, and Check permissions re-verifies it).
api.delete("/permissions/issues/:action", (req, res) => {
  const action = String(req.params.action);
  if (!/^[a-z0-9-]+:[A-Za-z0-9*]+$/.test(action)) return res.status(400).json({ error: "an IAM action is expected" });
  clearPermissionIssues([action]);
  res.json({ ok: true, issues: listPermissionIssues() });
});

api.post("/permissions/check", async (req, res) => {
  if (!hasConnectionFile()) return res.status(400).json({ error: "AWS credentials are not configured" });
  const instanceId = typeof req.body?.instance_id === "string" && req.body.instance_id.trim() ? req.body.instance_id.trim() : undefined;
  if (instanceId && !/^i-[0-9a-f]{8,17}$/.test(instanceId)) return res.status(400).json({ error: `"${instanceId}" is not an EC2 instance id` });
  try { res.json(await checkPermissions({ instanceId })); }
  catch (e: any) { res.status(502).json({ error: e.message }); }
});

// The SSM Command document that embeds the probe script: `aws ssm create-document --name AwsAdvisorProbe --document-type Command --content file://doc.json`.
api.get("/probe/document", (_req, res) => res.json(probeDocument()));

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
  const meta = writeConnection(settings);
  const [test, sdk] = await Promise.all([testConnection(45_000), sdkIdentity(20_000)]);
  if (test.ok) updateCredentialsMeta({ accountId: test.accountId });
  else if (sdk.ok && sdk.accountId) updateCredentialsMeta({ accountId: sdk.accountId });
  res.json({ saved: meta, test, sdk });
});

// Tests the saved credentials both ways: the Steampipe schema (aws_account) and the advisor's own SDK provider (sts:GetCallerIdentity).
api.post("/settings/aws/test", async (_req, res) => {
  if (!hasConnectionFile()) return res.status(400).json({ error: "AWS credentials are not configured" });
  const [test, sdk] = await Promise.all([testConnection(15_000), sdkIdentity(15_000)]);
  if (test.ok) updateCredentialsMeta({ accountId: test.accountId });
  else if (sdk.ok && sdk.accountId) updateCredentialsMeta({ accountId: sdk.accountId });
  res.json({ ...test, sdk });
});

api.delete("/settings/aws", (_req, res) => { clearConnection(); res.json({ ok: true }); });

// Runtime settings: the agent, Jev, the graph, the schedules, the probe pass. Saved values win over the env.
api.get("/settings/runtime", (_req, res) => res.json({ settings: listRuntimeSettings() }));
api.get("/quotas", (_req, res) => res.json({ quotas: quotaStatus() }));
api.post("/settings/runtime/:key/run", async (req, res) => {
  const key = String(req.params.key);
  if (!JOBS[key]) return res.status(404).json({ error: `no job for ${key}` });
  try { res.json({ key, label: JOBS[key].label, result: await runJobNow(key) }); }
  catch (e: any) { res.status(500).json({ error: e?.message || String(e) }); }
});
api.put("/settings/runtime", (req, res) => {
  const { key, value } = req.body || {};
  if (typeof key !== "string") return res.status(400).json({ error: "key required" });
  try { res.json({ setting: setRuntimeSetting(key, value == null ? null : String(value)) }); }
  catch (e: any) { res.status(400).json({ error: e.message }); }
});

api.put("/settings/benchmarks", (req, res) => {
  const enabled = (req.body?.enabled || []).filter((b: string) => ALL_BENCHMARKS.includes(b));
  setSetting("benchmarks", JSON.stringify(enabled));
  res.json({ enabled });
});

// ---- runs -----------------------------------------------------------------
api.get("/runs", (_req, res) => {
  res.json(db.prepare("select id, started_at, finished_at, status, trigger, account_id, findings_count, recommendations_count, error from runs order by id desc limit 100").all());
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

// ---- findings -------------------------------------------------------------
api.get("/findings", (req, res) => {
  const runId = req.query.run_id ? Number(req.query.run_id) : (db.prepare("select id from runs where status = 'completed' order by id desc limit 1").get() as { id: number } | undefined)?.id;
  if (!runId) return res.json({ run_id: null, findings: [] });
  const where: string[] = ["run_id = ?"]; const params: unknown[] = [runId];
  if (req.query.control_id) { where.push("control_id = ?"); params.push(req.query.control_id); }
  if (req.query.status) { where.push("status = ?"); params.push(req.query.status); }
  if (req.query.q) { where.push("(resource like ? or reason like ?)"); params.push(`%${req.query.q}%`, `%${req.query.q}%`); }
  const findings = db.prepare(`select id, source, benchmark, control_id, control_title, status, resource, reason, account_id, region, dimensions from findings where ${where.join(" and ")} order by control_id, resource limit 2000`).all(...params);
  const controls = db.prepare("select control_id, control_title, status, count(*) as n from findings where run_id = ? group by 1,2,3 order by n desc").all(runId);
  res.json({ run_id: runId, controls, findings });
});

// ---- recommendations ------------------------------------------------------
api.get("/recommendations", (req, res) => {
  const status = typeof req.query.status === "string" ? req.query.status : "open";
  const rows = status === "all"
    ? db.prepare("select * from recommendations order by coalesce(est_monthly_saving, -1) desc, updated_at desc").all()
    : db.prepare("select * from recommendations where status = ? order by coalesce(est_monthly_saving, -1) desc, updated_at desc").all(status);
  res.json(rows);
});

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
  res.json(rec);
});

api.get("/learnings", (_req, res) => {
  res.json(db.prepare("select * from learnings order by id desc limit 100").all());
});

// ---- instances (SSM probe) -------------------------------------------------
const probeInFlight = new Set<string>();

api.post("/instances/:id/probe", async (req, res) => {
  const id = String(req.params.id);
  if (probeInFlight.has(id)) return res.status(409).json({ error: `a probe of ${id} is already running` });
  probeInFlight.add(id);
  try {
    const p = await probeInstance(id);
    res.json({ ...p, summary: summarizeProbe(p.data) });
  } catch (e: any) {
    if (e instanceof ProbeError) return res.status(probeErrorStatus(e)).json({ error: e.message, code: e.code });
    res.status(502).json({ error: e?.message || String(e), code: "failed" });
  } finally {
    probeInFlight.delete(id);
  }
});

api.get("/instances/:id/metrics", (req, res) => {
  const limit = Math.min(100, Math.max(1, Number(req.query.limit) || 20));
  res.json(instanceMetrics(String(req.params.id), limit).map((p) => ({ ...p, summary: summarizeProbe(p.data) })));
});

// ---- inventory --------------------------------------------------------------
const str = (v: unknown) => (typeof v === "string" && v ? v : undefined);
const flag = (v: unknown) => v === "1" || v === "true";

api.post("/inventory/refresh", async (_req, res) => {
  if (!hasConnectionFile()) return res.status(400).json({ error: "AWS credentials are not configured" });
  try { res.json(await refreshInventory({ dns: true })); }
  catch (e: any) { res.status(502).json({ error: e.message }); }
});

api.get("/inventory/summary", (_req, res) => res.json(inventorySummary()));

api.get("/inventory/ec2", (req, res) => {
  res.json(listEc2({ state: str(req.query.state), ssm: str(req.query.ssm), q: str(req.query.q), sort: str(req.query.sort), gone: flag(req.query.gone) }));
});

api.get("/inventory/ec2/:id", (req, res) => {
  const d = ec2Detail(String(req.params.id));
  if (!d) return res.status(404).json({ error: "not found" });
  res.json({ ...d, role: resourceRole(String(req.params.id)), domains: domainsFor("ec2", String(req.params.id)) });
});

// Every list row carries the Route 53 records that lead to it (directly, or through a load balancer or distribution).
// A second (kind, column) pair adds the records that name the row's parent: an RDS instance's cluster, a cache node's replication group.
const withDomains = <T extends Record<string, any>>(rows: T[], ...by: Array<[kind: string, idCol: string]>) => {
  const maps = by.map(([kind, idCol]) => [domainsByResource(kind), idCol] as const);
  return rows.map((r) => ({ ...r, domains: maps.flatMap(([m, idCol]) => (r[idCol] ? m.get(String(r[idCol])) || [] : [])) }));
};
api.get("/inventory/rds", (req, res) => res.json(withDomains(listRds({ q: str(req.query.q), sort: str(req.query.sort), gone: flag(req.query.gone) }).map((r: any) => ({ ...r, role: resourceRole(String(r.db_instance_identifier)) })), ["rds", "db_instance_identifier"], ["rds_cluster", "cluster"])));
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
api.get("/inventory/elasticache", (req, res) => res.json(withDomains(listElasticache({ q: str(req.query.q), sort: str(req.query.sort), gone: flag(req.query.gone) }), ["elasticache", "cache_cluster_id"], ["elasticache_group", "replication_group"])));
api.get("/inventory/lambda", (req, res) => res.json(withDomains(listLambda({ q: str(req.query.q), sort: str(req.query.sort), gone: flag(req.query.gone) }), ["lambda", "name"])));
api.get("/inventory/ebs", (req, res) => res.json(listEbs({ q: str(req.query.q), sort: str(req.query.sort), gone: flag(req.query.gone), state: str(req.query.state) })));
api.get("/inventory/s3", (req, res) => res.json(withDomains(listS3({ q: str(req.query.q), sort: str(req.query.sort), gone: flag(req.query.gone) }), ["s3", "name"])));
api.post("/inventory/s3/refresh", async (_req, res) => { try { res.json(await refreshS3Inventory()); } catch (e: any) { res.status(500).json({ error: e.message }); } });
api.get("/inventory/route53", (req, res) => res.json(listRoute53({ q: str(req.query.q), sort: str(req.query.sort), gone: flag(req.query.gone), zone: str(req.query.zone), link: str(req.query.link), type: str(req.query.type) })));
api.get("/inventory/route53/zones", (req, res) => res.json(listRoute53Zones(flag(req.query.gone))));
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

// ?status=open (default) | acknowledged | all; ?all=1 is the older spelling of status=all. Rows carry incident_id / incident_status when investigated.
api.get("/alerts", (req, res) => {
  const all = req.query.all === "1" || req.query.all === "true";
  const status = typeof req.query.status === "string" ? req.query.status : all ? "all" : "open";
  res.json(listAlerts(status === "acknowledged" ? "acknowledged" : status === "all" ? "all" : "open"));
});

api.post("/alerts/:id/ack", (req, res) => {
  const r = db.prepare("update alerts set acknowledged = 1, acknowledged_by = ? where id = ?").run(typeof req.body?.by === "string" && req.body.by ? req.body.by : "ui", req.params.id);
  if (!r.changes) return res.status(404).json({ error: "not found" });
  mirrorAlertsInBackground();
  res.json(db.prepare("select * from alerts where id = ?").get(req.params.id));
});

// Undo of an acknowledgement, Jev's or a person's: the alert is open again (the triage stays on record).
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
api.get("/overview", (_req, res) => {
  // the latest completed run that produced cost metrics: an interrupted or empty run must not blank the cards
  const latest = db.prepare("select * from runs where status = 'completed' and id in (select run_id from metrics) order by id desc limit 1").get() as any;
  const running = db.prepare("select id, started_at from runs where status = 'running' order by id desc limit 1").get() as any;
  const metrics = latest ? db.prepare("select key, label, value, dims from metrics where run_id = ? order by key, value desc").all(latest.id) as any[] : [];
  const recs = db.prepare("select status, count(*) as n, coalesce(sum(est_monthly_saving), 0) as saving from recommendations group by status").all();
  // The open total counted once per resource (src/related.ts): two actions on one box do not both happen.
  const openSaving = distinctSaving(db.prepare("select resource, resource_name, est_monthly_saving from recommendations where status = 'open'").all() as any[]);
  const top = db.prepare("select id, title, est_monthly_saving, tier, confidence, source from recommendations where status = 'open' order by coalesce(est_monthly_saving, -1) desc limit 8").all();
  const commitments = latest ? db.prepare("select reason, dimensions from findings where run_id = ? and control_id = 'query.commitments' order by id").all(latest.id) : [];
  const alerts = listAlerts("open", 50);
  res.json({ latestRun: latest || null, running: running || null, busy: isBusy(), awsConfigured: hasConnectionFile(), aws: credentialsMeta(), metrics, recommendations: recs, open_saving: openSaving, top, commitments, alerts,
    agentConfigured: Boolean(config.repo2graphUrl), alertInvestigate: config.alertInvestigate, inventory: inventorySummary() });
});

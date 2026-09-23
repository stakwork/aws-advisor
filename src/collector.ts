import { EventEmitter } from "node:events";
import { createHash } from "node:crypto";
import { db, getJsonSetting } from "./db.js";
import { config } from "./config.js";
import { DEFAULT_BENCHMARKS, runBenchmark } from "./powerpipe.js";
import { AURORA_CLUSTERS_SQL, QUERIES, auroraMetricsSql } from "./queries.js";
import { AuroraStat, RecInput, buildRecommendations, gravitonRecommendations } from "./rules.js";
import { collectGravitonFacts, gravitonAlarms } from "./graviton_facts.js";
import { GravitonFacts, ec2ArmEquivalent } from "./graviton.js";
import { S, query, testConnection, updateCredentialsMeta } from "./steampipe.js";
import { dispatchToAgent } from "./agent.js";
import { computeRunChanges } from "./changes.js";
import { latestProbeSummaries } from "./ssm.js";
import { refreshInventory } from "./inventory.js";
import { syncDecisionConceptInBackground } from "./concepts.js";
import { flowLogRecommendations } from "./flowlogs.js";
import { describeError, tablesIn } from "./permissions.js";
import { classifyResources, ec2Facts, rdsFacts } from "./roles.js";
import { jevEnabled } from "./jev.js";
import { ensureRdsLoad, loadSummary } from "./rds_load.js";
import { refreshSpend } from "./spend.js";
import { mirrorAfterRunInBackground } from "./graph_mirror.js";

export const runEvents = new EventEmitter();
runEvents.setMaxListeners(100);

/** Runs that were in flight when the process died stay "running" forever otherwise. */
export function sweepInterruptedRuns(): number {
  const r = db.prepare(`update runs set status = 'failed', finished_at = datetime('now'),
      error = 'interrupted: the advisor process restarted while this run was in progress',
      log = log || '\nFAILED: interrupted by a restart of the advisor process\n'
    where status = 'running'`).run();
  if (r.changes) console.warn(`[collector] marked ${r.changes} interrupted run(s) as failed`);
  return r.changes;
}
sweepInterruptedRuns();

let busy = false;
export const isBusy = () => busy;

const fingerprint = (...parts: string[]) => createHash("sha1").update(parts.join("|")).digest("hex").slice(0, 16);

export function startRun(trigger = "manual"): number {
  if (busy) throw new Error("a run is already in progress");
  const id = Number(db.prepare("insert into runs(trigger) values (?)").run(trigger).lastInsertRowid);
  busy = true;
  execute(id).finally(() => { busy = false; });
  return id;
}

function log(runId: number, line: string) {
  db.prepare("update runs set log = log || ? where id = ?").run(line + "\n", runId);
  runEvents.emit(`run:${runId}`, { type: "log", line, at: new Date().toISOString() });
}

const insertFinding = db.prepare(`
  insert into findings(run_id, source, benchmark, control_id, control_title, status, resource, reason, dimensions, account_id, region, fingerprint)
  values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
const insertMetric = db.prepare("insert into metrics(run_id, key, label, value, dims) values (?, ?, ?, ?, ?)");

async function execute(runId: number) {
  try {
    log(runId, `Checking Steampipe connection "${S}"…`);
    const conn = await testConnection(20_000);
    if (!conn.ok) throw new Error(`Steampipe connection "${S}" is not ready: ${conn.error}`);
    db.prepare("update runs set account_id = ? where id = ?").run(conn.accountId, runId);
    updateCredentialsMeta({ accountId: conn.accountId });
    log(runId, `Connected to AWS account ${conn.accountId}`);

    let findingsCount = 0;
    const benchmarks = getJsonSetting<string[]>("benchmarks", DEFAULT_BENCHMARKS);
    for (const b of benchmarks) {
      log(runId, `Thrifty benchmark: ${b}`);
      try {
        const { findings: results, errors } = await runBenchmark(b, (l) => log(runId, `  ${l}`));
        // Controls that could not run, or whose results errored: a denied API call shows up here, never as an alarm.
        for (const ce of errors) {
          const what = ce.kind === "run_error" ? "failed" : `${ce.count} error result${ce.count === 1 ? "" : "s"}`;
          log(runId, `  control ${ce.controlId.replace(/^aws_thrifty\.control\./, "")} ${what}: ${describeError(ce.message, `benchmark ${b} control ${ce.controlId}`, 300)}`);
        }
        const alarms = results.filter((f) => f.status === "alarm");
        db.transaction(() => {
          for (const f of alarms) {
            insertFinding.run(runId, "thrifty", b, f.controlId, f.controlTitle, f.status, f.resource, f.reason,
              JSON.stringify(f.dimensions), f.dimensions.account_id || null, f.dimensions.region || null,
              fingerprint(f.controlId, f.resource));
          }
        })();
        findingsCount += alarms.length;
        log(runId, `  ${alarms.length} alarms out of ${results.length} results`);
      } catch (e: any) {
        log(runId, `  failed: ${describeError(e, `benchmark ${b}`)}`);
      }
    }

    const queryRows: Record<string, any[]> = {};
    for (const q of QUERIES) {
      log(runId, `Query: ${q.title}`);
      try {
        const rows = await query(q.sql);
        queryRows[q.id] = rows;
        if (q.kind === "metric") {
          db.transaction(() => {
            for (const r of rows) insertMetric.run(runId, q.id, String(r.label), r.value == null ? null : Number(r.value), JSON.stringify(r));
          })();
        } else {
          db.transaction(() => {
            for (const r of rows) {
              const resource = q.resource!(r);
              insertFinding.run(runId, "query", null, `query.${q.id}`, q.title, q.status || "alarm", resource, q.reason!(r),
                JSON.stringify(r), r.account_id || null, r.region || null, fingerprint(`query.${q.id}`, resource));
            }
          })();
          if ((q.status || "alarm") === "alarm") findingsCount += rows.length;
        }
        log(runId, `  ${rows.length} rows`);
      } catch (e: any) {
        log(runId, `  failed: ${describeError(e, `query ${q.id} (${tablesIn(q.sql).join(", ")})`)}`);
      }
    }

    log(runId, "Aurora storage tiers…");
    const aurora = await auroraStats((l) => log(runId, `  ${l}`));
    // The load profile behind each cluster (the hourly pass keeps it fresh; a run older than six hours refreshes it here).
    const loads: Record<string, NonNullable<ReturnType<typeof loadSummary>>> = {};
    for (const a of aurora) {
      const row = await ensureRdsLoad(a.cluster, 6, (l) => log(runId, `  ${l}`));
      const sum = loadSummary(row);
      if (sum) loads[a.cluster] = sum;
    }

    const probes = latestProbeSummaries();
    // The Thrifty graviton alarms of this run with their types and prices (src/graviton_facts.ts), for the graviton rule.
    const alarms = gravitonAlarms(db.prepare("select control_id, resource, region, reason from findings where run_id = ? and status = 'alarm'").all(runId) as any[]);
    let graviton;
    if (alarms.length) {
      log(runId, `Graviton facts for ${alarms.length} alarm(s)…`);
      try { graviton = await collectGravitonFacts(alarms, { onLog: (l) => log(runId, l) }); }
      catch (e: any) { log(runId, `  failed: ${describeError(e, "graviton facts")}`); }
    }
    // Jev classifies the instances the rules look at (stopped, idle, graviton) and every RDS instance; cached 7 days per resource.
    const roles = await classifyBatch(queryRows, graviton, (l) => log(runId, l));
    const recs = buildRecommendations({ queryRows, aurora, loads, probes, roles, graviton });
    if (graviton) {
      const g = gravitonRecommendations(graviton, roles);
      log(runId, `Graviton: ${g.recs.length} recommendation(s)${g.skipped.length ? `, ${g.skipped.length} skipped` : ""}`);
      for (const sk of g.skipped.filter((x) => !/^already arm64|no instance-hours/.test(x.why)).slice(0, 40)) log(runId, `  skipped ${sk.kind} ${sk.resource.split(":").pop()}: ${sk.why}`);
    }
    // VPCs whose NAT gateway alerted in the last 7 days and that have no flow logs (see src/flowlogs.ts).
    const flowLogRecs = await flowLogRecommendations({ onError: (m) => log(runId, `  flow logs: ${m}`) });
    if (flowLogRecs.length) log(runId, `Flow logs: ${flowLogRecs.length} VPC${flowLogRecs.length === 1 ? "" : "s"} with NAT alerts and no flow log`);
    const open = upsertRecommendations(runId, [...recs, ...flowLogRecs], "rules");

    log(runId, "Inventory refresh…");
    try {
      const inv = await refreshInventory({ dns: true });
      log(runId, `  ${inv.ec2} EC2 instances, ${inv.rds} RDS instances, ${inv.elasticache} ElastiCache clusters, ${inv.prices_fetched} prices fetched${inv.route53 ? `, ${inv.route53.zones} hosted zones with ${inv.route53.records} records (${inv.route53.linked} linked to resources here, ${inv.route53.unmatched} unmatched)` : ""}, ${inv.took_ms} ms${inv.errors.length ? `; errors: ${inv.errors.join("; ")}` : ""}`);
    } catch (e: any) {
      log(runId, `  failed: ${e.message}`);
    }

    // Daily spend for the Overview (one Cost Explorer call, skipped when fetched in the last 6 hours).
    log(runId, "Spend refresh…");
    try {
      const sp = await refreshSpend({ onLog: (l) => log(runId, `  ${l}`) });
      if (!sp.refreshed) log(runId, `  skipped: ${sp.skipped || sp.error}`);
    } catch (e: any) {
      log(runId, `  failed: ${e.message}`);
    }

    db.prepare("update runs set status = 'completed', finished_at = datetime('now'), findings_count = ?, recommendations_count = ? where id = ?")
      .run(findingsCount, open, runId);
    log(runId, `Done: ${findingsCount} findings, ${open} open recommendations`);
    // One-way mirror into Neo4j (src/graph_mirror.ts): the run, the refreshed inventory and every recommendation. Never awaited.
    mirrorAfterRunInBackground(runId);

    // Material until proven otherwise: a first run, or a failed comparison, still goes to the agent.
    let material = true;
    try {
      const changes = computeRunChanges(runId);
      if (changes.prev_run_id == null) {
        log(runId, "Change detection: no earlier completed run to compare with");
      } else {
        material = changes.findings.new.length > 0 || changes.findings.resolved.length > 0 || changes.flagged.length > 0;
        log(runId, `Changes since run #${changes.prev_run_id}: ${changes.findings.new.length} new findings, ${changes.findings.resolved.length} resolved, ${changes.flagged.length} cost metrics moved notably`);
      }
    } catch (e: any) {
      log(runId, `Change detection failed: ${e.message}`);
    }

    const policy = config.agentAutoDispatch;
    if (!config.repo2graphUrl) console.log(`[run #${runId}] agent dispatch skipped: no repo2graph URL (Settings > Agent)`);
    else if (policy === "never") console.log(`[run #${runId}] agent dispatch skipped: AGENT_AUTO_DISPATCH=never`);
    else if (policy === "changes" && !material) console.log(`[run #${runId}] agent dispatch skipped: nothing material changed (AGENT_AUTO_DISPATCH=changes)`);
    else console.log(`[run #${runId}] handing findings to the agent`);
    if (config.repo2graphUrl && policy === "never") {
      log(runId, "Agent dispatch skipped (AGENT_AUTO_DISPATCH=never); use \"Send findings to agent\" to run it by hand");
    } else if (config.repo2graphUrl && policy === "changes" && !material) {
      log(runId, "Agent dispatch skipped: nothing material changed since the previous run (AGENT_AUTO_DISPATCH=changes)");
    } else if (config.repo2graphUrl) {
      log(runId, `Handing findings to repo2graph at ${config.repo2graphUrl}…`);
      try {
        const r = await dispatchToAgent(runId);
        log(runId, `  agent run accepted: request ${r.requestId}`);
      } catch (e: any) {
        log(runId, `  agent dispatch failed: ${e.message}`);
      }
    }
    runEvents.emit(`run:${runId}`, { type: "done", status: "completed" });
  } catch (e: any) {
    db.prepare("update runs set status = 'failed', finished_at = datetime('now'), error = ? where id = ?").run(e.message, runId);
    log(runId, `FAILED: ${e.message}`);
    mirrorAfterRunInBackground(runId);
    runEvents.emit(`run:${runId}`, { type: "done", status: "failed", error: e.message });
  }
}

/** Roles for the EC2 instances in the stopped/idle rows and the running graviton alarms, and for the RDS inventory, from the resource_roles cache or one batched Jev call. */
async function classifyBatch(queryRows: Record<string, any[]>, graviton: GravitonFacts | undefined, onLog: (l: string) => void) {
  const rows = [...(queryRows.stopped_instance_ebs || []), ...(queryRows.idle_instances || [])];
  const fallback: Record<string, { name?: string | null; instance_type?: string | null; launched?: string | null; state?: string | null }> = Object.fromEntries(rows.map((r) => [r.instance_id, { name: r.name, instance_type: r.instance_type, launched: r.launched ?? null, state: queryRows.idle_instances?.includes(r) ? "running" : "stopped" }]));
  const ids = new Set(rows.map((r) => String(r.instance_id)));
  // Running x86 instances with a Graviton twin: the graviton rule tiers them by role.
  for (const [id, f] of Object.entries(graviton?.ec2 || {})) {
    if (f.state !== "running" || !ec2ArmEquivalent(f.instance_type)) continue;
    ids.add(id);
    fallback[id] ||= { name: f.name, instance_type: f.instance_type, state: f.state };
  }
  const facts = [...ec2Facts([...ids], fallback), ...rdsFacts()];
  if (!facts.length) return {};
  if (!jevEnabled()) { onLog("Resource roles: Jev is not configured (TYPESAFE_API_KEY); the rules use their name regex"); }
  else onLog(`Resource roles: classifying ${facts.length} resources with Jev (cached entries under ${7} days are reused)…`);
  try {
    const roles = await classifyResources(facts);
    const n = Object.keys(roles).length;
    if (jevEnabled()) onLog(`  ${n} of ${facts.length} resources have a role${n ? `: ${Object.values(roles).filter((r) => r.protected_prob >= 0.7).length} protected, ${Object.values(roles).filter((r) => ["blockchain_node", "cache_or_queue"].includes(r.role)).length} naturally idle` : ""}`);
    return roles;
  } catch (e: any) {
    onLog(`  failed: ${String(e?.message || e).slice(0, 200)}`);
    return {};
  }
}

async function auroraStats(onLog: (l: string) => void): Promise<AuroraStat[]> {
  const out: AuroraStat[] = [];
  let clusters: any[] = [];
  try {
    clusters = await query(AURORA_CLUSTERS_SQL);
  } catch (e: any) {
    onLog(`cluster list failed: ${describeError(e, `aurora clusters (${tablesIn(AURORA_CLUSTERS_SQL).join(", ")})`)}`);
    return out;
  }
  for (const c of clusters) {
    try {
      const rows = await query<{ metric_name: string; max_value: string; sum_value: string }>(auroraMetricsSql(c.cluster, c.region));
      const by = Object.fromEntries(rows.map((r) => [r.metric_name, r]));
      const volumeGb = Number(by.VolumeBytesUsed?.max_value || 0) / 1e9;
      const ios30d = Number(by.VolumeReadIOPs?.sum_value || 0) + Number(by.VolumeWriteIOPs?.sum_value || 0);
      out.push({ cluster: c.cluster, region: c.region, storageType: c.storage_type, members: Number(c.members), volumeGb, ios30d });
      onLog(`${c.cluster}: ${c.storage_type}, ${Math.round(volumeGb)} GB, ${(ios30d / 1e6).toFixed(1)}M I/Os in 30d`);
    } catch (e: any) {
      onLog(`${c.cluster}: metrics failed: ${describeError(e, `aurora metrics ${c.cluster} (aws_cloudwatch_metric_statistic_data_point)`)}`);
    }
  }
  return out;
}

/** Inserts new recommendations, refreshes open ones, and (for a full rules batch) resolves ones whose resource is gone. Returns open count. */
export function upsertRecommendations(runId: number, recs: RecInput[], source: "rules" | "agent", agentRequestId?: string, opts: { reconcile?: boolean } = {}): number {
  const select = db.prepare("select id, status from recommendations where fingerprint = ?");
  const insert = db.prepare(`
    insert into recommendations(fingerprint, run_id, source, rule, title, resource, resource_name, action_type, est_monthly_saving, tier, confidence, rationale, evidence, agent_request_id)
    values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
  const refresh = db.prepare(`
    update recommendations set run_id = ?, title = ?, est_monthly_saving = ?, tier = ?, confidence = ?, rationale = ?, evidence = ?, updated_at = datetime('now')
    where id = ?`);
  const seen = new Set<string>();
  const resolvedWithDecision: number[] = [];
  db.transaction(() => {
    for (const r of recs) {
      const fp = `${r.rule}:${r.resource}`;
      seen.add(fp);
      const existing = select.get(fp) as { id: number; status: string } | undefined;
      if (!existing) {
        insert.run(fp, runId, source, r.rule, r.title, r.resource, r.resourceName || null, r.actionType, r.estMonthlySaving, r.tier,
          r.confidence, r.rationale, JSON.stringify(r.evidence), agentRequestId || null);
      } else if (["open", "snoozed", "resolved"].includes(existing.status)) {
        // approved, pending, rejected and done rows are deliberately left alone: what a human decided (or is in
        // the middle of) must stay what it says (title, tier, saving), or a later agent answer could rewrite an
        // approval into something else under the same decision
        refresh.run(runId, r.title, r.estMonthlySaving, r.tier, r.confidence, r.rationale, JSON.stringify(r.evidence), existing.id);
        if (existing.status === "resolved") db.prepare("update recommendations set status = 'open' where id = ?").run(existing.id);
      }
    }
    // A partial batch (the watcher's flow-logs rule, an incident's fixes) must not resolve the rules it did not recompute.
    if (source === "rules" && opts.reconcile !== false) {
      // the daily review's items (rule review_*) come from the statistics, not from this batch: it refreshes them itself
      const stale = db.prepare("select id, fingerprint, decided_at from recommendations where status = 'open' and source = 'rules' and rule not like 'review_%'").all() as { id: number; fingerprint: string; decided_at: string | null }[];
      for (const s of stale) {
        if (seen.has(s.fingerprint)) continue;
        db.prepare("update recommendations set status = 'resolved', updated_at = datetime('now') where id = ?").run(s.id);
        // Only items that once carried a decision (reopened after approve/reject/...) are worth a Concept update; auto-resolved drafts are not.
        if (s.decided_at) resolvedWithDecision.push(s.id);
      }
    }
  })();
  for (const id of resolvedWithDecision) syncDecisionConceptInBackground(id);
  return (db.prepare("select count(*) as n from recommendations where status = 'open'").get() as { n: number }).n;
}

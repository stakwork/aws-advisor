import { Router } from "express";
import { authMiddleware } from "../auth.js";
import { config } from "../config.js";
import { db } from "../db.js";
import { CONCEPT_NAMESPACE, listDecisionConcepts } from "../concepts.js";
import { S, query } from "../steampipe.js";
import { credentialGate } from "../gate.js";
import { instanceHistory, rollupDaily } from "../history.js";
import { getReconciliation, lastFullMonth, listReconciliations, reconcileMonth } from "../reconcile.js";
import { ScopeKind, baselineSummary, listBaselines, refreshBaselines } from "../baselines.js";
import { latestReview, runReview } from "../review.js";
import { buildObserveBrief, dispatchObservation, latestObservation, listObservations } from "../observe.js";
import { refreshLogs, topLogGroups } from "../logs.js";
import { refreshTrail, trailSummary } from "../trail.js";
import { latestVerification, runVerifications, verificationSummary } from "../verify.js";
import { quantitiesFromHistory } from "../quantities.js";
import { listCommitments, refreshCommitments } from "../commitments.js";

/** The concept graph as the agent sees it: generic rules and internal decisions, with their full records. */
export const knowledge = Router();
knowledge.use(authMiddleware);

const headers = () => ({ "x-api-token": config.repo2graphToken });

knowledge.get("/knowledge", async (_req, res) => {
  if (!config.repo2graphUrl) return res.json({ configured: false, namespace: CONCEPT_NAMESPACE, generic: [], internal: [], learnings: [] });
  const concepts = await listDecisionConcepts(500);
  const local = new Map((db.prepare("select concept_id, fingerprint, status, scope, synced_at, error from concepts").all() as any[]).map((r) => [r.concept_id, r]));
  const recs = new Map((db.prepare("select fingerprint, id, title, resource, resource_name, action_type, status, decided_by, decided_at, decision_reason, est_monthly_saving from recommendations").all() as any[]).map((r) => [r.fingerprint, r]));
  const enrich = (c: any) => {
    const l = local.get(c.id);
    const rec = l ? recs.get(l.fingerprint) : undefined;
    return { ...c, synced_at: l?.synced_at ?? null, sync_error: l?.error ?? null, recommendation: rec ? { id: rec.id, title: rec.title, resource: rec.resource, resource_name: rec.resource_name, action_type: rec.action_type, status: rec.status, decided_by: rec.decided_by, decided_at: rec.decided_at, decision_reason: rec.decision_reason, est_monthly_saving: rec.est_monthly_saving } : null };
  };
  let learnings: any[] = [];
  try {
    const r = await fetch(`${config.repo2graphUrl}/learnings/all`, { headers: headers() });
    if (r.ok) { const data: any = await r.json(); learnings = (Array.isArray(data) ? data : data.learnings || []).filter((l: any) => String(l.id || "").startsWith("aws-advisor:")); }
  } catch { /* optional */ }
  res.json({
    configured: true,
    namespace: CONCEPT_NAMESPACE,
    generic: concepts.filter((c) => c.scope === "generic").map(enrich),
    internal: concepts.filter((c) => c.scope === "internal").map(enrich),
    learnings,
  });
});

knowledge.get("/knowledge/concept", async (req, res) => {
  const id = String(req.query.id || "");
  if (!id.startsWith(CONCEPT_NAMESPACE + "/")) return res.status(400).json({ error: "id must be in the advisor namespace" });
  if (!config.repo2graphUrl) return res.status(400).json({ error: "repo2graph is not configured" });
  try {
    const r = await fetch(`${config.repo2graphUrl}/gitree/concepts/${encodeURIComponent(id)}`, { headers: headers() });
    if (!r.ok) return res.status(r.status).json({ error: `repo2graph responded ${r.status}` });
    res.json(await r.json());
  } catch (e: any) {
    res.status(502).json({ error: e.message });
  }
});


// ---- per-instance hourly time series: probes (memory, disk, load) + CloudWatch CPU ------------------------
const cpuCache = new Map<string, { at: number; rows: any[]; error?: string }>();

knowledge.get("/instances/:id/timeseries", async (req, res) => {
  const id = String(req.params.id);
  if (!/^i-[0-9a-f]{8,17}$/.test(id)) return res.status(400).json({ error: "instance id expected" });
  const hours = Math.max(6, Math.min(24 * 30, Number(req.query.hours || 48)));
  const probes = (db.prepare("select id, collected_at, json from instance_metrics where instance_id = ? and datetime(collected_at) > datetime('now', ?) order by collected_at")
    .all(id, `-${hours} hours`) as { id: number; collected_at: string; json: string }[])
    .map((r) => {
      try {
        const d = JSON.parse(r.json);
        const mem = d.memory || {}; const cpus = Number(d.cpus || 0) || null;
        const disks: any[] = Array.isArray(d.disks) ? d.disks : [];
        const root = disks.find((x) => x.mount === "/") || disks.reduce((a, b) => (!a || Number(b.used_pct) > Number(a.used_pct) ? b : a), null as any);
        return {
          t: r.collected_at.endsWith("Z") ? r.collected_at : r.collected_at.replace(" ", "T") + "Z",
          mem_pct: mem.total_bytes ? Math.round((1000 * Number(mem.used_bytes)) / Number(mem.total_bytes)) / 10 : null,
          mem_used_gb: mem.used_bytes != null ? Math.round(Number(mem.used_bytes) / 1e8) / 10 : null,
          disk_pct: root ? Number(root.used_pct) : null,
          disk_mount: root ? root.mount : null,
          load1: d.load?.["1m"] != null ? Number(d.load["1m"]) : null,
          load_per_cpu: d.load?.["1m"] != null && cpus ? Math.round((100 * Number(d.load["1m"])) / cpus) / 100 : null,
          cpus,
          top_process: d.top_cpu?.[0]?.command || null,
        };
      } catch { return null; }
    })
    .filter(Boolean);

  let cpu: any[] = []; let cpu_error: string | undefined;
  const cached = cpuCache.get(id);
  if (cached && Date.now() - cached.at < 10 * 60 * 1000 && cached.rows.length && hours <= 48) { cpu = cached.rows; cpu_error = cached.error; }
  else {
    const gate = await credentialGate("timeseries");
    if (!gate.ok) cpu_error = "credentials not working";
    else {
      try {
        const rows = await query<{ timestamp: string; average: string; maximum: string }>(
          `select timestamp, average, maximum from ${S}.aws_ec2_instance_metric_cpu_utilization_hourly
           where instance_id = $1 and timestamp > now() - interval '${hours} hours' order by timestamp`, [id]);
        cpu = rows.map((r) => ({ t: new Date(r.timestamp).toISOString(), avg: Math.round(Number(r.average) * 10) / 10, max: Math.round(Number(r.maximum) * 10) / 10 }));
        cpuCache.set(id, { at: Date.now(), rows: cpu });
      } catch (e: any) { cpu_error = String(e?.message || e).slice(0, 200); }
    }
  }
  res.json({ instance_id: id, hours, probes, cpu, cpu_error });
});


// ---- long-lived statistics: daily roll-ups per instance and per container ------------------------------------
knowledge.get("/instances/:id/history", (req, res) => {
  const id = String(req.params.id);
  if (!/^i-[0-9a-f]{8,17}$/.test(id)) return res.status(400).json({ error: "instance id expected" });
  const days = Math.max(7, Math.min(400, Number(req.query.days || 90)));
  res.json(instanceHistory(id, days));
});
knowledge.post("/history/rollup", (req, res) => {
  const days = Math.max(1, Math.min(400, Number(req.query.days || 31)));
  res.json(rollupDaily(days));
});

// ---- bill reconstruction: our prices applied to last month's usage, against what was billed ----------------------
knowledge.get("/bill", (req, res) => {
  const month = typeof req.query.month === "string" && /^\d{4}-\d{2}$/.test(req.query.month) ? req.query.month : lastFullMonth();
  res.json({ month, reconciliation: getReconciliation(month), months: listReconciliations() });
});
knowledge.post("/bill/reconcile", async (req, res) => {
  const month = typeof req.query.month === "string" && /^\d{4}-\d{2}$/.test(req.query.month) ? req.query.month : lastFullMonth();
  const gate = await credentialGate("bill-reconcile");
  if (!gate.ok) return res.status(503).json({ error: gate.error || "credentials not working" });
  const log: string[] = [];
  try { res.json({ reconciliation: await reconcileMonth(month, (l) => log.push(l)), log }); }
  catch (e: any) { res.status(500).json({ error: e.message, log }); }
});

// ---- baselines: what is typical per gateway, instance and service ---------------------------------------------
knowledge.get("/baselines", (req, res) => {
  const kind = typeof req.query.scope_kind === "string" && ["nat", "instance", "service"].includes(req.query.scope_kind) ? (req.query.scope_kind as ScopeKind) : undefined;
  const id = typeof req.query.scope_id === "string" ? req.query.scope_id.slice(0, 200) : undefined;
  res.json({ summary: baselineSummary(), baselines: kind || id ? listBaselines(kind, id) : [] });
});
knowledge.post("/baselines/refresh", async (_req, res) => {
  const log: string[] = [];
  try { res.json({ ...(await refreshBaselines((l) => log.push(l))), log }); } catch (e: any) { res.status(500).json({ error: e.message, log }); }
});

// ---- the daily review of the collected statistics ---------------------------------------------------------------
knowledge.get("/review", (_req, res) => res.json(latestReview()));
knowledge.post("/review/run", async (_req, res) => {
  const log: string[] = [];
  try { res.json({ ...(await runReview((l) => log.push(l))), log }); } catch (e: any) { res.status(500).json({ error: e.message, log }); }
});

// ---- the agent's morning observation ---------------------------------------------------------------------------
knowledge.get("/observe", (_req, res) => res.json({ latest: latestObservation(), history: listObservations() }));
knowledge.get("/observe/brief", (_req, res) => res.type("text/plain; charset=utf-8").send(buildObserveBrief(new Date().toISOString().slice(0, 10)).text));
knowledge.post("/observe/run", async (req, res) => {
  try { res.json(await dispatchObservation(undefined, { force: req.query.force === "1" })); } catch (e: any) { res.status(400).json({ error: e.message }); }
});

// ---- CloudWatch Logs as a cost source, CloudTrail as the change feed ------------------------------------------
knowledge.get("/logs", (req, res) => res.json(topLogGroups(Math.max(5, Math.min(200, Number(req.query.limit || 25))))));
knowledge.post("/logs/refresh", async (_req, res) => { try { res.json(await refreshLogs()); } catch (e: any) { res.status(500).json({ error: e.message }); } });
knowledge.get("/trail", (req, res) => res.json(trailSummary(Math.max(1, Math.min(168, Number(req.query.hours || 24))))));
knowledge.post("/trail/refresh", async (req, res) => { try { res.json(await refreshTrail(Math.max(1, Math.min(168, Number(req.query.hours || 26))))); } catch (e: any) { res.status(500).json({ error: e.message }); } });

// ---- realised savings: approved recommendations checked against the bill ---------------------------------------
knowledge.get("/verifications", (_req, res) => res.json(verificationSummary()));
knowledge.get("/verifications/:id", (req, res) => res.json({ verification: latestVerification(Number(req.params.id)) }));
knowledge.post("/verifications/run", async (req, res) => {
  const log: string[] = [];
  const ids = typeof req.query.id === "string" ? [Number(req.query.id)] : undefined;
  try { res.json({ ...(await runVerifications({ force: req.query.force === "1", ids, onLog: (l) => log.push(l) })), log }); } catch (e: any) { res.status(500).json({ error: e.message, log }); }
});

// ---- usage quantities from our own history, beside Cost Explorer's, for the same days --------------------------
knowledge.get("/bill/quantities", async (req, res) => {
  const day = (v: unknown, d: string) => (typeof v === "string" && /^\d{4}-\d{2}-\d{2}$/.test(v) ? v : d);
  const today = new Date().toISOString().slice(0, 10);
  const from = day(req.query.from, `${today.slice(0, 7)}-01`); const to = day(req.query.to, today);
  try { res.json(await quantitiesFromHistory(from, to)); } catch (e: any) { res.status(500).json({ error: e.message }); }
});

// ---- commitments: utilisation and expiry -------------------------------------------------------------------------
knowledge.get("/commitments", (_req, res) => res.json({ commitments: listCommitments() }));
knowledge.post("/commitments/refresh", async (_req, res) => { try { res.json(await refreshCommitments()); } catch (e: any) { res.status(500).json({ error: e.message }); } });

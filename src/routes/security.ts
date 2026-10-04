/** Security posture: the aws_compliance scans, their findings and the reach of a flagged resource (src/compliance.ts). */
import { Router } from "express";
import { authMiddleware } from "../auth.js";
import { db, setSetting } from "../db.js";
import { hasConnectionFile } from "../steampipe.js";
import { pageParams, paginate } from "../paging.js";
import { COMPLIANCE_BENCHMARKS, complianceBusy, complianceFindings, enabledComplianceBenchmarks, exposureOfResource, getScan, latestCompletedScan, listScans, severityRank, startComplianceScan } from "../compliance.js";
import { accountScope, accountWhere, resourceInScope } from "../scope.js";

export const security = Router();
security.use(authMiddleware);

// The latest completed scan with the one before it (for the deltas), the recent scans, the benchmarks and the open security recommendations.
security.get("/security/summary", (req, res) => {
  const scope = accountScope(req.query as any); const inScope = resourceInScope(scope);
  const scans = listScans(15);
  const latestId = latestCompletedScan();
  const latest = scans.find((s) => s.id === latestId) ?? (latestId != null ? getScan(latestId) : null);
  const previous = latest ? scans.find((s) => s.status === "completed" && s.id < latest.id) ?? null : null;
  const recRows = (db.prepare("select status, resource from recommendations where action_type = 'security_fix'").all() as { status: string; resource: string | null }[]).filter((r) => inScope(r.resource));
  const recs = Object.entries(recRows.reduce((m, r) => ({ ...m, [r.status]: (m[r.status] || 0) + 1 }), {} as Record<string, number>)).map(([status, n]) => ({ status, n }));
  // the latest scan's alarms within the scope (a scan spans every AWS account; its own counts are organisation-wide)
  const scoped = latestId != null ? (() => { const a = accountWhere(scope); const r = db.prepare(`select count(*) as alarms, coalesce(sum(severity = 'critical'), 0) as critical, coalesce(sum(severity = 'high'), 0) as high, coalesce(sum(severity = 'medium'), 0) as medium, coalesce(sum(severity = 'low'), 0) as low, coalesce(sum(severity is null or severity not in ('critical', 'high', 'medium', 'low')), 0) as unrated from compliance_findings where scan_id = ? and ${a.sql}`).get(latestId, ...a.params) as any; return { alarms: r.alarms, critical: r.critical, high: r.high, counts: { critical: r.critical, high: r.high, medium: r.medium, low: r.low, unrated: r.unrated } }; })() : null;
  res.json({
    busy: complianceBusy(),
    running: scans.find((s) => s.status === "running") ?? null,
    latest: latest ? { ...latest, log: undefined } : null,
    previous: previous ? { id: previous.id, counts: previous.counts, alarms: previous.alarms } : null,
    scans,
    benchmarks: { all: COMPLIANCE_BENCHMARKS, enabled: enabledComplianceBenchmarks() },
    recommendations: Object.fromEntries(recs.map((r) => [r.status, r.n])),
    scope: scope ? { account: scope.id, ...scoped } : null,
    // the live ones, critical first (the severity is in the evidence), for the list at the top of the page
    open_recommendations: (db.prepare("select id, title, resource, resource_name, status, rule, evidence from recommendations where action_type = 'security_fix' and status in ('open', 'pending', 'approved') order by id desc limit 300").all() as any[])
      .filter((r: any) => inScope(r.resource)).slice(0, 100)
      .map(({ evidence, ...r }) => { let ev: any = {}; try { ev = JSON.parse(evidence || "{}"); } catch { /* keep empty */ } return { ...r, severity: ev.severity ?? null, exposed: Boolean(ev.exposure?.exposed), summary: ev.exposure?.summary ?? null }; })
      .sort((a, b) => severityRank(a.severity) - severityRank(b.severity) || Number(b.exposed) - Number(a.exposed) || b.id - a.id),
  });
});

// ?scan_id (default: latest completed), ?severity (critical|high|medium|low|unrated), ?control_id, ?q, ?new=1, ?page, ?page_size (default 50, max 200).
security.get("/security/findings", (req, res) => {
  const str = (v: unknown) => (typeof v === "string" && v ? v : undefined);
  const r = complianceFindings({ scope: accountScope(req.query as any),
    scan_id: req.query.scan_id ? Number(req.query.scan_id) : undefined,
    severity: str(req.query.severity), control_id: str(req.query.control_id), q: str(req.query.q),
    only_new: req.query.new === "1" || req.query.new === "true",
  });
  const p = paginate(r.rows, pageParams(req.query as Record<string, unknown>, { size: 50, max: 200 }));
  res.json({ scan_id: r.scan_id, total: p.total, page: p.page, page_size: p.page_size, findings: p.items, controls: r.controls, services: r.services });
});

security.get("/security/scans/:id", (req, res) => {
  const s = getScan(Number(req.params.id));
  if (!s) return res.status(404).json({ error: "no such scan" });
  res.json(s);
});

security.post("/security/scan", (_req, res) => {
  if (!hasConnectionFile()) return res.status(400).json({ error: "AWS credentials are not configured" });
  try { res.json({ id: startComplianceScan("manual") }); }
  catch (e: any) { res.status(409).json({ error: e?.message || String(e) }); }
});

security.put("/security/benchmarks", (req, res) => {
  const enabled = (Array.isArray(req.body?.enabled) ? req.body.enabled : []).filter((b: unknown) => COMPLIANCE_BENCHMARKS.some((x) => x.id === b));
  setSetting("compliance_benchmarks", JSON.stringify(enabled));
  res.json({ enabled });
});

// Who can reach a flagged resource (a security group's running instances, their public address, open ports with the app on them, domains).
security.get("/security/exposure", (req, res) => {
  const resource = typeof req.query.resource === "string" ? req.query.resource : "";
  if (!resource) return res.status(400).json({ error: "resource is required" });
  res.json({ resource, exposure: exposureOfResource(resource) });
});

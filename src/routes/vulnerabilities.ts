import { Router } from "express";
import { accountScope, resourceInScope } from "../scope.js";
import { authMiddleware } from "../auth.js";
import { pageParams, paginate } from "../paging.js";
import { listVulnScans, scanVulnerabilities, vulnScanBusy, vulnScanLog, vulnerabilityDetail, vulnerabilityMatches, vulnSummary, type VulnMatch } from "../software_vulns.js";

/**
 * The vulnerability posture (src/software_vulns.ts) for the Security page: the summary with the matches grouped by
 * advisory (worst verdict first), one advisory with every box it matches, a box's own list, the scans, and a scan on
 * demand (the cron does the same daily, after the software probe).
 */
export const vulnerabilities = Router();
vulnerabilities.use(authMiddleware);

export interface VulnGroup { vuln_id: string; source: string; severity: string | null; score: number | null; attack_vector: string | null; summary: string | null; cves: string[]; published: string | null; criticality: string; boxes: number; packages: string[]; fixed_versions: string[]; matches: VulnMatch[] }

/** Matches folded per advisory: the worst verdict leads, every box's row stays underneath. */
export function groupByVuln(matches: VulnMatch[]): VulnGroup[] {
  const groups = new Map<string, VulnGroup>();
  for (const m of matches) {
    const g = groups.get(m.vuln_id) ?? { vuln_id: m.vuln_id, source: m.source, severity: m.severity, score: m.score, attack_vector: m.attack_vector, summary: m.summary, cves: m.cves, published: m.published, criticality: m.criticality, boxes: 0, packages: [], fixed_versions: [], matches: [] };
    g.matches.push(m);
    if (!g.packages.includes(m.package)) g.packages.push(m.package);
    if (m.fixed_version && !g.fixed_versions.includes(m.fixed_version)) g.fixed_versions.push(m.fixed_version);
    groups.set(m.vuln_id, g);
  }
  for (const g of groups.values()) g.boxes = new Set(g.matches.map((m) => m.instance_id)).size;
  return [...groups.values()]; // the matches arrive sorted worst first, so the groups are too
}

// ?criticality=critical|exposed|mitigated|affected|local_only, ?severity=critical|high|medium|low|unrated, ?instance=i-…, ?q=<advisory, CVE, package or box>, ?page, ?page_size
vulnerabilities.get("/security/vulnerabilities", (req, res) => {
  // the matches of the scope's instances only: a member's boxes are its own, the parent's card shows the parent's
  const scope = accountScope(req.query as any); const inScope = resourceInScope(scope);
  const all = vulnerabilityMatches().filter((m) => inScope(m.instance_id));
  let rows = all;
  const crit = String(req.query.criticality || ""); if (crit) rows = rows.filter((m) => m.criticality === crit);
  const sev = String(req.query.severity || ""); if (sev) rows = rows.filter((m) => (m.severity ?? "unrated") === sev);
  const inst = String(req.query.instance || ""); if (inst) rows = rows.filter((m) => m.instance_id === inst);
  const q = String(req.query.q || "").toLowerCase().trim();
  if (q) rows = rows.filter((m) => [m.vuln_id, m.package, ...m.packages, ...m.cves, m.instance_id, m.instance_name ?? "", m.summary ?? "", m.process ?? ""].some((x) => String(x).toLowerCase().includes(q)));
  const groups = groupByVuln(rows);
  const p = pageParams(req.query as Record<string, unknown>, { size: 50, max: 200 });
  res.json({ summary: vulnSummary(all, scope ? (id) => inScope(id) : undefined), ...paginate(groups, p), scans: listVulnScans(8) });
});

vulnerabilities.get("/security/vulnerabilities/scans/:id", (req, res) => {
  const log = vulnScanLog(Number(req.params.id));
  if (log == null) return res.status(404).json({ error: "no such scan" });
  res.json({ id: Number(req.params.id), log });
});

vulnerabilities.get("/security/vulnerabilities/:id", (req, res) => {
  const d = vulnerabilityDetail(String(req.params.id));
  if (!d) return res.status(404).json({ error: "no such advisory stored" });
  res.json(d);
});

vulnerabilities.get("/instances/:id/vulnerabilities", (req, res) => {
  const id = String(req.params.id);
  res.json({ instance_id: id, matches: vulnerabilityMatches([id]) });
});

// Starts a scan now; the page polls the summary until it finishes. ?force=1 re-asks every version (ignores the recent-check cache).
vulnerabilities.post("/security/vulnerabilities/scan", (req, res) => {
  if (vulnScanBusy()) return res.status(409).json({ error: "a vulnerability scan is already running" });
  const force = req.query.force === "1" || (req.body && req.body.force === true);
  scanVulnerabilities({ trigger: "manual", force })
    .then(async () => { try { const { mirrorSoftware } = await import("../graph_software.js"); await mirrorSoftware(); } catch (e: any) { console.error(`[graph] software: ${e?.message || e}`); } })
    .catch((e) => console.error(`[vulns] scan failed: ${e?.message || e}`));
  res.status(202).json({ started: true });
});

import { Router } from "express";
import { authMiddleware } from "../auth.js";
import { config } from "../config.js";
import { db } from "../db.js";
import { PROBE_DEFS, PROBE_KINDS, type ProbeKind, defaultProbeScript, probeDocument, probeDocumentInfo, probeScriptOverride, probeScriptTemplate, resetProbeScript, setProbeScriptOverride } from "../probes.js";
import { probeDocumentStatus } from "../probes_status.js";
import { probeKindSettings, probePass, probeTargets } from "../probe_pass.js";
import { softwareOn, softwareSummary, wherePackage } from "../software_inventory.js";

/**
 * Settings > Probes: what each probe collects, its script (default or edited), its SSM document and whether the
 * deployed one is current, its schedule and scope, when it last ran and how many boxes it reached; plus the software
 * inventory the software probe fills. The scripts are the only editable part; an edit is refused unless it still looks
 * like a read-only probe (src/probes.ts setProbeScriptOverride), and it takes effect when the document is redeployed.
 */
export const probes = Router();
probes.use(authMiddleware);

const isKind = (k: string): k is ProbeKind => (PROBE_KINDS as readonly string[]).includes(k);
const cronOff = (c: string) => /^(off|none|disabled|0|false)$/i.test(String(c || "").trim()) || !String(c || "").trim();

/** One kind as the page shows it. */
function describe(kind: ProbeKind) {
  const def = PROBE_DEFS[kind];
  const last = db.prepare("select max(collected_at) as at, count(distinct instance_id) as boxes from instance_metrics where coalesce(kind, 'all') in (?, ?) and datetime(collected_at) > datetime('now', '-1 day')").get(kind, kind === "software" ? "software" : "all") as { at: string | null; boxes: number };
  const ever = db.prepare("select count(distinct instance_id) as boxes, count(*) as rows_ from instance_metrics where coalesce(kind, 'all') in (?, ?)").get(kind, kind === "software" ? "software" : "all") as { boxes: number; rows_: number };
  const cron = (config as any)[def.cron_key] as string;
  const { scope, intervalHours } = probeKindSettings(kind);
  const info = probeDocumentInfo(kind);
  return {
    ...def, cron, cron_off: cronOff(cron), scope, interval_hours: intervalHours,
    document: info,
    script: { default: defaultProbeScript(kind), override: probeScriptOverride(kind), effective: probeScriptTemplate(kind), edited: probeScriptOverride(kind) != null, lines: probeScriptTemplate(kind).split("\n").length },
    last_24h: { at: last?.at ?? null, boxes: Number(last?.boxes || 0) }, ever: { boxes: Number(ever?.boxes || 0), rows: Number(ever?.rows_ || 0) },
    candidates_now: probeTargets(kind).length,
  };
}

probes.get("/probes", async (req, res) => {
  const withStatus = req.query.status !== "0";
  let status: Awaited<ReturnType<typeof probeDocumentStatus>> | null = null;
  if (withStatus) { try { status = await probeDocumentStatus(); } catch { status = null; } }
  res.json({ base_document: config.probeDocument, kinds: PROBE_KINDS.map((k) => ({ ...describe(k), deployed: status?.find((s) => s.kind === k) ?? null })), legacy_rows: Number((db.prepare("select count(*) as n from instance_metrics where coalesce(kind, 'all') = 'all'").get() as any)?.n || 0) });
});

probes.get("/probes/:kind/document", (req, res) => {
  const kind = String(req.params.kind);
  if (!isKind(kind)) return res.status(404).json({ error: `no probe kind ${kind}; one of ${PROBE_KINDS.join(", ")}` });
  res.json(probeDocument(kind));
});

probes.put("/probes/:kind/script", (req, res) => {
  const kind = String(req.params.kind);
  if (!isKind(kind)) return res.status(404).json({ error: `no probe kind ${kind}` });
  try { setProbeScriptOverride(kind, String(req.body?.text ?? "")); res.json(describe(kind)); }
  catch (e: any) { res.status(400).json({ error: e.message }); }
});

probes.delete("/probes/:kind/script", (req, res) => {
  const kind = String(req.params.kind);
  if (!isKind(kind)) return res.status(404).json({ error: `no probe kind ${kind}` });
  resetProbeScript(kind);
  res.json(describe(kind));
});

probes.get("/probes/:kind/targets", (req, res) => {
  const kind = String(req.params.kind);
  if (!isKind(kind)) return res.status(404).json({ error: `no probe kind ${kind}` });
  res.json({ kind, targets: probeTargets(kind) });
});

probes.post("/probes/:kind/pass", async (req, res) => {
  const kind = String(req.params.kind);
  if (!isKind(kind)) return res.status(404).json({ error: `no probe kind ${kind}` });
  try { res.json(await probePass(kind)); } catch (e: any) { res.status(500).json({ error: e.message }); }
});

// ---- the software inventory (src/software_inventory.ts) ------------------------------------------------------------
probes.get("/software", (_req, res) => res.json(softwareSummary()));
probes.get("/software/where", (req, res) => {
  const name = String(req.query.name || "").trim();
  if (!name || name.length > 120) return res.status(400).json({ error: "name is required" });
  res.json({ name, where: wherePackage(name) });
});
probes.get("/instances/:id/software", (req, res) => {
  const id = String(req.params.id);
  if (!/^i-[0-9a-f]{8,17}$/.test(id)) return res.status(400).json({ error: "an EC2 instance id is expected" });
  res.json({ instance_id: id, ...softwareOn(id, { q: typeof req.query.q === "string" ? req.query.q : undefined, includeGone: req.query.gone === "1", limit: Number(req.query.limit) || undefined }) });
});

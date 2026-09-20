import { Router } from "express";
import { authMiddleware } from "../auth.js";
import { accountId, enabled, graphStats, graphUriForDisplay, mirrorAll, resourceView, verifyConnection, wipeMirror } from "../graph_mirror.js";

/**
 * The Neo4j mirror (src/graph_mirror.ts) as the UI sees it: whether it is configured and reachable, what is
 * in it, a full resync on demand, and one resource with everything linked to it. Nothing here feeds back into
 * the advisor's own logic: SQLite stays the source of truth.
 */
export const graph = Router();
graph.use(authMiddleware);

graph.get("/graph", async (_req, res) => {
  const uri = graphUriForDisplay();
  if (!enabled()) return res.json({ configured: false, uri: null, connected: false, stats: null, account_id: accountId() });
  const conn = await verifyConnection();
  let stats = null; let error = conn.error ?? null;
  if (conn.connected) {
    try { stats = await graphStats(); } catch (e: any) { error = String(e?.message || e).slice(0, 300); }
  }
  res.json({ configured: true, uri, connected: conn.connected, server: conn.server ?? null, error, stats, account_id: accountId() });
});

// Full resync (idempotent). ?wipe=1 first removes every Advisor node of this account, so stale nodes disappear too.
graph.post("/graph/sync", async (req, res) => {
  if (!enabled()) return res.status(400).json({ error: "the graph mirror is not configured (NEO4J_URI)" });
  const wipe = req.query.wipe === "1" || req.query.wipe === "true" || req.body?.wipe === true;
  try {
    const t0 = Date.now();
    const deleted = wipe ? (await wipeMirror()).deleted : 0;
    const counts = await mirrorAll();
    const stats = await graphStats();
    res.json({ ...counts, wiped: deleted, took_ms: Date.now() - t0, stats });
  } catch (e: any) {
    res.status(502).json({ error: String(e?.message || e).slice(0, 300) });
  }
});

graph.get("/graph/resource/:id", async (req, res) => {
  if (!enabled()) return res.status(400).json({ error: "the graph mirror is not configured (NEO4J_URI)", configured: false });
  try {
    const view = await resourceView(String(req.params.id));
    if (!view) return res.status(404).json({ error: "not in the graph yet; resync or wait for the next run" });
    res.json(view);
  } catch (e: any) {
    res.status(502).json({ error: String(e?.message || e).slice(0, 300) });
  }
});

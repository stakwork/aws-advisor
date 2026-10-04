import { Router } from "express";
import { accountScope } from "../scope.js";
import { authMiddleware } from "../auth.js";
import { accountId, enabled, graphStats, graphUriForDisplay, mirrorAll, resourceView, verifyConnection, wipeMirror } from "../graph_mirror.js";
import { graphBill, listSystems, logAttributionReport, mirrorKnowledge, systemView } from "../graph_knowledge.js";
import { filterDetail, listGatewayNodes, listInterfaces, listPublicIps, listSegments, mirrorNetwork, networkDetail, networkOverview } from "../graph_network.js";

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

// ---- the knowledge layer: systems, one system, the bill as the graph explains it ------------------------------
const off = (res: any) => res.status(503).json({ error: "The Neo4j mirror is not configured (Settings > Graph mirror)" });
// ?account= scopes to one account (the knowledge layer exists for AWS accounts today; another provider's scope gets an empty list, never AWS data)
graph.get("/graph/systems", async (req, res) => { if (!enabled()) return off(res); try { const scope = accountScope(req.query as any); res.json({ systems: await listSystems(typeof req.query.kind === "string" ? req.query.kind : undefined, scope?.id ?? accountId()) }); } catch (e: any) { res.status(500).json({ error: e.message }); } });
graph.get("/graph/system/:id", async (req, res) => { if (!enabled()) return off(res); try { const v = await systemView(String(req.params.id)); v ? res.json(v) : res.status(404).json({ error: "no such system" }); } catch (e: any) { res.status(500).json({ error: e.message }); } });
graph.get("/graph/bill", async (_req, res) => { if (!enabled()) return off(res); try { res.json(await graphBill()); } catch (e: any) { res.status(500).json({ error: e.message }); } });
graph.post("/graph/knowledge", async (_req, res) => { if (!enabled()) return off(res); try { res.json(await mirrorKnowledge()); } catch (e: any) { res.status(500).json({ error: e.message }); } });
// Log groups and the systems they belong to: how each was attributed, which instances were seen shipping to it, and the unattributed ones with their closest candidates.
// Where logs go for the account the sidebar looks at: CloudWatch groups with their attributed writers for an AWS account, log drains with the projects they cover for a Vercel team.
graph.get("/graph/logs", async (req, res) => { if (!enabled()) return off(res); try { const scope = accountScope(req.query as any); res.json({ account: scope?.id ?? accountId(), ...(await logAttributionReport(Math.min(2000, Math.max(50, Number(req.query.limit) || 500)), scope?.id ?? accountId())) }); } catch (e: any) { res.status(500).json({ error: e.message }); } });

// ---- the network layer (src/graph_network.ts): the Network page ------------------------------------------------------
graph.get("/graph/network", async (req, res) => { if (!enabled()) return off(res); try { res.json(await networkOverview(accountScope(req.query as any)?.id ?? accountId())); } catch (e: any) { res.status(500).json({ error: e.message }); } });
graph.get("/graph/network/:id", async (req, res) => { if (!enabled()) return off(res); try { const v = await networkDetail(String(req.params.id), accountScope(req.query as any)?.id ?? accountId()); v ? res.json(v) : res.status(404).json({ error: "no such network" }); } catch (e: any) { res.status(500).json({ error: e.message }); } });
graph.get("/graph/filter/:id", async (req, res) => { if (!enabled()) return off(res); try { const v = await filterDetail(String(req.params.id)); v ? res.json(v) : res.status(404).json({ error: "no such filter" }); } catch (e: any) { res.status(500).json({ error: e.message }); } });
graph.get("/graph/network-segments", async (req, res) => { if (!enabled()) return off(res); try { res.json({ segments: await listSegments(accountScope(req.query as any)?.id ?? accountId()) }); } catch (e: any) { res.status(500).json({ error: e.message }); } });
graph.get("/graph/network-gateways", async (req, res) => { if (!enabled()) return off(res); try { res.json({ gateways: await listGatewayNodes(accountScope(req.query as any)?.id ?? accountId()) }); } catch (e: any) { res.status(500).json({ error: e.message }); } });
graph.get("/graph/network-interfaces", async (req, res) => { if (!enabled()) return off(res); try { res.json({ interfaces: await listInterfaces(accountScope(req.query as any)?.id ?? accountId()) }); } catch (e: any) { res.status(500).json({ error: e.message }); } });
graph.get("/graph/network-public-ips", async (_req, res) => { if (!enabled()) return off(res); try { res.json({ public_ips: await listPublicIps() }); } catch (e: any) { res.status(500).json({ error: e.message }); } });
// Rebuild the network layer and every endpoint's verdicts from the current inventory (what the post-run hook does).
graph.post("/graph/network/sync", async (_req, res) => { if (!enabled()) return off(res); try { res.json(await mirrorNetwork()); } catch (e: any) { res.status(500).json({ error: e.message }); } });

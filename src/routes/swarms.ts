/** Cost per swarm (src/swarm_costs.ts): the month's report, one swarm's daily series, and a refresh. */
import { Router } from "express";
import { authMiddleware } from "../auth.js";
import { listSwarmCostHistory, refreshSwarmCosts, swarmCostMonths, swarmCostReport } from "../swarm_costs.js";

export const swarms = Router();
swarms.use(authMiddleware);

// ?month=YYYY-MM (default: the current month)
swarms.get("/swarms/costs", async (req, res) => {
  const month = req.query.month ? String(req.query.month) : undefined;
  if (month && !/^\d{4}-\d{2}$/.test(month)) return res.status(400).json({ error: "month must be YYYY-MM" });
  try { res.json({ ...(await swarmCostReport(month)), months: swarmCostMonths() }); } catch (e: any) { res.status(500).json({ error: e?.message || String(e) }); }
});
swarms.post("/swarms/costs/refresh", async (_req, res) => {
  try { res.json(await refreshSwarmCosts()); } catch (e: any) { res.status(500).json({ error: e?.message || String(e) }); }
});
swarms.get("/swarms/:id/costs", (req, res) => {
  const id = String(req.params.id);
  if (!/^i-[0-9a-f]{8,17}$/.test(id)) return res.status(400).json({ error: "an instance id is required" });
  res.json({ instance_id: id, days: listSwarmCostHistory(id) });
});

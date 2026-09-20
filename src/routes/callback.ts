import { Router } from "express";
import { config } from "../config.js";
import { safeEqual } from "../auth.js";
import { handleAgentResult } from "../agent.js";

/**
 * repo2graph's webhook. It carries no API token; it echoes CALLBACK_SECRET as ?key= instead. Mounted in
 * src/index.ts BEFORE every router that applies authMiddleware, because a router-level `use(authMiddleware)`
 * answers 401 to any /api path that passes through it, this one included.
 */
export const callback = Router();
callback.post("/agent-callback", async (req, res) => {
  if (config.callbackSecret && !safeEqual(req.query.key, config.callbackSecret)) return res.status(401).json({ error: "bad key" });
  const { request_id, ...rest } = req.body || {};
  console.log(`[agent-callback] ${request_id} status=${rest.status}`);
  if (!request_id) return res.status(400).json({ error: "request_id required" });
  try {
    res.json(await handleAgentResult(request_id, rest));
  } catch (e: any) {
    res.status(404).json({ error: e.message });
  }
});

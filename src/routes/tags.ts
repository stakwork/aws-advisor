/** Tag hygiene: the stored report and a refresh (src/tag_hygiene.ts). */
import { Router } from "express";
import { authMiddleware } from "../auth.js";
import { refreshTagHygiene, tagHygieneReport } from "../tag_hygiene.js";

export const tags = Router();
tags.use(authMiddleware);

tags.get("/tags/hygiene", (_req, res) => res.json(tagHygieneReport()));
tags.post("/tags/hygiene/refresh", async (_req, res) => {
  try { const r = await refreshTagHygiene((l) => console.log(`[tags] ${l}`)); res.json({ ...r, report: tagHygieneReport() }); }
  catch (e: any) { res.status(500).json({ error: e?.message || String(e) }); }
});

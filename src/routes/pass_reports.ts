/** The narrated passes (src/pass_report.ts): the latest reports for the Auto-actions page, and a resend of one message to Sphinx. */
import { Router } from "express";
import { authMiddleware } from "../auth.js";
import { getPassReport, listPassReports, resendPassReport } from "../pass_report.js";

export const passReports = Router();
passReports.use(authMiddleware);

// ?limit= (default 5, max 200): newest first, each with its result, grade and Sphinx receipt.
passReports.get("/actions/pass-reports", (req, res) => {
  const limit = Number(req.query.limit) || 5;
  res.json(listPassReports(limit).map(({ brief, ...r }) => ({ ...r, brief_chars: brief.length })));
});
passReports.get("/actions/pass-reports/:id", (req, res) => {
  const r = getPassReport(Number(req.params.id));
  return r ? res.json(r) : res.status(404).json({ error: "not found" });
});
passReports.post("/actions/pass-reports/:id/resend", async (req, res) => {
  try { res.json({ result: await resendPassReport(Number(req.params.id)) }); }
  catch (e: any) { res.status(400).json({ error: e?.message || String(e) }); }
});

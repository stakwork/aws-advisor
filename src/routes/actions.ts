/** The executor's API: status, the ledger, a preview, a pass, and apply / revert by row (src/executor.ts). */
import { Router } from "express";
import { authMiddleware } from "../auth.js";
import { actuatorPolicy, actuatorTrustPolicy } from "../permissions.js";
import { sdkIdentity } from "../steampipe.js";
import { applyAction, dispatchActionNotifications, executorStatus, getAction, listActions, previewActions, revertAction, runExecutorPass, verifyAction } from "../executor.js";

export const actions = Router();
actions.use(authMiddleware);

actions.get("/actions/status", async (_req, res) => {
  const status = await executorStatus();
  const read = await sdkIdentity(8000);
  res.json({ ...status, read_identity: read.ok ? read.arn : null, policy: actuatorPolicy(), trust_policy: actuatorTrustPolicy(read.ok ? read.arn.replace(/^arn:aws:sts::(\d+):assumed-role\/([^/]+)\/.*$/, "arn:aws:iam::$1:role/$2") : undefined) });
});
actions.get("/actions", (req, res) => res.json(listActions({ status: String(req.query.status || "all"), kind: req.query.kind ? String(req.query.kind) : undefined, limit: Number(req.query.limit) || 200 })));
actions.get("/actions/preview", async (_req, res) => {
  try { res.json(await previewActions()); } catch (e: any) { res.status(500).json({ error: e?.message || String(e) }); }
});
actions.post("/actions/run", async (_req, res) => {
  try { const r = await runExecutorPass("manual"); dispatchActionNotifications().catch(() => {}); res.json(r); } catch (e: any) { res.status(500).json({ error: e?.message || String(e) }); }
});
actions.get("/actions/:id", (req, res) => { const a = getAction(Number(req.params.id)); if (!a) return res.status(404).json({ error: "no such action" }); res.json(a); });
actions.post("/actions/:id/apply", async (req, res) => {
  try { const a = await applyAction(Number(req.params.id), "manual"); dispatchActionNotifications().catch(() => {}); res.json(a); } catch (e: any) { res.status(400).json({ error: e?.message || String(e) }); }
});
actions.post("/actions/:id/verify", async (req, res) => {
  try { res.json(await verifyAction(Number(req.params.id))); } catch (e: any) { res.status(400).json({ error: e?.message || String(e) }); }
});
actions.post("/actions/:id/revert", async (req, res) => {
  try { const a = await revertAction(Number(req.params.id), "manual"); dispatchActionNotifications().catch(() => {}); res.json(a); } catch (e: any) { res.status(400).json({ error: e?.message || String(e) }); }
});

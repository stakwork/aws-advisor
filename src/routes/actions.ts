/** The executor's API: status, the ledger, a preview, a pass, and apply / revert by row (src/executor.ts). */
import { Router } from "express";
import { authMiddleware } from "../auth.js";
import { actuatorPolicy, actuatorTrustPolicy } from "../permissions.js";
import { sdkIdentity } from "../steampipe.js";
import { applyAction, dispatchActionNotifications, executorStatus, getAction, listActions, pauseActions, pauseState, previewActions, resumeActions, revertAction, runExecutorPass, verifyAction } from "../executor.js";
import { askAboutAction, listMessages, threadForAction } from "../chat.js";

export const actions = Router();
actions.use(authMiddleware);

actions.get("/actions/status", async (_req, res) => {
  const status = await executorStatus();
  const read = await sdkIdentity(8000);
  res.json({ ...status, read_identity: read.ok ? read.arn : null, policy: actuatorPolicy(), trust_policy: actuatorTrustPolicy(read.ok ? read.arn.replace(/^arn:aws:sts::(\d+):assumed-role\/([^/]+)\/.*$/, "arn:aws:iam::$1:role/$2") : undefined) });
});
// ?status=all (default) | proposed | applied | …, ?kind=<action kind>, ?page (1-based), ?page_size (default 25, max 200),
// ?id=<row id> without ?page lands on the page holding that row (deep links from Sphinx).
actions.get("/actions", (req, res) => {
  const kind = req.query.kind ? String(req.query.kind) : undefined;
  if (kind && !/^[a-z0-9_]{1,40}$/.test(kind)) return res.status(400).json({ error: "kind must be an action kind (letters, digits, _)" });
  const id = Number(req.query.id);
  res.json(listActions({ status: String(req.query.status || "all"), kind, page: Number(req.query.page) || undefined, page_size: Number(req.query.page_size) || undefined, id: Number.isInteger(id) ? id : undefined }));
});
actions.get("/actions/preview", async (_req, res) => {
  try { res.json(await previewActions()); } catch (e: any) { res.status(500).json({ error: e?.message || String(e) }); }
});
actions.post("/actions/run", async (_req, res) => {
  try { const r = await runExecutorPass("manual"); dispatchActionNotifications().catch(() => {}); res.json(r); } catch (e: any) { res.status(500).json({ error: e?.message || String(e) }); }
});
// The kill switch: { reason?, until? (ISO date or hours as a number) } pauses planning and applying; revert stays allowed.
actions.post("/actions/pause", (req, res) => {
  try {
    const b = req.body || {};
    const reason = typeof b.reason === "string" ? b.reason.slice(0, 300) : "";
    let until: string | undefined;
    if (b.until != null && b.until !== "") {
      const n = Number(b.until);
      until = Number.isFinite(n) && typeof b.until !== "string" ? new Date(Date.now() + n * 3600000).toISOString() : String(b.until);
    }
    res.json(pauseActions("page", reason, until));
  } catch (e: any) { res.status(400).json({ error: e?.message || String(e) }); }
});
actions.post("/actions/resume", (_req, res) => { res.json(resumeActions("page")); });
actions.get("/actions/pause", (_req, res) => { res.json(pauseState()); });
actions.get("/actions/:id", (req, res) => { const a = getAction(Number(req.params.id)); if (!a) return res.status(404).json({ error: "no such action" }); res.json(a); });
// The thread on a ledger row (src/chat.ts): every message, oldest first; none until the first message.
actions.get("/actions/:id/messages", (req, res) => {
  const id = Number(req.params.id);
  if (!getAction(id)) return res.status(404).json({ error: "no such action" });
  const t = threadForAction(id, false);
  res.json(t ? listMessages(t.id) : []);
});
// Body: { message, by? }. Records the message and asks the agent; the answer lands through the webhook (202 while pending).
actions.post("/actions/:id/messages", async (req, res) => {
  try {
    const r = await askAboutAction(Number(req.params.id), String(req.body?.message ?? ""), typeof req.body?.by === "string" && req.body.by ? req.body.by : "ui");
    res.status(202).json(r);
  } catch (e: any) { res.status(e.code === "not_found" ? 404 : e.code === "pending" ? 409 : /empty/.test(e.message) ? 400 : 500).json({ error: e.message }); }
});
actions.post("/actions/:id/apply", async (req, res) => {
  try { const a = await applyAction(Number(req.params.id), "manual"); dispatchActionNotifications().catch(() => {}); res.json(a); } catch (e: any) { res.status(400).json({ error: e?.message || String(e) }); }
});
actions.post("/actions/:id/verify", async (req, res) => {
  try { res.json(await verifyAction(Number(req.params.id))); } catch (e: any) { res.status(400).json({ error: e?.message || String(e) }); }
});
actions.post("/actions/:id/revert", async (req, res) => {
  try { const a = await revertAction(Number(req.params.id), "manual"); dispatchActionNotifications().catch(() => {}); res.json(a); } catch (e: any) { res.status(400).json({ error: e?.message || String(e) }); }
});

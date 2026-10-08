/** The executor's API: status, the ledger, a preview, a pass, and apply / revert by row (src/executor.ts). */
import { Router } from "express";
import { authMiddleware } from "../auth.js";
import { actuatorPolicy, actuatorTrustPolicy } from "../permissions.js";
import { hostIdentity, sdkIdentity } from "../steampipe.js";
import { roleAccount } from "../accounts.js";
import { config } from "../config.js";
import { consentErrorStatus, runAsPerson } from "../consent.js";
import { PreviewError, previewAsPerson } from "../preview.js";
import { actuatorCapabilities, actuatorCapabilitiesByAccount, applyAction, deleteActions, dispatchActionNotifications, executorStatus, getAction, listActions, pauseActions, pauseState, previewActions, resumeActions, revertAction, runExecutorPass, stepAction, verifyAction } from "../executor.js";
import { askAboutAction, listMessages, threadForAction } from "../chat.js";
import { eventsForAction, listExecutorLog } from "../executor_log.js";
import { environmentTimeline } from "../capacity_timeline.js";
import { accountScope } from "../scope.js";

export const actions = Router();
actions.use(authMiddleware);

// The activity log (src/executor_log.ts): the newest passes with their lines and events, and the events made outside a pass. ?limit (default 30, max 200).
actions.get("/actions/log", (req, res) => { res.json(listExecutorLog({ limit: Number(req.query.limit) || undefined })); });

// The scaling timeline of a Beanstalk environment (src/capacity_timeline.ts): the next 24 hours of MinSize as the hourly
// pass will set it, the recent capacity and pressure rows, the pressure events. :env is the environment name or id;
// ?region, ?account_id as the panel has them; ?floor, ?ceiling, ?on the tags the panel just read (else the stored pattern's band).
actions.get("/actions/beanstalk/:env/timeline", async (req, res) => {
  const n = (v: unknown) => (v == null || v === "" || !Number.isFinite(Number(v)) ? null : Number(v));
  const s = (v: unknown) => (typeof v === "string" && v ? v : null);
  try {
    const t = await environmentTimeline({ env: String(req.params.env), region: s(req.query.region), account_id: s(req.query.account_id), floor: n(req.query.floor), ceiling: n(req.query.ceiling), consent: req.query.on == null ? null : req.query.on === "1" || req.query.on === "true" });
    if (!t) return res.status(404).json({ error: "environment not known yet: the capacity pass records it on its next run" });
    res.json(t);
  } catch (e: any) { res.status(500).json({ error: e?.message || String(e) }); }
});

// Re-check what the roles may do: drops the denials learned from failed applies (a role was widened) and simulates again,
// the parent's role and every member's (body.account_id narrows it to one account).
actions.post("/actions/capabilities/recheck", async (req, res) => {
  const accountId = typeof req.body?.account_id === "string" && /^\d{12}$/.test(req.body.account_id) ? req.body.account_id : null;
  try {
    if (accountId) { const r = await actuatorCapabilities(accountId, true); return res.json({ account_id: accountId, capabilities: r.caps, capabilities_note: r.note ?? null }); }
    const all = await actuatorCapabilitiesByAccount(true);
    const parent = all.find((a) => a.is_parent);
    res.json({ capabilities: parent?.capabilities ?? {}, capabilities_note: parent?.capabilities_note ?? null, accounts: all.filter((a) => !a.is_parent) });
  } catch (e: any) { res.status(500).json({ error: e?.message || String(e) }); }
});
actions.get("/actions/status", async (_req, res) => {
  const status = await executorStatus();
  const [read, host] = await Promise.all([sdkIdentity(8000), hostIdentity(8000)]);
  // the actuator is assumed from the host's own identity when it lives in the host's account (src/executor.ts actuatorMaster)
  const byHost = Boolean(host && config.actRoleArn && roleAccount(config.actRoleArn) === host.accountId);
  const readArn = read.ok ? read.arn.replace(/^arn:aws:sts::(\d+):assumed-role\/([^/]+)\/.*$/, "arn:aws:iam::$1:role/$2") : undefined;
  res.json({ ...status, read_identity: read.ok ? read.arn : null, host_identity: host?.arn ?? null, trust_principal: byHost ? "host" : "read", policy: actuatorPolicy(), trust_policy: actuatorTrustPolicy(byHost ? host!.arn : readArn) });
});
// ?status=all (default) | proposed | applied | …, ?kind=<action kind>, ?page (1-based), ?page_size (default 25, max 200),
// ?id=<row id> without ?page lands on the page holding that row (deep links from Sphinx).
actions.get("/actions", (req, res) => {
  const kind = req.query.kind ? String(req.query.kind) : undefined;
  if (kind && !/^[a-z0-9_]{1,40}$/.test(kind)) return res.status(400).json({ error: "kind must be an action kind (letters, digits, _)" });
  const id = Number(req.query.id);
  res.json(listActions({ scope: accountScope(req.query as any), status: String(req.query.status || "all"), kind, page: Number(req.query.page) || undefined, page_size: Number(req.query.page_size) || undefined, id: Number.isInteger(id) ? id : undefined }));
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
// One row with its history from the activity log (every apply, read-back and revert on it, oldest first).
actions.get("/actions/:id", (req, res) => { const a = getAction(Number(req.params.id)); if (!a) return res.status(404).json({ error: "no such action" }); res.json({ ...a, events: eventsForAction(a.id) }); });
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
// What "run as me" would send for a row, applying and undoing: its own apply and revert run with writes recorded, not sent (src/preview.ts).
actions.get("/actions/:id/preview", async (req, res) => {
  try { res.json(await previewAsPerson(Number(req.params.id))); }
  catch (e: any) { res.status(e instanceof PreviewError ? e.status : 500).json({ error: e?.message || String(e) }); }
});
// A consent row done with a person's own temporary credentials (src/consent.ts runAsPerson): used once, never stored or logged.
actions.post("/actions/:id/as-person", async (req, res) => {
  const verb = req.body?.verb === "revert" ? "revert" : "apply";
  try { const a = await runAsPerson(Number(req.params.id), verb, req.body?.credentials); dispatchActionNotifications().catch(() => {}); res.json(a); }
  catch (e: any) { res.status(consentErrorStatus(e)).json({ error: e?.message || String(e) }); }
});
// Delete rows that never changed anything (proposed, failed, refused, stale): the events and the thread go with them, and the graph node.
actions.post("/actions/delete", async (req, res) => {
  const ids = (Array.isArray(req.body?.ids) ? req.body.ids : [req.body?.id]).map(Number).filter((n: number) => Number.isInteger(n) && n > 0);
  if (!ids.length) return res.status(400).json({ error: "ids: the rows to delete" });
  try { res.json(await deleteActions(ids, { force: req.body?.force === true })); } catch (e: any) { res.status(400).json({ error: e?.message || String(e) }); }
});
actions.post("/actions/:id/apply", async (req, res) => {
  try { const a = await applyAction(Number(req.params.id), "manual"); dispatchActionNotifications().catch(() => {}); res.json(a); } catch (e: any) { res.status(400).json({ error: e?.message || String(e) }); }
});
actions.post("/actions/:id/verify", async (req, res) => {
  try { res.json(await verifyAction(Number(req.params.id))); } catch (e: any) { res.status(400).json({ error: e?.message || String(e) }); }
});
// A stage only a person starts on a staged row (the cut-over of a live hibernation relaunch): the row's facts.offers name them.
actions.post("/actions/:id/step/:name", async (req, res) => {
  try { res.json(await stepAction(Number(req.params.id), String(req.params.name), "page")); } catch (e: any) { res.status(400).json({ error: e?.message || String(e) }); }
});
actions.post("/actions/:id/revert", async (req, res) => {
  try { const a = await revertAction(Number(req.params.id), "manual"); dispatchActionNotifications().catch(() => {}); res.json(a); } catch (e: any) { res.status(400).json({ error: e?.message || String(e) }); }
});

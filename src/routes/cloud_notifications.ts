import { Router } from "express";
import { authMiddleware } from "../auth.js";
import { accountScope } from "../scope.js";
import { cloudNotificationsSummary, listCloudNotifications, refreshCloudNotifications, type Feed } from "../cloud_notifications.js";

/**
 * The provider's notifications (src/cloud_notifications.ts) for the Changes page: the last days' events with the
 * summary, and a refresh on demand (the daily logs job does the same). Not the advisor's own chat notifications,
 * which are /notifications in routes/api.ts.
 */
export const cloudNotifications = Router();
cloudNotifications.use(authMiddleware);

const str = (v: unknown) => (typeof v === "string" && v ? v : undefined);
cloudNotifications.get("/cloud-notifications", (req, res) => {
  const scope = accountScope(req.query as any); const days = Math.min(90, Math.max(1, Number(req.query.days) || 7));
  const feed = str(req.query.feed); const type = str(req.query.type);
  res.json({ ...cloudNotificationsSummary(days, scope), days, events: listCloudNotifications({ days, scope, feed: feed === "managed" || feed === "configured" ? (feed as Feed) : undefined, type, source: str(req.query.source), limit: Number(req.query.limit) || 200 }) });
});
cloudNotifications.post("/cloud-notifications/refresh", async (req, res) => {
  try { res.json(await refreshCloudNotifications(Number(req.body?.days) || undefined, (l) => console.log(`[notifications] ${l}`))); }
  catch (e: any) { res.status(502).json({ error: e?.message || String(e) }); }
});

import { Router } from "express";
import { authMiddleware } from "../auth.js";
import { accountScope } from "../scope.js";
import { accessSummary, listActors, listDirectoryChanges, listPeople, refreshSignIns } from "../sign_ins.js";
import { ssoMeta } from "../sso_inventory.js";

/**
 * Who can get in (src/sign_ins.ts) for Inventory › Identities: the root user of each account, every person and key
 * with its MFA and the devices and clients it was seen using, the summary, and a refresh on demand (the nightly
 * inventory refresh does the same).
 */
export const access = Router();
access.use(authMiddleware);

access.get("/inventory/access", (req, res) => {
  const scope = accountScope(req.query as any);
  const actors = listActors(scope);
  const m = ssoMeta();
  // the Identity Center console's user page, where the MFA devices no API exposes can be seen
  const ic = m.instance_arn && m.region ? { region: m.region, instance: m.instance_arn.split("/").pop()!.replace(/^ssoins-/, "") } : null;
  res.json({ ...accessSummary(scope, actors), roots: actors.filter((a) => a.kind === "root"), persons: listPeople(actors), directory_changes: listDirectoryChanges(200), identity_center_console: ic });
});
access.post("/inventory/access/refresh", async (_req, res) => {
  try { res.json(await refreshSignIns((m) => console.error(`[sign-ins] ${m}`), (l) => console.log(`[sign-ins] ${l}`))); }
  catch (e: any) { res.status(502).json({ error: e?.message || String(e) }); }
});

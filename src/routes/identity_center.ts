import { Router } from "express";
import { authMiddleware } from "../auth.js";
import { accountScope } from "../scope.js";
import { listSsoPermissionSets, listSsoUsers, refreshSsoInventory, ssoMeta, ssoSummary } from "../sso_inventory.js";

/**
 * IAM Identity Center (src/sso_inventory.ts) for Inventory › Identities: the users with their groups, assignments and
 * sign-ins, the permission sets with their policies and where each was last used, the summary, and a refresh on
 * demand (the nightly inventory refresh does the same).
 */
export const identityCenter = Router();
identityCenter.use(authMiddleware);

const str = (v: unknown) => (typeof v === "string" && v ? v : undefined);
identityCenter.get("/inventory/sso", (req, res) => {
  const scope = accountScope(req.query as any);
  res.json({ ...ssoSummary(scope), instance: ssoMeta(), users: listSsoUsers({ scope, q: str(req.query.q), sort: str(req.query.sort), gone: req.query.gone === "1" || req.query.gone === "true" }), permission_sets: listSsoPermissionSets({ scope }) });
});
identityCenter.post("/inventory/sso/refresh", async (_req, res) => {
  try { res.json(await refreshSsoInventory((m) => console.error(`[identity-center] ${m}`), (l) => console.log(`[identity-center] ${l}`))); }
  catch (e: any) { res.status(502).json({ error: e?.message || String(e) }); }
});

/**
 * Bulk inventory export for an external workflow (src/inventory_export.ts): the rows the sync would persist, read-only.
 * Auth: the usual API credentials, or INVENTORY_EXPORT_TOKEN (exportAuthMiddleware). Auth is per route, not router.use,
 * so this router never answers for other /api paths.
 */
import { Router, type Request, type Response } from "express";
import { exportAuthMiddleware } from "../auth.js";
import { listAccounts } from "../accounts.js";
import { BadRequest, EXPORT_TYPES, exportPage } from "../inventory_export.js";

export const inventoryExport = Router();

const param = (req: Request, k: string): unknown => (req.query[k] ?? (req.body && typeof req.body === "object" ? (req.body as any)[k] : undefined));

inventoryExport.get("/inventory/export/types", exportAuthMiddleware, (_req, res) => {
  res.json({ types: EXPORT_TYPES.map(({ type, description }) => ({ type, description })), accounts: listAccounts() });
});

async function handle(req: Request, res: Response) {
  try {
    res.set("cache-control", "no-store").json(await exportPage({ type: param(req, "type"), account: param(req, "account"), cursor: param(req, "cursor"), limit: param(req, "limit") }));
  } catch (e: any) {
    if (e instanceof BadRequest) return res.status(400).json({ error: e.message });
    res.status(500).json({ error: String(e?.message || e) });
  }
}
inventoryExport.get("/inventory/export", exportAuthMiddleware, handle);
inventoryExport.post("/inventory/export", exportAuthMiddleware, handle);

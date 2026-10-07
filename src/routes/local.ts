import { Router } from "express";
import { authMiddleware } from "../auth.js";
import { MACHINE_KINDS, PLATFORMS, WORKLOAD_KINDS, listMachines, localAdapter, thisMachine } from "../adapters/local/index.js";

/**
 * Settings › Accounts › Local machines: the declared machines with what runs on each, and what Node sees of the
 * machine the advisor runs on (to start the form from). Adding, editing and removing go through the adapter's
 * onboarding (POST /api/providers/local/accounts, DELETE /api/providers/local/accounts/:machine id).
 */
export const local = Router();
local.use(authMiddleware);

local.get("/local/machines", (_req, res) => {
  res.json({ machines: listMachines(), this_machine: thisMachine(), kinds: MACHINE_KINDS, platforms: PLATFORMS, workload_kinds: WORKLOAD_KINDS, configured: localAdapter.configured() });
});

import { Router } from "express";
import { authMiddleware } from "../auth.js";
import { accountScope } from "../scope.js";
import { accessSummary, listActors, listDirectoryChanges, listPeople, refreshSignIns } from "../sign_ins.js";
import { refreshSsoInventory, ssoMeta } from "../sso_inventory.js";
import { refreshIamInventory } from "../iam_inventory.js";
import { listRoles, refreshRoleTrust } from "../role_trust.js";
import { oidcLinks, staticKeyVars } from "../vercel_aws_links.js";
import { teamExtras, vercelTeam } from "../adapters/vercel/inventory.js";

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
  res.json({ ...accessSummary(scope, actors), roots: actors.filter((a) => a.kind === "root"), persons: listPeople(actors), directory_changes: listDirectoryChanges(200), identity_center_console: ic, roles: listRoles({ outside: true, scope }), vercel: vercelAccess() });
});
/** The Vercel team's sign-in guards, the token owner's tokens, and how its projects reach AWS (OIDC roles, static keys). */
function vercelAccess() {
  const team = vercelTeam(); if (!team) return null;
  const x = teamExtras(team.id);
  return { team: { id: team.id, name: team.name, slug: team.slug, plan: team.plan }, security: x.security, tokens: x.tokens, token_owner: x.token_owner?.username ?? null, read_at: x.read_at, oidc_links: oidcLinks(), static_keys: staticKeyVars() };
}

// the identities first (IAM users with their MFA devices, Identity Center users with their status), so the sign-ins fold onto fresh rows
access.post("/inventory/access/refresh", async (_req, res) => {
  try {
    const errors: string[] = [];
    await refreshIamInventory((m) => errors.push(m), (l) => console.log(`[inventory] ${l}`));
    try { await refreshRoleTrust((m) => errors.push(m), (l) => console.log(`[inventory] ${l}`)); } catch (e: any) { errors.push(`IAM roles: ${e?.message || e}`); }
    try { await refreshSsoInventory((m) => errors.push(m), (l) => console.log(`[identity-center] ${l}`)); } catch (e: any) { errors.push(`Identity Center: ${e?.message || e}`); }
    const r = await refreshSignIns((m) => console.error(`[sign-ins] ${m}`), (l) => console.log(`[sign-ins] ${l}`));
    res.json({ ...r, errors: [...errors, ...r.errors] });
  }
  catch (e: any) { res.status(502).json({ error: e?.message || String(e) }); }
});

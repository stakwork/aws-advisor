import { Router } from "express";
import { authMiddleware } from "../auth.js";
import { accountScope } from "../scope.js";
import { accessSummary, listActors, listDirectoryChanges, listPeople, refreshSignIns } from "../sign_ins.js";
import { refreshSsoInventory, ssoMeta } from "../sso_inventory.js";
import { refreshIamInventory } from "../iam_inventory.js";
import { listRoles, refreshRoleTrust } from "../role_trust.js";
import { oidcLinks, staticKeyVars } from "../vercel_aws_links.js";
import { teamExtras, vercelTeam } from "../adapters/vercel/inventory.js";
import { entitlementsMeta, refreshClusterAccess, refreshEntitlements, refreshLastAccessed } from "../entitlements.js";
import { personReach } from "../access_paths.js";
import { simulateForPerson } from "../access_simulate.js";

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
    const log = (l: string) => console.log(`[entitlements] ${l}`);
    try { await refreshEntitlements((m) => errors.push(m), log); await refreshLastAccessed((m) => errors.push(m), log); await refreshClusterAccess((m) => errors.push(m), log); } catch (e: any) { errors.push(`entitlements: ${e?.message || e}`); }
    res.json({ ...r, errors: [...errors, ...r.errors] });
  }
  catch (e: any) { res.status(502).json({ error: e?.message || String(e) }); }
});

/** What one person can touch (src/access_paths.ts): per account the grade and the paths, the Vercel projects, the clusters, the shells and the roles. */
access.get("/inventory/access/people/:id/reach", (req, res) => {
  const r = personReach(String(req.params.id));
  if (!r) return res.status(404).json({ error: "no such person" });
  res.json({ ...r, meta: entitlementsMeta() });
});

/** An exact answer for one question: can this person do these actions (on this resource, in this account)? iam:SimulatePrincipalPolicy on each identity that reaches the account. */
access.post("/inventory/access/people/:id/simulate", async (req, res) => {
  const b = req.body ?? {};
  const actions = (Array.isArray(b.actions) ? b.actions : String(b.actions ?? "").split(/[\s,]+/)).map(String).filter((a: string) => /^[a-z0-9-]+:[A-Za-z0-9*?]+$/.test(a)).slice(0, 20);
  if (!actions.length) return res.status(400).json({ error: "actions: one or more service:Action names" });
  try { res.json(await simulateForPerson(String(req.params.id), actions, b.resource ? String(b.resource) : null, b.account_id ? String(b.account_id) : null)); }
  catch (e: any) { res.status(502).json({ error: e?.message || String(e) }); }
});

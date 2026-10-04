import { Router } from "express";
import { authMiddleware } from "../auth.js";
import { VercelClient } from "../adapters/vercel/client.js";
import { vercelAdapter, vercelClient, projectEndpoints, vercelOverview, projectDetail, vercelBill, storeDetail, partnersConfigured } from "../adapters/vercel/index.js";
import { vercelRates } from "../adapters/vercel/pricing.js";
import { listDeployments, listDomains, listEnvNames, listProjects, listStores, vercelTeam, wipeVercel } from "../adapters/vercel/inventory.js";
import { setRuntimeSetting } from "../runtime_settings.js";
import { ensureVercelConnection } from "../adapters/vercel/steampipe.js";
import { config } from "../config.js";
import { db } from "../db.js";

/**
 * The Vercel account (Settings › Accounts › Vercel): save and test a token, see the projects with what each exposes
 * and how it is protected, refresh on demand, remove. The token is a runtime secret; it is never returned.
 */
export const vercel = Router();
vercel.use(authMiddleware);

/** Body: { token, team_id? }. Tests the token against the API before saving; collects and mirrors in the background. */
vercel.post("/accounts/vercel", async (req, res) => {
  const token = String(req.body?.token || "").trim(); const teamId = String(req.body?.team_id || "").trim();
  if (!/^[A-Za-z0-9_-]{16,}$/.test(token)) return res.status(400).json({ error: "the token looks wrong (16+ letters, digits, - or _)" });
  if (teamId && !/^team_[A-Za-z0-9]+$/.test(teamId)) return res.status(400).json({ error: "a team id looks like team_…; leave it empty for a personal account" });
  try {
    const who = await new VercelClient({ token, teamId: teamId || null }).whoami();
    setRuntimeSetting("vercelToken", token); setRuntimeSetting("vercelTeamId", teamId || null);
    (async () => { await vercelAdapter.collect(); console.log(`[vercel] steampipe connection ${ensureVercelConnection()}`); try { const { mirrorAdapter } = await import("../graph_mirror.js"); await mirrorAdapter(vercelAdapter); } catch (e: any) { console.error(`[graph] vercel: ${e?.message || e}`); } })().catch((e) => console.error(`[vercel] first collection failed: ${e?.message || e}`));
    res.json({ ok: true, account: who, note: "saved; the first collection runs now and the projects appear in a minute" });
  } catch (e: any) { res.status(400).json({ error: `the token was refused: ${String(e?.message || e).slice(0, 300)}` }); }
});

/** Body: { neon_api_key?, redis_api_key?, redis_secret_key? }. Each key is tested against the partner's API before it is saved; an empty string removes it. */
vercel.post("/accounts/vercel/partners", async (req, res) => {
  const { NeonClient, RedisCloudClient } = await import("../adapters/vercel/partners.js");
  const out: Record<string, unknown> = {};
  try {
    if (typeof req.body?.neon_api_key === "string") {
      const k = req.body.neon_api_key.trim();
      if (!k) { setRuntimeSetting("neonApiKey", null); out.neon = "removed"; }
      else { const me = await new NeonClient(k).whoami(); setRuntimeSetting("neonApiKey", k); out.neon = `saved: ${me.name ?? me.id ?? "a Neon user"}${me.email_domain ? ` at ${me.email_domain}` : ""}`; }
    }
    if (typeof req.body?.redis_api_key === "string" || typeof req.body?.redis_secret_key === "string") {
      const a = String(req.body.redis_api_key ?? "").trim(); const b = String(req.body.redis_secret_key ?? "").trim();
      if (!a && !b) { setRuntimeSetting("redisCloudApiKey", null); setRuntimeSetting("redisCloudSecretKey", null); out.redis = "removed"; }
      else if (!a || !b) return res.status(400).json({ error: "Redis Cloud needs both keys: the account key and the user (secret) key" });
      else { const who = await new RedisCloudClient(a, b).whoami(); setRuntimeSetting("redisCloudApiKey", a); setRuntimeSetting("redisCloudSecretKey", b); out.redis = `saved: account ${who.name ?? who.id ?? "read"}`; }
    }
  } catch (e: any) { return res.status(400).json({ error: `refused: ${String(e?.message || e).slice(0, 300)}` }); }
  if (vercelAdapter.configured()) (async () => { try { await vercelAdapter.collect(); const { mirrorAdapter } = await import("../graph_mirror.js"); await mirrorAdapter(vercelAdapter); } catch (e: any) { console.error(`[vercel] partners refresh: ${e?.message || e}`); } })();
  res.json({ ok: true, ...out, configured: partnersConfigured(), note: "the stores are re-read now" });
});
/** What changed on the team between collections (?days=7, ?kind=): the snapshot diffs, newest first. */
vercel.get("/vercel/changes", async (req, res) => {
  if (!vercelAdapter.configured()) return res.json({ configured: false, changes: [], summary: null });
  const { listChanges, changesSummary } = await import("../adapters/vercel/changes.js"); const team = vercelTeam()?.id ?? vercelAdapter.primaryAccountId();
  const days = Math.min(90, Math.max(1, Number(req.query.days) || 7));
  res.json({ configured: true, team_id: team, summary: changesSummary(team, days), changes: listChanges(team, { days, kind: typeof req.query.kind === "string" ? req.query.kind : undefined }) });
});
vercel.get("/vercel/members", (_req, res) => { if (!vercelAdapter.configured()) return res.json({ configured: false, members: [], read_at: null }); const { teamExtras } = require("../adapters/vercel/inventory.js") as typeof import("../adapters/vercel/inventory.js"); const x = teamExtras(vercelTeam()?.id ?? vercelAdapter.primaryAccountId()); res.json({ configured: true, members: x.members, read_at: x.read_at }); });
vercel.get("/vercel/partners", (_req, res) => { const stores = listStores(); res.json({ configured: partnersConfigured(), stores: stores.filter((s) => s.partner).map((s) => ({ id: s.id, name: s.name, product: s.product, read_at: s.partner!.read_at, error: s.partner!.error })) }); });

vercel.delete("/accounts/vercel", async (_req, res) => {
  const team = vercelTeam();
  setRuntimeSetting("vercelToken", null); setRuntimeSetting("vercelTeamId", null); setRuntimeSetting("neonApiKey", null); setRuntimeSetting("redisCloudApiKey", null); setRuntimeSetting("redisCloudSecretKey", null); wipeVercel(); console.log(`[vercel] steampipe connection ${ensureVercelConnection()}`);
  try { if (team) { const { wipeMirror } = await import("../graph_mirror.js"); await wipeMirror(team.id); } } catch (e: any) { console.error(`[graph] vercel wipe: ${e?.message || e}`); }
  res.json({ ok: true });
});

vercel.get("/vercel/projects", (_req, res) => {
  if (!vercelAdapter.configured()) return res.json({ configured: false, team: null, projects: [] });
  // Secure Compute names a security group and subnets: when they are in the AWS inventory the graph links the project to them; when not, the network is Vercel's own and only the ids are shown
  const known = (id: string | null) => Boolean(id && (db.prepare("select 1 from sg_ingress where group_id = ? limit 1").get(id) || db.prepare("select 1 from inventory_subnet where subnet_id = ? limit 1").get(id)));
  const projects = listProjects().map((p) => ({ ...p, domains: listDomains(p.id), endpoints: projectEndpoints(p), deployments: listDeployments(p.id, 5), env_names: listEnvNames(p.id).map((e) => ({ key: e.key, targets: e.targets, type: e.type })), stores: listStores({ projectId: p.id }).map((st) => ({ id: st.id, name: st.name, kind: st.kind, product: st.product, plan: st.plan, region: st.region, status: st.status })),
    connect_in_inventory: p.connect.some((c) => known(c.security_group) || c.subnets.some(known)) }));
  res.json({ configured: true, team: vercelTeam(), team_id_setting: config.vercelTeamId || null, projects, stores: listStores() });
});

/** The team at a glance for the Overview page. */
vercel.get("/vercel/overview", (_req, res) => { if (!vercelAdapter.configured()) return res.json({ configured: false }); res.json({ configured: true, ...vercelOverview() }); });

vercel.get("/vercel/projects/:id", (req, res) => { if (!vercelAdapter.configured()) return res.status(404).json({ error: "Vercel is not configured" }); const d = projectDetail(String(req.params.id)); d ? res.json(d) : res.status(404).json({ error: "no such project" }); });
/** This month for the team: subscription and period, the metered usage so far, the invoices with their lines and the unit prices they imply. */
vercel.get("/vercel/bill", (_req, res) => { if (!vercelAdapter.configured()) return res.json({ configured: false }); res.json({ configured: true, ...vercelBill() }); });

// ?kind=database|cache|storage: the team's stores (Neon, Redis, Blob, ...) with the projects on each.
vercel.get("/vercel/stores", (req, res) => { if (!vercelAdapter.configured()) return res.json({ configured: false, stores: [] }); res.json({ configured: true, stores: listStores({ kind: typeof req.query.kind === "string" ? req.query.kind : undefined }) }); });

vercel.get("/vercel/stores/:id", (req, res) => { if (!vercelAdapter.configured()) return res.status(404).json({ error: "Vercel is not configured" }); const d = storeDetail(String(req.params.id)); d ? res.json(d) : res.status(404).json({ error: "no such store" }); });
/** The prices the advisor knows for the team: the listed metered items, the marketplace plans' lines and what the last invoice charged per unit. */
vercel.get("/vercel/rates", (_req, res) => { if (!vercelAdapter.configured()) return res.json({ configured: false }); res.json({ configured: true, ...vercelRates(vercelTeam()?.id ?? vercelAdapter.primaryAccountId()) }); });

vercel.post("/vercel/refresh", async (_req, res) => {
  if (!vercelAdapter.configured()) return res.status(400).json({ error: "Vercel is not configured" });
  const r = await vercelAdapter.collect();
  ensureVercelConnection();
  try { const { mirrorAdapter } = await import("../graph_mirror.js"); await mirrorAdapter(vercelAdapter); } catch (e: any) { console.error(`[graph] vercel: ${e?.message || e}`); }
  res.json({ ok: r.errors.length === 0, errors: r.errors, team: vercelTeam(), projects: listProjects().length });
});

export { vercelClient };

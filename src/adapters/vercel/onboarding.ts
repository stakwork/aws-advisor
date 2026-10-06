import type { ProviderOnboarding } from "../types.js";

/**
 * A Vercel team in Settings: a token (and the team id for a team token) saved as runtime secrets after the API
 * accepts it; removing it forgets the token, the partner keys and the team's stored rows. One team at a time.
 */
export const vercelOnboarding: ProviderOnboarding = {
  async add(body) {
    const token = String(body?.token || "").trim(); const teamId = String(body?.team_id || "").trim();
    if (!/^[A-Za-z0-9_-]{16,}$/.test(token)) return { ok: false, status: 400, error: "the token looks wrong (16+ letters, digits, - or _)" };
    if (teamId && !/^team_[A-Za-z0-9]+$/.test(teamId)) return { ok: false, status: 400, error: "a team id looks like team_…; leave it empty for a personal account" };
    const { VercelClient } = await import("./client.js");
    const { setRuntimeSetting } = await import("../../runtime_settings.js");
    try {
      const who = await new VercelClient({ token, teamId: teamId || null }).whoami();
      setRuntimeSetting("vercelToken", token); setRuntimeSetting("vercelTeamId", teamId || null);
      const { vercelAdapter } = await import("./index.js"); const { ensureVercelConnection } = await import("./steampipe.js");
      (async () => { await vercelAdapter.collect(); console.log(`[vercel] steampipe connection ${ensureVercelConnection()}`); try { const { mirrorAdapter } = await import("../../graph_mirror.js"); await mirrorAdapter(vercelAdapter); } catch (e: any) { console.error(`[graph] vercel: ${e?.message || e}`); } })().catch((e) => console.error(`[vercel] first collection failed: ${e?.message || e}`));
      return { ok: true, account: who, note: "saved; the first collection runs now and the projects appear in a minute" };
    } catch (e: any) { return { ok: false, status: 400, error: `the token was refused: ${String(e?.message || e).slice(0, 300)}` }; }
  },
  async test() {
    const { vercelClient, vercelConfigured } = await import("./index.js");
    if (!vercelConfigured()) return { ok: false, detail: "no Vercel token saved" };
    try { const who = await vercelClient().whoami(); return { ok: true, detail: `token accepted${(who as any)?.name ? ` for ${(who as any).name}` : ""}`, account: who }; }
    catch (e: any) { return { ok: false, detail: String(e?.message || e).slice(0, 300) }; }
  },
  async remove() {
    const { vercelTeam, wipeVercel } = await import("./inventory.js"); const { setRuntimeSetting } = await import("../../runtime_settings.js"); const { ensureVercelConnection } = await import("./steampipe.js");
    const team = vercelTeam();
    for (const k of ["vercelToken", "vercelTeamId", "neonApiKey", "redisCloudApiKey", "redisCloudSecretKey"]) setRuntimeSetting(k, null);
    wipeVercel(); console.log(`[vercel] steampipe connection ${ensureVercelConnection()}`);
    try { if (team) { const { wipeMirror } = await import("../../graph_mirror.js"); await wipeMirror(team.id); } } catch (e: any) { console.error(`[graph] vercel wipe: ${e?.message || e}`); }
    return { ok: true };
  },
  setup: { kind: "token", detail: "a team access token with read scope (Account settings › Tokens), and the team id for a team token" },
};

import type { ProviderOnboarding } from "../types.js";

/**
 * A GitHub org in Settings: the org login, the read-only App's id, its installation id and its private key, saved as
 * runtime secrets after GitHub accepts them (an installation token is minted and the org read with it). Removing it
 * forgets the App's credentials and the org's stored rows. One org at a time.
 */
export const githubOnboarding: ProviderOnboarding = {
  async add(body) {
    const org = String(body?.org || "").trim(); const appId = String(body?.app_id || "").trim(); const inst = String(body?.installation_id || "").trim(); const keyIn = String(body?.private_key || "");
    if (!/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/.test(org)) return { ok: false, status: 400, error: "the org looks wrong: its login as in github.com/<org>" };
    if (!/^\d+$/.test(appId)) return { ok: false, status: 400, error: "the App id is a number (the App's settings page, About)" };
    if (!/^\d+$/.test(inst)) return { ok: false, status: 400, error: "the installation id is a number (the end of the installation's settings URL)" };
    const { config } = await import("../../config.js");
    const key = keyIn.trim() ? keyIn : config.githubAppPrivateKey;
    if (!/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(key)) return { ok: false, status: 400, error: "paste the App's private key (.pem), BEGIN and END lines included" };
    const { GitHubClient, normalisePem } = await import("./client.js");
    const { setRuntimeSetting } = await import("../../runtime_settings.js");
    const pem = normalisePem(key);
    let o: Awaited<ReturnType<InstanceType<typeof GitHubClient>["orgInfo"]>>;
    try { o = await new GitHubClient({ org, app: { appId, installationId: inst, privateKey: pem } }).orgInfo(); }
    catch (e: any) { return { ok: false, status: 400, error: `GitHub refused it: ${String(e?.message || e).slice(0, 300)}` }; }
    try {
      setRuntimeSetting("githubOrg", org); setRuntimeSetting("githubAppId", appId); setRuntimeSetting("githubInstallationId", inst); setRuntimeSetting("githubAppPrivateKey", pem);
      const { githubAdapter } = await import("./index.js");
      // the Steampipe connection the collection reads first (the plugin loads it within seconds)
      const { ensureGitHubConnection } = await import("./steampipe.js"); console.log(`[github] steampipe connection ${ensureGitHubConnection()}`);
      (async () => { const r = await githubAdapter.collect(); if (r.errors.length) console.log(`[github] first collection: ${r.errors.length} section(s) refused or failed`); })().catch((e) => console.error(`[github] first collection failed: ${e?.message || e}`));
      return { ok: true, account: { id: o.node_id, name: o.login, plan: o.plan, seats: o.seats, filled_seats: o.filled_seats }, note: "saved; the first collection runs now (a minute or two for the audit log and every repository)" };
    } catch (e: any) { return { ok: false, status: 400, error: `GitHub accepted the App, but the settings were not saved: ${String(e?.message || e).slice(0, 300)}` }; }
  },
  async test() {
    const { githubClient, githubConfigured } = await import("./index.js");
    if (!githubConfigured()) return { ok: false, detail: "no GitHub App saved" };
    try { const o = await githubClient().orgInfo(); return { ok: true, detail: `App accepted for ${o.login}${o.plan ? ` (${o.plan} plan)` : ""}`, account: o }; }
    catch (e: any) { return { ok: false, detail: String(e?.message || e).slice(0, 300) }; }
  },
  async remove() {
    const { githubOrgRow, wipeGitHub } = await import("./inventory.js"); const { setRuntimeSetting } = await import("../../runtime_settings.js");
    const org = githubOrgRow();
    for (const k of ["githubOrg", "githubAppId", "githubInstallationId", "githubAppPrivateKey"]) setRuntimeSetting(k, null);
    wipeGitHub();
    const { ensureGitHubConnection } = await import("./steampipe.js"); console.log(`[github] steampipe connection ${ensureGitHubConnection()}`);
    try { if (org) { const { wipeMirror } = await import("../../graph_mirror.js"); await wipeMirror(org.node_id); } } catch (e: any) { console.error(`[graph] github wipe: ${e?.message || e}`); }
    return { ok: true };
  },
  setup: { kind: "token", detail: "a GitHub App owned by the org, read-only, installed on all repositories: App id, installation id and a private key; the advisor writes the Steampipe github connection from it" },
};

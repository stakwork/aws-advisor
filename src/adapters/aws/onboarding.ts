import type { ProviderOnboarding } from "../types.js";

/**
 * AWS accounts in Settings: a member is a read role (and optionally an actuator role) the parent assumes
 * (src/accounts.ts); the parent itself is the saved credentials (Settings › Accounts › AWS access). The permission
 * check simulates and probes what the read identity may do (src/permission_check.ts).
 */
export const awsOnboarding: ProviderOnboarding = {
  async add(body) {
    const { listAccounts, saveAccount, testAccount, validateAccount } = await import("../../accounts.js");
    let a;
    try { a = validateAccount(body || {}); } catch (e: any) { return { ok: false, status: 400, error: e.message }; }
    const saved = saveAccount(a);
    const test = await testAccount(a.account_id, 20_000);
    return { ok: true, saved: saved.account, files_rewritten: saved.files_rewritten, test, accounts: listAccounts() };
  },
  async test(accountId) {
    const { listAccounts, testAccount } = await import("../../accounts.js");
    const test = await testAccount(accountId, 20_000);
    return { ok: test.ok, test, accounts: listAccounts() };
  },
  async remove(accountId) {
    const { listAccounts, removeAccount } = await import("../../accounts.js");
    const r = removeAccount(accountId);
    if (!r.removed) return { ok: false, status: 404, error: `no member account ${accountId}` };
    return { ok: true, ...r, accounts: listAccounts() };
  },
  async permissionCheck(accountId, opts = {}) {
    const { checkPermissions } = await import("../../permission_check.js");
    return checkPermissions({ accountId, instanceId: typeof opts.instance_id === "string" ? opts.instance_id : undefined });
  },
  setup: { kind: "script", detail: "the one-command setup (Settings › Accounts › AWS › Setup) creates the read role, the optional actuator role and the probe documents in each account" },
};

/**
 * Member accounts (src/accounts.ts): the registry the Settings page edits, the test that proves the parent may
 * assume a member's read role, and the bill per linked account for the Bill page.
 */
import { Router } from "express";
import { listAccounts, removeAccount, saveAccount, testAccount, validateAccount } from "../accounts.js";
import { credentialsMeta, hasConnectionFile, sdkIdentity } from "../steampipe.js";
import { actuatorTrustPolicy } from "../permissions.js";
import { spendByAccount } from "../spend.js";

export const accounts = Router();

/** The parent and the members, with the trust policy a member's roles need (the parent's read identity as principal). */
accounts.get("/accounts", async (_req, res) => {
  const parent = credentialsMeta();
  const identity = hasConnectionFile() ? await sdkIdentity(10_000) : { ok: false as const, error: "no credentials configured" };
  const readArn = identity.ok ? identity.arn : "<the parent's read role or user ARN>";
  res.json({ accounts: listAccounts(), parent_identity: identity, parent_account_id: parent?.accountId || null, trust_policy: actuatorTrustPolicy(readArn) });
});

/** Body: { account_id, name?, role_arn, act_role_arn?, regions?, enabled? }. Saves, rewrites the connection files, tests the read role. */
accounts.post("/accounts", async (req, res) => {
  let a;
  try { a = validateAccount(req.body || {}); } catch (e: any) { return res.status(400).json({ error: e.message }); }
  const saved = saveAccount(a);
  const test = await testAccount(a.account_id, 20_000);
  res.json({ saved: saved.account, files_rewritten: saved.files_rewritten, test, accounts: listAccounts() });
});

accounts.post("/accounts/:id/test", async (req, res) => {
  const test = await testAccount(String(req.params.id), 20_000);
  res.status(test.ok ? 200 : 400).json({ test, accounts: listAccounts() });
});

accounts.delete("/accounts/:id", (req, res) => {
  const r = removeAccount(String(req.params.id));
  if (!r.removed) return res.status(404).json({ error: `no member account ${req.params.id}` });
  res.json({ ...r, accounts: listAccounts() });
});

/** The last six months per linked account (the payer's Cost Explorer), with the names the registry knows. */
accounts.get("/accounts/bill", (_req, res) => {
  const names = new Map(listAccounts().map((a) => [a.account_id, a.is_parent ? `${a.name} (parent)` : a.name]));
  const rows = spendByAccount(6).map((r) => ({ ...r, name: names.get(r.account_id) || null }));
  const months = [...new Set(rows.map((r) => r.month))].sort().reverse();
  const byAccount = new Map<string, { account_id: string; name: string | null; months: Record<string, number>; total: number }>();
  for (const r of rows) { const a = byAccount.get(r.account_id) || { account_id: r.account_id, name: r.name, months: {}, total: 0 }; a.months[r.month] = r.usd; a.total += r.usd; byAccount.set(r.account_id, a); }
  res.json({ months, accounts: [...byAccount.values()].sort((x, y) => y.total - x.total) });
});

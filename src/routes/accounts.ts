/**
 * Member accounts (src/accounts.ts): the registry the Settings page edits, the test that proves the parent may
 * assume a member's read role, and the bill per linked account for the Bill page.
 */
import { Router } from "express";
import { listAccounts, removeAccount, saveAccount, testAccount, validateAccount } from "../accounts.js";
import { credentialsMeta, hasConnectionFile, sdkIdentity } from "../steampipe.js";
import { actuatorTrustPolicy } from "../permissions.js";
import { servicesByAccount, spendByAccount } from "../spend.js";
import { allAccounts, providers } from "../adapters/index.js";
import { accountsOverview , generalOverview } from "../accounts_overview.js";

export const accounts = Router();

/** The parent and the members, with the trust policy a member's roles need (the parent's read identity as principal). */
accounts.get("/accounts", async (_req, res) => {
  const parent = credentialsMeta();
  const identity = hasConnectionFile() ? await sdkIdentity(10_000) : { ok: false as const, error: "no credentials configured" };
  // what a child's trust policy must name: the IAM role (or user), never the STS session ARN the credentials show as
  const readArn = identity.ok ? principalArnOf(identity.arn) : "<the parent's read role or user ARN>";
  res.json({ accounts: listAccounts(), records: await allAccounts(), parent_identity: identity.ok ? { ...identity, principal_arn: readArn } : identity, parent_account_id: parent?.accountId || null, trust_policy: actuatorTrustPolicy(readArn) });
});

/** The IAM principal behind a caller ARN: an assumed-role session (arn:aws:sts::A:assumed-role/R/session) is the role arn:aws:iam::A:role/R; a user or role ARN is itself. */
export function principalArnOf(arn: string): string {
  const m = /^arn:aws:sts::(\d{12}):assumed-role\/([^/]+)\/.+$/.exec(arn);
  return m ? `arn:aws:iam::${m[1]}:role/${m[2]}` : arn;
}

/** Every provider the advisor knows: the adapters (with whether one is configured, their sections and capabilities) and the stubs with what they will need. */
accounts.get("/providers", (_req, res) => res.json({ providers: providers() }));

/** The general view: every account with its resources, cost, findings, security, vulnerabilities, recommendations, alerts and probe coverage. */
accounts.get("/accounts/overview", async (_req, res) => { try { res.json({ accounts: await accountsOverview() }); } catch (e: any) { res.status(500).json({ error: e.message }); } });
/** The organisation's accounts as the parent sees them (organizations:ListAccounts, management account only), with whether each is the parent, a registered member, or neither. */
accounts.get("/accounts/organization", async (_req, res) => {
  const { S, query, credentialsMeta } = await import("../steampipe.js");
  const parent = credentialsMeta()?.accountId ?? null; const members = new Set(listAccounts().filter((a) => !a.is_parent).map((a) => a.account_id));
  try {
    const rows = await query<any>(`select id, name, email, status, joined_timestamp, joined_method from ${S}.aws_organizations_account order by name`);
    res.json({ ok: true, parent, accounts: rows.map((r) => ({ id: String(r.id), name: r.name ?? null, email_domain: typeof r.email === "string" && r.email.includes("@") ? r.email.split("@")[1] : null, status: r.status ?? null, joined_at: r.joined_timestamp ? String(r.joined_timestamp) : null, joined_method: r.joined_method ?? null, role: String(r.id) === parent ? "parent" : members.has(String(r.id)) ? "member" : "not registered" })) });
  } catch (e: any) {
    const msg = String(e?.message || e);
    res.json({ ok: false, parent, accounts: [], error: /AccessDenied|not authorized/i.test(msg) ? "the parent's identity may not list the organisation (organizations:ListAccounts is in the recommended policy; rerun the parent's setup script, or the credentials are not the management account)" : msg.slice(0, 300) });
  }
});
accounts.get("/accounts/general", async (_req, res) => { try { res.json(await generalOverview()); } catch (e: any) { res.status(500).json({ error: e.message }); } });

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

/**
 * The last six months per linked account (the payer's Cost Explorer), with the names the registry knows, and what each
 * account's last three months are made of: `services[account_id][month]` = [{ service, usd }], biggest first.
 */
accounts.get("/accounts/bill", (_req, res) => {
  const names = new Map(listAccounts().map((a) => [a.account_id, a.is_parent ? `${a.name} (parent)` : a.name]));
  const rows = spendByAccount(6).map((r) => ({ ...r, name: names.get(r.account_id) || null }));
  const months = [...new Set(rows.map((r) => r.month))].sort().reverse();
  const byAccount = new Map<string, { account_id: string; name: string | null; months: Record<string, number>; total: number }>();
  for (const r of rows) { const a = byAccount.get(r.account_id) || { account_id: r.account_id, name: r.name, months: {}, total: 0 }; a.months[r.month] = r.usd; a.total += r.usd; byAccount.set(r.account_id, a); }
  const services: Record<string, Record<string, { service: string; usd: number }[]>> = {};
  for (const s of servicesByAccount(3)) { const a = (services[s.account_id] ??= {}); (a[s.month] ??= []).push({ service: s.service, usd: Math.round(s.usd * 100) / 100 }); }
  res.json({ months, accounts: [...byAccount.values()].sort((x, y) => y.total - x.total), services });
});

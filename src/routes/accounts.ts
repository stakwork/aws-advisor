/**
 * Member accounts (src/accounts.ts): the registry the Settings page edits, the test that proves the parent may
 * assume a member's read role, and the bill per linked account for the Bill page.
 */
import { Router } from "express";
import { listAccounts } from "../accounts.js";
import { credentialsMeta, hasConnectionFile, sdkIdentity } from "../steampipe.js";
import { actuatorTrustPolicy } from "../permissions.js";
import { servicesByAccount, spendByAccount } from "../spend.js";
import { adapterFor, allAccounts, providers } from "../adapters/index.js";
import { accountsBilling, accountsOverview, generalOverview } from "../accounts_overview.js";

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
accounts.get("/accounts/billing", async (req, res) => { try { res.json(await accountsBilling(req.query.basis === "invoice" ? "invoice" : "amortized")); } catch (e: any) { res.status(500).json({ error: e.message }); } });

/**
 * Accounts of any provider, through its adapter's onboarding (src/adapters/types.ts ProviderOnboarding): add from the
 * Settings form, test, remove, and check what the advisor may do there. The body is the provider's own form.
 */
const onboardingOf = (id: string) => adapterFor(id)?.onboarding ?? null;
accounts.post("/providers/:provider/accounts", async (req, res) => {
  const o = onboardingOf(String(req.params.provider)); if (!o) return res.status(404).json({ error: `no provider ${req.params.provider} that adds accounts` });
  const r = await o.add(req.body || {}); res.status(r.ok ? 200 : r.status ?? 400).json(r.ok ? r : { error: r.error });
});
accounts.post("/providers/:provider/accounts/:id/test", async (req, res) => {
  const o = onboardingOf(String(req.params.provider)); if (!o) return res.status(404).json({ error: `no provider ${req.params.provider}` });
  const r = await o.test(String(req.params.id)); res.status(r.ok ? 200 : 400).json(r);
});
accounts.delete("/providers/:provider/accounts/:id", async (req, res) => {
  const o = onboardingOf(String(req.params.provider)); if (!o) return res.status(404).json({ error: `no provider ${req.params.provider}` });
  const r = await o.remove(String(req.params.id)); res.status(r.ok ? 200 : r.status ?? 400).json(r.ok ? r : { error: r.error });
});
accounts.post("/providers/:provider/permissions", async (req, res) => {
  const o = onboardingOf(String(req.params.provider)); if (!o?.permissionCheck) return res.status(404).json({ error: `provider ${req.params.provider} has no permission check` });
  const account = typeof req.body?.account_id === "string" && req.body.account_id.trim() ? req.body.account_id.trim() : null;
  try { res.json(await o.permissionCheck(account, req.body || {})); } catch (e: any) { res.status(502).json({ error: e?.message || String(e) }); }
});

/** The AWS member routes the Settings page has always called: the AWS adapter's onboarding under their old paths. */
const aws = () => adapterFor("aws")!.onboarding!;
accounts.post("/accounts", async (req, res) => { const r = await aws().add(req.body || {}); res.status(r.ok ? 200 : r.status ?? 400).json(r.ok ? r : { error: r.error }); });
accounts.post("/accounts/:id/test", async (req, res) => { const r = await aws().test(String(req.params.id)); res.status(r.ok ? 200 : 400).json(r); });
accounts.delete("/accounts/:id", async (req, res) => { const r = await aws().remove(String(req.params.id)); res.status(r.ok ? 200 : r.status ?? 400).json(r.ok ? r : { error: r.error }); });

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

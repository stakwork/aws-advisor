import { adapterFor, adapters, allAccounts } from "./adapters/index.js";
import { db } from "./db.js";
import type { AccountRecord } from "./adapters/types.js";

/**
 * The general view across accounts (Overview › Accounts, GET /api/accounts/overview): one row per account with what
 * a person wants before choosing one to look at: how much is there, what it costs, what is open and what is urgent.
 * Everything comes from the tables that carry an account id (the inventories, findings, scans, recommendations,
 * alerts); vulnerability verdicts name an instance and are attributed through the inventory's ids; each provider
 * says what an account's bill was (src/adapters/types.ts ProviderCost). Rows stored before account ids were kept
 * belong to the primary account of the provider that has such rows.
 */

export interface AccountOverview extends AccountRecord {
  resources: { ec2_running: number; ec2_total: number; rds: number; lambda: number; dynamodb: number; elb: number; s3: number; ebs_gb: number; clusters: number };
  spend: { month: string | null; usd: number | null };
  findings_alarms: number;
  security: { critical: number; high: number; scan_at: string | null };
  recommendations: { open: number; saving_usd_month: number };
  alerts_open: number;
  vulnerabilities: { critical: number; exposed: number; boxes: number };
  probes: { ssm_online: number; probed_24h: number };
  last_collected_at: string | null;
}

const rows = (sql: string, ...p: unknown[]): any[] => { try { return db.prepare(sql).all(...p) as any[]; } catch { return []; } };
import { resourceAccountIndex } from "./resource_index.js";
const n = (v: unknown) => Number(v || 0);

export { resourceAccountIndex } from "./resource_index.js";

export async function accountsOverview(): Promise<AccountOverview[]> {
  const accounts = await allAccounts();
  if (!accounts.length) return [];
  const legacy = adapters().find((a) => a.legacy_blank_account);
  const primary = legacy?.primaryAccountId() ?? "";
  const key = (acct: unknown) => (String(acct || "") || primary);
  const byAcct = <T,>(init: () => T) => { const m = new Map<string, T>(); return { get: (a: unknown) => { const k = key(a); if (!m.has(k)) m.set(k, init()); return m.get(k)!; } }; };

  const res = byAcct(() => ({ ec2_running: 0, ec2_total: 0, rds: 0, lambda: 0, dynamodb: 0, elb: 0, s3: 0, ebs_gb: 0, clusters: 0 }));
  for (const r of rows("select account_id, count(*) as total, coalesce(sum(state = 'running'), 0) as running from inventory_ec2 where gone = 0 group by account_id")) { const x = res.get(r.account_id); x.ec2_total += n(r.total); x.ec2_running += n(r.running); }
  for (const [t, col] of [["inventory_rds", "rds"], ["inventory_lambda", "lambda"], ["inventory_dynamodb", "dynamodb"], ["inventory_elb", "elb"], ["inventory_s3", "s3"]] as const) for (const r of rows(`select account_id, count(*) as c from ${t} where gone = 0 group by account_id`)) { const x = res.get(r.account_id); (x as any)[col] += n(r.c); }
  for (const r of rows("select account_id, coalesce(sum(size_gb), 0) as gb from inventory_ebs where gone = 0 group by account_id")) { const x = res.get(r.account_id); x.ebs_gb += n(r.gb); }
  for (const r of rows("select account_id, count(*) as c from inventory_cluster where gone = 0 group by account_id")) res.get(r.account_id).clusters += n(r.c);

  // each provider's latest rules run for each of its accounts (one AWS run covers the parent and its members, each finding carrying its own account), and their alarm findings
  const alarms = byAcct(() => ({ n: 0 })); const lastRun = new Map<string, string | null>();
  for (const a of adapters()) {
    if (!a.rules) continue;
    const runIds = new Set(accounts.filter((x) => x.provider === a.id).map((x) => a.rules!.latestRunId(x.id)).filter((x): x is number => x != null));
    for (const runId of runIds) {
      const run = rows("select finished_at from runs where id = ?", runId)[0]; if (!lastRun.has(a.id) || String(run?.finished_at ?? "") > String(lastRun.get(a.id) ?? "")) lastRun.set(a.id, run?.finished_at ?? null);
      for (const r of rows("select account_id, count(*) as c from findings where run_id = ? and status = 'alarm' group by account_id", runId)) alarms.get(r.account_id).n += n(r.c);
    }
  }
  const scan = rows("select id, finished_at from compliance_scans where status = 'completed' order by id desc limit 1")[0];
  const sec = byAcct(() => ({ critical: 0, high: 0 }));
  if (scan) for (const r of rows("select account_id, severity, count(*) as c from compliance_findings where scan_id = ? and severity in ('critical', 'high') group by account_id, severity", scan.id)) { const x = sec.get(r.account_id); if (r.severity === "critical") x.critical += n(r.c); else x.high += n(r.c); }

  const idx = resourceAccountIndex(primary);
  // recommendations and alerts carry their account from when they were written (older rows were stamped once, src/scope.ts)
  const recs = byAcct(() => ({ open: 0, saving: 0 }));
  for (const r of rows("select account_id, est_monthly_saving from recommendations where status = 'open'")) { const x = recs.get(r.account_id); x.open++; x.saving += n(r.est_monthly_saving); }
  const alerts = byAcct(() => ({ n: 0 }));
  for (const r of rows("select account_id from alerts where acknowledged = 0")) alerts.get(r.account_id).n++;

  const vulns = byAcct(() => ({ critical: 0, exposed: 0, boxes: new Set<string>() }));
  try {
    const { vulnerabilityMatches } = await import("./software_vulns.js");
    for (const m of vulnerabilityMatches()) { const a = idx.of(m.instance_id); if (!a) continue; const x = vulns.get(a); if (m.criticality === "critical") x.critical++; if (m.criticality === "exposed") x.exposed++; x.boxes.add(m.instance_id); }
  } catch { /* the software layer is optional */ }

  const probes = byAcct(() => ({ ssm_online: 0, probed_24h: 0 }));
  for (const r of rows("select account_id, coalesce(sum(ssm_status = 'Online'), 0) as online, coalesce(sum(probe_at > datetime('now', '-1 day')), 0) as probed from inventory_ec2 where gone = 0 and state = 'running' group by account_id")) { const x = probes.get(r.account_id); x.ssm_online += n(r.online); x.probed_24h += n(r.probed); }

  // the last full month's bill per account, as its provider reads it (the current month when nothing else exists)
  const spendOf = (acct: string, provider: string) => adapterFor(provider)?.cost?.lastBill(acct) ?? { month: null, usd: null };
  const collectedAt = (rows("select max(last_seen) as at from inventory_ec2")[0]?.at as string | null) ?? null;

  return accounts.map((a) => {
    const r = res.get(a.id); const s = sec.get(a.id); const v = vulns.get(a.id); const p = probes.get(a.id); const rc = recs.get(a.id);
    return { ...a, resources: { ec2_running: r.ec2_running, ec2_total: r.ec2_total, rds: r.rds, lambda: r.lambda, dynamodb: r.dynamodb, elb: r.elb, s3: r.s3, ebs_gb: Math.round(r.ebs_gb), clusters: r.clusters }, spend: spendOf(a.id, a.provider),
      findings_alarms: alarms.get(a.id).n, security: { critical: s.critical, high: s.high, scan_at: scan?.finished_at ?? null }, recommendations: { open: rc.open, saving_usd_month: Math.round(rc.saving) }, alerts_open: alerts.get(a.id).n,
      vulnerabilities: { critical: v.critical, exposed: v.exposed, boxes: v.boxes.size }, probes: { ssm_online: p.ssm_online, probed_24h: p.probed_24h }, last_collected_at: a.parent_id ? collectedAt : (lastRun.get(a.provider) ?? collectedAt) };
  });
}


/**
 * The general view when the sidebar looks at every account (GET /api/accounts/general): the month across providers,
 * what is open and what needs attention, each item saying which account it is about. Numbers that only one provider
 * has (an AWS forecast, a Vercel period estimate) are summed where they mean the same thing (a month of spend) and
 * shown apart where they do not.
 */
export interface GeneralOverview {
  accounts: number; providers: string[];
  /** the month across providers: each provider's parts in its own terms, summed where they mean the same thing (a month of spend) */
  month: { total_usd: number | null; parts: { provider: string; key: string; label: string; usd: number | null; to_total: boolean; month_to_date_usd?: number | null }[] };
  recommendations: { open: number; saving_usd_month: number; by_provider: Record<string, { open: number; saving_usd_month: number }> };
  attention: { provider: string; account: string; account_name: string | null; level: "alarm" | "warning" | "info"; what: string; link: string | null }[];
  counts: { alarms: number; warnings: number; alerts_open: number; security_critical: number; security_high: number; vulnerabilities_critical: number };
}

export async function generalOverview(): Promise<GeneralOverview> {
  const accounts = await accountsOverview();
  const nameOf = (id: string) => accounts.find((a) => a.id === id)?.name ?? null;
  const present = new Set(accounts.map((a) => a.provider));
  const attention: GeneralOverview["attention"] = [];
  const parts: GeneralOverview["month"]["parts"] = [];
  for (const a of adapters().filter((x) => present.has(x.id))) {
    try { for (const p of (await a.cost?.month()) ?? []) parts.push({ provider: a.id, ...p }); } catch { /* a provider without a bill read yet */ }
    try { for (const i of (await a.attention?.()) ?? []) attention.push({ provider: a.id, account: i.account, account_name: nameOf(i.account), level: i.level, what: i.what, link: i.link }); } catch { /* not configured */ }
  }
  const recsBy: Record<string, { open: number; saving_usd_month: number }> = {};
  for (const a of accounts) { const b = recsBy[a.provider] ?? { open: 0, saving_usd_month: 0 }; b.open += a.recommendations.open; b.saving_usd_month += a.recommendations.saving_usd_month; recsBy[a.provider] = b; }
  const sec = accounts.reduce((acc, a) => ({ critical: acc.critical + a.security.critical, high: acc.high + a.security.high }), { critical: 0, high: 0 });
  const order = { alarm: 0, warning: 1, info: 2 };
  const summed = parts.filter((p) => p.to_total && p.usd != null).map((p) => p.usd as number);
  return {
    accounts: accounts.length, providers: [...present],
    month: { total_usd: summed.length ? Math.round(summed.reduce((x, y) => x + y, 0)) : null, parts },
    recommendations: { open: Object.values(recsBy).reduce((x, b) => x + b.open, 0), saving_usd_month: Math.round(Object.values(recsBy).reduce((x, b) => x + b.saving_usd_month, 0)), by_provider: recsBy },
    attention: attention.sort((a, b) => order[a.level] - order[b.level]).slice(0, 30),
    counts: { alarms: accounts.reduce((x, a) => x + a.findings_alarms, 0), warnings: attention.filter((a) => a.level === "warning").length, alerts_open: accounts.reduce((x, a) => x + a.alerts_open, 0), security_critical: sec.critical, security_high: sec.high, vulnerabilities_critical: accounts.reduce((x, a) => x + a.vulnerabilities.critical, 0) },
  };
}

/**
 * Billing across every account (GET /api/accounts/billing): each provider's accounts with this month so far, the
 * month projected and last month, and the totals. AWS lists every linked account the payer's Cost Explorer bills,
 * including the ones not added to the advisor; its per-account lines are unblended (before credits), so the payer's
 * net bill is given beside them as the figure the invoice will show.
 */
export interface AccountsBilling {
  month: string; previous_month: string; basis: "amortized" | "invoice";
  lines: import("./spend_compare.js").AccountBillingLine[];
  totals: { month_to_date_usd: number | null; projected_usd: number | null; last_month_usd: number | null; delta_usd: number | null; delta_pct: number | null };
  by_provider: Record<string, { month_to_date_usd: number | null; projected_usd: number | null; last_month_usd: number | null }>;
  /** the AWS payer's consolidated net bill: month to date, projected (the forecast, else the run rate) and last month */
  aws_net: { month_to_date_usd: number | null; projected_usd: number | null; basis: string | null; last_month_usd: number | null } | null;
}

export async function accountsBilling(basis: "amortized" | "invoice" = "amortized"): Promise<AccountsBilling> {
  const { steadyBlend } = await import("./spend_compare.js");
  const { localDay, addDays, monthStart } = await import("./localdate.js");
  const today = localDay(); const month = today.slice(0, 7); const prevMonth = addDays(monthStart(today), -1).slice(0, 7);
  const known = await allAccounts();
  const lines: AccountsBilling["lines"] = [];
  for (const a of adapters()) {
    if (!a.cost?.accounts) continue;
    try {
      for (const l of await a.cost.accounts({ basis })) {
        const k = known.find((x) => x.provider === a.id && x.id === l.account);
        // the steady-months rule (src/spend_compare.ts steadyBlend): a projection far from months that held steady leans on them
        const st = l.projected_usd != null && l.history?.length ? steadyBlend(l.projected_usd, l.history) : null;
        const projected = st ? st.projected : l.projected_usd;
        lines.push({ provider: a.id, name: k?.name ?? null, registered: Boolean(k), ...l, projected_usd: projected, run_rate_usd: st?.run_rate ?? l.projected_usd, typical_usd: st?.typical ?? null, steady: st?.steady ?? false, blended: st?.blended ?? false,
          delta_pct: projected != null && l.last_month_usd ? Math.round(((projected - l.last_month_usd) / l.last_month_usd) * 1000) / 10 : null });
      }
    } catch (e: any) { console.error(`[billing] ${a.id}: ${e?.message || e}`); }
  }
  const sum = (xs: (number | null)[]) => { const v = xs.filter((x): x is number => x != null); return v.length ? Math.round(v.reduce((s, x) => s + x, 0) * 100) / 100 : null; };
  const by_provider: AccountsBilling["by_provider"] = {};
  for (const p of [...new Set(lines.map((l) => l.provider))]) { const ls = lines.filter((l) => l.provider === p); by_provider[p] = { month_to_date_usd: sum(ls.map((l) => l.month_to_date_usd)), projected_usd: sum(ls.map((l) => l.projected_usd)), last_month_usd: sum(ls.map((l) => l.last_month_usd)) }; }
  let aws_net: AccountsBilling["aws_net"] = null;
  if (lines.some((l) => l.provider === "aws")) {
    try {
      const { payerProjection } = await import("./spend_compare.js"); const { spendSummary } = await import("./spend.js");
      const p = await payerProjection(today); const s = spendSummary(today);
      aws_net = { month_to_date_usd: s.month_to_date.usd, projected_usd: p.usd, basis: p.basis, last_month_usd: s.previous_month.usd };
    } catch { /* no spend read yet */ }
  }
  const projected = sum(lines.map((l) => l.projected_usd)); const last = sum(lines.map((l) => l.last_month_usd));
  return {
    month, previous_month: prevMonth, basis, lines, by_provider, aws_net,
    totals: { month_to_date_usd: sum(lines.map((l) => l.month_to_date_usd)), projected_usd: projected, last_month_usd: last, delta_usd: projected != null && last != null ? Math.round((projected - last) * 100) / 100 : null, delta_pct: projected != null && last ? Math.round(((projected - last) / last) * 1000) / 10 : null },
  };
}

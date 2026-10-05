import { allAccounts } from "./adapters/index.js";
import { awsAdapter } from "./adapters/aws/index.js";
import { db } from "./db.js";
import type { AccountRecord } from "./adapters/types.js";
import * as vercelInventory from "./adapters/vercel/inventory.js";
const require_vercel = () => vercelInventory;

/**
 * The general view across accounts (Overview › Accounts, GET /api/accounts/overview): one row per account with what
 * a person wants before choosing one to look at: how much is there, what it costs, what is open and what is urgent.
 * Everything comes from the tables that carry an account id (the inventories, findings, scans, spend); what names a
 * resource instead (recommendations, alerts, vulnerability verdicts) is attributed through the inventory's ids.
 * Rows stored before the inventory recorded account ids belong to the primary account.
 */

export interface AccountOverview extends AccountRecord {
  resources: { ec2_running: number; ec2_total: number; rds: number; lambda: number; dynamodb: number; elb: number; s3: number; ebs_gb: number; clusters: number };
  monthly_list_usd: number;
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
  const primary = awsAdapter.primaryAccountId();
  const key = (acct: unknown) => (String(acct || "") || primary);
  const byAcct = <T,>(init: () => T) => { const m = new Map<string, T>(); return { get: (a: unknown) => { const k = key(a); if (!m.has(k)) m.set(k, init()); return m.get(k)!; } }; };

  const res = byAcct(() => ({ ec2_running: 0, ec2_total: 0, rds: 0, lambda: 0, dynamodb: 0, elb: 0, s3: 0, ebs_gb: 0, clusters: 0, list: 0 }));
  for (const r of rows("select account_id, count(*) as total, coalesce(sum(state = 'running'), 0) as running, coalesce(sum(monthly_usd), 0) as usd from inventory_ec2 where gone = 0 group by account_id")) { const x = res.get(r.account_id); x.ec2_total += n(r.total); x.ec2_running += n(r.running); x.list += n(r.usd); }
  for (const [t, col] of [["inventory_rds", "rds"], ["inventory_lambda", "lambda"], ["inventory_dynamodb", "dynamodb"], ["inventory_elb", "elb"], ["inventory_s3", "s3"]] as const) for (const r of rows(`select account_id, count(*) as c, coalesce(sum(monthly_usd), 0) as usd from ${t} where gone = 0 group by account_id`)) { const x = res.get(r.account_id); (x as any)[col] += n(r.c); x.list += n(r.usd); }
  // the platform services (keys, web ACLs, file systems, vaults, topics, workgroups) add to the list price; they are not counted as resources here
  for (const r of rows("select account_id, coalesce(sum(monthly_usd), 0) as usd from inventory_service where gone = 0 group by account_id")) res.get(r.account_id).list += n(r.usd);
  for (const r of rows("select account_id, coalesce(sum(size_gb), 0) as gb, coalesce(sum(monthly_usd), 0) as usd from inventory_ebs where gone = 0 group by account_id")) { const x = res.get(r.account_id); x.ebs_gb += n(r.gb); x.list += n(r.usd); }
  for (const r of rows("select account_id, count(*) as c from inventory_cluster where gone = 0 group by account_id")) res.get(r.account_id).clusters += n(r.c);

  const latestRun = rows("select id, finished_at from runs where provider = 'aws' and status = 'completed' order by id desc limit 1")[0];
  const alarms = byAcct(() => ({ n: 0 }));
  if (latestRun) for (const r of rows("select account_id, count(*) as c from findings where run_id = ? and status = 'alarm' group by account_id", latestRun.id)) alarms.get(r.account_id).n += n(r.c);
  const scan = rows("select id, finished_at from compliance_scans where status = 'completed' order by id desc limit 1")[0];
  const sec = byAcct(() => ({ critical: 0, high: 0 }));
  if (scan) for (const r of rows("select account_id, severity, count(*) as c from compliance_findings where scan_id = ? and severity in ('critical', 'high') group by account_id, severity", scan.id)) { const x = sec.get(r.account_id); if (r.severity === "critical") x.critical += n(r.c); else x.high += n(r.c); }

  const idx = resourceAccountIndex(primary);
  const recs = byAcct(() => ({ open: 0, saving: 0 }));
  for (const r of rows("select resource, est_monthly_saving from recommendations where status = 'open'")) { const a = idx.of(r.resource); if (a) { const x = recs.get(a); x.open++; x.saving += n(r.est_monthly_saving); } }
  const alerts = byAcct(() => ({ n: 0 }));
  for (const r of rows("select resource from alerts where acknowledged = 0")) { const a = idx.of(r.resource); if (a) alerts.get(a).n++; }

  const vulns = byAcct(() => ({ critical: 0, exposed: 0, boxes: new Set<string>() }));
  try {
    const { vulnerabilityMatches } = await import("./software_vulns.js");
    for (const m of vulnerabilityMatches()) { const a = idx.of(m.instance_id); if (!a) continue; const x = vulns.get(a); if (m.criticality === "critical") x.critical++; if (m.criticality === "exposed") x.exposed++; x.boxes.add(m.instance_id); }
  } catch { /* the software layer is optional */ }

  const probes = byAcct(() => ({ ssm_online: 0, probed_24h: 0 }));
  for (const r of rows("select account_id, coalesce(sum(ssm_status = 'Online'), 0) as online, coalesce(sum(probe_at > datetime('now', '-1 day')), 0) as probed from inventory_ec2 where gone = 0 and state = 'running' group by account_id")) { const x = probes.get(r.account_id); x.ssm_online += n(r.online); x.probed_24h += n(r.probed); }

  // the last full month's bill per account (the current month is partial); the current month when nothing else exists
  const thisMonth = new Date().toISOString().slice(0, 7);
  const spendRows = rows("select month, account_id, usd from spend_by_account_monthly order by month desc");
  const spendOf = (acct: string, provider: string) => {
    if (provider === "vercel") { try { const inv = (require_vercel().listInvoices(3) as any[]).find((i) => i.status === "paid" && i.total != null); return inv ? { month: String(inv.created_at || "").slice(0, 7) || null, usd: n(inv.total) } : { month: null, usd: null }; } catch { return { month: null, usd: null }; } }
    const r = spendRows.find((s) => String(s.account_id) === acct && String(s.month) < thisMonth) ?? spendRows.find((s) => String(s.account_id) === acct); return r ? { month: String(r.month), usd: n(r.usd) } : { month: null, usd: null };
  };
  const collectedAt = (rows("select max(last_seen) as at from inventory_ec2")[0]?.at as string | null) ?? null;

  return accounts.map((a) => {
    const r = res.get(a.id); const s = sec.get(a.id); const v = vulns.get(a.id); const p = probes.get(a.id); const rc = recs.get(a.id);
    return { ...a, resources: { ec2_running: r.ec2_running, ec2_total: r.ec2_total, rds: r.rds, lambda: r.lambda, dynamodb: r.dynamodb, elb: r.elb, s3: r.s3, ebs_gb: Math.round(r.ebs_gb), clusters: r.clusters }, monthly_list_usd: Math.round(r.list), spend: spendOf(a.id, a.provider),
      findings_alarms: alarms.get(a.id).n, security: { critical: s.critical, high: s.high, scan_at: scan?.finished_at ?? null }, recommendations: { open: rc.open, saving_usd_month: Math.round(rc.saving) }, alerts_open: alerts.get(a.id).n,
      vulnerabilities: { critical: v.critical, exposed: v.exposed, boxes: v.boxes.size }, probes: { ssm_online: p.ssm_online, probed_24h: p.probed_24h }, last_collected_at: a.parent_id ? collectedAt : (latestRun?.finished_at ?? collectedAt) };
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
  month: { total_usd: number | null; aws_projected_usd: number | null; aws_month_to_date_usd: number | null; vercel_estimated_usd: number | null; vercel_stores_at_plan_usd: number | null };
  recommendations: { open: number; saving_usd_month: number; by_provider: Record<string, { open: number; saving_usd_month: number }> };
  attention: { provider: string; account: string; account_name: string | null; level: "alarm" | "warning" | "info"; what: string; link: string | null }[];
  counts: { alarms: number; warnings: number; alerts_open: number; security_critical: number; security_high: number; vulnerabilities_critical: number };
}

export async function generalOverview(): Promise<GeneralOverview> {
  const accounts = await accountsOverview();
  const nameOf = (id: string) => accounts.find((a) => a.id === id)?.name ?? null;
  const primary = awsAdapter.primaryAccountId();
  const attention: GeneralOverview["attention"] = [];
  let awsProjected: number | null = null; let awsMtd: number | null = null;
  try { const { latestForecast } = await import("./forecast.js"); const f: any = latestForecast(); awsProjected = f?.forecast_net ?? null; awsMtd = f?.mtd_net ?? null; } catch { /* no forecast */ }
  if (awsProjected == null) { try { const { spendSummary } = await import("./spend.js"); const sp: any = spendSummary(); awsProjected = sp?.month_to_date?.projected_month_end ?? null; awsMtd = sp?.month_to_date?.usd ?? null; } catch { /* no spend */ } }
  let vercelEst: number | null = null; let vercelStores: number | null = null;
  const vercelAccounts = accounts.filter((a) => a.provider === "vercel");
  if (vercelAccounts.length) {
    try {
      const v = await import("./adapters/vercel/index.js"); const o = v.vercelOverview();
      vercelEst = o.billing?.estimated_period_usd ?? null; vercelStores = o.store_stats?.monthly_list_usd ?? null;
      for (const a of o.attention) attention.push({ provider: "vercel", account: vercelAccounts[0].id, account_name: vercelAccounts[0].name, level: a.level, what: a.what, link: a.tab ? `/inventory?tab=${a.tab}` : "/findings" });
    } catch { /* not configured */ }
  }
  const latestRun = rows("select id from runs where provider = 'aws' and status = 'completed' order by id desc limit 1")[0];
  let alarms = 0;
  if (latestRun) for (const r of rows("select control_id, control_title, count(*) as c, min(coalesce(account_id, '')) as acct from findings where run_id = ? and status = 'alarm' group by control_id, control_title order by c desc limit 12", latestRun.id)) { alarms += n(r.c); attention.push({ provider: "aws", account: String(r.acct) || primary, account_name: nameOf(String(r.acct) || primary), level: "warning", what: `${r.control_title || r.control_id}: ${r.c} resource${n(r.c) === 1 ? "" : "s"}`, link: `/findings?control_id=${encodeURIComponent(String(r.control_id))}` }); }
  const idx = resourceAccountIndex(primary);
  for (const r of rows("select id, kind, message, resource, created_at from alerts where acknowledged = 0 and datetime(created_at) > datetime('now', '-7 days') order by id desc limit 10")) attention.push({ provider: "aws", account: idx.of(r.resource) ?? primary, account_name: nameOf(idx.of(r.resource) ?? primary), level: "alarm", what: `${r.kind}: ${String(r.message).slice(0, 160)}`, link: "/alerts" });
  const recsBy: Record<string, { open: number; saving_usd_month: number }> = {};
  for (const a of accounts) { const b = recsBy[a.provider] ?? { open: 0, saving_usd_month: 0 }; b.open += a.recommendations.open; b.saving_usd_month += a.recommendations.saving_usd_month; recsBy[a.provider] = b; }
  const sec = accounts.reduce((acc, a) => ({ critical: acc.critical + a.security.critical, high: acc.high + a.security.high }), { critical: 0, high: 0 });
  const order = { alarm: 0, warning: 1, info: 2 };
  const parts = [awsProjected, vercelEst, vercelStores].filter((x): x is number => x != null);
  return {
    accounts: accounts.length, providers: [...new Set(accounts.map((a) => a.provider))],
    month: { total_usd: parts.length ? Math.round(parts.reduce((x, y) => x + y, 0)) : null, aws_projected_usd: awsProjected, aws_month_to_date_usd: awsMtd, vercel_estimated_usd: vercelEst, vercel_stores_at_plan_usd: vercelStores },
    recommendations: { open: Object.values(recsBy).reduce((x, b) => x + b.open, 0), saving_usd_month: Math.round(Object.values(recsBy).reduce((x, b) => x + b.saving_usd_month, 0)), by_provider: recsBy },
    attention: attention.sort((a, b) => order[a.level] - order[b.level]).slice(0, 30),
    counts: { alarms, warnings: attention.filter((a) => a.level === "warning").length, alerts_open: accounts.reduce((x, a) => x + a.alerts_open, 0), security_critical: sec.critical, security_high: sec.high, vulnerabilities_critical: accounts.reduce((x, a) => x + a.vulnerabilities.critical, 0) },
  };
}

import { db } from "../../db.js";
import type { RecInput } from "../../rules.js";
import { listDomains, listProjects, listStores, teamExtras, vercelTeam, type ProjectRow, type StoreRow } from "./inventory.js";
import { usageTotals } from "./usage.js";
import { projectEndpoints, vercelAdapter } from "./index.js";

/**
 * Deterministic findings for a Vercel team, the way the AWS rules and benchmark controls work: each check is a
 * control (`vercel.control.<name>`), every alarm it raises is a finding on a resource (a project, a store, the team),
 * and the actionable ones become recommendations in the same table AWS rules write, with the same tiers, decisions,
 * resolution threads and graph record. Nothing here is automated (tier report or approve): the executor has no
 * Vercel actuator.
 *
 * One pass per collection: `runVercelRules()` writes a run row (`provider: vercel`, the team as account), the
 * findings of that run, upserts the recommendations (fingerprint rule:resource, so a decision survives the next
 * pass) and resolves the open ones whose finding went away. The Overview's attention list is these findings.
 */

export type Severity = "alarm" | "warning" | "info";
export interface VercelFinding { control_id: string; control_title: string; severity: Severity; category: "security" | "cost" | "reliability" | "operations"; resource: string; resource_name: string; reason: string; dimensions: Record<string, unknown>; tab?: string }

/** The documentation each control's playbook is generated from (src/playbook_gen.ts): Vercel's, Neon's and Redis Cloud's own pages, read and cited by the agent; nothing is hand-written. */
export const CONTROL_REFERENCES: Record<string, string[]> = {
  "vercel.control.production_deployment_failed": ["https://vercel.com/docs/deployments/troubleshoot-a-build", "https://vercel.com/docs/deployments/instant-rollback"],
  "vercel.control.preview_urls_open": ["https://vercel.com/docs/deployment-protection", "https://vercel.com/docs/deployment-protection/methods-to-protect-deployments/vercel-authentication", "https://vercel.com/docs/deployment-protection/methods-to-bypass-deployment-protection/protection-bypass-automation"],
  "vercel.control.domain_unverified": ["https://vercel.com/docs/domains/working-with-domains/add-a-domain", "https://vercel.com/docs/domains/troubleshooting"],
  "vercel.control.firewall_off": ["https://vercel.com/docs/vercel-firewall", "https://vercel.com/docs/vercel-firewall/vercel-waf/rate-limiting", "https://vercel.com/docs/vercel-firewall/vercel-waf/managed-rulesets"],
  "vercel.control.member_without_mfa": ["https://vercel.com/docs/accounts/team-members-and-roles/security", "https://vercel.com/docs/accounts/team-members-and-roles"],
  "vercel.control.project_without_log_drain": ["https://vercel.com/docs/log-drains", "https://vercel.com/docs/log-drains/log-drains-reference"],
  "vercel.control.store_unconnected": ["https://vercel.com/docs/storage", "https://vercel.com/docs/integrations/install-an-integration/manage-marketplace-integrations"],
  "vercel.control.store_quota_exceeded": ["https://vercel.com/docs/storage", "https://neon.com/docs/introduction/plans"],
  "vercel.control.store_partner_unhealthy": ["https://vercel.com/docs/storage", "https://neon.com/docs/introduction/support"],
  "vercel.control.blob_token_expired": ["https://vercel.com/docs/vercel-blob", "https://vercel.com/docs/vercel-blob/using-blob-sdk"],
  "vercel.control.free_plan_in_production": ["https://neon.com/docs/introduction/plans", "https://redis.io/docs/latest/operate/rc/subscriptions/view-essentials-subscription/"],
  "vercel.control.function_error_rate": ["https://vercel.com/docs/observability/runtime-logs", "https://vercel.com/docs/functions/runtimes"],
  "vercel.control.function_throttled": ["https://vercel.com/docs/functions/limitations", "https://vercel.com/docs/fluid-compute"],
  "vercel.control.function_timeouts": ["https://vercel.com/docs/functions/configuring-functions/duration", "https://vercel.com/docs/functions/limitations"],
  "vercel.control.builds_failing": ["https://vercel.com/docs/deployments/troubleshoot-a-build", "https://vercel.com/docs/deployments/configure-a-build"],
  "vercel.control.edge_cache_cold": ["https://vercel.com/docs/edge-cache", "https://vercel.com/docs/headers/cache-control-headers"],
  "vercel.control.neon_never_suspends": ["https://neon.com/docs/introduction/scale-to-zero", "https://neon.com/docs/manage/computes", "https://neon.com/docs/introduction/usage-metrics"],
  "vercel.control.neon_no_ip_allow": ["https://neon.com/docs/introduction/ip-allow", "https://neon.com/docs/manage/projects"],
  "vercel.control.neon_many_branches": ["https://neon.com/docs/introduction/branching", "https://neon.com/docs/introduction/usage-metrics"],
  "vercel.control.redis_memory_high": ["https://redis.io/docs/latest/operate/rc/databases/configuration/sizing/", "https://redis.io/docs/latest/operate/rc/databases/configuration/data-eviction-policies/"],
  "vercel.control.redis_open_source_ips": ["https://redis.io/docs/latest/operate/rc/security/cidr-whitelist/", "https://redis.io/docs/latest/operate/rc/security/database-security/"],
  "vercel.control.redis_no_persistence": ["https://redis.io/docs/latest/operate/rc/databases/configuration/data-persistence/"],
};

export const CONTROLS: Record<string, { title: string; category: VercelFinding["category"]; severity: Severity }> = {
  "vercel.control.production_deployment_failed": { title: "Latest production deployment failed", category: "reliability", severity: "alarm" },
  "vercel.control.preview_urls_open": { title: "Preview deployments open to anyone", category: "security", severity: "warning" },
  "vercel.control.domain_unverified": { title: "Custom domain not verified", category: "reliability", severity: "warning" },
  "vercel.control.firewall_off": { title: "Vercel firewall off", category: "security", severity: "info" },
  "vercel.control.member_without_mfa": { title: "Team member without MFA", category: "security", severity: "warning" },
  "vercel.control.project_without_log_drain": { title: "Project ships logs nowhere", category: "operations", severity: "info" },
  "vercel.control.store_unconnected": { title: "Store connected to no project", category: "cost", severity: "info" },
  "vercel.control.store_quota_exceeded": { title: "Store over its plan's quota", category: "reliability", severity: "warning" },
  "vercel.control.store_partner_unhealthy": { title: "Partner reports the store unhealthy", category: "reliability", severity: "warning" },
  "vercel.control.blob_token_expired": { title: "Blob store token expired", category: "reliability", severity: "warning" },
  "vercel.control.free_plan_in_production": { title: "Production database on a free plan", category: "reliability", severity: "info" },
  "vercel.control.function_error_rate": { title: "Function error rate above 1%", category: "reliability", severity: "warning" },
  "vercel.control.function_throttled": { title: "Function invocations throttled", category: "reliability", severity: "warning" },
  "vercel.control.function_timeouts": { title: "Function invocations timing out", category: "reliability", severity: "info" },
  "vercel.control.builds_failing": { title: "Builds failing", category: "operations", severity: "info" },
  "vercel.control.edge_cache_cold": { title: "Edge cache hit rate under 20%", category: "cost", severity: "info" },
  "vercel.control.neon_never_suspends": { title: "Neon compute never suspends", category: "cost", severity: "info" },
  "vercel.control.neon_no_ip_allow": { title: "Neon database without an IP allow list", category: "security", severity: "info" },
  "vercel.control.neon_many_branches": { title: "Many Neon branches", category: "cost", severity: "info" },
  "vercel.control.redis_memory_high": { title: "Redis memory near its limit", category: "reliability", severity: "warning" },
  "vercel.control.redis_open_source_ips": { title: "Redis public endpoint open to any address", category: "security", severity: "info" },
  "vercel.control.redis_no_persistence": { title: "Production cache without persistence", category: "reliability", severity: "info" },
};

const tabOf = (st: StoreRow) => (st.kind === "database" ? "rds" : st.kind === "cache" ? "elasticache" : "s3");
const openCidr = (ips: string[]) => !ips.length || ips.some((ip) => /^0\.0\.0\.0\/0$|^::\/0$/.test(ip));

/** Every finding the inventory supports right now; pure given the tables. */
export function vercelFindings(): VercelFinding[] {
  const team = vercelTeam(); const teamId = team?.id ?? vercelAdapter.primaryAccountId();
  const projects = listProjects(); const stores = listStores(); const extras = teamExtras(teamId);
  const out: VercelFinding[] = [];
  const add = (control_id: string, resource: string, resource_name: string, reason: string, dimensions: Record<string, unknown> = {}, severity?: Severity, tab?: string) => { const c = CONTROLS[control_id]; out.push({ control_id, control_title: c.title, severity: severity ?? c.severity, category: c.category, resource, resource_name, reason, dimensions, tab }); };

  for (const p of projects) {
    if (p.latest_target === "production" && (p.latest_state || "").toUpperCase() === "ERROR") add("vercel.control.production_deployment_failed", p.id, p.name, `the latest production deployment (${p.latest_at ?? "unknown time"}) ended in ERROR`, { latest_url: p.latest_url, at: p.latest_at }, undefined, "deployments");
    const prev = projectEndpoints(p).filter((e) => e.target === "preview" && !e.requires_auth);
    if (prev.length) add("vercel.control.preview_urls_open", p.id, p.name, `${prev.length} preview URL${prev.length === 1 ? "" : "s"} open to anyone (no deployment protection on previews): ${prev.slice(0, 3).map((e) => e.hostname).join(", ")}${prev.length > 3 ? ", …" : ""}`, { urls: prev.map((e) => e.hostname), protection: p.protection }, undefined, "deployments");
    for (const d of listDomains(p.id)) if (!d.verified) add("vercel.control.domain_unverified", p.id, p.name, `domain ${d.name} is not verified`, { domain: d.name }, undefined, "deployments");
    if (p.firewall && !p.firewall.enabled) add("vercel.control.firewall_off", p.id, p.name, "the Vercel firewall is off: no rate limits or WAF rules in front of the project", { firewall: p.firewall }, undefined, "deployments");
  }
  const drained = new Set(extras.log_drains.filter((d) => !d.status || /enabled|active/i.test(d.status)).flatMap((d) => (d.project_ids.length ? d.project_ids : projects.map((p) => p.id))));
  if (extras.log_drains.length) for (const p of projects) if (!drained.has(p.id)) add("vercel.control.project_without_log_drain", p.id, p.name, `no log drain covers this project; its function and edge logs stop at Vercel's retention (the team has ${extras.log_drains.length} drain${extras.log_drains.length === 1 ? "" : "s"})`, { drains: extras.log_drains.map((d) => d.name ?? d.id) }, undefined, "deployments");
  // one finding per member: the resource is the member within the team (the team id keeps it in the team's scope)
  for (const m of extras.members.filter((x) => x.confirmed && x.mfa === false)) add("vercel.control.member_without_mfa", `${teamId}/member/${m.username ?? m.uid}`, m.username ?? m.uid, `${m.username ?? m.uid} (${m.role ?? "member"}) has no MFA on the Vercel account`, { username: m.username, role: m.role, github: m.github });

  for (const st of stores) {
    const d = st.details; const tab = tabOf(st); const prod = st.projects.some((p) => p.environments.includes("production"));
    if (!st.projects.length) add("vercel.control.store_unconnected", st.id, st.name, `${st.product || st.kind} store connected to no project${st.plan ? `; plan ${st.plan}` : ""}`, { product: st.product, plan: st.plan }, undefined, tab);
    if (d.quota_exceeded) add("vercel.control.store_quota_exceeded", st.id, st.name, `${st.product || st.kind} reports the store over its plan's quota (${st.plan ?? "plan unknown"})`, { plan: st.plan }, undefined, tab);
    if (d.external_status && !/ready|available|active/i.test(d.external_status)) add("vercel.control.store_partner_unhealthy", st.id, st.name, `${st.product || "the partner"} reports ${d.external_status}`, { external_status: d.external_status }, undefined, tab);
    if (st.type === "blob" && d.token_expired) add("vercel.control.blob_token_expired", st.id, st.name, "the store's read-write token has expired; the projects on it cannot read or write it", {}, undefined, "s3");
    if (st.kind === "database" && prod && /free/i.test(st.plan || "")) add("vercel.control.free_plan_in_production", st.id, st.name, `serves production on the ${st.plan} plan`, { plan: st.plan, projects: st.projects.map((p) => p.name) }, undefined, tab);
    const snap = st.partner?.snapshot;
    if (snap?.kind === "neon") {
      const rw = snap.endpoints.find((e) => e.type === "read_write");
      if (rw && rw.suspend_timeout_seconds === 0 && st.plan && !/free/i.test(st.plan)) add("vercel.control.neon_never_suspends", st.id, st.name, `the Neon compute never suspends (suspend timeout 0), so it bills ${rw.min_cu ?? "its minimum"} CU every hour of the month`, { min_cu: rw.min_cu, max_cu: rw.max_cu, active_hours_period: snap.project.active_time_seconds != null ? Math.round(snap.project.active_time_seconds / 360) / 10 : null, compute_hours_period: snap.project.compute_time_seconds != null ? Math.round(snap.project.compute_time_seconds / 360) / 10 : null }, undefined, tab);
      if (!snap.project.ip_allow.length && prod) add("vercel.control.neon_no_ip_allow", st.id, st.name, "Neon has no IP allow list; any address may try the password", {}, undefined, tab);
      if (snap.branches.length > 10) add("vercel.control.neon_many_branches", st.id, st.name, `${snap.branches.length} Neon branches; each one's storage bills`, { branches: snap.branches.length }, undefined, tab);
    } else if (snap?.kind === "redis_cloud") {
      const r = snap.database; const pct = r.memory_used_mb != null && r.memory_limit_mb ? (r.memory_used_mb / r.memory_limit_mb) * 100 : null;
      if (pct != null && pct >= 80) add("vercel.control.redis_memory_high", st.id, st.name, `Redis memory at ${Math.round(pct)}% of its ${r.memory_limit_mb} MB limit${r.eviction ? ` (eviction ${r.eviction})` : ""}`, { memory_used_mb: r.memory_used_mb, memory_limit_mb: r.memory_limit_mb, eviction: r.eviction }, pct >= 95 ? "alarm" : "warning", tab);
      if (r.public_endpoint && openCidr(r.source_ips)) add("vercel.control.redis_open_source_ips", st.id, st.name, `the Redis public endpoint accepts connections from any address (password only${r.tls ? ", TLS" : ", no TLS"})`, { endpoint: r.public_endpoint, tls: r.tls }, undefined, tab);
      if (r.persistence && /none/i.test(r.persistence) && prod) add("vercel.control.redis_no_persistence", st.id, st.name, "no persistence; a restart empties the production cache", { persistence: r.persistence }, undefined, tab);
    }
  }
  if (team) {
    const u7 = usageTotals(team.id, 7);
    if (u7.error_pct != null && u7.error_pct >= 1) add("vercel.control.function_error_rate", teamId, team.name ?? teamId, `${u7.error_pct}% of function invocations errored in the last 7 days (${u7.invocation_errors.toLocaleString()} of ${u7.invocations.toLocaleString()})`, { error_pct: u7.error_pct, errors: u7.invocation_errors, invocations: u7.invocations });
    if (u7.invocation_throttles > 0) add("vercel.control.function_throttled", teamId, team.name ?? teamId, `${u7.invocation_throttles.toLocaleString()} function invocations throttled in the last 7 days`, { throttles: u7.invocation_throttles });
    if (u7.invocation_timeouts > 0) add("vercel.control.function_timeouts", teamId, team.name ?? teamId, `${u7.invocation_timeouts.toLocaleString()} function invocations timed out in the last 7 days`, { timeouts: u7.invocation_timeouts });
    if (u7.builds_failed > 0) add("vercel.control.builds_failing", teamId, team.name ?? teamId, `${u7.builds_failed} of ${u7.builds} builds failed in the last 7 days`, { failed: u7.builds_failed, builds: u7.builds });
    if (u7.cache_hit_pct != null && u7.requests > 10_000 && u7.cache_hit_pct < 20) add("vercel.control.edge_cache_cold", teamId, team.name ?? teamId, `edge cache hit rate ${u7.cache_hit_pct}% over ${u7.requests.toLocaleString()} requests: most requests reach the functions and bill as invocations`, { cache_hit_pct: u7.cache_hit_pct, requests: u7.requests });
  }
  const order = { alarm: 0, warning: 1, info: 2 };
  return out.sort((a, b) => order[a.severity] - order[b.severity] || a.control_id.localeCompare(b.control_id) || a.resource_name.localeCompare(b.resource_name));
}

/** The findings a person can act on, as recommendations: a rule per control, the saving where one can be estimated, nothing automated. */
export function vercelRecommendations(findings: VercelFinding[], rateCuHour = 0.106): RecInput[] {
  const out: RecInput[] = [];
  const by = new Map<string, VercelFinding[]>(); for (const f of findings) { const k = `${f.control_id}:${f.resource}`; by.set(k, [...(by.get(k) ?? []), f]); }
  for (const [, group] of by) {
    const f = group[0]; const rule = f.control_id.replace(/^vercel\.control\./, "vercel_");
    const base = { rule, resource: f.resource, resourceName: f.resource_name, evidence: { findings: group.map((g) => ({ reason: g.reason, ...g.dimensions })), control: f.control_id, category: f.category } };
    switch (f.control_id) {
      case "vercel.control.preview_urls_open": out.push({ ...base, title: `${f.resource_name}: protect preview deployments`, actionType: "security_fix", estMonthlySaving: null, tier: "approve", confidence: 0.9, rationale: `${group[0].reason}. Vercel Authentication on previews (Settings › Deployment Protection) keeps the production URL public and asks preview visitors to log in; nothing in production changes.` }); break;
      case "vercel.control.member_without_mfa": out.push({ ...base, title: `${f.resource_name}: enable MFA on the Vercel account`, actionType: "security_fix", estMonthlySaving: null, tier: "report", confidence: 0.95, rationale: `${f.reason}. A team member's password alone opens every project, env variable name and store on the team; MFA is the member's own setting (Account settings › Security).` }); break;
      case "vercel.control.firewall_off": out.push({ ...base, title: `${f.resource_name}: turn the Vercel firewall on`, actionType: "security_fix", estMonthlySaving: null, tier: "approve", confidence: 0.6, rationale: `${f.reason}. The firewall's managed rules and rate limits are free on Pro; a rate limit on the API routes stops a scraper from turning into a function invoice.` }); break;
      case "vercel.control.project_without_log_drain": out.push({ ...base, title: `${f.resource_name}: add the project to a log drain`, actionType: "enable_logging", estMonthlySaving: null, tier: "approve", confidence: 0.8, rationale: `${f.reason}. Without a drain an incident on this project has no logs older than Vercel's retention to read.` }); break;
      case "vercel.control.store_unconnected": out.push({ ...base, title: `${f.resource_name}: remove or connect the unused store`, actionType: "delete", estMonthlySaving: null, tier: "approve", confidence: 0.7, rationale: `${f.reason}. A store no project uses still holds its plan and its data; delete it after a last export, or connect the project that needs it.` }); break;
      case "vercel.control.domain_unverified": out.push({ ...base, title: `${f.resource_name}: finish the domain verification`, actionType: "other", estMonthlySaving: null, tier: "approve", confidence: 0.9, rationale: `${group.map((g) => g.reason).join("; ")}. An unverified domain serves nothing; either finish the DNS record or remove the domain so nobody expects it to work.` }); break;
      case "vercel.control.production_deployment_failed": out.push({ ...base, title: `${f.resource_name}: the latest production deployment failed`, actionType: "other", estMonthlySaving: null, tier: "report", confidence: 0.95, rationale: `${f.reason}. Production keeps serving the previous deployment; the build log says why the new one failed.` }); break;
      case "vercel.control.neon_never_suspends": { const d = f.dimensions as { min_cu: number | null; active_hours_period: number | null; compute_hours_period: number | null }; const idle = d.compute_hours_period != null && d.active_hours_period != null ? Math.max(0, d.compute_hours_period - d.active_hours_period) : null; const saving = idle != null && d.min_cu ? Math.round(idle * d.min_cu * rateCuHour * 100) / 100 : null;
        out.push({ ...base, title: `${f.resource_name}: let the Neon compute suspend when idle`, actionType: "schedule", estMonthlySaving: saving, tier: "approve", confidence: 0.7, rationale: `${f.reason}.${idle != null ? ` This period it ran ${d.compute_hours_period} compute hours for ${d.active_hours_period} active hours: ${idle} idle hours at ${d.min_cu} CU × $${rateCuHour}.` : ""} A suspend timeout of five minutes stops the idle billing; the first query after a suspend takes a few hundred milliseconds longer.` }); break; }
      case "vercel.control.neon_no_ip_allow": out.push({ ...base, title: `${f.resource_name}: restrict Neon to the addresses that need it`, actionType: "security_fix", estMonthlySaving: null, tier: "approve", confidence: 0.6, rationale: `${f.reason}. Vercel functions have no fixed egress address unless Secure Compute is on, so the allow list is practical only for production branches reached from fixed addresses; otherwise rotate the password and keep it in Vercel's env only.` }); break;
      case "vercel.control.redis_memory_high": out.push({ ...base, title: `${f.resource_name}: Redis is near its memory limit`, actionType: "rightsize", estMonthlySaving: null, tier: "approve", confidence: 0.85, rationale: `${f.reason}. Either the eviction policy is doing the work (acceptable for a cache) or writes will start failing; move to the next plan size or expire keys.` }); break;
      case "vercel.control.redis_open_source_ips": out.push({ ...base, title: `${f.resource_name}: limit the Redis endpoint's source IPs`, actionType: "security_fix", estMonthlySaving: null, tier: "approve", confidence: 0.6, rationale: `${f.reason}. Redis Cloud accepts a source IP list per database; with Vercel functions on Secure Compute the list is the VPC's NAT addresses, otherwise a strong password and TLS are the only guard.` }); break;
      case "vercel.control.redis_no_persistence": out.push({ ...base, title: `${f.resource_name}: decide whether the cache may be lost`, actionType: "other", estMonthlySaving: null, tier: "report", confidence: 0.7, rationale: `${f.reason}. Fine for a pure cache; not for sessions, queues or rate-limit counters.` }); break;
      case "vercel.control.free_plan_in_production": out.push({ ...base, title: `${f.resource_name}: production on a free plan`, actionType: "other", estMonthlySaving: null, tier: "report", confidence: 0.7, rationale: `${f.reason}. Free plans carry hard limits (size, connections, throughput) and no support; the plan is a decision, not a default.` }); break;
      case "vercel.control.edge_cache_cold": out.push({ ...base, title: "Edge cache serves almost nothing: review cache headers", actionType: "other", estMonthlySaving: null, tier: "report", confidence: 0.5, rationale: `${f.reason}. Static assets and public pages with Cache-Control headers are served by the edge for free; every miss is a function invocation and GB-hours on the bill.` }); break;
      default: break; // quota, token, partner health, errors, throttles, timeouts, builds, branches: findings and attention items, not recommendations
    }
  }
  return out;
}

export interface VercelRulesResult { run_id: number; findings: number; alarms: number; recommendations: number; resolved: number; alerts_raised: number; alerts_closed: number }

/** One rules pass: the run row, its findings, the recommendations upserted and the stale ones resolved. */
export async function runVercelRules(): Promise<VercelRulesResult> {
  // the collector is imported here, not at the top: it reaches the adapter registry, which reaches this module
  const { upsertRecommendations } = await import("../../collector.js");
  const team = vercelTeam(); const teamId = team?.id ?? vercelAdapter.primaryAccountId();
  const findings = vercelFindings(); const recs = vercelRecommendations(findings);
  let runId = 0; let resolved = 0; let raised = 0; let closed = 0;
  db.transaction(() => {
    runId = Number(db.prepare("insert into runs(trigger, status, account_id, provider, started_at) values ('vercel', 'running', ?, 'vercel', datetime('now'))").run(teamId).lastInsertRowid);
    const ins = db.prepare("insert into findings(run_id, source, benchmark, control_id, control_title, status, resource, reason, dimensions, account_id, region, fingerprint) values (?, 'vercel', 'vercel', ?, ?, ?, ?, ?, ?, ?, null, ?)");
    for (const f of findings) ins.run(runId, f.control_id, f.control_title, f.severity === "info" ? "info" : "alarm", f.resource, f.reason, JSON.stringify({ ...f.dimensions, severity: f.severity, category: f.category, resource_name: f.resource_name, tab: f.tab ?? null }), teamId, `${f.control_id}:${f.resource}`);
    upsertRecommendations(runId, recs, "rules", undefined, { reconcile: false });
    const live = new Set(recs.map((r) => `${r.rule}:${r.resource}`));
    for (const row of db.prepare("select id, fingerprint from recommendations where status = 'open' and source = 'rules' and rule like 'vercel\\_%' escape '\\'").all() as { id: number; fingerprint: string }[]) {
      if (!live.has(row.fingerprint)) { db.prepare("update recommendations set status = 'resolved', updated_at = datetime('now') where id = ?").run(row.id); resolved++; }
    }
    db.prepare("update runs set status = 'completed', finished_at = datetime('now'), findings_count = ?, recommendations_count = ? where id = ?").run(findings.length, recs.length, runId);
    const a = syncAlerts(teamId, team?.name ?? null, findings, runId);
    raised = a.raised; closed = a.closed;
  })();
  return { run_id: runId, findings: findings.length, alarms: findings.filter((f) => f.severity !== "info").length, recommendations: recs.length, resolved, alerts_raised: raised, alerts_closed: closed };
}

/**
 * Alerts follow the alarm and warning findings the way status checks do: a finding that was not in the previous
 * pass raises one (kind `vercel_<control>`, the fingerprint in its details), a finding that is gone closes its open
 * alert (acknowledged by the system, with the reason). Info findings never page. The notifier then applies its
 * own rules (level threshold, quiet hours) and the Sphinx bot carries what passes.
 */
export function syncAlerts(teamId: string, teamName: string | null, findings: VercelFinding[], runId: number): { raised: number; closed: number } {
  const live = new Map(findings.filter((f) => f.severity !== "info").map((f) => [`${f.control_id}:${f.resource}`, f]));
  const open = db.prepare("select id, details from alerts where kind like 'vercel\\_%' escape '\\' and acknowledged = 0").all() as { id: number; details: string | null }[];
  // the first pass ever finds the backlog: it is recorded as alerts but not paged, so the bot does not open with twenty messages about things that were already true
  const firstPass = !(db.prepare("select 1 from alerts where kind like 'vercel\\_%' escape '\\' limit 1").get());
  const openBy = new Map<string, number>();
  for (const a of open) { try { const fp = JSON.parse(a.details || "{}").fingerprint; if (fp) openBy.set(String(fp), a.id); } catch { /* */ } }
  let raised = 0; let closed = 0;
  const ins = firstPass ? db.prepare("insert into alerts(kind, resource, message, details, notified_at, notify_result) values (?, ?, ?, ?, datetime('now'), 'skipped: already true at the first rules pass; only new findings page')") : db.prepare("insert into alerts(kind, resource, message, details) values (?, ?, ?, ?)");
  const close = db.prepare("update alerts set acknowledged = 1, acknowledged_by = 'system', triage = ? where id = ?");
  for (const [fp, f] of live) {
    if (openBy.has(fp)) continue;
    const message = `${teamName ? `${teamName}: ` : ""}${f.resource_name && f.resource !== teamId && !f.resource.includes("/member/") ? `${f.resource_name}: ` : ""}${f.reason}`;
    ins.run(`vercel_${f.control_id.replace(/^vercel\.control\./, "")}`, f.resource, message, JSON.stringify({ summary: message, level: f.severity, fingerprint: fp, control_id: f.control_id, control_title: f.control_title, category: f.category, resource_name: f.resource_name, team_id: teamId, run_id: runId, tab: f.tab ?? null, ...f.dimensions }));
    raised++;
  }
  for (const [fp, id] of openBy) if (!live.has(fp)) { close.run(JSON.stringify({ closed_by: "system", reason: `the finding was not raised by rules pass #${runId}`, closed_at: new Date().toISOString() }), id); closed++; }
  return { raised, closed };
}

/** The latest pass's findings, for the Overview's attention list and the agent. */
export function latestVercelFindings(teamId: string): { run_id: number | null; at: string | null; findings: VercelFinding[] } {
  const run = db.prepare("select id, finished_at from runs where provider = 'vercel' and account_id = ? and status = 'completed' order by id desc limit 1").get(teamId) as { id: number; finished_at: string } | undefined;
  if (!run) return { run_id: null, at: null, findings: [] };
  const rows = db.prepare("select control_id, control_title, resource, reason, dimensions from findings where run_id = ? order by id").all(run.id) as any[];
  const order = { alarm: 0, warning: 1, info: 2 };
  const findings = rows.map((r) => { let d: any = {}; try { d = JSON.parse(r.dimensions || "{}"); } catch { /* */ } const { severity = "info", category = "operations", resource_name = r.resource, tab = null, ...dimensions } = d; return { control_id: r.control_id, control_title: r.control_title, severity, category, resource: r.resource, resource_name, reason: r.reason, dimensions, tab: tab ?? undefined } as VercelFinding; });
  return { run_id: run.id, at: run.finished_at, findings: findings.sort((a, b) => order[a.severity] - order[b.severity]) };
}

/** The projects' names by id, for pages that show a finding's resource. */
export const projectNames = (): Map<string, string> => new Map(listProjects(true).map((p: ProjectRow) => [p.id, p.name]));

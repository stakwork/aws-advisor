import { config } from "../../config.js";
import { db } from "../../db.js";
import type { AccountRecord, ProviderAdapter, ResourceNode, TelemetryKind } from "../types.js";
import { VercelClient, requiresAuth } from "./client.js";
import { invoiceMonths, streamOf } from "./bill_months.js";
import { listDeployments, listDomains, listEnvNames, listInvoices, listProjects, listStores, refreshVercel, storeById, teamBilling, teamExtras, vercelTeam, type ProjectRow, type StoreRow } from "./inventory.js";
import { storeUsageSeries, usageByProject, usageSeries, usageTotals } from "./usage.js";
import { projectListCost, storeListCost, vercelRates } from "./pricing.js";
import { NeonClient, RedisCloudClient } from "./partners.js";
import type { PartnerClients } from "./inventory.js";
import * as rulesMod from "./rules.js";
import { vercelResourceIndex } from "./account_index.js";
import { vercelOnboarding } from "./onboarding.js";
const require_rules = () => rulesMod;

/** The partner clients the saved keys allow (Settings › Accounts › Vercel › Partners). */
export function partnerClients(): PartnerClients {
  return { neon: config.neonApiKey ? new NeonClient(config.neonApiKey) : null, redis: config.redisCloudApiKey && config.redisCloudSecretKey ? new RedisCloudClient(config.redisCloudApiKey, config.redisCloudSecretKey) : null };
}
export const partnersConfigured = () => ({ neon: Boolean(config.neonApiKey), redis: Boolean(config.redisCloudApiKey && config.redisCloudSecretKey) });

/**
 * The Vercel adapter: the first provider after AWS, and the proof the boundary holds. A team is the account
 * (`native_type: team`, a personal account is a team of one); a project is an `AdvisorDeployment`
 * (`native_type: vercel_project`) whose state is its latest production deployment; its production URL, deployment
 * URL and domains are `AdvisorEndpoint`s the project EXPOSES, each `REACHABLE_FROM internet` with `requires_auth`
 * from the project's deployment protection; the Node runtime is an `AdvisorPackage` INSTALLED_ON the project and the
 * framework a property. No probes, metrics, executor or benchmarks: the capabilities say so, and the pages that
 * need them stay empty for this provider. Credentials: a token (and optional team id) saved as runtime settings.
 */

export const VERCEL = "vercel";
export const VERCEL_TELEMETRY: Record<TelemetryKind, { native: string }> = { api: { native: "vercel_api" }, metrics: { native: "none" }, probe: { native: "none" }, logs: { native: "none" }, audit: { native: "none" }, bill: { native: "none" } };

export const vercelConfigured = (): boolean => Boolean(config.vercelToken);
export const vercelClient = (fetchImpl?: typeof fetch): VercelClient => new VercelClient({ token: config.vercelToken, teamId: config.vercelTeamId || null, fetchImpl });

const stateOf = (p: ProjectRow): { state: ResourceNode["state"]; native: string | null } => {
  // `live` on a project is Vercel's "live preview" feature flag, not a lifecycle: the latest deployment's state is the lifecycle
  const s = (p.latest_state || "").toUpperCase();
  if (s === "READY") return { state: "running", native: p.latest_state };
  if (s === "BUILDING" || s === "QUEUED" || s === "INITIALIZING") return { state: "pending", native: p.latest_state };
  if (s === "ERROR") return { state: "degraded", native: p.latest_state };
  if (s === "CANCELED") return { state: "stopped", native: p.latest_state };
  return { state: s ? "unknown" : "unknown", native: p.latest_state };
};

/** A project as the generic model: an AdvisorDeployment with the framework, runtime, repo, protection and latest deployment on it. */
export function resourceFromProject(p: ProjectRow, teamId: string, usage?: Map<string, { requests: number; invocations: number; bandwidth_out_gb: number; gb_hours: number; builds: number }>): ResourceNode {
  const st = stateOf(p);
  const u = usage?.get(p.id);
  const prod = requiresAuth(p, "production"); const prev = requiresAuth(p, "preview");
  return {
    id: p.id, label: "AdvisorDeployment", native_type: "vercel_project", name: p.name, state: st.state, native_state: st.native, region: null,
    role: null, role_confidence: null, protected_prob: null, monthly_usd: null, gone: p.gone, first_seen: p.first_seen, last_seen: p.last_seen, pool: null, pool_kind: null,
    props: { platform: "vercel", framework: p.framework, runtime: p.node_version ? `node ${p.node_version}` : null, repo: p.repo, git_provider: p.git_provider, production_url: p.production_url, latest_deployment: p.latest_id, latest_url: p.latest_url, latest_target: p.latest_target, deployed_at: p.latest_at,
      protection_sso: p.protection.sso, protection_password: p.protection.password, protection_trusted_ips: p.protection.trusted_ips, protection_production: prod.requires_auth, protection_previews: prev.requires_auth, firewall_enabled: p.firewall?.enabled ?? null, firewall_rules: p.firewall?.rules ?? null, env_vars: p.env_count, team_id: teamId, environment: "production",
      usage_requests_7d: u?.requests ?? null, usage_invocations_7d: u?.invocations ?? null, usage_bandwidth_out_gb_7d: u?.bandwidth_out_gb ?? null, usage_gb_hours_7d: u?.gb_hours ?? null, usage_builds_7d: u?.builds ?? null,
      secure_compute: p.connect.length > 0, secure_compute_security_groups: [...new Set(p.connect.map((c) => c.security_group).filter((x): x is string => Boolean(x)))], secure_compute_subnets: [...new Set(p.connect.flatMap((c) => c.subnets))], oidc_federation: p.oidc?.enabled ?? null, oidc_issuer_mode: p.oidc?.issuer_mode ?? null },
    observed: [{ kind: "api", status: p.gone ? "stale" : "ok", last_at: p.last_seen, detail: "vercel REST API" }],
  };
}

/** The id of the one machine a team's projects run on as far as the graph can tell: Vercel never shows it. */
export const runtimeBoxId = (teamId: string) => `${teamId}/runtime`;

/**
 * The team's runtime as an opaque AdvisorBox {kind: managed}: the functions and builds run on machines Vercel manages
 * and never shows, so the graph keeps one box per team (and its AdvisorCompute, opaque too) for the projects to
 * RUNS_ON (./graph.ts). It costs nothing apart from the projects, whose own bill carries the usage.
 */
export function runtimeBox(teamId: string, seen: { first: string | null; last: string | null; any: boolean }): ResourceNode {
  return {
    id: runtimeBoxId(teamId), label: "AdvisorBox", native_type: "vercel_runtime", name: "Vercel runtime", state: seen.any ? "running" : "unknown", native_state: null, region: null,
    role: null, role_confidence: null, protected_prob: null, monthly_usd: null, gone: false, first_seen: seen.first, last_seen: seen.last, pool: null, pool_kind: null,
    props: { kind: "managed", opaque: true, managed_by: "vercel", platform: "linux", team_id: teamId },
    compute: { platform: "linux", os: null, opaque: true, managed_by: "vercel" },
    observed: [{ kind: "api", status: "ok", last_at: seen.last, detail: "inferred: the projects run here; Vercel does not show the machines" }],
  };
}

/** A store as the generic model: a database (Neon, ...), a cache (Redis, KV) or object storage (Blob), with the plan and the projects on it. */
/** The graph id of a team member: the same `<team>/member/<username>` the member findings name. */
export const memberNodeId = (teamId: string, m: { username: string | null; uid: string }) => `${teamId}/member/${m.username ?? m.uid}`;

/**
 * A team member as an AdvisorIdentity {kind: team_member}: a person, MFA on the Vercel account, admin when an Owner, the
 * role, the GitHub login, when they joined. Their 2FA and the tokens of the member whose token the advisor uses are
 * AdvisorCredential nodes (src/graph_access.ts), not identities: a token is something a member holds, not an actor.
 */
export function identitiesOfTeam(teamId: string, extras: ReturnType<typeof teamExtras>): ResourceNode[] {
  const now = extras.read_at; const obs = [{ kind: "api" as const, status: "ok" as const, last_at: now, detail: "vercel REST API" }];
  const node = (id: string, name: string, native_type: string, state: "available" | "pending" | "stopped", props: Record<string, unknown>): ResourceNode => ({ id, label: "AdvisorIdentity", native_type, name, state, native_state: state, region: null, role: null, role_confidence: null, protected_prob: null, monthly_usd: null, gone: false, first_seen: now, last_seen: now, pool: null, pool_kind: null, props, observed: obs });
  const owner = extras.token_owner;
  const members = extras.members.map((m) => node(memberNodeId(teamId, m), m.username ?? m.uid, "team_member", m.confirmed ? "available" : "pending", {
    kind: "team_member", human: true, platform: "vercel", team_id: teamId, role: m.role, admin: /owner/i.test(m.role ?? ""), mfa: m.mfa, confirmed: m.confirmed, github: m.github, joined_at: m.joined_at, joined_from: m.joined_from ?? null, access_groups: m.access_groups ?? 0,
    credentials: owner && owner.uid === m.uid ? extras.tokens.length : null,
  }));
  return members;
}

export function resourceFromStore(st: StoreRow, teamId: string): ResourceNode {
  const label = st.kind === "database" ? "AdvisorDatabase" : st.kind === "cache" ? "AdvisorCache" : "AdvisorStorage";
  const engine = st.product_slug === "neon" ? "postgres" : st.product_slug;
  const d = st.details; const cost = storeListCost(teamId, st);
  const compute = d.usage_period?.items.find((u) => /compute/i.test(u.name)) ?? null;
  const meta = Object.fromEntries(Object.entries(d.metadata).map(([k, v]) => [k.toLowerCase(), v]));
  const partner = partnerProps(st);
  return {
    id: st.id, label, native_type: "vercel_store", name: st.name, state: st.status === "available" || st.status === "ready" ? "available" : st.gone ? "terminated" : "unknown", native_state: st.status, region: st.region,
    role: null, role_confidence: null, protected_prob: null, monthly_usd: cost.monthly_list_usd, gone: st.gone, first_seen: st.first_seen, last_seen: st.last_seen, pool: null, pool_kind: null,
    props: { platform: "vercel", store_type: st.type, product: st.product, engine, plan: st.plan, plan_id: d.plan_id, plan_lines: d.plan_lines.map((l) => `${l.label}: ${l.value}`), kind: st.kind, projects: st.projects.map((p) => p.name ?? p.project_id), team_id: teamId, created_at: st.created_at, updated_at: d.updated_at,
      billing_state: d.billing_state, quota_exceeded: d.quota_exceeded, external_id: d.external_id, external_status: d.external_status, access: d.access, token_expired: d.token_expired,
      size_gb: d.size_bytes != null ? Math.round((d.size_bytes / 1e9) * 100) / 100 : null, objects: d.object_count, high_availability: meta.highavailability ?? null, storage_type: meta.storagetype ?? null, auth: typeof meta.auth === "boolean" ? meta.auth : null,
      secret_names: d.secret_names.map((x) => x.name), capabilities: Object.entries(d.capabilities).filter(([, v]) => v).map(([k]) => k),
      // the partner's own numbers (when its key is saved) override what Vercel relays; the relayed compute hours stay under their own name
      compute_hours_period: compute?.period_value ?? null, compute_hours_relayed: compute?.period_value ?? null, usage_period_start: d.usage_period?.start ?? null, usage_period_end: d.usage_period?.end ?? null, usage_read_at: d.usage_period?.read_at ?? null, monthly_list_usd: cost.monthly_list_usd, ...partner },
    observed: [{ kind: "api", status: st.gone ? "stale" : "ok", last_at: st.last_seen, detail: "vercel REST API (storage)" }],
  };
}

const gb2 = (b: number | null | undefined) => (b == null ? null : Math.round((b / 1e9) * 100) / 100);
/** What the partner's own API adds to a store node: Neon's storage, branches, compute and consumption; Redis Cloud's memory, persistence, endpoint and source IPs. Flat, so a Cypher query reads it like any property. */
export function partnerProps(st: StoreRow): Record<string, unknown> {
  const snap = st.partner?.snapshot; if (!snap) return st.partner?.error ? { partner_error: st.partner.error, partner_read_at: st.partner.read_at } : {};
  if (snap.kind === "neon") {
    const p = snap.project; const rw = snap.endpoints.find((e) => e.type === "read_write") ?? snap.endpoints[0] ?? null;
    return { partner: "neon", partner_read_at: snap.read_at, pg_version: p.pg_version, neon_region: p.region, storage_gb: gb2(p.storage_bytes), branches: snap.branches.length, branches_protected: snap.branches.filter((b) => b.protected).length, databases: snap.databases.map((d) => d.name),
      compute_min_cu: rw?.min_cu ?? p.autoscaling_min_cu, compute_max_cu: rw?.max_cu ?? p.autoscaling_max_cu, suspend_timeout_s: rw?.suspend_timeout_seconds ?? p.suspend_timeout_seconds, endpoint_state: rw?.state ?? null, endpoint_host: rw?.host ?? null, endpoints: snap.endpoints.length, last_active: rw?.last_active ?? null,
      compute_hours_period: p.compute_time_seconds != null ? Math.round((p.compute_time_seconds / 3600) * 10) / 10 : null, active_hours_period: p.active_time_seconds != null ? Math.round((p.active_time_seconds / 3600) * 10) / 10 : null, written_gb_period: gb2(p.written_data_bytes), transfer_gb_period: gb2(p.data_transfer_bytes), storage_gb_hours_period: p.data_storage_bytes_hour != null ? Math.round(p.data_storage_bytes_hour / 1e9) : null, consumption_period_start: p.consumption_period_start,
      history_retention_days: p.history_retention_seconds != null ? Math.round((p.history_retention_seconds / 86_400) * 10) / 10 : null, ip_allow: p.ip_allow, ip_allow_protected_only: p.ip_allow_protected_only };
  }
  const d = snap.database; const used = d.memory_used_mb != null && d.memory_limit_mb ? Math.round((d.memory_used_mb / d.memory_limit_mb) * 1000) / 10 : null;
  return { partner: "redis_cloud", partner_read_at: snap.read_at, redis_version: d.redis_version, subscription: snap.subscription.name, subscription_kind: snap.subscription.kind, partner_status: d.status, memory_limit_mb: d.memory_limit_mb, memory_used_mb: d.memory_used_mb, memory_used_pct: used, memory_storage: d.memory_storage, persistence: d.persistence, replication: d.replication, eviction: d.eviction, throughput: d.throughput_value != null ? `${d.throughput_value} ${d.throughput_by ?? ""}`.trim() : null, public_endpoint: d.public_endpoint, private_endpoint: d.private_endpoint, tls: d.tls, ssl_client_auth: d.ssl_client_auth, source_ips: d.source_ips, default_user: d.default_user, modules: d.modules, clustering: d.clustering, partner_region: d.region, partner_provider: d.provider };
}

/** The network endpoints a store answers on, as the partner reports them: a Neon compute endpoint (Postgres over TLS, password, optionally an IP allow list) and a Redis Cloud public endpoint (password; its source IPs say who may connect). */
export function storeEndpoints(st: StoreRow): { id: string; resource_id: string; kind: "service_endpoint"; protocol: string; port: number; hostname: string; requires_auth: boolean; via: string; restricted_to: string[]; note: string }[] {
  const snap = st.partner?.snapshot; if (!snap) return [];
  if (snap.kind === "neon") return snap.endpoints.filter((e) => e.host && !e.disabled).map((e) => ({ id: `${st.id}:neon:${e.id}`, resource_id: st.id, kind: "service_endpoint" as const, protocol: "postgres", port: 5432, hostname: e.host!, requires_auth: true, via: "password", restricted_to: snap.project.ip_allow, note: `Neon ${e.type ?? "compute"} endpoint${e.pooler ? " (pooler)" : ""}, ${e.state ?? "state unknown"}; TLS, a password${snap.project.ip_allow.length ? `, and an IP allow list of ${snap.project.ip_allow.length} entr${snap.project.ip_allow.length === 1 ? "y" : "ies"}${snap.project.ip_allow_protected_only ? " (protected branches only)" : ""}` : "; no IP allow list: any address may try the password"}` }));
  const d = snap.database; if (!d.public_endpoint) return [];
  const [host, port] = d.public_endpoint.split(":"); const open = !d.source_ips.length || d.source_ips.some((ip) => /^0\.0\.0\.0\/0$|^::\/0$/.test(ip));
  return [{ id: `${st.id}:redis:public`, resource_id: st.id, kind: "service_endpoint" as const, protocol: "redis", port: Number(port) || 6379, hostname: host, requires_auth: true, via: d.default_user === false ? "acl user" : "password", restricted_to: open ? [] : d.source_ips, note: `Redis Cloud public endpoint${d.tls ? ", TLS" : ", no TLS"}, a password${open ? "; source IPs open to any address" : `; source IPs limited to ${d.source_ips.join(", ")}`}` }];
}

/** One store in full, for the inventory's detail panel: the object as Vercel describes it, the projects on it with the variables it injects, its usage and what it costs at its plan. */
export function storeDetail(id: string) {
  const st = storeById(id); if (!st) return null;
  const team = vercelTeam(); const teamId = team?.id ?? vercelAdapter.primaryAccountId();
  const node = resourceFromStore(st, teamId); const cost = storeListCost(teamId, st);
  const projects = st.projects.map((p) => { const row = listProjects().find((x) => x.id === p.project_id); return { ...p, framework: row?.framework ?? null, latest_state: row?.latest_state ?? null, production_url: row?.production_url ?? null }; });
  const rates = vercelRates(teamId).store_plans.find((sp) => sp.store_id === st.id) ?? null;
  return { ...st, node_props: node.props, state: node.state, projects, usage_series: st.type === "blob" ? storeUsageSeries(teamId, st.id, 30) : [], cost, plan_rates: rates, endpoints: storeEndpoints(st), partners_configured: partnersConfigured() };
}

export const vercelAdapter: ProviderAdapter = {
  id: VERCEL,
  label: "Vercel",
  flow: { boundary: "team", credentials: "a team access token with read scope (Account settings › Tokens); the team id for a team token, none for a personal account", children: "none: a team is a leaf; a personal account is a team of one" },
  // page gates as much as facts: no probes, metrics, executor, benchmarks, bill, clusters; its endpoints and runtime live in the graph, but the Network and Security pages are AWS-shaped
  capabilities: { probes: false, metrics: false, executor: false, compliance: false, cost: false, bill: true, findings: true, changes: true, alerts: true, clusters: false, software: false, network: false },
  storage: ["vercel_team", "vercel_projects", "vercel_deployments", "vercel_domains", "vercel_env", "vercel_stores", "vercel_invoices"],
  telemetry: VERCEL_TELEMETRY,
  configured: vercelConfigured,
  primaryAccountId: () => vercelTeam()?.id || config.vercelTeamId || "vercel",
  async accounts(): Promise<AccountRecord[]> {
    if (!vercelConfigured()) return [];
    const t = vercelTeam();
    return [{ provider: VERCEL, id: t?.id || config.vercelTeamId || "vercel", native_type: t?.personal ? "personal_account" : "team", name: t?.name || t?.slug || (config.vercelTeamId ? "team" : "personal account"), parent_id: null,
      access: `token ${config.vercelToken.slice(0, 4)}…${config.vercelTeamId ? ` for team ${config.vercelTeamId}` : ""}`, actuator: false, enabled: true,
      last_test: t ? { ok: true, detail: (t.plan ? `${t.plan} plan · ` : "") + `read ${t.fetched_at.slice(0, 16)}`, at: t.fetched_at } : { ok: false, detail: "not read yet", at: null } }];
  },
  async collect() {
    if (!vercelConfigured()) return { errors: ["Vercel is not configured"] };
    try { const r = await refreshVercel(vercelClient(), { partners: partnerClients() }); try { try { const { recordChanges } = await import("./changes.js"); const ch = recordChanges(r.team.id); if (ch.changes) console.log(`[vercel] ${ch.changes} change${ch.changes === 1 ? "" : "s"} since the previous collection`); } catch (e: any) { r.errors.push(`changes: ${String(e?.message || e).slice(0, 160)}`); }
      const { runVercelRules } = await import("./rules.js"); const rr = await runVercelRules(); console.log(`[vercel] rules pass #${rr.run_id}: ${rr.findings} findings (${rr.alarms} alarms or warnings), ${rr.recommendations} recommendations, ${rr.resolved} resolved`); try { const gm = await import("../../graph_mirror.js"); await gm.mirrorRun(rr.run_id); await gm.mirrorRecommendations(); } catch (e: any) { console.error(`[graph] vercel rules: ${e?.message || e}`); } } catch (e: any) { r.errors.push(`rules: ${String(e?.message || e).slice(0, 160)}`); } console.log(`[vercel] ${r.team.name ?? r.team.id}: ${r.projects} projects, ${r.deployments} deployments, ${r.domains} domains, ${r.env} env names, ${r.stores} stores in ${r.took_ms} ms${r.errors.length ? `; ${r.errors.length} errors` : ""}`); return { errors: r.errors }; }
    catch (e: any) { return { errors: [String(e?.message || e)] }; }
  },
  resources(account: string): ResourceNode[] {
    // exact per-project numbers where they were read, the breakdown estimate otherwise
    const usage = new Map(usageByProject(account, 7).map((u) => [u.project_id, u]));
    for (const p of listProjects(true)) { const t = usageTotals(account, 7, p.id); if (t.requests || t.invocations || t.builds) usage.set(p.id, { project_id: p.id, name: p.name, requests: t.requests, invocations: t.invocations, bandwidth_out_gb: t.bandwidth_out_gb, gb_hours: t.gb_hours, builds: t.builds }); }
    const projects = listProjects(true); const live = projects.filter((p) => !p.gone);
    const box = runtimeBox(account, { first: projects.map((p) => p.first_seen).filter((x): x is string => Boolean(x)).sort()[0] ?? null, last: live.map((p) => p.last_seen).filter((x): x is string => Boolean(x)).sort().pop() ?? null, any: live.length > 0 });
    return [...projects.map((p) => resourceFromProject(p, account, usage)), ...(projects.length ? [box] : []), ...listStores({ includeGone: true }).map((st) => resourceFromStore(st, account)), ...identitiesOfTeam(account, teamExtras(account))]; },
  resourceIds: (account) => new Set([account, runtimeBoxId(account), ...listProjects(true).map((p) => p.id), ...listStores({ includeGone: true }).map((s) => s.id)]),
  owns: (id) => id === vercelAdapter.primaryAccountId() || (vercelConfigured() && /^team_/.test(id)) || Boolean(db.prepare("select 1 from vercel_team where id = ?").get(id)),
  accountOf(resource, details) {
    const d = (details ?? {}) as Record<string, unknown>;
    if (typeof d.team_id === "string" && d.team_id) return d.team_id;
    return vercelResourceIndex().of(resource) ?? (typeof d.run_account_id === "string" ? d.run_account_id : null);
  },
  // its rules are its own code (./rules.ts), run after every collection: one runs row per pass, for the team
  rules: {
    latestRunId: (account) => (db.prepare("select id from runs where provider = 'vercel' and account_id = ? and status = 'completed' order by id desc limit 1").get(account ?? vercelAdapter.primaryAccountId()) as { id: number } | undefined)?.id,
    benchmarks: () => ({ all: [], defaults: [] }),
    start: async () => { const r = await require_rules().runVercelRules(); return { run_id: r.run_id, note: `${r.findings} findings` }; },
    run_native_type: "rules_pass",
    control_prefixes: ["vercel."],
    controlForRule: (rule) => (/^vercel_/.test(rule) ? rule.replace(/^vercel_/, "vercel.control.") : null),
    controlFacts: (controlId) => {
      const id = controlId.toLowerCase(); if (!id.startsWith("vercel.control.")) return null;
      return { framework: "advisor", category: /mfa|open|firewall|ip_allow|source_ips/.test(id) ? "security" : /suspend|branches|unconnected|cache_cold/.test(id) ? "cost" : "reliability" };
    },
    controlSources: () => require_rules().CONTROL_REFERENCES,
    playbooks_from: "all",
    seed_playbooks: false,
  },
  onboarding: vercelOnboarding,
  agentNote: () => { const t = vercelTeam(); return t ? `Vercel team ${t.name ?? t.slug ?? t.id} (${t.id}; vercel_projects, vercel_stores, vercel_bill, the vercel.* Steampipe tables, and graph_systems / graph_query with account_id '${t.id}')` : null; },
  routes: async () => [(await import("../../routes/vercel.js")).vercel],
  // the team's money is its invoices and the period estimate, read with every collection (./inventory.ts, ./pricing.ts)
  cost: {
    refresh: async () => ({ refreshed: false, note: "read with the Vercel collection" }),
    // last month's bill is every invoice issued in it: the subscription and the Marketplace bill separately (./bill_months.ts)
    lastBill: () => { const m = invoiceMonths(listInvoices(24) as any[], new Date().toISOString().slice(0, 10)); const last = m.months[0]; return last ? { month: last.month, usd: last.usd } : { month: null, usd: null }; },
    month: async () => {
      if (!vercelConfigured()) return [];
      const o = vercelOverview();
      // the month's invoices: issued, plus each regular one not issued yet (the stores bill through the Marketplace invoice, so they are in it)
      return [{ key: "month_projected", label: "Vercel this month", usd: o.billing?.this_month?.projected_usd ?? null, to_total: true, month_to_date_usd: o.billing?.this_month?.month_to_date_usd ?? null }];
    },
    // one team: the invoices issued this month, plus each regular stream not issued yet at its usual amount
    accounts: async () => {
      if (!vercelConfigured()) return [];
      const m = invoiceMonths(listInvoices(24) as any[], new Date().toISOString().slice(0, 10));
      const note = m.streams.map((x) => x.issued != null ? `${x.stream} ${Math.round(x.issued)} USD issued` : x.expected != null ? `${x.stream} expected ≈ ${Math.round(x.expected)} USD as its last invoice of ${x.from} (${x.breakdown.map((b) => `${b.name} ${Math.round(b.usd)}`).join(", ")})` : null).filter(Boolean).join(" · ");
      return [{ account: vercelAdapter.primaryAccountId(), month_to_date_usd: m.month_to_date, projected_usd: m.projected, last_month_usd: m.last_month_usd, last_month: m.last_month, history: m.months.slice(0, 6), note }];
    },
  },
  attention: async () => {
    if (!vercelConfigured()) return [];
    const team = vercelAdapter.primaryAccountId();
    return vercelOverview().attention.map((a) => ({ account: team, level: a.level as "alarm" | "warning" | "info", what: a.what, link: a.tab ? `/inventory?tab=${a.tab}` : "/findings" }));
  },
  purgeStorage(account, { dryRun }) {
    // the team's own tables (vercel_domains and vercel_env hang off a project), its team row and its cached billing
    const out: Record<string, number> = {};
    const count = (sql: string) => { try { return (db.prepare(sql.replace(/^delete/, "select count(*) as n")).get(account) as { n: number }).n; } catch { return 0; } };
    const run = (sql: string) => { try { return db.prepare(sql).run(account).changes; } catch { return 0; } };
    const stmts: [string, string][] = [["vercel_domains", "delete from vercel_domains where project_id in (select id from vercel_projects where team_id = ?)"], ["vercel_env", "delete from vercel_env where project_id in (select id from vercel_projects where team_id = ?)"],
      ...["vercel_projects", "vercel_stores", "vercel_usage", "vercel_invoices", "vercel_snapshots", "vercel_changes", "vercel_deployments"].map((t): [string, string] => [t, `delete from ${t} where team_id = ?`]), ["vercel_team", "delete from vercel_team where id = ?"]];
    for (const [t, sql] of stmts) { const n = dryRun ? count(sql) : run(sql); if (n) out[t] = n; }
    if (!dryRun) db.prepare("delete from settings where key in (?, ?)").run(`vercel_billing:${account}`, `vercel_extras:${account}`);
    return out;
  },
  // the Vercel connection for Steampipe follows the saved token (written on save, removed with the account; here after a restart)
  onStart() { import("./steampipe.js").then((m) => { const r = m.ensureVercelConnection(); if (r !== "skipped" && r !== "unchanged") console.log(`[vercel] steampipe connection ${r}`); }).catch((e) => console.error(`[vercel] steampipe connection: ${e?.message || e}`)); },
  jobs: [{
    key: "vercelCron", label: "Vercel collection", schedule_name: "Vercel collection (VERCEL_CRON)", tag: "vercel", cron: () => config.vercelCron,
    blocked: () => (vercelConfigured() ? null : "skipped: no Vercel token (Settings > Accounts)"),
    run: async () => {
      const r = await vercelAdapter.collect();
      try { const { mirrorAdapter } = await import("../../graph_mirror.js"); await mirrorAdapter(vercelAdapter); } catch (e: any) { console.error(`[graph] vercel: ${e?.message || e}`); }
      return r.errors.length ? `collected with ${r.errors.length} error(s): ${r.errors[0]}` : "collected and mirrored";
    },
  }],
  ui: {
    overview: "vercel.overview", bill: "vercel.bill", changes: "vercel.changes",
    inventory: [{ tab: "rds", view: "vercel.stores.database", label: "Vercel stores (Neon, …)" }, { tab: "elasticache", view: "vercel.stores.cache", label: "Vercel stores (Redis, KV)" }, { tab: "s3", view: "vercel.stores.storage", label: "Vercel Blob" },
      { tab: "deployments", view: "vercel.projects", label: "Vercel projects" }, { tab: "identities", view: "vercel.members", label: "Vercel team members" }],
    settings: [{ id: "access", label: "Access", view: "vercel.access" }, { id: "projects", label: "Projects", view: "vercel.projects" }, { id: "partners", label: "Partners", view: "vercel.partners" }],
  },
  layers: [
    { name: "vercel endpoints and runtimes", mirror: async () => (await import("./graph.js")).mirrorVercel() },
    { name: "vercel pricing knowledge and systems", mirror: async () => (await import("./pricing.js")).mirrorVercelPricing() },
    { name: "vercel log drains", mirror: async () => (await import("./logs.js")).mirrorVercelLogs() },
  ],
};

/** The endpoints a project exposes: its production URL, its latest deployment URL and every verified domain, with who may open each. */
export function projectEndpoints(p: ProjectRow): { id: string; project_id: string; kind: "url"; hostname: string; url: string; target: "production" | "preview"; requires_auth: boolean; via: string | null; domain: boolean }[] {
  const out: ReturnType<typeof projectEndpoints> = [];
  const push = (url: string | null, target: "production" | "preview", domain: boolean) => {
    if (!url) return; const host = url.replace(/^https?:\/\//, "").split("/")[0]; if (!host || out.some((e) => e.hostname === host)) return;
    const a = requiresAuth(p, target);
    out.push({ id: `${p.id}:url:${host}`, project_id: p.id, kind: "url", hostname: host, url: `https://${host}`, target, requires_auth: a.requires_auth, via: a.via, domain });
  };
  push(p.production_url, "production", false);
  for (const d of listDomains(p.id)) if (d.verified && !d.redirect) push(`https://${d.name}`, d.branch ? "preview" : "production", true);
  if (p.latest_url && p.latest_target !== "production") push(p.latest_url, "preview", false);
  else if (p.latest_url) push(p.latest_url, "production", false);
  return out;
}

export const vercelStats = () => ({ projects: (db.prepare("select count(*) as n from vercel_projects where gone = 0").get() as any)?.n ?? 0, team: vercelTeam() });

/** The team at a glance for the Overview page: health, exposure, data stores, activity, and what deserves attention. */
export function vercelOverview() {
  const team = vercelTeam(); const projects = listProjects(); const stores = listStores(); const deployments = listDeployments(undefined, 2000);
  const now = Date.now(); const day = 86_400_000;
  const since = (ms: number) => deployments.filter((d) => d.created_at && now - Date.parse(d.created_at) < ms);
  const eps = projects.flatMap((p) => projectEndpoints(p).map((e) => ({ ...e, project: p.name })));
  const domains = projects.flatMap((p) => listDomains(p.id).map((d) => ({ ...d, project: p.name })));
  const by = <T,>(items: T[], key: (x: T) => string | null) => { const m = new Map<string, number>(); for (const x of items) { const k = key(x) ?? "unknown"; m.set(k, (m.get(k) || 0) + 1); } return [...m].map(([name, n]) => ({ name, n })).sort((a, b) => b.n - a.n); };
  // the attention list is the latest rules pass (src/adapters/vercel/rules.ts): the same findings the Findings page and the recommendations come from
  const { latestVercelFindings } = require_rules();
  const latest = latestVercelFindings(team?.id ?? vercelAdapter.primaryAccountId());
  const attention = latest.findings.map((f) => ({ level: f.severity, what: `${f.resource_name && f.resource !== (team?.id ?? "") && !f.resource.includes("/member/") ? `${f.resource_name}: ` : ""}${f.reason}`, project: f.tab === "deployments" ? f.resource_name : undefined, tab: f.tab, control_id: f.control_id }));
  const extras = team ? teamExtras(team.id) : { members: [], log_drains: [], read_at: null };
  const noMfa = extras.members.filter((m) => m.confirmed && m.mfa === false);
  const failed7d = since(7 * day).filter((d) => (d.state || "").toUpperCase() === "ERROR");
  return {
    team, read_at: team?.fetched_at ?? null,
    projects: { total: projects.length, production_ready: projects.filter((p) => (p.latest_state || "").toUpperCase() === "READY").length, production_failed: projects.filter((p) => p.latest_target === "production" && (p.latest_state || "").toUpperCase() === "ERROR").length, frameworks: by(projects, (p) => p.framework), runtimes: by(projects, (p) => p.node_version && `node ${p.node_version}`) },
    deployments: { last_24h: since(day).length, last_7d: since(7 * day).length, failed_7d: failed7d.length, stored: deployments.length },
    exposure: { urls: eps.length, open: eps.filter((e) => !e.requires_auth).length, protected: eps.filter((e) => e.requires_auth).length, custom_domains: domains.filter((d) => !d.redirect).length, unverified_domains: domains.filter((d) => !d.verified).length, firewall_on: projects.filter((p) => p.firewall?.enabled).length, firewall_known: projects.filter((p) => p.firewall).length },
    stores: { total: stores.length, by_kind: by(stores, (s) => s.kind), by_product: by(stores, (s) => s.product), plans: by(stores.filter((s) => s.plan), (s) => `${s.product}: ${s.plan}`), unconnected: stores.filter((s) => !s.projects.length).length },
    env_names: projects.reduce((n, p) => n + (p.env_count || 0), 0),
    store_stats: storeStats(team?.id ?? vercelAdapter.primaryAccountId(), stores),
    team_people: { members: extras.members.length, owners: extras.members.filter((m) => /owner/i.test(m.role || "")).length, without_mfa: noMfa.length, unconfirmed: extras.members.filter((m) => !m.confirmed).length },
    log_drains: extras.log_drains.map((d) => ({ id: d.id, name: d.name, status: d.status, sources: d.sources, environments: d.environments, host: d.host, sampling_rate: d.sampling_rate, projects: d.project_ids.length ? d.project_ids.map((id) => projects.find((p) => p.id === id)?.name ?? id) : ["all projects"] })),
    billing: vercelBilling(team?.id ?? null),
    usage: team ? { last_7d: usageTotals(team.id, 7), last_30d: usageTotals(team.id, 30), series: usageSeries(team.id, 30), by_project: usageByProject(team.id, 7) } : null,
    attention, rules_run: { id: latest.run_id, at: latest.at },
  };
}

/** The stores in numbers: blob bytes and objects, marketplace compute hours this period, what they cost at their plans. */
export function storeStats(teamId: string, stores: StoreRow[]) {
  const blob = stores.filter((s) => s.type === "blob");
  const costed = stores.map((s) => ({ store: s, cost: storeListCost(teamId, s) }));
  const compute = stores.map((s) => ({ name: s.name, hours: s.details.usage_period?.items.find((u) => /compute/i.test(u.name))?.period_value ?? null, start: s.details.usage_period?.start ?? null })).filter((x) => x.hours != null);
  return {
    blob_gb: Math.round((blob.reduce((n, s) => n + (s.details.size_bytes || 0), 0) / 1e9) * 100) / 100, blob_objects: blob.reduce((n, s) => n + (s.details.object_count || 0), 0),
    compute_hours_period: compute.length ? Math.round(compute.reduce((n, x) => n + (x.hours || 0), 0) * 10) / 10 : null, compute_by_store: compute.sort((a, b) => (b.hours || 0) - (a.hours || 0)).map((x) => ({ name: x.name, hours: Math.round((x.hours || 0) * 10) / 10 })), period_start: compute[0]?.start ?? null,
    monthly_list_usd: costed.some((c) => c.cost.monthly_list_usd != null) ? Math.round(costed.reduce((n, c) => n + (c.cost.monthly_list_usd || 0), 0) * 100) / 100 : null,
    token_expired: blob.filter((s) => s.details.token_expired).length, quota_exceeded: stores.filter((s) => s.details.quota_exceeded).length,
  };
}

/** The team's money: the subscription (plan, seats, period), the recent invoices and what the last one was made of. */
export function vercelBilling(teamId: string | null) {
  const b = teamId ? teamBilling(teamId) : null; const invoices = listInvoices(24);
  const last = invoices[0] ?? null;
  // by month: Vercel bills the subscription on its cycle day and the Marketplace on the 1st, so a month is every invoice issued in it (./bill_months.ts)
  const m = invoiceMonths(invoices as any[], new Date().toISOString().slice(0, 10));
  const last3 = m.months.slice(0, 3);
  return {
    plan: b?.plan ?? null, status: b?.status ?? null, currency: b?.currency ?? "usd", period_start: b?.period_start ?? null, period_end: b?.period_end ?? null,
    seats: b?.seats ?? null, seat_usd: b?.seat_usd ?? null, seats_usd_month: b?.seats != null && b?.seat_usd != null ? b.seats * b.seat_usd : null,
    last_invoice: last ? { number: last.number, status: last.status, total: last.total, created_at: last.created_at, period_start: last.period_start, period_end: last.period_end, hosted_url: last.hosted_url, groups: last.groups, top_items: last.line_items.slice(0, 8), kind: streamOf(last as any) } : null,
    /** the average of the last three complete months, every invoice of each */
    avg_last_3_usd: last3.length ? Math.round((last3.reduce((n, x) => n + x.usd, 0) / last3.length) * 100) / 100 : null,
    last_month: m.last_month, last_month_usd: m.last_month_usd,
    /** this month: what is issued, and the projection (each regular stream not issued yet at its last invoice) */
    this_month: { month_to_date_usd: m.month_to_date, projected_usd: m.projected, streams: m.streams },
    estimated_period_usd: m.projected,
    months: m.by_month.slice(0, 12),
    invoices: invoices.map((i) => ({ number: i.number, status: i.status, total: i.total, created_at: i.created_at, hosted_url: i.hosted_url, kind: streamOf(i as any) })),
  };
}

/** One project in full, for the inventory's detail panel. */
export function projectDetail(id: string) {
  const p = listProjects(true).find((x) => x.id === id); if (!p) return null;
  const team = vercelTeam(); const teamId = team?.id ?? vercelAdapter.primaryAccountId();
  const drains = teamExtras(teamId).log_drains.filter((d) => !d.project_ids.length || d.project_ids.includes(p.id));
  return { ...p, endpoints: projectEndpoints(p), domains: listDomains(p.id), deployments: listDeployments(p.id, 30), env_names: listEnvNames(p.id).map((e) => ({ key: e.key, targets: e.targets, type: e.type, updated_at: e.updated_at })), stores: listStores({ projectId: p.id }),
    log_drains: drains, list_cost: projectListCost(teamId, p.id),
    usage: { last_7d: usageTotals(teamId, 7, p.id), last_30d: usageTotals(teamId, 30, p.id), series: usageSeries(teamId, 30, p.id) } };
}

/** The team's bill: the subscription and period, what the metered usage did so far this period, the invoices with their lines. */
export function vercelBill() {
  const team = vercelTeam(); const teamId = team?.id ?? vercelAdapter.primaryAccountId();
  const billing = vercelBilling(teamId);
  const since = billing.period_start ? String(billing.period_start).slice(0, 10) : undefined;
  const period = { totals: usageTotals(teamId, 60, "", since), series: usageSeries(teamId, 60, "", since), by_project: usageByProject(teamId, 60, since), days_elapsed: billing.period_start ? Math.max(1, Math.round((Date.now() - Date.parse(billing.period_start)) / 86_400_000)) : null, days_total: billing.period_start && billing.period_end ? Math.round((Date.parse(billing.period_end) - Date.parse(billing.period_start)) / 86_400_000) : null };
  const invoices = listInvoices(24).map((i) => ({ id: i.id, number: i.number, status: i.status, total: i.total, subtotal: i.subtotal, tax: i.tax, created_at: i.created_at, period_start: i.period_start, period_end: i.period_end, hosted_url: i.hosted_url, pdf_url: i.pdf_url, groups: i.groups, line_items: i.line_items, kind: streamOf(i as any) }));
  // what the last paid invoice charged per unit, by line title: the only rates that are the team's own (the catalogue rates are list)
  const last = invoices.find((i) => i.status === "paid");
  const unit = last ? last.line_items.filter((l) => l.quantity && l.amount).map((l) => ({ title: l.title, unit_usd: Math.round((l.amount / (l.quantity || 1)) * 1e6) / 1e6, quantity: l.quantity, amount: l.amount })) : [];
  return { team, billing, period, invoices, unit_prices: unit, rates: vercelRates(teamId) };
}

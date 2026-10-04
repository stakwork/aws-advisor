import { db } from "../../db.js";
import { refreshUsage } from "./usage.js";
import type { NeonClient, PartnerRecord, RedisCloudClient } from "./partners.js";

/** The partner clients a refresh may use, built from the saved keys by the adapter; either may be missing. */
export interface PartnerClients { neon?: NeonClient | null; redis?: RedisCloudClient | null }

/** What Neon and Redis Cloud say about the stores whose keys are saved: one record per store, errors as words for the refresh result. */
export async function readPartners(stores: VercelStore[], clients: PartnerClients = {}): Promise<{ records: Map<string, PartnerRecord>; errors: string[] }> {
  const records = new Map<string, PartnerRecord>(); const errors: string[] = []; const now = new Date().toISOString();
  if (clients.neon) for (const st of stores.filter((x) => x.product_slug === "neon" && x.details.external_id)) {
    try { records.set(st.id, { snapshot: await clients.neon.snapshot(st.details.external_id!), error: null, read_at: now }); }
    catch (e: any) { const msg = String(e?.message || e).slice(0, 160); records.set(st.id, { snapshot: null, error: msg, read_at: now }); errors.push(`neon ${st.name}: ${msg}`); }
  }
  if (clients.redis) {
    const redisStores = stores.filter((x) => /redis/i.test(x.product_slug || x.type));
    if (redisStores.length) {
      try {
        for (const st of redisStores) { const snap = await clients.redis.find(st.name); records.set(st.id, { snapshot: snap, error: snap ? null : "no database with this name on the Redis Cloud account", read_at: now }); }
      } catch (e: any) { const msg = String(e?.message || e).slice(0, 160); for (const st of redisStores) records.set(st.id, { snapshot: null, error: msg, read_at: now }); errors.push(`redis cloud: ${msg}`); }
    }
  }
  return { records, errors };
}
import type { VercelClient, VercelDeployment, VercelDomain, VercelEnv, VercelFirewall, VercelInvoice, VercelLogDrain, VercelMember, VercelProject, VercelStore, VercelTeam, VercelTeamBilling } from "./client.js";

/**
 * The Vercel adapter's storage: the team, its projects with their protection and framework, the recent deployments,
 * the domains, the environment variable names (never values) and the firewall state. Refreshed by `refreshVercel`;
 * rows that disappear are marked gone, as the AWS inventories do.
 */

db.exec(`create table if not exists vercel_team (id text primary key, slug text, name text, plan text, personal integer not null default 0, fetched_at text not null);
create table if not exists vercel_invoices (
  id text primary key, team_id text not null, number text, status text, total real, subtotal real, tax real, currency text, created_at text, issued_at text, paid_at text, period_start text, period_end text, source text, hosted_url text, pdf_url text,
  groups text not null default '[]', line_items text not null default '[]', fetched_at text not null
);
create table if not exists vercel_projects (
  id text primary key, team_id text not null, name text not null, framework text, node_version text, created_at text, updated_at text, repo text, git_provider text, production_url text,
  latest_id text, latest_url text, latest_state text, latest_target text, latest_at text, protection text not null default '{}', live integer not null default 1,
  env_count integer not null default 0, firewall text, connect text not null default '[]', first_seen text not null, last_seen text not null, gone integer not null default 0
);
create table if not exists vercel_deployments (
  id text primary key, team_id text not null, project_id text, name text, url text, state text, target text, created_at text, ready_at text, source text, branch text, commit_sha text, first_seen text not null, last_seen text not null, gone integer not null default 0
);
create index if not exists vercel_deployments_project on vercel_deployments(project_id, created_at);
create table if not exists vercel_domains (
  project_id text not null, name text not null, apex text, verified integer not null default 0, redirect text, branch text, created_at text, first_seen text not null, last_seen text not null, gone integer not null default 0,
  primary key (project_id, name)
);
create table if not exists vercel_stores (
  id text primary key, team_id text not null, name text not null, type text not null, kind text not null, product text, product_slug text, status text, plan text, region text, created_at text, projects text not null default '[]',
  first_seen text not null, last_seen text not null, gone integer not null default 0
);
create table if not exists vercel_env (
  project_id text not null, key text not null, targets text not null default '[]', type text, updated_at text, first_seen text not null, last_seen text not null, gone integer not null default 0,
  primary key (project_id, key)
)`);
if (!(db.prepare("pragma table_info(vercel_stores)").all() as { name: string }[]).some((c) => c.name === "details")) db.exec("alter table vercel_stores add column details text not null default '{}'");
if (!(db.prepare("pragma table_info(vercel_stores)").all() as { name: string }[]).some((c) => c.name === "partner")) db.exec("alter table vercel_stores add column partner text");

if (!(db.prepare("pragma table_info(vercel_projects)").all() as { name: string }[]).some((c) => c.name === "connect")) db.exec("alter table vercel_projects add column connect text not null default '[]'");

export interface VercelRefreshResult { team: VercelTeam; projects: number; deployments: number; domains: number; env: number; stores: number; invoices: number; members: number; log_drains: number; usage: { types: number; days: number; projects: number }; errors: string[]; took_ms: number }

/** Reads the team, every project with its domains, env names, firewall and recent deployments; stores it all. */
export async function refreshVercel(client: VercelClient, opts: { deploymentsPerProject?: number; partners?: PartnerClients } = {}): Promise<VercelRefreshResult> {
  const t0 = Date.now(); const now = new Date().toISOString(); const errors: string[] = [];
  const team = await client.whoami();
  const projects = await client.projects();
  const per = opts.deploymentsPerProject ?? 20;
  const deployments: VercelDeployment[] = []; const domains: VercelDomain[] = []; const env: VercelEnv[] = []; const firewalls = new Map<string, VercelFirewall | null>(); const envCount = new Map<string, number>();
  for (const p of projects) {
    try { deployments.push(...(await client.deployments(p.id, per))); } catch (e: any) { errors.push(`${p.name} deployments: ${String(e?.message || e).slice(0, 160)}`); }
    try { domains.push(...(await client.domains(p.id))); } catch (e: any) { errors.push(`${p.name} domains: ${String(e?.message || e).slice(0, 160)}`); }
    try { const e = await client.env(p.id); env.push(...e); envCount.set(p.id, e.length); } catch (e: any) { errors.push(`${p.name} env: ${String(e?.message || e).slice(0, 160)}`); }
    firewalls.set(p.id, await client.firewall(p.id));
  }
  const stores = await client.stores();
  const invoices = await client.invoices(12);
  const members = await client.members(); const drains = await client.logDrains();
  const partners = await readPartners(stores, opts.partners); for (const e of partners.errors) errors.push(e);
  let usage = { types: 0, days: 0, projects: 0 }; try { usage = await refreshUsage(client, team.id, projects.map((p) => p.id)); } catch (e: any) { errors.push(`usage: ${String(e?.message || e).slice(0, 160)}`); }
  db.transaction(() => {
    db.prepare("insert into vercel_team(id, slug, name, plan, personal, fetched_at) values (?, ?, ?, ?, ?, ?) on conflict(id) do update set slug = excluded.slug, name = excluded.name, plan = excluded.plan, personal = excluded.personal, fetched_at = excluded.fetched_at").run(team.id, team.slug, team.name, team.plan, team.personal ? 1 : 0, now);
    const upP = db.prepare(`insert into vercel_projects(id, team_id, name, framework, node_version, created_at, updated_at, repo, git_provider, production_url, latest_id, latest_url, latest_state, latest_target, latest_at, protection, live, env_count, firewall, connect, first_seen, last_seen, gone)
      values (@id, @team_id, @name, @framework, @node_version, @created_at, @updated_at, @repo, @git_provider, @production_url, @latest_id, @latest_url, @latest_state, @latest_target, @latest_at, @protection, @live, @env_count, @firewall, @connect, @now, @now, 0)
      on conflict(id) do update set team_id = excluded.team_id, name = excluded.name, framework = excluded.framework, node_version = excluded.node_version, created_at = excluded.created_at, updated_at = excluded.updated_at, repo = excluded.repo, git_provider = excluded.git_provider, production_url = excluded.production_url,
      latest_id = excluded.latest_id, latest_url = excluded.latest_url, latest_state = excluded.latest_state, latest_target = excluded.latest_target, latest_at = excluded.latest_at, protection = excluded.protection, live = excluded.live, env_count = excluded.env_count, firewall = excluded.firewall, connect = excluded.connect, last_seen = excluded.last_seen, gone = 0`);
    for (const p of projects) upP.run({ id: p.id, team_id: team.id, name: p.name, framework: p.framework, node_version: p.node_version, created_at: p.created_at, updated_at: p.updated_at, repo: p.repo, git_provider: p.git_provider, production_url: p.production_url, latest_id: p.latest?.id ?? null, latest_url: p.latest?.url ?? null, latest_state: p.latest?.state ?? null, latest_target: p.latest?.target ?? null, latest_at: p.latest?.created_at ?? null, protection: JSON.stringify(p.protection), live: p.live ? 1 : 0, env_count: envCount.get(p.id) ?? 0, firewall: firewalls.get(p.id) ? JSON.stringify(firewalls.get(p.id)) : null, connect: JSON.stringify(p.connect ?? []), now });
    if (projects.length) db.prepare(`update vercel_projects set gone = 1 where team_id = ? and id not in (${projects.map(() => "?").join(",")})`).run(team.id, ...projects.map((p) => p.id));
    const upD = db.prepare(`insert into vercel_deployments(id, team_id, project_id, name, url, state, target, created_at, ready_at, source, branch, commit_sha, first_seen, last_seen, gone) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
      on conflict(id) do update set state = excluded.state, target = excluded.target, ready_at = excluded.ready_at, url = excluded.url, last_seen = excluded.last_seen, gone = 0`);
    for (const d of deployments) upD.run(d.id, team.id, d.project_id, d.name, d.url, d.state, d.target, d.created_at, d.ready_at, d.source, d.branch, d.commit, now, now);
    const upDom = db.prepare("insert into vercel_domains(project_id, name, apex, verified, redirect, branch, created_at, first_seen, last_seen, gone) values (?, ?, ?, ?, ?, ?, ?, ?, ?, 0) on conflict(project_id, name) do update set apex = excluded.apex, verified = excluded.verified, redirect = excluded.redirect, branch = excluded.branch, last_seen = excluded.last_seen, gone = 0");
    for (const d of domains) upDom.run(d.project_id, d.name, d.apex, d.verified ? 1 : 0, d.redirect, d.branch, d.created_at, now, now);
    db.prepare("update vercel_domains set gone = 1 where last_seen < ? and project_id in (select id from vercel_projects where team_id = ?)").run(now, team.id);
    const upE = db.prepare("insert into vercel_env(project_id, key, targets, type, updated_at, first_seen, last_seen, gone) values (?, ?, ?, ?, ?, ?, ?, 0) on conflict(project_id, key) do update set targets = excluded.targets, type = excluded.type, updated_at = excluded.updated_at, last_seen = excluded.last_seen, gone = 0");
    for (const e of env) upE.run(e.project_id, e.key, JSON.stringify(e.targets), e.type, e.updated_at, now, now);
    db.prepare("update vercel_env set gone = 1 where last_seen < ? and project_id in (select id from vercel_projects where team_id = ?)").run(now, team.id);
    const upS = db.prepare(`insert into vercel_stores(id, team_id, name, type, kind, product, product_slug, status, plan, region, created_at, projects, details, first_seen, last_seen, gone) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
      on conflict(id) do update set name = excluded.name, type = excluded.type, kind = excluded.kind, product = excluded.product, product_slug = excluded.product_slug, status = excluded.status, plan = excluded.plan, region = excluded.region, projects = excluded.projects, details = excluded.details, last_seen = excluded.last_seen, gone = 0`);
    for (const st of stores) upS.run(st.id, team.id, st.name, st.type, st.kind, st.product, st.product_slug, st.status, st.plan, st.region, st.created_at, JSON.stringify(st.projects), JSON.stringify(st.details), now, now);
    const upPartner = db.prepare("update vercel_stores set partner = ? where id = ?");
    for (const [id, rec] of partners.records) upPartner.run(JSON.stringify(rec), id);
    db.prepare("insert or replace into settings(key, value) values (?, ?)").run(`vercel_extras:${team.id}`, JSON.stringify({ members, log_drains: drains, read_at: now }));
    db.prepare("update vercel_stores set gone = 1 where team_id = ? and last_seen < ?").run(team.id, now);
    if (team.billing) db.prepare("insert or replace into settings(key, value) values (?, ?)").run(`vercel_billing:${team.id}`, JSON.stringify(team.billing));
    const upI = db.prepare(`insert into vercel_invoices(id, team_id, number, status, total, subtotal, tax, currency, created_at, issued_at, paid_at, period_start, period_end, source, hosted_url, pdf_url, groups, line_items, fetched_at) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      on conflict(id) do update set status = excluded.status, total = excluded.total, subtotal = excluded.subtotal, tax = excluded.tax, paid_at = excluded.paid_at, hosted_url = excluded.hosted_url, pdf_url = excluded.pdf_url, groups = excluded.groups, line_items = excluded.line_items, fetched_at = excluded.fetched_at`);
    for (const i of invoices) upI.run(i.id, team.id, i.number, i.status, i.total, i.subtotal, i.tax, i.currency, i.created_at, i.issued_at, i.paid_at, i.period_start, i.period_end, i.source, i.hosted_url, i.pdf_url, JSON.stringify(i.groups), JSON.stringify(i.line_items), now);
  })();
  return { team, projects: projects.length, deployments: deployments.length, domains: domains.length, env: env.length, stores: stores.length, invoices: invoices.length, members: members.length, log_drains: drains.length, usage, errors, took_ms: Date.now() - t0 };
}

const parse = <T,>(s: unknown, d: T): T => { if (typeof s !== "string") return d; try { return JSON.parse(s) as T; } catch { return d; } };
export interface ProjectRow { id: string; team_id: string; name: string; framework: string | null; node_version: string | null; created_at: string | null; updated_at: string | null; repo: string | null; git_provider: string | null; production_url: string | null; latest_id: string | null; latest_url: string | null; latest_state: string | null; latest_target: string | null; latest_at: string | null; protection: VercelProject["protection"]; live: boolean; env_count: number; firewall: VercelFirewall | null; connect: VercelProject["connect"]; first_seen: string; last_seen: string; gone: boolean }

export const vercelTeam = (): (VercelTeam & { fetched_at: string }) | null => { const r = db.prepare("select * from vercel_team order by fetched_at desc limit 1").get() as any; return r ? { id: r.id, slug: r.slug, name: r.name, plan: r.plan, personal: Boolean(r.personal), fetched_at: r.fetched_at } : null; };
export const listProjects = (includeGone = false): ProjectRow[] => (db.prepare(`select * from vercel_projects where 1 = 1${includeGone ? "" : " and gone = 0"} order by name`).all() as any[]).map((r) => ({ ...r, protection: parse(r.protection, { sso: null, password: null, trusted_ips: null, bypass_automation: false }), live: Boolean(r.live), firewall: parse(r.firewall, null), connect: parse<VercelProject["connect"]>(r.connect, []), gone: Boolean(r.gone) }));
export const listDomains = (projectId?: string): (VercelDomain & { gone: boolean })[] => (db.prepare(`select * from vercel_domains where gone = 0${projectId ? " and project_id = ?" : ""} order by name`).all(...(projectId ? [projectId] : [])) as any[]).map((r) => ({ ...r, verified: Boolean(r.verified), gone: Boolean(r.gone) }));
export const listDeployments = (projectId?: string, limit = 50): (VercelDeployment & { commit_sha?: string | null })[] => db.prepare(`select * from vercel_deployments where gone = 0${projectId ? " and project_id = ?" : ""} order by created_at desc limit ?`).all(...(projectId ? [projectId, limit] : [limit])) as any[];
export const listEnvNames = (projectId: string): VercelEnv[] => (db.prepare("select * from vercel_env where gone = 0 and project_id = ? order by key").all(projectId) as any[]).map((r) => ({ ...r, targets: parse<string[]>(r.targets, []) }));
export interface StoreRow extends VercelStore { team_id: string; first_seen: string; last_seen: string; gone: boolean; partner: PartnerRecord | null }
export const listStores = (opts: { projectId?: string; kind?: string; includeGone?: boolean } = {}): StoreRow[] => (db.prepare(`select * from vercel_stores where 1 = 1${opts.includeGone ? "" : " and gone = 0"}${opts.kind ? " and kind = ?" : ""} order by kind, name`).all(...(opts.kind ? [opts.kind] : [])) as any[])
  .map((r) => ({ ...r, projects: parse<VercelStore["projects"]>(r.projects, []).map((p) => ({ ...p, env_var_names: p.env_var_names ?? [], env_var_prefix: p.env_var_prefix ?? null })), details: { ...EMPTY_DETAILS, ...parse<Partial<VercelStore["details"]>>(r.details, {}) }, partner: parse<PartnerRecord | null>(r.partner, null), gone: Boolean(r.gone) })).filter((r) => !opts.projectId || r.projects.some((p: { project_id: string }) => p.project_id === opts.projectId));
export const storeById = (id: string): StoreRow | null => listStores({ includeGone: true }).find((s) => s.id === id) ?? null;
const EMPTY_DETAILS: VercelStore["details"] = { billing_state: null, quota_exceeded: false, ownership: null, updated_at: null, connected_projects: null, size_bytes: null, object_count: null, access: null, token_expired: null, external_id: null, external_status: null, plan_id: null, plan_scope: null, plan_type: null, plan_description: null, plan_cost: null, plan_lines: [], metadata: {}, secret_names: [], capabilities: {}, product_tags: [], product_description: null, usage_period: null };
/** The team's members and log drains as the last collection read them. */
export const teamExtras = (teamId: string): { members: VercelMember[]; log_drains: VercelLogDrain[]; read_at: string | null } => { const r = db.prepare("select value from settings where key = ?").get(`vercel_extras:${teamId}`) as { value: string } | undefined; return r ? { members: [], log_drains: [], read_at: null, ...parse<any>(r.value, {}) } : { members: [], log_drains: [], read_at: null }; };
export const teamBilling = (teamId: string): VercelTeamBilling | null => { const r = db.prepare("select value from settings where key = ?").get(`vercel_billing:${teamId}`) as { value: string } | undefined; return r ? parse<VercelTeamBilling | null>(r.value, null) : null; };
export const listInvoices = (limit = 12): VercelInvoice[] => (db.prepare("select * from vercel_invoices order by created_at desc limit ?").all(limit) as any[]).map((r) => ({ ...r, groups: parse(r.groups, []), line_items: parse(r.line_items, []) }));
export const wipeVercel = (): void => { db.transaction(() => { for (const t of ["vercel_env", "vercel_domains", "vercel_deployments", "vercel_stores", "vercel_invoices", "vercel_usage", "vercel_projects", "vercel_team"]) db.prepare(`delete from ${t}`).run(); db.prepare("delete from settings where key like 'vercel_billing:%' or key like 'vercel_extras:%'").run(); })(); };

import { addColumn, db } from "../../db.js";
import type { GitHubAuditEvent, GitHubClient, GitHubCopilot, GitHubInvitation, GitHubOrg, GitHubRepo, GitHubSecret, GitHubUser } from "./client.js";
import type { GitHubSql } from "./sql.js";

/**
 * The GitHub adapter's storage: the org, its people (members and outside collaborators, with 2FA and public profile),
 * teams, repositories and who has access to each, the credentials that reach it (deploy keys, fine-grained tokens and
 * their requests, SAML-authorized classic tokens and SSH keys, members' public SSH keys), installed Apps, secret names,
 * webhooks, Copilot seats, the metered bill and the audit log. Refreshed by `refreshGitHub`, one section at a time:
 * a section GitHub refuses (a permission the App lacks, a feature that is off) is recorded with its status and leaves
 * its rows as they were; rows a section no longer returns are marked gone, as the AWS inventories do.
 */

db.exec(`create table if not exists github_org (id text primary key, login text not null, name text, plan text, seats integer, filled_seats integer, details text not null default '{}', fetched_at text not null);
create table if not exists github_members (
  org_id text not null, login text not null, kind text not null, user_id integer, role text, name text, email_key text, company text, created_at text, mfa integer,
  first_seen text not null, last_seen text not null, gone integer not null default 0, primary key (org_id, login)
);
create table if not exists github_teams (org_id text not null, slug text not null, name text not null, privacy text, parent text, members text not null default '[]', repos text not null default '[]', first_seen text not null, last_seen text not null, gone integer not null default 0, primary key (org_id, slug));
create table if not exists github_repos (
  org_id text not null, full_name text not null, node_id text, private integer not null default 1, visibility text, archived integer not null default 0, fork integer not null default 0, default_branch text, pushed_at text, created_at text, html_url text,
  first_seen text not null, last_seen text not null, gone integer not null default 0, primary key (org_id, full_name)
);
create table if not exists github_repo_access (org_id text not null, repo text not null, login text not null, permission text, role_name text, first_seen text not null, last_seen text not null, gone integer not null default 0, primary key (org_id, repo, login));
create table if not exists github_credentials (
  org_id text not null, id text not null, kind text not null, holder text, name text, fingerprint text, created_at text, last_used_at text, expires_at text, details text not null default '{}',
  first_seen text not null, last_seen text not null, gone integer not null default 0, primary key (org_id, id)
);
create table if not exists github_apps (org_id text not null, id integer not null, app_slug text not null, repository_selection text, permissions text not null default '{}', events text not null default '[]', created_at text, updated_at text, suspended_at text, first_seen text not null, last_seen text not null, gone integer not null default 0, primary key (org_id, id));
create table if not exists github_secrets (org_id text not null, id text not null, scope text not null, kind text not null, repo text, environment text, name text not null, visibility text, selected_repos text not null default '[]', created_at text, updated_at text, first_seen text not null, last_seen text not null, gone integer not null default 0, primary key (org_id, id));
create table if not exists github_hooks (org_id text not null, id integer not null, repo text, name text, active integer not null default 1, events text not null default '[]', host text, insecure_ssl integer not null default 0, created_at text, updated_at text, first_seen text not null, last_seen text not null, gone integer not null default 0, primary key (org_id, id));
create table if not exists github_copilot_seats (org_id text not null, login text not null, plan_type text, created_at text, last_activity_at text, last_activity_editor text, pending_cancellation_date text, team text, first_seen text not null, last_seen text not null, gone integer not null default 0, primary key (org_id, login));
create table if not exists github_usage (org_id text not null, date text not null, product text not null, sku text not null, repo text not null default '', quantity real not null default 0, unit text, price_per_unit real, gross_usd real not null default 0, discount_usd real not null default 0, net_usd real not null default 0, fetched_at text not null, primary key (org_id, date, product, sku, repo));
create table if not exists github_audit (org_id text not null, id text not null, at text not null, action text not null, actor text, user text, repo text, team text, ip text, country text, user_agent text, access_type text, hashed_token text, token_id integer, operation text, primary key (org_id, id));
create index if not exists github_audit_actor on github_audit(org_id, actor, at);`);
// the SAML identity's name id or e-mail, reduced to a match key (the address itself is not kept)
addColumn("github_members", "saml_key", "text");
// when each repository's access, keys, secrets and webhooks were last read (a repository nothing touched is not read again)
addColumn("github_repos", "detail_at", "text");
// the last answer of each GET, for conditional requests (a 304 is free): ETag, body, next-page link
db.exec("create table if not exists github_http_cache (url text primary key, etag text not null, body text not null, next text, fetched_at text not null)");

/** The client's conditional-request store, in SQLite (./client.ts GitHubHttpCache). */
export const sqliteHttpCache = {
  get: (url: string) => (db.prepare("select etag, body, next from github_http_cache where url = ?").get(url) as { etag: string; body: string; next: string | null } | undefined) ?? null,
  set: (url: string, v: { etag: string; body: string; next: string | null }) => { db.prepare("insert into github_http_cache(url, etag, body, next, fetched_at) values (?, ?, ?, ?, ?) on conflict(url) do update set etag = excluded.etag, body = excluded.body, next = excluded.next, fetched_at = excluded.fetched_at").run(url, v.etag, v.body, v.next, new Date().toISOString()); },
};

/**
 * Audit log actions that change what the advisor reads per repository: its collaborators and team access, deploy
 * keys, secrets, environments, webhooks, visibility. A repository named by one of them since its last read is read
 * again; the others keep their stored rows until the daily full sweep. Pure.
 */
export const REPO_CHANGE_ACTION = /^(repo\.|team\.(add|remove|update)_repository|team\.update_repository_permission|public_key\.|deploy_key\.|repository_secret\.|environment\.|environment_secret\.|hook\.|org\.(add|remove)_outside_collaborator|org_credential_authorization\.|integration_installation\.repositories_)/;
export function reposToRead(opts: { repos: { full_name: string; archived: boolean }[]; known: Map<string, string | null>; changed: Set<string>; full: boolean }): Set<string> {
  if (opts.full) return new Set(opts.repos.map((r) => r.full_name));
  return new Set(opts.repos.filter((r) => !opts.known.get(r.full_name) || opts.changed.has(r.full_name)).map((r) => r.full_name));
}
const FULL_SWEEP_MS = 24 * 3_600_000;

/** Every table the adapter owns, children first (the purge order). */
export const GITHUB_TABLES = ["github_audit", "github_usage", "github_copilot_seats", "github_hooks", "github_secrets", "github_apps", "github_credentials", "github_repo_access", "github_repos", "github_teams", "github_members", "github_org"];

/** How one section of the collection went: rows read, or the refusal (403 = the App lacks a permission, 404 = off or not on this plan). */
/** `via` says where it was read: Steampipe (the plugin's tables) first, the API where no table exists or the plugin failed. */
export interface SectionStatus { ok: boolean; rows: number; status: number | null; error: string | null; via?: "steampipe" | "api" }
export interface GitHubExtras { sections: Record<string, SectionStatus>; invitations: GitHubInvitation[]; copilot: GitHubCopilot | null; audit_since: string | null; read_at: string | null }
const NO_EXTRAS: GitHubExtras = { sections: {}, invitations: [], copilot: null, audit_since: null, read_at: null };

/**
 * What the collection is doing right now, for the Overview's live panel (GET /api/github/progress): the step, the
 * repositories done of all, the calls made, and the last lines of its log. One collection at a time.
 */
export interface GitHubProgress { running: boolean; started_at: string | null; finished_at: string | null; phase: string | null; step: string | null; repos_done: number; repos_total: number; calls: number; errors: number; log: { at: string; line: string }[] }
export const githubProgress: GitHubProgress = { running: false, started_at: null, finished_at: null, phase: null, step: null, repos_done: 0, repos_total: 0, calls: 0, errors: 0, log: [] };
/** One line in the live log (the last 60 kept) and the console. */
export function progressLog(line: string, opts: { quiet?: boolean } = {}): void {
  githubProgress.log.push({ at: new Date().toISOString(), line }); if (githubProgress.log.length > 60) githubProgress.log.splice(0, githubProgress.log.length - 60);
  if (!opts.quiet) console.log(`[github] ${line}`);
}
export function progressStart(phase: string): boolean {
  if (githubProgress.running) return false;
  Object.assign(githubProgress, { running: true, started_at: new Date().toISOString(), finished_at: null, phase, step: null, repos_done: 0, repos_total: 0, calls: 0, errors: 0, log: [] });
  return true;
}
export function progressPhase(phase: string): void { githubProgress.phase = phase; githubProgress.step = null; progressLog(phase); }
export function progressEnd(summary: string): void { githubProgress.running = false; githubProgress.finished_at = new Date().toISOString(); githubProgress.phase = "done"; githubProgress.step = null; progressLog(summary); }

export interface GitHubRefreshResult { repos_read: number; repos_kept: number; full_sweep: boolean; not_modified: number; org: GitHubOrg; members: number; collaborators: number; teams: number; repos: number; credentials: number; apps: number; secrets: number; audit: number; usage_months: number; calls: number; errors: string[]; took_ms: number }

const J = (v: unknown) => JSON.stringify(v ?? null);
const AUDIT_DAYS = 90;

/**
 * Upserts one section's rows and marks the ones of the org it did not return gone. `cols` are the columns after
 * org_id; `key` the ones that identify a row (with org_id).
 */
function sync(table: string, orgId: string, now: string, cols: string[], key: string[], rows: Record<string, unknown>[]): void {
  const all = ["org_id", ...cols, "first_seen", "last_seen", "gone"];
  const upd = cols.filter((c) => !key.includes(c)).map((c) => `${c} = excluded.${c}`);
  const st = db.prepare(`insert into ${table} (${all.join(", ")}) values (${all.map((c) => `@${c}`).join(", ")}) on conflict(org_id, ${key.join(", ")}) do update set ${[...upd, "last_seen = excluded.last_seen", "gone = 0"].join(", ")}`);
  for (const r of rows) st.run({ ...Object.fromEntries(cols.map((c) => [c, r[c] ?? null])), org_id: orgId, first_seen: now, last_seen: now, gone: 0 });
  db.prepare(`update ${table} set gone = 1 where org_id = ? and last_seen < ?`).run(orgId, now);
}

/**
 * Reads the whole org, section by section, and stores what each section returned. With `sql` (the Steampipe
 * connection), every section the plugin has a table for is read there; a section the plugin fails on falls back to
 * the API; the rest (no table) are API calls on the same App.
 */
export async function refreshGitHub(client: GitHubClient, opts: { usageMonths?: number; repoDetail?: boolean; sql?: GitHubSql | null; full?: boolean } = {}): Promise<GitHubRefreshResult> {
  const t0 = Date.now(); const now = new Date().toISOString(); const errors: string[] = []; const sections: Record<string, SectionStatus> = {};
  const sql = opts.sql ?? null;
  const fail = (name: string, e: any, via: "steampipe" | "api") => { const status = typeof e?.status === "number" ? e.status : null; const msg = String(e?.message || e).slice(0, 240); sections[name] = { ok: false, rows: 0, status, error: msg, via }; errors.push(`${name}: ${msg}`); githubProgress.errors++; progressLog(`${name}: failed (${via}${status ? `, HTTP ${status}` : ""}): ${msg.slice(0, 140)}`); };
  const done = (name: string) => { const x = sections[name]; if (x?.ok) progressLog(`${name}: ${x.rows} via ${x.via}`, { quiet: true }); githubProgress.calls = client.calls; };
  const step = (name: string) => { githubProgress.step = name; githubProgress.calls = client.calls; };
  const count = (v: any) => (Array.isArray(v) ? v.length : 1);
  /** an API-only section (no Steampipe table) */
  const section = async <T,>(name: string, fn: () => Promise<T>, n: (v: T) => number = count): Promise<T | null> => {
    step(name);
    try { const v = await fn(); sections[name] = { ok: true, rows: n(v), status: null, error: null, via: "api" }; done(name); return v; } catch (e: any) { fail(name, e, "api"); return null; }
  };
  /** a section Steampipe covers: the table first, the API when the plugin fails (and the API can read it) */
  const dual = async <T,>(name: string, fromSql: (() => Promise<T>) | null, fromApi: (() => Promise<T>) | null, n: (v: T) => number = count): Promise<T | null> => {
    if (sql && fromSql) {
      step(name);
      try { const v = await fromSql(); sections[name] = { ok: true, rows: n(v), status: null, error: null, via: "steampipe" }; done(name); return v; }
      catch (e: any) { if (!fromApi) { fail(name, e, "steampipe"); return null; } progressLog(`${name}: Steampipe failed (${String(e?.message || e).slice(0, 120)}); reading the API`); }
    }
    return fromApi ? section(name, fromApi, n) : null;
  };

  const org = (sql ? await sql.orgInfo().catch(() => null) : null) ?? await client.orgInfo(); const orgId = org.node_id;
  const prev = githubExtras(orgId);
  const profiles = new Map<string, GitHubUser>();
  // members: role, 2FA and profile in one Steampipe read; the API needs three
  let sqlMfa: Map<string, boolean | null> | null = null;
  const members = await dual("members", sql && (async () => { const m = await sql.members(); for (const x of m) profiles.set(x.login, x.profile); sqlMfa = new Map(m.map((x) => [x.login, x.mfa])); return m.map(({ login, id, role }) => ({ login, id, role })); }), () => client.members());
  // 2FA from the member table when it says (it is null without owner-level access); the API's 2fa_disabled list otherwise
  const mfaSeen = sqlMfa as Map<string, boolean | null> | null;
  let no2fa: string[] | null;
  if (mfaSeen && [...mfaSeen.values()].some((v) => v != null)) { no2fa = [...mfaSeen.entries()].filter(([, v]) => v === false).map(([k]) => k); sections.members_2fa = { ok: true, rows: no2fa.length, status: null, error: null, via: "steampipe" }; }
  else no2fa = await section("members_2fa", () => client.without2fa("members"));
  const outsideRows = await dual("outside_collaborators", sql && (() => sql.outsideCollaborators()), async () => (await client.outsideCollaborators()).map((o) => ({ login: o.login, repos: [] as { repo: string; permission: string | null }[] })));
  const outside = outsideRows?.map((o, i) => ({ login: o.login, id: i })) ?? null;
  const outsideNo2fa = outside ? await section("outside_collaborators_2fa", () => client.without2fa("outside_collaborators")) : null;
  const logins = [...new Set([...(members ?? []).map((m) => m.login), ...(outside ?? []).map((m) => m.login)])];
  const sshKeys: Awaited<ReturnType<GitHubClient["sshKeys"]>> = [];
  await dual("profiles", sql && (async () => { for (const l of logins) if (!profiles.has(l)) { try { profiles.set(l, await sql.user(l)); } catch { /* a profile the plugin will not show */ } } return logins; }), async () => { for (const l of logins) if (!profiles.has(l)) { try { profiles.set(l, await client.user(l)); } catch { /* */ } } return logins; });
  // public SSH keys: no table
  await section("ssh_keys", async () => { for (const l of logins) { try { sshKeys.push(...(await client.sshKeys(l))); } catch { /* none public */ } } return sshKeys; });
  const saml = sql ? await dual("saml_identities", () => sql.samlIdentities(), null) : null;
  const invitations = await section("invitations", () => client.invitations());
  const teams = await dual("teams", sql && (() => sql.teams()), () => client.teams());
  const repos = await dual("repos", sql && (() => sql.repos()), () => client.repos());
  // the audit log since the last event read (a day of overlap), 90 days on the first pass
  const lastAudit = (db.prepare("select max(at) as at from github_audit where org_id = ?").get(orgId) as { at: string | null }).at;
  const auditSince = new Date(Math.max(Date.now() - AUDIT_DAYS * 86_400_000, lastAudit ? Date.parse(lastAudit) - 86_400_000 : 0)).toISOString().slice(0, 10);
  const audit = await dual("audit_log", sql && (() => sql.audit(auditSince)), () => client.audit(auditSince));
  // which repositories to read in detail: every one on the daily full sweep (or when the audit log is not readable), else
  // the new ones and the ones the audit log shows changed since they were last read
  const sweepKey = `github_full_sweep:${orgId}`;
  const lastSweep = (db.prepare("select value from settings where key = ?").get(sweepKey) as { value: string } | undefined)?.value ?? null;
  const known = new Map((db.prepare("select full_name, detail_at from github_repos where org_id = ? and gone = 0").all(orgId) as { full_name: string; detail_at: string | null }[]).map((r) => [r.full_name, r.detail_at]));
  const since = prev.read_at;
  const changed = new Set((audit ?? []).filter((e) => e.repo && (!since || e.at >= since) && REPO_CHANGE_ACTION.test(e.action)).map((e) => e.repo!.includes("/") ? e.repo! : `${org.login}/${e.repo}`));
  const full = Boolean(opts.full) || !audit || !lastSweep || Date.now() - Date.parse(lastSweep) > FULL_SWEEP_MS || !since;
  const toRead = repos ? reposToRead({ repos, known, changed, full }) : new Set<string>();
  const skipped = (repos ?? []).filter((r) => !toRead.has(r.full_name)).map((r) => r.full_name);
  if (repos) progressLog(full ? `repositories: full sweep of ${repos.length}` : `repositories: ${toRead.size} to read (${[...toRead].filter((r) => !known.get(r)).length} new, ${changed.size} changed per the audit log), ${skipped.length} unchanged kept as stored`);
  const access: Awaited<ReturnType<GitHubClient["collaborators"]>> = []; const deployKeys: Awaited<ReturnType<GitHubClient["deployKeys"]>> = [];
  const repoSecrets: GitHubSecret[] = []; const repoHooks: Awaited<ReturnType<GitHubClient["hooks"]>> = [];
  const perRepo = { collaborators: true, deploy_keys: true, repo_secrets: true, repo_hooks: true };
  const perRepoErr: Record<string, { status: number | null; error: string } | null> = { collaborators: null, deploy_keys: null, repo_secrets: null, repo_hooks: null };
  const perRepoVia: Record<string, "steampipe" | "api"> = { collaborators: sql ? "steampipe" : "api", deploy_keys: "api", repo_secrets: sql ? "steampipe" : "api", repo_hooks: "api" };
  const tryRepo = async (name: keyof typeof perRepo, fn: () => Promise<void>) => { if (!perRepo[name]) return; try { await fn(); } catch (e: any) { const st = typeof e?.status === "number" ? e.status : null; if (st === 403) { perRepo[name] = false; perRepoErr[name] = { status: st, error: String(e?.message || e).slice(0, 240) }; } else if (!perRepoErr[name]) perRepoErr[name] = { status: st, error: String(e?.message || e).slice(0, 240) }; } };
  /** a per-repository read: the table when there is one, the API when it fails for that repository */
  const either = async <T,>(fromSql: (() => Promise<T>) | null, fromApi: () => Promise<T>): Promise<T> => { if (sql && fromSql) { try { return await fromSql(); } catch { /* the API below */ } } return fromApi(); };
  // the repositories in parallel, a few at a time (a large org has hundreds; each needs several reads)
  const eachRepo = async (fn: (r: GitHubRepo) => Promise<void>) => {
    const queue = (repos ?? []).filter((r) => toRead.has(r.full_name)); githubProgress.repos_total = queue.length; githubProgress.repos_done = 0; step("repositories: collaborators, deploy keys, secrets, webhooks");
    await Promise.all(Array.from({ length: Math.min(8, queue.length) }, async () => { for (let r = queue.shift(); r; r = queue.shift()) { await fn(r); githubProgress.repos_done++; githubProgress.calls = client.calls; if (githubProgress.repos_done % 25 === 0) progressLog(`repositories: ${githubProgress.repos_done}/${githubProgress.repos_total}`, { quiet: true }); } }));
  };
  if (repos && opts.repoDetail !== false) await eachRepo(async (r) => {
    await tryRepo("collaborators", async () => { access.push(...(await either(sql && (() => sql.collaborators(r.full_name)), () => client.collaborators(r.full_name)))); });
    await tryRepo("deploy_keys", async () => { deployKeys.push(...(await client.deployKeys(r.full_name))); });
    if (!r.archived) {
      await tryRepo("repo_secrets", async () => {
        if (sql) {
          // the Actions secrets and the environments from Steampipe; each environment's secrets have no table: the API
          repoSecrets.push(...(await either(() => sql.repoActionsSecrets(r.full_name), async () => (await client.repoSecrets(r.full_name)).filter((x) => x.scope === "repo"))));
          for (const env of await either(() => sql.environments(r.full_name), async () => [])) repoSecrets.push(...(await client.environmentSecrets(r.full_name, env)));
        } else repoSecrets.push(...(await client.repoSecrets(r.full_name)));
      });
      await tryRepo("repo_hooks", async () => { repoHooks.push(...(await client.hooks(r.full_name))); });
    }
  });
  // the repositories not read keep what is stored for them (passed through the sync so they are not marked gone)
  if (skipped.length) {
    const ph = skipped.map(() => "?").join(",");
    for (const r of db.prepare(`select repo, login, permission, role_name from github_repo_access where org_id = ? and gone = 0 and repo in (${ph})`).all(orgId, ...skipped) as any[]) access.push(r);
    for (const r of db.prepare(`select * from github_secrets where org_id = ? and gone = 0 and scope <> 'org' and repo in (${ph})`).all(orgId, ...skipped) as any[]) repoSecrets.push({ scope: r.scope, kind: r.kind, repo: r.repo, environment: r.environment, name: r.name, visibility: r.visibility, selected_repos: JSON.parse(r.selected_repos || "[]"), created_at: r.created_at, updated_at: r.updated_at });
    for (const r of db.prepare(`select * from github_hooks where org_id = ? and gone = 0 and repo in (${ph})`).all(orgId, ...skipped) as any[]) repoHooks.push({ id: r.id, repo: r.repo, name: r.name, active: Boolean(r.active), events: JSON.parse(r.events || "[]"), host: r.host, insecure_ssl: Boolean(r.insecure_ssl), created_at: r.created_at, updated_at: r.updated_at });
    for (const r of db.prepare(`select * from github_credentials where org_id = ? and gone = 0 and kind = 'deploy_key' and holder in (${ph})`).all(orgId, ...skipped) as any[]) { const d = JSON.parse(r.details || "{}"); deployKeys.push({ repo: r.holder, id: Number(String(r.id).split(":").pop()), title: r.name, fingerprint: r.fingerprint, key_kind: d.key_kind ?? null, read_only: Boolean(d.read_only), verified: d.verified ?? null, added_by: d.added_by ?? null, created_at: r.created_at, last_used: r.last_used_at, enabled: d.enabled ?? null }); }
  }
  // a per-repository section refused everywhere (403) is not read: its rows stay; one repository failing for another reason is only noted
  const repoCounts: Record<string, number> = { collaborators: access.length, deploy_keys: deployKeys.length, repo_secrets: repoSecrets.length, repo_hooks: repoHooks.length };
  if (repos) for (const k of Object.keys(perRepo) as (keyof typeof perRepo)[]) { sections[k] = { ok: perRepo[k], rows: repoCounts[k], status: perRepoErr[k]?.status ?? null, error: perRepoErr[k]?.error ?? null, via: perRepoVia[k] }; if (perRepoErr[k]) errors.push(`${k}: ${perRepoErr[k]!.error}`); }
  // no Steampipe table for any of these
  const pats = await section("personal_access_tokens", () => client.pats());
  const patRequests = await section("personal_access_token_requests", () => client.patRequests());
  const credAuth = await section("credential_authorizations", () => client.credentialAuthorizations());
  const apps = await section("installations", () => client.installations());
  const orgSecrets = await section("org_secrets", () => client.orgSecrets());
  const orgHooks = await section("org_hooks", () => client.hooks());
  const copilot = await section("copilot", () => client.copilot(), (v) => v.seats.length);
  const usageMonths = opts.usageMonths ?? (db.prepare("select count(*) as n from github_usage where org_id = ?").get(orgId) as { n: number }).n ? 2 : 7;
  const usage: { y: number; m: number; items: Awaited<ReturnType<GitHubClient["usage"]>> }[] = [];
  await section("billing_usage", async () => { const d = new Date(); for (let i = 0; i < usageMonths; i++) { const x = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() - i, 1)); usage.push({ y: x.getUTCFullYear(), m: x.getUTCMonth() + 1, items: await client.usage(x.getUTCFullYear(), x.getUTCMonth() + 1) }); } return usage.flatMap((u) => u.items); });

  step("storing"); githubProgress.calls = client.calls;
  db.transaction(() => {
    db.prepare("insert into github_org(id, login, name, plan, seats, filled_seats, details, fetched_at) values (?, ?, ?, ?, ?, ?, ?, ?) on conflict(id) do update set login = excluded.login, name = excluded.name, plan = excluded.plan, seats = excluded.seats, filled_seats = excluded.filled_seats, details = excluded.details, fetched_at = excluded.fetched_at")
      .run(orgId, org.login, org.name, org.plan, org.seats, org.filled_seats, J(org), now);
    if (members && outside) {
      const off = new Set([...(no2fa ?? []), ...(outsideNo2fa ?? [])]);
      // 2FA is known only for the groups whose 2fa_disabled list was readable
      const mfaOf = (login: string, list: string[] | null) => (list == null ? null : off.has(login) ? 0 : 1);
      const samlKey = new Map((saml ?? []).map((x) => [x.login.toLowerCase(), x.email_keys[0] ?? x.name_id_key]));
      const row = (login: string, id: number, kind: string, role: string | null, list: string[] | null) => { const p = profiles.get(login); return { login, kind, user_id: id, role, name: p?.name ?? null, email_key: p?.email_key ?? null, company: p?.company ?? null, created_at: p?.created_at ?? null, mfa: mfaOf(login, list), saml_key: samlKey.get(login.toLowerCase()) ?? null }; };
      sync("github_members", orgId, now, ["login", "kind", "user_id", "role", "name", "email_key", "company", "created_at", "mfa", "saml_key"], ["login"], [...members.map((m) => row(m.login, m.id, "member", m.role, no2fa)), ...outside.map((m) => row(m.login, m.id, "collaborator", null, outsideNo2fa))]);
    }
    if (teams) sync("github_teams", orgId, now, ["slug", "name", "privacy", "parent", "members", "repos"], ["slug"], teams.map((t) => ({ ...t, members: J(t.members), repos: J(t.repos) })));
    if (repos) {
      sync("github_repos", orgId, now, ["full_name", "node_id", "private", "visibility", "archived", "fork", "default_branch", "pushed_at", "created_at", "html_url"], ["full_name"], repos.map((r) => ({ ...r, private: r.private ? 1 : 0, archived: r.archived ? 1 : 0, fork: r.fork ? 1 : 0 })));
      const mark = db.prepare("update github_repos set detail_at = ? where org_id = ? and full_name = ?");
      if (opts.repoDetail !== false && Object.values(perRepo).every(Boolean)) { for (const r of toRead) mark.run(now, orgId, r); if (full) db.prepare("insert or replace into settings(key, value) values (?, ?)").run(sweepKey, now); }
      if (perRepo.collaborators) {
        const have = new Set(access.map((a) => `${a.repo}|${a.login}`));
        for (const o of outsideRows ?? []) for (const r of o.repos) if (!have.has(`${r.repo}|${o.login}`)) access.push({ repo: r.repo, login: o.login, permission: r.permission as any, role_name: r.permission });
        sync("github_repo_access", orgId, now, ["repo", "login", "permission", "role_name"], ["repo", "login"], access as any[]);
      }
      if (perRepo.repo_hooks && orgHooks) sync("github_hooks", orgId, now, ["id", "repo", "name", "active", "events", "host", "insecure_ssl", "created_at", "updated_at"], ["id"], [...orgHooks, ...repoHooks].map((h) => ({ ...h, active: h.active ? 1 : 0, insecure_ssl: h.insecure_ssl ? 1 : 0, events: J(h.events) })));
      if (perRepo.repo_secrets && orgSecrets) sync("github_secrets", orgId, now, ["id", "scope", "kind", "repo", "environment", "name", "visibility", "selected_repos", "created_at", "updated_at"], ["id"], [...orgSecrets, ...repoSecrets].map((s) => ({ ...s, id: [s.scope, s.kind, s.repo ?? "", s.environment ?? "", s.name].join(":"), selected_repos: J(s.selected_repos) })));
    }
    // credentials: one table, each kind replaced only when its own section was read
    const creds: Record<string, unknown>[] = [];
    const keep = (kind: string) => (db.prepare("select * from github_credentials where org_id = ? and kind = ? and gone = 0").all(orgId, kind) as any[]);
    const kinds: [string, boolean, () => Record<string, unknown>[]][] = [
      ["deploy_key", Boolean(repos) && perRepo.deploy_keys, () => deployKeys.map((k) => ({ id: `deploy_key:${k.repo}:${k.id}`, kind: "deploy_key", holder: k.repo, name: k.title, fingerprint: k.fingerprint, created_at: k.created_at, last_used_at: k.last_used, expires_at: null, details: J({ read_only: k.read_only, verified: k.verified, added_by: k.added_by, key_kind: k.key_kind, enabled: k.enabled }) }))],
      ["ssh_key", Boolean(members), () => sshKeys.map((k) => ({ id: `ssh_key:${k.login}:${k.id}`, kind: "ssh_key", holder: k.login, name: `${k.key_kind ?? "ssh"} key`, fingerprint: k.fingerprint, created_at: null, last_used_at: null, expires_at: null, details: J({ key_kind: k.key_kind }) }))],
      ["pat", Boolean(pats), () => (pats ?? []).map((t) => ({ id: `pat:${t.id}`, kind: "pat", holder: t.owner, name: t.name, fingerprint: null, created_at: t.granted_at, last_used_at: t.last_used_at, expires_at: t.expires_at, details: J({ token_id: t.token_id, repository_selection: t.repository_selection, repos: t.repos, permissions: t.permissions, expired: t.expired }) }))],
      ["pat_request", Boolean(patRequests), () => (patRequests ?? []).map((t) => ({ id: `pat_request:${t.id}`, kind: "pat_request", holder: t.owner, name: t.name, fingerprint: null, created_at: t.created_at, last_used_at: null, expires_at: t.expires_at, details: J({ token_id: t.token_id, reason: t.reason, repository_selection: t.repository_selection, permissions: t.permissions }) }))],
      ["credential_authorization", Boolean(credAuth), () => (credAuth ?? []).map((c) => ({ id: `saml:${c.credential_id}`, kind: "credential_authorization", holder: c.login, name: c.title ?? (c.token_last_eight ? `…${c.token_last_eight}` : c.type), fingerprint: c.fingerprint, created_at: c.authorized_at, last_used_at: c.accessed_at, expires_at: c.expires_at, details: J({ type: c.type, scopes: c.scopes, token_last_eight: c.token_last_eight }) }))],
    ];
    for (const [kind, read, rows] of kinds) creds.push(...(read ? rows() : keep(kind)));
    sync("github_credentials", orgId, now, ["id", "kind", "holder", "name", "fingerprint", "created_at", "last_used_at", "expires_at", "details"], ["id"], creds);
    if (apps) sync("github_apps", orgId, now, ["id", "app_slug", "repository_selection", "permissions", "events", "created_at", "updated_at", "suspended_at"], ["id"], apps.map((a) => ({ ...a, permissions: J(a.permissions), events: J(a.events) })));
    if (copilot) sync("github_copilot_seats", orgId, now, ["login", "plan_type", "created_at", "last_activity_at", "last_activity_editor", "pending_cancellation_date", "team"], ["login"], copilot.seats as any[]);
    if (audit) {
      const up = db.prepare("insert or ignore into github_audit(org_id, id, at, action, actor, user, repo, team, ip, country, user_agent, access_type, hashed_token, token_id, operation) values (@org_id, @id, @at, @action, @actor, @user, @repo, @team, @ip, @country, @user_agent, @access_type, @hashed_token, @token_id, @operation)");
      for (const e of audit) up.run({ ...e, org_id: orgId });
      db.prepare("delete from github_audit where org_id = ? and at < ?").run(orgId, new Date(Date.now() - AUDIT_DAYS * 86_400_000).toISOString());
    }
    const upU = db.prepare("insert into github_usage(org_id, date, product, sku, repo, quantity, unit, price_per_unit, gross_usd, discount_usd, net_usd, fetched_at) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) on conflict(org_id, date, product, sku, repo) do update set quantity = excluded.quantity, unit = excluded.unit, price_per_unit = excluded.price_per_unit, gross_usd = excluded.gross_usd, discount_usd = excluded.discount_usd, net_usd = excluded.net_usd, fetched_at = excluded.fetched_at");
    for (const u of usage) {
      // a month is replaced whole: GitHub re-rates the current month as it goes
      const ym = `${u.y}-${String(u.m).padStart(2, "0")}`;
      db.prepare("delete from github_usage where org_id = ? and substr(date, 1, 7) = ?").run(orgId, ym);
      // several items can share a day, SKU and repository (an org-level item has none): summed
      const agg = new Map<string, (typeof u.items)[number]>();
      for (const it of u.items) { const k = [it.date, it.product, it.sku, it.repo ?? ""].join("|"); const a = agg.get(k); if (!a) agg.set(k, { ...it }); else { a.quantity += it.quantity; a.gross_usd += it.gross_usd; a.discount_usd += it.discount_usd; a.net_usd += it.net_usd; } }
      for (const it of agg.values()) upU.run(orgId, it.date, it.product, it.sku, it.repo ?? "", it.quantity, it.unit, it.price_per_unit, it.gross_usd, it.discount_usd, it.net_usd, now);
    }
    const extras: GitHubExtras = { sections, invitations: invitations ?? prev.invitations, copilot: copilot?.summary ?? prev.copilot, audit_since: audit ? (prev.audit_since && prev.audit_since < auditSince ? prev.audit_since : auditSince) : prev.audit_since, read_at: now };
    db.prepare("insert or replace into settings(key, value) values (?, ?)").run(`github_extras:${orgId}`, J(extras));
  })();
  return { repos_read: toRead.size, repos_kept: skipped.length, full_sweep: full, not_modified: client.not_modified, org, members: members?.length ?? 0, collaborators: outside?.length ?? 0, teams: teams?.length ?? 0, repos: repos?.length ?? 0, credentials: deployKeys.length + sshKeys.length + (pats?.length ?? 0) + (credAuth?.length ?? 0), apps: apps?.length ?? 0, secrets: (orgSecrets?.length ?? 0) + repoSecrets.length, audit: audit?.length ?? 0, usage_months: usage.length, calls: client.calls, errors, took_ms: Date.now() - t0 };
}

const parse = <T,>(s: unknown, d: T): T => { if (typeof s !== "string") return d; try { return JSON.parse(s) as T; } catch { return d; } };

export interface OrgRow extends GitHubOrg { fetched_at: string }
/** The org as last read (the adapter knows one org at a time). */
export const githubOrgRow = (): OrgRow | null => { const r = db.prepare("select * from github_org order by fetched_at desc limit 1").get() as any; return r ? { ...parse<GitHubOrg>(r.details, {} as GitHubOrg), node_id: r.id, login: r.login, name: r.name, plan: r.plan, seats: r.seats, filled_seats: r.filled_seats, fetched_at: r.fetched_at } : null; };
export const githubExtras = (orgId: string): GitHubExtras => { const r = db.prepare("select value from settings where key = ?").get(`github_extras:${orgId}`) as { value: string } | undefined; return r ? { ...NO_EXTRAS, ...parse<any>(r.value, {}) } : { ...NO_EXTRAS }; };

export interface MemberRow { org_id: string; login: string; kind: "member" | "collaborator"; user_id: number | null; role: string | null; name: string | null; email_key: string | null; saml_key: string | null; company: string | null; created_at: string | null; mfa: boolean | null; first_seen: string; last_seen: string; gone: boolean }
export const listMembers = (orgId: string, includeGone = false): MemberRow[] => (db.prepare(`select * from github_members where org_id = ?${includeGone ? "" : " and gone = 0"} order by kind, login`).all(orgId) as any[]).map((r) => ({ ...r, mfa: r.mfa == null ? null : Boolean(r.mfa), gone: Boolean(r.gone) }));
export interface TeamRow { slug: string; name: string; privacy: string | null; parent: string | null; members: { login: string; role: string }[]; repos: { repo: string; permission: string | null }[]; gone: boolean }
export const listTeams = (orgId: string): TeamRow[] => (db.prepare("select * from github_teams where org_id = ? and gone = 0 order by slug").all(orgId) as any[]).map((r) => ({ ...r, members: parse(r.members, []), repos: parse(r.repos, []), gone: Boolean(r.gone) }));
export interface RepoRow { full_name: string; node_id: string | null; private: boolean; visibility: string | null; archived: boolean; fork: boolean; default_branch: string | null; pushed_at: string | null; created_at: string | null; html_url: string | null; first_seen: string; last_seen: string; gone: boolean }
export const listRepos = (orgId: string, includeGone = false): RepoRow[] => (db.prepare(`select * from github_repos where org_id = ?${includeGone ? "" : " and gone = 0"} order by full_name`).all(orgId) as any[]).map((r) => ({ ...r, private: Boolean(r.private), archived: Boolean(r.archived), fork: Boolean(r.fork), gone: Boolean(r.gone) }));
export const listRepoAccess = (orgId: string): { repo: string; login: string; permission: string | null; role_name: string | null }[] => db.prepare("select repo, login, permission, role_name from github_repo_access where org_id = ? and gone = 0").all(orgId) as any[];
export interface CredentialStoreRow { id: string; kind: "deploy_key" | "ssh_key" | "pat" | "pat_request" | "credential_authorization"; holder: string | null; name: string | null; fingerprint: string | null; created_at: string | null; last_used_at: string | null; expires_at: string | null; details: Record<string, any>; first_seen: string; last_seen: string; gone: boolean }
export const listCredentials = (orgId: string, includeGone = false): CredentialStoreRow[] => (db.prepare(`select * from github_credentials where org_id = ?${includeGone ? "" : " and gone = 0"} order by kind, holder, name`).all(orgId) as any[]).map((r) => ({ ...r, details: parse(r.details, {}), gone: Boolean(r.gone) }));
export interface AppRow { id: number; app_slug: string; repository_selection: string | null; permissions: Record<string, string>; events: string[]; created_at: string | null; updated_at: string | null; suspended_at: string | null; first_seen: string; last_seen: string; gone: boolean }
export const listApps = (orgId: string): AppRow[] => (db.prepare("select * from github_apps where org_id = ? and gone = 0 order by app_slug").all(orgId) as any[]).map((r) => ({ ...r, permissions: parse(r.permissions, {}), events: parse(r.events, []), gone: Boolean(r.gone) }));
export interface SecretRow { id: string; scope: "org" | "repo" | "environment"; kind: string; repo: string | null; environment: string | null; name: string; visibility: string | null; selected_repos: string[]; created_at: string | null; updated_at: string | null; first_seen: string; last_seen: string; gone: boolean }
export const listSecrets = (orgId: string): SecretRow[] => (db.prepare("select * from github_secrets where org_id = ? and gone = 0 order by scope, repo, name").all(orgId) as any[]).map((r) => ({ ...r, selected_repos: parse(r.selected_repos, []), gone: Boolean(r.gone) }));
export const listHooks = (orgId: string): { id: number; repo: string | null; name: string | null; active: boolean; events: string[]; host: string | null; insecure_ssl: boolean; created_at: string | null }[] => (db.prepare("select * from github_hooks where org_id = ? and gone = 0 order by repo, id").all(orgId) as any[]).map((r) => ({ ...r, active: Boolean(r.active), insecure_ssl: Boolean(r.insecure_ssl), events: parse(r.events, []) }));
export const listCopilotSeats = (orgId: string): { login: string; plan_type: string | null; created_at: string | null; last_activity_at: string | null; last_activity_editor: string | null; pending_cancellation_date: string | null; team: string | null }[] => db.prepare("select * from github_copilot_seats where org_id = ? and gone = 0 order by login").all(orgId) as any[];
export const listAudit = (orgId: string, opts: { actor?: string; limit?: number } = {}): GitHubAuditEvent[] => db.prepare(`select * from github_audit where org_id = ?${opts.actor ? " and actor = ?" : ""} order by at desc limit ?`).all(...(opts.actor ? [orgId, opts.actor, opts.limit ?? 200] : [orgId, opts.limit ?? 200])) as any[];

/** What the audit log says about each actor: events, last time, the clients (user agents) and addresses seen, and which kinds of credential they acted with. */
export interface AuditActivity { actor: string; events: number; first_at: string; last_at: string; user_agents: { ua: string; events: number; last_at: string }[]; ips: { ip: string; events: number; last_at: string }[]; access_types: { type: string; events: number; last_at: string }[]; tokens: { hashed_token: string; token_id: number | null; access_type: string | null; events: number; last_at: string }[] }
export function auditActivity(orgId: string): Map<string, AuditActivity> {
  const out = new Map<string, AuditActivity>();
  const rows = db.prepare("select actor, at, ip, user_agent, access_type, hashed_token, token_id from github_audit where org_id = ? and actor is not null order by at").all(orgId) as { actor: string; at: string; ip: string | null; user_agent: string | null; access_type: string | null; hashed_token: string | null; token_id: number | null }[];
  const bump = <T extends { events: number; last_at: string }>(list: T[], find: (x: T) => boolean, make: () => T, at: string) => { const x = list.find(find); if (x) { x.events++; x.last_at = at; } else list.push(make()); };
  for (const r of rows) {
    let a = out.get(r.actor); if (!a) out.set(r.actor, (a = { actor: r.actor, events: 0, first_at: r.at, last_at: r.at, user_agents: [], ips: [], access_types: [], tokens: [] }));
    a.events++; a.last_at = r.at;
    if (r.user_agent) bump(a.user_agents, (x) => x.ua === r.user_agent, () => ({ ua: r.user_agent!, events: 1, last_at: r.at }), r.at);
    if (r.ip) bump(a.ips, (x) => x.ip === r.ip, () => ({ ip: r.ip!, events: 1, last_at: r.at }), r.at);
    const type = r.access_type ?? "web or git";
    bump(a.access_types, (x) => x.type === type, () => ({ type, events: 1, last_at: r.at }), r.at);
    if (r.hashed_token) bump(a.tokens, (x) => x.hashed_token === r.hashed_token, () => ({ hashed_token: r.hashed_token!, token_id: r.token_id, access_type: r.access_type, events: 1, last_at: r.at }), r.at);
  }
  return out;
}

/** Usage billing summed per month (net of discounts), and per product for one month. */
export const usageByMonth = (orgId: string): { month: string; usd: number; gross_usd: number }[] => db.prepare("select substr(date, 1, 7) as month, round(sum(net_usd), 2) as usd, round(sum(gross_usd), 2) as gross_usd from github_usage where org_id = ? group by 1 order by 1 desc").all(orgId) as any[];
export const usageByProduct = (orgId: string, month: string): { product: string; sku: string; quantity: number; unit: string | null; usd: number; gross_usd: number }[] => db.prepare("select product, sku, round(sum(quantity), 2) as quantity, max(unit) as unit, round(sum(net_usd), 2) as usd, round(sum(gross_usd), 2) as gross_usd from github_usage where org_id = ? and substr(date, 1, 7) = ? group by product, sku order by usd desc, gross_usd desc").all(orgId, month) as any[];
/**
 * Every month of the stored usage, spent on what: per product the used value at list price (gross), what the plan's
 * included allowance covered (discount) and what was billed (net), with its SKUs (quantity and unit) and the
 * repositories that used the most. Newest month first.
 */
export function usageHistory(orgId: string): { month: string; gross_usd: number; discount_usd: number; net_usd: number; products: { product: string; gross_usd: number; discount_usd: number; net_usd: number; skus: { sku: string; quantity: number; unit: string | null; gross_usd: number; net_usd: number }[]; repos: { repo: string; gross_usd: number; net_usd: number }[] }[] }[] {
  const r2 = (n: number) => Math.round(n * 100) / 100;
  const rows = db.prepare("select substr(date, 1, 7) as month, product, sku, repo, sum(quantity) as quantity, max(unit) as unit, sum(gross_usd) as gross, sum(discount_usd) as discount, sum(net_usd) as net from github_usage where org_id = ? group by 1, 2, 3, 4").all(orgId) as { month: string; product: string; sku: string; repo: string; quantity: number; unit: string | null; gross: number; discount: number; net: number }[];
  const months = new Map<string, Map<string, { skus: Map<string, { quantity: number; unit: string | null; gross: number; net: number }>; repos: Map<string, { gross: number; net: number }>; gross: number; discount: number; net: number }>>();
  for (const r of rows) {
    const m = months.get(r.month) ?? new Map(); months.set(r.month, m);
    const p = m.get(r.product) ?? { skus: new Map(), repos: new Map(), gross: 0, discount: 0, net: 0 }; m.set(r.product, p);
    p.gross += r.gross; p.discount += r.discount; p.net += r.net;
    const k = p.skus.get(r.sku) ?? { quantity: 0, unit: r.unit, gross: 0, net: 0 }; k.quantity += r.quantity; k.gross += r.gross; k.net += r.net; p.skus.set(r.sku, k);
    if (r.repo) { const x = p.repos.get(r.repo) ?? { gross: 0, net: 0 }; x.gross += r.gross; x.net += r.net; p.repos.set(r.repo, x); }
  }
  return [...months.entries()].sort((a, b) => b[0].localeCompare(a[0])).map(([month, m]) => {
    const products = [...m.entries()].map(([product, p]) => ({ product, gross_usd: r2(p.gross), discount_usd: r2(p.discount), net_usd: r2(p.net),
      skus: [...p.skus.entries()].map(([sku, k]) => ({ sku, quantity: Math.round(k.quantity * 100) / 100, unit: k.unit, gross_usd: r2(k.gross), net_usd: r2(k.net) })).sort((a, b) => b.gross_usd - a.gross_usd),
      repos: [...p.repos.entries()].map(([repo, x]) => ({ repo, gross_usd: r2(x.gross), net_usd: r2(x.net) })).sort((a, b) => b.gross_usd - a.gross_usd).slice(0, 10) })).sort((a, b) => b.gross_usd - a.gross_usd);
    return { month, gross_usd: r2(products.reduce((n, p) => n + p.gross_usd, 0)), discount_usd: r2(products.reduce((n, p) => n + p.discount_usd, 0)), net_usd: r2(products.reduce((n, p) => n + p.net_usd, 0)), products };
  });
}

export const usageDays = (orgId: string, month: string): { date: string; usd: number }[] => db.prepare("select date, round(sum(net_usd), 2) as usd from github_usage where org_id = ? and substr(date, 1, 7) = ? group by date order by date").all(orgId, month) as any[];

export const wipeGitHub = (): void => { db.transaction(() => { db.prepare("delete from github_http_cache").run(); db.prepare("delete from settings where key like 'github_full_sweep:%'").run(); for (const t of GITHUB_TABLES) db.prepare(`delete from ${t}`).run(); db.prepare("delete from settings where key like 'github_extras:%' or key like 'github_snapshot:%'").run(); })(); };

import { config } from "../../config.js";
import { db } from "../../db.js";
import type { AccountRecord, ProviderAdapter, ResourceNode, TelemetryKind } from "../types.js";
import { GitHubClient } from "./client.js";
import { GITHUB_TABLES, sqliteHttpCache, auditActivity, githubExtras, githubOrgRow, listApps, listCopilotSeats, listMembers, listSecrets, listTeams, usageByMonth, usageByProduct, usageDays } from "./inventory.js";
import { githubOnboarding } from "./onboarding.js";

/**
 * The GitHub adapter: the org is the account (`native_type: organization`, keyed by the org's node id `O_…`). Not
 * infrastructure but a way in to it: its people (members and outside collaborators) are AdvisorIdentity nodes joined
 * to the AWS and Vercel identities of the same person, its teams are group identities, its installed Apps are machine
 * identities, its Actions secrets are AdvisorSecret nodes (names only), and its repositories are the AdvisorRepository
 * nodes the GitHub Actions OIDC trust already points at (./graph.ts). Credentials (deploy keys, fine-grained tokens,
 * SAML-authorized classic tokens and SSH keys, public SSH keys, 2FA) are AdvisorCredential nodes (src/graph_access.ts).
 * The bill is the seats at the plan's price plus the metered usage. No probes, metrics or executor.
 * Credentials: a read-only GitHub App installed on the org (App id, installation id, private key) saved as runtime settings.
 */

export const GITHUB = "github";
export const GITHUB_TELEMETRY: Record<TelemetryKind, { native: string }> = { api: { native: "github_rest" }, metrics: { native: "none" }, probe: { native: "none" }, logs: { native: "none" }, audit: { native: "github_audit_log" }, bill: { native: "github_billing_usage" } };

export const githubConfigured = (): boolean => Boolean(config.githubOrg && config.githubAppId && config.githubInstallationId && config.githubAppPrivateKey);
/**
 * The Steampipe reader on the `github` connection, written from the saved App (./steampipe.ts); null when Steampipe
 * cannot load it, so the collection reads everything from the API instead. A connection written just now is waited for.
 */
export async function githubSql(): Promise<import("./sql.js").GitHubSql | null> {
  const sp = await import("./steampipe.js"); const { query } = await import("../../steampipe.js"); const { GitHubSql } = await import("./sql.js");
  const state = sp.ensureGitHubConnection();
  if (state === "written") console.log("[github] steampipe connection written");
  const ok = await sp.waitForConnection(query, state === "written" ? 60_000 : 5_000);
  if (!ok) { console.error("[github] the Steampipe github connection is not loaded (is the turbot/github plugin installed?): reading the API only"); return null; }
  return new GitHubSql(config.githubOrg, query);
}
export const githubClient = (fetchImpl?: typeof fetch, opts: { cache?: boolean } = {}): GitHubClient => new GitHubClient({ org: config.githubOrg, app: { appId: config.githubAppId, installationId: config.githubInstallationId, privateKey: config.githubAppPrivateKey }, fetchImpl, cache: opts.cache ? sqliteHttpCache : null });

/** Node ids: one namespace per org, the same ids the findings, credentials and people name. */
export const memberId = (orgId: string, login: string) => `${orgId}/member/${login}`;
export const collaboratorId = (orgId: string, login: string) => `${orgId}/collaborator/${login}`;
export const teamId = (orgId: string, slug: string) => `${orgId}/team/${slug}`;
export const appId = (orgId: string, slug: string) => `${orgId}/app/${slug}`;
export const secretId = (orgId: string, id: string) => `${orgId}/secret/${id}`;
/** The repository id the OIDC trust paths already use (src/access_paths.ts), so both land on one node. */
export const repoNodeId = (fullName: string) => `github:${fullName}`;
/** The identity id of a login in the org: a member's, else an outside collaborator's, else null. */
export function identityOfLogin(orgId: string, login: string | null | undefined): string | null {
  if (!login) return null;
  const m = listMembers(orgId).find((x) => x.login.toLowerCase() === login.toLowerCase());
  return m ? (m.kind === "member" ? memberId(orgId, m.login) : collaboratorId(orgId, m.login)) : null;
}

const node = (id: string, label: ResourceNode["label"], native_type: string, name: string, state: ResourceNode["state"], first: string | null, last: string | null, gone: boolean, props: Record<string, unknown>, detail = "github REST API"): ResourceNode => ({
  id, label, native_type, name, state, native_state: state, region: null, role: null, role_confidence: null, protected_prob: null, monthly_usd: null, gone, first_seen: first, last_seen: last, pool: null, pool_kind: null, props: { platform: "github", ...props },
  observed: [{ kind: "api", status: gone ? "stale" : "ok", last_at: last, detail }],
});

/** Members, outside collaborators, teams, installed Apps and secrets as the generic model. */
export function githubResources(orgId: string): ResourceNode[] {
  const org = githubOrgRow(); const seatUsd = config.githubSeatUsd; const activity = auditActivity(orgId);
  const copilot = new Map(listCopilotSeats(orgId).map((s) => [s.login.toLowerCase(), s]));
  const teams = listTeams(orgId); const teamsOf = (login: string) => teams.filter((t) => t.members.some((m) => m.login === login)).map((t) => t.slug);
  const out: ResourceNode[] = [];
  for (const m of listMembers(orgId, true)) {
    const a = activity.get(m.login); const cp = copilot.get(m.login.toLowerCase());
    const id = m.kind === "member" ? memberId(orgId, m.login) : collaboratorId(orgId, m.login);
    out.push(node(id, "AdvisorIdentity", m.kind === "member" ? "github_member" : "github_collaborator", m.login, m.gone ? "terminated" : "available", m.first_seen, m.last_seen, m.gone, {
      kind: m.kind === "member" ? "org_member" : "outside_collaborator", human: true, org_id: orgId, login: m.login, display_name: m.name, company: m.company, role: m.kind === "member" ? (m.role === "admin" ? "owner" : "member") : "outside_collaborator",
      admin: m.role === "admin", mfa: m.mfa, teams: teamsOf(m.login), seat_usd: org?.plan ? seatUsd : null, copilot_seat: Boolean(cp), copilot_last_activity_at: cp?.last_activity_at ?? null,
      last_activity_at: a?.last_at ?? null, audit_events_90d: a?.events ?? 0, account_created_at: m.created_at,
    }));
  }
  for (const t of teams) out.push(node(teamId(orgId, t.slug), "AdvisorIdentity", "github_team", t.name, "available", null, null, false, { kind: "group", human: false, org_id: orgId, slug: t.slug, privacy: t.privacy, parent: t.parent, members: t.members.length, maintainers: t.members.filter((m) => m.role === "maintainer").map((m) => m.login), repos: t.repos.length }));
  for (const a of listApps(orgId)) {
    const writes = Object.entries(a.permissions).filter(([, v]) => v === "write" || v === "admin").map(([k]) => k);
    out.push(node(appId(orgId, a.app_slug), "AdvisorIdentity", "github_app", a.app_slug, a.suspended_at ? "stopped" : "available", a.first_seen, a.last_seen, a.gone, { kind: "app", human: false, org_id: orgId, installation_id: a.id, repository_selection: a.repository_selection, write_permissions: writes, read_permissions: Object.entries(a.permissions).filter(([, v]) => v === "read").map(([k]) => k), installed_at: a.created_at, suspended_at: a.suspended_at }));
  }
  for (const s of listSecrets(orgId)) out.push(node(secretId(orgId, s.id), "AdvisorSecret", s.kind === "dependabot" ? "github_dependabot_secret" : "github_actions_secret", s.name, "available", s.first_seen, s.last_seen, s.gone, { org_id: orgId, scope: s.scope, repo: s.repo, environment: s.environment, visibility: s.visibility, selected_repos: s.selected_repos, created_at: s.created_at, updated_at: s.updated_at }));
  return out;
}

/** This month's GitHub bill: the seats at the plan's price (a flat line) and the metered usage, projected on the days so far. */
export function githubMonth(orgId: string, today = new Date()) {
  const org = githubOrgRow(); const ym = today.toISOString().slice(0, 7);
  const dim = new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth() + 1, 0)).getUTCDate(); const day = today.getUTCDate();
  const products = usageByProduct(orgId, ym);
  // when the usage itemises the licences itself, the seat line would count them twice
  const seatsItemised = products.some((p) => /enterprise|licen|seat|ghe/i.test(`${p.product} ${p.sku}`) && !/copilot/i.test(`${p.product} ${p.sku}`));
  const seats = org?.seats ?? null; const seatUsd = config.githubSeatUsd;
  const seatLine = seats != null && !seatsItemised ? Math.round(seats * seatUsd * 100) / 100 : 0;
  const metered = products.reduce((s, p) => s + p.usd, 0);
  const projectedMetered = day > 0 ? (metered / day) * dim : metered;
  const months = usageByMonth(orgId);
  const last = months.find((m) => m.month < ym) ?? null;
  return {
    month: ym, seats, filled_seats: org?.filled_seats ?? null, seat_usd: seatUsd, seat_line_usd: seatLine, seats_itemised: seatsItemised, unused_seats: seats != null && org?.filled_seats != null ? Math.max(0, seats - org.filled_seats) : null,
    metered_usd: Math.round(metered * 100) / 100, month_to_date_usd: Math.round((metered + seatLine * (day / dim)) * 100) / 100, projected_usd: Math.round((projectedMetered + seatLine) * 100) / 100,
    last_month: last?.month ?? null, last_month_usd: last ? Math.round((last.usd + seatLine) * 100) / 100 : null,
    history: months.slice(0, 6).map((m) => ({ month: m.month, usd: Math.round((m.usd + seatLine) * 100) / 100 })), products, days: usageDays(orgId, ym), usage_read: Boolean(githubExtras(orgId).sections.billing_usage?.ok),
  };
}

export const githubAdapter: ProviderAdapter = {
  id: GITHUB,
  label: "GitHub",
  flow: { boundary: "organization", credentials: "a read-only GitHub App installed on the org: App id, installation id, private key", children: "none: one org; enterprise-account endpoints are not read" },
  capabilities: { probes: false, metrics: false, executor: false, compliance: false, cost: false, bill: true, findings: true, changes: true, alerts: false, clusters: false, software: false, network: false },
  storage: GITHUB_TABLES,
  telemetry: GITHUB_TELEMETRY,
  configured: githubConfigured,
  primaryAccountId: () => githubOrgRow()?.node_id || (config.githubOrg ? `github:${config.githubOrg}` : "github"),
  async accounts(): Promise<AccountRecord[]> {
    if (!githubConfigured()) return [];
    const o = githubOrgRow(); const x = o ? githubExtras(o.node_id) : null; const refused = x ? Object.entries(x.sections).filter(([, s]) => !s.ok).map(([k]) => k) : [];
    return [{ provider: GITHUB, id: githubAdapter.primaryAccountId(), native_type: "organization", name: o?.login || config.githubOrg, parent_id: null, access: `GitHub App ${config.githubAppId} · installation ${config.githubInstallationId}`, actuator: false, enabled: true,
      last_test: o ? { ok: true, detail: `${o.plan ? `${o.plan} plan · ` : ""}read ${o.fetched_at.slice(0, 16)}${refused.length ? ` · not readable: ${refused.join(", ")}` : ""}`, at: o.fetched_at } : { ok: false, detail: "not read yet", at: null } }];
  },
  async collect(opts) {
    if (!githubConfigured()) return { errors: ["GitHub is not configured"] };
    const { githubProgress, progressStart, progressPhase, progressEnd } = await import("./inventory.js");
    // a collection already running (the schedule, a click, the first save) is not started twice
    const mine = progressStart("starting"); if (!mine) return { errors: ["a GitHub collection is already running"] };
    try {
      const { refreshGitHub } = await import("./inventory.js");
      progressPhase("connecting to Steampipe");
      const sql = await githubSql();
      progressPhase(sql ? "reading the org (Steampipe first, the API for the rest)" : "reading the org (API only: the Steampipe connection is not loaded)");
      const r = await refreshGitHub(githubClient(undefined, { cache: true }), { sql, full: opts?.full });
      progressPhase("changes and rules");
      try { const { recordChanges } = await import("./changes.js"); const ch = recordChanges(r.org.node_id); if (ch.changes) console.log(`[github] ${ch.changes} change${ch.changes === 1 ? "" : "s"} since the previous collection`); } catch (e: any) { r.errors.push(`changes: ${String(e?.message || e).slice(0, 160)}`); }
      try { const { runGitHubRules } = await import("./rules.js"); const rr = await runGitHubRules(); console.log(`[github] rules pass #${rr.run_id}: ${rr.findings} findings, ${rr.recommendations} recommendations, ${rr.resolved} resolved`); try { const gm = await import("../../graph_mirror.js"); await gm.mirrorRun(rr.run_id); await gm.mirrorRecommendations(); } catch (e: any) { console.error(`[graph] github rules: ${e?.message || e}`); } } catch (e: any) { r.errors.push(`rules: ${String(e?.message || e).slice(0, 160)}`); }
      progressPhase("graph");
      try { const { mirrorAdapter } = await import("../../graph_mirror.js"); await mirrorAdapter(githubAdapter); } catch (e: any) { r.errors.push(`graph: ${String(e?.message || e).slice(0, 160)}`); }
      progressEnd(`done in ${Math.round(r.took_ms / 1000)} s: ${r.members} members, ${r.collaborators} outside collaborators, ${r.repos} repos (${r.full_sweep ? "full sweep" : `${r.repos_read} read, ${r.repos_kept} unchanged`}), ${r.calls} API calls of which ${r.not_modified} answered 304 (free)${r.errors.length ? `, ${r.errors.length} sections failed` : ""}`);
      githubProgress.errors = r.errors.length;
      console.log(`[github] ${r.org.login}: ${r.members} members, ${r.collaborators} outside collaborators, ${r.teams} teams, ${r.repos} repos, ${r.credentials} credentials, ${r.apps} apps, ${r.secrets} secret names, ${r.audit} audit events in ${r.calls} calls, ${r.took_ms} ms${r.errors.length ? `; ${r.errors.length} sections refused or failed` : ""}`);
      return { errors: r.errors };
    } catch (e: any) { progressEnd(`failed: ${String(e?.message || e).slice(0, 200)}`); return { errors: [String(e?.message || e)] }; }
    finally { if (githubProgress.running) progressEnd("stopped"); }
  },
  resources: (account) => githubResources(account),
  owns: (id) => id === githubAdapter.primaryAccountId() || Boolean(db.prepare("select 1 from github_org where id = ?").get(id)),
  accountOf(resource, details) {
    const d = (details ?? {}) as Record<string, unknown>;
    if (typeof d.org_id === "string" && d.org_id) return d.org_id;
    const r = String(resource ?? ""); const org = githubOrgRow();
    return org && (r.startsWith(`${org.node_id}/`) || r.startsWith("github:")) ? org.node_id : null;
  },
  rules: {
    latestRunId: (account) => (db.prepare("select id from runs where provider = 'github' and account_id = ? and status = 'completed' order by id desc limit 1").get(account ?? githubAdapter.primaryAccountId()) as { id: number } | undefined)?.id,
    benchmarks: () => ({ all: [], defaults: [] }),
    start: async () => { const r = await (await import("./rules.js")).runGitHubRules(); return { run_id: r.run_id, note: `${r.findings} findings` }; },
    run_native_type: "rules_pass",
    control_prefixes: ["github."],
    controlForRule: (rule) => (/^github_/.test(rule) ? rule.replace(/^github_/, "github.control.") : null),
    controlFacts: (controlId) => {
      const id = controlId.toLowerCase(); if (!id.startsWith("github.control.")) return null;
      return { framework: "advisor", category: /seat|unused_seat|copilot/.test(id) ? "cost" : "security" };
    },
    controlSources: () => rulesRef?.CONTROL_REFERENCES ?? {},
    playbooks_from: "all",
    seed_playbooks: false,
  },
  onboarding: githubOnboarding,
  agentNote: () => { const o = githubOrgRow(); return o ? `GitHub org ${o.login} (${o.node_id}; the Steampipe github connection: github.github_organization_member, github_team_member, github_repository_collaborator, github_audit_log… with organization = '${o.login}'; the advisor's github_members, github_repo_access, github_credentials, github_usage; graph_query with account_id '${o.node_id}')` : null; },
  onStart() { import("./steampipe.js").then((m) => { const r = m.ensureGitHubConnection(); if (r !== "skipped" && r !== "unchanged") console.log(`[github] steampipe connection ${r}`); }).catch((e) => console.error(`[github] steampipe connection: ${e?.message || e}`)); },
  routes: async () => [(await import("../../routes/github.js")).github],
  cost: {
    refresh: async () => ({ refreshed: false, note: "read with the GitHub collection" }),
    lastBill: (account) => { const m = githubMonth(account); return { month: m.last_month, usd: m.last_month_usd }; },
    month: async () => {
      if (!githubConfigured()) return [];
      const m = githubMonth(githubAdapter.primaryAccountId());
      return [{ key: "github_month", label: "GitHub this month", usd: m.projected_usd, to_total: true, month_to_date_usd: m.month_to_date_usd }];
    },
    accounts: async () => {
      if (!githubConfigured()) return [];
      const m = githubMonth(githubAdapter.primaryAccountId());
      const note = [m.seats != null ? `${m.seats} seats × ${m.seat_usd} USD${m.unused_seats ? ` (${m.unused_seats} unused)` : ""}${m.seats_itemised ? ", itemised in the usage" : ""}` : null, m.usage_read ? `metered ${m.metered_usd} USD so far` : "metered usage not readable"].filter(Boolean).join(" · ");
      return [{ account: githubAdapter.primaryAccountId(), month_to_date_usd: m.month_to_date_usd, projected_usd: m.projected_usd, last_month_usd: m.last_month_usd, last_month: m.last_month, history: m.history, note }];
    },
  },
  attention: async () => {
    if (!githubConfigured()) return [];
    const org = githubAdapter.primaryAccountId();
    const { latestGitHubFindings } = await import("./rules.js");
    return latestGitHubFindings(org).findings.filter((f) => f.severity !== "info").slice(0, 20).map((f) => ({ account: org, level: f.severity, what: f.reason, link: "/findings" }));
  },
  purgeStorage(account, { dryRun }) {
    const out: Record<string, number> = {};
    for (const t of GITHUB_TABLES) {
      const col = t === "github_org" ? "id" : "org_id";
      const n = dryRun ? (db.prepare(`select count(*) as n from ${t} where ${col} = ?`).get(account) as { n: number }).n : db.prepare(`delete from ${t} where ${col} = ?`).run(account).changes;
      if (n) out[t] = n;
    }
    if (!dryRun) db.prepare("delete from settings where key in (?, ?)").run(`github_extras:${account}`, `github_snapshot:${account}`);
    return out;
  },
  jobs: [{
    key: "githubCron", label: "GitHub collection", schedule_name: "GitHub collection (GITHUB_CRON)", tag: "github", cron: () => config.githubCron,
    blocked: () => (githubConfigured() ? null : "skipped: no GitHub App (Settings > Accounts)"),
    run: async () => {
      const r = await githubAdapter.collect();
      return r.errors.length ? `collected; ${r.errors.length} section(s) refused or failed: ${r.errors[0]}` : "collected and mirrored";
    },
  }],
  ui: {
    overview: "github.overview", bill: "github.bill", changes: "github.changes",
    inventory: [{ tab: "identities", view: "github.members", label: "GitHub people" }, { tab: "repositories", view: "github.repos", label: "GitHub repositories" }, { tab: "credentials", view: "github.credentials", label: "GitHub credentials" }],
    settings: [{ id: "access", label: "Access", view: "github.access" }],
  },
  layers: [{ name: "github repositories and access", mirror: async () => (await import("./graph.js")).mirrorGitHub() }],
};

// the rules module is loaded lazily (it reaches the findings tables); its references are read once it is
let rulesRef: { CONTROL_REFERENCES: Record<string, string[]> } | null = null;
import("./rules.js").then((m) => { rulesRef = m; }).catch(() => {});

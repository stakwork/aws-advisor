import { Router } from "express";
import { authMiddleware } from "../auth.js";
import { config } from "../config.js";
import { githubAdapter, githubConfigured, githubMonth } from "../adapters/github/index.js";
import { auditActivity, githubExtras, githubProgress, githubOrgRow, listApps, listCopilotSeats, listCredentials, listHooks, listMembers, listRepoAccess, listRepos, listSecrets, listTeams, usageHistory } from "../adapters/github/inventory.js";
import { listChanges } from "../adapters/github/changes.js";
import { latestGitHubFindings } from "../adapters/github/rules.js";
import { GITHUB_APP_PERMISSIONS } from "../adapters/github/setup.js";

/**
 * The GitHub org (Settings › Accounts › GitHub and its pages): the org at a glance, its people with their access and
 * credentials, the repositories and who can write to each, the credentials, Apps and secret names, the bill, the
 * changes, and a refresh on demand. The App's private key is a runtime secret; it is never returned.
 */
export const github = Router();
github.use(authMiddleware);

const RANK: Record<string, number> = { read: 1, triage: 2, write: 3, maintain: 4, admin: 5 };
const stronger = (a: string | null, b: string | null) => ((RANK[b ?? ""] ?? 0) > (RANK[a ?? ""] ?? 0) ? b : a);

/** Every person's effective permission on every repository and how they got it (direct, a team, the base permission). */
function effectiveAccess(orgId: string) {
  const org = githubOrgRow(); const base = org?.default_permission && org.default_permission !== "none" ? org.default_permission : null;
  const repos = listRepos(orgId); const people = listMembers(orgId); const teams = listTeams(orgId);
  const out = new Map<string, Map<string, { permission: string | null; via: string[] }>>();
  const grant = (login: string, repo: string, perm: string | null, via: string) => { const m = out.get(login) ?? new Map(); out.set(login, m); const cur = m.get(repo) ?? { permission: null, via: [] }; cur.permission = stronger(cur.permission, perm); cur.via.push(`${via}${perm ? `: ${perm}` : ""}`); m.set(repo, cur); };
  for (const a of listRepoAccess(orgId)) grant(a.login, a.repo, a.permission, "direct");
  for (const t of teams) for (const r of t.repos) for (const m of t.members) grant(m.login, r.repo, r.permission, `team ${t.slug}`);
  if (base) for (const p of people.filter((x) => x.kind === "member")) for (const r of repos) grant(p.login, r.full_name, base, "base permission");
  // owners administer every repository
  for (const p of people.filter((x) => x.role === "admin")) for (const r of repos) grant(p.login, r.full_name, "admin", "owner");
  return out;
}

github.get("/github/overview", async (_req, res) => {
  if (!githubConfigured()) return res.json({ configured: false });
  const org = githubOrgRow(); if (!org) return res.json({ configured: true, org: null, note: "not read yet: the first collection runs right after the App is saved" });
  const orgId = org.node_id; const x = githubExtras(orgId); const people = listMembers(orgId); const creds = listCredentials(orgId);
  res.json({ configured: true, org, sections: x.sections, read_at: x.read_at, audit_since: x.audit_since,
    counts: { members: people.filter((p) => p.kind === "member").length, owners: people.filter((p) => p.role === "admin").length, collaborators: people.filter((p) => p.kind === "collaborator").length, without_2fa: people.filter((p) => p.mfa === false).length, teams: listTeams(orgId).length, repos: listRepos(orgId).length, private_repos: listRepos(orgId).filter((r) => r.private).length, apps: listApps(orgId).length, secrets: listSecrets(orgId).length, deploy_keys: creds.filter((c) => c.kind === "deploy_key").length, tokens: creds.filter((c) => c.kind === "pat" || c.kind === "credential_authorization").length, copilot_seats: listCopilotSeats(orgId).length, invitations: x.invitations.filter((i) => !i.failed_at).length },
    month: githubMonth(orgId), findings: latestGitHubFindings(orgId), copilot: x.copilot });
});

github.get("/github/members", (_req, res) => {
  if (!githubConfigured()) return res.json({ configured: false, people: [] });
  const org = githubOrgRow(); if (!org) return res.json({ configured: true, people: [] });
  const orgId = org.node_id; const act = auditActivity(orgId); const access = effectiveAccess(orgId); const teams = listTeams(orgId); const creds = listCredentials(orgId); const copilot = new Map(listCopilotSeats(orgId).map((s) => [s.login.toLowerCase(), s]));
  const people = listMembers(orgId).map((m) => {
    const a = act.get(m.login); const repos = [...(access.get(m.login) ?? new Map()).entries()].map(([repo, v]) => ({ repo, ...v })).sort((x, y) => (RANK[y.permission ?? ""] ?? 0) - (RANK[x.permission ?? ""] ?? 0) || x.repo.localeCompare(y.repo));
    return { login: m.login, kind: m.kind, role: m.kind === "member" ? (m.role === "admin" ? "owner" : "member") : "outside collaborator", name: m.name, company: m.company, mfa: m.mfa, teams: teams.filter((t) => t.members.some((x) => x.login === m.login)).map((t) => t.slug),
      copilot: copilot.get(m.login.toLowerCase()) ?? null, last_activity_at: a?.last_at ?? null, events_90d: a?.events ?? 0, clients: (a?.user_agents ?? []).slice(-5), access_types: a?.access_types ?? [],
      repos: { admin: repos.filter((r) => r.permission === "admin" || r.permission === "maintain").length, write: repos.filter((r) => r.permission === "write").length, read: repos.filter((r) => r.permission === "read" || r.permission === "triage").length, list: repos },
      credentials: creds.filter((c) => c.holder?.toLowerCase() === m.login.toLowerCase() && c.kind !== "deploy_key") };
  });
  res.json({ configured: true, org: { login: org.login, seats: org.seats, filled_seats: org.filled_seats, two_factor_required: org.two_factor_required, default_permission: org.default_permission }, people, invitations: githubExtras(orgId).invitations, audit_ok: Boolean(githubExtras(orgId).sections.audit_log?.ok) });
});

github.get("/github/repos", (_req, res) => {
  if (!githubConfigured()) return res.json({ configured: false, repos: [] });
  const org = githubOrgRow(); if (!org) return res.json({ configured: true, repos: [] });
  const orgId = org.node_id; const access = effectiveAccess(orgId); const creds = listCredentials(orgId); const secrets = listSecrets(orgId); const teams = listTeams(orgId); const outside = new Set(listMembers(orgId).filter((m) => m.kind === "collaborator").map((m) => m.login));
  const repos = listRepos(orgId).map((r) => {
    const who = [...access.entries()].map(([login, m]) => ({ login, outside: outside.has(login), ...(m.get(r.full_name) ?? { permission: null, via: [] }) })).filter((x) => x.permission).sort((a, b) => (RANK[b.permission ?? ""] ?? 0) - (RANK[a.permission ?? ""] ?? 0) || a.login.localeCompare(b.login));
    return { ...r, people: who, teams: teams.filter((t) => t.repos.some((x) => x.repo === r.full_name)).map((t) => ({ slug: t.slug, permission: t.repos.find((x) => x.repo === r.full_name)?.permission ?? null })), deploy_keys: creds.filter((c) => c.kind === "deploy_key" && c.holder === r.full_name), secrets: secrets.filter((s) => s.repo === r.full_name || (s.scope === "org" && (s.visibility === "all" || (s.visibility === "private" && r.private) || s.selected_repos.includes(r.full_name)))).map((s) => ({ name: s.name, scope: s.scope, environment: s.environment, kind: s.kind })) };
  });
  // newest push first; never-pushed repositories last
  repos.sort((a, b) => String(b.pushed_at ?? "").localeCompare(String(a.pushed_at ?? "")) || a.full_name.localeCompare(b.full_name));
  res.json({ configured: true, base_permission: org.default_permission, repos });
});

github.get("/github/credentials", (_req, res) => {
  if (!githubConfigured()) return res.json({ configured: false });
  const org = githubOrgRow(); if (!org) return res.json({ configured: true, credentials: [], apps: [], secrets: [], hooks: [] });
  const orgId = org.node_id; const act = auditActivity(orgId);
  // which tokens the audit log saw in use, by its hashed token and the actor (the API gives no hash of a fine-grained token, so the actor's token use is shown beside it)
  res.json({ configured: true, credentials: listCredentials(orgId), apps: listApps(orgId), secrets: listSecrets(orgId), hooks: listHooks(orgId), token_use: [...act.values()].filter((a) => a.tokens.length).map((a) => ({ actor: a.actor, tokens: a.tokens })), sections: githubExtras(orgId).sections });
});

github.get("/github/bill", (_req, res) => { if (!githubConfigured() || !githubOrgRow()) return res.json({ configured: githubConfigured() }); res.json({ configured: true, ...githubMonth(githubOrgRow()!.node_id), usage_history: usageHistory(githubOrgRow()!.node_id), copilot: githubExtras(githubOrgRow()!.node_id).copilot, copilot_seats: listCopilotSeats(githubOrgRow()!.node_id) }); });
github.get("/github/changes", (req, res) => { const org = githubOrgRow(); res.json({ configured: githubConfigured(), changes: org ? listChanges(org.node_id, Math.min(1000, Number(req.query.limit) || 200)) : [] }); });

/** What the Settings form needs to help create the App: the permissions to tick, and what is saved now (never the key). */
github.get("/github/setup", (_req, res) => res.json({ configured: githubConfigured(), org: config.githubOrg || null, app_id: config.githubAppId || null, installation_id: config.githubInstallationId || null, key_saved: Boolean(config.githubAppPrivateKey), permissions: GITHUB_APP_PERMISSIONS, sections: githubOrgRow() ? githubExtras(githubOrgRow()!.node_id).sections : {} }));

/** Starts a collection (it mirrors the graph at its end) and answers at once; ?wait=1 answers when it is done; ?full=1 re-reads every repository. Follow it on GET /github/progress. */
github.post("/github/refresh", async (req, res) => {
  if (!githubConfigured()) return res.status(400).json({ error: "GitHub is not configured" });
  if (githubProgress.running) return res.status(409).json({ error: "a GitHub collection is already running", progress: githubProgress });
  // ?full=1 reads every repository again (otherwise only the new ones and the ones the audit log shows changed, plus a daily full sweep)
  const run = githubAdapter.collect({ full: req.query.full === "1" });
  if (req.query.wait === "1") { const r = await run; return res.json({ ok: !r.errors.length, errors: r.errors }); }
  run.catch(() => {});
  res.status(202).json({ started: true });
});

/** What the collection is doing now (or did last): the step, repositories done of all, calls, the last log lines. */
github.get("/github/progress", (_req, res) => res.json(githubProgress));

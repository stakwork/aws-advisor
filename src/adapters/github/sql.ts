import { emailKey, permissionOf, type GitHubAuditEvent, type GitHubCollaborator, type GitHubOrg, type GitHubRepo, type GitHubSecret, type GitHubTeam, type GitHubUser } from "./client.js";
import { CONNECTION } from "./steampipe.js";

/**
 * The GitHub reads Steampipe has tables for (plugin turbot/github, connection `github`), in the same shapes the REST
 * client returns, so the refresh (./inventory.ts) takes each section from here first and from the API only where no
 * table exists. `q` runs one query (src/steampipe.ts query; a fake in tests).
 */

type Q = (sql: string, params?: unknown[]) => Promise<any[]>;
const s = CONNECTION;
const str = (v: unknown): string | null => (v == null || v === "" ? null : String(v));
const iso = (v: unknown): string | null => (v == null ? null : v instanceof Date ? v.toISOString() : /^\d{4}-/.test(String(v)) ? String(v) : null);
const lower = (v: unknown): string | null => (v == null ? null : String(v).toLowerCase());
/** A login as the plugin returns it: a string in some tables, a user object ({login, …}) in others (user_login of the collaborator and identity tables). Pure. */
export const loginOf = (v: unknown): string | null => { if (v == null) return null; if (typeof v === "object") { const l = (v as any).login; return l ? String(l) : null; } const t = String(v); if (t.startsWith("{")) { try { return loginOf(JSON.parse(t)); } catch { return t; } } return t || null; };
const obj = (v: unknown): any => { if (v == null) return null; if (typeof v === "string") { try { return JSON.parse(v); } catch { return null; } } return v; };

/** A Steampipe error as an HTTP-like status where the message carries one (a 403 or 404 from GitHub behind the plugin), for the section's record. */
export function statusOf(e: unknown): number | null {
  const m = String((e as any)?.message ?? e).match(/\b(401|403|404|422)\b/); if (m) return Number(m[1]);
  if (/not accessible by integration|forbidden|permission/i.test(String((e as any)?.message ?? e))) return 403;
  return null;
}
export class SteampipeSectionError extends Error { constructor(readonly status: number | null, msg: string) { super(msg); } }
const wrap = async <T,>(fn: () => Promise<T>): Promise<T> => { try { return await fn(); } catch (e: any) { throw new SteampipeSectionError(statusOf(e), `steampipe: ${String(e?.message || e).slice(0, 220)}`); } };

export class GitHubSql {
  constructor(readonly org: string, private readonly q: Q) {}

  orgInfo(): Promise<GitHubOrg> {
    return wrap(async () => {
      const [r] = await this.q(`select login, id, node_id, name, created_at, plan_name, plan_seats, plan_filled_seats, plan_private_repos, two_factor_requirement_enabled, default_repo_permission, members_can_create_repos, members_can_create_public_repos, web_commit_signoff_required from ${s}.github_organization where login = $1`, [this.org]);
      if (!r) throw new Error(`404 the org ${this.org} is not visible to the connection`);
      return { id: Number(r.id), node_id: String(r.node_id), login: String(r.login), name: str(r.name), plan: str(r.plan_name), seats: r.plan_seats ?? null, filled_seats: r.plan_filled_seats ?? null, private_repos: r.plan_private_repos ?? null, two_factor_required: typeof r.two_factor_requirement_enabled === "boolean" ? r.two_factor_requirement_enabled : null, default_permission: lower(r.default_repo_permission), members_can_create_repositories: r.members_can_create_repos ?? null, members_can_create_public_repositories: r.members_can_create_public_repos ?? null, web_commit_signoff_required: r.web_commit_signoff_required ?? null, created_at: iso(r.created_at) };
    });
  }
  /** Members with their role and 2FA (null when the App may not see it) and their public profile in one read. */
  members(): Promise<{ login: string; id: number; role: "admin" | "member"; mfa: boolean | null; profile: GitHubUser }[]> {
    return wrap(async () => (await this.q(`select login, id, role, has_two_factor_enabled, name, email, company, created_at from ${s}.github_organization_member where organization = $1`, [this.org])).map((r) => ({
      login: String(r.login), id: Number(r.id), role: String(r.role).toUpperCase() === "ADMIN" ? "admin" as const : "member" as const, mfa: typeof r.has_two_factor_enabled === "boolean" ? r.has_two_factor_enabled : null,
      profile: { login: String(r.login), id: Number(r.id), name: str(r.name), email_key: emailKey(r.email), company: str(r.company), created_at: iso(r.created_at), type: "User" },
    })));
  }
  /** Outside collaborators, each with the repositories and permissions the org gives them. */
  outsideCollaborators(): Promise<{ login: string; repos: { repo: string; permission: string | null }[] }[]> {
    return wrap(async () => {
      const by = new Map<string, { repo: string; permission: string | null }[]>();
      for (const r of await this.q(`select user_login, repository_name, permission from ${s}.github_organization_collaborator where organization = $1 and affiliation = 'OUTSIDE'`, [this.org])) { const login = loginOf(r.user_login); if (!login) continue; by.set(login, [...(by.get(login) ?? []), { repo: String(r.repository_name).includes("/") ? String(r.repository_name) : `${this.org}/${r.repository_name}`, permission: permissionOf(null, lower(r.permission)) }]); }
      return [...by.entries()].map(([login, repos]) => ({ login, repos }));
    });
  }
  user(login: string): Promise<GitHubUser> {
    return wrap(async () => { const [r] = await this.q(`select login, id, name, email, company, created_at from ${s}.github_user where login = $1`, [login]); return { login, id: Number(r?.id ?? 0), name: str(r?.name), email_key: emailKey(r?.email), company: str(r?.company), created_at: iso(r?.created_at), type: "User" }; });
  }
  teams(): Promise<GitHubTeam[]> {
    return wrap(async () => {
      const out: GitHubTeam[] = [];
      for (const t of await this.q(`select slug, name, id, privacy, parent_team from ${s}.github_team where organization = $1`, [this.org])) {
        const members = (await this.q(`select login, role from ${s}.github_team_member where organization = $1 and slug = $2`, [this.org, t.slug])).map((m) => ({ login: String(m.login), role: String(m.role).toUpperCase() === "MAINTAINER" ? "maintainer" as const : "member" as const }));
        const repos = (await this.q(`select name_with_owner, permission from ${s}.github_team_repository where organization = $1 and slug = $2`, [this.org, t.slug])).map((r) => ({ repo: String(r.name_with_owner), permission: permissionOf(null, lower(r.permission)) }));
        out.push({ id: Number(t.id), slug: String(t.slug), name: String(t.name), privacy: lower(t.privacy), parent: str(obj(t.parent_team)?.slug), members, repos });
      }
      return out;
    });
  }
  repos(): Promise<GitHubRepo[]> {
    return wrap(async () => (await this.q(`select name, name_with_owner, id, node_id, is_private, visibility, is_archived, is_fork, default_branch_ref, pushed_at, created_at, url from ${s}.github_search_repository where query = $1`, [`org:${this.org} fork:true`])).map((r) => ({
      id: Number(r.id), node_id: String(r.node_id), name: String(r.name), full_name: String(r.name_with_owner), private: Boolean(r.is_private), visibility: lower(r.visibility), archived: Boolean(r.is_archived), fork: Boolean(r.is_fork), default_branch: str(obj(r.default_branch_ref)?.name), pushed_at: iso(r.pushed_at), created_at: iso(r.created_at), html_url: str(r.url),
    })));
  }
  collaborators(repo: string): Promise<GitHubCollaborator[]> {
    return wrap(async () => (await this.q(`select user_login, permission from ${s}.github_repository_collaborator where repository_full_name = $1 and affiliation = 'DIRECT'`, [repo])).filter((c) => loginOf(c.user_login)).map((c) => ({ repo, login: loginOf(c.user_login)!, permission: permissionOf(null, lower(c.permission)), role_name: lower(c.permission) })));
  }
  repoActionsSecrets(repo: string): Promise<GitHubSecret[]> {
    return wrap(async () => (await this.q(`select name, created_at, updated_at from ${s}.github_actions_repository_secret where repository_full_name = $1`, [repo])).map((x) => ({ scope: "repo" as const, kind: "actions" as const, repo, environment: null, name: String(x.name), visibility: null, selected_repos: [], created_at: iso(x.created_at), updated_at: iso(x.updated_at) })));
  }
  environments(repo: string): Promise<string[]> { return wrap(async () => (await this.q(`select name from ${s}.github_repository_environment where repository_full_name = $1`, [repo])).map((r) => String(r.name))); }
  /** The SAML identity linked to each member (Enterprise with SAML SSO): the identity provider's name id and e-mail, reduced to match keys. */
  samlIdentities(): Promise<{ login: string; name_id_key: string | null; email_keys: string[] }[]> {
    return wrap(async () => (await this.q(`select user_login, saml_identity from ${s}.github_organization_external_identity where organization = $1`, [this.org])).filter((r) => loginOf(r.user_login)).map((r) => { const id = obj(r.saml_identity) ?? {}; const emails = Array.isArray(id.emails) ? id.emails.map((e: any) => emailKey(e?.value ?? e)).filter(Boolean) : []; return { login: loginOf(r.user_login)!, name_id_key: emailKey(id.name_id ?? id.nameId ?? id.username), email_keys: emails }; }));
  }
  /** Audit log events since a day; the client, token and address details live in the event's data. */
  audit(sinceDay: string, max = 20_000): Promise<GitHubAuditEvent[]> {
    return wrap(async () => (await this.q(`select id, created_at, action, actor, user_login, repo, team, actor_location, data from ${s}.github_audit_log where organization = $1 and phrase = $2 and include = 'all' limit ${Math.floor(max)}`, [this.org, `created:>=${sinceDay}`])).map((r) => {
      const d = obj(r.data) ?? {}; const loc = obj(r.actor_location) ?? {};
      return { id: String(r.id ?? d._document_id), at: iso(r.created_at) ?? new Date(0).toISOString(), action: String(r.action), actor: loginOf(r.actor), user: loginOf(r.user_login ?? d.user), repo: str(r.repo ?? d.repo), team: str(r.team ?? d.team), ip: str(d.actor_ip), country: str(loc.country_code ?? d.actor_location?.country_code), user_agent: str(d.user_agent), access_type: str(d.programmatic_access_type), hashed_token: str(d.hashed_token), token_id: d.token_id ?? null, operation: str(d.operation_type) };
    }));
  }
}

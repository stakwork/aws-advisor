import { createHash, createSign } from "node:crypto";

/**
 * A thin GitHub REST client for the adapter: a read-only GitHub App installed on the org, the App's JWT traded for an
 * installation token (kept until a minute before it expires), `Link` pagination, and a fetch that can be replaced in
 * tests. Only reads. Secret values never exist on the API (only names); public keys are reduced to their SHA256
 * fingerprint and webhook URLs to their host before they leave this module; e-mail addresses to their match key.
 */

export const GITHUB_API = "https://api.github.com";
const API_VERSION = "2022-11-28";

export interface GitHubAppAuth { appId: string; installationId: string; privateKey: string }
/**
 * Where the client keeps the last answer of each GET (its ETag, body and next-page link), so the next identical request
 * is conditional: GitHub answers 304 when nothing changed, and a 304 does not count against the rate limit.
 */
export interface GitHubHttpCache { get(url: string): { etag: string; body: string; next: string | null } | null; set(url: string, v: { etag: string; body: string; next: string | null }): void }
export interface GitHubClientOptions { org: string; app?: GitHubAppAuth; token?: string; fetchImpl?: typeof fetch; base?: string; now?: () => number; cache?: GitHubHttpCache | null }

/** A call GitHub refused: the status says whether a permission is missing (403), a feature is off (404) or the input is wrong (422). */
export class GitHubError extends Error { constructor(readonly path: string, readonly status: number, body: string) { super(`GitHub ${path}: HTTP ${status}${body ? ` ${body}` : ""}`); } }

/**
 * A private key as pasted: a .pem with its line breaks, or the same squeezed onto one line by a password field
 * (spaces or literal `\n` in place of the breaks). The body is re-wrapped at 64 columns between its armour lines. Pure.
 */
export function normalisePem(raw: string): string {
  const s = String(raw ?? "").replace(/\\n/g, "\n").trim();
  const m = s.match(/-----BEGIN ([A-Z ]+)-----([\s\S]*?)-----END \1-----/);
  if (!m) return s;
  const body = m[2].replace(/\s+/g, "");
  return `-----BEGIN ${m[1]}-----\n${body.match(/.{1,64}/g)!.join("\n")}\n-----END ${m[1]}-----\n`;
}

const b64url = (b: Buffer | string) => Buffer.from(b).toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");

/** The App's JWT (RS256, issued a minute in the past for clock drift, valid nine minutes), as GitHub asks for it. */
export function appJwt(appId: string, privateKey: string, nowMs = Date.now()): string {
  const iat = Math.floor(nowMs / 1000) - 60;
  const head = b64url(JSON.stringify({ alg: "RS256", typ: "JWT" })); const body = b64url(JSON.stringify({ iat, exp: iat + 600, iss: appId }));
  const sig = createSign("RSA-SHA256").update(`${head}.${body}`).sign(normalisePem(privateKey));
  return `${head}.${body}.${b64url(sig)}`;
}

/** The SHA256 fingerprint of an OpenSSH public key line (`ssh-ed25519 AAAA… comment`), as `ssh-keygen -lf` prints it; null when it does not parse. Pure. */
export function sshFingerprint(key: string | null | undefined): string | null {
  const parts = String(key ?? "").trim().split(/\s+/); if (parts.length < 2 || !/^[A-Za-z0-9+/=]+$/.test(parts[1])) return null;
  return `SHA256:${createHash("sha256").update(Buffer.from(parts[1], "base64")).digest("base64").replace(/=+$/, "")}`;
}
/** The algorithm of an OpenSSH public key line (`ed25519`, `rsa`, `ecdsa`). Pure. */
export const sshKind = (key: string | null | undefined): string | null => { const t = String(key ?? "").trim().split(/\s+/)[0] ?? ""; return t ? t.replace(/^ssh-/, "").replace(/^ecdsa-sha2-.*/, "ecdsa") : null; };
/** An e-mail reduced for matching people (the address itself is not kept): the local part, letters and digits. Pure. */
export const emailKey = (e: unknown): string | null => { const s = String(e ?? "").toLowerCase().split("@")[0].replace(/[^a-z0-9]/g, ""); return s.length >= 3 ? s : null; };
const hostOf = (u: unknown): string | null => { try { return new URL(String(u)).host || null; } catch { return null; } };
const str = (v: unknown): string | null => (v == null || v === "" ? null : String(v));
const iso = (v: unknown): string | null => { if (v == null || v === "") return null; if (typeof v === "number") return new Date(v).toISOString(); const s = String(v); return /^\d{4}-/.test(s) ? s : null; };

export type RepoPermission = "admin" | "maintain" | "write" | "triage" | "read";
/** The strongest permission in GitHub's `permissions` object (`push` is write, `pull` read), or the custom role's name. Pure. */
export function permissionOf(p: any, roleName?: unknown): RepoPermission | null {
  const rn = String(roleName ?? "").toLowerCase();
  if (["admin", "maintain", "write", "triage", "read"].includes(rn)) return rn as RepoPermission;
  if (!p) return rn === "pull" ? "read" : rn === "push" ? "write" : null;
  return p.admin ? "admin" : p.maintain ? "maintain" : p.push ? "write" : p.triage ? "triage" : p.pull ? "read" : null;
}

export interface GitHubOrg { id: number; node_id: string; login: string; name: string | null; plan: string | null; seats: number | null; filled_seats: number | null; private_repos: number | null; two_factor_required: boolean | null; default_permission: string | null; members_can_create_repositories: boolean | null; members_can_create_public_repositories: boolean | null; web_commit_signoff_required: boolean | null; created_at: string | null }
export interface GitHubUser { login: string; id: number; name: string | null; email_key: string | null; company: string | null; created_at: string | null; type: string | null }
export interface GitHubTeam { id: number; slug: string; name: string; privacy: string | null; parent: string | null; members: { login: string; role: "maintainer" | "member" }[]; repos: { repo: string; permission: RepoPermission | null }[] }
export interface GitHubRepo { id: number; node_id: string; name: string; full_name: string; private: boolean; visibility: string | null; archived: boolean; fork: boolean; default_branch: string | null; pushed_at: string | null; created_at: string | null; html_url: string | null }
export interface GitHubCollaborator { repo: string; login: string; permission: RepoPermission | null; role_name: string | null }
export interface GitHubDeployKey { repo: string; id: number; title: string | null; fingerprint: string | null; key_kind: string | null; read_only: boolean; verified: boolean | null; added_by: string | null; created_at: string | null; last_used: string | null; enabled: boolean | null }
export interface GitHubPat { id: number; token_id: number | null; name: string | null; owner: string | null; repository_selection: string | null; repos: string[]; permissions: Record<string, Record<string, string>>; granted_at: string | null; expires_at: string | null; expired: boolean; last_used_at: string | null }
export interface GitHubPatRequest { id: number; token_id: number | null; name: string | null; owner: string | null; reason: string | null; created_at: string | null; expires_at: string | null; repository_selection: string | null; permissions: Record<string, Record<string, string>> }
export interface GitHubCredentialAuthorization { login: string; credential_id: number; type: string; token_last_eight: string | null; fingerprint: string | null; title: string | null; scopes: string[]; authorized_at: string | null; accessed_at: string | null; expires_at: string | null }
export interface GitHubSshKey { login: string; id: number; fingerprint: string | null; key_kind: string | null }
export interface GitHubInstallation { id: number; app_id: number; app_slug: string; repository_selection: string | null; permissions: Record<string, string>; events: string[]; created_at: string | null; updated_at: string | null; suspended_at: string | null }
export interface GitHubSecret { scope: "org" | "repo" | "environment"; kind: "actions" | "dependabot"; repo: string | null; environment: string | null; name: string; visibility: string | null; selected_repos: string[]; created_at: string | null; updated_at: string | null }
export interface GitHubHook { id: number; repo: string | null; name: string | null; active: boolean; events: string[]; host: string | null; insecure_ssl: boolean; created_at: string | null; updated_at: string | null }
export interface GitHubInvitation { id: number; login: string | null; email_key: string | null; role: string | null; created_at: string | null; inviter: string | null; failed_at: string | null; failed_reason: string | null; source: string | null }
export interface GitHubCopilot { plan_type: string | null; seat_management: string | null; seats_total: number | null; seats_active: number | null; seats_inactive: number | null; pending_cancellation: number | null; pending_invitation: number | null }
export interface GitHubCopilotSeat { login: string; plan_type: string | null; created_at: string | null; last_activity_at: string | null; last_activity_editor: string | null; pending_cancellation_date: string | null; team: string | null }
export interface GitHubUsageItem { date: string; product: string; sku: string; quantity: number; unit: string | null; price_per_unit: number | null; gross_usd: number; discount_usd: number; net_usd: number; repo: string | null }
/** One audit log event, reduced: who, what, where from, with which client and which kind of credential. */
export interface GitHubAuditEvent { id: string; at: string; action: string; actor: string | null; user: string | null; repo: string | null; team: string | null; ip: string | null; country: string | null; user_agent: string | null; access_type: string | null; hashed_token: string | null; token_id: number | null; operation: string | null }

export class GitHubClient {
  readonly org: string; private readonly app: GitHubAppAuth | null; private readonly fixed: string | null; private readonly f: typeof fetch; private readonly base: string; private readonly now: () => number;
  private cached: { token: string; until: number } | null = null;
  /** calls made, for the collection's log line; `not_modified` of them were answered 304 from the cache (free) */
  calls = 0; not_modified = 0;
  private readonly cache: GitHubHttpCache | null;
  constructor(o: GitHubClientOptions) { this.org = o.org; this.app = o.app ?? null; this.fixed = o.token ?? null; this.f = o.fetchImpl ?? fetch; this.base = o.base ?? GITHUB_API; this.now = o.now ?? Date.now; this.cache = o.cache ?? null; }

  /** The installation token (minted from the App's JWT and kept until a minute before its expiry), or the fixed token tests pass. */
  async token(): Promise<string> {
    if (this.fixed) return this.fixed;
    if (!this.app) throw new Error("GitHub: no App credentials");
    if (this.cached && this.cached.until > this.now()) return this.cached.token;
    const path = `/app/installations/${encodeURIComponent(this.app.installationId)}/access_tokens`;
    const res = await this.f(`${this.base}${path}`, { method: "POST", headers: { authorization: `Bearer ${appJwt(this.app.appId, this.app.privateKey, this.now())}`, accept: "application/vnd.github+json", "x-github-api-version": API_VERSION, "user-agent": "cloud-advisor" }, signal: AbortSignal.timeout(30_000) });
    this.calls++;
    if (!res.ok) throw new GitHubError(path, res.status, (await res.text()).slice(0, 300));
    const j: any = await res.json();
    this.cached = { token: String(j.token), until: (Date.parse(j.expires_at) || this.now() + 3_600_000) - 60_000 };
    return this.cached.token;
  }

  private async raw(pathOrUrl: string, params: Record<string, string | number | undefined> = {}): Promise<{ body: any; next: string | null }> {
    const u = new URL(/^https?:/.test(pathOrUrl) ? pathOrUrl : `${this.base}${pathOrUrl}`);
    for (const [k, v] of Object.entries(params)) if (v != null && v !== "") u.searchParams.set(k, String(v));
    const url = u.toString();
    // the audit log is read by date and never repeats a page: no point keeping it
    const cached = this.cache && !/\/audit-log/.test(u.pathname) ? this.cache.get(url) : null;
    for (let attempt = 0; ; attempt++) {
      let res: Response;
      const headers: Record<string, string> = { authorization: `Bearer ${await this.token()}`, accept: "application/vnd.github+json", "x-github-api-version": API_VERSION, "user-agent": "cloud-advisor" };
      if (cached) headers["if-none-match"] = cached.etag;
      try { res = await this.f(url, { headers, signal: AbortSignal.timeout(30_000) }); }
      catch (e: any) {
        // a dropped connection or a timeout (fetch failed, ECONNRESET, aborted): retried three times with a growing pause; a refusal from GitHub is not retried
        if (attempt < 3 && !(e instanceof GitHubError)) { await new Promise((r) => setTimeout(r, 1_000 * 2 ** attempt)); continue; }
        throw e;
      }
      this.calls++;
      // a secondary or primary rate limit: wait as told (at most a minute) and try twice more
      if ((res.status === 403 || res.status === 429) && attempt < 2 && (res.headers.get("retry-after") || res.headers.get("x-ratelimit-remaining") === "0")) {
        const reset = Number(res.headers.get("x-ratelimit-reset")) * 1000; const wait = Number(res.headers.get("retry-after")) * 1000 || (reset ? reset - Date.now() : 5_000);
        await new Promise((r) => setTimeout(r, Math.min(60_000, Math.max(1_000, wait)))); continue;
      }
      if (res.status === 304 && cached) { this.not_modified++; return { body: JSON.parse(cached.body), next: cached.next }; }
      if (!res.ok) throw new GitHubError(u.pathname, res.status, (await res.text()).slice(0, 300));
      const link = res.headers.get("link") ?? ""; const next = link.match(/<([^>]+)>;\s*rel="next"/)?.[1] ?? null;
      if (res.status === 204) return { body: null, next };
      const text = await res.text(); const etag = res.headers.get("etag");
      if (this.cache && etag && !/\/audit-log/.test(u.pathname)) this.cache.set(url, { etag, body: text, next });
      return { body: JSON.parse(text), next };
    }
  }

  async get<T = any>(path: string, params: Record<string, string | number | undefined> = {}): Promise<T> { return (await this.raw(path, params)).body as T; }

  /** Follows `Link: rel="next"`; `key` names the array when the page is an object (`installations`, `secrets`). */
  async list<T = any>(path: string, params: Record<string, string | number | undefined> = {}, key?: string, max = 10_000): Promise<T[]> {
    const out: T[] = []; let page = await this.raw(path, { per_page: 100, ...params });
    for (let i = 0; i < 200; i++) {
      const items: T[] = key ? (Array.isArray(page.body?.[key]) ? page.body[key] : []) : Array.isArray(page.body) ? page.body : [];
      out.push(...items);
      if (!page.next || !items.length || out.length >= max) break;
      page = await this.raw(page.next);
    }
    return out;
  }

  private o = () => `/orgs/${encodeURIComponent(this.org)}`;
  private r = (full: string) => `/repos/${full.split("/").map(encodeURIComponent).join("/")}`;

  async orgInfo(): Promise<GitHubOrg> {
    const j = await this.get<any>(this.o());
    return { id: Number(j.id), node_id: String(j.node_id), login: String(j.login), name: str(j.name), plan: str(j.plan?.name), seats: j.plan?.seats ?? null, filled_seats: j.plan?.filled_seats ?? null, private_repos: j.plan?.private_repos ?? null,
      two_factor_required: typeof j.two_factor_requirement_enabled === "boolean" ? j.two_factor_requirement_enabled : null, default_permission: str(j.default_repository_permission),
      members_can_create_repositories: j.members_can_create_repositories ?? null, members_can_create_public_repositories: j.members_can_create_public_repositories ?? null, web_commit_signoff_required: j.web_commit_signoff_required ?? null, created_at: iso(j.created_at) };
  }
  /** Org members with their role (owners are `admin`). */
  async members(): Promise<{ login: string; id: number; role: "admin" | "member" }[]> {
    const admins = await this.list<any>(`${this.o()}/members`, { role: "admin" });
    const all = await this.list<any>(`${this.o()}/members`, { role: "all" });
    const owner = new Set(admins.map((u) => u.login));
    return all.map((u) => ({ login: String(u.login), id: Number(u.id), role: owner.has(u.login) ? "admin" as const : "member" as const }));
  }
  /** Logins without two-factor authentication (members, or outside collaborators); owners only, so a refusal is an error the caller records. */
  async without2fa(kind: "members" | "outside_collaborators"): Promise<string[]> { return (await this.list<any>(`${this.o()}/${kind}`, { filter: "2fa_disabled" })).map((u) => String(u.login)); }
  async outsideCollaborators(): Promise<{ login: string; id: number }[]> { return (await this.list<any>(`${this.o()}/outside_collaborators`)).map((u) => ({ login: String(u.login), id: Number(u.id) })); }
  /** A user's public profile: the name they show, their public e-mail reduced to a match key. */
  async user(login: string): Promise<GitHubUser> {
    const j = await this.get<any>(`/users/${encodeURIComponent(login)}`);
    return { login: String(j.login), id: Number(j.id), name: str(j.name), email_key: emailKey(j.email), company: str(j.company), created_at: iso(j.created_at), type: str(j.type) };
  }
  async sshKeys(login: string): Promise<GitHubSshKey[]> { return (await this.list<any>(`/users/${encodeURIComponent(login)}/keys`)).map((k) => ({ login, id: Number(k.id), fingerprint: sshFingerprint(k.key), key_kind: sshKind(k.key) })); }
  async invitations(): Promise<GitHubInvitation[]> {
    const inv = (x: any, failed: boolean): GitHubInvitation => ({ id: Number(x.id), login: str(x.login), email_key: emailKey(x.email), role: str(x.role), created_at: iso(x.created_at), inviter: str(x.inviter?.login), failed_at: failed ? iso(x.failed_at) : null, failed_reason: failed ? str(x.failed_reason) : null, source: str(x.invitation_source) });
    return [...(await this.list<any>(`${this.o()}/invitations`)).map((x) => inv(x, false)), ...(await this.list<any>(`${this.o()}/failed_invitations`)).map((x) => inv(x, true))];
  }
  async teams(): Promise<GitHubTeam[]> {
    const out: GitHubTeam[] = [];
    for (const t of await this.list<any>(`${this.o()}/teams`)) {
      const slug = String(t.slug);
      const maint = new Set((await this.list<any>(`${this.o()}/teams/${encodeURIComponent(slug)}/members`, { role: "maintainer" })).map((u) => u.login));
      const members = (await this.list<any>(`${this.o()}/teams/${encodeURIComponent(slug)}/members`, { role: "all" })).map((u) => ({ login: String(u.login), role: maint.has(u.login) ? "maintainer" as const : "member" as const }));
      const repos = (await this.list<any>(`${this.o()}/teams/${encodeURIComponent(slug)}/repos`)).map((r) => ({ repo: String(r.full_name), permission: permissionOf(r.permissions, r.role_name) }));
      out.push({ id: Number(t.id), slug, name: String(t.name), privacy: str(t.privacy), parent: str(t.parent?.slug), members, repos });
    }
    return out;
  }
  async repos(): Promise<GitHubRepo[]> {
    return (await this.list<any>(`${this.o()}/repos`, { type: "all" })).map((r) => ({ id: Number(r.id), node_id: String(r.node_id), name: String(r.name), full_name: String(r.full_name), private: Boolean(r.private), visibility: str(r.visibility), archived: Boolean(r.archived), fork: Boolean(r.fork), default_branch: str(r.default_branch), pushed_at: iso(r.pushed_at), created_at: iso(r.created_at), html_url: str(r.html_url) }));
  }
  /** People with access granted on the repository itself (members or outside collaborators), not through a team or the base permission. */
  async collaborators(repo: string): Promise<GitHubCollaborator[]> { return (await this.list<any>(`${this.r(repo)}/collaborators`, { affiliation: "direct" })).map((c) => ({ repo, login: String(c.login), permission: permissionOf(c.permissions, c.role_name), role_name: str(c.role_name) })); }
  async deployKeys(repo: string): Promise<GitHubDeployKey[]> {
    return (await this.list<any>(`${this.r(repo)}/keys`)).map((k) => ({ repo, id: Number(k.id), title: str(k.title), fingerprint: sshFingerprint(k.key), key_kind: sshKind(k.key), read_only: Boolean(k.read_only), verified: k.verified ?? null, added_by: str(k.added_by), created_at: iso(k.created_at), last_used: iso(k.last_used), enabled: k.enabled ?? null }));
  }
  /** Fine-grained personal access tokens granted access to the org, with the repositories of a token limited to some. GitHub Apps only. */
  async pats(): Promise<GitHubPat[]> {
    const out: GitHubPat[] = [];
    for (const t of await this.list<any>(`${this.o()}/personal-access-tokens`)) {
      let repos: string[] = [];
      if (t.repository_selection === "subset") { try { repos = (await this.list<any>(`${this.o()}/personal-access-tokens/${t.id}/repositories`)).map((r) => String(r.full_name)); } catch { /* the grant still counts; its repositories stay unknown */ } }
      out.push({ id: Number(t.id), token_id: t.token_id ?? null, name: str(t.token_name), owner: str(t.owner?.login), repository_selection: str(t.repository_selection), repos, permissions: t.permissions ?? {}, granted_at: iso(t.access_granted_at), expires_at: iso(t.token_expires_at), expired: Boolean(t.token_expired), last_used_at: iso(t.token_last_used_at) });
    }
    return out;
  }
  async patRequests(): Promise<GitHubPatRequest[]> {
    return (await this.list<any>(`${this.o()}/personal-access-token-requests`)).map((t) => ({ id: Number(t.id), token_id: t.token_id ?? null, name: str(t.token_name), owner: str(t.owner?.login), reason: str(t.reason), created_at: iso(t.created_at), expires_at: iso(t.token_expires_at), repository_selection: str(t.repository_selection), permissions: t.permissions ?? {} }));
  }
  /** Classic tokens and SSH keys members authorized for the org's SAML single sign-on (only when SAML is on). */
  async credentialAuthorizations(): Promise<GitHubCredentialAuthorization[]> {
    return (await this.list<any>(`${this.o()}/credential-authorizations`)).map((c) => ({ login: String(c.login), credential_id: Number(c.credential_id), type: String(c.credential_type ?? "unknown"), token_last_eight: str(c.token_last_eight), fingerprint: str(c.fingerprint), title: str(c.authorized_credential_title ?? c.authorized_credential_note), scopes: Array.isArray(c.scopes) ? c.scopes.map(String) : [], authorized_at: iso(c.credential_authorized_at), accessed_at: iso(c.credential_accessed_at), expires_at: iso(c.authorized_credential_expires_at) }));
  }
  async installations(): Promise<GitHubInstallation[]> {
    return (await this.list<any>(`${this.o()}/installations`, {}, "installations")).map((i) => ({ id: Number(i.id), app_id: Number(i.app_id), app_slug: String(i.app_slug), repository_selection: str(i.repository_selection), permissions: i.permissions ?? {}, events: Array.isArray(i.events) ? i.events : [], created_at: iso(i.created_at), updated_at: iso(i.updated_at), suspended_at: iso(i.suspended_at) }));
  }
  /** Secret names (GitHub never returns values) of the org, for Actions and Dependabot, with the repositories a `selected` one is shared with. */
  async orgSecrets(): Promise<GitHubSecret[]> {
    const out: GitHubSecret[] = [];
    for (const kind of ["actions", "dependabot"] as const) {
      let list: any[] = []; try { list = await this.list<any>(`${this.o()}/${kind}/secrets`, {}, "secrets"); } catch (e) { if (kind === "actions") throw e; }
      for (const s of list) {
        let selected: string[] = [];
        if (s.visibility === "selected") { try { selected = (await this.list<any>(`${this.o()}/${kind}/secrets/${encodeURIComponent(s.name)}/repositories`, {}, "repositories")).map((r) => String(r.full_name)); } catch { /* the names stay unknown */ } }
        out.push({ scope: "org", kind, repo: null, environment: null, name: String(s.name), visibility: str(s.visibility), selected_repos: selected, created_at: iso(s.created_at), updated_at: iso(s.updated_at) });
      }
    }
    return out;
  }
  async repoSecrets(repo: string): Promise<GitHubSecret[]> {
    const out: GitHubSecret[] = [];
    for (const s of await this.list<any>(`${this.r(repo)}/actions/secrets`, {}, "secrets")) out.push({ scope: "repo", kind: "actions", repo, environment: null, name: String(s.name), visibility: null, selected_repos: [], created_at: iso(s.created_at), updated_at: iso(s.updated_at) });
    for (const env of await this.list<any>(`${this.r(repo)}/environments`, {}, "environments")) {
      for (const s of await this.list<any>(`${this.r(repo)}/environments/${encodeURIComponent(env.name)}/secrets`, {}, "secrets")) out.push({ scope: "environment", kind: "actions", repo, environment: String(env.name), name: String(s.name), visibility: null, selected_repos: [], created_at: iso(s.created_at), updated_at: iso(s.updated_at) });
    }
    return out;
  }
  /** One environment's secret names (no Steampipe table has them). */
  async environmentSecrets(repo: string, env: string): Promise<GitHubSecret[]> {
    return (await this.list<any>(`${this.r(repo)}/environments/${encodeURIComponent(env)}/secrets`, {}, "secrets")).map((s) => ({ scope: "environment" as const, kind: "actions" as const, repo, environment: env, name: String(s.name), visibility: null, selected_repos: [], created_at: iso(s.created_at), updated_at: iso(s.updated_at) }));
  }
  async hooks(repo?: string): Promise<GitHubHook[]> {
    return (await this.list<any>(repo ? `${this.r(repo)}/hooks` : `${this.o()}/hooks`)).map((h) => ({ id: Number(h.id), repo: repo ?? null, name: str(h.name), active: Boolean(h.active), events: Array.isArray(h.events) ? h.events : [], host: hostOf(h.config?.url), insecure_ssl: String(h.config?.insecure_ssl ?? "0") === "1", created_at: iso(h.created_at), updated_at: iso(h.updated_at) }));
  }
  async copilot(): Promise<{ summary: GitHubCopilot; seats: GitHubCopilotSeat[] }> {
    const b = await this.get<any>(`${this.o()}/copilot/billing`); const sb = b?.seat_breakdown ?? {};
    const seats = (await this.list<any>(`${this.o()}/copilot/billing/seats`, {}, "seats")).map((s) => ({ login: String(s.assignee?.login ?? s.assignee?.slug ?? "unknown"), plan_type: str(s.plan_type), created_at: iso(s.created_at), last_activity_at: iso(s.last_activity_at), last_activity_editor: str(s.last_activity_editor), pending_cancellation_date: str(s.pending_cancellation_date), team: str(s.assigning_team?.slug) }));
    return { summary: { plan_type: str(b?.plan_type), seat_management: str(b?.seat_management_setting), seats_total: sb.total ?? null, seats_active: sb.active_this_cycle ?? null, seats_inactive: sb.inactive_this_cycle ?? null, pending_cancellation: sb.pending_cancellation ?? null, pending_invitation: sb.pending_invitation ?? null }, seats };
  }
  /** The metered bill of one month (Actions, Packages, Copilot, seats where the enhanced billing platform itemises them), per day and SKU. */
  async usage(year: number, month: number): Promise<GitHubUsageItem[]> {
    const j = await this.get<any>(`/organizations/${encodeURIComponent(this.org)}/settings/billing/usage`, { year, month });
    const n = (v: unknown) => (Number.isFinite(Number(v)) ? Number(v) : 0);
    return (Array.isArray(j?.usageItems) ? j.usageItems : []).map((u: any) => ({ date: String(u.date ?? "").slice(0, 10), product: String(u.product ?? "unknown"), sku: String(u.sku ?? "unknown"), quantity: n(u.quantity), unit: str(u.unitType), price_per_unit: u.pricePerUnit == null ? null : n(u.pricePerUnit), gross_usd: n(u.grossAmount), discount_usd: n(u.discountAmount), net_usd: n(u.netAmount), repo: str(u.repositoryName) }));
  }
  /** Audit log events since a day (newest first), git events included where the API keeps them (seven days). */
  async audit(sinceDay: string, max = 20_000): Promise<GitHubAuditEvent[]> {
    return (await this.list<any>(`${this.o()}/audit-log`, { phrase: `created:>=${sinceDay}`, include: "all", order: "desc" }, undefined, max)).map(auditFrom);
  }
}

/** One audit log entry in the advisor's shape. Pure. */
export function auditFrom(e: any): GitHubAuditEvent {
  const at = iso(e["@timestamp"] ?? e.created_at) ?? new Date(0).toISOString();
  return { id: String(e._document_id ?? `${at}:${e.action}:${e.actor ?? ""}`), at, action: String(e.action ?? "unknown"), actor: str(e.actor), user: str(e.user), repo: str(e.repo), team: str(e.team), ip: str(e.actor_ip), country: str(e.actor_location?.country_code), user_agent: str(e.user_agent), access_type: str(e.programmatic_access_type), hashed_token: str(e.hashed_token), token_id: e.token_id ?? null, operation: str(e.operation_type) };
}

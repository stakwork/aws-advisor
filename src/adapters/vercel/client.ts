/**
 * A thin Vercel REST client for the adapter: a team (or personal) token, the team id on every call, cursor
 * pagination, and a fetch that can be replaced in tests. Only reads. Environment variable *values* are never
 * returned: the env listing is reduced to names, targets and types before it leaves this module.
 */

export const VERCEL_API = "https://api.vercel.com";

export interface VercelClientOptions { token: string; teamId?: string | null; fetchImpl?: typeof fetch; base?: string }

export interface VercelTeam { id: string; slug: string | null; name: string | null; plan: string | null; personal: boolean; billing?: VercelTeamBilling | null; security?: VercelTeamSecurity | null }
/**
 * How the team guards sign-in: SAML single sign-on (connected, enforced), a team-wide MFA requirement when the API
 * names one (null when the team object carries no such field), the default for new env variables, and the role of the
 * token's owner on the team.
 */
export interface VercelTeamSecurity { saml_connected: boolean; saml_enforced: boolean; saml_provider: string | null; directory_sync: boolean; mfa_required: boolean | null; sensitive_env_policy: string | null; token_owner_role: string | null }
/** A token of the account the advisor's token belongs to (the API lists only the caller's own): never the secret. */
export interface VercelToken { id: string; name: string | null; type: string | null; origin: string | null; team_ids: string[]; expires_at: string | null; active_at: string | null; created_at: string | null }
/** What the team object says about its subscription: the plan and its period, the seats and their price, the status, and the metered rates. */
export interface VercelTeamBilling { plan: string | null; status: string | null; currency: string | null; period_start: string | null; period_end: string | null; seats: number | null; seat_usd: number | null; rates: { item: string; usd: number; quantity: number | null; unit: string }[] }

/** What a metered item is priced per, from its name: Vercel's invoice items say so only in the item key. */
export function rateUnit(item: string): string {
  const k = item.toLowerCase();
  if (/^(pro|hobby|enterprise)$/.test(k) || /base$|observabilitybase|secureconnect|sharednetworks|analytics$|includedallocation/.test(k)) return "month";
  if (/duration|cputime|cpuminutes|concurrencyminutes|minutes/.test(k)) return k.includes("minute") ? "minute" : "hour";
  if (/gbhours|gb-hours|provisionedmemory/.test(k)) return "GB-hour";
  if (/storage|avgsizeinbytes|lambdastorage|vcrstorage/.test(k)) return "GB-month";
  if (/transfer|volume|bandwidth|excessbytes/.test(k)) return "GB";
  if (/credits/.test(k)) return "credit";
  if (/transformation/.test(k)) return "transformation";
  if (/span|trace|event|message|notification|visibility|request|invocation|read|write|operation|trigger|unit|run$/.test(k)) return k.includes("unit") ? "execution unit" : "each";
  return "each";
}
export interface VercelInvoice { id: string; number: string | null; status: string | null; total: number | null; subtotal: number | null; tax: number | null; currency: string | null; created_at: string | null; issued_at: string | null; paid_at: string | null; period_start: string | null; period_end: string | null; source: string | null; hosted_url: string | null; pdf_url: string | null; groups: { id: string; name: string; total: number | null }[]; line_items: { title: string; amount: number; quantity: number | null; group: string | null; unit_usd: number | null }[] }
export interface VercelProject {
  /** Vercel OIDC federation: the project's functions get a token to assume a cloud role instead of holding static keys */
  oidc?: { enabled: boolean; issuer_mode: string | null } | null;
  id: string; name: string; framework: string | null; node_version: string | null; created_at: string | null; updated_at: string | null;
  repo: string | null; git_provider: string | null; production_url: string | null;
  latest: { id: string; url: string | null; state: string | null; target: string | null; created_at: string | null } | null;
  /** deployment protection: who can open a deployment URL */
  protection: { sso: string | null; password: string | null; trusted_ips: string | null; bypass_automation: boolean };
  live: boolean;
  /** Secure Compute: the project's functions run inside the account's own AWS VPC, behind this security group, in these subnets */
  connect: { id: string; dc: string | null; env: string; security_group: string | null; subnets: string[]; passive: boolean; builds: boolean }[];
}
export interface VercelDeployment { id: string; project_id: string | null; name: string | null; url: string | null; state: string | null; target: string | null; created_at: string | null; ready_at: string | null; source: string | null; branch: string | null; commit: string | null }
export interface VercelDomain { project_id: string; name: string; apex: string | null; verified: boolean; redirect: string | null; branch: string | null; created_at: string | null }
export interface VercelEnv { project_id: string; key: string; targets: string[]; type: string | null; updated_at: string | null; created_at?: string | null; edited_by?: string | null }
export interface VercelFirewall { project_id: string; enabled: boolean; rules: number; ips: number; version: string | null }
/** A storage store the team provisioned: a marketplace integration (Neon, Redis, ...) or Vercel's own (blob, KV, edge config), with the projects it is connected to. */
/** A team member; `email_key` is the e-mail's local part reduced to letters and digits, kept to match the person across providers (the address itself is not kept). */
export interface VercelMember { uid: string; username: string | null; role: string | null; confirmed: boolean; mfa: boolean | null; github: string | null; joined_at: string | null; email_key?: string | null; access_groups?: number; joined_from?: string | null }
export interface VercelLogDrain { id: string; name: string | null; status: string | null; sources: string[]; environments: string[]; sampling_rate: number | null; format: string | null; host: string | null; project_ids: string[]; created_at: string | null; created_from: string | null }
export interface VercelStore { id: string; name: string; type: string; kind: "database" | "cache" | "storage" | "other"; product: string | null; product_slug: string | null; status: string | null; plan: string | null; region: string | null; created_at: string | null; projects: { project_id: string; name: string | null; environments: string[]; env_var_names: string[]; env_var_prefix: string | null }[]; details: VercelStoreDetails }
/**
 * What else the store object says: size and object count (Blob), access, whether its token expired, the external
 * resource at the marketplace partner (a Neon project id), the plan with its price lines and quotas, the partner's
 * metadata (high availability, storage type, region, auth), the secret names it injects (names and lengths only),
 * what it can do (MCP, SSO, transfer), and the partner's usage for the current billing period (Neon compute hours).
 */
export interface VercelStoreDetails {
  billing_state: string | null; quota_exceeded: boolean; ownership: string | null; updated_at: string | null; connected_projects: number | null;
  size_bytes: number | null; object_count: number | null; access: string | null; token_expired: boolean | null;
  external_id: string | null; external_status: string | null;
  plan_id: string | null; plan_scope: string | null; plan_type: string | null; plan_description: string | null; plan_cost: string | null; plan_lines: { label: string; value: string }[];
  metadata: Record<string, string | number | boolean>; secret_names: { name: string; length: number | null }[]; capabilities: Record<string, boolean>;
  product_tags: string[]; product_description: string | null;
  usage_period: { start: string | null; end: string | null; read_at: string | null; items: { name: string; units: string | null; period_value: number | null; day_value: number | null }[] } | null;
}

const iso = (v: unknown): string | null => { if (v == null) return null; const n = Number(v); if (Number.isFinite(n) && n > 1e11) return new Date(n).toISOString(); const s = String(v); return /^\d{4}-/.test(s) ? s : null; };
const str = (v: unknown): string | null => (v == null || v === "" ? null : String(v));

export class VercelClient {
  private readonly token: string; private readonly teamId: string | null; private readonly f: typeof fetch; private readonly base: string;
  constructor(o: VercelClientOptions) { this.token = o.token; this.teamId = o.teamId || null; this.f = o.fetchImpl ?? fetch; this.base = o.base ?? VERCEL_API; }

  async get<T = any>(path: string, params: Record<string, string | number | undefined> = {}): Promise<T> {
    const u = new URL(`${this.base}${path}`);
    if (this.teamId) u.searchParams.set("teamId", this.teamId);
    for (const [k, v] of Object.entries(params)) if (v != null && v !== "") u.searchParams.set(k, String(v));
    const res = await this.f(u.toString(), { headers: { authorization: `Bearer ${this.token}`, "user-agent": "cloud-advisor" }, signal: AbortSignal.timeout(30_000) });
    if (!res.ok) { const body = (await res.text()).slice(0, 300); throw new Error(`Vercel ${path}: HTTP ${res.status}${body ? ` ${body}` : ""}`); }
    return res.json() as Promise<T>;
  }

  /** Follows `pagination.next` until the end; `key` names the array in each page. */
  async list<T = any>(path: string, key: string, params: Record<string, string | number | undefined> = {}, max = 2000): Promise<T[]> {
    const out: T[] = []; let until: number | undefined;
    for (let i = 0; i < 50; i++) {
      const page = await this.get<any>(path, { ...params, limit: 100, until });
      const items: T[] = Array.isArray(page?.[key]) ? page[key] : [];
      out.push(...items);
      const next = page?.pagination?.next;
      if (!next || !items.length || out.length >= max) break;
      until = Number(next);
    }
    return out;
  }

  /** The team the token is scoped to, or the personal account when no team id is set. */
  async whoami(): Promise<VercelTeam> {
    if (this.teamId) { const t = await this.get<any>(`/v2/teams/${encodeURIComponent(this.teamId)}`); return { id: String(t.id), slug: str(t.slug), name: str(t.name), plan: str(t.billing?.plan ?? t.plan), personal: false, billing: teamBillingFrom(t.billing), security: teamSecurityFrom(t) }; }
    const u = await this.get<any>("/v2/user"); const user = u.user ?? u;
    return { id: String(user.id ?? user.uid), slug: str(user.username), name: str(user.name ?? user.username), plan: str(user.billing?.plan), personal: true };
  }

  async projects(): Promise<VercelProject[]> { return (await this.list<any>("/v9/projects", "projects")).map(projectFrom); }
  async deployments(projectId?: string, limit = 50): Promise<VercelDeployment[]> { return (await this.list<any>("/v6/deployments", "deployments", { projectId }, limit)).map(deploymentFrom); }
  async domains(projectId: string): Promise<VercelDomain[]> { return (await this.list<any>(`/v9/projects/${encodeURIComponent(projectId)}/domains`, "domains")).map((d) => domainFrom(projectId, d)); }
  async env(projectId: string): Promise<VercelEnv[]> { const r = await this.get<any>(`/v9/projects/${encodeURIComponent(projectId)}/env`); return (Array.isArray(r?.envs) ? r.envs : []).map((e: any) => envFrom(projectId, e)); }
  /** The most recent invoices (Vercel's own billing; marketplace stores bill through it too). */
  async invoices(limit = 12): Promise<VercelInvoice[]> { try { const r = await this.get<any>("/v1/invoices", { limit }); return (Array.isArray(r?.data) ? r.data : []).map(invoiceFrom); } catch { return []; } }
  /** One row per day of a usage type, team-wide (or one project's), with the per-project breakdown in percent. */
  async usage(type: UsageType, from: Date, to: Date, projectId?: string): Promise<UsageDay[]> {
    try { return usageDaysFrom(await this.get("/v2/usage", { type, from: from.toISOString(), to: to.toISOString(), projectId })); } catch { return []; }
  }
  /** The team's members with their role and whether MFA is on (no e-mail addresses are kept). */
  /** Who the token belongs to (its user id and username): the owner of the tokens tokens() lists. */
  async owner(): Promise<{ uid: string; username: string | null } | null> { try { const u = await this.get<any>("/v2/user"); const x = u.user ?? u; return x?.id || x?.uid ? { uid: String(x.id ?? x.uid), username: str(x.username) } : null; } catch { return null; } }
  /** The caller's own tokens (the API lists no one else's): name, scope, expiry, last activity. */
  async tokens(): Promise<VercelToken[]> { try { const r = await this.get<any>("/v5/user/tokens"); return (Array.isArray(r?.tokens) ? r.tokens : []).map(tokenFrom); } catch { return []; } }
  async members(): Promise<VercelMember[]> { if (!this.teamId) return []; try { const r = await this.get<any>(`/v1/teams/${encodeURIComponent(this.teamId)}/members`, { limit: 100 }); return (Array.isArray(r?.members) ? r.members : Array.isArray(r) ? r : []).map(memberFrom); } catch { return []; } }
  /** Where the team's logs are drained to: the drain's name, sources, environments, sampling and the projects it covers (the destination URL is kept as its host only). */
  async logDrains(): Promise<VercelLogDrain[]> { try { const r = await this.get<any>("/v1/log-drains"); return (Array.isArray(r) ? r : Array.isArray(r?.drains) ? r.drains : []).map(logDrainFrom); } catch { return []; } }
  async stores(): Promise<VercelStore[]> { try { const r = await this.get<any>("/v1/storage/stores"); return (Array.isArray(r?.stores) ? r.stores : []).map(storeFrom); } catch { return []; } }
  async firewall(projectId: string): Promise<VercelFirewall | null> {
    try { const r = await this.get<any>("/v1/security/firewall/config", { projectId }); return { project_id: projectId, enabled: Boolean(r?.firewallEnabled), rules: Array.isArray(r?.rules) ? r.rules.length : 0, ips: Array.isArray(r?.ips) ? r.ips.length : 0, version: str(r?.version) }; }
    catch { return null; }
  }
}

// ---- the API's shapes folded to the adapter's rows (exported for tests) --------------------------------------------

export function projectFrom(p: any): VercelProject {
  const latest = Array.isArray(p.latestDeployments) && p.latestDeployments[0] ? p.latestDeployments[0] : p.targets?.production ?? null;
  const prod = p.targets?.production ?? null;
  const prodUrl = prod?.url ? `https://${prod.url}` : Array.isArray(p.alias) && p.alias[0]?.domain ? `https://${p.alias[0].domain}` : null;
  return {
    id: String(p.id), name: String(p.name ?? p.id), framework: str(p.framework), node_version: str(p.nodeVersion), created_at: iso(p.createdAt), updated_at: iso(p.updatedAt),
    repo: p.link?.repo ? `${p.link.org ? `${p.link.org}/` : ""}${p.link.repo}` : null, git_provider: str(p.link?.type), production_url: prodUrl,
    latest: latest ? { id: String(latest.id ?? latest.uid), url: latest.url ? `https://${latest.url}` : null, state: str(latest.readyState ?? latest.state), target: str(latest.target), created_at: iso(latest.createdAt ?? latest.created) } : null,
    protection: { sso: str(p.ssoProtection?.deploymentType), password: str(p.passwordProtection?.deploymentType), trusted_ips: str(p.trustedIps?.deploymentType), bypass_automation: Boolean(p.protectionBypass && Object.keys(p.protectionBypass).length) },
    live: Boolean(p.live ?? true),
    oidc: p.oidcTokenConfig ? { enabled: Boolean(p.oidcTokenConfig.enabled), issuer_mode: str(p.oidcTokenConfig.issuerMode) } : null,
    connect: (Array.isArray(p.connectConfigurations) ? p.connectConfigurations : []).filter((c: any) => c && c.connectConfigurationId).map((c: any) => ({ id: String(c.connectConfigurationId), dc: str(c.dc), env: String(c.envId ?? "production"), security_group: str(c.aws?.securityGroupId), subnets: Array.isArray(c.aws?.subnetIds) ? c.aws.subnetIds.map(String) : [], passive: Boolean(c.passive), builds: Boolean(c.buildsEnabled) })),
  };
}

export const memberFrom = (m: any): VercelMember => ({ uid: String(m.uid ?? m.id), username: str(m.username), role: str(m.role ?? (Array.isArray(m.teamRoles) ? m.teamRoles[0] : null)), confirmed: Boolean(m.confirmed), mfa: typeof m.mfaEnabled === "boolean" ? m.mfaEnabled : null, github: str(m.github?.login), joined_at: iso(m.createdAt),
  email_key: typeof m.email === "string" ? (m.email.toLowerCase().split("@")[0].replace(/[^a-z0-9]/g, "") || null) : null, access_groups: Array.isArray(m.accessGroups) ? m.accessGroups.length : 0, joined_from: str(m.joinedFrom?.origin) });
export const tokenFrom = (t: any): VercelToken => ({ id: String(t.id), name: str(t.name), type: str(t.type), origin: str(t.origin), team_ids: Array.isArray(t.scopes) ? [...new Set(t.scopes.map((s: any) => s?.teamId).filter(Boolean).map(String))] as string[] : [], expires_at: iso(t.expiresAt), active_at: iso(t.activeAt), created_at: iso(t.createdAt) });
/** The team's sign-in guards from the team object; a field the plan does not return reads as off (SAML) or unknown (MFA). Pure. */
export function teamSecurityFrom(t: any): VercelTeamSecurity {
  const saml = t?.saml ?? null;
  const mfaKey = Object.keys(t ?? {}).find((k) => /^(mfa|twoFactor|enforceMfa|mfaRequired|requireMfa)/i.test(k));
  const mfaVal = mfaKey ? t[mfaKey] : undefined;
  return {
    saml_connected: Boolean(saml?.connection), saml_enforced: Boolean(saml?.enforced), saml_provider: str(saml?.connection?.type ?? saml?.connection?.provider), directory_sync: Boolean(saml?.directory),
    mfa_required: typeof mfaVal === "boolean" ? mfaVal : typeof mfaVal?.enforced === "boolean" ? mfaVal.enforced : typeof mfaVal?.required === "boolean" ? mfaVal.required : null,
    sensitive_env_policy: str(t?.sensitiveEnvironmentVariablePolicy), token_owner_role: str(t?.membership?.role),
  };
}
export const logDrainFrom = (d: any): VercelLogDrain => { let host: string | null = null; try { if (d.url) host = new URL(String(d.url)).host; } catch { /* not a URL */ } return { id: String(d.id), name: str(d.name), status: str(d.status), sources: Array.isArray(d.sources) ? d.sources.map(String) : [], environments: Array.isArray(d.environments) ? d.environments.map(String) : [], sampling_rate: money(d.samplingRate), format: str(d.deliveryFormat), host, project_ids: Array.isArray(d.projectIds) ? d.projectIds.map(String) : [], created_at: iso(d.createdAt), created_from: str(d.createdFrom) }; };

export function deploymentFrom(d: any): VercelDeployment {
  return { id: String(d.uid ?? d.id), project_id: str(d.projectId), name: str(d.name), url: d.url ? `https://${d.url}` : null, state: str(d.readyState ?? d.state), target: str(d.target), created_at: iso(d.createdAt ?? d.created), ready_at: iso(d.ready), source: str(d.source), branch: str(d.meta?.githubCommitRef ?? d.meta?.gitlabCommitRef ?? d.meta?.bitbucketCommitRef), commit: str(d.meta?.githubCommitSha ?? d.meta?.gitlabCommitSha ?? d.meta?.bitbucketCommitSha)?.slice(0, 12) ?? null };
}

export const domainFrom = (projectId: string, d: any): VercelDomain => ({ project_id: projectId, name: String(d.name), apex: str(d.apexName), verified: Boolean(d.verified), redirect: str(d.redirect), branch: str(d.gitBranch), created_at: iso(d.createdAt) });

const money = (v: unknown): number | null => { if (v == null || v === "") return null; const n = Number(v); return Number.isFinite(n) ? n : null; };

/** The subscription as the team object carries it; prices in the invoice items are cents for licensed items (seats) and dollars per unit for metered ones. */
export function teamBillingFrom(b: any): VercelTeamBilling | null {
  if (!b || typeof b !== "object") return null;
  const items = b.invoiceItems && typeof b.invoiceItems === "object" ? b.invoiceItems : {};
  const seats = items.teamSeats ? { quantity: money(items.teamSeats.quantity), usd: money(items.teamSeats.price) != null ? Number(items.teamSeats.price) / 100 : null } : null;
  // every price in invoiceItems is in cents per unit of the item (pro = 2000 → $20; logDrainsVolume = 50 → $0.50 per GB; functionInvocation = 6e-05 → $6e-7 each)
  const rates = Object.entries(items).filter(([k, v]: any) => k !== "teamSeats" && v && !v.hidden && money(v.price) != null).map(([k, v]: any) => ({ item: k, usd: Number(v.price) / 100, quantity: money(v.quantity), unit: rateUnit(k) }));
  return { plan: str(b.plan), status: str(b.status), currency: str(b.currency), period_start: iso(b.period?.start), period_end: iso(b.period?.end), seats: seats?.quantity ?? null, seat_usd: seats?.usd ?? null, rates };
}

export function invoiceFrom(i: any): VercelInvoice {
  const groups = (Array.isArray(i.groups) ? i.groups : []).map((g: any) => ({ id: String(g.id ?? g.name), name: String(g.name ?? g.title ?? g.id), total: money(g.total ?? g.amount) }));
  const lines = (Array.isArray(i.lineItems) ? i.lineItems : []).map((l: any) => ({ title: String(l.title ?? l.description ?? l.billableItem ?? "item"), amount: money(l.amount ?? l.subtotal) ?? 0, quantity: money(l.quantity), group: str(l.group), unit_usd: money(l.unit?.unitAmount ?? l.unit?.defaultUnitAmount ?? l.price?.unitAmount) })).filter((l: any) => l.amount !== 0).sort((a: any, b: any) => b.amount - a.amount).slice(0, 25);
  const periods = (Array.isArray(i.lineItems) ? i.lineItems : []).map((l: any) => [l.periodStart, l.periodEnd]).filter((p: any) => p[0] && p[1]);
  return { id: String(i.id), number: str(i.invoiceNumber), status: str(i.status), total: money(i.total), subtotal: money(i.subtotal), tax: money(i.tax), currency: str(i.currency), created_at: iso(i.createdAt), issued_at: iso(i.issuedAt), paid_at: iso(i.statusTransitions?.paidAt),
    period_start: periods.length ? String(periods.map((p: any) => p[0]).sort()[0]) : null, period_end: periods.length ? String(periods.map((p: any) => p[1]).sort().slice(-1)[0]) : null, source: str(i.invoiceSource), hosted_url: str(typeof i.hostedUrl === "string" ? i.hostedUrl : i.hostedUrl?.url), pdf_url: str(i.pdfDownloadUrl), groups, line_items: lines };
}

/** What kind of thing a store is, from Vercel's type and the marketplace product: the generic labels the graph uses. */
export function storeKind(type: string | null, productSlug: string | null): VercelStore["kind"] {
  const p = String(productSlug || "").toLowerCase(); const t = String(type || "").toLowerCase();
  if (/neon|postgres|supabase|planetscale|mysql|mongo|turso|xata|prisma/.test(p) || t === "postgres") return "database";
  if (/redis|upstash|kv|memcache/.test(p) || t === "kv" || t === "redis") return "cache";
  if (t === "blob" || t === "edge-config" || /blob|s3|storage/.test(p)) return "storage";
  return "other";
}
export function storeFrom(st: any): VercelStore {
  const slug = str(st.product?.slug ?? st.product?.integration ?? st.productSlug);
  const plan = st.billingPlan && typeof st.billingPlan === "object" ? st.billingPlan : null;
  const planLines: { label: string; value: string }[] = [...(Array.isArray(plan?.details) ? plan.details : []), ...(Array.isArray(plan?.highlightedDetails) ? plan.highlightedDetails : [])].filter((d: any) => d && d.label != null).map((d: any) => ({ label: String(d.label), value: String(d.value ?? "") }));
  const usageSrc = st.billingDataV2?.usage ?? st.billingData ?? null;
  const usageItems = Array.isArray(usageSrc?.items) ? usageSrc.items : Array.isArray(usageSrc?.usage) ? usageSrc.usage : [];
  const metadata: Record<string, string | number | boolean> = {};
  if (st.metadata && typeof st.metadata === "object") for (const [k, v] of Object.entries(st.metadata)) if (["string", "number", "boolean"].includes(typeof v)) metadata[k] = v as any;
  const capabilities: Record<string, boolean> = {};
  if (st.capabilities && typeof st.capabilities === "object") for (const [k, v] of Object.entries(st.capabilities)) if (typeof v === "boolean") capabilities[k] = v;
  const details: VercelStoreDetails = {
    billing_state: str(st.billingState), quota_exceeded: Boolean(st.usageQuotaExceeded), ownership: str(st.ownership), updated_at: iso(st.updatedAt), connected_projects: money(st.totalConnectedProjects),
    size_bytes: money(st.size), object_count: money(st.count), access: str(st.access), token_expired: typeof st.isTokenExpired === "boolean" ? st.isTokenExpired : null,
    external_id: str(st.externalResourceId), external_status: str(st.externalResourceStatus),
    plan_id: str(plan?.id), plan_scope: str(plan?.scope), plan_type: str(plan?.type), plan_description: str(plan?.description), plan_cost: str(plan?.cost), plan_lines: planLines,
    metadata, secret_names: (Array.isArray(st.secrets) ? st.secrets : []).filter((x: any) => x && x.name).map((x: any) => ({ name: String(x.name), length: money(x.length) })), capabilities,
    product_tags: Array.isArray(st.product?.tags) ? st.product.tags.map(String) : [], product_description: str(st.product?.shortDescription),
    usage_period: usageSrc ? { start: iso(usageSrc.periodStart), end: iso(usageSrc.periodEnd), read_at: iso(usageSrc.timestamp), items: usageItems.map((u: any) => ({ name: String(u.name ?? "usage"), units: str(u.units), period_value: money(u.periodValue), day_value: money(u.dayValue) })) } : null,
  };
  return { id: String(st.id), name: String(st.name ?? st.id), type: String(st.type ?? "unknown"), kind: storeKind(str(st.type), slug), product: str(st.product?.name) ?? (st.type === "blob" ? "Vercel Blob" : st.type === "kv" ? "Vercel KV" : st.type === "edge-config" ? "Edge Config" : null), product_slug: slug, status: str(st.status ?? st.externalResourceStatus), plan: str(plan?.name), region: str(st.region ?? st.metadata?.region ?? st.metadata?.Region ?? st.metadata?.primaryRegion), created_at: iso(st.createdAt),
    projects: (Array.isArray(st.projectsMetadata) ? st.projectsMetadata : []).map((p: any) => ({ project_id: String(p.projectId ?? p.id), name: str(p.name), environments: Array.isArray(p.environments) ? p.environments.map(String) : [], env_var_names: Array.isArray(p.environmentVariables) ? p.environmentVariables.map(String) : [], env_var_prefix: str(p.envVarPrefix) })), details };
}

/** A price line from a marketplace plan ("$0.35 per GB-month", "$0.106 per CU-hour", "30 MB"): the number and what it is per, when it is a price. */
export function planLinePrice(value: string): { usd: number; unit: string } | null {
  const m = /^\$([\d.]+)\s*(?:per|\/)\s*([A-Za-z-]+)/.exec(String(value).trim()); if (!m) return null;
  const usd = Number(m[1]); return Number.isFinite(usd) ? { usd, unit: m[2] } : null;
}

/** Names, targets and types only: the value never leaves the API response. */
export const envFrom = (projectId: string, e: any): VercelEnv => ({ project_id: projectId, key: String(e.key), targets: Array.isArray(e.target) ? e.target.map(String) : e.target ? [String(e.target)] : [], type: str(e.type), updated_at: iso(e.updatedAt), created_at: iso(e.createdAt), edited_by: str(e.lastEditedByDisplayName) });

/**
 * Whether a deployment URL asks for authentication before serving, from the project's protection settings: Vercel
 * Authentication (SSO), a password, or trusted IPs on `all` deployments, or on previews only (`prod_deployment_urls_and_all_previews`
 * protects production deployment URLs too, but not the production domain).
 */
export function requiresAuth(p: Pick<VercelProject, "protection">, target: "production" | "preview"): { requires_auth: boolean; via: string | null } {
  const modes = [["sso", p.protection.sso], ["password", p.protection.password], ["trusted_ips", p.protection.trusted_ips]] as const;
  for (const [via, mode] of modes) {
    if (!mode) continue;
    if (mode === "all") return { requires_auth: true, via };
    if (target === "preview" && (mode === "only_preview_deployments" || mode === "prod_deployment_urls_and_all_previews")) return { requires_auth: true, via };
    if (target === "production" && mode === "only_production_deployments") return { requires_auth: true, via };
  }
  return { requires_auth: false, via: null };
}

// ---- usage: the metered numbers per day, team-wide with a per-project breakdown ----------------------------------

/** The usage types /v2/usage answers for; each returns one row per day with its own metric names and a per-project breakdown in percent. */
export const USAGE_TYPES = ["requests", "builds", "storage_blob", "storage_postgres", "storage_redis", "cron_jobs", "data_cache", "log_drains", "edge"] as const;
export type UsageType = (typeof USAGE_TYPES)[number];
export interface UsageDay { date: string; metrics: Record<string, number>; breakdown: Record<string, { id: string; name: string; percent: number }[]> }

export function usageDaysFrom(r: any): UsageDay[] {
  return (Array.isArray(r?.data) ? r.data : []).map((d: any) => {
    const metrics: Record<string, number> = {};
    for (const [k, v] of Object.entries(d)) if (typeof v === "number" && !["percent"].includes(k)) metrics[k] = v;
    const breakdown: UsageDay["breakdown"] = {};
    for (const [k, v] of Object.entries(d.breakdown || {})) if (Array.isArray(v)) breakdown[k] = v.map((x: any) => ({ id: String(x.id ?? x.name), name: String(x.title ?? x.name ?? x.id), percent: Number(x.percent) || 0 }));
    return { date: String(d.date).slice(0, 10), metrics, breakdown };
  });
}

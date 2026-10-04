/**
 * What the partners behind the marketplace stores know that Vercel does not relay: Neon (the Postgres behind a
 * Neon store: storage, branches, compute endpoints and their autoscaling, consumption this period, the IP allow
 * list) and Redis Cloud (the database behind the Redis store: memory used against its limit, persistence,
 * replication, eviction, throughput, the public endpoint and which source IPs may reach it). Each needs the
 * partner's own API key, saved as a runtime secret; without it the store shows what Vercel says and nothing more.
 *
 * Both clients take a fetch so tests run against a fake; nothing here writes.
 */

const iso = (v: unknown): string | null => { if (v == null) return null; const n = Number(v); if (Number.isFinite(n) && n > 1e11) return new Date(n).toISOString(); const s = String(v); return /^\d{4}-/.test(s) ? s : null; };
const str = (v: unknown): string | null => (v == null || v === "" ? null : String(v));
const num = (v: unknown): number | null => { if (v == null || v === "") return null; const n = Number(v); return Number.isFinite(n) ? n : null; };

// ---- Neon ---------------------------------------------------------------------------------------------------------

export interface NeonSnapshot {
  kind: "neon"; read_at: string;
  project: { id: string; name: string | null; region: string | null; pg_version: number | null; created_at: string | null; storage_bytes: number | null; data_storage_bytes_hour: number | null; compute_time_seconds: number | null; active_time_seconds: number | null; written_data_bytes: number | null; data_transfer_bytes: number | null; consumption_period_start: string | null; consumption_period_end: string | null; history_retention_seconds: number | null; autoscaling_min_cu: number | null; autoscaling_max_cu: number | null; suspend_timeout_seconds: number | null; ip_allow: string[]; ip_allow_protected_only: boolean; branch_limit: number | null };
  branches: { id: string; name: string | null; default: boolean; protected: boolean; state: string | null; logical_size_bytes: number | null; created_at: string | null }[];
  endpoints: { id: string; branch_id: string | null; type: string | null; host: string | null; state: string | null; min_cu: number | null; max_cu: number | null; suspend_timeout_seconds: number | null; last_active: string | null; pooler: boolean; disabled: boolean }[];
  databases: { name: string; branch_id: string | null; owner: string | null }[];
}

export function neonSnapshotFrom(project: any, branches: any[], endpoints: any[], databases: any[], readAt = new Date().toISOString()): NeonSnapshot {
  const p = project?.project ?? project ?? {};
  const s = p.default_endpoint_settings ?? {};
  return {
    kind: "neon", read_at: readAt,
    project: { id: String(p.id), name: str(p.name), region: str(p.region_id), pg_version: num(p.pg_version), created_at: iso(p.created_at), storage_bytes: num(p.synthetic_storage_size), data_storage_bytes_hour: num(p.data_storage_bytes_hour), compute_time_seconds: num(p.compute_time_seconds), active_time_seconds: num(p.active_time_seconds), written_data_bytes: num(p.written_data_bytes), data_transfer_bytes: num(p.data_transfer_bytes), consumption_period_start: iso(p.consumption_period_start), consumption_period_end: iso(p.consumption_period_end), history_retention_seconds: num(p.history_retention_seconds), autoscaling_min_cu: num(s.autoscaling_limit_min_cu), autoscaling_max_cu: num(s.autoscaling_limit_max_cu), suspend_timeout_seconds: num(s.suspend_timeout_seconds), ip_allow: Array.isArray(p.settings?.allowed_ips?.ips) ? p.settings.allowed_ips.ips.map(String) : [], ip_allow_protected_only: Boolean(p.settings?.allowed_ips?.protected_branches_only), branch_limit: num(p.branch_logical_size_limit_bytes) },
    branches: (Array.isArray(branches) ? branches : []).map((b: any) => ({ id: String(b.id), name: str(b.name), default: Boolean(b.default ?? b.primary), protected: Boolean(b.protected), state: str(b.current_state), logical_size_bytes: num(b.logical_size), created_at: iso(b.created_at) })),
    endpoints: (Array.isArray(endpoints) ? endpoints : []).map((e: any) => ({ id: String(e.id), branch_id: str(e.branch_id), type: str(e.type), host: str(e.host), state: str(e.current_state), min_cu: num(e.autoscaling_limit_min_cu), max_cu: num(e.autoscaling_limit_max_cu), suspend_timeout_seconds: num(e.suspend_timeout_seconds), last_active: iso(e.last_active), pooler: Boolean(e.pooler_enabled), disabled: Boolean(e.disabled) })),
    databases: (Array.isArray(databases) ? databases : []).map((d: any) => ({ name: String(d.name), branch_id: str(d.branch_id), owner: str(d.owner_name) })),
  };
}

export class NeonClient {
  private readonly fetchImpl: typeof fetch;
  constructor(private readonly apiKey: string, opts: { fetchImpl?: typeof fetch; base?: string } = {}) { this.fetchImpl = opts.fetchImpl ?? fetch; this.base = opts.base ?? "https://console.neon.tech/api/v2"; }
  private readonly base: string;
  async get<T = any>(path: string): Promise<T> {
    const res = await this.fetchImpl(`${this.base}${path}`, { headers: { authorization: `Bearer ${this.apiKey}`, accept: "application/json" }, signal: AbortSignal.timeout(20_000) });
    if (!res.ok) { const body = (await res.text()).slice(0, 200); throw new Error(`Neon ${path}: HTTP ${res.status}${body ? ` ${body}` : ""}`); }
    return (await res.json()) as T;
  }
  /** Proves the key: the caller's own identity. */
  async whoami(): Promise<{ id: string | null; name: string | null; email_domain: string | null }> { const me = await this.get<any>("/users/me"); return { id: str(me.id), name: str(me.name ?? me.login), email_domain: typeof me.email === "string" && me.email.includes("@") ? me.email.split("@")[1] : null }; }
  async snapshot(projectId: string): Promise<NeonSnapshot> {
    const enc = encodeURIComponent(projectId);
    const [project, branches, endpoints] = await Promise.all([this.get<any>(`/projects/${enc}`), this.get<any>(`/projects/${enc}/branches`).catch(() => ({ branches: [] })), this.get<any>(`/projects/${enc}/endpoints`).catch(() => ({ endpoints: [] }))]);
    const list: any[] = Array.isArray(branches?.branches) ? branches.branches : [];
    const dbs = (await Promise.all(list.map((b: any) => this.get<any>(`/projects/${enc}/branches/${encodeURIComponent(b.id)}/databases`).then((r) => (Array.isArray(r?.databases) ? r.databases : [])).catch(() => [])))).flat();
    return neonSnapshotFrom(project, list, Array.isArray(endpoints?.endpoints) ? endpoints.endpoints : [], dbs);
  }
}

// ---- Redis Cloud ----------------------------------------------------------------------------------------------------

export interface RedisSnapshot {
  kind: "redis_cloud"; read_at: string;
  subscription: { id: string; name: string | null; status: string | null; plan: string | null; kind: "pro" | "essentials" };
  database: { id: string; name: string; status: string | null; protocol: string | null; provider: string | null; region: string | null; redis_version: string | null; memory_limit_mb: number | null; memory_used_mb: number | null; memory_storage: string | null; persistence: string | null; replication: boolean | null; eviction: string | null; throughput_by: string | null; throughput_value: number | null; public_endpoint: string | null; private_endpoint: string | null; tls: boolean | null; ssl_client_auth: boolean | null; source_ips: string[]; default_user: boolean | null; modules: string[]; clustering: boolean | null; created_at: string | null };
}

export function redisDatabaseFrom(d: any, sub: any, kind: "pro" | "essentials", readAt = new Date().toISOString()): RedisSnapshot {
  const limitGb = num(d.memoryLimitInGb) ?? num(d.datasetSizeInGb) ?? num(d.planMemoryLimit);
  return {
    kind: "redis_cloud", read_at: readAt,
    subscription: { id: String(sub?.id ?? ""), name: str(sub?.name), status: str(sub?.status), plan: str(sub?.planName ?? sub?.plan?.name ?? sub?.plan), kind },
    database: { id: String(d.databaseId ?? d.id), name: String(d.name), status: str(d.status), protocol: str(d.protocol), provider: str(d.provider), region: str(d.region), redis_version: str(d.redisVersionCompliance ?? d.redisVersion), memory_limit_mb: limitGb != null ? Math.round(limitGb * 1024) : null, memory_used_mb: num(d.memoryUsedInMb), memory_storage: str(d.memoryStorage), persistence: str(d.dataPersistence), replication: typeof d.replication === "boolean" ? d.replication : null, eviction: str(d.dataEvictionPolicy), throughput_by: str(d.throughputMeasurement?.by), throughput_value: num(d.throughputMeasurement?.value), public_endpoint: str(d.publicEndpoint), private_endpoint: str(d.privateEndpoint), tls: typeof d.enableTls === "boolean" ? d.enableTls : null, ssl_client_auth: typeof d.security?.sslClientAuthentication === "boolean" ? d.security.sslClientAuthentication : null, source_ips: Array.isArray(d.security?.sourceIps) ? d.security.sourceIps.map(String) : [], default_user: typeof d.security?.enableDefaultUser === "boolean" ? d.security.enableDefaultUser : null, modules: Array.isArray(d.modules) ? d.modules.map((m: any) => String(m.name ?? m)) : [], clustering: typeof d.clustering?.enabled === "boolean" ? d.clustering.enabled : (typeof d.clustering === "boolean" ? d.clustering : null), created_at: iso(d.activatedOn ?? d.createdAt) },
  };
}

export class RedisCloudClient {
  private readonly fetchImpl: typeof fetch; private readonly base: string;
  constructor(private readonly apiKey: string, private readonly secretKey: string, opts: { fetchImpl?: typeof fetch; base?: string } = {}) { this.fetchImpl = opts.fetchImpl ?? fetch; this.base = opts.base ?? "https://api.redislabs.com/v1"; }
  async get<T = any>(path: string): Promise<T> {
    const res = await this.fetchImpl(`${this.base}${path}`, { headers: { "x-api-key": this.apiKey, "x-api-secret-key": this.secretKey, accept: "application/json" }, signal: AbortSignal.timeout(20_000) });
    if (!res.ok) { const body = (await res.text()).slice(0, 200); throw new Error(`Redis Cloud ${path}: HTTP ${res.status}${body ? ` ${body}` : ""}`); }
    return (await res.json()) as T;
  }
  /** Proves the keys: the account they belong to. */
  async whoami(): Promise<{ id: string | null; name: string | null }> { const r = await this.get<any>("/"); const a = r?.account ?? r; return { id: str(a?.id), name: str(a?.name) }; }
  /** Every database on every subscription, Pro and Essentials (fixed) alike, with its subscription. */
  async databases(): Promise<RedisSnapshot[]> {
    const out: RedisSnapshot[] = []; const now = new Date().toISOString();
    for (const kind of ["pro", "essentials"] as const) {
      const subsPath = kind === "pro" ? "/subscriptions" : "/fixed/subscriptions";
      let subs: any[] = []; try { const r = await this.get<any>(subsPath); subs = Array.isArray(r?.subscriptions) ? r.subscriptions : []; } catch { continue; }
      for (const sub of subs) {
        try {
          const r = await this.get<any>(`${subsPath}/${encodeURIComponent(sub.id)}/databases`);
          const dbs: any[] = Array.isArray(r?.subscription) ? r.subscription.flatMap((s: any) => (Array.isArray(s.databases) ? s.databases : [])) : Array.isArray(r?.databases) ? r.databases : [];
          for (const d of dbs) out.push(redisDatabaseFrom(d, sub, kind, now));
        } catch { /* a subscription the keys cannot read */ }
      }
    }
    return out;
  }
  /** The database behind a Vercel Redis store, by the store's name (the marketplace names them alike) or a public endpoint host. */
  async find(name: string, host?: string | null): Promise<RedisSnapshot | null> {
    const all = await this.databases();
    return all.find((s) => s.database.name === name) ?? (host ? all.find((s) => s.database.public_endpoint?.split(":")[0] === host) ?? null : null) ?? all.find((s) => s.database.name.toLowerCase() === name.toLowerCase()) ?? null;
  }
}

export type PartnerSnapshot = NeonSnapshot | RedisSnapshot;
export interface PartnerRecord { snapshot: PartnerSnapshot | null; error: string | null; read_at: string }

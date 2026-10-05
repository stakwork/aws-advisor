/**
 * The platform services the advisor inventories beyond compute and data stores: certificates (ACM), messaging (SNS),
 * keys (KMS), file systems (EFS), backups (AWS Backup vaults and plans), analytics (Athena workgroups), stacks
 * (CloudFormation), web filters (WAF) and threat detection (GuardDuty). One collector per service in src/services/
 * reads Steampipe (and CloudWatch where a number needs it) and returns rows already in the words of
 * docs/cloud-ontology.md: `props` are the generic node's properties, `links` the edges to other nodes. They share one
 * table, keyed by (native_type, id), so a service is a collector and a mapping, not a schema; the Inventory page reads
 * each kind from it, the AWS adapter (src/adapters/aws/resources.ts) emits one node per row and src/graph_services.ts
 * writes the links. GuardDuty findings are events, not resources: they have their own table (threat_findings).
 */
import { CloudWatchClient, GetMetricDataCommand, type MetricDataQuery } from "@aws-sdk/client-cloudwatch";
import { db } from "./db.js";
import { S, query } from "./steampipe.js";
import { describeError } from "./permissions.js";
import { accountCredentials } from "./accounts.js";
import { accountWhere, scopedStmt, type AccountScope } from "./scope.js";

db.exec(`create table if not exists inventory_service (
  native_type text not null, id text not null, account_id text not null default '', region text not null default '',
  name text, arn text, state text, created text, tags text, monthly_usd real, props text not null default '{}', links text not null default '[]',
  first_seen text not null, last_seen text not null, gone integer not null default 0,
  primary key (native_type, id)
);
create index if not exists inventory_service_kind on inventory_service(native_type, gone);
create table if not exists threat_findings (
  id text primary key, account_id text not null default '', region text not null default '', detector_id text, detector_arn text,
  type text, title text, description text, severity real, severity_label text, confidence real,
  resource_type text, resource_id text, resource_name text, count integer, first_seen_at text, last_seen_at text, created_at text, updated_at text,
  archived integer not null default 0, first_seen text not null, last_seen text not null, gone integer not null default 0
);`);

/** The inventory tab (and generic kind) each native type belongs to; WAF lands under the existing Filters tab. */
export const SERVICE_TABS = {
  certificates: ["acm_certificate"],
  messaging: ["sns_topic"],
  keys: ["kms_key"],
  files: ["efs_file_system"],
  backups: ["backup_vault", "backup_plan"],
  analytics: ["athena_workgroup"],
  stacks: ["cloudformation_stack"],
  threats: ["guardduty_detector"],
  waf: ["wafv2_web_acl"],
} as const;
export type ServiceTab = keyof typeof SERVICE_TABS;
export type NativeType = (typeof SERVICE_TABS)[ServiceTab][number];

/**
 * An edge from (dir out) or to (dir in) the row's node. `other` is a node id (an ARN, an instance or volume id, a
 * bucket name...) or, with `label`, the id of a network node (AdvisorFilter, AdvisorNetwork, AdvisorSegment).
 * `known_only` drops the edge when the graph has no node for `other` instead of writing a reference; `resolve` asks
 * the refresh to turn a KMS alias or key id into the key's ARN first.
 */
export interface ServiceLink { rel: LinkRel; other: string; dir: "out" | "in"; label?: "AdvisorFilter" | "AdvisorNetwork" | "AdvisorSegment"; known_only?: boolean; resolve?: "kms_key"; props?: Record<string, string | number | boolean | null> }
export const LINK_RELS = ["SECURES", "DELIVERS_TO", "ENCRYPTS", "GUARDED_BY", "IN_NETWORK", "IN_SEGMENT", "MANAGES", "PART_OF", "PROTECTS", "STORES_IN", "BACKED_UP_TO", "WRITES_TO"] as const;
export type LinkRel = (typeof LINK_RELS)[number];

export interface ServiceRow {
  native_type: NativeType; id: string; account_id: string; region: string; name: string | null; arn: string | null; state: string | null; created: string | null;
  tags: Record<string, string> | null; monthly_usd: number | null; props: Record<string, unknown>; links: ServiceLink[];
}

export interface ThreatFinding {
  id: string; account_id: string; region: string; detector_id: string | null; detector_arn: string | null; type: string | null; title: string | null; description: string | null;
  severity: number | null; severity_label: string | null; confidence: number | null; resource_type: string | null; resource_id: string | null; resource_name: string | null;
  count: number | null; first_seen_at: string | null; last_seen_at: string | null; created_at: string | null; updated_at: string | null; archived: boolean;
}

/**
 * `required`: columns without which the table is useless (a missing one fails the select). `optional`: the API call
 * that fills a column the plugin fetches per row (tags, a rotation status, a logging config) -> the columns it fills;
 * when the role may not make that call, those columns are dropped, the denial is reported once, and the rows still land.
 */
export interface SelectOpts { required?: string[]; where?: string; optional?: Record<string, string[]> }
/** The per-row tag calls every service makes for the tags column. */
const TAG_CALLS = /\b(ListResourceTags|ListTagsFor\w*|ListTags|ListTagsOfResource)\b/;

export interface CollectContext {
  onError: (m: string) => void;
  onLog: (l: string) => void;
  /** select the columns a plugin version has: a missing one is dropped and logged, the rest still lands; null when the table cannot be read */
  select: (table: string, cols: string[], opts?: SelectOpts) => Promise<any[] | null>;
  metrics: typeof metricSums;
}

/** What a collector read: its rows, the native types it read completely (only those can mark rows gone), and GuardDuty's findings. */
export interface CollectResult { rows: ServiceRow[]; complete: NativeType[]; findings?: ThreatFinding[] | null }
export interface ServiceCollector { name: string; collect: (ctx: CollectContext) => Promise<CollectResult> }

// ---- helpers the collectors share ----------------------------------------------------------------------------------

export const num = (v: unknown): number | null => (v == null || v === "" || !Number.isFinite(Number(v)) ? null : Number(v));
export const str = (v: unknown): string | null => (v == null || v === "" ? null : String(v));
export const iso = (v: unknown): string | null => { if (v == null || v === "") return null; const d = v instanceof Date ? v : new Date(String(v)); return Number.isNaN(d.getTime()) ? null : d.toISOString(); };
export const json = (v: unknown): any => { if (v == null) return null; if (typeof v === "string") { try { return JSON.parse(v); } catch { return null; } } return v; };
export const round2 = (v: number) => Math.round(v * 100) / 100;
export const gb = (bytes: unknown): number | null => (num(bytes) == null ? null : round2(Number(bytes) / 1e9));
export const daysUntil = (at: string | null, now = Date.now()): number | null => (at ? Math.floor((Date.parse(at) - now) / 86400000) : null);
/** Steampipe's tags column (a map, or the provider's [{Key, Value}] list) as a flat map; null when absent. */
export function tagsOf(v: unknown): Record<string, string> | null {
  const t = json(v);
  if (!t) return null;
  if (Array.isArray(t)) { const out: Record<string, string> = {}; for (const x of t) if (x?.Key) out[String(x.Key)] = String(x.Value ?? ""); return out; }
  if (typeof t === "object") return Object.fromEntries(Object.entries(t).map(([k, x]) => [k, String(x ?? "")]));
  return null;
}
/** "lambda 2, sqs 1": a count per word, most first. */
export const countList = (words: (string | null | undefined)[]): string[] => {
  const m = new Map<string, number>(); for (const w of words) if (w) m.set(w, (m.get(w) ?? 0) + 1);
  return [...m.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).map(([w, n]) => `${w} ${n}`);
};

const COLUMN_MISSING = /column "?(\w+)"? does not exist/i;

async function selectAvailable(table: string, cols: string[], opts: SelectOpts, onError: (m: string) => void, onLog: (l: string) => void): Promise<any[] | null> {
  let list = [...cols];
  const required = new Set(["region", "account_id", ...(opts.required ?? [])]);
  const context = `${table.replace(/^aws_/, "").replace(/_/g, " ")} inventory (${table})`;
  for (;;) {
    try { return await query<any>(`select ${list.join(", ")} from ${S}.${table}${opts.where ? ` where ${opts.where}` : ""}`); }
    catch (e) {
      const msg = String((e as any)?.message ?? e);
      const m = COLUMN_MISSING.exec(msg);
      if (m && list.includes(m[1]) && !required.has(m[1])) { list = list.filter((c) => c !== m[1]); onLog(`${table}: column ${m[1]} not available, skipped`); continue; }
      // a per-row call the role may not make: drop the columns it fills and keep the rows
      const denied = /AccessDenied|AuthorizationError|not authorized|UnauthorizedOperation/i.test(msg);
      const call = denied ? Object.keys(opts.optional ?? {}).find((op) => msg.includes(op)) ?? (TAG_CALLS.exec(msg)?.[1] ?? null) : null;
      const drop = call ? (opts.optional?.[call] ?? (TAG_CALLS.test(call) ? ["tags"] : [])).filter((c) => list.includes(c) && !required.has(c)) : [];
      if (drop.length) { onError(describeError(e, `${context}, column${drop.length === 1 ? "" : "s"} ${drop.join(", ")}`)); list = list.filter((c) => !drop.includes(c)); onLog(`${table}: ${call} denied, ${drop.join(", ")} left out`); continue; }
      onError(describeError(e, context)); return null;
    }
  }
}

/** One CloudWatch series to sum per day: a metric with its exact dimensions, or an expression (a SEARCH when the dimensions vary). */
export interface MetricAsk { key: string; namespace?: string; metric?: string; dims?: { Name: string; Value: string }[]; stat?: "Sum" | "Average" | "Maximum"; expression?: string }

/**
 * Daily sums over `days` for each ask, under the account's own credentials: the total and how many days had data
 * (so a caller can scale a partial window to a month). 500 queries a call, SEARCH expressions 5 a call.
 */
export async function metricSums(accountId: string | null, region: string, asks: MetricAsk[], days = 30): Promise<Map<string, { sum: number; days: number }>> {
  const out = new Map<string, { sum: number; days: number }>();
  if (!asks.length) return out;
  const cw = new CloudWatchClient({ region, credentials: accountCredentials(accountId).provider });
  try {
    const queries: MetricDataQuery[] = asks.map((a, i) => a.expression
      ? { Id: `q${i}`, Expression: a.expression, Period: 86400, ReturnData: true }
      : { Id: `q${i}`, MetricStat: { Metric: { Namespace: a.namespace, MetricName: a.metric, Dimensions: a.dims }, Period: 86400, Stat: a.stat ?? "Sum" }, ReturnData: true });
    const size = asks.some((a) => a.expression?.includes("SEARCH(")) ? 5 : 500;
    const end = Date.now();
    for (let i = 0; i < queries.length; i += size) {
      let token: string | undefined;
      do {
        const r = await cw.send(new GetMetricDataCommand({ StartTime: new Date(end - days * 86400000), EndTime: new Date(end), MetricDataQueries: queries.slice(i, i + size), ScanBy: "TimestampAscending", NextToken: token }));
        for (const m of r.MetricDataResults ?? []) {
          const ask = asks[Number(String(m.Id).slice(1))]; if (!ask) continue;
          const e = out.get(ask.key) ?? { sum: 0, days: 0 }; out.set(ask.key, e);
          e.sum += (m.Values ?? []).reduce((s, v) => s + (v || 0), 0); e.days = Math.max(e.days, (m.Values ?? []).length);
        }
        token = r.NextToken;
      } while (token);
    }
  } finally { cw.destroy(); }
  return out;
}

/** Group rows by (account, region): the unit a CloudWatch call is made for. */
export function byAccountRegion<T extends { account_id?: unknown; region?: unknown }>(rows: T[]): Map<string, { account: string | null; region: string; rows: T[] }> {
  const out = new Map<string, { account: string | null; region: string; rows: T[] }>();
  for (const r of rows) {
    const account = r.account_id ? String(r.account_id) : null; const region = String(r.region || "us-east-1");
    const k = `${account ?? ""}|${region}`;
    if (!out.has(k)) out.set(k, { account, region, rows: [] });
    out.get(k)!.rows.push(r);
  }
  return out;
}

/** Metrics per (account, region) group; a failed group is reported and skipped, the rows keep no metric. */
export async function metricsByGroup<T extends { account_id?: unknown; region?: unknown }>(ctx: CollectContext, what: string, rows: T[], asks: (r: T) => MetricAsk[]): Promise<Map<string, { sum: number; days: number }>> {
  const out = new Map<string, { sum: number; days: number }>();
  for (const g of byAccountRegion(rows).values()) {
    try { for (const [k, v] of await ctx.metrics(g.account, g.region, g.rows.flatMap(asks))) out.set(k, v); }
    catch (e) { ctx.onError(describeError(e, `${what} metrics ${g.region}${g.account ? ` (account ${g.account})` : ""} (cloudwatch:GetMetricData)`)); }
  }
  return out;
}

/**
 * A KMS reference (key ARN, key id, alias name or alias ARN) as the key's ARN, by the keys this refresh read in the
 * same account and region; an alias the refresh did not see stays an alias ARN (the graph writes it as a reference). Pure.
 */
export function kmsResolver(keys: ServiceRow[]): (ref: string, account: string, region: string) => string {
  const index = new Map<string, string>();
  for (const k of keys) {
    const at = `${k.account_id}|${k.region}|`;
    index.set(k.id, k.id);
    const keyId = str(k.props.key_id); if (keyId) index.set(at + keyId, k.id);
    for (const a of (k.props.aliases as string[] | undefined) ?? []) index.set(at + a, k.id);
  }
  return (ref, account, region) => {
    if (index.has(ref)) return index.get(ref)!;
    const m = /^arn:aws[a-z-]*:kms:([a-z0-9-]+):(\d{12}):(key\/.+|alias\/.+)$/.exec(ref);
    const [acct, reg, local] = m ? [m[2], m[1], m[3].startsWith("key/") ? m[3].slice(4) : m[3]] : [account, region, ref];
    const found = index.get(`${acct}|${reg}|${local}`);
    if (found) return found;
    if (m) return ref;
    return local.startsWith("alias/") ? `arn:aws:kms:${reg}:${acct}:${local}` : `arn:aws:kms:${reg}:${acct}:key/${local}`;
  };
}

// ---- refresh ----------------------------------------------------------------------------------------------------

const upsert = db.prepare(`insert into inventory_service(native_type, id, account_id, region, name, arn, state, created, tags, monthly_usd, props, links, first_seen, last_seen, gone)
  values (@native_type, @id, @account_id, @region, @name, @arn, @state, @created, @tags, @monthly_usd, @props, @links, @now, @now, 0)
  on conflict(native_type, id) do update set account_id = excluded.account_id, region = excluded.region, name = excluded.name, arn = excluded.arn, state = excluded.state, created = excluded.created,
    tags = excluded.tags, monthly_usd = excluded.monthly_usd, props = excluded.props, links = excluded.links, last_seen = excluded.last_seen, gone = 0`);
const upsertFinding = db.prepare(`insert into threat_findings(id, account_id, region, detector_id, detector_arn, type, title, description, severity, severity_label, confidence, resource_type, resource_id, resource_name,
    count, first_seen_at, last_seen_at, created_at, updated_at, archived, first_seen, last_seen, gone)
  values (@id, @account_id, @region, @detector_id, @detector_arn, @type, @title, @description, @severity, @severity_label, @confidence, @resource_type, @resource_id, @resource_name,
    @count, @first_seen_at, @last_seen_at, @created_at, @updated_at, @archived, @now, @now, 0)
  on conflict(id) do update set account_id = excluded.account_id, region = excluded.region, detector_id = excluded.detector_id, detector_arn = excluded.detector_arn, type = excluded.type, title = excluded.title,
    description = excluded.description, severity = excluded.severity, severity_label = excluded.severity_label, confidence = excluded.confidence, resource_type = excluded.resource_type, resource_id = excluded.resource_id,
    resource_name = excluded.resource_name, count = excluded.count, first_seen_at = excluded.first_seen_at, last_seen_at = excluded.last_seen_at, created_at = excluded.created_at, updated_at = excluded.updated_at,
    archived = excluded.archived, last_seen = excluded.last_seen, gone = 0`);

/**
 * Rows of a native type this refresh read completely but did not return go gone, in the accounts the refresh saw at
 * all (any service row from them): an account that answered nothing is one the credentials could not reach, and its
 * rows keep their state, as markGone does for the instances (src/inventory.ts). Pure over the arguments; exported for the tests.
 */
export function goneScope(rows: ServiceRow[], primary: string | null): string[] {
  const accounts = new Set(rows.map((r) => r.account_id));
  if (primary && accounts.has(primary)) accounts.add("");
  return [...accounts];
}

export async function refreshServiceInventory(onError: (m: string) => void = () => {}, onLog: (l: string) => void = () => {}, primary: string | null = null): Promise<Record<string, number>> {
  const { SERVICE_COLLECTORS } = await import("./services/index.js");
  const ctx: CollectContext = { onError, onLog, select: (t, c, o = {}) => selectAvailable(t, c, o, onError, onLog), metrics: metricSums };
  const rows: ServiceRow[] = []; const complete = new Set<NativeType>(); let findings: ThreatFinding[] | null = null;
  for (const c of SERVICE_COLLECTORS) {
    try { const r = await c.collect(ctx); rows.push(...r.rows); r.complete.forEach((t) => complete.add(t)); if (r.findings) findings = r.findings; }
    catch (e) { onError(describeError(e, `${c.name} inventory`)); }
  }
  // KMS references (an alias on a topic, a key id on a file system) become the key's ARN, so ENCRYPTS lands on the key node
  const resolveKey = kmsResolver(rows.filter((r) => r.native_type === "kms_key"));
  for (const r of rows) for (const l of r.links) if (l.resolve === "kms_key") { l.other = resolveKey(l.other, r.account_id, r.region); delete l.resolve; }
  const now = new Date().toISOString();
  const accounts = goneScope(rows, primary);
  const counts: Record<string, number> = {};
  db.transaction(() => {
    for (const r of rows) {
      upsert.run({ native_type: r.native_type, id: r.id, account_id: r.account_id, region: r.region, name: r.name, arn: r.arn, state: r.state, created: r.created, tags: r.tags ? JSON.stringify(r.tags) : null,
        monthly_usd: r.monthly_usd, props: JSON.stringify(r.props), links: JSON.stringify(r.links), now });
      counts[r.native_type] = (counts[r.native_type] ?? 0) + 1;
    }
    if (accounts.length) for (const t of complete) db.prepare(`update inventory_service set gone = 1 where native_type = ? and last_seen <> ? and account_id in (${accounts.map(() => "?").join(",")})`).run(t, now, ...accounts);
    if (findings) {
      for (const f of findings) upsertFinding.run({ ...f, archived: f.archived ? 1 : 0, now });
      if (accounts.length) db.prepare(`update threat_findings set gone = 1 where last_seen <> ? and account_id in (${accounts.map(() => "?").join(",")})`).run(now, ...accounts);
      // GuardDuty keeps a finding 90 days; so does the table
      db.prepare("delete from threat_findings where gone = 1 and coalesce(updated_at, last_seen) < ?").run(new Date(Date.now() - 90 * 86400000).toISOString());
      counts.threat_findings = findings.length;
    }
  })();
  return counts;
}

// ---- readers ----------------------------------------------------------------------------------------------------

const parse = (r: any) => ({ ...r, tags: json(r.tags) || {}, props: json(r.props) || {}, links: json(r.links) || [] });

/** One tab's rows: the props parsed, the most expensive first, then by name. */
export function listServices(tab: ServiceTab, f: { q?: string; gone?: boolean; scope?: AccountScope | null; type?: string } = {}) {
  const types = (SERVICE_TABS[tab] as readonly string[]).filter((t) => !f.type || t === f.type);
  if (!types.length) return [];
  const where = [`native_type in (${types.map(() => "?").join(",")})`]; const params: unknown[] = [...types];
  if (f.scope) { const a = accountWhere(f.scope); where.push(a.sql); params.push(...a.params); }
  if (!f.gone) where.push("gone = 0");
  if (f.q) { where.push("(name like ? or id like ? or region like ? or state like ? or props like ?)"); params.push(...Array(5).fill(`%${f.q}%`)); }
  return (db.prepare(`select * from inventory_service where ${where.join(" and ")} order by gone, coalesce(monthly_usd, 0) desc, name limit 2000`).all(...params) as any[]).map(parse);
}

/** Findings, the open and most severe first; archived and gone only when asked. */
export function listThreatFindings(f: { q?: string; gone?: boolean; archived?: boolean; scope?: AccountScope | null; detector?: string } = {}) {
  const where: string[] = []; const params: unknown[] = [];
  if (f.scope) { const a = accountWhere(f.scope); where.push(a.sql); params.push(...a.params); }
  if (!f.gone) where.push("gone = 0");
  if (!f.archived) where.push("archived = 0");
  if (f.detector) { where.push("(detector_arn = ? or detector_id = ?)"); params.push(f.detector, f.detector); }
  if (f.q) { where.push("(title like ? or type like ? or resource_id like ? or resource_name like ?)"); params.push(...Array(4).fill(`%${f.q}%`)); }
  return db.prepare(`select * from threat_findings ${where.length ? `where ${where.join(" and ")}` : ""} order by severity desc, last_seen_at desc limit 2000`).all(...params) as any[];
}

/** Per tab: how many, the list price, and the one or two numbers its header shows. */
export function serviceSummary(scope?: AccountScope | null): Record<ServiceTab, Record<string, number>> {
  const all = (scopedStmt(scope, "select native_type, gone, state, monthly_usd, props from inventory_service").all() as any[]).map((r) => ({ ...r, props: json(r.props) || {} }));
  const out = {} as Record<ServiceTab, Record<string, number>>;
  for (const tab of Object.keys(SERVICE_TABS) as ServiceTab[]) {
    const types = SERVICE_TABS[tab] as readonly string[];
    const live = all.filter((r) => types.includes(r.native_type) && !r.gone);
    const s: Record<string, number> = { total: live.length, gone: all.filter((r) => types.includes(r.native_type) && r.gone).length, monthly_usd: round2(live.reduce((t, r) => t + (Number(r.monthly_usd) || 0), 0)) };
    for (const t of types) s[t] = live.filter((r) => r.native_type === t).length;
    const p = live.map((r) => r.props);
    if (tab === "certificates") { s.expiring_30d = p.filter((x) => x.days_left != null && x.days_left >= 0 && x.days_left <= 30).length; s.expired = p.filter((x) => x.status === "expired").length; s.unused = p.filter((x) => x.in_use === false).length; }
    if (tab === "messaging") { s.subscriptions = p.reduce((t, x) => t + (Number(x.subscriptions) || 0), 0); s.unencrypted = p.filter((x) => x.encrypted === false).length; s.messages_30d = p.reduce((t, x) => t + (Number(x.messages_30d) || 0), 0); }
    if (tab === "keys") { s.customer = p.filter((x) => x.managed === false).length; s.no_rotation = p.filter((x) => x.managed === false && x.key_state === "enabled" && x.rotation_enabled === false).length; s.pending_deletion = p.filter((x) => x.key_state === "pending_deletion").length; }
    if (tab === "files") { s.size_gb = round2(p.reduce((t, x) => t + (Number(x.size_gb) || 0), 0)); s.unencrypted = p.filter((x) => x.encrypted === false).length; }
    if (tab === "backups") { s.recovery_points = p.reduce((t, x) => t + (Number(x.recovery_points) || 0), 0); s.size_gb = round2(p.reduce((t, x) => t + (Number(x.size_gb) || 0), 0)); s.protected = p.reduce((t, x) => t + (Number(x.protected_resources) || 0), 0); }
    if (tab === "analytics") s.scanned_gb_30d = round2(p.reduce((t, x) => t + (Number(x.scanned_gb_30d) || 0), 0));
    if (tab === "stacks") { s.drifted = p.filter((x) => x.drift === "drifted").length; s.failed = live.filter((r) => /FAILED|ROLLBACK_COMPLETE$/.test(String(r.state)) && r.state !== "UPDATE_ROLLBACK_COMPLETE").length; s.managed = p.reduce((t, x) => t + (Number(x.resources) || 0), 0); }
    if (tab === "waf") { s.attached = p.reduce((t, x) => t + (Number(x.attached) || 0), 0); s.unattached = p.filter((x) => !Number(x.attached)).length; }
    if (tab === "threats") {
      s.enabled = live.filter((r) => r.props.enabled).length;
      const f = scopedStmt(scope, "select coalesce(sum(severity_label = 'critical'), 0) as critical, coalesce(sum(severity_label = 'high'), 0) as high, coalesce(sum(severity_label = 'medium'), 0) as medium, coalesce(sum(severity_label = 'low'), 0) as low, count(*) as open from threat_findings where gone = 0 and archived = 0").get() as Record<string, number>;
      Object.assign(s, { findings_open: Number(f.open) || 0, critical: Number(f.critical) || 0, high: Number(f.high) || 0, medium: Number(f.medium) || 0, low: Number(f.low) || 0 });
    }
    out[tab] = s;
  }
  return out;
}

/** Ids of every service row, for the account index and the graph's id set. */
export function serviceIds(): { id: string; account_id: string }[] {
  try { return db.prepare("select id, account_id from inventory_service").all() as any[]; } catch { return []; }
}

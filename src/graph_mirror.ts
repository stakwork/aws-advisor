import neo4j, { Driver, Session } from "neo4j-driver";
import { config } from "./config.js";
import { db, getJsonSetting } from "./db.js";
import { listPlaybooks } from "./playbooks.js";
import { alertLevel } from "./alert_level.js";

/**
 * One-way mirror of the advisor's operational data into Neo4j, so the agent, NavFiber and Neo4j Browser can
 * walk resources, roles, recommendations, decisions, incidents and rules next to the code graph and the
 * team's Concepts. SQLite stays the source of truth: the advisor never reads this mirror back, every mirror
 * function is idempotent (MERGE on the id), and the whole thing can be wiped and resynced at any time
 * (`mirrorAll`, `POST /api/graph/sync`). Every write is fire-and-forget from the hooks: a failing Neo4j is
 * logged (at most once a minute) and never breaks a run, a decision or the UI. With `NEO4J_URI` unset every
 * function here is a no-op.
 *
 * Labels are all prefixed `Advisor` (the Neo4j is shared with stakgraph / repo2graph, whose nodes are never
 * touched); the only foreign label used is `Concept`, MATCHed by id to link a decided recommendation to the
 * team's decision or rule. Every node carries `account_id` and `updated_at`.
 */

export const BATCH = 250;
export const QUERY_TIMEOUT_MS = 5_000;
export const QUERY_ROW_CAP = 200;

export const LABELS = ["AdvisorAccount", "AdvisorResource", "AdvisorResourceRef", "AdvisorRole", "AdvisorNodePool", "AdvisorRecommendation", "AdvisorRun", "AdvisorControl", "AdvisorPlaybook", "AdvisorAlert", "AdvisorIncident"] as const;

/** The schema as told to the agent (graph_query tool) and shown in the README. */
export const SCHEMA_SUMMARY = [
  "(:KnSystem {id, name, kind: pool|instance|rds_cluster|rds_instance|cache_group|cache_cluster|nat, pool_kind, archetype, member_count, ebs_gb, monthly_list_usd, gone}) our systems as a schematic; (:AdvisorResource)-[:MEMBER_OF]->(:KnSystem); (:KnSystem)-[:IS_A]->(:KnArchetype {name, description}); (:KnSystem)-[:RUNS_ON {count, hours_month, list_price, list_usd_month}]->(:KnSystemType {id, kind: ec2|rds|elasticache|usage, sku, region, list_price, price_unit, source})",
  "(:KnPricingOverlay {kind: savings_plan|reservation, discount_rate, commitment_usd_month, sku, count, end})-[:COVERS]->(:KnSystemType); (:KnSystem|:AdvisorAccount)-[:TRANSFERS_TO {mechanism: nat|cross-az, gb_day, price_per_gb, usd_month, source}]->(:KnService {name}); (:KnSystem|:AdvisorAccount)-[:SHIPS_LOGS_TO {gb_day, usd_month}]->(:KnLogGroup {name, retention_days, stored_gb, ingest_gb_day, ingest_usd_month, storage_usd_month}); (:KnPattern {text}) operational rules; AdvisorRecommendation carries verdict, realised_usd_month, realised_ratio once verified",
  "(:AdvisorResource {id, kind: ec2|rds|elasticache, name, type, state, region, role, role_confidence, protected_prob, monthly_usd, cpu_30d, ssm_status, gone, first_seen, last_seen})-[:IN_ACCOUNT]->(:AdvisorAccount {id})",
  "(:AdvisorResource)-[:HAS_ROLE]->(:AdvisorRole {name}); (:AdvisorResource)-[:IN_POOL]->(:AdvisorNodePool {name}) for autoscaled EC2 nodes (Karpenter pool, EKS node group, ASG)",
  "(:AdvisorRecommendation {id, fingerprint, title, action_type, tier, status, source, rule, est_monthly_saving, confidence, decided_by, decided_at, decision_scope, created_at})-[:TARGETS]->(:AdvisorResource | :AdvisorResourceRef {id})",
  "(:AdvisorRecommendation)-[:DECIDED_AS]->(:Concept) when the team's decision was mirrored as a Concept (the Concept holds the decision, its reason and the rule)",
  "(:AdvisorRecommendation)-[:PROPOSED_IN]->(:AdvisorRun {id, started_at, finished_at, status, trigger, findings_count, recommendations_count})",
  "(:AdvisorRecommendation)-[:FROM_INCIDENT]->(:AdvisorIncident {id, status, cause, confidence, episode_cost_usd, monthly_run_rate_usd, created_at})-[:INVESTIGATES]->(:AdvisorAlert {id, kind, level, message, created_at, acknowledged, acknowledged_by})-[:ABOUT]->(:AdvisorResource | :AdvisorResourceRef)",
  "(:AdvisorControl {id, title})-[:FLAGGED {run_id, reason}]->(:AdvisorResource) for the latest completed run's alarm findings; (:AdvisorControl)-[:HAS_PLAYBOOK]->(:AdvisorPlaybook {control_id, title, tier, effort})",
].join("\n");

export const enabled = () => Boolean(config.neo4jUri);

/** The URI without credentials, for the UI and logs. */
export function graphUriForDisplay(uri = config.neo4jUri): string | null {
  if (!uri) return null;
  try { const u = new URL(uri); return `${u.protocol}//${u.host}`; } catch { return uri.replace(/\/\/[^@/]*@/, "//"); }
}

// ---- driver, logging ----------------------------------------------------------------------------------------

let driver: Driver | null = null;
/** Drops the cached driver so the next call connects with the current settings. */
export function resetGraphDriver(): void { const d = driver; driver = null; if (d) d.close().catch(() => { /* closing */ }); }
function getDriver(): Driver {
  if (!driver) {
    driver = neo4j.driver(config.neo4jUri, neo4j.auth.basic(config.neo4jUser, config.neo4jPassword), {
      disableLosslessIntegers: true,
      connectionTimeout: 5_000,
      connectionAcquisitionTimeout: 10_000,
      maxConnectionPoolSize: 10,
    });
  }
  return driver;
}

const session = (mode: "READ" | "WRITE"): Session =>
  getDriver().session({ defaultAccessMode: mode === "READ" ? neo4j.session.READ : neo4j.session.WRITE, ...(config.neo4jDatabase ? { database: config.neo4jDatabase } : {}) });

const LOG_INTERVAL_MS = 60_000;
let lastLogAt = 0;
let suppressed = 0;
/** Errors from the fire-and-forget hooks are logged at most once a minute; the ones in between are counted. */
function logError(what: string, e: unknown) {
  const now = Date.now();
  if (now - lastLogAt < LOG_INTERVAL_MS) { suppressed++; return; }
  const extra = suppressed ? ` (${suppressed} earlier error${suppressed === 1 ? "" : "s"} not shown)` : "";
  suppressed = 0;
  lastLogAt = now;
  console.error(`[graph] ${what} failed: ${String((e as any)?.message || e).slice(0, 300)}${extra}`);
}

/** Runs a mirror step in the background; never throws. */
function inBackground(what: string, fn: () => Promise<unknown>): void {
  if (!enabled()) return;
  void fn().catch((e) => logError(what, e));
}

export async function closeGraph(): Promise<void> {
  if (driver) { const d = driver; driver = null; await d.close().catch(() => {}); }
}

// ---- pure mapping (exported for tests) -------------------------------------------------------------------------

const num = (v: unknown): number | null => (v == null || v === "" || !Number.isFinite(Number(v)) ? null : Number(v));
const str = (v: unknown): string | null => (v == null ? null : String(v));
const safeJson = (s: unknown): any => { if (typeof s !== "string") return s ?? null; try { return JSON.parse(s); } catch { return null; } };

export interface RoleRow { role: string; role_confidence: number | null; protected_prob: number | null }
export type RoleMap = Map<string, RoleRow>;

export interface ResourceNode {
  id: string; kind: "ec2" | "rds" | "elasticache"; name: string | null; type: string | null; state: string | null; region: string | null;
  role: string | null; role_confidence: number | null; protected_prob: number | null; monthly_usd: number | null; cpu_30d: number | null;
  ssm_status: string | null; gone: boolean; first_seen: string | null; last_seen: string | null; pool: string | null;
}

/** The autoscaling pool an EC2 instance belongs to (Karpenter node pool, EKS node group or ASG), from its snapshot tags; the EKS cluster prefixes the name like the watcher does. */
export function poolOf(snapshot: unknown): string | null {
  const tags = (safeJson(snapshot)?.tags || {}) as Record<string, string>;
  const pool = tags["karpenter.sh/nodepool"] || tags["eks:nodegroup-name"] || tags["aws:autoscaling:groupName"];
  if (!pool) return null;
  const cluster = tags["eks:cluster-name"];
  return cluster ? `${cluster}/${pool}` : pool;
}

const withRole = (id: string, roles: RoleMap) => { const r = roles.get(id); return { role: r?.role ?? null, role_confidence: num(r?.role_confidence), protected_prob: num(r?.protected_prob) }; };

export function resourceFromEc2(row: any, roles: RoleMap = new Map()): ResourceNode {
  return { id: String(row.instance_id), kind: "ec2", name: str(row.name), type: str(row.instance_type), state: str(row.state), region: str(row.region),
    ...withRole(String(row.instance_id), roles), monthly_usd: num(row.monthly_usd), cpu_30d: num(row.cpu_30d), ssm_status: str(row.ssm_status),
    gone: Boolean(row.gone), first_seen: str(row.first_seen), last_seen: str(row.last_seen), pool: poolOf(row.snapshot) };
}

export function resourceFromRds(row: any, roles: RoleMap = new Map()): ResourceNode {
  return { id: String(row.db_instance_identifier), kind: "rds", name: str(row.db_instance_identifier), type: str(row.class), state: str(row.status), region: str(row.region),
    ...withRole(String(row.db_instance_identifier), roles), monthly_usd: num(row.monthly_usd), cpu_30d: num(row.cpu_30d), ssm_status: null,
    gone: Boolean(row.gone), first_seen: str(row.first_seen), last_seen: str(row.last_seen), pool: null };
}

export function resourceFromElasticache(row: any, roles: RoleMap = new Map()): ResourceNode {
  return { id: String(row.cache_cluster_id), kind: "elasticache", name: str(row.cache_cluster_id), type: str(row.node_type), state: str(row.status), region: str(row.region),
    ...withRole(String(row.cache_cluster_id), roles), monthly_usd: num(row.monthly_usd), cpu_30d: null, ssm_status: null,
    gone: Boolean(row.gone), first_seen: str(row.first_seen), last_seen: str(row.last_seen), pool: null };
}

/**
 * The inventory id a resource reference points at: the id itself, or the last segment of an ARN
 * (`arn:aws:ec2:us-east-1:1:instance/i-abc` → `i-abc`, `arn:aws:rds:...:db:name` → `name`); null when the
 * inventory does not know it (a Lambda, a bucket, a VPC...).
 */
export function inventoryIdOf(resource: string | null | undefined, inventoryIds: Set<string>): string | null {
  if (!resource) return null;
  if (inventoryIds.has(resource)) return resource;
  const tail = resource.split(/[/:]/).pop();
  return tail && inventoryIds.has(tail) ? tail : null;
}

export interface RecommendationNode {
  id: number; fingerprint: string; title: string; action_type: string; tier: string; status: string; source: string; rule: string;
  est_monthly_saving: number | null; confidence: number | null; decided_by: string | null; decided_at: string | null; decision_scope: string | null; created_at: string | null;
  resource: string | null; resource_id: string | null; concept_id: string | null; run_id: number | null; incident_id: number | null;
}

export function recommendationNode(row: any, inventoryIds: Set<string>, concepts: Map<string, string>): RecommendationNode {
  const ev = safeJson(row.evidence) || {};
  const runId = num(row.run_id);
  const conceptId = concepts.get(String(row.fingerprint));
  return { id: Number(row.id), fingerprint: String(row.fingerprint), title: String(row.title), action_type: String(row.action_type), tier: String(row.tier), status: String(row.status),
    source: String(row.source), rule: String(row.rule), est_monthly_saving: num(row.est_monthly_saving), confidence: num(row.confidence), decided_by: str(row.decided_by),
    decided_at: str(row.decided_at), decision_scope: str(row.decision_scope), created_at: str(row.created_at), resource: str(row.resource),
    resource_id: inventoryIdOf(row.resource, inventoryIds), concept_id: conceptId || null, run_id: runId && runId > 0 ? runId : null, incident_id: num(ev.incident_id) };
}

export interface AlertNode { id: number; kind: string; level: string; message: string; created_at: string; acknowledged: boolean; acknowledged_by: string | null; resource: string | null; resource_id: string | null }

/** The level rule of src/alert_level.ts is duplicated here in its result only; the message is cut so a node stays small. */
export function alertNode(row: any, inventoryIds: Set<string>, level: string): AlertNode {
  return { id: Number(row.id), kind: String(row.kind), level, message: String(row.message || "").slice(0, 500), created_at: String(row.created_at), acknowledged: Boolean(row.acknowledged),
    acknowledged_by: str(row.acknowledged_by), resource: str(row.resource), resource_id: inventoryIdOf(row.resource, inventoryIds) };
}

export interface IncidentNode { id: number; alert_id: number; status: string; cause: string | null; confidence: number | null; episode_cost_usd: number | null; monthly_run_rate_usd: number | null; created_at: string }

export function incidentNode(row: any): IncidentNode {
  return { id: Number(row.id), alert_id: Number(row.alert_id), status: String(row.status), cause: row.cause ? String(row.cause).slice(0, 1000) : null, confidence: num(row.confidence),
    episode_cost_usd: num(row.episode_cost_usd), monthly_run_rate_usd: num(row.monthly_run_rate_usd), created_at: String(row.created_at) };
}

export interface RunNode { id: number; started_at: string; finished_at: string | null; status: string; trigger: string; findings_count: number; recommendations_count: number }

export function runNode(row: any): RunNode {
  return { id: Number(row.id), started_at: String(row.started_at), finished_at: str(row.finished_at), status: String(row.status), trigger: String(row.trigger),
    findings_count: num(row.findings_count) ?? 0, recommendations_count: num(row.recommendations_count) ?? 0 };
}

export interface FlagEdge { control_id: string; control_title: string | null; resource_id: string; run_id: number; reason: string | null }

/** Alarm findings of one run whose resource is in the inventory, one edge per (control, resource); the rest are skipped. */
export function flagEdges(findings: any[], inventoryIds: Set<string>, runId: number): FlagEdge[] {
  const seen = new Set<string>();
  const out: FlagEdge[] = [];
  for (const f of findings) {
    const rid = inventoryIdOf(f.resource, inventoryIds);
    if (!rid) continue;
    const key = `${f.control_id}|${rid}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ control_id: String(f.control_id), control_title: str(f.control_title), resource_id: rid, run_id: runId, reason: f.reason ? String(f.reason).slice(0, 500) : null });
  }
  return out;
}

// ---- Cypher guard for the read-only graph_query tool -----------------------------------------------------------

const stripCypherLiterals = (q: string) => q
  .replace(/'(?:[^'\\]|\\.)*'/g, "''")
  .replace(/"(?:[^"\\]|\\.)*"/g, '""')
  .replace(/`(?:[^`])*`/g, "``")
  .replace(/\/\/[^\n]*/g, " ")
  .replace(/\/\*[\s\S]*?\*\//g, " ");

const CYPHER_FORBIDDEN = /\b(create|merge|set|delete|detach|remove|drop|load|foreach|alter|grant|deny|revoke|start|stop|terminate)\b/i;

/** Accepts one read-only Cypher statement: starts with MATCH / OPTIONAL MATCH / WITH / CALL { ... }, no write clause, no apoc or dbms procedure. */
export function guardReadCypher(input: string): { cypher: string } | { error: string } {
  const cypher = String(input || "").trim().replace(/;+\s*$/, "").trim();
  if (!cypher) return { error: "empty query" };
  const bare = stripCypherLiterals(cypher);
  if (bare.includes(";")) return { error: "only a single statement is allowed" };
  if (!/^\s*(match\b|optional\s+match\b|with\b|call\s*\{)/i.test(bare)) return { error: "the query must start with MATCH, OPTIONAL MATCH, WITH or CALL { ... }" };
  const bad = bare.match(CYPHER_FORBIDDEN);
  if (bad) return { error: `the query contains "${bad[1].toUpperCase()}"; only read-only Cypher is allowed` };
  if (/\bcall\s+(apoc\.|dbms\.|gds\.|db\.(create|drop|index|constraint))/i.test(bare) || /\bapoc\./i.test(bare)) return { error: "procedures under apoc, dbms and gds are not allowed" };
  return { cypher };
}

// ---- reading (the graph_query tool and the resource endpoint) ----------------------------------------------------

/** Neo4j values as plain JSON: nodes become their properties plus _labels, relationships their properties plus _type. */
export function plain(v: any): any {
  if (v == null) return v;
  if (neo4j.isInt(v)) return v.toNumber();
  if (neo4j.isNode(v)) return { _labels: v.labels, ...mapValues(v.properties) };
  if (neo4j.isRelationship(v)) return { _type: v.type, ...mapValues(v.properties) };
  if (neo4j.isPath(v)) return { _path: v.segments.map((s: any) => ({ start: plain(s.start), relationship: plain(s.relationship), end: plain(s.end) })) };
  if (neo4j.isDate(v) || neo4j.isDateTime(v) || neo4j.isLocalDateTime(v) || neo4j.isTime(v) || neo4j.isLocalTime(v) || neo4j.isDuration(v)) return v.toString();
  if (Array.isArray(v)) return v.map(plain);
  if (typeof v === "object") return mapValues(v);
  return v;
}
const mapValues = (o: Record<string, any>) => Object.fromEntries(Object.entries(o).map(([k, x]) => [k, plain(x)]));

export interface ReadResult { columns: string[]; rows: Record<string, any>[]; row_count: number; truncated: boolean }

/** One read transaction with a timeout and a row cap; throws on transport or Cypher errors. */
export async function readQuery(cypher: string, params: Record<string, unknown> = {}, opts: { timeoutMs?: number; rowCap?: number } = {}): Promise<ReadResult> {
  if (!enabled()) throw new Error("the graph mirror is not configured (NEO4J_URI)");
  const cap = opts.rowCap ?? QUERY_ROW_CAP;
  const s = session("READ");
  try {
    const res = await s.executeRead((tx) => tx.run(cypher, params), { timeout: opts.timeoutMs ?? QUERY_TIMEOUT_MS });
    const columns = res.records[0]?.keys.map(String) ?? [];
    const rows = res.records.slice(0, cap).map((r) => mapValues(r.toObject()));
    return { columns, rows, row_count: rows.length, truncated: res.records.length > cap };
  } finally { await s.close(); }
}

/** A write in one transaction; used by the knowledge layer too. */
export async function writeCypher(cypher: string, params: Record<string, unknown> = {}): Promise<void> { return write(cypher, params); }

async function write(cypher: string, params: Record<string, unknown> = {}): Promise<void> {
  const s = session("WRITE");
  try { await s.executeWrite((tx) => tx.run(cypher, params), { timeout: 60_000 }); }
  finally { await s.close(); }
}

// ---- schema -------------------------------------------------------------------------------------------------------

let schemaReady = false;
/** Unique constraints (which carry an index) on the id of every Advisor label, plus name for roles and pools. Created once per process. */
export async function ensureSchema(): Promise<void> {
  if (schemaReady || !enabled()) return;
  const keyed = LABELS.map((l) => [l, l === "AdvisorRole" || l === "AdvisorNodePool" ? "name" : "id"] as const);
  for (const [label, key] of keyed) {
    await write(`CREATE CONSTRAINT ${label.toLowerCase()}_${key} IF NOT EXISTS FOR (n:${label}) REQUIRE n.${key} IS UNIQUE`);
  }
  await write("CREATE INDEX advisorresource_account IF NOT EXISTS FOR (n:AdvisorResource) ON (n.account_id)");
  schemaReady = true;
}

// ---- the account and the helpers every step shares -------------------------------------------------------------------

/** The AWS account the mirrored data belongs to: the latest run's, else the credential test's, else "unknown". */
export function accountId(): string {
  const run = db.prepare("select account_id from runs where account_id is not null and account_id <> '' order by id desc limit 1").get() as { account_id: string } | undefined;
  if (run?.account_id) return run.account_id;
  const meta = getJsonSetting<{ accountId?: string }>("aws_credentials_meta", {});
  return meta.accountId || "unknown";
}

const now = () => new Date().toISOString();

function inventoryIds(): Set<string> {
  const ids = new Set<string>();
  for (const r of db.prepare("select instance_id as id from inventory_ec2").all() as { id: string }[]) ids.add(r.id);
  for (const r of db.prepare("select db_instance_identifier as id from inventory_rds").all() as { id: string }[]) ids.add(r.id);
  for (const r of db.prepare("select cache_cluster_id as id from inventory_elasticache").all() as { id: string }[]) ids.add(r.id);
  return ids;
}

/** fingerprint -> concept id from the concepts table (created by src/concepts.ts; absent in a bare database). */
function conceptIds(): Map<string, string> {
  try { return new Map((db.prepare("select fingerprint, concept_id from concepts where concept_id <> ''").all() as { fingerprint: string; concept_id: string }[]).map((r) => [r.fingerprint, r.concept_id])); }
  catch { return new Map(); }
}

function roleMap(): RoleMap {
  return new Map((db.prepare("select resource_id, role, role_confidence, protected_prob from resource_roles").all() as any[]).map((r) => [String(r.resource_id), { role: String(r.role), role_confidence: num(r.role_confidence), protected_prob: num(r.protected_prob) }]));
}

const chunks = <T,>(items: T[], size = BATCH): T[][] => { const out: T[][] = []; for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size)); return out; };

async function mirrorAccount(account: string): Promise<void> {
  await write("MERGE (a:AdvisorAccount {id: $id}) SET a.account_id = $id, a.updated_at = $now", { id: account, now: now() });
}

// ---- resources ---------------------------------------------------------------------------------------------------

const RESOURCE_CYPHER = `
UNWIND $rows AS row
MERGE (r:AdvisorResource {id: row.id})
SET r += {kind: row.kind, name: row.name, type: row.type, state: row.state, region: row.region, role: row.role, role_confidence: row.role_confidence,
          protected_prob: row.protected_prob, monthly_usd: row.monthly_usd, cpu_30d: row.cpu_30d, ssm_status: row.ssm_status, gone: row.gone,
          first_seen: row.first_seen, last_seen: row.last_seen, account_id: $account, updated_at: $now}
WITH r, row
MATCH (a:AdvisorAccount {id: $account})
MERGE (r)-[:IN_ACCOUNT]->(a)
WITH r, row
OPTIONAL MATCH (r)-[oldRole:HAS_ROLE]->(x:AdvisorRole) WHERE row.role IS NULL OR x.name <> row.role
DELETE oldRole
WITH DISTINCT r, row
OPTIONAL MATCH (r)-[oldPool:IN_POOL]->(y:AdvisorNodePool) WHERE row.pool IS NULL OR y.name <> row.pool
DELETE oldPool
WITH DISTINCT r, row
FOREACH (_ IN CASE WHEN row.role IS NULL THEN [] ELSE [1] END |
  MERGE (ro:AdvisorRole {name: row.role}) SET ro.account_id = $account, ro.updated_at = $now
  MERGE (r)-[:HAS_ROLE]->(ro))
FOREACH (_ IN CASE WHEN row.pool IS NULL THEN [] ELSE [1] END |
  MERGE (p:AdvisorNodePool {name: row.pool}) SET p.account_id = $account, p.updated_at = $now
  MERGE (r)-[:IN_POOL]->(p))`;

/** EC2, RDS and ElastiCache inventory rows as AdvisorResource nodes; resources the graph has but the inventory no longer lists are marked gone. */
export async function mirrorResources(): Promise<{ resources: number }> {
  if (!enabled()) return { resources: 0 };
  await ensureSchema();
  const account = accountId();
  await mirrorAccount(account);
  const roles = roleMap();
  const rows: ResourceNode[] = [
    ...(db.prepare("select * from inventory_ec2").all() as any[]).map((r) => resourceFromEc2(r, roles)),
    ...(db.prepare("select * from inventory_rds").all() as any[]).map((r) => resourceFromRds(r, roles)),
    ...(db.prepare("select * from inventory_elasticache").all() as any[]).map((r) => resourceFromElasticache(r, roles)),
  ];
  const stamp = now();
  for (const batch of chunks(rows)) await write(RESOURCE_CYPHER, { rows: batch, account, now: stamp });
  await write("MATCH (r:AdvisorResource {account_id: $account}) WHERE NOT r.id IN $ids AND coalesce(r.gone, false) = false SET r.gone = true, r.updated_at = $now",
    { account, ids: rows.map((r) => r.id), now: stamp });
  return { resources: rows.length };
}

// ---- recommendations ----------------------------------------------------------------------------------------------

const RECOMMENDATION_CYPHER = `
UNWIND $rows AS row
MERGE (rec:AdvisorRecommendation {id: row.id})
SET rec += {fingerprint: row.fingerprint, title: row.title, action_type: row.action_type, tier: row.tier, status: row.status, source: row.source, rule: row.rule,
            est_monthly_saving: row.est_monthly_saving, confidence: row.confidence, decided_by: row.decided_by, decided_at: row.decided_at, decision_scope: row.decision_scope,
            created_at: row.created_at, resource: row.resource, account_id: $account, updated_at: $now}
WITH rec, row
OPTIONAL MATCH (rec)-[t:TARGETS]->() DELETE t
WITH DISTINCT rec, row
OPTIONAL MATCH (rec)-[d:DECIDED_AS]->(oc:Concept) WHERE row.concept_id IS NULL OR oc.id <> row.concept_id
DELETE d
WITH DISTINCT rec, row
FOREACH (_ IN CASE WHEN row.resource_id IS NULL THEN [] ELSE [1] END |
  MERGE (res:AdvisorResource {id: row.resource_id})
  MERGE (rec)-[:TARGETS]->(res))
FOREACH (_ IN CASE WHEN row.resource_id IS NULL AND row.resource IS NOT NULL THEN [1] ELSE [] END |
  MERGE (ref:AdvisorResourceRef {id: row.resource}) SET ref.account_id = $account, ref.updated_at = $now
  MERGE (rec)-[:TARGETS]->(ref))
FOREACH (_ IN CASE WHEN row.run_id IS NULL THEN [] ELSE [1] END |
  MERGE (run:AdvisorRun {id: row.run_id}) SET run.account_id = coalesce(run.account_id, $account)
  MERGE (rec)-[:PROPOSED_IN]->(run))
FOREACH (_ IN CASE WHEN row.incident_id IS NULL THEN [] ELSE [1] END |
  MERGE (inc:AdvisorIncident {id: row.incident_id}) SET inc.account_id = coalesce(inc.account_id, $account)
  MERGE (rec)-[:FROM_INCIDENT]->(inc))
WITH rec, row
OPTIONAL MATCH (c:Concept {id: row.concept_id})
FOREACH (_ IN CASE WHEN c IS NULL THEN [] ELSE [1] END | MERGE (rec)-[:DECIDED_AS]->(c))`;

/** Recommendations (all, or the given ids) with their target, run, incident and, when the concepts table maps the fingerprint and the Concept exists, the DECIDED_AS edge. */
export async function mirrorRecommendations(ids?: number[]): Promise<{ recommendations: number }> {
  if (!enabled()) return { recommendations: 0 };
  if (ids && !ids.length) return { recommendations: 0 };
  await ensureSchema();
  const account = accountId();
  await mirrorAccount(account);
  const inv = inventoryIds();
  const concepts = conceptIds();
  const raw = ids
    ? db.prepare(`select * from recommendations where id in (${ids.map(() => "?").join(",")})`).all(...ids)
    : db.prepare("select * from recommendations").all();
  const rows = (raw as any[]).map((r) => recommendationNode(r, inv, concepts));
  const stamp = now();
  for (const batch of chunks(rows)) await write(RECOMMENDATION_CYPHER, { rows: batch, account, now: stamp });
  return { recommendations: rows.length };
}

// ---- runs, controls, playbooks ---------------------------------------------------------------------------------------

const FLAG_CYPHER = `
UNWIND $rows AS row
MERGE (c:AdvisorControl {id: row.control_id})
SET c.title = coalesce(row.control_title, c.title, row.control_id), c.account_id = $account, c.updated_at = $now
WITH c, row
MATCH (r:AdvisorResource {id: row.resource_id})
MERGE (c)-[f:FLAGGED]->(r)
SET f.run_id = row.run_id, f.reason = row.reason`;

const PLAYBOOK_CYPHER = `
UNWIND $rows AS row
MERGE (p:AdvisorPlaybook {id: row.control_id})
SET p += {control_id: row.control_id, title: row.title, tier: row.tier, effort: row.effort, account_id: $account, updated_at: $now}
MERGE (c:AdvisorControl {id: row.control_id})
SET c.title = coalesce(c.title, row.title), c.account_id = $account, c.updated_at = $now
MERGE (c)-[:HAS_PLAYBOOK]->(p)`;

function latestCompletedRunId(): number | null {
  return (db.prepare("select id from runs where status = 'completed' order by id desc limit 1").get() as { id: number } | undefined)?.id ?? null;
}

/** The static playbook catalog and its controls. */
export async function mirrorPlaybooks(): Promise<{ playbooks: number }> {
  if (!enabled()) return { playbooks: 0 };
  await ensureSchema();
  const account = accountId();
  const rows = listPlaybooks().map((p) => ({ control_id: p.control_id, title: p.title, tier: p.tier, effort: p.effort }));
  for (const batch of chunks(rows)) await write(PLAYBOOK_CYPHER, { rows: batch, account, now: now() });
  return { playbooks: rows.length };
}

/**
 * FLAGGED edges for the latest completed run's alarm findings whose resource is in the inventory (one per control and
 * resource); earlier runs' edges are dropped first, so the graph shows the current state, not the history.
 */
export async function mirrorControls(runId = latestCompletedRunId()): Promise<{ controls: number; flagged: number }> {
  if (!enabled() || runId == null) return { controls: 0, flagged: 0 };
  await ensureSchema();
  const account = accountId();
  const findings = db.prepare("select control_id, control_title, resource, reason from findings where run_id = ? and status = 'alarm' and resource is not null order by id").all(runId) as any[];
  const edges = flagEdges(findings, inventoryIds(), runId);
  await write("MATCH (:AdvisorControl)-[f:FLAGGED]->(:AdvisorResource {account_id: $account}) WHERE f.run_id <> $runId DELETE f", { account, runId });
  const stamp = now();
  for (const batch of chunks(edges)) await write(FLAG_CYPHER, { rows: batch, account, now: stamp });
  return { controls: new Set(edges.map((e) => e.control_id)).size, flagged: edges.length };
}

/** One run as an AdvisorRun node; when it is the latest completed run, its alarm findings become the FLAGGED edges (unless `controls` is false). */
export async function mirrorRun(runId: number, opts: { controls?: boolean } = {}): Promise<{ run: number | null; flagged: number }> {
  if (!enabled()) return { run: null, flagged: 0 };
  await ensureSchema();
  const row = db.prepare("select id, started_at, finished_at, status, trigger, findings_count, recommendations_count from runs where id = ?").get(runId);
  if (!row) return { run: null, flagged: 0 };
  const account = accountId();
  await mirrorAccount(account);
  const node = runNode(row);
  await write(`MERGE (r:AdvisorRun {id: $row.id}) SET r += $row, r.account_id = $account, r.updated_at = $now
    WITH r MATCH (a:AdvisorAccount {id: $account}) MERGE (r)-[:IN_ACCOUNT]->(a)`, { row: node, account, now: now() });
  let flagged = 0;
  if (opts.controls !== false && node.status === "completed" && latestCompletedRunId() === runId) flagged = (await mirrorControls(runId)).flagged;
  return { run: runId, flagged };
}

// ---- alerts and incidents --------------------------------------------------------------------------------------------

const ALERT_CYPHER = `
UNWIND $rows AS row
MERGE (a:AdvisorAlert {id: row.id})
SET a += {kind: row.kind, level: row.level, message: row.message, created_at: row.created_at, acknowledged: row.acknowledged, acknowledged_by: row.acknowledged_by,
          resource: row.resource, account_id: $account, updated_at: $now}
WITH a, row
OPTIONAL MATCH (a)-[t:ABOUT]->() DELETE t
WITH DISTINCT a, row
FOREACH (_ IN CASE WHEN row.resource_id IS NULL THEN [] ELSE [1] END |
  MERGE (res:AdvisorResource {id: row.resource_id})
  MERGE (a)-[:ABOUT]->(res))
FOREACH (_ IN CASE WHEN row.resource_id IS NULL AND row.resource IS NOT NULL THEN [1] ELSE [] END |
  MERGE (ref:AdvisorResourceRef {id: row.resource}) SET ref.account_id = $account, ref.updated_at = $now
  MERGE (a)-[:ABOUT]->(ref))`;

const INCIDENT_CYPHER = `
UNWIND $rows AS row
MERGE (i:AdvisorIncident {id: row.id})
SET i += {status: row.status, cause: row.cause, confidence: row.confidence, episode_cost_usd: row.episode_cost_usd, monthly_run_rate_usd: row.monthly_run_rate_usd,
          created_at: row.created_at, account_id: $account, updated_at: $now}
WITH i, row
MERGE (a:AdvisorAlert {id: row.alert_id})
MERGE (i)-[:INVESTIGATES]->(a)`;

/** Every alert with its level and its resource, and every incident with the alert it investigates. */
export async function mirrorAlertsAndIncidents(): Promise<{ alerts: number; incidents: number }> {
  if (!enabled()) return { alerts: 0, incidents: 0 };
  await ensureSchema();
  const account = accountId();
  await mirrorAccount(account);
  const inv = inventoryIds();
  const alerts = (db.prepare("select id, kind, resource, message, created_at, acknowledged, acknowledged_by, triage from alerts").all() as any[])
    .map((r) => alertNode(r, inv, alertLevel({ ...r, triage: safeJson(r.triage) })));
  const incidents = (db.prepare("select id, alert_id, status, cause, confidence, episode_cost_usd, monthly_run_rate_usd, created_at from incidents").all() as any[]).map(incidentNode);
  const stamp = now();
  for (const batch of chunks(alerts)) await write(ALERT_CYPHER, { rows: batch, account, now: stamp });
  for (const batch of chunks(incidents)) await write(INCIDENT_CYPHER, { rows: batch, account, now: stamp });
  return { alerts: alerts.length, incidents: incidents.length };
}

// ---- full resync, stats, wipe --------------------------------------------------------------------------------------------

export interface MirrorCounts {
  knowledge?: import("./graph_knowledge.js").KnowledgeCounts | null; account_id: string; resources: number; recommendations: number; runs: number; flagged: number; controls: number; playbooks: number; alerts: number; incidents: number; took_ms: number }

/** Everything, in dependency order, in batches; idempotent, so it doubles as the repair after a wipe. */
export async function mirrorAll(): Promise<MirrorCounts | null> {
  if (!enabled()) return null;
  const t0 = Date.now();
  await ensureSchema();
  const account = accountId();
  await mirrorAccount(account);
  const { resources } = await mirrorResources();
  const runs = db.prepare("select id from runs order by id").all() as { id: number }[];
  for (const r of runs) await mirrorRun(r.id, { controls: false });
  const { playbooks } = await mirrorPlaybooks();
  const ctl = await mirrorControls();
  const { recommendations } = await mirrorRecommendations();
  const { alerts, incidents } = await mirrorAlertsAndIncidents();
  const { mirrorKnowledge } = await import("./graph_knowledge.js");
  const knowledge = await mirrorKnowledge();
  return { account_id: account, knowledge, resources, recommendations, runs: runs.length, flagged: ctl.flagged, controls: ctl.controls, playbooks, alerts, incidents, took_ms: Date.now() - t0 };
}

export interface GraphStats { nodes: Record<string, number>; relationships: Record<string, number>; decided_as: number; total_nodes: number; total_relationships: number }

/** Node counts per Advisor label and relationship counts per type (relationships leaving an Advisor node, so DECIDED_AS to Concepts is included). */
export async function graphStats(): Promise<GraphStats> {
  const nodes = await readQuery("MATCH (n) WHERE any(l IN labels(n) WHERE l STARTS WITH 'Advisor' OR l STARTS WITH 'Kn') UNWIND labels(n) AS l WITH l, count(*) AS n WHERE l STARTS WITH 'Advisor' OR l STARTS WITH 'Kn' RETURN l AS label, n ORDER BY l", {}, { timeoutMs: 30_000, rowCap: 1000 });
  const rels = await readQuery("MATCH (n)-[r]->() WHERE any(l IN labels(n) WHERE l STARTS WITH 'Advisor' OR l STARTS WITH 'Kn') RETURN type(r) AS type, count(r) AS n ORDER BY type", {}, { timeoutMs: 30_000, rowCap: 1000 });
  const nodeCounts = Object.fromEntries(nodes.rows.map((r) => [String(r.label), Number(r.n)]));
  const relCounts = Object.fromEntries(rels.rows.map((r) => [String(r.type), Number(r.n)]));
  return { nodes: nodeCounts, relationships: relCounts, decided_as: relCounts.DECIDED_AS || 0,
    total_nodes: Object.values(nodeCounts).reduce((s, n) => s + n, 0), total_relationships: Object.values(relCounts).reduce((s, n) => s + n, 0) };
}

/**
 * Removes one account's Advisor nodes (account, resources, refs, recommendations, runs, alerts, incidents, by account_id)
 * and then the shared catalog nodes nothing points at any more (roles, pools, controls without a FLAGGED edge and their
 * playbooks). Concept nodes and everything else in the graph are untouched. A mirrorAll afterwards rebuilds it all.
 */
export async function wipeMirror(account = accountId()): Promise<{ deleted: number }> {
  if (!enabled()) return { deleted: 0 };
  const owned = ["AdvisorAccount", "AdvisorResource", "AdvisorResourceRef", "AdvisorRecommendation", "AdvisorRun", "AdvisorAlert", "AdvisorIncident", "KnSystem", "KnLogGroup", "KnPricingOverlay"];
  const del = async (cypher: string, params: Record<string, unknown>) => {
    let total = 0;
    for (;;) {
      const s = session("WRITE");
      try {
        const res = await s.executeWrite((tx) => tx.run(`${cypher} WITH n LIMIT 1000 DETACH DELETE n RETURN count(*) AS n`, params), { timeout: 60_000 });
        const n = Number(res.records[0]?.get("n") ?? 0);
        total += n;
        if (n < 1000) return total;
      } finally { await s.close(); }
    }
  };
  let deleted = await del("MATCH (n) WHERE any(l IN labels(n) WHERE l IN $owned) AND n.account_id = $account", { owned, account });
  deleted += await del("MATCH (n) WHERE (n:AdvisorRole OR n:AdvisorNodePool) AND NOT (n)--()", {});
  deleted += await del("MATCH (c:AdvisorControl) WHERE NOT (c)-[:FLAGGED]->() OPTIONAL MATCH (c)-[:HAS_PLAYBOOK]->(p:AdvisorPlaybook) WITH collect(c) + collect(p) AS ns UNWIND ns AS n", {});
  return { deleted };
}

export async function verifyConnection(): Promise<{ connected: boolean; error?: string; server?: string }> {
  if (!enabled()) return { connected: false, error: "NEO4J_URI is not set" };
  try {
    const info = await getDriver().verifyConnectivity(config.neo4jDatabase ? { database: config.neo4jDatabase } : undefined);
    return { connected: true, server: `${info.address} ${info.agent || ""}`.trim() };
  } catch (e: any) {
    return { connected: false, error: String(e?.message || e).slice(0, 300) };
  }
}

// ---- the resource view for the UI ------------------------------------------------------------------------------------

export interface ResourceView {
  resource: Record<string, unknown>; role: string | null; pool: string | null;
  recommendations: { rec: Record<string, unknown>; concept: { id: string; name: string | null } | null }[];
  alerts: Record<string, unknown>[]; incidents: Record<string, unknown>[]; controls: { id: string; title: string | null; run_id: number | null; reason: string | null }[];
  counts: { recommendations: number; alerts: number; incidents: number; controls: number };
}

/** One resource node with everything linked to it; null when the graph has no such node. Alerts are capped at 25 (instance_state alerts pile up). */
export async function resourceView(id: string): Promise<ResourceView | null> {
  const r = await readQuery(`
    MATCH (r:AdvisorResource {id: $id})
    OPTIONAL MATCH (r)-[:HAS_ROLE]->(role:AdvisorRole)
    OPTIONAL MATCH (r)-[:IN_POOL]->(pool:AdvisorNodePool)
    OPTIONAL MATCH (rec:AdvisorRecommendation)-[:TARGETS]->(r)
    OPTIONAL MATCH (rec)-[:DECIDED_AS]->(c:Concept)
    WITH r, role, pool, collect(DISTINCT CASE WHEN rec IS NULL THEN null ELSE {rec: properties(rec), concept: CASE WHEN c IS NULL THEN null ELSE {id: c.id, name: c.name} END} END) AS recs
    OPTIONAL MATCH (a:AdvisorAlert)-[:ABOUT]->(r)
    OPTIONAL MATCH (i:AdvisorIncident)-[:INVESTIGATES]->(a)
    WITH r, role, pool, recs, collect(DISTINCT properties(a)) AS alerts, collect(DISTINCT properties(i)) AS incidents
    OPTIONAL MATCH (ctl:AdvisorControl)-[f:FLAGGED]->(r)
    RETURN properties(r) AS resource, role.name AS role, pool.name AS pool, recs, alerts, incidents,
           collect(DISTINCT CASE WHEN ctl IS NULL THEN null ELSE {id: ctl.id, title: ctl.title, run_id: f.run_id, reason: f.reason} END) AS controls`, { id }, { rowCap: 1 });
  const row = r.rows[0];
  if (!row) return null;
  const recs = (row.recs as any[]).filter(Boolean);
  const alerts = (row.alerts as any[]).filter(Boolean).sort((a, b) => Number(b.id) - Number(a.id));
  const incidents = (row.incidents as any[]).filter(Boolean);
  const controls = (row.controls as any[]).filter(Boolean);
  return { resource: row.resource, role: row.role ?? null, pool: row.pool ?? null, recommendations: recs, alerts: alerts.slice(0, 25), incidents, controls,
    counts: { recommendations: recs.length, alerts: alerts.length, incidents: incidents.length, controls: controls.length } };
}

// ---- fire-and-forget hooks -----------------------------------------------------------------------------------------------

/** End of a collection run: the run node, the refreshed inventory and every recommendation (the batch reconciles many). */
export const mirrorAfterRunInBackground = (runId: number) => inBackground(`mirror of run ${runId}`, async () => { await mirrorRun(runId); await mirrorResources(); await mirrorRecommendations(); });
export const mirrorResourcesInBackground = () => inBackground("resource mirror", mirrorResources);
export const mirrorRecommendationsInBackground = (ids?: number[]) => inBackground(`recommendation mirror${ids ? ` (${ids.join(", ")})` : ""}`, () => mirrorRecommendations(ids));
export const mirrorAlertsInBackground = () => inBackground("alert mirror", mirrorAlertsAndIncidents);

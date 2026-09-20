import type { Express, NextFunction, Request, Response } from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import { config } from "./config.js";
import { safeEqual } from "./auth.js";
import { db } from "./db.js";
import { S, query, queryReadOnly } from "./steampipe.js";
import { ProbeError, probeInstance, summarizeProbe } from "./ssm.js";
import { PriceSpec, fetchPrices } from "./prices.js";
import { inventoryRefreshedAt, listEc2 } from "./inventory.js";
import { attributeNatTraffic } from "./watcher.js";
import { alertContext } from "./investigate.js";
import { describeError, tablesIn } from "./permissions.js";
import { QUERY_ROW_CAP as GRAPH_ROW_CAP, QUERY_TIMEOUT_MS as GRAPH_TIMEOUT_MS, SCHEMA_SUMMARY, enabled as graphEnabled, guardReadCypher, readQuery } from "./graph_mirror.js";

/**
 * MCP fact server, mounted at /mcp (Streamable HTTP, stateless: one server+transport per request).
 * Every tool is read-only. repo2graph's agent loads them as `aws_<tool>` and uses them to verify facts
 * (existing resources, real prices, history) before recommending.
 */

export const QUERY_ROW_CAP = 200;
export const QUERY_TIMEOUT_MS = 60_000;

const lit = (s: string) => `'${s.replace(/'/g, "''")}'`;
const text = (v: unknown) => ({ content: [{ type: "text" as const, text: typeof v === "string" ? v : JSON.stringify(v, null, 1) }] });
const fail = (msg: string) => ({ content: [{ type: "text" as const, text: msg }], isError: true });
const errMsg = (e: any) => String(e?.message || e).replace(/^rpc error: code = \w+ desc = /, "");
/** Error text for a tool result; a permission failure gets the missing action and the remedy appended (and is recorded). */
const toolError = (e: any, context: string) => describeError(errMsg(e), context);

/** Strips string literals and comments so keyword checks cannot be fooled by text inside quotes. */
function stripLiterals(sql: string): string {
  return sql
    .replace(/\$([A-Za-z_]*)\$[\s\S]*?\$\1\$/g, "''")
    .replace(/'(?:[^']|'')*'/g, "''")
    .replace(/"(?:[^"]|"")*"/g, '""')
    .replace(/--[^\n]*/g, " ")
    .replace(/\/\*[\s\S]*?\*\//g, " ");
}

// Belt and braces: the statement also runs inside a READ ONLY transaction.
const FORBIDDEN = /\b(insert|update|delete|merge|drop|alter|create|truncate|grant|revoke|copy|vacuum|reindex|set|reset|begin|commit|rollback|savepoint|into|pg_sleep|pg_sleep_for|pg_sleep_until|pg_cancel_backend|pg_terminate_backend|pg_read_file|pg_read_binary_file|pg_ls_dir|pg_stat_file|lo_import|lo_export|dblink|steampipe_internal|steampipe_command)\b/i;
// Only this app's connection may be named: `aws_parent.aws_iam_user` or `aws.aws_ssm_parameter` would read with
// credentials the advisor was never given (the other connections on the same Steampipe service).
const OTHER_SCHEMA = /\b(?!information_schema\b|pg_catalog\b)([a-z_][a-z0-9_]*)\s*\.\s*(aws_[a-z0-9_]*|[a-z0-9_]+)\b/gi;

/** Validates that sql is a single SELECT/WITH statement and qualifies bare aws_* tables with the schema. */
export function prepareUserSql(input: string): { sql: string } | { error: string } {
  const sql = input.trim().replace(/;+\s*$/, "").trim();
  if (!sql) return { error: "empty query" };
  const bare = stripLiterals(sql);
  if (bare.includes(";")) return { error: "only a single statement is allowed" };
  if (!/^\s*(select|with)\b/i.test(bare)) return { error: "only SELECT (or WITH ... SELECT) statements are allowed" };
  const bad = bare.match(FORBIDDEN);
  if (bad) return { error: `statement contains "${bad[1]}"; only read-only SELECT queries are allowed` };
  for (const m of bare.matchAll(OTHER_SCHEMA)) {
    const schema = m[1].toLowerCase();
    if (schema !== S.toLowerCase() && /^aws_/i.test(m[2])) return { error: `"${m[1]}.${m[2]}" names another Steampipe connection; only schema ${S} (this account, the advisor\'s credentials) can be queried` };
    if (/^(aws|aws_[a-z0-9_]*|steampipe[a-z0-9_]*)$/.test(schema) && schema !== S.toLowerCase()) return { error: `schema "${m[1]}" is not available to the agent; use ${S}` };
  }
  // Qualify unqualified aws_* table references so they hit this app's connection, not another one on the search path.
  const qualified = sql.replace(/\b(from|join)(\s+)(?!\w+\.)(aws_[a-z0-9_]+)\b/gi, (_m, kw: string, ws: string, t: string) => `${kw}${ws}${S}.${t}`);
  return { sql: qualified };
}

const days = (n: number, max = 90) => Math.min(max, Math.max(1, Math.floor(n)));

async function steampipeQuery(sql: string) {
  const prepared = prepareUserSql(sql);
  if ("error" in prepared) return fail(prepared.error);
  const wrapped = `select * from (\n${prepared.sql}\n) as _q limit ${QUERY_ROW_CAP + 1}`;
  try {
    const { rows, columns } = await queryReadOnly(wrapped, { timeoutMs: QUERY_TIMEOUT_MS });
    const truncated = rows.length > QUERY_ROW_CAP;
    return text({ columns, row_count: Math.min(rows.length, QUERY_ROW_CAP), truncated, rows: rows.slice(0, QUERY_ROW_CAP) });
  } catch (e: any) {
    return fail(`query failed: ${toolError(e, `mcp steampipe_query (${tablesIn(prepared.sql).join(", ")})`)}${/statement timeout/i.test(errMsg(e)) ? ` (limit ${QUERY_TIMEOUT_MS / 1000}s; narrow the query with region/id quals)` : ""}`);
  }
}

const STATS = ["average", "maximum", "minimum", "sum", "sample_count"] as const;

async function cloudwatchMetric(a: { namespace: string; metric_name: string; dimensions: { name: string; value: string }[]; statistic: (typeof STATS)[number]; days: number; region: string; period: number }) {
  const dims = JSON.stringify(a.dimensions.map((d) => ({ Name: d.name, Value: d.value })));
  const sql = `
    select timestamp, ${a.statistic} as value, unit
    from ${S}.aws_cloudwatch_metric_statistic_data_point
    where namespace = ${lit(a.namespace)} and metric_name = ${lit(a.metric_name)}
      and dimensions = ${lit(dims)}
      and timestamp between now() - interval '${days(a.days)} days' and now()
      and period = ${Math.floor(a.period)} and region = ${lit(a.region)}
    order by timestamp`;
  try {
    const rows = await query<{ timestamp: string; value: number | null; unit: string }>(sql);
    const values = rows.map((r) => Number(r.value)).filter(Number.isFinite);
    const summary = values.length
      ? { points: values.length, min: Math.min(...values), max: Math.max(...values), avg: values.reduce((s, v) => s + v, 0) / values.length, unit: rows[0].unit }
      : { points: 0 };
    const step = Math.ceil(rows.length / 500);
    return text({ namespace: a.namespace, metric: a.metric_name, statistic: a.statistic, period_seconds: a.period, dimensions: dims, summary,
      series: rows.filter((_r, i) => i % step === 0).map((r) => ({ t: r.timestamp, v: r.value == null ? null : Number(r.value) })) });
  } catch (e: any) {
    return fail(`cloudwatch query failed: ${toolError(e, "mcp cloudwatch_metric (aws_cloudwatch_metric_statistic_data_point)")}`);
  }
}

async function priceLookup(a: PriceSpec) {
  try {
    const { service, filters, prices } = await fetchPrices(a);
    if (!prices.length) return fail(`no on-demand price found for ${service} ${a.instance_type} in ${a.region} with ${JSON.stringify(filters)}; check the type, region and engine names`);
    return text({ service, filters, note: "monthly = hourly x 730; several rows mean several engines/licence models, pick the matching attributes", prices });
  } catch (e: any) {
    return fail(`price lookup failed: ${toolError(e, "mcp price_lookup (aws_pricing_product)")}`);
  }
}

function instanceInventory(a: { state?: string; ssm?: "online" | "lost" | "unmanaged" | "managed"; q?: string; include_gone: boolean; limit: number }) {
  const rows = listEc2({ state: a.state, ssm: a.ssm, q: a.q, gone: a.include_gone, limit: Math.min(QUERY_ROW_CAP, Math.max(1, a.limit)) });
  const refreshed = inventoryRefreshedAt();
  if (!refreshed) return fail("the inventory has not been refreshed yet; run a collection or POST /api/inventory/refresh");
  return text({ refreshed_at: refreshed, count: rows.length, truncated: rows.length >= QUERY_ROW_CAP, note: "monthly_usd is the on-demand list price of the type (x730 h), not what the invoice shows; cpu_30d is the 30-day average of the daily maximum CPU; ssm_status null means the instance is not registered with Systems Manager (no agent or no instance profile) so it cannot be probed or managed", instances: rows });
}

// Cost Explorer refuses resource-level queries until the feature is enabled on the payer account. Remember a
// refusal for a day so investigations do not produce a denied call in CloudTrail every time they ask.
let resourceCostDeniedUntil = 0;
let resourceCostDeniedMsg = "";

async function resourceCostHistory(a: { resource_id: string; days: number }) {
  if (Date.now() < resourceCostDeniedUntil) return fail(resourceCostDeniedMsg);
  const n = days(a.days, 14); // Cost Explorer only keeps resource-level daily data for 14 days
  const sql = `
    select period_start::date::text as day, round(sum(unblended_cost_amount)::numeric, 4) as unblended_usd,
           round(sum(amortized_cost_amount)::numeric, 4) as amortized_usd, round(sum(usage_quantity_amount)::numeric, 2) as usage_quantity, bool_or(estimated) as estimated
    from ${S}.aws_cost_by_resource_daily
    where resource_id = ${lit(a.resource_id)} and period_start >= (current_date - ${n})::timestamp and period_start < current_date::timestamp
    group by 1 order by 1`;
  try {
    const rows = await query<{ day: string; unblended_usd: string; amortized_usd: string; usage_quantity: string; estimated: boolean }>(sql);
    const total = rows.reduce((s, r) => s + Number(r.unblended_usd), 0);
    return text({ resource_id: a.resource_id, days: n, total_unblended_usd: Math.round(total * 100) / 100, daily: rows.map((r) => ({ ...r, unblended_usd: Number(r.unblended_usd), amortized_usd: Number(r.amortized_usd), usage_quantity: Number(r.usage_quantity) })) });
  } catch (e: any) {
    const m = errMsg(e);
    if (/Resource-level data granularity|AccessDenied|not authorized/i.test(m)) {
      resourceCostDeniedMsg = `resource-level cost data is not available: enable "resource-level data at daily granularity" under Cost Explorer > Preferences on the payer account (free, keeps 14 days); until then use steampipe_query on ${S}.aws_cost_by_service_daily. Not retried for 24 hours. ${m.slice(0, 200)}`;
      resourceCostDeniedUntil = Date.now() + 24 * 3600 * 1000;
      return fail(resourceCostDeniedMsg);
    }
    return fail(`cost history failed: ${toolError(e, "mcp resource_cost_history (aws_cost_by_resource_daily)")}`);
  }
}

function recommendationHistory(a: { resource?: string; rule?: string; limit: number }) {
  const where: string[] = []; const params: unknown[] = [];
  if (a.resource) { where.push("(resource = ? or resource_name = ? or resource like ?)"); params.push(a.resource, a.resource, `%${a.resource}%`); }
  if (a.rule) { where.push("(rule = ? or action_type = ?)"); params.push(a.rule, a.rule); }
  if (!where.length) return fail("pass a resource id/ARN/name or a rule/action_type");
  const rows = db.prepare(`
    select id, rule, source, title, resource, resource_name, action_type, est_monthly_saving, tier, confidence, status, decided_at, decided_by, decision_reason, run_id, created_at, updated_at
    from recommendations where ${where.join(" and ")} order by updated_at desc limit ?`).all(...params, Math.min(100, Math.max(1, a.limit)));
  return text({ count: rows.length, recommendations: rows });
}

function findingsForResource(a: { resource: string; run_id?: number; limit: number }) {
  const runId = a.run_id ?? (db.prepare("select id from runs where status = 'completed' order by id desc limit 1").get() as { id: number } | undefined)?.id;
  if (!runId) return text({ run_id: null, findings: [] });
  const rows = db.prepare(`
    select control_id, control_title, status, resource, reason, region, account_id, source, benchmark, dimensions
    from findings where run_id = ? and (resource = ? or resource like ?) order by control_id limit ?`)
    .all(runId, a.resource, `%${a.resource}%`, Math.min(200, Math.max(1, a.limit))) as { dimensions: string | null }[];
  const previous = db.prepare(`
    select run_id, count(*) as n from findings where (resource = ? or resource like ?) and run_id <> ? group by run_id order by run_id desc limit 10`).all(a.resource, `%${a.resource}%`, runId);
  return text({ run_id: runId, count: rows.length, findings: rows.map((r) => ({ ...r, dimensions: safeJson(r.dimensions) })), seen_in_earlier_runs: previous });
}

const safeJson = (s: string | null) => { if (!s) return null; try { return JSON.parse(s); } catch { return s; } };

async function instanceProbe(a: { instance_id: string }) {
  try {
    const p = await probeInstance(a.instance_id);
    return text({ instance_id: p.instance_id, collected_at: p.collected_at, summary: summarizeProbe(p.data), data: p.data });
  } catch (e: any) {
    if (e instanceof ProbeError) return fail(`probe ${e.code}: ${e.message}`);
    return fail(`probe failed: ${toolError(e, `mcp instance_probe ${a.instance_id} (ssm:SendCommand)`)}`);
  }
}

async function natAttribution(a: { nat_gateway_id: string; hours: number; limit: number }) {
  try {
    const r = await attributeNatTraffic(a.nat_gateway_id, a.hours, a.limit);
    if (!r.vpc_id) return fail(`${a.nat_gateway_id} is not a NAT gateway in this account`);
    return text({ nat_gateway_id: a.nat_gateway_id, vpc_id: r.vpc_id, hours: a.hours,
      note: "Instance NetworkIn/NetworkOut over the window, largest first, instances under 100 MB dropped. NetworkIn also counts intra-VPC traffic, so each figure is an upper bound on what crossed the NAT; the ranking is what matters. Destination-level attribution needs VPC flow logs.",
      receivers: r.receivers });
  } catch (e: any) {
    return fail(`attribution failed: ${toolError(e, "mcp nat_attribution (aws_vpc_nat_gateway, aws_ec2_instance, aws_cloudwatch_metric_statistic_data_point)")}`);
  }
}

/** Read-only Cypher against the Neo4j mirror (src/graph_mirror.ts): guarded, in a read transaction, 5 s, 200 rows. */
async function graphQuery(a: { cypher: string }) {
  if (!graphEnabled()) return fail("the graph mirror is not configured on this advisor (NEO4J_URI is unset); use recommendation_history, findings_for_resource and instance_inventory instead");
  const g = guardReadCypher(a.cypher);
  if ("error" in g) return fail(`rejected: ${g.error}`);
  try {
    const r = await readQuery(g.cypher, {}, { timeoutMs: GRAPH_TIMEOUT_MS, rowCap: GRAPH_ROW_CAP });
    return text({ ...r, note: r.truncated ? `only the first ${GRAPH_ROW_CAP} rows are returned; add a WHERE or LIMIT` : undefined });
  } catch (e: any) {
    return fail(`graph query failed: ${errMsg(e).slice(0, 400)}${/timed out|timeout/i.test(errMsg(e)) ? ` (limit ${GRAPH_TIMEOUT_MS / 1000}s; narrow the pattern)` : ""}`);
  }
}

function alertContextTool(a: { alert_id: number; hours: number }) {
  const ctx = alertContext(a.alert_id, a.hours);
  if (!ctx) return fail(`no alert with id ${a.alert_id}`);
  return text({ ...ctx, note: "watch_samples: nat_bytes_hour values are bytes in + out through the gateway over the hour before each sample (dims carry in/out); instance_state values are state codes (dims.state is the name)." });
}

export function createFactServer(): McpServer {
  const server = new McpServer({ name: "aws-advisor", version: "0.1.0" }, {
    instructions: `Read-only facts about one AWS account, served by aws-advisor. Steampipe tables live in schema "${S}": write them as ${S}.aws_ec2_instance etc. (bare aws_* names in FROM/JOIN are qualified for you). Use these tools to verify a recommendation before making it: whether a VPC endpoint already exists, the real on-demand price of a type, the resource's cost trend, and what the team decided about it before.`,
  });
  const ro = { readOnlyHint: true, destructiveHint: false, openWorldHint: false };

  server.registerTool("steampipe_query", {
    title: "Steampipe SQL query",
    description: `Run one read-only SELECT against the AWS Steampipe tables (schema ${S}, e.g. ${S}.aws_vpc_endpoint, ${S}.aws_ec2_instance, ${S}.aws_cost_by_service_daily). Single statement, ${QUERY_TIMEOUT_MS / 1000}s timeout, at most ${QUERY_ROW_CAP} rows. Add region/id quals to keep API calls small.`,
    inputSchema: { sql: z.string().min(1).max(20_000).describe("A single SELECT or WITH ... SELECT statement") },
    annotations: ro,
  }, ({ sql }) => steampipeQuery(sql));

  server.registerTool("cloudwatch_metric", {
    title: "CloudWatch metric series",
    description: "Hourly CloudWatch statistics for one metric over the last N days, from aws_cloudwatch_metric_statistic_data_point. Dimensions must match exactly (e.g. [{name:'InstanceId', value:'i-...'}] for AWS/EC2, [{name:'DBClusterIdentifier', value:'...'}] for AWS/RDS).",
    inputSchema: {
      namespace: z.string().describe("e.g. AWS/EC2, AWS/RDS, AWS/ElastiCache"),
      metric_name: z.string().describe("e.g. CPUUtilization, NetworkIn, FreeableMemory"),
      dimensions: z.array(z.object({ name: z.string(), value: z.string() })).min(1),
      statistic: z.enum(STATS).default("average"),
      days: z.number().int().min(1).max(90).default(7),
      region: z.string().default("us-east-1"),
      period: z.number().int().default(3600).describe("seconds; 3600 is the sensible default"),
    },
    annotations: ro,
  }, (a) => cloudwatchMetric(a));

  server.registerTool("price_lookup", {
    title: "On-demand price",
    description: "On-demand hourly and monthly (x730) USD price of an EC2 instance type, RDS instance class or ElastiCache node type in a region, from the AWS price list.",
    inputSchema: {
      kind: z.enum(["ec2", "rds", "elasticache"]),
      instance_type: z.string().describe("e.g. m6i.xlarge, db.r6g.large, cache.t3.micro"),
      region: z.string().default("us-east-1"),
      operating_system: z.string().default("Linux").describe("ec2 only: Linux, Windows, RHEL, SUSE"),
      engine: z.string().optional().describe("rds: PostgreSQL, MySQL, Aurora PostgreSQL, Aurora MySQL, MariaDB ...; elasticache: Redis, Memcached, Valkey. Omit to list all."),
      deployment: z.string().default("Single-AZ").describe("rds only: Single-AZ or Multi-AZ"),
    },
    annotations: ro,
  }, (a) => priceLookup(a));

  server.registerTool("resource_cost_history", {
    title: "Daily cost of a resource",
    description: "Daily unblended and amortized cost of one resource id/ARN over the last N days (max 14, the Cost Explorer limit for resource-level data), from aws_cost_by_resource_daily.",
    inputSchema: { resource_id: z.string().describe("instance id, volume id, ARN... as Cost Explorer names it"), days: z.number().int().min(1).max(14).default(14) },
    annotations: ro,
  }, (a) => resourceCostHistory(a));

  server.registerTool("recommendation_history", {
    title: "Past recommendations and decisions",
    description: "Earlier recommendations for a resource or rule and what the team decided (approved, rejected with reason, snoozed, done), from the advisor's database.",
    inputSchema: { resource: z.string().optional(), rule: z.string().optional().describe("rule name or action_type, e.g. idle_instance, rightsize_instance"), limit: z.number().int().default(30) },
    annotations: ro,
  }, (a) => recommendationHistory(a));

  server.registerTool("findings_for_resource", {
    title: "Findings for a resource",
    description: "All findings (Thrifty controls and custom queries) that mention a resource in a run (default: the latest completed run), plus which earlier runs saw it.",
    inputSchema: { resource: z.string().describe("id, ARN or a substring of it"), run_id: z.number().int().optional(), limit: z.number().int().default(50) },
    annotations: ro,
  }, (a) => findingsForResource(a));

  server.registerTool("instance_inventory", {
    title: "EC2 inventory",
    description: "The advisor's EC2 inventory snapshot (refreshed after every run and every watcher sample): name, type, state, SSM status (Online / ConnectionLost / null = not managed by Systems Manager), 30-day CPU, latest probe memory, attached EBS GB, on-demand monthly list price, open recommendations and findings per instance, and the pool it belongs to (pool_kind batch = AWS Batch compute environment worker that exists only while a job runs, karpenter, eks, asg; null = standalone). Pool members are managed by their controller: reason about the pool, never about one member. Filter by state, SSM status or a search string; at most 200 rows.",
    inputSchema: {
      state: z.string().optional().describe("running, stopped, terminated, ..."),
      ssm: z.enum(["online", "lost", "unmanaged", "managed"]).optional().describe("online = agent Online; lost = registered but not Online; unmanaged = not registered with SSM; managed = registered in any status"),
      q: z.string().optional().describe("substring of name, instance id, type or IP"),
      include_gone: z.boolean().default(false).describe("also return instances the last refresh no longer saw"),
      limit: z.number().int().min(1).max(QUERY_ROW_CAP).default(QUERY_ROW_CAP),
    },
    annotations: ro,
  }, (a) => instanceInventory(a));

  server.registerTool("instance_probe", {
    title: "Probe an instance over SSM",
    description: "Runs the advisor's fixed read-only shell probe on an SSM-managed Linux instance through Run Command and returns memory, disks, load and top processes. Takes 10 to 60 seconds. Fails clearly when the instance is not SSM-managed or the credentials lack SSM permission.",
    inputSchema: { instance_id: z.string().regex(/^i-[0-9a-f]+$/) },
    annotations: { ...ro, openWorldHint: true },
  }, (a) => instanceProbe(a));

  server.registerTool("nat_attribution", {
    title: "Who is behind a NAT gateway's traffic",
    description: "Running instances in a NAT gateway's VPC ranked by NetworkIn/NetworkOut over the last N hours (1 to 24), the same attribution the watcher attaches to a nat_traffic alert. Instance level only: without VPC flow logs the destinations cannot be named.",
    inputSchema: {
      nat_gateway_id: z.string().regex(/^nat-[0-9a-f]+$/),
      hours: z.number().int().min(1).max(24).default(1),
      limit: z.number().int().min(1).max(40).default(10),
    },
    annotations: ro,
  }, (a) => natAttribution(a));

  server.registerTool("graph_query", {
    title: "Cypher over the advisor's graph mirror",
    description: `Read-only Cypher against the Neo4j mirror of this advisor's data (a one-way copy of its database; the same facts as the other tools, but walkable). Labels are all prefixed Advisor; every node has account_id and updated_at:\n${SCHEMA_SUMMARY}\nConcept nodes (label Concept, not Advisor) hold the team's decisions and rules: a recommendation with a DECIDED_AS edge was approved, rejected, snoozed or done and the Concept's description and documentation carry the reason; Concepts named "<role> <action> rule" are generic rules that apply to any resource of that kind. Example: MATCH (r:AdvisorResource {id: 'i-0123'})-[e]-(x) RETURN r, e, x. The statement must start with MATCH, OPTIONAL MATCH, WITH or CALL { }, contain no CREATE/MERGE/SET/DELETE/REMOVE/DROP/LOAD and no apoc/dbms procedure; it runs in a read transaction with a ${GRAPH_TIMEOUT_MS / 1000}s timeout and returns at most ${GRAPH_ROW_CAP} rows. When the mirror is not configured the tool says so.`,
    inputSchema: { cypher: z.string().min(1).max(10_000).describe("One read-only Cypher statement") },
    annotations: ro,
  }, (a) => graphQuery(a));

  server.registerTool("alert_context", {
    title: "Watcher alert with its context",
    description: "One watcher alert (nat_traffic or instance_state) with its parsed details (bytes, baseline, vpc_id, top_receivers for NAT alerts; from/to state for instance alerts), the watcher samples for the same resource over the last N hours, and any incidents already investigated for it.",
    inputSchema: { alert_id: z.number().int().min(1), hours: z.number().int().min(1).max(168).default(24) },
    annotations: ro,
  }, (a) => alertContextTool(a));

  return server;
}

let warned = false;
function mcpAuth(req: Request, res: Response, next: NextFunction) {
  if (!config.mcpToken) {
    if (!warned) { console.warn("MCP_TOKEN is not set; /mcp is open. Fine for local dev only."); warned = true; }
    return next();
  }
  const bearer = req.header("authorization")?.replace(/^Bearer\s+/i, "");
  if (safeEqual(bearer, config.mcpToken) || safeEqual(req.header("x-api-token"), config.mcpToken)) return next();
  res.status(401).json({ jsonrpc: "2.0", error: { code: -32001, message: "unauthorized" }, id: null });
}

/** Mounts the stateless Streamable HTTP endpoint on the app. */
export function mountMcp(app: Express, path = "/mcp") {
  app.post(path, mcpAuth, async (req, res) => {
    const server = createFactServer();
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on("close", () => { transport.close().catch(() => {}); server.close().catch(() => {}); });
    try {
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (e: any) {
      console.error("[mcp] request failed:", e?.message || e);
      if (!res.headersSent) res.status(500).json({ jsonrpc: "2.0", error: { code: -32603, message: "internal error" }, id: null });
    }
  });
  const notAllowed = (_req: Request, res: Response) => res.status(405).json({ jsonrpc: "2.0", error: { code: -32000, message: "Method not allowed; this server is stateless, use POST" }, id: null });
  app.get(path, mcpAuth, notAllowed);
  app.delete(path, mcpAuth, notAllowed);
}

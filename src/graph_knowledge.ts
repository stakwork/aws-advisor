/**
 * The knowledge graph on top of the mirror (design note, section 1): a general area of system types with list
 * prices, archetypes and operational patterns, and our side as a schematic of systems (pools, clusters, groups,
 * standalone boxes) linked to their archetype and to the types they run on, with pricing overlays (the Savings
 * Plan, reservations) and traffic on the edges (NAT to the internet, cross-AZ, log shipping). Built from what the
 * advisor already holds; refreshed with every graph sync. The pure grouping is exported for the tests.
 */
import { db } from "./db.js";
import { S, query } from "./steampipe.js";
import { HOURS_PER_MONTH } from "./prices.js";
import { pricebookCatalog, PRICEBOOK_DATE } from "./pricebook.js";
import { ROLE_OPTIONS } from "./roles.js";
import { OPERATIONAL_PATTERNS } from "./pools.js";
import { LOG_INGEST_PRICE, LOG_STORAGE_PRICE } from "./logs.js";
import { getReconciliation, lastFullMonth } from "./reconcile.js";
import { accountId, enabled, readQuery, writeCypher } from "./graph_mirror.js";
import { AttributionContext, attributeLogGroup } from "./log_attribution.js";
import { LAMBDA_PRICE, lambdaFactsMap, lambdaMonthlyCost } from "./lambda_inventory.js";

export const KN_LABELS = ["KnSystemType", "KnArchetype", "KnPattern", "KnSystem", "KnService", "KnLogGroup", "KnPricingOverlay"] as const;

export interface SystemDef { id: string; name: string; kind: "pool" | "instance" | "rds_cluster" | "rds_instance" | "cache_group" | "cache_cluster" | "nat" | "eks_cluster" | "lambda"; parent?: string | null; pool_kind?: string | null; archetype: string; members: string[]; types: { key: string; kind: string; sku: string; region: string; count: number }[]; ebs_gb: number; region: string | null }

const tagsOf = (r: any): Record<string, string> => { try { return JSON.parse(r.snapshot || "{}").tags || {}; } catch { return {}; } };
const ARCHETYPE_FOR_POOL: Record<string, string> = { batch: "batch_or_worker", karpenter: "k8s_node", eks: "k8s_node", asg: "web_or_api" };

/** Groups inventory rows into systems: pools, clusters and groups become one system each, standalone resources one each. Pure. */
export function systemsFromInventory(ec2: any[], rds: any[], cache: any[], roles: Map<string, string>, nats: { id: string; region: string | null }[] = []): SystemDef[] {
  const out = new Map<string, SystemDef>();
  const add = (id: string, name: string, kind: SystemDef["kind"], archetype: string, member: string, type: { kind: string; sku: string; region: string }, ebs = 0, poolKind: string | null = null) => {
    const s = out.get(id) || { id, name, kind, pool_kind: poolKind, archetype, members: [], types: [], ebs_gb: 0, region: type.region || null };
    s.members.push(member); s.ebs_gb += ebs;
    const key = `${type.kind}|${type.sku}|${type.region}`;
    const t = s.types.find((x) => x.key === key); if (t) t.count++; else s.types.push({ key, kind: type.kind, sku: type.sku, region: type.region, count: 1 });
    if (s.archetype === "unknown" && archetype !== "unknown") s.archetype = archetype;
    out.set(id, s);
  };
  for (const r of ec2) {
    if (r.gone || r.state !== "running") continue;
    const role = roles.get(r.instance_id) || "unknown";
    if (r.pool_kind && r.pool) add(`pool:${r.pool}`, r.pool, "pool", ARCHETYPE_FOR_POOL[r.pool_kind] || role, r.instance_id, { kind: "ec2", sku: r.instance_type, region: r.region }, Number(r.ebs_gb || 0), r.pool_kind);
    else add(`ec2:${r.instance_id}`, r.name || r.instance_id, "instance", role, r.instance_id, { kind: "ec2", sku: r.instance_type, region: r.region }, Number(r.ebs_gb || 0));
  }
  for (const r of rds) {
    if (r.gone) continue;
    const id = r.db_instance_identifier;
    if (r.cluster) add(`rds:${r.cluster}`, r.cluster, "rds_cluster", "database", id, { kind: "rds", sku: r.class, region: r.region });
    else add(`rds:${id}`, id, "rds_instance", "database", id, { kind: "rds", sku: r.class, region: r.region });
  }
  for (const r of cache) {
    if (r.gone) continue;
    const id = r.cache_cluster_id;
    if (r.replication_group) add(`cache:${r.replication_group}`, r.replication_group, "cache_group", "cache_or_queue", id, { kind: "elasticache", sku: r.node_type, region: r.region });
    else add(`cache:${id}`, id, "cache_cluster", "cache_or_queue", id, { kind: "elasticache", sku: r.node_type, region: r.region });
  }
  // EKS clusters as parents of their pools, from the cluster tag in the members' snapshots
  for (const r of ec2) {
    if (r.gone || r.state !== "running" || !r.pool_kind || !r.pool) continue;
    const tags = tagsOf(r); const cluster = tags["aws:eks:cluster-name"] || tags["eks:cluster-name"];
    if (!cluster) continue;
    const pool = out.get(`pool:${r.pool}`); if (pool) pool.parent = `eks:${cluster}`;
    const c: SystemDef = out.get(`eks:${cluster}`) || { id: `eks:${cluster}`, name: cluster, kind: "eks_cluster", archetype: "k8s_node", members: [] as string[], types: [], ebs_gb: 0, region: r.region };
    if (!c.members.includes(r.instance_id)) c.members.push(r.instance_id);
    out.set(c.id, c);
  }
  for (const n of nats) out.set(`nat:${n.id}`, { id: `nat:${n.id}`, name: n.id, kind: "nat", archetype: "bastion_or_vpn", members: [n.id], types: [{ key: `nat|gateway|${n.region || ""}`, kind: "nat", sku: "gateway", region: n.region || "", count: 1 }], ebs_gb: 0, region: n.region });
  return [...out.values()];
}

export { LAMBDA_PRICE, lambdaMonthlyCost, type LambdaFacts } from "./lambda_inventory.js";

/** Lambda functions as systems, from the account's function list (fallback: the ARNs the latest run flagged). */
export function lambdaSystems(arns: string[]): SystemDef[] {
  const out = new Map<string, SystemDef>();
  for (const arn of arns) {
    const m = /^arn:aws:lambda:([a-z0-9-]+):\d+:function:([^:]+)/.exec(arn); if (!m) continue;
    out.set(`lambda:${m[2]}`, { id: `lambda:${m[2]}`, name: m[2], kind: "lambda", archetype: "batch_or_worker", members: [arn], types: [], ebs_gb: 0, region: m[1] });
  }
  return [...out.values()];
}

/** The attribution context for log groups: systems with their tokens, cluster and Beanstalk maps, lambdas. */
export function attributionContext(systems: SystemDef[], ec2: any[]): AttributionContext {
  const clusters = new Map<string, string>(); const beanstalk = new Map<string, string>(); const lambdas = new Map<string, string>();
  for (const s of systems) { if (s.kind === "eks_cluster") clusters.set(s.name, s.id); if (s.kind === "lambda") lambdas.set(s.name, s.id); }
  for (const r of ec2) {
    if (r.gone || !r.pool) continue; const t = tagsOf(r);
    for (const k of ["elasticbeanstalk:environment-name", "elasticbeanstalk:environment-id"]) if (t[k]) beanstalk.set(t[k], `pool:${r.pool}`);
  }
  const memberNames = new Map<string, string[]>();
  for (const r of ec2) { if (r.gone || !r.name) continue; const key = r.pool_kind && r.pool ? `pool:${r.pool}` : `ec2:${r.instance_id}`; memberNames.set(key, [...(memberNames.get(key) || []), r.name]); const t = tagsOf(r); if (t["elasticbeanstalk:environment-name"]) memberNames.set(key, [...(memberNames.get(key) || []), t["elasticbeanstalk:environment-name"]]); }
  return { systems: systems.map((s) => ({ id: s.id, name: s.name, kind: s.kind, members: s.members, pool: s.kind === "pool" ? s.name : null, aliases: [...new Set(memberNames.get(s.id) || [])] })), clusters, beanstalk, lambdas };
}

const priceFor = (kind: string, sku: string, region: string): number | null => {
  const row = db.prepare("select hourly from prices where kind = ? and sku = ? and region = ? and hourly is not null order by case when engine like 'Linux%' or engine like 'PostgreSQL%' or engine like 'Valkey%' then 0 else 1 end limit 1").get(kind, sku, region) as { hourly: number } | undefined;
  return row?.hourly ?? null;
};

export interface KnowledgeCounts { system_types: number; archetypes: number; patterns: number; systems: number; log_groups: number; log_groups_attributed: number; overlays: number; traffic_edges: number; took_ms: number }

/** Writes the general area and our schematic. Idempotent; a system that disappeared is marked gone. */
export async function mirrorKnowledge(): Promise<KnowledgeCounts | null> {
  if (!enabled()) return null;
  const t0 = Date.now();
  const account = accountId();
  const now = new Date().toISOString();
  for (const l of KN_LABELS) await writeCypher(`CREATE CONSTRAINT ${l.toLowerCase()}_id IF NOT EXISTS FOR (n:${l}) REQUIRE n.id IS UNIQUE`);

  // ---- general area: system types (instance SKUs from the price cache, usage rules from the pricebook), archetypes, patterns
  const skus = (db.prepare("select kind, sku, region, engine, hourly, fetched_at from prices where hourly is not null").all() as any[]).map((p) => ({
    id: `${p.kind}|${p.sku}|${p.region}`, kind: p.kind, sku: p.sku, region: p.region, engine: p.engine, list_price: p.hourly, price_unit: "USD/hour", unit: "hour", source: "pricing_api", valid_from: String(p.fetched_at).slice(0, 10) }));
  const usage = pricebookCatalog().map((r) => ({ id: `usage|${r.rule}`, kind: "usage", sku: r.rule, region: "us-east-1", engine: null, list_price: r.unit_price, price_unit: `USD/${r.unit}`, unit: r.unit, source: "pricebook", valid_from: PRICEBOOK_DATE, note: r.note ?? null }));
  await writeCypher(`UNWIND $rows AS row MERGE (t:KnSystemType {id: row.id}) SET t += row, t.updated_at = $now`, { rows: [...skus, ...usage], now });
  const archetypes = Object.entries(ROLE_OPTIONS).map(([name, description]) => ({ id: name, name, description }));
  await writeCypher(`UNWIND $rows AS row MERGE (a:KnArchetype {id: row.id}) SET a += row, a.updated_at = $now`, { rows: archetypes, now });
  const patterns = OPERATIONAL_PATTERNS.split("\n").filter((l) => l.startsWith("- ")).map((l, i) => ({ id: `pattern:${i + 1}`, text: l.slice(2).trim(), source: "advisor" }));
  await writeCypher(`UNWIND $rows AS row MERGE (p:KnPattern {id: row.id}) SET p += row, p.updated_at = $now`, { rows: patterns, now });

  // ---- our side: systems
  const roles = new Map<string, string>((db.prepare("select resource_id, role from resource_roles").all() as any[]).map((r) => [r.resource_id, r.role]));
  const nats = (db.prepare("select label as id, dims from watch_samples where key = 'nat_bytes_hour' and sample_id = (select max(sample_id) from watch_samples)").all() as any[]).map((r) => { let region: string | null = null; try { region = JSON.parse(r.dims || "{}").region ?? null; } catch { /* none */ } return { id: r.id, region }; });
  const ec2Rows = db.prepare("select * from inventory_ec2").all() as any[];
  const latestRun = (db.prepare("select max(run_id) as id from findings").get() as { id: number | null }).id;
  const lambdaArns = latestRun ? (db.prepare("select distinct resource from findings where run_id = ? and resource like 'arn:aws:lambda:%'").all(latestRun) as { resource: string }[]).map((r) => r.resource) : [];
  // Lambda: every function in the inventory (src/lambda_inventory.ts), priced from 30 days of invocations and duration
  const lambdaFacts = lambdaFactsMap();
  const lambdaFromAccount: SystemDef[] = [...lambdaFacts.values()].map((f) => ({ id: `lambda:${f.name}`, name: f.name, kind: "lambda", archetype: "batch_or_worker", members: [f.arn], types: [], ebs_gb: 0, region: f.region }));
  const systems = [...systemsFromInventory(ec2Rows, db.prepare("select * from inventory_rds").all(), db.prepare("select * from inventory_elasticache").all(), roles, nats), ...(lambdaFromAccount.length ? lambdaFromAccount : lambdaSystems(lambdaArns))];
  const attribution = attributionContext(systems, ec2Rows);
  const rows = systems.map((s) => {
    if (s.kind === "lambda") {
      const f = lambdaFacts.get(s.name);
      const cost = f ? lambdaMonthlyCost(f) : null;
      const types = f && cost ? [
        { id: f.arm ? "usage|lambda_gb_second_arm" : "usage|lambda_gb_second", key: "", kind: "usage", sku: f.arm ? "lambda_gb_second_arm" : "lambda_gb_second", region: f.region, count: cost.gb_seconds_month, hours_month: null, list_price: f.arm ? LAMBDA_PRICE.gb_second_arm : LAMBDA_PRICE.gb_second_x86, list_usd_month: Math.round(cost.gb_seconds_month * (f.arm ? LAMBDA_PRICE.gb_second_arm : LAMBDA_PRICE.gb_second_x86) * 100) / 100 },
        { id: "usage|lambda_requests", key: "", kind: "usage", sku: "lambda_requests", region: f.region, count: cost.invocations_month, hours_month: null, list_price: LAMBDA_PRICE.per_request, list_usd_month: Math.round(cost.invocations_month * LAMBDA_PRICE.per_request * 100) / 100 },
      ] : [];
      return { id: s.id, name: s.name, kind: s.kind, parent: null, pool_kind: null, archetype: s.archetype, member_count: 1, members: [], refs: s.members, ebs_gb: 0, ebs_usd_month: 0, region: s.region, monthly_list_usd: cost?.usd_month ?? 0, types, lambda: f ? { memory_mb: f.memory_mb, arm: f.arm, invocations_month: cost!.invocations_month, gb_seconds_month: cost!.gb_seconds_month, days: f.days } : null };
    }
    const types = s.types.map((t) => { const price = priceFor(t.kind, t.sku, t.region); return { ...t, id: t.key, hours_month: HOURS_PER_MONTH * t.count, list_price: price, list_usd_month: price != null ? Math.round(price * HOURS_PER_MONTH * t.count * 100) / 100 : null }; });
    const list = types.reduce((sum, t) => sum + (t.list_usd_month || 0), 0) + s.ebs_gb * 0.08;
    return { id: s.id, name: s.name, kind: s.kind, parent: s.parent ?? null, pool_kind: s.pool_kind ?? null, archetype: s.archetype, member_count: s.members.length, members: s.members, refs: [] as string[], ebs_gb: Math.round(s.ebs_gb), ebs_usd_month: Math.round(s.ebs_gb * 0.08 * 100) / 100, region: s.region, monthly_list_usd: Math.round(list * 100) / 100, types, lambda: null as any };
  });
  await writeCypher(`
UNWIND $rows AS row
MERGE (s:KnSystem {id: row.id})
SET s += {name: row.name, kind: row.kind, pool_kind: row.pool_kind, archetype: row.archetype, member_count: row.member_count, ebs_gb: row.ebs_gb, ebs_usd_month: row.ebs_usd_month, region: row.region, monthly_list_usd: row.monthly_list_usd, account_id: $account, gone: false, updated_at: $now}
SET s.lambda_memory_mb = CASE WHEN row.lambda IS NULL THEN null ELSE row.lambda.memory_mb END, s.lambda_arm = CASE WHEN row.lambda IS NULL THEN null ELSE row.lambda.arm END, s.invocations_month = CASE WHEN row.lambda IS NULL THEN null ELSE row.lambda.invocations_month END, s.gb_seconds_month = CASE WHEN row.lambda IS NULL THEN null ELSE row.lambda.gb_seconds_month END
WITH s, row
MATCH (a:AdvisorAccount {id: $account}) MERGE (s)-[:IN_ACCOUNT]->(a)
WITH s, row
OPTIONAL MATCH (s)-[old:IS_A]->() DELETE old
WITH DISTINCT s, row
MERGE (arch:KnArchetype {id: row.archetype}) MERGE (s)-[:IS_A]->(arch)
WITH s, row
OPTIONAL MATCH (s)-[ro:RUNS_ON]->() DELETE ro
WITH DISTINCT s, row
FOREACH (t IN row.types |
  MERGE (st:KnSystemType {id: t.id}) ON CREATE SET st.kind = t.kind, st.sku = t.sku, st.region = t.region, st.updated_at = $now
  MERGE (s)-[r:RUNS_ON]->(st) SET r.count = t.count, r.hours_month = t.hours_month, r.list_price = t.list_price, r.list_usd_month = t.list_usd_month)
WITH s, row
OPTIONAL MATCH (:AdvisorResource)-[m:MEMBER_OF]->(s) DELETE m
WITH DISTINCT s, row
FOREACH (id IN row.members | MERGE (res:AdvisorResource {id: id}) MERGE (res)-[:MEMBER_OF]->(s))
FOREACH (id IN row.refs | MERGE (ref:AdvisorResourceRef {id: id}) SET ref.account_id = $account MERGE (ref)-[:MEMBER_OF]->(s))
WITH s, row
OPTIONAL MATCH (s)-[po:PART_OF]->() DELETE po
WITH DISTINCT s, row
OPTIONAL MATCH (parent:KnSystem {id: row.parent})
FOREACH (_ IN CASE WHEN parent IS NULL THEN [] ELSE [1] END | MERGE (s)-[:PART_OF]->(parent))`, { rows, account, now });
  await writeCypher("MATCH (s:KnSystem {account_id: $account}) WHERE NOT s.id IN $ids SET s.gone = true, s.updated_at = $now", { account, ids: rows.map((r) => r.id), now });

  // ---- pricing overlays: the Savings Plan (from the reconstruction) and reservations (from the account)
  const overlays: any[] = [];
  const rec = getReconciliation(lastFullMonth());
  if (rec) overlays.push({ id: `sp:${account}`, kind: "savings_plan", account_id: account, commitment_usd_month: rec.totals.sp_fee_model, covered_od_usd_month: rec.totals.sp_covered_od, discount_rate: rec.totals.sp_discount_rate, month: rec.month, covers_kind: "ec2" });
  try {
    const ris = await query<any>(`select reserved_db_instance_id as id, db_instance_class as sku, db_instance_count as count, product_description as engine, state, start_time, duration, offering_type from ${S}.aws_rds_reserved_db_instance where state = 'active'`);
    for (const r of ris) overlays.push({ id: `ri:rds:${r.id}`, kind: "reservation", account_id: account, sku: r.sku, count: Number(r.count), engine: r.engine, offering: r.offering_type, start: r.start_time ? new Date(r.start_time).toISOString() : null, end: r.start_time && r.duration ? new Date(new Date(r.start_time).getTime() + Number(r.duration) * 1000).toISOString() : null, covers_kind: "rds" });
  } catch { /* not readable; the overlay is skipped */ }
  try {
    const ris = await query<any>(`select reserved_cache_node_id as id, cache_node_type as sku, cache_node_count as count, product_description as engine, state, start_time, duration, offering_type from ${S}.aws_elasticache_reserved_cache_node where state = 'active'`);
    for (const r of ris) overlays.push({ id: `ri:cache:${r.id}`, kind: "reservation", account_id: account, sku: r.sku, count: Number(r.count), engine: r.engine, offering: r.offering_type, start: r.start_time ? new Date(r.start_time).toISOString() : null, end: r.start_time && r.duration ? new Date(new Date(r.start_time).getTime() + Number(r.duration) * 1000).toISOString() : null, covers_kind: "elasticache" });
  } catch { /* skipped */ }
  if (overlays.length) await writeCypher(`
UNWIND $rows AS row
MERGE (o:KnPricingOverlay {id: row.id}) SET o += row, o.updated_at = $now
WITH o, row
OPTIONAL MATCH (o)-[c:COVERS]->() DELETE c
WITH DISTINCT o, row
MATCH (t:KnSystemType) WHERE t.kind = row.covers_kind AND (row.sku IS NULL OR t.sku = row.sku)
MERGE (o)-[:COVERS]->(t)`, { rows: overlays, now });

  // ---- traffic on the edges: NAT to the internet, cross-AZ at account level, log shipping
  await writeCypher(`MERGE (i:KnService {id: 'internet'}) SET i.name = 'internet' MERGE (r:KnService {id: 'regional'}) SET r.name = 'other AZs and VPCs in the region'`);
  const natEdges = (db.prepare("select scope_id, median, mean, p95, days from baselines where scope_kind = 'nat' and metric = 'bytes_hour'").all() as any[]).map((b) => ({ id: `nat:${b.scope_id}`, gb_day: (b.mean * 24) / 1e9, gb_day_median: (b.median * 24) / 1e9, p95_gb_hour: b.p95 / 1e9, price_per_gb: 0.045, usd_month: Math.round(((b.mean * 24) / 1e9) * 30 * 0.045 * 100) / 100, window_days: b.days, source: "cloudwatch BytesOutToSource+BytesOutToDestination" }));
  let traffic = 0;
  if (natEdges.length) { await writeCypher(`UNWIND $rows AS row MATCH (s:KnSystem {id: row.id}) MATCH (i:KnService {id: 'internet'}) MERGE (s)-[e:TRANSFERS_TO]->(i) SET e += {mechanism: 'nat', gb_day: row.gb_day, gb_day_median: row.gb_day_median, p95_gb_hour: row.p95_gb_hour, price_per_gb: row.price_per_gb, usd_month: row.usd_month, window_days: row.window_days, source: row.source, updated_at: $now}`, { rows: natEdges, now }); traffic += natEdges.length; }
  const regional = rec?.lines.find((l) => l.usage_type === "DataTransfer-Regional-Bytes");
  if (regional) { await writeCypher(`MATCH (a:AdvisorAccount {id: $account}) MATCH (r:KnService {id: 'regional'}) MERGE (a)-[e:TRANSFERS_TO]->(r) SET e += {mechanism: 'cross-az', gb_day: $gb, price_per_gb: 0.01, usd_month: $usd, source: $src, updated_at: $now}`, { account, gb: regional.quantity / 30, usd: regional.actual_od, src: `cost explorer ${rec!.month}`, now }); traffic++; }
  const groups = db.prepare("select name, region, retention_days, stored_bytes, ingest_bytes_day, ingest_days from log_groups where stored_bytes > 0 order by coalesce(ingest_bytes_day, 0) desc, stored_bytes desc limit 300").all() as any[];
  const lg = groups.map((g) => ({ id: g.name, name: g.name, region: g.region, retention_days: g.retention_days, stored_gb: g.stored_bytes / 1e9, ingest_gb_day: g.ingest_bytes_day != null ? g.ingest_bytes_day / 1e9 : null, ingest_usd_month: g.ingest_bytes_day != null ? Math.round((g.ingest_bytes_day / 1e9) * 30 * LOG_INGEST_PRICE * 100) / 100 : null, storage_usd_month: Math.round((g.stored_bytes / 1e9) * LOG_STORAGE_PRICE * 100) / 100, ...(() => { const a = attributeLogGroup(g.name, attribution); return { owner: a.owner, how: a.how }; })(), account_id: account }));
  if (lg.length) {
    await writeCypher(`
UNWIND $rows AS row
MERGE (g:KnLogGroup {id: row.id}) SET g += {name: row.name, region: row.region, retention_days: row.retention_days, stored_gb: row.stored_gb, ingest_gb_day: row.ingest_gb_day, ingest_usd_month: row.ingest_usd_month, storage_usd_month: row.storage_usd_month, account_id: row.account_id, updated_at: $now}
WITH g, row
OPTIONAL MATCH ()-[old:SHIPS_LOGS_TO]->(g) DELETE old
WITH DISTINCT g, row
OPTIONAL MATCH (s:KnSystem {id: row.owner})
FOREACH (_ IN CASE WHEN s IS NULL THEN [] ELSE [1] END | MERGE (s)-[e:SHIPS_LOGS_TO]->(g) SET e.gb_day = row.ingest_gb_day, e.usd_month = row.ingest_usd_month, e.price_per_gb = ${LOG_INGEST_PRICE}, e.attributed_by = row.how)
FOREACH (_ IN CASE WHEN s IS NULL THEN [1] ELSE [] END | MERGE (a:AdvisorAccount {id: row.account_id}) MERGE (a)-[e:SHIPS_LOGS_TO]->(g) SET e.gb_day = row.ingest_gb_day, e.usd_month = row.ingest_usd_month, e.price_per_gb = ${LOG_INGEST_PRICE})`, { rows: lg, now });
    traffic += lg.length;
  }
  // ---- decisions with an outcome
  const outcomes = db.prepare("select v.recommendation_id as id, v.verdict, v.realised_usd_month, v.ratio, v.checked_at from verifications v where v.id in (select max(id) from verifications group by recommendation_id)").all() as any[];
  if (outcomes.length) await writeCypher(`UNWIND $rows AS row MATCH (r:AdvisorRecommendation {id: row.id}) SET r.verdict = row.verdict, r.realised_usd_month = row.realised_usd_month, r.realised_ratio = row.ratio, r.verified_at = row.checked_at`, { rows: outcomes });

  const attributed = lg.filter((g) => g.owner).length;
  return { system_types: skus.length + usage.length, archetypes: archetypes.length, patterns: patterns.length, systems: rows.length, log_groups: lg.length, log_groups_attributed: attributed, overlays: overlays.length, traffic_edges: traffic, took_ms: Date.now() - t0 };
}

// ---- reading it back ----------------------------------------------------------------------------------------------

/** Every system with its cost at list and what it moves. */
export async function listSystems(kind?: string) {
  const r = await readQuery(`MATCH (s:KnSystem {account_id: $account}) WHERE coalesce(s.gone, false) = false ${kind ? "AND s.kind = $kind" : ""}
    OPTIONAL MATCH (s)-[t:TRANSFERS_TO]->() WITH s, sum(t.usd_month) AS transfer
    OPTIONAL MATCH (s)-[l:SHIPS_LOGS_TO]->() WITH s, transfer, sum(l.usd_month) AS logs
    OPTIONAL MATCH (s)-[:PART_OF]->(p:KnSystem)
    RETURN s.id AS id, s.name AS name, s.kind AS kind, s.pool_kind AS pool_kind, s.archetype AS archetype, s.member_count AS members, s.monthly_list_usd AS monthly_list_usd, transfer AS transfer_usd_month, logs AS logs_usd_month, p.name AS part_of
    ORDER BY s.monthly_list_usd DESC`, { account: accountId(), kind }, { rowCap: 500 });
  return r.rows;
}

/** One system with everything linked to it. */
export async function systemView(idOrName: string) {
  const r = await readQuery(`MATCH (s:KnSystem) WHERE s.id = $q OR toLower(s.name) = toLower($q) OR s.id ENDS WITH $q
    OPTIONAL MATCH (s)-[:IS_A]->(a:KnArchetype)
    OPTIONAL MATCH (s)-[ro:RUNS_ON]->(t:KnSystemType)
    OPTIONAL MATCH (o:KnPricingOverlay)-[:COVERS]->(t)
    OPTIONAL MATCH (m:AdvisorResource)-[:MEMBER_OF]->(s)
    OPTIONAL MATCH (s)-[tr:TRANSFERS_TO]->(svc:KnService)
    OPTIONAL MATCH (s)-[sl:SHIPS_LOGS_TO]->(g:KnLogGroup)
    OPTIONAL MATCH (rec:AdvisorRecommendation)-[:TARGETS]->(m)
    RETURN s AS system, a.description AS archetype_description,
      collect(DISTINCT {type: t.id, sku: t.sku, count: ro.count, list_price: t.list_price, price_unit: t.price_unit, list_usd_month: ro.list_usd_month}) AS runs_on,
      collect(DISTINCT {overlay: o.id, kind: o.kind, discount_rate: o.discount_rate, sku: o.sku, count: o.count, end: o.end}) AS overlays,
      collect(DISTINCT {id: m.id, name: m.name, type: m.type, state: m.state, cpu_30d: m.cpu_30d, monthly_usd: m.monthly_usd}) AS members,
      collect(DISTINCT {to: svc.name, mechanism: tr.mechanism, gb_day: tr.gb_day, price_per_gb: tr.price_per_gb, usd_month: tr.usd_month, source: tr.source}) AS transfers,
      collect(DISTINCT {log_group: g.name, gb_day: sl.gb_day, usd_month: sl.usd_month, retention_days: g.retention_days, stored_gb: g.stored_gb, attributed_by: sl.attributed_by}) AS logs,
      collect(DISTINCT {id: rec.id, title: rec.title, status: rec.status, est_monthly_saving: rec.est_monthly_saving, verdict: rec.verdict, realised_usd_month: rec.realised_usd_month}) AS recommendations
    LIMIT 1`, { q: idOrName });
  const row = r.rows[0]; if (!row) return null;
  const clean = (xs: any[]) => xs.filter((x) => x && Object.values(x).some((v) => v != null));
  return { ...row, runs_on: clean(row.runs_on), overlays: clean(row.overlays), members: clean(row.members), transfers: clean(row.transfers), logs: clean(row.logs), recommendations: clean(row.recommendations) };
}

/** The bill as the graph explains it: the current fleet at list for a month, the Savings Plan overlay, transfer and logs from the edges. */
export async function graphBill() {
  const account = accountId();
  const compute = await readQuery(`MATCH (s:KnSystem {account_id: $account})-[r:RUNS_ON]->(t:KnSystemType) WHERE coalesce(s.gone, false) = false
    RETURN t.kind AS kind, sum(r.list_usd_month) AS list_usd_month, sum(r.count) AS units, count(DISTINCT s) AS systems`, { account });
  const ebs = await readQuery(`MATCH (s:KnSystem {account_id: $account}) WHERE coalesce(s.gone, false) = false RETURN sum(s.ebs_usd_month) AS usd, sum(s.ebs_gb) AS gb`, { account });
  const transfer = await readQuery(`MATCH (x)-[e:TRANSFERS_TO]->() WHERE (x:KnSystem AND x.account_id = $account) OR (x:AdvisorAccount AND x.id = $account) RETURN e.mechanism AS mechanism, sum(e.usd_month) AS usd, sum(e.gb_day) AS gb_day`, { account });
  const logs = await readQuery(`MATCH (g:KnLogGroup {account_id: $account}) RETURN sum(g.ingest_usd_month) AS ingest, sum(g.storage_usd_month) AS storage, count(g) AS groups`, { account });
  const overlay = await readQuery(`MATCH (o:KnPricingOverlay {account_id: $account, kind: 'savings_plan'}) RETURN o.commitment_usd_month AS fee, o.covered_od_usd_month AS covered, o.discount_rate AS rate LIMIT 1`, { account });
  const rec = getReconciliation(lastFullMonth());
  const byService = (svc: string) => rec?.services.find((s) => s.service === svc)?.actual_od ?? null;
  const c = Object.fromEntries(compute.rows.map((r) => [String(r.kind), { list_usd_month: Number(r.list_usd_month || 0), units: Number(r.units || 0), systems: Number(r.systems || 0) }]));
  const lines = [
    { category: "EC2 compute (running fleet, a month at list)", graph_usd_month: c.ec2?.list_usd_month ?? 0, bill_usd_month: byService("Amazon Elastic Compute Cloud - Compute"), detail: `${c.ec2?.units ?? 0} instances in ${c.ec2?.systems ?? 0} systems` },
    { category: "RDS instances", graph_usd_month: c.rds?.list_usd_month ?? 0, bill_usd_month: null, detail: `${c.rds?.units ?? 0} instances; the bill's RDS line also carries storage and I/O` },
    { category: "ElastiCache nodes", graph_usd_month: c.elasticache?.list_usd_month ?? 0, bill_usd_month: byService("Amazon ElastiCache"), detail: `${c.elasticache?.units ?? 0} nodes` },
    { category: "Lambda (30 days of invocations and duration)", graph_usd_month: c.usage?.list_usd_month ?? 0, bill_usd_month: byService("AWS Lambda"), detail: `${c.usage?.systems ?? 0} functions with metrics; at list, before the Compute Savings Plan and the free tier the bill applies to Lambda` },
    { category: "EBS attached to running instances", graph_usd_month: Number(ebs.rows[0]?.usd || 0), bill_usd_month: null, detail: `${Math.round(Number(ebs.rows[0]?.gb || 0))} GB at gp3 list` },
    ...transfer.rows.map((r) => ({ category: `Transfer: ${r.mechanism}`, graph_usd_month: Number(r.usd || 0), bill_usd_month: null, detail: `${Number(r.gb_day || 0).toFixed(1)} GB/day` })),
    { category: "CloudWatch Logs ingestion + storage", graph_usd_month: Number(logs.rows[0]?.ingest || 0) + Number(logs.rows[0]?.storage || 0), bill_usd_month: byService("AmazonCloudWatch"), detail: `${logs.rows[0]?.groups ?? 0} groups` },
  ];
  const o = overlay.rows[0];
  return { month_compared: rec?.month ?? null, lines, savings_plan: o ? { fee_usd_month: Number(o.fee), covered_od_usd_month: Number(o.covered), discount_rate: Number(o.rate) } : null,
    graph_total_list: lines.reduce((s, l) => s + l.graph_usd_month, 0), note: "The graph prices the fleet as it is now at list rates for a full month; the bill column is last full month's on-demand value where the mapping is one to one. Gaps come from fleet changes during the month, from lines the graph does not hold yet (Lambda, S3, support) and from the Savings Plan, shown separately." };
}

import { db } from "./db.js";
import { REF_MERGE } from "./graph_cypher.js";
import { accountId, enabled, inventoryIdsOf, writeCypher } from "./graph_mirror.js";
import { guessedType, inventoryIdOf } from "./adapters/aws/resources.js";
import { AWS } from "./adapters/types.js";
import { LINK_RELS, type LinkRel, type ServiceLink } from "./service_inventory.js";

/**
 * The platform services' edges and GuardDuty's findings (src/service_inventory.ts, docs/cloud-ontology.md). Every
 * service row carries its links in generic words (SECURES, ENCRYPTS, GUARDED_BY, MANAGES, PROTECTS, BACKED_UP_TO,
 * STORES_IN, DELIVERS_TO, WRITES_TO, PART_OF, IN_NETWORK, IN_SEGMENT); each pass drops the edges of those types that
 * touch a service node and writes the current ones, so a certificate moved to another balancer or a stack that stopped
 * managing a volume leaves no stale edge. The other end is the node the graph has for it (matched by id or ARN tail),
 * a network node by label, or an AdvisorResourceRef naming what it probably is; MANAGES never makes a ref (a stack
 * manages dozens of things the graph has no node for, and those stay counts on the stack).
 */

const PROVIDER = AWS;
const BATCH = 250;
const chunks = <T,>(items: T[], size = BATCH): T[][] => { const out: T[][] = []; for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size)); return out; };
const rowsOf = (sql: string, ...params: unknown[]): any[] => { try { return db.prepare(sql).all(...params) as any[]; } catch { return []; } };
const safeJson = (s: unknown): any => { if (typeof s !== "string") return s ?? null; try { return JSON.parse(s); } catch { return null; } };

export interface EdgeRow { self: string; other: string; props: Record<string, unknown>; guessed_type: string | null; account_id: string | null }
export interface EdgeGroup { rel: LinkRel; dir: "out" | "in"; target: "resource" | "ref" | "AdvisorFilter" | "AdvisorNetwork" | "AdvisorSegment"; rows: EdgeRow[] }

/**
 * The service rows' links grouped by what one Cypher statement can write (a relationship type and a label cannot be
 * parameters): rel, direction, and whether the other end is a known resource, a network node or a ref. Pure.
 */
export function edgeGroups(rows: { id: string; account_id?: string | null; links: ServiceLink[] }[], known: Set<string>): EdgeGroup[] {
  const groups = new Map<string, EdgeGroup>();
  for (const r of rows) for (const l of r.links) {
    if (!(LINK_RELS as readonly string[]).includes(l.rel) || !l.other) continue;
    let target: EdgeGroup["target"]; let other = l.other;
    if (l.label) target = l.label;
    else { const id = inventoryIdOf(l.other, known); if (id) { target = "resource"; other = id; } else if (l.known_only) continue; else target = "ref"; }
    const k = `${l.rel}|${l.dir}|${target}`;
    if (!groups.has(k)) groups.set(k, { rel: l.rel, dir: l.dir, target, rows: [] });
    groups.get(k)!.rows.push({ self: r.id, other, props: l.props ?? {}, guessed_type: target === "ref" ? guessedType(l.other) : null, account_id: r.account_id || null });
  }
  return [...groups.values()];
}

const edgeCypher = (g: EdgeGroup): string => {
  const other = g.target === "ref" ? REF_MERGE("o", "row.other", "row.guessed_type", "service") : g.target === "resource" ? "MERGE (o:AdvisorResource {id: row.other})" : `MERGE (o:${g.target} {id: row.other})`;
  const edge = g.dir === "out" ? `MERGE (s)-[e:${g.rel}]->(o)` : `MERGE (o)-[e:${g.rel}]->(s)`;
  return `UNWIND $rows AS row
MATCH (s:AdvisorResource {id: row.self})
${other}
${edge}
SET e += row.props, e.updated_at = $now`;
};

/** Every service node's edges of the service types, written again from the rows; returns how many were written. */
export async function mirrorServiceLinks(account: string, stamp: string): Promise<number> {
  const rows = rowsOf("select id, account_id, links from inventory_service where gone = 0").map((r) => ({ id: String(r.id), account_id: r.account_id ? String(r.account_id) : null, links: (safeJson(r.links) || []) as ServiceLink[] }));
  const ids = rowsOf("select id from inventory_service").map((r) => String(r.id));
  for (const batch of chunks(ids)) await writeCypher(`UNWIND $ids AS id MATCH (s:AdvisorResource {id: id})-[e:${LINK_RELS.join("|")}]-() DELETE e`, { ids: batch });
  let n = 0;
  for (const g of edgeGroups(rows, inventoryIdsOf(account))) {
    for (const batch of chunks(g.rows)) await writeCypher(edgeCypher(g), { rows: batch, account, provider: PROVIDER, now: stamp });
    n += g.rows.length;
  }
  return n;
}

const FINDING_CYPHER = `
UNWIND $rows AS row
MERGE (f:AdvisorThreatFinding {id: row.id})
ON CREATE SET f.first_seen = $now
SET f += {type: row.type, title: row.title, description: row.description, severity: row.severity_label, native_severity: row.severity, confidence: row.confidence, resource_type: row.resource_type, resource: row.resource_id,
          resource_name: row.resource_name, count: row.count, first_seen_at: row.first_seen_at, last_seen_at: row.last_seen_at, created_at: row.created_at, archived: row.archived, region: row.region, gone: row.gone,
          provider: $provider, account_id: coalesce(row.account_id, $account), native_type: 'guardduty_finding', native_id: row.id, last_seen: $now, updated_at: $now}
WITH f, row
OPTIONAL MATCH (f)-[old:IN_ACCOUNT|REPORTED_BY|ABOUT]->() DELETE old
WITH DISTINCT f, row
MERGE (a:AdvisorAccount {id: coalesce(row.account_id, $account)}) ON CREATE SET a.account_id = coalesce(row.account_id, $account), a.provider = $provider, a.native_type = 'account', a.native_id = coalesce(row.account_id, $account), a.kind = 'account', a.updated_at = $now
MERGE (f)-[:IN_ACCOUNT]->(a)
WITH f, row
FOREACH (_ IN CASE WHEN row.detector_arn IS NULL THEN [] ELSE [1] END | MERGE (d:AdvisorResource {id: row.detector_arn}) MERGE (f)-[:REPORTED_BY]->(d))
FOREACH (_ IN CASE WHEN row.target_id IS NULL THEN [] ELSE [1] END | MERGE (r:AdvisorResource {id: row.target_id}) MERGE (f)-[:ABOUT]->(r))
FOREACH (_ IN CASE WHEN row.target_id IS NULL AND row.resource_id IS NOT NULL THEN [1] ELSE [] END |
  ${REF_MERGE("ref", "row.resource_id", "row.guessed_type", "threat_finding")}
  MERGE (f)-[:ABOUT]->(ref))`;

/**
 * GuardDuty's findings as AdvisorThreatFinding: IN_ACCOUNT, REPORTED_BY the detector, ABOUT the resource (its node,
 * or a ref). Findings the table no longer holds (past GuardDuty's 90 days) are removed from the graph too.
 */
export async function mirrorThreatFindings(): Promise<{ findings: number }> {
  if (!enabled()) return { findings: 0 };
  const account = accountId();
  const known = inventoryIdsOf(account);
  const rows = rowsOf("select * from threat_findings").map((f) => {
    const target = inventoryIdOf(f.resource_id, known);
    return { ...f, archived: Boolean(f.archived), gone: Boolean(f.gone), target_id: target, guessed_type: f.resource_id ? (guessedType(String(f.resource_id)) ?? (String(f.resource_type || "").toLowerCase() || null)) : null };
  });
  const stamp = new Date().toISOString();
  for (const batch of chunks(rows)) await writeCypher(FINDING_CYPHER, { rows: batch, account, provider: PROVIDER, now: stamp });
  await writeCypher("MATCH (f:AdvisorThreatFinding {provider: $provider}) WHERE f.updated_at < $now DETACH DELETE f", { provider: PROVIDER, now: stamp });
  return { findings: rows.length };
}

import { readQuery, writeCypher } from "./graph_mirror.js";

/**
 * Claims (and the Resolutions that resolve them) written into the graph by the Strut workflows, read for the Claims
 * page. Claim and Resolution nodes carry no Advisor label, so the mirror's sync and wipes (which select Advisor* / Kn*
 * labels) never match them. The only write here is marking one Resolution fixed.
 */

export const CLAIMS_CYPHER = `MATCH (r:Resolution)-[:RESOLVES]->(c:Claim)-[:ABOUT]->(a)
WHERE any(l IN labels(a) WHERE l STARTS WITH 'Advisor')
WITH c, a, collect(DISTINCT r { .id, .name, .markdown, .cli_command, .verify_command, .pr_url, .strategy, .resolution_status, .tested, .test_detail, .created_at, .updated_at }) AS resolutions
RETURN c.id AS id, c.name AS name, c.claim_text AS claim_text, c.verdict AS verdict, c.confidence_score AS confidence_score, c.assessed_at AS assessed_at,
       a.id AS resource_id, a.name AS resource_name, head([l IN labels(a) WHERE l STARTS WITH 'Advisor']) AS resource_label, resolutions
ORDER BY c.assessed_at DESC, c.id
LIMIT 200`;

export const COUNT_RESOLUTION_CYPHER = "MATCH (r:Resolution {id:$id}) RETURN count(r) AS n";
export const DONE_CYPHER = "MATCH (r:Resolution {id:$id}) SET r.resolution_status = 'fixed', r.updated_at = $now";

export interface ClaimRow { id: string; name: string | null; claim_text: string | null; verdict: string | null; confidence_score: number | null; assessed_at: number | null; resource: { id: string; name: string | null; label: string }; resolutions: Record<string, any>[] }

/** Claims with at least one Resolution, newest assessment first; a Claim about several Advisor nodes appears once, under the first. */
export async function listClaims(): Promise<ClaimRow[]> {
  const res = await readQuery(CLAIMS_CYPHER);
  const byId = new Map<string, ClaimRow>();
  for (const r of res.rows) {
    const id = String(r.id);
    const known = byId.get(id);
    if (known) { const seen = new Set(known.resolutions.map((x) => x.id)); for (const x of r.resolutions ?? []) if (!seen.has(x.id)) known.resolutions.push(x); continue; }
    byId.set(id, { id, name: r.name ?? null, claim_text: r.claim_text ?? null, verdict: r.verdict ?? null, confidence_score: r.confidence_score ?? null, assessed_at: r.assessed_at ?? null, resource: { id: r.resource_id, name: r.resource_name ?? null, label: r.resource_label }, resolutions: [...(r.resolutions ?? [])] });
  }
  return [...byId.values()];
}

/** A resolution id the done endpoint accepts: 'res:...', at most 300 characters. Pure. */
export const validResolutionId = (id: unknown): id is string => typeof id === "string" && id.length > 0 && id.length <= 300 && id.startsWith("res:");

export type DoneResult = { ok: true; id: string; resolution_status: "fixed"; updated_at: number } | { ok: false; status: 400 | 404 | 409; error: string };

/** Marks one Resolution fixed (idempotent). Touches only resolution_status and updated_at of that node, and only to 'fixed'. */
export async function markResolutionDone(id: unknown): Promise<DoneResult> {
  if (!validResolutionId(id)) return { ok: false, status: 400, error: "the resolution id must start with 'res:' and be at most 300 characters" };
  const n = Number((await readQuery(COUNT_RESOLUTION_CYPHER, { id })).rows[0]?.n ?? 0);
  if (n === 0) return { ok: false, status: 404, error: "no such resolution" };
  if (n > 1) return { ok: false, status: 409, error: `${n} resolutions share this id; not changing any` };
  const now = Math.floor(Date.now() / 1000);
  await writeCypher(DONE_CYPHER, { id, now });
  return { ok: true, id, resolution_status: "fixed", updated_at: now };
}

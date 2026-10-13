/**
 * The function facts layer of the graph (docs/cloud-ontology.md §AdvisorFunction, `src/function_facts.ts`): edges
 * from a function to its execution identity, its triggers, its function URL (and whether the internet can invoke
 * it with no auth) and the repository its stack or a tag names. Registered in `AWS_LAYERS` after `network` and
 * `clusters`, `after_run: true` (src/adapters/aws/index.ts). Reads only SQLite (`inventory_lambda`, and through
 * `src/function_facts.ts` the same stack and GitHub tables the tool reads), so a function's edges and its
 * `function_facts` output are always built from the same facts.
 *
 * Fact groups that failed this run (`facts_missing`, kept from an earlier run) mark the edges they would have built
 * `stale: true, stale_since`, so a traversal can tell a confirmed edge from one carried over.
 */
import { db } from "./db.js";
import { accountId, enabled, readQuery, writeCypher } from "./graph_mirror.js";
import { LINK_BY_ID } from "./graph_cypher.js";
import { AWS } from "./adapters/types.js";
import { normalizeTriggerTarget, type PolledTrigger, type PushTrigger } from "./adapters/aws/functions.js";
import { repositoriesFor, repoTagKeysList, stacksManaging, type RepoEntry } from "./function_facts.js";

const chunks = <T,>(items: T[], size = 250): T[][] => { const out: T[][] = []; for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size)); return out; };
const json = (v: unknown): any => { if (v == null) return null; if (typeof v === "string") { try { return JSON.parse(v); } catch { return null; } } return v; };

// ---- concurrency: a module-level lock, not a database one (one advisor process writes the graph). ----------------
let busy = false;

interface MissingFact { fact: string; reason: string; since?: string }
const staleOf = (missing: MissingFact[], fact: string): { stale: boolean; stale_since: string | null } => {
  const m = missing.find((x) => x.fact === fact);
  return m ? { stale: true, stale_since: m.since ?? null } : { stale: false, stale_since: null };
};

// ---- RUNS_AS: a function's execution identity, usually a ref (pure service roles are not mirrored) ----------------
const RUNS_AS_CYPHER = `
UNWIND $rows AS row
MATCH (f:AdvisorResource {id: row.id})
OPTIONAL MATCH (f)-[old:RUNS_AS {via: 'execution_identity'}]->() DELETE old
WITH DISTINCT f, row
${LINK_BY_ID({ from: "f", carry: ["row"], list: "CASE WHEN row.role_arn IS NULL THEN [] ELSE [row.role_arn] END", rel: "RUNS_AS", key: "{via: 'execution_identity'}", set: "e.updated_at = $now, e.stale = row.stale, e.stale_since = row.stale_since", namedBy: "function", guessed: "'identity'", accountExpr: "coalesce(row.account_id, $account)" })}`;

// ---- TRIGGERED_BY: polled sources and push invokers, normalised onto existing nodes or a generic ref --------------
const TRIGGERED_BY_CYPHER = `
UNWIND $rows AS row
MATCH (f:AdvisorResource {id: row.id})
OPTIONAL MATCH (f)-[old:TRIGGERED_BY]->() DELETE old
WITH DISTINCT f, row
${LINK_BY_ID({ from: "f", carry: ["row"], list: "row.triggers", id: "li.target_id", rel: "TRIGGERED_BY",
  set: "e.kind = li.kind, e.via = li.via, e.native_kind = li.native_kind, e.state = li.state, e.batch_size = li.batch_size, e.invoker = li.invoker, e.target_version = li.target_version, e.public = li.public, e.source_account = li.source_account, e.stale = li.stale, e.stale_since = li.stale_since, e.updated_at = $now",
  namedBy: "function", guessed: "li.guessed", accountExpr: "coalesce(row.account_id, $account)" })}`;

// ---- function URL: EXPOSES an AdvisorEndpoint, REACHABLE_FROM the internet when it needs no auth ------------------
const URL_CYPHER = `
UNWIND $rows AS row
MATCH (f:AdvisorResource {id: row.id})
OPTIONAL MATCH (f)-[old:EXPOSES]->(oe:AdvisorEndpoint {native_type: 'function_url'}) DELETE old
WITH DISTINCT f, row
MERGE (e:AdvisorEndpoint {id: row.id + ':url'}) ON CREATE SET e.first_seen = $now
SET e += {kind: 'url', native_type: 'function_url', requires_auth: row.requires_auth, resource_id: row.id, provider: $provider, account_id: coalesce(row.account_id, $account), gone: false, last_seen: $now, updated_at: $now}
MERGE (f)-[x:EXPOSES]->(e) SET x.updated_at = $now, x.stale = row.stale, x.stale_since = row.stale_since
WITH e, row
OPTIONAL MATCH (e)-[old2:REACHABLE_FROM]->() DELETE old2
WITH e, row
FOREACH (_ IN CASE WHEN row.requires_auth = false THEN [1] ELSE [] END |
  MERGE (s:AdvisorSource {id: 'internet'}) ON CREATE SET s.kind = 'internet', s.name = 'internet', s.native_type = 'source'
  MERGE (e)-[r:REACHABLE_FROM]->(s) SET r.requires_auth = false, r.via = 'invoke_permission', r.updated_at = $now)`;

// ---- repository nodes: new ones only (the fallback when github_repos has no match); an existing node's source is never overwritten ----
const REPO_NODE_CYPHER = `
UNWIND $rows AS row
MERGE (r:AdvisorRepository {id: row.id})
ON CREATE SET r.first_seen = $now, r.source = 'derived', r.named_by = 'tag', r.provider = 'github', r.native_type = 'repository', r.native_id = row.native_id, r.name = row.name
SET r.updated_at = $now`;

// ---- BUILT_FROM: a function (or its stack) names its repository by tag -------------------------------------------
const BUILT_FROM_CYPHER = `
UNWIND $rows AS row
MATCH (f:AdvisorResource {id: row.function_id})
MATCH (r:AdvisorRepository {id: row.repo_id})
OPTIONAL MATCH (f)-[old:BUILT_FROM {via: row.via, tag_key: row.tag_key, stack: row.stack}]->(other) WHERE other.id <> r.id DELETE old
WITH DISTINCT f, r, row
MERGE (f)-[x:BUILT_FROM {via: row.via, tag_key: row.tag_key, stack: row.stack}]->(r)
SET x += {asserted_by: 'tag', verified: false, stale: row.stale, stale_since: row.stale_since, updated_at: $now}`;

interface FnRow { id: string; name: string; arn: string; account_id: string; region: string; role_arn: string | null; tags: Record<string, string> | null; polled_triggers: PolledTrigger[]; push_triggers: PushTrigger[]; missing: MissingFact[] }

function fnRows(): FnRow[] {
  return (db.prepare("select name, arn, region, account_id, role_arn, tags, polled_triggers, push_triggers, facts_missing from inventory_lambda where gone = 0").all() as any[]).map((r) => ({
    id: String(r.arn), name: String(r.name), arn: String(r.arn), account_id: r.account_id ? String(r.account_id) : "", region: r.region, role_arn: r.role_arn ?? null,
    tags: (json(r.tags) || {}) as Record<string, string>, polled_triggers: (json(r.polled_triggers) || []) as PolledTrigger[], push_triggers: (json(r.push_triggers) || []) as PushTrigger[], missing: (json(r.facts_missing) || []) as MissingFact[],
  }));
}

/** The TRIGGERED_BY row for one trigger, or null when it is drawn by another layer (SNS's DELIVERS_TO, a load balancer's EXPOSES/FORWARDS_TO) or has no target this design can normalise. Pure. */
export function triggerRow(t: PolledTrigger | PushTrigger, stale: { stale: boolean; stale_since: string | null }): Record<string, unknown> | null {
  const nativeKind = (t as any).native_kind as string;
  if (nativeKind === "sns" || (t as any).via === "load_balancer" || nativeKind === "function_url") return null;
  const { id, guessed } = normalizeTriggerTarget((t as any).source ?? null, nativeKind);
  if (!id) return null;
  return { target_id: id, guessed, kind: t.kind, via: t.via, native_kind: nativeKind, state: (t as any).state ?? null, batch_size: (t as any).batch_size ?? null,
    invoker: (t as any).invoker ?? null, target_version: (t as any).target_version ?? null, public: (t as any).public ?? false, source_account: (t as any).source_account ?? null, ...stale };
}

/** Repository ids `repositoriesFor` returned, resolved onto an existing AdvisorRepository node's casing when one matches case-insensitively (the graph-only fallback used only when `github_repos` itself had no match); else the tag's own casing, to be created. Pure given the existing ids. */
export function resolveRepoCasing(ids: string[], existing: string[]): Map<string, string> {
  const byLower = new Map(existing.map((id) => [id.toLowerCase(), id]));
  return new Map(ids.map((id) => [id, byLower.get(id.toLowerCase()) ?? id]));
}

export interface FunctionsCounts { functions: number; runs_as: number; triggers: number; urls: number; repositories: number; skipped_concurrent?: boolean }

/** Writes RUNS_AS, TRIGGERED_BY, the function URL's EXPOSES/REACHABLE_FROM and BUILT_FROM for every function; removes what this pass did not confirm. Skipped (and logged) when another run of this layer is already in progress. */
export async function mirrorFunctions(onLog: (l: string) => void = (l) => console.log(`[graph] ${l}`)): Promise<FunctionsCounts | null> {
  if (!enabled()) return null;
  if (busy) { onLog("functions: a run is already in progress, skipped"); return { functions: 0, runs_as: 0, triggers: 0, urls: 0, repositories: 0, skipped_concurrent: true }; }
  busy = true;
  try {
    const account = accountId();
    const now = new Date().toISOString();
    const fns = fnRows();
    const keys = repoTagKeysList();

    const runsAs = fns.map((f) => ({ id: f.id, account_id: f.account_id || null, role_arn: f.role_arn, ...staleOf(f.missing, "config") }));
    for (const b of chunks(runsAs)) await writeCypher(RUNS_AS_CYPHER, { rows: b, account, provider: AWS, now });

    const triggerRows = fns.map((f) => {
      const polledStale = staleOf(f.missing, "polled_triggers");
      const pushStale = staleOf(f.missing, "invoke_permissions");
      const triggers = [...f.polled_triggers.map((t) => triggerRow(t, polledStale)), ...f.push_triggers.map((t) => triggerRow(t, pushStale))].filter((t): t is Record<string, unknown> => t != null);
      return { id: f.id, account_id: f.account_id || null, triggers };
    });
    let triggerCount = 0;
    for (const b of chunks(triggerRows)) { await writeCypher(TRIGGERED_BY_CYPHER, { rows: b, account, provider: AWS, now }); triggerCount += b.reduce((s, r) => s + r.triggers.length, 0); }

    const urlRows = fns.map((f) => {
      const url = f.push_triggers.find((t) => t.native_kind === "function_url");
      return url ? { id: f.id, account_id: f.account_id || null, requires_auth: Boolean(url.requires_auth), ...staleOf(f.missing, "invoke_permissions") } : null;
    }).filter((r): r is { id: string; account_id: string | null; requires_auth: boolean; stale: boolean; stale_since: string | null } => r != null);
    for (const b of chunks(urlRows)) await writeCypher(URL_CYPHER, { rows: b, account, provider: AWS, now });
    // a function that no longer has a URL trigger loses its old one through the final sweep below

    // repositories: the same `repositoriesFor` + stack rows function_facts.ts reads, so the tool and the graph agree
    const repoEntries: { function_id: string; account_id: string | null; entry: RepoEntry; stale: boolean; stale_since: string | null }[] = [];
    for (const f of fns) {
      const stacks = stacksManaging(f.arn, f.account_id);
      const tagsStale = staleOf(f.missing, "tags");
      for (const entry of repositoriesFor(f.tags, stacks, keys)) {
        const stale = entry.via === "function_tag" ? tagsStale.stale : false;
        repoEntries.push({ function_id: f.id, account_id: f.account_id || null, entry, stale, stale_since: stale ? tagsStale.stale_since : null });
      }
    }
    let repoCount = 0;
    if (repoEntries.length) {
      const existing = (await readQuery("MATCH (r:AdvisorRepository) RETURN r.id AS id", {}, { rowCap: 10_000 })).rows.map((r) => String(r.id));
      const casing = resolveRepoCasing([...new Set(repoEntries.map((r) => r.entry.id))], existing);
      const newIds = new Set(repoEntries.map((r) => casing.get(r.entry.id) ?? r.entry.id).filter((id) => !existing.some((e) => e === id)));
      const nodeRows = [...newIds].map((id) => { const m = /^github:([^/]+)\/(.+)$/.exec(id); return { id, native_id: m ? `${m[1]}/${m[2]}` : id, name: m ? m[2] : id }; });
      for (const b of chunks(nodeRows)) await writeCypher(REPO_NODE_CYPHER, { rows: b, now });
      const edgeRows = repoEntries.map((r) => ({ function_id: r.function_id, account_id: r.account_id, repo_id: casing.get(r.entry.id) ?? r.entry.id, via: r.entry.via, tag_key: r.entry.tag_key, stack: r.entry.stack, stale: r.stale, stale_since: r.stale_since }));
      for (const b of chunks(edgeRows)) await writeCypher(BUILT_FROM_CYPHER, { rows: b, now });
      repoCount = edgeRows.length;
    }

    // what this pass did not confirm goes: a function removed entirely, a trigger that stopped, a tag that changed
    await writeCypher("MATCH ()-[r:RUNS_AS {via: 'execution_identity'}]->() WHERE r.updated_at IS NULL OR r.updated_at <> $now DELETE r", { now });
    await writeCypher("MATCH (f:AdvisorResource)-[r:TRIGGERED_BY]->() WHERE r.updated_at IS NULL OR r.updated_at <> $now DELETE r", { now });
    await writeCypher("MATCH (f:AdvisorResource)-[r:EXPOSES]->(e:AdvisorEndpoint {native_type: 'function_url'}) WHERE r.updated_at IS NULL OR r.updated_at <> $now DELETE r", { now });
    await writeCypher("MATCH ()-[r:BUILT_FROM]->(:AdvisorRepository) WHERE r.via IN ['function_tag', 'stack_tag'] AND (r.updated_at IS NULL OR r.updated_at <> $now) DELETE r", { now });
    // a repository this layer named by a tag, with nothing pointing at or from it any more (not even CAN_ASSUME), goes; one the entitlements pass has since granted stays (and loses named_by there)
    await writeCypher("MATCH (n:AdvisorRepository {named_by: 'tag'}) WHERE NOT (n)--() DELETE n", {});

    return { functions: fns.length, runs_as: runsAs.filter((r) => r.role_arn).length, triggers: triggerCount, urls: urlRows.length, repositories: repoCount };
  } finally {
    busy = false;
  }
}

import { enabled, readQuery, writeCypher } from "./graph_mirror.js";
import { repoIdResolver } from "./function_facts.js";

/**
 * The join between the advisor's repositories and the code graph's: (:AdvisorRepository {id: 'github:<owner>/<repo>'})
 * -[:SAME_AS {via: source_link | name, matched}]->(:Repository) the stakgraph / repo2graph node of the same GitHub
 * repository in the shared Neo4j (its `source_link` is the URL it was ingested from, its `name` is `<owner>/<repo>`),
 * so a running container, a function or a pipeline's role reaches the code graph (files, functions, pull requests) in
 * one more hop. The Repository nodes are never written here: only read, and matched with the same rule a function's
 * tag or an image's label is resolved by (src/function_facts.ts repoIdFromTagValue), case-insensitively. Rebuilt by
 * every layer that writes AdvisorRepository nodes (the GitHub org, functions, containers, entitlements): an edge the
 * pass did not confirm goes; a Repository node that leaves takes its edges with it.
 */

export interface CodeRepository { name: string | null; source_link: string | null }
export interface CodeRepositoryRow { advisor_id: string; name: string | null; source_link: string | null; via: "source_link" | "name"; matched: string }

/** The SAME_AS rows between the given AdvisorRepository ids and the code graph's Repository nodes: a Repository's `source_link`
 *  resolved to a GitHub id (`resolve`: src/function_facts.ts repoIdResolver), else its `<owner>/<repo>` name when it has no
 *  source link at all (a link to another host names another host: no fallback). Matched case-insensitively, since the two
 *  graphs may spell the owner differently. Pure. */
export function codeRepositoryRows(advisorIds: string[], code: CodeRepository[], resolve: (raw: string | null) => string | null): CodeRepositoryRow[] {
  const byKey = new Map<string, { repo: CodeRepository; via: CodeRepositoryRow["via"]; matched: string }[]>();
  for (const repo of code) {
    let via: CodeRepositoryRow["via"] = "source_link";
    let id = repo.source_link ? resolve(repo.source_link) : null;
    if (!id && !repo.source_link && repo.name) { id = resolve(repo.name); via = "name"; }
    if (!id) continue;
    const key = id.toLowerCase();
    if (!byKey.has(key)) byKey.set(key, []);
    byKey.get(key)!.push({ repo, via, matched: id });
  }
  const out: CodeRepositoryRow[] = [];
  for (const advisor_id of advisorIds) {
    for (const m of byKey.get(advisor_id.toLowerCase()) ?? []) out.push({ advisor_id, name: m.repo.name, source_link: m.repo.source_link, via: m.via, matched: m.matched });
  }
  return out;
}

const SAME_AS_CYPHER = `
UNWIND $rows AS row
MATCH (a:AdvisorRepository {id: row.advisor_id})
MATCH (c:Repository) WHERE coalesce(c.name, '') = coalesce(row.name, '') AND coalesce(c.source_link, '') = coalesce(row.source_link, '')
MERGE (a)-[x:SAME_AS]->(c) SET x += {via: row.via, matched: row.matched, updated_at: $now}`;

const chunks = <T,>(xs: T[], n = 250): T[][] => { const out: T[][] = []; for (let i = 0; i < xs.length; i += n) out.push(xs.slice(i, i + n)); return out; };

/** Every AdvisorRepository to the code graph's Repository of the same GitHub repository; edges this pass did not confirm go. */
export async function linkCodeRepositories(now = new Date().toISOString()): Promise<{ linked: number } | null> {
  if (!enabled()) return null;
  const advisorIds = (await readQuery("MATCH (a:AdvisorRepository) WHERE a.id STARTS WITH 'github:' RETURN a.id AS id", {}, { rowCap: 10_000 })).rows.map((r) => String(r.id));
  const code: CodeRepository[] = (await readQuery("MATCH (c:Repository) RETURN c.name AS name, c.source_link AS source_link", {}, { rowCap: 10_000 })).rows
    .map((r) => ({ name: r.name == null ? null : String(r.name), source_link: r.source_link == null ? null : String(r.source_link) }));
  const rows = advisorIds.length && code.length ? codeRepositoryRows(advisorIds, code, repoIdResolver()) : [];
  for (const b of chunks(rows)) await writeCypher(SAME_AS_CYPHER, { rows: b, now });
  await writeCypher("MATCH (:AdvisorRepository)-[x:SAME_AS]->(:Repository) WHERE x.updated_at IS NULL OR x.updated_at <> $now DELETE x", { now });
  return { linked: rows.length };
}

/** `linkCodeRepositories` for a layer whose own result must not fail on the join: the error is logged, never thrown. */
export async function linkCodeRepositoriesQuietly(now?: string): Promise<void> {
  try { await linkCodeRepositories(now); } catch (e: any) { console.error(`[graph] code repositories: ${e?.message || e}`); }
}

import { enabled, writeCypher } from "../../graph_mirror.js";
import { githubOrgRow, listApps, listMembers, listRepoAccess, listRepos, listSecrets, listTeams } from "./inventory.js";
import { GITHUB, appId, collaboratorId, memberId, repoNodeId, secretId, teamId } from "./index.js";

/**
 * The GitHub adapter's graph layer, on top of the identity and secret nodes the mirror core writes from
 * `githubAdapter.resources()`:
 * - (:AdvisorRepository {id: 'github:<owner>/<repo>', source: 'github_org'}) per repository, IN_ACCOUNT the org: the same
 *   node the GitHub Actions OIDC trust paths point at (src/access_paths.ts), so a repository that can assume an AWS role
 *   and the people who can push to it meet on one node.
 * - (person identity)-[:MEMBER_OF {role}]->(team identity).
 * - (identity)-[:CAN_ACCESS {via, level}]->(repository): a direct grant (member or outside collaborator) or a team's.
 *   The org-wide grants go to the org's AdvisorAccount instead of every repository: an owner (level admin, via owner),
 *   the base permission every member holds (via base_permission), an App installed on all repositories (via app).
 * - (secret)-[:STORED_IN]->(repository | account).
 * Then the people and credentials (src/graph_access.ts mirrorAccess), which need the repositories for deploy keys.
 */

const REPO_CYPHER = `
UNWIND $rows AS row
MERGE (r:AdvisorRepository {id: row.id}) ON CREATE SET r.first_seen = $now
SET r += {name: row.full_name, provider: 'github', native_type: 'repository', native_id: row.full_name, source: 'github_org', org_id: $account, account_id: $account, private: row.private, visibility: row.visibility, archived: row.archived, fork: row.fork,
  default_branch: row.default_branch, pushed_at: row.pushed_at, created_at: row.created_at, url: row.html_url, gone: false, last_seen: $now, updated_at: $now}
WITH r
MATCH (a:AdvisorAccount {id: $account})
MERGE (r)-[i:IN_ACCOUNT]->(a) SET i.updated_at = $now`;

const MEMBER_OF_CYPHER = `
UNWIND $rows AS row
MATCH (i:AdvisorResource {id: row.identity}) MATCH (t:AdvisorResource {id: row.team})
MERGE (i)-[m:MEMBER_OF]->(t) SET m.role = row.role, m.updated_at = $now`;

const ACCESS_REPO_CYPHER = `
UNWIND $rows AS row
MATCH (i:AdvisorResource {id: row.identity}) MATCH (r:AdvisorRepository {id: row.repo})
MERGE (i)-[x:CAN_ACCESS {via: row.via}]->(r) SET x.level = row.level, x.updated_at = $now`;

const ACCESS_ORG_CYPHER = `
UNWIND $rows AS row
MATCH (i:AdvisorResource {id: row.identity}) MATCH (a:AdvisorAccount {id: $account})
MERGE (i)-[x:CAN_ACCESS {via: row.via}]->(a) SET x.level = row.level, x.repositories = row.repositories, x.updated_at = $now`;

const STORED_IN_CYPHER = `
UNWIND $rows AS row
MATCH (s:AdvisorResource {id: row.secret})
OPTIONAL MATCH (r:AdvisorRepository {id: row.repo}) OPTIONAL MATCH (a:AdvisorAccount {id: $account})
WITH s, row, CASE WHEN row.repo IS NULL THEN a ELSE r END AS t WHERE t IS NOT NULL
MERGE (s)-[x:STORED_IN]->(t) SET x.environment = row.environment, x.updated_at = $now`;

const chunks = <T,>(xs: T[], n = 250): T[][] => { const out: T[][] = []; for (let i = 0; i < xs.length; i += n) out.push(xs.slice(i, i + n)); return out; };

export async function mirrorGitHub(): Promise<{ repos: number; access: number; teams: number; secrets: number }> {
  const org = githubOrgRow();
  if (!enabled() || !org) return { repos: 0, access: 0, teams: 0, secrets: 0 };
  const account = org.node_id; const now = new Date().toISOString();
  const repos = listRepos(account);
  for (const b of chunks(repos.map((r) => ({ ...r, id: repoNodeId(r.full_name) })))) await writeCypher(REPO_CYPHER, { rows: b, now, account });
  await writeCypher("MATCH (r:AdvisorRepository {source: 'github_org', org_id: $account}) WHERE r.updated_at <> $now SET r.gone = true", { account, now });

  const people = listMembers(account); const idOf = (login: string) => { const m = people.find((p) => p.login.toLowerCase() === login.toLowerCase()); return m ? (m.kind === "member" ? memberId(account, m.login) : collaboratorId(account, m.login)) : null; };
  const teams = listTeams(account);
  const memberOf = teams.flatMap((t) => t.members.map((m) => ({ identity: idOf(m.login), team: teamId(account, t.slug), role: m.role }))).filter((r) => r.identity);
  for (const b of chunks(memberOf)) await writeCypher(MEMBER_OF_CYPHER, { rows: b, now });

  const toRepo = [
    ...listRepoAccess(account).map((a) => ({ identity: idOf(a.login), repo: repoNodeId(a.repo), via: "direct", level: a.permission })),
    ...teams.flatMap((t) => t.repos.map((r) => ({ identity: teamId(account, t.slug), repo: repoNodeId(r.repo), via: "team", level: r.permission }))),
  ].filter((r) => r.identity);
  for (const b of chunks(toRepo)) await writeCypher(ACCESS_REPO_CYPHER, { rows: b, now });
  const base = org.default_permission && org.default_permission !== "none" ? org.default_permission : null;
  const toOrg = [
    ...people.filter((p) => p.role === "admin").map((p) => ({ identity: memberId(account, p.login), via: "owner", level: "admin", repositories: "all" })),
    ...(base ? people.filter((p) => p.kind === "member" && p.role !== "admin").map((p) => ({ identity: memberId(account, p.login), via: "base_permission", level: base, repositories: "all" })) : []),
    ...listApps(account).map((a) => ({ identity: appId(account, a.app_slug), via: "app", level: Object.entries(a.permissions).some(([k, v]) => k !== "metadata" && (v === "write" || v === "admin")) ? "write" : "read", repositories: a.repository_selection ?? "unknown" })),
  ];
  for (const b of chunks(toOrg)) await writeCypher(ACCESS_ORG_CYPHER, { rows: b, now, account });

  const stored = listSecrets(account).map((s) => ({ secret: secretId(account, s.id), repo: s.repo ? repoNodeId(s.repo) : null, environment: s.environment }));
  for (const b of chunks(stored)) await writeCypher(STORED_IN_CYPHER, { rows: b, now, account });
  // edges this pass did not write are gone (the org's own nodes only)
  await writeCypher("MATCH (s:AdvisorResource {provider: $provider, account_id: $account})-[r:CAN_ACCESS|MEMBER_OF|STORED_IN]->() WHERE r.updated_at IS NULL OR r.updated_at <> $now DELETE r", { provider: GITHUB, account, now });

  // the people and their credentials across providers (deploy keys hang off the repositories just written)
  try { await (await import("../../graph_access.js")).mirrorAccess(now); } catch (e: any) { console.error(`[graph] github access: ${e?.message || e}`); }
  return { repos: repos.length, access: toRepo.length + toOrg.length, teams: teams.length, secrets: stored.length };
}

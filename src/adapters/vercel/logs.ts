import { enabled, neoParams, writeCypher } from "../../graph_mirror.js";
import { listProjects, teamBilling, teamExtras, vercelTeam } from "./inventory.js";
import { usageRows } from "./usage.js";
import { VERCEL, vercelAdapter } from "./index.js";

/**
 * The log layer for a Vercel team, in the shape the AWS layer gives CloudWatch groups: one `KnLogGroup` per log
 * drain (`native_type: log_drain`) with where it delivers (the host only, never the URL with its token), what it
 * carries (sources, environments, sampling, format), and the team's metered log volume as `ingest_gb_day` priced
 * at the team's own `logDrainsVolume` rate. Vercel meters the volume per team, not per drain, so it is split evenly
 * across the enabled drains and `attributed_by` says so.
 *
 * Who writes to a drain is not a guess here: the drain names its projects (or covers them all), so the edges are
 * `(:KnSystem vercel_project)-[:SHIPS_LOGS_TO {attributed_by: 'drain lists the project'}]->(g)` for each covered
 * project, `(:AdvisorAccount team)-[:SHIPS_LOGS_TO]->(g)` when the drain covers every project, and the project
 * resource itself `-[:SHIPS_LOGS_TO {via: 'log drain'}]->(g)`, the same three shapes the AWS layer draws. A project
 * no drain covers is the Vercel equivalent of an instance with no agent config: its logs stop at Vercel's retention,
 * and the overview's attention list says so.
 */

export interface DrainRow {
  id: string; account_id: string; name: string; host: string | null; status: string | null; sources: string[]; environments: string[]; sampling_rate: number | null; format: string | null;
  ingest_gb_day: number | null; ingest_usd_month: number | null; price_per_gb: number | null; how: string; owner: string | null; projects: { id: string; system: string }[]; all_projects: boolean; created_at: string | null;
}

const r2 = (n: number) => Math.round(n * 100) / 100;

/** The rows the layer writes, pure given the inventory: one per drain, with the volume split and the projects it covers. */
export function drainRows(teamId: string, days = 14): DrainRow[] {
  const extras = teamExtras(teamId); const projects = listProjects();
  // the team's log volume per day over the days that have a row (a fresh database has fewer than `days`)
  const volume = usageRows(teamId, "log_drains", days); const gbTotal = volume.reduce((n, r) => n + (Number(r.metrics.log_volume) || 0), 0) / 1e9;
  const gbDay = volume.length && gbTotal ? r2(gbTotal / volume.length) : null;
  const rate = (teamBilling(teamId)?.rates ?? []).find((r) => r.item === "logDrainsVolume")?.usd ?? null;
  const live = extras.log_drains.filter((d) => !d.status || /enabled|active/i.test(d.status));
  const share = live.length ? 1 / live.length : 0;
  return extras.log_drains.map((d) => {
    const enabledDrain = live.includes(d);
    const covered = d.project_ids.length ? projects.filter((p) => d.project_ids.includes(p.id)) : projects;
    const gb = enabledDrain && gbDay != null ? r2(gbDay * share) : null;
    const owner = d.project_ids.length === 1 && covered.length === 1 ? `vercel_project:${covered[0].name}` : null;
    return {
      id: `vercel:log_drain:${d.id}`, account_id: teamId, name: d.name ?? d.id, host: d.host, status: d.status, sources: d.sources, environments: d.environments, sampling_rate: d.sampling_rate, format: d.format,
      ingest_gb_day: gb, ingest_usd_month: gb != null && rate != null ? r2(gb * 30 * rate) : null, price_per_gb: rate,
      how: `${d.project_ids.length ? `drain lists ${covered.map((p) => p.name).join(", ") || d.project_ids.join(", ")}` : "drain covers every project"}${live.length > 1 && enabledDrain ? `; volume is the team's, split evenly across ${live.length} drains` : ""}${!enabledDrain ? `; ${d.status}` : ""}`,
      owner, projects: covered.map((p) => ({ id: p.id, system: `vercel_project:${p.name}` })), all_projects: !d.project_ids.length, created_at: d.created_at,
    };
  });
}

export async function mirrorVercelLogs(): Promise<{ drains: number }> {
  if (!enabled()) return { drains: 0 };
  const team = vercelTeam(); const account = team?.id ?? vercelAdapter.primaryAccountId(); const now = new Date().toISOString();
  const rows = drainRows(account);
  if (rows.length) await writeCypher(`
UNWIND $rows AS row
MERGE (g:KnLogGroup {id: row.id}) SET g += {name: row.name, region: null, retention_days: null, stored_gb: null, ingest_gb_day: row.ingest_gb_day, ingest_usd_month: row.ingest_usd_month, storage_usd_month: null,
  owner: row.owner, attributed_by: row.how, candidates: [], tags: null, jev_choice: null, jev_confidence: null, host: row.host, status: row.status, sources: row.sources, environments: row.environments, sampling_rate: row.sampling_rate, format: row.format, all_projects: row.all_projects,
  provider: $provider, account_id: row.account_id, native_type: 'log_drain', native_id: row.id, gone: false, created_at: row.created_at, updated_at: $now}
WITH g, row
OPTIONAL MATCH ()-[old:SHIPS_LOGS_TO]->(g) DELETE old
WITH DISTINCT g, row
FOREACH (p IN row.projects |
  MERGE (s:KnSystem {id: p.system}) ON CREATE SET s.name = substring(p.system, 15), s.kind = 'deployment', s.native_kind = 'vercel_project', s.provider = $provider, s.account_id = row.account_id, s.updated_at = $now
  MERGE (s)-[e:SHIPS_LOGS_TO]->(g) SET e.gb_day = CASE WHEN size(row.projects) = 1 THEN row.ingest_gb_day ELSE null END, e.usd_month = CASE WHEN size(row.projects) = 1 THEN row.ingest_usd_month ELSE null END, e.price_per_gb = row.price_per_gb, e.attributed_by = row.how
  MERGE (r:AdvisorResource {id: p.id}) MERGE (r)-[o:SHIPS_LOGS_TO]->(g) SET o.via = 'log drain', o.source = 'vercel log drains API', o.attributed_by = 'observed')
FOREACH (_ IN CASE WHEN row.all_projects THEN [1] ELSE [] END |
  MERGE (a:AdvisorAccount {id: row.account_id}) MERGE (a)-[e:SHIPS_LOGS_TO]->(g) SET e.gb_day = row.ingest_gb_day, e.usd_month = row.ingest_usd_month, e.price_per_gb = row.price_per_gb, e.attributed_by = row.how)`, neoParams({ rows, provider: VERCEL, now }));
  await writeCypher("MATCH (g:KnLogGroup {provider: $provider, account_id: $account}) WHERE NOT g.id IN $ids SET g.gone = true, g.updated_at = $now", { provider: VERCEL, account, ids: rows.map((r) => r.id), now });
  return { drains: rows.length };
}

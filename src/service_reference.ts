/**
 * AWS's machine-readable service reference (https://docs.aws.amazon.com/service-authorization/latest/reference/service-reference.html):
 * every action of every service with its access level, the same annotations the IAM console's policy summary reads.
 * Public JSON, no credentials: an index at servicereference.us-east-1.amazonaws.com and one file per service prefix.
 * Only the services a policy names are fetched (an Allow on "*" needs none), kept in the database and read again
 * after 30 days or when the index says the file changed. src/policy_facts.ts grades policies against it.
 */
import { db, getJsonSetting, setSetting } from "./db.js";
import { levelOf, type Catalogue, type Level } from "./policy_facts.js";

const INDEX_URL = "https://servicereference.us-east-1.amazonaws.com/";
const META = "service_reference_meta";
const MAX_AGE_MS = 30 * 86_400_000;

db.exec(`create table if not exists aws_service_actions (
  service text not null, action text not null, name text not null, level text not null, primary key (service, action)
)`);

interface Meta { index_at: string | null; index: Record<string, { url: string; modified: number }>; fetched: Record<string, { at: string; modified: number | null }>; missing: string[] }
const meta = (): Meta => getJsonSetting<Meta>(META, { index_at: null, index: {}, fetched: {}, missing: [] });

type Fetch = typeof fetch;

async function getJson(url: string, f: Fetch): Promise<any> {
  const r = await f(url, { headers: { "user-agent": "cloud-advisor" }, signal: AbortSignal.timeout(30_000) });
  if (!r.ok) throw new Error(`service reference ${url}: HTTP ${r.status}`);
  return r.json();
}

/** The actions of one service file as rows. Pure. */
export function actionRows(service: string, file: any): { service: string; action: string; name: string; level: Level }[] {
  return (Array.isArray(file?.Actions) ? file.Actions : []).filter((a: any) => a?.Name).map((a: any) => ({ service, action: String(a.Name).toLowerCase(), name: String(a.Name), level: levelOf(a.Annotations?.Properties) }));
}

/** Makes sure the given service prefixes are in the catalogue; returns the prefixes the reference does not list. */
export async function ensureServices(prefixes: Iterable<string>, f: Fetch = fetch): Promise<{ fetched: number; unknown: string[]; errors: string[] }> {
  const m = meta(); const errors: string[] = []; let fetched = 0;
  if (!m.index_at || Date.now() - Date.parse(m.index_at) > 86_400_000) {
    try { const idx = await getJson(INDEX_URL, f); m.index = Object.fromEntries((Array.isArray(idx) ? idx : []).map((x: any) => [String(x.service).toLowerCase(), { url: String(x.url), modified: Number(x.modified) || 0 }])); m.index_at = new Date().toISOString(); }
    catch (e: any) { errors.push(String(e?.message || e)); }
  }
  const want = [...new Set([...prefixes].map((p) => p.toLowerCase()).filter((p) => /^[a-z0-9-]+$/.test(p)))];
  const stale = want.filter((p) => { const i = m.index[p]; const h = m.fetched[p]; return i && (!h || Date.now() - Date.parse(h.at) > MAX_AGE_MS || (h.modified != null && i.modified > h.modified)); });
  const put = db.prepare("insert into aws_service_actions(service, action, name, level) values (?, ?, ?, ?) on conflict(service, action) do update set name = excluded.name, level = excluded.level");
  for (let i = 0; i < stale.length; i += 8) {
    await Promise.all(stale.slice(i, i + 8).map(async (p) => {
      try {
        const rows = actionRows(p, await getJson(m.index[p].url, f));
        db.transaction(() => { db.prepare("delete from aws_service_actions where service = ?").run(p); for (const r of rows) put.run(r.service, r.action, r.name, r.level); })();
        m.fetched[p] = { at: new Date().toISOString(), modified: m.index[p].modified }; fetched++;
      } catch (e: any) { errors.push(String(e?.message || e)); }
    }));
  }
  const unknown = want.filter((p) => !m.index[p] && Object.keys(m.index).length > 0);
  m.missing = [...new Set([...m.missing, ...unknown])].slice(-200);
  setSetting(META, JSON.stringify(m));
  return { fetched, unknown, errors };
}

/** The catalogue from what is stored: one read of the table, kept in memory for the call. */
export function storedCatalogue(): Catalogue {
  const by = new Map<string, Map<string, { name: string; level: Level }>>();
  for (const r of db.prepare("select service, action, name, level from aws_service_actions").all() as any[]) {
    let m = by.get(r.service); if (!m) { m = new Map(); by.set(r.service, m); }
    m.set(r.action, { name: r.name, level: r.level });
  }
  return { actions: (s) => by.get(s.toLowerCase()) ?? null };
}

/** The service prefixes a set of documents names (what ensureServices must fetch). Pure. */
export function servicesNamed(docs: unknown[]): string[] {
  const out = new Set<string>();
  const walk = (d: any) => { for (const s of Array.isArray(d?.Statement) ? d.Statement : d?.Statement ? [d.Statement] : []) for (const a of [...[s?.Action ?? []].flat(), ...[s?.NotAction ?? []].flat()]) { const i = String(a).indexOf(":"); if (i > 0) out.add(String(a).slice(0, i).toLowerCase()); } };
  for (const d of docs) walk(d && typeof d === "object" ? d : (() => { try { return JSON.parse(String(d)); } catch { try { return JSON.parse(decodeURIComponent(String(d))); } catch { return null; } } })());
  return [...out];
}

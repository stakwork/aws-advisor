/**
 * How Vercel projects reach AWS, without reading a single env value:
 *
 * - OIDC federation: a role whose trust names the Vercel issuer (`oidc.vercel.com/<team>`) and a subject
 *   `owner:<team>:project:<name>:environment:<env>` is assumed by that project in that environment. The project is
 *   matched by name on the team the advisor reads; the graph gets (project)-[:RUNS_AS {via: 'vercel_oidc'}]->(role).
 * - Static keys: an env variable named like an AWS access key (AWS_ACCESS_KEY_ID, *_SECRET_ACCESS_KEY …) holds a
 *   long-lived key. Which IAM key it is cannot be read without the value; the candidates are the active keys created
 *   in the three days before the variable was (a key is usually made, then pasted), closest first.
 */
import { db } from "./db.js";

/** Env variable names that hold an AWS access key pair. */
export const AWS_KEY_NAME = /(^|_)(AWS_)?(ACCESS_KEY_ID|SECRET_ACCESS_KEY)$|^AWS_ACCESS_KEY$|^AWS_SECRET_KEY$/i;

export interface OidcLink { project_id: string; project_name: string; role_arn: string; role_name: string; account_id: string | null; environments: string[]; subjects: string[] }
export interface KeyCandidate { user: string; user_arn: string; account_id: string | null; key: string; key_created: string; hours_before: number }
export interface StaticKeyVar { project_id: string; project_name: string; names: string[]; targets: string[]; created_at: string | null; edited_by: string | null; candidates: KeyCandidate[]; oidc_enabled: boolean }

const parse = (s: unknown): any => { if (typeof s !== "string") return s ?? null; try { return JSON.parse(s); } catch { return null; } };
const rows = (sql: string, ...p: unknown[]): any[] => { try { return db.prepare(sql).all(...p) as any[]; } catch { return []; } };

/** A Vercel OIDC subject pattern as project and environment (`project:hive:environment:production` or with `*`). Pure. */
export function vercelSubject(scope: string): { project: string; environment: string } | null {
  const m = /^project:([^:]+):environment:([^:]+)$/.exec(scope.replace(/^owner:[^:]+:/, ""));
  return m ? { project: m[1], environment: m[2] } : null;
}

/** `*` and `?` as in an IAM StringLike, matched against a name. Pure. */
export const likeMatch = (pattern: string, name: string) => new RegExp(`^${pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".")}$`).test(name);

/** Which project assumes which role through Vercel OIDC, from the roles' trust conditions and the team's project names. Pure given the rows. */
export function oidcLinksFrom(roles: { arn: string; name: string; account_id: string | null; principals: any[] }[], projects: { id: string; name: string }[], teamSlug: string | null): OidcLink[] {
  const out: OidcLink[] = [];
  for (const r of roles) for (const p of r.principals.filter((x) => x.kind === "vercel")) {
    const team = /^Vercel team (.+)$/.exec(String(p.who))?.[1] ?? null;
    if (team && teamSlug && team !== teamSlug) continue;
    const subs = (p.scope as string[]).map((s) => ({ raw: s, parsed: vercelSubject(s) }));
    for (const proj of projects) {
      const hits = subs.filter((s) => s.parsed ? likeMatch(s.parsed.project, proj.name) : !p.scope.length);
      if (!hits.length && p.scope.length) continue;
      out.push({ project_id: proj.id, project_name: proj.name, role_arn: r.arn, role_name: r.name, account_id: r.account_id, environments: [...new Set(hits.map((h) => h.parsed?.environment ?? "*"))].sort(), subjects: hits.map((h) => h.raw) });
    }
  }
  return out;
}

export function oidcLinks(): OidcLink[] {
  const team = rows("select slug from vercel_team order by fetched_at desc limit 1")[0];
  const roles = rows("select arn, name, account_id, principals from inventory_iam_role where gone = 0 and principals like '%\"vercel\"%'").map((r) => ({ ...r, principals: parse(r.principals) ?? [] }));
  return oidcLinksFrom(roles, rows("select id, name from vercel_projects where gone = 0"), team?.slug ?? null);
}

/** The active IAM keys created up to 72 hours before a variable was, closest first. Pure. */
export function keyCandidates(createdAt: string | null, users: { name: string; arn: string; account_id: string | null; access_keys: any[] }[]): KeyCandidate[] {
  if (!createdAt) return [];
  const t = Date.parse(createdAt); if (!Number.isFinite(t)) return [];
  const out: KeyCandidate[] = [];
  for (const u of users) for (const k of u.access_keys) {
    if (k.status !== "Active" || !k.created) continue;
    const h = (t - Date.parse(k.created)) / 3_600_000;
    if (h >= -1 && h <= 72) out.push({ user: u.name, user_arn: u.arn, account_id: u.account_id, key: String(k.id), key_created: k.created, hours_before: Math.round(h * 10) / 10 });
  }
  return out.sort((a, b) => Math.abs(a.hours_before) - Math.abs(b.hours_before));
}

/** Every project holding an AWS key pair in its env variables, with the IAM keys it most likely is. */
export function staticKeyVars(): StaticKeyVar[] {
  const users = rows("select name, arn, account_id, access_keys from inventory_iam_user where gone = 0").map((u) => ({ ...u, access_keys: parse(u.access_keys) ?? [] }));
  const byProject = new Map<string, StaticKeyVar>();
  for (const e of rows("select e.project_id, e.key, e.targets, e.created_at, e.updated_at, e.edited_by, p.name as project_name, p.oidc from vercel_env e join vercel_projects p on p.id = e.project_id where e.gone = 0 and p.gone = 0")) {
    if (!AWS_KEY_NAME.test(String(e.key))) continue;
    const cur: StaticKeyVar = byProject.get(e.project_id) ?? { project_id: e.project_id, project_name: e.project_name, names: [], targets: [], created_at: null, edited_by: null, candidates: [], oidc_enabled: Boolean(parse(e.oidc)?.enabled) };
    cur.names.push(String(e.key));
    for (const t of parse(e.targets) ?? []) if (!cur.targets.includes(t)) cur.targets.push(t);
    const when = e.created_at ?? e.updated_at;
    if (/ACCESS_KEY_ID|ACCESS_KEY$/i.test(e.key) && when && (!cur.created_at || when < cur.created_at)) { cur.created_at = when; cur.edited_by = e.edited_by ?? null; }
    byProject.set(e.project_id, cur);
  }
  for (const v of byProject.values()) v.candidates = keyCandidates(v.created_at, users).slice(0, 3);
  return [...byProject.values()].sort((a, b) => a.project_name.localeCompare(b.project_name));
}

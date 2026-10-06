import { db } from "../../db.js";

/** A Vercel project, store or the team itself belongs to the team. Imports nothing but the database (see src/resource_index.ts). */
const rows = (sql: string, ...p: unknown[]): any[] => { try { return db.prepare(sql).all(...p) as any[]; } catch { return []; } };

export function vercelResourceIndex(): { of: (resource: string | null | undefined) => string | null } {
  const ids = new Map<string, string>();
  for (const r of rows("select id, team_id from vercel_projects")) if (r.id && r.team_id) ids.set(String(r.id), String(r.team_id));
  for (const r of rows("select id, team_id from vercel_stores")) if (r.id && r.team_id) ids.set(String(r.id), String(r.team_id));
  for (const r of rows("select id from vercel_team")) if (r.id) ids.set(String(r.id), String(r.id));
  return {
    of: (resource) => {
      if (!resource) return null;
      const r = String(resource);
      if (ids.has(r)) return ids.get(r)!;
      // a member, a domain or an endpoint id is prefixed with its team or project (`<team>/member/<user>`, `<project>:url:<host>`)
      for (const [k, v] of ids) if (k.length >= 8 && r.includes(k)) return v;
      return null;
    },
  };
}

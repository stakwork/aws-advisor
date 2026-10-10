import { db } from "../../db.js";
import { githubOrgRow, listApps, listCredentials, listMembers, listRepoAccess, listSecrets, listTeams } from "./inventory.js";

/**
 * What changed in the org between two collections: people joining or leaving, roles, 2FA, repository access, team
 * membership, credentials, installed Apps, secret names and seats. Each collection ends with a snapshot; the diff
 * against the previous one is a row per difference in `github_changes`, with its before and after. The audit log
 * says who did it; this table says what the API showed before and after, whatever the log kept.
 */

db.exec(`create table if not exists github_changes (id integer primary key autoincrement, org_id text not null, at text not null, kind text not null, subject_kind text not null, subject_id text, subject_name text, what text not null, before text, after text);
create index if not exists github_changes_org_at on github_changes(org_id, at);`);

export interface Snapshot {
  people: Record<string, { kind: string; role: string | null; mfa: boolean | null }>;
  access: Record<string, string | null>;
  teams: Record<string, string[]>;
  credentials: Record<string, { kind: string; holder: string | null; name: string | null }>;
  apps: Record<string, { selection: string | null; permissions: Record<string, string> }>;
  secrets: string[];
  seats: { seats: number | null; filled: number | null; plan: string | null } | null;
}

export function takeSnapshot(orgId: string): Snapshot {
  const org = githubOrgRow();
  return {
    people: Object.fromEntries(listMembers(orgId).map((m) => [m.login, { kind: m.kind, role: m.role, mfa: m.mfa }])),
    access: Object.fromEntries(listRepoAccess(orgId).map((a) => [`${a.repo}|${a.login}`, a.permission])),
    teams: Object.fromEntries(listTeams(orgId).map((t) => [t.slug, t.members.map((m) => m.login).sort()])),
    credentials: Object.fromEntries(listCredentials(orgId).filter((c) => c.kind !== "pat_request").map((c) => [c.id, { kind: c.kind, holder: c.holder, name: c.name }])),
    apps: Object.fromEntries(listApps(orgId).map((a) => [a.app_slug, { selection: a.repository_selection, permissions: a.permissions }])),
    secrets: listSecrets(orgId).map((s) => s.id).sort(),
    seats: org ? { seats: org.seats, filled: org.filled_seats, plan: org.plan } : null,
  };
}

export interface Change { kind: "added" | "removed" | "changed"; subject_kind: "person" | "access" | "team" | "credential" | "app" | "secret" | "org"; subject_id: string; subject_name: string; what: string; before: unknown; after: unknown }

/** The differences between two snapshots, in words. Pure. */
export function diff(a: Snapshot, b: Snapshot): Change[] {
  const out: Change[] = []; const J = JSON.stringify;
  for (const [l, p] of Object.entries(b.people)) { const o = a.people[l]; if (!o) out.push({ kind: "added", subject_kind: "person", subject_id: l, subject_name: l, what: `${l} joined as ${p.kind === "member" ? p.role ?? "member" : "outside collaborator"}`, before: null, after: p }); else { if (o.role !== p.role || o.kind !== p.kind) out.push({ kind: "changed", subject_kind: "person", subject_id: l, subject_name: l, what: `${l}: ${o.kind === "member" ? o.role : "outside collaborator"} → ${p.kind === "member" ? p.role : "outside collaborator"}`, before: o, after: p }); if (o.mfa !== p.mfa && p.mfa != null && o.mfa != null) out.push({ kind: "changed", subject_kind: "person", subject_id: l, subject_name: l, what: `${l}: two-factor ${p.mfa ? "turned on" : "turned off"}`, before: o.mfa, after: p.mfa }); } }
  for (const [l, o] of Object.entries(a.people)) if (!b.people[l]) out.push({ kind: "removed", subject_kind: "person", subject_id: l, subject_name: l, what: `${l} left (${o.kind === "member" ? o.role ?? "member" : "outside collaborator"})`, before: o, after: null });
  for (const [k, p] of Object.entries(b.access)) { const [repo, login] = k.split("|"); if (!(k in a.access)) out.push({ kind: "added", subject_kind: "access", subject_id: k, subject_name: repo, what: `${login} given ${p ?? "access"} on ${repo}`, before: null, after: p }); else if (a.access[k] !== p) out.push({ kind: "changed", subject_kind: "access", subject_id: k, subject_name: repo, what: `${login} on ${repo}: ${a.access[k]} → ${p}`, before: a.access[k], after: p }); }
  for (const [k, p] of Object.entries(a.access)) if (!(k in b.access)) { const [repo, login] = k.split("|"); out.push({ kind: "removed", subject_kind: "access", subject_id: k, subject_name: repo, what: `${login} lost ${p ?? "access"} on ${repo}`, before: p, after: null }); }
  for (const [slug, ms] of Object.entries(b.teams)) { const old = a.teams[slug]; if (!old) { out.push({ kind: "added", subject_kind: "team", subject_id: slug, subject_name: slug, what: `team ${slug} created`, before: null, after: ms }); continue; } for (const m of ms) if (!old.includes(m)) out.push({ kind: "added", subject_kind: "team", subject_id: slug, subject_name: slug, what: `${m} joined team ${slug}`, before: null, after: m }); for (const m of old) if (!ms.includes(m)) out.push({ kind: "removed", subject_kind: "team", subject_id: slug, subject_name: slug, what: `${m} left team ${slug}`, before: m, after: null }); }
  for (const slug of Object.keys(a.teams)) if (!b.teams[slug]) out.push({ kind: "removed", subject_kind: "team", subject_id: slug, subject_name: slug, what: `team ${slug} deleted`, before: a.teams[slug], after: null });
  const credWord = (c: { kind: string; holder: string | null; name: string | null }) => `${c.kind.replace(/_/g, " ")} "${c.name ?? "unnamed"}" of ${c.holder ?? "unknown"}`;
  for (const [id, c] of Object.entries(b.credentials)) if (!a.credentials[id]) out.push({ kind: "added", subject_kind: "credential", subject_id: id, subject_name: c.holder ?? id, what: `new ${credWord(c)}`, before: null, after: c });
  for (const [id, c] of Object.entries(a.credentials)) if (!b.credentials[id]) out.push({ kind: "removed", subject_kind: "credential", subject_id: id, subject_name: c.holder ?? id, what: `${credWord(c)} removed`, before: c, after: null });
  for (const [slug, p] of Object.entries(b.apps)) { const o = a.apps[slug]; if (!o) out.push({ kind: "added", subject_kind: "app", subject_id: slug, subject_name: slug, what: `App ${slug} installed (${p.selection ?? "?"} repositories)`, before: null, after: p }); else if (J(o) !== J(p)) out.push({ kind: "changed", subject_kind: "app", subject_id: slug, subject_name: slug, what: `App ${slug}: permissions or repositories changed`, before: o, after: p }); }
  for (const slug of Object.keys(a.apps)) if (!b.apps[slug]) out.push({ kind: "removed", subject_kind: "app", subject_id: slug, subject_name: slug, what: `App ${slug} uninstalled`, before: a.apps[slug], after: null });
  for (const s of b.secrets) if (!a.secrets.includes(s)) out.push({ kind: "added", subject_kind: "secret", subject_id: s, subject_name: s.split(":").pop()!, what: `secret ${s.split(":").pop()} added (${s.split(":").slice(0, 3).filter(Boolean).join(" ")})`, before: null, after: s });
  for (const s of a.secrets) if (!b.secrets.includes(s)) out.push({ kind: "removed", subject_kind: "secret", subject_id: s, subject_name: s.split(":").pop()!, what: `secret ${s.split(":").pop()} removed`, before: s, after: null });
  if (a.seats && b.seats && J(a.seats) !== J(b.seats)) out.push({ kind: "changed", subject_kind: "org", subject_id: "seats", subject_name: "seats", what: `seats ${a.seats.filled}/${a.seats.seats} → ${b.seats.filled}/${b.seats.seats}${a.seats.plan !== b.seats.plan ? `, plan ${a.seats.plan} → ${b.seats.plan}` : ""}`, before: a.seats, after: b.seats });
  return out;
}

/** Snapshot now, diff against the last one, store the differences. The first snapshot records nothing. */
export function recordChanges(orgId: string): { changes: number } {
  const key = `github_snapshot:${orgId}`; const now = new Date().toISOString();
  const prev = db.prepare("select value from settings where key = ?").get(key) as { value: string } | undefined;
  const snap = takeSnapshot(orgId); let n = 0;
  if (prev) {
    let old: Snapshot | null = null; try { old = JSON.parse(prev.value); } catch { /* a broken snapshot starts over */ }
    if (old) { const ins = db.prepare("insert into github_changes(org_id, at, kind, subject_kind, subject_id, subject_name, what, before, after) values (?, ?, ?, ?, ?, ?, ?, ?, ?)"); for (const c of diff(old, snap)) { ins.run(orgId, now, c.kind, c.subject_kind, c.subject_id, c.subject_name, c.what, c.before == null ? null : JSON.stringify(c.before), c.after == null ? null : JSON.stringify(c.after)); n++; } }
  }
  db.prepare("insert or replace into settings(key, value) values (?, ?)").run(key, JSON.stringify(snap));
  return { changes: n };
}

export const listChanges = (orgId: string, limit = 200) => db.prepare("select * from github_changes where org_id = ? order by at desc, id desc limit ?").all(orgId, limit) as { id: number; at: string; kind: string; subject_kind: string; subject_id: string; subject_name: string; what: string }[];

import { db } from "../../db.js";
import { listDomains, listEnvNames, listProjects, listStores, teamBilling, teamExtras, vercelTeam } from "./inventory.js";

/**
 * What changed on the team between two collections: the Changes page for a Vercel account, in the place
 * CloudTrail holds for an AWS one. Every collection ends with a snapshot of what matters (projects with their
 * production deployment, protection, firewall, runtime, domains and env variable names; stores with plan, status
 * and projects; members with role and MFA; log drains; the subscription), the snapshot is diffed against the
 * previous one, and each difference is a row in `vercel_changes` with its before and after. Nothing is inferred:
 * a row says what the API said then and says now.
 */

db.exec(`create table if not exists vercel_snapshots (id integer primary key autoincrement, team_id text not null, taken_at text not null, data text not null);
create table if not exists vercel_changes (
  id integer primary key autoincrement, team_id text not null, at text not null, kind text not null, subject_kind text not null, subject_id text, subject_name text, what text not null, before text, after text, snapshot_id integer
);
create index if not exists vercel_changes_team_at on vercel_changes(team_id, at);`);

export interface Snapshot {
  taken_at: string;
  projects: Record<string, { name: string; framework: string | null; node_version: string | null; repo: string | null; production_url: string | null; latest_id: string | null; latest_state: string | null; latest_target: string | null; latest_at: string | null; protection: Record<string, unknown>; firewall_enabled: boolean | null; firewall_rules: number | null; domains: Record<string, { verified: boolean; redirect: string | null }>; env: string[]; secure_compute: boolean }>;
  stores: Record<string, { name: string; product: string | null; plan: string | null; status: string | null; external_status: string | null; projects: string[]; size_bytes: number | null; quota_exceeded: boolean; token_expired: boolean | null }>;
  members: Record<string, { username: string | null; role: string | null; mfa: boolean | null; confirmed: boolean }>;
  drains: Record<string, { name: string | null; status: string | null; host: string | null; project_ids: string[]; sources: string[] }>;
  team: { plan: string | null; seats: number | null; seat_usd: number | null } | null;
}

export interface ChangeRow { id: number; team_id: string; at: string; kind: string; subject_kind: "project" | "store" | "member" | "drain" | "team" | "domain" | "env"; subject_id: string | null; subject_name: string | null; what: string; before: string | null; after: string | null; snapshot_id: number | null }

/** The team as it is in the tables right now, in the shape the diff reads. */
export function takeSnapshot(teamId: string): Snapshot {
  const snap: Snapshot = { taken_at: new Date().toISOString(), projects: {}, stores: {}, members: {}, drains: {}, team: null };
  for (const p of listProjects()) {
    snap.projects[p.id] = { name: p.name, framework: p.framework, node_version: p.node_version, repo: p.repo, production_url: p.production_url, latest_id: p.latest_id, latest_state: p.latest_state, latest_target: p.latest_target, latest_at: p.latest_at, protection: { ...p.protection }, firewall_enabled: p.firewall?.enabled ?? null, firewall_rules: p.firewall?.rules ?? null,
      domains: Object.fromEntries(listDomains(p.id).map((d) => [d.name, { verified: d.verified, redirect: d.redirect }])), env: listEnvNames(p.id).map((e) => e.key).sort(), secure_compute: p.connect.length > 0 };
  }
  for (const st of listStores()) snap.stores[st.id] = { name: st.name, product: st.product, plan: st.plan, status: st.status, external_status: st.details.external_status, projects: st.projects.map((x) => x.name ?? x.project_id).sort(), size_bytes: st.details.size_bytes, quota_exceeded: st.details.quota_exceeded, token_expired: st.details.token_expired };
  const extras = teamExtras(teamId);
  for (const m of extras.members) snap.members[m.uid] = { username: m.username, role: m.role, mfa: m.mfa, confirmed: m.confirmed };
  for (const d of extras.log_drains) snap.drains[d.id] = { name: d.name, status: d.status, host: d.host, project_ids: [...d.project_ids].sort(), sources: [...d.sources].sort() };
  const b = teamBilling(teamId); snap.team = b ? { plan: b.plan, seats: b.seats, seat_usd: b.seat_usd } : null;
  return snap;
}

type NewChange = Omit<ChangeRow, "id" | "team_id" | "at" | "snapshot_id">;
const J = (v: unknown) => (v == null ? null : typeof v === "string" ? v : JSON.stringify(v));
const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);

/** The differences between two snapshots, in words; pure. */
export function diffSnapshots(prev: Snapshot, next: Snapshot): NewChange[] {
  const out: NewChange[] = [];
  const row = (kind: string, subject_kind: ChangeRow["subject_kind"], subject_id: string | null, subject_name: string | null, what: string, before: unknown = null, after: unknown = null) => out.push({ kind, subject_kind, subject_id, subject_name, what, before: J(before), after: J(after) });
  const mode = (v: unknown) => (v ? String(v).replace(/_/g, " ") : "off");
  for (const [id, p] of Object.entries(next.projects)) {
    const q = prev.projects[id];
    if (!q) { row("project_added", "project", id, p.name, `project ${p.name} appeared (${p.framework ?? "no framework"}${p.repo ? `, ${p.repo}` : ""})`, null, p); continue; }
    if (p.latest_id && p.latest_id !== q.latest_id && p.latest_target === "production") row("deployment", "project", id, p.name, `production deployment ${p.latest_state ?? "?"}${p.latest_at ? ` at ${p.latest_at}` : ""}${q.latest_state && q.latest_state !== p.latest_state ? ` (was ${q.latest_state})` : ""}`, { id: q.latest_id, state: q.latest_state, at: q.latest_at }, { id: p.latest_id, state: p.latest_state, at: p.latest_at, url: p.production_url });
    else if (p.latest_state !== q.latest_state && p.latest_target === "production") row("deployment_state", "project", id, p.name, `latest production deployment went from ${q.latest_state ?? "?"} to ${p.latest_state ?? "?"}`, q.latest_state, p.latest_state);
    for (const k of ["sso", "password", "trusted_ips"] as const) if (!same(p.protection[k], q.protection[k])) row("protection", "project", id, p.name, `deployment protection (${k.replace("_", " ")}) changed from ${mode(q.protection[k])} to ${mode(p.protection[k])}`, q.protection[k], p.protection[k]);
    if (p.firewall_enabled !== q.firewall_enabled && (p.firewall_enabled != null || q.firewall_enabled != null)) row("firewall", "project", id, p.name, `the firewall went ${p.firewall_enabled ? "on" : "off"}`, q.firewall_enabled, p.firewall_enabled);
    else if (p.firewall_rules != null && q.firewall_rules != null && p.firewall_rules !== q.firewall_rules) row("firewall_rules", "project", id, p.name, `firewall rules ${q.firewall_rules} → ${p.firewall_rules}`, q.firewall_rules, p.firewall_rules);
    if (p.node_version !== q.node_version) row("runtime", "project", id, p.name, `node runtime ${q.node_version ?? "?"} → ${p.node_version ?? "?"}`, q.node_version, p.node_version);
    if (p.framework !== q.framework) row("framework", "project", id, p.name, `framework ${q.framework ?? "none"} → ${p.framework ?? "none"}`, q.framework, p.framework);
    if (p.secure_compute !== q.secure_compute) row("secure_compute", "project", id, p.name, `Secure Compute ${p.secure_compute ? "attached" : "detached"}`, q.secure_compute, p.secure_compute);
    for (const [d, v] of Object.entries(p.domains)) { const w = q.domains[d]; if (!w) row("domain_added", "domain", d, p.name, `domain ${d} added to ${p.name}${v.verified ? "" : " (not verified yet)"}`, null, v); else if (v.verified !== w.verified) row("domain_verified", "domain", d, p.name, `domain ${d} ${v.verified ? "verified" : "lost its verification"}`, w.verified, v.verified); }
    for (const d of Object.keys(q.domains)) if (!p.domains[d]) row("domain_removed", "domain", d, p.name, `domain ${d} removed from ${p.name}`, q.domains[d], null);
    const addedEnv = p.env.filter((e) => !q.env.includes(e)); const removedEnv = q.env.filter((e) => !p.env.includes(e));
    if (addedEnv.length) row("env_added", "env", id, p.name, `${addedEnv.length} env variable${addedEnv.length === 1 ? "" : "s"} added to ${p.name}: ${addedEnv.slice(0, 8).join(", ")}${addedEnv.length > 8 ? ", …" : ""}`, null, addedEnv);
    if (removedEnv.length) row("env_removed", "env", id, p.name, `${removedEnv.length} env variable${removedEnv.length === 1 ? "" : "s"} removed from ${p.name}: ${removedEnv.slice(0, 8).join(", ")}${removedEnv.length > 8 ? ", …" : ""}`, removedEnv, null);
  }
  for (const [id, q] of Object.entries(prev.projects)) if (!next.projects[id]) row("project_removed", "project", id, q.name, `project ${q.name} is gone`, q, null);
  for (const [id, s] of Object.entries(next.stores)) {
    const t = prev.stores[id];
    if (!t) { row("store_added", "store", id, s.name, `store ${s.name} (${s.product ?? "?"}${s.plan ? `, ${s.plan}` : ""}) appeared`, null, s); continue; }
    if (s.plan !== t.plan) row("store_plan", "store", id, s.name, `${s.name}: plan ${t.plan ?? "?"} → ${s.plan ?? "?"}`, t.plan, s.plan);
    if (s.status !== t.status || s.external_status !== t.external_status) row("store_status", "store", id, s.name, `${s.name}: status ${t.status ?? "?"}${t.external_status ? `/${t.external_status}` : ""} → ${s.status ?? "?"}${s.external_status ? `/${s.external_status}` : ""}`, { status: t.status, partner: t.external_status }, { status: s.status, partner: s.external_status });
    if (!same(s.projects, t.projects)) row("store_projects", "store", id, s.name, `${s.name} is now used by ${s.projects.join(", ") || "no project"} (was ${t.projects.join(", ") || "none"})`, t.projects, s.projects);
    if (s.quota_exceeded !== t.quota_exceeded) row("store_quota", "store", id, s.name, `${s.name} ${s.quota_exceeded ? "went over" : "is back under"} its plan's quota`, t.quota_exceeded, s.quota_exceeded);
    if (s.token_expired !== t.token_expired && s.token_expired != null) row("store_token", "store", id, s.name, `${s.name}'s token ${s.token_expired ? "expired" : "is valid again"}`, t.token_expired, s.token_expired);
  }
  for (const [id, t] of Object.entries(prev.stores)) if (!next.stores[id]) row("store_removed", "store", id, t.name, `store ${t.name} (${t.product ?? "?"}) is gone`, t, null);
  for (const [id, m] of Object.entries(next.members)) {
    const n = prev.members[id]; const who = m.username ?? id;
    if (!n) { row("member_added", "member", id, who, `${who} joined the team as ${m.role ?? "member"}${m.mfa === false ? " (no MFA)" : ""}`, null, m); continue; }
    if (m.role !== n.role) row("member_role", "member", id, who, `${who}: role ${n.role ?? "?"} → ${m.role ?? "?"}`, n.role, m.role);
    if (m.mfa !== n.mfa && m.mfa != null) row("member_mfa", "member", id, who, `${who} ${m.mfa ? "enabled" : "disabled"} MFA`, n.mfa, m.mfa);
  }
  for (const [id, n] of Object.entries(prev.members)) if (!next.members[id]) row("member_removed", "member", id, n.username ?? id, `${n.username ?? id} left the team`, n, null);
  for (const [id, d] of Object.entries(next.drains)) {
    const e = prev.drains[id]; const name = d.name ?? id;
    if (!e) { row("drain_added", "drain", id, name, `log drain ${name} added${d.host ? ` → ${d.host}` : ""}`, null, d); continue; }
    if (d.status !== e.status) row("drain_status", "drain", id, name, `log drain ${name} is ${d.status ?? "?"} (was ${e.status ?? "?"})`, e.status, d.status);
    if (!same(d.project_ids, e.project_ids)) row("drain_projects", "drain", id, name, `log drain ${name} now covers ${d.project_ids.length ? `${d.project_ids.length} project${d.project_ids.length === 1 ? "" : "s"}` : "every project"}`, e.project_ids, d.project_ids);
  }
  for (const [id, e] of Object.entries(prev.drains)) if (!next.drains[id]) row("drain_removed", "drain", id, e.name ?? id, `log drain ${e.name ?? id} removed`, e, null);
  if (prev.team && next.team && !same(prev.team, next.team)) row("subscription", "team", null, null, `subscription: ${prev.team.plan ?? "?"} × ${prev.team.seats ?? "?"} seats → ${next.team.plan ?? "?"} × ${next.team.seats ?? "?"} seats`, prev.team, next.team);
  return out;
}

/** Called at the end of a collection: stores the snapshot and the rows that differ from the previous one. Keeps the last 60 snapshots. */
export function recordChanges(teamId: string): { snapshot_id: number; changes: number; first: boolean } {
  const next = takeSnapshot(teamId);
  const prevRow = db.prepare("select id, data from vercel_snapshots where team_id = ? order by id desc limit 1").get(teamId) as { id: number; data: string } | undefined;
  let changes: NewChange[] = [];
  if (prevRow) { try { changes = diffSnapshots(JSON.parse(prevRow.data) as Snapshot, next); } catch { changes = []; } }
  return db.transaction(() => {
    const snapshotId = Number(db.prepare("insert into vercel_snapshots(team_id, taken_at, data) values (?, ?, ?)").run(teamId, next.taken_at, JSON.stringify(next)).lastInsertRowid);
    const ins = db.prepare("insert into vercel_changes(team_id, at, kind, subject_kind, subject_id, subject_name, what, before, after, snapshot_id) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
    for (const c of changes) ins.run(teamId, next.taken_at, c.kind, c.subject_kind, c.subject_id, c.subject_name, c.what, c.before, c.after, snapshotId);
    db.prepare("delete from vercel_snapshots where team_id = ? and id not in (select id from vercel_snapshots where team_id = ? order by id desc limit 60)").run(teamId, teamId);
    return { snapshot_id: snapshotId, changes: changes.length, first: !prevRow };
  })();
}

export function listChanges(teamId: string, opts: { days?: number; limit?: number; kind?: string } = {}): ChangeRow[] {
  const since = new Date(Date.now() - (opts.days ?? 7) * 86_400_000).toISOString();
  return db.prepare(`select * from vercel_changes where team_id = ? and at >= ?${opts.kind ? " and kind = ?" : ""} order by id desc limit ?`).all(teamId, since, ...(opts.kind ? [opts.kind] : []), opts.limit ?? 300) as ChangeRow[];
}

export const changesSummary = (teamId: string, days = 7) => { const rows = listChanges(teamId, { days, limit: 5000 }); const by = new Map<string, number>(); for (const r of rows) by.set(r.kind, (by.get(r.kind) ?? 0) + 1); return { total: rows.length, days, by_kind: [...by].map(([kind, n]) => ({ kind, n })).sort((a, b) => b.n - a.n), snapshots: (db.prepare("select count(*) as n from vercel_snapshots where team_id = ?").get(teamId) as { n: number }).n, last_snapshot_at: (db.prepare("select taken_at from vercel_snapshots where team_id = ? order by id desc limit 1").get(teamId) as { taken_at: string } | undefined)?.taken_at ?? null }; };

/** The team id for the routes, when the inventory has one. */
export const teamIdNow = (): string | null => vercelTeam()?.id ?? null;

import { db, getSetting, setSetting } from "./db.js";
import { resourceAccountIndex } from "./resource_index.js";
import { listMembers } from "./accounts.js";

/**
 * When the AWS credentials start resolving to a different account than the one the advisor was collecting, the
 * change is recorded (never acted on by itself): the old account's rows stay until a person decides. Three ways
 * out, all explicit: keep the data (dismiss), purge it (every row attributed to that account, in SQLite and in the
 * graph), or register the old account as a member of the new parent (its rows then stay as the member's, since
 * they already carry its account id).
 */

export interface AccountChange { from: string; to: string; at: string }
const KEY = "aws_account_change";

/** Called after a credential test: records a change of parent, clears a stale one. */
export function noteAccountChange(previous: string | null | undefined, current: string | null | undefined): AccountChange | null {
  if (!current) return pendingAccountChange();
  const pending = pendingAccountChange();
  if (previous && previous !== current) { const c = { from: previous, to: current, at: new Date().toISOString() }; setSetting(KEY, JSON.stringify(c)); stampLegacyRows(previous); return c; }
  if (pending && pending.to !== current) { setSetting(KEY, ""); return null; }
  return pending;
}

export function pendingAccountChange(): AccountChange | null {
  let c: AccountChange | null = null;
  try { const v = getSetting(KEY); c = v ? (JSON.parse(v) as AccountChange) : null; } catch { c = null; }
  if (!c) return null;
  // the way out was taken: the previous parent is a registered member now (its rows are the member's), so there is nothing left to decide
  try { if (listMembers().some((m) => m.account_id === c!.from)) { setSetting(KEY, ""); return null; } } catch { /* accounts not loaded */ }
  return c;
}

export function dismissAccountChange(): void { setSetting(KEY, ""); }

/**
 * Rows collected before the advisor recorded account ids carry none, and the scope rule reads an empty account as
 * the parent's. When the parent changes, those rows belong to the previous parent (the only account collected then),
 * so they are stamped with it; otherwise they would surface as the new parent's history.
 */
export function stampLegacyRows(account: string): Record<string, number> {
  const out: Record<string, number> = {};
  for (const table of tablesWithAccountId()) {
    try { const n = db.prepare(`update ${table} set account_id = ? where account_id is null or account_id = ''`).run(account).changes; if (n) out[table] = n; } catch { /* a table without the column */ }
  }
  return out;
}

export interface PurgeResult { account: string; tables: Record<string, number>; attributed: Record<string, number>; graph_deleted: number }

/** Every table whose rows carry an account id; the ones that name a resource instead are attributed through the inventories before those go. */
export function tablesWithAccountId(): string[] {
  return (db.prepare("select name from sqlite_master where type = 'table' and sql like '%account_id%' and name not in ('settings', 'vercel_usage', 'vercel_team', 'vercel_projects', 'vercel_stores', 'vercel_invoices', 'vercel_snapshots', 'vercel_changes')").all() as { name: string }[]).map((r) => r.name).sort();
}

/** Removes everything the advisor holds about one AWS account. Irreversible; the caller confirms. */
export const ACCOUNT_TARGET_RE = /^(\d{12}|team_[A-Za-z0-9]+)$/;
/** The Vercel tables keyed by team (vercel_domains and vercel_env hang off a project). */
const VERCEL_TEAM_TABLES = ["vercel_projects", "vercel_stores", "vercel_usage", "vercel_invoices", "vercel_snapshots", "vercel_changes", "vercel_deployments"];
export async function purgeAccountData(account: string, opts: { graph?: boolean } = {}): Promise<PurgeResult> {
  if (!ACCOUNT_TARGET_RE.test(account)) throw new Error("account must be a 12-digit AWS account id or a Vercel team id");
  const out: PurgeResult = { account, tables: {}, attributed: {}, graph_deleted: 0 };
  if (!/^\d{12}$/.test(account)) {
    // a platform account: its own tables by team id, the rows its rules passes wrote, and its graph nodes
    db.transaction(() => {
      for (const [table, col] of [["vercel_domains", "project_id"], ["vercel_env", "project_id"]] as const) { try { const n = db.prepare(`delete from ${table} where ${col} in (select id from vercel_projects where team_id = ?)`).run(account).changes; if (n) out.tables[table] = n; } catch { /* */ } }
      for (const table of VERCEL_TEAM_TABLES) { try { const n = db.prepare(`delete from ${table} where team_id = ?`).run(account).changes; if (n) out.tables[table] = n; } catch { /* */ } }
      try { const n = db.prepare("delete from vercel_team where id = ?").run(account).changes; if (n) out.tables.vercel_team = n; } catch { /* */ }
      for (const table of ["recommendations", "alerts", "actions"]) { try { const n = db.prepare(`delete from ${table} where account_id = ?`).run(account).changes; if (n) out.attributed[table] = n; } catch { /* */ } }
      try { const n = db.prepare("delete from runs where provider <> 'aws' and account_id = ?").run(account).changes; if (n) out.tables.runs = n; } catch { /* */ }
      try { db.prepare("delete from findings where run_id not in (select id from runs)").run(); } catch { /* */ }
      db.prepare("delete from settings where key in (?, ?)").run(`vercel_billing:${account}`, `vercel_extras:${account}`);
    })();
    if (opts.graph !== false) { try { const { wipeMirror, enabled } = await import("./graph_mirror.js"); if (enabled()) out.graph_deleted = (await wipeMirror(account)).deleted; } catch (e: any) { console.error(`[purge] graph: ${e?.message || e}`); } }
    return out;
  }
  // rows that name a resource: attribute them while the inventories still exist
  const idx = resourceAccountIndex(account);
  const mine = (resource: unknown) => idx.of(resource ? String(resource) : null) === account;
  db.transaction(() => {
    for (const [table, col] of [["recommendations", "resource"], ["alerts", "resource"], ["actions", "resource"], ["incidents", "resource"]] as const) {
      let rows: { id: number }[] = []; try { rows = (db.prepare(`select id, ${col} as r from ${table}`).all() as any[]).filter((r) => mine(r.r)); } catch { continue; }
      if (!rows.length) continue;
      if (table === "recommendations") { try { db.prepare(`delete from verifications where recommendation_id in (${rows.map(() => "?").join(",")})`).run(...rows.map((r) => r.id)); } catch { /* no table */ } }
      const n = db.prepare(`delete from ${table} where id in (${rows.map(() => "?").join(",")})`).run(...rows.map((r) => r.id)).changes;
      out.attributed[table] = n;
    }
    for (const table of tablesWithAccountId()) {
      try { const n = db.prepare(`delete from ${table} where account_id = ?`).run(account).changes; if (n) out.tables[table] = n; } catch { /* a view or a table without the column */ }
    }
    try { db.prepare("delete from findings where run_id not in (select id from runs)").run(); } catch { /* */ }
  })();
  if (opts.graph !== false) { try { const { wipeMirror, enabled } = await import("./graph_mirror.js"); if (enabled()) out.graph_deleted = (await wipeMirror(account)).deleted; } catch (e: any) { console.error(`[purge] graph: ${e?.message || e}`); } }
  const pending = pendingAccountChange(); if (pending?.from === account) dismissAccountChange();
  return out;
}

/** What a purge would remove, for the confirmation. */
export function purgePreview(account: string): { tables: Record<string, number>; attributed: Record<string, number> } {
  if (!/^\d{12}$/.test(account)) {
    const tables: Record<string, number> = {}; const attributed: Record<string, number> = {};
    for (const t of [...VERCEL_TEAM_TABLES]) { try { const n = (db.prepare(`select count(*) as n from ${t} where team_id = ?`).get(account) as { n: number }).n; if (n) tables[t] = n; } catch { /* */ } }
    for (const t of ["recommendations", "alerts", "actions"]) { try { const n = (db.prepare(`select count(*) as n from ${t} where account_id = ?`).get(account) as { n: number }).n; if (n) attributed[t] = n; } catch { /* */ } }
    return { tables, attributed };
  }
  const idx = resourceAccountIndex(account); const mine = (resource: unknown) => idx.of(resource ? String(resource) : null) === account;
  const attributed: Record<string, number> = {};
  for (const [table, col] of [["recommendations", "resource"], ["alerts", "resource"], ["actions", "resource"]] as const) { try { const n = (db.prepare(`select ${col} as r from ${table}`).all() as any[]).filter((r) => mine(r.r)).length; if (n) attributed[table] = n; } catch { /* */ } }
  const tables: Record<string, number> = {};
  for (const table of tablesWithAccountId()) { try { const n = (db.prepare(`select count(*) as n from ${table} where account_id = ?`).get(account) as { n: number }).n; if (n) tables[table] = n; } catch { /* */ } }
  return { tables, attributed };
}

// ---- the full wipe --------------------------------------------------------------------------------------------

/**
 * Everything the advisor collected, decided and learned about every account goes; what stays is configuration
 * (credentials metadata, registered accounts, runtime settings), public reference data (price lists, Amazon Linux
 * advisories), the generated playbooks with their sources, and, when asked, the Concepts and learnings (the links to
 * repo2graph's Concept graph; the Concepts themselves are never deleted from there). The next collection run starts
 * from nothing: fresh inventories, findings and graph, every row stamped with its account.
 */
const KEEP_TABLES = new Set(["settings", "sqlite_sequence", "prices", "alas_advisories", "alas_packages", "playbooks", "sources", "playbook_jobs", "signal_rules"]);
const CONCEPT_TABLES = ["concepts", "learnings"];
/** Collection state in `settings`; configuration keys (accounts, aws_credentials_meta, cfg:*, aws_ip_ranges, alas_stamp:*) stay. */
const STATE_SETTING_KEYS = ["aws_account_change", "inventory_refreshed_at", "permission_check", "usage_last_pass"];
const STATE_SETTING_PREFIXES = ["act:", "fact:", "vercel_billing:", "vercel_extras:"];

export interface WipeResult { tables: Record<string, number>; settings: number; kept: string[]; graph_deleted: number; playbooks_remirrored: number }

function wipeTables(preserveConcepts: boolean): string[] {
  const all = (db.prepare("select name from sqlite_master where type = 'table'").all() as { name: string }[]).map((r) => r.name);
  return all.filter((t) => !KEEP_TABLES.has(t) && !(preserveConcepts && CONCEPT_TABLES.includes(t))).sort();
}

export function wipePreview(preserveConcepts: boolean): { tables: Record<string, number>; kept: string[] } {
  const tables: Record<string, number> = {};
  for (const t of wipeTables(preserveConcepts)) { try { const n = (db.prepare(`select count(*) as n from ${t}`).get() as { n: number }).n; if (n) tables[t] = n; } catch { /* */ } }
  return { tables, kept: [...KEEP_TABLES, ...(preserveConcepts ? CONCEPT_TABLES : [])].filter((t) => t !== "sqlite_sequence").sort() };
}

export async function wipeAllData(opts: { preserveConcepts: boolean; graph?: boolean }): Promise<WipeResult> {
  const out: WipeResult = { tables: {}, settings: 0, kept: wipePreview(opts.preserveConcepts).kept, graph_deleted: 0, playbooks_remirrored: 0 };
  db.transaction(() => {
    db.pragma("foreign_keys = OFF");
    try {
      for (const t of wipeTables(opts.preserveConcepts)) { try { const n = db.prepare(`delete from ${t}`).run().changes; if (n) out.tables[t] = n; } catch (e: any) { console.error(`[wipe] ${t}: ${e?.message || e}`); } }
      const keys = (db.prepare("select key from settings").all() as { key: string }[]).map((r) => r.key).filter((k) => STATE_SETTING_KEYS.includes(k) || STATE_SETTING_PREFIXES.some((p) => k.startsWith(p)));
      for (const k of keys) out.settings += db.prepare("delete from settings where key = ?").run(k).changes;
    } finally { db.pragma("foreign_keys = ON"); }
  })();
  if (opts.graph !== false) {
    try {
      const g = await import("./graph_mirror.js");
      if (g.enabled()) { out.graph_deleted = (await g.wipeMirrorAll()).deleted; out.playbooks_remirrored = (await g.mirrorPlaybooks()).playbooks; }
    } catch (e: any) { console.error(`[wipe] graph: ${e?.message || e}`); }
  }
  return out;
}

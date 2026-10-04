import { awsAdapter } from "./adapters/aws/index.js";

/**
 * The account scope a page asks for (?account=<id>): every list that has an account column narrows to it; "all" (or
 * no parameter) is the fleet across accounts. Rows the inventory stored before it recorded account ids carry an empty
 * account_id and are the primary account's, so the primary scope includes them. Tables without an account column
 * (recommendations, alerts, actions) are scoped through the resource they name, where a page needs it.
 */

export interface AccountScope { id: string; primary: boolean }

/** The scope from a request's query; null means every account. */
export function accountScope(query: Record<string, unknown>): AccountScope | null {
  const id = typeof query.account === "string" ? query.account.trim() : "";
  if (!id || id === "all") return null;
  return { id, primary: id === awsAdapter.primaryAccountId() };
}

/** A SQL fragment narrowing `column` to the scope (every account when null), with its parameters. */
export function accountWhere(scope: AccountScope | null | undefined, column = "account_id"): { sql: string; params: unknown[] } {
  if (!scope) return { sql: "1=1", params: [] };
  return scope.primary ? { sql: `coalesce(${column}, '') in (?, '')`, params: [scope.id] } : { sql: `${column} = ?`, params: [scope.id] };
}

/**
 * For tables without an account column (recommendations, alerts, actions): whether the resource a row names belongs
 * to the scope, attributed through the inventories' ids (exact, or contained in an ARN). Every account when null.
 * Built once per request: the index reads the inventories.
 */
export function resourceInScope(scope: AccountScope | null | undefined): (resource: string | null | undefined) => boolean {
  if (!scope) return () => true;
  const { resourceAccountIndex } = require_overview();
  const idx = resourceAccountIndex(awsAdapter.primaryAccountId());
  return (resource) => { const a = idx.of(resource); return a === scope.id || (a == null && scope.primary); };
}
import * as overview from "./accounts_overview.js";
const require_overview = () => overview;

/** The run a findings page shows by default: the latest completed AWS collection run, or the latest rules pass of the platform account the scope names. */
export function latestRunIdFor(scope: AccountScope | null | undefined): number | undefined {
  const { db } = require_db();
  if (scope && !scope.primary && !/^\d{12}$/.test(scope.id)) return (db.prepare("select id from runs where provider <> 'aws' and account_id = ? and status = 'completed' order by id desc limit 1").get(scope.id) as { id: number } | undefined)?.id;
  return (db.prepare("select id from runs where provider = 'aws' and status = 'completed' order by id desc limit 1").get() as { id: number } | undefined)?.id;
}
import * as dbmod from "./db.js";
const require_db = () => dbmod;

/**
 * A summary query narrowed to the scope: the account clause is added to its `where ... gone = 0|1` (qualified with the
 * table's alias, or its name when the query joins), after a bare `where`, or as the only condition when it has none.
 * A table without an account column (the Route 53 rows) is left unscoped. Statements take no parameters of their own.
 */
const accountColumnCache = new Map<string, boolean>();
export function scopedStmt(scope: AccountScope | null | undefined, sql: string): { get: () => unknown; all: () => unknown[] } {
  const { db } = require_db();
  const from = /\bfrom (\w+)(?:\s+(?!left\b|inner\b|join\b|where\b|group\b|order\b|limit\b|on\b)(\w+))?/i.exec(sql);
  const table = from?.[1] ?? ""; const alias = from?.[2] ?? null;
  if (!accountColumnCache.has(table)) { try { accountColumnCache.set(table, (db.prepare(`pragma table_info(${table})`).all() as { name: string }[]).some((c) => c.name === "account_id")); } catch { accountColumnCache.set(table, false); } }
  const joined = /\bjoin\b/i.test(sql);
  const a = accountColumnCache.get(table) ? accountWhere(scope, alias ? `${alias}.account_id` : joined ? `${table}.account_id` : "account_id") : { sql: "1=1", params: [] as unknown[] };
  let q: string;
  if (/\bwhere (?:\w+\.)?gone = [01]/.test(sql)) q = sql.replace(/\bwhere ((?:\w+\.)?gone = [01])/, (_m, cond) => `where ${cond} and ${a.sql}`);
  else if (/\bwhere\b/.test(sql)) q = sql.replace(/\bwhere\b/, `where ${a.sql} and`);
  else q = sql.replace(/(\s+(?:group by|order by|limit)\b)|\s*$/, (m) => ` where ${a.sql}${m}`);
  const st = db.prepare(q);
  return { get: () => st.get(...a.params), all: () => st.all(...a.params) };
}

/**
 * Recommendations and alerts name a resource rather than an account. Each row gets an `account_id` once: from the
 * resource through the inventories' ids, from the details a platform provider's rules wrote (team_id), or from the
 * run that proposed it; what cannot be attributed stays empty and reads as the primary account's. Rows are stamped
 * when listed (only the empty ones, so the pass is cheap) and when written.
 */
export function stampRowAccounts(table: "recommendations" | "alerts" | "actions"): number {
  const { db } = require_db();
  let rows: any[] = []; try { rows = db.prepare(`select id, resource, ${table === "alerts" ? "details" : table === "recommendations" ? "run_id, evidence" : "null as x"} from ${table} where account_id is null or account_id = ''`).all(); } catch { return 0; }
  if (!rows.length) return 0;
  const idx = resourceAccountIndexOf();
  const runAccount = new Map<number, string | null>();
  const up = db.prepare(`update ${table} set account_id = ? where id = ?`);
  let n = 0;
  for (const r of rows) {
    let acct: string | null = idx.of(r.resource);
    if (!acct && table === "alerts") { try { const d = JSON.parse(r.details || "{}"); acct = d.team_id ?? d.account_id ?? idx.of(d.instance_id) ?? idx.of(d.pool) ?? idx.of(d.log_group) ?? idx.of(d.vpc_id) ?? idx.of(d.nat_gateway_id) ?? (Array.isArray(d.events) ? d.events.map((e: any) => idx.of(e?.instance_id)).find(Boolean) ?? null : null); } catch { /* */ } }
    if (!acct && table === "recommendations") { try { const ev = JSON.parse(r.evidence || "{}"); acct = ev.account_id ?? null; } catch { /* */ } if (!acct && r.run_id) { if (!runAccount.has(r.run_id)) runAccount.set(r.run_id, (db.prepare("select account_id, provider from runs where id = ?").get(r.run_id) as any)?.provider !== "aws" ? ((db.prepare("select account_id from runs where id = ?").get(r.run_id) as any)?.account_id ?? null) : null); acct = runAccount.get(r.run_id) ?? null; } }
    if (acct) { up.run(acct, r.id); n++; }
  }
  return n;
}
let cachedIdx: { at: number; idx: ReturnType<typeof overview.resourceAccountIndex> } | null = null;
/** The resource index, reused for a few seconds across the stamping passes of one request burst. */
function resourceAccountIndexOf() { const now = Date.now(); if (!cachedIdx || now - cachedIdx.at > 5000) cachedIdx = { at: now, idx: require_overview().resourceAccountIndex(awsAdapter.primaryAccountId()) }; return cachedIdx.idx; }


/** Whether a row belongs to the scope: by its own account id when it has one, else through the resource it names. */
export function rowInScope(scope: AccountScope | null | undefined): (row: { account_id?: string | null; resource?: string | null }) => boolean {
  if (!scope) return () => true;
  const byResource = resourceInScope(scope);
  return (row) => (row.account_id ? row.account_id === scope.id : byResource(row.resource));
}

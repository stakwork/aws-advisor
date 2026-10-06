import { adapters, adapterFor } from "./adapters/index.js";
import type { ProviderAdapter } from "./adapters/types.js";
import { rowAccount } from "./alert_store.js";

/**
 * The account scope a page asks for (?account=<id>): every list that has an account column narrows to it; "all" (or
 * no parameter) is the fleet across accounts. The id resolves to its provider through the registry (each adapter says
 * which ids it owns). Rows a provider stored before it recorded account ids carry an empty account_id and are its
 * primary account's (the adapter says whether it has such rows), so that scope includes them. Recommendations,
 * alerts and actions carry their provider and account from when they were written; older rows fall back to the
 * resource they name.
 */

export interface AccountScope { id: string; primary: boolean; provider?: string | null }

/** The provider an account id belongs to, or null when no adapter owns it. */
export function providerOfAccount(id: string): ProviderAdapter | null {
  return adapters().find((a) => { try { return a.owns(id) || id === a.primaryAccountId(); } catch { return false; } }) ?? null;
}

/** The scope from a request's query; null means every account. */
export function accountScope(query: Record<string, unknown>): AccountScope | null {
  const id = typeof query.account === "string" ? query.account.trim() : "";
  if (!id || id === "all") return null;
  const a = providerOfAccount(id);
  return { id, provider: a?.id ?? null, primary: Boolean(a?.legacy_blank_account && id === a.primaryAccountId()) };
}

/** The adapter whose storage holds rows without an account id (they read as its primary account's), if any. */
const legacyAdapter = (): ProviderAdapter | null => adapters().find((a) => a.legacy_blank_account) ?? null;

/** A SQL fragment narrowing `column` to the scope (every account when null), with its parameters. */
export function accountWhere(scope: AccountScope | null | undefined, column = "account_id"): { sql: string; params: unknown[] } {
  if (!scope) return { sql: "1=1", params: [] };
  return scope.primary ? { sql: `coalesce(${column}, '') in (?, '')`, params: [scope.id] } : { sql: `${column} = ?`, params: [scope.id] };
}

/**
 * An `order by` term for a lookup by a name that is unique per account only (an RDS identifier, a log group, a Lambda
 * function): the row of `accountId` first, then any other, so a caller that knows the account gets its row and one
 * that does not still gets one. The rows stored before account ids were kept ('') count as the primary account's.
 */
export function accountRank(accountId: string | null | undefined, column = "account_id"): { sql: string; params: [string, number] } {
  const id = accountId || "";
  const legacy = legacyAdapter();
  const primary = !id || (legacy && id === legacy.primaryAccountId()) ? 1 : 0;
  return { sql: `(case when coalesce(${column}, '') = ? then 0 when coalesce(${column}, '') = '' and ? = 1 then 0 else 1 end)`, params: [id, primary] };
}

/**
 * For tables without an account column (recommendations, alerts, actions): whether the resource a row names belongs
 * to the scope, attributed through the inventories' ids (exact, or contained in an ARN). Every account when null.
 * Built once per request: the index reads the inventories.
 */
export function resourceInScope(scope: AccountScope | null | undefined): (resource: string | null | undefined) => boolean {
  if (!scope) return () => true;
  const { resourceAccountIndex } = require_overview();
  const idx = resourceAccountIndex(legacyAdapter()?.primaryAccountId() ?? "");
  return (resource) => { const a = idx.of(resource); return a === scope.id || (a == null && scope.primary); };
}
import * as overview from "./accounts_overview.js";
const require_overview = () => overview;

/** The run a findings page shows by default: the latest completed run of the scope's provider for that account (every account: the first provider with rules that has run). */
export function latestRunIdFor(scope: AccountScope | null | undefined): number | undefined {
  if (scope) { const a = scope.provider ? adapterFor(scope.provider) : null; return a?.rules?.latestRunId(scope.primary ? null : scope.id); }
  for (const a of adapters()) { const id = a.rules?.latestRunId(null); if (id != null) return id; }
  return undefined;
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
 * Rows written before recommendations, alerts and actions carried their account: each gets an `account_id` once,
 * from its provider (the adapter's `accountOf`, from the resource and the details or evidence), else from the run
 * that proposed it. What cannot be attributed stays empty. New rows are stamped when written (src/alert_store.ts,
 * src/collector.ts upsertRecommendations, src/executor.ts recordProposal), so this pass finds nothing on a current database.
 */
export function stampRowAccounts(table: "recommendations" | "alerts" | "actions"): number {
  const { db } = require_db();
  let rows: any[] = []; try { rows = db.prepare(`select id, resource, provider, ${table === "alerts" ? "details" : table === "recommendations" ? "run_id, evidence as details" : "facts_json as details"} from ${table} where account_id is null or account_id = ''`).all(); } catch { return 0; }
  if (!rows.length) return 0;
  const up = db.prepare(`update ${table} set account_id = ? where id = ?`);
  const runAccount = db.prepare("select account_id from runs where id = ?");
  let n = 0;
  for (const r of rows) {
    if (!r.provider) continue;
    let acct = rowAccount(String(r.provider), r.resource, r.details ?? null, { primary: false });
    if (!acct && r.run_id) acct = (runAccount.get(r.run_id) as { account_id: string | null } | undefined)?.account_id ?? null;
    if (acct) { up.run(acct, r.id); n++; }
  }
  return n;
}

/** Whether a row belongs to the scope: by its own account id when it has one, else through the resource it names. */
export function rowInScope(scope: AccountScope | null | undefined): (row: { account_id?: string | null; resource?: string | null }) => boolean {
  if (!scope) return () => true;
  const byResource = resourceInScope(scope);
  return (row) => (row.account_id ? row.account_id === scope.id : byResource(row.resource));
}

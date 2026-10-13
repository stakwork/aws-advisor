/**
 * Lambda inventory: every function in the account with its memory, architecture and runtime, 30 days of CloudWatch
 * invocations, duration and errors priced at list, plus the per-function facts `function_facts` serves (network,
 * triggers, execution identity, layers, package size, env var names, log group, tags): see `src/function_facts.ts`
 * and `src/adapters/aws/functions.ts` for the generic shaping, this file for the collecting and storing. Refreshed
 * with the rest of the inventory; the Inventory page's Lambda tab and the knowledge graph read it from here.
 *
 * `inventory_lambda` is keyed on (account_id, name) only: a function name is unique per account, not per region. A
 * function seen in more than one region of one account therefore has only one row (the last one collected wins);
 * `detectRegionCollisions` below catches this and records it in `facts_missing` (`region_collision`) rather than
 * silently keeping one region. Fixing the key is a breaking schema change and stays out of scope for now
 * (see docs/cloud-ontology.md).
 */
import { addColumn, db, rekeyByAccount } from "./db.js";
import { S, query, credentialsMeta } from "./steampipe.js";
import { describeError } from "./permissions.js";
import { config } from "./config.js";
import { accountWhere, scopedStmt, type AccountScope } from "./scope.js";
import { alertInsert } from "./alert_store.js";
import { AWS } from "./adapters/types.js";
import { selectAvailable, tagsOf } from "./service_inventory.js";
import { connectionSchemaFor } from "./permission_check.js";
import { listMembers } from "./accounts.js";
import { detectRegionCollisions, logGroupName, parseEventSourceMapping, parsePolicyStd, stripQualifier, type PushTrigger, type PolledTrigger } from "./adapters/aws/functions.js";

const openErr = db.prepare("select id from alerts where kind = 'lambda_errors' and resource = ? and acknowledged = 0 limit 1");
const insertAlert = alertInsert(AWS);
const ackErr = db.prepare("update alerts set acknowledged = 1, acknowledged_by = 'system' where kind = 'lambda_errors' and resource = ? and acknowledged = 0");

/** Pure: a function whose error share of invocations crosses the threshold (with enough invocations to mean it); closes at half the threshold. */
export function lambdaErrorVerdict(errors: number, invocations: number, thresholdPct: number, minInvocations: number, open: boolean): boolean {
  if (invocations < minInvocations) return false;
  const pct = (100 * errors) / invocations;
  return pct >= thresholdPct || (open && pct >= thresholdPct / 2);
}

db.exec(`create table if not exists inventory_lambda (
  name text primary key, arn text, region text, runtime text, memory_mb integer, arm integer not null default 0, timeout_s integer,
  invocations_30d real, duration_ms_30d real, errors_30d real, days integer,
  invocations_month real, gb_seconds_month real, avg_duration_ms real, monthly_usd real,
  open_recs integer not null default 0, findings integer not null default 0,
  first_seen text not null, last_seen text not null, gone integer not null default 0
)`);
addColumn("inventory_lambda", "account_id", "text");
rekeyByAccount("inventory_lambda", "name"); // function names are unique per account only

// ---- function facts: additive columns (Step 1). List-shaped columns are JSON text; old rows have null in all of them. ----
for (const [col, type] of [
  ["vpc_id", "text"], ["subnet_ids", "text"], ["security_group_ids", "text"], ["role_arn", "text"], ["layers", "text"],
  ["code_size_bytes", "integer"], ["package_type", "text"], ["env_var_names", "text"], ["log_group", "text"], ["tags", "text"],
  ["polled_triggers", "text"], ["push_triggers", "text"], ["facts_missing", "text"],
] as const) addColumn("inventory_lambda", col, type);

export interface LambdaFacts { name: string; region: string; memory_mb: number; arm: boolean; invocations_30d: number; duration_ms_30d: number; days: number }
export const LAMBDA_PRICE = { gb_second_x86: 0.0000166667, gb_second_arm: 0.0000133334, per_request: 0.20 / 1e6 };

/** A function's monthly cost at list from 30 days of metrics: GB-seconds × the architecture's rate + requests. Pure. */
export function lambdaMonthlyCost(f: LambdaFacts): { gb_seconds_month: number; invocations_month: number; usd_month: number } {
  const scale = f.days > 0 ? 30 / f.days : 0;
  const gbSeconds = (f.duration_ms_30d / 1000) * (f.memory_mb / 1024) * scale;
  const invocations = f.invocations_30d * scale;
  const usd = gbSeconds * (f.arm ? LAMBDA_PRICE.gb_second_arm : LAMBDA_PRICE.gb_second_x86) + invocations * LAMBDA_PRICE.per_request;
  return { gb_seconds_month: Math.round(gbSeconds), invocations_month: Math.round(invocations), usd_month: Math.round(usd * 100) / 100 };
}

// ---- function facts: collection (Step 2) ----------------------------------------------------------------------

export interface MissingFact { fact: string; reason: string; since?: string; stale?: boolean }

const asArray = (v: unknown): any[] => {
  if (Array.isArray(v)) return v;
  if (typeof v === "string") { try { const p = JSON.parse(v); return Array.isArray(p) ? p : []; } catch { return []; } }
  return [];
};
const normLayers = (raw: unknown): { arn: string; code_size: number | null }[] =>
  asArray(raw).map((l: any) => ({ arn: String(l?.arn ?? l?.Arn ?? ""), code_size: l?.code_size ?? l?.CodeSize ?? null })).filter((l) => l.arn);

interface ConfigRow { vpc_id: string | null; subnet_ids: string[]; security_group_ids: string[]; role_arn: string | null; layers: { arn: string; code_size: number | null }[]; code_size_bytes: number | null; package_type: string | null; log_group: string; kms_key_arn: string | null }

/** `config` fact group: network, identity, layers, package size, log group name. One query, no per-function call. */
async function collectConfig(onError: (m: string) => void, onLog: (l: string) => void): Promise<Map<string, ConfigRow> | null> {
  const rows = await selectAvailable("aws_lambda_function", ["arn", "name", "region", "account_id", "vpc_id", "vpc_subnet_ids", "vpc_security_group_ids", "role", "layers", "code_size", "package_type", "logging_config", "kms_key_arn"], {}, onError, onLog);
  if (!rows) return null;
  const out = new Map<string, ConfigRow>();
  for (const r of rows) {
    const { arn } = stripQualifier(String(r.arn || ""));
    out.set(arn, {
      vpc_id: r.vpc_id || null, subnet_ids: asArray(r.vpc_subnet_ids).map(String), security_group_ids: asArray(r.vpc_security_group_ids).map(String),
      role_arn: r.role || null, layers: normLayers(r.layers), code_size_bytes: r.code_size != null ? Number(r.code_size) : null, package_type: r.package_type || null,
      log_group: logGroupName(r.logging_config, String(r.name)), kms_key_arn: r.kms_key_arn || null,
    });
  }
  return out;
}

/** `tags` fact group: its own call (one ListTags per function), so a throttled tag lookup never takes config/identity/layers down with it. */
async function collectTags(onError: (m: string) => void, onLog: (l: string) => void): Promise<Map<string, Record<string, string>> | null> {
  const rows = await selectAvailable("aws_lambda_function", ["arn", "region", "account_id", "tags"], {}, onError, onLog);
  if (!rows) return null;
  const out = new Map<string, Record<string, string>>();
  for (const r of rows) out.set(stripQualifier(String(r.arn || "")).arn, tagsOf(r.tags) || {});
  return out;
}

/** `env_var_names` fact group: only the keys of the environment ever leave Steampipe. Not through `selectAvailable`: the raw column must never be in the select list at all. */
async function collectEnvVarNames(onError: (m: string) => void): Promise<Map<string, string[] | null> | null> {
  try {
    const rows = await query<any>(`select arn, case when jsonb_typeof(environment_variables) = 'object' then coalesce((select array_agg(k) from jsonb_object_keys(environment_variables) k), '{}') end as env_var_names from ${S}.aws_lambda_function`);
    const out = new Map<string, string[] | null>();
    for (const r of rows) out.set(stripQualifier(String(r.arn || "")).arn, r.env_var_names == null ? null : asArray(r.env_var_names).map(String));
    return out;
  } catch (e) { onError(describeError(e, "function facts (env_var_names)")); return null; }
}

/** `invoke_permissions` fact group: `policy_std` (push triggers). On a GetPolicy denial, retried per account through that account's own Steampipe connection; accounts still denied are reported, the rest still refresh. Raw `policy_std` never leaves this function. */
async function collectInvokePermissions(baseFns: { arn: string; account_id: string | null }[], onError: (m: string) => void, onLog: (l: string) => void): Promise<{ byArn: Map<string, PushTrigger[]>; deniedAccounts: Set<string> }> {
  const byArn = new Map<string, PushTrigger[]>();
  const accounts = [...new Set(baseFns.map((f) => String(f.account_id || "")))];
  const coveredAccounts = new Set<string>();
  try {
    const rows = await query<any>(`select arn, account_id, policy_std from ${S}.aws_lambda_function`);
    for (const r of rows) { coveredAccounts.add(String(r.account_id || "")); if (r.policy_std != null) byArn.set(stripQualifier(String(r.arn || "")).arn, parsePolicyStd(r.policy_std)); }
  } catch (e) {
    const denied = /AccessDenied|AuthorizationError|not authorized|UnauthorizedOperation/i.test(String((e as any)?.message ?? e));
    if (!denied) { onError(describeError(e, "function facts (invoke_permissions)")); return { byArn, deniedAccounts: new Set(accounts) }; }
  }
  const deniedAccounts = new Set<string>();
  const outstanding = accounts.filter((a) => !coveredAccounts.has(a));
  if (outstanding.length) {
    const parentId = credentialsMeta()?.accountId || "";
    const memberIds = listMembers().filter((m) => m.enabled).map((m) => m.account_id);
    for (const acct of outstanding) {
      try {
        const schema = connectionSchemaFor(S, acct || null, parentId, memberIds);
        const rows = await query<any>(`select arn, policy_std from ${schema}.aws_lambda_function`);
        for (const r of rows) if (r.policy_std != null) byArn.set(stripQualifier(String(r.arn || "")).arn, parsePolicyStd(r.policy_std));
      } catch (e) { deniedAccounts.add(acct); onError(describeError(e, `function facts (invoke_permissions, account ${acct || "primary"})`)); }
    }
  }
  if (deniedAccounts.size) onLog(`function facts (invoke_permissions): GetPolicy denied for account(s) ${[...deniedAccounts].map((a) => a || "(primary)").join(", ")}`);
  return { byArn, deniedAccounts };
}

/** `polled_triggers` fact group: event source mappings (queues, streams), via `selectAvailable` so a plugin without `self_managed_event_source` just drops that column. */
async function collectPolledTriggers(onError: (m: string) => void, onLog: (l: string) => void): Promise<Map<string, PolledTrigger[]> | null> {
  const rows = await selectAvailable("aws_lambda_event_source_mapping", ["function_arn", "event_source_arn", "state", "batch_size", "self_managed_event_source", "account_id", "region"], {}, onError, onLog);
  if (!rows) return null;
  const out = new Map<string, PolledTrigger[]>();
  for (const r of rows) {
    const { arn } = stripQualifier(String(r.function_arn || ""));
    const list = out.get(arn) ?? []; list.push(parseEventSourceMapping(r)); out.set(arn, list);
  }
  return out;
}

function mergeMissing(prev: MissingFact[], current: Omit<MissingFact, "since">[], now: string): MissingFact[] {
  const prevSince = new Map(prev.map((p) => [p.fact, p.since ?? now]));
  return current.map((c) => ({ fact: c.fact, reason: c.reason, since: prevSince.get(c.fact) ?? now }));
}

const safeJson = (v: unknown): any => { if (v == null) return null; if (typeof v === "string") { try { return JSON.parse(v); } catch { return null; } } return v; };

export async function refreshLambdaInventory(onError: (m: string) => void = () => {}, onLog: (l: string) => void = () => {}): Promise<number> {
  let fns: any[];
  try { fns = await query<any>(`select name, account_id, arn, region, runtime, memory_size, architectures, timeout from ${S}.aws_lambda_function`); }
  catch (e) { onError(describeError(e, "lambda inventory (aws_lambda_function)")); return 0; }
  const agg = async (table: string, col: string) => { try { return new Map((await query<any>(`select name, sum(sum) as v, count(*) as days from ${S}.${table} where timestamp > now() - interval '30 days' group by 1`)).map((r) => [r.name, { v: Number(r.v || 0), days: Number(r.days || 0) }])); } catch (e) { onError(describeError(e, `lambda metrics (${table})`)); return new Map<string, { v: number; days: number }>(); } };
  const inv = await agg("aws_lambda_function_metric_invocations_daily", "sum");
  const dur = await agg("aws_lambda_function_metric_duration_daily", "sum");
  const err = await agg("aws_lambda_function_metric_errors_daily", "sum");
  const findingsFor = db.prepare("select count(*) as n from findings where run_id = (select max(run_id) from findings) and resource = ?");
  const recsFor = db.prepare("select count(*) as n from recommendations where status = 'open' and resource = ?");

  // function facts (Step 2): one query per group, joined by unqualified arn
  const configByArn = await collectConfig(onError, onLog);
  const tagsByArn = await collectTags(onError, onLog);
  const envByArn = await collectEnvVarNames(onError);
  const polledByArn = await collectPolledTriggers(onError, onLog);
  const { byArn: pushByArn, deniedAccounts } = await collectInvokePermissions(fns.map((f) => ({ arn: f.arn, account_id: f.account_id })), onError, onLog);
  const collisions = detectRegionCollisions(fns.map((f) => ({ account_id: f.account_id, name: f.name, region: f.region })));
  if (collisions.size) for (const [key, regions] of collisions) onLog(`function facts: ${key.replace("|", " / ")} is in several regions (${regions.join(", ")}); only one region's facts are kept`);

  const prevMissing = new Map<string, MissingFact[]>();
  for (const r of db.prepare("select account_id, name, facts_missing from inventory_lambda").all() as any[]) prevMissing.set(`${r.account_id || ""}|${r.name}`, safeJson(r.facts_missing) || []);

  const now = new Date().toISOString();
  const up = db.prepare(`insert into inventory_lambda(account_id, name, arn, region, runtime, memory_mb, arm, timeout_s, invocations_30d, duration_ms_30d, errors_30d, days, invocations_month, gb_seconds_month, avg_duration_ms, monthly_usd, open_recs, findings,
      vpc_id, subnet_ids, security_group_ids, role_arn, layers, code_size_bytes, package_type, env_var_names, log_group, tags, polled_triggers, push_triggers, facts_missing, first_seen, last_seen, gone)
    values (@account_id, @name, @arn, @region, @runtime, @memory_mb, @arm, @timeout_s, @invocations_30d, @duration_ms_30d, @errors_30d, @days, @invocations_month, @gb_seconds_month, @avg_duration_ms, @monthly_usd, @open_recs, @findings,
      @vpc_id, @subnet_ids, @security_group_ids, @role_arn, @layers, @code_size_bytes, @package_type, @env_var_names, @log_group, @tags, @polled_triggers, @push_triggers, @facts_missing, @now, @now, 0)
    on conflict(account_id, name) do update set arn = excluded.arn, region = excluded.region, runtime = excluded.runtime, memory_mb = excluded.memory_mb, arm = excluded.arm, timeout_s = excluded.timeout_s,
      invocations_30d = excluded.invocations_30d, duration_ms_30d = excluded.duration_ms_30d, errors_30d = excluded.errors_30d, days = excluded.days, invocations_month = excluded.invocations_month,
      gb_seconds_month = excluded.gb_seconds_month, avg_duration_ms = excluded.avg_duration_ms, monthly_usd = excluded.monthly_usd, open_recs = excluded.open_recs, findings = excluded.findings, last_seen = excluded.last_seen, gone = 0,
      vpc_id = case when @config_collected = 1 then excluded.vpc_id else vpc_id end,
      subnet_ids = case when @config_collected = 1 then excluded.subnet_ids else subnet_ids end,
      security_group_ids = case when @config_collected = 1 then excluded.security_group_ids else security_group_ids end,
      role_arn = case when @config_collected = 1 then excluded.role_arn else role_arn end,
      layers = case when @config_collected = 1 then excluded.layers else layers end,
      code_size_bytes = case when @config_collected = 1 then excluded.code_size_bytes else code_size_bytes end,
      package_type = case when @config_collected = 1 then excluded.package_type else package_type end,
      log_group = case when @config_collected = 1 then excluded.log_group else log_group end,
      tags = case when @tags_collected = 1 then excluded.tags else tags end,
      env_var_names = case when @env_collected = 1 then excluded.env_var_names else env_var_names end,
      polled_triggers = case when @polled_collected = 1 then excluded.polled_triggers else polled_triggers end,
      push_triggers = case when @invoke_collected = 1 then excluded.push_triggers else push_triggers end,
      facts_missing = excluded.facts_missing`);
  let n = 0;
  db.transaction(() => {
    for (const f of fns) {
      const arch = Array.isArray(f.architectures) ? f.architectures : (() => { try { return JSON.parse(f.architectures || "[]"); } catch { return []; } })();
      const facts: LambdaFacts = { name: f.name, region: f.region, memory_mb: Number(f.memory_size || 128), arm: arch.includes("arm64"), invocations_30d: inv.get(f.name)?.v ?? 0, duration_ms_30d: dur.get(f.name)?.v ?? 0, days: inv.get(f.name)?.days ?? 0 };
      const cost = lambdaMonthlyCost(facts);
      const errors = err.get(f.name)?.v ?? 0;
      const isOpen = Boolean(openErr.get(f.arn));
      const bad = lambdaErrorVerdict(errors, facts.invocations_30d, config.lambdaErrorPct, 100, isOpen);
      if (bad && !isOpen) { const pct = (100 * errors) / facts.invocations_30d; const msg = `${f.name}: ${pct.toFixed(1)}% of invocations failed in the last 30 days (${Math.round(errors).toLocaleString()} errors of ${Math.round(facts.invocations_30d).toLocaleString()}); failed invocations are billed like the rest`; insertAlert.run("lambda_errors", f.arn, msg, JSON.stringify({ summary: msg, function: f.name, errors_30d: errors, invocations_30d: facts.invocations_30d, error_pct: pct, memory_mb: facts.memory_mb, monthly_usd: cost.usd_month })); }
      if (!bad && isOpen) ackErr.run(f.arn);

      const { arn: baseArn } = stripQualifier(String(f.arn || ""));
      const accountId = f.account_id ? String(f.account_id) : "";
      const cfg = configByArn?.get(baseArn);
      const tags = tagsByArn?.get(baseArn);
      const envNames = envByArn?.get(baseArn);
      const polled = polledByArn?.get(baseArn) ?? [];
      const push = pushByArn.get(baseArn) ?? [];

      const configCollected = Boolean(configByArn);
      const tagsCollected = Boolean(tagsByArn);
      const envCollected = Boolean(envByArn);
      const polledCollected = Boolean(polledByArn);
      const invokeCollected = !deniedAccounts.has(accountId);

      const missingKey = `${accountId}|${f.name}`;
      const reasons: Omit<MissingFact, "since">[] = [];
      if (!configCollected) reasons.push({ fact: "config", reason: "aws_lambda_function (network, identity, layers) not readable" });
      if (!tagsCollected) reasons.push({ fact: "tags", reason: "ListTags denied" });
      if (!invokeCollected) reasons.push({ fact: "invoke_permissions", reason: "GetPolicy denied" });
      if (!envCollected) reasons.push({ fact: "env_var_names", reason: "environment_variables not readable" });
      else if (envNames == null && cfg?.kms_key_arn) reasons.push({ fact: "env_var_names", reason: "encrypted environment unreadable (needs kms:Decrypt, not granted by design)" });
      if (!polledCollected) reasons.push({ fact: "polled_triggers", reason: "aws_lambda_event_source_mapping not readable" });
      const collision = collisions.get(`${accountId}|${f.name}`);
      if (collision) reasons.push({ fact: "region_collision", reason: `also in ${collision.filter((r) => r !== f.region).join(", ")}` });
      const factsMissing = mergeMissing(prevMissing.get(missingKey) ?? [], reasons, now);

      up.run({ account_id: accountId, name: f.name, arn: f.arn, region: f.region, runtime: f.runtime ?? null, memory_mb: facts.memory_mb, arm: facts.arm ? 1 : 0, timeout_s: f.timeout ?? null, invocations_30d: facts.invocations_30d, duration_ms_30d: facts.duration_ms_30d, errors_30d: err.get(f.name)?.v ?? 0, days: facts.days,
        invocations_month: cost.invocations_month, gb_seconds_month: cost.gb_seconds_month, avg_duration_ms: facts.invocations_30d > 0 ? Math.round(facts.duration_ms_30d / facts.invocations_30d) : null, monthly_usd: cost.usd_month,
        open_recs: (recsFor.get(f.arn) as any).n, findings: (findingsFor.get(f.arn) as any).n,
        vpc_id: cfg?.vpc_id ?? null, subnet_ids: cfg ? JSON.stringify(cfg.subnet_ids) : "[]", security_group_ids: cfg ? JSON.stringify(cfg.security_group_ids) : "[]", role_arn: cfg?.role_arn ?? null,
        layers: cfg ? JSON.stringify(cfg.layers) : "[]", code_size_bytes: cfg?.code_size_bytes ?? null, package_type: cfg?.package_type ?? null,
        env_var_names: envNames === undefined ? "[]" : JSON.stringify(envNames ?? []), log_group: cfg?.log_group ?? `/aws/lambda/${f.name}`,
        tags: JSON.stringify(tags ?? {}), polled_triggers: JSON.stringify(polled), push_triggers: JSON.stringify(push), facts_missing: JSON.stringify(factsMissing),
        now,
        config_collected: configCollected ? 1 : 0, tags_collected: tagsCollected ? 1 : 0, env_collected: envCollected ? 1 : 0, polled_collected: polledCollected ? 1 : 0, invoke_collected: invokeCollected ? 1 : 0,
      });
      n++;
    }
    db.prepare("update inventory_lambda set gone = 1 where last_seen <> ?").run(now);
  })();
  return n;
}

const SORTS = ["name", "runtime", "memory_mb", "invocations_month", "gb_seconds_month", "avg_duration_ms", "errors_30d", "monthly_usd", "open_recs", "findings"];
export function listLambda(f: { q?: string; sort?: string; gone?: boolean; scope?: AccountScope | null } = {}) {
  const where: string[] = []; const params: unknown[] = [];
  if (f.scope) { const a = accountWhere(f.scope); where.push(a.sql); params.push(...a.params); }
  if (!f.gone) where.push("gone = 0");
  if (f.q) { where.push("(name like ? or runtime like ? or arn like ?)"); params.push(`%${f.q}%`, `%${f.q}%`, `%${f.q}%`); }
  const desc = f.sort?.startsWith("-"); const col = (f.sort || "").replace(/^-/, "");
  const order = SORTS.includes(col) ? `order by ${col} ${desc ? "desc" : "asc"} nulls last` : "order by monthly_usd desc, invocations_month desc";
  return db.prepare(`select * from inventory_lambda ${where.length ? `where ${where.join(" and ")}` : ""} ${order} limit 2000`).all(...params) as any[];
}
export function lambdaSummary(scope?: AccountScope | null) {
  const r = scopedStmt(scope, "select count(*) as total, coalesce(sum(monthly_usd), 0) as monthly_usd, coalesce(sum(invocations_month), 0) as invocations_month, coalesce(sum(gb_seconds_month), 0) as gb_seconds_month, coalesce(sum(arm), 0) as arm, coalesce(sum(open_recs), 0) as open_recs, coalesce(sum(findings), 0) as findings, coalesce(sum(invocations_30d > 0), 0) as active from inventory_lambda where gone = 0").get() as any;
  const gone = (scopedStmt(scope, "select count(*) as n from inventory_lambda where gone = 1").get() as any).n;
  return { ...r, gone };
}
export function lambdaFactsMap(): Map<string, LambdaFacts & { arn: string }> {
  return new Map((db.prepare("select name, arn, region, memory_mb, arm, invocations_30d, duration_ms_30d, days from inventory_lambda where gone = 0").all() as any[]).map((r) => [r.name, { name: r.name, arn: r.arn, region: r.region, memory_mb: r.memory_mb, arm: Boolean(r.arm), invocations_30d: r.invocations_30d, duration_ms_30d: r.duration_ms_30d, days: r.days }]));
}

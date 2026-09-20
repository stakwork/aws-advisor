/**
 * Lambda inventory: every function in the account with its memory, architecture and runtime, and 30 days of
 * CloudWatch invocations, duration and errors, priced at list (GB-seconds at the architecture's rate plus
 * requests, scaled to a month). Refreshed with the rest of the inventory; the Inventory page's Lambda tab and
 * the knowledge graph read it from here.
 */
import { db } from "./db.js";
import { S, query } from "./steampipe.js";
import { describeError } from "./permissions.js";
import { config } from "./config.js";

const openErr = db.prepare("select id from alerts where kind = 'lambda_errors' and resource = ? and acknowledged = 0 limit 1");
const insertAlert = db.prepare("insert into alerts(kind, resource, message, details) values (?, ?, ?, ?)");
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

export async function refreshLambdaInventory(onError: (m: string) => void = () => {}): Promise<number> {
  let fns: any[];
  try { fns = await query<any>(`select name, arn, region, runtime, memory_size, architectures, timeout from ${S}.aws_lambda_function`); }
  catch (e) { onError(describeError(e, "lambda inventory (aws_lambda_function)")); return 0; }
  const agg = async (table: string, col: string) => { try { return new Map((await query<any>(`select name, sum(sum) as v, count(*) as days from ${S}.${table} where timestamp > now() - interval '30 days' group by 1`)).map((r) => [r.name, { v: Number(r.v || 0), days: Number(r.days || 0) }])); } catch (e) { onError(describeError(e, `lambda metrics (${table})`)); return new Map<string, { v: number; days: number }>(); } };
  const inv = await agg("aws_lambda_function_metric_invocations_daily", "sum");
  const dur = await agg("aws_lambda_function_metric_duration_daily", "sum");
  const err = await agg("aws_lambda_function_metric_errors_daily", "sum");
  const findingsFor = db.prepare("select count(*) as n from findings where run_id = (select max(run_id) from findings) and resource = ?");
  const recsFor = db.prepare("select count(*) as n from recommendations where status = 'open' and resource = ?");
  const now = new Date().toISOString();
  const up = db.prepare(`insert into inventory_lambda(name, arn, region, runtime, memory_mb, arm, timeout_s, invocations_30d, duration_ms_30d, errors_30d, days, invocations_month, gb_seconds_month, avg_duration_ms, monthly_usd, open_recs, findings, first_seen, last_seen, gone)
    values (@name, @arn, @region, @runtime, @memory_mb, @arm, @timeout_s, @invocations_30d, @duration_ms_30d, @errors_30d, @days, @invocations_month, @gb_seconds_month, @avg_duration_ms, @monthly_usd, @open_recs, @findings, @now, @now, 0)
    on conflict(name) do update set arn = excluded.arn, region = excluded.region, runtime = excluded.runtime, memory_mb = excluded.memory_mb, arm = excluded.arm, timeout_s = excluded.timeout_s,
      invocations_30d = excluded.invocations_30d, duration_ms_30d = excluded.duration_ms_30d, errors_30d = excluded.errors_30d, days = excluded.days, invocations_month = excluded.invocations_month,
      gb_seconds_month = excluded.gb_seconds_month, avg_duration_ms = excluded.avg_duration_ms, monthly_usd = excluded.monthly_usd, open_recs = excluded.open_recs, findings = excluded.findings, last_seen = excluded.last_seen, gone = 0`);
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
      up.run({ name: f.name, arn: f.arn, region: f.region, runtime: f.runtime ?? null, memory_mb: facts.memory_mb, arm: facts.arm ? 1 : 0, timeout_s: f.timeout ?? null, invocations_30d: facts.invocations_30d, duration_ms_30d: facts.duration_ms_30d, errors_30d: err.get(f.name)?.v ?? 0, days: facts.days,
        invocations_month: cost.invocations_month, gb_seconds_month: cost.gb_seconds_month, avg_duration_ms: facts.invocations_30d > 0 ? Math.round(facts.duration_ms_30d / facts.invocations_30d) : null, monthly_usd: cost.usd_month,
        open_recs: (recsFor.get(f.arn) as any).n, findings: (findingsFor.get(f.arn) as any).n, now });
      n++;
    }
    db.prepare("update inventory_lambda set gone = 1 where last_seen <> ?").run(now);
  })();
  return n;
}

const SORTS = ["name", "runtime", "memory_mb", "invocations_month", "gb_seconds_month", "avg_duration_ms", "errors_30d", "monthly_usd", "open_recs", "findings"];
export function listLambda(f: { q?: string; sort?: string; gone?: boolean } = {}) {
  const where: string[] = []; const params: unknown[] = [];
  if (!f.gone) where.push("gone = 0");
  if (f.q) { where.push("(name like ? or runtime like ? or arn like ?)"); params.push(`%${f.q}%`, `%${f.q}%`, `%${f.q}%`); }
  const desc = f.sort?.startsWith("-"); const col = (f.sort || "").replace(/^-/, "");
  const order = SORTS.includes(col) ? `order by ${col} ${desc ? "desc" : "asc"} nulls last` : "order by monthly_usd desc, invocations_month desc";
  return db.prepare(`select * from inventory_lambda ${where.length ? `where ${where.join(" and ")}` : ""} ${order} limit 2000`).all(...params) as any[];
}
export function lambdaSummary() {
  const r = db.prepare("select count(*) as total, coalesce(sum(monthly_usd), 0) as monthly_usd, coalesce(sum(invocations_month), 0) as invocations_month, coalesce(sum(gb_seconds_month), 0) as gb_seconds_month, coalesce(sum(arm), 0) as arm, coalesce(sum(open_recs), 0) as open_recs, coalesce(sum(findings), 0) as findings, coalesce(sum(invocations_30d > 0), 0) as active from inventory_lambda where gone = 0").get() as any;
  const gone = (db.prepare("select count(*) as n from inventory_lambda where gone = 1").get() as any).n;
  return { ...r, gone };
}
export function lambdaFactsMap(): Map<string, LambdaFacts & { arn: string }> {
  return new Map((db.prepare("select name, arn, region, memory_mb, arm, invocations_30d, duration_ms_30d, days from inventory_lambda where gone = 0").all() as any[]).map((r) => [r.name, { name: r.name, arn: r.arn, region: r.region, memory_mb: r.memory_mb, arm: Boolean(r.arm), invocations_30d: r.invocations_30d, duration_ms_30d: r.duration_ms_30d, days: r.days }]));
}

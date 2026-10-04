/**
 * Lambda memory right-sized from the REPORT lines, once a person approved it. Every invocation ends with a
 * REPORT line in the function's log group that says how much memory it actually used; nobody reads them, so
 * functions keep the memory someone guessed at creation. The plan runs one Logs Insights query per busy
 * function over the last fourteen days (peak and average memory used, p95 and average duration, how many
 * reports) and files a tier-approve recommendation where the peak stays under half of what is configured:
 * the target is the peak plus 50 % headroom, rounded up to 64 MB, never under 128 MB. Approval-tier and not
 * automatic because CPU scales with memory on Lambda, so a lower setting can lengthen the duration and eat
 * part of the saving; a human weighs that. Approving it is the decision; the executor makes the change with
 * UpdateFunctionConfiguration, online, and the revert puts the old memory back.
 */
import { CloudWatchLogsClient, GetQueryResultsCommand, StartQueryCommand, StopQueryCommand } from "@aws-sdk/client-cloudwatch-logs";
import { GetFunctionConfigurationCommand, LambdaClient, ListTagsCommand, UpdateFunctionConfigurationCommand } from "@aws-sdk/client-lambda";
import { db } from "../db.js";
import { config } from "../config.js";
import { upsertRecommendations } from "../collector.js";
import type { RecInput } from "../rules.js";
import { LAMBDA_PRICE } from "../lambda_inventory.js";
import { approvedRecs, type ActionModule, type Creds, type Proposal } from "../executor.js";

export const KIND = "lambda_memory" as const;
export const ACTION_TYPE = "set_lambda_memory";
export const RULE = "lambda_memory";
export const WINDOW_DAYS = 14;
export const MIN_REPORTS = 100;
/** Propose only when the observed peak stays under this share of the configured memory. */
export const MAX_USED_SHARE = 0.5;
export const HEADROOM = 1.5;
export const MEMORY_STEP_MB = 64;
export const MIN_MEMORY_MB = 128;
export const MIN_SAVING_USD = 1;
const MAX_FUNCTIONS_PER_PLAN = 40;
const QUERY_CONCURRENCY = 5;
const QUERY_TIMEOUT_MS = 25_000;

export const QUERY = `filter @type = "REPORT" | stats max(@maxMemoryUsed) as max_used, avg(@maxMemoryUsed) as avg_used, pct(@duration, 95) as p95_ms, avg(@duration) as avg_ms, count(*) as n, max(@memorySize) as configured`;

export interface ReportStats { max_used_mb: number; avg_used_mb: number; p95_ms: number; avg_ms: number; n: number; configured_mb: number | null }
export interface VerdictInput { configured_mb: number; max_used_mb: number; n: number; p95_ms: number; avg_ms: number; invocations_month: number; arm: boolean }
export interface Verdict { target_mb: number | null; saving_usd_month: number; reason: string }

const round2 = (n: number) => Math.round(n * 100) / 100;

/** The memory to set for an observed peak: the peak plus headroom, rounded up to 64 MB, never under 128. */
export const targetMemory = (maxUsedMb: number) => Math.max(MIN_MEMORY_MB, Math.ceil((maxUsedMb * HEADROOM) / MEMORY_STEP_MB) * MEMORY_STEP_MB);

/** What a month costs at a memory size for the observed average duration and invocation rate (GB-seconds only; requests do not change). */
export const monthlyComputeUsd = (memoryMb: number, avgMs: number, invocationsMonth: number, arm: boolean) =>
  round2((memoryMb / 1024) * (avgMs / 1000) * invocationsMonth * (arm ? LAMBDA_PRICE.gb_second_arm : LAMBDA_PRICE.gb_second_x86));

/** The verdict for one function: pure. */
export function memoryVerdict(i: VerdictInput): Verdict {
  const none = (reason: string): Verdict => ({ target_mb: null, saving_usd_month: 0, reason });
  if (i.n < MIN_REPORTS) return none(`${i.n} REPORT line(s) in ${WINDOW_DAYS} days, ${MIN_REPORTS} needed to trust the peak`);
  if (i.configured_mb <= MIN_MEMORY_MB) return none(`already at the ${MIN_MEMORY_MB} MB floor`);
  const share = i.max_used_mb / i.configured_mb;
  if (share > MAX_USED_SHARE) return none(`peak ${Math.round(i.max_used_mb)} MB is ${Math.round(share * 100)} % of the configured ${i.configured_mb} MB: no room to trim`);
  const target = Math.min(targetMemory(i.max_used_mb), i.configured_mb - MEMORY_STEP_MB);
  if (target >= i.configured_mb) return none(`target ${target} MB is not below the configured ${i.configured_mb} MB`);
  const saving = round2(monthlyComputeUsd(i.configured_mb, i.avg_ms, i.invocations_month, i.arm) - monthlyComputeUsd(target, i.avg_ms, i.invocations_month, i.arm));
  if (saving < MIN_SAVING_USD) return none(`${i.configured_mb} → ${target} MB would save ${saving.toFixed(2)} USD/month, under ${MIN_SAVING_USD}`);
  return {
    target_mb: target, saving_usd_month: saving,
    reason: `${i.n.toLocaleString()} REPORT lines over ${WINDOW_DAYS} days: peak memory used ${Math.round(i.max_used_mb)} MB (${Math.round(share * 100)} % of the configured ${i.configured_mb} MB), p95 duration ${Math.round(i.p95_ms)} ms; ${target} MB keeps 50 % headroom above the peak and saves about ${saving.toFixed(2)} USD/month at the current ${Math.round(i.invocations_month).toLocaleString()} invocations a month`,
  };
}

/** One row of GetQueryResults → the stats (memory in bytes, duration in ms as Logs Insights reports them). */
export function parseReportRow(row: { field?: string; value?: string }[]): ReportStats | null {
  const f: Record<string, number> = {};
  for (const c of row) if (c.field && c.value != null && c.value !== "") f[c.field] = Number(c.value);
  if (!Number.isFinite(f.n) || f.n <= 0 || !Number.isFinite(f.max_used)) return null;
  const mb = (b: number) => b / 1048576;
  return { max_used_mb: mb(f.max_used), avg_used_mb: mb(f.avg_used ?? f.max_used), p95_ms: f.p95_ms ?? 0, avg_ms: f.avg_ms ?? 0, n: f.n, configured_mb: Number.isFinite(f.configured) ? mb(f.configured) : null };
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** The REPORT stats of one function's log group over the window; null when the group is missing or the query gave nothing. */
async function reportStats(logs: CloudWatchLogsClient, fn: string, now = Date.now()): Promise<{ stats: ReportStats | null; note?: string }> {
  let queryId: string | undefined;
  try {
    const r = await logs.send(new StartQueryCommand({ logGroupName: `/aws/lambda/${fn}`, startTime: Math.floor((now - WINDOW_DAYS * 86400000) / 1000), endTime: Math.floor(now / 1000), queryString: QUERY, limit: 1 }));
    queryId = r.queryId;
  } catch (e: any) {
    if (/ResourceNotFound|does not exist/i.test(String(e?.name || e?.message))) return { stats: null, note: "no log group /aws/lambda/<name>" };
    throw e;
  }
  if (!queryId) return { stats: null, note: "StartQuery returned no id" };
  const deadline = now + QUERY_TIMEOUT_MS;
  while (Date.now() < deadline) {
    await sleep(1000);
    const r = await logs.send(new GetQueryResultsCommand({ queryId }));
    if (r.status === "Complete") { const row = r.results?.[0]; return { stats: row ? parseReportRow(row) : null, note: row ? undefined : "no REPORT lines in the window" }; }
    if (r.status && !["Running", "Scheduled"].includes(r.status)) return { stats: null, note: `query ${r.status}` };
  }
  try { await logs.send(new StopQueryCommand({ queryId })); } catch { /* best effort */ }
  return { stats: null, note: `Logs Insights query did not finish in ${QUERY_TIMEOUT_MS / 1000} s` };
}

async function mapLimit<T, R>(items: T[], limit: number, fn: (t: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length); let next = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => { while (next < items.length) { const i = next++; out[i] = await fn(items[i]); } }));
  return out;
}

interface Candidate { name: string; arn: string | null; region: string; memory_mb: number; arm: boolean; invocations_30d: number; invocations_month: number }

function candidates(defaultRegion: string): Candidate[] {
  const min = Math.max(1, config.actLambdaMinInvocations);
  const rows = db.prepare("select name, arn, region, memory_mb, arm, invocations_30d, invocations_month from inventory_lambda where gone = 0 and invocations_30d * ? / 30 >= ? and memory_mb > ? order by monthly_usd desc limit ?")
    .all(WINDOW_DAYS, min, MIN_MEMORY_MB, MAX_FUNCTIONS_PER_PLAN) as any[];
  return rows.map((r) => ({ name: r.name, arn: r.arn ?? null, region: r.region || defaultRegion, memory_mb: Number(r.memory_mb || 128), arm: Boolean(r.arm), invocations_30d: Number(r.invocations_30d || 0), invocations_month: Number(r.invocations_month || 0) }));
}

async function configuration(lambda: LambdaClient, name: string) {
  try { return await lambda.send(new GetFunctionConfigurationCommand({ FunctionName: name })); }
  catch (e: any) { if (/ResourceNotFoundException/i.test(String(e?.name || e?.message))) return null; throw e; }
}

export const lambdaMemoryAction: ActionModule = {
  kind: KIND,
  label: "Lambda memory right-sized from the REPORT lines, once approved",

  async plan(creds, log) {
    const proposals: Proposal[] = []; const notes: string[] = [];
    const runId = (db.prepare("select id from runs where provider = 'aws' order by id desc limit 1").get() as { id: number } | undefined)?.id ?? 0;
    const approved = approvedRecs([ACTION_TYPE]);
    const cands = candidates(creds.region);
    if (!cands.length) { notes.push(`no Lambda function with ${config.actLambdaMinInvocations.toLocaleString()}+ invocations in ${WINDOW_DAYS} days above ${MIN_MEMORY_MB} MB`); return { proposals, notes }; }
    const byRegion = new Map<string, Candidate[]>();
    for (const c of cands) { if (!byRegion.has(c.region)) byRegion.set(c.region, []); byRegion.get(c.region)!.push(c); }
    let filed = 0, queried = 0;
    for (const [region, list] of byRegion) {
      const logs = new CloudWatchLogsClient({ region, credentials: creds.read });
      const lambda = new LambdaClient({ region, credentials: creds.read });
      try {
        const stats = await mapLimit(list, QUERY_CONCURRENCY, async (c) => { try { return await reportStats(logs, c.name); } catch (e: any) { return { stats: null, note: String(e?.message || e).slice(0, 160) }; } });
        const recs: RecInput[] = [];
        for (let i = 0; i < list.length; i++) {
          const c = list[i]; const s = stats[i];
          const skip = (why: string) => { notes.push(`${c.name}: ${why}`); log(`${c.name}: ${why}`); };
          queried++;
          if (!s.stats) { skip(s.note || "no REPORT stats"); continue; }
          const configured = s.stats.configured_mb && s.stats.configured_mb > 0 ? Math.round(s.stats.configured_mb) : c.memory_mb;
          const v = memoryVerdict({ configured_mb: configured, max_used_mb: s.stats.max_used_mb, n: s.stats.n, p95_ms: s.stats.p95_ms, avg_ms: s.stats.avg_ms, invocations_month: c.invocations_month, arm: c.arm });
          if (!v.target_mb) { log(`${c.name}: ${v.reason}`); continue; }
          const cfg = await configuration(lambda, c.name);
          if (!cfg) { skip("function no longer exists"); continue; }
          if (cfg.State && cfg.State !== "Active") { skip(`function state ${cfg.State}`); continue; }
          if (cfg.MemorySize != null && cfg.MemorySize !== configured) { skip(`memory is ${cfg.MemorySize} MB now, the REPORT lines say ${configured}; wait for the next window`); continue; }
          const arn = cfg.FunctionArn || c.arn;
          if (arn) { try { if ("advisor:hands-off" in ((await lambda.send(new ListTagsCommand({ Resource: arn }))).Tags ?? {})) { skip("tagged advisor:hands-off"); continue; } } catch { /* the policy's Deny still protects a tagged function */ } }
          const evidence = { region, configured_mb: configured, max_used_mb: Math.round(s.stats.max_used_mb), avg_used_mb: Math.round(s.stats.avg_used_mb), p95_ms: Math.round(s.stats.p95_ms), avg_ms: Math.round(s.stats.avg_ms), reports: s.stats.n, target_mb: v.target_mb, invocations_month: Math.round(c.invocations_month), arm: c.arm };
          recs.push({
            rule: RULE, title: `${c.name}: memory ${configured} → ${v.target_mb} MB (≈ ${v.saving_usd_month.toFixed(2)} USD/month)`,
            resource: c.name, resourceName: c.name, actionType: ACTION_TYPE, estMonthlySaving: v.saving_usd_month, tier: "approve", confidence: s.stats.n >= 1000 ? 0.8 : 0.65,
            rationale: `${v.reason}. Lambda gives CPU in proportion to memory, so a lower setting can lengthen the duration and eat part of the saving; that is why this needs a person and keeps 50 % headroom above the observed peak. Apply with update-function-configuration --memory-size ${v.target_mb}; the executor does it once approved.`,
            evidence,
          });
          const rec = approved.find((a) => a.resource === c.name);
          if (!rec) { log(`${c.name}: recommendation filed, waiting for approval`); continue; }
          const target = Number(rec.evidence?.target_mb) > 0 ? Number(rec.evidence.target_mb) : v.target_mb;
          if (cfg.MemorySize === target) { skip(`already at ${target} MB`); continue; }
          proposals.push({
            kind: KIND, resource: c.name, resource_name: c.name, region,
            dedupe: `${KIND}:${region}:${c.name}:${target}`,
            title: `${c.name}: memory ${configured} → ${target} MB`,
            reason: `${v.reason}. Approved as recommendation #${rec.id}${rec.decided_by ? ` by ${rec.decided_by}` : ""}. UpdateFunctionConfiguration: online, the next invocations run at ${target} MB; CPU scales with memory, so watch the duration.`,
            before: { memory_mb: configured }, after: { memory_mb: target },
            facts: { recommendation_id: rec.id, ...evidence, target_mb: target },
            rollback: `UpdateFunctionConfiguration back to ${configured} MB`,
            est_usd_month: rec.est_monthly_saving ?? v.saving_usd_month,
          });
        }
        if (recs.length) { upsertRecommendations(runId, recs, "rules", undefined, { reconcile: false }); filed += recs.length; }
      } catch (e: any) { const m = String(e?.message || e); notes.push(`${region}: ${m.slice(0, 160)}`); log(`${region}: ${m}`); }
      finally { logs.destroy(); lambda.destroy(); }
    }
    if (queried && !filed) notes.push(`${queried} function(s) read from their REPORT lines: none has a peak under half its memory worth 1 USD/month`);
    else if (filed) notes.push(`${filed} memory recommendation(s) filed or refreshed; the executor acts once one is approved`);
    return { proposals, notes };
  },

  async apply(p, creds) {
    const lambda = new LambdaClient({ region: p.region, credentials: creds.act() });
    try {
      const r = await lambda.send(new UpdateFunctionConfigurationCommand({ FunctionName: p.resource, MemorySize: Number(p.after.memory_mb) }));
      return `UpdateFunctionConfiguration: memory ${p.before.memory_mb} → ${p.after.memory_mb} MB, update ${r.LastUpdateStatus || "InProgress"}`;
    } finally { lambda.destroy(); }
  },

  async verify(p, creds) {
    const lambda = new LambdaClient({ region: p.region, credentials: creds.read });
    try {
      const cfg = await configuration(lambda, p.resource);
      if (!cfg) return { ok: false, note: "function not found on read-back" };
      const want = Number(p.after.memory_mb);
      if (cfg.MemorySize !== want) return cfg.LastUpdateStatus === "InProgress" ? { ok: null, note: `update in progress, memory still reads ${cfg.MemorySize} MB` } : { ok: false, note: `memory reads ${cfg.MemorySize} MB` };
      if (cfg.LastUpdateStatus === "InProgress") return { ok: null, note: `memory reads ${want} MB, update still in progress` };
      if (cfg.LastUpdateStatus === "Failed") return { ok: false, note: `update failed: ${cfg.LastUpdateStatusReason || ""}` };
      return { ok: true, note: `read back: ${want} MB, update ${cfg.LastUpdateStatus || "Successful"}` };
    } finally { lambda.destroy(); }
  },

  async revert(p, creds) {
    const lambda = new LambdaClient({ region: p.region, credentials: creds.act() });
    try { await lambda.send(new UpdateFunctionConfigurationCommand({ FunctionName: p.resource, MemorySize: Number(p.before.memory_mb) })); return `memory back to ${p.before.memory_mb} MB`; }
    finally { lambda.destroy(); }
  },
};

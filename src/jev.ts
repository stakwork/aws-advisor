import { createHash } from "node:crypto";
import { APIError, TypeSafeClient, type EntryType, type Questions, type SystemOneResult } from "@typesafe-ai/sdk";
import { config } from "./config.js";
import { db } from "./db.js";

/**
 * Thin client for TypeSafe's Jev: typed answers (a probability, a choice with probabilities, a score on a
 * rubric) to atomic questions about structured state. The advisor uses it for three decisions that used to
 * be regexes or guesses: whether a watcher alert is routine (src/triage.ts), what an EC2 or RDS resource is
 * for (src/roles.ts), and whether a fix the agent proposed could destroy something (src/tiercheck.ts). Jev
 * never loosens a tier and never triggers an action; it only classifies. Every call is recorded in
 * jev_calls for auditing. Everything here is a no-op without TYPESAFE_API_KEY.
 */

export const JEV_TIMEOUT_MS = 10_000;

export interface JevAnswer<Q extends Questions> {
  answers: SystemOneResult<Q>["answers"];
  usage: { input_tokens: number; output_tokens: number };
  latency_ms: number;
  model: string;
  call_id: number;
}

export interface AskOptions {
  /** Which advisor flow asked (alert_triage, resource_role, tier_check); recorded on the call row. */
  purpose?: string;
  model?: string;
}

export const jevEnabled = () => Boolean(config.typesafeApiKey);

let client: TypeSafeClient | null = null;
/** Drops the cached client so the next call uses the current key and model. */
export function resetJevClient(): void { client = null; }
function getClient(): TypeSafeClient | null {
  if (!jevEnabled()) return null;
  if (!client) {
    client = new TypeSafeClient({
      apiKey: config.typesafeApiKey,
      defaultModel: config.jevModel,
      timeout: JEV_TIMEOUT_MS,
      // One retry, only on a rate limit or a server error; a timeout is not retried (it would double the wait).
      retry: { maxRetries: 1, httpStatuses: new Set([429, 500, 501, 502, 503, 504]), apiConnectionError: false, apiTimeoutError: false },
      logLevel: "off",
    });
  }
  return client;
}

const insertCall = db.prepare(`insert into jev_calls(purpose, state_hash, questions, answers, model, input_tokens, output_tokens, latency_ms, error) values (?, ?, ?, ?, ?, ?, ?, ?, ?)`);

const stateHash = (state: EntryType) => createHash("sha1").update(JSON.stringify(state ?? null)).digest("hex").slice(0, 16);

// One log line per purpose per minute: a dead key or a network outage must not flood the watcher's log.
const lastLogged = new Map<string, number>();
function logOnce(purpose: string, message: string) {
  const now = Date.now();
  if ((lastLogged.get(purpose) ?? 0) > now - 60_000) return;
  lastLogged.set(purpose, now);
  console.error(`[jev] ${purpose}: ${message}`);
}

function describe(e: any): string {
  if (e instanceof APIError) return `HTTP ${e.status}${e.requestId ? ` (request ${e.requestId})` : ""}: ${String(e.message).slice(0, 200)}`;
  return String(e?.message || e).slice(0, 300);
}

/**
 * Asks Jev one batch of questions about a state. Never throws: a disabled key, a timeout, a bad response or
 * an API error return null (recorded in jev_calls with the error, logged once a minute per purpose).
 */
export async function askJev<const Q extends Questions>(rawState: unknown, questions: Q, opts: AskOptions = {}): Promise<JevAnswer<Q> | null> {
  const purpose = opts.purpose || "adhoc";
  // A JSON round trip drops undefined values and anything non-serialisable, which is what the wire would do anyway.
  const state = JSON.parse(JSON.stringify(rawState ?? null)) as EntryType;
  let c: TypeSafeClient | null;
  try { c = getClient(); } catch (e: any) { logOnce(purpose, `client could not be created: ${describe(e)}`); return null; }
  if (!c) return null;
  const model = opts.model || config.jevModel;
  const t0 = Date.now();
  try {
    const res = await c.systemOne({ state, questions, model }, { timeout: JEV_TIMEOUT_MS });
    const latency = Date.now() - t0;
    const id = Number(insertCall.run(purpose, stateHash(state), JSON.stringify(questions), JSON.stringify(res.answers), res.model, res.usage?.input_tokens ?? null, res.usage?.output_tokens ?? null, latency, null).lastInsertRowid);
    return { answers: res.answers, usage: { input_tokens: res.usage?.input_tokens ?? 0, output_tokens: res.usage?.output_tokens ?? 0 }, latency_ms: latency, model: res.model, call_id: id };
  } catch (e: any) {
    const latency = Date.now() - t0;
    const msg = describe(e);
    try { insertCall.run(purpose, stateHash(state), JSON.stringify(questions), null, model, null, null, latency, msg); } catch { /* the audit row is best effort */ }
    logOnce(purpose, `${msg} (${latency} ms)`);
    return null;
  }
}

/** Runs fn over items with at most `limit` in flight; results keep the input order. */
export async function mapLimit<T, R>(items: T[], limit: number, fn: (item: T, index: number) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  const worker = async () => {
    for (let i = next++; i < items.length; i = next++) out[i] = await fn(items[i], i);
  };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, worker));
  return out;
}

/** Splits a list into batches of at most `size`. */
export const chunk = <T>(items: T[], size: number): T[][] => {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
};

/** What the Settings page shows: enabled, model, today's calls and tokens, the last error. */
export function jevStats() {
  const today = db.prepare(`
    select count(*) as calls, coalesce(sum(error is not null), 0) as failed, coalesce(sum(input_tokens), 0) as input_tokens, coalesce(sum(output_tokens), 0) as output_tokens
    from jev_calls where created_at >= date('now')`).get() as { calls: number; failed: number; input_tokens: number; output_tokens: number };
  const byPurpose = db.prepare("select purpose, count(*) as calls from jev_calls where created_at >= date('now') group by purpose order by calls desc").all() as { purpose: string; calls: number }[];
  const lastError = db.prepare("select purpose, error, created_at from jev_calls where error is not null order by id desc limit 1").get() as { purpose: string; error: string; created_at: string } | undefined;
  const last = db.prepare("select created_at from jev_calls order by id desc limit 1").get() as { created_at: string } | undefined;
  return {
    enabled: jevEnabled(),
    model: config.jevModel,
    timeout_ms: JEV_TIMEOUT_MS,
    today: { ...today, by_purpose: byPurpose },
    last_call_at: last?.created_at ?? null,
    last_error: lastError ? { purpose: lastError.purpose, error: lastError.error, at: lastError.created_at } : null,
  };
}

export interface JevCallRow { id: number; purpose: string; state_hash: string; questions: unknown; answers: unknown; model: string | null; input_tokens: number | null; output_tokens: number | null; latency_ms: number | null; created_at: string; error: string | null }

const safeJson = (s: unknown) => { if (typeof s !== "string") return s ?? null; try { return JSON.parse(s); } catch { return s; } };

/** Audit trail: the latest calls with their questions and answers (GET /api/jev/calls). */
export function listJevCalls(opts: { limit?: number; purpose?: string } = {}): JevCallRow[] {
  const limit = Math.min(500, Math.max(1, opts.limit || 50));
  const rows = (opts.purpose
    ? db.prepare("select * from jev_calls where purpose = ? order by id desc limit ?").all(opts.purpose, limit)
    : db.prepare("select * from jev_calls order by id desc limit ?").all(limit)) as any[];
  return rows.map((r) => ({ ...r, questions: safeJson(r.questions), answers: safeJson(r.answers) }));
}

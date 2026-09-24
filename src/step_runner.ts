/**
 * Runs the read-only half of a tailored plan. A step's command may be executed from the app when every part of it
 * is an `aws` read call (describe, get, list, lookup, …) optionally piped through a text filter (head, jq, grep, …).
 * Nothing else runs: no shell, no substitution, no redirection, no write verb, no local file reads, no secrets
 * retrieval. The output becomes the step's outcome (src/progress.ts), so the re-plan and the thread see it, and
 * every run is kept in `step_runs`. The CLI gets the advisor's own credentials (src/steampipe.ts sdkCredentials),
 * whatever the mode, as environment variables for that one process.
 */
import { spawn } from "node:child_process";
import { db } from "./db.js";
import { queryReadOnly, sdkCredentials } from "./steampipe.js";
import { QUERY_ROW_CAP, QUERY_TIMEOUT_MS, prepareUserSql } from "./mcp.js";
import { MAX_OUTCOME_NOTE, parseProgress, statusAfterProgress, Progress } from "./progress.js";

db.exec(`create table if not exists step_runs (
  id integer primary key autoincrement,
  recommendation_id integer not null references recommendations(id) on delete cascade,
  resolution_id integer,
  step integer not null,
  command text not null,
  by_user text,
  exit_code integer,
  ms integer,
  output text,
  created_at text not null default (datetime('now'))
)`);

export const RUN_TIMEOUT_MS = 90_000;
export const MAX_OUTPUT = 200_000;
/** Filters a read call may be piped through: they only reshape text. */
export const FILTERS = new Set(["head", "tail", "grep", "sort", "uniq", "wc", "cut", "tr", "awk", "sed", "jq", "column", "nl", "cat", "tee"]);
/** Operations that read but hand out credentials or secrets, or write to the local disk: never run from the app. */
const DENIED_OPS = /^(get-login|get-login-password|get-authorization-token|get-session-token|assume-role|assume-role-with-|get-federation-token|get-secret-value|get-parameter|get-parameters|get-parameters-by-path|decrypt|get-object|get-object-torrent|select-object-content|get-random-password|get-credential-report|get-access-key-info|generate-)/;
/** Verbs that only read. `s3` gets its own rule below. */
const READ_OPS = /^(describe-|get-|list-|lookup-|search|search-|batch-get-|head-|query$|scan$|filter-log-events$|start-query$|get-query-results$|test-|simulate-|estimate-|preview-|check-|validate-)/;
const DENIED_FLAGS = /^(--profile|--endpoint-url|--no-verify-ssl|--ca-bundle|--cli-input-json|--cli-input-yaml)$/;

export interface Verdict { runnable: boolean; reason: string; via?: "sql" | "cli" }

/** Whether the `aws` CLI is on this host: null until checked, then the version or false. Checked once at startup (src/index.ts). */
export let cli: { present: boolean; version: string | null } | null = null;
export async function checkCli(): Promise<{ present: boolean; version: string | null }> {
  const r = await spawnStage(["aws", "--version"], { PATH: process.env.PATH }, null).catch(() => ({ code: 127, stdout: "", stderr: "" }));
  cli = r.code === 0 ? { present: true, version: (r.stdout || r.stderr).trim().split(/\s+/)[0] || "aws-cli" } : { present: false, version: null };
  if (!cli.present) console.warn("[run] the aws CLI is not installed on this host: plan steps cannot be run from the app until it is (the image installs AWS CLI v2)");
  else console.log(`[run] ${cli.version} available for read-only plan steps`);
  return cli;
}
/** The verdict for this host: the command rule, and whether the CLI is here to run it. */
export function runnableHere(command: string | undefined | null): Verdict {
  const v = runnable(command);
  if (v.runnable && cli && !cli.present) return { runnable: false, reason: "the aws CLI is not installed on the advisor host", via: "cli" };
  return { ...v, via: "cli" };
}

/** Steampipe first: a valid read-only verify_sql runs through the advisor's own connection; else the CLI rule on the command. */
export function verdictFor(step: { command?: string | null; verify_sql?: string | null }): Verdict {
  if (step.verify_sql && step.verify_sql.trim()) {
    const p = prepareUserSql(step.verify_sql);
    if (!("error" in p)) return { runnable: true, reason: `steampipe: ${step.verify_sql.trim().replace(/\s+/g, " ").slice(0, 80)}`, via: "sql" };
  }
  return { ...runnable(step.command), via: "cli" };
}
export function verdictHere(step: { command?: string | null; verify_sql?: string | null }): Verdict {
  const v = verdictFor(step);
  return v.via === "cli" ? runnableHere(step.command) : v;
}

/** A query result as a transcript: the SQL, then the rows as one JSON object per line (capped like the tool). */
export function formatRows(sql: string, columns: string[], rows: Record<string, unknown>[], cap = QUERY_ROW_CAP): string {
  const lines = [`-- ${sql.trim().replace(/\s+/g, " ")}`, `-- ${columns.join(", ")}`];
  for (const r of rows.slice(0, cap)) lines.push(JSON.stringify(r));
  if (!rows.length) lines.push("(0 rows)");
  else lines.push(`(${rows.length > cap ? `${cap} of more than ${cap}` : rows.length} row${rows.length === 1 ? "" : "s"})`);
  return lines.join("\n");
}

/** Runs a verify_sql with fresh data; a query error is a failed outcome, not an exception. */
export async function executeSql(sql: string): Promise<RunResult> {
  const t0 = Date.now();
  const p = prepareUserSql(sql);
  if ("error" in p) return { exit_code: 2, ms: 0, output: `-- ${sql}\n${p.error}`, state: "failed" };
  try {
    const { rows, columns } = await queryReadOnly(`select * from (\n${p.sql}\n) as _q limit ${QUERY_ROW_CAP + 1}`, { timeoutMs: QUERY_TIMEOUT_MS, freshData: true });
    return { exit_code: 0, ms: Date.now() - t0, output: formatRows(sql, columns, rows).slice(0, MAX_OUTPUT), state: "worked" };
  } catch (e: any) {
    return { exit_code: 1, ms: Date.now() - t0, output: `-- ${sql.trim().replace(/\s+/g, " ")}\nquery failed: ${String(e?.message || e).slice(0, 2000)}`, state: "failed" };
  }
}
export type Stage = string[];
export interface Chain { stages: Stage[]; then: "&&" | ";" | null }

/** Splits a command line into chains (`&&`, `;`, newlines) of pipe stages of argv words. Rejects anything a shell would interpret beyond that. */
export function parseCommand(command: string): { ok: true; chains: Chain[] } | { ok: false; reason: string } {
  const src = command.replace(/\r/g, "").split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#")).join(" ; ");
  if (!src) return { ok: false, reason: "no command" };
  const chains: Chain[] = [];
  let stages: Stage[] = [], words: string[] = [], word = "", inWord = false, quote: '"' | "'" | null = null;
  const pushWord = () => { if (inWord) { words.push(word); word = ""; inWord = false; } };
  const pushStage = () => { pushWord(); if (!words.length) return false; stages.push(words); words = []; return true; };
  const pushChain = (then: Chain["then"]) => { if (!pushStage()) return false; chains.push({ stages, then }); stages = []; return true; };
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (quote) {
      if (c === quote) { quote = null; continue; }
      if (quote === '"' && c === "\\" && i + 1 < src.length) { word += src[++i]; continue; }
      if (c === "$" && src[i + 1] === "(") return { ok: false, reason: "command substitution $( ) is not run from the app" };
      if (c === "`") return { ok: false, reason: "backticks are not run from the app" };
      word += c; inWord = true; continue;
    }
    if (c === '"' || c === "'") { quote = c; inWord = true; continue; }
    if (c === "\\" && i + 1 < src.length) { word += src[++i]; inWord = true; continue; }
    if (c === "$" && (src[i + 1] === "(" || src[i + 1] === "{")) return { ok: false, reason: "shell substitution is not run from the app" };
    if (c === "`") return { ok: false, reason: "backticks are not run from the app" };
    if (c === ">" || c === "<") return { ok: false, reason: "redirection is not run from the app" };
    if (c === "&" && src[i + 1] === "&") { if (!pushChain("&&")) return { ok: false, reason: "empty command before &&" }; i++; continue; }
    if (c === "|" && src[i + 1] === "|") return { ok: false, reason: "|| is not run from the app" };
    if (c === "&") return { ok: false, reason: "background jobs are not run from the app" };
    if (c === ";") { if (stages.length || inWord || words.length) { if (!pushChain(";")) return { ok: false, reason: "empty command before ;" }; } continue; }
    if (c === "|") { if (!pushStage()) return { ok: false, reason: "empty command before |" }; continue; }
    if (/\s/.test(c)) { pushWord(); continue; }
    word += c; inWord = true;
  }
  if (quote) return { ok: false, reason: "unbalanced quotes" };
  if (inWord || words.length || stages.length) pushChain(null);
  else if (chains.length) chains[chains.length - 1].then = null;
  if (!chains.length) return { ok: false, reason: "no command" };
  return { ok: true, chains };
}

/** Is this argv an `aws` call that only reads? */
export function awsReadOnly(argv: string[]): Verdict {
  if (argv[0] !== "aws") return { runnable: false, reason: `only aws commands run from the app (got ${argv[0]})` };
  let i = 1;
  while (i < argv.length && argv[i].startsWith("-")) {
    if (DENIED_FLAGS.test(argv[i])) return { runnable: false, reason: `${argv[i]} is not allowed from the app` };
    i += argv[i].includes("=") || argv[i].startsWith("--no-") || argv[i] === "--debug" ? 1 : 2;
  }
  const service = argv[i], op = argv[i + 1];
  if (!service || !op) return { runnable: false, reason: "no service and operation" };
  for (const a of argv) {
    if (/^(file|fileb):\/\//.test(a)) return { runnable: false, reason: "local file arguments are not read from the app" };
    if (DENIED_FLAGS.test(a)) return { runnable: false, reason: `${a} is not allowed from the app` };
    if (a === "--with-decryption") return { runnable: false, reason: "decrypted values are not fetched from the app" };
  }
  if (service === "s3") return op === "ls" ? { runnable: true, reason: "aws s3 ls" } : { runnable: false, reason: `aws s3 ${op} touches objects; only ls runs from the app` };
  if (DENIED_OPS.test(op)) return { runnable: false, reason: `${service} ${op} hands out credentials, secrets or files` };
  if (!READ_OPS.test(op)) return { runnable: false, reason: `${service} ${op} is not a read call` };
  return { runnable: true, reason: `aws ${service} ${op}` };
}

/** The verdict for a whole step command: every chain's first stage must be an aws read call, later stages text filters. */
export function runnable(command: string | undefined | null): Verdict {
  if (!command || !command.trim()) return { runnable: false, reason: "no command" };
  const p = parseCommand(command);
  if (!p.ok) return { runnable: false, reason: p.reason };
  const parts: string[] = [];
  for (const chain of p.chains) {
    const first = awsReadOnly(chain.stages[0]);
    if (!first.runnable) return first;
    parts.push(first.reason);
    for (const st of chain.stages.slice(1)) {
      if (!FILTERS.has(st[0])) return { runnable: false, reason: `${st[0]} is not a text filter the app pipes through (${[...FILTERS].join(", ")})` };
      if (st[0] === "tee" || st[0] === "sed" && st.some((a) => /^-i/.test(a))) return { runnable: false, reason: `${st[0]} would write a file` };
    }
  }
  return { runnable: true, reason: parts.join(", ") };
}

function spawnStage(argv: string[], env: NodeJS.ProcessEnv, input: string | null): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(argv[0], argv.slice(1), { env, stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "", stderr = "", done = false;
    const finish = (code: number | null) => { if (done) return; done = true; resolve({ code, stdout, stderr }); };
    const t = setTimeout(() => { stderr += `\n(killed after ${RUN_TIMEOUT_MS / 1000}s)`; child.kill("SIGKILL"); finish(124); }, RUN_TIMEOUT_MS);
    child.stdout.on("data", (d) => { if (stdout.length < MAX_OUTPUT) stdout += String(d); });
    child.stderr.on("data", (d) => { if (stderr.length < MAX_OUTPUT) stderr += String(d); });
    child.on("error", (e) => { stderr += String(e.message); clearTimeout(t); finish(127); });
    child.on("close", (code) => { clearTimeout(t); finish(code); });
    if (input != null) child.stdin.write(input);
    child.stdin.end();
  });
}

/** The advisor's own credentials as environment for one CLI process. */
export async function cliEnv(): Promise<NodeJS.ProcessEnv> {
  const c = sdkCredentials();
  const id = await c.provider();
  const env: NodeJS.ProcessEnv = { PATH: process.env.PATH, HOME: process.env.HOME, LANG: "C.UTF-8", AWS_PAGER: "", AWS_DEFAULT_REGION: c.region, AWS_REGION: c.region, AWS_ACCESS_KEY_ID: id.accessKeyId, AWS_SECRET_ACCESS_KEY: id.secretAccessKey };
  if (id.sessionToken) env.AWS_SESSION_TOKEN = id.sessionToken;
  return env;
}

export interface RunResult { exit_code: number; ms: number; output: string; state: "worked" | "failed" }

/** Runs a parsed command with the given environment; output is the transcript of every segment. Pure given `env`. */
export async function execute(chains: Chain[], env: NodeJS.ProcessEnv): Promise<RunResult> {
  const t0 = Date.now();
  const out: string[] = [];
  let exit = 0;
  for (const chain of chains) {
    let input: string | null = null, code: number | null = 0, stderr = "";
    for (const st of chain.stages) {
      const r = await spawnStage(st, env, input);
      input = r.stdout; code = r.code; stderr = r.stderr;
      if (code !== 0) break;
    }
    out.push(`$ ${chain.stages.map((s) => s.map((a) => (/[\s"'$]/.test(a) ? `'${a.replace(/'/g, "'\\''")}'` : a)).join(" ")).join(" | ")}`);
    if (input) out.push(input.trimEnd());
    if (stderr.trim()) out.push(stderr.trimEnd());
    if (code !== 0) { out.push(`(exit ${code})`); exit = code ?? 1; if (chain.then === "&&") break; }
  }
  const output = out.join("\n").slice(0, MAX_OUTPUT);
  return { exit_code: exit, ms: Date.now() - t0, output, state: exit === 0 ? "worked" : "failed" };
}

/** Head and tail of a long transcript, within the outcome note limit. */
export function clipForNote(s: string, max = MAX_OUTCOME_NOTE): string {
  if (s.length <= max) return s;
  const head = Math.floor(max * 0.7), tail = max - head - 40;
  return `${s.slice(0, head)}\n… (${s.length - head - tail} characters left out) …\n${s.slice(-tail)}`;
}

const inFlight = new Set<number>();

/** Runs step `index` of the recommendation's latest completed plan and records the outcome. */
export async function runStep(recId: number, index: number, by: string | null): Promise<{ run_id: number; state: "worked" | "failed"; exit_code: number; ms: number; output: string; progress: Progress }> {
  const rec = db.prepare("select id, status, progress from recommendations where id = ?").get(recId) as { id: number; status: string; progress: string | null } | undefined;
  if (!rec) { const e: any = new Error("not found"); e.code = "not_found"; throw e; }
  const res = db.prepare("select id, plan from resolutions where recommendation_id = ? and status = 'completed' order by id desc limit 1").get(recId) as { id: number; plan: string } | undefined;
  const plan = res ? (JSON.parse(res.plan) as { plan: { step: string; command?: string; verify_sql?: string }[] }) : null;
  if (!plan) { const e: any = new Error("no tailored plan to run"); e.code = "no_plan"; throw e; }
  const step = plan.plan[index];
  if (!step) { const e: any = new Error(`the plan has ${plan.plan.length} steps`); e.code = "bad_step"; throw e; }
  const v = verdictHere(step);
  if (!v.runnable) { const e: any = new Error(`step ${index + 1} is not runnable from the app: ${v.reason}`); e.code = "not_runnable"; throw e; }
  if (inFlight.has(recId)) { const e: any = new Error("a step of this recommendation is already running"); e.code = "busy"; throw e; }
  inFlight.add(recId);
  try {
    let r: RunResult;
    if (v.via === "sql") r = await executeSql(step.verify_sql!);
    else { const parsed = parseCommand(step.command!) as { ok: true; chains: Chain[] }; r = await execute(parsed.chains, await cliEnv()); }
    const ran = v.via === "sql" ? `steampipe: ${step.verify_sql}` : step.command!;
    const runId = Number(db.prepare("insert into step_runs(recommendation_id, resolution_id, step, command, by_user, exit_code, ms, output) values (?, ?, ?, ?, ?, ?, ?, ?)").run(recId, res!.id, index, ran, by, r.exit_code, r.ms, r.output).lastInsertRowid);
    // the outcome lands on the checklist of this plan; progress on an older plan starts over on this one
    const planKey = `resolution:${res!.id}`;
    const prev = parseProgress(rec.progress);
    const p: Progress = prev && prev.plan === planKey ? prev : { plan: planKey, total: plan.plan.length, done: [], follow_up: null, outcomes: [], updated_at: "" };
    p.total = plan.plan.length;
    p.outcomes = [...p.outcomes.filter((o) => o.step !== index), { step: index, state: r.state, note: clipForNote(`(run #${runId}, ${r.ms} ms, exit ${r.exit_code})\n${r.output}`), at: new Date().toISOString().slice(0, 19).replace("T", " ") }].sort((a, b) => a.step - b.step);
    p.done = r.state === "worked" ? [...new Set([...p.done, index])].sort((a, b) => a - b) : p.done.filter((i) => i !== index);
    p.updated_at = new Date().toISOString().slice(0, 19).replace("T", " ");
    const next = statusAfterProgress(rec.status, p);
    if (next) db.prepare("update recommendations set status = ?, decided_at = datetime('now'), decided_by = ?, progress = ?, updated_at = datetime('now') where id = ?").run(next, by || "ui", JSON.stringify(p), recId);
    else db.prepare("update recommendations set progress = ?, updated_at = datetime('now') where id = ?").run(JSON.stringify(p), recId);
    console.log(`[run] #${recId} step ${index + 1} via ${v.via}: ${r.state} (exit ${r.exit_code}, ${r.ms} ms) by ${by || "ui"}`);
    return { run_id: runId, state: r.state, exit_code: r.exit_code, ms: r.ms, output: r.output, progress: p };
  } finally { inFlight.delete(recId); }
}

export function listRuns(recId: number, limit = 50) {
  return db.prepare("select id, resolution_id, step, command, by_user, exit_code, ms, length(output) as output_chars, created_at from step_runs where recommendation_id = ? order by id desc limit ?").all(recId, limit);
}
export function getRun(id: number) {
  return db.prepare("select * from step_runs where id = ?").get(id) as any;
}

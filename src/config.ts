import "dotenv/config";
import os from "node:os";
import path from "node:path";
import cron from "node-cron";

const port = Number(process.env.PORT || 9034);

/**
 * Two kinds of setting. Bootstrap settings (port, paths, the three shared secrets, the Steampipe connection,
 * the probe document) come from the environment only: the app needs them before the database exists, or they
 * gate what a person can change from the UI. Runtime settings (the agent, Jev, the graph, the schedules, the
 * probe pass) come from the Settings page first, then the environment, then a default: `settings` rows named
 * `cfg:<key>` win, so a value entered in the app survives a restart and needs no env at all. The environment
 * is the seed a deployment (the swarm) can provide; the app owns the rest.
 */
export type RuntimeKind = "string" | "secret" | "url" | "cron" | "number" | "bool" | "enum";
export interface RuntimeSpec { key: string; env: string; kind: RuntimeKind; def: string; group: string; label: string; help: string; options?: readonly string[]; min?: number; max?: number }

export const RUNTIME_SETTINGS: readonly RuntimeSpec[] = [
  { key: "repo2graphUrl", env: "REPO2GRAPH_URL", kind: "url", def: "", group: "Agent", label: "repo2graph URL", help: "The agent runner. Empty = rules only, no agent." },
  { key: "repo2graphToken", env: "REPO2GRAPH_TOKEN", kind: "secret", def: "", group: "Agent", label: "repo2graph token", help: "boltwall's stakwork_secret (x-api-token)." },
  { key: "agentModel", env: "AGENT_MODEL", kind: "string", def: "anthropic/claude-opus-5", group: "Agent", label: "Model", help: "repo2graph's provider/model form: anthropic/claude-opus-5, openai/gpt-5, openrouter/…" },
  { key: "agentApiKey", env: "AGENT_API_KEY", kind: "secret", def: "", group: "Agent", label: "Provider API key", help: "Sent per request, so the agent can use a provider or key repo2graph does not hold. Empty = repo2graph's own key." },
  { key: "agentWebSearch", env: "AGENT_WEB_SEARCH", kind: "bool", def: "false", group: "Agent", label: "Web search", help: "Off by default: a search query is an exfiltration channel for anything a hostile tag or probe line injects into a prompt." },
  { key: "agentAutoDispatch", env: "AGENT_AUTO_DISPATCH", kind: "enum", def: "changes", options: ["changes", "always", "never"], group: "Agent", label: "Send findings after a run", help: "changes = only when the run's diff is not empty." },
  { key: "alertInvestigate", env: "ALERT_INVESTIGATE", kind: "enum", def: "auto", options: ["auto", "manual", "off"], group: "Agent", label: "Investigate alerts", help: "auto = every new NAT alert Jev does not dismiss; manual = the button only; off = refuse." },
  { key: "typesafeApiKey", env: "TYPESAFE_API_KEY", kind: "secret", def: "", group: "Jev (TypeSafe)", label: "API key", help: "Typed decisions: alert triage, resource roles, tier checks, decision scope. Empty = every Jev use is a no-op." },
  { key: "jevModel", env: "JEV_MODEL", kind: "string", def: "jev-latest", group: "Jev (TypeSafe)", label: "Model", help: "" },
  { key: "neo4jUri", env: "NEO4J_URI", kind: "url", def: "", group: "Graph mirror (Neo4j)", label: "Bolt URI", help: "bolt://host:7687. Empty = the mirror is off." },
  { key: "neo4jUser", env: "NEO4J_USER", kind: "string", def: "neo4j", group: "Graph mirror (Neo4j)", label: "User", help: "" },
  { key: "neo4jPassword", env: "NEO4J_PASSWORD", kind: "secret", def: "", group: "Graph mirror (Neo4j)", label: "Password", help: "" },
  { key: "neo4jDatabase", env: "NEO4J_DATABASE", kind: "string", def: "", group: "Graph mirror (Neo4j)", label: "Database", help: "Empty = the server's default database." },
  { key: "runCron", env: "RUN_CRON", kind: "cron", def: "0 6 * * *", group: "Schedules", label: "Collection run", help: "Powerpipe benchmarks, rules, changes. off = disabled." },
  { key: "watchCron", env: "WATCH_CRON", kind: "cron", def: "*/30 * * * *", group: "Schedules", label: "Watcher", help: "Instances, NAT traffic, pools, EBS; raises alerts." },
  { key: "probeCron", env: "PROBE_CRON", kind: "cron", def: "30 5 * * *", group: "Schedules", label: "Probe pass", help: "SSM probes; hourly (5 * * * *) fills the utilisation charts." },
  { key: "spendCron", env: "SPEND_CRON", kind: "cron", def: "15 */6 * * *", group: "Schedules", label: "Spend refresh", help: "Cost Explorer, at most every 6 hours." },
  { key: "logsCron", env: "LOGS_CRON", kind: "cron", def: "50 6 * * *", group: "Schedules", label: "Logs and CloudTrail", help: "Log groups, ingestion, write events (3 to 4 minutes)." },
  { key: "baselineCron", env: "BASELINE_CRON", kind: "cron", def: "40 6 * * *", group: "Schedules", label: "Baselines", help: "What is typical per gateway, instance and service." },
  { key: "reviewCron", env: "REVIEW_CRON", kind: "cron", def: "0 7 * * *", group: "Schedules", label: "Daily review", help: "Reads the statistics back: idle, disks, containers, spend steps." },
  { key: "observeCron", env: "OBSERVE_CRON", kind: "cron", def: "15 7 * * *", group: "Schedules", label: "Morning observation", help: "The agent's read of the day; needs the repo2graph URL." },
  { key: "verifyCron", env: "VERIFY_CRON", kind: "cron", def: "30 7 * * *", group: "Schedules", label: "Saving verification", help: "Approved recommendations checked against the bill, from seven days after the decision." },
  { key: "probeScope", env: "PROBE_SCOPE", kind: "enum", def: "idle", options: ["idle", "all"], group: "Probe pass", label: "Scope", help: "idle = idle candidates and open idle recommendations; all = every SSM-online running instance." },
  { key: "probeMax", env: "PROBE_MAX", kind: "number", def: "25", min: 1, max: 500, group: "Probe pass", label: "Instances per pass", help: "" },
  { key: "probeIdleCpu", env: "PROBE_IDLE_CPU", kind: "number", def: "20", min: 1, max: 100, group: "Probe pass", label: "Idle CPU threshold (%)", help: "Below this 30-day average an instance is a probe candidate (scope idle)." },
  { key: "probeMinIntervalHours", env: "PROBE_MIN_INTERVAL_HOURS", kind: "number", def: "20", min: 0.1, max: 168, group: "Probe pass", label: "Minimum hours between probes", help: "1 for an hourly probe cron, 24 for daily; a five-minute margin is built in so the next scheduled pass is never skipped." },
  { key: "diskWarnPct", env: "DISK_WARN_PCT", kind: "number", def: "80", min: 50, max: 99, group: "Probe pass", label: "Disk warning at (%)", help: "A warning alert when any mount reported by the probe is this full; closes by itself five points below." },
  { key: "diskAlarmPct", env: "DISK_ALARM_PCT", kind: "number", def: "90", min: 60, max: 100, group: "Probe pass", label: "Disk alarm at (%)", help: "An alarm when a mount is this full." },
  { key: "memWarnPct", env: "MEM_WARN_PCT", kind: "number", def: "85", min: 50, max: 99, group: "Probe pass", label: "Memory warning at (%)", help: "Used memory (available subtracted) on a probe." },
  { key: "memAlarmPct", env: "MEM_ALARM_PCT", kind: "number", def: "95", min: 60, max: 100, group: "Probe pass", label: "Memory alarm at (%)", help: "" },
  { key: "swapWarnPct", env: "SWAP_WARN_PCT", kind: "number", def: "25", min: 1, max: 100, group: "Probe pass", label: "Swap in use warning at (%)", help: "Of the swap space; any swap use means memory is short." },
  { key: "loadPerCore", env: "LOAD_PER_CORE", kind: "number", def: "1.5", min: 0.5, max: 10, group: "Probe pass", label: "Load per core, 15 min", help: "The 15-minute load average divided by vCPUs at which the box counts as saturated." },
  { key: "commitmentMinUtilPct", env: "COMMITMENT_MIN_UTIL_PCT", kind: "number", def: "80", min: 1, max: 100, group: "Schedules", label: "Commitment utilisation warning under (%)", help: "Savings Plan or reservation used less than this over 30 days: capacity paid for and not used." },
  { key: "lambdaErrorPct", env: "LAMBDA_ERROR_PCT", kind: "number", def: "5", min: 0.1, max: 100, group: "Probe pass", label: "Lambda error rate warning (%)", help: "Share of invocations that failed over 30 days, for functions with at least 100 invocations; closes at half the threshold." },
  { key: "agentRunsPerHour", env: "AGENT_RUNS_PER_HOUR", kind: "number", def: "6", min: 1, max: 100, group: "Quotas", label: "Agent runs per hour", help: "Findings batches, investigations, resolutions and observations together; each costs a few USD. A hit raises a quota alert and refuses the run." },
  { key: "agentRunsPerDay", env: "AGENT_RUNS_PER_DAY", kind: "number", def: "20", min: 1, max: 500, group: "Quotas", label: "Agent runs per day", help: "" },
  { key: "probesPerHour", env: "PROBES_PER_HOUR", kind: "number", def: "150", min: 1, max: 5000, group: "Quotas", label: "SSM probes per hour", help: "Every probe is one SendCommand on an instance; the hourly pass over the whole fleet is about 60 here." },
];
const SPEC = new Map(RUNTIME_SETTINGS.map((r) => [r.key, r]));

/** Registered by src/db.ts once the settings table exists; until then only the environment is consulted. */
let resolver: (key: string) => string | null = () => null;
export function registerSettingsResolver(fn: (key: string) => string | null): void { resolver = fn; }

const envRaw = (spec: RuntimeSpec) => { const v = process.env[spec.env]; return v === undefined ? null : v; };
/** The raw string for a key: the saved setting, else the environment, else the default. */
export function runtimeRaw(key: string): { value: string; source: "setting" | "env" | "default" } {
  const spec = SPEC.get(key); if (!spec) throw new Error(`unknown runtime setting ${key}`);
  const saved = resolver(key); if (saved != null) return { value: saved, source: "setting" };
  const env = envRaw(spec); if (env != null) return { value: env.trim(), source: "env" };
  return { value: spec.def, source: "default" };
}
const rt = (key: string) => runtimeRaw(key).value;
const rtBool = (key: string) => /^(1|true|yes|on)$/i.test(rt(key));
const rtNum = (key: string) => { const s = SPEC.get(key)!; const n = Number(rt(key)); return Number.isFinite(n) ? n : Number(s.def); };
const rtEnum = <T extends string>(key: string): T => { const s = SPEC.get(key)!; const v = rt(key); return (s.options!.includes(v) ? v : s.def) as T; };

/** Validates a value for a key; returns the normalised string to store, or throws with a message for the UI. */
export function validateRuntime(key: string, value: string): string {
  const spec = SPEC.get(key); if (!spec) throw new Error(`unknown setting ${key}`);
  const v = String(value ?? "").trim();
  switch (spec.kind) {
    case "cron": if (!/^(off|none|false|0)$/i.test(v) && !cron.validate(v)) throw new Error(`"${v}" is not a cron expression (five fields, e.g. "0 6 * * *") or "off"`); return v;
    case "number": { const n = Number(v); if (!Number.isFinite(n)) throw new Error("a number is required"); if (spec.min != null && n < spec.min) throw new Error(`at least ${spec.min}`); if (spec.max != null && n > spec.max) throw new Error(`at most ${spec.max}`); return String(n); }
    case "bool": if (!/^(true|false|1|0|yes|no|on|off)$/i.test(v)) throw new Error("true or false"); return /^(1|true|yes|on)$/i.test(v) ? "true" : "false";
    case "enum": if (!spec.options!.includes(v)) throw new Error(`one of ${spec.options!.join(", ")}`); return v;
    case "url": if (v && !/^(https?|bolt(\+s|\+ssc)?|neo4j(\+s|\+ssc)?):\/\/[^\s]+$/i.test(v)) throw new Error("a URL (http://, https://, bolt:// or neo4j://) or empty"); return v.replace(/\/$/, "");
    default: if (v.length > 500) throw new Error("too long"); return v;
  }
}
export const isSecretSetting = (key: string) => SPEC.get(key)?.kind === "secret";

export const config = {
  port,
  /** Shared secret for the API. Unset = open (local dev only). */
  apiToken: process.env.API_TOKEN || "",
  /** Secret repo2graph must echo back on the agent callback URL. */
  callbackSecret: process.env.CALLBACK_SECRET || "",
  dataDir: process.env.DATA_DIR || path.resolve("data"),
  steampipeUrl: process.env.STEAMPIPE_DATABASE_URL || "postgres://steampipe@127.0.0.1:9193/steampipe",
  steampipeUrlExplicit: Boolean(process.env.STEAMPIPE_DATABASE_URL),
  /** Where the managed <schema>.spc connection file is written. */
  steampipeConfigDir: process.env.STEAMPIPE_CONFIG_DIR || path.join(os.homedir(), ".steampipe", "config"),
  /** Name of the Steampipe connection (and Postgres schema) this app owns. */
  schema: process.env.STEAMPIPE_CONNECTION || "advisor",
  /** Name of the AWS config profile the app manages when a role is assumed (`[profile <name>]`, plus `<name>-source` for pasted keys). */
  advisorAwsProfile: (process.env.ADVISOR_AWS_PROFILE || "aws-advisor-managed").trim(),
  /** AWS shared config file the managed profile is written into (the same file Steampipe's aws plugin and the SDK read). */
  awsConfigFile: process.env.AWS_CONFIG_FILE || path.join(os.homedir(), ".aws", "config"),
  /** AWS shared credentials file pasted keys go into when a role is chained onto them. */
  awsSharedCredentialsFile: process.env.AWS_SHARED_CREDENTIALS_FILE || path.join(os.homedir(), ".aws", "credentials"),
  modDir: process.env.POWERPIPE_MOD_DIR || path.resolve("mod"),
  powerpipeBin: process.env.POWERPIPE_BIN || "powerpipe",
  publicUrl: (process.env.PUBLIC_URL || `http://localhost:${port}`).replace(/\/$/, ""),
  /** Interface to listen on. Unset = every interface (containers reach the host that way); 127.0.0.1 for a laptop with no swarm. */
  bindAddr: (process.env.BIND_ADDR || "").trim(),
  /** Bearer token the MCP fact server at /mcp expects. Unset = open (local dev only). */
  mcpToken: process.env.MCP_TOKEN || "",
  /** SSM document the probe runs through. The custom document embeds the fixed script, so ssm:SendCommand
   *  can be granted on it alone. AWS-RunShellScript runs ANY shell text and is refused outside the tests.
   *  Environment only: it is part of the IAM scoping, not something to change from a browser. */
  probeDocument: (process.env.PROBE_DOCUMENT || "AwsAdvisorProbe").trim(),

  // ---- runtime settings: Settings page, then env, then default (see RUNTIME_SETTINGS) ----
  get repo2graphUrl(): string { return rt("repo2graphUrl").replace(/\/$/, ""); },
  get repo2graphToken(): string { return rt("repo2graphToken"); },
  get agentModel(): string { return rt("agentModel") || "anthropic/claude-opus-5"; },
  get agentApiKey(): string { return rt("agentApiKey"); },
  get agentWebSearch(): boolean { return rtBool("agentWebSearch"); },
  get agentAutoDispatch(): "changes" | "always" | "never" { return rtEnum("agentAutoDispatch"); },
  get alertInvestigate(): "auto" | "manual" | "off" { return rtEnum("alertInvestigate"); },
  get typesafeApiKey(): string { return rt("typesafeApiKey"); },
  get jevModel(): string { return rt("jevModel") || "jev-latest"; },
  get neo4jUri(): string { return rt("neo4jUri"); },
  get neo4jUser(): string { return rt("neo4jUser") || "neo4j"; },
  get neo4jPassword(): string { return rt("neo4jPassword"); },
  get neo4jDatabase(): string { return rt("neo4jDatabase"); },
  get runCron(): string { return rt("runCron"); },
  get watchCron(): string { return rt("watchCron"); },
  get probeCron(): string { return rt("probeCron"); },
  get spendCron(): string { return rt("spendCron"); },
  get logsCron(): string { return rt("logsCron"); },
  get baselineCron(): string { return rt("baselineCron"); },
  get reviewCron(): string { return rt("reviewCron"); },
  get observeCron(): string { return rt("observeCron"); },
  get verifyCron(): string { return rt("verifyCron"); },
  get probeScope(): "idle" | "all" { return rtEnum("probeScope"); },
  get probeMax(): number { return rtNum("probeMax"); },
  get probeIdleCpu(): number { return rtNum("probeIdleCpu"); },
  get probeMinIntervalHours(): number { return rtNum("probeMinIntervalHours"); },
  get diskWarnPct(): number { return rtNum("diskWarnPct"); },
  get memWarnPct(): number { return rtNum("memWarnPct"); },
  get memAlarmPct(): number { return rtNum("memAlarmPct"); },
  get swapWarnPct(): number { return rtNum("swapWarnPct"); },
  get loadPerCore(): number { return rtNum("loadPerCore"); },
  get diskAlarmPct(): number { return rtNum("diskAlarmPct"); },
  get lambdaErrorPct(): number { return rtNum("lambdaErrorPct"); },
  get commitmentMinUtilPct(): number { return rtNum("commitmentMinUtilPct"); },
  get agentRunsPerHour(): number { return rtNum("agentRunsPerHour"); },
  get agentRunsPerDay(): number { return rtNum("agentRunsPerDay"); },
  get probesPerHour(): number { return rtNum("probesPerHour"); },
};

if (!/^[A-Za-z0-9_.:/-]+$/.test(config.probeDocument)) {
  throw new Error(`PROBE_DOCUMENT must be an SSM document name, got "${config.probeDocument}"`);
}
if (/^AWS-RunShellScript$/i.test(config.probeDocument) && process.env.NODE_ENV !== "test") {
  throw new Error("PROBE_DOCUMENT=AWS-RunShellScript is refused: that document runs any shell text, so a leaked credential could run anything on every instance. Create the custom document (GET /api/probe/document, or the setup script) and leave PROBE_DOCUMENT at its default.");
}
const publicHost = (() => { try { return new URL(config.publicUrl).hostname; } catch { return ""; } })();
export const publicUrlIsLocal = publicHost === "localhost" || publicHost === "127.0.0.1" || publicHost === "::1";
if (!publicUrlIsLocal && process.env.NODE_ENV !== "test") {
  const missing = [!config.apiToken && "API_TOKEN", !config.mcpToken && "MCP_TOKEN", !config.callbackSecret && "CALLBACK_SECRET"].filter(Boolean);
  if (missing.length && !/^(1|true|yes)$/i.test(process.env.ALLOW_OPEN_ENDPOINTS || "")) {
    throw new Error(`PUBLIC_URL is ${config.publicUrl}, so the API, /mcp and the agent webhook are reachable from other hosts or containers, but ${missing.join(" and ")} ${missing.length > 1 ? "are" : "is"} not set. Generate them (openssl rand -hex 32), put them in .env and restart; the advisor passes both to repo2graph on every dispatch. Set ALLOW_OPEN_ENDPOINTS=1 only on an isolated machine.`);
  }
}
if (!/^[a-z_][a-z0-9_]*$/.test(config.schema)) {
  throw new Error(`STEAMPIPE_CONNECTION must be a plain identifier, got "${config.schema}"`);
}
if (!/^[A-Za-z0-9_.-]+$/.test(config.advisorAwsProfile)) {
  throw new Error(`ADVISOR_AWS_PROFILE must be an AWS profile name (letters, digits, _ . -), got "${config.advisorAwsProfile}"`);
}

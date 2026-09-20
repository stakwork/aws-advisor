import "dotenv/config";
import os from "node:os";
import path from "node:path";

const port = Number(process.env.PORT || 9034);

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
  repo2graphUrl: (process.env.REPO2GRAPH_URL || "").replace(/\/$/, ""),
  repo2graphToken: process.env.REPO2GRAPH_TOKEN || "",
  publicUrl: (process.env.PUBLIC_URL || `http://localhost:${port}`).replace(/\/$/, ""),
  /** Interface to listen on. Unset = every interface (containers reach the host that way); 127.0.0.1 for a laptop with no swarm. */
  bindAddr: (process.env.BIND_ADDR || "").trim(),
  /** Let the repo2graph agent use web search. Off by default: prices and facts come from the MCP tools, and a search query is an exfiltration channel for anything a hostile tag or probe line injected into the prompt. */
  agentWebSearch: /^(1|true|yes)$/i.test(process.env.AGENT_WEB_SEARCH || ""),
  agentModel: process.env.AGENT_MODEL || "anthropic/claude-opus-5",
  /** Optional: LLM key forwarded per request so a local repo2graph needs no key of its own. */
  agentApiKey: process.env.AGENT_API_KEY || "",
  /** Bearer token the MCP fact server at /mcp expects. Unset = open (local dev only). */
  mcpToken: process.env.MCP_TOKEN || "",
  /** Cron expression for scheduled full runs. "off" disables it. */
  runCron: process.env.RUN_CRON === undefined ? "0 6 * * *" : process.env.RUN_CRON.trim(),
  /** Cron expression for the lightweight watcher (cheap live queries, no Powerpipe/Cost Explorer). "off" disables it. */
  watchCron: process.env.WATCH_CRON === undefined ? "*/30 * * * *" : process.env.WATCH_CRON.trim(),
  /** Automatic SSM probe pass over idle candidates, shortly before the daily run. */
  probeCron: process.env.PROBE_CRON === undefined ? "30 5 * * *" : process.env.PROBE_CRON.trim(),
  probeMax: Number(process.env.PROBE_MAX || 25),
  /** `idle` (default): only idle candidates and open idle recommendations. `all`: every SSM-online running instance. */
  probeScope: (process.env.PROBE_SCOPE || "idle").trim() === "all" ? "all" as const : "idle" as const,
  /** Daily spend refresh (one Cost Explorer call per fetch, skipped when the last one is younger than 6 hours). "off" disables it. */
  spendCron: process.env.SPEND_CRON === undefined ? "15 */6 * * *" : process.env.SPEND_CRON.trim(),
  /** SSM document the probe runs through. AWS-RunShellScript needs no setup but runs any shell; a custom document (GET /api/probe/document) embeds the fixed script so IAM can be scoped to it. */
  /** SSM document the probe runs through. The custom document embeds the fixed script, so ssm:SendCommand
   *  can be granted on it alone. AWS-RunShellScript runs ANY shell text and is only for a throwaway test. */
  probeDocument: (process.env.PROBE_DOCUMENT || "AwsAdvisorProbe").trim(),
  probeIdleCpu: Number(process.env.PROBE_IDLE_CPU || 20),
  /** Daily baseline refresh (NAT bytes, CPU, probes, spend per service). "off" disables it. */
  baselineCron: (process.env.BASELINE_CRON || "40 6 * * *").trim(),
  /** Do not re-probe an instance probed more recently than this (hours). Match it to PROBE_CRON. */
  probeMinIntervalHours: Number(process.env.PROBE_MIN_INTERVAL_HOURS || 20),
  /** After a run: hand findings to repo2graph "always", "never", or only on material "changes" (default). */
  agentAutoDispatch: (["changes", "always", "never"].includes(process.env.AGENT_AUTO_DISPATCH || "") ? process.env.AGENT_AUTO_DISPATCH : "changes") as "changes" | "always" | "never",
  /** Watcher alerts: "auto" investigates every new nat_traffic alert with the agent (when REPO2GRAPH_URL is set), "manual" only on the button or the API, "off" refuses investigations. */
  alertInvestigate: (["auto", "manual", "off"].includes(process.env.ALERT_INVESTIGATE || "") ? process.env.ALERT_INVESTIGATE : "auto") as "auto" | "manual" | "off",
  /** TypeSafe (Jev) API key for typed decisions: alert triage, resource roles, tier checks. Unset = every Jev use is a no-op. */
  typesafeApiKey: (process.env.TYPESAFE_API_KEY || "").trim(),
  /** Jev model name sent with every systemOne call. */
  jevModel: (process.env.JEV_MODEL || "jev-latest").trim(),
  /** Neo4j the operational data is mirrored into (one way, see src/graph_mirror.ts). Unset = the mirror is off and every mirror call is a no-op. */
  neo4jUri: (process.env.NEO4J_URI || "").trim(),
  neo4jUser: (process.env.NEO4J_USER || "neo4j").trim(),
  neo4jPassword: process.env.NEO4J_PASSWORD || "",
  /** Optional database name (Neo4j Enterprise / multi-database); unset = the server's default database. */
  neo4jDatabase: (process.env.NEO4J_DATABASE || "").trim(),
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
if (config.probeDocument === "AWS-RunShellScript") {
  console.warn("PROBE_DOCUMENT=AWS-RunShellScript lets whoever holds the advisor's credentials run any command on any instance. Use the custom AwsAdvisorProbe document (the default) outside throwaway tests.");
}

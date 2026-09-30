import "dotenv/config";
import os from "node:os";
import path from "node:path";
import cron from "node-cron";
import { ROLE_ARN_RE } from "./aws_config.js";
import { DEFAULT_SIGNALS_STRING, parseSignals, serialiseSignals } from "./signals.js";

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
  { key: "complianceCron", env: "COMPLIANCE_CRON", kind: "cron", def: "20 6 * * *", group: "Schedules", label: "Security scan", help: "aws_compliance benchmarks (FSBP by default, under a minute), security findings and recommendations. off = disabled." },
  { key: "watchCron", env: "WATCH_CRON", kind: "cron", def: "*/30 * * * *", group: "Schedules", label: "Watcher", help: "Instances, NAT traffic, pools, EBS; raises alerts." },
  { key: "probeCron", env: "PROBE_CRON", kind: "cron", def: "30 5 * * *", group: "Schedules", label: "Probe pass", help: "SSM probes and the RDS load profiles; hourly (5 * * * *) fills the utilisation charts." },
  { key: "spendCron", env: "SPEND_CRON", kind: "cron", def: "15 */6 * * *", group: "Schedules", label: "Spend refresh", help: "Cost Explorer, at most every 6 hours." },
  { key: "logsCron", env: "LOGS_CRON", kind: "cron", def: "50 6 * * *", group: "Schedules", label: "Logs and CloudTrail", help: "Log groups, ingestion, write events (3 to 4 minutes)." },
  { key: "baselineCron", env: "BASELINE_CRON", kind: "cron", def: "40 6 * * *", group: "Schedules", label: "Baselines", help: "What is typical per gateway, instance and service." },
  { key: "reviewCron", env: "REVIEW_CRON", kind: "cron", def: "0 7 * * *", group: "Schedules", label: "Daily review", help: "Reads the statistics back: idle, disks, containers, spend steps." },
  { key: "observeCron", env: "OBSERVE_CRON", kind: "cron", def: "15 7 * * *", group: "Schedules", label: "Morning observation", help: "The agent's read of the day; needs the repo2graph URL." },
  { key: "verifyCron", env: "VERIFY_CRON", kind: "cron", def: "30 7 * * *", group: "Schedules", label: "Saving verification", help: "Approved and done recommendations checked against the bill, from seven days after the decision; the impact chart comes from it." },
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
  { key: "probeSignals", env: "PROBE_SIGNALS", kind: "string", def: DEFAULT_SIGNALS_STRING, group: "Probe pass", label: "Use-signal patterns", help: "name=regex entries joined by ;; (POSIX ERE, case-insensitive), matched against each container's log by the probe; the names are the kinds the drawer chips and the rules speak of. Passed to the SSM document as its signals parameter on every probe, so no document update is needed to revise them. Which kinds count per image is decided by the rules in the EC2 drawer." },
  { key: "commitmentMinUtilPct", env: "COMMITMENT_MIN_UTIL_PCT", kind: "number", def: "80", min: 1, max: 100, group: "Schedules", label: "Commitment utilisation warning under (%)", help: "Savings Plan or reservation used less than this over 30 days: capacity paid for and not used." },
  { key: "lambdaErrorPct", env: "LAMBDA_ERROR_PCT", kind: "number", def: "5", min: 0.1, max: 100, group: "Probe pass", label: "Lambda error rate warning (%)", help: "Share of invocations that failed over 30 days, for functions with at least 100 invocations; closes at half the threshold." },
  { key: "sphinxBotUrl", env: "SPHINX_BOT_URL", kind: "url", def: "", group: "Notifications (Sphinx)", label: "Bot endpoint", help: "The swarm's bot URL the broadcast is posted to (the same one Hive and the swarm checker use). Empty = notifications off." },
  { key: "sphinxBotId", env: "SPHINX_BOT_ID", kind: "string", def: "", group: "Notifications (Sphinx)", label: "Bot id", help: "" },
  { key: "sphinxBotSecret", env: "SPHINX_BOT_SECRET", kind: "secret", def: "", group: "Notifications (Sphinx)", label: "Bot secret", help: "Never logged; sent only to the bot endpoint." },
  { key: "sphinxChatPubkey", env: "SPHINX_CHAT_PUBKEY", kind: "string", def: "", group: "Notifications (Sphinx)", label: "Chat pubkey", help: "The tribe or chat the bot posts into." },
  { key: "notifyLevel", env: "NOTIFY_LEVEL", kind: "enum", def: "alarm", options: ["alarm", "warning", "off"], group: "Notifications (Sphinx)", label: "Send from level", help: "alarm = alarms only; warning = alarms and warnings; off = nothing is sent (the test button still works)." },
  { key: "notifyScope", env: "NOTIFY_SCOPE", kind: "enum", def: "watched", options: ["watched", "all"], group: "Notifications (Sphinx)", label: "Resources", help: "watched = alerts on resources marked watched (by hand, an advisor:watch tag, a database, a Route 53 record reaching it, or protected per Jev) plus account-level alerts; all = every alert at the level." },
  { key: "notifyLinkUrl", env: "NOTIFY_LINK_URL", kind: "url", def: "", group: "Notifications (Sphinx)", label: "Link base for messages", help: "The address people open the advisor at, used only for the links in chat messages, e.g. http://10.0.1.23:9034 when the app is reached over the VPN by private IP. Empty = PUBLIC_URL (which is also what repo2graph calls back to, so leave that one alone)." },
  { key: "notifyRecommendations", env: "NOTIFY_RECOMMENDATIONS", kind: "enum", def: "on", options: ["on", "off"], group: "Notifications (Sphinx)", label: "Recommendation events", help: "on = approvals, rejections, items marked done and measured savings are posted (quiet hours defer them to the next dispatch); off = alerts only. \"Send to Sphinx\" on a recommendation always works." },
  { key: "notifyQuietHours", env: "NOTIFY_QUIET_HOURS", kind: "string", def: "", group: "Notifications (Sphinx)", label: "Quiet hours", help: "HH-HH in the server's local time, e.g. 22-07: warnings wait until the morning's next dispatch, alarms still go. Empty = none." },
  { key: "actMode", env: "ACT_MODE", kind: "enum", def: "dry_run", options: ["off", "dry_run", "apply"], group: "Auto-actions", label: "Mode", help: "off = the executor never runs; dry_run = every pass records what it would change and touches nothing; apply = changes are made under the actuator role. Applying one row by hand from the Auto-actions page works in dry_run too." },
  { key: "actRoleArn", env: "ACT_ROLE_ARN", kind: "string", def: "", group: "Auto-actions", label: "Actuator role ARN", help: "The only identity that ever changes AWS: a role with the actuator policy (Auto-actions page), assumed from the advisor's read credentials. Empty = nothing can be applied." },
  { key: "actCron", env: "ACT_CRON", kind: "cron", def: "45 * * * *", group: "Auto-actions", label: "Executor pass", help: "Hourly by default, fifteen minutes before the hour, so a capacity change is in place before the hour it is for. off = disabled." },
  { key: "actAcuFloor", env: "ACT_ACU_FLOOR", kind: "number", def: "0.5", min: 0.5, max: 64, group: "Auto-actions", label: "Lowest Serverless v2 minimum (ACU)", help: "The executor moves a cluster's minimum capacity between this floor and the minimum you configured; it never goes below this, never above yours, and never touches the maximum." },
  { key: "actMaxPerPass", env: "ACT_MAX_PER_PASS", kind: "number", def: "10", min: 1, max: 200, group: "Auto-actions", label: "Changes per pass", help: "At most this many changes in one pass, across every action." },
  { key: "actLogRetentionDays", env: "ACT_LOG_RETENTION_DAYS", kind: "number", def: "90", min: 1, max: 3653, group: "Auto-actions", label: "Retention for log groups without one (days)", help: "Put on every group that has no retention policy (snapped to a value CloudWatch accepts). An existing retention is never lowered. Events older than this are purged, so keep it long." },
  { key: "actS3MinGb", env: "ACT_S3_MIN_GB", kind: "number", def: "20", min: 1, max: 100000, group: "Auto-actions", label: "S3 buckets analysed from (GB)", help: "Buckets at or above this get a lifecycle analysis (Inventory › S3, recommendations); the executor proposes request metrics on those where the cold Standard bytes could pay for them." },
  { key: "actSnapshotMinAgeDays", env: "ACT_SNAPSHOT_MIN_AGE_DAYS", kind: "number", def: "90", min: 30, max: 3650, group: "Auto-actions", label: "Archive snapshots older than (days)", help: "EBS snapshots at least this old, whose volume is gone or that are the only snapshot of their volume, move to the Archive tier (a quarter of the price, 24 to 72 hours to restore)." },
  { key: "actEcrUntaggedDays", env: "ACT_ECR_UNTAGGED_DAYS", kind: "number", def: "30", min: 1, max: 365, group: "Auto-actions", label: "Expire untagged ECR images after (days)", help: "Repositories with no lifecycle policy get one that expires untagged images older than this. Tagged images are never touched. An image deleted by the policy does not come back when the policy is removed." },
  { key: "actParkIdleDays", env: "ACT_PARK_IDLE_DAYS", kind: "number", def: "7", min: 2, max: 60, group: "Auto-actions", label: "Park a swarm after (idle days)", help: "An instance tagged advisor:park=auto is stopped (never terminated) once every use signal from the probe has been quiet for this many consecutive days. Any signal, or a missing probe, keeps it running." },
  { key: "actDeleteGraceHours", env: "ACT_DELETE_GRACE_HOURS", kind: "number", def: "24", min: 0, max: 168, group: "Auto-actions", label: "Announce an irreversible change this long before (hours)", help: "An approved Elastic IP release, snapshot deletion, load balancer deletion or KMS key retirement is announced in the Sphinx chat when first proposed; the pass waits this long before doing it so anyone can object. Apply on the page does not wait." },
  { key: "actKmsPendingDays", env: "ACT_KMS_PENDING_DAYS", kind: "number", def: "30", min: 7, max: 30, group: "Auto-actions", label: "KMS key deletion waiting period (days)", help: "A retired key is scheduled for deletion, never deleted outright: KMS keeps it for this many days, during which Revert (CancelKeyDeletion) brings it back intact." },
  { key: "actAlarmStaleDays", env: "ACT_ALARM_STALE_DAYS", kind: "number", def: "30", min: 7, max: 365, group: "Auto-actions", label: "Delete alarms in INSUFFICIENT_DATA after (days)", help: "A metric alarm whose resource no longer exists and that has had no data for this long is deleted; its definition is kept on the row so Revert recreates it." },
  { key: "actLogQuietDays", env: "ACT_LOG_QUIET_DAYS", kind: "number", def: "90", min: 30, max: 365, group: "Auto-actions", label: "Shorten log retention after this long unqueried (days)", help: "Only for groups whose retention the executor itself set: when the recorded Logs Insights history shows nobody queried the group for this long, the retention drops to the value below. A retention a person set is never touched." },
  { key: "actLogQuietRetentionDays", env: "ACT_LOG_QUIET_RETENTION_DAYS", kind: "number", def: "30", min: 1, max: 3653, group: "Auto-actions", label: "Retention for unqueried log groups (days)", help: "What an unqueried group's retention is lowered to (snapped to a value CloudWatch accepts). Events older than this are purged, so keep it long enough for an incident." },
  { key: "actEfsIaDays", env: "ACT_EFS_IA_DAYS", kind: "number", def: "30", min: 7, max: 90, group: "Auto-actions", label: "EFS files move to Infrequent Access after (days)", help: "File systems with no lifecycle policy get one: files not read for this many days move to IA (a twentieth of the price) and come back to Standard on their first read. Snapped to a value EFS accepts (7, 14, 30, 60, 90)." },
  { key: "tagKeysRequired", env: "TAG_KEYS_REQUIRED", kind: "string", def: "owner,env", group: "Inventory", label: "Required tags", help: "Comma-separated tag keys every resource should carry; Inventory › Tags lists what lacks them with a suggested value. Aliases count: Environment or stage for env, team or maintainer for owner. The advisor never writes a tag." },
  { key: "actMultipartDays", env: "ACT_MULTIPART_DAYS", kind: "number", def: "7", min: 1, max: 90, group: "Auto-actions", label: "Abort incomplete multipart uploads after (days)", help: "Every bucket gets a lifecycle rule that aborts multipart uploads not completed within this many days: their parts are billed as Standard storage and never listed. An upload still in progress past this is aborted too, so keep it longer than your slowest upload." },
  { key: "actLambdaMinInvocations", env: "ACT_LAMBDA_MIN_INVOCATIONS", kind: "number", def: "1000", min: 1, max: 100000000, group: "Auto-actions", label: "Lambda memory right-sizing from (invocations in 14 days)", help: "Functions with fewer invocations in the window are not worth a recommendation: the REPORT lines are too few to trust the peak memory." },
  { key: "actJevCheck", env: "ACT_JEV_CHECK", kind: "enum", def: "hold", options: ["off", "advise", "hold"], group: "Auto-actions", label: "Jev second opinion on proposals", help: "Every new proposal is shown to Jev once (how irreversible, how visible, does it fit what the team decided). advise = the verdict is recorded on the row; hold = a proposal Jev objects to waits for a person (Apply on the page still works); off = no check. A refreshed proposal keeps its first verdict." },
  { key: "actNarrate", env: "ACT_NARRATE", kind: "enum", def: "changes", options: ["off", "changes", "always"], group: "Auto-actions", label: "Narrate the pass (agent)", help: "After a pass the agent writes the short version for Sphinx and the page: what happens next, what waits on approval, what was left alone and why. changes = only when the pass differs from the last narrated one; always = every scheduled pass; off = never." },
  { key: "actEbLowCpu", env: "ACT_EB_LOW_CPU", kind: "number", def: "30", min: 5, max: 90, group: "Auto-actions", label: "Beanstalk floor cut under (p95 CPU %)", help: "An environment tagged advisor:scale whose group sat at its minimum for 90 % of the last 14 days with the hourly average CPU under this (p95) gets its MinSize lowered by one, never below the tag's floor." },
  { key: "actEbHighCpu", env: "ACT_EB_HIGH_CPU", kind: "number", def: "70", min: 10, max: 100, group: "Auto-actions", label: "Beanstalk ceiling raise from (CPU %)", help: "An hour pinned at MaxSize with the group's average CPU at or above this counts as pressure." },
  { key: "actEbTargetCpu", env: "ACT_EB_TARGET_CPU", kind: "number", def: "60", min: 10, max: 95, group: "Auto-actions", label: "Beanstalk learned week: CPU per member (%)", help: "The learned week sizes each hour so the group's average CPU would sit at about this: an hour that ran 6 members at 20 % needed 2 at 60 %. Lower keeps more headroom and more machines." },
  { key: "actEbTargetMem", env: "ACT_EB_TARGET_MEM", kind: "number", def: "75", min: 20, max: 95, group: "Auto-actions", label: "Beanstalk learned week: memory per member (%)", help: "The same for memory, counted above the members' idle footprint (the lowest memory the group shows): only the part that grows with load is spread over more or fewer machines. Needs the CloudWatch agent (mem_used_percent) or the probe on the members." },
  { key: "actEbHighMem", env: "ACT_EB_HIGH_MEM", kind: "number", def: "90", min: 30, max: 100, group: "Auto-actions", label: "Beanstalk ceiling raise from (memory %)", help: "Pinned at MaxSize with the members' average memory at or above this counts as pressure, like the CPU line. Needs the CloudWatch agent (mem_used_percent) on the members." },
  { key: "actEbHighDisk", env: "ACT_EB_HIGH_DISK", kind: "number", def: "85", min: 30, max: 100, group: "Auto-actions", label: "Beanstalk learned week: disk hold from (%)", help: "An hour in which a member's fullest disk was at or above this never learns fewer machines than it ran: more members do not empty a disk, but fewer would concentrate what fills it. The pass notes say which disk." },
  { key: "actPressureCron", env: "ACT_PRESSURE_CRON", kind: "cron", def: "*/10 * * * *", group: "Auto-actions", label: "Pressure check", help: "How often the executor looks for a Beanstalk group pinned at its MaxSize with high CPU and raises the ceiling by one within its AdvisorScaleBand, applied at once. Every ten minutes by default. off = disabled." },
  { key: "actEbPressureHours", env: "ACT_EB_PRESSURE_HOURS", kind: "number", def: "3", min: 1, max: 336, group: "Auto-actions", label: "Beanstalk ceiling raise after (pressure hours in 14 days)", help: "This many pressure hours in the window raise MaxSize by one, never above the tag's ceiling. Raising the ceiling adds cost." },
  { key: "usageLogDays", env: "USAGE_LOG_DAYS", kind: "number", def: "7", min: 0, max: 28, group: "Probe pass", label: "Usage: scan shipped logs for use signals (days)", help: "The usage profile runs one Logs Insights query per box over the CloudWatch log groups it ships to, counting the use-signal lines per hour (the same patterns as the probe, after the per-image noise rules), over this many days. Log evidence for every hour, not only the probed ones. 0 = off. Cost: the scan, about 0.005 USD per GB." },
  { key: "usageMinOffHours", env: "USAGE_MIN_OFF_HOURS", kind: "number", def: "4", min: 1, max: 24, group: "Auto-actions", label: "Shortest stop worth making (hours)", help: "A quiet stretch shorter than this, margins taken, is not a window: a box off for twenty minutes saves nothing and costs a restart. The usage agent may set a different number for one box when the evidence supports it (a slow boot, a DNS TTL); the profile and the office-hours action then use that number for the box." },
  { key: "usageAgentMaxPerDay", env: "USAGE_AGENT_MAX_PER_DAY", kind: "number", def: "5", min: 0, max: 50, group: "Quotas", label: "Usage investigations per day (agent)", help: "Boxes whose usage review is not sure (Jev unsure of its pick, or in two minds about the quiet windows) are handed to the agent, which reads the box with the tools and decides; at most this many a day. 0 = never." },
  { key: "actParkGraceHours", env: "ACT_PARK_GRACE_HOURS", kind: "number", def: "24", min: 0, max: 168, group: "Auto-actions", label: "Announce a parking this long before (hours)", help: "A swarm about to be parked is announced in the Sphinx chat when first proposed; the pass waits this long before stopping it so anyone can object. Apply on the page does not wait." },
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
    default:
      if (key === "notifyQuietHours" && v && !/^([01]?\d|2[0-3])-([01]?\d|2[0-3])$/.test(v)) throw new Error('HH-HH, e.g. "22-07", or empty');
      if (key === "actRoleArn" && v && (!ROLE_ARN_RE.test(v) || /\s/.test(v))) throw new Error("arn:aws:iam::<12 digits>:role/<name>, or empty");
      if (key === "probeSignals") return serialiseSignals(parseSignals(v));
      if (v.length > 500) throw new Error("too long"); return v;
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
  get sphinxBotUrl(): string { return rt("sphinxBotUrl"); },
  get sphinxBotId(): string { return rt("sphinxBotId"); },
  get sphinxBotSecret(): string { return rt("sphinxBotSecret"); },
  get sphinxChatPubkey(): string { return rt("sphinxChatPubkey"); },
  get notifyLevel(): "alarm" | "warning" | "off" { return rtEnum("notifyLevel"); },
  get notifyScope(): "watched" | "all" { return rtEnum("notifyScope"); },
  get notifyQuietHours(): string { return rt("notifyQuietHours"); },
  get notifyRecommendations(): "on" | "off" { return rtEnum("notifyRecommendations"); },
  /** Base for the links in chat messages: the link setting when set, else PUBLIC_URL. */
  get notifyLinkUrl(): string { return (rt("notifyLinkUrl") || this.publicUrl).replace(/\/$/, ""); },
  get runCron(): string { return rt("runCron"); },
  get complianceCron(): string { return rt("complianceCron"); },
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
  get actMode(): "off" | "dry_run" | "apply" { return rtEnum("actMode"); },
  get actRoleArn(): string { return rt("actRoleArn"); },
  get actCron(): string { return rt("actCron"); },
  get actPressureCron(): string { return rt("actPressureCron"); },
  get actAcuFloor(): number { return rtNum("actAcuFloor"); },
  get actMaxPerPass(): number { return rtNum("actMaxPerPass"); },
  get actSnapshotMinAgeDays(): number { return rtNum("actSnapshotMinAgeDays"); },
  get actLogRetentionDays(): number { return rtNum("actLogRetentionDays"); },
  get actS3MinGb(): number { return rtNum("actS3MinGb"); },
  get actEcrUntaggedDays(): number { return rtNum("actEcrUntaggedDays"); },
  get actParkIdleDays(): number { return rtNum("actParkIdleDays"); },
  get actParkGraceHours(): number { return rtNum("actParkGraceHours"); },
  get usageLogDays(): number { return rtNum("usageLogDays"); },
  get usageMinOffHours(): number { return rtNum("usageMinOffHours"); },
  get usageAgentMaxPerDay(): number { return rtNum("usageAgentMaxPerDay"); },
  get actEbLowCpu(): number { return rtNum("actEbLowCpu"); },
  get actEbHighCpu(): number { return rtNum("actEbHighCpu"); },
  get actEbPressureHours(): number { return rtNum("actEbPressureHours"); },
  get actEbTargetCpu(): number { return rtNum("actEbTargetCpu"); },
  get actEbTargetMem(): number { return rtNum("actEbTargetMem"); },
  get actEbHighMem(): number { return rtNum("actEbHighMem"); },
  get actEbHighDisk(): number { return rtNum("actEbHighDisk"); },
  get actDeleteGraceHours(): number { return rtNum("actDeleteGraceHours"); },
  get actKmsPendingDays(): number { return rtNum("actKmsPendingDays"); },
  get actAlarmStaleDays(): number { return rtNum("actAlarmStaleDays"); },
  get actLogQuietDays(): number { return rtNum("actLogQuietDays"); },
  get actLogQuietRetentionDays(): number { return rtNum("actLogQuietRetentionDays"); },
  get actEfsIaDays(): number { return rtNum("actEfsIaDays"); },
  get actMultipartDays(): number { return rtNum("actMultipartDays"); },
  get tagKeysRequired(): string { return rt("tagKeysRequired"); },
  get actJevCheck(): "off" | "advise" | "hold" { return rtEnum("actJevCheck"); },
  get actNarrate(): "off" | "changes" | "always" { return rtEnum("actNarrate"); },
  get actLambdaMinInvocations(): number { return rtNum("actLambdaMinInvocations"); },
  /** The use-signal patterns as the probe takes them (validated; the default list when the saved value is broken). */
  get probeSignals(): string { try { return serialiseSignals(parseSignals(rt("probeSignals"))); } catch { return DEFAULT_SIGNALS_STRING; } },
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

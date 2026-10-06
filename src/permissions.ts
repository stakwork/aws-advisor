import { config } from "./config.js";
import { db, addColumn } from "./db.js";

/**
 * Permission diagnostics. Every place the app catches an AWS error runs it through
 * explainPermissionError: when the error is an IAM authorization failure (as Steampipe, the AWS SDK or
 * Powerpipe surface it) the missing action is worked out, recorded in `permission_issues`, and the log
 * line or API error gets a one-line remedy pointing at Settings > Permissions, where the merged IAM
 * policy that fixes everything seen so far can be copied. This module only depends on the database so
 * steampipe.ts, ssm.ts and the rest can import it without cycles; the live capability check that uses
 * Steampipe and the SSM SDK lives in permission_check.ts.
 */

export interface IamStatement {
  Sid: string;
  Effect: "Allow" | "Deny";
  Action: string[];
  Resource: string | string[];
  Condition?: Record<string, Record<string, string | string[]>>;
}

export interface IamPolicy { Version: "2012-10-17"; Statement: IamStatement[] }

export interface PermissionIssue {
  /** IAM action, `ec2:DescribeInstances` style; "unknown" when neither the message nor the context names one. */
  action: string;
  /** IAM service prefix (ec2, ce, ssm...). */
  service: string;
  /** The resource ARN the denial named, when it did. */
  resource?: string;
  /** Where in the app it happened (benchmark, query, table, tool...). */
  context: string;
  /** The original error message, trimmed. */
  message: string;
  /** One IAM statement that allows the action. */
  policy_statement: IamStatement;
}

export interface PermissionIssueRow {
  action: string;
  service: string;
  contexts: string[];
  /** The accounts the denial was seen in (from the identity ARN, the member's connection name or an "account <id>" in the context); empty when none was named. */
  accounts: string[];
  first_seen: string;
  last_seen: string;
  count: number;
  last_message: string | null;
}

db.exec(`
create table if not exists permission_issues (
  action text primary key,
  service text not null,
  contexts text not null default '[]',
  first_seen text not null default (datetime('now')),
  last_seen text not null default (datetime('now')),
  count integer not null default 1,
  last_message text
);`);

addColumn("permission_issues", "accounts", "text");

/** The 12-digit account ids a denial names: the caller's identity ARN, a member's Steampipe connection (advisor_<id>), or "account <id>" / "member <id>" in the context. Pure. */
export function accountsIn(text: string): string[] {
  const out = new Set<string>();
  for (const re of [/arn:aws:(?:sts|iam)::(\d{12}):/g, /\badvisor_(\d{12})\b/g, /\b(?:account|member)\s+(\d{12})\b/gi]) for (const m of text.matchAll(re)) out.add(m[1]);
  return [...out];
}

export const AWS_RUN_SHELL_SCRIPT = "AWS-RunShellScript";
export const EC2_ANY_INSTANCE = "arn:aws:ec2:*:*:instance/*";
/** Whether the probe runs through a custom document (the script embedded, so SendCommand can be scoped to it) or the stock one. */
export const usesCustomProbeDocument = () => config.probeDocument !== AWS_RUN_SHELL_SCRIPT;
/** Name of the document the policy should grant SendCommand on: always a custom, script-embedding document. */
export const RECOMMENDED_PROBE_DOCUMENT = "AwsAdvisorProbe";
export const policyProbeDocument = () => (usesCustomProbeDocument() ? config.probeDocument : RECOMMENDED_PROBE_DOCUMENT);
/**
 * ARN used in every generated policy. Deliberately never AWS-RunShellScript: that document executes whatever
 * text it is sent, so granting SendCommand on it hands out root on every instance to whoever holds the key.
 * When the stock document is configured, the policy still names the custom one and the permission check warns.
 */
/** One ARN pattern covers the per-kind documents (AwsAdvisorProbe-host, -docker, -apps, -software; src/probes.ts) and the pre-2.0 combined one. */
export const probeDocumentArn = (accountId = "*") => `arn:aws:ssm:*:${accountId}:document/${policyProbeDocument()}*`;

/** Steampipe table -> the IAM action its List/Describe call needs (only the tables this app and its benchmarks use). */
export const TABLE_ACTIONS: Record<string, string> = {
  aws_account: "iam:ListAccountAliases",
  aws_iam_role: "iam:ListRoles",
  aws_region: "ec2:DescribeRegions",
  aws_ec2_instance: "ec2:DescribeInstances",
  aws_ec2_instance_metric_cpu_utilization_daily: "cloudwatch:GetMetricStatistics",
  aws_ec2_reserved_instance: "ec2:DescribeReservedInstances",
  aws_ec2_ami: "ec2:DescribeImages",
  aws_ec2_ami_shared: "ec2:DescribeImages",
  aws_ec2_launch_template_version: "ec2:DescribeLaunchTemplateVersions",
  aws_ec2_target_group: "elasticloadbalancing:DescribeTargetGroups",
  aws_vpc_security_group_rule: "ec2:DescribeSecurityGroupRules",
  aws_ec2_application_load_balancer: "elasticloadbalancing:DescribeLoadBalancers",
  aws_ec2_network_load_balancer: "elasticloadbalancing:DescribeLoadBalancers",
  aws_ec2_gateway_load_balancer: "elasticloadbalancing:DescribeLoadBalancers",
  aws_ec2_classic_load_balancer: "elasticloadbalancing:DescribeLoadBalancers",
  aws_ec2_load_balancer_listener: "elasticloadbalancing:DescribeListeners",
  aws_ec2_autoscaling_group: "autoscaling:DescribeAutoScalingGroups",
  aws_ebs_volume: "ec2:DescribeVolumes",
  aws_ebs_volume_metric_read_ops_daily: "cloudwatch:GetMetricStatistics",
  aws_ebs_volume_metric_write_ops_daily: "cloudwatch:GetMetricStatistics",
  aws_ebs_snapshot: "ec2:DescribeSnapshots",
  aws_vpc: "ec2:DescribeVpcs",
  aws_vpc_subnet: "ec2:DescribeSubnets",
  aws_vpc_eip: "ec2:DescribeAddresses",
  aws_ec2_network_interface: "ec2:DescribeNetworkInterfaces",
  aws_vpc_nat_gateway: "ec2:DescribeNatGateways",
  aws_vpc_nat_gateway_metric_bytes_out_to_destination: "cloudwatch:GetMetricStatistics",
  aws_vpc_flow_log: "ec2:DescribeFlowLogs",
  aws_vpc_endpoint: "ec2:DescribeVpcEndpoints",
  aws_cloudwatch_log_group: "logs:DescribeLogGroups",
  aws_cloudtrail_lookup_event: "cloudtrail:LookupEvents",
  ce_savings_plans_utilization: "ce:GetSavingsPlansUtilization",
  ce_reservation_utilization: "ce:GetReservationUtilization",
  aws_ecr_registry: "ecr:DescribeRegistry",
  aws_cloudwatch_log_stream: "logs:DescribeLogStreams",
  aws_cloudwatch_metric_statistic_data_point: "cloudwatch:GetMetricStatistics",
  aws_cloudwatch_metric_data_point: "cloudwatch:GetMetricData",
  aws_cloudwatch_metric: "cloudwatch:ListMetrics",
  aws_rds_db_instance: "rds:DescribeDBInstances",
  aws_rds_db_instance_metric_cpu_utilization_daily: "cloudwatch:GetMetricStatistics",
  aws_rds_db_instance_metric_connections_daily: "cloudwatch:GetMetricStatistics",
  aws_rds_db_cluster: "rds:DescribeDBClusters",
  aws_rds_db_snapshot: "rds:DescribeDBSnapshots",
  aws_rds_reserved_db_instance: "rds:DescribeReservedDBInstances",
  aws_elasticache_cluster: "elasticache:DescribeCacheClusters",
  aws_elasticache_replication_group: "elasticache:DescribeReplicationGroups",
  aws_elasticache_reserved_cache_node: "elasticache:DescribeReservedCacheNodes",
  aws_savingsplans_savings_plan: "savingsplans:DescribeSavingsPlans",
  aws_cost_by_record_type_monthly: "ce:GetCostAndUsage",
  aws_cost_by_record_type_daily: "ce:GetCostAndUsage",
  aws_cost_by_service_daily: "ce:GetCostAndUsage",
  aws_cost_by_service_monthly: "ce:GetCostAndUsage",
  aws_cost_by_service_usage_type_monthly: "ce:GetCostAndUsage",
  aws_cost_by_resource_daily: "ce:GetCostAndUsageWithResources",
  aws_cost_usage: "ce:GetCostAndUsage",
  aws_pricing_product: "pricing:GetProducts",
  aws_ssm_managed_instance: "ssm:DescribeInstanceInformation",
  aws_s3_bucket: "s3:ListAllMyBuckets",
  aws_lambda_function: "lambda:ListFunctions",
  aws_lambda_function_metric_invocations_daily: "cloudwatch:GetMetricStatistics",
  aws_lambda_function_metric_errors_daily: "cloudwatch:GetMetricStatistics",
  aws_lambda_function_metric_duration_daily: "cloudwatch:GetMetricStatistics",
  aws_ecr_repository: "ecr:DescribeRepositories",
  aws_ecr_image: "ecr:DescribeImages",
  aws_ecs_cluster: "ecs:DescribeClusters",
  aws_ecs_cluster_metric_cpu_utilization_daily: "cloudwatch:GetMetricStatistics",
  aws_ecs_service: "ecs:DescribeServices",
  aws_ecs_container_instance: "ecs:DescribeContainerInstances",
  aws_eks_cluster: "eks:DescribeCluster",
  aws_eks_node_group: "eks:DescribeNodegroup",
  aws_dynamodb_table: "dynamodb:DescribeTable",
  aws_appautoscaling_target: "application-autoscaling:DescribeScalableTargets",
  aws_secretsmanager_secret: "secretsmanager:ListSecrets",
  aws_cloudtrail_trail: "cloudtrail:DescribeTrails",
  aws_cloudfront_distribution: "cloudfront:ListDistributions",
  aws_route53_zone: "route53:ListHostedZones",
  aws_route53_record: "route53:ListResourceRecordSets",
  aws_route53_health_check: "route53:ListHealthChecks",
  aws_elastic_beanstalk_environment: "elasticbeanstalk:DescribeEnvironments",
  aws_redshift_cluster: "redshift:DescribeClusters",
  aws_redshift_cluster_metric_cpu_utilization_daily: "cloudwatch:GetMetricStatistics",
  aws_emr_cluster: "elasticmapreduce:ListClusters",
  aws_emr_instance_group: "elasticmapreduce:ListInstanceGroups",
  aws_emr_cluster_metric_is_idle: "cloudwatch:GetMetricStatistics",
  aws_api_gateway_stage: "apigateway:GET",
  aws_api_gateway_domain_name: "apigateway:GET",
  aws_api_gatewayv2_domain_name: "apigateway:GET",
  aws_tagging_resource: "tag:GetResources",
  // the platform services inventory (src/services/)
  aws_acm_certificate: "acm:ListCertificates",
  aws_athena_workgroup: "athena:ListWorkGroups",
  aws_backup_vault: "backup:ListBackupVaults",
  aws_backup_plan: "backup:ListBackupPlans",
  aws_backup_selection: "backup:ListBackupSelections",
  aws_backup_protected_resource: "backup:ListProtectedResources",
  aws_backup_recovery_point: "backup:ListRecoveryPointsByBackupVault",
  aws_cloudformation_stack: "cloudformation:ListStacks",
  aws_cloudformation_stack_resource: "cloudformation:ListStackResources",
  aws_guardduty_detector: "guardduty:ListDetectors",
  aws_guardduty_finding: "guardduty:ListFindings",
  aws_kms_key: "kms:ListKeys",
  aws_wafv2_web_acl: "wafv2:ListWebACLs",
  aws_sns_topic: "sns:ListTopics",
  aws_sns_topic_subscription: "sns:ListSubscriptions",
  aws_efs_file_system: "elasticfilesystem:DescribeFileSystems",
  aws_efs_mount_target: "elasticfilesystem:DescribeMountTargets",
};

/** Service names as the AWS SDK prints them in "operation error <Service>: <Operation>" -> IAM prefix. */
const SDK_SERVICE_PREFIX: Record<string, string> = {
  ec2: "ec2", rds: "rds", elasticache: "elasticache", cloudwatch: "cloudwatch", "cloudwatch logs": "logs", sns: "sns", sqs: "sqs",
  "cost explorer": "ce", pricing: "pricing", ssm: "ssm", s3: "s3", lambda: "lambda", ecr: "ecr", ecs: "ecs", eks: "eks",
  dynamodb: "dynamodb", "secrets manager": "secretsmanager", cloudtrail: "cloudtrail", cloudfront: "cloudfront",
  "route 53": "route53", route53: "route53", redshift: "redshift", emr: "elasticmapreduce", "api gateway": "apigateway",
  apigateway: "apigateway", savingsplans: "savingsplans", "savings plans": "savingsplans", sts: "sts", iam: "iam",
  "resource groups tagging api": "tag", "elastic load balancing v2": "elasticloadbalancing", "elastic load balancing": "elasticloadbalancing",
  "application auto scaling": "application-autoscaling",
  acm: "acm", athena: "athena", backup: "backup", cloudformation: "cloudformation", guardduty: "guardduty", kms: "kms", wafv2: "wafv2", efs: "elasticfilesystem",
};

/** Thrifty benchmark name -> the service whose read actions it needs, for a benchmark that fails before naming a table. */
const BENCHMARK_SERVICE: Record<string, string> = {
  apigateway: "apigateway", cloudfront: "cloudfront", cloudtrail: "cloudtrail", cloudwatch: "logs", cost_explorer: "ce", dynamodb: "dynamodb",
  ebs: "ec2", ec2: "ec2", ecr: "ecr", ecs: "ecs", eks: "eks", elasticache: "elasticache", emr: "elasticmapreduce", lambda: "lambda", network: "ec2",
  rds: "rds", redshift: "redshift", route53: "route53", s3: "s3", secretsmanager: "secretsmanager",
};

/** The read wildcard for a service, used when only the service is known. */
const SERVICE_READ_ACTION: Record<string, string> = {
  ec2: "ec2:Describe*", rds: "rds:Describe*", elasticache: "elasticache:Describe*", cloudwatch: "cloudwatch:GetMetricStatistics", logs: "logs:Describe*",
  ce: "ce:GetCostAndUsage", pricing: "pricing:GetProducts", ssm: "ssm:DescribeInstanceInformation", s3: "s3:ListAllMyBuckets", lambda: "lambda:ListFunctions",
  ecr: "ecr:Describe*", ecs: "ecs:Describe*", eks: "eks:Describe*", dynamodb: "dynamodb:Describe*", secretsmanager: "secretsmanager:ListSecrets",
  cloudtrail: "cloudtrail:DescribeTrails", cloudfront: "cloudfront:List*", route53: "route53:List*", redshift: "redshift:Describe*",
  elasticmapreduce: "elasticmapreduce:List*", apigateway: "apigateway:GET", savingsplans: "savingsplans:DescribeSavingsPlans", sts: "sts:GetCallerIdentity",
  iam: "iam:ListAccountAliases", tag: "tag:GetResources", elasticloadbalancing: "elasticloadbalancing:Describe*", "application-autoscaling": "application-autoscaling:Describe*",
  acm: "acm:ListCertificates", athena: "athena:ListWorkGroups", backup: "backup:List*", cloudformation: "cloudformation:ListStacks", guardduty: "guardduty:ListDetectors",
  kms: "kms:ListKeys", wafv2: "wafv2:ListWebACLs", elasticfilesystem: "elasticfilesystem:DescribeFileSystems", sns: "sns:ListTopics",
};

const PERMISSION_PATTERNS = [
  /\bAccessDenied(?:Exception)?\b/, /\bUnauthorizedOperation\b/, /\bAuthorizationError(?:Exception)?\b/, /\bnot authorized\b/i,
  /\bexplicit deny\b/i, /\bAccess Denied\b/, /\bUnauthorizedAccess\b/, /\bForbidden\b.*\b403\b|\b403\b.*\bForbidden\b/,
];
/** Bad or expired credentials are not a missing permission; they get their own message elsewhere. */
const CREDENTIAL_PATTERNS = [/InvalidSignature/, /UnrecognizedClient/, /ExpiredToken/, /InvalidClientTokenId/, /SignatureDoesNotMatch/, /InvalidAccessKeyId/];

const ACTION_RE = /\b([a-z0-9-]+):([A-Z][A-Za-z0-9*]+)\b/;
const isAction = (s: string) => ACTION_RE.test(s) && !/^(arn|aws):/i.test(s);

/** Tables named in a piece of SQL (or any text), for building contexts. */
export function tablesIn(text: string): string[] {
  return [...new Set((text.match(/\baws_[a-z0-9_]+\b/g) || []).filter((t) => t in TABLE_ACTIONS || !/_thrifty_/.test(t)))];
}

/** The IAM statement that allows one action; SendCommand is scoped to the shell-script document and instances. */
export function statementFor(action: string): IamStatement {
  const [service, name] = action.split(":");
  const sid = `Advisor${sidPart(service)}${sidPart(name || "")}`;
  if (action === "ssm:SendCommand") return { Sid: sid, Effect: "Allow", Action: [action], Resource: [probeDocumentArn(), EC2_ANY_INSTANCE] };
  if (action === "ssm:DescribeDocument" || action === "ssm:GetDocument") return { Sid: sid, Effect: "Allow", Action: [action], Resource: probeDocumentArn() };
  return { Sid: sid, Effect: "Allow", Action: [action], Resource: "*" };
}
const sidPart = (s: string) => s.replace(/[^A-Za-z0-9]/g, "").replace(/^./, (c) => c.toUpperCase());

/**
 * Recognises an AWS authorization failure in an error (Steampipe/Postgres error text, an AWS SDK error with
 * `name`, or a Powerpipe control error) and works out the IAM action. `context` says where the app was
 * (e.g. "query idle_instances (aws_ec2_instance)", "benchmark ec2", "ssm SendCommand i-123"): when the
 * message does not name an action, the tables, benchmark or "service:Action" in the context decide.
 * Returns null for anything that is not a permission problem.
 */
export function explainPermissionError(err: unknown, context: string): PermissionIssue | null {
  const e = err as any;
  const name: string = typeof e?.name === "string" ? e.name : typeof e?.Code === "string" ? e.Code : typeof e?.code === "string" ? e.code : "";
  const message: string = (typeof err === "string" ? err : e?.message ? String(e.message) : String(err ?? "")).trim();
  const text = `${name} ${message}`;
  if (CREDENTIAL_PATTERNS.some((p) => p.test(text))) return null;
  if (!PERMISSION_PATTERNS.some((p) => p.test(text))) return null;

  let action: string | null = null;
  // 1. "is not authorized to perform: ec2:DescribeInstances" (Steampipe, Cost Explorer, pricing, SSM...)
  const perform = message.match(/not authorized to perform:?\s+([a-z0-9-]+:[A-Za-z0-9*]+)/i);
  if (perform) action = perform[1];
  // 2. any "service:Action" token in the message or the context
  if (!action) {
    for (const source of [message, context]) {
      const m = source.match(new RegExp(ACTION_RE.source, "g"));
      const found = (m || []).find(isAction);
      if (found) { action = found; break; }
    }
  }
  // 3. the SDK's "operation error <Service>: <Operation>" prefix
  if (!action) {
    const op = message.match(/operation error ([A-Za-z0-9 ]+?): ([A-Z][A-Za-z0-9]+)/);
    if (op) {
      const prefix = SDK_SERVICE_PREFIX[op[1].trim().toLowerCase()];
      if (prefix) action = prefix === "apigateway" ? "apigateway:GET" : `${prefix}:${op[2]}`;
    }
  }
  // 4. a table named in the context or the message
  if (!action) {
    for (const t of [...tablesIn(context), ...tablesIn(message)]) {
      if (TABLE_ACTIONS[t]) { action = TABLE_ACTIONS[t]; break; }
    }
  }
  // 5. the benchmark's service, or a bare service word in the context
  if (!action) {
    const bench = context.match(/benchmark\s+([a-z_]+)/);
    const service = (bench && BENCHMARK_SERVICE[bench[1]]) || Object.keys(SERVICE_READ_ACTION).find((s) => new RegExp(`\\b${s}\\b`, "i").test(context));
    if (service) action = SERVICE_READ_ACTION[service];
  }
  if (!action) action = "unknown";
  // IAM reads the service prefix case-insensitively; the policy and the issue list keep it lowercase so one action is one row
  if (action !== "unknown") action = action.replace(/^[^:]+/, (s) => s.toLowerCase());

  const service = action === "unknown" ? "unknown" : action.split(":")[0];
  const res = message.match(/on resource:?\s+(arn:[^\s,;)]+)/i);
  return {
    action,
    service,
    ...(res ? { resource: res[1] } : {}),
    context,
    message: message.slice(0, 600),
    policy_statement: action === "unknown" ? { Sid: "AdvisorUnknownActionSeeMessage", Effect: "Allow", Action: [], Resource: "*" } : statementFor(action),
  };
}

/** The one-line remedy appended to log lines and API errors. */
export const remedyFor = (issue: PermissionIssue) =>
  issue.action === "unknown"
    ? "Missing IAM permission (the error did not name the action; see the message); add it to the advisor's policy (see Settings > Permissions)."
    : `Missing IAM permission ${issue.action}; add it to the advisor's policy (see Settings > Permissions).`;

const upsertIssue = db.prepare(`
  insert into permission_issues(action, service, contexts, first_seen, last_seen, count, last_message, accounts)
  values (?, ?, ?, datetime('now'), datetime('now'), 1, ?, ?)
  on conflict(action) do update set service = excluded.service, contexts = ?, last_seen = datetime('now'), count = count + 1, last_message = excluded.last_message, accounts = excluded.accounts`);
const selectContexts = db.prepare("select contexts, accounts from permission_issues where action = ?");

/** Records (or bumps) an issue; the contexts list keeps the last 20 distinct places it was seen. */
export function recordPermissionIssue(issue: PermissionIssue): PermissionIssue {
  const prev = selectContexts.get(issue.action) as { contexts: string; accounts: string | null } | undefined;
  let contexts: string[] = []; let accounts: string[] = [];
  try { contexts = prev ? (JSON.parse(prev.contexts) as string[]) : []; } catch { contexts = []; }
  try { accounts = prev?.accounts ? (JSON.parse(prev.accounts) as string[]) : []; } catch { accounts = []; }
  contexts = [...contexts.filter((c) => c !== issue.context), issue.context].slice(-20);
  accounts = [...new Set([...accounts, ...accountsIn(`${issue.context} ${issue.message}`)])].slice(-10);
  const json = JSON.stringify(contexts);
  upsertIssue.run(issue.action, issue.service, json, issue.message, JSON.stringify(accounts), json);
  openIssues.add(issue.action);
  console.warn(`[permissions] ${issue.context}: ${remedyFor(issue)}`);
  return issue;
}

export function listPermissionIssues(): PermissionIssueRow[] {
  const rows = db.prepare("select action, service, contexts, first_seen, last_seen, count, last_message, accounts from permission_issues order by last_seen desc, action").all() as (Omit<PermissionIssueRow, "contexts" | "accounts"> & { contexts: string; accounts: string | null })[];
  return rows.map((r) => { let c: string[] = []; let a: string[] = []; try { c = JSON.parse(r.contexts); } catch { /* keep empty */ } try { a = r.accounts ? JSON.parse(r.accounts) : []; } catch { /* keep empty */ } return { ...r, contexts: c, accounts: a }; });
}

/** Drops issues for actions a check just proved are granted. */
export function clearPermissionIssues(actions: string[]) {
  const del = db.prepare("delete from permission_issues where action = ?");
  db.transaction(() => { for (const a of actions) del.run(a); })();
  for (const a of actions) openIssues.delete(a);
}

/** Actions with a recorded issue, kept in memory so the success hooks cost nothing when there is none. */
const openIssues = new Set<string>((db.prepare("select action from permission_issues").all() as { action: string }[]).map((r) => r.action));

/** A call that needs `actions` just succeeded: any recorded issue for them is stale, drop it. */
export function noteSuccess(actions: string[], context = ""): string[] {
  const cleared = actions.filter((a) => openIssues.has(a));
  if (cleared.length) {
    clearPermissionIssues(cleared);
    console.log(`[permissions] cleared ${cleared.join(", ")}: it worked${context ? ` (${context})` : ""}`);
  }
  return cleared;
}
/** Same, for a successful query over these tables. */
export function noteSuccessForTables(tables: string[], context = ""): string[] {
  if (!openIssues.size) return [];
  return noteSuccess([...new Set(tables.map((t) => TABLE_ACTIONS[t]).filter((a): a is string => Boolean(a)))], context);
}
/** The table that proves an action, for re-verifying a recorded issue. */
export function tableForAction(action: string): string | null {
  for (const [t, a] of Object.entries(TABLE_ACTIONS)) if (a === action) return t;
  return null;
}
export const hasOpenIssues = () => openIssues.size > 0;

/**
 * Runs an error through the diagnostics: when it is a permission failure the issue is recorded and the
 * message comes back with the remedy appended; otherwise the message is returned as it was. This is what
 * every catch block in the app uses to build its log line or API error.
 */
export function describeError(err: unknown, context: string, maxLen = 400): string {
  const e = err as any;
  const raw = String(typeof err === "string" ? err : e?.message || err);
  // the Steampipe service is down: a plugin panic or memory pressure; in the image a watchdog restarts it within 30 s
  if (/ECONNREFUSED [0-9.]+:9193|connect ECONNREFUSED/.test(raw) && /9193|steampipe/i.test(raw + context)) {
    return `Steampipe service is not running (${raw.slice(0, 80)}): it restarts by itself within 30 seconds in the image; locally run \`steampipe service start\`. Its log is ~/.steampipe/logs/steampipe-<date>.log.`;
  }
  const message = raw.slice(0, maxLen);
  // AWS's throttle answer ("Rate exceeded") carries no service or call: say which read it was, and that the next refresh retries
  if (/Rate exceeded|Throttl|TooManyRequests|RequestLimitExceeded/i.test(`${e?.name ?? ""} ${raw}`)) return `${context}: AWS throttled the calls (${message.replace(/[.\s]+$/, "")}); the next refresh tries again`;
  const issue = explainPermissionError(err, context);
  if (!issue) return message;
  recordPermissionIssue(issue);
  return `${message.replace(/[.\s]+$/, "")}. ${remedyFor(issue)}`;
}

/**
 * One IAM policy document for a set of issues: statements grouped by service with sorted, de-duplicated
 * actions; SendCommand keeps its own scoped statement; unknown actions are left out.
 */
export function policyForIssues(issues: { action: string; service?: string }[]): IamPolicy {
  const byService = new Map<string, Set<string>>();
  const scoped = new Map<string, IamStatement>();
  for (const i of issues) {
    if (!i.action || i.action === "unknown" || !isAction(i.action)) continue;
    const st = statementFor(i.action);
    if (Array.isArray(st.Resource)) { scoped.set(i.action, st); continue; }
    const service = i.action.split(":")[0];
    if (!byService.has(service)) byService.set(service, new Set());
    byService.get(service)!.add(i.action);
  }
  const statements: IamStatement[] = [...byService.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([service, actions]) => ({ Sid: `Advisor${sidPart(service)}Read`, Effect: "Allow" as const, Action: [...actions].sort(), Resource: "*" }));
  for (const [, st] of [...scoped.entries()].sort(([a], [b]) => a.localeCompare(b))) statements.push(st);
  return { Version: "2012-10-17", Statement: statements };
}

/**
 * The AWS-managed policy attached next to the advisor's inline one: every List/Describe call AWS ships, kept current
 * by AWS, with no data reads (no s3:GetObject, no table rows, no log events). New collectors that only list and
 * describe need nothing added here.
 */
export const VIEW_ONLY_POLICY_ARN = "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess";

/**
 * The inline read-only policy the advisor needs on top of ViewOnlyAccess (kept in step with the README's "IAM
 * permissions" section): only what that managed policy leaves out, such as cost data, Logs Insights queries, bucket
 * settings, Identity Center and the wildcards for services whose describe calls it names one by one.
 * The SSM statements follow PROBE_DOCUMENT: a custom document gets SendCommand scoped to it, the stock
 * AWS-RunShellScript is the zero-setup fallback.
 */
export const recommendedPolicy = (accountId = "*", memberReadRoleName = "aws-advisor-read"): IamPolicy => ({
  Version: "2012-10-17",
  Statement: [
    {
      Sid: "AdvisorReadOnly",
      Effect: "Allow",
      Action: [
        "ec2:Describe*",
        "rds:ListTagsForResource", "rds:DownloadDBLogFilePortion",
        "pi:DescribeDimensionKeys", "pi:GetResourceMetadata",
        "elasticache:ListTagsForResource",
        "logs:StartQuery", "logs:GetQueryResults", "logs:StopQuery",
        "cloudwatch:DescribeAlarms",
        "kms:DescribeKey", "kms:ListAliases", "kms:GetKeyRotationStatus", "kms:ListResourceTags",
        "elasticfilesystem:DescribeLifecycleConfiguration", "elasticfilesystem:DescribeTags", "elasticfilesystem:DescribeMountTargets", "elasticfilesystem:DescribeMountTargetSecurityGroups", "elasticfilesystem:DescribeBackupPolicy",
        "ce:GetCostAndUsage", "ce:GetCostAndUsageWithResources", "ce:GetSavingsPlansUtilization", "ce:GetSavingsPlansCoverage", "ce:GetReservationUtilization",
        "savingsplans:DescribeSavingsPlans",
        "pricing:GetProducts",
        "support:DescribeSeverityLevels",
        "ssm:DescribeInstanceInformation",
        "s3:GetBucketLocation", "s3:GetLifecycleConfiguration", "s3:GetBucketTagging", "s3:GetBucketVersioning", "s3:GetBucketPolicyStatus",
        "s3:ListBucketVersions", "s3:ListBucketMultipartUploads", "s3:GetMetricsConfiguration",
        "lambda:GetFunction*",
        "ecr:DescribeImages", "ecr:GetLifecyclePolicy", "ecr:ListTagsForResource",
        "eks:Describe*", "eks:List*",
        "dynamodb:Describe*", "dynamodb:List*",
        "application-autoscaling:DescribeScalableTargets",
        "elasticloadbalancing:Describe*",
        "secretsmanager:ListSecrets", "secretsmanager:DescribeSecret",
        "cloudtrail:GetTrailStatus", "cloudtrail:ListTags",
        "cloudfront:Get*",
        "elasticbeanstalk:DescribeConfigurationSettings", "elasticbeanstalk:DescribeEnvironmentResources", "elasticbeanstalk:ListTagsForResource",
        "redshift:Describe*",
        "elasticmapreduce:Describe*",
        "apigateway:GET",
        "tag:GetResources",
        "sts:GetCallerIdentity",
        "iam:SimulatePrincipalPolicy", "iam:GetUser", "iam:GetAccessKeyLastUsed", "iam:GetUserPolicy",
        // the root user's password and key last use (src/sign_ins.ts); ViewOnlyAccess has GetAccountSummary and List* but not the credential report
        "iam:GenerateCredentialReport", "iam:GetCredentialReport",
        "organizations:DescribeOrganization",
        // IAM Identity Center (the management account or its delegated administrator answers; elsewhere the calls return nothing and the Identities tab says so)
        "sso:ListInstances", "sso:ListPermissionSets", "sso:DescribePermissionSet", "sso:ListManagedPoliciesInPermissionSet", "sso:ListCustomerManagedPolicyReferencesInPermissionSet", "sso:GetInlinePolicyForPermissionSet", "sso:GetPermissionsBoundaryForPermissionSet", "sso:ListAccountsForProvisionedPermissionSet", "sso:ListAccountAssignmentsForPrincipal", "sso:ListApplications", "sso:ListApplicationAssignmentsForPrincipal",
        "identitystore:ListUsers", "identitystore:ListGroups", "identitystore:ListGroupMemberships", "identitystore:DescribeUser", "identitystore:DescribeGroup",
        "iam:GetRole",
        // the advisor reads its own inline policy to say what is missing before a person updates it (src/actions/read_policy.ts)
        "iam:GetRolePolicy",
        // the foundational security benchmark's SNS controls (topic encryption, delivery logging, subscriptions)
        "sns:GetTopicAttributes",
        // the platform services inventory (src/services/): certificates, workgroups, backups, stacks, web ACLs, threat detection
        "acm:DescribeCertificate", "acm:ListTagsForCertificate",
        "athena:GetWorkGroup",
        "cloudformation:DescribeStackResources", "cloudformation:DescribeStackResource",
        "wafv2:GetWebACL", "wafv2:GetLoggingConfiguration",
        "guardduty:ListDetectors", "guardduty:GetDetector", "guardduty:ListFindings", "guardduty:GetFindings", "guardduty:ListTagsForResource", "guardduty:GetAdministratorAccount",
        // User Notifications (the console bell): the AWS-managed feed and the account's own configurations
        "notifications:ListNotificationHubs", "notifications:ListManagedNotificationEvents", "notifications:GetManagedNotificationEvent", "notifications:ListManagedNotificationChildEvents", "notifications:ListNotificationEvents", "notifications:GetNotificationEvent",
      ],
      Resource: "*",
    },
    {
      // member accounts: the read role of each child carries this same name by default and trusts this identity; both sides are needed to assume it
      Sid: "AdvisorAssumeMembers",
      Effect: "Allow",
      Action: ["sts:AssumeRole"],
      Resource: [`arn:aws:iam::*:role/${memberReadRoleName}`],
    },
    {
      Sid: "AdvisorSsmProbe",
      Effect: "Allow",
      Action: ["ssm:SendCommand"],
      Resource: [probeDocumentArn(accountId), EC2_ANY_INSTANCE],
    },
    {
      Sid: "AdvisorSsmProbeDocument",
      Effect: "Allow",
      Action: ["ssm:DescribeDocument", "ssm:GetDocument"],
      Resource: probeDocumentArn(accountId),
    },
    {
      Sid: "AdvisorSsmProbeResults",
      Effect: "Allow",
      Action: ["ssm:GetCommandInvocation", "ssm:ListCommandInvocations"],
      Resource: "*",
    },
  ],
});

/**
 * The actuator policy: what the executor's role (Settings > Auto-actions, `ACT_ROLE_ARN`) may change, and nothing
 * else. One statement per action the executor implements, each with the read calls its pre- and post-checks make,
 * and a Deny on anything tagged `advisor:hands-off`, so a human can fence a resource off from the executor with a
 * tag whatever the executor thinks. The read-only role never gets any of this: the executor assumes this role from
 * the read credentials only for the change itself.
 */
/**
 * What the actuator role must be allowed to do for each action kind: the calls apply makes and the calls revert
 * makes. The executor checks these against the role (iam:SimulatePrincipalPolicy from the read identity) and
 * learns them from denied applies, so a role narrower than the policy below hides Apply instead of failing.
 */
/** Actions a module declares that only a person's own credentials perform ("Run as me"): never in the actuator policy, never counted as its gap. */
/** Actions the actuator holds only through an instance's Auto-park grant (src/autopark_grant.ts), never in the static policy: the right is scoped to that instance's own records. */
export const GRANT_ONLY_ACTIONS: ReadonlySet<string> = new Set(["route53:ChangeResourceRecordSets"]);
export const PERSON_ONLY_ACTIONS: ReadonlySet<string> = new Set(["iam:GetPolicy", "iam:GetPolicyVersion", "iam:ListPolicyVersions", "iam:CreatePolicy", "iam:CreatePolicyVersion", "iam:DeletePolicyVersion", "iam:DeletePolicy", "iam:AttachRolePolicy", "iam:DetachRolePolicy", "iam:AttachUserPolicy", "iam:DetachUserPolicy", "iam:PutRolePolicy", "iam:PutUserPolicy", "iam:DeleteRolePolicy", "iam:DeleteUserPolicy"]);

export const ACTUATOR_NEEDS: Record<string, { apply: string[]; revert: string[] }> = {
  acu_window: { apply: ["rds:ModifyDBCluster"], revert: ["rds:ModifyDBCluster"] },
  snapshot_archive: { apply: ["ec2:ModifySnapshotTier"], revert: ["ec2:RestoreSnapshotTier"] },
  ebs_iops_trim: { apply: ["ec2:ModifyVolume"], revert: ["ec2:ModifyVolume"] },
  ebs_gp3_migrate: { apply: ["ec2:ModifyVolume"], revert: ["ec2:ModifyVolume"] },
  log_retention: { apply: ["logs:PutRetentionPolicy"], revert: ["logs:DeleteRetentionPolicy"] },
  s3_request_metrics: { apply: ["s3:PutMetricsConfiguration"], revert: ["s3:DeleteMetricsConfiguration"] },
  s3_lifecycle: { apply: ["s3:GetLifecycleConfiguration", "s3:PutLifecycleConfiguration"], revert: ["s3:PutLifecycleConfiguration"] },
  aurora_storage: { apply: ["rds:ModifyDBCluster"], revert: ["rds:ModifyDBCluster"] },
  ecr_lifecycle: { apply: ["ecr:PutLifecyclePolicy"], revert: ["ecr:DeleteLifecyclePolicy"] },
  swarm_park: { apply: ["ec2:StopInstances"], revert: ["ec2:StartInstances"] },
  // Irreversible deletes (EIP, snapshot, load balancer) have no revert call: the row says so and Revert explains.
  eip_release: { apply: ["ec2:ReleaseAddress"], revert: ["ec2:AllocateAddress"] },
  vpc_gateway_endpoint: { apply: ["ec2:CreateVpcEndpoint"], revert: ["ec2:DeleteVpcEndpoints"] },
  kms_key_retire: { apply: ["kms:ScheduleKeyDeletion"], revert: ["kms:CancelKeyDeletion", "kms:EnableKey"] },
  dynamodb_capacity_mode: { apply: ["dynamodb:UpdateTable"], revert: ["dynamodb:UpdateTable"] },
  snapshot_delete: { apply: ["ec2:DeleteSnapshot"], revert: [] },
  idle_load_balancer: { apply: ["elasticloadbalancing:DeleteLoadBalancer"], revert: [] },
  schedule_hours: { apply: ["ec2:StopInstances", "ec2:StartInstances", "rds:StopDBInstance", "rds:StartDBInstance", "rds:StopDBCluster", "rds:StartDBCluster"], revert: ["ec2:StopInstances", "ec2:StartInstances", "rds:StopDBInstance", "rds:StartDBInstance", "rds:StopDBCluster", "rds:StartDBCluster"] },
  ebs_throughput_trim: { apply: ["ec2:ModifyVolume"], revert: ["ec2:ModifyVolume"] },
  cpu_credit_spec: { apply: ["ec2:ModifyInstanceCreditSpecification"], revert: ["ec2:ModifyInstanceCreditSpecification"] },
  efs_lifecycle: { apply: ["elasticfilesystem:PutLifecycleConfiguration"], revert: ["elasticfilesystem:PutLifecycleConfiguration"] },
  alarm_cleanup: { apply: ["cloudwatch:DeleteAlarms"], revert: ["cloudwatch:PutMetricAlarm"] },
  log_retention_tune: { apply: ["logs:PutRetentionPolicy"], revert: ["logs:PutRetentionPolicy"] },
  s3_multipart_abort: { apply: ["s3:GetLifecycleConfiguration", "s3:PutLifecycleConfiguration"], revert: ["s3:PutLifecycleConfiguration"] },
  lambda_memory: { apply: ["lambda:UpdateFunctionConfiguration"], revert: ["lambda:UpdateFunctionConfiguration"] },
  beanstalk_scale: { apply: ["elasticbeanstalk:UpdateEnvironment"], revert: ["elasticbeanstalk:UpdateEnvironment"] },
  beanstalk_pressure: { apply: ["elasticbeanstalk:UpdateEnvironment"], revert: ["elasticbeanstalk:UpdateEnvironment"] },
  usage_schedule: { apply: ["ec2:CreateTags"], revert: ["ec2:DeleteTags"] },
  // UpdateTagsForResource is the API; the IAM actions it checks are AddTags (TagsToAdd) and RemoveTags (TagsToRemove).
  // the AdvisorAutoPark and advisor:hibernate switches are done with a person's credentials ("Run as me"; PERSON_ONLY_ACTIONS are never the actuator's) ("Run as me"): the tag, and for Auto-park the grant on the actuator role
  // the advisor's own read policy, brought up to date from Settings › Permissions with a person's credentials (src/actions/read_policy.ts): never the actuator's
  read_policy: { apply: ["iam:PutRolePolicy", "iam:PutUserPolicy", "iam:AttachRolePolicy", "iam:AttachUserPolicy"], revert: ["iam:PutRolePolicy", "iam:PutUserPolicy", "iam:DeleteRolePolicy", "iam:DeleteUserPolicy", "iam:DetachRolePolicy", "iam:DetachUserPolicy"] },
  consent_tag: { apply: ["ec2:CreateTags", "elasticbeanstalk:AddTags", ...PERSON_ONLY_ACTIONS], revert: ["ec2:DeleteTags", "elasticbeanstalk:AddTags", "elasticbeanstalk:RemoveTags", ...PERSON_ONLY_ACTIONS] },
  // A staged relaunch: apply, the stages (advance) and the cut-over (step) are all checked as apply.
  ec2_hibernate_migrate: { apply: ["ec2:CreateImage", "ec2:StopInstances", "ec2:RunInstances", "ec2:CreateTags", "iam:PassRole", "ec2:AssociateAddress", "route53:ChangeResourceRecordSets", "elasticloadbalancing:RegisterTargets", "elasticloadbalancing:DeregisterTargets"],
    revert: ["ec2:StartInstances", "ec2:StopInstances", "ec2:AssociateAddress", "route53:ChangeResourceRecordSets", "elasticloadbalancing:RegisterTargets", "elasticloadbalancing:DeregisterTargets", "ec2:DeleteTags"] },
};

export const actuatorPolicy = (): IamPolicy => ({
  Version: "2012-10-17",
  Statement: [
    { Sid: "ActuatorIdentity", Effect: "Allow", Action: ["sts:GetCallerIdentity"], Resource: "*" },
    { Sid: "ActuatorServerlessCapacity", Effect: "Allow", Action: ["rds:ModifyDBCluster", "rds:DescribeDBClusters", "rds:ListTagsForResource"], Resource: "*" },
    { Sid: "ActuatorSnapshotTier", Effect: "Allow", Action: ["ec2:ModifySnapshotTier", "ec2:RestoreSnapshotTier", "ec2:DescribeSnapshots", "ec2:DescribeSnapshotTierStatus"], Resource: "*" },
    { Sid: "ActuatorVolumeIops", Effect: "Allow", Action: ["ec2:ModifyVolume", "ec2:DescribeVolumes", "ec2:DescribeVolumesModifications"], Resource: "*" },
    { Sid: "ActuatorLogRetention", Effect: "Allow", Action: ["logs:PutRetentionPolicy", "logs:DeleteRetentionPolicy", "logs:DescribeLogGroups", "logs:ListTagsForResource"], Resource: "*" },
    { Sid: "ActuatorS3RequestMetrics", Effect: "Allow", Action: ["s3:PutMetricsConfiguration", "s3:GetMetricsConfiguration", "s3:DeleteMetricsConfiguration"], Resource: "*" },
    { Sid: "ActuatorS3Lifecycle", Effect: "Allow", Action: ["s3:PutLifecycleConfiguration", "s3:GetLifecycleConfiguration", "s3:GetBucketTagging"], Resource: "*" },
    { Sid: "ActuatorEcrLifecycle", Effect: "Allow", Action: ["ecr:PutLifecyclePolicy", "ecr:DeleteLifecyclePolicy", "ecr:GetLifecyclePolicy", "ecr:DescribeRepositories", "ecr:ListTagsForResource"], Resource: "*" },
    // The parked marker the executor puts on an instance it stopped: a label, it opens nothing (and no statement reads it).
    { Sid: "ActuatorParkedMarker", Effect: "Allow", Action: ["ec2:CreateTags", "ec2:DeleteTags"], Resource: "arn:aws:ec2:*:*:instance/*", Condition: { "ForAllValues:StringEquals": { "aws:TagKeys": ["advisor:parked"] } } },
    // Stopping and starting EC2 instances: no statement here. Each instance a person switched Auto-park on for is
    // listed in the customer-managed policy /aws-advisor/AdvisorAutoParkInstances attached to this role
    // (src/autopark_grant.ts), written with that person's credentials ("Run as me"); the actuator has no IAM write
    // right and no tag it can write opens a stop.
    { Sid: "ActuatorSwarmParkDescribe", Effect: "Allow", Action: ["ec2:DescribeInstances", "ec2:DescribeAddresses"], Resource: "*" },
    // Approved deletes: an Elastic IP nobody uses, a snapshot a person approved deleting, an idle load balancer. AllocateAddress is the EIP recovery path (the same address, while nobody else has it).
    { Sid: "ActuatorEipRelease", Effect: "Allow", Action: ["ec2:ReleaseAddress", "ec2:AllocateAddress", "ec2:DescribeAddresses"], Resource: "*" },
    { Sid: "ActuatorSnapshotDelete", Effect: "Allow", Action: ["ec2:DeleteSnapshot", "ec2:DescribeImages"], Resource: "*" },
    { Sid: "ActuatorLoadBalancerDelete", Effect: "Allow", Action: ["elasticloadbalancing:DeleteLoadBalancer", "elasticloadbalancing:DescribeLoadBalancers", "elasticloadbalancing:DescribeListeners", "elasticloadbalancing:DescribeTargetGroups", "elasticloadbalancing:DescribeTargetHealth", "elasticloadbalancing:DescribeTags", "elasticloadbalancing:DescribeLoadBalancerAttributes"], Resource: "*" },
    // Gateway endpoints for S3 and DynamoDB: free, and the route tables they go on come from the endpoint call itself.
    { Sid: "ActuatorGatewayEndpoint", Effect: "Allow", Action: ["ec2:CreateVpcEndpoint", "ec2:DeleteVpcEndpoints", "ec2:DescribeVpcEndpoints", "ec2:DescribeRouteTables", "ec2:DescribeVpcs", "ec2:DescribeNatGateways"], Resource: "*" },
    { Sid: "ActuatorGatewayEndpointTag", Effect: "Allow", Action: ["ec2:CreateTags"], Resource: "arn:aws:ec2:*:*:vpc-endpoint/*", Condition: { StringEquals: { "ec2:CreateAction": "CreateVpcEndpoint" } } },
    // KMS: schedule (never immediate) and cancel; a cancelled key comes back disabled, so EnableKey completes the revert.
    { Sid: "ActuatorKmsRetire", Effect: "Allow", Action: ["kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion", "kms:EnableKey", "kms:DescribeKey", "kms:ListResourceTags"], Resource: "*" },
    { Sid: "ActuatorDynamoCapacity", Effect: "Allow", Action: ["dynamodb:UpdateTable", "dynamodb:DescribeTable", "dynamodb:ListTagsOfResource"], Resource: "*" },
    // Office hours on databases: only those someone tagged advisor:schedule (EC2 instances need their Auto-park grant, above).
    { Sid: "ActuatorScheduleRds", Effect: "Allow", Action: ["rds:StopDBInstance", "rds:StartDBInstance", "rds:StopDBCluster", "rds:StartDBCluster"], Resource: "*", Condition: { StringLike: { "aws:ResourceTag/advisor:schedule": "*" } } },
    { Sid: "ActuatorScheduleDescribe", Effect: "Allow", Action: ["rds:DescribeDBInstances"], Resource: "*" },
    { Sid: "ActuatorCreditSpec", Effect: "Allow", Action: ["ec2:ModifyInstanceCreditSpecification", "ec2:DescribeInstanceCreditSpecifications"], Resource: "*" },
    { Sid: "ActuatorEfsLifecycle", Effect: "Allow", Action: ["elasticfilesystem:PutLifecycleConfiguration", "elasticfilesystem:DescribeFileSystems", "elasticfilesystem:DescribeLifecycleConfiguration", "elasticfilesystem:DescribeTags"], Resource: "*" },
    { Sid: "ActuatorLambdaMemory", Effect: "Allow", Action: ["lambda:UpdateFunctionConfiguration", "lambda:GetFunctionConfiguration", "lambda:ListTags"], Resource: "*" },
    { Sid: "ActuatorAlarmCleanup", Effect: "Allow", Action: ["cloudwatch:DeleteAlarms", "cloudwatch:PutMetricAlarm", "cloudwatch:DescribeAlarms", "cloudwatch:ListTagsForResource"], Resource: "*" },
    // Beanstalk capacity: only an environment someone tagged advisor:scale can have its MinSize/MaxSize moved. With an operations role on the environment Beanstalk does the CloudFormation and Auto Scaling work under that role; without one the caller needs those rights too (README).
    { Sid: "ActuatorBeanstalkScale", Effect: "Allow", Action: ["elasticbeanstalk:UpdateEnvironment"], Resource: "arn:aws:elasticbeanstalk:*:*:environment/*/*", Condition: { StringLike: { "aws:ResourceTag/advisor:scale": "*" } } },
    // Usage schedules: the one tag the role may write on any instance is advisor:schedule (an approved usage_schedule recommendation); the office-hours action then does the stops and starts.
    { Sid: "ActuatorUsageScheduleTag", Effect: "Allow", Action: ["ec2:CreateTags", "ec2:DeleteTags"], Resource: "arn:aws:ec2:*:*:instance/*", Condition: { "ForAllValues:StringEquals": { "aws:TagKeys": ["advisor:schedule"] } } },
    // Consent switches from the page (src/consent.ts): AdvisorAutoPark on instances (above), AdvisorAutoScale and its band on environments.
    { Sid: "ActuatorBeanstalkConsentTag", Effect: "Allow", Action: ["elasticbeanstalk:AddTags", "elasticbeanstalk:RemoveTags"], Resource: "arn:aws:elasticbeanstalk:*:*:environment/*/*", Condition: { "ForAllValues:StringEquals": { "aws:TagKeys": ["AdvisorAutoScale", "AdvisorScaleBand"] } } },
    // AdvisorAutoScale=ON lets the capacity action move an environment's MinSize and MaxSize.
    { Sid: "ActuatorAutoScale", Effect: "Allow", Action: ["elasticbeanstalk:UpdateEnvironment"], Resource: "arn:aws:elasticbeanstalk:*:*:environment/*/*", Condition: { StringEqualsIgnoreCase: { "aws:ResourceTag/AdvisorAutoScale": "ON" } } },
    // On a start without an Elastic IP the office-hours action points the A records that named the old public address at the new one
    // (the hibernation relaunch moves them too). No write statement here: the right to UPSERT exactly those A records in their zones
    // is part of the instance's Auto-park grant in /aws-advisor/AdvisorAutoParkInstances (src/autopark_grant.ts), written by a person.
    { Sid: "ActuatorDnsReattachRead", Effect: "Allow", Action: ["route53:ListResourceRecordSets", "route53:GetChange", "ec2:DescribeInstances"], Resource: "*" },
    // Hibernation-ready relaunch: only an instance someone tagged advisor:hibernate is imaged or stopped; the new box must carry advisor:migrated-from from its launch, and is the only other box the role may stop or start.
    { Sid: "ActuatorHibernateImage", Effect: "Allow", Action: ["ec2:CreateImage", "ec2:StopInstances", "ec2:StartInstances"], Resource: "arn:aws:ec2:*:*:instance/*", Condition: { StringLike: { "aws:ResourceTag/advisor:hibernate": "*" } } },
    { Sid: "ActuatorHibernateImageOut", Effect: "Allow", Action: ["ec2:CreateImage"], Resource: ["arn:aws:ec2:*::image/*", "arn:aws:ec2:*::snapshot/*"] },
    { Sid: "ActuatorHibernateLaunch", Effect: "Allow", Action: ["ec2:RunInstances"], Resource: "arn:aws:ec2:*:*:instance/*", Condition: { StringLike: { "aws:RequestTag/advisor:migrated-from": "i-*" } } },
    { Sid: "ActuatorHibernateLaunchParts", Effect: "Allow", Action: ["ec2:RunInstances"], Resource: ["arn:aws:ec2:*::image/*", "arn:aws:ec2:*::snapshot/*", "arn:aws:ec2:*:*:volume/*", "arn:aws:ec2:*:*:network-interface/*", "arn:aws:ec2:*:*:subnet/*", "arn:aws:ec2:*:*:security-group/*", "arn:aws:ec2:*:*:key-pair/*", "arn:aws:ec2:*:*:placement-group/*"] },
    { Sid: "ActuatorHibernateLaunchTags", Effect: "Allow", Action: ["ec2:CreateTags"], Resource: "*", Condition: { StringEquals: { "ec2:CreateAction": ["RunInstances", "CreateImage"] } } },
    { Sid: "ActuatorHibernateNewBox", Effect: "Allow", Action: ["ec2:StopInstances", "ec2:StartInstances"], Resource: "arn:aws:ec2:*:*:instance/*", Condition: { StringLike: { "aws:ResourceTag/advisor:migrated-from": "i-*" } } },
    { Sid: "ActuatorHibernateMarker", Effect: "Allow", Action: ["ec2:CreateTags", "ec2:DeleteTags"], Resource: "arn:aws:ec2:*:*:instance/*", Condition: { StringLike: { "aws:ResourceTag/advisor:hibernate": "*" }, "ForAllValues:StringEquals": { "aws:TagKeys": ["advisor:migrated-to"] } } },
    { Sid: "ActuatorHibernateMove", Effect: "Allow", Action: ["ec2:AssociateAddress", "ec2:DescribeImages", "ec2:DescribeInstanceStatus", "ec2:DescribeVolumes", "elasticloadbalancing:RegisterTargets", "elasticloadbalancing:DeregisterTargets"], Resource: "*" },
    { Sid: "ActuatorHibernatePassRole", Effect: "Allow", Action: ["iam:PassRole"], Resource: "*", Condition: { StringEquals: { "iam:PassedToService": "ec2.amazonaws.com" } } },
    // Encrypting at launch with a customer-managed default EBS key needs these through EC2; the AWS-managed aws/ebs key needs nothing.
    { Sid: "ActuatorHibernateKms", Effect: "Allow", Action: ["kms:CreateGrant", "kms:Decrypt", "kms:DescribeKey", "kms:GenerateDataKeyWithoutPlaintext", "kms:ReEncrypt*"], Resource: "*", Condition: { StringLike: { "kms:ViaService": "ec2.*.amazonaws.com" } } },
    { Sid: "ActuatorBeanstalkScaleDescribe", Effect: "Allow", Action: ["elasticbeanstalk:DescribeEnvironments", "elasticbeanstalk:DescribeConfigurationSettings", "elasticbeanstalk:DescribeEnvironmentResources", "elasticbeanstalk:ListTagsForResource", "autoscaling:DescribeAutoScalingGroups"], Resource: "*" },
    { Sid: "ActuatorHandsOff", Effect: "Deny", Action: ["rds:ModifyDBCluster", "ec2:ModifySnapshotTier", "ec2:RestoreSnapshotTier", "ec2:ModifyVolume", "logs:PutRetentionPolicy", "logs:DeleteRetentionPolicy", "s3:PutMetricsConfiguration", "s3:DeleteMetricsConfiguration", "s3:PutLifecycleConfiguration", "ecr:PutLifecyclePolicy", "ecr:DeleteLifecyclePolicy", "ec2:StopInstances", "ec2:StartInstances",
      "ec2:ReleaseAddress", "ec2:DeleteSnapshot", "elasticloadbalancing:DeleteLoadBalancer", "ec2:DeleteVpcEndpoints", "kms:ScheduleKeyDeletion", "dynamodb:UpdateTable", "rds:StopDBInstance", "rds:StartDBInstance", "rds:StopDBCluster", "rds:StartDBCluster", "ec2:ModifyInstanceCreditSpecification", "elasticfilesystem:PutLifecycleConfiguration", "cloudwatch:DeleteAlarms", "lambda:UpdateFunctionConfiguration", "elasticbeanstalk:UpdateEnvironment", "ec2:CreateTags", "ec2:DeleteTags", "elasticbeanstalk:AddTags", "elasticbeanstalk:RemoveTags", "ec2:CreateImage"], Resource: "*", Condition: { StringLike: { "aws:ResourceTag/advisor:hands-off": "*" } } },
  ],
});

/** The trust policy the actuator role needs: the advisor's read identity (role or user ARN) may assume it. */
export const actuatorTrustPolicy = (readIdentityArn = "<the advisor's read role or user ARN>") => ({
  Version: "2012-10-17",
  Statement: [{ Sid: "AdvisorExecutor", Effect: "Allow", Principal: { AWS: readIdentityArn }, Action: "sts:AssumeRole" }],
});

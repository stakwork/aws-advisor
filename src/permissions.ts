import { config } from "./config.js";
import { db } from "./db.js";

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
export const probeDocumentArn = (accountId = "*") => `arn:aws:ssm:*:${accountId}:document/${policyProbeDocument()}`;

/** Steampipe table -> the IAM action its List/Describe call needs (only the tables this app and its benchmarks use). */
export const TABLE_ACTIONS: Record<string, string> = {
  aws_account: "iam:ListAccountAliases",
  aws_region: "ec2:DescribeRegions",
  aws_ec2_instance: "ec2:DescribeInstances",
  aws_ec2_instance_metric_cpu_utilization_daily: "cloudwatch:GetMetricStatistics",
  aws_ec2_reserved_instance: "ec2:DescribeReservedInstances",
  aws_ec2_ami: "ec2:DescribeImages",
  aws_ec2_ami_shared: "ec2:DescribeImages",
  aws_ec2_launch_template_version: "ec2:DescribeLaunchTemplateVersions",
  aws_ec2_target_group: "elasticloadbalancing:DescribeTargetGroups",
  aws_ec2_application_load_balancer: "elasticloadbalancing:DescribeLoadBalancers",
  aws_ec2_network_load_balancer: "elasticloadbalancing:DescribeLoadBalancers",
  aws_ec2_gateway_load_balancer: "elasticloadbalancing:DescribeLoadBalancers",
  aws_ec2_classic_load_balancer: "elasticloadbalancing:DescribeLoadBalancers",
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
};

/** Service names as the AWS SDK prints them in "operation error <Service>: <Operation>" -> IAM prefix. */
const SDK_SERVICE_PREFIX: Record<string, string> = {
  ec2: "ec2", rds: "rds", elasticache: "elasticache", cloudwatch: "cloudwatch", "cloudwatch logs": "logs",
  "cost explorer": "ce", pricing: "pricing", ssm: "ssm", s3: "s3", lambda: "lambda", ecr: "ecr", ecs: "ecs", eks: "eks",
  dynamodb: "dynamodb", "secrets manager": "secretsmanager", cloudtrail: "cloudtrail", cloudfront: "cloudfront",
  "route 53": "route53", route53: "route53", redshift: "redshift", emr: "elasticmapreduce", "api gateway": "apigateway",
  apigateway: "apigateway", savingsplans: "savingsplans", "savings plans": "savingsplans", sts: "sts", iam: "iam",
  "resource groups tagging api": "tag", "elastic load balancing v2": "elasticloadbalancing", "elastic load balancing": "elasticloadbalancing",
  "application auto scaling": "application-autoscaling",
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
  insert into permission_issues(action, service, contexts, first_seen, last_seen, count, last_message)
  values (?, ?, ?, datetime('now'), datetime('now'), 1, ?)
  on conflict(action) do update set service = excluded.service, contexts = ?, last_seen = datetime('now'), count = count + 1, last_message = excluded.last_message`);
const selectContexts = db.prepare("select contexts from permission_issues where action = ?");

/** Records (or bumps) an issue; the contexts list keeps the last 20 distinct places it was seen. */
export function recordPermissionIssue(issue: PermissionIssue): PermissionIssue {
  const prev = selectContexts.get(issue.action) as { contexts: string } | undefined;
  let contexts: string[] = [];
  try { contexts = prev ? (JSON.parse(prev.contexts) as string[]) : []; } catch { contexts = []; }
  contexts = [...contexts.filter((c) => c !== issue.context), issue.context].slice(-20);
  const json = JSON.stringify(contexts);
  upsertIssue.run(issue.action, issue.service, json, issue.message, json);
  openIssues.add(issue.action);
  console.warn(`[permissions] ${issue.context}: ${remedyFor(issue)}`);
  return issue;
}

export function listPermissionIssues(): PermissionIssueRow[] {
  const rows = db.prepare("select action, service, contexts, first_seen, last_seen, count, last_message from permission_issues order by last_seen desc, action").all() as (Omit<PermissionIssueRow, "contexts"> & { contexts: string })[];
  return rows.map((r) => { let c: string[] = []; try { c = JSON.parse(r.contexts); } catch { /* keep empty */ } return { ...r, contexts: c }; });
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
 * The complete read-only policy the advisor needs (kept in step with the README's "IAM permissions" section).
 * The SSM statements follow PROBE_DOCUMENT: a custom document gets SendCommand scoped to it, the stock
 * AWS-RunShellScript is the zero-setup fallback.
 */
export const recommendedPolicy = (accountId = "*"): IamPolicy => ({
  Version: "2012-10-17",
  Statement: [
    {
      Sid: "AdvisorReadOnly",
      Effect: "Allow",
      Action: [
        "ec2:Describe*",
        "rds:Describe*", "rds:ListTagsForResource", "rds:DownloadDBLogFilePortion",
        "pi:DescribeDimensionKeys", "pi:GetResourceMetadata",
        "elasticache:Describe*", "elasticache:ListTagsForResource",
        "cloudwatch:GetMetricStatistics", "cloudwatch:GetMetricData", "cloudwatch:ListMetrics",
        "logs:DescribeLogGroups", "logs:DescribeLogStreams", "logs:ListTagsForResource",
        "ce:GetCostAndUsage", "ce:GetCostAndUsageWithResources", "ce:GetSavingsPlansUtilization", "ce:GetSavingsPlansCoverage", "ce:GetReservationUtilization",
        "savingsplans:DescribeSavingsPlans",
        "pricing:GetProducts",
        "support:DescribeSeverityLevels",
        "ssm:DescribeInstanceInformation",
        "s3:ListAllMyBuckets", "s3:GetBucketLocation", "s3:GetLifecycleConfiguration", "s3:GetBucketTagging", "s3:GetBucketVersioning", "s3:GetBucketPolicyStatus",
        "lambda:ListFunctions", "lambda:GetFunction*", "lambda:GetPolicy", "lambda:ListTags",
        "ecr:DescribeRepositories", "ecr:DescribeImages", "ecr:ListImages", "ecr:GetLifecyclePolicy", "ecr:ListTagsForResource",
        "ecs:Describe*", "ecs:List*",
        "eks:Describe*", "eks:List*",
        "dynamodb:Describe*", "dynamodb:List*",
        "application-autoscaling:DescribeScalableTargets",
        "elasticloadbalancing:Describe*",
        "secretsmanager:ListSecrets", "secretsmanager:DescribeSecret",
        "cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus", "cloudtrail:ListTags", "cloudtrail:LookupEvents",
        "cloudfront:List*", "cloudfront:Get*",
        "route53:List*", "route53:Get*",
        "elasticbeanstalk:DescribeEnvironments",
        "redshift:Describe*",
        "elasticmapreduce:List*", "elasticmapreduce:Describe*",
        "apigateway:GET",
        "tag:GetResources",
        "sts:GetCallerIdentity",
        "iam:ListAccountAliases",
      ],
      Resource: "*",
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
export const actuatorPolicy = (): IamPolicy => ({
  Version: "2012-10-17",
  Statement: [
    { Sid: "ActuatorIdentity", Effect: "Allow", Action: ["sts:GetCallerIdentity"], Resource: "*" },
    { Sid: "ActuatorServerlessCapacity", Effect: "Allow", Action: ["rds:ModifyDBCluster", "rds:DescribeDBClusters", "rds:ListTagsForResource"], Resource: "*" },
    { Sid: "ActuatorSnapshotTier", Effect: "Allow", Action: ["ec2:ModifySnapshotTier", "ec2:RestoreSnapshotTier", "ec2:DescribeSnapshots", "ec2:DescribeSnapshotTierStatus"], Resource: "*" },
    { Sid: "ActuatorHandsOff", Effect: "Deny", Action: ["rds:ModifyDBCluster", "ec2:ModifySnapshotTier", "ec2:RestoreSnapshotTier"], Resource: "*", Condition: { StringLike: { "aws:ResourceTag/advisor:hands-off": "*" } } },
  ],
});

/** The trust policy the actuator role needs: the advisor's read identity (role or user ARN) may assume it. */
export const actuatorTrustPolicy = (readIdentityArn = "<the advisor's read role or user ARN>") => ({
  Version: "2012-10-17",
  Statement: [{ Sid: "AdvisorExecutor", Effect: "Allow", Principal: { AWS: readIdentityArn }, Action: "sts:AssumeRole" }],
});

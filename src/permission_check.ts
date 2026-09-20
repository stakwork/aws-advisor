import { DescribeDocumentCommand, DescribeInstanceInformationCommand, SSMClient } from "@aws-sdk/client-ssm";
import { config } from "./config.js";
import { getJsonSetting, setSetting } from "./db.js";
import { AWS_RUN_SHELL_SCRIPT, PermissionIssue, clearPermissionIssues, explainPermissionError, listPermissionIssues, policyForIssues, recordPermissionIssue, remedyFor, tableForAction } from "./permissions.js";
import { CloudTrailClient, LookupEventsCommand } from "@aws-sdk/client-cloudtrail";
import { ProbeError, probeDocumentInfo, probeInstance } from "./ssm.js";
import { NoSdkCredentials } from "./aws_config.js";
import { S, credentialsMeta, queryReadOnly, sdkCredentials, sdkIdentity } from "./steampipe.js";

/**
 * The permission check (POST /api/permissions/check): one cheap probe per capability the app uses, each a
 * `select 1 ... limit 1` on the relevant Steampipe table pinned to one region, plus the SSM calls the probe
 * makes through the SDK. A denial becomes a permission issue with its IAM statement; anything else that
 * fails is reported as a non-permission error. The last result is kept in settings for GET /api/permissions.
 */

export type CapabilityStatus = "ok" | "missing" | "error" | "skipped";

export interface CapabilityResult {
  id: string;
  label: string;
  group: string;
  actions: string[];
  status: CapabilityStatus;
  message?: string;
  issue?: PermissionIssue;
  took_ms: number;
}

export interface PermissionCheckResult {
  /** recorded issues outside the capability list, proved again on this check */
  reverified?: { action: string; status: "ok" | "missing" | "error"; message: string }[];
  checked_at: string;
  account_id: string | null;
  region: string;
  /** Set when the credentials themselves were rejected (expired, invalid): permissions cannot be judged until they are fixed. */
  credentials_error?: string;
  results: CapabilityResult[];
  missing: string[];
  policy: ReturnType<typeof policyForIssues>;
  took_ms: number;
}

interface Capability {
  id: string;
  label: string;
  group: string;
  actions: string[];
  /** Builds the probe SQL; region and account are the one region / account the check pins itself to. */
  sql?: (ctx: { region: string; account: string; regionQual: string }) => string;
  /** SDK-side check instead of SQL. Throws an AWS error, returns a message on success, or returns { skipped } */
  sdk?: (ctx: CheckContext) => Promise<string | { skipped: string }>;
}

interface CheckContext { region: string; account: string; instanceId?: string }

const PROBE_TIMEOUT_MS = 60_000;
const CONCURRENCY = 3;

const table = (t: string, where = "") => ({ regionQual }: { regionQual: string }) => `select 1 from ${S}.${t} ${where ? `where ${where}${regionQual ? ` and ${regionQual}` : ""}` : regionQual ? `where ${regionQual}` : ""} limit 1`;
const global = (t: string, where = "") => () => `select 1 from ${S}.${t}${where ? ` where ${where}` : ""} limit 1`;

const lastMonth = "period_start >= date_trunc('month', now() - interval '1 month') and period_start < date_trunc('month', now())";

export const CAPABILITIES: Capability[] = [
  // Which credential mode is in use and whether the SDK side can resolve it (a profile that needs `aws sso login`, a host
  // without an instance role, a role that refuses the assumption): sts:GetCallerIdentity through the same provider the probe uses.
  { id: "credentials", label: "Credentials (SDK identity)", group: "core", actions: ["sts:GetCallerIdentity"],
    sdk: async () => {
      const meta = credentialsMeta();
      const r = await sdkIdentity();
      if (!r.ok) throw new CredentialsError(`${meta ? `mode ${meta.mode} (${meta.label}): ` : ""}${r.error}`);
      return `mode ${meta?.mode ?? "keys"} (${r.describe}): ${r.arn}`;
    } },
  { id: "account", label: "Account identity (aws_account)", group: "core", actions: ["sts:GetCallerIdentity", "iam:ListAccountAliases"], sql: global("aws_account") },
  { id: "ec2_instances", label: "EC2 instances", group: "compute", actions: ["ec2:DescribeInstances"], sql: table("aws_ec2_instance") },
  { id: "ebs_volumes", label: "EBS volumes", group: "compute", actions: ["ec2:DescribeVolumes"], sql: table("aws_ebs_volume") },
  { id: "ebs_snapshots", label: "EBS snapshots (owned)", group: "compute", actions: ["ec2:DescribeSnapshots"], sql: ({ account, regionQual }) => `select 1 from ${S}.aws_ebs_snapshot where owner_id = '${account}' and ${regionQual} limit 1` },
  { id: "eips", label: "Elastic IPs", group: "network", actions: ["ec2:DescribeAddresses"], sql: table("aws_vpc_eip") },
  { id: "nat_gateways", label: "NAT gateways", group: "network", actions: ["ec2:DescribeNatGateways"], sql: table("aws_vpc_nat_gateway") },
  { id: "flow_logs", label: "VPC flow logs", group: "network", actions: ["ec2:DescribeFlowLogs"], sql: table("aws_vpc_flow_log") },
  { id: "vpc_endpoints", label: "VPC endpoints", group: "network", actions: ["ec2:DescribeVpcEndpoints"], sql: table("aws_vpc_endpoint") },
  { id: "log_groups", label: "CloudWatch log groups", group: "monitoring", actions: ["logs:DescribeLogGroups"], sql: table("aws_cloudwatch_log_group") },
  { id: "cloudwatch_metrics", label: "CloudWatch metric statistics", group: "monitoring", actions: ["cloudwatch:GetMetricStatistics"],
    sql: ({ regionQual }) => `select 1 from ${S}.aws_cloudwatch_metric_statistic_data_point where namespace = 'AWS/EC2' and metric_name = 'CPUUtilization' and timestamp between now() - interval '2 hours' and now() and period = 3600 and ${regionQual} limit 1` },
  { id: "ec2_cpu_daily", label: "EC2 daily CPU metrics", group: "monitoring", actions: ["cloudwatch:GetMetricStatistics", "ec2:DescribeInstances"], sql: table("aws_ec2_instance_metric_cpu_utilization_daily") },
  { id: "rds_instances", label: "RDS instances", group: "databases", actions: ["rds:DescribeDBInstances"], sql: table("aws_rds_db_instance") },
  { id: "rds_clusters", label: "RDS clusters", group: "databases", actions: ["rds:DescribeDBClusters"], sql: table("aws_rds_db_cluster") },
  { id: "elasticache", label: "ElastiCache clusters", group: "databases", actions: ["elasticache:DescribeCacheClusters"], sql: table("aws_elasticache_cluster") },
  { id: "savings_plans", label: "Savings Plans", group: "commitments", actions: ["savingsplans:DescribeSavingsPlans"], sql: global("aws_savingsplans_savings_plan") },
  { id: "ec2_reservations", label: "EC2 reserved instances", group: "commitments", actions: ["ec2:DescribeReservedInstances"], sql: table("aws_ec2_reserved_instance") },
  { id: "rds_reservations", label: "RDS reserved instances", group: "commitments", actions: ["rds:DescribeReservedDBInstances"], sql: table("aws_rds_reserved_db_instance") },
  { id: "elasticache_reservations", label: "ElastiCache reserved nodes", group: "commitments", actions: ["elasticache:DescribeReservedCacheNodes"], sql: table("aws_elasticache_reserved_cache_node") },
  { id: "cost_by_record_type", label: "Cost Explorer: by record type", group: "billing", actions: ["ce:GetCostAndUsage"], sql: global("aws_cost_by_record_type_monthly", lastMonth) },
  { id: "cost_usage", label: "Cost Explorer: service by record type", group: "billing", actions: ["ce:GetCostAndUsage"],
    sql: global("aws_cost_usage", `granularity = 'MONTHLY' and dimension_type_1 = 'SERVICE' and dimension_type_2 = 'RECORD_TYPE' and ${lastMonth}`) },
  { id: "cost_by_usage_type", label: "Cost Explorer: service by usage type", group: "billing", actions: ["ce:GetCostAndUsage"], sql: global("aws_cost_by_service_usage_type_monthly", lastMonth) },
  { id: "pricing", label: "Price list", group: "billing", actions: ["pricing:GetProducts"],
    sql: ({ region }) => `select 1 from ${S}.aws_pricing_product where service_code = 'AmazonEC2' and term = 'OnDemand' and filters = '${JSON.stringify({ regionCode: region, instanceType: "t3.micro", operatingSystem: "Linux", tenancy: "Shared", preInstalledSw: "NA", capacitystatus: "Used" })}' limit 1` },
  { id: "ssm_managed_instances", label: "SSM managed instances", group: "ssm", actions: ["ssm:DescribeInstanceInformation"], sql: table("aws_ssm_managed_instance") },
  { id: "s3", label: "S3 buckets", group: "benchmarks", actions: ["s3:ListAllMyBuckets"], sql: global("aws_s3_bucket") },
  { id: "lambda", label: "Lambda functions", group: "benchmarks", actions: ["lambda:ListFunctions"], sql: table("aws_lambda_function") },
  { id: "ecr", label: "ECR repositories", group: "benchmarks", actions: ["ecr:DescribeRepositories"], sql: table("aws_ecr_repository") },
  { id: "ecs", label: "ECS clusters", group: "benchmarks", actions: ["ecs:ListClusters", "ecs:DescribeClusters"], sql: table("aws_ecs_cluster") },
  { id: "eks", label: "EKS clusters", group: "benchmarks", actions: ["eks:ListClusters", "eks:DescribeCluster"], sql: table("aws_eks_cluster") },
  { id: "dynamodb", label: "DynamoDB tables", group: "benchmarks", actions: ["dynamodb:ListTables", "dynamodb:DescribeTable"], sql: table("aws_dynamodb_table") },
  { id: "secretsmanager", label: "Secrets Manager secrets", group: "benchmarks", actions: ["secretsmanager:ListSecrets"], sql: table("aws_secretsmanager_secret") },
  { id: "cloudtrail", label: "CloudTrail trails", group: "benchmarks", actions: ["cloudtrail:DescribeTrails"], sql: table("aws_cloudtrail_trail") },
  { id: "cloudfront", label: "CloudFront distributions", group: "benchmarks", actions: ["cloudfront:ListDistributions"], sql: global("aws_cloudfront_distribution") },
  { id: "route53", label: "Route 53 zones", group: "benchmarks", actions: ["route53:ListHostedZones"], sql: global("aws_route53_zone") },
  { id: "redshift", label: "Redshift clusters", group: "benchmarks", actions: ["redshift:DescribeClusters"], sql: table("aws_redshift_cluster") },
  { id: "emr", label: "EMR clusters", group: "benchmarks", actions: ["elasticmapreduce:ListClusters"], sql: table("aws_emr_cluster") },
  { id: "apigateway", label: "API Gateway stages", group: "benchmarks", actions: ["apigateway:GET"], sql: table("aws_api_gateway_stage") },
  // SDK-side: what the probe itself does, with the same credentials the probe reads from the connection file.
  { id: "ssm_describe_sdk", label: "SSM DescribeInstanceInformation (SDK)", group: "ssm", actions: ["ssm:DescribeInstanceInformation"],
    sdk: async (ctx) => { const c = ssmClient(ctx); try { const r = await c.send(new DescribeInstanceInformationCommand({ MaxResults: 5 })); return `${r.InstanceInformationList?.length ?? 0} managed instance(s) in the first page`; } finally { c.destroy(); } } },
  { id: "ssm_document", label: `SSM probe document (${config.probeDocument})`, group: "ssm", actions: ["ssm:DescribeDocument"],
    sdk: async (ctx) => { const c = ssmClient(ctx); try { const r = await c.send(new DescribeDocumentCommand({ Name: config.probeDocument })); return `${r.Document?.Name} v${r.Document?.DocumentVersion} (${r.Document?.Owner}), ${r.Document?.Description || "no description"}`; } finally { c.destroy(); } } },
  { id: "ssm_probe", label: "SSM probe (SendCommand + GetCommandInvocation)", group: "ssm", actions: ["ssm:SendCommand", "ssm:GetCommandInvocation"],
    sdk: async (ctx) => {
      if (!ctx.instanceId) return { skipped: "pass instance_id (an SSM-online Linux instance) to run the real probe once; SendCommand has no dry run" };
      const p = await probeInstance(ctx.instanceId);
      return `probed ${ctx.instanceId} at ${p.collected_at}: ${p.data.hostname}, ${p.data.cpus} CPUs`;
    } },
];

function ssmClient(ctx: CheckContext): SSMClient {
  const creds = sdkCredentials(); // throws NoSdkCredentials when nothing is configured
  return new SSMClient({ region: creds.region || ctx.region, credentials: creds.provider });
}

/** The SDK side could not resolve credentials at all (reported as an error with the remedy, never as a missing permission). */
class CredentialsError extends Error {}

let inflight: Promise<PermissionCheckResult> | null = null;

/** Runs every capability probe (a few at a time); concurrent calls share one run. */
export function checkPermissions(opts: { instanceId?: string } = {}): Promise<PermissionCheckResult> {
  if (!inflight) inflight = run(opts).finally(() => { inflight = null; });
  return inflight;
}

async function run(opts: { instanceId?: string }): Promise<PermissionCheckResult> {
  const t0 = Date.now();
  const meta = credentialsMeta();
  const region = meta?.defaultRegion && meta.defaultRegion !== "*" ? meta.defaultRegion : "us-east-1";
  let account: string | null = null;
  try {
    const { rows } = await queryReadOnly<{ account_id: string }>(`select account_id from ${S}.aws_account limit 1`, { timeoutMs: PROBE_TIMEOUT_MS });
    account = rows[0]?.account_id ?? null;
  } catch { /* the account capability reports it */ }
  const ctx: CheckContext = { region, account: account || "", instanceId: opts.instanceId };
  const regionQual = `region = '${region.replace(/'/g, "''")}'`;

  const results: CapabilityResult[] = new Array(CAPABILITIES.length);
  const queue = CAPABILITIES.map((c, i) => ({ c, i }));
  const worker = async () => {
    for (let next = queue.shift(); next; next = queue.shift()) results[next.i] = await runOne(next.c, ctx, regionQual);
  };
  await Promise.all(Array.from({ length: CONCURRENCY }, worker));

  const accountMsg = results.find((r) => r.id === "account")?.message || "";
  const credentialsError = /ExpiredToken|InvalidClientTokenId|UnrecognizedClient|InvalidSignature|SignatureDoesNotMatch|InvalidAccessKeyId/.exec(accountMsg)?.[0];
  const sdkCreds = results.find((r) => r.id === "credentials");
  const okActions = results.filter((r) => r.status === "ok").flatMap((r) => r.actions);
  const missingActions = new Set(results.filter((r) => r.status === "missing").map((r) => r.issue!.action));
  clearPermissionIssues(okActions.filter((a) => !missingActions.has(a)));
  // Recorded issues the capabilities above do not cover (an agent query on some table, the CloudTrail feed):
  // prove each one again with the cheapest call that needs the action, and drop the ones that work now.
  const covered = new Set(results.flatMap((r) => r.actions));
  const reverified: { action: string; status: "ok" | "missing" | "error"; message: string }[] = [];
  for (const issue of listPermissionIssues()) {
    if (covered.has(issue.action)) continue;
    try {
      if (issue.action === "cloudtrail:LookupEvents") {
        const creds = sdkCredentials();
        const client = new CloudTrailClient({ region, credentials: creds.provider });
        try { await client.send(new LookupEventsCommand({ StartTime: new Date(Date.now() - 60_000), EndTime: new Date(), MaxResults: 1 })); } finally { client.destroy(); }
      } else {
        const table = tableForAction(issue.action);
        if (!table) { reverified.push({ action: issue.action, status: "error", message: "no probe for this action; dismiss it once the policy carries it" }); continue; }
        await queryReadOnly(`select 1 from ${S}.${table} where ${regionQual} limit 1`, { timeoutMs: PROBE_TIMEOUT_MS });
      }
      clearPermissionIssues([issue.action]);
      reverified.push({ action: issue.action, status: "ok", message: "works now; cleared" });
    } catch (e: any) {
      const still = explainPermissionError(e, `re-check ${issue.action}`);
      reverified.push({ action: issue.action, status: still ? "missing" : "error", message: String(e?.message || e).slice(0, 200) });
    }
  }
  const issues = results.filter((r) => r.issue).map((r) => r.issue!);
  const out: PermissionCheckResult = {
    checked_at: new Date().toISOString(),
    account_id: account,
    region,
    reverified,
    ...(credentialsError ? { credentials_error: `The credentials of the "${S}" connection were rejected (${credentialsError}); ${meta?.mode === "profile" ? `refresh the profile (for SSO: \`aws sso login --profile ${meta.profile}\`)` : meta?.mode === "chain" ? "check the instance or environment credentials" : "save valid credentials in Settings"}, then check again. Nothing below says anything about permissions.` }
      : sdkCreds?.status === "error" ? { credentials_error: `The advisor's own AWS SDK calls (SSM probe, identity) cannot resolve credentials: ${sdkCreds.message}` } : {}),
    results,
    missing: [...missingActions].sort(),
    policy: policyForIssues(issues),
    took_ms: Date.now() - t0,
  };
  setSetting("permission_check", JSON.stringify(out));
  console.log(`[permissions] check: ${results.filter((r) => r.status === "ok").length} ok, ${out.missing.length} missing, ${results.filter((r) => r.status === "error").length} errors in ${out.took_ms} ms`);
  return out;
}

async function runOne(c: Capability, ctx: CheckContext, regionQual: string): Promise<CapabilityResult> {
  const t0 = Date.now();
  const base = { id: c.id, label: c.label, group: c.group, actions: c.actions };
  const done = (r: Omit<CapabilityResult, "id" | "label" | "group" | "actions" | "took_ms">): CapabilityResult => ({ ...base, ...r, took_ms: Date.now() - t0 });
  const context = `permission check ${c.id} (${c.actions.join(", ")})`;
  try {
    if (c.sdk) {
      const r = await c.sdk(ctx);
      if (typeof r === "object") return done({ status: "skipped", message: r.skipped });
      return done({ status: "ok", message: r });
    }
    if (c.sql) {
      if (c.id === "ebs_snapshots" && !ctx.account) return done({ status: "error", message: "account id unknown (the account check failed), cannot scope the snapshot query" });
      await queryReadOnly(c.sql({ region: ctx.region, account: ctx.account.replace(/'/g, "''"), regionQual }), { timeoutMs: PROBE_TIMEOUT_MS });
      return done({ status: "ok" });
    }
    return done({ status: "skipped", message: "no probe defined" });
  } catch (e: any) {
    if (e instanceof NoSdkCredentials || e instanceof CredentialsError) return done({ status: "error", message: e.message });
    if (e instanceof ProbeError) {
      if (e.code === "permission" && e.issue) return done({ status: "missing", issue: recordPermissionIssue(e.issue), message: e.message });
      return done({ status: "error", message: `${e.code}: ${e.message}` });
    }
    const issue = explainPermissionError(e, context);
    if (issue) return done({ status: "missing", issue: recordPermissionIssue(issue), message: `${String(e?.message || e).slice(0, 400)}. ${remedyFor(issue)}` });
    const msg = String(e?.message || e).replace(/^rpc error: code = \w+ desc = /, "").slice(0, 400);
    if (c.id === "ssm_document" && /InvalidDocument\b/i.test(`${e?.name || ""} ${msg}`)) {
      const info = probeDocumentInfo();
      return done({ status: "error", message: `SSM document ${config.probeDocument} does not exist in ${ctx.region}${config.probeDocument === AWS_RUN_SHELL_SCRIPT ? "" : `; create it with: ${info.create_command}`}. ${msg}` });
    }
    return done({ status: "error", message: msg });
  }
}

/** The last stored check, or null. */
export const lastPermissionCheck = () => getJsonSetting<PermissionCheckResult | null>("permission_check", null);

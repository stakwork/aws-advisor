import { DescribeDocumentCommand, DescribeInstanceInformationCommand, SSMClient } from "@aws-sdk/client-ssm";
import { config } from "./config.js";
import { getJsonSetting, setSetting } from "./db.js";
import { AWS_RUN_SHELL_SCRIPT, PermissionIssue, clearPermissionIssues, explainPermissionError, listPermissionIssues, policyForIssues, recordPermissionIssue, remedyFor, tableForAction } from "./permissions.js";
import { CloudTrailClient, LookupEventsCommand } from "@aws-sdk/client-cloudtrail";
import { ProbeError, probeDocumentInfo, probeInstance } from "./ssm.js";
import { NoSdkCredentials, memberConnectionName, parentConnectionName } from "./aws_config.js";
import { S, credentialsMeta, queryReadOnly, sdkCredentials, sdkIdentity } from "./steampipe.js";
import { accountCredentials, listMembers } from "./accounts.js";
import { GetCallerIdentityCommand, STSClient } from "@aws-sdk/client-sts";

/**
 * The permission check (POST /api/permissions/check): one cheap probe per capability the app uses, each a
 * `select 1 ... limit 1` on the relevant Steampipe table pinned to one region, plus the SSM calls the probe
 * makes through the SDK. A denial becomes a permission issue with its IAM statement; anything else that
 * fails is reported as a non-permission error. The last result is kept in settings for GET /api/permissions.
 *
 * Per account (src/accounts.ts): the parent is checked through its own Steampipe connection (`<schema>_p` once
 * there are members, the schema itself otherwise) and its own SDK credentials; a member through its connection
 * (`<schema>_<account id>`) and its read role assumed from the parent, so the result says what *that* account's
 * role lacks. One stored result per account (`permission_check` for the parent, `permission_check:<id>` for a member).
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
  /** which account was checked: the parent or a member (src/accounts.ts), and the Steampipe connection it went through */
  target: { account_id: string; name: string; is_parent: boolean; schema: string };
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
  /** Builds the probe SQL; region and account are the one region / account the check pins itself to, schema the account's Steampipe connection. */
  sql?: (ctx: { region: string; account: string; regionQual: string; schema: string }) => string;
  /** SDK-side check instead of SQL. Throws an AWS error, returns a message on success, or returns { skipped } */
  sdk?: (ctx: CheckContext) => Promise<string | { skipped: string }>;
}

/** The account under check: its Steampipe connection (schema) and the SDK credentials of that account. */
export interface CheckTarget { account_id: string; name: string; is_parent: boolean; schema: string; region: string }
interface CheckContext extends CheckTarget { account: string; instanceId?: string; creds: { provider: SdkProvider; region: string } }
type SdkProvider = ReturnType<typeof sdkCredentials>["provider"];

const PROBE_TIMEOUT_MS = 60_000;
const CONCURRENCY = 3;

const table = (t: string, where = "") => ({ regionQual, schema }: { regionQual: string; schema: string }) => `select 1 from ${schema}.${t} ${where ? `where ${where}${regionQual ? ` and ${regionQual}` : ""}` : regionQual ? `where ${regionQual}` : ""} limit 1`;
const global = (t: string, where = "") => ({ schema }: { schema: string }) => `select 1 from ${schema}.${t}${where ? ` where ${where}` : ""} limit 1`;

const lastMonth = "period_start >= date_trunc('month', now() - interval '1 month') and period_start < date_trunc('month', now())";

export const CAPABILITIES: Capability[] = [
  // Which credential mode is in use and whether the SDK side can resolve it (a profile that needs `aws sso login`, a host
  // without an instance role, a role that refuses the assumption): sts:GetCallerIdentity through the same provider the probe uses.
  { id: "credentials", label: "Credentials (SDK identity)", group: "core", actions: ["sts:GetCallerIdentity"],
    sdk: async (ctx) => {
      if (!ctx.is_parent) {
        // the member's read role assumed from the parent's identity (src/accounts.ts accountCredentials)
        const sts = new STSClient({ region: ctx.creds.region, credentials: ctx.creds.provider });
        try { const r = await sts.send(new GetCallerIdentityCommand({})); return `member ${ctx.name}, read role assumed from the parent: ${r.Arn}`; }
        catch (e: any) { throw new CredentialsError(`the parent's identity could not assume member ${ctx.account_id}'s read role: ${String(e?.message || e).slice(0, 300)}`); }
        finally { sts.destroy(); }
      }
      const meta = credentialsMeta();
      const r = await sdkIdentity();
      if (!r.ok) throw new CredentialsError(`${meta ? `mode ${meta.mode} (${meta.label}): ` : ""}${r.error}`);
      return `mode ${meta?.mode ?? "keys"} (${r.describe}): ${r.arn}`;
    } },
  { id: "account", label: "Account identity (aws_account)", group: "core", actions: ["sts:GetCallerIdentity", "iam:ListAccountAliases"], sql: global("aws_account") },
  { id: "ec2_instances", label: "EC2 instances", group: "compute", actions: ["ec2:DescribeInstances"], sql: table("aws_ec2_instance") },
  { id: "ebs_volumes", label: "EBS volumes", group: "compute", actions: ["ec2:DescribeVolumes"], sql: table("aws_ebs_volume") },
  { id: "ebs_snapshots", label: "EBS snapshots (owned)", group: "compute", actions: ["ec2:DescribeSnapshots"], sql: ({ account, regionQual, schema }) => `select 1 from ${schema}.aws_ebs_snapshot where owner_id = '${account}' and ${regionQual} limit 1` },
  { id: "eips", label: "Elastic IPs", group: "network", actions: ["ec2:DescribeAddresses"], sql: table("aws_vpc_eip") },
  { id: "nat_gateways", label: "NAT gateways", group: "network", actions: ["ec2:DescribeNatGateways"], sql: table("aws_vpc_nat_gateway") },
  { id: "flow_logs", label: "VPC flow logs", group: "network", actions: ["ec2:DescribeFlowLogs"], sql: table("aws_vpc_flow_log") },
  { id: "vpc_endpoints", label: "VPC endpoints", group: "network", actions: ["ec2:DescribeVpcEndpoints"], sql: table("aws_vpc_endpoint") },
  { id: "log_groups", label: "CloudWatch log groups", group: "monitoring", actions: ["logs:DescribeLogGroups"], sql: table("aws_cloudwatch_log_group") },
  { id: "cloudwatch_metrics", label: "CloudWatch metric statistics", group: "monitoring", actions: ["cloudwatch:GetMetricStatistics"],
    sql: ({ regionQual, schema }) => `select 1 from ${schema}.aws_cloudwatch_metric_statistic_data_point where namespace = 'AWS/EC2' and metric_name = 'CPUUtilization' and timestamp between now() - interval '2 hours' and now() and period = 3600 and ${regionQual} limit 1` },
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
    sql: ({ region, schema }) => `select 1 from ${schema}.aws_pricing_product where service_code = 'AmazonEC2' and term = 'OnDemand' and filters = '${JSON.stringify({ regionCode: region, instanceType: "t3.micro", operatingSystem: "Linux", tenancy: "Shared", preInstalledSw: "NA", capacitystatus: "Used" })}' limit 1` },
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
  { id: "ssm_document", label: `SSM probe documents (${config.probeDocument}-<kind>)`, group: "ssm", actions: ["ssm:DescribeDocument"],
    sdk: async (ctx) => { const { probeDocumentStatus } = await import("./probes_status.js"); const st = await probeDocumentStatus(ctx.region, ctx.creds); const missing = st.filter((d) => d.status === "missing").map((d) => d.name); const stale = st.filter((d) => d.status === "stale").map((d) => d.name);
      if (st.some((d) => d.status === "error")) throw new Error(st.find((d) => d.status === "error")!.error || "DescribeDocument failed");
      return `${st.filter((d) => d.status === "current").length}/${st.length} current${stale.length ? `; stale: ${stale.join(", ")}` : ""}${missing.length ? `; missing: ${missing.join(", ")} (Settings > Probes has the create commands)` : ""}`; } },
  { id: "ssm_probe", label: "SSM probe (SendCommand + GetCommandInvocation)", group: "ssm", actions: ["ssm:SendCommand", "ssm:GetCommandInvocation"],
    sdk: async (ctx) => {
      if (!ctx.instanceId) return { skipped: "pass instance_id (an SSM-online Linux instance) to run the real probe once; SendCommand has no dry run" };
      const p = await probeInstance(ctx.instanceId, { kind: "host", accountId: ctx.is_parent ? null : ctx.account_id });
      return `probed ${ctx.instanceId} (host probe) at ${p.collected_at}: ${p.data.hostname}, ${p.data.cpus} CPUs`;
    } },
];

function ssmClient(ctx: CheckContext): SSMClient {
  return new SSMClient({ region: ctx.region || ctx.creds.region, credentials: ctx.creds.provider });
}

/**
 * Which Steampipe connection an account's check goes through. Without members the schema is the one connection;
 * with members the schema is an aggregator over all of them, so the parent is pinned to `<schema>_p` and a member
 * to `<schema>_<id>`, each a plain connection with that account's credentials. Pure.
 */
export function connectionSchemaFor(schema: string, accountId: string | null | undefined, parentId: string, memberIds: string[]): string {
  if (accountId && accountId !== parentId && memberIds.includes(accountId)) return memberConnectionName(schema, accountId);
  return memberIds.length ? parentConnectionName(schema) : schema;
}

/** The account a check is for: the parent (null, '' or its own id), or a registered, enabled member. Throws for an unknown id. */
export function checkTargetFor(accountId: string | null | undefined): CheckTarget {
  const meta = credentialsMeta();
  const parentId = meta?.accountId || "";
  const members = listMembers().filter((m) => m.enabled);
  const schema = connectionSchemaFor(S, accountId, parentId, members.map((m) => m.account_id));
  const defaultRegion = meta?.defaultRegion && meta.defaultRegion !== "*" ? meta.defaultRegion : "us-east-1";
  if (!accountId || accountId === parentId) return { account_id: parentId, name: "parent", is_parent: true, schema, region: defaultRegion };
  const m = members.find((x) => x.account_id === accountId);
  if (!m) throw new Error(`account ${accountId} is not a registered, enabled member (Settings › Member accounts)`);
  const region = m.regions?.[0] && m.regions[0] !== "*" ? m.regions[0] : defaultRegion;
  return { account_id: m.account_id, name: m.name, is_parent: false, schema, region };
}

/** The SDK side could not resolve credentials at all (reported as an error with the remedy, never as a missing permission). */
class CredentialsError extends Error {}

const inflight = new Map<string, Promise<PermissionCheckResult>>();

/** Runs every capability probe (a few at a time) for one account (the parent by default); concurrent calls for the same account share one run. */
export function checkPermissions(opts: { instanceId?: string; accountId?: string | null } = {}): Promise<PermissionCheckResult> {
  const target = checkTargetFor(opts.accountId);
  const key = target.is_parent ? "" : target.account_id;
  if (!inflight.has(key)) inflight.set(key, run(opts, target).finally(() => { inflight.delete(key); }));
  return inflight.get(key)!;
}

/** The settings key the result of an account's check is kept under. */
const resultKey = (target: Pick<CheckTarget, "account_id" | "is_parent">) => (target.is_parent ? "permission_check" : `permission_check:${target.account_id}`);

async function run(opts: { instanceId?: string }, target: CheckTarget): Promise<PermissionCheckResult> {
  const t0 = Date.now();
  const meta = credentialsMeta();
  const region = target.region;
  // the account's SDK credentials: the parent's own, or the member's read role assumed from them (throws NoSdkCredentials when nothing is configured)
  let creds: CheckContext["creds"];
  try { const c = accountCredentials(target.is_parent ? null : target.account_id); creds = { provider: c.provider, region: c.region }; }
  catch (e: any) {
    const message = e instanceof NoSdkCredentials ? e.message : String(e?.message || e);
    return { checked_at: new Date().toISOString(), account_id: target.account_id || null, target, region, credentials_error: `The advisor's own AWS SDK calls cannot resolve credentials: ${message}`, results: [], missing: [], policy: policyForIssues([]), took_ms: Date.now() - t0 };
  }
  let account: string | null = null;
  try {
    const { rows } = await queryReadOnly<{ account_id: string }>(`select account_id from ${target.schema}.aws_account limit 1`, { timeoutMs: PROBE_TIMEOUT_MS });
    account = rows[0]?.account_id ?? null;
  } catch { /* the account capability reports it */ }
  const ctx: CheckContext = { ...target, region, account: account || "", instanceId: opts.instanceId, creds };
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
        const client = new CloudTrailClient({ region, credentials: creds.provider });
        try { await client.send(new LookupEventsCommand({ StartTime: new Date(Date.now() - 60_000), EndTime: new Date(), MaxResults: 1 })); } finally { client.destroy(); }
      } else {
        const table = tableForAction(issue.action);
        if (!table) { reverified.push({ action: issue.action, status: "error", message: "no probe for this action; dismiss it once the policy carries it" }); continue; }
        await queryReadOnly(`select 1 from ${target.schema}.${table} where ${regionQual} limit 1`, { timeoutMs: PROBE_TIMEOUT_MS });
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
    target,
    region,
    reverified,
    ...(credentialsError ? { credentials_error: `The credentials of the "${target.schema}" connection were rejected (${credentialsError}); ${!target.is_parent ? `the parent's identity assumes member ${target.account_id}'s read role for it: check the role's trust policy (Settings › Member accounts)` : meta?.mode === "profile" ? `refresh the profile (for SSO: \`aws sso login --profile ${meta.profile}\`)` : meta?.mode === "chain" ? "check the instance or environment credentials" : "save valid credentials in Settings"}, then check again. Nothing below says anything about permissions.` }
      : sdkCreds?.status === "error" ? { credentials_error: `The advisor's own AWS SDK calls (SSM probe, identity) cannot resolve credentials: ${sdkCreds.message}` } : {}),
    results,
    missing: [...missingActions].sort(),
    policy: policyForIssues(issues),
    took_ms: Date.now() - t0,
  };
  setSetting(resultKey(target), JSON.stringify(out));
  console.log(`[permissions] check (${target.is_parent ? "parent" : `member ${target.account_id}`} via ${target.schema}): ${results.filter((r) => r.status === "ok").length} ok, ${out.missing.length} missing, ${results.filter((r) => r.status === "error").length} errors in ${out.took_ms} ms`);
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
      await queryReadOnly(c.sql({ region: ctx.region, account: ctx.account.replace(/'/g, "''"), regionQual, schema: ctx.schema }), { timeoutMs: PROBE_TIMEOUT_MS });
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

/** The last stored check of an account (the parent by default), or null. An unknown member id reads as null. */
export function lastPermissionCheck(accountId: string | null | undefined = null): PermissionCheckResult | null {
  let target: CheckTarget;
  try { target = checkTargetFor(accountId); } catch { return null; }
  return getJsonSetting<PermissionCheckResult | null>(resultKey(target), null);
}

/** Every account's last check in one line each, for the Permissions card's account picker and the Member accounts page. */
export function permissionCheckSummary(): { account_id: string; name: string; is_parent: boolean; schema: string; checked_at: string | null; ok: number; missing: number; errors: number; credentials_error: string | null }[] {
  const parentId = credentialsMeta()?.accountId || "";
  const members = listMembers().filter((m) => m.enabled);
  const targets: CheckTarget[] = [checkTargetFor(null), ...members.map((m) => checkTargetFor(m.account_id))];
  return targets.map((t) => {
    const last = getJsonSetting<PermissionCheckResult | null>(resultKey(t), null);
    const n = (status: CapabilityStatus) => last?.results.filter((r) => r.status === status).length ?? 0;
    return { account_id: t.account_id || parentId, name: t.name, is_parent: t.is_parent, schema: t.schema, checked_at: last?.checked_at ?? null, ok: n("ok"), missing: last?.missing.length ?? 0, errors: n("error"), credentials_error: last?.credentials_error ?? null };
  });
}

import assert from "node:assert/strict";
import { test } from "node:test";

const ACCT = "123456789012";
const R = "us-east-1";
const LB = `arn:aws:elasticloadbalancing:${R}:${ACCT}:loadbalancer/app/web/0123456789abcdef`;
const KEY = `arn:aws:kms:${R}:${ACCT}:key/11111111-2222-3333-4444-555555555555`;

test("acm: names, days left, generic status, SECURES to what uses it; public certificates cost nothing", async () => {
  const { acmRow } = await import("../services/acm.js");
  const now = Date.parse("2026-10-01T00:00:00Z");
  const r = acmRow({ certificate_arn: `arn:aws:acm:${R}:${ACCT}:certificate/abc`, domain_name: "example.com", subject_alternative_names: ["example.com", "*.example.com"], status: "ISSUED", type: "AMAZON_ISSUED",
    not_after: "2026-10-21T00:00:00Z", in_use_by: [LB], renewal_eligibility: "ELIGIBLE", region: R, account_id: ACCT }, now);
  assert.deepEqual(r.props.domains, ["example.com", "*.example.com"]);
  assert.equal(r.props.days_left, 20);
  assert.equal(r.props.status, "issued");
  assert.equal(r.props.issuer, "acm");
  assert.equal(r.props.wildcard, true);
  assert.equal(r.monthly_usd, 0);
  assert.deepEqual(r.links, [{ rel: "SECURES", other: LB, dir: "out" }]);
  const unused = acmRow({ certificate_arn: "arn:aws:acm:x", domain_name: "old.example.com", status: "EXPIRED", type: "IMPORTED", issuer: "Example CA", in_use_by: [], region: R, account_id: ACCT }, now);
  assert.equal(unused.props.in_use, false);
  assert.equal(unused.props.status, "expired");
  assert.equal(unused.props.issuer, "example ca");
});

test("kms: AWS-managed keys are free, the account's 1 USD, pending deletion 0; references resolve to the key's ARN", async () => {
  const { kmsRow } = await import("../services/kms.js");
  const { kmsResolver } = await import("../service_inventory.js");
  const own = kmsRow({ id: "11111111-2222-3333-4444-555555555555", arn: KEY, key_manager: "CUSTOMER", key_state: "Enabled", aliases: [{ AliasName: "alias/app" }], key_rotation_enabled: false, region: R, account_id: ACCT });
  assert.equal(own.monthly_usd, 1);
  assert.equal(own.name, "app");
  assert.equal(own.props.key_state, "enabled");
  assert.equal(own.props.managed, false);
  assert.equal(kmsRow({ arn: "arn:aws:kms:x", key_manager: "AWS", key_state: "Enabled", region: R, account_id: ACCT }).monthly_usd, 0);
  assert.equal(kmsRow({ arn: "arn:aws:kms:y", key_manager: "CUSTOMER", key_state: "PendingDeletion", region: R, account_id: ACCT }).props.key_state, "pending_deletion");
  const resolve = kmsResolver([own]);
  assert.equal(resolve("alias/app", ACCT, R), KEY);
  assert.equal(resolve("11111111-2222-3333-4444-555555555555", ACCT, R), KEY);
  assert.equal(resolve(`arn:aws:kms:${R}:${ACCT}:alias/app`, ACCT, R), KEY);
  // an alias it did not read stays an alias ARN (a ref in the graph), in the row's own account and region
  assert.equal(resolve("alias/aws/sns", ACCT, R), `arn:aws:kms:${R}:${ACCT}:alias/aws/sns`);
});

test("efs: storage by class plus provisioned throughput; mount targets give the network, subnets and groups", async () => {
  const { efsRow, efsMonthlyCost, EFS_PRICE } = await import("../services/efs.js");
  const r = efsRow({ file_system_id: "fs-0abc", arn: `arn:aws:elasticfilesystem:${R}:${ACCT}:file-system/fs-0abc`, life_cycle_state: "available", throughput_mode: "provisioned", provisioned_throughput_in_mibps: 2, encrypted: true, kms_key_id: KEY,
    size_in_bytes: { Value: 12e9, ValueInStandard: 10e9, ValueInIA: 2e9, ValueInArchive: 0 }, region: R, account_id: ACCT },
    [{ vpc_id: "vpc-0a", subnet_id: "subnet-0a", security_groups: ["sg-0a"] }, { vpc_id: "vpc-0a", subnet_id: "subnet-0b", security_groups: ["sg-0a"] }]);
  assert.equal(r.monthly_usd, Math.round((10 * EFS_PRICE.standard + 2 * EFS_PRICE.ia + 2 * EFS_PRICE.provisioned_mibps_month) * 100) / 100);
  assert.equal(r.props.kind, "file");
  assert.equal(r.props.class, "regional");
  const rels = r.links.map((l) => `${l.rel} ${l.other}${l.label ? ` ${l.label}` : ""}`).sort();
  assert.deepEqual(rels, ["ENCRYPTS " + KEY, "GUARDED_BY sg-0a AdvisorFilter", "IN_NETWORK vpc-0a AdvisorNetwork", "IN_SEGMENT subnet-0a AdvisorSegment", "IN_SEGMENT subnet-0b AdvisorSegment"]);
  assert.equal(efsMonthlyCost({ standard_bytes: 1e9, ia_bytes: 0, archive_bytes: 0, one_zone: true, provisioned_mibps: null }), EFS_PRICE.one_zone_standard);
});

test("waf: 5 USD an ACL, 1 USD a rule, requests at 0.60 per million; the rules read as lines; GUARDED_BY from what it protects", async () => {
  const { wafRow, WAF_PRICE } = await import("../services/waf.js");
  const rules = [
    { Name: "rate", Priority: 2, Action: { Block: {} }, Statement: { RateBasedStatement: { Limit: 1000 } } },
    { Name: "common", Priority: 1, OverrideAction: { None: {} }, Statement: { ManagedRuleGroupStatement: { VendorName: "AWS", Name: "AWSManagedRulesCommonRuleSet" } } },
  ];
  const r = wafRow({ name: "web", arn: `arn:aws:wafv2:${R}:${ACCT}:regional/webacl/web/1`, scope: "REGIONAL", default_action: { Allow: {} }, rules, associated_resources: [LB], region: R, account_id: ACCT },
    { sum: 1.5e6, days: 15 }, { sum: 0.5e6, days: 15 });
  assert.equal(r.props.requests_30d, 4e6);
  assert.equal(r.monthly_usd, WAF_PRICE.acl_month + 2 * WAF_PRICE.rule_month + 4 * WAF_PRICE.per_million_requests);
  assert.deepEqual(r.props.rule_list, ["1 common: managed AWS group AWSManagedRulesCommonRuleSet, rule actions", "2 rate: rate limit 1000 per 300s, block"]);
  assert.equal(r.props.default_action, "allow");
  assert.deepEqual(r.links, [{ rel: "GUARDED_BY", other: LB, dir: "in" }]);
});

test("athena: 5 USD per TB scanned when the workgroup publishes metrics, unpriced when it does not; results WRITES_TO the bucket", async () => {
  const { athenaRow, bucketOf } = await import("../services/athena.js");
  assert.equal(bucketOf("s3://results-bucket/prefix/"), "results-bucket");
  const r = athenaRow({ name: "primary", state: "ENABLED", publish_cloudwatch_metrics_enabled: true, output_location: "s3://results-bucket/x/", region: R, account_id: ACCT }, { sum: 1e12, days: 30 });
  assert.equal(r.id, `arn:aws:athena:${R}:${ACCT}:workgroup/primary`);
  assert.equal(r.monthly_usd, 5);
  assert.equal(r.props.output_encrypted, false);
  assert.deepEqual(r.links, [{ rel: "WRITES_TO", other: "results-bucket", dir: "out" }]);
  assert.equal(athenaRow({ name: "quiet", publish_cloudwatch_metrics_enabled: false, region: R, account_id: ACCT }).monthly_usd, null);
});

test("backup: a vault priced by stored GB per type, BACKED_UP_TO from what it holds; a plan STORES_IN its vaults and PROTECTS only ARNs it names", async () => {
  const { vaultRow, planRow, BACKUP_WARM_USD_GB, BACKUP_COLD_USD_GB } = await import("../services/backup.js");
  const vaultArn = `arn:aws:backup:${R}:${ACCT}:backup-vault:Default`;
  const v = vaultRow({ name: "Default", arn: vaultArn, number_of_recovery_points: 3, encryption_key_arn: KEY, region: R, account_id: ACCT },
    [{ backup_vault_arn: vaultArn, resource_type: "RDS", storage_class: "WARM", n: 2, bytes: 10e9, oldest: "2026-09-01T00:00:00Z", newest: "2026-09-30T00:00:00Z" },
     { backup_vault_arn: vaultArn, resource_type: "EBS", storage_class: "COLD", n: 1, bytes: 100e9, oldest: "2026-06-01T00:00:00Z", newest: "2026-06-01T00:00:00Z" }],
    [{ resource_arn: `arn:aws:rds:${R}:${ACCT}:db:app`, resource_type: "RDS", last_backup_time: "2026-09-30T00:00:00Z" }]);
  assert.equal(v.monthly_usd, Math.round((10 * BACKUP_WARM_USD_GB.RDS + 100 * BACKUP_COLD_USD_GB) * 100) / 100);
  assert.equal(v.props.oldest_at, "2026-06-01T00:00:00.000Z");
  assert.equal(v.props.newest_at, "2026-09-30T00:00:00.000Z");
  assert.ok(v.links.some((l) => l.rel === "BACKED_UP_TO" && l.dir === "in" && l.other.endsWith(":db:app")));
  const plan = planRow({ name: "daily", arn: `arn:aws:backup:${R}:${ACCT}:backup-plan:p1`, backup_plan_id: "p1", region: R, account_id: ACCT,
    backup_plan: { Rules: [{ RuleName: "daily", TargetBackupVaultName: "Default", ScheduleExpression: "cron(0 5 * * ? *)", Lifecycle: { DeleteAfterDays: 35 } }] } },
    [{ selection_name: "explicit", backup_plan_id: "p1", resources: [`arn:aws:ec2:${R}:${ACCT}:volume/vol-0a`, "arn:aws:ec2:*:*:volume/*"], list_of_tags: [] }], () => vaultArn);
  assert.deepEqual(plan.links.map((l) => `${l.rel} ${l.other}`), [`STORES_IN ${vaultArn}`, `PROTECTS arn:aws:ec2:${R}:${ACCT}:volume/vol-0a`]);
  assert.equal(plan.props.retention_days, 35);
  assert.equal(plan.props.keeps_forever, false);
  assert.match((plan.props.selections as string[])[0], /1 by ARN; arn:aws:ec2:\*:\*:volume\/\*/);
});

test("cloudformation: MANAGES what the graph can have a node for, network nodes by label, nested stacks PART_OF the parent", async () => {
  const { stackRow, managedTarget } = await import("../services/cloudformation.js");
  assert.deepEqual(managedTarget("AWS::Lambda::Function", "fn", R, ACCT), { id: `arn:aws:lambda:${R}:${ACCT}:function:fn` });
  assert.deepEqual(managedTarget("AWS::EC2::SecurityGroup", "sg-0a", R, ACCT), { id: "sg-0a", label: "AdvisorFilter" });
  assert.equal(managedTarget("AWS::IAM::Role", "role", R, ACCT), null);
  const parent = `arn:aws:cloudformation:${R}:${ACCT}:stack/root/1`;
  const s = stackRow({ id: `arn:aws:cloudformation:${R}:${ACCT}:stack/app/2`, name: "app", status: "UPDATE_COMPLETE", parent_id: parent, stack_drift_status: "DRIFTED", region: R, account_id: ACCT }, [
    { resource_type: "AWS::EC2::Instance", physical_resource_id: "i-0abc", logical_resource_id: "Web", resource_status: "CREATE_COMPLETE" },
    { resource_type: "AWS::IAM::Role", physical_resource_id: "role", logical_resource_id: "Role", resource_status: "CREATE_COMPLETE" },
    { resource_type: "AWS::EC2::VPC", physical_resource_id: "vpc-0a", logical_resource_id: "Vpc", resource_status: "CREATE_COMPLETE" },
    { resource_type: "AWS::EC2::Volume", physical_resource_id: "vol-0a", logical_resource_id: "Data", resource_status: "DELETE_COMPLETE" },
  ]);
  assert.equal(s.props.resources, 4);
  assert.equal(s.props.mapped_resources, 2);
  assert.equal(s.props.drift, "drifted");
  assert.deepEqual(s.links.map((l) => `${l.rel} ${l.other} ${l.label ?? (l.known_only ? "known" : "")}`), [`PART_OF ${parent} `, "MANAGES i-0abc known", "MANAGES vpc-0a AdvisorNetwork"]);
});

test("guardduty: severity in generic words, the resource a finding is about, the detector's open counts", async () => {
  const { severityLabel, findingRow, detectorRow } = await import("../services/guardduty.js");
  assert.deepEqual([1, 4, 7, 9, null].map(severityLabel), ["low", "medium", "high", "critical", null]);
  const f = findingRow({ id: "f1", detector_id: "d1", severity: 8, type: "UnauthorizedAccess:EC2/SSHBruteForce", title: "SSH brute force", region: R, account_id: ACCT,
    resource: { ResourceType: "Instance", InstanceDetails: { InstanceId: "i-0abc", Tags: [{ Key: "Name", Value: "web" }] } }, service: { Count: 12, Archived: false, EventLastSeen: "2026-09-30T00:00:00Z" } }, (id) => `det:${id}`);
  assert.equal(f.severity_label, "high");
  assert.equal(f.resource_id, "i-0abc");
  assert.equal(f.resource_name, "web");
  assert.equal(f.detector_arn, "det:d1");
  assert.equal(f.count, 12);
  const d = detectorRow({ detector_id: "d1", status: "ENABLED", features: [{ Name: "S3_DATA_EVENTS", Status: "ENABLED" }, { Name: "RDS_LOGIN_EVENTS", Status: "DISABLED" }], region: R, account_id: ACCT },
    [f, { ...f, id: "f2", archived: true }]);
  assert.equal(d.props.findings_open, 1);
  assert.equal(d.props.findings_high, 1);
  assert.deepEqual(d.props.protections_off, ["rds_login_events"]);
  assert.equal(d.id, `arn:aws:guardduty:${R}:${ACCT}:detector/d1`);
});

test("sns: subscribers counted by protocol, only ARN endpoints become DELIVERS_TO, publishes scaled to a month and priced", async () => {
  const { snsRow, SNS_PUBLISH_USD_PER_MILLION } = await import("../services/sns.js");
  const fn = `arn:aws:lambda:${R}:${ACCT}:function:handler`;
  const r = snsRow({ topic_arn: `arn:aws:sns:${R}:${ACCT}:alerts`, subscriptions_confirmed: 2, kms_master_key_id: "alias/aws/sns", region: R, account_id: ACCT },
    [{ protocol: "lambda", endpoint: fn }, { protocol: "email", endpoint: "ops@example.com" }], { sum: 1e6, days: 15 });
  assert.equal(r.name, "alerts");
  assert.equal(r.props.messages_30d, 2e6);
  assert.equal(r.monthly_usd, 2 * SNS_PUBLISH_USD_PER_MILLION);
  assert.deepEqual(r.props.protocols, ["email 1", "lambda 1"]);
  assert.equal(r.links.length, 2);
  assert.ok(!JSON.stringify(r).includes("ops@example.com"), "an e-mail address is never stored");
  assert.deepEqual(r.links.find((l) => l.rel === "ENCRYPTS"), { rel: "ENCRYPTS", other: "alias/aws/sns", dir: "in", resolve: "kms_key" });
});

test("a service row becomes its generic node: label per kind, flat props, generic state", async () => {
  const { resourceFromService, flatProps, genericState } = await import("../adapters/aws/resources.js");
  const base = { id: "arn:aws:wafv2:x", account_id: ACCT, region: R, name: "web", state: "available", gone: 0, first_seen: "2026-10-01", last_seen: "2026-10-02", monthly_usd: 7 };
  const waf = resourceFromService({ ...base, native_type: "wafv2_web_acl", props: JSON.stringify({ kind: "web_acl", rule_list: ["1 a"], requests_30d: 5 }), tags: "{}" })!;
  assert.equal(waf.label, "AdvisorFilter");
  assert.equal(waf.props.kind, "web_acl");
  assert.ok(waf.observed.some((o) => o.kind === "metrics"));
  assert.equal(resourceFromService({ ...base, native_type: "kms_key", props: "{}" })!.label, "AdvisorSecret");
  assert.equal(resourceFromService({ ...base, native_type: "something_else", props: "{}" }), null);
  assert.deepEqual(flatProps({ a: 1, b: ["x", null], c: { k: 1 }, d: [{ k: 1 }] }), { a: 1, b: ["x"], c: '{"k":1}', d: '[{"k":1}]' });
  assert.equal(genericState("cloudformation_stack", "UPDATE_ROLLBACK_COMPLETE"), "available");
  assert.equal(genericState("cloudformation_stack", "ROLLBACK_COMPLETE"), "degraded");
  assert.equal(genericState("cloudformation_stack", "UPDATE_IN_PROGRESS"), "pending");
  assert.equal(genericState("kms_key", "PendingDeletion"), "stopped");
  assert.equal(genericState("acm_certificate", "EXPIRED"), "degraded");
  assert.equal(genericState("guardduty_detector", "DISABLED"), "stopped");
});

test("links group by what one statement writes: known nodes, network labels, refs; known_only drops the unknown", async () => {
  const { edgeGroups } = await import("../graph_services.js");
  const known = new Set(["i-0abc", LB]);
  const groups = edgeGroups([
    { id: "stack", account_id: ACCT, links: [{ rel: "MANAGES", other: "i-0abc", dir: "out", known_only: true }, { rel: "MANAGES", other: "i-0gone", dir: "out", known_only: true }, { rel: "MANAGES", other: "vpc-0a", dir: "out", label: "AdvisorNetwork" }] },
    { id: "cert", account_id: ACCT, links: [{ rel: "SECURES", other: LB, dir: "out" }, { rel: "SECURES", other: "arn:aws:cloudfront::123456789012:distribution/E1", dir: "out" }] },
  ], known);
  const by = Object.fromEntries(groups.map((g) => [`${g.rel}|${g.target}`, g.rows.map((r) => `${r.self}->${r.other}${r.guessed_type ? ` (${r.guessed_type})` : ""}`)]));
  assert.deepEqual(by, {
    "MANAGES|resource": ["stack->i-0abc"],
    "MANAGES|AdvisorNetwork": ["stack->vpc-0a"],
    "SECURES|resource": [`cert->${LB}`],
    "SECURES|ref": ["cert->arn:aws:cloudfront::123456789012:distribution/E1 (cdn_distribution)"],
  });
});

test("rows go gone only in accounts the refresh saw; the primary's unstamped rows follow it", async () => {
  const { goneScope } = await import("../service_inventory.js");
  const row = (account_id: string) => ({ account_id } as any);
  assert.deepEqual(goneScope([row(ACCT), row("210987654321")], ACCT).sort(), ["", "123456789012", "210987654321"]);
  assert.deepEqual(goneScope([row("210987654321")], ACCT), ["210987654321"]);
  assert.deepEqual(goneScope([], ACCT), []);
});

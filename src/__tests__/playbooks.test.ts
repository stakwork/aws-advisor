import assert from "node:assert/strict";
import { test } from "node:test";
import { PLAYBOOKS, RULE_CONTROL, controlForRecommendation, listPlaybooks, playbookFor, stepsSentence } from "../playbooks.js";
import { EC2_GRAVITON_CONTROL, GravitonFacts, LAMBDA_GRAVITON_CONTROL, RDS_GRAVITON_CONTROL, ec2ArmEquivalent, gravitonPriceKey, gravitonSaving, k8sPoolOf, rdsArmEquivalent } from "../graviton.js";
import { RoleFacts, buildRecommendations, ec2GravitonTier, gravitonRecommendations } from "../rules.js";

// ---- catalog ------------------------------------------------------------------------------------------------

/** `select distinct control_id from findings` on the account's database at the time of writing (30 controls). */
const CONTROLS_SEEN = [
  "aws_thrifty.control.buckets_with_no_lifecycle", "aws_thrifty.control.dynamodb_table_without_autoscaling", "aws_thrifty.control.ebs_snapshot_max_age",
  "aws_thrifty.control.ebs_unused_snapshots", "aws_thrifty.control.ebs_volumes_on_stopped_instances", "aws_thrifty.control.ebs_with_low_usage",
  "aws_thrifty.control.ec2_instance_older_generation", "aws_thrifty.control.ec2_instance_with_graviton", "aws_thrifty.control.ec2_reserved_instance_lease_expiration_days",
  "aws_thrifty.control.ecr_repository_unused_images", "aws_thrifty.control.ecs_cluster_low_utilization", "aws_thrifty.control.elasticache_cluster_long_running",
  "aws_thrifty.control.full_month_cost_changes", "aws_thrifty.control.instances_with_low_utilization", "aws_thrifty.control.lambda_function_excessive_timeout",
  "aws_thrifty.control.lambda_function_with_graviton", "aws_thrifty.control.large_ebs_volumes", "aws_thrifty.control.long_running_ec2_instances",
  "aws_thrifty.control.long_running_rds_db_instances", "aws_thrifty.control.rds_db_instance_with_graviton", "aws_thrifty.control.rds_db_low_utilization",
  "aws_thrifty.control.secretsmanager_secret_unused", "aws_thrifty.control.stale_dynamodb_table_data", "aws_thrifty.control.unattached_eips",
  "query.commitments", "query.eip_unattached", "query.idle_instances", "query.log_groups_no_retention", "query.old_snapshots", "query.stopped_instance_ebs",
];

test("every control that raised an alarm in the account has a playbook, and every playbook is complete", () => {
  for (const id of CONTROLS_SEEN) {
    const pb = playbookFor(id);
    assert.ok(pb, `no playbook for ${id}`);
    assert.equal(pb.control_id, id);
  }
  for (const pb of listPlaybooks()) {
    assert.ok(pb.title && pb.meaning.length > 40 && pb.act_when.length > 20 && pb.ignore_when.length > 20, `${pb.control_id}: text too thin`);
    assert.ok(pb.steps.length >= 2 && pb.steps.every((s) => s.length > 15), `${pb.control_id}: steps`);
    assert.ok(pb.saving.length > 10, `${pb.control_id}: saving formula`);
    assert.ok(["auto", "approve", "report"].includes(pb.tier) && ["low", "medium", "high"].includes(pb.effort), `${pb.control_id}: tier/effort`);
  }
  // The rules that have no Thrifty control behind them, and every rule the app drafts, map to a playbook.
  for (const [rule, control] of Object.entries(RULE_CONTROL)) assert.ok(PLAYBOOKS[control], `rule ${rule} -> ${control} missing`);
  assert.equal(playbookFor("aws_thrifty.control.does_not_exist"), null);
  assert.equal(playbookFor(null), null);
  assert.ok(Object.keys(PLAYBOOKS).length >= CONTROLS_SEEN.length + 4);
});

test("controlForRecommendation prefers evidence.playbook and falls back to the rule's control", () => {
  assert.equal(controlForRecommendation({ rule: "graviton_migration", evidence: JSON.stringify({ playbook: EC2_GRAVITON_CONTROL }) }), EC2_GRAVITON_CONTROL);
  assert.equal(controlForRecommendation({ rule: "graviton_migration", evidence: { playbook: LAMBDA_GRAVITON_CONTROL } }), LAMBDA_GRAVITON_CONTROL);
  assert.equal(controlForRecommendation({ rule: "idle_instance", evidence: "{}" }), "query.idle_instances");
  assert.equal(controlForRecommendation({ rule: "agent:other", evidence: null }), null);
  const sentence = stepsSentence(playbookFor(EC2_GRAVITON_CONTROL)!);
  assert.match(sentence, /^Playbook \(EC2 instance is not on Graviton\): list what runs on the box, then check each one has an arm64 build, then /);
  assert.ok(sentence.endsWith("."));
});

// ---- Graviton type map ----------------------------------------------------------------------------------------

test("ARM equivalents: a dozen EC2 types and the RDS classes, unknown and already-ARM types give null", () => {
  const ec2: [string, string | null][] = [
    ["m6i.xlarge", "m7g.xlarge"], ["m5.large", "m7g.large"], ["m7i.2xlarge", "m7g.2xlarge"], ["m4.xlarge", "m7g.xlarge"],
    ["c5.xlarge", "c7g.xlarge"], ["c6i.4xlarge", "c7g.4xlarge"], ["r5.large", "r7g.large"], ["r6i.8xlarge", "r7g.8xlarge"],
    ["t3.medium", "t4g.medium"], ["t3a.small", "t4g.small"], ["t2.micro", "t4g.micro"], ["i3.large", "i4g.large"], ["x1.16xlarge", "x2gd.16xlarge"],
    ["g4dn.8xlarge", null], ["m8i.4xlarge", null], ["m7g.xlarge", null], ["c7gn.large", null], ["m6i.24xlarge", null], ["nonsense", null],
  ];
  for (const [from, to] of ec2) assert.equal(ec2ArmEquivalent(from), to, from);
  assert.equal(ec2ArmEquivalent(null), null);
  assert.equal(ec2ArmEquivalent("M6I.XLARGE"), "m7g.xlarge");
  const rds: [string, string | null][] = [
    ["db.m5.large", "db.m7g.large"], ["db.m6i.xlarge", "db.m7g.xlarge"], ["db.r5.large", "db.r7g.large"], ["db.r6i.2xlarge", "db.r7g.2xlarge"],
    ["db.t3.medium", "db.t4g.medium"], ["db.t3.micro", "db.t4g.micro"], ["db.r7g.xlarge", null], ["db.t4g.medium", null], ["db.serverless", null], ["db.x2iedn.large", null],
  ];
  for (const [from, to] of rds) assert.equal(rdsArmEquivalent(from), to, from);
});

test("saving math: hourly difference x 730, rounded to cents, null when a price is unknown", () => {
  assert.equal(gravitonSaving(0.192, 0.1632), 21.02); // m6i.xlarge -> m7g.xlarge in us-east-1
  assert.equal(gravitonSaving(0.0416, 0.0336), 5.84); // t3.medium -> t4g.medium
  assert.equal(gravitonSaving(0.2, 0.1632), 26.86); // m4.xlarge -> m7g.xlarge
  assert.equal(gravitonSaving(null, 0.1), null);
  assert.equal(gravitonSaving(0.1, undefined), null);
  assert.equal(gravitonSaving(NaN, 0.1), null);
});

// ---- the rule -------------------------------------------------------------------------------------------------

const role = (r: string, conf = 0.9, prot = 0.1): RoleFacts => ({ role: r, role_confidence: conf, protected_prob: prot });
const REGION = "us-east-1";

function fixtureFacts(): GravitonFacts {
  const prices: Record<string, number | null> = {};
  const ec2Price = (sku: string, hourly: number | null) => { prices[gravitonPriceKey("ec2", sku, REGION, "Linux")] = hourly; };
  ec2Price("m6i.xlarge", 0.192); ec2Price("m7g.xlarge", 0.1632);
  ec2Price("t3.medium", 0.0416); ec2Price("t4g.medium", 0.0336);
  ec2Price("m4.xlarge", 0.2); // m7g.xlarge already priced
  ec2Price("t3.large", 0.0832); ec2Price("t4g.large", null); // unknown ARM price
  ec2Price("m5.large", 0.096); ec2Price("m7g.large", 0.0816);
  ec2Price("t2.large", 0.0928); ec2Price("t4g.large", null);
  prices[gravitonPriceKey("rds", "db.r5.large", REGION, "PostgreSQL")] = 0.25;
  prices[gravitonPriceKey("rds", "db.r7g.large", REGION, "PostgreSQL")] = 0.239;
  prices[gravitonPriceKey("rds", "db.t3.medium", REGION, "PostgreSQL Multi-AZ")] = 0.146;
  prices[gravitonPriceKey("rds", "db.t4g.medium", REGION, "PostgreSQL Multi-AZ")] = 0.13;
  const ec2 = (id: string, instance_type: string, name: string, state = "running", tags: Record<string, string> = {}) => [id, { instance_type, platform: "Linux/UNIX", name, state, region: REGION, tags, operating_system: "Linux" }] as const;
  return {
    alarms: [
      { kind: "ec2", resource: `arn:aws:ec2:${REGION}:1:instance/i-k8s`, id: "i-k8s", region: REGION },
      { kind: "ec2", resource: `arn:aws:ec2:${REGION}:1:instance/i-k8s-tags`, id: "i-k8s-tags", region: REGION },
      { kind: "ec2", resource: `arn:aws:ec2:${REGION}:1:instance/i-web`, id: "i-web", region: REGION },
      { kind: "ec2", resource: `arn:aws:ec2:${REGION}:1:instance/i-dev`, id: "i-dev", region: REGION },
      { kind: "ec2", resource: `arn:aws:ec2:${REGION}:1:instance/i-chain`, id: "i-chain", region: REGION },
      { kind: "ec2", resource: `arn:aws:ec2:${REGION}:1:instance/i-unknown`, id: "i-unknown", region: REGION },
      { kind: "ec2", resource: `arn:aws:ec2:${REGION}:1:instance/i-norole`, id: "i-norole", region: REGION },
      { kind: "ec2", resource: `arn:aws:ec2:${REGION}:1:instance/i-protected`, id: "i-protected", region: REGION },
      { kind: "ec2", resource: `arn:aws:ec2:${REGION}:1:instance/i-regex`, id: "i-regex", region: REGION },
      { kind: "ec2", resource: `arn:aws:ec2:${REGION}:1:instance/i-noprice`, id: "i-noprice", region: REGION },
      { kind: "ec2", resource: `arn:aws:ec2:${REGION}:1:instance/i-stopped`, id: "i-stopped", region: REGION },
      { kind: "ec2", resource: `arn:aws:ec2:${REGION}:1:instance/i-gpu`, id: "i-gpu", region: REGION },
      { kind: "rds", resource: `arn:aws:rds:${REGION}:1:db:pg-main`, id: "pg-main", region: REGION },
      { kind: "rds", resource: `arn:aws:rds:${REGION}:1:db:pg-ha`, id: "pg-ha", region: REGION },
      { kind: "rds", resource: `arn:aws:rds:${REGION}:1:db:already-arm`, id: "already-arm", region: REGION },
      { kind: "lambda", resource: `arn:aws:lambda:${REGION}:1:function:priced`, id: "priced", region: REGION },
      { kind: "lambda", resource: `arn:aws:lambda:${REGION}:1:function:nocost`, id: "nocost", region: REGION },
      { kind: "lambda", resource: `arn:aws:lambda:${REGION}:1:function:arm`, id: "arm", region: REGION },
    ],
    ec2: Object.fromEntries([
      ec2("i-k8s", "m6i.xlarge", "ip-10-0-1-1.ec2.internal"),
      ec2("i-k8s-tags", "m6i.xlarge", "node", "running", { "karpenter.sh/nodepool": "default" }),
      ec2("i-web", "t3.medium", "example-web"),
      ec2("i-dev", "m4.xlarge", "whinx-test"),
      ec2("i-chain", "m5.large", "bitcoind-Swarm"),
      ec2("i-unknown", "m6i.xlarge", "example-node-4"),
      ec2("i-norole", "m6i.xlarge", "example-node-5"),
      ec2("i-protected", "m6i.xlarge", "example-node-2"),
      ec2("i-regex", "m6i.xlarge", "evan - dont delete"),
      ec2("i-noprice", "t3.large", "legal-synch"),
      ec2("i-stopped", "m6i.xlarge", "parked", "stopped"),
      ec2("i-gpu", "g4dn.8xlarge", "gpu"),
    ]),
    rds: {
      "pg-main": { class: "db.r5.large", engine: "postgres", region: REGION, pricing_engine: "PostgreSQL", multi_az: false, io_optimized: false },
      "pg-ha": { class: "db.t3.medium", engine: "postgres", region: REGION, pricing_engine: "PostgreSQL", multi_az: true, io_optimized: false },
      "already-arm": { class: "db.r7g.large", engine: "postgres", region: REGION, pricing_engine: "PostgreSQL", multi_az: false, io_optimized: false },
    },
    lambda: {
      priced: { architectures: ["x86_64"], runtime: "python3.12", package_type: "Zip", last_month_cost: 42.5, cost_note: "1.98 USD over 14 days, scaled" },
      nocost: { architectures: ["x86_64"], runtime: "nodejs20.x", package_type: "Image", last_month_cost: null, cost_note: "resource-level Cost Explorer data is not enabled for this account" },
      arm: { architectures: ["arm64"], runtime: "python3.12", package_type: "Zip", last_month_cost: 1, cost_note: null },
    },
    prices,
  };
}

const roles: Record<string, RoleFacts> = {
  "i-k8s": role("k8s_node"), "i-web": role("web_or_api"), "i-dev": role("dev_or_test", 0.96), "i-chain": role("blockchain_node", 1.0),
  "i-unknown": role("unknown", 0.85), "i-protected": role("unknown", 0.66, 0.94), "i-noprice": role("web_or_api"), "i-stopped": role("web_or_api"),
};

test("graviton rule: tier by role, protected and k8s detection, skips with reasons", () => {
  const { recs, skipped } = gravitonRecommendations(fixtureFacts(), roles);
  const by = Object.fromEntries(recs.map((r) => [r.resource, r]));
  assert.deepEqual(Object.keys(by).sort(), ["i-chain", "i-dev", "i-k8s", "i-k8s-tags", "i-norole", "i-protected", "i-regex", "i-unknown", "i-web", "nocost", "pg-ha", "pg-main", "priced"]);
  for (const r of recs) { assert.equal(r.rule, "graviton_migration"); assert.equal(r.actionType, "migrate_to_graviton"); assert.match(r.rationale, /Playbook \(/); }

  assert.equal(by["i-k8s"].tier, "approve"); assert.match(by["i-k8s"].rationale, /node group or Karpenter NodePool/); assert.match(by["i-k8s"].rationale, /multi-arch/);
  assert.equal(by["i-k8s-tags"].tier, "approve"); assert.match(by["i-k8s-tags"].rationale, /pool default/); assert.equal((by["i-k8s-tags"].evidence as any).k8s_pool, "default");
  assert.equal(by["i-web"].tier, "approve"); assert.match(by["i-web"].rationale, /arm64 AMI/);
  assert.equal(by["i-dev"].tier, "approve"); assert.match(by["i-dev"].rationale, /dev_or_test/);
  assert.equal(by["i-chain"].tier, "report"); assert.match(by["i-chain"].rationale, /ARM build audit/);
  assert.equal(by["i-unknown"].tier, "report"); assert.match(by["i-unknown"].rationale, /ARM build audit/);
  assert.equal(by["i-norole"].tier, "report"); assert.match(by["i-norole"].rationale, /unclassified/);
  assert.equal(by["i-protected"].tier, "report"); assert.match(by["i-protected"].rationale, /deliberately kept \(0\.94\)/);
  assert.equal(by["i-regex"].tier, "report"); assert.match(by["i-regex"].rationale, /name asks not to touch it/);

  // evidence carries the playbook and the prices
  assert.deepEqual((by["i-web"].evidence as any).playbook, EC2_GRAVITON_CONTROL);
  assert.equal((by["i-web"].evidence as any).current_sku, "t3.medium");
  assert.equal((by["i-web"].evidence as any).target_sku, "t4g.medium");
  assert.deepEqual((by["i-web"].evidence as any).prices, { current_hourly: 0.0416, target_hourly: 0.0336, region: REGION, operating_system: "Linux" });
  assert.equal((by["pg-main"].evidence as any).playbook, RDS_GRAVITON_CONTROL);
  assert.equal((by["priced"].evidence as any).playbook, LAMBDA_GRAVITON_CONTROL);

  const why = Object.fromEntries(skipped.map((s) => [s.resource.split(/[/:]/).pop(), s.why]));
  assert.match(why["i-noprice"], /price unknown for t4g\.large/);
  assert.match(why["i-stopped"], /stopped: no instance-hours/);
  assert.match(why["i-gpu"], /no same-size Graviton equivalent/);
  assert.match(why["already-arm"], /no same-size Graviton equivalent/);
  assert.equal(why["arm"], "already arm64");
});

test("graviton rule: saving math on the fixture prices and the Lambda 20% rule", () => {
  const { recs } = gravitonRecommendations(fixtureFacts(), roles);
  const by = Object.fromEntries(recs.map((r) => [r.resource, r]));
  assert.equal(by["i-k8s"].estMonthlySaving, 21.02); // (0.192 - 0.1632) x 730
  assert.equal(by["i-web"].estMonthlySaving, 5.84); // (0.0416 - 0.0336) x 730
  assert.equal(by["i-dev"].estMonthlySaving, 26.86); // (0.2 - 0.1632) x 730
  assert.equal(by["i-chain"].estMonthlySaving, 10.51); // (0.096 - 0.0816) x 730
  assert.equal(by["pg-main"].estMonthlySaving, 8.03); // (0.25 - 0.239) x 730
  assert.equal(by["pg-ha"].estMonthlySaving, 11.68); // Multi-AZ label priced separately
  assert.match(by["pg-ha"].rationale, /PostgreSQL Multi-AZ/);
  assert.equal(by["priced"].estMonthlySaving, 8.5); // 20% of 42.5
  assert.equal(by["priced"].tier, "approve");
  assert.equal(by["nocost"].estMonthlySaving, null);
  assert.match(by["nocost"].rationale, /cost could not be read \(resource-level Cost Explorer data is not enabled/);
  assert.match(by["nocost"].rationale, /container image/);
  assert.equal(by["nocost"].confidence, 0.4);
  // and through buildRecommendations, next to the other rules
  const all = buildRecommendations({ queryRows: {}, aurora: [], roles, graviton: fixtureFacts() });
  assert.equal(all.filter((r) => r.rule === "graviton_migration").length, recs.length);
  assert.equal(buildRecommendations({ queryRows: {}, aurora: [] }).length, 0);
});

test("ec2GravitonTier and k8sPoolOf on their own", () => {
  assert.equal(ec2GravitonTier({ name: "x", tags: {} }, role("batch_or_worker")).tier, "approve");
  assert.equal(ec2GravitonTier({ name: "x", tags: {} }, role("cache_or_queue")).tier, "approve");
  assert.equal(ec2GravitonTier({ name: "x", tags: {} }, role("ci_or_build")).tier, "report");
  assert.equal(ec2GravitonTier({ name: "x", tags: {} }, role("database")).tier, "report");
  assert.equal(ec2GravitonTier({ name: "keep me", tags: {} }, undefined).tier, "report");
  assert.equal(ec2GravitonTier({ name: "x", tags: { "eks:nodegroup-name": "ng-1" } }, undefined).tier, "approve");
  assert.equal(k8sPoolOf({ "kubernetes.io/cluster/prod": "owned" }), "prod");
  assert.equal(k8sPoolOf({ Name: "x" }), null);
});

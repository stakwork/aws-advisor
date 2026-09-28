import { test } from "node:test";
import assert from "node:assert";
import { attributeLogGroup, tokens } from "../log_attribution.js";
import { hoursFromSamples } from "../quantities.js";

const ctx = {
  systems: [
    { id: "pool:awseb-e-x-stack-ASG", name: "awseb-e-x-stack-ASG", kind: "pool", members: ["i-1", "i-2"], pool: "awseb-e-x-stack-ASG" },
    { id: "pool:sysbox-quasar-nodes", name: "sysbox-quasar-nodes", kind: "pool", members: ["i-3"], pool: "sysbox-quasar-nodes" },
    { id: "eks:quasar-cluster", name: "quasar-cluster", kind: "eks_cluster", members: ["i-3"] },
    { id: "ec2:i-9", name: "swarmab12cd", kind: "instance", members: ["i-9"] },
    { id: "ec2:i-8", name: "orion-app-1", kind: "instance", members: ["i-8"] },
    { id: "rds:orion", name: "orion", kind: "rds_instance", members: ["orion"] },
    { id: "rds:prod", name: "prod", kind: "rds_cluster", members: ["prod-1"] },
    { id: "lambda:example-script-lambda", name: "example-script-lambda", kind: "lambda", members: ["arn"] },
  ],
  clusters: new Map([["quasar-cluster", "eks:quasar-cluster"]]),
  beanstalk: new Map([["AcmecorpProductionDocker-env", "pool:awseb-e-x-stack-ASG"], ["e-appag8ksyi", "pool:awseb-e-x-stack-ASG"]]),
  lambdas: new Map([["example-script-lambda", "lambda:example-script-lambda"]]),
};

test("log attribution: AWS naming conventions, tags, then name tokens", () => {
  assert.equal(attributeLogGroup("/aws/lambda/example-script-lambda", ctx).owner, "lambda:example-script-lambda");
  assert.equal(attributeLogGroup("/aws/lambda/other", ctx).owner, null);
  assert.equal(attributeLogGroup("/aws/rds/cluster/prod/postgresql", ctx).owner, "rds:prod");
  assert.equal(attributeLogGroup("/aws/eks/quasar-cluster/cluster", ctx).owner, "eks:quasar-cluster");
  assert.equal(attributeLogGroup("/aws/elasticbeanstalk/AcmecorpProductionDocker-env/var/log/eb.log", ctx).owner, "pool:awseb-e-x-stack-ASG");
  assert.equal(attributeLogGroup("/workspaces/quasar-cluster/pools/cmi7/workspaces", ctx).owner, "eks:quasar-cluster");
  assert.equal(attributeLogGroup("/swarms/ab12cd", ctx).owner, "ec2:i-9", "a long token contained in the name");
  assert.equal(attributeLogGroup("/orion/app", ctx).owner, "ec2:i-8", "on a tie the compute system beats the database");
  assert.equal(attributeLogGroup("/acmecorp/production", { ...ctx, systems: [...ctx.systems, { id: "cache:acmecorp-production-sidekiq", name: "acmecorp-production-sidekiq", kind: "cache_group", members: ["x"] }, { id: "pool:eb", name: "awseb-stack", kind: "pool", members: ["i-5"], aliases: ["AcmecorpProductionDocker-env"] }] }).owner, "pool:eb", "member Name tags count as names; the pool beats the cache group");
  assert.equal(attributeLogGroup("/acmecorp/production", ctx).owner, null, "no system carries those tokens without an alias");
  assert.deepEqual(tokens("/aws/lambda/example-script-lambda"), ["lambda", "example", "script"]);
});

test("log attribution: an unattributed group says why and lists the closest systems", () => {
  const r = attributeLogGroup("/orion/nothing-here-xyz", { ...ctx, systems: ctx.systems.filter((s) => s.id !== "ec2:i-8") });
  assert.equal(r.owner, "rds:orion", "one system left with the token: it wins even as a database");
  const weak = attributeLogGroup("/zzzz/qqqq", ctx);
  assert.equal(weak.owner, null); assert.equal(weak.how, "no match"); assert.deepEqual(weak.candidates, []);
  const amb = attributeLogGroup("/orion/app", { ...ctx, systems: [...ctx.systems, { id: "ec2:i-7", name: "orion-app-2", kind: "instance", members: ["i-7"] }] });
  assert.equal(amb.owner, null); assert.match(amb.how, /^ambiguous/); assert.equal(amb.candidates.length, 3, "the tied compute systems and the database, best first");
  assert.match(amb.candidates[0], /^ec2:i-[78] \(1: orion\)$/, "\"app\" is a generic token and does not count");
});

test("log attribution: the group's tags beat the name, a member id or alias counts, ownership tags do not", () => {
  assert.equal(attributeLogGroup("/misc/group-1", ctx, { service: "orion-app-1" }).owner, "ec2:i-8");
  assert.equal(attributeLogGroup("/misc/group-1", ctx, { service: "orion-app-1" }).how, "tag service=orion-app-1");
  assert.equal(attributeLogGroup("/misc/group-1", ctx, { Instance: "i-3" }).owner, "pool:sysbox-quasar-nodes", "a member id names its pool, not the EKS cluster above it");
  assert.equal(attributeLogGroup("/misc/group-1", ctx, { "eks:cluster-name": "quasar-cluster" }).owner, "eks:quasar-cluster");
  assert.equal(attributeLogGroup("/misc/group-1", ctx, { "elasticbeanstalk:environment-name": "AcmecorpProductionDocker-env" }).owner, "pool:awseb-e-x-stack-ASG");
  assert.equal(attributeLogGroup("/misc/group-1", ctx, { Environment: "orion" }).owner, null, "Environment is not a system name even when its value matches one");
  const two = attributeLogGroup("/misc/group-1", ctx, { service: "orion-app-1", db: "orion" });
  assert.equal(two.owner, null); assert.match(two.how, /^ambiguous: tags/);
  assert.equal(attributeLogGroup("/orion/app", ctx, { service: "swarmab12cd" }).owner, "ec2:i-9", "a tag decides before the name tokens do");
  assert.equal(attributeLogGroup("/aws/lambda/example-script-lambda", ctx, { service: "orion" }).owner, "lambda:example-script-lambda", "but the AWS naming convention decides before the tags");
});

test("log attribution: what an instance's agent config says wins over everything, and disagreement is reported", () => {
  const observed = new Map([
    ["/orion/app", [{ instance_id: "orion", via: "cloudwatch-agent", source: "/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json", at: "2026-09-28T00:00:00Z" }]],
    ["/shared/app", [{ instance_id: "i-1", via: "fluent-bit", source: null, at: "2026-09-28T00:00:00Z" }, { instance_id: "i-9", via: "docker:web", source: "log driver", at: "2026-09-28T00:00:00Z" }]],
    ["/orphan/app", [{ instance_id: "i-404", via: "awslogs", source: null, at: "2026-09-28T00:00:00Z" }]],
  ]);
  const c = { ...ctx, observed };
  const r = attributeLogGroup("/orion/app", c);
  assert.equal(r.owner, "rds:orion", "the name alone would pick the compute box; the config on the database's member says otherwise");
  assert.equal(r.how, "observed: cloudwatch-agent on orion");
  const shared = attributeLogGroup("/shared/app", c);
  assert.equal(shared.owner, null); assert.match(shared.how, /^observed on several systems/); assert.equal(shared.candidates.length, 2);
  const orphan = attributeLogGroup("/orphan/app", c);
  assert.equal(orphan.owner, null); assert.match(orphan.how, /in no system/);
  assert.equal(attributeLogGroup("/swarms/ab12cd", c).owner, "ec2:i-9", "groups nobody was seen shipping to fall through to the other rules");
});

test("hours from samples: each count stands for the time to the next sample, capped at one hour", () => {
  const h = 3600e3; const t0 = Date.parse("2026-09-20T00:00:00Z");
  assert.equal(hoursFromSamples([{ t: t0, value: 10 }, { t: t0 + h / 2, value: 10 }, { t: t0 + h, value: 12 }]), 5 + 5 + 6);
  assert.equal(hoursFromSamples([{ t: t0, value: 10 }, { t: t0 + 5 * h, value: 10 }]), 10 + 5, "a five-hour gap counts as one hour, not five");
});

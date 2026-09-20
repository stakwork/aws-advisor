import { test } from "node:test";
import assert from "node:assert";
import { attributeLogGroup, tokens } from "../log_attribution.js";
import { hoursFromSamples } from "../quantities.js";

const ctx = {
  systems: [
    { id: "pool:awseb-e-x-stack-ASG", name: "awseb-e-x-stack-ASG", kind: "pool", members: ["i-1", "i-2"], pool: "awseb-e-x-stack-ASG" },
    { id: "pool:sysbox-workspace-nodes", name: "sysbox-workspace-nodes", kind: "pool", members: ["i-3"], pool: "sysbox-workspace-nodes" },
    { id: "eks:workspace-cluster", name: "workspace-cluster", kind: "eks_cluster", members: ["i-3"] },
    { id: "ec2:i-9", name: "swarmrn9cYL", kind: "instance", members: ["i-9"] },
    { id: "ec2:i-8", name: "senza-app-1", kind: "instance", members: ["i-8"] },
    { id: "rds:senza", name: "senza", kind: "rds_instance", members: ["senza"] },
    { id: "rds:prod", name: "prod", kind: "rds_cluster", members: ["prod-1"] },
    { id: "lambda:stak-script-lambda", name: "stak-script-lambda", kind: "lambda", members: ["arn"] },
  ],
  clusters: new Map([["workspace-cluster", "eks:workspace-cluster"]]),
  beanstalk: new Map([["StakworkProductionDocker-env", "pool:awseb-e-x-stack-ASG"], ["e-appag8ksyi", "pool:awseb-e-x-stack-ASG"]]),
  lambdas: new Map([["stak-script-lambda", "lambda:stak-script-lambda"]]),
};

test("log attribution: AWS naming conventions, tags, then name tokens", () => {
  assert.equal(attributeLogGroup("/aws/lambda/stak-script-lambda", ctx).owner, "lambda:stak-script-lambda");
  assert.equal(attributeLogGroup("/aws/lambda/other", ctx).owner, null);
  assert.equal(attributeLogGroup("/aws/rds/cluster/prod/postgresql", ctx).owner, "rds:prod");
  assert.equal(attributeLogGroup("/aws/eks/workspace-cluster/cluster", ctx).owner, "eks:workspace-cluster");
  assert.equal(attributeLogGroup("/aws/elasticbeanstalk/StakworkProductionDocker-env/var/log/eb.log", ctx).owner, "pool:awseb-e-x-stack-ASG");
  assert.equal(attributeLogGroup("/workspaces/workspace-cluster/pools/cmi7/workspaces", ctx).owner, "eks:workspace-cluster");
  assert.equal(attributeLogGroup("/swarms/rn9cYL", ctx).owner, "ec2:i-9", "a long token contained in the name");
  assert.equal(attributeLogGroup("/senza/app", ctx).owner, "ec2:i-8", "on a tie the compute system beats the database");
  assert.equal(attributeLogGroup("/stakwork/production", { ...ctx, systems: [...ctx.systems, { id: "cache:stakwork-production-sidekiq", name: "stakwork-production-sidekiq", kind: "cache_group", members: ["x"] }, { id: "pool:eb", name: "awseb-stack", kind: "pool", members: ["i-5"], aliases: ["StakworkProductionDocker-env"] }] }).owner, "pool:eb", "member Name tags count as names; the pool beats the cache group");
  assert.equal(attributeLogGroup("/stakwork/production", ctx).owner, null, "no system carries those tokens without an alias");
  assert.deepEqual(tokens("/aws/lambda/stak-script-lambda"), ["lambda", "stak", "script"]);
});

test("hours from samples: each count stands for the time to the next sample, capped at one hour", () => {
  const h = 3600e3; const t0 = Date.parse("2026-09-20T00:00:00Z");
  assert.equal(hoursFromSamples([{ t: t0, value: 10 }, { t: t0 + h / 2, value: 10 }, { t: t0 + h, value: 12 }]), 5 + 5 + 6);
  assert.equal(hoursFromSamples([{ t: t0, value: 10 }, { t: t0 + 5 * h, value: 10 }]), 10 + 5, "a five-hour gap counts as one hour, not five");
});

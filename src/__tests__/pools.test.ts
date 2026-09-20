import { test } from "node:test";
import assert from "node:assert";
import { batchEnvironmentName, isEphemeralPool, poolOf } from "../pools.js";

test("pools: AWS Batch workers are recognised by their service tag or their ASG name", () => {
  const byTag = poolOf({ AWSBatchServiceTag: "batch", "aws:autoscaling:groupName": "AWSBatch-production-20250408154910170200000001-asg-640012bd-4e90-3f19-9dd2-c09a23dc923d" });
  assert.equal(byTag?.kind, "batch");
  assert.equal(byTag?.name, "production-20250408154910170200000001");
  assert.match(byTag!.note, /compute environment/);
  assert.equal(poolOf({ "aws:autoscaling:groupName": "AWSBatch-x-asg-0000" })?.kind, "batch");
  assert.equal(batchEnvironmentName("AWSBatch-ml-gpu-asg-12ab"), "ml-gpu");
  assert.equal(batchEnvironmentName("web-asg"), null);
});

test("pools: kubernetes and plain autoscaling pools, and standalone instances", () => {
  assert.equal(poolOf({ "karpenter.sh/nodepool": "workspaces" })?.kind, "karpenter");
  assert.equal(poolOf({ "eks:nodegroup-name": "ng-1", "aws:autoscaling:groupName": "eks-ng-1-abc" })?.kind, "eks");
  assert.equal(poolOf({ "aws:autoscaling:groupName": "web-asg" })?.kind, "asg");
  assert.equal(poolOf({ Name: "bitcoind" }), null);
  assert.equal(poolOf(null), null);
  assert.ok(isEphemeralPool(poolOf({ AWSBatchServiceTag: "batch" })));
  assert.ok(!isEphemeralPool(poolOf({ "aws:autoscaling:groupName": "web-asg" })));
});

test("probe pass: Batch workers and instances younger than fifteen minutes are not probe targets", async () => {
  const { db } = await import("../db.js");
  const { probeTargets } = await import("../probe_pass.js");
  const mk = (iid: string, extra: Record<string, any>) => {
    db.prepare("delete from inventory_ec2 where instance_id = ?").run(iid);
    const row: Record<string, any> = { instance_id: iid, name: "t", state: "running", ssm_status: "Online", gone: 0, cpu_30d: 1, snapshot: "{}", first_seen: "2026-01-01", last_seen: "2026-01-01", launch_time: "2026-01-01T00:00:00Z", ...extra };
    const cols = Object.keys(row);
    db.prepare(`insert into inventory_ec2(${cols.join(",")}) values (${cols.map(() => "?").join(",")})`).run(...cols.map((k) => row[k]));
  };
  const ids = ["i-0feedfacecafe0002", "i-0feedfacecafe0003", "i-0feedfacecafe0004"];
  mk(ids[0], { pool_kind: "batch", pool: "production" });
  mk(ids[1], { launch_time: new Date(Date.now() - 5 * 60000).toISOString() });
  mk(ids[2], { pool_kind: "asg", pool: "web-asg" });
  const targets = probeTargets(1000).map((t) => t.instance_id);
  assert.ok(!targets.includes(ids[0]), "batch worker skipped");
  assert.ok(!targets.includes(ids[1]), "five-minute-old instance skipped");
  assert.ok(targets.includes(ids[2]), "asg member probed like any other");
  for (const id of ids) db.prepare("delete from inventory_ec2 where instance_id = ?").run(id);
});

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

// resourceChanges reads the inventory: a scratch database seeded below.
process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "advisor-forecast-test-"));
process.env.TYPESAFE_API_KEY = "";

const { db } = await import("../db.js");
const { resourceChanges } = await import("../forecast.js");

const add = (id: string, o: { launch: string; first_seen: string; last_seen?: string; gone?: number; pool_kind?: string; tags?: Record<string, string> }) =>
  db.prepare(`insert into inventory_ec2(instance_id, instance_type, state, launch_time, monthly_usd, first_seen, last_seen, gone, snapshot, pool_kind)
    values (?, 'm6i.4xlarge', 'running', ?, 561, ?, ?, ?, ?, ?)`)
    .run(id, o.launch, o.first_seen, o.last_seen ?? "2026-10-05 00:00:00", o.gone ?? 0, JSON.stringify({ tags: o.tags || {} }), o.pool_kind ?? null);

test("resourceChanges leaves out pool churn and restarted instances", () => {
  add("i-first-sweep", { launch: "2026-01-01T00:00:00.000Z", first_seen: "2026-09-01 00:00:00" });
  add("i-restarted", { launch: "2026-10-02T00:00:00.000Z", first_seen: "2026-09-01 00:00:00" });
  add("i-launched", { launch: "2026-10-03T00:00:00.000Z", first_seen: "2026-10-03 01:00:00" });
  add("i-batch-new", { launch: "2026-10-03T00:00:00.000Z", first_seen: "2026-10-03 01:00:00", pool_kind: "batch" });
  add("i-batch-gone", { launch: "2026-10-02T00:00:00.000Z", first_seen: "2026-10-02 01:00:00", last_seen: "2026-10-02 05:00:00", gone: 1, tags: { "aws:autoscaling:groupName": "AWSBatch-prod-asg-0a" } });
  add("i-asg-gone-untagged-kind", { launch: "2026-09-02T00:00:00.000Z", first_seen: "2026-09-02 01:00:00", last_seen: "2026-10-02 05:00:00", gone: 1, tags: { "aws:autoscaling:groupName": "web-asg" } });
  add("i-terminated", { launch: "2026-05-01T00:00:00.000Z", first_seen: "2026-09-01 00:00:00", last_seen: "2026-10-04 00:00:00", gone: 1 });

  const c = resourceChanges("2026-10");
  assert.deepEqual(c.new_resources.map((r) => r.id), ["i-launched"]);
  assert.deepEqual(c.gone_resources.map((r) => r.id), ["i-terminated"]);
});

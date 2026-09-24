import assert from "node:assert/strict";
import { test } from "node:test";
import { distinctSaving, findConflicts, makesCycle, resourceKeys } from "../related.js";
import { mergeRecommendations } from "../paging.js";

const rec = (id: number, o: Partial<{ resource: string | null; resource_name: string | null; action_type: string; status: string; title: string; est_monthly_saving: number | null }>) =>
  ({ id, resource: "i-1", resource_name: null, action_type: "stop_instance", status: "open", title: `rec ${id}`, est_monthly_saving: 10, ...o });

test("related: resource keys reduce every entry of the resource column to a bare id", () => {
  assert.deepEqual(resourceKeys({ resource: "i-1, arn:aws:rds:us-east-1:1:cluster:foo, rds:bar", resource_name: null }), ["i-1", "foo", "bar"]);
  assert.deepEqual(resourceKeys({ resource: "22 stopped EC2 instances (see list)", resource_name: null }), []);
  assert.deepEqual(resourceKeys({ resource: null, resource_name: null }), []);
});

test("related: different resource-changing actions on one resource conflict; same action, report-only or closed items do not", () => {
  const rows = [
    rec(1, { action_type: "stop_instance", est_monthly_saving: 140 }),
    rec(2, { action_type: "migrate_graviton", status: "approved", est_monthly_saving: 30 }),
    rec(3, { action_type: "stop_instance", resource: "arn:aws:ec2:us-east-1:1:instance/i-1" }),   // same action: merges, no conflict
    rec(4, { action_type: "other", title: "look at it" }),                                        // report-only
    rec(5, { action_type: "delete_snapshot", status: "rejected" }),                                // closed
    rec(6, { resource: "i-2", action_type: "rightsize_instance" }),                                // other resource
    rec(7, { resource: "i-1, i-2", action_type: "terminate_stopped_instance", status: "pending" }),
  ];
  const c = findConflicts(rows);
  assert.deepEqual(c.get(1)!.map((x) => [x.id, x.on]), [[2, "i-1"], [7, "i-1"]]);
  assert.deepEqual(c.get(2)!.map((x) => x.id), [1, 3, 7]);
  assert.deepEqual(c.get(6)!.map((x) => x.id), [7]);
  assert.deepEqual(c.get(7)!.map((x) => x.id), [1, 2, 3, 6]);
  assert.equal(c.get(4), undefined);
  assert.equal(c.get(5), undefined);
  assert.equal(c.get(3)!.some((x) => x.id === 1), false);
});

test("related: the distinct total counts one claim per resource, the largest; unnamed resources always count", () => {
  const s = distinctSaving([
    rec(1, { est_monthly_saving: 140 }),
    rec(2, { est_monthly_saving: 30, action_type: "migrate_graviton" }),       // same box: overlaps
    rec(3, { resource: "i-2", est_monthly_saving: 50 }),
    rec(4, { resource: "i-1, i-3", est_monthly_saving: 20 }),                  // i-3 is new: counts
    rec(5, { resource: "18 snapshots (see list)", est_monthly_saving: 40 }),   // no key: counts
    rec(6, { resource: null, est_monthly_saving: null }),
  ]);
  assert.deepEqual(s, { total: 280, distinct: 250, overlap: 30 });
});

test("related: a blocked-by link that loops back is refused", () => {
  const chain: Record<number, number | null> = { 1: 2, 2: 3, 3: null, 9: null };
  const of = (id: number) => chain[id] ?? null;
  assert.equal(makesCycle(3, 1, of), true);     // 1 → 2 → 3, so 3 waiting on 1 loops
  assert.equal(makesCycle(1, 9, of), false);
  assert.equal(makesCycle(4, 1, of), false);
});

test("merge: members of a pool or cluster are one entry per (system, action), the members listed", () => {
  const row = (id: number, resource: string, action_type = "rightsize_instance", status = "open") =>
    ({ id, source: "rules", rule: "r", resource, action_type, status, est_monthly_saving: 10 + id, confidence: 0.8, updated_at: "2026-09-18 00:00:00" });
  const systems = new Map([["i-a", { kind: "pool" as const, id: "karpenter/default" }], ["i-b", { kind: "pool" as const, id: "karpenter/default" }], ["db-1", { kind: "rds_cluster" as const, id: "prod" }]]);
  const merged = mergeRecommendations([row(1, "i-a"), row(2, "i-b"), row(3, "i-c"), row(4, "i-a", "stop_instance"), row(5, "db-1"), row(6, "i-b", "rightsize_instance", "approved")], (rid) => systems.get(rid));
  const pool = merged.find((r) => r.system?.kind === "pool" && r.action_type === "rightsize_instance" && r.status === "open")!;
  assert.deepEqual(pool.merged_ids, [2, 1]);
  assert.deepEqual(pool.system, { kind: "pool", id: "karpenter/default", members: ["i-a", "i-b"] });
  assert.equal(merged.find((r) => r.id === 3)!.system, null);
  assert.equal(merged.find((r) => r.id === 4)!.system?.kind, "pool");   // another action on the pool: its own entry
  assert.deepEqual(merged.find((r) => r.id === 5)!.system, { kind: "rds_cluster", id: "prod", members: ["db-1"] });
  assert.equal(merged.find((r) => r.id === 6)!.merged_ids.length, 1);   // other status: apart
});

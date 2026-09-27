import assert from "node:assert/strict";
import { test } from "node:test";
import { PUBLIC_IPV4_USD_MONTH, buildReport, idleDays, shouldNudge, swarmCost } from "../swarm_costs.js";

test("swarm cost: compute only while running, storage and address always, snapshots when known", () => {
  const running = swarmCost({ state: "running", monthly_usd: 60, ebs_usd: 8, snapshot_gb: 100, public_ip: "3.3.3.3" });
  assert.deepEqual(running, { compute_usd: 60, ebs_usd: 8, snapshot_usd: 5, ip_usd: PUBLIC_IPV4_USD_MONTH, total_usd: 76.65 });
  const stopped = swarmCost({ state: "stopped", monthly_usd: 60, ebs_usd: 8, snapshot_gb: null, public_ip: null });
  assert.equal(stopped.compute_usd, 0);
  assert.equal(stopped.snapshot_usd, null);
  assert.equal(stopped.ip_usd, 0);
  assert.equal(stopped.total_usd, 8);
});

test("swarm cost: idle days count whole days since the last use, null when there was none", () => {
  const now = new Date("2026-09-27T12:00:00Z");
  assert.equal(idleDays(null, now), null);
  assert.equal(idleDays("2026-09-27 11:00:00", now), 0);
  assert.equal(idleDays("2026-09-17T13:00:00Z", now), 9);
  assert.equal(idleDays("2026-09-17T11:00:00Z", now), 10);
});

test("swarm cost: nudge only a running, idle box that nobody is parking", () => {
  const base = { state: "running", idle_days: 9, parked: false, parking_proposed: false, idle_threshold: 7 };
  assert.equal(shouldNudge(base), true);
  assert.equal(shouldNudge({ ...base, idle_days: 6 }), false);
  assert.equal(shouldNudge({ ...base, idle_days: null }), false);
  assert.equal(shouldNudge({ ...base, state: "stopped" }), false);
  assert.equal(shouldNudge({ ...base, parked: true }), false);
  assert.equal(shouldNudge({ ...base, parking_proposed: true }), false);
});

test("swarm cost report: the month is the mean of the daily totals, the latest row is the state, totals add up", () => {
  const row = (day: string, id: string, total: number, over: Record<string, unknown> = {}) => ({ day, instance_id: id, name: `${id}-swarm`, state: "running", instance_type: "t3.large", compute_usd: total - 5, ebs_usd: 5, snapshot_usd: null, ip_usd: 0, total_usd: total, last_use_at: null, idle_days: null, parked: 0, ...over });
  const rows = [
    row("2026-09-01", "i-a", 70), row("2026-09-02", "i-a", 70), row("2026-09-03", "i-a", 10, { state: "stopped", parked: 1, compute_usd: 0, idle_days: 12, last_use_at: "2026-08-22T00:00:00Z" }),
    row("2026-09-03", "i-b", 40, { idle_days: 30, last_use_at: "2026-08-04T00:00:00Z" }),
  ];
  const r = buildReport(rows, "2026-09", { idleThreshold: 7, parkingProposed: new Set() });
  assert.equal(r.days_in_month, 30);
  assert.equal(r.swarms.length, 2);
  const a = r.swarms.find((s) => s.instance_id === "i-a")!, b = r.swarms.find((s) => s.instance_id === "i-b")!;
  assert.equal(a.month_usd, 50); // (70 + 70 + 10) / 3
  assert.equal(a.state, "stopped"); assert.equal(a.parked, true); assert.equal(a.nudge, false);
  assert.equal(b.month_usd, 40); assert.equal(b.nudge, true);
  assert.equal(r.swarms[0].instance_id, "i-a"); // sorted by month cost
  assert.deepEqual(r.totals, { swarms: 2, running: 1, parked: 1, nudge: 1, month_usd: 90, compute_usd: 35, ebs_usd: 10, snapshot_usd: 0, ip_usd: 0 });
  // a parking proposal in flight is the executor's job, not a nudge
  const r2 = buildReport(rows, "2026-09", { idleThreshold: 7, parkingProposed: new Set(["i-b"]) });
  assert.equal(r2.swarms.find((s) => s.instance_id === "i-b")!.nudge, false);
});

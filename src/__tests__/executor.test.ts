import assert from "node:assert/strict";
import { test } from "node:test";
import { decideAcuWindow, quietHours, acuWindowSaving, type AcuDecisionInput } from "../actions/acu_window.js";
import { pickSnapshots, archiveSaving, NO_VOLUME, type SnapshotFacts } from "../actions/snapshot_archive.js";
import { formatActionMessage } from "../executor.js";
import { hourProfile } from "../rds_load.js";
import { validateRuntime } from "../config.js";

/** A day that idles at 0.5 ACU from 22:00 to 06:00 UTC and works at 2-4 ACU otherwise, with p95 a little above the median. */
const dayNight = () => {
  const median = Array.from({ length: 24 }, (_, h) => (h >= 22 || h < 6 ? 0.5 : 2.5));
  const p95 = Array.from({ length: 24 }, (_, h) => (h >= 22 || h < 6 ? 0.5 : 4));
  return { median, p95, days: 14 };
};
const base = (over: Partial<AcuDecisionInput> = {}): AcuDecisionInput => ({
  cluster: "hub", by_hour: dayNight(), current_min: 2, current_max: 16, floor: 0.5, baseline_min: 2, last_set: null, acu_now: 0.5, cadence: "irregular", burst_start_minute: null, hour: 23, ...over,
});

test("acu: the quiet hours are those whose p95 stays at the floor", () => {
  assert.deepEqual(quietHours(dayNight(), 0.5), [0, 1, 2, 3, 4, 5, 22, 23]);
  assert.deepEqual(quietHours(dayNight(), 2), [0, 1, 2, 3, 4, 5, 22, 23]);
  assert.deepEqual(quietHours({ median: Array(24).fill(3), p95: Array(24).fill(3), days: 14 }, 0.5), []);
});

test("acu: lowers before two quiet hours, raises before a working hour, leaves the rest", () => {
  const down = decideAcuWindow(base({ hour: 23 }));
  assert.equal(down.wanted, 0.5);
  assert.match(down.reason, /23:00 and 00:00 UTC are quiet/);
  // at the floor already, still quiet: nothing
  assert.equal(decideAcuWindow(base({ hour: 1, current_min: 0.5, last_set: 0.5 })).wanted, null);
  // 05:00 is quiet but 06:00 works: not worth a single hour
  const single = decideAcuWindow(base({ hour: 5, current_min: 2 }));
  assert.equal(single.wanted, null);
  assert.match(single.reason, /not worth a change for one hour/);
  // the working hour comes: back to the configured minimum
  const up = decideAcuWindow(base({ hour: 6, current_min: 0.5, last_set: 0.5 }));
  assert.equal(up.wanted, 2);
  assert.match(up.reason, /06:00 UTC is a working hour/);
  // working hour and already at the baseline
  assert.equal(decideAcuWindow(base({ hour: 12 })).wanted, null);
});

test("acu: a busy database now is not lowered even in a usually quiet hour", () => {
  const d = decideAcuWindow(base({ hour: 23, acu_now: 3.2 }));
  assert.equal(d.wanted, null);
  assert.match(d.reason, /3.2 ACU right now/);
});

test("acu: the owner's own change to the minimum becomes the new band", () => {
  // the executor had set 0.5; the owner then set 4: 4 is neither floor, baseline nor last_set
  const d = decideAcuWindow(base({ hour: 23, current_min: 4, last_set: 0.5, baseline_min: 2 }));
  assert.equal(d.baseline_min, 4);
  assert.equal(d.wanted, 0.5);
  // the owner set the minimum to the floor themselves: nothing to move within
  const flat = decideAcuWindow(base({ hour: 23, current_min: 0.5, baseline_min: 0.5 }));
  assert.equal(flat.wanted, null);
  assert.match(flat.reason, /already at the floor/);
});

test("acu: hourly bursts, a round-the-clock database and a daily burst hour are respected", () => {
  assert.match(decideAcuWindow(base({ cadence: "hourly" })).reason, /every hour/);
  const busy = { median: Array(24).fill(2), p95: Array(24).fill(3), days: 14 };
  assert.match(decideAcuWindow(base({ by_hour: busy })).reason, /only 0 quiet hour/);
  // the profile says 03:00 is quiet but the daily job starts at 03:10: raise before it, never lower into it
  const job = decideAcuWindow(base({ hour: 3, current_min: 0.5, last_set: 0.5, cadence: "daily", burst_start_minute: 190 }));
  assert.equal(job.wanted, 2);
  assert.match(job.reason, /daily burst starts around 03:00/);
  const before = decideAcuWindow(base({ hour: 2, current_min: 2, cadence: "daily", burst_start_minute: 190 }));
  assert.equal(before.wanted, null);
});

test("acu: the saving is the band over the quiet hours at the ACU-hour price", () => {
  assert.equal(acuWindowSaving(2, 0.5, 8), Math.round(1.5 * 0.12 * 8 * 30.4 * 100) / 100);
});

test("rds load: the hour profile needs seven days and every hour", () => {
  const t: number[] = [], v: number[] = [];
  const start = Date.UTC(2026, 8, 1);
  for (let d = 0; d < 10; d++) for (let h = 0; h < 24; h++) for (let m = 0; m < 60; m += 5) { t.push(start + ((d * 24 + h) * 60 + m) * 60000); v.push(h < 6 ? 0.5 : 2 + (m === 55 ? 3 : 0)); }
  const p = hourProfile({ t, v })!;
  assert.equal(p.days, 10);
  assert.equal(p.median[3], 0.5);
  assert.equal(p.median[12], 2);
  assert.equal(p.p95[12], 5);
  assert.equal(hourProfile({ t: t.slice(0, 24 * 12 * 3), v: v.slice(0, 24 * 12 * 3) }), null);
});

const snap = (over: Partial<SnapshotFacts>): SnapshotFacts => ({
  snapshot_id: "snap-1", volume_id: "vol-a", size_gb: 100, started: "2026-01-01T00:00:00.000Z", age_days: 200, tier: "standard", description: null, name: null, ami_backed: false, managed_by: null, hands_off: false, volume_exists: false, ...over,
});

test("snapshots: the newest standard snapshot of a gone volume goes first, the rest wait", () => {
  const all = [
    snap({ snapshot_id: "snap-old", started: "2025-06-01T00:00:00.000Z", age_days: 400 }),
    snap({ snapshot_id: "snap-mid", started: "2025-09-01T00:00:00.000Z", age_days: 300 }),
    snap({ snapshot_id: "snap-new", started: "2026-01-01T00:00:00.000Z", age_days: 200 }),
  ];
  const { picks, left } = pickSnapshots(all, 90);
  assert.deepEqual(picks.map((p) => p.snapshot_id), ["snap-new"]);
  assert.equal(picks[0].rule, "orphan_newest");
  assert.equal(left["older sibling of a gone volume: waits for the newer one"], 2);
  // once snap-new is archived, snap-mid is the newest standard one
  const next = pickSnapshots(all.map((s) => (s.snapshot_id === "snap-new" ? { ...s, tier: "archive" } : s)), 90);
  assert.deepEqual(next.picks.map((p) => p.snapshot_id), ["snap-mid"]);
});

test("snapshots: age, AMI, Backup/DLM, hands-off, live volumes with several snapshots and unknown tiers are left alone", () => {
  const all = [
    snap({ snapshot_id: "young", age_days: 30 }),
    snap({ snapshot_id: "ami", ami_backed: true }),
    snap({ snapshot_id: "backup", managed_by: "aws:backup:source-resource" }),
    snap({ snapshot_id: "fenced", hands_off: true }),
    snap({ snapshot_id: "live-only", volume_id: "vol-live", volume_exists: true }),
    snap({ snapshot_id: "live-a", volume_id: "vol-busy", volume_exists: true }),
    snap({ snapshot_id: "live-b", volume_id: "vol-busy", volume_exists: true, started: "2026-02-01T00:00:00.000Z", age_days: 150 }),
    snap({ snapshot_id: "notier", tier: null }),
    snap({ snapshot_id: "copied-1", volume_id: NO_VOLUME, volume_exists: null, size_gb: 8 }),
    snap({ snapshot_id: "copied-2", volume_id: NO_VOLUME, volume_exists: null, size_gb: 500 }),
  ];
  const { picks, left } = pickSnapshots(all, 90);
  assert.deepEqual(picks.map((p) => p.snapshot_id), ["copied-2", "live-only", "copied-1"]);
  assert.equal(picks[1].rule, "only_snapshot");
  assert.equal(left["younger than 90 days"], 1);
  assert.equal(left["behind an AMI"], 1);
  assert.equal(left["managed by aws:backup:source-resource"], 1);
  assert.equal(left["tagged advisor:hands-off"], 1);
  assert.equal(left["one of several snapshots of a live volume"], 2);
  assert.equal(left["storage tier unknown"], 1);
  assert.equal(archiveSaving(100), 3.75);
});

test("executor: the Sphinx message says what happened, why, and how to undo, with the link", () => {
  const m = formatActionMessage({ id: 7, status: "verified", kind: "acu_window", title: "hub: minimum capacity 2 → 0.5 ACU for the quiet hours", reason: "23:00 and 00:00 UTC are quiet", rollback: "set the minimum back to 2 ACU", result: null, error: null, est_usd_month: 43.78 }, "http://10.0.0.5:9034");
  assert.match(m, /^✅ Auto-action applied and verified · hub: minimum capacity 2 → 0.5 ACU/);
  assert.match(m, /≈ 43.78 USD\/month/);
  assert.match(m, /Undo: set the minimum back to 2 ACU/);
  assert.match(m, /http:\/\/10.0.0.5:9034\/actions\?id=7$/);
  const f = formatActionMessage({ id: 8, status: "failed", kind: "snapshot_archive", title: "snap-1: 100 GB snapshot", reason: "r", rollback: "x", result: null, error: "AccessDenied", est_usd_month: null }, "http://x");
  assert.match(f, /^❌ Auto-action failed/);
  assert.match(f, /Error: AccessDenied/);
  assert.doesNotMatch(f, /Undo/);
});

test("executor settings: the actuator role must be a role ARN, the mode one of three", () => {
  assert.equal(validateRuntime("actRoleArn", "arn:aws:iam::123456789012:role/aws-advisor-act"), "arn:aws:iam::123456789012:role/aws-advisor-act");
  assert.equal(validateRuntime("actRoleArn", ""), "");
  assert.throws(() => validateRuntime("actRoleArn", "aws-advisor-act"), /arn:aws:iam/);
  assert.equal(validateRuntime("actMode", "apply"), "apply");
  assert.throws(() => validateRuntime("actMode", "yes"), /one of off, dry_run, apply/);
  assert.throws(() => validateRuntime("actAcuFloor", "0.1"), /at least 0.5/);
});

import assert from "node:assert/strict";
import { test } from "node:test";
import { targetThroughput, throughputSaving, peakFromSeries, GP3_BASELINE_MIBPS } from "../actions/ebs_throughput_trim.js";
import { snapEfsDays, iaRule, lifecyclePolicies, efsSavingCeiling } from "../actions/efs_lifecycle.js";
import { quietVerdict } from "../actions/log_retention_tune.js";

test("gp3 throughput trim: target is twice the peak rounded up to 25, within the baseline, the 1,000 ceiling and the IOPS ratio", () => {
  assert.equal(targetThroughput(0, 3000), GP3_BASELINE_MIBPS);
  assert.equal(targetThroughput(40, 3000), 125); // 80 → floor
  assert.equal(targetThroughput(70, 3000), 150); // 140 → 150
  assert.equal(targetThroughput(76, 3000), 175); // 152 → 175
  assert.equal(targetThroughput(150, 3000), 300);
  assert.equal(targetThroughput(700, 16000), 1000); // 1,400 → ceiling
  // the ratio cap: 3,000 IOPS allow 750 MiB/s; 600 IOPS would allow 150
  assert.equal(targetThroughput(500, 3000), 750);
  assert.equal(targetThroughput(200, 600), 150);
  // a cap under the baseline never pushes the target under 125
  assert.equal(targetThroughput(200, 100), 125);
});

test("gp3 throughput trim: the saving is the MiB/s removed at 0.04, never negative", () => {
  assert.equal(throughputSaving(500, 250), 10);
  assert.equal(throughputSaving(125, 250), 0);
});

test("gp3 throughput trim: the peak is the busiest five-minute period of reads plus writes, days counted once", () => {
  const t0 = Date.UTC(2026, 8, 1, 0, 0, 0);
  const ts = [t0, t0 + 300000, t0 + 86400000];
  const read = { ts, values: [300 * 1048576 * 10, 300 * 1048576 * 2, 0] };
  const write = { ts, values: [300 * 1048576 * 5, 300 * 1048576 * 40, 300 * 1048576] };
  const p = peakFromSeries(read, write);
  assert.equal(p.peak_mibps, 42);
  assert.equal(p.metric_days, 2);
  assert.deepEqual(peakFromSeries({ ts: [], values: [] }, { ts: [], values: [] }), { peak_mibps: 0, metric_days: 0 });
});

test("efs lifecycle: days snap to a value EFS accepts and the policy moves to IA and back on first read", () => {
  assert.equal(snapEfsDays(1), 1); assert.equal(snapEfsDays(10), 14); assert.equal(snapEfsDays(30), 30); assert.equal(snapEfsDays(31), 60); assert.equal(snapEfsDays(9999), 365);
  assert.equal(iaRule(1), "AFTER_1_DAY"); assert.equal(iaRule(30), "AFTER_30_DAYS"); assert.equal(iaRule(45), "AFTER_60_DAYS");
  assert.deepEqual(lifecyclePolicies(30), [{ TransitionToIA: "AFTER_30_DAYS" }, { TransitionToPrimaryStorageClass: "AFTER_1_ACCESS" }]);
  // 100 GB standard: half turns cold at (0.30 − 0.016) → 14.20
  assert.equal(efsSavingCeiling(100e9), 14.2);
});

test("log retention tune: quiet only with enough history, no query in the window and no subscription", () => {
  const now = new Date("2026-09-27T12:00:00Z");
  assert.match(quietVerdict({ historySince: null, quietDays: 90, lastQueryAt: null, hasSubscription: false, now }).reason, /no query history/);
  const young = quietVerdict({ historySince: "2026-09-01T00:00:00Z", quietDays: 90, lastQueryAt: null, hasSubscription: false, now });
  assert.equal(young.quiet, false); assert.match(young.reason, /history since 2026-09-01, 64 day\(s\) to go/); assert.equal(young.days_to_go, 64);
  const old = "2026-05-01T00:00:00Z";
  assert.equal(quietVerdict({ historySince: old, quietDays: 90, lastQueryAt: null, hasSubscription: true, now }).reason, "a subscription filter reads the group");
  assert.match(quietVerdict({ historySince: old, quietDays: 90, lastQueryAt: "2026-08-15T10:00:00Z", hasSubscription: false, now }).reason, /queried 2026-08-15 10:00 UTC/);
  const quiet = quietVerdict({ historySince: old, quietDays: 90, lastQueryAt: "2026-06-01T00:00:00Z", hasSubscription: false, now });
  assert.equal(quiet.quiet, true); assert.equal(quiet.days_to_go, 0);
});

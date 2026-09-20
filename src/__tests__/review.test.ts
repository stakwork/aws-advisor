import { test } from "node:test";
import assert from "node:assert";
import { diskForecast, idleContainers, memoryPressure, spendStep, sustainedIdle } from "../review_math.js";

const day = (i: number, o: Partial<any> = {}) => ({ day: `2026-09-${String(i + 1).padStart(2, "0")}`, samples: 24, mem_pct_avg: 20, mem_pct_max: 30, disk_pct_avg: 40, disk_pct_max: 41, load_per_cpu_avg: 0.05, load_per_cpu_max: 0.3, containers_running_avg: 3, ...o });

test("sustained idle needs five days and low memory, load and CPU together", () => {
  assert.equal(sustainedIdle([day(0), day(1), day(2)], 5).idle, false);
  const v = sustainedIdle(Array.from({ length: 7 }, (_, i) => day(i)), 8);
  assert.equal(v.idle, true);
  assert.equal(v.reasons.length, 3);
  assert.equal(sustainedIdle(Array.from({ length: 7 }, (_, i) => day(i, { mem_pct_avg: 70, mem_pct_max: 80 })), 8).idle, false, "memory in use");
  assert.equal(sustainedIdle(Array.from({ length: 7 }, (_, i) => day(i)), 45).idle, false, "CPU p95 high");
  assert.equal(sustainedIdle(Array.from({ length: 7 }, (_, i) => day(i)), null).idle, true, "no CPU baseline yet: memory and load decide");
});

test("disk forecast: a steady climb gives days to full; flat disks give none", () => {
  const rising = Array.from({ length: 10 }, (_, i) => day(i, { disk_pct_avg: 60 + i * 2 }));
  const f = diskForecast(rising)!;
  assert.ok(Math.abs(f.slope_pct_day - 2) < 1e-9);
  assert.ok(Math.abs(f.days_to_full! - 6) < 1e-6, `days to full ${f.days_to_full}`);
  assert.ok(f.r2 > 0.99);
  assert.equal(diskForecast(Array.from({ length: 10 }, (_, i) => day(i)))!.days_to_full, null);
  assert.equal(diskForecast([day(0), day(1)]), null);
});

test("memory pressure, idle containers and spend steps", () => {
  assert.equal(memoryPressure(Array.from({ length: 6 }, (_, i) => day(i, { mem_pct_avg: 90, mem_pct_max: 95 }))).pressure, true);
  assert.equal(memoryPressure(Array.from({ length: 6 }, (_, i) => day(i))).pressure, false);
  const cs = idleContainers([
    { name: "exporter", image: "x", days: 10, running_share: 1, cpu_pct_avg: 0.05, cpu_pct_max: 1, mem_bytes_avg: 2e7 },
    { name: "app", image: "y", days: 10, running_share: 1, cpu_pct_avg: 12, cpu_pct_max: 80, mem_bytes_avg: 2e9 },
    { name: "cron", image: "z", days: 10, running_share: 0.1, cpu_pct_avg: 0.01, cpu_pct_max: 0.1, mem_bytes_avg: 1e6 },
  ], 30);
  assert.deepEqual(cs.map((c) => c.name), ["exporter"]);
  assert.equal(spendStep("EC2", [110, 112, 108], { median: 100, mad: 5 }), null, "10 % up is not a step");
  const s = spendStep("EC2", [160, 170, 165], { median: 100, mad: 5 })!;
  assert.ok(s && s.ratio > 1.6 && s.excess_per_day > 60);
  assert.equal(spendStep("tiny", [12, 13], { median: 5, mad: 1 }), null, "under 20 USD a day of excess is noise");
  assert.equal(spendStep("EC2", [160], { median: 100, mad: 5 }), null, "one day is not enough");
});

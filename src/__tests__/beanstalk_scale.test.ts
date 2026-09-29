import assert from "node:assert/strict";
import { test } from "node:test";
import { desiredByHour, desiredChanges, parseBand, scaleVerdict, FLOOR_SHARE, type Band, type UsageHour, type VerdictInput } from "../actions/beanstalk_scale.js";

const H = 3600000;
const band = (floor: number, ceiling: number | null): Band => ({ floor, ceiling, text: ceiling == null ? "auto" : `${floor}-${ceiling}` });
/** `days` days of hourly points; `desired` and `cpu` decide each hour from its index. */
const series = (days: number, desired: (i: number) => number, cpu: (i: number) => number): UsageHour[] => Array.from({ length: days * 24 }, (_, i) => ({ at: i * H, desired: desired(i), cpu_avg: cpu(i) }));
const input = (over: Partial<VerdictInput> = {}): VerdictInput => ({ bounds: { min: 2, max: 6, desired: 2 }, band: band(1, 8), hours: series(14, () => 2, () => 12), days: 14, low_cpu: 30, high_cpu: 70, pressure_hours: 3, health_ok: true, ...over });

test("beanstalk scale: the tag is a band, floor-ceiling or auto", () => {
  assert.deepEqual(parseBand("2-8"), { floor: 2, ceiling: 8, text: "2-8" });
  assert.deepEqual(parseBand(" 1 - 4 "), { floor: 1, ceiling: 4, text: "1 - 4" });
  assert.deepEqual(parseBand("AUTO"), { floor: 1, ceiling: null, text: "auto" });
  assert.match((parseBand("0-4") as any).error, /at least 1/);
  assert.match((parseBand("4-4") as any).error, /above the floor/);
  assert.match((parseBand("big") as any).error, /expected/);
});

test("beanstalk scale: the desired capacity is replayed hour by hour from the activities' causes", () => {
  const acts = [
    { StartTime: new Date(30 * H + 600000), Cause: "At 2026-09-28T10:10:00Z a monitor alarm awseb-e-x-stack-AWSEBCloudwatchAlarmHigh in state ALARM triggered policy changing the desired capacity from 2 to 3.  At 2026-09-28T10:10:30Z an instance was started in response to a difference between desired and actual capacity, increasing the capacity from 2 to 3." },
    { StartTime: new Date(35 * H + 100), Cause: "At 2026-09-28T15:00:00Z a monitor alarm AlarmLow in state ALARM triggered policy changing the desired capacity from 3 to 2." },
    { StartTime: new Date(40 * H), Cause: "At 2026-09-28T20:00:00Z a user request update of AutoScalingGroup constraints to min: 1, max: 6, desired: 1 changing the desired capacity from 2 to 1." },
  ];
  const changes = desiredChanges(acts);
  assert.deepEqual(changes.map((c) => [c.from, c.to]), [[2, 3], [3, 2], [2, 1]]);
  const hours = [0, 30 * H, 31 * H, 35 * H, 36 * H, 40 * H, 41 * H];
  const d = desiredByHour(hours, 1, changes);
  assert.equal(d.get(0), 2); // before any change: what the first change started from
  assert.equal(d.get(30 * H), 2); // the change at 30:10 lands after the hour started
  assert.equal(d.get(31 * H), 3);
  assert.equal(d.get(35 * H), 3); // 35:00:00.1 is after the hour start
  assert.equal(d.get(36 * H), 2);
  assert.equal(d.get(40 * H), 1); // exactly at the hour start counts as in force
  assert.equal(d.get(41 * H), 1);
});

test("beanstalk scale: a group idle at its floor for the whole window gets the floor cut by one, with the projection", () => {
  const v = scaleVerdict(input());
  assert.equal(v.move, "floor_down"); assert.equal(v.option, "MinSize"); assert.equal(v.from, 2); assert.equal(v.to, 1);
  assert.equal(v.floor_share, 1); assert.equal(v.floor_p95, 12);
  assert.match(v.reason, /100 % of the last 14 days/); assert.match(v.reason, /1 instance would have run at about 24\.0 %/);
});

test("beanstalk scale: the floor never goes under the tag, and a group that scales out for real or runs warm is left alone", () => {
  assert.equal(scaleVerdict(input({ band: band(2, 8) })).move, null);
  assert.match(scaleVerdict(input({ band: band(2, 8) })).reason, /already the tag's floor/);
  // out at 3 for 20 % of the hours
  const busy = scaleVerdict(input({ hours: series(14, (i) => (i % 5 === 0 ? 3 : 2), () => 12) }));
  assert.equal(busy.move, null); assert.match(busy.reason, /80 % of the window/); assert.ok(FLOOR_SHARE > 0.8);
  const warm = scaleVerdict(input({ hours: series(14, () => 2, (i) => (i % 10 === 0 ? 45 : 12)) }));
  assert.equal(warm.move, null); assert.match(warm.reason, /p95 CPU there is 45\.0 %/);
  const sick = scaleVerdict(input({ health_ok: false }));
  assert.equal(sick.move, null); assert.match(sick.reason, /health is not Ok/);
  assert.match(scaleVerdict(input({ days: 6 })).reason, /6 day\(s\) of metrics/);
});

test("beanstalk scale: hours pinned at the maximum with high CPU raise the ceiling by one, up to the tag, and win over an idle floor", () => {
  const pinned = series(14, (i) => (i < 4 ? 6 : 2), (i) => (i < 4 ? 85 : 10));
  const v = scaleVerdict(input({ hours: pinned }));
  assert.equal(v.move, "ceiling_up"); assert.equal(v.option, "MaxSize"); assert.equal(v.from, 6); assert.equal(v.to, 7); assert.equal(v.pressure_hours, 4);
  assert.match(v.reason, /4 h of the last 14 days pinned/);
  // two hours only: not pressure, so the idle floor rule speaks
  assert.equal(scaleVerdict(input({ hours: series(14, (i) => (i < 2 ? 6 : 2), (i) => (i < 2 ? 85 : 10)) })).move, "floor_down");
  // at max but cool: the cap was not the problem
  assert.equal(scaleVerdict(input({ hours: series(14, (i) => (i < 4 ? 6 : 2), () => 40) })).pressure_hours, 0);
  // the tag's ceiling and "auto" both hold the ceiling
  assert.match(scaleVerdict(input({ hours: pinned, band: band(1, 6) })).reason, /is the tag's ceiling/);
  assert.match(scaleVerdict(input({ hours: pinned, band: band(1, null) })).reason, /tag says "auto"/);
});

import assert from "node:assert/strict";
import { test } from "node:test";
import { passMinute, planTimeline, type PlanInput } from "../capacity_timeline.js";
import type { CapacityPattern } from "../capacity_pattern.js";
import type { QuietWindow } from "../usage_profile.js";

const H = 3600000;
// Wednesday 2026-09-30 13:10 UTC: ring hour 3*24+13 = 85
const NOW = Date.parse("2026-09-30T13:10:00Z");
/** A learned week at `base`, with `busy` from 14:00 to 18:00 UTC every day. */
function pattern(base: number, busy: number, over: Partial<CapacityPattern> = {}): CapacityPattern {
  const learned = Array.from({ length: 168 }, (_, r) => (r % 24 >= 14 && r % 24 < 18 ? busy : base));
  return { computed_at: new Date(NOW).toISOString(), days: 28, weeks: 4, coverage: 1, confident: true, floor: base, ceiling: 8, learned, wanted: learned, pressure: new Array(168).fill(0), pressure_events: 0, summary: "", ...over };
}
const input = (over: Partial<PlanInput> = {}): PlanInput => ({
  now: NOW, mode: "apply", paused: false, consent: true, band: { floor: 3, ceiling: 8 }, pattern: pattern(3, 5), current_min: 3,
  state: { baseline_min: 3, last_set: 3, since: "2026-09-01T00:00:00Z" }, last_applied_at: null, windows: [], window_confidence: 0, pass_minute: 45, ...over,
});

test("capacity timeline: the pass minute comes from a plain hourly cron", () => {
  assert.equal(passMinute("45 * * * *"), 45);
  assert.equal(passMinute("0 * * * *"), 0);
  assert.equal(passMinute("*/10 * * * *"), null);
  assert.equal(passMinute("45 6 * * *"), null);
});

test("capacity timeline: a confident pattern in apply mode raises before the busy hours and drops back after them", () => {
  const t = planTimeline(input());
  assert.equal(t.status, "driving");
  assert.equal(t.hours.length, 24);
  assert.equal(t.hours[0].at, "2026-09-30T14:00:00.000Z");
  assert.equal(t.hours[0].decided_at, "2026-09-30T13:45:00.000Z");
  assert.deepEqual(t.hours[0].change, { from: 3, to: 5, driver: "pattern", applied: true });
  assert.equal(t.hours[0].min, 5);
  // the hourly moves are exempt from the one-step-per-24-hours rule: 18:00 goes back to 3 at the 17:45 pass
  const six = t.hours.find((h) => h.at === "2026-09-30T18:00:00.000Z")!;
  assert.deepEqual(six.change, { from: 5, to: 3, driver: "pattern", applied: true });
  assert.equal(six.held, null);
  assert.equal(six.min, 3);
  assert.equal(t.blocked_until, null);
});

test("capacity timeline: dry run never moves the minimum; every differing hour is a proposal", () => {
  const t = planTimeline(input({ mode: "dry_run" }));
  const changes = t.hours.filter((h) => h.change);
  assert.equal(changes.length, 4); // 14, 15, 16, 17 today
  assert.ok(changes.every((h) => h.change!.applied === false && h.min === 3));
  assert.ok(t.uncertain.some((u) => /dry run/.test(u)));
});

test("capacity timeline: a recent step holds the trim and the raise, not the hourly moves", () => {
  const t = planTimeline(input({ last_applied_at: "2026-09-30 10:45:00" }));
  assert.deepEqual(t.hours[0].change, { from: 3, to: 5, driver: "pattern", applied: true });
  assert.equal(t.blocked_until, "2026-10-01T10:45:00.000Z");
  assert.ok(t.uncertain.some((u) => /idle-floor trim and the ceiling raise wait until 2026-10-01 10:45 UTC/.test(u)));
});

test("capacity timeline: a hand-set minimum holds the pattern for a day", () => {
  const t = planTimeline(input({ current_min: 4, state: { baseline_min: 3, last_set: 3, since: "x", hand_set_at: "2026-09-30T12:00:00Z" } }));
  assert.equal(t.status, "hand_set");
  assert.equal(t.hand_set_until, "2026-10-01T12:00:00.000Z");
  assert.ok(t.hours.slice(0, 20).every((h) => !h.change));
  assert.match(t.hours[0].held!, /set by hand/);
});

test("capacity timeline: not confident yet falls back to the quiet windows, or learns", () => {
  const learning = planTimeline(input({ pattern: pattern(3, 5, { confident: false, weeks: 1, coverage: 0.5 }) }));
  assert.equal(learning.status, "learning");
  assert.match(learning.headline, /1 of 2 weeks, 50 % of 80 %/);
  assert.ok(learning.hours.every((h) => !h.change && h.min === 3));
  // quiet every night 20:00–06:00 UTC, baseline 5, floor 3: the pass drops to 3 before 20:00
  const nights: QuietWindow[] = [0, 1, 2, 3, 4, 5, 6].map((d) => ({ start: d * 24 + 20, end: d * 24 + 30, hours: 10, effective_start: d * 24 + 20, effective_end: d * 24 + 30, effective_hours: 10, confidence: 0.95, probe_coverage: 1, label: "" }));
  const w = planTimeline(input({ pattern: pattern(3, 5, { confident: false, weeks: 1 }), current_min: 5, state: { baseline_min: 5, last_set: null, since: "x" }, windows: nights, window_confidence: 0.95 }));
  assert.equal(w.status, "window");
  const drop = w.hours.find((h) => h.change)!;
  assert.equal(drop.at, "2026-09-30T20:00:00.000Z");
  assert.deepEqual(drop.change, { from: 5, to: 3, driver: "window", applied: true });
});

test("capacity timeline: off, paused and no consent plan nothing", () => {
  assert.equal(planTimeline(input({ mode: "off" })).status, "off");
  assert.equal(planTimeline(input({ paused: true })).status, "paused");
  assert.equal(planTimeline(input({ consent: false })).status, "no_consent");
  assert.ok(planTimeline(input({ paused: true })).hours.every((h) => !h.change));
  assert.equal(planTimeline(input({ band: { floor: 3, ceiling: null } })).status, "no_band");
});

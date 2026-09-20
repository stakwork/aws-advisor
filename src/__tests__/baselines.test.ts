import { test } from "node:test";
import assert from "node:assert";
import { buildBaseline, robustStats, scoreValue, seasonal } from "../baseline_math.js";

const hour = 3600_000;
const start = Date.UTC(2026, 8, 1); // a Tuesday

test("robust stats: a spike does not move the median or the MAD", () => {
  const calm = robustStats([10, 11, 9, 10, 12, 10, 11]);
  const spiked = robustStats([10, 11, 9, 10, 12, 10, 11, 500]);
  assert.equal(calm.median, 10);
  assert.equal(spiked.median, 10.5, "eight values: the median moves half a unit, not towards 500");
  assert.ok(spiked.mad < 3, `mad ${spiked.mad}`);
  assert.equal(spiked.max, 500);
  assert.ok(spiked.p95 > 12);
});

test("seasonal profile: needs seven days, then gives a median per hour of day", () => {
  const twoDays = Array.from({ length: 48 }, (_, i) => ({ t: start + i * hour, v: i % 24 === 15 ? 5 : 1 }));
  assert.ok(seasonal(twoDays).by_hour.every((x) => x == null), "two days: no profile");
  const tenDays = Array.from({ length: 240 }, (_, i) => ({ t: start + i * hour, v: i % 24 === 15 ? 5 : 1 }));
  const s = seasonal(tenDays);
  assert.equal(s.days, 10);
  assert.equal(s.by_hour[15], 5);
  assert.equal(s.by_hour[3], 1);
});

test("scoring: the expected value follows the hour; a value twice the hourly median and beyond p95 is extreme", () => {
  const pts = Array.from({ length: 24 * 14 }, (_, i) => ({ t: start + i * hour, v: (i % 24 === 15 ? 3e9 : 1e9) + (i % 7) * 1e7 }));
  const b = buildBaseline(pts, 14, "test", "bytes");
  const at15 = new Date(start + 15 * hour);
  const at03 = new Date(start + 3 * hour);
  assert.equal(scoreValue(b, 3.1e9, at15).level, "normal", "3.1 GB at 15:00 is what the hour looks like");
  assert.equal(scoreValue(b, 3.1e9, at03).level, "extreme", "3.1 GB at 03:00 is three times the hour's median and beyond p95");
  assert.equal(scoreValue(b, 1.4e9, at03).level, "high", "1.4 GB at 03:00 is far in spread terms but not double");
  assert.equal(scoreValue(b, 3.1e9, at15).basis, "hour");
  assert.equal(scoreValue({ median: 1e9, mad: 1e8, by_hour: Array(24).fill(null), p95: 1.3e9 }, 1e9).basis, "median");
});

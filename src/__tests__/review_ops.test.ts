import { test } from "node:test";
import assert from "node:assert";
import { dayJump } from "../review_ops.js";

const series = (vals: number[]) => vals.map((usd, i) => ({ day: `2026-03-${String(i + 1).padStart(2, "0")}`, usd }));

test("dayJump flags a day well above the two weeks before it", () => {
  const j = dayJump(series([...Array(14).fill(500), 800]))!;
  assert.equal(j.day, "2026-03-15"); assert.equal(j.median, 500); assert.equal(j.excess, 300);
});

test("dayJump stays quiet on small or short moves", () => {
  assert.equal(dayJump(series([...Array(14).fill(500), 560])), null);
  assert.equal(dayJump(series([...Array(14).fill(10), 40])), null);
  assert.equal(dayJump(series([100, 100, 300])), null);
});

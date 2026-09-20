import { test } from "node:test";
import assert from "node:assert";
import { diskVerdict } from "../disk_alerts.js";

test("disk verdicts with hysteresis: alarm at 90, warning at 80, each holds until five points below", () => {
  const t = { warn: 80, alarm: 90 };
  assert.equal(diskVerdict(95, t), "full");
  assert.equal(diskVerdict(90, t), "full");
  assert.equal(diskVerdict(87, t, "full"), "full", "an open alarm holds at 87");
  assert.equal(diskVerdict(84, t, "full"), "high", "below 85 the alarm steps down to a warning");
  assert.equal(diskVerdict(84, t), "high");
  assert.equal(diskVerdict(77, t, "high"), "high", "an open warning holds at 77");
  assert.equal(diskVerdict(74, t, "high"), "ok");
  assert.equal(diskVerdict(60, t), "ok");
});

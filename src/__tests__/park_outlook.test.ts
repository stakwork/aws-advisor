import { test } from "node:test";
import assert from "node:assert";

test("nextParkTimes: the office-hours pass replayed forward, at the pass minute, before the hour the window names", async () => {
  const { nextParkTimes } = await import("../park_outlook.js");
  const { parseSchedule } = await import("../actions/schedule_hours.js");
  const s = parseSchedule("off daily 01-06 UTC") as any;
  const now = new Date("2026-10-08T14:10:00Z");
  // running: the 00:45 pass decides for 01:00, the 05:45 pass for 06:00
  assert.deepEqual(nextParkTimes(s, "running", now, 45), { sleep_at: new Date("2026-10-09T00:45:00Z"), wake_at: new Date("2026-10-09T05:45:00Z") });
  // stopped: wake first, then the next night's sleep
  const night = new Date("2026-10-09T02:00:00Z");
  assert.deepEqual(nextParkTimes(s, "stopped", night, 45), { wake_at: new Date("2026-10-09T05:45:00Z"), sleep_at: new Date("2026-10-10T00:45:00Z") });
  // a box running inside the off window sleeps at the very next pass
  assert.equal(nextParkTimes(s, "running", night, 45).sleep_at?.toISOString(), "2026-10-09T02:45:00.000Z");
  // woken by hand: held awake until the hold ends, then the next pass that wants it stopped
  assert.equal(nextParkTimes(s, "running", night, 45, new Date("2026-10-09T04:00:00Z")).sleep_at?.toISOString(), "2026-10-09T04:45:00.000Z");
  // a pass exactly now has run already
  assert.equal(nextParkTimes(s, "running", new Date("2026-10-09T00:45:00Z"), 45).sleep_at?.toISOString(), "2026-10-09T01:45:00.000Z");
  // a running window in another time zone: weekdays 08-20 Madrid (UTC+2 in October) sleeps at 17:45 UTC
  const office = parseSchedule("weekdays 08-20 Europe/Madrid") as any;
  assert.equal(nextParkTimes(office, "running", now, 45).sleep_at?.toISOString(), "2026-10-08T17:45:00.000Z");
  // Friday evening: wakes Monday 05:45 UTC
  assert.equal(nextParkTimes(office, "stopped", new Date("2026-10-09T20:00:00Z"), 45).wake_at?.toISOString(), "2026-10-12T05:45:00.000Z");
  // a window that never wants it stopped
  assert.deepEqual(nextParkTimes(parseSchedule("daily 00-24 UTC") as any, "running", now, 45), { sleep_at: null, wake_at: null });
});

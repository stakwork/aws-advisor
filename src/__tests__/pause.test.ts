import assert from "node:assert/strict";
import { test } from "node:test";

test("kill switch: pause is remembered with who and why, an expired until counts as resumed, resume clears it", async () => {
  const { pauseActions, pauseState, resumeActions } = await import("../executor.js");
  const { setSetting } = await import("../db.js");
  setSetting("act:paused", JSON.stringify({ paused: false }));
  assert.deepEqual(pauseState(), { paused: false });
  const p = pauseActions("chat", "the IOPS trim on vol-1 looked wrong");
  assert.equal(p.paused, true); assert.equal(p.by, "chat"); assert.equal(p.reason, "the IOPS trim on vol-1 looked wrong"); assert.ok(p.at);
  assert.equal(pauseState().paused, true);
  // a timed pause: paused before `until`, resumed after it
  const until = new Date(Date.now() + 3600000).toISOString();
  pauseActions("page", "deploy window", until);
  assert.equal(pauseState().paused, true);
  assert.equal(pauseState(Date.now() + 2 * 3600000).paused, false);
  assert.throws(() => pauseActions("page", "x", "not a date"), /is not a date/);
  assert.deepEqual(resumeActions("page"), { paused: false });
  assert.equal(pauseState().paused, false);
  // resuming when not paused is a no-op
  assert.deepEqual(resumeActions("page"), { paused: false });
});

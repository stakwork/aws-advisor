import assert from "node:assert/strict";
import { test } from "node:test";
import { parseProgress, progressSummary, statusAfterProgress, validateProgress } from "../progress.js";
import { parseRecQuery, recMatches } from "../paging.js";

const NOW = new Date("2026-09-23T10:00:00Z");

test("progress: a valid checklist is normalised (unique, sorted) and stamped; bad shapes are named", () => {
  const ok = validateProgress({ plan: "resolution:12", total: 6, done: [3, 1, 1], follow_up: "2026-09-30" }, NOW);
  assert.ok("progress" in ok);
  assert.deepEqual(ok.progress, { plan: "resolution:12", total: 6, done: [1, 3], follow_up: "2026-09-30", updated_at: "2026-09-23 10:00:00" });
  const pb = validateProgress({ plan: "playbook:aws_thrifty.control.nat_gateway", total: 4, done: [], follow_up: "" }, NOW);
  assert.ok("progress" in pb && pb.progress.follow_up === null);
  for (const [body, why] of [
    [{ plan: "whatever", total: 3, done: [] }, "plan"],
    [{ plan: "resolution:1", total: 99, done: [] }, "total"],
    [{ plan: "resolution:1", total: 3, done: [3] }, "done"],
    [{ plan: "resolution:1", total: 3, done: [0], follow_up: "next week" }, "follow_up"],
    [{ plan: "resolution:1", total: 3, done: [0], follow_up: "2026-13-45" }, "follow_up"],
    [null, "plan"],
  ] as const) {
    const v = validateProgress(body, NOW);
    assert.ok("error" in v && v.error.includes(why), `${JSON.stringify(body)} → ${JSON.stringify(v)}`);
  }
});

test("progress: the stored JSON round-trips, and garbage reads as no progress", () => {
  const v = validateProgress({ plan: "resolution:12", total: 6, done: [0] }, NOW);
  assert.ok("progress" in v);
  assert.deepEqual(parseProgress(JSON.stringify(v.progress)), v.progress);
  assert.equal(parseProgress(null), null);
  assert.equal(parseProgress("not json"), null);
  assert.equal(parseProgress('{"done": 3}'), null);
});

test("progress: ticking the first step moves an open or snoozed item to pending, and nothing else", () => {
  const started = { plan: "resolution:1", total: 3, done: [0], follow_up: null, updated_at: "" };
  const nothing = { ...started, done: [] };
  assert.equal(statusAfterProgress("open", started), "pending");
  assert.equal(statusAfterProgress("snoozed", started), "pending");
  assert.equal(statusAfterProgress("open", nothing), null);
  for (const s of ["pending", "approved", "done", "rejected"]) assert.equal(statusAfterProgress(s, started), null, s);
});

test("progress: the row summary says how far and when to look again, flagged once that day has come", () => {
  const p = { plan: "resolution:1", total: 6, done: [0, 1], follow_up: "2026-09-30", updated_at: "" };
  assert.deepEqual(progressSummary(p, "2026-09-23"), { text: "2 of 6 steps · check again 2026-09-30", due: false });
  assert.deepEqual(progressSummary(p, "2026-09-30"), { text: "2 of 6 steps · check again: due 2026-09-30", due: true });
  assert.deepEqual(progressSummary({ ...p, follow_up: null }, "2026-09-23"), { text: "2 of 6 steps", due: false });
  assert.equal(progressSummary(null, "2026-09-23"), null);
  assert.equal(progressSummary({ ...p, total: 0, follow_up: null }, "2026-09-23"), null);
});

test("recommendation search: '#123' and '123' are ids, exact, and still match text; words match title and resource", () => {
  const rows = [
    { id: 12, title: "Stop idle i-0abc", resource: "i-0abc", resource_name: "batch-worker" },
    { id: 120, title: "Delete snapshot snap-120", resource: "snap-120", resource_name: null },
  ];
  assert.deepEqual(parseRecQuery(" #12 "), { id: 12, text: "#12" });
  assert.deepEqual(parseRecQuery("12"), { id: 12, text: "12" });
  assert.deepEqual(parseRecQuery("Idle"), { id: null, text: "idle" });
  assert.deepEqual(rows.filter((r) => recMatches(r, parseRecQuery("#12"))).map((r) => r.id), [12]);
  // "120" is an id and a substring of the snapshot's resource, so both routes find #120 and only #120.
  assert.deepEqual(rows.filter((r) => recMatches(r, parseRecQuery("120"))).map((r) => r.id), [120]);
  assert.deepEqual(rows.filter((r) => recMatches(r, parseRecQuery("worker"))).map((r) => r.id), [12]);
  assert.deepEqual(rows.filter((r) => recMatches(r, parseRecQuery(""))).map((r) => r.id), [12, 120]);
});

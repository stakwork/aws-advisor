import assert from "node:assert/strict";
import { test } from "node:test";
import { buildProfile, busyReasons, insightsRegex, logQuerySets, logSignalQuery, sampleQuiet, type HourSample } from "../usage_profile.js";
import { isUnsure, parseUsageResult } from "../usage_agent.js";
import type { UsageReview } from "../usage_review.js";

const H = 3600000; const START = Date.UTC(2026, 8, 6);
const office = (d: number, h: number) => d >= 1 && d <= 5 && h >= 8 && h < 18;

test("usage log signal: a use-signal line in the shipped logs makes the hour busy and counts as evidence for the window", () => {
  const base: HourSample = { at: START, cpu_avg: 1, cpu_max: 3, net_bytes: 1e5, requests: null, probes: [] };
  assert.equal(sampleQuiet({ ...base, log_signals: 0 }), true);
  assert.equal(sampleQuiet({ ...base, log_signals: 3 }), false);
  assert.equal(busyReasons({ ...base, log_signals: 3 }).logs, true);
  assert.equal(busyReasons({ ...base, log_signals: null }).logs, false);
  // a week of log evidence over a CloudWatch-only profile lifts the confidence above 0.6
  const samples: HourSample[] = Array.from({ length: 28 * 24 }, (_, i) => { const at = START + i * H; const d = new Date(at); const b = office(d.getUTCDay(), d.getUTCHours()); return { at, cpu_avg: b ? 30 : 2, cpu_max: b ? 60 : 4, net_bytes: b ? 50e6 : 1e6, requests: null, probes: [], log_signals: i >= 21 * 24 ? (b ? 40 : 0) : null }; });
  const p = buildProfile({ subject: "i-l1", kind: "ec2", samples });
  assert.equal(p.signals.log_hours, 7 * 24);
  assert.ok(p.quiet_windows[0].confidence > 0.6 && p.quiet_windows[0].confidence < 1, `confidence ${p.quiet_windows[0].confidence}`);
  assert.match(p.summary, /the shipped logs \(168 h scanned\) cover 25 % of the quiet hours/);
  assert.equal(p.hours[1 * 24 + 9].busy_logs, 1); assert.equal(p.hours[1 * 24 + 9].log_signals, 40);
});

test("usage log signal: the query groups the log groups by the kinds that count for their container's image", () => {
  const kinds = [{ name: "login", regex: "log(ged)? ?in" }, { name: "auth", regex: "authenticat|authoriz" }, { name: "write_request", regex: "\"(POST|PUT|PATCH|DELETE) " }];
  const shipping = [{ group: "/swarms/20", via: "docker:relay.sphinx" }, { group: "/swarms/20-bolt", via: "docker:boltwall.sphinx" }, { group: "/var/log/syslog", via: "cloudwatch-agent" }];
  const containers = [{ name: "relay.sphinx", image: "sphinxlightning/sphinx-relay:latest" }, { name: "boltwall.sphinx", image: "sphinxlightning/sphinx-boltwall:latest" }];
  const sets = logQuerySets(shipping, containers, kinds);
  // no noise rules in the test database: one set with every kind, all three groups
  assert.equal(sets.length, 1); assert.deepEqual(sets[0].groups, ["/swarms/20", "/swarms/20-bolt", "/var/log/syslog"]); assert.deepEqual(sets[0].kinds, ["login", "auth", "write_request"]);
  assert.equal(insightsRegex("a/b"), "a\\/b");
  assert.equal(logSignalQuery(["log(ged)? ?in", "\"(POST|PUT) "]), 'filter @message like /(?i)(log(ged)? ?in|"(POST|PUT) )/ | stats count(*) as n by bin(1h)');
});

test("usage agent: a box is unsure when Jev's pick is weak or it is in two minds about the quiet windows", () => {
  const profile = { suggested_schedule: "weekdays 07-19 UTC", confidence: 0.7, quiet_hours_week: 108 };
  const review = (over: Partial<UsageReview>): UsageReview => ({ subject: "i", reviewed_at: "", verdict: "confirm", schedule: "weekdays 07-19 UTC", off_hours_week: 108, est_usd_month: null, confidence: 0.9, quiet_is_real: 0.9, busy_is_machine: 0.2, reason: "", options: {}, model: null, call_id: null, ...over });
  assert.equal(isUnsure(null, profile).unsure, true);
  assert.equal(isUnsure(null, { suggested_schedule: null, confidence: 0, quiet_hours_week: 4 }).unsure, false);
  assert.equal(isUnsure(review({}), profile).unsure, false);
  assert.match(isUnsure(review({ confidence: 0.6 }), profile).why, /at only 0\.6/);
  assert.match(isUnsure(review({ quiet_is_real: 0.5 }), profile).why, /two minds/);
  assert.equal(isUnsure(review({ verdict: "keep_running", schedule: null, confidence: 0.9, quiet_is_real: 0.1 }), profile).unsure, false);
  assert.match(isUnsure(review({ verdict: "keep_running", schedule: null, confidence: 0.6, quiet_is_real: 0.1 }), profile).why, /kept running at only 0\.6/);
});

test("usage agent: the answer is validated, a bad window or a missing one keeps the box running, and confirm/adjust follow the profile", () => {
  const ok = parseUsageResult({ verdict: "adjust", schedule: "weekdays 06-20 UTC", confidence: 0.8, reasoning: "people from 7", evidence: ["12 logins on weekdays (aws_activity_signals)", "0 at night"], busy_hours_explained: [{ when: "Thu 15:00 once", cause: "deploy", is_people: false }] }, "weekdays 07-19 UTC")!;
  assert.equal(ok.verdict, "adjust"); assert.equal(ok.schedule, "weekdays 06-20 UTC"); assert.equal(ok.evidence.length, 2); assert.equal(ok.busy_hours_explained[0].is_people, false);
  assert.equal(parseUsageResult({ verdict: "adjust", schedule: "weekdays 07-19 UTC", confidence: 0.8, reasoning: "" }, "weekdays 07-19 UTC")!.verdict, "confirm", "adjust to the same window is a confirm");
  assert.equal(parseUsageResult({ verdict: "confirm", schedule: "daily 06-22 UTC", confidence: 0.8, reasoning: "" }, "weekdays 07-19 UTC")!.verdict, "adjust", "confirm with another window is an adjust");
  const bad = parseUsageResult({ verdict: "adjust", schedule: "whenever", confidence: 2, reasoning: "x" }, null)!;
  assert.equal(bad.verdict, "keep_running"); assert.equal(bad.schedule, null); assert.equal(bad.confidence, 1); assert.match(bad.reasoning, /not understood/);
  const none = parseUsageResult({ verdict: "confirm", schedule: null, confidence: 0.9, reasoning: "x" }, "weekdays 07-19 UTC")!;
  assert.equal(none.verdict, "keep_running"); assert.match(none.reasoning, /no window given/);
  assert.equal(parseUsageResult({ verdict: "keep_running", schedule: "weekdays 07-19 UTC", confidence: 0.9, reasoning: "x" }, null)!.schedule, null);
  assert.equal(parseUsageResult("nope", null), null);
});

import { parseSchedule, wantedState, offHoursPerWeek, describeSchedule, clauseCovers } from "../actions/schedule_hours.js";
import { decidedOffHours, windowsFromSchedule } from "../usage_review.js";

test("schedules: several running clauses, or several off clauses, never both; off windows say when to be stopped", () => {
  const on = parseSchedule("weekdays 08-20 UTC | sat 10-14 UTC");
  assert.ok(!("error" in on)); if ("error" in on) return;
  assert.equal(on.clauses.length, 2); assert.equal(on.off, false);
  assert.equal(wantedState(on, new Date(Date.UTC(2026, 8, 7, 9))), "running"); // Mon 09:00
  assert.equal(wantedState(on, new Date(Date.UTC(2026, 8, 12, 11))), "running"); // Sat 11:00
  assert.equal(wantedState(on, new Date(Date.UTC(2026, 8, 12, 15))), "stopped");
  assert.equal(offHoursPerWeek(on), 168 - 60 - 4);
  assert.equal(describeSchedule(on), "weekdays 08:00-20:00 UTC | sat 10:00-14:00 UTC");
  const off = parseSchedule("off daily 01-06 UTC | off weekends 00-24 UTC");
  assert.ok(!("error" in off)); if ("error" in off) return;
  assert.equal(off.off, true);
  assert.equal(wantedState(off, new Date(Date.UTC(2026, 8, 7, 3))), "stopped"); // Mon 03:00
  assert.equal(wantedState(off, new Date(Date.UTC(2026, 8, 7, 9))), "running");
  assert.equal(wantedState(off, new Date(Date.UTC(2026, 8, 12, 12))), "stopped"); // Sat noon
  assert.equal(offHoursPerWeek(off), 5 * 5 + 48);
  assert.equal(describeSchedule(off), "off daily 01:00-06:00 UTC | off weekends 00:00-24:00 UTC");
  assert.match((parseSchedule("weekdays 08-20 UTC | off sat 10-14 UTC") as any).error, /not both/);
  assert.match((parseSchedule("weekdays 08-20 UTC | sat 10-14 Europe/Madrid") as any).error, /same time zone/);
  // an overnight off clause
  const night = parseSchedule("off weekdays 22-06 UTC"); if ("error" in night) return;
  assert.equal(clauseCovers(night.clauses[0], 2, 23), true); assert.equal(clauseCovers(night.clauses[0], 3, 5), true); assert.equal(clauseCovers(night.clauses[0], 6, 5), true, "Saturday small hours belong to Friday night"); assert.equal(clauseCovers(night.clauses[0], 1, 5), false, "Monday small hours belong to Sunday night, not a weekday");
  // the old single window still parses and reads the same
  const single = parseSchedule("weekdays 08-20 Europe/Madrid"); if ("error" in single) return;
  assert.equal(single.clauses.length, 1); assert.equal(offHoursPerWeek(single), 108); assert.equal(describeSchedule(single), "weekdays 08:00-20:00 Europe/Madrid");
});

test("usage agent: the agent's windows become an off schedule, uncertain or short ones are dropped, and a group's bounds are read", () => {
  const r = parseUsageResult({ verdict: "adjust", safe_off_windows: [{ days: "weekdays", start: 1, end: 6, certain: true, why: "quiet" }, { days: "weekends", start: 0, end: 24, certain: true, why: "off" }, { days: "daily", start: 13, end: 14, certain: true, why: "lunch" }, { days: "sat", start: 8, end: 20, certain: false, why: "maybe" }], confidence: 0.9, reasoning: "x", evidence: [], busy_hours_explained: [] }, null, { min_off_hours: 4 })!;
  assert.equal(r.verdict, "adjust"); assert.equal(r.schedule, "off weekdays 01-06 UTC | off weekends 00-24 UTC");
  assert.equal(r.windows.length, 2); assert.equal(r.dropped_windows.length, 2);
  assert.match(r.dropped_windows[0], /1 h, under the 4 h/); assert.match(r.dropped_windows[1], /not certain/);
  // the agent's own minimum: two hours is worth it for this box
  const short = parseUsageResult({ verdict: "adjust", safe_off_windows: [{ days: "daily", start: 2, end: 4, certain: true, why: "q" }], min_off_hours: 2, confidence: 0.8, reasoning: "boots in a minute", evidence: [], busy_hours_explained: [] }, null, { min_off_hours: 4 })!;
  assert.equal(short.schedule, "off daily 02-04 UTC"); assert.equal(short.min_off_hours, 2);
  // nothing certain: kept running
  const none = parseUsageResult({ verdict: "adjust", safe_off_windows: [{ days: "daily", start: 2, end: 4, certain: false, why: "q" }], confidence: 0.8, reasoning: "x", evidence: [], busy_hours_explained: [] }, null)!;
  assert.equal(none.verdict, "keep_running"); assert.equal(none.schedule, null); assert.match(none.reasoning, /no certain window/);
  // a group: downsize windows and fewer machines
  const g = parseUsageResult({ verdict: "keep_running", downsize_windows: [{ days: "daily", start: 0, end: 7, certain: true, why: "no requests" }], group_min_size: 2, group_max_size: 6, confidence: 0.85, reasoning: "4 machines at 8 % each", evidence: [], busy_hours_explained: [] }, null)!;
  assert.equal(g.verdict, "adjust", "bounds make it an adjust"); assert.equal(g.schedule, "off daily 00-07 UTC"); assert.equal(g.group_min, 2); assert.equal(g.group_max, 6);
  const w = windowsFromSchedule(g.schedule);
  assert.equal(w.length, 7); assert.equal(w[0].effective_hours, 7); assert.equal(w[0].confidence, 1);
  const all = windowsFromSchedule("off daily 00-24 UTC"); assert.equal(all[0].label, "all week");
  assert.deepEqual(decidedOffHours("off weekends 00-24 UTC").length, 48);
  assert.deepEqual(decidedOffHours("off mon 01-03 UTC"), [25, 26]);
  assert.deepEqual(decidedOffHours(null), []);
  assert.deepEqual(windowsFromSchedule("weekdays 08-20 Europe/Madrid"), [], "only UTC schedules are read as ring windows");
});

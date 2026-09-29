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

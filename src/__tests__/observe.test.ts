import { test } from "node:test";
import assert from "node:assert";
import { gradeObservation } from "../observe_grade.js";

const facts = { review_resources: ["i-0abc000000000001", "Amazon Relational Database Service"], alert_ids: [1], alert_resources: ["Amazon Relational Database Service"], review_count: 2, alert_count: 1, pools: ["prod"] };

test("observation rubric: a good note passes every check", () => {
  const g = gradeObservation({
    summary: "Spend is flat. RDS stepped up after the approved storage change. One instance has been idle for a week.",
    changes: [
      { what: "RDS up 27 USD/day", why: "Aurora I/O-Optimized storage approved on the 19th", evidence: "113 vs 86 USD/day median over 60 days (aws_baseline)", resource: "Amazon Relational Database Service", expected: true, confidence: 0.8 },
      { what: "i-0abc000000000001 idle", why: "unknown", evidence: "memory 19 % avg over 7 days, load 4 % of cores (aws_instance_history)", resource: "i-0abc000000000001", expected: false, confidence: 0.7 },
    ],
    attention: [{ item: "confirm the RDS step is the approved change", reason: "811 USD/month if it holds", resource: "Amazon Relational Database Service", urgency: "this week" }],
    proposals: [{ action: "right-size to t3.large", resource: "i-0abc000000000001", est_monthly_saving: 60, tier: "approve", rationale: "a week of idle memory and load" }],
    nothing_to_report: false,
  }, facts);
  assert.equal(g.score, 1, JSON.stringify(g.checks.filter((c) => !c.pass)));
});

test("observation rubric: missing numbers, destructive auto proposals and inconsistent flags fail their checks", () => {
  const g = gradeObservation({
    summary: "Things happened. Many things. Really many. And more.",
    changes: [{ what: "RDS up", why: "unknown", evidence: "it looks higher", expected: false, confidence: 1.5 }],
    attention: [],
    proposals: [{ action: "terminate the idle instance", tier: "auto", rationale: "idle" }],
    nothing_to_report: true,
  }, facts);
  const failed = g.checks.filter((c) => !c.pass).map((c) => c.check);
  assert.ok(failed.some((c) => c.startsWith("every change cites numbers")));
  assert.ok(failed.some((c) => c.startsWith("no destructive proposal")));
  assert.ok(failed.some((c) => c.startsWith("every proposal names")));
  assert.ok(failed.some((c) => c.startsWith("confidence")));
  assert.ok(failed.some((c) => c.startsWith("summary is three")));
  assert.ok(failed.some((c) => c.startsWith("nothing_to_report")));
  assert.ok(g.score < 0.4);
  assert.equal(gradeObservation(null, facts).score, 0);
});

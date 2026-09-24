import assert from "node:assert/strict";
import { test } from "node:test";
import { parseProgress, progressSummary, statusAfterProgress, validateProgress } from "../progress.js";
import { parseRecQuery, recMatches } from "../paging.js";

const NOW = new Date("2026-09-23T10:00:00Z");

test("progress: a valid checklist is normalised (unique, sorted) and stamped; bad shapes are named", () => {
  const ok = validateProgress({ plan: "resolution:12", total: 6, done: [3, 1, 1], follow_up: "2026-09-30" }, NOW);
  assert.ok("progress" in ok);
  assert.deepEqual(ok.progress, { plan: "resolution:12", total: 6, done: [1, 3], follow_up: "2026-09-30", outcomes: [], updated_at: "2026-09-23 10:00:00" });
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
  const started = { plan: "resolution:1", total: 3, done: [0], follow_up: null, outcomes: [], updated_at: "" };
  const nothing = { ...started, done: [] };
  assert.equal(statusAfterProgress("open", started), "pending");
  assert.equal(statusAfterProgress("snoozed", started), "pending");
  assert.equal(statusAfterProgress("open", nothing), null);
  for (const s of ["pending", "approved", "done", "rejected"]) assert.equal(statusAfterProgress(s, started), null, s);
});

test("progress: the row summary says how far and when to look again, flagged once that day has come", () => {
  const p = { plan: "resolution:1", total: 6, done: [0, 1], follow_up: "2026-09-30", outcomes: [], updated_at: "" };
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

import { outcomesText } from "../progress.js";
import { buildFeedbackSection } from "../resolve.js";
import { buildChatPrompt } from "../chat.js";

test("progress: outcomes are validated per step, one each, and the feedback text names what failed with its output", () => {
  const now = new Date("2026-09-24T10:00:00Z");
  const ok = validateProgress({ plan: "resolution:5", total: 4, done: [0, 1], outcomes: [{ step: 1, state: "failed", note: "SCHEMA_NOT_FOUND: Schema 'default' does not exist" }, { step: 0, state: "worked" }] }, now);
  assert.ok("progress" in ok);
  if ("progress" in ok) {
    assert.deepEqual(ok.progress.outcomes.map((o) => [o.step, o.state, o.at]), [[0, "worked", "2026-09-24 10:00:00"], [1, "failed", "2026-09-24 10:00:00"]]);
    const steps = [{ step: "Create the bucket" }, { step: "Run the Athena query\nwith the table" }, { step: "Wait 72 h" }, { step: "Tear down" }];
    assert.deepEqual(outcomesText(steps, ok.progress).split("\n"), [
      "1. worked: Create the bucket",
      "2. FAILED: Run the Athena query",
      "```", "SCHEMA_NOT_FOUND: Schema 'default' does not exist", "```",
    ]);
  }
  assert.deepEqual(validateProgress({ plan: "resolution:5", total: 2, done: [], outcomes: [{ step: 2, state: "failed" }] }), { error: "each outcome names a step index below total" });
  assert.deepEqual(validateProgress({ plan: "resolution:5", total: 2, done: [], outcomes: [{ step: 0, state: "meh" }] }), { error: 'an outcome state is "worked" or "failed"' });
  assert.deepEqual(validateProgress({ plan: "resolution:5", total: 2, done: [], outcomes: [{ step: 0, state: "worked" }, { step: 0, state: "failed" }] }), { error: "step 1 has two outcomes" });
  assert.equal(outcomesText([{ step: "x" }], null), "");
});

test("resolve: the re-plan feedback carries the old plan, the outcomes and the note, and asks for a plan from there", () => {
  const plan = { applies: true, summary: "Attribute the NAT bytes.", blockers: [], plan: [{ step: "Enable flow logs", command: "aws ec2 create-flow-logs", verify: "4 rows" }, { step: "Query with Athena", command: "aws athena start-query-execution", verify: "rows" }], risk: "approve" as any, est_monthly_saving: 400, needs_from_human: [], concepts_used: [] };
  const progress = { plan: "resolution:9", total: 2, done: [0], follow_up: null, outcomes: [{ step: 1, state: "failed" as const, note: "Schema 'default' does not exist", at: "" }], updated_at: "" };
  const text = buildFeedbackSection({ resolutionId: 9, plan }, progress, "we only have 24h of data");
  assert.match(text, /^## The previous plan \(resolution 9\)/);
  assert.match(text, /1\. Enable flow logs\n   command: aws ec2 create-flow-logs/);
  assert.match(text, /### Outcomes\n1\. worked: Enable flow logs\n2\. FAILED: Query with Athena\n```\nSchema 'default' does not exist\n```/);
  assert.match(text, /### Note from the person asking for the new plan\nwe only have 24h of data/);
  assert.match(text, /Write the new plan from here/);
  // outcomes ticked on another plan do not count
  assert.match(buildFeedbackSection({ resolutionId: 9, plan }, { ...progress, plan: "resolution:8" }, null), /- no step was recorded as tried/);
  assert.equal(buildFeedbackSection(null, null, null), "");
  assert.equal(buildFeedbackSection(null, null, "just do it"), "## Note from the person asking for the plan\njust do it");
});

test("chat: the brief carries the recommendation, the plan, the outcomes, the last messages and the new one", () => {
  const rec: any = { id: 317, rule: "nat_attribution", source: "agent", title: "Attribute the NAT line", resource: "nat-1", resource_name: "prod NGW", action_type: "enable_flow_logs", tier: "approve", est_monthly_saving: 400, status: "pending", decision_reason: null, rationale: "The bill is bursts." };
  const plan = { resolutionId: 9, plan: { applies: true, summary: "Find the destinations.", blockers: [], plan: [{ step: "Enable flow logs", verify: "4 rows" }, { step: "Query with Athena", command: "aws athena start-query-execution", verify: "rows" }], risk: "approve" as any, est_monthly_saving: 400, needs_from_human: ["approve 60 USD"], concepts_used: [] } };
  const progress = { plan: "resolution:9", total: 2, done: [0], follow_up: null, outcomes: [{ step: 1, state: "failed" as const, note: "SCHEMA_NOT_FOUND", at: "" }], updated_at: "" };
  const thread = [{ role: "user" as const, author: "gonzalo", content: "why did step 2 fail?", status: "completed" as const }, { role: "agent" as const, author: null, content: "No database exists.", status: "completed" as const }, { role: "agent" as const, author: null, content: "", status: "pending" as const }];
  const text = buildChatPrompt(rec, { kind: "nat" }, plan, progress, thread, "so what do I run?");
  assert.match(text, /^# Thread on recommendation #317: Attribute the NAT line/);
  assert.match(text, /## The current tailored plan \(resolution 9\)\nFind the destinations\.\n1\. Enable flow logs\n   verify: 4 rows\n2\. Query with Athena\n```\naws athena start-query-execution\n```/);
  assert.match(text, /Needs from a human:\n- approve 60 USD/);
  assert.match(text, /## What happened when the steps were tried\n1\. worked: Enable flow logs\n2\. FAILED: Query with Athena\n```\nSCHEMA_NOT_FOUND\n```/);
  assert.match(text, /\*\*gonzalo:\*\* why did step 2 fail\?\n\n\*\*advisor:\*\* No database exists\./);
  assert.ok(!text.includes("**advisor:** \n"), "a pending message is left out");
  assert.match(text, /## The new message to answer\nso what do I run\?/);
  assert.match(buildChatPrompt(rec, {}, null, null, [], "hi"), /No tailored plan has been written yet/);
  assert.match(buildChatPrompt(rec, {}, null, null, [], "hi"), /- this is the first message/);
});

import { buildAccountPrompt } from "../chat.js";

test("chat: the account-wide brief carries the observation, the open recommendations and the thread, and asks for a reply only", () => {
  const observation = "# Morning observation for 2026-09-24\n\n## Spend (Cost Explorer, net)\n- latest day with data 2026-09-23: 812 USD";
  const open = [{ id: 317, title: "Attribute the NAT line", status: "pending", est_monthly_saving: 400, resource: "nat-1" }, { id: 306, title: "Interface endpoint", status: "open", est_monthly_saving: null, resource: null }];
  const text = buildAccountPrompt(observation, open, [{ role: "user", author: "gonzalo", content: "what is the NAT costing us?", status: "completed" }], "and the workspace VPC?");
  assert.match(text, /^# Thread with the team about this AWS account\n\n## What the advisor knows today\n## Spend \(Cost Explorer, net\)\n- latest day with data 2026-09-23: 812 USD/);
  assert.match(text, /## Open recommendations \(2\)\n- #317 \[pending\] Attribute the NAT line \(≈ 400 USD\/month\) on nat-1\n- #306 \[open\] Interface endpoint\n/);
  assert.match(text, /\*\*gonzalo:\*\* what is the NAT costing us\?/);
  assert.match(text, /## The new message to answer\nand the workspace VPC\?/);
  assert.match(text, /step_fixes and suggest_replan stay empty here/);
  assert.match(buildAccountPrompt("", [], [], "hi"), /\(no observation yet: no collection run has completed\)/);
  assert.match(buildAccountPrompt("", [], [], "hi"), /## Open recommendations \(0\)\n- none/);
});

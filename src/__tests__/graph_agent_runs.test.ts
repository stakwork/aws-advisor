import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "advisor-agent-runs-test-"));
process.env.REPO2GRAPH_URL = "";

const { db } = await import("../db.js");
await import("../observe.js"); // creates the observations table
const g = await import("../graph_agent_runs.js");

test("a findings review links to its run and the recommendations it imported", () => {
  db.prepare("insert into runs(id, started_at, status, trigger) values (42, datetime('now'), 'done', 'schedule')").run();
  db.prepare("insert into agent_runs(kind, run_id, request_id, session_id, status, result, agent_name, model, link, metadata, created_at, finished_at) values ('findings', 42, 'req-findings', 's-1', 'completed', ?, 'aws-cost-advisor', 'test-model', ?, '{}', '2026-10-07 06:00:00', '2026-10-07 06:02:30')")
    .run(JSON.stringify({ content: { recommendations: [{ title: "Delete snap-0example" }] } }), JSON.stringify({ kind: "findings", runId: 42 }));
  const [n] = g.agentRunNodes(["req-findings"]);
  assert.equal(n.id, "req-findings");
  assert.deepEqual(n.about.runs, [42]);
  assert.equal(n.props.name, "Findings batch · run #42");
  assert.equal(n.props.took_s, 150);
  assert.equal(n.props.answer, "1 recommendation: Delete snap-0example");
  assert.equal(n.props.agent_name, "aws-cost-advisor");
});

test("a morning observation from before the link was stored finds its day in observations", () => {
  db.prepare("insert into agent_runs(kind, request_id, session_id, status, result, created_at) values ('observe', 'req-observe', 's-2', 'completed', ?, '2026-10-06 07:00:00')").run(JSON.stringify({ content: { summary: "Quiet day." } }));
  db.prepare("insert into observations(day, request_id, status, brief) values ('2026-10-06', 'req-observe', 'completed', 'brief')").run();
  const [n] = g.agentRunNodes(["req-observe"]);
  assert.equal(n.about.day, "2026-10-06");
  assert.equal(n.props.name, "Daily observation · 2026-10-06");
  assert.equal(n.props.answer, "Quiet day.");
});

test("chat turns in one session continue each other; a retry points at its original", () => {
  db.prepare("insert into agent_runs(kind, request_id, session_id, status, metadata, link) values ('chat', 'req-chat-1', 's-chat', 'completed', ?, ?)").run(JSON.stringify({ threadId: 3, actionId: 9 }), JSON.stringify({ kind: "chat", recommendationId: null }));
  db.prepare("insert into agent_runs(kind, request_id, session_id, status, metadata, link, retry_of) values ('chat', 'req-chat-2', 's-chat', 'pending', ?, ?, 'req-chat-1')").run(JSON.stringify({ threadId: 3 }), JSON.stringify({ kind: "chat", recommendationId: null }));
  const [first, second] = g.agentRunNodes(["req-chat-1", "req-chat-2"]);
  assert.equal(first.continues, null);
  assert.deepEqual(first.about.actions, [9]);
  assert.equal(second.continues, "req-chat-1");
  assert.equal(second.retry_of, "req-chat-1");
  assert.equal(second.props.thread_id, 3);
  assert.equal(second.props.name, "Recommendation chat · account");
});

test("a usage investigation of a group links to the pool, of a box to the resource", () => {
  const pool = g.ownerOf({ kind: "usage", link: JSON.stringify({ kind: "usage", subject: "asg:web" }) });
  assert.deepEqual(pool.pools, ["web"]);
  const box = g.ownerOf({ kind: "usage", link: JSON.stringify({ kind: "usage", subject: "i-0example" }) });
  assert.deepEqual(box.resources, ["i-0example"]);
});

test("a failed request keeps a short error", () => {
  const n = g.agentRunNode({ kind: "incident", request_id: "r", alert_id: 7, status: "failed", error: JSON.stringify({ message: "timeout" }) }, g.ownerOf({ alert_id: 7 }));
  assert.equal(n.props.error, "timeout");
  assert.equal(n.props.name, "Incident investigation · alert #7");
});

test("a usage answer shows its verdict with the reasoning, not the bare verdict", () => {
  assert.equal(g.answerExcerpt(JSON.stringify({ content: { verdict: "keep_running", reasoning: "people log in every weekday from 07:00", confidence: 0.9 } })), "keep_running: people log in every weekday from 07:00");
  assert.equal(g.answerExcerpt(JSON.stringify({ content: { verdict: "adjust" } })), "adjust");
});

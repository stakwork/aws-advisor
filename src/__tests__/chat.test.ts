import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

// chat.ts keeps threads in the database (a scratch one here) and talks to repo2graph over fetch, stubbed below:
// POST /repo/agent accepts every request and hands back its sessionId; GET /api/sessions/:id answers from `alive`.
process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "advisor-chat-test-"));
process.env.TYPESAFE_API_KEY = "";
process.env.REPO2GRAPH_URL = "http://repo2graph.test";
process.env.REPO2GRAPH_TOKEN = "secret";
process.env.AGENT_RUNS_PER_HOUR = "100";

const alive = new Set<string>();
const posts: { url: string; body: any }[] = [];
const gets: string[] = [];
let n = 0;
globalThis.fetch = (async (input: any, init?: any) => {
  const url = String(input);
  if (init?.method === "POST" && url.endsWith("/repo/agent")) {
    const body = JSON.parse(init.body);
    posts.push({ url, body });
    return new Response(JSON.stringify({ request_id: `req-${++n}`, sessionId: body.sessionId, events_token: "ev" }), { status: 200, headers: { "content-type": "application/json" } });
  }
  const m = url.match(/\/api\/sessions\/([^/?]+)$/);
  if (m) { gets.push(decodeURIComponent(m[1])); return new Response(alive.has(decodeURIComponent(m[1])) ? "{}" : '{"error":"Session not found"}', { status: alive.has(decodeURIComponent(m[1])) ? 200 : 404 }); }
  throw new Error(`unexpected fetch ${init?.method ?? "GET"} ${url}`);
}) as any;

const { db } = await import("../db.js");
// the server loads the task definitions at startup (src/index.ts), which registers the chat system prompt
(await import("../tasks.js")).loadTasks();
const { ask, askAboutRecommendation, buildAccountPrompt, buildChatPrompt, completeChat, createThread, getThread, listMessages, sessionFor, sessionStateFor } = await import("../chat.js");
type RecRow = import("../resolve.js").RecRow;

const header = { account: "123456789012", latest_run: "2026-09-25T06:00:00Z", spend_7d: 700, month_to_date: 2500, projected: 3000, open_alerts: 2, open_recs: 5, open_saving: 400 };
const rec: RecRow = { id: 7, rule: "ec2_stopped", source: "rules", title: "Terminate i-0abc", resource: "i-0abc", resource_name: "old-box", action_type: "terminate_stopped_instance", est_monthly_saving: 40, tier: "approve", confidence: 0.9, rationale: "Stopped for 60 days.", evidence: null, status: "open", decision_reason: null };
const planA = { resolutionId: 11, plan: { applies: true, summary: "Snapshot, then terminate.", blockers: [], plan: [{ step: "Snapshot the root volume", command: "aws ec2 create-snapshot --volume-id vol-1", verify: "snapshot completed" }, { step: "Terminate the instance", verify: "instance gone" }], risk: "approve" as const, est_monthly_saving: 40, needs_from_human: [], concepts_used: [] } };
const planB = { ...planA, resolutionId: 12, plan: { ...planA.plan, summary: "Terminate; the volume is already backed up." } };
const progressA = { plan: "resolution:11", total: 2, done: [0], follow_up: null, outcomes: [{ step: 0, state: "worked", note: "snap-1 done" }], updated_at: "2026-09-25T10:00:00Z" } as any;

test("the general brief is sent once: a resumed turn carries the message alone", () => {
  const first = buildAccountPrompt(header, [["bill", "the bill"]], [], "Why did NAT go up?", "NAT");
  assert.ok(first.includes("## What you can look up") && first.includes("- bill: the bill") && first.includes("this is the first message"));
  const next = buildAccountPrompt(header, [["bill", "the bill"]], [{ role: "user", author: "gonzalo", content: "Why did NAT go up?", status: "completed" }], "And last week?", "NAT", true);
  assert.ok(!next.includes("What you can look up") && !next.includes("- bill:") && !next.includes("conversation so far"));
  assert.ok(next.includes("And last week?") && next.includes("in front of you") && next.includes("step_fixes and suggest_replan stay empty"));
});

test("a resumed recommendation turn repeats the plan and the outcomes only when they changed", () => {
  const full = buildChatPrompt(rec, { kind: "ec2" }, planA, progressA, [], "Snapshot done, next?");
  assert.ok(full.includes("## Rationale") && full.includes("resolution 11") && full.includes("snap-1 done") && full.includes("this is the first message"));
  const state = sessionStateFor(planA, progressA);
  assert.equal(state.resolutionId, 11);
  assert.ok(state.outcomes.includes("snap-1 done"));

  const same = buildChatPrompt(rec, { kind: "ec2" }, planA, progressA, [], "Is step 2 safe?", state);
  assert.ok(same.startsWith("# Follow-up on recommendation #7"));
  assert.ok(!same.includes("Rationale") && !same.includes("tailored plan") && !same.includes("What happened") && !same.includes("conversation so far"));
  assert.ok(same.includes("status open") && same.includes("Is step 2 safe?") && same.includes("reply, suggest_replan, step_fixes"));

  const progressB = { ...progressA, done: [0, 1], outcomes: [...progressA.outcomes, { step: 1, state: "failed", note: "DependencyViolation" }] };
  const outcomes = buildChatPrompt(rec, { kind: "ec2" }, planA, progressB, [], "Step 2 failed", state);
  assert.ok(outcomes.includes("changed since your last answer") && outcomes.includes("DependencyViolation") && !outcomes.includes("tailored plan"));

  const replanned = buildChatPrompt(rec, { kind: "ec2" }, planB, null, [], "New plan ok?", state);
  assert.ok(replanned.includes("(resolution 12), replacing the one you saw") && replanned.includes("already backed up") && replanned.includes("nothing recorded yet"));
  assert.ok(!replanned.includes("changed since your last answer"));
});

test("a general thread keeps one repo2graph session and reopens it only when it is lost or the last turn failed", async () => {
  const t = createThread(null, "tester");
  assert.equal(t.session_id, null);
  // 1st message: no session yet, full brief
  const a1 = await ask(t.id, "Why did NAT traffic double?", "gonzalo");
  const s1 = posts.at(-1)!.body.sessionId as string;
  assert.ok(s1.startsWith(`aws-advisor-chat-${t.id}-`));
  assert.ok(posts.at(-1)!.body.prompt.includes("## What you can look up"));
  assert.equal(getThread(t.id)!.session_id, s1);
  assert.equal(getThread(t.id)!.title, "Why did NAT traffic double?");
  alive.add(s1);
  completeChat({ id: 1, kind: "chat", run_id: null, alert_id: null, recommendation_id: null, request_id: a1.agent.request_id! }, { status: "completed", result: { content: { reply: "Because of the backup job." } } });

  // 2nd message: same session, the brief is the message alone
  gets.length = 0;
  await ask(t.id, "Which instance runs it?", "gonzalo");
  assert.deepEqual(gets, [s1]);
  assert.equal(posts.at(-1)!.body.sessionId, s1);
  assert.ok(!posts.at(-1)!.body.prompt.includes("What you can look up"));
  assert.ok(posts.at(-1)!.body.prompt.includes("Which instance runs it?"));
  assert.equal(posts.at(-1)!.body.systemOverride, posts.at(-2)!.body.systemOverride);
  const a2 = listMessages(t.id).at(-1)!;
  completeChat({ id: 2, kind: "chat", run_id: null, alert_id: null, recommendation_id: null, request_id: a2.request_id! }, { status: "completed", result: { content: { reply: "i-0backup." } } });

  // 3rd message: repo2graph lost the session, so a new one opens with the full brief and the conversation so far
  alive.delete(s1);
  await ask(t.id, "Can we stop it at night?", "gonzalo");
  const s3 = posts.at(-1)!.body.sessionId as string;
  assert.notEqual(s3, s1);
  assert.ok(s3.startsWith(`aws-advisor-chat-${t.id}-`));
  const p3 = posts.at(-1)!.body.prompt as string;
  assert.ok(p3.includes("## What you can look up") && p3.includes("## The conversation so far"));
  assert.ok(p3.includes("**gonzalo:** Why did NAT traffic double?") && p3.includes("**advisor:** Because of the backup job.") && p3.includes("**advisor:** i-0backup."));
  assert.equal(getThread(t.id)!.session_id, s3);
  alive.add(s3);
  const a3 = listMessages(t.id).at(-1)!;
  completeChat({ id: 3, kind: "chat", run_id: null, alert_id: null, recommendation_id: null, request_id: a3.request_id! }, { status: "failed", error: "timeout" });

  // 4th message: the previous turn failed, so the session is not trusted even though it is alive
  gets.length = 0;
  await ask(t.id, "Still there?", "gonzalo");
  assert.deepEqual(gets, []);
  assert.notEqual(posts.at(-1)!.body.sessionId, s3);
  assert.ok(posts.at(-1)!.body.prompt.includes("## What you can look up"));
});

test("a recommendation thread carries the plan again only after a re-plan", async () => {
  db.prepare("insert into runs(status, finished_at) values ('completed', datetime('now'))").run();
  const recId = Number(db.prepare("insert into recommendations(fingerprint, run_id, rule, title, resource, action_type, est_monthly_saving, tier, confidence, rationale) values ('fp-chat', 1, 'ec2_stopped', 'Terminate i-0abc', 'i-0abc', 'terminate_stopped_instance', 40, 'approve', 0.9, 'Stopped for 60 days.')").run().lastInsertRowid);
  const r1 = Number(db.prepare("insert into resolutions(recommendation_id, status, plan) values (?, 'completed', ?)").run(recId, JSON.stringify(planA.plan)).lastInsertRowid);
  const a1 = await askAboutRecommendation(recId, "Snapshot done, next?", "gonzalo");
  const s1 = posts.at(-1)!.body.sessionId as string;
  const p1 = posts.at(-1)!.body.prompt as string;
  assert.ok(p1.includes("## Rationale") && p1.includes(`resolution ${r1}`) && p1.includes("Snapshot the root volume"));
  assert.equal(posts.at(-1)!.body.agentName, "aws-resolution-chat");
  const thread = getThread(a1.agent.thread_id)!;
  assert.equal(thread.recommendation_id, recId);
  assert.deepEqual(thread.session_state, { resolutionId: r1, outcomes: "" });
  alive.add(s1);
  completeChat({ id: 4, kind: "chat", run_id: null, alert_id: null, recommendation_id: recId, request_id: a1.agent.request_id! }, { status: "completed", result: { content: { reply: "Terminate it.", step_fixes: [], suggest_replan: false } } });

  await askAboutRecommendation(recId, "Is that reversible?", "gonzalo");
  assert.equal(posts.at(-1)!.body.sessionId, s1);
  const p2 = posts.at(-1)!.body.prompt as string;
  assert.ok(p2.startsWith("# Follow-up on recommendation") && !p2.includes("Rationale") && !p2.includes("tailored plan") && !p2.includes("What happened"));
  const a2 = listMessages(thread.id).at(-1)!;
  completeChat({ id: 5, kind: "chat", run_id: null, alert_id: null, recommendation_id: recId, request_id: a2.request_id! }, { status: "completed", result: { content: { reply: "Only with the snapshot." } } });

  const r2 = Number(db.prepare("insert into resolutions(recommendation_id, status, plan) values (?, 'completed', ?)").run(recId, JSON.stringify(planB.plan)).lastInsertRowid);
  await askAboutRecommendation(recId, "Does the new plan still snapshot?", "gonzalo");
  assert.equal(posts.at(-1)!.body.sessionId, s1);
  const p3 = posts.at(-1)!.body.prompt as string;
  assert.ok(p3.includes(`(resolution ${r2}), replacing the one you saw`) && p3.includes("already backed up") && !p3.includes("Rationale"));
  assert.equal(getThread(thread.id)!.session_state!.resolutionId, r2);
});

test("sessionFor: a thread without a session, or whose last agent turn is not completed, gets a new one", async () => {
  const base = { id: 99, recommendation_id: null, title: null, created_by: null, created_at: "", updated_at: "", session_state: null, messages: 0, last_at: null, pending: false };
  const fresh = await sessionFor({ ...base, session_id: null }, []);
  assert.equal(fresh.resumed, false);
  assert.ok(fresh.sessionId.startsWith("aws-advisor-chat-99-"));
  alive.add("s-alive");
  const msg = (role: "user" | "agent", status: "completed" | "failed") => ({ id: 1, recommendation_id: null, thread_id: 99, role, author: null, content: "x", extra: null, request_id: null, status, error: null, created_at: "", finished_at: null });
  assert.equal((await sessionFor({ ...base, session_id: "s-alive" }, [msg("user", "completed"), msg("agent", "completed")])).resumed, true);
  assert.equal((await sessionFor({ ...base, session_id: "s-alive" }, [msg("user", "completed"), msg("agent", "failed")])).resumed, false);
  assert.equal((await sessionFor({ ...base, session_id: "s-gone" }, [msg("user", "completed"), msg("agent", "completed")])).resumed, false);
});

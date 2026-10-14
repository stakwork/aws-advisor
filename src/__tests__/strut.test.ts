import assert from "node:assert/strict";
import { test } from "node:test";

process.env.STRUT_URL = "";
process.env.STRUT_API_KEY = "";
const { runAdvisorSimulation } = await import("../strut.js");

type Call = { url: string; method: string; auth?: string; body?: any };
function stub(replies: { status?: number; body: unknown }[]) {
  const calls: Call[] = []; let i = 0;
  const fetchImpl = (async (url: string, init: any) => {
    calls.push({ url, method: init.method, auth: init.headers.authorization, body: init.body ? JSON.parse(init.body) : undefined });
    const r = replies[Math.min(i++, replies.length - 1)]; const status = r.status ?? 200;
    return { ok: status < 400, status, json: async () => r.body, text: async () => (typeof r.body === "string" ? r.body : JSON.stringify(r.body)) } as any;
  }) as unknown as typeof fetch;
  return { calls, fetchImpl };
}
const base = "http://strut.test";

test("launch then poll to success returns the output", async () => {
  const s = stub([{ status: 202, body: { runId: "r1" } }, { body: { status: "success", output: { report: "http://x/r", claim_count: 3 } } }]);
  const r = await runAdvisorSimulation({ question: "q?", base, fetchImpl: s.fetchImpl, pollMs: 1 });
  assert.deepEqual(r, { status: "completed", run_id: "r1", output: { report: "http://x/r", claim_count: 3 } });
  assert.equal(s.calls[0].url, `${base}/workflows/advisor-simulate/run`);
  assert.deepEqual(s.calls[0].body, { input: { question: "q?" } });
  assert.equal(s.calls[1].url, `${base}/workflows/advisor-simulate/runs/r1`);
});

test("a partial running summary is polled again", async () => {
  const s = stub([{ status: 202, body: { runId: "r1" } }, { body: { partial: true, status: "running" } }, { body: { status: "success", output: { a: 1 } } }]);
  const r = await runAdvisorSimulation({ question: "q", base, fetchImpl: s.fetchImpl, pollMs: 1 });
  assert.equal(r.status, "completed"); assert.equal(s.calls.length, 3);
});

test("error, cancelled and stale runs throw with the message", async () => {
  for (const [body, re] of [[{ status: "error", error: { message: "Input validation failed: x" } }, /Input validation failed: x/], [{ status: "cancelled" }, /cancelled/], [{ status: "stale", lastError: "boom" }, /stale.*boom/]] as const) {
    const s = stub([{ status: 202, body: { runId: "r1" } }, { body }]);
    await assert.rejects(runAdvisorSimulation({ question: "q", base, fetchImpl: s.fetchImpl, pollMs: 1 }), re);
  }
});

test("404 and non-OK bodies are bounded", async () => {
  const s = stub([{ status: 404, body: "x".repeat(1000) }]);
  await assert.rejects(runAdvisorSimulation({ question: "q", base, fetchImpl: s.fetchImpl }), (e: Error) => /HTTP 404 x+/.test(e.message) && /published/.test(e.message) && e.message.length < 450);
  const s2 = stub([{ status: 500, body: "y".repeat(1000) }]);
  await assert.rejects(runAdvisorSimulation({ question: "q", base, fetchImpl: s2.fetchImpl }), (e: Error) => /HTTP 500/.test(e.message) && e.message.length < 400);
});

test("not configured", async () => {
  await assert.rejects(runAdvisorSimulation({ question: "q" }), /STRUT_URL is not configured/);
});

test("hitting the wait bound returns running with the run id", async () => {
  const s = stub([{ status: 202, body: { runId: "r9" } }, { body: { status: "running", partial: true } }]);
  const r = await runAdvisorSimulation({ question: "q", base, fetchImpl: s.fetchImpl, pollMs: 5, timeoutMs: 20 });
  assert.deepEqual(r, { status: "running", run_id: "r9" });
});

test("run_id skips the launch and is validated", async () => {
  const s = stub([{ body: { status: "success", output: {} } }]);
  await runAdvisorSimulation({ runId: "abc-1.2_3", base, fetchImpl: s.fetchImpl, pollMs: 1 });
  assert.equal(s.calls.length, 1); assert.equal(s.calls[0].method, "GET");
  await assert.rejects(runAdvisorSimulation({ runId: "../x", base, fetchImpl: s.fetchImpl }), /run_id/);
});

test("the bearer header is sent only when a key is set", async () => {
  const mk = () => stub([{ status: 202, body: { runId: "r1" } }, { body: { status: "success", output: {} } }]);
  const a = mk(); await runAdvisorSimulation({ question: "q", base, fetchImpl: a.fetchImpl, pollMs: 1, apiKey: "k123" });
  assert.ok(a.calls.every((c) => c.auth === "Bearer k123"));
  const b = mk(); await runAdvisorSimulation({ question: "q", base, fetchImpl: b.fetchImpl, pollMs: 1, apiKey: "" });
  assert.ok(b.calls.every((c) => c.auth === undefined));
});

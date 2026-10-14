import { config } from "./config.js";

/** Client for the Strut workflow runner: launches `advisor-simulate` and polls the run until it settles. */
const WORKFLOW = "advisor-simulate";
export const STRUT_POLL_MS = 5_000;
export const STRUT_TIMEOUT_MS = 10 * 60_000;
const REQUEST_TIMEOUT_MS = 30_000;
export const RUN_ID_RE = /^[A-Za-z0-9._-]{1,128}$/;

export interface SimulationOptions { question?: string; runId?: string; fetchImpl?: typeof fetch; pollMs?: number; timeoutMs?: number; base?: string; apiKey?: string }
export type SimulationResult =
  | { status: "completed"; run_id: string; output: Record<string, unknown> }
  | { status: "running"; run_id: string };

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export async function runAdvisorSimulation(o: SimulationOptions): Promise<SimulationResult> {
  const base = (o.base ?? config.strutUrl).replace(/\/$/, "");
  if (!base) throw new Error("STRUT_URL is not configured");
  const key = o.apiKey ?? config.strutApiKey;
  const f = o.fetchImpl ?? fetch;
  const pollMs = o.pollMs ?? STRUT_POLL_MS, timeoutMs = o.timeoutMs ?? STRUT_TIMEOUT_MS;
  const call = async (method: "GET" | "POST", path: string, body?: unknown): Promise<any> => {
    const headers: Record<string, string> = { "user-agent": "cloud-advisor" };
    if (key) headers.authorization = `Bearer ${key}`;
    if (body !== undefined) headers["content-type"] = "application/json";
    const res = await f(`${base}${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
    if (!res.ok) {
      const b = (await res.text()).slice(0, 300);
      throw new Error(`Strut ${path}: HTTP ${res.status}${b ? ` ${b}` : ""}${res.status === 404 && method === "POST" ? " (is the advisor-simulate workflow published?)" : ""}`);
    }
    return res.json();
  };

  let runId = o.runId;
  if (runId) { if (!RUN_ID_RE.test(runId)) throw new Error("run_id must be 1-128 characters of A-Z a-z 0-9 . _ -"); }
  else {
    if (!o.question) throw new Error("question is required");
    const launched = await call("POST", `/workflows/${WORKFLOW}/run`, { input: { question: o.question } });
    runId = String(launched?.runId ?? "");
    if (!RUN_ID_RE.test(runId)) throw new Error("Strut did not return a run id");
  }

  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const r = await call("GET", `/workflows/${WORKFLOW}/runs/${encodeURIComponent(runId)}`);
    const status = String(r?.status ?? "");
    if (status === "success") return { status: "completed", run_id: runId, output: (r.output && typeof r.output === "object" ? r.output : {}) as Record<string, unknown> };
    if (status === "error" || status === "cancelled") throw new Error(`Strut run ${runId} ${status}: ${String(r?.error?.message ?? "no message").slice(0, 300)}`);
    if (status === "stale") throw new Error(`Strut run ${runId} died (stale)${r?.lastError ? `: ${String(r.lastError).slice(0, 300)}` : ""}`);
    if (Date.now() + pollMs >= deadline) return { status: "running", run_id: runId };
    await sleep(pollMs);
  }
}

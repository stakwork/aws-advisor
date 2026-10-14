/** The what-if simulation (src/strut.ts): one MCP tool that runs the Strut workflow advisor-simulate, registered from src/mcp.ts. */
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { RUN_ID_RE, runAdvisorSimulation } from "./strut.js";

const text = (v: unknown) => ({ content: [{ type: "text" as const, text: typeof v === "string" ? v : JSON.stringify(v, null, 1) }] });
const fail = (msg: string) => ({ content: [{ type: "text" as const, text: msg }], isError: true });

export function registerStrutTools(server: McpServer): void {
  server.registerTool("advisor_simulate", {
    title: "How would this change impact us (what-if simulation)",
    description: "Use when the user asks how a change (moving a database to Azure, bridging Vercel and AWS, ...) would impact the cost, feasibility or security of OUR infrastructure. Runs the Strut workflow advisor-simulate with the user's question; it takes minutes. It researches vendor pages and records claims in the Strut knowledge graph (namespace advisor-sim); it changes no infrastructure. The result's `report` is the link to show the user. `comparison` holds cost_today_usd, cost_after_usd, saving_usd, saving_pct and break_even, with `computed` and `problems`: when computed is false (usage not measured) the totals may be null and break_even (a break-even volume) is what to report. Values flagged in `estimated_quantities` are estimates, say so. `open_external_checks` are questions for the team to settle. If the wait limit is hit the result is {status:\"running\", run_id}: call again with that run_id (and no question) to keep waiting.",
    inputSchema: {
      question: z.string().min(1).max(2000).optional().describe("the what-if question, e.g. \"would it be cheaper to host our databases in Azure?\"; omit when giving run_id"),
      run_id: z.string().regex(RUN_ID_RE).optional().describe("a run_id from an earlier call that returned status running: keeps waiting for that run instead of launching a new one"),
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  }, async (a) => {
    if (Boolean(a.question) === Boolean(a.run_id)) return fail("give exactly one of question (to start a simulation) or run_id (to keep waiting for one)");
    try {
      const r = await runAdvisorSimulation({ question: a.question, runId: a.run_id });
      return text(r.status === "completed" ? { ...r.output, run_id: r.run_id, status: "completed" } : r);
    } catch (e: any) { return fail(e?.message || String(e)); }
  });
}

/** The chat's view of cost per swarm (src/swarm_costs.ts): one read-only MCP tool, registered from src/mcp.ts. */
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { listSwarmCostHistory, swarmCostReport } from "./swarm_costs.js";

const text = (v: unknown) => ({ content: [{ type: "text" as const, text: typeof v === "string" ? v : JSON.stringify(v, null, 1) }] });
const fail = (msg: string) => ({ content: [{ type: "text" as const, text: msg }], isError: true });

export function registerSwarmTools(server: McpServer): void {
  server.registerTool("swarm_costs", {
    title: "What each swarm (customer) costs",
    description: "Cost per swarm at list price for a month (default: this month): per box the instance hours while running, its volumes, its public IPv4 and its standard snapshots, the month-to-date figure, last use, idle days, whether the executor parked it, and a nudge flag for running boxes nobody has used for the parking threshold that are not being parked. Give an instance id to get that swarm's daily series instead.",
    inputSchema: { month: z.string().regex(/^\d{4}-\d{2}$/).optional().describe("YYYY-MM"), instance: z.string().regex(/^i-[0-9a-f]{8,17}$/).optional().describe("one swarm's instance id: returns its daily series") },
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
  }, async (a) => {
    try {
      if (a.instance) return text({ instance_id: a.instance, days: listSwarmCostHistory(a.instance) });
      const r = await swarmCostReport(a.month);
      if (!r.swarms.length) return fail(`no swarm cost rows for ${r.month} (swarms are EC2 instances named like "swarm"; the daily refresh writes the rows)`);
      return text(r);
    } catch (e: any) { return fail(e?.message || String(e)); }
  });
}

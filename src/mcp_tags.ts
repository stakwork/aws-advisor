/** The chat's view of tag hygiene: one read-only tool on the fact server (src/mcp.ts calls registerTagTools). */
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { tagHygieneReport } from "./tag_hygiene.js";

const text = (v: unknown) => ({ content: [{ type: "text" as const, text: typeof v === "string" ? v : JSON.stringify(v, null, 1) }] });
const fail = (msg: string) => ({ content: [{ type: "text" as const, text: msg }], isError: true });
const ROWS = 50;

export function registerTagTools(server: McpServer): void {
  server.registerTool("tag_hygiene", {
    title: "Resources missing the required tags, and the opt-in candidates",
    description: "The advisor's tag hygiene report: per resource kind how many lack the required tags (owner and env by default, aliases such as Environment or team count), the first 50 resources with the suggested values and the CLI to tag them, and the EC2 instances that could opt into parking (advisor:park=auto: swarm-named, untagged) or office hours (advisor:schedule: dev/staging/test boxes, untagged). Refreshed daily with the logs job and from Inventory › Tags. Read-only: the advisor never writes a tag.",
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  }, async () => {
    try {
      const r = tagHygieneReport();
      if (!r.checked_at) return fail("no tag hygiene report yet: press Refresh on Inventory › Tags (or wait for the daily logs job)");
      return text({ required: r.required, checked_at: r.checked_at, total_missing: r.total_missing, kinds: r.kinds, opt_in: r.opt_in, rows: r.rows.slice(0, ROWS).map((x) => ({ resource: x.resource, name: x.name, region: x.region, missing: x.missing, suggested: x.suggested, cli: x.cli })), note: r.total_missing > ROWS ? `${r.total_missing - ROWS} more on Inventory › Tags` : undefined });
    } catch (e: any) { return fail(e?.message || String(e)); }
  });
}

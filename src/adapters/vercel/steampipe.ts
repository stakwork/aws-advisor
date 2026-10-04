import fs from "node:fs";
import path from "node:path";
import { config } from "../../config.js";
import { vercelTeam } from "./inventory.js";

/**
 * The Steampipe side of the Vercel adapter: the `vercel` connection (plugin turbot/vercel) written from the saved
 * token, so the agent's steampipe_query tool and ad-hoc SQL can read `vercel.vercel_project`, `vercel_deployment`,
 * `vercel_domain`, `vercel_dns_record`, `vercel_team` next to the AWS tables. The advisor owns the whole file
 * (`<steampipe config dir>/vercel.spc`): it is rewritten on every save and removed with the account. Collection
 * itself goes through the REST client (src/adapters/vercel/client.ts), which reads what the plugin does not expose
 * (deployment protection, env variable names, the firewall).
 */

export const MARKER = "# managed by cloud-advisor: rewritten from Settings › Accounts › Vercel; edits are lost";
export const vercelSpcPath = (): string => path.join(config.steampipeConfigDir, "vercel.spc");

/** The file's text for a token and an optional team (the slug the plugin targets; the id works too). */
export function vercelSpcText(token: string, team: string | null): string {
  const esc = (s: string) => s.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
  return [MARKER, 'connection "vercel" {', '  plugin    = "vercel"', `  api_token = "${esc(token)}"`, ...(team ? [`  team      = "${esc(team)}"`] : []), "}", ""].join("\n");
}

/** Writes the connection from the saved settings (0600); removes it when no token is saved. Returns what it did. */
export function ensureVercelConnection(): "written" | "removed" | "unchanged" | "skipped" {
  const file = vercelSpcPath();
  const token = config.vercelToken;
  if (!token) {
    try { if (fs.existsSync(file) && fs.readFileSync(file, "utf8").startsWith(MARKER)) { fs.unlinkSync(file); return "removed"; } } catch { /* not ours or not there */ }
    return "skipped";
  }
  const team = vercelTeam()?.slug || config.vercelTeamId || null;
  const text = vercelSpcText(token, team);
  try {
    if (fs.existsSync(file) && fs.readFileSync(file, "utf8") === text) return "unchanged";
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, text, { mode: 0o600 });
    try { fs.chmodSync(file, 0o600); } catch { /* best effort */ }
    return "written";
  } catch (e: any) { console.error(`[vercel] steampipe connection not written: ${e?.message || e}`); return "skipped"; }
}

import fs from "node:fs";
import path from "node:path";
import { config } from "../../config.js";
import { normalisePem } from "./client.js";

/**
 * The Steampipe side of the GitHub adapter: the `github` connection (plugin turbot/github) written from the saved
 * GitHub App, so the collection (./sql.ts), the agent's steampipe_query tool and ad-hoc SQL read the org through
 * Steampipe. The plugin takes the App's private key as a file path, so the key is written next to the connection
 * (0600). The advisor owns both files: rewritten on every save, removed with the account.
 */

export const CONNECTION = "github";
export const MARKER = "# managed by cloud-advisor: rewritten from Settings › Accounts › GitHub; edits are lost";
export const githubSpcPath = (): string => path.join(config.steampipeConfigDir, "github.spc");
export const githubPemPath = (): string => path.join(config.steampipeConfigDir, "github_app.pem");

/** The connection file's text for an App (its id, installation and the key file's path). Pure. */
export function githubSpcText(appId: string, installationId: string, pemPath: string): string {
  const esc = (s: string) => s.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
  return [MARKER, `connection "${CONNECTION}" {`, '  plugin              = "github"', `  app_id              = "${esc(appId)}"`, `  app_installation_id = "${esc(installationId)}"`, `  app_private_key     = "${esc(pemPath)}"`, "}", ""].join("\n");
}

const write600 = (file: string, text: string) => { fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, text, { mode: 0o600 }); try { fs.chmodSync(file, 0o600); } catch { /* best effort */ } };
const ours = (file: string) => { try { return fs.existsSync(file) && fs.readFileSync(file, "utf8").startsWith(MARKER); } catch { return false; } };
/** The sample `steampipe plugin install github` leaves: a connection that sets no credential (every argument commented out). Safe to replace. Pure. */
export const isPluginSample = (text: string): boolean => !text.split("\n").filter((l) => !/^\s*(#|\/\/)/.test(l)).some((l) => /^\s*(token|app_id|app_installation_id|app_private_key|base_url)\s*=/.test(l));

/** Writes the connection and the key from the saved settings; removes both when no App is saved. Returns what it did. */
export function ensureGitHubConnection(): "written" | "removed" | "unchanged" | "skipped" {
  const spc = githubSpcPath(); const pem = githubPemPath();
  if (!(config.githubAppId && config.githubInstallationId && config.githubAppPrivateKey)) {
    if (!ours(spc)) return "skipped";
    try { fs.unlinkSync(spc); if (fs.existsSync(pem)) fs.unlinkSync(pem); return "removed"; } catch { return "skipped"; }
  }
  // a github.spc someone wrote by hand is theirs: never overwritten
  if (fs.existsSync(spc) && !ours(spc) && !isPluginSample(fs.readFileSync(spc, "utf8"))) { console.error(`[github] ${spc} exists and is not managed by the advisor: left as it is; the collection reads its "${CONNECTION}" connection`); return "skipped"; }
  const key = normalisePem(config.githubAppPrivateKey); const text = githubSpcText(config.githubAppId, config.githubInstallationId, pem);
  try {
    const same = fs.existsSync(spc) && fs.readFileSync(spc, "utf8") === text && fs.existsSync(pem) && fs.readFileSync(pem, "utf8") === key;
    if (same) return "unchanged";
    write600(pem, key); write600(spc, text);
    return "written";
  } catch (e: any) { console.error(`[github] steampipe connection not written: ${e?.message || e}`); return "skipped"; }
}

/** Waits (up to `ms`) for the Steampipe service to load the connection after the file changed; true once its tables answer. */
export async function waitForConnection(q: (sql: string, p?: unknown[]) => Promise<any[]>, ms = 45_000): Promise<boolean> {
  const until = Date.now() + ms;
  while (Date.now() < until) {
    try { const r = await q("select 1 from information_schema.tables where table_schema = $1 and table_name = 'github_organization'", [CONNECTION]); if (r.length) return true; } catch { /* not loaded yet */ }
    await new Promise((r) => setTimeout(r, 1_500));
  }
  return false;
}

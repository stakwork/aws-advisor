import type { Actor } from "../../sign_ins.js";
import { parseUserAgent, type ClientInfo, type ClientUse, type IpUse } from "../../sign_in_facts.js";
import { auditActivity, githubOrgRow, listCredentials, listMembers } from "./inventory.js";
import { collaboratorId, memberId } from "./index.js";

/**
 * The org's people as actors for "Who can get in" (src/sign_ins.ts listActors): a member or outside collaborator,
 * with the org role, 2FA as the org reports it, the credentials they hold on the org (public SSH keys, fine-grained
 * tokens, SSO-authorized classic tokens and keys) and the clients the audit log saw them use. The public name is the
 * display name and the public e-mail's local part the e-mail key, so groupPeople joins them to the AWS and Vercel
 * identities of the same person (the Vercel member carries the GitHub login as its display name).
 */

/** A GitHub audit log user agent as a client: git and the GitHub CLI by name, browsers as the web, the rest as parseUserAgent reads it. Pure. */
export function githubClientOf(ua: string | null | undefined): ClientInfo {
  const s = String(ua ?? "").trim();
  if (/^git\//i.test(s)) return { client: "git", platform: /Apple Git/.test(s) ? "macOS" : /windows/i.test(s) ? "Windows" : null, channel: "cli" };
  if (/^(GitHub CLI|gh\/)/i.test(s)) return { client: "GitHub CLI", platform: null, channel: "cli" };
  if (/GitHubDesktop/i.test(s)) return { client: "GitHub Desktop", platform: /Macintosh/.test(s) ? "macOS" : /Windows/.test(s) ? "Windows" : null, channel: "cli" };
  if (/^(Octokit|octokit)/.test(s)) return { client: "Octokit", platform: null, channel: "sdk" };
  if (/^Terraform\//i.test(s)) return { client: "Terraform", platform: null, channel: "iac" };
  return parseUserAgent(s);
}

export function githubActors(scopeId?: string | null): Actor[] {
  const org = githubOrgRow(); if (!org) return [];
  if (scopeId && scopeId !== org.node_id) return [];
  const orgId = org.node_id; const activity = auditActivity(orgId); const creds = listCredentials(orgId);
  return listMembers(orgId).map((m) => {
    const a = activity.get(m.login);
    const clients: ClientUse[] = [];
    for (const u of a?.user_agents ?? []) {
      const c = githubClientOf(u.ua); const cur = clients.find((x) => x.client === c.client && x.platform === c.platform && x.channel === c.channel);
      if (cur) { cur.events += u.events; if (u.last_at > cur.last_at) cur.last_at = u.last_at; } else clients.push({ account_id: orgId, channel: c.channel, client: c.client, platform: c.platform, factors: [], events: u.events, failures: 0, first_at: a!.first_at, last_at: u.last_at, last_ip: null, keys: [], via: ["api"] });
    }
    const held = creds.filter((c) => c.holder?.toLowerCase() === m.login.toLowerCase() && c.kind !== "deploy_key" && c.kind !== "pat_request");
    return {
      kind: m.kind === "member" ? "github_member" as const : "github_collaborator" as const, id: m.kind === "member" ? memberId(orgId, m.login) : collaboratorId(orgId, m.login), name: m.login, email: m.saml_key ?? m.email_key, display_name: m.name, account_id: orgId,
      admin: m.role === "admin", console: true, keys: held.length, mfa: m.mfa === true ? "mfa" as const : m.mfa === false ? "none" as const : "unknown" as const, mfa_source: m.mfa == null ? null : "account" as const,
      last_seen_at: a?.last_at ?? null, clients: clients.sort((x, y) => y.last_at.localeCompare(x.last_at)), sign_ins_90d: null, mfa_sign_ins_90d: null, status: "active" as const, changes: [], role: m.kind === "member" ? (m.role === "admin" ? "owner" : "member") : "outside collaborator",
    };
  });
}

/** Each actor's source addresses from the audit log (only when the org discloses IPs), keyed by the actor's node id. */
export function githubIps(): Map<string, IpUse[]> {
  const org = githubOrgRow(); const out = new Map<string, IpUse[]>(); if (!org) return out;
  const activity = auditActivity(org.node_id);
  for (const m of listMembers(org.node_id)) { const a = activity.get(m.login); if (!a?.ips.length) continue; out.set(m.kind === "member" ? memberId(org.node_id, m.login) : collaboratorId(org.node_id, m.login), a.ips.map((i) => ({ ip: i.ip, events: i.events, failures: 0, first_at: a.first_at, last_at: i.last_at, clients: [], accounts: [org.node_id] }))); }
  return out;
}

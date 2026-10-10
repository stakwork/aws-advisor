import { db } from "../../db.js";
import type { RecInput } from "../../rules.js";
import { config } from "../../config.js";
import { AWS_KEY_NAME } from "../../vercel_aws_links.js";
import { auditActivity, githubExtras, githubOrgRow, listApps, listCopilotSeats, listCredentials, listMembers, listRepoAccess, listSecrets } from "./inventory.js";
import { appId, collaboratorId, memberId, repoNodeId } from "./index.js";

/**
 * Deterministic findings for a GitHub org, the way the Vercel rules work: each check is a control
 * (`github.control.<name>`), each finding names a resource (the org, a person, a repository, a credential, an App),
 * and the actionable ones become recommendations (fingerprint rule:resource, so a decision survives the next pass).
 * One pass per collection; nothing is automated (the executor has no GitHub actuator). Activity comes from the audit
 * log (90 days kept), so "inactive" means no audit event in the window the log covers.
 */

export type Severity = "alarm" | "warning" | "info";
export interface GitHubFinding { control_id: string; control_title: string; severity: Severity; category: "security" | "cost" | "operations"; resource: string; resource_name: string; reason: string; dimensions: Record<string, unknown> }

/** The documentation each control's playbook is generated from (src/playbook_gen.ts); nothing is hand-written. */
export const CONTROL_REFERENCES: Record<string, string[]> = {
  "github.control.two_factor_not_required": ["https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-two-factor-authentication-for-your-organization/requiring-two-factor-authentication-in-your-organization"],
  "github.control.member_no_2fa": ["https://docs.github.com/en/authentication/securing-your-account-with-two-factor-authentication-2fa/configuring-two-factor-authentication", "https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-two-factor-authentication-for-your-organization/viewing-whether-users-in-your-organization-have-2fa-enabled"],
  "github.control.outside_collaborator_admin": ["https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-outside-collaborators/adding-outside-collaborators-to-repositories-in-your-organization", "https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-repository-roles/repository-roles-for-an-organization"],
  "github.control.base_permission_write": ["https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-repository-roles/setting-base-permissions-for-an-organization"],
  "github.control.too_many_owners": ["https://docs.github.com/en/organizations/managing-peoples-access-to-your-organization-with-roles/roles-in-an-organization", "https://docs.github.com/en/organizations/managing-peoples-access-to-your-organization-with-roles/maintaining-ownership-continuity-for-your-organization"],
  "github.control.single_owner": ["https://docs.github.com/en/organizations/managing-peoples-access-to-your-organization-with-roles/maintaining-ownership-continuity-for-your-organization"],
  "github.control.deploy_key_write": ["https://docs.github.com/en/authentication/connecting-to-github-with-ssh/managing-deploy-keys", "https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication"],
  "github.control.deploy_key_unused": ["https://docs.github.com/en/authentication/connecting-to-github-with-ssh/managing-deploy-keys", "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/reviewing-your-deploy-keys"],
  "github.control.pat_no_expiry": ["https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/setting-a-personal-access-token-policy-for-your-organization", "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens"],
  "github.control.pat_unused": ["https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/reviewing-and-revoking-personal-access-tokens-in-your-organization"],
  "github.control.credential_authorization_unused": ["https://docs.github.com/en/organizations/granting-access-to-your-organization-with-saml-single-sign-on/viewing-and-managing-a-members-saml-access-to-your-organization", "https://docs.github.com/en/rest/orgs/orgs#list-saml-sso-authorizations-for-an-organization"],
  "github.control.app_all_repos_write": ["https://docs.github.com/en/apps/using-github-apps/reviewing-and-modifying-installed-github-apps", "https://docs.github.com/en/apps/using-github-apps/installing-a-github-app-from-a-third-party"],
  "github.control.copilot_seat_unused": ["https://docs.github.com/en/copilot/managing-copilot/managing-github-copilot-in-your-organization/reviewing-activity-related-to-github-copilot-in-your-organization/reviewing-user-activity-data-for-copilot-in-your-organization", "https://docs.github.com/en/copilot/managing-copilot/managing-github-copilot-in-your-organization/managing-access-to-github-copilot-in-your-organization/revoking-access-to-copilot-for-members-of-your-organization"],
  "github.control.seats_unused": ["https://docs.github.com/en/billing/managing-the-plan-for-your-github-account/downgrading-your-accounts-plan", "https://docs.github.com/en/billing/managing-your-billing/about-per-user-pricing"],
  "github.control.outside_collaborator_seat": ["https://docs.github.com/en/billing/managing-your-billing/about-per-user-pricing", "https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-outside-collaborators/removing-an-outside-collaborator-from-an-organization-repository"],
  "github.control.member_inactive": ["https://docs.github.com/en/organizations/managing-membership-in-your-organization/removing-a-member-from-your-organization", "https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization"],
  "github.control.invitation_stale": ["https://docs.github.com/en/organizations/managing-membership-in-your-organization/canceling-or-editing-an-invitation-to-join-your-organization"],
  "github.control.static_aws_keys": ["https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services", "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html"],
  "github.control.webhook_insecure_ssl": ["https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks", "https://docs.github.com/en/rest/orgs/webhooks"],
};

export const CONTROLS: Record<string, { title: string; category: GitHubFinding["category"]; severity: Severity }> = {
  "github.control.two_factor_not_required": { title: "Organization does not require two-factor authentication", category: "security", severity: "warning" },
  "github.control.member_no_2fa": { title: "Person without two-factor authentication", category: "security", severity: "alarm" },
  "github.control.outside_collaborator_admin": { title: "Outside collaborator with admin on a repository", category: "security", severity: "warning" },
  "github.control.base_permission_write": { title: "Every member can write to every repository", category: "security", severity: "warning" },
  "github.control.too_many_owners": { title: "More owners than the org needs", category: "security", severity: "info" },
  "github.control.single_owner": { title: "Only one owner", category: "operations", severity: "warning" },
  "github.control.deploy_key_write": { title: "Deploy key with write access", category: "security", severity: "info" },
  "github.control.deploy_key_unused": { title: "Deploy key not used in 90 days", category: "security", severity: "warning" },
  "github.control.pat_no_expiry": { title: "Fine-grained token without expiry", category: "security", severity: "warning" },
  "github.control.pat_unused": { title: "Fine-grained token not used in 90 days", category: "security", severity: "warning" },
  "github.control.credential_authorization_unused": { title: "SSO-authorized credential not used in 90 days", category: "security", severity: "warning" },
  "github.control.app_all_repos_write": { title: "App with write access to every repository", category: "security", severity: "info" },
  "github.control.copilot_seat_unused": { title: "Copilot seat with no activity in 30 days", category: "cost", severity: "warning" },
  "github.control.seats_unused": { title: "Paid seats nobody fills", category: "cost", severity: "warning" },
  "github.control.outside_collaborator_seat": { title: "Outside collaborator holding a paid seat, inactive", category: "cost", severity: "warning" },
  "github.control.member_inactive": { title: "Member with no activity in the audit log", category: "security", severity: "warning" },
  "github.control.invitation_stale": { title: "Invitation pending for over a week", category: "operations", severity: "info" },
  "github.control.static_aws_keys": { title: "AWS access key stored as a GitHub secret", category: "security", severity: "warning" },
  "github.control.webhook_insecure_ssl": { title: "Webhook skips TLS verification", category: "security", severity: "warning" },
};

const DAY = 86_400_000;
const daysSince = (iso: string | null | undefined, now: number) => (iso ? Math.floor((now - Date.parse(iso)) / DAY) : null);

/** Every finding of the org as the tables hold it now. Pure over the database. */
export function githubFindings(now = Date.now()): GitHubFinding[] {
  const org = githubOrgRow(); if (!org) return [];
  const orgId = org.node_id; const out: GitHubFinding[] = [];
  const add = (control: string, resource: string, resource_name: string, reason: string, dimensions: Record<string, unknown> = {}, severity?: Severity) => { const c = CONTROLS[control]; out.push({ control_id: control, control_title: c.title, severity: severity ?? c.severity, category: c.category, resource, resource_name, reason, dimensions }); };
  const extras = githubExtras(orgId); const activity = auditActivity(orgId);
  const auditOk = Boolean(extras.sections.audit_log?.ok) && extras.audit_since != null;
  const window = auditOk ? Math.max(0, Math.floor((now - Date.parse(extras.audit_since!)) / DAY)) : 0;
  const people = listMembers(orgId); const owners = people.filter((m) => m.kind === "member" && m.role === "admin");
  const idOf = (m: { kind: string; login: string }) => (m.kind === "member" ? memberId(orgId, m.login) : collaboratorId(orgId, m.login));

  if (org.two_factor_required === false) add("github.control.two_factor_not_required", orgId, org.login, `${org.login} lets members and outside collaborators in without two-factor authentication`);
  for (const m of people) if (m.mfa === false) add("github.control.member_no_2fa", idOf(m), m.login, `${m.login} (${m.kind === "member" ? (m.role === "admin" ? "owner" : "member") : "outside collaborator"}) has no two-factor authentication`, { kind: m.kind, owner: m.role === "admin" }, m.role === "admin" ? "alarm" : undefined);
  if (org.default_permission === "write" || org.default_permission === "admin") add("github.control.base_permission_write", orgId, org.login, `the base permission is ${org.default_permission}: every member can ${org.default_permission === "admin" ? "administer" : "push to"} every repository`, { base_permission: org.default_permission });
  if (owners.length === 1) add("github.control.single_owner", orgId, org.login, `${owners[0].login} is the only owner`, { owners: owners.map((o) => o.login) });
  const members = people.filter((m) => m.kind === "member");
  if (owners.length > 3 && owners.length > members.length / 3) add("github.control.too_many_owners", orgId, org.login, `${owners.length} of ${members.length} members are owners`, { owners: owners.map((o) => o.login) });

  // repository access: an outside collaborator with admin on a repository
  const outside = new Set(people.filter((m) => m.kind === "collaborator").map((m) => m.login));
  for (const a of listRepoAccess(orgId)) if (outside.has(a.login) && a.permission === "admin") add("github.control.outside_collaborator_admin", collaboratorId(orgId, a.login), a.login, `${a.login}, an outside collaborator, is admin on ${a.repo}`, { repo: a.repo });

  // credentials
  for (const c of listCredentials(orgId)) {
    const idle = daysSince(c.last_used_at ?? c.created_at, now);
    if (c.kind === "deploy_key") {
      if (!c.details.read_only) add("github.control.deploy_key_write", `github_credential:${c.id}`, `${c.holder}: ${c.name ?? "deploy key"}`, `deploy key "${c.name ?? c.fingerprint}" can push to ${c.holder}`, { repo: c.holder, fingerprint: c.fingerprint, added_by: c.details.added_by ?? null });
      if (idle != null && idle >= 90) add("github.control.deploy_key_unused", `github_credential:${c.id}`, `${c.holder}: ${c.name ?? "deploy key"}`, `deploy key "${c.name ?? c.fingerprint}" on ${c.holder} ${c.last_used_at ? `last used ${idle} days ago` : `never used since it was added ${idle} days ago`}`, { repo: c.holder, last_used_at: c.last_used_at, read_only: c.details.read_only });
    }
    if (c.kind === "pat") {
      if (!c.expires_at) add("github.control.pat_no_expiry", `github_credential:${c.id}`, `${c.holder}: ${c.name ?? "token"}`, `${c.holder}'s fine-grained token "${c.name}" never expires (${c.details.repository_selection === "all" ? "all repositories" : `${(c.details.repos ?? []).length} repositories`})`, { owner: c.holder });
      if (idle != null && idle >= 90) add("github.control.pat_unused", `github_credential:${c.id}`, `${c.holder}: ${c.name ?? "token"}`, `${c.holder}'s fine-grained token "${c.name}" ${c.last_used_at ? `last used ${idle} days ago` : `never used since it was granted ${idle} days ago`}`, { owner: c.holder, last_used_at: c.last_used_at });
    }
    if (c.kind === "credential_authorization" && idle != null && idle >= 90) add("github.control.credential_authorization_unused", `github_credential:${c.id}`, `${c.holder}: ${c.name ?? c.details.type}`, `${c.holder}'s ${c.details.type} "${c.name}" is authorized for the org's SSO and ${c.last_used_at ? `was last used ${idle} days ago` : "has no recorded use"}`, { owner: c.holder, scopes: c.details.scopes ?? [] });
  }
  for (const a of listApps(orgId)) {
    const writes = Object.entries(a.permissions).filter(([k, v]) => (v === "write" || v === "admin") && k !== "metadata").map(([k]) => k);
    if (a.repository_selection === "all" && writes.some((w) => ["contents", "administration", "workflows", "actions", "secrets"].includes(w))) add("github.control.app_all_repos_write", appId(orgId, a.app_slug), a.app_slug, `${a.app_slug} is installed on every repository with write on ${writes.join(", ")}`, { write_permissions: writes });
  }

  // money: seats nobody fills, Copilot seats nobody uses, outside collaborators holding a seat with no activity
  const seatUsd = config.githubSeatUsd;
  if (org.seats != null && org.filled_seats != null && org.seats > org.filled_seats) { const n = org.seats - org.filled_seats; add("github.control.seats_unused", orgId, org.login, `${n} of ${org.seats} paid seats are empty (${org.filled_seats} used): ${Math.round(n * seatUsd)} USD a month at ${seatUsd} USD a seat`, { seats: org.seats, filled_seats: org.filled_seats, unused: n, monthly_usd: n * seatUsd }); }
  for (const s of listCopilotSeats(orgId)) { const d = daysSince(s.last_activity_at ?? s.created_at, now); if (d != null && d >= 30 && !s.pending_cancellation_date) add("github.control.copilot_seat_unused", identityIdOf(orgId, people, s.login), s.login, `${s.login}'s Copilot seat ${s.last_activity_at ? `was last used ${d} days ago` : `has not been used since it was assigned ${d} days ago`}`, { plan_type: s.plan_type, last_activity_at: s.last_activity_at }); }
  if (auditOk) for (const m of people) {
    const a = activity.get(m.login); const known = daysSince(m.first_seen, now) ?? 0;
    if (a || known < 7) continue; // seen in the log, or too new to the advisor to judge
    if (m.kind === "collaborator" && window >= 60) add("github.control.outside_collaborator_seat", idOf(m), m.login, `${m.login}, an outside collaborator, has no event in the audit log in ${window} days and holds a ${seatUsd} USD seat while they have access to a private repository`, { window_days: window, seat_usd: seatUsd });
    if (m.kind === "member" && window >= 60) add("github.control.member_inactive", idOf(m), m.login, `${m.login} has no event in the audit log in ${window} days`, { window_days: window, owner: m.role === "admin" }, m.role === "admin" ? "alarm" : undefined);
  }
  for (const i of extras.invitations) { const d = daysSince(i.created_at, now); if (!i.failed_at && d != null && d >= 7) add("github.control.invitation_stale", `${orgId}/invitation/${i.id}`, i.login ?? "invitation by e-mail", `the invitation to ${i.login ?? "an e-mail address"} (${i.role ?? "member"}) by ${i.inviter ?? "someone"} has waited ${d} days`, { role: i.role, inviter: i.inviter }); }

  // secrets that look like a static AWS key, on repositories that could use OIDC instead
  const byHolder = new Map<string, string[]>();
  for (const s of listSecrets(orgId)) if (AWS_KEY_NAME.test(s.name)) { const k = s.repo ? `${s.repo}${s.environment ? ` (${s.environment})` : ""}` : `${org.login} (org secret)`; byHolder.set(k, [...(byHolder.get(k) ?? []), s.name]); }
  for (const [holder, names] of byHolder) add("github.control.static_aws_keys", holder.includes("(org secret)") ? orgId : repoNodeId(holder.split(" ")[0]), holder, `${holder} stores ${names.join(", ")}: a long-lived AWS key a workflow can read`, { names });
  for (const h of (db.prepare("select id, repo, host from github_hooks where org_id = ? and gone = 0 and insecure_ssl = 1").all(orgId) as { id: number; repo: string | null; host: string | null }[])) add("github.control.webhook_insecure_ssl", h.repo ? repoNodeId(h.repo) : orgId, h.repo ?? org.login, `the webhook to ${h.host ?? "an unknown host"} on ${h.repo ?? "the org"} does not verify TLS`, { host: h.host });
  return out;
}

const identityIdOf = (orgId: string, people: { kind: string; login: string }[], login: string) => { const m = people.find((p) => p.login.toLowerCase() === login.toLowerCase()); return m ? (m.kind === "member" ? memberId(orgId, m.login) : collaboratorId(orgId, m.login)) : `${orgId}/user/${login}`; };

/** The recommendations the findings carry: the ones a person can act on, with what they save where the bill says. */
export function githubRecommendations(findings: GitHubFinding[]): RecInput[] {
  const out: RecInput[] = []; const seatUsd = config.githubSeatUsd;
  for (const f of findings) {
    const rule = f.control_id.replace(/^github\.control\./, "github_");
    const base = { rule, resource: f.resource, resourceName: f.resource_name, evidence: { findings: [{ reason: f.reason, ...f.dimensions }], control: f.control_id, category: f.category } };
    const rec = (title: string, actionType: string, tier: "report" | "approve", confidence: number, rationale: string, saving: number | null = null) => out.push({ ...base, title, actionType, estMonthlySaving: saving, tier, confidence, rationale: `${f.reason}. ${rationale}` });
    switch (f.control_id) {
      case "github.control.two_factor_not_required": rec(`${f.resource_name}: require two-factor authentication`, "security_fix", "report", 0.85, "Organization settings › Authentication security › Require two-factor authentication removes everyone without it, so ask those people to turn it on first."); break;
      case "github.control.member_no_2fa": rec(`${f.resource_name}: turn on two-factor authentication`, "security_fix", "report", 0.95, "A password alone opens every repository this person can reach."); break;
      case "github.control.outside_collaborator_admin": rec(`${f.resource_name}: lower the outside collaborator's role`, "security_fix", "approve", 0.75, "Admin lets them change settings, deploy keys, webhooks and collaborators; write or maintain is usually enough."); break;
      case "github.control.base_permission_write": rec(`${f.resource_name}: lower the base permission to read`, "security_fix", "report", 0.7, "Grant write through teams on the repositories each team works on."); break;
      case "github.control.single_owner": rec(`${f.resource_name}: add a second owner`, "other", "report", 0.7, "A second owner keeps billing and membership reachable if the only owner's account is lost."); break;
      case "github.control.deploy_key_unused": rec(`${f.resource_name}: delete the unused deploy key`, "delete", "approve", 0.75, "Nothing has used it; deleting it removes a credential nobody watches."); break;
      case "github.control.pat_no_expiry": rec(`${f.resource_name}: require token expiry`, "security_fix", "report", 0.75, "Organization settings › Personal access tokens can cap the lifetime of fine-grained tokens; ask the owner to replace this one."); break;
      case "github.control.pat_unused": rec(`${f.resource_name}: revoke the unused token's access`, "delete", "approve", 0.75, "Organization settings › Personal access tokens › Active tokens lets an owner revoke it."); break;
      case "github.control.credential_authorization_unused": rec(`${f.resource_name}: revoke the SSO authorization`, "delete", "approve", 0.7, "People › the member › SAML identity linking lists it; revoking it keeps the key or token off the org."); break;
      case "github.control.copilot_seat_unused": rec(`${f.resource_name}: remove the unused Copilot seat`, "delete", "approve", 0.7, "The seat is billed every month whether used or not."); break;
      case "github.control.seats_unused": rec(`${f.resource_name}: remove the empty seats`, "rightsize", "approve", 0.85, "Billing › Remove unused seats lowers the count from the next billing cycle.", Number(f.dimensions.monthly_usd) || null); break;
      case "github.control.outside_collaborator_seat": rec(`${f.resource_name}: remove the inactive outside collaborator`, "delete", "approve", 0.65, "An outside collaborator on a private repository takes a paid seat; remove them and the seat with it.", seatUsd); break;
      case "github.control.member_inactive": rec(`${f.resource_name}: confirm the member still needs access`, "other", "report", 0.6, "If they left, removing them frees a seat and every path in their access.", seatUsd); break;
      case "github.control.static_aws_keys": rec(`${f.resource_name}: reach AWS through OIDC instead of a stored key`, "security_fix", "report", 0.8, "With GitHub's OIDC provider a workflow assumes an AWS role with a short-lived token; then delete the secret and the IAM key."); break;
      case "github.control.webhook_insecure_ssl": rec(`${f.resource_name}: verify TLS on the webhook`, "security_fix", "approve", 0.8, "Without verification anyone on the path can read the payloads."); break;
      default: break;
    }
  }
  return out;
}

export interface GitHubRulesResult { run_id: number; findings: number; alarms: number; recommendations: number; resolved: number }

/** One rules pass: the run row, its findings, the recommendations upserted and the stale ones resolved. */
export async function runGitHubRules(): Promise<GitHubRulesResult> {
  const { upsertRecommendations } = await import("../../collector.js");
  const org = githubOrgRow(); if (!org) throw new Error("the org has not been read yet");
  const orgId = org.node_id; const findings = githubFindings(); const recs = githubRecommendations(findings);
  let runId = 0; let resolved = 0;
  db.transaction(() => {
    runId = Number(db.prepare("insert into runs(trigger, status, account_id, provider, started_at) values ('github', 'running', ?, 'github', datetime('now'))").run(orgId).lastInsertRowid);
    const ins = db.prepare("insert into findings(run_id, source, benchmark, control_id, control_title, status, resource, reason, dimensions, account_id, region, fingerprint) values (?, 'github', 'github', ?, ?, ?, ?, ?, ?, ?, null, ?)");
    for (const f of findings) ins.run(runId, f.control_id, f.control_title, f.severity === "info" ? "info" : "alarm", f.resource, f.reason, JSON.stringify({ ...f.dimensions, severity: f.severity, category: f.category, resource_name: f.resource_name }), orgId, `${f.control_id}:${f.resource}`);
    upsertRecommendations(runId, recs, "rules", undefined, { reconcile: false });
    const live = new Set(recs.map((r) => `${r.rule}:${r.resource}`));
    for (const row of db.prepare("select id, fingerprint from recommendations where status = 'open' and source = 'rules' and provider = 'github'").all() as { id: number; fingerprint: string }[]) {
      if (!live.has(row.fingerprint)) { db.prepare("update recommendations set status = 'resolved', updated_at = datetime('now') where id = ?").run(row.id); resolved++; }
    }
    db.prepare("update runs set status = 'completed', finished_at = datetime('now'), findings_count = ?, recommendations_count = ? where id = ?").run(findings.length, recs.length, runId);
  })();
  return { run_id: runId, findings: findings.length, alarms: findings.filter((f) => f.severity !== "info").length, recommendations: recs.length, resolved };
}

/** The latest pass's findings, for the Overview and the attention list. */
export function latestGitHubFindings(orgId: string): { run_id: number | null; at: string | null; findings: GitHubFinding[] } {
  const run = db.prepare("select id, finished_at from runs where provider = 'github' and account_id = ? and status = 'completed' order by id desc limit 1").get(orgId) as { id: number; finished_at: string } | undefined;
  if (!run) return { run_id: null, at: null, findings: [] };
  const order = { alarm: 0, warning: 1, info: 2 };
  const findings = (db.prepare("select control_id, control_title, resource, reason, dimensions from findings where run_id = ? order by id").all(run.id) as any[]).map((r) => { let d: any = {}; try { d = JSON.parse(r.dimensions || "{}"); } catch { /* */ } const { severity = "info", category = "operations", resource_name = r.resource, ...dimensions } = d; return { control_id: r.control_id, control_title: r.control_title, severity, category, resource: r.resource, resource_name, reason: r.reason, dimensions } as GitHubFinding; });
  return { run_id: run.id, at: run.finished_at, findings: findings.sort((a, b) => order[a.severity] - order[b.severity]) };
}

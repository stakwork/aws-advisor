/**
 * Recommendations from who can get in (src/sign_ins.ts, src/role_trust.ts): what the foundational security benchmark
 * cannot see because it needs CloudTrail or the organisation's settings. Root MFA, root keys, console users without MFA
 * and key rotation are the benchmark's own controls and are not repeated here.
 *
 * - identity_central_root_access: the organisation has member accounts but does not manage their roots centrally;
 * - identity_center_mfa: Identity Center sign-ins that were not asked for a second factor, or administrators whose
 *   only factor is an authenticator app (phishable);
 * - identity_key_on_laptop: a long-lived access key called from a desktop OS (the CLI or an SDK on someone's machine);
 * - identity_mfa_device_removed: an MFA device was removed from an Identity Center user who is still enabled;
 * - identity_role_wide_trust: a role whose trust is wider than it looks (an OIDC issuer without a subject, "*", an
 *   external account without an external id, Cognito guests);
 * - identity_unused_outside_role: a role another account, a pipeline or a federated issuer may assume, unused for 90 days.
 *
 * Nothing is automated (tier report or approve): every fix is a person's change to sign-in or trust. Each rule's
 * playbook is generated from the official pages listed in src/playbooks.ts CONTROL_SOURCES (rule.identity_*).
 */
import type { RecInput } from "./rules.js";
import { listActors, listDirectoryChanges, signInMeta } from "./sign_ins.js";
import { listRoles, isOutsideTrust } from "./role_trust.js";
import { listMembers } from "./accounts.js";
import { oidcLinks } from "./vercel_aws_links.js";
import { credentialsMeta } from "./steampipe.js";
import { ssoMeta } from "./sso_inventory.js";

const DESKTOP = new Set(["macOS", "Windows", "Linux"]);
const days = (iso: string | null | undefined) => (iso ? (Date.now() - Date.parse(iso)) / 86_400_000 : Infinity);

/** Every identity recommendation the stored inventory supports right now. */
export function identityRecommendations(): RecInput[] {
  const out: RecInput[] = [];
  const actors = listActors(null);
  const parent = credentialsMeta()?.accountId ?? null;

  // the organisation's roots: central management is a management-account setting, one recommendation for the organisation
  const m = signInMeta();
  if (m.centralized === false && listMembers().some((x) => x.enabled) && parent) out.push({
    rule: "identity_central_root_access", title: "Manage member accounts' root users centrally", resource: parent, resourceName: "organisation root access", actionType: "security_fix", estMonthlySaving: null, tier: "report", confidence: 0.9,
    rationale: "Every member account still has its own root user with its own password and MFA to keep. Central root access management (IAM › Root access management, from the management account) removes member root credentials and lets the management account run the few root-only tasks for a short session instead.",
    evidence: { centralized: false, members: listMembers().filter((x) => x.enabled).map((x) => x.account_id) },
  });

  // Identity Center: sign-ins never asked for a second factor, and administrators on an authenticator app only
  const sso = actors.filter((a) => a.kind === "sso_user" && a.status === "active");
  const notAsked = sso.filter((a) => (a.sign_ins_90d ?? 0) > 0 && (a.mfa_sign_ins_90d ?? 0) === 0);
  const appAdmins = sso.filter((a) => a.admin && a.mfa === "app");
  const ic = ssoMeta();
  if ((notAsked.length || appAdmins.length) && ic.instance_arn) out.push({
    rule: "identity_center_mfa", title: "Identity Center: ask for MFA at every sign-in and prefer passkeys", resource: ic.instance_arn, resourceName: `Identity Center${ic.name ? ` ${ic.name}` : ""}`, actionType: "security_fix", estMonthlySaving: null, tier: "report", confidence: 0.85,
    rationale: [
      notAsked.length ? `${notAsked.length} enabled user${notAsked.length === 1 ? " was" : "s were"} never asked for a second factor in 90 days of sign-ins (${notAsked.slice(0, 5).map((a) => a.name).join(", ")}${notAsked.length > 5 ? ", …" : ""}): context-aware MFA skips a browser it trusts, so a stolen password on a trusted machine is enough` : "",
      appAdmins.length ? `${appAdmins.length} administrator${appAdmins.length === 1 ? "" : "s"} sign${appAdmins.length === 1 ? "s" : ""} in with an authenticator app only (${appAdmins.slice(0, 5).map((a) => a.name).join(", ")}), a code a fake sign-in page can phish` : "",
    ].filter(Boolean).join("; ") + ". Settings › Authentication › MFA: prompt every time, and allow security keys and built-in authenticators (passkeys) only.",
    evidence: { not_asked: notAsked.map((a) => ({ user: a.name, sign_ins_90d: a.sign_ins_90d })), app_only_admins: appAdmins.map((a) => a.name) },
  });

  // long-lived keys called from a laptop or desktop: Identity Center's short-lived credentials (aws sso login) replace them
  for (const a of actors.filter((x) => x.kind === "iam_user" && x.status === "active")) {
    const laptops = a.clients.filter((c) => c.factors.includes("access_key") && c.platform && DESKTOP.has(c.platform));
    if (!laptops.length) continue;
    out.push({
      rule: "identity_key_on_laptop", title: `${a.name}: replace the access key used from a laptop`, resource: a.id, resourceName: a.name, actionType: "security_fix", estMonthlySaving: null, tier: "report", confidence: 0.8,
      rationale: `${a.name}'s long-lived access key${laptops.flatMap((c) => c.keys).length ? ` (…${[...new Set(laptops.flatMap((c) => c.keys))].join(", …")})` : ""} is called from ${[...new Set(laptops.map((c) => `${c.client} on ${c.platform}`))].join(", ")}. A key on a laptop works from anywhere until someone deletes it, with no MFA. Configure the AWS CLI for IAM Identity Center (aws configure sso, then aws sso login), move the work over, then deactivate and delete the key.`,
      evidence: { clients: laptops, admin: a.admin, account_id: a.account_id },
    });
  }

  // MFA devices removed from users who are still enabled, in the last 30 days
  const enabled = new Map(sso.map((a) => [a.id, a]));
  for (const c of listDirectoryChanges(500).filter((x) => x.event_name === "DeleteMfaDeviceForUser" && !x.failed && days(x.event_time) <= 30)) {
    const u = c.target_user_id ? enabled.get(c.target_user_id) : undefined;
    if (!u) continue;
    out.push({
      rule: "identity_mfa_device_removed", title: `${u.name}: an MFA device was removed`, resource: `${u.id}:mfa-removed:${c.event_time.slice(0, 10)}`, resourceName: u.name, actionType: "security_fix", estMonthlySaving: null, tier: "report", confidence: 0.7,
      rationale: `${c.by ?? "Someone"} removed an MFA device from ${u.name} on ${c.event_time.slice(0, 10)}, and the user is still enabled. Confirm the change was asked for (a lost phone, a new key) and that the user has registered a new device; an unexplained removal is how an attacker who has the password gets past MFA.`,
      evidence: { change: c, user_id: u.id },
    });
  }

  // roles: a trust wider than it looks, and outside ways in nobody has used for 90 days. "Outside" here leaves out the
  // organisation's own accounts: OrganizationAccountAccessRole and admin roles between accounts are rarely used by design
  const vercelUse = new Map<string, string[]>(); for (const l of oidcLinks()) vercelUse.set(l.role_arn, [...(vercelUse.get(l.role_arn) ?? []), `${l.project_name} (${l.environments.join(", ")})`]);
  for (const r of listRoles({ outside: false })) {
    // Cognito guests are allowed by design: the fix is what the role may do, not who may assume it
    const guests = r.principals.some((p) => p.kind === "cognito" && p.risk && /unauthenticated/i.test(p.who));
    if (r.risk) out.push({
      rule: "identity_role_wide_trust", title: guests ? `${r.name}: keep the guest role's permissions minimal` : `${r.name}: narrow who may assume the role`, resource: r.arn, resourceName: r.name, actionType: "security_fix", estMonthlySaving: null, tier: "report", confidence: r.risk === "alarm" ? 0.9 : guests ? 0.6 : 0.75,
      rationale: guests
        ? `${r.risk_reason}.${r.admin ? " The role is administrative: an anonymous visitor gets administrator credentials." : ""} Its policies (${r.policies.join(", ") || "none"}) are what anyone on the internet may do; keep them to what an anonymous visitor of the app needs, or turn guest access off on the identity pool.`
        : `${r.risk_reason}.${r.admin ? " The role is administrative." : ""} Add the condition that names exactly who should assume it (a subject for an OIDC issuer, sts:ExternalId for another company's account, aws:PrincipalOrgID for "*"), or remove the statement.`,
      evidence: { principals: r.principals.filter((p) => p.kind !== "service"), admin: r.admin, last_used: r.last_used, account_id: r.account_id },
    });
    const strangers = r.principals.filter((p) => !["service", "same_account", "org_account", "identity_center", "eks"].includes(p.kind));
    const projects = vercelUse.get(r.arn) ?? [];
    if (isOutsideTrust(r.principals) && strangers.length && days(r.last_used) > 90 && days(r.created) > 90) out.push({
      rule: "identity_unused_outside_role", title: `${r.name}: remove the unused role`, resource: r.arn, resourceName: r.name, actionType: "delete", estMonthlySaving: null, tier: "approve", confidence: projects.length ? 0.4 : 0.6,
      rationale: `${strangers.map((p) => p.who).join(", ")} may assume ${r.name}, and it ${r.last_used ? `was last used on ${r.last_used.slice(0, 10)}` : "has never been used"}.${projects.length ? ` The Vercel project${projects.length === 1 ? "" : "s"} ${projects.join(", ")} still ${projects.length === 1 ? "has" : "have"} OIDC set up for it, so check whether the code still calls AWS before removing it.` : ""} An unused way in is still a way in; delete the role, or its trust statement, once the owner confirms nothing depends on it.`,
      evidence: { principals: r.principals.filter((p) => p.kind !== "service"), last_used: r.last_used, created: r.created, admin: r.admin, account_id: r.account_id },
    });
  }
  return out;
}


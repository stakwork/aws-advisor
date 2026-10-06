/**
 * IAM roles and who may assume them: the non-human ways in. Read from Steampipe's aws_iam_role across every account
 * (trust policy, last use, attached and inline policies). Each Allow statement on sts:AssumeRole* is reduced to a
 * principal with a kind:
 *
 * - `service`: an AWS service (ec2.amazonaws.com …), the system itself;
 * - `same_account`, `org_account` (an account the advisor knows), `external_account` (anyone else's), `public` ("*");
 * - `github_actions`, `vercel`, `gitlab`, `terraform_cloud`, `circleci`, `bitbucket`, `oidc` (another issuer),
 *   `eks` (pods of a cluster), `cognito` (identity pool users, `unauthenticated` when the pool's guests may), `web_identity`,
 *   `identity_center` (the AWSReservedSSO_ roles), `saml`;
 *
 * with the conditions that narrow it (the GitHub repositories, the Vercel projects and environments, an external id,
 * the organisation id). A risk is raised where the trust is wider than it looks: an OIDC issuer without a subject
 * condition (any repository on GitHub, any project on the issuer), a wildcard subject, an external account without an
 * external id, "*" without a condition, guests of a Cognito pool. One row per role; in the graph each role that is not
 * a pure service role is an AdvisorIdentity {kind: role} with `trust` and `trusted_by` (docs/cloud-ontology.md).
 */
import { addColumn, db } from "./db.js";
import { S, query } from "./steampipe.js";
import { describeError } from "./permissions.js";
import { isAdmin } from "./iam_inventory.js";
import { accountWhere, type AccountScope } from "./scope.js";

db.exec(`create table if not exists inventory_iam_role (
  arn text primary key, name text not null, account_id text, path text, created text, description text, last_used text, last_used_region text,
  admin integer not null default 0, policies text not null default '[]', principals text not null default '[]', trust text, risk text, risk_reason text,
  first_seen text not null, last_seen text not null, gone integer not null default 0
)`);
addColumn("inventory_iam_role", "max_session_hours", "real");

export type PrincipalKind = "service" | "same_account" | "org_account" | "external_account" | "public" | "github_actions" | "vercel" | "gitlab" | "terraform_cloud" | "circleci" | "bitbucket" | "oidc" | "eks" | "cognito" | "web_identity" | "identity_center" | "saml";
export interface TrustPrincipal {
  kind: PrincipalKind; who: string; account_id: string | null;
  /** what the conditions narrow it to: repositories, projects and environments, a cluster's service accounts, an organisation */
  scope: string[];
  external_id: boolean; org_restricted: boolean; risk: "alarm" | "warning" | null; risk_reason: string | null;
}

const arr = <T,>(v: T | T[] | undefined | null): T[] => (v == null ? [] : Array.isArray(v) ? v : [v]);
const obj = (v: unknown): any => (v && typeof v === "object" ? v : typeof v === "string" ? (() => { try { return JSON.parse(v); } catch { return null; } })() : null);
const iso = (v: unknown): string | null => (v == null ? null : v instanceof Date ? v.toISOString() : String(v));

/** The values every condition operator gives a key (StringEquals, StringLike, ForAnyValue:StringLike …), case-insensitive on the key. Pure. */
export function conditionValues(cond: any, key: string): string[] {
  const out: string[] = []; const k = key.toLowerCase();
  for (const [, block] of Object.entries(cond ?? {})) for (const [ck, v] of Object.entries((block as any) ?? {})) if (ck.toLowerCase() === k) out.push(...arr(v as any).map(String));
  return out;
}
const hasKey = (cond: any, key: string) => Object.values(cond ?? {}).some((b: any) => Object.keys(b ?? {}).some((ck) => ck.toLowerCase() === key.toLowerCase()));

/** The issuer host of an OIDC provider ARN or a bare host. Pure. */
export const oidcHost = (federated: string) => federated.replace(/^arn:aws:iam::\d+:oidc-provider\//, "");

/** One federated principal (an OIDC provider, a SAML provider, a web identity) with its conditions, classified. Pure. */
export function federatedPrincipal(federated: string, cond: any, ownAccount: string | null): TrustPrincipal {
  const base = { account_id: ownAccount, external_id: false, org_restricted: false, risk: null as TrustPrincipal["risk"], risk_reason: null as string | null };
  if (/:saml-provider\//.test(federated)) { const name = federated.split("/").pop() ?? federated; return { ...base, kind: /^AWSSSO_/.test(name) ? "identity_center" : "saml", who: name, scope: [] }; }
  if (federated === "cognito-identity.amazonaws.com") {
    const pools = conditionValues(cond, "cognito-identity.amazonaws.com:aud"); const amr = conditionValues(cond, "cognito-identity.amazonaws.com:amr");
    const guests = amr.some((a) => /unauthenticated/i.test(a));
    return { ...base, kind: "cognito", who: guests ? "Cognito guests (unauthenticated)" : "Cognito signed-in users", scope: pools,
      risk: !pools.length ? "alarm" : guests ? "warning" : null, risk_reason: !pools.length ? "no identity pool named: any Cognito pool's users could assume it" : guests ? "unauthenticated guests of the pool: anyone on the internet gets these credentials" : null };
  }
  if (/^(accounts\.google\.com|graph\.facebook\.com|www\.amazon\.com|appleid\.apple\.com)$/.test(federated)) return { ...base, kind: "web_identity", who: federated, scope: conditionValues(cond, `${federated}:aud`) };
  const host = oidcHost(federated);
  const sub = conditionValues(cond, `${host}:sub`); const aud = conditionValues(cond, `${host}:aud`);
  const wild = (v: string) => v === "*" || /^repo:\*/.test(v) || /^owner:\*/.test(v);
  if (host === "token.actions.githubusercontent.com") {
    const risk = !sub.length ? "alarm" : sub.some(wild) ? "alarm" : null;
    return { ...base, kind: "github_actions", who: "GitHub Actions", scope: sub.map((s) => s.replace(/^repo:/, "")), risk, risk_reason: !sub.length ? "no subject condition: a workflow in any GitHub repository can assume it" : sub.some(wild) ? "a wildcard subject lets any repository's workflows assume it" : null };
  }
  if (/^oidc\.vercel\.com(\/|$)/.test(host)) {
    const team = host.split("/")[1] ?? null;
    const risk = !sub.length && !team ? "alarm" : !sub.length ? "warning" : sub.some(wild) ? "warning" : null;
    return { ...base, kind: "vercel", who: team ? `Vercel team ${team}` : "Vercel (global issuer)", scope: sub.map((s) => s.replace(/^owner:[^:]+:/, "")), risk,
      risk_reason: !sub.length && !team ? "the global issuer with no subject condition: a project of any Vercel team can assume it" : !sub.length ? "no subject condition: any project and environment of the team can assume it" : sub.some(wild) ? "a wildcard subject" : null };
  }
  if (/^oidc\.eks\.[^/]+\.amazonaws\.com\/id\//.test(host)) return { ...base, kind: "eks", who: `EKS cluster ${host.split("/").pop()?.slice(0, 8)}…`, scope: sub.map((s) => s.replace(/^system:serviceaccount:/, "")), risk: !sub.length ? "warning" : null, risk_reason: !sub.length ? "no subject condition: any service account in the cluster can assume it" : null };
  const known: [RegExp, PrincipalKind, string][] = [[/^gitlab\.com$/, "gitlab", "GitLab CI"], [/^app\.terraform\.io$/, "terraform_cloud", "Terraform Cloud"], [/^oidc\.circleci\.com\//, "circleci", "CircleCI"], [/bitbucket/, "bitbucket", "Bitbucket Pipelines"]];
  const k = known.find(([re]) => re.test(host));
  return { ...base, kind: k?.[1] ?? "oidc", who: k?.[2] ?? host, scope: sub.length ? sub : aud, risk: !sub.length && !aud.length ? "alarm" : !sub.length ? "warning" : null, risk_reason: !sub.length && !aud.length ? "no subject or audience condition on the issuer" : !sub.length ? "no subject condition: anything the issuer signs for this audience can assume it" : null };
}

/** The account id an AWS principal names ("*", an account id, an ARN). Pure. */
export const accountOfPrincipal = (p: string): string | null => (p === "*" ? null : /^\d{12}$/.test(p) ? p : /^arn:aws[^:]*:(iam|sts)::(\d{12}):/.exec(p)?.[2] ?? null);

/** Every principal of a trust policy, classified against the role's own account and the accounts the advisor knows. Pure. */
export function trustPrincipals(policy: unknown, ownAccount: string | null, knownAccounts: Set<string>): TrustPrincipal[] {
  const doc = obj(policy); const out: TrustPrincipal[] = [];
  for (const st of arr(doc?.Statement)) {
    if (st?.Effect !== "Allow") continue;
    const actions = arr(st.Action).map(String);
    if (!actions.some((a) => /^sts:(AssumeRole|AssumeRoleWithWebIdentity|AssumeRoleWithSAML|\*)$|^\*$|^sts:AssumeRole\*$/.test(a))) continue;
    const cond = st.Condition ?? {};
    const extId = hasKey(cond, "sts:ExternalId") && !Object.keys(cond).some((op) => /^Null$/i.test(op));
    const org = conditionValues(cond, "aws:PrincipalOrgID"); const orgPaths = conditionValues(cond, "aws:PrincipalOrgPaths");
    const p = st.Principal;
    if (p === "*" || arr(p?.AWS).includes("*")) {
      const restricted = org.length > 0 || orgPaths.length > 0 || hasKey(cond, "aws:PrincipalAccount") || hasKey(cond, "aws:PrincipalArn");
      out.push({ kind: "public", who: "anyone (*)", account_id: null, scope: [...org, ...orgPaths, ...conditionValues(cond, "aws:PrincipalAccount"), ...conditionValues(cond, "aws:PrincipalArn")], external_id: extId, org_restricted: restricted,
        risk: restricted ? null : "alarm", risk_reason: restricted ? null : "\"*\" with no organisation or account condition: any AWS account can assume it" });
      continue;
    }
    for (const svc of arr(p?.Service)) out.push({ kind: "service", who: String(svc), account_id: null, scope: [], external_id: false, org_restricted: false, risk: null, risk_reason: null });
    for (const a of arr(p?.AWS).map(String)) {
      const acct = accountOfPrincipal(a);
      const kind: PrincipalKind = acct && acct === ownAccount ? "same_account" : acct && knownAccounts.has(acct) ? "org_account" : "external_account";
      const who = /:root$/.test(a) || /^\d{12}$/.test(a) ? `account ${acct}` : a.replace(/^arn:aws[^:]*:(iam|sts)::\d{12}:/, "");
      out.push({ kind, who, account_id: acct, scope: org, external_id: extId, org_restricted: org.length > 0,
        risk: kind === "external_account" && !extId && !org.length ? "warning" : null, risk_reason: kind === "external_account" && !extId && !org.length ? "another company's account with no external id: the confused-deputy guard is missing" : null });
    }
    for (const f of arr(p?.Federated).map(String)) out.push(federatedPrincipal(f, cond, ownAccount));
  }
  return out;
}

/** The ontology's `trust` summary: the widest kind of principal, in the words of docs/cloud-ontology.md. Pure. */
export function trustSummary(ps: TrustPrincipal[]): "public" | "federated" | "cross_account" | "same_account" | "service" | "none" {
  const k = new Set(ps.map((p) => p.kind));
  if (k.has("public")) return "public";
  if ([...k].some((x) => !["service", "same_account", "org_account", "external_account"].includes(x))) return "federated";
  if (k.has("external_account") || k.has("org_account")) return "cross_account";
  if (k.has("same_account")) return "same_account";
  return k.size ? "service" : "none";
}

/** Whether a role is a way in from outside the account: anything but a service, the same account, Identity Center or the pods of an EKS cluster (the account's own workloads). Pure. */
export const isOutsideTrust = (ps: TrustPrincipal[]) => ps.some((p) => !["service", "same_account", "identity_center", "eks"].includes(p.kind));

export interface RoleRow {
  arn: string; name: string; account_id: string | null; path: string | null; created: string | null; description: string | null; last_used: string | null; last_used_region: string | null;
  admin: boolean; policies: string[]; principals: TrustPrincipal[]; trust: string | null; risk: "alarm" | "warning" | null; risk_reason: string | null; max_session_hours: number | null; first_seen: string; last_seen: string; gone: boolean;
}

const ROLES_SQL = `select arn, name, account_id, path, create_date, description, assume_role_policy, role_last_used_date, role_last_used_region, attached_policy_arns, inline_policies, max_session_duration from ${S}.aws_iam_role`;

export async function refreshRoleTrust(onError: (m: string) => void = () => {}, onLog: (l: string) => void = () => {}): Promise<{ roles: number; outside: number; risky: number }> {
  let rows: any[] = [];
  try { rows = await query(ROLES_SQL); } catch (e: any) { onError(`IAM roles: ${describeError(e, "iam roles (aws_iam_role)")}`); return { roles: 0, outside: 0, risky: 0 }; }
  // the accounts the advisor reaches (the parent and every member) are the organisation's own
  const known = new Set<string>();
  try { const { listAccounts } = await import("./accounts.js"); for (const a of listAccounts()) if (a.account_id) known.add(String(a.account_id)); } catch { /* none known: every other account reads as external */ }
  try { const { credentialsMeta } = await import("./steampipe.js"); const p = credentialsMeta()?.accountId; if (p) known.add(p); } catch { /* the members alone */ }
  const now = new Date().toISOString(); let outside = 0; let risky = 0;
  const up = db.prepare(`insert into inventory_iam_role(arn, name, account_id, path, created, description, last_used, last_used_region, admin, policies, principals, trust, risk, risk_reason, max_session_hours, first_seen, last_seen, gone)
    values (@arn, @name, @account_id, @path, @created, @description, @last_used, @last_used_region, @admin, @policies, @principals, @trust, @risk, @risk_reason, @max_session_hours, @now, @now, 0)
    on conflict(arn) do update set name = excluded.name, account_id = excluded.account_id, path = excluded.path, created = excluded.created, description = excluded.description, last_used = coalesce(excluded.last_used, inventory_iam_role.last_used), last_used_region = excluded.last_used_region,
      admin = excluded.admin, policies = excluded.policies, principals = excluded.principals, trust = excluded.trust, risk = excluded.risk, risk_reason = excluded.risk_reason, max_session_hours = excluded.max_session_hours, last_seen = excluded.last_seen, gone = 0`);
  db.transaction(() => {
    for (const r of rows) {
      const ps = trustPrincipals(r.assume_role_policy, r.account_id ? String(r.account_id) : null, known);
      const attached = (Array.isArray(r.attached_policy_arns) ? r.attached_policy_arns : obj(r.attached_policy_arns) ?? []).map(String);
      const inline = Array.isArray(r.inline_policies) ? r.inline_policies : obj(r.inline_policies) ?? [];
      const worst = ps.find((p) => p.risk === "alarm") ?? ps.find((p) => p.risk === "warning") ?? null;
      if (isOutsideTrust(ps)) outside++; if (worst) risky++;
      up.run({ arn: String(r.arn), name: String(r.name), account_id: r.account_id ? String(r.account_id) : null, path: r.path ?? null, created: iso(r.create_date), description: r.description ?? null, last_used: iso(r.role_last_used_date), last_used_region: r.role_last_used_region ?? null,
        admin: isAdmin(attached, inline) ? 1 : 0, policies: JSON.stringify([...attached.map((a: string) => a.split("/").pop()), ...inline.map((p: any) => `inline ${p?.PolicyName ?? p?.policy_name ?? "policy"}`)]), principals: JSON.stringify(ps), trust: trustSummary(ps),
        risk: worst?.risk ?? null, risk_reason: worst ? `${worst.who}: ${worst.risk_reason}` : null, max_session_hours: r.max_session_duration ? Number(r.max_session_duration) / 3600 : null, now });
    }
  })();
  const gone = rows.length ? db.prepare("update inventory_iam_role set gone = 1 where gone = 0 and last_seen < ?").run(now).changes : 0;
  onLog(`${rows.length} IAM roles, ${outside} trusted from outside the account, ${risky} with a wide trust${gone ? `, ${gone} gone` : ""}`);
  return { roles: rows.length, outside, risky };
}

const parse = (r: any): RoleRow => ({ ...r, admin: Boolean(r.admin), policies: obj(r.policies) ?? [], principals: obj(r.principals) ?? [], gone: Boolean(r.gone) });

/** The roles; `outside` keeps those a principal outside the account (or a federated issuer) may assume, riskiest first. */
export function listRoles(f: { outside?: boolean; scope?: AccountScope | null; gone?: boolean } = {}): RoleRow[] {
  const a = accountWhere(f.scope);
  const rows = (db.prepare(`select * from inventory_iam_role where ${f.gone ? "1=1" : "gone = 0"} and ${a.sql} order by case risk when 'alarm' then 0 when 'warning' then 1 else 2 end, admin desc, name`).all(...a.params) as any[]).map(parse);
  return f.outside ? rows.filter((r) => isOutsideTrust(r.principals)) : rows;
}

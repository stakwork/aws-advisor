/**
 * The exact answer for one question: can this person do these actions (on this resource)? The graph's grades are
 * read from the policy documents (src/policy_facts.ts) and leave conditions and tag-based scopes as "conditional";
 * iam:SimulatePrincipalPolicy evaluates them the way IAM does, with the permissions boundary and the organisation's
 * SCPs, for each principal the person reaches in the account (their IAM user, the reserved role of each Identity
 * Center assignment, every role a path leads to). Resource policies (a bucket policy) are not part of it.
 * https://docs.aws.amazon.com/IAM/latest/APIReference/API_SimulatePrincipalPolicy.html
 */
import { IAMClient, SimulatePrincipalPolicyCommand } from "@aws-sdk/client-iam";
import { accountCredentials } from "./accounts.js";
import { personReach, type ReachPath } from "./access_paths.js";
import { listPrincipals } from "./entitlements.js";
import { listActors, listPeople } from "./sign_ins.js";
import { personId } from "./graph_access.js";
import { describeError, noteSuccess } from "./permissions.js";

export interface SimulationRow { principal: string; account_id: string; action: string; resource: string; decision: "allowed" | "explicitDeny" | "implicitDeny" | "error"; matched: string[]; boundary_allows: boolean | null; scp_allows: boolean | null; missing_context: string[]; path: ReachPath | null; error?: string }
export interface Simulation { person_id: string; actions: string[]; resource: string | null; rows: SimulationRow[]; allowed: boolean; summary: string }

const accountOfResource = (r: string | null) => (r ? /^arn:aws[^:]*:[^:]*:[^:]*:(\d{12}):/.exec(r)?.[1] ?? null : null);

/** Simulates the actions for every principal the person reaches in the account (or every account they reach when none is named and the resource names none). */
export async function simulateForPerson(personId: string, actions: string[], resource: string | null, accountId: string | null): Promise<Simulation> {
  const reach = personReach(personId);
  if (!reach) throw new Error("no such person");
  const acct = accountId ?? accountOfResource(resource);
  const targets = reach.accounts.filter((a) => !acct || a.account_id === acct);
  const rows: SimulationRow[] = [];
  for (const a of targets) for (const principal of a.principals.slice(0, 12)) {
    const path = a.paths.find((p) => p.steps.some((s) => s.includes(principal.split("/").pop() ?? principal))) ?? a.paths[0] ?? null;
    for (const r of await simulatePrincipal(principal, a.account_id, actions, resource)) rows.push({ ...r, path });
  }
  const allowed = rows.some((r) => r.decision === "allowed");
  const by = rows.filter((r) => r.decision === "allowed").map((r) => `${r.action} as ${r.principal.split("/").pop()}`);
  const summary = !targets.length ? `The person reaches no${acct ? ` principal in account ${acct}` : " AWS account"}.` : allowed ? `Allowed: ${[...new Set(by)].slice(0, 6).join("; ")}${rows.some((r) => r.missing_context.length && r.decision === "allowed") ? " (some depend on condition values the simulation did not have)" : ""}.` : rows.every((r) => r.decision === "error") ? "Could not simulate: see the errors." : "Denied for every principal the person reaches.";
  return { person_id: reach.person_id, actions, resource, rows, allowed, summary };
}

/** One principal's simulation, as rows. */
async function simulatePrincipal(principal: string, accountId: string, actions: string[], resource: string | null): Promise<SimulationRow[]> {
  const iam = new IAMClient({ region: "us-east-1", credentials: accountCredentials(accountId).provider });
  try {
    const r = await iam.send(new SimulatePrincipalPolicyCommand({ PolicySourceArn: principal, ActionNames: actions, ResourceArns: resource ? [resource] : undefined, MaxItems: 100 }));
    noteSuccess(["iam:SimulatePrincipalPolicy"], "entitlements");
    return (r.EvaluationResults ?? []).map((e) => ({ principal, account_id: accountId, action: String(e.EvalActionName), resource: String(e.EvalResourceName ?? resource ?? "*"), decision: e.EvalDecision as SimulationRow["decision"],
      matched: (e.MatchedStatements ?? []).map((m) => String(m.SourcePolicyId ?? m.SourcePolicyType ?? "")).filter(Boolean), boundary_allows: e.PermissionsBoundaryDecisionDetail?.AllowedByPermissionsBoundary ?? null,
      scp_allows: e.OrganizationsDecisionDetail?.AllowedByOrganizations ?? null, missing_context: e.MissingContextValues ?? [], path: null }));
  } catch (e: any) { return [{ principal, account_id: accountId, action: actions.join(", "), resource: resource ?? "*", decision: "error", matched: [], boundary_allows: null, scp_allows: null, missing_context: [], path: null, error: describeError(e, "iam:SimulatePrincipalPolicy") }]; }
}

/**
 * The agent's access check: `who` is a person (node id `person:<key>`, a name or an e-mail), an IAM user or role ARN, or
 * a user or role name. A person is simulated on every principal they reach; a principal on itself.
 */
export async function accessCheck(who: string, actions: string[], resource: string | null, accountId: string | null): Promise<Simulation | { error: string; candidates?: string[] }> {
  const w = who.trim();
  const arnAccount = /^arn:aws[^:]*:iam::(\d{12}):(user|role)\//.exec(w)?.[1];
  if (arnAccount) { const rows = await simulatePrincipal(w, arnAccount, actions, resource); return summarize(w, actions, resource, rows, true); }
  // a person by id, key, name or e-mail
  const people = listPeople(listActors(null)); const lw = w.toLowerCase();
  const person = people.find((p) => personId(p) === w || p.key === w) ?? people.find((p) => p.name.toLowerCase() === lw || (p.email ?? "").toLowerCase() === lw || p.identities.some((i) => i.name.toLowerCase() === lw));
  if (person) return simulateForPerson(personId(person) ?? person.key, actions, resource, accountId);
  // a user or role by name
  const hits = listPrincipals().filter((p) => p.kind !== "group" && p.name.toLowerCase() === lw && (!accountId || p.account_id === accountId));
  if (hits.length === 1) return summarize(hits[0].arn, actions, resource, await simulatePrincipal(hits[0].arn, hits[0].account_id, actions, resource), true);
  if (hits.length > 1) return { error: `"${w}" names a principal in ${hits.length} accounts: pass account_id or the ARN`, candidates: hits.map((h) => h.arn) };
  return { error: `no person, user or role named "${w}"`, candidates: people.filter((p) => p.name.toLowerCase().includes(lw.split(/[\s@.]/)[0])).slice(0, 5).map((p) => `${personId(p)} (${p.name})`) };
}

function summarize(who: string, actions: string[], resource: string | null, rows: SimulationRow[], principal: boolean): Simulation {
  const allowed = rows.some((r) => r.decision === "allowed");
  const summary = rows.every((r) => r.decision === "error") ? `Could not simulate: ${rows[0]?.error ?? "no result"}` : allowed ? `Allowed: ${[...new Set(rows.filter((r) => r.decision === "allowed").map((r) => r.action))].join(", ")}${rows.some((r) => r.decision !== "allowed" && r.decision !== "error") ? `; denied: ${[...new Set(rows.filter((r) => r.decision.endsWith("Deny")).map((r) => `${r.action} (${r.decision}${r.scp_allows === false ? ", SCP" : r.boundary_allows === false ? ", boundary" : ""})`))].join(", ")}` : ""}.` : `Denied${principal ? "" : " for every principal"}.`;
  return { person_id: who, actions, resource, rows, allowed, summary };
}

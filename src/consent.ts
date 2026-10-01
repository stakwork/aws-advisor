/**
 * Consent tags: one label per resource that says whether the advisor may take it down.
 *
 *  - `AdvisorAutoPark=ON` on an instance: the executor may stop and start it when the evidence says so. Idle
 *    parking (src/actions/swarm_park.ts) and the usage schedule (src/usage_profile.ts through
 *    src/actions/schedule_hours.ts) both read it, and the Stop / Start buttons on the Inventory page work only
 *    on a box that carries it. `OFF` (or no tag) means the executor never stops or starts the box, whatever
 *    else it is tagged; the older `advisor:park=auto` and `advisor:schedule` tags keep working as they did.
 *  - `AdvisorAutoScale=ON` on an Elastic Beanstalk environment: the capacity action may move the group's
 *    MinSize and MaxSize (floor 1, the ceiling where it is, unless `AdvisorScaleBand=<floor>-<ceiling>` widens
 *    it). Beanstalk propagates the tag to its group and balancer, so the environment is the one place to tag.
 *
 * The switches on the page write the tag through the actuator role, ledgered as a `consent_tag` row (Revert puts
 * the previous value back), and the IAM policy lets the role write these keys and no other; the stop, start and
 * scaling grants carry the same tag conditions, so the tag is enforced on the role, not only in the code.
 */
import { DescribeAddressesCommand, DescribeInstancesCommand, EC2Client } from "@aws-sdk/client-ec2";
import { DescribeEnvironmentsCommand, ElasticBeanstalkClient, ListTagsForResourceCommand } from "@aws-sdk/client-elastic-beanstalk";
import { GetCallerIdentityCommand, STSClient } from "@aws-sdk/client-sts";
import { db } from "./db.js";
import { config } from "./config.js";
import { actionModules, applyAction, executorCreds, getAction, proposalOf, recordProposal, verifyAction, type ActionRow, type Creds, type Proposal } from "./executor.js";
import { logEvent } from "./executor_log.js";
import { mirrorActionsInBackground } from "./graph_mirror.js";
import type { AwsCredentialIdentityProvider } from "@aws-sdk/types";
import { KIND as SCHEDULE_KIND, recordsForStart, recordsNamingIp } from "./actions/schedule_hours.js";
import { HIBERNATE_TAG } from "./actions/ec2_hibernate_migrate.js";
import { forgetHibernationStatus } from "./hibernation.js";
import { AUTOPARK_POLICY, accountOfArn, checkGrant, instanceArn, roleNameOf } from "./autopark_grant.js";
import { actuatorRoleFor } from "./accounts.js";

export const AUTO_PARK_TAG = "AdvisorAutoPark";
export const AUTO_SCALE_TAG = "AdvisorAutoScale";
export const SCALE_BAND_TAG = "AdvisorScaleBand";
export const CONSENT_KIND = "consent_tag" as const;

export type ConsentValue = "ON" | "OFF";
/** `ON`, `on`, `true`, `yes` and `1` all mean on; anything else is off. Pure. */
export const isOn = (v: string | null | undefined): boolean => /^(on|true|yes|1)$/i.test(String(v ?? "").trim());
/** Whether the tag is present and says off (an explicit no, which wins over every other opt-in tag). Pure. */
export const isOff = (v: string | null | undefined): boolean => v != null && !isOn(v);
export const normaliseConsent = (v: unknown): ConsentValue => (isOn(String(v)) ? "ON" : "OFF");

export interface ConsentRequest { kind: "ec2" | "beanstalk"; id: string; value: ConsentValue; by?: string; region?: string | null; account_id?: string | null }

class ConsentError extends Error { constructor(m: string, public status = 400) { super(m); this.name = "ConsentError"; } }

/** Flips the consent tag on an instance or an environment: one proposal, applied at once, on the ledger. */
export async function requestConsent(r: ConsentRequest): Promise<ActionRow> {
  const creds = executorCreds();
  const by = r.by || "ui";
  if (r.kind === "ec2") {
    const row = db.prepare("select instance_id, account_id, name, region, state from inventory_ec2 where instance_id = ?").get(r.id) as any;
    if (!row) throw new ConsentError(`${r.id} is not in the inventory`, 404);
    const region = row.region || creds.region;
    const ec2 = new EC2Client({ region, credentials: creds.forAccount(row.account_id || null).read });
    let inst;
    try { inst = (await ec2.send(new DescribeInstancesCommand({ InstanceIds: [r.id] }))).Reservations?.[0]?.Instances?.[0]; } finally { ec2.destroy(); }
    if (!inst) throw new ConsentError(`${r.id} not found by DescribeInstances`, 404);
    const tags = Object.fromEntries((inst.Tags ?? []).map((t) => [t.Key!, t.Value ?? ""]));
    if (tags["advisor:hands-off"] != null) throw new ConsentError(`${row.name || r.id} is tagged advisor:hands-off: remove that first`, 409);
    const before = tags[AUTO_PARK_TAG] ?? null;
    // the grant on the actuator role is half of the switch (src/autopark_grant.ts): a box tagged ON without it (from
    // before grants existed) can be switched ON again to add it
    const roleArn = actuatorRoleFor(row.account_id);
    if (!roleArn) throw new ConsentError(`no actuator role is configured for account ${row.account_id || "(parent)"}: there is nothing to grant stop and start on (Settings > Auto-actions)`, 409);
    const arn = instanceArn(region, accountOfArn(roleArn), r.id);
    if (before != null && normaliseConsent(before) === r.value) {
      const g = await checkGrant(creds.forAccount(row.account_id || null).read, roleArn, arn);
      if (r.value === "OFF" || g.granted !== false) throw new ConsentError(`${row.name || r.id} already carries ${AUTO_PARK_TAG}=${before}${r.value === "ON" ? ` and ${g.detail}` : ""}`, 409);
    }
    const p: Proposal = {
      kind: CONSENT_KIND, resource: r.id, resource_name: row.name, region, account_id: row.account_id ?? null,
      dedupe: `${CONSENT_KIND}:${r.id}:${r.value}`,
      title: `${row.name || r.id}: ${AUTO_PARK_TAG} ${before ?? "(none)"} → ${r.value}`,
      reason: r.value === "ON" ? `${by} switched auto-park on from the page: the executor may stop this box when it is idle or in its confident quiet hours and start it again before it is needed, re-pointing its DNS records when it has no Elastic IP. Done with your own credentials ("Run as me"): the tag, and a grant on the actuator role (${roleNameOf(roleArn)}, policy ${AUTOPARK_POLICY}) to stop and start this one instance. Stop and Start on the page work from then on.` : `${by} switched auto-park off from the page: the tag goes to OFF and this instance leaves the actuator role's grant, so nothing can stop or start it until it is switched on again (a box it stopped stays stopped until Start on the page or Revert on the row). Done with your own credentials ("Run as me").`,
      before: { [AUTO_PARK_TAG]: before }, after: { [AUTO_PARK_TAG]: r.value },
      facts: { kind: "ec2", tag: AUTO_PARK_TAG, by, state: inst.State?.Name ?? row.state ?? null, grant: { role_arn: roleArn, instance_arn: arn, on: r.value === "ON", before: isOn(before) } },
      rollback: `${before == null ? `DeleteTags ${AUTO_PARK_TAG}` : `CreateTags ${AUTO_PARK_TAG}=${before}`}, and the grant back to how it was`,
      est_usd_month: null,
    };
    // never tried with the actuator: it has no IAM write rights and may not write this tag. The row waits for "Run as me".
    return recordProposal(p, config.actMode, "manual").row;
  }
  const region = r.region || creds.region;
  const acct = creds.forAccount(r.account_id || null);
  const envId = (db.prepare("select beanstalk_env_id from inventory_elb where beanstalk_env = ? and gone = 0 and beanstalk_env_id is not null limit 1").get(r.id) as { beanstalk_env_id: string } | undefined)?.beanstalk_env_id ?? null;
  const eb = new ElasticBeanstalkClient({ region, credentials: acct.read });
  let env; let tags: Record<string, string> = {};
  try {
    env = await findEnvironment(eb, r.id, { region, account: acct.account_id, envId, credentials: acct.read });
    if (env?.EnvironmentArn) for (const t of (await eb.send(new ListTagsForResourceCommand({ ResourceArn: env.EnvironmentArn }))).ResourceTags ?? []) if (t.Key) tags[t.Key] = t.Value ?? "";
  } finally { eb.destroy(); }
  if (!env?.EnvironmentId || !env.EnvironmentArn) throw new ConsentError(`environment ${r.id} has no id or ARN`, 404);
  if (tags["advisor:hands-off"] != null) throw new ConsentError(`${r.id} is tagged advisor:hands-off: remove that first`, 409);
  const before = tags[AUTO_SCALE_TAG] ?? null;
  if (before != null && normaliseConsent(before) === r.value) throw new ConsentError(`${r.id} already carries ${AUTO_SCALE_TAG}=${before}`, 409);
  const p: Proposal = {
    kind: CONSENT_KIND, resource: env.EnvironmentId, resource_name: env.EnvironmentName ?? r.id, region, account_id: r.account_id ?? null,
    dedupe: `${CONSENT_KIND}:${env.EnvironmentId}:${r.value}`,
    title: `${env.EnvironmentName}: ${AUTO_SCALE_TAG} ${before ?? "(none)"} → ${r.value}`,
    reason: r.value === "ON" ? `${by} switched auto-scale on from the page: the capacity action may move the environment's MinSize and MaxSize (floor 1, the ceiling where it is, unless ${SCALE_BAND_TAG}=<floor>-<ceiling> widens it) from the group's usage. Beanstalk propagates the tag to the group and the balancer.` : `${by} switched auto-scale off from the page: the capacity action leaves the environment alone until it is switched on again.`,
    before: { [AUTO_SCALE_TAG]: before }, after: { [AUTO_SCALE_TAG]: r.value },
    facts: { kind: "beanstalk", tag: AUTO_SCALE_TAG, by, arn: env.EnvironmentArn, application: env.ApplicationName ?? null, band: tags[SCALE_BAND_TAG] ?? null },
    rollback: before == null ? `UpdateTagsForResource: remove ${AUTO_SCALE_TAG}` : `UpdateTagsForResource ${AUTO_SCALE_TAG}=${before}`,
    est_usd_month: null,
  };
  const rec = recordProposal(p, config.actMode, "manual");
  return applyAction(rec.row.id, "manual");
}

export type HibernateChoice = "stop" | "live" | "no" | null;

/**
 * The owner's hibernation choice from the Auto-park row, as the `advisor:hibernate` tag (one ledgered consent row,
 * Revert puts the old value back): `stop` or `live` asks the relaunch (src/actions/ec2_hibernate_migrate.ts) to make
 * the box hibernation-ready, announced and after its grace period; `no` keeps stop/start and stops the suggestion;
 * null removes the tag.
 */
export async function requestHibernateChoice(instanceId: string, value: HibernateChoice, by = "ui"): Promise<ActionRow> {
  if (value != null && !["stop", "live", "no"].includes(value)) throw new ConsentError(`the choice is stop, live, no or none, not ${value}`, 400);
  const creds = executorCreds();
  const row = db.prepare("select instance_id, account_id, name, region, state from inventory_ec2 where instance_id = ?").get(instanceId) as any;
  if (!row) throw new ConsentError(`${instanceId} is not in the inventory`, 404);
  const region = row.region || creds.region;
  const ec2 = new EC2Client({ region, credentials: creds.forAccount(row.account_id || null).read });
  let inst;
  try { inst = (await ec2.send(new DescribeInstancesCommand({ InstanceIds: [instanceId] }))).Reservations?.[0]?.Instances?.[0]; } finally { ec2.destroy(); }
  if (!inst) throw new ConsentError(`${instanceId} not found by DescribeInstances`, 404);
  const tags = Object.fromEntries((inst.Tags ?? []).map((t) => [t.Key!, t.Value ?? ""]));
  if (tags["advisor:hands-off"] != null) throw new ConsentError(`${row.name || instanceId} is tagged advisor:hands-off: remove that first`, 409);
  const before = tags[HIBERNATE_TAG] ?? null;
  if (before === value) throw new ConsentError(`${row.name || instanceId} already carries ${HIBERNATE_TAG}=${before ?? "(none)"}`, 409);
  const name = row.name || instanceId;
  const what = value === "stop" ? `make ${name} hibernation-ready with downtime: the next executor pass proposes the relaunch (image, new instance launched with hibernation on, addresses moved), announced and after its grace period; the old box is stopped, never terminated`
    : value === "live" ? `make ${name} hibernation-ready without downtime: a warm image while it runs, and the cut-over waits for a person to click Cut over`
    : value === "no" ? `keep ${name} on stop/start: parking stops it instead of hibernating it, and the page stops suggesting the migration`
    : `clear the hibernation choice on ${name}`;
  const p: Proposal = {
    kind: CONSENT_KIND, resource: instanceId, resource_name: row.name, region, account_id: row.account_id ?? null,
    dedupe: `${CONSENT_KIND}:${instanceId}:${HIBERNATE_TAG}:${value ?? "none"}`,
    title: `${name}: ${HIBERNATE_TAG} ${before ?? "(none)"} → ${value ?? "(none)"}`,
    reason: `${by} chose on the Auto-park row to ${what}. Done with your own credentials ("Run as me").`,
    before: { [HIBERNATE_TAG]: before }, after: { [HIBERNATE_TAG]: value },
    facts: { kind: "ec2", tag: HIBERNATE_TAG, by, state: inst.State?.Name ?? row.state ?? null, configured: Boolean(inst.HibernationOptions?.Configured) },
    rollback: before == null ? `DeleteTags ${HIBERNATE_TAG}` : `CreateTags ${HIBERNATE_TAG}=${before}`,
    est_usd_month: null,
  };
  // a person's own credentials write it ("Run as me"): advisor:hibernate opens the relaunch (image, stop, start) on the box,
  // so the actuator may not set it on itself
  forgetHibernationStatus(instanceId);
  return recordProposal(p, config.actMode, "manual").row;
}

/** The band as text for the tag, or null to remove it; the numbers are checked the way the capacity action reads them (parseBand). */
export function bandText(floor: unknown, ceiling: unknown): string | null {
  if (floor == null && ceiling == null) return null;
  if (floor == null || ceiling == null) throw new ConsentError("the band needs both a floor and a ceiling (empty both to remove it)", 400);
  const f = Number(floor), c = Number(ceiling);
  if (!Number.isInteger(f) || !Number.isInteger(c)) throw new ConsentError("the band is two whole numbers: floor and ceiling", 400);
  if (f < 1) throw new ConsentError("the floor is at least 1", 400);
  if (c <= f) throw new ConsentError("the ceiling must be above the floor", 400);
  if (c > 999) throw new ConsentError("the ceiling is at most 999", 400);
  return `${f}-${c}`;
}

export interface BandRequest { id: string; floor: number | null; ceiling: number | null; by?: string; region?: string | null; account_id?: string | null }

/**
 * Sets the bare minimum and the ceiling of an environment from the page: `AdvisorScaleBand=<floor>-<ceiling>`, one
 * ledgered consent row applied at once, the same as the switch. Nothing the executor does ever goes below the
 * floor or above the ceiling; the learned hourly minimum (src/capacity_pattern.ts) lives between them.
 */
export async function requestScaleBand(r: BandRequest): Promise<ActionRow> {
  const creds = executorCreds();
  const by = r.by || "ui";
  const value = bandText(r.floor, r.ceiling);
  const region = r.region || creds.region;
  const acct = creds.forAccount(r.account_id || null);
  const envId = (db.prepare("select beanstalk_env_id from inventory_elb where beanstalk_env = ? and gone = 0 and beanstalk_env_id is not null limit 1").get(r.id) as { beanstalk_env_id: string } | undefined)?.beanstalk_env_id ?? null;
  const eb = new ElasticBeanstalkClient({ region, credentials: acct.read });
  let env; const tags: Record<string, string> = {};
  try {
    env = await findEnvironment(eb, r.id, { region, account: acct.account_id, envId, credentials: acct.read });
    if (env?.EnvironmentArn) for (const t of (await eb.send(new ListTagsForResourceCommand({ ResourceArn: env.EnvironmentArn }))).ResourceTags ?? []) if (t.Key) tags[t.Key] = t.Value ?? "";
  } finally { eb.destroy(); }
  if (!env?.EnvironmentId || !env.EnvironmentArn) throw new ConsentError(`environment ${r.id} has no id or ARN`, 404);
  if (tags["advisor:hands-off"] != null) throw new ConsentError(`${r.id} is tagged advisor:hands-off: remove that first`, 409);
  const before = tags[SCALE_BAND_TAG] ?? null;
  if (before === value) throw new ConsentError(value == null ? `${r.id} carries no ${SCALE_BAND_TAG}` : `${r.id} already carries ${SCALE_BAND_TAG}=${before}`, 409);
  const p: Proposal = {
    kind: CONSENT_KIND, resource: env.EnvironmentId, resource_name: env.EnvironmentName ?? r.id, region, account_id: r.account_id ?? null,
    dedupe: `${CONSENT_KIND}:${env.EnvironmentId}:band:${value ?? "none"}`,
    title: `${env.EnvironmentName}: ${SCALE_BAND_TAG} ${before ?? "(none)"} → ${value ?? "(none)"}`,
    reason: value == null
      ? `${by} removed the band from the page: the capacity action is back to floor 1 and the ceiling where it is (${AUTO_SCALE_TAG} unchanged).`
      : `${by} set the band from the page: MinSize never goes below ${r.floor} (the bare minimum) and MaxSize never above ${r.ceiling}, whatever the usage says. Between them the executor moves the bounds from the group's usage: the learned minimum per hour of the week, a ceiling raise under pressure, the idle floor trim. Beanstalk propagates the tag to the group and the balancer.`,
    before: { [SCALE_BAND_TAG]: before }, after: { [SCALE_BAND_TAG]: value },
    facts: { kind: "beanstalk", tag: SCALE_BAND_TAG, by, arn: env.EnvironmentArn, application: env.ApplicationName ?? null, floor: r.floor, ceiling: r.ceiling, consent: tags[AUTO_SCALE_TAG] ?? null },
    rollback: before == null ? `UpdateTagsForResource: remove ${SCALE_BAND_TAG}` : `UpdateTagsForResource ${SCALE_BAND_TAG}=${before}`,
    est_usd_month: null,
  };
  const rec = recordProposal(p, config.actMode, "manual");
  return applyAction(rec.row.id, "manual");
}

/**
 * Finds an environment by id (the balancer's `elasticbeanstalk:environment-id` tag, when the inventory has it), else
 * by name, else by a case-insensitive scan of the region; a miss names the account, the region and what is there,
 * so a wrong account or a renamed environment is visible at once.
 */
async function findEnvironment(eb: ElasticBeanstalkClient, name: string, where: { region: string; account: string; envId?: string | null; credentials: any }) {
  if (where.envId) { const byId = (await eb.send(new DescribeEnvironmentsCommand({ EnvironmentIds: [where.envId], IncludeDeleted: false }))).Environments?.[0]; if (byId?.EnvironmentId) return byId; }
  const byName = (await eb.send(new DescribeEnvironmentsCommand({ EnvironmentNames: [name], IncludeDeleted: false }))).Environments?.[0];
  if (byName?.EnvironmentId) return byName;
  const all = (await eb.send(new DescribeEnvironmentsCommand({ IncludeDeleted: false }))).Environments ?? [];
  const loose = all.find((e) => e.EnvironmentName?.toLowerCase() === name.toLowerCase() || e.CNAME?.toLowerCase().startsWith(`${name.toLowerCase()}.`));
  if (loose?.EnvironmentId) return loose;
  const seen = all.map((e) => e.EnvironmentName).filter(Boolean);
  // who actually made the calls: the account the inventory row names and the identity the SDK holds can differ (Steampipe connection vs advisor credentials)
  let who = "";
  try { const sts = new STSClient({ region: where.region, credentials: where.credentials }); try { const id = await sts.send(new GetCallerIdentityCommand({})); who = ` The calls were made as ${id.Arn} (account ${id.Account}).`; } finally { sts.destroy(); } } catch { who = " The identity behind the calls could not be read (sts:GetCallerIdentity)."; }
  throw new ConsentError(`environment ${name}${where.envId ? ` (${where.envId})` : ""} not found in ${where.region} with the credentials of account ${where.account || "(parent)"}: ${seen.length ? `that account and region hold ${seen.length} environment(s): ${seen.slice(0, 8).join(", ")}${seen.length > 8 ? "…" : ""}` : "no environment is visible there at all"}.${who} If that account is not the balancer's, the advisor's credentials and the Steampipe connection point at different accounts, or the member account needs enabling under Settings › Accounts; a rebuilt environment needs an inventory refresh so the tag is read again.`, 404);
}

/** What an environment carries right now: the consent, the band and the operations role, for the switch on the page. */
export async function beanstalkConsent(name: string, region?: string | null, accountId?: string | null): Promise<{ environment_id: string; name: string; consent: string | null; on: boolean; band: string | null; floor: number | null; ceiling: number | null; operations_role: string | null; status: string | null; account_id: string; region: string }> {
  const creds = executorCreds();
  const acct = creds.forAccount(accountId || null);
  const envId = (db.prepare("select beanstalk_env_id from inventory_elb where beanstalk_env = ? and gone = 0 and beanstalk_env_id is not null limit 1").get(name) as { beanstalk_env_id: string } | undefined)?.beanstalk_env_id ?? null;
  const eb = new ElasticBeanstalkClient({ region: region || creds.region, credentials: acct.read });
  try {
    const env = await findEnvironment(eb, name, { region: region || creds.region, account: acct.account_id, envId, credentials: acct.read });
    const tags: Record<string, string> = {};
    if (env.EnvironmentArn) for (const t of (await eb.send(new ListTagsForResourceCommand({ ResourceArn: env.EnvironmentArn }))).ResourceTags ?? []) if (t.Key) tags[t.Key] = t.Value ?? "";
    const band = tags[SCALE_BAND_TAG] ?? null;
    const m = band ? /^(\d{1,3})\s*-\s*(\d{1,3})$/.exec(band.trim()) : null;
    return { environment_id: env.EnvironmentId!, name: env.EnvironmentName ?? name, consent: tags[AUTO_SCALE_TAG] ?? null, on: isOn(tags[AUTO_SCALE_TAG]), band, floor: m ? Number(m[1]) : null, ceiling: m ? Number(m[2]) : null, operations_role: env.OperationsRole ?? null, status: env.Status ?? null, account_id: acct.account_id, region: region || creds.region };
  } finally { eb.destroy(); }
}

/**
 * Stop or start a box from the page: only one tagged `AdvisorAutoPark=ON`, through the office-hours module (so a
 * start re-points the DNS records the way a scheduled one does), as a manual row on the ledger.
 */
export async function manualPower(instanceId: string, action: "stop" | "start", by = "ui"): Promise<ActionRow> {
  const creds = executorCreds();
  const row = db.prepare("select instance_id, account_id, name, region, instance_type, monthly_usd, pool_kind from inventory_ec2 where instance_id = ?").get(instanceId) as any;
  if (!row) throw new ConsentError(`${instanceId} is not in the inventory`, 404);
  const region = row.region || creds.region;
  const ec2 = new EC2Client({ region, credentials: creds.forAccount(row.account_id || null).read });
  let inst; let hasEip = false;
  try {
    inst = (await ec2.send(new DescribeInstancesCommand({ InstanceIds: [instanceId] }))).Reservations?.[0]?.Instances?.[0];
    if (inst) { try { hasEip = ((await ec2.send(new DescribeAddressesCommand({ Filters: [{ Name: "instance-id", Values: [instanceId] }] }))).Addresses ?? []).length > 0; } catch { hasEip = false; } }
  } finally { ec2.destroy(); }
  if (!inst) throw new ConsentError(`${instanceId} not found by DescribeInstances`, 404);
  const tags = Object.fromEntries((inst.Tags ?? []).map((t) => [t.Key!, t.Value ?? ""]));
  const name = row.name || instanceId;
  if (!isOn(tags[AUTO_PARK_TAG])) throw new ConsentError(`${name} is not tagged ${AUTO_PARK_TAG}=ON: switch auto-park on first`, 403);
  if (tags["advisor:hands-off"] != null) throw new ConsentError(`${name} is tagged advisor:hands-off`, 409);
  if (row.pool_kind) throw new ConsentError(`${name} is a member of a ${row.pool_kind} pool: its controller decides`, 409);
  const state = inst.State?.Name || "unknown";
  if (action === "stop" && state !== "running") throw new ConsentError(`${name} is ${state}, not running`, 409);
  if (action === "start" && state !== "stopped") throw new ConsentError(`${name} is ${state}, not stopped`, 409);
  const dns = hasEip ? [] : action === "stop" ? recordsNamingIp(inst.PublicIpAddress) : recordsForStart(instanceId);
  const names = [...new Set(dns.map((r) => r.name))];
  const p: Proposal = {
    kind: SCHEDULE_KIND, resource: instanceId, resource_name: row.name, region, account_id: row.account_id ?? null,
    dedupe: `${SCHEDULE_KIND}:${instanceId}:${action}:manual:${new Date().toISOString().slice(0, 16)}`,
    title: `${action} ${name} (${row.instance_type || inst.InstanceType || "ec2"}): requested by ${by} on the page`,
    reason: `Tagged ${AUTO_PARK_TAG}=ON; ${by} pressed ${action === "stop" ? "Stop" : "Start"} on the Inventory page.${hasEip ? " The Elastic IP keeps the address." : action === "start" ? (names.length ? ` No Elastic IP: ${names.join(", ")} will be pointed at the new public address.` : " No Elastic IP: the public address changes; no A record in the account's zones names the old one.") : (names.length ? ` No Elastic IP: the start re-points ${names.join(", ")}.` : " No Elastic IP: the public address changes when it starts again.")}`,
    before: { state }, after: { state: action === "stop" ? "stopped" : "running" },
    facts: { kind: "ec2", manual: true, by, elastic_ip: hasEip, public_ip: inst.PublicIpAddress ?? null, dns_records: dns.length ? dns : null, monthly_usd: row.monthly_usd },
    rollback: `the opposite call (${action === "stop" ? "start" : "stop"})`,
    est_usd_month: null,
  };
  const rec = recordProposal(p, config.actMode, "manual");
  return applyAction(rec.row.id, "manual");
}

export const consentErrorStatus = (e: unknown): number => (e instanceof ConsentError ? e.status : 400);

// ---- a person's one-time credentials ----------------------------------------------------------------------------------

/**
 * Any row the actuator cannot or may not do can be done by a person from the page with temporary credentials of
 * their own (it began with Beanstalk tag writes, which run under the caller's rights whatever the operations role):
 * one call, made with those credentials in memory, attributed to their identity on the ledger, and forgotten the
 * moment it returns. The person authorises that one change; the actuator stays as narrow as it is. Long-lived keys are refused (a session
 * token is required; a fifteen-minute session from `aws sts get-session-token` is the token's own lifetime), the
 * call is the row's and nothing else, and the credentials are never logged or stored.
 */
export interface OneTimeCredentials { access_key_id: string; secret_access_key: string; session_token: string }

/** Checks the shape of pasted credentials without using them. Pure. */
export function parseOneTimeCredentials(input: unknown): OneTimeCredentials {
  const o = (input && typeof input === "object" ? input : {}) as Record<string, unknown>;
  const s = (k: string) => (typeof o[k] === "string" ? (o[k] as string).trim() : "");
  const access_key_id = s("access_key_id"), secret_access_key = s("secret_access_key"), session_token = s("session_token");
  if (!access_key_id || !secret_access_key) throw new ConsentError("paste an access key id and a secret access key", 400);
  if (!/^ASIA[A-Z0-9]{16}$/.test(access_key_id)) throw new ConsentError(/^AKIA/.test(access_key_id) ? "that is a long-lived access key (AKIA…): only temporary credentials are accepted (ASIA…, with a session token)" : "the access key id does not look like a temporary one (ASIA…)", 400);
  if (!session_token || session_token.length < 100) throw new ConsentError("temporary credentials come with a session token; paste it too", 400);
  return { access_key_id, secret_access_key, session_token };
}

/**
 * Any ledger row may be done with a person's own credentials from the page: the credentials are the authorization
 * for that one change, and the row records who gave it. `null` means every kind (kept as a set for the tests and
 * for narrowing later).
 */
export const PERSON_KINDS: ReadonlySet<string> | null = null;

/**
 * Applies (or reverts) one consent row with a person's temporary credentials. The row must be one the actuator
 * could not do (proposed, failed, or applied/verified for a revert). Who did it is read from STS and written on
 * the row; the credentials live in this call's scope only.
 */
export async function runAsPerson(id: number, verb: "apply" | "revert", input: unknown): Promise<ActionRow> {
  const creds = parseOneTimeCredentials(input);
  const row = getAction(id);
  if (!row) throw new ConsentError(`no action #${id}`, 404);
  if (PERSON_KINDS && !PERSON_KINDS.has(row.kind)) throw new ConsentError(`#${id} is a ${row.kind} row: not done with a person's credentials`, 400);
  if (verb === "apply" && !["proposed", "failed", "applied"].includes(row.status)) throw new ConsentError(`#${id} is ${row.status}; only a proposed, failed or still-unverified row is applied`, 409);
  if (verb === "revert" && !["applied", "verified"].includes(row.status)) throw new ConsentError(`#${id} is ${row.status}; only an applied or verified row is reverted`, 409);
  const mod = actionModules().find((m) => m.kind === row.kind);
  if (!mod) throw new ConsentError(`no module for ${row.kind}`, 500);
  if (mod.advance) throw new ConsentError(`${row.kind} is a staged change that runs for minutes to hours after the first call: it runs under the actuator role only (Apply and Revert on the page)`, 409);
  const region = row.region || executorCreds().region;
  const provider: AwsCredentialIdentityProvider = async () => ({ accessKeyId: creds.access_key_id, secretAccessKey: creds.secret_access_key, sessionToken: creds.session_token });
  // who: the identity behind the credentials, for the ledger
  let who = "";
  const sts = new STSClient({ region, credentials: provider });
  try { const me = await sts.send(new GetCallerIdentityCommand({})); who = me.Arn || me.UserId || "?"; }
  catch (e: any) { throw new ConsentError(`the credentials did not identify themselves (sts:GetCallerIdentity): ${String(e?.message || e).slice(0, 160)}`, 401); }
  finally { sts.destroy(); }
  const personCreds: Creds = { read: provider, act: () => provider, region, accounts: [], forAccount: () => ({ account_id: row.account_id ?? "", name: "person", is_parent: true, read: provider, act: () => provider, region }) };
  const trigger = `person:${who}`;
  const p = proposalOf(row);
  try {
    if (verb === "apply") {
      const result = `${await mod.apply(p, personCreds)} (as ${who})`;
      db.prepare("update actions set status = 'applied', mode = 'apply', trigger = ?, result = ?, error = null, applied_at = datetime('now') where id = ?").run(trigger, result, id);
      logEvent({ action_id: id, kind: row.kind, event: "apply", outcome: "applied", trigger, detail: result });
    } else {
      const result = `${await mod.revert(p, personCreds)} (as ${who})`;
      db.prepare("update actions set status = 'reverted', trigger = ?, result = coalesce(result, '') || ' · ' || ?, reverted_at = datetime('now') where id = ?").run(trigger, result, id);
      logEvent({ action_id: id, kind: row.kind, event: "revert", outcome: "reverted", trigger, detail: result });
    }
  } catch (e: any) {
    const error = `as ${who}: ${String(e?.message || e).slice(0, 300)}`;
    if (verb === "apply") db.prepare("update actions set status = 'failed', mode = 'apply', trigger = ?, error = ?, applied_at = datetime('now') where id = ?").run(trigger, error, id);
    logEvent({ action_id: id, kind: row.kind, event: verb, outcome: "failed", trigger, detail: error });
    mirrorActionsInBackground([id]);
    return getAction(id)!;
  }
  // the read-back runs under the advisor's own read credentials; Beanstalk's update takes a minute, so it is usually inconclusive here and lands on the next pass
  if (verb === "apply") { try { await verifyAction(id, undefined, trigger); } catch { /* the next pass reads it back */ } }
  mirrorActionsInBackground([id]);
  return getAction(id)!;
}

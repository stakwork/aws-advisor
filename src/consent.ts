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
import { db } from "./db.js";
import { config } from "./config.js";
import { applyAction, executorCreds, recordProposal, type ActionRow, type Proposal } from "./executor.js";
import { KIND as SCHEDULE_KIND, recordsForStart, recordsNamingIp } from "./actions/schedule_hours.js";

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
    if (before != null && normaliseConsent(before) === r.value) throw new ConsentError(`${row.name || r.id} already carries ${AUTO_PARK_TAG}=${before}`, 409);
    const p: Proposal = {
      kind: CONSENT_KIND, resource: r.id, resource_name: row.name, region, account_id: row.account_id ?? null,
      dedupe: `${CONSENT_KIND}:${r.id}:${r.value}`,
      title: `${row.name || r.id}: ${AUTO_PARK_TAG} ${before ?? "(none)"} → ${r.value}`,
      reason: r.value === "ON" ? `${by} switched auto-park on from the page: the executor may stop this box when it is idle or in its confident quiet hours and start it again before it is needed, re-pointing its DNS records when it has no Elastic IP. Stop and Start on the page work from now on.` : `${by} switched auto-park off from the page: the executor never stops or starts this box until it is switched on again (a box it stopped stays stopped until Start on the page or Revert on the row).`,
      before: { [AUTO_PARK_TAG]: before }, after: { [AUTO_PARK_TAG]: r.value },
      facts: { kind: "ec2", tag: AUTO_PARK_TAG, by, state: inst.State?.Name ?? row.state ?? null },
      rollback: before == null ? `DeleteTags ${AUTO_PARK_TAG}` : `CreateTags ${AUTO_PARK_TAG}=${before}`,
      est_usd_month: null,
    };
    const rec = recordProposal(p, config.actMode, "manual");
    return applyAction(rec.row.id, "manual");
  }
  const region = r.region || creds.region;
  const eb = new ElasticBeanstalkClient({ region, credentials: creds.forAccount(r.account_id || null).read });
  let env; let tags: Record<string, string> = {};
  try {
    env = (await eb.send(new DescribeEnvironmentsCommand({ EnvironmentNames: [r.id], IncludeDeleted: false }))).Environments?.[0];
    if (env?.EnvironmentArn) for (const t of (await eb.send(new ListTagsForResourceCommand({ ResourceArn: env.EnvironmentArn }))).ResourceTags ?? []) if (t.Key) tags[t.Key] = t.Value ?? "";
  } finally { eb.destroy(); }
  if (!env?.EnvironmentId || !env.EnvironmentArn) throw new ConsentError(`environment ${r.id} not found in ${region}`, 404);
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

/** What an environment carries right now: the consent, the band and the operations role, for the switch on the page. */
export async function beanstalkConsent(name: string, region?: string | null, accountId?: string | null): Promise<{ environment_id: string; name: string; consent: string | null; on: boolean; band: string | null; operations_role: string | null; status: string | null }> {
  const creds = executorCreds();
  const eb = new ElasticBeanstalkClient({ region: region || creds.region, credentials: creds.forAccount(accountId || null).read });
  try {
    const env = (await eb.send(new DescribeEnvironmentsCommand({ EnvironmentNames: [name], IncludeDeleted: false }))).Environments?.[0];
    if (!env?.EnvironmentId) throw new ConsentError(`environment ${name} not found in ${region || creds.region}`, 404);
    const tags: Record<string, string> = {};
    if (env.EnvironmentArn) for (const t of (await eb.send(new ListTagsForResourceCommand({ ResourceArn: env.EnvironmentArn }))).ResourceTags ?? []) if (t.Key) tags[t.Key] = t.Value ?? "";
    return { environment_id: env.EnvironmentId, name: env.EnvironmentName ?? name, consent: tags[AUTO_SCALE_TAG] ?? null, on: isOn(tags[AUTO_SCALE_TAG]), band: tags[SCALE_BAND_TAG] ?? null, operations_role: env.OperationsRole ?? null, status: env.Status ?? null };
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

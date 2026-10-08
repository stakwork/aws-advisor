/**
 * Hibernation when parking. Every stop the executor makes (idle parking, office hours, the Stop button) goes through
 * stopOrHibernate: an instance launched with hibernation on (HibernationOptions.Configured) is hibernated, so it comes
 * back in about a minute with its memory, processes and containers as they were; any other instance, or one whose
 * owner chose stop/start (`advisor:hibernate=no`), is stopped as before. The guest must be able to finish it too
 * (src/guest_hibernation.ts): EC2 accepts the hibernate of a box with no agent and then waits in "stopping" for a
 * guest that never answers, so a box the software probe has not seen ready gets a plain stop, with the reason.
 * If EC2 refuses the hibernation (the root volume is too small for the RAM) the call falls back to a plain stop.
 *
 * hibernationStatus is the note on the Auto-park row: ready, or not and why, with the same eligibility rules the
 * relaunch uses (src/actions/ec2_hibernate_migrate.ts skipReason), so the badge and the migration never disagree.
 */
import { DescribeInstancesCommand, DescribeInstanceTypesCommand, EC2Client, StopInstancesCommand, type Instance } from "@aws-sdk/client-ec2";
import { db } from "./db.js";
import { executorCreds } from "./executor.js";
import { HIBERNATE_TAG, NO_HIBERNATE, candidateFor, skipReason } from "./actions/ec2_hibernate_migrate.js";
import { explainRefusal } from "./autopark_grant.js";
import { guestHibernation, type GuestHibernation } from "./guest_hibernation.js";

const tagOf = (i: Instance | undefined, key: string) => i?.Tags?.find((t) => t.Key === key)?.Value ?? null;

/** Whether a stop of this instance should hibernate it: launched for it, not opted out, and the guest can finish it. Pure. */
export function shouldHibernate(inst: Pick<Instance, "HibernationOptions" | "Tags"> | undefined, guest: GuestHibernation | null): boolean {
  return Boolean(inst?.HibernationOptions?.Configured) && tagOf(inst as Instance, HIBERNATE_TAG) !== NO_HIBERNATE && guest?.ready === true;
}

export interface StopResult { state: string; hibernated: boolean; line: string }

/**
 * Stops one instance, hibernating it when it can be; never throws on a refused hibernation, only on a refused stop.
 * `ec2` carries the actuator's credentials (the stop); `reader` the read credentials for the look at the instance
 * (the actuator role has no Describe rights), or the instance as already read. `guest` defaults to what the software
 * probe saw of the box.
 */
export async function stopOrHibernate(ec2: EC2Client, instanceId: string, reader: EC2Client | Instance, guest: GuestHibernation = guestHibernation(instanceId)): Promise<StopResult> {
  let known: Instance | undefined;
  if (reader instanceof EC2Client) {
    try { known = (await reader.send(new DescribeInstancesCommand({ InstanceIds: [instanceId] }))).Reservations?.[0]?.Instances?.[0]; }
    catch { known = undefined; /* unknown: a plain stop, as before */ }
  } else known = reader;
  if (shouldHibernate(known, guest)) {
    try {
      const r = await ec2.send(new StopInstancesCommand({ InstanceIds: [instanceId], Hibernate: true }));
      const state = r.StoppingInstances?.[0]?.CurrentState?.Name || "stopping";
      return { state, hibernated: true, line: `StopInstances (hibernate): ${state}` };
    } catch (e: any) {
      const why = `${e?.name || "error"}: ${String(e?.message || e).slice(0, 120)}`;
      let r;
      try { r = await ec2.send(new StopInstancesCommand({ InstanceIds: [instanceId] })); } catch (e2) { throw explainRefusal(e2, instanceId); }
      const state = r.StoppingInstances?.[0]?.CurrentState?.Name || "stopping";
      return { state, hibernated: false, line: `StopInstances: ${state} (hibernation refused, ${why}; stopped instead)` };
    }
  }
  let r;
  try { r = await ec2.send(new StopInstancesCommand({ InstanceIds: [instanceId] })); } catch (e) { throw explainRefusal(e, instanceId); }
  const state = r.StoppingInstances?.[0]?.CurrentState?.Name || "stopping";
  const why = !known?.HibernationOptions?.Configured ? ""
    : tagOf(known, HIBERNATE_TAG) === NO_HIBERNATE ? ` (${HIBERNATE_TAG}=${NO_HIBERNATE}: stop/start chosen)`
    : ` (launched with hibernation, but not hibernated: ${guest.reason})`;
  return { state, hibernated: false, line: `StopInstances: ${state}${why}` };
}

export interface HibernationStatus {
  instance_id: string;
  /** ready: launched with hibernation on and the guest can finish it; guest_not_ready / guest_unknown: launched for it, but the guest cannot (reason) or was not read yet, so parking stops it; chosen_stop: ready but the owner keeps stop/start; can_migrate: a relaunch would make it ready; cannot: the reason says why; migrating: a relaunch is under way. */
  status: "ready" | "guest_not_ready" | "guest_unknown" | "chosen_stop" | "can_migrate" | "cannot" | "migrating" | "kept_stop";
  configured: boolean; tag: string | null; reason: string | null; ram_gib: number | null; instance_type: string | null; checked_at: string;
}

const cache = new Map<string, { at: number; v: HibernationStatus }>();
const TTL_MS = 10 * 60_000;

/** Whether an instance hibernates when parked, and if not whether it could; read from EC2, kept ten minutes. */
export async function hibernationStatus(instanceId: string, opts: { fresh?: boolean } = {}): Promise<HibernationStatus | null> {
  const hit = cache.get(instanceId);
  if (hit && !opts.fresh && Date.now() - hit.at < TTL_MS) return hit.v;
  const row = db.prepare("select account_id, region, pool_kind from inventory_ec2 where instance_id = ?").get(instanceId) as { account_id: string | null; region: string | null; pool_kind: string | null } | undefined;
  if (!row) return null;
  const creds = executorCreds();
  const acct = creds.forAccount(row.account_id || null);
  const ec2 = new EC2Client({ region: row.region || acct.region || creds.region, credentials: acct.read });
  try {
    let inst: Instance | undefined;
    try { inst = (await ec2.send(new DescribeInstancesCommand({ InstanceIds: [instanceId] }))).Reservations?.[0]?.Instances?.[0]; }
    catch (e: any) { if (/InvalidInstanceID/.test(String(e?.name || e?.message))) return null; throw e; }
    if (!inst) return null;
    const t = inst.InstanceType ? (await ec2.send(new DescribeInstanceTypesCommand({ InstanceTypes: [inst.InstanceType as any] }))).InstanceTypes?.[0] : undefined;
    const guest = guestHibernation(instanceId);
    const c = { ...candidateFor(inst, t, row.pool_kind, instanceId), guest_reason: guest.ready === false ? guest.reason : null };
    const tag = c.tag_value;
    let status: HibernationStatus["status"]; let reason: string | null = null;
    if (c.configured && tag === NO_HIBERNATE) status = "chosen_stop";
    else if (c.configured) { status = guest.ready === true ? "ready" : guest.ready === false ? "guest_not_ready" : "guest_unknown"; reason = guest.reason; }
    else if (c.in_flight) status = "migrating";
    else if (tag === NO_HIBERNATE) status = "kept_stop";
    else {
      // eligibility as if the owner had asked for a migration with downtime (the live one adds only "must be running")
      reason = skipReason({ ...c, mode: "stop", tag_value: "stop" });
      status = reason ? "cannot" : "can_migrate";
    }
    const v: HibernationStatus = { instance_id: instanceId, status, configured: c.configured, tag, reason, ram_gib: c.ram_gib, instance_type: inst.InstanceType ?? null, checked_at: new Date().toISOString() };
    cache.set(instanceId, { at: Date.now(), v });
    return v;
  } finally { ec2.destroy(); }
}

/** Forgets a cached status (after the owner's choice changed the tag). */
export const forgetHibernationStatus = (instanceId: string) => cache.delete(instanceId);

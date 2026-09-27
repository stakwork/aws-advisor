/**
 * Unattached Elastic IPs released, once a person approved the recommendation. The eip_unattached rule files one
 * per allocated address with no association (3.65 USD a month each); the recommendation is tier approve because
 * releasing loses the address, and something outside the account (a DNS record, a customer's allow-list) may
 * still point at it. Approving it is the decision; the executor releases the address, but only after announcing
 * it in the Sphinx chat and waiting ACT_DELETE_GRACE_HOURS, and only while the address is still unattached when
 * the pass looks. Revert is the recovery path AWS offers: AllocateAddress with the same address works while
 * nobody else has been allocated it; after that the address is gone and the revert says so.
 */
import { AllocateAddressCommand, DescribeAddressesCommand, EC2Client, ReleaseAddressCommand, type Address } from "@aws-sdk/client-ec2";
import { config } from "../config.js";
import { approvedRecs, markRecommendationsDone, type ActionModule, type Creds, type Proposal } from "../executor.js";

export const KIND = "eip_release" as const;
export const ACTION_TYPES = ["release_eip"];
/** What an idle address costs a month (0.005 USD an hour, the same figure the rule uses). */
export const EIP_USD_MONTH = 3.65;

export interface EipFacts {
  allocation_id: string; public_ip: string | null; associated: boolean; association_id: string | null; instance_id: string | null;
  network_interface_id: string | null; domain: string | null; network_border_group: string | null; hands_off: boolean; name: string | null;
}

const tagOf = (a: Address, key: string) => a.Tags?.find((t) => t.Key === key)?.Value ?? null;

/** One described address as facts. Pure. */
export function eipFacts(a: Address): EipFacts {
  return {
    allocation_id: a.AllocationId || "", public_ip: a.PublicIp ?? null,
    associated: Boolean(a.AssociationId || a.InstanceId || a.NetworkInterfaceId),
    association_id: a.AssociationId ?? null, instance_id: a.InstanceId ?? null, network_interface_id: a.NetworkInterfaceId ?? null,
    domain: a.Domain ?? null, network_border_group: a.NetworkBorderGroup ?? null,
    hands_off: tagOf(a, "advisor:hands-off") != null, name: tagOf(a, "Name"),
  };
}

/** Why an approved address is left alone this pass, or null when it can be released. Pure. */
export function eipSkipReason(f: EipFacts): string | null {
  if (f.associated) return `associated now (${f.instance_id ? `instance ${f.instance_id}` : f.network_interface_id ? `interface ${f.network_interface_id}` : f.association_id}): somebody is using it`;
  if (f.hands_off) return "tagged advisor:hands-off";
  return null;
}

const notFound = (e: any) => /InvalidAllocationID\.NotFound|InvalidAddress\.NotFound/i.test(String(e?.name || e?.message));

export const eipReleaseAction: ActionModule = {
  kind: KIND,
  label: "Unattached Elastic IPs released, once approved",
  grace_hours: () => config.actDeleteGraceHours,
  announce: true,

  async plan(creds, log) {
    const proposals: Proposal[] = []; const notes: string[] = [];
    const recs = approvedRecs(ACTION_TYPES);
    if (!recs.length) { notes.push("no approved recommendation to release an Elastic IP"); return { proposals, notes }; }
    const byRegion = new Map<string, typeof recs>();
    // Grouped per (account, region): the finding row behind the recommendation carries the account it came from.
    for (const r of recs) { const key = `${r.evidence?.account_id || ""}|${String(r.evidence?.region || creds.region)}`; if (!byRegion.has(key)) byRegion.set(key, []); byRegion.get(key)!.push(r); }
    for (const [key, list] of byRegion) {
      const [account, region] = key.split("|");
      const acct = creds.forAccount(account || null);
      const ec2 = new EC2Client({ region, credentials: acct.read });
      try {
        // One approval per allocation id; describe each on its own so a released one does not fail the whole batch.
        const seen = new Set<string>();
        for (const rec of list) {
          if (seen.has(rec.resource)) continue; seen.add(rec.resource);
          const label = rec.resource_name || String(rec.evidence?.public_ip || rec.resource);
          const skip = (why: string) => { notes.push(`${label}: ${why}`); log(`${label}: ${why}`); };
          let a: Address | undefined;
          try { a = (await ec2.send(new DescribeAddressesCommand({ AllocationIds: [rec.resource] }))).Addresses?.[0]; }
          catch (e: any) {
            if (notFound(e)) { const n = markRecommendationsDone([rec.id], "already released when the executor checked (done by hand); recommendation closed"); skip(`already released; ${n} approved recommendation(s) marked done`); continue; }
            skip(String(e?.message || e).slice(0, 200)); continue;
          }
          if (!a) { const n = markRecommendationsDone([rec.id], "already released when the executor checked (done by hand); recommendation closed"); skip(`already released; ${n} approved recommendation(s) marked done`); continue; }
          const f = eipFacts(a);
          const why = eipSkipReason(f);
          if (why) { skip(why); continue; }
          proposals.push({
            kind: KIND, resource: f.allocation_id, resource_name: f.name || f.public_ip, region, account_id: acct.is_parent ? null : acct.account_id,
            dedupe: `${KIND}:${f.allocation_id}`,
            title: `release Elastic IP ${f.public_ip}${f.name ? ` (${f.name})` : ""}: allocated, attached to nothing`,
            reason: `${rec.title}. Approved as recommendation #${rec.id}${rec.decided_by ? ` by ${rec.decided_by}` : ""}. Still unattached when the executor looked. Releasing loses the address: anything outside AWS that points at ${f.public_ip} (DNS, an allow-list) stops working. Recovery is possible only while nobody else has been allocated it.`,
            before: { associated: false, public_ip: f.public_ip }, after: { released: true },
            facts: { recommendation_id: rec.id, public_ip: f.public_ip, domain: f.domain, network_border_group: f.network_border_group },
            rollback: "recover the same address with AllocateAddress --address (works while nobody else has been allocated it); otherwise a new address",
            est_usd_month: rec.est_monthly_saving ?? EIP_USD_MONTH,
          });
        }
      } catch (e: any) { const m = String(e?.message || e); notes.push(`${region}: ${m.slice(0, 160)}`); log(`${region}: ${m}`); }
      finally { ec2.destroy(); }
    }
    return { proposals, notes };
  },

  async apply(p, creds) {
    const ec2 = new EC2Client({ region: p.region, credentials: creds.act() });
    try { await ec2.send(new ReleaseAddressCommand({ AllocationId: p.resource })); return `ReleaseAddress: ${p.facts.public_ip || p.resource} released`; }
    finally { ec2.destroy(); }
  },

  async verify(p, creds) {
    const ec2 = new EC2Client({ region: p.region, credentials: creds.read });
    try {
      const a = (await ec2.send(new DescribeAddressesCommand({ AllocationIds: [p.resource] }))).Addresses?.[0];
      return a ? { ok: false, note: `${p.resource} still allocated on read-back` } : { ok: true, note: "read back: allocation gone" };
    } catch (e: any) { return notFound(e) ? { ok: true, note: "read back: allocation gone" } : { ok: null, note: String(e?.message || e).slice(0, 120) }; }
    finally { ec2.destroy(); }
  },

  async revert(p, creds) {
    const ip = String(p.facts.public_ip || p.before.public_ip || "");
    if (!ip) throw new Error("the released address is not on the row; allocate a new one by hand");
    const ec2 = new EC2Client({ region: p.region, credentials: creds.act() });
    try {
      const r = await ec2.send(new AllocateAddressCommand({ Domain: "vpc", Address: ip, ...(p.facts.network_border_group ? { NetworkBorderGroup: String(p.facts.network_border_group) } : {}) }));
      return `AllocateAddress: ${ip} recovered as ${r.AllocationId} (not associated with anything yet)`;
    } catch (e: any) {
      const m = String(e?.message || e);
      if (/InvalidAddress|not available|already allocated|AddressLimitExceeded|not found/i.test(m)) throw new Error(`${ip} cannot be recovered (${m.slice(0, 120)}): the address is gone; allocate a new one by hand and update whatever pointed at the old one`);
      throw e;
    } finally { ec2.destroy(); }
  },
};

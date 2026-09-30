/**
 * The consent switch as an executor action: writes `AdvisorAutoPark` on an instance, or `AdvisorAutoScale` and the
 * band `AdvisorScaleBand` on an Elastic Beanstalk environment (src/consent.ts builds the proposal from the page and applies it at once). The
 * pass never plans one of these by itself: a switch is a person's decision. Revert puts the previous value back,
 * or removes the tag when there was none. The actuator policy allows these tag keys and no other.
 */
import { CreateTagsCommand, DeleteTagsCommand, DescribeInstancesCommand, EC2Client } from "@aws-sdk/client-ec2";
import { DescribeEnvironmentsCommand, DescribeEventsCommand, ElasticBeanstalkClient, ListTagsForResourceCommand, UpdateTagsForResourceCommand } from "@aws-sdk/client-elastic-beanstalk";
import { db } from "../db.js";
import type { ActionModule, Creds, Proposal } from "../executor.js";

/** Beanstalk applies a tag change as an environment update; the list shows it only once that is through. A read-back younger than this is inconclusive, not a failure. */
export const BEANSTALK_TAG_SETTLE_MS = 10 * 60_000;

export const KIND = "consent_tag" as const;

const tagOf = (p: Proposal) => String(p.facts.tag);
const wanted = (p: Proposal, side: "before" | "after") => { const v = p[side][tagOf(p)]; return v == null ? null : String(v); };

async function writeTag(p: Proposal, creds: Creds, value: string | null): Promise<string> {
  const tag = tagOf(p);
  if (p.facts.kind === "beanstalk") {
    const eb = new ElasticBeanstalkClient({ region: p.region, credentials: creds.act() });
    try {
      await eb.send(new UpdateTagsForResourceCommand({ ResourceArn: String(p.facts.arn), ...(value == null ? { TagsToRemove: [tag] } : { TagsToAdd: [{ Key: tag, Value: value }] }) }));
      return value == null ? `UpdateTagsForResource: ${tag} removed` : `UpdateTagsForResource: ${tag}=${value}`;
    } finally { eb.destroy(); }
  }
  const ec2 = new EC2Client({ region: p.region, credentials: creds.act() });
  try {
    if (value == null) { await ec2.send(new DeleteTagsCommand({ Resources: [p.resource], Tags: [{ Key: tag }] })); return `DeleteTags: ${tag} removed`; }
    await ec2.send(new CreateTagsCommand({ Resources: [p.resource], Tags: [{ Key: tag, Value: value }] }));
    return `CreateTags: ${tag}=${value}`;
  } finally { ec2.destroy(); }
}

async function readTag(p: Proposal, creds: Creds): Promise<string | null | undefined> {
  const tag = tagOf(p);
  if (p.facts.kind === "beanstalk") {
    const eb = new ElasticBeanstalkClient({ region: p.region, credentials: creds.read });
    try { return (await eb.send(new ListTagsForResourceCommand({ ResourceArn: String(p.facts.arn) }))).ResourceTags?.find((t) => t.Key === tag)?.Value ?? null; } finally { eb.destroy(); }
  }
  const ec2 = new EC2Client({ region: p.region, credentials: creds.read });
  try {
    const i = (await ec2.send(new DescribeInstancesCommand({ InstanceIds: [p.resource] }))).Reservations?.[0]?.Instances?.[0];
    return i ? (i.Tags?.find((t) => t.Key === tag)?.Value ?? null) : undefined;
  } finally { ec2.destroy(); }
}

export const consentTagAction: ActionModule = {
  kind: KIND,
  label: "Consent switches (AdvisorAutoPark, AdvisorAutoScale) and the scale band (AdvisorScaleBand) set from the page",
  async plan() { return { proposals: [], notes: ["switches are flipped from the Inventory page, never planned"] }; },
  async apply(p, creds) { return writeTag(p, creds, wanted(p, "after")); },
  async verify(p, creds) {
    const v = await readTag(p, creds);
    if (v === undefined) return { ok: false, note: "resource not found on read-back" };
    const want = wanted(p, "after");
    if (v === want) return { ok: true, note: `read back: ${tagOf(p)}=${v ?? "(absent)"}` };
    const mismatch = `${tagOf(p)} reads ${v ?? "(absent)"}, expected ${want ?? "(absent)"}`;
    if (p.facts.kind === "beanstalk") {
      // still propagating: the environment is Updating, or the write is recent (the row's applied_at, by dedupe)
      const row = db.prepare("select applied_at from actions where dedupe = ? and status = 'applied' order by id desc limit 1").get(p.dedupe) as { applied_at: string | null } | undefined;
      const appliedAt = row?.applied_at ? new Date(row.applied_at.includes("T") ? row.applied_at : row.applied_at.replace(" ", "T") + "Z").getTime() : null;
      const age = appliedAt == null ? Infinity : Date.now() - appliedAt;
      const eb = new ElasticBeanstalkClient({ region: p.region, credentials: creds.read });
      let status: string | undefined; let failed: string | null = null;
      try {
        status = (await eb.send(new DescribeEnvironmentsCommand({ EnvironmentIds: [p.resource], IncludeDeleted: false }))).Environments?.[0]?.Status;
        // Beanstalk accepts the tag call and applies it as an environment update; when that update fails it says so in the events, not in the call
        const ev = (await eb.send(new DescribeEventsCommand({ EnvironmentId: p.resource, Severity: "ERROR", StartTime: new Date((appliedAt ?? Date.now()) - 60_000), MaxRecords: 20 }))).Events ?? [];
        failed = ev.find((e) => /tag update failed/i.test(e.Message || ""))?.Message ?? null;
      } catch { /* the tag read is the verdict then */ } finally { eb.destroy(); }
      if (failed) {
        const tags = [tagOf(p), want == null ? null : `Key=${tagOf(p)},Value=${want}`];
        const cmd = want == null ? `aws elasticbeanstalk update-tags-for-resource --region ${p.region} --resource-arn ${p.facts.arn} --tags-to-remove ${tags[0]}` : `aws elasticbeanstalk update-tags-for-resource --region ${p.region} --resource-arn ${p.facts.arn} --tags-to-add ${tags[1]}`;
        return { ok: false, note: `${mismatch}; Beanstalk: "${failed}". Beanstalk applies a tag change as an environment update under the caller's own rights (the operations role is not used for it), and the actuator is kept too narrow for that. Write the tag by hand once, the page reads it live: ${cmd}` };
      }
      if (status && status !== "Ready") return { ok: null, note: `${mismatch}; the environment is ${status} (tags land when the update is through)` };
      if (age < BEANSTALK_TAG_SETTLE_MS) return { ok: null, note: `${mismatch}; written ${Math.round(age / 1000)} s ago, Beanstalk is still propagating it` };
    }
    return { ok: false, note: mismatch };
  },
  async revert(p, creds) { const v = wanted(p, "before"); return `${await writeTag(p, creds, v)} (back to ${v ?? "no tag"})`; },
};

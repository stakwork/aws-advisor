/**
 * The consent switch as an executor action: writes `AdvisorAutoPark` on an instance or `AdvisorAutoScale` on an
 * Elastic Beanstalk environment (src/consent.ts builds the proposal from the page and applies it at once). The
 * pass never plans one of these by itself: a switch is a person's decision. Revert puts the previous value back,
 * or removes the tag when there was none. The actuator policy allows these tag keys and no other.
 */
import { CreateTagsCommand, DeleteTagsCommand, DescribeInstancesCommand, EC2Client } from "@aws-sdk/client-ec2";
import { ElasticBeanstalkClient, ListTagsForResourceCommand, UpdateTagsForResourceCommand } from "@aws-sdk/client-elastic-beanstalk";
import type { ActionModule, Creds, Proposal } from "../executor.js";

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
  label: "Consent switches (AdvisorAutoPark, AdvisorAutoScale) flipped from the page",
  async plan() { return { proposals: [], notes: ["switches are flipped from the Inventory page, never planned"] }; },
  async apply(p, creds) { return writeTag(p, creds, wanted(p, "after")); },
  async verify(p, creds) {
    const v = await readTag(p, creds);
    if (v === undefined) return { ok: false, note: "resource not found on read-back" };
    const want = wanted(p, "after");
    return v === want ? { ok: true, note: `read back: ${tagOf(p)}=${v ?? "(absent)"}` } : { ok: false, note: `${tagOf(p)} reads ${v ?? "(absent)"}, expected ${want ?? "(absent)"}` };
  },
  async revert(p, creds) { const v = wanted(p, "before"); return `${await writeTag(p, creds, v)} (back to ${v ?? "no tag"})`; },
};

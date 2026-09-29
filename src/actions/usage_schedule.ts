/**
 * Usage schedules, once approved: the tag that turns a usage profile into office hours.
 *
 * The usage profile (src/usage_profile.ts) files a tier-approve `usage_schedule` recommendation for a running
 * instance whose quiet hours are confident enough: "run it weekdays 06-22 UTC". Approving is the decision, and
 * this action carries it out with one `CreateTags`: `advisor:schedule=<the window>` on the instance. From then
 * on the office-hours action (src/actions/schedule_hours.ts) stops the box outside the window and starts it
 * before the window opens, re-attaching the public address to its DNS records on the way back. Revert removes
 * the tag, and the next office-hours pass leaves the box alone (a stopped box stays stopped until someone starts
 * it; Revert on that row does). The actuator policy lets the role write and delete this one tag key and no other.
 * An instance that already carries the tag, one tagged `advisor:hands-off`, a pool member or a stopped box is
 * left alone and the note says why; a recommendation whose tag is already in place is marked done.
 */
import { CreateTagsCommand, DeleteTagsCommand, DescribeInstancesCommand, EC2Client } from "@aws-sdk/client-ec2";
import { db } from "../db.js";
import { approvedRecs, markRecommendationsDone, type ActionModule, type Proposal } from "../executor.js";
import { SCHEDULE_TAG, parseSchedule, describeSchedule, offHoursPerWeek, HOURS_PER_WEEK } from "./schedule_hours.js";
import { ACTION_TYPE } from "../usage_profile.js";

export const KIND = "usage_schedule" as const;

export const usageScheduleAction: ActionModule = {
  kind: KIND,
  label: "Usage schedules tagged on instances, once approved",

  async plan(creds, log) {
    const proposals: Proposal[] = []; const notes: string[] = [];
    const approved = approvedRecs([ACTION_TYPE]);
    if (!approved.length) { notes.push("no approved usage_schedule recommendation (the daily usage profile files them for instances with confident quiet hours)"); return { proposals, notes }; }
    const byScope = new Map<string, typeof approved>();
    for (const rec of approved) {
      const row = db.prepare("select instance_id, account_id, region, name, monthly_usd, pool_kind, state from inventory_ec2 where instance_id = ?").get(rec.resource) as any;
      if (!row) { notes.push(`${rec.resource}: not in the inventory (recommendation #${rec.id})`); continue; }
      const key = `${row.account_id || ""}|${row.region || creds.region}`;
      if (!byScope.has(key)) byScope.set(key, []);
      byScope.get(key)!.push({ ...rec, row } as any);
    }
    for (const [key, list] of byScope) {
      const [account, region] = key.split("|");
      const ec2 = new EC2Client({ region, credentials: creds.forAccount(account || null).read });
      try {
        const live = new Map<string, { tags: Record<string, string>; state: string }>();
        for (const res of (await ec2.send(new DescribeInstancesCommand({ InstanceIds: list.map((r) => r.resource) }))).Reservations ?? []) for (const i of res.Instances ?? []) live.set(i.InstanceId!, { tags: Object.fromEntries((i.Tags ?? []).map((t) => [t.Key!, t.Value ?? ""])), state: i.State?.Name || "unknown" });
        for (const rec of list as any[]) {
          const name = rec.row.name || rec.resource;
          const skip = (why: string) => { notes.push(`${name}: ${why}`); log(`${name}: ${why}`); };
          const inst = live.get(rec.resource);
          if (!inst) { skip("not found by DescribeInstances"); continue; }
          const schedule = String(rec.evidence?.schedule || "");
          const parsed = parseSchedule(schedule);
          if ("error" in parsed) { skip(`recommendation #${rec.id} carries no usable schedule: ${parsed.error}`); continue; }
          if (inst.tags["advisor:hands-off"] != null) { skip("tagged advisor:hands-off"); continue; }
          if (rec.row.pool_kind) { skip(`member of a ${rec.row.pool_kind} pool: its controller decides`); continue; }
          if (inst.tags[SCHEDULE_TAG] === schedule) { markRecommendationsDone([rec.id], `already tagged ${SCHEDULE_TAG}=${schedule}`); skip(`already tagged ${SCHEDULE_TAG}=${schedule}; recommendation #${rec.id} marked done`); continue; }
          if (inst.tags[SCHEDULE_TAG] != null) { skip(`already tagged ${SCHEDULE_TAG}=${inst.tags[SCHEDULE_TAG]} by someone: not overwritten (remove the tag first if the profile's ${schedule} is wanted)`); continue; }
          if (inst.state !== "running") { skip(`state ${inst.state}: the tag goes on a running box`); continue; }
          const off = offHoursPerWeek(parsed);
          proposals.push({
            kind: KIND, resource: rec.resource, resource_name: rec.row.name, region, account_id: rec.row.account_id ?? null,
            dedupe: `${KIND}:${rec.resource}:${schedule}`,
            title: `${name}: tag ${SCHEDULE_TAG}=${schedule} (${describeSchedule(parsed)}, off ${off} h/week)`,
            reason: `Approved as recommendation #${rec.id}${rec.decided_by ? ` by ${rec.decided_by}` : ""}: ${rec.title}. The tag is the consent the office-hours action reads: outside ${describeSchedule(parsed)} the box is stopped, before the window opens it is started, and on start the A records that named its old public address are pointed at the new one when it has no Elastic IP. Confidence ${rec.evidence?.confidence ?? "?"} over ${rec.evidence?.window_days ?? 28} days.`,
            before: { [SCHEDULE_TAG]: inst.tags[SCHEDULE_TAG] ?? null }, after: { [SCHEDULE_TAG]: schedule },
            facts: { recommendation_id: rec.id, schedule, off_hours_per_week: off, confidence: rec.evidence?.confidence ?? null, quiet_windows: rec.evidence?.quiet_windows ?? null, monthly_usd: rec.row.monthly_usd },
            rollback: `DeleteTags ${SCHEDULE_TAG}: the office-hours action stops following the window (a box it stopped stays stopped until started; Revert on that row does)`,
            est_usd_month: rec.est_monthly_saving ?? (rec.row.monthly_usd ? Math.round(rec.row.monthly_usd * (off / HOURS_PER_WEEK) * 100) / 100 : null),
          });
        }
      } catch (e: any) { const m = String(e?.message || e); notes.push(`${region}: ${m.slice(0, 160)}`); log(`${region}: ${m}`); }
      finally { ec2.destroy(); }
    }
    return { proposals, notes };
  },

  async apply(p, creds) {
    const ec2 = new EC2Client({ region: p.region, credentials: creds.act() });
    try {
      await ec2.send(new CreateTagsCommand({ Resources: [p.resource], Tags: [{ Key: SCHEDULE_TAG, Value: String(p.after[SCHEDULE_TAG]) }] }));
      return `CreateTags: ${SCHEDULE_TAG}=${p.after[SCHEDULE_TAG]} (the office-hours action follows it from the next pass)`;
    } finally { ec2.destroy(); }
  },

  async verify(p, creds) {
    const ec2 = new EC2Client({ region: p.region, credentials: creds.read });
    try {
      const i = (await ec2.send(new DescribeInstancesCommand({ InstanceIds: [p.resource] }))).Reservations?.[0]?.Instances?.[0];
      if (!i) return { ok: false, note: "instance not found on read-back" };
      const v = i.Tags?.find((t) => t.Key === SCHEDULE_TAG)?.Value ?? null;
      return v === String(p.after[SCHEDULE_TAG]) ? { ok: true, note: `read back: ${SCHEDULE_TAG}=${v}` } : { ok: false, note: `tag reads ${v ?? "(absent)"}` };
    } finally { ec2.destroy(); }
  },

  async revert(p, creds) {
    const ec2 = new EC2Client({ region: p.region, credentials: creds.act() });
    try {
      await ec2.send(new DeleteTagsCommand({ Resources: [p.resource], Tags: [{ Key: SCHEDULE_TAG }] }));
      return `DeleteTags ${SCHEDULE_TAG}: no schedule on the box any more`;
    } finally { ec2.destroy(); }
  },
};

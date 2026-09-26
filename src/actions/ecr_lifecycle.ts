/**
 * ECR repositories with no lifecycle policy keep every image ever pushed at 0.10 USD per GB-month; most of the
 * bytes are untagged layers left behind by rebuilds under the same tag. The executor puts one rule on every
 * repository that has no policy: expire untagged images older than ACT_ECR_UNTAGGED_DAYS (30). Tagged images are
 * never touched, and a repository that already has a policy, whatever it says, is left alone. Removing the policy
 * afterwards stops the expiry; images it already deleted do not come back, hence the long default and the row
 * saying so. Repositories whose untagged images are under 1 GB and fewer than twenty are not worth a row.
 */
import { DeleteLifecyclePolicyCommand, DescribeImagesCommand, DescribeRepositoriesCommand, ECRClient, GetLifecyclePolicyCommand, ListTagsForResourceCommand, PutLifecyclePolicyCommand, type Repository } from "@aws-sdk/client-ecr";
import { db } from "../db.js";
import { config } from "../config.js";
import type { ActionModule, Creds, Proposal } from "../executor.js";

export const KIND = "ecr_lifecycle" as const;
export const ECR_USD_GB_MONTH = 0.10;
export const MIN_UNTAGGED_BYTES = 1e9;
export const MIN_UNTAGGED_COUNT = 20;
const MAX_REPOS_PER_PLAN = 300;
const MAX_IMAGE_PAGES = 5;
export const MARKER = "aws-advisor: expire untagged images";

/** The policy text: one rule, untagged images older than `days` expire. */
export const policyText = (days: number) => JSON.stringify({ rules: [{ rulePriority: 1, description: `${MARKER} after ${days} days`, selection: { tagStatus: "untagged", countType: "sinceImagePushed", countUnit: "days", countNumber: days }, action: { type: "expire" } }] });

export interface UntaggedTally { count: number; bytes: number; expiring_count: number; expiring_bytes: number; oldest_at: string | null; sampled: boolean }
/** What the rule would expire now, from the untagged images' push dates and sizes. */
export function tallyUntagged(images: { imageSizeInBytes?: number; imagePushedAt?: Date }[], days: number, sampled = false, now = Date.now()): UntaggedTally {
  const t: UntaggedTally = { count: 0, bytes: 0, expiring_count: 0, expiring_bytes: 0, oldest_at: null, sampled };
  for (const i of images) {
    const size = i.imageSizeInBytes ?? 0; const at = i.imagePushedAt ? new Date(i.imagePushedAt).getTime() : null;
    t.count++; t.bytes += size;
    if (at != null && now - at > days * 86400000) { t.expiring_count++; t.expiring_bytes += size; }
    if (at != null && (!t.oldest_at || at < new Date(t.oldest_at).getTime())) t.oldest_at = new Date(at).toISOString();
  }
  return t;
}

async function hasPolicy(ecr: ECRClient, repo: string): Promise<boolean> {
  try { await ecr.send(new GetLifecyclePolicyCommand({ repositoryName: repo })); return true; }
  catch (e: any) { if (/LifecyclePolicyNotFoundException/i.test(String(e?.name || e?.message))) return false; throw e; }
}

async function untagged(ecr: ECRClient, repo: string, days: number): Promise<UntaggedTally> {
  const images: { imageSizeInBytes?: number; imagePushedAt?: Date }[] = [];
  let token: string | undefined; let pages = 0; let sampled = false;
  do {
    const r = await ecr.send(new DescribeImagesCommand({ repositoryName: repo, filter: { tagStatus: "UNTAGGED" }, maxResults: 1000, nextToken: token }));
    images.push(...(r.imageDetails ?? [])); pages++;
    token = r.nextToken;
    if (token && pages >= MAX_IMAGE_PAGES) { sampled = true; token = undefined; }
  } while (token);
  return tallyUntagged(images, days, sampled);
}

/** The regions the ECR findings mention, plus the configured one. */
function regions(defaultRegion: string): string[] {
  const rows = db.prepare("select distinct region from findings where control_id like '%ecr_repository%' and region is not null and run_id = (select max(run_id) from findings where control_id like '%ecr_repository%')").all() as { region: string }[];
  return [...new Set([defaultRegion, ...rows.map((r) => r.region)])];
}

export const ecrLifecycleAction: ActionModule = {
  kind: KIND,
  label: "ECR repositories without a lifecycle policy get one",

  async plan(creds, log) {
    const proposals: Proposal[] = []; const notes: string[] = [];
    const days = Math.max(1, Math.round(config.actEcrUntaggedDays));
    let scanned = 0, withPolicy = 0, small = 0;
    for (const region of regions(creds.region)) {
      const ecr = new ECRClient({ region, credentials: creds.read });
      try {
        const repos: Repository[] = [];
        let token: string | undefined;
        do { const r = await ecr.send(new DescribeRepositoriesCommand({ maxResults: 1000, nextToken: token })); repos.push(...(r.repositories ?? [])); token = r.nextToken; } while (token);
        for (const repo of repos) {
          const name = repo.repositoryName!;
          if (scanned >= MAX_REPOS_PER_PLAN) break;
          scanned++;
          const skip = (why: string) => { notes.push(`${name}: ${why}`); log(`${name}: ${why}`); };
          try {
            if (await hasPolicy(ecr, name)) { withPolicy++; continue; }
            const t = await untagged(ecr, name, days);
            if (t.bytes < MIN_UNTAGGED_BYTES && t.count < MIN_UNTAGGED_COUNT) { small++; continue; }
            if (repo.repositoryArn) {
              try { if ((await ecr.send(new ListTagsForResourceCommand({ resourceArn: repo.repositoryArn }))).tags?.some((x) => x.Key === "advisor:hands-off")) { skip("tagged advisor:hands-off"); continue; } }
              catch { /* tags unreadable: the policy's Deny still protects a tagged repository */ }
            }
            const gb = (b: number) => (b / 1e9).toFixed(2);
            proposals.push({
              kind: KIND, resource: name, resource_name: name, region,
              dedupe: `${KIND}:${region}:${name}:${days}`,
              title: `${name}: expire untagged images after ${days} days (${t.count}${t.sampled ? "+" : ""} untagged, ${gb(t.bytes)} GB)`,
              reason: `no lifecycle policy; ${t.count}${t.sampled ? "+" : ""} untagged image(s) hold ${gb(t.bytes)} GB${t.oldest_at ? `, the oldest pushed ${t.oldest_at.slice(0, 10)}` : ""}. ${t.expiring_count} of them (${gb(t.expiring_bytes)} GB) are already older than ${days} days and go on the first run; tagged images are never touched. Removing the policy later does not bring deleted images back.`,
              before: { lifecycle_policy: null }, after: { lifecycle_policy: `expire untagged after ${days} days` },
              facts: { untagged: t, days, repository_arn: repo.repositoryArn ?? null },
              rollback: "delete the lifecycle policy (images it already expired are gone)",
              est_usd_month: Math.round((t.expiring_bytes / 1e9) * ECR_USD_GB_MONTH * 100) / 100,
            });
          } catch (e: any) { const m = String(e?.message || e); skip(m.slice(0, 160)); if (/AccessDenied|not authorized/i.test(m)) break; }
        }
        if (scanned >= MAX_REPOS_PER_PLAN && repos.length > MAX_REPOS_PER_PLAN) notes.push(`${region}: ${repos.length - MAX_REPOS_PER_PLAN} repository(ies) wait for a later pass`);
      } catch (e: any) { const m = String(e?.message || e); notes.push(`${region}: ${m.slice(0, 160)}`); log(`${region}: ${m}`); }
      finally { ecr.destroy(); }
    }
    if (!scanned) notes.push("no ECR repository found");
    if (withPolicy) notes.push(`${withPolicy} repository(ies) already have a lifecycle policy`);
    if (small) notes.push(`${small} repository(ies) without a policy hold under 1 GB and fewer than ${MIN_UNTAGGED_COUNT} untagged images: left alone`);
    return { proposals, notes };
  },

  async apply(p, creds) {
    const ecr = new ECRClient({ region: p.region, credentials: creds.act() });
    try { await ecr.send(new PutLifecyclePolicyCommand({ repositoryName: p.resource, lifecyclePolicyText: policyText(Number(p.facts.days)) })); return `PutLifecyclePolicy: untagged images expire after ${p.facts.days} days`; }
    finally { ecr.destroy(); }
  },

  async verify(p, creds) {
    const ecr = new ECRClient({ region: p.region, credentials: creds.read });
    try {
      const r = await ecr.send(new GetLifecyclePolicyCommand({ repositoryName: p.resource }));
      return r.lifecyclePolicyText?.includes(MARKER) ? { ok: true, note: "policy read back" } : { ok: false, note: "a different policy is on the repository" };
    } catch (e: any) { return /LifecyclePolicyNotFoundException/i.test(String(e?.name || e?.message)) ? { ok: false, note: "no policy on read-back" } : { ok: null, note: String(e?.message || e).slice(0, 120) }; }
    finally { ecr.destroy(); }
  },

  async revert(p, creds) {
    const ecr = new ECRClient({ region: p.region, credentials: creds.act() });
    try { await ecr.send(new DeleteLifecyclePolicyCommand({ repositoryName: p.resource })); return "lifecycle policy deleted; images it already expired are gone"; }
    finally { ecr.destroy(); }
  },
};

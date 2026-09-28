/**
 * The last word on a log group nothing claimed: Jev (purpose log_group_owner) picks the system a group belongs
 * to from the group's name and tags and the account's systems, or says none. Only groups the evidence rules of
 * src/log_attribution.ts left unattributed get here, in batches, and each answer is cached in log_group_jev until
 * the group's name, tags or the set of systems change (state hash) or 30 days pass, so the knowledge mirror, which
 * runs after every collection run, costs nothing on a quiet account. An answer counts only above
 * JEV_ATTRIBUTION_THRESHOLD; a weaker one is kept on the node as a hint, never as the owner.
 */
import { createHash } from "node:crypto";
import { choice } from "@typesafe-ai/sdk";
import { db } from "./db.js";
import { askJev, chunk, jevEnabled } from "./jev.js";
import type { AttributableSystem } from "./log_attribution.js";

db.exec(`create table if not exists log_group_jev (
  name text primary key, owner text, confidence real, probabilities text, state_hash text not null, model text, call_id integer, decided_at text not null
)`);

export const JEV_ATTRIBUTION_THRESHOLD = 0.6;
export const JEV_CACHE_DAYS = 30;
export const JEV_BATCH_SIZE = 8;
/** How many systems a question offers: the rule candidates first, then compute systems, then the rest. */
export const JEV_MAX_OPTIONS = 50;

export interface JevGroupInput { name: string; tags: Record<string, string> | null; candidates: string[]; how: string }
export interface JevSystemInput extends AttributableSystem { region?: string | null; archetype?: string | null; member_count?: number }
export interface JevLogAttribution { owner: string | null; confidence: number; probabilities: Record<string, number>; decided_at: string; cached: boolean }

const COMPUTE = new Set(["pool", "instance", "eks_cluster", "lambda"]);
const describeSystem = (s: JevSystemInput) => {
  const bits = [s.kind.replace("_", " "), s.region || null, s.archetype ? `archetype ${s.archetype}` : null, s.member_count != null ? `${s.member_count} member${s.member_count === 1 ? "" : "s"}` : null,
    s.aliases?.length ? `also known as ${s.aliases.slice(0, 4).join(", ")}` : null, s.members.length && s.kind !== "lambda" ? `ids ${s.members.slice(0, 3).join(", ")}` : null].filter(Boolean);
  return `${s.name}: ${bits.join(", ")}`;
};

/** The options one group is offered, in the order that matters: the closest by the rules, then compute systems, then the rest, capped; plus none. Pure. */
export function jevOptionsFor(g: JevGroupInput, systems: JevSystemInput[]): Record<string, string> {
  const byId = new Map(systems.map((s) => [s.id, s]));
  const first = g.candidates.map((c) => c.replace(/ \(.*$/, "")).filter((id) => byId.has(id));
  const ordered = [...first, ...systems.filter((s) => COMPUTE.has(s.kind) && !first.includes(s.id)).map((s) => s.id), ...systems.filter((s) => !COMPUTE.has(s.kind) && !first.includes(s.id)).map((s) => s.id)];
  const out: Record<string, string> = {};
  for (const id of ordered.slice(0, JEV_MAX_OPTIONS)) out[id] = describeSystem(byId.get(id)!);
  out.none = "no system in this account writes this group, a shared or platform group, or the name and tags do not say";
  return out;
}

/** The facts Jev sees for one group: its name split into its path, its tags, what the rules found. */
export function jevGroupState(g: JevGroupInput) {
  return { log_group: g.name, path: g.name.split("/").filter(Boolean), tags: g.tags && Object.keys(g.tags).length ? g.tags : undefined, rules_said: g.how, rules_closest: g.candidates.length ? g.candidates : undefined };
}

/** Name, tags, candidates and the set of systems offered: any change re-asks. */
export const jevStateHash = (g: JevGroupInput, options: Record<string, string>) => createHash("sha1").update(JSON.stringify([g.name, g.tags, Object.keys(options)])).digest("hex").slice(0, 16);

/** A Jev choice as an attribution: the owner only above the threshold and never "none". Pure. */
export function applyJevAnswer(a: { choice?: unknown; confidence?: unknown; probabilities?: unknown } | null | undefined): { owner: string | null; confidence: number; probabilities: Record<string, number> } | null {
  if (!a || typeof a.choice !== "string" || typeof a.confidence !== "number") return null;
  const probabilities = a.probabilities && typeof a.probabilities === "object" ? Object.fromEntries(Object.entries(a.probabilities as Record<string, unknown>).map(([k, v]) => [k, Number(v)])) : {};
  return { owner: a.choice !== "none" && a.confidence >= JEV_ATTRIBUTION_THRESHOLD ? a.choice : null, confidence: a.confidence, probabilities };
}

const cached = db.prepare("select owner, confidence, probabilities, state_hash, decided_at from log_group_jev where name = ?");
const upsert = db.prepare(`insert into log_group_jev(name, owner, confidence, probabilities, state_hash, model, call_id, decided_at) values (?, ?, ?, ?, ?, ?, ?, ?)
  on conflict(name) do update set owner = excluded.owner, confidence = excluded.confidence, probabilities = excluded.probabilities, state_hash = excluded.state_hash, model = excluded.model, call_id = excluded.call_id, decided_at = excluded.decided_at`);

/**
 * Attributes the given unattributed groups with Jev, cache first. Returns an answer for every group Jev (or the
 * cache) could speak for; a group without an entry stays as the rules left it. No-op without a key beyond the cache.
 */
export async function jevAttributeLogGroups(groups: JevGroupInput[], systems: JevSystemInput[], opts: { force?: boolean; max?: number } = {}): Promise<Map<string, JevLogAttribution>> {
  const out = new Map<string, JevLogAttribution>();
  if (!groups.length || !systems.length) return out;
  const stale: { g: JevGroupInput; options: Record<string, string>; hash: string }[] = [];
  for (const g of groups) {
    const options = jevOptionsFor(g, systems);
    const hash = jevStateHash(g, options);
    const row = cached.get(g.name) as any;
    const fresh = row && !opts.force && row.state_hash === hash && new Date(row.decided_at).getTime() > Date.now() - JEV_CACHE_DAYS * 86400000;
    if (fresh) { let p = {}; try { p = JSON.parse(row.probabilities || "{}"); } catch { /* none */ } out.set(g.name, { owner: row.owner ?? null, confidence: Number(row.confidence ?? 0), probabilities: p, decided_at: row.decided_at, cached: true }); }
    else stale.push({ g, options, hash });
  }
  if (!jevEnabled() || !stale.length) return out;
  const budget = stale.slice(0, opts.max ?? 80);
  for (const batch of chunk(budget, JEV_BATCH_SIZE)) {
    const state: Record<string, unknown> = {};
    let questions: Record<string, ReturnType<typeof choice>> = {};
    batch.forEach((x, i) => {
      state[`g${i}`] = jevGroupState(x.g);
      questions = { ...questions, [`g${i}_owner`]: choice(`Consider only the log group under log_groups.g${i} (ignore the others). Which system in this AWS account writes it? Judge from its name and path, its tags and the systems' names, ids and aliases; a CloudWatch agent or application usually names the group after the service, environment or cluster that emits it. Pick none when nothing ties it to one system.`, x.options) };
    });
    const res = await askJev({ log_groups: state, note: "The systems are the account's autoscaled pools, standalone instances, EKS clusters, Lambda functions, RDS clusters and instances, ElastiCache groups and NAT gateways, as the advisor's knowledge graph holds them." }, questions, { purpose: "log_group_owner" });
    if (!res) continue;
    const now = new Date().toISOString();
    db.transaction(() => {
      batch.forEach((x, i) => {
        const a = applyJevAnswer(res.answers[`g${i}_owner`] as any);
        if (!a) return;
        upsert.run(x.g.name, a.owner, a.confidence, JSON.stringify(a.probabilities), x.hash, res.model, res.call_id, now);
        out.set(x.g.name, { ...a, decided_at: now, cached: false });
      });
    })();
    console.log(`[jev] log_group_owner: ${batch.length} groups judged, ${batch.filter((x) => out.get(x.g.name)?.owner).length} attributed (${res.latency_ms} ms, ${res.usage.input_tokens}+${res.usage.output_tokens} tokens)`);
  }
  return out;
}

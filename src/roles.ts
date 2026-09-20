import { createHash } from "node:crypto";
import { choice, noul } from "@typesafe-ai/sdk";
import { db } from "./db.js";
import { askJev, chunk, jevEnabled } from "./jev.js";
import { latestProbe } from "./ssm.js";
import { poolOf } from "./pools.js";

/**
 * Resource classification with Jev (purpose resource_role). For the EC2 instances a rules batch looks at
 * (stopped and idle instances) and for every RDS instance, one batched call per run asks, per resource, what
 * it is for (`role`) and whether its name or tags say it is deliberately kept (`protected`). The answers are
 * cached in resource_roles for 7 days or until the name/tags/type change (state hash), and src/rules.ts
 * consumes them: a protected resource is report-only, a blockchain node or a cache is not "idle" because its
 * CPU is low, a dev/test box gets a scheduler suggestion. Without a key the rules fall back to their regex.
 */

export const ROLE_OPTIONS = {
  blockchain_node: "a bitcoind, lnd, CLN or similar chain/lightning node: syncs blocks, holds a wallet or channels, naturally low on CPU",
  database: "a database server: postgres, mysql, mongo, redis as a primary store, an RDS instance",
  cache_or_queue: "a cache or message broker: redis/memcached cache, MQTT, RabbitMQ, Kafka; low CPU by nature",
  web_or_api: "a web server, API, application backend or frontend serving users",
  batch_or_worker: "a batch job runner, worker, ML or data-processing box, session generator",
  ci_or_build: "a CI runner, build box or AMI/image builder",
  bastion_or_vpn: "a bastion host, VPN server, jump box or peer/relay",
  dev_or_test: "a developer's own box, a staging/test/demo environment, a personal swarm",
  k8s_node: "a Kubernetes/EKS worker or system node managed by a node group or autoscaler",
  unknown: "the name, tags and processes do not say",
} as const;
export type Role = keyof typeof ROLE_OPTIONS;

export const ROLE_CACHE_DAYS = 7;
export const ROLE_BATCH_SIZE = 40;
/** Thresholds src/rules.ts applies. */
export const PROTECTED_THRESHOLD = 0.7;
export const ROLE_CONFIDENCE_THRESHOLD = 0.7;

export interface ResourceFacts {
  resource_id: string;
  kind: "ec2" | "rds";
  name: string | null;
  tags: Record<string, string>;
  instance_type: string | null;
  platform: string | null;
  launch_time: string | null;
  state: string | null;
  top_processes?: string[];
  containers?: string[];
  volume_sizes_gb?: number[];
  description?: string | null;
}

export interface ResourceRole {
  resource_id: string;
  role: Role;
  role_confidence: number;
  protected_prob: number;
  evidence: { role_probabilities: Record<string, number>; state: Record<string, unknown>; model: string; call_id: number };
  updated_at: string;
}

const safeJson = (s: unknown) => { if (typeof s !== "string") return s ?? null; try { return JSON.parse(s); } catch { return null; } };
const ageDays = (iso: string | null | undefined) => (iso ? Math.round((Date.now() - new Date(iso).getTime()) / 86400000) : null);

/** The facts Jev sees for one resource: identity and usage, no judgment. */
export function roleState(r: ResourceFacts) {
  const tags = Object.fromEntries(Object.entries(r.tags || {}).filter(([k]) => k !== "Name").slice(0, 20));
  const pool = r.kind === "ec2" ? poolOf(r.tags) : null;
  return {
    kind: r.kind === "rds" ? "RDS database instance" : "EC2 instance",
    name: r.name, description: r.description ?? undefined, tags,
    pool: pool ? { kind: pool.kind, name: pool.name, note: pool.note } : undefined,
    instance_type: r.instance_type, platform: r.platform, state: r.state,
    launch_age_days: ageDays(r.launch_time),
    top_processes: r.top_processes?.length ? r.top_processes : "no probe on file",
    attached_volume_sizes_gb: r.volume_sizes_gb?.length ? r.volume_sizes_gb : undefined,
  };
}

/** Changes to what Jev would see (name, tags, type, platform, description) invalidate the cache. */
export const roleStateHash = (r: ResourceFacts) => createHash("sha1").update(JSON.stringify([r.kind, r.name, r.tags, r.instance_type, r.platform, r.description ?? null])).digest("hex").slice(0, 16);

/** Questions for one resource of a batch. Each names its key in the state: unscoped questions make Jev answer the batch as a whole. */
export const roleQuestions = (prefix: string) => ({
  [`${prefix}_role`]: choice(`Consider only the resource under resources.${prefix} (ignore the others). What is it for?`, ROLE_OPTIONS),
  [`${prefix}_protected`]: noul(`Consider only the resource under resources.${prefix} (ignore the others). Its name, tags or description indicate it is deliberately kept and must not be deleted or stopped`),
});

/** Cached role for one resource id, or null. */
export function resourceRole(resourceId: string): ResourceRole | null {
  const row = db.prepare("select resource_id, role, role_confidence, protected_prob, evidence, updated_at from resource_roles where resource_id = ?").get(resourceId) as any;
  return row ? { ...row, evidence: safeJson(row.evidence) } : null;
}

const upsertRole = db.prepare(`
  insert into resource_roles(resource_id, role, role_confidence, protected_prob, evidence, state_hash, updated_at) values (?, ?, ?, ?, ?, ?, datetime('now'))
  on conflict(resource_id) do update set role = excluded.role, role_confidence = excluded.role_confidence, protected_prob = excluded.protected_prob,
    evidence = excluded.evidence, state_hash = excluded.state_hash, updated_at = excluded.updated_at`);

/**
 * Classifies resources, serving fresh cache entries and asking Jev for the rest in batches of up to 40.
 * Returns what is known (cached or freshly answered), keyed by resource id; a resource Jev could not answer
 * for is absent, and the rules then fall back to their regex. No-op without a key (returns the cache only).
 */
export async function classifyResources(resources: ResourceFacts[], opts: { force?: boolean } = {}): Promise<Record<string, ResourceRole>> {
  const out: Record<string, ResourceRole> = {};
  const stale: ResourceFacts[] = [];
  const seen = new Set<string>();
  const cached = db.prepare("select resource_id, role, role_confidence, protected_prob, evidence, state_hash, updated_at from resource_roles where resource_id = ?");
  for (const r of resources) {
    if (seen.has(r.resource_id)) continue;
    seen.add(r.resource_id);
    const row = cached.get(r.resource_id) as any;
    const fresh = row && !opts.force && row.state_hash === roleStateHash(r) && new Date(row.updated_at.replace(" ", "T") + "Z").getTime() > Date.now() - ROLE_CACHE_DAYS * 86400000;
    if (fresh) out[r.resource_id] = { ...row, evidence: safeJson(row.evidence) };
    else stale.push(r);
  }
  if (!jevEnabled() || !stale.length) return out;

  for (const batch of chunk(stale, ROLE_BATCH_SIZE)) {
    const state: Record<string, unknown> = {};
    let questions: Record<string, ReturnType<typeof roleQuestions>[string]> = {};
    batch.forEach((r, i) => { state[`r${i}`] = roleState(r); questions = { ...questions, ...roleQuestions(`r${i}`) }; });
    const res = await askJev({ resources: state }, questions, { purpose: "resource_role" });
    if (!res) continue;
    db.transaction(() => {
      batch.forEach((r, i) => {
        const role = res.answers[`r${i}_role`] as any;
        const prot = res.answers[`r${i}_protected`] as any;
        if (role?.type !== "choice" || prot?.type !== "noul") return;
        const rec: ResourceRole = {
          resource_id: r.resource_id, role: role.choice as Role, role_confidence: role.confidence, protected_prob: prot.noul,
          evidence: { role_probabilities: role.probabilities, state: state[`r${i}`] as Record<string, unknown>, model: res.model, call_id: res.call_id },
          updated_at: new Date().toISOString().replace("T", " ").slice(0, 19),
        };
        upsertRole.run(rec.resource_id, rec.role, rec.role_confidence, rec.protected_prob, JSON.stringify(rec.evidence), roleStateHash(r), );
        out[r.resource_id] = rec;
      });
    })();
    console.log(`[jev] resource_role: ${batch.length} resources classified (${res.latency_ms} ms, ${res.usage.input_tokens}+${res.usage.output_tokens} tokens)`);
  }
  return out;
}

// ---- facts from the inventory -----------------------------------------------------------------------------

/** EC2 facts from inventory_ec2 (with the latest probe's top processes); a fallback row for instances the inventory has not seen yet. */
export function ec2Facts(instanceIds: string[], fallback: Record<string, { name?: string | null; instance_type?: string | null; launched?: string | null; state?: string | null }> = {}): ResourceFacts[] {
  if (!instanceIds.length) return [];
  const rows = db.prepare(`select instance_id, name, instance_type, state, platform, launch_time, snapshot from inventory_ec2 where instance_id in (${instanceIds.map(() => "?").join(",")})`).all(...instanceIds) as any[];
  const byId = new Map(rows.map((r) => [r.instance_id, r]));
  return instanceIds.map((id) => {
    const r = byId.get(id);
    const snap = r ? safeJson(r.snapshot) || {} : {};
    const probe = latestProbe(id);
    const procs = probe ? [...new Set([...probe.data.top_cpu, ...probe.data.top_mem].map((p) => p.command))].slice(0, 8) : [];
    const containers = probe?.data.containers?.length ? probe.data.containers.filter((c) => c.state === "running").slice(0, 12).map((c) => `${c.name} (${c.image})`) : undefined;
    const fb = fallback[id] || {};
    return {
      resource_id: id, kind: "ec2" as const,
      name: r?.name ?? fb.name ?? null, tags: snap.tags || {},
      instance_type: r?.instance_type ?? fb.instance_type ?? null, platform: r?.platform ?? null,
      launch_time: r?.launch_time ?? fb.launched ?? null, state: r?.state ?? fb.state ?? null,
      top_processes: procs, volume_sizes_gb: (snap.storage?.volumes || []).map((v: any) => Number(v.size)).filter((n: number) => Number.isFinite(n)),
      containers,
    };
  });
}

/** Every RDS instance the inventory currently sees. */
export function rdsFacts(): ResourceFacts[] {
  const rows = db.prepare("select db_instance_identifier, class, engine, engine_version, status, created, cluster, storage_gb, snapshot from inventory_rds where gone = 0").all() as any[];
  return rows.map((r) => {
    const snap = safeJson(r.snapshot) || {};
    return {
      resource_id: r.db_instance_identifier, kind: "rds" as const, name: r.db_instance_identifier, tags: snap.tags || {},
      instance_type: r.class, platform: `${r.engine} ${r.engine_version || ""}`.trim(), launch_time: r.created, state: r.status,
      description: [r.cluster ? `member of cluster ${r.cluster}` : null, snap.identity?.deletion_protection ? "deletion protection on" : null, r.storage_gb ? `${r.storage_gb} GB allocated` : null].filter(Boolean).join("; ") || null,
    };
  });
}

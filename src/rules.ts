/**
 * Deterministic recommendations. These are the cheap, well-understood cases; the agent layer
 * (repo2graph) ranks and enriches on top of them and can add its own.
 */
import { EC2_GRAVITON_CONTROL, GravitonEc2Fact, GravitonFacts, LAMBDA_ARM_DISCOUNT, LAMBDA_GRAVITON_CONTROL, RDS_GRAVITON_CONTROL, ec2ArmEquivalent, gravitonPriceKey, gravitonSaving, k8sPoolOf, rdsArmEquivalent } from "./graviton.js";
import { playbookFor, stepsSentence } from "./playbooks.js";
import { poolOf } from "./pools.js";
import type { RdsLoadSummary } from "./rds_load.js";

export type Tier = "auto" | "approve" | "report";

export interface RecInput {
  rule: string;
  title: string;
  resource: string;
  resourceName?: string;
  actionType: string;
  estMonthlySaving: number | null;
  tier: Tier;
  confidence: number;
  rationale: string;
  evidence: unknown;
}

/** Latest SSM probe per instance id (see src/ssm.ts); optional. */
export interface ProbeFacts {
  collected_at: string;
  memory_used_pct: number;
  memory_total_gb: number;
  memory_used_gb: number;
  load_1m: number;
  cpus: number;
  top_process: string | null;
}

/** Jev's classification of a resource (see src/roles.ts); optional, keyed by resource id. */
export interface RoleFacts {
  role: string;
  role_confidence: number;
  protected_prob: number;
}

/** Roles whose low CPU is by design, so the idle-instance rule must not read it as waste. */
export const NATURALLY_IDLE_ROLES = ["blockchain_node", "cache_or_queue"];
export const PROTECTED_THRESHOLD = 0.7;
export const ROLE_CONFIDENCE_THRESHOLD = 0.7;

/** The regex the stopped-instance rule used before Jev; still the fallback when a resource has no role on file. */
export const protectedNameRegex = /do ?n.?t delete|keep|protect/i;

/** Whether a resource is deliberately kept: Jev's answer when there is one, the name regex otherwise. */
export function isProtected(name: string, role?: RoleFacts): { protected: boolean; source: "jev" | "regex" } {
  if (role) return { protected: role.protected_prob >= PROTECTED_THRESHOLD, source: "jev" };
  return { protected: protectedNameRegex.test(name), source: "regex" };
}

export interface AuroraStat {
  cluster: string;
  region: string;
  storageType: string;
  members: number;
  volumeGb: number;
  ios30d: number;
}

// us-east-1 list prices, USD
const PRICE = {
  gp3PerGbMonth: 0.08,
  snapshotPerGbMonth: 0.05,
  eipPerMonth: 3.65,
  logsStoragePerGbMonth: 0.03,
  auroraStdPerGbMonth: 0.10,
  auroraIoptPerGbMonth: 0.225,
  auroraIoPerMillion: 0.20,
};

const num = (v: unknown) => (v == null ? 0 : Number(v));

export interface RulesContext {
  queryRows: Record<string, any[]>;
  aurora: AuroraStat[];
  /** The load profile per Aurora cluster (src/rds_load.ts), when the hourly pass has one. */
  loads?: Record<string, RdsLoadSummary>;
  probes?: Record<string, ProbeFacts>;
  roles?: Record<string, RoleFacts>;
  /** The Thrifty graviton alarms with their types, prices and Lambda facts (src/graviton_facts.ts); optional. */
  graviton?: GravitonFacts;
}

/**
 * What the load profile adds to an Aurora storage-tier recommendation: the shape, the cache picture and Jev's
 * read, and a confidence that rises when Jev finds the pattern structural and falls when it does not.
 */
export function auroraLoadNote(load: RdsLoadSummary | undefined, base: number): { note: string; confidence: number } {
  if (!load) return { note: "", confidence: base };
  const parts: string[] = [];
  const c = load.capacity;
  if (load.io.reads_per_day != null) parts.push(`${(load.io.reads_per_day / 1e6).toFixed(1)}M reads and ${((load.io.writes_per_day || 0) / 1e6).toFixed(2)}M writes a day over ${load.window_days} days`);
  if (c) parts.push(`${c.configured ? `${c.configured}, ` : ""}${c.avg_acu} ACU on average, at the ceiling ${Math.round(c.pct_time_at_cap * 100)}% of the time, ${c.bursts_per_day} bursts a day${c.cadence ? ` (${c.cadence})` : ""}${c.db_fits_in_cache_at_avg === false ? `; the database does not fit in the buffer cache at that capacity (about ${c.cache_gib_avg} GiB)` : ""}`);
  if (load.io.buffer_cache_hit_pct_avg != null) parts.push(`buffer cache hit ${load.io.buffer_cache_hit_pct_avg}%`);
  let confidence = base;
  const j = load.jev;
  if (j) {
    parts.push(`Jev: ${j.shape.replace(/_/g, " ")}, I/O from ${j.io_cause.replace(/_/g, " ")} (${Math.round(j.io_cause_confidence * 100)}%), structural ${Math.round(j.structural * 100)}%, first lever ${j.lever.replace(/_/g, " ")}`);
    if (j.structural >= 0.7) confidence = Math.round(Math.min(0.9, base + 0.2) * 100) / 100;
    else if (j.structural <= 0.3) confidence = Math.round(Math.max(0.3, base - 0.2) * 100) / 100;
  }
  return { note: parts.length ? ` Load profile: ${parts.join("; ")}.` : "", confidence };
}

export function buildRecommendations(ctx: RulesContext): RecInput[] {
  const out: RecInput[] = [];

  for (const r of ctx.queryRows.stopped_instance_ebs || []) {
    const gb = num(r.ebs_gb);
    const daysStopped = r.stopped_on ? Math.round((Date.now() - new Date(r.stopped_on).getTime()) / 86400000) : 0;
    const name = r.name || r.instance_id;
    const role = ctx.roles?.[r.instance_id];
    const prot = isProtected(name, role);
    const protectedName = prot.protected;
    const protectedNote = protectedName
      ? prot.source === "jev" ? ` Jev reads the name and tags as deliberately kept (${role!.protected_prob.toFixed(2)}), so this is report-only.` : " The name asks not to delete it, so this is report-only."
      : role?.role === "dev_or_test" ? ` Jev classifies it as dev_or_test (${role.role_confidence.toFixed(2)}); if it is still needed now and then, a scheduler that parks it out of hours beats keeping the volumes around.` : "";
    out.push({
      rule: "stopped_instance_ebs",
      title: `Terminate stopped instance ${name} after imaging it (${gb} GB of EBS)`,
      resource: r.instance_id,
      resourceName: name,
      actionType: "terminate_stopped_instance",
      estMonthlySaving: gb * PRICE.gp3PerGbMonth,
      tier: protectedName ? "report" : "approve",
      confidence: protectedName ? 0.3 : daysStopped > 30 ? 0.9 : 0.6,
      rationale: `${name} has been stopped for ${daysStopped} days but still pays for ${gb} GB of gp3 storage. Create an AMI (snapshots are 0.05 USD/GB against 0.08 for the volumes and only bill used blocks), then terminate.${protectedNote}`,
      evidence: role ? { ...r, role } : r,
    });
  }

  for (const r of ctx.queryRows.old_snapshots || []) {
    const gb = num(r.size_gb);
    const orphan = r.volume_exists === false || r.volume_exists === "false";
    out.push({
      rule: "old_snapshot",
      title: `Delete ${orphan ? "orphaned " : ""}snapshot ${r.snapshot_id} (${gb} GB, ${r.created})`,
      resource: r.snapshot_id,
      resourceName: r.description || r.snapshot_id,
      actionType: "delete_snapshot",
      estMonthlySaving: gb * PRICE.snapshotPerGbMonth,
      tier: "approve",
      confidence: orphan ? 0.7 : 0.5,
      rationale: `Snapshot from ${r.created}${orphan ? " whose source volume no longer exists" : ""}. Confirm nothing restores from it before deleting.`,
      evidence: r,
    });
  }

  for (const r of ctx.queryRows.eip_unattached || []) {
    out.push({
      rule: "eip_unattached",
      title: `Release unattached Elastic IP ${r.public_ip}${r.name ? ` (${r.name})` : ""}`,
      resource: r.allocation_id,
      resourceName: r.name || r.public_ip,
      actionType: "release_eip",
      estMonthlySaving: PRICE.eipPerMonth,
      tier: "approve",
      confidence: 0.95,
      rationale: "An allocated but unattached Elastic IP bills every hour. Releasing it loses the address permanently, so it needs a human check that nothing external points at it.",
      evidence: r,
    });
  }

  for (const r of ctx.queryRows.log_groups_no_retention || []) {
    const gb = num(r.stored_gb);
    out.push({
      rule: "log_group_no_retention",
      title: `Set 30-day retention on log group ${r.name}`,
      resource: r.arn || r.name,
      resourceName: r.name,
      actionType: "set_log_retention",
      estMonthlySaving: gb * PRICE.logsStoragePerGbMonth,
      tier: "auto",
      confidence: 0.8,
      rationale: `${gb} GB stored with no expiry. A retention policy stops the growth; the saving shown is only the current storage, the real value is capping future ingestion storage.`,
      evidence: r,
    });
  }

  for (const r of ctx.queryRows.idle_instances || []) {
    // a Batch worker is idle between jobs by design and gone when the queue drains: nothing to right-size
    if (poolOf(typeof r.tags === "string" ? safeTags(r.tags) : r.tags)?.kind === "batch") continue;
    const probe = ctx.probes?.[r.instance_id];
    const role = ctx.roles?.[r.instance_id];
    const name = r.name || r.instance_id;
    // A probe answers the "is it idle on memory too?" question the CPU metric cannot.
    const memIdle = probe ? probe.memory_used_pct < 40 : false;
    const loadIdle = probe ? probe.load_1m < Math.max(0.5, probe.cpus * 0.2) : false;
    let confidence = !probe ? 0.4 : memIdle && loadIdle ? 0.8 : memIdle || loadIdle ? 0.6 : 0.3;
    const probeNote = probe
      ? ` SSM probe on ${probe.collected_at.slice(0, 10)}: memory ${probe.memory_used_pct}% used (${probe.memory_used_gb} of ${probe.memory_total_gb} GB), load ${probe.load_1m} on ${probe.cpus} vCPU${probe.top_process ? `, busiest process ${probe.top_process}` : ""}.${memIdle && loadIdle ? " Memory and load confirm it is idle." : memIdle ? " Memory is low but the load is not; check what runs there." : " Memory is in use, so the workload may be memory-bound rather than idle."}`
      : " Some workloads (nodes, brokers) are naturally idle on CPU, so check memory and network before resizing (run the SSM probe to see memory).";
    // Jev's role: a chain node or a broker is idle on CPU by design; a protected box is report-only; a dev box wants a scheduler.
    const prot = isProtected(name, role);
    let tier: Tier = prot.protected && prot.source === "jev" ? "report" : "approve";
    let roleNote = "";
    if (role && NATURALLY_IDLE_ROLES.includes(role.role) && role.role_confidence >= ROLE_CONFIDENCE_THRESHOLD) {
      confidence = 0.2;
      roleNote = ` Jev classifies it as ${role.role} (${role.role_confidence.toFixed(2)}): such workloads are naturally low on CPU, so the CPU figure is not evidence of waste and the confidence is lowered to 0.2.`;
    } else if (role?.role === "dev_or_test") {
      roleNote = ` Jev classifies it as dev_or_test (${role.role_confidence.toFixed(2)}): rather than resizing, consider a scheduler that parks it out of hours (nights and weekends save about two thirds of the bill).`;
    }
    if (tier === "report") roleNote += ` Jev reads the name and tags as deliberately kept (${role!.protected_prob.toFixed(2)}), so this is report-only.`;
    out.push({
      rule: "idle_instance",
      title: `Right-size or stop ${name} (${r.instance_type}, ${r.avg_max_cpu}% max CPU)`,
      resource: r.instance_id,
      resourceName: name,
      actionType: "rightsize_instance",
      estMonthlySaving: null,
      tier,
      confidence,
      rationale: `Average daily peak CPU of ${r.avg_max_cpu}% over ${r.days} days.${probeNote}${roleNote}`,
      evidence: { ...r, ...(probe ? { probe } : {}), ...(role ? { role } : {}) },
    });
  }

  for (const a of ctx.aurora) {
    const ioCost = (a.ios30d / 1e6) * PRICE.auroraIoPerMillion;
    const stdStorage = a.volumeGb * PRICE.auroraStdPerGbMonth;
    const ioptStorage = a.volumeGb * PRICE.auroraIoptPerGbMonth;
    if (a.storageType === "aurora-iopt1" && ioCost < 0.3 * stdStorage) {
      out.push({
        rule: "aurora_storage_tier",
        title: `Move Aurora cluster ${a.cluster} from I/O-Optimized to Standard storage`,
        resource: a.cluster,
        resourceName: a.cluster,
        actionType: "aurora_set_storage_standard",
        estMonthlySaving: ioptStorage - stdStorage - ioCost,
        tier: "approve",
        confidence: 0.8,
        rationale: `About ${Math.round(a.volumeGb)} GB on I/O-Optimized storage (2.25x the per-GB price) but only ${(a.ios30d / 1e6).toFixed(1)} million I/Os in 30 days, which would cost ${ioCost.toFixed(2)} USD on Standard. The instance surcharge also disappears. Online change, no failover.`,
        evidence: a,
      });
    } else if (a.storageType !== "aurora-iopt1" && ioCost > 0.3 * (stdStorage + 50)) {
      const load = ctx.loads?.[a.cluster];
      const { note, confidence } = auroraLoadNote(load, 0.6);
      out.push({
        rule: "aurora_storage_tier",
        title: `Move Aurora cluster ${a.cluster} to I/O-Optimized storage`,
        resource: a.cluster,
        resourceName: a.cluster,
        actionType: "aurora_set_storage_iopt",
        estMonthlySaving: ioCost * 0.7,
        tier: "approve",
        confidence,
        rationale: `${(a.ios30d / 1e6).toFixed(0)} million I/Os in 30 days cost about ${ioCost.toFixed(0)} USD/month on Standard storage. I/O-Optimized removes that charge for roughly 30% more on storage and instance hours. Switching to I/O-Optimized is allowed once every 30 days; switching back to Standard at any time.${note}`,
        evidence: load ? { ...a, load } : a,
      });
    }
  }

  out.push(...gravitonRecommendations(ctx.graviton, ctx.roles || {}).recs);

  return out;
}

// ---- Graviton -------------------------------------------------------------------------------------------------

/** The roles that can be rebuilt on an ARM AMI with a known amount of work; everything else needs an audit first. */
const REBUILDABLE_ROLES = new Set(["web_or_api", "batch_or_worker", "dev_or_test", "cache_or_queue", "bastion_or_vpn"]);

const safeTags = (t: string): Record<string, string> => { try { return JSON.parse(t) || {}; } catch { return {}; } };

export interface GravitonSkip { resource: string; kind: "ec2" | "rds" | "lambda"; why: string }

/**
 * EC2 tier by role (see src/roles.ts): a Kubernetes node is handled at the pool level, a rebuildable role is
 * approve with the AMI caveat, a chain node / database / unknown box is report until an ARM build audit says
 * otherwise, and a protected resource is always report.
 */
export function ec2GravitonTier(fact: Pick<GravitonEc2Fact, "name" | "tags">, role: RoleFacts | undefined): { tier: Tier; confidence: number; note: string } {
  const name = fact.name || "";
  const prot = isProtected(name, role);
  const pool = k8sPoolOf(fact.tags || {});
  const batch = poolOf(fact.tags || {});
  if (batch?.kind === "batch") {
    return { tier: "approve", confidence: 0.6, note: ` It is an AWS Batch worker (compute environment ${batch.name}): do not touch the instance; set Graviton instance types on the compute environment and build the job images for linux/arm64 (GPU jobs need a Graviton GPU family such as g5g, which is a different GPU).` };
  }
  if (prot.protected) {
    return { tier: "report", confidence: 0.3, note: prot.source === "jev" ? ` Jev reads the name and tags as deliberately kept (${role!.protected_prob.toFixed(2)}), so this is report-only: raise it with the owner rather than scheduling it.` : " The name asks not to touch it, so this is report-only." };
  }
  if (role?.role === "k8s_node" || pool) {
    return { tier: "approve", confidence: 0.7, note: ` It is a Kubernetes node${pool ? ` (pool ${pool})` : ""}: do not touch the instance; add an arm64 node group or Karpenter NodePool, make every workload image multi-arch (linux/amd64 and linux/arm64), and let the scheduler drain the x86 nodes.` };
  }
  if (role && REBUILDABLE_ROLES.has(role.role)) {
    return { tier: "approve", confidence: 0.6, note: ` Jev classifies it as ${role.role} (${role.role_confidence.toFixed(2)}): rebuild from an arm64 AMI with the same provisioning; every binary and container image on it needs an ARM build, and the data volume moves as is.` };
  }
  if (role?.role === "ci_or_build") {
    return { tier: "report", confidence: 0.3, note: ` Jev classifies it as ci_or_build (${role.role_confidence.toFixed(2)}): a build box produces artifacts for the architecture it runs on, so moving it changes what it builds; only worth it together with an arm64 fleet.` };
  }
  const label = role ? `${role.role} (${role.role_confidence.toFixed(2)})` : "unclassified";
  return { tier: "report", confidence: 0.4, note: ` Jev classifies it as ${label}: needs an ARM build audit first (chain daemons, database builds and unknown software may have no arm64 binary); report-only until the audit says the stack runs on ARM.` };
}

/** The graviton recommendations plus what was skipped and why (the collector logs the skips). */
export function gravitonRecommendations(facts: GravitonFacts | undefined, roles: Record<string, RoleFacts> = {}): { recs: RecInput[]; skipped: GravitonSkip[] } {
  const recs: RecInput[] = [];
  const skipped: GravitonSkip[] = [];
  if (!facts) return { recs, skipped };
  const seen = new Set<string>();
  const pct = (cur: number, arm: number) => Math.round((1 - arm / cur) * 100);
  for (const a of facts.alarms) {
    if (seen.has(`${a.kind}|${a.id}`)) continue;
    seen.add(`${a.kind}|${a.id}`);
    const skip = (why: string) => skipped.push({ resource: a.resource, kind: a.kind, why });

    if (a.kind === "ec2") {
      const f = facts.ec2[a.id];
      if (!f?.instance_type) { skip("instance type unknown (not in the inventory yet)"); continue; }
      const target = ec2ArmEquivalent(f.instance_type);
      if (!target) { skip(`${f.instance_type} has no same-size Graviton equivalent in the type map`); continue; }
      if (f.state && f.state !== "running") { skip(`${f.instance_type} is ${f.state}: no instance-hours to save until it runs`); continue; }
      const region = f.region || a.region;
      const cur = facts.prices[gravitonPriceKey("ec2", f.instance_type, region, f.operating_system)];
      const arm = facts.prices[gravitonPriceKey("ec2", target, region, f.operating_system)];
      const saving = gravitonSaving(cur, arm);
      if (saving == null) { skip(`price unknown for ${cur == null ? f.instance_type : target} (${f.operating_system}, ${region})`); continue; }
      if (saving <= 0) { skip(`${target} is not cheaper than ${f.instance_type} in ${region}`); continue; }
      const role = roles[a.id];
      const t = ec2GravitonTier(f, role);
      const name = f.name || a.id;
      const pool = k8sPoolOf(f.tags || {});
      recs.push({
        rule: "graviton_migration",
        title: `Move ${name} from ${f.instance_type} to ${target} (Graviton)`,
        resource: a.id,
        resourceName: name,
        actionType: "migrate_to_graviton",
        estMonthlySaving: saving,
        tier: t.tier,
        confidence: t.confidence,
        rationale: `${f.instance_type} bills ${cur!.toFixed(4)} USD/h on demand; ${target} is the same size on Graviton at ${arm!.toFixed(4)} USD/h (${pct(cur!, arm!)}% less), ${saving.toFixed(2)} USD/month at 730 h. Same vCPU and memory; every binary and image on the box must have an arm64 build.${t.note} ${stepsSentence(playbookFor(EC2_GRAVITON_CONTROL)!)}`,
        evidence: { playbook: EC2_GRAVITON_CONTROL, current_sku: f.instance_type, target_sku: target, prices: { current_hourly: cur, target_hourly: arm, region, operating_system: f.operating_system }, state: f.state, ...(pool ? { k8s_pool: pool } : {}), ...(role ? { role } : {}), finding: a.resource },
      });
      continue;
    }

    if (a.kind === "rds") {
      const f = facts.rds[a.id];
      if (!f?.class) { skip("instance class unknown (not in the inventory yet)"); continue; }
      const target = rdsArmEquivalent(f.class);
      if (!target) { skip(`${f.class} has no same-size Graviton equivalent in the class map`); continue; }
      if (!f.pricing_engine) { skip(`engine ${f.engine ?? "?"} has no price-list name`); continue; }
      const region = f.region || a.region;
      const label = `${f.pricing_engine}${f.multi_az ? " Multi-AZ" : ""}${f.io_optimized ? " IO-Optimized" : ""}`;
      const cur = facts.prices[gravitonPriceKey("rds", f.class, region, label)];
      const arm = facts.prices[gravitonPriceKey("rds", target, region, label)];
      const saving = gravitonSaving(cur, arm);
      if (saving == null) { skip(`price unknown for ${cur == null ? f.class : target} (${label}, ${region})`); continue; }
      if (saving <= 0) { skip(`${target} is not cheaper than ${f.class} in ${region}`); continue; }
      recs.push({
        rule: "graviton_migration",
        title: `Move RDS ${a.id} from ${f.class} to ${target} (Graviton)`,
        resource: a.id,
        resourceName: a.id,
        actionType: "migrate_to_graviton",
        estMonthlySaving: saving,
        tier: "approve",
        confidence: 0.7,
        rationale: `${f.class} (${label}) bills ${cur!.toFixed(4)} USD/h; ${target} runs the same ${f.engine ?? "engine"} on Graviton at ${arm!.toFixed(4)} USD/h (${pct(cur!, arm!)}% less), ${saving.toFixed(2)} USD/month. The engine does not change; the class change restarts the instance (a Multi-AZ failover takes about a minute), so do it in the maintenance window, and check no reservation covers the current class. ${stepsSentence(playbookFor(RDS_GRAVITON_CONTROL)!)}`,
        evidence: { playbook: RDS_GRAVITON_CONTROL, current_sku: f.class, target_sku: target, prices: { current_hourly: cur, target_hourly: arm, region, engine: label }, engine: f.engine, finding: a.resource },
      });
      continue;
    }

    const f = facts.lambda[a.id];
    if (!f) { skip("function not found in aws_lambda_function"); continue; }
    if (f.architectures.includes("arm64")) { skip("already arm64"); continue; }
    const saving = f.last_month_cost != null ? Math.round(f.last_month_cost * LAMBDA_ARM_DISCOUNT * 100) / 100 : null;
    const costNote = f.last_month_cost != null
      ? ` Last month it cost ${f.last_month_cost.toFixed(2)} USD (aws_cost_by_resource_daily); arm64 bills about 20% less per GB-second, so about ${saving!.toFixed(2)} USD/month.`
      : ` Its cost could not be read${f.cost_note ? ` (${f.cost_note})` : ""}, so the saving is unknown: arm64 bills about 20% less per GB-second, worth it when the function has real monthly cost.`;
    recs.push({
      rule: "graviton_migration",
      title: `Switch Lambda ${a.id} to arm64`,
      resource: a.id,
      resourceName: a.id,
      actionType: "migrate_to_graviton",
      estMonthlySaving: saving,
      tier: "approve",
      confidence: saving == null ? 0.4 : 0.6,
      rationale: `${a.id} runs on ${f.architectures.join("/") || "x86_64"}${f.runtime ? ` (${f.runtime})` : ""}${f.package_type === "Image" ? ", deployed as a container image (the image needs a linux/arm64 manifest)" : ""}.${costNote} Pure Python/Node code just needs the architecture switched; native extensions need arm64 wheels or builds. ${stepsSentence(playbookFor(LAMBDA_GRAVITON_CONTROL)!)}`,
      evidence: { playbook: LAMBDA_GRAVITON_CONTROL, current_sku: f.architectures[0] || "x86_64", target_sku: "arm64", prices: { last_month_cost: f.last_month_cost, discount: LAMBDA_ARM_DISCOUNT }, runtime: f.runtime, package_type: f.package_type, finding: a.resource },
    });
  }
  return { recs, skipped };
}

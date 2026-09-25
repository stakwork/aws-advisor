/**
 * Pools: instances that a controller launches and terminates on its own (AWS Batch compute environments,
 * Karpenter NodePools, EKS node groups, plain autoscaling groups). Their per-instance CPU, idle time and
 * lifetime are the controller's doing, so the advisor reasons about the pool, never the member. Detection
 * is deterministic from the instance tags; Jev and the agent receive the result as a fact.
 */
export type PoolKind = "batch" | "karpenter" | "eks" | "asg";

export interface Pool {
  kind: PoolKind;
  /** the controller's own name for the pool: compute environment, NodePool, node group or ASG */
  name: string;
  /** one line for humans and prompts */
  note: string;
}

const NOTES: Record<PoolKind, (name: string) => string> = {
  batch: (n) => `AWS Batch compute environment worker (${n}): Batch launches it when jobs are queued and terminates it when the queue drains, so its lifetime, idle CPU and SSM registration lag are expected. Not a stop, right-size or Graviton candidate on its own; change the compute environment (instance types, allocation strategy, min/max vCPUs) or the job definition instead.`,
  karpenter: (n) => `Karpenter NodePool member (${n}): the scheduler adds and removes nodes with demand. Act on the NodePool and the workloads, not on the instance.`,
  eks: (n) => `EKS managed node group member (${n}): the group scales the nodes. Act on the node group and the workloads, not on the instance.`,
  asg: (n) => `Auto Scaling group member (${n}): the group launches and replaces instances. Act on the launch template and the scaling policy, not on the instance.`,
};

/** The pool an instance belongs to, from its tags, or null for a standalone instance. */
export function poolOf(tags: Record<string, string> | null | undefined): Pool | null {
  const t = tags || {};
  const asg = t["aws:autoscaling:groupName"];
  if (t.AWSBatchServiceTag || (asg && /^AWSBatch-/.test(asg))) {
    const name = batchEnvironmentName(asg) || asg || "batch";
    return { kind: "batch", name, note: NOTES.batch(name) };
  }
  const karpenter = t["karpenter.sh/nodepool"];
  if (karpenter) return { kind: "karpenter", name: karpenter, note: NOTES.karpenter(karpenter) };
  const eks = t["eks:nodegroup-name"] || t["alpha.eksctl.io/nodegroup-name"] || t["aws:eks:nodegroup-name"];
  if (eks) return { kind: "eks", name: eks, note: NOTES.eks(eks) };
  if (asg) return { kind: "asg", name: asg, note: NOTES.asg(asg) };
  return null;
}

/** "AWSBatch-production-2025...-asg-<uuid>" -> "production-2025..." (the compute environment's name). */
export function batchEnvironmentName(asg: string | undefined): string | null {
  if (!asg) return null;
  const m = /^AWSBatch-(.+?)-asg-[0-9a-f-]+$/.exec(asg);
  return m ? m[1] : null;
}

/** Pools whose members appear and disappear with demand: probing or judging one member says nothing. */
export const isEphemeralPool = (pool: Pool | null | undefined): boolean => pool?.kind === "batch" || pool?.kind === "karpenter";

/** Shared prompt text so every agent call reasons the same way about pools. */
export const OPERATIONAL_PATTERNS = `Operational patterns to respect (facts, not guesses):
- Pool members are not individual candidates. Instances with a pool (batch = AWS Batch compute environment, karpenter,
  eks = managed node group, asg) are launched and terminated by their controller. A Batch worker exists only while a
  job runs: its appearance, its short life, its idle CPU between jobs and a late SSM registration are all expected.
  Recommend changes to the compute environment, NodePool, node group, launch template or job definition, never
  "stop", "right-size" or "migrate" one member.
- New instances take a few minutes to register with Systems Manager; "not managed" on an instance younger than
  fifteen minutes is not a finding.
- Autoscaling churn (nodes appearing and disappearing) is normal; only a change in the pool's size over days is.
- The advisor is the monitor for SSM-managed instances. It probes memory, disk, load, reboots and containers itself,
  keeps daily roll-ups, raises disk_high, disk_full and disk_fill (days until full at the current rate), memory and
  load alerts, and reviews the statistics every day. Never recommend installing the CloudWatch agent, creating
  CloudWatch alarms or adding external monitoring for these; a monitoring gap (an instance the advisor does not probe,
  a threshold, a figure it does not compute) goes under needs_from_human or in the rationale, not in a recommendation
  or a fix.`;

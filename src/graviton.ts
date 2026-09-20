/**
 * Graviton migration rule: the Thrifty "not using Graviton" alarms for EC2, RDS and Lambda turned into
 * recommendations with a real saving. The ARM equivalent of an x86 type is the same size in the g-suffixed
 * family; the saving is the on-demand price difference over a month. Pure: the facts (types, prices, Lambda
 * architectures and costs) are gathered by src/graviton_facts.ts and passed in through the rules context; the
 * rule itself (tiering by role, the recommendations) is in src/rules.ts so both can be tested with fixtures.
 */
/** Same figure as src/prices.ts HOURS_PER_MONTH (not imported: prices.ts opens the database, this module stays pure). */
export const HOURS_PER_MONTH = 730;

/** x86 EC2 family -> the Graviton family of the same generation class (same size suffix). */
export const EC2_ARM_FAMILY: Record<string, string> = {
  m5: "m7g", m5a: "m7g", m5n: "m7g", m6i: "m7g", m6a: "m7g", m7i: "m7g", m7a: "m7g", m4: "m7g",
  c5: "c7g", c5a: "c7g", c5n: "c7g", c6i: "c7g", c6a: "c7g", c7i: "c7g", c7a: "c7g", c4: "c7g",
  r5: "r7g", r5a: "r7g", r5n: "r7g", r6i: "r7g", r6a: "r7g", r7i: "r7g", r7a: "r7g", r4: "r7g",
  t3: "t4g", t3a: "t4g", t2: "t4g",
  i3: "i4g", i3en: "i4g",
  x1: "x2gd", x1e: "x2gd",
};

/** x86 RDS class family (after the `db.` prefix) -> Graviton family. */
export const RDS_ARM_FAMILY: Record<string, string> = {
  m5: "m7g", m6i: "m7g", m7i: "m7g", m4: "m7g",
  r5: "r7g", r6i: "r7g", r7i: "r7g", r4: "r7g",
  t3: "t4g", t2: "t4g",
};

const TYPE_RE = /^([a-z]+[0-9]+[a-z-]*)\.([a-z0-9-]+)$/;

/** The ARM-equivalent EC2 type (m6i.xlarge -> m7g.xlarge), or null when the family has no mapping or is already Graviton. */
export function ec2ArmEquivalent(instanceType: string | null | undefined): string | null {
  if (!instanceType) return null;
  const m = TYPE_RE.exec(instanceType.trim().toLowerCase());
  if (!m) return null;
  const [, family, size] = m;
  if (/g$|gd$|gn$|ge$/.test(family)) return null; // already Graviton (m7g, c7gn, r6gd...)
  const target = EC2_ARM_FAMILY[family];
  if (!target) return null;
  // Graviton families cap at 16xlarge / metal; a 24xlarge x86 has no same-size twin.
  if (/^(24xlarge|32xlarge|48xlarge|metal-.*|metal)$/.test(size)) return null;
  return `${target}.${size}`;
}

/** The ARM-equivalent RDS class (db.r5.large -> db.r7g.large), or null. */
export function rdsArmEquivalent(instanceClass: string | null | undefined): string | null {
  if (!instanceClass) return null;
  const m = /^db\.([a-z]+[0-9]+[a-z]*)\.([a-z0-9]+)$/.exec(instanceClass.trim().toLowerCase());
  if (!m) return null;
  const [, family, size] = m;
  if (/g$/.test(family)) return null;
  const target = RDS_ARM_FAMILY[family];
  return target ? `db.${target}.${size}` : null;
}

/** Monthly saving from two hourly prices, rounded to cents; null when either is unknown. */
export function gravitonSaving(currentHourly: number | null | undefined, armHourly: number | null | undefined): number | null {
  if (currentHourly == null || armHourly == null || !Number.isFinite(currentHourly) || !Number.isFinite(armHourly)) return null;
  return Math.round((currentHourly - armHourly) * HOURS_PER_MONTH * 100) / 100;
}

// ---- facts and the rule -----------------------------------------------------------------------------------------

export interface GravitonAlarm {
  kind: "ec2" | "rds" | "lambda";
  /** The finding's resource (an ARN). */
  resource: string;
  /** Instance id, DB identifier or function name. */
  id: string;
  region: string;
  reason?: string | null;
}

export interface GravitonEc2Fact { instance_type: string | null; platform: string | null; name: string | null; state: string | null; region: string | null; tags: Record<string, string>; operating_system: string }
export interface GravitonRdsFact { class: string | null; engine: string | null; region: string | null; pricing_engine: string | null; multi_az: boolean; io_optimized: boolean }
export interface GravitonLambdaFact { architectures: string[]; runtime: string | null; package_type: string | null; last_month_cost: number | null; cost_note: string | null }

export interface GravitonFacts {
  alarms: GravitonAlarm[];
  ec2: Record<string, GravitonEc2Fact>;
  rds: Record<string, GravitonRdsFact>;
  lambda: Record<string, GravitonLambdaFact>;
  /** Hourly on-demand prices keyed by src/prices.ts priceKey (kind|sku|region|engine); null when the price list had nothing. */
  prices: Record<string, number | null>;
}

export const gravitonPriceKey = (kind: "ec2" | "rds", sku: string, region: string, engine: string) => `${kind}|${sku}|${region}|${engine}`;

export const EC2_GRAVITON_CONTROL = "aws_thrifty.control.ec2_instance_with_graviton";
export const RDS_GRAVITON_CONTROL = "aws_thrifty.control.rds_db_instance_with_graviton";
export const LAMBDA_GRAVITON_CONTROL = "aws_thrifty.control.lambda_function_with_graviton";
export const LAMBDA_ARM_DISCOUNT = 0.2;

/** Tags that say the instance belongs to a Kubernetes pool even when Jev has not classified it. */
export function k8sPoolOf(tags: Record<string, string>): string | null {
  return tags["karpenter.sh/nodepool"] || tags["eks:nodegroup-name"] || tags["alpha.eksctl.io/nodegroup-name"] || tags["aws:eks:nodegroup-name"]
    || Object.keys(tags).find((k) => k.startsWith("kubernetes.io/cluster/"))?.slice("kubernetes.io/cluster/".length) || null;
}

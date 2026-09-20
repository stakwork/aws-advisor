import { db } from "./db.js";
import { S, query } from "./steampipe.js";
import { PriceWant, ec2OperatingSystem, ensurePrices, priceKey, rdsPricingEngine } from "./prices.js";
import { EC2_GRAVITON_CONTROL, GravitonAlarm, GravitonEc2Fact, GravitonFacts, GravitonLambdaFact, GravitonRdsFact, LAMBDA_GRAVITON_CONTROL, RDS_GRAVITON_CONTROL, ec2ArmEquivalent, rdsArmEquivalent } from "./graviton.js";
import { shortResourceId } from "./resource_id.js";
import { describeError } from "./permissions.js";

/**
 * Gathers what the graviton rule (src/rules.ts) needs for the current run's Thrifty graviton alarms: the
 * instance type / class and state (Steampipe, with the inventory as fallback), the on-demand price of the
 * current and the ARM SKU through the shared price cache (src/prices.ts ensurePrices), the Lambda functions'
 * architectures and, when resource-level Cost Explorer data is enabled, their cost over the last weeks.
 * Every lookup that fails is reported through onLog and leaves the facts empty, so the rule skips rather than
 * guesses.
 */

const GRAVITON_CONTROLS: Record<string, GravitonAlarm["kind"]> = { [EC2_GRAVITON_CONTROL]: "ec2", [RDS_GRAVITON_CONTROL]: "rds", [LAMBDA_GRAVITON_CONTROL]: "lambda" };

/** The graviton alarms among a run's findings, one per resource. */
export function gravitonAlarms(findings: { control_id: string; resource: string | null; region?: string | null; reason?: string | null }[]): GravitonAlarm[] {
  const out: GravitonAlarm[] = [];
  const seen = new Set<string>();
  for (const f of findings) {
    const kind = GRAVITON_CONTROLS[f.control_id];
    if (!kind || !f.resource) continue;
    const id = shortResourceId(f.resource);
    if (!id || seen.has(`${kind}|${id}`)) continue;
    seen.add(`${kind}|${id}`);
    out.push({ kind, resource: f.resource, id, region: f.region || regionOfArn(f.resource) || "us-east-1", reason: f.reason ?? null });
  }
  return out;
}

const regionOfArn = (arn: string) => (arn.startsWith("arn:") ? arn.split(":")[3] || null : null);
const inList = (ids: string[]) => ids.map((_, i) => `$${i + 1}`).join(", ");
const safeJson = (s: unknown) => { if (typeof s !== "string") return s ?? null; try { return JSON.parse(s); } catch { return null; } };

/** Cost Explorer keeps resource-level daily data for 14 days; the sum is extrapolated to a 30-day month. */
export const LAMBDA_COST_DAYS = 14;

export async function collectGravitonFacts(alarms: GravitonAlarm[], opts: { onLog?: (line: string) => void } = {}): Promise<GravitonFacts> {
  const log = opts.onLog ?? (() => {});
  const facts: GravitonFacts = { alarms, ec2: {}, rds: {}, lambda: {}, prices: {} };
  const ec2Ids = alarms.filter((a) => a.kind === "ec2").map((a) => a.id);
  const rdsIds = alarms.filter((a) => a.kind === "rds").map((a) => a.id);
  const lambdaNames = alarms.filter((a) => a.kind === "lambda").map((a) => a.id);
  const wants: PriceWant[] = [];

  // ---- EC2: type, platform, state, tags ---------------------------------------------------------------------
  if (ec2Ids.length) {
    let rows: any[] = [];
    try {
      rows = await query(`select instance_id, instance_type, platform, platform_details, instance_state, region, tags, title from ${S}.aws_ec2_instance where instance_id in (${inList(ec2Ids)})`, ec2Ids);
    } catch (e: any) {
      log(`  EC2 types from Steampipe failed, using the inventory: ${describeError(e, "graviton facts (aws_ec2_instance)", 200)}`);
      rows = (db.prepare(`select instance_id, instance_type, platform as platform_details, state as instance_state, region, name as title, snapshot from inventory_ec2 where instance_id in (${ec2Ids.map(() => "?").join(",")})`).all(...ec2Ids) as any[])
        .map((r) => ({ ...r, platform: null, tags: safeJson(r.snapshot)?.tags || {} }));
    }
    // Instances Steampipe no longer lists (terminated since the benchmark ran) come from the inventory, so the skip names the state.
    const listed = new Set(rows.map((r) => r.instance_id));
    const gone = ec2Ids.filter((id) => !listed.has(id));
    if (gone.length) {
      for (const r of db.prepare(`select instance_id, instance_type, platform as platform_details, state as instance_state, region, name as title, snapshot from inventory_ec2 where instance_id in (${gone.map(() => "?").join(",")})`).all(...gone) as any[]) {
        rows.push({ ...r, platform: null, tags: safeJson(r.snapshot)?.tags || {}, instance_state: r.instance_state === "running" ? "terminated" : r.instance_state });
      }
    }
    for (const r of rows) {
      const tags: Record<string, string> = r.tags && typeof r.tags === "object" ? r.tags : safeJson(r.tags) || {};
      const os = ec2OperatingSystem(r.platform, r.platform_details);
      facts.ec2[r.instance_id] = { instance_type: r.instance_type ?? null, platform: r.platform_details ?? r.platform ?? null, name: tags.Name || r.title || null, state: r.instance_state ?? null, region: r.region ?? null, tags, operating_system: os };
      const target = ec2ArmEquivalent(r.instance_type);
      if (r.instance_type && target && r.region && r.instance_state === "running") {
        for (const sku of [r.instance_type, target]) wants.push({ kind: "ec2", sku, region: r.region, engine: os, spec: { kind: "ec2", instance_type: sku, region: r.region, operating_system: os } });
      }
    }
  }

  // ---- RDS: class, engine, deployment ------------------------------------------------------------------------
  if (rdsIds.length) {
    let rows: any[] = [];
    try {
      rows = await query(`select db_instance_identifier, class, engine, multi_az, storage_type, region from ${S}.aws_rds_db_instance where db_instance_identifier in (${inList(rdsIds)})`, rdsIds);
    } catch (e: any) {
      log(`  RDS classes from Steampipe failed, using the inventory: ${describeError(e, "graviton facts (aws_rds_db_instance)", 200)}`);
      rows = db.prepare(`select db_instance_identifier, class, engine, multi_az, storage_type, region from inventory_rds where db_instance_identifier in (${rdsIds.map(() => "?").join(",")})`).all(...rdsIds) as any[];
    }
    for (const r of rows) {
      const engine = rdsPricingEngine(r.engine);
      const aurora = /^aurora/i.test(String(r.engine || ""));
      const multiAz = Boolean(r.multi_az) && !aurora;
      const ioOptimized = aurora && r.storage_type === "aurora-iopt1";
      facts.rds[r.db_instance_identifier] = { class: r.class ?? null, engine: r.engine ?? null, region: r.region ?? null, pricing_engine: engine, multi_az: multiAz, io_optimized: ioOptimized };
      const target = rdsArmEquivalent(r.class);
      if (engine && target && r.region) {
        const deployment = multiAz ? "Multi-AZ" : "Single-AZ";
        const label = `${engine}${multiAz ? " Multi-AZ" : ""}${ioOptimized ? " IO-Optimized" : ""}`;
        for (const sku of [r.class, target]) wants.push({ kind: "rds", sku, region: r.region, engine: label, ioOptimized, spec: { kind: "rds", instance_type: sku, region: r.region, engine, deployment } });
      }
    }
  }

  // ---- prices through the shared 7-day cache ------------------------------------------------------------------
  if (wants.length) {
    const { prices, fetched } = await ensurePrices(wants, (m) => log(`  ${m}`));
    for (const w of wants) facts.prices[priceKey(w)] = prices.get(priceKey(w))?.hourly ?? null;
    const unknown = wants.filter((w) => facts.prices[priceKey(w)] == null).map((w) => `${w.sku} (${w.engine})`);
    log(`  Graviton prices: ${wants.length} SKUs wanted, ${fetched} fetched${unknown.length ? `; unknown: ${[...new Set(unknown)].join(", ")}` : ""}`);
  }

  // ---- Lambda: architectures, then cost over the last 14 days in one Cost Explorer query ---------------------------
  if (lambdaNames.length) {
    try {
      const rows = await query<{ name: string; arn: string; architectures: string[] | string; runtime: string | null; package_type: string | null }>(
        `select name, arn, architectures, runtime, package_type from ${S}.aws_lambda_function where name in (${inList(lambdaNames)})`, lambdaNames);
      const byName = new Map(rows.map((r) => [r.name, r]));
      for (const name of lambdaNames) {
        const r = byName.get(name);
        if (!r) continue;
        const arch = Array.isArray(r.architectures) ? r.architectures : safeJson(r.architectures) || [];
        facts.lambda[name] = { architectures: arch.map(String), runtime: r.runtime ?? null, package_type: r.package_type ?? null, last_month_cost: null, cost_note: null };
      }
      const missing = lambdaNames.filter((n) => !byName.has(n));
      if (missing.length) log(`  Lambda: ${missing.length} alarmed function(s) no longer exist`);
    } catch (e: any) {
      log(`  Lambda architectures failed: ${describeError(e, "graviton facts (aws_lambda_function)", 200)}`);
    }
    if (Object.keys(facts.lambda).length) await lambdaCosts(facts.lambda, log);
  }
  return facts;
}

/**
 * Cost per function from aws_cost_by_resource_daily, one query for the whole service (each Cost Explorer request
 * costs 0.01 USD, so never one per function). Resource-level data goes back 14 days; the sum is scaled to 30 days.
 */
async function lambdaCosts(lambda: Record<string, GravitonLambdaFact>, log: (l: string) => void): Promise<void> {
  const sql = `
    select resource_id, count(distinct period_start) as days, sum(unblended_cost_amount) as usd
    from ${S}.aws_cost_by_resource_daily
    where dimension_key = 'SERVICE' and dimension_value = 'AWS Lambda'
      and period_start >= (current_date - ${LAMBDA_COST_DAYS})::timestamp and period_start < current_date::timestamp
    group by resource_id`;
  try {
    const rows = await query<{ resource_id: string; days: string; usd: string }>(sql);
    const byName = new Map<string, { days: number; usd: number }>();
    for (const r of rows) {
      const name = shortResourceId(r.resource_id);
      if (!name) continue;
      const cur = byName.get(name) || { days: 0, usd: 0 };
      byName.set(name, { days: Math.max(cur.days, Number(r.days)), usd: cur.usd + Number(r.usd) });
    }
    let priced = 0;
    for (const [name, f] of Object.entries(lambda)) {
      const c = byName.get(name);
      if (c && c.days > 0) {
        f.last_month_cost = Math.round((c.usd / c.days) * 30 * 100) / 100;
        f.cost_note = `${c.usd.toFixed(4)} USD over ${c.days} day(s), scaled to 30 days`;
        priced++;
      } else {
        f.last_month_cost = 0;
        f.cost_note = `no Lambda cost line for it in the last ${LAMBDA_COST_DAYS} days`;
      }
    }
    log(`  Lambda cost: ${rows.length} resources billed in the last ${LAMBDA_COST_DAYS} days, ${priced} of ${Object.keys(lambda).length} alarmed functions among them`);
  } catch (e: any) {
    const m = String(e?.message || e);
    const note = /Resource-level data granularity|resource-level/i.test(m) ? "resource-level Cost Explorer data is not enabled for this account" : describeError(e, "graviton facts (aws_cost_by_resource_daily)", 160);
    for (const f of Object.values(lambda)) f.cost_note = note;
    log(`  Lambda cost unavailable: ${note}`);
  }
}

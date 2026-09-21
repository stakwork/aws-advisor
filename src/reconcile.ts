/**
 * Bill reconstruction: price last month's usage from our own knowledge (the pricebook for usage types, the price
 * cache for instance hours, the Savings Plan and support as account overlays) and compare, line by line and per
 * service, with what Cost Explorer says we paid. The gap is the eval of the graph's pricing knowledge: a priced
 * line that disagrees is a wrong price; an unpriced line is a system type the general area does not hold yet.
 *
 * v0 takes the usage QUANTITIES from Cost Explorer (BoxUsage hours, GB-months, bytes) and prices them
 * independently. Reconstructing the quantities themselves from the inventory history is the next step.
 */
import { db } from "./db.js";
import { S, query } from "./steampipe.js";
import { PriceWant, elasticachePricingEngine, ensurePrices, getCachedPrice, priceKey, rdsPricingEngine } from "./prices.js";
import { PRICEBOOK_DATE, PriceRule, SkuRule, businessSupport, hoursInMonth, priceRuleFor, splitUsageType } from "./pricebook.js";
import { describeError } from "./permissions.js";

db.exec(`create table if not exists reconciliations (
  month text primary key,
  computed_at text not null,
  json text not null
)`);

export interface UsageLine { service: string; usage_type: string; quantity: number; unit: string | null; unblended: number; net: number; amortized: number }
export interface RecordTotals { usage_net: number; sp_fee: number; sp_covered_od: number; ri_amortized: number; support: number; tax: number; other: number; net_total: number }
export interface ReconcileInput {
  month: string;
  lines: UsageLine[];
  records: RecordTotals;
  /** hourly commitment of the active Savings Plans (our overlay); null = take the fee Cost Explorer reports */
  sp_hourly: number | null;
  /** price per SKU key (see priceKey) in USD per hour */
  sku_prices: Map<string, number | null>;
  /** engine label per (kind|sku) so the SKU price key can be built, from the inventory */
  sku_engines: Map<string, string>;
}
export interface PricedLine extends UsageLine {
  region: string; rule: string | null; unit_price: number | null; modelled: number | null; actual_od: number; residual: number | null; note?: string;
  /** which commitment covered part of the line: the Savings Plan, a reservation, or none */
  covered: "sp" | "ri" | null;
  /** the modelled cost of the part that was billed on demand (the covered part costs nothing net this month) */
  modelled_uncovered: number | null;
}

/** Services a Compute Savings Plan can cover; a discount anywhere else comes from a reservation. */
const SP_SERVICES = /Elastic Compute Cloud|Lambda|Fargate|Container Service$/;
export interface ServiceRollup { service: string; actual_net: number; actual_od: number; modelled: number; unpriced_actual: number; lines: number; priced_lines: number; gap_pct: number | null; status: "pass" | "named" | "fail" }
export interface Reconciliation {
  month: string; computed_at: string; pricebook_date: string; hours: number;
  totals: {
    actual_net: number; modelled_net: number; strict_gap_pct: number;
    usage_list_model: number; unpriced_actual: number; priced_share_pct: number;
    sp_fee_actual: number; sp_fee_model: number; sp_covered_od: number; sp_discount: number; sp_discount_rate: number;
    ri_amortized: number; support_actual: number; support_model: number; tax_actual: number; other_actual: number;
  };
  eval: { criterion: string; pass: boolean; detail: string }[];
  services: ServiceRollup[];
  lines: PricedLine[];
  assumptions: string[];
}

const round2 = (n: number) => Math.round(n * 100) / 100;
/** Services that are record types in disguise (fee, support, tax): reconciled from the record totals, never as usage. */
export const NOT_USAGE = /^(Savings Plans for |AWS Support|AWS Business Support|AWS Developer Support|AWS Enterprise Support|Tax$)/;

/** Pure: prices the lines and builds the comparison. Exported for the tests. */
export function computeReconciliation(input: ReconcileInput): Reconciliation {
  const hours = hoursInMonth(input.month);
  const r = input.records;
  // Savings Plan overlay: the fee buys covered usage worth its on-demand equivalent; the difference is the discount
  const spFeeModel = input.sp_hourly != null ? round2(input.sp_hourly * hours) : r.sp_fee;
  const discountRate = r.sp_covered_od > 0 ? 1 - r.sp_fee / r.sp_covered_od : 0;
  const assumptions: string[] = [
    `Usage quantities are Cost Explorer's; only the prices are ours (pricebook ${PRICEBOOK_DATE}, us-east-1 list rates, Pricing API for instance hours).`,
    `Savings Plan: the fee (${input.sp_hourly != null ? `${input.sp_hourly} USD/h × ${hours} h` : "as billed"}) is compared with the on-demand value of the usage it covered; the implied discount (${(discountRate * 100).toFixed(1)} %) is used to bring covered lines back to on-demand for the line comparison.`,
    "Reservations (DiscountedUsage) are shown at their amortized cost; their discount is not modelled yet.",
    "Business Support is modelled with the published tiers (10 % to 10k, 7 % to 80k) on the modelled charges; the billed amount runs about 100 USD under that formula. Tax is taken as billed.",
    "The net identity: modelled net = the uncovered part of every usage line at our price (as billed where unpriced) + the Savings Plan fee + modelled support + billed tax. Covered usage costs nothing net in the month; its on-demand value is compared separately.",
    "An RDS class or cache node type no longer in the inventory is priced as PostgreSQL / Redis, the most common engines here.",
    "Tiered and free-tier prices (transfer out, SQS, custom metrics) use the first paid tier for everything.",
  ];
  const lines: PricedLine[] = input.lines.map((l) => {
    const { region } = splitUsageType(l.usage_type);
    const rule = priceRuleFor(l.service, l.usage_type);
    const discounted = l.amortized > l.unblended + 0.005;
    const covered: PricedLine["covered"] = !discounted ? null : SP_SERVICES.test(l.service) ? "sp" : "ri";
    let unitPrice: number | null = null; let ruleName: string | null = null; let note: string | undefined;
    if (rule && rule.rule === "sku") {
      const sk = rule as SkuRule;
      const engine = input.sku_engines.get(`${sk.kind}|${sk.sku}`) ?? (sk.kind === "ec2" ? "Linux" : "");
      const key = priceKey({ kind: sk.kind, sku: sk.sku, region, engine: sk.kind === "rds" ? `${engine}${sk.multiAz ? " Multi-AZ" : ""}${sk.ioOptimized ? " IO-Optimized" : ""}` : engine });
      const p = input.sku_prices.get(key);
      if (p != null) { unitPrice = sk.spot ? null : p; ruleName = `${sk.kind}_hours`; note = `${sk.sku} · ${engine || "Linux"}${sk.ioOptimized ? " IO-Optimized" : ""}${sk.multiAz ? " Multi-AZ" : ""}`; }
      else { ruleName = null; note = `no price on file for ${sk.kind} ${sk.sku} (${engine || "?"}) in ${region}`; }
      if (sk.spot) { unitPrice = null; ruleName = null; note = "spot: market price, not list"; }
    } else if (rule) {
      const pr = rule as PriceRule;
      unitPrice = pr.unit_price; ruleName = pr.rule; note = pr.note;
      if (region !== "us-east-1") note = `${note ? `${note}; ` : ""}priced at the us-east-1 rate`;
    }
    const modelled = unitPrice != null ? round2(l.quantity * unitPrice) : null;
    // on-demand value of the line: uncovered part as billed, the Savings-Plan-covered part scaled back by the
    // implied discount, a reservation-covered part taken from the model (Cost Explorer does not carry its list value)
    const actualOd = covered === "sp" && discountRate > 0 && discountRate < 1 ? l.unblended + (l.amortized - l.unblended) / (1 - discountRate)
      : covered === "ri" ? Math.max(modelled ?? l.amortized, l.unblended) : l.amortized;
    if (covered === "ri") note = `${note ? `${note}; ` : ""}reservation-covered: on-demand value taken from the model`;
    const uncoveredShare = actualOd > 0 ? Math.min(1, Math.max(0, l.unblended / actualOd)) : 1;
    const modelledUncovered = modelled != null ? round2(modelled * uncoveredShare) : null;
    return { ...l, region, rule: ruleName, unit_price: unitPrice, modelled, actual_od: round2(actualOd), residual: modelled != null ? round2(modelled - actualOd) : null, note, covered, modelled_uncovered: modelledUncovered };
  });
  // per service
  const byService = new Map<string, PricedLine[]>();
  for (const l of lines) byService.set(l.service, [...(byService.get(l.service) || []), l]);
  const services: ServiceRollup[] = [...byService.entries()].map(([service, ls]) => {
    const actualNet = ls.reduce((s, l) => s + l.net, 0);
    const actualOd = ls.reduce((s, l) => s + l.actual_od, 0);
    const pricedOd = ls.filter((l) => l.modelled != null).reduce((s, l) => s + l.actual_od, 0);
    const modelled = ls.reduce((s, l) => s + (l.modelled ?? 0), 0);
    const unpriced = actualOd - pricedOd;
    const gap = pricedOd > 1 ? ((modelled - pricedOd) / pricedOd) * 100 : null;
    // under 20 USD a service cannot fail: a rounding of a tiered price is not a wrong price sheet
    const status: ServiceRollup["status"] = gap != null && Math.abs(gap) <= 10 ? (unpriced > 0.05 * Math.max(1, actualOd) ? "named" : "pass") : pricedOd <= 1 || Math.abs(actualOd) < 20 ? "named" : "fail";
    return { service, actual_net: round2(actualNet), actual_od: round2(actualOd), modelled: round2(modelled), unpriced_actual: round2(unpriced), lines: ls.length, priced_lines: ls.filter((l) => l.modelled != null).length, gap_pct: gap != null ? round2(gap) : null, status };
  }).sort((a, b) => b.actual_od - a.actual_od);
  const usageListModel = round2(lines.reduce((s, l) => s + (l.modelled ?? 0), 0));
  const unpricedActual = round2(lines.filter((l) => l.modelled == null).reduce((s, l) => s + l.actual_od, 0));
  const totalOd = lines.reduce((s, l) => s + l.actual_od, 0);
  const spDiscount = round2(r.sp_covered_od - spFeeModel);
  // what AWS charged for usage before support = the uncovered part of every line (modelled where we have a price,
  // as billed where we do not) + the Savings Plan fee
  const uncoveredModel = round2(lines.reduce((s, l) => s + (l.modelled_uncovered ?? l.unblended), 0));
  const chargesModel = uncoveredModel + spFeeModel;
  const supportModel = r.support > 0 ? round2(businessSupport(chargesModel)) : 0;
  const modelledNet = round2(chargesModel + supportModel + r.tax + r.other);
  const strictGap = r.net_total > 0 ? ((modelledNet - r.net_total) / r.net_total) * 100 : 0;
  const evalRows = [
    { criterion: "total within 5 %", pass: Math.abs(strictGap) <= 5, detail: `modelled ${modelledNet.toFixed(0)} vs billed ${r.net_total.toFixed(0)} USD (${strictGap >= 0 ? "+" : ""}${strictGap.toFixed(1)} %); on-demand value of all usage ${usageListModel.toFixed(0)} modelled vs ${totalOd.toFixed(0)} observed, ${unpricedActual.toFixed(0)} USD of it unpriced and carried as billed` },
    { criterion: "every service within 10 % or its residual named", pass: services.every((s) => s.status !== "fail"), detail: services.filter((s) => s.status === "fail").map((s) => `${s.service} ${s.gap_pct}%`).join(", ") || "all services pass or carry a named residual" },
    { criterion: "commitments: Savings Plan fee matches the commitment", pass: Math.abs(spFeeModel - r.sp_fee) <= Math.max(5, 0.01 * r.sp_fee), detail: `${spFeeModel.toFixed(0)} modelled vs ${r.sp_fee.toFixed(0)} billed; it covered ${r.sp_covered_od.toFixed(0)} USD of on-demand value (discount ${(discountRate * 100).toFixed(1)} %)` },
    { criterion: "priced share: at least 90 % of usage cost has a price rule", pass: totalOd > 0 && (totalOd - unpricedActual) / totalOd >= 0.9, detail: `${totalOd > 0 ? (((totalOd - unpricedActual) / totalOd) * 100).toFixed(1) : "0"} % of on-demand usage value is priced by a rule` },
    { criterion: "provenance: every priced line names its rule", pass: lines.every((l) => l.modelled == null || l.rule), detail: "rule and note on every line" },
  ];
  return {
    month: input.month, computed_at: new Date().toISOString(), pricebook_date: PRICEBOOK_DATE, hours,
    totals: {
      actual_net: round2(r.net_total), modelled_net: modelledNet, strict_gap_pct: round2(strictGap),
      usage_list_model: usageListModel, unpriced_actual: unpricedActual, priced_share_pct: totalOd > 0 ? round2(((totalOd - unpricedActual) / totalOd) * 100) : 0,
      sp_fee_actual: round2(r.sp_fee), sp_fee_model: spFeeModel, sp_covered_od: round2(r.sp_covered_od), sp_discount: spDiscount, sp_discount_rate: round2(discountRate * 100),
      ri_amortized: round2(r.ri_amortized), support_actual: round2(r.support), support_model: supportModel, tax_actual: round2(r.tax), other_actual: round2(r.other),
    },
    eval: evalRows, services, lines: lines.sort((a, b) => b.actual_od - a.actual_od), assumptions,
  };
}

/** The previous full month as YYYY-MM. */
export function lastFullMonth(now = new Date()): string {
  const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - 1, 1));
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, "0")}`;
}

function monthBounds(month: string): { from: string; to: string } {
  if (!/^\d{4}-\d{2}$/.test(month)) throw new Error("month must be YYYY-MM");
  const [y, m] = month.split("-").map(Number);
  const to = new Date(Date.UTC(y, m, 1));
  return { from: `${month}-01`, to: `${to.getUTCFullYear()}-${String(to.getUTCMonth() + 1).padStart(2, "0")}-01` };
}

/** Engine label per SKU from the inventory, so an RDS class or cache node type gets the right price. */
function skuEngines(): Map<string, string> {
  const out = new Map<string, string>();
  const rds = db.prepare("select class, engine, count(*) as n from inventory_rds group by class, engine order by n desc").all() as any[];
  for (const r of rds) if (!out.has(`rds|${r.class}`)) { const e = rdsPricingEngine(r.engine); if (e) out.set(`rds|${r.class}`, e); }
  const ec = db.prepare("select node_type, engine, count(*) as n from inventory_elasticache group by node_type, engine order by n desc").all() as any[];
  for (const r of ec) if (!out.has(`elasticache|${r.node_type}`)) { const e = elasticachePricingEngine(r.engine); if (e) out.set(`elasticache|${r.node_type}`, e); }
  return out;
}

/** Pulls the month from Cost Explorer, prices it and stores the result. One Cost Explorer call per table (3). */
export async function reconcileMonth(month = lastFullMonth(), onLog: (s: string) => void = () => {}): Promise<Reconciliation> {
  const input = await loadMonthInput(month, onLog);
  const result = computeReconciliation(input);
  db.prepare("insert into reconciliations(month, computed_at, json) values (?, ?, ?) on conflict(month) do update set computed_at = excluded.computed_at, json = excluded.json").run(month, result.computed_at, JSON.stringify(result));
  onLog(`${month}: modelled ${result.totals.modelled_net} vs billed ${result.totals.actual_net} (${result.totals.strict_gap_pct} %), ${result.totals.priced_share_pct} % priced`);
  return result;
}

/** The month's usage lines and record totals from Cost Explorer plus our overlays: what both the reconstruction and the forecast price. */
export async function loadMonthInput(month: string, onLog: (s: string) => void = () => {}): Promise<ReconcileInput> {
  const { from, to } = monthBounds(month);
  const num = (v: unknown) => Number(v ?? 0) || 0;
  let lineRows: any[]; let recRows: any[];
  try {
    lineRows = await query(`select service, usage_type, sum(usage_quantity_amount) as quantity, max(usage_quantity_unit) as unit,
        sum(unblended_cost_amount) as unblended, sum(net_unblended_cost_amount) as net, sum(amortized_cost_amount) as amortized
      from ${S}.aws_cost_by_service_usage_type_monthly where period_start >= '${from}' and period_start < '${to}' group by 1, 2`);
    recRows = await query(`select record_type, sum(unblended_cost_amount) as unblended, sum(net_unblended_cost_amount) as net, sum(amortized_cost_amount) as amortized
      from ${S}.aws_cost_by_record_type_monthly where period_start >= '${from}' and period_start < '${to}' group by 1`);
  } catch (e) { throw new Error(describeError(e, "bill reconciliation (aws_cost_by_service_usage_type_monthly)")); }
  const rec: Record<string, { unblended: number; net: number; amortized: number }> = Object.fromEntries(recRows.map((r) => [String(r.record_type), { unblended: num(r.unblended), net: num(r.net), amortized: num(r.amortized) }]));
  const known = ["Usage", "SavingsPlanCoveredUsage", "SavingsPlanRecurringFee", "SavingsPlanNegation", "DiscountedUsage", "Support", "Tax"];
  const other = Object.entries(rec).filter(([k]) => !known.includes(k)).reduce((s, [, v]) => s + v.net, 0);
  const records: RecordTotals = {
    usage_net: (rec.Usage?.net ?? 0), sp_fee: rec.SavingsPlanRecurringFee?.net ?? 0, sp_covered_od: rec.SavingsPlanCoveredUsage?.unblended ?? 0,
    ri_amortized: rec.DiscountedUsage?.amortized ?? 0, support: rec.Support?.net ?? 0, tax: rec.Tax?.net ?? 0, other,
    net_total: Object.values(rec).reduce((s, v) => s + v.net, 0),
  };
  // Savings Plan commitment from the account (our overlay), when the table is readable
  let spHourly: number | null = null;
  try {
    const sp = await query(`select commitment, state from ${S}.aws_savingsplans_savings_plan where state = 'active'`);
    const total = sp.reduce((s: number, r: any) => s + num(r.commitment), 0);
    if (total > 0) spHourly = total;
  } catch (e) { onLog(`savings plan commitment not readable, using the billed fee: ${describeError(e, "aws_savingsplans_savings_plan")}`); }
  // instance-hour prices: whatever the cache has, fetching the missing SKUs once
  const lines: UsageLine[] = lineRows.map((r) => ({ service: String(r.service), usage_type: String(r.usage_type), quantity: num(r.quantity), unit: r.unit ?? null, unblended: num(r.unblended), net: num(r.net), amortized: num(r.amortized) }))
    .filter((l) => (Math.abs(l.amortized) >= 0.005 || Math.abs(l.net) >= 0.005) && !NOT_USAGE.test(l.service));
  const engines = skuEngines();
  const wants: PriceWant[] = [];
  for (const l of lines) {
    const rule = priceRuleFor(l.service, l.usage_type);
    if (!rule || rule.rule !== "sku" || (rule as SkuRule).spot) continue;
    const sk = rule as SkuRule; const { region } = splitUsageType(l.usage_type);
    if (sk.kind === "ec2") wants.push({ kind: "ec2", sku: sk.sku, region, engine: "Linux", spec: { kind: "ec2", instance_type: sk.sku, region, operating_system: "Linux" } });
    else if (sk.kind === "rds") {
      const engine = engines.get(`rds|${sk.sku}`) ?? "PostgreSQL"; if (!engines.has(`rds|${sk.sku}`)) engines.set(`rds|${sk.sku}`, engine);
      const deployment = sk.multiAz ? "Multi-AZ" : "Single-AZ";
      wants.push({ kind: "rds", sku: sk.sku, region, engine: `${engine}${sk.multiAz ? " Multi-AZ" : ""}${sk.ioOptimized ? " IO-Optimized" : ""}`, ioOptimized: sk.ioOptimized, spec: { kind: "rds", instance_type: sk.sku, region, engine, deployment } });
    } else {
      const engine = engines.get(`elasticache|${sk.sku}`) ?? "Redis"; if (!engines.has(`elasticache|${sk.sku}`)) engines.set(`elasticache|${sk.sku}`, engine);
      wants.push({ kind: "elasticache", sku: sk.sku, region, engine, spec: { kind: "elasticache", instance_type: sk.sku, region, engine } });
    }
  }
  const skuPrices = new Map<string, number | null>();
  try {
    const { prices, fetched } = await ensurePrices(wants, (m) => onLog(`price lookup: ${m}`));
    if (fetched) onLog(`fetched ${fetched} instance prices`);
    for (const w of wants) skuPrices.set(priceKey(w), prices.get(priceKey(w))?.hourly ?? getCachedPrice(w.kind, w.sku, w.region, w.engine)?.hourly ?? null);
  } catch (e: any) { onLog(`price lookup failed: ${e?.message || e}`); for (const w of wants) skuPrices.set(priceKey(w), getCachedPrice(w.kind, w.sku, w.region, w.engine)?.hourly ?? null); }
  return { month, lines, records, sp_hourly: spHourly, sku_prices: skuPrices, sku_engines: engines };
}

export function getReconciliation(month: string): Reconciliation | null {
  const row = db.prepare("select json from reconciliations where month = ?").get(month) as { json: string } | undefined;
  return row ? (JSON.parse(row.json) as Reconciliation) : null;
}
export function listReconciliations(): { month: string; computed_at: string; actual_net: number; modelled_net: number; strict_gap_pct: number; priced_share_pct: number }[] {
  return (db.prepare("select month, computed_at, json from reconciliations order by month desc").all() as any[]).map((r) => {
    const j = JSON.parse(r.json) as Reconciliation;
    return { month: r.month, computed_at: r.computed_at, actual_net: j.totals.actual_net, modelled_net: j.totals.modelled_net, strict_gap_pct: j.totals.strict_gap_pct, priced_share_pct: j.totals.priced_share_pct };
  });
}

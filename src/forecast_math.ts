/**
 * The month's bill, forecast from what is running now. Pure, so the arithmetic is tested.
 *
 * Month to date comes from Cost Explorer (the priced lines of the partial month and its record totals). The
 * remaining days are priced three ways, and every service says which:
 *   - inventory: compute, databases, cache nodes, volumes, buckets and functions from the inventory as it is
 *     right now, at our prices, with the Savings Plan and the reservations applied;
 *   - run rate: usage-based lines (transfer, NAT, CloudWatch, requests) at their month-to-date daily average;
 *   - fixed: the Savings Plan fee, reservations and support, known in advance.
 */
import type { PricedLine, RecordTotals } from "./reconcile.js";
import { businessSupport } from "./pricebook.js";

export type Basis = "inventory" | "run_rate" | "fixed" | "mixed";
export interface InventoryNow {
  /** on-demand value per hour of the running EC2 instances (Batch and spot workers excluded) */
  ec2_od_hourly: number; ec2_running: number;
  rds_od_hourly: number; cache_od_hourly: number;
  /** on-demand value per hour of the instances and nodes the reservations cover (null when unknown) */
  rds_reserved_hourly: number | null; cache_reserved_hourly: number | null;
  /** list price of a month of the volumes, the buckets and the functions as they are now */
  ebs_month: number; s3_month: number; lambda_month: number;
}
export interface ForecastInput {
  month: string;
  /** complete days the month-to-date figures cover (Cost Explorer lags a day) */
  elapsed_days: number; days_in_month: number;
  lines: PricedLine[]; records: RecordTotals;
  sp_hourly: number | null;
  /** the Savings Plan's discount on the on-demand value it covers (0.27 = 27 %), from the last full month */
  sp_discount_rate: number;
  now: InventoryNow;
  /** last full month's billed net per service and in total, for the comparison */
  last_month: { total: number; services: Record<string, number> } | null;
}
export interface ForecastService { service: string; mtd: number; per_day: number; remaining: number; forecast: number; basis: Basis; last_month: number | null; delta: number | null }
export interface ForecastCategory { key: string; label: string; basis: Basis; mtd: number; mtd_per_day: number; per_day: number; remaining: number; detail: string }
export interface Forecast {
  month: string; computed_at: string; elapsed_days: number; remaining_days: number; days_in_month: number;
  mtd_net: number; remaining_net: number; forecast_net: number;
  locked_in: number; support_forecast: number;
  basis_share: { inventory_pct: number; run_rate_pct: number; fixed_pct: number };
  last_month_total: number | null; delta_pct: number | null;
  services: ForecastService[]; categories: ForecastCategory[];
  movers: { service: string; delta: number; forecast: number; last_month: number }[];
  assumptions: string[];
}

const round2 = (n: number) => Math.round(n * 100) / 100;
const SP_FEE_SERVICE = /^Savings Plans for /;
const SUPPORT_SERVICE = /Support/;
const TAX_SERVICE = /^Tax$/;

/** Which inventory-priced bucket a usage line belongs to, or null for a usage-based line. */
export function categoryOf(l: { service: string; usage_type: string; rule: string | null }): string | null {
  const u = l.usage_type.replace(/^[A-Z]{2,4}\d-/, "");
  if (/Elastic Compute Cloud/.test(l.service) && /^(BoxUsage|DedicatedUsage)/.test(u)) return "ec2_compute";
  if (/^EBS:Volume/.test(u)) return "ebs";
  if (/Simple Storage/.test(l.service) && /^TimedStorage/.test(u)) return "s3_storage";
  if (/Relational Database/.test(l.service) && /(InstanceUsage|Multi-AZUsage)/.test(u)) return "rds_instances";
  if (/ElastiCache/.test(l.service) && /NodeUsage/.test(u)) return "cache_nodes";
  if (/Lambda/.test(l.service) && /^(Lambda-GB-Second|Request)/.test(u)) return "lambda";
  return null;
}

export function computeForecast(input: ForecastInput, now = new Date()): Forecast {
  const elapsed = Math.max(1, input.elapsed_days);
  const remaining = Math.max(0, input.days_in_month - elapsed);
  const r = input.records;
  const ratio = (ls: PricedLine[]) => { const od = ls.reduce((s, l) => s + l.actual_od, 0); const net = ls.reduce((s, l) => s + l.net, 0); return od > 1 ? Math.min(1, Math.max(0, net / od)) : 1; };
  const sum = (ls: PricedLine[]) => ls.reduce((s, l) => s + l.net, 0);
  const byCat = new Map<string, PricedLine[]>();
  for (const l of input.lines) { const c = categoryOf(l) ?? "usage"; byCat.set(c, [...(byCat.get(c) || []), l]); }
  const get = (c: string) => byCat.get(c) || [];
  // Savings Plan: the fee is fixed; it covers on-demand value up to fee / (1 - discount) per hour, EC2 first
  const rate = input.sp_discount_rate > 0 && input.sp_discount_rate < 1 ? input.sp_discount_rate : 0;
  const spHourly = input.sp_hourly ?? (elapsed > 0 ? r.sp_fee / (elapsed * 24) : 0);
  const coveredCapHourly = spHourly > 0 && rate > 0 ? spHourly / (1 - rate) : 0;
  const ec2NetHourly = Math.max(0, input.now.ec2_od_hourly - coveredCapHourly);
  const categories: ForecastCategory[] = [];
  const cat = (key: string, label: string, basis: Basis, perDay: number, detail: string) => {
    const ls = get(key); const mtd = sum(ls);
    categories.push({ key, label, basis, mtd: round2(mtd), mtd_per_day: round2(mtd / elapsed), per_day: round2(perDay), remaining: round2(perDay * remaining), detail });
  };
  cat("ec2_compute", "EC2 instances", "inventory", ec2NetHourly * 24,
    `${input.now.ec2_running} running at ${round2(input.now.ec2_od_hourly)} USD/h on demand${coveredCapHourly > 0 ? `; the Savings Plan covers ${round2(coveredCapHourly)} USD/h of it` : ""}`);
  cat("ebs", "EBS volumes", "inventory", input.now.ebs_month / input.days_in_month, `volumes as they are now, ${round2(input.now.ebs_month)} USD a month at list`);
  cat("s3_storage", "S3 storage", "inventory", input.now.s3_month / input.days_in_month, `buckets as they are now, ${round2(input.now.s3_month)} USD a month at list`);
  const rdsRatio = ratio(get("rds_instances")); const cacheRatio = ratio(get("cache_nodes")); const lambdaRatio = ratio(get("lambda"));
  // reservations: two estimates of what is left to pay on demand, the month's own billed share (catches reservations the
  // list misses) and the reservation list against the inventory (catches ones bought late in the month); the lower wins
  const toPay = (od: number, reserved: number | null, billedRatio: number): { hourly: number; how: string } => {
    const billed = od * billedRatio; const listed = reserved != null ? Math.max(0, od - reserved) : null;
    return listed != null && listed < billed ? { hourly: listed, how: `reservations cover ${round2(reserved!)} USD/h of it` } : { hourly: billed, how: `reservations leave ${Math.round(billedRatio * 100)} % of it to pay, as billed so far` };
  };
  const rdsPay = toPay(input.now.rds_od_hourly, input.now.rds_reserved_hourly, rdsRatio);
  const cachePay = toPay(input.now.cache_od_hourly, input.now.cache_reserved_hourly, cacheRatio);
  cat("rds_instances", "RDS instances", "inventory", rdsPay.hourly * 24, `${round2(input.now.rds_od_hourly)} USD/h on demand, ${rdsPay.how}`);
  cat("cache_nodes", "ElastiCache nodes", "inventory", cachePay.hourly * 24, `${round2(input.now.cache_od_hourly)} USD/h on demand, ${cachePay.how}`);
  cat("lambda", "Lambda", "inventory", (input.now.lambda_month / 30) * lambdaRatio, `30-day rate of the functions, ${round2(input.now.lambda_month)} USD a month at list, ${Math.round(lambdaRatio * 100)} % of it to pay`);
  const usageLines = get("usage");
  cat("usage", "Usage-based lines", "run_rate", sum(usageLines) / elapsed, `${usageLines.length} lines (transfer, NAT, CloudWatch, requests, snapshots) at their month-to-date daily average`);
  // fixed legs from the record totals
  const spFeeRemaining = spHourly * 24 * remaining;
  const riPerDay = r.ri_amortized / elapsed;
  categories.push({ key: "sp_fee", label: "Savings Plan fee", basis: "fixed", mtd: round2(r.sp_fee), mtd_per_day: round2(r.sp_fee / elapsed), per_day: round2(spHourly * 24), remaining: round2(spFeeRemaining), detail: `${round2(spHourly)} USD/h committed` });
  categories.push({ key: "reservations", label: "Reservations", basis: "fixed", mtd: round2(r.ri_amortized), mtd_per_day: round2(riPerDay), per_day: round2(riPerDay), remaining: round2(riPerDay * remaining), detail: "amortized, at the month-to-date rate" });
  // charges before support and tax
  const usageRemaining = categories.filter((c) => c.key !== "sp_fee" && c.key !== "reservations").reduce((s, c) => s + c.remaining, 0);
  const chargesMtd = input.lines.reduce((s, l) => s + l.net, 0) + r.sp_fee;
  const chargesForecast = chargesMtd + usageRemaining + spFeeRemaining;
  const supportForecast = r.support > 0 ? round2(businessSupport(chargesForecast)) : 0;
  const supportRemaining = Math.max(0, supportForecast - r.support);
  categories.push({ key: "support", label: "Support", basis: "fixed", mtd: round2(r.support), mtd_per_day: round2(r.support / elapsed), per_day: round2(supportRemaining / Math.max(1, remaining)), remaining: round2(supportRemaining), detail: r.support > 0 ? "Business Support tiers on the month's charges" : "no support plan" });
  const taxPerDay = r.tax / elapsed;
  categories.push({ key: "tax", label: "Tax", basis: "run_rate", mtd: round2(r.tax), mtd_per_day: round2(taxPerDay), per_day: round2(taxPerDay), remaining: round2(taxPerDay * remaining), detail: "as billed so far, pro rata" });
  const remainingNet = categories.reduce((s, c) => s + c.remaining, 0);
  const mtdNet = r.net_total;
  const forecastNet = round2(mtdNet + remainingNet);
  // per service: month to date as billed, remaining from the categories its lines fall in (fee, support and tax as their own services)
  const services = new Map<string, { mtd: number; remaining: number; bases: Set<Basis> }>();
  const add = (service: string, mtd: number, rem: number, basis: Basis) => { const e = services.get(service) ?? { mtd: 0, remaining: 0, bases: new Set() }; e.mtd += mtd; e.remaining += rem; e.bases.add(basis); services.set(service, e); };
  for (const c of categories) {
    if (["sp_fee", "reservations", "support", "tax"].includes(c.key)) continue;
    const ls = get(c.key); const catMtd = sum(ls);
    // split a category's remaining across its services in proportion to their month-to-date net (one service almost always)
    const byService = new Map<string, number>(); for (const l of ls) byService.set(l.service, (byService.get(l.service) || 0) + l.net);
    if (!byService.size) continue;
    for (const [service, mtd] of byService) { const share = catMtd > 0 ? mtd / catMtd : 1 / byService.size; add(service, mtd, c.remaining * share, c.basis); }
  }
  add("Savings Plans for AWS Compute usage", r.sp_fee, spFeeRemaining, "fixed");
  if (r.support > 0) add("AWS Support", r.support, supportRemaining, "fixed");
  if (r.tax !== 0) add("Tax", r.tax, taxPerDay * remaining, "run_rate");
  const lastServices = input.last_month?.services ?? {};
  const lastKey = (service: string) => Object.keys(lastServices).find((k) => k === service || (SP_FEE_SERVICE.test(service) && SP_FEE_SERVICE.test(k)) || (SUPPORT_SERVICE.test(service) && SUPPORT_SERVICE.test(k)) || (TAX_SERVICE.test(service) && TAX_SERVICE.test(k)));
  const serviceRows: ForecastService[] = [...services.entries()].map(([service, e]) => {
    const forecast = round2(e.mtd + e.remaining);
    const lk = input.last_month ? lastKey(service) : undefined; const last = lk != null ? lastServices[lk] : input.last_month ? 0 : null;
    const basis: Basis = e.bases.size === 1 ? [...e.bases][0] : "mixed";
    return { service, mtd: round2(e.mtd), per_day: round2(e.remaining / Math.max(1, remaining)), remaining: round2(e.remaining), forecast, basis, last_month: last != null ? round2(last) : null, delta: last != null ? round2(forecast - last) : null };
  }).sort((a, b) => b.forecast - a.forecast);
  // services billed last month that have nothing this month yet
  if (input.last_month) for (const [k, v] of Object.entries(lastServices)) if (v >= 1 && !serviceRows.some((s) => lastKey(s.service) === k)) serviceRows.push({ service: k, mtd: 0, per_day: 0, remaining: 0, forecast: 0, basis: "run_rate", last_month: round2(v), delta: round2(-v) });
  const movers = serviceRows.filter((s) => s.delta != null && Math.abs(s.delta) >= 20).sort((a, b) => Math.abs(b.delta!) - Math.abs(a.delta!)).slice(0, 8).map((s) => ({ service: s.service, delta: s.delta!, forecast: s.forecast, last_month: s.last_month! }));
  const lockedIn = round2(spHourly * 24 * input.days_in_month + riPerDay * input.days_in_month + supportForecast);
  const byBasis = (b: Basis) => categories.filter((c) => c.basis === b).reduce((s, c) => s + c.remaining, 0);
  const share = (b: Basis) => (remainingNet > 0 ? round2((byBasis(b) / remainingNet) * 100) : 0);
  const lastTotal = input.last_month?.total ?? null;
  return {
    month: input.month, computed_at: now.toISOString(), elapsed_days: elapsed, remaining_days: remaining, days_in_month: input.days_in_month,
    mtd_net: round2(mtdNet), remaining_net: round2(remainingNet), forecast_net: forecastNet,
    locked_in: lockedIn, support_forecast: supportForecast,
    basis_share: { inventory_pct: share("inventory"), run_rate_pct: share("run_rate"), fixed_pct: share("fixed") },
    last_month_total: lastTotal != null ? round2(lastTotal) : null, delta_pct: lastTotal ? round2(((forecastNet - lastTotal) / lastTotal) * 100) : null,
    services: serviceRows, categories, movers,
    assumptions: [
      `Month to date is what Cost Explorer has for ${elapsed} complete day${elapsed === 1 ? "" : "s"}; the remaining ${remaining} are priced from the inventory as it is now (instances, databases, cache nodes, volumes, buckets, functions), usage-based lines at their month-to-date daily average, and the commitments and support as fixed.`,
      `The Savings Plan fee is fixed (${round2(spHourly)} USD/h); at its ${Math.round(rate * 100)} % discount it covers ${round2(coveredCapHourly)} USD/h of on-demand compute, and only compute above that is paid on demand. Reservations are taken at their month-to-date amortized rate and the instances and nodes they cover cost nothing more; what is left is priced on demand.`,
      "Spot instances are billed at market price and stay in the usage-based leg; Batch workers count while they run, so the compute leg moves with the queue.",
      "Support is the Business Support tier formula on the forecast charges; tax is pro rata of what was billed so far.",
    ],
  };
}

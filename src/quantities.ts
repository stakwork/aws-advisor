/**
 * Usage quantities from the advisor's own history, independent of Cost Explorer: instance hours per type from
 * the watcher's running_by_type samples, EBS GB-days from its ebs_total_gb samples, NAT GB from its hourly
 * gateway bytes, log GB from the metered ingestion. Priced with the same pricebook and price cache as the bill
 * reconstruction and set beside what Cost Explorer reports for the same days. This is the step that makes the
 * reconstruction independent: when both quantity and price come from our knowledge and still explain the bill,
 * the graph is right. History starts when the watcher started, so the window is "this month so far".
 */
import { db } from "./db.js";
import { S, query } from "./steampipe.js";
import { priceRuleFor, PriceRule, SkuRule } from "./pricebook.js";
import { getCachedPrice } from "./prices.js";
import { credentialGate } from "./gate.js";
import { describeError } from "./permissions.js";

export interface SamplePoint { t: number; value: number }

/** Hours represented by a series of point-in-time counts: each sample stands for the gap to the next one, capped at one hour (a gap in sampling is not usage we saw). */
export function hoursFromSamples(points: SamplePoint[], capHours = 1): number {
  const s = [...points].sort((a, b) => a.t - b.t);
  let hours = 0;
  for (let i = 0; i < s.length; i++) {
    const next = s[i + 1]?.t;
    const gap = next != null ? Math.min(capHours, (next - s[i].t) / 3600e3) : Math.min(capHours, 0.5);
    hours += s[i].value * gap;
  }
  return hours;
}

export interface QuantitiesResult { from: string; to: string; days_with_history: number; coverage_hours: number; coverage_pct: number; lines: QuantityLine[]; computed_at: string; ce_error?: string }
export interface QuantityLine { category: string; unit: string; history_qty: number; history_qty_scaled: number | null; ce_qty: number | null; coverage_days: number; unit_price: number | null; history_usd: number | null; ce_usd: number | null; note: string }

const addDay = (d: string) => { const x = new Date(`${d}T00:00:00Z`); x.setUTCDate(x.getUTCDate() + 1); return x.toISOString().slice(0, 10); };
const lit = (s: string) => `'${String(s).replace(/'/g, "''")}'`;
let cache: { key: string; at: number; value: QuantitiesResult } | null = null;

export async function quantitiesFromHistory(from: string, to: string): Promise<QuantitiesResult> {
  const key = `${from}|${to}`;
  if (cache && cache.key === key && Date.now() - cache.at < 6 * 3600e3) return cache.value;
  const fromIso = `${from}T00:00:00Z`; const toIso = `${to}T00:00:00Z`;
  const samples = db.prepare("select key, label, value, collected_at from watch_samples where key in ('running_by_type', 'ebs_total_gb', 'nat_bytes_hour') and collected_at >= ? and collected_at < ? order by collected_at").all(fromIso, toIso) as { key: string; label: string; value: number; collected_at: string }[];
  const days = new Set(samples.map((s) => s.collected_at.slice(0, 10)));
  const byType = new Map<string, SamplePoint[]>(); const ebs: SamplePoint[] = []; const natByHour = new Map<string, number>();
  for (const s of samples) {
    const t = Date.parse(s.collected_at);
    if (s.key === "running_by_type") byType.set(s.label, [...(byType.get(s.label) || []), { t, value: s.value }]);
    else if (s.key === "ebs_total_gb") ebs.push({ t, value: s.value });
    else if (s.key === "nat_bytes_hour") { const h = `${s.label}|${s.collected_at.slice(0, 13)}`; natByHour.set(h, Math.max(natByHour.get(h) || 0, s.value)); }
  }
  // the comparison is only fair over the days the watcher saw
  // Cost Explorer's newest day is still filling in, so the comparison stops before yesterday
  const yesterday = addDay(new Date(Date.now() - 2 * 86400e3).toISOString().slice(0, 10));
  const dayList = [...days].filter((d) => d < yesterday).sort(); const effFrom = dayList[0] || from; const effTo = dayList.length ? addDay(dayList[dayList.length - 1]) : to;
  for (const [k, pts] of byType) byType.set(k, pts.filter((p) => new Date(p.t).toISOString().slice(0, 10) < yesterday));
  const ebsIn = ebs.filter((p) => new Date(p.t).toISOString().slice(0, 10) < yesterday);
  for (const k of [...natByHour.keys()]) if (k.slice(k.indexOf("|") + 1, k.indexOf("|") + 11) >= yesterday) natByHour.delete(k);
  const coverageHours = hoursFromSamples(dayList.length ? [...ebsIn.map((p) => ({ t: p.t, value: 1 }))] : []);
  const windowHours = dayList.length * 24; const coverage = windowHours ? Math.min(1, coverageHours / windowHours) : 0;
  const natGb = [...natByHour.values()].reduce((a, b) => a + b, 0) / 1e9;
  const ebsGbMonth = hoursFromSamples(ebsIn) / 730; // GB-hours -> GB-months
  const logGb = (db.prepare("select sum(bytes) as b from log_ingest_daily where name like '__total__/%' and day >= ? and day < ?").get(effFrom, effTo) as { b: number | null }).b ?? null;
  // Cost Explorer for the same days
  let ce = new Map<string, { qty: number; usd: number }>(); let ceError: string | undefined;
  if ((await credentialGate("quantities")).ok) {
    try {
      const rows = await query<{ usage_type: string; qty: string; usd: string }>(`select usage_type, sum(usage_quantity_amount) as qty, sum(net_unblended_cost_amount) as usd
        from ${S}.aws_cost_by_service_usage_type_daily where period_start >= ${lit(effFrom)} and period_start < ${lit(effTo)}
          and (usage_type like '%BoxUsage:%' or usage_type like '%EBS:VolumeUsage%' or usage_type like '%NatGateway-Bytes' or usage_type like '%DataProcessing-Bytes') group by 1`);
      for (const r of rows) ce.set(r.usage_type.replace(/^[A-Z]{2,4}\d?-/, ""), { qty: Number(r.qty), usd: Number(r.usd) });
    } catch (e) { ceError = describeError(e, "quantities (aws_cost_by_service_usage_type_daily)"); }
  } else ceError = "credentials not working";
  const lines: QuantityLine[] = [];
  const region = "us-east-1";
  for (const [type, pts] of [...byType.entries()].sort((a, b) => b[1].length - a[1].length)) {
    const hours = hoursFromSamples(pts);
    const price = getCachedPrice("ec2", type, region, "Linux")?.hourly ?? null;
    const c = ce.get(`BoxUsage:${type}`);
    lines.push({ category: `EC2 hours ${type}`, unit: "Hrs", history_qty_scaled: null, history_qty: Math.round(hours * 10) / 10, ce_qty: c ? Math.round(c.qty * 10) / 10 : null, coverage_days: days.size, unit_price: price, history_usd: price != null ? Math.round(hours * price * 100) / 100 : null, ce_usd: c ? Math.round(c.usd * 100) / 100 : null, note: "running count sampled every 30 min × elapsed time; CE counts every on-demand hour, covered or not, so its cost is after the Savings Plan" });
  }
  const ebsRule = priceRuleFor("EC2 - Other", "EBS:VolumeUsage.gp3") as PriceRule | null;
  const ceEbs = [...ce.entries()].filter(([k]) => k.startsWith("EBS:VolumeUsage")).reduce((a, [, v]) => ({ qty: a.qty + v.qty, usd: a.usd + v.usd }), { qty: 0, usd: 0 });
  lines.push({ category: "EBS volume GB-months (all types, priced as gp3)", unit: "GB-Mo", history_qty_scaled: null, history_qty: Math.round(ebsGbMonth * 10) / 10, ce_qty: ce.size ? Math.round(ceEbs.qty * 10) / 10 : null, coverage_days: days.size, unit_price: ebsRule?.unit_price ?? null, history_usd: ebsRule ? Math.round(ebsGbMonth * ebsRule.unit_price * 100) / 100 : null, ce_usd: ce.size ? Math.round(ceEbs.usd * 100) / 100 : null, note: "total attached GB sampled every 30 min; CE bills every volume including detached ones" });
  const natRule = priceRuleFor("EC2 - Other", "NatGateway-Bytes") as PriceRule | null; const ceNat = ce.get("NatGateway-Bytes");
  lines.push({ category: "NAT gateway GB processed", unit: "GB", history_qty_scaled: null, history_qty: Math.round(natGb * 10) / 10, ce_qty: ceNat ? Math.round(ceNat.qty * 10) / 10 : null, coverage_days: days.size, unit_price: natRule?.unit_price ?? null, history_usd: natRule ? Math.round(natGb * natRule.unit_price * 100) / 100 : null, ce_usd: ceNat ? Math.round(ceNat.usd * 100) / 100 : null, note: "in + out bytes per gateway per hour from CloudWatch, one value per hour" });
  const logRule = priceRuleFor("AmazonCloudWatch", "DataProcessing-Bytes") as PriceRule | null; const ceLog = ce.get("DataProcessing-Bytes");
  if (logGb != null) lines.push({ category: "CloudWatch Logs GB ingested", unit: "GB", history_qty_scaled: null, history_qty: Math.round((logGb / 1e9) * 10) / 10, ce_qty: ceLog ? Math.round(ceLog.qty * 10) / 10 : null, coverage_days: days.size, unit_price: logRule?.unit_price ?? null, history_usd: logRule ? Math.round((logGb / 1e9) * logRule.unit_price * 100) / 100 : null, ce_usd: ceLog ? Math.round(ceLog.usd * 100) / 100 : null, note: "account total IncomingBytes per day" });
  // log ingestion is a complete daily figure, not a sample: it is not scaled
  for (const l of lines) l.history_qty_scaled = l.category.startsWith("CloudWatch Logs") ? l.history_qty : coverage > 0 ? Math.round((l.history_qty / coverage) * 10) / 10 : null;
  const value: QuantitiesResult = { from: effFrom, to: effTo, days_with_history: dayList.length, coverage_hours: Math.round(coverageHours * 10) / 10, coverage_pct: Math.round(coverage * 1000) / 10, lines, computed_at: new Date().toISOString(), ...(ceError ? { ce_error: ceError } : {}) };
  cache = { key, at: Date.now(), value };
  return value;
}

import { enabled, neoParams, writeCypher } from "../../graph_mirror.js";
import { planLinePrice } from "./client.js";
import { listInvoices, listProjects, listStores, teamBilling, vercelTeam, type StoreRow } from "./inventory.js";
import { usageTotals } from "./usage.js";
import { VERCEL, vercelAdapter } from "./index.js";

/**
 * Vercel's prices as pricing knowledge, the same shapes AWS fills from its pricing API and the pricebook:
 *
 * - `KnSystemType {kind: usage}` per metered item the team object lists (`billing.invoiceItems`, cents per unit):
 *   the team's own list price for function invocations, GB-hours, data transfer, builds, blob, logs, ...;
 * - `KnSystemType {kind: plan}` for the Pro plan (the seat price and the base fee) and, per marketplace plan a store is
 *   on (Neon Launch, Redis Free), one type per price line ("$0.35 per GB-month", "$0.106 per CU-hour") plus one
 *   plan type carrying the non-price lines as `included` (30 MB, 100 projects, 16 CU);
 * - `KnSystemType {source: invoice}` for what the last paid invoice actually charged per unit, line by line: the
 *   observed price, next to the listed one;
 * - `KnPricingOverlay {kind: plan}` for the team's subscription (seats, period, included allocation) and for each
 *   store's plan, COVERS the types above;
 * - `KnSystem` per project (kind deployment) and per store (database / cache / storage), MEMBER_OF from the resource,
 *   RUNS_ON the usage types with last month's quantity and what it costs at list: the project's `monthly_list_usd`
 *   before the plan's included allocation, the store's from the marketplace usage the store object reports
 *   (Neon compute hours this period) or the blob size.
 *
 * Nothing here is a forecast: the quantities are the last 30 days of metered usage, the prices the ones Vercel states.
 */

/** Which usage number pays which metered item, and in what unit the item is priced. */
const USAGE_TO_ITEM: { item: string; label: string; qty: (t: ReturnType<typeof usageTotals>) => number; unit: string }[] = [
  { item: "functionInvocation", label: "function invocations", qty: (t) => t.invocations, unit: "each" },
  { item: "fluidDuration", label: "function GB-hours (provisioned memory)", qty: (t) => t.gb_hours, unit: "GB-hour" },
  { item: "edgeRequest", label: "edge requests", qty: (t) => t.requests, unit: "each" },
  { item: "fastDataTransfer", label: "data transfer out", qty: (t) => t.bandwidth_out_gb, unit: "GB" },
  { item: "buildCpuMinutes", label: "build minutes", qty: (t) => t.build_minutes, unit: "minute" },
  { item: "logDrainsVolume", label: "log drain volume", qty: (t) => t.log_gb, unit: "GB" },
  { item: "blobTotalSimpleRequests", label: "blob simple requests", qty: (t) => t.blob_requests, unit: "each" },
];

const slug = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_|_$/g, "");
/** camelCase item keys as words: functionInvocation → function invocation. */
export const itemLabel = (item: string) => item.replace(/([a-z])([A-Z])/g, "$1 $2").replace(/_/g, " ").toLowerCase();
const r2 = (n: number) => Math.round(n * 100) / 100;

export interface RateRow { item: string; label: string; usd: number; unit: string; source: "team_billing" | "marketplace_plan" | "invoice"; store?: string; product?: string | null; plan?: string | null; quantity?: number | null; amount?: number | null; invoice?: string | null }

/** Every rate the advisor knows for the team: the listed metered items, the marketplace plans' lines and the invoice-observed ones. */
export function vercelRates(teamId: string | null) {
  const b = teamId ? teamBilling(teamId) : null;
  const team_rates: RateRow[] = (b?.rates ?? []).filter((r) => r.usd > 0 && !/^(pro|hobby|enterprise)$/.test(r.item)).map((r) => ({ item: r.item, label: itemLabel(r.item), usd: r.usd, unit: r.unit, source: "team_billing" as const })).sort((x, y) => x.label.localeCompare(y.label));
  const base = (b?.rates ?? []).find((r) => /^(pro|hobby|enterprise)$/.test(r.item)) ?? null;
  const included = (b?.rates ?? []).find((r) => /includedallocation/i.test(r.item)) ?? null;
  const plan = b ? { plan: b.plan, status: b.status, seats: b.seats, seat_usd: b.seat_usd, base_usd_month: base?.usd ?? null, seats_usd_month: b.seats != null && b.seat_usd != null ? r2(b.seats * b.seat_usd) : null, included_usage_usd: included?.quantity ?? null, period_start: b.period_start, period_end: b.period_end } : null;
  const store_plans = listStores().filter((st) => st.plan || st.details.plan_lines.length).map((st) => ({
    store_id: st.id, store: st.name, kind: st.kind, product: st.product, product_slug: st.product_slug, plan: st.plan, plan_id: st.details.plan_id, scope: st.details.plan_scope, cost: st.details.plan_cost, description: st.details.plan_description,
    lines: st.details.plan_lines.map((l) => ({ ...l, price: planLinePrice(l.value) })),
  }));
  const last = listInvoices(12).find((i) => i.status === "paid") ?? null;
  const observed: RateRow[] = last ? last.line_items.filter((l) => l.quantity && l.amount).map((l) => ({ item: `invoice:${slug(l.title)}`, label: l.title, usd: Math.round((l.amount / (l.quantity || 1)) * 1e7) / 1e7, unit: "each", source: "invoice" as const, quantity: l.quantity, amount: l.amount, invoice: last.number })) : [];
  return { plan, team_rates, store_plans, observed, invoice: last ? { number: last.number, created_at: last.created_at } : null };
}

/** What a project's last 30 days cost at the team's listed rates, item by item (before the plan's included allocation). */
export function projectListCost(teamId: string, projectId: string, days = 30): { monthly_list_usd: number; lines: { item: string; label: string; quantity: number; unit: string; usd: number; usd_month: number }[] } {
  const b = teamBilling(teamId); const rates = new Map((b?.rates ?? []).map((r) => [r.item, r]));
  const t = usageTotals(teamId, days, projectId); const scale = 30 / Math.max(1, Math.min(days, t.days || days));
  const lines = USAGE_TO_ITEM.flatMap(({ item, label, qty, unit }) => { const r = rates.get(item); const q = qty(t); if (!r || !q) return []; return [{ item, label, quantity: r2(q * scale), unit, usd: r.usd, usd_month: r2(q * scale * r.usd) }]; });
  return { monthly_list_usd: r2(lines.reduce((n, l) => n + l.usd_month, 0)), lines };
}

/** What a store costs at its plan's rates from the usage its object reports (Neon compute hours this period) or its size (blob). */
export function storeListCost(teamId: string, st: StoreRow): { monthly_list_usd: number | null; lines: { label: string; quantity: number; unit: string; usd: number; usd_month: number }[]; period: { start: string | null; end: string | null } | null } {
  const lines: { label: string; quantity: number; unit: string; usd: number; usd_month: number }[] = [];
  const prices = st.details.plan_lines.map((l) => ({ ...l, price: planLinePrice(l.value) })).filter((l) => l.price);
  const up = st.details.usage_period;
  if (up?.items.length) {
    const elapsed = up.start ? Math.max(1, (Date.now() - Date.parse(up.start)) / 86_400_000) : 30; const scale = 30 / Math.min(30, elapsed);
    for (const u of up.items) {
      if (!u.period_value) continue;
      const p = prices.find((l) => (/compute/i.test(u.name) && /compute|cu-hour/i.test(l.label + l.value)) || (/storage/i.test(u.name) && /storage/i.test(l.label)) || l.label.toLowerCase() === u.name.toLowerCase());
      if (p?.price) lines.push({ label: `${u.name} (${u.units || p.price.unit})`, quantity: r2(u.period_value * scale), unit: p.price.unit, usd: p.price.usd, usd_month: r2(u.period_value * scale * p.price.usd) });
    }
  }
  if (st.type === "blob" && st.details.size_bytes != null) {
    const b = teamBilling(teamId); const rate = (b?.rates ?? []).find((r) => r.item === "blobTotalAvgSizeInBytes");
    if (rate) lines.push({ label: "blob storage (GB-month)", quantity: r2(st.details.size_bytes / 1e9), unit: "GB-month", usd: rate.usd, usd_month: r2((st.details.size_bytes / 1e9) * rate.usd) });
  }
  return { monthly_list_usd: lines.length ? r2(lines.reduce((n, l) => n + l.usd_month, 0)) : null, lines, period: up ? { start: up.start, end: up.end } : null };
}

const KIND_OF_STORE = { database: "database", cache: "cache", storage: "storage", other: "storage" } as const;

/** The knowledge layer for the team: types, overlays and systems, as the AWS knowledge mirror writes them. */
export async function mirrorVercelPricing(): Promise<{ types: number; overlays: number; systems: number }> {
  if (!enabled()) return { types: 0, overlays: 0, systems: 0 };
  const team = vercelTeam(); const account = team?.id ?? vercelAdapter.primaryAccountId(); const now = new Date().toISOString(); const today = now.slice(0, 10);
  const rates = vercelRates(account);
  const types: any[] = []; const overlays: any[] = []; const systems: any[] = [];
  for (const r of rates.team_rates) types.push({ id: `vercel|usage|${r.item}|global`, provider: VERCEL, kind: "usage", native_kind: "vercel_metered", sku: r.item, region: "global", engine: null, list_price: r.usd, price_unit: `USD/${r.unit}`, unit: r.unit, source: "team_billing", valid_from: today, note: r.label });
  for (const o of rates.observed) types.push({ id: `vercel|usage|${o.item}|global`, provider: VERCEL, kind: "usage", native_kind: "vercel_invoice_line", sku: o.item, region: "global", engine: null, list_price: o.usd, price_unit: "USD/each", unit: "each", source: "invoice", valid_from: o.invoice ? String(rates.invoice?.created_at ?? today).slice(0, 10) : today, note: `${o.label}: ${o.quantity} for $${o.amount} on invoice ${o.invoice ?? "?"}` });
  if (rates.plan) {
    const planId = `vercel|plan|${rates.plan.plan ?? "plan"}|global`;
    types.push({ id: planId, provider: VERCEL, kind: "plan", native_kind: `vercel_${rates.plan.plan ?? "plan"}`, sku: rates.plan.plan, region: "global", engine: null, list_price: rates.plan.seat_usd, price_unit: "USD/seat-month", unit: "seat-month", source: "team_billing", valid_from: today, note: rates.plan.base_usd_month != null ? `base $${rates.plan.base_usd_month}/month plus seats` : null, included: JSON.stringify({ included_usage_usd: rates.plan.included_usage_usd }) });
    overlays.push({ id: `plan:vercel:${account}`, provider: VERCEL, account_id: account, kind: "plan", covers_kind: "usage", sku: rates.plan.plan, count: rates.plan.seats, commitment_usd_month: r2((rates.plan.base_usd_month ?? 0) + (rates.plan.seats_usd_month ?? 0)), included: JSON.stringify({ seats: rates.plan.seats, included_usage_usd: rates.plan.included_usage_usd }), start: rates.plan.period_start, end: rates.plan.period_end, covers_ids: [planId, ...rates.team_rates.map((r) => `vercel|usage|${r.item}|global`)] });
  }
  for (const sp of rates.store_plans) {
    const kind = KIND_OF_STORE[sp.kind]; const base = `vercel|${kind}|${sp.product_slug ?? "store"}:${sp.plan_id ?? slug(sp.plan ?? "plan")}`;
    const priced = sp.lines.filter((l) => l.price); const quotas = sp.lines.filter((l) => !l.price);
    const ids = [`${base}|global`, ...priced.map((l) => `${base}:${slug(l.label)}|global`)];
    types.push({ id: `${base}|global`, provider: VERCEL, kind, native_kind: "marketplace_plan", sku: sp.plan_id ?? sp.plan, region: "global", engine: sp.product_slug, list_price: null, price_unit: null, unit: null, source: "marketplace_plan", valid_from: today, note: `${sp.product} ${sp.plan}${sp.cost ? ` (${sp.cost.replace(/^—\s*/, "")})` : ""}`, included: JSON.stringify(Object.fromEntries(quotas.map((l) => [l.label, l.value]))) });
    for (const l of priced) types.push({ id: `${base}:${slug(l.label)}|global`, provider: VERCEL, kind, native_kind: "marketplace_plan_rate", sku: sp.plan_id ?? sp.plan, region: "global", engine: sp.product_slug, list_price: l.price!.usd, price_unit: `USD/${l.price!.unit}`, unit: l.price!.unit, source: "marketplace_plan", valid_from: today, note: `${sp.product} ${sp.plan}: ${l.label}` });
    overlays.push({ id: `plan:vercel:${sp.store_id}`, provider: VERCEL, account_id: account, kind: "plan", covers_kind: kind, sku: sp.plan_id ?? sp.plan, engine: sp.product_slug, count: 1, commitment_usd_month: null, included: JSON.stringify(Object.fromEntries(quotas.map((l) => [l.label, l.value]))), start: null, end: null, covers_ids: ids, store_id: sp.store_id });
  }
  // systems: the projects at the team's rates, the stores at their plans
  const typeIds = new Set(types.map((t) => t.id));
  for (const p of listProjects()) {
    const cost = projectListCost(account, p.id);
    systems.push({ id: `vercel_project:${p.name}`, name: p.name, kind: "deployment", native_kind: "vercel_project", archetype: "web_or_api", member_count: 1, members: [p.id], region: "global", monthly_list_usd: cost.monthly_list_usd, usage_units: JSON.stringify(Object.fromEntries(cost.lines.map((l) => [l.item, l.quantity]))),
      types: cost.lines.map((l) => ({ id: `vercel|usage|${l.item}|global`, count: l.quantity, hours_month: null, list_price: l.usd, list_usd_month: l.usd_month })).filter((t) => typeIds.has(t.id)) });
  }
  for (const st of listStores()) {
    const kind = KIND_OF_STORE[st.kind]; const cost = storeListCost(account, st);
    const base = `vercel|${kind}|${st.product_slug ?? "store"}:${st.details.plan_id ?? slug(st.plan ?? "plan")}`;
    const planType = typeIds.has(`${base}|global`) ? [{ id: `${base}|global`, count: 1, hours_month: null, list_price: null, list_usd_month: cost.monthly_list_usd }] : [];
    systems.push({ id: `vercel_store:${st.name}`, name: st.name, kind: kind === "storage" ? "storage" : kind, native_kind: "vercel_store", archetype: kind === "cache" ? "cache_or_queue" : kind === "database" ? "database" : "unknown", member_count: 1, members: [st.id], region: st.region ?? "global", monthly_list_usd: cost.monthly_list_usd, usage_units: JSON.stringify(Object.fromEntries(cost.lines.map((l) => [l.label, l.quantity]))), types: planType });
  }
  if (types.length) await writeCypher(`UNWIND $rows AS row MERGE (t:KnSystemType {id: row.id}) SET t += row, t.updated_at = $now`, { rows: types, now });
  if (overlays.length) await writeCypher(`
UNWIND $rows AS row
MERGE (o:KnPricingOverlay {id: row.id}) SET o += row, o.updated_at = $now
WITH o, row
OPTIONAL MATCH (o)-[c:COVERS]->() DELETE c
WITH DISTINCT o, row
UNWIND row.covers_ids AS tid
MATCH (t:KnSystemType {id: tid}) MERGE (o)-[:COVERS]->(t)`, { rows: overlays.map((o) => ({ ...o, covers_ids: o.covers_ids })), now });
  if (systems.length) await writeCypher(`
UNWIND $rows AS row
MERGE (s:KnSystem {id: row.id})
SET s += {name: row.name, kind: row.kind, native_kind: row.native_kind, archetype: row.archetype, member_count: row.member_count, region: row.region, monthly_list_usd: row.monthly_list_usd, usage_units: row.usage_units, provider: $provider, account_id: $account, native_type: 'system', native_id: row.id, gone: false, updated_at: $now}
WITH s, row
OPTIONAL MATCH (a:AdvisorAccount {id: $account}) FOREACH (_ IN CASE WHEN a IS NULL THEN [] ELSE [1] END | MERGE (s)-[:IN_ACCOUNT]->(a))
WITH s, row
OPTIONAL MATCH (s)-[old:IS_A]->() DELETE old
WITH DISTINCT s, row
OPTIONAL MATCH (arch:KnArchetype {id: row.archetype}) FOREACH (_ IN CASE WHEN arch IS NULL THEN [] ELSE [1] END | MERGE (s)-[:IS_A]->(arch))
WITH s, row
OPTIONAL MATCH (s)-[ro:RUNS_ON]->() DELETE ro
WITH DISTINCT s, row
FOREACH (t IN row.types | MERGE (st:KnSystemType {id: t.id}) MERGE (s)-[r:RUNS_ON]->(st) SET r.count = t.count, r.hours_month = t.hours_month, r.list_price = t.list_price, r.list_usd_month = t.list_usd_month)
WITH s, row
OPTIONAL MATCH (:AdvisorResource)-[m:MEMBER_OF]->(s) DELETE m
WITH DISTINCT s, row
FOREACH (id IN row.members | MERGE (res:AdvisorResource {id: id}) MERGE (res)-[:MEMBER_OF]->(s))`, neoParams({ rows: systems, now, provider: VERCEL, account }));
  await writeCypher("MATCH (s:KnSystem {provider: $provider, account_id: $account}) WHERE NOT s.id IN $ids SET s.gone = true, s.updated_at = $now", { provider: VERCEL, account, ids: systems.map((s) => s.id), now });
  return { types: types.length, overlays: overlays.length, systems: systems.length };
}

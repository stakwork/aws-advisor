import { enabled, neoParams, writeCypher } from "../../graph_mirror.js";
import { listBilledCharges, vercelTeam } from "./inventory.js";
import { VERCEL, vercelAdapter } from "./index.js";

/**
 * The Vercel bill in the graph: one `AdvisorCharge {kind: stream}` per usage month and stream (subscription, marketplace)
 * with the billed total (tax included), subtotal, tax, credits, the invoice it came from and whether it is an `invoice`
 * or a `focus` charge (`source`); one `AdvisorCharge {kind: month}` per month with the total of its streams. The
 * account BILLED the month, the month INCLUDES its streams. Ids are `vercel:charge:<team>:<month>[:<stream>]`, so a
 * refresh updates in place; a month that disappears from the stored charges is marked gone.
 */

export interface ChargeNode {
  id: string; kind: "month" | "stream"; month: string; stream: string | null; total: number; subtotal: number | null; tax: number | null; credits: number | null;
  source: string | null; invoice_id: string | null; number: string | null; period_start: string | null; period_end: string | null; streams: string[];
}

const r2 = (n: number) => Math.round(n * 100) / 100;

/** The nodes the layer writes, pure given the charges: a stream node per month and stream, a month node over them. */
export function chargeNodes(account: string, charges: ReturnType<typeof listBilledCharges>): ChargeNode[] {
  const out: ChargeNode[] = []; const months = [...new Set(charges.map((c) => c.month))];
  for (const month of months) {
    const mine = charges.filter((c) => c.month === month);
    const streams = [...new Set(mine.map((c) => c.stream))];
    for (const stream of streams) {
      const rows = mine.filter((c) => c.stream === stream); const sum = (f: (c: (typeof rows)[number]) => number | null) => rows.some((c) => f(c) != null) ? r2(rows.reduce((n, c) => n + Math.round((f(c) ?? 0) * 100), 0) / 100) : null;
      out.push({ id: `vercel:charge:${account}:${month}:${stream}`, kind: "stream", month, stream, total: sum((c) => c.total)!, subtotal: sum((c) => c.subtotal), tax: sum((c) => c.tax), credits: sum((c) => c.credits), source: [...new Set(rows.map((c) => c.source))].join("+"),
        invoice_id: rows.map((c) => c.invoice_id).filter(Boolean).join(",") || null, number: rows.map((c) => c.number).filter(Boolean).join(",") || null, period_start: rows.map((c) => c.period_start).filter(Boolean).sort()[0] ?? null, period_end: rows.map((c) => c.period_end).filter(Boolean).sort().slice(-1)[0] ?? null, streams: [] });
    }
    const mine2 = out.filter((n) => n.kind === "stream" && n.month === month);
    out.push({ id: `vercel:charge:${account}:${month}`, kind: "month", month, stream: null, total: r2(mine2.reduce((n, c) => n + Math.round(c.total * 100), 0) / 100), subtotal: null, tax: null, credits: null, source: null, invoice_id: null, number: null, period_start: null, period_end: null, streams: mine2.map((c) => c.id) });
  }
  return out;
}

export async function mirrorVercelBilledCharges(): Promise<{ charges: number }> {
  if (!enabled()) return { charges: 0 };
  const team = vercelTeam(); const account = team?.id ?? vercelAdapter.primaryAccountId(); const now = new Date().toISOString();
  const rows = chargeNodes(account, listBilledCharges(24));
  if (rows.length) await writeCypher(`
UNWIND $rows AS row
MERGE (a:AdvisorAccount {id: $account})
MERGE (c:AdvisorCharge {id: row.id}) ON CREATE SET c.first_seen = $now
SET c += {name: 'Vercel ' + row.month + CASE WHEN row.stream IS NULL THEN '' ELSE ' ' + row.stream END, kind: row.kind, month: row.month, stream: row.stream, total_usd: row.total, subtotal_usd: row.subtotal, tax_usd: row.tax, credits_usd: row.credits,
  source: row.source, invoice_id: row.invoice_id, invoice_number: row.number, period_start: row.period_start, period_end: row.period_end, currency: 'usd',
  provider: $provider, account_id: $account, native_type: 'vercel_billed_charge', gone: false, last_seen: $now, updated_at: $now}
MERGE (a)-[b:BILLED]->(c) SET b.gone = false, b.updated_at = $now
WITH c, row
UNWIND CASE WHEN size(row.streams) = 0 THEN [null] ELSE row.streams END AS sid
WITH c, sid WHERE sid IS NOT NULL
MERGE (s:AdvisorCharge {id: sid}) MERGE (c)-[i:INCLUDES]->(s) SET i.updated_at = $now`, neoParams({ rows, account, provider: VERCEL, now }));
  await writeCypher("MATCH (c:AdvisorCharge {provider: $provider, account_id: $account}) WHERE NOT c.id IN $ids SET c.gone = true, c.updated_at = $now", { provider: VERCEL, account, ids: rows.map((r) => r.id), now });
  return { charges: rows.length };
}

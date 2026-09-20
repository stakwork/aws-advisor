import { Fragment, useEffect, useState } from "react";
import { api, usd, when } from "../api";
import { Badge, Button, Card, Empty, Td, Th } from "../components/ui";

type Line = { service: string; usage_type: string; quantity: number; unit: string | null; region: string; rule: string | null; unit_price: number | null; modelled: number | null; actual_od: number; net: number; residual: number | null; note?: string };
type Service = { service: string; actual_net: number; actual_od: number; modelled: number; unpriced_actual: number; lines: number; priced_lines: number; gap_pct: number | null; status: "pass" | "named" | "fail" };
type Recon = { month: string; computed_at: string; pricebook_date: string; hours: number; totals: Record<string, number>; eval: { criterion: string; pass: boolean; detail: string }[]; services: Service[]; lines: Line[]; assumptions: string[] };

const pct = (v: number | null | undefined) => (v == null ? "—" : `${v > 0 ? "+" : ""}${v.toFixed(1)} %`);
const StatusBadge = ({ s }: { s: Service["status"] | boolean }) => {
  const k = s === true ? "pass" : s === false ? "fail" : s;
  const cls = k === "pass" ? "border-emerald-500/30 bg-emerald-500/15 text-emerald-300" : k === "named" ? "border-amber-500/30 bg-amber-500/15 text-amber-300" : "border-red-500/30 bg-red-500/15 text-red-300";
  return <span className={`inline-block rounded border px-1.5 py-0.5 text-[11px] font-medium ${cls}`}>{k}</span>;
};
const fmtQty = (q: number, unit: string | null) => `${q >= 1e6 ? `${(q / 1e6).toFixed(1)}M` : q >= 1e4 ? Math.round(q).toLocaleString() : q.toFixed(q < 10 ? 2 : 0)} ${unit || ""}`.trim();
const fmtPrice = (p: number | null) => (p == null ? "—" : p < 0.001 ? p.toExponential(2) : p < 1 ? p.toFixed(4) : p.toFixed(3));

/** Last month's bill rebuilt from our own prices, line by line against Cost Explorer: the eval of the pricing knowledge. */
export default function Bill() {
  const [month, setMonth] = useState<string>("");
  const [data, setData] = useState<{ month: string; reconciliation: Recon | null; months: { month: string }[] } | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [open, setOpen] = useState<string | null>(null);
  const [gb, setGb] = useState<any>(null);
  const [qty, setQty] = useState<any>(null);
  useEffect(() => { api("/graph/bill").then(setGb).catch(() => setGb(null)); api("/bill/quantities").then(setQty).catch(() => setQty(null)); }, []);
  const load = (m = month) => api(`/bill${m ? `?month=${m}` : ""}`).then((d) => { setData(d); if (!month) setMonth(d.month); }).catch((e) => setErr(e.message));
  useEffect(() => { load(); }, [month]);
  const run = async () => {
    setBusy(true); setErr("");
    try { await api(`/bill/reconcile?month=${month}`, { method: "POST" }); await load(); } catch (e: any) { setErr(e.message); } finally { setBusy(false); }
  };
  const months: string[] = [];
  for (let i = 1; i <= 6; i++) { const d = new Date(); d.setUTCDate(1); d.setUTCMonth(d.getUTCMonth() - i); months.push(`${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, "0")}`); }
  const r = data?.reconciliation;
  const t = r?.totals;
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h1 className="text-xl font-semibold text-zinc-100">Bill reconstruction</h1>
        <span className="flex items-center gap-2 text-sm">
          <select value={month} onChange={(e) => setMonth(e.target.value)}>{months.map((m) => <option key={m} value={m}>{m}</option>)}</select>
          <Button onClick={run} disabled={busy}>{busy ? "Pricing the month…" : r ? "Recompute" : "Compute"}</Button>
        </span>
      </div>
      <p className="max-w-3xl text-sm text-zinc-400">The month's usage priced from the advisor's own knowledge (the pricebook for usage types, the Pricing API for instance hours, the Savings Plan and support as account overlays), compared line by line with what Cost Explorer says was billed. A priced line that disagrees is a wrong price; an unpriced line is a system type the knowledge does not hold yet. This is the eval for the pricing side of the graph.</p>
      {err && <div className="text-sm text-red-300">{err}</div>}
      {!data ? <Empty>Loading…</Empty> : !r ? <Empty>No reconstruction for {data.month} yet. Compute runs three Cost Explorer queries and prices every line (about 30 s).</Empty> : (
        <>
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
            <Card><div className="text-xs text-zinc-500">Billed (net)</div><div className="text-2xl font-semibold text-zinc-100">{usd(t!.actual_net)}</div></Card>
            <Card><div className="text-xs text-zinc-500">Modelled from our prices</div><div className="text-2xl font-semibold text-zinc-100">{usd(t!.modelled_net)}</div><div className={`text-xs ${Math.abs(t!.strict_gap_pct) <= 5 ? "text-emerald-300" : "text-amber-300"}`}>{pct(t!.strict_gap_pct)}</div></Card>
            <Card><div className="text-xs text-zinc-500">Usage value priced by a rule</div><div className="text-2xl font-semibold text-zinc-100">{t!.priced_share_pct.toFixed(1)} %</div><div className="text-xs text-zinc-500">{usd(t!.unpriced_actual)} unpriced</div></Card>
            <Card><div className="text-xs text-zinc-500">Savings Plan</div><div className="text-2xl font-semibold text-zinc-100">{usd(t!.sp_fee_actual)}</div><div className="text-xs text-zinc-500">covered {usd(t!.sp_covered_od)} of on-demand · {t!.sp_discount_rate.toFixed(1)} % off</div></Card>
            <Card><div className="text-xs text-zinc-500">Support and tax</div><div className="text-2xl font-semibold text-zinc-100">{usd(t!.support_actual + t!.tax_actual)}</div><div className="text-xs text-zinc-500">support modelled {usd(t!.support_model)}</div></Card>
          </div>
          <Card title={<span>Eval · {r.eval.filter((e) => e.pass).length} of {r.eval.length} pass <span className="font-normal text-zinc-500">· computed {when(r.computed_at)} · pricebook {r.pricebook_date} · {r.hours} h in the month</span></span>}>
            <ul className="space-y-1 text-sm">{r.eval.map((e) => <li key={e.criterion} className="flex flex-wrap items-start gap-2"><StatusBadge s={e.pass} /><span className="text-zinc-200">{e.criterion}</span><span className="text-zinc-500">{e.detail}</span></li>)}</ul>
          </Card>
          <Card title="Per service · click a row for its lines">
            <table className="w-full border-collapse text-sm">
              <thead><tr><Th>Service</Th><Th className="text-right">Billed net</Th><Th className="text-right">On-demand value</Th><Th className="text-right">Modelled</Th><Th className="text-right">Gap</Th><Th className="text-right">Unpriced</Th><Th className="text-right">Lines</Th><Th>Status</Th></tr></thead>
              <tbody>
                {r.services.map((s) => {
                  const lines = r.lines.filter((l) => l.service === s.service);
                  const isOpen = open === s.service;
                  return (
                    <Fragment key={s.service}>
                      <tr className={`cursor-pointer border-t border-zinc-800 hover:bg-zinc-900/60 ${isOpen ? "bg-zinc-900/40" : ""}`} onClick={() => setOpen(isOpen ? null : s.service)}>
                        <Td className="text-zinc-100">{s.service}</Td>
                        <Td className="text-right">{usd(s.actual_net)}</Td>
                        <Td className="text-right">{usd(s.actual_od)}</Td>
                        <Td className="text-right">{usd(s.modelled)}</Td>
                        <Td className={`text-right ${s.gap_pct != null && Math.abs(s.gap_pct) > 10 ? "text-red-300" : "text-zinc-300"}`}>{pct(s.gap_pct)}</Td>
                        <Td className="text-right text-zinc-400">{s.unpriced_actual > 0.5 ? usd(s.unpriced_actual) : "—"}</Td>
                        <Td className="text-right text-zinc-400">{s.priced_lines}/{s.lines}</Td>
                        <Td><StatusBadge s={s.status} /></Td>
                      </tr>
                      {isOpen && (
                        <tr className="border-t border-zinc-800 bg-zinc-950/40"><td colSpan={8} className="max-w-0 p-3">
                          <table className="w-full border-collapse text-xs">
                            <thead className="text-zinc-500"><tr><th className="py-1 text-left font-normal">Usage type</th><th className="text-right font-normal">Quantity</th><th className="text-right font-normal">Our unit price</th><th className="text-left font-normal">Rule</th><th className="text-right font-normal">Modelled</th><th className="text-right font-normal">On-demand value</th><th className="text-right font-normal">Residual</th></tr></thead>
                            <tbody>{lines.map((l) => (
                              <tr key={l.usage_type} className="border-t border-zinc-800/70">
                                <td className="py-1 pr-2 font-mono text-zinc-200">{l.usage_type}{l.region !== "us-east-1" ? <span className="ml-1 text-zinc-500">{l.region}</span> : null}</td>
                                <td className="text-right whitespace-nowrap">{fmtQty(l.quantity, l.unit)}</td>
                                <td className="text-right font-mono">{fmtPrice(l.unit_price)}</td>
                                <td className="max-w-64 truncate pr-2 text-zinc-400" title={l.note}>{l.rule ? <span className="font-mono text-zinc-300">{l.rule}</span> : <span className="text-amber-300">unpriced</span>}{l.note ? <span className="ml-1 text-zinc-500">{l.note}</span> : null}</td>
                                <td className="text-right">{l.modelled != null ? usd(l.modelled, 2) : "—"}</td>
                                <td className="text-right">{usd(l.actual_od, 2)}</td>
                                <td className={`text-right ${l.residual != null && Math.abs(l.residual) > Math.max(5, 0.1 * l.actual_od) ? "text-amber-300" : "text-zinc-400"}`}>{l.residual != null ? usd(l.residual, 2) : "—"}</td>
                              </tr>
                            ))}</tbody>
                          </table>
                        </td></tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </Card>
          {gb && (
            <Card title={<span>From the graph <span className="font-normal text-zinc-500">· the current fleet at list for a month, from system types, overlays and edges; the bill column is {gb.month_compared}</span></span>}>
              <table className="w-full border-collapse text-sm">
                <thead><tr><Th>Category</Th><Th className="text-right">Graph, a month at list</Th><Th className="text-right">Bill, on-demand value</Th><Th>Detail</Th></tr></thead>
                <tbody>{gb.lines.map((l: any) => <tr key={l.category} className="border-t border-zinc-800"><Td className="text-zinc-100">{l.category}</Td><Td className="text-right">{usd(l.graph_usd_month)}</Td><Td className="text-right">{l.bill_usd_month != null ? usd(l.bill_usd_month) : <span className="text-zinc-600">—</span>}</Td><Td className="text-xs text-zinc-500">{l.detail}</Td></tr>)}
                  <tr className="border-t border-zinc-700 font-medium"><Td className="text-zinc-100">Total the graph explains</Td><Td className="text-right">{usd(gb.graph_total_list)}</Td><Td></Td><Td className="text-xs text-zinc-500">{gb.savings_plan ? `Savings Plan overlay: ${usd(gb.savings_plan.fee_usd_month)}/mo buys ${usd(gb.savings_plan.covered_od_usd_month)} of on-demand value (${gb.savings_plan.discount_rate} % off)` : "no Savings Plan overlay yet"}</Td></tr></tbody>
              </table>
              <div className="mt-2 text-xs text-zinc-500">{gb.note}</div>
            </Card>
          )}
          {qty && qty.lines?.length > 0 && (
            <Card title={<span>Quantities from our own history <span className="font-normal text-zinc-500">· {qty.from} to {qty.to}, {qty.days_with_history} complete day{qty.days_with_history === 1 ? "" : "s"}, the watcher saw {qty.coverage_pct} % of those hours · Cost Explorer for the same days beside it</span></span>}>
              <table className="w-full border-collapse text-sm">
                <thead><tr><Th>Line</Th><Th className="text-right">Ours, as sampled</Th><Th className="text-right">Ours, at full coverage</Th><Th className="text-right">Cost Explorer</Th><Th className="text-right">Our price</Th><Th className="text-right">Ours, priced</Th><Th className="text-right">CE cost (net)</Th></tr></thead>
                <tbody>{qty.lines.slice(0, 16).map((l: any) => <tr key={l.category} className="border-t border-zinc-800"><Td className="text-zinc-100"><span title={l.note}>{l.category}</span></Td><Td className="text-right">{l.history_qty.toLocaleString()} {l.unit}</Td><Td className="text-right">{l.history_qty_scaled != null ? `${l.history_qty_scaled.toLocaleString()} ${l.unit}` : "—"}</Td><Td className="text-right">{l.ce_qty != null ? `${l.ce_qty.toLocaleString()} ${l.unit}` : "—"}</Td><Td className="text-right font-mono text-xs">{l.unit_price ?? "—"}</Td><Td className="text-right">{l.history_usd != null ? usd(l.history_usd, 2) : "—"}</Td><Td className="text-right">{l.ce_usd != null ? usd(l.ce_usd, 2) : "—"}</Td></tr>)}</tbody>
              </table>
              <div className="mt-2 text-xs text-zinc-500">Quantities here come from the advisor's own samples (running instances every 30 minutes, attached EBS, NAT bytes per hour, log ingestion per day), not from the bill. Hours the watcher did not see (expired credentials, restarts) count as nothing, so the sampled column undercounts; the full-coverage column scales it by the hours seen. Where they match Cost Explorer's, a reconstruction from the graph alone becomes possible for that line. History starts when the watcher started.{qty.ce_error ? ` Cost Explorer: ${qty.ce_error}` : ""}</div>
            </Card>
          )}
          <Card title="How the numbers are built">
            <ul className="list-disc space-y-1 pl-4 text-sm text-zinc-400">{r.assumptions.map((a) => <li key={a}>{a}</li>)}</ul>
            <div className="mt-2 text-xs text-zinc-500">Identity: modelled net = the uncovered part of every usage line at our price (as billed where unpriced) + the Savings Plan fee + modelled support + billed tax. The on-demand value of everything, covered or not, is compared per line and per service above.</div>
          </Card>
        </>
      )}
    </div>
  );
}

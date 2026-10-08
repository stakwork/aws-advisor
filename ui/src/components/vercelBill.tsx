import { Fragment, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, usd, when } from "../api";
import { Card, Empty, HelpTip, Stat, Td, Th } from "./ui";
import { VercelRatesCard } from "./vercelStores";

/**
 * This month for a Vercel team: the subscription and its period, what the metered usage did since the period
 * started, the month projected from its invoices (src/adapters/vercel/bill_months.ts), the invoices grouped by the
 * month they were issued in, each marked subscription or Marketplace, with their groups and lines, and the unit prices the last paid invoice
 * implies (amount over quantity per line: the team's own rates, not the catalogue's).
 */
const KIND: Record<string, string> = { subscription: "Subscription", marketplace: "Marketplace" };
const monthName = (m: string) => new Date(`${m}-01T00:00:00Z`).toLocaleString(undefined, { month: "long", year: "numeric", timeZone: "UTC" });
/** "Subscription $457 · Marketplace $259" for a month. */
const splitOf = (m: any) => (m ? Object.entries(m.streams || {}).sort().reverse().map(([k, v]) => `${KIND[k] ?? k} ${usd(v as number)}`).join(" · ") : "");

export function VercelBill() {
  const [d, setD] = useState<any>(null); const [err, setErr] = useState(""); const [open, setOpen] = useState<string | null>(null);
  useEffect(() => { api("/vercel/bill").then(setD).catch((e) => setErr(e.message)); }, []);
  if (err) return <Empty>{err}</Empty>;
  if (!d) return <Empty>Loading…</Empty>;
  if (!d.configured) return <Empty>No Vercel token saved: <Link className="underline" to="/settings?tab=accounts">add the account</Link>.</Empty>;
  const b = d.billing; const p = d.period; const t = p.totals; const tm = b.this_month;
  // every month with an invoice, newest first; this month is listed even before its first invoice when one is expected
  const months: any[] = [...(b.months || [])];
  if (tm && !months.some((m) => m.partial) && tm.streams.some((x: any) => x.expected != null)) months.unshift({ month: new Date().toISOString().slice(0, 7), usd: 0, streams: {}, partial: true });
  const day = (s: string | null) => (s ? String(s).slice(0, 10) : "—");
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-zinc-100">This month</h1>
        <div className="text-sm text-zinc-500">{d.team?.name || d.team?.slug} · {b.plan} plan{b.status ? ` · ${b.status}` : ""} · period {day(b.period_start)} → {day(b.period_end)}{p.days_elapsed != null && p.days_total ? ` · day ${p.days_elapsed} of ${p.days_total}` : ""}</div>
      </div>

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
        <Stat label={<>This month, projected<HelpTip><div className="font-medium text-zinc-100">Projected = the invoices issued this month + each regular invoice not issued yet at its last amount</div><div className="mt-1">Vercel bills twice a month: the subscription (seats, plan, add-ons, infrastructure usage) on its cycle day, and the Marketplace (the stores) on the 1st. A month is every invoice issued in it.</div></HelpTip></>} value={tm?.projected_usd != null ? `≈ ${usd(tm.projected_usd)}` : "—"}
          hint={tm ? tm.streams.map((x: any) => x.issued != null ? `${KIND[x.stream] ?? x.stream} ${usd(x.issued)} issued` : x.expected != null ? `${KIND[x.stream] ?? x.stream} ≈ ${usd(x.expected)} expected` : null).filter(Boolean).join(" · ") : ""} />
        <Stat label={`Last month${b.last_month ? ` (${monthName(b.last_month)})` : ""}`} value={usd(b.last_month_usd)} hint={splitOf(b.months?.find((m: any) => m.month === b.last_month))} />
        <Stat label="Average, last 3 months" value={b.avg_last_3_usd != null ? `${usd(b.avg_last_3_usd)}/mo` : "—"} hint="every invoice of each month" />
        <Stat label="Subscription seats" value={b.seats_usd_month != null ? `${usd(b.seats_usd_month)}/mo` : b.plan || "—"} hint={b.seats != null ? `${b.seats} seats × ${usd(b.seat_usd)}; the plan, add-ons and usage come on top` : ""} />
        <Stat label="Invoices read" value={d.invoices.length} hint={d.invoices.length ? `since ${day(d.invoices[d.invoices.length - 1].created_at)}` : ""} />
      </div>

      <Card title={<span>This period so far <span className="font-normal text-zinc-500">· Vercel's metered usage since {day(b.period_start)}; what it will cost is on the invoice at the period's end</span></span>}>
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-6">
          <Stat label="Requests" value={t.requests.toLocaleString()} hint={`edge cache ${t.cache_hit_pct ?? "—"}% hits`} />
          <Stat label="Function invocations" value={t.invocations.toLocaleString()} hint={`${t.gb_hours} GB-hours · ${t.error_pct ?? "—"}% errors`} />
          <Stat label="Bandwidth out" value={`${t.bandwidth_out_gb} GB`} hint={`${t.bandwidth_in_gb} GB in`} />
          <Stat label="Builds" value={t.builds} hint={`${t.build_minutes} build minutes${t.builds_failed ? ` · ${t.builds_failed} failed` : ""}`} />
          <Stat label="Blob" value={t.blob_gb != null ? `${t.blob_gb} GB` : "—"} hint={`${t.blob_requests.toLocaleString()} requests`} />
          <Stat label="Cron and logs" value={t.cron_invocations.toLocaleString()} hint={`cron runs · ${t.log_gb} GB of logs drained`} />
        </div>
        {p.series.length > 1 && (() => { const max = Math.max(1, ...p.series.map((x: any) => x.requests)); return (
          <div className="mt-3">
            <div className="flex h-14 items-end gap-px" title="requests per day this period">{p.series.map((x: any) => <div key={x.day} className="flex-1 rounded-t bg-sky-500/40" style={{ height: `${Math.max(2, (x.requests / max) * 100)}%` }} title={`${x.day}: ${x.requests.toLocaleString()} requests · ${x.invocations.toLocaleString()} invocations · ${x.bandwidth_out_gb} GB out`} />)}</div>
            <div className="mt-0.5 flex justify-between text-[10px] text-zinc-600"><span>{p.series[0].day}</span><span>requests per day</span><span>{p.series[p.series.length - 1].day}</span></div>
          </div>
        ); })()}
        {p.by_project.length > 0 && <div className="mt-2 text-xs text-zinc-400">By project: {p.by_project.slice(0, 6).map((x: any) => `${x.name} ${x.requests.toLocaleString()} req · ${x.gb_hours} GB-h`).join(" · ")}</div>}
      </Card>

      <Card title={<span>Invoices by month <span className="font-normal text-zinc-500">· as Vercel issued them: the subscription on its cycle day, the Marketplace (stores such as Neon, Redis) on the 1st</span></span>}>
        {!d.invoices.length ? <div className="text-sm text-zinc-500">No invoice read yet.</div> : (
          <table className="w-full border-collapse text-sm">
            <thead><tr><Th>Issued</Th><Th>Kind</Th><Th>Number</Th><Th>Status</Th><Th>Period</Th><Th>Groups</Th><Th className="text-right">Subtotal</Th><Th className="text-right">Tax</Th><Th className="text-right">Total</Th><Th></Th></tr></thead>
            <tbody>
              {months.map((m: any) => (
                <Fragment key={m.month}>
                  <tr className="border-t border-zinc-700 bg-zinc-900/40">
                    <td colSpan={8} className="px-3 py-2 text-sm"><span className="font-medium text-zinc-100">{monthName(m.month)}</span>{m.partial && <span className="ml-1 text-xs text-zinc-500">so far</span>}<span className="ml-3 text-xs text-zinc-400">{splitOf(m)}</span></td>
                    <td className="px-3 py-2 text-right font-medium text-zinc-100">{usd(m.usd)}</td><td />
                  </tr>
                  {d.invoices.filter((i: any) => String(i.created_at).slice(0, 7) === m.month).map((i: any) => (
                    <Fragment key={i.id}>
                      <tr className="cursor-pointer border-t border-zinc-800 hover:bg-zinc-900/60" onClick={() => setOpen(open === i.id ? null : i.id)}>
                        <Td className="whitespace-nowrap">{day(i.created_at)}</Td>
                        <Td><span className={i.kind === "subscription" ? "text-sky-300" : "text-violet-300"}>{KIND[i.kind] ?? i.kind}</span></Td>
                        <Td className="font-mono text-xs">{i.number || "—"}</Td>
                        <Td><span className={i.status === "paid" ? "text-emerald-300" : "text-orange-300"}>{i.status}</span></Td>
                        <Td className="text-xs text-zinc-400">{i.period_start ? `${day(i.period_start)} → ${day(i.period_end)}` : "—"}</Td>
                        <Td className="text-xs text-zinc-400">{i.groups.map((g: any) => `${g.name} ${usd(g.total)}`).join(" · ") || "—"}</Td>
                        <Td className="text-right">{usd(i.subtotal)}</Td><Td className="text-right text-zinc-400">{usd(i.tax)}</Td><Td className="text-right text-zinc-100">{usd(i.total)}</Td>
                        <Td className="text-right text-xs">{i.hosted_url && <a className="text-sky-300 hover:underline" href={i.hosted_url} target="_blank" rel="noreferrer" onClick={(e) => e.stopPropagation()}>open</a>}</Td>
                      </tr>
                      {open === i.id && (
                        <tr className="bg-zinc-950/40"><td colSpan={10} className="p-3">
                          {!i.line_items.length ? <div className="text-xs text-zinc-500">No line items on this invoice.</div> : (
                            <ul className="grid gap-x-6 gap-y-0.5 text-xs text-zinc-400 md:grid-cols-2">
                              {i.line_items.map((l: any, k: number) => <li key={k} className="flex justify-between gap-2"><span className="truncate">{l.title}{l.quantity ? <span className="text-zinc-600"> × {Math.round(l.quantity * 100) / 100}{l.unit_usd != null ? ` @ ${l.unit_usd}` : ""}</span> : null}{l.group ? <span className="text-zinc-600"> · {l.group}</span> : null}</span><span className="text-zinc-300">{usd(l.amount)}</span></li>)}
                            </ul>
                          )}
                        </td></tr>
                      )}
                    </Fragment>
                  ))}
                  {m.partial && (tm?.streams || []).filter((x: any) => x.expected != null).map((x: any) => (
                    <tr key={`exp-${x.stream}`} className="border-t border-zinc-800 text-zinc-500">
                      <Td className="italic">not issued yet</Td><Td><span className={x.stream === "subscription" ? "text-sky-300/70" : "text-violet-300/70"}>{KIND[x.stream] ?? x.stream}</span></Td>
                      <td colSpan={4} className="px-3 py-2 text-xs italic">expected as its last invoice ({day(x.from)}): {x.breakdown.map((g: any) => `${g.name} ${usd(g.usd)}`).join(" · ")}</td>
                      <Td /><Td /><Td className="text-right italic">≈ {usd(x.expected)}</Td><Td />
                    </tr>
                  ))}
                </Fragment>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      <VercelRatesCard rates={d.rates} />
    </div>
  );
}

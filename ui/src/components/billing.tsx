import { useEffect, useState, type ReactNode } from "react";
import { api, usd } from "../api";
import { Badge, Card, Stat, Td, Th } from "./ui";

/**
 * Cost control views: this month against the previous one (GET /api/spend/compare) and every account's line on the
 * bill across providers (GET /api/accounts/billing). Spending more reads orange, less green, and every change also
 * carries its sign and the words "more" / "less", so the colour is never the only cue.
 */

const monthName = (m: string | null | undefined) => (m ? new Date(`${m}-01T00:00:00Z`).toLocaleString(undefined, { month: "long", year: "numeric", timeZone: "UTC" }) : "—");
const shortMonth = (m: string) => new Date(`${m}-01T00:00:00Z`).toLocaleString(undefined, { month: "short", timeZone: "UTC" });

/** A change in spend: "+$120 (+4.1 %) more" in orange, "−$80 (−3 %) less" in green. */
export function Delta({ usd: d, pct, words = true }: { usd?: number | null; pct?: number | null; words?: boolean }) {
  const v = d ?? pct;
  if (v == null) return <span className="text-zinc-500">—</span>;
  const up = v > 0; const flat = Math.abs(pct ?? 0) < 0.5 && Math.abs(d ?? 0) < 1;
  const tone = flat ? "text-zinc-400" : up ? "text-orange-300" : "text-emerald-300";
  const sign = up ? "+" : v < 0 ? "−" : "";
  const parts = [d != null ? `${sign}${usd(Math.abs(d))}` : null, pct != null ? `${d != null ? "(" : ""}${sign}${Math.abs(pct).toFixed(1)} %${d != null ? ")" : ""}` : null].filter(Boolean).join(" ");
  return <span className={tone}>{parts}{words && !flat ? ` ${up ? "more" : "less"}` : ""}</span>;
}

const STATUS: Record<string, string> = { new: "new this month", gone: "nothing yet this month", up: "up", down: "down" };

/** This month against the previous one: the same days side by side, the projection against last month's bill, the months before, and which services moved. */
export function MonthComparison() {
  const [c, setC] = useState<any>(null);
  const [err, setErr] = useState("");
  useEffect(() => { api("/spend/compare").then(setC).catch((e) => setErr(e.message)); }, []);
  if (err) return <Card title="This month against last month"><div className="text-sm text-zinc-500">{err}</div></Card>;
  if (!c) return null;
  const p = c.projected; const l = c.like_for_like; const da = c.daily_avg;
  const prev = monthName(c.previous_month);
  const months: any[] = c.months || [];
  const max = Math.max(1, ...months.map((m) => Math.max(m.usd, m.projected ?? 0)));
  const whose = c.kind === "account" ? "this account's line on the bill, unblended" : `the payer's bill, ${c.metric}${p.basis === "forecast" ? "; projection from the forecast" : ""}`;
  return (
    <Card title={<span className="flex flex-wrap items-baseline justify-between gap-2">This month against {prev} <span className="text-xs font-normal text-zinc-500">{whose}</span></span>}>
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <Stat label={l ? `First ${l.days} day${l.days === 1 ? "" : "s"}, both months` : "Month to date"} value={usd(l ? l.this_usd : c.month_to_date)}
          hint={l ? <>against {usd(l.last_usd)} for {l.last_from.slice(5)} to {l.last_to.slice(5)} · <Delta usd={l.delta_usd} pct={l.delta_pct} /></> : "no day-by-day rows for last month yet"} />
        <Stat label={`Projected for ${monthName(c.month)}`} value={p.usd != null ? `≈ ${usd(p.usd)}` : "—"}
          hint={p.last_month_usd != null ? <>{prev}: {usd(p.last_month_usd)}{p.last_month_complete ? "" : " (incomplete)"} · <Delta usd={p.delta_usd} pct={p.delta_pct} /></> : "no bill for last month yet"} />
        <Stat label={c.kind === "account" ? "Typical day now" : "Daily average"} value={da.this_month != null ? usd(da.this_month, 2) : "—"}
          hint={da.last_month != null ? <>{prev}: {usd(da.last_month, 2)} a day · <Delta usd={da.this_month != null ? da.this_month - da.last_month : null} pct={da.this_month != null && da.last_month ? ((da.this_month - da.last_month) / da.last_month) * 100 : null} /></> : c.kind === "account" ? "median of the last complete days" : ""} />
      </div>
      <div className="mt-4 grid gap-6 lg:grid-cols-[minmax(0,2fr)_minmax(0,3fr)]">
        <div>
          <div className="mb-2 text-xs text-zinc-500">Month by month{months.some((m) => m.partial) ? "; this month so far, the outline is its projection" : ""}</div>
          {months.length === 0 ? <div className="text-sm text-zinc-500">No monthly totals yet: they arrive with the next spend refresh.</div> : (
            <ul className="space-y-1.5">
              {months.map((m, i) => {
                const before = i > 0 ? months[i - 1].usd : null; const val = m.partial && m.projected != null ? m.projected : m.usd;
                const change = before ? ((val - before) / before) * 100 : null;
                return (
                  <li key={m.month} className="grid grid-cols-[3rem_minmax(0,1fr)_6rem] items-center gap-2 text-xs" title={`${monthName(m.month)}: ${usd(m.usd)}${m.partial ? ` so far, ≈ ${usd(m.projected)} projected` : ""}${change != null ? ` · ${change >= 0 ? "+" : "−"}${Math.abs(change).toFixed(1)} % on the month before` : ""}`}>
                    <span className="text-zinc-400">{shortMonth(m.month)}</span>
                    <span className="relative h-2.5 rounded bg-zinc-800">
                      {m.partial && m.projected != null && <span className="absolute inset-y-0 left-0 rounded border border-dashed border-orange-400/70" style={{ width: `${(100 * m.projected) / max}%` }} />}
                      <span className="absolute inset-y-0 left-0 rounded bg-orange-500" style={{ width: `${(100 * m.usd) / max}%` }} />
                    </span>
                    <span className="text-right text-zinc-200">{m.partial && m.projected != null ? `≈ ${usd(m.projected)}` : usd(m.usd)}</span>
                  </li>
                );
              })}
            </ul>
          )}
        </div>
        <div>
          <div className="mb-2 flex flex-wrap items-baseline justify-between gap-2 text-xs text-zinc-500"><span>What moved: each service's projected month against {prev}</span>{c.movers.length > 0 && <span><Delta usd={c.moved.up_usd} words={false} /> up · <Delta usd={c.moved.down_usd} words={false} /> down</span>}</div>
          {c.movers.length === 0 ? <div className="text-sm text-zinc-500">No service moved by more than $5.</div> : (
            <table className="w-full border-collapse text-xs">
              <thead><tr><Th>Service</Th><Th className="text-right">{shortMonth(c.previous_month)}</Th><Th className="text-right">{shortMonth(c.month)} (proj.)</Th><Th className="text-right">Change</Th></tr></thead>
              <tbody>
                {c.movers.map((m: any) => (
                  <tr key={m.service} className="border-t border-zinc-800">
                    <Td><span className="text-zinc-200">{m.service}</span>{(m.status === "new" || m.status === "gone") && <span className="ml-1"><Badge>{STATUS[m.status]}</Badge></span>}</Td>
                    <Td className="text-right text-zinc-400">{usd(m.last_month)}</Td>
                    <Td className="text-right text-zinc-200"><span title={m.mtd != null ? `${usd(m.mtd)} so far` : undefined}>{usd(m.projected)}</span></Td>
                    <Td className="text-right whitespace-nowrap"><Delta usd={m.delta} pct={m.status === "new" || m.status === "gone" ? null : m.delta_pct} words={false} /></Td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </Card>
  );
}

/** Every account's line on the bill, across providers: this month so far, projected, last month and the change, with the totals. */
export function AccountsBilling({ title }: { title?: ReactNode }) {
  const [b, setB] = useState<any>(null);
  useEffect(() => { api("/accounts/billing").then(setB).catch(() => setB(null)); }, []);
  if (!b || !b.lines?.length) return null;
  const t = b.totals; const net = b.aws_net;
  const providers = Object.keys(b.by_provider);
  const prev = monthName(b.previous_month);
  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Stat label="Spent so far this month" value={usd(t.month_to_date_usd)} hint={providers.length > 1 ? providers.map((p) => `${p.toUpperCase()} ${usd(b.by_provider[p].month_to_date_usd)}`).join(" · ") : `${b.lines.length} accounts`} />
        <Stat label={`Projected for ${monthName(b.month)}`} value={t.projected_usd != null ? `≈ ${usd(t.projected_usd)}` : "—"} hint={providers.map((p) => `${p.toUpperCase()} ${usd(b.by_provider[p].projected_usd)}`).join(" · ")} />
        <Stat label={`Spent in ${prev}`} value={usd(t.last_month_usd)} hint={providers.map((p) => `${p.toUpperCase()} ${usd(b.by_provider[p].last_month_usd)}`).join(" · ")} />
        <Stat label="Projected against last month" value={<Delta usd={t.delta_usd} words={false} />} hint={t.delta_pct != null ? <><Delta pct={t.delta_pct} /> than {prev}</> : "no last month to compare"} />
      </div>
      <Card title={title ?? <span>Billing by account <span className="font-normal text-zinc-500">· every account each provider bills</span></span>}>
        <table className="w-full border-collapse text-sm">
          <thead><tr><Th>Account</Th><Th className="text-right">This month so far</Th><Th className="text-right">Projected</Th><Th className="text-right">{prev}</Th><Th className="text-right">Change</Th></tr></thead>
          <tbody>
            {b.lines.map((l: any) => (
              <tr key={`${l.provider}:${l.account}`} className="border-t border-zinc-800">
                <Td>
                  <div className="text-zinc-100">{l.provider.toUpperCase()} · {l.name || l.account}{!l.registered && <span className="ml-1 text-xs text-zinc-500" title="Billed through the organisation but not added to the advisor (Settings › Accounts)">not added</span>}</div>
                  {l.name && l.name !== l.account && <div className="font-mono text-[11px] text-zinc-500">{l.account}</div>}
                  {l.note && <div className="text-[11px] text-zinc-600">{l.note}</div>}
                </Td>
                <Td className="text-right">{usd(l.month_to_date_usd)}</Td>
                <Td className="text-right text-zinc-100">{l.projected_usd != null ? `≈ ${usd(l.projected_usd)}` : "—"}</Td>
                <Td className="text-right text-zinc-400"><span title={l.last_month ?? undefined}>{usd(l.last_month_usd)}</span></Td>
                <Td className="text-right whitespace-nowrap"><Delta usd={l.projected_usd != null && l.last_month_usd != null ? l.projected_usd - l.last_month_usd : null} pct={l.delta_pct} words={false} /></Td>
              </tr>
            ))}
            <tr className="border-t border-zinc-700 font-medium">
              <Td>Total</Td>
              <Td className="text-right">{usd(t.month_to_date_usd)}</Td>
              <Td className="text-right text-zinc-100">{t.projected_usd != null ? `≈ ${usd(t.projected_usd)}` : "—"}</Td>
              <Td className="text-right text-zinc-400">{usd(t.last_month_usd)}</Td>
              <Td className="text-right whitespace-nowrap"><Delta usd={t.delta_usd} pct={t.delta_pct} words={false} /></Td>
            </tr>
          </tbody>
        </table>
        <div className="mt-2 text-xs text-zinc-500">
          AWS lines are each linked account's unblended cost from the payer's Cost Explorer, projected from the account's own recent days, so a charge posted once on the 1st is not multiplied by the month.
          {net && <> The payer's net bill (after credits and refunds): {usd(net.month_to_date_usd)} so far, ≈ {usd(net.projected_usd)} projected{net.basis === "forecast" ? " by the forecast" : ""}, {usd(net.last_month_usd)} in {prev}.</>}
        </div>
      </Card>
    </div>
  );
}

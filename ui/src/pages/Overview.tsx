import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api, usd, when } from "../api";
import { Badge, Button, Card, Empty, Pager, Stat } from "../components/ui";
import { IncidentView, InvestigateButton, incidentOfAlertRow } from "../components/incident";
import { TriageLine, triageOfAlertRow } from "../components/jev";
import { alertLevel } from "../alertLevel";
import { ImpactList } from "../components/impact";

const PREVIEW = 5;
const PAGE = 10;

/** 45 daily bars of net cost, plain divs; today's bar (a partial day) is drawn lighter. */
function DailyCostChart({ series, today, asOf }: { series: any[]; today: string; asOf: string }) {
  const [hover, setHover] = useState<number | null>(null);
  const rows = series.map((r) => ({ day: String(r.day), net: Number(r.net_unblended ?? 0), amortized: Number(r.amortized ?? 0), usage: Number(r.usage_only ?? 0) }));
  if (rows.length === 0) return null;
  const W = 900, H = 170, padL = 56, padR = 12, padT = 14, padB = 30;
  const innerW = W - padL - padR, innerH = H - padT - padB;
  const rawMax = Math.max(1, ...rows.map((r) => r.net));
  // a round ceiling for the axis: 1, 2, 5 x 10^n
  const pow = Math.pow(10, Math.floor(Math.log10(rawMax)));
  const step = pow / 2; // ceiling snaps to a half-decade so the bars fill the height
  const max = Math.ceil(rawMax / step) * step;
  const ticks = [0, max / 2, max];
  const slot = innerW / rows.length;
  const barW = Math.max(2, slot - 2);
  const y = (v: number) => padT + innerH - (innerH * Math.max(0, v)) / max;
  const fmt = (v: number) => (v >= 1000 ? `$${(v / 1000).toFixed(v >= 10000 ? 0 : 1)}k` : `$${Math.round(v)}`);
  const avg = rows.reduce((a, r) => a + r.net, 0) / rows.length;
  const h = hover != null ? rows[hover] : null;
  const dow = (d: string) => new Date(d + "T00:00:00Z").getUTCDay();
  return (
    <div className="relative">
      <div className="mb-1 flex items-baseline justify-between text-xs text-zinc-500">
        <span>Daily net cost, last {rows.length} days · average {usd(avg)} / day</span>
        <span>as of {asOf}</span>
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full" role="img" aria-label={`Daily net AWS cost for the last ${rows.length} days, average ${usd(avg)} per day`} onMouseLeave={() => setHover(null)}>
        {ticks.map((t) => (
          <g key={t}>
            <line x1={padL} x2={W - padR} y1={y(t)} y2={y(t)} stroke="currentColor" strokeOpacity={t === 0 ? 0.5 : 0.15} />
            <text x={padL - 8} y={y(t) + 4} textAnchor="end" fontSize="11" fill="currentColor" fillOpacity="0.6">{fmt(t)}</text>
          </g>
        ))}
        <line x1={padL} x2={W - padR} y1={y(avg)} y2={y(avg)} stroke="currentColor" strokeOpacity="0.45" strokeDasharray="4 3" />
        <text x={W - padR} y={y(avg) - 4} textAnchor="end" fontSize="10" fill="currentColor" fillOpacity="0.6">avg</text>
        {rows.map((r, i) => {
          const x = padL + i * slot + 1;
          const partial = r.day === today;
          const weekend = dow(r.day) === 0 || dow(r.day) === 6;
          const isHover = hover === i;
          return (
            <g key={r.day} onMouseEnter={() => setHover(i)}>
              <rect x={padL + i * slot} y={padT} width={slot} height={innerH} fill="transparent" />
              <rect x={x} y={y(r.net)} width={barW} height={Math.max(1, padT + innerH - y(r.net))} rx="2"
                fill="#f97316" fillOpacity={partial ? 0.35 : isHover ? 1 : weekend ? 0.55 : 0.85} />
              {(i === 0 || dow(r.day) === 1) && (
                <text x={x + barW / 2} y={H - 10} textAnchor="middle" fontSize="10.5" fill="currentColor" fillOpacity="0.6">{r.day.slice(5)}</text>
              )}
            </g>
          );
        })}
        {h && hover != null && (
          <line x1={padL + hover * slot + slot / 2} x2={padL + hover * slot + slot / 2} y1={padT} y2={padT + innerH} stroke="currentColor" strokeOpacity="0.3" />
        )}
      </svg>
      {h && hover != null && (
        <div className="pointer-events-none absolute top-6 rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-xs shadow"
          style={{ left: `calc(${((padL + hover * slot + slot / 2) / W) * 100}% ${hover > rows.length / 2 ? "- 11rem" : "+ 0.5rem"})` }}>
          <div className="font-medium text-zinc-100">{h.day}{h.day === today ? " (partial day)" : ""}</div>
          <div className="text-zinc-300">net {usd(h.net, 2)}</div>
          <div className="text-zinc-500">amortized {usd(h.amortized, 2)} · usage only {usd(h.usage, 2)}</div>
        </div>
      )}
      <div className="mt-1 text-[11px] text-zinc-500">Bars: net unblended cost per day (Cost Explorer). Lighter bars are weekends; the faded bar is today's partial day. Dashed line: period average. Hover for the breakdown.</div>
    </div>
  );
}

/** The agent's morning note: what changed, what deserves attention, what it proposes. Its quality grade shows only when it failed. */
function ObservationCard() {
  const [d, setD] = useState<any>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");
  const load = () => api("/observe").then(setD).catch(() => setD(null));
  useEffect(() => { load(); const t = setInterval(load, 15000); return () => clearInterval(t); }, []);
  const run = async () => { setBusy(true); setMsg(""); try { await api("/observe/run?force=1", { method: "POST", body: "{}" }); await load(); } catch (e: any) { setMsg(e.message); } finally { setBusy(false); } };
  const o = d?.latest;
  const r = o?.result;
  return (
    <div className="space-y-1 text-sm">
      <div className="flex items-center justify-between text-xs text-zinc-500"><span>{o ? `${o.day} · ${o.status}` : "not run yet"}</span><Button variant="ghost" className="!px-2 !py-1 !text-xs" onClick={run} disabled={busy}>{busy ? "Dispatching…" : "Observe now"}</Button></div>
      {msg && <div className="text-xs text-red-300">{msg}</div>}
      {o?.status === "pending" && <div className="text-xs text-zinc-500">The agent is reading the brief and checking facts; a few minutes.</div>}
      {o?.status === "failed" && <div className="text-xs text-red-300">{String(o.error).slice(0, 200)}</div>}
      {r && (
        <>
          <div className="text-zinc-200">{r.summary}</div>
          {r.attention?.length > 0 && <ul className="space-y-0.5 text-xs">{r.attention.map((a: any, i: number) => <li key={i} className="flex items-start gap-2"><Badge>{a.urgency}</Badge><span className="text-zinc-300">{a.item}{a.reason ? <span className="text-zinc-500"> — {a.reason}</span> : null}</span></li>)}</ul>}
          {r.changes?.length > 0 && <details className="text-xs"><summary className="cursor-pointer text-zinc-500">{r.changes.length} change{r.changes.length === 1 ? "" : "s"} explained</summary><ul className="mt-1 space-y-1 pl-3">{r.changes.map((c: any, i: number) => <li key={i} className="text-zinc-300">{c.what} <span className="text-zinc-500">· {c.why} · {c.evidence}{c.expected ? " · expected" : ""}</span></li>)}</ul></details>}
          {r.proposals?.length > 0 && <details className="text-xs"><summary className="cursor-pointer text-zinc-500">{r.proposals.length} proposal{r.proposals.length === 1 ? "" : "s"}</summary><ul className="mt-1 space-y-1 pl-3">{r.proposals.map((p: any, i: number) => <li key={i} className="text-zinc-300"><Badge>{p.tier}</Badge> {p.action}{p.resource ? <span className="font-mono text-zinc-500"> {p.resource}</span> : null}{p.est_monthly_saving ? <span className="text-zinc-500"> · ≈ {usd(p.est_monthly_saving)}/mo</span> : null}<div className="text-zinc-500">{p.rationale}</div></li>)}</ul></details>}
          {o.below_bar && <div className="text-xs text-amber-300">Quality check failed ({o.below_bar.join(", ")}); read this note with care.</div>}
        </>
      )}
    </div>
  );
}

/** CloudTrail write events by people and deployments, top actions; heartbeats counted. */
function ChangesSummary() {
  const [t, setT] = useState<any>(null);
  useEffect(() => { api("/trail?hours=24").then(setT).catch(() => setT(null)); }, []);
  if (!t) return <Empty>Loading…</Empty>;
  if (!t.last_fetch) return <div className="text-sm text-zinc-500">Not collected yet: needs cloudtrail:LookupEvents, then the 06:50 job or <Link to="/changes" className="underline">Collect now</Link>.</div>;
  return (
    <div className="space-y-1 text-sm">
      <div className="text-xs text-zinc-500">{t.events} by people or deployments · {Number(t.noise).toLocaleString()} machine heartbeats hidden · collected {when(t.last_fetch)}</div>
      <ul className="space-y-0.5">{t.by_action.slice(0, 7).map((a: any, i: number) => <li key={i} className="flex justify-between gap-2 text-xs"><span className="min-w-0 truncate text-zinc-300"><span className="font-mono text-zinc-100">{a.event_name}</span> <span className="text-zinc-500">by {a.username || "unknown"}</span></span><span className="text-zinc-500">{a.n}</span></li>)}</ul>
    </div>
  );
}

/** Approved savings: claimed against realised, from the daily verification (seven days after a decision). */
function RealisedLine() {
  const [v, setV] = useState<any>(null);
  useEffect(() => { api("/verifications").then(setV).catch(() => setV(null)); }, []);
  if (!v || !v.approved) return null;
  return <Link to="/recommendations?status=approved" className="text-xs font-normal text-zinc-500 hover:text-zinc-300">{v.approved} approved · claimed {usd(v.claimed_usd_month)}/mo · realised {usd(v.realised_usd_month)}/mo{v.pending ? ` · ${v.pending} awaiting ${v.min_days_after} days` : ""}</Link>;
}

/** Savings Plan and reservations with 30-day utilisation (Cost Explorer) and days to expiry. */
function CommitmentsList({ fallback }: { fallback: any[] }) {
  const [c, setC] = useState<any[] | null>(null);
  useEffect(() => { api("/commitments").then((d) => setC(d.commitments)).catch(() => setC(null)); }, []);
  const rows = c ?? fallback.map((f: any) => JSON.parse(f.dimensions));
  if (!rows.length) return <Empty>No active Savings Plans or reservations found.</Empty>;
  return (
    <ul className="space-y-1 text-sm">
      {rows.map((x: any, i: number) => (
        <li key={i} className="flex justify-between gap-2">
          <span className="min-w-0 truncate text-zinc-300">{x.kind === "savings_plan" ? "Savings Plan" : x.kind.replace(/_ri$/, " RI")} · {x.detail}{x.monthly_usd ? <span className="text-zinc-500"> · {usd(x.monthly_usd)}/mo</span> : null}</span>
          <span className="whitespace-nowrap text-xs">
            {x.utilization_pct != null && <span className={x.utilization_pct < 80 ? "text-amber-300" : "text-emerald-300"} title="30-day utilisation from Cost Explorer">{Math.round(x.utilization_pct)} % used</span>}
            {x.utilization_pct == null && <span className="text-zinc-600" title="utilisation arrives with the next spend refresh">— used</span>}
            <span className={`ml-2 ${Number(x.days_left) < 60 ? "text-amber-300" : "text-zinc-400"}`}>{x.days_left} days</span>
          </span>
        </li>
      ))}
    </ul>
  );
}

const REVIEW_LABEL: Record<string, string> = { sustained_idle: "idle for days", memory_pressure: "memory pressure", disk_fill: "disk filling", idle_container: "idle container", spend_step: "spend stepped up" };
/** Yesterday's read of the collected statistics: idle instances, memory pressure, disks filling, idle containers, spend steps. */
function ReviewSummary() {
  const [r, setR] = useState<any>(null);
  const [busy, setBusy] = useState(false);
  const load = () => api("/review").then(setR).catch(() => setR(null));
  useEffect(() => { load(); }, []);
  const run = async () => { setBusy(true); try { await api("/review/run", { method: "POST", body: "{}" }); await load(); } finally { setBusy(false); } };
  if (!r) return <Empty>Loading…</Empty>;
  const counts: Record<string, number> = {};
  for (const f of r.findings) counts[f.kind] = (counts[f.kind] || 0) + 1;
  return (
    <div className="space-y-1 text-sm">
      <div className="flex items-center justify-between text-xs text-zinc-500"><span>{r.day ? `${r.day} · ${r.findings.length} observation${r.findings.length === 1 ? "" : "s"}` : "not run yet"}</span><Button variant="ghost" className="!px-2 !py-1 !text-xs" onClick={run} disabled={busy}>{busy ? "Reviewing…" : "Run now"}</Button></div>
      {r.day && r.findings.length === 0 && <div className="text-zinc-500">Nothing stands out in the statistics.</div>}
      <div className="flex flex-wrap gap-2 text-xs">{Object.entries(counts).map(([k, n]) => <Badge key={k}>{`${n} ${REVIEW_LABEL[k] || k}`}</Badge>)}</div>
      <ul className="space-y-0.5">{r.findings.slice(0, 6).map((f: any) => (
        <li key={f.id} className="flex items-start gap-2 text-xs"><Badge>{f.severity}</Badge><span className="min-w-0 text-zinc-300">{/^i-/.test(f.resource) ? <Link to={`/inventory?tab=ec2&id=${f.resource}`} className="hover:underline">{f.message}</Link> : f.message}</span></li>
      ))}</ul>
      {r.findings.length > 6 && <div className="text-xs text-zinc-500">and {r.findings.length - 6} more in Recommendations and Alerts</div>}
    </div>
  );
}

/** This month so far and where it is heading, priced from what runs now; the price check surfaces only when it fails. */
function ForecastSummary() {
  const [d, setD] = useState<any>(null);
  useEffect(() => { api("/forecast").then(setD).catch(() => setD(null)); }, []);
  if (!d) return <Empty>Loading…</Empty>;
  const f = d.forecast; const pc = d.price_check?.reconciliation;
  const pcFailed = pc && !pc.eval.every((e: any) => e.pass);
  if (!f) return <div className="text-sm text-zinc-500">Not computed yet. <Link to="/bill" className="underline">Open This month</Link> to run it.</div>;
  return (
    <div className="space-y-1 text-sm">
      <div className="flex justify-between"><span className="text-zinc-400">spent so far, {f.elapsed_days} days</span><span className="text-zinc-100">{usd(f.mtd_net)}</span></div>
      <div className="flex justify-between"><span className="text-zinc-400">on track for</span><span className="text-zinc-100">{usd(f.forecast_net)}{f.delta_pct != null && <span className={`ml-1 ${f.delta_pct > 5 ? "text-amber-300" : f.delta_pct < -5 ? "text-emerald-300" : "text-zinc-500"}`}>({f.delta_pct > 0 ? "+" : ""}{f.delta_pct.toFixed(1)} % vs last month)</span>}</span></div>
      <div className="flex justify-between"><span className="text-zinc-400">locked in</span><span>{usd(f.locked_in)}</span></div>
      {f.movers?.length > 0 && <div className="text-xs text-zinc-500">moved most: {f.movers.slice(0, 3).map((m: any) => `${m.service.replace(/^Amazon |^AWS /, "")} ${m.delta > 0 ? "+" : "−"}${usd(Math.abs(m.delta))}`).join(" · ")}</div>}
      {pcFailed && <div className="text-xs text-amber-300">Price check failed for {d.price_check.month}: saving estimates may be off. <Link to="/bill" className="underline">See why</Link></div>}
    </div>
  );
}

export default function Overview() {
  const [d, setD] = useState<any>(null);
  const [spend, setSpend] = useState<any>(null);
  const [spendMsg, setSpendMsg] = useState("");
  const [alerts, setAlerts] = useState<any>(null);
  const [expanded, setExpanded] = useState(false);
  const [alertPage, setAlertPage] = useState(1);
  const [err, setErr] = useState("");
  const [investigating, setInvestigating] = useState<number | null>(null);
  const nav = useNavigate();
  const load = () => api("/overview").then(setD).catch((e) => setErr(e.message));
  const loadSpend = () => api("/spend").then(setSpend).catch(() => setSpend(null));
  const loadAlerts = () => api(`/alerts?status=open&page=${expanded ? alertPage : 1}&page_size=${expanded ? PAGE : PREVIEW}`).then(setAlerts).catch(() => {});
  useEffect(() => { load(); loadSpend(); const t = setInterval(() => { load(); loadSpend(); }, 10000); return () => clearInterval(t); }, []);
  useEffect(() => { loadAlerts(); const t = setInterval(loadAlerts, 10000); return () => clearInterval(t); }, [expanded, alertPage]);
  if (err) return <Empty>{err}</Empty>;
  if (!d) return <Empty>Loading…</Empty>;

  const metric = (key: string) => (d.metrics as any[]).filter((m) => m.key === key);
  const rt = Object.fromEntries(metric("spend_by_record_type").map((m) => [m.label, m]));
  const invoice = metric("spend_by_record_type").reduce((s, m) => s + Number(JSON.parse(m.dims).net_unblended || 0), 0);
  const recs = Object.fromEntries((d.recommendations as any[]).map((r) => [r.status, r]));

  const startRun = async () => { const r = await api("/runs", { method: "POST" }); nav(`/runs/${r.id}`); };
  const ack = async (id: number) => { try { await api(`/alerts/${id}/ack`, { method: "POST" }); loadAlerts(); load(); } catch (e: any) { setErr(e.message); } };
  const investigate = async (id: number) => {
    setInvestigating(id);
    try { await api(`/alerts/${id}/investigate`, { method: "POST" }); await loadAlerts(); } catch (e: any) { setErr(e.message); } finally { setInvestigating(null); }
  };
  const refreshSpend = async () => {
    setSpendMsg("Refreshing…");
    try { const r = await api("/spend/refresh?force=1", { method: "POST" }); setSpendMsg(r.refreshed ? `${r.days} days fetched` : `skipped: ${r.skipped || r.error}`); loadSpend(); }
    catch (e: any) { setSpendMsg(e.message); }
  };

  const counts = alerts?.counts || { alarm: 0, warning: 0, info: 0 };
  const total = alerts?.total ?? 0;
  const mtd = spend?.month_to_date;
  const hasSpend = Boolean(spend?.as_of);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-zinc-100">Overview</h1>
          <div className="text-sm text-zinc-500">
            {d.latestRun ? <>Last completed run #{d.latestRun.id} at {when(d.latestRun.finished_at)} on account {d.latestRun.account_id}</> : "No completed run yet"}
            {d.running && <> · run #{d.running.id} in progress</>}
          </div>
        </div>
        <Button onClick={startRun} disabled={d.busy || !d.awsConfigured}>{d.busy ? "Running…" : "Run now"}</Button>
      </div>

      {/* Spend: today, last 7 days, month to date with its projection, previous month; from spend_daily (Cost Explorer, at most every 6 h). */}
      <div className="space-y-2">
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          <Stat label={spend?.today?.usd != null ? "Spend today" : "Latest day"} value={spend?.today?.usd != null ? usd(spend.today.usd, 2) : spend?.latest ? usd(spend.latest.usd, 2) : "—"}
            hint={spend?.today?.usd != null ? `${spend.today.day} · partial day, Cost Explorer is still adding to it` : spend?.latest ? `${spend.latest.day}${spend.latest.partial ? " · still filling in; today is not in Cost Explorer yet" : ""}` : "no spend data yet"} />
          <Stat label="Last 7 days" value={usd(spend?.last_7_days?.usd)}
            hint={spend?.last_7_days?.usd != null ? `${spend.last_7_days.from} to ${spend.last_7_days.to}${spend.last_7_days.days < 7 ? ` · ${spend.last_7_days.days} days with data` : ""}` : "net unblended"} />
          <Stat label="Month to date" value={usd(mtd?.usd)}
            hint={mtd?.projected_month_end != null ? <>projected ≈ <span className="text-zinc-300">{usd(mtd.projected_month_end)}</span> at month end ({usd(mtd.projection_basis?.daily_avg)} / day over {mtd.projection_basis?.days} day{mtd.projection_basis?.days === 1 ? "" : "s"})</> : "no projection yet"} />
          <Stat label="Previous month" value={usd(spend?.previous_month?.usd)}
            hint={spend?.previous_month?.usd != null ? `${spend.previous_month.from.slice(0, 7)}${spend.previous_month.complete ? "" : ` · ${spend.previous_month.days} days with data`}` : "for comparison"} />
        </div>
        <Card>
          <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-zinc-500">
            <span>{hasSpend ? <>Daily net unblended cost, last {spend.days} days · as of <span className="text-zinc-300">{spend.as_of}</span> · fetched {when(spend.fetched_at)}</> : "No spend data yet: it is fetched at the end of every run and every 6 hours (SPEND_CRON), one Cost Explorer call each time."}</span>
            <span className="flex items-center gap-2">{spendMsg && <span>{spendMsg}</span>}<Button variant="ghost" className="!px-2 !py-1 !text-xs" onClick={refreshSpend} disabled={!d.awsConfigured}>Refresh</Button></span>
          </div>
          {spend?.series?.length > 0 && <div className="mt-2"><DailyCostChart series={spend.series} today={spend.today.day} asOf={spend.as_of} /></div>}
        </Card>
      </div>

      {total > 0 && alerts && (
        <Card title={<span className="flex flex-wrap items-center justify-between gap-2">
          <span className="flex items-center gap-2">Alerts ({total})
            {counts.alarm > 0 && <span className="flex items-center gap-1"><Badge>alarm</Badge>{counts.alarm}</span>}
            {counts.warning > 0 && <span className="flex items-center gap-1"><Badge>warning</Badge>{counts.warning}</span>}
            {counts.info > 0 && <span className="flex items-center gap-1"><Badge>info</Badge>{counts.info}</span>}
          </span>
          <span className="flex items-center gap-3 text-xs font-normal">
            {total > PREVIEW && <button className="underline" onClick={() => { setExpanded(!expanded); setAlertPage(1); }}>{expanded ? `Show first ${PREVIEW}` : `Show all (${total})`}</button>}
            <Link className="underline" to="/alerts?status=all">all alerts</Link>
          </span>
        </span>} className="border-amber-500/30">
          <ul className="divide-y divide-zinc-800">
            {alerts.alerts.map((a: any) => {
              const inc = incidentOfAlertRow(a);
              const triage = triageOfAlertRow(a);
              return (
                <li key={a.id} className="py-2 text-sm">
                  <div className="flex items-center justify-between gap-3">
                    <span className="flex min-w-0 items-center gap-2"><Badge>{alertLevel(a)}</Badge><Link to={`/alerts?status=all&id=${a.id}`} className="truncate text-zinc-200 hover:underline" title={a.details || ""}>{a.message}</Link><span className="shrink-0 text-xs text-zinc-500">{when(a.created_at)}</span></span>
                    <span className="flex shrink-0 gap-2">
                      <InvestigateButton incident={inc} enabled={Boolean(d.agentConfigured) && d.alertInvestigate !== "off"} busy={investigating === a.id} onClick={() => investigate(a.id)} />
                      <Button variant="ghost" className="!px-2 !py-1 !text-xs" onClick={() => ack(a.id)}>Acknowledge</Button>
                    </span>
                  </div>
                  {triage && <div className="mt-1"><TriageLine alert={a} triage={triage} compact /></div>}
                  {inc && <div className="mt-1 rounded border border-zinc-800 bg-zinc-950/60 p-2"><IncidentView incident={inc} compact /></div>}
                </li>
              );
            })}
          </ul>
          {expanded
            ? <Pager className="mt-3" page={alerts.page} pageSize={alerts.page_size} total={total} onPage={setAlertPage} always />
            : total > PREVIEW && <div className="mt-2 text-xs text-zinc-500">{total - alerts.alerts.length} more open · <button className="underline" onClick={() => setExpanded(true)}>show all</button></div>}
        </Card>
      )}

      {!d.latestRun && <Empty>{d.awsConfigured ? <>Start a run to collect findings.</> : <>Add AWS credentials in <Link className="underline" to="/settings">Settings</Link>, then start a run.</>}</Empty>}

      {d.latestRun && (
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          <Stat label="Last full month invoice" value={usd(invoice)} hint="net unblended" />
          <Stat label="On-demand usage" value={usd(rt.Usage?.value)} hint={`Savings Plan covered ${usd(rt.SavingsPlanCoveredUsage?.value)} · reserved ${usd(rt.DiscountedUsage?.value)}`} />
          <Stat label="Open recommendations" value={recs.open?.n || 0} hint={`≈ ${usd(recs.open?.saving)} / month if all applied`} />
          <Stat label="Findings in last run" value={d.latestRun.findings_count} hint={<Link className="underline" to="/findings">browse</Link>} />
        </div>
      )}

      {d.inventory?.refreshed_at && (
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          <Stat label="Running instances" value={d.inventory.ec2.running} hint={<><Link className="underline" to="/inventory">inventory</Link> · {d.inventory.ec2.stopped} stopped · refreshed {when(d.inventory.refreshed_at)}</>} />
          <Stat label="SSM coverage" value={`${d.inventory.ec2.ssm_online} / ${d.inventory.ec2.running}`} hint={<Link className="underline" to="/inventory?ssm=unmanaged">{d.inventory.ec2.ssm_unmanaged} not managed · {d.inventory.ec2.ssm_lost} connection lost</Link>} />
          <Stat label="EC2 on-demand list price" value={usd(d.inventory.ec2.monthly_usd_running)} hint={<Link className="underline" to="/inventory?sort=-monthly_usd">running instances / month{d.inventory.ec2.running_unpriced ? ` · ${d.inventory.ec2.running_unpriced} unpriced` : ""}</Link>} />
          <Stat label="RDS + ElastiCache" value={usd(d.inventory.rds.monthly_usd + d.inventory.elasticache.monthly_usd)} hint={<Link className="underline" to="/inventory?tab=rds">{d.inventory.rds.total} databases · {d.inventory.elasticache.total} cache clusters / month</Link>} />
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        <Card title={<span className="flex items-center justify-between">Top recommendations by saving <RealisedLine /></span>}>
          {d.top.length === 0 ? <Empty>None open.</Empty> : (
            <ul className="divide-y divide-zinc-800">
              {d.top.map((r: any) => (
                <li key={r.id} className="flex items-center justify-between gap-3 py-2 text-sm">
                  <Link to={`/recommendations?id=${r.id}`} className="truncate hover:underline">{r.title}</Link>
                  <span className="flex shrink-0 items-center gap-2"><Badge>{r.tier}</Badge><span className="w-20 text-right font-medium text-zinc-100">{usd(r.est_monthly_saving)}</span></span>
                </li>
              ))}
            </ul>
          )}
        </Card>
        <Card title="On-demand spend by service (last full month)">
          {metric("on_demand_by_service").length === 0 ? <Empty>No cost data yet.</Empty> : (
            <ul className="space-y-1">
              {metric("on_demand_by_service").slice(0, 10).map((m) => {
                const max = metric("on_demand_by_service")[0].value || 1;
                return (
                  <li key={m.label} className="text-sm">
                    <div className="flex justify-between"><span className="truncate text-zinc-300">{m.label}</span><span className="text-zinc-100">{usd(m.value)}</span></div>
                    <div className="h-1.5 rounded bg-zinc-800"><div className="h-1.5 rounded bg-orange-500" style={{ width: `${(100 * m.value) / max}%` }} /></div>
                  </li>
                );
              })}
            </ul>
          )}
        </Card>
        <Card title={<span className="flex items-center justify-between">Changes in the last 24 h <Link to="/changes" className="text-xs font-normal text-zinc-500 hover:text-zinc-300">open →</Link></span>}>
          <ChangesSummary />
        </Card>
        <Card title="Inside EC2 - Other (last full month)">
          {metric("ec2_other_usage").length === 0 ? <Empty>No data.</Empty> : (
            <ul className="space-y-1 text-sm">
              {metric("ec2_other_usage").map((m) => <li key={m.label} className="flex justify-between"><span className="text-zinc-300">{m.label}</span><span>{usd(m.value)}</span></li>)}
            </ul>
          )}
        </Card>
        <Card title={<span className="flex items-center justify-between">Morning observation <span className="text-xs font-normal text-zinc-500">the agent's read of the day</span></span>}>
          <ObservationCard />
        </Card>
        <Card title={<span className="flex items-center justify-between">Daily review <span className="text-xs font-normal text-zinc-500">what the statistics say</span></span>}>
          <ReviewSummary />
        </Card>
        <Card title={<span className="flex items-center justify-between">This month <Link to="/bill" className="text-xs font-normal text-zinc-500 hover:text-zinc-300">open →</Link></span>}>
          <ForecastSummary />
        </Card>
        <Card title="Commitments">
          <CommitmentsList fallback={d.commitments} />
        </Card>
        <Card className="lg:col-span-2" title={<span className="flex items-center justify-between">Impact of your decisions <span className="text-xs font-normal text-zinc-500">what the bill did after each approval, measured from seven days on</span></span>}>
          <ImpactList />
        </Card>
      </div>
    </div>
  );
}

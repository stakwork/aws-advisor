import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api, currentScope, usd, when } from "../api";
import { Badge, Button, Card, Empty, Pager, Stat } from "../components/ui";
import { IncidentView, InvestigateButton, incidentOfAlertRow } from "../components/incident";
import { TriageLine, triageOfAlertRow } from "../components/jev";
import { alertLevel } from "../alertLevel";
import { ImpactList } from "../components/impact";
import { AccountsOverview, GeneralOverview } from "../components/accounts";
import { AccountsBilling, MonthComparison } from "../components/billing";
import { useScopeInfo } from "../scope";
import { ScopedPage } from "../views";

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

/** Approved savings: claimed against realised, from the daily verification (seven days after a decision). */
function RealisedLine() {
  const [v, setV] = useState<any>(null);
  useEffect(() => { api("/verifications").then(setV).catch(() => setV(null)); }, []);
  if (!v || !v.actioned) return null;
  return <Link to="/recommendations?status=approved" className="text-xs font-normal text-zinc-500 hover:text-zinc-300">{v.approved} approved{v.auto ? ` + ${v.auto} auto-action${v.auto === 1 ? "" : "s"}` : ""} · claimed {usd(v.claimed_usd_month)}/mo · realised {usd(v.realised_usd_month)}/mo{v.pending ? ` · ${v.pending} awaiting ${v.min_days_after} days` : ""}</Link>;
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
  // what the last Run now did: a run on the same day often finds the same things, so the list alone looks unchanged
  const [ran, setRan] = useState<{ ok: boolean; text: string } | null>(null);
  const load = () => api("/review").then(setR).catch(() => setR(null));
  useEffect(() => { load(); }, []);
  const run = async () => {
    setBusy(true); setRan(null);
    try {
      const x: any = await api("/review/run", { method: "POST", body: "{}" });
      const found = Object.values(x.findings || {}).reduce((s: number, n: any) => s + Number(n || 0), 0);
      setRan({ ok: !(x.errors || []).length, text: `Reviewed ${x.instances} instance${x.instances === 1 ? "" : "s"} in ${(x.took_ms / 1000).toFixed(1)} s: ${found} observation${found === 1 ? "" : "s"}, ${x.recommendations} recommendation${x.recommendations === 1 ? "" : "s"}, ${x.alerts} new alert${x.alerts === 1 ? "" : "s"}${(x.errors || []).length ? `; errors: ${x.errors.join("; ")}` : ""}` });
      await load();
    } catch (e: any) { setRan({ ok: false, text: `Review failed: ${e?.message || e}` }); }
    finally { setBusy(false); }
  };
  if (!r) return <Empty>Loading…</Empty>;
  const lr = r.last_run;
  // a run that started over an hour ago and never finished died with the process
  const stale = lr && !lr.finished_at && Date.now() - Date.parse(`${lr.started_at.replace(" ", "T")}Z`) > 3600_000;
  const counts: Record<string, number> = {};
  for (const f of r.findings) counts[f.kind] = (counts[f.kind] || 0) + 1;
  return (
    <div className="space-y-1 text-sm">
      <div className="flex items-center justify-between text-xs text-zinc-500"><span>{r.day ? `${r.day} · ${r.findings.length} observation${r.findings.length === 1 ? "" : "s"}${r.scope && r.scope.total !== r.findings.length ? ` for this account (${r.scope.total} across accounts)` : ""}` : lr ? "nothing found yet" : "not run yet"}</span><Button variant="ghost" className="!px-2 !py-1 !text-xs" onClick={run} disabled={busy}>{busy ? "Reviewing…" : "Run now"}</Button></div>
      {ran && <div className={`text-xs ${ran.ok ? "text-zinc-400" : "text-red-400"}`}>{ran.text}</div>}
      {lr && <div className={`text-xs ${lr.error || (!lr.finished_at && stale) ? "text-red-400" : "text-zinc-500"}`}>{lastRunLine(lr, stale)}</div>}
      {r.day && r.findings.length === 0 && <div className="text-zinc-500">Nothing stands out in the statistics.</div>}
      <div className="flex flex-wrap gap-2 text-xs">{Object.entries(counts).map(([k, n]) => <Badge key={k}>{`${n} ${REVIEW_LABEL[k] || k}`}</Badge>)}</div>
      <ul className="space-y-0.5">{r.findings.slice(0, 6).map((f: any) => (
        <li key={f.id} className="flex items-start gap-2 text-xs"><Badge>{f.severity}</Badge><span className="min-w-0 text-zinc-300">{/^i-/.test(f.resource) ? <Link to={`/inventory?tab=ec2&id=${f.resource}`} className="hover:underline">{f.message}</Link> : f.message}</span></li>
      ))}</ul>
      {r.findings.length > 6 && <div className="text-xs text-zinc-500">and {r.findings.length - 6} more in Recommendations and Alerts</div>}
    </div>
  );
}


/** What the review's last run did: when, how many instances had daily statistics, or how it failed. */
function lastRunLine(lr: any, stale: boolean): string {
  const at = `Last run ${when(lr.started_at.replace(" ", "T") + "Z")}`;
  if (lr.error) return `${at} failed: ${lr.error}`;
  if (!lr.finished_at) return stale ? `${at} never finished (the server restarted or it hung)` : `${at}, still running…`;
  const found = Object.values(lr.findings || {}).reduce((t: number, n: any) => t + Number(n || 0), 0);
  const cover = `${lr.instances} of ${lr.candidates ?? "?"} running instances had daily statistics${lr.instances === 0 ? " (they come from the probe passes: check that probes reach the instances)" : ""}`;
  return `${at}: ${cover}; ${found} observation${found === 1 ? "" : "s"}${(lr.errors || []).length ? `; errors: ${lr.errors.join("; ")}` : ""}`;
}

/** A section title on the overview, with a link to the page that holds the full picture. */
function SectionHeading({ title, to, label = "open →" }: { title: string; to: string; label?: string }) {
  return <div className="flex items-baseline justify-between border-b border-zinc-800 pb-1"><h2 className="text-base font-medium text-zinc-100">{title}</h2><Link to={to} className="text-xs text-zinc-500 hover:text-zinc-300">{label}</Link></div>;
}

/**
 * One account: the overview its provider declares (ui/src/views.tsx), never another provider's cards; every account
 * with more than one provider configured: the general view across them.
 */
export default function Overview() {
  const scopeInfo = useScopeInfo();
  if (scopeInfo.ready && scopeInfo.scope === "all" && scopeInfo.providers.filter((p) => p.configured).length > 1) {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between"><h1 className="text-xl font-semibold text-zinc-100">Overview</h1><span className="text-sm text-zinc-500">All accounts · pick one under "Looking at" for its own overview</span></div>
        <GeneralOverview />
      </div>
    );
  }
  return <ScopedPage slot="overview" what="overview" />;
}

/** The AWS account's overview (the AWS adapter's overview view). */
export function AwsOverview() {
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
    <div className="space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-zinc-100">Overview</h1>
          <div className="text-sm text-zinc-500">
            {d.scope && <>Looking at account {d.scope.account}{d.scope.consolidated ? " · recommendations, alerts and the inventory are this account's; billing is the payer's consolidated bill" : ""}. </>}
            {d.latestRun ? <>Last completed run #{d.latestRun.id} at {when(d.latestRun.finished_at)}{d.scope ? "" : <> on account {d.latestRun.account_id}</>}</> : "No completed run yet"}
            {d.running && <> · run #{d.running.id} in progress</>}
          </div>
        </div>
        <Button onClick={startRun} disabled={d.busy || !d.awsConfigured}>{d.busy ? "Running…" : "Run now"}</Button>
      </div>
      <AccountsOverview />

      {!d.latestRun && <Empty>{d.awsConfigured ? <>Start a run to collect findings.</> : <>Add AWS credentials in <Link className="underline" to="/settings?tab=accounts">Settings</Link>, then start a run.</>}</Empty>}

      {/* Alerts: what is open now, then the agent's morning note and yesterday's statistical review. */}
      <section className="space-y-4">
        <SectionHeading title="Alerts" to="/alerts?status=all" />
        {total > 0 && alerts ? (
          <Card title={<span className="flex flex-wrap items-center justify-between gap-2">
            <span className="flex items-center gap-2">Open ({total})
              {counts.alarm > 0 && <span className="flex items-center gap-1"><Badge>alarm</Badge>{counts.alarm}</span>}
              {counts.warning > 0 && <span className="flex items-center gap-1"><Badge>warning</Badge>{counts.warning}</span>}
              {counts.info > 0 && <span className="flex items-center gap-1"><Badge>info</Badge>{counts.info}</span>}
            </span>
            <span className="flex items-center gap-3 text-xs font-normal">
              {total > PREVIEW && <button className="underline" onClick={() => { setExpanded(!expanded); setAlertPage(1); }}>{expanded ? `Show first ${PREVIEW}` : `Show all (${total})`}</button>}
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
        ) : alerts && <div className="text-sm text-zinc-500">No open alerts.</div>}
        <div className="grid gap-4 lg:grid-cols-2">
          <Card title={<span className="flex items-center justify-between">Morning observation <span className="text-xs font-normal text-zinc-500">{d.scope ? "the agent's read of the day, across every account" : "the agent's read of the day"}</span></span>}>
            <ObservationCard />
          </Card>
          <Card title={<span className="flex items-center justify-between">Daily review <span className="text-xs font-normal text-zinc-500">what the statistics say</span></span>}>
            <ReviewSummary />
          </Card>
        </div>
      </section>

      {/* Recommendations: what is open, the largest savings, and what past approvals did to the bill. */}
      {d.latestRun && (
        <section className="space-y-4">
          <SectionHeading title="Recommendations" to="/recommendations" />
          <div className="grid grid-cols-2 gap-4">
            <Stat label="Open recommendations" value={recs.open?.n || 0} hint={<>≈ {usd(d.open_saving?.distinct ?? recs.open?.saving)} / month if all applied{d.open_saving?.overlap > 0 ? <span title="Several actions claim the same resource; only the largest claim per resource is counted"> ({usd(d.open_saving.overlap)} more is claimed twice)</span> : null}{recs.pending?.n ? <> · <Link className="underline" to="/recommendations?status=pending">{recs.pending.n} in progress</Link></> : null}</>} />
            <Stat label={d.scope ? "Findings in last run (this account)" : "Findings in last run"} value={d.scope ? d.scope.findings ?? "—" : d.latestRun.findings_count} hint={<Link className="underline" to="/findings">browse</Link>} />
          </div>
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
            <Card title={<span className="flex items-center justify-between">Impact of your decisions <span className="text-xs font-normal text-zinc-500">what the bill did after each approval and auto-action, measured from seven days on</span></span>}>
              <ImpactList />
            </Card>
          </div>
        </section>
      )}

      {/* Billing: daily spend (Cost Explorer, at most every 6 h), the last full month, list prices of what runs, and commitments. This month's forecast lives on its own page. */}
      <section className="space-y-4">
        <SectionHeading title="Billing" to="/bill" label="this month →" />
        {!d.scope && currentScope() === "all" && <AccountsBilling />}
        {d.scope?.consolidated && (
          <div className="space-y-2">
            <div className="text-xs text-zinc-500">This account's own months, from Cost Explorer's per-account view (refreshed with the daily spend). Everything below it is the payer's consolidated bill: Cost Explorer reports the organisation as one.</div>
            {d.scope.spend?.length > 0 ? (
              <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
                {d.scope.spend.slice(0, 4).map((m: any, i: number) => <Stat key={m.month} label={i === 0 ? `${m.month} (this account, to date)` : `${m.month} (this account)`} value={usd(m.usd)} hint={i === 0 ? "month to date · unblended" : "unblended"} />)}
              </div>
            ) : <div className="text-sm text-zinc-500">No per-account spend yet: it arrives with the next spend refresh.</div>}
          </div>
        )}
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
        <MonthComparison />
        <Card>
          <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-zinc-500">
            <span>{hasSpend ? <>Daily net unblended cost, last {spend.days} days · as of <span className="text-zinc-300">{spend.as_of}</span> · fetched {when(spend.fetched_at)}</> : "No spend data yet: it is fetched at the end of every run and every 6 hours (SPEND_CRON), one Cost Explorer call each time."}</span>
            <span className="flex items-center gap-2">{spendMsg && <span>{spendMsg}</span>}<Button variant="ghost" className="!px-2 !py-1 !text-xs" onClick={refreshSpend} disabled={!d.awsConfigured}>Refresh</Button></span>
          </div>
          {spend?.series?.length > 0 && <div className="mt-2"><DailyCostChart series={spend.series} today={spend.today.day} asOf={spend.as_of} /></div>}
        </Card>

        {(d.latestRun || d.inventory?.refreshed_at) && (
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            {d.latestRun && <>
              <Stat label="Last full month invoice" value={usd(invoice)} hint={d.scope?.consolidated ? "net unblended · whole organisation" : "net unblended"} />
              <Stat label="On-demand usage" value={usd(rt.Usage?.value)} hint={`Savings Plan covered ${usd(rt.SavingsPlanCoveredUsage?.value)} · reserved ${usd(rt.DiscountedUsage?.value)}`} />
            </>}
            {d.inventory?.refreshed_at && <>
              <Stat label="EC2 on-demand list price" value={usd(d.inventory.ec2.monthly_usd_running)} hint={<Link className="underline" to="/inventory?sort=-monthly_usd">running instances / month{d.inventory.ec2.running_unpriced ? ` · ${d.inventory.ec2.running_unpriced} unpriced` : ""}</Link>} />
              <Stat label="RDS + ElastiCache" value={usd(d.inventory.rds.monthly_usd + d.inventory.elasticache.monthly_usd)} hint={<Link className="underline" to="/inventory?tab=rds">{d.inventory.rds.total} databases · {d.inventory.elasticache.total} cache clusters / month</Link>} />
            </>}
          </div>
        )}

        {d.latestRun && (
          <div className="grid gap-4 lg:grid-cols-2">
            <Card title={`On-demand spend by service (last full month${d.scope?.consolidated ? ", whole organisation" : ""})`}>
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
            <Card title="Commitments">
              <CommitmentsList fallback={d.commitments} />
            </Card>
            <Card title={`Inside EC2 - Other (last full month${d.scope?.consolidated ? ", whole organisation" : ""})`}>
              {metric("ec2_other_usage").length === 0 ? <Empty>No data.</Empty> : (
                <ul className="space-y-1 text-sm">
                  {metric("ec2_other_usage").map((m) => <li key={m.label} className="flex justify-between"><span className="text-zinc-300">{m.label}</span><span>{usd(m.value)}</span></li>)}
                </ul>
              )}
            </Card>
          </div>
        )}
      </section>
    </div>
  );
}

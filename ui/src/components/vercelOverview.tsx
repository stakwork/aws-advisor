import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, usd, when } from "../api";
import { Badge, Card, Empty, Stat, Td, Th } from "./ui";

/**
 * Overview for a Vercel team: health (production deployments ready or failed), activity (deployments in the last
 * day and week), exposure (URLs open to anyone versus behind protection, domains, firewall), the data stores by kind
 * and plan, and the attention list. The project list itself lives in Inventory › Deployments.
 */
export function VercelOverview() {
  const [d, setD] = useState<any>(null); const [err, setErr] = useState("");
  useEffect(() => { api("/vercel/overview").then(setD).catch((e) => setErr(e.message)); }, []);
  if (err) return <Empty>{err}</Empty>;
  if (!d) return <Empty>Loading…</Empty>;
  if (!d.configured) return <Empty>No Vercel token saved: <Link className="underline" to="/settings?tab=accounts">add the account</Link>.</Empty>;
  const list = (xs: { name: string; n: number }[], max = 4) => xs.slice(0, max).map((x) => `${x.name} ${x.n}`).join(" · ") || "—";
  return (
    <div className="space-y-6">
      <div className="text-sm text-zinc-500">{d.team?.name || d.team?.slug}{d.team?.plan ? ` · ${d.team.plan} plan` : ""} · read {when(d.read_at)} · <Link className="underline" to="/inventory?tab=deployments">inventory</Link></div>
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-6">
        <Stat label="Projects" value={d.projects.total} hint={`${d.projects.production_ready} with production ready${d.projects.production_failed ? ` · ${d.projects.production_failed} failed` : ""}`} />
        <Stat label="Deployments, 24 h" value={d.deployments.last_24h} hint={`${d.deployments.last_7d} in 7 days${d.deployments.failed_7d ? ` · ${d.deployments.failed_7d} failed` : ""}`} />
        <Stat label="URLs open to anyone" value={<span className={d.exposure.open ? "text-orange-300" : "text-emerald-300"}>{d.exposure.open}</span>} hint={`${d.exposure.protected} behind protection · ${d.exposure.urls} in all`} />
        <Stat label="Custom domains" value={d.exposure.custom_domains} hint={d.exposure.unverified_domains ? `${d.exposure.unverified_domains} not verified` : "all verified"} />
        <Stat label="Data stores" value={d.stores.total} hint={list(d.stores.by_kind)} />
        <Stat label="Firewall on" value={`${d.exposure.firewall_on} / ${d.exposure.firewall_known}`} hint={`${d.env_names} env variable names`} />
      </div>

      <Card title={<span>Attention <span className="font-normal text-zinc-500">· what the last read says is worth a look</span></span>}>
        {!d.attention.length ? <div className="text-sm text-zinc-500">Nothing: production deployments ready, previews protected, domains verified.</div> : (
          <ul className="space-y-1 text-sm">
            {d.attention.map((a: any, i: number) => (
              <li key={i} className="flex items-start gap-2">
                <Badge>{a.level}</Badge>
                <span className="text-zinc-300">{a.what}</span>
                {a.tab && <Link className="text-xs text-sky-300 hover:underline" to={`/inventory?tab=${a.tab}`}>open</Link>}
              </li>
            ))}
          </ul>
        )}
      </Card>

      {d.usage && (
        <Card title={<span>Traffic and compute <span className="font-normal text-zinc-500">· Vercel's metered usage, daily; the last 7 days with the 30-day totals underneath</span></span>}>
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-6">
            <Stat label="Requests, 7 d" value={d.usage.last_7d.requests.toLocaleString()} hint={`${d.usage.last_30d.requests.toLocaleString()} in 30 d · edge cache ${d.usage.last_7d.cache_hit_pct ?? "—"}% hits`} />
            <Stat label="Function invocations" value={d.usage.last_7d.invocations.toLocaleString()} hint={`${d.usage.last_7d.gb_hours} GB-h · ${d.usage.last_30d.invocations.toLocaleString()} in 30 d`} />
            <Stat label="Invocation errors" value={<span className={d.usage.last_7d.error_pct >= 1 ? "text-orange-300" : "text-emerald-300"}>{d.usage.last_7d.error_pct ?? "—"}%</span>} hint={`${d.usage.last_7d.invocation_errors.toLocaleString()} errors · ${d.usage.last_7d.invocation_throttles} throttled · ${d.usage.last_7d.invocation_timeouts} timed out`} />
            <Stat label="Bandwidth out, 7 d" value={`${d.usage.last_7d.bandwidth_out_gb} GB`} hint={`${d.usage.last_30d.bandwidth_out_gb} GB in 30 d · ${d.usage.last_7d.bandwidth_in_gb} GB in`} />
            <Stat label="Builds, 7 d" value={d.usage.last_7d.builds} hint={`${d.usage.last_7d.build_minutes} min${d.usage.last_7d.builds_failed ? ` · ${d.usage.last_7d.builds_failed} failed` : ""} · ${d.usage.last_30d.builds} in 30 d`} />
            <Stat label="Blob and cron" value={d.usage.last_7d.blob_gb != null ? `${d.usage.last_7d.blob_gb} GB` : "—"} hint={`${d.usage.last_7d.blob_requests.toLocaleString()} blob requests · ${d.usage.last_7d.cron_invocations.toLocaleString()} cron runs · ${d.usage.last_7d.log_gb} GB logs`} />
          </div>
          {d.usage.series.length > 1 && (() => { const max = Math.max(1, ...d.usage.series.map((x: any) => x.requests)); return (
            <div className="mt-3">
              <div className="flex h-16 items-end gap-px" title="requests per day, last 30 days">{d.usage.series.map((x: any) => <div key={x.day} className="flex-1 rounded-t bg-sky-500/40" style={{ height: `${Math.max(2, (x.requests / max) * 100)}%` }} title={`${x.day}: ${x.requests.toLocaleString()} requests · ${x.invocations.toLocaleString()} invocations · ${x.errors} errors · ${x.bandwidth_out_gb} GB out · ${x.builds} builds`} />)}</div>
              <div className="mt-0.5 flex justify-between text-[10px] text-zinc-600"><span>{d.usage.series[0].day}</span><span>requests per day</span><span>{d.usage.series[d.usage.series.length - 1].day}</span></div>
            </div>
          ); })()}
          {d.usage.by_project.length > 0 && (
            <table className="mt-3 w-full border-collapse text-xs">
              <thead><tr><Th>Project, last 7 d</Th><Th className="text-right">Requests</Th><Th className="text-right">Invocations</Th><Th className="text-right">GB-hours</Th><Th className="text-right">Bandwidth out</Th><Th className="text-right">Builds</Th></tr></thead>
              <tbody>{d.usage.by_project.map((p: any) => <tr key={p.project_id} className="border-t border-zinc-800"><Td>{p.name}</Td><Td className="text-right">{p.requests.toLocaleString()}</Td><Td className="text-right">{p.invocations.toLocaleString()}</Td><Td className="text-right">{p.gb_hours}</Td><Td className="text-right">{p.bandwidth_out_gb} GB</Td><Td className="text-right">{p.builds}</Td></tr>)}</tbody>
            </table>
          )}
          <div className="mt-1 text-[11px] text-zinc-600">Per-project numbers come from Vercel's whole-percent breakdown of each day's totals, so they are estimates.</div>
        </Card>
      )}

      {d.billing && (
        <Card title={<span>Billing <span className="font-normal text-zinc-500">· two invoices a month: the subscription (seats, plan, add-ons, usage) on its cycle day and the Marketplace (stores such as Neon) on the 1st</span></span>}>
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            <Stat label="This month, projected" value={d.billing.this_month?.projected_usd != null ? `≈ ${usd(d.billing.this_month.projected_usd)}` : "—"} hint={(d.billing.this_month?.streams || []).map((x: any) => x.issued != null ? `${x.stream === "subscription" ? "Subscription" : "Marketplace"} ${usd(x.issued)} issued` : x.expected != null ? `${x.stream === "subscription" ? "Subscription" : "Marketplace"} ≈ ${usd(x.expected)} expected` : null).filter(Boolean).join(" · ")} />
            <Stat label="Last month" value={usd(d.billing.last_month_usd)} hint={(() => { const m = (d.billing.months || []).find((x: any) => x.month === d.billing.last_month); return m ? Object.entries(m.streams).sort().reverse().map(([k, v]: any) => `${k === "subscription" ? "Subscription" : "Marketplace"} ${usd(v)}`).join(" · ") : ""; })()} />
            <Stat label="Average, last 3 months" value={d.billing.avg_last_3_usd != null ? `${usd(d.billing.avg_last_3_usd)}/mo` : "—"} hint="every invoice of each month" />
            <Stat label="Subscription seats" value={d.billing.seats_usd_month != null ? `${usd(d.billing.seats_usd_month)}/mo` : d.billing.plan || "—"} hint={d.billing.seats != null ? `${d.billing.plan} plan · ${d.billing.seats} seats × ${usd(d.billing.seat_usd)}` : d.billing.plan ? `${d.billing.plan} plan` : ""} />
          </div>
          {d.billing.last_invoice?.groups?.length > 0 && <div className="mt-3 text-xs text-zinc-400">Last invoice ({d.billing.last_invoice.kind === "subscription" ? "subscription" : "Marketplace"}) by group: {d.billing.last_invoice.groups.map((g: any) => `${g.name} ${usd(g.total)}`).join(" · ")}</div>}
          {d.billing.last_invoice?.top_items?.length > 0 && (
            <ul className="mt-2 grid gap-x-6 gap-y-0.5 text-xs text-zinc-400 md:grid-cols-2">
              {d.billing.last_invoice.top_items.map((it: any, i: number) => <li key={i} className="flex justify-between gap-2"><span className="truncate">{it.title}{it.quantity ? <span className="text-zinc-600"> × {Math.round(it.quantity)}</span> : null}</span><span className="text-zinc-300">{usd(it.amount)}</span></li>)}
            </ul>
          )}
          {d.billing.months?.length > 0 && <div className="mt-2 text-xs text-zinc-500">By month: {d.billing.months.slice(0, 6).map((m: any) => `${m.month}${m.partial ? " (so far)" : ""} ${usd(m.usd)} (${Object.entries(m.streams).sort().reverse().map(([k, v]: any) => `${k === "subscription" ? "sub" : "mkt"} ${usd(v)}`).join(" + ")})`).join(" · ")}</div>}
        </Card>
      )}

      {(d.team_people || d.log_drains) && (
        <div className="grid gap-4 md:grid-cols-2">
          <Card title="People">
            <dl className="grid grid-cols-[9rem_1fr] gap-x-3 gap-y-1 text-sm">
              <dt className="text-zinc-500">Members</dt><dd>{d.team_people.members} · {d.team_people.owners} owners{d.team_people.unconfirmed ? ` · ${d.team_people.unconfirmed} not confirmed` : ""}</dd>
              <dt className="text-zinc-500">Without MFA</dt><dd><span className={d.team_people.without_mfa ? "text-orange-300" : "text-emerald-300"}>{d.team_people.without_mfa}</span></dd>
            </dl>
          </Card>
          <Card title={<span>Log drains <span className="font-normal text-zinc-500">· where the team's logs go</span></span>}>
            {!d.log_drains.length ? <div className="text-sm text-orange-300">None: nothing keeps the function and edge logs beyond Vercel's retention.</div> : (
              <ul className="space-y-1 text-sm">{d.log_drains.map((x: any) => <li key={x.id}><span className="text-zinc-200">{x.name || x.id}</span> <span className="text-zinc-500">→ {x.host || "?"} · {x.sources.join("+")}{x.environments.length ? ` · ${x.environments.join("/")}` : ""}{x.sampling_rate != null && x.sampling_rate < 1 ? ` · sampled ${Math.round(x.sampling_rate * 100)}%` : ""}{x.status && x.status !== "enabled" ? ` · ${x.status}` : ""} · {x.projects.join(", ")}</span></li>)}</ul>
            )}
          </Card>
        </div>
      )}

      <div className="grid gap-4 md:grid-cols-2">
        <Card title="What runs">
          <dl className="grid grid-cols-[9rem_1fr] gap-x-3 gap-y-1 text-sm">
            <dt className="text-zinc-500">Frameworks</dt><dd>{list(d.projects.frameworks)}</dd>
            <dt className="text-zinc-500">Runtimes</dt><dd>{list(d.projects.runtimes)}</dd>
          </dl>
        </Card>
        <Card title="Data stores">
          <dl className="grid grid-cols-[9rem_1fr] gap-x-3 gap-y-1 text-sm">
            <dt className="text-zinc-500">By product</dt><dd>{list(d.stores.by_product)}</dd>
            <dt className="text-zinc-500">Plans</dt><dd>{list(d.stores.plans, 6)}</dd>
            <dt className="text-zinc-500">Not connected</dt><dd>{d.stores.unconnected}</dd>
            {d.store_stats && <>
              <dt className="text-zinc-500">Blob</dt><dd>{d.store_stats.blob_gb} GB · {d.store_stats.blob_objects.toLocaleString()} objects{d.store_stats.token_expired ? <span className="text-orange-300"> · {d.store_stats.token_expired} token expired</span> : null}</dd>
              {d.store_stats.compute_hours_period != null && <><dt className="text-zinc-500">Database compute</dt><dd>{d.store_stats.compute_hours_period} h since {String(d.store_stats.period_start).slice(0, 10)} <span className="text-xs text-zinc-500">· {d.store_stats.compute_by_store.filter((x: any) => x.hours).map((x: any) => `${x.name} ${x.hours} h`).join(" · ")}</span></dd></>}
              {d.store_stats.monthly_list_usd != null && <><dt className="text-zinc-500">At their plans</dt><dd>~{usd(d.store_stats.monthly_list_usd)}/mo <span className="text-xs text-zinc-500">· this period's pace at the plans' listed rates</span></dd></>}
            </>}
          </dl>
          <div className="mt-2 text-xs text-zinc-500"><Link className="underline" to="/inventory?tab=rds">databases</Link> · <Link className="underline" to="/inventory?tab=elasticache">caches</Link> · <Link className="underline" to="/inventory?tab=s3">object storage</Link></div>
        </Card>
      </div>
    </div>
  );
}

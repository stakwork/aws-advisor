import { useEffect, useState } from "react";
import { api, usd, when } from "../api";
import { Card, Stat, Td, Th } from "./ui";

const gb = (bytes: number | null | undefined) => (bytes == null ? "—" : bytes >= 1e9 ? `${(bytes / 1e9).toFixed(2)} GB` : bytes >= 1e6 ? `${(bytes / 1e6).toFixed(1)} MB` : `${bytes} B`);
const h = (n: number | null | undefined) => (n == null ? "—" : `${Math.round(n * 10) / 10} h`);
/** One line from the partner's own API, when a key is saved: Neon's storage, compute range and state; Redis Cloud's memory used against its limit. */
function partnerCell(st: any) {
  const snap = st.partner?.snapshot;
  if (!snap) return st.partner?.error ? <span className="text-orange-300" title={st.partner.error}>read failed</span> : <span className="text-zinc-600">no key</span>;
  if (snap.kind === "neon") { const p = snap.project; const rw = snap.endpoints.find((e: any) => e.type === "read_write") ?? snap.endpoints[0]; return <>{gb(p.storage_bytes)} · {snap.branches.length} branch{snap.branches.length === 1 ? "" : "es"} · {rw ? `${rw.min_cu}–${rw.max_cu} CU, ${rw.state ?? "?"}` : "no compute"} · pg {p.pg_version}</>; }
  const d = snap.database; return <>{d.memory_used_mb != null ? `${d.memory_used_mb} MB` : "?"} of {d.memory_limit_mb ?? "?"} MB · {d.persistence || "no persistence"}{d.replication ? " · replicated" : ""} · {d.status || "?"}</>;
}

/**
 * The team's stores of one kind (databases, caches, object storage) with the numbers Vercel gives for each: a Neon
 * database's compute hours this period and what they cost at its plan, a Redis store's plan limits, a Blob store's
 * size and objects. Click a name for the store in full.
 */
export function VercelStores({ kind }: { kind: "database" | "cache" | "storage" }) {
  const [d, setD] = useState<any>(null); const [msg, setMsg] = useState(""); const [detail, setDetail] = useState<string | null>(null);
  useEffect(() => { api(`/vercel/stores?kind=${kind}`).then(setD).catch((e) => setMsg(e.message)); }, [kind]);
  const title = kind === "database" ? "Databases" : kind === "cache" ? "Caches" : "Object storage";
  if (!d) return <Card title={title}><div className="text-sm text-zinc-500">{msg || "Loading…"}</div></Card>;
  if (!d.configured) return <Card title={title}><div className="text-sm text-zinc-500">No Vercel token saved.</div></Card>;
  const compute = (st: any) => st.details?.usage_period?.items?.find((u: any) => /compute/i.test(u.name)) ?? null;
  const meta = (st: any, key: string) => { const m = st.details?.metadata || {}; const k = Object.keys(m).find((x) => x.toLowerCase() === key); return k ? String(m[k]) : null; };
  return (
    <Card title={<span>{title} <span className="font-normal text-zinc-500">· {d.stores.length} on Vercel, provisioned through the marketplace or Vercel's own storage; click one for everything Vercel says about it</span></span>}>
      {!d.stores.length ? <div className="text-sm text-zinc-500">None on this team.</div> : (
        <table className="w-full border-collapse text-sm">
          <thead><tr>
            <Th>Name</Th><Th>Product</Th><Th>Plan</Th><Th>Region</Th><Th>Status</Th>
            {kind === "database" && <><Th className="text-right">Compute, this period</Th><Th>At Neon</Th><Th>Auth</Th></>}
            {kind === "cache" && <><Th>High availability</Th><Th>Storage</Th><Th>At Redis Cloud</Th></>}
            {kind === "storage" && <><Th className="text-right">Size</Th><Th className="text-right">Objects</Th><Th>Access</Th></>}
            <Th>Used by</Th><Th>Since</Th>
          </tr></thead>
          <tbody>
            {d.stores.map((st: any) => {
              const c = compute(st);
              return (
                <>
                  <tr key={st.id} className="border-t border-zinc-800">
                    <Td><button type="button" className="text-left text-zinc-100 hover:underline" onClick={() => setDetail(detail === st.id ? null : st.id)} title="Open the store's detail">{st.name}</button><div className="font-mono text-[11px] text-zinc-500">{st.id}</div></Td>
                    <Td>{st.product || st.type}{st.details?.external_id ? <div className="font-mono text-[11px] text-zinc-500">{st.details.external_id}</div> : null}</Td>
                    <Td className="text-zinc-300">{st.plan || "—"}{st.details?.quota_exceeded ? <span className="text-orange-300"> · over quota</span> : null}</Td>
                    <Td className="text-zinc-400">{st.region || "—"}</Td>
                    <Td><span className={st.status === "available" || st.status === "ready" ? "text-emerald-300" : "text-zinc-300"}>{st.status || "—"}</span>{st.details?.external_status && st.details.external_status !== st.status ? <span className="text-xs text-zinc-500"> · {st.details.external_status}</span> : null}</Td>
                    {kind === "database" && <><Td className="text-right">{c ? h(c.period_value) : "—"}</Td><Td className="text-xs text-zinc-400">{partnerCell(st)}</Td><Td className="text-xs text-zinc-400">{meta(st, "auth") === "true" ? "Neon Auth on" : meta(st, "auth") === "false" ? "off" : "—"}</Td></>}
                    {kind === "cache" && <><Td className="text-xs text-zinc-400">{meta(st, "highavailability") || "—"}</Td><Td className="text-xs text-zinc-400">{meta(st, "storagetype") || "—"}</Td><Td className="text-xs text-zinc-400">{partnerCell(st)}</Td></>}
                    {kind === "storage" && <><Td className="text-right">{gb(st.details?.size_bytes)}</Td><Td className="text-right">{st.details?.object_count?.toLocaleString?.() ?? "—"}</Td><Td className="text-xs text-zinc-400">{st.details?.access || "—"}{st.details?.token_expired ? <span className="text-orange-300"> · token expired</span> : null}</Td></>}
                    <Td className="text-xs">{st.projects.length ? st.projects.map((pr: any) => `${pr.name || pr.project_id}${pr.environments.length ? ` (${pr.environments.join(", ")})` : ""}`).join(", ") : <span className="text-zinc-500">no project connected</span>}</Td>
                    <Td className="whitespace-nowrap text-xs text-zinc-500">{when(st.created_at)}</Td>
                  </tr>
                  {detail === st.id && <tr key={`${st.id}-detail`}><td colSpan={12} className="py-2"><VercelStoreDetail id={st.id} onClose={() => setDetail(null)} /></td></tr>}
                </>
              );
            })}
          </tbody>
        </table>
      )}
    </Card>
  );
}

/** One store in full: the plan and its lines, the partner's metadata, the secrets it injects (names only), the projects on it, its usage and what it costs at the plan. */
export function VercelStoreDetail({ id, onClose }: { id: string; onClose: () => void }) {
  const [d, setD] = useState<any>(null); const [err, setErr] = useState("");
  useEffect(() => { setD(null); api(`/vercel/stores/${encodeURIComponent(id)}`).then(setD).catch((e) => setErr(e.message)); }, [id]);
  if (err) return <Card title="Store"><div className="text-sm text-red-300">{err}</div></Card>;
  if (!d) return <Card title="Store"><div className="text-sm text-zinc-500">Loading…</div></Card>;
  const dd = d.details; const compute = dd.usage_period?.items?.find((u: any) => /compute/i.test(u.name)) ?? null;
  const metaRows = Object.entries(dd.metadata || {});
  const caps = Object.entries(dd.capabilities || {}).filter(([, v]) => v).map(([k]) => k);
  return (
    <Card title={<span className="flex items-center justify-between"><span>{d.name} <span className="font-normal text-zinc-500">· {d.product || d.type}{d.plan ? ` · ${d.plan}` : ""}{d.region ? ` · ${d.region}` : ""} · <span className="font-mono text-xs">{d.id}</span></span></span><button type="button" className="text-zinc-500" onClick={onClose}>close</button></span>}>
      <div className="grid gap-4 md:grid-cols-2">
        <dl className="grid grid-cols-[10rem_1fr] gap-x-3 gap-y-1 text-sm">
          <dt className="text-zinc-500">Status</dt><dd><span className={d.state === "available" ? "text-emerald-300" : "text-zinc-300"}>{d.status || "—"}</span>{dd.external_status ? <span className="text-xs text-zinc-500"> · partner: {dd.external_status}</span> : null}{dd.billing_state ? <span className="text-xs text-zinc-500"> · billing {dd.billing_state}</span> : null}{dd.quota_exceeded ? <span className="text-orange-300"> · over quota</span> : null}</dd>
          {dd.external_id && <><dt className="text-zinc-500">At {d.product || "the partner"}</dt><dd className="font-mono text-xs">{dd.external_id}{dd.ownership ? <span className="font-sans text-zinc-500"> · {dd.ownership}</span> : null}</dd></>}
          {d.type === "blob" && <><dt className="text-zinc-500">Size</dt><dd>{gb(dd.size_bytes)} · {dd.object_count?.toLocaleString?.() ?? "—"} objects · {dd.access || "—"}{dd.token_expired ? <span className="text-orange-300"> · token expired</span> : ""}</dd></>}
          {metaRows.map(([k, v]) => <><dt key={`${k}-k`} className="text-zinc-500">{k.replace(/([a-z])([A-Z])/g, "$1 $2")}</dt><dd key={`${k}-v`}>{String(v)}</dd></>)}
          <dt className="text-zinc-500">Created</dt><dd>{when(d.created_at)}{dd.updated_at ? <span className="text-xs text-zinc-500"> · updated {when(dd.updated_at)}</span> : null}</dd>
          {caps.length > 0 && <><dt className="text-zinc-500">Can</dt><dd className="text-xs text-zinc-400">{caps.join(", ")}</dd></>}
          {dd.product_description && <><dt className="text-zinc-500">Product</dt><dd className="text-xs text-zinc-400">{dd.product_description}{dd.product_tags?.length ? ` · ${dd.product_tags.map((t: string) => t.replace(/^tag_/, "")).join(", ")}` : ""}</dd></>}
        </dl>
        <div className="space-y-2 text-xs">
          <div className="text-zinc-500">Plan{dd.plan_scope ? ` · ${dd.plan_scope}` : ""}{dd.plan_type ? ` · ${dd.plan_type}` : ""}</div>
          {d.plan ? <div>{d.plan}{dd.plan_cost ? <span className="text-zinc-500"> {dd.plan_cost}</span> : null}{dd.plan_description ? <div className="text-zinc-500">{dd.plan_description}</div> : null}</div> : <div className="text-zinc-600">no plan reported</div>}
          {dd.plan_lines?.length > 0 && <ul className="space-y-0.5">{dd.plan_lines.map((l: any, i: number) => <li key={i} className="flex justify-between gap-2"><span className="text-zinc-400">{l.label}</span><span className="text-zinc-200">{l.value}</span></li>)}</ul>}
          <div className="text-zinc-500">Used by</div>
          {d.projects.length ? <ul className="space-y-0.5">{d.projects.map((p: any) => <li key={p.project_id}>{p.name || p.project_id} <span className="text-zinc-500">· {p.environments.join(", ") || "no environment"}{p.framework ? ` · ${p.framework}` : ""}{p.env_var_names?.length ? ` · injects ${p.env_var_names.length} variables${p.env_var_prefix ? ` (prefix ${p.env_var_prefix})` : ""}` : ""}</span></li>)}</ul> : <div className="text-zinc-600">no project connected</div>}
          {dd.secret_names?.length > 0 && <><div className="text-zinc-500">Secrets it provides <span className="text-zinc-600">(names only; values are never read)</span></div><div className="break-words font-mono text-[11px] leading-4 text-zinc-500">{dd.secret_names.map((x: any) => x.name).join(" · ")}</div></>}
        </div>
      </div>
      {d.partner?.snapshot?.kind === "neon" && (() => { const p = d.partner.snapshot.project; const s = d.partner.snapshot; return (
        <div className="mt-4 rounded border border-zinc-800 p-3 text-xs">
          <div className="mb-1 text-zinc-500">At Neon <span className="text-zinc-600">· project {p.id}{p.name ? ` (${p.name})` : ""} · read {when(s.read_at)}</span></div>
          <div className="grid gap-x-6 gap-y-1 md:grid-cols-2">
            <div><span className="text-zinc-500">Storage</span> {gb(p.storage_bytes)} · history {p.history_retention_seconds != null ? `${Math.round(p.history_retention_seconds / 3600)} h` : "—"} · pg {p.pg_version} · {p.region}</div>
            <div><span className="text-zinc-500">This period</span> {p.compute_time_seconds != null ? `${Math.round(p.compute_time_seconds / 360) / 10} compute h` : "—"} · {p.active_time_seconds != null ? `${Math.round(p.active_time_seconds / 360) / 10} active h` : "—"} · wrote {gb(p.written_data_bytes)} · transferred {gb(p.data_transfer_bytes)}{p.consumption_period_start ? ` · since ${String(p.consumption_period_start).slice(0, 10)}` : ""}</div>
            <div><span className="text-zinc-500">IP allow list</span> {p.ip_allow.length ? `${p.ip_allow.join(", ")}${p.ip_allow_protected_only ? " (protected branches only)" : ""}` : <span className="text-orange-300/80">none: any address may try the password</span>}</div>
            <div><span className="text-zinc-500">Databases</span> {s.databases.map((x: any) => x.name).join(", ") || "—"}</div>
          </div>
          <table className="mt-2 w-full border-collapse"><thead><tr><Th>Compute endpoint</Th><Th>Branch</Th><Th>State</Th><Th>CU</Th><Th>Suspends after</Th><Th>Last active</Th></tr></thead>
            <tbody>{s.endpoints.map((e: any) => { const b = s.branches.find((x: any) => x.id === e.branch_id); return <tr key={e.id} className="border-t border-zinc-800/60"><Td className="font-mono">{e.host || e.id}{e.pooler ? <span className="font-sans text-zinc-500"> pooler</span> : null}</Td><Td>{b?.name || e.branch_id || "—"}{b?.default ? <span className="text-zinc-500"> default</span> : ""}{b?.protected ? <span className="text-zinc-500"> protected</span> : ""}</Td><Td className={e.state === "active" ? "text-emerald-300" : "text-zinc-400"}>{e.state || "—"}{e.disabled ? " (disabled)" : ""}</Td><Td>{e.min_cu}–{e.max_cu}</Td><Td>{e.suspend_timeout_seconds === 0 ? <span className="text-orange-300/80">never</span> : e.suspend_timeout_seconds != null ? `${e.suspend_timeout_seconds} s` : "—"}</Td><Td className="whitespace-nowrap text-zinc-500">{when(e.last_active)}</Td></tr>; })}</tbody></table>
          {s.branches.length > 1 && <div className="mt-1 text-zinc-500">Branches: {s.branches.map((b: any) => `${b.name || b.id} ${gb(b.logical_size_bytes)}${b.default ? " (default)" : ""}`).join(" · ")}</div>}
        </div>
      ); })()}
      {d.partner?.snapshot?.kind === "redis_cloud" && (() => { const r = d.partner.snapshot.database; const sub = d.partner.snapshot.subscription; return (
        <div className="mt-4 rounded border border-zinc-800 p-3 text-xs">
          <div className="mb-1 text-zinc-500">At Redis Cloud <span className="text-zinc-600">· {sub.kind === "essentials" ? "Essentials" : "Pro"} subscription {sub.name || sub.id}{sub.plan ? ` (${sub.plan})` : ""} · read {when(d.partner.snapshot.read_at)}</span></div>
          <div className="grid gap-x-6 gap-y-1 md:grid-cols-2">
            <div><span className="text-zinc-500">Memory</span> {r.memory_used_mb != null ? `${r.memory_used_mb} MB` : "?"} of {r.memory_limit_mb ?? "?"} MB{r.memory_used_mb != null && r.memory_limit_mb ? ` (${Math.round((r.memory_used_mb / r.memory_limit_mb) * 100)}%)` : ""} · {r.memory_storage || "ram"} · eviction {r.eviction || "—"}</div>
            <div><span className="text-zinc-500">Durability</span> persistence {r.persistence || "none"} · {r.replication ? "replicated" : "no replica"}{r.clustering ? " · clustered" : ""} · redis {r.redis_version || "?"} · {r.status || "?"}</div>
            <div><span className="text-zinc-500">Throughput</span> {r.throughput_value != null ? `${r.throughput_value} ${r.throughput_by || ""}` : "—"}{r.modules?.length ? ` · modules ${r.modules.join(", ")}` : ""}</div>
            <div><span className="text-zinc-500">Endpoint</span> <span className="font-mono">{r.public_endpoint || "—"}</span> · {r.tls ? "TLS" : <span className="text-orange-300/80">no TLS</span>} · {r.source_ips.length && !r.source_ips.some((ip: string) => /^0\.0\.0\.0\/0$|^::\/0$/.test(ip)) ? `source IPs ${r.source_ips.join(", ")}` : <span className="text-orange-300/80">any source IP, password only</span>}</div>
          </div>
        </div>
      ); })()}
      {d.partner?.error && <div className="mt-2 text-xs text-orange-300">{d.product}: {d.partner.error} (read {when(d.partner.read_at)})</div>}
      {!d.partner && d.partners_configured && ((d.product_slug === "neon" && !d.partners_configured.neon) || (/redis/i.test(d.product_slug || d.type) && !d.partners_configured.redis)) && <div className="mt-2 text-xs text-zinc-500">What {d.product} itself knows (storage, compute, memory, endpoints) needs its API key: Settings › Accounts › Vercel › Partners.</div>}
      {d.endpoints?.length > 0 && <div className="mt-2 text-xs text-zinc-400">Answers on: {d.endpoints.map((e: any) => `${e.hostname}:${e.port} (${e.protocol}, ${e.note})`).join(" · ")}</div>}
      <div className="mt-4 grid grid-cols-2 gap-3 lg:grid-cols-4">
        {compute && <Stat label={`Compute, since ${String(dd.usage_period.start).slice(0, 10)}`} value={h(compute.period_value)} hint={`as ${d.product || "the partner"} reports it to Vercel${dd.usage_period.read_at ? ` · read ${when(dd.usage_period.read_at)}` : ""}`} />}
        {d.type === "blob" && <Stat label="Stored" value={gb(dd.size_bytes)} hint={`${dd.object_count?.toLocaleString?.() ?? "—"} objects`} />}
        <Stat label="At the plan's rates" value={d.cost.monthly_list_usd != null ? `~${usd(d.cost.monthly_list_usd, 2)}/mo` : "—"} hint={d.cost.lines.length ? d.cost.lines.map((l: any) => `${l.quantity} ${l.unit} × $${l.usd}`).join(" · ") : "no priced usage"} />
        {d.plan_rates?.lines?.some((l: any) => l.price) && <Stat label="Plan rates" value={d.plan_rates.lines.filter((l: any) => l.price).map((l: any) => `$${l.price.usd}/${l.price.unit}`).join(" · ")} hint={d.plan_rates.lines.filter((l: any) => l.price).map((l: any) => l.label).join(" · ")} />}
      </div>
      {d.cost.lines.length > 0 && <div className="mt-1 text-[11px] text-zinc-600">At this period's pace: the usage so far scaled to 30 days and priced at the plan's listed rate; the marketplace bills through Vercel's invoice at the period's end.</div>}
      {d.usage_series.length > 1 && (() => { const max = Math.max(1, ...d.usage_series.map((x: any) => x.simple_requests + x.advanced_requests)); return (
        <div className="mt-3">
          <div className="flex h-12 items-end gap-px">{d.usage_series.map((x: any) => <div key={x.day} className="flex-1 rounded-t bg-sky-500/40" style={{ height: `${Math.max(2, ((x.simple_requests + x.advanced_requests) / max) * 100)}%` }} title={`${x.day}: ${x.simple_requests.toLocaleString()} simple + ${x.advanced_requests.toLocaleString()} advanced requests${x.size_gb != null ? ` · ${x.size_gb} GB` : ""}`} />)}</div>
          <div className="mt-0.5 flex justify-between text-[10px] text-zinc-600"><span>{d.usage_series[0].day}</span><span>blob requests per day (from Vercel's per-store breakdown)</span><span>{d.usage_series[d.usage_series.length - 1].day}</span></div>
        </div>
      ); })()}
    </Card>
  );
}

/** The rates the advisor knows for the team, for the bill page: the plan, the listed metered items, the marketplace plans and what the last invoice charged per unit. */
export function VercelRatesCard({ rates }: { rates: any }) {
  const [all, setAll] = useState(false);
  if (!rates) return null;
  const p = rates.plan; const shown = all ? rates.team_rates : rates.team_rates.slice(0, 12);
  const fmt = (v: number) => (v >= 0.01 ? `$${v}` : `$${v.toExponential(2)}`);
  return (
    <Card title={<span>Your rates <span className="font-normal text-zinc-500">· Vercel's price list for this team (the team object), the marketplace plans the stores are on, and what the last invoice actually charged per unit; written to the graph as pricing knowledge</span></span>}>
      {p && <div className="mb-3 text-sm text-zinc-300">{p.plan} plan{p.status ? ` (${p.status})` : ""}: {p.base_usd_month != null ? `$${p.base_usd_month}/mo base` : ""}{p.seat_usd != null ? ` · $${p.seat_usd} per seat × ${p.seats}` : ""}{p.included_usage_usd != null ? ` · $${p.included_usage_usd} of usage included` : ""}</div>}
      <div className="grid gap-4 md:grid-cols-2">
        <div>
          <div className="mb-1 text-xs text-zinc-500">Metered items · {rates.team_rates.length} listed</div>
          <ul className="space-y-0.5 text-xs">{shown.map((r: any) => <li key={r.item} className="flex justify-between gap-2"><span className="truncate text-zinc-400">{r.label}</span><span className="text-zinc-200">{fmt(r.usd)} / {r.unit}</span></li>)}</ul>
          {rates.team_rates.length > 12 && <button type="button" className="mt-1 text-xs text-sky-300 hover:underline" onClick={() => setAll(!all)}>{all ? "fewer" : `all ${rates.team_rates.length}`}</button>}
        </div>
        <div className="space-y-3">
          {rates.store_plans.length > 0 && <div>
            <div className="mb-1 text-xs text-zinc-500">Marketplace plans</div>
            <ul className="space-y-1 text-xs">{rates.store_plans.map((sp: any) => <li key={sp.store_id}><span className="text-zinc-200">{sp.store}</span> <span className="text-zinc-500">· {sp.product} {sp.plan}</span><div className="text-zinc-400">{sp.lines.map((l: any) => `${l.label}: ${l.value}`).join(" · ")}</div></li>)}</ul>
          </div>}
          {rates.observed.length > 0 && <div>
            <div className="mb-1 text-xs text-zinc-500">Observed on invoice {rates.invoice?.number || ""} · amount over quantity</div>
            <ul className="space-y-0.5 text-xs">{rates.observed.map((o: any) => <li key={o.item} className="flex justify-between gap-2"><span className="truncate text-zinc-400">{o.label}</span><span className="text-zinc-200">{fmt(o.usd)} each · {Math.round(o.quantity * 100) / 100} for {usd(o.amount, 2)}</span></li>)}</ul>
          </div>}
        </div>
      </div>
    </Card>
  );
}

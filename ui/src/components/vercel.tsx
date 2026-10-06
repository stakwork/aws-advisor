import { useEffect, useState } from "react";
import { api, when } from "../api";
import { Button, Card, Stat, Td, Th } from "./ui";

/**
 * Settings › Accounts › a Vercel account: Access (the token and team id, tested against the API before they are
 * saved; the token is never shown again) and Projects (every project with its framework and runtime, the latest
 * deployment, the URLs it exposes and who may open each, its domains, the env variable names, the firewall).
 */

export function VercelAccess({ configured, onChange }: { configured: boolean; onChange: () => void }) {
  const [token, setToken] = useState(""); const [teamId, setTeamId] = useState("");
  const [busy, setBusy] = useState(false); const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const save = async (e: React.FormEvent) => {
    e.preventDefault(); setBusy(true); setMsg(null);
    try { const r = await api("/providers/vercel/accounts", { method: "POST", body: JSON.stringify({ token, team_id: teamId }) }); setMsg({ ok: true, text: `${r.account.name || r.account.id}${r.account.plan ? ` (${r.account.plan} plan)` : ""}: ${r.note}` }); setToken(""); onChange(); }
    catch (err: any) { setMsg({ ok: false, text: err.message }); } finally { setBusy(false); }
  };
  const remove = async () => { setBusy(true); try { await api("/providers/vercel/accounts/current", { method: "DELETE" }); setMsg({ ok: true, text: "removed: the token, the stored projects and the graph nodes" }); onChange(); } catch (err: any) { setMsg({ ok: false, text: err.message }); } finally { setBusy(false); } };
  return (
    <Card title="Vercel access">
      <p className="mb-3 text-sm text-zinc-400">A Vercel access token with read scope (Account settings › Tokens). For a team, the team id (<span className="font-mono text-xs">team_…</span>, from the team's settings); leave it empty for a personal account. The token is checked against the API, saved as a runtime secret and never shown again. Only reads: projects, deployments, domains, the <em>names</em> of environment variables (never their values) and the firewall state.</p>
      <form onSubmit={save} className="grid gap-3">
        <label className="grid gap-1 text-sm"><span className="text-zinc-400">Access token{configured ? " (paste to replace)" : ""}</span><input type="password" autoComplete="off" value={token} onChange={(e) => setToken(e.target.value)} required /></label>
        <label className="grid gap-1 text-sm"><span className="text-zinc-400">Team id (optional)</span><input autoComplete="off" value={teamId} onChange={(e) => setTeamId(e.target.value)} placeholder="team_…" pattern="^(team_[A-Za-z0-9]+)?$" /></label>
        <div className="flex items-center gap-2">
          <Button type="submit" disabled={busy}>{busy ? "Testing…" : "Save and test"}</Button>
          {configured && <Button type="button" variant="danger" onClick={remove} disabled={busy}>Remove</Button>}
        </div>
        {msg && <div className={`text-sm ${msg.ok ? "text-emerald-300" : "text-red-300"}`}>{msg.text}</div>}
      </form>
    </Card>
  );
}

export function VercelProjects() {
  const [d, setD] = useState<any>(null); const [msg, setMsg] = useState(""); const [busy, setBusy] = useState(false); const [open, setOpen] = useState<string | null>(null); const [detail, setDetail] = useState<string | null>(null);
  const load = () => api("/vercel/projects").then(setD).catch((e) => setMsg(e.message));
  useEffect(() => { load(); }, []);
  const refresh = async () => { setBusy(true); setMsg(""); try { const r = await api("/vercel/refresh", { method: "POST" }); setMsg(r.ok ? `read ${r.projects} projects` : `read with errors: ${r.errors.join("; ")}`); load(); } catch (e: any) { setMsg(e.message); } finally { setBusy(false); } };
  if (!d) return <Card title="Projects"><div className="text-sm text-zinc-500">{msg || "Loading…"}</div></Card>;
  if (!d.configured) return <Card title="Projects"><div className="text-sm text-zinc-500">Save a token under Access first.</div></Card>;
  const authWords = (e: any) => (e.requires_auth ? `asks for ${e.via === "sso" ? "Vercel login" : e.via === "password" ? "a password" : "a trusted IP"}` : "open to anyone");
  const SHOW = 5;
  return (
    <Card title={<span>Projects <span className="font-normal text-zinc-500">· {d.team?.name || d.team?.slug || "team"}{d.team?.plan ? ` · ${d.team.plan} plan` : ""}{d.team?.fetched_at ? ` · read ${when(d.team.fetched_at)}` : ""}</span></span>}>
      <div className="mb-3 flex flex-wrap items-center gap-2 text-xs text-zinc-400"><span>{d.projects.length} projects · each URL says whether Vercel asks for authentication before serving it (deployment protection)</span><span className="grow" /><Button variant="ghost" onClick={refresh} disabled={busy}>{busy ? "Reading…" : "Refresh now"}</Button>{msg && <span className="text-zinc-300">{msg}</span>}</div>
      {!d.projects.length ? <div className="text-sm text-zinc-500">No projects read yet; the first collection runs right after the token is saved.</div> : (
        <div className="space-y-2">
          {d.projects.map((p: any) => {
            const isOpen = open === p.id;
            const eps = isOpen ? p.endpoints : p.endpoints.slice(0, SHOW);
            const openCount = p.endpoints.filter((e: any) => !e.requires_auth).length;
            return (
              <div key={p.id} className="rounded border border-zinc-800 bg-zinc-950/40 p-3 text-sm">
                <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
                  <button type="button" className="text-zinc-100 hover:underline" onClick={() => setDetail(detail === p.id ? null : p.id)} title="Open the project's detail: deployments, domains, env names, usage">{p.name}</button>
                  <span className="text-xs text-zinc-400">{p.framework || "no framework"}{p.node_version ? ` · node ${p.node_version}` : ""}</span>
                  <span className="text-xs"><span className={p.latest_state === "READY" ? "text-emerald-300" : p.latest_state === "ERROR" ? "text-red-300" : "text-zinc-300"}>{p.latest_state || "—"}</span><span className="text-zinc-500">{p.latest_target ? ` · ${p.latest_target}` : " · preview"} · {when(p.latest_at)}</span></span>
                  <span className="text-xs text-zinc-500">{p.env_count} env names · firewall {p.firewall ? (p.firewall.enabled ? `on, ${p.firewall.rules} rules` : "off") : "not readable"}</span>
                  <span className="grow" />
                  <span className={`text-xs ${openCount ? "text-orange-300" : "text-emerald-300"}`}>{openCount} of {p.endpoints.length} URLs open to anyone</span>
                </div>
                {p.repo && <div className="mt-0.5 text-[11px] text-zinc-500">{p.git_provider} · {p.repo} · <span className="font-mono">{p.id}</span></div>}
                {p.stores?.length > 0 && <div className="mt-1 text-[11px] text-zinc-400">uses: {p.stores.map((st: any) => `${st.name} (${st.product || st.kind}${st.plan ? ` · ${st.plan}` : ""}${st.region ? ` · ${st.region}` : ""})`).join(", ")}</div>}
                {p.connect?.length > 0 && <div className="mt-1 text-[11px] text-zinc-400">Secure Compute: functions run in a dedicated AWS network behind <span className="font-mono">{[...new Set(p.connect.map((c: any) => c.security_group).filter(Boolean))].join(", ")}</span>, {[...new Set(p.connect.flatMap((c: any) => c.subnets))].length} subnets ({[...new Set(p.connect.map((c: any) => c.env))].join(", ")}{p.connect[0]?.dc ? ` · ${p.connect[0].dc}` : ""}){p.connect_in_inventory ? <span className="text-emerald-300"> · in the AWS inventory, linked in the graph</span> : <span className="text-zinc-500"> · Vercel's own network, not in the AWS inventory (a peering to it would show under Network › Gateways)</span>}</div>}
                <ul className="mt-2 space-y-0.5 text-xs">
                  {eps.map((e: any) => (
                    <li key={e.id} className="flex flex-wrap gap-x-2">
                      <a className="min-w-0 break-all font-mono hover:underline" href={e.url} target="_blank" rel="noreferrer">{e.hostname}</a>
                      <span className="text-zinc-500">{e.target}{e.domain ? " · domain" : ""}</span>
                      <span className={e.requires_auth ? "text-emerald-300" : "text-orange-300"}>{authWords(e)}</span>
                    </li>
                  ))}
                </ul>
                <div className="mt-1 flex flex-wrap gap-3 text-[11px]">
                  {p.endpoints.length > SHOW && <button type="button" className="text-sky-300 hover:underline" onClick={() => setOpen(isOpen ? null : p.id)}>{isOpen ? "fewer URLs" : `${p.endpoints.length - SHOW} more URLs`}</button>}
                  {(p.protection.sso || p.protection.password || p.protection.trusted_ips) && <span className="text-zinc-500">protection: {[p.protection.sso && `login on ${p.protection.sso.replace(/_/g, " ")}`, p.protection.password && `password on ${p.protection.password.replace(/_/g, " ")}`, p.protection.trusted_ips && `trusted IPs on ${p.protection.trusted_ips.replace(/_/g, " ")}`].filter(Boolean).join("; ")}</span>}
                  {p.domains.some((x: any) => x.redirect) && <span className="text-zinc-500">redirects: {p.domains.filter((x: any) => x.redirect).map((x: any) => `${x.name} → ${x.redirect}`).join(", ")}</span>}
                  {p.env_names.length > 0 && <button type="button" className="text-sky-300 hover:underline" onClick={() => setOpen(isOpen ? null : p.id)}>{isOpen ? "hide env names" : "env names"}</button>}
                </div>
                {isOpen && p.env_names.length > 0 && <div className="mt-1 break-words font-mono text-[11px] leading-4 text-zinc-500">{p.env_names.map((e: any) => `${e.key} (${e.targets.join(",")})`).join(" · ")}</div>}
                {detail === p.id && <div className="mt-3"><VercelProjectDetail id={p.id} onClose={() => setDetail(null)} /></div>}
              </div>
            );
          })}
        </div>
      )}
    </Card>
  );
}

/** The team's stores of one kind (database: Neon and friends; cache: Redis, KV; storage: Blob, Edge Config), with the projects on each. */
/** One project in full: the detail panel the Deployments tab opens, with the same depth an instance gets. */
export function VercelProjectDetail({ id, onClose }: { id: string; onClose: () => void }) {
  const [d, setD] = useState<any>(null); const [err, setErr] = useState(""); const [tab, setTab] = useState<"overview" | "deployments" | "domains" | "env" | "usage">("overview");
  useEffect(() => { setD(null); api(`/vercel/projects/${encodeURIComponent(id)}`).then(setD).catch((e) => setErr(e.message)); }, [id]);
  if (err) return <Card title="Project"><div className="text-sm text-red-300">{err}</div></Card>;
  if (!d) return <Card title="Project"><div className="text-sm text-zinc-500">Loading…</div></Card>;
  const tabs: [typeof tab, string][] = [["overview", "Overview"], ["deployments", `Deployments ${d.deployments.length}`], ["domains", `Domains ${d.domains.length}`], ["env", `Env names ${d.env_names.length}`], ["usage", "Usage"]];
  const u7 = d.usage.last_7d; const u30 = d.usage.last_30d;
  const authWords = (e: any) => (e.requires_auth ? `asks for ${e.via === "sso" ? "Vercel login" : e.via === "password" ? "a password" : "a trusted IP"}` : "open to anyone");
  return (
    <Card title={<span className="flex items-center justify-between"><span>{d.name} <span className="font-normal text-zinc-500">· {d.framework || "no framework"}{d.node_version ? ` · node ${d.node_version}` : ""} · <span className="font-mono text-xs">{d.id}</span></span></span><button type="button" className="text-zinc-500" onClick={onClose}>close</button></span>}>
      <div className="mb-3 flex gap-1 border-b border-zinc-800">{tabs.map(([k, label]) => <button key={k} type="button" onClick={() => setTab(k)} className={`-mb-px border-b-2 px-3 py-1.5 text-sm ${tab === k ? "border-zinc-100 text-zinc-100" : "border-transparent text-zinc-400 hover:text-zinc-200"}`}>{label}</button>)}</div>
      {tab === "overview" && (
        <div className="grid gap-4 md:grid-cols-2">
          <dl className="grid grid-cols-[9rem_1fr] gap-x-3 gap-y-1 text-sm">
            <dt className="text-zinc-500">Repository</dt><dd>{d.repo ? `${d.git_provider} · ${d.repo}` : "—"}</dd>
            <dt className="text-zinc-500">Created</dt><dd>{when(d.created_at)}</dd>
            <dt className="text-zinc-500">Latest deployment</dt><dd><span className={d.latest_state === "READY" ? "text-emerald-300" : d.latest_state === "ERROR" ? "text-red-300" : ""}>{d.latest_state || "—"}</span> · {d.latest_target || "preview"} · {when(d.latest_at)}{d.latest_url && <> · <a className="font-mono text-xs hover:underline" href={d.latest_url} target="_blank" rel="noreferrer">{d.latest_url.replace(/^https:\/\//, "")}</a></>}</dd>
            <dt className="text-zinc-500">Protection</dt><dd className="text-xs">{d.protection.sso ? `login on ${d.protection.sso.replace(/_/g, " ")}` : ""}{d.protection.password ? ` · password on ${d.protection.password.replace(/_/g, " ")}` : ""}{d.protection.trusted_ips ? ` · trusted IPs on ${d.protection.trusted_ips.replace(/_/g, " ")}` : ""}{!d.protection.sso && !d.protection.password && !d.protection.trusted_ips && <span className="text-orange-300">none: every URL opens for anyone</span>}</dd>
            <dt className="text-zinc-500">Firewall</dt><dd className="text-xs">{d.firewall ? (d.firewall.enabled ? `on · ${d.firewall.rules} rules · ${d.firewall.ips} IP rules` : "off") : "not readable with this token"}</dd>
            <dt className="text-zinc-500">At list</dt><dd className="text-xs">{d.list_cost?.lines?.length ? <>~${d.list_cost.monthly_list_usd}/mo <span className="text-zinc-500">· {d.list_cost.lines.map((l: any) => `${l.label} ${l.quantity.toLocaleString()} × $${l.usd} = $${l.usd_month}`).join(" · ")} · last 30 days at the team's rates, before the plan's included allocation</span></> : <span className="text-zinc-500">no metered usage priced yet</span>}</dd>
            <dt className="text-zinc-500">Logs drain to</dt><dd className="text-xs">{d.log_drains?.length ? d.log_drains.map((x: any) => `${x.name || x.id} → ${x.host || "?"} (${x.sources.join("+")}${x.environments.length ? `, ${x.environments.join("/")}` : ""}${x.status && x.status !== "enabled" ? `, ${x.status}` : ""})`).join(" · ") : <span className="text-orange-300">nowhere: no log drain covers this project</span>}</dd>
            <dt className="text-zinc-500">Secure Compute</dt><dd className="text-xs">{d.connect?.length ? <>{[...new Set(d.connect.map((c: any) => c.security_group))].join(", ")} · {[...new Set(d.connect.flatMap((c: any) => c.subnets))].length} subnets · {[...new Set(d.connect.map((c: any) => c.env))].join(", ")}</> : "no"}</dd>
          </dl>
          <div className="space-y-2 text-xs">
            <div className="text-zinc-500">Serves</div>
            <ul className="space-y-0.5">{d.endpoints.map((e: any) => <li key={e.id} className="flex flex-wrap gap-x-2"><a className="break-all font-mono hover:underline" href={e.url} target="_blank" rel="noreferrer">{e.hostname}</a><span className="text-zinc-500">{e.target}{e.domain ? " · domain" : ""}</span><span className={e.requires_auth ? "text-emerald-300" : "text-orange-300"}>{authWords(e)}</span></li>)}</ul>
            <div className="text-zinc-500">Uses</div>
            {d.stores.length ? <ul className="space-y-0.5">{d.stores.map((st: any) => <li key={st.id}>{st.name} <span className="text-zinc-500">· {st.product || st.kind}{st.plan ? ` · ${st.plan}` : ""}{st.region ? ` · ${st.region}` : ""}</span></li>)}</ul> : <div className="text-zinc-600">no store connected</div>}
            <div className="text-zinc-500">Last 7 days</div>
            <div>{u7.requests.toLocaleString()} requests · {u7.invocations.toLocaleString()} invocations · {u7.error_pct ?? "—"}% errors · {u7.gb_hours} GB-h · {u7.bandwidth_out_gb} GB out · {u7.builds} builds</div>
          </div>
        </div>
      )}
      {tab === "deployments" && (
        <table className="w-full border-collapse text-xs">
          <thead><tr><Th>When</Th><Th>State</Th><Th>Target</Th><Th>Branch · commit</Th><Th>URL</Th><Th>Source</Th></tr></thead>
          <tbody>{d.deployments.map((x: any) => <tr key={x.id} className="border-t border-zinc-800"><Td className="whitespace-nowrap">{when(x.created_at)}</Td><Td><span className={x.state === "READY" ? "text-emerald-300" : x.state === "ERROR" ? "text-red-300" : "text-zinc-300"}>{x.state}</span></Td><Td>{x.target || "preview"}</Td><Td className="font-mono">{x.branch || "—"}{x.commit_sha ? ` · ${x.commit_sha}` : ""}</Td><Td>{x.url ? <a className="font-mono hover:underline" href={x.url} target="_blank" rel="noreferrer">{x.url.replace(/^https:\/\//, "")}</a> : "—"}</Td><Td className="text-zinc-500">{x.source || "—"}</Td></tr>)}</tbody>
        </table>
      )}
      {tab === "domains" && (
        <table className="w-full border-collapse text-xs">
          <thead><tr><Th>Domain</Th><Th>Apex</Th><Th>Verified</Th><Th>Redirect</Th><Th>Branch</Th><Th>Since</Th></tr></thead>
          <tbody>{d.domains.map((x: any) => <tr key={x.name} className="border-t border-zinc-800"><Td className="font-mono">{x.name}</Td><Td className="text-zinc-400">{x.apex || "—"}</Td><Td>{x.verified ? <span className="text-emerald-300">yes</span> : <span className="text-orange-300">no</span>}</Td><Td className="text-zinc-400">{x.redirect || "—"}</Td><Td className="text-zinc-400">{x.branch || "—"}</Td><Td className="whitespace-nowrap text-zinc-500">{when(x.created_at)}</Td></tr>)}</tbody>
        </table>
      )}
      {tab === "env" && (
        <div className="text-xs"><div className="mb-1 text-zinc-500">Names, targets and types only; values are never read.</div>
          <table className="w-full border-collapse"><thead><tr><Th>Name</Th><Th>Targets</Th><Th>Type</Th><Th>Updated</Th></tr></thead>
            <tbody>{d.env_names.map((e: any) => <tr key={e.key} className="border-t border-zinc-800/60"><Td className="font-mono">{e.key}</Td><Td className="text-zinc-400">{e.targets.join(", ")}</Td><Td className="text-zinc-500">{e.type || "—"}</Td><Td className="whitespace-nowrap text-zinc-500">{when(e.updated_at)}</Td></tr>)}</tbody></table>
        </div>
      )}
      {tab === "usage" && (
        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
            <Stat label="Requests, 7 d" value={u7.requests.toLocaleString()} hint={`${u30.requests.toLocaleString()} in 30 d · cache ${u7.cache_hit_pct ?? "—"}%`} />
            <Stat label="Invocations, 7 d" value={u7.invocations.toLocaleString()} hint={`${u7.gb_hours} GB-h · ${u30.invocations.toLocaleString()} in 30 d`} />
            <Stat label="Errors" value={`${u7.error_pct ?? "—"}%`} hint={`${u7.invocation_errors} errors · ${u7.invocation_throttles} throttled · ${u7.invocation_timeouts} timed out`} />
            <Stat label="Bandwidth out, 7 d" value={`${u7.bandwidth_out_gb} GB`} hint={`${u30.bandwidth_out_gb} GB in 30 d`} />
            <Stat label="Builds, 7 d" value={u7.builds} hint={`${u7.build_minutes} min · ${u30.builds} in 30 d${u30.builds_failed ? ` · ${u30.builds_failed} failed` : ""}`} />
          </div>
          {d.usage.series.length > 1 ? (() => { const max = Math.max(1, ...d.usage.series.map((x: any) => x.requests)); return (
            <div><div className="flex h-14 items-end gap-px">{d.usage.series.map((x: any) => <div key={x.day} className="flex-1 rounded-t bg-sky-500/40" style={{ height: `${Math.max(2, (x.requests / max) * 100)}%` }} title={`${x.day}: ${x.requests.toLocaleString()} requests · ${x.invocations.toLocaleString()} invocations · ${x.errors} errors · ${x.builds} builds`} />)}</div>
              <div className="mt-0.5 flex justify-between text-[10px] text-zinc-600"><span>{d.usage.series[0].day}</span><span>requests per day, this project</span><span>{d.usage.series[d.usage.series.length - 1].day}</span></div></div>
          ); })() : <div className="text-xs text-zinc-500">No usage read for this project yet (it fills with the next collection).</div>}
        </div>
      )}
    </Card>
  );
}

/** The partners behind the marketplace stores: a Neon API key and Redis Cloud keys, each tested before it is saved, and what the last read got per store. */
export function VercelPartners() {
  const [d, setD] = useState<any>(null); const [neon, setNeon] = useState(""); const [rk, setRk] = useState(""); const [rs, setRs] = useState("");
  const [busy, setBusy] = useState(false); const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const load = () => api("/vercel/partners").then(setD).catch(() => setD({ configured: { neon: false, redis: false }, stores: [] }));
  useEffect(() => { load(); }, []);
  const send = async (body: Record<string, string>, what: string) => { setBusy(true); setMsg(null); try { const r = await api("/accounts/vercel/partners", { method: "POST", body: JSON.stringify(body) }); setMsg({ ok: true, text: `${what}: ${r.neon ?? r.redis ?? "ok"} · ${r.note}` }); setNeon(""); setRk(""); setRs(""); setTimeout(load, 4000); } catch (e: any) { setMsg({ ok: false, text: e.message }); } finally { setBusy(false); } };
  const c = d?.configured ?? { neon: false, redis: false };
  return (
    <div className="space-y-4">
      <Card title={<span>Neon <span className="font-normal text-zinc-500">· {c.neon ? "key saved" : "no key"} · reads the Postgres behind each Neon store: storage, branches, compute and its autoscaling, consumption this period, the IP allow list</span></span>}>
        <p className="mb-3 text-sm text-zinc-400">An API key from console.neon.tech › Account settings › API keys (a personal or organization key with read access to the projects the stores point at). Saved as a runtime secret, never shown again.</p>
        <form onSubmit={(e) => { e.preventDefault(); send({ neon_api_key: neon }, "Neon"); }} className="grid gap-3">
          <label className="grid gap-1 text-sm"><span className="text-zinc-400">API key{c.neon ? " (paste to replace)" : ""}</span><input type="password" autoComplete="off" value={neon} onChange={(e) => setNeon(e.target.value)} className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1 font-mono text-xs" /></label>
          <div className="flex items-center gap-2"><Button type="submit" disabled={busy || !neon}>{busy ? "Testing…" : "Save and test"}</Button>{c.neon && <Button type="button" variant="danger" disabled={busy} onClick={() => send({ neon_api_key: "" }, "Neon")}>Remove</Button>}</div>
        </form>
      </Card>
      <Card title={<span>Redis Cloud <span className="font-normal text-zinc-500">· {c.redis ? "keys saved" : "no keys"} · reads the database behind each Redis store: memory used and limit, persistence, replication, throughput, the public endpoint and its source IPs</span></span>}>
        <p className="mb-3 text-sm text-zinc-400">The account key and a user (secret) key from app.redislabs.com › Access Management › API Keys. The store is matched by name on the Redis Cloud account.</p>
        <form onSubmit={(e) => { e.preventDefault(); send({ redis_api_key: rk, redis_secret_key: rs }, "Redis Cloud"); }} className="grid gap-3">
          <label className="grid gap-1 text-sm"><span className="text-zinc-400">Account key</span><input type="password" autoComplete="off" value={rk} onChange={(e) => setRk(e.target.value)} className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1 font-mono text-xs" /></label>
          <label className="grid gap-1 text-sm"><span className="text-zinc-400">User key</span><input type="password" autoComplete="off" value={rs} onChange={(e) => setRs(e.target.value)} className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1 font-mono text-xs" /></label>
          <div className="flex items-center gap-2"><Button type="submit" disabled={busy || !rk || !rs}>{busy ? "Testing…" : "Save and test"}</Button>{c.redis && <Button type="button" variant="danger" disabled={busy} onClick={() => send({ redis_api_key: "", redis_secret_key: "" }, "Redis Cloud")}>Remove</Button>}</div>
        </form>
      </Card>
      {msg && <div className={`text-sm ${msg.ok ? "text-emerald-300" : "text-red-300"}`}>{msg.text}</div>}
      {d?.stores?.length > 0 && (
        <Card title="Last read per store">
          <ul className="space-y-0.5 text-xs">{d.stores.map((s: any) => <li key={s.id}><span className="text-zinc-200">{s.name}</span> <span className="text-zinc-500">· {s.product} · {when(s.read_at)}</span>{s.error ? <span className="text-orange-300"> · {s.error}</span> : <span className="text-emerald-300"> · ok</span>}</li>)}</ul>
        </Card>
      )}
    </div>
  );
}

/** What changed on the team between collections: the Changes page under the Vercel scope. */
export function VercelChanges() {
  const [d, setD] = useState<any>(null); const [days, setDays] = useState(7); const [kind, setKind] = useState("");
  useEffect(() => { api(`/vercel/changes?days=${days}${kind ? `&kind=${encodeURIComponent(kind)}` : ""}`).then(setD).catch((e) => setD({ error: e.message })); }, [days, kind]);
  if (!d) return <Card title="Changes"><div className="text-sm text-zinc-500">Loading…</div></Card>;
  if (d.error) return <Card title="Changes"><div className="text-sm text-red-300">{d.error}</div></Card>;
  if (!d.configured) return <Card title="Changes"><div className="text-sm text-zinc-500">No Vercel token saved.</div></Card>;
  const s = d.summary;
  return (
    <Card title={<span className="flex flex-wrap items-center justify-between gap-2"><span>Changes <span className="font-normal text-zinc-500">· what the API said differently between two collections: deployments, protection, firewall, domains, env variable names, stores, members, drains, the subscription · {s.snapshots} snapshots{s.last_snapshot_at ? `, last ${when(s.last_snapshot_at)}` : ""}</span></span>
      <span className="flex items-center gap-2 text-xs"><select value={days} onChange={(e) => setDays(Number(e.target.value))} className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1">{[1, 7, 30, 90].map((n) => <option key={n} value={n}>{n} day{n === 1 ? "" : "s"}</option>)}</select>
        <select value={kind} onChange={(e) => setKind(e.target.value)} className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1"><option value="">every kind</option>{s.by_kind.map((k: any) => <option key={k.kind} value={k.kind}>{k.kind.replace(/_/g, " ")} ({k.n})</option>)}</select></span></span>}>
      {!d.changes.length ? <div className="text-sm text-zinc-500">{s.snapshots < 2 ? "Nothing to compare yet: the first collection took the first snapshot; the next one lists what differs." : `Nothing changed in the last ${days} day${days === 1 ? "" : "s"}.`}</div> : (
        <table className="w-full border-collapse text-sm">
          <thead><tr><Th>When</Th><Th>Kind</Th><Th>Subject</Th><Th>What</Th></tr></thead>
          <tbody>{d.changes.map((c: any) => (
            <tr key={c.id} className="border-t border-zinc-800 align-top">
              <Td className="whitespace-nowrap text-xs text-zinc-500">{when(c.at)}</Td>
              <Td className="text-xs text-zinc-400">{c.kind.replace(/_/g, " ")}</Td>
              <Td className="text-xs">{c.subject_name || c.subject_id || "team"}<div className="font-mono text-[11px] text-zinc-600">{c.subject_kind}{c.subject_id && c.subject_id !== c.subject_name ? ` · ${c.subject_id}` : ""}</div></Td>
              <Td className="text-zinc-200">{c.what}{(c.before || c.after) && <details className="mt-0.5 text-[11px] text-zinc-500"><summary className="cursor-pointer">before / after</summary><pre className="whitespace-pre-wrap break-all">{c.before ?? "—"}{"\n→ "}{c.after ?? "—"}</pre></details>}</Td>
            </tr>
          ))}</tbody>
        </table>
      )}
    </Card>
  );
}

/** The team's members: role, MFA, GitHub login, when they joined; the Identities tab under the Vercel scope. */
export function VercelMembers() {
  const [d, setD] = useState<any>(null);
  useEffect(() => { api("/vercel/members").then(setD).catch((e) => setD({ error: e.message })); }, []);
  if (!d) return <Card title="Team members"><div className="text-sm text-zinc-500">Loading…</div></Card>;
  if (d.error) return <Card title="Team members"><div className="text-sm text-red-300">{d.error}</div></Card>;
  const noMfa = d.members.filter((m: any) => m.confirmed && m.mfa === false).length;
  return (
    <Card title={<span>Team members <span className="font-normal text-zinc-500">· {d.members.length} on the Vercel team · {noMfa ? <span className="text-orange-300">{noMfa} without MFA</span> : "all with MFA"}{d.read_at ? ` · read ${when(d.read_at)}` : ""}</span></span>}>
      <table className="w-full border-collapse text-sm">
        <thead><tr><Th>Member</Th><Th>Role</Th><Th>MFA</Th><Th>Confirmed</Th><Th>GitHub</Th><Th>Joined</Th></tr></thead>
        <tbody>{d.members.map((m: any) => <tr key={m.uid} className="border-t border-zinc-800"><Td className="text-zinc-100">{m.username || m.uid}</Td><Td className="text-xs text-zinc-400">{m.role || "—"}</Td><Td className="text-xs">{m.mfa === true ? <span className="text-emerald-300">on</span> : m.mfa === false ? <span className="text-orange-300">off</span> : "—"}</Td><Td className="text-xs text-zinc-400">{m.confirmed ? "yes" : "pending"}</Td><Td className="text-xs text-zinc-400">{m.github || "—"}</Td><Td className="whitespace-nowrap text-xs text-zinc-500">{when(m.joined_at)}</Td></tr>)}</tbody>
      </table>
    </Card>
  );
}

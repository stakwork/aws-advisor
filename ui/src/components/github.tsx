import { useEffect, useState } from "react";
import { api, usd, when } from "../api";
import { Button, Card, Stat, Td, Th } from "./ui";

/**
 * The GitHub org: Settings › Access (the read-only App, tested before it is saved; the key is never shown again, with
 * the steps and permissions to create it), the Overview, People (role, 2FA, teams, Copilot, last activity, repository
 * access and credentials), Repositories (who can write and how), Credentials (keys, tokens, Apps, secret names,
 * webhooks), the Bill and the Changes.
 */

const RANK: Record<string, number> = { read: 1, triage: 2, write: 3, maintain: 4, admin: 5 };
const permClass = (p: string | null) => (p === "admin" ? "text-red-300" : p === "maintain" ? "text-orange-300" : p === "write" ? "text-amber-200" : "text-zinc-400");
const mfaWord = (m: boolean | null) => (m === true ? <span className="text-emerald-300">on</span> : m === false ? <span className="text-red-300">off</span> : <span className="text-zinc-500">unknown</span>);
const ago = (iso: string | null | undefined) => { if (!iso) return "never"; const d = Math.floor((Date.now() - Date.parse(iso)) / 86_400_000); return d <= 0 ? "today" : d === 1 ? "yesterday" : `${d} days ago`; };

function useApi<T = any>(path: string): [T | null, string, () => void] {
  const [d, setD] = useState<T | null>(null); const [err, setErr] = useState("");
  const load = () => api(path).then(setD).catch((e) => setErr(e.message));
  useEffect(() => { load(); }, [path]);
  return [d, err, load];
}

export function GitHubAccess({ configured, onChange }: { configured: boolean; onChange: () => void }) {
  const [s, , reload] = useApi<any>("/github/setup");
  const [org, setOrg] = useState(""); const [appId, setAppId] = useState(""); const [inst, setInst] = useState(""); const [key, setKey] = useState("");
  const [busy, setBusy] = useState(false); const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  useEffect(() => { if (s) { setOrg((v) => v || s.org || ""); setAppId((v) => v || s.app_id || ""); setInst((v) => v || s.installation_id || ""); } }, [s]);
  const save = async (e: React.FormEvent) => {
    e.preventDefault(); setBusy(true); setMsg(null);
    try { const r = await api("/providers/github/accounts", { method: "POST", body: JSON.stringify({ org, app_id: appId, installation_id: inst, private_key: key }) }); setKey(""); setMsg({ ok: true, text: `${r.account.name}${r.account.plan ? ` (${r.account.plan} plan, ${r.account.filled_seats}/${r.account.seats} seats)` : ""}: ${r.note}` }); onChange(); reload(); }
    catch (err: any) { setMsg({ ok: false, text: err.message }); } finally { setBusy(false); }
  };
  const remove = async () => { setBusy(true); try { await api("/providers/github/accounts/current", { method: "DELETE" }); setMsg({ ok: true, text: "removed: the App's credentials, the stored org and the graph nodes" }); onChange(); reload(); } catch (err: any) { setMsg({ ok: false, text: err.message }); } finally { setBusy(false); } };
  const newAppUrl = `https://github.com/organizations/${org || "<org>"}/settings/apps/new`;
  const refused = Object.entries(s?.sections ?? {}).filter(([, v]: any) => !v.ok);
  return (
    <div className="space-y-4">
      <Card title="GitHub access">
        <p className="mb-3 text-sm text-zinc-400">A GitHub App owned by the org, with read-only permissions, installed on all repositories. The advisor signs in as the App: no person's token, nothing it can change.</p>
        <form onSubmit={save} className="grid gap-3">
          <label className="grid gap-1 text-sm"><span className="text-zinc-400">Organization</span><input autoComplete="off" value={org} onChange={(e) => setOrg(e.target.value)} placeholder="the login in github.com/<org>" required /></label>
          <div className="grid gap-3 sm:grid-cols-2">
            <label className="grid gap-1 text-sm"><span className="text-zinc-400">App id</span><input autoComplete="off" inputMode="numeric" value={appId} onChange={(e) => setAppId(e.target.value)} required /></label>
            <label className="grid gap-1 text-sm"><span className="text-zinc-400">Installation id</span><input autoComplete="off" inputMode="numeric" value={inst} onChange={(e) => setInst(e.target.value)} required /></label>
          </div>
          <label className="grid gap-1 text-sm"><span className="text-zinc-400">Private key (.pem){s?.key_saved ? " · saved; paste to replace" : ""}</span><textarea className="min-h-28 font-mono text-xs" autoComplete="off" spellCheck={false} value={key} onChange={(e) => setKey(e.target.value)} placeholder="-----BEGIN RSA PRIVATE KEY-----" required={!s?.key_saved} /></label>
          <div className="flex items-center gap-2">
            <Button type="submit" disabled={busy}>{busy ? "Testing…" : "Save and test"}</Button>
            {configured && <Button type="button" variant="danger" onClick={remove} disabled={busy}>Remove</Button>}
          </div>
          {msg && <div className={`text-sm ${msg.ok ? "text-emerald-300" : "text-red-300"}`}>{msg.text}</div>}
          {refused.length > 0 && <div className="text-xs text-orange-300">Not readable on the last collection: {refused.map(([k, v]: any) => `${k}${v.status ? ` (HTTP ${v.status})` : ""}`).join(", ")}. Add the permission below, then accept it on the installation.</div>}
        </form>
      </Card>
      <Card title="Creating the App">
        <ol className="list-decimal space-y-1.5 pl-5 text-sm text-zinc-300">
          <li>As an org owner, open <a className="text-sky-300 hover:underline" href={newAppUrl} target="_blank" rel="noreferrer">{newAppUrl}</a> (Organization settings › Developer settings › GitHub Apps › New GitHub App).</li>
          <li>Name it (e.g. <span className="font-mono">cloud-advisor-read</span>), any homepage URL, and <b>untick Webhook › Active</b>: the advisor reads, it does not listen.</li>
          <li>Under Permissions, set each of the ones below to <b>Read-only</b> and leave everything else at No access.</li>
          <li>"Where can this GitHub App be installed?" → <b>Only on this account</b>. Create it; the page shows the <b>App id</b>.</li>
          <li>On the same page, <b>Generate a private key</b>: a .pem downloads. Paste its contents above.</li>
          <li><b>Install App</b> (left menu) → the org → <b>All repositories</b>. The URL ends in <span className="font-mono">/installations/&lt;number&gt;</span>: that is the <b>installation id</b>.</li>
        </ol>
        <table className="mt-3 w-full border-collapse text-sm">
          <thead><tr><Th>Scope</Th><Th>Permission</Th><Th>Access</Th><Th>What it reads</Th></tr></thead>
          <tbody>{(s?.permissions ?? []).map((p: any) => <tr key={`${p.scope}:${p.permission}`} className="border-t border-zinc-800"><Td className="text-xs text-zinc-400">{p.scope}</Td><Td className="text-zinc-100">{p.permission}</Td><Td className="text-xs">{p.access}</Td><Td className="text-xs text-zinc-500">{p.sections.join(", ")}</Td></tr>)}</tbody>
        </table>
        <p className="mt-2 text-xs text-zinc-500">The org's audit log needs the org's "Administration: Read-only"; the SSO credential authorizations list exists only when SAML single sign-on is on, and GitHub may refuse it to Apps (it is then shown as not readable, nothing else is affected).</p>
      </Card>
    </div>
  );
}

/** The collection live: its phase and step, repositories done of all, calls, the last log lines; "Collect now" starts one. Polls every 2 s while it runs. */
export function GitHubProgress({ onDone }: { onDone?: () => void }) {
  const [p, setP] = useState<any>(null); const [msg, setMsg] = useState("");
  const load = () => api("/github/progress").then(setP).catch((e) => setMsg(e.message));
  useEffect(() => { load(); }, []);
  useEffect(() => {
    if (!p?.running) return;
    const t = setTimeout(async () => { const was = p.running; const n = await api("/github/progress").catch(() => p); setP(n); if (was && !n.running) onDone?.(); }, 2000);
    return () => clearTimeout(t);
  }, [p]);
  const start = async (full = false) => { setMsg(""); try { await api(`/github/refresh${full ? "?full=1" : ""}`, { method: "POST", body: "{}" }); load(); } catch (e: any) { setMsg(e.message); } };
  const elapsed = p?.started_at ? Math.round(((p.running ? Date.now() : Date.parse(p.finished_at ?? p.started_at)) - Date.parse(p.started_at)) / 1000) : null;
  const pct = p?.repos_total ? Math.round((p.repos_done / p.repos_total) * 100) : null;
  return (
    <Card title={<span>Collection {p?.running ? <span className="font-normal text-sky-300">· running {elapsed}s</span> : p?.finished_at ? <span className="font-normal text-zinc-500">· last ended {when(p.finished_at)}</span> : null}</span>}>
      <div className="mb-2 flex flex-wrap items-center gap-3 text-sm">
        <Button onClick={() => start(false)} disabled={p?.running} title="Reads the new repositories and the ones the audit log shows changed; the rest keep what is stored">{p?.running ? "Collecting…" : "Collect now"}</Button>
        {!p?.running && <button type="button" className="text-xs text-zinc-400 hover:underline" onClick={() => start(true)} title="Reads every repository again (the daily run does this anyway)">full sweep</button>}
        {p?.running && <span className="text-zinc-300">{p.phase}{p.step ? <span className="text-zinc-500"> · {p.step}</span> : null}</span>}
        {p?.running && <span className="text-xs text-zinc-500">{p.calls} API calls{p.errors ? ` · ${p.errors} failed` : ""}</span>}
        {msg && <span className="text-xs text-red-300">{msg}</span>}
      </div>
      {p?.running && pct != null && p.repos_total > 0 && <div className="mb-2"><div className="h-1.5 w-full overflow-hidden rounded bg-zinc-800"><div className="h-full bg-sky-500 transition-all" style={{ width: `${pct}%` }} /></div><div className="mt-1 text-[11px] text-zinc-500">repositories {p.repos_done}/{p.repos_total}</div></div>}
      {p?.log?.length > 0 && <div className="max-h-48 overflow-auto rounded border border-zinc-800 bg-zinc-950/60 p-2 font-mono text-[11px] leading-relaxed">{[...p.log].reverse().map((l: any, i: number) => <div key={i} className={/failed/.test(l.line) ? "text-orange-300" : "text-zinc-400"}><span className="text-zinc-600">{new Date(l.at).toLocaleTimeString()}</span> {l.line}</div>)}</div>}
    </Card>
  );
}

export function GitHubOverview() {
  const [d, err, reload] = useApi<any>("/github/overview");
  if (err) return <Card title="GitHub"><div className="text-sm text-red-300">{err}</div></Card>;
  if (!d) return <Card title="GitHub"><div className="text-sm text-zinc-500">Loading…</div></Card>;
  if (!d.configured) return <Card title="GitHub"><div className="text-sm text-zinc-500">Add the GitHub App under Settings › Accounts › GitHub.</div></Card>;
  if (!d.org) return <div className="space-y-4"><GitHubProgress onDone={reload} /><Card title="GitHub"><div className="text-sm text-zinc-500">{d.note}</div></Card></div>;
  const c = d.counts; const m = d.month; const f = d.findings.findings;
  return (
    <div className="space-y-4">
      <GitHubProgress onDone={reload} />
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat label="People" value={`${c.members} + ${c.collaborators}`} hint={`${c.members} members (${c.owners} owners) and ${c.collaborators} outside collaborators`} />
        <Stat label="Without 2FA" value={<span className={c.without_2fa ? "text-red-300" : "text-emerald-300"}>{c.without_2fa}</span>} hint={d.org.two_factor_required ? "the org requires 2FA" : d.org.two_factor_required === false ? "the org does not require 2FA" : "requirement not readable"} />
        <Stat label="Seats" value={`${d.org.filled_seats ?? "?"} / ${d.org.seats ?? "?"}`} hint={m.unused_seats ? `${m.unused_seats} paid and empty: ${usd(m.unused_seats * m.seat_usd)}/month` : "every paid seat is used"} />
        <Stat label="This month" value={usd(m.projected_usd)} hint={`so far ${usd(m.month_to_date_usd)} · last month ${usd(m.last_month_usd)}`} />
        <Stat label="Repositories" value={c.repos} hint={`${c.private_repos} private · base permission ${d.org.default_permission ?? "?"}`} />
        <Stat label="Credentials" value={c.deploy_keys + c.tokens} hint={`${c.deploy_keys} deploy keys · ${c.tokens} tokens granted`} />
        <Stat label="Apps installed" value={c.apps} hint={`${c.secrets} secret names`} />
        <Stat label="Copilot seats" value={c.copilot_seats} hint={d.copilot?.plan_type ?? "no Copilot plan read"} />
      </div>
      <Card title={<span>Needs attention <span className="font-normal text-zinc-500">· rules pass {d.findings.run_id ? `#${d.findings.run_id} · ${when(d.findings.at)}` : "not run yet"}</span></span>}>
        {!f.length ? <div className="text-sm text-zinc-500">Nothing.</div> : <ul className="space-y-1 text-sm">{f.map((x: any, i: number) => <li key={i} className="flex gap-2"><span className={`w-16 shrink-0 text-xs ${x.severity === "alarm" ? "text-red-300" : x.severity === "warning" ? "text-orange-300" : "text-zinc-500"}`}>{x.severity}</span><span className="text-zinc-300">{x.reason}</span></li>)}</ul>}
      </Card>
      <Card title={<span>Sections <span className="font-normal text-zinc-500">· read {when(d.read_at)}{d.audit_since ? ` · audit log since ${d.audit_since}` : ""}</span></span>}>
        <div className="flex flex-wrap gap-1.5 text-xs">{Object.entries(d.sections).map(([k, v]: any) => <span key={k} title={v.error ?? `${v.rows} rows`} className={`rounded border px-1.5 py-0.5 ${v.ok ? "border-zinc-800 text-zinc-400" : "border-orange-900 text-orange-300"}`}>{k}{v.ok ? ` · ${v.rows}` : ` · ${v.status ?? "error"}`}{v.via ? <span className={v.via === "steampipe" ? "text-emerald-400/70" : "text-zinc-600"}> · {v.via}</span> : null}</span>)}</div>
        <div className="mt-2 text-[11px] text-zinc-500">Read through the Steampipe <span className="font-mono">github</span> connection where the plugin has a table; the API on the same App for the rest (deploy keys, tokens, Apps, org secrets, webhooks, Copilot, billing).</div>
      </Card>
    </div>
  );
}

export function GitHubMembers() {
  const [d, err] = useApi<any>("/github/members"); const [open, setOpen] = useState<string | null>(null);
  if (err) return <Card title="GitHub people"><div className="text-sm text-red-300">{err}</div></Card>;
  if (!d) return <Card title="GitHub people"><div className="text-sm text-zinc-500">Loading…</div></Card>;
  if (!d.configured) return null;
  const noMfa = d.people.filter((p: any) => p.mfa === false).length;
  return (
    <Card title={<span>GitHub people <span className="font-normal text-zinc-500">· {d.org?.login} · {d.people.length} people on {d.org?.filled_seats ?? "?"}/{d.org?.seats ?? "?"} seats · {noMfa ? <span className="text-red-300">{noMfa} without 2FA</span> : "everyone has 2FA"}{!d.audit_ok ? " · audit log not readable: no activity" : ""}</span></span>}>
      <table className="w-full border-collapse text-sm">
        <thead><tr><Th>Login</Th><Th>Role</Th><Th>2FA</Th><Th>Teams</Th><Th>Repos admin / write / read</Th><Th>Credentials</Th><Th>Copilot</Th><Th>Last activity</Th></tr></thead>
        <tbody>{d.people.map((p: any) => (
          <>
            <tr key={p.login} className="cursor-pointer border-t border-zinc-800 hover:bg-zinc-900/50" onClick={() => setOpen(open === p.login ? null : p.login)}>
              <Td className="text-zinc-100">{p.login}{p.name ? <span className="ml-1 text-xs text-zinc-500">{p.name}</span> : null}</Td>
              <Td className={`text-xs ${p.role === "owner" ? "text-orange-300" : p.role === "outside collaborator" ? "text-sky-300" : "text-zinc-400"}`}>{p.role}</Td>
              <Td className="text-xs">{mfaWord(p.mfa)}</Td>
              <Td className="text-xs text-zinc-400">{p.teams.join(", ") || "—"}</Td>
              <Td className="text-xs"><span className="text-red-300">{p.repos.admin}</span> / <span className="text-amber-200">{p.repos.write}</span> / <span className="text-zinc-400">{p.repos.read}</span></Td>
              <Td className="text-xs text-zinc-400">{p.credentials.length || "—"}</Td>
              <Td className="text-xs text-zinc-400">{p.copilot ? `seat · ${ago(p.copilot.last_activity_at)}` : "—"}</Td>
              <Td className="text-xs text-zinc-400">{p.last_activity_at ? `${ago(p.last_activity_at)} (${p.events_90d})` : "none in the log"}</Td>
            </tr>
            {open === p.login && <tr key={`${p.login}:x`}><td colSpan={8} className="bg-zinc-950/60 p-3 text-xs">
              <div className="grid gap-3 md:grid-cols-3">
                <div><div className="mb-1 text-zinc-500">Repositories</div><ul className="max-h-56 space-y-0.5 overflow-auto">{p.repos.list.map((r: any) => <li key={r.repo}><span className={permClass(r.permission)}>{r.permission}</span> <span className="text-zinc-300">{r.repo}</span> <span className="text-zinc-600">{r.via.join("; ")}</span></li>)}</ul></div>
                <div><div className="mb-1 text-zinc-500">Credentials</div>{p.credentials.length ? <ul className="space-y-0.5">{p.credentials.map((c: any) => <li key={c.id} className="text-zinc-300">{c.kind.replace(/_/g, " ")} · {c.name ?? c.fingerprint}{c.expires_at ? ` · expires ${when(c.expires_at)}` : c.kind === "pat" ? " · no expiry" : ""}{c.last_used_at ? ` · used ${ago(c.last_used_at)}` : ""}</li>)}</ul> : <div className="text-zinc-600">none on the org</div>}</div>
                <div><div className="mb-1 text-zinc-500">Seen using (audit log)</div>{p.clients.length ? <ul className="space-y-0.5">{p.clients.map((c: any) => <li key={c.ua} className="break-all text-zinc-400">{c.ua} <span className="text-zinc-600">× {c.events}</span></li>)}</ul> : <div className="text-zinc-600">no user agents</div>}{p.access_types.length > 0 && <div className="mt-1 text-zinc-500">{p.access_types.map((a: any) => `${a.type} × ${a.events}`).join(" · ")}</div>}</div>
              </div>
            </td></tr>}
          </>
        ))}</tbody>
      </table>
      {d.invitations?.length > 0 && <div className="mt-3 text-xs text-zinc-400">Invitations: {d.invitations.map((i: any) => `${i.login ?? "by e-mail"} (${i.role}${i.failed_at ? `, failed: ${i.failed_reason}` : `, ${ago(i.created_at)}`})`).join(" · ")}</div>}
    </Card>
  );
}

export function GitHubRepos() {
  const [d, err] = useApi<any>("/github/repos"); const [open, setOpen] = useState<string | null>(null); const [q, setQ] = useState("");
  if (err) return <Card title="GitHub repositories"><div className="text-sm text-red-300">{err}</div></Card>;
  if (!d) return <Card title="GitHub repositories"><div className="text-sm text-zinc-500">Loading…</div></Card>;
  if (!d.configured) return null;
  const rows = d.repos.filter((r: any) => !q || r.full_name.toLowerCase().includes(q.toLowerCase()));
  return (
    <Card title={<span>GitHub repositories <span className="font-normal text-zinc-500">· {d.repos.length} · base permission {d.base_permission ?? "?"} (owners administer all)</span></span>}>
      <input className="mb-2 w-full max-w-xs text-sm" placeholder="filter" value={q} onChange={(e) => setQ(e.target.value)} />
      <table className="w-full border-collapse text-sm">
        <thead><tr><Th>Repository</Th><Th>Visibility</Th><Th>Admin</Th><Th>Write</Th><Th>Outside</Th><Th>Deploy keys</Th><Th>Secrets</Th><Th>Pushed</Th></tr></thead>
        <tbody>{rows.map((r: any) => {
          const admin = r.people.filter((p: any) => (RANK[p.permission] ?? 0) >= 4); const write = r.people.filter((p: any) => p.permission === "write"); const outside = r.people.filter((p: any) => p.outside);
          return (<>
            <tr key={r.full_name} className="cursor-pointer border-t border-zinc-800 hover:bg-zinc-900/50" onClick={() => setOpen(open === r.full_name ? null : r.full_name)}>
              <Td className="text-zinc-100">{r.full_name}{r.archived ? <span className="ml-1 text-xs text-zinc-500">archived</span> : null}</Td>
              <Td className="text-xs text-zinc-400">{r.visibility}</Td><Td className="text-xs text-red-300">{admin.length}</Td><Td className="text-xs text-amber-200">{write.length}</Td><Td className="text-xs text-sky-300">{outside.length || "—"}</Td>
              <Td className="text-xs">{r.deploy_keys.length ? <span className={r.deploy_keys.some((k: any) => !k.details.read_only) ? "text-orange-300" : "text-zinc-300"}>{r.deploy_keys.length}</span> : "—"}</Td>
              <Td className="text-xs text-zinc-400">{r.secrets.length || "—"}</Td><Td className="text-xs text-zinc-500">{ago(r.pushed_at)}</Td>
            </tr>
            {open === r.full_name && <tr key={`${r.full_name}:x`}><td colSpan={8} className="bg-zinc-950/60 p-3 text-xs">
              <div className="grid gap-3 md:grid-cols-3">
                <div><div className="mb-1 text-zinc-500">Who has access</div><ul className="max-h-56 space-y-0.5 overflow-auto">{r.people.map((p: any) => <li key={p.login}><span className={permClass(p.permission)}>{p.permission}</span> <span className={p.outside ? "text-sky-300" : "text-zinc-300"}>{p.login}</span> <span className="text-zinc-600">{p.via.join("; ")}</span></li>)}</ul></div>
                <div><div className="mb-1 text-zinc-500">Deploy keys</div>{r.deploy_keys.length ? <ul className="space-y-0.5">{r.deploy_keys.map((k: any) => <li key={k.id} className="text-zinc-300">{k.name} · {k.details.read_only ? "read-only" : <span className="text-orange-300">read/write</span>} · {k.last_used_at ? `used ${ago(k.last_used_at)}` : "never used"}</li>)}</ul> : <div className="text-zinc-600">none</div>}</div>
                <div><div className="mb-1 text-zinc-500">Secrets it can read (names)</div>{r.secrets.length ? <ul className="space-y-0.5">{r.secrets.map((s: any, i: number) => <li key={i} className="font-mono text-zinc-300">{s.name} <span className="font-sans text-zinc-600">{s.scope}{s.environment ? ` ${s.environment}` : ""}{s.kind === "dependabot" ? " · dependabot" : ""}</span></li>)}</ul> : <div className="text-zinc-600">none</div>}</div>
              </div>
            </td></tr>}
          </>);
        })}</tbody>
      </table>
    </Card>
  );
}

export function GitHubCredentials() {
  const [d, err] = useApi<any>("/github/credentials");
  if (err) return <Card title="GitHub credentials"><div className="text-sm text-red-300">{err}</div></Card>;
  if (!d) return <Card title="GitHub credentials"><div className="text-sm text-zinc-500">Loading…</div></Card>;
  if (!d.configured) return null;
  const by = (k: string) => d.credentials.filter((c: any) => c.kind === k);
  const section = (title: string, rows: any[], cols: [string, (c: any) => any][]) => (
    <Card title={<span>{title} <span className="font-normal text-zinc-500">· {rows.length}</span></span>}>
      {!rows.length ? <div className="text-sm text-zinc-500">None.</div> : <table className="w-full border-collapse text-sm"><thead><tr>{cols.map(([h]) => <Th key={h}>{h}</Th>)}</tr></thead><tbody>{rows.map((c: any, i: number) => <tr key={c.id ?? i} className="border-t border-zinc-800">{cols.map(([h, f]) => <Td key={h} className="text-xs text-zinc-300">{f(c)}</Td>)}</tr>)}</tbody></table>}
    </Card>
  );
  return (
    <div className="space-y-4">
      {section("Fine-grained tokens granted to the org", by("pat"), [["Owner", (c) => c.holder], ["Name", (c) => c.name], ["Repositories", (c) => c.details.repository_selection === "all" ? "all" : `${(c.details.repos ?? []).length}`], ["Expires", (c) => c.expires_at ? when(c.expires_at) : <span className="text-orange-300">never</span>], ["Last used", (c) => ago(c.last_used_at)]])}
      {section("SSO-authorized classic tokens and SSH keys", by("credential_authorization"), [["Owner", (c) => c.holder], ["Type", (c) => c.details.type], ["Name", (c) => c.name], ["Scopes", (c) => (c.details.scopes ?? []).join(", ") || "—"], ["Expires", (c) => c.expires_at ? when(c.expires_at) : "never"], ["Last used", (c) => ago(c.last_used_at)]])}
      {section("Deploy keys", by("deploy_key"), [["Repository", (c) => c.holder], ["Title", (c) => c.name], ["Access", (c) => c.details.read_only ? "read-only" : <span className="text-orange-300">read/write</span>], ["Added by", (c) => c.details.added_by ?? "—"], ["Last used", (c) => ago(c.last_used_at)]])}
      {section("Public SSH keys of the people", by("ssh_key"), [["Login", (c) => c.holder], ["Kind", (c) => c.details.key_kind], ["Fingerprint", (c) => <span className="font-mono">{c.fingerprint}</span>]])}
      {section("Pending token requests", by("pat_request"), [["Owner", (c) => c.holder], ["Name", (c) => c.name], ["Reason", (c) => c.details.reason ?? "—"], ["Asked", (c) => ago(c.created_at)]])}
      {section("Installed Apps", d.apps, [["App", (a) => a.app_slug], ["Repositories", (a) => a.repository_selection], ["Write", (a) => Object.entries(a.permissions).filter(([, v]) => v === "write" || v === "admin").map(([k]) => k).join(", ") || "—"], ["Installed", (a) => when(a.created_at)], ["Suspended", (a) => a.suspended_at ? when(a.suspended_at) : "—"]])}
      {section("Secret names", d.secrets, [["Name", (s) => <span className="font-mono">{s.name}</span>], ["Where", (s) => s.scope === "org" ? `org (${s.visibility}${s.selected_repos.length ? `: ${s.selected_repos.length} repos` : ""})` : `${s.repo}${s.environment ? ` · ${s.environment}` : ""}`], ["Kind", (s) => s.kind], ["Updated", (s) => ago(s.updated_at)]])}
      {section("Webhooks", d.hooks, [["Where", (h) => h.repo ?? "org"], ["Host", (h) => h.host ?? "—"], ["Active", (h) => (h.active ? "yes" : "no")], ["TLS", (h) => (h.insecure_ssl ? <span className="text-red-300">not verified</span> : "verified")], ["Events", (h) => h.events.join(", ")]])}
    </div>
  );
}

export function GitHubBill() {
  const [d, err] = useApi<any>("/github/bill");
  if (err) return <Card title="GitHub bill"><div className="text-sm text-red-300">{err}</div></Card>;
  if (!d) return <Card title="GitHub bill"><div className="text-sm text-zinc-500">Loading…</div></Card>;
  if (!d.configured || !d.month) return <Card title="GitHub bill"><div className="text-sm text-zinc-500">Not read yet.</div></Card>;
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat label="Projected this month" value={usd(d.projected_usd)} hint={`so far ${usd(d.month_to_date_usd)}`} />
        <Stat label="Seats" value={usd(d.seat_line_usd)} hint={`${d.seats ?? "?"} × ${usd(d.seat_usd)}${d.seats_itemised ? " (itemised in usage)" : ""}`} />
        <Stat label="Unused seats" value={<span className={d.unused_seats ? "text-orange-300" : ""}>{d.unused_seats ?? "?"}</span>} hint={d.unused_seats ? `${usd(d.unused_seats * d.seat_usd)}/month` : `${d.filled_seats ?? "?"} used`} />
        <Stat label="Metered so far" value={usd(d.metered_usd, 2)} hint={d.usage_read ? "Actions, Packages, Copilot…" : "usage not readable"} />
      </div>
      <Card title="Metered usage this month">
        {!d.products.length ? <div className="text-sm text-zinc-500">{d.usage_read ? "No metered usage this month." : "The billing usage endpoint refused the App: Administration (org) read-only is needed."}</div> : <table className="w-full border-collapse text-sm"><thead><tr><Th>Product</Th><Th>SKU</Th><Th>Quantity</Th><Th>Gross</Th><Th>Net</Th></tr></thead><tbody>{d.products.map((p: any, i: number) => <tr key={i} className="border-t border-zinc-800"><Td>{p.product}</Td><Td className="text-xs text-zinc-400">{p.sku}</Td><Td className="text-xs">{p.quantity} {p.unit ?? ""}</Td><Td className="text-xs text-zinc-400">{usd(p.gross_usd, 2)}</Td><Td>{usd(p.usd, 2)}</Td></tr>)}</tbody></table>}
      </Card>
      <GitHubUsageHistory months={d.usage_history ?? []} seatLine={d.seat_line_usd} seats={d.seats} seatUsd={d.seat_usd} />
      {d.copilot_seats?.length > 0 && <Card title={<span>Copilot seats <span className="font-normal text-zinc-500">· {d.copilot?.plan_type}</span></span>}><table className="w-full border-collapse text-sm"><thead><tr><Th>Login</Th><Th>Last activity</Th><Th>Editor</Th><Th>Assigned</Th></tr></thead><tbody>{d.copilot_seats.map((s: any) => <tr key={s.login} className="border-t border-zinc-800"><Td>{s.login}</Td><Td className="text-xs">{ago(s.last_activity_at)}</Td><Td className="text-xs text-zinc-500">{s.last_activity_editor ?? "—"}</Td><Td className="text-xs text-zinc-500">{when(s.created_at)}</Td></tr>)}</tbody></table></Card>}
    </div>
  );
}

/**
 * The previous months, spent on what: each month's seats and metered usage, per product the value used at list price,
 * what the plan's included allowance covered and what was billed; a product opens to its SKUs and the repositories
 * that used the most.
 */
function GitHubUsageHistory({ months, seatLine, seats, seatUsd }: { months: any[]; seatLine: number; seats: number | null; seatUsd: number }) {
  const [open, setOpen] = useState<string | null>(null);
  if (!months.length) return <Card title="Previous months"><div className="text-sm text-zinc-500">No usage stored yet.</div></Card>;
  const fmt = (v: number) => usd(v, 2);
  return (
    <Card title="What you paid for, by month">
      <p className="mb-3 text-xs text-zinc-500">Each row adds across: <b className="text-zinc-300">list price</b> − <b className="text-zinc-300">covered by your plan</b> = <b className="text-zinc-300">you pay</b>. Covered is the plan's monthly allowance (Actions minutes, Git LFS, Packages) plus what GitHub gives free (Actions on public repositories); larger runners (e.g. Linux ARM 4-core) are never covered, so they are always paid. Seats are a flat {usd(seatUsd)} each ({seats ?? "?"} today; past months assume the same count). Click a product for its details.</p>
      <table className="w-full border-collapse text-sm">
        <thead><tr><Th>Month</Th><Th>What</Th><Th className="text-right">List price</Th><Th className="text-right">Covered</Th><Th className="text-right">You pay</Th></tr></thead>
        <tbody>{months.map((m) => {
          const covered = m.products.reduce((n: number, p: any) => n + (p.gross_usd - p.net_usd), 0);
          return (<>
            <tr key={`${m.month}:seats`} className="border-t-2 border-zinc-700">
              <Td className="font-medium text-zinc-100">{m.month}</Td><Td className="text-zinc-300">Seats <span className="text-xs text-zinc-500">{seats ?? "?"} × {usd(seatUsd)}</span></Td>
              <Td className="text-right text-xs text-zinc-400">{fmt(seatLine)}</Td><Td className="text-right text-xs text-zinc-600">—</Td><Td className="text-right text-xs text-zinc-200">{fmt(seatLine)}</Td>
            </tr>
            {m.products.map((p: any) => { const k = `${m.month}|${p.product}`; const cov = p.gross_usd - p.net_usd; const raw = p.gross_usd > 0 ? (cov / p.gross_usd) * 100 : null;
              // one decimal below 100, so 99.5 % never reads as "100 %" while something is still billed
              const pct = raw == null ? null : p.net_usd > 0.005 ? Math.min(99.9, Math.floor(raw * 10) / 10) : 100; return (<>
              <tr key={k} className="cursor-pointer border-t border-zinc-800 hover:bg-zinc-900/50" onClick={() => setOpen(open === k ? null : k)}>
                <Td /><Td className="text-zinc-300">{p.product.replace(/_/g, " ")} <span className="text-xs text-zinc-600">{open === k ? "▾" : "▸"}</span></Td>
                <Td className="text-right text-xs text-zinc-400">{fmt(p.gross_usd)}</Td>
                <Td className="text-right text-xs text-emerald-300/80">{cov > 0.005 ? `−${fmt(cov)}${pct != null ? ` (${pct}%)` : ""}` : "—"}</Td>
                <Td className="text-right text-xs text-zinc-200">{fmt(p.net_usd)}</Td>
              </tr>
              {open === k && <tr key={`${k}:x`}><td /><td colSpan={4} className="bg-zinc-950/60 p-3 text-xs">
                <div className="grid gap-3 md:grid-cols-2">
                  <div><div className="mb-1 text-zinc-500">What it was (list price → you pay; a paid line is what the allowance does not cover)</div><ul className="space-y-0.5">{p.skus.map((x: any) => <li key={x.sku} className="flex justify-between gap-3"><span className="text-zinc-300">{x.sku}</span><span className="text-zinc-500">{x.quantity} {x.unit ?? ""} · {fmt(x.gross_usd)} → {fmt(x.net_usd)}</span></li>)}</ul></div>
                  <div><div className="mb-1 text-zinc-500">Repositories that used the most (list price)</div>{p.repos.length ? <ul className="space-y-0.5">{p.repos.map((x: any) => <li key={x.repo} className="flex justify-between gap-3"><span className="text-zinc-300">{x.repo}</span><span className="text-zinc-500">{fmt(x.gross_usd)}</span></li>)}</ul> : <div className="text-zinc-600">not itemised by repository</div>}</div>
                </div>
              </td></tr>}
            </>); })}
            <tr key={`${m.month}:total`} className="border-t border-zinc-800 bg-zinc-900/40">
              <Td /><Td className="font-medium text-zinc-200">Total {m.month}</Td>
              <Td className="text-right text-zinc-300">{fmt(seatLine + m.gross_usd)}</Td><Td className="text-right text-emerald-300/80">−{fmt(covered)}</Td><Td className="text-right font-medium text-zinc-100">{fmt(seatLine + m.net_usd)}</Td>
            </tr>
          </>);
        })}</tbody>
      </table>
    </Card>
  );
}

export function GitHubChanges() {
  const [d, err] = useApi<any>("/github/changes");
  if (err) return <Card title="Changes"><div className="text-sm text-red-300">{err}</div></Card>;
  if (!d) return <Card title="Changes"><div className="text-sm text-zinc-500">Loading…</div></Card>;
  return (
    <Card title="GitHub changes between collections">
      {!d.changes.length ? <div className="text-sm text-zinc-500">Nothing yet: the first collection is the baseline; changes appear from the second.</div> : <ul className="space-y-1 text-sm">{d.changes.map((c: any) => <li key={c.id} className="flex gap-3"><span className="w-40 shrink-0 text-xs text-zinc-500">{when(c.at)}</span><span className={c.kind === "added" ? "text-emerald-300" : c.kind === "removed" ? "text-red-300" : "text-amber-200"}>{c.kind}</span><span className="text-zinc-300">{c.what}</span></li>)}</ul>}
    </Card>
  );
}

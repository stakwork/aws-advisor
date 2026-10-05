import { useEffect, useState } from "react";
import { api, currentScope, when } from "../api";
import { Badge, Button, Card, Empty, Stat, Td, Th } from "./ui";

type Assignment = { account_id: string; permission_set: string; permission_set_arn: string; via: string };
type User = { user_id: string; user_name: string; display_name: string | null; email: string | null; idp: string | null; groups: string[]; assignments: Assignment[]; accounts: number; permission_sets: number; applications: string[]; admin: boolean; last_sign_in: string | null; sign_ins_30d: number; failed_30d: number; activity: Record<string, string>; gone: boolean; status: "ENABLED" | "DISABLED" | null };
type PermissionSet = { arn: string; name: string; description: string | null; session_duration: string | null; managed_policies: string[]; customer_managed: string[]; inline_policy: string | null; boundary: string | null; admin: boolean; accounts: string[]; last_used: Record<string, string>; users: number; gone: boolean };
type Data = {
  configured: boolean; users: User[]; permission_sets: PermissionSet[]; disabled: number; admins: number; never_signed_in: number; stale_90d: number; external: number; groups: number; admin_sets: number; accounts: number; sign_ins_30d: number; failed_30d: number;
  read_at: string | null; region: string | null; owner_account_id: string | null; errors: string[]; notes: string[]; instance: { name: string | null; status: string | null; identity_store_id: string | null };
};

const day = (iso: string | null | undefined) => (iso ? new Date(iso).toLocaleDateString() : "—");
const ago = (iso: string | null) => { if (!iso) return null; const d = Math.floor((Date.now() - Date.parse(iso)) / 86_400_000); return d <= 0 ? "today" : d === 1 ? "1 d" : `${d} d`; };
/** ISO-8601 duration as the console shows it: PT8H → 8 h, PT1H30M → 1 h 30 m. */
const duration = (s: string | null) => { const m = /^PT(?:(\d+)H)?(?:(\d+)M)?/.exec(s || ""); return m ? [m[1] && `${m[1]} h`, m[2] && `${m[2]} m`].filter(Boolean).join(" ") : s || "—"; };

/** IAM Identity Center: the organisation's people, where each can go and when each last signed in; the permission sets underneath. */
export function IdentityCenter() {
  const [d, setD] = useState<Data | null>(null);
  const [accountNames, setAccountNames] = useState<Record<string, string>>({});
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const [open, setOpen] = useState<string | null>(null);
  const [showSets, setShowSets] = useState(false);
  const load = () => api("/inventory/sso").then((r) => { setD(r); setErr(""); }).catch((e) => setErr(e.message));
  useEffect(() => { load(); api("/accounts").then((a) => setAccountNames(Object.fromEntries((a.records || []).filter((r: any) => r.provider === "aws").map((r: any) => [String(r.id), String(r.name || "")])))).catch(() => { /* ids alone */ }); }, []);
  const refresh = async () => { setBusy(true); try { await api("/inventory/sso/refresh", { method: "POST", body: "{}" }); await load(); } catch (e: any) { setErr(e.message); } finally { setBusy(false); } };
  const name = (id: string) => (accountNames[id] && accountNames[id] !== id ? `${accountNames[id]} (${id})` : id);
  const title = <span className="flex flex-wrap items-center justify-between gap-2"><span>IAM Identity Center {d?.read_at ? <span className="font-normal text-zinc-500">· {d.instance?.name || d.owner_account_id ? `${d.instance?.name ? `${d.instance.name} · ` : ""}owned by ${d.owner_account_id ? name(d.owner_account_id) : "?"}` : ""}{d.region ? ` · ${d.region}` : ""} · read {when(d.read_at)}</span> : null}</span><Button variant="ghost" className="!px-2 !py-1 !text-xs" onClick={refresh} disabled={busy}>{busy ? "Reading…" : "Refresh"}</Button></span>;
  if (err) return <Card title={title}><div className="text-sm text-red-300">{err}</div></Card>;
  if (!d) return <Card title={title}><div className="text-sm text-zinc-500">Loading…</div></Card>;
  if (!d.configured) return <Card title={title}><Empty>{d.read_at ? <>No Identity Center instance answered from the parent's credentials{d.errors?.length ? <>: {d.errors[0]}</> : <>. The directory lives in the organisation's management account (or its delegated administrator); point the parent there, or there is no Identity Center.</>}</> : <>Not read yet. Refresh asks the parent's credentials for the Identity Center instance; the nightly inventory does the same.</>}</Empty></Card>;
  return (
    <Card title={title}>
      <div className="mb-4 grid grid-cols-2 gap-4 lg:grid-cols-6">
        <Stat label="People" value={d.users.length - (d.disabled || 0)} hint={`${d.disabled ? `${d.disabled} disabled · ` : ""}${d.groups} group${d.groups === 1 ? "" : "s"}${d.external ? ` · ${d.external} from an identity provider` : ""}`} />
        <Stat label="Administrators" value={<span className={d.admins ? "text-orange-300" : "text-emerald-300"}>{d.admins}</span>} hint={`${d.admin_sets} administrative permission set${d.admin_sets === 1 ? "" : "s"}`} />
        <Stat label="Accounts reached" value={d.accounts} hint={`${d.permission_sets.length} permission set${d.permission_sets.length === 1 ? "" : "s"}`} />
        <Stat label="Sign-ins, 30 days" value={d.sign_ins_30d} hint={d.failed_30d ? <span className="text-orange-300">{d.failed_30d} failed</span> : "none failed"} />
        <Stat label="Quiet 90 days" value={d.stale_90d} hint="signed in once, not in 90 days" />
        <Stat label="Never seen" value={d.never_signed_in} hint="no sign-in in the trail (90 days back at most)" />
      </div>
      {(d.errors?.length || d.notes?.length) ? <div className="mb-3 space-y-0.5 text-xs">{d.errors.map((e, i) => <div key={`e${i}`} className="text-orange-300">{e}</div>)}{d.notes.map((n, i) => <div key={`n${i}`} className="text-zinc-500">{n}</div>)}</div> : null}
      <p className="mb-3 text-xs text-zinc-500">MFA devices are not exposed by any Identity Center API; "Who can get in" above reads the factors from the sign-ins. Disabled users are listed last. Sign-ins come from the home region's CloudTrail (sso.amazonaws.com, 90 days back at most); the per-account activity is the newest stored write made under the user's session.</p>
      {d.users.length === 0 ? <Empty>No users in the directory{currentScope() !== "all" ? " with an assignment in this account" : ""}.</Empty> : (
        <table className="w-full border-collapse text-sm">
          <thead><tr><Th>User</Th><Th>Admin</Th><Th>Groups</Th><Th>Access</Th><Th className="text-right">Sign-ins 30d</Th><Th>Last sign-in</Th><Th>Last activity</Th></tr></thead>
          <tbody>{d.users.map((u) => {
            const isOpen = open === u.user_id; const activity = Object.entries(u.activity).sort((a, b) => b[1].localeCompare(a[1]));
            return (
              <tr key={u.user_id} onClick={() => setOpen(isOpen ? null : u.user_id)} className={`cursor-pointer border-t border-zinc-800 align-top hover:bg-zinc-900/60 ${u.status === "DISABLED" ? "opacity-50" : ""}`}>
                <Td><div className="flex items-center gap-2"><span className="font-medium text-zinc-100">{u.user_name}</span>{u.status === "DISABLED" ? <Badge>disabled</Badge> : null}{u.gone ? <Badge>gone</Badge> : null}{u.idp ? <Badge>{u.idp.toLowerCase().includes("okta") ? "Okta" : u.idp.toLowerCase().includes("google") ? "Google" : u.idp.toLowerCase().includes("azure") || u.idp.toLowerCase().includes("microsoft") ? "Entra" : "IdP"}</Badge> : null}</div>{(u.display_name || u.email) && <div className="text-xs text-zinc-500">{[u.display_name, u.email].filter(Boolean).join(" · ")}</div>}</Td>
                <Td className="text-xs">{u.admin ? <span className="text-orange-300">admin</span> : <span className="text-zinc-500">—</span>}</Td>
                <Td className="max-w-48 text-xs text-zinc-400">{u.groups.join(", ") || "—"}</Td>
                <Td className="max-w-md text-xs text-zinc-400">
                  {u.assignments.length === 0 ? <span className="text-zinc-500">no account{u.applications.length ? `; ${u.applications.length} application${u.applications.length === 1 ? "" : "s"}` : ""}</span>
                    : !isOpen ? <span>{u.accounts} account{u.accounts === 1 ? "" : "s"} · {[...new Set(u.assignments.map((a) => a.permission_set))].join(", ")}{u.applications.length ? ` · ${u.applications.length} app${u.applications.length === 1 ? "" : "s"}` : ""}</span>
                    : <div className="space-y-0.5">{u.assignments.map((a, i) => <div key={i}><span className="text-zinc-200">{name(a.account_id)}</span> · {a.permission_set} <span className="text-zinc-600">{a.via}</span></div>)}{u.applications.length ? <div className="text-zinc-500">applications: {u.applications.join(", ")}</div> : null}</div>}
                </Td>
                <Td className="text-right text-xs">{u.sign_ins_30d || <span className="text-zinc-600">0</span>}{u.failed_30d ? <span className="ml-1 text-orange-300" title="failed sign-ins in 30 days">({u.failed_30d})</span> : null}</Td>
                <Td className="whitespace-nowrap text-xs text-zinc-400">{u.last_sign_in ? <span title={when(u.last_sign_in)}>{day(u.last_sign_in)} <span className="text-zinc-600">{ago(u.last_sign_in)}</span></span> : <span className="text-zinc-500">none in 90 d</span>}</Td>
                <Td className="text-xs text-zinc-400">{activity.length === 0 ? <span className="text-zinc-600">no stored write</span> : isOpen ? <div className="space-y-0.5">{activity.map(([acct, t]) => <div key={acct}><span className="text-zinc-200">{name(acct)}</span> {day(t)}</div>)}</div> : <span title={activity.map(([a, t]) => `${name(a)} ${day(t)}`).join("\n")}>{day(activity[0][1])} <span className="text-zinc-600">{activity.length > 1 ? `${activity.length} accounts` : name(activity[0][0])}</span></span>}</Td>
              </tr>
            );
          })}</tbody>
        </table>
      )}
      <div className="mt-4">
        <button onClick={() => setShowSets(!showSets)} className="text-xs text-zinc-400 hover:text-zinc-200">{showSets ? "▾" : "▸"} Permission sets · {d.permission_sets.length}{d.admin_sets ? <span className="text-orange-300"> · {d.admin_sets} administrative</span> : null}</button>
        {showSets && (d.permission_sets.length === 0 ? <Empty>None.</Empty> : (
          <table className="mt-2 w-full border-collapse text-sm">
            <thead><tr><Th>Permission set</Th><Th>Policies</Th><Th>Session</Th><Th className="text-right">People</Th><Th>Accounts · last used</Th></tr></thead>
            <tbody>{d.permission_sets.map((p) => (
              <tr key={p.arn} className="border-t border-zinc-800 align-top">
                <Td><div className="flex items-center gap-2"><span className="font-medium text-zinc-100">{p.name}</span>{p.admin ? <span className="text-xs text-orange-300">admin</span> : null}{p.gone ? <Badge>gone</Badge> : null}</div>{p.description && <div className="text-xs text-zinc-500">{p.description}</div>}</Td>
                <Td className="max-w-sm text-xs text-zinc-400">{[...p.managed_policies, ...p.customer_managed.map((c) => `customer ${c}`), ...(p.inline_policy ? ["inline"] : [])].join(" · ") || "—"}{p.boundary ? <div className="text-zinc-500">boundary {p.boundary}</div> : null}</Td>
                <Td className="whitespace-nowrap text-xs text-zinc-400">{duration(p.session_duration)}</Td>
                <Td className="text-right text-xs">{p.users}</Td>
                <Td className="text-xs text-zinc-400">{p.accounts.length === 0 ? <span className="text-zinc-500">not provisioned</span> : <div className="space-y-0.5">{p.accounts.map((a) => <div key={a}><span className="text-zinc-200">{name(a)}</span> {p.last_used[a] ? <span title={when(p.last_used[a])}>used {day(p.last_used[a])}</span> : <span className="text-zinc-600">never used</span>}</div>)}</div>}</Td>
              </tr>))}</tbody>
          </table>
        ))}
      </div>
    </Card>
  );
}

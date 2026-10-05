import { Fragment, useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { api, when } from "../api";
import { Badge, Button, Card, Empty, Stat, Td, Th } from "./ui";

type Change = { event_id: string; event_time: string; event_name: string; what: string; target_user_id: string | null; target_name: string | null; by: string | null; failed: boolean };
type Console = { region: string; instance: string } | null;
type Client = { account_id: string | null; channel: string; client: string; platform: string | null; factors: string[]; events: number; failures: number; first_at: string; last_at: string; last_ip: string | null; keys: string[]; via: string[] };
type Identity = {
  kind: "root" | "iam_user" | "sso_user"; id: string; name: string; email: string | null; display_name: string | null; account_id: string | null; admin: boolean; console: boolean; keys: number;
  mfa: string; mfa_source: string | null; last_seen_at: string | null; clients: Client[]; sign_ins_90d: number | null; mfa_sign_ins_90d: number | null; status: "active" | "disabled" | "no_access"; changes: Change[];
};
type Person = { key: string; name: string; email: string | null; machine: boolean; matched_by: string[]; identities: Identity[]; admin: boolean; mfa: string; platforms: string[]; channels: string[]; keys: number; last_seen_at: string | null; status: "active" | "disabled" };
type Data = {
  accounts: number; roots_without_mfa: number; roots_with_keys: number; roots_signed_in_90d: number; centralized: boolean | null; root_sessions: boolean | null;
  people: number; machines: number; disabled: number; people_passkey: number; people_app_only: number; people_no_mfa: number; people_unknown_mfa: number; keys_on_desktops: number;
  platforms: { platform: string; actors: number }[]; read_at: string | null; errors: string[]; notes: string[]; roots: Identity[]; persons: Person[]; directory_changes: Change[]; identity_center_console: Console;
};

/** The Identity Center console's page for a user, where its MFA devices can be seen. */
const consoleUserUrl = (c: Console, userId: string) => (c ? `https://${c.region}.console.aws.amazon.com/singlesignon/home?region=${c.region}#!/instances/${c.instance}/users/user-details/${userId}` : null);
/** Changes that weaken or remove a way in stand out. */
const RISKY = new Set(["DeleteMfaDeviceForUser", "UpdatePassword", "ResetPassword", "EnableUser", "CreateUser"]);

function Changes({ changes, showTarget = false }: { changes: Change[]; showTarget?: boolean }) {
  return (
    <div className="space-y-0.5 text-xs">{changes.map((c) => (
      <div key={c.event_id} className={c.failed ? "text-zinc-600 line-through" : ""}>
        <span className="text-zinc-500">{day(c.event_time)}</span>{" "}
        <span className={RISKY.has(c.event_name) ? "text-amber-300" : c.event_name === "DisableUser" || c.event_name === "DeleteUser" ? "text-zinc-300" : "text-zinc-400"}>{c.what}</span>
        {showTarget ? <span className="text-zinc-300"> · {c.target_name ?? c.target_user_id ?? "?"}</span> : null}
        {c.by ? <span className="text-zinc-500"> by {c.by}</span> : null}
      </div>))}</div>
  );
}

const day = (iso: string | null | undefined) => (iso ? new Date(iso).toLocaleDateString() : "—");
const KIND: Record<Identity["kind"], string> = { root: "root", iam_user: "IAM user", sso_user: "Identity Center" };
const FACTOR: Record<string, string> = { password: "password", app: "authenticator app", passkey: "passkey", hardware: "hardware token", mfa: "MFA", sso: "SSO session", federated: "federated", access_key: "access key", session: "temporary credentials", console_session: "console session" };
const CHANNEL: Record<string, string> = { console: "console", portal: "access portal", cli: "CLI", sdk: "SDK", iac: "infrastructure as code", aws: "AWS", unknown: "?" };
const DESKTOP = new Set(["macOS", "Windows", "Linux"]);

/** What each factor means, for the ? next to it. */
const FACTOR_HELP: Record<string, string> = {
  password: "Signed in with a password only on that sign-in: no second factor was asked. For Identity Center this can be context-aware MFA skipping a browser it already trusts.",
  app: "A 6-digit code from an authenticator app (Google Authenticator, 1Password, Authy…). A real second factor, but a fake sign-in page can phish the code, and an app that syncs codes puts them in that app's cloud account.",
  passkey: "A passkey or security key (Touch ID, Face ID, iCloud Keychain, a YubiKey). Bound to the real AWS domain, so a fake page cannot phish it: the strongest option.",
  hardware: "A hardware token that shows a code (a key fob). A second factor like the app, without a phone, still phishable.",
  mfa: "MFA was used, but CloudTrail did not record which kind of device.",
  sso: "Signed in through the Identity Center access portal, then AWS issued short-lived credentials for an account and role: opening the console from the portal, the portal's Access keys, or aws sso login.",
  federated: "Opened the AWS console without an AWS password: signed in somewhere else first (the Identity Center portal or an external identity provider) and AWS trusted that sign-in. The factors are on the portal sign-in.",
  access_key: "A long-lived access key (starts with AKIA). It works from anywhere until it is deleted or deactivated, with no MFA: the riskiest credential, especially on a laptop.",
  session: "Temporary credentials (start with ASIA) from an assumed role or a session token; they expire on their own, usually within hours.",
  console_session: "A call made from the AWS console in a browser, under the credentials of that console sign-in.",
};
/** What each channel means. */
const CHANNEL_HELP: Record<string, string> = {
  console: "The AWS web console in a browser, or the AWS Console mobile app.",
  portal: "The Identity Center access portal (the start page that lists your accounts): signing in to it, or copying temporary keys from its Access keys button.",
  cli: "The AWS command line (aws-cli), including aws sso login.",
  sdk: "Code using an AWS SDK (JavaScript, Go, Python's boto3…): an app, a script or a tool.",
  iac: "Infrastructure as code: Terraform, Pulumi or the AWS CDK.",
  aws: "AWS itself acting on the account's behalf.",
  unknown: "CloudTrail recorded no user agent.",
};

/** A small ? that explains a word on hover or keyboard focus. The text is drawn on the page (a portal, fixed position)
 * and kept inside the window, so a table cell or the card's edge never clips it. */
function Help({ text }: { text: string }) {
  const ref = useRef<HTMLSpanElement>(null);
  const [pos, setPos] = useState<{ left: number; top: number; above: boolean } | null>(null);
  const W = 256; const M = 8;
  const show = () => {
    const r = ref.current?.getBoundingClientRect(); if (!r) return;
    const left = Math.min(Math.max(M, r.left + r.width / 2 - W / 2), window.innerWidth - W - M);
    const above = r.top > 140;
    setPos({ left, top: above ? r.top - 6 : r.bottom + 6, above });
  };
  const hide = () => setPos(null);
  return (
    <span ref={ref} tabIndex={0} onMouseEnter={show} onMouseLeave={hide} onFocus={show} onBlur={hide} aria-label={text}
      className="ml-0.5 inline-flex h-3.5 w-3.5 cursor-help items-center justify-center rounded-full border border-zinc-600 align-middle text-[9px] leading-none text-zinc-400 outline-none hover:border-zinc-400 hover:text-zinc-200 focus:border-zinc-400">
      ?
      {pos && createPortal(
        <span role="tooltip" style={{ position: "fixed", left: pos.left, top: pos.top, width: W, transform: pos.above ? "translateY(-100%)" : undefined }}
          className="pointer-events-none z-50 rounded border border-zinc-700 bg-zinc-900 p-2 text-left text-[11px] font-normal normal-case leading-snug text-zinc-200 shadow-lg">{text}</span>,
        document.body)}
    </span>
  );
}

/** A word followed by its ?, when there is an explanation for it. */
const Term = ({ label, help }: { label: string; help?: string }) => <span className="whitespace-nowrap">{label}{help ? <Help text={help} /> : null}</span>;

/** The MFA cell: the strongest factor, and for Identity Center how many sign-ins asked for it. */
function Mfa({ a, long = false }: { a: Pick<Identity, "kind" | "mfa" | "mfa_source" | "console" | "sign_ins_90d" | "mfa_sign_ins_90d"> & { kind: string }; long?: boolean }) {
  const ratio = a.kind === "sso_user" && a.sign_ins_90d ? <span className="text-zinc-500"> · asked on {a.mfa_sign_ins_90d ?? 0}/{a.sign_ins_90d} sign-ins</span> : null;
  if (a.mfa === "none") return a.console || a.kind === "root" ? <span className="text-red-300">none</span> : <span className="text-zinc-500">— keys only</span>;
  if (a.mfa === "unknown") {
    if (a.kind === "sso_user" && a.sign_ins_90d) return <span className="text-zinc-400" title="Identity Center did not ask for a second factor on any sign-in in 90 days: context-aware MFA skips a browser it trusts. Registered devices are not exposed by any API.">not asked{ratio}{long ? <span className="text-zinc-500"> · context-aware MFA skips a trusted browser; registered devices are not exposed by any API</span> : null}</span>;
    return <span className="text-zinc-500" title="no sign-in in 90 days">not seen</span>;
  }
  const label = a.mfa === "app" ? "authenticator app" : a.mfa === "passkey" ? "passkey / security key" : a.mfa === "hardware" ? "hardware token" : a.mfa === "passkey_or_hardware" ? "passkey or hardware" : "on";
  const cls = a.mfa === "app" ? "text-amber-300" : a.mfa === "mfa" ? "text-zinc-300" : "text-emerald-300";
  const title = a.mfa === "app" ? "a TOTP code from an app such as Google Authenticator: works, but can be phished, and synced codes follow that app's cloud account" : a.mfa === "mfa" ? "MFA on; the device type was not recorded" : "phishing-resistant";
  return <span title={title}><span className={cls}>{label}</span>{ratio}{long && a.mfa_source ? <span className="text-zinc-500"> · from {a.mfa_source === "device" ? "the registered devices" : a.mfa_source === "account" ? "the account summary" : "sign-ins"}</span> : null}</span>;
}

function Status({ s }: { s: Identity["status"] | Person["status"] }) {
  if (s === "disabled") return <Badge>disabled</Badge>;
  if (s === "no_access") return <span title="no console password and no active access key" className="rounded bg-zinc-800 px-1.5 py-0.5 text-[11px] text-zinc-400">no way in</span>;
  return null;
}

/** Every client an identity was seen using, one row each. */
function ClientsTable({ clients, acct }: { clients: Client[]; acct: (id: string | null) => string }) {
  if (!clients.length) return <div className="text-xs text-zinc-600">Nothing seen in 90 days.</div>;
  return (
    <table className="w-full border-collapse text-xs">
      <thead><tr className="text-zinc-500"><Th>Client</Th><Th>Channel</Th><Th>Factors</Th><Th className="text-right">Events</Th><Th>First</Th><Th>Last</Th><Th>Last IP</Th><Th>Account</Th></tr></thead>
      <tbody>{clients.map((c, i) => (
        <tr key={i} className="border-t border-zinc-800/60">
          <Td><span className="text-zinc-200">{c.client}</span>{c.platform ? <span className={c.factors.includes("access_key") && DESKTOP.has(c.platform) ? "text-amber-300" : "text-zinc-400"}> · {c.platform}</span> : null}</Td>
          <Td className="text-zinc-400"><Term label={CHANNEL[c.channel] ?? c.channel} help={CHANNEL_HELP[c.channel]} />{c.via.length ? <span className="text-zinc-600"> ({c.via.join(", ")})</span> : null}</Td>
          <Td className="text-zinc-400">{c.factors.length ? c.factors.map((f, i) => <Fragment key={f}>{i ? <span className="text-zinc-600"> + </span> : null}<Term label={FACTOR[f] ?? f} help={FACTOR_HELP[f]} /></Fragment>) : "—"}{c.keys.length ? <span className="font-mono text-zinc-500"> …{c.keys.join(", …")}</span> : null}</Td>
          <Td className="text-right">{c.events}{c.failures ? <span className="text-orange-300"> ({c.failures} failed)</span> : null}</Td>
          <Td className="whitespace-nowrap text-zinc-500" >{day(c.first_at)}</Td>
          <Td className="whitespace-nowrap text-zinc-400"><span title={when(c.last_at)}>{day(c.last_at)}</span></Td>
          <Td className="font-mono text-zinc-500">{c.last_ip ?? "—"}</Td>
          <Td className="text-zinc-500">{acct(c.account_id)}</Td>
        </tr>))}</tbody>
    </table>
  );
}

/** One identity inside an opened person: what it is, its way in, and its clients. */
function IdentityBlock({ i, acct, ic }: { i: Identity; acct: (id: string | null) => string; ic: Console }) {
  const url = i.kind === "sso_user" ? consoleUserUrl(ic, i.id) : null;
  return (
    <div className={`rounded border border-zinc-800 p-3 ${i.status !== "active" ? "opacity-60" : ""}`}>
      <div className="mb-2 flex flex-wrap items-center gap-2 text-xs">
        <Badge>{KIND[i.kind]}</Badge><span className="font-medium text-zinc-100">{i.name}</span><Status s={i.status} />
        {i.admin ? <span className="text-orange-300">admin</span> : null}
        <span className="text-zinc-500">{i.kind === "sso_user" ? [i.display_name, i.email].filter(Boolean).join(" · ") || "every assigned account" : acct(i.account_id)}</span>
      </div>
      <div className="mb-2 grid gap-x-6 gap-y-1 text-xs sm:grid-cols-3">
        <div><span className="text-zinc-500">MFA </span><Mfa a={i} long /></div>
        <div><span className="text-zinc-500">Console </span>{i.console ? "yes" : <span className="text-zinc-500">no</span>}</div>
        <div><span className="text-zinc-500">Active keys </span>{i.keys ? <span className={i.kind === "root" ? "text-red-300" : ""}>{i.keys}</span> : <span className="text-zinc-500">none</span>}</div>
      </div>
      {i.kind === "sso_user" ? <div className="mb-2 text-xs text-zinc-500">Registered MFA devices are not exposed by any AWS API{url ? <> — <a href={url} target="_blank" rel="noreferrer" className="text-sky-300 hover:underline">see them in the Identity Center console ↗</a></> : null}.</div> : null}
      {i.changes?.length ? <div className="mb-2"><div className="mb-0.5 text-xs text-zinc-500">Directory changes</div><Changes changes={i.changes} /></div> : null}
      <ClientsTable clients={i.clients} acct={acct} />
    </div>
  );
}

/**
 * Who can get in and with what: the root user of each account, then people (an IAM user and an Identity Center user of
 * the same name or email folded into one) with their MFA and the devices each was seen using. A row opens to every
 * identity and client behind it.
 */
export function Access() {
  const [d, setD] = useState<Data | null>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const [names, setNames] = useState<Record<string, string>>({});
  const [open, setOpen] = useState<string | null>(null);
  const [showDisabled, setShowDisabled] = useState(false);
  const [showChanges, setShowChanges] = useState(false);
  const load = () => api("/inventory/access").then((r) => { setD(r); setErr(""); }).catch((e) => setErr(e.message));
  useEffect(() => { load(); api("/accounts").then((a) => setNames(Object.fromEntries((a.records || []).filter((r: any) => r.provider === "aws").map((r: any) => [String(r.id), String(r.name || "")])))).catch(() => { /* ids alone */ }); }, []);
  const refresh = async () => { setBusy(true); try { await api("/inventory/access/refresh", { method: "POST", body: "{}" }); await load(); } catch (e: any) { setErr(e.message); } finally { setBusy(false); } };
  const acct = (id: string | null) => (!id ? "—" : names[id] && names[id] !== id ? `${names[id]} (${id})` : id);
  const toggle = (k: string) => setOpen(open === k ? null : k);
  const title = <span className="flex flex-wrap items-center justify-between gap-2"><span>Who can get in {d?.read_at ? <span className="font-normal text-zinc-500">· read {when(d.read_at)}</span> : null}</span><Button variant="ghost" className="!px-2 !py-1 !text-xs" onClick={refresh} disabled={busy}>{busy ? "Reading…" : "Refresh"}</Button></span>;
  if (err) return <Card title={title}><div className="text-sm text-red-300">{err}</div></Card>;
  if (!d) return <Card title={title}><div className="text-sm text-zinc-500">Loading…</div></Card>;
  const roots: Identity[] = Array.isArray(d.roots) ? d.roots : [];
  const everyone: Person[] = Array.isArray(d.persons) ? d.persons : [];
  if (!d.read_at && !roots.length && !everyone.length) return <Card title={title}><Empty>Not read yet. Refresh reads the root user of every account and 90 days of sign-ins from CloudTrail; the nightly inventory does the same.</Empty></Card>;
  const disabled = everyone.filter((p) => p.status === "disabled");
  const shown = showDisabled ? everyone : everyone.filter((p) => p.status !== "disabled");
  return (
    <Card title={title}>
      <div className="mb-4 grid grid-cols-2 gap-4 lg:grid-cols-6">
        <Stat label="Root users" value={d.accounts} hint={d.roots_without_mfa || d.roots_with_keys ? <span className="text-red-300">{[d.roots_without_mfa && `${d.roots_without_mfa} without MFA`, d.roots_with_keys && `${d.roots_with_keys} with access keys`].filter(Boolean).join(" · ")}</span> : `${d.roots_signed_in_90d} signed in within 90 days`} />
        <Stat label="Central root access" value={d.centralized == null ? <span className="text-zinc-500">?</span> : d.centralized ? <span className="text-emerald-300">on</span> : <span className="text-amber-300">off</span>} hint={d.centralized == null ? "the management account answers this" : d.centralized ? `member roots managed by the organisation${d.root_sessions ? " · root sessions on" : ""}` : "every member keeps its own root password"} />
        <Stat label="People" value={d.people} hint={`${d.machines ? `${d.machines} machine${d.machines === 1 ? "" : "s"} · ` : ""}${d.disabled} disabled`} />
        <Stat label="Phishing-resistant" value={<span className={d.people_passkey ? "text-emerald-300" : "text-zinc-400"}>{d.people_passkey}</span>} hint="passkey, security key or hardware token" />
        <Stat label="Authenticator app" value={<span className={d.people_app_only ? "text-amber-300" : "text-zinc-400"}>{d.people_app_only}</span>} hint={`${d.people_no_mfa ? `${d.people_no_mfa} with no MFA · ` : ""}${d.people_unknown_mfa} not asked or not seen`} />
        <Stat label="Keys used from laptops" value={<span className={d.keys_on_desktops ? "text-amber-300" : "text-emerald-300"}>{d.keys_on_desktops}</span>} hint="long-lived access key called from macOS, Windows or Linux" />
      </div>
      {d.platforms?.length ? <div className="mb-3 flex flex-wrap gap-1.5 text-xs text-zinc-400">Seen from: {d.platforms.map((p) => <span key={p.platform} className="rounded bg-zinc-800 px-1.5 py-0.5">{p.platform} <span className="text-zinc-500">{p.actors}</span></span>)}</div> : null}
      {(d.errors?.length || d.notes?.length) ? <div className="mb-3 space-y-0.5 text-xs">{d.errors.map((e, i) => <div key={`e${i}`} className="text-orange-300">{e}</div>)}{d.notes.map((n, i) => <div key={`n${i}`} className="text-zinc-500">{n}</div>)}</div> : null}

      <table className="mb-5 w-full border-collapse text-sm">
        <thead><tr><Th>Root of account</Th><Th>MFA</Th><Th>Root keys</Th><Th>Last sign-in</Th><Th>Devices</Th></tr></thead>
        <tbody>{roots.length === 0 ? <tr><Td className="text-zinc-500">No root user read yet.</Td></tr> : roots.map((r) => {
          const isOpen = open === r.id; const plats = [...new Set(r.clients.map((c) => c.platform).filter(Boolean))];
          return (<Fragment key={r.id}>
            <tr onClick={() => toggle(r.id)} className="cursor-pointer border-t border-zinc-800 align-top hover:bg-zinc-900/60">
              <Td><span className="mr-1 text-zinc-500">{isOpen ? "▾" : "▸"}</span><span className="text-zinc-100">{acct(r.account_id)}</span></Td>
              <Td className="text-xs"><Mfa a={r} /></Td>
              <Td className="text-xs">{r.keys ? <span className="text-red-300">{r.keys} active</span> : <span className="text-emerald-300">none</span>}</Td>
              <Td className="whitespace-nowrap text-xs text-zinc-400">{r.last_seen_at ? <span title={when(r.last_seen_at)}>{day(r.last_seen_at)}</span> : <span className="text-zinc-500">none seen</span>}</Td>
              <Td className="text-xs text-zinc-400">{plats.join(" · ") || <span className="text-zinc-600">—</span>}</Td>
            </tr>
            {isOpen && <tr className="bg-zinc-950/40"><td colSpan={5} className="px-3 pb-3 pt-1"><IdentityBlock i={r} acct={acct} ic={d.identity_center_console} /></td></tr>}
          </Fragment>);
        })}</tbody>
      </table>

      {everyone.length === 0 ? <Empty>No IAM or Identity Center users{d.read_at ? "" : " read yet"}.</Empty> : (<>
        <table className="w-full border-collapse text-sm">
          <thead><tr><Th>Person</Th><Th>Identities</Th><Th>Admin</Th><Th>MFA</Th><Th>Devices</Th><Th>Last seen</Th></tr></thead>
          <tbody>{shown.map((p) => {
            const isOpen = open === p.key; const sso = p.identities.find((i) => i.kind === "sso_user");
            return (<Fragment key={p.key}>
              <tr onClick={() => toggle(p.key)} className={`cursor-pointer border-t border-zinc-800 align-top hover:bg-zinc-900/60 ${p.status === "disabled" ? "opacity-50" : ""}`}>
                <Td><div className="flex items-center gap-2"><span className="text-zinc-500">{isOpen ? "▾" : "▸"}</span><span className="font-medium text-zinc-100">{p.name}</span>{p.machine ? <Badge>machine</Badge> : null}<Status s={p.status} /></div>{p.email && p.email !== p.name ? <div className="pl-5 text-xs text-zinc-500">{p.email}</div> : null}</Td>
                <Td className="text-xs"><div className="flex flex-wrap gap-1">{p.identities.map((i) => <span key={i.id} title={i.kind === "sso_user" ? i.name : `${i.name} · ${acct(i.account_id)}`} className={`rounded border px-1.5 py-0.5 ${i.status !== "active" ? "border-zinc-800 text-zinc-500 line-through" : "border-zinc-700 text-zinc-300"}`}>{KIND[i.kind]}{i.kind === "iam_user" ? ` · ${names[i.account_id ?? ""] || i.account_id}` : ""}</span>)}</div></Td>
                <Td className="text-xs">{p.admin ? <span className="text-orange-300">admin</span> : <span className="text-zinc-500">—</span>}</Td>
                <Td className="text-xs"><Mfa a={{ ...(sso ?? p.identities[0]), mfa: p.mfa, kind: sso && p.mfa === sso.mfa ? "sso_user" : p.identities[0].kind }} /></Td>
                <Td className="text-xs text-zinc-400">{p.platforms.join(" · ") || <span className="text-zinc-600">—</span>}{p.channels.length ? <div className="text-[11px] text-zinc-600">{p.channels.map((c) => CHANNEL[c] ?? c).join(", ")}</div> : null}</Td>
                <Td className="whitespace-nowrap text-xs text-zinc-400">{p.last_seen_at ? day(p.last_seen_at) : <span className="text-zinc-500">never</span>}</Td>
              </tr>
              {isOpen && <tr className="bg-zinc-950/40"><td colSpan={6} className="space-y-2 px-3 pb-3 pt-1">
                {p.identities.length > 1 ? <div className="text-xs text-zinc-500">Matched on {p.matched_by.map((k) => <code key={k} className="mr-1 text-zinc-400">{k}</code>)}(name, email or display name).</div> : null}
                {p.identities.map((i) => <IdentityBlock key={i.id} i={i} acct={acct} ic={d.identity_center_console} />)}
              </td></tr>}
            </Fragment>);
          })}</tbody>
        </table>
        {disabled.length ? <button onClick={() => setShowDisabled(!showDisabled)} className="mt-2 text-xs text-zinc-400 hover:text-zinc-200">{showDisabled ? "▾ Hide" : "▸ Show"} {disabled.length} disabled</button> : null}
      </>)}
      {d.directory_changes?.length ? <div className="mt-4">
        <button onClick={() => setShowChanges(!showChanges)} className="text-xs text-zinc-400 hover:text-zinc-200">{showChanges ? "▾" : "▸"} Identity Center directory changes · {d.directory_changes.length}{(() => { const n = d.directory_changes.filter((c) => c.event_name === "DeleteMfaDeviceForUser" && !c.failed).length; return n ? <span className="text-amber-300"> · {n} MFA device{n === 1 ? "" : "s"} removed</span> : null; })()}</button>
        {showChanges && <div className="mt-2"><Changes changes={d.directory_changes} showTarget /></div>}
      </div> : null}
      <p className="mt-3 text-xs text-zinc-500">No API lists devices. They come from CloudTrail: console sign-ins (whether MFA was used and which device), Identity Center sign-ins (the credential type per sign-in), the access portal and <code>aws sso login</code>, and the user agent and key type on stored writes. CloudTrail keeps 90 days. A person is an IAM user and an Identity Center user whose name, email or display name match.</p>
    </Card>
  );
}

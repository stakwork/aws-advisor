import { useEffect, useState } from "react";
import { api, when } from "../api";
import { Button, Card, Empty, Td, Th } from "./ui";

type Event = { arn: string; account_id: string | null; feed: "managed" | "configured"; source: string | null; event_type: string | null; headline: string | null; notification_type: string | null; event_status: string | null; origin_region: string | null; related_account: string | null; created_at: string; aggregation: string | null; event_count: number; regions: string[] };
type Data = { days: number; total: number; alerts: number; warnings: number; unhealthy: number; managed: number; configured: number; by_source: { source: string; n: number; alerts: number }[]; by_account: { account_id: string | null; n: number }[]; last_fetch: string | null; hubs: string[]; errors: string[]; notes: string[]; events: Event[] };

const DAYS = [7, 30, 90];
const typeClass: Record<string, string> = { ALERT: "text-red-300", WARNING: "text-orange-300", ANNOUNCEMENT: "text-sky-300", INFORMATIONAL: "text-zinc-400" };

/** What AWS told the account through User Notifications: the managed feed (Health, announcements, billing, security) and the account's own configured notifications. */
export function CloudNotifications() {
  const [days, setDays] = useState(7);
  const [d, setD] = useState<Data | null>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");
  const [source, setSource] = useState<string | null>(null);
  const load = () => api(`/cloud-notifications?days=${days}${source ? `&source=${encodeURIComponent(source)}` : ""}`).then((r) => { setD(r); setErr(""); }).catch((e) => setErr(e.message));
  useEffect(() => { load(); }, [days, source]);
  const refresh = async () => {
    setBusy(true); setMsg("");
    try { const r = await api("/cloud-notifications/refresh", { method: "POST", body: "{}" }); setMsg(`${r.events} read across ${r.accounts} account(s), ${r.stored} new, ${Math.round(r.took_ms / 1000)} s${r.errors?.length ? ` · ${r.errors[0]}` : ""}`); await load(); }
    catch (e: any) { setMsg(e.message); } finally { setBusy(false); }
  };
  const title = <span className="flex flex-wrap items-center justify-between gap-2">
    <span>AWS notifications <span className="font-normal text-zinc-500">(User Notifications, the console bell: the AWS-managed feed per account{d?.hubs?.length ? `, plus the configured notifications of the hub${d.hubs.length === 1 ? "" : "s"} in ${d.hubs.join(", ")}` : ""})</span>{d?.last_fetch ? <span className="font-normal text-zinc-500"> · collected {when(d.last_fetch)} · {d.total} in {days} d{d.alerts ? <span className="text-red-300"> · {d.alerts} alert{d.alerts === 1 ? "" : "s"}</span> : null}{d.unhealthy ? <span className="text-orange-300"> · {d.unhealthy} unhealthy</span> : null}</span> : null}</span>
    <span className="flex items-center gap-1 text-xs">{DAYS.map((h) => <button key={h} onClick={() => setDays(h)} className={`rounded border px-1.5 py-0.5 ${h === days ? "border-zinc-400 text-zinc-100" : "border-zinc-700 text-zinc-400 hover:bg-zinc-800"}`}>{h}d</button>)}<Button variant="ghost" className="!px-2 !py-1 !text-xs" onClick={refresh} disabled={busy}>{busy ? "Reading…" : "Collect now"}</Button></span>
  </span>;
  return (
    <Card title={title}>
      {msg && <div className="mb-2 text-xs text-zinc-500">{msg}</div>}
      {err ? <div className="text-sm text-red-300">{err}</div> : !d ? <Empty>Loading…</Empty> : !d.last_fetch ? <Empty>Not collected yet. The daily logs job reads the feed with notifications:ListManagedNotificationEvents (Settings › Permissions names it); Collect now runs it.</Empty> : (
        <>
          {(d.errors?.length || d.notes?.length) ? <div className="mb-2 space-y-0.5 text-xs">{d.errors.map((e, i) => <div key={`e${i}`} className="text-orange-300">{e}</div>)}{d.notes.map((n, i) => <div key={`n${i}`} className="text-zinc-500">{n}</div>)}</div> : null}
          {d.total === 0 && !source ? <Empty>Nothing from AWS in this window.</Empty> : (
            <div className="grid gap-4 lg:grid-cols-[minmax(0,3fr)_minmax(0,1fr)]">
              <table className="w-full border-collapse text-sm">
                <thead><tr><Th>When</Th><Th>Kind</Th><Th>Source</Th><Th>What</Th><Th>Where</Th></tr></thead>
                <tbody>{d.events.map((e) => (
                  <tr key={e.arn} className="border-t border-zinc-800 align-top">
                    <Td className="whitespace-nowrap text-xs text-zinc-400"><span title={e.created_at}>{when(e.created_at)}</span></Td>
                    <Td className="text-xs"><span className={typeClass[e.notification_type || ""] || "text-zinc-400"}>{(e.notification_type || "event").toLowerCase()}</span>{e.event_status === "UNHEALTHY" ? <div className="text-orange-300">unhealthy</div> : null}{e.feed === "configured" ? <div className="text-zinc-600">configured</div> : null}</Td>
                    <Td className="text-xs text-zinc-300">{e.source || "—"}{e.event_type ? <div className="font-mono text-[11px] text-zinc-500">{e.event_type}</div> : null}</Td>
                    <Td className="max-w-xl text-xs text-zinc-200"><span className="block" title={e.headline || ""}>{e.headline || <span className="text-zinc-500">no headline</span>}</span>{e.event_count > 1 ? <span className="text-zinc-500">{e.event_count} events{e.regions.length ? ` in ${e.regions.join(", ")}` : ""}</span> : null}</Td>
                    <Td className="whitespace-nowrap text-xs text-zinc-400">{e.related_account && e.related_account !== e.account_id ? <div>{e.related_account}</div> : e.account_id ? <div>{e.account_id}</div> : null}{e.origin_region ? <div className="text-zinc-500">{e.origin_region}</div> : null}</Td>
                  </tr>))}</tbody>
              </table>
              <div>
                <div className="mb-1 text-xs uppercase tracking-wide text-zinc-500">By source</div>
                <ul className="space-y-0.5 text-sm">{source ? <li><button className="text-xs text-zinc-400 hover:text-zinc-200" onClick={() => setSource(null)}>← every source</button></li> : null}{d.by_source.map((s) => <li key={s.source} className="flex justify-between gap-2"><button className={`truncate text-left hover:underline ${s.source === source ? "text-zinc-100" : "text-zinc-300"}`} onClick={() => setSource(s.source === source ? null : s.source)}>{s.source}{s.alerts ? <span className="ml-1 text-red-300">{s.alerts} alert{s.alerts === 1 ? "" : "s"}</span> : null}</button><span className="text-zinc-500">{s.n}</span></li>)}</ul>
                {d.by_account.length > 1 ? <><div className="mb-1 mt-3 text-xs uppercase tracking-wide text-zinc-500">By account</div><ul className="space-y-0.5 text-sm">{d.by_account.map((a) => <li key={a.account_id || "parent"} className="flex justify-between gap-2"><span className="text-zinc-300">{a.account_id || "parent"}</span><span className="text-zinc-500">{a.n}</span></li>)}</ul></> : null}
                <div className="mt-3 text-xs text-zinc-500">{d.managed} from the AWS-managed feed{d.configured ? `, ${d.configured} from the account's own configurations` : ""}.{d.hubs.length ? "" : " No notification hub is registered, so only the managed feed exists."}</div>
              </div>
            </div>
          )}
          {d.total === 0 && source ? <div className="mt-2 text-xs text-zinc-500">Nothing from {source} in this window. <button className="hover:underline" onClick={() => setSource(null)}>Every source</button></div> : null}
        </>
      )}
    </Card>
  );
}

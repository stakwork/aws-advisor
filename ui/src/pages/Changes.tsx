import { useEffect, useState } from "react";
import { api, when } from "../api";
import { Badge, Button, Card, Empty, Td, Th } from "../components/ui";

type Action = { event_name: string; event_source: string; username: string | null; n: number; resources: string[]; errors: number };
type Trail = { since: string; events: number; noise: number; last_fetch: string | null; by_action: Action[]; by_user: { username: string | null; n: number }[] };
type LogGroup = { name: string; region: string; retention_days: number | null; stored_gb: number; ingest_gb_day: number | null; ingest_usd_month: number | null; storage_usd_month: number; log_class: string | null };
type Logs = { refreshed_at: string | null; total_gb_day: number | null; total_stored_gb: number; no_retention: number; groups: LogGroup[] };

const HOURS = [24, 72, 168];

/** What changed in the account (CloudTrail write events by people and deployments) and what the logs cost. */
export default function Changes() {
  const [hours, setHours] = useState(24);
  const [trail, setTrail] = useState<Trail | null>(null);
  const [logs, setLogs] = useState<Logs | null>(null);
  const [busy, setBusy] = useState<"" | "trail" | "logs">("");
  const [msg, setMsg] = useState("");
  const load = () => { api(`/trail?hours=${hours}`).then(setTrail).catch(() => setTrail(null)); api("/logs?limit=40").then(setLogs).catch(() => setLogs(null)); };
  useEffect(() => { load(); }, [hours]);
  const refresh = async (what: "trail" | "logs") => {
    setBusy(what); setMsg("");
    try { const r = await api(`/${what}/refresh`, { method: "POST", body: "{}" }); setMsg(what === "trail" ? `${r.events} events read, ${r.stored} new, ${Math.round(r.took_ms / 1000)} s${r.errors?.length ? ` · ${r.errors[0]}` : ""}` : `${r.groups} groups, ${r.metered} metered, ${Math.round(r.took_ms / 1000)} s`); load(); }
    catch (e: any) { setMsg(e.message); } finally { setBusy(""); }
  };
  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold text-zinc-100">Changes and logs</h1>
      <p className="max-w-3xl text-sm text-zinc-400">Who changed what in the account, from CloudTrail write events, with machine heartbeat (agents checking in, log streams opening, Batch and EKS running their tasks) counted but left out. Below, what CloudWatch Logs ingests and stores, priced at list. Both feed the agent's morning observation.</p>
      {msg && <div className="text-xs text-zinc-500">{msg}</div>}
      <Card title={<span className="flex flex-wrap items-center justify-between gap-2"><span>Changes · CloudTrail {trail?.last_fetch ? <span className="font-normal text-zinc-500">· collected {when(trail.last_fetch)} · {trail.events} events, {trail.noise.toLocaleString()} heartbeats hidden</span> : null}</span>
        <span className="flex items-center gap-1 text-xs">{HOURS.map((h) => <button key={h} onClick={() => setHours(h)} className={`rounded border px-1.5 py-0.5 ${h === hours ? "border-zinc-400 text-zinc-100" : "border-zinc-700 text-zinc-400 hover:bg-zinc-800"}`}>{h === 168 ? "7d" : `${h}h`}</button>)}<Button variant="ghost" className="!px-2 !py-1 !text-xs" onClick={() => refresh("trail")} disabled={busy !== ""}>{busy === "trail" ? "Collecting (3-4 min)…" : "Collect now"}</Button></span></span>}>
        {!trail ? <Empty>Loading…</Empty> : !trail.last_fetch ? <Empty>Not collected yet. The daily job needs cloudtrail:LookupEvents (Settings › Permissions names it); Collect now runs it.</Empty> : trail.by_action.length === 0 ? <Empty>No changes by people or deployments in this window.</Empty> : (
          <div className="grid gap-4 lg:grid-cols-[minmax(0,3fr)_minmax(0,1fr)]">
            <table className="w-full border-collapse text-sm">
              <thead><tr><Th className="text-right">Events</Th><Th>Action</Th><Th>By</Th><Th>On</Th></tr></thead>
              <tbody>{trail.by_action.map((a, i) => (
                <tr key={i} className="border-t border-zinc-800">
                  <Td className="text-right">{a.n}{a.errors ? <span className="ml-1 text-red-300" title="failed calls">({a.errors})</span> : null}</Td>
                  <Td><span className="text-zinc-500">{a.event_source}</span> <span className="font-mono text-xs text-zinc-100">{a.event_name}</span></Td>
                  <Td className="max-w-56"><span className="block truncate" title={a.username || ""}>{a.username || <span className="text-zinc-500">unknown</span>}</span></Td>
                  <Td className="max-w-72 font-mono text-xs text-zinc-400"><span className="block truncate" title={a.resources.join("\n")}>{a.resources.slice(0, 2).join(", ")}{a.resources.length > 2 ? ` +${a.resources.length - 2}` : ""}</span></Td>
                </tr>))}</tbody>
            </table>
            <div>
              <div className="mb-1 text-xs uppercase tracking-wide text-zinc-500">By principal</div>
              <ul className="space-y-0.5 text-sm">{trail.by_user.slice(0, 15).map((u, i) => <li key={i} className="flex justify-between gap-2"><span className="truncate text-zinc-300" title={u.username || ""}>{u.username || "unknown"}</span><span className="text-zinc-500">{u.n}</span></li>)}</ul>
            </div>
          </div>
        )}
      </Card>
      <Card title={<span className="flex flex-wrap items-center justify-between gap-2"><span>CloudWatch Logs {logs?.refreshed_at ? <span className="font-normal text-zinc-500">· {logs.total_gb_day != null ? `${logs.total_gb_day.toFixed(1)} GB/day ingested ≈ ${Math.round(logs.total_gb_day * 30 * 0.5)} USD/month` : "ingestion unknown"} · {logs.total_stored_gb.toFixed(0)} GB stored · {logs.no_retention} groups never expire</span> : null}</span><Button variant="ghost" className="!px-2 !py-1 !text-xs" onClick={() => refresh("logs")} disabled={busy !== ""}>{busy === "logs" ? "Collecting…" : "Collect now"}</Button></span>}>
        {!logs ? <Empty>Loading…</Empty> : !logs.refreshed_at ? <Empty>Not collected yet; Collect now reads every log group and 14 days of ingestion for the biggest ones.</Empty> : (
          <table className="w-full border-collapse text-sm">
            <thead><tr><Th>Log group</Th><Th className="text-right">Ingested / day</Th><Th className="text-right">Ingestion / month</Th><Th className="text-right">Stored</Th><Th className="text-right">Storage / month</Th><Th className="text-right">Retention</Th></tr></thead>
            <tbody>{logs.groups.map((g) => (
              <tr key={g.name} className="border-t border-zinc-800">
                <Td className="max-w-96 font-mono text-xs text-zinc-100"><span className="block truncate" title={g.name}>{g.name}</span></Td>
                <Td className="text-right">{g.ingest_gb_day != null ? `${g.ingest_gb_day.toFixed(2)} GB` : <span className="text-zinc-600">not metered</span>}</Td>
                <Td className="text-right">{g.ingest_usd_month != null ? `$${Math.round(g.ingest_usd_month)}` : "—"}</Td>
                <Td className="text-right">{g.stored_gb.toFixed(1)} GB</Td>
                <Td className="text-right text-zinc-400">${g.storage_usd_month.toFixed(2)}</Td>
                <Td className="text-right">{g.retention_days != null ? `${g.retention_days} d` : <Badge>never</Badge>}</Td>
              </tr>))}</tbody>
          </table>
        )}
      </Card>
    </div>
  );
}

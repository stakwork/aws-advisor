import React, { useEffect, useState } from "react";
import { NavLink } from "react-router-dom";
import { api, usd, when } from "../api";
import { Badge, Button, Card, Empty, Stat, Td, Th } from "../components/ui";

/** Cost per swarm: what each customer's box costs to keep at list price, whether anyone uses it, and who to ask. */
export default function Swarms() {
  const [month, setMonth] = useState<string>("");
  const [data, setData] = useState<any>(null);
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState(false);
  const load = (m = month) => api(`/swarms/costs${m ? `?month=${m}` : ""}`).then((d) => { setData(d); setMsg(""); if (!m) setMonth(d.month); }).catch((e) => setMsg(e.message));
  useEffect(() => { load(); }, [month]);
  const refresh = async () => {
    setBusy(true);
    try { const r = await api("/swarms/costs/refresh", { method: "POST" }); setMsg(`${r.swarms} swarm(s) refreshed, ≈ ${usd(r.total_usd, 2)}/month${r.snapshots_known ? "" : " (snapshots unknown)"}`); await load(); }
    catch (e: any) { setMsg(e.message); } finally { setBusy(false); }
  };
  const t = data?.totals;
  const months: string[] = data?.months?.length ? data.months : month ? [month] : [];
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <h1 className="text-xl font-semibold text-zinc-100">Swarms</h1>
        <span className="text-sm text-zinc-500">one box per customer: what it costs to keep, and whether anyone uses it</span>
        <span className="ml-auto flex items-center gap-2">
          <select value={month} onChange={(e) => setMonth(e.target.value)} className="rounded border border-zinc-800 bg-zinc-950 px-2 py-1 text-sm text-zinc-300">
            {months.map((m) => <option key={m} value={m}>{m}</option>)}
          </select>
          <Button variant="ghost" onClick={refresh} disabled={busy} title="recompute today's rows from the inventory">{busy ? "Refreshing…" : "Refresh"}</Button>
        </span>
      </div>
      {msg && <div className="text-sm text-amber-300">{msg}</div>}
      {t && (
        <div className="grid gap-3 md:grid-cols-4">
          <Stat label="Swarms" value={t.swarms} hint={`${t.running} running · ${t.parked} parked`} />
          <Stat label={`${data.month} at list`} value={usd(t.month_usd)} hint={`compute ${usd(t.compute_usd)} · volumes ${usd(t.ebs_usd)} · IPv4 ${usd(t.ip_usd)} · snapshots ${usd(t.snapshot_usd)}`} />
          <Stat label="To nudge" value={t.nudge} hint={`running, idle ≥ ${data.idle_threshold_days} days, not being parked`} />
          <Stat label="Parking" value={t.parked} hint={<>stopped by the <NavLink to="/actions?kind=swarm_park" className="text-sky-300">executor</NavLink>; volumes and address kept</>} />
        </div>
      )}
      <Card title="Per swarm">
        {!data ? <div className="text-sm text-zinc-500">Loading…</div> : !data.swarms?.length ? <Empty>No swarm cost rows for {data.month}. Swarms are EC2 instances named like "swarm"; the daily refresh writes one row per box.</Empty> : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead><tr>
                <Th>Swarm</Th><Th>State</Th><Th>Type</Th>
                <Th className="text-right">Compute</Th><Th className="text-right">Volumes</Th><Th className="text-right">IPv4</Th><Th className="text-right">Snapshots</Th><Th className="text-right">Now / month</Th><Th className="text-right">{data.month}</Th>
                <Th>Last use</Th><Th className="text-right">Idle</Th><Th>Ask?</Th>
              </tr></thead>
              <tbody>
                {data.swarms.map((s: any) => (
                  <tr key={s.instance_id} className={`border-t border-zinc-800 ${s.nudge ? "bg-amber-950/20" : ""}`}>
                    <Td><div className="text-zinc-200">{s.name || s.instance_id}</div><div className="font-mono text-[11px] text-zinc-500">{s.instance_id}</div></Td>
                    <Td><span className={s.state === "running" ? "text-emerald-300" : "text-zinc-400"}>{s.state || "?"}</span>{s.parked && <span className="ml-1"><Badge>parked</Badge></span>}{s.parking_proposed && <span className="ml-1 text-[11px] text-sky-300" title="the executor proposed to park it">parking proposed</span>}</Td>
                    <Td className="font-mono text-xs text-zinc-400">{s.instance_type || "—"}</Td>
                    <Td className="text-right">{usd(s.compute_usd)}</Td>
                    <Td className="text-right">{usd(s.ebs_usd)}</Td>
                    <Td className="text-right">{usd(s.ip_usd)}</Td>
                    <Td className="text-right">{s.snapshot_usd == null ? <span className="text-zinc-600" title="Steampipe did not answer">?</span> : usd(s.snapshot_usd)}</Td>
                    <Td className="text-right text-zinc-200">{usd(s.total_usd)}</Td>
                    <Td className="text-right text-zinc-200"><span title={`mean of ${s.days_sampled} daily figure(s)`}>{usd(s.month_usd)}</span></Td>
                    <Td className="text-xs text-zinc-400">{s.last_use_at ? when(s.last_use_at) : <span className="text-zinc-600">no signal</span>}</Td>
                    <Td className="text-right">{s.idle_days == null ? "—" : `${s.idle_days} d`}</Td>
                    <Td>{s.nudge ? <span className="text-amber-300" title="running, nobody has used it for the parking threshold, and the executor is not parking it">nudge</span> : ""}</Td>
                  </tr>
                ))}
                <tr className="border-t border-zinc-700 font-medium text-zinc-200">
                  <Td>Total</Td><Td>{t.running} running</Td><Td></Td>
                  <Td className="text-right">{usd(t.compute_usd)}</Td><Td className="text-right">{usd(t.ebs_usd)}</Td><Td className="text-right">{usd(t.ip_usd)}</Td><Td className="text-right">{usd(t.snapshot_usd)}</Td>
                  <Td className="text-right">{usd(data.swarms.reduce((a: number, s: any) => a + s.total_usd, 0))}</Td><Td className="text-right">{usd(t.month_usd)}</Td>
                  <Td></Td><Td></Td><Td>{t.nudge ? `${t.nudge} to ask` : ""}</Td>
                </tr>
              </tbody>
            </table>
          </div>
        )}
        {data && <div className="mt-3 text-xs text-zinc-500">{data.estimate_note} "Now / month" is today's rate; the month column is the mean of the month's daily figures. Last use and idle days come from the probe's daily roll-ups; a swarm never probed shows no signal. Parking follows the <code className="text-zinc-400">advisor:park=auto</code> tag (Auto-actions).</div>}
      </Card>
    </div>
  );
}

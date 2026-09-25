import { Fragment, useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api, when } from "../api";
import { Badge, Button, Card, Empty, Pager, Td, Th } from "../components/ui";
import { IncidentSummary, IncidentView, InvestigateButton, incidentOfAlertRow, pct } from "../components/incident";
import { TriageLine, triageOfAlertRow } from "../components/jev";
import { alertLevel } from "../alertLevel";

const FILTERS = ["open", "acknowledged", "all"];
const PAGE_SIZE = 10;
const gb = (b: number | null | undefined) => (b == null ? "—" : `${(Number(b) / 1e9).toFixed(2)} GB`);

/** The parsed details of one alert: NAT figures with the top receivers table, or the state change. */
function Details({ alert }: { alert: any }) {
  let d: any = {};
  try { d = JSON.parse(alert.details || "{}"); } catch { /* shown raw below */ }
  if (alert.kind === "nat_traffic") {
    return (
      <div className="space-y-2 text-sm">
        <div className="flex flex-wrap gap-x-4 gap-y-0.5 text-xs text-zinc-400">
          <span>hour <span className="text-zinc-200">{gb(d.bytes_hour)}</span> (in {gb(d.in)}, out {gb(d.out)})</span>
          {d.baseline ? <span>typical for this hour <span className="text-zinc-200">{gb(d.baseline.expected)}</span> ({d.baseline.ratio?.toFixed(1)}×, p95 {gb(d.baseline.p95)}, median {gb(d.baseline.median)} over {d.baseline.days} days{d.baseline.basis === "median" ? ", no hourly profile yet" : ""})</span>
            : <span>baseline <span className="text-zinc-200">{gb(d.baseline_avg)}</span> over {d.baseline_samples ?? "?"} samples</span>}
          {d.vpc_id && <span>VPC <span className="font-mono text-zinc-200">{d.vpc_id}</span></span>}
          {d.region && <span>{d.region}</span>}
        </div>
        {Array.isArray(d.top_receivers) && d.top_receivers.length > 0 ? (
          <table className="w-full text-xs">
            <thead><tr><Th>Instance</Th><Th>Private IP</Th><Th className="text-right">In</Th><Th className="text-right">Out</Th></tr></thead>
            <tbody>
              {d.top_receivers.map((r: any) => (
                <tr key={r.instance_id} className="border-t border-zinc-800/60">
                  <Td className="!py-1">{r.name || r.instance_id}<div className="font-mono text-[11px] text-zinc-500">{r.instance_id}</div></Td>
                  <Td className="!py-1 font-mono">{r.private_ip || "—"}</Td>
                  <Td className="!py-1 text-right">{gb(r.bytes_in)}</Td><Td className="!py-1 text-right">{gb(r.bytes_out)}</Td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : <div className="text-xs text-zinc-500">No receiver attribution stored for this alert (instances under 100 MB in the hour are dropped). An investigation attributes it again.</div>}
      </div>
    );
  }
  if (alert.kind === "instance_state") {
    return <div className="text-xs text-zinc-400">{d.name || alert.resource} · {d.type} · {d.region} · {d.from ?? "new"} → {d.to ?? "gone"}</div>;
  }
  if (d?.summary) return <div className="space-y-1 text-sm"><div className="text-zinc-200">{d.summary}</div><div className="text-xs text-zinc-500">From the daily review of the collected statistics (probes, roll-ups, baselines).</div></div>;
  return <pre className="max-h-40 overflow-auto rounded bg-zinc-950 p-2 text-xs">{alert.details}</pre>;
}

export default function Alerts() {
  const [params, setParams] = useSearchParams();
  const filter = FILTERS.includes(params.get("status") || "") ? params.get("status")! : "open";
  const kind = params.get("kind") || "";
  const page = Math.max(1, Number(params.get("page")) || 1);
  const selectedId = params.get("id");
  // A deep link carries an id and no page: the server answers with the page that holds that alert.
  const pageQuery = params.get("page") ? `page=${page}` : selectedId ? `id=${encodeURIComponent(selectedId)}` : "page=1";
  const [data, setData] = useState<{ total: number; page: number; page_size: number; counts: Record<string, number>; kinds: Record<string, number>; alerts: any[] } | null>(null);
  const [settings, setSettings] = useState<any>(null);
  const [notify, setNotify] = useState<any>(null);
  useEffect(() => { api("/notify/status").then(setNotify).catch(() => setNotify(null)); }, []);
  const [incident, setIncident] = useState<any>(null);
  const [busy, setBusy] = useState<number | null>(null); // the alert whose investigation is being started
  const [err, setErr] = useState("");
  const rows = data?.alerts ?? null;

  const load = () => api(`/alerts?status=${filter}${kind ? `&kind=${encodeURIComponent(kind)}` : ""}&${pageQuery}&page_size=${PAGE_SIZE}`).then(setData).catch((e) => { setErr(e.message); setData({ total: 0, page: 1, page_size: PAGE_SIZE, counts: {}, kinds: {}, alerts: [] }); });
  const [sending, setSending] = useState<number | null>(null);
  // Sends one alert to the Sphinx chat by hand, whatever the rules say; the receipt shows on the row.
  const sendNow = async (id: number) => { setSending(id); setErr(""); try { await api(`/alerts/${id}/notify`, { method: "POST", body: "{}" }); } catch (e: any) { setErr(e.message); } finally { setSending(null); load(); } };
  const loadIncident = () => { if (!selectedId) { setIncident(null); return; } api(`/alerts/${selectedId}/incident`).then(setIncident).catch(() => setIncident(null)); };
  useEffect(() => { api("/settings").then(setSettings).catch(() => {}); }, []);
  useEffect(() => { load(); }, [filter, kind, pageQuery]);
  useEffect(() => { loadIncident(); }, [selectedId, rows]);
  // Once the page holding the linked alert is on screen, bring its row into view.
  useEffect(() => { if (selectedId && rows) document.getElementById(`alert-${selectedId}`)?.scrollIntoView({ block: "nearest" }); }, [selectedId, rows]);
  // While an investigation is running, refresh so the webhook's result shows up without a reload.
  useEffect(() => {
    if (!rows?.some((r) => r.incident_status === "pending")) return;
    const t = setInterval(load, 10000);
    return () => clearInterval(t);
  }, [rows]);

  const set = (k: string, v: string | null) => { const p = new URLSearchParams(params); v ? p.set(k, v) : p.delete(k); if (k === "status" || k === "kind") p.delete("page"); setParams(p); };
  // Expands or collapses a row. Once the page was resolved from a deep link's id, it is written to the URL here, so
  // collapsing the linked row (or a refresh after that) stays on this page instead of falling back to page 1.
  const toggle = (id: number) => {
    const p = new URLSearchParams(params);
    String(id) === selectedId ? p.delete("id") : p.set("id", String(id));
    if (!p.get("page") && data) p.set("page", String(data.page));
    setParams(p);
  };
  const investigate = async (id: number, force = false) => {
    setBusy(id); setErr("");
    try { await api(`/alerts/${id}/investigate${force ? "?force=1" : ""}`, { method: "POST" }); await load(); }
    catch (e: any) { setErr(e.message); }
    finally { setBusy(null); }
  };
  const ack = async (id: number) => { try { await api(`/alerts/${id}/ack`, { method: "POST" }); load(); } catch (e: any) { setErr(e.message); } };
  const reopen = async (id: number) => { try { await api(`/alerts/${id}/reopen`, { method: "POST" }); load(); } catch (e: any) { setErr(e.message); } };
  const poll = async (requestId: string) => {
    setErr("");
    try { const r = await api(`/agent-runs/${requestId}/poll`, { method: "POST" }); setErr(`agent status: ${r.status}${r.imported != null ? `, ${r.imported} fixes imported` : ""}`); load(); }
    catch (e: any) { setErr(e.message); }
  };

  const canInvestigate = Boolean(settings?.agent?.configured) && settings?.schedule?.alertInvestigate !== "off";
  const selected = rows?.find((r) => String(r.id) === selectedId);
  const shownIncident: IncidentSummary | null = incident
    ? { id: incident.id, status: incident.status, cause: incident.cause, confidence: incident.confidence, episode_cost_usd: incident.episode_cost_usd, monthly_run_rate_usd: incident.monthly_run_rate_usd, fixes: incident.fixes || [], error: incident.error }
    : selected ? incidentOfAlertRow(selected) : null;
  const counts = data?.counts || {};
  // The kinds in scope (status and day, before the kind filter), so the picked kind stays listed with the others.
  const kinds = Object.entries(data?.kinds || {});
  if (kind && !kinds.some(([k]) => k === kind)) kinds.push([kind, 0]);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h1 className="flex flex-wrap items-center gap-2 text-xl font-semibold text-zinc-100">Alerts {data && <span className="text-sm font-normal text-zinc-500">{data.total}</span>}
            {data && (["alarm", "warning", "info"] as const).filter((l) => counts[l] > 0).map((l) => <span key={l} className="flex items-center gap-1 text-sm font-normal text-zinc-400"><Badge>{l}</Badge>{counts[l]}</span>)}
          </h1>
          <div className="text-sm text-zinc-500">Raised by the watcher ({settings?.schedule?.watchCron ? <>cron <code className="text-zinc-300">{settings.schedule.watchCron}</code></> : "WATCH_CRON off"}); NAT alerts are {settings?.schedule?.alertInvestigate === "auto" ? "investigated automatically" : settings?.schedule?.alertInvestigate === "manual" ? "investigated on request" : "not investigated"} (ALERT_INVESTIGATE={settings?.schedule?.alertInvestigate || "…"}).{settings?.jev?.enabled ? " Jev triages every new NAT and instance alert: routine ones are acknowledged for you (undo any time), unexpected ones go to the agent." : ""} Today first, then older days; alarms before warnings before info.</div>
        </div>
        <div className="flex items-center gap-2">
          <select value={kind} onChange={(e) => { set("kind", e.target.value || null); }} title="Only alerts of one kind">
            <option value="">all kinds</option>
            {kinds.map(([k, n]) => <option key={k} value={k}>{k} · {n}</option>)}
          </select>
          <select value={filter} onChange={(e) => { set("status", e.target.value); }}>
            {FILTERS.map((f) => <option key={f} value={f}>{f}</option>)}
          </select>
        </div>
      </div>
      {err && <div className="text-sm text-zinc-400">{err}</div>}
      {!rows ? <Empty>Loading…</Empty> : rows.length === 0 ? <Empty>No {filter === "all" ? "" : filter + " "}{kind ? `${kind} ` : ""}alerts{data && data.total > 0 ? " on this page" : ""}.</Empty> : (
        <table className="w-full border-collapse overflow-hidden rounded-lg border border-zinc-800">
          <thead className="bg-zinc-900"><tr><Th>When</Th><Th>Kind</Th><Th>Alert</Th><Th>Investigation</Th><Th /></tr></thead>
          <tbody>
            {rows.map((a) => {
              const inc = incidentOfAlertRow(a);
              const triage = triageOfAlertRow(a);
              const open = String(a.id) === selectedId;
              return (
                <Fragment key={a.id}>
                  <tr id={`alert-${a.id}`} onClick={() => toggle(a.id)} className={`cursor-pointer border-t border-zinc-800 hover:bg-zinc-900/60 ${open ? "bg-zinc-900" : ""}`}>
                    <Td className="whitespace-nowrap text-zinc-400">{when(a.created_at)}</Td>
                    <Td><Badge>{alertLevel(a)}</Badge><div className="mt-0.5 text-xs text-zinc-500"><button className={`hover:text-zinc-300 ${kind === a.kind ? "text-zinc-300 underline" : ""}`} title={kind === a.kind ? "Show every kind" : `Only ${a.kind} alerts`} onClick={(e) => { e.stopPropagation(); set("kind", kind === a.kind ? null : a.kind); }}>{a.kind}</button></div></Td>
                    <Td>
                      <div className={open ? "" : "line-clamp-2"}>{a.message}</div>
                      <div className="font-mono text-xs text-zinc-500">{a.resource}{a.acknowledged ? ` · acknowledged${a.acknowledged_by ? ` by ${a.acknowledged_by}` : ""}` : ""}</div>
                      {triage && <div className="mt-0.5" onClick={(e) => e.stopPropagation()}><TriageLine alert={a} triage={triage} onUndo={() => reopen(a.id)} /></div>}
                      {a.notify_result && <div className={`mt-0.5 text-xs ${a.notify_result === "sent" ? "text-emerald-300" : a.notify_result.startsWith("failed") ? "text-red-300" : "text-zinc-500"}`}>{a.notify_result === "sent" ? `sent to Sphinx ${when(a.notified_at)}` : a.notify_result}</div>}
                    </Td>
                    <Td className="whitespace-nowrap">
                      {inc ? <span className="flex items-center gap-2"><Badge>{inc.status}</Badge>{inc.status === "completed" && <span className="text-xs text-zinc-400">{pct(inc.confidence)}</span>}</span> : <span className="text-xs text-zinc-500">—</span>}
                    </Td>
                    <Td className="whitespace-nowrap text-right">
                      <span className="flex justify-end gap-2" onClick={(e) => e.stopPropagation()}>
                        <InvestigateButton incident={inc} enabled={canInvestigate} busy={busy === a.id} onClick={() => investigate(a.id)} />
                        {notify?.configured && <Button variant="ghost" className="!px-2 !py-1 !text-xs" onClick={() => sendNow(a.id)} disabled={sending === a.id} title={a.notify_result === "sent" ? "Send it again" : "Send this alert to the Sphinx chat now, whatever the rules say"}>{a.notify_result === "sent" ? "Resend" : "Send to Sphinx"}</Button>}
                        {!a.acknowledged && <Button variant="ghost" className="!px-2 !py-1 !text-xs" onClick={() => ack(a.id)}>Acknowledge</Button>}
                        {a.acknowledged ? <Button variant="ghost" className="!px-2 !py-1 !text-xs" onClick={() => reopen(a.id)}>Reopen</Button> : null}
                      </span>
                    </Td>
                  </tr>
                  {open && (
                    <tr className="border-t border-zinc-800/60 bg-zinc-950/40">
                      <td colSpan={5} className="p-3">
                        <div className="grid gap-4 lg:grid-cols-[minmax(0,2fr)_minmax(0,3fr)]">
                          <Card title="Details"><Details alert={a} /></Card>
                          <Card title={<span className="flex items-center justify-between">Incident{shownIncident ? ` #${shownIncident.id}` : ""}
                            {incident?.status === "pending" && incident.request_id && <Button variant="ghost" className="!px-2 !py-1 !text-xs" onClick={() => poll(incident.request_id)}>Poll result</Button>}</span>}>
                            {!shownIncident ? (
                              <div className="text-sm text-zinc-500">{canInvestigate ? "Not investigated yet. Investigate sends the alert, its attribution, the VPC's flow-log status, the last 24 h of samples and the instances involved to the agent." : "Investigations need REPO2GRAPH_URL and ALERT_INVESTIGATE other than off."}</div>
                            ) : (
                              <div className="space-y-2">
                                <IncidentView incident={shownIncident} />
                                {incident?.status === "completed" && Array.isArray(incident.evidence) && incident.evidence.length > 0 && (
                                  <details className="text-xs" open><summary className="cursor-pointer text-zinc-500">Evidence ({incident.evidence.length})</summary>
                                    <ul className="mt-2 list-disc space-y-1.5 pl-4 leading-relaxed text-zinc-300">{incident.evidence.map((e: string, i: number) => <li key={i}>{e}</li>)}</ul></details>
                                )}
                                {incident && <div className="text-xs text-zinc-500">started {when(incident.created_at)}{incident.finished_at ? ` · finished ${when(incident.finished_at)}` : ""}{incident.request_id ? ` · request ${incident.request_id}` : ""}</div>}
                                {incident?.status === "failed" && canInvestigate && <Button variant="ghost" className="!px-2 !py-1 !text-xs" onClick={() => investigate(a.id, true)} disabled={busy != null}>Retry</Button>}
                              </div>
                            )}
                          </Card>
                        </div>
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      )}
      {data && <Pager page={data.page} pageSize={data.page_size} total={data.total} onPage={(p) => set("page", String(p))} />}
    </div>
  );
}

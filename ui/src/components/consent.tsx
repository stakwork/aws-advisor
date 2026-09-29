import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";

/** The consent switches (src/consent.ts): AdvisorAutoPark on an instance, AdvisorAutoScale on a Beanstalk environment. Each flip is a ledgered auto-action, applied at once. */
const isOn = (v: string | null | undefined) => /^(on|true|yes|1)$/i.test(String(v ?? "").trim());

function Switch({ on, busy, onChange, label }: { on: boolean; busy: boolean; onChange: (v: boolean) => void; label: string }) {
  return (
    <button type="button" role="switch" aria-checked={on} disabled={busy} onClick={() => onChange(!on)} title={label}
      className={`inline-flex items-center gap-2 rounded-full border px-2 py-0.5 text-xs ${on ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300" : "border-zinc-700 bg-zinc-900 text-zinc-400"} disabled:opacity-60`}>
      <span className={`inline-block h-3 w-6 rounded-full ${on ? "bg-emerald-500" : "bg-zinc-600"} relative`}><span className={`absolute top-0.5 h-2 w-2 rounded-full bg-zinc-100 transition-all ${on ? "left-3.5" : "left-0.5"}`} /></span>
      {busy ? "…" : on ? "ON" : "OFF"}
    </button>
  );
}

export function AutoParkSwitch({ instanceId, name, state, tags, poolKind }: { instanceId: string; name?: string | null; state: string; tags?: Record<string, string> | null; poolKind?: string | null }) {
  const [value, setValue] = useState<string | null>(tags?.AdvisorAutoPark ?? null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ text: string; err?: boolean; actionId?: number } | null>(null);
  useEffect(() => { setValue(tags?.AdvisorAutoPark ?? null); setMsg(null); }, [instanceId, tags?.AdvisorAutoPark]);
  const on = isOn(value);
  const flip = (want: boolean) => {
    setBusy(true); setMsg(null);
    api(`/inventory/ec2/${encodeURIComponent(instanceId)}/consent`, { method: "POST", body: JSON.stringify({ value: want ? "ON" : "OFF" }) })
      .then((a) => { setValue(want ? "ON" : "OFF"); setMsg({ text: `${a.status}: ${a.result || a.title}`, actionId: a.id }); })
      .catch((e) => setMsg({ text: e.message, err: true })).finally(() => setBusy(false));
  };
  const power = (action: "stop" | "start") => {
    setBusy(true); setMsg(null);
    api(`/inventory/ec2/${encodeURIComponent(instanceId)}/power`, { method: "POST", body: JSON.stringify({ action }) })
      .then((a) => setMsg({ text: `${a.status}: ${a.result || a.title}`, actionId: a.id }))
      .catch((e) => setMsg({ text: e.message, err: true })).finally(() => setBusy(false));
  };
  const handsOff = tags?.["advisor:hands-off"] != null;
  return (
    <div className="mt-2 rounded-lg border border-zinc-800 bg-zinc-950/40 p-2 text-xs">
      <div className="flex flex-wrap items-center gap-3">
        <span className="text-zinc-300">Auto-park</span>
        <Switch on={on} busy={busy || handsOff || Boolean(poolKind)} onChange={flip} label="AdvisorAutoPark: may the executor stop and start this box?" />
        <span className="text-zinc-500">{handsOff ? "tagged advisor:hands-off" : poolKind ? `member of a ${poolKind} pool: its controller decides` : on ? "the executor may stop it when idle or in its confident quiet hours, and start it before it is needed (DNS re-pointed when there is no Elastic IP)" : value ? `AdvisorAutoPark=${value}: never stopped or started by the executor` : "no AdvisorAutoPark tag: never stopped or started by the executor"}</span>
        {on && !handsOff && (
          <span className="ml-auto flex gap-1">
            <button className="rounded border border-zinc-700 px-2 py-0.5 text-zinc-200 hover:bg-zinc-800 disabled:opacity-50" disabled={busy || state !== "running"} onClick={() => power("stop")} title={state === "running" ? `stop ${name || instanceId} now` : `state ${state}`}>Stop</button>
            <button className="rounded border border-zinc-700 px-2 py-0.5 text-zinc-200 hover:bg-zinc-800 disabled:opacity-50" disabled={busy || state !== "stopped"} onClick={() => power("start")} title={state === "stopped" ? `start ${name || instanceId} now` : `state ${state}`}>Start</button>
          </span>
        )}
      </div>
      {msg && <div className={`mt-1 ${msg.err ? "text-red-300" : "text-zinc-400"}`}>{msg.text}{msg.actionId ? <> · <Link className="text-sky-300 hover:underline" to={`/actions?id=${msg.actionId}`}>row #{msg.actionId}</Link></> : null}</div>}
    </div>
  );
}

export function AutoScaleSwitch({ env, region, accountId }: { env: string; region?: string | null; accountId?: string | null }) {
  const [state, setState] = useState<{ on: boolean; consent: string | null; band: string | null; operations_role: string | null; status: string | null } | null | undefined>(undefined);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ text: string; err?: boolean; actionId?: number } | null>(null);
  const qs = new URLSearchParams(); if (region) qs.set("region", region); if (accountId) qs.set("account_id", accountId);
  useEffect(() => { setState(undefined); setMsg(null); api(`/inventory/beanstalk/${encodeURIComponent(env)}/consent?${qs}`).then(setState).catch((e) => { setState(null); setMsg({ text: e.message, err: true }); }); }, [env, region, accountId]);
  const flip = (want: boolean) => {
    setBusy(true); setMsg(null);
    api(`/inventory/beanstalk/${encodeURIComponent(env)}/consent`, { method: "POST", body: JSON.stringify({ value: want ? "ON" : "OFF", region, account_id: accountId }) })
      .then((a) => { setState((s) => (s ? { ...s, on: want, consent: want ? "ON" : "OFF" } : s)); setMsg({ text: `${a.status}: ${a.result || a.title}`, actionId: a.id }); })
      .catch((e) => setMsg({ text: e.message, err: true })).finally(() => setBusy(false));
  };
  return (
    <div className="mt-2 rounded-lg border border-zinc-800 bg-zinc-950/40 p-2 text-xs">
      <div className="flex flex-wrap items-center gap-3">
        <span className="text-zinc-300">Auto-scale</span>
        {state === undefined ? <span className="text-zinc-500">reading the environment…</span> : state === null ? <span className="text-zinc-500">environment not readable</span> : (
          <>
            <Switch on={state.on} busy={busy} onChange={flip} label="AdvisorAutoScale: may the executor move this environment's MinSize and MaxSize?" />
            <span className="text-zinc-500">{state.on ? `the capacity action may move the bounds within ${state.band ? `AdvisorScaleBand=${state.band}` : "floor 1 and the current maximum (add AdvisorScaleBand=<floor>-<ceiling> for more room)"}` : state.consent ? `AdvisorAutoScale=${state.consent}: left alone` : "no AdvisorAutoScale tag: left alone"}{state.operations_role ? "" : " · no operations role on the environment (the README says how to attach one; without it the update needs wider rights)"}</span>
          </>
        )}
      </div>
      {msg && <div className={`mt-1 ${msg.err ? "text-red-300" : "text-zinc-400"}`}>{msg.text}{msg.actionId ? <> · <Link className="text-sky-300 hover:underline" to={`/actions?id=${msg.actionId}`}>row #{msg.actionId}</Link></> : null}</div>}
    </div>
  );
}

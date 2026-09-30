import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";

/** The consent switches (src/consent.ts): AdvisorAutoPark on an instance, AdvisorAutoScale on a Beanstalk environment. Each flip is a ledgered auto-action, applied at once. */
const isOn = (v: string | null | undefined) => /^(on|true|yes|1)$/i.test(String(v ?? "").trim());
/** What a ledger row says after a click: its result, or on a failed or refused row the error the actuator hit. */
const rowMsg = (a: { id: number; status: string; title: string; result?: string | null; error?: string | null }) => ({ text: `${a.status}: ${(a.status === "failed" || a.status === "refused") && a.error ? a.error : a.result || a.title}`, err: a.status === "failed" || a.status === "refused", actionId: a.id, status: a.status });

function Switch({ on, busy, onChange, label }: { on: boolean; busy: boolean; onChange: (v: boolean) => void; label: string }) {
  return (
    <button type="button" role="switch" aria-checked={on} disabled={busy} onClick={() => onChange(!on)} title={label}
      className={`inline-flex items-center gap-2 rounded-full border px-2 py-0.5 text-xs ${on ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300" : "border-zinc-700 bg-zinc-900 text-zinc-400"} disabled:opacity-60`}>
      <span className={`inline-block h-3 w-6 rounded-full ${on ? "bg-emerald-500" : "bg-zinc-600"} relative`}><span className={`absolute top-0.5 h-2 w-2 rounded-full bg-zinc-100 transition-all ${on ? "left-3.5" : "left-0.5"}`} /></span>
      {busy ? "…" : on ? "ON" : "OFF"}
    </button>
  );
}

/**
 * A consent row done with the person's own temporary credentials (POST /actions/:id/as-person): Beanstalk applies a tag
 * as an environment update under the caller's rights, which the narrow actuator lacks. The credentials are used for that
 * one call and forgotten; the ledger records who. Long-lived keys are refused server-side.
 */
export function RunAsMe({ actionId, verb = "apply", onDone, compact }: { actionId: number; verb?: "apply" | "revert"; onDone?: (row: any) => void; compact?: boolean }) {
  const [open, setOpen] = useState(false);
  const [key, setKey] = useState(""); const [secret, setSecret] = useState(""); const [token, setToken] = useState("");
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<{ text: string; err?: boolean } | null>(null);
  const submit = () => {
    setBusy(true); setNote(null);
    api(`/actions/${actionId}/as-person`, { method: "POST", body: JSON.stringify({ verb, credentials: { access_key_id: key, secret_access_key: secret, session_token: token } }) })
      .then((row) => { setKey(""); setSecret(""); setToken(""); setNote({ text: `${row.status}: ${(row.status === "failed" && row.error) || row.result || row.title}`, err: row.status === "failed" }); if (row.status !== "failed") setOpen(false); onDone?.(row); })
      .catch((e) => setNote({ text: e.message, err: true })).finally(() => setBusy(false));
  };
  const field = (v: string, set: (x: string) => void, label: string, secretField = false) => (
    <input type={secretField ? "password" : "text"} value={v} disabled={busy} onChange={(e) => set(e.target.value)} placeholder={label} aria-label={label} autoComplete="off" spellCheck={false}
      className="w-full rounded border border-zinc-700 bg-zinc-900 px-2 py-1 font-mono text-xs text-zinc-200 disabled:opacity-60" />
  );
  return (
    <div className={compact ? "inline" : "mt-1"}>
      <button type="button" className="text-sky-300 hover:underline" onClick={() => setOpen((o) => !o)} title="do this one row with temporary credentials of your own (the actuator cannot: Beanstalk applies a tag as an environment update under the caller's rights); used once, never stored">
        {open ? "cancel" : verb === "revert" ? "undo as me" : "run as me"}
      </button>
      {open && (
        <div className="mt-1 max-w-xl space-y-1 rounded border border-zinc-800 bg-zinc-950/60 p-2 text-xs">
          <div className="text-zinc-400">Temporary credentials of your own, for this one call. From the console's "Command line or programmatic access", from SSO, or <span className="font-mono">aws sts get-session-token --duration-seconds 900</span>. Long-lived keys (AKIA…) are refused. Nothing is stored; the row records who.</div>
          {field(key, setKey, "AWS_ACCESS_KEY_ID (ASIA…)")}
          {field(secret, setSecret, "AWS_SECRET_ACCESS_KEY", true)}
          {field(token, setToken, "AWS_SESSION_TOKEN", true)}
          <div className="flex items-center gap-2">
            <button type="button" disabled={busy || !key || !secret || !token} onClick={submit} className="rounded border border-zinc-700 px-2 py-0.5 text-zinc-200 hover:bg-zinc-800 disabled:opacity-50">{busy ? "…" : verb === "revert" ? "Undo with these" : "Apply with these"}</button>
            {note && <span className={note.err ? "text-red-300" : "text-zinc-400"}>{note.text}</span>}
          </div>
        </div>
      )}
    </div>
  );
}

export function AutoParkSwitch({ instanceId, name, state, tags, poolKind }: { instanceId: string; name?: string | null; state: string; tags?: Record<string, string> | null; poolKind?: string | null }) {
  const [value, setValue] = useState<string | null>(tags?.AdvisorAutoPark ?? null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ text: string; err?: boolean; actionId?: number; status?: string } | null>(null);
  useEffect(() => { setValue(tags?.AdvisorAutoPark ?? null); setMsg(null); }, [instanceId, tags?.AdvisorAutoPark]);
  const on = isOn(value);
  const flip = (want: boolean) => {
    setBusy(true); setMsg(null);
    api(`/inventory/ec2/${encodeURIComponent(instanceId)}/consent`, { method: "POST", body: JSON.stringify({ value: want ? "ON" : "OFF" }) })
      .then((a) => { setValue(want ? "ON" : "OFF"); setMsg(rowMsg(a)); })
      .catch((e) => setMsg({ text: e.message, err: true })).finally(() => setBusy(false));
  };
  const power = (action: "stop" | "start") => {
    setBusy(true); setMsg(null);
    api(`/inventory/ec2/${encodeURIComponent(instanceId)}/power`, { method: "POST", body: JSON.stringify({ action }) })
      .then((a) => setMsg(rowMsg(a)))
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
      {msg?.actionId && msg.status !== "verified" ? <RunAsMe actionId={msg.actionId} onDone={(row) => { if (row.status !== "failed") { setMsg({ text: `${row.status}: ${row.result || row.title}`, actionId: row.id, status: row.status }); setValue(row.after?.AdvisorAutoPark ?? null); } }} /> : null}
    </div>
  );
}

export function AutoScaleSwitch({ env, region, accountId }: { env: string; region?: string | null; accountId?: string | null }) {
  const [state, setState] = useState<{ on: boolean; consent: string | null; band: string | null; floor: number | null; ceiling: number | null; operations_role: string | null; status: string | null } | null | undefined>(undefined);
  const [floor, setFloor] = useState(""); const [ceiling, setCeiling] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ text: string; err?: boolean; actionId?: number; status?: string } | null>(null);
  const qs = new URLSearchParams(); if (region) qs.set("region", region); if (accountId) qs.set("account_id", accountId);
  const [readErr, setReadErr] = useState("");
  // What the environment carries is read from AWS, never assumed: after a flip (whether the call succeeded, timed out
  // on the way back, or was refused because the tag is already there) the switch re-reads it, so the page shows the tag as it is.
  const read = () => api(`/inventory/beanstalk/${encodeURIComponent(env)}/consent?${qs}`).then((s) => { setState(s); setFloor(s.floor == null ? "" : String(s.floor)); setCeiling(s.ceiling == null ? "" : String(s.ceiling)); setReadErr(""); }).catch((e) => { setState(null); setReadErr(e.message); });
  useEffect(() => { setState(undefined); setMsg(null); setReadErr(""); read(); }, [env, region, accountId]);
  const flip = (want: boolean) => {
    setBusy(true); setMsg(null);
    api(`/inventory/beanstalk/${encodeURIComponent(env)}/consent`, { method: "POST", body: JSON.stringify({ value: want ? "ON" : "OFF", region, account_id: accountId }) })
      .then((a) => setMsg(rowMsg(a)))
      .catch((e) => setMsg({ text: e.message, err: true }))
      .finally(() => read().finally(() => setBusy(false)));
  };
  // The band: the bare minimum and the ceiling, written as AdvisorScaleBand through the same ledgered action; empty both to remove it.
  const bandDirty = state ? floor !== (state.floor == null ? "" : String(state.floor)) || ceiling !== (state.ceiling == null ? "" : String(state.ceiling)) : false;
  const saveBand = () => {
    setBusy(true); setMsg(null);
    api(`/inventory/beanstalk/${encodeURIComponent(env)}/band`, { method: "POST", body: JSON.stringify({ floor: floor === "" ? null : Number(floor), ceiling: ceiling === "" ? null : Number(ceiling), region, account_id: accountId }) })
      .then((a) => setMsg(rowMsg(a)))
      .catch((e) => setMsg({ text: e.message, err: true }))
      .finally(() => read().finally(() => setBusy(false)));
  };
  const numInput = (value: string, set: (v: string) => void, label: string) => (
    <input type="number" min={1} max={999} value={value} disabled={busy} onChange={(e) => set(e.target.value)} placeholder="–" title={label} aria-label={label}
      className="w-12 rounded border border-zinc-700 bg-zinc-900 px-1 py-0.5 text-center text-xs text-zinc-200 disabled:opacity-60" />
  );
  return (
    <div className="mt-2 rounded-lg border border-zinc-800 bg-zinc-950/40 p-2 text-xs">
      <div className="flex flex-wrap items-center gap-3">
        <span className="text-zinc-300">Auto-scale</span>
        {state === undefined ? <span className="text-zinc-500">reading the environment…</span> : state === null ? <span className="text-amber-300/90">{readErr || "environment not readable"}</span> : (
          <>
            <Switch on={state.on} busy={busy} onChange={flip} label="AdvisorAutoScale: may the executor move this environment's MinSize and MaxSize?" />
            <span className="text-zinc-500">{state.on ? `the capacity action may move the bounds within ${state.band ? `AdvisorScaleBand=${state.band}` : "floor 1 and the current maximum (set a band below for more room)"}` : state.consent ? `AdvisorAutoScale=${state.consent}: left alone` : "no AdvisorAutoScale tag: left alone"}{state.operations_role ? "" : " · no operations role on the environment (the README says how to attach one; without it the update needs wider rights)"}</span>
          </>
        )}
      </div>
      {state && (
        <div className="mt-1.5 flex flex-wrap items-center gap-2">
          <span className="text-zinc-300">Band</span>
          <span className="text-zinc-500">bare minimum</span>{numInput(floor, setFloor, "AdvisorScaleBand floor: MinSize never goes below this")}
          <span className="text-zinc-500">ceiling</span>{numInput(ceiling, setCeiling, "AdvisorScaleBand ceiling: MaxSize never goes above this")}
          <button type="button" disabled={busy || !bandDirty} onClick={saveBand} className="rounded border border-zinc-700 px-2 py-0.5 text-zinc-200 hover:bg-zinc-800 disabled:opacity-50" title="write AdvisorScaleBand=<floor>-<ceiling> on the environment (a ledgered row, Revert puts the old value back); empty both fields to remove the band">{busy ? "…" : "Save"}</button>
          <span className="text-zinc-500">{state.band ? `AdvisorScaleBand=${state.band}: the executor keeps MinSize at or above ${state.floor} and MaxSize at or below ${state.ceiling}; the learned minimum per hour and the pressure raise move between them` : "no band: floor 1, the ceiling never moves and pressure at the ceiling cannot be answered"}</span>
        </div>
      )}
      {msg && <div className={`mt-1 ${msg.err ? "text-red-300" : "text-zinc-400"}`}>{msg.text}{msg.actionId ? <> · <Link className="text-sky-300 hover:underline" to={`/actions?id=${msg.actionId}`}>row #{msg.actionId}</Link></> : null}</div>}
      {msg?.actionId && msg.status !== "verified" ? <RunAsMe actionId={msg.actionId} onDone={(row) => { if (row.status !== "failed") { setMsg({ text: `${row.status}: ${row.result || row.title}`, actionId: row.id, status: row.status }); read(); } }} /> : null}
    </div>
  );
}

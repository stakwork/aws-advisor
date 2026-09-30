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
      <button type="button" className="text-sky-300 hover:underline" onClick={() => setOpen((o) => !o)} title="do this one row with temporary credentials of your own: you authorise this change, the row records who; used once, never stored">
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

type ScaleState = { on: boolean; consent: string | null; band: string | null; floor: number | null; ceiling: number | null; operations_role: string | null; status: string | null };
/** How long the switch keeps re-reading the environment for a tag it just wrote: Beanstalk lands it as an environment update, a minute or two. */
const SETTLE_MS = 3 * 60_000;
const POLL_MS = 5_000;

export function AutoScaleSwitch({ env, region, accountId }: { env: string; region?: string | null; accountId?: string | null }) {
  const [state, setState] = useState<ScaleState | null | undefined>(undefined);
  const [floor, setFloor] = useState(""); const [ceiling, setCeiling] = useState("");
  // what was just asked for, until the environment reads it back (or the wait runs out)
  const [pending, setPending] = useState<{ on?: boolean; band?: string | null; since: number; what: string } | null>(null);
  const [tick, setTick] = useState(0);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ text: string; err?: boolean; actionId?: number; status?: string } | null>(null);
  const qs = new URLSearchParams(); if (region) qs.set("region", region); if (accountId) qs.set("account_id", accountId);
  const [readErr, setReadErr] = useState("");
  // What the environment carries is read from AWS, never assumed: after a flip (whether the call succeeded, timed out
  // on the way back, or was refused because the tag is already there) the switch re-reads it, so the page shows the tag as it is.
  const read = (): Promise<ScaleState | null> => api(`/inventory/beanstalk/${encodeURIComponent(env)}/consent?${qs}`).then((s: ScaleState) => { setState(s); setFloor(s.floor == null ? "" : String(s.floor)); setCeiling(s.ceiling == null ? "" : String(s.ceiling)); setReadErr(""); return s; }).catch((e) => { setState(null); setReadErr(e.message); return null; });
  useEffect(() => { setState(undefined); setMsg(null); setReadErr(""); setPending(null); read(); }, [env, region, accountId]);
  // while a write is landing: re-read every few seconds until the environment shows it, then stop
  const landed = (s: ScaleState | null, p: NonNullable<typeof pending>) => Boolean(s) && (p.on === undefined || s!.on === p.on) && (p.band === undefined || (s!.band ?? null) === (p.band ?? null));
  useEffect(() => {
    if (!pending) return;
    if (Date.now() - pending.since > SETTLE_MS) { setPending(null); setMsg((m) => ({ ...(m ?? { text: "" }), text: `${m?.text ?? ""} · the environment still does not show it after ${Math.round(SETTLE_MS / 60000)} minutes: check the row and the environment's events` })); return; }
    const t = setTimeout(() => { read().then((s) => { if (landed(s, pending)) setPending(null); else setTick((n) => n + 1); }); }, POLL_MS);
    return () => clearTimeout(t);
  }, [pending, tick]);
  const waitFor = (what: string, want: { on?: boolean; band?: string | null }) => setPending({ ...want, since: Date.now(), what });
  const flip = (want: boolean) => {
    setBusy(true); setMsg(null); setPending(null);
    api(`/inventory/beanstalk/${encodeURIComponent(env)}/consent`, { method: "POST", body: JSON.stringify({ value: want ? "ON" : "OFF", region, account_id: accountId }) })
      .then((a) => { setMsg(rowMsg(a)); if (a.status !== "failed" && a.status !== "refused") waitFor(`AdvisorAutoScale=${want ? "ON" : "OFF"}`, { on: want }); })
      .catch((e) => setMsg({ text: e.message, err: true }))
      .finally(() => read().then((s) => { if (s && pending && landed(s, pending)) setPending(null); }).finally(() => setBusy(false)));
  };
  // The band: the bare minimum and the ceiling, written as AdvisorScaleBand through the same ledgered action; empty both to remove it.
  const bandDirty = state ? floor !== (state.floor == null ? "" : String(state.floor)) || ceiling !== (state.ceiling == null ? "" : String(state.ceiling)) : false;
  const saveBand = () => {
    setBusy(true); setMsg(null); setPending(null);
    const want = floor === "" && ceiling === "" ? null : `${floor}-${ceiling}`;
    api(`/inventory/beanstalk/${encodeURIComponent(env)}/band`, { method: "POST", body: JSON.stringify({ floor: floor === "" ? null : Number(floor), ceiling: ceiling === "" ? null : Number(ceiling), region, account_id: accountId }) })
      .then((a) => { setMsg(rowMsg(a)); if (a.status !== "failed" && a.status !== "refused") waitFor(want ? `AdvisorScaleBand=${want}` : "the band removed", { band: want }); })
      .catch((e) => setMsg({ text: e.message, err: true }))
      .finally(() => read().finally(() => setBusy(false)));
  };
  const numInput = (value: string, set: (v: string) => void, label: string) => (
    <input type="number" min={1} max={999} value={value} disabled={busy} onChange={(e) => set(e.target.value)} placeholder="–" title={label} aria-label={label}
      className="w-12 rounded border border-zinc-700 bg-zinc-900 px-1 py-0.5 text-center text-xs text-zinc-200 disabled:opacity-60" />
  );
  const progress = busy
    ? "writing the tag… Beanstalk applies it as an environment update and reads it back, up to fifteen seconds"
    : pending ? `waiting for the environment to show ${pending.what} (${Math.round((Date.now() - pending.since) / 1000)} s; an environment update takes a minute or two)` : null;
  return (
    <div className="mt-2 rounded-lg border border-zinc-800 bg-zinc-950/40 p-2 text-xs">
      {progress && (
        <div className="mb-2">
          <div className="h-1 w-full overflow-hidden rounded bg-zinc-800"><div className="h-full w-1/3 animate-pulse rounded bg-sky-500/70" style={{ animation: "consent-slide 1.4s linear infinite" }} /></div>
          <div className="mt-1 text-zinc-400">{progress}</div>
          <style>{`@keyframes consent-slide { from { transform: translateX(-100%) } to { transform: translateX(300%) } }`}</style>
        </div>
      )}
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
      {state && !pending && <ScalingTimeline env={env} region={region} accountId={accountId} state={state} />}
      {msg && <div className={`mt-1 ${msg.err ? "text-red-300" : "text-zinc-400"}`}>{msg.text}{msg.actionId ? <> · <Link className="text-sky-300 hover:underline" to={`/actions?id=${msg.actionId}`}>row #{msg.actionId}</Link></> : null}</div>}
      {msg?.actionId && msg.status !== "verified" ? <RunAsMe actionId={msg.actionId} onDone={(row) => { if (row.status !== "failed") { setMsg({ text: `${row.status}: ${row.result || row.title}`, actionId: row.id, status: row.status }); const after = row.after || {}; if ("AdvisorAutoScale" in after) waitFor(`AdvisorAutoScale=${after.AdvisorAutoScale ?? "(removed)"}`, { on: isOn(after.AdvisorAutoScale) }); else if ("AdvisorScaleBand" in after) waitFor(after.AdvisorScaleBand ? `AdvisorScaleBand=${after.AdvisorScaleBand}` : "the band removed", { band: after.AdvisorScaleBand ?? null }); read(); } }} /> : null}
    </div>
  );
}

/** "2026-09-30T14:00:00.000Z" → "14:00"; with the day when it is not today (UTC). */
const hhmm = (iso: string | null | undefined, withDay = false) => { if (!iso) return "—"; const d = new Date(iso.includes("T") ? iso : `${iso.replace(" ", "T")}Z`); const t = `${String(d.getUTCHours()).padStart(2, "0")}:${String(d.getUTCMinutes()).padStart(2, "0")}`; return withDay ? `${d.toISOString().slice(5, 10)} ${t}` : t; };
const STATUS_TEXT: Record<string, string> = { driving: "learned week in charge", hand_set: "hand-set, pattern waiting", learning: "still learning", window: "quiet windows in charge", no_band: "no band ceiling", off: "executor off", paused: "paused", no_consent: "not switched on", unknown: "unknown" };
const KIND_TEXT: Record<string, string> = { beanstalk_scale: "capacity", beanstalk_pressure: "pressure" };

/**
 * What the capacity action will do to MinSize over the next 24 hours and what it did lately (GET
 * /actions/beanstalk/:env/timeline, src/capacity_timeline.ts): a bar per hour inside the band, the hours it changes
 * marked, the hours the one-step-per-24-hours rule or a hand-set minimum holds, the recent ledger rows and pressure events.
 */
function ScalingTimeline({ env, region, accountId, state }: { env: string; region?: string | null; accountId?: string | null; state: ScaleState }) {
  const [t, setT] = useState<any>(undefined);
  const [err, setErr] = useState("");
  const [open, setOpen] = useState(false);
  useEffect(() => {
    const qs = new URLSearchParams();
    if (region) qs.set("region", region); if (accountId) qs.set("account_id", accountId);
    if (state.floor != null) qs.set("floor", String(state.floor)); if (state.ceiling != null) qs.set("ceiling", String(state.ceiling));
    qs.set("on", state.on ? "1" : "0");
    setT(undefined); setErr("");
    api(`/actions/beanstalk/${encodeURIComponent(env)}/timeline?${qs}`).then(setT).catch((e) => { setT(null); setErr(e.message); });
  }, [env, region, accountId, state.on, state.floor, state.ceiling]);
  if (t === undefined) return <div className="mt-2 text-zinc-500">Scaling timeline: reading…</div>;
  if (t === null) return <div className="mt-2 text-zinc-500">Scaling timeline: {err}</div>;
  const plan = t.plan;
  const hours: any[] = plan.hours;
  const top = Math.max(plan.ceiling ?? 0, ...hours.map((h) => h.min ?? 0), ...hours.map((h) => h.learned ?? 0), 1);
  const changes = hours.filter((h) => h.change || h.held);
  const dry = plan.mode !== "apply";
  return (
    <div className="mt-2 border-t border-zinc-800 pt-2">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-zinc-300">Scaling timeline</span>
        <span className={`rounded border px-1.5 py-0 text-[11px] ${plan.status === "driving" || plan.status === "window" ? "border-emerald-500/40 text-emerald-300" : plan.status === "hand_set" || plan.status === "learning" ? "border-amber-500/40 text-amber-300" : "border-zinc-700 text-zinc-400"}`}>{STATUS_TEXT[plan.status] || plan.status}</span>
        <span className="rounded border border-zinc-700 px-1.5 py-0 text-[11px] text-zinc-400" title="ACT_MODE">{plan.mode === "apply" ? "apply" : plan.mode === "dry_run" ? "dry run: proposes only" : plan.mode}</span>
        <span className="text-zinc-500">MinSize now {plan.current_min ?? "?"}{t.max_size != null ? `, MaxSize ${t.max_size}` : ""}{t.min_source === "ledger" ? " (from the ledger)" : ""} · next capacity pass {hhmm(t.passes.next_capacity_pass)} UTC ({t.passes.capacity}) · pressure check {t.passes.pressure}</span>
      </div>
      <div className="mt-1 text-zinc-400">{plan.headline}</div>
      <div className="mt-2 flex h-16 items-end gap-px" role="img" aria-label="planned MinSize for each of the next 24 hours">
        {hours.map((h) => {
          const v = h.min ?? h.learned ?? 0;
          return (
            <div key={h.at} className="relative flex h-full min-w-0 flex-1 flex-col justify-end" title={`${h.label} UTC · MinSize ${h.min ?? "?"}${h.learned != null ? ` · learned ${h.learned}` : ""}${h.change ? ` · ${h.change.applied ? "set" : "proposed"} ${h.change.from} → ${h.change.to} at ${hhmm(h.decided_at)} (${h.change.driver})` : ""}${h.held ? ` · ${h.held}` : ""}`}>
              {h.learned != null && h.learned !== h.min && <div className="absolute inset-x-0 border-t border-dashed border-zinc-400" style={{ bottom: `${(h.learned / top) * 100}%` }} />}
              <div className={`rounded-sm ${h.change ? (h.change.applied ? "bg-sky-400" : "bg-sky-400/50") : h.held ? "bg-amber-400/60" : "bg-zinc-600"}`} style={{ height: `${Math.max(4, (v / top) * 100)}%` }} />
            </div>
          );
        })}
      </div>
      <div className="flex gap-px text-[10px] text-zinc-600">{hours.map((h, k) => <div key={h.at} className="min-w-0 flex-1 text-center">{k % 3 === 0 ? hhmm(h.at) : ""}</div>)}</div>
      <div className="mt-1 flex flex-wrap gap-3 text-[11px] text-zinc-500">
        <span><span className="mr-1 inline-block h-2 w-2 rounded-sm bg-sky-400" />{dry ? "a proposal row (nothing changes in dry run)" : "MinSize changes here"}</span>
        <span><span className="mr-1 inline-block h-2 w-2 rounded-sm bg-amber-400/60" />held (24-hour rule or hand-set)</span>
        <span><span className="mr-1 inline-block w-3 border-t border-dashed border-zinc-500 align-middle" />learned minimum, when it differs</span>
        {plan.pattern && <span>pattern: {plan.pattern.weeks} of {plan.pattern.min_weeks} weeks, {Math.round(plan.pattern.coverage * 100)} % of {Math.round(plan.pattern.min_coverage * 100)} % hours, {plan.pattern.pressure_events} pressure event(s), computed {hhmm(plan.pattern.computed_at, true)} UTC</span>}
      </div>
      {changes.length > 0 && (
        <ul className="mt-1 space-y-0.5 text-zinc-400">
          {changes.slice(0, 8).map((h) => <li key={h.at}><span className="font-mono text-zinc-300">{hhmm(h.decided_at)}</span> for {h.label}: {h.change ? `${h.change.applied ? "MinSize" : "proposes MinSize"} ${h.change.from} → ${h.change.to} (${h.change.driver === "pattern" ? "learned week" : "quiet window"})` : h.held}</li>)}
          {changes.length > 8 && <li className="text-zinc-500">… {changes.length - 8} more hour(s)</li>}
        </ul>
      )}
      <button type="button" className="mt-1 text-sky-300 hover:underline" onClick={() => setOpen((o) => !o)}>{open ? "hide history" : `history: ${t.changes.length} capacity row(s), ${t.pressure.length} pressure event(s) in 7 days`}</button>
      {open && (
        <div className="mt-1 space-y-2">
          {t.changes.length ? (
            <ul className="space-y-0.5">
              {t.changes.slice(0, 15).map((a: any) => (
                <li key={a.id} className="flex flex-wrap gap-2">
                  <span className="font-mono text-zinc-500">{hhmm(a.applied_at || a.created_at, true)}</span>
                  <span className="text-zinc-500">{KIND_TEXT[a.kind] || a.kind}</span>
                  <span className={a.status === "failed" || a.status === "refused" ? "text-red-300" : a.status === "applied" || a.status === "verified" ? "text-emerald-300" : "text-zinc-400"}>{a.status}</span>
                  <Link className="text-zinc-300 hover:underline" to={`/actions?id=${a.id}`}>{a.title}</Link>
                </li>
              ))}
            </ul>
          ) : <div className="text-zinc-500">No capacity rows for this environment yet.</div>}
          {t.pressure.length > 0 && (
            <div>
              <div className="text-zinc-400">Pressure events (pinned at the ceiling with high CPU; each raises its hour and the one before in the learned week)</div>
              <ul className="space-y-0.5">{t.pressure.map((e: any) => <li key={e.id} className="text-zinc-500"><span className="font-mono">{hhmm(e.at, true)}</span> {e.label} UTC · {e.desired} of max {e.max_size}{e.cpu_avg != null ? ` · CPU ${Math.round(e.cpu_avg)} %` : ""}{e.action_id ? <> · <Link className="text-sky-300 hover:underline" to={`/actions?id=${e.action_id}`}>row #{e.action_id}</Link></> : null}</li>)}</ul>
            </div>
          )}
          <ul className="list-disc space-y-0.5 pl-4 text-zinc-500">{plan.uncertain.map((u: string) => <li key={u}>{u}</li>)}</ul>
        </div>
      )}
    </div>
  );
}

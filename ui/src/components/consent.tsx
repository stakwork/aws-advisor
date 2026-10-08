import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
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
type PreviewCall = { service: string; operation: string; region: string | null; iam: string; cli: string };
type PreviewSide = { writes: PreviewCall[]; reads: string[]; local: string[]; result: string | null; stopped: string | null };
type Preview = { apply: PreviewSide; revert: PreviewSide };

/** What the credentials will be used for (GET /actions/:id/preview): the row's own apply or revert run dry, writes recorded and not sent. */
function PreviewList({ side, error, verb }: { side: PreviewSide | null; error: string; verb: "apply" | "revert" }) {
  if (error) return <div className="text-red-300">Could not preview: {error}</div>;
  if (!side) return <div className="text-zinc-500">Working out what this sends…</div>;
  const perms = [...new Set(["sts:GetCallerIdentity", ...side.writes.map((w) => w.iam)])];
  const reads = Object.entries(side.reads.reduce<Record<string, number>>((m, r) => ({ ...m, [r]: (m[r] ?? 0) + 1 }), {}));
  return (
    <div className="space-y-1 rounded border border-zinc-800 bg-zinc-900/60 p-2">
      <div className="text-zinc-300">What {verb === "revert" ? "undoing" : "running"} this sends with your credentials <span className="text-zinc-500">(a dry run of the same code; nothing has been sent)</span></div>
      <ol className="list-decimal space-y-1 pl-5">
        <li><pre className="whitespace-pre-wrap break-all font-mono text-zinc-400">aws sts get-caller-identity</pre><span className="text-zinc-500">who you are, for the ledger</span></li>
        {side.writes.map((w, i) => <li key={i}><pre className="whitespace-pre-wrap break-all font-mono text-zinc-200">{w.cli}</pre><span className="text-zinc-500">needs {w.iam}</span></li>)}
      </ol>
      {!side.writes.length && !side.stopped && <div className="text-amber-300">No write call: as things stand this would change nothing.</div>}
      {side.stopped && <div className="text-amber-300">The dry run stopped early ({side.stopped}); a step that needs an earlier call's reply may be missing above.</div>}
      {reads.length > 0 && <div className="text-zinc-500">Also reads: {reads.map(([r, n]) => `${r}${n > 1 ? ` ×${n}` : ""}`).join(", ")}</div>}
      {side.local.length > 0 && <div className="text-zinc-500">And records {side.local.length} note{side.local.length > 1 ? "s" : ""} in the advisor's own database.</div>}
      <div className="text-zinc-500">Permissions your credentials need: <span className="font-mono">{perms.join(", ")}</span>{reads.length > 0 ? ", plus read access for the reads" : ""}</div>
    </div>
  );
}

export function RunAsMe({ actionId, verb = "apply", onDone, compact }: { actionId: number; verb?: "apply" | "revert"; onDone?: (row: any) => void; compact?: boolean }) {
  const [open, setOpen] = useState(false);
  const [key, setKey] = useState(""); const [secret, setSecret] = useState(""); const [token, setToken] = useState("");
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<{ text: string; err?: boolean } | null>(null);
  const [preview, setPreview] = useState<Preview | null>(null);
  const [previewErr, setPreviewErr] = useState("");
  useEffect(() => {
    if (!open) return;
    setPreview(null); setPreviewErr("");
    api(`/actions/${actionId}/preview`).then(setPreview).catch((e) => setPreviewErr(e.message));
  }, [open, actionId]);
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
  const close = () => { if (!busy) { setOpen(false); setNote(null); } };
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") close(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, busy]);
  const title = verb === "revert" ? "Undo as me" : "Run as me";
  return (
    <div className={compact ? "inline" : "mt-1"}>
      <button type="button" className="text-sky-300 hover:underline" onClick={() => { setNote(null); setOpen(true); }} title="do this one row with temporary credentials of your own: you authorise this change, the row records who; used once, never stored">
        {verb === "revert" ? "undo as me" : "run as me"}
      </button>
      {open && createPortal(
        // a dialog over the page, not a panel inside the row: the preview and three fields do not fit a table cell
        <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/60 p-4 sm:items-center" onMouseDown={(e) => { if (e.target === e.currentTarget) close(); }}>
          <div role="dialog" aria-modal="true" aria-label={title} className="w-full max-w-2xl space-y-2 rounded-lg border border-zinc-700 bg-zinc-950 p-4 text-left text-xs shadow-xl">
            <div className="flex items-center justify-between">
              <div className="text-sm font-medium text-zinc-100">{title} <span className="font-normal text-zinc-500">· row #{actionId}</span></div>
              <button type="button" disabled={busy} onClick={close} aria-label="close" className="text-zinc-500 hover:text-zinc-200 disabled:opacity-50">✕</button>
            </div>
            <div className="max-h-[45vh] overflow-y-auto"><PreviewList side={preview?.[verb] ?? null} error={previewErr} verb={verb} /></div>
            <div className="text-zinc-400">Temporary credentials of your own, for this one call. From the console's "Command line or programmatic access", from SSO, or <span className="font-mono">aws sts get-session-token --duration-seconds 900</span>. Long-lived keys (AKIA…) are refused. Nothing is stored; the row records who.</div>
            {field(key, setKey, "AWS_ACCESS_KEY_ID (ASIA…)")}
            {field(secret, setSecret, "AWS_SECRET_ACCESS_KEY", true)}
            {field(token, setToken, "AWS_SESSION_TOKEN", true)}
            <div className="flex items-center justify-end gap-2 pt-1">
              {note && <span className={`mr-auto ${note.err ? "text-red-300" : "text-zinc-400"}`}>{note.text}</span>}
              <button type="button" disabled={busy} onClick={close} className="rounded px-2 py-0.5 text-zinc-400 hover:text-zinc-200 disabled:opacity-50">Cancel</button>
              <button type="button" disabled={busy || !key || !secret || !token} onClick={submit} className="rounded border border-sky-600/50 bg-sky-600/10 px-3 py-1 text-sky-200 hover:bg-sky-600/20 disabled:opacity-50">{busy ? "…" : verb === "revert" ? "Undo with these" : "Apply with these"}</button>
            </div>
          </div>
        </div>,
        document.body,
      )}
    </div>
  );
}

/** EC2 states on the way somewhere: the row keeps polling while one of these shows. */
const TRANSIENT = /^(pending|stopping|shutting-down)$/;
const WATCH_MS = 4 * 60_000;

export function AutoParkSwitch({ instanceId, name, state, tags, poolKind, onValue, onState }: { instanceId: string; name?: string | null; state: string; tags?: Record<string, string> | null; poolKind?: string | null; onValue?: (value: string | null) => void; onState?: (state: string) => void }) {
  const [value, setValue] = useState<string | null>(tags?.AdvisorAutoPark ?? null);
  // the state as EC2 reports it now (the inventory row is as old as its last collection); polled after Stop and Start until it lands
  const [live, setLive] = useState<string | null>(null);
  const [watch, setWatch] = useState<{ from: string; until: number } | null>(null);
  const readState = () => api(`/inventory/ec2/${encodeURIComponent(instanceId)}/state`).then((s) => { setLive(s.state); onState?.(s.state); return s.state as string; }).catch(() => null);
  useEffect(() => { setLive(null); setWatch(null); readState(); }, [instanceId]);
  useEffect(() => {
    if (!watch) return;
    let stop = false; let timer: ReturnType<typeof setTimeout> | undefined;
    const tick = async () => {
      const s = await readState();
      if (stop) return;
      if ((s && s !== watch.from && !TRANSIENT.test(s)) || Date.now() > watch.until) { setWatch(null); return; }
      timer = setTimeout(tick, 4000);
    };
    timer = setTimeout(tick, 2500);
    return () => { stop = true; if (timer) clearTimeout(timer); };
  }, [watch]);
  const cur = live ?? state;
  /** The tag as just written: the switch, and through onValue the rest of the page (the On-demand tab), follow it before the detail is read again. */
  const setTag = (v: string | null) => { setValue(v); onValue?.(v); };
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ text: string; err?: boolean; actionId?: number; status?: string } | null>(null);
  const [grant, setGrant] = useState<{ granted: boolean | null; detail: string; role_arn: string | null } | null>(null);
  const loadGrant = () => api(`/inventory/ec2/${encodeURIComponent(instanceId)}/autopark-grant`).then(setGrant).catch(() => setGrant(null));
  useEffect(() => { setValue(tags?.AdvisorAutoPark ?? null); setMsg(null); setGrant(null); loadGrant(); }, [instanceId, tags?.AdvisorAutoPark]);
  const on = isOn(value);
  // Switching is done with the person's own credentials: the row is proposed here and "Run as me" (below) writes the
  // tag and the grant on the actuator role (src/autopark_grant.ts); the switch moves once it is done.
  const flip = (want: boolean) => {
    setBusy(true); setMsg(null);
    api(`/inventory/ec2/${encodeURIComponent(instanceId)}/consent`, { method: "POST", body: JSON.stringify({ value: want ? "ON" : "OFF" }) })
      .then((a) => {
        if (a.status === "applied" || a.status === "verified") { setTag(want ? "ON" : "OFF"); setMsg(rowMsg(a)); loadGrant(); return; }
        setMsg({ ...rowMsg(a), err: false, text: want ? "Needs your own AWS credentials: Run as me tags the box and lets the actuator stop and start this instance only." : "Needs your own AWS credentials: Run as me sets the tag to OFF and removes this instance from the actuator's grant." });
      })
      .catch((e) => setMsg({ text: e.message, err: true })).finally(() => setBusy(false));
  };
  const power = (action: "stop" | "start") => {
    setBusy(true); setMsg(null);
    api(`/inventory/ec2/${encodeURIComponent(instanceId)}/power`, { method: "POST", body: JSON.stringify({ action }) })
      .then((a) => { setMsg(rowMsg(a)); if (a.status === "applied" || a.status === "verified") setWatch({ from: cur, until: Date.now() + WATCH_MS }); })
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
            <button className="rounded border border-zinc-700 px-2 py-0.5 text-zinc-200 hover:bg-zinc-800 disabled:opacity-50" disabled={busy || Boolean(watch) || cur !== "running"} onClick={() => power("stop")} title={cur === "running" ? `stop ${name || instanceId} now` : `state ${cur}`}>Stop</button>
            <button className="rounded border border-zinc-700 px-2 py-0.5 text-zinc-200 hover:bg-zinc-800 disabled:opacity-50" disabled={busy || Boolean(watch) || cur !== "stopped"} onClick={() => power("start")} title={cur === "stopped" ? `start ${name || instanceId} now` : `state ${cur}`}>Start</button>
            {watch && <span className="self-center text-zinc-500">{cur}…</span>}
          </span>
        )}
      </div>
      {msg && <div className={`mt-1 ${msg.err ? "text-red-300" : "text-zinc-400"}`}>{msg.text}{msg.actionId ? <> · <Link className="text-sky-300 hover:underline" to={`/actions?id=${msg.actionId}`}>row #{msg.actionId}</Link></> : null}</div>}
      {on && grant && !msg && (
        <div className={`mt-1 ${grant.granted === false ? "text-amber-300/90" : "text-zinc-500"}`}>
          {grant.granted === true ? <>Granted: {grant.detail}.</> : grant.granted === false ? <>Tagged ON but not granted: {grant.detail}. <button className="text-sky-300 hover:underline" disabled={busy} onClick={() => flip(true)}>Grant it</button></> : <>Grant not checked: {grant.detail}.</>}
        </div>
      )}
      {msg?.actionId && (msg.status === "proposed" || msg.status === "failed") ? <RunAsMe actionId={msg.actionId} onDone={(row) => { if (row.status !== "failed") { setMsg({ text: `${row.status}: ${row.result || row.title}`, actionId: row.id, status: row.status }); setTag(row.after?.AdvisorAutoPark ?? null); loadGrant(); } }} /> : null}
      {!poolKind && <HibernationNote instanceId={instanceId} handsOff={handsOff} autoPark={on} />}
    </div>
  );
}

type Hibernation = { status: "ready" | "guest_not_ready" | "guest_unknown" | "chosen_stop" | "can_migrate" | "cannot" | "migrating" | "kept_stop"; configured: boolean; tag: string | null; reason: string | null; ram_gib: number | null; instance_type: string | null };

/**
 * Whether parking hibernates this box (src/hibernation.ts): ready (back in about a minute, memory kept), or a cold
 * start with the migration offered, never forced: "Keep stop/start" is a first-class answer and hides the suggestion.
 * Each choice is the advisor:hibernate tag, written as a ledgered consent row (Revert puts it back).
 */
function HibernationNote({ instanceId, handsOff, autoPark }: { instanceId: string; handsOff: boolean; autoPark: boolean }) {
  const [h, setH] = useState<Hibernation | null | undefined>(undefined);
  const [readErr, setReadErr] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ text: string; err?: boolean; actionId?: number; status?: string } | null>(null);
  const load = (fresh = false) => { setReadErr(""); return api(`/inventory/ec2/${encodeURIComponent(instanceId)}/hibernation${fresh ? "?fresh=1" : ""}`).then(setH).catch((e) => { setH(null); setReadErr(e.message); }); };
  useEffect(() => { setH(undefined); setMsg(null); load(); }, [instanceId]);
  // the switch just moved: read again, fresh, since the Auto-park grant decides whether the A records may move with a relaunch
  const firstAutoPark = useRef(true);
  useEffect(() => { if (firstAutoPark.current) { firstAutoPark.current = false; return; } load(true); }, [autoPark]);
  const choose = (value: "stop" | "live" | "no" | null) => {
    setBusy(true); setMsg(null);
    api(`/inventory/ec2/${encodeURIComponent(instanceId)}/hibernation`, { method: "POST", body: JSON.stringify({ value }) })
      .then((a) => { setMsg(a.status === "proposed" ? { ...rowMsg(a), err: false, text: "Needs your own AWS credentials: Run as me writes the advisor:hibernate tag." } : rowMsg(a)); return load(true); })
      .catch((e) => setMsg({ text: e.message, err: true })).finally(() => setBusy(false));
  };
  if (h === undefined) return <div className="mt-1.5 text-zinc-500">Checking hibernation…</div>;
  if (h === null) return readErr && !/^not found$/i.test(readErr) ? <div className="mt-1.5 text-amber-300/90">Hibernation not checked: {readErr} <button className="text-sky-300 hover:underline" onClick={() => load(true)}>Retry</button></div> : null;
  const chip = (tone: string, text: string) => <span className={`rounded border px-1.5 py-px ${tone}`}>{text}</span>;
  const btn = (label: string, value: "stop" | "live" | "no" | null, title: string) => (
    <button key={label} className="rounded border border-zinc-700 px-2 py-0.5 text-zinc-200 hover:bg-zinc-800 disabled:opacity-50" disabled={busy || handsOff} onClick={() => choose(value)} title={title}>{label}</button>
  );
  return (
    <div className="mt-1.5 border-t border-zinc-800/70 pt-1.5">
      <div className="flex flex-wrap items-center gap-2">
        {h.status === "ready" && <>{chip("border-emerald-900/60 bg-emerald-950/50 text-emerald-300", "Hibernation ready")}<span className="text-zinc-500">parking hibernates it: back in about a minute, memory and containers as they were</span><span className="ml-auto">{btn("Use stop/start instead", "no", "Tag advisor:hibernate=no: parking stops it instead of hibernating it")}</span></>}
        {(h.status === "guest_not_ready" || h.status === "guest_unknown") && <>{chip("border-amber-900/60 bg-amber-950/50 text-amber-300", h.status === "guest_not_ready" ? "Guest cannot hibernate" : "Guest not checked")}<span className="text-zinc-500">launched with hibernation, but parking stops it (cold start, 2–4 min): {h.reason}{h.status === "guest_unknown" ? "; the next software probe tells" : ""}</span><span className="ml-auto">{btn("Use stop/start", "no", "Tag advisor:hibernate=no: parking stops it, and this note goes away")}</span></>}
        {h.status === "chosen_stop" && <>{chip("border-zinc-700 bg-zinc-900 text-zinc-300", "Stop/start chosen")}<span className="text-zinc-500">launched for hibernation, but advisor:hibernate=no keeps parking on a plain stop (cold start, 2–4 min)</span><span className="ml-auto">{btn("Hibernate again", null, "Remove advisor:hibernate=no")}</span></>}
        {h.status === "migrating" && <>{chip("border-sky-900/60 bg-sky-950/50 text-sky-300", "Migration under way")}<span className="text-zinc-500">the relaunch with hibernation on is in progress: follow it on the <Link className="text-sky-300 hover:underline" to="/actions">Auto-actions</Link> page</span></>}
        {h.status === "kept_stop" && <>{chip("border-zinc-700 bg-zinc-900 text-zinc-300", "Stop/start kept")}<span className="text-zinc-500">cold start, 2–4 min on a wake; the migration is not suggested</span><span className="ml-auto">{btn("Suggest hibernation again", null, "Remove advisor:hibernate=no")}</span></>}
        {(h.status === "can_migrate" || h.status === "cannot") && <>
          {chip("border-amber-900/60 bg-amber-950/50 text-amber-300", "Cold start")}
          <span className="text-zinc-500">{h.status === "cannot" ? <>wakes in 2–4 min, and cannot be made hibernation-ready: {h.reason}</> : <>wakes in 2–4 min: not launched with hibernation. A relaunch would make it resume in about a minute{h.ram_gib ? ` (${h.ram_gib} GiB RAM goes to disk)` : ""}.</>}{h.tag === "stop" || h.tag === "live" ? <> Migration requested ({h.tag}): the next executor pass proposes it.</> : null}</span>
          {h.status === "can_migrate" && h.tag !== "stop" && h.tag !== "live" && <span className="ml-auto flex gap-1">
            {btn("Migrate (with downtime)", "stop", "Tag advisor:hibernate=stop: the box is stopped, imaged and relaunched with hibernation on; announced, after the grace period")}
            {btn("Migrate live", "live", "Tag advisor:hibernate=live: a warm image while it runs; the cut-over waits for your click")}
            {btn("Keep stop/start", "no", "Tag advisor:hibernate=no: stay on cold starts and stop suggesting the migration")}
          </span>}
          {(h.tag === "stop" || h.tag === "live") && <span className="ml-auto">{btn("Cancel the request", null, "Remove advisor:hibernate")}</span>}
        </>}
      </div>
      {msg && <div className={`mt-1 ${msg.err ? "text-red-300" : "text-zinc-400"}`}>{msg.text}{msg.actionId ? <> · <Link className="text-sky-300 hover:underline" to={`/actions?id=${msg.actionId}`}>row #{msg.actionId}</Link></> : null}</div>}
      {msg?.actionId && msg.status === "proposed" ? <RunAsMe actionId={msg.actionId} onDone={(row) => { setMsg({ ...rowMsg(row) }); load(true); }} /> : null}
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
            <div key={h.at} className="relative flex h-full min-w-0 flex-1 flex-col justify-end" title={`${h.label} UTC · MinSize ${h.min ?? "?"}${h.learned != null ? ` · learned ${h.learned}${h.binding ? ` (set by ${h.binding.replace("_", " ")})` : ""}` : ""}${h.change ? ` · ${h.change.applied ? "set" : "proposed"} ${h.change.from} → ${h.change.to} at ${hhmm(h.decided_at)} (${h.change.driver})` : ""}${h.held ? ` · ${h.held}` : ""}`}>
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
        {plan.pattern && <span>pattern: {plan.pattern.weeks} weeks (needs {plan.pattern.min_weeks}), {Math.round(plan.pattern.coverage * 100)} % of hours (needs {Math.round(plan.pattern.min_coverage * 100)} %), {plan.pattern.pressure_events} pressure event(s), computed {hhmm(plan.pattern.computed_at, true)} UTC</span>}
        {plan.pattern && <span className="basis-full">sized by: {plan.pattern.signals ?? "the trigger's desired capacity only (relearned from the signals on the next pass)"}{plan.pattern.targets ? ` · targets CPU ${plan.pattern.targets.cpu} %, memory ${plan.pattern.targets.mem} %, disk hold ${plan.pattern.targets.disk} %` : ""}</span>}
      </div>
      {changes.length > 0 && (
        <ul className="mt-1 space-y-0.5 text-zinc-400">
          {changes.slice(0, 8).map((h) => <li key={h.at}><span className="font-mono text-zinc-300">{hhmm(h.decided_at)}</span> for {h.label}: {h.change ? `${h.change.applied ? "MinSize" : "proposes MinSize"} ${h.change.from} → ${h.change.to} (${h.change.driver === "pattern" ? `learned week${h.binding ? `, set by ${h.binding.replace("_", " ")}` : ""}` : "quiet window"})` : h.held}</li>)}
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

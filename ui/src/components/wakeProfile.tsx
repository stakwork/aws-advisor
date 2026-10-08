import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, when } from "../api";
import { Td, Th } from "./ui";

/**
 * The On-demand tab of an EC2 instance: its wake profile (src/wake_profiles.ts) as a form, the doorman's view of it
 * (src/doorman.ts: asleep, starting, ready), the link to the test page and the latest wakes. Saving changes nothing in
 * AWS; the switch at the top is what lets a visit wake the box on its own.
 */

const BEHAVIOUR: Record<string, string> = {
  page: "waiting page (browsers) and hold (API, WebSocket)",
  hold: "hold the connection until it is up",
  redirect: "redirect to https",
  ignore: "ignore: never wakes the box",
};

const field = "w-full rounded border border-zinc-700 bg-zinc-950 px-2 py-1 text-sm text-zinc-100";
const label = "mb-0.5 block text-xs text-zinc-400";

function Row({ title, hint, children }: { title: string; hint?: string; children: React.ReactNode }) {
  return (
    <div className="grid gap-1 sm:grid-cols-[180px_minmax(0,1fr)] sm:gap-3">
      <div className="pt-1 text-sm text-zinc-300">{title}{hint && <div className="text-xs text-zinc-500">{hint}</div>}</div>
      <div className="min-w-0">{children}</div>
    </div>
  );
}

export function WakeProfilePanel({ instanceId, autoPark }: { instanceId: string; autoPark: boolean }) {
  const [data, setData] = useState<any>(null);
  const [form, setForm] = useState<any>(null);
  const [saved, setSaved] = useState<string | null>(null);
  const [errors, setErrors] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState<any>(null);
  const load = () => api(`/wake-profiles/${encodeURIComponent(instanceId)}`).then((d) => { setData(d); setForm(structuredClone(d.profile ?? d.suggested)); });
  useEffect(() => { setData(null); setForm(null); setErrors([]); setSaved(null); setStatus(null); load().catch((e) => setErrors([e.message])); }, [instanceId]);
  useEffect(() => {
    if (!data?.profile) return;
    let stop = false;
    const tick = () => api(`/wake-profiles/${encodeURIComponent(instanceId)}/status`).then((s) => { if (!stop) setStatus(s); }).catch(() => {}).finally(() => { if (!stop) setTimeout(tick, 5000); });
    tick();
    return () => { stop = true; };
  }, [instanceId, data?.profile?.updated_at]);
  if (!form) return <div className="mt-3 text-sm text-zinc-500">{errors[0] || "Loading…"}</div>;

  const set = (patch: any) => { setForm({ ...form, ...patch }); setSaved(null); };
  const setIn = (key: string, patch: any) => set({ [key]: { ...form[key], ...patch } });
  const save = async () => {
    setBusy(true); setErrors([]); setSaved(null);
    try { await api(`/wake-profiles/${encodeURIComponent(instanceId)}`, { method: "PUT", body: JSON.stringify(form) }); await load(); setSaved("Saved."); }
    catch (e: any) { setErrors(String(e.message).split("; ")); }
    finally { setBusy(false); }
  };
  const remove = async () => {
    setBusy(true);
    try { await api(`/wake-profiles/${encodeURIComponent(instanceId)}`, { method: "DELETE" }); await load(); setSaved("Profile deleted."); } catch (e: any) { setErrors([e.message]); } finally { setBusy(false); }
  };
  const testUrl = data?.doorman_port ? `${window.location.protocol}//${window.location.hostname}:${data.doorman_port}${data.test_path}` : null;
  const phaseTone: Record<string, string> = { ready: "text-emerald-300", error: "text-red-300", asleep: "text-zinc-300", starting: "text-amber-300", booting: "text-amber-300", stopping: "text-zinc-400" };

  return (
    <div className="mt-3 space-y-4">
      <div className="rounded-lg border border-zinc-800 bg-zinc-950/40 p-3 text-sm">
        <div className="flex flex-wrap items-center gap-3">
          <label className="flex items-center gap-2"><input id="wake-enabled" type="checkbox" checked={form.enabled} onChange={(e) => set({ enabled: e.target.checked })} /> <span className="text-zinc-100">Wake on traffic</span></label>
          <span className="text-xs text-zinc-500">{form.enabled ? "a real visit to one of the domains starts the box while it sleeps" : "off: the doorman shows the waiting page, but only the test page's button starts the box"}</span>
          {!data.profile && <span className="rounded bg-sky-950/60 px-1.5 text-xs text-sky-300">suggested from its DNS records and listening ports, not saved yet</span>}
        </div>
        {!autoPark && <div className="mt-2 text-xs text-amber-300/90">Auto-park is off for this box: a wake is the Inventory's Start, which needs AdvisorAutoPark=ON (switch it on in the Overview tab).</div>}
        {data.profile && status && (
          <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-zinc-400">
            <span>Now: <span className={phaseTone[status.phase] || "text-zinc-300"}>{status.phase}</span> · instance {status.state} · {status.detail}</span>
            {status.waking_since && <span>waking for {status.elapsed_s}s</span>}
            {status.expected_s && <span>a wake usually takes {status.expected_s}s</span>}
            {status.error && <span className="text-red-300">{status.error}</span>}
          </div>
        )}
        {data.profile && testUrl && (
          <div className="mt-2 text-xs text-zinc-400">
            Test page (VPN only): <a className="text-sky-300 hover:underline" href={testUrl} target="_blank" rel="noreferrer">{testUrl}</a>
            <span className="text-zinc-500"> · shows the waiting page with a Start button, whatever the switch says</span>
          </div>
        )}
        {data.profile && !testUrl && <div className="mt-2 text-xs text-zinc-500">The doorman is off (DOORMAN_PORT=0): no waiting page.</div>}
      </div>

      <div className="space-y-3">
        <Row title="Domains" hint="the host names the doorman answers for">
          <input id="wake-domains" className={field} value={(form.domains || []).join(", ")} onChange={(e) => set({ domains: e.target.value.split(/[\s,]+/).filter(Boolean) })} placeholder="app.example.com, *.example.com" />
        </Row>
        <Row title="Front door" hint="how traffic reaches the doorman while it sleeps: with the DNS flip, every stop points the A records at the doorman's public address (Settings > Auto-actions) and the start points them back">
          <select id="wake-front" className={field} value={form.front_door} onChange={(e) => set({ front_door: e.target.value })}>
            <option value="dns">DNS flip: the A record points at the swarm host while asleep (works without an Elastic IP)</option>
            <option value="eip">Elastic IP moves to the doorman (instant, needs an EIP)</option>
          </select>
        </Row>
        <Row title="Ports" hint="what the doorman does on each while it sleeps">
          <div className="overflow-x-auto rounded border border-zinc-800">
            <table className="w-full text-sm">
              <thead className="bg-zinc-900"><tr><Th>Port</Th><Th>Proto</Th><Th>While asleep</Th><Th>Note</Th><Th /></tr></thead>
              <tbody>
                {form.ports.map((p: any, i: number) => (
                  <tr key={i} className="border-t border-zinc-800/70">
                    <Td><input aria-label="port" className={`${field} w-20`} value={p.port} onChange={(e) => { const ports = [...form.ports]; ports[i] = { ...p, port: e.target.value }; set({ ports }); }} /></Td>
                    <Td><select aria-label="protocol" className={field} value={p.proto} onChange={(e) => { const ports = [...form.ports]; ports[i] = { ...p, proto: e.target.value, behaviour: e.target.value === "udp" ? "ignore" : p.behaviour }; set({ ports }); }}><option>tcp</option><option>udp</option></select></Td>
                    <Td><select aria-label="behaviour" className={field} value={p.behaviour} disabled={p.proto === "udp"} onChange={(e) => { const ports = [...form.ports]; ports[i] = { ...p, behaviour: e.target.value }; set({ ports }); }}>{Object.entries(BEHAVIOUR).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></Td>
                    <Td><input aria-label="note" className={field} value={p.note ?? ""} onChange={(e) => { const ports = [...form.ports]; ports[i] = { ...p, note: e.target.value }; set({ ports }); }} /></Td>
                    <Td><button className="text-xs text-zinc-500 hover:text-red-300" onClick={() => set({ ports: form.ports.filter((_: any, j: number) => j !== i) })}>remove</button></Td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <button className="mt-1 text-xs text-sky-300 hover:underline" onClick={() => set({ ports: [...form.ports, { port: "", proto: "tcp", behaviour: "hold", note: "" }] })}>+ add a port</button>
        </Row>
        <Row title="Ready when" hint="checked over the private address">
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-5">
            <div><span className={label}>scheme</span><select id="wake-ready-scheme" className={field} value={form.ready.scheme} onChange={(e) => setIn("ready", { scheme: e.target.value })}><option>https</option><option>http</option><option>tcp</option></select></div>
            <div><span className={label}>port</span><input id="wake-ready-port" className={field} value={form.ready.port} onChange={(e) => setIn("ready", { port: e.target.value })} /></div>
            {form.ready.scheme !== "tcp" && <>
              <div><span className={label}>path</span><input id="wake-ready-path" className={field} value={form.ready.path} onChange={(e) => setIn("ready", { path: e.target.value })} /></div>
              <div><span className={label}>Host header</span><input id="wake-ready-host" className={field} value={form.ready.host ?? ""} placeholder={form.domains?.[0] || ""} onChange={(e) => setIn("ready", { host: e.target.value || null })} /></div>
              <div><span className={label}>expect status</span><input id="wake-ready-expect" className={field} value={form.ready.expect} onChange={(e) => setIn("ready", { expect: e.target.value })} /></div>
            </>}
          </div>
        </Row>
        <Row title="Sleep mode">
          <select id="wake-sleep" className={field} value={form.sleep_mode} onChange={(e) => set({ sleep_mode: e.target.value })}>
            <option value="auto">automatic: hibernate when the box is ready for it, else stop</option>
            <option value="hibernate">hibernate (back in about a minute)</option>
            <option value="stop">stop (cold start, 2–4 min)</option>
          </select>
        </Row>
        <Row title="Timing">
          <div className="grid grid-cols-2 gap-2">
            <div><span className={label}>stay awake at least (minutes) after a wake</span><input id="wake-min-awake" className={field} value={form.min_awake_minutes} onChange={(e) => set({ min_awake_minutes: e.target.value })} /></div>
            <div><span className={label}>hold API and WebSocket calls up to (seconds)</span><input id="wake-hold" className={field} value={form.hold_seconds} onChange={(e) => set({ hold_seconds: e.target.value })} /></div>
          </div>
        </Row>
        <Row title="Wake with it" hint="other instance ids, started first">
          <input id="wake-with" className={field} value={(form.wake_with || []).join(", ")} onChange={(e) => set({ wake_with: e.target.value.split(/[\s,]+/).filter(Boolean) })} placeholder="i-0123456789abcdef0" />
        </Row>
        <Row title="Commands" hint="through SSM; run by the sleep and wake steps still to come">
          <div className="grid gap-2">
            <div><span className={label}>after it wakes</span><input id="wake-after" className={`${field} font-mono`} value={form.after_wake_command ?? ""} onChange={(e) => set({ after_wake_command: e.target.value || null })} placeholder="docker restart app" /></div>
            <div><span className={label}>before it sleeps</span><input id="wake-before" className={`${field} font-mono`} value={form.before_park_command ?? ""} onChange={(e) => set({ before_park_command: e.target.value || null })} /></div>
          </div>
        </Row>
        <Row title="Wake filter" hint="what does not count as a visit">
          <div className="grid gap-2">
            <label className="flex items-center gap-2 text-sm text-zinc-300"><input id="wake-hostmatch" type="checkbox" checked={form.filter.require_host_match} onChange={(e) => setIn("filter", { require_host_match: e.target.checked })} /> only requests for one of the domains</label>
            <div><span className={label}>ignored paths</span><input id="wake-paths" className={`${field} font-mono`} value={(form.filter.ignore_paths || []).join(", ")} onChange={(e) => setIn("filter", { ignore_paths: e.target.value.split(/[\s,]+/).filter(Boolean) })} /></div>
            <div><span className={label}>ignored user agents (regular expression)</span><input id="wake-ua" className={`${field} font-mono`} value={form.filter.ignore_user_agents} onChange={(e) => setIn("filter", { ignore_user_agents: e.target.value })} /></div>
            <div className="w-40"><span className={label} title="Past this the box still wakes; the chat gets one message that day naming the paths and user agents behind the wakes">alert past N wakes a day</span><input id="wake-max" className={field} value={form.filter.max_wakes_per_day} onChange={(e) => setIn("filter", { max_wakes_per_day: e.target.value })} /></div>
          </div>
        </Row>
        <Row title="Waiting page" hint="what visitors read">
          <div className="grid gap-2">
            <input id="wake-page-title" className={field} value={form.page?.title ?? ""} placeholder={form.domains?.[0] || "This server"} onChange={(e) => setIn("page", { title: e.target.value || null })} />
            <textarea id="wake-page-message" className={field} rows={2} value={form.page?.message ?? ""} placeholder="It sleeps while nobody is using it, to save energy and cost. It is waking up now and this page will continue on its own." onChange={(e) => setIn("page", { message: e.target.value || null })} />
          </div>
        </Row>
      </div>

      {errors.length > 0 && <ul className="list-disc space-y-0.5 pl-5 text-sm text-red-300">{errors.map((e, i) => <li key={i}>{e}</li>)}</ul>}
      <div className="flex items-center gap-3">
        <button className="rounded bg-zinc-100 px-3 py-1.5 text-sm font-medium text-zinc-900 hover:bg-white disabled:opacity-50" disabled={busy} onClick={save}>{data.profile ? "Save" : "Create profile"}</button>
        {data.profile && <button className="rounded border border-zinc-700 px-3 py-1.5 text-sm text-zinc-300 hover:bg-zinc-800 disabled:opacity-50" disabled={busy} onClick={remove}>Delete profile</button>}
        {saved && <span className="text-sm text-emerald-300">{saved}</span>}
        {data.profile && <span className="text-xs text-zinc-500">updated {when(data.profile.updated_at)}{data.profile.updated_by ? ` by ${data.profile.updated_by}` : ""}</span>}
      </div>

      {data.events?.length > 0 && (
        <div>
          <div className="mb-1 text-sm text-zinc-300">Latest wakes</div>
          <div className="overflow-x-auto rounded border border-zinc-800">
            <table className="w-full text-sm">
              <thead className="bg-zinc-900"><tr><Th>When</Th><Th>By</Th><Th>Outcome</Th><Th>Detail</Th></tr></thead>
              <tbody>{data.events.map((e: any) => (
                <tr key={e.id} className="border-t border-zinc-800/70">
                  <Td className="whitespace-nowrap text-xs text-zinc-400">{when(e.at)}</Td>
                  <Td className="text-xs">{e.by}{e.path ? <span className="font-mono text-zinc-500"> {e.path}</span> : null}</Td>
                  <Td className={`text-xs ${e.outcome === "failed" || e.outcome === "refused" ? "text-red-300" : e.outcome === "ready" ? "text-emerald-300" : "text-zinc-300"}`}>{e.outcome}{e.ready_after_s ? ` in ${Math.round(e.ready_after_s)}s` : ""}</Td>
                  <Td className="text-xs text-zinc-500">{e.detail}{e.action_id ? <> · <Link className="text-sky-300 hover:underline" to={`/actions?id=${e.action_id}`}>row #{e.action_id}</Link></> : null}</Td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

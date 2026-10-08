/**
 * The doorman: what answers for a parked instance while it sleeps (the wake-on-traffic plan, feature 4, first cut).
 * A plain-HTTP server on an internal port (DOORMAN_PORT, 9035), meant to sit behind the swarm's Traefik, which ends
 * TLS and forwards the sleeping domains here. Two ways in:
 *
 *  - by host name (production): the Host header picks the wake profile (src/wake_profiles.ts). While the box is not
 *    ready a browser gets the waiting page (it polls /__wake/status and reloads when the box answers), and other
 *    requests and WebSocket upgrades are held up to the profile's hold time, then passed through or answered 503 with
 *    Retry-After. A visit wakes the box only when the profile is enabled and the visit passes the wake filter (host
 *    match, ignored paths, scanner user agents). Past the profile's wakes per day the box still wakes, and the chat gets
 *    one message that day naming the paths and user agents doing it, so an ignore rule can be added. Once the box
 *    answers its ready check, requests are
 *    reverse-proxied to its private address (clients whose DNS still points here keep working).
 *  - the test page, /__wake/test/<instance-id>, for a person on the VPN: the same waiting page with a Start button,
 *    whatever the profile's switch says. It is served only to private addresses and never for a profile's own host,
 *    so nothing outside reaches it through Traefik.
 *
 * A wake is the Start of the Inventory page (src/consent.ts manualPower: a ledger row, the DNS records re-pointed
 * when there is no Elastic IP, and only on a box tagged AdvisorAutoPark=ON), its dependencies first. Every wake is a
 * row in wake_events.
 */
import http from "node:http";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";
import { DescribeInstancesCommand, EC2Client } from "@aws-sdk/client-ec2";
import { addColumn, db } from "./db.js";
import { config } from "./config.js";
import { executorCreds } from "./executor.js";
import { getProfile, profileForHost, type StoredProfile, type WakeProfile } from "./wake_profiles.js";

db.exec(`create table if not exists wake_events (
  id integer primary key autoincrement, instance_id text not null, at text not null default (datetime('now')),
  by text not null, path text, outcome text not null, detail text, ready_after_s real, action_id integer
);
create index if not exists wake_events_instance on wake_events(instance_id, id);`);
addColumn("wake_events", "ua", "text");

// ---- pure ------------------------------------------------------------------------------------------------------------

/** Whether a status code is inside "200-399", "200" or "2xx". Pure. */
export function statusMatches(code: number, expect: string): boolean {
  const e = expect.trim();
  if (/^[1-5]xx$/.test(e)) return Math.floor(code / 100) === Number(e[0]);
  const m = /^(\d{3})(?:-(\d{3}))?$/.exec(e);
  if (!m) return code >= 200 && code < 400;
  return code >= Number(m[1]) && code <= Number(m[2] ?? m[1]);
}

/** Why a request must not wake the box, or null when it may. Pure. */
export function filterReason(p: Pick<WakeProfile, "filter" | "domains">, req: { host: string; path: string; ua: string }): string | null {
  const host = req.host.toLowerCase().replace(/:\d+$/, "");
  if (p.filter.require_host_match && !p.domains.some((d) => d === host || (d.startsWith("*.") && host.endsWith(d.slice(1))))) return `host ${host} is not one of the profile's domains`;
  const path = req.path.split("?")[0];
  const ignored = p.filter.ignore_paths.find((x) => (x.endsWith("/") ? path.startsWith(x) : path === x || path.startsWith(`${x}/`)));
  if (ignored) return `path ${path} is ignored (${ignored})`;
  if (p.filter.ignore_user_agents) { try { if (new RegExp(p.filter.ignore_user_agents, "i").test(req.ua || "")) return "user agent looks like a bot or a scanner"; } catch { /* a bad pattern filters nothing */ } }
  if (!req.ua) return "no user agent";
  return null;
}

/** The chat message for a box woken more often than its profile expects in a day, with who did it. Pure. */
export function overCapMessage(o: { name: string; instance_id: string; wakes: number; cap: number; paths: { v: string; n: number }[]; uas: { v: string; n: number }[]; link: string }): string {
  const top = (xs: { v: string; n: number }[]) => xs.length ? xs.map((x) => `${x.v} (${x.n})`).join(", ") : "none recorded";
  return [
    `🟠 WAKES — ${o.name} woke ${o.wakes} times today (expected at most ${o.cap}). It keeps waking: nothing is refused.`,
    `Top paths: ${top(o.paths)}`,
    `Top user agents: ${top(o.uas)}`,
    `If these are not people, add an ignored path or user agent on the On-demand tab: ${o.link}`,
  ].join("\n");
}

/** Whether a client address is private (RFC 1918, loopback, link-local, ULA): who may open the test page. Pure. */
export function isPrivateAddress(addr: string | undefined | null): boolean {
  const a = String(addr || "").replace(/^::ffff:/, "");
  return /^(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.)/.test(a) || a === "::1" || /^f[cd][0-9a-f]{2}:/i.test(a);
}

/** True for a request a browser makes for a page (not an API call, not an asset). Pure. */
export const wantsPage = (method: string, accept: string | undefined) => method === "GET" && /text\/html/i.test(accept || "");

// ---- the box: state and readiness ------------------------------------------------------------------------------------

interface BoxState { state: string; private_ip: string | null; ready: boolean; detail: string; at: number }
const boxCache = new Map<string, BoxState>();
const BOX_TTL_MS = 3000;

async function describeBox(instanceId: string): Promise<{ state: string; private_ip: string | null }> {
  const row = db.prepare("select account_id, region from inventory_ec2 where instance_id = ?").get(instanceId) as { account_id: string | null; region: string | null } | undefined;
  const creds = executorCreds();
  const acct = creds.forAccount(row?.account_id || null);
  const ec2 = new EC2Client({ region: row?.region || acct.region || creds.region, credentials: acct.read });
  try {
    const i = (await ec2.send(new DescribeInstancesCommand({ InstanceIds: [instanceId] }))).Reservations?.[0]?.Instances?.[0];
    return { state: i?.State?.Name ?? "unknown", private_ip: i?.PrivateIpAddress ?? null };
  } finally { ec2.destroy(); }
}

/** Whether the box answers its ready check, over its private address. */
export function readyCheck(p: Pick<WakeProfile, "ready" | "domains">, ip: string, timeoutMs = 3000): Promise<{ ok: boolean; detail: string }> {
  const r = p.ready;
  if (r.scheme === "tcp") {
    return new Promise((resolve) => {
      const s = net.connect({ host: ip, port: r.port, timeout: timeoutMs }, () => { s.destroy(); resolve({ ok: true, detail: `tcp ${r.port} open` }); });
      s.on("timeout", () => { s.destroy(); resolve({ ok: false, detail: `tcp ${r.port}: no answer` }); });
      s.on("error", (e) => resolve({ ok: false, detail: `tcp ${r.port}: ${e.message}` }));
    });
  }
  const host = r.host || p.domains[0] || ip;
  return new Promise((resolve) => {
    const mod = r.scheme === "https" ? https : http;
    const req = mod.request({ host: ip, port: r.port, path: r.path || "/", method: "GET", timeout: timeoutMs, headers: { host, "user-agent": "aws-advisor-doorman/1 (ready check)" }, ...(r.scheme === "https" ? { servername: host, rejectUnauthorized: false } : {}) }, (res) => {
      res.resume();
      const code = res.statusCode ?? 0;
      resolve({ ok: statusMatches(code, r.expect), detail: `${r.scheme} ${r.port}${r.path} → ${code}` });
    });
    req.on("timeout", () => { req.destroy(); resolve({ ok: false, detail: `${r.scheme} ${r.port}: no answer within ${timeoutMs / 1000}s` }); });
    req.on("error", (e) => resolve({ ok: false, detail: `${r.scheme} ${r.port}: ${e.message}` }));
    req.end();
  });
}

export async function boxState(p: StoredProfile, fresh = false): Promise<BoxState> {
  const hit = boxCache.get(p.instance_id);
  if (hit && !fresh && Date.now() - hit.at < BOX_TTL_MS) return hit;
  let st: BoxState;
  try {
    const d = await describeBox(p.instance_id);
    if (d.state === "running" && d.private_ip) {
      const rc = await readyCheck(p, d.private_ip);
      st = { state: d.state, private_ip: d.private_ip, ready: rc.ok, detail: rc.detail, at: Date.now() };
    } else st = { state: d.state, private_ip: d.private_ip, ready: false, detail: `instance ${d.state}`, at: Date.now() };
  } catch (e: any) { st = { state: "unknown", private_ip: null, ready: false, detail: `cannot read the instance: ${String(e?.message || e).slice(0, 160)}`, at: Date.now() }; }
  boxCache.set(p.instance_id, st);
  return st;
}

// ---- waking ------------------------------------------------------------------------------------------------------------

interface Wake { started_at: number; by: string; error: string | null; action_id: number | null; ready_at: number | null; event_id: number }
const wakes = new Map<string, Wake>();

export const wakesToday = (instanceId: string) => (db.prepare("select count(*) as n from wake_events where instance_id = ? and outcome = 'started' and date(at) = date('now')").get(instanceId) as { n: number }).n;

/** Once a day, past the profile's wakes per day: a chat message naming the paths and user agents behind today's wakes. */
export async function noticeOverCap(p: StoredProfile): Promise<void> {
  const n = wakesToday(p.instance_id);
  if (n <= p.filter.max_wakes_per_day) return;
  if (db.prepare("select 1 from wake_events where instance_id = ? and outcome = 'over_cap' and date(at) = date('now')").get(p.instance_id)) return;
  const id = Number(db.prepare("insert into wake_events(instance_id, by, outcome, detail) values (?, 'doorman', 'over_cap', ?)").run(p.instance_id, `${n} wakes today, expected at most ${p.filter.max_wakes_per_day}`).lastInsertRowid);
  const top = (col: "path" | "ua") => (db.prepare(`select coalesce(${col}, '(none)') as v, count(*) as n from wake_events where instance_id = ? and outcome = 'started' and date(at) = date('now') group by v order by n desc limit 5`).all(p.instance_id) as { v: string; n: number }[]).map((r) => ({ v: r.v.length > 80 ? `${r.v.slice(0, 77)}...` : r.v, n: r.n }));
  const row = db.prepare("select name from inventory_ec2 where instance_id = ?").get(p.instance_id) as { name: string | null } | undefined;
  const name = p.domains[0] || row?.name || p.instance_id;
  let result = "notifications off for this profile";
  if (p.notify) {
    const { sendSphinx } = await import("./notify.js");
    const r = await sendSphinx(overCapMessage({ name, instance_id: p.instance_id, wakes: n, cap: p.filter.max_wakes_per_day, paths: top("path"), uas: top("ua"), link: `${config.notifyLinkUrl}/inventory?tab=ec2&id=${p.instance_id}` }));
    result = r.ok ? "sent to the chat" : `chat send failed: ${r.status} ${r.body}`.slice(0, 200);
  }
  db.prepare("update wake_events set detail = detail || ' · ' || ? where id = ?").run(result, id);
}

/** Seconds a wake has taken here before (the median of the last ten that got ready), or null. */
export function expectedWakeSeconds(instanceId: string): number | null {
  const xs = (db.prepare("select ready_after_s from wake_events where instance_id = ? and outcome = 'ready' and ready_after_s is not null order by id desc limit 10").all(instanceId) as { ready_after_s: number }[]).map((r) => r.ready_after_s).sort((a, b) => a - b);
  return xs.length ? Math.round(xs[Math.floor(xs.length / 2)]) : null;
}

/** Starts the box (dependencies first) unless it is already up or waking; returns the wake in progress. */
export async function wake(p: StoredProfile, by: string, path: string | null, ua: string | null = null): Promise<Wake> {
  const running = wakes.get(p.instance_id);
  if (running && !running.ready_at && !running.error && Date.now() - running.started_at < 15 * 60_000) return running;
  const st = await boxState(p, true);
  const event = (outcome: string, detail: string | null, actionId: number | null = null) => Number(db.prepare("insert into wake_events(instance_id, by, path, outcome, detail, action_id, ua) values (?, ?, ?, ?, ?, ?, ?)").run(p.instance_id, by, path, outcome, detail, actionId, ua).lastInsertRowid);
  const w: Wake = { started_at: Date.now(), by, error: null, action_id: null, ready_at: null, event_id: 0 };
  if (st.state === "running" || st.state === "pending") { w.event_id = event("already_up", `instance ${st.state}`); wakes.set(p.instance_id, w); return w; }
  wakes.set(p.instance_id, w);
  const { manualPower } = await import("./consent.js");
  for (const dep of p.wake_with) {
    try { const a = await manualPower(dep, "start", `doorman:${by}`); event("dependency", `${dep}: ${a.status}`, a.id); }
    catch (e: any) { event("dependency", `${dep}: ${String(e?.message || e).slice(0, 200)}`); }
  }
  try {
    if (st.state === "stopping") { w.error = "the instance is still stopping; it can be started once it has stopped (a minute or so)"; w.event_id = event("refused", w.error); return w; }
    const a = await manualPower(p.instance_id, "start", `doorman:${by}`);
    w.action_id = a.id;
    if (a.status === "failed" || a.status === "refused") { w.error = a.error || `start ${a.status}`; w.event_id = event("failed", w.error, a.id); }
    else { w.event_id = event("started", a.result ?? a.status, a.id); noticeOverCap(p).catch((e) => console.error(`[doorman] over-cap notice ${p.instance_id}: ${e?.message || e}`)); }
  } catch (e: any) { w.error = String(e?.message || e).slice(0, 300); w.event_id = event("failed", w.error); }
  boxCache.delete(p.instance_id);
  return w;
}

function markReady(p: StoredProfile) {
  const w = wakes.get(p.instance_id);
  if (!w || w.ready_at || w.error || !w.event_id) return;
  w.ready_at = Date.now();
  db.prepare("insert into wake_events(instance_id, by, path, outcome, detail, ready_after_s, action_id) values (?, ?, null, 'ready', null, ?, ?)").run(p.instance_id, w.by, (w.ready_at - w.started_at) / 1000, w.action_id);
}

export async function statusOf(p: StoredProfile) {
  const st = await boxState(p);
  if (st.ready) markReady(p);
  const w = wakes.get(p.instance_id);
  const name = (db.prepare("select name from inventory_ec2 where instance_id = ?").get(p.instance_id) as { name: string | null } | undefined)?.name ?? null;
  const phase = st.ready ? "ready" : w?.error ? "error" : st.state === "running" ? "booting" : st.state === "pending" ? "starting" : st.state === "stopping" ? "stopping" : w ? "starting" : "asleep";
  return {
    instance_id: p.instance_id, name, enabled: p.enabled, state: st.state, ready: st.ready, phase, detail: st.detail,
    waking_since: w && !w.ready_at ? new Date(w.started_at).toISOString() : null, elapsed_s: w ? Math.round(((w.ready_at ?? Date.now()) - w.started_at) / 1000) : null,
    expected_s: expectedWakeSeconds(p.instance_id), error: w?.error ?? null, action_id: w?.action_id ?? null, domain: p.domains[0] ?? null,
  };
}

// ---- proxying to the awake box -----------------------------------------------------------------------------------------

function target(p: StoredProfile, ip: string) { return { ip, port: p.ready.scheme === "tcp" ? 443 : p.ready.port, tls: p.ready.scheme !== "http" }; }

function proxyHttp(req: http.IncomingMessage, res: http.ServerResponse, p: StoredProfile, ip: string) {
  const t = target(p, ip);
  const host = String(req.headers.host || p.domains[0] || ip);
  const mod = t.tls ? https : http;
  const up = mod.request({ host: t.ip, port: t.port, method: req.method, path: req.url, headers: { ...req.headers, host }, ...(t.tls ? { servername: host.replace(/:\d+$/, ""), rejectUnauthorized: false } : {}) }, (r) => {
    res.writeHead(r.statusCode ?? 502, r.headers);
    r.pipe(res);
  });
  up.on("error", (e) => { if (!res.headersSent) { res.writeHead(502, { "content-type": "text/plain" }); } res.end(`the server is up but did not answer: ${e.message}`); boxCache.delete(p.instance_id); });
  req.pipe(up);
}

function proxyUpgrade(req: http.IncomingMessage, socket: net.Socket, head: Buffer, p: StoredProfile, ip: string) {
  const t = target(p, ip);
  const host = String(req.headers.host || p.domains[0] || ip);
  const up = t.tls ? tls.connect({ host: t.ip, port: t.port, servername: host.replace(/:\d+$/, ""), rejectUnauthorized: false }) : net.connect({ host: t.ip, port: t.port });
  up.on(t.tls ? "secureConnect" : "connect", () => {
    const lines = [`${req.method} ${req.url} HTTP/1.1`];
    for (let i = 0; i < req.rawHeaders.length; i += 2) lines.push(`${req.rawHeaders[i]}: ${req.rawHeaders[i + 1]}`);
    up.write(lines.join("\r\n") + "\r\n\r\n");
    if (head?.length) up.write(head);
    up.pipe(socket); socket.pipe(up);
  });
  const end = () => { up.destroy(); socket.destroy(); };
  up.on("error", end); socket.on("error", end);
}

/** Polls until the box is ready or the hold time is up. */
async function holdUntilReady(p: StoredProfile): Promise<BoxState | null> {
  const until = Date.now() + p.hold_seconds * 1000;
  while (Date.now() < until) {
    const st = await boxState(p, true);
    if (st.ready && st.private_ip) { markReady(p); return st; }
    if (wakes.get(p.instance_id)?.error) return null;
    await new Promise((r) => setTimeout(r, 2000));
  }
  return null;
}

// ---- the waiting page -------------------------------------------------------------------------------------------------

const esc = (s: unknown) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!));

/** The page shown while the box wakes: self-contained, light and dark, polls its status and reloads (or links out, on the test page) once ready. */
export function waitingPage(p: StoredProfile, o: { statusUrl: string; startUrl: string | null; test: boolean; name: string | null }): string {
  const title = p.page.title || p.domains[0] || o.name || "This server";
  const message = p.page.message || "It sleeps while nobody is using it, to save energy and cost. It is waking up now and this page will continue on its own.";
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<title>${esc(title)}: waking up</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--ink:#16202a;--muted:#5d6b78;--line:#e1e6ec;--accent:#2563eb;--ok:#15803d;--bad:#b42318;color-scheme:light}
@media (prefers-color-scheme:dark){:root{--bg:#0e1318;--card:#151c23;--ink:#e6ebf0;--muted:#93a1ae;--line:#26313b;--accent:#7aa7ff;--ok:#4ade80;--bad:#f87171;color-scheme:dark}}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--ink);font:15px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;padding:24px}
.card{width:min(520px,100%);background:var(--card);border:1px solid var(--line);border-radius:14px;padding:28px 28px 22px}
h1{font-size:1.3rem;margin:0 0 6px;font-weight:650}p{margin:0 0 14px;color:var(--muted)}
.bar{height:6px;border-radius:99px;background:var(--line);overflow:hidden;margin:18px 0 10px}.bar i{display:block;height:100%;width:8%;background:var(--accent);border-radius:99px;transition:width .8s ease}
.row{display:flex;justify-content:space-between;gap:12px;font-size:.88rem;color:var(--muted)}.phase{color:var(--ink);font-weight:550}
.err{color:var(--bad)}.ok{color:var(--ok)}button,a.btn{font:inherit;border:1px solid var(--line);background:var(--card);color:var(--ink);border-radius:8px;padding:7px 14px;cursor:pointer;text-decoration:none;display:inline-block;margin-top:14px}
button:hover,a.btn:hover{border-color:var(--accent)}.small{font-size:.8rem;color:var(--muted);margin-top:16px}
@media (prefers-reduced-motion:reduce){.bar i{transition:none}}
</style></head><body><main class="card" role="status" aria-live="polite">
<h1>${esc(title)} is waking up</h1><p>${esc(message)}</p>
<div class="bar" aria-hidden="true"><i id="bar"></i></div>
<div class="row"><span class="phase" id="phase">Checking…</span><span id="time"></span></div>
<div id="extra"></div>
${o.test ? `<p class="small">Test page for ${esc(o.name || p.instance_id)} (${esc(p.instance_id)}), visible on the private network only. The automatic wake is ${p.enabled ? "on" : "off"} for this profile.</p>` : ""}
</main><script>
const statusUrl=${JSON.stringify(o.statusUrl)}, startUrl=${JSON.stringify(o.startUrl)}, test=${o.test ? "true" : "false"}, domain=${JSON.stringify(p.domains[0] ?? null)};
const words={asleep:"Asleep",starting:"Starting the server…",booting:"Server is up, waiting for the app to answer…",stopping:"Still shutting down from its last sleep…",ready:"Ready",error:"Could not wake it"};
let started=false;
function fmt(s){return s==null?"":s<60?s+"s":Math.floor(s/60)+"m "+(s%60)+"s"}
async function tick(){
  try{
    const r=await fetch(statusUrl,{cache:"no-store"}); const s=await r.json();
    document.getElementById("phase").textContent=words[s.phase]||s.phase;
    document.getElementById("phase").className="phase"+(s.phase==="error"?" err":s.phase==="ready"?" ok":"");
    const exp=s.expected_s||120, el=s.elapsed_s||0;
    document.getElementById("bar").style.width=(s.ready?100:Math.min(95,Math.max(8,el/exp*100)))+"%";
    document.getElementById("time").textContent=s.ready?"":(el?fmt(el)+" so far":"")+(s.expected_s?" · usually about "+fmt(s.expected_s):"");
    const x=document.getElementById("extra"); x.innerHTML="";
    if(s.error){const p=document.createElement("p");p.className="err";p.style.marginTop="12px";p.textContent=s.error;x.appendChild(p)}
    if(s.ready){ if(test){ if(domain){const a=document.createElement("a");a.className="btn";a.href="https://"+domain+"/";a.textContent="Open "+domain;x.appendChild(a)} return } location.reload(); return }
    if(test&&startUrl&&!started&&(s.phase==="asleep"||s.phase==="error")){const b=document.createElement("button");b.textContent="Start it now";b.onclick=async()=>{started=true;b.disabled=true;b.textContent="Starting…";await fetch(startUrl,{method:"POST"});tick()};x.appendChild(b)}
  }catch(e){document.getElementById("phase").textContent="Checking…"}
  setTimeout(tick,3000);
}
tick();
</script></body></html>`;
}

// ---- the server ------------------------------------------------------------------------------------------------------

const json = (res: http.ServerResponse, code: number, body: unknown, extra: Record<string, string> = {}) => { res.writeHead(code, { "content-type": "application/json", "cache-control": "no-store", ...extra }); res.end(JSON.stringify(body)); };

async function handle(req: http.IncomingMessage, res: http.ServerResponse) {
  const host = String(req.headers.host || "");
  const url = new URL(req.url || "/", "http://doorman");
  if (url.pathname === "/__wake/health") return json(res, 200, { ok: true });
  const p = profileForHost(host);

  // the test page: a person on the private network, never through a profile's own host
  const test = /^\/__wake\/test\/(i-[0-9a-f]{8,17})(\/status|\/start)?\/?$/.exec(url.pathname);
  if (test && !p) {
    if (!isPrivateAddress(req.socket.remoteAddress) || req.headers["x-forwarded-for"]) return json(res, 403, { error: "the test page is for the private network only" });
    const tp = getProfile(test[1]);
    if (!tp) return json(res, 404, { error: `no wake profile for ${test[1]}: save one on the instance's On-demand tab first` });
    if (test[2] === "/status") return json(res, 200, await statusOf(tp));
    if (test[2] === "/start") { if (req.method !== "POST") return json(res, 405, { error: "POST" }); const w = await wake(tp, "test-page", null); return json(res, w.error ? 409 : 202, { error: w.error, action_id: w.action_id }); }
    const name = (await statusOf(tp)).name;
    res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
    return res.end(waitingPage(tp, { statusUrl: `/__wake/test/${tp.instance_id}/status`, startUrl: `/__wake/test/${tp.instance_id}/start`, test: true, name }));
  }
  if (!p) { res.writeHead(404, { "content-type": "text/plain" }); return res.end("unknown host"); }

  if (url.pathname === "/__wake/status") return json(res, 200, await statusOf(p));
  const st = await boxState(p);
  if (st.ready && st.private_ip) { markReady(p); return proxyHttp(req, res, p, st.private_ip); }

  const ua = String(req.headers["user-agent"] || "");
  const why = filterReason(p, { host, path: url.pathname, ua });
  if (p.enabled && !why) wake(p, "visit", url.pathname, ua).catch((e) => console.error(`[doorman] wake ${p.instance_id}: ${e?.message || e}`));
  if (wantsPage(String(req.method), req.headers.accept)) {
    res.writeHead(503, { "content-type": "text/html; charset=utf-8", "retry-after": "15", "cache-control": "no-store" });
    return res.end(waitingPage(p, { statusUrl: "/__wake/status", startUrl: null, test: false, name: null }));
  }
  if (p.enabled && !why) {
    const ready = await holdUntilReady(p);
    if (ready?.private_ip) return proxyHttp(req, res, p, ready.private_ip);
  }
  return json(res, 503, { error: "the server is waking up", retry_after_s: 15, ...(why && p.enabled ? { not_woken: why } : {}) }, { "retry-after": "15" });
}

let server: http.Server | null = null;

/** Sets what the doorman believes about a box, as if just read (tests, which have no AWS to ask). */
export function primeBoxState(instanceId: string, st: Omit<BoxState, "at">, ttlMs = 60_000): void { boxCache.set(instanceId, { ...st, at: Date.now() + ttlMs - BOX_TTL_MS }); }

/** Starts the doorman on DOORMAN_PORT (0 = not started). */
export function startDoorman(): http.Server | null {
  if (!config.doormanPort || server) return server;
  server = createDoorman();
  const onListen = () => console.log(`[doorman] listening on ${config.bindAddr || "all interfaces"}:${config.doormanPort} (test page: /__wake/test/<instance-id> from the private network)`);
  if (config.bindAddr) server.listen(config.doormanPort, config.bindAddr, onListen); else server.listen(config.doormanPort, onListen);
  server.on("error", (e) => console.error(`[doorman] ${e.message}`));
  return server;
}

/** The doorman's server, not yet listening. */
export function createDoorman(): http.Server {
  const server = http.createServer((req, res) => { handle(req, res).catch((e) => { console.error(`[doorman] ${e?.message || e}`); if (!res.headersSent) json(res, 500, { error: "doorman error" }); else res.end(); }); });
  server.on("upgrade", (req, socket, head) => {
    (async () => {
      const p = profileForHost(String(req.headers.host || ""));
      if (!p) { socket.end("HTTP/1.1 404 Not Found\r\n\r\n"); return; }
      let st = await boxState(p);
      if (!st.ready) {
        const ua = String(req.headers["user-agent"] || "");
        const why = filterReason(p, { host: String(req.headers.host || ""), path: req.url || "/", ua });
        if (p.enabled && !why) { wake(p, "visit", req.url || "/", ua).catch(() => {}); st = (await holdUntilReady(p)) ?? st; }
      }
      if (st.ready && st.private_ip) return proxyUpgrade(req, socket as net.Socket, head, p, st.private_ip);
      socket.end("HTTP/1.1 503 Service Unavailable\r\nRetry-After: 15\r\nContent-Length: 0\r\n\r\n");
    })().catch(() => socket.destroy());
  });
  return server;
}

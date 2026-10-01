declare global { interface Window { __AUTH_TOKEN__?: string } }

// The index page injects a 30-day session token when the request was signed in (/?token=<API_TOKEN>); keep it for
// the next visit. An empty injection means "not signed in": fall back to whatever the browser kept.
try { if (window.__AUTH_TOKEN__) localStorage.setItem("advisor_token", window.__AUTH_TOKEN__); } catch { /* storage unavailable */ }

/** Sign in from the browser: the server checks the raw token and injects a session on the way back. */
export function signIn(apiToken: string) {
  const u = new URL(window.location.href);
  u.searchParams.set("token", apiToken.trim());
  window.location.assign(u.toString());
}
export function signOut() {
  try { localStorage.removeItem("advisor_token"); } catch { /* ignore */ }
  window.__AUTH_TOKEN__ = "";
  window.location.assign("/");
}

export function token(): string {
  return window.__AUTH_TOKEN__ || localStorage.getItem("advisor_token") || "";
}

// ---- the connection: retried reads and the "unstable connection" banner --------------------------------------------
//
// A flaky network shows up as fetch throwing ("Failed to fetch") or, behind the swarm's proxy while the advisor
// restarts, as a 502/503/504. Reads (GET) are safe to repeat, so they are retried with backoff and the page simply
// waits; changes (POST, PUT, DELETE) are never repeated by themselves, since a request lost on the way back may have
// been applied, and they fail with a message that says so. The banner (components/connection.tsx) shows while any
// request is retrying or the browser says it is offline.

export interface ConnectionState { trouble: boolean; offline: boolean; retrying: number; attempt: number; next_retry_at: number | null; recovered_at: number | null }
let conn: ConnectionState = { trouble: false, offline: typeof navigator !== "undefined" && navigator.onLine === false, retrying: 0, attempt: 0, next_retry_at: null, recovered_at: null };
const listeners = new Set<(s: ConnectionState) => void>();
const emit = (patch: Partial<ConnectionState>) => { conn = { ...conn, ...patch }; conn.trouble = conn.offline || conn.retrying > 0; for (const l of listeners) l(conn); };
export const connectionState = () => conn;
export function onConnectionChange(cb: (s: ConnectionState) => void): () => void { listeners.add(cb); return () => { listeners.delete(cb); }; }

let wakeWaiters: (() => void)[] = [];
/** Ends every pending backoff now (the banner's "Retry now", and the browser coming back online). */
export function retryNow() { const w = wakeWaiters; wakeWaiters = []; for (const f of w) f(); }
if (typeof window !== "undefined") {
  window.addEventListener("offline", () => emit({ offline: true }));
  window.addEventListener("online", () => { emit({ offline: false }); retryNow(); });
}

/** Backoff between read retries: 1, 2, 4, 8 s, then every 10 s; about three minutes in all before giving up. */
const BACKOFF_MS = [1000, 2000, 4000, 8000, ...Array(17).fill(10000)];
const RETRY_STATUS = new Set([502, 503, 504]);
const isNetworkError = (e: unknown) => e instanceof TypeError || (e as any)?.name === "NetworkError";

const sleep = (ms: number) => new Promise<void>((resolve) => { const t = setTimeout(() => { wakeWaiters = wakeWaiters.filter((f) => f !== wake); resolve(); }, ms); const wake = () => { clearTimeout(t); resolve(); }; wakeWaiters.push(wake); });

async function fetchWithRetry(url: string, init: RequestInit): Promise<Response> {
  const method = String(init.method || "GET").toUpperCase();
  const repeatable = method === "GET" || method === "HEAD";
  let counted = false;
  const settle = (ok: boolean) => {
    if (!counted) return;
    counted = false;
    const retrying = Math.max(0, conn.retrying - 1);
    emit({ retrying, attempt: retrying ? conn.attempt : 0, next_retry_at: retrying ? conn.next_retry_at : null, recovered_at: ok && retrying === 0 && !conn.offline ? Date.now() : conn.recovered_at });
  };
  for (let attempt = 0; ; attempt++) {
    try {
      const res = await fetch(url, init);
      if (!(repeatable && RETRY_STATUS.has(res.status) && attempt < BACKOFF_MS.length)) { settle(true); if (conn.offline && res.ok) emit({ offline: false }); return res; }
    } catch (e) {
      if ((e as any)?.name === "AbortError") { settle(false); throw e; }
      if (!isNetworkError(e)) { settle(false); throw e; }
      if (!repeatable) {
        emit({ recovered_at: null });
        throw new Error("Could not reach the advisor: the connection dropped. The change may or may not have been applied; reload to check before trying again.");
      }
      if (attempt >= BACKOFF_MS.length) { settle(false); throw new Error("Could not reach the advisor: the connection has been down for a few minutes. Check your network (or VPN) and reload."); }
    }
    if (!counted) { counted = true; emit({ retrying: conn.retrying + 1 }); }
    const wait = BACKOFF_MS[attempt];
    emit({ attempt: attempt + 1, next_retry_at: Date.now() + wait });
    await sleep(wait);
  }
}

export async function api<T = any>(path: string, init: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = { ...(init.headers as Record<string, string> || {}) };
  if (init.body && !headers["content-type"]) headers["content-type"] = "application/json";
  const t = token();
  if (t) headers["authorization"] = `Bearer ${t}`;
  const res = await fetchWithRetry(`/api${path}`, { ...init, headers });
  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`;
    try { const j = await res.json(); if (j?.error) msg = j.error; } catch { /* ignore */ }
    if (res.status === 401) { msg = "Not signed in or the session expired."; window.dispatchEvent(new Event("advisor:unauthorized")); }
    throw new Error(msg);
  }
  return res.json() as Promise<T>;
}

/** The probe's own machinery (the SSM worker that runs the document, its shell and tools) is always running when the probe looks: left out of the top-process lists (mirrors realProcesses in src/ssm.ts). */
const PROBE_MACHINERY = /^(ssm-document-wo\S*|ssm-agent-worke\S*|ssm-session-wor\S*|amazon-ssm-agen\S*|ps|awk|sh|bash|dash|sed|grep|sort|head|tail|tr|cat|docker|ss|who|last|df|free|uptime)$/;
export const realProcesses = <T extends { command: string }>(list: T[] | null | undefined): T[] => (list ?? []).filter((x) => !PROBE_MACHINERY.test(String(x.command).trim()));

export function stream(path: string): EventSource {
  const t = token();
  return new EventSource(`/api${path}${t ? `${path.includes("?") ? "&" : "?"}token=${encodeURIComponent(t)}` : ""}`);
}

export const usd = (v: number | null | undefined, digits = 0) =>
  v == null ? "—" : `$${Number(v).toLocaleString(undefined, { maximumFractionDigits: digits, minimumFractionDigits: digits })}`;

/** A ledger trigger for display: "person:<assumed-role arn>" shortens to the session name (the person's login), the full ARN goes in the title. */
export const triggerLabel = (t: string | null | undefined): { text: string; title?: string } => {
  const s = String(t ?? "");
  if (!s.startsWith("person:")) return { text: s };
  const arn = s.slice("person:".length);
  const who = arn.includes("/") ? arn.split("/").pop()! : arn.split(":").pop()!;
  return { text: `person: ${who}`, title: arn };
};
export const when = (iso: string | null | undefined) => (iso ? new Date(iso.endsWith("Z") || iso.includes("+") ? iso : iso + "Z").toLocaleString() : "—");

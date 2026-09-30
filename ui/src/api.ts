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

export async function api<T = any>(path: string, init: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = { ...(init.headers as Record<string, string> || {}) };
  if (init.body && !headers["content-type"]) headers["content-type"] = "application/json";
  const t = token();
  if (t) headers["authorization"] = `Bearer ${t}`;
  const res = await fetch(`/api${path}`, { ...init, headers });
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

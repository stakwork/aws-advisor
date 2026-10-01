/**
 * Wake profiles: how one parked instance is woken by its own traffic (docs: the wake-on-traffic plan). A profile
 * names the domains the box answers for, what the doorman (src/doorman.ts) does on each port while the box sleeps,
 * how to tell it is ready again, how it sleeps (hibernate when it can, or stop), what else must start first and what
 * to run after it wakes, and the filter that keeps internet scanners from waking it.
 *
 * Saving a profile changes nothing in AWS. `enabled` is the switch for the automatic wake: while it is off the
 * doorman still serves the waiting page (to try it from the VPN) but only a person's click starts the box. Every
 * save is mirrored onto the instance's AdvisorResource node in the graph.
 */
import { db } from "./db.js";
import { recordsNamingIp } from "./actions/schedule_hours.js";

db.exec(`create table if not exists wake_profiles (
  instance_id text primary key,
  enabled integer not null default 0,
  profile text not null,
  created_at text not null default (datetime('now')),
  updated_at text not null default (datetime('now')),
  updated_by text
)`);

export type PortBehaviour = "page" | "hold" | "redirect" | "ignore";
export interface WakePort { port: number; proto: "tcp" | "udp"; behaviour: PortBehaviour; note?: string | null }
export interface ReadyCheck { scheme: "http" | "https" | "tcp"; port: number; path: string; host: string | null; expect: string }
export interface WakeFilter { require_host_match: boolean; ignore_paths: string[]; ignore_user_agents: string; max_wakes_per_day: number }
export interface WakeProfile {
  instance_id: string;
  enabled: boolean;
  domains: string[];
  front_door: "dns" | "eip";
  ports: WakePort[];
  ready: ReadyCheck;
  sleep_mode: "auto" | "hibernate" | "stop";
  min_awake_minutes: number;
  hold_seconds: number;
  wake_with: string[];
  after_wake_command: string | null;
  before_park_command: string | null;
  filter: WakeFilter;
  page: { title: string | null; message: string | null };
  notify: boolean;
}

export const DEFAULT_FILTER: WakeFilter = {
  require_host_match: true,
  ignore_paths: ["/favicon.ico", "/robots.txt", "/.env", "/wp-login.php", "/.git/", "/actuator", "/cgi-bin/"],
  ignore_user_agents: "(bot|crawler|spider|scan|curl/|python-requests|go-http-client|zgrab|masscan|nmap|censys|shodan)",
  max_wakes_per_day: 6,
};

const DOMAIN = /^(?=.{1,253}$)(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const INSTANCE = /^i-[0-9a-f]{8,17}$/;

/** A profile from what the client sent, normalised, with the problems that block saving it. Pure. */
export function validateProfile(input: any, instanceId: string): { profile: WakeProfile; errors: string[] } {
  const errors: string[] = [];
  const num = (v: any, def: number, min: number, max: number, what: string) => {
    const n = v == null || v === "" ? def : Number(v);
    if (!Number.isFinite(n) || n < min || n > max) { errors.push(`${what} must be between ${min} and ${max}`); return def; }
    return Math.round(n);
  };
  const domains = [...new Set((Array.isArray(input?.domains) ? input.domains : String(input?.domains ?? "").split(/[\s,]+/)).map((d: any) => String(d).trim().toLowerCase().replace(/\.$/, "")).filter(Boolean))] as string[];
  for (const d of domains) if (!DOMAIN.test(d)) errors.push(`"${d}" is not a domain name`);
  const ports: WakePort[] = [];
  for (const p of Array.isArray(input?.ports) ? input.ports : []) {
    const port = Number(p?.port); const proto = p?.proto === "udp" ? "udp" : "tcp";
    const behaviour: PortBehaviour = ["page", "hold", "redirect", "ignore"].includes(p?.behaviour) ? p.behaviour : "ignore";
    if (!Number.isInteger(port) || port < 1 || port > 65535) { errors.push(`port ${p?.port} is not a port number`); continue; }
    if (proto === "udp" && behaviour !== "ignore") errors.push(`${port}/udp can only be ignored: UDP carries no host name to tell a real visit from a scanner`);
    if (ports.some((x) => x.port === port && x.proto === proto)) { errors.push(`${port}/${proto} is listed twice`); continue; }
    ports.push({ port, proto, behaviour: proto === "udp" ? "ignore" : behaviour, note: p?.note ? String(p.note).slice(0, 200) : null });
  }
  const r = input?.ready ?? {};
  const scheme = r.scheme === "http" || r.scheme === "tcp" ? r.scheme : "https";
  const ready: ReadyCheck = {
    scheme, port: num(r.port, scheme === "http" ? 80 : 443, 1, 65535, "the ready check's port"),
    path: scheme === "tcp" ? "" : String(r.path || "/").startsWith("/") ? String(r.path || "/").slice(0, 300) : `/${String(r.path).slice(0, 299)}`,
    host: r.host ? String(r.host).trim().toLowerCase() : null,
    expect: /^[1-5](\d\d|xx)(-[1-5]\d\d)?$/.test(String(r.expect || "")) ? String(r.expect) : "200-399",
  };
  if (ready.host && !DOMAIN.test(ready.host)) errors.push(`the ready check's host "${ready.host}" is not a domain name`);
  const wakeWith = [...new Set((Array.isArray(input?.wake_with) ? input.wake_with : String(input?.wake_with ?? "").split(/[\s,]+/)).map((x: any) => String(x).trim()).filter(Boolean))] as string[];
  for (const w of wakeWith) { if (!INSTANCE.test(w)) errors.push(`"${w}" is not an instance id`); else if (w === instanceId) errors.push("an instance cannot wake itself first"); }
  const f = input?.filter ?? {};
  const ua = f.ignore_user_agents == null ? DEFAULT_FILTER.ignore_user_agents : String(f.ignore_user_agents);
  try { if (ua) new RegExp(ua, "i"); } catch { errors.push("the user-agent filter is not a valid regular expression"); }
  const profile: WakeProfile = {
    instance_id: instanceId,
    enabled: Boolean(input?.enabled),
    domains,
    front_door: input?.front_door === "eip" ? "eip" : "dns",
    ports,
    ready,
    sleep_mode: input?.sleep_mode === "hibernate" || input?.sleep_mode === "stop" ? input.sleep_mode : "auto",
    min_awake_minutes: num(input?.min_awake_minutes, 60, 5, 24 * 60, "the minimum awake time (minutes)"),
    hold_seconds: num(input?.hold_seconds, 90, 5, 600, "the hold time (seconds)"),
    wake_with: wakeWith,
    after_wake_command: input?.after_wake_command ? String(input.after_wake_command).slice(0, 2000) : null,
    before_park_command: input?.before_park_command ? String(input.before_park_command).slice(0, 2000) : null,
    filter: {
      require_host_match: f.require_host_match !== false,
      ignore_paths: (Array.isArray(f.ignore_paths) ? f.ignore_paths : String(f.ignore_paths ?? DEFAULT_FILTER.ignore_paths.join(",")).split(/[\s,]+/)).map((x: any) => String(x).trim()).filter(Boolean).slice(0, 50),
      ignore_user_agents: ua,
      max_wakes_per_day: num(f.max_wakes_per_day, DEFAULT_FILTER.max_wakes_per_day, 1, 100, "wakes per day"),
    },
    page: { title: input?.page?.title ? String(input.page.title).slice(0, 120) : null, message: input?.page?.message ? String(input.page.message).slice(0, 600) : null },
    notify: input?.notify !== false,
  };
  if (profile.enabled && !profile.domains.length) errors.push("an enabled profile needs at least one domain: the doorman routes by host name");
  if (profile.enabled && !profile.ports.some((p) => p.behaviour !== "ignore")) errors.push("an enabled profile needs at least one port the doorman answers on (page, hold or redirect)");
  return { profile, errors };
}

/** What a new profile starts from: the A records naming the box, its listening ports, a ready check on the first web port. */
export function suggestProfile(instanceId: string): WakeProfile {
  const inv = db.prepare("select public_ip from inventory_ec2 where instance_id = ?").get(instanceId) as { public_ip: string | null } | undefined;
  const domains = [...new Set(recordsNamingIp(inv?.public_ip).map((r) => r.name.replace(/\.$/, "").toLowerCase()))].filter((d) => !d.startsWith("*."));
  let listening: { port: number; proto: string; scope: string; exposure: string; app_name: string | null }[] = [];
  try { listening = db.prepare("select port, proto, scope, exposure, app_name from instance_ports where instance_id = ? and gone = 0 order by port").all(instanceId) as any; } catch { /* no probe 1.8 yet */ }
  const ports: WakePort[] = [];
  for (const l of listening) {
    if (l.scope === "loopback" || l.exposure === "local") continue;
    const proto = l.proto === "udp" ? "udp" : "tcp";
    const behaviour: PortBehaviour = proto === "udp" ? "ignore" : l.port === 443 ? "page" : l.port === 80 ? "redirect" : l.exposure === "internet" ? "hold" : "ignore";
    ports.push({ port: l.port, proto, behaviour, note: l.app_name });
  }
  if (!ports.some((p) => p.port === 443 && p.proto === "tcp")) ports.unshift({ port: 443, proto: "tcp", behaviour: "page", note: null });
  if (!ports.some((p) => p.port === 80 && p.proto === "tcp")) ports.unshift({ port: 80, proto: "tcp", behaviour: "redirect", note: null });
  return validateProfile({
    enabled: false, domains, front_door: "dns", ports,
    ready: { scheme: "https", port: 443, path: "/", host: domains[0] ?? null, expect: "200-399" },
    sleep_mode: "auto", min_awake_minutes: 60, hold_seconds: 90, filter: DEFAULT_FILTER, notify: true,
  }, instanceId).profile;
}

export interface StoredProfile extends WakeProfile { created_at: string; updated_at: string; updated_by: string | null }

const rowToProfile = (r: any): StoredProfile => ({ ...(JSON.parse(r.profile) as WakeProfile), instance_id: r.instance_id, enabled: Boolean(r.enabled), created_at: r.created_at, updated_at: r.updated_at, updated_by: r.updated_by ?? null });

export function getProfile(instanceId: string): StoredProfile | null {
  const r = db.prepare("select * from wake_profiles where instance_id = ?").get(instanceId);
  return r ? rowToProfile(r) : null;
}

export function listProfiles(): (StoredProfile & { name: string | null; state: string | null })[] {
  return (db.prepare("select w.*, i.name, i.state from wake_profiles w left join inventory_ec2 i on i.instance_id = w.instance_id order by i.name").all() as any[])
    .map((r) => ({ ...rowToProfile(r), name: r.name ?? null, state: r.state ?? null }));
}

export class ProfileError extends Error { constructor(m: string, public status = 400, public errors: string[] = []) { super(m); this.name = "ProfileError"; } }

/** Saves a profile (validated; a domain may belong to one profile only). */
export function saveProfile(instanceId: string, input: any, by: string): StoredProfile {
  if (!INSTANCE.test(instanceId)) throw new ProfileError(`${instanceId} is not an instance id`);
  if (!db.prepare("select 1 from inventory_ec2 where instance_id = ?").get(instanceId)) throw new ProfileError(`${instanceId} is not in the inventory`, 404);
  const { profile, errors } = validateProfile(input, instanceId);
  for (const other of listProfiles()) {
    if (other.instance_id === instanceId) continue;
    for (const d of profile.domains) if (other.domains.includes(d)) errors.push(`${d} already belongs to the profile of ${other.name || other.instance_id}`);
  }
  if (errors.length) throw new ProfileError(errors.join("; "), 400, errors);
  const { instance_id: _i, enabled, ...body } = profile;
  db.prepare(`insert into wake_profiles(instance_id, enabled, profile, updated_by) values (?, ?, ?, ?)
    on conflict(instance_id) do update set enabled = excluded.enabled, profile = excluded.profile, updated_at = datetime('now'), updated_by = excluded.updated_by`)
    .run(instanceId, enabled ? 1 : 0, JSON.stringify(body), by);
  mirrorProfileInBackground(instanceId);
  return getProfile(instanceId)!;
}

export function deleteProfile(instanceId: string): boolean {
  const r = db.prepare("delete from wake_profiles where instance_id = ?").run(instanceId);
  if (r.changes) mirrorProfileInBackground(instanceId);
  return r.changes > 0;
}

/** The profile a request is for, by its Host header (port and trailing dot ignored; a *.domain entry covers one label). */
export function profileForHost(host: string | null | undefined): StoredProfile | null {
  const h = String(host || "").toLowerCase().replace(/:\d+$/, "").replace(/\.$/, "");
  if (!h) return null;
  const all = listProfiles();
  return all.find((p) => p.domains.includes(h)) ?? all.find((p) => p.domains.some((d) => d.startsWith("*.") && h.endsWith(d.slice(1)) && h.split(".").length === d.split(".").length)) ?? null;
}

function mirrorProfileInBackground(instanceId: string) {
  import("./graph_mirror.js").then((m) => (m as any).mirrorWakeProfile?.(instanceId)).catch((e) => console.error(`[graph] wake profile ${instanceId}: ${e?.message || e}`));
}

import { gunzipSync } from "node:zlib";
import { GetCommandInvocationCommand, SSMClient, SendCommandCommand } from "@aws-sdk/client-ssm";
import { config } from "./config.js";
import { recordContainerSamples } from "./history.js";
import { db } from "./db.js";
import { AWS_RUN_SHELL_SCRIPT, PermissionIssue, explainPermissionError, recordPermissionIssue, remedyFor, usesCustomProbeDocument } from "./permissions.js";
import { NoSdkCredentials, credentialRemedy } from "./aws_config.js";
import { S, credentialsMeta, query } from "./steampipe.js";
import { accountCredentials } from "./accounts.js";
import { checkProbeQuota } from "./quota.js";
import { checkDiskLevels } from "./disk_alerts.js";
import { applyProbeDisks } from "./ebs_inventory.js";
import { checkHostLevels } from "./host_alerts.js";
import { effectiveSignals } from "./signal_rules.js";

/**
 * The probes through AWS Systems Manager Run Command: sending one kind's document to a box (src/probes.ts holds the
 * scripts and documents), parsing the JSON it prints, storing the result with its kind, and reading an instance back
 * as one merged view (each section from its kind's latest row; a pre-2.0 combined probe counts for every section).
 * Tested on Amazon Linux 2023 and Ubuntu 24.04 (needs procps `ps --sort`).
 */
import { PROBE_DEFS, PROBE_KINDS, type ProbeKind, GZ_MARKER, PROBE_VERSION, SSM_OUTPUT_CAP, legacyProbeDocumentName, probeDocument as probeDocumentFor, probeDocumentInfo as probeDocumentInfoFor, probeDocumentName, probeDocumentsInfo, probeKindOf, probeScript } from "./probes.js";
export { PROBE_KINDS, PROBE_VERSION, GZ_MARKER, SSM_OUTPUT_CAP, probeScript, probeDocumentsInfo, type ProbeKind };
/** The host kind's document and info, for the places that still ask for "the" probe document. */
export const probeDocument = (kind: ProbeKind = "host") => probeDocumentFor(kind);
export const probeDocumentInfo = (kind: ProbeKind = "host") => probeDocumentInfoFor(kind);

/** device is the whole disk in sysfs terms (nvme0n1, xvda); volume_id the EBS volume read from the NVMe serial, null on Xen and for anything that is not EBS. Both absent from probes before 1.3. */
export interface ProbeDisk { mount: string; filesystem: string; device?: string | null; volume_id?: string | null; total_bytes: number; used_bytes: number; used_pct: number }
export interface ProbeProcess { pid: number; cpu_pct: number; mem_pct: number; rss_bytes: number; command: string }
export interface ProbeContainer { name: string; image: string; state: string; running_for: string; cpu_pct: number | null; mem_bytes: number; mem_pct: number | null; /** Cumulative since the container started (probe 1.4); the difference between probes is its traffic. */ net_rx_bytes?: number | null; net_tx_bytes?: number | null }

/** Probe docker 2.1: what one container is, from `docker inspect`. Labels are a fixed list (image source and revision, compose project and service); the environment and arguments are never read. */
export interface ProbeContainerDetail {
  id: string; name: string; created: string | null; image: string; image_id: string | null; state: string; health: string | null; exit_code: number | null; oom_killed: boolean;
  started_at: string | null; finished_at: string | null; restarts: number; restart_policy: string | null; privileged: boolean; network_mode: string | null; user: string | null;
  /** The program it starts (the entrypoint or the command's first word), no arguments. */
  entrypoint: string | null; networks: string[];
  ports: { container_port: number; proto: string; host_ip: string | null; host_port: number | null }[];
  mounts: { type: string; name: string | null; source: string | null; destination: string; rw: boolean }[];
  /** The repository the image is built from and the commit (OCI labels, or the older label-schema ones), its version and build date; the compose project, service, directory and files. */
  labels: { source: string | null; revision: string | null; version: string | null; built: string | null; title: string | null; compose_project: string | null; compose_service: string | null; compose_dir: string | null; compose_files: string[] };
}

/** Probe 1.4: what the last 24 h of a running container's log say about use. `last_lines` is untrusted text shown only in the UI. */
export interface ProbeContainerActivity {
  name: string; started_at: string | null; restarts: number; log_lines: number; last_log_at: string | null; errors: number; warns: number;
  /** Lines matching any use pattern (exact), the count per named pattern (a line can match two), and up to five recent distinct matched lines (untrusted text). */
  signal_lines: number; last_signal_at: string | null; signal_kinds: Record<string, number>; signal_samples: string[]; last_lines: string[];
}
export interface ProbeActivity {
  version: number;
  containers: ProbeContainerActivity[];
  /** Established TCP flows (conntrack sees the DNAT'd container traffic; ss covers host sockets). external = public peers, internal = RFC1918 peers other than docker bridges. */
  connections: { source: string; established: number; external: number; internal: number; peers: number; ssh: number; by_port: Record<string, number>;
    /** The busiest (peer, host port) pairs, so the drawer can say who is connected to what. */
    top_peers: { ip: string; port: number; flows: number; kind: "external" | "internal" }[];
    /** Published host port → container name, from `docker ps`. */
    port_map: Record<string, string> } | null;
  /** Requests on the front door (a proxy container's log over 24 h, or the host's access log tail), health checks counted apart. */
  front_door: { source: string | null; requests: number; health: number; last_request_at: string | null; last_request_raw: string | null; window: string | null };
  logins: { users_now: number; last_login_user: string | null; last_login_at: string | null };
  /** Host interface counters since boot (loopback and docker bridges excluded); the difference between probes is traffic. */
  net: { rx_bytes: number; tx_bytes: number } | null;
}

/** Probe 1.6: one CloudWatch log group an agent on the box is configured to write to, and which agent (cloudwatch-agent, awslogs, fluent-bit, fluentd, docker-daemon, docker:<container>). */
export interface ProbeLogShipping { group: string; via: string; source: string | null }
/** Probe 1.6: the processes of one program under one user, summed: how many, CPU now, resident memory, the oldest one's age, the program with its first words. */
export interface ProbeProcessGroup { name: string; user: string; count: number; cpu_pct: number; rss_bytes: number; oldest_seconds: number; command: string }
/** Probe 1.8: one port the box answers on. `scope` says which interfaces (all, loopback, one address); a host socket names its process and pid, a port a container publishes names the container and the port inside it. */
export interface ProbeListener { proto: "tcp" | "udp"; port: number; bind: string; scope: "all" | "loopback" | "address"; process: string | null; pid: number | null; container: string | null; container_port: number | null }

export interface ProbeResult {
  probe: string;
  hostname: string;
  collected_at: string;
  cpus: number;
  uptime_seconds: number;
  memory: { total_bytes: number; used_bytes: number; available_bytes: number; swap_total_bytes: number; swap_used_bytes: number };
  load: { "1m": number; "5m": number; "15m": number };
  disks: ProbeDisk[];
  top_cpu: ProbeProcess[];
  top_mem: ProbeProcess[];
  /** Present from probe 1.2: Docker daemon state and the containers on the box (running and stopped, up to 40). */
  docker?: { available: boolean; running: number; total: number };
  containers?: ProbeContainer[];
  /** Present from probe docker 2.1: each container's identity, image, health and wiring (up to 40). */
  container_details?: ProbeContainerDetail[];
  /** Present from probe 1.4: the use signals beyond CPU, memory and disk. */
  activity?: ProbeActivity;
  /** Present from probe 1.6: where the box's log agents ship to, and what runs on it (kernel threads excluded). */
  log_shipping?: ProbeLogShipping[];
  processes?: ProbeProcessGroup[];
  /** Present from probe 1.8: the listening ports, host sockets and published container ports alike. */
  listeners?: ProbeListener[];
  /** Probe 2.0: which kind printed this row ("all" for the pre-2.0 combined probe); on a merged view, when each kind last ran. */
  kind?: ProbeKind | "all";
  probes_at?: Partial<Record<ProbeKind | "all", string>>;
  /** The software probe: the OS, the kernel, every package, the versions of well-known programs, the container images. */
  os?: { id: string | null; version: string | null; name: string | null };
  kernel?: string | null;
  arch?: string | null;
  package_manager?: string | null;
  packages?: { n: string; v: string; a: string | null; s?: string | null }[];
  binaries?: { name: string; version: string; path: string | null }[];
  images?: { image: string; id: string | null; digests: string | null; created: string | null; platform: string | null }[];
}

/** Compact view of a probe used by the idle-instance rule and the UI. */
export interface ProbeSummary {
  collected_at: string;
  memory_used_pct: number;
  memory_total_gb: number;
  memory_used_gb: number;
  load_1m: number;
  cpus: number;
  top_process: string | null;
  containers_running?: number | null;
  top_container?: string | null;
  /** Probe 1.4: when the box was last really used, from the activity section. */
  last_use_at?: string | null;
  last_use_kind?: UseSummary["last_use_kind"];
}

export type ProbeErrorCode = "no_credentials" | "not_managed" | "permission" | "timeout" | "failed" | "bad_output";

export class ProbeError extends Error {
  /** For code "permission": the missing IAM action and the statement that grants it (recorded in permission_issues). */
  issue?: PermissionIssue;
  constructor(public code: ProbeErrorCode, message: string, issue?: PermissionIssue) {
    super(message);
    this.name = "ProbeError";
    if (issue) this.issue = issue;
  }
}

/** HTTP status a ProbeError maps to in the API. */
export const probeErrorStatus = (e: ProbeError): number =>
  ({ no_credentials: 400, not_managed: 404, permission: 403, timeout: 504, failed: 502, bad_output: 502 })[e.code];

const num = (v: unknown, what: string): number => {
  const n = typeof v === "number" ? v : Number(v);
  if (!Number.isFinite(n)) throw new ProbeError("bad_output", `probe output: ${what} is not a number`);
  return n;
};

/** Parses the command's stdout: tolerates noise before the JSON line and validates the shape. */
export function parseProbeOutput(stdout: string): ProbeResult {
  const lines = stdout.split("\n").map((l) => l.trim());
  let line: string | undefined;
  const packed = lines.filter((l) => l.startsWith(GZ_MARKER)).pop();
  if (packed) {
    // Probe 1.7 on a big box: the JSON is gzip-compressed and base64-encoded on one line so it fits under SSM's output cap.
    let text: string;
    try { text = gunzipSync(Buffer.from(packed.slice(GZ_MARKER.length), "base64")).toString("utf8").trim(); }
    catch (e: any) { throw new ProbeError("bad_output", `probe output is compressed but does not decode (${e?.message || e}); the line may have been cut off`); }
    if (text.startsWith("{") && text.endsWith("}")) line = text;
  } else line = lines.filter((l) => l.startsWith("{") && l.endsWith("}")).pop();
  if (!line) throw new ProbeError("bad_output", "probe output contained no JSON object");
  let raw: any;
  try { raw = JSON.parse(line); } catch (e: any) { throw new ProbeError("bad_output", `probe output is not valid JSON: ${e.message}`); }
  if (typeof raw?.probe !== "string" || !raw.probe.startsWith("aws-advisor/")) throw new ProbeError("bad_output", "probe output is not from the advisor probe");
  const kind = probeKindOf(raw);
  // a kind that does not own the host sections prints none; the merged view fills them from the host row
  const hostOwned = kind === "all" || kind === "host";
  const num = (v: unknown, what: string): number => { if (!hostOwned && v == null) return 0; const n = Number(v); if (!Number.isFinite(n)) throw new ProbeError("bad_output", `probe output has a bad ${what}`); return n; };
  const proc = (p: any): ProbeProcess => ({ pid: num(p.pid, "pid"), cpu_pct: num(p.cpu_pct, "cpu_pct"), mem_pct: num(p.mem_pct, "mem_pct"), rss_bytes: num(p.rss_bytes, "rss_bytes"), command: String(p.command ?? "") });
  const disk = (d: any): ProbeDisk => ({ mount: String(d.mount ?? ""), filesystem: String(d.filesystem ?? ""), device: d.device == null ? null : String(d.device), volume_id: d.volume_id == null ? null : String(d.volume_id), total_bytes: num(d.total_bytes, "total_bytes"), used_bytes: num(d.used_bytes, "used_bytes"), used_pct: num(d.used_pct, "used_pct") });
  const m = raw.memory || {};
  const l = raw.load || {};
  return {
    probe: raw.probe,
    hostname: String(raw.hostname ?? ""),
    collected_at: String(raw.collected_at || new Date().toISOString()),
    cpus: num(raw.cpus, "cpus"),
    uptime_seconds: num(raw.uptime_seconds, "uptime_seconds"),
    memory: {
      total_bytes: num(m.total_bytes, "memory.total_bytes"), used_bytes: num(m.used_bytes, "memory.used_bytes"), available_bytes: num(m.available_bytes, "memory.available_bytes"),
      swap_total_bytes: num(m.swap_total_bytes ?? 0, "memory.swap_total_bytes"), swap_used_bytes: num(m.swap_used_bytes ?? 0, "memory.swap_used_bytes"),
    },
    load: { "1m": num(l["1m"], "load.1m"), "5m": num(l["5m"], "load.5m"), "15m": num(l["15m"], "load.15m") },
    disks: Array.isArray(raw.disks) ? raw.disks.map(disk) : [],
    top_cpu: Array.isArray(raw.top_cpu) ? raw.top_cpu.map(proc) : [],
    top_mem: Array.isArray(raw.top_mem) ? raw.top_mem.map(proc) : [],
    docker: raw.docker && typeof raw.docker === "object" ? { available: Boolean(raw.docker.available), running: Number(raw.docker.running || 0), total: Number(raw.docker.total || 0) } : undefined,
    containers: Array.isArray(raw.containers) ? raw.containers.map((c: any): ProbeContainer => ({
      name: String(c.name ?? ""), image: String(c.image ?? ""), state: String(c.state ?? ""), running_for: String(c.running_for ?? ""),
      cpu_pct: c.cpu_pct == null ? null : Number(c.cpu_pct), mem_bytes: Number(c.mem_bytes || 0), mem_pct: c.mem_pct == null ? null : Number(c.mem_pct),
      net_rx_bytes: c.net_rx_bytes == null ? null : Number(c.net_rx_bytes), net_tx_bytes: c.net_tx_bytes == null ? null : Number(c.net_tx_bytes),
    })) : undefined,
    container_details: Array.isArray(raw.container_details) ? raw.container_details.filter((c: any) => c && typeof c.name === "string" && c.name).slice(0, 60).map(parseContainerDetail) : undefined,
    activity: raw.activity && typeof raw.activity === "object" ? parseActivity(raw.activity) : undefined,
    log_shipping: Array.isArray(raw.log_shipping) ? raw.log_shipping.filter((s: any) => s && typeof s.group === "string" && s.group).slice(0, 200).map((s: any): ProbeLogShipping => ({
      group: String(s.group).slice(0, 512), via: String(s.via || "unknown").slice(0, 120), source: s.source == null ? null : String(s.source).slice(0, 200) })) : undefined,
    processes: Array.isArray(raw.processes) ? raw.processes.filter((p: any) => p && typeof p.name === "string" && p.name).slice(0, 200).map((p: any): ProbeProcessGroup => ({
      name: String(p.name).slice(0, 64), user: String(p.user ?? "").slice(0, 64), count: Math.max(1, int(p.count)), cpu_pct: Number.isFinite(Number(p.cpu_pct)) ? Number(p.cpu_pct) : 0,
      rss_bytes: Math.max(0, int(p.rss_bytes)), oldest_seconds: Math.max(0, int(p.oldest_seconds)), command: String(p.command ?? p.name).slice(0, 120) })) : undefined,
    listeners: Array.isArray(raw.listeners) ? raw.listeners.filter((l: any) => l && (l.proto === "tcp" || l.proto === "udp") && Number.isInteger(Number(l.port)) && Number(l.port) > 0 && Number(l.port) < 65536).slice(0, 200).map((l: any): ProbeListener => ({
      proto: l.proto, port: Number(l.port), bind: String(l.bind ?? "").slice(0, 64), scope: l.scope === "loopback" || l.scope === "address" ? l.scope : "all",
      process: l.process == null ? null : String(l.process).slice(0, 64), pid: l.pid == null ? null : int(l.pid),
      container: l.container == null ? null : String(l.container).slice(0, 120), container_port: l.container_port == null ? null : int(l.container_port) })) : undefined,
    kind,
    os: raw.os && typeof raw.os === "object" ? { id: raw.os.id == null ? null : String(raw.os.id).slice(0, 40), version: raw.os.version == null ? null : String(raw.os.version).slice(0, 40), name: raw.os.name == null ? null : String(raw.os.name).slice(0, 120) } : undefined,
    kernel: raw.kernel === undefined ? undefined : raw.kernel == null ? null : String(raw.kernel).slice(0, 80),
    arch: raw.arch === undefined ? undefined : raw.arch == null ? null : String(raw.arch).slice(0, 20),
    package_manager: raw.package_manager === undefined ? undefined : raw.package_manager == null ? null : String(raw.package_manager).slice(0, 20),
    packages: Array.isArray(raw.packages) ? raw.packages.filter((p: any) => p && typeof p.n === "string" && p.n).slice(0, 20000).map((p: any) => ({ n: String(p.n).slice(0, 120), v: String(p.v ?? "").slice(0, 120), a: p.a == null || p.a === "" ? null : String(p.a).slice(0, 20) , s: p.s == null || p.s === "" ? null : String(p.s).slice(0, 120) })) : undefined,
    binaries: Array.isArray(raw.binaries) ? raw.binaries.filter((b: any) => b && typeof b.name === "string" && b.name).slice(0, 100).map((b: any) => ({ name: String(b.name).slice(0, 64), version: String(b.version ?? "").slice(0, 120), path: b.path == null ? null : String(b.path).slice(0, 200) })) : undefined,
    images: Array.isArray(raw.images) ? raw.images.filter((i: any) => i && typeof i.image === "string" && i.image).slice(0, 200).map((i: any) => ({ image: String(i.image).slice(0, 300), id: i.id == null || i.id === "" ? null : String(i.id).slice(0, 100), digests: i.digests == null || i.digests === "" ? null : String(i.digests).slice(0, 600), created: i.created == null || i.created === "" ? null : String(i.created).slice(0, 40), platform: i.platform == null || i.platform === "" ? null : String(i.platform).slice(0, 40) })) : undefined,
  };
}

const iso = (v: unknown): string | null => { if (typeof v !== "string" || !v) return null; const d = new Date(v); return Number.isNaN(d.getTime()) ? null : d.toISOString(); };
const MONTHS: Record<string, number> = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };
/** An access log's `25/Sep/2026:10:00:00 +0000` (nginx, Apache, Caddy's common format) as ISO, or null. */
export function parseClfDate(raw: unknown): string | null {
  const m = /^(\d{1,2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\s*([+-])(\d{2}):?(\d{2}))?/.exec(String(raw ?? "").trim());
  if (!m) return null;
  const mon = MONTHS[m[2].toLowerCase()]; if (mon == null) return null;
  const utc = Date.UTC(Number(m[3]), mon, Number(m[1]), Number(m[4]), Number(m[5]), Number(m[6]));
  const offset = m[7] ? (m[7] === "-" ? -1 : 1) * (Number(m[8]) * 60 + Number(m[9])) * 60000 : 0;
  const d = new Date(utc - offset);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}
const int = (v: unknown) => { const n = Number(v); return Number.isFinite(n) ? Math.round(n) : 0; };

const text = (v: unknown, max: number): string | null => (v == null || v === "" ? null : String(v).slice(0, max));
/** Docker's zero time (a container never started or never stopped) is no time. */
const dockerTime = (v: unknown): string | null => { const s = iso(v); return s && !s.startsWith("0001-") ? s : null; };

/** One `docker inspect` line, tolerant: the name loses its leading slash, ports become one row per published binding (or one unpublished row), labels fall back to the label-schema names. */
export function parseContainerDetail(c: any): ProbeContainerDetail {
  const l = c.labels && typeof c.labels === "object" ? c.labels : {};
  const ports: ProbeContainerDetail["ports"] = [];
  if (c.ports && typeof c.ports === "object") for (const [k, binds] of Object.entries(c.ports)) {
    const m = /^(\d+)\/(tcp|udp|sctp)$/.exec(k); if (!m) continue;
    const list = Array.isArray(binds) ? binds : [];
    if (!list.length) ports.push({ container_port: Number(m[1]), proto: m[2], host_ip: null, host_port: null });
    // the same host port bound on 0.0.0.0 and :: is one publication
    for (const b of list as any[]) { const hp = b?.HostPort ? int(b.HostPort) || null : null; if (!ports.some((p) => p.container_port === Number(m[1]) && p.proto === m[2] && p.host_port === hp)) ports.push({ container_port: Number(m[1]), proto: m[2], host_ip: text(b?.HostIp, 45), host_port: hp }); }
  }
  return {
    id: String(c.id ?? "").slice(0, 64), name: String(c.name).replace(/^\//, "").slice(0, 120), created: dockerTime(c.created), image: String(c.image ?? "").slice(0, 300), image_id: text(c.image_id, 100),
    state: String(c.state ?? "").slice(0, 20), health: text(c.health, 20), exit_code: c.exit_code == null ? null : int(c.exit_code), oom_killed: c.oom_killed === true,
    started_at: dockerTime(c.started_at), finished_at: dockerTime(c.finished_at), restarts: Math.max(0, int(c.restarts)), restart_policy: text(c.restart_policy, 30),
    privileged: c.privileged === true, network_mode: text(c.network_mode, 120), user: text(c.user, 64), entrypoint: text(c.entrypoint, 200),
    networks: String(c.networks ?? "").split(",").map((s) => s.trim()).filter(Boolean).slice(0, 20).map((s) => s.slice(0, 120)),
    ports: ports.slice(0, 60),
    mounts: (Array.isArray(c.mounts) ? c.mounts : []).filter((m: any) => m && m.destination).slice(0, 40).map((m: any) => ({ type: String(m.type ?? "").slice(0, 20), name: text(m.name, 200), source: text(m.source, 300), destination: String(m.destination).slice(0, 300), rw: m.rw !== false })),
    labels: { source: text(l.source, 300) ?? text(l.vcs_url, 300), revision: text(l.revision, 80) ?? text(l.vcs_ref, 80), version: text(l.version, 80), built: text(l.built, 40), title: text(l.title, 120),
      compose_project: text(l.compose_project, 120), compose_service: text(l.compose_service, 120), compose_dir: text(l.compose_dir, 300), compose_files: String(l.compose_files ?? "").split(",").map((s) => s.trim()).filter(Boolean).slice(0, 10).map((s) => s.slice(0, 300)) },
  };
}

/** Tolerant: a missing or malformed part becomes null or zero; the probe never fails on the activity section alone. */
export function parseActivity(a: any): ProbeActivity {
  const c = a.connections && typeof a.connections === "object" ? a.connections : null;
  const f = a.front_door && typeof a.front_door === "object" ? a.front_door : {};
  const l = a.logins && typeof a.logins === "object" ? a.logins : {};
  const byPort: Record<string, number> = {};
  if (c?.by_port && typeof c.by_port === "object") for (const [k, v] of Object.entries(c.by_port)) if (/^\d+$/.test(k)) byPort[k] = int(v);
  return {
    version: int(a.version) || 1,
    containers: Array.isArray(a.containers) ? a.containers.map((x: any): ProbeContainerActivity => ({
      name: String(x.name ?? ""), started_at: iso(x.started_at), restarts: int(x.restarts), log_lines: int(x.log_lines), last_log_at: iso(x.last_log_at),
      errors: int(x.errors), warns: int(x.warns), signal_lines: int(x.signal_lines), last_signal_at: iso(x.last_signal_at),
      signal_kinds: x.signal_kinds && typeof x.signal_kinds === "object" ? Object.fromEntries(Object.entries(x.signal_kinds).filter(([k]) => /^[a-z_]+$/.test(k)).map(([k, v]) => [k, int(v)])) : {},
      signal_samples: Array.isArray(x.signal_samples) ? x.signal_samples.slice(0, 5).map((s: unknown) => String(s).slice(0, 160)) : [],
      last_lines: Array.isArray(x.last_lines) ? x.last_lines.slice(0, 3).map((s: unknown) => String(s).slice(0, 160)) : [],
    })) : [],
    connections: c ? {
      source: String(c.source ?? "none"), established: int(c.established), external: int(c.external), internal: int(c.internal), peers: int(c.peers), ssh: int(c.ssh), by_port: byPort,
      top_peers: Array.isArray(c.top_peers) ? c.top_peers.filter((t: any) => t && typeof t.ip === "string").slice(0, 8).map((t: any) => ({ ip: String(t.ip).slice(0, 45), port: int(t.port), flows: int(t.flows), kind: t.kind === "internal" ? "internal" as const : "external" as const })) : [],
      port_map: c.port_map && typeof c.port_map === "object" ? Object.fromEntries(Object.entries(c.port_map).filter(([k]) => /^\d+$/.test(k)).map(([k, v]) => [k, String(v).slice(0, 80)])) : {},
    } : null,
    front_door: { source: f.source == null ? null : String(f.source), requests: int(f.requests), health: int(f.health), last_request_at: iso(f.last_request_at) ?? parseClfDate(f.last_request_raw), last_request_raw: f.last_request_raw == null ? null : String(f.last_request_raw).slice(0, 80), window: f.window == null ? null : String(f.window) },
    logins: { users_now: int(l.users_now), last_login_user: l.last_login_user == null ? null : String(l.last_login_user).slice(0, 64), last_login_at: iso(l.last_login_at) },
    net: a.net && typeof a.net === "object" ? { rx_bytes: int(a.net.rx_bytes), tx_bytes: int(a.net.tx_bytes) } : null,
  };
}

/** The one line the drawer, the review and the rules want: when this box was last really used, and by what evidence. */
export interface UseSummary {
  /** The newest of the signals below, or null when the probe has none. */
  last_use_at: string | null;
  last_use_kind: "signal_line" | "request" | "login" | "external_connection" | null;
  external_connections_now: number;
  ssh_sessions_now: number;
  users_now: number;
  requests_24h: number | null;
  health_checks_24h: number | null;
  signal_lines_24h: number;
  containers_logging_24h: number;
  containers_running: number;
  restarting_containers: string[];
}

/** A container's use-signal count after the image's rules (src/signal_rules.ts); a container whose every matched kind is noise has no last use. */
export function containerSignals(p: ProbeResult, c: ProbeContainerActivity): { signal_lines: number; last_signal_at: string | null; noise_kinds: string[] } {
  const image = p.containers?.find((x) => x.name === c.name)?.image ?? "";
  const eff = effectiveSignals(image, c.signal_kinds, c.signal_lines);
  return { signal_lines: eff.signal_lines, last_signal_at: eff.signal_lines > 0 ? c.last_signal_at : null, noise_kinds: eff.noise_kinds };
}

export function useSummary(p: ProbeResult): UseSummary | null {
  const a = p.activity; if (!a) return null;
  const cands: { at: string; kind: UseSummary["last_use_kind"] }[] = [];
  const eff = a.containers.map((c) => containerSignals(p, c));
  for (const e of eff) if (e.last_signal_at) cands.push({ at: e.last_signal_at, kind: "signal_line" });
  if (a.front_door.last_request_at) cands.push({ at: a.front_door.last_request_at, kind: "request" });
  if (a.logins.last_login_at) cands.push({ at: a.logins.last_login_at, kind: "login" });
  if (a.connections && a.connections.external > 0) cands.push({ at: iso(p.collected_at) ?? p.collected_at, kind: "external_connection" });
  cands.sort((x, y) => y.at.localeCompare(x.at));
  return {
    last_use_at: cands[0]?.at ?? null, last_use_kind: cands[0]?.kind ?? null,
    external_connections_now: a.connections?.external ?? 0, ssh_sessions_now: a.connections?.ssh ?? 0, users_now: a.logins.users_now,
    requests_24h: a.front_door.source ? a.front_door.requests : null, health_checks_24h: a.front_door.source ? a.front_door.health : null,
    signal_lines_24h: eff.reduce((s, e) => s + e.signal_lines, 0),
    containers_logging_24h: a.containers.filter((c) => c.log_lines > 0).length,
    containers_running: a.containers.length,
    restarting_containers: a.containers.filter((c) => c.restarts >= 10).map((c) => c.name),
  };
}

/** The probe's own machinery, which is always running at the moment the probe looks: the SSM worker that runs the document, its shell and the tools the script pipes through. Never "the busiest process". */
export const PROBE_MACHINERY = /^(ssm-document-wo\S*|ssm-agent-worke\S*|ssm-session-wor\S*|amazon-ssm-agen\S*|ps|awk|sh|bash|dash|sed|grep|sort|head|tail|tr|cat|docker|ss|who|last|df|free|uptime)$/;
/** The process list without the probe's own machinery. Pure. */
export const realProcesses = <T extends { command: string }>(list: T[] | undefined): T[] => (list ?? []).filter((x) => !PROBE_MACHINERY.test(String(x.command).trim()));

export function summarizeProbe(p: ProbeResult): ProbeSummary {
  const gb = (b: number) => Math.round((b / 1024 ** 3) * 10) / 10;
  return {
    collected_at: p.collected_at,
    memory_used_pct: p.memory.total_bytes > 0 ? Math.round((100 * p.memory.used_bytes) / p.memory.total_bytes) : 0,
    memory_total_gb: gb(p.memory.total_bytes),
    memory_used_gb: gb(p.memory.used_bytes),
    load_1m: p.load["1m"],
    cpus: p.cpus,
    top_process: realProcesses(p.top_cpu)[0]?.command || realProcesses(p.top_mem)[0]?.command || null,
    containers_running: p.docker?.available ? p.docker.running : null,
    top_container: p.containers?.length ? [...p.containers].filter((c) => c.state === "running").sort((a, b) => (b.mem_bytes || 0) - (a.mem_bytes || 0))[0]?.name || null : null,
    ...(p.activity ? { last_use_at: useSummary(p)!.last_use_at, last_use_kind: useSummary(p)!.last_use_kind } : {}),
  };
}

export interface StoredProbe { id: number; instance_id: string; collected_at: string; data: ProbeResult; kind?: ProbeKind | "all" }

type MetricsRow = { id: number; instance_id: string; collected_at: string; json: string; kind?: string | null };
const rowToProbe = (r: MetricsRow): StoredProbe => ({ id: r.id, instance_id: r.instance_id, collected_at: r.collected_at, data: JSON.parse(r.json) as ProbeResult, kind: (r.kind as any) || "all" });

/** The kinds a stored row speaks for: its own, or host, docker and apps for the pre-2.0 combined probe (it never carried software). */
const LEGACY_KINDS: readonly ProbeKind[] = ["host", "docker", "apps"];
const kindsOfRow = (kind: string | null | undefined): readonly ProbeKind[] => (!kind || kind === "all" ? LEGACY_KINDS : [kind as ProbeKind]);

/**
 * One instance as a single view: for each section, the newest row of a kind that owns it (a pre-2.0 combined row owns
 * every section). `collected_at` is the newest of them; `probes_at` says when each kind last ran; `kind` is "all".
 * Null when the instance was never probed.
 */
export function mergeProbes(rows: StoredProbe[]): StoredProbe | null {
  if (!rows.length) return null;
  const sorted = [...rows].sort((x, y) => x.collected_at.localeCompare(y.collected_at));
  const newestFor = (kind: ProbeKind) => sorted.filter((r) => kindsOfRow(r.kind).includes(kind)).pop();
  const latest = sorted[sorted.length - 1];
  const host = newestFor("host") ?? latest;
  const out: ProbeResult = { ...host.data, kind: "all", probes_at: {} };
  for (const kind of PROBE_KINDS) {
    const r = newestFor(kind);
    if (!r) continue;
    out.probes_at![kind] = r.collected_at;
    for (const section of PROBE_DEFS[kind].sections) (out as any)[section] = (r.data as any)[section];
  }
  out.collected_at = latest.collected_at;
  out.hostname = out.hostname || latest.data.hostname;
  return { id: latest.id, instance_id: latest.instance_id, collected_at: latest.collected_at, data: out, kind: "all" };
}

/** The newest stored row per kind (and the newest pre-2.0 row) of one instance. */
export function latestProbeRows(instanceId: string): StoredProbe[] {
  const rows = db.prepare("select id, instance_id, collected_at, json, kind from instance_metrics where instance_id = ? and id in (select max(id) from instance_metrics where instance_id = ? group by kind)").all(instanceId, instanceId) as MetricsRow[];
  const out: StoredProbe[] = [];
  for (const r of rows) { try { out.push(rowToProbe(r)); } catch { /* malformed */ } }
  return out;
}

/** The merged view of one instance (see mergeProbes), or null. */
export function latestProbe(instanceId: string): StoredProbe | null {
  return mergeProbes(latestProbeRows(instanceId));
}

/** Latest merged probe per instance, as summaries keyed by instance id (for the rules). */
export function latestProbeSummaries(): Record<string, ProbeSummary> {
  const rows = db.prepare("select id, instance_id, collected_at, json, kind from instance_metrics where id in (select max(id) from instance_metrics group by instance_id, kind)").all() as MetricsRow[];
  const byInstance = new Map<string, StoredProbe[]>();
  for (const r of rows) { try { byInstance.set(r.instance_id, [...(byInstance.get(r.instance_id) || []), rowToProbe(r)]); } catch { /* skip malformed */ } }
  const out: Record<string, ProbeSummary> = {};
  for (const [id, list] of byInstance) { const m = mergeProbes(list); if (m) out[id] = summarizeProbe(m.data); }
  return out;
}

/** The host rows of an instance, newest first: the series behind the memory, load and disk charts. */
export function instanceMetrics(instanceId: string, limit = 20): StoredProbe[] {
  const rows = db.prepare("select id, instance_id, collected_at, json, kind from instance_metrics where instance_id = ? and coalesce(kind, 'all') in ('host', 'all') order by id desc limit ?").all(instanceId, limit) as MetricsRow[];
  return rows.map(rowToProbe);
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const sqlLit = (s: string) => `'${s.replace(/'/g, "''")}'`;

function classifyAwsError(e: any, instanceId: string, operation: "SendCommand" | "GetCommandInvocation", document = config.probeDocument): ProbeError {
  const name: string = e?.name || e?.Code || "";
  const msg: string = e?.message || String(e);
  // A denial names the action in its message; when it does not (UnauthorizedOperation, AccessDeniedException alone), the context does.
  const issue = explainPermissionError(e, `ssm ${operation} ${instanceId} (ssm:${operation}, document ${document})`);
  if (issue) {
    recordPermissionIssue(issue);
    return new ProbeError("permission", `The advisor's AWS credentials cannot run SSM commands (${name || "AccessDenied"}); ssm:SendCommand on document ${document} and instance ${instanceId}, plus ssm:GetCommandInvocation, are required. ${msg.replace(/[.\s]+$/, "")}. ${remedyFor(issue)}`, issue);
  }
  if (/InvalidSignature|UnrecognizedClient|ExpiredToken|InvalidClientTokenId|SignatureDoesNotMatch|InvalidAccessKeyId|CredentialsProviderError|Could not load credentials|sso|Token is expired/i.test(`${name} ${msg}`)) {
    const meta = credentialsMeta();
    return new ProbeError("permission", `The advisor's AWS credentials were rejected by SSM (${name || "credential error"}); ${meta ? credentialRemedy(e, meta) : `save valid credentials in Settings. ${msg}`}`);
  }
  if (/InvalidInstanceId/i.test(name)) return new ProbeError("not_managed", `${instanceId} is not an SSM-managed instance or is not online (${msg})`);
  if (/InvalidDocument\b/i.test(name)) return new ProbeError("failed", `SSM document ${document} does not exist in this region or account; create it with the command on Settings > Probes or run the setup script. ${msg}`);
  return new ProbeError("failed", `${name ? name + ": " : ""}${msg}`);
}

export interface ProbeOptions { timeoutMs?: number; kind?: ProbeKind; /** the member account the instance lives in (src/accounts.ts); default: what the SSM inventory says, else the parent */ accountId?: string | null }

/**
 * Sends one kind's probe to one SSM-managed instance, waits for it, parses and stores the result, and runs the hooks
 * that kind feeds (disk and host alerts for host; container samples for docker; apps, ports and their verdicts for
 * apps; the software inventory for software). A missing per-kind document falls back to the pre-2.0 combined document
 * once per process for host, docker and apps, so a fleet still on the old document keeps probing until it is updated.
 */
export async function probeInstance(instanceId: string, opts: ProbeOptions = {}): Promise<StoredProbe> {
  const kind: ProbeKind = opts.kind ?? "host";
  if (!/^i-[0-9a-f]{8,17}$/.test(instanceId)) throw new ProbeError("not_managed", `"${instanceId}" is not an EC2 instance id`);
  checkProbeQuota(instanceId);
  // The same identity Steampipe uses (keys, profile or default chain, with the role when one is set), as an SDK provider.
  // A member's instance (src/accounts.ts) is probed through that member's read role: SendCommand must run in its account.
  const managed = await query<{ ping_status: string; region: string; platform_type: string; account_id: string | null }>(
    `select ping_status, region, platform_type, account_id from ${S}.aws_ssm_managed_instance where instance_id = ${sqlLit(instanceId)} limit 1`);
  if (!managed.length) throw new ProbeError("not_managed", `${instanceId} is not registered with Systems Manager (no SSM agent, no instance profile, or outside the connection's regions)`);
  const m = managed[0];
  if (m.ping_status !== "Online") throw new ProbeError("not_managed", `${instanceId} is registered with SSM but its agent is ${m.ping_status}`);
  if (m.platform_type && m.platform_type !== "Linux") throw new ProbeError("not_managed", `${instanceId} runs ${m.platform_type}; the probe is Linux-only`);
  let creds: ReturnType<typeof accountCredentials>;
  try { creds = accountCredentials(opts.accountId ?? (m.account_id ? String(m.account_id) : null)); }
  catch (e: any) { throw new ProbeError("no_credentials", `${e instanceof NoSdkCredentials ? e.message : String(e?.message || e)}; the probe uses the credentials saved in Settings.`); }

  const client = new SSMClient({ region: m.region || creds.region, credentials: creds.provider });
  const def = PROBE_DEFS[kind];
  const timeoutMs = opts.timeoutMs ?? Math.max(90_000, def.timeout_seconds * 1000 + 30_000);
  try {
    let commandId = "";
    let documentUsed = probeDocumentName(kind);
    try {
      const send = (document: string, withSignals: boolean) => client.send(new SendCommandCommand({
        DocumentName: document,
        InstanceIds: [instanceId],
        ...(withSignals ? { Parameters: { signals: [config.probeSignals] } } : {}),
        TimeoutSeconds: def.timeout_seconds,
        Comment: `aws-advisor probe ${kind} ${def.version}`,
      }));
      let sent;
      try { sent = await send(documentUsed, def.takes_signals); }
      catch (e: any) {
        const name = String(e?.name || e?.Code || "");
        // the per-kind document is not deployed yet: the combined pre-2.0 document covers host, docker and apps
        if (/InvalidDocument\b/i.test(name) && kind !== "software" && legacyProbeDocumentName() !== documentUsed) {
          if (!warnedLegacyDocument.has(kind)) { warnedLegacyDocument.add(kind); console.warn(`[probe] SSM document ${documentUsed} does not exist; probing ${kind} through the pre-2.0 combined document ${legacyProbeDocumentName()} until it is created (Settings > Probes)`); }
          documentUsed = legacyProbeDocumentName();
          try { sent = await send(documentUsed, true); }
          catch (e2: any) {
            if (!/InvalidParameters/i.test(String(e2?.name || e2?.message))) throw e2;
            sent = await send(documentUsed, false); // a document from before 1.5 has no signals parameter
          }
        } else throw e;
      }
      commandId = sent.Command?.CommandId || "";
      if (!commandId) throw new ProbeError("failed", "SSM returned no command id");
    } catch (e: any) {
      if (e instanceof ProbeError) throw e;
      throw classifyAwsError(e, instanceId, "SendCommand", documentUsed);
    }

    const deadline = Date.now() + timeoutMs;
    let stdout = "", stderr = "";
    for (;;) {
      await sleep(2000);
      if (Date.now() > deadline) throw new ProbeError("timeout", `SSM command ${commandId} did not finish within ${Math.round(timeoutMs / 1000)}s`);
      let status = "";
      try {
        const inv = await client.send(new GetCommandInvocationCommand({ CommandId: commandId, InstanceId: instanceId }));
        status = inv.Status || "";
        if (status === "Success") { stdout = inv.StandardOutputContent || ""; stderr = inv.StandardErrorContent || ""; break; }
        if (!["Pending", "InProgress", "Delayed", ""].includes(status)) {
          // The agent reports a script that died, or one it could not even stage (root disk full), as a bare "Failed" with
          // nothing on stderr: the reason, when there is one, is at the end of stdout, so that goes into the message too.
          const stderr = (inv.StandardErrorContent || "").trim();
          const tail = (inv.StandardOutputContent || "").trim().slice(-300);
          const why = [inv.StatusDetails && inv.StatusDetails !== status ? inv.StatusDetails : "", stderr.slice(0, 400), tail ? `stdout tail: ${tail}` : ""].filter(Boolean).join("; ");
          throw new ProbeError("failed", `SSM command ${commandId} ended with ${status}${why ? `: ${why}` : " and no output (the agent could not run the script: a full root disk is the usual cause)"}`);
        }
      } catch (e: any) {
        if (e instanceof ProbeError) throw e;
        if (e?.name === "InvocationDoesNotExist") continue; // the invocation is not registered yet
        throw classifyAwsError(e, instanceId, "GetCommandInvocation", documentUsed);
      }
    }

    let data: ProbeResult;
    try { data = parseProbeOutput(stdout); }
    catch (e: any) {
      if (!(e instanceof ProbeError) || e.code !== "bad_output") throw e;
      // GetCommandInvocation returns the first 24,000 characters of stdout and the JSON is the last line, so a big box
      // loses the end of it; say so, and show the tail and stderr so the reason is visible without the AWS console.
      const truncated = stdout.length >= SSM_OUTPUT_CAP || /---Output truncated---/.test(stdout);
      const tail = stdout.trim().slice(-200).replace(/\s+/g, " ");
      const detail = [`${stdout.length} chars of stdout${truncated ? ` (SSM caps the command output at ${SSM_OUTPUT_CAP} characters, the probe's JSON line was cut off)` : ""}`, tail ? `tail: ${tail}` : "", stderr.trim() ? `stderr: ${stderr.trim().slice(0, 300)}` : ""].filter(Boolean).join("; ");
      throw new ProbeError("bad_output", `${e.message}: ${detail}`);
    }
    const stored = (data.kind ?? "all") as ProbeKind | "all";
    const collectedAt = data.collected_at;
    const id = Number(db.prepare("insert into instance_metrics(instance_id, collected_at, json, kind) values (?, ?, ?, ?)").run(instanceId, collectedAt, JSON.stringify(data), stored).lastInsertRowid);
    runProbeHooks(instanceId, id, collectedAt, data, kindsOfRow(stored));
    return { id, instance_id: instanceId, collected_at: collectedAt, data, kind: stored };
  } finally {
    client.destroy();
  }
}
const warnedLegacyDocument = new Set<ProbeKind>();

/** What each kind feeds once its row is stored; a combined row runs every hook. Failures are logged, never thrown. */
function runProbeHooks(instanceId: string, rowId: number, collectedAt: string, data: ProbeResult, kinds: readonly ProbeKind[]): void {
  const name = (db.prepare("select name from inventory_ec2 where instance_id = ?").get(instanceId) as { name: string | null } | undefined)?.name ?? null;
  if (kinds.includes("host")) {
    try { applyProbeDisks(instanceId, data.disks, collectedAt); } catch (e: any) { console.error(`[probe] disk usage not credited to volumes for ${instanceId}: ${e?.message || e}`); }
    try { checkDiskLevels(instanceId, name, data.disks as any, collectedAt); checkHostLevels(instanceId, name, rowId, collectedAt, data); } catch (e: any) { console.error(`[probe] disk or host levels not checked for ${instanceId}: ${e?.message || e}`); }
  }
  if (kinds.includes("docker")) {
    try { recordContainerSamples(instanceId, collectedAt, data); } catch (e: any) { console.error(`[probe] container samples not recorded for ${instanceId}: ${e?.message || e}`); }
    // docker 2.1: what each container is and what changed, then the graph's AdvisorContainer nodes
    void (async () => {
      try {
        const { recordContainers } = await import("./container_inventory.js");
        const r = recordContainers(instanceId, collectedAt, data);
        if (r?.events.length) console.log(`[probe] ${instanceId} containers: ${r.containers}, ${r.events.slice(0, 6).map((e) => `${e.name} ${e.event.replace("container_", "")}`).join(", ")}${r.events.length > 6 ? ", ..." : ""}`);
        if (r) import("./graph_containers.js").then((m) => m.mirrorContainersInBackground([instanceId])).catch(() => { /* graph off */ });
      } catch (e: any) { console.error(`[probe] containers not recorded for ${instanceId}: ${e?.message || e}`); }
    })();
  }
  if (kinds.includes("apps")) {
    // probe 1.6 / 1.8: what runs here and what listens go to the apps and ports tables, then to the graph with their reachability verdicts
    void (async () => {
      try {
        const { recordApps, recordPorts } = await import("./instance_apps.js");
        const r = recordApps(instanceId, collectedAt, data, name);
        const pr = recordPorts(instanceId, collectedAt, data, name);
        if (pr && (pr.opened.length || pr.closed.length)) console.log(`[probe] ${instanceId} ports: ${pr.ports} listening${pr.opened.length ? `, opened ${pr.opened.join(", ")}` : ""}${pr.closed.length ? `, closed ${pr.closed.join(", ")}` : ""}${pr.alerts ? `, ${pr.alerts} alert(s)` : ""}`);
        if (r && (r.appeared.length || r.disappeared.length || r.returned.length)) console.log(`[probe] ${instanceId} apps: ${r.apps} running${r.appeared.length ? `, appeared ${r.appeared.join(", ")}` : ""}${r.disappeared.length ? `, disappeared ${r.disappeared.join(", ")}` : ""}${r.returned.length ? `, returned ${r.returned.join(", ")}` : ""}`);
        const { mirrorAppsInBackground } = await import("./graph_mirror.js");
        mirrorAppsInBackground([instanceId]);
      } catch (e: any) { console.error(`[probe] apps not recorded for ${instanceId}: ${e?.message || e}`); }
    })();
  }
  if (kinds.includes("software")) {
    void (async () => {
      try {
        const { recordSoftware } = await import("./software_inventory.js");
        const r = recordSoftware(instanceId, collectedAt, data as any);
        if (r) console.log(`[probe] ${instanceId} software: ${r.packages} packages${r.changed.length ? `, ${r.changed.length} changed (${r.changed.slice(0, 3).map((c) => `${c.name} ${c.from} -> ${c.to}`).join("; ")}${r.changed.length > 3 ? ", ..." : ""})` : ""}${r.added.length ? `, ${r.added.length} added` : ""}${r.removed.length ? `, ${r.removed.length} removed` : ""}, ${r.binaries} program versions, ${r.images} images`);
        if (r) import("./graph_software.js").then((m) => m.mirrorSoftwareInBackground([instanceId])).catch(() => { /* graph off */ });
      } catch (e: any) { console.error(`[probe] software not recorded for ${instanceId}: ${e?.message || e}`); }
    })();
  }
}

/** Every kind in turn (host, docker, apps, software unless `kinds` narrows it); the merged view afterwards, and which kinds failed. */
export async function probeInstanceAll(instanceId: string, kinds: readonly ProbeKind[] = PROBE_KINDS): Promise<{ probe: StoredProbe | null; ran: ProbeKind[]; failed: { kind: ProbeKind; code: string; message: string }[] }> {
  const ran: ProbeKind[] = []; const failed: { kind: ProbeKind; code: string; message: string }[] = [];
  for (const kind of kinds) {
    try { await probeInstance(instanceId, { kind }); ran.push(kind); }
    catch (e: any) { failed.push({ kind, code: e instanceof ProbeError ? e.code : "failed", message: String(e?.message || e).slice(0, 300) }); if (e instanceof ProbeError && (e.code === "no_credentials" || e.code === "not_managed" || e.code === "permission")) break; }
  }
  return { probe: latestProbe(instanceId), ran, failed };
}

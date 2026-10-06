/**
 * What runs on each instance, from the probe's process list (probe 1.6, src/ssm.ts): the applications, with the
 * operating system's own daemons and the probe's utilities set aside, and the platform pieces (container runtime,
 * monitoring agents) kept but marked `infra`. One row per instance, program and user with first and last seen,
 * and an event when a program appears, disappears or comes back, so a box can be watched for what it is running,
 * not only how busy it is. A long-running application that vanishes raises an `app_gone` alert. The graph carries
 * the same as (:AdvisorResource)-[:RUNS]->(:AdvisorApp) (src/graph_mirror.ts).
 */
import { db } from "./db.js";
import type { ProbeListener, ProbeProcessGroup, ProbeResult } from "./ssm.js";
import { alertInsert } from "./alert_store.js";
import { AWS } from "./adapters/types.js";

db.exec(`
create table if not exists instance_apps (
  instance_id text not null, name text not null, user text not null, kind text not null,
  command text, count integer, cpu_pct real, rss_bytes real, oldest_seconds integer,
  first_seen text not null, last_seen text not null, probes integer not null default 1, gone integer not null default 0,
  primary key (instance_id, name, user)
);
create table if not exists instance_app_events (
  id integer primary key autoincrement, instance_id text not null, name text not null, user text not null,
  event text not null, at text not null, details text
);
create index if not exists instance_app_events_instance on instance_app_events(instance_id, at);
create index if not exists instance_app_events_at on instance_app_events(at);
create table if not exists instance_ports (
  instance_id text not null, proto text not null, port integer not null, bind text, scope text not null,
  process text, pid integer, container text, container_port integer, app_name text, exposure text not null,
  first_seen text not null, last_seen text not null, probes integer not null default 1, gone integer not null default 0,
  primary key (instance_id, proto, port)
);
create table if not exists sg_ingress (
  group_id text not null, region text, ip_protocol text, from_port integer, to_port integer, cidr_ipv4 text, cidr_ipv6 text, referenced_group_id text, prefix_list_id text, refreshed_at text not null
);
create index if not exists sg_ingress_group on sg_ingress(group_id);`);
db.exec(`create table if not exists nacls (
  acl_id text primary key, vpc_id text, region text, is_default integer not null default 0, subnets text not null default '[]', entries text not null default '[]', refreshed_at text not null
)`);
try { db.exec("alter table sg_ingress add column rule_id text"); } catch { /* exists */ }
try { db.exec("alter table sg_ingress add column description text"); } catch { /* exists */ }

export type AppKind = "app" | "infra";
export interface AppRow { name: string; user: string; kind: AppKind; command: string; count: number; cpu_pct: number; rss_bytes: number; oldest_seconds: number }
export interface StoredApp extends AppRow { instance_id: string; first_seen: string; last_seen: string; probes: number; gone: boolean }
export type AppEvent = "appeared" | "disappeared" | "returned" | "port_opened" | "port_closed" | import("./container_inventory.js").ContainerEvent;
export interface StoredAppEvent { id: number; instance_id: string; name: string; user: string; event: AppEvent; at: string; details: Record<string, unknown> | null }

/** The kernel's comm field is 15 characters, so daemon names arrive cut ("amazon-ssm-agen"); the patterns match the cut form. */
const OS = new RegExp("^(" + [
  "systemd.*", "init", "\\(sd-pam\\)", "dbus.*", "cron", "crond", "anacron", "atd", "rsyslogd", "syslog-ng", "journald", "sshd", "sshd-session", "chronyd", "ntpd", "snapd", "polkitd", "udevd", "auditd",
  "agetty", "login", "dhclient", "dhcpcd", "NetworkManager", "networkd-dispat.*", "wpa_supplicant", "ModemManager", "acpid", "irqbalance", "rngd", "gssproxy", "unattended-upgr.*", "apt.*", "yum.*", "dnf.*",
  "packagekitd", "multipathd", "lvmetad", "rpcbind", "rpc\\..*", "rpc-statd", "sssd.*", "nscd", "cloud-init", "ec2-instance-co.*", "ec2net", "amazon-ec2-net.*", "hibinit-agent", "thermald", "upowerd",
  "udisksd", "accounts-daemon", "fwupd", "lxcfs", "haveged", "serial-getty.*", "getty", "mandb", "logrotate", "update-notifier", "motd-news", "apport", "whoopsie", "kerneloops", "rtkit-daemon", "colord",
  "avahi-daemon", "at-spi.*", "gvfs.*", "dconf-service", "smartd", "mdadm", "iscsid", "lvm", "blkmapd", "nfsdcld", "ssm-session-wor.*", "ssm-document-wo.*", "sudo", "su", "sh", "bash", "dash", "zsh",
  "awk", "gawk", "mawk", "sed", "grep", "ps", "sort", "head", "tail", "cut", "paste", "tr", "cat", "sleep", "xargs", "tee", "find", "timeout", "less", "more", "watch", "tmux.*", "screen", "top", "htop",
].join("|") + ")$", "i");
/** Platform and observability: kept, but not the workload. */
const INFRA = new RegExp("^(" + [
  "amazon-cloudwat.*", "amazon-ssm-agen.*", "ssm-agent-worke.*", "node_exporter", "datadog-agent", "agent", "process-agent", "trace-agent", "system-probe", "fluent-bit", "td-agent.*", "fluentd", "ruby td-agent.*",
  "filebeat", "metricbeat", "vector", "promtail", "otelcol.*", "newrelic.*", "nrsysmond", "collectd", "telegraf", "zabbix_agent.*", "falco", "containerd", "containerd-shim.*", "dockerd", "docker-proxy", "docker",
  "runc", "kubelet", "kube-proxy", "aws-k8s-agent", "aws-vpc-cni.*", "crio", "conmon", "nomad", "consul", "envoy", "coredns", "ecs-agent", "ecs-init", "amazon-ecs-init", "ssm-session-log.*", "teleport", "tailscaled",
  "wireguard", "openvpn", "fail2ban-server", "postfix", "master", "pickup", "qmgr", "sendmail", "exim4", "nscd", "ssh-agent", "gpg-agent", "docker-init", "tini", "dumb-init", "supervisord", "s6-.*", "runsv.*",
].join("|") + ")$", "i");

/** The app rows for one probe: OS daemons and shell utilities dropped, platform pieces marked infra, everything else an app. */
export function appsFromProbe(p: Pick<ProbeResult, "processes">): AppRow[] {
  const out = new Map<string, AppRow>();
  for (const g of p.processes ?? []) {
    const base = g.name.split(" ")[0];
    if (OS.test(base)) continue;
    const kind: AppKind = INFRA.test(base) ? "infra" : "app";
    const key = `${g.name}\u0000${g.user}`;
    const row = out.get(key);
    if (row) { row.count += g.count; row.cpu_pct += g.cpu_pct; row.rss_bytes += g.rss_bytes; row.oldest_seconds = Math.max(row.oldest_seconds, g.oldest_seconds); }
    else out.set(key, { name: g.name, user: g.user, kind, command: g.command, count: g.count, cpu_pct: g.cpu_pct, rss_bytes: g.rss_bytes, oldest_seconds: g.oldest_seconds });
  }
  return [...out.values()].sort((a, b) => (a.kind === b.kind ? b.rss_bytes - a.rss_bytes : a.kind === "app" ? -1 : 1));
}

/** A disappearance is worth an event when the program had been seen on two probes or had run an hour; an alert when it had run a day. */
export const EVENT_MIN_PROBES = 2, EVENT_MIN_AGE_S = 3600, ALERT_MIN_AGE_S = 86_400;

const upsert = db.prepare(`insert into instance_apps(instance_id, name, user, kind, command, count, cpu_pct, rss_bytes, oldest_seconds, first_seen, last_seen, probes, gone)
  values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0)
  on conflict(instance_id, name, user) do update set kind = excluded.kind, command = excluded.command, count = excluded.count, cpu_pct = excluded.cpu_pct, rss_bytes = excluded.rss_bytes,
    oldest_seconds = excluded.oldest_seconds, last_seen = excluded.last_seen, probes = probes + 1, gone = 0`);
const markGone = db.prepare("update instance_apps set gone = 1 where instance_id = ? and name = ? and user = ?");
const insertEvent = db.prepare("insert into instance_app_events(instance_id, name, user, event, at, details) values (?, ?, ?, ?, ?, ?)");
const insertAlert = alertInsert(AWS);
const openAppGone = db.prepare("select 1 from alerts where kind = 'app_gone' and resource = ? and acknowledged = 0 and json_extract(details, '$.app') = ? limit 1");

export interface RecordAppsResult { apps: number; appeared: string[]; disappeared: string[]; returned: string[]; alerts: number }

/**
 * Called for every stored probe that carries a process list. The first probe of a box records its apps without
 * events (nothing to compare with); from the second on, a program not seen before is `appeared`, one that was
 * there and is not any more is `disappeared` (when it had been seen twice or had run an hour: a cron job seen
 * once is not news), and one back after being gone is `returned`.
 */
export function recordApps(instanceId: string, collectedAt: string, data: Pick<ProbeResult, "processes">, instanceName: string | null = null): RecordAppsResult | null {
  if (!Array.isArray(data.processes)) return null;
  const apps = appsFromProbe(data);
  const res: RecordAppsResult = { apps: apps.length, appeared: [], disappeared: [], returned: [], alerts: 0 };
  const label = instanceName ? `${instanceName} (${instanceId})` : instanceId;
  db.transaction(() => {
    const prev = db.prepare("select name, user, kind, probes, gone, oldest_seconds, last_seen, first_seen from instance_apps where instance_id = ?").all(instanceId) as { name: string; user: string; kind: AppKind; probes: number; gone: number; oldest_seconds: number; last_seen: string; first_seen: string }[];
    const known = new Map(prev.map((r) => [`${r.name}\u0000${r.user}`, r]));
    const first = prev.length === 0;
    const now = new Set<string>();
    for (const a of apps) {
      const key = `${a.name}\u0000${a.user}`;
      now.add(key);
      const was = known.get(key);
      upsert.run(instanceId, a.name, a.user, a.kind, a.command, a.count, a.cpu_pct, a.rss_bytes, a.oldest_seconds, collectedAt, collectedAt);
      if (!was && !first) { res.appeared.push(a.name); insertEvent.run(instanceId, a.name, a.user, "appeared", collectedAt, JSON.stringify({ kind: a.kind, command: a.command, count: a.count, oldest_seconds: a.oldest_seconds })); }
      else if (was?.gone) { res.returned.push(a.name); insertEvent.run(instanceId, a.name, a.user, "returned", collectedAt, JSON.stringify({ kind: a.kind, command: a.command, gone_since: was.last_seen })); }
    }
    for (const r of prev) {
      const key = `${r.name}\u0000${r.user}`;
      if (r.gone || now.has(key)) continue;
      markGone.run(instanceId, r.name, r.user);
      if (r.probes < EVENT_MIN_PROBES && r.oldest_seconds < EVENT_MIN_AGE_S) continue;
      res.disappeared.push(r.name);
      insertEvent.run(instanceId, r.name, r.user, "disappeared", collectedAt, JSON.stringify({ kind: r.kind, last_seen: r.last_seen, first_seen: r.first_seen, probes: r.probes, oldest_seconds: r.oldest_seconds }));
      if (r.kind === "app" && r.oldest_seconds >= ALERT_MIN_AGE_S && r.probes >= EVENT_MIN_PROBES && !openAppGone.get(instanceId, r.name)) {
        const days = Math.round(r.oldest_seconds / 86_400);
        const msg = `${label}: ${r.name} is no longer running (it had run for ${days} day${days === 1 ? "" : "s"}, seen on ${r.probes} probes, last ${r.last_seen.slice(0, 16).replace("T", " ")} UTC)`;
        insertAlert.run("app_gone", instanceId, msg, JSON.stringify({ summary: msg, instance_id: instanceId, name: instanceName, app: r.name, user: r.user, last_seen: r.last_seen, first_seen: r.first_seen, oldest_seconds: r.oldest_seconds, probes: r.probes, probed_at: collectedAt }));
        res.alerts++;
      }
    }
    db.prepare("delete from instance_app_events where at < datetime('now', '-180 days')").run();
  })();
  return res;
}

const rowToApp = (r: any): StoredApp => ({ instance_id: r.instance_id, name: r.name, user: r.user, kind: r.kind, command: r.command ?? "", count: Number(r.count ?? 0), cpu_pct: Number(r.cpu_pct ?? 0), rss_bytes: Number(r.rss_bytes ?? 0), oldest_seconds: Number(r.oldest_seconds ?? 0), first_seen: r.first_seen, last_seen: r.last_seen, probes: Number(r.probes ?? 0), gone: Boolean(r.gone) });
const rowToEvent = (r: any): StoredAppEvent => { let d = null; try { d = r.details ? JSON.parse(r.details) : null; } catch { /* keep null */ } return { id: r.id, instance_id: r.instance_id, name: r.name, user: r.user, event: r.event, at: r.at, details: d }; };

/** What runs on one instance now (and, with `includeGone`, what used to). Apps before infra, biggest first. */
export function appsOn(instanceId: string, includeGone = false): StoredApp[] {
  return (db.prepare(`select * from instance_apps where instance_id = ? ${includeGone ? "" : "and gone = 0"} order by gone, case kind when 'app' then 0 else 1 end, rss_bytes desc`).all(instanceId) as any[]).map(rowToApp);
}

/** Where a program runs across the fleet (name match is a case-insensitive substring), current rows first. */
export function whereRuns(name: string, limit = 200): (StoredApp & { instance_name: string | null; instance_state: string | null })[] {
  return (db.prepare(`select a.*, i.name as instance_name, i.state as instance_state from instance_apps a left join inventory_ec2 i on i.instance_id = a.instance_id
    where lower(a.name) like ? order by a.gone, a.rss_bytes desc limit ?`).all(`%${name.toLowerCase()}%`, limit) as any[]).map((r) => ({ ...rowToApp(r), instance_name: r.instance_name ?? null, instance_state: r.instance_state ?? null }));
}

export interface FleetApp { name: string; kind: AppKind; instances: number; instance_ids: string[]; processes: number; rss_bytes: number; cpu_pct: number; users: string[] }

/** Every program running anywhere, with how many boxes run it; apps first, then by footprint. */
export function fleetApps(kind?: AppKind): FleetApp[] {
  const rows = db.prepare(`select name, kind, count(distinct instance_id) as instances, group_concat(distinct instance_id) as ids, sum(count) as processes, sum(rss_bytes) as rss, sum(cpu_pct) as cpu, group_concat(distinct user) as users
    from instance_apps where gone = 0 ${kind ? "and kind = ?" : ""} group by name, kind order by case kind when 'app' then 0 else 1 end, instances desc, rss desc`).all(...(kind ? [kind] : [])) as any[];
  return rows.map((r) => ({ name: r.name, kind: r.kind, instances: Number(r.instances), instance_ids: String(r.ids || "").split(",").filter(Boolean), processes: Number(r.processes ?? 0), rss_bytes: Number(r.rss ?? 0), cpu_pct: Number(r.cpu ?? 0), users: String(r.users || "").split(",").filter(Boolean) }));
}

/** Appear, disappear and return events, newest first, for one instance, one program, or the fleet. */
export function appEvents(opts: { instance_id?: string; name?: string; since?: string; limit?: number } = {}): StoredAppEvent[] {
  const where: string[] = []; const args: unknown[] = [];
  if (opts.instance_id) { where.push("instance_id = ?"); args.push(opts.instance_id); }
  if (opts.name) { where.push("lower(name) like ?"); args.push(`%${opts.name.toLowerCase()}%`); }
  if (opts.since) { where.push("at >= ?"); args.push(opts.since); }
  args.push(Math.min(Math.max(opts.limit ?? 100, 1), 1000));
  return (db.prepare(`select * from instance_app_events ${where.length ? `where ${where.join(" and ")}` : ""} order by at desc, id desc limit ?`).all(...args) as any[]).map(rowToEvent);
}

/** Counts for the UI and the tools: instances with a process list, distinct apps, events in the last day. */
export function appsSummary(): { instances: number; apps: number; infra: number; events_24h: number; last_seen: string | null } {
  const a = db.prepare("select count(distinct instance_id) as instances, count(distinct case when kind = 'app' then name end) as apps, count(distinct case when kind = 'infra' then name end) as infra, max(last_seen) as last_seen from instance_apps where gone = 0").get() as any;
  const e = db.prepare("select count(*) as n from instance_app_events where at >= datetime('now', '-1 day')").get() as { n: number };
  return { instances: Number(a?.instances ?? 0), apps: Number(a?.apps ?? 0), infra: Number(a?.infra ?? 0), events_24h: Number(e?.n ?? 0), last_seen: a?.last_seen ?? null };
}


// ---- ports (probe 1.8): what the box answers on, who owns it, and who can reach it ----------------------------------------------

export type PortScope = "all" | "loopback" | "address";
/** internet = a rule lets 0.0.0.0/0 or ::/0 in; network = other addresses or a prefix list; group = other security groups only; closed = no rule lets it in; local = the socket listens on loopback only. */
export type PortExposure = "internet" | "network" | "group" | "closed" | "local";
export interface PortRow { proto: "tcp" | "udp"; port: number; bind: string; scope: PortScope; process: string | null; pid: number | null; container: string | null; container_port: number | null; app_name: string | null; exposure: PortExposure }
export interface StoredPort extends PortRow { instance_id: string; first_seen: string; last_seen: string; probes: number; gone: boolean }
export interface IngressRule { group_id: string; ip_protocol: string | null; from_port: number | null; to_port: number | null; cidr_ipv4: string | null; cidr_ipv6: string | null; referenced_group_id: string | null; prefix_list_id: string | null; rule_id?: string | null; description?: string | null }

/**
 * The listeners of one probe, one per protocol and port: a host socket and the container publishing the same port
 * (docker-proxy on the host, the container behind it) merge into one row that names both. Pure.
 */
export function listenersFromProbe(p: Pick<ProbeResult, "listeners">): ProbeListener[] {
  const out = new Map<string, ProbeListener>();
  for (const l of p.listeners ?? []) {
    const key = `${l.proto}:${l.port}`;
    const have = out.get(key);
    if (!have) { out.set(key, { ...l }); continue; }
    // the container entry carries the owner; the socket entry the pid and the bind address
    const container = have.container ?? l.container, container_port = have.container_port ?? l.container_port;
    const process = have.container || l.container ? (have.process && have.process !== "docker-proxy" ? have.process : l.process && l.process !== "docker-proxy" ? l.process : null) : have.process ?? l.process;
    const scope: PortScope = have.scope === "all" || l.scope === "all" ? "all" : have.scope === "address" || l.scope === "address" ? "address" : "loopback";
    out.set(key, { proto: l.proto, port: l.port, bind: have.bind || l.bind, scope, process, pid: have.pid ?? l.pid, container, container_port });
  }
  return [...out.values()].sort((a, b) => a.port - b.port || a.proto.localeCompare(b.proto));
}

/** The app row a listener belongs to: the container's name when it publishes the port, else the process by its program name (the first word of an app's name). Pure. */
export function ownerOf(l: Pick<ProbeListener, "process" | "container">, apps: Pick<AppRow, "name">[]): string | null {
  if (l.container) return l.container;
  if (!l.process) return null;
  const exact = apps.find((a) => a.name === l.process) ?? apps.find((a) => a.name.split(" ")[0] === l.process);
  return exact?.name ?? l.process;
}

const protoMatches = (rule: string | null, proto: string) => rule == null || rule === "-1" || rule.toLowerCase() === proto || (rule === "6" && proto === "tcp") || (rule === "17" && proto === "udp");
const portMatches = (r: IngressRule, port: number) => (r.from_port == null && r.to_port == null) || (r.from_port === -1) || ((r.from_port ?? 0) <= port && port <= (r.to_port ?? 65535));

/** One security group rule as people read it: which group, which ports, from where. */
export interface RuleRef { group_id: string; group_name: string | null; rule_id: string | null; ports: string; source: string; description: string | null; world: boolean; broad: boolean; /** An IPv6 rule on a box without an IPv6 address: it lets nothing in. */ unreachable?: boolean }
/** How far a port can be reached and why: the rules that let it in (widest first), or what blocks it. */
export interface PortReach {
  exposure: PortExposure; allowed_by: RuleRef[]; reason: string; broad: boolean;
  /** What stops it when it is closed: no security group rule, or the subnet's network ACL (in, or the replies out). */
  blocked_by?: "security_group" | "network_acl" | null;
  /** The network ACL's say when it narrows or half-blocks the port (some clients' replies dropped). */
  nacl_note?: string | null;
}
/** What is known about the box itself: its public IPv4 address (null = it has none, undefined = not known), its IPv6 addresses (undefined = not known) and its groups' names. */
export interface ReachContext { public_ip?: string | null; ipv6?: string[]; group_names?: Record<string, string>; nacl?: { acl_id: string; entries: NaclEntry[] } | null }

/** One network ACL entry as EC2 describes it (Steampipe aws_vpc_network_acl.entries). */
export interface NaclEntry { RuleNumber: number; RuleAction: "allow" | "deny" | string; Egress: boolean; Protocol: string; CidrBlock?: string | null; Ipv6CidrBlock?: string | null; PortRange?: { From?: number; To?: number } | null }

// ---- network ACLs: stateless, first matching rule by number wins, and the replies need an outbound rule too ----------

const v4 = (cidr: string): [number, number] | null => {
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)\/(\d+)$/.exec(cidr);
  if (!m) return null;
  const ip = ((+m[1] << 24) >>> 0) + (+m[2] << 16) + (+m[3] << 8) + +m[4];
  const bits = +m[5]; const size = 2 ** (32 - bits);
  const start = Math.floor(ip / size) * size;
  return [start, start + size - 1];
};
/** Whether CIDR `outer` holds every address of `inner` (IPv4 by arithmetic; IPv6 only ::/0 or the same block). Pure. */
export function cidrContains(outer: string, inner: string): boolean {
  if (outer.includes(":") || inner.includes(":")) return outer === "::/0" ? inner.includes(":") : outer === inner;
  const o = v4(outer), i = v4(inner);
  return Boolean(o && i && o[0] <= i[0] && i[1] <= o[1]);
}
const naclProto = (p: string, proto: string) => p === "-1" || (p === "6" && proto === "tcp") || (p === "17" && proto === "udp");
const naclPort = (e: NaclEntry, port: number) => !e.PortRange || e.PortRange.From == null || ((e.PortRange.From ?? 0) <= port && port <= (e.PortRange.To ?? 65535));
const isWorld = (cidr: string) => cidr === "0.0.0.0/0" || cidr === "::/0";

/**
 * The entry that decides traffic of `proto` on `port` with the far end in `cidr`, in or out: the lowest-numbered
 * entry that matches the protocol and port and holds the whole of `cidr`. For a world source, narrower entries
 * before it are exceptions: allows are recorded (only those addresses get in if the world entry denies), denies are
 * ignored (a few addresses blocked does not close a port to the internet). No entry = the implicit deny. Pure.
 */
export function naclDecide(entries: NaclEntry[], egress: boolean, proto: string, port: number, cidr: string): { action: "allow" | "deny"; entry: NaclEntry | null; narrower_allows: string[] } {
  const v6 = cidr.includes(":");
  const narrower: string[] = [];
  for (const e of [...entries].filter((x) => Boolean(x.Egress) === egress).sort((a, b) => a.RuleNumber - b.RuleNumber)) {
    const block = v6 ? e.Ipv6CidrBlock : e.CidrBlock;
    if (!block || !naclProto(String(e.Protocol), proto) || !naclPort(e, port)) continue;
    if (cidrContains(block, cidr)) return { action: e.RuleAction === "allow" ? "allow" : "deny", entry: e, narrower_allows: narrower };
    if (isWorld(cidr) && e.RuleAction === "allow") narrower.push(block);
  }
  return { action: "deny", entry: null, narrower_allows: narrower };
}

/** Client ephemeral ports the replies go to: Linux (32768-60999), both, Windows and macOS (49152-65535). */
export const EPHEMERAL_SAMPLES = [40000, 55000, 62000];

export interface NaclVerdict { verdict: "allow" | "deny" | "narrow" | "no_reply"; cidrs: string[]; entry: NaclEntry | null; reply_entry: NaclEntry | null; partial_reply: boolean }

/** Whether a network ACL lets `cidr` reach `port` and the replies get back out. Pure. */
export function naclVerdict(entries: NaclEntry[], proto: string, port: number, cidr: string): NaclVerdict {
  const inbound = naclDecide(entries, false, proto, port, cidr);
  const reply = (to: string) => EPHEMERAL_SAMPLES.map((p) => naclDecide(entries, true, proto, p, to));
  if (inbound.action === "deny") {
    const ok = inbound.narrower_allows.filter((c) => reply(c).some((r) => r.action === "allow"));
    if (ok.length) return { verdict: "narrow", cidrs: ok, entry: inbound.entry, reply_entry: null, partial_reply: false };
    return { verdict: "deny", cidrs: [], entry: inbound.entry, reply_entry: null, partial_reply: false };
  }
  const out = reply(cidr);
  const allowed = out.filter((r) => r.action === "allow").length;
  if (!allowed) return { verdict: "no_reply", cidrs: [], entry: inbound.entry, reply_entry: out.find((r) => r.entry)?.entry ?? null, partial_reply: false };
  return { verdict: "allow", cidrs: [cidr], entry: inbound.entry, reply_entry: out.find((r) => r.action === "deny")?.entry ?? null, partial_reply: allowed < out.length };
}

const entryText = (e: NaclEntry | null, egress = false) => e ? `rule #${e.RuleNumber} ${e.RuleAction === "allow" ? "allows" : "denies"} ${String(e.Protocol) === "-1" ? "all traffic" : `${e.Protocol === "6" ? "tcp" : e.Protocol === "17" ? "udp" : e.Protocol}${e.PortRange?.From != null ? ` ${e.PortRange.From === e.PortRange.To ? e.PortRange.From : `${e.PortRange.From}-${e.PortRange.To}`}` : ""}`} ${egress ? "to" : "from"} ${e.CidrBlock ?? e.Ipv6CidrBlock}` : "the implicit deny (no rule matches)";

const WORLD = (r: IngressRule) => r.cidr_ipv4 === "0.0.0.0/0" || r.cidr_ipv6 === "::/0";
/** An IPv6-only rule does nothing for a box without an IPv6 address: nothing can reach it over IPv6. */
const V6_ONLY = (r: IngressRule) => Boolean(r.cidr_ipv6) && !r.cidr_ipv4 && !r.referenced_group_id && !r.prefix_list_id;
const ALL_PROTO = (r: IngressRule) => r.ip_protocol == null || r.ip_protocol === "-1";
/** An all-traffic rule, or one range wider than this many ports, is "broad": it opens what nobody chose to open. */
export const BROAD_RANGE = 1000;

/** A rule in words: "all traffic", "tcp 22", "tcp 7000-9200"; from "anywhere", a CIDR, a group or a prefix list. Pure. */
export function ruleRef(r: IngressRule, names: Record<string, string> = {}): RuleRef {
  const proto = r.ip_protocol === "6" ? "tcp" : r.ip_protocol === "17" ? "udp" : r.ip_protocol === "1" ? "icmp" : r.ip_protocol;
  const allPorts = r.from_port == null || r.from_port === -1 || (r.from_port === 0 && r.to_port === 65535);
  const ports = ALL_PROTO(r) ? "all traffic" : allPorts ? `all ${proto}` : r.from_port === r.to_port ? `${proto} ${r.from_port}` : `${proto} ${r.from_port}-${r.to_port}`;
  const world = WORLD(r);
  const source = world ? (r.cidr_ipv4 === "0.0.0.0/0" ? "anywhere" : "anywhere over IPv6") : r.cidr_ipv4 || r.cidr_ipv6 || (r.referenced_group_id ? `${names[r.referenced_group_id] ? `${names[r.referenced_group_id]} ` : ""}${r.referenced_group_id}` : r.prefix_list_id ? `prefix list ${r.prefix_list_id}` : "nowhere");
  const width = allPorts ? 65536 : (r.to_port ?? 0) - (r.from_port ?? 0) + 1;
  return { group_id: r.group_id, group_name: names[r.group_id] ?? null, rule_id: r.rule_id ?? null, ports, source, description: r.description ?? null, world, broad: world && (ALL_PROTO(r) || width > BROAD_RANGE) };
}

const groupLabel = (ids: string[], names: Record<string, string>) => ids.map((g) => names[g] ? `${names[g]} (${g})` : g).join(", ") || "its security groups";

/**
 * How far a listening port can be reached and why, from the ingress rules of the box's security groups and its public
 * address. A rule that lets the world in only makes a port public when the box has a public address: without one the
 * port is reachable from the VPC (network). Pure.
 */
export function reachOf(l: Pick<ProbeListener, "proto" | "port" | "scope" | "bind">, rules: IngressRule[], ctx: ReachContext = {}): PortReach {
  const names = ctx.group_names ?? {};
  const groups = [...new Set(rules.map((r) => r.group_id))];
  if (l.scope === "loopback") return { exposure: "local", allowed_by: [], reason: `listens on ${l.bind || "loopback"} only: nothing outside the box can reach it, whatever the security groups say`, broad: false };
  const rank: Record<PortExposure, number> = { local: 0, closed: 0, group: 1, network: 2, internet: 3 };
  let best: PortExposure = "closed";
  const allowed: { ref: RuleRef; e: PortExposure }[] = [];
  const v6Only: RuleRef[] = [];
  const naclBlocked: { ref: RuleRef; why: string }[] = [];
  const naclNotes: string[] = [];
  for (const r of rules) {
    if (!protoMatches(r.ip_protocol, l.proto) || !portMatches(r, l.port)) continue;
    if (V6_ONLY(r) && ctx.ipv6 && ctx.ipv6.length === 0) { v6Only.push(ruleRef(r, names)); continue; }
    let e: PortExposure = WORLD(r) ? "internet" : r.cidr_ipv4 || r.cidr_ipv6 || r.prefix_list_id ? "network" : r.referenced_group_id ? "group" : "closed";
    // a world rule makes a port public only through an address the world can reach: the public IPv4 for an IPv4
    // rule, an IPv6 address (all of them are global in a VPC) for an IPv6 one
    if (e === "internet" && (r.cidr_ipv4 === "0.0.0.0/0" ? ctx.public_ip === null : false)) e = "network";
    if (e === "closed") continue;
    let ref = ruleRef(r, names);
    // the subnet's network ACL sits in front of the security group for traffic from outside the subnet; a source
    // that is another group or a prefix list has no address to judge, so only CIDR sources are checked
    const src = r.cidr_ipv4 || r.cidr_ipv6;
    if (ctx.nacl && src) {
      const n = naclVerdict(ctx.nacl.entries, l.proto, l.port, src);
      if (n.verdict === "deny") { naclBlocked.push({ ref, why: `${ctx.nacl.acl_id} ${entryText(n.entry)}` }); continue; }
      if (n.verdict === "no_reply") { naclBlocked.push({ ref, why: `${ctx.nacl.acl_id} lets it in but drops the replies: ${entryText(n.reply_entry, true)}` }); continue; }
      if (n.verdict === "narrow") { e = "network"; ref = { ...ref, source: n.cidrs.join(", "), world: false, broad: false }; naclNotes.push(`the network ACL ${ctx.nacl.acl_id} denies the rest of the internet (${entryText(n.entry)}) and lets in only ${n.cidrs.join(", ")}`); }
      else if (n.partial_reply) naclNotes.push(`the network ACL ${ctx.nacl.acl_id} drops replies to some client ports (${entryText(n.reply_entry, true)}): some clients cannot connect`);
    }
    allowed.push({ ref, e });
    if (rank[e] > rank[best]) best = e;
  }
  allowed.sort((a, b) => rank[b.e] - rank[a.e] || Number(b.ref.broad) - Number(a.ref.broad));
  const refs = allowed.map((a) => a.ref);
  const top = refs[0];
  const what = `${l.port}/${l.proto}`;
  const by = (r: RuleRef) => `${r.group_name ?? r.group_id} allows ${r.ports} from ${r.source}${r.description ? ` ("${r.description}")` : ""}`;
  let reason: string;
  if (best === "closed" && naclBlocked.length) reason = `blocked by network ACL: ${naclBlocked[0].ref.group_name ?? naclBlocked[0].ref.group_id} lets ${what} in from ${naclBlocked[0].ref.source}, but ${naclBlocked[0].why}`;
  else if (best === "closed") reason = !rules.length ? "no security group rules known for this box (the inventory has not read them yet)"
    : v6Only.length ? `blocked by the security groups: only ${v6Only[0].group_name ?? v6Only[0].group_id}'s ${v6Only[0].ports} rule from ${v6Only[0].source} covers ${what}, and the box has no IPv6 address`
    : `blocked by the security groups: no rule in ${groupLabel(groups, names)} lets ${what} in`;
  else if (best === "internet") reason = `open to the internet: ${by(top)}${!top.broad ? "" : top.ports === "all traffic" ? ", a broad rule that opens every port the box listens on" : ", a broad range that opens whatever listens in it"}`;
  else if (top.world && ctx.public_ip === null) reason = `${by(top)}, but the box has no public address: reachable from inside the VPC only`;
  else if (best === "network") reason = `reachable from ${top.source} only: ${by(top)}`;
  else reason = `reachable from members of ${top.source} only`;
  const nacl_note = naclNotes[0] ?? null;
  if (nacl_note && best !== "closed") reason += `; ${nacl_note}`;
  return { exposure: best, allowed_by: refs, reason, broad: refs.some((r) => r.broad && r.world), blocked_by: best === "closed" ? (naclBlocked.length ? "network_acl" : "security_group") : null, nacl_note };
}

/** How far a listening port can be reached, from the ingress rules of the box's security groups. Pure. */
export function exposureOf(l: Pick<ProbeListener, "proto" | "port" | "scope">, rules: IngressRule[], ctx: ReachContext = {}): PortExposure {
  return reachOf({ ...l, bind: "" }, rules, ctx).exposure;
}

/**
 * The other direction: rules that open ports nothing on the box listens on (all-traffic rules aside, which always
 * cover something). Each is a hole without a reason, or a leftover from something that moved. Pure.
 */
export function rulesWithoutListener(rules: IngressRule[], listening: Pick<ProbeListener, "proto" | "port" | "scope">[], names: Record<string, string> = {}, ipv6?: string[]): RuleRef[] {
  const open = listening.filter((l) => l.scope !== "loopback");
  const seen = new Set<string>();
  const out: RuleRef[] = [];
  for (const r of rules) {
    const dead = V6_ONLY(r) && ipv6 != null && ipv6.length === 0;
    if (!dead && (ALL_PROTO(r) || r.ip_protocol === "1" || r.ip_protocol === "icmp" || r.ip_protocol === "58")) continue;
    if (!dead && open.some((l) => protoMatches(r.ip_protocol, l.proto) && portMatches(r, l.port))) continue;
    const ref = { ...ruleRef(r, names), ...(dead ? { unreachable: true } : {}) };
    const key = `${ref.group_id}|${ref.ports}|${ref.source}`;
    if (seen.has(key)) continue;
    seen.add(key); out.push(ref);
  }
  return out.sort((a, b) => Number(b.world) - Number(a.world) || a.ports.localeCompare(b.ports, undefined, { numeric: true }));
}

/** The network ACL of a subnet: the one associated with it, else the VPC's default. null when none is known. */
export function naclOf(subnetId: string | null | undefined, vpcId: string | null | undefined): { acl_id: string; entries: NaclEntry[] } | null {
  if (!subnetId && !vpcId) return null;
  const rows = db.prepare("select acl_id, vpc_id, is_default, subnets, entries from nacls where vpc_id = ? or ? is null").all(vpcId ?? null, vpcId ?? null) as { acl_id: string; vpc_id: string | null; is_default: number; subnets: string; entries: string }[];
  const parse = (x: string) => { try { return JSON.parse(x); } catch { return []; } };
  const hit = (subnetId ? rows.find((r) => (parse(r.subnets) as string[]).includes(subnetId)) : undefined) ?? rows.find((r) => r.is_default && r.vpc_id === vpcId);
  return hit ? { acl_id: hit.acl_id, entries: parse(hit.entries) as NaclEntry[] } : null;
}

/** Replaces the network ACLs the inventory read from Steampipe (src/inventory.ts, every refresh). */
export function replaceNacls(rows: { acl_id: string; vpc_id: string | null; region: string | null; is_default: boolean; subnets: string[]; entries: NaclEntry[] }[]): number {
  const at = new Date().toISOString();
  db.transaction(() => {
    db.prepare("delete from nacls").run();
    const ins = db.prepare("insert into nacls(acl_id, vpc_id, region, is_default, subnets, entries, refreshed_at) values (?, ?, ?, ?, ?, ?, ?)");
    for (const r of rows) ins.run(r.acl_id, r.vpc_id, r.region, r.is_default ? 1 : 0, JSON.stringify(r.subnets), JSON.stringify(r.entries), at);
  })();
  return rows.length;
}

/** The box's public address (null when it has none) and its security groups' names, from its inventory snapshot. */
export function reachContextOf(instanceId: string): ReachContext {
  try {
    const r = db.prepare("select snapshot from inventory_ec2 where instance_id = ?").get(instanceId) as { snapshot: string | null } | undefined;
    const net = r?.snapshot ? JSON.parse(r.snapshot)?.network : null;
    if (!net) return {};
    const names: Record<string, string> = {};
    for (const g of Array.isArray(net.security_groups) ? net.security_groups : []) if (g?.GroupId && g?.GroupName) names[g.GroupId] = g.GroupName;
    // the inventory always writes the key (null when the box has none); a snapshot without it says nothing either way
    // a VPC without an IPv6 block cannot give the box an IPv6 address, whatever the snapshot says (src/security_groups.ts reads the VPCs)
    let ipv6: string[] | undefined = Array.isArray(net.ipv6) ? net.ipv6.map(String) : undefined;
    try { const v = net.vpc_id ? db.prepare("select ipv6_blocks from inventory_vpc where vpc_id = ?").get(net.vpc_id) as { ipv6_blocks: number } | undefined : undefined; if (v && v.ipv6_blocks === 0) ipv6 = []; } catch { /* the table arrives with the first refresh */ }
    return { public_ip: "public_ip" in net ? (net.public_ip ? String(net.public_ip) : null) : undefined, ipv6, group_names: names, nacl: naclOf(net.subnet_id, net.vpc_id) };
  } catch { return {}; }
}

/** The security group ids of an instance, from its inventory snapshot. */
export function securityGroupsOf(instanceId: string): string[] {
  try {
    const r = db.prepare("select snapshot from inventory_ec2 where instance_id = ?").get(instanceId) as { snapshot: string | null } | undefined;
    const snap = r?.snapshot ? JSON.parse(r.snapshot) : null;
    const sgs = snap?.network?.security_groups ?? [];
    return (Array.isArray(sgs) ? sgs : []).map((g: any) => String(g?.GroupId ?? g?.group_id ?? g ?? "")).filter((g: string) => /^sg-/.test(g));
  } catch { return []; }
}

export function ingressRulesFor(groupIds: string[]): IngressRule[] {
  if (!groupIds.length) return [];
  return db.prepare(`select group_id, ip_protocol, from_port, to_port, cidr_ipv4, cidr_ipv6, referenced_group_id, prefix_list_id, rule_id, description from sg_ingress where group_id in (${groupIds.map(() => "?").join(",")})`).all(...groupIds) as IngressRule[];
}

/** Replaces the ingress rules the inventory read from Steampipe (src/inventory.ts, every refresh). */
export function replaceIngressRules(rows: (IngressRule & { region?: string | null })[]): number {
  const at = new Date().toISOString();
  db.transaction(() => {
    db.prepare("delete from sg_ingress").run();
    const ins = db.prepare("insert into sg_ingress(group_id, region, ip_protocol, from_port, to_port, cidr_ipv4, cidr_ipv6, referenced_group_id, prefix_list_id, rule_id, description, refreshed_at) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
    for (const r of rows) ins.run(r.group_id, r.region ?? null, r.ip_protocol ?? null, r.from_port ?? null, r.to_port ?? null, r.cidr_ipv4 ?? null, r.cidr_ipv6 ?? null, r.referenced_group_id ?? null, r.prefix_list_id ?? null, r.rule_id ?? null, r.description ?? null, at);
  })();
  return rows.length;
}

/** The port rows for one probe, owners matched to the app rows and exposure read from the given rules. Pure. */
export function portsFromProbe(p: Pick<ProbeResult, "listeners" | "processes">, rules: IngressRule[], ctx: ReachContext = {}): PortRow[] {
  const apps = appsFromProbe(p);
  return listenersFromProbe(p).map((l) => ({ ...l, app_name: ownerOf(l, apps), exposure: exposureOf(l, rules, ctx) }));
}

const upsertPort = db.prepare(`insert into instance_ports(instance_id, proto, port, bind, scope, process, pid, container, container_port, app_name, exposure, first_seen, last_seen, probes, gone)
  values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0)
  on conflict(instance_id, proto, port) do update set bind = excluded.bind, scope = excluded.scope, process = excluded.process, pid = excluded.pid, container = excluded.container, container_port = excluded.container_port,
    app_name = excluded.app_name, exposure = excluded.exposure, last_seen = excluded.last_seen, probes = probes + 1, gone = 0`);
const markPortGone = db.prepare("update instance_ports set gone = 1 where instance_id = ? and proto = ? and port = ?");
const openPortExposed = db.prepare("select 1 from alerts where kind = 'port_exposed' and resource = ? and acknowledged = 0 and json_extract(details, '$.port') = ? and json_extract(details, '$.proto') = ? limit 1");

export interface RecordPortsResult { ports: number; opened: string[]; closed: string[]; alerts: number }
const portLabel = (r: Pick<PortRow, "proto" | "port" | "app_name">) => `${r.port}/${r.proto}${r.app_name ? ` (${r.app_name})` : ""}`;

/**
 * Called for every stored probe that carries listeners. The first probe of a box records its ports without events;
 * from the second on, a port not seen before is `port_opened`, one gone is `port_closed` (both in the app events, under
 * the owner's name). A port open to the internet raises a `port_exposed` alert when first seen (first inventory included:
 * that is a finding whenever it is found), once while it stays open.
 */
export function recordPorts(instanceId: string, collectedAt: string, data: Pick<ProbeResult, "listeners" | "processes">, instanceName: string | null = null): RecordPortsResult | null {
  if (!Array.isArray(data.listeners)) return null;
  const rules = ingressRulesFor(securityGroupsOf(instanceId));
  const ctx = reachContextOf(instanceId);
  const ports = portsFromProbe(data, rules, ctx);
  const res: RecordPortsResult = { ports: ports.length, opened: [], closed: [], alerts: 0 };
  const label = instanceName ? `${instanceName} (${instanceId})` : instanceId;
  db.transaction(() => {
    const prev = db.prepare("select proto, port, app_name, exposure, gone, probes, last_seen from instance_ports where instance_id = ?").all(instanceId) as { proto: string; port: number; app_name: string | null; exposure: string; gone: number; probes: number; last_seen: string }[];
    const known = new Map(prev.map((r) => [`${r.proto}:${r.port}`, r]));
    const first = prev.length === 0;
    const now = new Set<string>();
    for (const r of ports) {
      const key = `${r.proto}:${r.port}`;
      now.add(key);
      const was = known.get(key);
      upsertPort.run(instanceId, r.proto, r.port, r.bind, r.scope, r.process, r.pid, r.container, r.container_port, r.app_name, r.exposure, collectedAt, collectedAt);
      const fresh = (!was || was.gone) && !first;
      if (fresh) { res.opened.push(portLabel(r)); insertEvent.run(instanceId, r.app_name ?? `:${r.port}`, r.container ? "container" : r.process ?? "", "port_opened", collectedAt, JSON.stringify({ proto: r.proto, port: r.port, scope: r.scope, exposure: r.exposure, container: r.container, process: r.process })); }
      // an internet-facing port is news the first time it is seen, first inventory or not, and again if it closes and reopens or its rules widen
      if (r.exposure === "internet" && (!was || was.gone || was.exposure !== "internet") && !openPortExposed.get(instanceId, r.port, r.proto)) {
        const reach = reachOf(r, rules, ctx);
        const rule = reach.allowed_by[0];
        const msg = `${label}: ${r.port}/${r.proto} is open to the internet${r.app_name ? `, served by ${r.app_name}` : ""} (listening on ${r.scope === "all" ? "every interface" : r.bind}; ${rule ? `${rule.group_name ?? rule.group_id} allows ${rule.ports} from anywhere${rule.broad ? ", a broad rule" : ""}` : "a security group rule lets 0.0.0.0/0 in"})`;
        insertAlert.run("port_exposed", instanceId, msg, JSON.stringify({ summary: msg, instance_id: instanceId, name: instanceName, port: r.port, proto: r.proto, app: r.app_name, container: r.container, process: r.process, scope: r.scope, probed_at: collectedAt }));
        res.alerts++;
      }
    }
    for (const r of prev) {
      const key = `${r.proto}:${r.port}`;
      if (r.gone || now.has(key)) continue;
      markPortGone.run(instanceId, r.proto, r.port);
      res.closed.push(portLabel({ proto: r.proto as "tcp" | "udp", port: r.port, app_name: r.app_name }));
      insertEvent.run(instanceId, r.app_name ?? `:${r.port}`, "", "port_closed", collectedAt, JSON.stringify({ proto: r.proto, port: r.port, exposure: r.exposure, last_seen: r.last_seen, probes: r.probes }));
    }
  })();
  return res;
}

const rowToPort = (r: any): StoredPort => ({ instance_id: r.instance_id, proto: r.proto, port: Number(r.port), bind: r.bind ?? "", scope: r.scope, process: r.process ?? null, pid: r.pid == null ? null : Number(r.pid), container: r.container ?? null, container_port: r.container_port == null ? null : Number(r.container_port), app_name: r.app_name ?? null, exposure: r.exposure, first_seen: r.first_seen, last_seen: r.last_seen, probes: Number(r.probes ?? 1), gone: Boolean(r.gone) });

/** The ports one instance answers on now (and, with `includeGone`, what it used to), exposure re-read from the current rules; widest reach first. */
export function portsOn(instanceId: string, includeGone = false): (StoredPort & Partial<Omit<PortReach, "exposure">>)[] {
  const rules = ingressRulesFor(securityGroupsOf(instanceId));
  const ctx = reachContextOf(instanceId);
  const rank: Record<string, number> = { internet: 0, network: 1, group: 2, closed: 3, local: 4 };
  return (db.prepare(`select * from instance_ports where instance_id = ? ${includeGone ? "" : "and gone = 0"}`).all(instanceId) as any[])
    .map((r) => {
      const p = rowToPort(r);
      if (!rules.length && p.exposure !== "local") return p;
      const reach = reachOf(p, rules, ctx);
      return { ...p, exposure: reach.exposure, allowed_by: reach.allowed_by, reason: reach.reason, broad: reach.broad, blocked_by: reach.blocked_by ?? null, nacl_note: reach.nacl_note ?? null };
    })
    .sort((a, b) => Number(a.gone) - Number(b.gone) || rank[a.exposure] - rank[b.exposure] || a.port - b.port);
}

/** Security group rules on the box that no listening port uses. */
export function unusedRulesOn(instanceId: string): RuleRef[] {
  const rules = ingressRulesFor(securityGroupsOf(instanceId));
  if (!rules.length) return [];
  const listening = db.prepare("select proto, port, scope from instance_ports where instance_id = ? and gone = 0").all(instanceId) as Pick<ProbeListener, "proto" | "port" | "scope">[];
  if (!listening.length) return [];
  const ctx = reachContextOf(instanceId);
  return rulesWithoutListener(rules, listening, ctx.group_names, ctx.ipv6);
}

/** Where a port is open across the fleet, widest reach first. */
export function whereListens(port: number, proto?: "tcp" | "udp"): (StoredPort & { instance_name: string | null; instance_state: string | null })[] {
  const rank: Record<string, number> = { internet: 0, network: 1, group: 2, closed: 3, local: 4 };
  return (db.prepare(`select p.*, i.name as instance_name, i.state as instance_state from instance_ports p left join inventory_ec2 i on i.instance_id = p.instance_id where p.gone = 0 and p.port = ? ${proto ? "and p.proto = ?" : ""}`).all(...(proto ? [port, proto] : [port])) as any[])
    .map((r) => ({ ...rowToPort(r), instance_name: r.instance_name ?? null, instance_state: r.instance_state ?? null }))
    .sort((a, b) => rank[a.exposure] - rank[b.exposure]);
}

export interface FleetPort { proto: string; port: number; instances: number; instance_ids: string[]; apps: string[]; exposures: Record<string, number> }

/** Every open port anywhere, with how many boxes answer on it and how far each can be reached; the internet-facing ones first. */
export function fleetPorts(): FleetPort[] {
  const rows = db.prepare("select proto, port, instance_id, app_name, exposure from instance_ports where gone = 0").all() as { proto: string; port: number; instance_id: string; app_name: string | null; exposure: string }[];
  const out = new Map<string, FleetPort>();
  for (const r of rows) {
    const k = `${r.proto}:${r.port}`;
    const f = out.get(k) ?? { proto: r.proto, port: r.port, instances: 0, instance_ids: [], apps: [], exposures: {} };
    f.instances++; f.instance_ids.push(r.instance_id); if (r.app_name && !f.apps.includes(r.app_name)) f.apps.push(r.app_name); f.exposures[r.exposure] = (f.exposures[r.exposure] ?? 0) + 1;
    out.set(k, f);
  }
  return [...out.values()].sort((a, b) => (b.exposures.internet ?? 0) - (a.exposures.internet ?? 0) || b.instances - a.instances || a.port - b.port);
}

/** Counts for the UI and the tools. */
export function portsSummary(): { instances: number; ports: number; internet: number; rules: number } {
  const a = db.prepare("select count(distinct instance_id) as instances, count(*) as ports, sum(case when exposure = 'internet' then 1 else 0 end) as internet from instance_ports where gone = 0").get() as any;
  const r = db.prepare("select count(*) as n from sg_ingress").get() as { n: number };
  return { instances: Number(a?.instances ?? 0), ports: Number(a?.ports ?? 0), internet: Number(a?.internet ?? 0), rules: Number(r?.n ?? 0) };
}

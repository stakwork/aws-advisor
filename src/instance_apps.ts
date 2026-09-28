/**
 * What runs on each instance, from the probe's process list (probe 1.6, src/ssm.ts): the applications, with the
 * operating system's own daemons and the probe's utilities set aside, and the platform pieces (container runtime,
 * monitoring agents) kept but marked `infra`. One row per instance, program and user with first and last seen,
 * and an event when a program appears, disappears or comes back, so a box can be watched for what it is running,
 * not only how busy it is. A long-running application that vanishes raises an `app_gone` alert. The graph carries
 * the same as (:AdvisorResource)-[:RUNS]->(:AdvisorApp) (src/graph_mirror.ts).
 */
import { db } from "./db.js";
import type { ProbeProcessGroup, ProbeResult } from "./ssm.js";

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
create index if not exists instance_app_events_at on instance_app_events(at);`);

export type AppKind = "app" | "infra";
export interface AppRow { name: string; user: string; kind: AppKind; command: string; count: number; cpu_pct: number; rss_bytes: number; oldest_seconds: number }
export interface StoredApp extends AppRow { instance_id: string; first_seen: string; last_seen: string; probes: number; gone: boolean }
export type AppEvent = "appeared" | "disappeared" | "returned";
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
const insertAlert = db.prepare("insert into alerts(kind, resource, message, details) values (?, ?, ?, ?)");
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

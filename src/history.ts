/**
 * Long-lived statistics from the probes. Raw hourly probes (instance_metrics) and per-container samples are
 * kept for 30 days; daily roll-ups per instance and per container are kept for 400 days, so trends survive
 * after the detail expires. Roll-ups are idempotent: a day is recomputed whenever it is rolled again.
 */
import { db } from "./db.js";
import type { ProbeResult } from "./ssm.js";

db.exec(`
create table if not exists container_samples (
  id integer primary key autoincrement,
  instance_id text not null,
  collected_at text not null,
  name text not null,
  image text,
  state text,
  cpu_pct real,
  mem_bytes real,
  mem_pct real
);
create index if not exists container_samples_inst on container_samples(instance_id, collected_at);
create table if not exists instance_daily (
  instance_id text not null,
  day text not null,
  samples integer not null,
  mem_pct_avg real, mem_pct_max real,
  disk_pct_avg real, disk_pct_max real,
  load_per_cpu_avg real, load_per_cpu_max real,
  containers_running_avg real,
  primary key (instance_id, day)
);
create table if not exists container_daily (
  instance_id text not null,
  name text not null,
  day text not null,
  image text,
  samples integer not null,
  running_share real,
  cpu_pct_avg real, cpu_pct_max real,
  mem_bytes_avg real, mem_bytes_max real,
  primary key (instance_id, name, day)
);
create index if not exists container_daily_inst on container_daily(instance_id, day);
create table if not exists instance_activity (
  id integer primary key autoincrement,
  instance_id text not null,
  collected_at text not null,
  external_connections integer, internal_connections integer, ssh_sessions integer, users_now integer,
  requests_24h integer, health_24h integer, last_request_at text,
  last_login_at text, last_login_user text,
  signal_lines_24h integer, last_signal_at text, last_log_at text,
  net_rx_bytes real, net_tx_bytes real
);
create index if not exists instance_activity_inst on instance_activity(instance_id, collected_at);
`);

const addColumn = (table: string, column: string, type: string) => { try { db.exec(`alter table ${table} add column ${column} ${type}`); } catch { /* exists */ } };
// probe 1.4: what a container's log says about use, and its traffic
for (const [c, t] of [["log_lines_24h", "integer"], ["signal_lines_24h", "integer"], ["errors_24h", "integer"], ["warns_24h", "integer"], ["restarts", "integer"], ["last_log_at", "text"], ["last_signal_at", "text"], ["net_rx_bytes", "real"], ["net_tx_bytes", "real"]]) addColumn("container_samples", c, t);
for (const [c, t] of [["log_lines_avg", "real"], ["signal_lines_avg", "real"], ["errors_avg", "real"], ["restarts_max", "integer"], ["last_log_at", "text"], ["last_signal_at", "text"], ["net_bytes_day", "real"]]) addColumn("container_daily", c, t);
for (const [c, t] of [["external_connections_avg", "real"], ["external_connections_max", "integer"], ["ssh_sessions_max", "integer"], ["requests_24h_avg", "real"], ["signal_lines_24h_avg", "real"], ["last_use_at", "text"], ["last_use_kind", "text"], ["net_bytes_day", "real"]]) addColumn("instance_daily", c, t);

const insertSample = db.prepare(`insert into container_samples(instance_id, collected_at, name, image, state, cpu_pct, mem_bytes, mem_pct, log_lines_24h, signal_lines_24h, errors_24h, warns_24h, restarts, last_log_at, last_signal_at, net_rx_bytes, net_tx_bytes)
  values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
const insertActivity = db.prepare(`insert into instance_activity(instance_id, collected_at, external_connections, internal_connections, ssh_sessions, users_now, requests_24h, health_24h, last_request_at, last_login_at, last_login_user, signal_lines_24h, last_signal_at, last_log_at, net_rx_bytes, net_tx_bytes)
  values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);

/** Called for every stored probe: one row per container so container history is queryable, plus (probe 1.4) one activity row per probe. */
export function recordContainerSamples(instanceId: string, collectedAt: string, data: ProbeResult): number {
  const act = new Map((data.activity?.containers ?? []).map((a) => [a.name, a]));
  const tx = db.transaction(() => {
    for (const c of data.containers ?? []) {
      const a = act.get(c.name);
      insertSample.run(instanceId, collectedAt, c.name, c.image, c.state, c.cpu_pct, c.mem_bytes, c.mem_pct,
        a?.log_lines ?? null, a?.signal_lines ?? null, a?.errors ?? null, a?.warns ?? null, a?.restarts ?? null, a?.last_log_at ?? null, a?.last_signal_at ?? null, c.net_rx_bytes ?? null, c.net_tx_bytes ?? null);
    }
    const A = data.activity;
    if (A) {
      const lastSignal = A.containers.map((c) => c.last_signal_at).filter((x): x is string => Boolean(x)).sort().pop() ?? null;
      const lastLog = A.containers.map((c) => c.last_log_at).filter((x): x is string => Boolean(x)).sort().pop() ?? null;
      insertActivity.run(instanceId, collectedAt, A.connections?.external ?? null, A.connections?.internal ?? null, A.connections?.ssh ?? null, A.logins.users_now,
        A.front_door.source ? A.front_door.requests : null, A.front_door.source ? A.front_door.health : null, A.front_door.last_request_at, A.logins.last_login_at, A.logins.last_login_user,
        A.containers.reduce((s, c) => s + c.signal_lines, 0), lastSignal, lastLog, A.net?.rx_bytes ?? null, A.net?.tx_bytes ?? null);
    }
  });
  tx();
  return data.containers?.length ?? 0;
}

/** Bytes moved between the first and last counter of a day, tolerating a reset (a restart) by dropping the negative step. */
export function counterDelta(points: { at: string; rx: number | null; tx: number | null }[]): number | null {
  const ps = points.filter((p) => p.rx != null && p.tx != null).sort((a, b) => a.at.localeCompare(b.at));
  if (ps.length < 2) return null;
  let total = 0;
  for (let i = 1; i < ps.length; i++) { const d = (ps[i].rx! + ps[i].tx!) - (ps[i - 1].rx! + ps[i - 1].tx!); if (d > 0) total += d; }
  return total;
}

function summarise(json: string): { mem: number | null; disk: number | null; load: number | null; running: number | null } {
  try {
    const d = JSON.parse(json);
    const mem = d.memory?.total_bytes ? (100 * Number(d.memory.used_bytes)) / Number(d.memory.total_bytes) : null;
    const disks: any[] = Array.isArray(d.disks) ? d.disks : [];
    const root = disks.find((x) => x.mount === "/") || disks.reduce((a, b) => (!a || Number(b.used_pct) > Number(a.used_pct) ? b : a), null as any);
    const cpus = Number(d.cpus || 0);
    return {
      mem: mem == null ? null : Math.round(mem * 10) / 10,
      disk: root ? Number(root.used_pct) : null,
      load: d.load?.["1m"] != null && cpus ? Math.round((100 * Number(d.load["1m"])) / cpus) / 100 : null,
      running: d.docker?.available ? Number(d.docker.running || 0) : null,
    };
  } catch { return { mem: null, disk: null, load: null, running: null }; }
}

const avg = (xs: number[]) => (xs.length ? Math.round((xs.reduce((a, b) => a + b, 0) / xs.length) * 100) / 100 : null);
const max = (xs: number[]) => (xs.length ? Math.max(...xs) : null);

/**
 * Rolls every day that has raw data but is older than today (UTC) into instance_daily and container_daily.
 * `days` limits how far back to (re)compute; the default covers the raw retention window.
 */
export function rollupDaily(days = 31): { instance_days: number; container_days: number } {
  const since = `-${Math.max(1, days)} days`;
  const rows = db.prepare(`select instance_id, substr(collected_at, 1, 10) as day, json from instance_metrics
    where datetime(collected_at) >= datetime('now', ?) and substr(collected_at, 1, 10) <= date('now') order by instance_id, day`).all(since) as { instance_id: string; day: string; json: string }[];
  const groups = new Map<string, { instance_id: string; day: string; mem: number[]; disk: number[]; load: number[]; running: number[]; n: number }>();
  for (const r of rows) {
    const k = `${r.instance_id}|${r.day}`;
    const g = groups.get(k) || { instance_id: r.instance_id, day: r.day, mem: [], disk: [], load: [], running: [], n: 0 };
    const s = summarise(r.json);
    g.n++;
    if (s.mem != null) g.mem.push(s.mem); if (s.disk != null) g.disk.push(s.disk); if (s.load != null) g.load.push(s.load); if (s.running != null) g.running.push(s.running);
    groups.set(k, g);
  }
  const upInst = db.prepare(`insert into instance_daily(instance_id, day, samples, mem_pct_avg, mem_pct_max, disk_pct_avg, disk_pct_max, load_per_cpu_avg, load_per_cpu_max, containers_running_avg)
    values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    on conflict(instance_id, day) do update set samples = excluded.samples, mem_pct_avg = excluded.mem_pct_avg, mem_pct_max = excluded.mem_pct_max,
      disk_pct_avg = excluded.disk_pct_avg, disk_pct_max = excluded.disk_pct_max, load_per_cpu_avg = excluded.load_per_cpu_avg, load_per_cpu_max = excluded.load_per_cpu_max,
      containers_running_avg = excluded.containers_running_avg`);
  // activity per day (probe 1.4): connections, requests, signal lines, the newest use seen that day and the traffic between the first and last counter
  const actRows = db.prepare(`select instance_id, substr(collected_at, 1, 10) as day, collected_at, external_connections, ssh_sessions, requests_24h, signal_lines_24h, last_signal_at, last_request_at, last_login_at, net_rx_bytes, net_tx_bytes
    from instance_activity where datetime(collected_at) >= datetime('now', ?) and substr(collected_at, 1, 10) <= date('now') order by instance_id, collected_at`).all(since) as any[];
  const actGroups = new Map<string, any[]>();
  for (const r of actRows) { const k = `${r.instance_id}|${r.day}`; if (!actGroups.has(k)) actGroups.set(k, []); actGroups.get(k)!.push(r); }
  const upAct = db.prepare(`update instance_daily set external_connections_avg = ?, external_connections_max = ?, ssh_sessions_max = ?, requests_24h_avg = ?, signal_lines_24h_avg = ?, last_use_at = ?, last_use_kind = ?, net_bytes_day = ? where instance_id = ? and day = ?`);
  const ensureDay = db.prepare("insert or ignore into instance_daily(instance_id, day, samples) values (?, ?, 0)");
  const cont = db.prepare(`select instance_id, name, substr(collected_at, 1, 10) as day, max(image) as image, count(*) as samples,
      avg(case when state = 'running' then 1.0 else 0.0 end) as running_share,
      avg(cpu_pct) as cpu_avg, max(cpu_pct) as cpu_max, avg(mem_bytes) as mem_avg, max(mem_bytes) as mem_max
    from container_samples where datetime(collected_at) >= datetime('now', ?) and substr(collected_at, 1, 10) <= date('now')
    group by instance_id, name, day`).all(since) as any[];
  const upCont = db.prepare(`insert into container_daily(instance_id, name, day, image, samples, running_share, cpu_pct_avg, cpu_pct_max, mem_bytes_avg, mem_bytes_max)
    values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    on conflict(instance_id, name, day) do update set image = excluded.image, samples = excluded.samples, running_share = excluded.running_share,
      cpu_pct_avg = excluded.cpu_pct_avg, cpu_pct_max = excluded.cpu_pct_max, mem_bytes_avg = excluded.mem_bytes_avg, mem_bytes_max = excluded.mem_bytes_max`);
  const contAct = db.prepare(`select instance_id, name, substr(collected_at, 1, 10) as day, avg(log_lines_24h) as log_avg, avg(signal_lines_24h) as sig_avg, avg(errors_24h) as err_avg, max(restarts) as restarts, max(last_log_at) as last_log_at, max(last_signal_at) as last_signal_at
    from container_samples where datetime(collected_at) >= datetime('now', ?) and substr(collected_at, 1, 10) <= date('now') and log_lines_24h is not null group by instance_id, name, day`).all(since) as any[];
  const contNet = db.prepare(`select instance_id, name, substr(collected_at, 1, 10) as day, collected_at as at, net_rx_bytes as rx, net_tx_bytes as tx
    from container_samples where datetime(collected_at) >= datetime('now', ?) and substr(collected_at, 1, 10) <= date('now') and net_rx_bytes is not null order by collected_at`).all(since) as any[];
  const contNetGroups = new Map<string, any[]>();
  for (const r of contNet) { const k = `${r.instance_id}|${r.name}|${r.day}`; if (!contNetGroups.has(k)) contNetGroups.set(k, []); contNetGroups.get(k)!.push(r); }
  const upContAct = db.prepare("update container_daily set log_lines_avg = ?, signal_lines_avg = ?, errors_avg = ?, restarts_max = ?, last_log_at = ?, last_signal_at = ?, net_bytes_day = ? where instance_id = ? and name = ? and day = ?");
  const r2 = (v: number | null) => (v == null ? null : Math.round(v * 100) / 100);
  const tx = db.transaction(() => {
    for (const g of groups.values()) upInst.run(g.instance_id, g.day, g.n, avg(g.mem), max(g.mem), avg(g.disk), max(g.disk), avg(g.load), max(g.load), avg(g.running));
    for (const c of cont) upCont.run(c.instance_id, c.name, c.day, c.image, c.samples, Math.round(Number(c.running_share) * 100) / 100, c.cpu_avg == null ? null : Math.round(c.cpu_avg * 100) / 100, c.cpu_max, c.mem_avg == null ? null : Math.round(c.mem_avg), c.mem_max);
    for (const c of contAct) upContAct.run(r2(c.log_avg), r2(c.sig_avg), r2(c.err_avg), c.restarts, c.last_log_at, c.last_signal_at, counterDelta(contNetGroups.get(`${c.instance_id}|${c.name}|${c.day}`) || []), c.instance_id, c.name, c.day);
    for (const [k, rows] of actGroups) {
      const [instance_id, day] = k.split("|");
      const ext = rows.map((r) => r.external_connections).filter((v) => v != null) as number[];
      const uses: { at: string; kind: string }[] = [];
      for (const r of rows) { if (r.last_signal_at) uses.push({ at: r.last_signal_at, kind: "signal_line" }); if (r.last_request_at) uses.push({ at: r.last_request_at, kind: "request" }); if (r.last_login_at) uses.push({ at: r.last_login_at, kind: "login" }); if (r.external_connections > 0) uses.push({ at: new Date(r.collected_at.endsWith("Z") || r.collected_at.includes("+") ? r.collected_at : r.collected_at + "Z").toISOString(), kind: "external_connection" }); }
      uses.sort((a, b) => b.at.localeCompare(a.at));
      ensureDay.run(instance_id, day);
      upAct.run(avg(ext), max(ext), max(rows.map((r) => r.ssh_sessions).filter((v) => v != null)), avg(rows.map((r) => r.requests_24h).filter((v) => v != null)), avg(rows.map((r) => r.signal_lines_24h).filter((v) => v != null)),
        uses[0]?.at ?? null, uses[0]?.kind ?? null, counterDelta(rows.map((r) => ({ at: r.collected_at, rx: r.net_rx_bytes, tx: r.net_tx_bytes }))), instance_id, day);
    }
  });
  tx();
  return { instance_days: groups.size, container_days: cont.length };
}

/** Raw detail expires after 30 days, roll-ups after 400. Returns rows removed. */
export function pruneHistory(): { probes: number; container_samples: number; rollups: number } {
  const probes = db.prepare("delete from instance_metrics where datetime(collected_at) < datetime('now', '-30 days')").run().changes;
  const samples = db.prepare("delete from container_samples where datetime(collected_at) < datetime('now', '-30 days')").run().changes
    + db.prepare("delete from instance_activity where datetime(collected_at) < datetime('now', '-30 days')").run().changes;
  const r1 = db.prepare("delete from instance_daily where day < date('now', '-400 days')").run().changes;
  const r2 = db.prepare("delete from container_daily where day < date('now', '-400 days')").run().changes;
  return { probes, container_samples: samples, rollups: r1 + r2 };
}

export function instanceHistory(instanceId: string, days = 90) {
  const daily = db.prepare("select * from instance_daily where instance_id = ? and day >= date('now', ?) order by day").all(instanceId, `-${days} days`);
  const containers = db.prepare(`select name, max(image) as image, count(*) as days, avg(running_share) as running_share, avg(cpu_pct_avg) as cpu_pct_avg, max(cpu_pct_max) as cpu_pct_max,
      avg(mem_bytes_avg) as mem_bytes_avg, max(mem_bytes_max) as mem_bytes_max, min(day) as first_day, max(day) as last_day,
      avg(log_lines_avg) as log_lines_avg, avg(signal_lines_avg) as signal_lines_avg, avg(errors_avg) as errors_avg, max(restarts_max) as restarts_max, max(last_log_at) as last_log_at, max(last_signal_at) as last_signal_at, sum(net_bytes_day) as net_bytes
    from container_daily where instance_id = ? and day >= date('now', ?) group by name order by mem_bytes_avg desc`).all(instanceId, `-${days} days`);
  // the activity summary over the window: the newest use of any kind, how many days had external connections, requests or signal lines
  const act = db.prepare(`select max(last_use_at) as last_use_at, count(*) as days_with_data,
      sum(case when external_connections_max > 0 then 1 else 0 end) as days_with_external, sum(case when requests_24h_avg > 0 then 1 else 0 end) as days_with_requests,
      sum(case when signal_lines_24h_avg > 0 then 1 else 0 end) as days_with_signals, sum(net_bytes_day) as net_bytes, max(ssh_sessions_max) as ssh_sessions_max
    from instance_daily where instance_id = ? and day >= date('now', ?) and (last_use_at is not null or external_connections_avg is not null)`).get(instanceId, `-${days} days`) as any;
  const containerDaily = db.prepare("select name, day, cpu_pct_avg, mem_bytes_avg, running_share from container_daily where instance_id = ? and day >= date('now', ?) order by day").all(instanceId, `-${days} days`);
  // today's containers straight from the latest probe, so the table is not empty before the first roll-up
  const latest = db.prepare("select json from instance_metrics where instance_id = ? order by collected_at desc limit 1").get(instanceId) as { json: string } | undefined;
  let today: any[] = [];
  try { today = latest ? (JSON.parse(latest.json).containers || []) : []; } catch { today = []; }
  const latestActivity = (db.prepare("select * from instance_activity where instance_id = ? order by collected_at desc limit 1").get(instanceId) as Record<string, unknown> | undefined) ?? null;
  return { instance_id: instanceId, days, daily, containers, container_daily: containerDaily, containers_now: today, activity: { window: act && act.days_with_data ? act : null, latest: latestActivity as any } };
}

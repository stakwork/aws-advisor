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
`);

const insertSample = db.prepare("insert into container_samples(instance_id, collected_at, name, image, state, cpu_pct, mem_bytes, mem_pct) values (?, ?, ?, ?, ?, ?, ?, ?)");

/** Called for every stored probe: one row per container so container history is queryable. */
export function recordContainerSamples(instanceId: string, collectedAt: string, data: ProbeResult): number {
  if (!data.containers?.length) return 0;
  const tx = db.transaction(() => {
    for (const c of data.containers!) insertSample.run(instanceId, collectedAt, c.name, c.image, c.state, c.cpu_pct, c.mem_bytes, c.mem_pct);
  });
  tx();
  return data.containers.length;
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
  const cont = db.prepare(`select instance_id, name, substr(collected_at, 1, 10) as day, max(image) as image, count(*) as samples,
      avg(case when state = 'running' then 1.0 else 0.0 end) as running_share,
      avg(cpu_pct) as cpu_avg, max(cpu_pct) as cpu_max, avg(mem_bytes) as mem_avg, max(mem_bytes) as mem_max
    from container_samples where datetime(collected_at) >= datetime('now', ?) and substr(collected_at, 1, 10) <= date('now')
    group by instance_id, name, day`).all(since) as any[];
  const upCont = db.prepare(`insert into container_daily(instance_id, name, day, image, samples, running_share, cpu_pct_avg, cpu_pct_max, mem_bytes_avg, mem_bytes_max)
    values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    on conflict(instance_id, name, day) do update set image = excluded.image, samples = excluded.samples, running_share = excluded.running_share,
      cpu_pct_avg = excluded.cpu_pct_avg, cpu_pct_max = excluded.cpu_pct_max, mem_bytes_avg = excluded.mem_bytes_avg, mem_bytes_max = excluded.mem_bytes_max`);
  const tx = db.transaction(() => {
    for (const g of groups.values()) upInst.run(g.instance_id, g.day, g.n, avg(g.mem), max(g.mem), avg(g.disk), max(g.disk), avg(g.load), max(g.load), avg(g.running));
    for (const c of cont) upCont.run(c.instance_id, c.name, c.day, c.image, c.samples, Math.round(Number(c.running_share) * 100) / 100, c.cpu_avg == null ? null : Math.round(c.cpu_avg * 100) / 100, c.cpu_max, c.mem_avg == null ? null : Math.round(c.mem_avg), c.mem_max);
  });
  tx();
  return { instance_days: groups.size, container_days: cont.length };
}

/** Raw detail expires after 30 days, roll-ups after 400. Returns rows removed. */
export function pruneHistory(): { probes: number; container_samples: number; rollups: number } {
  const probes = db.prepare("delete from instance_metrics where datetime(collected_at) < datetime('now', '-30 days')").run().changes;
  const samples = db.prepare("delete from container_samples where datetime(collected_at) < datetime('now', '-30 days')").run().changes;
  const r1 = db.prepare("delete from instance_daily where day < date('now', '-400 days')").run().changes;
  const r2 = db.prepare("delete from container_daily where day < date('now', '-400 days')").run().changes;
  return { probes, container_samples: samples, rollups: r1 + r2 };
}

export function instanceHistory(instanceId: string, days = 90) {
  const daily = db.prepare("select * from instance_daily where instance_id = ? and day >= date('now', ?) order by day").all(instanceId, `-${days} days`);
  const containers = db.prepare(`select name, max(image) as image, count(*) as days, avg(running_share) as running_share, avg(cpu_pct_avg) as cpu_pct_avg, max(cpu_pct_max) as cpu_pct_max,
      avg(mem_bytes_avg) as mem_bytes_avg, max(mem_bytes_max) as mem_bytes_max, min(day) as first_day, max(day) as last_day
    from container_daily where instance_id = ? and day >= date('now', ?) group by name order by mem_bytes_avg desc`).all(instanceId, `-${days} days`);
  const containerDaily = db.prepare("select name, day, cpu_pct_avg, mem_bytes_avg, running_share from container_daily where instance_id = ? and day >= date('now', ?) order by day").all(instanceId, `-${days} days`);
  // today's containers straight from the latest probe, so the table is not empty before the first roll-up
  const latest = db.prepare("select json from instance_metrics where instance_id = ? order by collected_at desc limit 1").get(instanceId) as { json: string } | undefined;
  let today: any[] = [];
  try { today = latest ? (JSON.parse(latest.json).containers || []) : []; } catch { today = []; }
  return { instance_id: instanceId, days, daily, containers, container_daily: containerDaily, containers_now: today };
}

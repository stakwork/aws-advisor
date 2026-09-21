import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { PROBE_SCRIPT, ProbeError, parseProbeOutput, summarizeProbe } from "../ssm.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const fixture = fs.readFileSync(path.join(here, "probe.fixture.txt"), "utf8");

test("parseProbeOutput reads the JSON line and ignores noise", () => {
  const p = parseProbeOutput(fixture);
  assert.equal(p.probe, "aws-advisor/1");
  assert.equal(p.hostname, "ip-10-0-1-42");
  assert.equal(p.cpus, 4);
  assert.equal(p.memory.total_bytes, 16748113920);
  assert.equal(p.memory.used_bytes, 10697072640);
  assert.deepEqual(p.load, { "1m": 0.41, "5m": 0.2, "15m": 0.18 });
  assert.equal(p.disks.length, 2);
  assert.equal(p.disks[0].mount, "/");
  assert.equal(p.disks[0].used_pct, 57.3);
  assert.equal(p.top_cpu.length, 5);
  assert.equal(p.top_cpu[0].command, "java");
  assert.equal(p.top_cpu[0].rss_bytes, 520093696);
  assert.equal(p.top_cpu[4].command, 'my "quoted" proc');
  assert.equal(p.top_mem[0].pid, 1234);
});

test("summarizeProbe derives the numbers the idle rule uses", () => {
  const s = summarizeProbe(parseProbeOutput(fixture));
  assert.equal(s.memory_used_pct, 64);
  assert.equal(s.memory_total_gb, 15.6);
  assert.equal(s.memory_used_gb, 10);
  assert.equal(s.load_1m, 0.41);
  assert.equal(s.cpus, 4);
  assert.equal(s.top_process, "java");
  assert.equal(s.collected_at, "2026-09-18T17:14:31Z");
});

test("parseProbeOutput rejects output that is not the probe's", () => {
  assert.throws(() => parseProbeOutput("nothing here\n"), (e: unknown) => e instanceof ProbeError && e.code === "bad_output");
  assert.throws(() => parseProbeOutput('{"probe":"other","memory":{}}'), (e: unknown) => e instanceof ProbeError && e.code === "bad_output");
  assert.throws(() => parseProbeOutput('{"probe":"aws-advisor/1","cpus":"x"}'), (e: unknown) => e instanceof ProbeError && /cpus/.test((e as Error).message));
  assert.throws(() => parseProbeOutput("{not json}"), (e: unknown) => e instanceof ProbeError && e.code === "bad_output");
});

test("the probe script is a single read-only shell script", () => {
  assert.match(PROBE_SCRIPT, /^# aws-advisor probe v1/);
  assert.match(PROBE_SCRIPT, /"probe":"aws-advisor\/1"/);
  for (const forbidden of [/\brm\b/, /\bkill\b/, /\bsystemctl\b/, /\bsudo\b/, />\s*\/(etc|var|usr)/]) assert.doesNotMatch(PROBE_SCRIPT, forbidden);
});


test("probe 1.2: docker and container fields parse and summarise; older probes without them still parse", () => {
  const withContainers = JSON.stringify({
    probe: "aws-advisor/1", hostname: "h", collected_at: "2026-09-19T15:00:00Z", cpus: 4, uptime_seconds: 10,
    memory: { total_bytes: 8e9, used_bytes: 4e9, available_bytes: 4e9, swap_total_bytes: 0, swap_used_bytes: 0 },
    load: { "1m": 0.5, "5m": 0.4, "15m": 0.3 }, disks: [], top_cpu: [], top_mem: [],
    docker: { available: true, running: 2, total: 3 },
    containers: [
      { name: "bitcoind", image: "lncm/bitcoind:v27", state: "running", running_for: "3 days ago", cpu_pct: 3.2, mem_bytes: 2147483648, mem_pct: 26.8 },
      { name: "lnd", image: "lightninglabs/lnd:v0.18", state: "running", running_for: "3 days ago", cpu_pct: 0.4, mem_bytes: 536870912, mem_pct: 6.7 },
      { name: "old-job", image: "alpine", state: "exited", running_for: "2 weeks ago", cpu_pct: null, mem_bytes: 0, mem_pct: null },
    ],
  });
  const p = parseProbeOutput(withContainers);
  assert.equal(p.docker?.running, 2);
  assert.equal(p.containers?.length, 3);
  assert.equal(p.containers?.[2].cpu_pct, null);
  const s = summarizeProbe(p);
  assert.equal(s.containers_running, 2);
  assert.equal(s.top_container, "bitcoind");
  const old = summarizeProbe(parseProbeOutput(fixture));
  assert.equal(old.containers_running, null);
  assert.equal(old.top_container, null);
  assert.match(PROBE_SCRIPT, /docker stats --no-stream/);
  assert.match(PROBE_SCRIPT, /"docker":%s,"containers":%s/);
});

test("history: container samples are recorded per probe and daily roll-ups aggregate them", async () => {
  const { db } = await import("../db.js");
  const { recordContainerSamples, rollupDaily, instanceHistory } = await import("../history.js");
  const iid = "i-0123456789abcdef0";
  db.prepare("delete from instance_metrics where instance_id = ?").run(iid);
  db.prepare("delete from container_samples where instance_id = ?").run(iid);
  db.prepare("delete from instance_daily where instance_id = ?").run(iid);
  db.prepare("delete from container_daily where instance_id = ?").run(iid);
  const day = new Date(Date.now() - 86400000).toISOString().slice(0, 10);
  const mk = (h: number, memUsed: number, cpu: number) => ({
    probe: "aws-advisor/1", hostname: "h", collected_at: `${day}T${String(h).padStart(2, "0")}:05:00Z`, cpus: 2, uptime_seconds: 1,
    memory: { total_bytes: 1000, used_bytes: memUsed, available_bytes: 1000 - memUsed, swap_total_bytes: 0, swap_used_bytes: 0 },
    load: { "1m": 1, "5m": 1, "15m": 1 }, disks: [{ mount: "/", filesystem: "x", total_bytes: 100, used_bytes: 50, used_pct: 50 }], top_cpu: [], top_mem: [],
    docker: { available: true, running: 1, total: 1 },
    containers: [{ name: "web", image: "nginx", state: "running", running_for: "1 day", cpu_pct: cpu, mem_bytes: 100 * h, mem_pct: 10 }],
  });
  for (const [h, mem, cpu] of [[1, 400, 2], [2, 600, 4]] as const) {
    const p = mk(h, mem, cpu);
    db.prepare("insert into instance_metrics(instance_id, collected_at, json) values (?, ?, ?)").run(iid, p.collected_at, JSON.stringify(p));
    recordContainerSamples(iid, p.collected_at, p as any);
  }
  rollupDaily(3);
  const h = instanceHistory(iid, 7);
  const d: any = h.daily.find((r: any) => r.day === day);
  assert.ok(d, "instance day rolled");
  assert.equal(d.samples, 2);
  assert.equal(d.mem_pct_avg, 50);
  assert.equal(d.mem_pct_max, 60);
  assert.equal(d.load_per_cpu_avg, 0.5);
  const c: any = h.containers.find((r: any) => r.name === "web");
  assert.ok(c, "container rolled");
  assert.equal(c.cpu_pct_max, 4);
  assert.equal(Math.round(c.mem_bytes_avg), 150);
  assert.equal(c.running_share, 1);
  for (const t of ["instance_metrics", "container_samples", "instance_daily", "container_daily"]) db.prepare(`delete from ${t} where instance_id = ?`).run(iid);
});

test("probe pass: an ISO-timestamped probe from earlier today does not hide the instance from the next hourly pass", async () => {
  const { db } = await import("../db.js");
  const { probeTargets } = await import("../probe_pass.js");
  const iid = "i-0feedfacecafe0001";
  db.prepare("delete from inventory_ec2 where instance_id = ?").run(iid);
  db.prepare("delete from instance_metrics where instance_id = ?").run(iid);
  const cols = (db.prepare("pragma table_info(inventory_ec2)").all() as any[]).map((c) => c.name);
  const row: Record<string, any> = { instance_id: iid, name: "t", state: "running", ssm_status: "Online", gone: 0, cpu_30d: 1, snapshot: "{}", first_seen: "2026-01-01", last_seen: "2026-01-01" };
  const use = Object.keys(row).filter((k) => cols.includes(k));
  db.prepare(`insert into inventory_ec2(${use.join(",")}) values (${use.map(() => "?").join(",")})`).run(...use.map((k) => row[k]));
  const iso = (minsAgo: number) => new Date(Date.now() - minsAgo * 60000).toISOString().replace(/\.\d{3}Z$/, "Z");
  db.prepare("insert into instance_metrics(instance_id, collected_at, json) values (?, ?, '{}')").run(iid, iso(3 * 60));
  assert.ok(probeTargets(1000).some((t) => t.instance_id === iid), "probed three hours ago: due again");
  db.prepare("insert into instance_metrics(instance_id, collected_at, json) values (?, ?, '{}')").run(iid, iso(10));
  assert.ok(!probeTargets(1000).some((t) => t.instance_id === iid), "probed ten minutes ago: skipped");
  for (const t of ["inventory_ec2", "instance_metrics"]) db.prepare(`delete from ${t} where instance_id = ?`).run(iid);
});

test("probe window: the configured hours minus a five-minute margin, never under a minute", async () => {
  const { probeWindowMinutes } = await import("../probe_pass.js");
  assert.equal(probeWindowMinutes(1), 55);
  assert.equal(probeWindowMinutes(24), 1435);
  assert.equal(probeWindowMinutes(0.05), 1);
});

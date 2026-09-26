import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { PROBE_SCRIPT, PROBE_VERSION, ProbeError, parseProbeOutput, summarizeProbe, useSummary } from "../ssm.js";

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
  assert.equal(p.disks[0].device, null, "a probe before 1.3 names no device");
  assert.equal(p.disks[0].volume_id, null);
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

test("parseProbeOutput keeps the device and volume id a 1.3 probe reports per mount", () => {
  const p = parseProbeOutput('{"probe":"aws-advisor/1","cpus":2,"uptime_seconds":1,"memory":{"total_bytes":1,"used_bytes":1,"available_bytes":0},"load":{"1m":0,"5m":0,"15m":0},"disks":[{"mount":"/","filesystem":"/dev/nvme0n1p1","device":"nvme0n1","volume_id":"vol-0abc","total_bytes":100,"used_bytes":50,"used_pct":50.0},{"mount":"/data","filesystem":"/dev/xvdf","device":"xvdf","volume_id":null,"total_bytes":100,"used_bytes":1,"used_pct":1.0}]}');
  assert.deepEqual(p.disks.map((d) => [d.device, d.volume_id]), [["nvme0n1", "vol-0abc"], ["xvdf", null]]);
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

const probe14 = () => JSON.stringify({
  probe: "aws-advisor/1", hostname: "swarm-27", collected_at: "2026-09-25T10:00:00Z", cpus: 4, uptime_seconds: 100,
  memory: { total_bytes: 100, used_bytes: 50, available_bytes: 50 }, load: { "1m": 0.1, "5m": 0.1, "15m": 0.1 }, disks: [], top_cpu: [], top_mem: [],
  docker: { available: true, running: 2, total: 2 },
  containers: [{ name: "relay", image: "sphinx/relay", state: "running", running_for: "9 days", cpu_pct: 0.2, mem_bytes: 1000, mem_pct: 1, net_rx_bytes: 5000, net_tx_bytes: 700 }, { name: "proxy", image: "nginx", state: "running", running_for: "9 days", cpu_pct: 0, mem_bytes: 100, mem_pct: 0 }],
  activity: {
    version: 1,
    containers: [
      { name: "relay", started_at: "2026-09-16T08:00:00Z", restarts: 0, log_lines: 300, last_log_at: "2026-09-25T09:59:00Z", errors: 2, warns: 1, signal_lines: 4, last_signal_at: "2026-09-24T18:30:00Z", signal_kinds: { message: 3, auth: 2, "bad kind": 1 }, signal_samples: ["new message from 02ab", "authorized macaroon"], last_lines: ["2026-09-25T09:59:00Z ping", "x".repeat(300)] },
      { name: "proxy", started_at: "2026-09-16T08:00:00Z", restarts: 41, log_lines: 2000, last_log_at: "2026-09-25T09:58:00Z", errors: 0, warns: 0, signal_lines: 0, last_signal_at: null, last_lines: [] },
    ],
    connections: { source: "conntrack", established: 3, external: 1, internal: 2, peers: 2, ssh: 0, by_port: { "443": 1, "22": 0, "bad": 9 }, top_peers: [{ ip: "203.0.113.5", port: 443, flows: 1, kind: "external" }, { ip: "10.0.1.9", port: 5002, flows: 2, kind: "internal" }], port_map: { "443": "proxy", "5002": "relay", "x": "no" } },
    front_door: { source: "container:proxy", requests: 7, health: 2880, last_request_at: "2026-09-25T07:12:00Z", last_request_raw: null, window: "24h" },
    logins: { users_now: 0, last_login_user: "ssm-user", last_login_at: "2026-09-20T11:00:00+00:00" },
    net: { rx_bytes: 123456789, tx_bytes: 987654 },
  },
});

test("probe 1.4: the activity section parses, is tolerant, and the use summary picks the newest real-use signal", () => {
  const p = parseProbeOutput(`noise\n${probe14()}`);
  assert.equal(PROBE_VERSION, "aws-advisor/1.5");
  assert.equal(p.containers?.[0].net_rx_bytes, 5000);
  assert.equal(p.containers?.[1].net_rx_bytes, null, "a container without NetIO reports null, not zero");
  const a = p.activity!;
  assert.equal(a.containers.length, 2);
  assert.equal(a.containers[0].last_lines[1].length, 160, "last lines are capped");
  assert.deepEqual(a.containers[0].signal_kinds, { message: 3, auth: 2 }, "a kind that is not a pattern name is dropped");
  assert.equal(a.containers[0].signal_samples.length, 2);
  assert.deepEqual(a.containers[1].signal_kinds, {}, "a 1.4 probe without kinds parses");
  assert.deepEqual(a.connections?.by_port, { "443": 1, "22": 0 }, "a port that is not a number is dropped");
  assert.deepEqual(a.connections?.port_map, { "443": "proxy", "5002": "relay" });
  assert.equal(a.connections?.top_peers[0].ip, "203.0.113.5");
  assert.equal(a.logins.last_login_at, "2026-09-20T11:00:00.000Z");
  const u = useSummary(p)!;
  assert.equal(u.last_use_at, "2026-09-25T10:00:00.000Z", "an external connection at probe time is the newest evidence");
  assert.equal(u.last_use_kind, "external_connection");
  assert.equal(u.requests_24h, 7);
  assert.equal(u.health_checks_24h, 2880);
  assert.equal(u.signal_lines_24h, 4);
  assert.deepEqual(u.restarting_containers, ["proxy"]);
  const s = summarizeProbe(p);
  assert.equal(s.last_use_at, "2026-09-25T10:00:00.000Z");
  // without the external connection the last request wins over the older signal line
  const q = JSON.parse(probe14()); q.activity.connections.external = 0;
  const u2 = useSummary(parseProbeOutput(JSON.stringify(q)))!;
  assert.equal(u2.last_use_kind, "request");
  assert.equal(u2.last_use_at, "2026-09-25T07:12:00.000Z");
  // a 1.3 probe has no activity and no summary line
  const old = JSON.parse(probe14()); delete old.activity;
  assert.equal(parseProbeOutput(JSON.stringify(old)).activity, undefined);
  assert.equal(useSummary(parseProbeOutput(JSON.stringify(old))), null);
  assert.equal(summarizeProbe(parseProbeOutput(JSON.stringify(old))).last_use_at, undefined);
});

test("probe 1.4: the activity script reads logs and counters only, and the history keeps the signals per container and per day", async () => {
  assert.match(PROBE_SCRIPT, /docker logs --since 24h --tail 2000 --timestamps/);
  assert.match(PROBE_SCRIPT, /"activity":%s/);
  assert.doesNotMatch(PROBE_SCRIPT, /docker (exec|run|restart|stop|start|rm)\b/);
  const { db } = await import("../db.js");
  const { recordContainerSamples, rollupDaily, instanceHistory, counterDelta } = await import("../history.js");
  const id = "i-0activity000000001";
  db.prepare("delete from instance_metrics where instance_id = ?").run(id);
  db.prepare("delete from container_samples where instance_id = ?").run(id);
  db.prepare("delete from instance_activity where instance_id = ?").run(id);
  db.prepare("delete from instance_daily where instance_id = ?").run(id);
  db.prepare("delete from container_daily where instance_id = ?").run(id);
  const day = new Date(Date.now() - 86400000).toISOString().slice(0, 10);
  for (const [h, rx] of [["01", 1000], ["02", 4000], ["03", 500]] as const) {
    const q = JSON.parse(probe14()); q.collected_at = `${day}T${h}:00:00Z`; q.activity.net.rx_bytes = rx; q.containers[0].net_rx_bytes = rx;
    db.prepare("insert into instance_metrics(instance_id, collected_at, json) values (?, ?, ?)").run(id, q.collected_at, JSON.stringify(q));
    recordContainerSamples(id, q.collected_at, parseProbeOutput(JSON.stringify(q)));
  }
  assert.equal((db.prepare("select count(*) as n from instance_activity where instance_id = ?").get(id) as any).n, 3);
  assert.equal(counterDelta([{ at: "1", rx: 1000, tx: 0 }, { at: "2", rx: 4000, tx: 0 }, { at: "3", rx: 500, tx: 0 }]), 3000, "a counter reset is not counted as negative traffic");
  rollupDaily(3);
  const h = instanceHistory(id, 7);
  const relay = h.containers.find((c: any) => c.name === "relay") as any;
  assert.equal(relay.signal_lines_avg, 4);
  assert.equal(relay.last_signal_at, "2026-09-24T18:30:00.000Z");
  assert.equal(relay.net_bytes, 3000);
  const proxy = h.containers.find((c: any) => c.name === "proxy") as any;
  assert.equal(proxy.restarts_max, 41);
  const d = (h.daily as any[]).find((x) => x.day === day);
  assert.equal(d.external_connections_max, 1);
  // the probes are dated yesterday, so the fixture's front-door request (today 07:12) is the newest evidence of that day
  assert.equal(d.last_use_kind, "request");
  assert.equal(d.last_use_at, "2026-09-25T07:12:00.000Z");
  assert.equal(d.net_bytes_day, 3000);
  assert.equal(h.activity.window.days_with_external, 1);
  assert.equal(h.activity.latest.requests_24h, 7);
  assert.deepEqual(JSON.parse(h.activity.latest.peers)[0], { ip: "203.0.113.5", port: 443, flows: 1, kind: "external", container: "proxy" });
});

test("use-signal rules: a kind ruled noise for an image stops counting, per image, and the agent can only propose", async () => {
  const { effectiveSignals, upsertRule, deleteRule, listRules, rulesFor, imageKey, validateRule } = await import("../signal_rules.js");
  for (const r of listRules()) deleteRule(r.id);
  assert.equal(imageKey("sphinxlightning/sphinx-boltwall:latest"), "sphinxlightning/sphinx-boltwall");
  assert.equal(imageKey("ghcr.io/stakwork/stakgraph-mcp@sha256:abc"), "ghcr.io/stakwork/stakgraph-mcp");
  assert.equal(effectiveSignals("sphinxlightning/sphinx-boltwall:latest", { auth: 200, write_request: 18 }, 215).signal_lines, 215, "no rule: the probe's exact count");
  const proposed = upsertRule({ image_pattern: "sphinxlightning/sphinx-boltwall", kind: "auth", verdict: "noise", note: "one line per macaroon check", decided_by: "agent", status: "proposed" });
  assert.equal(proposed.status, "proposed");
  assert.equal(effectiveSignals("sphinxlightning/sphinx-boltwall:latest", { auth: 200, write_request: 18 }, 215).signal_lines, 215, "a proposal changes nothing until confirmed");
  const confirmed = upsertRule({ image_pattern: "sphinxlightning/sphinx-boltwall", kind: "auth", verdict: "noise", note: "one line per macaroon check", decided_by: "gonzalo", status: "confirmed" });
  const e = effectiveSignals("sphinxlightning/sphinx-boltwall:latest", { auth: 200, write_request: 18 }, 215);
  assert.equal(e.signal_lines, 18);
  assert.deepEqual(e.noise_kinds, ["auth"]);
  assert.equal(effectiveSignals("sphinxlightning/sphinx-relay:latest", { auth: 5 }, 5).signal_lines, 5, "another image is untouched");
  assert.equal(rulesFor("sphinxlightning/sphinx-boltwall:v2").length, 1);
  assert.throws(() => upsertRule({ image_pattern: "sphinxlightning/sphinx-boltwall", kind: "auth", verdict: "signal", note: null, decided_by: "agent", status: "proposed" }), /a person has to change it/);
  assert.throws(() => validateRule({ image_pattern: "x y", kind: "auth", verdict: "noise" }), /image_pattern/);
  assert.throws(() => validateRule({ image_pattern: "x", kind: "nope", verdict: "noise" }), /kind/);
  // the use summary follows the rule: relay's only kinds are message and auth; ruling both noise removes its last use
  const { parseProbeOutput: parse, useSummary: use } = await import("../ssm.js");
  const q = JSON.parse(probe14()); q.activity.connections.external = 0; q.activity.front_door.last_request_at = null; q.activity.front_door.source = null; q.activity.logins.last_login_at = null;
  assert.equal(use(parse(JSON.stringify(q)))!.last_use_kind, "signal_line");
  upsertRule({ image_pattern: "sphinx/relay", kind: "message", verdict: "noise", note: null, decided_by: "t", status: "confirmed" });
  upsertRule({ image_pattern: "sphinx/relay", kind: "auth", verdict: "noise", note: null, decided_by: "t", status: "confirmed" });
  const u = use(parse(JSON.stringify(q)))!;
  assert.equal(u.last_use_at, null);
  assert.equal(u.signal_lines_24h, 0);
  deleteRule(confirmed.id);
  for (const r of listRules()) deleteRule(r.id);
});

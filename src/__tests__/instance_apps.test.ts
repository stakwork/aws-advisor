import assert from "node:assert/strict";
import { test } from "node:test";
import { db } from "../db.js";
import { ALERT_MIN_AGE_S, appEvents, appsFromProbe, appsOn, fleetApps, recordApps, whereRuns } from "../instance_apps.js";
import { parseProbeOutput } from "../ssm.js";

const proc = (name: string, user = "app", extra: Partial<{ count: number; cpu_pct: number; rss_bytes: number; oldest_seconds: number; command: string }> = {}) =>
  ({ name, user, count: 1, cpu_pct: 0, rss_bytes: 100e6, oldest_seconds: 600, command: name, ...extra });

test("apps from a probe: the OS and the probe's own utilities are dropped, platform pieces are infra, the rest are apps", () => {
  const apps = appsFromProbe({ processes: [
    proc("systemd", "root"), proc("sshd", "root"), proc("amazon-ssm-agen", "root"), proc("ps", "root"), proc("awk", "root"), proc("bash", "ec2-user"),
    proc("containerd-shim", "root", { count: 4 }), proc("dockerd", "root"), proc("amazon-cloudwat", "root"),
    proc("postgres", "postgres", { count: 8, rss_bytes: 2e9 }), proc("node server.js", "app", { rss_bytes: 400e6 }), proc("python3 worker.py", "app", { count: 3 }), proc("nginx", "www-data", { count: 5 }),
  ] });
  assert.deepEqual(apps.map((a) => a.name), ["postgres", "node server.js", "python3 worker.py", "nginx", "amazon-ssm-agen", "containerd-shim", "dockerd", "amazon-cloudwat"], "apps first, then infra, biggest first");
  assert.deepEqual(apps.filter((a) => a.kind === "infra").map((a) => a.name), ["amazon-ssm-agen", "containerd-shim", "dockerd", "amazon-cloudwat"]);
  assert.equal(apps.find((a) => a.name === "python3 worker.py")!.count, 3);
  assert.deepEqual(appsFromProbe({ processes: undefined }), []);
});

test("probe 1.6 output: the process list and the log shipping parse and older probes still do", () => {
  const out = parseProbeOutput(JSON.stringify({ probe: "aws-advisor/1", hostname: "h", collected_at: "2026-09-28T10:00:00Z", cpus: 2, uptime_seconds: 100, memory: { total_bytes: 1, used_bytes: 1, available_bytes: 0 }, load: { "1m": 0, "5m": 0, "15m": 0 }, disks: [], top_cpu: [], top_mem: [],
    log_shipping: [{ group: "/app/web", via: "cloudwatch-agent", source: "/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json" }, { group: "", via: "x" }, { group: "/docker/web", via: "docker:web", source: "log driver" }],
    processes: [{ name: "nginx", user: "www-data", count: "5", cpu_pct: "1.5", rss_bytes: "52428800", oldest_seconds: "86400", command: "nginx: master process" }, { name: "" }, { user: "x" }] }));
  assert.deepEqual(out.log_shipping, [{ group: "/app/web", via: "cloudwatch-agent", source: "/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json" }, { group: "/docker/web", via: "docker:web", source: "log driver" }]);
  assert.deepEqual(out.processes, [{ name: "nginx", user: "www-data", count: 5, cpu_pct: 1.5, rss_bytes: 52428800, oldest_seconds: 86400, command: "nginx: master process" }]);
  const old = parseProbeOutput(JSON.stringify({ probe: "aws-advisor/1", hostname: "h", collected_at: "2026-09-28T10:00:00Z", cpus: 2, uptime_seconds: 100, memory: { total_bytes: 1, used_bytes: 1, available_bytes: 0 }, load: { "1m": 0, "5m": 0, "15m": 0 }, disks: [], top_cpu: [], top_mem: [] }));
  assert.equal(old.processes, undefined); assert.equal(old.log_shipping, undefined);
});

test("recording apps: first probe is silent, then appear / disappear / return events, and a long-running app that vanishes raises an alert", () => {
  const id = "i-apps0000000001";
  db.prepare("delete from instance_apps where instance_id = ?").run(id); db.prepare("delete from instance_app_events where instance_id = ?").run(id); db.prepare("delete from alerts where resource = ?").run(id);
  assert.equal(recordApps(id, "2026-09-28T10:00:00Z", { processes: undefined }), null, "a probe without a process list records nothing");
  const day1 = [proc("postgres", "postgres", { oldest_seconds: 30 * 86400 }), proc("node server.js"), proc("systemd", "root"), proc("dockerd", "root")];
  const r1 = recordApps(id, "2026-09-28T10:00:00Z", { processes: day1 }, "web-1")!;
  assert.equal(r1.apps, 3); assert.deepEqual(r1.appeared, []); assert.deepEqual(r1.disappeared, []);
  assert.equal(appsOn(id).length, 3); assert.equal(appEvents({ instance_id: id }).length, 0, "the first inventory is not news");
  // second probe: a cron-like one-off appears; node is still there
  const r2 = recordApps(id, "2026-09-28T11:00:00Z", { processes: [...day1, proc("backup.sh-runner", "root", { oldest_seconds: 5 })] }, "web-1")!;
  assert.deepEqual(r2.appeared, ["backup.sh-runner"]);
  // third probe: the one-off is gone (seen once, young: no event), postgres is gone (30 days old, seen twice: event and alert), node stays
  const r3 = recordApps(id, "2026-09-28T12:00:00Z", { processes: [proc("node server.js"), proc("dockerd", "root")] }, "web-1")!;
  assert.deepEqual(r3.disappeared, ["postgres"]); assert.equal(r3.alerts, 1);
  const alert = db.prepare("select kind, message, details from alerts where resource = ? and kind = 'app_gone'").get(id) as any;
  assert.match(alert.message, /^web-1 \(i-apps0000000001\): postgres is no longer running \(it had run for 30 days/);
  assert.equal(JSON.parse(alert.details).app, "postgres");
  assert.equal(appsOn(id).length, 2); assert.equal(appsOn(id, true).filter((a) => a.gone).length, 2, "postgres and the one-off are kept as gone");
  // fourth probe: postgres is back; no second alert while the first is open
  const r4 = recordApps(id, "2026-09-28T13:00:00Z", { processes: [...day1] }, "web-1")!;
  assert.deepEqual(r4.returned, ["postgres"]);
  const ev = appEvents({ instance_id: id }).map((e) => `${e.event}:${e.name}`);
  assert.deepEqual(ev, ["returned:postgres", "disappeared:postgres", "appeared:backup.sh-runner"]);
  recordApps(id, "2026-09-28T14:00:00Z", { processes: [proc("node server.js")] }, "web-1");
  assert.equal((db.prepare("select count(*) as n from alerts where resource = ? and kind = 'app_gone'").get(id) as { n: number }).n, 1, "an open app_gone alert is not repeated");
  assert.ok(ALERT_MIN_AGE_S === 86_400);
  assert.equal(whereRuns("node").some((w) => w.instance_id === id), true);
  assert.ok(fleetApps("app").some((f) => f.name === "node server.js" && f.instance_ids.includes(id)));
  db.prepare("delete from instance_apps where instance_id = ?").run(id); db.prepare("delete from instance_app_events where instance_id = ?").run(id); db.prepare("delete from alerts where resource = ?").run(id);
});

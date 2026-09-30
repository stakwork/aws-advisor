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

test("probe 1.8 ports: listeners parse, a host socket and its published container port merge, owners match the apps, exposure follows the security group rules", async () => {
  const out = parseProbeOutput(JSON.stringify({ probe: "aws-advisor/1", hostname: "h", collected_at: "2026-09-30T10:00:00Z", cpus: 2, uptime_seconds: 100, memory: { total_bytes: 1, used_bytes: 1, available_bytes: 0 }, load: { "1m": 0, "5m": 0, "15m": 0 }, disks: [], top_cpu: [], top_mem: [],
    listeners: [{ proto: "tcp", port: "443", bind: "0.0.0.0", scope: "all", process: "docker-proxy", pid: "77" }, { proto: "tcp", port: 443, bind: "0.0.0.0", scope: "all", container: "web", container_port: 8443 },
      { proto: "tcp", port: 22, bind: "0.0.0.0", scope: "all", process: "sshd", pid: 12 }, { proto: "tcp", port: 5432, bind: "127.0.0.1", scope: "loopback", process: "postgres", pid: 30 }, { proto: "udp", port: 68, bind: "0.0.0.0", scope: "all", process: "dhclient" },
      { proto: "sctp", port: 1 }, { proto: "tcp", port: 70000 }, { port: 80 }] }));
  assert.equal(out.listeners!.length, 5, "bad protocols, bad ports and missing fields are dropped");
  const { listenersFromProbe, ownerOf, exposureOf, portsFromProbe } = await import("../instance_apps.js");
  const merged = listenersFromProbe(out);
  assert.deepEqual(merged.map((l) => `${l.port}/${l.proto}`), ["22/tcp", "68/udp", "443/tcp", "5432/tcp"]);
  const https = merged.find((l) => l.port === 443)!;
  assert.equal(https.container, "web"); assert.equal(https.container_port, 8443); assert.equal(https.pid, 77); assert.equal(https.process, null, "docker-proxy is not the owner");
  const apps = [{ name: "postgres" }, { name: "node server.js" }, { name: "nginx" }];
  assert.equal(ownerOf({ process: "node", container: null }, apps), "node server.js", "the program name matches the app by its first word");
  assert.equal(ownerOf({ process: "postgres", container: null }, apps), "postgres");
  assert.equal(ownerOf({ process: null, container: "web" }, apps), "web");
  assert.equal(ownerOf({ process: "sshd", container: null }, apps), "sshd", "an OS daemon keeps its own name");
  const rules = [
    { group_id: "sg-1", ip_protocol: "tcp", from_port: 443, to_port: 443, cidr_ipv4: "0.0.0.0/0", cidr_ipv6: null, referenced_group_id: null, prefix_list_id: null },
    { group_id: "sg-1", ip_protocol: "tcp", from_port: 22, to_port: 22, cidr_ipv4: "10.0.0.0/8", cidr_ipv6: null, referenced_group_id: null, prefix_list_id: null },
    { group_id: "sg-1", ip_protocol: "tcp", from_port: 5432, to_port: 5432, cidr_ipv4: null, cidr_ipv6: null, referenced_group_id: "sg-2", prefix_list_id: null },
    { group_id: "sg-1", ip_protocol: "-1", from_port: null, to_port: null, cidr_ipv4: null, cidr_ipv6: null, referenced_group_id: "sg-1", prefix_list_id: null },
  ];
  assert.equal(exposureOf({ proto: "tcp", port: 443, scope: "all" }, rules), "internet");
  assert.equal(exposureOf({ proto: "tcp", port: 22, scope: "all" }, rules), "network");
  assert.equal(exposureOf({ proto: "tcp", port: 5432, scope: "all" }, rules), "group");
  assert.equal(exposureOf({ proto: "tcp", port: 5432, scope: "loopback" }, rules), "local", "loopback wins whatever the rules say");
  assert.equal(exposureOf({ proto: "udp", port: 68, scope: "all" }, rules), "group", "the all-traffic rule from the group itself");
  assert.equal(exposureOf({ proto: "tcp", port: 9999, scope: "all" }, [rules[0]]), "closed");
  const ports = portsFromProbe({ listeners: out.listeners, processes: [{ name: "postgres", user: "postgres", count: 1, cpu_pct: 0, rss_bytes: 1, oldest_seconds: 1, command: "postgres" }] }, rules);
  assert.deepEqual(ports.map((p) => [p.port, p.app_name, p.exposure]), [[22, "sshd", "network"], [68, "dhclient", "group"], [443, "web", "internet"], [5432, "postgres", "local"]]);
});

test("recording ports: first probe is silent, an opened internet-facing port raises port_exposed once, a closed port is an event", async () => {
  const { recordPorts, portsOn, replaceIngressRules, whereListens, fleetPorts } = await import("../instance_apps.js");
  const id = "i-ports000000001";
  db.prepare("delete from instance_ports where instance_id = ?").run(id); db.prepare("delete from instance_app_events where instance_id = ?").run(id); db.prepare("delete from alerts where resource = ?").run(id);
  db.prepare("insert or replace into inventory_ec2(instance_id, name, state, region, snapshot, gone) values (?, 'web-1', 'running', 'us-east-1', ?, 0)").run(id, JSON.stringify({ network: { security_groups: [{ GroupId: "sg-ports1", GroupName: "web" }] } }));
  replaceIngressRules([{ group_id: "sg-ports1", ip_protocol: "tcp", from_port: 80, to_port: 443, cidr_ipv4: "0.0.0.0/0", cidr_ipv6: null, referenced_group_id: null, prefix_list_id: null }]);
  const l = (port: number, extra: Partial<import("../ssm.js").ProbeListener> = {}): import("../ssm.js").ProbeListener => ({ proto: "tcp", port, bind: "0.0.0.0", scope: "all", process: "nginx", pid: 1, container: null, container_port: null, ...extra });
  assert.equal(recordPorts(id, "2026-09-30T10:00:00Z", { listeners: undefined, processes: [] }), null, "a probe without listeners records nothing");
  const r1 = recordPorts(id, "2026-09-30T10:00:00Z", { listeners: [l(22, { process: "sshd" }), l(443)], processes: [] }, "web-1")!;
  assert.equal(r1.ports, 2); assert.deepEqual(r1.opened, []); assert.equal(r1.alerts, 1, "443 is open to the internet: alerted even on the first inventory");
  assert.equal(portsOn(id)[0].exposure, "internet"); assert.equal(portsOn(id)[0].port, 443);
  const r2 = recordPorts(id, "2026-09-30T11:00:00Z", { listeners: [l(22, { process: "sshd" }), l(443), l(8080, { process: "node" })], processes: [] }, "web-1")!;
  assert.deepEqual(r2.opened, ["8080/tcp (node)"]); assert.equal(r2.alerts, 0, "8080 is not let in by the rules");
  const r3 = recordPorts(id, "2026-09-30T12:00:00Z", { listeners: [l(22, { process: "sshd" }), l(443)], processes: [] }, "web-1")!;
  assert.deepEqual(r3.closed, ["8080/tcp (node)"]);
  assert.deepEqual(db.prepare("select event, name from instance_app_events where instance_id = ? order by id").all(id), [{ event: "port_opened", name: "node" }, { event: "port_closed", name: "node" }]);
  assert.equal((db.prepare("select count(*) as n from alerts where resource = ? and kind = 'port_exposed'").get(id) as { n: number }).n, 1);
  assert.ok(whereListens(443).some((w) => w.instance_id === id && w.instance_name === "web-1"));
  assert.ok(fleetPorts().some((f) => f.port === 443 && f.instance_ids.includes(id) && f.exposures.internet === 1));
  db.prepare("delete from instance_ports where instance_id = ?").run(id); db.prepare("delete from instance_app_events where instance_id = ?").run(id); db.prepare("delete from alerts where resource = ?").run(id); db.prepare("delete from inventory_ec2 where instance_id = ?").run(id);
});

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

test("ports: which rule lets a port in, what blocks it, a box without a public address, and rules nothing listens on", async () => {
  const { reachOf, ruleRef, rulesWithoutListener } = await import("../instance_apps.js");
  const r = (o: Partial<{ ip_protocol: string | null; from_port: number | null; to_port: number | null; cidr_ipv4: string | null; referenced_group_id: string | null; description: string | null }>) =>
    ({ group_id: "sg-0example1", ip_protocol: "tcp", from_port: null, to_port: null, cidr_ipv4: null, cidr_ipv6: null, referenced_group_id: null, prefix_list_id: null, rule_id: null, description: null, ...o });
  const names = { "sg-0example1": "web-sg" };
  const allWorld = r({ ip_protocol: "-1", cidr_ipv4: "0.0.0.0/0" });
  const https = r({ from_port: 443, to_port: 443, cidr_ipv4: "0.0.0.0/0", description: "web" });
  const ssh = r({ from_port: 22, to_port: 22, cidr_ipv4: "10.0.0.0/8" });
  const mqtt = r({ from_port: 1883, to_port: 1883, cidr_ipv4: "0.0.0.0/0" });
  const redis = { proto: "tcp" as const, port: 6379, scope: "all" as const, bind: "0.0.0.0" };

  assert.deepEqual(ruleRef(allWorld, names), { group_id: "sg-0example1", group_name: "web-sg", rule_id: null, ports: "all traffic", source: "anywhere", description: null, world: true, broad: true });
  assert.equal(ruleRef(r({ from_port: 7000, to_port: 9200, cidr_ipv4: "0.0.0.0/0" })).broad, true, "a 2,201-port range open to the world is broad");
  assert.equal(ruleRef(https).broad, false);
  assert.equal(ruleRef(r({ ip_protocol: "6", from_port: 8000, to_port: 8010, cidr_ipv4: "10.1.0.0/16" })).ports, "tcp 8000-8010");

  const open = reachOf(redis, [https, ssh, allWorld], { public_ip: "203.0.113.10", group_names: names });
  assert.equal(open.exposure, "internet");
  assert.equal(open.broad, true);
  assert.equal(open.allowed_by[0].ports, "all traffic");
  assert.match(open.reason, /^open to the internet: web-sg allows all traffic from anywhere, a broad rule/);

  const blocked = reachOf(redis, [https, ssh], { public_ip: "203.0.113.10", group_names: names });
  assert.equal(blocked.exposure, "closed");
  assert.equal(blocked.reason, "blocked by the security groups: no rule in web-sg (sg-0example1) lets 6379/tcp in");

  const priv = reachOf(redis, [allWorld], { public_ip: null, group_names: names });
  assert.equal(priv.exposure, "network", "a world rule on a box with no public address is the VPC, not the internet");
  assert.match(priv.reason, /no public address: reachable from inside the VPC only/);
  assert.equal(reachOf(redis, [allWorld], {}).exposure, "internet", "an unknown address keeps the old answer");

  assert.equal(reachOf({ ...redis, scope: "loopback", bind: "127.0.0.1" }, [allWorld], { public_ip: "198.51.100.7" }).exposure, "local");
  assert.equal(reachOf({ proto: "tcp", port: 443, scope: "all", bind: "0.0.0.0" }, [https], { public_ip: "198.51.100.7", group_names: names }).reason, 'open to the internet: web-sg allows tcp 443 from anywhere ("web")');
  assert.equal(reachOf({ proto: "tcp", port: 7474, scope: "all", bind: "0.0.0.0" }, [r({ from_port: 7000, to_port: 9200, cidr_ipv4: "0.0.0.0/0" })], { public_ip: "198.51.100.7", group_names: names }).reason, "open to the internet: web-sg allows tcp 7000-9200 from anywhere, a broad range that opens whatever listens in it");

  // an all-traffic rule is IPv6-only and the box has no IPv6 address, so it opens nothing
  const allV6 = { ...r({ ip_protocol: "-1" }), cidr_ipv6: "::/0" };
  const v6 = reachOf(redis, [https, allV6], { public_ip: "203.0.113.10", ipv6: [], group_names: names });
  assert.equal(v6.exposure, "closed");
  assert.equal(v6.reason, "blocked by the security groups: only web-sg's all traffic rule from anywhere over IPv6 covers 6379/tcp, and the box has no IPv6 address");
  assert.equal(reachOf(redis, [allV6], { public_ip: null, ipv6: ["2001:db8::1"], group_names: names }).exposure, "internet", "with an IPv6 address the IPv6 rule is the internet, public IPv4 or not");
  assert.equal(reachOf(redis, [allV6], { public_ip: "198.51.100.7", group_names: names }).exposure, "internet", "IPv6 addresses not known yet: the old answer");
  assert.deepEqual(rulesWithoutListener([allV6, https], [{ proto: "tcp", port: 443, scope: "all" }], names, []).map((u) => [u.ports, u.source, u.unreachable]), [["all traffic", "anywhere over IPv6", true]]);

  const unused = rulesWithoutListener([allWorld, https, ssh, mqtt], [{ proto: "tcp", port: 443, scope: "all" }, { proto: "tcp", port: 22, scope: "loopback" }], names);
  assert.deepEqual(unused.map((u) => `${u.ports} from ${u.source}`), ["tcp 1883 from anywhere", "tcp 22 from 10.0.0.0/8"], "all-traffic rules always cover something; a loopback socket does not use a rule");
});

test("network ACLs: first matching rule by number wins, narrow denies are exceptions, the replies need an outbound rule", async () => {
  const { cidrContains, naclDecide, naclVerdict, reachOf } = await import("../instance_apps.js");
  type E = import("../instance_apps.js").NaclEntry;
  const e = (RuleNumber: number, RuleAction: string, Egress: boolean, CidrBlock: string, Protocol = "-1", PortRange: E["PortRange"] = null): E => ({ RuleNumber, RuleAction, Egress, Protocol, CidrBlock, Ipv6CidrBlock: null, PortRange });
  const DEFAULT: E[] = [e(100, "allow", false, "0.0.0.0/0"), e(32767, "deny", false, "0.0.0.0/0"), e(100, "allow", true, "0.0.0.0/0"), e(32767, "deny", true, "0.0.0.0/0")];

  assert.ok(cidrContains("0.0.0.0/0", "203.0.113.0/24"));
  assert.ok(cidrContains("10.0.0.0/8", "10.9.0.0/16"));
  assert.ok(!cidrContains("10.9.0.0/16", "10.0.0.0/8"));
  assert.ok(!cidrContains("203.0.113.7/32", "0.0.0.0/0"));
  assert.ok(cidrContains("::/0", "2001:db8::/32"));

  assert.equal(naclVerdict(DEFAULT, "tcp", 443, "0.0.0.0/0").verdict, "allow", "the default ACL lets everything in and out");
  // a few attackers blocked does not close the port to the internet
  const blocklist = [e(90, "deny", false, "203.0.113.7/32"), ...DEFAULT];
  assert.equal(naclDecide(blocklist, false, "tcp", 443, "0.0.0.0/0").entry?.RuleNumber, 100);
  assert.equal(naclVerdict(blocklist, "tcp", 443, "0.0.0.0/0").verdict, "allow");
  // a deny on the port from anywhere, before the allow, blocks it
  const noRedis = [e(50, "deny", false, "0.0.0.0/0", "6", { From: 6379, To: 6379 }), ...DEFAULT];
  assert.equal(naclVerdict(noRedis, "tcp", 6379, "0.0.0.0/0").verdict, "deny");
  assert.equal(naclVerdict(noRedis, "tcp", 443, "0.0.0.0/0").verdict, "allow");
  assert.equal(naclVerdict(noRedis, "udp", 6379, "0.0.0.0/0").verdict, "allow", "the deny is tcp only");
  // only one network allowed in, the rest of the world denied: reachable from that network only
  const office = [e(10, "allow", false, "198.51.100.0/24", "6", { From: 22, To: 22 }), e(20, "deny", false, "0.0.0.0/0", "6", { From: 22, To: 22 }), ...DEFAULT];
  assert.deepEqual(naclVerdict(office, "tcp", 22, "0.0.0.0/0"), { verdict: "narrow", cidrs: ["198.51.100.0/24"], entry: office[1], reply_entry: null, partial_reply: false });
  // stateless: no outbound rule for the replies means nobody can use the port
  const noOut: E[] = [e(100, "allow", false, "0.0.0.0/0"), e(32767, "deny", true, "0.0.0.0/0")];
  assert.equal(naclVerdict(noOut, "tcp", 443, "0.0.0.0/0").verdict, "no_reply");
  const linuxOnly: E[] = [e(100, "allow", false, "0.0.0.0/0"), e(100, "allow", true, "0.0.0.0/0", "6", { From: 32768, To: 60999 })];
  const half = naclVerdict(linuxOnly, "tcp", 443, "0.0.0.0/0");
  assert.equal(half.verdict, "allow"); assert.equal(half.partial_reply, true, "clients on 61000-65535 get no reply");

  // through reachOf: the security group lets it in, the ACL does not
  const sg = [{ group_id: "sg-0example1", ip_protocol: "tcp", from_port: 6379, to_port: 6379, cidr_ipv4: "0.0.0.0/0", cidr_ipv6: null, referenced_group_id: null, prefix_list_id: null }];
  const redis = { proto: "tcp" as const, port: 6379, scope: "all" as const, bind: "0.0.0.0" };
  const blocked = reachOf(redis, sg, { public_ip: "203.0.113.10", group_names: { "sg-0example1": "web-sg" }, nacl: { acl_id: "acl-0example1", entries: noRedis } });
  assert.equal(blocked.exposure, "closed");
  assert.equal(blocked.blocked_by, "network_acl");
  assert.equal(blocked.reason, "blocked by network ACL: web-sg lets 6379/tcp in from anywhere, but acl-0example1 rule #50 denies tcp 6379 from 0.0.0.0/0");
  const open = reachOf(redis, sg, { public_ip: "203.0.113.10", nacl: { acl_id: "acl-0example1", entries: DEFAULT } });
  assert.equal(open.exposure, "internet"); assert.equal(open.blocked_by, null);
  assert.equal(reachOf(redis, [], { public_ip: "203.0.113.10" }).blocked_by, "security_group");
  const narrow = reachOf({ ...redis, port: 22 }, [{ ...sg[0], from_port: 22, to_port: 22 }], { public_ip: "203.0.113.10", nacl: { acl_id: "acl-0example1", entries: office } });
  assert.equal(narrow.exposure, "network");
  assert.equal(narrow.allowed_by[0].source, "198.51.100.0/24");
  assert.match(narrow.nacl_note ?? "", /lets in only 198\.51\.100\.0\/24/);
});

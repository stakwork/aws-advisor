import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "advisor-ksmbd-test-"));
process.env.TYPESAFE_API_KEY = "";

const pr = await import("../probes.js");
const sw = await import("../software_inventory.js");
const ssm = await import("../ssm.js");
const kx = await import("../ksmbd_exposure.js");
const { db } = await import("../db.js");

const reading = (over: Partial<import("../software_inventory.js").ProbeKsmbd> = {}): import("../software_inventory.js").ProbeKsmbd => ({
  module_loaded: false, module_sysfs: false, module_file: false, builtin: false, config: null, config_smbdirect: null, autoload: false, modules: [], kthreads: 0, daemons: [],
  units_installed: [], units_enabled: [], listeners: [], rdma_devices: [], conf_files: [], shares: [], settings: {}, smb_direct_cfg: null, ...over,
});
const serving = (over: Partial<import("../software_inventory.js").ProbeKsmbd> = {}) => reading({ module_loaded: true, module_sysfs: true, module_file: true, config: "m", modules: ["ksmbd"], kthreads: 2, daemons: ["ksmbd.mountd"],
  listeners: [{ proto: "tcp", port: 445, scope: "all", process: null }], conf_files: ["/etc/ksmbd/ksmbd.conf"], shares: [{ name: "data", path: "/srv/data", read_only: false, guest: false, hosts_allow: null }], ...over });
const p445 = (exposure: string) => [{ proto: "tcp", port: 445, scope: "all", process: null, exposure }];

test("the probe script's ksmbd section reads the box read-only: module, kernel threads, listeners, RDMA, shares without secrets", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "ksmbd-fx-"));
  const w = (f: string, t: string) => { fs.mkdirSync(path.dirname(path.join(root, f)), { recursive: true }); fs.writeFileSync(path.join(root, f), t); };
  w("proc/modules", "ksmbd 1 0 - Live 0x0\nrdma_rxe 1 0 - Live 0x0\next4 1 0 - Live 0x0\n");
  w("sys/module/ksmbd/.keep", ""); w("sys/class/infiniband/rxe0/.keep", "");
  w("boot/config-6.8.0-fx", "CONFIG_SMB_SERVER=m\n# CONFIG_SMB_SERVER_SMBDIRECT is not set\n");
  w("etc/ksmbd/ksmbd.conf", "[global]\n server min protocol = SMB2_10\n smb direct = yes\n password = hunter2\n[data] ; c\n path = /srv/data\n read only = no\n username = bob\n guest ok = yes\n[ro]\n path = /srv/ro\n");
  w("etc/samba/smb.conf", "[global]\n usershare path = /var/x\n[homes]\n writable = yes\n smb passwd file = /etc/samba/smbpasswd\n");
  const bin = path.join(root, "bin"); fs.mkdirSync(bin);
  const fake = (n: string, body: string) => fs.writeFileSync(path.join(bin, n), `#!/bin/sh\n${body}\n`, { mode: 0o755 });
  fake("uname", 'case "$1" in -r) echo 6.8.0-fx;; -m) echo x86_64;; *) echo Linux;; esac');
  fake("dpkg-query", "exit 0"); // a small package list: the host's own would push the line into the gzip form
  fake("ss", "printf 'LISTEN 0 64 0.0.0.0:445 0.0.0.0:*\\nLISTEN 0 64 127.0.0.1:139 0.0.0.0:* users:((\"smbd\",pid=9,fd=3))\\nLISTEN 0 64 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))\\n'");
  fake("ps", 'case "$*" in *ppid*) printf "    2 ksmbd:445\\n    2 kworker/0:1\\n  100 bash\\n";; *) printf "ksmbd.mountd\\nbash\\n";; esac');
  const script = pr.defaultProbeScript("software")
    .replace(/\/proc\/modules/g, `${root}/proc/modules`).replace(/\/sys\/module\/ksmbd/g, `${root}/sys/module/ksmbd`).replace(/\/sys\/class\/infiniband/g, `${root}/sys/class/infiniband`)
    .replace(/\/boot\/config-/g, `${root}/boot/config-`).replace(/\/etc\/ksmbd\/ksmbd\.conf/g, `${root}/etc/ksmbd/ksmbd.conf`).replace(/\/etc\/samba\/smb\.conf/g, `${root}/etc/samba/smb.conf`);
  const r = spawnSync("sh", [], { input: script, encoding: "utf8", env: { ...process.env, PATH: `${bin}:${process.env.PATH}` } });
  const out = ssm.parseProbeOutput(r.stdout);
  assert.equal(out.probe, "aws-advisor/software/4");
  const k = out.ksmbd!;
  assert.equal(k.module_loaded, true); assert.equal(k.module_sysfs, true); assert.deepEqual(k.modules.sort(), ["ksmbd", "rdma_rxe"]);
  assert.equal(k.config, "m"); assert.equal(k.config_smbdirect, "n");
  assert.equal(k.kthreads, 1); assert.deepEqual(k.daemons, ["ksmbd.mountd"]);
  assert.deepEqual(k.rdma_devices, ["rxe0"]);
  assert.deepEqual(k.listeners.map((l) => [l.port, l.scope, l.process]).sort(), [[139, "loopback", "smbd"], [445, "all", null]]);
  assert.equal(k.smb_direct_cfg, true); assert.equal(k.settings["smb direct"], "yes"); assert.equal(k.settings["server min protocol"], "SMB2_10");
  assert.deepEqual(k.shares.map((s) => [s.name, s.path, s.read_only, s.guest]), [["data", "/srv/data", false, true], ["ro", "/srv/ro", true, false], ["homes", null, false, false]]);
  assert.equal(k.conf_files.length, 2);
  const raw = r.stdout;
  for (const secret of ["hunter2", "bob", "smbpasswd", "usershare"]) assert.ok(!raw.includes(secret), `${secret} must never reach the output`);
});

test("the software script stays inside the read-only guard and a box without ksmbd or config reads as empty, not as an error", () => {
  const script = pr.defaultProbeScript("software");
  for (const word of [/\bsystemctl\b/, /\bsudo\b/, /\brm\b/, /\bchmod\b/]) assert.ok(!word.test(script), String(word));
  assert.doesNotThrow(() => pr.setProbeScriptOverride("software", script));
  assert.ok(!/ksmbdpwd|smbpasswd|passdb|tdbsam/.test(script.split("\n").filter((l) => !l.startsWith("#")).join("\n")), "the password databases are never opened");
  const r = spawnSync("sh", [], { input: script, encoding: "utf8", env: { ...process.env, PATH: process.env.PATH } });
  const k = ssm.parseProbeOutput(r.stdout).ksmbd!;
  assert.equal(typeof k.module_loaded, "boolean"); assert.deepEqual(k.shares, []);
});

test("parseProbeOutput keeps software 4's ksmbd section typed and capped, drops what is not whitelisted, and is absent for an older probe", () => {
  const base = { probe: "aws-advisor/software/4", kind: "software", hostname: "box", collected_at: "2026-10-09T03:11:11Z", os: { id: "ubuntu", version: "24.04", name: "Ubuntu" }, kernel: "6.8.0", arch: "x86_64", package_manager: "deb", packages: [{ n: "bash", v: "5.2", a: "amd64" }], binaries: [], images: [] };
  const k = { module_loaded: true, config: "m", config_smbdirect: "x", modules: ["ksmbd", "é"], kthreads: 3, daemons: ["ksmbd.mountd"], listeners: [{ proto: "tcp", port: 445, scope: "all", process: null }, { proto: "tcp", port: 22, scope: "all", process: "sshd" }],
    shares: [{ name: "a\u0001b", path: "/srv", read_only: false, guest: true }], settings: { "smb direct": "yes" }, password: "x", smb_direct_cfg: true };
  const data = ssm.parseProbeOutput(JSON.stringify({ ...base, ksmbd: k }));
  assert.equal(data.ksmbd?.module_loaded, true); assert.equal(data.ksmbd?.config_smbdirect, null);
  assert.deepEqual(data.ksmbd?.listeners, [{ proto: "tcp", port: 445, scope: "all", process: null }], "only the SMB ports are kept");
  assert.equal(data.ksmbd?.shares[0].name, "ab"); assert.equal((data.ksmbd as any).password, undefined);
  assert.equal(ssm.parseProbeOutput(JSON.stringify(base)).ksmbd, undefined);
  assert.ok(pr.PROBE_DEFS.software.sections.includes("ksmbd"), "the merged view takes the section from the software row");
});

test("the ksmbd section is stored on the OS row; an older probe without it leaves the last reading in place", () => {
  const iid = "i-0feedfacecafe0201";
  assert.equal(sw.ksmbdOf(iid), null);
  sw.recordSoftware(iid, "2026-10-01T00:00:00Z", { package_manager: "deb", packages: [{ n: "bash", v: "5", a: "amd64" }], ksmbd: serving() });
  assert.equal(sw.ksmbdOf(iid)?.probe.kthreads, 2);
  sw.recordSoftware(iid, "2026-10-02T00:00:00Z", { package_manager: "deb", packages: [{ n: "bash", v: "5", a: "amd64" }] });
  assert.deepEqual(sw.ksmbdOf(iid), { probe: serving(), collected_at: "2026-10-02T00:00:00Z" });
  for (const t of ["instance_os", "instance_packages", "package_changes"]) db.prepare(`delete from ${t} where instance_id = ?`).run(iid);
});

test("verdict: ZDI-CAN-33774 is flagged only with ksmbd active and 445 reachable; loopback, closed or not loaded are not", () => {
  const v = (probe: any, ports: any[] = [], extra: any = {}) => kx.ksmbdVerdict({ probe, ports, kernel: "6.8.0-45-generic", ...extra });
  assert.equal(v(null).state, "unknown"); assert.equal(v(null).flags.pre_auth.status, "unknown");
  const open = v(serving(), p445("internet"));
  assert.equal(open.state, "serving_exposed"); assert.equal(open.flags.pre_auth.status, "flagged"); assert.match(open.flags.pre_auth.reasons[0], /tcp 445 \(internet\)/);
  assert.equal(open.listening[0].kernel_owned, true);
  assert.equal(v(serving(), p445("network")).state, "serving_exposed");
  const closed = v(serving(), p445("closed")); assert.equal(closed.state, "serving_internal"); assert.equal(closed.flags.pre_auth.status, "low");
  const lo = v(serving({ listeners: [{ proto: "tcp", port: 445, scope: "loopback", process: null }] })); assert.equal(lo.state, "serving_internal");
  assert.equal(v(reading({ module_file: true, config: "m" })).state, "present_not_loaded");
  assert.equal(v(reading({ module_file: true, config: "m" })).flags.pre_auth.status, "not_indicated");
  assert.equal(v(reading({ config: "n" })).state, "not_present"); assert.equal(v(reading({ config: "n" })).shipped, false);
  const idle = v(reading({ module_loaded: true, modules: ["ksmbd"] })); assert.equal(idle.state, "loaded_not_serving"); assert.equal(idle.active, false);
  // Samba owns 445: a userspace server, not ksmbd
  const samba = v(reading({ listeners: [{ proto: "tcp", port: 445, scope: "all", process: "smbd" }], daemons: ["smbd"] }), [{ proto: "tcp", port: 445, scope: "all", process: "smbd", exposure: "internet" }]);
  assert.equal(samba.flags.pre_auth.status, "not_indicated"); assert.ok(samba.notes.some((n) => /Samba/.test(n)));
});

test("verdict: ZDI-CAN-33549 needs ksmbd active, an SMB Direct or RDMA indicator and a writable share", () => {
  const v = (probe: any) => kx.ksmbdVerdict({ probe, ports: p445("internet"), kernel: "6.8.0" });
  assert.equal(v(serving()).flags.smb_direct.status, "not_indicated", "no RDMA: a typical EC2 box");
  const rdma = v(serving({ rdma_devices: ["rxe0"], modules: ["ksmbd", "rdma_rxe"] }));
  assert.equal(rdma.flags.smb_direct.status, "flagged"); assert.deepEqual(rdma.writable_shares, ["data"]); assert.equal(rdma.smb_direct.indicated, true);
  assert.equal(v(serving({ smb_direct_cfg: true })).flags.smb_direct.status, "flagged", "the config alone is an indicator");
  assert.equal(v(serving({ rdma_devices: ["rxe0"], shares: [{ name: "ro", path: "/a", read_only: true, guest: false, hosts_allow: null }] })).flags.smb_direct.status, "low");
  assert.equal(v(serving({ rdma_devices: ["rxe0"], shares: [], conf_files: [] })).flags.smb_direct.status, "low", "no readable share definitions: unknown writability is not cleared");
  assert.equal(v(serving({ rdma_devices: ["rxe0"], config_smbdirect: "n" })).flags.smb_direct.status, "not_indicated", "a kernel built without SMB Direct");
  assert.equal(v(reading({ rdma_devices: ["rxe0"] })).flags.smb_direct.status, "not_indicated", "RDMA without ksmbd");
});

test("kernel note never judges a fix from a version: no advisory is not proof of a fix, a matched one is reported with its caveats", () => {
  const none = kx.ksmbdVerdict({ probe: serving(), ports: p445("internet"), kernel: "6.8.0-45-generic" });
  assert.match(none.kernel_note, /not evidence the kernel is fixed/); assert.match(none.kernel_note, /not judged from the kernel version/i);
  const adv = [{ vuln_id: "USN-9999-1", cves: ["CVE-2026-0001"], summary: "ksmbd: fix", package: "linux", packages: ["linux-image-6.8.0-45-generic"], version: "6.8.0-45.45", fixed_version: "6.8.0-60.63" }];
  assert.equal(kx.runningKernelPackage("6.8.0-45-generic", [{ name: "linux-image-6.8.0-40-generic", version: "6.8.0-40.40" }, { name: "linux-image-6.8.0-45-generic", version: "6.8.0-45.45" }]), "linux-image-6.8.0-45-generic");
  assert.equal(kx.runningKernelPackage("5.14.0-427.el9.x86_64", [{ name: "kernel", version: "5.14.0-427.el9", arch: "x86_64" }]), "kernel");
  const hit = kx.ksmbdVerdict({ probe: serving(), ports: p445("internet"), kernel: "6.8.0-45-generic", running_pkg: "linux-image-6.8.0-45-generic", advisories: adv });
  assert.match(hit.kernel_note, /USN-9999-1 \(fixed in 6\.8\.0-60\.63\)/); assert.match(hit.kernel_note, /predates the fix the distribution published/);
  assert.equal(hit.flags.pre_auth.status, "flagged", "an advisory match does not clear or raise the exposure flag");
  const other = kx.ksmbdVerdict({ probe: serving(), ports: p445("internet"), kernel: "6.8.0-60-generic", running_pkg: "linux-image-6.8.0-60-generic", advisories: adv });
  assert.match(other.kernel_note, /may be a different|reboot/);
  const absent = kx.ksmbdVerdict({ probe: reading({ config: "n" }), ports: [], kernel: "6.8.0", advisories: adv });
  assert.match(absent.kernel_note, /no ksmbd in this kernel/);
});

test("ksmbdOn and fleetKsmbd put the stored reading, the port rows and the kernel packages together, flagged boxes first", () => {
  const a = "i-0feedfacecafe0301", b = "i-0feedfacecafe0302";
  for (const [id, name] of [[a, "smb-1"], [b, "web-1"]]) db.prepare("insert or replace into inventory_ec2(instance_id, name, state, snapshot) values (?, ?, 'running', '{}')").run(id, name);
  sw.recordSoftware(a, "2026-10-01T00:00:00Z", { os: { id: "ubuntu", version: "24.04", name: "Ubuntu 24.04" }, kernel: "6.8.0-45-generic", package_manager: "deb", packages: [{ n: "linux-image-6.8.0-45-generic", v: "6.8.0-45.45", a: "amd64", s: "linux" }], ksmbd: serving() });
  sw.recordSoftware(b, "2026-10-01T00:00:00Z", { os: { id: "ubuntu", version: "24.04", name: "Ubuntu 24.04" }, kernel: "6.8.0-45-generic", package_manager: "deb", packages: [{ n: "bash", v: "5", a: "amd64" }], ksmbd: reading({ config: "n" }) });
  db.prepare("insert or replace into instance_ports(instance_id, proto, port, bind, scope, process, exposure, first_seen, last_seen) values (?, 'tcp', 445, '0.0.0.0', 'all', null, 'internet', 'x', 'x')").run(a);
  const one = kx.ksmbdOn(a);
  assert.equal(one.instance_name, "smb-1"); assert.equal(one.verdict.state, "serving_exposed"); assert.equal(one.verdict.flags.pre_auth.status, "flagged");
  const fleet = kx.fleetKsmbd({ only: "all" });
  assert.deepEqual(fleet.instances.filter((i) => [a, b].includes(i.instance_id)).map((i) => i.instance_id), [a, b], "flagged first");
  assert.ok(fleet.summary.pre_auth_flagged >= 1);
  assert.deepEqual(kx.fleetKsmbd().instances.map((i) => i.instance_id), [a], "the default list is the flagged boxes");
  for (const t of ["instance_os", "instance_packages", "package_changes", "instance_ports"]) db.prepare(`delete from ${t} where instance_id in (?, ?)`).run(a, b);
  db.prepare("delete from inventory_ec2 where instance_id in (?, ?)").run(a, b);
});

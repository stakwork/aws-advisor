import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "advisor-probes-test-"));
process.env.TYPESAFE_API_KEY = "";

const pr = await import("../probes.js");
const sw = await import("../software_inventory.js");
const { db } = await import("../db.js");

test("every probe kind has a document of its own that passes sh -n, embeds its hash and names its kind", () => {
  // an SSM document reads every {{word}} in the script as a parameter reference and refuses an undeclared one ("Parameter \"end\" is not declared"); a name starting with a dot (docker's {{.Image}}) is not a word
  for (const kind of pr.PROBE_KINDS) {
    const doc = pr.probeDocument(kind); const script = (doc.mainSteps[0]!.inputs.runCommand as string[]).join("\n");
    const refs = [...script.matchAll(/\{\{\s*([A-Za-z0-9_-]+)\s*\}\}/g)].map((m) => m[1]!);
    assert.deepEqual(refs.filter((r) => !(r in doc.parameters)), [], `${kind}: every {{word}} in the script is a declared parameter`);
  }
  for (const kind of pr.PROBE_KINDS) {
    const doc = pr.probeDocument(kind) as any;
    assert.equal(doc.schemaVersion, "2.2");
    assert.ok(doc.description.includes(` ${kind} `) && doc.description.includes(pr.probeScriptHash(kind)), `${kind}: the description carries the kind and the script hash`);
    assert.equal(doc.mainSteps[0].name, `probe_${kind}`);
    assert.equal(doc.mainSteps[0].inputs.timeoutSeconds, String(pr.PROBE_DEFS[kind].timeout_seconds));
    const script = doc.mainSteps[0].inputs.runCommand.join("\n");
    const r = spawnSync("sh", ["-n"], { input: script.replace("{{ signals }}", "x=y").replace("{{ install }}", "yes").replace("{{ upload }}", "").replace("{{ images }}", kind === "sbom" ? "all" : "").replace("{{ timeout }}", "180"), encoding: "utf8" });
    assert.equal(r.status, 0, `${kind}: ${r.stderr}`);
    assert.ok(!script.includes("__"), `${kind}: every placeholder is mapped to a document parameter`);
    assert.equal(pr.probeDocumentName(kind), `AwsAdvisorProbe-${kind}`);
    assert.ok(pr.probeDocumentInfo(kind).create_command.includes(`/api/probes/${kind}/document`));
  }
  assert.ok(Object.keys((pr.probeDocument("docker") as any).parameters).includes("signals"));
  assert.deepEqual((pr.probeDocument("host") as any).parameters, {});
  assert.deepEqual(Object.keys((pr.probeDocument("sbom") as any).parameters), ["install", "images", "host", "upload"]);
  assert.deepEqual(Object.keys((pr.probeDocument("images") as any).parameters), ["install", "images", "timeout", "upload"]);
  assert.deepEqual((pr.probeDocument("sbom") as any).parameters.images.allowedValues, ["all", "local"]);
  assert.equal((pr.probeDocument("images") as any).parameters.images.default, "", "a batch is always passed");
  assert.deepEqual(Object.keys((pr.probeDocument("software") as any).parameters), ["upload"]);
  for (const k of ["software", "sbom", "images"] as const) assert.ok((pr.probeDocument(k) as any).mainSteps[0].inputs.runCommand.some((l: string) => l.includes("upload='{{ upload }}'")), `${k}: the upload URL is a document parameter, quoted (a presigned URL is full of & and =)`);
  for (const k of ["sbom", "images"] as const) assert.ok((pr.probeDocument(k) as any).mainSteps[0].inputs.runCommand.some((l: string) => l.includes("install={{ install }}")), `${k}: the install switch is a document parameter`);
  assert.ok((pr.probeDocument("sbom") as any).mainSteps[0].inputs.runCommand.some((l: string) => l.includes("imgmode={{ images }}")), "the sbom images mode is a document parameter");
  assert.ok((pr.probeDocument("images") as any).mainSteps[0].inputs.runCommand.some((l: string) => l.includes("images='{{ images }}'") && l.includes("itmo={{ timeout }}")), "the batch and the per-image timeout are document parameters");
  assert.equal(pr.PROBE_DEFS.images.per_box, false); assert.ok(pr.PROBE_KINDS.filter((k) => pr.PROBE_DEFS[k].per_box).length === pr.PROBE_KINDS.length - 1, "every other kind goes to the boxes");
  // SSM compiles allowedPattern with RE2, which rejects a repeat count above 1000 (CreateDocument: "invalid repeat count")
  for (const kind of pr.PROBE_KINDS) for (const p of Object.values((pr.probeDocument(kind) as any).parameters) as any[]) {
    const counts = [...String(p.allowedPattern || "").matchAll(/\{(\d+)(?:,(\d+))?\}/g)].flatMap((m) => [m[1], m[2]].filter(Boolean).map(Number));
    assert.ok(counts.every((n) => n <= 1000), `${kind}: allowedPattern ${p.allowedPattern} has a repeat count RE2 refuses`);
  }
});

test("probeKindOf reads the kind from the JSON or the probe id; the old combined probe is 'all'", () => {
  assert.equal(pr.probeKindOf({ probe: "aws-advisor/1" }), "all");
  assert.equal(pr.probeKindOf({ probe: "aws-advisor/host/2", kind: "host" }), "host");
  assert.equal(pr.probeKindOf({ probe: "aws-advisor/software/2" }), "software");
  assert.equal(pr.probeKindOf({ probe: "aws-advisor/other/1" }), "all");
});

test("every default script passes the read-only validation it imposes on edits", () => {
  for (const kind of pr.PROBE_KINDS) { assert.doesNotThrow(() => pr.setProbeScriptOverride(kind, pr.defaultProbeScript(kind)), `${kind}`); assert.equal(pr.probeScriptOverride(kind), null); }
});

test("script overrides: a read-only edit is kept and changes the hash, a dangerous or malformed one is refused, reset goes back to the default", () => {
  const before = pr.probeScriptHash("apps");
  const edited = pr.defaultProbeScript("apps").replace("# the version string", "# the version string (edited)") + "\n# a harmless comment";
  pr.setProbeScriptOverride("apps", edited);
  assert.equal(pr.probeScriptOverride("apps"), edited);
  assert.notEqual(pr.probeScriptHash("apps"), before, "the hash follows the text");
  assert.ok(pr.probeDocumentInfo("apps").edited);
  assert.ok((pr.probeDocument("apps") as any).mainSteps[0].inputs.runCommand.join("\n").includes("# a harmless comment"), "the document embeds the edited text");
  assert.throws(() => pr.setProbeScriptOverride("apps", pr.defaultProbeScript("apps") + "\nrm -rf /tmp/x"), /read-only/);
  assert.throws(() => pr.setProbeScriptOverride("apps", "echo hi"), /"probe":"aws-advisor/);
  assert.throws(() => pr.setProbeScriptOverride("docker", pr.defaultProbeScript("docker").replace("__SIGNALS__", "none")), /__SIGNALS__/);
  assert.throws(() => pr.setProbeScriptOverride("host", "   "), /empty/);
  pr.setProbeScriptOverride("apps", pr.defaultProbeScript("apps"));
  assert.equal(pr.probeScriptOverride("apps"), null, "saving the default clears the override");
  pr.setProbeScriptOverride("apps", edited); pr.resetProbeScript("apps");
  assert.equal(pr.probeScriptHash("apps"), before);
});

test("binaryVersion: the number alone out of whatever a program prints for its version flag", () => {
  const cases: [string, string][] = [
    ["Python 3.11.2", "3.11.2"], ["v18.20.4", "18.20.4"], ["OpenSSH_9.2p1 Debian-2+deb12u10, OpenSSL 3.0.22 25 Aug 2026", "9.2p1"], ["OpenSSH_7.4p1, OpenSSL 1.0.2k-fips  26 Jan 2017", "7.4p1"],
    ["OpenSSL 1.0.2k-fips  26 Jan 2017", "1.0.2k-fips"], ["OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024)", "3.0.13"], ["Docker version 25.0.14, build 0bab007", "25.0.14"],
    ["containerd containerd.io 1.7.19 2bf793ef6dc9a18e00cb12efb64355c2c9d5eb41", "1.7.19"], ["containerd containerd v2.3.5 1294c24a7da8e5a793ed378161673abe94118892", "2.3.5"], ["containerd github.com/containerd/containerd/v2 2.2.7+unknown ", "2.2.7+unknown"],
    ["curl 7.88.1 (x86_64-pc-linux-gnu) libcurl/7.88.1 OpenSSL/3.0.22 zlib/1.2.13", "7.88.1"], ["git version 2.39.5", "2.39.5"], ["go version go1.23.8 linux/amd64", "1.23.8"], ["Server version: Apache/2.4.62 ()", "2.4.62"],
    ["nginx version: nginx/1.26.3", "1.26.3"], ["lnd version 0.18.0-beta commit=v0.18.0-beta", "0.18.0-beta"], ["Bitcoin Core version v23.0.0", "23.0.0"], ["Bitcoin Knots version v23.0.knots20220529", "23.0.knots20220529"],
    ["db version v7.0.14", "7.0.14"], ["ruby 2.3.1p112 (2016-04-26) [x86_64-linux-gnu]", "2.3.1p112"], ["openjdk version \"17.0.2\" 2022-01-18", "17.0.2"], ["java version \"1.8.0_292\"", "1.8.0_292"],
    ["PHP 8.3.6 (cli) (built: Apr 15 2024 19:21:47) (NTS)", "8.3.6"], ["This is perl 5, version 38, subversion 2 (v5.38.2) built for x86_64-linux-gnu-thread-multi", "5.38.2"], ["postgres (PostgreSQL) 16.3 (Debian 16.3-1.pgdg120+1)", "16.3"],
    ["Redis server v=7.0.15 sha=00000000:0 malloc=jemalloc-5.3.0 bits=64 build=abc", "7.0.15"], ["mysqld  Ver 8.0.37-0ubuntu0.24.04.1 for Linux on x86_64 ((Ubuntu))", "8.0.37-0ubuntu0.24.04.1"], ["v2.8.4 h1:q/Q4u4qX5Ox3ZrQ=", "2.8.4"],
    ["HAProxy version 2.8.5-1ubuntu3 2024/04/01", "2.8.5-1ubuntu3"], ["3.11.2", "3.11.2"],
    ["nginx: invalid option: \"-\"", "nginx: invalid option: \"-\""],
  ];
  for (const [line, want] of cases) assert.equal(sw.binaryVersion(line), want, line);
});

test("software inventory: a newer version replaces the row, what left is deleted, both are logged, and a package can be found across the fleet", () => {
  const iid = "i-0feedfacecafe0010";
  db.prepare("insert or replace into inventory_ec2(instance_id, name, state, snapshot) values (?, 'web-1', 'running', '{}')").run(iid);
  const first = sw.recordSoftware(iid, "2026-10-01T00:00:00Z", { os: { id: "ubuntu", version: "24.04", name: "Ubuntu 24.04 LTS" }, kernel: "6.8.0-45-generic", arch: "x86_64", package_manager: "deb",
    packages: [{ n: "openssh-server", v: "1:9.6p1-3ubuntu13.4", a: "amd64" }, { n: "nginx", v: "1.24.0-2ubuntu7", a: "amd64" }], binaries: [{ name: "sshd", version: "OpenSSH_9.6p1 Ubuntu-3ubuntu13.4", path: "/usr/sbin/sshd" }], images: [{ image: "nginx:1.25", id: "sha256:abc", digests: "nginx@sha256:def", created: "2026-01-01T00:00:00Z", platform: "linux/amd64" }] })!;
  assert.equal(first.packages, 2); assert.equal(first.added.length, 0, "the first probe is silent"); assert.equal(first.binaries, 1); assert.equal(first.images, 1);
  const second = sw.recordSoftware(iid, "2026-10-02T00:00:00Z", { package_manager: "deb", packages: [{ n: "openssh-server", v: "1:9.6p1-3ubuntu13.5", a: "amd64" }, { n: "curl", v: "8.5.0", a: "amd64" }], binaries: [], images: [] })!;
  assert.deepEqual(second.changed, [{ name: "openssh-server", from: "1:9.6p1-3ubuntu13.4", to: "1:9.6p1-3ubuntu13.5" }]);
  assert.deepEqual(second.added, ["curl"]); assert.deepEqual(second.removed, ["nginx"]);
  const on = sw.softwareOn(iid);
  assert.equal(on.os?.kernel, "6.8.0-45-generic"); assert.equal(on.os?.packages, 2);
  assert.equal(on.os?.kernel_upstream, null, "an Ubuntu ABI name without /proc/version_signature: no upstream version, rather than 6.8.0"); assert.equal(on.os?.kernel_package, null);
  assert.deepEqual(on.packages.map((p) => p.name), ["curl", "openssh-server"]);
  assert.equal((db.prepare("select count(*) as n from instance_packages where instance_id = ?").get(iid) as any).n, 2, "the removed package is deleted, not kept");
  assert.equal(on.packages.find((p) => p.name === "openssh-server")?.first_seen, "2026-10-02T00:00:00Z", "since: when this version appeared");
  assert.equal(on.binaries.length, 0, "a probe that reports no binaries deletes the old ones");
  assert.equal(on.images.length, 0);
  assert.deepEqual(on.changes.map((c) => [c.name, c.from_version, c.to_version]).sort(), [["nginx", "1.24.0-2ubuntu7", null], ["openssh-server", "1:9.6p1-3ubuntu13.4", "1:9.6p1-3ubuntu13.5"]]);
  // a box whose package manager changed (reinstalled): the old manager's packages go too
  sw.recordSoftware(iid, "2026-10-02T12:00:00Z", { package_manager: "rpm", packages: [{ n: "curl", v: "8.5.0-1.amzn2023", a: "x86_64" }] });
  assert.deepEqual(sw.softwareOn(iid).packages.map((p) => [p.ecosystem, p.name]), [["rpm", "curl"]]);
  sw.recordSoftware(iid, "2026-10-02T13:00:00Z", { package_manager: "deb", packages: [{ n: "openssh-server", v: "1:9.6p1-3ubuntu13.5", a: "amd64" }, { n: "curl", v: "8.5.0", a: "amd64" }] });
  const where = sw.wherePackage("openssh");
  assert.ok(where.some((w) => w.instance_id === iid && w.version === "1:9.6p1-3ubuntu13.5" && w.instance_name === "web-1"));
  const sum = sw.softwareSummary();
  assert.ok(sum.instances >= 1 && sum.changes_7d >= 0);
  assert.equal(sw.recordSoftware(iid, "x", {}), null, "nothing to record");
  // probe software/3: the hibernation setup is kept on the OS row; an older probe without it leaves it in place
  assert.deepEqual(sw.hibernationSetupOf(iid), { probe: null, agent_package: null, packages_known: true, collected_at: "2026-10-02T13:00:00Z" });
  sw.recordSoftware(iid, "2026-10-03T00:00:00Z", { package_manager: "deb", packages: [{ n: "ec2-hibinit-agent", v: "1.0.0-0ubuntu16.24.04.1", a: "all" }], hibernation: { kernel_disk: true, agent: "hibinit-agent" } });
  sw.recordSoftware(iid, "2026-10-04T00:00:00Z", { package_manager: "deb", packages: [{ n: "ec2-hibinit-agent", v: "1.0.0-0ubuntu16.24.04.1", a: "all" }] });
  assert.deepEqual(sw.hibernationSetupOf(iid), { probe: { kernel_disk: true, agent: "hibinit-agent" }, agent_package: "ec2-hibinit-agent", packages_known: true, collected_at: "2026-10-04T00:00:00Z" });
  for (const t of ["instance_os", "instance_packages", "instance_binaries", "instance_images", "package_changes"]) db.prepare(`delete from ${t} where instance_id = ?`).run(iid);
  db.prepare("delete from inventory_ec2 where instance_id = ?").run(iid);
});

test("the software script reads the source package from dpkg, rpm and apk (what the advisories name) and prints it as s when it differs", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "advisor-fake-pm-"));
  const fake: Record<string, string> = {
    // dpkg-query answers the package list, and (probe software/4) a Depends field when asked for one; dpkg -S names the package owning a program; node prints what it bundles
    "dpkg-query": "#!/bin/sh\ncase \"$*\" in *Depends*) printf 'libc6 (>= 2.34), nginx (>= 1), libnotinstalled (>= 1)';; *linux-image-unsigned-*) exit 1;; *linux-image-*) printf 'ii \\tlinux-image-%s\\t6.1.176-1\\tlinux' \"$(uname -r)\";; *) printf 'ii\\topenssh-server\\t1:9.6p1-3ubuntu13.4\\tamd64\\topenssh\\n'; printf 'ii\\tnginx\\t1.24.0-2ubuntu7\\tamd64\\tnginx\\n'; printf 'rc\\tgone\\t1.0\\tall\\tgone\\n';; esac\n",
    rpm: "#!/bin/sh\ncase \"$*\" in '-qf '*) printf 'kernel-core\\t(none):6.1.134-150.224.amzn2023\\tkernel-6.1.134-150.224.amzn2023.src.rpm\\n'; exit 0;; esac\nprintf 'openssh-server\\t(none):8.7p1-38.el9\\tx86_64\\topenssh-8.7p1-38.el9.src.rpm\\n'; printf 'kernel\\t(none):5.14.0-427.el9\\tx86_64\\tkernel-5.14.0-427.el9.src.rpm\\n'\n",
    apk: "#!/bin/sh\ncase \"$1\" in list) printf 'openssh-server-9.6_p1-r0 x86_64 {openssh} (BSD) [installed]\\nmusl-1.2.4_git20230717-r4 x86_64 {musl} (MIT) [installed]\\n';; *) exit 1;; esac\n",
  };
  const expected: Record<string, unknown[]> = {
    "dpkg-query": [{ n: "openssh-server", v: "1:9.6p1-3ubuntu13.4", a: "amd64", s: "openssh" }, { n: "nginx", v: "1.24.0-2ubuntu7", a: "amd64" }],
    rpm: [{ n: "openssh-server", v: "8.7p1-38.el9", a: "x86_64", s: "openssh" }, { n: "kernel", v: "5.14.0-427.el9", a: "x86_64" }],
    apk: [{ n: "openssh-server", v: "9.6_p1-r0", a: "", s: "openssh" }, { n: "musl", v: "1.2.4_git20230717-r4", a: "" }],
  };
  const extras: Record<string, Record<string, string>> = {
    "dpkg-query": {
      dpkg: "#!/bin/sh\nprintf 'nodejs: /usr/bin/node\\n'\n",
      node: "#!/bin/sh\ncase \"$1\" in --version) printf 'v22.12.0\\n';; -p) printf '{\"node\":\"22.12.0\",\"brotli\":\"1.1.0\",\"openssl\":\"3.0.15+quic\",\"modules\":\"127\"}';; esac\n",
    },
  };
  for (const [name, body] of Object.entries(fake)) {
    const bin = path.join(dir, name); fs.mkdirSync(bin); fs.writeFileSync(path.join(bin, name), body, { mode: 0o755 });
    for (const [extra, b] of Object.entries(extras[name] ?? {})) fs.writeFileSync(path.join(bin, extra), b, { mode: 0o755 });
    if (name === "dpkg-query") fs.symlinkSync(path.join(bin, "node"), path.join(bin, "nodejs")); // Debian's nodejs is a link to node
    const r = spawnSync("sh", [], { input: pr.defaultProbeScript("software"), encoding: "utf8", env: { ...process.env, PATH: `${bin}:${process.env.PATH}` } });
    const last = r.stdout.trim().split("\n").pop() || "{}";
    const j = JSON.parse(last);
    assert.equal(j.kind, "software"); assert.equal(j.probe, "aws-advisor/software/7");
    assert.deepEqual(j.packages, expected[name], name);
    assert.ok(j.os.cpe === null || /^cpe:/.test(j.os.cpe), `software/7: the OS CPE os-release declares, or null (${j.os.cpe})`);
    // probe software/6: the package that owns the running kernel (dpkg by name, rpm by the modules directory it owns) and the upstream version read from it;
    // a host that publishes /proc/version_signature (Ubuntu) names the upstream version itself, whatever the fakes say
    const signed = fs.existsSync("/proc/version_signature");
    if (name === "dpkg-query") { assert.deepEqual(j.kernel_package, { n: `linux-image-${os.release()}`, v: "6.1.176-1", s: "linux" }); if (!signed) assert.equal(j.kernel_upstream, "6.1.176", "Debian's package version starts with the upstream version"); }
    else if (name === "rpm") { assert.deepEqual(j.kernel_package, { n: "kernel-core", v: "6.1.134-150.224.amzn2023", s: "kernel" }); if (!signed) assert.equal(j.kernel_upstream, "6.1.134"); }
    else assert.equal(j.kernel_package, null, "apk: the fake owns no vmlinuz, so no package");
    assert.ok(Array.isArray(j.bundles) && Array.isArray(j.depends), `${name}: bundles and depends are arrays`);
    if (name === "dpkg-query") {
      // probe software/4: what the Node binary says it bundles, verbatim JSON; the Depends field of the package that owns each probed program
      assert.equal(j.bundles.length, 1); assert.equal(j.bundles[0].name, "node"); assert.ok(String(j.bundles[0].path).endsWith("/node"), "the install's path, so several Nodes on one box stay apart");
      assert.deepEqual(j.bundles[0].versions, { node: "22.12.0", brotli: "1.1.0", openssl: "3.0.15+quic", modules: "127" });
      assert.deepEqual(j.binaries.filter((b: any) => /^node(js)?$/.test(b.name)).map((b: any) => b.name), ["node"], "nodejs resolves to the node file already listed: one row, not two programs");
      assert.deepEqual(j.depends, [{ n: "nodejs", d: "libc6 (>= 2.34), nginx (>= 1), libnotinstalled (>= 1)" }]);
    } else assert.deepEqual(j.depends, [], `${name}: dependencies are read through dpkg only`);
  }
});

test("the sbom script: with syft it reads each running executable in place (host and container, through the root the daemon keeps mounted), reads each running image through that root, walks the filesystem only when asked, keeps each scan's status, trims to the budget and fits the SSM cap; without syft it says so and reads nothing", async () => {
  const { parseProbeOutput, SSM_OUTPUT_CAP } = await import("../ssm.js");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "advisor-fake-syft-"));
  const bin = path.join(dir, "bin"); fs.mkdirSync(bin); const bare = path.join(dir, "bare"); fs.mkdirSync(bare);
  const log = path.join(dir, "args.log");
  const w = (where: string, name: string, body: string) => fs.writeFileSync(path.join(where, name), body, { mode: 0o755 });
  // four running containers of three images, as the daemon lists them, and the root filesystems it keeps mounted: nginx's and app's exist, huge's does not
  const cid = (c: string) => c.repeat(64); const short = (c: string) => cid(c).slice(0, 12);
  const roots = path.join(dir, "roots");
  for (const r of ["nginx", "app"]) { fs.mkdirSync(path.join(roots, r, "usr", "local", "bin"), { recursive: true }); fs.writeFileSync(path.join(roots, r, "usr", "local", "bin", "node"), "#!/bin/sh\n", { mode: 0o755 }); }
  const ps = `${cid("1")}\tnginx:1.27\n${cid("2")}\tapp:latest\n${cid("3")}\thuge:1\n${cid("4")}\tnginx:1.27\n`;
  const inspect = `${cid("1")}|sha256:bbbb|${roots}/nginx\n${cid("2")}|sha256:aaaa|${roots}/app\n${cid("3")}|sha256:dddd|${roots}/huge\n${cid("4")}|sha256:bbbb|${roots}/nginx\n`;
  for (const where of [bin, bare]) {
    w(where, "docker", `#!/bin/sh\ncase "$1 $2 $3" in info*) exit 0;; "ps --no-trunc --format") printf '%s' '${ps}';; "ps --format "*) printf 'nginx:1.27\\napp:latest\\nhuge:1\\n';; "inspect --format "*) printf '%s' '${inspect}';; "image inspect --format") case "$5" in nginx:1.27) printf 'sha256:bbbb|nginx@sha256:cccc|linux/amd64\\n';; app:latest) printf 'sha256:aaaa||linux/arm64\\n';; huge:1) printf 'sha256:dddd|huge@sha256:eeee|linux/amd64\\n';; *) exit 1;; esac;; *) exit 1;; esac\n`);
    w(where, "dpkg-query", "#!/bin/sh\nexit 0\n");
    w(where, "dpkg", `#!/bin/sh\ncase "$*" in "-S "*/hostbin/sshd) printf 'openssh-server: %s\\n' "$2";; *) exit 1;; esac\n`); // what owns a host executable
    w(where, "timeout", "#!/bin/sh\nshift; exec \"$@\"\n"); // macOS has none; the script falls back to no bound either way
  }
  // a /proc of the test's own (AWS_ADVISOR_PROC): node twice in the app container (read once), node in a nginx container (another image: read again), a host
  // program (a file of the test's), a binary replaced while running, a process in the container whose root is not mounted, and a kernel thread with no executable
  const proc = path.join(dir, "proc"); fs.mkdirSync(proc); fs.mkdirSync(path.join(proc, "self"));
  const hostbin = path.join(dir, "hostbin"); fs.mkdirSync(hostbin); fs.writeFileSync(path.join(hostbin, "sshd"), "#!/bin/sh\n", { mode: 0o755 });
  const p = (pid: number, exe: string | null, c: string | null) => { fs.mkdirSync(path.join(proc, String(pid))); if (exe) fs.symlinkSync(exe, path.join(proc, String(pid), "exe")); fs.writeFileSync(path.join(proc, String(pid), "cgroup"), c ? `0::/system.slice/docker-${cid(c)}.scope\n` : "0::/system.slice/ssh.service\n"); };
  p(100, "/usr/local/bin/node", "2"); p(101, "/usr/local/bin/node", "2"); p(102, "/usr/local/bin/node", "4"); p(103, path.join(hostbin, "sshd"), null); p(104, "/usr/sbin/old (deleted)", null); p(105, "/usr/bin/python3", "3"); p(106, null, null);
  // Playwright's headless Chromium in the app container: syft has no classifier for it, the version text inside the file is read instead
  const shell = "/ms-playwright/chromium_headless_shell-1243/chrome-headless-shell-linux64/chrome-headless-shell";
  fs.mkdirSync(path.dirname(path.join(roots, "app", shell)), { recursive: true }); fs.writeFileSync(path.join(roots, "app", shell), "\x7fELF\0\0junk Google Chrome for Testing\0Chrome/153.0.8010.12\0more", { mode: 0o755 });
  p(107, shell, "2");
  // nothing identifies these: a crash handler in the app container, and a host program no package owns (the test's own file): hash, size and owner travel with the record
  const crashpad = "/ms-playwright/chromium-1243/chrome-linux64/chrome_crashpad_handler";
  fs.mkdirSync(path.dirname(path.join(roots, "app", crashpad)), { recursive: true }); fs.writeFileSync(path.join(roots, "app", crashpad), "\x7fELF\0crashpad\0", { mode: 0o755 }); p(108, crashpad, "2");
  fs.writeFileSync(path.join(hostbin, "mytool"), "#!/bin/sh\nexit 0\n", { mode: 0o755 }); p(109, path.join(hostbin, "mytool"), null);
  const sha256 = (f: string) => createHash("sha256").update(fs.readFileSync(f)).digest("hex");
  // the fake syft logs its arguments, checks the template it is given, and answers by what it is asked to read: an executable, a container root, the filesystem
  w(bin, "syft", `#!/bin/sh\necho "$* tmpdir=\${TMPDIR:-}" >> ${log}\nif [ -n "\${TMPDIR:-}" ]; then mkdir -p "$TMPDIR/stereoscope-fake" && : > "$TMPDIR/stereoscope-fake/layer.tar"; fi\nprev=""; for a in "$@"; do if [ "$prev" = "-t" ]; then [ -f "$a" ] || exit 3; cp "$a" ${dir}/tpl.copy; fi; prev=$a; done\ncase "$*" in version) printf 'Application: syft\\nVersion: 1.55.0\\n';; *file:*/node\\ *) printf 'pkg:generic/node@22.12.0\\tcpe:2.3:a:nodejs:node.js:22.12.0:*:*:*:*:*:*:*\\n';; *file:*) exit 0;; *dir:${roots}/nginx*) exit 124;; *dir:${roots}/app*) printf 'pkg:npm/%%40aws-sdk/core@3.1.0\\tcpe:2.3:a:aws-sdk:core:3.1.0:*:*:*:*:*:*:* cpe:2.3:a:aws:core:3.1.0:*:*:*:*:*:*:* \\npkg:npm/express@4.19.2\\tcpe:2.3:a:expressjs:express:4.19.2:*:*:*:*:*:*:* cpe:2.3:a:express:express:4.19.2:*:*:*:*:*:*:*\\npkg:npm/express@4.19.2\\tcpe:2.3:a:other:express:4.19.2:*:*:*:*:*:*:*\\npkg:deb/debian/libc6@2.36-9?arch=amd64&upstream=glibc&distro=debian-12\\t\\n';; *dir:/*) printf 'pkg:deb/ubuntu/curl@8.5.0?arch=amd64\\tcpe:2.3:a:haxx:curl:8.5.0:*:*:*:*:*:*:*\\n'; i=0; while [ $i -lt 6000 ]; do printf 'pkg:pypi/package-%s@1.0.%s\\tcpe:2.3:a:package-%s:package-%s:1.0.%s:*:*:*:*:*:*:*\\n' "$i" "$i" "$i" "$i" "$i"; i=$((i+1)); done;; *) exit 2;; esac\n`);
  const run = (PATH: string, script = pr.defaultProbeScript("sbom"), extra: Record<string, string> = {}) => { const r = spawnSync("sh", [], { input: script, encoding: "utf8", env: { ...process.env, PATH, AWS_ADVISOR_PROC: proc, ...extra } }); assert.equal(r.status, 0, r.stderr); return r.stdout.trim().split("\n").pop() || ""; };
  const scratch = path.join(dir, "aws-advisor-sbom"); // the name the guarded removals require
  const line = run(`${bin}:/usr/bin:/bin`, pr.defaultProbeScript("sbom"), { AWS_ADVISOR_SBOM_TMP: scratch });
  const firstRun = fs.readFileSync(log, "utf8"); // what syft was asked in this run alone
  assert.ok(!fs.existsSync(scratch), "the scratch directory (the template) is gone when the probe exits");
  // a directory of another name is never touched: the probe then leaves syft its default TMPDIR
  const other = path.join(dir, "elsewhere"); fs.mkdirSync(other); fs.writeFileSync(path.join(other, "keep"), "");
  run(`${bin}:/usr/bin:/bin`, pr.defaultProbeScript("sbom"), { AWS_ADVISOR_SBOM_TMP: other });
  assert.ok(fs.existsSync(path.join(other, "keep")), "a scratch path that does not end in /aws-advisor-sbom is refused, not emptied");
  assert.ok(line.length < SSM_OUTPUT_CAP, `the line fits SSM's cap (${line.length})`);
  const j = parseProbeOutput(line);
  assert.equal(j.kind, "sbom"); assert.equal(j.probe, "aws-advisor/sbom/6"); assert.equal(j.sbom?.install, null, "syft was there: nothing to install");
  assert.equal(j.sbom?.available, true); assert.equal(j.sbom?.tool, "syft 1.55.0"); assert.equal(j.sbom?.images_mode, "all", "the default: every running image, here");
  assert.equal(j.sbom?.host_mode, "processes", "the default: the running executables, not the filesystem");
  const by = Object.fromEntries(j.sbom!.sources.map((s) => [`${s.source} ${s.ref}`, s]));
  const logText = () => fs.readFileSync(log, "utf8");
  // the running executables (sbom 1.7), each read once in place: a container's through the root the daemon reports, with the container and its image on the record
  assert.deepEqual(by[`proc container:${short("2")}:/usr/local/bin/node`], { source: "proc", ref: `container:${short("2")}:/usr/local/bin/node`, image_id: "sha256:aaaa", digest: null, platform: null, container: short("2"), sha256: null, size: null, package: null, status: "ok", total: 1, note: null, purls: ["pkg:generic/node@22.12.0"], cpes: { "pkg:generic/node@22.12.0": ["cpe:2.3:a:nodejs:node.js:22.12.0:*:*:*:*:*:*:*"] } }, "a container process: the binary read through the container root, once for the two processes of that image");
  assert.equal(by[`proc container:${short("4")}:/usr/local/bin/node`]?.status, "ok", "the same path in another image is another executable, read again");
  const sshdRec = by[`proc host:${path.join(hostbin, "sshd")}`]!;
  assert.deepEqual([sshdRec.status, sshdRec.container, sshdRec.purls, sshdRec.sha256, sshdRec.size, sshdRec.package], ["ok", null, [], sha256(path.join(hostbin, "sshd")), fs.statSync(path.join(hostbin, "sshd")).size, "openssh-server"], "a host process at its own path, nothing recognised in it: its hash, size and the package that owns it");
  const toolRec = by[`proc host:${path.join(hostbin, "mytool")}`]!;
  assert.deepEqual([toolRec.sha256, toolRec.size, toolRec.package], [sha256(path.join(hostbin, "mytool")), fs.statSync(path.join(hostbin, "mytool")).size, null], "no package owns it: hash and size alone");
  const crashRec = by[`proc container:${short("2")}:${crashpad}`]!;
  assert.deepEqual([crashRec.status, crashRec.purls, crashRec.sha256, crashRec.size, crashRec.package, crashRec.container], ["ok", [], sha256(path.join(roots, "app", crashpad)), fs.statSync(path.join(roots, "app", crashpad)).size, null, short("2")], "a container executable nothing identifies: hashed through the container root, no package asked (the container is not entered)");
  assert.equal(by["proc host:/usr/sbin/old"]?.status, "skipped"); assert.match(by["proc host:/usr/sbin/old"]?.note ?? "", /gone from disk/, "a binary replaced while running cannot be read in place");
  assert.equal(by[`proc container:${short("3")}:/usr/bin/python3`]?.status, "skipped"); assert.match(by[`proc container:${short("3")}:/usr/bin/python3`]?.note ?? "", /not mounted where the daemon or containerd keep it/);
  assert.deepEqual([by[`proc container:${short("2")}:${shell}`]?.status, by[`proc container:${short("2")}:${shell}`]?.purls, by[`proc container:${short("2")}:${shell}`]?.cpes, by[`proc container:${short("2")}:${shell}`]?.note], ["ok", ["pkg:generic/chrome@153.0.8010.12"], { "pkg:generic/chrome@153.0.8010.12": ["cpe:2.3:a:google:chrome:153.0.8010.12:*:*:*:*:*:*:*"] }, "version read from the text inside the binary (syft has no classifier for it)"], "a headless Chromium: syft found nothing, the version text inside the file names it, as Chrome at that version");
  assert.equal(j.sbom!.sources.filter((s) => s.source === "proc").length, 8, "one record per distinct executable: the duplicate process and the kernel thread add none");
  assert.equal(firstRun.split("\n").filter((l) => l.includes(`file:${roots}/app/usr/local/bin/node`)).length, 1, "syft read the container's binary in place, once");
  assert.ok(!logText().includes("docker:"), "no image is saved through the daemon any more");
  assert.equal(fs.readFileSync(path.join(dir, "tpl.copy"), "utf8"), '{{range .artifacts}}{{.purl}}{{"\\t"}}{{range $i, $c := .cpes}}{{if ne $c.source "syft-generated"}}{{$c.cpe}} {{end}}{{end}}{{range $i, $c := .cpes}}{{if eq $c.source "syft-generated"}}{{$c.cpe}} {{end}}{{end}}{{"\\n"}}{{end}}', "the Go template syft renders, its closing tokens assembled at run time (an SSM document would read a literal {{end}} as a parameter)");
  // the images, each read through the root of one container that runs it, with that container on the record
  assert.deepEqual(by["image app:latest"], { source: "image", ref: "app:latest", image_id: "sha256:aaaa", digest: null, platform: "linux/arm64", container: short("2"), sha256: null, size: null, package: null, status: "ok", total: 3, note: null, purls: ["pkg:npm/%40aws-sdk/core@3.1.0", "pkg:npm/express@4.19.2", "pkg:deb/debian/libc6@2.36-9?arch=amd64&upstream=glibc&distro=debian-12"], cpes: { "pkg:npm/%40aws-sdk/core@3.1.0": ["cpe:2.3:a:aws-sdk:core:3.1.0:*:*:*:*:*:*:*", "cpe:2.3:a:aws:core:3.1.0:*:*:*:*:*:*:*"], "pkg:npm/express@4.19.2": ["cpe:2.3:a:expressjs:express:4.19.2:*:*:*:*:*:*:*", "cpe:2.3:a:express:express:4.19.2:*:*:*:*:*:*:*"] } }, "duplicates dropped (the first line's CPEs kept), order kept; a purl without CPEs is out of the map; a local build has an id and no digest; the platform travels");
  assert.deepEqual(by["image nginx:1.27"], { source: "image", ref: "nginx:1.27", image_id: "sha256:bbbb", digest: "sha256:cccc", platform: "linux/amd64", container: short("1"), sha256: null, size: null, package: null, status: "timeout", total: 0, note: null, purls: [], cpes: {} }, "a pulled image carries its registry digest; read through the first container that runs it");
  assert.equal(by["image huge:1"]!.status, "skipped"); assert.equal(by["image huge:1"]!.platform, "linux/amd64"); assert.match(by["image huge:1"]!.note ?? "", /not mounted where the daemon or containerd keep it/, "an image whose container root is not mounted is skipped: nothing is pulled or saved on a box");
  assert.ok(logText().includes(`dir:${roots}/app --base-path ${roots}/app`), "the container root is read in place, links resolved inside it");
  assert.equal(by["dir /"], undefined, "the filesystem is not walked in processes mode");
  // host=both: the filesystem as before, next to the executables; filesystem: the filesystem alone; none: only the images
  const both = parseProbeOutput(run(`${bin}:/usr/bin:/bin`, pr.defaultProbeScript("sbom").replace("__HOST_MODE__", "both"), { AWS_ADVISOR_SBOM_TMP: scratch }));
  const bb = Object.fromEntries(both.sbom!.sources.map((s) => [`${s.source} ${s.ref}`, s]));
  assert.equal(both.sbom?.host_mode, "both"); assert.ok(bb[`proc container:${short("2")}:/usr/local/bin/node`], "the executables");
  assert.equal(bb["dir /"]!.status, "ok"); assert.equal(bb["dir /"]!.total, 6000, "the OS package is left to the software probe; the true count is reported");
  assert.deepEqual([bb["dir /"]!.image_id, bb["dir /"]!.platform, bb["dir /"]!.container, both.upload], [null, null, null, undefined], "no upload URL: no receipt");
  assert.ok(bb["dir /"]!.purls.length < 6000 && bb["dir /"]!.purls.length >= 100 && bb["dir /"]!.purls.every((p) => p.startsWith("pkg:pypi/")), `trimmed to the budget (${bb["dir /"]!.purls.length}, cap ${both.sbom!.cap})`);
  assert.ok(Object.values(bb["dir /"]!.cpes).every((c) => c.length === 1 && c[0]!.startsWith("cpe:2.3:a:package-")) && Object.keys(bb["dir /"]!.cpes).length === bb["dir /"]!.purls.length, "every listed purl keeps its CPEs, trimmed with the list");
  const args = logText().split("\n").find((l) => l.includes("dir:/ "))!;
  assert.ok(args.includes(`tmpdir=${scratch}`), "syft is given the probe's scratch directory as TMPDIR");
  for (const ex of ["./proc/**", "./sys/**", "./var/lib/docker/**", "./home/*/.cache/**"]) assert.ok(args.includes(`--exclude ${ex}`), `the filesystem scan excludes ${ex} (globbing off)`);
  assert.ok(args.includes("-o template") && args.includes(`-t ${scratch}/purlcpe.tmpl`) && args.includes("-q"), `the purl and CPE template from the scratch directory, quiet: ${args}`);
  assert.ok(args.includes(`--exclude .${path.join(bin, "syft")}`), "syft does not catalog its own Go modules");
  const fsOnly = parseProbeOutput(run(`${bin}:/usr/bin:/bin`, pr.defaultProbeScript("sbom").replace("__HOST_MODE__", "filesystem"), { AWS_ADVISOR_SBOM_TMP: scratch }));
  assert.deepEqual(fsOnly.sbom!.sources.map((s) => s.source).sort(), ["dir", "image", "image", "image"], "filesystem alone: no executables");
  const none = parseProbeOutput(run(`${bin}:/usr/bin:/bin`, pr.defaultProbeScript("sbom").replace("__HOST_MODE__", "none"), { AWS_ADVISOR_SBOM_TMP: scratch }));
  assert.deepEqual(none.sbom!.sources.map((s) => s.source), ["image", "image", "image"], "none: the images alone");
  // local mode (sbom 1.6): the images with a registry digest are the scanner's and are not listed; the local build and the executables stay
  const nginxReads = () => logText().split("\n").filter((l) => l.includes(`dir:${roots}/nginx`)).length;
  const beforeLocal = nginxReads();
  const local = parseProbeOutput(run(`${bin}:/usr/bin:/bin`, pr.defaultProbeScript("sbom").replace("__IMAGES_MODE__", "local"), { AWS_ADVISOR_SBOM_TMP: scratch }));
  assert.equal(local.sbom?.images_mode, "local");
  assert.deepEqual(local.sbom!.sources.filter((s) => s.source === "image").map((s) => s.ref), ["app:latest"], "nginx (digest) and huge (digest) are left to the scanner, not even reported as skipped");
  assert.equal(local.sbom!.sources.filter((s) => s.source === "proc").length, 8, "the executables are read whatever the images mode");
  assert.equal(nginxReads(), beforeLocal, "the digested image was not read in local mode");
  // no syft and the install switch off: reported, left alone
  const noSyft = parseProbeOutput(run(`${bare}:/usr/bin:/bin`, pr.defaultProbeScript("sbom").replace("__INSTALL__", "no")));
  assert.deepEqual(noSyft.sbom, { available: false, tool: null, install: "not installed; the install parameter is no", images_mode: "all", host_mode: "processes", cap: 3000, sources: [] });
  // the switch on (the default): the installer is fetched with curl and run; the fake one copies the fake syft into the target directory, then the reads run with it
  const target = path.join(dir, "installed");
  w(bare, "curl", `#!/bin/sh\ncase "$*" in *get.anchore.io/syft*) printf 'mkdir -p "$2"; cp "%s" "$2/syft"\n' "${path.join(bin, "syft")}";; *) exit 22;; esac\n`);
  const got = parseProbeOutput(run(`${bare}:/usr/bin:/bin`, pr.probeScript("sbom"), { AWS_ADVISOR_SYFT_DIR: target }));
  assert.equal(got.sbom?.install, "installed v1.55.0"); assert.equal(got.sbom?.available, true); assert.equal(got.sbom?.sources.length, 11, "read right after installing: eight executables, three images");
  assert.ok(fs.existsSync(path.join(target, "syft")));
  // the switch on but no egress: the failure and what it needs are reported, nothing read
  w(bare, "curl", "#!/bin/sh\nexit 6\n");
  const failed = parseProbeOutput(run(`${bare}:/usr/bin:/bin`, pr.probeScript("sbom"), { AWS_ADVISOR_SYFT_DIR: path.join(dir, "nowhere") }));
  assert.equal(failed.sbom?.available, false); assert.match(failed.sbom?.install ?? "", /^install failed: curl, egress/);
  // an upload URL (probe 2.1): the whole, untrimmed result is posted gzip-compressed with curl; the inline line carries the receipt and stays trimmed
  const capture = path.join(dir, "uploaded.json.gz");
  w(bin, "curl", `#!/bin/sh\ncase "$*" in *" -X PUT "*) for a in "$@"; do case "$a" in @*) cp "\${a#@}" "$UPLOAD_CAPTURE";; esac; done; exit 0;; *) exit 22;; esac\n`);
  const withUrl = parseProbeOutput(run(`${bin}:/usr/bin:/bin`, pr.defaultProbeScript("sbom").replace("__UPLOAD__", "https://bucket.s3.amazonaws.com/k?X-Amz-Signature=1").replace("__HOST_MODE__", "both"), { UPLOAD_CAPTURE: capture }));
  assert.match(withUrl.upload ?? "", /^uploaded \d+ [0-9a-f]{64}$/, "the receipt: bytes and sha256");
  assert.ok(withUrl.sbom!.sources.find((s) => s.ref === "/")!.purls.length < 6000, "the inline list is still trimmed");
  const { gunzipSync } = await import("node:zlib");
  const blob = fs.readFileSync(capture);
  assert.equal(`uploaded ${blob.length} ${createHash("sha256").update(blob).digest("hex")}`, withUrl.upload, "the receipt describes the object");
  const whole = parseProbeOutput(gunzipSync(blob).toString("utf8"));
  assert.equal(whole.sbom!.cap, 0); assert.equal(whole.sbom!.sources.find((s) => s.ref === "/")!.purls.length, 6000, "the object holds everything");
  assert.equal(whole.sbom!.sources.find((s) => s.ref === "nginx:1.27")!.digest, "sha256:cccc");
  assert.equal(whole.upload, undefined, "the object was written before the receipt existed");
  // a syft too old for the template model refuses it: each read is retried for the purls alone and the lists come without CPEs
  const oldSyft = path.join(dir, "oldsyft"); fs.mkdirSync(oldSyft);
  for (const f of ["docker", "dpkg-query", "timeout"]) fs.copyFileSync(path.join(bin, f), path.join(oldSyft, f));
  w(oldSyft, "syft", `#!/bin/sh\ncase "$*" in version) printf 'Application: syft\\nVersion: 0.98.0\\n';; *"-o template"*) echo "unable to render template: can't evaluate field artifacts" >&2; exit 1;; *file:*/node\\ *) printf 'pkg:generic/node@22.12.0\\n';; *file:*) exit 0;; *dir:${roots}/app*) printf 'pkg:npm/express@4.19.2\\n';; *dir:/*) printf 'pkg:pypi/requests@2.32.3\\n';; *) exit 124;; esac\n`);
  const legacy = parseProbeOutput(run(`${oldSyft}:/usr/bin:/bin`, pr.defaultProbeScript("sbom").replace("__HOST_MODE__", "both"), { AWS_ADVISOR_SBOM_TMP: scratch }));
  const lb = Object.fromEntries(legacy.sbom!.sources.map((s) => [`${s.source} ${s.ref}`, s]));
  assert.deepEqual([lb["image app:latest"]!.status, lb["image app:latest"]!.purls, lb["image app:latest"]!.cpes, lb["dir /"]!.status, lb["dir /"]!.purls, lb[`proc container:${short("2")}:/usr/local/bin/node`]!.purls], ["ok", ["pkg:npm/express@4.19.2"], {}, "ok", ["pkg:pypi/requests@2.32.3"], ["pkg:generic/node@22.12.0"]], "the purls-only fallback");
});

test("the software script with an upload URL: a result that fits goes inline with the receipt; one the cap would cut becomes a stub, the whole in S3", async () => {
  const { parseProbeOutput } = await import("../ssm.js");
  const { gunzipSync } = await import("node:zlib");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "advisor-fake-upload-")); const bin = path.join(dir, "bin"); fs.mkdirSync(bin);
  const capture = path.join(dir, "uploaded.json.gz");
  const w = (name: string, body: string) => fs.writeFileSync(path.join(bin, name), body, { mode: 0o755 });
  w("curl", `#!/bin/sh\ncase "$*" in *" -X PUT "*) for a in "$@"; do case "$a" in @*) cp "\${a#@}" "$UPLOAD_CAPTURE";; esac; done; exit 0;; *) exit 22;; esac\n`);
  // dpkg-query lists N packages: 3 fits inline; 2000 does not
  const dpkg = (n: number) => `#!/bin/sh\ncase "$*" in *Depends*) exit 1;; *) i=0; while [ $i -lt ${n} ]; do printf 'ii\\tpackage-%s\\t1.0.%s-1ubuntu1\\tamd64\\tsource-%s\\n' $i $i $i; i=$((i+1)); done;; esac\n`;
  const run = () => { const r = spawnSync("sh", [], { input: pr.defaultProbeScript("software").replace("__UPLOAD__", "https://bucket.s3.amazonaws.com/k?sig=1"), encoding: "utf8", env: { ...process.env, PATH: `${bin}:/usr/bin:/bin`, UPLOAD_CAPTURE: capture } }); assert.equal(r.status, 0, r.stderr); return parseProbeOutput(r.stdout.trim().split("\n").pop() || ""); };
  w("dpkg-query", dpkg(3));
  const small = run();
  assert.equal(small.kind, "software"); assert.equal(small.packages?.length, 3, "inline, whole"); assert.match(small.upload ?? "", /^uploaded \d+ /); assert.equal(small.inline, undefined);
  w("dpkg-query", dpkg(2000));
  const big = run();
  assert.equal(big.inline, false, "a stub: the inline object would have been cut"); assert.equal(big.packages, undefined); assert.equal(big.kind, "software"); assert.equal(big.probe, "aws-advisor/software/7");
  const whole = parseProbeOutput(gunzipSync(fs.readFileSync(capture)).toString("utf8"));
  assert.equal(whole.packages?.length, 2000, "the object holds every package"); assert.equal(whole.os?.id ?? null, whole.os?.id ?? null);
});

test("parsePurl takes a package URL apart; recordSbom keeps each scan's status, replaces a good scan's list, keeps the last good one through a timeout, drops a scan no longer reported and forgets everything when syft is gone", () => {
  assert.deepEqual(sw.parsePurl("pkg:npm/%40aws-sdk/core@3.1.0"), { type: "npm", namespace: "@aws-sdk", name: "core", version: "3.1.0", qualifiers: {}, full_name: "@aws-sdk/core" });
  const deb = sw.parsePurl("pkg:deb/debian/libc6@2.36-9?arch=amd64&upstream=glibc&distro=debian-12")!;
  assert.equal(deb.full_name, "libc6"); assert.equal(deb.namespace, "debian"); assert.deepEqual(deb.qualifiers, { arch: "amd64", upstream: "glibc", distro: "debian-12" });
  assert.equal(sw.parsePurl("pkg:maven/org.apache/commons@1.0")!.full_name, "org.apache:commons");
  assert.equal(sw.parsePurl("pkg:golang/github.com/foo/bar@v1.2.3")!.full_name, "github.com/foo/bar");
  assert.equal(sw.parsePurl("pkg:generic/node")!.version, null);
  assert.equal(sw.parsePurl("nonsense"), null);
  const iid = "i-0sbom00000000001";
  const r1 = sw.recordSbom(iid, "2026-10-29T10:00:00Z", { available: true, tool: "syft 1.55.0", cap: 3000, images_mode: "all", sources: [
    { source: "image", ref: "app:latest", status: "ok", total: 2, purls: ["pkg:npm/express@4.19.2", "pkg:deb/debian/libc6@2.36-9?upstream=glibc&distro=debian-12"], cpes: { "pkg:npm/express@4.19.2": ["cpe:2.3:a:expressjs:express:4.19.2:*:*:*:*:*:*:*", "cpe:2.3:a:express:express:4.19.2:*:*:*:*:*:*:*"], "pkg:deb/debian/libc6@2.36-9?upstream=glibc&distro=debian-12": ["not a cpe"] } },
    { source: "dir", ref: "/", status: "ok", total: 1, purls: ["pkg:pypi/requests@2.32.3"], cpes: { "pkg:pypi/requests@2.32.3": ["cpe:2.3:a:python:requests:2.32.3:*:*:*:*:*:*:*"] } } ] })!;
  assert.equal(r1.packages, 3); assert.equal(r1.sources, 2); assert.equal(r1.added, 0, "a first scan adds nothing");
  assert.deepEqual(r1.images.ok, [`ref:${iid}|app:latest`], "an image with neither digest nor id is keyed by the box and the reference");
  let on = sw.softwareOn(iid).sbom;
  assert.equal(on.scan?.available, true); assert.equal(on.scan?.packages, 3); assert.equal(on.scan?.tool, "syft 1.55.0"); assert.equal(on.scan?.images_mode, "all");
  assert.deepEqual(on.packages.map((p) => [p.ref, p.type, p.name, p.version]), [["app:latest", "deb", "libc6", "2.36-9"], ["app:latest", "npm", "express", "4.19.2"], ["/", "pypi", "requests", "2.32.3"]]);
  assert.deepEqual(on.packages.map((p) => p.cpes), [null, JSON.stringify(["cpe:2.3:a:expressjs:express:4.19.2:*:*:*:*:*:*:*", "cpe:2.3:a:express:express:4.19.2:*:*:*:*:*:*:*"]), JSON.stringify(["cpe:2.3:a:python:requests:2.32.3:*:*:*:*:*:*:*"])], "the CPEs syft assigned stay with the row (sbom 1.7); a malformed one is dropped");
  assert.deepEqual(on.sources.map((s) => [s.source, s.ref, s.status, s.scanned_on, s.via]), [["image", "app:latest", "ok", iid, "box"], ["dir", "/", "ok", iid, "box"]], "the image's scan is the box's own, through the box's image row");
  // the image timed out this time (its rows stay), the filesystem moved on: one version replaced, one package new
  const r2 = sw.recordSbom(iid, "2026-10-30T10:00:00Z", { available: true, tool: "syft 1.55.0", cap: 3000, sources: [
    { source: "image", ref: "app:latest", status: "timeout", total: 0, purls: [] },
    { source: "dir", ref: "/", status: "ok", total: 2, purls: ["pkg:pypi/requests@2.32.4", "pkg:pypi/urllib3@2.2.0"] } ] })!;
  assert.deepEqual(r2.failed, [{ ref: "app:latest", status: "timeout" }]); assert.equal(r2.added, 2); assert.equal(r2.removed, 1);
  on = sw.softwareOn(iid).sbom;
  assert.equal(on.sources.find((s) => s.ref === "app:latest")?.status, "timeout");
  assert.equal(on.packages.filter((p) => p.ref === "app:latest").length, 2, "a timed-out scan keeps the last good list");
  assert.deepEqual(on.packages.filter((p) => p.ref === "/").map((p) => p.version), ["2.32.4", "2.2.0"]);
  assert.deepEqual(sw.softwareOn(iid, { q: "url" }).sbom.packages.map((p) => p.name), ["urllib3"], "the search filters the sbom too");
  // the container stopped: the image's scan is no longer reported by this box, but what the image contains stays a fact about the image (the box's image row keeps it in view until the software probe drops the image; pruneImageSboms retires it a month after the last box)
  const r3 = sw.recordSbom(iid, "2026-10-31T10:00:00Z", { available: true, sources: [{ source: "dir", ref: "/", status: "ok", total: 2, purls: ["pkg:pypi/requests@2.32.4", "pkg:pypi/urllib3@2.2.0"] }] })!;
  assert.equal(r3.removed, 0); assert.equal(sw.softwareOn(iid).sbom.sources.length, 2);
  assert.ok(sw.wherePackage("urllib3").some((w) => w.kind === "sbom" && w.instance_id === iid && w.ref === "/" && w.ecosystem === "pypi"));
  assert.ok(sw.wherePackage("express").some((w) => w.kind === "sbom" && w.instance_id === iid && w.ref === "app:latest" && w.ecosystem === "npm"), "an image's package is found on every box running the image, with the box's name for it");
  assert.ok(sw.softwareSummary().sbom.boxes >= 1); assert.ok(sw.softwareSummary().sbom.images.distinct >= 1);
  // syft uninstalled: what it read of the filesystem is no longer known to be there; the image's contents remain the image's
  sw.recordSbom(iid, "2026-11-01T10:00:00Z", { available: false, sources: [] });
  on = sw.softwareOn(iid).sbom; assert.equal(on.scan?.available, false); assert.deepEqual(on.packages.map((p) => p.ref), ["app:latest", "app:latest"]); assert.deepEqual(on.sources.map((s) => s.ref), ["app:latest"]);
  assert.ok(sw.softwareSummary().sbom.without_syft >= 1);
  // sbom 1.7: a running executable (source proc) is the box's own reading like the filesystem, kept with its container and the container's image, gone when the process is
  const pid = "i-0sbom00000000002";
  const node = { source: "proc" as const, ref: "container:abcdefabcdef:/usr/local/bin/node", image_id: "sha256:aaaa", container: "abcdefabcdef", status: "ok", total: 1, purls: ["pkg:generic/node@22.12.0"], cpes: { "pkg:generic/node@22.12.0": ["cpe:2.3:a:nodejs:node.js:22.12.0:*:*:*:*:*:*:*"] } };
  const sshd = { source: "proc" as const, ref: "host:/usr/sbin/sshd", status: "ok", total: 0, purls: [], sha256: "ab".repeat(32), size: 1234567, package: "openssh-server" };
  const p1 = sw.recordSbom(pid, "2026-11-03T10:00:00Z", { available: true, tool: "syft 1.55.0", host_mode: "processes", sources: [node, sshd, { source: "proc", ref: "container:fedcba987654:/usr/bin/python3", container: "fedcba987654", status: "skipped", total: 0, note: "the container root filesystem is not mounted where the daemon or containerd keep it", purls: [] }] })!;
  assert.equal(p1.sources, 3); assert.equal(p1.packages, 1); assert.deepEqual(p1.failed, [{ ref: "container:fedcba987654:/usr/bin/python3", status: "skipped" }]);
  let pon = sw.softwareOn(pid).sbom;
  assert.equal(pon.scan?.host_mode, "processes");
  assert.deepEqual(pon.sources.map((s) => [s.source, s.ref, s.container, s.image_id, s.status]), [["proc", "container:abcdefabcdef:/usr/local/bin/node", "abcdefabcdef", "sha256:aaaa", "ok"], ["proc", "container:fedcba987654:/usr/bin/python3", "fedcba987654", null, "skipped"], ["proc", "host:/usr/sbin/sshd", null, null, "ok"]], "by ref: the containers, then the host");
  assert.deepEqual(pon.sources.map((s) => [s.sha256, s.size, s.package]), [[null, null, null], [null, null, null], ["ab".repeat(32), 1234567, "openssh-server"]], "an executable nothing identified keeps its hash, size and owning package");
  assert.deepEqual(pon.packages.map((p) => [p.source, p.ref, p.name, p.version, p.cpes]), [["proc", "container:abcdefabcdef:/usr/local/bin/node", "node", "22.12.0", JSON.stringify(["cpe:2.3:a:nodejs:node.js:22.12.0:*:*:*:*:*:*:*"])]]);
  assert.ok(sw.wherePackage("node").some((w) => w.kind === "sbom" && w.instance_id === pid && w.ref === "container:abcdefabcdef:/usr/local/bin/node"), "found across the fleet like any sbom package");
  const p2 = sw.recordSbom(pid, "2026-11-04T10:00:00Z", { available: true, host_mode: "processes", sources: [sshd] })!;
  assert.equal(p2.removed, 1, "the node process ended: its reading goes");
  pon = sw.softwareOn(pid).sbom; assert.deepEqual(pon.sources.map((s) => s.ref), ["host:/usr/sbin/sshd"]); assert.deepEqual(pon.packages, []);
});

test("the images script: each entry of the batch is pulled from its registry by digest with its platform, ECR hosts get a token through the AWS CLI into a syft config file, and each image's status is reported", async () => {
  const { parseProbeOutput } = await import("../ssm.js");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "advisor-fake-scanner-"));
  const bin = path.join(dir, "bin"); fs.mkdirSync(bin); const noaws = path.join(dir, "noaws"); fs.mkdirSync(noaws);
  const log = path.join(dir, "args.log"); const cfgcopy = path.join(dir, "cfg.yaml");
  const w = (where: string, name: string, body: string) => fs.writeFileSync(path.join(where, name), body, { mode: 0o755 });
  for (const where of [bin, noaws]) {
    w(where, "timeout", "#!/bin/sh\nshift; exec \"$@\"\n");
    // logs its arguments and keeps a copy of the config it was given (the scratch directory is emptied after every scan); one image times out, one is read
    w(where, "syft", `#!/bin/sh\necho "$*" >> ${log}\nprev=""; for a in "$@"; do if [ "$prev" = "-c" ]; then cp "$a" ${cfgcopy}; fi; prev=$a; done\ncase "$*" in version) printf 'Application: syft\\nVersion: 1.55.0\\n';; *registry:nginx@sha256:*) exit 124;; *registry:*) printf 'pkg:npm/express@4.19.2\\tcpe:2.3:a:expressjs:express:4.19.2:*:*:*:*:*:*:*\\npkg:deb/debian/libc6@2.36-9?arch=arm64&upstream=glibc&distro=debian-12\\tcpe:2.3:a:gnu:glibc:2.36-9:*:*:*:*:*:*:* cpe:2.3:a:libc6:libc6:2.36-9:*:*:*:*:*:*:*\\n';; *) exit 2;; esac\n`);
  }
  w(bin, "aws", "#!/bin/sh\ncase \"$*\" in 'ecr get-login-password --region eu-west-1') printf 'TOKEN-EU\\n';; 'ecr-public get-login-password --region us-east-1') printf 'TOKEN-PUBLIC\\n';; *) exit 1;; esac\n");
  const sha = (c: string) => `sha256:${c.repeat(64)}`;
  const batch = [`123456789012.dkr.ecr.eu-west-1.amazonaws.com/api@${sha("a")}|linux/arm64`, `nginx@${sha("b")}|linux/amd64`, `public.ecr.aws/docker/library/redis@${sha("c")}`, `123456789012.dkr.ecr.eu-west-1.amazonaws.com/web@${sha("d")}|linux/arm64`].join(" ");
  const script = (images: string) => pr.defaultProbeScript("images").replace("__IMAGES__", images).replace("__IMAGE_TIMEOUT__", "90").replace("__INSTALL__", "no").replace("__UPLOAD__", "");
  const run = (PATH: string, s: string, extra: Record<string, string> = {}) => { const r = spawnSync("sh", [], { input: s, encoding: "utf8", env: { ...process.env, PATH, AWS_ADVISOR_SBOM_TMP: path.join(dir, "aws-advisor-sbom"), ...extra } }); assert.equal(r.status, 0, r.stderr); return parseProbeOutput(r.stdout.trim().split("\n").pop() || ""); };
  const j = run(`${bin}:/usr/bin:/bin`, script(batch));
  assert.equal(j.kind, "images"); assert.equal(j.probe, "aws-advisor/images/3"); assert.equal(j.sbom?.available, true); assert.equal(j.sbom?.images_mode, null);
  const by = Object.fromEntries(j.sbom!.sources.map((s) => [s.ref, s]));
  assert.deepEqual(Object.keys(by), batch.split(" ").map((e) => e.split("|")[0]), "one record per entry, in order");
  assert.deepEqual(by[`123456789012.dkr.ecr.eu-west-1.amazonaws.com/api@${sha("a")}`], { source: "image", ref: `123456789012.dkr.ecr.eu-west-1.amazonaws.com/api@${sha("a")}`, image_id: null, digest: sha("a"), platform: "linux/arm64", container: null, sha256: null, size: null, package: null, status: "ok", total: 2, note: null, purls: ["pkg:npm/express@4.19.2", "pkg:deb/debian/libc6@2.36-9?arch=arm64&upstream=glibc&distro=debian-12"], cpes: { "pkg:npm/express@4.19.2": ["cpe:2.3:a:expressjs:express:4.19.2:*:*:*:*:*:*:*"], "pkg:deb/debian/libc6@2.36-9?arch=arm64&upstream=glibc&distro=debian-12": ["cpe:2.3:a:gnu:glibc:2.36-9:*:*:*:*:*:*:*", "cpe:2.3:a:libc6:libc6:2.36-9:*:*:*:*:*:*:*"] } }, "the digest from the entry, no docker id, the platform, distro purls kept (the image's OS packages are its own) with the CPEs syft assigned");
  assert.equal(by[`nginx@${sha("b")}`]!.status, "timeout"); assert.equal(by[`nginx@${sha("b")}`]!.platform, "linux/amd64");
  assert.equal(by[`public.ecr.aws/docker/library/redis@${sha("c")}`]!.status, "ok"); assert.equal(by[`public.ecr.aws/docker/library/redis@${sha("c")}`]!.platform, null, "no platform in the entry: syft picks the host's");
  const args = fs.readFileSync(log, "utf8").split("\n");
  const api = args.find((l) => l.includes(`registry:123456789012.dkr.ecr.eu-west-1.amazonaws.com/api@`))!;
  assert.ok(api.includes("--platform linux/arm64") && api.includes("-o template") && api.includes("/aws-advisor-sbom/purlcpe.tmpl") && api.includes("-c ") && api.includes("/aws-advisor-sbom/syft.yaml"), `pulled from the registry for the box's platform with the config and the purl and CPE template: ${api}`);
  assert.ok(!args.find((l) => l.includes(`registry:public.ecr.aws`))!.includes("--platform"), "no platform flag without a platform");
  const cfg = fs.readFileSync(cfgcopy, "utf8");
  assert.ok(cfg.includes("authority: 123456789012.dkr.ecr.eu-west-1.amazonaws.com") && cfg.includes('password: "TOKEN-EU"') && cfg.includes("authority: public.ecr.aws") && cfg.includes('password: "TOKEN-PUBLIC"'), `one auth entry per ECR host, the token from the CLI: ${cfg}`);
  assert.equal(cfg.split("authority: 123456789012").length, 2, "one entry per host, not per image");
  assert.ok(!cfg.includes("nginx"), "Docker Hub is left to the scanner's own docker config");
  assert.ok(!JSON.stringify(j).includes("TOKEN-"), "no token in the result");
  assert.ok(!fs.existsSync(path.join(dir, "aws-advisor-sbom")), "the scratch directory, config included, is gone when the probe exits");
  // no AWS CLI on the scanner: the ECR entries are skipped with the reason, never attempted; the rest is read
  fs.writeFileSync(log, "");
  const k = run(`${noaws}:/usr/bin:/bin`, script(batch));
  const kb = Object.fromEntries(k.sbom!.sources.map((s) => [s.ref, s]));
  assert.equal(kb[`123456789012.dkr.ecr.eu-west-1.amazonaws.com/api@${sha("a")}`]!.status, "skipped"); assert.match(kb[`123456789012.dkr.ecr.eu-west-1.amazonaws.com/api@${sha("a")}`]!.note ?? "", /^ECR auth needs the AWS CLI on the scanner/);
  assert.equal(kb[`public.ecr.aws/docker/library/redis@${sha("c")}`]!.status, "skipped");
  assert.equal(kb[`nginx@${sha("b")}`]!.status, "timeout", "Docker Hub needs no token");
  assert.ok(!fs.readFileSync(log, "utf8").includes("dkr.ecr"), "syft was never asked for an ECR image");
  // a scanner with a Docker daemon (images 1.4): the daemon is logged in with the ECR token, pulls each image for its platform, a container is created from it and
  // its filesystem exported into the scratch directory, which syft reads; a pull that times out is the image's timeout, a pull that fails leaves the image to the registry source
  const withdk = path.join(dir, "withdk"); fs.mkdirSync(withdk);
  w(withdk, "timeout", "#!/bin/sh\nshift; exec \"$@\"\n");
  w(withdk, "aws", fs.readFileSync(path.join(bin, "aws"), "utf8"));
  w(withdk, "syft", `#!/bin/sh\necho "$*" >> ${log}\ncase "$*" in version) printf 'Application: syft\\nVersion: 1.55.0\\n';; *dir:*) printf 'pkg:pypi/flask@3.0.0\\tcpe:2.3:a:palletsprojects:flask:3.0.0:*:*:*:*:*:*:*\\n';; *registry:*) printf 'pkg:npm/express@4.19.2\\t\\n';; *) exit 2;; esac\n`);
  // the fake daemon: pulls (one times out, one fails), reports a size, creates a container id, exports a one-file filesystem as a tar on stdout
  const payload = path.join(dir, "payload"); fs.mkdirSync(path.join(payload, "usr", "bin"), { recursive: true }); fs.writeFileSync(path.join(payload, "usr", "bin", "flask"), "#!/bin/sh\n");
  w(withdk, "docker", `#!/bin/sh\necho "docker $* config=\${DOCKER_CONFIG:-}" >> ${log}\ncase "$1 $2" in "info --format") case "$3" in '{{.ServerVersion}}') echo 25.0.18;; '{{.DockerRootDir}}') echo /var/lib/docker;; esac;; "login --username") cat > ${dir}/login-$5;; "pull -q") [ -f "$DOCKER_CONFIG/config.json" ] && cp "$DOCKER_CONFIG/config.json" ${dir}/cfg-at-pull.json; for a in "$@"; do ref=$a; done; case "$ref" in *nginx@*) exit 124;; *web@*) exit 1;; *) exit 0;; esac;; "image inspect") printf '8469383050\\n';; "create "*) printf 'c0ffee%s\\n' "$(printf '%058d' 7)";; "export "*) tar -c -C ${payload} . ;; "rm -f") exit 0;; "image rm") exit 0;; *) exit 1;; esac\n`);
  fs.writeFileSync(log, "");
  // root's docker config on the scanner: a Docker Hub login the daemon and syft must keep using
  const home = path.join(dir, "home"); fs.mkdirSync(path.join(home, ".docker"), { recursive: true }); fs.writeFileSync(path.join(home, ".docker", "config.json"), '{"auths":{"https://index.docker.io/v1/":{"auth":"aHVi"}}}');
  const d = run(`${withdk}:/usr/bin:/bin`, script(batch), { HOME: home });
  const db = Object.fromEntries(d.sbom!.sources.map((s) => [s.ref, s]));
  const apiRef = `123456789012.dkr.ecr.eu-west-1.amazonaws.com/api@${sha("a")}`; const webRef = `123456789012.dkr.ecr.eu-west-1.amazonaws.com/web@${sha("d")}`;
  assert.equal(db[apiRef]!.status, "ok"); assert.deepEqual(db[apiRef]!.purls, ["pkg:pypi/flask@3.0.0"], "read from the export, not the registry"); assert.equal(db[apiRef]!.platform, "linux/arm64");
  assert.equal(db[`public.ecr.aws/docker/library/redis@${sha("c")}`]!.status, "ok"); assert.deepEqual(db[`public.ecr.aws/docker/library/redis@${sha("c")}`]!.purls, ["pkg:pypi/flask@3.0.0"]);
  assert.equal(db[`nginx@${sha("b")}`]!.status, "timeout"); assert.match(db[`nginx@${sha("b")}`]!.note ?? "", /^the daemon did not finish pulling and exporting the image within 90 s/);
  assert.equal(db[webRef]!.status, "ok"); assert.deepEqual(db[webRef]!.purls, ["pkg:npm/express@4.19.2"], "the daemon could not pull it: the registry source read it");
  const dl = fs.readFileSync(log, "utf8").split("\n");
  const img = path.join(dir, "aws-advisor-sbom", "img"); const dcfg = path.join(dir, "aws-advisor-sbom-docker");
  assert.ok(dl.some((l) => l === `docker pull -q --platform linux/arm64 ${apiRef} config=${dcfg}`), `pulled by the daemon for the box's platform with the probe's docker config: ${dl.join(" | ")}`);
  assert.ok(dl.some((l) => l.startsWith(`docker pull -q public.ecr.aws/docker/library/redis@`) && !l.includes("--platform")), "no platform flag without a platform");
  const cid = "c0ffee" + "0".repeat(57) + "7";
  assert.ok(dl.some((l) => l.startsWith(`docker create --platform linux/arm64 ${apiRef} /aws-advisor-probe-never-runs`)), `a container created from the image for its platform, never started: ${dl.filter((l) => l.startsWith("docker create")).join(" | ")}`);
  assert.equal(dl.filter((l) => l.startsWith(`docker export ${cid}`)).length, 2, "the two pulled images exported, once each");
  assert.equal(dl.filter((l) => l.startsWith(`scan dir:${img} --base-path ${img} -o template`)).length, 2, `syft reads the export: ${dl.filter((l) => l.startsWith("scan")).join(" | ")}`);
  assert.ok(dl.some((l) => l.startsWith(`scan -c `) && l.includes(`registry:${webRef}`)), "the registry fallback carries the syft config");
  assert.ok(!dl.some((l) => l.startsWith("mount") || l.startsWith("umount")), "no overlay mount any more");
  assert.equal(dl.filter((l) => l === `docker rm -f ${cid} config=${dcfg}`).length, 2, "each container removed, once");
  assert.ok(!fs.existsSync(img), "the export is gone with the scratch directory");
  assert.equal(fs.readFileSync(path.join(dir, "login-123456789012.dkr.ecr.eu-west-1.amazonaws.com"), "utf8"), "TOKEN-EU", "the daemon logged in with the CLI's token on stdin");
  assert.equal(fs.readFileSync(path.join(dir, "login-public.ecr.aws"), "utf8"), "TOKEN-PUBLIC");
  assert.ok(!fs.existsSync(dcfg), "the docker config copy is gone when the probe exits");
  // sbom 1.8: syft is trimmed to packages and binaries and runs under the cap at low priority, on the scanner and on the boxes alike
  for (const kind of ["sbom", "images"] as const) {
    const s = pr.defaultProbeScript(kind);
    for (const v of ["SYFT_FILE_METADATA_SELECTION=none", "SYFT_PACKAGE_SEARCH_INDEXED_ARCHIVES=false", "SYFT_PACKAGE_SEARCH_UNINDEXED_ARCHIVES=false", "SYFT_UNKNOWNS_EXECUTABLES_WITHOUT_PACKAGES=false", "SYFT_PARALLELISM=1", `SYFT_SELECT_CATALOGERS='${pr.SYFT_TRIM}'`, "GOMEMLIMIT=$lastcap", "-p MemoryMax=$lastcap", "nice -n 19"]) assert.ok(s.includes(v), `${kind}: ${v}`);
    assert.ok(!/\btmo "\$secs" "\$syft"/.test(s), `${kind}: every syft read goes through syftrun`);
  }
  assert.equal(pr.defaultProbeScript("images").match(/^mem_pct=70$/m)?.[0], "mem_pct=70"); assert.equal(pr.defaultProbeScript("sbom").match(/^mem_pct=40$/m)?.[0], "mem_pct=40");
  for (const name of pr.SYFT_TRIM.split(",")) assert.match(name, /^-[a-z-]+-cataloger$/);
  assert.equal(fs.readFileSync(path.join(dir, "cfg-at-pull.json"), "utf8"), '{"auths":{"https://index.docker.io/v1/":{"auth":"aHVi"}}}', "the pull ran with a copy of root's docker config: the Hub login applies");
  assert.equal(fs.readFileSync(path.join(home, ".docker", "config.json"), "utf8"), '{"auths":{"https://index.docker.io/v1/":{"auth":"aHVi"}}}', "root's own file is untouched");
  assert.equal(dl.filter((l) => l.startsWith("docker image rm -f ")).length, 4, "the two scanned images and the two failed pulls");
  assert.ok(!JSON.stringify(d).includes("TOKEN-"), "no token in the result");
  // an empty batch: nothing read, a valid answer
  assert.deepEqual(run(`${bin}:/usr/bin:/bin`, script("")).sbom!.sources, []);
});

test("the apps script reports the host firewall (apps 2.1): iptables-save stripped of timestamps and counters, the backend, the true line count; without the tools it says so", async () => {
  const { parseProbeOutput } = await import("../ssm.js");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "advisor-fake-iptables-"));
  const bin = path.join(dir, "bin"); fs.mkdirSync(bin);
  const dump = ["# Generated by iptables-save v1.8.7 on Sat Nov  1 10:00:00 2026", "*filter", ":INPUT DROP [12:3456]", ":FORWARD ACCEPT [0:0]", ":OUTPUT ACCEPT [99:1000]", ":DOCKER - [0:0]",
    "-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", '-A INPUT -p tcp -m tcp --dport 22 -m comment --comment "allow \\"office\\" ssh" -j ACCEPT', "-A FORWARD -j DOCKER",
    "-A DOCKER -d 172.17.0.2/32 ! -i docker0 -o docker0 -p tcp -m tcp --dport 80 -j ACCEPT", "COMMIT", "# Completed on Sat Nov  1 10:00:00 2026"];
  fs.writeFileSync(path.join(bin, "iptables-save"), `#!/bin/sh\ncat <<'X'\n${dump.join("\n")}\nX\n`, { mode: 0o755 });
  fs.writeFileSync(path.join(bin, "ip6tables-save"), "#!/bin/sh\nprintf '*filter\\n:INPUT ACCEPT [0:0]\\nCOMMIT\\n'\n", { mode: 0o755 });
  fs.writeFileSync(path.join(bin, "iptables"), "#!/bin/sh\necho 'iptables v1.8.7 (nf_tables)'\n", { mode: 0o755 });
  const run = (p: string) => { const r = spawnSync("sh", [], { input: pr.defaultProbeScript("apps"), encoding: "utf8", env: { ...process.env, PATH: p } }); assert.equal(r.status, 0, r.stderr); return parseProbeOutput(r.stdout); };
  const a = run(`${bin}:/usr/bin:/bin`);
  assert.equal(a.probe, "aws-advisor/apps/3"); assert.equal(a.kind, "apps");
  const fw = a.firewall!;
  assert.equal(fw.available, true); assert.equal(fw.backend, "nf_tables"); assert.equal(fw.oversize, false);
  assert.deepEqual(fw.v4, dump.filter((l) => !l.startsWith("#")).map((l) => l.replace(/ \[\d+:\d+\]$/, "")), "the lines as printed, no timestamps, no counters, the comment intact");
  assert.equal(fw.v4_lines, 10); assert.deepEqual(fw.v6, ["*filter", ":INPUT ACCEPT", "COMMIT"]); assert.equal(fw.v6_lines, 3); assert.deepEqual(fw.nft, []);
  assert.ok(Array.isArray(a.listeners) && Array.isArray(a.processes), "the rest of the apps probe is untouched");
  // the box has no iptables at all (the PATH has neither the stubs nor /sbin)
  const b = run("/usr/bin:/bin").firewall!;
  assert.equal(b.available, false); assert.equal(b.backend, null); assert.deepEqual(b.v4, []); assert.equal(b.v4_lines, 0);
  // nft beside iptables: its ruleset is read too (counters and handles dropped, the indentation gone), the backend stays iptables'
  const nftbin = path.join(dir, "nftbin"); fs.mkdirSync(nftbin);
  const nft = ["table inet firewalld {", "\tchain filter_INPUT {", "\t\ttype filter hook input priority filter + 10; policy accept;", "\t\tct state { established, related } counter packets 10 bytes 900 accept # handle 3", "\t\ttcp dport 22 accept comment \"ssh\"", "\t\treject with icmpx type admin-prohibited", "\t}", "}"];
  fs.writeFileSync(path.join(nftbin, "nft"), `#!/bin/sh\n[ "$1" = list ] || exit 1\ncat <<'X'\n${nft.join("\n")}\nX\n`, { mode: 0o755 });
  const c = run(`${bin}:${nftbin}:/usr/bin:/bin`).firewall!;
  assert.equal(c.backend, "nf_tables"); assert.equal(c.available, true);
  assert.deepEqual(c.nft, ["table inet firewalld {", "chain filter_INPUT {", "type filter hook input priority filter + 10; policy accept;", "ct state { established, related } accept", 'tcp dport 22 accept comment "ssh"', "reject with icmpx type admin-prohibited", "}", "}"]);
  assert.equal(c.nft_lines, 8); assert.equal(c.v4_lines, 10, "iptables-save is still read");
  // nft alone: the backend is nftables
  const d = run(`${nftbin}:/usr/bin:/bin`).firewall!;
  assert.equal(d.available, true); assert.equal(d.backend, "nftables"); assert.equal(d.nft_lines, 8); assert.deepEqual(d.v4, []); assert.equal(d.v4_lines, 0);
});

test("kernelFacts: the running kernel's upstream version and owning package, from the probe or derived from the package list; uname -r alone is never read as a version when it is an ABI", () => {
  const deb = [{ name: "linux-image-6.1.0-54-cloud-amd64", version: "6.1.176-1", arch: "amd64", source: "linux-signed-amd64" }, { name: "linux-image-6.1.0-37-cloud-amd64", version: "6.1.140-1", arch: "amd64", source: "linux-signed-amd64" }, { name: "linux-image-cloud-amd64", version: "6.1.176-1", arch: "amd64", source: "linux-signed-amd64" }];
  // Debian, an older probe: the booted image's package is the one named by uname -r (not the newer one apt installed, not the metapackage), and its version starts with the upstream version
  assert.deepEqual(sw.kernelFacts({ kernel: "6.1.0-54-cloud-amd64", os_id: "debian", package_manager: "deb" }, deb), { upstream: "6.1.176", pkg: { name: "linux-image-6.1.0-54-cloud-amd64", version: "6.1.176-1", source: "linux-signed-amd64" } });
  // the probe's own reading wins (software/6): what dpkg said owns the image, what /proc/version_signature said the upstream version is
  assert.deepEqual(sw.kernelFacts({ kernel: "6.8.0-45-generic", kernel_upstream: "6.8.12", kernel_package: { n: "linux-image-6.8.0-45-generic", v: "6.8.0-45.45", s: "linux-signed" }, os_id: "ubuntu", package_manager: "deb" }, []), { upstream: "6.8.12", pkg: { name: "linux-image-6.8.0-45-generic", version: "6.8.0-45.45", source: "linux-signed" } });
  // Ubuntu without the probe's reading: the package is found, the upstream version is not guessed from 6.8.0-45.45
  assert.deepEqual(sw.kernelFacts({ kernel: "6.8.0-45-generic", os_id: "ubuntu", package_manager: "deb" }, [{ name: "linux-image-6.8.0-45-generic", version: "6.8.0-45.45", arch: "amd64", source: "linux-signed" }]), { upstream: null, pkg: { name: "linux-image-6.8.0-45-generic", version: "6.8.0-45.45", source: "linux-signed" } });
  assert.equal(sw.kernelFacts({ kernel: "6.8.0-45-generic", os_id: "ubuntu", package_manager: "deb" }, []).upstream, null, "an ABI name is never read as 6.8.0");
  assert.equal(sw.kernelFacts({ kernel: "6.1.0-54-cloud-amd64", os_id: "debian", package_manager: "deb" }, []).upstream, null, "nor as 6.1.0 (a Debian kernel in a container, no dpkg)");
  // rpm: uname -r is version-release.arch of the kernel package, and starts with the upstream version; the source equal to the name is dropped
  assert.deepEqual(sw.kernelFacts({ kernel: "6.1.134-150.224.amzn2023.x86_64", os_id: "amzn", package_manager: "rpm" }, [{ name: "kernel", version: "6.1.134-150.224.amzn2023", arch: "x86_64", source: "kernel" }, { name: "kernel", version: "6.1.141-155.222.amzn2023", arch: "x86_64", source: null }]),
    { upstream: "6.1.134", pkg: { name: "kernel", version: "6.1.134-150.224.amzn2023", source: null } });
  assert.deepEqual(sw.kernelFacts({ kernel: "5.14.0-427.el9.x86_64", package_manager: "rpm" }, [{ name: "kernel-core", version: "5.14.0-427.el9", arch: "x86_64", source: "kernel" }]), { upstream: "5.14.0", pkg: { name: "kernel-core", version: "5.14.0-427.el9", source: "kernel" } });
  // apk: linux-<flavor>; a self-built kernel: uname -r starts with the upstream version, no package
  assert.deepEqual(sw.kernelFacts({ kernel: "6.6.30-0-virt", os_id: "alpine", package_manager: "apk" }, [{ name: "linux-virt", version: "6.6.30-r0", arch: null, source: null }]), { upstream: "6.6.30", pkg: { name: "linux-virt", version: "6.6.30-r0", source: null } });
  assert.deepEqual(sw.kernelFacts({ kernel: "6.6.30-custom", os_id: "debian", package_manager: "deb" }, []), { upstream: "6.6.30", pkg: null });
  assert.deepEqual(sw.kernelFacts({ kernel: null }, deb), { upstream: null, pkg: null });
});

test("software inventory: the kernel's upstream version and owning package are stored with the OS row, derived for an older probe, replaced by a newer one, cleared by a reboot into an unowned kernel, kept by a probe that did not read the kernel", () => {
  const iid = "i-0feedfacecafe0011";
  db.prepare("insert or replace into inventory_ec2(instance_id, name, state, snapshot) values (?, 'deb-1', 'running', '{}')").run(iid);
  const pk = (n: string, v: string) => ({ n, v, a: "amd64", s: "linux-signed-amd64" });
  // software/5 shape: no kernel facts from the probe; the package list has the booted image's package
  sw.recordSoftware(iid, "2026-10-01T00:00:00Z", { os: { id: "debian", version: "12", name: "Debian GNU/Linux 12 (bookworm)" }, kernel: "6.1.0-54-cloud-amd64", arch: "x86_64", package_manager: "deb", packages: [pk("linux-image-6.1.0-54-cloud-amd64", "6.1.176-1"), { n: "bash", v: "5.2.15-2+b7", a: "amd64" }] });
  let o = sw.softwareOn(iid).os!;
  assert.deepEqual([o.kernel, o.kernel_upstream, o.kernel_package, o.kernel_package_version, o.kernel_package_source], ["6.1.0-54-cloud-amd64", "6.1.176", "linux-image-6.1.0-54-cloud-amd64", "6.1.176-1", "linux-signed-amd64"]);
  // apt installed the fix, no reboot yet: the booted image is still the old package, a second linux-image row sits next to it
  sw.recordSoftware(iid, "2026-10-02T00:00:00Z", { kernel: "6.1.0-54-cloud-amd64", package_manager: "deb", packages: [pk("linux-image-6.1.0-54-cloud-amd64", "6.1.176-1"), pk("linux-image-6.1.0-56-cloud-amd64", "6.1.190-1")] });
  o = sw.softwareOn(iid).os!;
  assert.deepEqual([o.kernel_upstream, o.kernel_package_version], ["6.1.176", "6.1.176-1"], "installed is not booted");
  // rebooted, and the probe is software/6: its own reading replaces the derived one
  sw.recordSoftware(iid, "2026-10-03T00:00:00Z", { kernel: "6.1.0-56-cloud-amd64", kernel_upstream: "6.1.190", kernel_package: { n: "linux-image-6.1.0-56-cloud-amd64", v: "6.1.190-1", s: "linux-signed-amd64" }, package_manager: "deb", packages: [pk("linux-image-6.1.0-56-cloud-amd64", "6.1.190-1")] });
  o = sw.softwareOn(iid).os!;
  assert.deepEqual([o.kernel, o.kernel_upstream, o.kernel_package, o.kernel_package_version], ["6.1.0-56-cloud-amd64", "6.1.190", "linux-image-6.1.0-56-cloud-amd64", "6.1.190-1"]);
  // a probe that did not read the kernel (another section's shape) leaves the three names alone
  sw.recordSoftware(iid, "2026-10-04T00:00:00Z", { package_manager: "deb", packages: [pk("linux-image-6.1.0-56-cloud-amd64", "6.1.190-1")] });
  o = sw.softwareOn(iid).os!;
  assert.deepEqual([o.kernel, o.kernel_upstream, o.kernel_package], ["6.1.0-56-cloud-amd64", "6.1.190", "linux-image-6.1.0-56-cloud-amd64"]);
  // a reboot into a kernel no package owns (self-built): the package goes, the upstream version is the release's own
  sw.recordSoftware(iid, "2026-10-05T00:00:00Z", { kernel: "6.6.30-custom", kernel_upstream: "6.6.30", kernel_package: null, package_manager: "deb", packages: [pk("linux-image-6.1.0-56-cloud-amd64", "6.1.190-1")] });
  o = sw.softwareOn(iid).os!;
  assert.deepEqual([o.kernel, o.kernel_upstream, o.kernel_package, o.kernel_package_version], ["6.6.30-custom", "6.6.30", null, null]);
  for (const t of ["instance_os", "instance_packages", "instance_binaries", "instance_images", "package_changes"]) db.prepare(`delete from ${t} where instance_id = ?`).run(iid);
  db.prepare("delete from inventory_ec2 where instance_id = ?").run(iid);
});

test("software inventory: several installed versions of one package (rpm kernels) are rows of their own; the change log pairs what left with what arrived", () => {
  const iid = "i-0feedfacecafe0020";
  db.prepare("insert or replace into inventory_ec2(instance_id, name, state, snapshot) values (?, 'al-1', 'running', '{}')").run(iid);
  for (const t of ["instance_os", "instance_packages", "instance_binaries", "instance_images", "package_changes"]) db.prepare(`delete from ${t} where instance_id = ?`).run(iid);
  const two = [{ n: "kernel", v: "6.1.119-129.201.amzn2023", a: "x86_64" }, { n: "kernel", v: "6.1.189-236.400.amzn2023", a: "x86_64" }, { n: "gpg-pubkey", v: "d832c631-6515c85e" }, { n: "gpg-pubkey", v: "cf8e292a-63c8e149" }, { n: "curl", v: "8.5.0", a: "x86_64" }];
  const first = sw.recordSoftware(iid, "2026-11-01T00:00:00Z", { os: { id: "amzn", version: "2023" }, kernel: "6.1.189-236.400.amzn2023.x86_64", arch: "x86_64", package_manager: "rpm", packages: two, binaries: [], images: [] })!;
  assert.equal(first.packages, 5); assert.equal(first.changed.length, 0);
  assert.equal((db.prepare("select count(*) as n from instance_packages where instance_id = ? and name = 'kernel'").get(iid) as any).n, 2, "one row per installed kernel");
  const same = sw.recordSoftware(iid, "2026-11-02T00:00:00Z", { package_manager: "rpm", packages: [...two].reverse(), binaries: [], images: [] })!;
  assert.deepEqual([same.changed, same.added, same.removed], [[], [], []], "the same list in another order changes nothing");
  assert.equal((db.prepare("select count(*) as n from package_changes where instance_id = ?").get(iid) as any).n, 0);
  // a newer kernel installed, the oldest image purged: an upgrade from the one that left to the one that arrived
  const third = sw.recordSoftware(iid, "2026-11-03T00:00:00Z", { package_manager: "rpm", packages: [two[1]!, { n: "kernel", v: "6.1.200-240.500.amzn2023", a: "x86_64" }, two[2]!, two[3]!, two[4]!], binaries: [], images: [] })!;
  assert.deepEqual(third.changed, [{ name: "kernel", from: "6.1.119-129.201.amzn2023", to: "6.1.200-240.500.amzn2023" }]); assert.deepEqual(third.removed, [], "the name is still installed");
  // a kernel added beside the two kept: logged as following the newest kept; a version purged on its own: that version's removal, the name stays
  const fourth = sw.recordSoftware(iid, "2026-11-04T00:00:00Z", { package_manager: "rpm", packages: [two[1]!, { n: "kernel", v: "6.1.200-240.500.amzn2023", a: "x86_64" }, { n: "kernel", v: "6.1.210-250.600.amzn2023", a: "x86_64" }, two[2]!, two[4]!], binaries: [], images: [] })!;
  assert.deepEqual(fourth.changed, [{ name: "kernel", from: "6.1.200-240.500.amzn2023", to: "6.1.210-250.600.amzn2023" }]); assert.deepEqual(fourth.removed, []);
  assert.deepEqual(db.prepare("select name, from_version, to_version from package_changes where instance_id = ? order by id").all(iid), [
    { name: "kernel", from_version: "6.1.119-129.201.amzn2023", to_version: "6.1.200-240.500.amzn2023" },
    { name: "kernel", from_version: "6.1.200-240.500.amzn2023", to_version: "6.1.210-250.600.amzn2023" },
    { name: "gpg-pubkey", from_version: "cf8e292a-63c8e149", to_version: null },
  ]);
  assert.deepEqual(sw.softwareOn(iid).packages.filter((p) => p.name === "kernel").map((p) => p.version).sort(), ["6.1.189-236.400.amzn2023", "6.1.200-240.500.amzn2023", "6.1.210-250.600.amzn2023"]);
  assert.equal(sw.softwareOn(iid).packages.find((p) => p.version === "6.1.189-236.400.amzn2023")?.first_seen, "2026-11-01T00:00:00Z", "a version row keeps when it was first seen");
  const whole = sw.recordSoftware(iid, "2026-11-05T00:00:00Z", { package_manager: "rpm", packages: [two[4]!], binaries: [], images: [] })!;
  assert.deepEqual([...whole.removed].sort(), ["gpg-pubkey", "kernel"], "a name gone altogether is removed once, however many versions it had");
  for (const t of ["instance_os", "instance_packages", "instance_binaries", "instance_images", "package_changes"]) db.prepare(`delete from ${t} where instance_id = ?`).run(iid);
});

test("compareVersions orders an epoch first, then numbers by value, then text", () => {
  const sorted = ["6.1.189-236.400.amzn2023", "1:6.1.119-129.201.amzn2023", "6.1.119-129.201.amzn2023", "4.14.355-277.647.amzn2", "4.14.355-271.569.amzn2", "6.1.0~rc1-1", "6.1.0-1"].sort(sw.compareVersions);
  assert.deepEqual(sorted, ["4.14.355-271.569.amzn2", "4.14.355-277.647.amzn2", "6.1.0~rc1-1", "6.1.0-1", "6.1.119-129.201.amzn2023", "6.1.189-236.400.amzn2023", "1:6.1.119-129.201.amzn2023"]);
});

import assert from "node:assert/strict";
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
  assert.deepEqual(Object.keys((pr.probeDocument("sbom") as any).parameters), ["install", "images", "upload"]);
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
    "dpkg-query": "#!/bin/sh\ncase \"$*\" in *Depends*) printf 'libc6 (>= 2.34), nginx (>= 1), libnotinstalled (>= 1)';; *) printf 'ii\\topenssh-server\\t1:9.6p1-3ubuntu13.4\\tamd64\\topenssh\\n'; printf 'ii\\tnginx\\t1.24.0-2ubuntu7\\tamd64\\tnginx\\n'; printf 'rc\\tgone\\t1.0\\tall\\tgone\\n';; esac\n",
    rpm: "#!/bin/sh\nprintf 'openssh-server\\t(none):8.7p1-38.el9\\tx86_64\\topenssh-8.7p1-38.el9.src.rpm\\n'; printf 'kernel\\t(none):5.14.0-427.el9\\tx86_64\\tkernel-5.14.0-427.el9.src.rpm\\n'\n",
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
    assert.equal(j.kind, "software"); assert.equal(j.probe, "aws-advisor/software/5");
    assert.deepEqual(j.packages, expected[name], name);
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

test("the sbom script: with syft it scans each running image and the filesystem, keeps each scan's status, trims to the budget and fits the SSM cap; without syft it says so and scans nothing", async () => {
  const { parseProbeOutput, SSM_OUTPUT_CAP } = await import("../ssm.js");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "advisor-fake-syft-"));
  const bin = path.join(dir, "bin"); fs.mkdirSync(bin); const bare = path.join(dir, "bare"); fs.mkdirSync(bare);
  const log = path.join(dir, "args.log");
  const w = (where: string, name: string, body: string) => fs.writeFileSync(path.join(where, name), body, { mode: 0o755 });
  for (const where of [bin, bare]) {
    w(where, "docker", "#!/bin/sh\ncase \"$1 $2 $5\" in info*) exit 0;; ps*) printf 'nginx:1.27\\napp:latest\\nnginx:1.27\\nhuge:1\\n';; 'image inspect nginx:1.27') printf 'sha256:bbbb|nginx@sha256:cccc|52428800|linux/amd64\\n';; 'image inspect app:latest') printf 'sha256:aaaa||104857600|linux/arm64\\n';; 'image inspect huge:1') printf 'sha256:dddd|huge@sha256:eeee|9000000000000000000|linux/amd64\\n';; *) exit 1;; esac\n");
    w(where, "dpkg-query", "#!/bin/sh\nexit 0\n");
    w(where, "timeout", "#!/bin/sh\nshift; exec \"$@\"\n"); // macOS has none; the script falls back to no bound either way
  }
  // one image times out, one lists a duplicate and a distro package, the filesystem lists an OS package (dropped: dpkg owns it) and far more than the budget
  w(bin, "syft", `#!/bin/sh\necho "$* tmpdir=\${TMPDIR:-}" >> ${log}\nif [ -n "\${TMPDIR:-}" ]; then mkdir -p "$TMPDIR/stereoscope-fake" && : > "$TMPDIR/stereoscope-fake/layer.tar"; fi\ncase "$*" in version) printf 'Application: syft\\nVersion: 1.55.0\\n';; *docker:nginx:1.27*) exit 124;; *docker:app:latest*) printf 'pkg:npm/%%40aws-sdk/core@3.1.0\\npkg:npm/express@4.19.2\\npkg:npm/express@4.19.2\\npkg:deb/debian/libc6@2.36-9?arch=amd64&upstream=glibc&distro=debian-12\\n';; *dir:/*) printf 'pkg:deb/ubuntu/curl@8.5.0?arch=amd64\\n'; i=0; while [ $i -lt 6000 ]; do printf 'pkg:pypi/package-%s@1.0.%s\\n' "$i" "$i"; i=$((i+1)); done;; *) exit 2;; esac\n`);
  const run = (PATH: string, script = pr.defaultProbeScript("sbom"), extra: Record<string, string> = {}) => { const r = spawnSync("sh", [], { input: script, encoding: "utf8", env: { ...process.env, PATH, ...extra } }); assert.equal(r.status, 0, r.stderr); return r.stdout.trim().split("\n").pop() || ""; };
  const scratch = path.join(dir, "aws-advisor-sbom"); // the name the guarded removals require
  const line = run(`${bin}:/usr/bin:/bin`, pr.defaultProbeScript("sbom"), { AWS_ADVISOR_SBOM_TMP: scratch });
  assert.ok(!fs.existsSync(scratch), "the scratch directory syft unpacked images in is gone when the probe exits");
  // a directory of another name is never touched: the probe then leaves syft its default TMPDIR
  const other = path.join(dir, "elsewhere"); fs.mkdirSync(other); fs.writeFileSync(path.join(other, "keep"), "");
  run(`${bin}:/usr/bin:/bin`, pr.defaultProbeScript("sbom"), { AWS_ADVISOR_SBOM_TMP: other });
  assert.ok(fs.existsSync(path.join(other, "keep")), "a scratch path that does not end in /aws-advisor-sbom is refused, not emptied");
  assert.ok(line.length < SSM_OUTPUT_CAP, `the line fits SSM's cap (${line.length})`);
  const j = parseProbeOutput(line);
  assert.equal(j.kind, "sbom"); assert.equal(j.probe, "aws-advisor/sbom/4"); assert.equal(j.sbom?.install, null, "syft was there: nothing to install");
  assert.equal(j.sbom?.available, true); assert.equal(j.sbom?.tool, "syft 1.55.0"); assert.equal(j.sbom?.images_mode, "all", "the default: every running image, here");
  const by = Object.fromEntries(j.sbom!.sources.map((s) => [`${s.source} ${s.ref}`, s]));
  assert.deepEqual(by["image app:latest"], { source: "image", ref: "app:latest", image_id: "sha256:aaaa", digest: null, platform: "linux/arm64", status: "ok", total: 3, note: null, purls: ["pkg:npm/%40aws-sdk/core@3.1.0", "pkg:npm/express@4.19.2", "pkg:deb/debian/libc6@2.36-9?arch=amd64&upstream=glibc&distro=debian-12"] }, "duplicates dropped, order kept; a local build has an id and no digest; the platform travels");
  assert.deepEqual(by["image nginx:1.27"], { source: "image", ref: "nginx:1.27", image_id: "sha256:bbbb", digest: "sha256:cccc", platform: "linux/amd64", status: "timeout", total: 0, note: null, purls: [] }, "a pulled image carries its registry digest");
  assert.equal(by["image huge:1"]!.status, "skipped"); assert.equal(by["image huge:1"]!.platform, "linux/amd64"); assert.match(by["image huge:1"]!.note ?? "", /^needs about \d+ MB of scratch space under .*, \d+ MB free$/, "an image the free disk cannot hold is skipped, not half-read");
  assert.ok(!fs.readFileSync(log, "utf8").includes("docker:huge:1"), "syft was never asked for it");
  assert.equal(by["dir /"]!.image_id, null); assert.equal(by["dir /"]!.platform, null); assert.equal(j.upload, undefined, "no upload URL: no receipt");
  // local mode (sbom 1.6): the images with a registry digest are the scanner's and are not listed; the local build and the filesystem stay
  const nginxScans = () => fs.readFileSync(log, "utf8").split("\n").filter((l) => l.includes("docker:nginx:1.27")).length;
  const beforeLocal = nginxScans();
  const local = parseProbeOutput(run(`${bin}:/usr/bin:/bin`, pr.defaultProbeScript("sbom").replace("__IMAGES_MODE__", "local"), { AWS_ADVISOR_SBOM_TMP: scratch }));
  assert.equal(local.sbom?.images_mode, "local");
  assert.deepEqual(local.sbom!.sources.map((s) => `${s.source} ${s.ref}`), ["image app:latest", "dir /"], "nginx (digest) and huge (digest) are left to the scanner, not even reported as skipped");
  assert.equal(nginxScans(), beforeLocal, "the digested image was not scanned in local mode");
  assert.equal(by["dir /"]!.status, "ok"); assert.equal(by["dir /"]!.total, 6000, "the OS package is left to the software probe; the true count is reported");
  assert.ok(by["dir /"]!.purls.length < 6000 && by["dir /"]!.purls.length >= 100 && by["dir /"]!.purls.every((p) => p.startsWith("pkg:pypi/")), `trimmed to the budget (${by["dir /"]!.purls.length}, cap ${j.sbom!.cap})`);
  const args = fs.readFileSync(log, "utf8").split("\n").find((l) => l.includes("dir:/"))!;
  assert.ok(args.includes(`tmpdir=${scratch}`), "syft is given the probe's scratch directory as TMPDIR");
  for (const ex of ["./proc/**", "./sys/**", "./var/lib/docker/**", "./home/*/.cache/**"]) assert.ok(args.includes(`--exclude ${ex}`), `the filesystem scan excludes ${ex} (globbing off)`);
  assert.ok(args.includes("-o purls") && args.includes("-q"), "purls only, quiet");
  assert.ok(args.includes(`--exclude .${path.join(bin, "syft")}`), "syft does not catalog its own Go modules");
  // no syft and the install switch off: reported, left alone
  const none = parseProbeOutput(run(`${bare}:/usr/bin:/bin`, pr.defaultProbeScript("sbom").replace("__INSTALL__", "no")));
  assert.deepEqual(none.sbom, { available: false, tool: null, install: "not installed; the install parameter is no", images_mode: "all", cap: 3000, sources: [] });
  // the switch on (the default): the installer is fetched with curl and run; the fake one copies the fake syft into the target directory, then the scan runs with it
  const target = path.join(dir, "installed");
  w(bare, "curl", `#!/bin/sh\ncase "$*" in *get.anchore.io/syft*) printf 'mkdir -p "$2"; cp "%s" "$2/syft"\n' "${path.join(bin, "syft")}";; *) exit 22;; esac\n`);
  const got = parseProbeOutput(run(`${bare}:/usr/bin:/bin`, pr.probeScript("sbom"), { AWS_ADVISOR_SYFT_DIR: target }));
  assert.equal(got.sbom?.install, "installed v1.55.0"); assert.equal(got.sbom?.available, true); assert.equal(got.sbom?.sources.length, 4, "scanned right after installing");
  assert.ok(fs.existsSync(path.join(target, "syft")));
  // the switch on but no egress: the failure and what it needs are reported, nothing scanned
  w(bare, "curl", "#!/bin/sh\nexit 6\n");
  const failed = parseProbeOutput(run(`${bare}:/usr/bin:/bin`, pr.probeScript("sbom"), { AWS_ADVISOR_SYFT_DIR: path.join(dir, "nowhere") }));
  assert.equal(failed.sbom?.available, false); assert.match(failed.sbom?.install ?? "", /^install failed: curl, egress/);
  // an upload URL (probe 2.1): the whole, untrimmed result is posted gzip-compressed with curl; the inline line carries the receipt and stays trimmed
  const capture = path.join(dir, "uploaded.json.gz");
  w(bin, "curl", `#!/bin/sh\ncase "$*" in *" -X PUT "*) for a in "$@"; do case "$a" in @*) cp "\${a#@}" "$UPLOAD_CAPTURE";; esac; done; exit 0;; *) exit 22;; esac\n`);
  const withUrl = parseProbeOutput(run(`${bin}:/usr/bin:/bin`, pr.defaultProbeScript("sbom").replace("__UPLOAD__", "https://bucket.s3.amazonaws.com/k?X-Amz-Signature=1"), { UPLOAD_CAPTURE: capture }));
  assert.match(withUrl.upload ?? "", /^uploaded \d+ [0-9a-f]{64}$/, "the receipt: bytes and sha256");
  assert.ok(withUrl.sbom!.sources.find((s) => s.ref === "/")!.purls.length < 6000, "the inline list is still trimmed");
  const { gunzipSync } = await import("node:zlib"); const { createHash } = await import("node:crypto");
  const blob = fs.readFileSync(capture);
  assert.equal(`uploaded ${blob.length} ${createHash("sha256").update(blob).digest("hex")}`, withUrl.upload, "the receipt describes the object");
  const whole = parseProbeOutput(gunzipSync(blob).toString("utf8"));
  assert.equal(whole.sbom!.cap, 0); assert.equal(whole.sbom!.sources.find((s) => s.ref === "/")!.purls.length, 6000, "the object holds everything");
  assert.equal(whole.sbom!.sources.find((s) => s.ref === "nginx:1.27")!.digest, "sha256:cccc");
  assert.equal(whole.upload, undefined, "the object was written before the receipt existed");
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
  assert.equal(big.inline, false, "a stub: the inline object would have been cut"); assert.equal(big.packages, undefined); assert.equal(big.kind, "software"); assert.equal(big.probe, "aws-advisor/software/5");
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
    { source: "image", ref: "app:latest", status: "ok", total: 2, purls: ["pkg:npm/express@4.19.2", "pkg:deb/debian/libc6@2.36-9?upstream=glibc&distro=debian-12"] },
    { source: "dir", ref: "/", status: "ok", total: 1, purls: ["pkg:pypi/requests@2.32.3"] } ] })!;
  assert.equal(r1.packages, 3); assert.equal(r1.sources, 2); assert.equal(r1.added, 0, "a first scan adds nothing");
  assert.deepEqual(r1.images.ok, [`ref:${iid}|app:latest`], "an image with neither digest nor id is keyed by the box and the reference");
  let on = sw.softwareOn(iid).sbom;
  assert.equal(on.scan?.available, true); assert.equal(on.scan?.packages, 3); assert.equal(on.scan?.tool, "syft 1.55.0"); assert.equal(on.scan?.images_mode, "all");
  assert.deepEqual(on.packages.map((p) => [p.ref, p.type, p.name, p.version]), [["app:latest", "deb", "libc6", "2.36-9"], ["app:latest", "npm", "express", "4.19.2"], ["/", "pypi", "requests", "2.32.3"]]);
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
    w(where, "syft", `#!/bin/sh\necho "$*" >> ${log}\nprev=""; for a in "$@"; do if [ "$prev" = "-c" ]; then cp "$a" ${cfgcopy}; fi; prev=$a; done\ncase "$*" in version) printf 'Application: syft\\nVersion: 1.55.0\\n';; *registry:nginx@sha256:*) exit 124;; *registry:*) printf 'pkg:npm/express@4.19.2\\npkg:deb/debian/libc6@2.36-9?arch=arm64&upstream=glibc&distro=debian-12\\n';; *) exit 2;; esac\n`);
  }
  w(bin, "aws", "#!/bin/sh\ncase \"$*\" in 'ecr get-login-password --region eu-west-1') printf 'TOKEN-EU\\n';; 'ecr-public get-login-password --region us-east-1') printf 'TOKEN-PUBLIC\\n';; *) exit 1;; esac\n");
  const sha = (c: string) => `sha256:${c.repeat(64)}`;
  const batch = [`123456789012.dkr.ecr.eu-west-1.amazonaws.com/api@${sha("a")}|linux/arm64`, `nginx@${sha("b")}|linux/amd64`, `public.ecr.aws/docker/library/redis@${sha("c")}`, `123456789012.dkr.ecr.eu-west-1.amazonaws.com/web@${sha("d")}|linux/arm64`].join(" ");
  const script = (images: string) => pr.defaultProbeScript("images").replace("__IMAGES__", images).replace("__IMAGE_TIMEOUT__", "90").replace("__INSTALL__", "no").replace("__UPLOAD__", "");
  const run = (PATH: string, s: string) => { const r = spawnSync("sh", [], { input: s, encoding: "utf8", env: { ...process.env, PATH, AWS_ADVISOR_SBOM_TMP: path.join(dir, "aws-advisor-sbom") } }); assert.equal(r.status, 0, r.stderr); return parseProbeOutput(r.stdout.trim().split("\n").pop() || ""); };
  const j = run(`${bin}:/usr/bin:/bin`, script(batch));
  assert.equal(j.kind, "images"); assert.equal(j.probe, "aws-advisor/images/1"); assert.equal(j.sbom?.available, true); assert.equal(j.sbom?.images_mode, null);
  const by = Object.fromEntries(j.sbom!.sources.map((s) => [s.ref, s]));
  assert.deepEqual(Object.keys(by), batch.split(" ").map((e) => e.split("|")[0]), "one record per entry, in order");
  assert.deepEqual(by[`123456789012.dkr.ecr.eu-west-1.amazonaws.com/api@${sha("a")}`], { source: "image", ref: `123456789012.dkr.ecr.eu-west-1.amazonaws.com/api@${sha("a")}`, image_id: null, digest: sha("a"), platform: "linux/arm64", status: "ok", total: 2, note: null, purls: ["pkg:npm/express@4.19.2", "pkg:deb/debian/libc6@2.36-9?arch=arm64&upstream=glibc&distro=debian-12"] }, "the digest from the entry, no docker id, the platform, distro purls kept (the image's OS packages are its own)");
  assert.equal(by[`nginx@${sha("b")}`]!.status, "timeout"); assert.equal(by[`nginx@${sha("b")}`]!.platform, "linux/amd64");
  assert.equal(by[`public.ecr.aws/docker/library/redis@${sha("c")}`]!.status, "ok"); assert.equal(by[`public.ecr.aws/docker/library/redis@${sha("c")}`]!.platform, null, "no platform in the entry: syft picks the host's");
  const args = fs.readFileSync(log, "utf8").split("\n");
  const api = args.find((l) => l.includes(`registry:123456789012.dkr.ecr.eu-west-1.amazonaws.com/api@`))!;
  assert.ok(api.includes("--platform linux/arm64") && api.includes("-o purls") && api.includes("-c ") && api.includes("/aws-advisor-sbom/syft.yaml"), `pulled from the registry for the box's platform with the config: ${api}`);
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
  // an empty batch: nothing read, a valid answer
  assert.deepEqual(run(`${bin}:/usr/bin:/bin`, script("")).sbom!.sources, []);
});

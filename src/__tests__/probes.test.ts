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
    const r = spawnSync("sh", ["-n"], { input: script.replace("{{ signals }}", "x=y"), encoding: "utf8" });
    assert.equal(r.status, 0, `${kind}: ${r.stderr}`);
    assert.equal(pr.probeDocumentName(kind), `AwsAdvisorProbe-${kind}`);
    assert.ok(pr.probeDocumentInfo(kind).create_command.includes(`/api/probes/${kind}/document`));
  }
  assert.ok(Object.keys((pr.probeDocument("docker") as any).parameters).includes("signals"));
  assert.deepEqual((pr.probeDocument("software") as any).parameters, {});
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

test("software inventory: packages are upserted with history, changes are logged, what left is marked gone, and a package can be found across the fleet", () => {
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
  assert.equal(sw.softwareOn(iid, { includeGone: true }).packages.length, 3);
  assert.equal(on.binaries.length, 0, "a probe that reports no binaries marks the old ones gone");
  assert.equal(on.images.length, 0);
  assert.equal(on.changes[0].name, "openssh-server");
  const where = sw.wherePackage("openssh");
  assert.ok(where.some((w) => w.instance_id === iid && w.version === "1:9.6p1-3ubuntu13.5" && w.instance_name === "web-1"));
  const sum = sw.softwareSummary();
  assert.ok(sum.instances >= 1 && sum.changes_7d >= 0);
  assert.equal(sw.recordSoftware(iid, "x", {}), null, "nothing to record");
  for (const t of ["instance_os", "instance_packages", "instance_binaries", "instance_images", "package_changes"]) db.prepare(`delete from ${t} where instance_id = ?`).run(iid);
  db.prepare("delete from inventory_ec2 where instance_id = ?").run(iid);
});

test("the software script reads the source package from dpkg, rpm and apk (what the advisories name) and prints it as s when it differs", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "advisor-fake-pm-"));
  const fake: Record<string, string> = {
    "dpkg-query": "#!/bin/sh\nprintf 'ii\\topenssh-server\\t1:9.6p1-3ubuntu13.4\\tamd64\\topenssh\\n'; printf 'ii\\tnginx\\t1.24.0-2ubuntu7\\tamd64\\tnginx\\n'; printf 'rc\\tgone\\t1.0\\tall\\tgone\\n'\n",
    rpm: "#!/bin/sh\nprintf 'openssh-server\\t(none):8.7p1-38.el9\\tx86_64\\topenssh-8.7p1-38.el9.src.rpm\\n'; printf 'kernel\\t(none):5.14.0-427.el9\\tx86_64\\tkernel-5.14.0-427.el9.src.rpm\\n'\n",
    apk: "#!/bin/sh\ncase \"$1\" in list) printf 'openssh-server-9.6_p1-r0 x86_64 {openssh} (BSD) [installed]\\nmusl-1.2.4_git20230717-r4 x86_64 {musl} (MIT) [installed]\\n';; *) exit 1;; esac\n",
  };
  const expected: Record<string, unknown[]> = {
    "dpkg-query": [{ n: "openssh-server", v: "1:9.6p1-3ubuntu13.4", a: "amd64", s: "openssh" }, { n: "nginx", v: "1.24.0-2ubuntu7", a: "amd64" }],
    rpm: [{ n: "openssh-server", v: "8.7p1-38.el9", a: "x86_64", s: "openssh" }, { n: "kernel", v: "5.14.0-427.el9", a: "x86_64" }],
    apk: [{ n: "openssh-server", v: "9.6_p1-r0", a: "", s: "openssh" }, { n: "musl", v: "1.2.4_git20230717-r4", a: "" }],
  };
  for (const [name, body] of Object.entries(fake)) {
    const bin = path.join(dir, name); fs.mkdirSync(bin); fs.writeFileSync(path.join(bin, name), body, { mode: 0o755 });
    const r = spawnSync("sh", [], { input: pr.defaultProbeScript("software"), encoding: "utf8", env: { ...process.env, PATH: `${bin}:${process.env.PATH}` } });
    const last = r.stdout.trim().split("\n").pop() || "{}";
    const j = JSON.parse(last);
    assert.equal(j.kind, "software"); assert.equal(j.probe, "aws-advisor/software/2");
    assert.deepEqual(j.packages, expected[name], name);
  }
});

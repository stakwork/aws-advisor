import assert from "node:assert/strict";
import { test } from "node:test";

// What the software layer says about a package for the strut match and the PROVIDES edges: the advisory ecosystem
// of a distribution's packages (spelled as OSV indexes them) and what kind of thing a package is.
const ps = await import("../package_scope.js");

test("ecosystemOf: release-qualified ecosystems the way OSV indexes them; Amazon Linux 2 and 2023 by release; null for a distribution no public feed covers", () => {
  assert.deepEqual(ps.ecosystemOf("deb", "ubuntu", "24.04"), { feed: "osv", ecosystem: "Ubuntu:24.04:LTS" });
  assert.deepEqual(ps.ecosystemOf("deb", "ubuntu", "25.04"), { feed: "osv", ecosystem: "Ubuntu:25.04" });
  assert.deepEqual(ps.ecosystemOf("deb", "debian", "12"), { feed: "osv", ecosystem: "Debian:12" });
  assert.deepEqual(ps.ecosystemOf("apk", "alpine", "3.19.1"), { feed: "osv", ecosystem: "Alpine:v3.19" });
  assert.deepEqual(ps.ecosystemOf("rpm", "rocky", "9.3"), { feed: "osv", ecosystem: "Rocky Linux:9" });
  assert.deepEqual(ps.ecosystemOf("rpm", "almalinux", "9.3"), { feed: "osv", ecosystem: "AlmaLinux:9" });
  assert.deepEqual(ps.ecosystemOf("rpm", "amzn", "2023"), { feed: "alas", ecosystem: "Amazon Linux:2023", release: "2023" });
  assert.deepEqual(ps.ecosystemOf("rpm", "amzn", "2"), { feed: "alas", ecosystem: "Amazon Linux:2", release: "2" });
  assert.equal(ps.ecosystemOf("rpm", "amzn", "2018.03"), null);
  assert.equal(ps.ecosystemOf("rpm", "rhel", "9.3"), null);
  assert.equal(ps.ecosystemOf(null, null, null), null);
});

test("packageScope: a service names the processes the apps probe sees; a library, the kernel and a tool listen as nothing", () => {
  assert.deepEqual(ps.packageScope("openssh"), { scope: "service", processes: ["sshd"] });
  assert.equal(ps.packageScope("openssh-server").scope, "service");
  assert.deepEqual(ps.packageScope("postgresql-16").processes, ["postgres", "postmaster"]);
  assert.equal(ps.packageScope("libssl3t64").scope, "library");
  assert.equal(ps.packageScope("linux-image-6.8.0-45-generic").scope, "kernel");
  assert.equal(ps.packageScope("vim").scope, "tool");
});

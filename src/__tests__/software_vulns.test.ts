import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

// The vulnerability matcher's pure parts: which feed a box belongs to, CVSS scoring, the fixed version and severity
// read from OSV records, rpm version comparison and the Amazon Linux updateinfo parser, which program a package
// provides, the verdict from reachability, and the join from installed packages to stored advisories.
process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "advisor-vulns-test-"));
process.env.TYPESAFE_API_KEY = "";

const sv = await import("../software_vulns.js");
const alas = await import("../alas_feed.js");
const sw = await import("../software_inventory.js");
const { db } = await import("../db.js");

test("ecosystemOf: release-qualified OSV ecosystems the way OSV indexes them; Amazon Linux goes to the updateinfo feed; the rest is unsupported with a reason", () => {
  assert.deepEqual(sv.ecosystemOf("deb", "ubuntu", "24.04"), { feed: "osv", ecosystem: "Ubuntu:24.04:LTS" });
  assert.deepEqual(sv.ecosystemOf("deb", "ubuntu", "25.04"), { feed: "osv", ecosystem: "Ubuntu:25.04" });
  assert.deepEqual(sv.ecosystemOf("deb", "debian", "12"), { feed: "osv", ecosystem: "Debian:12" });
  assert.deepEqual(sv.ecosystemOf("apk", "alpine", "3.19.1"), { feed: "osv", ecosystem: "Alpine:v3.19" });
  assert.deepEqual(sv.ecosystemOf("rpm", "rocky", "9.3"), { feed: "osv", ecosystem: "Rocky Linux:9" });
  assert.deepEqual(sv.ecosystemOf("rpm", "almalinux", "9.3"), { feed: "osv", ecosystem: "AlmaLinux:9" });
  assert.deepEqual(sv.ecosystemOf("rpm", "amzn", "2023"), { feed: "alas", ecosystem: "Amazon Linux:2023", release: "2023" });
  assert.deepEqual(sv.ecosystemOf("rpm", "amzn", "2"), { feed: "alas", ecosystem: "Amazon Linux:2", release: "2" });
  assert.equal(sv.ecosystemOf("rpm", "amzn", "2018.03"), null);
  assert.equal(sv.ecosystemOf("rpm", "rhel", "9.3"), null);
  assert.match(sv.unsupportedReason("rpm", "rhel", "9.3"), /not in OSV/);
  assert.match(sv.unsupportedReason(null, null, null), /no package manager/);
});

test("cvssBaseScore follows the 3.1 formula; the rating words and attack vector fold the feeds' vocabularies", () => {
  assert.equal(sv.cvssBaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8);
  assert.equal(sv.cvssBaseScore("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"), 8.1, "regreSSHion's vector");
  assert.equal(sv.cvssBaseScore("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"), 5.5);
  assert.equal(sv.cvssBaseScore("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N"), 5.4, "changed scope");
  assert.equal(sv.cvssBaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"), 0);
  assert.equal(sv.cvssBaseScore("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"), null);
  assert.equal(sv.severityOfScore(9.8), "critical"); assert.equal(sv.severityOfScore(7), "high"); assert.equal(sv.severityOfScore(4), "medium"); assert.equal(sv.severityOfScore(0.1), "low"); assert.equal(sv.severityOfScore(0), null);
  assert.equal(sv.severityOfWord("Important"), "high"); assert.equal(sv.severityOfWord("unimportant"), "low"); assert.equal(sv.severityOfWord("not yet assigned"), null); assert.equal(sv.severityOfWord("moderate"), "medium");
  assert.equal(sv.attackVectorOf("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"), "local"); assert.equal(sv.attackVectorOf(null), null);
});

const USN = { id: "USN-0000-1", summary: "openssh vulnerability", upstream: ["CVE-2024-6387"], published: "2024-07-01T09:06:31Z", modified: "2026-02-10T04:44:20Z",
  affected: [{ package: { name: "openssh", ecosystem: "Ubuntu:24.04:LTS" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "1:9.6p1-3ubuntu13.3" }] }], ecosystem_specific: { binaries: [{ binary_name: "openssh-server" }] } },
    { package: { name: "openssh", ecosystem: "Ubuntu:22.04:LTS" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "1:8.9p1-3ubuntu0.10" }] }] }] };
const CVE = { id: "CVE-2024-6387", severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" }], database_specific: { cwe_ids: ["CWE-364"] } };
const DSA = { id: "DSA-0000-1", summary: "openssl - security update", aliases: ["CVE-2024-0000"], affected: [{ package: { name: "openssl", ecosystem: "Debian:12" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "3.0.14-1~deb12u1" }] }], ecosystem_specific: { urgency: "high" } }] };

test("an OSV advisory without a score borrows the CVSS of the CVE it fixes; fixed versions are read per ecosystem and package", () => {
  assert.deepEqual(sv.fixedVersions(USN as any, "Ubuntu:24.04:LTS", "openssh"), ["1:9.6p1-3ubuntu13.3"]);
  assert.deepEqual(sv.fixedVersions(USN as any, "Ubuntu:24.04:LTS", "openssh-server"), [], "the binary is not the source");
  assert.deepEqual(sv.fixesOf(USN as any), { "Ubuntu:24.04:LTS|openssh": ["1:9.6p1-3ubuntu13.3"], "Ubuntu:22.04:LTS|openssh": ["1:8.9p1-3ubuntu0.10"] });
  assert.deepEqual(sv.severityFromRecord(USN as any), { score: null, cvss: null, severity: null, attack_vector: null });
  assert.equal(sv.severityFromRecord(DSA as any).severity, "high", "Debian's urgency word when there is no vector");
  sv.storeOsvRecord(USN as any, new Map([["CVE-2024-6387", CVE as any]]));
  const row = db.prepare("select * from vulnerabilities where id = 'USN-0000-1'").get() as any;
  assert.equal(row.score, 8.1); assert.equal(row.severity, "high"); assert.equal(row.severity_from, "CVE-2024-6387"); assert.equal(row.attack_vector, "network"); assert.equal(row.cwe, "CWE-364");
  assert.deepEqual(JSON.parse(row.cves), ["CVE-2024-6387"]);
  assert.deepEqual(JSON.parse(row.fixes)["Ubuntu:24.04:LTS|openssh"], ["1:9.6p1-3ubuntu13.3"]);
});

test("dedupeAdvisories drops the USN/DSA bundles when the per-CVE records are there, and keeps them otherwise", () => {
  assert.deepEqual(sv.dedupeAdvisories([{ id: "USN-6859-1" }, { id: "UBUNTU-CVE-2024-6387" }, { id: "UBUNTU-CVE-2024-6409" }]).map((v) => v.id), ["UBUNTU-CVE-2024-6387", "UBUNTU-CVE-2024-6409"]);
  assert.deepEqual(sv.dedupeAdvisories([{ id: "DSA-5729-1" }, { id: "DLA-3900-1" }]).map((v) => v.id), ["DSA-5729-1", "DLA-3900-1"]);
  assert.deepEqual(sv.dedupeAdvisories([{ id: "DSA-5729-1" }, { id: "DEBIAN-CVE-2024-38473" }]).map((v) => v.id), ["DEBIAN-CVE-2024-38473"]);
});

test("rpmEvrCmp orders like rpm: epochs first, numeric segments by value, tilde before everything, release after version", () => {
  assert.equal(alas.rpmEvrCmp("1.0-1", "1.0-2"), -1);
  assert.equal(alas.rpmEvrCmp("1.10-1", "1.9-1"), 1);
  assert.equal(alas.rpmEvrCmp("1:1.0-1", "2.0-1"), 1, "the epoch wins");
  assert.equal(alas.rpmEvrCmp("8.7p1-38.el9", "8.7p1-38.el9"), 0);
  assert.equal(alas.rpmEvrCmp("8.7p1-34.el9", "8.7p1-38.el9"), -1);
  assert.equal(alas.rpmEvrCmp("1.0~rc1-1", "1.0-1"), -1);
  assert.equal(alas.rpmEvrCmp("2.4.57-1.amzn2023.0.3", "2.4.58-1.amzn2023.0.1"), -1);
  assert.equal(alas.rpmEvrCmp("1.0a-1", "1.0-1"), 1, "a letter segment after the number is newer");
  assert.equal(alas.rpmEvrCmp("1.0.1", "1.0"), 1);
});

const UPDATEINFO = `<?xml version="1.0"?><updates>
<update status="final" version="1.4" author="linux-security@amazon.com" type="security" from="linux-security@amazon.com"><id>ALAS2023-2024-001</id><title>Amazon Linux 2023 - ALAS2023-2024-001: Important priority package update for openssh</title><issued date="2024-07-01 20:41:00" /><updated date="2024-07-02 23:22:00" /><severity>Important</severity><description>x</description>
<references><reference href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-6387" title="" id="CVE-2024-6387" type="cve" /></references>
<pkglist><collection short="amazon-linux-2023"><name>Amazon Linux 2023</name>
<package name="openssh-server" version="8.7p1" release="12.amzn2023.0.3" epoch="0" arch="x86_64"><filename>x</filename></package>
<package name="openssh-server-debuginfo" version="8.7p1" release="12.amzn2023.0.3" epoch="0" arch="x86_64"><filename>x</filename></package>
<package name="openssh" version="8.7p1" release="12.amzn2023.0.3" epoch="0" arch="x86_64"><filename>x</filename></package>
</collection></pkglist></update>
<update status="final" type="bugfix"><id>ALAS2023-2024-002</id><title>bugfix</title><pkglist><collection><package name="openssh" version="9.0" release="1" epoch="0" arch="x86_64" /></collection></pkglist></update>
<update status="final" type="security"><id>ALAS2023-2024-003</id><title>Amazon Linux 2023 - ALAS2023-2024-003: Medium priority package update for curl</title><issued date="2024-08-01 00:00:00" /><severity>Medium</severity><references><reference id="CVE-2024-1111" type="cve" href="x" /></references>
<pkglist><collection><package name="libcurl" version="8.5.0" release="1.amzn2023.0.2" epoch="1" arch="noarch" /></collection></pkglist></update>
</updates>`;

test("parseUpdateinfo keeps the security advisories with their CVEs, severity and fixing builds (debuginfo left out); alasMatches finds what a box is behind on", () => {
  const adv = alas.parseUpdateinfo(UPDATEINFO, "2023");
  assert.deepEqual(adv.map((a) => a.id), ["ALAS2023-2024-001", "ALAS2023-2024-003"]);
  assert.deepEqual(adv[0].cves, ["CVE-2024-6387"]); assert.equal(adv[0].severity, "Important"); assert.equal(adv[0].issued, "2024-07-01T20:41:00");
  assert.deepEqual(adv[0].packages, [{ name: "openssh-server", evr: "8.7p1-12.amzn2023.0.3", arch: "x86_64" }, { name: "openssh", evr: "8.7p1-12.amzn2023.0.3", arch: "x86_64" }]);
  assert.deepEqual(adv[1].packages, [{ name: "libcurl", evr: "1:8.5.0-1.amzn2023.0.2", arch: "noarch" }], "a non-zero epoch is kept");
  assert.equal(alas.alasSeverity("Important"), "high"); assert.equal(alas.alasSeverity("Critical"), "critical");
  const now = new Date().toISOString();
  db.transaction(() => {
    for (const a of adv) { db.prepare("insert or replace into alas_advisories(id, release, severity, title, issued, updated, cves, fetched_at) values (?, ?, ?, ?, ?, ?, ?, ?)").run(a.id, a.release, alas.alasSeverity(a.severity), a.title, a.issued, a.updated, JSON.stringify(a.cves), now); for (const p of a.packages) db.prepare("insert or ignore into alas_packages(advisory_id, name, evr, arch) values (?, ?, ?, ?)").run(a.id, p.name, p.evr, p.arch); }
  })();
  assert.deepEqual(alas.alasMatches("2023", "openssh-server", "8.7p1-10.amzn2023.0.1", "x86_64").map((m) => [m.advisory_id, m.fixed_evr, m.severity]), [["ALAS2023-2024-001", "8.7p1-12.amzn2023.0.3", "high"]]);
  assert.deepEqual(alas.alasMatches("2023", "openssh-server", "8.7p1-12.amzn2023.0.3", "x86_64"), [], "at the fixed build");
  assert.deepEqual(alas.alasMatches("2023", "openssh-server", "8.7p1-10.amzn2023.0.1", "aarch64"), [], "another architecture's build does not apply");
  assert.equal(alas.alasMatches("2023", "libcurl", "1:8.4.0-1.amzn2023.0.1", "aarch64").length, 1, "noarch applies to every architecture");
  assert.equal(alas.alasMatches("2", "openssh-server", "7.4p1-1.amzn2", "x86_64").length, 0, "another release");
});

test("packageScope and criticalityOf: the program's ports and their exposure decide the verdict; a local attack vector or a library does not depend on them", () => {
  assert.deepEqual(sv.packageScope("openssh"), { scope: "service", processes: ["sshd"] });
  assert.equal(sv.packageScope("openssh-server").scope, "service");
  assert.equal(sv.packageScope("libssl3t64").scope, "library"); assert.equal(sv.packageScope("linux-image-6.8.0-45-generic").scope, "kernel"); assert.equal(sv.packageScope("vim").scope, "tool");
  const ports = [{ proto: "tcp", port: 22, process: "sshd", exposure: "internet" }, { proto: "tcp", port: 80, process: "nginx", exposure: "closed" }, { proto: "tcp", port: 5432, process: "postgres", exposure: "local" }, { proto: "tcp", port: 6379, process: "redis-server", exposure: "group" }];
  assert.deepEqual(sv.criticalityOf("service", ["sshd"], ports, "network"), { criticality: "critical", reachable: "internet", via: ports[0] });
  assert.deepEqual(sv.criticalityOf("service", ["redis-server"], ports, null), { criticality: "exposed", reachable: "network", via: ports[3] });
  assert.deepEqual(sv.criticalityOf("service", ["nginx"], ports, "network"), { criticality: "mitigated", reachable: "none", via: ports[1] });
  assert.deepEqual(sv.criticalityOf("service", ["postgres", "postmaster"], ports, "network"), { criticality: "local_only", reachable: "local", via: ports[2] });
  assert.deepEqual(sv.criticalityOf("service", ["mysqld"], ports, "network"), { criticality: "affected", reachable: "none", via: null }, "installed but not listening");
  assert.deepEqual(sv.criticalityOf("service", ["sshd"], ports, "local"), { criticality: "local_only", reachable: "none", via: null }, "a local attack is local whatever listens");
  assert.deepEqual(sv.criticalityOf("library", [], ports, "network"), { criticality: "affected", reachable: "none", via: null });
});

test("vulnerabilityMatches joins installed packages (by source name and exact version, in the box's own ecosystem) to stored advisories, one match per source, worst first", () => {
  const at = "2026-10-01T04:10:00Z";
  sw.recordSoftware("i-0ubuntu", at, { os: { id: "ubuntu", version: "24.04", name: "Ubuntu 24.04.1 LTS" }, kernel: "6.8.0-45-generic", arch: "x86_64", package_manager: "deb",
    packages: [{ n: "openssh-server", v: "1:9.6p1-3ubuntu13.2", a: "amd64", s: "openssh" }, { n: "openssh-client", v: "1:9.6p1-3ubuntu13.2", a: "amd64", s: "openssh" }, { n: "nginx", v: "1.24.0-2ubuntu7", a: "amd64" }] });
  sw.recordSoftware("i-0debian", at, { os: { id: "debian", version: "12", name: "Debian 12" }, kernel: "6.1.0-25-amd64", arch: "x86_64", package_manager: "deb", packages: [{ n: "openssh-server", v: "1:9.6p1-3ubuntu13.2", a: "amd64", s: "openssh" }] });
  sw.recordSoftware("i-0amzn", at, { os: { id: "amzn", version: "2023", name: "Amazon Linux 2023" }, kernel: "6.1.0", arch: "x86_64", package_manager: "rpm", packages: [{ n: "openssh-server", v: "8.7p1-10.amzn2023.0.1", a: "x86_64", s: "openssh" }] });
  db.prepare("insert or replace into package_vulns(ecosystem, name, version, vuln_id, fixed_version) values (?, ?, ?, ?, ?)").run("Ubuntu:24.04:LTS", "openssh", "1:9.6p1-3ubuntu13.2", "USN-0000-1", "1:9.6p1-3ubuntu13.3");
  db.prepare("insert or replace into package_vulns(ecosystem, name, version, vuln_id, fixed_version) values (?, ?, ?, ?, ?)").run("Amazon Linux:2023", "openssh-server", "8.7p1-10.amzn2023.0.1", "ALAS2023-2024-001", "8.7p1-12.amzn2023.0.3");
  sv.storeAlasRecord({ advisory_id: "ALAS2023-2024-001", severity: "high", title: "Amazon Linux 2023 - ALAS2023-2024-001: Important priority package update for openssh", cves: ["CVE-2024-6387"], issued: "2024-07-01T20:41:00", updated: null }, new Map([["CVE-2024-6387", CVE as any]]));
  db.prepare("insert or replace into instance_ports(instance_id, proto, port, bind, scope, process, exposure, first_seen, last_seen) values ('i-0ubuntu', 'tcp', 22, '0.0.0.0', 'all', 'sshd', 'internet', ?, ?)").run(at, at);
  db.prepare("insert or replace into instance_ports(instance_id, proto, port, bind, scope, process, exposure, first_seen, last_seen) values ('i-0amzn', 'tcp', 22, '0.0.0.0', 'all', 'sshd', 'closed', ?, ?)").run(at, at);
  const m = sv.vulnerabilityMatches();
  assert.deepEqual(m.map((x) => [x.instance_id, x.vuln_id, x.criticality]), [["i-0ubuntu", "USN-0000-1", "critical"], ["i-0amzn", "ALAS2023-2024-001", "mitigated"]], "the Debian box has the same version but its ecosystem's advisories are not Ubuntu's");
  assert.deepEqual(m[0].packages.sort(), ["openssh-client", "openssh-server"], "two binaries of one source are one match");
  assert.equal(m[0].package, "openssh"); assert.equal(m[0].fixed_version, "1:9.6p1-3ubuntu13.3"); assert.equal(m[0].port, 22); assert.equal(m[0].process, "sshd"); assert.equal(m[0].score, 8.1);
  assert.equal(m[1].summary, "Important priority package update for openssh"); assert.equal(m[1].attack_vector, "network");
  assert.deepEqual(sv.vulnerabilityMatches(["i-0amzn"]).length, 1);
  const s = sv.vulnSummary(m);
  assert.equal(s.boxes_affected, 2); assert.equal(s.boxes_with_inventory, 3); assert.deepEqual(s.by_criticality, { critical: 1, mitigated: 1 }); assert.deepEqual(s.by_severity, { high: 2 });
  assert.equal(s.unsupported.length, 0);
  const q = sv.fleetQueries();
  assert.ok(q.queries.some((x) => x.eco.ecosystem === "Debian:12" && x.name === "openssh"), "the Debian box asks Debian's feed for the source package");
  assert.ok(q.queries.some((x) => x.eco.feed === "alas" && x.name === "openssh-server" && x.arch === "x86_64"), "Amazon Linux asks by binary package and architecture");
  const d = sv.vulnerabilityDetail("USN-0000-1")!;
  assert.equal(d.vuln.url, "https://osv.dev/vulnerability/USN-0000-1"); assert.equal(d.matches.length, 1);
});

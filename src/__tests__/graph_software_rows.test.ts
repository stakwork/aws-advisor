import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "advisor-graph-sbom-test-"));
process.env.TYPESAFE_API_KEY = "";
const g = await import("../graph_software.js");

test("sbomGraphRow: a purl inside an image is a CONTAINS row keyed by the package id with the image alongside; a filesystem purl is an INSTALLED_ON row; a distro purl takes the image's distribution", () => {
  const base = { instance_id: "i-1", first_seen: "2026-10-29T12:45:19Z", last_seen: "2026-10-29T12:45:19Z" };
  const deb = g.sbomGraphRow({ ...base, source: "image", ref: "nginx:1.27", purl: "pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&upstream=openssl&distro=debian-12", name: "libssl3", version: "3.0.11-1~deb12u2" })!;
  assert.equal(deb.edge, "contains");
  assert.equal(deb.row.id, "pkg:deb:libssl3:3.0.11-1~deb12u2", "the package's id, never the image's");
  assert.equal(deb.row.image_id, "image:nginx:1.27"); assert.equal(deb.row.repository, "nginx"); assert.equal(deb.row.tag, "1.27");
  assert.equal(deb.row.advisory_ecosystem, "Debian:12", "the image's distribution, from the distro qualifier");
  assert.equal(deb.row.source_name, "openssl"); assert.equal(deb.row.source_purl, "pkg:deb/debian/openssl"); assert.equal(deb.row.purl, "pkg:deb/debian/libssl3");
  assert.equal(deb.row.version_purl, "pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&upstream=openssl&distro=debian-12", "the purl as syft printed it, qualifiers included"); assert.equal(deb.row.source_kind, "syft");
  // an Amazon Linux rpm as syft prints it: the namespace and distro say amazon_linux, os-release and the public graph say amzn; the upstream is the src.rpm filename
  const al = g.sbomGraphRow({ ...base, source: "image", ref: "eks-node-monitoring-agent:v1.4.0", purl: "pkg:rpm/amazon_linux/libgcrypt@1.10.2-1.amzn2023.0.2?arch=x86_64&distro=amazon_linux-2023&upstream=libgcrypt-1.10.2-1.amzn2023.0.2.src.rpm", name: "libgcrypt", version: "1.10.2-1.amzn2023.0.2" })!;
  assert.equal(al.row.purl, "pkg:rpm/amzn/libgcrypt", "the purl the rpm collector gives the same package, and the one ALAS ranges are filed under");
  assert.equal(al.row.source_purl, "pkg:rpm/amzn/libgcrypt"); assert.equal(al.row.source_name, "libgcrypt", "the source package, not the src.rpm filename");
  assert.equal(al.row.advisory_ecosystem, "Amazon Linux:2023", "the release tag, from the distro qualifier");
  assert.equal(al.row.id, "pkg:rpm:libgcrypt:1.10.2-1.amzn2023.0.2");
  assert.ok((al.row.cpes as string[]).every((c) => !c.includes(".src.rpm")), "no src.rpm filename leaks into the CPE candidates");
  assert.equal(g.sourcePackage("python3-libs-3.9.16-1.amzn2023.0.10.src.rpm"), "python3-libs", "a dashed source name keeps its dashes");
  assert.equal(g.sourcePackage("openssl@3.0.11-1~deb12u2"), "openssl"); assert.equal(g.sourcePackage("openssl"), "openssl"); assert.equal(g.sourcePackage(undefined), null);
  const npm = g.sbomGraphRow({ ...base, source: "dir", ref: "/", purl: "pkg:npm/%40aws-sdk/core@3.1.0", name: "@aws-sdk/core", version: "3.1.0" })!;
  assert.equal(npm.edge, "installed_on");
  assert.equal(npm.row.id, "pkg:npm:@aws-sdk/core:3.1.0"); assert.equal(npm.row.ecosystem, "npm"); assert.equal(npm.row.advisory_ecosystem, null);
  assert.equal(npm.row.purl, "pkg:npm/%40aws-sdk/core", "the scope survives, encoded as the purl spec prints it"); assert.equal(npm.row.source_purl, "pkg:npm/%40aws-sdk/core");
  assert.equal(deb.row.platform, null, "no platform known");
  const arm = g.sbomGraphRow({ ...base, source: "image", ref: "nginx:1.27", digest: "nginx@sha256:" + "c".repeat(64), image_id: "sha256:" + "b".repeat(64), platform: "linux/arm64", purl: "pkg:deb/debian/libssl3@3.0.11-1~deb12u2", name: "libssl3", version: "3.0.11-1~deb12u2" })!;
  assert.equal(arm.row.image_id, "image:nginx@sha256:" + "c".repeat(64), "the image node is the repository at its digest, whatever the platform (RUNS_IMAGE and BUILT_FROM reach the same node)");
  assert.equal(arm.row.platform, "linux/arm64", "the edge says which platform the contents were read on"); assert.equal(arm.row.digest, "sha256:" + "c".repeat(64)); assert.equal(arm.row.docker_image_id, "sha256:" + "b".repeat(64));
  const go = g.sbomGraphRow({ ...base, source: "image", ref: "app:1", purl: "pkg:golang/github.com/andybalholm/brotli@v1.0.5", name: "github.com/andybalholm/brotli", version: "v1.0.5" })!;
  assert.equal(go.row.purl, "pkg:golang/github.com/andybalholm/brotli", "a module path keeps its slashes"); assert.equal(go.row.id, "pkg:golang:github.com/andybalholm/brotli:v1.0.5");
  const mvn = g.sbomGraphRow({ ...base, source: "image", ref: "app:1", purl: "pkg:maven/org.apache.commons/commons-lang3@3.12.0?type=jar", name: "org.apache.commons:commons-lang3", version: "3.12.0" })!;
  assert.equal(mvn.row.purl, "pkg:maven/org.apache.commons/commons-lang3", "group and artifact, no qualifiers");
  const py = g.sbomGraphRow({ ...base, source: "dir", ref: "/", purl: "pkg:pypi/requests@2.31.0", name: "requests", version: "2.31.0" })!;
  assert.equal(py.row.purl, "pkg:pypi/requests");
  // syft's binary cataloger and the software probe's version flag read the same program: one node, the probe's binary ecosystem
  const node = g.sbomGraphRow({ ...base, source: "dir", ref: "/", purl: "pkg:generic/node@20.18.0", name: "node", version: "20.18.0" })!;
  assert.equal(node.row.id, "pkg:binary:node:20.18.0", "the id the probe's reading of the same node gets"); assert.equal(node.row.ecosystem, "binary"); assert.equal(node.row.purl, "pkg:generic/node");
  assert.equal(node.row.id, g.packageId("binary", "node", "20.18.0")); assert.equal(g.sbomEcosystem("npm"), "npm");
  assert.equal(g.sbomGraphRow({ ...base, source: "dir", ref: "/", purl: "nonsense", name: "x", version: null }), null);
  // a running executable (sbom 1.7) inside a container whose node and image are known (2026-11-03): a file of the image, so CONTAINS from the image node the
  // container is BUILT_FROM, and EXECUTES from the container; the same node syft and the software probe give that program
  const img = { image_id: "image:ghcr.io/stakwork/strut-browser@sha256:" + "1".repeat(64), image: "ghcr.io/stakwork/strut-browser:latest", repository: "ghcr.io/stakwork/strut-browser", tag: "latest", digest: "sha256:" + "1".repeat(64), docker_image_id: "sha256:" + "2".repeat(64) };
  const ctx = { container_image: img, container_node: "container:i-1:browser.sphinx", sha256: "cd".repeat(32), size: 4242 };
  const cnode = g.sbomGraphRow({ ...base, source: "proc", ref: "container:abcdefabcdef:/usr/local/bin/node", purl: "pkg:generic/node@20.18.0", name: "node", version: "20.18.0", ...ctx })!;
  assert.equal(cnode.edge, "contains"); assert.equal(cnode.row.id, "pkg:binary:node:20.18.0"); assert.equal(cnode.row.image_id, img.image_id); assert.equal(cnode.row.image, img.image); assert.equal(cnode.row.digest, img.digest);
  assert.equal(cnode.row.edge_source_kind, "proc"); assert.equal(cnode.row.observed, "running"); assert.equal(cnode.row.path, "/usr/local/bin/node"); assert.equal(cnode.row.container, "abcdefabcdef"); assert.equal(cnode.row.platform, null);
  assert.deepEqual(cnode.executes, { container_node: "container:i-1:browser.sphinx", id: "pkg:binary:node:20.18.0", path: "/usr/local/bin/node", sha256: "cd".repeat(32), size: 4242, first_seen: base.first_seen, last_seen: base.last_seen });
  // the same executable on a bind mount: not the image's; INSTALLED_ON the compute with the container id, EXECUTES from the container all the same
  const mounted = g.sbomGraphRow({ ...base, source: "proc", ref: "container:abcdefabcdef:/vol/bin/node", purl: "pkg:generic/node@20.18.0", name: "node", version: "20.18.0", ...ctx, on_mount: true })!;
  assert.equal(mounted.edge, "installed_on"); assert.equal(mounted.row.container, "abcdefabcdef"); assert.equal(mounted.row.path, "/vol/bin/node"); assert.equal(mounted.executes?.container_node, "container:i-1:browser.sphinx");
  // a container the docker probe has not recorded (no node, no image): the compute edge with the container id, as before 2026-11-03, and no EXECUTES
  const unknownCt = g.sbomGraphRow({ ...base, source: "proc", ref: "container:abcdefabcdef:/usr/local/bin/node", purl: "pkg:generic/node@20.18.0", name: "node", version: "20.18.0" })!;
  assert.equal(unknownCt.edge, "installed_on"); assert.equal(unknownCt.row.container, "abcdefabcdef"); assert.equal(unknownCt.executes, undefined);
  // a known container whose image the box has no row for yet: EXECUTES from the container, the compute edge until the image is known
  const noImage = g.sbomGraphRow({ ...base, source: "proc", ref: "container:abcdefabcdef:/usr/local/bin/node", purl: "pkg:generic/node@20.18.0", name: "node", version: "20.18.0", container_node: "container:i-1:x", container_image: null })!;
  assert.equal(noImage.edge, "installed_on"); assert.equal(noImage.executes?.container_node, "container:i-1:x");
  const hnode = g.sbomGraphRow({ ...base, source: "proc", ref: "host:/usr/sbin/sshd", purl: "pkg:generic/openssh@9.2p1", name: "openssh", version: "9.2p1", ...ctx })!;
  assert.equal(hnode.edge, "installed_on"); assert.equal(hnode.row.path, "/usr/sbin/sshd"); assert.equal(hnode.row.container, null, "a host process"); assert.equal(hnode.executes, undefined, "no container runs it");
  assert.equal(npm.row.container, null, "the filesystem: no container, no path");
  assert.equal(arm.row.edge_source_kind, "image_scan", "the scanner's reading of an image is told from a process's by the edge's source_kind"); assert.equal(arm.row.observed, null);
  // an executable nothing identified: a binary component at version unknown, classified false, hash and size on the edge
  const un = g.unclassifiedComponentRow({ instance_id: "i-1", ref: "container:abcdefabcdef:/ms-playwright/chromium-1243/chrome-linux64/chrome_crashpad_handler", container: "abcdefabcdef", sha256: "ab".repeat(32), size: 1234567, collected_at: "2026-11-03T12:00:00Z" })!;
  assert.deepEqual([un.id, un.name, un.version, un.ecosystem, un.source_kind, un.classified, un.purl, un.sort_key, un.cpe, un.cpes, un.path, un.container, un.sha256, un.size, un.scope], ["pkg:binary:chrome_crashpad_handler:unknown", "chrome_crashpad_handler", "unknown", "binary", "unclassified", false, "pkg:generic/chrome-crashpad-handler", null, null, [], "/ms-playwright/chromium-1243/chrome-linux64/chrome_crashpad_handler", "abcdefabcdef", "ab".repeat(32), 1234567, "tool"]);
  assert.equal(g.unclassifiedComponentRow({ instance_id: "i-1", ref: "host:/usr/sbin/sshd", collected_at: "2026-11-03T12:00:00Z" })!.container, null);
  assert.equal(g.unclassifiedComponentRow({ instance_id: "i-1", ref: "nonsense", collected_at: "2026-11-03T12:00:00Z" }), null);
  // placed like an identified executable: on the container's image and the container when both are known, on the compute otherwise
  const unG = g.unclassifiedGraphRow({ instance_id: "i-1", ref: "container:abcdefabcdef:/ms-playwright/chromium-1243/chrome-linux64/chrome", collected_at: "2026-11-03T12:00:00Z", ...ctx, sha256: "ab".repeat(32), size: 99 })!;
  assert.equal(unG.edge, "contains"); assert.equal(unG.row.id, "pkg:binary:chrome:unknown"); assert.equal(unG.row.classified, false); assert.equal(unG.row.image_id, img.image_id); assert.equal(unG.row.edge_source_kind, "proc"); assert.equal(unG.row.sha256, "ab".repeat(32)); assert.equal(unG.row.size, 99);
  assert.deepEqual(unG.executes, { container_node: "container:i-1:browser.sphinx", id: "pkg:binary:chrome:unknown", path: "/ms-playwright/chromium-1243/chrome-linux64/chrome", sha256: "ab".repeat(32), size: 99, first_seen: "2026-11-03T12:00:00Z", last_seen: "2026-11-03T12:00:00Z" });
  const unH = g.unclassifiedGraphRow({ instance_id: "i-1", ref: "host:/opt/thing/bin/thing", sha256: "ab".repeat(32), size: 1, collected_at: "2026-11-03T12:00:00Z" })!;
  assert.equal(unH.edge, "installed_on"); assert.equal(unH.row.path, "/opt/thing/bin/thing"); assert.equal(unH.row.container, null); assert.equal(unH.row.classified, false); assert.equal(unH.executes, undefined);
  assert.equal(g.unclassifiedGraphRow({ instance_id: "i-1", ref: "nonsense", collected_at: "2026-11-03T12:00:00Z" }), null);
  // the CPEs (src/sec/cpe.ts): what syft assigned when the row has them (stored as a JSON list, best first), the rule's candidates when not
  const withCpes = g.sbomGraphRow({ ...base, source: "image", ref: "nginx:1.27", purl: "pkg:deb/debian/libssl3@3.0.11-1~deb12u2?upstream=openssl&distro=debian-12", name: "libssl3", version: "3.0.11-1~deb12u2", cpes: JSON.stringify(["cpe:2.3:a:openssl:openssl:3.0.11-1~deb12u2:*:*:*:*:*:*:*", "cpe:2.3:a:libssl3:libssl3:3.0.11-1~deb12u2:*:*:*:*:*:*:*", "junk"]) })!;
  assert.equal(withCpes.row.cpe, "cpe:2.3:a:openssl:openssl:3.0.11-1~deb12u2:*:*:*:*:*:*:*", "the first CPE the probe listed is the one the node is known by");
  assert.deepEqual(withCpes.row.cpes, ["cpe:2.3:a:openssl:openssl:3.0.11-1~deb12u2:*:*:*:*:*:*:*", "cpe:2.3:a:libssl3:libssl3:3.0.11-1~deb12u2:*:*:*:*:*:*:*"], "every candidate, in the probe's order, anything that is not a CPE dropped");
  assert.equal(deb.row.cpe, "cpe:2.3:a:libssl3:libssl3:3.0.11-1\\~deb12u2:*:*:*:*:*:*:*", "no CPEs stored (an older probe): the syft-style guesses, the name first, the version bound as the formatted string binds it (~ escaped, as syft prints +)");
  assert.deepEqual(deb.row.cpes, ["cpe:2.3:a:libssl3:libssl3:3.0.11-1\\~deb12u2:*:*:*:*:*:*:*", "cpe:2.3:a:openssl:libssl3:3.0.11-1\\~deb12u2:*:*:*:*:*:*:*", "cpe:2.3:a:openssl:openssl:3.0.11-1\\~deb12u2:*:*:*:*:*:*:*"], "then the source package as vendor");
  assert.equal(node.row.cpe, "cpe:2.3:a:nodejs:node.js:20.18.0:*:*:*:*:*:*:*", "syft's generic purl for a program the probe also names takes NVD's name for it, as syft's classifier would");
  assert.equal(py.row.cpe, "cpe:2.3:a:requests:requests:2.31.0:*:*:*:*:*:*:*", "a library nobody named: its name as vendor and product");
  assert.equal(g.sbomGraphRow({ ...base, source: "dir", ref: "/", purl: "pkg:npm/%40aws-sdk/core@3.1.0", name: "@aws-sdk/core", version: "3.1.0", cpes: ["cpe:2.3:a:amazon:aws-sdk:3.1.0:*:*:*:*:*:*:*"] })!.row.cpe, "cpe:2.3:a:amazon:aws-sdk:3.1.0:*:*:*:*:*:*:*", "a list is taken as it is");
});

test("kernelComponent: the running kernel is versioned by its upstream x.y.z (shared across boxes, sortable against the kernel CNA's ranges); without it the node is named by uname -r and carries no sort_key", () => {
  const deb = g.kernelComponent({ instance_id: "i-1", kernel: "6.1.0-54-cloud-amd64", kernel_upstream: "6.1.176", arch: "x86_64", collected_at: "2026-11-02T04:10:00Z" });
  assert.equal(deb.cpe, "cpe:2.3:o:linux:linux_kernel:6.1.176:*:*:*:*:*:*:*", "the kernel's CPE at its upstream version");
  assert.equal(deb.id, "pkg:kernel:linux:6.1.176"); assert.equal(deb.version, "6.1.176"); assert.equal(deb.purl, "pkg:generic/linux"); assert.equal(deb.scope, "kernel"); assert.equal(deb.source_kind, "uname");
  assert.equal(deb.sort_key, "00000006.00000001.00000176.00000000.00000000=", "6.1.176 < 6.1.190: inside a range fixed in 6.1.190, as it should be");
  const amzn = g.kernelComponent({ instance_id: "i-2", kernel: "6.1.176-200.100.amzn2023.x86_64", kernel_upstream: "6.1.176", arch: "x86_64", collected_at: "2026-11-02T04:10:00Z" });
  assert.equal(amzn.id, deb.id, "one node per upstream version, whatever each distribution calls its build");
  const unknown = g.kernelComponent({ instance_id: "i-3", kernel: "6.8.0-45-generic", kernel_upstream: null, arch: "x86_64", collected_at: "2026-11-02T04:10:00Z" });
  assert.equal(unknown.id, "pkg:kernel:linux:6.8.0-45-generic"); assert.equal(unknown.version, "6.8.0-45-generic");
  assert.equal(unknown.sort_key, null, "an ABI name read as 6.8.0 would sit below every fix in the series forever: nothing to compare instead");
});

test("dormantKernelImage: an installed kernel image that is not the booted one gets no INSTALLED_ON edge; the booted one, headers, firmware, and every image on a box that has not said what it booted keep theirs", () => {
  const deb = { kernel: "6.1.0-54-cloud-amd64", kernel_package: "linux-image-6.1.0-54-cloud-amd64" };
  assert.equal(g.dormantKernelImage({ ecosystem: "deb", name: "linux-image-6.1.0-23-cloud-amd64", version: "6.1.99-1" }, deb), true, "the GRUB fallback apt kept");
  assert.equal(g.dormantKernelImage({ ecosystem: "deb", name: "linux-image-6.1.0-54-cloud-amd64", version: "6.1.190-1" }, deb), false, "the booted one");
  assert.equal(g.dormantKernelImage({ ecosystem: "deb", name: "linux-image-cloud-amd64", version: "6.1.190-1" }, deb), true, "a metapackage carries no code");
  for (const name of ["linux-headers-6.1.0-23-cloud-amd64", "linux-libc-dev", "linux-base", "firmware-linux-free", "linux-kbuild-6.1"]) assert.equal(g.dormantKernelImage({ ecosystem: "deb", name, version: "1" }, deb), false, `${name} is not an image`);
  assert.equal(g.dormantKernelImage({ ecosystem: "deb", name: "linux-image-6.1.0-23-cloud-amd64", version: "6.1.99-1" }, { kernel: "6.1.0-54-cloud-amd64", kernel_package: null }), false, "the box has not said what it booted: every image stays");
  assert.equal(g.dormantKernelImage({ ecosystem: "deb", name: "linux-image-6.1.0-23-cloud-amd64", version: "6.1.99-1" }, undefined), false, "never probed");
  // rpm keeps one inventory row per name, so the version tells the booted kernel apart
  const rpm = { kernel: "6.1.134-150.224.amzn2023.x86_64", kernel_package: "kernel" };
  assert.equal(g.dormantKernelImage({ ecosystem: "rpm", name: "kernel", version: "6.1.134-150.224.amzn2023", arch: "x86_64" }, rpm), false, "the booted kernel row, by name");
  assert.equal(g.dormantKernelImage({ ecosystem: "rpm", name: "kernel-core", version: "6.1.141-155.222.amzn2023", arch: "x86_64" }, rpm), true, "a newer kernel installed, not yet booted");
  assert.equal(g.dormantKernelImage({ ecosystem: "rpm", name: "kernel-core", version: "6.1.134-150.224.amzn2023", arch: "x86_64" }, rpm), false, "the running kernel's own core package");
  assert.equal(g.dormantKernelImage({ ecosystem: "rpm", name: "kernel-devel", version: "6.1.141-155.222.amzn2023", arch: "x86_64" }, rpm), false, "headers are not an image");
  // apk: the flavor package
  const apk = { kernel: "6.6.30-0-virt", kernel_package: "linux-virt" };
  assert.equal(g.dormantKernelImage({ ecosystem: "apk", name: "linux-lts", version: "6.6.30-r0" }, apk), true);
  assert.equal(g.dormantKernelImage({ ecosystem: "apk", name: "linux-virt", version: "6.6.30-r0" }, apk), false);
  assert.equal(g.dormantKernelImage({ ecosystem: "apk", name: "linux-firmware-none", version: "1" }, apk), false);
});

test("onMount: an executable under a bind mount or a volume destination is not the image's; the root destination claims nothing; junk is false", () => {
  const mounts = JSON.stringify([{ type: "bind", name: null, source: "/home/admin/vol", destination: "/vol", rw: true }, { type: "volume", name: "data", source: "/var/lib/docker/volumes/data/_data", destination: "/data/", rw: true }]);
  assert.equal(g.onMount("/vol/app/bin/x", mounts), true);
  assert.equal(g.onMount("/vol", mounts), true, "the mount point itself");
  assert.equal(g.onMount("/volume/x", mounts), false, "a sibling path that merely starts with the same letters");
  assert.equal(g.onMount("/data/bin/x", mounts), true, "a trailing slash on the destination is fine");
  assert.equal(g.onMount("/ms-playwright/chromium-1243/chrome-linux64/chrome", mounts), false);
  assert.equal(g.onMount("/usr/bin/x", JSON.stringify([{ type: "bind", destination: "/", rw: true }])), false, "a bind of / would claim everything: ignored");
  assert.equal(g.onMount("/usr/bin/x", "not json"), false); assert.equal(g.onMount("/usr/bin/x", null), false); assert.equal(g.onMount(null, mounts), false);
  assert.equal(g.onMount("/vol/x", [{ destination: "/vol" }]), true, "a parsed list is taken as it is");
});

test("imageNodeResolver: a box's image reference resolves to the digest-keyed node its instance_images row gives (what RUNS_IMAGE, CONTAINS and BUILT_FROM must share), by reference first, then by docker image id; the bare reference when the box has no row", () => {
  const rows = [{ instance_id: "i-1", image: "ghcr.io/stakwork/strut-browser:latest", image_id: "sha256:" + "2".repeat(64), digest: "ghcr.io/stakwork/strut-browser@sha256:" + "1".repeat(64) }, { instance_id: "i-2", image: "ghcr.io/stakwork/strut-browser:latest", image_id: null, digest: null }];
  const of = g.imageNodeResolver(rows);
  const a = of("i-1", "ghcr.io/stakwork/strut-browser:latest")!;
  assert.equal(a.image_id, "image:ghcr.io/stakwork/strut-browser@sha256:" + "1".repeat(64)); assert.equal(a.repository, "ghcr.io/stakwork/strut-browser"); assert.equal(a.tag, "latest"); assert.equal(a.digest, "sha256:" + "1".repeat(64)); assert.equal(a.docker_image_id, "sha256:" + "2".repeat(64));
  assert.equal(of("i-1", null, "sha256:" + "2".repeat(64))!.image_id, a.image_id, "by docker image id when the reference is not known");
  assert.equal(of("i-2", "ghcr.io/stakwork/strut-browser:latest")!.image_id, "image:ghcr.io/stakwork/strut-browser:latest", "no digest recorded on that box: the bare reference, as imageNodeId gives it");
  assert.equal(of("i-3", "ghcr.io/stakwork/strut-browser:latest")!.image_id, "image:ghcr.io/stakwork/strut-browser:latest", "a box with no row at all still names the image");
  assert.equal(of("i-3", "ghcr.io/stakwork/strut-browser:latest", "sha256:" + "3".repeat(64))!.image_id, "image:sha256:" + "3".repeat(64), "a docker image id in hand outranks the reference, as imageNodeId has it");
  assert.equal(of("i-3", null, "sha256:" + "9".repeat(64)), null, "nothing to name it by");
});

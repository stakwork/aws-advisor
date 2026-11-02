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
});

test("kernelComponent: the running kernel is versioned by its upstream x.y.z (shared across boxes, sortable against the kernel CNA's ranges); without it the node is named by uname -r and carries no sort_key", () => {
  const deb = g.kernelComponent({ instance_id: "i-1", kernel: "6.1.0-54-cloud-amd64", kernel_upstream: "6.1.176", arch: "x86_64", collected_at: "2026-11-02T04:10:00Z" });
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

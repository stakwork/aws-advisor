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
  assert.equal(npm.row.id, "pkg:npm:@aws-sdk/core:3.1.0"); assert.equal(npm.row.ecosystem, "npm"); assert.equal(npm.row.advisory_ecosystem, null); assert.equal(npm.row.gone, false);
  assert.equal(g.sbomGraphRow({ ...base, source: "dir", ref: "/", purl: "nonsense", name: "x", version: null }), null);
});

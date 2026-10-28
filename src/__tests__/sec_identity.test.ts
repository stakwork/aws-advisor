import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { componentIdentity, distroOf } from "../sec/identity.js";
import { identify, identifyCpe } from "../sec/purl.js";
import { inRange, sortKey } from "../sec/version.js";

// The identity an installed thing carries into the graph for the public vulnerability graph to match by walking:
// the purl rules and the version sort key — vendored from the vuln-graph workspace and pinned here, since a range's
// keys there and a sort_key here are compared as plain strings.

test("sortKey: the pinned examples both graphs rely on", () => {
  assert.equal(sortKey("1.0.4"), "00000001.00000000.00000004.00000000.00000000=");
  assert.equal(sortKey("1.0.4-rc1"), "00000001.00000000.00000004.00000000.00000000-rc.00000001");
  assert.equal(sortKey("1.1.1k"), "00000001.00000001.00000001.00000000.00000000=k");
  assert.equal(sortKey("v22.12.0"), "00000022.00000012.00000000.00000000.00000000=");
  const order = ["1.0.4-beta.2", "1.0.4-rc1", "1.0.4", "1.0.4.1", "1.0.10", "1.1.0", "1.1.1", "1.1.1k", "1.1.2"];
  assert.deepEqual([...order].sort((a, b) => (sortKey(a) < sortKey(b) ? -1 : 1)), order);
  // brotli 1.1.0 is inside [1.1.0, 1.1.1); 1.1.1 is not: the CVE-2026-111497 case
  assert.equal(inRange("1.1.0", sortKey("1.1.0"), sortKey("1.1.1")), true);
  assert.equal(inRange("1.1.1", sortKey("1.1.0"), sortKey("1.1.1")), false);
});

test("purl rules are rules only: vendor:product keeps the vendor, a repo keeps its owner, a bare name is generic", () => {
  assert.equal(identify({ vendor: "Google", product: "Brotli" }).purl, "pkg:generic/google/brotli");
  assert.equal(identify({ packageName: "github.com/andybalholm/brotli" }).purl, "pkg:github/andybalholm/brotli");
  assert.equal(identify({ product: "brotli" }).purl, "pkg:generic/brotli");
  assert.equal(identifyCpe("cpe:2.3:a:nodejs:node.js:22.12.0:*:*:*:-:*:*:*")?.purl, "pkg:generic/nodejs/node.js");
});

test("componentIdentity: what each kind of installed row becomes", () => {
  const deb = componentIdentity({ ecosystem: "deb", name: "libbrotli1", version: "1.1.0-2build3", source: "brotli", os_id: "ubuntu" });
  assert.equal(deb.purl, "pkg:deb/ubuntu/libbrotli1");
  assert.equal(deb.source_purl, "pkg:deb/ubuntu/brotli", "the source package the distribution advisories name");
  assert.ok(deb.sort_key.startsWith("00000001.00000001.00000000"));
  const noSource = componentIdentity({ ecosystem: "deb", name: "nginx", version: "1.24.0-2", os_id: "debian" });
  assert.equal(noSource.source_purl, noSource.purl);
  assert.equal(componentIdentity({ ecosystem: "rpm", name: "openssl", version: "1:3.0.8-1.amzn2023", source: "openssl", os_id: "amzn" }).purl, "pkg:rpm/amzn/openssl");
  assert.equal(componentIdentity({ ecosystem: "apk", name: "zlib", version: "1.3.1-r1", os_id: "alpine" }).purl, "pkg:apk/alpine/zlib");
  assert.equal(componentIdentity({ ecosystem: "binary", name: "node", version: "v22.12.0" }).purl, "pkg:generic/node");
  assert.equal(componentIdentity({ ecosystem: "bundled", name: "brotli", version: "1.1.0" }).purl, "pkg:generic/brotli", "what process.versions calls it; the public graph's SAME_AS joins it to NVD's google/brotli");
  assert.equal(componentIdentity({ ecosystem: "kernel", name: "linux", version: "6.8.0-45-generic" }).purl, "pkg:generic/linux");
  assert.equal(componentIdentity({ ecosystem: "os", name: "Ubuntu 24.04.1 LTS", version: "24.04", source: "ubuntu" }).purl, "pkg:generic/ubuntu");
  assert.equal(componentIdentity({ ecosystem: "npm", name: "next", version: "14.2.3" }).purl, "pkg:npm/next");
  assert.equal(distroOf("deb", null), "debian");
  assert.equal(distroOf("rpm", "Rocky"), "rocky");
});

test("the vendored modules match the vuln-graph workspace when it is checked out beside this repo", (t) => {
  const workspace = path.resolve(process.cwd(), "..", "vuln-graph", "steps", "custom", "sec");
  if (!fs.existsSync(workspace)) { t.skip("no ../vuln-graph checkout"); return; }
  const body = (file: string) => fs.readFileSync(file, "utf-8").replace(/^(\/\/[^\n]*\n)+\n?/, "");
  for (const [ours, theirs] of [["version", "_version"], ["purl", "_purl"]] as const) {
    assert.equal(body(path.resolve(process.cwd(), "src", "sec", `${ours}.ts`)), body(path.join(workspace, `${theirs}.ts`)), `src/sec/${ours}.ts differs from the workspace's ${theirs}.ts — copy it over`);
  }
});

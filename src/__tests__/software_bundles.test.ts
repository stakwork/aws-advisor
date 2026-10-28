import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

// Probe software/4 adds what a runtime bundles (Node's process.versions) and the dependencies of the packages that own
// the probed programs. The inventory keeps one row per (runtime, library) and per (package, installed dependency),
// deletes what a later probe no longer reports, and answers it all from softwareOn. No real identifiers: RFC 5737-style
// instance ids, example versions.
process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "advisor-bundles-test-"));
process.env.TYPESAFE_API_KEY = "";

const sw = await import("../software_inventory.js");
const { db } = await import("../db.js");

const BOX = "i-0000000000000bund";
const probe = (collectedAt: string, overrides: Partial<Parameters<typeof sw.recordSoftware>[2]> = {}) => sw.recordSoftware(BOX, collectedAt, {
  os: { id: "debian", version: "13", name: "Debian GNU/Linux 13 (trixie)" }, kernel: "6.12.0-1-amd64", arch: "x86_64", package_manager: "deb",
  packages: [{ n: "nodejs", v: "22.12.0-1nodesource1" }, { n: "libbrotli1", v: "1.1.0-2+deb13u1", s: "brotli" }, { n: "libc6", v: "2.41-1", s: "glibc" }, { n: "nginx", v: "1.26.3-1" }],
  binaries: [{ name: "node", version: "v22.12.0", path: "/usr/bin/node" }, { name: "nginx", version: "nginx version: nginx/1.26.3" }],
  bundles: [{ name: "node", path: "/usr/bin/node", versions: { node: "22.12.0", brotli: "1.1.0", openssl: "3.0.15+quic", zlib: "1.3.0.1-motley", uv: "1.49.2", modules: "127", napi: "10", unicode: "16.0", cldr: "46.0", tz: "2024b" } }],
  depends: [{ n: "nodejs", d: "libc6 (>= 2.34), libbrotli1 (>= 1.1.0), libnode115 | libnode-dev, python3:any" }, { n: "nginx", d: "libc6 (>= 2.34), libssl3t64 (>= 3.0.0)" }],
  ...overrides,
});

test("parseDepends: every alternative, no constraints, no architecture qualifiers", () => {
  assert.deepEqual(sw.parseDepends("libc6 (>= 2.34), libbrotli1 (>= 1.1.0), libnode115 | libnode-dev, python3:any"), ["libc6", "libbrotli1", "libnode115", "libnode-dev", "python3"]);
  assert.deepEqual(sw.parseDepends(""), []);
  assert.deepEqual(sw.parseDepends("Weird Thing, ok-pkg"), ["ok-pkg"]);
});

test("bundles: the runtime's libraries become rows under the binary's own version; the runtime and its ABI numbers are not libraries", () => {
  const r = probe("2026-10-28T10:00:00Z")!;
  assert.equal(r.bundles, 4, "brotli, openssl, zlib, uv");
  const rows = sw.softwareOn(BOX).bundles;
  assert.deepEqual(rows.map((b) => [b.parent, b.parent_version, b.name, b.version]), [
    ["node", "v22.12.0", "brotli", "1.1.0"], ["node", "v22.12.0", "openssl", "3.0.15+quic"], ["node", "v22.12.0", "uv", "1.49.2"], ["node", "v22.12.0", "zlib", "1.3.0.1-motley"],
  ]);
});

test("depends: only dependencies that are installed on the box, never a package on itself", () => {
  probe("2026-10-28T10:00:00Z");
  const rows = sw.softwareOn(BOX).depends;
  assert.deepEqual(rows.map((d) => [d.name, d.dep]), [["nginx", "libc6"], ["nodejs", "libbrotli1"], ["nodejs", "libc6"]], "libnode115, libnode-dev, python3 and libssl3t64 are not installed");
});

test("a later probe replaces: a library gone from the runtime and a dependency gone from the field disappear; the rest keeps first_seen", () => {
  probe("2026-10-28T10:00:00Z");
  const r = probe("2026-10-28T11:00:00Z", {
    binaries: [{ name: "node", version: "v22.13.0", path: "/usr/bin/node" }],
    bundles: [{ name: "node", path: "/usr/bin/node", versions: { node: "22.13.0", brotli: "1.1.1", openssl: "3.0.15+quic" } }],
    depends: [{ n: "nodejs", d: "libc6 (>= 2.34)" }],
  })!;
  assert.equal(r.bundles, 2);
  const after = sw.softwareOn(BOX);
  assert.deepEqual(after.bundles.map((b) => [b.parent_version, b.name, b.version]), [["v22.13.0", "brotli", "1.1.1"], ["v22.13.0", "openssl", "3.0.15+quic"]]);
  assert.deepEqual(after.depends.map((d) => [d.name, d.dep]), [["nodejs", "libc6"]]);
  assert.equal(after.depends[0]!.first_seen, "2026-10-28T10:00:00Z", "an unchanged dependency keeps when it was first seen");
});

test("several Nodes on one box (nvm): each install is its own binary row and bundles under its own version", () => {
  probe("2026-10-28T10:00:00Z", {
    binaries: [{ name: "node", version: "v22.12.0", path: "/usr/bin/node" }, { name: "node", version: "v20.18.0", path: "/home/example/.nvm/versions/node/v20.18.0/bin/node" }, { name: "node", version: "v18.20.4", path: "/home/example/.nvm/versions/node/v18.20.4/bin/node" }],
    bundles: [
      { name: "node", path: "/usr/bin/node", versions: { node: "22.12.0", brotli: "1.1.0" } },
      { name: "node", path: "/home/example/.nvm/versions/node/v20.18.0/bin/node", versions: { node: "20.18.0", brotli: "1.1.0" } },
      { name: "node", path: "/home/example/.nvm/versions/node/v18.20.4/bin/node", versions: { node: "18.20.4", brotli: "1.0.9" } },
    ],
    depends: [],
  });
  const sw2 = sw.softwareOn(BOX);
  assert.deepEqual(sw2.binaries.filter((b) => b.name === "node").map((b) => b.version).sort(), ["v18.20.4", "v20.18.0", "v22.12.0"]);
  assert.deepEqual(sw2.bundles.map((b) => [b.parent_version, b.name, b.version]), [["v18.20.4", "brotli", "1.0.9"], ["v20.18.0", "brotli", "1.1.0"], ["v22.12.0", "brotli", "1.1.0"]], "the Node 18 carries the older brotli, inside CVE-2026-111497's first range");
});

test("an older probe without the sections leaves the tables alone", () => {
  probe("2026-10-28T10:00:00Z");
  const r = sw.recordSoftware(BOX, "2026-10-28T12:00:00Z", { os: { id: "debian", version: "13" }, package_manager: "deb", packages: [{ n: "nodejs", v: "22.12.0-1nodesource1" }, { n: "libbrotli1", v: "1.1.0-2+deb13u1" }, { n: "libc6", v: "2.41-1" }, { n: "nginx", v: "1.26.3-1" }], binaries: [{ name: "node", version: "v22.12.0" }] })!;
  assert.equal(r.bundles, 0);
  assert.equal(sw.softwareOn(BOX).bundles.length, 4, "no `bundles` array: nothing was said about them, nothing is removed");
  assert.equal((db.prepare("select count(*) as n from instance_depends where instance_id = ?").get(BOX) as any).n, 3);
});

test("parseProbeOutput keeps software 5's bundles and depends sections, bounded, so the inventory ever sees them", async () => {
  const { parseProbeOutput } = await import("../ssm.js");
  const out = parseProbeOutput(JSON.stringify({
    probe: "aws-advisor/software/5", kind: "software", hostname: "h", collected_at: "2026-10-28T18:00:00Z", os: { id: "debian", version: "13", name: "Debian" }, kernel: "6.12", arch: "x86_64", package_manager: "deb",
    packages: [{ n: "nodejs", v: "22.12.0-1", a: "amd64" }], binaries: [{ name: "node", version: "v20.18.0", path: "/home/example/.nvm/versions/node/v20.18.0/bin/node" }], images: [],
    bundles: [{ name: "node", path: "/home/example/.nvm/versions/node/v20.18.0/bin/node", versions: { node: "20.18.0", brotli: "1.1.0", openssl: "3.0.13+quic", "bad key!": "x", modules: 115 } }, { name: "", versions: {} }, "junk"],
    depends: [{ n: "nodejs", d: "libc6 (>= 2.34), libbrotli1 (>= 1.1.0)" }, { n: "x" }],
    hibernation: null,
  }));
  assert.deepEqual(out.bundles, [{ name: "node", path: "/home/example/.nvm/versions/node/v20.18.0/bin/node", versions: { node: "20.18.0", brotli: "1.1.0", openssl: "3.0.13+quic" } }], "string values under plain keys only; a nameless or non-object entry is dropped");
  assert.deepEqual(out.depends, [{ n: "nodejs", d: "libc6 (>= 2.34), libbrotli1 (>= 1.1.0)" }]);
  const older = parseProbeOutput(JSON.stringify({ probe: "aws-advisor/software/3", kind: "software", hostname: "h", collected_at: "2026-10-28T18:00:00Z", os: { id: "debian", version: "13", name: "Debian" }, packages: [], binaries: [], images: [] }));
  assert.equal(older.bundles, undefined, "an older probe says nothing about bundles, and the inventory leaves its rows alone");
  assert.equal(older.depends, undefined);
});

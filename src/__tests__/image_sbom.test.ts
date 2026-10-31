import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

// Image contents once per image (src/software_inventory.ts): the key, the scanner's and a box's writes into the image tables, what every box running the image sees, the prune.
process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "advisor-image-sbom-test-"));
process.env.TYPESAFE_API_KEY = "";
const sw = await import("../software_inventory.js");
const { db } = await import("../db.js");

const SHA = (c: string) => `sha256:${c.repeat(64)}`;
const box = (id: string, state = "running", gone = 0) => {
  db.prepare("delete from inventory_ec2 where instance_id = ?").run(id);
  const cols = (db.prepare("pragma table_info(inventory_ec2)").all() as any[]).map((c) => c.name);
  const row: Record<string, any> = { instance_id: id, name: id.slice(-4), state, ssm_status: "Online", gone, cpu_30d: 1, snapshot: "{}", first_seen: "2026-01-01", last_seen: "2026-01-01" };
  const use = Object.keys(row).filter((k) => cols.includes(k));
  db.prepare(`insert into inventory_ec2(${use.join(",")}) values (${use.map(() => "?").join(",")})`).run(...use.map((k) => row[k]));
};

test("imageKey: the registry digest with the platform, else the local image id, else nothing; pullRefOf: the RepoDigest the box recorded, else the repository at the digest", () => {
  assert.equal(sw.imageKey({ digest: `nginx@${SHA("a")}`, image_id: SHA("b"), platform: "linux/amd64" }), `dg:${SHA("a")}|linux/amd64`, "the digest wins over the id; the repository prefix is dropped");
  assert.equal(sw.imageKey({ digest: SHA("a"), platform: "Linux/ARM64" }), `dg:${SHA("a")}|linux/arm64`, "a bare digest, the platform lowercased");
  assert.notEqual(sw.imageKey({ digest: SHA("a"), platform: "linux/amd64" }), sw.imageKey({ digest: SHA("a"), platform: "linux/arm64" }), "one multi-arch index digest on two platforms is two keys");
  assert.equal(sw.imageKey({ digest: SHA("a"), platform: null }), `dg:${SHA("a")}|`, "no platform known: still keyed by the digest");
  assert.equal(sw.imageKey({ digest: null, image_id: SHA("b") }), `id:${SHA("b")}`, "a build that never left the box: its id");
  assert.equal(sw.imageKey({ digest: "", image_id: "sha256:abcdef123456", platform: "linux/amd64" }), "id:sha256:abcdef123456", "a short id is enough");
  assert.equal(sw.imageKey({ digest: "nginx@sha256:short", image_id: "sha256:ab" }), null, "neither a full digest nor an id");
  assert.equal(sw.imageKey({}), null);
  assert.equal(sw.pullRefOf({ image: "nginx:1.27", digest: `docker.io/library/nginx@${SHA("a")}` }), `docker.io/library/nginx@${SHA("a")}`, "the RepoDigest names the repository the box pulled from");
  assert.equal(sw.pullRefOf({ image: "ghcr.io/org/app:v1", digest: SHA("a") }), `ghcr.io/org/app@${SHA("a")}`, "a bare digest: the reference's repository");
  assert.equal(sw.pullRefOf({ image: "localhost:5000/app:v1", digest: SHA("a") }), `localhost:5000/app@${SHA("a")}`, "a port is not a tag");
  assert.equal(sw.pullRefOf({ image: "app:latest", digest: null }), null, "no digest: nothing to pull");
  assert.equal(sw.repositoryOf("redis"), "redis"); assert.equal(sw.repositoryOf(`redis@${SHA("a")}`), "redis"); assert.equal(sw.repositoryOf("a/b/c:1.2"), "a/b/c");
});

test("recordImageSbom: an ok scan replaces the image's list, a failed one keeps it under its status; two boxes running the image see the same contents; the scanner's record and a box's own agree on the key", () => {
  const A = "i-0image0000000000a", B = "i-0image0000000000b"; box(A); box(B);
  const key = `dg:${SHA("1")}|linux/amd64`;
  // the software probe lists the image on both boxes (the key is computed on the way in)
  for (const id of [A, B]) sw.recordSoftware(id, "2026-10-31T08:00:00Z", { os: { id: "debian", version: "12", name: "Debian" }, package_manager: "dpkg-query", packages: [{ n: "bash", v: "5.2" }], images: [{ image: "nginx:1.27", id: SHA("9"), digests: `nginx@${SHA("1")}`, platform: "linux/amd64" }, { image: "app:latest", id: SHA("8"), digests: null, platform: "linux/amd64" }] });
  assert.deepEqual(db.prepare("select image, sbom_key from instance_images where instance_id = ? order by image").all(A), [{ image: "app:latest", sbom_key: `id:${SHA("8")}` }, { image: "nginx:1.27", sbom_key: key }]);
  // the scanner reads nginx: one row, both boxes see it, pending before that
  assert.equal(sw.softwareOn(A).sbom.sources.find((s) => s.ref === "nginx:1.27")?.status, "pending", "listed, not yet read by anyone");
  const r1 = sw.recordImageSbom("i-0scanner000000001", "2026-10-31T09:00:00Z", { available: true, tool: "syft 1.55.0", sources: [
    { source: "image", ref: `nginx@${SHA("1")}`, digest: SHA("1"), platform: "linux/amd64", status: "ok", total: 2, purls: ["pkg:deb/debian/nginx@1.27.0-1?distro=debian-12", "pkg:deb/debian/libssl3@3.0.11?distro=debian-12"] },
    { source: "image", ref: `redis@${SHA("2")}`, digest: SHA("2"), platform: "linux/arm64", status: "timeout", total: 0, purls: [] },
    { source: "dir", ref: "/", status: "ok", total: 1, purls: ["pkg:pypi/x@1"] } ] }, { via: "scanner", keyOf: (s) => sw.imageKey({ digest: s.digest, platform: s.platform }) });
  assert.deepEqual(r1.ok, [key]); assert.deepEqual(r1.failed.map((f) => [f.key, f.status]), [[`dg:${SHA("2")}|linux/arm64`, "timeout"]]); assert.equal(r1.scans, 2, "the dir source is not an image");
  assert.equal(r1.packages, 2);
  for (const id of [A, B]) {
    const on = sw.softwareOn(id).sbom;
    const src = on.sources.find((s) => s.ref === "nginx:1.27")!;
    assert.equal(src.status, "ok"); assert.equal(src.scanned_on, "i-0scanner000000001"); assert.equal(src.via, "scanner"); assert.equal(src.digest, SHA("1")); assert.equal(src.platform, "linux/amd64"); assert.equal(src.listed, 2);
    assert.deepEqual(on.packages.filter((p) => p.ref === "nginx:1.27").map((p) => p.name).sort(), ["libssl3", "nginx"], `${id} sees the image's packages through its own image row`);
  }
  assert.equal(sw.wherePackage("libssl3").filter((w) => w.kind === "sbom" && w.ref === "nginx:1.27").length, 2, "one row per box running the image");
  assert.equal(sw.instancesRunningImages([key]).sort().join(","), [A, B].sort().join(","));
  assert.deepEqual(sw.instancesRunningImages([]), []);
  // the box's own sbom probe in local mode: only the local build, keyed by its id; the scanner's nginx row is untouched
  const r2 = sw.recordSbom(A, "2026-10-31T10:00:00Z", { available: true, tool: "syft 1.55.0", images_mode: "local", sources: [
    { source: "image", ref: "app:latest", image_id: SHA("8"), digest: null, platform: "linux/amd64", status: "ok", total: 1, purls: ["pkg:npm/express@4.19.2"] },
    { source: "dir", ref: "/", status: "ok", total: 1, purls: ["pkg:pypi/requests@2.32.3"] } ] })!;
  assert.deepEqual(r2.images.ok, [`id:${SHA("8")}`]); assert.equal(r2.packages, 2, "the filesystem's package and the local image's");
  assert.equal((db.prepare("select via, scanned_on from image_sbom_scans where key = ?").get(`id:${SHA("8")}`) as any).via, "box");
  assert.equal((db.prepare("select via from image_sbom_scans where key = ?").get(key) as any).via, "scanner", "the scanner's row stands");
  assert.deepEqual(sw.softwareOn(A).sbom.packages.map((p) => `${p.ref} ${p.name}`), ["app:latest express", "nginx:1.27 libssl3", "nginx:1.27 nginx", "/ requests"]);
  assert.deepEqual(sw.softwareOn(B).sbom.packages.map((p) => `${p.ref} ${p.name}`), ["app:latest express", "nginx:1.27 libssl3", "nginx:1.27 nginx"], "B runs the same local build (same id): it sees A's reading of it");
  assert.equal(sw.softwareOn(A).sbom.scan?.images_mode, "local");
  // the scanner reads nginx again: a changed list replaces the old one; then a failure keeps it
  const r3 = sw.recordImageSbom("i-0scanner000000001", "2026-11-01T09:00:00Z", { available: true, sources: [{ source: "image", ref: `nginx@${SHA("1")}`, digest: SHA("1"), platform: "linux/amd64", status: "ok", total: 2, purls: ["pkg:deb/debian/nginx@1.27.0-1?distro=debian-12", "pkg:deb/debian/zlib1g@1.3?distro=debian-12"] }] }, { via: "scanner", keyOf: (s) => sw.imageKey({ digest: s.digest, platform: s.platform }) });
  assert.equal(r3.added, 1); assert.equal(r3.removed, 1);
  const r4 = sw.recordImageSbom("i-0scanner000000001", "2026-11-02T09:00:00Z", { available: true, sources: [{ source: "image", ref: `nginx@${SHA("1")}`, digest: SHA("1"), platform: "linux/amd64", status: "error", total: 0, note: "403 from the registry", purls: [] }] }, { via: "scanner", keyOf: (s) => sw.imageKey({ digest: s.digest, platform: s.platform }) });
  assert.deepEqual(r4.failed.map((f) => f.note), ["403 from the registry"]);
  const row = db.prepare("select status, note, listed, ok_at, collected_at from image_sbom_scans where key = ?").get(key) as any;
  assert.deepEqual(row, { status: "error", note: "403 from the registry", listed: 2, ok_at: "2026-11-01T09:00:00Z", collected_at: "2026-11-02T09:00:00Z" }, "the failure is on the row, the last good list and its time stay");
  assert.deepEqual(sw.softwareOn(B).sbom.packages.filter((p) => p.ref === "nginx:1.27").map((p) => p.name).sort(), ["nginx", "zlib1g"]);
  const sum = sw.softwareSummary().sbom;
  assert.ok(sum.images.distinct >= 3 && sum.images.failed >= 2 && sum.images.scanner === "i-0scanner000000001", JSON.stringify(sum.images));
  // the prune: a key no running box carries goes once old enough; one still run stays however old
  db.prepare("update image_sbom_scans set collected_at = '2026-01-01T00:00:00Z'").run();
  const p = sw.pruneImageSboms(30);
  assert.deepEqual(p, { scans: 1, packages: 0 }, "redis (never run by a box) goes; nginx and app stay");
  assert.ok(db.prepare("select 1 from image_sbom_scans where key = ?").get(key));
  box(A, "stopped"); box(B, "running", 1);
  assert.deepEqual(sw.pruneImageSboms(30), { scans: 2, packages: 3 }, "no running box left: both go, their packages with them");
  assert.deepEqual(sw.pruneImageSboms(30), { scans: 0, packages: 0 });
});

test("recordSbom keys an image the way the software probe does, so a box's own reading and the scanner's meet; a reading without digest or id is keyed by the box", () => {
  const C = "i-0image0000000000c"; box(C);
  const r = sw.recordSbom(C, "2026-10-31T10:00:00Z", { available: true, images_mode: "all", sources: [
    { source: "image", ref: "nginx:1.27", image_id: SHA("9"), digest: SHA("3"), platform: "linux/amd64", status: "ok", total: 1, purls: ["pkg:deb/debian/nginx@1.27.0-1"] },
    { source: "image", ref: "old:1", status: "ok", total: 1, purls: ["pkg:npm/left-pad@1.3.0"] } ] })!;
  assert.deepEqual(r.images.ok, [`dg:${SHA("3")}|linux/amd64`, `ref:${C}|old:1`]);
  assert.deepEqual(db.prepare("select image, sbom_key, digest from instance_images where instance_id = ? order by image").all(C), [{ image: "nginx:1.27", sbom_key: `dg:${SHA("3")}|linux/amd64`, digest: SHA("3") }, { image: "old:1", sbom_key: null, digest: null }], "the box's image rows exist for the page; the per-box key is not stored on the row");
  assert.deepEqual(sw.softwareOn(C).sbom.sources.map((s) => [s.ref, s.status, s.via]), [["nginx:1.27", "ok", "box"], ["old:1", "ok", "box"]]);
  // the software probe then lists the images with the same facts: the keys agree, the scan rows are reused
  sw.recordSoftware(C, "2026-10-31T11:00:00Z", { os: { id: "debian" }, package_manager: "dpkg-query", packages: [{ n: "bash", v: "5.2" }], images: [{ image: "nginx:1.27", id: SHA("9"), digests: `nginx@${SHA("3")}`, platform: "linux/amd64" }] });
  assert.deepEqual(sw.softwareOn(C).sbom.sources.map((s) => s.ref), ["nginx:1.27"], "old:1 left the box's list with the software probe");
  assert.equal(sw.softwareOn(C).sbom.packages.length, 1);
});

test("the one-time migration moves per-box image rows into the image tables and leaves the filesystem rows", async () => {
  // a database as it was before the image tables: image rows per box in instance_sbom_sources / instance_sbom, the image tables empty
  const D = "i-0image0000000000d", E = "i-0image0000000000e"; box(D); box(E);
  db.exec("delete from image_sbom; delete from image_sbom_scans");
  for (const id of [D, E]) {
    db.prepare("insert or replace into instance_images(instance_id, image, image_id, digest, platform, first_seen, last_seen, sbom_key) values (?, 'redis:7', ?, ?, 'linux/amd64', '2026-10-01', '2026-10-30', ?)").run(id, SHA("5"), `redis@${SHA("4")}`, `dg:${SHA("4")}|linux/amd64`);
    db.prepare("insert or replace into instance_sbom_sources(instance_id, source, ref, status, total, listed, collected_at, image_id, digest) values (?, 'image', 'redis:7', ?, 1, 1, ?, ?, ?)").run(id, id === D ? "timeout" : "ok", id === D ? "2026-10-30T10:00:00Z" : "2026-10-29T10:00:00Z", SHA("5"), SHA("4"));
    db.prepare("insert or replace into instance_sbom(instance_id, source, ref, purl, type, namespace, name, version, first_seen, last_seen) values (?, 'image', 'redis:7', 'pkg:deb/debian/redis@7.0', 'deb', 'debian', 'redis', '7.0', '2026-10-29', '2026-10-29')").run(id);
    db.prepare("insert or replace into instance_sbom_sources(instance_id, source, ref, status, total, listed, collected_at) values (?, 'dir', '/', 'ok', 1, 1, '2026-10-30T10:00:00Z')").run(id);
    db.prepare("insert or replace into instance_sbom(instance_id, source, ref, purl, type, namespace, name, version, first_seen, last_seen) values (?, 'dir', '/', 'pkg:pypi/requests@2.32.3', 'pypi', null, 'requests', '2.32.3', '2026-10-29', '2026-10-29')").run(id);
  }
  // the module runs its migration at load: load it again in a fresh module instance against the same database
  const again = await import(`../software_inventory.js?migrate=${Date.now()}`);
  const scan = db.prepare("select status, via, scanned_on, listed from image_sbom_scans where key = ?").get(`dg:${SHA("4")}|linux/amd64`) as any;
  assert.deepEqual(scan, { status: "ok", via: "box", scanned_on: E, listed: 1 }, "the ok reading wins over the newer timeout");
  const n = (sql: string, ...p: unknown[]) => Number((db.prepare(sql).get(...p) as any).n);
  assert.equal(n("select count(*) as n from image_sbom where key = ?", `dg:${SHA("4")}|linux/amd64`), 1);
  assert.equal(n("select count(*) as n from instance_sbom where source = 'image'"), 0); assert.equal(n("select count(*) as n from instance_sbom_sources where source = 'image'"), 0);
  assert.equal(n("select count(*) as n from instance_sbom where source = 'dir' and instance_id in (?, ?)", D, E), 2, "the filesystem rows stay");
  for (const id of [D, E]) assert.deepEqual(again.softwareOn(id).sbom.packages.map((p: any) => `${p.ref} ${p.name}`), ["redis:7 redis", "/ requests"]);
});

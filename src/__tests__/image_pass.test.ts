import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

// The image half of the sbom pass (src/image_pass.ts): which images are due on the scanner, how they are batched, what the boxes do afterwards.
process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "advisor-image-pass-test-"));
process.env.TYPESAFE_API_KEY = "";
process.env.NEO4J_URI = "";
const ip = await import("../image_pass.js");
const sw = await import("../software_inventory.js");
const { db } = await import("../db.js");
const { config, validateRuntime } = await import("../config.js");

const SHA = (c: string) => `sha256:${c.repeat(64)}`;
const box = (id: string, state = "running", gone = 0) => {
  db.prepare("delete from inventory_ec2 where instance_id = ?").run(id);
  const cols = (db.prepare("pragma table_info(inventory_ec2)").all() as any[]).map((c) => c.name);
  const row: Record<string, any> = { instance_id: id, name: id.slice(-4), state, ssm_status: "Online", gone, cpu_30d: 1, snapshot: "{}", first_seen: "2026-01-01", last_seen: "2026-01-01" };
  const use = Object.keys(row).filter((k) => cols.includes(k));
  db.prepare(`insert into inventory_ec2(${use.join(",")}) values (${use.map(() => "?").join(",")})`).run(...use.map((k) => row[k]));
};
const iso = (minsAgo: number) => new Date(Date.now() - minsAgo * 60000).toISOString().replace(/\.\d{3}Z$/, "Z");

test("dueImages: distinct registry images across running boxes, the most shared first, without an ok scan inside the window; local builds and stopped boxes are out", () => {
  const A = "i-0pass00000000000a", B = "i-0pass00000000000b", S = "i-0pass00000000000s", G = "i-0pass00000000000g";
  box(A); box(B); box(S, "stopped"); box(G, "running", 1);
  const images = (id: string, list: { image: string; id?: string; digests?: string | null; platform?: string }[]) => sw.recordSoftware(id, iso(60), { os: { id: "debian" }, package_manager: "dpkg-query", packages: [{ n: "bash", v: "5.2" }], images: list.map((i) => ({ image: i.image, id: i.id ?? SHA("9"), digests: i.digests === undefined ? null : i.digests, platform: i.platform ?? "linux/amd64" })) });
  images(A, [{ image: "nginx:1.27", digests: `nginx@${SHA("1")}` }, { image: "api:v3", digests: `123456789012.dkr.ecr.eu-west-1.amazonaws.com/api@${SHA("2")}`, platform: "linux/arm64" }, { image: "local:dev", id: SHA("8") }]);
  images(B, [{ image: "nginx:1.27", digests: `nginx@${SHA("1")}` }, { image: "redis:7", digests: `redis@${SHA("3")}` }]);
  images(S, [{ image: "stopped:1", digests: `stopped@${SHA("4")}` }]);
  images(G, [{ image: "gone:1", digests: `gone@${SHA("5")}` }]);
  let due = ip.dueImages();
  assert.deepEqual(due.map((d) => [d.image, d.boxes, d.pull_ref, d.platform]), [["nginx:1.27", 2, `nginx@${SHA("1")}`, "linux/amd64"], ["api:v3", 1, `123456789012.dkr.ecr.eu-west-1.amazonaws.com/api@${SHA("2")}`, "linux/arm64"], ["redis:7", 1, `redis@${SHA("3")}`, "linux/amd64"]], "nginx once though two boxes run it; no local build, nothing from a stopped or gone box");
  assert.deepEqual(due.map(ip.imageEntry), [`nginx@${SHA("1")}|linux/amd64`, `123456789012.dkr.ecr.eu-west-1.amazonaws.com/api@${SHA("2")}|linux/arm64`, `redis@${SHA("3")}|linux/amd64`]);
  assert.equal(ip.imageEntry({ pull_ref: "x@y", platform: null }), "x@y", "no platform: no bar");
  // read ok a moment ago: not due; read ok long ago, or failed just now: due again
  sw.recordImageSbom("i-0scanner000000001", iso(5), { available: true, sources: [
    { source: "image", ref: `nginx@${SHA("1")}`, digest: SHA("1"), platform: "linux/amd64", status: "ok", total: 1, purls: ["pkg:deb/debian/nginx@1.27"] },
    { source: "image", ref: `redis@${SHA("3")}`, digest: SHA("3"), platform: "linux/amd64", status: "timeout", total: 0, purls: [] } ] }, { via: "scanner", keyOf: (s) => sw.imageKey({ digest: s.digest, platform: s.platform }) });
  sw.recordImageSbom("i-0scanner000000001", iso(48 * 60), { available: true, sources: [{ source: "image", ref: `123456789012.dkr.ecr.eu-west-1.amazonaws.com/api@${SHA("2")}`, digest: SHA("2"), platform: "linux/arm64", status: "ok", total: 1, purls: ["pkg:npm/express@4"] }] }, { via: "scanner", keyOf: (s) => sw.imageKey({ digest: s.digest, platform: s.platform }) });
  due = ip.dueImages();
  assert.deepEqual(due.map((d) => d.image), ["api:v3", "redis:7"], "nginx was read within the window; api's reading is older than the window; redis failed");
  assert.deepEqual(ip.dueImages(3 * 24 * 60).map((d) => d.image), ["redis:7"], "a wider window keeps api");
  assert.deepEqual(ip.dueImages(undefined, 1).map((d) => d.image), ["api:v3"], "the limit");
  // the same digest on another platform is another image to read
  images(B, [{ image: "nginx:1.27", digests: `nginx@${SHA("1")}`, platform: "linux/arm64" }]);
  assert.deepEqual(ip.dueImages().map((d) => [d.image, d.platform]), [["api:v3", "linux/arm64"], ["nginx:1.27", "linux/arm64"]], "nginx for arm64 is due, nginx for amd64 was read; redis left B");
});

test("batchImages cuts the entries by count and by characters; sbomImagesMode follows the outcome; imageScanner validates the setting", () => {
  const e = (n: number) => `repo${n}@${SHA(String(n % 10))}|linux/amd64`; // 90 characters each
  assert.deepEqual(ip.batchImages([], ip.IMAGE_BATCH), []);
  const b = ip.batchImages(Array.from({ length: 33 }, (_, i) => e(i)), ip.IMAGE_BATCH);
  assert.deepEqual(b.map((x) => x.length), [15, 15, 3]);
  assert.ok(b.every((x) => x.join(" ").length <= ip.IMAGE_BATCH.maxChars));
  const c = ip.batchImages(Array.from({ length: 10 }, (_, i) => e(i)), { maxEntries: 15, maxChars: 200 });
  assert.deepEqual(c.map((x) => x.length), [2, 2, 2, 2, 2], "two entries of 90 characters fit in 200, three do not");
  assert.deepEqual(ip.batchImages(["x".repeat(500), "y"], { maxEntries: 15, maxChars: 200 }), [["x".repeat(500)], ["y"]], "an entry over the limit goes alone");
  assert.deepEqual(ip.batchImages(Array.from({ length: 9 }, (_, i) => e(i)), ip.INLINE_IMAGE_BATCH).map((x) => x.length), [4, 4, 1]);
  assert.equal(ip.sbomImagesMode(null), "all"); assert.equal(ip.sbomImagesMode({ ok: false } as any), "all"); assert.equal(ip.sbomImagesMode({ ok: true } as any), "local");
  const before = process.env.PROBE_IMAGES_SCANNER;
  try {
    process.env.PROBE_IMAGES_SCANNER = ""; assert.equal(ip.imageScanner(), null);
    process.env.PROBE_IMAGES_SCANNER = "i-0123456789abcdef0"; assert.equal(ip.imageScanner(), "i-0123456789abcdef0");
    process.env.PROBE_IMAGES_SCANNER = "not-an-id"; assert.equal(ip.imageScanner(), null, "a malformed setting is no scanner");
    assert.throws(() => validateRuntime("probeImagesScanner", "nope"), /instance id/); assert.equal(validateRuntime("probeImagesScanner", " i-0123456789abcdef0 "), "i-0123456789abcdef0"); assert.equal(validateRuntime("probeImagesScanner", ""), "");
    assert.equal(config.probeImagesTimeoutSeconds, 180);
  } finally { if (before === undefined) delete process.env.PROBE_IMAGES_SCANNER; else process.env.PROBE_IMAGES_SCANNER = before; }
});

test("imagePass: no scanner configured says so and leaves the boxes scanning every image; a scanner the environment cannot reach is reported after the first batch, the rest is not attempted", async () => {
  const before = process.env.PROBE_IMAGES_SCANNER;
  try {
    process.env.PROBE_IMAGES_SCANNER = "";
    const none = await ip.imagePass();
    assert.equal(none.ok, false); assert.equal(none.scanner, null); assert.match(none.reason ?? "", /no image scanner configured/); assert.equal(ip.sbomImagesMode(none), "all");
    // a scanner set: either the credentials gate is closed (nothing sent) or the first command fails because SSM does not know the box; both leave the boxes scanning every image
    process.env.PROBE_IMAGES_SCANNER = "i-0123456789abcdef0";
    const gated = await ip.imagePass();
    assert.equal(gated.ok, false); assert.equal(gated.scanner, "i-0123456789abcdef0"); assert.ok(gated.reason, "a reason is given"); assert.ok(gated.batches <= 1 && gated.commands_failed.length <= 1, "at most the first batch is tried"); assert.deepEqual(gated.scanned, []);
    assert.equal(ip.sbomImagesMode(gated), "all");
  } finally { if (before === undefined) delete process.env.PROBE_IMAGES_SCANNER; else process.env.PROBE_IMAGES_SCANNER = before; }
});

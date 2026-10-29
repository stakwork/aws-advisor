import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "advisor-uploads-test-"));
process.env.TYPESAFE_API_KEY = "";
const u = await import("../probe_uploads.js");
const g = await import("../graph_software.js");

test("upload keys say what an object is and parse back; receipts carry bytes and sha256; no bucket means no check and no signing", async () => {
  const key = u.uploadKey("123456789012", "i-0abc123456789def0", "sbom", new Date("2026-10-29T12:45:19.123Z"));
  assert.equal(key, "aws-advisor/probes/123456789012/i-0abc123456789def0/sbom/2026-10-29T12-45-19-123Z.json.gz");
  assert.deepEqual(u.parseUploadKey(key), { account_id: "123456789012", instance_id: "i-0abc123456789def0", kind: "sbom", at: "2026-10-29T12:45:19.123Z" });
  assert.equal(u.parseUploadKey("aws-advisor/probes/readme.txt"), null);
  assert.deepEqual(u.parseReceipt("uploaded 1741 " + "a".repeat(64)), { bytes: 1741, sha256: "a".repeat(64) });
  assert.deepEqual(u.parseReceipt("uploaded 1741"), { bytes: 1741, sha256: null }, "a box without sha256sum");
  assert.deepEqual(u.parseReceipt("upload failed (curl and egress to S3 are needed)"), { bytes: null, sha256: null });
  assert.equal(u.probeUploadsConfigured(), false, "no bucket in the test settings");
  assert.deepEqual(await u.checkProbeUploads(true), { configured: false, bucket: null, prefix: null, ok: null, error: null, checked_at: null, identity: null }, "nothing to check without a bucket");
  assert.equal(await u.probeUploadsReady(), false);
});

test("imageNodeId: the repository at its registry digest, else the local image id, else the bare reference", () => {
  const d = "sha256:" + "c".repeat(64);
  assert.equal(g.imageNodeId("redis:latest", d, "sha256:" + "a".repeat(64)), `image:redis@${d}`);
  assert.equal(g.imageNodeId("redis:latest", `redis@${d}`, null), `image:redis@${d}`, "a RepoDigest as docker prints it");
  assert.equal(g.imageNodeId("ghcr.io/stakwork/aws-advisor:latest", d, null), `image:ghcr.io/stakwork/aws-advisor@${d}`);
  assert.equal(g.imageNodeId("9d6578ab7f42", null, "sha256:9d6578ab7f42aaaa"), "image:sha256:9d6578ab7f42aaaa", "a local build: its id");
  assert.equal(g.imageNodeId("redis:latest", null, null), "image:redis:latest", "nothing better known");
  const row = g.sbomGraphRow({ instance_id: "i-1", source: "image", ref: "redis:latest", purl: "pkg:deb/debian/libssl3@3.0.11-1?distro=debian-12", name: "libssl3", version: "3.0.11-1", first_seen: "t", last_seen: "t", digest: d, image_id: "sha256:" + "a".repeat(64) })!;
  assert.equal(row.row.image_id, `image:redis@${d}`); assert.equal(row.row.digest, d); assert.equal(row.row.id, "pkg:deb:libssl3:3.0.11-1");
});

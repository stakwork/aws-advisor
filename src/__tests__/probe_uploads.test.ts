import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { gunzipSync } from "node:zlib";

process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "advisor-uploads-test-"));
process.env.TYPESAFE_API_KEY = "";
const { S3Client } = await import("@aws-sdk/client-s3");
const u = await import("../probe_uploads.js");
const g = await import("../graph_software.js");
const { setSetting } = await import("../db.js");

const AT = new Date("2026-10-29T12:45:19.123Z");

test("upload keys follow the dated layout (kind, day, account, box, time) and parse back; the legacy layout still parses; markers, cluster objects and unknown kinds do not", () => {
  const key = u.uploadKey("123456789012", "i-0abc123456789def0", "sbom", AT);
  assert.equal(key, "aws-advisor/probes/sbom/2026-10-29/123456789012/i-0abc123456789def0/2026-10-29T12-45-19-123Z.json.gz");
  assert.deepEqual(u.parseUploadKey(key), { account_id: "123456789012", instance_id: "i-0abc123456789def0", kind: "sbom", at: "2026-10-29T12:45:19.123Z", layout: "dated" });
  assert.equal(u.uploadKey(null, "i-0abc123456789def0", "host", AT), "aws-advisor/probes/host/2026-10-29/unknown/i-0abc123456789def0/2026-10-29T12-45-19-123Z.json.gz", "no account known");
  assert.deepEqual(u.parseUploadKey("aws-advisor/probes/123456789012/i-0abc123456789def0/software/2026-10-29T12-45-19-123Z.json.gz"),
    { account_id: "123456789012", instance_id: "i-0abc123456789def0", kind: "software", at: "2026-10-29T12:45:19.123Z", layout: "legacy" }, "an object from before the dated layout");
  assert.equal(u.parseUploadKey("aws-advisor/probes/readme.txt"), null);
  assert.equal(u.parseUploadKey("aws-advisor/probes/_check/2026-10-29T12-45-19-123Z.txt"), null, "the bucket check's marker");
  assert.equal(u.parseUploadKey("aws-advisor/probes/cluster-images/2026-10-29/123456789012/prod/2026-10-29T12-45-19-123Z.json.gz"), null, "a cluster-images object is not a probe result");
  assert.equal(u.parseUploadKey("aws-advisor/probes/firmware/2026-10-29/123456789012/i-0abc123456789def0/2026-10-29T12-45-19-123Z.json.gz"), null, "a kind this build does not know");
});

test("the cluster-images key names the cluster as a slug under its own tree", () => {
  assert.equal(u.clusterImagesKey("123456789012", "prod", AT), "aws-advisor/probes/cluster-images/2026-10-29/123456789012/prod/2026-10-29T12-45-19-123Z.json.gz");
  assert.equal(u.clusterImagesKey(null, "team a/eu west", AT), "aws-advisor/probes/cluster-images/2026-10-29/unknown/team_a_eu_west/2026-10-29T12-45-19-123Z.json.gz", "a name the key cannot carry as is");
});

test("receipts carry bytes and sha256; no bucket means no check and no signing", async () => {
  assert.deepEqual(u.parseReceipt("uploaded 1741 " + "a".repeat(64)), { bytes: 1741, sha256: "a".repeat(64) });
  assert.deepEqual(u.parseReceipt("uploaded 1741"), { bytes: 1741, sha256: null }, "a box without sha256sum");
  assert.deepEqual(u.parseReceipt("upload failed (curl and egress to S3 are needed)"), { bytes: null, sha256: null });
  assert.equal(u.probeUploadsConfigured(), false, "no bucket in the test settings");
  assert.deepEqual(await u.checkProbeUploads(true), { configured: false, bucket: null, prefix: null, ok: null, error: null, checked_at: null, identity: null }, "nothing to check without a bucket");
  assert.equal(await u.probeUploadsReady(), false);
});

/** Records every S3 call and answers from `reply` (a client of the test's own: no saved credentials here); restores the client afterwards. */
async function withS3(reply: (name: string, input: any) => any, fn: (s3: InstanceType<typeof S3Client>, calls: { name: string; input: any }[]) => Promise<void>) {
  const calls: { name: string; input: any }[] = [];
  const orig = S3Client.prototype.send;
  (S3Client.prototype as any).send = async function (cmd: any) { const name = cmd.constructor.name; calls.push({ name, input: cmd.input }); return reply(name, cmd.input); };
  const s3 = new S3Client({ region: "us-east-1", credentials: async () => ({ accessKeyId: "ASIAEXAMPLEEXAMPLE00", secretAccessKey: "x" }) });
  setSetting("cfg:probeUploadBucket", "advisor-probes");
  try { await fn(s3, calls); } finally { (S3Client.prototype as any).send = orig; s3.destroy(); setSetting("cfg:probeUploadBucket", ""); }
}

test("putProbeObject writes the JSON gzip-compressed under the key and answers with the object's size and hash", async () => {
  await withS3(() => ({}), async (s3, calls) => {
    const body = { probe: "aws-advisor/cluster-images/1", kind: "cluster-images", nodes: [{ instance_id: "i-1", images: [] }] };
    const r = await u.putProbeObject("aws-advisor/probes/cluster-images/2026-10-29/123456789012/prod/x.json.gz", body, s3);
    assert.equal(calls.length, 1); assert.equal(calls[0]!.name, "PutObjectCommand");
    const { Bucket, Key, Body, ContentType, ContentEncoding } = calls[0]!.input;
    assert.deepEqual([Bucket, Key, ContentType, ContentEncoding], ["advisor-probes", "aws-advisor/probes/cluster-images/2026-10-29/123456789012/prod/x.json.gz", "application/json", "gzip"]);
    assert.deepEqual(JSON.parse(gunzipSync(Body).toString("utf8")), body);
    assert.deepEqual(r, { bytes: Body.length, sha256: createHash("sha256").update(Body).digest("hex") });
  });
});

test("listProbeUploads walks only the wanted kinds' trees and the legacy account trees, never the markers or the cluster objects, and reads both layouts", async () => {
  const t = "2026-10-29T12-45-19-123Z";
  const trees: Record<string, { Key: string; Size: number }[]> = {
    "aws-advisor/probes/software/": [{ Key: `aws-advisor/probes/software/2026-10-29/123456789012/i-0abc123456789def0/${t}.json.gz`, Size: 10 }],
    "aws-advisor/probes/host/": [{ Key: `aws-advisor/probes/host/2026-10-29/123456789012/i-0abc123456789def0/${t}.json.gz`, Size: 5 }],
    "aws-advisor/probes/123456789012/": [
      { Key: `aws-advisor/probes/123456789012/i-0abc123456789def0/software/${t}.json.gz`, Size: 20 },
      { Key: `aws-advisor/probes/123456789012/i-0abc123456789def0/sbom/${t}.json.gz`, Size: 30 },
    ],
    "aws-advisor/probes/cluster-images/": [{ Key: `aws-advisor/probes/cluster-images/2026-10-29/123456789012/prod/${t}.json.gz`, Size: 7 }],
    "aws-advisor/probes/_check/": [{ Key: `aws-advisor/probes/_check/${t}.txt`, Size: 1 }],
  };
  const reply = (name: string, input: any) => {
    assert.equal(name, "ListObjectsV2Command");
    if (input.Delimiter === "/") return { CommonPrefixes: Object.keys(trees).map((Prefix) => ({ Prefix })) };
    return { Contents: trees[input.Prefix] ?? [] };
  };
  await withS3(reply, async (s3, calls) => {
    const got = await u.listProbeUploads({ kinds: ["software"], s3 });
    assert.deepEqual(calls.map((c) => c.input.Prefix), ["aws-advisor/probes/", "aws-advisor/probes/software/", "aws-advisor/probes/123456789012/"], "one delimiter listing, then the software tree and the legacy account tree");
    assert.deepEqual(got.map((o) => [o.layout, o.kind, o.bytes]), [["dated", "software", 10], ["legacy", "software", 20]], "the legacy sbom object is filtered out, the markers and cluster objects never listed");
  });
  await withS3(reply, async (s3, calls) => {
    const got = await u.listProbeUploads({ s3 });
    assert.ok(!calls.some((c) => /_check|cluster-images/.test(c.input.Prefix)), "every kind: still no walk of the markers or the cluster objects");
    assert.deepEqual(got.map((o) => o.kind).sort(), ["host", "sbom", "software", "software"]);
  });
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

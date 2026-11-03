import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "advisor-graph-containers-test-"));
process.env.TYPESAFE_API_KEY = "";
const { containerGraphRow } = await import("../graph_containers.js");
const { imageNodeResolver } = await import("../graph_software.js");

test("containerGraphRow: BUILT_FROM goes to the digest-keyed image node the box's software probe recorded (the node RUNS_IMAGE and CONTAINS use), the bare reference only while no row names it", () => {
  const row = { instance_id: "i-1", name: "browser.sphinx", container_id: "a".repeat(64), image: "ghcr.io/stakwork/strut-browser:latest", image_id: "sha256:" + "2".repeat(64), state: "running", first_seen: "2026-11-03T00:00:00Z", last_seen: "2026-11-03T01:00:00Z", mounts: "[]", ports: "[]", networks: "[]" };
  const of = imageNodeResolver([{ instance_id: "i-1", image: "ghcr.io/stakwork/strut-browser:latest", image_id: "sha256:" + "2".repeat(64), digest: "ghcr.io/stakwork/strut-browser@sha256:" + "1".repeat(64) }]);
  const withDigest = containerGraphRow(row, of);
  assert.equal(withDigest.id, "container:i-1:browser.sphinx");
  assert.equal(withDigest.image_node, "image:ghcr.io/stakwork/strut-browser@sha256:" + "1".repeat(64));
  assert.equal(withDigest.repository, "ghcr.io/stakwork/strut-browser"); assert.equal(withDigest.tag, "latest", "the reference's own repository and tag still describe the node");
  assert.equal(containerGraphRow({ ...row, instance_id: "i-2" }, of).image_node, "image:sha256:" + "2".repeat(64), "another box without a row: the docker image id the container reports, what that box's RUNS_IMAGE gets until a digest is known");
  assert.equal(containerGraphRow({ ...row, instance_id: "i-2", image_id: null }, of).image_node, "image:ghcr.io/stakwork/strut-browser:latest", "no row and no docker id: the reference");
  assert.equal(containerGraphRow(row).image_node, "image:ghcr.io/stakwork/strut-browser:latest", "no resolver (the pre-2026-11-03 call): the reference");
  assert.equal(containerGraphRow({ ...row, image: null }, of).image_node, null, "a container whose image is unknown has no image node");
});

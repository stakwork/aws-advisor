import assert from "node:assert/strict";
import { test } from "node:test";
import { idsInText, kindOfId, namesInText, splitResourceList } from "../affected.js";

test("affected: the resource column splits into ids paired with names, a parenthesised name winning", () => {
  assert.deepEqual(splitResourceList("i-1", "Hive"), [{ id: "i-1", name: "Hive" }]);
  assert.deepEqual(splitResourceList("i-0f00000000000a001 (Hive)", null), [{ id: "i-0f00000000000a001", name: "Hive" }]);
  assert.deepEqual(splitResourceList("i-1, i-2, i-3", "a, b, c"), [{ id: "i-1", name: "a" }, { id: "i-2", name: "b" }, { id: "i-3", name: "c" }]);
  // names do not pair up with the ids: none are guessed
  assert.deepEqual(splitResourceList("i-1, i-2", "app-prod and 3 others"), [{ id: "i-1", name: null }, { id: "i-2", name: null }]);
  assert.deepEqual(splitResourceList("hub-production", "hub-production"), [{ id: "hub-production", name: null }]);
  assert.deepEqual(splitResourceList(null, null), []);
  assert.deepEqual(splitResourceList("22 stopped EC2 instances (see list)", ""), [{ id: "22 stopped EC2 instances", name: "see list" }]);
});

test("affected: kinds from the shape of an id or ARN; bare names are left to the inventory", () => {
  assert.equal(kindOfId("i-0f00000000000a001"), "ec2");
  assert.equal(kindOfId("vol-0123456789abcdef0"), "ebs");
  assert.equal(kindOfId("snap-0ea7c1c0a472f072c"), "snapshot");
  assert.equal(kindOfId("eipalloc-097b3d3a892abbb16"), "eip");
  assert.equal(kindOfId("vpc-0f0000000000a0001"), "vpc");
  assert.equal(kindOfId("arn:aws:ec2:us-east-1:123456789012:instance/i-1"), "ec2");
  assert.equal(kindOfId("arn:aws:rds:us-east-1:123456789012:cluster:foo"), "rds");
  assert.equal(kindOfId("arn:aws:lambda:us-east-1:123456789012:function:foo"), "lambda");
  assert.equal(kindOfId("arn:aws:s3:::bucket"), "s3");
  assert.equal(kindOfId("/stakwork/production"), "log-group");
  assert.equal(kindOfId("rds:hub-production"), "rds");
  assert.equal(kindOfId("hub-production"), null);
});

test("affected: ids and inventory names spotted in prose, whole words only, once each", () => {
  const text = "app-prod (i-0f00000000000a004, m5.xlarge) and video-session-worker (i-0f00000000000a003); i-0f00000000000a004 again. Right-size Hive and swarmAbc123x; not Hives, not 34.";
  assert.deepEqual(idsInText(text), ["i-0f00000000000a004", "i-0f00000000000a003"]);
  assert.deepEqual(namesInText(text, ["Hive", "swarmAbc123x", "app-prod", "prod", "34", "hive", "app-cache", "Hive"]), ["Hive", "swarmAbc123x", "app-prod"]);
});

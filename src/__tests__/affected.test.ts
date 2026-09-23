import assert from "node:assert/strict";
import { test } from "node:test";
import { idsInText, kindOfId, namesInText, splitResourceList } from "../affected.js";

test("affected: the resource column splits into ids paired with names, a parenthesised name winning", () => {
  assert.deepEqual(splitResourceList("i-1", "Hive"), [{ id: "i-1", name: "Hive" }]);
  assert.deepEqual(splitResourceList("i-0b19ba7373c82230f (Hive)", null), [{ id: "i-0b19ba7373c82230f", name: "Hive" }]);
  assert.deepEqual(splitResourceList("i-1, i-2, i-3", "a, b, c"), [{ id: "i-1", name: "a" }, { id: "i-2", name: "b" }, { id: "i-3", name: "c" }]);
  // names do not pair up with the ids: none are guessed
  assert.deepEqual(splitResourceList("i-1, i-2", "tribes-prod and 3 others"), [{ id: "i-1", name: null }, { id: "i-2", name: null }]);
  assert.deepEqual(splitResourceList("sphinx-hub-production", "sphinx-hub-production"), [{ id: "sphinx-hub-production", name: null }]);
  assert.deepEqual(splitResourceList(null, null), []);
  assert.deepEqual(splitResourceList("22 stopped EC2 instances (see list)", ""), [{ id: "22 stopped EC2 instances", name: "see list" }]);
});

test("affected: kinds from the shape of an id or ARN; bare names are left to the inventory", () => {
  assert.equal(kindOfId("i-0b19ba7373c82230f"), "ec2");
  assert.equal(kindOfId("vol-0123456789abcdef0"), "ebs");
  assert.equal(kindOfId("snap-0ea7c1c0a472f072c"), "snapshot");
  assert.equal(kindOfId("eipalloc-097b3d3a892abbb16"), "eip");
  assert.equal(kindOfId("vpc-08119ea08c0689921"), "vpc");
  assert.equal(kindOfId("arn:aws:ec2:us-east-1:123456789012:instance/i-1"), "ec2");
  assert.equal(kindOfId("arn:aws:rds:us-east-1:123456789012:cluster:foo"), "rds");
  assert.equal(kindOfId("arn:aws:lambda:us-east-1:123456789012:function:foo"), "lambda");
  assert.equal(kindOfId("arn:aws:s3:::bucket"), "s3");
  assert.equal(kindOfId("/stakwork/production"), "log-group");
  assert.equal(kindOfId("rds:sphinx-hub-production"), "rds");
  assert.equal(kindOfId("sphinx-hub-production"), null);
});

test("affected: ids and inventory names spotted in prose, whole words only, once each", () => {
  const text = "tribes-prod (i-001b4ce61fdbf7ef2, m5.xlarge) and youtube-session-generator (i-004beaedbd695fc05); i-001b4ce61fdbf7ef2 again. Right-size Hive and swarmPExsmg; not Hives, not 34.";
  assert.deepEqual(idsInText(text), ["i-001b4ce61fdbf7ef2", "i-004beaedbd695fc05"]);
  assert.deepEqual(namesInText(text, ["Hive", "swarmPExsmg", "tribes-prod", "prod", "34", "hive", "sphinx-cache", "Hive"]), ["Hive", "swarmPExsmg", "tribes-prod"]);
});

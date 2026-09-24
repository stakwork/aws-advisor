import assert from "node:assert/strict";
import { test } from "node:test";
import { assemble, namesId } from "../timeline.js";
import { DISRUPTIVE } from "../exposure.js";

test("timeline: a recommendation names a resource alone, in a list, as an ARN or with its name in brackets; not as a substring", () => {
  assert.equal(namesId({ resource: "i-1" }, "i-1"), true);
  assert.equal(namesId({ resource: "i-2, i-1, i-3" }, "i-1"), true);
  assert.equal(namesId({ resource: "arn:aws:ec2:us-east-1:1:instance/i-1" }, "i-1"), true);
  assert.equal(namesId({ resource: "i-1 (Hive)" }, "i-1"), true);
  assert.equal(namesId({ resource: "i-10" }, "i-1"), false);
  assert.equal(namesId({ resource: null }, "i-1"), false);
});

test("timeline: newest first, insertion order within one instant, capped", () => {
  const e = (at: string, title: string) => ({ at, kind: "alert" as const, title, detail: null, href: null, badge: null });
  const out = assemble([e("2026-09-01 00:00:00", "a"), e("2026-09-03 00:00:00", "b"), e("2026-09-03 00:00:00", "c"), e("2026-09-02 00:00:00", "d")], 3);
  assert.deepEqual(out.map((x) => x.title), ["b", "c", "d"]);
});

test("exposure: the disruptive actions are the ones that stop, replace, remove or re-address; reports are not", () => {
  for (const a of ["stop_instance", "terminate_stopped_instance", "rightsize_instance", "aurora_set_storage_iopt", "migrate_graviton", "release_eip", "delete_snapshot"]) assert.ok(DISRUPTIVE.test(a), a);
  for (const a of ["other", "add_lifecycle_rule", "set_log_retention", "tag_resources"]) assert.ok(!DISRUPTIVE.test(a), a);
});

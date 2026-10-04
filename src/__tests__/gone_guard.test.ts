import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

// An account the credentials could not see must not have its instances declared gone (src/watcher.ts canCallGone,
// src/inventory.ts markGone). Fake account ids and instance ids throughout.
process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "advisor-gone-test-"));
process.env.NEO4J_URI = "";
const { canCallGone } = await import("../watcher.js");
const { markGone } = await import("../inventory.js");
const { db } = await import("../db.js");

test("canCallGone: nothing seen at all, or the instance's account answered with nothing, is not gone", () => {
  const seen = new Set(["111111111111"]);
  assert.equal(canCallGone({ account: "111111111111" }, seen, true), true, "its account answered: a missing instance is gone");
  assert.equal(canCallGone({ account: "222222222222" }, seen, true), false, "its account returned nothing: we could not see it");
  assert.equal(canCallGone({ account: "111111111111" }, seen, false), false, "an empty pass says nothing");
  assert.equal(canCallGone({}, seen, true), true, "a sample from before accounts were recorded follows the pass");
  assert.equal(canCallGone(null, new Set(), false), false);
});

test("markGone: only rows of accounts the refresh returned rows for are marked; the primary's unstamped rows follow it", () => {
  const ins = db.prepare("insert into inventory_ec2(instance_id, name, instance_type, state, region, account_id, first_seen, last_seen, gone, snapshot) values (?, ?, 't3.micro', 'running', 'us-east-1', ?, 'old', 'old', 0, '{}')");
  db.transaction(() => {
    ins.run("i-0aaaaaaaaaaaaaaa1", "parent-a", "111111111111");
    ins.run("i-0aaaaaaaaaaaaaaa2", "parent-legacy", null);
    ins.run("i-0bbbbbbbbbbbbbbb1", "member-b", "222222222222");
    ins.run("i-0bbbbbbbbbbbbbbb2", "member-b2", "222222222222");
  })();
  const now = "2026-10-04 12:00:00";
  db.prepare("update inventory_ec2 set last_seen = ? where instance_id = 'i-0bbbbbbbbbbbbbbb1'").run(now);
  const log: string[] = [];
  // the refresh saw only the member: its unseen row goes, the parent's rows (stamped and legacy) stay
  const n = markGone("inventory_ec2", now, [{ account_id: "222222222222" }], (l) => log.push(l), "111111111111");
  assert.equal(n, 1);
  const gone = (id: string) => (db.prepare("select gone from inventory_ec2 where instance_id = ?").get(id) as { gone: number }).gone;
  assert.equal(gone("i-0bbbbbbbbbbbbbbb2"), 1); assert.equal(gone("i-0aaaaaaaaaaaaaaa1"), 0); assert.equal(gone("i-0aaaaaaaaaaaaaaa2"), 0);
  assert.match(log[0], /2 rows in accounts this refresh could not see/);
  // nothing returned at all: nothing is marked
  assert.equal(markGone("inventory_ec2", "2026-10-04 13:00:00", [], () => {}, "111111111111"), 0);
  assert.equal(gone("i-0aaaaaaaaaaaaaaa1"), 0);
  // the parent answered: its stamped and legacy rows both go
  assert.equal(markGone("inventory_ec2", "2026-10-04 14:00:00", [{ account_id: "111111111111" }], () => {}, "111111111111"), 2);
  assert.equal(gone("i-0aaaaaaaaaaaaaaa2"), 1);
});

import assert from "node:assert/strict";
import { test } from "node:test";

test("a consent tag the advisor writes lands in the stored snapshot at once, and null removes it", async () => {
  const { db } = await import("../db.js");
  const { patchEc2Tag, ec2Detail } = await import("../inventory.js");
  const id = "i-0f0000000000c0ffee";
  db.prepare("delete from inventory_ec2 where instance_id = ?").run(id);
  db.prepare("insert into inventory_ec2 (instance_id, name, state, region, snapshot) values (?, 'box', 'running', 'us-east-1', ?)")
    .run(id, JSON.stringify({ identity: { instance_id: id }, tags: { Name: "box" } }));
  assert.equal(patchEc2Tag(id, "AdvisorAutoPark", "ON"), true);
  assert.deepEqual(ec2Detail(id)!.snapshot.tags, { Name: "box", AdvisorAutoPark: "ON" });
  assert.equal(patchEc2Tag(id, "AdvisorAutoPark", null), true);
  assert.deepEqual(ec2Detail(id)!.snapshot.tags, { Name: "box" }, "the other tags and the rest of the snapshot are kept");
  assert.equal((ec2Detail(id)!.snapshot as any).identity.instance_id, id);
  assert.equal(patchEc2Tag("i-0f00000000000dead", "AdvisorAutoPark", "ON"), false, "not in the inventory");
  db.prepare("delete from inventory_ec2 where instance_id = ?").run(id);
});

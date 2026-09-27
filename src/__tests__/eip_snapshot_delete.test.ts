import assert from "node:assert/strict";
import { test } from "node:test";
import { eipFacts, eipSkipReason, EIP_USD_MONTH } from "../actions/eip_release.js";
import { deleteFacts, deleteSkipReason, deleteSaving } from "../actions/snapshot_delete.js";

test("eip release: an unattached, untagged address can go; an associated or hands-off one waits", () => {
  const free = eipFacts({ AllocationId: "eipalloc-1", PublicIp: "3.3.3.3", Domain: "vpc", NetworkBorderGroup: "us-east-1", Tags: [{ Key: "Name", Value: "old-lb" }] });
  assert.equal(free.associated, false);
  assert.equal(free.name, "old-lb");
  assert.equal(eipSkipReason(free), null);
  const onInstance = eipFacts({ AllocationId: "eipalloc-2", PublicIp: "3.3.3.4", AssociationId: "eipassoc-1", InstanceId: "i-1" });
  assert.match(eipSkipReason(onInstance)!, /associated now \(instance i-1\)/);
  const onEni = eipFacts({ AllocationId: "eipalloc-3", PublicIp: "3.3.3.5", NetworkInterfaceId: "eni-1" });
  assert.match(eipSkipReason(onEni)!, /interface eni-1/);
  const kept = eipFacts({ AllocationId: "eipalloc-4", PublicIp: "3.3.3.6", Tags: [{ Key: "advisor:hands-off", Value: "" }] });
  assert.equal(eipSkipReason(kept), "tagged advisor:hands-off");
  assert.equal(EIP_USD_MONTH, 3.65);
});

test("snapshot delete: AMI, Backup/DLM, hands-off, pending and archiving snapshots are left alone; the saving follows the tier", () => {
  const base = { SnapshotId: "snap-1", VolumeId: "vol-1", VolumeSize: 100, State: "completed", StorageTier: "standard", StartTime: new Date("2026-01-01T00:00:00Z") };
  const ok = deleteFacts(base as any, [], false);
  assert.equal(deleteSkipReason(ok), null);
  assert.equal(ok.volume_id, "vol-1");
  assert.equal(ok.started, "2026-01-01T00:00:00.000Z");
  assert.match(deleteSkipReason(deleteFacts(base as any, ["ami-1"], false))!, /behind AMI ami-1/);
  assert.match(deleteSkipReason(deleteFacts({ ...base, Tags: [{ Key: "aws:backup:source-resource", Value: "x" }] } as any, [], false))!, /managed by aws:backup/);
  assert.equal(deleteSkipReason(deleteFacts({ ...base, Tags: [{ Key: "advisor:hands-off", Value: "1" }] } as any, [], false)), "tagged advisor:hands-off");
  assert.match(deleteSkipReason(deleteFacts({ ...base, State: "pending" } as any, [], false))!, /state pending/);
  assert.match(deleteSkipReason(deleteFacts(base as any, [], true))!, /archive in flight/);
  // a snapshot copied in from elsewhere has no volume lineage
  assert.equal(deleteFacts({ ...base, VolumeId: "vol-ffffffff" } as any, [], false).volume_id, null);
  assert.equal(deleteSaving(100, "standard"), 5);
  assert.equal(deleteSaving(100, "archive"), 1.25);
  assert.equal(deleteSaving(100, null), 5);
});

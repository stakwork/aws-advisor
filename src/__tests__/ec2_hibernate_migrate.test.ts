import assert from "node:assert/strict";
import { test } from "node:test";
import { carriedTags, launchInput, launchMappings, movedIp, rootTargetGib, skipReason, type Candidate } from "../actions/ec2_hibernate_migrate.js";

const ok: Candidate = {
  mode: "stop", tag_value: "stop", state: "running", hands_off: false, configured: false, root_device_type: "ebs", spot: false, managed_by: null,
  enis: 1, private_ips: 1, source_dest_check: true, instance_store: false, type_supports: true, ram_gib: 8, windows: false, migrated_to: null, in_flight: false,
};

test("hibernate: only a tagged, single-interface, EBS-rooted box on a supported type within the RAM limit is relaunched", () => {
  assert.equal(skipReason(ok), null);
  assert.equal(skipReason({ ...ok, mode: "live" }), null);
  assert.match(skipReason({ ...ok, mode: null, tag_value: null })!, /not tagged advisor:hibernate/);
  assert.match(skipReason({ ...ok, mode: null, tag_value: "yes" })!, /expected "stop".*"live".*or "no"/);
  assert.equal(skipReason({ ...ok, mode: null, tag_value: "no" }), "advisor:hibernate=no: the owner keeps stop/start");
  assert.match(skipReason({ ...ok, configured: true })!, /already hibernation-ready/);
  assert.match(skipReason({ ...ok, migrated_to: "i-new" })!, /already migrated to i-new/);
  assert.match(skipReason({ ...ok, in_flight: true })!, /under way/);
  assert.match(skipReason({ ...ok, reverted_at: "2026-09-29 10:00:00" })!, /reverted 2026-09-29 10:00 UTC: not proposed again for 7 days/);
  assert.equal(skipReason({ ...ok, state: "stopped" }), null, "a stopped box can take the downtime path");
  assert.match(skipReason({ ...ok, mode: "live", state: "stopped" })!, /live migration needs it running/);
  assert.match(skipReason({ ...ok, managed_by: "Auto Scaling group web" })!, /launch template/);
  assert.match(skipReason({ ...ok, enis: 2 })!, /2 network interfaces/);
  assert.match(skipReason({ ...ok, source_dest_check: false })!, /NAT/);
  assert.match(skipReason({ ...ok, instance_store: true })!, /instance-store/);
  assert.match(skipReason({ ...ok, type_supports: false })!, /does not support hibernation/);
  assert.match(skipReason({ ...ok, ram_gib: 192 })!, /150 GiB on Linux/);
  assert.match(skipReason({ ...ok, ram_gib: 32, windows: true })!, /16 GiB on Windows/);
  assert.equal(skipReason({ ...ok, hands_off: true }), "tagged advisor:hands-off");
});

test("hibernate: the root grows only by what the RAM needs beyond the free space, or by the RAM whole when usage is unknown", () => {
  assert.equal(rootTargetGib(30, 8, 20), 30, "6 GiB used + 8 RAM + 1 fits in 30");
  assert.equal(rootTargetGib(8, 4, 50), 9, "4 used + 4 RAM + 1 = 9");
  assert.equal(rootTargetGib(20, 16, null), 36);
  assert.equal(rootTargetGib(20, 15.5, 90), 35);
});

test("hibernate: the launch encrypts every EBS mapping, grows the root, turns hibernation on and does not carry the opt-in tag or the user data", () => {
  const image = { ImageId: "ami-final", RootDeviceName: "/dev/xvda", BlockDeviceMappings: [
    { DeviceName: "/dev/xvda", Ebs: { SnapshotId: "snap-root", VolumeSize: 8, VolumeType: "gp3" as const, DeleteOnTermination: true, Encrypted: false } },
    { DeviceName: "/dev/sdf", Ebs: { SnapshotId: "snap-data", VolumeSize: 100, VolumeType: "gp3" as const, DeleteOnTermination: false, Encrypted: false } },
    { DeviceName: "/dev/sdb", VirtualName: "ephemeral0" },
  ] };
  const maps = launchMappings(image, 17);
  assert.equal(maps.length, 2);
  assert.deepEqual(maps.map((m) => [m.DeviceName, m.Ebs?.Encrypted, m.Ebs?.VolumeSize]), [["/dev/xvda", true, 17], ["/dev/sdf", true, 100]]);
  const old: any = {
    InstanceId: "i-old", InstanceType: "t3.large", KeyName: "ops", SubnetId: "subnet-1", EbsOptimized: true, PublicIpAddress: "3.3.3.3", PrivateIpAddress: "10.0.0.5",
    SecurityGroups: [{ GroupId: "sg-1" }, { GroupId: "sg-2" }], IamInstanceProfile: { Arn: "arn:aws:iam::1:instance-profile/app" }, Monitoring: { State: "disabled" },
    MetadataOptions: { HttpTokens: "required", HttpEndpoint: "enabled", HttpPutResponseHopLimit: 2 }, Placement: { Tenancy: "default" }, NetworkInterfaces: [{}],
    Tags: [{ Key: "Name", Value: "app" }, { Key: "advisor:hibernate", Value: "live" }, { Key: "aws:cloudformation:stack-name", Value: "x" }, { Key: "team", Value: "core" }],
  };
  const withEip = launchInput(old, image, { eip: { allocation_id: "eipalloc-1", public_ip: "3.3.3.3" }, root_target_gib: 17, cpu_credits: "unlimited" }, "tok");
  assert.deepEqual(withEip.HibernationOptions, { Configured: true });
  assert.equal(withEip.ClientToken, "tok");
  assert.equal(withEip.UserData, undefined);
  assert.equal(withEip.NetworkInterfaces?.[0].AssociatePublicIpAddress, false, "the Elastic IP is moved across afterwards");
  assert.deepEqual(withEip.NetworkInterfaces?.[0].Groups, ["sg-1", "sg-2"]);
  assert.deepEqual(withEip.CreditSpecification, { CpuCredits: "unlimited" });
  assert.equal(withEip.MetadataOptions?.HttpTokens, "required");
  const tags = withEip.TagSpecifications?.[0].Tags?.map((t) => t.Key);
  assert.deepEqual(tags, ["Name", "team", "advisor:migrated-from", "advisor:hibernate-migration"]);
  const plain = launchInput(old, image, { eip: null, root_target_gib: 17 }, "tok");
  assert.equal(plain.NetworkInterfaces?.[0].AssociatePublicIpAddress, true, "a plain public address is asked for again");
  assert.equal(plain.CreditSpecification, undefined);
  assert.deepEqual(carriedTags([{ Key: "advisor:parked", Value: "x" }], "i-1", "r").map((t) => t.Key), ["advisor:migrated-from", "advisor:hibernate-migration"]);
});

test("hibernate: a record of the old public address follows the new public one, a private record the new private one", () => {
  const from = { public_ip: "3.3.3.3", private_ip: "10.0.0.5" }, to = { public_ip: "4.4.4.4", private_ip: "10.0.0.9" };
  assert.equal(movedIp({ old_ip: "3.3.3.3" }, from, to), "4.4.4.4");
  assert.equal(movedIp({ old_ip: "10.0.0.5" }, from, to), "10.0.0.9");
  assert.equal(movedIp({ old_ip: "9.9.9.9" }, from, to), null);
});

test("hibernate: the role needs are inside the actuator policy and a staged failure can be reverted", async () => {
  await import("../actions/index.js");
  const { stagedFailure } = await import("../executor.js");
  const { ACTUATOR_NEEDS } = await import("../permissions.js");
  assert.ok(ACTUATOR_NEEDS.ec2_hibernate_migrate.apply.includes("ec2:RunInstances"));
  assert.equal(stagedFailure({ kind: "ec2_hibernate_migrate", status: "failed", facts: { stage: "launching" } } as any), true);
  assert.equal(stagedFailure({ kind: "ec2_hibernate_migrate", status: "failed", facts: {} } as any), false, "failed before anything was done: nothing to undo");
  assert.equal(stagedFailure({ kind: "swarm_park", status: "failed", facts: { stage: "x" } } as any), false);
});

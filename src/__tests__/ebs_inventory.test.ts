import assert from "node:assert/strict";
import { test } from "node:test";
import { deviceKey, matchDisksToVolumes } from "../ebs_inventory.js";

test("deviceKey folds the attachment name, the Xen guest name and the sysfs disk into one key", () => {
  assert.equal(deviceKey("/dev/sda1"), "xvda");
  assert.equal(deviceKey("/dev/xvda1"), "xvda");
  assert.equal(deviceKey("xvda"), "xvda");
  assert.equal(deviceKey("/dev/sdf"), "xvdf");
  assert.equal(deviceKey("/dev/xvdba"), "xvdba");
  assert.equal(deviceKey("nvme0n1p1"), "nvme0n1");
  assert.equal(deviceKey("/dev/nvme1n1"), "nvme1n1");
  assert.equal(deviceKey(null), null);
  assert.equal(deviceKey(""), null);
});

const volumes = [{ volume_id: "vol-root", device: "/dev/sda1" }, { volume_id: "vol-data", device: "/dev/sdf" }];

test("matchDisksToVolumes credits Nitro mounts by the volume id the probe read from the NVMe serial and sums partitions", () => {
  const usage = matchDisksToVolumes([
    { mount: "/", filesystem: "/dev/nvme0n1p1", device: "nvme0n1", volume_id: "vol-root", total_bytes: 100e9, used_bytes: 57e9, used_pct: 57 },
    { mount: "/boot/efi", filesystem: "/dev/nvme0n1p15", device: "nvme0n1", volume_id: "vol-root", total_bytes: 100e6, used_bytes: 6e6, used_pct: 6 },
    { mount: "/data", filesystem: "/dev/nvme1n1", device: "nvme1n1", volume_id: "vol-data", total_bytes: 1000e9, used_bytes: 100e9, used_pct: 10 },
    { mount: "/scratch", filesystem: "/dev/nvme2n1", device: "nvme2n1", volume_id: null, total_bytes: 500e9, used_bytes: 1e9, used_pct: 0.2 }, // instance store
    { mount: "/mnt/efs", filesystem: "fs-1.efs.amazonaws.com:/", device: null, volume_id: null, total_bytes: 9e15, used_bytes: 1e9, used_pct: 0 },
  ], volumes);
  assert.deepEqual([...usage.keys()].sort(), ["vol-data", "vol-root"]);
  const root = usage.get("vol-root")!;
  assert.equal(root.total_bytes, 100.1e9);
  assert.equal(root.used_bytes, 57.006e9);
  assert.equal(root.used_pct, 56.9);
  assert.deepEqual(root.mounts.map((m) => m.mount), ["/", "/boot/efi"]);
  assert.equal(usage.get("vol-data")!.used_pct, 10);
});

test("matchDisksToVolumes falls back to the device name on Xen, and to the filesystem name for probes before 1.3", () => {
  const xen = matchDisksToVolumes([{ mount: "/", filesystem: "/dev/xvda1", device: "xvda", volume_id: null, total_bytes: 10, used_bytes: 5, used_pct: 50 }], volumes);
  assert.equal(xen.get("vol-root")!.used_pct, 50);
  const old = matchDisksToVolumes([
    { mount: "/", filesystem: "/dev/xvda1", total_bytes: 10, used_bytes: 8, used_pct: 80 },
    { mount: "/data", filesystem: "/dev/nvme1n1", total_bytes: 10, used_bytes: 1, used_pct: 10 }, // no serial in an old probe: unknown volume
  ], volumes);
  assert.equal(old.get("vol-root")!.used_pct, 80);
  assert.equal(old.has("vol-data"), false);
});

test("matchDisksToVolumes ignores a volume id the instance does not have", () => {
  const usage = matchDisksToVolumes([{ mount: "/", filesystem: "/dev/nvme0n1p1", device: "nvme0n1", volume_id: "vol-elsewhere", total_bytes: 10, used_bytes: 5, used_pct: 50 }], volumes);
  assert.equal(usage.size, 0);
});

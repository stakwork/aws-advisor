import { test } from "node:test";
import assert from "node:assert";

/** A stand-in for the actuator's EC2 client: records each StopInstances input and fails the ones `refuse` says. */
function fakeEc2(refuse: (input: any) => Error | null = () => null) {
  const calls: any[] = [];
  return { calls, client: { send: async (cmd: any) => { calls.push(cmd.input); const e = refuse(cmd.input); if (e) throw e; return { StoppingInstances: [{ CurrentState: { Name: "stopping" } }] }; } } as any };
}

test("parking hibernates a box launched for it, falls back to a plain stop when EC2 refuses, and respects advisor:hibernate=no", async () => {
  const { shouldHibernate, stopOrHibernate } = await import("../hibernation.js");
  const ready = { InstanceId: "i-0f0000000000c0001", HibernationOptions: { Configured: true }, Tags: [] } as any;
  const plain = { InstanceId: "i-0f0000000000c0002", HibernationOptions: { Configured: false }, Tags: [] } as any;
  const kept = { ...ready, Tags: [{ Key: "advisor:hibernate", Value: "no" }] };
  const able = { ready: true, reason: "the hibernation agent (hibinit-agent) answers the sleep button", source: "probe" } as const;
  assert.equal(shouldHibernate(ready, able), true);
  assert.equal(shouldHibernate(plain, able), false);
  assert.equal(shouldHibernate(kept, able), false, "the owner chose stop/start");
  assert.equal(shouldHibernate(undefined, able), false);

  const a = fakeEc2();
  const r1 = await stopOrHibernate(a.client, ready.InstanceId, ready, able);
  assert.deepEqual(a.calls, [{ InstanceIds: [ready.InstanceId], Hibernate: true }]);
  assert.equal(r1.hibernated, true); assert.equal(r1.line, "StopInstances (hibernate): stopping");

  const b = fakeEc2((input) => (input.Hibernate ? Object.assign(new Error("Instance is not ready to hibernate yet"), { name: "UnsupportedHibernationConfiguration" }) : null));
  const r2 = await stopOrHibernate(b.client, ready.InstanceId, ready, able);
  assert.equal(b.calls.length, 2, "one refused hibernation, then the plain stop");
  assert.equal(b.calls[1].Hibernate, undefined);
  assert.equal(r2.hibernated, false);
  assert.match(r2.line, /hibernation refused, UnsupportedHibernationConfiguration: Instance is not ready to hibernate yet; stopped instead/);

  const c = fakeEc2();
  const r3 = await stopOrHibernate(c.client, plain.InstanceId, plain, able);
  assert.deepEqual(c.calls, [{ InstanceIds: [plain.InstanceId] }]); assert.equal(r3.line, "StopInstances: stopping");
  const d = fakeEc2();
  assert.equal((await stopOrHibernate(d.client, kept.InstanceId, kept, able)).line, "StopInstances: stopping (advisor:hibernate=no: stop/start chosen)");

  // a refused plain stop is still an error the executor records
  const e = fakeEc2(() => Object.assign(new Error("not authorized"), { name: "UnauthorizedOperation" }));
  await assert.rejects(stopOrHibernate(e.client, plain.InstanceId, plain, able), /not authorized/);
});

test("a box launched for hibernation whose guest cannot finish it, or was not looked at, gets a plain stop with the reason", async () => {
  const { shouldHibernate, stopOrHibernate } = await import("../hibernation.js");
  const ready = { InstanceId: "i-0f0000000000c0003", HibernationOptions: { Configured: true }, Tags: [] } as any;
  const missing = { ready: false, reason: "no hibernation agent installed", source: "packages" } as const;
  const unknown = { ready: null, reason: "the software probe has not looked inside this box yet", source: "none" } as const;
  assert.equal(shouldHibernate(ready, missing), false);
  assert.equal(shouldHibernate(ready, unknown), false);
  assert.equal(shouldHibernate(ready, null), false);
  for (const g of [missing, unknown]) {
    const f = fakeEc2();
    const r = await stopOrHibernate(f.client, ready.InstanceId, ready, g);
    assert.deepEqual(f.calls, [{ InstanceIds: [ready.InstanceId] }], "never Hibernate: true");
    assert.equal(r.hibernated, false);
    assert.equal(r.line, `StopInstances: stopping (launched with hibernation, but not hibernated: ${g.reason})`);
  }
});

test("guestReadiness: the probe's reading first, the agent package as fallback, no package is unknown, not ready", async () => {
  const { guestReadiness } = await import("../guest_hibernation.js");
  const G = 1024 ** 3;
  const base = { kernel_disk: true, cmdline_resume: true, sys_resume: "259:1", agent: null, acpi_sleep_handler: false, logind_suspend_key: "hibernate", swap_active_bytes: 0, swap_file_bytes: 8 * G, mem_bytes: 8 * G };
  const v = (probe: any, agent_package: string | null = null, packages_known = true) => guestReadiness({ probe, agent_package, packages_known });
  assert.equal(v(base).ready, true, "logind hibernates, swap as big as the RAM, resume set");
  assert.equal(v({ ...base, logind_suspend_key: null, agent: "hibinit-agent", swap_file_bytes: 0, cmdline_resume: false }).ready, true, "the agent makes its own swap and resume");
  assert.match(v({ ...base, kernel_disk: false, agent: "hibinit-agent" }).reason, /kernel offers no hibernation/);
  // a Debian 12 box from an image of a box that never hibernated: nothing answers the sleep button
  const debian = v({ ...base, logind_suspend_key: null, cmdline_resume: false, sys_resume: "0:0", swap_file_bytes: 0 });
  assert.equal(debian.ready, false); assert.match(debian.reason, /nothing in the guest answers EC2's sleep button/);
  assert.match(v({ ...base, logind_suspend_key: "suspend" }).reason, /HandleSuspendKey=suspend/);
  assert.match(v({ ...base, acpi_sleep_handler: true, logind_suspend_key: null, swap_file_bytes: 2 * G }).reason, /swap \(2\.0 GiB\) is smaller than the RAM \(8\.0 GiB\)/);
  assert.match(v({ ...base, cmdline_resume: false, sys_resume: "0:0" }).reason, /no resume=/);
  assert.equal(v({ ...base, cmdline_resume: false, sys_resume: "259:1" }).ready, true, "a resume device set at runtime counts");
  assert.deepEqual(v(null, "ec2-hibinit-agent"), { ready: true, reason: "the hibernation agent package (ec2-hibinit-agent) is installed", source: "packages" });
  // no reading and no package: a logind setup has no package, so this is unknown, never "cannot"
  assert.equal(v(null, null, true).ready, null); assert.match(v(null, null, true).reason, /predates the hibernation check/);
  assert.equal(v(null, null, false).ready, null);
});

test("parseProbeOutput keeps software 3's hibernation section, so the readiness verdict sees it", async () => {
  const { parseProbeOutput } = await import("../ssm.js");
  const { guestReadiness } = await import("../guest_hibernation.js");
  const G = 1024 ** 3;
  // a Debian box set up by hand: no agent package, logind answers the sleep button, an 8 GiB swap file, resume= set
  const hib = { kernel_disk: true, cmdline_resume: true, sys_resume: "259:1", agent: null, acpi_sleep_handler: false, logind_suspend_key: "hibernate", swap_active_bytes: 8 * G, swap_file_bytes: 8 * G, mem_bytes: 8 * G - 200 * 1024 ** 2 };
  const line = JSON.stringify({ probe: "aws-advisor/software/3", kind: "software", hostname: "box", collected_at: "2026-10-09T03:11:11Z", os: { id: "debian", version: "12", name: "Debian GNU/Linux 12" }, kernel: "6.1.0", arch: "x86_64", package_manager: "deb", packages: [{ n: "bash", v: "5.2", a: "amd64" }], binaries: [], images: [], hibernation: hib });
  const data = parseProbeOutput(`noise\n${line}\n`);
  assert.deepEqual(data.hibernation, hib);
  const v = guestReadiness({ probe: data.hibernation!, agent_package: null, packages_known: true });
  assert.equal(v.ready, true); assert.match(v.reason, /logind \(HandleSuspendKey=hibernate\)/);
  // software 2 has no section: nothing is invented
  assert.equal(parseProbeOutput(line.replace(/,"hibernation":\{[^}]*\}/, "")).hibernation, undefined);
});

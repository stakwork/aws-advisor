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
  assert.equal(shouldHibernate(ready), true);
  assert.equal(shouldHibernate(plain), false);
  assert.equal(shouldHibernate(kept), false, "the owner chose stop/start");
  assert.equal(shouldHibernate(undefined), false);

  const a = fakeEc2();
  const r1 = await stopOrHibernate(a.client, ready.InstanceId, ready);
  assert.deepEqual(a.calls, [{ InstanceIds: [ready.InstanceId], Hibernate: true }]);
  assert.equal(r1.hibernated, true); assert.equal(r1.line, "StopInstances (hibernate): stopping");

  const b = fakeEc2((input) => (input.Hibernate ? Object.assign(new Error("Instance is not ready to hibernate yet"), { name: "UnsupportedHibernationConfiguration" }) : null));
  const r2 = await stopOrHibernate(b.client, ready.InstanceId, ready);
  assert.equal(b.calls.length, 2, "one refused hibernation, then the plain stop");
  assert.equal(b.calls[1].Hibernate, undefined);
  assert.equal(r2.hibernated, false);
  assert.match(r2.line, /hibernation refused, UnsupportedHibernationConfiguration: Instance is not ready to hibernate yet; stopped instead/);

  const c = fakeEc2();
  const r3 = await stopOrHibernate(c.client, plain.InstanceId, plain);
  assert.deepEqual(c.calls, [{ InstanceIds: [plain.InstanceId] }]); assert.equal(r3.line, "StopInstances: stopping");
  const d = fakeEc2();
  assert.equal((await stopOrHibernate(d.client, kept.InstanceId, kept)).line, "StopInstances: stopping (advisor:hibernate=no: stop/start chosen)");

  // a refused plain stop is still an error the executor records
  const e = fakeEc2(() => Object.assign(new Error("not authorized"), { name: "UnauthorizedOperation" }));
  await assert.rejects(stopOrHibernate(e.client, plain.InstanceId, plain), /not authorized/);
});

import assert from "node:assert/strict";
import { test } from "node:test";
import { db } from "../db.js";
import { InstanceStatusRow, describeEvents, recordInstanceStatus, statusEvents, statusTransitions, statusVerdicts } from "../status_checks.js";

const base = (over: Partial<InstanceStatusRow> = {}): InstanceStatusRow => ({ instance_id: "i-status00000000001", account_id: "1", region: "us-east-1", system_status: "ok", instance_status: "ok", ebs_status: "ok", events: [], checked_at: "2026-09-28T10:00:00Z", ...over });

test("status transitions: every field that changed, and a first reading counts from null", () => {
  assert.deepEqual(statusTransitions(null, base()).map((t) => `${t.field}:${t.from}>${t.to}`), ["system_status:null>ok", "instance_status:null>ok", "ebs_status:null>ok"]);
  assert.deepEqual(statusTransitions(base(), base({ instance_status: "impaired" })), [{ field: "instance_status", from: "ok", to: "impaired" }]);
  assert.deepEqual(statusTransitions(base(), base({ ebs_status: null })), [], "a field the API did not return is not a change");
});

test("status verdicts: one alert while any check is impaired, closed when they pass; no data is neither", () => {
  const sys = statusVerdicts(base({ system_status: "impaired" }), false);
  assert.match(sys.raise!.message, /^system status check failing \(AWS-side: hardware or network under the box/);
  const both = statusVerdicts(base({ system_status: "impaired", instance_status: "impaired", events: [{ code: "system-reboot", description: null, not_before: "2026-09-29T02:00:00Z", not_after: null }] }), false);
  assert.match(both.raise!.message, /^system and instance status checks failing .*; AWS scheduled: system-reboot from 2026-09-29 02:00 UTC$/);
  assert.equal(statusVerdicts(base({ ebs_status: "impaired" }), true).raise, null, "not raised twice while open");
  assert.deepEqual(statusVerdicts(base(), true), { raise: null, close: true });
  assert.deepEqual(statusVerdicts(base({ system_status: "insufficient-data", instance_status: "insufficient-data", ebs_status: "insufficient-data" }), true), { raise: null, close: false }, "no data is not good news yet");
  assert.deepEqual(statusVerdicts(base({ system_status: "insufficient-data", instance_status: "insufficient-data" }), true), { raise: null, close: true }, "one check passing again is enough to close");
  assert.deepEqual(describeEvents([{ code: "instance-retirement", description: "x", not_before: "2026-10-01T00:00:00Z", not_after: null }, { code: null, description: null, not_before: null, not_after: null }]), ["instance-retirement from 2026-10-01 00:00 UTC"]);
});

test("recording a status: events on change, an alert when a check goes impaired, closed by the system when it recovers", () => {
  const id = "i-status00000000001";
  db.prepare("delete from instance_status where instance_id = ?").run(id); db.prepare("delete from instance_status_events where instance_id = ?").run(id); db.prepare("delete from alerts where resource = ?").run(id);
  const first = recordInstanceStatus(base(), "web-1");
  assert.equal(first.transitions.length, 3); assert.equal(first.raised, false);
  assert.equal(statusEvents({ instance_id: id }).length, 0, "a clean first reading is not an event");
  const down = recordInstanceStatus(base({ instance_status: "impaired", checked_at: "2026-09-28T10:30:00Z" }), "web-1");
  assert.equal(down.raised, true);
  const ev = statusEvents({ instance_id: id });
  assert.equal(ev.length, 1); assert.equal(ev[0].field, "instance_status"); assert.equal(ev[0].from_status, "ok"); assert.equal(ev[0].to_status, "impaired");
  const alert = db.prepare("select message from alerts where resource = ? and kind = 'status_check_failed' and acknowledged = 0").get(id) as any;
  assert.match(alert.message, /^web-1 \(i-status00000000001\): instance status check failing \(the OS is not reachable/);
  const still = recordInstanceStatus(base({ instance_status: "impaired", checked_at: "2026-09-28T11:00:00Z" }), "web-1");
  assert.equal(still.raised, false); assert.equal(still.transitions.length, 0);
  const up = recordInstanceStatus(base({ checked_at: "2026-09-28T11:30:00Z" }), "web-1");
  assert.equal(up.closed, true);
  assert.equal((db.prepare("select acknowledged_by from alerts where resource = ? and kind = 'status_check_failed'").get(id) as any).acknowledged_by, "system");
  assert.equal(statusEvents({ instance_id: id }).length, 2);
  db.prepare("delete from instance_status where instance_id = ?").run(id); db.prepare("delete from instance_status_events where instance_id = ?").run(id); db.prepare("delete from alerts where resource = ?").run(id);
});

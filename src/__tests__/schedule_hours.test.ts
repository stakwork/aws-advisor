import assert from "node:assert/strict";
import { test } from "node:test";
import { decideSchedule, describeSchedule, nextHour, offHoursPerWeek, parseSchedule, wantedState, type Schedule } from "../actions/schedule_hours.js";

const sched = (tag: string): Schedule => { const s = parseSchedule(tag); if ("error" in s) throw new Error(s.error); return s; };

test("schedule tag: weekdays, ranges, lists, minutes, time zones and overnight windows parse", () => {
  const w = sched("weekdays 08-20");
  assert.deepEqual([...w.days].sort(), [1, 2, 3, 4, 5]); assert.equal(w.start, 8); assert.equal(w.end, 20); assert.equal(w.tz, "UTC");
  const r = sched("mon-fri 08:00-20:00 Europe/Madrid");
  assert.deepEqual([...r.days].sort(), [1, 2, 3, 4, 5]); assert.equal(r.tz, "Europe/Madrid");
  const l = sched("mon,tue,wed 09-18");
  assert.deepEqual([...l.days].sort(), [1, 2, 3]);
  assert.equal(sched("daily 07-23 America/Argentina/Buenos_Aires").days.size, 7);
  assert.deepEqual([...sched("weekends 10-16").days].sort(), [0, 6]);
  // a range that wraps the week
  assert.deepEqual([...sched("fri-mon 00-24").days].sort(), [0, 1, 5, 6]);
  const night = sched("Weekdays 22-06");
  assert.equal(night.start, 22); assert.equal(night.end, 6);
  assert.equal(sched("daily 00-24").end, 0);
  assert.equal(describeSchedule(w), "weekdays 08:00-20:00 UTC");
  assert.equal(describeSchedule(l), "mon,tue,wed 09:00-18:00 UTC");
});

test("schedule tag: what is not understood says why", () => {
  const err = (t: string) => { const s = parseSchedule(t); assert.ok("error" in s, `${t} should fail`); return s.error; };
  assert.match(err(""), /expected/);
  assert.match(err("weekdays"), /expected/);
  assert.match(err("someday 08-20"), /days are/);
  assert.match(err("weekdays 8am-8pm"), /HH-HH/);
  assert.match(err("weekdays 08:30-20:00"), /whole hours/);
  assert.match(err("weekdays 08-08"), /not the same hour/);
  assert.match(err("weekdays 08-25"), /end 01-24/);
  assert.match(err("weekdays 08-20 Mars/Olympus"), /IANA time zone/);
  assert.match(err("weekdays 08-20 Europe/Madrid extra"), /expected/);
});

test("wanted state: boundaries in a non-UTC zone, days off, and overnight windows", () => {
  const madrid = sched("weekdays 08-20 Europe/Madrid");
  // 2026-09-28 is a Monday; Madrid is UTC+2 in September
  assert.equal(wantedState(madrid, new Date("2026-09-28T05:00:00Z")), "stopped"); // 07:00 local
  assert.equal(wantedState(madrid, new Date("2026-09-28T06:00:00Z")), "running"); // 08:00 local
  assert.equal(wantedState(madrid, new Date("2026-09-28T17:00:00Z")), "running"); // 19:00 local
  assert.equal(wantedState(madrid, new Date("2026-09-28T18:00:00Z")), "stopped"); // 20:00 local
  assert.equal(wantedState(madrid, new Date("2026-09-26T10:00:00Z")), "stopped"); // Saturday
  // the local day, not the UTC day, decides: Sunday 23:30 UTC is Monday 01:30 in Madrid (still outside 08-20)
  assert.equal(wantedState(sched("mon 00-03 Europe/Madrid"), new Date("2026-09-27T23:30:00Z")), "running");
  const night = sched("weekdays 22-06");
  assert.equal(wantedState(night, new Date("2026-09-28T22:00:00Z")), "running"); // Monday evening
  assert.equal(wantedState(night, new Date("2026-09-29T03:00:00Z")), "running"); // Tuesday early morning belongs to Monday
  assert.equal(wantedState(night, new Date("2026-09-29T06:00:00Z")), "stopped");
  assert.equal(wantedState(night, new Date("2026-09-26T03:00:00Z")), "running"); // Saturday 03:00 belongs to Friday night
  assert.equal(wantedState(night, new Date("2026-09-27T03:00:00Z")), "stopped"); // Sunday 03:00 belongs to Saturday
  assert.equal(wantedState(night, new Date("2026-09-28T12:00:00Z")), "stopped");
});

test("next hour: a pass at :45 decides for the top of the coming hour", () => {
  assert.equal(nextHour(new Date("2026-09-28T07:45:00Z")).toISOString(), "2026-09-28T08:00:00.000Z");
  assert.equal(nextHour(new Date("2026-09-28T08:00:00Z")).toISOString(), "2026-09-28T09:00:00.000Z");
  assert.equal(nextHour(new Date("2026-09-28T23:59:59Z")).toISOString(), "2026-09-29T00:00:00.000Z");
});

test("decision: running outside → stop, stopped inside → start, otherwise leave, transitional states wait", () => {
  const s = sched("weekdays 08-20");
  const at = (iso: string) => new Date(iso);
  const stop = decideSchedule(s, "running", at("2026-09-28T19:45:00Z")); // 20:00 is outside
  assert.equal(stop.action, "stop"); assert.match(stop.reason, /mon 20:00 UTC is outside/);
  assert.equal(decideSchedule(s, "running", at("2026-09-28T18:45:00Z")).action, null); // 19:00 still inside
  const start = decideSchedule(s, "stopped", at("2026-09-28T07:45:00Z")); // 08:00 is inside
  assert.equal(start.action, "start"); assert.match(start.reason, /mon 08:00 UTC is inside/);
  assert.equal(decideSchedule(s, "stopped", at("2026-09-28T06:45:00Z")).action, null);
  assert.equal(decideSchedule(s, "stopped", at("2026-09-26T07:45:00Z")).action, null); // Saturday stays stopped
  const wait = decideSchedule(s, "stopping", at("2026-09-28T07:45:00Z"));
  assert.equal(wait.action, null); assert.match(wait.reason, /waiting/);
  assert.equal(stop.target.toISOString(), "2026-09-28T20:00:00.000Z");
});

test("dns flip on sleep: only with a profile asking for it, no Elastic IP, records naming the box and a doorman address", async () => {
  const { dnsParkPlan } = await import("../actions/schedule_hours.js");
  const rec = { zone_id: "Z0000000EXAMPLE1", name: "app.example.com", ttl: 300, values: ["203.0.113.10"], routing: null, old_ip: "203.0.113.10" };
  const dns = { front_door: "dns" as const }, eip = { front_door: "eip" as const };
  assert.deepEqual(dnsParkPlan({ profile: null, elasticIp: false, records: [rec], doormanIp: "198.51.100.5" }), { skip: "no wake profile" });
  assert.match((dnsParkPlan({ profile: eip, elasticIp: false, records: [rec], doormanIp: "198.51.100.5" }) as any).skip, /front door is eip/);
  assert.match((dnsParkPlan({ profile: dns, elasticIp: true, records: [rec], doormanIp: "198.51.100.5" }) as any).skip, /Elastic IP/);
  assert.match((dnsParkPlan({ profile: dns, elasticIp: false, records: [], doormanIp: "198.51.100.5" }) as any).skip, /no A record/);
  assert.match((dnsParkPlan({ profile: dns, elasticIp: false, records: [rec], doormanIp: "" }) as any).skip, /no doorman public address/);
  assert.match((dnsParkPlan({ profile: dns, elasticIp: false, records: [{ ...rec, old_ip: "198.51.100.5" }], doormanIp: "198.51.100.5" }) as any).skip, /already point/);
  assert.deepEqual(dnsParkPlan({ profile: dns, elasticIp: false, records: [rec], doormanIp: "198.51.100.5" }), { to: "198.51.100.5", records: [rec] });
});

test("dns upsert: a plain record stays plain whatever the stored routing says; a routed record keeps its policy", async () => {
  const { upsertChange } = await import("../actions/schedule_hours.js");
  const base = { zone_id: "Z0000000EXAMPLE1", name: "app.example.com", ttl: 300, values: ["203.0.113.10"], old_ip: "203.0.113.10" };
  // what older inventories stored on every record: the table's region column, which Route 53 would read as a latency policy
  const plain = upsertChange({ ...base, routing: { region: "global" } }, "203.0.113.20").ResourceRecordSet;
  assert.deepEqual(plain, { Name: "app.example.com", Type: "A", TTL: 300, ResourceRecords: [{ Value: "203.0.113.20" }] });
  const routed = upsertChange({ ...base, routing: { set_identifier: "eu", latency_region: "eu-west-1", region: "global" } }, "203.0.113.20").ResourceRecordSet;
  assert.equal(routed.SetIdentifier, "eu"); assert.equal(routed.Region, "eu-west-1");
  assert.deepEqual(upsertChange({ ...base, routing: null }, "203.0.113.20").Action, "UPSERT");
});

test("off hours: what a stop saves per week", () => {
  assert.equal(offHoursPerWeek(sched("weekdays 08-20")), 168 - 60);
  assert.equal(offHoursPerWeek(sched("daily 00-24")), 0);
  assert.equal(offHoursPerWeek(sched("weekdays 22-06")), 168 - 40);
});

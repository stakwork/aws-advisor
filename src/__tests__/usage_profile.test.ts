import assert from "node:assert/strict";
import { test } from "node:test";
import { db } from "../db.js";
import { buildProfile, bucketize, latestProfile, probeMarks, quietWindows, ringIndex, sampleQuiet, storeProfile, suggestSchedule, MARGIN_HOURS, MIN_WINDOW_HOURS, WINDOW_DAYS, type HourSample, type ProbeMark } from "../usage_profile.js";
import { decideWindow } from "../actions/beanstalk_scale.js";
import { recordsNamingIp, upsertChange } from "../actions/schedule_hours.js";

const H = 3600000;
// 2026-09-06 is a Sunday: the window starts on a Sunday 00:00 UTC so ring indexes read directly
const START = Date.UTC(2026, 8, 6, 0, 0, 0);
const quietMark: ProbeMark = { ext_conn: 0, users_now: 0, signals_recent: false, request_recent: false, login_recent: false, logs_recent: true, container_busy: false };
const busyMark: ProbeMark = { ...quietMark, ext_conn: 2, signals_recent: true };

/** Four weeks of hourly samples; `busy(day, hour, week)` says which are busy; `off` hours have no CloudWatch point. */
function samples(busy: (day: number, hour: number, week: number) => boolean, opts: { probes?: (day: number, hour: number) => boolean; off?: (day: number, hour: number) => boolean } = {}): HourSample[] {
  const out: HourSample[] = [];
  for (let h = 0; h < WINDOW_DAYS * 24; h++) {
    const at = START + h * H; const d = new Date(at); const day = d.getUTCDay(), hour = d.getUTCHours(), week = Math.floor(h / 168);
    if (opts.off?.(day, hour)) { out.push({ at, cpu_avg: null, cpu_max: null, net_bytes: null, requests: null, probes: [] }); continue; }
    const b = busy(day, hour, week);
    out.push({ at, cpu_avg: b ? 35 : 2, cpu_max: b ? 70 : 4, net_bytes: b ? 50e6 : 1e6, requests: null, probes: opts.probes?.(day, hour) ? [b ? busyMark : quietMark] : [] });
  }
  return out;
}
const office = (day: number, hour: number) => day >= 1 && day <= 5 && hour >= 8 && hour < 18;

test("usage profile: an hour is quiet only when CPU, network, requests and every probe agree", () => {
  const base: HourSample = { at: START, cpu_avg: 1, cpu_max: 3, net_bytes: 1e5, requests: null, probes: [] };
  assert.equal(sampleQuiet(base), true);
  assert.equal(sampleQuiet({ ...base, cpu_max: 12 }), false);
  assert.equal(sampleQuiet({ ...base, net_bytes: 6e6 }), false);
  assert.equal(sampleQuiet({ ...base, requests: 1 }), false);
  assert.equal(sampleQuiet({ ...base, probes: [quietMark] }), true, "a log line alone is not use");
  assert.equal(sampleQuiet({ ...base, probes: [{ ...quietMark, login_recent: true }] }), false);
  assert.equal(sampleQuiet({ ...base, probes: [{ ...quietMark, container_busy: true }] }), false);
  assert.equal(sampleQuiet({ ...base, cpu_max: null }), false, "no CloudWatch point is no evidence");
  assert.equal(ringIndex(Date.UTC(2026, 8, 7, 9)), 33); // Monday 09:00
});

test("usage profile: office hours make weekday days busy, nights and weekends quiet, with windows and a schedule", () => {
  const p = buildProfile({ subject: "i-1", kind: "ec2", samples: samples((d, h) => office(d, h), { probes: () => true }), monthly_usd: 100 });
  const at = (day: number, hour: number) => p.hours[day * 24 + hour];
  assert.equal(at(1, 9).verdict, "busy"); assert.equal(at(1, 3).verdict, "quiet"); assert.equal(at(0, 12).verdict, "quiet");
  assert.equal(at(1, 9).seen, 4); assert.equal(at(1, 9).quiet, 0); assert.equal(at(1, 3).quiet, 4);
  assert.equal(p.quiet_hours_week, 168 - 50);
  // the weekend run: Fri 18:00 → Mon 08:00 is 62 h, margins leave 60
  const weekend = p.quiet_windows[0];
  assert.equal(weekend.hours, 62); assert.equal(weekend.effective_hours, 60); assert.equal(weekend.label, "Fri 19:00 → Mon 07:00");
  assert.equal(weekend.confidence, 1); assert.equal(weekend.probe_coverage, 1);
  // a weeknight: 18:00 → 08:00 is 14 h, 12 effective
  assert.equal(p.quiet_windows.filter((w) => w.hours === 14).length, 4);
  assert.equal(p.confidence, 1);
  assert.equal(p.suggested_schedule, "weekdays 07-19 UTC");
  assert.equal(p.off_hours_week, 168 - 5 * 12);
  assert.equal(p.est_usd_month, Math.round(100 * (108 / 168) * 100) / 100);
  assert.match(p.summary, /quiet 118 of 168 hours a week over 4 weeks/);
  assert.match(p.summary, /schedule that keeps it up whenever it was used: weekdays 07-19 UTC/);
});

test("usage profile: one busy week poisons the hour, too few weeks are unknown, and CloudWatch alone caps the confidence", () => {
  // the third week has a Saturday afternoon of work
  const p = buildProfile({ subject: "i-2", kind: "ec2", samples: samples((d, h, w) => office(d, h) || (w === 2 && d === 6 && h >= 14 && h < 16)) });
  assert.equal(p.hours[6 * 24 + 14].verdict, "busy"); assert.equal(p.hours[6 * 24 + 14].quiet, 3);
  assert.equal(p.suggested_schedule, "mon,tue,wed,thu,fri,sat 07-19 UTC");
  assert.equal(p.signals.probes, 0);
  assert.equal(p.quiet_windows[0].confidence, 0.6, "no probes: 0.6 at most");
  assert.match(p.summary, /CloudWatch only/);
  // a box off (no point) on weekends for two of the weeks: weekend hours seen twice → unknown
  const off = buildProfile({ subject: "i-3", kind: "ec2", samples: samples((d, h) => office(d, h), { off: (d) => d === 0 || d === 6 }) });
  assert.equal(off.hours[0].verdict, "unknown"); assert.equal(off.hours[0].seen, 0);
  assert.equal(off.suggested_schedule, "weekdays 07-19 UTC", "hours the box was never on do not extend the window");
  // too few weeks (seen, but under MIN_WEEKS) is unknown and does stay inside the window
  const few = buildProfile({ subject: "i-3b", kind: "ec2", samples: samples((d, h) => office(d, h), { off: (d, h) => d === 6 && h >= 10 && h < 12 }).map((x) => (new Date(x.at).getUTCDay() === 6 && new Date(x.at).getUTCHours() === 10 && x.at < START + 14 * 86400000 ? { ...x, cpu_avg: 2, cpu_max: 4, net_bytes: 1e6 } : x)) });
  assert.equal(few.hours[6 * 24 + 10].verdict, "unknown"); assert.equal(few.hours[6 * 24 + 10].seen, 2);
  assert.equal(few.suggested_schedule, "mon,tue,wed,thu,fri,sat 07-19 UTC");
});

test("usage profile: a box used around the clock or never gets no schedule", () => {
  const allBusy = buildProfile({ subject: "i-4", kind: "ec2", samples: samples(() => true) });
  assert.equal(allBusy.quiet_windows.length, 0); assert.equal(allBusy.suggested_schedule, null); assert.match(allBusy.summary, /no quiet stretch/);
  const never = buildProfile({ subject: "i-5", kind: "ec2", samples: samples(() => false) });
  assert.equal(never.quiet_windows.length, 1); assert.equal(never.quiet_windows[0].label, "all week"); assert.equal(never.suggested_schedule, null); assert.match(never.summary, /never used in the window: parking/);
  // a quiet run shorter than the minimum is not a window
  const hours = bucketize(samples((d, h) => !(h >= 2 && h < 2 + MIN_WINDOW_HOURS - 1)));
  assert.equal(quietWindows(hours, 4).length, 0);
  assert.equal(suggestSchedule(hours), null, "busy 22 h a day: no schedule");
  assert.ok(MARGIN_HOURS >= 1);
});

test("usage profile: probes in the tables become marks on their hour, and the profile stores and reads back", () => {
  db.prepare("delete from instance_activity where instance_id = 'i-probe'").run();
  db.prepare("delete from container_samples where instance_id = 'i-probe'").run();
  db.prepare("insert into instance_activity(instance_id, collected_at, external_connections, users_now, ssh_sessions, last_signal_at, last_request_at, last_login_at, last_log_at) values ('i-probe', '2026-09-07 09:12:00', 3, 0, 1, '2026-09-07 09:05:00', null, '2026-09-06 08:00:00', '2026-09-07 09:11:00')").run();
  db.prepare("insert into container_samples(instance_id, collected_at, name, cpu_pct) values ('i-probe', '2026-09-07 09:12:00', 'relay', 12.5)").run();
  const marks = probeMarks("i-probe", Date.UTC(2026, 8, 1));
  const m = marks.get(Date.UTC(2026, 8, 7, 9))!;
  assert.equal(m.length, 1);
  assert.deepEqual(m[0], { ext_conn: 3, users_now: 1, signals_recent: true, request_recent: false, login_recent: false, logs_recent: true, container_busy: true });
  const p = buildProfile({ subject: "i-probe", kind: "ec2", samples: samples((d, h) => office(d, h)) });
  storeProfile(p);
  const back = latestProfile("i-probe")!;
  assert.equal(back.hours.length, 168); assert.equal(back.suggested_schedule, p.suggested_schedule); assert.equal(back.quiet_windows.length, p.quiet_windows.length);
  db.prepare("delete from usage_profiles where subject = 'i-probe'").run();
  db.prepare("delete from instance_activity where instance_id = 'i-probe'").run();
  db.prepare("delete from container_samples where instance_id = 'i-probe'").run();
});

test("usage profile: a group's balancer requests count as use evidence, so its confidence is not capped at 0.6", () => {
  const withLb = buildProfile({ subject: "asg:web", kind: "asg", samples: samples((d, h) => office(d, h)).map((x) => ({ ...x, requests: office(new Date(x.at).getUTCDay(), new Date(x.at).getUTCHours()) ? 500 : 0 })) });
  assert.equal(withLb.confidence, 1); assert.match(withLb.summary, /balancer's request count covers 100 %/);
  const noLb = buildProfile({ subject: "asg:bare", kind: "asg", samples: samples((d, h) => office(d, h)) });
  assert.equal(noLb.confidence, 0.6); assert.match(noLb.summary, /no balancer in front of the group/);
});

test("beanstalk window: the floor before two quiet hours, the baseline back before a working hour, the owner's change becomes the baseline", () => {
  const p = buildProfile({ subject: "asg:web", kind: "asg", samples: samples((d, h) => office(d, h), { probes: () => true }) });
  const base = { windows: p.quiet_windows, confidence: p.confidence, floor: 1, baseline_min: 3, last_set: null as number | null };
  // Monday 22:00 coming, quiet through the night: drop
  const night = decideWindow({ ...base, current_min: 3, next: 24 + 22 });
  assert.equal(night.wanted, 1); assert.equal(night.active, true); assert.match(night.reason, /quiet hours/);
  // Tuesday 07:00 coming (the window ends at 07:00, a working hour by the margin): back to 3
  const morning = decideWindow({ ...base, current_min: 1, last_set: 1, next: 2 * 24 + 7 });
  assert.equal(morning.wanted, 3); assert.match(morning.reason, /working hour/);
  // already at the floor in the night, already at the baseline by day: nothing
  assert.equal(decideWindow({ ...base, current_min: 1, last_set: 1, next: 24 + 23 }).wanted, null);
  assert.equal(decideWindow({ ...base, current_min: 3, next: 2 * 24 + 10 }).wanted, null);
  // the owner set 4 by hand: that is the new baseline, and the night drop still goes to the floor
  const changed = decideWindow({ ...base, current_min: 4, last_set: 1, next: 24 + 22 });
  assert.equal(changed.baseline_min, 4); assert.equal(changed.wanted, 1);
  // a profile without confident windows is not scheduled from
  const none = decideWindow({ ...base, windows: p.quiet_windows.map((w) => ({ ...w, confidence: 0.5 })), current_min: 3, next: 24 + 22 });
  assert.equal(none.active, false); assert.equal(none.wanted, null);
});

test("office hours: the A records naming an address are found and the UPSERT swaps the address, keeping the routing", () => {
  db.prepare("delete from inventory_route53_record where id like 'Z1|%'").run();
  const now = "2026-09-29T00:00:00.000Z";
  db.prepare(`insert into inventory_route53_record(id, zone_id, zone_name, name, type, ttl, alias, "values", alias_target, routing, health_check_id, link_state, target, summary, links, first_seen, last_seen, gone)
    values ('Z1|app.example.com|A|', 'Z1', 'example.com', 'app.example.com', 'A', 60, 0, '["3.3.3.3"]', null, null, null, 'linked', '3.3.3.3', 'instance', '[]', ?, ?, 0)`).run(now, now);
  db.prepare(`insert into inventory_route53_record(id, zone_id, zone_name, name, type, ttl, alias, "values", alias_target, routing, health_check_id, link_state, target, summary, links, first_seen, last_seen, gone)
    values ('Z1|w.example.com|A|blue', 'Z1', 'example.com', 'w.example.com', 'A', 300, 0, '["3.3.3.3","4.4.4.4"]', null, '{"set_identifier":"blue","weight":10}', null, 'linked', '3.3.3.3', 'instance', '[]', ?, ?, 0)`).run(now, now);
  const recs = recordsNamingIp("3.3.3.3");
  assert.deepEqual(recs.map((r) => r.name).sort(), ["app.example.com", "w.example.com"]);
  assert.equal(recordsNamingIp("9.9.9.9").length, 0);
  const w = recs.find((r) => r.name === "w.example.com")!;
  const change = upsertChange(w, "5.5.5.5");
  assert.equal(change.Action, "UPSERT");
  assert.deepEqual(change.ResourceRecordSet.ResourceRecords, [{ Value: "5.5.5.5" }, { Value: "4.4.4.4" }]);
  assert.equal(change.ResourceRecordSet.SetIdentifier, "blue"); assert.equal(change.ResourceRecordSet.Weight, 10); assert.equal(change.ResourceRecordSet.TTL, 300);
  const simple = upsertChange(recs.find((r) => r.name === "app.example.com")!, "5.5.5.5");
  assert.equal(simple.ResourceRecordSet.SetIdentifier, undefined); assert.equal(simple.ResourceRecordSet.TTL, 60);
  db.prepare("delete from inventory_route53_record where id like 'Z1|%'").run();
});

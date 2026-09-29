import assert from "node:assert/strict";
import { test } from "node:test";
import { db } from "../db.js";
import { buildProfile, storeProfile, type HourSample } from "../usage_profile.js";
import { candidateSchedules, latestReview, reviewState, reviewVerdict, scheduleFor, MIN_CHOICE_CONFIDENCE } from "../usage_review.js";

const H = 3600000; const START = Date.UTC(2026, 8, 6);
const office = (d: number, h: number) => d >= 1 && d <= 5 && h >= 8 && h < 18;
const samples = (busy: (d: number, h: number) => boolean): HourSample[] => Array.from({ length: 28 * 24 }, (_, i) => { const at = START + i * H; const d = new Date(at); const b = busy(d.getUTCDay(), d.getUTCHours()); return { at, cpu_avg: b ? 30 : 2, cpu_max: b ? 60 : 4, net_bytes: b ? 50e6 : 1e6, requests: null, probes: [] }; });

test("usage review: the candidates are the profile's window, a wider one, weekdays when the profile runs daily, and keep running", () => {
  const p = buildProfile({ subject: "i-r1", kind: "ec2", samples: samples(office) });
  const c = candidateSchedules(p);
  assert.equal(c.profile.split(":")[0], "weekdays 07-19 UTC");
  assert.equal(c.wider.split(":")[0], "weekdays 06-20 UTC");
  assert.equal(c.weekdays, undefined, "already weekdays");
  assert.ok(c.keep_running);
  const daily = buildProfile({ subject: "i-r2", kind: "ec2", samples: samples((d, h) => h >= 8 && h < 18) });
  assert.equal(candidateSchedules(daily).weekdays.split(":")[0], "weekdays 07-19 UTC");
  assert.match(candidateSchedules(daily).weekdays, /some weekend hours were busy/);
  const never = buildProfile({ subject: "i-r3", kind: "ec2", samples: samples(() => true) });
  assert.deepEqual(Object.keys(candidateSchedules(never)), ["keep_running"]);
});

test("usage review: the verdict follows Jev's pick, downgraded to keep running when unsure or when the quiet windows are doubted", () => {
  const p = buildProfile({ subject: "i-r1", kind: "ec2", samples: samples(office), monthly_usd: 100 });
  const options = candidateSchedules(p);
  const confirm = reviewVerdict({ choice: "profile", confidence: 0.8, quiet_real: 0.9, busy_machine: 0.2 }, options, p, 100, { model: "m" });
  assert.equal(confirm.verdict, "confirm"); assert.equal(confirm.schedule, "weekdays 07-19 UTC"); assert.equal(confirm.off_hours_week, 108); assert.equal(confirm.est_usd_month, 64.29);
  assert.match(confirm.reason, /confirms the profile's window weekdays 07-19 UTC \(0\.80\)/);
  const adjust = reviewVerdict({ choice: "wider", confidence: 0.7, quiet_real: 0.8, busy_machine: 0.5 }, options, p, 100);
  assert.equal(adjust.verdict, "adjust"); assert.equal(adjust.schedule, "weekdays 06-20 UTC"); assert.match(adjust.reason, /prefers weekdays 06-20 UTC over the profile's weekdays 07-19 UTC/);
  const unsure = reviewVerdict({ choice: "profile", confidence: MIN_CHOICE_CONFIDENCE - 0.1, quiet_real: 0.9, busy_machine: 0.2 }, options, p, 100);
  assert.equal(unsure.verdict, "keep_running"); assert.equal(unsure.schedule, null); assert.match(unsure.reason, /only at 0\.45/);
  const doubted = reviewVerdict({ choice: "profile", confidence: 0.9, quiet_real: 0.3, busy_machine: 0.2 }, options, p, 100);
  assert.equal(doubted.verdict, "keep_running"); assert.match(doubted.reason, /doubts the quiet windows are real non-use \(0\.30\)/);
  const keep = reviewVerdict({ choice: "keep_running", confidence: 0.85, quiet_real: 0.4, busy_machine: 0.1 }, options, p, 100);
  assert.equal(keep.verdict, "keep_running"); assert.match(keep.reason, /keeps it running \(0\.85\)/);
  const bogus = reviewVerdict({ choice: "nonsense", confidence: 0.9, quiet_real: 0.9, busy_machine: 0.9 }, options, p, 100);
  assert.equal(bogus.verdict, "keep_running");
});

test("usage review: the state carries the profile, what tripped the busy hours and the box's record; the executor follows the review, not the raw profile", () => {
  const p = buildProfile({ subject: "i-r9", kind: "ec2", samples: samples(office) });
  storeProfile(p);
  const s = reviewState(p) as any;
  assert.equal(s.instance.id, "i-r9"); assert.equal(s.profile.busy_hours_week, 50); assert.equal(s.profile.busy_tripped_by.network_over_5mb_h, 200); assert.ok(s.note.includes("Memory use is not a usage signal"));
  assert.equal(latestReview("i-r9"), null);
  // no Jev key in tests: the executor falls back to the profile's own window when it is confident, else waits
  const f = scheduleFor("i-r9");
  assert.equal(f.source, p.confidence >= 0.85 ? "profile" : null);
  db.prepare("insert into usage_reviews(subject, reviewed_at, verdict, schedule, off_hours_week, est_usd_month, confidence, quiet_is_real, busy_is_machine, reason, options) values ('i-r9', ?, 'keep_running', null, null, null, 0.8, 0.4, 0.2, 'Jev keeps it running.', '{}')").run(new Date().toISOString());
  const kept = scheduleFor("i-r9");
  assert.equal(kept.schedule, null); assert.equal(kept.source, "review"); assert.match(kept.note, /Jev keeps it running/);
  db.prepare("update usage_reviews set verdict = 'adjust', schedule = 'weekdays 06-20 UTC' where subject = 'i-r9'").run();
  const set = scheduleFor("i-r9");
  assert.equal(set.schedule, "weekdays 06-20 UTC"); assert.match(set.note, /Jev set weekdays 06-20 UTC/);
  db.prepare("delete from usage_reviews where subject = 'i-r9'").run();
  db.prepare("delete from usage_profiles where subject = 'i-r9'").run();
});

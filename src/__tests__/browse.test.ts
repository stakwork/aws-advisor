import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { addDays, daysInMonth, localDay } from "../localdate.js";
import { alertDay, dedupeFindings, levelCounts, mergeRecommendations, orderAlerts, pageParams, paginate } from "../paging.js";
import { SpendRow, summarizeSpend } from "../spend_math.js";

// ---- spend --------------------------------------------------------------------------------------------------

const TODAY = "2026-09-19";
const row = (day: string, net: number | null, fetched = "2026-09-19 06:15:00"): SpendRow => ({ day, net_unblended: net, unblended: net, amortized: net, usage_only: net, fetched_at: fetched });
/** August complete at 10/day, September 1..18 at 20/day: no row for today. */
function fixture(): SpendRow[] {
  const rows: SpendRow[] = [];
  for (let d = "2026-08-01"; d <= "2026-08-31"; d = addDays(d, 1)) rows.push(row(d, 10));
  for (let d = "2026-09-01"; d <= "2026-09-18"; d = addDays(d, 1)) rows.push(row(d, 20));
  return rows;
}

test("spend summary: today null when Cost Explorer has not reported it, 7-day window ends yesterday, MTD projection from complete days", () => {
  const s = summarizeSpend(fixture(), TODAY);
  assert.equal(s.as_of, "2026-09-18");
  assert.deepEqual(s.today, { day: TODAY, usd: null });
  assert.deepEqual(s.last_7_days, { from: "2026-09-12", to: "2026-09-18", usd: 140, days: 7 });
  assert.equal(s.month_to_date.from, "2026-09-01");
  assert.equal(s.month_to_date.usd, 360);
  assert.equal(s.month_to_date.days, 18);
  assert.deepEqual(s.month_to_date.projection_basis, { days: 18, daily_avg: 20 });
  assert.equal(s.month_to_date.projected_month_end, 600); // 20 a day over 30 days
  assert.deepEqual(s.previous_month, { from: "2026-08-01", to: "2026-08-31", usd: 310, days: 31, complete: true });
  assert.equal(s.fetched_at, "2026-09-19 06:15:00");
});

test("spend summary: a partial today is shown but kept out of the projection and the 7-day window", () => {
  const rows = [...fixture(), row(TODAY, 3, "2026-09-19 12:15:00")];
  const s = summarizeSpend(rows, TODAY);
  assert.equal(s.as_of, TODAY);
  assert.deepEqual(s.today, { day: TODAY, usd: 3 });
  assert.deepEqual(s.last_7_days, { from: "2026-09-12", to: "2026-09-18", usd: 140, days: 7 });
  assert.equal(s.month_to_date.usd, 363);
  assert.equal(s.month_to_date.days, 19);
  assert.equal(s.month_to_date.projected_month_end, 600);
  assert.equal(s.fetched_at, "2026-09-19 12:15:00");
});

test("spend summary: gaps, a lagging as-of, an incomplete previous month, and no data at all", () => {
  // Data stops 3 days ago: the 7-day window ends on the last day with data; September has 3 days missing.
  const rows = fixture().filter((r) => r.day <= "2026-09-16" && r.day !== "2026-09-10");
  const s = summarizeSpend(rows, TODAY);
  assert.equal(s.as_of, "2026-09-16");
  assert.deepEqual(s.last_7_days, { from: "2026-09-10", to: "2026-09-16", usd: 120, days: 6 });
  assert.equal(s.month_to_date.days, 15);
  assert.equal(s.month_to_date.projected_month_end, 600);
  // Only the last 45 days: the previous month is partial and says so.
  const short = fixture().filter((r) => r.day >= addDays(TODAY, -44));
  assert.equal(summarizeSpend(short, TODAY).previous_month.complete, false);
  assert.equal(summarizeSpend(short, TODAY).previous_month.days, 26);
  // Nothing stored yet.
  const empty = summarizeSpend([], TODAY);
  assert.equal(empty.as_of, null);
  assert.equal(empty.today.usd, null);
  assert.equal(empty.last_7_days.usd, null);
  assert.equal(empty.month_to_date.projected_month_end, null);
  assert.equal(empty.previous_month.usd, null);
  assert.equal(empty.fetched_at, null);
  // Only today has data: the projection falls back to it.
  const onlyToday = summarizeSpend([row(TODAY, 5)], TODAY);
  assert.equal(onlyToday.month_to_date.projected_month_end, 150);
  // Metric choice.
  const amortized = summarizeSpend([{ ...row("2026-09-18", 1), amortized: 7 }], TODAY, "amortized");
  assert.equal(amortized.last_7_days.usd, 7);
});

test("spend summary reads the spend_daily table (fixture rows in a scratch database)", async () => {
  process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "advisor-browse-test-"));
  const { db } = await import("../db.js");
  const { spendSummary, spendRows } = await import("../spend.js");
  const ins = db.prepare("insert into spend_daily(day, net_unblended, unblended, amortized, usage_only, fetched_at) values (?, ?, ?, ?, ?, ?)");
  for (const r of [...fixture(), row(TODAY, 3, "2026-09-19 12:15:00")]) ins.run(r.day, r.net_unblended, r.unblended, r.amortized, r.usage_only, r.fetched_at);
  const s = spendSummary(TODAY);
  assert.equal(s.today.usd, 3);
  assert.equal(s.last_7_days.usd, 140);
  assert.equal(s.previous_month.usd, 310);
  assert.equal(s.month_to_date.projected_month_end, 600);
  assert.equal(spendRows(45, TODAY).length, 45);
  assert.equal(spendRows(45, TODAY)[0].day, addDays(TODAY, -44));
});

test("local calendar helpers", () => {
  assert.equal(addDays("2026-03-01", -1), "2026-02-28");
  assert.equal(addDays("2026-12-31", 1), "2027-01-01");
  assert.equal(daysInMonth("2026-02-10"), 28);
  assert.equal(daysInMonth("2028-02-10"), 29);
  assert.match(localDay(), /^\d{4}-\d{2}-\d{2}$/);
});

// ---- alerts --------------------------------------------------------------------------------------------------

const utc = (d: Date) => d.toISOString().replace("T", " ").slice(0, 19);
const now = new Date();
const t = (hoursAgo: number) => utc(new Date(now.getTime() - hoursAgo * 3600_000));

test("alerts: today before older days, alarms then warnings then info within a day, newest first", () => {
  const rows = [
    { id: 1, created_at: t(30), kind: "credentials", triage: null },                                   // yesterday alarm
    { id: 2, created_at: t(1), kind: "node_churn", triage: null },                                     // today info
    { id: 3, created_at: t(2), kind: "nat_traffic", triage: null },                                    // today alarm
    { id: 4, created_at: t(3), kind: "instance_state", triage: JSON.stringify({ expected: 0.9 }) },    // today info (expected)
    { id: 5, created_at: t(4), kind: "instance_state", triage: { expected: 0.2 } },                    // today warning
    { id: 6, created_at: t(0.5), kind: "nat_traffic", triage: { severity: 0.5 } },                     // today warning (low severity)
    { id: 7, created_at: t(26), kind: "node_churn", triage: null },                                    // yesterday info
    { id: 8, created_at: t(0.1), kind: "nat_traffic", triage: { severity: 2 } },                       // today alarm, newest
  ];
  const ordered = orderAlerts(rows);
  assert.deepEqual(ordered.map((a) => a.id), [8, 3, 6, 5, 2, 4, 1, 7]);
  assert.deepEqual(ordered.map((a) => a.level), ["alarm", "alarm", "warning", "warning", "info", "info", "alarm", "info"]);
  assert.equal(ordered[0].day, alertDay(t(0)));
  assert.notEqual(ordered[6].day, ordered[0].day);
  assert.deepEqual(levelCounts(ordered), { alarm: 3, warning: 2, info: 3 });
  // The day is the server's local date of a UTC timestamp.
  assert.equal(alertDay("2026-09-19 12:00:00"), localDay(new Date("2026-09-19T12:00:00Z")));
});

test("paging: 1-based pages, size clamped to the maximum, defaults", () => {
  assert.deepEqual(pageParams({}, { size: 10, max: 50 }), { page: 1, page_size: 10 });
  assert.deepEqual(pageParams({ page: "3", page_size: "500" }, { size: 10, max: 50 }), { page: 3, page_size: 50 });
  assert.deepEqual(pageParams({ page: "-2", page_size: "abc" }, { size: 10, max: 50 }), { page: 1, page_size: 10 });
  const all = Array.from({ length: 23 }, (_, i) => i + 1);
  assert.deepEqual(paginate(all, { page: 3, page_size: 10 }), { total: 23, page: 3, page_size: 10, items: [21, 22, 23] });
  assert.deepEqual(paginate(all, { page: 9, page_size: 10 }).items, []);
});

// ---- findings ------------------------------------------------------------------------------------------------

test("findings: one row per fingerprint and per (control, resource), first by id", () => {
  const rows = [
    { id: 5, fingerprint: "fp-a", control_id: "c1", resource: "r1", region: "us-east-1" },
    { id: 2, fingerprint: "fp-a", control_id: "c1", resource: "r1", region: "eu-west-1" },   // same fingerprint, lower id wins
    { id: 3, fingerprint: "fp-b", control_id: "c1", resource: "r1", region: "us-west-2" },   // same control+resource, other fingerprint
    { id: 4, fingerprint: "fp-c", control_id: "c2", resource: "r1", region: "us-east-1" },   // other control: kept
    { id: 6, fingerprint: "fp-d", control_id: "c2", resource: null, region: null },
    { id: 7, fingerprint: "fp-e", control_id: "c2", resource: null, region: null },          // no resource: never collapsed
  ];
  assert.deepEqual(dedupeFindings(rows).map((f) => f.id), [2, 4, 6, 7]);
  assert.deepEqual(dedupeFindings([]), []);
});

// ---- recommendations -----------------------------------------------------------------------------------------

test("recommendations: same (resource, action) merge into the highest estimate, sorted by saving with nulls last", () => {
  const rec = (id: number, o: Partial<{ source: string; rule: string; resource: string | null; action_type: string; status: string; est_monthly_saving: number | null; confidence: number | null; updated_at: string }>) =>
    ({ id, source: "rules", rule: "idle_instance", resource: "i-1", action_type: "stop_instance", status: "open", est_monthly_saving: 10, confidence: 0.8, updated_at: "2026-09-18 00:00:00", ...o });
  const rows = [
    rec(1, { est_monthly_saving: 10 }),
    rec(2, { source: "agent", rule: "agent:stop", est_monthly_saving: 25, confidence: 0.6 }),
    rec(3, { resource: "i-2", est_monthly_saving: null }),
    rec(4, { resource: "i-3", action_type: "release_eip", est_monthly_saving: 3.6 }),
    rec(5, { source: "agent", resource: "i-3", action_type: "release_eip", est_monthly_saving: 3.6, updated_at: "2026-09-19 00:00:00" }),
    rec(6, { resource: null, est_monthly_saving: 100 }),
    rec(7, { resource: null, est_monthly_saving: 90 }),
    rec(8, { status: "approved", est_monthly_saving: 50 }),   // same resource/action, other status: its own entry
  ];
  const merged = mergeRecommendations(rows);
  assert.deepEqual(merged.map((r) => r.id), [6, 7, 8, 2, 5, 3]);
  const stop = merged.find((r) => r.id === 2)!;
  assert.deepEqual(stop.merged, [{ id: 1, source: "rules", rule: "idle_instance", est_monthly_saving: 10, confidence: 0.8 }]);
  assert.deepEqual(stop.sources, ["rules", "agent"]);
  assert.deepEqual(stop.merged_ids, [2, 1]);
  const eip = merged.find((r) => r.id === 5)!;   // equal estimate: the most recently updated is primary
  assert.deepEqual(eip.merged.map((m) => m.id), [4]);
  assert.deepEqual(merged.find((r) => r.id === 6)!.merged, []);
  assert.deepEqual(merged.find((r) => r.id === 8)!.merged, []);
  assert.equal(merged[merged.length - 1].est_monthly_saving, null);
});

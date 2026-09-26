import assert from "node:assert/strict";
import { test } from "node:test";
import { decideAcuWindow, quietHours, acuWindowSaving, type AcuDecisionInput } from "../actions/acu_window.js";
import { pickSnapshots, archiveSaving, NO_VOLUME, type SnapshotFacts } from "../actions/snapshot_archive.js";
import { formatActionMessage } from "../executor.js";
import { hourProfile } from "../rds_load.js";
import { validateRuntime } from "../config.js";

/** A day that idles at 0.5 ACU from 22:00 to 06:00 UTC and works at 2-4 ACU otherwise, with p95 a little above the median. */
const dayNight = () => {
  const median = Array.from({ length: 24 }, (_, h) => (h >= 22 || h < 6 ? 0.5 : 2.5));
  const p95 = Array.from({ length: 24 }, (_, h) => (h >= 22 || h < 6 ? 0.5 : 4));
  return { median, p95, days: 14 };
};
const base = (over: Partial<AcuDecisionInput> = {}): AcuDecisionInput => ({
  cluster: "hub", by_hour: dayNight(), current_min: 2, current_max: 16, floor: 0.5, baseline_min: 2, last_set: null, acu_now: 0.5, cadence: "irregular", burst_start_minute: null, hour: 23, ...over,
});

test("acu: the quiet hours are those whose p95 stays at the floor", () => {
  assert.deepEqual(quietHours(dayNight(), 0.5), [0, 1, 2, 3, 4, 5, 22, 23]);
  assert.deepEqual(quietHours(dayNight(), 2), [0, 1, 2, 3, 4, 5, 22, 23]);
  assert.deepEqual(quietHours({ median: Array(24).fill(3), p95: Array(24).fill(3), days: 14 }, 0.5), []);
});

test("acu: lowers before two quiet hours, raises before a working hour, leaves the rest", () => {
  const down = decideAcuWindow(base({ hour: 23 }));
  assert.equal(down.wanted, 0.5);
  assert.match(down.reason, /23:00 and 00:00 UTC are quiet/);
  // at the floor already, still quiet: nothing
  assert.equal(decideAcuWindow(base({ hour: 1, current_min: 0.5, last_set: 0.5 })).wanted, null);
  // 05:00 is quiet but 06:00 works: not worth a single hour
  const single = decideAcuWindow(base({ hour: 5, current_min: 2 }));
  assert.equal(single.wanted, null);
  assert.match(single.reason, /not worth a change for one hour/);
  // the working hour comes: back to the configured minimum
  const up = decideAcuWindow(base({ hour: 6, current_min: 0.5, last_set: 0.5 }));
  assert.equal(up.wanted, 2);
  assert.match(up.reason, /06:00 UTC is a working hour/);
  // working hour and already at the baseline
  assert.equal(decideAcuWindow(base({ hour: 12 })).wanted, null);
});

test("acu: a busy database now is not lowered even in a usually quiet hour", () => {
  const d = decideAcuWindow(base({ hour: 23, acu_now: 3.2 }));
  assert.equal(d.wanted, null);
  assert.match(d.reason, /3.2 ACU right now/);
});

test("acu: the owner's own change to the minimum becomes the new band", () => {
  // the executor had set 0.5; the owner then set 4: 4 is neither floor, baseline nor last_set
  const d = decideAcuWindow(base({ hour: 23, current_min: 4, last_set: 0.5, baseline_min: 2 }));
  assert.equal(d.baseline_min, 4);
  assert.equal(d.wanted, 0.5);
  // the owner set the minimum to the floor themselves: nothing to move within
  const flat = decideAcuWindow(base({ hour: 23, current_min: 0.5, baseline_min: 0.5 }));
  assert.equal(flat.wanted, null);
  assert.match(flat.reason, /already at the floor/);
});

test("acu: hourly bursts, a round-the-clock database and a daily burst hour are respected", () => {
  assert.match(decideAcuWindow(base({ cadence: "hourly" })).reason, /every hour/);
  const busy = { median: Array(24).fill(2), p95: Array(24).fill(3), days: 14 };
  assert.match(decideAcuWindow(base({ by_hour: busy })).reason, /only 0 quiet hour/);
  // the profile says 03:00 is quiet but the daily job starts at 03:10: raise before it, never lower into it
  const job = decideAcuWindow(base({ hour: 3, current_min: 0.5, last_set: 0.5, cadence: "daily", burst_start_minute: 190 }));
  assert.equal(job.wanted, 2);
  assert.match(job.reason, /daily burst starts around 03:00/);
  const before = decideAcuWindow(base({ hour: 2, current_min: 2, cadence: "daily", burst_start_minute: 190 }));
  assert.equal(before.wanted, null);
});

test("acu: the saving is the band over the quiet hours at the ACU-hour price", () => {
  assert.equal(acuWindowSaving(2, 0.5, 8), Math.round(1.5 * 0.12 * 8 * 30.4 * 100) / 100);
});

test("rds load: the hour profile needs seven days and every hour", () => {
  const t: number[] = [], v: number[] = [];
  const start = Date.UTC(2026, 8, 1);
  for (let d = 0; d < 10; d++) for (let h = 0; h < 24; h++) for (let m = 0; m < 60; m += 5) { t.push(start + ((d * 24 + h) * 60 + m) * 60000); v.push(h < 6 ? 0.5 : 2 + (m === 55 ? 3 : 0)); }
  const p = hourProfile({ t, v })!;
  assert.equal(p.days, 10);
  assert.equal(p.median[3], 0.5);
  assert.equal(p.median[12], 2);
  assert.equal(p.p95[12], 5);
  assert.equal(hourProfile({ t: t.slice(0, 24 * 12 * 3), v: v.slice(0, 24 * 12 * 3) }), null);
});

const snap = (over: Partial<SnapshotFacts>): SnapshotFacts => ({
  snapshot_id: "snap-1", volume_id: "vol-a", size_gb: 100, started: "2026-01-01T00:00:00.000Z", age_days: 200, tier: "standard", description: null, name: null, ami_backed: false, managed_by: null, hands_off: false, volume_exists: false, ...over,
});

test("snapshots: the newest standard snapshot of a gone volume goes first, the rest wait", () => {
  const all = [
    snap({ snapshot_id: "snap-old", started: "2025-06-01T00:00:00.000Z", age_days: 400 }),
    snap({ snapshot_id: "snap-mid", started: "2025-09-01T00:00:00.000Z", age_days: 300 }),
    snap({ snapshot_id: "snap-new", started: "2026-01-01T00:00:00.000Z", age_days: 200 }),
  ];
  const { picks, left } = pickSnapshots(all, 90);
  assert.deepEqual(picks.map((p) => p.snapshot_id), ["snap-new"]);
  assert.equal(picks[0].rule, "orphan_newest");
  assert.equal(left["older sibling of a gone volume: waits for the newer one"], 2);
  // once snap-new is archived, snap-mid is the newest standard one
  const next = pickSnapshots(all.map((s) => (s.snapshot_id === "snap-new" ? { ...s, tier: "archive" } : s)), 90);
  assert.deepEqual(next.picks.map((p) => p.snapshot_id), ["snap-mid"]);
});

test("snapshots: age, AMI, Backup/DLM, hands-off, live volumes with several snapshots and unknown tiers are left alone", () => {
  const all = [
    snap({ snapshot_id: "young", age_days: 30 }),
    snap({ snapshot_id: "ami", ami_backed: true }),
    snap({ snapshot_id: "backup", managed_by: "aws:backup:source-resource" }),
    snap({ snapshot_id: "fenced", hands_off: true }),
    snap({ snapshot_id: "live-only", volume_id: "vol-live", volume_exists: true }),
    snap({ snapshot_id: "live-a", volume_id: "vol-busy", volume_exists: true }),
    snap({ snapshot_id: "live-b", volume_id: "vol-busy", volume_exists: true, started: "2026-02-01T00:00:00.000Z", age_days: 150 }),
    snap({ snapshot_id: "notier", tier: null }),
    snap({ snapshot_id: "copied-1", volume_id: NO_VOLUME, volume_exists: null, size_gb: 8 }),
    snap({ snapshot_id: "copied-2", volume_id: NO_VOLUME, volume_exists: null, size_gb: 500 }),
  ];
  const { picks, left } = pickSnapshots(all, 90);
  assert.deepEqual(picks.map((p) => p.snapshot_id), ["copied-2", "live-only", "copied-1"]);
  assert.equal(picks[1].rule, "only_snapshot");
  assert.equal(left["younger than 90 days"], 1);
  assert.equal(left["behind an AMI"], 1);
  assert.equal(left["managed by aws:backup:source-resource"], 1);
  assert.equal(left["tagged advisor:hands-off"], 1);
  assert.equal(left["one of several snapshots of a live volume"], 2);
  assert.equal(left["storage tier unknown"], 1);
  assert.equal(archiveSaving(100), 3.75);
});

test("executor: the Sphinx message says what happened, why, and how to undo, with the link", () => {
  const m = formatActionMessage({ id: 7, status: "verified", kind: "acu_window", title: "hub: minimum capacity 2 → 0.5 ACU for the quiet hours", reason: "23:00 and 00:00 UTC are quiet", rollback: "set the minimum back to 2 ACU", result: null, error: null, est_usd_month: 43.78 }, "http://10.0.0.5:9034");
  assert.match(m, /^✅ Auto-action applied and verified · hub: minimum capacity 2 → 0.5 ACU/);
  assert.match(m, /≈ 43.78 USD\/month/);
  assert.match(m, /Undo: set the minimum back to 2 ACU/);
  assert.match(m, /http:\/\/10.0.0.5:9034\/actions\?id=7$/);
  const f = formatActionMessage({ id: 8, status: "failed", kind: "snapshot_archive", title: "snap-1: 100 GB snapshot", reason: "r", rollback: "x", result: null, error: "AccessDenied", est_usd_month: null }, "http://x");
  assert.match(f, /^❌ Auto-action failed/);
  assert.match(f, /Error: AccessDenied/);
  assert.doesNotMatch(f, /Undo/);
});

test("executor settings: the actuator role must be a role ARN, the mode one of three", () => {
  assert.equal(validateRuntime("actRoleArn", "arn:aws:iam::123456789012:role/aws-advisor-act"), "arn:aws:iam::123456789012:role/aws-advisor-act");
  assert.equal(validateRuntime("actRoleArn", ""), "");
  assert.throws(() => validateRuntime("actRoleArn", "aws-advisor-act"), /arn:aws:iam/);
  assert.equal(validateRuntime("actMode", "apply"), "apply");
  assert.throws(() => validateRuntime("actMode", "yes"), /one of off, dry_run, apply/);
  assert.throws(() => validateRuntime("actAcuFloor", "0.1"), /at least 0.5/);
});

test("gp3 IOPS trim: target is twice the peak rounded up to 500, never under the free baseline", async () => {
  const { targetIops, iopsSaving } = await import("../actions/ebs_iops_trim.js");
  assert.equal(targetIops(900), 3000);
  assert.equal(targetIops(2100), 4500);
  assert.equal(targetIops(2000), 4000);
  assert.equal(iopsSaving(16000, 4500), 57.5);
});

test("log retention: the requested days snap to a value CloudWatch accepts", async () => {
  const { snapRetention } = await import("../actions/log_retention.js");
  assert.equal(snapRetention(90), 90);
  assert.equal(snapRetention(100), 120);
  assert.equal(snapRetention(1), 1);
  assert.equal(snapRetention(9999), 3653);
});

test("s3 usage: the tally by age, class and prefix, and the rules that fall out of it", async () => {
  const { tallyObjects, proposeLifecycle } = await import("../s3_usage.js");
  const now = Date.UTC(2026, 8, 25);
  const day = 86400000;
  const objs = [
    { Key: "logs/2024/a.gz", Size: 3e9, LastModified: new Date(now - 500 * day), StorageClass: "STANDARD" },
    { Key: "logs/2025/b.gz", Size: 2e9, LastModified: new Date(now - 200 * day), StorageClass: "STANDARD" },
    { Key: "uploads/c.png", Size: 50e6, LastModified: new Date(now - 10 * day), StorageClass: "STANDARD" },
    { Key: "uploads/d.png", Size: 1000, LastModified: new Date(now - 400 * day), StorageClass: "STANDARD" },
    { Key: "archive/e.bin", Size: 5e9, LastModified: new Date(now - 800 * day), StorageClass: "GLACIER_IR" },
  ];
  const t = tallyObjects(objs, now);
  assert.equal(t.standard_by_age["365+"].bytes, 3e9 + 1000);
  assert.equal(t.standard_by_age["90-365"].bytes, 2e9);
  assert.equal(t.by_class.GLACIER_IR.bytes, 5e9);
  assert.equal(t.by_prefix[0].bytes, 5e9, "the two biggest prefixes tie at 5 GB");
  assert.equal(t.by_prefix.find((p) => p.prefix === "logs/")!.old_bytes, 3e9);
  const base: any = { bucket: "b", region: "us-east-1", collected_at: "2026-09-25T00:00:00Z", sample: { objects: 5, bytes: 10e9, truncated: false, pages: 1 }, ...t, multipart: { uploads: 3, oldest_at: "2026-01-01T00:00:00Z" }, versioning: true, noncurrent: { versions: 400, bytes: 4e9, sampled: false }, lifecycle: [], requests: null, inventory: { total_gb: 10, standard_gb: 5, objects: 5 } };
  const p = proposeLifecycle(base);
  assert.deepEqual(p.rules.map((r) => r.id), ["aws-advisor-abort-incomplete-multipart", "aws-advisor-expire-noncurrent", "aws-advisor-intelligent-tiering"], "no request metrics: Intelligent-Tiering, not a guess at IA");
  assert.equal((p.rules[2].rule as any).Filter.Prefix, "logs/", "the old bytes sit under one prefix, so the rule is scoped to it");
  assert.ok(p.est_usd_month > 0);
  // with request metrics showing almost no reads: Glacier Instant Retrieval; with reads: Standard-IA
  const cold = proposeLifecycle({ ...base, requests: { days: 14, get_per_day: 2, put_per_day: 0, bytes_downloaded_per_day: 0, metrics_id: "x" } });
  assert.ok(cold.rules.some((r) => r.id === "aws-advisor-glacier-ir-90"));
  const warm = proposeLifecycle({ ...base, requests: { days: 14, get_per_day: 5000, put_per_day: 0, bytes_downloaded_per_day: 1e9, metrics_id: "x" } });
  assert.ok(warm.rules.some((r) => r.id === "aws-advisor-standard-ia-30"));
  // an existing transition rule and an existing abort rule are respected
  const has = proposeLifecycle({ ...base, lifecycle: [{ id: "old", status: "Enabled", prefix: null, transitions: [{ days: 30, storage_class: "STANDARD_IA" }], expiration_days: null, noncurrent_expiration_days: 30, abort_multipart_days: 7 }] });
  assert.deepEqual(has.rules, []);
  assert.match(has.notes.join(" "), /already covered by a transition rule/);
});

test("use-signal patterns: the setting is validated and the probe document takes them as a parameter", async () => {
  const { parseSignals, serialiseSignals, DEFAULT_SIGNALS_STRING } = await import("../signals.js");
  const { probeDocument, probeScript, PROBE_SCRIPT, parseClfDate } = await import("../ssm.js");
  assert.equal(serialiseSignals(parseSignals(DEFAULT_SIGNALS_STRING)), DEFAULT_SIGNALS_STRING);
  assert.equal(parseSignals("login=log(ged)? ?in;;deploy=deploy(ed|ing)? ").length, 2);
  assert.equal(parseSignals("deploy=deploying")[0].description, "custom pattern /deploying/i");
  assert.throws(() => parseSignals("Login=x"), /lowercase/);
  assert.throws(() => parseSignals("a=it's"), /single quotes/);
  assert.throws(() => parseSignals("a=(unclosed"), /not a valid regex/);
  assert.throws(() => parseSignals("a=x;;a=y"), /twice/);
  assert.equal(validateRuntime("probeSignals", "  login=log(ged)? ?in;; auth=authoriz"), "login=log(ged)? ?in;;auth=authoriz");
  assert.equal(parseSignals("w=\"POST ")[0].regex, "\"POST ", "a trailing space in a pattern is kept");
  assert.throws(() => validateRuntime("probeSignals", ""), /at least one/);
  const doc = probeDocument() as any;
  assert.equal(doc.parameters.signals.default, DEFAULT_SIGNALS_STRING);
  assert.ok(doc.mainSteps[0].inputs.runCommand.some((l: string) => l.includes("'{{ signals }}'")), "the document line takes the parameter, single-quoted");
  assert.ok(!doc.mainSteps[0].inputs.runCommand.some((l: string) => l.includes("__SIGNALS__")));
  assert.match(PROBE_SCRIPT, /__SIGNALS__/);
  assert.ok(probeScript("a=b;;c=d").includes("'a=b;;c=d'"), "the stock path inlines the current list");
  assert.equal(parseClfDate("25/Sep/2026:10:00:00 +0000"), "2026-09-25T10:00:00.000Z");
  assert.equal(parseClfDate("25/Sep/2026:12:30:00 +0200"), "2026-09-25T10:30:00.000Z");
  assert.equal(parseClfDate("nonsense"), null);
});

test("ledger: pages newest first, counts kinds within the status scope, lands on the page holding an id", async () => {
  const { listActions } = await import("../executor.js");
  const { db } = await import("../db.js");
  db.exec("delete from actions");
  const ins = db.prepare("insert into actions(kind, resource, region, dedupe, status, mode, trigger, title, reason) values (?, ?, 'us-east-1', ?, ?, 'dry_run', 'test', ?, 'because')");
  for (let i = 1; i <= 7; i++) ins.run(i % 2 ? "log_retention" : "s3_request_metrics", `r${i}`, `d${i}`, i === 7 ? "stale" : "proposed", `row ${i}`);
  const all = listActions({ page_size: 3 });
  assert.equal(all.total, 7);
  assert.deepEqual(all.actions.map((a) => a.title), ["row 7", "row 6", "row 5"]);
  assert.deepEqual(all.counts, { proposed: 6, stale: 1 });
  assert.deepEqual(all.kinds, { log_retention: 4, s3_request_metrics: 3 });
  const p3 = listActions({ page_size: 3, page: 3 });
  assert.deepEqual(p3.actions.map((a) => a.title), ["row 1"]);
  // kinds count the status scope before the kind filter, so the other kind stays listed
  const s3 = listActions({ status: "proposed", kind: "s3_request_metrics", page_size: 10 });
  assert.equal(s3.total, 3);
  assert.deepEqual(s3.kinds, { log_retention: 3, s3_request_metrics: 3 });
  // a deep link's id resolves to its page; an id outside the filter gives page 1
  const row2 = all.actions.length && (db.prepare("select id from actions where title = 'row 2'").get() as { id: number }).id;
  assert.equal(listActions({ page_size: 3, id: row2 as number }).page, 2);
  assert.equal(listActions({ status: "stale", page_size: 3, id: row2 as number }).page, 1);
  db.exec("delete from actions");
});

test("gp2 → gp3: the target keeps gp2's performance and the saving nets out the extras", async () => {
  const { gp3Target, gp3Saving } = await import("../actions/ebs_gp3_migrate.js");
  assert.deepEqual(gp3Target(100), { iops: 3000, throughput_mibps: 125 });
  assert.deepEqual(gp3Target(500), { iops: 3000, throughput_mibps: 250 });
  assert.deepEqual(gp3Target(2000), { iops: 6000, throughput_mibps: 250 });
  assert.deepEqual(gp3Target(8000), { iops: 16000, throughput_mibps: 250 });
  assert.equal(gp3Saving(100), 2);
  assert.equal(gp3Saving(500), 5); // 10 − 5 for the 125 extra MiB/s
  assert.equal(gp3Saving(2000), 20); // 40 − 15 (3,000 extra IOPS) − 5
  assert.ok(gp3Saving(8000) > 0);
});

test("ecr: the policy expires untagged only, and the tally counts what goes on the first run", async () => {
  const { policyText, tallyUntagged, MARKER } = await import("../actions/ecr_lifecycle.js");
  const p = JSON.parse(policyText(30));
  assert.equal(p.rules.length, 1);
  assert.equal(p.rules[0].selection.tagStatus, "untagged");
  assert.equal(p.rules[0].selection.countNumber, 30);
  assert.match(p.rules[0].description, new RegExp(MARKER));
  const now = Date.parse("2026-09-26T00:00:00Z");
  const t = tallyUntagged([{ imageSizeInBytes: 5e8, imagePushedAt: new Date(now - 40 * 86400000) }, { imageSizeInBytes: 3e8, imagePushedAt: new Date(now - 10 * 86400000) }, { imageSizeInBytes: 2e8 }], 30, false, now);
  assert.equal(t.count, 3); assert.equal(t.bytes, 1e9);
  assert.equal(t.expiring_count, 1); assert.equal(t.expiring_bytes, 5e8);
  assert.equal(t.oldest_at, new Date(now - 40 * 86400000).toISOString());
});

test("swarm park: idle only when every signal is quiet every day; a missing signal keeps it running", async () => {
  const { idleVerdict } = await import("../actions/swarm_park.js");
  const now = new Date("2026-09-26T12:00:00Z");
  const quiet = (day: string, over: Partial<import("../actions/swarm_park.js").DayUse> = {}) => ({ day, samples: 4, last_use_at: null, external_connections_max: 0, requests_24h_avg: 0, signal_lines_24h_avg: 0, net_bytes_day: 1e6, container_cpu_avg_max: 0.2, container_cpu_max: 1.5, ...over });
  const days = (f: (d: string) => any) => Array.from({ length: 8 }, (_, i) => f(new Date(now.getTime() - i * 86400000).toISOString().slice(0, 10)));
  const all = idleVerdict(days((d) => quiet(d)), { idleDays: 7, minProbes: 7, now });
  assert.equal(all.idle, true, all.reasons.join("; "));
  assert.equal(all.days_seen, 8);
  // one connection on one day
  const conn = idleVerdict(days((d) => quiet(d, { external_connections_max: d.endsWith("22") ? 2 : 0 })), { idleDays: 7, minProbes: 7, now });
  assert.equal(conn.idle, false); assert.match(conn.reasons.join(";"), /external connections seen/);
  // a recent use signal
  const used = idleVerdict(days((d) => quiet(d, { last_use_at: d === "2026-09-24" ? "2026-09-24T09:00:00Z" : null })), { idleDays: 7, minProbes: 7, now });
  assert.equal(used.idle, false); assert.match(used.reasons.join(";"), /last use 2026-09-24 09:00/);
  // an old use signal is fine
  assert.equal(idleVerdict(days((d) => quiet(d, { last_use_at: "2026-09-01T09:00:00Z" })), { idleDays: 7, minProbes: 7, now }).idle, true);
  // no front-door log = unknown = alive; missing day = alive; too few probes = alive
  assert.equal(idleVerdict(days((d) => quiet(d, { requests_24h_avg: null })), { idleDays: 7, minProbes: 7, now }).idle, false);
  assert.equal(idleVerdict(days((d) => quiet(d)).slice(2), { idleDays: 7, minProbes: 7, now }).idle, false);
  assert.equal(idleVerdict(days((d) => quiet(d, { samples: 1 })), { idleDays: 7, minProbes: 20, now }).idle, false);
  // busy containers
  assert.equal(idleVerdict(days((d) => quiet(d, { container_cpu_max: 40 })), { idleDays: 7, minProbes: 7, now }).idle, false);
});

test("aurora storage: the newest approval per cluster wins and older ones ride along", async () => {
  const { targetsFrom } = await import("../actions/aurora_storage.js");
  const rec = (id: number, action_type: string, resource = "hub") => ({ id, title: `r${id}`, decided_by: "ui", resource, resource_name: resource, action_type, rule: "x", est_monthly_saving: 100, evidence: { region: "us-east-1" } });
  const t = targetsFrom([rec(9, "aurora_set_storage_iopt"), rec(7, "aurora_set_storage_iopt"), rec(3, "aurora_set_storage_standard"), rec(5, "aurora_set_storage_iopt", "other")], "eu-west-1");
  assert.equal(t.length, 2);
  const hub = t.find((x) => x.cluster === "hub")!;
  assert.equal(hub.target, "aurora-iopt1");
  assert.deepEqual(hub.recs.map((r) => r.id), [9, 7]);
  assert.match(hub.conflict!, /#3 \(older\) asks for Standard/);
  assert.equal(t.find((x) => x.cluster === "other")!.region, "us-east-1");
});

test("s3 lifecycle: merge replaces a rule with the same id and keeps the rest", async () => {
  const { mergeRules } = await import("../actions/s3_lifecycle.js");
  const m = mergeRules([{ ID: "keep", Status: "Enabled" }, { ID: "aws-advisor-x", Status: "Disabled" }], [{ ID: "aws-advisor-x", Status: "Enabled" }, { ID: "aws-advisor-y", Status: "Enabled" }]);
  assert.deepEqual(m.map((r) => `${r.ID}:${r.Status}`), ["keep:Enabled", "aws-advisor-x:Enabled", "aws-advisor-y:Enabled"]);
});

test("grace: a fresh proposal waits, an old one does not, and the announcement says what happens", async () => {
  const { graceLeftMs, formatProposalMessage } = await import("../executor.js");
  const now = Date.parse("2026-09-26T12:00:00Z");
  assert.equal(graceLeftMs({ created_at: "2026-09-26 11:00:00" }, 24, now), 23 * 3600000);
  assert.equal(graceLeftMs({ created_at: "2026-09-24 11:00:00" }, 24, now), 0);
  assert.equal(graceLeftMs({ created_at: "2026-09-26 11:00:00" }, 0, now), 0);
  const m = formatProposalMessage({ id: 4, title: "stop swarm-27: idle 7 days", reason: "why", rollback: "start it", est_usd_month: 140 }, 24, "apply", "http://x");
  assert.match(m, /planned · stop swarm-27/); assert.match(m, /about 24 h unless someone objects/); assert.match(m, /http:\/\/x\/actions\?id=4$/);
  assert.match(formatProposalMessage({ id: 4, title: "t", reason: "r", rollback: null, est_usd_month: null }, 24, "dry_run", "http://x"), /Dry run/);
});

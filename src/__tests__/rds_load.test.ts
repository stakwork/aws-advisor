import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

// rds_load.ts reduces CloudWatch series to a profile and reads the inventory for its targets: a scratch database,
// no network (fetchSeries, Performance Insights and the log are never called here).
process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "advisor-rds-load-test-"));
process.env.TYPESAFE_API_KEY = "";

const { db } = await import("../db.js");
const { buildProfile, burstCadence, detectBursts, latestRdsLoad, loadSummary, parseLoadAnswers, parseSlowLog, profileHash, rdsLoadTargets, shapeOf } = await import("../rds_load.js");
const { auroraLoadNote } = await import("../rules.js");
const { resourceFacts } = await import("../resolve.js");

const T0 = Date.UTC(2026, 8, 9, 0, 0, 0); // 2026-09-09T00:00Z
const NOW = T0 + 14 * 86400000;
const target = (over: Partial<any> = {}) => ({ kind: "cluster", id: "sphinx-hub-production", region: "us-east-1", engine: "aurora-postgresql", engine_version: "16.11", storage_type: "aurora", serverless: true, configured_min_acu: 0.5, configured_max_acu: 2, instance_class: "db.serverless", members: 1, writer: "sphinx-hub-production-instance-1", dbi_resource_id: "db-ABC", performance_insights: false, ...over }) as any;

/** A minute series like the real cluster: idle at 0.5 ACU, a burst to 2.0 at minute 9 of every hour for 12 minutes, decaying through 1.0 for 4 minutes. */
function burstyAcu(days: number, from = NOW - days * 86400000) {
  const t: number[] = [], v: number[] = [];
  for (let ms = from; ms < NOW; ms += 60000) {
    const minute = new Date(ms).getUTCMinutes();
    t.push(ms); v.push(minute >= 9 && minute < 21 ? 2 : minute >= 21 && minute < 25 ? 1 : 0.5);
  }
  return { t, v };
}
const flat = (days: number, period: number, value: number | ((ms: number) => number)) => { const t: number[] = [], v: number[] = []; for (let ms = NOW - days * 86400000; ms < NOW; ms += period * 1000) { t.push(ms); v.push(typeof value === "function" ? value(ms) : value); } return { t, v }; };

test("detectBursts finds the hourly bursts and their length; the 1.0 decay does not split them", () => {
  const s = burstyAcu(1);
  const bursts = detectBursts(s, 0.5, 2);
  assert.equal(bursts.length, 24);
  assert.equal(bursts[0].minutes, 12);
  assert.equal(bursts[0].peak, 2);
  assert.equal(new Date(bursts[0].start).getUTCMinutes(), 9);
  assert.deepEqual(detectBursts({ t: [], v: [] }, 0.5, 2), []);
  assert.deepEqual(detectBursts(s, 2, 2), [], "no range, no bursts");
});

test("burstCadence: hourly when the starts share a five-minute slot, daily by hour, irregular otherwise", () => {
  const hourly = detectBursts(burstyAcu(1), 0.5, 2);
  assert.deepEqual(burstCadence(hourly), { cadence: "hourly", top_start_minute: 5 });
  const daily = [0, 1, 2, 3].map((d) => ({ start: new Date(T0 + d * 86400000 + 3 * 3600000 + (d % 2) * 7 * 60000).toISOString(), minutes: 30, peak: 2 }));
  assert.equal(burstCadence(daily).cadence, "daily");
  assert.equal(burstCadence(daily).top_start_minute, 180);
  const irregular = [0, 1, 2, 3, 4, 5, 6].map((i) => ({ start: new Date(T0 + i * 5.3 * 3600000 + i * 11 * 60000).toISOString(), minutes: 5, peak: 2 }));
  assert.equal(burstCadence(irregular).cadence, "irregular");
  assert.equal(burstCadence(irregular.slice(0, 2)).cadence, null);
});

test("buildProfile: the Serverless v2 cluster with hourly bursts and a cache-starved read storm", () => {
  const acu1m = burstyAcu(3);
  const acu5 = flat(14, 300, (ms) => { const minute = new Date(ms).getUTCMinutes(); return minute >= 10 && minute < 20 ? 2 : minute >= 20 && minute < 25 ? 1 : 0.5; });
  const series = {
    reads: flat(14, 300, 330_000), writes: flat(14, 300, 1_000), storage: flat(14, 3600, 6.39e9),
    cpu_avg: flat(14, 300, 20), cpu_max: flat(14, 300, 90), conn_avg: flat(14, 300, 12), conn_max: flat(14, 300, 40), mem_min: flat(14, 300, 0.6 * 2 ** 30),
    cache_hit: flat(14, 300, 91), acu_1m: acu1m, acu_avg: acu5, acu_util: flat(14, 300, 50),
  };
  const p = buildProfile(target(), series, NOW);
  assert.equal(p.io.reads_per_day, 330_000 * 288);
  assert.equal(p.io.writes_per_day, 1_000 * 288);
  assert.equal(p.io.read_write_ratio, 330);
  assert.equal(p.io.storage_gb, 6.39);
  assert.equal(p.io.io_cost_standard_usd_month, Math.round(((330_000 + 1_000) * 288 * 30.4 / 1e6) * 0.20 * 100) / 100);
  assert.equal(p.io.days_with_data, 14);
  assert.equal(p.io.buffer_cache_hit_pct_avg, 91);
  const c = p.capacity!;
  assert.equal(c.floor, 0.5); assert.equal(c.cap, 2);
  assert.equal(c.pct_time_at_cap, 0.2);
  assert.equal(c.pct_time_at_floor, 0.733, "44 of every 60 minutes at 0.5 ACU");
  assert.equal(c.bursts.count, 72);
  assert.equal(c.bursts.per_day, 24);
  assert.equal(c.bursts.cadence, "hourly");
  assert.equal(c.bursts.median_minutes, 12);
  assert.equal(c.db_fits_in_cache_at_avg, false);
  assert.equal(c.db_fits_in_cache_at_cap, false, "6.39 GB does not fit in 3 GiB of cache at 2 ACU");
  assert.equal(p.shape, "scheduled_bursts");
  assert.ok(p.notes.some((n) => /larger than the buffer cache/.test(n)));
  assert.ok(p.notes.some((n) => /reads outnumber writes 330:1/.test(n)));
  assert.equal(p.daily.length, 14);
  assert.equal(p.daily[0].reads, 330_000 * 288);
  assert.equal(p.daily[0].avg_acu, 0.79, "per hour on the five-minute series: two samples at 2, one at 1, nine at 0.5");
});

test("buildProfile: a provisioned instance has no capacity block and takes its shape from CPU; per-second IOPS become per day", () => {
  const series = { reads: flat(14, 300, 50), writes: flat(14, 300, 5), cpu_avg: flat(14, 300, 3), cpu_max: flat(14, 300, 8) };
  const p = buildProfile(target({ kind: "instance", id: "db-1", serverless: false, configured_min_acu: null, configured_max_acu: null, instance_class: "db.t4g.medium" }), series, NOW);
  assert.equal(p.capacity, null);
  assert.equal(p.io.reads_per_day, 50 * 86400);
  assert.equal(p.shape, "mostly_idle");
  assert.equal(shapeOf({ capacity: null, cpu: { avg_pct: 10, p95_pct: 60, max_pct: 90 } }), "irregular_bursts");
  assert.equal(shapeOf({ capacity: null, cpu: { avg_pct: 40, p95_pct: 55, max_pct: 70 } }), "steady");
  assert.equal(shapeOf({ capacity: null, cpu: { avg_pct: null, p95_pct: null, max_pct: null } }), "unknown");
});

test("parseSlowLog aggregates Postgres durations by normalised statement and counts temp files and checkpoints; MySQL slow-log blocks too", () => {
  const pg = [
    "2026-09-22 10:00:01 UTC:10.0.0.1(1234):app@db:[100]:LOG:  duration: 1500.123 ms  statement: SELECT * FROM events WHERE user_id = 42 AND ts > '2026-09-01'",
    "2026-09-22 10:00:02 UTC:10.0.0.1(1234):app@db:[100]:LOG:  duration: 2500.5 ms  statement: SELECT * FROM events WHERE user_id = 43 AND ts > '2026-09-02'",
    "2026-09-22 10:00:03 UTC:10.0.0.1(1234):app@db:[100]:LOG:  duration: 300 ms  execute <unnamed>: UPDATE users SET seen = $1 WHERE id = $2",
    "2026-09-22 10:00:04 UTC::@:[50]:LOG:  temporary file: path \"base/pgsql_tmp/pgsql_tmp50.0\", size 104857600",
    "2026-09-22 10:00:05 UTC::@:[40]:LOG:  checkpoint starting: time",
    "2026-09-22 10:00:09 UTC::@:[40]:LOG:  checkpoint complete: wrote 100 buffers",
  ].join("\n");
  const r = parseSlowLog(pg);
  assert.equal(r.duration_lines, 3);
  assert.equal(r.temp_file_lines, 1);
  assert.equal(r.checkpoint_lines, 2);
  assert.equal(r.statements.length, 2);
  assert.equal(r.statements[0].count, 2);
  assert.equal(r.statements[0].total_ms, 4001);
  assert.equal(r.statements[0].max_ms, 2501);
  assert.equal(r.statements[0].sql, "SELECT * FROM events WHERE user_id = ? AND ts > '?'");
  assert.equal(r.statements[1].sql, "UPDATE users SET seen = $? WHERE id = $?");
  const my = ["# Time: 2026-09-22T10:00:00", "# User@Host: app[app] @ [10.0.0.1]", "# Query_time: 2.5  Lock_time: 0.0 Rows_sent: 1", "SET timestamp=1;", "SELECT count(*) FROM orders WHERE status = 'open';"].join("\n");
  const r2 = parseSlowLog(my);
  assert.equal(r2.duration_lines, 1);
  assert.equal(r2.statements[0].total_ms, 2500);
  assert.equal(r2.statements[0].sql, "SELECT count(*) FROM orders WHERE status = '?';");
  assert.equal(parseSlowLog("").duration_lines, 0);
});

test("parseLoadAnswers reads the five answers and maps unknown choices to unknown; anything malformed is null", () => {
  const a = parseLoadAnswers({
    shape: { type: "choice", choice: "scheduled_bursts", confidence: 0.83 }, io_cause: { type: "choice", choice: "cache_starved_reads", confidence: 0.9 },
    throttled_by_cap: { type: "noul", noul: 0.7 }, structural: { type: "noul", noul: 0.95 }, lever: { type: "choice", choice: "io_optimized_storage", confidence: 0.6 },
  }, { model: "m", call_id: 7 });
  assert.equal(a?.shape, "scheduled_bursts"); assert.equal(a?.io_cause, "cache_starved_reads"); assert.equal(a?.structural, 0.95); assert.equal(a?.lever, "io_optimized_storage"); assert.equal(a?.call_id, 7);
  const odd = parseLoadAnswers({ shape: { type: "choice", choice: "zigzag", confidence: 0.5 }, io_cause: { type: "choice", choice: "moon", confidence: 0.5 }, throttled_by_cap: { type: "noul", noul: 0.1 }, structural: { type: "noul", noul: 0.2 }, lever: { type: "choice", choice: "pray", confidence: 0.5 } });
  assert.equal(odd?.shape, "unknown"); assert.equal(odd?.io_cause, "unknown"); assert.equal(odd?.lever, "unknown");
  assert.equal(parseLoadAnswers({ shape: { type: "choice", choice: "steady" } }), null);
  assert.equal(parseLoadAnswers(null), null);
});

test("profileHash ignores small drift and changes with the picture", () => {
  const series = { reads: flat(14, 300, 330_000), writes: flat(14, 300, 1_000), storage: flat(14, 3600, 6.39e9), cache_hit: flat(14, 300, 91), acu_1m: burstyAcu(3), acu_avg: flat(14, 300, 0.8) };
  const base = buildProfile(target(), series, NOW);
  const drift = buildProfile(target(), { ...series, reads: flat(14, 300, 345_000), cache_hit: flat(14, 300, 91.6) }, NOW);
  const changed = buildProfile(target(), { ...series, reads: flat(14, 300, 900_000), acu_1m: flat(3, 60, 2) }, NOW);
  assert.equal(profileHash(base, null), profileHash(drift, null));
  assert.notEqual(profileHash(base, null), profileHash(changed, null));
  assert.notEqual(profileHash(base, null), profileHash(base, { enabled: true, window_days: 7, statements: [{ sql: "SELECT 1", load_avg: 1, share_pct: 100 }] }));
});

test("rdsLoadTargets: one entry per cluster, standalone instances by id, fresh profiles skipped; resourceFacts finds a cluster and carries its load", () => {
  const ins = db.prepare("insert into inventory_rds(db_instance_identifier, class, engine, engine_version, storage_type, storage_gb, status, region, created, cluster, monthly_usd, snapshot) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
  ins.run("sphinx-hub-production-instance-1", "db.serverless", "aurora-postgresql", "16.11", "aurora", 6.39, "available", "us-east-1", "2025-01-01T00:00:00Z", "sphinx-hub-production", 150, JSON.stringify({ tags: { Name: "sphinx" } }));
  ins.run("lnd-db-1", "db.r7g.xlarge", "aurora-postgresql", "16.4", "aurora-iopt1", 200, "available", "us-east-1", "2025-01-01T00:00:00Z", "lnd-cluster", 400, "{}");
  ins.run("lnd-db-2", "db.r7g.xlarge", "aurora-postgresql", "16.4", "aurora-iopt1", 200, "available", "us-east-1", "2025-01-01T00:00:00Z", "lnd-cluster", 400, "{}");
  ins.run("legacy-mysql", "db.t4g.medium", "mysql", "8.0", "gp3", 50, "available", "us-east-1", "2025-01-01T00:00:00Z", null, 60, "{}");
  assert.deepEqual(rdsLoadTargets(1).map((t) => t.id), ["legacy-mysql", "lnd-cluster", "sphinx-hub-production"]);

  const series = { reads: flat(14, 300, 330_000), writes: flat(14, 300, 1_000), storage: flat(14, 3600, 6.39e9), cache_hit: flat(14, 300, 91), acu_1m: burstyAcu(3), acu_avg: flat(14, 300, 0.8), cpu_avg: flat(14, 300, 20), cpu_max: flat(14, 300, 90) };
  const profile = buildProfile(target(), series, NOW);
  const jev = parseLoadAnswers({ shape: { type: "choice", choice: "scheduled_bursts", confidence: 0.8 }, io_cause: { type: "choice", choice: "cache_starved_reads", confidence: 0.9 }, throttled_by_cap: { type: "noul", noul: 0.7 }, structural: { type: "noul", noul: 0.95 }, lever: { type: "choice", choice: "io_optimized_storage", confidence: 0.6 } });
  db.prepare("insert into rds_load_profiles(target_id, kind, region, profile, statements, slow_log, jev, profile_hash) values (?, 'cluster', 'us-east-1', ?, ?, ?, ?, ?)")
    .run("sphinx-hub-production", JSON.stringify(profile), JSON.stringify({ enabled: false, window_days: 7, statements: [], note: "PI off" }), JSON.stringify({ files: [], lines_scanned: 0, duration_lines: 0, temp_file_lines: 0, checkpoint_lines: 0, statements: [], note: "no durations" }), JSON.stringify(jev), profileHash(profile, null));
  assert.deepEqual(rdsLoadTargets(1).map((t) => t.id), ["legacy-mysql", "lnd-cluster"], "a profile from this minute is fresh");

  // by the cluster id, and through a member instance id
  assert.equal(latestRdsLoad("sphinx-hub-production")?.jev?.lever, "io_optimized_storage");
  assert.equal(latestRdsLoad("sphinx-hub-production-instance-1")?.target_id, "sphinx-hub-production");
  assert.equal(latestRdsLoad("legacy-mysql"), null);

  const facts = resourceFacts({ resource: "sphinx-hub-production", resource_name: null, rule: "aurora_storage_tier" });
  assert.equal(facts.kind, "rds");
  assert.equal(facts.id, "sphinx-hub-production");
  assert.deepEqual(facts.cluster, { id: "sphinx-hub-production", members: ["sphinx-hub-production-instance-1"], storage_type: "aurora" });
  assert.equal(facts.engine, "aurora-postgresql 16.11");
  assert.deepEqual(facts.tags, { Name: "sphinx" });
  assert.equal(facts.load?.shape, "scheduled_bursts");
  assert.equal(facts.load?.capacity?.db_fits_in_cache_at_cap, false);
  assert.equal(facts.load?.jev?.structural, 0.95);
  assert.equal(facts.load?.statements_note, "PI off");
  const two = resourceFacts({ resource: "lnd-cluster", resource_name: null, rule: "aurora_storage_tier" });
  assert.deepEqual(two.cluster?.members, ["lnd-db-1", "lnd-db-2"]);
  assert.equal(two.monthly_usd, 800);
  assert.equal(two.load, null);

  // the rule cites the profile and trusts a structural pattern more
  const sum = loadSummary(latestRdsLoad("sphinx-hub-production"));
  const note = auroraLoadNote(sum!, 0.6);
  assert.equal(note.confidence, 0.8);
  assert.match(note.note, /95\.0M reads/);
  assert.match(note.note, /at the ceiling 20% of the time, 24 bursts a day \(hourly\)/);
  assert.match(note.note, /does not fit in the buffer cache/);
  assert.match(note.note, /Jev: scheduled bursts, I\/O from cache starved reads \(90%\), structural 95%, first lever io optimized storage/);
  assert.equal(auroraLoadNote(undefined, 0.6).confidence, 0.6);
  assert.equal(auroraLoadNote({ ...sum!, jev: { ...sum!.jev!, structural: 0.2 } }, 0.6).confidence, 0.4);
});

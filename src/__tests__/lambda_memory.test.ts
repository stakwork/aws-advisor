import assert from "node:assert/strict";
import { test } from "node:test";
import { memoryVerdict, monthlyComputeUsd, parseReportRow, targetMemory, type VerdictInput } from "../actions/lambda_memory.js";

const base = (over: Partial<VerdictInput> = {}): VerdictInput => ({ configured_mb: 1024, max_used_mb: 300, n: 5000, p95_ms: 800, avg_ms: 400, invocations_month: 2_000_000, arm: false, ...over });

test("lambda memory: the target is the peak plus 50 % headroom, rounded up to 64 MB, never under 128", () => {
  assert.equal(targetMemory(300), 512); // 450 → 512
  assert.equal(targetMemory(40), 128); // 60 → floor
  assert.equal(targetMemory(85.4), 192); // 128.1 → the next 64 MB step
  assert.equal(targetMemory(1000), 1536);
});

test("lambda memory: a peak under half the configured memory with enough reports is trimmed and the saving is the GB-seconds difference", () => {
  const v = memoryVerdict(base());
  assert.equal(v.target_mb, 512);
  const expected = Math.round((monthlyComputeUsd(1024, 400, 2_000_000, false) - monthlyComputeUsd(512, 400, 2_000_000, false)) * 100) / 100;
  assert.equal(v.saving_usd_month, expected);
  assert.ok(v.saving_usd_month > 1);
  assert.match(v.reason, /peak memory used 300 MB \(29 % of the configured 1024 MB\)/);
  assert.match(v.reason, /50 % headroom/);
});

test("lambda memory: too few reports, a peak over half, and the 128 MB floor leave the function alone", () => {
  assert.equal(memoryVerdict(base({ n: 99 })).target_mb, null);
  assert.match(memoryVerdict(base({ n: 99 })).reason, /99 REPORT line/);
  assert.equal(memoryVerdict(base({ max_used_mb: 520 })).target_mb, null);
  assert.match(memoryVerdict(base({ max_used_mb: 520 })).reason, /51 %/);
  assert.equal(memoryVerdict(base({ configured_mb: 128, max_used_mb: 20 })).target_mb, null);
  assert.match(memoryVerdict(base({ configured_mb: 128, max_used_mb: 20 })).reason, /floor/);
});

test("lambda memory: the target never lands on the configured value and a saving under 1 USD is not worth a row", () => {
  // 192 configured, peak 60 → target 128 (one step below), fine
  assert.equal(memoryVerdict(base({ configured_mb: 192, max_used_mb: 60, invocations_month: 5_000_000 })).target_mb, 128);
  // 256 configured, peak 128 exactly half → target 192 capped at 256-64 = 192
  assert.equal(memoryVerdict(base({ configured_mb: 256, max_used_mb: 128, invocations_month: 5_000_000 })).target_mb, 192);
  // a quiet function: 1024 → 512 saves cents
  const small = memoryVerdict(base({ invocations_month: 1000 }));
  assert.equal(small.target_mb, null);
  assert.match(small.reason, /under 1/);
  // arm is cheaper per GB-second, so the same trim saves less
  assert.ok(memoryVerdict(base({ arm: true })).saving_usd_month < memoryVerdict(base()).saving_usd_month);
});

test("lambda memory: a Logs Insights row is parsed with bytes → MB and an empty row is null", () => {
  const row = [{ field: "max_used", value: String(300 * 1048576) }, { field: "avg_used", value: String(200 * 1048576) }, { field: "p95_ms", value: "812.5" }, { field: "avg_ms", value: "401" }, { field: "n", value: "5000" }, { field: "configured", value: String(1024 * 1048576) }];
  const s = parseReportRow(row)!;
  assert.equal(s.max_used_mb, 300); assert.equal(s.avg_used_mb, 200); assert.equal(s.p95_ms, 812.5); assert.equal(s.n, 5000); assert.equal(s.configured_mb, 1024);
  assert.equal(parseReportRow([{ field: "n", value: "0" }]), null);
  assert.equal(parseReportRow([]), null);
});

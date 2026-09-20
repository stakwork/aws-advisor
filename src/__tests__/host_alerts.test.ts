import { test } from "node:test";
import assert from "node:assert";
import { hostVerdicts, sampleFromProbe } from "../host_alerts.js";

const t = { memWarn: 85, memAlarm: 95, swapWarn: 25, loadPerCore: 1.5 };
const s = (o: Partial<ReturnType<typeof sampleFromProbe>>) => ({ collected_at: "2026-09-20T10:00:00Z", cpus: 4, mem_used_pct: 40, swap_used_pct: 0, load1: 1, load5: 1, load15: 1, uptime_seconds: 100000, ...o });

test("host verdicts: memory, swap and load with hysteresis; a reboot from a falling uptime", () => {
  assert.deepEqual(hostVerdicts(s({}), null, t, new Set()).raise, []);
  assert.equal(hostVerdicts(s({ mem_used_pct: 88 }), null, t, new Set()).raise[0].kind, "memory_high");
  assert.equal(hostVerdicts(s({ mem_used_pct: 96 }), null, t, new Set(["memory_high"])).raise[0].kind, "memory_full");
  assert.deepEqual(hostVerdicts(s({ mem_used_pct: 96 }), null, t, new Set(["memory_high"])).close, ["memory_high"]);
  assert.deepEqual(hostVerdicts(s({ mem_used_pct: 92 }), null, t, new Set(["memory_full"])).raise, [], "an open alarm holds at 92");
  assert.deepEqual(hostVerdicts(s({ mem_used_pct: 70 }), null, t, new Set(["memory_full"])).close, ["memory_full"]);
  assert.equal(hostVerdicts(s({ swap_used_pct: 40 }), null, t, new Set()).raise[0].kind, "swap_in_use");
  assert.equal(hostVerdicts(s({ load15: 7 }), null, t, new Set()).raise[0].kind, "load_high", "7 on 4 cores is 1.75 per core");
  assert.deepEqual(hostVerdicts(s({ load15: 5 }), null, t, new Set()).raise, [], "1.25 per core is under the line");
  assert.deepEqual(hostVerdicts(s({ load15: 5 }), null, t, new Set(["load_high"])).raise, [], "an open load alert holds at 1.25");
  const reboot = hostVerdicts(s({ uptime_seconds: 600 }), s({ uptime_seconds: 100000 }), t, new Set());
  assert.equal(reboot.raise[0].kind, "reboot");
  assert.match(reboot.raise[0].message, /rebooted at about/);
  assert.deepEqual(hostVerdicts(s({ uptime_seconds: 103600 }), s({ uptime_seconds: 100000 }), t, new Set()).raise, [], "uptime growing is no reboot");
});

test("a probe converts to a sample with memory and swap percentages", () => {
  const x = sampleFromProbe("2026-09-20T10:00:00Z", { cpus: 2, memory: { total_bytes: 1000, used_bytes: 900, swap_total_bytes: 100, swap_used_bytes: 50 }, load: { "1m": 0.5, "5m": 0.4, "15m": 0.3 }, uptime_seconds: 42 });
  assert.equal(x.mem_used_pct, 90); assert.equal(x.swap_used_pct, 50); assert.equal(x.load15, 0.3); assert.equal(x.uptime_seconds, 42);
  assert.equal(sampleFromProbe("t", { memory: {} }).swap_used_pct, null);
});

import assert from "node:assert/strict";
import { test } from "node:test";
import { decide, formatMessage, inQuietHours, resourceOfAlert } from "../notify.js";
import { validateRuntime } from "../config.js";

test("notify: the resource an alert is about, from its kind and resource column", () => {
  assert.deepEqual(resourceOfAlert({ kind: "instance_state", resource: "i-0b19ba7373c82230f" }), { kind: "ec2", id: "i-0b19ba7373c82230f" });
  assert.deepEqual(resourceOfAlert({ kind: "disk_full", resource: "i-0eee40d4ae2c317f8:/" }), { kind: "ec2", id: "i-0eee40d4ae2c317f8" });
  assert.deepEqual(resourceOfAlert({ kind: "network_step", resource: "i-0fd6f281cb9856479:NetworkIn" }), { kind: "ec2", id: "i-0fd6f281cb9856479" });
  assert.deepEqual(resourceOfAlert({ kind: "rds_memory_low", resource: "tribes-dev" }), { kind: "rds", id: "tribes-dev" });
  assert.deepEqual(resourceOfAlert({ kind: "cache_memory_high", resource: "senza-valkey-1" }), { kind: "elasticache", id: "senza-valkey-1" });
  assert.deepEqual(resourceOfAlert({ kind: "nat_traffic", resource: "nat-00c56905d5984cf31" }), { kind: "nat", id: "nat-00c56905d5984cf31" });
  assert.deepEqual(resourceOfAlert({ kind: "node_churn", resource: "AWSBatch-production-asg" }), { kind: "pool", id: "AWSBatch-production-asg" });
  assert.equal(resourceOfAlert({ kind: "commitment_underused", resource: "elasticache_ri:senza-valkey" }), null);
  assert.equal(resourceOfAlert({ kind: "credentials", resource: "advisor" }), null);
  assert.equal(resourceOfAlert({ kind: "quota", resource: null }), null);
});

test("notify: quiet hours wrap midnight; an empty or degenerate window is never quiet", () => {
  assert.equal(inQuietHours("22-07", 23), true);
  assert.equal(inQuietHours("22-07", 3), true);
  assert.equal(inQuietHours("22-07", 7), false);
  assert.equal(inQuietHours("22-07", 12), false);
  assert.equal(inQuietHours("9-17", 12), true);
  assert.equal(inQuietHours("9-17", 17), false);
  assert.equal(inQuietHours("", 3), false);
  assert.equal(inQuietHours("5-5", 5), false);
  assert.equal(validateRuntime("notifyQuietHours", "22-07"), "22-07");
  assert.equal(validateRuntime("notifyQuietHours", ""), "");
  assert.throws(() => validateRuntime("notifyQuietHours", "night"), /HH-HH/);
  assert.throws(() => validateRuntime("notifyQuietHours", "25-3"), /HH-HH/);
});

test("notify: the rule, in the words the receipt shows", () => {
  const on = { level: "alarm" as const, scope: "watched" as const, quiet: false };
  assert.deepEqual(decide({ level: "alarm", acknowledged: false, aboutResource: true, watched: true }, on), { send: true, reason: "sent" });
  assert.equal(decide({ level: "warning", acknowledged: false, aboutResource: true, watched: true }, on).reason, "skipped: warning is below the alarm threshold");
  assert.equal(decide({ level: "alarm", acknowledged: true, aboutResource: true, watched: true }, on).reason, "skipped: acknowledged before sending");
  assert.equal(decide({ level: "alarm", acknowledged: false, aboutResource: true, watched: false }, on).reason, "skipped: resource not watched");
  // account-level alerts (credentials, quota, spend) are not about a watched resource: they go
  assert.equal(decide({ level: "alarm", acknowledged: false, aboutResource: false, watched: false }, on).send, true);
  assert.equal(decide({ level: "alarm", acknowledged: false, aboutResource: true, watched: false }, { ...on, scope: "all" }).send, true);
  const warn = { level: "warning" as const, scope: "all" as const, quiet: true };
  assert.equal(decide({ level: "warning", acknowledged: false, aboutResource: true, watched: true }, warn).reason, "skipped: quiet hours");
  assert.equal(decide({ level: "alarm", acknowledged: false, aboutResource: true, watched: true }, warn).send, true);   // alarms ignore quiet hours
  assert.equal(decide({ level: "info", acknowledged: false, aboutResource: false, watched: false }, warn).reason, "skipped: info is below the warning threshold");
  assert.equal(decide({ level: "alarm", acknowledged: false, aboutResource: false, watched: false }, { ...on, level: "off" }).reason, "skipped: notifications off");
});

test("notify: the message leads with the level and the alert, then what you would look up next, then the link", () => {
  const msg = formatMessage({ id: 42, kind: "instance_state", resource: "i-1", message: "Hive (i-1) is gone (was running)", created_at: "2026-09-24 10:00:00" },
    { level: "alarm", resource: { kind: "ec2", id: "i-1", name: "Hive", region: "us-east-1" }, domains: ["api.example.com", "www.example.com"], recommendations: [{ id: 106, title: "Move Hive to Graviton", est_monthly_saving: 30.4 }], publicUrl: "https://advisor.example" });
  assert.deepEqual(msg.split("\n"), [
    "🔴 ALARM — Hive (i-1) is gone (was running)",
    "instance_state · EC2 Hive (i-1) · us-east-1",
    "Reaches: api.example.com, www.example.com",
    "Open on it: #106 Move Hive to Graviton (≈ 30 USD/month)",
    "https://advisor.example/alerts?status=all&id=42",
  ]);
  const bare = formatMessage({ id: 7, kind: "credentials", resource: "advisor", message: "AWS credentials expired", created_at: "" }, { level: "alarm", resource: null, domains: [], recommendations: [], publicUrl: "http://x" });
  assert.deepEqual(bare.split("\n"), ["🔴 ALARM — AWS credentials expired", "credentials · advisor", "http://x/alerts?status=all&id=7"]);
});

import { decideRecommendationEvent, formatRecommendationMessage } from "../notify.js";

test("notify: a decision message says what happened, by whom and why, then the resource and the link", () => {
  const rec = { id: 317, title: "Attribute the 1,940 USD NAT line", status: "approved", resource: "nat-01043d58a73015593", resource_name: "production NGW us-east-1a", est_monthly_saving: 400, decided_by: "gonzalo", decision_reason: "flow logs first" };
  assert.deepEqual(formatRecommendationMessage(rec, "approved", { publicUrl: "https://advisor.example" }).split("\n"), [
    "✅ APPROVED — #317 Attribute the 1,940 USD NAT line (≈ 400 USD/month)",
    "by gonzalo · flow logs first",
    "production NGW us-east-1a (nat-01043d58a73015593)",
    "https://advisor.example/recommendations?status=all&id=317",
  ]);
  assert.equal(formatRecommendationMessage({ ...rec, decision_reason: null, resource_name: null, est_monthly_saving: null }, "rejected", { by: "jev", publicUrl: "http://x" }).split("\n")[0], "⛔ REJECTED — #317 Attribute the 1,940 USD NAT line");
  assert.equal(formatRecommendationMessage({ ...rec, decision_reason: null, resource_name: null, est_monthly_saving: null }, "rejected", { by: "jev", publicUrl: "http://x" }).split("\n")[1], "by jev");
});

test("notify: a measured saving leads with the verdict and the numbers, never the estimate in the head", () => {
  const rec = { id: 317, title: "NAT: bake the whisper model into the image", status: "done", resource: null, resource_name: null, est_monthly_saving: 400, decided_by: "ui", decision_reason: null };
  const msg = formatRecommendationMessage(rec, "verified", { verdict: { verdict: "realised", realised_usd_month: 512, estimate_usd_month: 400, ratio: 1.28, days_after: 14, note: "NatGateway-Bytes down 330 GB/day" }, publicUrl: "http://x" });
  assert.deepEqual(msg.split("\n"), [
    "📏 MEASURED — #317 NAT: bake the whisper model into the image",
    "saving realised · 512 USD/month measured of 400 USD/month estimated (128 %) · 14 days after the decision",
    "NatGateway-Bytes down 330 GB/day",
    "http://x/recommendations?status=all&id=317",
  ]);
  assert.equal(formatRecommendationMessage(rec, "shared", { by: "gonzalo", publicUrl: "http://x" }).split("\n")[1], "status done · shared by gonzalo");
});

test("notify: recommendation events wait through quiet hours, but off and unconfigured are final; a share ignores both", () => {
  assert.deepEqual(decideRecommendationEvent({ configured: true, enabled: true, quiet: false, forced: false }), { send: true, reason: "sent" });
  assert.deepEqual(decideRecommendationEvent({ configured: true, enabled: true, quiet: true, forced: false }), { send: false, reason: null });
  assert.equal(decideRecommendationEvent({ configured: true, enabled: false, quiet: false, forced: false }).reason, "skipped: recommendation events off");
  assert.equal(decideRecommendationEvent({ configured: false, enabled: true, quiet: false, forced: true }).reason, "skipped: bot not configured");
  assert.equal(decideRecommendationEvent({ configured: true, enabled: false, quiet: true, forced: true }).send, true);
});

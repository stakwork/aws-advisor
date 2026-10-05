import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

// AWS User Notifications folded into rows (src/cloud_notifications.ts): both feeds' shapes, the window and the summary.
process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "advisor-notif-test-"));
process.env.NEO4J_URI = "";
const cn = await import("../cloud_notifications.js");
const { db } = await import("../db.js");

const ARN = (n: number) => `arn:aws:notifications::210987654321:managed-notification-configuration/category/AWS-Health/sub-category/Scheduled-Change/event/0000000000000000000000000000000${n}`;

test("notificationRowFrom: a managed overview and a configured overview fold to the same row shape; nothing without an ARN", () => {
  const managed = cn.notificationRowFrom({
    arn: ARN(1), managedNotificationConfigurationArn: "arn:aws:notifications::aws:managed-notification-configuration/category/AWS-Health/sub-category/Scheduled-Change", relatedAccount: "210987654322", creationTime: new Date("2026-10-03T10:00:00Z"),
    notificationEvent: { schemaVersion: "v1.0", sourceEventMetadata: { eventOriginRegion: "us-east-1", source: "aws.health", eventType: "AWS_EC2_INSTANCE_RETIREMENT_SCHEDULED" }, messageComponents: { headline: "An instance is scheduled for retirement" }, eventStatus: "UNHEALTHY", notificationType: "ALERT" },
    aggregationEventType: "AGGREGATE", aggregationSummary: { eventCount: 3 }, aggregatedNotificationRegions: ["us-east-1", "eu-west-1"],
  }, "managed", "210987654321", "2026-10-04T00:00:00Z");
  assert.ok(managed);
  assert.equal(managed.source, "health"); assert.equal(managed.event_type, "AWS_EC2_INSTANCE_RETIREMENT_SCHEDULED"); assert.equal(managed.headline, "An instance is scheduled for retirement");
  assert.equal(managed.notification_type, "ALERT"); assert.equal(managed.event_status, "UNHEALTHY"); assert.equal(managed.origin_region, "us-east-1"); assert.equal(managed.related_account, "210987654322");
  assert.equal(managed.created_at, "2026-10-03T10:00:00.000Z"); assert.equal(managed.aggregation, "AGGREGATE"); assert.equal(managed.event_count, 3); assert.equal(managed.regions, '["us-east-1","eu-west-1"]'); assert.equal(managed.feed, "managed");
  const configured = cn.notificationRowFrom({ arn: ARN(2), notificationConfigurationArn: "arn:aws:notifications::210987654321:configuration/0000", relatedAccount: "210987654321", creationTime: new Date("2026-10-02T10:00:00Z"), notificationEvent: { sourceEventMetadata: { source: "aws.cloudwatch", eventType: "CloudWatch Alarm State Change" }, messageComponents: { headline: "Alarm cpu-high in ALARM" }, eventStatus: "HEALTHY", notificationType: "WARNING" } }, "configured", "210987654321");
  assert.ok(configured); assert.equal(configured.feed, "configured"); assert.equal(configured.event_count, 1); assert.equal(configured.configuration_arn, "arn:aws:notifications::210987654321:configuration/0000"); assert.equal(configured.aggregation, null);
  assert.equal(cn.notificationRowFrom({ notificationEvent: {} }, "managed", null), null);
});

test("list and summary: the window, the scope, the counts by type, source and account", () => {
  const ins = db.prepare(`insert into cloud_notifications(arn, account_id, feed, source, event_type, headline, notification_type, event_status, origin_region, related_account, created_at, aggregation, event_count, regions, configuration_arn, fetched_at) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, null, ?, '[]', null, ?)`);
  const now = Date.now(); const at = (h: number) => new Date(now - h * 3600_000).toISOString(); const f = new Date().toISOString();
  ins.run(ARN(11), "210987654321", "managed", "health", "AWS_EC2_INSTANCE_RETIREMENT_SCHEDULED", "retirement", "ALERT", "UNHEALTHY", "us-east-1", "210987654321", at(2), 1, f);
  ins.run(ARN(12), "210987654321", "managed", "billing", "FreeTierUsageAlert", "free tier", "INFORMATIONAL", "HEALTHY", null, "210987654321", at(30), 1, f);
  ins.run(ARN(13), "210987654322", "managed", "health", "AWS_RDS_MAINTENANCE_SCHEDULED", "maintenance", "WARNING", "HEALTHY", "eu-west-1", "210987654322", at(24 * 10), 1, f);
  ins.run(ARN(14), "210987654322", "configured", "cloudwatch", "CloudWatch Alarm State Change", "alarm", "ALERT", "HEALTHY", "eu-west-1", "210987654322", at(24 * 40), 2, f);
  assert.equal(cn.listCloudNotifications({ days: 7 }).length, 2);
  assert.equal(cn.listCloudNotifications({ days: 30 }).length, 3);
  assert.equal(cn.listCloudNotifications({ days: 90, feed: "configured" }).length, 1);
  assert.equal(cn.listCloudNotifications({ days: 90, source: "health" }).length, 2);
  assert.deepEqual(cn.listCloudNotifications({ days: 90, scope: { id: "210987654322", primary: false } }).map((r) => r.source), ["health", "cloudwatch"], "newest first, the member alone");
  const s = cn.cloudNotificationsSummary(90);
  assert.equal(s.total, 4); assert.equal(s.alerts, 2); assert.equal(s.warnings, 1); assert.equal(s.unhealthy, 1); assert.equal(s.managed, 3); assert.equal(s.configured, 1);
  assert.deepEqual(s.by_source[0], { source: "health", n: 2, alerts: 1 });
  assert.deepEqual(s.by_account.map((a) => a.n), [2, 2]);
  assert.equal(s.last_fetch, null, "never refreshed through the API");
});

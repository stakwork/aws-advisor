import { test } from "node:test";
import assert from "node:assert";
import { isNoise } from "../trail.js";

test("cloudtrail noise: heartbeats and controller-driven events are noise, people and deployments are not", () => {
  assert.ok(isNoise("UpdateInstanceInformation", "i-0123456789abcdef0"));
  assert.ok(isNoise("CreateLogStream", "some-lambda"));
  assert.ok(isNoise("RunTask", "aws-batch"));
  assert.ok(isNoise("RunInstances", "AutoScaling"));
  assert.ok(!isNoise("RunTask", "alice"));
  assert.ok(!isNoise("RunInstances", "alice"));
  assert.ok(!isNoise("ModifyDBInstance", "alice"));
  assert.ok(!isNoise("PutRetentionPolicy", "deploy-role"));
  assert.ok(isNoise("PutConfigurePackageResult", "i-0123456789abcdef0"));
  assert.ok(isNoise("SendCommand", "StateManagerService"));
  assert.ok(isNoise("CreatePlatformEndpoint", "i-0123456789abcdef0"));
  assert.ok(!isNoise("ModifyDBInstance", "ops-user"));
});

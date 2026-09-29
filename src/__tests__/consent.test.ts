import assert from "node:assert/strict";
import { test } from "node:test";
import { AUTO_PARK_TAG, AUTO_SCALE_TAG, SCALE_BAND_TAG, isOff, isOn, normaliseConsent } from "../consent.js";
import { ACTUATOR_NEEDS, actuatorPolicy } from "../permissions.js";

test("consent: ON in any spelling is on, an absent tag is neither on nor off, anything else is an explicit off", () => {
  for (const v of ["ON", "on", "On", " true ", "yes", "1"]) { assert.equal(isOn(v), true, v); assert.equal(isOff(v), false, v); }
  for (const v of ["OFF", "off", "no", "0", "", "maybe"]) { assert.equal(isOn(v), false, v); assert.equal(isOff(v), true, v); }
  assert.equal(isOn(null), false); assert.equal(isOff(null), false); assert.equal(isOff(undefined), false);
  assert.equal(normaliseConsent("on"), "ON"); assert.equal(normaliseConsent("anything"), "OFF"); assert.equal(normaliseConsent(undefined), "OFF");
  assert.equal(AUTO_PARK_TAG, "AdvisorAutoPark"); assert.equal(AUTO_SCALE_TAG, "AdvisorAutoScale"); assert.equal(SCALE_BAND_TAG, "AdvisorScaleBand");
});

test("consent: the actuator policy carries the tag conditions, writes only the consent keys, and denies hands-off", () => {
  const st = actuatorPolicy().Statement as any[];
  const sid = (s: string) => st.find((x) => x.Sid === s);
  assert.deepEqual(sid("ActuatorAutoPark").Condition, { StringEqualsIgnoreCase: { "aws:ResourceTag/AdvisorAutoPark": "ON" } });
  assert.deepEqual(sid("ActuatorAutoPark").Action, ["ec2:StopInstances", "ec2:StartInstances"]);
  assert.deepEqual(sid("ActuatorAutoScale").Condition, { StringEqualsIgnoreCase: { "aws:ResourceTag/AdvisorAutoScale": "ON" } });
  assert.deepEqual(sid("ActuatorUsageScheduleTag").Condition["ForAllValues:StringEquals"]["aws:TagKeys"], ["advisor:schedule", "AdvisorAutoPark"]);
  assert.deepEqual(sid("ActuatorBeanstalkConsentTag").Condition["ForAllValues:StringEquals"]["aws:TagKeys"], ["AdvisorAutoScale", "AdvisorScaleBand"]);
  assert.deepEqual(sid("ActuatorAutoParkMarker").Condition["ForAllValues:StringEquals"]["aws:TagKeys"], ["advisor:parked"]);
  const deny = sid("ActuatorHandsOff");
  for (const a of ["ec2:StopInstances", "ec2:CreateTags", "elasticbeanstalk:UpdateEnvironment", "elasticbeanstalk:UpdateTagsForResource"]) assert.ok(deny.Action.includes(a), a);
  assert.deepEqual(ACTUATOR_NEEDS.consent_tag, { apply: ["ec2:CreateTags", "elasticbeanstalk:UpdateTagsForResource"], revert: ["ec2:DeleteTags", "elasticbeanstalk:UpdateTagsForResource"] });
  // no statement grants an unconditioned tag write on instances
  for (const s of st) if (s.Effect === "Allow" && (s.Action as string[]).includes("ec2:CreateTags")) assert.ok(s.Condition, `${s.Sid} writes tags without a condition`);
});

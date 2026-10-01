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
  // EC2 stop and start come only from the per-instance grant a person writes (src/autopark_grant.ts): no statement
  // opens them by a tag the actuator could write itself
  for (const gone of ["ActuatorAutoPark", "ActuatorAutoParkMarker", "ActuatorScheduleEc2", "ActuatorSwarmPark", "ActuatorSwarmParkMarker", "ActuatorHibernateChoiceTag"]) assert.equal(sid(gone), undefined, gone);
  const writable = new Set<string>();
  for (const s of st) if (s.Effect === "Allow" && (s.Action as string[]).includes("ec2:CreateTags")) for (const k of s.Condition?.["ForAllValues:StringEquals"]?.["aws:TagKeys"] ?? []) writable.add(k);
  assert.ok(!writable.has("AdvisorAutoPark"), "the actuator may not write AdvisorAutoPark");
  assert.ok(!writable.has("advisor:hibernate"), "the actuator may not write advisor:hibernate (it opens the relaunch)");
  for (const s of st) {
    if (s.Effect !== "Allow" || !(s.Action as string[]).some((a) => a === "ec2:StopInstances" || a === "ec2:StartInstances")) continue;
    const keys = Object.values(s.Condition ?? {}).flatMap((c: any) => Object.keys(c)).filter((k) => k.startsWith("aws:ResourceTag/")).map((k) => k.slice("aws:ResourceTag/".length));
    assert.ok(keys.length > 0, `${s.Sid} stops or starts instances without a condition`);
    for (const k of keys) assert.ok(!writable.has(k), `${s.Sid} opens stop/start by ${k}, a tag the actuator can write itself`);
  }
  assert.deepEqual(sid("ActuatorAutoScale").Condition, { StringEqualsIgnoreCase: { "aws:ResourceTag/AdvisorAutoScale": "ON" } });
  assert.deepEqual(sid("ActuatorUsageScheduleTag").Condition["ForAllValues:StringEquals"]["aws:TagKeys"], ["advisor:schedule"]);
  assert.deepEqual(sid("ActuatorBeanstalkConsentTag").Condition["ForAllValues:StringEquals"]["aws:TagKeys"], ["AdvisorAutoScale", "AdvisorScaleBand"]);
  for (const s of st) for (const a of s.Action as string[]) assert.ok(!/^iam:(Put|Attach|Delete|Create|Update)/.test(a), `${s.Sid}: the actuator never writes IAM (${a})`);
  const deny = sid("ActuatorHandsOff");
  for (const a of ["ec2:StopInstances", "ec2:CreateTags", "elasticbeanstalk:UpdateEnvironment", "elasticbeanstalk:AddTags", "elasticbeanstalk:RemoveTags"]) assert.ok(deny.Action.includes(a), a);
  assert.ok(ACTUATOR_NEEDS.consent_tag.apply.includes("iam:PutRolePolicy"), "a person switching Auto-park on writes the grant");
  // no statement grants an unconditioned tag write on instances
  for (const s of st) if (s.Effect === "Allow" && (s.Action as string[]).includes("ec2:CreateTags")) assert.ok(s.Condition, `${s.Sid} writes tags without a condition`);
});

test("auto-park grant: one inline policy listing exactly the granted instances, emptied away when the last one goes", async () => {
  const { grantDocument, grantedArnsOf, withArn, instanceArn, roleNameOf, accountOfArn, explainRefusal } = await import("../autopark_grant.js");
  const a = instanceArn("us-east-1", "123456789012", "i-0f0000000000e0001"), b = instanceArn("us-east-1", "123456789012", "i-0f0000000000e0002");
  assert.equal(a, "arn:aws:ec2:us-east-1:123456789012:instance/i-0f0000000000e0001");
  assert.equal(roleNameOf("arn:aws:iam::123456789012:role/advisor-actuator"), "advisor-actuator");
  assert.equal(accountOfArn("arn:aws:iam::123456789012:role/advisor-actuator"), "123456789012");
  const doc: any = grantDocument([b, a, a]);
  assert.deepEqual(doc.Statement[0], { Sid: "AutoParkStartStop", Effect: "Allow", Action: ["ec2:StartInstances", "ec2:StopInstances"], Resource: [a, b] });
  assert.deepEqual(doc.Statement[1].Condition, { "ForAllValues:StringEquals": { "aws:TagKeys": ["advisor:parked"] } });
  assert.deepEqual(grantedArnsOf(doc), [a, b]);
  assert.deepEqual(grantedArnsOf({ Statement: { Sid: "AutoParkStartStop", Resource: a } }), [a]);
  assert.deepEqual(grantedArnsOf({ Statement: [{ Sid: "Other", Resource: [a] }] }), []);
  assert.deepEqual(withArn([a], b, true), [a, b]);
  assert.deepEqual(withArn([a, b], a, false), [b]);
  assert.equal(grantDocument(withArn([a], a, false)), null, "no instance left: the policy is deleted");
  assert.match(explainRefusal(Object.assign(new Error("You are not authorized to perform this operation."), { name: "UnauthorizedOperation" }), "i-0f0000000000e0001").message, /switch Auto-park on with "Run as me"/);
  assert.equal(explainRefusal(new Error("InsufficientInstanceCapacity"), "i-x").message, "InsufficientInstanceCapacity");
});

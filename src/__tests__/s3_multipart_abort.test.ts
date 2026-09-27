import assert from "node:assert/strict";
import { test } from "node:test";
import { RULE_ID, abortRule, abortSaving, coversWholeBucket, existingAbort } from "../actions/s3_multipart_abort.js";
import { mergeRules } from "../actions/s3_lifecycle.js";

test("multipart abort: an enabled whole-bucket abort rule counts as covered; a prefixed or disabled one does not", () => {
  const whole = { ID: "ops", Status: "Enabled", Filter: { Prefix: "" }, AbortIncompleteMultipartUpload: { DaysAfterInitiation: 3 } } as any;
  const noFilter = { ID: "legacy", Status: "Enabled", AbortIncompleteMultipartUpload: { DaysAfterInitiation: 14 } } as any;
  const prefixed = { ID: "logs", Status: "Enabled", Filter: { Prefix: "logs/" }, AbortIncompleteMultipartUpload: { DaysAfterInitiation: 3 } } as any;
  const legacyPrefix = { ID: "old", Status: "Enabled", Prefix: "tmp/", AbortIncompleteMultipartUpload: { DaysAfterInitiation: 3 } } as any;
  const tagged = { ID: "tagged", Status: "Enabled", Filter: { And: { Prefix: "", Tags: [{ Key: "a", Value: "b" }] } }, AbortIncompleteMultipartUpload: { DaysAfterInitiation: 3 } } as any;
  const disabled = { ...whole, ID: "off", Status: "Disabled" };
  const transitionOnly = { ID: "ia", Status: "Enabled", Filter: { Prefix: "" }, Transitions: [{ Days: 30, StorageClass: "STANDARD_IA" }] } as any;
  assert.equal(coversWholeBucket(whole), true);
  assert.equal(coversWholeBucket(noFilter), true);
  assert.equal(coversWholeBucket(prefixed), false);
  assert.equal(coversWholeBucket(legacyPrefix), false);
  assert.equal(coversWholeBucket(tagged), false);
  assert.deepEqual(existingAbort([transitionOnly, whole]), { id: "ops", days: 3 });
  assert.deepEqual(existingAbort([noFilter]), { id: "legacy", days: 14 });
  assert.equal(existingAbort([prefixed, disabled, transitionOnly]), null);
  assert.equal(existingAbort([]), null);
});

test("multipart abort: the rule merges by id, keeps the rest in order, and disables cleanly for the revert", () => {
  const existing = [{ ID: "ia", Status: "Enabled", Filter: { Prefix: "" }, Transitions: [{ Days: 30, StorageClass: "STANDARD_IA" }] }, { ID: RULE_ID, Status: "Disabled", Filter: { Prefix: "" }, AbortIncompleteMultipartUpload: { DaysAfterInitiation: 30 } }] as any[];
  const merged = mergeRules(existing, [abortRule(7)]);
  assert.deepEqual(merged.map((r) => r.ID), ["ia", RULE_ID]);
  assert.equal(merged[1].Status, "Enabled");
  assert.equal(merged[1].AbortIncompleteMultipartUpload?.DaysAfterInitiation, 7);
  assert.equal(abortRule(0.4).AbortIncompleteMultipartUpload?.DaysAfterInitiation, 1);
  assert.equal(abortRule(7, "Disabled").Status, "Disabled");
});

test("multipart abort: the estimate is Standard storage of the parts when known, else nothing is claimed", () => {
  assert.equal(abortSaving(null), null);
  assert.equal(abortSaving(0), null);
  assert.equal(abortSaving(100e9), 2.3);
});

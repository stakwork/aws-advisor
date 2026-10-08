import { test } from "node:test";
import assert from "node:assert";
import { setSetting } from "../db.js";
import { actuatorRoleFor, roleAccount } from "../accounts.js";

test("roleAccount reads the account out of a role ARN", () => {
  assert.equal(roleAccount("arn:aws:iam::222222222222:role/advisor-act"), "222222222222");
  assert.equal(roleAccount("not an arn"), null);
});

test("actuatorRoleFor: a member's own role, else the Auto-actions role when it lives in that member", () => {
  setSetting("aws_credentials_meta", JSON.stringify({ mode: "keys", accountId: "111111111111" }));
  setSetting("cfg:actRoleArn", "arn:aws:iam::222222222222:role/advisor-act");
  setSetting("accounts", JSON.stringify([
    { account_id: "222222222222", name: "boxes", role_arn: "arn:aws:iam::222222222222:role/advisor-read", act_role_arn: null, regions: null, enabled: true },
    { account_id: "333333333333", name: "other", role_arn: "arn:aws:iam::333333333333:role/advisor-read", act_role_arn: "arn:aws:iam::333333333333:role/own-act", regions: null, enabled: true },
    { account_id: "444444444444", name: "none", role_arn: "arn:aws:iam::444444444444:role/advisor-read", act_role_arn: null, regions: null, enabled: true },
  ]));
  assert.equal(actuatorRoleFor("111111111111"), "arn:aws:iam::222222222222:role/advisor-act", "the parent uses the setting");
  assert.equal(actuatorRoleFor("222222222222"), "arn:aws:iam::222222222222:role/advisor-act", "the member the setting's role lives in");
  assert.equal(actuatorRoleFor("333333333333"), "arn:aws:iam::333333333333:role/own-act", "a member's own role wins");
  assert.equal(actuatorRoleFor("444444444444"), "", "nothing fits: dry runs only");
  setSetting("cfg:actRoleArn", ""); setSetting("accounts", "[]"); setSetting("aws_credentials_meta", "");
});

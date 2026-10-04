import assert from "node:assert/strict";
import { test } from "node:test";
import { bucketsByAccount } from "../s3_inventory.js";

test("bucketsByAccount groups buckets by account with each account's regions; rows without an account id are the parent's", () => {
  const groups = bucketsByAccount([
    { account_id: "111111111111", region: "us-east-1" }, { account_id: "111111111111", region: "eu-west-1" }, { account_id: "111111111111", region: "us-east-1" },
    { account_id: "222222222222", region: "us-east-1" }, { region: null }, { account_id: null, region: "us-west-2" },
  ]);
  assert.deepEqual(groups.get("111111111111"), ["us-east-1", "eu-west-1"]);
  assert.deepEqual(groups.get("222222222222"), ["us-east-1"]);
  assert.deepEqual(groups.get(null), ["us-east-1", "us-west-2"]);
  assert.equal(groups.size, 3);
});

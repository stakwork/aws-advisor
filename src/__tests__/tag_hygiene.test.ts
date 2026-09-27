import assert from "node:assert/strict";
import { test } from "node:test";
import { missingTags, normaliseTags, parseRequired, suggestTags, tagList } from "../tag_hygiene.js";

test("tag hygiene: aliases and case satisfy a required key, an empty value does not", () => {
  const req = ["owner", "env"];
  assert.deepEqual(missingTags({ Owner: "platform", Environment: "prod" }, req), []);
  assert.deepEqual(missingTags({ team: "data", stage: "dev" }, req), []);
  assert.deepEqual(missingTags({ OWNER: "x" }, req), ["env"]);
  assert.deepEqual(missingTags({ env: "", owner: "  " }, req), ["owner", "env"]);
  assert.deepEqual(missingTags({}, req), ["owner", "env"]);
  assert.deepEqual(missingTags(null, ["costcenter"]), ["costcenter"]);
  // a key without aliases matches itself only, case-insensitively
  assert.deepEqual(missingTags({ CostCenter: "42" }, ["costcenter"]), []);
});

test("tag hygiene: the setting is parsed leniently and tags arrive in three shapes", () => {
  assert.deepEqual(parseRequired(" Owner, ENV ,,owner"), ["owner", "env"]);
  assert.deepEqual(parseRequired(""), ["owner", "env"]);
  assert.deepEqual(parseRequired(undefined), ["owner", "env"]);
  assert.deepEqual(normaliseTags({ Name: "api-1", Env: "prod" }), { name: "api-1", env: "prod" });
  assert.deepEqual(normaliseTags('{"Team":"core"}'), { team: "core" });
  assert.deepEqual(normaliseTags([{ Key: "Owner", Value: "ops" }]), { owner: "ops" });
  assert.deepEqual(normaliseTags("not json"), {});
});

test("tag hygiene: suggestions come from the name and the tags there, never invented", () => {
  assert.deepEqual(suggestTags({ kind: "ec2", name: "payments-api-prod", tags: {} }), { owner: "payments", env: "prod" });
  // "swarm" is not an owner, so a swarm-named box gets env=customer and no owner
  assert.deepEqual(suggestTags({ kind: "ec2", name: "swarm-acme-42", tags: {} }), { env: "customer" });
  assert.deepEqual(suggestTags({ kind: "rds", name: "staging-db", tags: { Team: "data" } }), { owner: "data", env: "staging" });
  assert.deepEqual(suggestTags({ kind: "s3", name: "x", tags: {} }), {});
  // only the missing keys are suggested; a Jev dev_or_test role fills env when the name says nothing
  assert.deepEqual(suggestTags({ kind: "ec2", name: "gonzalo-box", tags: {}, role: "dev_or_test" }, ["env"]), { env: "dev" });
  assert.deepEqual(suggestTags({ kind: "ec2", name: "gonzalo-box", tags: {}, role: "dev_or_test" }, ["owner"]), { owner: "gonzalo" });
  assert.equal(tagList({ owner: "data", env: "" }), "Key=owner,Value=data Key=env,Value=<value>");
});

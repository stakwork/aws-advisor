import assert from "node:assert/strict";
import { test } from "node:test";
import { JEV_MAX_OPTIONS, applyJevAnswer, jevAttributeLogGroups, jevGroupState, jevOptionsFor, jevStateHash } from "../log_attribution_jev.js";

const systems = [
  { id: "rds:orion", name: "orion", kind: "rds_instance", members: ["orion"], region: "us-east-1" },
  { id: "pool:web", name: "web-asg", kind: "pool", members: ["i-1", "i-2"], pool: "web-asg", aliases: ["Web env"], region: "us-east-1", archetype: "web_or_api", member_count: 2 },
  { id: "ec2:i-9", name: "swarm9", kind: "instance", members: ["i-9"], region: "us-east-1" },
  { id: "cache:sidekiq", name: "sidekiq", kind: "cache_group", members: ["sidekiq-001"], region: "us-east-1" },
];

test("jev options: the rule candidates first, then compute systems, then the rest, always with none", () => {
  const o = jevOptionsFor({ name: "/orion/app", tags: null, candidates: ["rds:orion (1: orion)", "nope:x (1: x)"], how: "weak match only" }, systems);
  assert.deepEqual(Object.keys(o), ["rds:orion", "pool:web", "ec2:i-9", "cache:sidekiq", "none"]);
  assert.match(o["pool:web"], /^web-asg: pool, us-east-1, archetype web_or_api, 2 members, also known as Web env, ids i-1, i-2$/);
  const many = Array.from({ length: 80 }, (_, i) => ({ id: `ec2:i-${i}`, name: `box${i}`, kind: "instance", members: [`i-${i}`] }));
  assert.equal(Object.keys(jevOptionsFor({ name: "/x", tags: null, candidates: [], how: "no match" }, many)).length, JEV_MAX_OPTIONS + 1);
});

test("jev state and hash: the path is split, empty tags are left out, and a changed tag or system set re-asks", () => {
  const g = { name: "/ecs/prod-api/app", tags: {}, candidates: [], how: "no match" };
  const s = jevGroupState(g);
  assert.deepEqual(s.path, ["ecs", "prod-api", "app"]); assert.equal(s.tags, undefined); assert.equal(s.rules_closest, undefined);
  const o = jevOptionsFor(g, systems);
  assert.notEqual(jevStateHash(g, o), jevStateHash({ ...g, tags: { service: "api" } }, o));
  assert.notEqual(jevStateHash(g, o), jevStateHash(g, { ...o, "pool:api": "api" }));
  assert.equal(jevStateHash(g, o), jevStateHash({ ...g, how: "weak match only" }, o), "what the rules said is context, not identity");
});

test("jev answer: an owner only above the threshold and never none; malformed answers are ignored", () => {
  assert.deepEqual(applyJevAnswer({ choice: "pool:web", confidence: 0.82, probabilities: { "pool:web": 0.82, none: 0.1 } }), { owner: "pool:web", confidence: 0.82, probabilities: { "pool:web": 0.82, none: 0.1 } });
  assert.equal(applyJevAnswer({ choice: "pool:web", confidence: 0.45 })!.owner, null, "under the bar: a hint, not an owner");
  assert.equal(applyJevAnswer({ choice: "none", confidence: 0.95 })!.owner, null);
  assert.equal(applyJevAnswer({ choice: 3, confidence: 0.9 }), null);
  assert.equal(applyJevAnswer(undefined), null);
});

test("jev attribution with no budget answers from the cache only and asks nothing, whatever the key", async () => {
  const { db } = await import("../db.js");
  db.prepare("delete from log_group_jev where name like '/test-jev/%'").run();
  const r = await jevAttributeLogGroups([{ name: "/test-jev/never/seen", tags: null, candidates: [], how: "no match" }], systems, { max: 0 });
  assert.equal(r.size, 0);
  db.prepare("insert into log_group_jev(name, owner, confidence, probabilities, state_hash, decided_at) values ('/test-jev/cached', 'pool:web', 0.9, '{}', ?, ?)")
    .run(jevStateHash({ name: "/test-jev/cached", tags: null, candidates: [], how: "no match" }, jevOptionsFor({ name: "/test-jev/cached", tags: null, candidates: [], how: "no match" }, systems)), new Date().toISOString());
  const c = await jevAttributeLogGroups([{ name: "/test-jev/cached", tags: null, candidates: [], how: "no match" }], systems, { max: 0 });
  assert.deepEqual({ owner: c.get("/test-jev/cached")?.owner, cached: c.get("/test-jev/cached")?.cached }, { owner: "pool:web", cached: true });
  db.prepare("delete from log_group_jev where name like '/test-jev/%'").run();
});

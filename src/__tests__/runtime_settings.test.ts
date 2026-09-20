import { test } from "node:test";
import assert from "node:assert";
import { config, runtimeRaw, validateRuntime } from "../config.js";
import { db } from "../db.js";

test("runtime settings: a saved value wins over the environment, a reset falls back, validation guards each kind", () => {
  const key = "cfg:agentModel";
  const before = db.prepare("select value from settings where key = ?").get(key);
  try {
    process.env.AGENT_MODEL = "anthropic/from-env";
    db.prepare("delete from settings where key = ?").run(key);
    assert.deepEqual(runtimeRaw("agentModel"), { value: "anthropic/from-env", source: "env" });
    assert.equal(config.agentModel, "anthropic/from-env");
    db.prepare("insert into settings(key, value) values (?, ?)").run(key, "openai/gpt-5");
    assert.equal(config.agentModel, "openai/gpt-5");
    assert.equal(runtimeRaw("agentModel").source, "setting");
    db.prepare("delete from settings where key = ?").run(key);
    delete process.env.AGENT_MODEL;
    assert.deepEqual(runtimeRaw("agentModel"), { value: "anthropic/claude-opus-5", source: "default" });
  } finally {
    db.prepare("delete from settings where key = ?").run(key);
    if (before) db.prepare("insert into settings(key, value) values (?, ?)").run(key, (before as any).value);
  }
  assert.equal(validateRuntime("runCron", "0 6 * * *"), "0 6 * * *");
  assert.equal(validateRuntime("runCron", "off"), "off");
  assert.throws(() => validateRuntime("runCron", "every day"), /cron expression/);
  assert.throws(() => validateRuntime("probeMax", "0"), /at least 1/);
  assert.equal(validateRuntime("probeMax", "40"), "40");
  assert.throws(() => validateRuntime("probeScope", "some"), /one of/);
  assert.equal(validateRuntime("agentWebSearch", "yes"), "true");
  assert.equal(validateRuntime("neo4jUri", "bolt://neo4j.sphinx:7687/"), "bolt://neo4j.sphinx:7687");
  assert.throws(() => validateRuntime("neo4jUri", "neo4j.sphinx:7687"), /URL/);
  assert.throws(() => validateRuntime("nope", "x"), /unknown setting/);
});

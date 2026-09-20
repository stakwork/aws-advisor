import { test } from "node:test";
import assert from "node:assert";
import { db } from "../db.js";
import { checkAgentQuota, checkProbeQuota, quotaStatus } from "../quota.js";

test("quotas: agent runs are counted from agent_runs; over the hourly limit the call is refused and one alert opens", () => {
  db.prepare("delete from agent_runs where request_id like 'quota-test-%'").run();
  db.prepare("delete from alerts where kind = 'quota'").run();
  db.prepare("delete from settings where key = 'cfg:agentRunsPerHour'").run();
  db.prepare("insert into settings(key, value) values ('cfg:agentRunsPerHour', '2')").run();
  try {
    assert.doesNotThrow(() => checkAgentQuota("test"));
    for (let i = 0; i < 2; i++) db.prepare("insert into agent_runs(kind, request_id, status) values ('findings', ?, 'pending')").run(`quota-test-${i}`);
    assert.equal(quotaStatus()[0].used >= 2, true);
    assert.throws(() => checkAgentQuota("test"), /2 agent runs in the last hour/);
    assert.throws(() => checkAgentQuota("test"), /refused/);
    assert.equal((db.prepare("select count(*) as n from alerts where kind = 'quota' and acknowledged = 0").get() as any).n, 1, "one open alert, not one per refusal");
  } finally {
    db.prepare("delete from agent_runs where request_id like 'quota-test-%'").run();
    db.prepare("delete from alerts where kind = 'quota'").run();
    db.prepare("delete from settings where key = 'cfg:agentRunsPerHour'").run();
  }
});

test("quotas: failed probe attempts count against the hourly probe limit", () => {
  db.prepare("delete from settings where key = 'cfg:probesPerHour'").run();
  db.prepare("insert into settings(key, value) values ('cfg:probesPerHour', '3')").run();
  try {
    checkProbeQuota("i-0123456789abcdef0"); checkProbeQuota("i-0123456789abcdef0"); checkProbeQuota("i-0123456789abcdef0");
    assert.throws(() => checkProbeQuota("i-0123456789abcdef0"), /probes in the last hour/);
  } finally { db.prepare("delete from settings where key = 'cfg:probesPerHour'").run(); db.prepare("delete from alerts where kind = 'quota'").run(); }
});

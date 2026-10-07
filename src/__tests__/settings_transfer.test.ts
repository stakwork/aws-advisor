import { test } from "node:test";
import assert from "node:assert/strict";
import { db } from "../db.js";
import { runtimeRaw } from "../config.js";
import { applyImport, buildPayload, openBundle, planImport, sealPayload, type SettingsPayload } from "../settings_transfer.js";

const PASS = "correct horse battery";
const KEYS = { mode: "keys" as const, accessKey: "AKIAEXAMPLEKEY000001", secretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", regions: ["us-east-1"], defaultRegion: "us-east-1" };
const base = (): SettingsPayload => ({ runtime: [], aws: null, aws_account_id: "111122223333", members: [], benchmarks: null, compliance_benchmarks: null, prompts: {}, probe_scripts: {} });

const snapshot = () => db.prepare("select key, value from settings").all() as { key: string; value: string }[];
const restore = (rows: { key: string; value: string }[]) => { db.prepare("delete from settings").run(); const ins = db.prepare("insert into settings(key, value) values (?, ?)"); for (const r of rows) ins.run(r.key, r.value); };

test("settings transfer: the bundle is sealed, keeps no secret in clear, and opens only with its passphrase", () => {
  const p = { ...base(), aws: KEYS, runtime: [{ key: "typesafeApiKey", value: "ts-example-secret-0001", source: "setting" as const }] };
  const b = sealPayload(p, PASS);
  const text = JSON.stringify(b);
  assert.doesNotMatch(text, /AKIAEXAMPLEKEY000001|EXAMPLEKEY|ts-example-secret/);
  assert.equal(b.from.account_id, "111122223333");
  assert.equal(b.from.aws_mode, "keys");
  assert.deepEqual(openBundle(JSON.parse(text), PASS).aws, KEYS);
  assert.throws(() => openBundle(b, "wrong passphrase!"), /wrong passphrase/);
  assert.throws(() => openBundle({ ...b, cipher: { ...b.cipher, data: Buffer.from("tampered").toString("base64") } }, PASS), /wrong passphrase|changed/);
  assert.throws(() => openBundle({ format: "other" }, PASS), /not a Cloud Advisor/);
  assert.throws(() => sealPayload(p, "short"), /at least 10/);
});

test("settings transfer: export reads saved runtime values, members and overrides; import plans and applies them", async () => {
  const before = snapshot();
  const envBefore = process.env.SPHINX_BOT_ID;
  try {
    db.prepare("delete from settings").run();
    delete process.env.SPHINX_BOT_ID;
    const set = db.prepare("insert into settings(key, value) values (?, ?)");
    set.run("cfg:typesafeApiKey", "ts-example-secret-0001");
    set.run("cfg:agentModel", "openai/example-model");
    set.run("accounts", JSON.stringify([{ account_id: "222233334444", name: "child", role_arn: "arn:aws:iam::222233334444:role/aws-advisor-read", act_role_arn: null, regions: null, enabled: true, last_test: { ok: true, at: "2026-10-01T00:00:00Z" } }]));
    set.run("prompt:chat", "be brief");
    const out = buildPayload();
    assert.deepEqual(out.runtime.find((r) => r.key === "typesafeApiKey"), { key: "typesafeApiKey", value: "ts-example-secret-0001", source: "setting" });
    assert.equal(out.members.length, 1);
    assert.equal((out.members[0] as any).last_test, undefined);
    assert.equal(out.prompts.chat, "be brief");

    // the target: empty, with an env value of its own
    db.prepare("delete from settings").run();
    process.env.SPHINX_BOT_ID = "target-bot";
    const incoming: SettingsPayload = { ...out, runtime: [...out.runtime, { key: "sphinxBotId", value: "source-bot", source: "env" }, { key: "neonApiKey", value: "neon-example", source: "env" }, { key: "notARealKey", value: "x", source: "setting" }] };
    const plan = planImport(incoming);
    const row = (k: string) => plan.runtime.find((r) => r.key === k);
    assert.equal(row("typesafeApiKey")?.selected, true);
    assert.equal(row("typesafeApiKey")?.secret, true);
    assert.equal(row("sphinxBotId")?.selected, false, "the target's own env wins over a value the source had from its env");
    assert.equal(row("neonApiKey")?.selected, true, "an env value fills a gap on the target");
    assert.equal(row("notARealKey"), undefined);
    assert.deepEqual(plan.members, [{ account_id: "222233334444", name: "child", enabled: true }]);

    const r = await applyImport(incoming, { connect: false });
    assert.ok(r.runtime.applied.includes("typesafeApiKey") && r.runtime.applied.includes("agentModel") && r.runtime.applied.includes("neonApiKey"));
    assert.ok(r.runtime.skipped.includes("sphinxBotId"));
    assert.equal(runtimeRaw("typesafeApiKey").value, "ts-example-secret-0001");
    assert.equal(runtimeRaw("sphinxBotId").value, "target-bot");
    assert.equal(JSON.parse((db.prepare("select value from settings where key = 'accounts'").get() as any).value)[0].last_test, null);
    assert.equal((db.prepare("select value from settings where key = 'prompt:chat'").get() as any).value, "be brief");

    // a member that is the incoming parent is refused before anything is written
    await assert.rejects(applyImport({ ...base(), aws_account_id: "222233334444", members: incoming.members }, { connect: false }), /parent account/);
  } finally {
    restore(before);
    if (envBefore === undefined) delete process.env.SPHINX_BOT_ID; else process.env.SPHINX_BOT_ID = envBefore;
  }
});

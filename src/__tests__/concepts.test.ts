import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "advisor-concepts-test-"));
process.env.REPO2GRAPH_URL = "";

const { OPERATIONAL_PATTERN_SEEDS, operationalPatternsBlock, patternFingerprint, seedOperationalPatterns, systemPromptFor } = await import("../concepts.js");
const { registerDefaultPrompt } = await import("../prompts.js");

test("the operational pattern seeds are distinct, named and phrased as rules", () => {
  assert.ok(OPERATIONAL_PATTERN_SEEDS.length >= 4);
  assert.equal(new Set(OPERATIONAL_PATTERN_SEEDS.map((s) => s.key)).size, OPERATIONAL_PATTERN_SEEDS.length);
  assert.equal(new Set(OPERATIONAL_PATTERN_SEEDS.map((s) => s.name)).size, OPERATIONAL_PATTERN_SEEDS.length);
  for (const s of OPERATIONAL_PATTERN_SEEDS) {
    assert.match(s.key, /^[a-z_]+$/);
    assert.ok(s.rule.length > 40 && !s.rule.includes("\n"), `${s.key} is one paragraph`);
    assert.equal(patternFingerprint(s.key), `pattern:${s.key}`);
  }
  assert.ok(OPERATIONAL_PATTERN_SEEDS.some((s) => /advisor is the monitor/i.test(s.rule)));
});

test("operationalPatternsBlock renders only pattern concepts, one rule per line with its id", () => {
  const concepts = [
    { id: "aws/cost-advisor/pool-members", name: "Pool members", description: "Pool members are not candidates.", scope: "pattern" as const },
    { id: "aws/cost-advisor/web-rule", name: "web migrate rule", description: "A generic rule.", scope: "generic" as const },
    { id: "aws/cost-advisor/keep-x", name: "keep x", description: "An internal decision.", scope: "internal" as const },
    { id: "aws/cost-advisor/ssm-late", name: "SSM late", description: "New instances register late.", scope: "pattern" as const },
  ];
  const block = operationalPatternsBlock(concepts);
  assert.equal(block, "Operational patterns to respect (facts, not guesses):\n- [aws/cost-advisor/pool-members] Pool members are not candidates.\n- [aws/cost-advisor/ssm-late] New instances register late.");
  assert.equal(operationalPatternsBlock(concepts.filter((c) => c.scope !== "pattern")), "");
});

test("systemPromptFor appends the patterns to the editable prompt, and nothing when there are none", async () => {
  registerDefaultPrompt("observe", "You observe.");
  const withPatterns = await systemPromptFor("observe", [{ id: "p1", name: "n", description: "Churn is normal.", scope: "pattern" }]);
  assert.equal(withPatterns, "You observe.\nOperational patterns to respect (facts, not guesses):\n- [p1] Churn is normal.");
  assert.equal(await systemPromptFor("observe", []), "You observe.");
  registerDefaultPrompt("chat", "You chat.");
  assert.equal(await systemPromptFor("chat", [{ id: "p1", name: "n", description: "Churn is normal.", scope: "pattern" }]), "You chat.", "chat never carried the patterns");
});

test("seeding is a no-op without repo2graph", async () => {
  assert.deepEqual(await seedOperationalPatterns(), { created: [], adopted: [] });
});

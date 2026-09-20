import { test } from "node:test";
import assert from "node:assert";
import { critiqueText, gradeByRubric, valuesAt } from "../rubric.js";
import { loadTasks, taskFor } from "../tasks.js";

test("rubric paths fan out over arrays", () => {
  const o = { changes: [{ evidence: "a 12", confidence: 0.5 }, { evidence: "b", confidence: 2 }], summary: "One. Two. Three. Four." };
  assert.deepEqual(valuesAt(o, "changes[].evidence"), ["a 12", "b"]);
  assert.deepEqual(valuesAt(o, "summary"), ["One. Two. Three. Four."]);
  assert.deepEqual(valuesAt(o, "missing[].x"), []);
});

test("task files load, register the prompts and carry rubrics the grader understands", () => {
  const tasks = loadTasks();
  assert.equal(tasks.length, 4);
  const observe = taskFor("observe");
  assert.ok(observe.system.includes("observing agent"));
  assert.ok(observe.rubric.length >= 6);
  assert.equal(observe.retry.max, 1);
  const good = { summary: "Flat day. One idle box.", changes: [{ what: "x", why: "y", evidence: "19 % memory", resource: "i-1", expected: false, confidence: 0.7 }], attention: [], proposals: [{ action: "right-size", resource: "i-1", tier: "approve", rationale: "idle" }], nothing_to_report: false };
  const g = gradeByRubric(good, observe.rubric, { resources: ["i-1"] });
  assert.equal(g.score, 1, JSON.stringify(g.checks.filter((c) => !c.pass)));
  const bad = { summary: "A. B. C. D. E.", changes: [{ what: "x", why: "y", evidence: "looks higher", confidence: 3 }], attention: [], proposals: [{ action: "terminate everything", tier: "auto", rationale: "idle" }], nothing_to_report: true };
  const b = gradeByRubric(bad, observe.rubric, { resources: ["i-1"] });
  assert.ok(b.score < 0.5);
  assert.match(critiqueText(b), /failed these checks/);
  assert.match(critiqueText(b), /destructive/);
  const inc = gradeByRubric({ cause: "c", confidence: 0.8, evidence: ["5 GB at 02:30", "baseline 2 GB"], fixes: [{ title: "t", action_type: "enable_flow_logs", resource: "vpc-1", tier: "approve", rationale: "r" }, { title: "t2", action_type: "enable_flow_logs", resource: "vpc-1", tier: "approve", rationale: "r" }] }, taskFor("incident").rubric);
  assert.ok(inc.checks.find((c) => c.check.startsWith("no duplicate"))!.pass === false);
});

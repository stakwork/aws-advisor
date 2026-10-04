import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

// Playbooks from sources: the mod parser and the reference extraction (src/sources.ts), the agent answer's parsing,
// the publish decision and what is due (src/playbook_gen.ts), and the generated-only lookup (nothing is hand-written; a held generation leaves the
// fallback (src/playbooks.ts). Nothing here talks to the agent, Jev or the web.
process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "advisor-playbooks-test-"));
process.env.TYPESAFE_API_KEY = "";
process.env.REPO2GRAPH_URL = "";
const modRoot = fs.mkdtempSync(path.join(os.tmpdir(), "advisor-mods-test-"));
process.env.POWERPIPE_MOD_DIR = modRoot;

const src = await import("../sources.js");
const gen = await import("../playbook_gen.js");
const pb = await import("../playbooks.js");
const { db } = await import("../db.js");

// a mod on disk the way Powerpipe installs it: one thrifty control with its service doc, one compliance control with its own doc
const thrifty = path.join(modRoot, ".powerpipe", "mods", "github.com", "turbot", "steampipe-mod-aws-thrifty@v9.9.9");
fs.mkdirSync(path.join(thrifty, "controls", "docs"), { recursive: true });
fs.writeFileSync(path.join(thrifty, "controls", "ec2.pp"), `locals { x = 1 }

control "ec2_instance_with_graviton" {
  title       = "EC2 instances without graviton processor should be reviewed"
  description = "With graviton processor you can save money. See https://aws.amazon.com/ec2/graviton/ for details."
  severity    = "low"

  tags = merge(local.ec2_common_tags, {
    class = "deprecated"
  })

  sql = <<-EOQ
    select arn as resource, case when architecture = 'arm64' then 'ok' else 'alarm' end as status
    from aws_ec2_instance
  EOQ
}

control "ec2_instance_running_max_age" {
  title       = "Long running EC2 instances should be reviewed"
  description = "Instances should ideally be ephemeral."
  severity    = "low"
  sql = <<-EOQ
    select 1
  EOQ
}
`);
fs.writeFileSync(path.join(thrifty, "controls", "docs", "ec2.md"), "## Thrifty EC2 Benchmark\n\nThrifty developers eliminate unused instances.\n");
const compliance = path.join(modRoot, ".powerpipe", "mods", "github.com", "turbot", "steampipe-mod-aws-compliance@v1.0.0");
fs.mkdirSync(path.join(compliance, "foundational_security", "docs"), { recursive: true });
fs.writeFileSync(path.join(compliance, "foundational_security", "ec2.pp"), `control "foundational_security_ec2_1" {
  title         = "1 Amazon EBS snapshots should not be public"
  description   = "EBS snapshots should not be public, determined by the ability to be restorable by anyone."
  severity      = "critical"
  query         = query.ebs_snapshot_not_publicly_restorable
  documentation = file("./foundational_security/docs/foundational_security_ec2_1.md")

  tags = merge(local.foundational_security_ec2_common_tags, {
    foundational_security_item_id  = "ec2_1"
  })
}
`);
fs.writeFileSync(path.join(compliance, "foundational_security", "docs", "foundational_security_ec2_1.md"), "## Description\n\nPublic snapshots expose data.\n\n## Remediation\n\nMake the snapshot private: https://docs.aws.amazon.com/ebs/latest/userguide/ebs-modifying-snapshot-permissions.html and see https://example.com/blog for a story.\n");

test("readModControls parses every control block of the installed mods: title, description, severity, sql or query, tags, the control's own doc or the service doc", () => {
  const all = src.readModControls();
  assert.deepEqual(all.map((c) => c.control_id).sort(), ["aws_compliance.control.foundational_security_ec2_1", "aws_thrifty.control.ec2_instance_running_max_age", "aws_thrifty.control.ec2_instance_with_graviton"]);
  const g = all.find((c) => c.name === "ec2_instance_with_graviton")!;
  assert.equal(g.title, "EC2 instances without graviton processor should be reviewed"); assert.equal(g.severity, "low"); assert.match(g.sql!, /architecture = 'arm64'/); assert.deepEqual(g.tags, { class: "deprecated" });
  assert.equal(g.doc, null); assert.match(g.benchmark_doc!, /Thrifty EC2 Benchmark/);
  const f = all.find((c) => c.name === "foundational_security_ec2_1")!;
  assert.equal(f.query, "ebs_snapshot_not_publicly_restorable"); assert.match(f.doc!, /Public snapshots expose data/); assert.equal(f.sql, null);
  const text = src.controlSourceText(f);
  assert.match(text, /^# 1 Amazon EBS snapshots/); assert.match(text, /## Documentation shipped with the control/); assert.doesNotMatch(text, /```sql/);
  assert.match(src.controlSourceText(g), /```sql/);
  assert.deepEqual(src.modDirs().map((m) => [m.mod, m.version]).sort(), [["aws_compliance", "v1.0.0"], ["aws_thrifty", "v9.9.9"]]);
});

test("refreshModSources stores one benchmark_doc source per control and reports what changed; sourcesFor returns the mod text first and lists references it will not read", async () => {
  const r1 = src.refreshModSources(); assert.equal(r1.controls, 3); assert.equal(r1.changed, 3);
  const r2 = src.refreshModSources(); assert.equal(r2.changed, 0, "unchanged text keeps its hash");
  const s = src.getSource("mod:aws_thrifty.control.ec2_instance_with_graviton")!;
  assert.equal(s.origin, "mod"); assert.equal(s.kind, "benchmark_doc"); assert.ok(s.hash); assert.ok(s.changed_at);
  // the referenced pages are allow-listed hosts only; example.com is listed but never fetched
  assert.deepEqual(src.referencedUrls("see https://docs.aws.amazon.com/x/y.html#frag, and https://example.com/blog. Also https://aws.amazon.com/ec2/graviton/)").map((u) => [u.url, u.fetchable]),
    [["https://docs.aws.amazon.com/x/y.html", true], ["https://aws.amazon.com/ec2/graviton/", true], ["https://example.com/blog", false]]);
  const t = src.htmlToText("<html><head><title>EBS snapshots</title><script>x()</script></head><body><nav>menu</nav><main><h1>Snapshots</h1><p>Make it &amp; private.</p><pre>aws ec2 modify-snapshot-attribute</pre></main><footer>f</footer></body></html>");
  assert.equal(t.title, "EBS snapshots"); assert.match(t.text, /Snapshots\nMake it & private\./); assert.doesNotMatch(t.text, /menu|x\(\)/);
});

test("parsePlaybookResult keeps well-formed playbooks with their step citations and drops the rest", () => {
  const out = gen.parsePlaybookResult({ playbooks: [
    { control_id: "aws_thrifty.control.ec2_instance_with_graviton", title: "Not on Graviton", meaning: "x86 instance", act_when: "arm64 builds exist", ignore_when: "x86-only binaries", steps: [{ text: "check the AMI", source: "mod:aws_thrifty.control.ec2_instance_with_graviton" }, { text: "launch a g type", source: "https://aws.amazon.com/ec2/graviton/" }, "verify"], saving: "price delta x 730", references: ["https://aws.amazon.com/ec2/graviton/"], gaps: [], confidence: 0.8 },
    { control_id: "aws_thrifty.control.broken", meaning: "no steps", act_when: "a", ignore_when: "b", steps: [], saving: "" },
    "junk",
  ] });
  assert.equal(out.length, 1);
  assert.deepEqual(out[0].steps.map((s) => s.source), ["mod:aws_thrifty.control.ec2_instance_with_graviton", "https://aws.amazon.com/ec2/graviton/", null]);
  assert.equal(out[0].confidence, 0.8); assert.equal(out[0].title, "Not on Graviton");
  assert.deepEqual(gen.parsePlaybookResult({ nope: 1 }), []);
});

test("publishDecision: with a seed the generated playbook must cover it; without one the agent's confidence decides; Jev silence holds it", () => {
  const p = { control_id: "c", title: "t", meaning: "m", act_when: "a", ignore_when: "i", steps: [], saving: "s", references: [], gaps: [], confidence: 0.7 };
  const j = (covers: number | null) => ({ tier: "approve" as const, effort: "low" as const, irreversible: 0.1, service_impact: 0, effort_score: 0, covers, model: "m", call_id: 1, judged: true });
  assert.equal(gen.publishDecision(p, j(0.9), true).published, true);
  assert.deepEqual([gen.publishDecision(p, j(0.3), true).published, gen.publishDecision(p, j(0.3), true).review_status], [false, "below_reference"]);
  assert.deepEqual([gen.publishDecision(p, j(null), true).published, gen.publishDecision(p, j(null), true).review_status], [false, "unjudged"]);
  assert.equal(gen.publishDecision(p, j(null), false).published, true, "no seed: confidence 0.7 suffices");
  assert.equal(gen.publishDecision({ ...p, confidence: 0.2 }, j(null), false).review_status, "low_confidence");
});

test("playbookFor serves the published generated playbook with its provenance and nothing while a generation is held; listPlaybooks lists generated controls only; controlsDue sees listed sources, moved hashes and age", async () => {
  const id = "aws_thrifty.control.ec2_instance_with_graviton";
  assert.equal(pb.playbookFor(id), null, "nothing generated yet: nothing in force");
  const now = new Date().toISOString();
  const ins = db.prepare(`insert into playbooks(control_id, title, meaning, act_when, ignore_when, steps, saving, references_, gaps, confidence, tier, effort, judged, sources, generated_at, generated_by, stale_after, review_status, published, reason, status)
    values (?, ?, ?, ?, ?, ?, ?, '[]', '[]', ?, 'approve', 'low', '{"judged":true,"covers":null}', ?, ?, 'test', ?, ?, ?, ?, 'completed')`);
  const srcHash = src.getSource(`mod:${id}`)!.hash;
  // held: the agent was not confident
  ins.run(id, "Generated title", "gm", "ga", "gi", JSON.stringify([{ text: "s1", source: `mod:${id}` }, { text: "s2", source: null }]), "gs", 0.3, JSON.stringify([{ id: `mod:${id}`, hash: srcHash }]), now, "2999-01-01T00:00:00Z", "low_confidence", 0, "the agent's confidence is 0.30 (needs 0.5)");
  assert.equal(pb.playbookFor(id), null, "a held generation is not in force");
  assert.equal(pb.heldPlaybook(id)?.review_status, "low_confidence");
  // published
  db.prepare("update playbooks set published = 1, review_status = 'generated' where control_id = ?").run(id);
  const live = pb.playbookFor(id)!;
  assert.equal(live.provenance?.origin, "generated"); assert.equal(live.title, "Generated title"); assert.deepEqual(live.steps, ["s1", "s2"]); assert.deepEqual(live.citations, [`mod:${id}`, null]);
  assert.equal(pb.heldPlaybook(id), null);
  // a generated-only control shows up in the list
  const newId = "aws_compliance.control.foundational_security_ec2_1";
  ins.run(newId, "Public snapshot", "m", "a", "i", JSON.stringify([{ text: "s", source: `mod:${newId}` }]), "none: a security control", 0.8, JSON.stringify([{ id: `mod:${newId}`, hash: "stale-hash" }]), now, "2999-01-01T00:00:00Z", "generated", 1, "confidence");
  assert.ok(pb.listPlaybooks().some((p) => p.control_id === newId));
  const due = gen.controlsDue();
  assert.ok(due.some((d) => d.control_id === newId && /source changed/.test(d.why)), "its source hash moved");
  assert.ok(!due.some((d) => d.control_id === id), "the graviton playbook is current");
  assert.ok(due.some((d) => /sources listed, no generated playbook yet/.test(d.why)), "listed controls without a generation are due");
  db.prepare("update playbooks set stale_after = '2000-01-01T00:00:00Z' where control_id = ?").run(id);
  assert.ok(gen.controlsDue().some((d) => d.control_id === id && /older than/.test(d.why)));
  assert.equal(gen.reviewPlaybook(id, "disputed"), true); assert.equal(pb.playbookFor(id), null, "a disputed generation is out of force; nothing replaces it");
  assert.equal(gen.reviewPlaybook("nope", "reviewed"), false);
});

test("the prompt names each source by id and caps the total", () => {
  const section = gen.controlSection("aws_thrifty.control.x", [{ id: "mod:aws_thrifty.control.x", kind: "benchmark_doc", origin: "mod", title: "X", url: null, text: "the mod text", hash: "h", fetched_at: null, changed_at: null, error: null }], ["https://example.com/notread"]);
  assert.match(section, /### Source mod:aws_thrifty\.control\.x — X \(benchmark mod\)/); assert.match(section, /not read.*example\.com/);
  const prompt = gen.buildPlaybookPrompt([section, "x".repeat(100_000)]);
  assert.ok(prompt.length < 72_000); assert.match(prompt, /\[sources truncated here\]/); assert.match(prompt, /2 controls/);
});

test("readJudgement reads Jev's typed answers (noul and score objects) and tightens the tier from approve; a missing answer keeps the fallback", () => {
  const fb = { tier: "report" as const, effort: "high" as const, irreversible: null, service_impact: null, effort_score: null, covers: null, model: null, call_id: null, judged: false };
  const j = gen.readJudgement({ pb_irreversible: { type: "noul", noul: 0.06 }, pb_service_impact: { type: "score", score: 0.6 }, pb_effort: { type: "score", score: 0.93 }, pb_covers: { type: "noul", noul: 0.67 } }, fb);
  assert.deepEqual([j.tier, j.effort, j.covers, j.judged], ["approve", "medium", 0.67, true]);
  const risky = gen.readJudgement({ pb_irreversible: { type: "noul", noul: 0.9 }, pb_service_impact: { type: "score", score: 0.2 }, pb_effort: { type: "score", score: 0.1 } }, fb);
  assert.equal(risky.tier, "report"); assert.equal(risky.effort, "low"); assert.equal(risky.covers, null);
  assert.deepEqual(gen.readJudgement({}, fb), { ...fb });
  assert.equal(gen.readJudgement({ pb_covers: 0.8 }, fb).covers, 0.8, "a bare number is accepted too");
});

test("confidenceOf folds words and percentages into 0..1; gaps given as one string become one item", () => {
  assert.deepEqual([gen.confidenceOf(0.8), gen.confidenceOf("0.4"), gen.confidenceOf(85), gen.confidenceOf("high"), gen.confidenceOf("medium"), gen.confidenceOf("low"), gen.confidenceOf(undefined)], [0.8, 0.4, 0.85, 0.85, 0.6, 0.3, 0.5]);
  const out = gen.parsePlaybookResult({ playbooks: [{ control_id: "c", title: "t", meaning: "m", act_when: "a", ignore_when: "i", steps: [{ text: "s1", source: "x" }, { text: "s2", source: "x" }], saving: "s", references: ["mod:c — title (benchmark mod)", "https://docs.aws.amazon.com/a"], gaps: "one long gap", confidence: "medium" }] });
  assert.deepEqual(out[0].gaps, ["one long gap"]); assert.equal(out[0].confidence, 0.6); assert.deepEqual(out[0].references, ["https://docs.aws.amazon.com/a"], "only URLs are references");
});

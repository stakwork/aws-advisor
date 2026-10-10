import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

// The adapter boundary: the registry lists the AWS adapter and the stubs, the AWS adapter emits the generic model
// from its own storage and reports its accounts, and the mirror's re-exports still point at the moved mapping.
process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "advisor-adapters-test-"));
process.env.TYPESAFE_API_KEY = "";
process.env.REPO2GRAPH_URL = "";

const reg = await import("../adapters/index.js");
const types = await import("../adapters/types.js");
const mirror = await import("../graph_mirror.js");
const { db } = await import("../db.js");

test("the registry: the adapters (aws, vercel, github, local) with their sections, storage and capabilities; stubs with what each needs", () => {
  assert.deepEqual(reg.adapters().map((a) => a.id), ["aws", "vercel", "github", "local"]);
  const aws = reg.adapterFor("aws")!;
  assert.equal(aws.label, "AWS"); assert.equal(aws.flow.boundary, "account");
  assert.deepEqual(aws.ui.settings.map((s) => s.id), ["access", "permissions", "probes", "benchmarks", "members"]);
  assert.ok(aws.storage.includes("inventory_ec2") && aws.storage.includes("instance_packages") && aws.storage.includes("alas_advisories"));
  assert.equal(aws.capabilities.probes, true); assert.equal(typeof aws.configured(), "boolean", "configured() reads the machine's connection file, not the data dir");
  assert.equal(reg.adapterFor("gcp"), null);
  const vercel = reg.adapterFor("vercel")!; assert.equal(vercel.flow.boundary, "team"); assert.equal(vercel.capabilities.probes, false); assert.equal(vercel.configured(), false, "no token in this test's environment");
  const list = reg.providers();
  assert.deepEqual(list.map((p) => [p.id, p.available]), [["aws", true], ["vercel", true], ["github", true], ["local", true], ["gcp", false], ["azure", false], ["cloudflare", false]]);
  assert.equal(list.find((p) => p.id === "cloudflare")!.boundary, "account");
  assert.equal(typeof list[0].configured, "boolean");
});

test("the AWS adapter emits generic resource nodes from its storage, and the mirror re-exports the moved mapping unchanged", async () => {
  db.prepare("insert into inventory_ec2(instance_id, name, instance_type, state, region, account_id, snapshot, first_seen, last_seen) values ('i-0abc', 'web', 'm6i.large', 'running', 'us-east-1', '123456789012', ?, '2026-01-01', '2026-10-01')").run(JSON.stringify({ tags: { Name: "web" }, network: { private_ips: ["10.0.0.1"] } }));
  const aws = reg.adapterFor("aws")!;
  const nodes = aws.resources("123456789012");
  const web = nodes.find((n) => n.id === "i-0abc")!;
  assert.equal(web.label, "AdvisorBox"); assert.equal(web.props.kind, "vm"); assert.equal(web.compute?.opaque, false); assert.equal(web.native_type, "ec2_instance"); assert.equal(web.state, "running"); assert.equal(web.name, "web");
  assert.equal(types.RESOURCE_LABELS.includes(web.label), true);
  assert.equal(mirror.RESOURCE_LABELS, types.RESOURCE_LABELS);
  assert.equal(typeof mirror.resourceFromEc2, "function"); assert.equal(mirror.genericState("ec2_instance", "stopping"), "stopped");
  const accounts = await aws.accounts();
  if (aws.configured()) { assert.ok(accounts.length >= 1); assert.equal(accounts[0].provider, "aws"); assert.equal(accounts[0].native_type, "account"); assert.equal(accounts[0].parent_id, null); }
  else assert.deepEqual(accounts, [], "no credentials: no accounts");
  assert.equal(aws.layers.length >= 5, true);
});

test("the account scope: none or 'all' means every account; the primary scope also takes rows stored without an account id; a member scope is exact", async () => {
  const scope = await import("../scope.js");
  assert.equal(scope.accountScope({}), null); assert.equal(scope.accountScope({ account: "all" }), null);
  const primary = reg.adapterFor("aws")!.primaryAccountId();
  const p = scope.accountScope({ account: primary })!; assert.equal(p.primary, true);
  assert.deepEqual(scope.accountWhere(p), { sql: "coalesce(account_id, '') in (?, '')", params: [primary] });
  const m = scope.accountScope({ account: "210987654321" })!; assert.equal(m.primary, false);
  assert.deepEqual(scope.accountWhere(m, "a.account_id"), { sql: "a.account_id = ?", params: ["210987654321"] });
  assert.deepEqual(scope.accountWhere(null), { sql: "1=1", params: [] });
  // the EC2 list honours it: the fixture row belongs to 123456789012; rows without an account id follow the primary
  db.prepare("insert into inventory_ec2(instance_id, name, instance_type, state, region, account_id, snapshot, first_seen, last_seen) values ('i-0noacct', 'legacy', 't3.small', 'running', 'us-east-1', '', '{}', '2026-01-01', '2026-10-01')").run();
  const inv = await import("../inventory.js");
  assert.deepEqual(inv.listEc2({ scope: m }).map((r) => r.instance_id), []);
  assert.deepEqual(inv.listEc2({ scope: scope.accountScope({ account: "123456789012" }) }).map((r) => r.instance_id), ["i-0abc"]);
  assert.equal(inv.listEc2({}).length, 2);
});

test("a Vercel team's projects run on one opaque runtime box with its compute", async () => {
  const { runtimeBox, runtimeBoxId } = await import("../adapters/vercel/index.js");
  const box = runtimeBox("team_test", { first: "2026-01-01", last: "2026-10-01", any: true });
  assert.equal(box.id, runtimeBoxId("team_test")); assert.equal(box.label, "AdvisorBox");
  assert.deepEqual([box.props.kind, box.props.opaque, box.compute?.opaque, box.compute?.os, box.monthly_usd], ["managed", true, true, null, null]);
  assert.equal(runtimeBox("team_test", { first: null, last: null, any: false }).state, "unknown", "no live project, nothing known to run");
});

test("local machines: declared in Settings, a box hosting its OS with a deployment per thing it runs", async () => {
  const local = reg.adapterFor("local")!;
  const lm = await import("../adapters/local/index.js");
  assert.equal(local.configured(), false); assert.deepEqual(await local.accounts(), []);
  assert.deepEqual(lm.parseMachine({ name: "  " }), { ok: false, error: "a name is needed (letters or digits)" });
  assert.equal((lm.parseMachine({ name: "x", kind: "phone" }) as any).ok, false);
  assert.equal((lm.parseMachine({ name: "x", deployments: [{ name: "a", kind: "lambda" }] }) as any).ok, false);
  const r = await local.onboarding!.add({ name: "Dev Laptop", kind: "laptop", platform: "macos", os: "macOS 26", arch: "arm64", hostname: "dev.example.com",
    deployments: [{ name: "Hive stack", kind: "compose", url: "http://localhost:3000" }, { name: "hive stack", kind: "service" }, { name: "", kind: "service" }] });
  assert.equal(r.ok, true);
  assert.equal(local.configured(), true);
  const [acc] = await local.accounts(); assert.deepEqual([acc.id, acc.provider, acc.native_type], ["local", "local", "site"]);
  const nodes = local.resources("local");
  assert.deepEqual(nodes.map((n) => [n.id, n.label, n.native_type]), [["local:dev-laptop", "AdvisorBox", "local_laptop"], ["local:dev-laptop:hive-stack", "AdvisorDeployment", "local_compose"]], "the duplicate and the unnamed entries are dropped");
  assert.deepEqual([nodes[0].props.kind, nodes[0].compute?.os, nodes[0].compute?.platform, nodes[0].account_id], ["laptop", "macOS 26", "macos", "local"]);
  assert.deepEqual([nodes[1].props.platform, nodes[1].props.environment, nodes[1].props.machine_id, nodes[1].props.url], ["local", "development", "local:dev-laptop", "http://localhost:3000"]);
  assert.equal(local.owns("local:dev-laptop"), true); assert.equal(local.owns("i-0abc"), false);
  const me = lm.thisMachine(); assert.ok(me.name && me.kernel);
  assert.equal((await local.onboarding!.remove("local:nope")).ok, false);
  assert.equal((await local.onboarding!.remove("local:dev-laptop")).ok, true);
  assert.equal(local.configured(), false);
});

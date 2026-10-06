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

test("the registry: the adapters (aws, vercel) with their sections, storage and capabilities; stubs with what each needs", () => {
  assert.deepEqual(reg.adapters().map((a) => a.id), ["aws", "vercel"]);
  const aws = reg.adapterFor("aws")!;
  assert.equal(aws.label, "AWS"); assert.equal(aws.flow.boundary, "account");
  assert.deepEqual(aws.ui.settings.map((s) => s.id), ["access", "permissions", "probes", "benchmarks", "members"]);
  assert.ok(aws.storage.includes("inventory_ec2") && aws.storage.includes("instance_packages") && aws.storage.includes("alas_advisories"));
  assert.equal(aws.capabilities.probes, true); assert.equal(typeof aws.configured(), "boolean", "configured() reads the machine's connection file, not the data dir");
  assert.equal(reg.adapterFor("gcp"), null);
  const vercel = reg.adapterFor("vercel")!; assert.equal(vercel.flow.boundary, "team"); assert.equal(vercel.capabilities.probes, false); assert.equal(vercel.configured(), false, "no token in this test's environment");
  const list = reg.providers();
  assert.deepEqual(list.map((p) => [p.id, p.available]), [["aws", true], ["vercel", true], ["gcp", false], ["azure", false], ["cloudflare", false]]);
  assert.equal(list.find((p) => p.id === "cloudflare")!.boundary, "account");
  assert.equal(typeof list[0].configured, "boolean");
});

test("the AWS adapter emits generic resource nodes from its storage, and the mirror re-exports the moved mapping unchanged", async () => {
  db.prepare("insert into inventory_ec2(instance_id, name, instance_type, state, region, account_id, snapshot, first_seen, last_seen) values ('i-0abc', 'web', 'm6i.large', 'running', 'us-east-1', '123456789012', ?, '2026-01-01', '2026-10-01')").run(JSON.stringify({ tags: { Name: "web" }, network: { private_ips: ["10.0.0.1"] } }));
  const aws = reg.adapterFor("aws")!;
  const nodes = aws.resources("123456789012");
  const web = nodes.find((n) => n.id === "i-0abc")!;
  assert.equal(web.label, "AdvisorCompute"); assert.equal(web.native_type, "ec2_instance"); assert.equal(web.state, "running"); assert.equal(web.name, "web");
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

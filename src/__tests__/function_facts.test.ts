import assert from "node:assert/strict";
import { test } from "node:test";
import { db } from "../db.js";
import "../adapters/github/inventory.js";
import "../logs.js";
import "../elb_inventory.js";
import "../service_inventory.js";
import "../lambda_inventory.js";
import { FunctionFactsError, functionFacts, repoIdFromTagValue, repositoriesFor } from "../function_facts.js";

const now = new Date().toISOString();

function insertFn(over: Partial<Record<string, unknown>> = {}) {
  const row: Record<string, unknown> = {
    account_id: "111111111111", name: "fn1", arn: "arn:aws:lambda:us-east-1:111111111111:function:fn1", region: "us-east-1",
    runtime: "nodejs20.x", memory_mb: 256, arm: 0, timeout_s: 30,
    invocations_30d: 0, duration_ms_30d: 0, errors_30d: 0, days: 0, invocations_month: 0, gb_seconds_month: 0, avg_duration_ms: null, monthly_usd: 0,
    open_recs: 0, findings: 0, first_seen: now, last_seen: now, gone: 0,
    vpc_id: null, subnet_ids: "[]", security_group_ids: "[]", role_arn: "arn:aws:iam::111111111111:role/fn1-role", layers: "[]", code_size_bytes: 1000, package_type: "Zip",
    env_var_names: "[]", log_group: "/aws/lambda/fn1", tags: "{}", polled_triggers: "[]", push_triggers: "[]", facts_missing: "[]",
    ...over,
  };
  db.prepare(`insert into inventory_lambda(${Object.keys(row).join(",")}) values (${Object.keys(row).map((k) => `@${k}`).join(",")})
    on conflict(account_id, name) do update set ${Object.keys(row).filter((k) => k !== "account_id" && k !== "name").map((k) => `${k} = excluded.${k}`).join(", ")}`).run(row);
  return row;
}

test("repositoriesFor / repoIdFromTagValue: URL and owner/repo forms, canonical casing, bare names only with githubOrg + github_repos, GitLab skipped", () => {
  db.prepare("delete from github_repos where org_id = ?").run("t");
  db.prepare("insert into github_repos(org_id, full_name, node_id, first_seen, last_seen) values (?,?,?,?,?)").run("t", "Acme/Billing-Service", "n1", now, now);
  const canon = new Map([["acme/billing-service", "Acme/Billing-Service"]]);
  assert.equal(repoIdFromTagValue("https://github.com/acme/billing-service", canon, ""), "github:Acme/Billing-Service");
  assert.equal(repoIdFromTagValue("https://github.com/acme/billing-service.git", canon, ""), "github:Acme/Billing-Service");
  assert.equal(repoIdFromTagValue("git@github.com:acme/billing-service.git", canon, ""), "github:Acme/Billing-Service");
  assert.equal(repoIdFromTagValue("acme/billing-service", canon, ""), "github:Acme/Billing-Service");
  assert.equal(repoIdFromTagValue("https://gitlab.com/acme/billing-service", canon, ""), null);
  assert.equal(repoIdFromTagValue("billing-service", canon, ""), null); // bare, no org configured
  assert.equal(repoIdFromTagValue("billing-service", canon, "acme"), "github:Acme/Billing-Service"); // bare, org configured, known in github_repos
  assert.equal(repoIdFromTagValue("unknown-repo", canon, "acme"), null); // bare, org configured, not known

  const entries = repositoriesFor({ repository: "acme/billing-service" }, [{ name: "stack1", tags: { repo: "acme/other-service" } }], ["repository", "repo"]);
  assert.equal(entries.length, 2);
  assert.ok(entries.some((e) => e.via === "function_tag" && e.id === "github:Acme/Billing-Service"));
  assert.ok(entries.some((e) => e.via === "stack_tag" && e.stack === "stack1" && /other-service/i.test(e.id)));
});

test("functionFacts: found by name, by ARN, not found, ambiguous across accounts", () => {
  insertFn({ account_id: "111111111111", name: "ambig", arn: "arn:aws:lambda:us-east-1:111111111111:function:ambig" });
  insertFn({ account_id: "222222222222", name: "ambig", arn: "arn:aws:lambda:us-east-1:222222222222:function:ambig" });
  insertFn({ account_id: "111111111111", name: "solo", arn: "arn:aws:lambda:us-east-1:111111111111:function:solo" });

  const byName = functionFacts({ function: "solo" });
  assert.equal(byName.name, "solo");
  const byArn = functionFacts({ function: "arn:aws:lambda:us-east-1:111111111111:function:solo:live" });
  assert.equal(byArn.id, "arn:aws:lambda:us-east-1:111111111111:function:solo");

  assert.throws(() => functionFacts({ function: "does-not-exist" }), FunctionFactsError);
  assert.throws(() => functionFacts({ function: "ambig" }), FunctionFactsError);
  const scoped = functionFacts({ function: "ambig", account_id: "222222222222" });
  assert.equal(scoped.account_id, "222222222222");
});

test("functionFacts: no AWS-shaped keys in the output (no arn, vpc, lambda or role_arn as a field name)", () => {
  insertFn({ account_id: "111111111111", name: "shape-check", arn: "arn:aws:lambda:us-east-1:111111111111:function:shape-check" });
  const out = functionFacts({ function: "shape-check" });
  const seen = new Set<string>();
  const walk = (v: unknown) => { if (Array.isArray(v)) v.forEach(walk); else if (v && typeof v === "object") for (const [k, x] of Object.entries(v)) { seen.add(k); walk(x); } };
  walk(out);
  for (const bad of ["arn", "vpc", "lambda", "role_arn"]) assert.ok(!seen.has(bad), `output should not have a "${bad}" key`);
});

test("functionFacts: an image package has total_size_bytes null; region_collision surfaces in missing", () => {
  insertFn({ account_id: "111111111111", name: "img-fn", arn: "arn:aws:lambda:us-east-1:111111111111:function:img-fn", package_type: "Image", code_size_bytes: 50_000_000 });
  const img = functionFacts({ function: "img-fn" });
  assert.equal((img.package as any).kind, "image");
  assert.equal((img.package as any).total_size_bytes, null);

  insertFn({ account_id: "111111111111", name: "collided", arn: "arn:aws:lambda:us-east-1:111111111111:function:collided", facts_missing: JSON.stringify([{ fact: "region_collision", reason: "also in us-west-2", since: now }]) });
  const coll = functionFacts({ function: "collided" });
  assert.ok((coll.missing as any[]).some((m) => m.fact === "region_collision" && /us-west-2/.test(m.reason)));
});

test("functionFacts: a log group in another region reports stored_bytes null and a missing entry; trigger_coverage is always present", () => {
  db.prepare("delete from log_groups where account_id = ? and name = ?").run("111111111111", "/aws/lambda/other-region-fn");
  db.prepare("insert into log_groups(account_id, name, region, retention_days, stored_bytes, last_seen) values (?,?,?,?,?,?)").run("111111111111", "/aws/lambda/other-region-fn", "eu-west-1", 30, 1000, now);
  insertFn({ account_id: "111111111111", name: "other-region-fn", arn: "arn:aws:lambda:us-east-1:111111111111:function:other-region-fn", region: "us-east-1", log_group: "/aws/lambda/other-region-fn" });
  const out = functionFacts({ function: "other-region-fn" });
  assert.equal((out.log_group as any).stored_bytes, null);
  assert.ok((out.missing as any[]).some((m) => m.fact === "log_group_stored_bytes"));
  assert.deepEqual((out.trigger_coverage as any).checked.length > 0, true);
  assert.ok((out.trigger_coverage as any).not_checked.includes("direct_invoke"));
});

test("functionFacts: SNS and load balancer triggers merge with a matching push permission into also_via", () => {
  const fnArn = "arn:aws:lambda:us-east-1:111111111111:function:dedupe-fn";
  insertFn({ account_id: "111111111111", name: "dedupe-fn", arn: fnArn, push_triggers: JSON.stringify([{ kind: "event", via: "invoke_permission", native_kind: "sns", source: "arn:aws:sns:us-east-1:111111111111:topic1" }, { kind: "http", via: "load_balancer", native_kind: "elasticloadbalancing", source: null }]) });
  db.prepare("delete from inventory_service where native_type = 'sns_topic' and id = ?").run("arn:aws:sns:us-east-1:111111111111:topic1");
  db.prepare(`insert into inventory_service(native_type, id, account_id, region, name, links, first_seen, last_seen) values ('sns_topic', ?, ?, 'us-east-1', 'topic1', ?, ?, ?)`)
    .run("arn:aws:sns:us-east-1:111111111111:topic1", "111111111111", JSON.stringify([{ rel: "DELIVERS_TO", other: fnArn, dir: "out" }]), now, now);
  db.prepare("delete from inventory_elb where arn = ?").run("arn:aws:elasticloadbalancing:us-east-1:111111111111:loadbalancer/app/web/1");
  db.prepare(`insert into inventory_elb(arn, name, kind, region, account_id, target_groups, first_seen, last_seen) values (?, 'web', 'alb', 'us-east-1', '111111111111', ?, ?, ?)`)
    .run("arn:aws:elasticloadbalancing:us-east-1:111111111111:loadbalancer/app/web/1", JSON.stringify([{ arn: "tg1", name: "web-tg", targets: [{ id: fnArn }] }]), now, now);

  const out = functionFacts({ function: "dedupe-fn" });
  const triggers = out.triggers as any[];
  const sns = triggers.find((t) => t.via === "subscription");
  assert.ok(sns, "expected a subscription trigger");
  assert.deepEqual(sns.also_via, ["invoke_permission"]);
  const lb = triggers.find((t) => t.via === "load_balancer");
  assert.ok(lb, "expected a load_balancer trigger");
  assert.deepEqual(lb.also_via, ["invoke_permission"]);
});

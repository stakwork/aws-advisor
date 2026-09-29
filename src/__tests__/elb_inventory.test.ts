import assert from "node:assert/strict";
import { test } from "node:test";
import { db } from "../db.js";
import { elbMonthlyUsd, elbSummary, elbsForInstance, elbsForLambda, listElb, metricDimension, resolveTargets } from "../elb_inventory.js";
import { elbEdges, resourceFromElb } from "../graph_mirror.js";

test("elb inventory: targets resolve to instances by id or private IP, to functions by ARN, and keep their health", () => {
  const byIp = new Map([["10.0.1.5", { id: "i-aaa", name: "api-1" }]]);
  const byId = new Map([["i-bbb", "api-2"], ["i-aaa", "api-1"]]);
  const out = resolveTargets("ip", [
    { Target: { Id: "10.0.1.5", Port: 8080 }, TargetHealth: { State: "healthy" } },
    { Target: { Id: "10.0.9.9", Port: 8080 }, TargetHealth: { State: "unhealthy", Reason: "Target.Timeout" } },
  ], byIp, byId);
  assert.deepEqual(out.map((t) => [t.id, t.instance_id ?? null, t.name ?? null, t.health]), [["10.0.1.5", "i-aaa", "api-1", "healthy"], ["10.0.9.9", null, null, "unhealthy"]]);
  assert.equal(out[1].reason, "Target.Timeout");
  const inst = resolveTargets("instance", [{ Target: { Id: "i-bbb", Port: 80 }, TargetHealth: { State: "healthy" } }], byIp, byId);
  assert.equal(inst[0].instance_id, "i-bbb"); assert.equal(inst[0].name, "api-2");
  const fn = resolveTargets("lambda", [{ Target: { Id: "arn:aws:lambda:us-east-1:1:function:hello" }, TargetHealth: { State: "healthy" } }], byIp, byId);
  assert.equal(fn[0].lambda, "hello"); assert.equal(fn[0].name, "hello");
  assert.equal(resolveTargets("instance", [{ Target: {} }], byIp, byId).length, 0);
});

test("elb inventory: the CloudWatch dimension is the ARN tail and the fixed price is hourly x 730", () => {
  assert.equal(metricDimension("arn:aws:elasticloadbalancing:us-east-1:1:loadbalancer/app/web/abc123"), "app/web/abc123");
  assert.equal(elbMonthlyUsd("alb"), 16.43);
  assert.equal(elbMonthlyUsd("clb"), 18.25);
  assert.equal(elbMonthlyUsd("gwlb"), 9.13);
});

test("elb inventory: rows list with their targets parsed, an instance finds the balancers in front of it, the summary counts", () => {
  db.prepare("delete from inventory_elb").run();
  const now = "2026-09-29 10:00:00";
  const ins = db.prepare(`insert into inventory_elb(arn, name, kind, scheme, dns_name, state, region, listeners, target_groups, targets, healthy, unhealthy, requests_30d, gb_30d, beanstalk_env, asgs, ecs_services, monthly_usd, first_seen, last_seen, gone)
    values (@arn, @name, @kind, @scheme, @dns, 'active', 'us-east-1', '[]', @tg, @targets, @healthy, @unhealthy, @req, @gb, @eb, '[]', '[]', 16.43, @now, @now, @gone)`);
  const tg = JSON.stringify([{ arn: "tg1", name: "web-tg", target_type: "instance", protocol: "HTTP", port: 80, targets: [{ id: "i-aaa", port: 80, health: "healthy", instance_id: "i-aaa", name: "web-1" }, { id: "i-bbb", port: 80, health: "unhealthy", instance_id: "i-bbb", name: "web-2" }] }]);
  ins.run({ arn: "arn:lb/app/web/1", name: "web", kind: "alb", scheme: "internet-facing", dns: "web-1.elb.amazonaws.com", tg, targets: 2, healthy: 1, unhealthy: 1, req: 120000, gb: 3.5, eb: "prod-env", now, gone: 0 });
  ins.run({ arn: "arn:lb/net/tcp/2", name: "tcp", kind: "nlb", scheme: "internal", dns: "tcp.elb.amazonaws.com", tg: JSON.stringify([{ arn: "tg2", name: "fn-tg", target_type: "lambda", targets: [{ id: "arn:aws:lambda:us-east-1:1:function:hello", port: null, health: "healthy", lambda: "hello", name: "hello" }] }]), targets: 1, healthy: 1, unhealthy: 0, req: null, gb: 0.1, eb: null, now, gone: 0 });
  ins.run({ arn: "arn:lb/app/old/3", name: "old", kind: "alb", scheme: "internal", dns: null, tg: "[]", targets: 0, healthy: 0, unhealthy: 0, req: null, gb: null, eb: null, now: "2026-09-01 00:00:00", gone: 1 });

  const rows = listElb();
  assert.deepEqual(rows.map((r) => r.name), ["web", "tcp"]);
  assert.equal(rows[0].target_groups[0].targets[1].name, "web-2");
  assert.equal(listElb({ kind: "nlb" }).length, 1);
  assert.equal(listElb({ q: "web-2" }).length, 1, "the search reaches into the targets");
  assert.equal(listElb({ gone: true }).length, 3);
  assert.equal(listElb({ sort: "-gb_30d" })[0].name, "web");

  const front = elbsForInstance("i-bbb");
  assert.equal(front.length, 1); assert.equal(front[0].name, "web"); assert.equal(front[0].health, "unhealthy"); assert.equal(front[0].target_group, "web-tg");
  assert.equal(elbsForInstance("i-zzz").length, 0);
  assert.deepEqual(elbsForLambda("hello").map((r) => [r.name, r.target_groups]), [["tcp", ["fn-tg"]]]);

  const s = elbSummary();
  assert.equal(s.total, 2); assert.equal(s.alb, 1); assert.equal(s.nlb, 1); assert.equal(s.gone, 1);
  assert.equal(s.internet_facing, 1); assert.equal(s.targets, 3); assert.equal(s.healthy, 2); assert.equal(s.unhealthy, 1); assert.equal(s.beanstalk, 1);
  assert.equal(s.requests_30d, 120000);

  // the graph side: the ARN is the node id, the edges follow the targets
  const node = resourceFromElb(db.prepare("select * from inventory_elb where name = 'web'").get());
  assert.equal(node.id, "arn:lb/app/web/1"); assert.equal(node.kind, "elb"); assert.equal(node.type, "alb"); assert.equal(node.name, "web");
  const edges = elbEdges(db.prepare("select * from inventory_elb where name = 'web'").get());
  assert.deepEqual(edges.ec2_edges.map((e) => [e.target, e.health]), [["i-aaa", "healthy"], ["i-bbb", "unhealthy"]]);
  assert.equal(edges.beanstalk_env, "prod-env");
  const fnEdges = elbEdges(db.prepare("select * from inventory_elb where name = 'tcp'").get());
  assert.equal(fnEdges.ec2_edges.length, 0); assert.equal(fnEdges.ref_edges[0].target, "arn:aws:lambda:us-east-1:1:function:hello");
  db.prepare("delete from inventory_elb").run();
});

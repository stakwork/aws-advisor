import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "advisor-clusters-test-"));
process.env.TYPESAFE_API_KEY = "";

const ci = await import("../cluster_inventory.js");
const k8s = await import("../k8s_client.js");

const ARN = "arn:aws:eks:us-east-1:123456789012:cluster/test";
const deploy = { kind: "Deployment", metadata: { name: "api", namespace: "prod", uid: "u1", labels: { app: "api", tier: "web" }, creationTimestamp: "2026-01-01T00:00:00Z", annotations: { "deployment.kubernetes.io/revision": "7" } },
  spec: { replicas: 3, selector: { matchLabels: { app: "api" } }, strategy: { type: "RollingUpdate" }, template: { spec: { serviceAccountName: "api-sa", containers: [{ name: "api", image: "ghcr.io/example/api:1.4.2", ports: [{ containerPort: 3000, protocol: "TCP" }] }, { name: "sidecar", image: "nginx:1.25" }] } } },
  status: { readyReplicas: 2 } };
const pods = [
  { metadata: { namespace: "prod", name: "api-6d9f-abc", labels: { app: "api" }, ownerReferences: [{ kind: "ReplicaSet", name: "api-6d9f" }] }, spec: { nodeName: "i-0aaa" }, status: { phase: "Running" } },
  { metadata: { namespace: "prod", name: "api-6d9f-def", labels: { app: "api" }, ownerReferences: [{ kind: "ReplicaSet", name: "api-6d9f" }] }, spec: { nodeName: "i-0bbb" }, status: { phase: "Running" } },
  { metadata: { namespace: "prod", name: "other-xyz", labels: { app: "other" }, ownerReferences: [{ kind: "ReplicaSet", name: "other-1" }] }, spec: { nodeName: "i-0aaa" }, status: { phase: "Running" } },
  { metadata: { namespace: "staging", name: "api-6d9f-ghi", labels: { app: "api" }, ownerReferences: [{ kind: "ReplicaSet", name: "api-6d9f" }] }, spec: { nodeName: "i-0ccc" }, status: { phase: "Running" } },
];

test("workloadFromK8s: a Deployment with its containers, images, replicas, nodes from its pods (own namespace, through the ReplicaSet) and revision", () => {
  const w = ci.workloadFromK8s(ARN, deploy, pods);
  assert.equal(w.id, `${ARN}/prod/Deployment/api`); assert.equal(w.kind, "deployment"); assert.equal(w.namespace, "prod");
  assert.deepEqual([w.replicas_desired, w.replicas_ready], [3, 2]);
  assert.deepEqual(w.images, ["ghcr.io/example/api:1.4.2", "nginx:1.25"]);
  assert.deepEqual(w.containers[0].ports, [{ port: 3000, protocol: "tcp", name: null }]);
  assert.deepEqual(w.nodes.sort(), ["i-0aaa", "i-0bbb"], "the staging pod and the other app's pod are not its own");
  assert.equal(w.pods_running, 2); assert.equal(w.revision, "7"); assert.equal(w.service_account, "api-sa"); assert.equal(w.strategy, "RollingUpdate");
  assert.deepEqual(w.selector, { app: "api" });
  const ds = ci.workloadFromK8s(ARN, { kind: "DaemonSet", metadata: { name: "node-exporter", namespace: "monitoring" }, spec: { selector: { matchLabels: { app: "ne" } }, template: { spec: { containers: [{ name: "ne", image: "prom/node-exporter:v1.8.0" }] } } }, status: { desiredNumberScheduled: 5, numberReady: 5 } });
  assert.equal(ds.kind, "daemonset"); assert.deepEqual([ds.replicas_desired, ds.replicas_ready], [5, 5]);
  const cj = ci.workloadFromK8s(ARN, { kind: "CronJob", metadata: { name: "backup", namespace: "prod" }, spec: { schedule: "0 3 * * *", jobTemplate: { spec: { template: { spec: { containers: [{ name: "b", image: "backup:2" }] } } } } }, status: { active: [] } });
  assert.equal(cj.kind, "cronjob"); assert.equal(cj.schedule, "0 3 * * *"); assert.deepEqual(cj.images, ["backup:2"]);
});

test("services, ingresses and network policies map to rows; selects() is matchLabels equality", () => {
  const svc = ci.serviceFromK8s(ARN, { metadata: { name: "api", namespace: "prod" }, spec: { type: "LoadBalancer", clusterIP: "10.100.0.5", selector: { app: "api" }, ports: [{ port: 443, targetPort: 3000, protocol: "TCP", name: "https" }] }, status: { loadBalancer: { ingress: [{ hostname: "a1b2-123.us-east-1.elb.amazonaws.com" }] } } });
  assert.equal(svc.type, "LoadBalancer"); assert.deepEqual(svc.ports, [{ port: 443, target_port: 3000, node_port: null, protocol: "tcp", name: "https" }]); assert.deepEqual(svc.lb_hostnames, ["a1b2-123.us-east-1.elb.amazonaws.com"]);
  const headless = ci.serviceFromK8s(ARN, { metadata: { name: "db", namespace: "prod" }, spec: { clusterIP: "None", selector: { app: "db" }, ports: [{ port: 5432 }] } });
  assert.equal(headless.cluster_ip, null); assert.equal(headless.type, "ClusterIP");
  const ing = ci.ingressFromK8s(ARN, { metadata: { name: "web", namespace: "prod", annotations: { "kubernetes.io/ingress.class": "alb" } }, spec: { tls: [{ hosts: ["app.example.com"] }], rules: [{ host: "app.example.com", http: { paths: [{ path: "/api", backend: { service: { name: "api", port: { number: 443 } } } }, { path: "/", backend: { service: { name: "web", port: { name: "http" } } } }] } }] }, status: { loadBalancer: { ingress: [{ hostname: "k8s-prod-web-abc.us-east-1.elb.amazonaws.com" }] } } });
  assert.equal(ing.class, "alb"); assert.equal(ing.tls, true); assert.deepEqual(ing.hosts, ["app.example.com"]);
  assert.deepEqual(ing.rules, [{ host: "app.example.com", path: "/api", service: "api", port: 443 }, { host: "app.example.com", path: "/", service: "web", port: "http" }]);
  const pol = ci.policyFromK8s(ARN, { metadata: { name: "api-ingress", namespace: "prod" }, spec: { podSelector: { matchLabels: { app: "api" } }, policyTypes: ["Ingress"], ingress: [{ from: [{ podSelector: { matchLabels: { app: "web" } } }], ports: [{ port: 3000, protocol: "TCP" }] }] } });
  assert.deepEqual(pol.pod_selector, { app: "api" }); assert.deepEqual(pol.policy_types, ["Ingress"]); assert.equal(pol.ingress.length, 1);
  assert.equal(ci.selects({ app: "api" }, { app: "api", tier: "web" }), true);
  assert.equal(ci.selects({ app: "api", tier: "db" }, { app: "api", tier: "web" }), false);
  assert.equal(ci.selects({}, { app: "api" }), false, "an empty selector selects nothing here (a NetworkPolicy with an empty podSelector is handled by the caller)");
});

test("workloadFromEcs: a service with its task definition's containers and the instances behind its running tasks", () => {
  const svc = { service_name: "api", arn: "arn:aws:ecs:us-east-1:1:service/prod/api", cluster_arn: "arn:aws:ecs:us-east-1:1:cluster/prod", task_definition: "arn:aws:ecs:us-east-1:1:task-definition/api:12", desired_count: 2, running_count: 2, launch_type: "EC2", created_at: "2026-01-01T00:00:00Z" };
  const td = { task_definition_arn: svc.task_definition, family: "api", revision: 12, container_definitions: [{ name: "api", image: "123.dkr.ecr.us-east-1.amazonaws.com/api:1.0", portMappings: [{ containerPort: 8080, protocol: "tcp" }] }] };
  const tasks = [{ cluster_arn: svc.cluster_arn, service_name: "api", group: "service:api", container_instance_arn: "ci-1" }, { cluster_arn: svc.cluster_arn, service_name: "api", group: "service:api", container_instance_arn: "ci-2" }, { cluster_arn: svc.cluster_arn, service_name: "other", group: "service:other", container_instance_arn: "ci-3" }];
  const w = ci.workloadFromEcs(svc, td, tasks, new Map([["ci-1", "i-0aaa"], ["ci-2", "i-0bbb"], ["ci-3", "i-0ccc"]]));
  assert.equal(w.kind, "ecs_service"); assert.equal(w.namespace, "prod"); assert.deepEqual(w.images, ["123.dkr.ecr.us-east-1.amazonaws.com/api:1.0"]);
  assert.deepEqual(w.containers[0].ports, [{ port: 8080, protocol: "tcp", name: null }]);
  assert.deepEqual(w.nodes.sort(), ["i-0aaa", "i-0bbb"]); assert.equal(w.revision, "api:12"); assert.equal(w.strategy, "EC2");
  assert.deepEqual([w.replicas_desired, w.replicas_ready], [2, 2]);
});

test("the EKS bearer token is a presigned sts:GetCallerIdentity URL carrying the cluster name, base64url behind the k8s-aws-v1 prefix", async () => {
  const creds = { provider: async () => ({ accessKeyId: "AKIAEXAMPLE", secretAccessKey: "secret" }), region: "us-east-1" } as any;
  const token = await k8s.eksToken({ name: "test", region: "us-east-1" }, creds);
  assert.ok(token.startsWith("k8s-aws-v1."));
  const url = Buffer.from(token.slice("k8s-aws-v1.".length).replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
  const u = new URL(url);
  assert.equal(u.hostname, "sts.us-east-1.amazonaws.com");
  assert.equal(u.searchParams.get("Action"), "GetCallerIdentity");
  assert.equal(u.searchParams.get("X-Amz-Expires"), "60");
  assert.match(u.searchParams.get("X-Amz-SignedHeaders") || "", /host/);
  assert.match(u.searchParams.get("X-Amz-SignedHeaders") || "", /x-k8s-aws-id/);
  assert.ok(u.searchParams.get("X-Amz-Signature"));
  assert.ok(!token.includes("="), "no padding in the token");
});

test("accessInstructions: access entries when the cluster supports them, aws-auth with a view binding otherwise", () => {
  const api = k8s.accessInstructions({ name: "c", region: "us-east-1", authentication_mode: "API_AND_CONFIG_MAP" }, "arn:aws:iam::123456789012:user/aws-advisor");
  assert.equal(api.steps.length, 2); assert.match(api.steps[0].command, /create-access-entry/); assert.match(api.steps[1].command, /AmazonEKSViewPolicy/);
  const cm = k8s.accessInstructions({ name: "c", region: "us-east-1", authentication_mode: "CONFIG_MAP" }, "arn:aws:iam::123456789012:role/aws-advisor-read");
  assert.match(cm.steps[0].command, /authenticationMode=API_AND_CONFIG_MAP/);
  assert.match(cm.steps[1].command, /mapRoles/); assert.match(cm.steps[1].command, /clusterrole=view/);
  assert.ok(!cm.steps.some((s) => /delete|edit-cluster-config --delete/.test(s.command)), "nothing destructive");
});

test("clusterSummary and listClusters follow the account scope: a parent looking at itself does not count a member's clusters", async () => {
  const { db } = await import("../db.js");
  const now = "2026-10-04T00:00:00Z";
  const ins = db.prepare("insert or replace into inventory_cluster(arn, kind, name, region, account_id, status, nodes, workloads, access_status, first_seen, last_seen, gone) values (?, ?, ?, 'us-east-1', ?, 'ACTIVE', ?, ?, 'ok', ?, ?, 0)");
  ins.run("arn:aws:eks:us-east-1:111111111111:cluster/child-eks", "eks", "child-eks", "111111111111", 3, 4, now, now);
  ins.run("arn:aws:ecs:us-east-1:111111111111:cluster/child-ecs", "ecs", "child-ecs", "111111111111", 2, 1, now, now);
  ins.run("arn:aws:ecs:us-east-1:222222222222:cluster/parent-ecs", "ecs", "parent-ecs", "222222222222", 1, 0, now, now);
  assert.equal(ci.clusterSummary(null).total, 3, "no scope: the fleet");
  const child = ci.clusterSummary({ id: "111111111111", primary: false });
  assert.deepEqual([child.total, child.eks, child.ecs, child.nodes, child.workloads], [2, 1, 1, 5, 5]);
  const parent = ci.clusterSummary({ id: "222222222222", primary: true });
  assert.deepEqual([parent.total, parent.eks, parent.ecs, parent.nodes, parent.workloads], [1, 0, 1, 1, 0]);
  assert.deepEqual(ci.listClusters({ id: "222222222222", primary: true }).map((c) => c.name), ["parent-ecs"]);
});

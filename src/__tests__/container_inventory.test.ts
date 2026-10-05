import assert from "node:assert/strict";
import { test } from "node:test";
import { db } from "../db.js";
import { containersOn, recordContainers, whereImage } from "../container_inventory.js";
import { containerGraphRow } from "../graph_containers.js";
import { appEvents } from "../instance_apps.js";
import { defaultProbeScript } from "../probes.js";
import { parseContainerDetail, parseProbeOutput, type ProbeContainerDetail } from "../ssm.js";

const ID = "i-c0a7a1ae70000001";
const detail = (name: string, over: Partial<ProbeContainerDetail> = {}, labels: Partial<ProbeContainerDetail["labels"]> = {}): ProbeContainerDetail => ({
  id: "a".repeat(64), name, created: "2026-10-01T10:00:00.000Z", image: "registry.example.com/web:1.2", image_id: "sha256:" + "1".repeat(64), state: "running", health: "healthy", exit_code: 0, oom_killed: false,
  started_at: "2026-10-01T10:00:01.000Z", finished_at: null, restarts: 0, restart_policy: "unless-stopped", privileged: false, network_mode: "app_default", user: "app", entrypoint: "/sbin/tini",
  networks: ["app_default"], ports: [{ container_port: 80, proto: "tcp", host_ip: "0.0.0.0", host_port: 8080 }], mounts: [{ type: "volume", name: "web-data", source: "/var/lib/docker/volumes/web-data/_data", destination: "/data", rw: true }],
  labels: { source: "https://github.com/example/web", revision: "abc123", version: "1.2", built: "2026-09-30T00:00:00Z", title: "web", compose_project: "app", compose_service: "web", compose_dir: "/srv/app", compose_files: ["/srv/app/docker-compose.yml"], ...labels },
  ...over,
});
const reset = () => { db.prepare("delete from instance_containers where instance_id = ?").run(ID); db.prepare("delete from instance_app_events where instance_id = ?").run(ID); };
const events = () => appEvents({ instance_id: ID }).filter((e) => e.user === "container").map((e) => `${e.name} ${e.event}`).sort();

test("docker 2.1 output: inspect lines parse tolerantly, docker's zero time is none, a dual-stack binding is one port, label-schema labels fill in", () => {
  const out = parseProbeOutput(JSON.stringify({ probe: "aws-advisor/docker/3", kind: "docker", hostname: "h", collected_at: "2026-10-05T10:00:00Z", docker: { available: true, running: 1, total: 2 }, containers: [],
    container_details: [
      { id: "b".repeat(64), name: "/web", created: "2026-10-01T10:00:00.123456789Z", image: "registry.example.com/web:1.2", image_id: "sha256:" + "2".repeat(64), state: "running", health: "", exit_code: 0, oom_killed: false,
        started_at: "2026-10-01T10:00:01Z", finished_at: "0001-01-01T00:00:00Z", restarts: 2, restart_policy: "always", privileged: false, network_mode: "bridge", user: "", entrypoint: "node",
        networks: "bridge,app_default,", ports: { "80/tcp": [{ HostIp: "0.0.0.0", HostPort: "8080" }, { HostIp: "::", HostPort: "8080" }], "9000/tcp": null, "bad": [] },
        mounts: [{ type: "bind", name: null, source: "/srv/app/config", destination: "/config", rw: false }], labels: { source: "", vcs_url: "https://github.com/example/web", vcs_ref: "def456", compose_files: "a.yml,b.yml" } },
      { name: "" },
    ] }));
  assert.equal(out.container_details!.length, 1, "a line without a name is dropped");
  const c = out.container_details![0];
  assert.equal(c.name, "web"); assert.equal(c.health, null); assert.equal(c.user, null); assert.equal(c.finished_at, null); assert.equal(c.created, "2026-10-01T10:00:00.123Z");
  assert.deepEqual(c.networks, ["bridge", "app_default"]);
  assert.deepEqual(c.ports, [{ container_port: 80, proto: "tcp", host_ip: "0.0.0.0", host_port: 8080 }, { container_port: 9000, proto: "tcp", host_ip: null, host_port: null }]);
  assert.deepEqual(c.mounts, [{ type: "bind", name: null, source: "/srv/app/config", destination: "/config", rw: false }]);
  assert.equal(c.labels.source, "https://github.com/example/web"); assert.equal(c.labels.revision, "def456"); assert.deepEqual(c.labels.compose_files, ["a.yml", "b.yml"]);
  assert.equal(parseContainerDetail({ name: "x" }).restarts, 0, "a near-empty line still parses");
});

test("the docker script reads containers through docker inspect and never the environment, the arguments or arbitrary labels", () => {
  const s = defaultProbeScript("docker");
  assert.match(s, /docker inspect --format '\{"id":\{\{json \.Id\}\}/);
  assert.match(s, /"container_details":\[%s\]/);
  assert.doesNotMatch(s, /\.Config\.Env|\.Args\b|\.Config\.Cmd|json \.Config\.Labels/);
  // SSM reads {{ word }} as a document parameter: the template must never hold a bare {{end}} or {{else}}
  assert.doesNotMatch(s, /\{\{\s*(end|else)\s*\}\}/);
});

test("recording containers: the first inventory is silent, then redeploys, recreates, restarts, stops, starts, departures and returns are events", () => {
  reset();
  assert.equal(recordContainers(ID, "2026-10-05T10:00:00Z", { docker: { available: false, running: 0, total: 0 }, containers: [] }), null, "an unreachable daemon says nothing");
  assert.equal(recordContainers(ID, "2026-10-05T10:00:00Z", {}), null);
  const r1 = recordContainers(ID, "2026-10-05T10:00:00Z", { docker: { available: true, running: 3, total: 3 }, containers: [{ name: "web", image: "registry.example.com/web:1.2", state: "running", running_for: "", cpu_pct: 3.5, mem_bytes: 200e6, mem_pct: 5 }],
    container_details: [detail("web"), detail("worker", { id: "c".repeat(64) }), detail("db", { id: "d".repeat(64), image: "postgres:16" })] })!;
  assert.equal(r1.containers, 3); assert.deepEqual(r1.events, [], "the first inventory is not news");
  const web = containersOn(ID).find((c) => c.name === "web")!;
  assert.equal(web.cpu_pct, 3.5); assert.equal(web.source_url, "https://github.com/example/web"); assert.equal(web.compose_service, "web"); assert.deepEqual(web.ports[0], { container_port: 80, proto: "tcp", host_ip: "0.0.0.0", host_port: 8080 });

  // web: same tag, new image id (a redeploy); worker: new container, same image (a recreate); db: restarted twice, then stopped next probe
  recordContainers(ID, "2026-10-05T11:00:00Z", { docker: { available: true, running: 3, total: 3 }, containers: [],
    container_details: [detail("web", { id: "e".repeat(64), image_id: "sha256:" + "3".repeat(64) }, { revision: "fff999" }), detail("worker", { id: "f".repeat(64) }), detail("db", { id: "d".repeat(64), image: "postgres:16", restarts: 2 })] });
  assert.deepEqual(events(), ["db container_restarted", "web container_redeployed", "worker container_recreated"]);
  const redeploy = appEvents({ instance_id: ID }).find((e) => e.event === "container_redeployed")!;
  assert.equal((redeploy.details as any).from_revision, "abc123"); assert.equal((redeploy.details as any).to_revision, "fff999");

  reset();
  recordContainers(ID, "2026-10-05T10:00:00Z", { docker: { available: true, running: 2, total: 2 }, container_details: [detail("web"), detail("db", { id: "d".repeat(64) })] });
  recordContainers(ID, "2026-10-05T11:00:00Z", { docker: { available: true, running: 0, total: 1 }, container_details: [detail("db", { id: "d".repeat(64), state: "exited", exit_code: 137, oom_killed: true })] });
  assert.deepEqual(events(), ["db container_stopped", "web container_gone"]);
  assert.equal(containersOn(ID).length, 1); assert.equal(containersOn(ID, true).length, 2, "the departed container is kept as gone");
  const stopped = appEvents({ instance_id: ID }).find((e) => e.event === "container_stopped")!;
  assert.equal((stopped.details as any).oom_killed, true);
  recordContainers(ID, "2026-10-05T12:00:00Z", { docker: { available: true, running: 2, total: 2 }, container_details: [detail("web"), detail("db", { id: "d".repeat(64) })] });
  assert.deepEqual(events(), ["db container_started", "db container_stopped", "web container_gone", "web container_returned"]);

  // a probe before docker 2.1 updates usage and state and keeps what inspect said
  recordContainers(ID, "2026-10-05T13:00:00Z", { docker: { available: true, running: 2, total: 2 }, containers: [{ name: "web", image: "registry.example.com/web:1.2", state: "running", running_for: "", cpu_pct: 1, mem_bytes: 1, mem_pct: 1 }, { name: "db", image: "registry.example.com/db:1", state: "running", running_for: "", cpu_pct: 1, mem_bytes: 1, mem_pct: 1 }] });
  const after = containersOn(ID).find((c) => c.name === "web")!;
  assert.equal(after.source_url, "https://github.com/example/web"); assert.equal(after.container_id, "a".repeat(64)); assert.equal(after.cpu_pct, 1);
  assert.ok(events().includes("db container_redeployed"), "an image change is seen without inspect too");
  assert.ok(whereImage("github.com/example/web").some((c) => c.instance_id === ID && c.name === "web"), "an image can be found by its source repository");
  reset();
});

test("the graph row of a container: its node id, its image node, and the ports and mounts as strings", () => {
  reset();
  recordContainers(ID, "2026-10-05T10:00:00Z", { docker: { available: true, running: 1, total: 1 }, container_details: [detail("web", { ports: [{ container_port: 80, proto: "tcp", host_ip: "127.0.0.1", host_port: 8080 }, { container_port: 9000, proto: "tcp", host_ip: null, host_port: null }],
    mounts: [{ type: "bind", name: null, source: "/srv/app/config", destination: "/config", rw: false }] })] });
  const row = containerGraphRow(db.prepare("select * from instance_containers where instance_id = ? and name = 'web'").get(ID));
  assert.equal(row.id, `container:${ID}:web`); assert.equal(row.image_node, "image:registry.example.com/web:1.2"); assert.equal(row.repository, "registry.example.com/web"); assert.equal(row.tag, "1.2");
  assert.deepEqual(row.ports, ["127.0.0.1:8080->80/tcp", "9000/tcp"]);
  assert.deepEqual(row.mounts, ["bind /srv/app/config:/config (ro)"]);
  assert.equal(row.revision, "abc123");
  reset();
});

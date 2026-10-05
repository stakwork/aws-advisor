import { db } from "./db.js";
import type { ProbeContainerDetail, ProbeResult } from "./ssm.js";

/**
 * The containers on each instance, from the docker probe (src/probes.ts, kind "docker"): one row per (instance,
 * container name) with what `docker inspect` says it is (image reference and id, state, health, restarts, the program
 * it starts, networks, ports, mounts, the repository and commit the image was built from, the compose project) and
 * its CPU and memory from the same probe. A container is kept by name, so a redeploy is a change of the same row, not
 * a new one; a container that disappears is marked gone. What changed between probes goes to instance_app_events
 * (user "container") next to the program events: appeared, gone, returned, redeployed (a new image or image id),
 * recreated (a new container from the same image), restarted, stopped, started. The graph carries the same as
 * (:AdvisorResource)-[:RUNS]->(:AdvisorContainer)-[:BUILT_FROM]->(:AdvisorImage) (src/graph_containers.ts).
 */

db.exec(`create table if not exists instance_containers (
  instance_id text not null, name text not null, container_id text, image text, image_id text, state text, health text, exit_code integer, oom_killed integer not null default 0,
  created text, started_at text, finished_at text, restarts integer, restart_policy text, privileged integer not null default 0, network_mode text, user text, entrypoint text,
  networks text, ports text, mounts text, source_url text, revision text, image_version text, image_title text, image_built text,
  compose_project text, compose_service text, compose_dir text, compose_files text, cpu_pct real, mem_bytes real,
  first_seen text not null, last_seen text not null, probes integer not null default 1, gone integer not null default 0,
  primary key (instance_id, name)
);
create index if not exists instance_containers_image on instance_containers(image);
create table if not exists instance_app_events (
  id integer primary key autoincrement, instance_id text not null, name text not null, user text not null,
  event text not null, at text not null, details text
)`);

export type ContainerEvent = "container_appeared" | "container_gone" | "container_returned" | "container_redeployed" | "container_recreated" | "container_restarted" | "container_stopped" | "container_started";
export const CONTAINER_EVENT_USER = "container";

export interface StoredContainer {
  instance_id: string; name: string; container_id: string | null; image: string | null; image_id: string | null; state: string | null; health: string | null; exit_code: number | null; oom_killed: boolean;
  created: string | null; started_at: string | null; finished_at: string | null; restarts: number | null; restart_policy: string | null; privileged: boolean; network_mode: string | null; user: string | null; entrypoint: string | null;
  networks: string[]; ports: ProbeContainerDetail["ports"]; mounts: ProbeContainerDetail["mounts"];
  source_url: string | null; revision: string | null; image_version: string | null; image_title: string | null; image_built: string | null;
  compose_project: string | null; compose_service: string | null; compose_dir: string | null; compose_files: string[]; cpu_pct: number | null; mem_bytes: number | null;
  first_seen: string; last_seen: string; probes: number; gone: boolean;
}

export interface RecordContainersResult { containers: number; events: { name: string; event: ContainerEvent }[] }

const upsertFull = db.prepare(`insert into instance_containers(instance_id, name, container_id, image, image_id, state, health, exit_code, oom_killed, created, started_at, finished_at, restarts, restart_policy, privileged, network_mode, user, entrypoint,
  networks, ports, mounts, source_url, revision, image_version, image_title, image_built, compose_project, compose_service, compose_dir, compose_files, cpu_pct, mem_bytes, first_seen, last_seen, probes, gone)
  values (@instance_id, @name, @container_id, @image, @image_id, @state, @health, @exit_code, @oom_killed, @created, @started_at, @finished_at, @restarts, @restart_policy, @privileged, @network_mode, @user, @entrypoint,
  @networks, @ports, @mounts, @source_url, @revision, @image_version, @image_title, @image_built, @compose_project, @compose_service, @compose_dir, @compose_files, @cpu_pct, @mem_bytes, @at, @at, 1, 0)
  on conflict(instance_id, name) do update set container_id = excluded.container_id, image = excluded.image, image_id = excluded.image_id, state = excluded.state, health = excluded.health, exit_code = excluded.exit_code, oom_killed = excluded.oom_killed,
  created = excluded.created, started_at = excluded.started_at, finished_at = excluded.finished_at, restarts = excluded.restarts, restart_policy = excluded.restart_policy, privileged = excluded.privileged, network_mode = excluded.network_mode, user = excluded.user,
  entrypoint = excluded.entrypoint, networks = excluded.networks, ports = excluded.ports, mounts = excluded.mounts, source_url = excluded.source_url, revision = excluded.revision, image_version = excluded.image_version, image_title = excluded.image_title,
  image_built = excluded.image_built, compose_project = excluded.compose_project, compose_service = excluded.compose_service, compose_dir = excluded.compose_dir, compose_files = excluded.compose_files, cpu_pct = excluded.cpu_pct, mem_bytes = excluded.mem_bytes,
  last_seen = excluded.last_seen, probes = probes + 1, gone = 0`);
// a probe before docker 2.1 lists name, image, state and usage only: the inspect facts already known are kept
const upsertBasic = db.prepare(`insert into instance_containers(instance_id, name, image, state, cpu_pct, mem_bytes, first_seen, last_seen, probes, gone) values (@instance_id, @name, @image, @state, @cpu_pct, @mem_bytes, @at, @at, 1, 0)
  on conflict(instance_id, name) do update set image = excluded.image, state = excluded.state, cpu_pct = excluded.cpu_pct, mem_bytes = excluded.mem_bytes, last_seen = excluded.last_seen, probes = probes + 1, gone = 0`);
const insertEvent = db.prepare("insert into instance_app_events(instance_id, name, user, event, at, details) values (?, ?, ?, ?, ?, ?)");

const running = (state: string | null | undefined) => state === "running";

/**
 * Records one docker probe: upserts every container, marks the ones that left as gone, and logs what changed. The first
 * inventory of a box is not news. A probe that could not reach the Docker daemon says nothing about the containers.
 */
export function recordContainers(instanceId: string, collectedAt: string, data: Pick<ProbeResult, "docker" | "containers" | "container_details">): RecordContainersResult | null {
  if (data.docker && !data.docker.available) return null;
  if (!Array.isArray(data.containers) && !Array.isArray(data.container_details)) return null;
  const usage = new Map((data.containers ?? []).map((c) => [c.name, c]));
  const details = data.container_details ?? null;
  const res: RecordContainersResult = { containers: 0, events: [] };
  db.transaction(() => {
    const prev = new Map((db.prepare("select * from instance_containers where instance_id = ?").all(instanceId) as any[]).map((r) => [String(r.name), r]));
    const first = prev.size === 0;
    const event = (name: string, ev: ContainerEvent, d: Record<string, unknown>) => { if (first) return; res.events.push({ name, event: ev }); insertEvent.run(instanceId, name, CONTAINER_EVENT_USER, ev, collectedAt, JSON.stringify(d)); };
    const seen = new Set<string>();
    if (details) for (const c of details) {
      if (seen.has(c.name)) continue; seen.add(c.name);
      const u = usage.get(c.name);
      upsertFull.run({ instance_id: instanceId, name: c.name, container_id: c.id || null, image: c.image || null, image_id: c.image_id, state: c.state || null, health: c.health, exit_code: c.exit_code, oom_killed: c.oom_killed ? 1 : 0,
        created: c.created, started_at: c.started_at, finished_at: c.finished_at, restarts: c.restarts, restart_policy: c.restart_policy, privileged: c.privileged ? 1 : 0, network_mode: c.network_mode, user: c.user, entrypoint: c.entrypoint,
        networks: JSON.stringify(c.networks), ports: JSON.stringify(c.ports), mounts: JSON.stringify(c.mounts), source_url: c.labels.source, revision: c.labels.revision, image_version: c.labels.version, image_title: c.labels.title, image_built: c.labels.built,
        compose_project: c.labels.compose_project, compose_service: c.labels.compose_service, compose_dir: c.labels.compose_dir, compose_files: JSON.stringify(c.labels.compose_files),
        cpu_pct: u?.cpu_pct ?? null, mem_bytes: u ? u.mem_bytes : null, at: collectedAt });
      changes(prev.get(c.name), { name: c.name, container_id: c.id || null, image: c.image || null, image_id: c.image_id, revision: c.labels.revision, state: c.state, restarts: c.restarts, exit_code: c.exit_code, oom_killed: c.oom_killed, finished_at: c.finished_at, health: c.health }, event);
    }
    else for (const c of data.containers ?? []) {
      if (!c.name || seen.has(c.name)) continue; seen.add(c.name);
      upsertBasic.run({ instance_id: instanceId, name: c.name, image: c.image || null, state: c.state || null, cpu_pct: c.cpu_pct, mem_bytes: c.mem_bytes, at: collectedAt });
      changes(prev.get(c.name), { name: c.name, container_id: null, image: c.image || null, image_id: null, revision: null, state: c.state, restarts: null, exit_code: null, oom_killed: false, finished_at: null, health: null }, event);
    }
    for (const [name, r] of prev) if (!seen.has(name) && !r.gone) {
      db.prepare("update instance_containers set gone = 1 where instance_id = ? and name = ?").run(instanceId, name);
      event(name, "container_gone", { image: r.image, last_seen: r.last_seen, first_seen: r.first_seen, probes: r.probes, state: r.state });
    }
    res.containers = seen.size;
  })();
  return res;
}

interface Now { name: string; container_id: string | null; image: string | null; image_id: string | null; revision: string | null; state: string; restarts: number | null; exit_code: number | null; oom_killed: boolean; finished_at: string | null; health: string | null }

/** The events between the stored row and this probe's view of one container; at most one lifecycle event plus a state change. */
function changes(was: any, c: Now, event: (name: string, ev: ContainerEvent, d: Record<string, unknown>) => void): void {
  if (!was) { event(c.name, "container_appeared", { image: c.image, state: c.state, revision: c.revision }); return; }
  if (was.gone) { event(c.name, "container_returned", { image: c.image, state: c.state, gone_since: was.last_seen }); return; }
  const imageChanged = (was.image ?? null) !== c.image || (was.image_id != null && c.image_id != null && was.image_id !== c.image_id);
  const sameContainer = was.container_id == null || c.container_id == null || was.container_id === c.container_id;
  if (imageChanged) event(c.name, "container_redeployed", { from_image: was.image, to_image: c.image, from_image_id: was.image_id, to_image_id: c.image_id, from_revision: was.revision, to_revision: c.revision });
  else if (!sameContainer) event(c.name, "container_recreated", { image: c.image, from_container_id: was.container_id, to_container_id: c.container_id });
  else if (c.restarts != null && was.restarts != null && c.restarts > Number(was.restarts)) event(c.name, "container_restarted", { from: Number(was.restarts), to: c.restarts, exit_code: c.exit_code, oom_killed: c.oom_killed });
  if (!imageChanged && sameContainer) {
    if (running(was.state) && !running(c.state)) event(c.name, "container_stopped", { state: c.state, exit_code: c.exit_code, oom_killed: c.oom_killed, finished_at: c.finished_at });
    else if (!running(was.state) && running(c.state)) event(c.name, "container_started", { from_state: was.state, health: c.health });
  }
}

const list = <T,>(v: unknown, fallback: T): T => { if (typeof v !== "string" || !v) return fallback; try { return JSON.parse(v) as T; } catch { return fallback; } };
export const rowToContainer = (r: any): StoredContainer => ({
  instance_id: r.instance_id, name: r.name, container_id: r.container_id ?? null, image: r.image ?? null, image_id: r.image_id ?? null, state: r.state ?? null, health: r.health ?? null, exit_code: r.exit_code == null ? null : Number(r.exit_code), oom_killed: Boolean(r.oom_killed),
  created: r.created ?? null, started_at: r.started_at ?? null, finished_at: r.finished_at ?? null, restarts: r.restarts == null ? null : Number(r.restarts), restart_policy: r.restart_policy ?? null, privileged: Boolean(r.privileged), network_mode: r.network_mode ?? null, user: r.user ?? null, entrypoint: r.entrypoint ?? null,
  networks: list(r.networks, []), ports: list(r.ports, []), mounts: list(r.mounts, []), source_url: r.source_url ?? null, revision: r.revision ?? null, image_version: r.image_version ?? null, image_title: r.image_title ?? null, image_built: r.image_built ?? null,
  compose_project: r.compose_project ?? null, compose_service: r.compose_service ?? null, compose_dir: r.compose_dir ?? null, compose_files: list(r.compose_files, []), cpu_pct: r.cpu_pct == null ? null : Number(r.cpu_pct), mem_bytes: r.mem_bytes == null ? null : Number(r.mem_bytes),
  first_seen: r.first_seen, last_seen: r.last_seen, probes: Number(r.probes ?? 1), gone: Boolean(r.gone),
});

/** The containers of one instance, running first; with `includeGone`, the ones that left too. */
export function containersOn(instanceId: string, includeGone = false): StoredContainer[] {
  return (db.prepare(`select * from instance_containers where instance_id = ?${includeGone ? "" : " and gone = 0"} order by gone, case state when 'running' then 0 else 1 end, name`).all(instanceId) as any[]).map(rowToContainer);
}

/** Where an image runs across the fleet (case-insensitive substring of the reference or the source repository). */
export function whereImage(q: string, limit = 200): (StoredContainer & { instance_name: string | null })[] {
  const like = `%${q.toLowerCase()}%`;
  return (db.prepare(`select c.*, i.name as instance_name from instance_containers c left join inventory_ec2 i on i.instance_id = c.instance_id
    where c.gone = 0 and (lower(c.image) like ? or lower(c.source_url) like ?) order by c.image, i.name limit ?`).all(like, like, limit) as any[]).map((r) => ({ ...rowToContainer(r), instance_name: r.instance_name ?? null }));
}

import { db } from "./db.js";

/**
 * What is installed on the instances, from the software probe (src/probes.ts, kind "software"): the OS and kernel,
 * every package with its version, the versions of well-known programs read from the binaries, and the images behind
 * the running containers. One row per (instance, package) with first and last seen, so a version change is a
 * history, not an overwrite; a package that disappears is marked gone. This is the inventory a vulnerability is
 * matched against (the graph's AdvisorPackage / AdvisorImage nodes come from these tables).
 */

db.exec(`create table if not exists instance_os (
  instance_id text primary key, collected_at text not null, os_id text, os_version text, os_name text, kernel text, arch text, package_manager text, packages integer not null default 0
);
create table if not exists instance_packages (
  instance_id text not null, ecosystem text not null, name text not null, version text not null, arch text,
  first_seen text not null, last_seen text not null, gone integer not null default 0,
  primary key (instance_id, ecosystem, name)
);
create index if not exists instance_packages_name on instance_packages(name, version);
create table if not exists instance_binaries (
  instance_id text not null, name text not null, version text not null, path text,
  first_seen text not null, last_seen text not null, gone integer not null default 0,
  primary key (instance_id, name)
);
create table if not exists instance_images (
  instance_id text not null, image text not null, image_id text, digest text, created text, platform text,
  first_seen text not null, last_seen text not null, gone integer not null default 0,
  primary key (instance_id, image)
);
create table if not exists package_changes (
  id integer primary key autoincrement, instance_id text not null, ecosystem text not null, name text not null, from_version text, to_version text, at text not null
);
create index if not exists package_changes_instance on package_changes(instance_id, id)`);
// probe software/2 adds the source package (what the distribution advisories name: openssh for openssh-server); older rows have none
if (!(db.prepare("pragma table_info(instance_packages)").all() as { name: string }[]).some((c) => c.name === "source")) db.exec("alter table instance_packages add column source text");
// probe software/3 adds the guest's hibernation setup (JSON, ProbeHibernation); src/guest_hibernation.ts reads it
if (!(db.prepare("pragma table_info(instance_os)").all() as { name: string }[]).some((c) => c.name === "hibernation")) db.exec("alter table instance_os add column hibernation text");

/** One package as the probe prints it: name, version, architecture and the source package when it differs from the name. */
export interface ProbePackage { n: string; v: string; a?: string | null; s?: string | null }
export interface ProbeBinary { name: string; version: string; path?: string | null }
export interface ProbeImage { image: string; id?: string | null; digests?: string | null; created?: string | null; platform?: string | null }
/** What the guest has for hibernation (probe software/3): the kernel, the resume target, what answers the sleep button, the swap. */
export interface ProbeHibernation {
  kernel_disk?: boolean; cmdline_resume?: boolean; sys_resume?: string | null; agent?: string | null; acpi_sleep_handler?: boolean;
  logind_suspend_key?: string | null; swap_active_bytes?: number; swap_file_bytes?: number; mem_bytes?: number;
}
export interface SoftwareData {
  hibernation?: ProbeHibernation | null;
  os?: { id?: string | null; version?: string | null; name?: string | null } | null; kernel?: string | null; arch?: string | null; package_manager?: string | null;
  packages?: ProbePackage[]; binaries?: ProbeBinary[]; images?: ProbeImage[];
}

export interface RecordSoftwareResult { packages: number; added: string[]; removed: string[]; changed: { name: string; from: string; to: string }[]; binaries: number; images: number }

const upsertOs = db.prepare(`insert into instance_os(instance_id, collected_at, os_id, os_version, os_name, kernel, arch, package_manager, packages, hibernation) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  on conflict(instance_id) do update set collected_at = excluded.collected_at, hibernation = coalesce(excluded.hibernation, hibernation), os_id = coalesce(excluded.os_id, os_id), os_version = coalesce(excluded.os_version, os_version), os_name = coalesce(excluded.os_name, os_name), kernel = coalesce(excluded.kernel, kernel), arch = coalesce(excluded.arch, arch), package_manager = coalesce(excluded.package_manager, package_manager), packages = excluded.packages`);
const upsertPkg = db.prepare(`insert into instance_packages(instance_id, ecosystem, name, version, arch, source, first_seen, last_seen, gone) values (?, ?, ?, ?, ?, ?, ?, ?, 0)
  on conflict(instance_id, ecosystem, name) do update set version = excluded.version, arch = excluded.arch, source = coalesce(excluded.source, source), last_seen = excluded.last_seen, gone = 0`);
const upsertBin = db.prepare(`insert into instance_binaries(instance_id, name, version, path, first_seen, last_seen, gone) values (?, ?, ?, ?, ?, ?, 0)
  on conflict(instance_id, name) do update set version = excluded.version, path = excluded.path, last_seen = excluded.last_seen, gone = 0`);
const upsertImg = db.prepare(`insert into instance_images(instance_id, image, image_id, digest, created, platform, first_seen, last_seen, gone) values (?, ?, ?, ?, ?, ?, ?, ?, 0)
  on conflict(instance_id, image) do update set image_id = excluded.image_id, digest = excluded.digest, created = excluded.created, platform = excluded.platform, last_seen = excluded.last_seen, gone = 0`);
const insertChange = db.prepare("insert into package_changes(instance_id, ecosystem, name, from_version, to_version, at) values (?, ?, ?, ?, ?, ?)");

const clean = (s: unknown, n = 200): string => String(s ?? "").replace(/[^\x20-\x7e]/g, "").slice(0, n);

/** Records one software probe: upserts, marks what left as gone, and keeps a change log of version moves. */
export function recordSoftware(instanceId: string, collectedAt: string, data: SoftwareData): RecordSoftwareResult | null {
  if (!Array.isArray(data.packages) && !Array.isArray(data.binaries) && !data.os) return null;
  const eco = clean(data.package_manager || "unknown", 20);
  const pkgs = (data.packages ?? []).filter((p) => p && typeof p.n === "string" && p.n).map((p) => ({ name: clean(p.n, 120), version: clean(p.v, 120), arch: p.a == null ? null : clean(p.a, 20), source: p.s == null || !String(p.s).trim() ? null : clean(p.s, 120) }));
  const res: RecordSoftwareResult = { packages: pkgs.length, added: [], removed: [], changed: [], binaries: 0, images: 0 };
  db.transaction(() => {
    const prev = new Map((db.prepare("select name, version, gone from instance_packages where instance_id = ? and ecosystem = ?").all(instanceId, eco) as { name: string; version: string; gone: number }[]).map((r) => [r.name, r]));
    const first = prev.size === 0;
    const seen = new Set<string>();
    for (const p of pkgs) {
      seen.add(p.name);
      const was = prev.get(p.name);
      upsertPkg.run(instanceId, eco, p.name, p.version, p.arch, p.source, collectedAt, collectedAt);
      if (!was && !first) res.added.push(p.name);
      else if (was && was.version !== p.version) { res.changed.push({ name: p.name, from: was.version, to: p.version }); insertChange.run(instanceId, eco, p.name, was.version, p.version, collectedAt); }
    }
    if (pkgs.length) for (const [name, was] of prev) if (!seen.has(name) && !was.gone) { db.prepare("update instance_packages set gone = 1 where instance_id = ? and ecosystem = ? and name = ?").run(instanceId, eco, name); res.removed.push(name); }
    const bins = (data.binaries ?? []).filter((b) => b && typeof b.name === "string" && b.name && b.version);
    const binSeen = new Set<string>();
    for (const b of bins) { binSeen.add(b.name); upsertBin.run(instanceId, clean(b.name, 64), clean(b.version, 120), b.path == null ? null : clean(b.path, 200), collectedAt, collectedAt); }
    if (Array.isArray(data.binaries)) db.prepare(`update instance_binaries set gone = 1 where instance_id = ? and gone = 0${binSeen.size ? ` and name not in (${[...binSeen].map(() => "?").join(",")})` : ""}`).run(instanceId, ...binSeen);
    res.binaries = bins.length;
    const imgs = (data.images ?? []).filter((i) => i && typeof i.image === "string" && i.image);
    const imgSeen = new Set<string>();
    for (const i of imgs) { imgSeen.add(i.image); upsertImg.run(instanceId, clean(i.image, 300), i.id == null ? null : clean(i.id, 100), i.digests ? clean(String(i.digests).split(",")[0], 300) : null, i.created == null ? null : clean(i.created, 40), i.platform == null ? null : clean(i.platform, 40), collectedAt, collectedAt); }
    if (Array.isArray(data.images)) db.prepare(`update instance_images set gone = 1 where instance_id = ? and gone = 0${imgSeen.size ? ` and image not in (${[...imgSeen].map(() => "?").join(",")})` : ""}`).run(instanceId, ...imgSeen);
    res.images = imgs.length;
    upsertOs.run(instanceId, collectedAt, clean(data.os?.id, 40) || null, clean(data.os?.version, 40) || null, clean(data.os?.name, 120) || null, clean(data.kernel, 80) || null, clean(data.arch, 20) || null, data.package_manager ? eco : null, pkgs.length, data.hibernation && typeof data.hibernation === "object" ? JSON.stringify(data.hibernation).slice(0, 2000) : null);
  })();
  return res;
}

/** The hibernation agent packages (Amazon Linux, Ubuntu): the fallback signal while a box has no probe software/3 reading. */
export const HIBERNATION_AGENT_PACKAGES = ["ec2-hibinit-agent", "hibagent", "ec2-hibernate-linux-agent"];

/** What the software probe saw of one box's hibernation setup: its reading, an installed agent package, whether packages were read at all. */
export function hibernationSetupOf(instanceId: string): { probe: ProbeHibernation | null; agent_package: string | null; packages_known: boolean; collected_at: string | null } {
  const os = db.prepare("select collected_at, packages, hibernation from instance_os where instance_id = ?").get(instanceId) as { collected_at: string; packages: number; hibernation: string | null } | undefined;
  let probe: ProbeHibernation | null = null;
  try { probe = os?.hibernation ? JSON.parse(os.hibernation) : null; } catch { probe = null; }
  const pkg = db.prepare(`select name from instance_packages where instance_id = ? and gone = 0 and name in (${HIBERNATION_AGENT_PACKAGES.map(() => "?").join(",")}) limit 1`).get(instanceId, ...HIBERNATION_AGENT_PACKAGES) as { name: string } | undefined;
  return { probe, agent_package: pkg?.name ?? null, packages_known: Boolean(os && os.packages > 0), collected_at: os?.collected_at ?? null };
}

export interface InstanceSoftware {
  os: { instance_id: string; collected_at: string; os_id: string | null; os_version: string | null; os_name: string | null; kernel: string | null; arch: string | null; package_manager: string | null; packages: number } | null;
  packages: { ecosystem: string; name: string; version: string; arch: string | null; source: string | null; first_seen: string; last_seen: string; gone: boolean }[];
  binaries: { name: string; version: string; path: string | null; first_seen: string; last_seen: string; gone: boolean }[];
  images: { image: string; image_id: string | null; digest: string | null; created: string | null; platform: string | null; first_seen: string; last_seen: string; gone: boolean }[];
  changes: { ecosystem: string; name: string; from_version: string | null; to_version: string | null; at: string }[];
}

/** Everything the software probe knows about one instance; `q` filters packages by name. */
export function softwareOn(instanceId: string, opts: { q?: string; includeGone?: boolean; limit?: number } = {}): InstanceSoftware {
  const gone = opts.includeGone ? "" : " and gone = 0";
  const q = opts.q ? `%${opts.q.toLowerCase()}%` : null;
  const limit = Math.min(5000, Math.max(1, opts.limit ?? 2000));
  return {
    os: (db.prepare("select * from instance_os where instance_id = ?").get(instanceId) as any) ?? null,
    packages: (db.prepare(`select ecosystem, name, version, arch, source, first_seen, last_seen, gone from instance_packages where instance_id = ?${gone}${q ? " and (lower(name) like ? or lower(source) like ?)" : ""} order by name limit ?`).all(...(q ? [instanceId, q, q, limit] : [instanceId, limit])) as any[]).map((r) => ({ ...r, gone: Boolean(r.gone) })),
    binaries: (db.prepare(`select name, version, path, first_seen, last_seen, gone from instance_binaries where instance_id = ?${gone} order by name`).all(instanceId) as any[]).map((r) => ({ ...r, gone: Boolean(r.gone) })),
    images: (db.prepare(`select image, image_id, digest, created, platform, first_seen, last_seen, gone from instance_images where instance_id = ?${gone} order by image`).all(instanceId) as any[]).map((r) => ({ ...r, gone: Boolean(r.gone) })),
    changes: db.prepare("select ecosystem, name, from_version, to_version, at from package_changes where instance_id = ? order by id desc limit 50").all(instanceId) as any[],
  };
}

/** Where a package (or binary) is installed across the fleet, with its version per box: the question a CVE asks. */
export function wherePackage(name: string): { instance_id: string; instance_name: string | null; kind: "package" | "binary"; ecosystem: string | null; name: string; version: string; source?: string | null; last_seen: string }[] {
  const like = `%${name.toLowerCase()}%`;
  const pk = db.prepare(`select p.instance_id, i.name as instance_name, 'package' as kind, p.ecosystem, p.name, p.version, p.source, p.last_seen from instance_packages p left join inventory_ec2 i on i.instance_id = p.instance_id where p.gone = 0 and (lower(p.name) like ? or lower(p.source) like ?) order by p.name, p.version, i.name limit 2000`).all(like, like) as any[];
  const bn = db.prepare(`select b.instance_id, i.name as instance_name, 'binary' as kind, null as ecosystem, b.name, b.version, b.last_seen from instance_binaries b left join inventory_ec2 i on i.instance_id = b.instance_id where b.gone = 0 and lower(b.name) like ? order by b.name, i.name limit 500`).all(like) as any[];
  return [...pk, ...bn];
}

export interface SoftwareSummary { instances: number; packages: number; distinct_packages: number; images: number; os: { os: string; n: number }[]; kernels: { kernel: string; n: number }[]; last_collected_at: string | null; changes_7d: number }

/** The fleet's software at a glance. */
export function softwareSummary(): SoftwareSummary {
  const a = db.prepare("select count(*) as instances, sum(packages) as packages, max(collected_at) as last from instance_os").get() as any;
  const d = db.prepare("select count(distinct name) as n from instance_packages where gone = 0").get() as any;
  const im = db.prepare("select count(*) as n from instance_images where gone = 0").get() as any;
  const os = db.prepare("select coalesce(os_name, os_id, 'unknown') as os, count(*) as n from instance_os group by 1 order by n desc limit 12").all() as any[];
  const kernels = db.prepare("select coalesce(kernel, 'unknown') as kernel, count(*) as n from instance_os group by 1 order by n desc limit 12").all() as any[];
  const ch = db.prepare("select count(*) as n from package_changes where datetime(at) > datetime('now', '-7 days')").get() as any;
  return { instances: Number(a?.instances || 0), packages: Number(a?.packages || 0), distinct_packages: Number(d?.n || 0), images: Number(im?.n || 0), os, kernels, last_collected_at: a?.last ?? null, changes_7d: Number(ch?.n || 0) };
}

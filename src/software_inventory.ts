import { db } from "./db.js";

/**
 * What is installed on the instances, from the software probe (src/probes.ts, kind "software"): the OS and kernel,
 * every package with its version, the versions of well-known programs read from the binaries, and the images behind
 * the running containers. One row per (instance, package) holding what is installed now: a newer version replaces
 * the row and a package, program or image the probe no longer reports is deleted. The history is package_changes:
 * every version move (from → to) and every removal (to null). This is the inventory the vulnerability match (a strut
 * workflow over the graph, docs/vulnerability-graph-plan.md) is run
 * against (the graph's SoftwareComponent / AdvisorImage nodes come from these tables).
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
  instance_id text not null, name text not null, version text not null, path text not null default '',
  first_seen text not null, last_seen text not null, gone integer not null default 0,
  primary key (instance_id, name, path)
);
create table if not exists instance_images (
  instance_id text not null, image text not null, image_id text, digest text, created text, platform text,
  first_seen text not null, last_seen text not null, gone integer not null default 0,
  primary key (instance_id, image)
);
create table if not exists instance_bundles (
  instance_id text not null, parent text not null, parent_version text not null, name text not null, version text not null,
  first_seen text not null, last_seen text not null,
  primary key (instance_id, parent, parent_version, name)
);
create table if not exists instance_depends (
  instance_id text not null, name text not null, dep text not null, first_seen text not null, last_seen text not null,
  primary key (instance_id, name, dep)
);
create table if not exists package_changes (
  id integer primary key autoincrement, instance_id text not null, ecosystem text not null, name text not null, from_version text, to_version text, at text not null
);
create index if not exists package_changes_instance on package_changes(instance_id, id)`);
// probe software/2 adds the source package (what the distribution advisories name: openssh for openssh-server); older rows have none
if (!(db.prepare("pragma table_info(instance_packages)").all() as { name: string }[]).some((c) => c.name === "source")) db.exec("alter table instance_packages add column source text");
// probe software/3 adds the guest's hibernation setup (JSON, ProbeHibernation); src/guest_hibernation.ts reads it
if (!(db.prepare("pragma table_info(instance_os)").all() as { name: string }[]).some((c) => c.name === "hibernation")) db.exec("alter table instance_os add column hibernation text");
// probe software/4 adds what the runtimes bundle (instance_bundles) and the dependencies of the packages owning the probed programs (instance_depends)
// probe software/5 finds programs beyond PATH (nvm, /opt, /usr/local), so a box may hold several installs of one program: binaries are keyed by
// (name, path) and bundles by the parent's version too. Older tables are rebuilt once with the wider key.
for (const [table, want, create] of [
  ["instance_binaries", ["instance_id", "name", "path"], "create table instance_binaries (instance_id text not null, name text not null, version text not null, path text not null default '', first_seen text not null, last_seen text not null, gone integer not null default 0, primary key (instance_id, name, path))"],
  ["instance_bundles", ["instance_id", "parent", "parent_version", "name"], "create table instance_bundles (instance_id text not null, parent text not null, parent_version text not null, name text not null, version text not null, first_seen text not null, last_seen text not null, primary key (instance_id, parent, parent_version, name))"],
] as const) {
  const pk = (db.prepare(`pragma table_info(${table})`).all() as { name: string; pk: number }[]).filter((c) => c.pk > 0).sort((a, b) => a.pk - b.pk).map((c) => c.name);
  if (pk.join(",") === want.join(",")) continue;
  const cols = table === "instance_binaries" ? "instance_id, name, version, coalesce(path, ''), first_seen, last_seen, gone" : "instance_id, parent, parent_version, name, version, first_seen, last_seen";
  const into = table === "instance_binaries" ? "instance_id, name, version, path, first_seen, last_seen, gone" : "instance_id, parent, parent_version, name, version, first_seen, last_seen";
  db.exec(`alter table ${table} rename to ${table}_old; ${create}; insert or ignore into ${table}(${into}) select ${cols} from ${table}_old; drop table ${table}_old`);
}
// rows marked gone before superseded software was deleted (2026-10-13): the column stays, nothing sets it any more
db.exec("delete from instance_packages where gone = 1; delete from instance_binaries where gone = 1; delete from instance_images where gone = 1");
// the advisor's own OSV/ALAS matcher (src/software_vulns.ts, src/alas_feed.ts) was removed on 2026-10-29: the strut workflows match against the graph now; its tables go
for (const t of ["vuln_queries", "vulnerabilities", "package_vulns", "vuln_scans", "alas_advisories", "alas_packages"]) db.exec(`drop table if exists ${t}`);

// ---- the sbom probe (src/probes.ts, kind "sbom"): what syft read inside the running images and on the host filesystem --
// One row per (instance, scan, purl): the scan is a running image (ref as `docker ps` names it, the same string as
// instance_images.image) or the filesystem (ref "/"). A scan that timed out or failed keeps the rows of the last good
// one, with its status on the sources row; a scan the probe no longer reports (the container stopped) loses its rows.
db.exec(`create table if not exists instance_sbom_scans (
  instance_id text primary key, collected_at text not null, available integer not null default 0, tool text, cap integer not null default 0, sources integer not null default 0, packages integer not null default 0
);
create table if not exists instance_sbom_sources (
  instance_id text not null, source text not null, ref text not null, status text not null, total integer not null default 0, listed integer not null default 0, collected_at text not null,
  primary key (instance_id, source, ref)
);
create table if not exists instance_sbom (
  instance_id text not null, source text not null, ref text not null, purl text not null, type text not null, namespace text, name text not null, version text, first_seen text not null, last_seen text not null,
  primary key (instance_id, source, ref, purl)
);
create index if not exists instance_sbom_name on instance_sbom(name, version);
create index if not exists instance_sbom_ref on instance_sbom(source, ref)`);
// sbom 1.1 adds what the probe did about a missing syft (installed it, failed and why, left it alone); 1.4 the image behind each scan (docker id, registry digest)
for (const c of ["image_id", "digest"]) if (!(db.prepare("pragma table_info(instance_sbom_sources)").all() as { name: string }[]).some((x) => x.name === c)) db.exec(`alter table instance_sbom_sources add column ${c} text`);
if (!(db.prepare("pragma table_info(instance_sbom_scans)").all() as { name: string }[]).some((c) => c.name === "note")) db.exec("alter table instance_sbom_scans add column note text");

/** One package as the probe prints it: name, version, architecture and the source package when it differs from the name. */
export interface ProbePackage { n: string; v: string; a?: string | null; s?: string | null }
export interface ProbeBinary { name: string; version: string; path?: string | null }
export interface ProbeImage { image: string; id?: string | null; digests?: string | null; created?: string | null; platform?: string | null }
/** What a runtime bundles (probe software/4): the program and the library versions compiled into it, as Node's process.versions prints them. */
export interface ProbeBundle { name: string; path?: string | null; versions: Record<string, unknown> }
/** A package's dependency field as dpkg prints it (probe software/4): `libc6 (>= 2.34), libbrotli1 (>= 1.1.0) | libfoo`. */
export interface ProbeDepend { n: string; d: string }
/** What the guest has for hibernation (probe software/3): the kernel, the resume target, what answers the sleep button, the swap. */
export interface ProbeHibernation {
  kernel_disk?: boolean; cmdline_resume?: boolean; sys_resume?: string | null; agent?: string | null; acpi_sleep_handler?: boolean;
  logind_suspend_key?: string | null; swap_active_bytes?: number; swap_file_bytes?: number; mem_bytes?: number;
}
export interface SoftwareData {
  hibernation?: ProbeHibernation | null;
  os?: { id?: string | null; version?: string | null; name?: string | null } | null; kernel?: string | null; arch?: string | null; package_manager?: string | null;
  packages?: ProbePackage[]; binaries?: ProbeBinary[]; images?: ProbeImage[];
  bundles?: ProbeBundle[]; depends?: ProbeDepend[];
}

export interface RecordSoftwareResult { packages: number; added: string[]; removed: string[]; changed: { name: string; from: string; to: string }[]; binaries: number; images: number; bundles: number; depends: number }

const upsertOs = db.prepare(`insert into instance_os(instance_id, collected_at, os_id, os_version, os_name, kernel, arch, package_manager, packages, hibernation) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  on conflict(instance_id) do update set collected_at = excluded.collected_at, hibernation = coalesce(excluded.hibernation, hibernation), os_id = coalesce(excluded.os_id, os_id), os_version = coalesce(excluded.os_version, os_version), os_name = coalesce(excluded.os_name, os_name), kernel = coalesce(excluded.kernel, kernel), arch = coalesce(excluded.arch, arch), package_manager = coalesce(excluded.package_manager, package_manager), packages = excluded.packages`);
const upsertPkg = db.prepare(`insert into instance_packages(instance_id, ecosystem, name, version, arch, source, first_seen, last_seen, gone) values (?, ?, ?, ?, ?, ?, ?, ?, 0)
  on conflict(instance_id, ecosystem, name) do update set first_seen = case when version = excluded.version then first_seen else excluded.first_seen end, version = excluded.version, arch = excluded.arch, source = coalesce(excluded.source, source), last_seen = excluded.last_seen, gone = 0`);
const upsertBin = db.prepare(`insert into instance_binaries(instance_id, name, version, path, first_seen, last_seen, gone) values (?, ?, ?, ?, ?, ?, 0)
  on conflict(instance_id, name, path) do update set first_seen = case when version = excluded.version then first_seen else excluded.first_seen end, version = excluded.version, path = excluded.path, last_seen = excluded.last_seen, gone = 0`);
const upsertImg = db.prepare(`insert into instance_images(instance_id, image, image_id, digest, created, platform, first_seen, last_seen, gone) values (?, ?, ?, ?, ?, ?, ?, ?, 0)
  on conflict(instance_id, image) do update set image_id = excluded.image_id, digest = excluded.digest, created = excluded.created, platform = excluded.platform, last_seen = excluded.last_seen, gone = 0`);
const upsertBundle = db.prepare(`insert into instance_bundles(instance_id, parent, parent_version, name, version, first_seen, last_seen) values (?, ?, ?, ?, ?, ?, ?)
  on conflict(instance_id, parent, parent_version, name) do update set first_seen = case when version = excluded.version then first_seen else excluded.first_seen end, version = excluded.version, last_seen = excluded.last_seen`);
const upsertDepend = db.prepare(`insert into instance_depends(instance_id, name, dep, first_seen, last_seen) values (?, ?, ?, ?, ?)
  on conflict(instance_id, name, dep) do update set last_seen = excluded.last_seen`);
const insertChange = db.prepare("insert into package_changes(instance_id, ecosystem, name, from_version, to_version, at) values (?, ?, ?, ?, ?, ?)");

const clean = (s: unknown, n = 200): string => String(s ?? "").replace(/[^\x20-\x7e]/g, "").slice(0, n);

/** The package names a dpkg Depends field names: every alternative, without version constraints or architecture qualifiers. Pure. */
export function parseDepends(field: string): string[] {
  const out = new Set<string>();
  for (const clause of String(field ?? "").split(",")) for (const alt of clause.split("|")) {
    const name = alt.replace(/\([^)]*\)/g, "").trim().split(":")[0]!.trim().toLowerCase();
    if (/^[a-z0-9][a-z0-9+.-]*$/.test(name)) out.add(name);
  }
  return [...out];
}

/** A version as process.versions prints it, or null for anything that is not a plain version string. */
const bundledVersion = (v: unknown): string | null => (typeof v === "string" && /^[0-9][0-9A-Za-z.+:~-]{0,60}$/.test(v) ? v : null);
/** The version in the first line a program prints for its version flag: `Python 3.11.2` → `3.11.2`, `v18.20.4` → `18.20.4`,
 *  `OpenSSH_9.2p1 Debian-2+deb12u10, OpenSSL 3.0.22 ...` → `9.2p1`, `Docker version 25.0.14, build 0bab007` → `25.0.14`,
 *  `go version go1.23.8 linux/amd64` → `1.23.8`, `nginx version: nginx/1.26.3` → `1.26.3`, `Redis server v=7.0.15 ...` → `7.0.15`,
 *  `openjdk version "17.0.2" 2022-01-18` → `17.0.2`, `This is perl 5, version 38, subversion 2 (v5.38.2) ...` → `5.38.2`.
 *  The first word that is a dotted version once its wrapping (quotes, parentheses, a trailing comma) and a product prefix
 *  (`OpenSSH_`, `nginx/`, `v=`, `go`, `v`) are taken off; the line itself when no word is one, so an unforeseen format is kept
 *  rather than lost. The stored version is the key of the SoftwareComponent node and what a CVE range is compared against. Pure. */
export function binaryVersion(line: string): string {
  const raw = String(line ?? "").trim();
  for (const word of raw.split(/\s+/)) {
    const w = word.replace(/^[("'\[]+|[)"',;\]]+$/g, "");
    const m = /^(?:[A-Za-z][A-Za-z0-9_.-]*[=\/_:]|[a-z]{1,4})?[vV]?(\d+(?:\.\d+)+[0-9A-Za-z.+~_-]*)$/.exec(w);
    if (m) return m[1]!;
  }
  return raw;
}
/** process.versions keys that are not libraries: the runtime itself and its ABI numbers. */
const NOT_LIBRARIES = new Set(["node", "modules", "napi", "unicode", "tz", "cldr"]);

/** Records one software probe: upserts what is installed, deletes what was superseded or removed, and logs both in package_changes. */
export function recordSoftware(instanceId: string, collectedAt: string, data: SoftwareData): RecordSoftwareResult | null {
  if (!Array.isArray(data.packages) && !Array.isArray(data.binaries) && !data.os) return null;
  const eco = clean(data.package_manager || "unknown", 20);
  const pkgs = (data.packages ?? []).filter((p) => p && typeof p.n === "string" && p.n).map((p) => ({ name: clean(p.n, 120), version: clean(p.v, 120), arch: p.a == null ? null : clean(p.a, 20), source: p.s == null || !String(p.s).trim() ? null : clean(p.s, 120) }));
  const res: RecordSoftwareResult = { packages: pkgs.length, added: [], removed: [], changed: [], binaries: 0, images: 0, bundles: 0, depends: 0 };
  db.transaction(() => {
    const all = db.prepare("select ecosystem, name, version from instance_packages where instance_id = ?").all(instanceId) as { ecosystem: string; name: string; version: string }[];
    const prev = new Map(all.filter((r) => r.ecosystem === eco).map((r) => [r.name, r]));
    const first = prev.size === 0;
    const seen = new Set<string>();
    for (const p of pkgs) {
      seen.add(p.name);
      const was = prev.get(p.name);
      upsertPkg.run(instanceId, eco, p.name, p.version, p.arch, p.source, collectedAt, collectedAt);
      if (!was && !first) res.added.push(p.name);
      else if (was && was.version !== p.version) { res.changed.push({ name: p.name, from: was.version, to: p.version }); insertChange.run(instanceId, eco, p.name, was.version, p.version, collectedAt); }
    }
    // what the probe no longer lists is gone from the box (or from a package manager it no longer uses): deleted, the removal logged
    if (pkgs.length) for (const was of all) if (was.ecosystem !== eco || !seen.has(was.name)) {
      db.prepare("delete from instance_packages where instance_id = ? and ecosystem = ? and name = ?").run(instanceId, was.ecosystem, was.name);
      insertChange.run(instanceId, was.ecosystem, was.name, was.version, null, collectedAt); res.removed.push(was.name);
    }
    // one row per install: a box may hold several Nodes (nvm), each at its own path
    const bins = (data.binaries ?? []).filter((b) => b && typeof b.name === "string" && b.name && b.version).map((b) => ({ name: clean(b.name, 64), version: clean(binaryVersion(b.version), 120), path: b.path == null ? "" : clean(b.path, 200) }));
    const binSeen = new Set<string>();
    for (const b of bins) { binSeen.add(`${b.name}\t${b.path}`); upsertBin.run(instanceId, b.name, b.version, b.path, collectedAt, collectedAt); }
    if (Array.isArray(data.binaries)) for (const r of db.prepare("select name, path from instance_binaries where instance_id = ?").all(instanceId) as { name: string; path: string }[]) if (!binSeen.has(`${r.name}\t${r.path}`)) db.prepare("delete from instance_binaries where instance_id = ? and name = ? and path = ?").run(instanceId, r.name, r.path);
    res.binaries = bins.length;
    // what a runtime bundles: one row per (runtime, library); the runtime's own entry (`node`) is the parent, not a child
    const bundles = (data.bundles ?? []).filter((b) => b && typeof b.name === "string" && b.name && b.versions && typeof b.versions === "object");
    const bundleSeen = new Set<string>();
    for (const b of bundles) {
      const parent = clean(b.name, 64);
      const path = b.path == null ? "" : clean(b.path, 200);
      // the runtime's own version: the binary row at the same path, else the entry's own key (`node`), so several installs stay apart
      const own = (path ? bins.find((x) => x.name === parent && x.path === path)?.version : undefined) ?? bundledVersion(b.versions[parent]) ?? bundledVersion(b.versions["node"]) ?? bins.find((x) => x.name === parent)?.version;
      if (!own) continue;
      for (const [lib, raw] of Object.entries(b.versions)) {
        const v = bundledVersion(raw); const name = clean(lib, 64).toLowerCase();
        if (!v || !name || name === parent || NOT_LIBRARIES.has(name)) continue;
        bundleSeen.add(`${parent}\t${clean(own, 120)}\t${name}`); res.bundles++;
        upsertBundle.run(instanceId, parent, clean(own, 120), name, clean(v, 120), collectedAt, collectedAt);
      }
    }
    if (Array.isArray(data.bundles)) for (const r of db.prepare("select parent, parent_version, name from instance_bundles where instance_id = ?").all(instanceId) as { parent: string; parent_version: string; name: string }[]) if (!bundleSeen.has(`${r.parent}\t${r.parent_version}\t${r.name}`)) db.prepare("delete from instance_bundles where instance_id = ? and parent = ? and parent_version = ? and name = ?").run(instanceId, r.parent, r.parent_version, r.name);
    // dependencies between installed packages, for the packages the probe read them of
    const installed = new Set(pkgs.map((p) => p.name));
    const depSeen = new Set<string>();
    for (const d of (data.depends ?? []).filter((x) => x && typeof x.n === "string" && x.n && typeof x.d === "string")) {
      const name = clean(d.n, 120);
      for (const dep of parseDepends(d.d)) if (installed.has(dep) && dep !== name) { depSeen.add(`${name}\t${dep}`); res.depends++; upsertDepend.run(instanceId, name, dep, collectedAt, collectedAt); }
    }
    if (Array.isArray(data.depends)) for (const r of db.prepare("select name, dep from instance_depends where instance_id = ?").all(instanceId) as { name: string; dep: string }[]) if (!depSeen.has(`${r.name}\t${r.dep}`)) db.prepare("delete from instance_depends where instance_id = ? and name = ? and dep = ?").run(instanceId, r.name, r.dep);
    const imgs = (data.images ?? []).filter((i) => i && typeof i.image === "string" && i.image);
    const imgSeen = new Set<string>();
    for (const i of imgs) { imgSeen.add(i.image); upsertImg.run(instanceId, clean(i.image, 300), i.id == null ? null : clean(i.id, 100), i.digests ? clean(String(i.digests).split(",")[0], 300) : null, i.created == null ? null : clean(i.created, 40), i.platform == null ? null : clean(i.platform, 40), collectedAt, collectedAt); }
    if (Array.isArray(data.images)) db.prepare(`delete from instance_images where instance_id = ?${imgSeen.size ? ` and image not in (${[...imgSeen].map(() => "?").join(",")})` : ""}`).run(instanceId, ...imgSeen);
    res.images = imgs.length;
    upsertOs.run(instanceId, collectedAt, clean(data.os?.id, 40) || null, clean(data.os?.version, 40) || null, clean(data.os?.name, 120) || null, clean(data.kernel, 80) || null, clean(data.arch, 20) || null, data.package_manager ? eco : null, pkgs.length, data.hibernation && typeof data.hibernation === "object" ? JSON.stringify(data.hibernation).slice(0, 2000) : null);
  })();
  return res;
}

/** A package URL taken apart (https://github.com/package-url/purl-spec): `pkg:type/namespace/name@version?qualifiers#subpath`. */
export interface Purl {
  type: string; namespace: string | null; name: string; version: string | null; qualifiers: Record<string, string>;
  /** The name as its ecosystem spells it: `@scope/name` for npm, `group:artifact` for maven, the module path for golang, the bare package name for distro packages. */
  full_name: string;
}
const decode = (s: string): string => { try { return decodeURIComponent(s); } catch { return s; } };
const DISTRO_TYPES = new Set(["deb", "rpm", "apk"]);
/** Pure; null for anything that is not a purl. */
export function parsePurl(purl: string): Purl | null {
  const m = /^pkg:([A-Za-z0-9.+-]+)\/([^?#]+)(?:\?([^#]*))?(?:#.*)?$/.exec(String(purl ?? "").trim());
  if (!m) return null;
  const type = m[1]!.toLowerCase();
  let path = m[2]!; let version: string | null = null;
  const at = path.lastIndexOf("@"); if (at > 0) { version = decode(path.slice(at + 1)) || null; path = path.slice(0, at); }
  const segs = path.split("/").filter(Boolean).map(decode);
  const name = segs.pop(); if (!name) return null;
  const namespace = segs.length ? segs.join("/") : null;
  const qualifiers: Record<string, string> = {};
  for (const q of (m[3] ?? "").split("&")) { const i = q.indexOf("="); if (i > 0) qualifiers[decode(q.slice(0, i)).toLowerCase()] = decode(q.slice(i + 1)); }
  const full_name = !namespace || DISTRO_TYPES.has(type) ? name : type === "maven" ? `${namespace}:${name}` : `${namespace}/${name}`;
  return { type, namespace, name, version, qualifiers, full_name };
}

/** A purl segment percent-encoded as the spec prints it: `@` becomes %40, `:` and `+` stay (syft's own spelling, so the key matches). */
const purlSegment = (s: string): string => encodeURIComponent(s).replace(/%3A/gi, ":").replace(/%2B/gi, "+");
/** The component a purl names, without version, qualifiers or subpath: `pkg:golang/github.com/andybalholm/brotli`, `pkg:npm/%40aws-sdk/core`.
 *  The namespace keeps its slashes (a Go module path, an npm scope, a maven group); nothing is slugged. Pure. */
export function componentPurl(p: Purl): string {
  const ns = p.namespace ? p.namespace.split("/").filter(Boolean).map(purlSegment).join("/") + "/" : "";
  return `pkg:${p.type}/${ns}${purlSegment(p.name)}`;
}

/** One syft scan as the probe prints it (src/ssm.ts ProbeSbomSource). */
export interface SbomSource { source: "image" | "dir"; ref: string; image_id?: string | null; digest?: string | null; status: string; total?: number; purls?: string[] }
export interface SbomData { available?: boolean; tool?: string | null; install?: string | null; cap?: number; sources?: SbomSource[] }
export interface RecordSbomResult { available: boolean; tool: string | null; /** what the probe did about a missing syft */ note: string | null; sources: number; packages: number; /** purls syft found that did not fit the probe's output budget */ trimmed: number; failed: { ref: string; status: string }[]; added: number; removed: number }

const upsertSbomScan = db.prepare(`insert into instance_sbom_scans(instance_id, collected_at, available, tool, cap, sources, packages, note) values (?, ?, ?, ?, ?, ?, ?, ?)
  on conflict(instance_id) do update set collected_at = excluded.collected_at, available = excluded.available, tool = excluded.tool, cap = excluded.cap, sources = excluded.sources, packages = excluded.packages, note = excluded.note`);
const upsertSbomSource = db.prepare(`insert into instance_sbom_sources(instance_id, source, ref, status, total, listed, collected_at, image_id, digest) values (?, ?, ?, ?, ?, ?, ?, ?, ?)
  on conflict(instance_id, source, ref) do update set status = excluded.status, total = excluded.total, listed = case when excluded.status = 'ok' then excluded.listed else listed end, collected_at = excluded.collected_at, image_id = coalesce(excluded.image_id, image_id), digest = coalesce(excluded.digest, digest)`);
const upsertSbomRow = db.prepare(`insert into instance_sbom(instance_id, source, ref, purl, type, namespace, name, version, first_seen, last_seen) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  on conflict(instance_id, source, ref, purl) do update set last_seen = excluded.last_seen`);
const int = (v: unknown): number => { const n = Number(v); return Number.isFinite(n) ? Math.max(0, Math.round(n)) : 0; };

/** Records one sbom probe: every scan's status, the purls of the scans that succeeded (replacing the last good list), nothing when syft is not on the box. */
export function recordSbom(instanceId: string, collectedAt: string, sbom: SbomData): RecordSbomResult | null {
  if (!sbom || typeof sbom !== "object") return null;
  const res: RecordSbomResult = { available: sbom.available === true, tool: sbom.tool ? clean(sbom.tool, 40) || null : null, note: sbom.install ? clean(sbom.install, 200) || null : null, sources: 0, packages: 0, trimmed: 0, failed: [], added: 0, removed: 0 };
  db.transaction(() => {
    if (!res.available) {
      // syft gone from the box: what it read is no longer known to be there
      for (const t of ["instance_sbom", "instance_sbom_sources"]) db.prepare(`delete from ${t} where instance_id = ?`).run(instanceId);
      upsertSbomScan.run(instanceId, collectedAt, 0, null, 0, 0, 0, res.note);
      return;
    }
    const seen = new Set<string>();
    for (const s of sbom.sources ?? []) {
      if (!s || (s.source !== "image" && s.source !== "dir")) continue;
      const ref = clean(s.ref, 300); if (!ref) continue;
      const key = `${s.source}\t${ref}`; if (seen.has(key)) continue; seen.add(key);
      const status = ["ok", "timeout", "error", "skipped"].includes(String(s.status)) ? String(s.status) : "error";
      const purls = status === "ok" ? [...new Set((s.purls ?? []).map((p) => clean(p, 300)).filter(Boolean))] : [];
      res.sources++;
      upsertSbomSource.run(instanceId, s.source, ref, status, int(s.total), purls.length, collectedAt, s.image_id ? clean(s.image_id, 100) || null : null, s.digest ? clean(s.digest, 100) || null : null);
      if (status !== "ok") { res.failed.push({ ref, status }); continue; } // the rows of the last good scan stay
      res.trimmed += Math.max(0, int(s.total) - purls.length);
      const before = new Set((db.prepare("select purl from instance_sbom where instance_id = ? and source = ? and ref = ?").all(instanceId, s.source, ref) as { purl: string }[]).map((r) => r.purl));
      const now = new Set<string>();
      for (const purl of purls) {
        const p = parsePurl(purl); if (!p) continue;
        now.add(purl); res.packages++;
        if (before.size && !before.has(purl)) res.added++;
        upsertSbomRow.run(instanceId, s.source, ref, purl, p.type, p.namespace, clean(p.full_name, 200), p.version ? clean(p.version, 120) : null, collectedAt, collectedAt);
      }
      for (const purl of before) if (!now.has(purl)) { db.prepare("delete from instance_sbom where instance_id = ? and source = ? and ref = ? and purl = ?").run(instanceId, s.source, ref, purl); res.removed++; }
    }
    // a scan the probe no longer reports (the container stopped, the image changed): its rows go with it
    for (const r of db.prepare("select source, ref from instance_sbom_sources where instance_id = ?").all(instanceId) as { source: string; ref: string }[]) if (!seen.has(`${r.source}\t${r.ref}`)) {
      res.removed += (db.prepare("delete from instance_sbom where instance_id = ? and source = ? and ref = ?").run(instanceId, r.source, r.ref) as { changes: number }).changes;
      db.prepare("delete from instance_sbom_sources where instance_id = ? and source = ? and ref = ?").run(instanceId, r.source, r.ref);
    }
    upsertSbomScan.run(instanceId, collectedAt, 1, res.tool, int(sbom.cap), res.sources, (db.prepare("select count(*) as n from instance_sbom where instance_id = ?").get(instanceId) as { n: number }).n, res.note);
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
  bundles: { parent: string; parent_version: string; name: string; version: string; first_seen: string; last_seen: string }[];
  depends: { name: string; dep: string; first_seen: string; last_seen: string }[];
  /** The sbom probe: whether syft is on the box, each scan (image or filesystem) with its status and counts, and the packages (`q` filters by name). */
  sbom: { scan: { collected_at: string; available: boolean; tool: string | null; note: string | null; cap: number; sources: number; packages: number } | null;
    sources: { source: string; ref: string; image_id: string | null; digest: string | null; status: string; total: number; listed: number; collected_at: string }[];
    packages: { source: string; ref: string; purl: string; type: string; namespace: string | null; name: string; version: string | null; first_seen: string; last_seen: string }[] };
}

/** Everything the software probe knows about one instance; `q` filters packages by name. */
export function softwareOn(instanceId: string, opts: { q?: string; limit?: number } = {}): InstanceSoftware {
  const q = opts.q ? `%${opts.q.toLowerCase()}%` : null;
  const limit = Math.min(5000, Math.max(1, opts.limit ?? 2000));
  return {
    os: (db.prepare("select * from instance_os where instance_id = ?").get(instanceId) as any) ?? null,
    packages: (db.prepare(`select ecosystem, name, version, arch, source, first_seen, last_seen, gone from instance_packages where instance_id = ?${q ? " and (lower(name) like ? or lower(source) like ?)" : ""} order by name limit ?`).all(...(q ? [instanceId, q, q, limit] : [instanceId, limit])) as any[]).map((r) => ({ ...r, gone: Boolean(r.gone) })),
    binaries: (db.prepare(`select name, version, path, first_seen, last_seen, gone from instance_binaries where instance_id = ? order by name`).all(instanceId) as any[]).map((r) => ({ ...r, gone: Boolean(r.gone) })),
    images: (db.prepare(`select image, image_id, digest, created, platform, first_seen, last_seen, gone from instance_images where instance_id = ? order by image`).all(instanceId) as any[]).map((r) => ({ ...r, gone: Boolean(r.gone) })),
    changes: db.prepare("select ecosystem, name, from_version, to_version, at from package_changes where instance_id = ? order by id desc limit 50").all(instanceId) as any[],
    bundles: db.prepare("select parent, parent_version, name, version, first_seen, last_seen from instance_bundles where instance_id = ? order by parent, name").all(instanceId) as any[],
    depends: db.prepare("select name, dep, first_seen, last_seen from instance_depends where instance_id = ? order by name, dep").all(instanceId) as any[],
    sbom: {
      scan: ((r) => (r ? { ...r, available: Boolean(r.available) } : null))(db.prepare("select collected_at, available, tool, note, cap, sources, packages from instance_sbom_scans where instance_id = ?").get(instanceId) as any),
      sources: db.prepare("select source, ref, image_id, digest, status, total, listed, collected_at from instance_sbom_sources where instance_id = ? order by source desc, ref").all(instanceId) as any[],
      packages: db.prepare(`select source, ref, purl, type, namespace, name, version, first_seen, last_seen from instance_sbom where instance_id = ?${q ? " and lower(name) like ?" : ""} order by source desc, ref, type, name limit ?`).all(...(q ? [instanceId, q, limit] : [instanceId, limit])) as any[],
    },
  };
}

/** Where a package (or binary) is installed across the fleet, with its version per box: the question a CVE asks. */
export function wherePackage(name: string): { instance_id: string; instance_name: string | null; kind: "package" | "binary" | "sbom"; ecosystem: string | null; name: string; version: string; source?: string | null; /** sbom rows: the image the package is inside, or "/" for the filesystem */ ref?: string | null; last_seen: string }[] {
  const like = `%${name.toLowerCase()}%`;
  const pk = db.prepare(`select p.instance_id, i.name as instance_name, 'package' as kind, p.ecosystem, p.name, p.version, p.source, p.last_seen from instance_packages p left join inventory_ec2 i on i.instance_id = p.instance_id where p.gone = 0 and (lower(p.name) like ? or lower(p.source) like ?) order by p.name, p.version, i.name limit 2000`).all(like, like) as any[];
  const bn = db.prepare(`select b.instance_id, i.name as instance_name, 'binary' as kind, null as ecosystem, b.name, b.version, b.last_seen from instance_binaries b left join inventory_ec2 i on i.instance_id = b.instance_id where b.gone = 0 and lower(b.name) like ? order by b.name, i.name limit 500`).all(like) as any[];
  // what syft read inside the images and on the filesystems: the image (or "/") says where
  const sb = db.prepare(`select s.instance_id, i.name as instance_name, 'sbom' as kind, s.type as ecosystem, s.name, coalesce(s.version, '') as version, s.ref, s.last_seen from instance_sbom s left join inventory_ec2 i on i.instance_id = s.instance_id where lower(s.name) like ? order by s.name, s.version, i.name limit 1000`).all(like) as any[];
  return [...pk, ...bn, ...sb];
}

export interface SoftwareSummary { instances: number; packages: number; distinct_packages: number; images: number; os: { os: string; n: number }[]; kernels: { kernel: string; n: number }[]; last_collected_at: string | null; changes_7d: number; /** the sbom probe: boxes with syft, boxes probed without it, packages read */ sbom: { boxes: number; without_syft: number; packages: number } }

/** The fleet's software at a glance. */
export function softwareSummary(): SoftwareSummary {
  const a = db.prepare("select count(*) as instances, sum(packages) as packages, max(collected_at) as last from instance_os").get() as any;
  const d = db.prepare("select count(distinct name) as n from instance_packages where gone = 0").get() as any;
  const im = db.prepare("select count(*) as n from instance_images where gone = 0").get() as any;
  const os = db.prepare("select coalesce(os_name, os_id, 'unknown') as os, count(*) as n from instance_os group by 1 order by n desc limit 12").all() as any[];
  const kernels = db.prepare("select coalesce(kernel, 'unknown') as kernel, count(*) as n from instance_os group by 1 order by n desc limit 12").all() as any[];
  const ch = db.prepare("select count(*) as n from package_changes where datetime(at) > datetime('now', '-7 days')").get() as any;
  const sb = db.prepare("select sum(available) as boxes, sum(1 - available) as without_syft, sum(packages) as packages from instance_sbom_scans").get() as any;
  return { instances: Number(a?.instances || 0), packages: Number(a?.packages || 0), distinct_packages: Number(d?.n || 0), images: Number(im?.n || 0), os, kernels, last_collected_at: a?.last ?? null, changes_7d: Number(ch?.n || 0), sbom: { boxes: Number(sb?.boxes || 0), without_syft: Number(sb?.without_syft || 0), packages: Number(sb?.packages || 0) } };
}

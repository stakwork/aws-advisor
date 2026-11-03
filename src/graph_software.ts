import { db } from "./db.js";
import { accountId, enabled, inBackground, neoParams, writeCypher } from "./graph_mirror.js";
import { resourceAccountIndex } from "./resource_index.js";
import { ecosystemOf, packageScope } from "./package_scope.js";
import { AWS } from "./adapters/types.js";
import { COMPUTE_OF } from "./graph_cypher.js";
import { DISTRO_ECOSYSTEMS, componentIdentity } from "./sec/identity.js";
import { componentCpe, sbomCpe } from "./sec/cpe.js";
import { componentPurl, parsePurl } from "./software_inventory.js";

/**
 * The software layer of the graph (docs/cloud-ontology.md §2) for the AWS adapter: what the software probe found
 * installed on each box (src/software_inventory.ts) as SoftwareComponent nodes shared across the fleet, one per
 * (ecosystem, name, version), INSTALLED_ON the operating system (AdvisorCompute) the box HOSTS, which also takes the
 * distribution, version and kernel; the OS and the kernel as packages of their
 * own ecosystems; the versions read from well-known binaries as packages of the `binary` ecosystem; the container
 * images the box runs (RUNS_IMAGE → AdvisorImage, the same nodes cluster workloads are BUILT_FROM; on a Kubernetes node, where the
 * probe has no docker command, the images of the pods the cluster API places there, src/cluster_inventory.ts), what syft read
 * inside each image (the sbom probe: CONTAINS from the image to SoftwareComponent nodes of the purl's own ecosystem, npm,
 * pypi, deb of the image's distribution, ...) and on the filesystem (INSTALLED_ON like any package); PROVIDES edges
 * from a package to the program (AdvisorApp) it ships, so "which package is this listening process from" is one hop.
 *
 * A running executable (the sbom probe's proc sources, sbom 1.7) is attached where it lives (2026-11-03). A host process is
 * INSTALLED_ON the compute at its path. A process inside a container is a file of the image the container was built from, so
 * it is CONTAINS {source_kind: proc, observed: running, path} from that image node (the same node the scanner's reading of the
 * image fills, keyed by digest) and EXECUTES {path, sha256, size} from the AdvisorContainer that runs it, so "what runs in this
 * container" and "what does this image carry" are one hop each; the compute reaches it through RUNS → EXECUTES and RUNS_IMAGE →
 * CONTAINS. An executable on a bind mount or a volume (its path under one of the container's mount destinations) is not the
 * image's: it keeps INSTALLED_ON the compute with the container id on the edge, plus EXECUTES. The two writers of CONTAINS
 * (the scanner's image_scan edges, the boxes' proc edges) each retire only their own kind.
 *
 * The kernel is two nodes joined by PACKAGED_AS (probe software/6): the running kernel (ecosystem kernel, pkg:generic/linux) at its upstream
 * version, the x.y.z the kernel CNA's ranges name, and the distribution package that owns the booted image (a deb/rpm/apk node like any
 * other, what the distribution's advisories name). uname -r stays on the compute: on Debian and Ubuntu it is an ABI (6.1.0-54-cloud-amd64)
 * that never carries the point release, and read as a version it matched every fix in the series forever. Old kernel images linger after
 * upgrades (apt keeps the previous kernel as the GRUB fallback and never removes one on its own), so PACKAGED_AS also says which of several
 * installed linux-image packages is the one running, and a kernel image that is installed but not booted is not INSTALLED_ON at all
 * (dormantKernelImage, 2026-11-02): it runs no code, and a Finding on its version node would reach every box that merely keeps it as a
 * fallback. Its edge is retired like a removed package's and comes back if the box boots it; the inventory's package list still shows it.
 * A box that does not say which image it booted keeps every kernel image, the conservative side.
 *
 * The label is the public vulnerability graph's: a SoftwareComponent there is keyed by `product_key` (scheme-specific;
 * for the purl scheme the purl without version), and every node here carries that key (`product_key` = `purl`, `scheme`
 * = purl, `package` = the name) next to its own identity (src/sec/identity.ts): `purl`, `source_purl` (the source
 * package a distribution's advisories name), `sort_key` (the version as a sortable string), `version_purl`, and `cpe` / `cpes` (src/sec/cpe.ts:
 * the CPE 2.3 strings the version answers to, best first: what syft assigned from the NVD dictionary or a binary classifier for a purl it read,
 * the CPE the distribution declares in os-release, NVD's vendor:product for a program the probe named, syft-style name guesses for the rest;
 * a CVE whose only identity is a CPE configuration is matched by vendor and product against these). One node
 * here is one installed version, so several share a product_key; the match reads (product_key, sort_key). Containment is edges between package nodes, the same two whatever the mechanism:
 * BUNDLES (a runtime to the libraries compiled into it, from Node's process.versions; the library is an SoftwareComponent
 * in the `binary` ecosystem with source_kind process_versions, one node with the system copy of the same version) and DEPENDS_ON (a package to the installed packages its dpkg Depends names). A CVE in brotli
 * then reaches a box as (compute)<-[:INSTALLED_ON]-(node)-[:BUNDLES]->(brotli), with no lookup. The match itself is a
 * strut workflow against the public graph; nothing here decides vulnerability from these.
 *
 * The vulnerability knowledge and the verdicts are not written here: the strut workflows match these nodes against the
 * public vulnerability graph (docs/vulnerability-graph-plan.md) and write their own. The advisor's own OSV/ALAS matcher
 * and its KnVulnerability, AFFECTS and VULNERABLE_TO writes were removed on 2026-10-29. Rebuilt per box after its probes.
 *
 * History is kept. A version node is a fact about the world and is never deleted; the box-side edges (INSTALLED_ON,
 * RUNS_IMAGE, CONTAINS) carry the lifecycle: what a probe no longer reports is marked `is_deleted: true, deleted_at` rather
 * than removed, and comes back (`is_deleted: false`) if the probe reports it again. The upgrade itself is an edge between
 * the two version nodes, SUPERSEDED_BY, from the inventory's package_changes log. A Finding the strut match attached to
 * the old version stays with it; whoever asks "vulnerable now?" walks only edges where is_deleted is false.
 */

export const SOFTWARE_LABELS = ["SoftwareComponent", "AdvisorImage"] as const;

const PACKAGE_CYPHER = `
UNWIND $rows AS row
MATCH (b:AdvisorResource {id: row.instance_id})
${COMPUTE_OF("b", "c")}
MERGE (p:SoftwareComponent {id: row.id}) ON CREATE SET p.first_seen = $now
SET p += {name: row.name, version: row.version, ecosystem: row.ecosystem, source_name: row.source_name, source_kind: row.source_kind, advisory_ecosystem: row.advisory_ecosystem, scope: row.scope, purl: row.purl, source_purl: row.source_purl, sort_key: row.sort_key, version_purl: row.version_purl, cpe: row.cpe, cpes: row.cpes, classified: coalesce(row.classified, true), scheme: 'purl', product_key: row.purl, package: row.name, native_type: 'software_component', is_deleted: false, deleted_at: null, provider: $provider, account_id: coalesce(row.account_id, $account), updated_at: $now}
MERGE (p)-[r:INSTALLED_ON]->(c)
SET r += {arch: row.arch, path: row.path, container: row.container, sha256: row.sha256, size: row.size, first_seen: row.first_seen, last_seen: row.last_seen, is_deleted: false, deleted_at: null, updated_at: $now}`;

const IMAGE_CYPHER = `
UNWIND $rows AS row
MATCH (b:AdvisorResource {id: row.instance_id})
${COMPUTE_OF("b", "c")}
MERGE (i:AdvisorResource {id: row.id}) ON CREATE SET i.first_seen = $now
SET i:AdvisorImage, i += {name: row.image, kind: 'container', repository: row.repository, tag: row.tag, digest: row.digest, created_at: row.created, platform: row.platform, native_type: 'container_image', native_id: row.image, provider: $provider, account_id: coalesce(row.account_id, $account), updated_at: $now}
MERGE (c)-[r:RUNS_IMAGE]->(i)
SET r += {image_id: row.image_id, first_seen: row.first_seen, last_seen: row.last_seen, is_deleted: false, deleted_at: null, updated_at: $now}`;

/** What syft read inside a running image: the image node (merged, so an image the software probe has not listed yet still
 *  gets its contents), the package node of the purl's ecosystem, and CONTAINS between them. */
const CONTAINS_CYPHER = `
UNWIND $rows AS row
MERGE (i:AdvisorResource {id: row.image_id}) ON CREATE SET i.first_seen = $now, i.name = row.image, i.kind = 'container', i.repository = row.repository, i.tag = row.tag, i.native_type = 'container_image', i.native_id = row.image, i.provider = $provider, i.account_id = coalesce(row.account_id, $account)
SET i:AdvisorImage, i.digest = coalesce(row.digest, i.digest), i.image_id = coalesce(row.docker_image_id, i.image_id)
MERGE (p:SoftwareComponent {id: row.id}) ON CREATE SET p.first_seen = $now
SET p += {name: row.name, version: row.version, ecosystem: row.ecosystem, source_name: row.source_name, source_kind: row.source_kind, advisory_ecosystem: row.advisory_ecosystem, scope: row.scope, purl: row.purl, source_purl: row.source_purl, sort_key: row.sort_key, version_purl: row.version_purl, cpe: row.cpe, cpes: row.cpes, scheme: 'purl', product_key: row.purl, package: row.name, native_type: 'software_component', is_deleted: false, deleted_at: null, provider: $provider, account_id: coalesce(row.account_id, $account), updated_at: $now}
MERGE (i)-[r:CONTAINS]->(p)
SET r += {first_seen: row.first_seen, last_seen: row.last_seen, platform: row.platform, source_kind: coalesce(row.edge_source_kind, 'image_scan'), observed: row.observed, path: row.path, sha256: row.sha256, size: row.size, is_deleted: false, deleted_at: null, updated_at: $now}`;

/** Scoped by who wrote the edge (`source_kind`): the scanner's keep list retires only image_scan edges, a box's proc keep list only proc edges. */
const PRUNE_CONTAINS_CYPHER = `
UNWIND $rows AS row
MATCH (i:AdvisorImage {id: row.image_id})-[r:CONTAINS]->(p:SoftwareComponent)
WHERE NOT p.id IN row.keep AND coalesce(r.is_deleted, false) = false AND coalesce(r.source_kind, 'image_scan') = row.source_kind
SET r.is_deleted = true, r.deleted_at = $now`;

/** A container to the executables it runs (sbom 1.7 proc sources read through the container's root): the container node is the docker
 *  probe's (src/graph_containers.ts), matched, never merged; a container that probe has not written yet gets its edges on the next sync. */
const EXECUTES_CYPHER = `
UNWIND $rows AS row
MATCH (k:AdvisorContainer {id: row.container_node}) MATCH (p:SoftwareComponent {id: row.id})
MERGE (k)-[r:EXECUTES]->(p)
SET r.first_seen = CASE WHEN r.first_seen IS NULL OR coalesce(r.is_deleted, false) THEN row.first_seen ELSE r.first_seen END,
    r += {path: row.path, sha256: row.sha256, size: row.size, last_seen: row.last_seen, is_deleted: false, deleted_at: null, updated_at: $now}`;

const PRUNE_EXECUTES_CYPHER = `
UNWIND $rows AS row
MATCH (k:AdvisorContainer {id: row.container_node})-[r:EXECUTES]->(p:SoftwareComponent)
WHERE NOT p.id IN row.keep AND coalesce(r.is_deleted, false) = false
SET r.is_deleted = true, r.deleted_at = $now`;

/** What the probe read of the operating system (/etc/os-release, uname) onto the compute the box hosts. */
const OS_CYPHER = `
UNWIND $rows AS row
MATCH (b:AdvisorResource {id: row.instance_id})
${COMPUTE_OF("b", "c")}
SET c += {os: row.os, os_id: row.os_id, os_version: row.os_version, os_cpe: row.os_cpe, kernel: row.kernel, kernel_upstream: row.kernel_upstream, kernel_package: row.kernel_package, kernel_package_version: row.kernel_package_version, arch: coalesce(row.arch, c.arch), package_manager: row.package_manager, os_collected_at: row.collected_at, updated_at: $now}`;

/** A box's package and image edges the probe no longer reports (an older version, something removed): the node id is
 *  per version, so an upgrade adds an edge and only this retires the superseded one. Retired, not deleted: the edge keeps
 *  its dates and gains is_deleted and deleted_at (the first sync that missed it), so the box's history stays walkable. */
const PRUNE_PACKAGES_CYPHER = `
UNWIND $rows AS row
MATCH (p:SoftwareComponent)-[r:INSTALLED_ON]->(c:AdvisorCompute {id: 'compute:' + row.instance_id})
WHERE NOT p.id IN row.keep AND coalesce(r.is_deleted, false) = false
SET r.is_deleted = true, r.deleted_at = $now`;

const PRUNE_IMAGES_CYPHER = `
UNWIND $rows AS row
MATCH (c:AdvisorCompute {id: 'compute:' + row.instance_id})-[r:RUNS_IMAGE]->(i:AdvisorImage)
WHERE NOT i.id IN row.keep AND coalesce(r.is_deleted, false) = false
SET r.is_deleted = true, r.deleted_at = $now`;

/** A runtime to a library compiled into it, and a package to an installed package it depends on: both between the
 *  shared version nodes, so "node 22.12.0 bundles brotli 1.1.0" is one fact however many boxes have it. */
const BUNDLES_CYPHER = `
UNWIND $rows AS row
MATCH (a:SoftwareComponent {id: row.parent_id}) MATCH (b:SoftwareComponent {id: row.child_id})
MERGE (a)-[r:BUNDLES]->(b) SET r += {source_kind: 'process_versions', updated_at: $now}`;

const DEPENDS_ON_CYPHER = `
UNWIND $rows AS row
MATCH (a:SoftwareComponent {id: row.from_id}) MATCH (b:SoftwareComponent {id: row.to_id})
MERGE (a)-[r:DEPENDS_ON]->(b) SET r += {source_kind: row.source_kind, updated_at: $now}`;

/** The running kernel to the distribution package that owns its boot image: one fact per (upstream version, package version) pair, so a
 *  distribution advisory against the package reaches the kernel node, and the booted image is told from the installed ones. */
const PACKAGED_AS_CYPHER = `
UNWIND $rows AS row
MATCH (k:SoftwareComponent {id: row.kernel_id}) MATCH (p:SoftwareComponent {id: row.package_id})
MERGE (k)-[r:PACKAGED_AS]->(p) SET r += {source_kind: row.source_kind, updated_at: $now}`;

const PROVIDES_CYPHER = `
UNWIND $rows AS row
MATCH (p:SoftwareComponent {id: row.package_id}) MATCH (a:AdvisorApp {id: row.app})
MERGE (p)-[r:PROVIDES]->(a) SET r.updated_at = $now`;

/** What happened to an old version: the inventory's package_changes row (box, name, from, to) as an edge between the two
 *  version nodes. One edge per pair however many boxes made the move; `at` is the latest probe that saw it, `boxes` how many. */
/** Ids an older advisor wrote under ecosystems that merged into `binary` on 2026-10-31: syft's pkg:generic (a program recognised by its
 *  contents) and pkg:bundled (a library a runtime ships) are the same kind of fact as a version read from the program, and the matcher counted
 *  the same software on a box twice or three times. A node whose new id is free is renamed in place, history and all; one whose new id the
 *  collector has already written is retired (its edges and itself marked deleted, `merged_into` naming the survivor), never deleted: what the
 *  match attached to it stays attached. Idempotent: nothing matches once the fleet has been through it. */
const MIGRATE_IDS_RENAME_CYPHER = `
MATCH (o:SoftwareComponent) WHERE o.id STARTS WITH 'pkg:generic:' OR o.id STARTS WITH 'pkg:bundled:'
WITH o, 'pkg:binary:' + substring(o.id, 12) AS nid
OPTIONAL MATCH (n:SoftwareComponent {id: nid}) WITH o, nid, n WHERE n IS NULL
SET o.id = nid, o.ecosystem = 'binary', o.updated_at = $now`;
const MIGRATE_IDS_RETIRE_CYPHER = `
MATCH (o:SoftwareComponent) WHERE o.id STARTS WITH 'pkg:generic:' OR o.id STARTS WITH 'pkg:bundled:'
WITH o, 'pkg:binary:' + substring(o.id, 12) AS nid
MATCH (n:SoftwareComponent {id: nid})
OPTIONAL MATCH (o)-[i:INSTALLED_ON]->()
FOREACH (r IN CASE WHEN i IS NULL OR coalesce(i.is_deleted, false) THEN [] ELSE [i] END | SET r.is_deleted = true, r.deleted_at = $now)
WITH DISTINCT o, nid
OPTIONAL MATCH ()-[c:CONTAINS]->(o)
FOREACH (r IN CASE WHEN c IS NULL OR coalesce(c.is_deleted, false) THEN [] ELSE [c] END | SET r.is_deleted = true, r.deleted_at = $now)
WITH DISTINCT o, nid
SET o.is_deleted = true, o.deleted_at = coalesce(o.deleted_at, $now), o.merged_into = nid, o.updated_at = $now`;

/** The node's own lifecycle, after the edges': a version no box holds and no image contains any more (every INSTALLED_ON and CONTAINS edge
 *  to it retired) is marked `is_deleted: true, deleted_at`, and comes back the moment an edge does. The node stays: it is the history the
 *  SUPERSEDED_BY chain and the match's findings hang from, and a reader that wants the present (the matcher, a fleet query) filters on it. */
const ORPHAN_COMPONENTS_CYPHER = `
MATCH (p:SoftwareComponent) WHERE coalesce(p.is_deleted, false) = false
AND size([(p)-[r:INSTALLED_ON]->() WHERE coalesce(r.is_deleted, false) = false | 1]) = 0
AND size([()-[r:CONTAINS]->(p) WHERE coalesce(r.is_deleted, false) = false | 1]) = 0
AND size([()-[r:EXECUTES]->(p) WHERE coalesce(r.is_deleted, false) = false | 1]) = 0
SET p.is_deleted = true, p.deleted_at = $now`;
const REVIVE_COMPONENTS_CYPHER = `
MATCH (p:SoftwareComponent) WHERE p.is_deleted = true
AND size([(p)-[r:INSTALLED_ON]->() WHERE coalesce(r.is_deleted, false) = false | 1]) + size([()-[r:CONTAINS]->(p) WHERE coalesce(r.is_deleted, false) = false | 1]) + size([()-[r:EXECUTES]->(p) WHERE coalesce(r.is_deleted, false) = false | 1]) > 0
SET p.is_deleted = false, p.deleted_at = null`;

const SUPERSEDED_BY_CYPHER = `
UNWIND $rows AS row
MATCH (a:SoftwareComponent {id: row.from_id}) MATCH (b:SoftwareComponent {id: row.to_id})
MERGE (a)-[r:SUPERSEDED_BY]->(b) ON CREATE SET r.first_at = row.first_at
SET r.at = row.at, r.boxes = row.boxes, r.updated_at = $now`;

const chunks = <T,>(items: T[], size = 250): T[][] => { const out: T[][] = []; for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size)); return out; };
const rows = (sql: string, ...params: unknown[]): any[] => { try { return db.prepare(sql).all(...params) as any[]; } catch { return []; } };
const SOURCE_KIND: Record<string, string> = { deb: "dpkg", rpm: "rpm", apk: "apk", bundled: "process_versions" };
export const packageId = (ecosystem: string, name: string, version: string) => `pkg:${ecosystem}:${name}:${version}`;
/** The ecosystem a syft purl's type lands in: its own (npm, pypi, golang, deb, ...), except that `generic`, what syft's binary cataloger gives a program
 *  it recognised by its contents (pkg:generic/node@20.18.0), is the `binary` ecosystem of the software probe's version-flag readings, so the node
 *  syft found and the node the probe asked are one SoftwareComponent (pkg:binary:node:20.18.0) rather than two with the same purl and version. */
export const sbomEcosystem = (type: string): string => (type === "generic" ? "binary" : type);

/** An installed kernel image package that is not the one booted (probe software/6, the instance_os row's kernel_package; or on rpm, where
 *  the inventory keeps one row per name, a kernel whose version-release.arch is not uname -r): a deb linux-image-*, an rpm kernel, kernel-core
 *  or kernel-modules*, an apk linux-<flavor>. Such a package gets no INSTALLED_ON edge: the code is on disk but not running. Metapackages
 *  (linux-image-amd64, linux-image-cloud-amd64) carry no code either and are never the booted name, so they count as dormant too. Headers,
 *  libc-dev, firmware and tools are not images and are left alone. False when the box has not said what it booted. Pure. */
export function dormantKernelImage(p: { ecosystem: string; name: string; version: string; arch?: string | null }, o: { kernel?: string | null; kernel_package?: string | null } | undefined): boolean {
  if (!o?.kernel || !o.kernel_package) return false;
  if (p.name === o.kernel_package) return false;
  switch (p.ecosystem) {
    case "deb": return /^linux-image-/.test(p.name);
    case "rpm": return /^kernel(-core|-modules(-[a-z]+)?|-uek(-core)?|-lt|-ml)?$/.test(p.name) && `${p.version}.${p.arch ?? ""}` !== o.kernel && p.version !== o.kernel;
    case "apk": return /^linux-(lts|virt|edge|rpi[0-9]*|asahi|vanilla)$/.test(p.name);
    default: return false;
  }
}

/** The running kernel as a component (an instance_os row; src/software_inventory.ts kernelFacts): the version is the upstream x.y.z the kernel
 *  CNA's ranges name, so every box on that upstream shares the node and its sort_key compares to a SecAffectedRange's keys; uname -r (on Debian
 *  and Ubuntu an ABI, 6.1.0-54-cloud-amd64, that never carries the point release) stays on the compute as `kernel`. Until the upstream version
 *  is known the node is named by uname -r and carries no sort_key: 6.1.0-54 read as 6.1.0 would miss every fix in the 6.1 series forever. Pure. */
export function kernelComponent(o: { instance_id: string; kernel: string; kernel_upstream?: string | null; arch?: string | null; collected_at: string }) {
  const version = o.kernel_upstream || o.kernel;
  const row = { instance_id: o.instance_id, version_purl: null as string | null, id: packageId("kernel", "linux", version), name: "linux", version, ecosystem: "kernel", source_name: null as string | null, source_kind: "uname", advisory_ecosystem: null as string | null, scope: "kernel", arch: o.arch ?? null, path: null as string | null, first_seen: o.collected_at, last_seen: o.collected_at, ...componentIdentity({ ecosystem: "kernel", name: "linux", version }), ...componentCpe({ ecosystem: "kernel", name: "linux", version }) };
  if (!o.kernel_upstream) row.sort_key = null;
  return row;
}

/** The node id of an image: its content when known (the repository at its registry digest, else the local image id for a build that never
 *  left the box), the bare reference otherwise. A tag such as latest moves; two boxes on different builds of it are two nodes, and a box that
 *  pulls the new build moves to a new node while the old one is pruned once nobody runs it. Pure. */
export function imageNodeId(ref: string, digest?: string | null, imageId?: string | null): string {
  const d = digest ? String(digest).split("@").pop()! : "";
  if (/^sha256:[0-9a-f]{64}$/.test(d)) return `image:${imageRef(ref).repository}@${d}`;
  if (imageId && /^sha256:[0-9a-f]{12,64}$/.test(imageId)) return `image:${imageId}`;
  return `image:${ref}`;
}

/** An image reference's node id (by name alone; imageNodeId prefers the content), repository and tag (latest when none is named; none when pinned by digest). */
export function imageRef(image: string): { id: string; repository: string; tag: string | null } {
  const noDigest = image.split("@")[0]; const idx = noDigest.lastIndexOf(":"); const hasTag = idx > noDigest.lastIndexOf("/");
  return { id: `image:${image}`, repository: hasTag ? noDigest.slice(0, idx) : noDigest, tag: image.includes("@") ? null : hasTag ? noDigest.slice(idx + 1) : "latest" };
}

/** One instance_sbom row as the graph takes it: a filesystem purl, or one read from a running executable (source proc, the ref naming the host path or the
 *  container and the path), is INSTALLED_ON the box like any package (PACKAGE_CYPHER), a purl inside
 *  an image is CONTAINS from the image node (CONTAINS_CYPHER). The purl\'s own type is the ecosystem; a distro purl carries the image\'s
 *  distribution (distro qualifier, else the namespace) and source package (upstream), so its identity and advisory ecosystem are that
 *  distribution\'s, not the host\'s. The package id is the package\'s; the image id travels as image_id. Pure; null for a purl that does not parse. */
/** The image a container process belongs to (the container's BUILT_FROM node: imageNodeId of the box's instance_images row) and the container's own node, as the caller resolves them. */
export interface ContainerContext {
  /** The image node and its reference fields, as CONTAINS_CYPHER merges them; null when the box has no image row for the container. */
  container_image?: ContainerImageRef | null;
  /** The executable lives under one of the container's mount destinations (a bind mount or a volume): not a file of the image. */
  on_mount?: boolean;
  /** The AdvisorContainer node id (container:<instance>:<name>); null when the docker probe has not recorded the container. */
  container_node?: string | null;
  sha256?: string | null; size?: number | null;
}
export interface ContainerImageRef { image_id: string; image: string; repository: string; tag: string | null; digest: string | null; docker_image_id: string | null }
export interface ExecutesRow { container_node: string; id: string; path: string | null; sha256: string | null; size: number | null; first_seen: string; last_seen: string }
export interface SbomGraphRow { edge: "installed_on" | "contains"; row: Record<string, unknown>; /** the container's edge to the executable, when it runs in a recorded container */ executes?: ExecutesRow }

export function sbomGraphRow(r: { instance_id: string; source: string; ref: string; purl: string; name: string; version: string | null; first_seen: string; last_seen: string; digest?: string | null; image_id?: string | null; platform?: string | null; /** the CPEs syft assigned, as the row stores them (a JSON list) or as a list; the rule forms candidates when none */ cpes?: string | string[] | null } & ContainerContext): SbomGraphRow | null {
  const p = parsePurl(String(r.purl)); if (!p) return null;
  const version = String(r.version || p.version || "unknown");
  const upstream = p.qualifiers.upstream ? p.qualifiers.upstream.split("@")[0] || null : null;
  const distro = /^(.+?)-([0-9][^-]*)$/.exec(p.qualifiers.distro ?? "");
  const distroId = DISTRO_ECOSYSTEMS.has(p.type) ? (distro?.[1] ?? p.namespace ?? null) : null;
  const advisory = distroId ? ecosystemOf(p.type, distroId, distro?.[2] ?? null)?.ecosystem ?? null : null;
  // a distro purl takes the identity rules (distribution segment, source package); any other keeps the purl's own path, namespace and
  // all (componentIdentity slugs the name, which would fold github.com/andybalholm/brotli into github.comandybalholmbrotli)
  const identity = componentIdentity({ ecosystem: p.type, name: String(r.name), version, source: upstream, os_id: distroId });
  if (!DISTRO_ECOSYSTEMS.has(p.type)) { const purl = componentPurl(p); identity.purl = purl; identity.source_purl = purl; }
  const eco = sbomEcosystem(p.type);
  const node = { id: packageId(eco, String(r.name), version), name: String(r.name), version, ecosystem: eco, source_name: upstream, source_kind: "syft", advisory_ecosystem: advisory, scope: eco === "binary" ? packageScope(String(r.name)).scope : "library", version_purl: String(r.purl), ...identity, ...sbomCpe(r.cpes, { ecosystem: eco, name: String(r.name), version, source: upstream }) };
  if (r.source === "dir") return { edge: "installed_on", row: { instance_id: r.instance_id, ...node, arch: p.qualifiers.arch ?? null, path: null, container: null, first_seen: r.first_seen, last_seen: r.last_seen } };
  // a running executable (sbom 1.7): a host process INSTALLED_ON the box at its path; a container process CONTAINS from the container's image (a file of it)
  // and EXECUTES from the container; one on a mount keeps the compute edge with the container id (placement, 2026-11-03)
  if (r.source === "proc") return placeProcess(r, node, p.qualifiers.arch ?? null);
  const im = imageRef(String(r.ref));
  return { edge: "contains", row: { instance_id: r.instance_id, ...node, image_id: imageNodeId(String(r.ref), r.digest, r.image_id), image: String(r.ref), repository: im.repository, tag: im.tag, digest: r.digest ? String(r.digest).split("@").pop() : null, docker_image_id: r.image_id ?? null, platform: r.platform ?? null, path: null, sha256: null, size: null, edge_source_kind: "image_scan", observed: null, first_seen: r.first_seen, last_seen: r.last_seen } };
}

/** Where a running executable's node hangs (sbomGraphRow and unclassifiedGraphRow share it): the ref says host or container and the path. Pure. */
function placeProcess(r: { instance_id: string; ref: string; first_seen: string; last_seen: string } & ContainerContext, node: Record<string, unknown> & { id: string }, arch: string | null): SbomGraphRow | null {
  const m = /^(?:host|container:([0-9a-f]{12})):(\/.*)$/.exec(String(r.ref)); if (!m) return null;
  const path = m[2]!; const container = m[1] ?? null;
  const executes: ExecutesRow | undefined = container && r.container_node ? { container_node: r.container_node, id: node.id, path, sha256: r.sha256 ?? null, size: r.size ?? null, first_seen: r.first_seen, last_seen: r.last_seen } : undefined;
  if (container && r.container_image && !r.on_mount) {
    const i = r.container_image;
    return { edge: "contains", row: { instance_id: r.instance_id, ...node, image_id: i.image_id, image: i.image, repository: i.repository, tag: i.tag, digest: i.digest, docker_image_id: i.docker_image_id, platform: null, path, container, sha256: r.sha256 ?? null, size: r.size ?? null, edge_source_kind: "proc", observed: "running", first_seen: r.first_seen, last_seen: r.last_seen }, executes };
  }
  return { edge: "installed_on", row: { instance_id: r.instance_id, ...node, arch, path, container, sha256: r.sha256 ?? null, size: r.size ?? null, first_seen: r.first_seen, last_seen: r.last_seen }, executes };
}

/** An executable's path is under one of the container's mount destinations (`instance_containers.mounts`, a JSON list of {type, source, destination, rw}):
 *  a bind mount or a volume, so the file is not the image's. A destination of `/` is ignored (it would claim everything). Pure; false for anything unparsable. */
export function onMount(path: string | null | undefined, mounts: string | unknown[] | null | undefined): boolean {
  if (!path) return false;
  let list: unknown[] = [];
  try { list = Array.isArray(mounts) ? mounts : mounts ? JSON.parse(String(mounts)) : []; } catch { return false; }
  if (!Array.isArray(list)) return false;
  for (const m of list) {
    const d = m && typeof m === "object" ? String((m as any).destination ?? "") : "";
    if (!d || d === "/" ) continue;
    const dest = d.replace(/\/+$/, "");
    if (path === dest || path.startsWith(dest + "/")) return true;
  }
  return false;
}

/** A running executable nothing identified, placed like an identified one (placeProcess): on the compute when it is a host process or on a mount, on the
 *  container's image and the container otherwise. Null for a ref that does not parse. */
export function unclassifiedGraphRow(s: { instance_id: string; ref: string; container?: string | null; sha256?: string | null; size?: number | null; collected_at: string } & ContainerContext): SbomGraphRow | null {
  const row = unclassifiedComponentRow(s); if (!row) return null;
  const { path: _p, container: _c, sha256: _h, size: _z, arch: _a, ...node } = row as Record<string, unknown> & { id: string };
  return placeProcess({ instance_id: s.instance_id, ref: s.ref, first_seen: s.collected_at, last_seen: s.collected_at, container_image: s.container_image, on_mount: s.on_mount, container_node: s.container_node, sha256: s.sha256 ?? null, size: s.size ?? null }, node, null);
}

/** The image node a box's image reference resolves to, from its instance_images rows (digest or docker id when the probe recorded one, the bare
 *  reference otherwise: imageNodeId), so a container's BUILT_FROM and a process's CONTAINS meet the node RUNS_IMAGE and the scanner use. Looked up
 *  by (box, reference), then by (box, docker image id); null when the box has no row for it. Pure over the rows given. */
export function imageNodeResolver(rows: { instance_id: string; image: string; image_id?: string | null; digest?: string | null }[]): (instanceId: string, image: string | null | undefined, imageId?: string | null) => ContainerImageRef | null {
  const byRef = new Map<string, (typeof rows)[number]>(); const byId = new Map<string, (typeof rows)[number]>();
  for (const r of rows) { byRef.set(`${r.instance_id}\t${r.image}`, r); if (r.image_id) byId.set(`${r.instance_id}\t${r.image_id}`, r); }
  return (instanceId, image, imageId) => {
    const r = (image ? byRef.get(`${instanceId}\t${image}`) : undefined) ?? (imageId ? byId.get(`${instanceId}\t${imageId}`) : undefined);
    const ref = image ?? r?.image; if (!ref) return null;
    const im = imageRef(ref);
    return { image_id: imageNodeId(ref, r?.digest ?? null, r?.image_id ?? imageId ?? null), image: ref, repository: im.repository, tag: im.tag, digest: r?.digest ? String(r.digest).split("@").pop()! : null, docker_image_id: r?.image_id ?? imageId ?? null };
  };
}

/** A running executable nothing identified (sbom 1.7: syft found no package in it and the probe's text read knew it no better), as the graph keeps it: a binary
 *  component named by the file at version `unknown` with `classified: false`, INSTALLED_ON the box at its path with the container, the file's sha256 and size
 *  on the edge. One node per name across the fleet, however many builds (the hashes tell them apart on the edges); no purl version, no sort_key, no CPE: it is
 *  the list of what the fleet runs that no rule names yet, where the next classifier (src/probes.ts sniff) is written from. Null for a ref that does not parse. */
export function unclassifiedComponentRow(s: { instance_id: string; ref: string; container?: string | null; sha256?: string | null; size?: number | null; collected_at: string }): Record<string, unknown> | null {
  const m = /^(?:host|container:([0-9a-f]{12})):(\/.*)$/.exec(String(s.ref)); if (!m) return null;
  const path = m[2]!; const name = path.split("/").pop() || "unknown";
  return { instance_id: s.instance_id, version_purl: null, id: packageId("binary", name, "unknown"), name, version: "unknown", ecosystem: "binary", source_name: null, source_kind: "unclassified", advisory_ecosystem: null, scope: packageScope(name).scope, arch: null, path, container: m[1] ?? null, sha256: s.sha256 ?? null, size: s.size ?? null, first_seen: s.collected_at, last_seen: s.collected_at, ...componentIdentity({ ecosystem: "binary", name, version: "unknown" }), sort_key: null, cpe: null, cpes: [], classified: false };
}

/** The image key of an instance_images row in SQL (software_inventory.ts IMG_KEY): its sbom_key, else the per-box fallback. */
const IMG_KEY = "coalesce(ii.sbom_key, 'ref:' || ii.instance_id || '|' || ii.image)";

export interface SoftwareGraphCounts { packages: number; installed: number; images: number; contains: number; /** EXECUTES edges, container → running executable */ executes: number; provides: number; bundles: number; depends: number; packaged_as: number; superseded: number; took_ms: number }

/** Everything the software and sbom probes know about the given boxes (or all). */
export async function mirrorSoftware(instanceIds?: string[]): Promise<SoftwareGraphCounts | null> {
  if (!enabled()) return null;
  if (instanceIds && !instanceIds.length) return null;
  const t0 = Date.now(); const now = new Date().toISOString(); const account = accountId();
  // Member accounts (src/accounts.ts): a package or image node is stamped with the account of the box it was seen on
  const idx = resourceAccountIndex(account);
  const w = (cypher: string, batch: any[]) => writeCypher(cypher, neoParams({ rows: batch.map((r) => (r && typeof r === "object" && "instance_id" in r && !("account_id" in r) ? { ...r, account_id: idx.of(String(r.instance_id)) } : r)), now, provider: AWS, account }));
  const where = instanceIds ? ` and instance_id in (${instanceIds.map(() => "?").join(",")})` : "";
  const args = instanceIds ?? [];
  // ids from before the ecosystems merged (see MIGRATE_IDS_RENAME_CYPHER): renamed or retired before this sync writes, so it meets no twin
  await writeCypher(MIGRATE_IDS_RENAME_CYPHER, neoParams({ now }));
  await writeCypher(MIGRATE_IDS_RETIRE_CYPHER, neoParams({ now }));
  const os = new Map<string, any>(); for (const o of rows(`select * from instance_os where 1=1${where}`, ...args)) os.set(o.instance_id, o);

  // packages: one node per (ecosystem, name, version), the box's edge carries its own dates
  const pkgRows: any[] = [];
  for (const p of rows(`select instance_id, ecosystem, name, version, arch, source, first_seen, last_seen, gone from instance_packages where 1=1${where}`, ...args)) {
    const o = os.get(p.instance_id); const eco = o ? ecosystemOf(o.package_manager, o.os_id, o.os_version) : null;
    if (dormantKernelImage(p, o)) continue; // installed, not booted: no edge (left out of the keep list, so an edge an earlier sync wrote is retired)
    pkgRows.push({ instance_id: p.instance_id, version_purl: null, id: packageId(p.ecosystem, p.name, p.version), name: p.name, version: p.version, ecosystem: p.ecosystem, source_name: p.source ?? null, source_kind: SOURCE_KIND[p.ecosystem] ?? p.ecosystem, advisory_ecosystem: eco?.ecosystem ?? null, scope: packageScope(p.source ?? p.name).scope, arch: p.arch ?? null, path: null, first_seen: p.first_seen, last_seen: p.last_seen, ...componentIdentity({ ecosystem: p.ecosystem, name: p.name, version: p.version, source: p.source ?? null, os_id: o?.os_id ?? null }), ...componentCpe({ ecosystem: p.ecosystem, name: p.name, version: p.version, source: p.source ?? null }) });
  }
  // what the runtimes bundle (probe software/4): the library is a package of its own, installed on the box through the runtime; a binary
  // component (one node with the system copy of the same version, since 2026-10-31), its source_kind saying it was read from process.versions
  const bundleRows = rows(`select instance_id, parent, parent_version, name, version, first_seen, last_seen from instance_bundles where 1=1${where}`, ...args);
  for (const b of bundleRows) {
    pkgRows.push({ instance_id: b.instance_id, version_purl: null, id: packageId("binary", b.name, b.version), name: b.name, version: b.version, ecosystem: "binary", source_name: null, source_kind: "process_versions", advisory_ecosystem: null, scope: "library", arch: null, path: null, first_seen: b.first_seen, last_seen: b.last_seen, ...componentIdentity({ ecosystem: "binary", name: b.name, version: b.version }), ...componentCpe({ ecosystem: "binary", name: b.name, version: b.version }) });
  }
  const versionedPaths = new Set<string>(); // what the software probe read a version from, by path: a running executable there is identified already
  for (const b of rows(`select instance_id, name, version, path, first_seen, last_seen, gone from instance_binaries where 1=1${where}`, ...args)) {
    if (b.path) versionedPaths.add(`${b.instance_id}\t${b.path}`);
    pkgRows.push({ instance_id: b.instance_id, version_purl: null, id: packageId("binary", b.name, b.version), name: b.name, version: b.version, ecosystem: "binary", source_name: null, source_kind: "binary_version", advisory_ecosystem: null, scope: packageScope(b.name).scope, arch: null, path: b.path ?? null, first_seen: b.first_seen, last_seen: b.last_seen, ...componentIdentity({ ecosystem: "binary", name: b.name, version: b.version }), ...componentCpe({ ecosystem: "binary", name: b.name, version: b.version }) });
  }
  for (const o of os.values()) {
    if (o.kernel) pkgRows.push(kernelComponent(o));
    if (o.os_id) pkgRows.push({ instance_id: o.instance_id, version_purl: null, id: packageId("os", o.os_id, o.os_version ?? "unknown"), name: o.os_name ?? o.os_id, version: o.os_version ?? "unknown", ecosystem: "os", source_name: o.os_id, source_kind: "os_release", advisory_ecosystem: ecosystemOf(o.package_manager, o.os_id, o.os_version)?.ecosystem ?? null, scope: "tool", arch: o.arch ?? null, path: null, first_seen: o.collected_at, last_seen: o.collected_at, ...componentIdentity({ ecosystem: "os", name: o.os_name ?? o.os_id, version: o.os_version ?? "unknown", source: o.os_id }), ...componentCpe({ ecosystem: "os", name: o.os_name ?? o.os_id, version: o.os_version ?? "unknown", source: o.os_id, declared: o.os_cpe ?? null }) });
  }
  // the sbom probe: a purl on the filesystem is INSTALLED_ON the box like any package; a purl inside an image is CONTAINS from the image node, the
  // image's contents being kept once per image (image_sbom, keyed by digest and platform; the scanner instance or a box read it) and reaching the
  // graph through every box that runs the image (its instance_images row; the first box stamps the account). Two platforms of one multi-arch digest
  // are two keys on one image node (imageNodeId is platform-less, as RUNS_IMAGE and BUILT_FROM are): the node's CONTAINS set is their union, each
  // edge saying which platform it was read on.
  // The purl's own type is the ecosystem (npm, pypi, golang, deb, ...); a distro purl carries the image's distribution (namespace, distro qualifier)
  // and its source package (upstream), so its identity and advisory ecosystem are those of that distribution, not the host's
  // A program both collectors saw on a box (syft's pkg:generic/node and the probe's node, the same id through sbomEcosystem) is one row: the probe's,
  // which knows the path; the syft row would only rewrite the same node and edge with less
  const probed = new Set(pkgRows.filter((p) => p.ecosystem === "binary").map((p) => `${p.instance_id}\t${p.id}`));
  const containsRows: any[] = [];
  // a container process (2026-11-03) is placed on the container's image and the container (sbomGraphRow placeProcess): the container's node and image
  // from the docker probe's rows, the image node from the box's instance_images row (imageNodeResolver, the node BUILT_FROM and RUNS_IMAGE share).
  // The proc rows are read fleet-wide: a proc CONTAINS edge on an image node may come from any box that runs the image, so the keep list that
  // retires an image's proc edges must be the union over every box, not only the boxes this sync writes
  const scope = instanceIds ? new Set(instanceIds) : null;
  const imageNodeOf = imageNodeResolver(rows("select instance_id, image, image_id, digest from instance_images where gone = 0"));
  const containers = new Map<string, { node: string; image: string | null; image_id: string | null; mounts: string | null }>(); // `${instance}\t${12-hex}` → the container
  const containersOfBox = new Map<string, { node: string; image_node: string | null }[]>(); // every container of a box, gone or not: a container with nothing readable retires its edges, and its image's proc edges are re-judged
  for (const c of rows("select instance_id, name, container_id, image, image_id, mounts from instance_containers")) {
    const node = `container:${c.instance_id}:${c.name}`;
    containersOfBox.set(c.instance_id, [...(containersOfBox.get(c.instance_id) ?? []), { node, image_node: imageNodeOf(c.instance_id, c.image ?? null, c.image_id ?? null)?.image_id ?? null }]);
    if (c.container_id) containers.set(`${c.instance_id}\t${String(c.container_id).slice(0, 12)}`, { node, image: c.image ?? null, image_id: c.image_id ?? null, mounts: c.mounts ?? null });
  }
  const contextOf = (instanceId: string, ref: string, imageIdSeen: string | null, path: string | null): ContainerContext => {
    const m = /^container:([0-9a-f]{12}):/.exec(ref); if (!m) return {};
    const c = containers.get(`${instanceId}\t${m[1]}`);
    const image = imageNodeOf(instanceId, c?.image ?? null, c?.image_id ?? imageIdSeen);
    return { container_node: c?.node ?? null, container_image: image, on_mount: c ? onMount(path, c.mounts) : false };
  };
  const executesRows: ExecutesRow[] = [];
  const procKeep = new Map<string, Set<string>>(); // image node → the proc-sourced package ids any box's processes put on it (the keep list of its proc CONTAINS edges)
  const procTouched = new Set<string>(); // image nodes a box in scope wrote proc edges to
  const place = (g: SbomGraphRow, instanceId: string) => {
    if (g.edge === "contains") { const nid = String(g.row.image_id); if (!procKeep.has(nid)) procKeep.set(nid, new Set()); procKeep.get(nid)!.add(String(g.row.id)); if (!scope || scope.has(instanceId)) procTouched.add(nid); }
    if (scope && !scope.has(instanceId)) return;
    (g.edge === "installed_on" ? pkgRows : containsRows).push(g.row);
    if (g.executes) executesRows.push(g.executes);
  };
  for (const r of rows(`select p.instance_id, p.source, p.ref, p.purl, p.name, p.version, p.cpes, p.first_seen, p.last_seen, null as digest, null as image_id, null as platform, s.image_id as image_id_seen, s.sha256, s.size from instance_sbom p left join instance_sbom_sources s on s.instance_id = p.instance_id and s.source = p.source and s.ref = p.ref where p.source in ('dir', 'proc')`)) {
    if (r.source === "dir" && scope && !scope.has(r.instance_id)) continue;
    const path = /^(?:host|container:[0-9a-f]{12}):(\/.*)$/.exec(String(r.ref))?.[1] ?? null;
    const g = sbomGraphRow({ ...r, ...(r.source === "proc" ? contextOf(r.instance_id, String(r.ref), r.image_id_seen ?? null, path) : {}) }); if (!g) continue;
    if (g.edge === "installed_on" && g.row.ecosystem === "binary" && !g.row.container && probed.has(`${g.row.instance_id}\t${g.row.id}`)) continue; // a container's own copy keeps its row: the edge says which container
    place(g, r.instance_id);
  }
  // running executables nothing identified (sbom 1.7): kept as unclassified components, except a host program a package owns or the software probe versioned at that path (those are identified)
  for (const s of rows("select s.instance_id, s.ref, s.container, s.image_id, s.sha256, s.size, s.package, s.collected_at from instance_sbom_sources s where s.source = 'proc' and s.status = 'ok' and s.listed = 0")) {
    const path = /^(?:host|container:[0-9a-f]{12}):(\/.*)$/.exec(String(s.ref))?.[1] ?? null;
    const g = unclassifiedGraphRow({ ...s, ...contextOf(s.instance_id, String(s.ref), s.image_id ?? null, path) }); if (!g) continue;
    if (g.edge === "installed_on" && !g.row.container && (s.package || versionedPaths.has(`${s.instance_id}\t${path}`))) continue;
    place(g, s.instance_id);
  }
  const containsSeen = new Set<string>();
  for (const r of rows(`select ii.instance_id, 'image' as source, ii.image as ref, p.purl, p.name, p.version, p.cpes, p.first_seen, p.last_seen, coalesce(s.digest, ii.digest) as digest, coalesce(s.image_id, ii.image_id) as image_id, coalesce(s.platform, ii.platform) as platform
    from image_sbom p join image_sbom_scans s on s.key = p.key join instance_images ii on ${IMG_KEY} = p.key where ii.gone = 0${where.replace(" instance_id in", " ii.instance_id in")} order by ii.instance_id`, ...args)) {
    const g = sbomGraphRow(r); if (!g || g.edge !== "contains") continue;
    const k = `${g.row.image_id}\t${g.row.id}`; if (containsSeen.has(k)) continue; containsSeen.add(k);
    containsRows.push(g.row);
  }
  const osRows = [...os.values()].map((o) => ({ instance_id: o.instance_id, os: [o.os_name ?? o.os_id, o.os_version].filter(Boolean).join(" ") || null, os_id: o.os_id ?? null, os_version: o.os_version ?? null, kernel: o.kernel ?? null, kernel_upstream: o.kernel_upstream ?? null, kernel_package: o.kernel_package ?? null, kernel_package_version: o.kernel_package_version ?? null, os_cpe: o.os_cpe ?? null, arch: o.arch ?? null, package_manager: o.package_manager ?? null, collected_at: o.collected_at ?? null }));
  for (const b of chunks(osRows)) await w(OS_CYPHER, b);
  for (const b of chunks(pkgRows)) await w(PACKAGE_CYPHER, b);

  // the container images the box runs
  const imgRows = rows(`select instance_id, image, image_id, digest, created, platform, first_seen, last_seen, gone from instance_images where 1=1${where}`, ...args).map((i) => {
    const image = String(i.image);
    return { instance_id: i.instance_id, ...imageRef(image), id: imageNodeId(image, i.digest, i.image_id), image, digest: i.digest ?? null, created: i.created ?? null, platform: i.platform ?? null, image_id: i.image_id ?? null, first_seen: i.first_seen, last_seen: i.last_seen };
  });
  for (const b of chunks(imgRows)) await w(IMAGE_CYPHER, b);
  // only the boxes the software probe has read (an instance_os row): what they no longer have loses its edge
  const keepOf = (items: { instance_id: string; id: string }[], boxes: Iterable<string> = os.keys()) => {
    const by = new Map<string, string[]>([...boxes].map((id) => [id, []]));
    for (const x of items) by.get(x.instance_id)?.push(x.id);
    return [...by].map(([instance_id, keep]) => ({ instance_id, keep }));
  };
  for (const b of chunks(keepOf(pkgRows), 50)) await w(PRUNE_PACKAGES_CYPHER, b);

  // containment: the runtime that bundles a library, the package that depends on another — edges between version nodes
  const byInstanceName = new Map<string, string>(); // `${instance}\t${ecosystem}\t${name}` → node id
  for (const p of pkgRows) byInstanceName.set(`${p.instance_id}\t${p.ecosystem}\t${p.name}`, p.id);
  const bundles: any[] = [];
  for (const b of bundleRows) {
    const parent_id = packageId("binary", b.parent, b.parent_version); // one box may hold several Nodes: the parent is the install of that version
    bundles.push({ parent_id, child_id: packageId("binary", b.name, b.version) }); // the library is a binary component like the runtime: node's openssl 3.0.22 and the system's are one version node, reached by BUNDLES or INSTALLED_ON
  }
  const depends: any[] = [];
  for (const d of rows(`select instance_id, name, dep from instance_depends where 1=1${where}`, ...args)) {
    const eco = os.get(d.instance_id)?.package_manager; if (!eco) continue;
    const from_id = byInstanceName.get(`${d.instance_id}\t${eco}\t${d.name}`); const to_id = byInstanceName.get(`${d.instance_id}\t${eco}\t${d.dep}`);
    if (from_id && to_id && from_id !== to_id) depends.push({ from_id, to_id, source_kind: SOURCE_KIND[eco] ?? eco });
  }
  const uniq = (list: any[], key: (r: any) => string) => { const s = new Set<string>(); return list.filter((r) => { const k = key(r); if (s.has(k)) return false; s.add(k); return true; }); };
  const bundleEdges = uniq(bundles, (r) => `${r.parent_id}\t${r.child_id}`); const dependEdges = uniq(depends, (r) => `${r.from_id}\t${r.to_id}`);
  for (const b of chunks(bundleEdges)) await w(BUNDLES_CYPHER, b);
  for (const b of chunks(dependEdges)) await w(DEPENDS_ON_CYPHER, b);
  // the running kernel to the package that owns its boot image (the package row of the same probe, so the versions agree)
  const packaged: any[] = [];
  for (const o of os.values()) {
    if (!o.kernel || !o.kernel_package || !o.package_manager) continue;
    const package_id = byInstanceName.get(`${o.instance_id}\t${o.package_manager}\t${o.kernel_package}`); if (!package_id) continue;
    packaged.push({ kernel_id: kernelComponent(o).id, package_id, source_kind: SOURCE_KIND[o.package_manager] ?? o.package_manager });
  }
  const packagedEdges = uniq(packaged, (r) => `${r.kernel_id}\t${r.package_id}`);
  for (const b of chunks(packagedEdges)) await w(PACKAGED_AS_CYPHER, b);
  // the image edges are pruned on the probed boxes and on the cluster nodes (their rows are the cluster inventory's, probed or not)
  const clusterNodes = rows(`select distinct instance_id from instance_images where source = 'cluster'${where}`, ...args).map((r) => String(r.instance_id));
  for (const b of chunks(keepOf(imgRows, new Set([...os.keys(), ...clusterNodes])), 50)) await w(PRUNE_IMAGES_CYPHER, b);
  // what each image contains; an edge the scans no longer support is retired (the keep list is every key's reading of that image node: the platforms of one digest add up)
  for (const b of chunks(containsRows)) await w(CONTAINS_CYPHER, b);
  const keepBy = new Map<string, Set<string>>();
  for (const r of rows(`select ii.image as ref, p.purl, p.name, p.version, coalesce(s.digest, ii.digest) as digest, coalesce(s.image_id, ii.image_id) as image_id from image_sbom p join image_sbom_scans s on s.key = p.key join instance_images ii on ${IMG_KEY} = p.key where ii.gone = 0`)) {
    const p = parsePurl(String(r.purl)); if (!p) continue;
    const nid = imageNodeId(String(r.ref), r.digest, r.image_id);
    if (!keepBy.has(nid)) keepBy.set(nid, new Set());
    keepBy.get(nid)!.add(packageId(sbomEcosystem(p.type), String(r.name), String(r.version || p.version || "unknown")));
  }
  const inScope = new Set(containsRows.filter((r) => r.edge_source_kind !== "proc").map((r) => String(r.image_id)));
  const keepContains = [...keepBy].filter(([nid]) => inScope.has(nid)).map(([image_id, keep]) => ({ image_id, keep: [...keep], source_kind: "image_scan" }));
  for (const b of chunks(keepContains, 50)) await w(PRUNE_CONTAINS_CYPHER, b);
  // the proc edges of every image a box in scope touched, or runs a container of (a process that stopped leaves no row, so the image must be re-judged
  // even when the box wrote nothing to it this time): retired when no box's processes put them there any more (the fleet-wide keep list)
  for (const box of os.keys()) for (const c of containersOfBox.get(box) ?? []) if (c.image_node) procTouched.add(c.image_node);
  const keepProc = [...procTouched].map((image_id) => ({ image_id, keep: [...(procKeep.get(image_id) ?? [])], source_kind: "proc" }));
  for (const b of chunks(keepProc, 50)) await w(PRUNE_CONTAINS_CYPHER, b);
  // what each container runs; every container of the probed boxes gets its keep list, an empty one retiring all its edges (nothing readable this pass, or gone)
  const execEdges = uniq(executesRows, (r) => `${r.container_node}\t${r.id}`);
  for (const b of chunks(execEdges)) await w(EXECUTES_CYPHER, b);
  const execKeep = new Map<string, Set<string>>();
  for (const box of os.keys()) for (const c of containersOfBox.get(box) ?? []) execKeep.set(c.node, new Set());
  for (const e of execEdges) { if (!execKeep.has(e.container_node)) execKeep.set(e.container_node, new Set()); execKeep.get(e.container_node)!.add(e.id); }
  for (const b of chunks([...execKeep].map(([container_node, keep]) => ({ container_node, keep: [...keep] })), 50)) await w(PRUNE_EXECUTES_CYPHER, b);

  // the program a package ships, where that program is seen running (AdvisorApp nodes are keyed by name)
  const apps = new Set(rows(`select distinct name from instance_apps where gone = 0${where}`, ...args).map((a) => String(a.name)));
  const provides: any[] = [];
  for (const p of pkgRows) { if (p.ecosystem === "os" || p.ecosystem === "kernel") continue; for (const proc of packageScope(p.source_name ?? p.name).processes) if (apps.has(proc)) provides.push({ package_id: p.id, app: proc }); }
  const seenProv = new Set<string>(); const provRows = provides.filter((r) => { const k = `${r.package_id}\t${r.app}`; if (seenProv.has(k)) return false; seenProv.add(k); return true; });
  for (const b of chunks(provRows)) await w(PROVIDES_CYPHER, b);

  // the upgrades: old version to new, from the inventory's change log (nodes nobody has any more are kept: they are the history,
  // and what the match attached to them stays attached)
  const superseded = new Map<string, any>();
  for (const ch of rows(`select instance_id, ecosystem, name, from_version, to_version, at from package_changes where from_version is not null and to_version is not null and from_version <> to_version${where} order by id`, ...args)) {
    const from_id = packageId(ch.ecosystem, ch.name, ch.from_version); const to_id = packageId(ch.ecosystem, ch.name, ch.to_version);
    const k = `${from_id}\t${to_id}`; const cur = superseded.get(k);
    if (cur) { cur.at = ch.at > cur.at ? ch.at : cur.at; cur.first_at = ch.at < cur.first_at ? ch.at : cur.first_at; cur.boxSet.add(ch.instance_id); }
    else superseded.set(k, { from_id, to_id, at: ch.at, first_at: ch.at, boxSet: new Set([ch.instance_id]) });
  }
  const supersededRows = [...superseded.values()].map(({ boxSet, ...r }) => ({ ...r, boxes: boxSet.size }));
  for (const b of chunks(supersededRows)) await w(SUPERSEDED_BY_CYPHER, b);
  // the advisor's own vulnerability nodes (KnVulnerability, with their AFFECTS and VULNERABLE_TO edges) are not written since 2026-10-29: what an older advisor left goes on every sync, wipe or not
  await writeCypher("MATCH (n:KnVulnerability) DETACH DELETE n");
  // the nodes' own lifecycle, from the edges': what came back is live again, what nothing holds any more is marked (never deleted)
  await writeCypher(REVIVE_COMPONENTS_CYPHER);
  await writeCypher(ORPHAN_COMPONENTS_CYPHER, neoParams({ now }));
  return { packages: new Set(pkgRows.map((p) => p.id)).size, installed: pkgRows.length, images: imgRows.length, contains: containsRows.length, executes: execEdges.length, provides: provRows.length, bundles: bundleEdges.length, depends: dependEdges.length, packaged_as: packagedEdges.length, superseded: supersededRows.length, took_ms: Date.now() - t0 };
}


export const mirrorSoftwareInBackground = (instanceIds?: string[]) => inBackground(`software mirror${instanceIds ? ` (${instanceIds.join(", ")})` : ""}`, () => mirrorSoftware(instanceIds));

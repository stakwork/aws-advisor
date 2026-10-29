import { db } from "./db.js";
import { accountId, enabled, inBackground, neoParams, writeCypher } from "./graph_mirror.js";
import { resourceAccountIndex } from "./resource_index.js";
import { ecosystemOf, packageScope } from "./package_scope.js";
import { AWS } from "./adapters/types.js";
import { COMPUTE_OF } from "./graph_cypher.js";
import { DISTRO_ECOSYSTEMS, componentIdentity } from "./sec/identity.js";
import { parsePurl } from "./software_inventory.js";

/**
 * The software layer of the graph (docs/cloud-ontology.md §2) for the AWS adapter: what the software probe found
 * installed on each box (src/software_inventory.ts) as AdvisorPackage nodes shared across the fleet, one per
 * (ecosystem, name, version), INSTALLED_ON the operating system (AdvisorCompute) the box HOSTS, which also takes the
 * distribution, version and kernel; the OS and the kernel as packages of their
 * own ecosystems; the versions read from well-known binaries as packages of the `binary` ecosystem; the container
 * images the box runs (RUNS_IMAGE → AdvisorImage, the same nodes cluster workloads are BUILT_FROM), what syft read
 * inside each image (the sbom probe: CONTAINS from the image to AdvisorPackage nodes of the purl's own ecosystem, npm,
 * pypi, deb of the image's distribution, ...) and on the filesystem (INSTALLED_ON like any package); PROVIDES edges
 * from a package to the program (AdvisorApp) it ships, so "which package is this listening process from" is one hop.
 *
 * Every package carries the identity the public vulnerability graph is walked with (src/sec/identity.ts): `purl` (the
 * component, no version), `source_purl` (the source package a distribution's advisories name) and `sort_key` (the
 * version as a sortable string). Containment is edges between package nodes, the same two whatever the mechanism:
 * BUNDLES (a runtime to the libraries compiled into it, from Node's process.versions; the library is an AdvisorPackage
 * of ecosystem `bundled`) and DEPENDS_ON (a package to the installed packages its dpkg Depends names). A CVE in brotli
 * then reaches a box as (compute)<-[:INSTALLED_ON]-(node)-[:BUNDLES]->(brotli), with no lookup. The match itself is a
 * strut workflow against the public graph; nothing here decides vulnerability from these.
 *
 * The vulnerability knowledge and the verdicts are not written here: the strut workflows match these nodes against the
 * public vulnerability graph (docs/vulnerability-graph-plan.md) and write their own. The advisor's own OSV/ALAS matcher
 * and its KnVulnerability, AFFECTS and VULNERABLE_TO writes were removed on 2026-10-29. Rebuilt per box after its probes.
 */

export const SOFTWARE_LABELS = ["AdvisorPackage", "AdvisorImage"] as const;

const PACKAGE_CYPHER = `
UNWIND $rows AS row
MATCH (b:AdvisorResource {id: row.instance_id})
${COMPUTE_OF("b", "c")}
MERGE (p:AdvisorPackage {id: row.id}) ON CREATE SET p.first_seen = $now
SET p += {name: row.name, version: row.version, ecosystem: row.ecosystem, source_name: row.source_name, source_kind: row.source_kind, advisory_ecosystem: row.advisory_ecosystem, scope: row.scope, purl: row.purl, source_purl: row.source_purl, sort_key: row.sort_key, native_type: 'package', provider: $provider, account_id: coalesce(row.account_id, $account), updated_at: $now}
MERGE (p)-[r:INSTALLED_ON]->(c)
SET r += {arch: row.arch, path: row.path, first_seen: row.first_seen, last_seen: row.last_seen, gone: row.gone, updated_at: $now}`;

const IMAGE_CYPHER = `
UNWIND $rows AS row
MATCH (b:AdvisorResource {id: row.instance_id})
${COMPUTE_OF("b", "c")}
MERGE (i:AdvisorResource {id: row.id}) ON CREATE SET i.first_seen = $now
SET i:AdvisorImage, i += {name: row.image, kind: 'container', repository: row.repository, tag: row.tag, digest: row.digest, created_at: row.created, platform: row.platform, native_type: 'container_image', native_id: row.image, provider: $provider, account_id: coalesce(row.account_id, $account), updated_at: $now}
MERGE (c)-[r:RUNS_IMAGE]->(i)
SET r += {image_id: row.image_id, first_seen: row.first_seen, last_seen: row.last_seen, gone: row.gone, updated_at: $now}`;

/** What syft read inside a running image: the image node (merged, so an image the software probe has not listed yet still
 *  gets its contents), the package node of the purl's ecosystem, and CONTAINS between them. */
const CONTAINS_CYPHER = `
UNWIND $rows AS row
MERGE (i:AdvisorResource {id: row.image_id}) ON CREATE SET i.first_seen = $now, i.name = row.image, i.kind = 'container', i.repository = row.repository, i.tag = row.tag, i.native_type = 'container_image', i.native_id = row.image, i.provider = $provider, i.account_id = coalesce(row.account_id, $account)
SET i:AdvisorImage
MERGE (p:AdvisorPackage {id: row.id}) ON CREATE SET p.first_seen = $now
SET p += {name: row.name, version: row.version, ecosystem: row.ecosystem, source_name: row.source_name, source_kind: row.source_kind, advisory_ecosystem: row.advisory_ecosystem, scope: row.scope, purl: row.purl, source_purl: row.source_purl, sort_key: row.sort_key, version_purl: row.version_purl, native_type: 'package', provider: $provider, account_id: coalesce(row.account_id, $account), updated_at: $now}
MERGE (i)-[r:CONTAINS]->(p)
SET r += {first_seen: row.first_seen, last_seen: row.last_seen, updated_at: $now}`;

const PRUNE_CONTAINS_CYPHER = `
UNWIND $rows AS row
MATCH (i:AdvisorImage {id: row.image_id})-[r:CONTAINS]->(p:AdvisorPackage)
WHERE NOT p.id IN row.keep
DELETE r`;

/** What the probe read of the operating system (/etc/os-release, uname) onto the compute the box hosts. */
const OS_CYPHER = `
UNWIND $rows AS row
MATCH (b:AdvisorResource {id: row.instance_id})
${COMPUTE_OF("b", "c")}
SET c += {os: row.os, os_id: row.os_id, os_version: row.os_version, kernel: row.kernel, arch: coalesce(row.arch, c.arch), package_manager: row.package_manager, os_collected_at: row.collected_at, updated_at: $now}`;

/** A box's package and image edges the probe no longer reports (an older version, something removed): the node id is
 *  per version, so an upgrade adds an edge and only this takes the superseded one away. */
const PRUNE_PACKAGES_CYPHER = `
UNWIND $rows AS row
MATCH (p:AdvisorPackage)-[r:INSTALLED_ON]->(c:AdvisorCompute {id: 'compute:' + row.instance_id})
WHERE NOT p.id IN row.keep
DELETE r`;

const PRUNE_IMAGES_CYPHER = `
UNWIND $rows AS row
MATCH (c:AdvisorCompute {id: 'compute:' + row.instance_id})-[r:RUNS_IMAGE]->(i:AdvisorImage)
WHERE NOT i.id IN row.keep
DELETE r`;

/** A runtime to a library compiled into it, and a package to an installed package it depends on: both between the
 *  shared version nodes, so "node 22.12.0 bundles brotli 1.1.0" is one fact however many boxes have it. */
const BUNDLES_CYPHER = `
UNWIND $rows AS row
MATCH (a:AdvisorPackage {id: row.parent_id}) MATCH (b:AdvisorPackage {id: row.child_id})
MERGE (a)-[r:BUNDLES]->(b) SET r += {source_kind: 'process_versions', updated_at: $now}`;

const DEPENDS_ON_CYPHER = `
UNWIND $rows AS row
MATCH (a:AdvisorPackage {id: row.from_id}) MATCH (b:AdvisorPackage {id: row.to_id})
MERGE (a)-[r:DEPENDS_ON]->(b) SET r += {source_kind: row.source_kind, updated_at: $now}`;

const PROVIDES_CYPHER = `
UNWIND $rows AS row
MATCH (p:AdvisorPackage {id: row.package_id}) MATCH (a:AdvisorApp {id: row.app})
MERGE (p)-[r:PROVIDES]->(a) SET r.updated_at = $now`;

const chunks = <T,>(items: T[], size = 250): T[][] => { const out: T[][] = []; for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size)); return out; };
const rows = (sql: string, ...params: unknown[]): any[] => { try { return db.prepare(sql).all(...params) as any[]; } catch { return []; } };
const SOURCE_KIND: Record<string, string> = { deb: "dpkg", rpm: "rpm", apk: "apk", bundled: "process_versions" };
export const packageId = (ecosystem: string, name: string, version: string) => `pkg:${ecosystem}:${name}:${version}`;

/** An image reference's node id, repository and tag (latest when none is named; none when pinned by digest). */
export function imageRef(image: string): { id: string; repository: string; tag: string | null } {
  const noDigest = image.split("@")[0]; const idx = noDigest.lastIndexOf(":"); const hasTag = idx > noDigest.lastIndexOf("/");
  return { id: `image:${image}`, repository: hasTag ? noDigest.slice(0, idx) : noDigest, tag: image.includes("@") ? null : hasTag ? noDigest.slice(idx + 1) : "latest" };
}

export interface SoftwareGraphCounts { packages: number; installed: number; images: number; contains: number; provides: number; bundles: number; depends: number; took_ms: number }

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
  const os = new Map<string, any>(); for (const o of rows(`select * from instance_os where 1=1${where}`, ...args)) os.set(o.instance_id, o);

  // packages: one node per (ecosystem, name, version), the box's edge carries its own dates
  const pkgRows: any[] = [];
  for (const p of rows(`select instance_id, ecosystem, name, version, arch, source, first_seen, last_seen, gone from instance_packages where 1=1${where}`, ...args)) {
    const o = os.get(p.instance_id); const eco = o ? ecosystemOf(o.package_manager, o.os_id, o.os_version) : null;
    pkgRows.push({ instance_id: p.instance_id, id: packageId(p.ecosystem, p.name, p.version), name: p.name, version: p.version, ecosystem: p.ecosystem, source_name: p.source ?? null, source_kind: SOURCE_KIND[p.ecosystem] ?? p.ecosystem, advisory_ecosystem: eco?.ecosystem ?? null, scope: packageScope(p.source ?? p.name).scope, arch: p.arch ?? null, path: null, first_seen: p.first_seen, last_seen: p.last_seen, gone: Boolean(p.gone), ...componentIdentity({ ecosystem: p.ecosystem, name: p.name, version: p.version, source: p.source ?? null, os_id: o?.os_id ?? null }) });
  }
  // what the runtimes bundle (probe software/4): the library is a package of its own, installed on the box through the runtime
  const bundleRows = rows(`select instance_id, parent, parent_version, name, version, first_seen, last_seen from instance_bundles where 1=1${where}`, ...args);
  for (const b of bundleRows) {
    pkgRows.push({ instance_id: b.instance_id, id: packageId("bundled", b.name, b.version), name: b.name, version: b.version, ecosystem: "bundled", source_name: null, source_kind: "process_versions", advisory_ecosystem: null, scope: "library", arch: null, path: null, first_seen: b.first_seen, last_seen: b.last_seen, gone: false, ...componentIdentity({ ecosystem: "bundled", name: b.name, version: b.version }) });
  }
  for (const b of rows(`select instance_id, name, version, path, first_seen, last_seen, gone from instance_binaries where 1=1${where}`, ...args)) {
    pkgRows.push({ instance_id: b.instance_id, id: packageId("binary", b.name, b.version), name: b.name, version: b.version, ecosystem: "binary", source_name: null, source_kind: "binary_version", advisory_ecosystem: null, scope: packageScope(b.name).scope, arch: null, path: b.path ?? null, first_seen: b.first_seen, last_seen: b.last_seen, gone: Boolean(b.gone), ...componentIdentity({ ecosystem: "binary", name: b.name, version: b.version }) });
  }
  for (const o of os.values()) {
    if (o.kernel) pkgRows.push({ instance_id: o.instance_id, id: packageId("kernel", "linux", o.kernel), name: "linux", version: o.kernel, ecosystem: "kernel", source_name: null, source_kind: "uname", advisory_ecosystem: null, scope: "kernel", arch: o.arch ?? null, path: null, first_seen: o.collected_at, last_seen: o.collected_at, gone: false, ...componentIdentity({ ecosystem: "kernel", name: "linux", version: o.kernel }) });
    if (o.os_id) pkgRows.push({ instance_id: o.instance_id, id: packageId("os", o.os_id, o.os_version ?? "unknown"), name: o.os_name ?? o.os_id, version: o.os_version ?? "unknown", ecosystem: "os", source_name: o.os_id, source_kind: "os_release", advisory_ecosystem: ecosystemOf(o.package_manager, o.os_id, o.os_version)?.ecosystem ?? null, scope: "tool", arch: o.arch ?? null, path: null, first_seen: o.collected_at, last_seen: o.collected_at, gone: false, ...componentIdentity({ ecosystem: "os", name: o.os_name ?? o.os_id, version: o.os_version ?? "unknown", source: o.os_id }) });
  }
  // the sbom probe: a purl inside an image is CONTAINS from the image node; one on the filesystem is INSTALLED_ON the box like any package.
  // The purl's own type is the ecosystem (npm, pypi, golang, deb, ...); a distro purl carries the image's distribution (namespace, distro qualifier)
  // and its source package (upstream), so its identity and advisory ecosystem are those of that distribution, not the host's
  const containsRows: any[] = [];
  for (const r of rows(`select instance_id, source, ref, purl, type, namespace, name, version, first_seen, last_seen from instance_sbom where 1=1${where}`, ...args)) {
    const p = parsePurl(String(r.purl)); if (!p) continue;
    const version = String(r.version || p.version || "unknown");
    const upstream = p.qualifiers.upstream ? p.qualifiers.upstream.split("@")[0] || null : null;
    const distro = /^(.+?)-([0-9][^-]*)$/.exec(p.qualifiers.distro ?? "");
    const distroId = DISTRO_ECOSYSTEMS.has(p.type) ? (distro?.[1] ?? p.namespace ?? null) : null;
    const advisory = distroId ? ecosystemOf(p.type, distroId, distro?.[2] ?? null)?.ecosystem ?? null : null;
    const node = { id: packageId(p.type, String(r.name), version), name: String(r.name), version, ecosystem: p.type, source_name: upstream, source_kind: "syft", advisory_ecosystem: advisory, scope: "library", version_purl: String(r.purl),
      ...componentIdentity({ ecosystem: p.type, name: String(r.name), version, source: upstream, os_id: distroId }) };
    if (r.source === "dir") pkgRows.push({ instance_id: r.instance_id, ...node, arch: p.qualifiers.arch ?? null, path: null, first_seen: r.first_seen, last_seen: r.last_seen, gone: false });
    else containsRows.push({ instance_id: r.instance_id, ...node, ...imageRef(String(r.ref)), image_id: imageRef(String(r.ref)).id, image: String(r.ref), first_seen: r.first_seen, last_seen: r.last_seen });
  }
  const osRows = [...os.values()].map((o) => ({ instance_id: o.instance_id, os: [o.os_name ?? o.os_id, o.os_version].filter(Boolean).join(" ") || null, os_id: o.os_id ?? null, os_version: o.os_version ?? null, kernel: o.kernel ?? null, arch: o.arch ?? null, package_manager: o.package_manager ?? null, collected_at: o.collected_at ?? null }));
  for (const b of chunks(osRows)) await w(OS_CYPHER, b);
  for (const b of chunks(pkgRows)) await w(PACKAGE_CYPHER, b);

  // the container images the box runs
  const imgRows = rows(`select instance_id, image, image_id, digest, created, platform, first_seen, last_seen, gone from instance_images where 1=1${where}`, ...args).map((i) => {
    const image = String(i.image);
    return { instance_id: i.instance_id, ...imageRef(image), image, digest: i.digest ?? null, created: i.created ?? null, platform: i.platform ?? null, image_id: i.image_id ?? null, first_seen: i.first_seen, last_seen: i.last_seen, gone: Boolean(i.gone) };
  });
  for (const b of chunks(imgRows)) await w(IMAGE_CYPHER, b);
  // only the boxes the software probe has read (an instance_os row): what they no longer have loses its edge
  const keepOf = (items: { instance_id: string; id: string }[]) => {
    const by = new Map<string, string[]>([...os.keys()].map((id) => [id, []]));
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
    bundles.push({ parent_id, child_id: packageId("bundled", b.name, b.version) });
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
  for (const b of chunks(keepOf(imgRows), 50)) await w(PRUNE_IMAGES_CYPHER, b);
  // what each image contains; an edge the scans no longer support goes (the keep list is every box's reading of that image, so one trimmed list does not drop what another box still lists)
  for (const b of chunks(containsRows)) await w(CONTAINS_CYPHER, b);
  const imagesScanned = [...new Set(rows(`select ref from instance_sbom_sources where source = 'image' and status = 'ok' and instance_id in (select instance_id from instance_sbom_scans where 1=1${where})`, ...args).map((r) => String(r.ref)))];
  const keepContains = imagesScanned.map((ref) => ({ image_id: imageRef(ref).id, keep: rows("select purl, name, version from instance_sbom where source = 'image' and ref = ?", ref).map((r) => { const p = parsePurl(String(r.purl)); return p ? packageId(p.type, String(r.name), String(r.version || p.version || "unknown")) : null; }).filter(Boolean) }));
  for (const b of chunks(keepContains, 50)) await w(PRUNE_CONTAINS_CYPHER, b);

  // the program a package ships, where that program is seen running (AdvisorApp nodes are keyed by name)
  const apps = new Set(rows(`select distinct name from instance_apps where gone = 0${where}`, ...args).map((a) => String(a.name)));
  const provides: any[] = [];
  for (const p of pkgRows) { if (p.ecosystem === "os" || p.ecosystem === "kernel") continue; for (const proc of packageScope(p.source_name ?? p.name).processes) if (apps.has(proc)) provides.push({ package_id: p.id, app: proc }); }
  const seenProv = new Set<string>(); const provRows = provides.filter((r) => { const k = `${r.package_id}\t${r.app}`; if (seenProv.has(k)) return false; seenProv.add(k); return true; });
  for (const b of chunks(provRows)) await w(PROVIDES_CYPHER, b);

  // packages nobody has any more
  await writeCypher("MATCH (p:AdvisorPackage) WHERE NOT (p)--() DELETE p");
  return { packages: new Set(pkgRows.map((p) => p.id)).size, installed: pkgRows.length, images: imgRows.length, contains: containsRows.length, provides: provRows.length, bundles: bundleEdges.length, depends: dependEdges.length, took_ms: Date.now() - t0 };
}


export const mirrorSoftwareInBackground = (instanceIds?: string[]) => inBackground(`software mirror${instanceIds ? ` (${instanceIds.join(", ")})` : ""}`, () => mirrorSoftware(instanceIds));

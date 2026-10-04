import { db } from "./db.js";
import { PROVIDER, accountId, enabled, inBackground, neoParams, writeCypher } from "./graph_mirror.js";
import { ecosystemOf, packageScope, vulnerabilityMatches, type VulnMatch } from "./software_vulns.js";

/**
 * The software layer of the graph (docs/cloud-ontology.md §2) for the AWS adapter: what the software probe found
 * installed on each box (src/software_inventory.ts) as AdvisorPackage nodes shared across the fleet, one per
 * (ecosystem, name, version), INSTALLED_ON the compute that has them; the OS and the kernel as packages of their
 * own ecosystems; the versions read from well-known binaries as packages of the `binary` ecosystem; the container
 * images the box runs (RUNS_IMAGE → AdvisorImage, the same nodes cluster workloads are BUILT_FROM); PROVIDES edges
 * from a package to the program (AdvisorApp) it ships, so "which package is this listening process from" is one hop.
 *
 * On top, the knowledge: KnVulnerability nodes (general area, no account_id: an advisory is true everywhere) for the
 * advisories matched (src/software_vulns.ts, from OSV and the Amazon Linux feed), AFFECTS edges to the package
 * versions they match with the fixed version, and the VULNERABLE_TO verdict from each box to each advisory with how
 * reachable the affected program is. Rebuilt per box after its software probe and whole after each vulnerability scan.
 */

export const SOFTWARE_LABELS = ["AdvisorPackage", "AdvisorImage", "KnVulnerability"] as const;

const PACKAGE_CYPHER = `
UNWIND $rows AS row
MATCH (c:AdvisorResource {id: row.instance_id})
MERGE (p:AdvisorPackage {id: row.id}) ON CREATE SET p.first_seen = $now
SET p += {name: row.name, version: row.version, ecosystem: row.ecosystem, source_name: row.source_name, source_kind: row.source_kind, advisory_ecosystem: row.advisory_ecosystem, scope: row.scope, native_type: 'package', native_id: row.id, provider: $provider, account_id: $account, updated_at: $now}
MERGE (p)-[r:INSTALLED_ON]->(c)
SET r += {arch: row.arch, path: row.path, first_seen: row.first_seen, last_seen: row.last_seen, gone: row.gone, updated_at: $now}`;

const IMAGE_CYPHER = `
UNWIND $rows AS row
MATCH (c:AdvisorResource {id: row.instance_id})
MERGE (i:AdvisorResource {id: row.id}) ON CREATE SET i.first_seen = $now
SET i:AdvisorImage, i += {name: row.image, kind: 'container', repository: row.repository, tag: row.tag, digest: row.digest, created_at: row.created, platform: row.platform, native_type: 'container_image', native_id: row.image, provider: $provider, account_id: $account, updated_at: $now}
MERGE (c)-[r:RUNS_IMAGE]->(i)
SET r += {image_id: row.image_id, first_seen: row.first_seen, last_seen: row.last_seen, gone: row.gone, updated_at: $now}`;

const PROVIDES_CYPHER = `
UNWIND $rows AS row
MATCH (p:AdvisorPackage {id: row.package_id}) MATCH (a:AdvisorApp {id: row.app})
MERGE (p)-[r:PROVIDES]->(a) SET r.updated_at = $now`;

const VULN_CYPHER = `
UNWIND $rows AS row
MERGE (v:KnVulnerability {id: row.id}) ON CREATE SET v.first_seen = $now
SET v += {source: row.source, aliases: row.aliases, cves: row.cves, summary: row.summary, severity: row.severity, cvss: row.score, cvss_vector: row.cvss, attack_vector: row.attack_vector, severity_from: row.severity_from, cwe: row.cwe, published: row.published, modified: row.modified, url: row.url, fetched_at: row.fetched_at, native_type: 'advisory', native_id: row.id, provider: 'osv', updated_at: $now}`;

const AFFECTS_CYPHER = `
UNWIND $rows AS row
MATCH (v:KnVulnerability {id: row.vuln_id}) MATCH (p:AdvisorPackage {id: row.package_id})
MERGE (v)-[r:AFFECTS]->(p) SET r += {fixed_in: row.fixed_version, ecosystem: row.ecosystem, updated_at: $now}`;

const VERDICT_CYPHER = `
UNWIND $rows AS row
MATCH (c:AdvisorResource {id: row.instance_id}) MATCH (v:KnVulnerability {id: row.vuln_id})
MERGE (c)-[r:VULNERABLE_TO {package_id: row.package_id}]->(v)
SET r += {package: row.package, packages: row.packages, version: row.version, fixed_in: row.fixed_version, reachable: row.reachable, criticality: row.criticality, via_endpoint: row.via_endpoint, process: row.process, port: row.port, exposure: row.exposure, computed_at: $now}`;

const chunks = <T,>(items: T[], size = 250): T[][] => { const out: T[][] = []; for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size)); return out; };
const rows = (sql: string, ...params: unknown[]): any[] => { try { return db.prepare(sql).all(...params) as any[]; } catch { return []; } };
const SOURCE_KIND: Record<string, string> = { deb: "dpkg", rpm: "rpm", apk: "apk" };
export const packageId = (ecosystem: string, name: string, version: string) => `pkg:${ecosystem}:${name}:${version}`;

export interface SoftwareGraphCounts { packages: number; installed: number; images: number; provides: number; vulnerabilities: number; verdicts: number; took_ms: number }

/** Everything the software probe knows about the given boxes (or all), then the vulnerability knowledge and verdicts. */
export async function mirrorSoftware(instanceIds?: string[]): Promise<SoftwareGraphCounts | null> {
  if (!enabled()) return null;
  if (instanceIds && !instanceIds.length) return null;
  const t0 = Date.now(); const now = new Date().toISOString(); const account = accountId();
  const w = (cypher: string, batch: any[]) => writeCypher(cypher, neoParams({ rows: batch, now, provider: PROVIDER, account }));
  const where = instanceIds ? ` and instance_id in (${instanceIds.map(() => "?").join(",")})` : "";
  const args = instanceIds ?? [];
  const os = new Map<string, any>(); for (const o of rows(`select * from instance_os where 1=1${where}`, ...args)) os.set(o.instance_id, o);

  // packages: one node per (ecosystem, name, version), the box's edge carries its own dates
  const pkgRows: any[] = [];
  for (const p of rows(`select instance_id, ecosystem, name, version, arch, source, first_seen, last_seen, gone from instance_packages where 1=1${where}`, ...args)) {
    const o = os.get(p.instance_id); const eco = o ? ecosystemOf(o.package_manager, o.os_id, o.os_version) : null;
    pkgRows.push({ instance_id: p.instance_id, id: packageId(p.ecosystem, p.name, p.version), name: p.name, version: p.version, ecosystem: p.ecosystem, source_name: p.source ?? null, source_kind: SOURCE_KIND[p.ecosystem] ?? p.ecosystem, advisory_ecosystem: eco?.ecosystem ?? null, scope: packageScope(p.source ?? p.name).scope, arch: p.arch ?? null, path: null, first_seen: p.first_seen, last_seen: p.last_seen, gone: Boolean(p.gone) });
  }
  for (const b of rows(`select instance_id, name, version, path, first_seen, last_seen, gone from instance_binaries where 1=1${where}`, ...args)) {
    pkgRows.push({ instance_id: b.instance_id, id: packageId("binary", b.name, b.version), name: b.name, version: b.version, ecosystem: "binary", source_name: null, source_kind: "binary_version", advisory_ecosystem: null, scope: packageScope(b.name).scope, arch: null, path: b.path ?? null, first_seen: b.first_seen, last_seen: b.last_seen, gone: Boolean(b.gone) });
  }
  for (const o of os.values()) {
    if (o.kernel) pkgRows.push({ instance_id: o.instance_id, id: packageId("kernel", "linux", o.kernel), name: "linux", version: o.kernel, ecosystem: "kernel", source_name: null, source_kind: "uname", advisory_ecosystem: null, scope: "kernel", arch: o.arch ?? null, path: null, first_seen: o.collected_at, last_seen: o.collected_at, gone: false });
    if (o.os_id) pkgRows.push({ instance_id: o.instance_id, id: packageId("os", o.os_id, o.os_version ?? "unknown"), name: o.os_name ?? o.os_id, version: o.os_version ?? "unknown", ecosystem: "os", source_name: o.os_id, source_kind: "os_release", advisory_ecosystem: ecosystemOf(o.package_manager, o.os_id, o.os_version)?.ecosystem ?? null, scope: "tool", arch: o.arch ?? null, path: null, first_seen: o.collected_at, last_seen: o.collected_at, gone: false });
  }
  for (const b of chunks(pkgRows)) await w(PACKAGE_CYPHER, b);

  // the container images the box runs
  const imgRows = rows(`select instance_id, image, image_id, digest, created, platform, first_seen, last_seen, gone from instance_images where 1=1${where}`, ...args).map((i) => {
    const image = String(i.image); const noDigest = image.split("@")[0]; const idx = noDigest.lastIndexOf(":"); const hasTag = idx > noDigest.lastIndexOf("/");
    return { instance_id: i.instance_id, id: `image:${image}`, image, repository: hasTag ? noDigest.slice(0, idx) : noDigest, tag: image.includes("@") ? null : hasTag ? noDigest.slice(idx + 1) : "latest", digest: i.digest ?? null, created: i.created ?? null, platform: i.platform ?? null, image_id: i.image_id ?? null, first_seen: i.first_seen, last_seen: i.last_seen, gone: Boolean(i.gone) };
  });
  for (const b of chunks(imgRows)) await w(IMAGE_CYPHER, b);

  // the program a package ships, where that program is seen running (AdvisorApp nodes are keyed by name)
  const apps = new Set(rows(`select distinct name from instance_apps where gone = 0${where}`, ...args).map((a) => String(a.name)));
  const provides: any[] = [];
  for (const p of pkgRows) { if (p.ecosystem === "os" || p.ecosystem === "kernel") continue; for (const proc of packageScope(p.source_name ?? p.name).processes) if (apps.has(proc)) provides.push({ package_id: p.id, app: proc }); }
  const seenProv = new Set<string>(); const provRows = provides.filter((r) => { const k = `${r.package_id}\t${r.app}`; if (seenProv.has(k)) return false; seenProv.add(k); return true; });
  for (const b of chunks(provRows)) await w(PROVIDES_CYPHER, b);

  // vulnerabilities and verdicts
  const matches = vulnerabilityMatches(instanceIds);
  const vulnIds = [...new Set(matches.map((m) => m.vuln_id))];
  const vulnRows = vulnIds.length ? rows(`select * from vulnerabilities where id in (${vulnIds.map(() => "?").join(",")})`, ...vulnIds).map((v) => ({ id: v.id, source: v.source, aliases: JSON.parse(v.aliases || "[]"), cves: JSON.parse(v.cves || "[]"), summary: v.summary, severity: v.severity, score: v.score, cvss: v.cvss, attack_vector: v.attack_vector, severity_from: v.severity_from, cwe: v.cwe, published: v.published, modified: v.modified, fetched_at: v.fetched_at,
    url: v.source === "alas" ? JSON.parse(v.references_ || "[]")[0] ?? null : `https://osv.dev/vulnerability/${v.id}` })) : [];
  for (const b of chunks(vulnRows)) await w(VULN_CYPHER, b);
  // the AFFECTS edge goes to every binary package of the matched source on that box (the node is shared, the match is per version)
  const pm = new Map<string, string>(); for (const p of pkgRows) if (p.ecosystem !== "binary" && p.ecosystem !== "os" && p.ecosystem !== "kernel") pm.set(`${p.instance_id}\t${p.name}`, p.id);
  const affects: any[] = []; const verdicts: any[] = []; const seenAff = new Set<string>();
  for (const m of matches) {
    const ids = m.packages.map((n) => pm.get(`${m.instance_id}\t${n}`)).filter((x): x is string => Boolean(x));
    for (const id of ids) { const k = `${m.vuln_id}\t${id}`; if (!seenAff.has(k)) { seenAff.add(k); affects.push({ vuln_id: m.vuln_id, package_id: id, fixed_version: m.fixed_version, ecosystem: m.ecosystem }); } }
    verdicts.push(verdictRow(m, ids[0] ?? packageId(m.ecosystem, m.package, m.version)));
  }
  for (const b of chunks(affects)) await w(AFFECTS_CYPHER, b);
  // a rebuilt verdict replaces the old ones of the same boxes; what no longer matches disappears
  if (instanceIds) await writeCypher(`UNWIND $ids AS id MATCH (c:AdvisorResource {id: id})-[r:VULNERABLE_TO]->() DELETE r`, { ids: instanceIds });
  else await writeCypher(`MATCH (c:AdvisorResource {account_id: $account})-[r:VULNERABLE_TO]->() DELETE r`, { account });
  for (const b of chunks(verdicts)) await w(VERDICT_CYPHER, b);
  // packages nobody has any more, advisories nothing is affected by
  await writeCypher("MATCH (p:AdvisorPackage) WHERE NOT (p)--() DELETE p");
  await writeCypher("MATCH (v:KnVulnerability) WHERE NOT (v)--() DELETE v");
  return { packages: new Set(pkgRows.map((p) => p.id)).size, installed: pkgRows.length, images: imgRows.length, provides: provRows.length, vulnerabilities: vulnRows.length, verdicts: verdicts.length, took_ms: Date.now() - t0 };
}

/** One VULNERABLE_TO edge: the match with the endpoint it is reached through, when one is. */
export function verdictRow(m: VulnMatch, packageId: string) {
  return { instance_id: m.instance_id, vuln_id: m.vuln_id, package_id: packageId, package: m.package, packages: m.packages, version: m.version, fixed_version: m.fixed_version, reachable: m.reachable, criticality: m.criticality,
    via_endpoint: m.port != null ? `${m.instance_id}:${m.proto ?? "tcp"}:${m.port}` : null, process: m.process, port: m.port, exposure: m.exposure };
}

export const mirrorSoftwareInBackground = (instanceIds?: string[]) => inBackground(`software mirror${instanceIds ? ` (${instanceIds.join(", ")})` : ""}`, () => mirrorSoftware(instanceIds));

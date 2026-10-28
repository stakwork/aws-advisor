import { identify, slug } from "./purl.js";
import { sortKey } from "./version.js";

/**
 * The identity an installed thing carries into the graph so the public vulnerability graph can be matched against
 * it by walking, with no lookup: `purl` is the component without its version (the key SecComponent nodes use over
 * there; aliases between spellings are SAME_AS edges in that graph, never a table here), `source_purl` is the source
 * package a distribution's advisories name (`libbrotli1` is fixed by an advisory against `brotli`), and `sort_key` is
 * the version rewritten so plain string order equals version order — the same function the public graph's ranges
 * use for `introduced_key`/`fixed_key`. For deb and rpm versions the key is an index hint only; their own ordering
 * (epoch, tilde, revision) decides the match, in the matcher.
 *
 *   deb/rpm/apk package  → pkg:<eco>/<distro>/<name>       pkg:deb/ubuntu/libbrotli1, source pkg:deb/ubuntu/brotli
 *   probed binary        → pkg:generic/<name>              pkg:generic/node
 *   bundled library      → pkg:generic/<name>              pkg:generic/brotli (what process.versions calls it)
 *   kernel               → pkg:generic/linux
 *   operating system     → pkg:generic/<os_id>             pkg:generic/ubuntu
 *   anything else        → pkg:<eco>/<name>                pkg:npm/next, pkg:runtime/node
 */

export interface InstalledRow {
  ecosystem: string;
  name: string;
  version: string;
  /** The source package (deb/rpm/apk) or the os_id (os rows); null when it is the name itself. */
  source?: string | null;
  /** The box's distribution id from /etc/os-release, for distro packages. */
  os_id?: string | null;
}

export interface Identity {
  purl: string;
  source_purl: string;
  /** Null when the version is not one version but a line (`22.x`, as a platform reports its runtime): nothing to compare. */
  sort_key: string | null;
}

/** A version string that names a line rather than a release: `22.x`, `18.*`, `3`. */
export const isVersionLine = (v: string): boolean => /[x*]/i.test(v) || /^\d+$/.test(v.trim());

export const DISTRO_ECOSYSTEMS = new Set(["deb", "rpm", "apk"]);

/** The distribution segment of a distro package's purl: the box's os_id, else the ecosystem's usual home. */
export function distroOf(ecosystem: string, osId: string | null | undefined): string {
  return slug(osId ?? "") || ({ deb: "debian", rpm: "rpm", apk: "alpine" } as Record<string, string>)[ecosystem] || "unknown";
}

export function componentIdentity(row: InstalledRow): Identity {
  const sort_key = isVersionLine(row.version) ? null : sortKey(row.version);
  const eco = row.ecosystem.toLowerCase();
  if (DISTRO_ECOSYSTEMS.has(eco)) {
    const d = distroOf(eco, row.os_id);
    const purl = `pkg:${eco}/${d}/${slug(row.name)}`;
    return { purl, source_purl: row.source ? `pkg:${eco}/${d}/${slug(row.source)}` : purl, sort_key };
  }
  let purl: string;
  switch (eco) {
    case "kernel": purl = "pkg:generic/linux"; break;
    case "os": purl = `pkg:generic/${slug(row.source ?? row.name) || "unknown"}`; break;
    case "binary": case "bundled": case "runtime": purl = identify({ product: row.name }).purl; break;
    default: purl = `pkg:${slug(eco) || "generic"}/${slug(row.name) || "unknown"}`;
  }
  return { purl, source_purl: purl, sort_key };
}

/**
 * The CPE (NVD's Common Platform Enumeration, the 2.3 formatted string: `cpe:2.3:a:nodejs:node.js:22.12.0:*:*:*:*:*:*:*`)
 * an installed thing carries into the graph next to its purl, so a CVE whose only identity is a CPE configuration (most of
 * NVD's) can be matched against the SoftwareComponent node by vendor and product with no lookup. The purl stays the key
 * (src/sec/identity.ts, rules only); the CPE is a property, and a node may carry several candidates (`cpes`) with the one
 * best known first (`cpe`).
 *
 * Where a CPE comes from, in order of trust:
 *  - syft, for everything the sbom and images probes read: the probe prints each purl with the CPEs syft assigned
 *    (the NVD dictionary match or a binary classifier's declaration first, its own name permutations after), and the
 *    rows keep them as they came (src/software_inventory.ts, src/graph_software.ts sbomGraphRow).
 *  - the box, for the operating system: /etc/os-release names its own CPE (CPE_NAME) on Amazon Linux, Fedora, RHEL, Rocky,
 *    Alma and SUSE; the software probe reads it (software/7) and it is taken as is, rewritten to the 2.3 form when the file
 *    uses the 2.2 URI (`cpe:/o:amazon:amazon_linux:2023`).
 *  - this module, for what the software probe reads without syft (packages, probed programs, bundled libraries, the
 *    kernel, an OS without CPE_NAME): the same guesses syft makes for the same thing, so the node a program gets is the
 *    same whichever collector wrote it. A program the probe asks by name (node, openssl, nginx, ...) takes the vendor and
 *    product syft's binary classifiers declare for it (KNOWN_PRODUCTS: NVD's names, `nodejs:node.js`, `openssl:openssl`),
 *    a library a runtime bundles (process.versions) the NVD name of that library (`google:brotli`), the kernel
 *    `linux:linux_kernel`, a distribution package the syft-style permutations (its name as vendor and product, then its
 *    source package as vendor), anything else `<name>:<name>`. KNOWN_PRODUCTS is not an identity rule (the purl never
 *    reads it; docs/vulnerability-graph-plan.md §4 keeps identity rules-only): it only spells NVD's name for a product the
 *    probe already named, and a wrong entry mislabels one property, never merges two nodes.
 */

import { slug } from "./purl.js";

/** What a CPE says about an installed row: the best candidate and every candidate, best first; empty when nothing can be formed. */
export interface ComponentCpe { cpe: string | null; cpes: string[] }

/** NVD's vendor and product for the programs the software probe asks by name and the libraries Node's process.versions names:
 *  what syft's binary classifiers and the NVD dictionary assign the same things, so the probe's node and syft's agree. Several
 *  pairs where NVD itself spells one product two ways (nginx moved from `nginx:nginx` to `f5:nginx`). */
export const KNOWN_PRODUCTS: Record<string, [vendor: string, product: string][]> = {
  node: [["nodejs", "node.js"]], nodejs: [["nodejs", "node.js"]],
  python: [["python", "python"]], python3: [["python", "python"]],
  openssl: [["openssl", "openssl"]],
  nginx: [["f5", "nginx"], ["nginx", "nginx"]],
  apache2: [["apache", "http_server"]], httpd: [["apache", "http_server"]],
  sshd: [["openbsd", "openssh"]],
  docker: [["docker", "docker"]], containerd: [["linuxfoundation", "containerd"]],
  postgres: [["postgresql", "postgresql"]],
  "redis-server": [["redis", "redis"]], redis: [["redis", "redis"]],
  mysqld: [["oracle", "mysql"]], mariadbd: [["mariadb", "mariadb"]], mongod: [["mongodb", "mongodb"]],
  java: [["oracle", "openjdk"], ["oracle", "jdk"]],
  ruby: [["ruby-lang", "ruby"]], go: [["golang", "go"]], php: [["php", "php"]], perl: [["perl", "perl"]],
  caddy: [["caddyserver", "caddy"]], haproxy: [["haproxy", "haproxy"]], traefik: [["traefik", "traefik"]],
  bitcoind: [["bitcoin", "bitcoin_core"]],
  git: [["git-scm", "git"]], curl: [["haxx", "curl"]],
  // what Node bundles, as process.versions names it
  brotli: [["google", "brotli"]], zlib: [["zlib", "zlib"]], uv: [["libuv", "libuv"]], nghttp2: [["nghttp2", "nghttp2"]],
  icu: [["icu-project", "international_components_for_unicode"]], llhttp: [["llhttp", "llhttp"]], ada: [["ada-url", "ada"]],
  simdjson: [["simdjson", "simdjson"]], sqlite: [["sqlite", "sqlite"]], v8: [["google", "v8"]], ares: [["c-ares_project", "c-ares"]],
  undici: [["nodejs", "undici"]], zstd: [["facebook", "zstandard"]],
};

/** NVD's name for a distribution whose /etc/os-release carries no CPE_NAME (Ubuntu, Debian, Alpine), and a fallback for the ones that do. */
const KNOWN_OS: Record<string, [vendor: string, product: string]> = {
  ubuntu: ["canonical", "ubuntu_linux"], debian: ["debian", "debian_linux"], alpine: ["alpinelinux", "alpine_linux"],
  amzn: ["amazon", "amazon_linux"], fedora: ["fedoraproject", "fedora"], rhel: ["redhat", "enterprise_linux"], centos: ["centos", "centos"],
  rocky: ["rocky", "rocky"], almalinux: ["almalinux", "almalinux"], ol: ["oracle", "linux"], sles: ["suse", "linux_enterprise_server"], opensuse: ["opensuse", "leap"],
};

/** A value as the CPE 2.3 formatted string binds it: lowercase, whitespace to `_`, every character that is not a letter, digit, `_`, `-` or `.`
 *  escaped with a backslash (`libstdc\+\+6`, `node\.js` is not needed: the dot is plain). Empty becomes `*` (any). */
export function cpeValue(s: string | null | undefined): string {
  const v = String(s ?? "").trim().toLowerCase().replace(/\s+/g, "_");
  if (!v) return "*";
  return v.replace(/[^a-z0-9_.-]/g, (c) => `\\${c}`);
}

/** `cpe:2.3:<part>:<vendor>:<product>:<version>:*:*:*:*:*:*:*`, the full 13-field string. */
export const cpe23 = (part: "a" | "o" | "h", vendor: string, product: string, version?: string | null): string =>
  `cpe:2.3:${part}:${cpeValue(vendor)}:${cpeValue(product)}:${cpeValue(version)}:*:*:*:*:*:*:*`;

/** A CPE as a source wrote it, in the 2.3 formatted string: a 2.2 URI (`cpe:/o:amazon:amazon_linux:2023`, `cpe:/o:rocky:rocky:9::baseos`) is
 *  rewritten (part, vendor, product, version, update, edition, language; the rest `*`), a 2.3 string is kept once it parses, anything else is null. */
export function normalizeCpe(s: string | null | undefined): string | null {
  const raw = String(s ?? "").trim().replace(/^"|"$/g, "");
  if (!raw) return null;
  if (/^cpe:2\.3:[aoh](:[^:]*){10}$/i.test(raw)) return raw.toLowerCase();
  if (/^cpe:2\.3:[aoh]:/i.test(raw)) { const f = raw.toLowerCase().split(":"); while (f.length < 13) f.push("*"); return f.slice(0, 13).map((x) => x || "*").join(":"); }
  const uri = /^cpe:\/([aoh])(?::([^:]*))?(?::([^:]*))?(?::([^:]*))?(?::([^:]*))?(?::([^:]*))?(?::([^:]*))?$/i.exec(raw);
  if (!uri) return null;
  const f = [uri[2], uri[3], uri[4], uri[5], uri[6], uri[7]].map((x) => (x ? x.toLowerCase() : "*"));
  return `cpe:2.3:${uri[1]!.toLowerCase()}:${f.join(":")}:*:*:*:*`;
}

/** The vendor and product of a CPE 2.3 string (`nodejs:node.js`), for telling candidates apart; null when it does not parse. */
export const cpeKey = (cpe: string): string | null => { const f = cpe.split(":"); return f.length >= 5 && f[0] === "cpe" && f[1] === "2.3" ? `${f[2]}:${f[3]}:${f[4]}` : null; };

const uniq = (list: string[]): string[] => { const seen = new Set<string>(); return list.filter((c) => { const k = cpeKey(c) ?? c; if (seen.has(k)) return false; seen.add(k); return true; }); };

export interface CpeRow {
  ecosystem: string;
  name: string;
  version: string;
  /** The source package (deb/rpm/apk) or the os_id (os rows); null when it is the name itself. */
  source?: string | null;
  /** For os rows: the distribution's own CPE_NAME from /etc/os-release, when the probe read one. */
  declared?: string | null;
}

/** The CPE candidates of a row the software probe read (no syft): see the module comment for the rules. Pure. */
export function componentCpe(row: CpeRow): ComponentCpe {
  const eco = row.ecosystem.toLowerCase(); const name = row.name.trim().toLowerCase(); const version = row.version;
  let cpes: string[] = [];
  switch (eco) {
    case "kernel": cpes = [cpe23("o", "linux", "linux_kernel", version)]; break;
    case "os": {
      const declared = normalizeCpe(row.declared);
      const id = slug(row.source ?? name);
      const known = KNOWN_OS[id];
      cpes = [...(declared ? [declared] : []), ...(known ? [cpe23("o", known[0], known[1], version === "unknown" ? null : version)] : [])];
      break;
    }
    case "deb": case "rpm": case "apk": {
      // syft's permutations for a distro package: the name as vendor and product, then the source package as vendor
      cpes = [cpe23("a", name, name, version)];
      const src = row.source?.trim().toLowerCase();
      if (src && src !== name) cpes.push(cpe23("a", src, name, version), cpe23("a", src, src, version));
      break;
    }
    default: {
      const known = KNOWN_PRODUCTS[name];
      cpes = known ? known.map(([v, p]) => cpe23("a", v, p, version)) : [cpe23("a", name, name, version)];
    }
  }
  cpes = uniq(cpes.filter(Boolean));
  return { cpe: cpes[0] ?? null, cpes };
}

/** The CPEs a syft row carries (the probe's list, best first), typed and bounded; the rule's candidates when the row has none (an older probe). */
export function sbomCpe(stored: string | string[] | null | undefined, fallback: CpeRow): ComponentCpe {
  let list: unknown = stored;
  if (typeof stored === "string") { try { list = JSON.parse(stored); } catch { list = null; } }
  const cpes = uniq((Array.isArray(list) ? list : []).filter((c): c is string => typeof c === "string" && /^cpe:2\.3:[aoh]:/.test(c)).map((c) => normalizeCpe(c)).filter((c): c is string => Boolean(c)).slice(0, 8));
  return cpes.length ? { cpe: cpes[0]!, cpes } : componentCpe(fallback);
}

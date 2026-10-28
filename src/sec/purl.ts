// Vendored from the vuln-graph strut workspace (steps/custom/sec/_purl.ts): the rules that turn a name into a purl, the
// component identity both graphs key on. The two MUST stay identical. Edit there, copy here (sec_identity.test.ts checks).

/**
 * Component identity. A Component is a purl without a version
 * (`pkg:generic/google/brotli`); a ComponentVersion is the purl with one.
 * Every source names software differently — NVD by CPE vendor/product or by a
 * CNA's `packageName`, OSV by ecosystem + name, a probe by what a binary
 * prints — and this module turns a name into a purl by RULES ONLY. No table:
 * the same input always gives the same purl, and two spellings of one piece
 * of software give two purls that the graph joins with a SAME_AS edge
 * (`_aliases.ts` seeds the first ones; other sources add more). A false merge
 * is worse than two nodes an edge can join, so the rules keep what
 * distinguishes a name — the vendor, the repo owner — in the purl.
 *
 *   vendor + product        → pkg:generic/<vendor>/<product>     (NVD's CPE identity)
 *   repo path, no vendor    → pkg:github/<owner>/<repo>, pkg:gitlab/…, pkg:generic/<host>/<path>
 *   bare name               → pkg:generic/<name>                 (a probe's `brotli`, process.versions keys)
 */

export interface ComponentRef {
  vendor?: string | null;
  product?: string | null;
  /** A CNA's package identifier (`github.com/google/brotli`), a repo URL, an npm or Go name. */
  packageName?: string | null;
  repo?: string | null;
}

export interface ComponentIdentity {
  /** `pkg:<type>/<namespace>/<name>` with no version. The node's key. */
  purl: string;
  ecosystem: string;
  package: string;
  vendor: string | null;
  product: string | null;
  /** `cpe:2.3:a:<vendor>:<product>` when a vendor and product are known. */
  cpe: string | null;
  /** Every other name this component was seen under, for search and SAME_AS. */
  aliases: string[];
}

const cpeToken = (s: string): string => s.trim().toLowerCase().replace(/\s+/g, "_");
/** A name usable in a purl: lowercase, spaces and underscores to `-`, nothing but `[a-z0-9.+-]`. */
export const slug = (s: string): string => s.trim().toLowerCase().replace(/[\s_]+/g, "-").replace(/[^a-z0-9.+-]/g, "").replace(/-+/g, "-").replace(/^-|-$/g, "");

/** `github.com/google/brotli` → `github.com/google/brotli`; a URL → its host and path without scheme, `.git` or a trailing slash. */
export function repoPath(s: string | null | undefined): string | null {
  if (!s) return null;
  let p = s.trim().replace(/^https?:\/\//i, "").replace(/\.git$/i, "").replace(/\/+$/, "");
  p = p.replace(/^www\./i, "");
  return p.toLowerCase() || null;
}

/** Parse `cpe:2.3:a:vendor:product:version:...` (CPE 2.3 formatted string); null for anything else. */
export function parseCpe(cpe: string): { part: string; vendor: string; product: string; version: string | null } | null {
  const f = cpe.split(":");
  if (f.length < 6 || f[0] !== "cpe" || f[1] !== "2.3") return null;
  const version = f[5] && f[5] !== "*" && f[5] !== "-" ? f[5] : null;
  return { part: f[2]!, vendor: f[3]!, product: f[4]!, version };
}

/** `github.com/owner/repo` → `pkg:github/owner/repo`; another host → `pkg:generic/<host>/<path>`; null when `s` has no host. */
export function repoPurl(path: string | null): string | null {
  if (!path || !path.includes("/")) return null;
  const [host, ...rest] = path.split("/").filter(Boolean);
  if (!host || !host.includes(".") || rest.length === 0) return null;
  const tail = rest.map(slug).filter(Boolean);
  if (host === "github.com" && tail.length >= 2) return `pkg:github/${tail[0]}/${tail[1]}`;
  if (host === "gitlab.com" && tail.length >= 2) return `pkg:gitlab/${tail.join("/")}`;
  return `pkg:generic/${host}/${tail.join("/")}`;
}

/** The ecosystem and package name a purl carries (`pkg:github/google/brotli` → github, brotli). */
export function identifyPurl(purl: string): { ecosystem: string; package: string } {
  const m = /^pkg:([^/]+)\/(.+)$/.exec(purl);
  if (!m) return { ecosystem: "generic", package: slug(purl) || "unknown" };
  return { ecosystem: m[1]!, package: m[2]!.split("/").pop()!.replace(/@.*$/, "") };
}

/**
 * The component a source is talking about, by the rules above. The names
 * that did not make the purl become aliases, so a SAME_AS can be proposed
 * from them later.
 */
export function identify(ref: ComponentRef): ComponentIdentity {
  const vendor = ref.vendor ? cpeToken(ref.vendor) : null;
  const product = ref.product ? cpeToken(ref.product) : null;
  const pkg = ref.packageName?.trim() || null;
  const repo = repoPath(ref.repo);
  const cpe = vendor && product ? `cpe:2.3:a:${vendor}:${product}` : null;
  const aliases = new Set<string>();
  for (const c of [pkg, repo, product ? ref.product!.trim() : null]) if (c) aliases.add(c);
  const done = (purl: string) => {
    const id = identifyPurl(purl);
    aliases.delete(id.package);
    return { purl, ecosystem: id.ecosystem, package: id.package, vendor, product, cpe, aliases: [...aliases].sort() };
  };
  if (vendor && product) return done(`pkg:generic/${slug(vendor)}/${slug(product)}`);
  const fromRepo = [pkg?.toLowerCase(), repoPath(pkg), repo].filter((x): x is string => Boolean(x)).map(repoPurl).find(Boolean);
  if (fromRepo) return done(fromRepo);
  return done(`pkg:generic/${slug(product ?? pkg ?? "") || "unknown"}`);
}

/** The component behind a CPE 2.3 string, and the exact version it names when it does. */
export function identifyCpe(cpe: string): (ComponentIdentity & { version: string | null }) | null {
  const p = parseCpe(cpe);
  if (!p) return null;
  return { ...identify({ vendor: p.vendor, product: p.product }), version: p.version };
}

export const versionPurl = (componentPurl: string, version: string): string => `${componentPurl}@${encodeURIComponent(version)}`;

import { gunzipSync } from "node:zlib";
import { db, getSetting, setSetting } from "./db.js";

/**
 * Amazon Linux security advisories (ALAS) for the vulnerability matcher (src/software_vulns.ts). OSV does not carry
 * Amazon Linux, so the source is the one `dnf updateinfo` itself reads: the `updateinfo.xml.gz` of the core
 * repository on cdn.amazonlinux.com (public, no credentials), one per release and architecture. Each security
 * advisory names its CVEs, Amazon's severity and the exact package builds that fix it; a box is affected when it
 * has one of those packages at a lower version (rpm's own comparison, `rpmvercmp`). Only the core repository is
 * read: the AL2 "extras" topics (docker, nginx1, ...) publish their own updateinfo and are not covered yet.
 */

db.exec(`create table if not exists alas_advisories (
  id text primary key, release text not null, severity text, title text, issued text, updated text, cves text not null default '[]', fetched_at text not null
);
create table if not exists alas_packages (
  advisory_id text not null, name text not null, evr text not null, arch text not null,
  primary key (advisory_id, name, evr, arch)
);
create index if not exists alas_packages_name on alas_packages(name)`);

export type AlasRelease = "2" | "2023";
export type AlasArch = "x86_64" | "aarch64";

/** Where a release's core repository lives: the mirror list resolves to the current repository root. */
export const alasMirrorList = (release: AlasRelease, arch: AlasArch): string =>
  release === "2023" ? `https://cdn.amazonlinux.com/al2023/core/mirrors/latest/${arch}/mirror.list` : `https://cdn.amazonlinux.com/2/core/latest/${arch}/mirror.list`;

/** The release of an Amazon Linux box from its os-release VERSION_ID ("2", "2023"); null for anything else. */
export const alasRelease = (osId: string | null | undefined, osVersion: string | null | undefined): AlasRelease | null =>
  osId === "amzn" ? (String(osVersion) === "2023" ? "2023" : String(osVersion) === "2" ? "2" : null) : null;

/** Amazon's severity words, folded to the advisor's: Critical, Important, Medium, Low. */
export const alasSeverity = (s: string | null | undefined): "critical" | "high" | "medium" | "low" | null => {
  const w = String(s ?? "").trim().toLowerCase();
  return w === "critical" ? "critical" : w === "important" ? "high" : w === "medium" || w === "moderate" ? "medium" : w === "low" ? "low" : null;
};

export interface AlasAdvisory { id: string; release: AlasRelease; type: string; severity: string | null; title: string | null; issued: string | null; updated: string | null; cves: string[]; packages: { name: string; evr: string; arch: string }[] }

const attr = (tag: string, name: string): string | null => { const m = new RegExp(`\\b${name}="([^"]*)"`).exec(tag); return m ? m[1] : null; };
const text = (block: string, tag: string): string | null => { const m = new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)</${tag}>`).exec(block); return m ? m[1].replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').trim() : null; };

/** The security advisories in one updateinfo document (the XML as text); bugfix and enhancement updates are left out. */
export function parseUpdateinfo(xml: string, release: AlasRelease): AlasAdvisory[] {
  const out: AlasAdvisory[] = [];
  const re = /<update\b([^>]*)>([\s\S]*?)<\/update>/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(xml))) {
    const type = attr(m[1], "type") ?? "unknown";
    if (type !== "security") continue;
    const body = m[2];
    const id = text(body, "id"); if (!id) continue;
    const cves = [...new Set([...body.matchAll(/<reference\b[^>]*\bid="(CVE-\d{4}-\d+)"[^>]*\btype="cve"/g)].map((x) => x[1]))].sort();
    const packages: AlasAdvisory["packages"] = [];
    const seen = new Set<string>();
    for (const p of body.matchAll(/<package\b([^>]*)>/g)) {
      const name = attr(p[1], "name"); const version = attr(p[1], "version"); const rel = attr(p[1], "release"); const arch = attr(p[1], "arch") ?? "noarch"; const epoch = attr(p[1], "epoch");
      if (!name || !version || /-debuginfo$|-debugsource$/.test(name)) continue;
      const evr = `${epoch && epoch !== "0" ? `${epoch}:` : ""}${version}${rel ? `-${rel}` : ""}`;
      const key = `${name}\t${evr}\t${arch}`; if (seen.has(key)) continue; seen.add(key);
      packages.push({ name, evr, arch });
    }
    const issued = /<issued\b[^>]*\bdate="([^"]*)"/.exec(body)?.[1] ?? null; const updated = /<updated\b[^>]*\bdate="([^"]*)"/.exec(body)?.[1] ?? null;
    out.push({ id, release, type, severity: text(body, "severity"), title: text(body, "title"), issued: issued ? issued.replace(" ", "T") : null, updated: updated ? updated.replace(" ", "T") : null, cves, packages });
  }
  return out;
}

// ---- rpm version comparison (rpmvercmp): segments of digits or letters, tilde sorts before anything, caret after everything but the end ----

const rpmSegCmp = (a: string, b: string): number => {
  let i = 0, j = 0;
  while (i < a.length || j < b.length) {
    while (i < a.length && !/[A-Za-z0-9~^]/.test(a[i])) i++;
    while (j < b.length && !/[A-Za-z0-9~^]/.test(b[j])) j++;
    if (a[i] === "~" || b[j] === "~") { if (a[i] !== "~") return 1; if (b[j] !== "~") return -1; i++; j++; continue; }
    if (a[i] === "^" || b[j] === "^") { if (i >= a.length) return -1; if (j >= b.length) return 1; if (a[i] !== "^") return 1; if (b[j] !== "^") return -1; i++; j++; continue; }
    if (i >= a.length || j >= b.length) break;
    const isNum = /[0-9]/.test(a[i]);
    const re = isNum ? /[0-9]/ : /[A-Za-z]/;
    let sa = ""; while (i < a.length && re.test(a[i])) sa += a[i++];
    let sb = ""; while (j < b.length && re.test(b[j])) sb += b[j++];
    if (!sb) return isNum ? 1 : -1; // one is a number where the other is letters: numbers are newer
    if (isNum) { sa = sa.replace(/^0+/, ""); sb = sb.replace(/^0+/, ""); if (sa.length !== sb.length) return sa.length > sb.length ? 1 : -1; }
    const c = sa < sb ? -1 : sa > sb ? 1 : 0; if (c) return c;
  }
  if (i >= a.length && j >= b.length) return 0;
  return i >= a.length ? -1 : 1;
};

/** rpm's EVR comparison: -1 when a is older than b, 0 when equal, 1 when newer. "epoch:version-release"; a missing epoch is 0. */
export function rpmEvrCmp(a: string, b: string): number {
  const split = (s: string) => { const m = /^(?:(\d+):)?([^-]*)(?:-(.*))?$/.exec(s) || []; return { e: m[1] ? parseInt(m[1], 10) : 0, v: m[2] ?? "", r: m[3] ?? "" }; };
  const x = split(a), y = split(b);
  if (x.e !== y.e) return x.e < y.e ? -1 : 1;
  const v = rpmSegCmp(x.v, y.v); if (v) return v;
  return rpmSegCmp(x.r, y.r);
}

// ---- the feed: one download per release and architecture a day, skipped when the repository has not changed ----

const log = (l: string) => console.log(`[alas] ${l}`);

async function fetchText(url: string, timeoutMs = 30_000): Promise<string> {
  const res = await fetch(url, { signal: AbortSignal.timeout(timeoutMs), headers: { "user-agent": "cloud-advisor" } });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return res.text();
}

export interface AlasRefreshResult { release: AlasRelease; arch: AlasArch; skipped?: string; advisories: number; packages: number }

/** Reads one release's core updateinfo and stores its security advisories; `force` re-reads even when the repository timestamp is unchanged. */
export async function refreshAlas(release: AlasRelease, arch: AlasArch, opts: { force?: boolean } = {}): Promise<AlasRefreshResult> {
  const root = (await fetchText(alasMirrorList(release, arch), 15_000)).split(/\r?\n/).map((l) => l.trim()).find(Boolean);
  if (!root) throw new Error("the mirror list is empty");
  const base = root.endsWith("/") ? root : `${root}/`;
  const repomd = await fetchText(`${base}repodata/repomd.xml`, 15_000);
  const data = /<data type="updateinfo">([\s\S]*?)<\/data>/.exec(repomd)?.[1];
  const href = data ? /<location href="([^"]+)"/.exec(data)?.[1] : null;
  const stamp = data ? /<timestamp>(\d+)<\/timestamp>/.exec(data)?.[1] ?? null : null;
  if (!href) throw new Error("repomd.xml names no updateinfo");
  const key = `alas_stamp:${release}:${arch}`;
  if (!opts.force && stamp && getSetting(key) === stamp) return { release, arch, skipped: "unchanged", advisories: 0, packages: 0 };
  const res = await fetch(`${base}${href}`, { signal: AbortSignal.timeout(120_000), headers: { "user-agent": "cloud-advisor" } });
  if (!res.ok) throw new Error(`${href}: HTTP ${res.status}`);
  const buf = Buffer.from(await res.arrayBuffer());
  const xml = href.endsWith(".gz") ? gunzipSync(buf).toString("utf8") : buf.toString("utf8");
  const advisories = parseUpdateinfo(xml, release);
  const now = new Date().toISOString();
  let packages = 0;
  db.transaction(() => {
    const up = db.prepare("insert into alas_advisories(id, release, severity, title, issued, updated, cves, fetched_at) values (?, ?, ?, ?, ?, ?, ?, ?) on conflict(id) do update set severity = excluded.severity, title = excluded.title, issued = excluded.issued, updated = excluded.updated, cves = excluded.cves, fetched_at = excluded.fetched_at");
    const pk = db.prepare("insert or ignore into alas_packages(advisory_id, name, evr, arch) values (?, ?, ?, ?)");
    for (const a of advisories) {
      up.run(a.id, a.release, alasSeverity(a.severity), a.title, a.issued, a.updated, JSON.stringify(a.cves), now);
      for (const p of a.packages) { pk.run(a.id, p.name, p.evr, p.arch); packages++; }
    }
  })();
  if (stamp) setSetting(key, stamp);
  log(`Amazon Linux ${release} ${arch}: ${advisories.length} security advisories, ${packages} package builds`);
  return { release, arch, advisories: advisories.length, packages };
}

export interface AlasMatch { advisory_id: string; fixed_evr: string; severity: string | null; title: string | null; cves: string[]; issued: string | null; updated: string | null }

/**
 * The advisories an installed Amazon Linux package is behind on: those whose fix for this package name (and
 * architecture, or noarch) is a newer build than the one installed. The newest fix of each advisory is the one
 * reported.
 */
export function alasMatches(release: AlasRelease, name: string, evr: string, arch: string | null): AlasMatch[] {
  const rows = db.prepare("select a.id, a.severity, a.title, a.cves, a.issued, a.updated, p.evr, p.arch from alas_packages p join alas_advisories a on a.id = p.advisory_id where a.release = ? and p.name = ?").all(release, name) as any[];
  const byAdvisory = new Map<string, AlasMatch>();
  for (const r of rows) {
    if (arch && r.arch !== "noarch" && r.arch !== arch) continue;
    if (rpmEvrCmp(evr, String(r.evr)) >= 0) continue;
    const prev = byAdvisory.get(r.id);
    if (!prev || rpmEvrCmp(String(r.evr), prev.fixed_evr) > 0) byAdvisory.set(r.id, { advisory_id: r.id, fixed_evr: String(r.evr), severity: r.severity, title: r.title, cves: JSON.parse(r.cves || "[]"), issued: r.issued, updated: r.updated });
  }
  return [...byAdvisory.values()];
}

/** How current the stored feed is, per release and architecture. */
export function alasStatus(): { release: string; advisories: number; fetched_at: string | null }[] {
  return db.prepare("select release, count(*) as advisories, max(fetched_at) as fetched_at from alas_advisories group by release order by release").all() as any[];
}

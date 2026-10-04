import { db } from "./db.js";
import { alasMatches, alasRelease, refreshAlas, type AlasArch, type AlasRelease } from "./alas_feed.js";
import "./instance_apps.js"; // the instance_ports table the verdict reads

/**
 * Which published vulnerabilities the fleet's installed software is affected by, and how much that matters given
 * what can reach the affected program (docs/cloud-ontology.md §2, KnVulnerability and the VULNERABLE_TO verdict).
 *
 * Sources, never hand-written: OSV (https://osv.dev, the distribution advisories of Ubuntu, Debian, Alpine, Rocky
 * and AlmaLinux, queried by source package and exact installed version through its batch API) and the Amazon Linux
 * updateinfo feed (src/alas_feed.ts) for Amazon Linux 2 and 2023. The advisories' CVE records, read from OSV, give
 * the CVSS score and attack vector when the distribution advisory itself carries none (Ubuntu's and Debian's do not).
 * Everything read is cached in SQLite, so a scan re-asks only for versions it has not seen or advisories that changed.
 *
 * A match is a fact (this package, this version, this advisory); the verdict adds reachability: the ports the
 * affected program listens on (the apps probe) and their exposure (security groups and network ACLs) decide whether
 * the vulnerability is critical (the internet can reach it), exposed (the network can), mitigated (blocked by a
 * filter), local_only (nothing listens, or the attack needs local access) or merely affected (installed, no known
 * listening program: a library, a kernel, a tool).
 */

db.exec(`create table if not exists vuln_queries (
  ecosystem text not null, name text not null, version text not null, checked_at text not null, vuln_ids text not null default '[]',
  primary key (ecosystem, name, version)
);
create table if not exists vulnerabilities (
  id text primary key, source text not null, aliases text not null default '[]', cves text not null default '[]', summary text, details text,
  severity text, score real, cvss text, attack_vector text, severity_from text, cwe text, published text, modified text, references_ text not null default '[]', fixes text not null default '{}', fetched_at text not null
);
create table if not exists package_vulns (
  ecosystem text not null, name text not null, version text not null, vuln_id text not null, fixed_version text,
  primary key (ecosystem, name, version, vuln_id)
);
create index if not exists package_vulns_vuln on package_vulns(vuln_id);
create table if not exists vuln_scans (
  id integer primary key autoincrement, started_at text not null, finished_at text, status text not null, trigger text not null,
  queries integer not null default 0, fetched integer not null default 0, matches integer not null default 0, error text, log text
)`);

export const OSV_API = "https://api.osv.dev/v1";
const OSV_BATCH = 500;
/** Advisory and CVE records read per scan at most; the rest wait for the next scan (the queries are cached, so it catches up). */
const DETAIL_BUDGET = 600;
/** A version asked about this recently is not asked about again (a manual re-run must not hammer the API). */
const RECHECK_HOURS = 6;

// ---- which advisory feed an installed package belongs to --------------------------------------------------------------

export interface Ecosystem { feed: "osv" | "alas"; ecosystem: string; release?: AlasRelease }

/**
 * The OSV ecosystem (release-qualified, the way OSV indexes distribution advisories: Ubuntu:24.04:LTS, Debian:12,
 * Alpine:v3.19, Rocky Linux:9, AlmaLinux:9), or the Amazon Linux feed for amzn; null for a distribution neither covers
 * (RHEL, CentOS, Fedora, SUSE, ...), with a word on why in `unsupportedReason`.
 */
export function ecosystemOf(pm: string | null | undefined, osId: string | null | undefined, osVersion: string | null | undefined): Ecosystem | null {
  const id = String(osId ?? "").toLowerCase(); const ver = String(osVersion ?? "").trim();
  if (id === "amzn") { const r = alasRelease(id, ver); return r ? { feed: "alas", ecosystem: `Amazon Linux:${r}`, release: r } : null; }
  if (pm === "deb") {
    if (id === "ubuntu" && /^\d\d\.\d\d$/.test(ver)) { const [yy, mm] = ver.split(".").map(Number); return { feed: "osv", ecosystem: yy % 2 === 0 && mm === 4 ? `Ubuntu:${ver}:LTS` : `Ubuntu:${ver}` }; }
    if (id === "debian" && /^\d+/.test(ver)) return { feed: "osv", ecosystem: `Debian:${ver.split(".")[0]}` };
    return null;
  }
  if (pm === "apk") { const m = /^(\d+\.\d+)/.exec(ver); return id === "alpine" && m ? { feed: "osv", ecosystem: `Alpine:v${m[1]}` } : null; }
  if (pm === "rpm") {
    const major = ver.split(".")[0];
    if (id === "rocky" && major) return { feed: "osv", ecosystem: `Rocky Linux:${major}` };
    if (id === "almalinux" && major) return { feed: "osv", ecosystem: `AlmaLinux:${major}` };
    return null;
  }
  return null;
}

export const unsupportedReason = (pm: string | null | undefined, osId: string | null | undefined, osVersion: string | null | undefined): string => {
  const id = String(osId ?? "").toLowerCase();
  if (id === "amzn") return `Amazon Linux ${osVersion ?? ""}: only releases 2 and 2023 publish the updateinfo feed the advisor reads`;
  if (["rhel", "centos", "fedora", "ol"].includes(id)) return `${osId} ${osVersion ?? ""}: its advisories are not in OSV (Red Hat publishes OVAL/CSAF feeds; not read yet)`;
  if (["sles", "opensuse-leap", "opensuse"].includes(id)) return `${osId} ${osVersion ?? ""}: SUSE advisories are not in OSV (not read yet)`;
  if (!pm) return "no package manager found by the probe (dpkg, rpm or apk)";
  return `${osId ?? "unknown OS"} ${osVersion ?? ""} (${pm}): no advisory feed known for it`;
};

// ---- CVSS v3 base score from the vector string (the spec's formula), its rating and the attack vector -----------------

const AV: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const AC: Record<string, number> = { L: 0.77, H: 0.44 };
const PR_U: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 };
const PR_C: Record<string, number> = { N: 0.85, L: 0.68, H: 0.5 };
const UI: Record<string, number> = { N: 0.85, R: 0.62 };
const CIA: Record<string, number> = { H: 0.56, L: 0.22, N: 0 };
const roundUp = (x: number): number => { const i = Math.round(x * 100000); return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10; };

/** The CVSS 3.x base score of a vector ("CVSS:3.1/AV:N/AC:L/..."); null for anything else (a 4.0 vector carries no computable score here). */
export function cvssBaseScore(vector: string): number | null {
  if (!/^CVSS:3\.[01]\//.test(vector)) return null;
  const m: Record<string, string> = {}; for (const part of vector.split("/").slice(1)) { const [k, v] = part.split(":"); m[k] = v; }
  const scope = m.S; if (!(m.AV in AV) || !(m.AC in AC) || !(m.UI in UI) || !(m.C in CIA) || !(m.I in CIA) || !(m.A in CIA) || (scope !== "U" && scope !== "C")) return null;
  const pr = (scope === "C" ? PR_C : PR_U)[m.PR]; if (pr == null) return null;
  const iss = 1 - (1 - CIA[m.C]) * (1 - CIA[m.I]) * (1 - CIA[m.A]);
  const impact = scope === "U" ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15;
  const expl = 8.22 * AV[m.AV] * AC[m.AC] * pr * UI[m.UI];
  if (impact <= 0) return 0;
  return roundUp(Math.min(scope === "U" ? impact + expl : 1.08 * (impact + expl), 10));
}

export type Severity = "critical" | "high" | "medium" | "low";
export const severityOfScore = (score: number | null | undefined): Severity | null => (score == null ? null : score >= 9 ? "critical" : score >= 7 ? "high" : score >= 4 ? "medium" : score > 0 ? "low" : null);
/** The words the feeds use (Debian urgency, GHSA, Red Hat, Amazon) folded to four. */
export const severityOfWord = (w: string | null | undefined): Severity | null => {
  const s = String(w ?? "").toLowerCase().trim();
  if (!s) return null;
  if (/^(critical|urgent)$/.test(s)) return "critical";
  if (/^(high|important)$/.test(s)) return "high";
  if (/^(medium|moderate)$/.test(s)) return "medium";
  if (/^(low|unimportant|negligible|minor)$/.test(s)) return "low";
  return null;
};
export const attackVectorOf = (vector: string | null | undefined): "network" | "adjacent" | "local" | "physical" | null => {
  const m = /\bAV:([NALP])\b/.exec(String(vector ?? "")); return m ? ({ N: "network", A: "adjacent", L: "local", P: "physical" } as const)[m[1] as "N" | "A" | "L" | "P"] : null;
};
export const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
export const severityRank = (s: string | null | undefined): number => SEVERITY_RANK[String(s)] ?? 4;

// ---- OSV records --------------------------------------------------------------------------------------------------------

export interface OsvVuln { id: string; aliases?: string[]; related?: string[]; upstream?: string[]; summary?: string; details?: string; severity?: { type: string; score: string }[]; published?: string; modified?: string; references?: { type: string; url: string }[]; affected?: any[]; database_specific?: any }

/** What one OSV record says about severity: the best CVSS vector it carries (3.x scored here), or a severity word in its database fields. */
export function severityFromRecord(v: OsvVuln): { score: number | null; cvss: string | null; severity: Severity | null; attack_vector: ReturnType<typeof attackVectorOf> } {
  let best: { score: number | null; cvss: string | null } = { score: null, cvss: null };
  for (const s of v.severity ?? []) {
    const vec = String(s.score ?? ""); if (!vec) continue;
    const score = cvssBaseScore(vec);
    if (best.cvss == null || (score != null && (best.score == null || score > best.score))) best = { score, cvss: vec };
  }
  const word = severityOfWord(v.database_specific?.severity) ?? severityOfWord((v.affected ?? []).map((a) => a?.ecosystem_specific?.urgency ?? a?.database_specific?.urgency).find(Boolean));
  const sev = severityOfScore(best.score) ?? word;
  return { score: best.score, cvss: best.cvss, severity: sev, attack_vector: attackVectorOf(best.cvss) };
}

/** The versions that fix it for one ecosystem and package, from the ECOSYSTEM ranges of the matching `affected` entries. */
export function fixedVersions(v: OsvVuln, ecosystem: string, name: string): string[] {
  const out: string[] = [];
  for (const a of v.affected ?? []) {
    if (a?.package?.name !== name || a?.package?.ecosystem !== ecosystem) continue;
    for (const r of a.ranges ?? []) if (r.type === "ECOSYSTEM") for (const e of r.events ?? []) if (e.fixed) out.push(String(e.fixed));
  }
  return [...new Set(out)];
}

/** Every fixed version the record names, keyed "<ecosystem>|<package>", so the fixed version of a later match is read from the stored record. */
export function fixesOf(v: OsvVuln): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const a of v.affected ?? []) {
    const key = `${a?.package?.ecosystem ?? ""}|${a?.package?.name ?? ""}`; if (key === "|") continue;
    for (const r of a.ranges ?? []) if (r.type === "ECOSYSTEM") for (const e of r.events ?? []) if (e.fixed) out[key] = [...new Set([...(out[key] ?? []), String(e.fixed)])];
  }
  return out;
}
const cveIdsOf = (v: OsvVuln): string[] => [...new Set([...(v.aliases ?? []), ...(v.upstream ?? []), ...(v.related ?? [])].filter((x) => /^CVE-\d{4}-\d+$/.test(x)))].sort();

async function osvPost<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${OSV_API}${path}`, { method: "POST", headers: { "content-type": "application/json", "user-agent": "cloud-advisor" }, body: JSON.stringify(body), signal: AbortSignal.timeout(60_000) });
  if (!res.ok) throw new Error(`OSV ${path}: HTTP ${res.status} ${(await res.text()).slice(0, 200)}`);
  return res.json() as Promise<T>;
}
async function osvGet<T>(path: string): Promise<T | null> {
  const res = await fetch(`${OSV_API}${path}`, { headers: { "user-agent": "cloud-advisor" }, signal: AbortSignal.timeout(30_000) });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`OSV ${path}: HTTP ${res.status}`);
  return res.json() as Promise<T>;
}

/** OSV's batch query: for each (ecosystem, package, version) the ids (and modified stamps) of the advisories that affect it. */
export async function osvQueryBatch(queries: { ecosystem: string; name: string; version: string }[], post: typeof osvPost = osvPost): Promise<{ id: string; modified: string | null }[][]> {
  const out: { id: string; modified: string | null }[][] = [];
  for (let i = 0; i < queries.length; i += OSV_BATCH) {
    const slice = queries.slice(i, i + OSV_BATCH);
    const r = await post<{ results: { vulns?: { id: string; modified?: string }[] }[] }>("/querybatch", { queries: slice.map((q) => ({ package: { name: q.name, ecosystem: q.ecosystem }, version: q.version })) });
    for (const res of r.results ?? []) out.push((res.vulns ?? []).map((v) => ({ id: v.id, modified: v.modified ?? null })));
    while (out.length < Math.min(i + OSV_BATCH, queries.length)) out.push([]);
  }
  return out;
}

/**
 * Ubuntu and Debian publish the same issue twice in OSV: one record per CVE (UBUNTU-CVE-…, DEBIAN-CVE-…, which carry
 * the score) and the bundle that fixed several at once (USN-…, DSA-…, DLA-…). When a version has per-CVE records the
 * bundles are left out, so a box is not counted twice for one hole; the fixed version is on the per-CVE record too.
 */
export function dedupeAdvisories<T extends { id: string }>(vulns: T[]): T[] {
  const perCve = vulns.some((v) => /^(UBUNTU|DEBIAN)-CVE-/.test(v.id));
  return perCve ? vulns.filter((v) => !/^(USN|DSA|DLA|ELA)-\d/.test(v.id)) : vulns;
}

// ---- storing advisories -------------------------------------------------------------------------------------------------

const upsertVuln = db.prepare(`insert into vulnerabilities(id, source, aliases, cves, summary, details, severity, score, cvss, attack_vector, severity_from, cwe, published, modified, references_, fixes, fetched_at)
  values (@id, @source, @aliases, @cves, @summary, @details, @severity, @score, @cvss, @attack_vector, @severity_from, @cwe, @published, @modified, @references_, @fixes, @fetched_at)
  on conflict(id) do update set source = excluded.source, aliases = excluded.aliases, cves = excluded.cves, summary = excluded.summary, details = excluded.details, severity = excluded.severity, score = excluded.score, cvss = excluded.cvss,
  attack_vector = excluded.attack_vector, severity_from = excluded.severity_from, cwe = excluded.cwe, published = excluded.published, modified = excluded.modified, references_ = excluded.references_, fixes = excluded.fixes, fetched_at = excluded.fetched_at`);
const upsertPkgVuln = db.prepare("insert or replace into package_vulns(ecosystem, name, version, vuln_id, fixed_version) values (?, ?, ?, ?, ?)");
const upsertQuery = db.prepare("insert or replace into vuln_queries(ecosystem, name, version, checked_at, vuln_ids) values (?, ?, ?, ?, ?)");
const clip = (s: unknown, n: number): string | null => (s == null ? null : String(s).slice(0, n));

/** Stores an OSV advisory; when it carries no severity of its own, the first CVE it fixes lends its CVSS (`severity_from`). */
export function storeOsvRecord(v: OsvVuln, cveRecords: Map<string, OsvVuln | null>, now = new Date().toISOString()): void {
  let sev = severityFromRecord(v); let from: string | null = null; let cwe: string | null = null;
  const cves = cveIdsOf(v);
  if (sev.score == null && !sev.severity) for (const c of cves) { const r = cveRecords.get(c); if (!r) continue; const s = severityFromRecord(r); if (s.score != null || s.severity) { sev = s; from = c; cwe = (r.database_specific?.cwe_ids ?? [])[0] ?? null; break; } }
  if (!cwe) cwe = (v.database_specific?.cwe_ids ?? [])[0] ?? null;
  upsertVuln.run({ id: v.id, source: "osv", aliases: JSON.stringify(v.aliases ?? []), cves: JSON.stringify(cves), summary: clip(v.summary, 300), details: clip(v.details, 2000), severity: sev.severity, score: sev.score, cvss: sev.cvss, attack_vector: sev.attack_vector, severity_from: from, cwe,
    published: v.published ?? null, modified: v.modified ?? null, references_: JSON.stringify((v.references ?? []).slice(0, 12).map((r) => r.url)), fixes: JSON.stringify(fixesOf(v)), fetched_at: now });
}

/** Stores an Amazon Linux advisory as a vulnerability record; its CVEs lend the CVSS score and attack vector when read. */
export function storeAlasRecord(m: { advisory_id: string; severity: string | null; title: string | null; cves: string[]; issued: string | null; updated: string | null }, cveRecords: Map<string, OsvVuln | null>, now = new Date().toISOString()): void {
  let score: number | null = null, cvss: string | null = null, from: string | null = null, av: ReturnType<typeof attackVectorOf> = null, cwe: string | null = null;
  for (const c of m.cves) { const r = cveRecords.get(c); if (!r) continue; const s = severityFromRecord(r); if (s.score != null && (score == null || s.score > score)) { score = s.score; cvss = s.cvss; from = c; av = s.attack_vector; cwe = (r.database_specific?.cwe_ids ?? [])[0] ?? null; } }
  upsertVuln.run({ id: m.advisory_id, source: "alas", aliases: "[]", cves: JSON.stringify(m.cves), summary: clip(m.title?.replace(/^Amazon Linux \d+ - [A-Z0-9-]+: /, ""), 300), details: null, severity: m.severity ?? severityOfScore(score), score, cvss, attack_vector: av, severity_from: from, cwe,
    published: m.issued, modified: m.updated, references_: JSON.stringify([`https://alas.aws.amazon.com/${m.advisory_id.startsWith("ALAS2023") ? "AL2023/" : "AL2/"}${m.advisory_id}.html`]), fixes: "{}", fetched_at: now });
}

// ---- the scan ------------------------------------------------------------------------------------------------------------

export interface FleetQuery { eco: Ecosystem; name: string; version: string; arch: string | null }

/** Every distinct (feed, package, version) installed anywhere on the fleet, for a distribution a feed covers. */
export function fleetQueries(within?: (instanceId: string) => boolean): { queries: FleetQuery[]; unsupported: { os: string; reason: string; instances: number }[]; boxes: number } {
  const osRows = (db.prepare("select instance_id, os_id, os_version, package_manager, arch from instance_os").all() as any[]).filter((o) => !within || within(String(o.instance_id)));
  const eco = new Map<string, Ecosystem | null>(); const unsupported = new Map<string, { os: string; reason: string; instances: number }>();
  for (const o of osRows) {
    const e = ecosystemOf(o.package_manager, o.os_id, o.os_version); eco.set(o.instance_id, e);
    if (!e && (o.package_manager || o.os_id)) { const k = `${o.os_id} ${o.os_version} ${o.package_manager}`; const u = unsupported.get(k) ?? { os: `${o.os_id ?? "?"} ${o.os_version ?? ""}`.trim(), reason: unsupportedReason(o.package_manager, o.os_id, o.os_version), instances: 0 }; u.instances++; unsupported.set(k, u); }
  }
  // OSV indexes distribution advisories by source package; the Amazon Linux feed lists the binary builds that fix them
  const pk = db.prepare("select instance_id, name, coalesce(source, name) as qname, version, arch from instance_packages where gone = 0").all() as any[];
  const seen = new Map<string, FleetQuery>();
  for (const p of pk) { const e = eco.get(p.instance_id); if (!e) continue; const name = e.feed === "alas" ? String(p.name) : String(p.qname); const key = `${e.ecosystem}\t${name}\t${p.version}\t${e.feed === "alas" ? p.arch ?? "" : ""}`; if (!seen.has(key)) seen.set(key, { eco: e, name, version: String(p.version), arch: p.arch ?? null }); }
  return { queries: [...seen.values()], unsupported: [...unsupported.values()], boxes: osRows.length };
}

let busy = false;
export const vulnScanBusy = () => busy;

export interface VulnScanResult { id: number; queries: number; asked: number; fetched: number; matches: number; vulns: number; unsupported: { os: string; reason: string; instances: number }[]; alas: string[]; took_ms: number }

/**
 * One scan: the fleet's distinct package versions not asked about recently go to OSV in batches (and, for Amazon
 * Linux, against the stored updateinfo feed, refreshed first); the advisories not yet stored, or changed since, are
 * read in detail with their CVE records for a score; then the matches are recomputed. Incremental and idempotent.
 */
export async function scanVulnerabilities(opts: { trigger?: string; force?: boolean; log?: (l: string) => void } = {}): Promise<VulnScanResult> {
  if (busy) throw new Error("a vulnerability scan is already running");
  busy = true;
  const t0 = Date.now(); const lines: string[] = [];
  const log = (l: string) => { lines.push(`${new Date().toISOString().slice(11, 19)} ${l}`); (opts.log ?? ((x: string) => console.log(`[vulns] ${x}`)))(l); };
  const scanId = Number(db.prepare("insert into vuln_scans(started_at, status, trigger) values (?, 'running', ?)").run(new Date().toISOString(), opts.trigger ?? "manual").lastInsertRowid);
  try {
    const now = new Date().toISOString();
    const { queries, unsupported, boxes } = fleetQueries();
    log(`${boxes} boxes with a software inventory, ${queries.length} distinct package versions to match${unsupported.length ? `; not matchable: ${unsupported.map((u) => `${u.os} (${u.instances})`).join(", ")}` : ""}`);
    const cutoff = new Date(Date.now() - RECHECK_HOURS * 3600_000).toISOString();
    const recent = new Set((db.prepare("select ecosystem, name, version from vuln_queries where checked_at > ?").all(cutoff) as any[]).map((r) => `${r.ecosystem}\t${r.name}\t${r.version}`));
    const due = opts.force ? queries : queries.filter((q) => !recent.has(`${q.eco.ecosystem}\t${q.name}\t${q.version}`));
    const wanted = new Map<string, string | null>(); // advisory id -> modified stamp the feed reports (null = unknown, read if absent)
    const pending: { eco: Ecosystem; name: string; version: string; vulns: { id: string; modified: string | null }[] }[] = [];

    // Amazon Linux: the updateinfo feed, per release and architecture present
    const alasDone: string[] = [];
    const alasDue = due.filter((q) => q.eco.feed === "alas");
    if (alasDue.length) {
      const combos = new Set(alasDue.map((q) => `${q.eco.release}\t${/^(x86_64|aarch64)$/.test(q.arch ?? "") ? q.arch : "x86_64"}`));
      for (const c of combos) { const [release, arch] = c.split("\t") as [AlasRelease, AlasArch]; try { const r = await refreshAlas(release, arch, { force: Boolean(opts.force) }); alasDone.push(`${release}/${arch}${r.skipped ? " (unchanged)" : `: ${r.advisories} advisories`}`); } catch (e: any) { log(`Amazon Linux ${release} ${arch} feed not read: ${e?.message || e}`); } }
      for (const q of alasDue) {
        const ms = alasMatches(q.eco.release!, q.name, q.version, q.arch);
        pending.push({ eco: q.eco, name: q.name, version: q.version, vulns: ms.map((m) => ({ id: m.advisory_id, modified: m.updated })) });
        for (const m of ms) wanted.set(m.advisory_id, m.updated);
      }
    }
    // OSV: the batch query
    const osvDue = due.filter((q) => q.eco.feed === "osv");
    if (osvDue.length) {
      const results = await osvQueryBatch(osvDue.map((q) => ({ ecosystem: q.eco.ecosystem, name: q.name, version: q.version })));
      osvDue.forEach((q, i) => { const vulns = dedupeAdvisories(results[i] ?? []); pending.push({ eco: q.eco, name: q.name, version: q.version, vulns }); for (const v of vulns) wanted.set(v.id, v.modified); });
      log(`OSV: ${osvDue.length} versions asked, ${pending.filter((p) => p.eco.feed === "osv" && p.vulns.length).length} with advisories`);
    }

    // the advisories to read in detail: new ones, and those the feed says changed since we stored them
    const stored = new Map((db.prepare("select id, modified from vulnerabilities").all() as any[]).map((r) => [r.id, r.modified as string | null]));
    const toFetch = [...wanted].filter(([id, mod]) => !stored.has(id) || (mod && stored.get(id) && mod > stored.get(id)!)).map(([id]) => id);
    const budgeted = toFetch.slice(0, DETAIL_BUDGET);
    if (toFetch.length > budgeted.length) log(`${toFetch.length} advisories to read; ${budgeted.length} this scan, the rest next time`);
    let fetched = 0;
    const alasById = new Map<string, ReturnType<typeof alasMatches>[number]>();
    for (const q of alasDue) for (const m of alasMatches(q.eco.release!, q.name, q.version, q.arch)) alasById.set(m.advisory_id, m);
    const cveCache = new Map<string, OsvVuln | null>();
    const readCves = async (ids: string[]) => { for (const c of ids.slice(0, 3)) if (!cveCache.has(c)) { try { cveCache.set(c, await osvGet<OsvVuln>(`/vulns/${encodeURIComponent(c)}`)); } catch { cveCache.set(c, null); } } };
    const worker = async (ids: string[]) => {
      for (const id of ids) {
        try {
          const alas = alasById.get(id);
          if (alas) { await readCves(alas.cves); storeAlasRecord(alas, cveCache, now); fetched++; continue; }
          const v = await osvGet<OsvVuln>(`/vulns/${encodeURIComponent(id)}`); if (!v) continue;
          const own = severityFromRecord(v); if (own.score == null && !own.severity) await readCves(cveIdsOf(v));
          storeOsvRecord(v, cveCache, now); fetched++;
        } catch (e: any) { log(`${id} not read: ${String(e?.message || e).slice(0, 120)}`); }
      }
    };
    const lanes = 6; const lanesIds: string[][] = Array.from({ length: lanes }, () => []); budgeted.forEach((id, i) => lanesIds[i % lanes].push(id));
    await Promise.all(lanesIds.map(worker));
    if (fetched) log(`${fetched} advisories read (${cveCache.size} CVE records for scores)`);

    // the package → advisory rows and the query cache; the fixed version comes from the record just stored (or stored earlier)
    db.transaction(() => {
      for (const p of pending) {
        db.prepare("delete from package_vulns where ecosystem = ? and name = ? and version = ?").run(p.eco.ecosystem, p.name, p.version);
        for (const v of p.vulns) {
          let fixed: string | null = null;
          if (p.eco.feed === "alas") fixed = alasMatches(p.eco.release!, p.name, p.version, null).find((m) => m.advisory_id === v.id)?.fixed_evr ?? null;
          else { const row = db.prepare("select fixes from vulnerabilities where id = ?").get(v.id) as any; const fixes = row ? (JSON.parse(row.fixes || "{}") as Record<string, string[]>)[`${p.eco.ecosystem}|${p.name}`] : undefined; fixed = fixes?.length ? fixes.join(", ") : null; }
          upsertPkgVuln.run(p.eco.ecosystem, p.name, p.version, v.id, fixed);
        }
        upsertQuery.run(p.eco.ecosystem, p.name, p.version, now, JSON.stringify(p.vulns.map((v) => v.id)));
      }
    })();
    const matches = vulnerabilityMatches();
    const vulns = new Set(matches.map((m) => m.vuln_id)).size;
    log(`${matches.length} matches: ${vulns} advisories across ${new Set(matches.map((m) => m.instance_id)).size} boxes`);
    db.prepare("update vuln_scans set finished_at = ?, status = 'completed', queries = ?, fetched = ?, matches = ?, log = ? where id = ?").run(new Date().toISOString(), due.length, fetched, matches.length, lines.join("\n"), scanId);
    return { id: scanId, queries: queries.length, asked: due.length, fetched, matches: matches.length, vulns, unsupported, alas: alasDone, took_ms: Date.now() - t0 };
  } catch (e: any) {
    db.prepare("update vuln_scans set finished_at = ?, status = 'failed', error = ?, log = ? where id = ?").run(new Date().toISOString(), String(e?.message || e).slice(0, 500), lines.join("\n"), scanId);
    throw e;
  } finally { busy = false; }
}

// ---- which program a package provides, and the verdict ----------------------------------------------------------------

/** Source or binary package names → the process names the apps probe sees listening (instance_ports.process). */
export const PROCESSES_OF: [RegExp, string[]][] = [
  [/^openssh/, ["sshd"]], [/^nginx/, ["nginx"]], [/^(apache2|httpd)/, ["apache2", "httpd"]], [/^postgresql/, ["postgres", "postmaster"]], [/^redis/, ["redis-server", "redis-serve"]],
  [/^(mysql|mariadb|percona)/, ["mysqld", "mariadbd"]], [/^mongodb/, ["mongod"]], [/^haproxy/, ["haproxy"]], [/^traefik/, ["traefik"]], [/^caddy/, ["caddy"]], [/^(nodejs|node)\d*$/, ["node"]],
  [/^(docker|containerd|moby)/, ["dockerd", "containerd", "docker-proxy"]], [/^memcached/, ["memcached"]], [/^rabbitmq/, ["beam.smp"]], [/^bind9?$/, ["named"]], [/^postfix/, ["master"]], [/^exim4/, ["exim4"]],
  [/^dovecot/, ["dovecot"]], [/^samba/, ["smbd"]], [/^vsftpd/, ["vsftpd"]], [/^openvpn/, ["openvpn"]], [/^squid/, ["squid"]], [/^varnish/, ["varnishd"]], [/^(tomcat|jenkins|elasticsearch|opensearch|kafka|java-|openjdk)/, ["java"]],
  [/^grafana/, ["grafana", "grafana-server"]], [/^prometheus/, ["prometheus"]], [/^python3?(\.\d+)?$/, ["python3", "python"]], [/^php/, ["php-fpm"]], [/^ruby/, ["ruby", "puma", "unicorn"]], [/^bitcoin/, ["bitcoind"]], [/^lnd$/, ["lnd"]],
  [/^unbound/, ["unbound"]], [/^dnsmasq/, ["dnsmasq"]], [/^chrony/, ["chronyd"]], [/^rpcbind/, ["rpcbind"]], [/^cups/, ["cupsd"]], [/^zabbix/, ["zabbix_agentd"]], [/^(telegraf|prometheus-node-exporter|node-exporter)/, ["telegraf", "node_exporter"]],
  [/^amazon-ssm-agent/, ["amazon-ssm-agent", "ssm-agent-worker"]], [/^rsyslog/, ["rsyslogd"]], [/^systemd-resolved|^systemd$/, ["systemd-resolve"]], [/^(cockpit)/, ["cockpit-ws"]], [/^(rpcbind|nfs-utils|nfs-kernel-server)/, ["rpc.mountd", "rpcbind"]],
];
const LIBRARY = /^(openssl|libssl|glibc|libc6|zlib|libxml2|curl|libcurl|gnutls|libgnutls|libssh|libgcrypt|expat|libexpat|libpng|libjpeg|pcre|libpcre|sqlite|libsqlite|ncurses|libtasn1|nettle|krb5|p11-kit|ca-certificates|busybox|libtiff|libwebp|freetype|harfbuzz|glib2?|libgd|gdk-pixbuf|openldap|libldap|cyrus-sasl|libsasl|libyaml|jansson|json-c|libarchive|xz|bzip2|gzip|tar|libzstd|zstd|libnghttp2|nghttp2|pam|libpam|shadow|util-linux|coreutils|bash|dash|perl|libperl|libxslt|libgcc|gcc|binutils|libstdc|readline|gmp|libgmp|libidn|libunistring|libffi|libseccomp|libcap|dbus|avahi|libuv|c-ares|libevent|libev|icu|libicu|openjpeg|libvpx|ffmpeg|imagemagick|ghostscript|poppler|libxml|libxslt|python3-.*|golang|rust|libtomcrypt|mbedtls|wolfssl|libsodium|protobuf|grpc|libgit2|libmicrohttpd|libmodsecurity)/;
const KERNEL = /^(linux|kernel|linux-image|linux-aws|linux-signed|linux-meta|linux-headers|kernel-livepatch)/;

export type PackageScope = "service" | "library" | "kernel" | "tool";
/** What kind of thing a package is for the verdict: a program that may listen, a library linked by others, the kernel, or a tool nothing listens as. */
export function packageScope(name: string): { scope: PackageScope; processes: string[] } {
  const n = name.toLowerCase();
  for (const [re, procs] of PROCESSES_OF) if (re.test(n)) return { scope: "service", processes: procs };
  if (KERNEL.test(n)) return { scope: "kernel", processes: [] };
  if (LIBRARY.test(n)) return { scope: "library", processes: [] };
  return { scope: "tool", processes: [] };
}

export type Criticality = "critical" | "exposed" | "mitigated" | "local_only" | "affected";
export const CRITICALITY_RANK: Record<Criticality, number> = { critical: 0, exposed: 1, mitigated: 2, affected: 3, local_only: 4 };
export interface PortSeen { proto: string; port: number; process: string | null; exposure: string; scope?: string | null }

/**
 * The verdict for one package on one box: the ports its program listens on and their exposure decide it; an attack
 * that needs local access is local_only whatever listens; a library or kernel is affected (reached through whichever
 * program uses it; a library behind an internet-facing program is still reported as such, with the box's open ports).
 */
export function criticalityOf(scope: PackageScope, processes: string[], ports: PortSeen[], attackVector: string | null): { criticality: Criticality; reachable: "internet" | "network" | "local" | "none"; via: PortSeen | null } {
  if (attackVector === "local" || attackVector === "physical") return { criticality: "local_only", reachable: "none", via: null };
  if (scope !== "service") return { criticality: "affected", reachable: "none", via: null };
  const mine = ports.filter((p) => p.process && processes.includes(p.process));
  if (!mine.length) return { criticality: "affected", reachable: "none", via: null };
  const rank: Record<string, number> = { internet: 0, network: 1, group: 1, closed: 2, local: 3 };
  const via = [...mine].sort((a, b) => (rank[a.exposure] ?? 9) - (rank[b.exposure] ?? 9))[0];
  if (via.exposure === "internet") return { criticality: "critical", reachable: "internet", via };
  if (via.exposure === "network" || via.exposure === "group") return { criticality: "exposed", reachable: "network", via };
  if (via.exposure === "closed") return { criticality: "mitigated", reachable: "none", via };
  return { criticality: "local_only", reachable: "local", via };
}

export interface VulnMatch {
  instance_id: string; instance_name: string | null; vuln_id: string; source: string; severity: Severity | null; score: number | null; attack_vector: string | null; summary: string | null; cves: string[]; published: string | null;
  ecosystem: string; package: string; packages: string[]; version: string; fixed_version: string | null; scope: PackageScope; process: string | null; port: number | null; proto: string | null; exposure: string | null;
  criticality: Criticality; reachable: "internet" | "network" | "local" | "none";
}

/**
 * Every (box, advisory, source package) the stored advisories match, with the verdict. Several binary packages of
 * one source (openssh-server, openssh-client) are one match. `instanceIds` narrows it.
 */
export function vulnerabilityMatches(instanceIds?: string[]): VulnMatch[] {
  const osRows = (instanceIds ? db.prepare(`select instance_id, os_id, os_version, package_manager from instance_os where instance_id in (${instanceIds.map(() => "?").join(",")})`).all(...instanceIds) : db.prepare("select instance_id, os_id, os_version, package_manager from instance_os").all()) as any[];
  const eco = new Map<string, Ecosystem>(); for (const o of osRows) { const e = ecosystemOf(o.package_manager, o.os_id, o.os_version); if (e) eco.set(o.instance_id, e); }
  if (!eco.size) return [];
  const ids = [...eco.keys()];
  const names = new Map((db.prepare(`select instance_id, name from inventory_ec2 where instance_id in (${ids.map(() => "?").join(",")})`).all(...ids) as any[]).map((r) => [r.instance_id, r.name]));
  const ports = new Map<string, PortSeen[]>();
  for (const p of db.prepare(`select instance_id, proto, port, process, exposure, scope from instance_ports where gone = 0 and instance_id in (${ids.map(() => "?").join(",")})`).all(...ids) as any[]) ports.set(p.instance_id, [...(ports.get(p.instance_id) ?? []), { proto: p.proto, port: Number(p.port), process: p.process, exposure: p.exposure, scope: p.scope }]);
  const rows = db.prepare(`select p.instance_id, p.name, coalesce(p.source, p.name) as qname, p.version, pv.ecosystem, pv.name as pv_name, pv.vuln_id, pv.fixed_version, v.source, v.severity, v.score, v.attack_vector, v.summary, v.cves, v.published
    from instance_packages p join package_vulns pv on (pv.name = coalesce(p.source, p.name) or pv.name = p.name) and pv.version = p.version join vulnerabilities v on v.id = pv.vuln_id
    where p.gone = 0 and p.instance_id in (${ids.map(() => "?").join(",")})`).all(...ids) as any[];
  const out = new Map<string, VulnMatch>();
  for (const r of rows) {
    const e = eco.get(r.instance_id)!; if (r.ecosystem !== e.ecosystem) continue;
    if (r.pv_name !== (e.feed === "alas" ? r.name : r.qname)) continue; // the join admits both names; the feed decides which one counts
    const key = `${r.instance_id}\t${r.vuln_id}\t${r.qname}`;
    const prev = out.get(key);
    if (prev) { if (!prev.packages.includes(r.name)) prev.packages.push(r.name); continue; }
    // the program comes from the binary or the source name, whichever is known to listen
    const sc = [packageScope(r.name), packageScope(r.qname)].sort((a, b) => (a.scope === "service" ? 0 : 1) - (b.scope === "service" ? 0 : 1))[0];
    const v = criticalityOf(sc.scope, sc.processes, ports.get(r.instance_id) ?? [], r.attack_vector);
    out.set(key, { instance_id: r.instance_id, instance_name: names.get(r.instance_id) ?? null, vuln_id: r.vuln_id, source: r.source, severity: r.severity, score: r.score, attack_vector: r.attack_vector, summary: r.summary, cves: JSON.parse(r.cves || "[]"), published: r.published,
      ecosystem: r.ecosystem, package: r.qname, packages: [r.name], version: r.version, fixed_version: r.fixed_version, scope: sc.scope, process: v.via?.process ?? (sc.processes[0] ?? null), port: v.via?.port ?? null, proto: v.via?.proto ?? null, exposure: v.via?.exposure ?? null, criticality: v.criticality, reachable: v.reachable });
  }
  return [...out.values()].sort((a, b) => CRITICALITY_RANK[a.criticality] - CRITICALITY_RANK[b.criticality] || severityRank(a.severity) - severityRank(b.severity) || (b.score ?? 0) - (a.score ?? 0) || a.vuln_id.localeCompare(b.vuln_id));
}

export interface VulnSummary {
  boxes_with_inventory: number; boxes_affected: number; matches: number; vulns: number; by_criticality: Record<string, number>; by_severity: Record<string, number>;
  unsupported: { os: string; reason: string; instances: number }[]; last_scan: any | null; running: boolean; feeds: { osv_queries: number; alas: { release: string; advisories: number; fetched_at: string | null }[] };
}

/** The fleet's vulnerability posture at a glance, for the Security page. */
export function vulnSummary(matches = vulnerabilityMatches(), within?: (instanceId: string) => boolean): VulnSummary {
  const { unsupported, boxes } = fleetQueries(within);
  const byC: Record<string, number> = {}; const byS: Record<string, number> = {};
  for (const m of matches) { byC[m.criticality] = (byC[m.criticality] || 0) + 1; const s = m.severity ?? "unrated"; byS[s] = (byS[s] || 0) + 1; }
  const last = db.prepare("select id, started_at, finished_at, status, trigger, queries, fetched, matches, error from vuln_scans order by id desc limit 1").get() ?? null;
  const q = db.prepare("select count(*) as n from vuln_queries").get() as any;
  const alas = db.prepare("select release, count(*) as advisories, max(fetched_at) as fetched_at from alas_advisories group by release").all() as any[];
  return { boxes_with_inventory: boxes, boxes_affected: new Set(matches.map((m) => m.instance_id)).size, matches: matches.length, vulns: new Set(matches.map((m) => m.vuln_id)).size, by_criticality: byC, by_severity: byS, unsupported, last_scan: last, running: busy, feeds: { osv_queries: Number(q?.n || 0), alas } };
}

/** One advisory as stored, with the boxes it matches. */
export function vulnerabilityDetail(id: string): { vuln: any; matches: VulnMatch[] } | null {
  const v = db.prepare("select * from vulnerabilities where id = ?").get(id) as any;
  if (!v) return null;
  const vuln = { ...v, aliases: JSON.parse(v.aliases || "[]"), cves: JSON.parse(v.cves || "[]"), references: JSON.parse(v.references_ || "[]"), references_: undefined, url: v.source === "alas" ? JSON.parse(v.references_ || "[]")[0] ?? null : `https://osv.dev/vulnerability/${encodeURIComponent(v.id)}` };
  return { vuln, matches: vulnerabilityMatches().filter((m) => m.vuln_id === id) };
}

export const listVulnScans = (limit = 10) => db.prepare("select id, started_at, finished_at, status, trigger, queries, fetched, matches, error from vuln_scans order by id desc limit ?").all(limit) as any[];
export const vulnScanLog = (id: number): string | null => (db.prepare("select log from vuln_scans where id = ?").get(id) as any)?.log ?? null;

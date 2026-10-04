import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { config } from "./config.js";
import { db } from "./db.js";

/**
 * KnSource: the documents the advisor builds knowledge from (docs/cloud-ontology.md §4, KnSource). Two origins:
 *
 * - the benchmark mods on disk (POWERPIPE_MOD_DIR/.powerpipe/mods): every control's own definition (title,
 *   description, severity, the query) and, where the mod ships one, the control's documentation page (the CIS and
 *   Foundational Security benchmarks carry Description, Rationale, Remediation and References per control; Thrifty
 *   carries one page per service);
 * - the web pages those documents reference (docs.aws.amazon.com and a short allow-list), fetched as text.
 *
 * Every source is stored with a content hash and the time the hash last changed, so whatever cites it (a generated
 * playbook) can be rebuilt when it changes. Nothing here is written by hand: the text is the mod's and the provider's.
 */

db.exec(`create table if not exists sources (
  id text primary key, kind text not null, origin text not null, title text, url text, text text not null default '', hash text not null default '',
  fetched_at text, changed_at text, error text
);
create index if not exists sources_kind on sources(kind)`);

export type SourceKind = "benchmark_doc" | "provider_doc" | "advisory" | "pricing" | "well_architected";
export interface SourceRow { id: string; kind: SourceKind; origin: "mod" | "web"; title: string | null; url: string | null; text: string; hash: string; fetched_at: string | null; changed_at: string | null; error: string | null }

/** Hosts a referenced page may be fetched from; anything else is listed as a reference but never read. */
export const ALLOWED_HOSTS = ["docs.aws.amazon.com", "aws.amazon.com", "repost.aws", "github.com", "www.cisecurity.org", "cloud.google.com", "learn.microsoft.com", "vercel.com", "neon.com", "neon.tech", "redis.io", "developers.cloudflare.com"];
const MAX_TEXT = 60_000;
export const WEB_REFRESH_DAYS = 7;

const sha = (s: string) => createHash("sha1").update(s).digest("hex").slice(0, 16);
const now = () => new Date().toISOString();

const upsert = db.prepare(`insert into sources(id, kind, origin, title, url, text, hash, fetched_at, changed_at, error) values (@id, @kind, @origin, @title, @url, @text, @hash, @fetched_at, @changed_at, @error)
  on conflict(id) do update set kind = excluded.kind, origin = excluded.origin, title = excluded.title, url = excluded.url, text = excluded.text, hash = excluded.hash, fetched_at = excluded.fetched_at,
  changed_at = case when excluded.hash <> sources.hash then excluded.changed_at else sources.changed_at end, error = excluded.error`);

/** Stores a source; `changed_at` moves only when the content hash does. Returns whether the content changed. */
export function storeSource(s: { id: string; kind: SourceKind; origin: "mod" | "web"; title?: string | null; url?: string | null; text: string; error?: string | null }): boolean {
  const text = s.text.slice(0, MAX_TEXT); const hash = sha(text);
  const prev = db.prepare("select hash from sources where id = ?").get(s.id) as { hash: string } | undefined;
  upsert.run({ id: s.id, kind: s.kind, origin: s.origin, title: s.title ?? null, url: s.url ?? null, text, hash, fetched_at: now(), changed_at: now(), error: s.error ?? null });
  return !prev || prev.hash !== hash;
}

export const getSource = (id: string): SourceRow | null => (db.prepare("select * from sources where id = ?").get(id) as SourceRow) ?? null;
export const listSources = (kind?: SourceKind): Omit<SourceRow, "text">[] => db.prepare(`select id, kind, origin, title, url, hash, fetched_at, changed_at, error, length(text) as chars from sources${kind ? " where kind = ?" : ""} order by id`).all(...(kind ? [kind] : [])) as any[];

// ---- the mods on disk --------------------------------------------------------------------------------------------------

/** A control as its mod declares it. `doc` is the documentation page's text when the mod ships one. */
export interface ModControl { control_id: string; mod: string; name: string; title: string; description: string; severity: string | null; query: string | null; sql: string | null; doc_file: string | null; doc: string | null; benchmark_doc: string | null; file: string; tags: Record<string, string> }

const MOD_OF: Record<string, string> = { "steampipe-mod-aws-thrifty": "aws_thrifty", "steampipe-mod-aws-compliance": "aws_compliance" };
const attr = (block: string, name: string): string | null => { const m = new RegExp(`^\\s*${name}\\s*=\\s*"((?:[^"\\\\]|\\\\.)*)"`, "m").exec(block); return m ? m[1].replace(/\\"/g, '"').replace(/\\n/g, "\n") : null; };

/** The mod directories Powerpipe installed under the advisor's mod folder, by their short name (aws_thrifty, aws_compliance). */
export function modDirs(root = config.modDir): { mod: string; dir: string; version: string | null }[] {
  const base = path.join(root, ".powerpipe", "mods", "github.com", "turbot");
  let names: string[] = []; try { names = fs.readdirSync(base); } catch { return []; }
  return names.flatMap((n) => { const key = Object.keys(MOD_OF).find((k) => n.startsWith(k)); return key ? [{ mod: MOD_OF[key], dir: path.join(base, n), version: n.split("@")[1] ?? null }] : []; });
}

/** Parses every `control "<name>" { ... }` block of a mod file. */
export function parseControls(text: string, mod: string, file: string, modDir: string): ModControl[] {
  const out: ModControl[] = [];
  const re = /^control\s+"([a-z0-9_]+)"\s*\{/gm;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text))) {
    // the block ends at the first "}" on its own line after the header; sql heredocs are inside and indented
    const start = m.index + m[0].length; const endRe = /^\}/gm; endRe.lastIndex = start; const e = endRe.exec(text); const block = text.slice(start, e ? e.index : text.length);
    const sqlM = /sql\s*=\s*<<-?EOQ\n([\s\S]*?)\n\s*EOQ/.exec(block);
    const docM = /documentation\s*=\s*file\("([^"]+)"\)/.exec(block);
    const tags: Record<string, string> = {}; for (const t of block.matchAll(/^\s{4}([a-z0-9_]+)\s*=\s*"([^"]*)"/gm)) tags[t[1]] = t[2];
    const docFile = docM ? path.resolve(modDir, docM[1].replace(/^\.\//, "")) : null;
    let doc: string | null = null; if (docFile) { try { doc = fs.readFileSync(docFile, "utf8"); } catch { doc = null; } }
    out.push({ control_id: `${mod}.control.${m[1]}`, mod, name: m[1], title: attr(block, "title") ?? m[1], description: attr(block, "description") ?? "", severity: attr(block, "severity"), query: /query\s*=\s*query\.([a-z0-9_]+)/.exec(block)?.[1] ?? null, sql: sqlM ? sqlM[1] : null, doc_file: docFile, doc, benchmark_doc: null, file, tags });
  }
  return out;
}

/** Thrifty keeps one page per service under controls/docs/<service>.md; the control file name says which. */
function benchmarkDocFor(file: string, modDir: string): string | null {
  const svc = path.basename(file, ".pp"); const p = path.join(modDir, "controls", "docs", `${svc}.md`);
  try { return fs.readFileSync(p, "utf8"); } catch { return null; }
}

/** Every control of every installed mod, parsed from the .pp files (benchmarks, dashboards and queries are skipped). */
export function readModControls(root = config.modDir): ModControl[] {
  const out: ModControl[] = [];
  for (const { mod, dir } of modDirs(root)) {
    const files: string[] = [];
    const walk = (d: string, depth: number) => { if (depth > 2) return; let ents: fs.Dirent[] = []; try { ents = fs.readdirSync(d, { withFileTypes: true }); } catch { return; } for (const e of ents) { const p = path.join(d, e.name); if (e.isDirectory()) { if (!e.name.startsWith(".") && e.name !== "docs") walk(p, depth + 1); } else if (e.name.endsWith(".pp") && !/^(mod|variables|locals|query|queries)\.pp$/.test(e.name)) files.push(p); } };
    walk(dir, 0);
    for (const f of files) { let t = ""; try { t = fs.readFileSync(f, "utf8"); } catch { continue; } if (!/^control\s+"/m.test(t)) continue; const bd = mod === "aws_thrifty" ? benchmarkDocFor(f, dir) : null; for (const c of parseControls(t, mod, f, dir)) out.push({ ...c, benchmark_doc: bd }); }
  }
  return out;
}

/** The source text of one control: what the mod says about it, in order of usefulness. */
export function controlSourceText(c: ModControl): string {
  const parts = [`# ${c.title}`, `Control: ${c.control_id}${c.severity ? ` (severity ${c.severity})` : ""}`, "", c.description];
  if (c.doc) parts.push("", "## Documentation shipped with the control", "", c.doc.trim());
  else if (c.benchmark_doc) parts.push("", "## Benchmark documentation", "", c.benchmark_doc.trim().slice(0, 6000));
  if (c.sql) parts.push("", "## What the check evaluates (the control's SQL)", "", "```sql", c.sql.trim().slice(0, 3000), "```");
  return parts.join("\n");
}

export const modSourceId = (controlId: string) => `mod:${controlId}`;

/** Stores every installed control as a benchmark_doc source; returns how many changed since the last read. */
export function refreshModSources(root = config.modDir): { controls: number; changed: number; mods: { mod: string; version: string | null }[] } {
  const controls = readModControls(root); let changed = 0;
  db.transaction(() => { for (const c of controls) if (storeSource({ id: modSourceId(c.control_id), kind: "benchmark_doc", origin: "mod", title: c.title, url: null, text: controlSourceText(c) })) changed++; })();
  return { controls: controls.length, changed, mods: modDirs(root).map((m) => ({ mod: m.mod, version: m.version })) };
}

export const modControl = (controlId: string): ModControl | null => readModControls().find((c) => c.control_id === controlId) ?? null;

// ---- the web pages a control's documentation references --------------------------------------------------------------

/** The http(s) links in a document, fetchable ones first (allow-listed hosts), de-duplicated, fragments dropped. */
export function referencedUrls(text: string): { url: string; fetchable: boolean }[] {
  const seen = new Set<string>(); const out: { url: string; fetchable: boolean }[] = [];
  for (const m of text.matchAll(/https?:\/\/[^\s)\]>"'`]+/g)) {
    let u = m[0].replace(/[.,;:]+$/, "").split("#")[0];
    try { const p = new URL(u); if (!/^https?:$/.test(p.protocol)) continue; u = p.toString(); if (seen.has(u)) continue; seen.add(u); out.push({ url: u, fetchable: ALLOWED_HOSTS.includes(p.hostname) }); } catch { /* not a url */ }
  }
  return out.sort((a, b) => Number(b.fetchable) - Number(a.fetchable));
}

/** HTML to readable text: scripts, styles and navigation dropped, tags removed, entities decoded, whitespace folded. */
export function htmlToText(html: string): { title: string | null; text: string } {
  const title = /<title[^>]*>([^<]*)<\/title>/i.exec(html)?.[1]?.trim() ?? null;
  let s = html.replace(/<script[\s\S]*?<\/script>/gi, " ").replace(/<style[\s\S]*?<\/style>/gi, " ").replace(/<nav[\s\S]*?<\/nav>/gi, " ").replace(/<header[\s\S]*?<\/header>/gi, " ").replace(/<footer[\s\S]*?<\/footer>/gi, " ").replace(/<!--[\s\S]*?-->/g, " ");
  const main = /<main[\s\S]*?<\/main>/i.exec(s)?.[0] ?? /<article[\s\S]*?<\/article>/i.exec(s)?.[0] ?? s;
  s = main.replace(/<(br|\/p|\/div|\/li|\/h[1-6]|\/tr|\/pre)[^>]*>/gi, "\n").replace(/<[^>]+>/g, " ");
  s = s.replace(/&nbsp;/g, " ").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;|&apos;/g, "'").replace(/&#(\d+);/g, (_, n) => String.fromCharCode(Number(n)));
  s = s.replace(/[ \t]+/g, " ").replace(/ *\n */g, "\n").replace(/\n{3,}/g, "\n\n").trim();
  return { title, text: s };
}

/** Fetches a referenced page as text (allow-listed hosts only) unless it was read within WEB_REFRESH_DAYS; stores it with its hash. */
export async function fetchWebSource(url: string, opts: { force?: boolean } = {}): Promise<SourceRow | null> {
  let host = ""; try { host = new URL(url).hostname; } catch { return null; }
  if (!ALLOWED_HOSTS.includes(host)) return null;
  const prev = getSource(url);
  if (!opts.force && prev?.fetched_at && !prev.error && Date.now() - Date.parse(prev.fetched_at) < WEB_REFRESH_DAYS * 86_400_000) return prev;
  try {
    const res = await fetch(url, { headers: { "user-agent": "cloud-advisor (knowledge sources)", accept: "text/html,text/plain" }, signal: AbortSignal.timeout(20_000), redirect: "follow" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const body = await res.text();
    const { title, text } = /html/i.test(res.headers.get("content-type") || "") || /<html/i.test(body.slice(0, 500)) ? htmlToText(body) : { title: null, text: body };
    if (text.length < 200) throw new Error("the page has no readable text (a script-rendered page, or a block)");
    storeSource({ id: url, kind: /cisecurity/.test(host) ? "benchmark_doc" : "provider_doc", origin: "web", title, url, text });
  } catch (e: any) {
    // keep the last good text when the refresh fails; record the error either way
    storeSource({ id: url, kind: "provider_doc", origin: "web", title: prev?.title ?? null, url, text: prev?.text ?? "", error: String(e?.message || e).slice(0, 200) });
  }
  return getSource(url);
}

/**
 * The sources of one control, for a playbook: the mod's own text first, then the referenced pages (fetched now when
 * due), then references that were listed but not read. `extraUrls` adds the references the seed catalogue cited.
 */
export async function sourcesFor(controlId: string, extraUrls: string[] = []): Promise<{ sources: SourceRow[]; unread: string[] }> {
  let mod = getSource(modSourceId(controlId));
  if (!mod) { refreshModSources(); mod = getSource(modSourceId(controlId)); }
  const sources: SourceRow[] = mod ? [mod] : []; const unread: string[] = [];
  const refs = [...referencedUrls(mod?.text ?? ""), ...extraUrls.map((u) => ({ url: u, fetchable: (() => { try { return ALLOWED_HOSTS.includes(new URL(u).hostname); } catch { return false; } })() }))];
  const seen = new Set<string>();
  for (const r of refs.slice(0, 8)) {
    if (seen.has(r.url)) continue; seen.add(r.url);
    if (!r.fetchable) { unread.push(r.url); continue; }
    const s = await fetchWebSource(r.url);
    if (s && s.text) sources.push(s); else unread.push(r.url);
  }
  return { sources, unread };
}

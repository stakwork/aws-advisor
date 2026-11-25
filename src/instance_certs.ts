import { db } from "./db.js";
import { alertInsert } from "./alert_store.js";
import { AWS } from "./adapters/types.js";
import type { ProbeCert, ProbeTlsLive } from "./ssm.js";

/**
 * The TLS certificates a box holds (software probe 9): the public parts the probe read from files (Traefik, certbot, nginx, Apache, Caddy,
 * acme.json, a bounded sweep) and what each TLS port on the box answers. Kept per box in `instance_certs` and `instance_tls_live`, replaced
 * whole by every software probe that reports a `certs` list (a probe without openssl reports null and leaves the rows alone). The graph shows a
 * certificate as one (:AdvisorCertificate {id: 'cert:<sha256 fingerprint>'}) node however many boxes hold it, with
 * (cert)-[:SECURES {sources, path, container}]->(AdvisorCompute) per box (src/graph_software.ts); ACM certificates stay the ACM collector's
 * (src/services/acm.ts, keyed by ARN) and are never read from a box. An expiry alert (`cert_expiring`) opens at 30 days (warning) and 7 days
 * (alarm, expired included) per box and certificate, and closes when the certificate on the box is replaced or renewed.
 */

db.exec(`
create table if not exists instance_certs (
  instance_id text not null, fingerprint text not null, path text not null, source text not null, container text,
  subject text, cn text, issuer text, issuer_cn text, sans text, serial text, not_before text, not_after text, file_mtime text,
  renewer text, renewer_found integer not null default 0, provenance text, served integer not null default 0,
  first_seen text not null, last_seen text not null,
  primary key (instance_id, fingerprint, path)
);
create index if not exists instance_certs_fp on instance_certs(fingerprint);
create table if not exists instance_tls_live (
  instance_id text not null, port integer not null, sni text not null default '', fingerprint text not null, not_after text, match text not null,
  collected_at text not null,
  primary key (instance_id, port, sni)
)`);

export const CERT_WARN_DAYS = 30;
export const CERT_CRITICAL_DAYS = 7;
export type CertLevel = "warning" | "alarm";

/** Whole days from `now` to an ISO time, rounded down (negative once past); null for no date. Pure. */
export function daysLeft(notAfter: string | null | undefined, now = Date.now()): number | null {
  const t = notAfter ? Date.parse(notAfter) : NaN;
  return Number.isNaN(t) ? null : Math.floor((t - now) / 86_400_000);
}

/** The expiry finding for a certificate with this many days left: alarm at 7 or fewer (or expired), warning at 30 or fewer, none beyond. Pure. */
export function certLevel(days: number | null | undefined): CertLevel | null {
  if (days == null) return null;
  return days <= CERT_CRITICAL_DAYS ? "alarm" : days <= CERT_WARN_DAYS ? "warning" : null;
}

/** The names a certificate answers for: its SANs, else its common name. Pure. */
export const certDomains = (c: { sans?: string[] | null; cn?: string | null }): string[] => [...new Set((c.sans?.length ? c.sans : c.cn ? [c.cn] : []).filter(Boolean))];

export const certNodeId = (fingerprint: string): string => `cert:${fingerprint}`;

const clean = (v: unknown, n: number): string | null => (v == null || v === "" ? null : String(v).replace(/[^\x20-\x7e]/g, "").slice(0, n));
const isoOrNull = (v: unknown): string | null => { if (typeof v !== "string" || !v) return null; const d = new Date(v); return Number.isNaN(d.getTime()) ? null : d.toISOString(); };

const upsertCert = db.prepare(`insert into instance_certs(instance_id, fingerprint, path, source, container, subject, cn, issuer, issuer_cn, sans, serial, not_before, not_after, file_mtime, renewer, renewer_found, provenance, served, first_seen, last_seen)
  values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  on conflict(instance_id, fingerprint, path) do update set source = excluded.source, container = excluded.container, subject = excluded.subject, cn = excluded.cn, issuer = excluded.issuer, issuer_cn = excluded.issuer_cn, sans = excluded.sans,
    serial = excluded.serial, not_before = excluded.not_before, not_after = excluded.not_after, file_mtime = excluded.file_mtime, renewer = excluded.renewer, renewer_found = excluded.renewer_found, provenance = excluded.provenance, served = excluded.served, last_seen = excluded.last_seen`);
const upsertLive = db.prepare(`insert into instance_tls_live(instance_id, port, sni, fingerprint, not_after, match, collected_at) values (?, ?, ?, ?, ?, ?, ?)
  on conflict(instance_id, port, sni) do update set fingerprint = excluded.fingerprint, not_after = excluded.not_after, match = excluded.match, collected_at = excluded.collected_at`);

export interface CertRecordResult { certs: number; live: number; raised: number; closed: number }

/** Stores one box's certificates and live answers (replacing what it held), then judges expiry. Null when the probe reported no list (no openssl, an older probe). */
export function recordCerts(instanceId: string, collectedAt: string, data: { certs?: ProbeCert[] | null; tls_live?: ProbeTlsLive[] | null }, name: string | null = null): CertRecordResult | null {
  if (!Array.isArray(data.certs)) return null;
  const kept: ProbeCert[] = [];
  db.transaction(() => {
    const keep = new Set<string>();
    for (const c of data.certs!) {
      if (!c || typeof c.fingerprint !== "string" || !/^[0-9a-f]{64}$/.test(c.fingerprint) || typeof c.path !== "string" || !c.path) continue;
      const path = clean(c.path, 300)!; const k = `${c.fingerprint}\t${path}`; if (keep.has(k)) continue; keep.add(k);
      upsertCert.run(instanceId, c.fingerprint, path, clean(c.source, 20) ?? "pem-sweep", clean(c.container, 120), clean(c.subject, 200), clean(c.cn, 200), clean(c.issuer, 200), clean(c.issuer_cn, 200),
        JSON.stringify((Array.isArray(c.sans) ? c.sans : []).map((s) => clean(s, 120)).filter(Boolean).slice(0, 20)), clean(c.serial, 80), isoOrNull(c.not_before), isoOrNull(c.not_after), isoOrNull(c.file_mtime),
        clean(c.renewer, 40), c.renewer_found ? 1 : 0, c.provenance === "local" ? "local" : "managed_elsewhere", c.served ? 1 : 0, collectedAt, collectedAt);
      kept.push(c);
    }
    for (const r of db.prepare("select fingerprint, path from instance_certs where instance_id = ?").all(instanceId) as { fingerprint: string; path: string }[])
      if (!keep.has(`${r.fingerprint}\t${r.path}`)) db.prepare("delete from instance_certs where instance_id = ? and fingerprint = ? and path = ?").run(instanceId, r.fingerprint, r.path);
    db.prepare("delete from instance_tls_live where instance_id = ?").run(instanceId);
    for (const l of Array.isArray(data.tls_live) ? data.tls_live : []) {
      if (!l || !/^[0-9a-f]{64}$/.test(String(l.fingerprint)) || !Number.isInteger(Number(l.port))) continue;
      upsertLive.run(instanceId, Number(l.port), clean(l.sni, 120) ?? "", l.fingerprint, isoOrNull(l.not_after), l.match === "match" || l.match === "mismatch" ? l.match : "unknown", collectedAt);
    }
  })();
  const { raised, closed } = checkCertExpiry(instanceId, name, kept, Date.parse(collectedAt) || Date.now());
  return { certs: kept.length, live: (db.prepare("select count(*) as n from instance_tls_live where instance_id = ?").get(instanceId) as { n: number }).n, raised, closed };
}

const openAlerts = db.prepare("select id, details from alerts where kind = 'cert_expiring' and resource = ? and acknowledged = 0");
const ack = db.prepare("update alerts set acknowledged = 1, acknowledged_by = 'system' where id = ?");
// built on first use: alert_store reaches the adapters, which reach this module through the software inventory (an import cycle)
const insertAlert = () => alertInsert(AWS, "cert_expiring");

/** Pure: the certificates (one per fingerprint, the soonest path) that warrant an expiry alert now, with their level. */
export function expiryVerdicts(certs: { fingerprint: string; cn?: string | null; sans?: string[] | null; not_after?: string | null; path?: string }[], now = Date.now()): { fingerprint: string; level: CertLevel; days_left: number; domains: string[]; not_after: string; path: string | null }[] {
  const out = new Map<string, { fingerprint: string; level: CertLevel; days_left: number; domains: string[]; not_after: string; path: string | null }>();
  for (const c of certs) {
    const days = daysLeft(c.not_after, now); const level = certLevel(days);
    if (!level || days == null || out.has(c.fingerprint)) continue;
    out.set(c.fingerprint, { fingerprint: c.fingerprint, level, days_left: days, domains: certDomains(c), not_after: String(c.not_after), path: c.path ?? null });
  }
  return [...out.values()];
}

/** One open `cert_expiring` alert per box and certificate: raised on entering the window, closed when the certificate left the box or is out of the window. */
export function checkCertExpiry(instanceId: string, name: string | null, certs: ProbeCert[], now = Date.now()): { raised: number; closed: number } {
  const verdicts = expiryVerdicts(certs, now); const due = new Map(verdicts.map((v) => [v.fingerprint, v]));
  let raised = 0; let closed = 0; const open = new Set<string>();
  for (const a of openAlerts.all(instanceId) as { id: number; details: string | null }[]) {
    let fp = ""; try { fp = String(JSON.parse(a.details ?? "{}").fingerprint ?? ""); } catch { /* not ours */ }
    if (!fp || !due.has(fp)) { ack.run(a.id); closed++; } else open.add(fp);
  }
  const label = name || instanceId;
  for (const v of verdicts) {
    if (open.has(v.fingerprint)) continue;
    const what = v.domains.slice(0, 3).join(", ") || v.fingerprint.slice(0, 12);
    const message = `${label}: TLS certificate for ${what} ${v.days_left < 0 ? `expired ${-v.days_left} day(s) ago` : `expires in ${v.days_left} day(s)`}`;
    insertAlert().run(instanceId, message, JSON.stringify({ summary: message, level: v.level, instance_id: instanceId, name: label, fingerprint: v.fingerprint, domains: v.domains, not_after: v.not_after, days_left: v.days_left, path: v.path }));
    raised++;
  }
  return { raised, closed };
}

export interface CertRow {
  instance_id: string; fingerprint: string; path: string; source: string; container: string | null; subject: string | null; cn: string | null; issuer: string | null; issuer_cn: string | null; sans: string[]; serial: string | null;
  not_before: string | null; not_after: string | null; days_left: number | null; file_mtime: string | null; renewer: string | null; renewer_found: boolean; provenance: string; served: boolean; first_seen: string; last_seen: string;
  /** days between the certificate's start and the file's mtime: far from 0 means the file was copied here after issue (renewed elsewhere), not issued on the box */
  copied_after_days: number | null;
}

const toRow = (r: any, now: number): CertRow => {
  let sans: string[] = []; try { sans = JSON.parse(r.sans ?? "[]"); } catch { /* none */ }
  const nb = r.not_before ? Date.parse(r.not_before) : NaN; const mt = r.file_mtime ? Date.parse(r.file_mtime) : NaN;
  return { ...r, sans, days_left: daysLeft(r.not_after, now), renewer_found: Boolean(r.renewer_found), served: Boolean(r.served), copied_after_days: Number.isNaN(nb) || Number.isNaN(mt) ? null : Math.round(((mt - nb) / 86_400_000) * 10) / 10 };
};

/** What one box holds: its certificates and what its TLS ports answer. */
export function certsOn(instanceId: string, now = Date.now()): { certs: CertRow[]; tls_live: { port: number; sni: string | null; fingerprint: string; not_after: string | null; match: string; collected_at: string }[] } {
  return {
    certs: (db.prepare("select * from instance_certs where instance_id = ? order by not_after").all(instanceId) as any[]).map((r) => toRow(r, now)),
    tls_live: (db.prepare("select port, sni, fingerprint, not_after, match, collected_at from instance_tls_live where instance_id = ? order by port, sni").all(instanceId) as any[]).map((r) => ({ ...r, sni: r.sni || null })),
  };
}

export interface CertGroup { fingerprint: string; id: string; domains: string[]; issuer: string | null; not_after: string | null; days_left: number | null; level: CertLevel | null; renewer_found: boolean; instances: { instance_id: string; sources: string[]; path: string; container: string | null; served: boolean; renewer_found: boolean; provenance: string; file_mtime: string | null }[] }

/** The certificates of every box grouped by fingerprint (one wildcard certificate copied to five boxes is one group of five), soonest expiry first. */
export function certGroups(instanceIds?: string[], now = Date.now()): CertGroup[] {
  const rows = (db.prepare("select * from instance_certs order by fingerprint, instance_id, path").all() as any[]).filter((r) => !instanceIds || instanceIds.includes(r.instance_id)).map((r) => toRow(r, now));
  const groups = new Map<string, CertGroup>();
  for (const r of rows) {
    let g = groups.get(r.fingerprint);
    if (!g) { g = { fingerprint: r.fingerprint, id: certNodeId(r.fingerprint), domains: certDomains(r), issuer: r.issuer_cn ?? r.issuer, not_after: r.not_after, days_left: r.days_left, level: certLevel(r.days_left), renewer_found: false, instances: [] }; groups.set(r.fingerprint, g); }
    if (r.renewer_found) g.renewer_found = true;
    const own = g.instances.find((i) => i.instance_id === r.instance_id);
    if (own) { if (!own.sources.includes(r.source)) own.sources.push(r.source); own.served = own.served || r.served; own.renewer_found = own.renewer_found || r.renewer_found; }
    else g.instances.push({ instance_id: r.instance_id, sources: [r.source], path: r.path, container: r.container, served: r.served, renewer_found: r.renewer_found, provenance: r.provenance, file_mtime: r.file_mtime });
  }
  return [...groups.values()].sort((a, b) => (a.days_left ?? 1e9) - (b.days_left ?? 1e9));
}

export interface CertGraphRow {
  instance_id: string; id: string; fingerprint: string; name: string | null; domains: string[]; issuer: string | null; subject: string | null; serial: string | null; not_before: string | null; not_after: string | null; days_left: number | null;
  /** the kinds of source that read it on this box, comma separated (the node keeps the first box's; the edge has the list) */
  source: string; sources: string[]; path: string; container: string | null; served: boolean; renewer: string | null; renewer_found: boolean; provenance: string; wildcard: boolean; file_mtime: string | null; last_seen: string;
}

/** One row per (certificate, box) for the graph's AdvisorCertificate node and its SECURES edge to the box's compute; `instanceIds` limits the boxes. Pure over the table. */
export function certGraphRows(instanceIds?: string[], now = Date.now()): CertGraphRow[] {
  const out = new Map<string, CertGraphRow>();
  for (const r of (db.prepare("select * from instance_certs order by fingerprint, instance_id, path").all() as any[]).filter((x) => !instanceIds || instanceIds.includes(x.instance_id)).map((x) => toRow(x, now))) {
    const key = `${r.instance_id}\t${r.fingerprint}`; const cur = out.get(key);
    if (cur) { if (!cur.sources.includes(r.source)) cur.sources.push(r.source); cur.served = cur.served || r.served; if (r.renewer_found && !cur.renewer_found) { cur.renewer_found = true; cur.renewer = r.renewer; cur.provenance = r.provenance; } cur.source = cur.sources.join(","); continue; }
    const domains = certDomains(r);
    out.set(key, { instance_id: r.instance_id, id: certNodeId(r.fingerprint), fingerprint: r.fingerprint, name: r.cn ?? domains[0] ?? null, domains, issuer: r.issuer_cn ?? r.issuer, subject: r.subject, serial: r.serial, not_before: r.not_before, not_after: r.not_after, days_left: r.days_left,
      source: r.source, sources: [r.source], path: r.path, container: r.container, served: r.served, renewer: r.renewer, renewer_found: r.renewer_found, provenance: r.provenance, wildcard: domains.some((d) => d.startsWith("*.")), file_mtime: r.file_mtime, last_seen: r.last_seen });
  }
  return [...out.values()];
}

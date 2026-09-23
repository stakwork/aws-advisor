/**
 * The resources a recommendation touches, as links into the Inventory page.
 *
 * `recommendations.resource` is one id, or a comma-separated list when the agent grouped several ("i-1, i-2"),
 * sometimes with the name in parentheses ("i-0b19 (Hive)"); `resource_name` pairs with it. The agent also names
 * resources only in the title or the rationale ("Right-size two boxes: Hive and swarmPExsmg" with one id in
 * `resource`), so the text is scanned for ids and for inventory names; those are reported apart, as "mentioned",
 * because the rationale also names what the agent ruled out.
 */
import { db } from "./db.js";
import { shortResourceId } from "./paging.js";

export type Kind = "ec2" | "rds" | "elasticache" | "lambda" | "ebs" | "s3" | "snapshot" | "eip" | "vpc" | "nat" | "log-group" | "other";
/** Inventory tabs that open a resource by id (`/inventory?tab=<tab>&id=<id>`, see ui/src/pages/Inventory.tsx). */
export const TAB_FOR: Partial<Record<Kind, string>> = { ec2: "ec2", rds: "rds", elasticache: "elasticache", lambda: "lambda", ebs: "ebs", s3: "s3" };

export interface AffectedResource { id: string; name: string | null; kind: Kind; tab: string | null; found: boolean }

/** "i-1, i-2 (two)" + "a, b" → [{ id: "i-1", name: "a" }, { id: "i-2", name: "b" }]; the name in parentheses wins over the paired list. */
export function splitResourceList(resource: string | null | undefined, resourceName: string | null | undefined): { id: string; name: string | null }[] {
  const ids = (resource || "").split(/\s*,\s*/).map((s) => s.trim()).filter(Boolean);
  const names = (resourceName || "").split(/\s*,\s*/).map((s) => s.trim());
  const paired = names.length === ids.length;
  return ids.map((raw, i) => {
    const m = /^(.*?)\s*\(([^()]+)\)\s*$/.exec(raw);
    const id = m ? m[1].trim() : raw;
    const name = m ? m[2].trim() : paired && names[i] && names[i] !== id ? names[i] : null;
    return { id, name };
  });
}

/** What an id is, from its shape alone; null when only the inventory can tell (an RDS identifier, a bucket, a function name). */
export function kindOfId(id: string): Kind | null {
  const r = id.trim();
  if (r.startsWith("arn:")) {
    const [, , service, , , ...rest] = r.split(":");
    const tail = rest.join(":");
    if (service === "ec2") return tail.startsWith("instance/") ? "ec2" : tail.startsWith("volume/") ? "ebs" : tail.startsWith("snapshot/") ? "snapshot" : tail.startsWith("vpc/") ? "vpc" : tail.startsWith("natgateway/") ? "nat" : "other";
    if (service === "rds") return "rds";
    if (service === "elasticache") return "elasticache";
    if (service === "lambda") return "lambda";
    if (service === "s3") return "s3";
    if (service === "logs") return "log-group";
    return "other";
  }
  if (/^i-[0-9a-f]{8,17}$/.test(r)) return "ec2";
  if (/^vol-[0-9a-f]{8,17}$/.test(r)) return "ebs";
  if (/^snap-[0-9a-f]{8,17}$/.test(r)) return "snapshot";
  if (/^eipalloc-[0-9a-f]{8,17}$/.test(r)) return "eip";
  if (/^vpc-[0-9a-f]{8,17}$/.test(r)) return "vpc";
  if (/^nat-[0-9a-f]{8,17}$/.test(r)) return "nat";
  if (r.startsWith("/aws/") || r.startsWith("/")) return "log-group";
  if (/^rds:/.test(r)) return "rds";
  if (/^elasticache:/.test(r)) return "elasticache";
  if (/^lambda:/.test(r)) return "lambda";
  return null;
}

/** Resource ids written in free text: instance, volume, snapshot, EIP, VPC and NAT ids, in order of first mention. */
export function idsInText(text: string): string[] {
  return [...new Set(text.match(/\b(?:i|vol|snap|eipalloc|vpc|nat)-[0-9a-f]{8,17}\b/g) || [])];
}

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** Inventory names written in free text as whole words, case-sensitive; short or letterless names ("34") are skipped. */
export function namesInText(text: string, names: Iterable<string>): string[] {
  const out: string[] = [];
  for (const n of new Set(names)) {
    if (n.length < 3 || !/[A-Za-z]/.test(n)) continue;
    if (new RegExp(`(^|[^A-Za-z0-9_./-])${escapeRe(n)}(?=$|[^A-Za-z0-9_./-])`).test(text)) out.push(n);
  }
  return out;
}

interface Hit { kind: Kind; id: string; name: string | null }

/** The inventory row an id or a name points at, if any: each tab's identifier, plus EC2 names and RDS / ElastiCache group names. */
function lookup(idOrName: string): Hit | null {
  const q = <T>(sql: string, ...p: unknown[]) => { try { return db.prepare(sql).get(...p) as T | undefined; } catch { return undefined; } };
  const ec2 = q<{ instance_id: string; name: string | null }>("select instance_id, name from inventory_ec2 where instance_id = ? or name = ? order by case when instance_id = ? then 0 else 1 end, last_seen desc", idOrName, idOrName, idOrName);
  if (ec2) return { kind: "ec2", id: ec2.instance_id, name: ec2.name };
  const rds = q<{ db_instance_identifier: string; cluster: string | null }>("select db_instance_identifier, cluster from inventory_rds where db_instance_identifier = ? or cluster = ? order by case when db_instance_identifier = ? then 0 else 1 end", idOrName, idOrName, idOrName);
  if (rds) return { kind: "rds", id: rds.db_instance_identifier, name: rds.cluster && rds.cluster === idOrName ? `${idOrName} (cluster)` : null };
  const ec = q<{ cache_cluster_id: string }>("select cache_cluster_id from inventory_elasticache where cache_cluster_id = ? or replication_group = ? order by case when cache_cluster_id = ? then 0 else 1 end", idOrName, idOrName, idOrName);
  if (ec) return { kind: "elasticache", id: ec.cache_cluster_id, name: null };
  const fn = q<{ name: string }>("select name from inventory_lambda where name = ? or arn = ?", idOrName, idOrName);
  if (fn) return { kind: "lambda", id: fn.name, name: null };
  const vol = q<{ volume_id: string; name: string | null }>("select volume_id, name from inventory_ebs where volume_id = ?", idOrName);
  if (vol) return { kind: "ebs", id: vol.volume_id, name: vol.name };
  const bucket = q<{ name: string }>("select name from inventory_s3 where name = ?", idOrName);
  if (bucket) return { kind: "s3", id: bucket.name, name: null };
  return null;
}

function resolve(rawId: string, name: string | null): AffectedResource {
  const short = shortResourceId(rawId) || rawId;
  const hit = lookup(short) || (name ? lookup(name) : null);
  const kind = hit?.kind ?? kindOfId(rawId) ?? "other";
  return { id: hit?.id ?? short, name: hit?.name ?? name, kind, tab: TAB_FOR[kind] ?? null, found: Boolean(hit) };
}

/** Every inventory name worth spotting in text, loaded once per call (a few hundred rows). */
function inventoryNames(): string[] {
  const all = (sql: string) => { try { return (db.prepare(sql).all() as { n: string | null }[]).map((r) => r.n).filter((n): n is string => Boolean(n)); } catch { return []; } };
  return [...all("select name as n from inventory_ec2"), ...all("select db_instance_identifier as n from inventory_rds"), ...all("select cluster as n from inventory_rds"), ...all("select cache_cluster_id as n from inventory_elasticache"), ...all("select name as n from inventory_lambda")];
}

/**
 * `resources`: the resource column, one entry per id, resolved against the inventory. `mentioned`: ids and
 * inventory names that appear in the title or rationale but not in the resource column, resolved the same way.
 */
export function affectedResources(rec: { resource: string | null; resource_name: string | null; title: string | null; rationale: string | null }): { resources: AffectedResource[]; mentioned: AffectedResource[] } {
  const resources = splitResourceList(rec.resource, rec.resource_name).map((r) => resolve(r.id, r.name));
  const seen = new Set<string>();
  for (const r of resources) { seen.add(r.id); if (r.name) seen.add(r.name); }
  const text = `${rec.title || ""}\n${rec.rationale || ""}`;
  const mentioned: AffectedResource[] = [];
  for (const m of [...idsInText(text), ...namesInText(text, inventoryNames())]) {
    if (seen.has(m)) continue;
    const r = resolve(m, null);
    if (seen.has(r.id) || (r.name && seen.has(r.name))) continue;
    seen.add(r.id); if (r.name) seen.add(r.name);
    mentioned.push(r);
  }
  return { resources, mentioned };
}

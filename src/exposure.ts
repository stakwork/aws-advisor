/**
 * What breaks if a recommendation is carried out: the Route 53 records that reach each affected resource, the
 * volumes attached to it, the alerts open on it, and the pool or cluster it belongs to. Shown before the
 * decision buttons and handed to Jev's gate and the plan through the resource facts (src/resolve.ts).
 */
import { db } from "./db.js";
import { affectedResources } from "./affected.js";
import { domainsFor } from "./route53_inventory.js";

/** Actions that stop, replace or remove the resource, or change its address. */
export const DISRUPTIVE = /stop|terminate|rightsize|resize|downsize|migrat|graviton|delete|release|switch|modify|convert|upgrade|move|retire|storage/i;

export interface DomainRef { name: string; type: string; hop: number; summary: string | null }
export interface ResourceExposure {
  id: string; kind: string; name: string | null;
  domains: DomainRef[];
  volumes: { volume_id: string; size_gb: number | null; type: string | null; device: string | null }[];
  open_alerts: { id: number; kind: string; message: string; created_at: string }[];
  pool: { kind: string; name: string } | null;
  cluster: string | null;
}

const q = <T>(sql: string, ...p: unknown[]): T[] => { try { return db.prepare(sql).all(...p) as T[]; } catch { return []; } };

/** The Route 53 records that reach a resource, by its inventory kind (a cluster's members count for the cluster). */
export function domainsReaching(kind: string, id: string): DomainRef[] {
  const kinds = kind === "ec2" ? ["ec2"] : kind === "rds" ? ["rds", "rds_cluster"] : kind === "elasticache" ? ["elasticache", "elasticache_group"] : kind === "s3" ? ["s3"] : kind === "lambda" ? ["lambda"] : [];
  const out: DomainRef[] = [];
  for (const k of kinds) for (const d of domainsFor(k, id)) if (!out.some((x) => x.name === d.name && x.type === d.type)) out.push({ name: d.name, type: d.type, hop: Number(d.hop) || 1, summary: d.summary ?? null });
  return out;
}

export function exposureOf(kind: string, id: string, name: string | null): ResourceExposure {
  const alerts = q<{ id: number; kind: string; message: string; created_at: string }>("select id, kind, message, created_at from alerts where acknowledged = 0 and (resource = ? or resource like ?) order by created_at desc limit 10", id, `${id}:%`);
  const out: ResourceExposure = { id, kind, name, domains: domainsReaching(kind, id), volumes: [], open_alerts: alerts, pool: null, cluster: null };
  if (kind === "ec2") {
    out.volumes = q("select volume_id, size_gb, volume_type as type, device from inventory_ebs where instance_id = ? and gone = 0 order by device", id);
    const ec2 = q<{ pool_kind: string | null; pool: string | null }>("select pool_kind, pool from inventory_ec2 where instance_id = ?", id)[0];
    if (ec2?.pool) out.pool = { kind: ec2.pool_kind || "pool", name: ec2.pool };
  } else if (kind === "rds") {
    const rds = q<{ cluster: string | null; storage_gb: number | null; storage_type: string | null }>("select cluster, storage_gb, storage_type from inventory_rds where db_instance_identifier = ?", id)[0];
    if (rds?.cluster) out.cluster = rds.cluster;
    // an Aurora item names the cluster: the members' records reach it too
    const members = q<{ db_instance_identifier: string }>("select db_instance_identifier from inventory_rds where cluster = ? and gone = 0", id);
    for (const m of members) for (const d of domainsReaching("rds", m.db_instance_identifier)) if (!out.domains.some((x) => x.name === d.name && x.type === d.type)) out.domains.push(d);
  }
  return out;
}

/** The exposure of every affected resource the inventory knows, and whether the action is the disruptive kind. */
export function exposureFor(rec: { resource: string | null; resource_name: string | null; title: string | null; rationale: string | null; action_type: string }): { disruptive: boolean; resources: ResourceExposure[] } {
  const affected = affectedResources(rec).resources.filter((r) => r.found && ["ec2", "rds", "elasticache", "s3", "lambda"].includes(r.kind));
  return { disruptive: DISRUPTIVE.test(rec.action_type), resources: affected.map((r) => exposureOf(r.kind, r.id, r.name)) };
}

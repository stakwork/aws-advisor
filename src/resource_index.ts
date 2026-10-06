import { db } from "./db.js";

/**
 * Which account a resource id belongs to, by the ids the inventories hold. A module of its own with no other
 * imports, so the adapters and the overview can both use it without a cycle through the adapter registry.
 */
const rows = (sql: string, ...p: unknown[]): any[] => { try { return db.prepare(sql).all(...p) as any[]; } catch { return []; } };

/** Which account a resource string belongs to, by the ids the inventories hold (exact, or contained in an ARN). */
export function resourceAccountIndex(primary: string): { of: (resource: string | null | undefined) => string | null } {
  const ids = new Map<string, string>();
  const put = (id: unknown, acct: unknown) => { if (id) ids.set(String(id), String(acct || "") || primary); };
  for (const r of rows("select instance_id as id, account_id from inventory_ec2")) put(r.id, r.account_id);
  for (const r of rows("select db_instance_identifier as id, account_id from inventory_rds")) put(r.id, r.account_id);
  for (const r of rows("select arn as id, account_id from inventory_lambda")) put(r.id, r.account_id);
  for (const r of rows("select arn as id, account_id from inventory_elb")) put(r.id, r.account_id);
  for (const r of rows("select name as id, account_id from inventory_s3")) put(r.id, r.account_id);
  for (const r of rows("select volume_id as id, account_id from inventory_ebs")) put(r.id, r.account_id);
  for (const r of rows("select arn as id, account_id from inventory_iam_user")) put(r.id, r.account_id);
  for (const r of rows("select user_id as id, account_id from inventory_sso_user")) put(r.id, r.account_id);
  for (const r of rows("select arn as id, account_id from inventory_root_user")) put(r.id, r.account_id);
  for (const r of rows("select arn as id, account_id from inventory_iam_role")) put(r.id, r.account_id);
  // what the watcher, the review and the rules name besides instances: pools, clusters, filters, networks, gateways, log groups, functions by name
  for (const r of rows("select pool as id, account_id from inventory_ec2 where pool is not null and pool <> '' group by pool, account_id")) put(r.id, r.account_id);
  for (const r of rows("select arn as id, account_id from inventory_cluster")) put(r.id, r.account_id);
  for (const r of rows("select name as id, account_id from inventory_cluster")) put(r.id, r.account_id);
  for (const r of rows("select group_id as id, account_id from inventory_sg")) put(r.id, r.account_id);
  for (const r of rows("select vpc_id as id, account_id from inventory_vpc")) put(r.id, r.account_id);
  for (const r of rows("select gateway_id as id, account_id from inventory_gateway")) put(r.id, r.account_id);
  for (const r of rows("select name as id, account_id from log_groups")) put(r.id, r.account_id);
  for (const r of rows("select name as id, account_id from inventory_lambda")) put(r.id, r.account_id);
  for (const r of rows("select arn as id, account_id from inventory_dynamodb where arn is not null")) put(r.id, r.account_id);
  for (const r of rows("select name as id, account_id from inventory_dynamodb")) put(r.id, r.account_id);
  // certificates, topics, keys, file systems, vaults, plans, workgroups, stacks, web ACLs, detectors and their findings
  for (const r of rows("select id, account_id from inventory_service")) put(r.id, r.account_id);
  for (const r of rows("select id, account_id from threat_findings")) put(r.id, r.account_id);
  // platform accounts: a Vercel project, store or the team itself belongs to the team
  for (const r of rows("select id, team_id from vercel_projects")) put(r.id, r.team_id);
  for (const r of rows("select id, team_id from vercel_stores")) put(r.id, r.team_id);
  for (const r of rows("select id from vercel_team")) put(r.id, r.id);
  const list = [...ids.keys()].filter((k) => k.length >= 8);
  return {
    of: (resource) => {
      if (!resource) return null;
      const r = String(resource);
      if (ids.has(r)) return ids.get(r)!;
      const m = /^arn:aws:[a-z0-9-]*:[a-z0-9-]*:(\d{12}):/.exec(r); if (m) return m[1];
      for (const k of list) if (r.includes(k)) return ids.get(k)!;
      return null;
    },
  };
}

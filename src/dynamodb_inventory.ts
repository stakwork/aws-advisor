/**
 * DynamoDB inventory: every table in every account with its billing mode, provisioned capacity, size and item count,
 * plus 30 days of consumed read and write units from CloudWatch, priced at list (storage, provisioned capacity by the
 * hour, or on-demand request units scaled to a month). Refreshed with the rest of the inventory; the Inventory page's
 * Tables tab, the account overview and the capacity-mode action's facts read it from here. Table names are unique per
 * account and region only, so the key is (account_id, region, name).
 */
import { CloudWatchClient, GetMetricDataCommand, type MetricDataQuery } from "@aws-sdk/client-cloudwatch";
import { db } from "./db.js";
import { S, query } from "./steampipe.js";
import { describeError } from "./permissions.js";
import { accountCredentials } from "./accounts.js";
import { accountWhere, scopedStmt, type AccountScope } from "./scope.js";

db.exec(`create table if not exists inventory_dynamodb (
  account_id text not null default '', region text not null default '', name text not null, arn text, status text,
  billing_mode text, read_capacity integer, write_capacity integer, gsi_count integer not null default 0, gsi_read_capacity integer not null default 0, gsi_write_capacity integer not null default 0,
  item_count real, size_bytes real, table_class text, pitr integer not null default 0, stream integer not null default 0, created text, tags text,
  read_units_30d real, write_units_30d real, metric_days integer not null default 0,
  storage_usd real, capacity_usd real, monthly_usd real,
  open_recs integer not null default 0, findings integer not null default 0,
  first_seen text not null, last_seen text not null, gone integer not null default 0,
  primary key (account_id, region, name)
)`);

/** List prices (us-east-1 standard class; other regions differ by a few percent). The capacity-mode action uses the same unit rates. */
export const DYNAMODB_PRICE = { storage_gb_month: 0.25, rcu_hour: 0.00013, wcu_hour: 0.00065, hours_month: 730, on_demand_read_per_million: 0.125, on_demand_write_per_million: 0.625 };
const METRIC_DAYS = 30;
const MAX_METRIC_TABLES = 500;

export interface DynamoFacts { billing_mode: string | null; read_capacity: number; write_capacity: number; gsi_read_capacity: number; gsi_write_capacity: number; size_bytes: number; read_units_30d: number; write_units_30d: number; metric_days: number }

/**
 * A table's monthly cost at list: storage plus, for a provisioned table, its own and its indexes' units by the hour, or,
 * on demand, the 30-day consumed units scaled to a month at the request-unit rates. Pure.
 */
export function dynamodbMonthlyCost(f: DynamoFacts): { storage_usd: number; capacity_usd: number; usd_month: number } {
  const p = DYNAMODB_PRICE;
  const storage = (f.size_bytes / 1e9) * p.storage_gb_month;
  let capacity: number;
  if ((f.billing_mode || "PROVISIONED") === "PAY_PER_REQUEST") {
    const scale = f.metric_days > 0 ? 30 / f.metric_days : 0;
    capacity = (f.read_units_30d * scale / 1e6) * p.on_demand_read_per_million + (f.write_units_30d * scale / 1e6) * p.on_demand_write_per_million;
  } else {
    capacity = ((f.read_capacity + f.gsi_read_capacity) * p.rcu_hour + (f.write_capacity + f.gsi_write_capacity) * p.wcu_hour) * p.hours_month;
  }
  const r = (v: number) => Math.round(v * 100) / 100;
  return { storage_usd: r(storage), capacity_usd: r(capacity), usd_month: r(storage + capacity) };
}

const num = (v: unknown): number => (v == null || v === "" ? 0 : Number(v) || 0);
const json = (v: unknown): any => { if (v == null) return null; if (typeof v === "string") { try { return JSON.parse(v); } catch { return null; } } return v; };

/** Summed consumed read and write units per table over the window, by GetMetricData (daily sums, 500 queries per call), under the account's own credentials. */
async function consumedUnits(accountId: string | null, region: string, names: string[]): Promise<Map<string, { read: number; write: number; days: number }>> {
  const out = new Map<string, { read: number; write: number; days: number }>();
  if (!names.length) return out;
  const creds = accountCredentials(accountId);
  const cw = new CloudWatchClient({ region, credentials: creds.provider });
  try {
    const queries: MetricDataQuery[] = [];
    names.forEach((name, i) => {
      for (const [k, mn] of [["r", "ConsumedReadCapacityUnits"], ["w", "ConsumedWriteCapacityUnits"]] as const) {
        queries.push({ Id: `${k}${i}`, MetricStat: { Metric: { Namespace: "AWS/DynamoDB", MetricName: mn, Dimensions: [{ Name: "TableName", Value: name }] }, Period: 86400, Stat: "Sum" }, ReturnData: true });
      }
    });
    const now = Date.now();
    for (let i = 0; i < queries.length; i += 500) {
      let token: string | undefined;
      do {
        const r = await cw.send(new GetMetricDataCommand({ StartTime: new Date(now - METRIC_DAYS * 86400000), EndTime: new Date(now), MetricDataQueries: queries.slice(i, i + 500), ScanBy: "TimestampAscending", NextToken: token }));
        for (const m of r.MetricDataResults ?? []) {
          const id = m.Id || ""; const idx = Number(id.slice(1)); const name = names[idx]; if (!name) continue;
          const e = out.get(name) ?? { read: 0, write: 0, days: 0 }; out.set(name, e);
          const sum = (m.Values ?? []).reduce((s, v) => s + (v || 0), 0);
          if (id[0] === "r") { e.read += sum; e.days = Math.max(e.days, (m.Values ?? []).length); } else e.write += sum;
        }
        token = r.NextToken;
      } while (token);
    }
  } finally { cw.destroy(); }
  return out;
}

export async function refreshDynamodbInventory(onError: (m: string) => void = () => {}, onLog: (l: string) => void = () => {}): Promise<number> {
  // every column is a DescribeTable field; one the plugin version does not have is dropped and reported, the rest still lands
  let cols = ["name", "arn", "region", "account_id", "table_status", "billing_mode", "read_capacity", "write_capacity", "item_count", "table_size_bytes", "table_class", "creation_date_time", "global_secondary_indexes", "point_in_time_recovery_description", "latest_stream_arn", "tags"];
  let tables: any[];
  for (;;) {
    try { tables = await query<any>(`select ${cols.join(", ")} from ${S}.aws_dynamodb_table`); break; }
    catch (e) {
      const m = /column "?(\w+)"? does not exist/i.exec(String((e as any)?.message ?? e));
      if (!m || !cols.includes(m[1]) || ["name", "region", "account_id"].includes(m[1])) { onError(describeError(e, "dynamodb inventory (aws_dynamodb_table)")); return 0; }
      cols = cols.filter((c) => c !== m[1]); onLog(`dynamodb: column ${m[1]} not available, skipped`);
    }
  }
  // consumed units per (account, region), the biggest tables first when there are more than the cap
  const groups = new Map<string, any[]>();
  for (const t of tables) { const k = `${t.account_id ? String(t.account_id) : ""}|${t.region}`; if (!groups.has(k)) groups.set(k, []); groups.get(k)!.push(t); }
  const metrics = new Map<string, { read: number; write: number; days: number }>();
  for (const [k, list] of groups) {
    const [account, region] = k.split("|");
    const names = list.sort((a, b) => num(b.table_size_bytes) - num(a.table_size_bytes)).slice(0, MAX_METRIC_TABLES).map((t) => String(t.name));
    try { for (const [name, m] of await consumedUnits(account || null, region, names)) metrics.set(`${k}|${name}`, m); }
    catch (e) { onError(describeError(e, `dynamodb metrics ${region}${account ? ` (account ${account})` : ""} (cloudwatch:GetMetricData)`)); }
  }
  const findingsFor = db.prepare("select count(*) as n from findings where run_id = (select max(run_id) from findings) and (resource = ? or resource = ?)");
  const recsFor = db.prepare("select count(*) as n from recommendations where status = 'open' and (resource = ? or resource = ?)");
  const now = new Date().toISOString();
  const up = db.prepare(`insert into inventory_dynamodb(account_id, region, name, arn, status, billing_mode, read_capacity, write_capacity, gsi_count, gsi_read_capacity, gsi_write_capacity, item_count, size_bytes, table_class, pitr, stream, created, tags,
      read_units_30d, write_units_30d, metric_days, storage_usd, capacity_usd, monthly_usd, open_recs, findings, first_seen, last_seen, gone)
    values (@account_id, @region, @name, @arn, @status, @billing_mode, @read_capacity, @write_capacity, @gsi_count, @gsi_read_capacity, @gsi_write_capacity, @item_count, @size_bytes, @table_class, @pitr, @stream, @created, @tags,
      @read_units_30d, @write_units_30d, @metric_days, @storage_usd, @capacity_usd, @monthly_usd, @open_recs, @findings, @now, @now, 0)
    on conflict(account_id, region, name) do update set arn = excluded.arn, status = excluded.status, billing_mode = excluded.billing_mode, read_capacity = excluded.read_capacity, write_capacity = excluded.write_capacity,
      gsi_count = excluded.gsi_count, gsi_read_capacity = excluded.gsi_read_capacity, gsi_write_capacity = excluded.gsi_write_capacity, item_count = excluded.item_count, size_bytes = excluded.size_bytes, table_class = excluded.table_class,
      pitr = excluded.pitr, stream = excluded.stream, created = excluded.created, tags = excluded.tags, read_units_30d = excluded.read_units_30d, write_units_30d = excluded.write_units_30d, metric_days = excluded.metric_days,
      storage_usd = excluded.storage_usd, capacity_usd = excluded.capacity_usd, monthly_usd = excluded.monthly_usd, open_recs = excluded.open_recs, findings = excluded.findings, last_seen = excluded.last_seen, gone = 0`);
  let n = 0;
  db.transaction(() => {
    for (const t of tables) {
      const account = t.account_id ? String(t.account_id) : "";
      const gsis: any[] = Array.isArray(json(t.global_secondary_indexes)) ? json(t.global_secondary_indexes) : [];
      const gsiRead = gsis.reduce((s, g) => s + num(g?.ProvisionedThroughput?.ReadCapacityUnits), 0);
      const gsiWrite = gsis.reduce((s, g) => s + num(g?.ProvisionedThroughput?.WriteCapacityUnits), 0);
      const pitr = json(t.point_in_time_recovery_description)?.PointInTimeRecoveryStatus === "ENABLED" ? 1 : 0;
      const m = metrics.get(`${account}|${t.region}|${t.name}`) ?? { read: 0, write: 0, days: 0 };
      const facts: DynamoFacts = { billing_mode: t.billing_mode ?? null, read_capacity: num(t.read_capacity), write_capacity: num(t.write_capacity), gsi_read_capacity: gsiRead, gsi_write_capacity: gsiWrite, size_bytes: num(t.table_size_bytes), read_units_30d: m.read, write_units_30d: m.write, metric_days: m.days };
      const cost = dynamodbMonthlyCost(facts);
      up.run({ account_id: account, region: String(t.region || ""), name: String(t.name), arn: t.arn ?? null, status: t.table_status ?? null, billing_mode: t.billing_mode ?? null,
        read_capacity: facts.read_capacity, write_capacity: facts.write_capacity, gsi_count: gsis.length, gsi_read_capacity: gsiRead, gsi_write_capacity: gsiWrite,
        item_count: num(t.item_count), size_bytes: facts.size_bytes, table_class: t.table_class ?? null, pitr, stream: t.latest_stream_arn ? 1 : 0, created: t.creation_date_time ? new Date(t.creation_date_time).toISOString() : null,
        tags: t.tags == null ? null : typeof t.tags === "string" ? t.tags : JSON.stringify(t.tags), read_units_30d: m.read, write_units_30d: m.write, metric_days: m.days,
        storage_usd: cost.storage_usd, capacity_usd: cost.capacity_usd, monthly_usd: cost.usd_month,
        open_recs: (recsFor.get(String(t.name), t.arn ?? "") as any).n, findings: (findingsFor.get(String(t.name), t.arn ?? "") as any).n, now });
      n++;
    }
    db.prepare("update inventory_dynamodb set gone = 1 where last_seen <> ?").run(now);
  })();
  return n;
}

const SORTS = ["name", "region", "billing_mode", "read_capacity", "write_capacity", "item_count", "size_bytes", "read_units_30d", "write_units_30d", "monthly_usd", "open_recs", "findings", "created"];
export function listDynamodb(f: { q?: string; sort?: string; gone?: boolean; scope?: AccountScope | null } = {}) {
  const where: string[] = []; const params: unknown[] = [];
  if (f.scope) { const a = accountWhere(f.scope); where.push(a.sql); params.push(...a.params); }
  if (!f.gone) where.push("gone = 0");
  if (f.q) { where.push("(name like ? or region like ? or billing_mode like ? or arn like ?)"); params.push(`%${f.q}%`, `%${f.q}%`, `%${f.q}%`, `%${f.q}%`); }
  const desc = f.sort?.startsWith("-"); const col = (f.sort || "").replace(/^-/, "");
  const order = SORTS.includes(col) ? `order by ${col} ${desc ? "desc" : "asc"} nulls last` : "order by monthly_usd desc, size_bytes desc";
  return (db.prepare(`select * from inventory_dynamodb ${where.length ? `where ${where.join(" and ")}` : ""} ${order} limit 2000`).all(...params) as any[]).map((r) => ({ ...r, tags: json(r.tags) || {} }));
}
export function dynamodbSummary(scope?: AccountScope | null) {
  const r = scopedStmt(scope, `select count(*) as total, coalesce(sum(billing_mode = 'PAY_PER_REQUEST'), 0) as on_demand, coalesce(sum(size_bytes), 0) / 1e9 as gb, coalesce(sum(item_count), 0) as items,
      coalesce(sum(monthly_usd), 0) as monthly_usd, coalesce(sum(storage_usd), 0) as storage_usd, coalesce(sum(capacity_usd), 0) as capacity_usd,
      coalesce(sum(read_units_30d > 0 or write_units_30d > 0), 0) as active, coalesce(sum(open_recs), 0) as open_recs, coalesce(sum(findings), 0) as findings
    from inventory_dynamodb where gone = 0`).get() as Record<string, number>;
  const gone = (scopedStmt(scope, "select count(*) as n from inventory_dynamodb where gone = 1").get() as { n: number }).n;
  const out: Record<string, number> = { gone };
  for (const [k, v] of Object.entries(r)) out[k] = typeof v === "number" ? Math.round(v * 100) / 100 : Number(v) || 0;
  return out;
}

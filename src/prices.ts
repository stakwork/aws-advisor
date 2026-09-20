import { db } from "./db.js";
import { describeError } from "./permissions.js";
import { S, query } from "./steampipe.js";

/**
 * On-demand prices from the AWS price list (aws_pricing_product), shared by the MCP price_lookup tool and
 * the inventory. The inventory keeps a 7-day cache in the `prices` table so a refresh only hits the pricing
 * API for SKUs it has not seen; the MCP tool always asks live.
 */

export type PriceKind = "ec2" | "rds" | "elasticache";
export const PRICE_TTL_DAYS = 7;
export const HOURS_PER_MONTH = 730;

export interface PriceSpec {
  kind: PriceKind;
  /** EC2 instance type, RDS instance class or ElastiCache node type. */
  instance_type: string;
  region: string;
  /** ec2: Linux, Windows, RHEL, SUSE */
  operating_system?: string;
  /** rds: PostgreSQL, Aurora PostgreSQL, MySQL...; elasticache: Redis, Memcached, Valkey. Omit to list all. */
  engine?: string;
  /** rds: Single-AZ or Multi-AZ */
  deployment?: string;
}

export interface PriceRow {
  hourly_usd: number;
  monthly_usd: number;
  unit: string;
  currency: string;
  description: string;
  attributes: Record<string, string>;
}

const lit = (s: string) => `'${s.replace(/'/g, "''")}'`;

/** The service code and the `filters` JSON the pricing table expects for a spec. */
export function priceFilters(a: PriceSpec): { service: string; filters: Record<string, string> } {
  const filters: Record<string, string> = { regionCode: a.region, instanceType: a.instance_type };
  let service = "";
  if (a.kind === "ec2") { service = "AmazonEC2"; Object.assign(filters, { operatingSystem: a.operating_system || "Linux", tenancy: "Shared", preInstalledSw: "NA", capacitystatus: "Used" }); }
  else if (a.kind === "rds") { service = "AmazonRDS"; Object.assign(filters, { deploymentOption: a.deployment || "Single-AZ" }); if (a.engine) filters.databaseEngine = a.engine; }
  else { service = "AmazonElastiCache"; if (a.engine) filters.cacheEngine = a.engine; }
  return { service, filters };
}

const KEEP_ATTRIBUTES = ["instanceType", "operatingSystem", "licenseModel", "databaseEngine", "databaseEdition", "deploymentOption", "cacheEngine", "usagetype", "vcpu", "memory", "location"];

/** Live lookup: every matching on-demand row, cheapest first, extended-support rows dropped. */
export async function fetchPrices(a: PriceSpec): Promise<{ service: string; filters: Record<string, string>; prices: PriceRow[] }> {
  const { service, filters } = priceFilters(a);
  const sql = `
    select price_per_unit, unit, currency, description, attributes
    from ${S}.aws_pricing_product
    where service_code = ${lit(service)} and term = 'OnDemand' and filters = ${lit(JSON.stringify(filters))}`;
  const rows = await query<{ price_per_unit: string; unit: string; currency: string; description: string; attributes: Record<string, string> }>(sql);
  const prices = rows
    .filter((r) => !/ExtendedSupport/i.test(r.attributes?.usagetype || ""))
    .map((r) => {
      const hourly = Number(r.price_per_unit);
      return { hourly_usd: hourly, monthly_usd: Math.round(hourly * HOURS_PER_MONTH * 100) / 100, unit: r.unit, currency: r.currency, description: r.description,
        attributes: Object.fromEntries(KEEP_ATTRIBUTES.filter((k) => r.attributes?.[k] != null).map((k) => [k, r.attributes[k]])) };
    })
    .sort((x, y) => x.hourly_usd - y.hourly_usd);
  return { service, filters, prices };
}

// ---- mapping resource attributes to price-list names ----------------------------------------------

/** EC2 `platform` / `platform_details` to the price list's operatingSystem. */
export function ec2OperatingSystem(platform: string | null | undefined, platformDetails: string | null | undefined): string {
  const d = `${platform || ""} ${platformDetails || ""}`;
  if (/windows/i.test(d)) return "Windows";
  if (/red hat|rhel/i.test(d)) return "RHEL";
  if (/suse/i.test(d)) return "SUSE";
  return "Linux";
}

const RDS_ENGINES: Record<string, string> = {
  postgres: "PostgreSQL", "aurora-postgresql": "Aurora PostgreSQL", mysql: "MySQL", "aurora-mysql": "Aurora MySQL", aurora: "Aurora MySQL",
  mariadb: "MariaDB", oracle: "Oracle", "oracle-ee": "Oracle", "oracle-se2": "Oracle", "oracle-se": "Oracle", "oracle-se1": "Oracle",
  sqlserver: "SQL Server", "sqlserver-ee": "SQL Server", "sqlserver-se": "SQL Server", "sqlserver-ex": "SQL Server", "sqlserver-web": "SQL Server",
};

/** RDS `engine` to the price list's databaseEngine (null when unknown). */
export const rdsPricingEngine = (engine: string | null | undefined): string | null => (engine ? RDS_ENGINES[engine.toLowerCase()] ?? null : null);

/** ElastiCache `engine` to the price list's cacheEngine. */
export const elasticachePricingEngine = (engine: string | null | undefined): string | null => {
  const e = (engine || "").toLowerCase();
  return e === "redis" ? "Redis" : e === "memcached" ? "Memcached" : e === "valkey" ? "Valkey" : null;
};

// ---- cache -----------------------------------------------------------------------------------------

/** One cache entry to make sure of. `engine` is the cache key label (may carry Multi-AZ / IO-Optimized); `spec` is what is queried. */
export interface PriceWant {
  kind: PriceKind;
  sku: string;
  region: string;
  engine: string;
  spec: PriceSpec;
  /** rds only: pick the Aurora I/O-Optimized instance price instead of the standard one */
  ioOptimized?: boolean;
}

export interface CachedPrice { hourly: number | null; monthly: number | null; fetched_at: string }

const selectPrice = db.prepare("select hourly, monthly, fetched_at from prices where kind = ? and sku = ? and region = ? and engine = ?");
const upsertPrice = db.prepare(`
  insert into prices(kind, sku, region, engine, hourly, monthly, fetched_at) values (?, ?, ?, ?, ?, ?, datetime('now'))
  on conflict(kind, sku, region, engine) do update set hourly = excluded.hourly, monthly = excluded.monthly, fetched_at = excluded.fetched_at`);

export const priceKey = (w: { kind: string; sku: string; region: string; engine: string }) => `${w.kind}|${w.sku}|${w.region}|${w.engine}`;

export function getCachedPrice(kind: PriceKind, sku: string, region: string, engine: string): CachedPrice | null {
  return (selectPrice.get(kind, sku, region, engine) as CachedPrice | undefined) ?? null;
}

const isFresh = (fetchedAt: string) => Date.now() - new Date(fetchedAt.endsWith("Z") ? fetchedAt : fetchedAt + "Z").getTime() < PRICE_TTL_DAYS * 86400_000;

/** Picks the hourly price for one spec out of the rows the price list returned. */
export function chooseHourly(rows: PriceRow[], w: PriceWant): number | null {
  // The price list also carries add-ons under the same filters (SyncDurability-NodeUsage, ExtendedSupport,
  // Multi-AZ usage...). Only the plain instance-hour usage type is the instance price; a region prefix (USE1-) is fine.
  const usage = (r: PriceRow) => r.attributes.usagetype || "";
  const plain = (name: string) => new RegExp(`^(?:[A-Z0-9]+-)?${name}:`, "i"); // "BoxUsage:m6i.xlarge" or "USE1-BoxUsage:m6i.xlarge", never "USE1-SyncDurability-NodeUsage:..."
  let candidates = rows;
  if (w.kind === "rds") {
    const instance = rows.filter((r) => plain("InstanceUsage(?:IOOptimized)?").test(usage(r)));
    if (instance.length) candidates = instance;
    const io = (r: PriceRow) => /IOOptimized/i.test(usage(r));
    const tier = candidates.filter((r) => io(r) === Boolean(w.ioOptimized));
    if (tier.length || w.ioOptimized) candidates = tier;
  } else if (w.kind === "ec2") {
    const box = rows.filter((r) => plain("BoxUsage").test(usage(r)));
    if (box.length) candidates = box;
  } else {
    const node = rows.filter((r) => plain("NodeUsage").test(usage(r)));
    if (node.length) candidates = node;
  }
  const ok = candidates.filter((r) => Number.isFinite(r.hourly_usd) && r.hourly_usd > 0);
  return ok.length ? ok[0].hourly_usd : null;
}

/**
 * Makes sure every wanted (kind, sku, region, engine) has a cache row younger than PRICE_TTL_DAYS, fetching
 * the rest from the price list one distinct SKU at a time. Returns the prices keyed by priceKey and how many
 * were fetched. A lookup that finds nothing is cached as null so it is not retried on every refresh.
 */
export async function ensurePrices(wants: PriceWant[], onError?: (msg: string) => void): Promise<{ prices: Map<string, CachedPrice>; fetched: number }> {
  const prices = new Map<string, CachedPrice>();
  const distinct = new Map<string, PriceWant>();
  for (const w of wants) if (!distinct.has(priceKey(w))) distinct.set(priceKey(w), w);
  let fetched = 0;
  for (const [key, w] of distinct) {
    const cached = getCachedPrice(w.kind, w.sku, w.region, w.engine);
    if (cached && isFresh(cached.fetched_at)) { prices.set(key, cached); continue; }
    try {
      const { prices: rows } = await fetchPrices(w.spec);
      const hourly = chooseHourly(rows, w);
      const monthly = hourly == null ? null : Math.round(hourly * HOURS_PER_MONTH * 100) / 100;
      upsertPrice.run(w.kind, w.sku, w.region, w.engine, hourly, monthly);
      fetched++;
      prices.set(key, { hourly, monthly, fetched_at: new Date().toISOString() });
    } catch (e: any) {
      onError?.(`price ${w.kind} ${w.sku} ${w.region} ${w.engine}: ${describeError(e, "price list (aws_pricing_product)", 200)}`);
      if (cached) prices.set(key, cached); // stale is better than nothing
    }
  }
  return { prices, fetched };
}

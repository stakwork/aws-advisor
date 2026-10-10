/**
 * The graph's own schema, written the way Jarvis keeps one: a (:Schema {type, parent, domain, node_key, title_key,
 * type_description, <attribute>: 'string' | '?int' | ...}) node per label, (:Schema)-[:CHILD_OF]->(:Schema) up to
 * Jarvis's root Thing (resource labels under AdvisorResource), and one (:Schema)-[:<EDGE_TYPE> {<attribute>: '?type'}]->
 * (:Schema) per (source label, relationship, target label) the graph holds. It is read from the graph itself after a
 * sync, not declared, so it is always what we have: a label, property or edge appears when the mirror first writes it
 * and goes when the last one is gone (node schemas are soft-deleted with is_deleted, as Jarvis does; edge schemas are
 * removed). Ours are the Schema nodes of domain Cloud; Thing and every other domain's schema are never touched.
 */
import { enabled, readQuery, writeCypher, logError, LEGACY_LABELS, SCHEMA_DOMAIN } from "./graph_mirror.js";

export { SCHEMA_DOMAIN };
const ROOT = "Thing";
const BASE = "AdvisorResource";

/**
 * Property names Jarvis reads as the schema's own fields (ApplicationConstant.SCHEMA_KNOWN_PROPERTIES plus ref_id and
 * is_deleted): a node attribute by one of these names would overwrite the field (a GuardDuty finding's `type`,
 * an AdvisorRecommendation's `action` is not a Jarvis action list), so they are listed in the
 * description instead.
 */
const JARVIS_FIELDS = new Set(["type", "parent", "attributes", "icon", "media_url", "source_link", "primary_color", "secondary_color", "shape", "index", "node_key",
  "conditional_formatting", "action", "type_description", "description", "display_name", "title_key", "description_key", "paid_properties", "domain", "vector_index",
  "volatility", "ref_id", "is_deleted"]);

/** One line per label for the type_description; a label the mirror starts writing without one gets a generic line until it is added here. */
const DESCRIPTIONS: Record<string, string> = {
  AdvisorAccount: "A cloud account, team or project the advisor collects from, or the site of the local machines; resources, runs and scans hang off it with IN_ACCOUNT",
  AdvisorResource: "Base label of every inventoried cloud resource; provider, account_id and native_type say what it is at the provider (native_id where its id there differs)",
  AdvisorBox: "A machine: a cloud instance (EC2), a platform's hidden runtime (Vercel, opaque) or a local laptop, desktop or server; it HOSTS one AdvisorCompute",
  AdvisorCompute: "The operating system a box runs: programs, containers, packages and vulnerabilities hang off it, and deployments RUNS_ON it",
  AdvisorDatabase: "A managed database instance or store (RDS, Aurora, DynamoDB, a Vercel Neon store)",
  AdvisorCache: "A managed cache node or group (ElastiCache, a Vercel Redis store)",
  AdvisorLoadBalancer: "A load balancer (application, network, gateway or classic)",
  AdvisorFunction: "A serverless function (Lambda)",
  AdvisorStorage: "Object, block, file or backup storage (S3 bucket, EBS volume, EFS file system, backup vault, a Vercel Blob store)",
  AdvisorDeployment: "A deployed application environment (Elastic Beanstalk environment, cluster workload, Vercel project, something declared on a local machine); RUNS_ON the compute it runs on",
  AdvisorDnsZone: "A DNS hosted zone",
  AdvisorDnsRecord: "A DNS record in a zone and what it points to",
  AdvisorIdentity: "Who can get in: an IAM user or role, an Identity Center user, the root user, a Vercel team member",
  AdvisorCertificate: "A TLS certificate (ACM) and what terminates TLS with it",
  AdvisorMessaging: "A messaging topic (SNS) and where it delivers",
  AdvisorSecret: "An encryption key (KMS) and what it encrypts",
  AdvisorAnalytics: "A query engine workgroup (Athena)",
  AdvisorStack: "An infrastructure-as-code stack (CloudFormation) and the resources it manages",
  AdvisorBackupPlan: "A backup plan, the vaults it stores in and the resources it protects",
  AdvisorDetector: "A threat detection service (GuardDuty detector)",
  AdvisorFilter: "A traffic filter: security group, network ACL or web ACL, with its rules",
  AdvisorFilterRule: "One allow or deny rule of a filter",
  AdvisorResourceRef: "A resource some record names that the inventory has no node for, created on demand",
  AdvisorNodePool: "A group of interchangeable compute (autoscaling group, Karpenter pool, node group, Beanstalk group), with its usage profile and capacity pattern",
  AdvisorTelemetry: "A source the advisor sees resources through (API, metrics, SSM probe, logs, audit trail, bill); the OBSERVED_BY edge says what it covers",
  AdvisorRecommendation: "A recommendation the rules or the agent made, with its tier, status and decision",
  AdvisorRun: "A collection or rules run",
  AdvisorControl: "A benchmark or advisor control (cost, CIS, foundational security) and the resources it flagged",
  AdvisorAlert: "An alert raised on a resource",
  AdvisorIncident: "An incident grouping alerts",
  AdvisorAction: "An executor action: every change the advisor proposed, applied, verified or reverted",
  AdvisorPass: "One observe pass of the monitor",
  AdvisorAgentRun: "One request to the repo2graph agent (findings review, morning observation, investigation, chat turn) and what it was about",
  AdvisorApp: "A program or container running on a box, from the probe's process list",
  AdvisorEndpoint: "Something listening: a port on a box, a balancer listener, a database endpoint, a function URL, a cluster API",
  AdvisorPressureEvent: "A capacity pressure event on a pool and the action that answered it",
  AdvisorSecurityScan: "A security scan run (compliance benchmark)",
  AdvisorPackage: "An installed software package seen on a box",
  AdvisorImage: "A container image and the repository and revision it is built from",
  AdvisorContainer: "A Docker container on a box, kept by name",
  AdvisorNotification: "A notification the provider sent the account (AWS User Notifications)",
  AdvisorThreatFinding: "A threat detection finding and the resource it is about",
  AdvisorCredential: "A credential an identity holds: password, access key, MFA device, passkey, API token",
  AdvisorPerson: "The person (or machine) behind one or more identities across providers, matched by name or e-mail",
  AdvisorPolicy: "An IAM policy (AWS managed, customer managed or inline) graded by access level per service",
  AdvisorGroup: "An IAM group: the policies its users share",
  AdvisorPermissionSet: "An Identity Center permission set and the role it is provisioned as in each account",
  AdvisorRepository: "A source repository: read from the GitHub org (who can access it, its deploy keys and secrets) or named by a cloud role's GitHub Actions OIDC trust (its pipelines may assume the role)",
  AdvisorClient: "A client identities sign in or call with (browser, CLI, SDK, IaC tool) on a platform",
  AdvisorSource: "An address or range traffic and sign-ins come from (the internet, a CIDR, a prefix list)",
  AdvisorNetwork: "A virtual network (VPC)",
  AdvisorSegment: "A subnet",
  AdvisorRouteTable: "A route table and its routes",
  AdvisorGateway: "A network gateway (internet, NAT, transit, VPC endpoint)",
  AdvisorInterface: "A network interface",
  AdvisorPublicIp: "A public IP address",
  AdvisorCluster: "A container cluster (EKS, ECS) and its control plane",
  KnSystem: "Knowledge layer: one of our systems as a schematic (an instance, a pool, a database cluster, a cache group)",
  KnArchetype: "Knowledge layer: the role a resource or system plays (web or API, worker, blockchain node, ...)",
  KnSystemType: "Knowledge layer: a priced unit (instance type, plan, usage rate) and where its price comes from",
  KnPricingOverlay: "Knowledge layer: a pricing overlay (commitment, discount) on system types",
  KnLogGroup: "Knowledge layer: a log group or drain, its volume and cost, and the system it is attributed to",
  KnDestination: "Knowledge layer: where traffic or data goes",
  KnSource: "Knowledge layer: where traffic or data comes from",
  KnPlaybook: "Knowledge layer: the playbook for a control, generated from its official sources",
  KnVulnerability: "A published vulnerability advisory (OSV, ALAS) and the packages it affects; shared across accounts",
};

export type AttrType = "string" | "int" | "float" | "boolean" | "list" | "complex";

/** Jarvis's attribute type of a sample of one property's values (as they come back from a read: integers as numbers, dates as strings). */
export function attrType(values: unknown[]): AttrType {
  const kinds = new Set(values.filter((v) => v !== null && v !== undefined).map((v) => Array.isArray(v) ? "list" : typeof v === "number" ? (Number.isInteger(v) ? "int" : "float") : typeof v));
  if (kinds.has("int") && kinds.has("float")) { kinds.delete("int"); }
  if (kinds.size !== 1) return kinds.size === 0 ? "string" : "complex";
  const k = [...kinds][0];
  return k === "list" || k === "int" || k === "float" || k === "boolean" || k === "string" ? k : "complex";
}

/** The label a node is filed under: its own Advisor/Kn labels without the base one, or the base one when it has nothing else. */
export function specificLabels(labels: string[], ours: (l: string) => boolean = isOurs): string[] {
  const own = labels.filter(ours);
  const specific = own.filter((l) => l !== BASE);
  return specific.length ? specific : own;
}

export const isOurs = (l: string) => (l.startsWith("Advisor") || l.startsWith("Kn")) && !(LEGACY_LABELS as readonly string[]).includes(l);
const RELTYPE = /^[A-Z][A-Z0-9_]*$/;

export interface LabelSample { label: string; total: number; under_base: number; props: { key: string; count: number; values: unknown[] }[] }
export interface EdgeSample { source_labels: string[]; type: string; target_labels: string[]; key: string | null; count: number; values: unknown[] }
export interface NodeSchema { type: string; parent: string; props: Record<string, unknown> }
export interface EdgeSchema { source: string; target: string; type: string; props: Record<string, string> }

/** The schema nodes and edges for what was sampled (pure, so it is tested without a graph). */
export function buildSchema(labels: LabelSample[], edges: EdgeSample[]): { nodes: NodeSchema[]; edges: EdgeSchema[] } {
  const attrs = new Map<string, Record<string, string>>();
  const skipped = new Map<string, string[]>();
  for (const l of labels) {
    const a: Record<string, string> = {}; const s: string[] = [];
    for (const p of l.props) {
      if (JARVIS_FIELDS.has(p.key)) { s.push(p.key); continue; }
      a[p.key] = `${p.count >= l.total ? "" : "?"}${attrType(p.values)}`;
    }
    attrs.set(l.label, a); skipped.set(l.label, s.sort());
  }
  const parentOf = (l: LabelSample) => l.label !== BASE && attrs.has(BASE) && l.under_base * 2 > l.total ? BASE : ROOT;
  // every resource node also carries the base label, so the base's sample holds every subtype's properties: it declares
  // only the ones more than half the resource types share (id, name, state, region, monthly_usd ...), the rest stay with
  // the subtypes that have them
  const children = labels.filter((l) => parentOf(l) === BASE);
  const shared = (key: string) => children.length === 0 || children.filter((c) => c.props.some((p) => p.key === key)).length * 2 > children.length;
  if (attrs.has(BASE)) attrs.set(BASE, Object.fromEntries(Object.entries(attrs.get(BASE)!).filter(([k]) => shared(k))));
  const baseAttrs = attrs.get(BASE) ?? {};
  const nodes: NodeSchema[] = labels.map((l) => {
    const parent = parentOf(l);
    const own = attrs.get(l.label)!;
    // a subtype states only what it adds: what the base declares is inherited through CHILD_OF, as Jarvis resolves it
    const declared = parent === BASE ? Object.fromEntries(Object.entries(own).filter(([k]) => !(k in baseAttrs))) : own;
    const also = skipped.get(l.label)!;
    const description = `${DESCRIPTIONS[l.label] ?? `Cloud Advisor ${l.label.replace(/^(Advisor|Kn)/, "")} nodes`}.${also.length ? ` Also carries ${also.join(", ")} (not listed: Jarvis reserves the names).` : ""}`;
    const props: Record<string, unknown> = {
      ...declared, type: l.label, parent, domain: SCHEMA_DOMAIN, node_key: `${l.label.toLowerCase()}-id`,
      title_key: "name" in own || (parent === BASE && "name" in baseAttrs) ? "name" : "id", type_description: description, is_deleted: false,
    };
    return { type: l.label, parent, props };
  });
  const known = new Set(labels.map((l) => l.label));
  const byTriple = new Map<string, EdgeSchema & { samples: Map<string, unknown[]> }>();
  for (const e of edges) {
    if (!RELTYPE.test(e.type) || e.type === "CHILD_OF") continue;
    for (const source of specificLabels(e.source_labels)) for (const target of specificLabels(e.target_labels)) {
      if (!known.has(source) || !known.has(target)) continue;
      const k = `${source}|${e.type}|${target}`;
      const t = byTriple.get(k) ?? { source, target, type: e.type, props: {}, samples: new Map() };
      if (e.key && !JARVIS_FIELDS.has(e.key)) t.samples.set(e.key, [...(t.samples.get(e.key) ?? []), ...e.values]);
      byTriple.set(k, t);
    }
  }
  const out = [...byTriple.values()].map(({ samples, ...e }) => ({ ...e, props: Object.fromEntries([...samples].map(([k, v]) => [k, `?${attrType(v)}`])) }));
  return { nodes: nodes.sort((a, b) => a.type.localeCompare(b.type)), edges: out.sort((a, b) => `${a.source}${a.type}${a.target}`.localeCompare(`${b.source}${b.type}${b.target}`)) };
}

const VALUES_PER_KEY = 20;
const READ = { timeoutMs: 60_000, rowCap: 100_000 };

/** Every Advisor and Kn label in the graph, with each property's count and a sample of its values. */
async function sampleLabels(): Promise<LabelSample[]> {
  const names = (await readQuery("CALL db.labels() YIELD label RETURN label", {}, READ)).rows.map((r) => String(r.label)).filter(isOurs);
  const out: LabelSample[] = [];
  for (const label of names) {
    const head = (await readQuery(`MATCH (n:\`${label}\`) RETURN count(n) AS total, count(CASE WHEN n:${BASE} THEN 1 END) AS under_base`, {}, READ)).rows[0];
    const total = Number(head?.total ?? 0);
    if (!total) continue;
    const props = await readQuery(`MATCH (n:\`${label}\`) UNWIND keys(n) AS k WITH k, count(*) AS c, collect(n[k])[..${VALUES_PER_KEY}] AS vals RETURN k, c, vals`, {}, READ);
    out.push({ label, total, under_base: Number(head?.under_base ?? 0), props: props.rows.map((r) => ({ key: String(r.k), count: Number(r.c), values: r.vals as unknown[] })) });
  }
  return out;
}

/** Every relationship leaving one of our nodes, grouped by the labels at both ends, with each relationship property's sample. */
async function sampleEdges(labels: string[]): Promise<EdgeSample[]> {
  const out: EdgeSample[] = [];
  for (const label of labels) {
    const r = await readQuery(`MATCH (a:\`${label}\`)-[r]->(b) WITH labels(a) AS al, type(r) AS t, labels(b) AS bl, r
      UNWIND (CASE WHEN size(keys(r)) = 0 THEN [null] ELSE keys(r) END) AS k
      WITH al, t, bl, k, count(*) AS c, collect(CASE WHEN k IS NULL THEN null ELSE r[k] END)[..${VALUES_PER_KEY}] AS vals RETURN al, t, bl, k, c, vals`, {}, READ);
    for (const row of r.rows) {
      const al = row.al as string[];
      if (!specificLabels(al).includes(label)) continue; // the same edge is read once, from the label it is filed under
      out.push({ source_labels: al, type: String(row.t), target_labels: row.bl as string[], key: row.k == null ? null : String(row.k), count: Number(row.c), values: row.vals as unknown[] });
    }
  }
  return out;
}

export interface SchemaCounts { node_schemas: number; edge_schemas: number; retired: number; took_ms: number }

/** Reads the graph and writes its schema; idempotent, ref_ids are kept across runs. */
export async function mirrorSchema(): Promise<SchemaCounts | null> {
  if (!enabled()) return null;
  const t0 = Date.now();
  const labels = await sampleLabels();
  if (!labels.length) return { node_schemas: 0, edge_schemas: 0, retired: 0, took_ms: Date.now() - t0 }; // an empty graph (mid-wipe) retires nothing
  const { nodes, edges } = buildSchema(labels, await sampleEdges(labels.map((l) => l.label)));
  // Jarvis seeds Thing on boot; a graph Jarvis never ran on gets the bare root so the hierarchy has somewhere to hang
  await writeCypher("MERGE (t:Schema {type: $root}) ON CREATE SET t.name = 'string', t.node_key = 'thing-name', t.title_key = 'name', t.description_key = 'description', t.ref_id = randomUUID(), t.is_deleted = false", { root: ROOT });
  await writeCypher(`UNWIND $rows AS row MERGE (s:Schema {type: row.type}) WITH s, row, s.ref_id AS rid SET s = row.props SET s.ref_id = coalesce(rid, randomUUID())`, { rows: nodes.map((n) => ({ type: n.type, props: n.props })) });
  await writeCypher(`UNWIND $rows AS row MATCH (c:Schema {type: row.type})-[l:CHILD_OF]->(p:Schema) WHERE p.type <> row.parent DELETE l`, { rows: nodes });
  await writeCypher(`UNWIND $rows AS row MATCH (c:Schema {type: row.type}), (p:Schema {type: row.parent}) MERGE (c)-[l:CHILD_OF]->(p) ON CREATE SET l.ref_id = randomUUID()`, { rows: nodes.map((n) => ({ type: n.type, parent: n.parent })) });
  const types = nodes.map((n) => n.type);
  await writeCypher(`MATCH (s:Schema {domain: $domain}) WHERE NOT s.type IN $types SET s.is_deleted = true`, { domain: SCHEMA_DOMAIN, types });
  const byType = new Map<string, EdgeSchema[]>();
  for (const e of edges) byType.set(e.type, [...(byType.get(e.type) ?? []), e]);
  for (const [type, rows] of byType) {
    await writeCypher(`UNWIND $rows AS e MATCH (s:Schema {type: e.source, domain: $domain}), (t:Schema {type: e.target, domain: $domain}) MERGE (s)-[r:\`${type}\`]->(t) WITH r, e, r.ref_id AS rid SET r = e.props SET r.ref_id = coalesce(rid, randomUUID())`, { rows, domain: SCHEMA_DOMAIN });
  }
  // edge schemas between our schemas that the graph no longer holds
  const keep = edges.map((e) => `${e.source}|${e.type}|${e.target}`);
  await writeCypher(`MATCH (s:Schema {domain: $domain})-[r]->(t:Schema {domain: $domain}) WHERE type(r) <> 'CHILD_OF' AND NOT (s.type + '|' + type(r) + '|' + t.type) IN $keep DELETE r`, { domain: SCHEMA_DOMAIN, keep });
  const retired = Number((await readQuery(`MATCH (s:Schema {domain: $domain}) WHERE s.is_deleted = true RETURN count(s) AS n`, { domain: SCHEMA_DOMAIN }, READ)).rows[0]?.n ?? 0);
  return { node_schemas: nodes.length, edge_schemas: edges.length, retired, took_ms: Date.now() - t0 };
}

let inFlight = false;
/** After a sync or a knowledge refresh; overlapping triggers are dropped (the next one reads the graph again). */
export function mirrorSchemaInBackground(why: string): void {
  if (!enabled() || inFlight) return;
  inFlight = true;
  mirrorSchema().then((c) => { if (c) console.log(`[graph] schema refreshed after ${why}: ${c.node_schemas} node types, ${c.edge_schemas} edge types, ${c.took_ms} ms`); })
    .catch((e) => logError(`schema mirror (${why})`, e)).finally(() => { inFlight = false; });
}

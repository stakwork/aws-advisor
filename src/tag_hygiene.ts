/**
 * Tag hygiene: which resources lack the tags the team relies on (owner and env by default, Settings ›
 * Inventory › TAG_KEYS_REQUIRED), with a suggested value for each from the name and the tags already there, and
 * which EC2 instances could opt into the executor's parking (`advisor:park=auto`) or office hours
 * (`advisor:schedule`) but carry no tag yet. Tags come straight from Steampipe (the inventories do not keep them).
 * One report-tier recommendation per resource kind carries the list and the CLI shape to fix it; the executor
 * never writes tags: naming an owner is a decision for a person.
 */
import { db } from "./db.js";
import { config } from "./config.js";
import { S, query } from "./steampipe.js";
import { describeError } from "./permissions.js";
import { upsertRecommendations } from "./collector.js";
import type { RecInput } from "./rules.js";

db.exec(`create table if not exists tag_hygiene (
  resource text primary key, kind text not null, name text, region text, account_id text,
  tags text, missing text not null, suggested text, checked_at text not null
);
create index if not exists tag_hygiene_kind on tag_hygiene(kind);
create table if not exists tag_optin (
  resource text primary key, name text, region text, state text, opt text not null, tag text not null, checked_at text not null
)`);

export const DEFAULT_REQUIRED = "owner,env";
/** Keys that count as the same thing: a resource tagged `Environment` has its env. Matching is case-insensitive. */
export const TAG_ALIASES: Record<string, string[]> = {
  env: ["env", "environment", "stage"],
  owner: ["owner", "team", "owner-team", "maintainer"],
};
export const PARK_TAG = "advisor:park";
export const SCHEDULE_TAG = "advisor:schedule";
export const SUGGESTED_SCHEDULE = "weekdays 08-20";
const ROW_CAP = 500;
const REC_NAMES = 10;

export type Tags = Record<string, string | null | undefined>;

/** The required keys from the setting: lower-cased, de-duplicated, never empty. */
export function parseRequired(setting: string | null | undefined): string[] {
  const keys = String(setting ?? DEFAULT_REQUIRED).split(",").map((k) => k.trim().toLowerCase()).filter(Boolean);
  return keys.length ? [...new Set(keys)] : DEFAULT_REQUIRED.split(",");
}
const requiredKeys = () => parseRequired((config as unknown as Record<string, unknown>).tagKeysRequired as string | undefined);

/** The tags as a lower-cased key map (Steampipe hands back an object or a JSON string; a list of {Key, Value} appears on some tables). */
export function normaliseTags(raw: unknown): Record<string, string> {
  let v: unknown = raw;
  if (typeof v === "string") { try { v = JSON.parse(v); } catch { return {}; } }
  const out: Record<string, string> = {};
  if (Array.isArray(v)) { for (const t of v) if (t && typeof t === "object" && "Key" in t) out[String((t as any).Key).toLowerCase()] = String((t as any).Value ?? ""); return out; }
  if (v && typeof v === "object") for (const [k, val] of Object.entries(v as Record<string, unknown>)) out[k.toLowerCase()] = val == null ? "" : String(val);
  return out;
}

/** Which required keys the tags do not carry (under any alias, any case, with a non-empty value). Pure. */
export function missingTags(tags: Tags | null | undefined, required: string[]): string[] {
  const have = new Set(Object.entries(tags ?? {}).filter(([, v]) => v != null && String(v).trim() !== "").map(([k]) => k.toLowerCase()));
  return required.filter((key) => !(TAG_ALIASES[key] ?? [key]).some((alias) => have.has(alias)));
}

export interface TagSubject { kind: string; name: string | null | undefined; tags: Tags | null | undefined; pool_kind?: string | null; role?: string | null }

const ENV_WORDS: [RegExp, string][] = [
  [/\b(prod|production|prd|live)\b|[-_.](prod|production|prd)([-_.]|$)/i, "prod"],
  [/\b(staging|stage|stg|preprod|uat)\b|[-_.](staging|stage|stg)([-_.]|$)/i, "staging"],
  [/\b(dev|develop|development|sandbox)\b|[-_.](dev|develop)([-_.]|$)/i, "dev"],
  [/\b(test|testing|qa|demo)\b|[-_.](test|qa|demo)([-_.]|$)/i, "test"],
  [/swarm/i, "customer"],
];
const NOT_AN_OWNER = new Set(["prod", "production", "staging", "stage", "dev", "test", "qa", "demo", "swarm", "aws", "arn", "the", "my", "new", "old", "tmp", "temp", "app", "api", "web", "db", "eks", "ecs", "rds", "ec2", "s3"]);

/** Suggested values for the missing keys, from the tags already there and the name; empty when nothing says. Pure. */
export function suggestTags(r: TagSubject, missing: string[] = ["owner", "env"]): Record<string, string> {
  const tags = normaliseTags(r.tags ?? {});
  const name = String(r.name ?? "");
  const out: Record<string, string> = {};
  if (missing.includes("env")) {
    const fromTag = ["environment", "env", "stage", "tier"].map((k) => tags[k]).find((v) => v);
    const fromName = ENV_WORDS.find(([re]) => re.test(name))?.[1];
    const fromRole = r.role === "dev_or_test" ? "dev" : null;
    const v = fromTag || fromName || fromRole;
    if (v) out.env = v.toLowerCase();
  }
  if (missing.includes("owner")) {
    const fromTag = ["team", "owner", "created-by", "createdby", "creator", "maintainer", "project", "service"].map((k) => tags[k]).find((v) => v && !/^arn:/i.test(v));
    const prefix = name.split(/[-_.\s/]/)[0]?.toLowerCase() ?? "";
    const fromName = prefix.length >= 3 && /^[a-z][a-z0-9]*$/.test(prefix) && !NOT_AN_OWNER.has(prefix) ? prefix : null;
    const v = fromTag || fromName;
    if (v) out.owner = v;
  }
  return out;
}

interface Source { kind: string; sql: string }
/** Every table read for tags; each is one Steampipe query, so a table the credentials cannot read only costs a note. */
const SOURCES: Source[] = [
  { kind: "ec2", sql: `select instance_id as id, tags ->> 'Name' as name, tags, region, account_id, instance_state as state from ${S}.aws_ec2_instance where instance_state <> 'terminated'` },
  { kind: "ebs", sql: `select volume_id as id, tags ->> 'Name' as name, tags, region, account_id, state from ${S}.aws_ebs_volume` },
  { kind: "rds", sql: `select db_instance_identifier as id, db_instance_identifier as name, tags, region, account_id, status as state from ${S}.aws_rds_db_instance` },
  { kind: "rds_cluster", sql: `select db_cluster_identifier as id, db_cluster_identifier as name, tags, region, account_id, status as state from ${S}.aws_rds_db_cluster` },
  { kind: "s3", sql: `select name as id, name, tags, region, account_id, null as state from ${S}.aws_s3_bucket` },
  { kind: "lambda", sql: `select name as id, name, tags, region, account_id, state from ${S}.aws_lambda_function` },
  { kind: "dynamodb", sql: `select name as id, name, tags, region, account_id, table_status as state from ${S}.aws_dynamodb_table` },
  { kind: "alb", sql: `select name as id, name, tags, region, account_id, state_code as state from ${S}.aws_ec2_application_load_balancer` },
  { kind: "nlb", sql: `select name as id, name, tags, region, account_id, state_code as state from ${S}.aws_ec2_network_load_balancer` },
  { kind: "log_group", sql: `select name as id, name, tags, region, account_id, null as state from ${S}.aws_cloudwatch_log_group where name not like '/aws/%'` },
  { kind: "ecr", sql: `select repository_name as id, repository_name as name, tags, region, account_id, null as state from ${S}.aws_ecr_repository` },
];
export const KIND_LABEL: Record<string, string> = { ec2: "EC2 instance", ebs: "EBS volume", rds: "RDS instance", rds_cluster: "RDS cluster", s3: "S3 bucket", lambda: "Lambda function", dynamodb: "DynamoDB table", alb: "application load balancer", nlb: "network load balancer", log_group: "log group", ecr: "ECR repository" };
/** The CLI that tags one resource of the kind (the person fills the values). */
export const TAG_CLI: Record<string, (id: string, tags: string) => string> = {
  ec2: (id, t) => `aws ec2 create-tags --resources ${id} --tags ${t}`,
  ebs: (id, t) => `aws ec2 create-tags --resources ${id} --tags ${t}`,
  rds: (id, t) => `aws rds add-tags-to-resource --resource-name <arn of ${id}> --tags ${t}`,
  rds_cluster: (id, t) => `aws rds add-tags-to-resource --resource-name <arn of ${id}> --tags ${t}`,
  s3: (id, t) => `aws s3api put-bucket-tagging --bucket ${id} --tagging 'TagSet=[${t}]'`,
  lambda: (id, t) => `aws lambda tag-resource --resource <arn of ${id}> --tags ${t}`,
  dynamodb: (id, t) => `aws dynamodb tag-resource --resource-arn <arn of ${id}> --tags ${t}`,
  alb: (id, t) => `aws elbv2 add-tags --resource-arns <arn of ${id}> --tags ${t}`,
  nlb: (id, t) => `aws elbv2 add-tags --resource-arns <arn of ${id}> --tags ${t}`,
  log_group: (id, t) => `aws logs tag-resource --resource-arn <arn of ${id}> --tags ${t}`,
  ecr: (id, t) => `aws ecr tag-resource --resource-arn <arn of ${id}> --tags ${t}`,
};
export const tagList = (tags: Record<string, string>) => Object.entries(tags).map(([k, v]) => `Key=${k},Value=${v || "<value>"}`).join(" ");

export interface TagRow { resource: string; kind: string; id: string; name: string | null; region: string | null; account_id: string | null; tags: Record<string, string>; missing: string[]; suggested: Record<string, string>; cli: string }
export interface OptIn { resource: string; name: string | null; region: string | null; state: string | null; opt: "park" | "schedule"; tag: string; cli: string }
export interface TagHygieneRefresh { scanned: number; missing: number; opt_in: number; kinds: Record<string, { total: number; missing: number }>; errors: string[]; took_ms: number }

const rowOf = (r: any): TagRow => {
  const [kind, ...rest] = String(r.resource).split(":"); const id = rest.join(":");
  const missing = JSON.parse(r.missing || "[]"); const suggested = JSON.parse(r.suggested || "{}");
  const cli = (TAG_CLI[kind] ?? TAG_CLI.ec2)(id, tagList(Object.fromEntries(missing.map((k: string) => [k, suggested[k] ?? ""]))));
  return { resource: r.resource, kind, id, name: r.name, region: r.region, account_id: r.account_id, tags: JSON.parse(r.tags || "{}"), missing, suggested, cli };
};

/** Reads every table's tags, stores the resources with missing keys and the opt-in candidates, refreshes the report recommendations. */
export async function refreshTagHygiene(onLog: (l: string) => void = () => {}): Promise<TagHygieneRefresh> {
  const t0 = Date.now();
  const required = requiredKeys();
  const now = new Date().toISOString();
  const out: TagHygieneRefresh = { scanned: 0, missing: 0, opt_in: 0, kinds: {}, errors: [], took_ms: 0 };
  const roles = new Map((db.prepare("select resource_id, role from resource_roles").all() as { resource_id: string; role: string }[]).map((r) => [r.resource_id, r.role]));
  const pools = new Map((db.prepare("select instance_id, pool_kind from inventory_ec2 where gone = 0").all() as { instance_id: string; pool_kind: string | null }[]).map((r) => [r.instance_id, r.pool_kind]));
  const rows: { resource: string; kind: string; name: string | null; region: string | null; account_id: string | null; tags: Record<string, string>; missing: string[]; suggested: Record<string, string> }[] = [];
  const optIns: OptIn[] = [];
  const seenKinds: string[] = [];
  for (const src of SOURCES) {
    let list: any[];
    try { list = await query<any>(src.sql); }
    catch (e) { const m = describeError(e, `tags (${src.kind})`); out.errors.push(m); onLog(m); continue; }
    seenKinds.push(src.kind);
    out.kinds[src.kind] = { total: list.length, missing: 0 };
    for (const r of list) {
      out.scanned++;
      const tags = normaliseTags(r.tags);
      const id = String(r.id ?? ""); if (!id) continue;
      const name = r.name ? String(r.name) : null;
      if (src.kind === "ec2") {
        const running = String(r.state ?? "") === "running";
        const pool = pools.get(id) ?? null;
        if (/swarm/i.test(name ?? "") && !(PARK_TAG in tags)) optIns.push({ resource: id, name, region: r.region ?? null, state: r.state ?? null, opt: "park", tag: `${PARK_TAG}=auto`, cli: TAG_CLI.ec2(id, `Key=${PARK_TAG},Value=auto`) });
        else if (running && !pool && !(SCHEDULE_TAG in tags) && /\b(dev|develop|staging|stage|test|qa|demo|sandbox)\b|[-_.](dev|staging|stage|test|qa|demo)([-_.]|$)/i.test(name ?? "")) optIns.push({ resource: id, name, region: r.region ?? null, state: r.state ?? null, opt: "schedule", tag: `${SCHEDULE_TAG}=${SUGGESTED_SCHEDULE}`, cli: TAG_CLI.ec2(id, `"Key=${SCHEDULE_TAG},Value=${SUGGESTED_SCHEDULE}"`) });
      }
      const missing = missingTags(tags, required);
      if (!missing.length) continue;
      out.kinds[src.kind].missing++; out.missing++;
      rows.push({ resource: `${src.kind}:${id}`, kind: src.kind, name, region: r.region ?? null, account_id: r.account_id ?? null, tags, missing, suggested: suggestTags({ kind: src.kind, name, tags, pool_kind: pools.get(id) ?? null, role: roles.get(id) ?? null }, missing) });
    }
  }
  out.opt_in = optIns.length;
  const up = db.prepare("insert into tag_hygiene(resource, kind, name, region, account_id, tags, missing, suggested, checked_at) values (?, ?, ?, ?, ?, ?, ?, ?, ?) on conflict(resource) do update set kind = excluded.kind, name = excluded.name, region = excluded.region, account_id = excluded.account_id, tags = excluded.tags, missing = excluded.missing, suggested = excluded.suggested, checked_at = excluded.checked_at");
  const upOpt = db.prepare("insert into tag_optin(resource, name, region, state, opt, tag, checked_at) values (?, ?, ?, ?, ?, ?, ?) on conflict(resource) do update set name = excluded.name, region = excluded.region, state = excluded.state, opt = excluded.opt, tag = excluded.tag, checked_at = excluded.checked_at");
  db.transaction(() => {
    for (const r of rows) up.run(r.resource, r.kind, r.name, r.region, r.account_id, JSON.stringify(r.tags), JSON.stringify(r.missing), JSON.stringify(r.suggested), now);
    for (const o of optIns) upOpt.run(o.resource, o.name, o.region, o.state, o.opt, o.tag, now);
    // Resources of a kind that was read and no longer lack a tag (or are gone) drop out; a kind that failed to read keeps its rows.
    if (seenKinds.length) {
      db.prepare(`delete from tag_hygiene where kind in (${seenKinds.map(() => "?").join(", ")}) and checked_at < ?`).run(...seenKinds, now);
      if (seenKinds.includes("ec2")) db.prepare("delete from tag_optin where checked_at < ?").run(now);
    }
  })();
  fileRecommendations(rows, required, seenKinds);
  out.took_ms = Date.now() - t0;
  onLog(`${out.scanned} resources, ${out.missing} missing ${required.join("/")}, ${out.opt_in} opt-in candidates in ${out.took_ms} ms${out.errors.length ? `; ${out.errors.length} table(s) unreadable` : ""}`);
  return out;
}

/** One report-tier recommendation per kind with missing tags; kinds now clean have theirs resolved. */
function fileRecommendations(rows: { resource: string; kind: string; name: string | null; missing: string[]; suggested: Record<string, string> }[], required: string[], seenKinds: string[]): void {
  const byKind = new Map<string, typeof rows>();
  for (const r of rows) { if (!byKind.has(r.kind)) byKind.set(r.kind, []); byKind.get(r.kind)!.push(r); }
  const runId = (db.prepare("select id from runs order by id desc limit 1").get() as { id: number } | undefined)?.id ?? 0;
  const recs: RecInput[] = [];
  for (const [kind, list] of byKind) {
    const label = KIND_LABEL[kind] ?? kind;
    const sample = list.slice(0, REC_NAMES).map((r) => { const id = r.resource.slice(kind.length + 1); const fill = Object.fromEntries(r.missing.map((k) => [k, r.suggested[k] ?? ""])); return `${r.name && r.name !== id ? `${r.name} (${id})` : id}: ${(TAG_CLI[kind] ?? TAG_CLI.ec2)(id, tagList(fill))}`; });
    recs.push({
      rule: "tag_hygiene", resource: `tags:${kind}`, resourceName: `${label}s`, actionType: "other", tier: "report", confidence: 0.9, estMonthlySaving: 0,
      title: `${list.length} ${label}${list.length === 1 ? "" : "s"} missing ${required.join("/")} tags`,
      rationale: `${list.length} of the ${label}s carry no ${required.map((k) => `\`${k}\``).join(" or ")} tag (aliases such as Environment or team count). Without them nobody can be asked about a resource, and the executor's opt-in tags (advisor:park, advisor:schedule) have no owner to propose them to. Suggested values come from the name and the tags already there; confirm before tagging. First ${Math.min(REC_NAMES, list.length)}: ${sample.join("; ")}${list.length > REC_NAMES ? `; the full list is on Inventory › Tags.` : "."}`,
      evidence: { kind, required, rows: list.slice(0, ROW_CAP).map((r) => ({ resource: r.resource, name: r.name, missing: r.missing, suggested: r.suggested })) },
    });
  }
  if (recs.length) upsertRecommendations(runId, recs, "rules", undefined, { reconcile: false });
  const clean = seenKinds.filter((k) => !byKind.has(k));
  if (clean.length) db.prepare(`update recommendations set status = 'resolved', decision_reason = 'every resource of the kind carries the required tags now', updated_at = datetime('now') where rule = 'tag_hygiene' and status = 'open' and resource in (${clean.map((k) => `'tags:${k}'`).join(", ")})`).run();
}

export interface TagHygieneReport { required: string[]; checked_at: string | null; kinds: { kind: string; label: string; missing: number; by_key: Record<string, number> }[]; rows: TagRow[]; total_missing: number; opt_in: OptIn[] }

/** The stored report: per kind the counts, the rows (capped) with suggestions and CLI, the opt-in candidates. */
export function tagHygieneReport(): TagHygieneReport {
  const required = requiredKeys();
  const all = (db.prepare("select * from tag_hygiene order by kind, name, resource").all() as any[]).map(rowOf);
  const kinds = new Map<string, { kind: string; label: string; missing: number; by_key: Record<string, number> }>();
  for (const r of all) {
    const k = kinds.get(r.kind) ?? { kind: r.kind, label: KIND_LABEL[r.kind] ?? r.kind, missing: 0, by_key: Object.fromEntries(required.map((x) => [x, 0])) };
    k.missing++; for (const m of r.missing) k.by_key[m] = (k.by_key[m] ?? 0) + 1;
    kinds.set(r.kind, k);
  }
  const checked = (db.prepare("select max(checked_at) as at from tag_hygiene").get() as { at: string | null }).at ?? (db.prepare("select max(checked_at) as at from tag_optin").get() as { at: string | null }).at;
  const opt_in = (db.prepare("select * from tag_optin order by opt, name").all() as any[]).map((o) => ({ resource: o.resource, name: o.name, region: o.region, state: o.state, opt: o.opt, tag: o.tag, cli: o.opt === "park" ? TAG_CLI.ec2(o.resource, `Key=${PARK_TAG},Value=auto`) : TAG_CLI.ec2(o.resource, `"Key=${SCHEDULE_TAG},Value=${SUGGESTED_SCHEDULE}"`) }) as OptIn);
  return { required, checked_at: checked, kinds: [...kinds.values()].sort((a, b) => b.missing - a.missing), rows: all.slice(0, ROW_CAP), total_missing: all.length, opt_in };
}

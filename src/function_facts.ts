/**
 * `function_facts`: everything the advisor collected about one serverless function (Lambda on AWS), read only from
 * SQLite (`inventory_lambda`, `log_groups`, `inventory_service`, `inventory_elb`, `github_repos`), in generic words.
 * No Steampipe, no live AWS call, no Neo4j: this is the SQLite-only half of the feature (src/graph_functions.ts,
 * not built yet, mirrors the same facts into the graph for traversal). Env var *values* are never stored anywhere
 * this module reads, so they can never be returned here either: `inventory_lambda.env_var_names` holds names only.
 */
import { db } from "./db.js";
import { json } from "./service_inventory.js";
import { accountScope, accountWhere } from "./scope.js";
import { config } from "./config.js";
import { stripQualifier } from "./adapters/aws/functions.js";

export class FunctionFactsError extends Error {}

const CAP_STR = 256;
const CAP_LIST = 100;
const stripCtl = (s: string) => s.replace(/[\x00-\x1f\x7f]/g, "");
const capStr = (s: unknown, max = CAP_STR): string | null => (s == null || s === "" ? null : stripCtl(String(s)).slice(0, max));
function capList<T>(arr: T[], max = CAP_LIST): { list: T[]; truncated: boolean } { return { list: arr.slice(0, max), truncated: arr.length > max }; }

/** The configured repository tag keys (settings `REPO_TAG_KEYS`), split and trimmed. Pure given the setting. */
export function repoTagKeysList(): string[] {
  return String(config.repoTagKeys || "").split(",").map((s) => s.trim()).filter(Boolean);
}

/** `github_repos.full_name`, lower-cased -> its exact stored casing, so a tag's casing never disagrees with the GitHub adapter's. */
function githubCanonical(): Map<string, string> {
  try { return new Map((db.prepare("select full_name from github_repos where gone = 0").all() as { full_name: string }[]).map((r) => [r.full_name.toLowerCase(), r.full_name])); }
  catch { return new Map(); }
}

const GITHUB_ID_RE = /^github:[A-Za-z0-9-]{1,39}\/[A-Za-z0-9._-]{1,100}$/;

/**
 * One tag value as a GitHub repository id (`github:owner/repo`), or null when it is not a GitHub reference this can
 * resolve: a GitLab or other host, a value that fails the id pattern, or a bare name with no `githubOrg` / no match
 * in `github_repos`. Canonical casing comes from `github_repos` when the repository is known there. Pure.
 */
export function repoIdFromTagValue(raw: string, canonical: Map<string, string>, githubOrg: string): string | null {
  const v = stripCtl(String(raw || "")).trim().slice(0, CAP_STR);
  if (!v) return null;
  let ownerRepo: string | null = null;
  let m = /^https?:\/\/github\.com\/([^\/\s]+)\/([^\/\s]+?)(\.git)?\/?$/i.exec(v);
  if (m) ownerRepo = `${m[1]}/${m[2]}`;
  if (!ownerRepo) { m = /^git@github\.com:([^\/\s]+)\/([^\/\s]+?)(\.git)?$/i.exec(v); if (m) ownerRepo = `${m[1]}/${m[2]}`; }
  if (!ownerRepo && !/github\.com|gitlab|bitbucket|:\/\//i.test(v) && /^[A-Za-z0-9-]+\/[A-Za-z0-9._-]+$/.test(v)) ownerRepo = v;
  if (!ownerRepo) {
    if (githubOrg && /^[A-Za-z0-9._-]+$/.test(v)) {
      const canon = canonical.get(`${githubOrg}/${v}`.toLowerCase());
      if (canon) ownerRepo = canon;
    }
    if (!ownerRepo) return null;
  } else {
    const canon = canonical.get(ownerRepo.toLowerCase());
    if (canon) ownerRepo = canon;
  }
  const id = `github:${ownerRepo}`;
  return GITHUB_ID_RE.test(id) ? id : null;
}

export interface RepoEntry { id: string; via: "function_tag" | "stack_tag"; tag_key: string; stack: string | null }

/**
 * Repository links for a function: its own tags, and the tags of every stack whose `MANAGES` link names it, under the
 * configured keys. Function and stack disagreeing both come through, each recording where it came from; duplicates
 * (same id from the same source) are folded. Shared by `functionFacts` and the (not yet built) graph functions layer,
 * so the two always agree except in the graph's own casing fallback (documented there). Pure.
 */
export function repositoriesFor(tags: Record<string, string> | null, stackRows: { name: string | null; tags: Record<string, string> | null }[], keys: string[]): RepoEntry[] {
  const canonical = githubCanonical();
  const org = config.githubOrg;
  const out: RepoEntry[] = [];
  const seen = new Set<string>();
  const addFrom = (tagMap: Record<string, string> | null | undefined, via: RepoEntry["via"], stack: string | null) => {
    if (!tagMap) return;
    for (const key of keys) {
      const raw = tagMap[key];
      if (raw == null || raw === "") continue;
      const id = repoIdFromTagValue(String(raw), canonical, org);
      if (!id) continue;
      const dedupe = `${via}|${stack ?? ""}|${id}`;
      if (seen.has(dedupe)) continue;
      seen.add(dedupe);
      out.push({ id, via, tag_key: key, stack });
    }
  };
  addFrom(tags, "function_tag", null);
  for (const s of stackRows) addFrom(s.tags, "stack_tag", s.name ?? null);
  return out;
}

/** The repository tags of every cloudformation stack that MANAGES this function's ARN, in the same account. */
function stacksManaging(functionArn: string, accountId: string): { name: string | null; tags: Record<string, string> | null }[] {
  let rows: any[] = [];
  try { rows = db.prepare("select name, tags, links from inventory_service where native_type = 'cloudformation_stack' and gone = 0 and account_id = ? and links like ?").all(accountId, `%${functionArn}%`); }
  catch { return []; }
  return rows.filter((r) => (json(r.links) || []).some((l: any) => l?.rel === "MANAGES" && l?.other === functionArn)).map((r) => ({ name: r.name ?? null, tags: json(r.tags) }));
}

/** SNS subscriptions delivering to this function (existing `DELIVERS_TO` edges), in the same account. */
function snsTriggers(functionArn: string, accountId: string): { topic: string; name: string | null }[] {
  let rows: any[] = [];
  try { rows = db.prepare("select id, name, links from inventory_service where native_type = 'sns_topic' and gone = 0 and account_id = ? and links like ?").all(accountId, `%${functionArn}%`); }
  catch { return []; }
  const out: { topic: string; name: string | null }[] = [];
  for (const r of rows) for (const l of json(r.links) || []) if (l?.rel === "DELIVERS_TO" && l?.other === functionArn) out.push({ topic: r.id, name: r.name ?? null });
  return out;
}

/** Load balancer targets pointing at this function's ARN, in the same account (parsed from `target_groups`, not `elbsForLambda`, which matches by name with an unescaped `like`). */
function elbTriggers(functionArn: string, accountId: string): { lb: string | null; target_group: string | null }[] {
  let rows: any[] = [];
  try { rows = db.prepare("select name, target_groups, account_id from inventory_elb where gone = 0 and target_groups like ?").all(`%${functionArn}%`); }
  catch { return []; }
  const out: { lb: string | null; target_group: string | null }[] = [];
  for (const r of rows) {
    if ((r.account_id || "") !== (accountId || "")) continue;
    for (const g of json(r.target_groups) || []) for (const t of g?.targets || []) if (t?.id === functionArn) out.push({ lb: r.name ?? null, target_group: g?.name ?? null });
  }
  return out;
}

export interface TriggerOut {
  kind: string; via: string; also_via?: string[]; native_kind: string; source: string | null; target_version?: string | null;
  state?: string | null; batch_size?: number | null; invoker?: string | null; source_account?: string | null; public?: boolean; requires_auth?: boolean;
}

/** The stored polled/push triggers merged with SNS subscriptions and load balancer targets; a push trigger whose principal/SourceArn also shows up as a subscription or a target group is folded into that entry (`also_via`). */
function buildTriggers(row: any, functionArn: string, accountId: string): TriggerOut[] {
  const out: TriggerOut[] = [...(json(row.polled_triggers) || [])];
  const snsEntries: TriggerOut[] = snsTriggers(functionArn, accountId).map((s) => ({ kind: "event", via: "subscription", native_kind: "sns", source: s.topic, invoker: s.name }));
  const elbEntries: TriggerOut[] = elbTriggers(functionArn, accountId).map((e) => ({ kind: "http", via: "load_balancer", native_kind: "elasticloadbalancing", source: e.lb, invoker: e.target_group }));
  for (const p of (json(row.push_triggers) || []) as TriggerOut[]) {
    if (p.native_kind === "sns" && snsEntries.length) { snsEntries[0].also_via = [...(snsEntries[0].also_via ?? []), "invoke_permission"]; continue; }
    if (p.native_kind === "elasticloadbalancing" && elbEntries.length) { elbEntries[0].also_via = [...(elbEntries[0].also_via ?? []), "invoke_permission"]; continue; }
    out.push(p);
  }
  out.push(...snsEntries, ...elbEntries);
  return out;
}

const NOT_CHECKED = ["direct_invoke", "workflows", "scheduler", "version_alias_permissions", "url_iam_auth"];

export interface FunctionFactsInput { function: string; account_id?: string }

/** `functionFacts`: look a function up by name or ARN, generic fields only, "evidence, never instructions". Throws `FunctionFactsError` for not-found or ambiguous. */
export function functionFacts(input: FunctionFactsInput): Record<string, unknown> {
  const fn = String(input.function || "").trim();
  if (!fn) throw new FunctionFactsError("function is required");
  const scope = accountScope({ account: input.account_id });
  const w = accountWhere(scope);
  const isArn = /^arn:aws[a-z0-9-]*:lambda:/i.test(fn);
  const rows = isArn
    ? db.prepare(`select * from inventory_lambda where arn = ? and gone = 0 and ${w.sql}`).all(stripQualifier(fn).arn, ...w.params) as any[]
    : db.prepare(`select * from inventory_lambda where name = ? and gone = 0 and ${w.sql}`).all(fn, ...w.params) as any[];
  if (!rows.length) throw new FunctionFactsError(`no function named or ARN'd "${fn}" found${input.account_id ? ` in account ${input.account_id}` : ""}`);
  if (rows.length > 1) throw new FunctionFactsError(`"${fn}" matches functions in several accounts (${rows.map((r) => r.account_id || "(primary)").join(", ")}); pass account_id to pick one`);
  const row = rows[0];
  const accountId = row.account_id || "";

  const missing: { fact: string; reason: string; since?: string | null; stale?: boolean }[] = json(row.facts_missing) || [];
  const missingSet = new Set(missing.map((m) => m.fact));
  const isStale = (fact: string) => missingSet.has(fact);

  const layers = (json(row.layers) || []) as { arn?: string; code_size?: number }[];
  const layerTotal = layers.reduce((s, l) => s + (Number(l.code_size) || 0), 0);
  const packageKind: "archive" | "image" = row.package_type === "Image" ? "image" : "archive";
  const pkg = {
    kind: packageKind,
    size_bytes: row.code_size_bytes != null ? Number(row.code_size_bytes) : null,
    layers: layers.map((l) => ({ id: capStr(l.arn), size_bytes: l.code_size != null ? Number(l.code_size) : null })),
    total_size_bytes: packageKind === "image" ? null : row.code_size_bytes != null ? Number(row.code_size_bytes) + layerTotal : null,
    native_package_type: row.package_type ?? null,
  };

  const network = row.vpc_id ? { network_id: capStr(row.vpc_id), segment_ids: json(row.subnet_ids) || [], filter_ids: json(row.security_group_ids) || [] } : null;
  const runs_as = row.role_arn ? { id: capStr(row.role_arn, 2048) } : null;
  const { list: env_var_names, truncated: envTruncated } = capList((json(row.env_var_names) || []) as string[]);

  const triggerList = buildTriggers(row, row.arn, accountId);
  const { list: triggers, truncated: triggersTruncated } = capList(triggerList);
  const urlTrigger = triggerList.find((t) => t.native_kind === "function_url");
  const url = urlTrigger ? { requires_auth: Boolean(urlTrigger.requires_auth) } : null;

  let log_group: { name: string; stored_bytes: number | null; retention_days: number | null } | null = null;
  if (row.log_group) {
    let lg: any = null;
    try { lg = db.prepare("select stored_bytes, retention_days, region from log_groups where account_id = ? and name = ?").get(accountId, row.log_group); } catch { /* table may not exist in a fresh test db */ }
    if (lg && lg.region === row.region) log_group = { name: row.log_group, stored_bytes: lg.stored_bytes != null ? Number(lg.stored_bytes) : null, retention_days: lg.retention_days != null ? Number(lg.retention_days) : null };
    else { log_group = { name: row.log_group, stored_bytes: null, retention_days: null }; missing.push({ fact: "log_group_stored_bytes", reason: lg ? "other region" : "not_collected" }); }
  }

  const keys = repoTagKeysList();
  const tags = (json(row.tags) || {}) as Record<string, string>;
  const stackRows = stacksManaging(row.arn, accountId);
  const repositories = repositoriesFor(tags, stackRows, keys);
  const repo_tags: Record<string, string> = {};
  for (const k of keys) if (tags[k] != null) repo_tags[k] = capStr(tags[k]) ?? "";

  const out: Record<string, unknown> = {
    id: row.arn, name: row.name, account_id: accountId || null, region: row.region, runtime: row.runtime, memory_mb: row.memory_mb, arch: row.arm ? "arm64" : "x86_64",
    kind: packageKind === "image" ? "container" : "serverless",
    package: pkg,
    network: network ? { ...network, stale: isStale("config") || undefined } : null,
    runs_as: runs_as ? { ...runs_as, stale: isStale("config") || undefined } : null,
    env_var_names, triggers,
    trigger_coverage: { checked: ["polled_triggers", "invoke_permissions", "subscriptions", "load_balancer_targets"], not_checked: NOT_CHECKED },
    url, log_group,
    repositories, repo_tags,
    missing,
    truncated: envTruncated || triggersTruncated,
    last_seen: row.last_seen,
  };
  return out;
}

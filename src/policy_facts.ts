/**
 * What an IAM policy lets its holder do, graded the way the IAM console's policy summary grades it: per service, the
 * access levels the allowed actions fall in (List, Read, Write, Tagging, Permissions management), from AWS's own
 * service reference (src/service_reference.ts, https://docs.aws.amazon.com/service-authorization/latest/reference/service-reference.html).
 * Pure: the documents and the catalogue come in, the grades go out.
 *
 * - `permsOf` folds a principal's policy documents (identity policies, the group's, a permission set's) into one
 *   allowed set: per service the actions (or every action), whether some statement narrows the resources or adds a
 *   condition, and the resource patterns named. An Allow on "*" (or NotAction) is "every service" with the exceptions.
 *   An unconditional Deny on every resource takes its actions away; a conditional or resource-scoped Deny is noted.
 * - `intersect` keeps what two sets both allow: a permissions boundary, the organisation's service control policies.
 * - `grade` turns a set into the summary the graph and the page show.
 * - `allows` answers one action on one resource (assume this role, start a session on this instance): yes, only
 *   under a condition, or no; how the transitive paths (src/access_paths.ts) are found.
 *
 * Not modelled: resource policies (a bucket policy granting another account), session policies, the condition keys'
 * values (a tag condition reads as "conditional", never as a resource list). `SimulatePrincipalPolicy` answers those
 * exactly for one question (src/access_simulate.ts).
 */

export type Level = "list" | "read" | "tagging" | "write" | "permissions";
export const LEVELS: Level[] = ["list", "read", "tagging", "write", "permissions"];
export const LEVEL_RANK: Record<Level, number> = { list: 1, read: 2, tagging: 3, write: 4, permissions: 5 };
/** The console's words for each level. */
export const LEVEL_LABEL: Record<Level, string> = { list: "List", read: "Read", tagging: "Tagging", write: "Write", permissions: "Permissions management" };

/** The catalogue: per service prefix, each action's name (as AWS spells it) and level; null for a service the reference does not know. */
export interface Catalogue { actions(service: string): Map<string, { name: string; level: Level }> | null }

/** A level from the service reference's annotations (Properties: IsList, IsWrite, IsPermissionManagement, IsTaggingOnly). Pure. */
export function levelOf(p: { IsList?: boolean; IsWrite?: boolean; IsPermissionManagement?: boolean; IsTaggingOnly?: boolean } | null | undefined): Level {
  if (p?.IsPermissionManagement) return "permissions";
  if (p?.IsTaggingOnly) return "tagging";
  if (p?.IsWrite) return "write";
  if (p?.IsList) return "list";
  return "read";
}

/** A level from an action's name alone, for a service the catalogue does not know. Pure. */
export function guessLevel(action: string): Level {
  if (/^(List|Describe)/.test(action)) return "list";
  if (/^(Get|BatchGet|Search|Query|Scan|Lookup|View|Read|Download|Select)/.test(action)) return "read";
  if (/^(Tag|Untag)/.test(action)) return "tagging";
  if (/^(Put|Attach|Detach|Delete|Create|Update)\w*Polic(y|ies)$|^(Add|Remove)Permission|^(Create|Update)Grant|^PassRole$/.test(action)) return "permissions";
  return "write";
}

export interface Statement { effect: "Allow" | "Deny"; actions: string[] | null; not_actions: string[] | null; resources: string[] | null; not_resources: string[] | null; conditional: boolean; condition_keys: string[]; source: string }

const arr = <T,>(v: T | T[] | undefined | null): T[] => (v == null ? [] : Array.isArray(v) ? v : [v]);
/** A policy document from JSON text, a URL-encoded string (GetAccountAuthorizationDetails, GetPolicyVersion) or an object. Pure. */
export function docOf(v: unknown): any {
  if (v && typeof v === "object") return v;
  if (typeof v !== "string" || !v) return null;
  for (const s of [v, (() => { try { return decodeURIComponent(v); } catch { return v; } })()]) { try { return JSON.parse(s); } catch { /* the next form */ } }
  return null;
}

/** The statements of one document, normalised. Pure. */
export function statementsOf(doc: unknown, source = "policy"): Statement[] {
  const d = docOf(doc); const out: Statement[] = [];
  for (const s of arr(d?.Statement)) {
    if (!s || (s.Effect !== "Allow" && s.Effect !== "Deny")) continue;
    const keys = Object.values(s.Condition ?? {}).flatMap((b: any) => Object.keys(b ?? {}));
    out.push({ effect: s.Effect, actions: s.Action != null ? arr(s.Action).map(String) : null, not_actions: s.NotAction != null ? arr(s.NotAction).map(String) : null,
      resources: s.Resource != null ? arr(s.Resource).map(String) : null, not_resources: s.NotResource != null ? arr(s.NotResource).map(String) : null, conditional: keys.length > 0, condition_keys: keys, source });
  }
  return out;
}

const patterns = new Map<string, RegExp>();
/** IAM wildcard matching (`*` any run, `?` one character). Actions are case-insensitive, resources are not. Pure. */
export function wildcard(pattern: string, value: string, caseInsensitive = false): boolean {
  if (!/[*?]/.test(pattern)) return caseInsensitive ? pattern.toLowerCase() === value.toLowerCase() : pattern === value;
  const key = `${caseInsensitive ? "i" : "s"}${pattern}`;
  let re = patterns.get(key);
  if (!re) { re = new RegExp(`^${pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".")}$`, caseInsensitive ? "i" : ""); if (patterns.size > 20_000) patterns.clear(); patterns.set(key, re); }
  return re.test(value);
}
const splitAction = (a: string): [string, string] => { const i = a.indexOf(":"); return i < 0 ? [a.toLowerCase(), "*"] : [a.slice(0, i).toLowerCase(), a.slice(i + 1)]; };
const everyResource = (s: Statement) => (s.resources ?? []).includes("*") && !s.not_resources;

interface ServiceSet { all: boolean; actions: Set<string>; scoped: boolean; conditional: boolean; resources: Set<string>; sources: Set<string>;
  /** each granting statement's actions ("all" for a wildcard) and narrowing, so the grade can say whether its top level is narrowed */
  grants: { actions: string[] | "all"; scoped: boolean; conditional: boolean }[] }
/** What a set of documents allows. `every` is an Allow on every service, minus the patterns in `except`. */
export interface Perms { every: { except: string[]; scoped: boolean; conditional: boolean; sources: string[] } | null; services: Map<string, ServiceSet>; denies: string[]; conditional_denies: string[] }

const emptySet = (): ServiceSet => ({ all: false, actions: new Set(), scoped: false, conditional: false, resources: new Set(), sources: new Set(), grants: [] });

/** The actions of one service a pattern names, by the catalogue (the pattern itself, lower-cased, for an unknown service). Pure. */
function expand(service: string, pattern: string, cat: Catalogue): { all: boolean; actions: string[] } {
  if (pattern === "*") return { all: true, actions: [] };
  const known = cat.actions(service);
  if (!known) return { all: false, actions: /[*?]/.test(pattern) ? [] : [pattern.toLowerCase()] };
  return { all: false, actions: [...known.keys()].filter((k) => wildcard(pattern, k, true)) };
}

/** Folds documents into what they allow. `docs` are policy documents with the name each came from. Pure. */
export function permsOf(docs: { doc: unknown; source: string }[], cat: Catalogue): Perms {
  const p: Perms = { every: null, services: new Map(), denies: [], conditional_denies: [] };
  const sts = docs.flatMap((d) => statementsOf(d.doc, d.source));
  for (const s of sts.filter((x) => x.effect === "Allow")) {
    const scoped = !everyResource(s);
    const named = (s.resources ?? []).filter((r) => r !== "*");
    if (s.not_actions) {
      // every action but these: every service, the listed patterns excepted
      const e = p.every ?? { except: s.not_actions.map((a) => a.toLowerCase()), scoped, conditional: s.conditional, sources: [] };
      if (p.every) e.except = e.except.filter((x) => s.not_actions!.some((n) => n.toLowerCase() === x));
      e.scoped = e.scoped && scoped; e.conditional = e.conditional && s.conditional; e.sources.push(s.source); p.every = e;
      continue;
    }
    for (const a of s.actions ?? []) {
      if (a === "*") { const e = p.every ?? { except: [], scoped, conditional: s.conditional, sources: [] }; if (p.every) { e.except = []; e.scoped = e.scoped && scoped; e.conditional = e.conditional && s.conditional; } e.sources.push(s.source); p.every = e; continue; }
      const [svc, name] = splitAction(a);
      const x = expand(svc, name, cat);
      const set = p.services.get(svc) ?? emptySet();
      // scoped or conditional only when every statement granting the service is: one wide, unconditional Allow decides
      const first = set.sources.size === 0 && !set.all && !set.actions.size;
      set.scoped = first ? scoped : set.scoped && scoped; set.conditional = first ? s.conditional : set.conditional && s.conditional;
      if (x.all) set.all = true; for (const n of x.actions) set.actions.add(n);
      set.grants.push({ actions: x.all ? "all" : x.actions, scoped, conditional: s.conditional });
      for (const r of named.slice(0, 20)) set.resources.add(r); set.sources.add(s.source);
      p.services.set(svc, set);
    }
  }
  for (const s of sts.filter((x) => x.effect === "Deny")) {
    const patterns = s.actions ?? []; if (!patterns.length) continue; // a Deny with NotAction denies nearly everything but is rare outside SCPs: noted, not applied
    if (s.conditional || !everyResource(s)) { p.conditional_denies.push(...patterns); continue; }
    p.denies.push(...patterns);
    for (const a of patterns) {
      if (a === "*") { p.every = null; p.services.clear(); continue; }
      const [svc, name] = splitAction(a);
      if (p.every && !p.every.except.includes(a.toLowerCase())) p.every.except.push(a.toLowerCase());
      const set = p.services.get(svc); if (!set) continue;
      if (name === "*") { p.services.delete(svc); continue; }
      const x = expand(svc, name, cat);
      if (set.all) { const known = cat.actions(svc); if (known) { set.all = false; for (const k of known.keys()) if (!x.actions.includes(k)) set.actions.add(k); } }
      for (const n of x.actions) set.actions.delete(n);
      if (!set.all && !set.actions.size) p.services.delete(svc);
    }
  }
  return p;
}

/** Whether `every` (with its exceptions) covers an action. Pure. */
const everyCovers = (e: Perms["every"], service: string, action: string) => Boolean(e) && !e!.except.some((x) => wildcard(x, `${service}:${action}`, true));

/** The actions of one service a set allows, by name, or "all". Pure. */
function actionsIn(p: Perms, service: string, cat: Catalogue): Set<string> | "all" {
  const own = p.services.get(service);
  if (p.every) {
    const known = cat.actions(service);
    if (!p.every.except.some((x) => x.startsWith(`${service}:`))) return "all";
    if (!known) return own?.all ? "all" : new Set(own?.actions ?? []);
    const out = new Set([...known.keys()].filter((k) => everyCovers(p.every, service, k)));
    if (own?.all) return "all"; for (const a of own?.actions ?? []) out.add(a); return out;
  }
  if (!own) return new Set();
  return own.all ? "all" : own.actions;
}

/** What both sets allow: a principal's policies within its permissions boundary, or within the organisation's SCPs. Pure. */
export function intersect(a: Perms, b: Perms, cat: Catalogue): Perms {
  const out: Perms = { every: null, services: new Map(), denies: [...a.denies, ...b.denies], conditional_denies: [...a.conditional_denies, ...b.conditional_denies] };
  if (a.every && b.every) out.every = { except: [...new Set([...a.every.except, ...b.every.except])], scoped: a.every.scoped || b.every.scoped, conditional: a.every.conditional || b.every.conditional, sources: a.every.sources };
  const services = new Set([...a.services.keys(), ...b.services.keys()]);
  for (const svc of services) {
    const x = actionsIn(a, svc, cat); const y = actionsIn(b, svc, cat);
    const src = a.services.get(svc) ?? emptySet();
    let set: ServiceSet;
    if (x === "all" && y === "all") set = { ...src, all: true, actions: new Set() };
    else if (x === "all") set = { ...src, all: false, actions: new Set(y as Set<string>) };
    else if (y === "all") set = { ...src, all: false, actions: new Set(x) };
    else set = { ...src, all: false, actions: new Set([...x].filter((n) => y.has(n))) };
    if (out.every && set.all) continue; // covered by every
    if (set.all || set.actions.size) out.services.set(svc, set);
  }
  return out;
}

export interface ServiceGrant {
  service: string; top: Level; levels: Level[];
  /** every action of the service (a wildcard or every service) */
  all: boolean; actions: number; total: number | null;
  /** every statement granting it names resources rather than "*" (scoped) or adds a condition (conditional): the grade is the most it allows */
  scoped: boolean; conditional: boolean; resources: string[];
  /** the actions at the permissions-management level, by name (the escalation paths: PutUserPolicy, PassRole, CreatePolicyVersion…) */
  permissions_actions: string[];
}
export interface Grants {
  /** an Allow on every action of every service (with `except` patterns left out) */
  every: { except: string[]; scoped: boolean; conditional: boolean } | null;
  services: ServiceGrant[];
  top: Level | null; admin: boolean;
  /** permissions management on identity services (IAM, STS, Organizations, Identity Center): who may do what */
  permissions_services: string[];
  /** permissions management on a service's own resources (a log group's or topic's resource policy, CloudWatch access grants): who may reach that data, not IAM */
  resource_access_services: string[];
  write_services: string[]; read_services: string[];
  denies: string[]; conditional_denies: string[];
}

/**
 * The services whose permissions-management actions change identities' permissions. The console calls a topic's
 * resource policy permissions management too; here that is resource access, and only these make the top level
 * "permissions".
 */
export const IDENTITY_SERVICES = new Set(["iam", "sts", "organizations", "sso", "sso-directory", "identitystore", "account"]);

/** The services whose permissions-management actions matter most when held without being an administrator. */
const ESCALATION_SERVICES = new Set(["iam", "sts", "organizations", "sso", "identitystore", "kms", "lambda", "ec2", "ssm", "cloudformation", "glue", "codebuild", "secretsmanager"]);

/** The summary of a set. Pure. */
export function grade(p: Perms, cat: Catalogue): Grants {
  const services: ServiceGrant[] = [];
  for (const [svc, set] of p.services) {
    const known = cat.actions(svc);
    const names = set.all ? (known ? [...known.keys()] : []) : [...set.actions];
    const levels = new Set<Level>(); const perm: string[] = [];
    for (const n of names) { const l = known?.get(n)?.level ?? guessLevel(n); levels.add(l); if (l === "permissions") perm.push(known?.get(n)?.name ?? n); }
    if (set.all && !known) levels.add("write");
    const sorted = LEVELS.filter((l) => levels.has(l)); if (!sorted.length) continue;
    // narrowed when every statement that grants an action at the top level is (a read on "*" does not widen a conditional write)
    const top = sorted[sorted.length - 1];
    const atTop = (n: string) => (known?.get(n)?.level ?? guessLevel(n)) === top;
    const behind = set.grants.filter((g) => g.actions === "all" || g.actions.some(atTop));
    const narrowed = (k: "scoped" | "conditional") => (behind.length ? behind.every((g) => g[k]) : set[k]);
    services.push({ service: svc, top, levels: sorted, all: set.all, actions: set.all ? (known?.size ?? 0) : names.length, total: known?.size ?? null,
      scoped: narrowed("scoped"), conditional: narrowed("conditional"), resources: [...set.resources].slice(0, 20), permissions_actions: perm.sort().slice(0, 40) });
  }
  services.sort((a, b) => LEVEL_RANK[b.top] - LEVEL_RANK[a.top] || a.service.localeCompare(b.service));
  const every = p.every ? { except: p.every.except, scoped: p.every.scoped, conditional: p.every.conditional } : null;
  // every service with nothing excepted on IAM is an administrator; PowerUserAccess (every service but iam, organizations, account) is write everywhere
  const iamOut = every?.except.some((x) => x === "iam:*" || x === "*") ?? true;
  const admin = Boolean(every && !every.except.length && !every.scoped && !every.conditional);
  const capped = (x: ServiceGrant): Level => (x.top === "permissions" && !IDENTITY_SERVICES.has(x.service) ? "write" : x.top);
  const top: Level | null = every ? (iamOut ? "write" : "permissions") : services.length ? services.reduce<Level>((m, x) => (LEVEL_RANK[capped(x)] > LEVEL_RANK[m] ? capped(x) : m), "list") : null;
  const at = (min: Level) => services.filter((x) => LEVEL_RANK[x.top] >= LEVEL_RANK[min]).map((x) => x.service);
  const perm = services.filter((x) => x.levels.includes("permissions"));
  return { every, services, top, admin, write_services: at("write"), permissions_services: perm.filter((x) => IDENTITY_SERVICES.has(x.service)).map((x) => x.service), resource_access_services: perm.filter((x) => !IDENTITY_SERVICES.has(x.service)).map((x) => x.service),
    read_services: services.filter((s) => s.levels.some((l) => l === "read" || l === "list")).map((s) => s.service), denies: [...new Set(p.denies)], conditional_denies: [...new Set(p.conditional_denies)] };
}

/** Whether a non-administrator holds a way to raise its own permissions (an IAM, STS, Organizations or similar permissions-management action, or everything but IAM). Pure. */
export function canEscalate(g: Grants): string[] {
  if (g.admin) return [];
  const out: string[] = [];
  if (g.every && g.top === "permissions") out.push("every service, IAM included");
  for (const s of g.services) if (ESCALATION_SERVICES.has(s.service)) for (const a of s.permissions_actions) out.push(`${s.service}:${a}`);
  return out;
}

export type Decision = "allowed" | "conditional" | "denied";
/**
 * One action on one resource against a set of documents: an unconditional Deny wins, then an Allow (conditional when
 * every Allow that matches carries a condition), else denied. Resource "*" and wildcards in ARNs match. Pure.
 */
export function allows(docs: { doc: unknown; source: string }[], action: string, resource: string): { decision: Decision; by: string[] } {
  return allowsCompiled(compile(docs), action, resource);
}
/** The statements of a set of documents, parsed once for many `allowsCompiled` questions. Pure. */
export const compile = (docs: { doc: unknown; source: string }[]): Statement[] => docs.flatMap((d) => statementsOf(d.doc, d.source));
/** `allows` over statements already parsed. Pure. */
export function allowsCompiled(sts: Statement[], action: string, resource: string): { decision: Decision; by: string[] } {
  const actionMatch = (s: Statement) => (s.actions ? s.actions.some((p) => wildcard(p, action, true)) : !(s.not_actions ?? []).some((p) => wildcard(p, action, true)));
  const resourceMatch = (s: Statement) => (s.resources ? s.resources.some((p) => wildcard(p, resource)) : !(s.not_resources ?? []).some((p) => wildcard(p, resource)));
  const deny = sts.filter((s) => s.effect === "Deny" && !s.conditional && actionMatch(s) && resourceMatch(s));
  if (deny.length) return { decision: "denied", by: deny.map((s) => s.source) };
  const allow = sts.filter((s) => s.effect === "Allow" && actionMatch(s) && resourceMatch(s));
  if (!allow.length) return { decision: "denied", by: [] };
  const firm = allow.filter((s) => !s.conditional);
  return { decision: firm.length ? "allowed" : "conditional", by: (firm.length ? firm : allow).map((s) => s.source) };
}

/** The weaker of two decisions (a path is as strong as its weakest step). Pure. */
export const weaker = (a: Decision, b: Decision): Decision => (a === "denied" || b === "denied" ? "denied" : a === "conditional" || b === "conditional" ? "conditional" : "allowed");

/** One service's grade as `describeServices` reads it. */
export interface ServiceLevel { service: string; top: Level; scoped: boolean; conditional: boolean }

/**
 * Services grouped by level in the console's words, each qualified when every grant of it is narrowed:
 * "Permissions management on iam (under a condition); Access to the data of logs, sns; Write on ec2, s3 (named resources)". Pure.
 */
export function describeServices(list: ServiceLevel[], max = 5): string {
  const q = (x: ServiceLevel) => `${x.service}${x.conditional ? " (under a condition)" : x.scoped ? " (named resources)" : ""}`;
  const group = (label: string, xs: ServiceLevel[]) => (xs.length ? `${label} ${xs.slice(0, max).map(q).join(", ")}${xs.length > max ? ` (+${xs.length - max})` : ""}` : "");
  const identity = list.filter((x) => x.top === "permissions" && IDENTITY_SERVICES.has(x.service));
  const access = list.filter((x) => x.top === "permissions" && !IDENTITY_SERVICES.has(x.service));
  return [group("Permissions management on", identity), group("Write, and who may reach the data, on", access), group("Write on", list.filter((x) => x.top === "write")), group("Tagging on", list.filter((x) => x.top === "tagging")), group("Read on", list.filter((x) => x.top === "read")), group("List on", list.filter((x) => x.top === "list"))].filter(Boolean).join("; ");
}

/** A compact line for a grade: "Administrator", "Permissions management on iam; Write on ec2, s3 (+3)". Pure. */
export function gradeLine(g: Grants): string {
  if (g.admin) return "Administrator (every action on every service)";
  if (g.every) return `Every service${g.every.except.length ? ` except ${g.every.except.slice(0, 4).join(", ")}${g.every.except.length > 4 ? ", …" : ""}` : ""}${g.every.conditional ? " (under a condition)" : g.every.scoped ? " (named resources)" : ""}`;
  if (!g.services.length) return "Nothing";
  return describeServices(g.services);
}

/**
 * Which system a CloudWatch log group belongs to, from evidence rather than a bare substring, strongest first:
 * what the instances themselves say they ship (the CloudWatch agent, awslogs, Fluent Bit and Docker awslogs
 * configs the SSM probe reads, src/ssm.ts), the AWS naming conventions (Lambda, RDS, EKS, Elastic Beanstalk),
 * the tags on the log group, the tags the systems carry (cluster name, environment name), then a token match
 * between the group's path and the systems' names, pools and member ids. Every answer says how it was reached,
 * and an unattributed group lists the systems that came closest. Pure; src/graph_knowledge.ts feeds it.
 */
export interface AttributableSystem { id: string; name: string; kind: string; members: string[]; pool?: string | null; /** other names the system goes by: member Name tags, environment names */ aliases?: string[] }
/** One instance's own statement that it ships to a group (probe 1.6 `log_shipping`). */
export interface ObservedShipping { instance_id: string; via: string; source: string | null; at: string | null }
export interface AttributionContext {
  systems: AttributableSystem[];
  /** EKS cluster name -> the cluster system's id */
  clusters: Map<string, string>;
  /** Elastic Beanstalk environment name or id -> the pool system's id */
  beanstalk: Map<string, string>;
  /** Lambda function name -> the lambda system's id */
  lambdas: Map<string, string>;
  /** log group name -> the instances whose agent configs name it (optional; from the latest probes) */
  observed?: Map<string, ObservedShipping[]>;
}
export interface Attribution {
  owner: string | null;
  /** The rule that decided, in words: "observed: cloudwatch-agent on i-abc", "tag service=orion", "name tokens: orion" ... */
  how: string;
  /** For an unattributed group: the systems that came closest, best first ("pool:web (1.5: ~orion)"); empty when nothing scored. */
  candidates: string[];
}

const GENERIC = new Set(["aws", "log", "logs", "group", "app", "api", "service", "services", "default", "main", "prod", "dev", "test", "cluster", "pool", "pools", "system", "instance", "node", "nodes", "env", "docker", "stack", "web", "server"]);
export const tokens = (s: string): string[] => [...new Set(String(s).toLowerCase().split(/[^a-z0-9]+/).filter((t) => t.length >= 3 && !GENERIC.has(t) && !/^\d+$/.test(t)))];

/** Tag keys whose value names a resource the graph knows directly. */
const CLUSTER_TAGS = ["eks:cluster-name", "aws:eks:cluster-name", "alpha.eksctl.io/cluster-name", "kubernetes.io/cluster"];
const BEANSTALK_TAGS = ["elasticbeanstalk:environment-name", "elasticbeanstalk:environment-id"];
/** Tag keys whose values are about ownership or environment, never a system's name. */
const SKIP_TAGS = /^(environment|env|stage|owner|team|cost.?cent(er|re)|managed.?by|created.?by|terraform|purpose|tier|project|aws:cloudformation:(logical-id|stack-id))$/i;

const done = (owner: string | null, how: string, candidates: string[] = []): Attribution => ({ owner, how, candidates });

/** The system an instance (or any member id) belongs to, else null. */
export function systemOfMember(memberId: string, ctx: AttributionContext): AttributableSystem | null {
  // a pool member is also a member of its EKS cluster system; the pool is the tighter answer
  const hits = ctx.systems.filter((s) => s.members.includes(memberId));
  if (!hits.length) return null;
  return hits.find((s) => s.kind !== "eks_cluster") ?? hits[0];
}

export function attributeLogGroup(name: string, ctx: AttributionContext, tags: Record<string, string> = {}): Attribution {
  let m: RegExpMatchArray | null;
  // 1. observed: an instance's own agent config names the group
  const seen = ctx.observed?.get(name);
  if (seen?.length) {
    const bySystem = new Map<string, ObservedShipping[]>();
    let orphan: ObservedShipping | null = null;
    for (const o of seen) { const s = systemOfMember(o.instance_id, ctx); if (s) bySystem.set(s.id, [...(bySystem.get(s.id) || []), o]); else orphan ??= o; }
    if (bySystem.size === 1) { const [id, obs] = [...bySystem.entries()][0]; return done(id, `observed: ${obs[0].via} on ${obs.map((o) => o.instance_id).slice(0, 3).join(", ")}${obs.length > 3 ? ` and ${obs.length - 3} more` : ""}`); }
    if (bySystem.size > 1) return done(null, `observed on several systems: ${[...bySystem.keys()].join(", ")}`, [...bySystem.entries()].sort((a, b) => b[1].length - a[1].length).map(([id, obs]) => `${id} (${obs.length} instance${obs.length === 1 ? "" : "s"})`));
    if (orphan) return done(null, `observed: ${orphan.via} on ${orphan.instance_id}, which is in no system (stopped, or not in the inventory)`);
  }
  // 2. the AWS naming conventions
  if ((m = /^\/aws\/lambda\/([^/]+)/.exec(name))) { const id = ctx.lambdas.get(m[1]); return id ? done(id, "lambda function name") : done(null, "lambda not in the graph"); }
  if ((m = /^\/aws\/rds\/(cluster|instance)\/([^/]+)/.exec(name))) { const id = `rds:${m[2]}`; return ctx.systems.some((s) => s.id === id) ? done(id, `rds ${m[1]} name`) : done(null, "rds resource not in the inventory"); }
  if ((m = /^\/aws\/eks\/([^/]+)\/cluster/.exec(name))) { const id = ctx.clusters.get(m[1]); return id ? done(id, "eks control-plane log") : done(null, "eks cluster not in the inventory"); }
  if ((m = /^\/aws\/elasticbeanstalk\/([^/]+)\//.exec(name))) { const id = ctx.beanstalk.get(m[1]); return id ? done(id, "beanstalk environment name") : done(null, "beanstalk environment not in the inventory"); }
  // 3. the group's own tags
  const byTag = attributeByTags(tags, ctx);
  if (byTag) return byTag;
  // 4. the members' tags in the path
  const lower = name.toLowerCase();
  for (const [cluster, id] of ctx.clusters) if (cluster && lower.includes(cluster.toLowerCase())) return done(id, "eks cluster name in the path");
  for (const [env, id] of ctx.beanstalk) if (env && lower.includes(env.toLowerCase())) return done(id, "beanstalk environment in the path");
  // 5. token match: exact tokens count 1, a long token (6+) contained in a name counts 1, a 5-letter one 0.5
  const gt = tokens(name);
  if (!gt.length) return done(null, "no usable token");
  // compute kinds emit application logs; data kinds (databases, caches, gateways) have their own log conventions,
  // so on an equal score the compute system wins and only a tie between compute systems is ambiguous
  const rank = (k: string) => (["pool", "instance", "eks_cluster", "lambda"].includes(k) ? 1 : 0);
  const scored: { id: string; score: number; via: string; rank: number }[] = [];
  for (const s of ctx.systems) {
    const names = [s.name, s.pool || "", ...(s.aliases || [])];
    const st = new Set([...names.flatMap((n) => tokens(n)), ...s.members.flatMap((mm) => tokens(mm))]);
    const nameLower = `${names.join(" ")} ${s.members.join(" ")}`.toLowerCase();
    let score = 0; const via: string[] = [];
    for (const t of gt) {
      if (st.has(t)) { score += 1; via.push(t); }
      else if (t.length >= 6 && nameLower.includes(t)) { score += 1; via.push(`~${t}`); } // a long specific token inside a name (ab12cd in swarmab12cd)
      else if (t.length >= 5 && nameLower.includes(t)) { score += 0.5; via.push(`~${t}`); }
    }
    if (score > 0) scored.push({ id: s.id, score, via: via.join(","), rank: rank(s.kind) });
  }
  scored.sort((a, b) => b.score - a.score || b.rank - a.rank);
  const candidates = scored.slice(0, 3).map((c) => `${c.id} (${c.score}: ${c.via})`);
  const best = scored[0];
  if (!best || best.score < 1) return done(null, best ? `weak match only (${best.via})` : "no match", candidates);
  const tie = scored.some((c) => c !== best && c.score === best.score && c.rank === best.rank);
  if (tie) return done(null, `ambiguous: several systems match (${best.via})`, candidates);
  return done(best.id, `name tokens: ${best.via}`);
}

/** A tag value that is a cluster, an environment, or exactly a system's name, pool or alias. Two tags naming two systems is a tie. */
function attributeByTags(tags: Record<string, string>, ctx: AttributionContext): Attribution | null {
  const entries = Object.entries(tags || {}).filter(([k, v]) => k && v != null && String(v).trim() !== "");
  if (!entries.length) return null;
  const byKey = new Map(entries.map(([k, v]) => [k.toLowerCase(), String(v)]));
  for (const k of CLUSTER_TAGS) { const v = byKey.get(k); if (v) { for (const [cluster, id] of ctx.clusters) if (cluster.toLowerCase() === v.toLowerCase()) return done(id, `tag ${k}=${v}`); } }
  for (const k of BEANSTALK_TAGS) { const v = byKey.get(k); if (v) { for (const [env, id] of ctx.beanstalk) if (env.toLowerCase() === v.toLowerCase()) return done(id, `tag ${k}=${v}`); } }
  const index = new Map<string, Set<string>>();
  const put = (n: string | null | undefined, id: string) => { const key = String(n || "").trim().toLowerCase(); if (key) index.set(key, new Set([...(index.get(key) || []), id])); };
  for (const s of ctx.systems) { put(s.name, s.id); put(s.pool, s.id); for (const a of s.aliases || []) put(a, s.id); for (const mm of s.members) put(mm, s.id); }
  for (const [fn, id] of ctx.lambdas) put(fn, id);
  const hits = new Map<string, string>(); // system id -> "key=value"
  for (const [k, v] of entries) {
    if (SKIP_TAGS.test(k)) continue;
    const ids = index.get(String(v).trim().toLowerCase());
    if (!ids) continue;
    // a member id tagged on the group names its system; a pool and its EKS cluster both matching is one answer, the pool
    const narrowed = [...ids].filter((id) => !(ids.size > 1 && ctx.systems.find((s) => s.id === id)?.kind === "eks_cluster"));
    for (const id of narrowed) if (!hits.has(id)) hits.set(id, `${k}=${v}`);
  }
  if (hits.size === 1) { const [id, kv] = [...hits.entries()][0]; return done(id, `tag ${kv}`); }
  if (hits.size > 1) return done(null, `ambiguous: tags name several systems (${[...hits.values()].join(", ")})`, [...hits.entries()].map(([id, kv]) => `${id} (tag ${kv})`));
  return null;
}

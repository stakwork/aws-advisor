/**
 * Which system a CloudWatch log group belongs to, from evidence rather than a bare substring: the AWS naming
 * conventions first (Lambda, RDS, EKS, Elastic Beanstalk), then the tags the systems carry (cluster name,
 * environment name), then a token match between the group's path and the systems' names, pools and member
 * ids. Pure; src/graph_knowledge.ts feeds it.
 */
export interface AttributableSystem { id: string; name: string; kind: string; members: string[]; pool?: string | null; /** other names the system goes by: member Name tags, environment names */ aliases?: string[] }
export interface AttributionContext {
  systems: AttributableSystem[];
  /** EKS cluster name -> the cluster system's id */
  clusters: Map<string, string>;
  /** Elastic Beanstalk environment name or id -> the pool system's id */
  beanstalk: Map<string, string>;
  /** Lambda function name -> the lambda system's id */
  lambdas: Map<string, string>;
}
export interface Attribution { owner: string | null; how: string }

const GENERIC = new Set(["aws", "log", "logs", "group", "app", "api", "service", "services", "default", "main", "prod", "dev", "test", "cluster", "pool", "pools", "system", "instance", "node", "nodes", "env", "docker", "stack", "web", "server"]);
export const tokens = (s: string): string[] => [...new Set(String(s).toLowerCase().split(/[^a-z0-9]+/).filter((t) => t.length >= 3 && !GENERIC.has(t) && !/^\d+$/.test(t)))];

export function attributeLogGroup(name: string, ctx: AttributionContext): Attribution {
  let m: RegExpMatchArray | null;
  if ((m = /^\/aws\/lambda\/([^/]+)/.exec(name))) { const id = ctx.lambdas.get(m[1]); return id ? { owner: id, how: "lambda function name" } : { owner: null, how: "lambda not in the graph" }; }
  if ((m = /^\/aws\/rds\/(cluster|instance)\/([^/]+)/.exec(name))) { const id = `rds:${m[2]}`; return ctx.systems.some((s) => s.id === id) ? { owner: id, how: `rds ${m[1]} name` } : { owner: null, how: "rds resource not in the inventory" }; }
  if ((m = /^\/aws\/eks\/([^/]+)\/cluster/.exec(name))) { const id = ctx.clusters.get(m[1]); return id ? { owner: id, how: "eks control-plane log" } : { owner: null, how: "eks cluster not in the inventory" }; }
  if ((m = /^\/aws\/elasticbeanstalk\/([^/]+)\//.exec(name))) { const id = ctx.beanstalk.get(m[1]); return id ? { owner: id, how: "beanstalk environment name" } : { owner: null, how: "beanstalk environment not in the inventory" }; }
  const lower = name.toLowerCase();
  for (const [cluster, id] of ctx.clusters) if (cluster && lower.includes(cluster.toLowerCase())) return { owner: id, how: "eks cluster name in the path" };
  for (const [env, id] of ctx.beanstalk) if (env && lower.includes(env.toLowerCase())) return { owner: id, how: "beanstalk environment in the path" };
  // token match: exact tokens count 1, a long token (6+) contained in a name counts 1, a 5-letter one 0.5
  const gt = tokens(name);
  if (!gt.length) return { owner: null, how: "no usable token" };
  // compute kinds emit application logs; data kinds (databases, caches, gateways) have their own log conventions,
  // so on an equal score the compute system wins and only a tie between compute systems is ambiguous
  const rank = (k: string) => (["pool", "instance", "eks_cluster", "lambda"].includes(k) ? 1 : 0);
  let best: { id: string; score: number; via: string; rank: number } | null = null; let tie = false;
  for (const s of ctx.systems) {
    const names = [s.name, s.pool || "", ...(s.aliases || [])];
    const st = new Set([...names.flatMap((n) => tokens(n)), ...s.members.flatMap((mm) => tokens(mm))]);
    const nameLower = `${names.join(" ")} ${s.members.join(" ")}`.toLowerCase();
    let score = 0; const via: string[] = [];
    for (const t of gt) {
      if (st.has(t)) { score += 1; via.push(t); }
      else if (t.length >= 6 && nameLower.includes(t)) { score += 1; via.push(`~${t}`); } // a long specific token inside a name (rn9cyl in swarmrn9cyl)
      else if (t.length >= 5 && nameLower.includes(t)) { score += 0.5; via.push(`~${t}`); }
    }
    const r = rank(s.kind);
    if (score > 0 && (!best || score > best.score || (score === best.score && r > best.rank))) { best = { id: s.id, score, via: via.join(","), rank: r }; tie = false; }
    else if (best && score === best.score && r === best.rank && score > 0 && s.id !== best.id) tie = true;
  }
  if (!best || best.score < 1) return { owner: null, how: best ? `weak match only (${best.via})` : "no match" };
  if (tie) return { owner: null, how: `ambiguous: several systems match (${best.via})` };
  return { owner: best.id, how: `name tokens: ${best.via}` };
}

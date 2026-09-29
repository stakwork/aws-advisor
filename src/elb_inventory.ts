/**
 * Load balancers: every ALB, NLB, gateway and classic load balancer in the account with what it fronts and what
 * reaches it. Refreshed with the inventory. Each balancer carries its listeners, its target groups and their
 * targets resolved against the inventory (an instance target by id, an IP target by the instance's private
 * address, a Lambda target by function ARN), the Beanstalk environment that made it (from its tags), the
 * autoscaling groups and ECS services attached to its target groups, 30 days of traffic from CloudWatch
 * (requests and bytes, or flows for an NLB) and the hourly list price (the LCU part of the bill, which scales
 * with traffic, is left out and said so). The Route 53 links (src/route53_inventory.ts) already follow records
 * through a balancer to its targets; here the balancer is a row of its own, so "what is behind app-lb-1" and
 * "which balancers front i-abc" are one lookup, in the UI, the MCP tool and the graph
 * ((:AdvisorResource {kind: elb})-[:ROUTES_TO]->(:AdvisorResource)).
 */
import { CloudWatchClient, GetMetricDataCommand, type MetricDataQuery } from "@aws-sdk/client-cloudwatch";
import { addColumn, db } from "./db.js";
import { S, query, sdkCredentials } from "./steampipe.js";
import { describeError } from "./permissions.js";

db.exec(`create table if not exists inventory_elb (
  arn text primary key, name text not null, kind text not null, scheme text, dns_name text, state text, region text, vpc_id text, created text,
  azs integer, security_groups text, tags text, listeners text, target_groups text,
  targets integer not null default 0, healthy integer not null default 0, unhealthy integer not null default 0,
  requests_30d real, gb_30d real, flows_30d real, metric_days integer,
  beanstalk_env text, asgs text, ecs_services text, monthly_usd real,
  open_recs integer not null default 0, findings integer not null default 0,
  first_seen text not null, last_seen text not null, gone integer not null default 0
)`);
addColumn("inventory_elb", "account_id", "text");
db.exec("create index if not exists inventory_elb_name on inventory_elb(name)");

export type LbKind = "alb" | "nlb" | "gwlb" | "clb";
/** USD per hour at us-east-1 list: the fixed part. ALB and NLB add LCU-hours (0.008 and 0.006 USD), a classic balancer 0.008 USD per GB. */
export const ELB_USD_HOUR: Record<LbKind, number> = { alb: 0.0225, nlb: 0.0225, gwlb: 0.0125, clb: 0.025 };
export const HOURS_MONTH = 730;
export const METRIC_DAYS = 30;

export interface TargetRow { id: string; port: number | null; health: string | null; reason?: string | null; instance_id?: string | null; name?: string | null; lambda?: string | null }
export interface TargetGroupRow { arn: string; name: string; target_type: string | null; protocol: string | null; port: number | null; health_check: string | null; targets: TargetRow[]; asgs?: string[]; ecs_services?: string[] }
export interface ListenerRow { port: number | null; protocol: string | null; certificates: number; default_action: string | null }

const arr = (v: unknown): any[] => (Array.isArray(v) ? v : typeof v === "string" ? (() => { try { const p = JSON.parse(v); return Array.isArray(p) ? p : []; } catch { return []; } })() : []);
const obj = (v: unknown): any => (v && typeof v === "object" ? v : typeof v === "string" ? (() => { try { return JSON.parse(v); } catch { return null; } })() : null);
const num = (v: unknown): number | null => (v == null || v === "" ? null : Number.isFinite(Number(v)) ? Number(v) : null);
const iso = (v: unknown): string | null => (v == null ? null : v instanceof Date ? v.toISOString() : String(v));
const tgName = (arn: string) => arn.split(":targetgroup/")[1]?.split("/")[0] ?? arn;

/** The dimension value CloudWatch uses for an ALB, NLB or gateway balancer: the ARN's tail after `loadbalancer/` (e.g. `app/name/id`). */
export const metricDimension = (arn: string) => arn.split(":loadbalancer/")[1] ?? arn;

/** The fixed monthly price at list. Pure. */
export const elbMonthlyUsd = (kind: LbKind) => Math.round(ELB_USD_HOUR[kind] * HOURS_MONTH * 100) / 100;

/**
 * Targets of a target group resolved against the inventory: an `instance` target is the instance id, an `ip`
 * target is matched to an instance by private address, a `lambda` target is the function ARN. Pure.
 */
export function resolveTargets(targetType: string | null, descriptions: any[], byIp: Map<string, { id: string; name: string | null }>, byId: Map<string, string | null>): TargetRow[] {
  return descriptions.map((d) => {
    const id = String(d?.Target?.Id ?? ""); if (!id) return null;
    const row: TargetRow = { id, port: num(d?.Target?.Port), health: d?.TargetHealth?.State ?? null, reason: d?.TargetHealth?.Reason ?? null };
    if (targetType === "lambda" || id.startsWith("arn:aws:lambda:")) { row.lambda = id.split(":function:")[1]?.split(":")[0] ?? id; row.name = row.lambda; }
    else if (/^i-[0-9a-f]+$/.test(id)) { row.instance_id = id; row.name = byId.get(id) ?? null; }
    else if (targetType === "ip" || /^\d+\.\d+\.\d+\.\d+$/.test(id)) { const hit = byIp.get(id); if (hit) { row.instance_id = hit.id; row.name = hit.name; } }
    else if (id.startsWith("arn:aws:elasticloadbalancing:")) row.name = `ALB ${id.split("/")[2] ?? id}`;
    return row;
  }).filter((r): r is TargetRow => Boolean(r));
}

async function traffic(lbs: { arn: string; kind: LbKind; name: string; region: string }[], onLog: (s: string) => void): Promise<Map<string, { requests: number | null; bytes: number | null; flows: number | null; days: number }>> {
  const out = new Map<string, { requests: number | null; bytes: number | null; flows: number | null; days: number }>();
  const creds = sdkCredentials();
  const byRegion = new Map<string, typeof lbs>();
  for (const lb of lbs) { if (!byRegion.has(lb.region)) byRegion.set(lb.region, []); byRegion.get(lb.region)!.push(lb); }
  const now = Date.now();
  for (const [region, list] of byRegion) {
    const cw = new CloudWatchClient({ region, credentials: creds.provider });
    try {
      const queries: MetricDataQuery[] = []; const key: { arn: string; what: "requests" | "bytes" | "flows" }[] = [];
      const add = (arn: string, what: "requests" | "bytes" | "flows", Namespace: string, MetricName: string, dim: { Name: string; Value: string }, Stat = "Sum") => { queries.push({ Id: `q${key.length}`, MetricStat: { Metric: { Namespace, MetricName, Dimensions: [dim] }, Period: 86400, Stat }, ReturnData: true }); key.push({ arn, what }); };
      for (const lb of list) {
        const dim = lb.kind === "clb" ? { Name: "LoadBalancerName", Value: lb.name } : { Name: "LoadBalancer", Value: metricDimension(lb.arn) };
        if (lb.kind === "alb") { add(lb.arn, "requests", "AWS/ApplicationELB", "RequestCount", dim); add(lb.arn, "bytes", "AWS/ApplicationELB", "ProcessedBytes", dim); }
        else if (lb.kind === "nlb") { add(lb.arn, "flows", "AWS/NetworkELB", "ActiveFlowCount", dim, "Maximum"); add(lb.arn, "bytes", "AWS/NetworkELB", "ProcessedBytes", dim); }
        else if (lb.kind === "gwlb") add(lb.arn, "bytes", "AWS/GatewayELB", "ProcessedBytes", dim);
        else { add(lb.arn, "requests", "AWS/ELB", "RequestCount", dim); }
      }
      for (let i = 0; i < queries.length; i += 100) {
        const slice = queries.slice(i, i + 100);
        let NextToken: string | undefined;
        do {
          const r = await cw.send(new GetMetricDataCommand({ MetricDataQueries: slice, StartTime: new Date(now - METRIC_DAYS * 86400000), EndTime: new Date(now), NextToken, ScanBy: "TimestampDescending" }));
          for (const m of r.MetricDataResults ?? []) {
            const k = key[Number(String(m.Id).slice(1))]; if (!k || !m.Values?.length) continue;
            const e = out.get(k.arn) ?? { requests: null, bytes: null, flows: null, days: 0 }; out.set(k.arn, e);
            const v = k.what === "flows" ? Math.max(...m.Values) : m.Values.reduce((a, b) => a + b, 0);
            e[k.what] = (e[k.what] ?? 0) + v;
            e.days = Math.max(e.days, m.Values.length);
          }
          NextToken = r.NextToken;
        } while (NextToken);
      }
    } catch (e) { onLog(`elb traffic ${region}: ${describeError(e, `elb metrics ${region} (cloudwatch:GetMetricData)`, 160)}`); }
    finally { cw.destroy(); }
  }
  return out;
}

export async function refreshElbInventory(onError: (m: string) => void = () => {}, onLog: (s: string) => void = () => {}): Promise<number> {
  const opt = async <T,>(what: string, sql: string, required = false): Promise<T[] | null> => {
    try { return await query<T>(sql); }
    catch (e) { const m = describeError(e, `elb inventory (${what})`); if (required) onError(m); else onLog(`elb inventory: ${what} skipped: ${m.slice(0, 140)}`); return null; }
  };
  const [albs, nlbs, gwlbs, clbs, tgs, listeners, asgs, ecs] = await Promise.all([
    opt<any>("aws_ec2_application_load_balancer", `select name, arn, account_id, dns_name, state_code, scheme, vpc_id, created_time, availability_zones, security_groups, tags, region from ${S}.aws_ec2_application_load_balancer`, true),
    opt<any>("aws_ec2_network_load_balancer", `select name, arn, account_id, dns_name, state_code, scheme, vpc_id, created_time, availability_zones, tags, region from ${S}.aws_ec2_network_load_balancer`),
    opt<any>("aws_ec2_gateway_load_balancer", `select name, arn, account_id, dns_name, state_code, vpc_id, created_time, availability_zones, tags, region from ${S}.aws_ec2_gateway_load_balancer`),
    opt<any>("aws_ec2_classic_load_balancer", `select name, arn, account_id, dns_name, scheme, vpc_id, created_time, availability_zones, security_groups, instances, listener_descriptions, tags, region from ${S}.aws_ec2_classic_load_balancer`),
    opt<any>("aws_ec2_target_group", `select target_group_arn, target_group_name, target_type, protocol, port, load_balancer_arns, target_health_descriptions, health_check_path, health_check_protocol, health_check_port from ${S}.aws_ec2_target_group`),
    opt<any>("aws_ec2_load_balancer_listener", `select load_balancer_arn, port, protocol, certificates, default_actions from ${S}.aws_ec2_load_balancer_listener`),
    opt<any>("aws_ec2_autoscaling_group", `select name, load_balancer_names, target_group_arns from ${S}.aws_ec2_autoscaling_group`),
    opt<any>("aws_ecs_service", `select service_name, cluster_arn, load_balancers from ${S}.aws_ecs_service`),
  ]);
  if (!albs && !nlbs && !clbs && !gwlbs) return 0;

  const ec2 = db.prepare("select instance_id, name, private_ip from inventory_ec2 where gone = 0").all() as { instance_id: string; name: string | null; private_ip: string | null }[];
  const byIp = new Map(ec2.filter((r) => r.private_ip).map((r) => [r.private_ip!, { id: r.instance_id, name: r.name }]));
  const byId = new Map(ec2.map((r) => [r.instance_id, r.name]));

  // target groups per balancer, with the ASGs and ECS services attached to each group
  const asgByTg = new Map<string, string[]>(); const asgByLbName = new Map<string, string[]>();
  for (const g of asgs || []) {
    for (const t of arr(g.target_group_arns)) asgByTg.set(t, [...(asgByTg.get(t) || []), g.name]);
    for (const n of arr(g.load_balancer_names)) asgByLbName.set(n, [...(asgByLbName.get(n) || []), g.name]);
  }
  const ecsByTg = new Map<string, string[]>(); const ecsByLbName = new Map<string, string[]>();
  for (const s of ecs || []) {
    const cluster = String(s.cluster_arn || "").split("/").pop();
    const label = cluster ? `${cluster}/${s.service_name}` : String(s.service_name);
    for (const lb of arr(s.load_balancers)) { if (lb?.TargetGroupArn) ecsByTg.set(lb.TargetGroupArn, [...(ecsByTg.get(lb.TargetGroupArn) || []), label]); if (lb?.LoadBalancerName) ecsByLbName.set(lb.LoadBalancerName, [...(ecsByLbName.get(lb.LoadBalancerName) || []), label]); }
  }
  const tgByLb = new Map<string, TargetGroupRow[]>();
  for (const tg of tgs || []) {
    const row: TargetGroupRow = {
      arn: tg.target_group_arn, name: tg.target_group_name || tgName(tg.target_group_arn), target_type: tg.target_type ?? null, protocol: tg.protocol ?? null, port: num(tg.port),
      health_check: tg.health_check_path ? `${tg.health_check_protocol || ""}:${tg.health_check_port || ""}${tg.health_check_path}` : null,
      targets: resolveTargets(tg.target_type ?? null, arr(tg.target_health_descriptions), byIp, byId),
      asgs: asgByTg.get(tg.target_group_arn) || [], ecs_services: ecsByTg.get(tg.target_group_arn) || [],
    };
    for (const lbArn of arr(tg.load_balancer_arns)) tgByLb.set(lbArn, [...(tgByLb.get(lbArn) || []), row]);
  }
  const listenersByLb = new Map<string, ListenerRow[]>();
  for (const l of listeners || []) {
    const action = arr(l.default_actions)[0];
    const target = action?.Type === "forward" ? `forward → ${tgName(String(action?.TargetGroupArn || action?.ForwardConfig?.TargetGroups?.[0]?.TargetGroupArn || "?"))}` : action?.Type === "redirect" ? `redirect → ${action?.RedirectConfig?.Protocol || ""}:${action?.RedirectConfig?.Port || ""}` : action?.Type ? String(action.Type).replace(/-/g, " ") : null;
    listenersByLb.set(l.load_balancer_arn, [...(listenersByLb.get(l.load_balancer_arn) || []), { port: num(l.port), protocol: l.protocol ?? null, certificates: arr(l.certificates).length, default_action: target }]);
  }

  interface Lb { arn: string; name: string; kind: LbKind; account_id: string | null; dns_name: string | null; state: string | null; scheme: string | null; vpc_id: string | null; created: string | null; azs: number; security_groups: string[]; tags: Record<string, string>; listeners: ListenerRow[]; target_groups: TargetGroupRow[]; region: string }
  const lbs: Lb[] = [];
  const common = (r: any, kind: LbKind): Omit<Lb, "listeners" | "target_groups"> => ({ arn: r.arn, name: r.name, kind, account_id: r.account_id ? String(r.account_id) : null, dns_name: r.dns_name ?? null, state: r.state_code ?? (kind === "clb" ? "active" : null), scheme: r.scheme ?? null, vpc_id: r.vpc_id ?? null, created: iso(r.created_time), azs: arr(r.availability_zones).length, security_groups: arr(r.security_groups).map(String), tags: obj(r.tags) || {}, region: r.region });
  for (const r of albs || []) lbs.push({ ...common(r, "alb"), listeners: listenersByLb.get(r.arn) || [], target_groups: tgByLb.get(r.arn) || [] });
  for (const r of nlbs || []) lbs.push({ ...common(r, "nlb"), listeners: listenersByLb.get(r.arn) || [], target_groups: tgByLb.get(r.arn) || [] });
  for (const r of gwlbs || []) lbs.push({ ...common(r, "gwlb"), listeners: listenersByLb.get(r.arn) || [], target_groups: tgByLb.get(r.arn) || [] });
  for (const r of clbs || []) {
    const instances = arr(r.instances).map((i: any) => String(i?.InstanceId || "")).filter(Boolean);
    const tg: TargetGroupRow = { arn: r.arn, name: `${r.name} (classic)`, target_type: "instance", protocol: null, port: null, health_check: null, targets: instances.map((id: string) => ({ id, port: null, health: null, instance_id: id, name: byId.get(id) ?? null })), asgs: asgByLbName.get(r.name) || [], ecs_services: ecsByLbName.get(r.name) || [] };
    const ls: ListenerRow[] = arr(r.listener_descriptions).map((d: any) => ({ port: num(d?.Listener?.LoadBalancerPort), protocol: d?.Listener?.Protocol ?? null, certificates: d?.Listener?.SSLCertificateId ? 1 : 0, default_action: d?.Listener?.InstancePort != null ? `forward → instance port ${d.Listener.InstancePort}` : null }));
    lbs.push({ ...common(r, "clb"), listeners: ls, target_groups: instances.length ? [tg] : [] });
  }

  const metrics = lbs.length ? await traffic(lbs.map((l) => ({ arn: l.arn, kind: l.kind, name: l.name, region: l.region })), onLog) : new Map();
  const findingsFor = db.prepare("select count(*) as n from findings where run_id = (select max(run_id) from findings) and (resource = ? or resource = ?)");
  const recsFor = db.prepare("select count(*) as n from recommendations where status = 'open' and (resource = ? or resource = ?)");
  const now = new Date().toISOString().replace("T", " ").slice(0, 19);
  const up = db.prepare(`insert into inventory_elb(arn, name, kind, scheme, dns_name, state, region, vpc_id, created, azs, security_groups, tags, listeners, target_groups, targets, healthy, unhealthy, requests_30d, gb_30d, flows_30d, metric_days, beanstalk_env, asgs, ecs_services, monthly_usd, open_recs, findings, account_id, first_seen, last_seen, gone)
    values (@arn, @name, @kind, @scheme, @dns_name, @state, @region, @vpc_id, @created, @azs, @security_groups, @tags, @listeners, @target_groups, @targets, @healthy, @unhealthy, @requests_30d, @gb_30d, @flows_30d, @metric_days, @beanstalk_env, @asgs, @ecs_services, @monthly_usd, @open_recs, @findings, @account_id, @now, @now, 0)
    on conflict(arn) do update set name = excluded.name, kind = excluded.kind, scheme = excluded.scheme, dns_name = excluded.dns_name, state = excluded.state, region = excluded.region, vpc_id = excluded.vpc_id, created = excluded.created, azs = excluded.azs,
      security_groups = excluded.security_groups, tags = excluded.tags, listeners = excluded.listeners, target_groups = excluded.target_groups, targets = excluded.targets, healthy = excluded.healthy, unhealthy = excluded.unhealthy,
      requests_30d = excluded.requests_30d, gb_30d = excluded.gb_30d, flows_30d = excluded.flows_30d, metric_days = excluded.metric_days, beanstalk_env = excluded.beanstalk_env, asgs = excluded.asgs, ecs_services = excluded.ecs_services,
      monthly_usd = excluded.monthly_usd, open_recs = excluded.open_recs, findings = excluded.findings, account_id = coalesce(excluded.account_id, inventory_elb.account_id), last_seen = excluded.last_seen, gone = 0`);
  let n = 0;
  db.transaction(() => {
    for (const lb of lbs) {
      const all = lb.target_groups.flatMap((g) => g.targets);
      const healthy = all.filter((t) => t.health === "healthy").length;
      const unhealthy = all.filter((t) => t.health === "unhealthy").length;
      const m = metrics.get(lb.arn);
      const asgList = [...new Set([...lb.target_groups.flatMap((g) => g.asgs || []), ...(asgByLbName.get(lb.name) || [])])];
      const ecsList = [...new Set([...lb.target_groups.flatMap((g) => g.ecs_services || []), ...(ecsByLbName.get(lb.name) || [])])];
      up.run({
        arn: lb.arn, name: lb.name, kind: lb.kind, scheme: lb.scheme, dns_name: lb.dns_name, state: lb.state, region: lb.region, vpc_id: lb.vpc_id, created: lb.created, azs: lb.azs,
        security_groups: JSON.stringify(lb.security_groups), tags: JSON.stringify(lb.tags), listeners: JSON.stringify(lb.listeners), target_groups: JSON.stringify(lb.target_groups),
        targets: all.length, healthy, unhealthy, requests_30d: m?.requests ?? null, gb_30d: m?.bytes != null ? Math.round((m.bytes / 1e9) * 100) / 100 : null, flows_30d: m?.flows ?? null, metric_days: m?.days ?? 0,
        beanstalk_env: lb.tags["elasticbeanstalk:environment-name"] || null, asgs: JSON.stringify(asgList), ecs_services: JSON.stringify(ecsList), monthly_usd: elbMonthlyUsd(lb.kind),
        open_recs: (recsFor.get(lb.arn, lb.name) as any).n, findings: (findingsFor.get(lb.arn, lb.name) as any).n, account_id: lb.account_id, now,
      });
      n++;
    }
    db.prepare("update inventory_elb set gone = 1 where last_seen <> ?").run(now);
  })();
  onLog(`${n} load balancer(s): ${lbs.filter((l) => l.kind === "alb").length} ALB, ${lbs.filter((l) => l.kind === "nlb").length} NLB, ${lbs.filter((l) => l.kind === "clb").length} classic, ${lbs.filter((l) => l.kind === "gwlb").length} gateway`);
  return n;
}

const parseRow = (r: any) => ({ ...r, security_groups: arr(r.security_groups), tags: obj(r.tags) || {}, listeners: arr(r.listeners), target_groups: arr(r.target_groups), asgs: arr(r.asgs), ecs_services: arr(r.ecs_services) });

const SORTS = ["name", "kind", "scheme", "state", "region", "targets", "healthy", "requests_30d", "gb_30d", "monthly_usd", "created", "beanstalk_env", "open_recs", "findings"];
export function listElb(f: { q?: string; sort?: string; gone?: boolean; kind?: string; scheme?: string } = {}) {
  const where: string[] = []; const params: unknown[] = [];
  if (!f.gone) where.push("gone = 0");
  if (f.kind) { where.push("kind = ?"); params.push(f.kind); }
  if (f.scheme) { where.push("scheme = ?"); params.push(f.scheme); }
  if (f.q) { where.push("(name like ? or dns_name like ? or arn like ? or beanstalk_env like ? or target_groups like ? or vpc_id like ?)"); for (let i = 0; i < 6; i++) params.push(`%${f.q}%`); }
  const desc = f.sort?.startsWith("-"); const col = (f.sort || "").replace(/^-/, "");
  const order = SORTS.includes(col) ? `order by ${col} ${desc ? "desc" : "asc"} nulls last` : "order by requests_30d desc nulls last, gb_30d desc nulls last, name asc";
  return (db.prepare(`select * from inventory_elb ${where.length ? `where ${where.join(" and ")}` : ""} ${order} limit 2000`).all(...params) as any[]).map(parseRow);
}

export function elbDetail(idOrName: string) {
  const r = db.prepare("select * from inventory_elb where arn = ? or name = ? order by gone asc, last_seen desc limit 1").get(idOrName, idOrName);
  return r ? parseRow(r) : null;
}

/** The balancers in front of an instance (as an instance target, or an IP target matching its private address): name, kind, target group and health. */
export function elbsForInstance(instanceId: string): { arn: string; name: string; kind: string; scheme: string | null; dns_name: string | null; target_group: string; health: string | null; port: number | null }[] {
  const rows = db.prepare("select arn, name, kind, scheme, dns_name, target_groups from inventory_elb where gone = 0 and target_groups like ?").all(`%"instance_id":"${instanceId}"%`) as any[];
  const out: ReturnType<typeof elbsForInstance> = [];
  for (const r of rows) for (const g of arr(r.target_groups)) for (const t of g.targets || []) if (t.instance_id === instanceId) out.push({ arn: r.arn, name: r.name, kind: r.kind, scheme: r.scheme, dns_name: r.dns_name, target_group: g.name, health: t.health ?? null, port: t.port ?? null });
  return out;
}

/** The balancers whose target groups name a Lambda function. */
export function elbsForLambda(name: string) {
  const rows = db.prepare("select arn, name, kind, dns_name, target_groups from inventory_elb where gone = 0 and target_groups like ?").all(`%"lambda":"${name}"%`) as any[];
  return rows.map((r) => ({ arn: r.arn, name: r.name, kind: r.kind, dns_name: r.dns_name, target_groups: arr(r.target_groups).filter((g: any) => (g.targets || []).some((t: any) => t.lambda === name)).map((g: any) => g.name) }));
}

export function elbSummary() {
  const r = db.prepare(`select count(*) as total, coalesce(sum(kind = 'alb'), 0) as alb, coalesce(sum(kind = 'nlb'), 0) as nlb, coalesce(sum(kind = 'clb'), 0) as clb, coalesce(sum(kind = 'gwlb'), 0) as gwlb,
    coalesce(sum(scheme = 'internet-facing'), 0) as internet_facing, coalesce(sum(targets), 0) as targets, coalesce(sum(healthy), 0) as healthy, coalesce(sum(unhealthy), 0) as unhealthy,
    coalesce(sum(healthy = 0), 0) as no_healthy_target, coalesce(sum(requests_30d), 0) as requests_30d, coalesce(sum(gb_30d), 0) as gb_30d, coalesce(sum(monthly_usd), 0) as monthly_usd,
    coalesce(sum(beanstalk_env is not null), 0) as beanstalk, coalesce(sum(open_recs), 0) as open_recs, coalesce(sum(findings), 0) as findings from inventory_elb where gone = 0`).get() as any;
  const gone = (db.prepare("select count(*) as n from inventory_elb where gone = 1").get() as any).n;
  return { ...r, gone };
}

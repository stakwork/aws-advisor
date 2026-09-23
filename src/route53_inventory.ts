/**
 * Route 53 per record: every hosted zone with its records, and where each record actually leads inside this
 * account. A record's value (an alias, a CNAME host or an A/AAAA address) is followed to the load balancer,
 * CloudFront distribution, Elastic IP, instance, RDS or ElastiCache endpoint, S3 website bucket, Lambda URL or
 * API Gateway domain it names, and through load balancers to their targets and through distributions to their
 * origins, so an instance's detail can say which domains reach it and a domain's row can say what serves it.
 * Refreshed with the inventory (a handful of queries), plus by hand. The review of the result: records that
 * name an AWS-hosted thing this account does not have (deleted, or in another account: dangling either way),
 * records pointing outside AWS, and what the zones cost at list (0.50 USD per zone per month, queries at
 * 0.40 USD per million from the DNSQueries metric).
 */
import { db, getSetting, setSetting } from "./db.js";
import { S, query } from "./steampipe.js";
import { describeError } from "./permissions.js";

db.exec(`create table if not exists inventory_route53_zone (
  zone_id text primary key, name text not null, private integer not null default 0, comment text,
  records integer not null default 0, linked integer not null default 0, external integer not null default 0, unmatched integer not null default 0,
  queries_30d real, monthly_usd real, first_seen text not null, last_seen text not null, gone integer not null default 0
);
create table if not exists inventory_route53_record (
  id text primary key, zone_id text not null, zone_name text not null, name text not null, type text not null, ttl integer,
  alias integer not null default 0, "values" text, alias_target text, routing text, health_check_id text,
  link_state text not null, target text, summary text, links text,
  first_seen text not null, last_seen text not null, gone integer not null default 0
);
create index if not exists inventory_route53_record_zone on inventory_route53_record(gone, zone_id);
create table if not exists inventory_route53_link (
  record_id text not null, resource_kind text not null, resource_id text not null, hop integer not null default 1,
  primary key (record_id, resource_kind, resource_id)
);
create index if not exists inventory_route53_link_resource on inventory_route53_link(resource_kind, resource_id)`);

// ---- pure: the resolver ---------------------------------------------------------------------------------

export type LinkState = "linked" | "external" | "unmatched" | "none";

/** One in-account resource a record leads to. hop 1 is the record's direct target, 2 what that target fronts (an ALB's instances, a distribution's origins). */
export interface Link { kind: string; id: string; name?: string | null; state?: string | null; hop: number; via?: string | null }

export interface Resolution { link_state: LinkState; target: string | null; summary: string; links: Link[] }

export interface RecordIn { name: string; type: string; alias_target?: { DNSName?: string; HostedZoneId?: string } | null; values: string[] }

/** What the account has, by the names DNS can carry. Every list is optional so a missing permission drops one lookup, not the refresh. */
export interface ResourceIndex {
  ec2?: Array<{ id: string; name?: string | null; state?: string | null; public_ip?: string | null; private_ip?: string | null; public_dns?: string | null; private_dns?: string | null }>;
  eips?: Array<{ public_ip: string; instance_id?: string | null; network_interface_id?: string | null; private_ip?: string | null }>;
  enis?: Array<{ id: string; description?: string | null; interface_type?: string | null; instance_id?: string | null; private_ip?: string | null; public_ip?: string | null }>;
  lbs?: Array<{ kind: "alb" | "nlb" | "clb"; name: string; arn?: string | null; dns_name: string; state?: string | null; targets?: string[] }>;
  cloudfront?: Array<{ id: string; domain_name: string; aliases?: string[]; origins?: string[]; enabled?: boolean | null; status?: string | null }>;
  rds?: Array<{ id: string; endpoints: string[]; state?: string | null; cluster?: boolean }>;
  elasticache?: Array<{ id: string; endpoints: string[]; state?: string | null; group?: boolean }>;
  s3?: string[];
  lambda?: Array<{ name: string; url?: string | null }>;
  apigw?: Array<{ domain_name: string; targets: string[] }>;
  beanstalk?: Array<{ name: string; cname: string; endpoint?: string | null; state?: string | null }>;
  /** AWS's published EC2 IPv4 prefixes: an address in one of them that no resource here owns is a terminated instance's (or another account's), not a stranger's */
  awsRanges?: AwsRange[];
  /** every record in the account's zones, so an alias or CNAME to another record is followed */
  records?: RecordIn[];
}

export interface AwsRange { prefix: string; region: string; service: string }
const ip4 = (ip: string): number | null => { const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip); if (!m) return null; const p = m.slice(1).map(Number); return p.some((x) => x > 255) ? null : ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0; };
/** Which published AWS range holds an IPv4 address, if any. Pure. */
export function awsRangeOf(ip: string, ranges: AwsRange[] | undefined): AwsRange | null {
  const n = ip4(ip); if (n == null || !ranges) return null;
  for (const r of ranges) {
    const [base, bits] = r.prefix.split("/"); const b = ip4(base); const len = Number(bits);
    if (b == null || !Number.isFinite(len)) continue;
    const mask = len === 0 ? 0 : (0xffffffff << (32 - len)) >>> 0;
    if (((n & mask) >>> 0) === ((b & mask) >>> 0)) return r;
  }
  return null;
}

/** Route 53 returns names with octal escapes (`\052` for `*`, `\100` for `@`); decoded before anything compares them. */
export const decodeName = (s: string) => s.replace(/\\(\d{3})/g, (_, o) => String.fromCharCode(parseInt(o, 8)));
const host = (s: string | null | undefined) => decodeName(s || "").trim().toLowerCase().replace(/\.$/, "").replace(/^dualstack\./, "");
const isIp = (s: string) => /^\d{1,3}(\.\d{1,3}){3}$/.test(s) || /^[0-9a-f:]+$/i.test(s) && s.includes(":");
const isPrivateIp = (ip: string) => /^10\./.test(ip) || /^192\.168\./.test(ip) || /^172\.(1[6-9]|2\d|3[01])\./.test(ip) || /^fd/i.test(ip);

/** Well-known hosts outside AWS, for the "Points to" column; the suffix is enough, the record itself carries the full host. */
const PROVIDERS: Array<[RegExp, string]> = [
  [/\.cloudflare(-dns)?\.com$|\.cdn\.cloudflare\.net$/, "Cloudflare"], [/\.herokudns\.com$|\.herokuapp\.com$|\.herokussl\.com$/, "Heroku"], [/\.netlify\.(app|com)$/, "Netlify"],
  [/\.vercel(-dns(-\d+)?)?\.(app|com)$/, "Vercel"], [/\.github\.io$|\.githubusercontent\.com$/, "GitHub Pages"], [/\.googlehosted\.com$|\.google\.com$|\.googleusercontent\.com$|\.appspot\.com$|\.firebaseapp\.com$|\.web\.app$/, "Google"],
  [/\.myshopify\.com$|\.shopify\.com$/, "Shopify"], [/\.wixdns\.net$|\.wix\.com$/, "Wix"], [/\.squarespace\.com$/, "Squarespace"], [/\.hubspot\.(com|net)$|\.hs-sites\.com$|\.hubspotemail\.net$/, "HubSpot"],
  [/\.sendgrid\.net$/, "SendGrid"], [/\.mailgun\.org$/, "Mailgun"], [/\.azurewebsites\.net$|\.azure\.com$|\.trafficmanager\.net$|\.azurefd\.net$|\.azureedge\.net$/, "Azure"], [/\.fastly\.net$|\.fastlylb\.net$/, "Fastly"],
  [/\.akamai(edge|hd)?\.net$|\.edgekey\.net$|\.edgesuite\.net$/, "Akamai"], [/\.digitaloceanspaces\.com$|\.ondigitalocean\.app$/, "DigitalOcean"], [/\.fly\.dev$/, "Fly.io"], [/\.render\.com$|\.onrender\.com$/, "Render"],
  [/\.zendesk\.com$/, "Zendesk"], [/\.intercom\.(io|help)$/, "Intercom"], [/\.readme\.io$/, "ReadMe"], [/\.ghost\.io$/, "Ghost"], [/\.webflow\.io$|\.proxy-ssl\.webflow\.com$/, "Webflow"],
  [/\.outlook\.com$|\.office365\.com$|mail\.protection\.outlook\.com$/, "Microsoft 365"], [/\.pphosted\.com$/, "Proofpoint"], [/\.mimecast\.com$/, "Mimecast"], [/\.pobox\.com$|\.fastmail\.com$|\.messagingengine\.com$/, "Fastmail"],
];
const providerOf = (h: string) => PROVIDERS.find(([re]) => re.test(h))?.[1] ?? null;

/** AWS-hosted names: when one of these is not in the account's index the record is dangling from this account's point of view. */
const AWS_SHAPES: Array<[RegExp, string]> = [
  [/\.elb\.amazonaws\.com$|\.elb\.[a-z0-9-]+\.amazonaws\.com$/, "load balancer"], [/\.cloudfront\.net$/, "CloudFront distribution"], [/\.rds\.amazonaws\.com$/, "RDS endpoint"],
  [/\.cache\.amazonaws\.com$/, "ElastiCache endpoint"], [/\.compute(-1)?\.amazonaws\.com$/, "EC2 public DNS"], [/\.elasticbeanstalk\.com$/, "Elastic Beanstalk environment"],
  [/\.execute-api\.[a-z0-9-]+\.amazonaws\.com$/, "API Gateway"], [/\.lambda-url\.[a-z0-9-]+\.on\.aws$/, "Lambda function URL"], [/\.awsglobalaccelerator\.com$/, "Global Accelerator"],
  [/\.amplifyapp\.com$/, "Amplify app"], [/\.awsapprunner\.com$/, "App Runner service"], [/\.s3[.-][a-z0-9-]*\.?amazonaws\.com$|\.s3\.amazonaws\.com$/, "S3 bucket"],
  [/\.elasticloadbalancing\.[a-z0-9-]+\.amazonaws\.com$/, "load balancer"], [/\.vpce\.amazonaws\.com$/, "VPC endpoint"], [/\.awsapps\.com$/, "AWS app"],
];
const awsShape = (h: string) => AWS_SHAPES.find(([re]) => re.test(h))?.[1] ?? null;

const S3_HOST = [/^(?<bucket>[a-z0-9.-]+)\.s3-website[-.](?<region>[a-z0-9-]+)\.amazonaws\.com$/, /^(?<bucket>[a-z0-9.-]+)\.s3\.amazonaws\.com$/, /^(?<bucket>[a-z0-9.-]+)\.s3[.-](?<region>[a-z0-9-]+)\.amazonaws\.com$/];
/** The bucket an S3 host names: `bucket.s3-website-us-east-1.amazonaws.com`, or the record's own name for the plain website alias `s3-website-us-east-1.amazonaws.com`. */
export function s3BucketFromHost(h: string, recordName: string): string | null {
  if (/^s3-website[-.][a-z0-9-]+\.amazonaws\.com$/.test(h)) return host(recordName);
  for (const re of S3_HOST) { const m = re.exec(h); if (m?.groups?.bucket) return m.groups.bucket; }
  return null;
}

class Resolver {
  private lbByDns = new Map<string, NonNullable<ResourceIndex["lbs"]>[number]>();
  private lbByArn = new Map<string, NonNullable<ResourceIndex["lbs"]>[number]>();
  private cfByDomain = new Map<string, NonNullable<ResourceIndex["cloudfront"]>[number]>();
  private rdsByHost = new Map<string, NonNullable<ResourceIndex["rds"]>[number]>();
  private cacheByHost = new Map<string, NonNullable<ResourceIndex["elasticache"]>[number]>();
  private ec2ByHost = new Map<string, NonNullable<ResourceIndex["ec2"]>[number]>();
  private ec2ByIp = new Map<string, NonNullable<ResourceIndex["ec2"]>[number]>();
  private ec2ById = new Map<string, NonNullable<ResourceIndex["ec2"]>[number]>();
  private eipByIp = new Map<string, NonNullable<ResourceIndex["eips"]>[number]>();
  private eniByIp = new Map<string, NonNullable<ResourceIndex["enis"]>[number]>();
  private eniById = new Map<string, NonNullable<ResourceIndex["enis"]>[number]>();
  private buckets = new Set<string>();
  private lambdaByUrlHost = new Map<string, string>();
  private lambdaNames = new Set<string>();
  private apigwByDomain = new Map<string, NonNullable<ResourceIndex["apigw"]>[number]>();
  private beanstalkByCname = new Map<string, NonNullable<ResourceIndex["beanstalk"]>[number]>();
  private ranges: AwsRange[] | undefined;
  private recordsByName = new Map<string, RecordIn[]>();

  constructor(idx: ResourceIndex) {
    for (const lb of idx.lbs || []) { this.lbByDns.set(host(lb.dns_name), lb); if (lb.arn) this.lbByArn.set(lb.arn, lb); }
    for (const d of idx.cloudfront || []) this.cfByDomain.set(host(d.domain_name), d);
    for (const r of idx.rds || []) for (const e of r.endpoints) if (e) this.rdsByHost.set(host(e), r);
    for (const c of idx.elasticache || []) for (const e of c.endpoints) if (e) this.cacheByHost.set(host(e), c);
    for (const i of idx.ec2 || []) {
      this.ec2ById.set(i.id, i);
      if (i.public_dns) this.ec2ByHost.set(host(i.public_dns), i); if (i.private_dns) this.ec2ByHost.set(host(i.private_dns), i);
      if (i.public_ip) this.ec2ByIp.set(i.public_ip, i); if (i.private_ip) this.ec2ByIp.set(i.private_ip, i);
    }
    for (const e of idx.eips || []) if (e.public_ip) this.eipByIp.set(e.public_ip, e);
    for (const n of idx.enis || []) { this.eniById.set(n.id, n); if (n.public_ip) this.eniByIp.set(n.public_ip, n); if (n.private_ip) this.eniByIp.set(n.private_ip, n); }
    for (const b of idx.s3 || []) this.buckets.add(b.toLowerCase());
    for (const f of idx.lambda || []) { this.lambdaNames.add(f.name); if (f.url) { try { this.lambdaByUrlHost.set(host(new URL(f.url).hostname), f.name); } catch { /* not a URL */ } } }
    for (const a of idx.apigw || []) this.apigwByDomain.set(host(a.domain_name), a);
    for (const b of idx.beanstalk || []) if (b.cname) this.beanstalkByCname.set(host(b.cname), b);
    this.ranges = idx.awsRanges;
    for (const r of idx.records || []) { const k = host(r.name); if (!this.recordsByName.has(k)) this.recordsByName.set(k, []); this.recordsByName.get(k)!.push(r); }
  }

  private ec2Link(i: NonNullable<ResourceIndex["ec2"]>[number], hop: number, via: string | null): Link { return { kind: "ec2", id: i.id, name: i.name ?? null, state: i.state ?? null, hop, via }; }

  /** An ALB/NLB target or a classic LB instance: an instance id, an IP (a private one is usually an instance's), or a Lambda ARN. */
  private targetLinks(lb: NonNullable<ResourceIndex["lbs"]>[number], hop: number): Link[] {
    const out: Link[] = []; const seen = new Set<string>();
    for (const t of lb.targets || []) {
      const via = `${lb.kind.toUpperCase()} ${lb.name}`;
      if (/^i-/.test(t)) { const i = this.ec2ById.get(t); const l = i ? this.ec2Link(i, hop, via) : { kind: "ec2", id: t, name: null, state: "unknown", hop, via }; if (!seen.has(l.id)) { seen.add(l.id); out.push(l); } }
      else if (/^arn:aws:lambda:/.test(t)) { const name = t.split(":")[6]; if (name && !seen.has(name)) { seen.add(name); out.push({ kind: "lambda", id: name, hop, via }); } }
      else if (isIp(t)) { for (const l of this.resolveIp(t, hop, via).links) if (!seen.has(`${l.kind}:${l.id}`)) { seen.add(`${l.kind}:${l.id}`); out.push(l); } }
    }
    return out;
  }

  resolveIp(ip: string, hop = 1, via: string | null = null): Resolution {
    const eip = this.eipByIp.get(ip);
    if (eip?.instance_id) { const i = this.ec2ById.get(eip.instance_id); const l = i ? this.ec2Link(i, hop, via ?? `Elastic IP ${ip}`) : { kind: "ec2", id: eip.instance_id, name: null, state: "unknown", hop, via: via ?? `Elastic IP ${ip}` }; return { link_state: "linked", target: ip, summary: `Elastic IP ${ip} on ${l.name || l.id}${l.state ? ` (${l.state})` : ""}`, links: [l] }; }
    const direct = this.ec2ByIp.get(ip);
    if (direct) { const l = this.ec2Link(direct, hop, via); return { link_state: "linked", target: ip, summary: `${direct.public_ip === ip ? "public" : "private"} IP of ${direct.name || direct.id}${direct.state ? ` (${direct.state})` : ""}`, links: [l] }; }
    const eni = this.eniByIp.get(ip) ?? (eip?.network_interface_id ? this.eniById.get(eip.network_interface_id) : undefined);
    if (eni) return this.eniResolution(eni, ip, hop, via, Boolean(eip));
    if (eip) return { link_state: "linked", target: ip, summary: `Elastic IP ${ip}, not associated with anything (it still costs 3.65 USD a month)`, links: [{ kind: "eip", id: ip, name: null, state: "unassociated", hop, via }] };
    if (isPrivateIp(ip)) return { link_state: "unmatched", target: ip, summary: `private IP ${ip}: no interface in this account has it`, links: [] };
    const range = awsRangeOf(ip, this.ranges);
    if (range) return { link_state: "unmatched", target: ip, summary: `AWS ${range.service === "EC2" ? "EC2" : range.service} address ${ip} (${range.region}) that nothing in this account holds: a terminated instance's, a released Elastic IP's, or another account's`, links: [] };
    return { link_state: "external", target: ip, summary: `${ip}, not an AWS address${this.ranges ? "" : " of this account (AWS ranges not loaded)"}`, links: [] };
  }

  private eniResolution(eni: NonNullable<ResourceIndex["enis"]>[number], ip: string, hop: number, via: string | null, viaEip: boolean): Resolution {
    const desc = eni.description || ""; const pre = viaEip ? `Elastic IP ${ip} on ` : "";
    if (eni.instance_id) { const i = this.ec2ById.get(eni.instance_id); const l = i ? this.ec2Link(i, hop, via ?? (viaEip ? `Elastic IP ${ip}` : null)) : { kind: "ec2", id: eni.instance_id, name: null, state: "unknown", hop, via }; return { link_state: "linked", target: ip, summary: `${pre}${l.name || l.id}${l.state ? ` (${l.state})` : ""}`, links: [l] }; }
    const nat = /NAT Gateway (nat-[0-9a-f]+)/i.exec(desc);
    if (nat || eni.interface_type === "nat_gateway") { const id = nat?.[1] ?? eni.id; return { link_state: "linked", target: ip, summary: `${pre}NAT gateway ${id}`, links: [{ kind: "nat", id, name: null, state: null, hop, via }] }; }
    const elb = /^ELB (?:app|net)\/([^/]+)\/|^ELB ([^\s/]+)$/.exec(desc);
    if (elb) { const name = elb[1] || elb[2]; const lb = [...this.lbByDns.values()].find((l) => l.name === name); if (lb) return this.lbResolution(lb, ip, hop, via); return { link_state: "linked", target: ip, summary: `${pre}load balancer ${name}`, links: [{ kind: "lb", id: name, name, state: null, hop, via }] }; }
    if (/RDSNetworkInterface/i.test(desc) || eni.interface_type === "rds") return { link_state: "linked", target: ip, summary: `${pre}an RDS instance's interface (${eni.id})`, links: [{ kind: "eni", id: eni.id, name: desc || null, state: null, hop, via }] };
    if (/ElastiCache/i.test(desc)) return { link_state: "linked", target: ip, summary: `${pre}an ElastiCache node's interface (${eni.id})`, links: [{ kind: "eni", id: eni.id, name: desc || null, state: null, hop, via }] };
    if (/^AWS Lambda VPC ENI/i.test(desc) || eni.interface_type === "lambda") return { link_state: "linked", target: ip, summary: `${pre}a Lambda VPC interface (${eni.id})`, links: [{ kind: "eni", id: eni.id, name: desc || null, state: null, hop, via }] };
    if (/^Interface for (?:EKS|ECS)|^amazon-eks|^arn:aws:ecs/i.test(desc) || eni.interface_type === "branch") return { link_state: "linked", target: ip, summary: `${pre}a container interface (${desc || eni.id})`, links: [{ kind: "eni", id: eni.id, name: desc || null, state: null, hop, via }] };
    if (/VPC Endpoint Interface/i.test(desc) || eni.interface_type === "vpc_endpoint") return { link_state: "linked", target: ip, summary: `${pre}a VPC endpoint interface (${eni.id})`, links: [{ kind: "eni", id: eni.id, name: desc || null, state: null, hop, via }] };
    return { link_state: "linked", target: ip, summary: `${pre}network interface ${eni.id}${desc ? ` (${desc})` : ""}`, links: [{ kind: "eni", id: eni.id, name: desc || null, state: null, hop, via }] };
  }

  private lbResolution(lb: NonNullable<ResourceIndex["lbs"]>[number], target: string, hop: number, via: string | null): Resolution {
    const targets = this.targetLinks(lb, hop + 1);
    const label = lb.kind === "clb" ? "classic load balancer" : lb.kind.toUpperCase();
    const behind = targets.length ? ` → ${targets.map((t) => t.name || t.id).slice(0, 4).join(", ")}${targets.length > 4 ? ` and ${targets.length - 4} more` : ""}` : " (no registered targets)";
    return { link_state: "linked", target, summary: `${label} ${lb.name}${lb.state && lb.state !== "active" ? ` (${lb.state})` : ""}${behind}`, links: [{ kind: lb.kind, id: lb.name, name: lb.name, state: lb.state ?? null, hop, via }, ...targets] };
  }

  resolveHost(h: string, recordName: string, hop = 1, via: string | null = null, depth = 0): Resolution {
    h = host(h);
    const lb = this.lbByDns.get(h) ?? this.lbByDns.get(h.replace(/^internal-/, ""));
    if (lb) return this.lbResolution(lb, h, hop, via);
    const cf = this.cfByDomain.get(h);
    if (cf) {
      const origins: Link[] = []; const parts: string[] = [];
      for (const o of cf.origins || []) {
        if (depth > 3) break;
        const r = this.resolveHost(o, recordName, hop + 1, `CloudFront ${cf.id}`, depth + 1);
        origins.push(...r.links); parts.push(r.link_state === "linked" ? r.summary : host(o));
      }
      const state = cf.enabled === false ? "disabled" : cf.status ?? null;
      return { link_state: "linked", target: h, summary: `CloudFront ${cf.id}${state && state !== "Deployed" ? ` (${state})` : ""}${parts.length ? ` → ${parts.join("; ")}` : ""}`, links: [{ kind: "cloudfront", id: cf.id, name: cf.aliases?.[0] ?? null, state, hop, via }, ...origins] };
    }
    const rds = this.rdsByHost.get(h);
    if (rds) return { link_state: "linked", target: h, summary: `RDS ${rds.cluster ? "cluster " : ""}${rds.id}${rds.state ? ` (${rds.state})` : ""}`, links: [{ kind: rds.cluster ? "rds_cluster" : "rds", id: rds.id, name: rds.id, state: rds.state ?? null, hop, via }] };
    const cache = this.cacheByHost.get(h);
    if (cache) return { link_state: "linked", target: h, summary: `ElastiCache ${cache.group ? "replication group " : ""}${cache.id}${cache.state ? ` (${cache.state})` : ""}`, links: [{ kind: cache.group ? "elasticache_group" : "elasticache", id: cache.id, name: cache.id, state: cache.state ?? null, hop, via }] };
    const ec2 = this.ec2ByHost.get(h);
    if (ec2) return { link_state: "linked", target: h, summary: `${ec2.name || ec2.id}${ec2.state ? ` (${ec2.state})` : ""}`, links: [this.ec2Link(ec2, hop, via)] };
    const bucket = s3BucketFromHost(h, recordName);
    if (bucket) {
      if (this.buckets.has(bucket)) return { link_state: "linked", target: h, summary: `S3 bucket ${bucket}`, links: [{ kind: "s3", id: bucket, name: bucket, state: null, hop, via }] };
      return { link_state: "unmatched", target: h, summary: `S3 bucket ${bucket} does not exist in this account: the name can be claimed by anyone (delete the record or create the bucket)`, links: [] };
    }
    const eb = this.beanstalkByCname.get(h);
    if (eb) {
      const behind = eb.endpoint ? (isIp(eb.endpoint) ? this.resolveIp(eb.endpoint, hop + 1, `Beanstalk ${eb.name}`) : this.resolveHost(eb.endpoint, recordName, hop + 1, `Beanstalk ${eb.name}`, depth + 1)) : null;
      const state = eb.state && eb.state !== "Ready" ? ` (${eb.state})` : "";
      return { link_state: "linked", target: h, summary: `Elastic Beanstalk ${eb.name}${state}${behind?.links.length ? ` → ${behind.summary}` : ""}`, links: [{ kind: "beanstalk", id: eb.name, name: eb.name, state: eb.state ?? null, hop, via }, ...(behind?.links ?? [])] };
    }
    const fn = this.lambdaByUrlHost.get(h);
    if (fn) return { link_state: "linked", target: h, summary: `Lambda ${fn} (function URL)`, links: [{ kind: "lambda", id: fn, name: fn, state: null, hop, via }] };
    const api = this.apigwByDomain.get(h) ?? this.apigwByDomain.get(host(recordName));
    if (api && (api.domain_name === h || api.targets.map(host).includes(h))) return { link_state: "linked", target: h, summary: `API Gateway custom domain ${api.domain_name}`, links: [{ kind: "apigw", id: api.domain_name, name: api.domain_name, state: null, hop, via }] };
    if (/\.acm-validations\.aws$/.test(h)) return { link_state: "none", target: h, summary: "ACM certificate validation", links: [] };
    if (/\.dkim\.amazonses\.com$/.test(h)) return { link_state: "none", target: h, summary: "SES DKIM signing", links: [] };
    if (/^mail\.[a-z0-9-]+\.awsapps\.com$/.test(h)) return { link_state: "none", target: h, summary: "WorkMail", links: [] };
    // another record in the account's zones (an apex alias to www, a CNAME chain): follow it
    const next = (this.recordsByName.get(h) || []).filter((r) => ["A", "AAAA", "CNAME"].includes(r.type));
    if (next.length && depth <= 3 && h !== host(recordName)) {
      const r = this.resolve(next[0], depth + 1);
      return { link_state: r.link_state, target: h, summary: `record ${h} → ${r.summary}`, links: r.links.map((l) => ({ ...l, hop: l.hop + hop - 1, via: l.via ?? `record ${h}` })) };
    }
    const shape = awsShape(h);
    if (shape) return { link_state: "unmatched", target: h, summary: `${shape} ${h} is not in this account: deleted (a dangling record) or owned by another account`, links: [] };
    const provider = providerOf(h);
    return { link_state: "external", target: h, summary: provider ? `${provider} (${h})` : h, links: [] };
  }

  resolve(rec: RecordIn, depth = 0): Resolution {
    const type = rec.type.toUpperCase(); const vals = (rec.values || []).map((v) => String(v).trim()).filter(Boolean);
    if (type === "NS") return { link_state: "none", target: null, summary: vals.some((v) => /awsdns/.test(v)) ? "zone delegation (Route 53 name servers)" : "zone delegation (name servers elsewhere)", links: [] };
    if (type === "SOA") return { link_state: "none", target: null, summary: "zone authority", links: [] };
    if (type === "MX") {
      const hosts = vals.map((v) => host(v.split(/\s+/).pop()));
      if (hosts.some((h) => /\.amazonaws\.com$/.test(h) && /inbound-smtp/.test(h))) return { link_state: "none", target: hosts[0], summary: "SES inbound mail", links: [] };
      const p = hosts.map(providerOf).find(Boolean);
      return { link_state: "external", target: hosts[0] ?? null, summary: `mail: ${p ?? hosts.slice(0, 2).join(", ")}`, links: [] };
    }
    if (type === "TXT") {
      const joined = vals.join(" ");
      if (/^_dmarc\./i.test(rec.name)) return { link_state: "none", target: null, summary: "DMARC policy", links: [] };
      if (/v=spf1/i.test(joined)) return { link_state: "none", target: null, summary: `SPF${/amazonses/.test(joined) ? " (includes SES)" : ""}`, links: [] };
      if (/^_amazonses\./i.test(rec.name) || /amazonses/i.test(joined)) return { link_state: "none", target: null, summary: "SES domain verification", links: [] };
      if (/^_acme-challenge\./i.test(rec.name)) return { link_state: "none", target: null, summary: "ACME (Let's Encrypt) challenge", links: [] };
      if (/-site-verification=|^ms=|^google-site|_domainconnect|verification/i.test(joined + rec.name)) return { link_state: "none", target: null, summary: "domain ownership verification", links: [] };
      return { link_state: "none", target: null, summary: "text record", links: [] };
    }
    if (["CAA", "SRV", "PTR", "SPF", "DS", "NAPTR", "TLSA", "SSHFP", "HTTPS", "SVCB"].includes(type)) return { link_state: "none", target: null, summary: type === "CAA" ? "certificate authority authorization" : `${type} record`, links: [] };
    if (rec.alias_target?.DNSName) return this.resolveHost(rec.alias_target.DNSName, rec.name, 1, null, depth);
    if (type === "CNAME") return vals.length ? this.resolveHost(vals[0], rec.name, 1, null, depth) : { link_state: "none", target: null, summary: "empty", links: [] };
    if (type === "A" || type === "AAAA") {
      const rs = vals.filter(isIp).map((ip) => this.resolveIp(ip));
      if (!rs.length) return { link_state: "none", target: null, summary: "empty", links: [] };
      const links: Link[] = []; const seen = new Set<string>();
      for (const r of rs) for (const l of r.links) { const k = `${l.kind}:${l.id}`; if (!seen.has(k)) { seen.add(k); links.push(l); } }
      const link_state: LinkState = rs.some((r) => r.link_state === "linked") ? "linked" : rs.some((r) => r.link_state === "unmatched") ? "unmatched" : "external";
      const summary = rs.length === 1 ? rs[0].summary : `${rs.length} addresses: ${rs.map((r) => r.summary).join("; ")}`;
      return { link_state, target: vals.join(", "), summary, links };
    }
    return { link_state: "none", target: vals[0] ?? null, summary: `${type} record`, links: [] };
  }
}

/** Follows one record to what serves it. Pure: the index is everything it looks at. */
export function resolveRecord(rec: RecordIn, idx: ResourceIndex): Resolution { return new Resolver(idx).resolve(rec); }
/** One resolver for a whole refresh (the index is built once). */
export function makeResolver(idx: ResourceIndex): (rec: RecordIn) => Resolution { const r = new Resolver(idx); return (rec) => r.resolve(rec); }

/** Route 53 list price: 0.50 USD per hosted zone per month for the first 25, 0.10 after; standard queries 0.40 USD per million (alias queries to AWS resources are free, so this is the ceiling). Pure. */
export function zoneMonthlyCost(zoneIndex: number, queriesPerMonth: number | null): number {
  return Math.round(((zoneIndex < 25 ? 0.5 : 0.1) + (queriesPerMonth ?? 0) * 0.4 / 1e6) * 100) / 100;
}

// ---- refresh ------------------------------------------------------------------------------------------

const arr = (v: unknown): any[] => (Array.isArray(v) ? v : typeof v === "string" ? (() => { try { const p = JSON.parse(v); return Array.isArray(p) ? p : []; } catch { return []; } })() : []);
const obj = (v: unknown): any => (v && typeof v === "object" ? v : typeof v === "string" ? (() => { try { return JSON.parse(v); } catch { return null; } })() : null);
const zoneId = (v: unknown) => String(v ?? "").replace(/^\/hostedzone\//, "");

/** What the account has, from the inventory tables already refreshed and a few Steampipe lookups. Each lookup fails on its own. */
async function buildIndex(onLog: (s: string) => void, errors: string[]): Promise<ResourceIndex> {
  const idx: ResourceIndex = {};
  const opt = async <T,>(what: string, sql: string, permissionOnly = false): Promise<T[] | null> => {
    try { return await query<T>(sql); }
    catch (e) { const m = describeError(e, `route53 links (${what})`); if (!permissionOnly || /not authorized|AccessDenied|missing IAM/i.test(m)) errors.push(`${what}: ${m}`); else onLog(`route53: ${what} skipped: ${m.slice(0, 120)}`); return null; }
  };
  idx.ec2 = (db.prepare("select instance_id, name, state, public_ip, private_ip, snapshot from inventory_ec2 where gone = 0").all() as any[]).map((r) => { const n = obj(r.snapshot)?.network || {}; return { id: r.instance_id, name: r.name, state: r.state, public_ip: r.public_ip, private_ip: r.private_ip, public_dns: n.public_dns, private_dns: n.private_dns }; });
  idx.rds = (db.prepare("select db_instance_identifier, status, snapshot from inventory_rds where gone = 0").all() as any[]).map((r) => ({ id: r.db_instance_identifier, state: r.status, endpoints: [obj(r.snapshot)?.network?.endpoint].filter(Boolean) }));
  idx.s3 = (db.prepare("select name from inventory_s3 where gone = 0").all() as any[]).map((r) => r.name);
  idx.lambda = (db.prepare("select name from inventory_lambda where gone = 0").all() as any[]).map((r) => ({ name: r.name }));
  const cacheState = new Map<string, string>((db.prepare("select cache_cluster_id, status from inventory_elasticache where gone = 0").all() as any[]).map((r) => [r.cache_cluster_id, r.status]));

  const lookups = await Promise.all([
    opt<any>("elastic ips", `select public_ip, allocation_id, instance_id, network_interface_id, private_ip_address from ${S}.aws_vpc_eip`),
    opt<any>("network interfaces", `select network_interface_id, description, interface_type, attached_instance_id, private_ip_address, association_public_ip from ${S}.aws_ec2_network_interface`),
    opt<any>("application load balancers", `select name, arn, dns_name, state_code from ${S}.aws_ec2_application_load_balancer`),
    opt<any>("network load balancers", `select name, arn, dns_name, state_code from ${S}.aws_ec2_network_load_balancer`),
    opt<any>("classic load balancers", `select name, arn, dns_name, instances from ${S}.aws_ec2_classic_load_balancer`),
    opt<any>("target groups", `select target_group_arn, target_type, load_balancer_arns, target_health_descriptions from ${S}.aws_ec2_target_group`),
    opt<any>("cloudfront distributions", `select id, domain_name, aliases, origins, status, enabled from ${S}.aws_cloudfront_distribution`),
    opt<any>("rds clusters", `select db_cluster_identifier, endpoint, reader_endpoint, status from ${S}.aws_rds_db_cluster`),
    opt<any>("elasticache endpoints", `select cache_cluster_id, cache_nodes, configuration_endpoint from ${S}.aws_elasticache_cluster`, true),
    opt<any>("elasticache replication groups", `select replication_group_id, node_groups, configuration_endpoint, status from ${S}.aws_elasticache_replication_group`, true),
    opt<any>("lambda function urls", `select name, url_config ->> 'FunctionUrl' as url from ${S}.aws_lambda_function where url_config is not null`, true),
    opt<any>("api gateway domains", `select domain_name, regional_domain_name, distribution_domain_name from ${S}.aws_api_gateway_domain_name`, true),
    opt<any>("api gateway v2 domains", `select domain_name, domain_name_configurations from ${S}.aws_api_gatewayv2_domain_name`, true),
    opt<any>("elastic beanstalk environments", `select environment_name, cname, endpoint_url, status from ${S}.aws_elastic_beanstalk_environment`, true),
  ]);
  const [eips, enis, albs, nlbs, clbs, tgs, cfs, clusters, cacheClusters, cacheGroups, fnUrls, apiV1, apiV2, ebEnvs] = lookups;
  if (eips) idx.eips = eips.map((e) => ({ public_ip: e.public_ip, instance_id: e.instance_id, network_interface_id: e.network_interface_id, private_ip: e.private_ip_address }));
  if (enis) idx.enis = enis.map((n) => ({ id: n.network_interface_id, description: n.description, interface_type: n.interface_type, instance_id: n.attached_instance_id, private_ip: n.private_ip_address, public_ip: n.association_public_ip }));
  const targetsByLb = new Map<string, string[]>();
  for (const tg of tgs || []) {
    const ids = arr(tg.target_health_descriptions).map((d: any) => d?.Target?.Id).filter(Boolean);
    for (const lbArn of arr(tg.load_balancer_arns)) targetsByLb.set(lbArn, [...(targetsByLb.get(lbArn) || []), ...ids]);
  }
  idx.lbs = [
    ...(albs || []).map((l) => ({ kind: "alb" as const, name: l.name, arn: l.arn, dns_name: l.dns_name, state: l.state_code, targets: targetsByLb.get(l.arn) || [] })),
    ...(nlbs || []).map((l) => ({ kind: "nlb" as const, name: l.name, arn: l.arn, dns_name: l.dns_name, state: l.state_code, targets: targetsByLb.get(l.arn) || [] })),
    ...(clbs || []).map((l) => ({ kind: "clb" as const, name: l.name, arn: l.arn, dns_name: l.dns_name, state: null, targets: arr(l.instances).map((i: any) => i?.InstanceId).filter(Boolean) })),
  ];
  if (cfs) idx.cloudfront = cfs.map((d) => ({ id: d.id, domain_name: d.domain_name, aliases: arr(obj(d.aliases)?.Items ?? d.aliases), origins: arr(obj(d.origins)?.Items ?? d.origins).map((o: any) => o?.DomainName).filter(Boolean), enabled: d.enabled, status: d.status }));
  for (const c of clusters || []) idx.rds.push({ id: c.db_cluster_identifier, cluster: true, state: c.status, endpoints: [c.endpoint, c.reader_endpoint].filter(Boolean) });
  idx.elasticache = [];
  for (const c of cacheClusters || []) idx.elasticache.push({ id: c.cache_cluster_id, state: cacheState.get(c.cache_cluster_id) ?? null, endpoints: [obj(c.configuration_endpoint)?.Address, ...arr(c.cache_nodes).map((n: any) => n?.Endpoint?.Address)].filter(Boolean) });
  for (const g of cacheGroups || []) {
    const ends = [obj(g.configuration_endpoint)?.Address];
    for (const ng of arr(g.node_groups)) { ends.push(ng?.PrimaryEndpoint?.Address, ng?.ReaderEndpoint?.Address); for (const m of arr(ng?.NodeGroupMembers)) ends.push(m?.ReadEndpoint?.Address); }
    idx.elasticache.push({ id: g.replication_group_id, group: true, state: g.status, endpoints: ends.filter(Boolean) });
  }
  if (fnUrls) { const byName = new Map(fnUrls.map((f) => [f.name, f.url])); idx.lambda = idx.lambda.map((f) => ({ ...f, url: byName.get(f.name) ?? null })); for (const f of fnUrls) if (!idx.lambda.some((x) => x.name === f.name)) idx.lambda.push({ name: f.name, url: f.url }); }
  idx.apigw = [
    ...(apiV1 || []).map((a) => ({ domain_name: a.domain_name, targets: [a.regional_domain_name, a.distribution_domain_name].filter(Boolean) })),
    ...(apiV2 || []).map((a) => ({ domain_name: a.domain_name, targets: arr(a.domain_name_configurations).map((c: any) => c?.ApiGatewayDomainName).filter(Boolean) })),
  ];
  if (ebEnvs) idx.beanstalk = ebEnvs.map((e) => ({ name: e.environment_name, cname: e.cname, endpoint: e.endpoint_url, state: e.status }));
  idx.awsRanges = await awsRanges(onLog);
  onLog(`route53 index: ${idx.ec2.length} instances, ${idx.eips?.length ?? "?"} EIPs, ${idx.enis?.length ?? "?"} interfaces, ${idx.lbs.length} load balancers, ${idx.cloudfront?.length ?? "?"} distributions, ${idx.rds.length} databases, ${idx.elasticache.length} caches, ${idx.s3.length} buckets, ${idx.lambda.length} functions, ${idx.apigw.length} API domains, ${idx.beanstalk?.length ?? "?"} Beanstalk environments, ${idx.awsRanges?.length ?? 0} AWS EC2 ranges`);
  return idx;
}

/** AWS's published EC2 IPv4 prefixes (ip-ranges.amazonaws.com), kept a day in the settings table; the cached copy serves when the fetch fails. */
export async function awsRanges(onLog: (s: string) => void): Promise<AwsRange[] | undefined> {
  const cached = (() => { try { return JSON.parse(getSetting("aws_ip_ranges") || "null") as { fetched_at: string; prefixes: AwsRange[] } | null; } catch { return null; } })();
  if (cached && Date.now() - Date.parse(cached.fetched_at) < 86400e3) return cached.prefixes;
  try {
    const res = await fetch("https://ip-ranges.amazonaws.com/ip-ranges.json", { signal: AbortSignal.timeout(20_000) });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const j = await res.json() as { prefixes: Array<{ ip_prefix: string; region: string; service: string }> };
    const prefixes = j.prefixes.filter((p) => p.service === "EC2").map((p) => ({ prefix: p.ip_prefix, region: p.region, service: p.service }));
    setSetting("aws_ip_ranges", JSON.stringify({ fetched_at: new Date().toISOString(), prefixes }));
    onLog(`route53: ${prefixes.length} AWS EC2 IPv4 ranges fetched`);
    return prefixes;
  } catch (e) {
    onLog(`route53: AWS IP ranges not fetched (${String((e as any)?.message ?? e).slice(0, 80)})${cached ? ", using the copy from " + cached.fetched_at : "; addresses outside this account count as external"}`);
    return cached?.prefixes;
  }
}

export interface Route53RefreshResult { zones: number; records: number; linked: number; external: number; unmatched: number; errors: string[]; took_ms: number }

export async function refreshRoute53Inventory(onLog: (s: string) => void = () => {}): Promise<Route53RefreshResult> {
  const t0 = Date.now();
  const out: Route53RefreshResult = { zones: 0, records: 0, linked: 0, external: 0, unmatched: 0, errors: [], took_ms: 0 };
  let zones: any[];
  try { zones = await query<any>(`select id, name, private_zone, comment, resource_record_set_count from ${S}.aws_route53_zone`); }
  catch (e) { out.errors.push(describeError(e, "route53 zones (aws_route53_zone)")); out.took_ms = Date.now() - t0; return out; }
  let records: any[] = [];
  if (zones.length) {
    try { records = await query<any>(`select name, zone_id, type, ttl, records, alias_target, set_identifier, weight, failover, region, geo_location, latency_region, multi_value_answer, health_check_id from ${S}.aws_route53_record`); }
    catch (e) { out.errors.push(describeError(e, "route53 records (aws_route53_record)")); }
  }
  // DNS queries per zone over 30 days (the metric lives in us-east-1); alias queries to AWS resources are free, so this is a ceiling
  const queries = new Map<string, number>();
  await Promise.all(zones.filter((z) => !z.private_zone).map(async (z) => {
    try {
      const rows = await query<{ v: string | null }>(`select sum as v from ${S}.aws_cloudwatch_metric_statistic_data_point where namespace = 'AWS/Route53' and metric_name = 'DNSQueries' and dimensions = '[{"Name":"HostedZoneId","Value":"${zoneId(z.id).replace(/'/g, "''")}"}]' and timestamp between now() - interval '30 days' and now() and period = 86400 and region = 'us-east-1'`);
      const vs = rows.map((r) => Number(r.v)).filter(Number.isFinite); if (vs.length) queries.set(zoneId(z.id), vs.reduce((a, b) => a + b, 0));
    } catch (e) { onLog(`route53: no query metric for ${z.name}: ${String((e as any)?.message ?? e).slice(0, 100)}`); }
  }));

  const recIn: RecordIn[] = records.map((r) => ({ name: r.name, type: r.type, alias_target: obj(r.alias_target), values: arr(r.records).map(String) }));
  const idx = await buildIndex(onLog, out.errors);
  idx.records = recIn;
  const c = storeRoute53(zones, records, makeResolver(idx), queries, out.errors.some((e) => /aws_route53_record/.test(e)));
  Object.assign(out, c);
  out.took_ms = Date.now() - t0;
  onLog(`${out.zones} zones, ${out.records} records: ${out.linked} linked to resources here, ${out.external} outside AWS, ${out.unmatched} unmatched`);
  return out;
}

/** Steampipe's aws_route53_zone and aws_route53_record rows, as far as the store reads them. */
export interface ZoneRow { id: string; name: string; private_zone?: boolean | null; comment?: string | null; resource_record_set_count?: number | null }
export interface RecordRow { name: string; zone_id: string; type: string; ttl?: number | null; records?: unknown; alias_target?: unknown; set_identifier?: string | null; weight?: number | null; failover?: string | null; region?: string | null; geo_location?: unknown; latency_region?: string | null; multi_value_answer?: boolean | null; health_check_id?: string | null }

/**
 * Writes zones, records and their links; marks what this pass did not see as gone. `recordsFailed` keeps the
 * old records when the record listing itself failed (the zones still refresh). Synchronous, one transaction.
 */
export function storeRoute53(zones: ZoneRow[], records: RecordRow[], resolve: (rec: RecordIn) => Resolution, queries: Map<string, number>, recordsFailed = false): { zones: number; records: number; linked: number; external: number; unmatched: number } {
  const out = { zones: 0, records: 0, linked: 0, external: 0, unmatched: 0 };
  const now = new Date().toISOString();
  const upZone = db.prepare(`insert into inventory_route53_zone(zone_id, name, private, comment, records, linked, external, unmatched, queries_30d, monthly_usd, first_seen, last_seen, gone)
    values (@zone_id, @name, @private, @comment, @records, @linked, @external, @unmatched, @queries_30d, @monthly_usd, @now, @now, 0)
    on conflict(zone_id) do update set name = excluded.name, private = excluded.private, comment = excluded.comment, records = excluded.records, linked = excluded.linked, external = excluded.external, unmatched = excluded.unmatched,
      queries_30d = excluded.queries_30d, monthly_usd = excluded.monthly_usd, last_seen = excluded.last_seen, gone = 0`);
  const upRec = db.prepare(`insert into inventory_route53_record(id, zone_id, zone_name, name, type, ttl, alias, "values", alias_target, routing, health_check_id, link_state, target, summary, links, first_seen, last_seen, gone)
    values (@id, @zone_id, @zone_name, @name, @type, @ttl, @alias, @values, @alias_target, @routing, @health_check_id, @link_state, @target, @summary, @links, @now, @now, 0)
    on conflict(id) do update set zone_name = excluded.zone_name, ttl = excluded.ttl, alias = excluded.alias, "values" = excluded."values", alias_target = excluded.alias_target, routing = excluded.routing, health_check_id = excluded.health_check_id,
      link_state = excluded.link_state, target = excluded.target, summary = excluded.summary, links = excluded.links, last_seen = excluded.last_seen, gone = 0`);
  const delLinks = db.prepare("delete from inventory_route53_link where record_id = ?");
  const insLink = db.prepare("insert or ignore into inventory_route53_link(record_id, resource_kind, resource_id, hop) values (?, ?, ?, ?)");
  const zoneNames = new Map<string, string>(zones.map((z) => [zoneId(z.id), host(z.name)]));
  const counts = new Map<string, { records: number; linked: number; external: number; unmatched: number }>();

  db.transaction(() => {
    for (const r of records) {
      const zid = zoneId(r.zone_id); const zname = zoneNames.get(zid) ?? "";
      const rec: RecordIn = { name: r.name, type: r.type, alias_target: obj(r.alias_target), values: arr(r.records).map(String) };
      const res = resolve(rec);
      const routing: Record<string, unknown> = {};
      for (const k of ["set_identifier", "weight", "failover", "region", "geo_location", "latency_region", "multi_value_answer"] as const) if (r[k] != null && r[k] !== false && r[k] !== "") routing[k] = obj(r[k]) ?? r[k];
      const id = `${zid}|${host(r.name)}|${r.type}|${r.set_identifier ?? ""}`;
      upRec.run({ id, zone_id: zid, zone_name: zname, name: host(r.name), type: r.type, ttl: r.ttl != null ? Number(r.ttl) : null, alias: rec.alias_target?.DNSName ? 1 : 0,
        values: JSON.stringify(rec.values), alias_target: rec.alias_target?.DNSName ? host(rec.alias_target.DNSName) : null, routing: Object.keys(routing).length ? JSON.stringify(routing) : null,
        health_check_id: r.health_check_id ?? null, link_state: res.link_state, target: res.target, summary: res.summary, links: JSON.stringify(res.links), now });
      delLinks.run(id);
      for (const l of res.links) insLink.run(id, l.kind, l.id, l.hop);
      const c = counts.get(zid) ?? { records: 0, linked: 0, external: 0, unmatched: 0 }; counts.set(zid, c);
      c.records++; if (res.link_state === "linked") c.linked++; else if (res.link_state === "external") c.external++; else if (res.link_state === "unmatched") c.unmatched++;
      out.records++; if (res.link_state === "linked") out.linked++; else if (res.link_state === "external") out.external++; else if (res.link_state === "unmatched") out.unmatched++;
    }
    const sorted = [...zones].sort((a, b) => String(a.name).localeCompare(String(b.name)));
    sorted.forEach((z, i) => {
      const zid = zoneId(z.id); const c = counts.get(zid) ?? { records: Number(z.resource_record_set_count ?? 0), linked: 0, external: 0, unmatched: 0 };
      const q = queries.get(zid) ?? null;
      upZone.run({ zone_id: zid, name: host(z.name), private: z.private_zone ? 1 : 0, comment: z.comment ?? null, ...c, queries_30d: q, monthly_usd: zoneMonthlyCost(i, q), now });
      out.zones++;
    });
    db.prepare("update inventory_route53_zone set gone = 1 where last_seen <> ?").run(now);
    if (!recordsFailed) {
      db.prepare("update inventory_route53_record set gone = 1 where last_seen <> ?").run(now);
      db.prepare("delete from inventory_route53_link where record_id in (select id from inventory_route53_record where gone = 1)").run();
    }
  })();
  return out;
}

// ---- readers ------------------------------------------------------------------------------------------

const parse = (r: any) => ({ ...r, values: arr(r.values), links: arr(r.links), routing: obj(r.routing) });
const SORTS = ["name", "type", "zone_name", "ttl", "link_state", "target", "summary"];

export function listRoute53(f: { q?: string; sort?: string; gone?: boolean; zone?: string; link?: string; type?: string; limit?: number } = {}) {
  const where: string[] = []; const params: unknown[] = [];
  if (!f.gone) where.push("gone = 0");
  if (f.zone) { where.push("(zone_id = ? or zone_name = ?)"); params.push(f.zone, host(f.zone)); }
  if (f.link && ["linked", "external", "unmatched", "none"].includes(f.link)) { where.push("link_state = ?"); params.push(f.link); }
  if (f.type) { where.push("type = ?"); params.push(f.type.toUpperCase()); }
  if (f.q) { where.push("(name like ? or target like ? or summary like ? or \"values\" like ? or links like ?)"); params.push(...Array(5).fill(`%${f.q}%`)); }
  const desc = f.sort?.startsWith("-"); const col = (f.sort || "").replace(/^-/, "");
  const order = SORTS.includes(col) ? `order by ${col} ${desc ? "desc" : "asc"} nulls last, name asc` : "order by zone_name asc, case link_state when 'unmatched' then 0 when 'linked' then 1 when 'external' then 2 else 3 end, name asc";
  return (db.prepare(`select * from inventory_route53_record ${where.length ? `where ${where.join(" and ")}` : ""} ${order} limit ${Math.min(5000, Math.max(1, f.limit ?? 3000))}`).all(...params) as any[]).map(parse);
}

export function listRoute53Zones(gone = false) {
  return db.prepare(`select * from inventory_route53_zone ${gone ? "" : "where gone = 0"} order by name`).all() as any[];
}

/** Records that lead to one resource (an instance, a database, a bucket...), directly or through a load balancer or distribution. */
export function domainsFor(kind: string, id: string) {
  return (db.prepare(`select r.id, r.name, r.type, r.zone_name, r.zone_id, r.link_state, r.summary, r.alias, r.target, l.hop from inventory_route53_link l join inventory_route53_record r on r.id = l.record_id
    where l.resource_kind = ? and l.resource_id = ? and r.gone = 0 order by l.hop, r.name`).all(kind, id) as any[]);
}

/** Same, for every resource of one kind at once (the list endpoints attach it per row). */
export function domainsByResource(kind: string): Map<string, any[]> {
  const out = new Map<string, any[]>();
  for (const r of db.prepare(`select l.resource_id, r.id, r.name, r.type, r.zone_name, r.zone_id, r.link_state, r.summary, r.alias, l.hop from inventory_route53_link l join inventory_route53_record r on r.id = l.record_id where l.resource_kind = ? and r.gone = 0 order by l.hop, r.name`).all(kind) as any[]) {
    if (!out.has(r.resource_id)) out.set(r.resource_id, []); out.get(r.resource_id)!.push(r);
  }
  return out;
}

export function route53Summary() {
  const r = db.prepare(`select count(*) as total, coalesce(sum(link_state = 'linked'), 0) as linked, coalesce(sum(link_state = 'external'), 0) as external, coalesce(sum(link_state = 'unmatched'), 0) as unmatched,
    coalesce(sum(link_state = 'none'), 0) as none, coalesce(sum(alias), 0) as aliases from inventory_route53_record where gone = 0`).get() as any;
  const z = db.prepare("select count(*) as zones, coalesce(sum(private), 0) as private_zones, coalesce(sum(monthly_usd), 0) as monthly_usd, coalesce(sum(queries_30d), 0) as queries_30d, coalesce(sum(records <= 2), 0) as empty_zones from inventory_route53_zone where gone = 0").get() as any;
  return { ...r, ...z, monthly_usd: Math.round(z.monthly_usd * 100) / 100, gone: (db.prepare("select count(*) as n from inventory_route53_record where gone = 1").get() as any).n };
}

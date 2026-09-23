import assert from "node:assert/strict";
import { test } from "node:test";
import { awsRangeOf, decodeName, domainsByResource, domainsFor, listRoute53, listRoute53Zones, makeResolver, resolveRecord, route53Summary, s3BucketFromHost, storeRoute53, zoneMonthlyCost, type ResourceIndex } from "../route53_inventory.js";

const idx: ResourceIndex = {
  ec2: [
    { id: "i-0aaa", name: "web-1", state: "running", public_ip: "54.1.1.1", private_ip: "10.0.1.10", public_dns: "ec2-54-1-1-1.compute-1.amazonaws.com", private_dns: "ip-10-0-1-10.ec2.internal" },
    { id: "i-0bbb", name: "web-2", state: "stopped", public_ip: null, private_ip: "10.0.1.11" },
    { id: "i-0ccc", name: "bastion", state: "running", public_ip: null, private_ip: "10.0.9.9" },
  ],
  eips: [{ public_ip: "3.3.3.3", instance_id: "i-0ccc" }, { public_ip: "3.3.3.4", network_interface_id: "eni-nat" }, { public_ip: "3.3.3.5" }],
  enis: [{ id: "eni-nat", description: "Interface for NAT Gateway nat-0123", interface_type: "nat_gateway", private_ip: "10.0.0.5", public_ip: "3.3.3.4" }, { id: "eni-rds", description: "RDSNetworkInterface", private_ip: "10.0.2.20" }],
  lbs: [
    { kind: "alb", name: "prod-alb", arn: "arn:aws:elasticloadbalancing:us-east-1:1:loadbalancer/app/prod-alb/abc", dns_name: "prod-alb-123.us-east-1.elb.amazonaws.com", state: "active", targets: ["i-0aaa", "i-0bbb", "10.0.9.9"] },
    { kind: "clb", name: "legacy", dns_name: "legacy-456.us-east-1.elb.amazonaws.com", targets: [] },
  ],
  cloudfront: [{ id: "E1ABC", domain_name: "d111.cloudfront.net", aliases: ["www.example.com"], origins: ["assets.s3.us-east-1.amazonaws.com", "prod-alb-123.us-east-1.elb.amazonaws.com"], enabled: true, status: "Deployed" }],
  rds: [{ id: "main-db", endpoints: ["main-db.cxyz.us-east-1.rds.amazonaws.com"], state: "available" }, { id: "aurora", cluster: true, endpoints: ["aurora.cluster-cxyz.us-east-1.rds.amazonaws.com", "aurora.cluster-ro-cxyz.us-east-1.rds.amazonaws.com"], state: "available" }],
  elasticache: [{ id: "cache-001", endpoints: ["cache-001.abc.0001.use1.cache.amazonaws.com"], state: "available" }, { id: "sessions", group: true, endpoints: ["sessions.abc.ng.0001.use1.cache.amazonaws.com"] }],
  s3: ["assets", "www.example.com"],
  lambda: [{ name: "hook", url: "https://abcdef.lambda-url.us-east-1.on.aws/" }],
  apigw: [{ domain_name: "api.example.com", targets: ["d-xyz.execute-api.us-east-1.amazonaws.com"] }],
  records: [
    { name: "example.com.", type: "A", alias_target: { DNSName: "www.example.com." }, values: [] },
    { name: "www.example.com.", type: "A", alias_target: { DNSName: "dualstack.prod-alb-123.us-east-1.elb.amazonaws.com." }, values: [] },
  ],
};
const r = makeResolver(idx);
const rec = (name: string, type: string, values: string[] = [], alias?: string) => ({ name, type, values, alias_target: alias ? { DNSName: alias } : null });

test("an alias to an ALB links the balancer and every instance behind it", () => {
  const x = r(rec("www.example.com.", "A", [], "dualstack.prod-alb-123.us-east-1.elb.amazonaws.com."));
  assert.equal(x.link_state, "linked");
  assert.deepEqual(x.links.map((l) => [l.kind, l.id, l.hop]), [["alb", "prod-alb", 1], ["ec2", "i-0aaa", 2], ["ec2", "i-0bbb", 2], ["ec2", "i-0ccc", 2]], "instance targets by id and an IP target by private address");
  assert.match(x.summary, /ALB prod-alb → web-1, web-2, bastion/);
  assert.equal(x.links[2].state, "stopped", "a stopped target keeps its state so the UI can say so");
});

test("an apex alias to another record is followed to what that record serves", () => {
  const x = r(rec("example.com.", "A", [], "www.example.com."));
  assert.equal(x.link_state, "linked");
  assert.match(x.summary, /^record www\.example\.com → ALB prod-alb/);
  assert.ok(x.links.some((l) => l.kind === "ec2" && l.id === "i-0aaa" && l.via === "ALB prod-alb"));
});

test("a CloudFront alias links the distribution and resolves its origins one hop down", () => {
  const x = r(rec("cdn.example.com.", "A", [], "d111.cloudfront.net."));
  assert.equal(x.link_state, "linked");
  assert.deepEqual(x.links.map((l) => `${l.kind}:${l.id}:${l.hop}`), ["cloudfront:E1ABC:1", "s3:assets:2", "alb:prod-alb:2", "ec2:i-0aaa:3", "ec2:i-0bbb:3", "ec2:i-0ccc:3"]);
  assert.match(x.summary, /CloudFront E1ABC → S3 bucket assets; ALB prod-alb/);
});

test("addresses: an Elastic IP, an instance's own IP, a NAT gateway's interface, an unassociated EIP, a stranger", () => {
  assert.deepEqual(r(rec("ssh.example.com.", "A", ["3.3.3.3"])).links.map((l) => [l.kind, l.id, l.via]), [["ec2", "i-0ccc", "Elastic IP 3.3.3.3"]]);
  assert.equal(r(rec("web.example.com.", "A", ["54.1.1.1"])).summary, "public IP of web-1 (running)");
  const nat = r(rec("egress.example.com.", "A", ["3.3.3.4"]));
  assert.deepEqual(nat.links.map((l) => [l.kind, l.id]), [["nat", "nat-0123"]]);
  const idle = r(rec("old.example.com.", "A", ["3.3.3.5"]));
  assert.equal(idle.link_state, "linked"); assert.match(idle.summary, /not associated with anything/);
  const ext = r(rec("other.example.com.", "A", ["8.8.8.8"]));
  assert.equal(ext.link_state, "external"); assert.deepEqual(ext.links, []);
  const priv = r(rec("db-old.internal.", "A", ["10.0.2.20", "10.0.2.99"]));
  assert.equal(priv.link_state, "linked", "one of two private addresses is an RDS interface");
  assert.match(priv.summary, /2 addresses: an RDS instance's interface \(eni-rds\); private IP 10\.0\.2\.99: no interface/);
  assert.equal(r(rec("gone.internal.", "A", ["10.0.2.99"])).link_state, "unmatched");
});

test("CNAMEs to RDS, Aurora, ElastiCache, a Lambda URL, an API Gateway domain and an EC2 public DNS name", () => {
  assert.deepEqual(r(rec("db.example.com.", "CNAME", ["main-db.cxyz.us-east-1.rds.amazonaws.com"])).links.map((l) => [l.kind, l.id]), [["rds", "main-db"]]);
  assert.deepEqual(r(rec("db-ro.example.com.", "CNAME", ["aurora.cluster-ro-cxyz.us-east-1.rds.amazonaws.com."])).links.map((l) => [l.kind, l.id]), [["rds_cluster", "aurora"]]);
  assert.deepEqual(r(rec("redis.example.com.", "CNAME", ["sessions.abc.ng.0001.use1.cache.amazonaws.com"])).links.map((l) => [l.kind, l.id]), [["elasticache_group", "sessions"]]);
  assert.deepEqual(r(rec("cache.example.com.", "CNAME", ["cache-001.abc.0001.use1.cache.amazonaws.com"])).links.map((l) => [l.kind, l.id]), [["elasticache", "cache-001"]]);
  assert.deepEqual(r(rec("hook.example.com.", "CNAME", ["abcdef.lambda-url.us-east-1.on.aws"])).links.map((l) => [l.kind, l.id]), [["lambda", "hook"]]);
  assert.deepEqual(r(rec("api.example.com.", "A", [], "d-xyz.execute-api.us-east-1.amazonaws.com.")).links.map((l) => [l.kind, l.id]), [["apigw", "api.example.com"]]);
  assert.deepEqual(r(rec("box.example.com.", "CNAME", ["ec2-54-1-1-1.compute-1.amazonaws.com"])).links.map((l) => [l.kind, l.id]), [["ec2", "i-0aaa"]]);
});

test("S3 website endpoints: the bucket from the host, or the record's own name for the plain website alias", () => {
  assert.equal(s3BucketFromHost("assets.s3-website-us-east-1.amazonaws.com", "x"), "assets");
  assert.equal(s3BucketFromHost("assets.s3.eu-west-1.amazonaws.com", "x"), "assets");
  assert.equal(s3BucketFromHost("s3-website-us-east-1.amazonaws.com", "www.example.com."), "www.example.com");
  assert.equal(s3BucketFromHost("s3-website.eu-central-1.amazonaws.com", "www.example.com."), "www.example.com");
  assert.equal(s3BucketFromHost("example.com", "x"), null);
  assert.deepEqual(r(rec("www.example.com.", "A", [], "s3-website-us-east-1.amazonaws.com.")).links.map((l) => [l.kind, l.id]), [["s3", "www.example.com"]]);
  const takeover = r(rec("old-site.example.com.", "A", [], "s3-website-us-east-1.amazonaws.com."));
  assert.equal(takeover.link_state, "unmatched"); assert.match(takeover.summary, /old-site\.example\.com does not exist in this account/);
});

test("AWS-shaped names the account does not have are unmatched; everything else outside AWS is external, with the provider named", () => {
  const gone = r(rec("app.example.com.", "CNAME", ["old-alb-999.us-east-1.elb.amazonaws.com"]));
  assert.equal(gone.link_state, "unmatched"); assert.match(gone.summary, /load balancer .* is not in this account: deleted/);
  assert.equal(r(rec("cdn2.example.com.", "CNAME", ["d999.cloudfront.net"])).link_state, "unmatched");
  const ext = r(rec("blog.example.com.", "CNAME", ["example.netlify.app"]));
  assert.equal(ext.link_state, "external"); assert.equal(ext.summary, "Netlify (example.netlify.app)");
  assert.equal(r(rec("shop.example.com.", "CNAME", ["shops.myshopify.com"])).summary, "Shopify (shops.myshopify.com)");
  assert.equal(r(rec("x.example.com.", "CNAME", ["some.host.example.org"])).summary, "some.host.example.org");
});

test("records that name no resource: delegation, mail, verification, ACM and SES plumbing", () => {
  assert.equal(r(rec("example.com.", "NS", ["ns-1.awsdns-00.org."])).summary, "zone delegation (Route 53 name servers)");
  assert.equal(r(rec("example.com.", "SOA", ["ns-1.awsdns-00.org. awsdns-hostmaster.amazon.com. 1 7200 900 1209600 86400"])).link_state, "none");
  const mx = r(rec("example.com.", "MX", ["1 aspmx.l.google.com.", "5 alt1.aspmx.l.google.com."]));
  assert.equal(mx.link_state, "external"); assert.equal(mx.summary, "mail: Google");
  assert.equal(r(rec("example.com.", "MX", ["10 inbound-smtp.us-east-1.amazonaws.com."])).summary, "SES inbound mail");
  assert.equal(r(rec("example.com.", "TXT", ["\"v=spf1 include:amazonses.com ~all\""])).summary, "SPF (includes SES)");
  assert.equal(r(rec("_dmarc.example.com.", "TXT", ["\"v=DMARC1; p=none\""])).summary, "DMARC policy");
  assert.equal(r(rec("_amazonses.example.com.", "TXT", ["\"abc=\""])).summary, "SES domain verification");
  assert.equal(r(rec("_x.example.com.", "CNAME", ["_y.acm-validations.aws."])).summary, "ACM certificate validation");
  assert.equal(r(rec("k1._domainkey.example.com.", "CNAME", ["k1.dkim.amazonses.com"])).summary, "SES DKIM signing");
  assert.equal(r(rec("example.com.", "CAA", ["0 issue \"amazon.com\""])).summary, "certificate authority authorization");
});

test("resolveRecord works on an empty index and never loops on a record that points at itself", () => {
  assert.equal(resolveRecord(rec("a.example.com.", "A", ["1.2.3.4"]), {}).link_state, "external");
  const loop = makeResolver({ records: [rec("loop.example.com.", "CNAME", ["loop.example.com."])] });
  assert.equal(loop(rec("loop.example.com.", "CNAME", ["loop.example.com."])).link_state, "external");
  const chain = makeResolver({ records: [rec("a.example.com.", "CNAME", ["b.example.com"]), rec("b.example.com.", "CNAME", ["a.example.com"])] });
  assert.equal(chain(rec("a.example.com.", "CNAME", ["b.example.com"])).link_state, "external", "a two-record loop stops at the depth guard");
});

test("Route 53 octal escapes decode, so a wildcard record is *.example.com everywhere", () => {
  assert.equal(decodeName("\\052.example.com."), "*.example.com.");
  assert.equal(decodeName("\\100.example.com."), "@.example.com.");
  assert.equal(decodeName("plain.example.com."), "plain.example.com.");
  const x = makeResolver({ records: [{ name: "\\052.example.com.", type: "A", values: ["54.1.1.1"] }] })(rec("\\052.example.com.", "A", ["54.1.1.1"]));
  assert.equal(x.link_state, "external");
});

test("an address in AWS's EC2 ranges that nothing here holds is unmatched (a terminated instance), a stranger's stays external", () => {
  const ranges = [{ prefix: "54.160.0.0/13", region: "us-east-1", service: "EC2" }, { prefix: "3.0.0.0/8", region: "us-east-1", service: "EC2" }];
  assert.deepEqual(awsRangeOf("54.162.84.242", ranges), ranges[0]);
  assert.equal(awsRangeOf("8.8.8.8", ranges), null);
  assert.equal(awsRangeOf("not-an-ip", ranges), null);
  assert.equal(awsRangeOf("54.162.84.242", undefined), null);
  const rr = makeResolver({ ...idx, awsRanges: ranges });
  const dead = rr(rec("old-swarm.example.com.", "A", ["54.162.84.242"]));
  assert.equal(dead.link_state, "unmatched"); assert.match(dead.summary, /AWS EC2 address 54\.162\.84\.242 \(us-east-1\) that nothing in this account holds/);
  assert.equal(rr(rec("ssh.example.com.", "A", ["3.3.3.3"])).link_state, "linked", "an address the account holds is still matched first");
  assert.equal(rr(rec("x.example.com.", "A", ["8.8.8.8"])).link_state, "external");
});

test("an alias to a Beanstalk environment links it and what its endpoint fronts", () => {
  const rr = makeResolver({ ...idx, beanstalk: [{ name: "prod-env", cname: "prod-env.eba-abc.us-east-1.elasticbeanstalk.com", endpoint: "prod-alb-123.us-east-1.elb.amazonaws.com", state: "Ready" }, { name: "single", cname: "single.eba-def.us-east-1.elasticbeanstalk.com", endpoint: "3.3.3.3" }] });
  const x = rr(rec("app.example.com.", "A", [], "prod-env.eba-abc.us-east-1.elasticbeanstalk.com."));
  assert.equal(x.link_state, "linked");
  assert.deepEqual(x.links.map((l) => `${l.kind}:${l.id}:${l.hop}`), ["beanstalk:prod-env:1", "alb:prod-alb:2", "ec2:i-0aaa:3", "ec2:i-0bbb:3", "ec2:i-0ccc:3"]);
  assert.match(x.summary, /^Elastic Beanstalk prod-env → ALB prod-alb/);
  assert.deepEqual(rr(rec("one.example.com.", "A", [], "single.eba-def.us-east-1.elasticbeanstalk.com.")).links.map((l) => `${l.kind}:${l.id}:${l.hop}`), ["beanstalk:single:1", "ec2:i-0ccc:2"]);
  assert.equal(rr(rec("gone.example.com.", "A", [], "gone.eba-xyz.us-east-1.elasticbeanstalk.com.")).link_state, "unmatched");
});

test("zone cost: 0.50 for the first 25 zones, 0.10 after, plus 0.40 per million queries", () => {
  assert.equal(zoneMonthlyCost(0, null), 0.5);
  assert.equal(zoneMonthlyCost(24, 0), 0.5);
  assert.equal(zoneMonthlyCost(25, 0), 0.1);
  assert.equal(zoneMonthlyCost(0, 2_500_000), 1.5);
});

test("the store writes zones, records and links that the readers and the per-resource lookups see; a vanished record goes gone", () => {
  const zones = [{ id: "/hostedzone/Z1", name: "example.com.", private_zone: false, comment: "prod", resource_record_set_count: 3 }, { id: "Z2", name: "corp.internal.", private_zone: true }];
  const rows = [
    { name: "example.com.", zone_id: "Z1", type: "NS", ttl: 172800, records: ["ns-1.awsdns-00.org."] },
    { name: "www.example.com.", zone_id: "Z1", type: "A", alias_target: { DNSName: "dualstack.prod-alb-123.us-east-1.elb.amazonaws.com.", HostedZoneId: "Z35SXDOTRQ7X7K" } },
    { name: "db.example.com.", zone_id: "Z1", type: "CNAME", ttl: 300, records: ["main-db.cxyz.us-east-1.rds.amazonaws.com"], set_identifier: "primary", weight: 100 },
    { name: "old.corp.internal.", zone_id: "Z2", type: "A", ttl: 60, records: '["10.0.2.99"]' },
  ];
  const resolve = makeResolver(idx);
  const c = storeRoute53(zones, rows, resolve, new Map([["Z1", 2_500_000]]));
  assert.deepEqual(c, { zones: 2, records: 4, linked: 2, external: 0, unmatched: 1 });
  const z = listRoute53Zones();
  assert.deepEqual(z.map((x) => [x.zone_id, x.name, x.private, x.records, x.linked, x.unmatched, x.monthly_usd]), [["Z2", "corp.internal", 1, 1, 0, 1, 0.5], ["Z1", "example.com", 0, 3, 2, 0, 1.5]], "ids lose the /hostedzone/ prefix; queries price the zone");
  const www = listRoute53({ q: "www.example" })[0];
  assert.equal(www.alias, 1); assert.equal(www.alias_target, "prod-alb-123.us-east-1.elb.amazonaws.com"); assert.equal(www.link_state, "linked");
  assert.deepEqual(www.links.map((l: any) => l.id), ["prod-alb", "i-0aaa", "i-0bbb", "i-0ccc"]);
  assert.deepEqual(listRoute53({ q: "db.example" })[0].routing, { set_identifier: "primary", weight: 100 });
  assert.equal(listRoute53({ zone: "corp.internal" }).length, 1, "zone filter by name"); assert.equal(listRoute53({ zone: "Z1" }).length, 3, "zone filter by id");
  assert.deepEqual(listRoute53({ link: "unmatched" }).map((r) => r.name), ["old.corp.internal"]);
  assert.deepEqual(listRoute53({ type: "cname" }).map((r) => r.name), ["db.example.com"]);
  assert.deepEqual(listRoute53({ q: "web-2" }).map((r) => r.name), ["www.example.com"], "search reaches the linked resource names");
  assert.deepEqual(domainsFor("ec2", "i-0bbb").map((d) => [d.name, d.hop]), [["www.example.com", 2]], "an instance behind the ALB is reached through it");
  assert.deepEqual(domainsFor("rds", "main-db").map((d) => [d.name, d.hop]), [["db.example.com", 1]]);
  assert.deepEqual([...domainsByResource("ec2").keys()].sort(), ["i-0aaa", "i-0bbb", "i-0ccc"]);
  const sum = route53Summary();
  assert.equal(sum.total, 4); assert.equal(sum.zones, 2); assert.equal(sum.private_zones, 1); assert.equal(sum.linked, 2); assert.equal(sum.unmatched, 1); assert.equal(sum.none, 1); assert.equal(sum.monthly_usd, 2);
  // next pass: the CNAME is gone and the zone listing failed to list records, so nothing is marked gone
  storeRoute53(zones, rows.slice(0, 2), resolve, new Map(), true);
  assert.equal(listRoute53().length, 4, "a failed record listing keeps the old records");
  storeRoute53(zones, rows.slice(0, 2), resolve, new Map());
  assert.equal(listRoute53().length, 2); assert.equal(listRoute53({ gone: true }).length, 4);
  assert.deepEqual(domainsFor("rds", "main-db"), [], "a gone record's links are dropped");
  assert.equal(route53Summary().gone, 2);
});

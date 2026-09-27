/**
 * Gateway endpoints for S3 and DynamoDB, once a person approved the fix. The NAT investigator (src/investigate.ts)
 * files `add_vpc_endpoint` fixes as recommendations when a NAT gateway is carrying S3 or DynamoDB traffic that a
 * gateway endpoint would take for free: no hourly charge, no per-GB charge, and the route tables it goes on come
 * from the endpoint call itself. Approving the recommendation is the decision; the executor creates the endpoint
 * in the fix's VPC (named by a vpc id, the NAT gateway id or an instance in it) on the route tables that send
 * 0.0.0.0/0 through a NAT gateway (the private ones), or on every route table of the VPC when none does, and says
 * so. A VPC that already has a gateway endpoint for the service closes the recommendation as done by hand. Revert
 * deletes the endpoint: traffic goes back through the NAT gateway, nothing else changes.
 */
import { CreateVpcEndpointCommand, DeleteVpcEndpointsCommand, DescribeInstancesCommand, DescribeNatGatewaysCommand, DescribeRouteTablesCommand, DescribeVpcEndpointsCommand, DescribeVpcsCommand, EC2Client, type RouteTable, type VpcEndpoint } from "@aws-sdk/client-ec2";
import { approvedRecs, markRecommendationsDone, type ActionModule, type Creds, type Proposal } from "../executor.js";

export const KIND = "vpc_gateway_endpoint" as const;
export const ACTION_TYPES = ["add_vpc_endpoint"];
export const CREATED_TAG = "advisor:created";
export type GatewayService = "s3" | "dynamodb";
export const serviceName = (region: string, svc: GatewayService) => `com.amazonaws.${region}.${svc}`;

type Rec = ReturnType<typeof approvedRecs>[number];

/** Which gateway services a fix asks for: S3 unless the text only mentions DynamoDB; both when it mentions both. Pure. */
export function servicesOf(rec: Pick<Rec, "title" | "evidence"> & { rationale?: string | null }): GatewayService[] {
  const text = [rec.title, rec.rationale ?? "", JSON.stringify(rec.evidence ?? {})].join(" ").toLowerCase();
  const dynamo = /dynamo/.test(text);
  const s3 = /\bs3\b/.test(text);
  if (dynamo && !s3) return ["dynamodb"];
  if (dynamo && s3) return ["s3", "dynamodb"];
  return ["s3"];
}

/** What kind of id a fix's resource is: the VPC itself, a NAT gateway in it or an instance in it. Pure. */
export function resourceKind(resource: string): "vpc" | "nat" | "instance" | "unknown" {
  if (/^vpc-[0-9a-f]+$/i.test(resource)) return "vpc";
  if (/^nat-[0-9a-f]+$/i.test(resource)) return "nat";
  if (/^i-[0-9a-f]+$/i.test(resource)) return "instance";
  return "unknown";
}

/** The route tables to put the endpoint on: those sending 0.0.0.0/0 through a NAT gateway; all of them when none does. Pure. */
export function pickRouteTables(tables: Pick<RouteTable, "RouteTableId" | "Routes" | "Tags">[]): { ids: string[]; names: { id: string; name: string | null }[]; fallback: boolean } {
  const name = (t: Pick<RouteTable, "Tags">) => t.Tags?.find((x) => x.Key === "Name")?.Value ?? null;
  const viaNat = tables.filter((t) => (t.Routes ?? []).some((r) => r.DestinationCidrBlock === "0.0.0.0/0" && /^nat-/.test(r.NatGatewayId ?? "")));
  const chosen = viaNat.length ? viaNat : tables;
  const ids = chosen.map((t) => t.RouteTableId!).filter(Boolean);
  return { ids, names: chosen.map((t) => ({ id: t.RouteTableId!, name: name(t) })), fallback: !viaNat.length };
}

interface Target { vpc: string; service: GatewayService; region: string; recs: Rec[]; nat: string | null }

async function resolveVpc(ec2: EC2Client, resource: string): Promise<{ vpc: string | null; nat: string | null; why?: string }> {
  switch (resourceKind(resource)) {
    case "vpc": return { vpc: resource, nat: null };
    case "nat": {
      const g = (await ec2.send(new DescribeNatGatewaysCommand({ NatGatewayIds: [resource] }))).NatGateways?.[0];
      return g?.VpcId ? { vpc: g.VpcId, nat: resource } : { vpc: null, nat: resource, why: "NAT gateway not found" };
    }
    case "instance": {
      const i = (await ec2.send(new DescribeInstancesCommand({ InstanceIds: [resource] }))).Reservations?.[0]?.Instances?.[0];
      return i?.VpcId ? { vpc: i.VpcId, nat: null } : { vpc: null, nat: null, why: "instance not found or has no VPC" };
    }
    default: return { vpc: null, nat: null, why: `${resource} is not a VPC, NAT gateway or instance id` };
  }
}

const stateOf = (e: Pick<VpcEndpoint, "State">) => String(e.State || "").toLowerCase();

async function findEndpoint(ec2: EC2Client, vpc: string, region: string, svc: GatewayService, opts: { ours?: boolean } = {}): Promise<VpcEndpoint | null> {
  const r = await ec2.send(new DescribeVpcEndpointsCommand({ Filters: [{ Name: "vpc-id", Values: [vpc] }, { Name: "service-name", Values: [serviceName(region, svc)] }, { Name: "vpc-endpoint-type", Values: ["Gateway"] }] }));
  // The API answers lowercase states ("available", "pending") although the SDK's enum spells them capitalised: compare case-insensitively.
  const all = (r.VpcEndpoints ?? []).filter((e) => !["deleted", "deleting", "failed", "rejected", "expired"].includes(stateOf(e)));
  const list = opts.ours ? all.filter((e) => e.Tags?.some((t) => t.Key === CREATED_TAG)) : all;
  return list[0] ?? null;
}

export const vpcGatewayEndpointAction: ActionModule = {
  kind: KIND,
  label: "Gateway endpoints for S3 and DynamoDB, once approved",

  async plan(creds, log) {
    const proposals: Proposal[] = []; const notes: string[] = [];
    const recs = approvedRecs(ACTION_TYPES);
    if (!recs.length) { notes.push("no approved recommendation to add a gateway endpoint"); return { proposals, notes }; }
    // Resolve every approved fix to (vpc, service); several fixes for one VPC ride along on one proposal.
    const targets = new Map<string, Target>();
    const byRegion = new Map<string, Rec[]>();
    for (const r of recs) { const region = String(r.evidence?.region || r.evidence?.alert?.region || creds.region); if (!byRegion.has(region)) byRegion.set(region, []); byRegion.get(region)!.push(r); }
    for (const [region, list] of byRegion) {
      const ec2 = new EC2Client({ region, credentials: creds.read });
      try {
        for (const r of list) {
          const skip = (why: string) => { notes.push(`#${r.id} ${r.resource}: ${why}`); log(`#${r.id} ${r.resource}: ${why}`); };
          let res: Awaited<ReturnType<typeof resolveVpc>>;
          try { res = await resolveVpc(ec2, r.resource); } catch (e: any) { skip(String(e?.message || e).slice(0, 160)); continue; }
          if (!res.vpc) { skip(res.why || "no VPC"); continue; }
          for (const svc of servicesOf({ title: r.title, evidence: r.evidence, rationale: (r as any).rationale })) {
            const key = `${region}:${res.vpc}:${svc}`;
            const t = targets.get(key);
            if (t) { t.recs.push(r); if (!t.nat) t.nat = res.nat; }
            else targets.set(key, { vpc: res.vpc, service: svc, region, recs: [r], nat: res.nat });
          }
        }
        for (const t of [...targets.values()].filter((t) => t.region === region)) {
          const label = `${t.vpc} ${t.service}`;
          const skip = (why: string) => { notes.push(`${label}: ${why}`); log(`${label}: ${why}`); };
          try {
            const vpc = (await ec2.send(new DescribeVpcsCommand({ VpcIds: [t.vpc] }))).Vpcs?.[0];
            if (!vpc) { skip("VPC not found"); continue; }
            if (vpc.Tags?.some((x) => x.Key === "advisor:hands-off")) { skip("VPC tagged advisor:hands-off"); continue; }
            const existing = await findEndpoint(ec2, t.vpc, region, t.service);
            if (existing) {
              const n = markRecommendationsDone(t.recs.map((r) => r.id), `${t.vpc} already has a gateway endpoint for ${t.service} (${existing.VpcEndpointId}); recommendation closed`);
              skip(`already has a gateway endpoint (${existing.VpcEndpointId}); ${n} approved recommendation(s) marked done`); continue;
            }
            const tables: RouteTable[] = [];
            let NextToken: string | undefined;
            do { const rt = await ec2.send(new DescribeRouteTablesCommand({ Filters: [{ Name: "vpc-id", Values: [t.vpc] }], NextToken })); tables.push(...(rt.RouteTables ?? [])); NextToken = rt.NextToken; } while (NextToken);
            const pick = pickRouteTables(tables);
            if (!pick.ids.length) { skip("the VPC has no route table"); continue; }
            const lead = t.recs[0];
            const vpcName = vpc.Tags?.find((x) => x.Key === "Name")?.Value ?? null;
            proposals.push({
              kind: KIND, resource: t.vpc, resource_name: vpcName ? `${vpcName} (${t.service})` : `${t.vpc} (${t.service})`, region,
              dedupe: `${KIND}:${region}:${t.vpc}:${t.service}`,
              title: `${vpcName || t.vpc}: gateway endpoint for ${t.service === "s3" ? "S3" : "DynamoDB"} on ${pick.ids.length} route table${pick.ids.length === 1 ? "" : "s"}`,
              reason: `${lead.title}. Approved as recommendation #${lead.id}${lead.decided_by ? ` by ${lead.decided_by}` : ""}${t.recs.length > 1 ? ` (and #${t.recs.slice(1).map((r) => r.id).join(", #")})` : ""}. A gateway endpoint costs nothing and takes ${t.service === "s3" ? "S3" : "DynamoDB"} traffic off the NAT gateway${t.nat ? ` (${t.nat})` : ""}. ${pick.fallback ? "No route table sends 0.0.0.0/0 through a NAT gateway, so it goes on every route table of the VPC." : `It goes on the route table${pick.ids.length === 1 ? "" : "s"} that send 0.0.0.0/0 through a NAT gateway: ${pick.names.map((n) => n.name ? `${n.name} (${n.id})` : n.id).join(", ")}.`} Existing connections are not interrupted; new ones take the endpoint route.`,
              before: { endpoint: null }, after: { service: serviceName(region, t.service), route_table_ids: pick.ids },
              facts: { recommendation_id: lead.id, recommendation_ids: t.recs.map((r) => r.id), vpc_id: t.vpc, vpc_name: vpcName, nat_gateway_id: t.nat, service: t.service, route_tables: pick.names, route_tables_fallback: pick.fallback },
              rollback: "delete the endpoint (DeleteVpcEndpoints); traffic goes back through the NAT gateway",
              est_usd_month: t.recs.reduce((s, r) => s + (r.est_monthly_saving ?? 0), 0) || null,
            });
          } catch (e: any) { skip(String(e?.message || e).slice(0, 200)); }
        }
      } finally { ec2.destroy(); }
    }
    return { proposals, notes };
  },

  async apply(p, creds) {
    const ec2 = new EC2Client({ region: p.region, credentials: creds.act() });
    try {
      const svc = String(p.facts.service) as GatewayService;
      const r = await ec2.send(new CreateVpcEndpointCommand({
        VpcEndpointType: "Gateway", ServiceName: String(p.after.service), VpcId: p.resource, RouteTableIds: (p.after.route_table_ids as string[]) ?? [],
        TagSpecifications: [{ ResourceType: "vpc-endpoint", Tags: [{ Key: "Name", Value: `aws-advisor-${svc}` }, { Key: CREATED_TAG, Value: new Date().toISOString() }] }],
      }));
      return `CreateVpcEndpoint: ${r.VpcEndpoint?.VpcEndpointId || "requested"} (${r.VpcEndpoint?.State || "pending"}) on ${(p.after.route_table_ids as string[])?.length ?? 0} route table(s)`;
    } finally { ec2.destroy(); }
  },

  async verify(p, creds) {
    const ec2 = new EC2Client({ region: p.region, credentials: creds.read });
    try {
      const e = await findEndpoint(ec2, p.resource, p.region, String(p.facts.service) as GatewayService, { ours: true });
      if (!e) return { ok: false, note: "no gateway endpoint of ours on read-back" };
      const state = stateOf(e);
      if (state === "available") return { ok: true, note: `read back: ${e.VpcEndpointId} available on ${e.RouteTableIds?.length ?? 0} route table(s)` };
      if (state === "pending" || state === "pendingacceptance") return { ok: null, note: `${e.VpcEndpointId} ${e.State}` };
      return { ok: false, note: `${e.VpcEndpointId} is ${e.State}` };
    } finally { ec2.destroy(); }
  },

  async revert(p, creds) {
    const ec2 = new EC2Client({ region: p.region, credentials: creds.act() });
    try {
      const e = await findEndpoint(ec2, p.resource, p.region, String(p.facts.service) as GatewayService, { ours: true });
      if (!e?.VpcEndpointId) throw new Error("no gateway endpoint of ours (tagged advisor:created) found in the VPC to delete");
      const r = await ec2.send(new DeleteVpcEndpointsCommand({ VpcEndpointIds: [e.VpcEndpointId] }));
      const bad = r.Unsuccessful?.[0];
      if (bad) throw new Error(`DeleteVpcEndpoints ${e.VpcEndpointId}: ${bad.Error?.Message || bad.Error?.Code || "unsuccessful"}`);
      return `${e.VpcEndpointId} deleted; ${p.facts.service} traffic goes back through the NAT gateway`;
    } finally { ec2.destroy(); }
  },
};

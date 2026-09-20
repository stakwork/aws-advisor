import { db } from "./db.js";
import { S, query } from "./steampipe.js";
import { RecInput } from "./rules.js";

/**
 * Deterministic rule: a VPC whose NAT gateway raised a nat_traffic alert in the last 7 days and that has no
 * VPC flow log (on the VPC or on any of its subnets) gets an `enable_flow_logs` recommendation. Without flow
 * logs a NAT spike can only be attributed to the instances behind the gateway (NetworkIn/Out), never to the
 * destinations, so the "why" stays a guess. The advisor never enables flow logs itself; it only recommends.
 * Runs from the collector (full reconcile) and from the watcher when a NAT alert fires (partial upsert).
 */

export const FLOW_LOG_ALERT_WINDOW_DAYS = 7;

export interface FlowLogRow { flow_log_id: string; resource_id: string; log_destination_type: string | null; log_destination: string | null; max_aggregation_interval: number | null; traffic_type: string | null; flow_log_status: string | null }

export interface VpcFlowLogFacts {
  vpc_id: string;
  vpc_name: string | null;
  region: string;
  nat_gateways: string[];
  subnets: string[];
  flow_logs: FlowLogRow[];
}

/** VPC name, subnets and flow logs on the VPC or its subnets. Steampipe queries only; throws on transport errors. */
export async function vpcFlowLogFacts(vpcId: string): Promise<VpcFlowLogFacts> {
  const vpc = (await query<{ vpc_id: string; name: string | null; region: string }>(`select vpc_id, tags ->> 'Name' as name, region from ${S}.aws_vpc where vpc_id = $1`, [vpcId]))[0];
  const subnets = (await query<{ subnet_id: string }>(`select subnet_id from ${S}.aws_vpc_subnet where vpc_id = $1`, [vpcId])).map((r) => r.subnet_id);
  const nats = (await query<{ nat_gateway_id: string }>(`select nat_gateway_id from ${S}.aws_vpc_nat_gateway where vpc_id = $1`, [vpcId])).map((r) => r.nat_gateway_id);
  const ids = [vpcId, ...subnets];
  const flowLogs = await query<FlowLogRow>(`
    select flow_log_id, resource_id, log_destination_type, log_destination, max_aggregation_interval, traffic_type, flow_log_status
    from ${S}.aws_vpc_flow_log where resource_id = any($1::text[])`, [ids]);
  return { vpc_id: vpcId, vpc_name: vpc?.name ?? null, region: vpc?.region ?? "", nat_gateways: nats, subnets, flow_logs: flowLogs };
}

/** The recommendation for one VPC, or null when it already has a flow log. Pure, so it is unit-tested. */
export function flowLogRecommendation(v: VpcFlowLogFacts, recentAlerts: number): RecInput | null {
  if (v.flow_logs.length) return null;
  const name = v.vpc_name ? `${v.vpc_name} (${v.vpc_id})` : v.vpc_id;
  const gws = v.nat_gateways.length ? v.nat_gateways.join(", ") : "its NAT gateway";
  return {
    rule: "enable_flow_logs",
    title: `Enable VPC flow logs on ${name} to attribute NAT traffic spikes`,
    resource: v.vpc_id,
    resourceName: v.vpc_name || v.vpc_id,
    actionType: "enable_flow_logs",
    estMonthlySaving: null,
    tier: "approve",
    confidence: 0.9,
    rationale: `${gws} in this VPC raised ${recentAlerts} NAT traffic alert${recentAlerts === 1 ? "" : "s"} in the last ${FLOW_LOG_ALERT_WINDOW_DAYS} days, ` +
      `but neither the VPC nor any of its ${v.subnets.length} subnets has a flow log. Without flow logs a spike can only be attributed to the instances behind ` +
      `the gateway (from their NetworkIn/NetworkOut), not to the destinations they talk to, so the cause (image pulls, S3 without a gateway endpoint, a backup job, an ` +
      `external API) stays a guess and the data-processing charge of 0.045 USD/GB keeps recurring. A flow log on this VPC with 5-minute aggregation delivered to ` +
      `CloudWatch Logs costs on the order of a few USD per month (ingestion at 0.50 USD/GB of log data, typically hundreds of MB to a few GB for a VPC this size); ` +
      `S3 delivery is cheaper still. The advisor does not enable flow logs itself: this is a recommendation for the team.`,
    evidence: { vpc_id: v.vpc_id, vpc_name: v.vpc_name, region: v.region, nat_gateways: v.nat_gateways, subnets: v.subnets.length, flow_logs: v.flow_logs, recent_nat_alerts: recentAlerts },
  };
}

/** NAT gateways with a nat_traffic alert in the window, with how many alerts each raised. */
export function natGatewaysWithRecentAlerts(): Map<string, number> {
  const rows = db.prepare(`select resource, count(*) as n from alerts where kind = 'nat_traffic' and resource is not null and created_at > datetime('now', ?) group by resource`)
    .all(`-${FLOW_LOG_ALERT_WINDOW_DAYS} days`) as { resource: string; n: number }[];
  return new Map(rows.map((r) => [r.resource, r.n]));
}

/**
 * Builds the enable_flow_logs recommendations for every VPC that owns an alerting NAT gateway (or only the
 * given VPCs). Errors on one VPC are reported through onError and skip that VPC.
 */
export async function flowLogRecommendations(opts: { vpcIds?: string[]; onError?: (m: string) => void } = {}): Promise<RecInput[]> {
  const alerting = natGatewaysWithRecentAlerts();
  if (!alerting.size) return [];
  let gws: { nat_gateway_id: string; vpc_id: string }[] = [];
  try {
    gws = await query(`select nat_gateway_id, vpc_id from ${S}.aws_vpc_nat_gateway where nat_gateway_id = any($1::text[])`, [[...alerting.keys()]]);
  } catch (e: any) {
    opts.onError?.(`nat gateways: ${String(e?.message || e).slice(0, 200)}`);
    return [];
  }
  const alertsByVpc = new Map<string, number>();
  for (const g of gws) {
    if (opts.vpcIds && !opts.vpcIds.includes(g.vpc_id)) continue;
    alertsByVpc.set(g.vpc_id, (alertsByVpc.get(g.vpc_id) || 0) + (alerting.get(g.nat_gateway_id) || 0));
  }
  const out: RecInput[] = [];
  for (const [vpcId, n] of alertsByVpc) {
    try {
      const rec = flowLogRecommendation(await vpcFlowLogFacts(vpcId), n);
      if (rec) out.push(rec);
    } catch (e: any) {
      opts.onError?.(`flow logs ${vpcId}: ${String(e?.message || e).slice(0, 200)}`);
    }
  }
  return out;
}

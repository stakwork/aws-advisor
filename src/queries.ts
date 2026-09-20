import { S } from "./steampipe.js";

/**
 * Custom fact queries. "finding" queries turn each row into a finding; "metric" queries must
 * return (label, value) rows and feed the Overview page. Every table is qualified with the
 * schema this app owns, so nothing leaks in from other Steampipe connections.
 */
export interface QueryDef {
  id: string;
  title: string;
  kind: "finding" | "metric";
  /** finding status: alarm = actionable, info = context */
  status?: "alarm" | "info";
  sql: string;
  resource?: (row: any) => string;
  reason?: (row: any) => string;
}

const lastFullMonth = `period_start >= date_trunc('month', now() - interval '1 month') and period_start < date_trunc('month', now())`;

export const QUERIES: QueryDef[] = [
  {
    id: "stopped_instance_ebs",
    title: "Stopped instances still holding EBS",
    kind: "finding",
    sql: `
      select i.instance_id, i.tags ->> 'Name' as name, i.instance_type, i.region, i.account_id,
             i.state_transition_time::date::text as stopped_on, coalesce(sum(v.size), 0) as ebs_gb
      from ${S}.aws_ec2_instance i
      left join ${S}.aws_ebs_volume v
        on v.attachments @> jsonb_build_array(jsonb_build_object('InstanceId', i.instance_id))
      where i.instance_state = 'stopped'
      group by 1, 2, 3, 4, 5, 6
      order by ebs_gb desc`,
    resource: (r) => r.instance_id,
    reason: (r) => `${r.name || r.instance_id} (${r.instance_type}) stopped since ${r.stopped_on}, holding ${r.ebs_gb} GB of EBS`,
  },
  {
    id: "idle_instances",
    title: "Running instances under 10% max CPU over 30 days",
    kind: "finding",
    sql: `
      with cpu as (
        select instance_id, round(avg(maximum)::numeric, 1) as avg_max_cpu, count(*) as days
        from ${S}.aws_ec2_instance_metric_cpu_utilization_daily
        where timestamp > now() - interval '30 days'
        group by instance_id
      )
      select i.instance_id, i.tags ->> 'Name' as name, i.tags, i.instance_type, i.region, i.account_id,
             i.launch_time::date::text as launched, c.avg_max_cpu, c.days
      from ${S}.aws_ec2_instance i
      join cpu c using (instance_id)
      where i.instance_state = 'running' and c.avg_max_cpu < 10 and c.days >= 14
      order by i.instance_type desc, c.avg_max_cpu`,
    resource: (r) => r.instance_id,
    reason: (r) => `${r.name || r.instance_id} (${r.instance_type}) averages ${r.avg_max_cpu}% max CPU over ${r.days} days`,
  },
  {
    id: "old_snapshots",
    title: "EBS snapshots older than 90 days",
    kind: "finding",
    sql: `
      select snapshot_id, volume_id, volume_size as size_gb, start_time::date::text as created, region, account_id, description,
             exists (select 1 from ${S}.aws_ebs_volume v where v.volume_id = s.volume_id) as volume_exists
      from ${S}.aws_ebs_snapshot s
      where owner_id = account_id and start_time < now() - interval '90 days'
      order by start_time`,
    resource: (r) => r.snapshot_id,
    reason: (r) => `${r.snapshot_id} (${r.size_gb} GB) created ${r.created}${r.volume_exists ? "" : ", source volume gone"}`,
  },
  {
    id: "eip_unattached",
    title: "Elastic IPs not attached to anything",
    kind: "finding",
    sql: `
      select public_ip, allocation_id, region, account_id, tags ->> 'Name' as name
      from ${S}.aws_vpc_eip
      where association_id is null`,
    resource: (r) => r.allocation_id,
    reason: (r) => `${r.public_ip}${r.name ? ` (${r.name})` : ""} is allocated but unattached`,
  },
  {
    id: "log_groups_no_retention",
    title: "CloudWatch log groups with no retention policy",
    kind: "finding",
    sql: `
      select name, arn, region, account_id, round(stored_bytes / 1024.0 / 1024 / 1024, 2) as stored_gb
      from ${S}.aws_cloudwatch_log_group
      where retention_in_days is null
      order by stored_bytes desc`,
    resource: (r) => r.arn || r.name,
    reason: (r) => `${r.name} has no retention policy (${r.stored_gb} GB stored)`,
  },
  {
    id: "commitments",
    title: "Active commitments and their expiry",
    kind: "finding",
    status: "info",
    sql: `
      select 'savings_plan' as kind, savings_plan_id as id, savings_plan_type as detail,
             round((commitment::numeric * 730), 0) as monthly_usd, end_time::date::text as expires,
             (end_time::date - current_date) as days_left, account_id, region
      from ${S}.aws_savingsplans_savings_plan where state = 'active'
      union all
      select 'rds_ri', reserved_db_instance_id, class || ' x' || db_instance_count, null,
             (start_time + (duration || ' seconds')::interval)::date::text,
             ((start_time + (duration || ' seconds')::interval)::date - current_date), account_id, region
      from ${S}.aws_rds_reserved_db_instance where state = 'active'
      union all
      select 'elasticache_ri', reserved_cache_node_id, cache_node_type || ' x' || cache_node_count, null,
             (start_time + (duration || ' seconds')::interval)::date::text,
             ((start_time + (duration || ' seconds')::interval)::date - current_date), account_id, region
      from ${S}.aws_elasticache_reserved_cache_node where state = 'active'
      union all
      select 'ec2_ri', reserved_instance_id, instance_type || ' x' || instance_count, null,
             end_time::date::text, (end_time::date - current_date), account_id, region
      from ${S}.aws_ec2_reserved_instance where instance_state = 'active'
      order by expires`,
    resource: (r) => r.id,
    reason: (r) => `${r.kind} ${r.detail} expires ${r.expires} (${r.days_left} days)`,
  },
  {
    id: "spend_by_record_type",
    title: "Last full month spend by record type",
    kind: "metric",
    sql: `
      select record_type as label, round(sum(amortized_cost_amount)::numeric, 0) as value,
             round(sum(unblended_cost_amount)::numeric, 0) as unblended,
             round(sum(net_unblended_cost_amount)::numeric, 0) as net_unblended
      from ${S}.aws_cost_by_record_type_monthly
      where ${lastFullMonth}
      group by 1 order by 2 desc`,
  },
  {
    id: "on_demand_by_service",
    title: "Last full month on-demand spend by service",
    kind: "metric",
    sql: `
      select dimension_1 as label, round(sum(unblended_cost_amount)::numeric, 0) as value
      from ${S}.aws_cost_usage
      where granularity = 'MONTHLY' and dimension_type_1 = 'SERVICE' and dimension_type_2 = 'RECORD_TYPE'
        and dimension_2 = 'Usage' and ${lastFullMonth}
      group by 1 having sum(unblended_cost_amount) > 20
      order by 2 desc limit 15`,
  },
  {
    id: "ec2_other_usage",
    title: "Last full month EC2 - Other by usage type",
    kind: "metric",
    sql: `
      select usage_type as label, round(sum(unblended_cost_amount)::numeric, 0) as value
      from ${S}.aws_cost_by_service_usage_type_monthly
      where service = 'EC2 - Other' and ${lastFullMonth}
      group by 1 having sum(unblended_cost_amount) > 10
      order by 2 desc`,
  },
];

export const AURORA_CLUSTERS_SQL = `
  select db_cluster_identifier as cluster, engine, coalesce(storage_type, 'aurora') as storage_type,
         jsonb_array_length(members) as members, region, account_id
  from ${S}.aws_rds_db_cluster
  where engine like 'aurora%'`;

/** 30-day volume size and I/O for one cluster; exact-match dimensions are required by the CloudWatch table. */
export const auroraMetricsSql = (cluster: string, region: string) => `
  select metric_name, max(maximum) as max_value, sum(sum) as sum_value
  from ${S}.aws_cloudwatch_metric_statistic_data_point
  where namespace = 'AWS/RDS'
    and metric_name in ('VolumeBytesUsed', 'VolumeReadIOPs', 'VolumeWriteIOPs')
    and dimensions = '[{"Name":"DBClusterIdentifier","Value":${JSON.stringify(cluster)}}]'
    and timestamp between now() - interval '30 days' and now()
    and period = 3600
    and region = ${JSON.stringify(region).replace(/"/g, "'")}
  group by 1`;

# Ad-hoc cost queries tailored to this account's bill (EC2 m6i fleet,
# ElastiCache, EBS, CloudWatch). Run with:
#   powerpipe query run local.query.<name>
# or open them in the Powerpipe UI (powerpipe server) under "Queries".

query "ec2_running_by_type" {
  title = "Running EC2 instances grouped by type and region"
  sql   = <<-EOQ
    select
      instance_type,
      region,
      count(*)                                   as instances,
      sum(extract(epoch from now() - launch_time) / 3600)::int as total_uptime_hours,
      min(launch_time)                           as oldest_launch
    from aws_ec2_instance
    where instance_state = 'running'
    group by instance_type, region
    order by instances desc, instance_type;
  EOQ
}

query "ec2_running_untagged" {
  title = "Running EC2 instances with no Name tag"
  sql   = <<-EOQ
    select
      instance_id,
      instance_type,
      region,
      launch_time,
      tags
    from aws_ec2_instance
    where instance_state = 'running'
      and (tags ->> 'Name') is null
    order by launch_time;
  EOQ
}

# NOTE: as of 2026-09 every Savings Plan and reservation in the org is owned
# by the member account (the member); the payer holds none.
# All EC2 RIs here are retired; coverage comes from the Compute Savings Plan.
query "ec2_reserved_instances" {
  title = "EC2 reserved instances (all retired; see savings_plans for live coverage)"
  sql   = <<-EOQ
    select
      reserved_instance_id,
      instance_type,
      instance_count,
      offering_class,
      offering_type,
      instance_state,
      region,
      end_time                                  as expires,
      (end_time::date - current_date)           as days_left
    from aws_ec2_reserved_instance
    order by end_time;
  EOQ
}

query "ebs_unattached_volumes" {
  title = "Unattached EBS volumes (paying for storage nobody uses)"
  sql   = <<-EOQ
    select
      volume_id,
      volume_type,
      size                                       as size_gb,
      iops,
      region,
      create_time,
      tags ->> 'Name'                            as name
    from aws_ebs_volume
    where state = 'available'
    order by size desc;
  EOQ
}

query "ebs_gp2_volumes" {
  title = "gp2 volumes that could move to gp3 (~20% cheaper)"
  sql   = <<-EOQ
    select
      volume_id,
      size                                       as size_gb,
      state,
      region,
      jsonb_array_elements(attachments) ->> 'InstanceId' as instance_id
    from aws_ebs_volume
    where volume_type = 'gp2'
    order by size desc;
  EOQ
}

query "ebs_old_snapshots" {
  title = "EBS snapshots older than 90 days"
  sql   = <<-EOQ
    select
      snapshot_id,
      volume_id,
      volume_size                                as size_gb,
      start_time,
      region,
      description
    from aws_ebs_snapshot
    where owner_id = account_id
      and start_time < now() - interval '90 days'
    order by start_time;
  EOQ
}

query "elasticache_clusters" {
  title = "ElastiCache clusters with node type and age"
  sql   = <<-EOQ
    select
      cache_cluster_id,
      cache_node_type,
      engine,
      engine_version,
      num_cache_nodes,
      region,
      cache_cluster_create_time                  as created,
      (current_date - cache_cluster_create_time::date) as age_days
    from aws_elasticache_cluster
    order by cache_cluster_create_time;
  EOQ
}

query "eip_unattached" {
  title = "Elastic IPs not attached to anything (billed hourly)"
  sql   = <<-EOQ
    select
      public_ip,
      allocation_id,
      region,
      tags ->> 'Name'                            as name
    from aws_vpc_eip
    where association_id is null;
  EOQ
}

query "cloudwatch_log_groups_no_retention" {
  title = "CloudWatch log groups with no retention policy"
  sql   = <<-EOQ
    select
      name,
      region,
      round(stored_bytes / 1024.0 / 1024 / 1024, 2) as stored_gb,
      retention_in_days
    from aws_cloudwatch_log_group
    where retention_in_days is null
    order by stored_bytes desc;
  EOQ
}

query "commitment_coverage" {
  title = "Monthly spend split by on-demand vs Savings Plan vs RI coverage (works in a member account)"
  sql   = <<-EOQ
    select
      period_start::date                              as month,
      record_type,
      round(sum(unblended_cost_amount)::numeric, 0)   as unblended_usd,
      round(sum(amortized_cost_amount)::numeric, 0)   as amortized_usd
    from aws_cost_by_record_type_monthly
    where period_start > now() - interval '6 months'
      and record_type in ('Usage', 'SavingsPlanCoveredUsage', 'SavingsPlanRecurringFee', 'DiscountedUsage')
    group by 1, 2
    order by 1, 3 desc;
  EOQ
}

query "uncovered_usage_by_service" {
  title = "Last full month's on-demand (uncovered) spend by service"
  sql   = <<-EOQ
    select
      dimension_1                                     as service,
      round(sum(unblended_cost_amount)::numeric, 0)   as on_demand_usd
    from aws_cost_usage
    where granularity = 'MONTHLY'
      and dimension_type_1 = 'SERVICE'
      and dimension_type_2 = 'RECORD_TYPE'
      and dimension_2 = 'Usage'
      and period_start >= date_trunc('month', now() - interval '1 month')
      and period_start <  date_trunc('month', now())
    group by 1
    having sum(unblended_cost_amount) > 50
    order by 2 desc;
  EOQ
}

# ---------------------------------------------------------------------------
# Commitment queries. Unqualified table names run through the aws_all
# aggregator, so these cover both the member and payer accounts.
# ---------------------------------------------------------------------------

query "savings_plans" {
  title = "Savings Plans: commitment, term and expiry (both accounts)"
  sql   = <<-EOQ
    select
      account_id,
      savings_plan_id,
      savings_plan_type,
      ec2_instance_family,
      payment_option,
      state,
      commitment                                   as hourly_commitment_usd,
      round((commitment::numeric * 730), 0)        as monthly_commitment_usd,
      term_duration_in_seconds / 86400 / 365       as term_years,
      start_time::date                             as starts,
      end_time::date                               as expires,
      (end_time::date - current_date)              as days_left
    from aws_savingsplans_savings_plan
    order by end_time;
  EOQ
}

query "rds_reserved_instances" {
  title = "RDS reserved instances (both accounts)"
  sql   = <<-EOQ
    select
      account_id,
      reserved_db_instance_id,
      class,
      db_instance_count,
      multi_az,
      product_description,
      offering_type,
      state,
      start_time::date                                          as starts,
      (start_time + (duration || ' seconds')::interval)::date   as expires,
      ((start_time + (duration || ' seconds')::interval)::date - current_date) as days_left
    from aws_rds_reserved_db_instance
    order by 10;
  EOQ
}

query "elasticache_reserved_nodes" {
  title = "ElastiCache reserved nodes (both accounts)"
  sql   = <<-EOQ
    select
      account_id,
      reserved_cache_node_id,
      cache_node_type,
      cache_node_count,
      product_description,
      offering_type,
      state,
      start_time::date                                          as starts,
      (start_time + (duration || ' seconds')::interval)::date   as expires,
      ((start_time + (duration || ' seconds')::interval)::date - current_date) as days_left
    from aws_elasticache_reserved_cache_node
    order by 9;
  EOQ
}

query "commitments_expiring_90d" {
  title = "Every commitment (SP, EC2/RDS/ElastiCache RI) that ends in the next 90 days"
  sql   = <<-EOQ
    select 'savings_plan' as kind, savings_plan_id as id, savings_plan_type as detail, end_time::date as expires
    from aws_savingsplans_savings_plan where state = 'active'
    union all
    select 'ec2_ri', reserved_instance_id, instance_type || ' x' || instance_count, end_time::date
    from aws_ec2_reserved_instance where instance_state = 'active'
    union all
    select 'rds_ri', reserved_db_instance_id, class || ' x' || db_instance_count, (start_time + (duration || ' seconds')::interval)::date
    from aws_rds_reserved_db_instance where state = 'active'
    union all
    select 'elasticache_ri', reserved_cache_node_id, cache_node_type || ' x' || cache_node_count, (start_time + (duration || ' seconds')::interval)::date
    from aws_elasticache_reserved_cache_node where state = 'active'
    order by expires;
  EOQ
}

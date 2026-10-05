# What is in the graph today (AWS adapter, model v2 steps 1 and 2)

The target model is `docs/cloud-ontology.md`; this file is the record of what the mirror actually writes now, label by
label, after steps 1 and 2 of that plan (generic labels and properties, telemetry edges, endpoints, functions, storage,
DNS and Beanstalk deployments; the network layer and the reachability verdicts). Steps 3 to 7 (packages and
vulnerabilities, cluster workloads, playbooks from sources, the adapter boundary, Vercel) are not here yet; §4 lists
what that leaves out. The code: `src/graph_mirror.ts` (the `Advisor*` labels and the AWS mapping),
`src/graph_network.ts` (the network layer and the verdicts), `src/graph_knowledge.ts` (the `Kn*` labels),
`src/swarm_costs_graph.ts` (tenant costs), `src/concepts.ts` (Concepts).

Conventions, as in the model: every node carries `provider` (`aws`), `account_id`, `native_type`, `native_id` and
`updated_at`; resources also `name`, `state` (generic) with `native_state`, `region`, `gone`, `first_seen`, `last_seen`.
Those are not repeated below. Unique constraint on `id` for every label; `provider`, `account_id` and `native_type`
are indexed on `AdvisorResource`. Wiping an account removes every node that carries its `account_id`; archetypes,
system types and Concepts survive.

---

## 1. Records (`Advisor*`)

### AdvisorAccount

`{id: the 12-digit account id, kind: account}`. Everything hangs off it through `IN_ACCOUNT`; it carries the
`TRANSFERS_TO` edge for cross-AZ bytes and `SHIPS_LOGS_TO` for log groups no system claimed.

### AdvisorTelemetry

One node per source per account, `id = aws:<account>:telemetry:<kind>`:

| kind | native | covers |
|---|---|---|
| `api` | `steampipe` | every inventoried resource |
| `metrics` | `cloudwatch` | EC2 and RDS with CPU history, balancers with request metrics, functions with invocation metrics, buckets with storage metrics, volumes with IOPS metrics |
| `probe` | `ssm_probe` | EC2 instances with a Systems Manager status or a probe on file |
| `logs`, `audit`, `bill` | `cloudwatch_logs`, `cloudtrail`, `cost_explorer` | nodes exist; per-resource edges come with later steps |

`(:AdvisorResource)-[:OBSERVED_BY {since, last_at, status: ok|stale|offline, detail}]->(:AdvisorTelemetry)`. The probe
edge's `status` is `ok` when the agent is `Online`, `offline` otherwise, with the agent's own word in `detail`; the
`api` edge is `stale` on a gone resource. Edges the row no longer claims are pruned on every resource mirror.

### AdvisorResource and its labels

Shared beyond the base: `role` (judged archetype), `role_confidence`, `protected_prob`, `monthly_usd` (a month at
list), `pool` (EC2: the autoscaling pool name).

| label | native_type | id | own properties |
|---|---|---|---|
| `AdvisorCompute` | `ec2_instance` | instance id | `type`, `arch`, `platform`, `image_id`, `private_ips`, `public_ip`, `ipv6`, `hostname`, `zone`, `lifecycle` (`on_demand` \| `spot`), `launch_time`, `cpu_30d`, `ebs_gb`, `volumes`, `probe_at`, `probe_mem_pct`, `vpc_id`, `subnet_id`, `security_groups`; health checks `health` (`ok` \| `impaired` \| `initializing` \| `unknown`), `health_host`, `health_instance`, `health_storage`, `scheduled_events`, `health_checked_at`; the usage profile block; the wake block; the tenant block (below) |
| `AdvisorDatabase` | `rds_instance` | DB instance identifier | `engine`, `engine_version`, `type` (class), `cluster`, `cluster_role` (`member` \| `standalone`), `storage_gb`, `storage_type`, `multi_az`, `publicly_accessible`, `encrypted`, `backup_retention_days`, `deletion_protection`, `endpoint_host`, `port`, `vpc_id`, `cpu_30d`, `created_at` |
| `AdvisorCache` | `elasticache_cluster` | cache cluster id | `engine`, `engine_version`, `type` (node type), `nodes`, `group` (replication group), `created_at` |
| `AdvisorLoadBalancer` | `elb_alb` \| `elb_nlb` \| `elb_gwlb` \| `elb_clb` | ARN | `kind` (`application` \| `network` \| `gateway` \| `classic`), `type` (the AWS word), `scheme` (`public` \| `internal`), `native_scheme`, `dns_name`, `targets`, `healthy`, `unhealthy`, `requests_30d`, `gb_30d`, `asgs`, `ecs_services`, `platform_owner` (the Beanstalk environment), `vpc_id`, `created_at` |
| `AdvisorFunction` | `lambda_function` | ARN | `runtime`, `runtime_version`, `memory_mb`, `timeout_s`, `arch`, `kind: serverless`, `invocations_30d`, `errors_30d`, `duration_avg_ms`, `invocations_month`, `gb_seconds_month` |
| `AdvisorStorage` | `s3_bucket` | bucket name | `kind: object`, `size_gb`, `objects`, `standard_gb`, `versioning`, `lifecycle_rules`, `public`, `created_at` |
| `AdvisorStorage` | `ebs_volume` | volume id | `kind: block`, `size_gb`, `class` (volume type), `iops`, `throughput_mibps`, `encrypted`, `attached_to`, `device`, `iops_30d`, `iops_max`, `used_pct`, `created_at` |
| `AdvisorDeployment` | `beanstalk_environment` \| `kubernetes_deployment` \| `kubernetes_statefulset` \| `kubernetes_daemonset` \| `kubernetes_job` \| `kubernetes_cronjob` \| `ecs_service` | `aws:<account>:beanstalk:<env>`, or `<cluster arn>/<namespace>/<Kind>/<name>` | `platform` (`beanstalk` \| `eks` \| `ecs`), `workload_kind`, `namespace`, `environment` (from the name or namespace), `containers` (count), `images`, `replicas_desired`, `replicas_ready`, `health` (`ok` \| `degraded` \| `severe` \| `unknown` from ready vs desired), `revision`, `strategy`, `schedule`, `service_account`, `labels` (as `key=value`), `pods_running`, `created_at` |
| `AdvisorCluster` | `eks_cluster` \| `ecs_cluster` | cluster ARN | `kind` (`kubernetes` \| `ecs`), `version`, `platform_version`, `endpoint_public`, `public_cidrs`, `endpoint_private`, `authentication_mode`, `access_status` (`ok` \| `unauthorized` \| `forbidden` \| `unreachable` \| `tls` \| `error`) and `access_error` (what the advisor can read of it), `nodes`, `workloads`, `namespaces`, `vpc_id`, `security_groups` |
| `AdvisorImage` | `container_image` | `image:<reference>` | `name`, `kind: container`, `repository`, `tag`, `digest`, `created_at`, `platform`; the images workloads are built from (`BUILT_FROM`) and boxes run containers of (`RUNS_IMAGE`, from the software probe); packages inside an image are not read yet |
| `AdvisorDnsZone` | `route53_zone` | zone id | `private`, `records`, `linked`, `external`, `unmatched`, `queries_30d`, `comment` |
| `AdvisorDnsRecord` | `route53_record` | the record id | `fqdn`, `type`, `ttl`, `values`, `alias`, `alias_target`, `routing`, `link_state` (`resource` \| `external` \| `dangling` \| `none` \| `unknown`), `native_link_state`, `summary`, `zone_id` |
| `AdvisorDatabase` | `dynamodb_table` | ARN | `engine: dynamodb`, `kind: key_value`, `serverless: true`, `type` (`on-demand` or `provisioned N RCU / M WCU`), `billing_mode`, `read_capacity`, `write_capacity`, `indexes`, `storage_gb`, `items`, `point_in_time_recovery`, `backup_retention_days` (35 or 0), `streams`, `reads_30d`, `writes_30d` |
| `AdvisorIdentity` | `iam_user` \| `sso_user` | user ARN \| Identity Center user id | `kind: user`, `human`, `mfa`, `admin`, `credentials`, `credential_age_days`, `last_used_at`, `groups`, `policies`; IAM: `console_access`, `access_keys`, `permissions_boundary`; Identity Center: `display_name`, `email`, `identity_provider`, `accounts`, `assignments`, `sign_ins_30d`, `failed_sign_ins_30d`, `activity` |
| `AdvisorCertificate` | `acm_certificate` | ARN | `domains`, `issuer` (`acm` \| `private_ca` \| the imported issuer), `origin` (`issued` \| `imported` \| `private`), `status` (`issued` \| `expired` \| `pending` \| `revoked` \| `failed` \| `inactive`), `not_before`, `not_after`, `days_left`, `in_use`, `used_by`, `key_algorithm`, `renewal_eligible`, `wildcard` |
| `AdvisorMessaging` | `sns_topic` | ARN | `kind: topic`, `fifo`, `display_name`, `subscriptions`, `pending`, `protocols` (`lambda 2`; addresses never stored), `encrypted`, `kms_key`, `dlq`, `messages_30d` |
| `AdvisorSecret` | `kms_key` | ARN | `kind: kms_key`, `key_id`, `managed` (AWS-managed), `key_state` (`enabled` \| `disabled` \| `pending_deletion` \| …), `encrypted: true`, `usage`, `spec`, `origin`, `rotation_enabled`, `aliases`, `multi_region`, `deletion_at`, `description` |
| `AdvisorStorage` | `efs_file_system` | ARN | `kind: file`, `file_system_id`, `size_gb`, `standard_gb`, `ia_gb`, `archive_gb`, `class` (`regional` \| `one_zone`), `zone`, `performance_mode`, `throughput_mode`, `provisioned_mibps`, `encrypted`, `mount_targets`, `zones`, `automatic_backups`, `vpc_id`, `security_groups` |
| `AdvisorStorage` | `backup_vault` | ARN | `kind: backup`, `recovery_points`, `size_gb`, `warm_gb`, `cold_gb`, `by_type` (`RDS 12`), `oldest_at`, `newest_at`, `locked`, `min_retention_days`, `max_retention_days`, `encrypted: true`, `protected_resources`, `protected_types` |
| `AdvisorBackupPlan` | `backup_plan` | ARN | `rules`, `schedules` (one line per rule), `retention_days`, `keeps_forever`, `cold_after_days`, `copies`, `vaults`, `selections` (in words), `selected_by_arn`, `selects_all`, `last_run_at`, `plan_id` |
| `AdvisorAnalytics` | `athena_workgroup` | `arn:aws:athena:<region>:<account>:workgroup/<name>` | `kind: query_engine`, `engine: athena`, `engine_version`, `enforce_config`, `scan_limit_gb`, `output_location`, `output_encrypted`, `encryption`, `metrics_published`, `scanned_gb_30d`, `requester_pays` |
| `AdvisorStack` | `cloudformation_stack` | stack ARN | `tool: cloudformation`, `resources`, `mapped_resources`, `resource_types` (`EC2::Instance 3`), `failed_resources`, `drift` (`in_sync` \| `drifted` \| `unknown`), `termination_protection`, `nested`, `root_id`, `status_reason`, `role_arn`, `updated_at` |
| `AdvisorFilter` (also `AdvisorResource`) | `wafv2_web_acl` | ARN | `kind: web_acl`, `stateful: false`, `default_action` (`allow` \| `block`), `rules`, `rule_list` (one line per rule in priority order), `managed_groups`, `rate_limits`, `attached`, `native_scope`, `edge` (CloudFront scope), `capacity`, `logging`, `firewall_manager`, `requests_30d`, `blocked_30d` |
| `AdvisorDetector` | `guardduty_detector` | ARN | `kind: threat_detection`, `engine: guardduty`, `detector_id`, `enabled`, `protections_on`, `protections_off`, `publishing_frequency`, `administrator`, `findings_open`, `findings_critical`, `findings_high`, `last_finding_at` |

Tenant block (swarm costs, on an `AdvisorCompute` that is one customer's environment): `tenant: true`,
`tenant_kind: swarm`, `cost_month_usd`, `cost_compute_usd`, `cost_storage_usd`, `cost_snapshot_usd`, `cost_ip_usd`,
`cost_month`, `cost_updated_at`, `last_use_at`, `idle_days`, `parked`, `nudge`.

Usage profile block (`AdvisorCompute`, `AdvisorNodePool`): `usage_quiet_hours_week`, `usage_confidence`,
`usage_schedule`, `usage_off_hours_week`, `usage_est_usd_month`, `usage_quiet_windows`, `usage_summary`,
`usage_computed_at`, `usage_review_verdict`, `usage_review_schedule`, `usage_review_confidence`,
`usage_review_reason`, `usage_reviewed_at`.

Wake block (`AdvisorCompute`): `wake_enabled`, `wake_domains`, `wake_profile`, `wake_updated_at`, `wake_updated_by`.

Edges from a resource: `IN_ACCOUNT`; `HAS_ROLE` → `KnArchetype`; `IN_POOL` → `AdvisorNodePool` (compute);
`OBSERVED_BY` → `AdvisorTelemetry`; `EXPOSES {gone}` → `AdvisorEndpoint`; `RUNS {…}` → `AdvisorApp`;
`STORES_ON {device}` → `AdvisorStorage` (compute → its volumes); `SHIPS_LOGS_TO {via, source, observed_at,
attributed_by: observed}` → `KnLogGroup`; `MEMBER_OF` → `KnSystem`; `IN_ZONE` (record → zone); `POINTS_TO {hop, via}`
(record → the node the resolver linked, or a ref); `RUNS_ON_POOL` and `BACKED_BY` (Beanstalk deployment → pool, balancer);
`RUNS_IN` (workload → cluster); `BUILT_FROM` (workload → image); `SCHEDULED_ON {pods}` (workload → the compute nodes its
pods run on); `GUARDED_BY` (workload → NetworkPolicy filter); `PART_OF` (node pool → cluster); `IN_CLUSTER` (NetworkPolicy
filter → cluster); `FRONTED_BY` (a workload's endpoint → the balancer an Ingress or LoadBalancer Service created, or a
ref when it is not in the inventory). The cluster `EXPOSES` an `api` endpoint whose `REACHABLE_FROM` sources are its
public access CIDRs with `requires_auth: true`. A resource the inventory stops listing is marked `gone`; Beanstalk
deployments are rebuilt each sync and never marked, cluster workloads are marked when the cluster stops listing them.

The platform services (`src/service_inventory.ts`, one collector per service in `src/services/`, the edges written by
`src/graph_services.ts`; every pass drops these edge types on a service node and writes the current ones):
`SECURES` (certificate → the balancer, distribution or API ACM says uses it); `DELIVERS_TO {protocol, raw, filtered}`
(topic → function, queue or stream); `ENCRYPTS` (key → file system, topic, backup vault; an alias or key id is
resolved to the key's ARN, an unread alias stays a ref); `IN_NETWORK`, `IN_SEGMENT`, `GUARDED_BY` (file system → the
VPC, subnets and security groups of its mount targets); `BACKED_UP_TO {last_backup_at, resource_type}` (resource →
the vault its latest backup is in); `STORES_IN` (plan → vault); `PROTECTS` (plan → the resources its selections name
by ARN; tag and wildcard selections stay words); `WRITES_TO` (workgroup → results bucket); `MANAGES {logical_id,
resource_type}` (stack → the resources and network nodes it created, never a ref); `PART_OF` (nested stack → parent);
`GUARDED_BY` (balancer or API → the web ACL attached to it). A target the graph has no node for is an
`AdvisorResourceRef` with `guessed_type` (`cdn_distribution`, `api`, `queue`, `key_alias`, …).

### AdvisorThreatFinding

GuardDuty's findings (`threat_findings`, kept 90 days like GuardDuty keeps them; the `threat findings` layer): `id`
(the finding ARN), `type`, `title`, `description`, `severity` (`low` \| `medium` \| `high` \| `critical`: below 4, 7,
9, from 9), `native_severity` (1-10), `confidence`, `resource_type`, `resource` (the instance id, bucket, function or
cluster ARN, IAM user ARN), `resource_name`, `count`, `first_seen_at`, `last_seen_at`, `created_at`, `archived`, `gone`.
Edges: `IN_ACCOUNT`; `REPORTED_BY` → `AdvisorDetector`; `ABOUT` → the resource, or a ref. A finding the table no longer
holds is deleted from the graph.

### AdvisorNotification

What AWS told the account through User Notifications (`src/cloud_notifications.ts`, 90 days): `feed`, `source`,
`event_type`, `headline`, `notification_type`, `event_status`, `origin_region`, `related_account`, `created_at`,
`aggregation`, `event_count`, `regions`; `IN_ACCOUNT` the account that received it.

### AdvisorResourceRef

`{id: the string as the record named it, guessed_type, first_named_at, named_by: recommendation|alert|action|dns_record}`.
`guessed_type` comes from the id's shape: `vpc`, `subnet`, `security_group`, `snapshot`, `volume`, `bucket`, `function`,
`table`, `repository`, `file_system`, `key`, `alarm`, `log_group`, `nat_gateway`, `public_ip`, `interface`, `instance`,
`cdn_distribution`, or the ARN's service. Upgrade in place is not implemented yet: a ref whose id later gets a real
node keeps the ref label beside the new one (both MERGE on the same `id` only if the labels match, so today they are two
nodes; see §4).

### AdvisorNodePool

`{id: aws:<account>:pool:<name>, name, kind: asg|karpenter|node_group|batch, platform (beanstalk when it backs an
environment), region}` plus the usage profile block and the capacity pattern block: `capacity_env_id`,
`capacity_env_name`, `capacity_computed_at`, `capacity_days`, `capacity_weeks`, `capacity_coverage`,
`capacity_confident`, `capacity_floor`, `capacity_ceiling`, `capacity_learned_min`, `capacity_wanted`,
`capacity_trigger`, `capacity_binding`, `capacity_signals`, `capacity_pressure_events`, `capacity_summary`,
`capacity_updated_at`. Edges: `IN_POOL` ← members; `PRESSURED_AT` → `AdvisorPressureEvent`.

### AdvisorPressureEvent

`{id, env_id, at, ring (0..167, 0 = Sunday 00:00 UTC), desired, max_size, signal: cpu, value, cpu_avg, note}`; last 28
days only. `ANSWERED` ← the action that raised the ceiling.

### AdvisorEndpoint

| kind | native_type | id | written by |
|---|---|---|---|
| `port` | `instance_port` | `<instance>:<proto>:<port>` | the probe's listeners (`protocol`, `port`, `bind`, `scope`, `exposure`, `process`, `container`, `container_port`, `probes`) and balancer targets (port only) |
| `listener` | `elb_listener` | `<lb arn>:listener:<protocol>:<port>` | the balancer inventory (`protocol`, `port`, `tls`, `certificates`, `hostname` = the balancer's DNS name, `exposure` from the scheme) |
| `service_endpoint` | `rds_endpoint` | `<db>:tcp:<port>` | the RDS snapshot (`hostname`, `port`, `exposure` from `publicly_accessible`) |
| `url` | `lambda_invoke` \| `kubernetes_ingress_path` | `<function arn>:invoke`, or `<ingress id>:<host><path>` | a Lambda target behind a balancer (`protocol: https`); an Ingress host and path (`hostname`, `path`, `url`, `tls`, `service`), `FORWARDS_TO` its Service endpoint |
| `service_endpoint` | `kubernetes_service_port` | `<service id>:<port>` | a Service port on the workloads it selects (`hostname` `<svc>.<ns>.svc`, `service_type` ClusterIP \| NodePort \| LoadBalancer) |
| `api` | `eks_api_endpoint` | `<cluster arn>:api` | the Kubernetes control plane endpoint; `REACHABLE_FROM` its public access CIDRs with `requires_auth` |

All carry `resource_id`, `first_seen`, `last_seen`, `gone`. Edges: `EXPOSES` ← the resource; `SERVES` ← the app
behind a port; `FORWARDS_TO {target_group, health}` listener → target endpoint (from the balancer itself when the
listener cannot be told). `exposure` (`internet` \| `network` \| `group` \| `closed` \| `local`), `reach_reason` and
`reach_computed_at` summarise the verdict edges below (§1a).

### 1a. Network layer and verdicts (`src/graph_network.ts`)

Rebuilt after every inventory and resource mirror; verdicts of one instance's ports again after each probe.

| label | native_type | id | properties |
|---|---|---|---|
| `AdvisorNetwork` | `vpc` | vpc id | `cidr_blocks`, `ipv6_blocks` (count), `default`, `flat: false`, `region`; `foreign: true` on a peer VPC in another account |
| `AdvisorSegment` | `subnet` | subnet id | `cidr`, `ipv6_cidr`, `zone`, `public` (its route table sends `0.0.0.0/0` or `::/0` to an internet gateway through an active route), `auto_public_ip`, `available_ips`, `default`, `name` |
| `AdvisorRouteTable` | `route_table` | route table id | `main`, `routes` (count), `name` |
| `AdvisorGateway` | `internet_gateway` \| `nat_gateway` \| `egress_only_internet_gateway` \| `vpc_peering_connection` \| `vpc_endpoint` (and bare `transit`, `vpn` nodes named only by routes) | the AWS id | `kind` (`internet` \| `nat` \| `egress_only` \| `peering` \| `endpoint` \| `transit` \| `vpn`), `state`, `public_ip` / `public_ips` and `private_ip` (NAT), `service` and `endpoint_type` (endpoints), `peer_network_id` and `peer_account_id` (peering), `name` |
| `AdvisorInterface` | `network_interface` | eni id | `private_ips`, `public_ip`, `ipv6`, `mac`, `interface_type` (AWS's), `owner_kind` (`instance` \| `load_balancer` \| `function` \| `nat_gateway` \| `vpc_endpoint` \| `database` \| `cache` \| `efs` \| `other`, from the attachment or the description), `description`, `status`, `source_dest_check`, `primary` |
| `AdvisorPublicIp` | `elastic_ip` | allocation id (or the address) | `ip`, `kind: static`, `associated`, `allocation_id` |
| `AdvisorFilter` | `security_group` \| `network_acl` | group id or ACL id | `kind`, `stateful` (true for groups, false for ACLs), `default_action: deny`, `default` (the VPC's default group or ACL), `name`, `description`, `rules` (count), `attached` (interfaces wearing it, or subnets under it) |
| `AdvisorFilterRule` | `security_group_rule` \| `network_acl_entry` | the rule id (`sgr-…`), a synthesized key when AWS gave none, or `<acl>:in\|out:<rule number>` | `direction` (`ingress` \| `egress`), `action` (`allow` \| `deny`), `protocol` (`tcp` \| `udp` \| `icmp` \| `icmpv6` \| `any`), `from_port` / `to_port` (null = all), `priority` (ACL rule number; null for group rules), `source_kind` (`internet` \| `cidr` \| `filter` \| `prefix_list` \| `any`), `source` (the CIDR, group id or prefix list id), `description`, `dormant` (an IPv6-only rule in a network without IPv6), `filter_id`. The ACL's catch-all deny (rule 32767) is not a node: it is the implicit deny |
| `AdvisorSource` | `source` | `internet` \| `cidr:<cidr>` \| `prefix:<id>` | `kind` (`internet` \| `cidr` \| `prefix_list`), `label`, `cidr`, `private` (RFC 1918, link-local or loopback). Shared catalogue nodes, no `account_id`; `internet` also carries `KnDestination` |

Edges: `IN_NETWORK` (segments, route tables, gateways, interfaces, filters and resources → network); `IN_SEGMENT`
(interfaces, NAT gateways and compute → segment); `USES_ROUTE_TABLE` (segment → table, the associated one else the
main); `ROUTES {destination, state, origin}` (table → gateway, interface or the instance a route names; local routes
are not edges); `PEERS_WITH {state, cidrs, via}` both ways between peered networks; `ATTACHED_TO` (interface → its
instance, balancer by name, function by name, or NAT gateway and endpoint by id); `WEARS` (interface → group);
`ASSIGNED` (public IP → interface, or the NAT gateway that holds it); `GUARDED_BY` (segment → its ACL or the VPC's
default; compute, databases, caches and balancers → their groups; endpoints with groups → their groups); `HAS_RULE`
(filter → rule); `FROM` (rule → the source it admits, or the group it references); `MEMBER_OF` (NAT gateway → the
priced `KnSystem nat:`).

**Verdicts**, on every `AdvisorEndpoint` of kind `port` (groups + public address + subnet ACL; probed ports and the
ports balancers forward to), `listener` (groups + scheme; a balancer with no groups admits what its scheme allows) and
`service_endpoint` (groups + `publicly_accessible`), recomputed by `verdictEdges` from `reachOf` and `naclVerdict`.
Verified against a real account on 2026-10-02: 21 networks, 165 filters, 528 rules, 39 sources, verdicts on 34
endpoints in half a second; a probed box reads port 22 closed with the group that blocks it named, 80 and 443 served
by nginx and reachable from the internet. Note that OS daemons (sshd) are not `AdvisorApp` nodes, so a question about
sshd goes by the port endpoint's `process`, not by `RUNS`.

| edge | to | properties | meaning |
|---|---|---|---|
| `REACHABLE_FROM` | `AdvisorSource` or `AdvisorFilter` | `protocol`, `port`, `via_rule`, `through` (the rule id and the ACL entry id it passed), `note`, `requires_auth: false`, `computed_at` | one per distinct source that can reach the endpoint; a world rule on a box without a public address still points at `internet` with a note that it is reachable from inside the network only, and the endpoint's `exposure` says `network` |
| `ALLOWED_BY` | `AdvisorFilterRule` | `source`, `computed_at` | the rule that lets that source in |
| `BLOCKED_BY` | `AdvisorFilterRule` or `AdvisorFilter` | `source`, `reason`, `computed_at` | what stops a source a group rule would admit: the ACL entry that denies it or drops the replies, the ACL itself for its implicit deny, or every group the box wears when no rule matches the port |

Not judged yet: ElastiCache endpoints (no endpoint node), egress, NACLs in front of balancers and databases (their
subnets are not tied to them), network paths across peerings, the function invoke endpoint behind a balancer, and
target ports of balancers the inventory marks gone.

### AdvisorApp

`{id = name, name, kind: app|infra}`, a catalogue node shared across instances (no `account_id`). `RUNS` edge from the
instance: `user`, `count`, `cpu_pct`, `rss_bytes`, `oldest_seconds`, `command`, `first_seen`, `last_seen`, `probes`,
`gone`. `SERVES` → the port endpoints it answers on.

### AdvisorRecommendation

`{id, fingerprint, title, action (generic verb), native_action (the rule's action_type), tier, status, source, rule,
est_monthly_saving, confidence, decided_by, decided_at, decision_scope, created_at, resource, verdict,
realised_usd_month, realised_ratio, verified_at}`. The verb map: `stop_instance → stop`, `terminate_stopped_instance →
terminate`, `rightsize_instance → rightsize`, `migrate_graviton → migrate_arch`, `release_eip → release_address`,
`delete_snapshot`, `enable_flow_logs → enable_logging`, `aurora_set_storage_iopt → change_storage_tier`,
`delete_everything → delete`, `security_fix`, else by word (`delete`, `stop`, `schedule`) or `other`. Edges: `TARGETS`
→ resource or ref; `DECIDED_AS` → `Concept`; `PROPOSED_IN` → `AdvisorRun`; `FROM_INCIDENT` → `AdvisorIncident`.

### AdvisorRun, AdvisorControl, AdvisorAlert, AdvisorIncident, AdvisorAction, AdvisorPass, AdvisorSecurityScan

As in the model (§4 of `docs/cloud-ontology.md`) with these specifics:

- `AdvisorControl.framework` is read off the id: `aws_thrifty.` → `cost`; `aws_compliance.` → `cis` or
  `foundational_security` by benchmark; else `advisor`. `category` is `security` for compliance controls and for
  advisor controls whose id says so (`sg_`, `exposed`, `public`), else `cost`.
- `AdvisorAlert.cause_actor_kind` maps the cause's `aws` onto `provider`.
- `AdvisorAction` is unchanged in shape; `TARGETS` goes to any resource label, a ref otherwise, with `guessed_type`.
- `AdvisorSecurityScan` and `AdvisorPass` are unchanged.

---

## 1a½. Where the mapping lives (step 6, 2026-10-03)

The AWS adapter (`src/adapters/aws/`) maps its tables onto the labels below (`resources.ts`) and writes its graph
layers in order (apps and ports, status checks, usage, capacity, network, clusters, software); the mirror core
(`src/graph_mirror.ts`) reads the registry (`src/adapters/index.ts`) and writes what the adapter emits. A second
provider implements `src/adapters/types.ts` and appears in the same graph with its own `provider` and `native_*` words:
the Vercel adapter (`src/adapters/vercel/`, 2026-10-03) writes an `AdvisorAccount {provider: vercel, native_type: team}`,
one `AdvisorDeployment {native_type: vercel_project, platform: vercel, framework, runtime, repo, protection_*,
firewall_*}` per project, its URLs as `AdvisorEndpoint {kind: url, exposure: internet, requires_auth, protection}`
with `REACHABLE_FROM internet {requires_auth}` edges, and `AdvisorPackage {ecosystem: runtime}` nodes for the Node
version, through the same mirror core (`mirrorAdapter`).

## 1b. Software and vulnerabilities (step 3, 2026-10-03)

What the software probe (`AwsAdvisorProbe-software`, `src/probes.ts`) found installed, and what the advisories say about
it (`src/software_inventory.ts`, `src/software_vulns.ts`, `src/alas_feed.ts`, `src/graph_software.ts`).

| label | id | properties |
|---|---|---|
| `AdvisorPackage` | `pkg:<ecosystem>:<name>:<version>` | `name`, `version` (the exact installed string, epoch included), `ecosystem` (`deb` \| `rpm` \| `apk` for the package database; `binary` for a version read from the program itself with `--version`; `kernel` for `uname -r`; `os` for `/etc/os-release`), `source_name` (the source package the advisories name: `openssh` for `openssh-server`; null when it is the name itself), `source_kind` (`dpkg` \| `rpm` \| `apk` \| `binary_version` \| `uname` \| `os_release`), `advisory_ecosystem` (the feed's name for the box's distribution: `Ubuntu:24.04:LTS`, `Debian:12`, `Alpine:v3.19`, `Rocky Linux:9`, `AlmaLinux:9`, `Amazon Linux:2023`; null when no feed covers it), `scope` (`service`: a program that may listen, `library`: linked by others, `kernel`, `tool`: nothing listens as it), plus `provider`, `account_id`, `native_type: package`, `updated_at`. One node per version, shared by every box that has it |
| `KnVulnerability` | the advisory id (`UBUNTU-CVE-…`, `USN-…`, `DEBIAN-CVE-…`, `DSA-…`, `ALAS2023-…`, `RLSA-…`, `CVE-…`) | general area, no `account_id`: `source` (`osv` \| `alas`), `aliases`, `cves` (the CVEs it fixes), `summary`, `severity` (`critical` \| `high` \| `medium` \| `low`, null = unrated), `cvss` (the 3.x base score, computed from the vector), `cvss_vector`, `attack_vector` (`network` \| `adjacent` \| `local` \| `physical`), `severity_from` (the CVE whose CVSS was borrowed when the advisory carried none, as Ubuntu's and Debian's do not), `cwe`, `published`, `modified`, `url`, `fetched_at` |

Edges: `INSTALLED_ON {arch, path, first_seen, last_seen, gone}` (package → compute; `path` for binaries); `PROVIDES`
(package → `AdvisorApp`, when the program it ships is seen running: `openssh` → `sshd`, `nginx` → `nginx`, …);
`RUNS_IMAGE {image_id, first_seen, last_seen, gone}` (compute → `AdvisorImage`, the containers' images on a plain
box); `AFFECTS {fixed_in, ecosystem}` (vulnerability → the package versions it matches).

**Verdict `VULNERABLE_TO`** (compute → vulnerability), one per box, advisory and source package (`openssh-server` and
`openssh-client` of one `openssh` fold into one edge, `packages` lists them): `package`, `packages`, `version`,
`fixed_in`, `reachable` (`internet` \| `network` \| `local` \| `none`), `criticality`, `via_endpoint` (the
`AdvisorEndpoint` id the program listens on, when it does), `process`, `port`, `exposure`, `computed_at`. The
criticality is reachability, not severity (severity is on the advisory): `critical` = the program the package
provides listens on a port the internet can reach; `exposed` = the network or another group can reach it;
`mitigated` = it listens but the groups or the ACL block it; `local_only` = loopback only, or the advisory's attack
vector is local/physical; `affected` = installed with no listening program of its own (a library, the kernel, a
tool). A library behind an internet-facing program is `affected`: the graph does not know which program links it.

Sources, never hand-written: OSV (`api.osv.dev` batch queries by source package and exact version, release-qualified
ecosystems) for Ubuntu, Debian, Alpine, Rocky and AlmaLinux; the Amazon Linux `updateinfo.xml.gz` of the core
repository on `cdn.amazonlinux.com` (what `dnf updateinfo` reads) for Amazon Linux 2 and 2023, matched by binary
package with rpm's version order. Ubuntu and Debian publish both per-CVE records and the bundles (USN, DSA, DLA) that
fixed them; when a version has per-CVE records the bundles are left out so one hole is one edge. Advisories and query
results are cached in SQLite (`vulnerabilities`, `package_vulns`, `vuln_queries`, `alas_*`); the daily `VULN_CRON`
re-asks only for versions not asked about and advisories that changed. Not covered (said so on the Security page):
RHEL, CentOS, Fedora, SUSE, Amazon Linux 2 "extras" topics.

## 1c. Playbooks and their sources (step 5, 2026-10-03)

`KnPlaybook` nodes are no longer the hand-written catalogue: `src/playbook_gen.ts` has the agent write each control's
playbook from its sources, and the catalogue in `src/playbooks.ts` is the seed (served until a generated playbook is
published) and the eval set (a generated playbook must cover it).

| label | id | properties |
|---|---|---|
| `KnPlaybook` | `aws:<control_id>` | `control_id`, `title`, `meaning`, `act_when`, `ignore_when`, `steps` (list), `citations` (one source id per step, empty for a seed step), `saving` (the formula in words), `tier` (judged by Jev from the steps, stricter only), `effort` (judged), `references`, `sources` (the source ids it was built from), `source_hashes` (their hashes at generation), `generated_at`, `generated_by` (model and request id, or `hand-written seed`), `stale_after`, `review_status` (`generated` \| `reviewed` \| `disputed` \| `below_reference` \| `low_confidence` \| `unjudged` \| `seed`), `origin` (`generated` \| `seed`), `confidence` (the agent's own, 0..1) |
| `KnSource` | the source id: `mod:<control_id>` for a control's definition and documentation as the installed mod ships them, or the URL of a provider page | `kind` (`benchmark_doc` \| `provider_doc`), `origin` (`mod` \| `web`), `title`, `url`, `hash` (of the text), `fetched_at`, `changed_at` (when the hash last moved: whatever cites it is due again) |

Edges: `HAS_PLAYBOOK` (control → playbook); `CITES` (playbook → the sources it was built from; rebuilt on every sync).

A playbook is due again when a cited source's hash changed, when `stale_after` passed, or when a control flagged in
the latest run has none; the weekly `PLAYBOOK_CRON` writes a few per run under the agent quota, and Findings ›
Playbooks has Generate now. Not yet: `ADDRESSES` → `KnVulnerability`.

## 2. Knowledge (`Kn*`)

### KnArchetype

`{id = name, name, description}`, the ten archetypes from `ROLE_OPTIONS`; the one role node, reached by resources
with `HAS_ROLE` and by systems with `IS_A`. No `account_id`.

### KnSystem

`{id: <native_kind>:<name> (pool:, ec2:, rds:, cache:, eks:, nat:, lambda:), name, kind, native_kind, pool_kind,
archetype, member_count, storage_gb, storage_usd_month, region, monthly_list_usd, gone, lambda_memory_mb, lambda_arm,
invocations_month, gb_seconds_month}`. The id keeps the AWS adapter's prefixes because the log attribution rules key on
them; `kind` is generic: `pool → autoscaled_group`, `instance`, `rds_cluster → database_cluster`, `rds_instance →
database`, `cache_group`, `cache_cluster → cache`, `nat → gateway`, `eks_cluster → cluster`, `lambda → function`.
Edges: `IN_ACCOUNT`, `IS_A`, `RUNS_ON {count, hours_month, list_price, list_usd_month}`, `PART_OF`, `TRANSFERS_TO`,
`SHIPS_LOGS_TO`; `MEMBER_OF` in from resources.

### KnSystemType

`{id: <native_kind>|<sku>|<region> or usage|<rule>, provider, kind: compute|database|cache|transfer|usage,
native_kind: ec2|rds|elasticache|nat|usage, sku, region, engine, list_price, price_unit, unit, source: pricing_api|pricebook,
valid_from, note}`. No `account_id`.

### KnPricingOverlay

`{id: sp:<account> | ri:rds:<id> | ri:cache:<id>, provider, kind: commitment|reservation, native_kind:
savings_plan|reserved_db_instance|reserved_cache_node, covers_kind: compute|database|cache, commitment_usd_month,
covered_od_usd_month, discount_rate, month, sku, count, engine, offering, start, end}`. `COVERS` → `KnSystemType`.

### KnDestination

`{id: internet | regional, name, kind}`; `internet` also carries `AdvisorSource`. `TRANSFERS_TO {mechanism: nat|cross-az,
gb_day, gb_day_median, p95_gb_hour, price_per_gb, usd_month, window_days, source}` in from NAT systems and the account.

### KnLogGroup

Unchanged from the model: `name`, `region`, `retention_days`, `stored_gb`, `ingest_gb_day`, `ingest_usd_month`,
`storage_usd_month`, `owner`, `attributed_by`, `candidates`, `tags`, `jev_choice`, `jev_confidence`.

### KnPlaybook

`{id: aws:<control id>, provider, control_id, title, meaning, act_when, ignore_when, steps, saving, tier, effort,
references, sources, generated_by: "hand-written catalogue (src/playbooks.ts)", review_status: reviewed}`. Still the
static catalogue; the node says so in `generated_by`. `HAS_PLAYBOOK` ← `AdvisorControl`. No `account_id`.

---

## 3. Concepts

Unchanged: repo2graph's `Concept` nodes under `aws/cost-advisor`, three parents (decisions, generic knowledge,
operational patterns), reached from recommendations with `DECIDED_AS`. See `docs/cloud-ontology.md` §3.

---

## 4. Not in the graph yet

- Reachability for ElastiCache endpoints, egress verdicts, ACLs in front of balancers and databases, paths across
  peerings and transit gateways (see §1a).
- Software gaps (§1b): packages inside container images (`CONTAINS`) and in cluster workloads (`VULNERABLE_TO` stops
  at the node); language ecosystems (npm, pypi, go lockfiles) and frameworks; advisory feeds for RHEL, CentOS, Fedora,
  SUSE and the Amazon Linux 2 extras topics; `blocked_by` on the verdict edge (today the endpoint's `BLOCKED_BY` says it).
- Workloads inside EKS: collected when the cluster lets the advisor's identity read (Inventory › Clusters shows the
  status and the commands); a cluster that does not keeps its `AdvisorCluster` node with `access_status` and no workloads.
  ECS services come from the AWS API. Reachability inside a cluster stops at the balancer in front: Service and Ingress
  endpoints inherit the listener's verdict, NetworkPolicies are filters but are not yet evaluated into verdicts.
- `AdvisorPolicy` (an identity's `policies` are names on the node); `AdvisorSecret` beyond KMS keys (Secrets Manager,
  SSM parameters); messaging beyond SNS (SQS, Kinesis); IAM roles as identities. Web ACL rules stay lines on the
  filter, not `AdvisorFilterRule` nodes (they match requests, not ports and sources).
- Telemetry edges for `logs`, `audit` and `bill` per resource (the nodes exist).
- Upgrading an `AdvisorResourceRef` in place when its resource gets a node.
- Findings as nodes (by design: the latest run's alarms are `FLAGGED` edges; the history stays in SQLite).

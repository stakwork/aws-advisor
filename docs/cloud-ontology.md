# Cloud Advisor ontology (v2, provider-neutral)

Status: design, 2026-10-02. This is the complete target model the graph migrates to, self-contained. `docs/ontology.md` describes what is in
the graph today (AWS-shaped, v1); this file describes what it becomes and how the AWS data maps onto it. Nothing in
v1 is lost: every v1 node and property has a place here, either as a generic property or as a capability block.

## Why

The advisor becomes a Cloud Advisor. The graph is the record every agent, page and tool reads, so it has to describe
AWS, GCP, Azure, Vercel or Cloudflare in the same words. The questions an agent asks do not depend on the provider:

- what is running, and which version of what;
- what is listening, and who can reach it, through what;
- what it costs, at list and after discounts;
- what we decided, did and saw happen.

The model is therefore built around those questions. Provider objects (a security group, a NACL, a Vercel firewall
rule) sit underneath generic ones (a filter, a filter rule), and the verdicts an agent needs (reachable from the
internet, blocked by this rule) are materialised edges that mean the same thing everywhere.

## Principles

1. **Generic labels, provider as a property.** Every node carries `provider`, `native_type` and `native_id`. There
   are no provider labels: `provider` and `native_type` are indexed and do the same job without multiplying labels.
2. **The `Advisor` prefix stays.** It namespaces us from stakgraph and repo2graph in the shared Neo4j; it is about
   the advisor, not AWS.
3. **Verdict edges are the contract.** `REACHABLE_FROM`, `ALLOWED_BY`, `BLOCKED_BY`, `VULNERABLE_TO` are computed
   per provider and read generically. An agent never re-implements NACL precedence or Vercel protection rules.
4. **Capabilities, not provider objects, carry the operational data.** Probes, agent status, health checks, usage
   profiles, capacity patterns and executor actions attach to the generic node as property blocks that declare their
   source. What covers a node is an `OBSERVED_BY` edge to an `AdvisorTelemetry` node, so a new source is a new node,
   not a new property: an RDS instance has metrics but no probe, so it gets a usage profile and no process list.
5. **One normalised model, one adapter per provider.** An adapter collects and maps into this model; rules, the
   executor and the mirror read the model. Today the SQLite tables are AWS-shaped, so the first normalisation
   boundary is the mirror; the tables migrate behind it.
6. **Everything the advisor plans, does or decides is in the graph, always.** Proposals included, so a later agent
   sees what was planned and why it was left alone.

## Conventions

Every node carries these base properties (not repeated below):

| property | meaning |
|---|---|
| `id` | the graph key. The provider's native id when it is globally unique (AWS ids and ARNs, Vercel `prj_…`, GCP resource names); otherwise `<provider>:<account>:<native_type>:<native_id>` |
| `provider` | `aws` \| `gcp` \| `azure` \| `vercel` \| `cloudflare` \| … |
| `account_id` | the `AdvisorAccount.id` the node belongs to |
| `native_type` | the provider's object type: `ec2_instance`, `rds_instance`, `vercel_project`, `gce_instance`, … |
| `native_id` | the provider's own identifier (same as `id` when that is native) |
| `name` | display name (Name tag, project name, resource name) |
| `region` | provider region (`us-east-1`, `iad1`, `europe-west1`); null for global objects |
| `tags` | the provider's labels or tags as a JSON string (Neo4j cannot hold maps); `tags_kv` the same as a list of `key=value` for `IN` queries |
| `gone` | true when the provider no longer lists it; the node stays so history remains walkable |
| `first_seen` / `last_seen` | when the advisor first and last saw it |
| `updated_at` | last mirror write |
| `source` | how the advisor learned it: `api` \| `probe` \| `derived` \| `bill` |

Property blocks marked **capability** below exist only where that capability runs; each says what produces it. Values
are UTC ISO timestamps, USD, and 0..1 for ratios and confidences. Enumerations are closed lists; a provider adapter
maps its values onto them and keeps the raw value in a `native_*` property when it matters.

Every label has a unique constraint on `id`; `provider`, `account_id` and `native_type` are indexed on `AdvisorResource`.

### `Advisor*` and `Kn*`: two prefixes, two kinds of node

Both prefixes namespace the advisor's nodes from stakgraph's and repo2graph's in the shared Neo4j. The difference
between them is how a node comes to exist and how long it lives:

| | `Advisor*` | `Kn*` |
|---|---|---|
| what it is | a record of something that exists: a resource the provider lists, an endpoint a probe saw, a recommendation, an action, an alert | knowledge about things: what a type costs, what an archetype means, which CVE affects which version, and the account drawn as a schematic of systems |
| how it is written | mirrored one to one from the advisor's tables or the provider's API, by id, incrementally (a run, a pass, a probe each write their part) | rebuilt wholesale on every sync from the `Advisor*` nodes and the price and vulnerability catalogues; nothing is written to it directly |
| scope | per account: carries `account_id`, removed by a wipe of that account | two areas: the **general area** (`KnSystemType`, `KnArchetype`, `KnVulnerability`, `KnPlaybook`, `KnSource`, `KnDestination`) is true in any account, shared, never wiped; **our side** (`KnSystem`, `KnPricingOverlay`, `KnLogGroup`) is per account and rebuilt |
| who reads it | pages and agents asking "what is there and what happened to it" | pages and agents asking "what does it cost, what is it for, what is it exposed to as a whole" |
| examples | `AdvisorCompute i-0abc`, `AdvisorEndpoint i-0abc:tcp:22`, `AdvisorAction #412` | `KnSystemType aws|compute|m6i.large|us-east-1`, `KnSystem autoscaled_group:web`, `KnVulnerability CVE-2025-29927` |

The rule of thumb: if deleting it would lose a fact nobody else has, it is `Advisor*`; if it can be recomputed from
the `Advisor*` nodes and a catalogue, it is `Kn*`. Verdict edges (`REACHABLE_FROM`, `VULNERABLE_TO`) are derived
like `Kn*` but hang off `Advisor*` nodes, because they are facts about one endpoint or one resource.

---

## 1. Accounts and resources

### AdvisorAccount

The billing and permission boundary the advisor was pointed at.

| property | meaning |
|---|---|
| `provider` | `aws` \| `gcp` \| `azure` \| `vercel` \| `cloudflare` |
| `native_type` | the provider's own word for the boundary: `account`, `project`, `subscription`, `team`, `organization`, `management_account` |
| `kind` | the only generic distinction: `account` (a leaf that bills and holds resources) \| `organization` (a parent of accounts; holds no resources of its own) |
| `parent_id` | the organisation or management account it belongs to, when known |
| `role` | `management` (a parent other accounts are members of; on AWS it holds resources of its own too) \| `member` \| `standalone` |
| `name` / `enabled` / `access` / `actuator` | the name Settings gave it, whether it is collected, how the advisor reaches it in words (never a secret), whether the advisor may act there |
| `last_test_ok` / `last_test_at` | the last credential test |
| `plan` | the plan or support tier: `hobby` \| `pro` \| `enterprise` for SaaS providers, the support plan for AWS |
| `members` | number of human identities with access |

Edges out: `PART_OF` → the parent `AdvisorAccount` (a member of an AWS organisation to its management account; a
provider without a hierarchy has none), `TRANSFERS_TO` (§5), `SHIPS_LOGS_TO` (§5). Edges in: `IN_ACCOUNT` from every
resource, run, pass and scan, each attached to the account it was collected from: a member's instances hang off the
member, not off the parent, so "what runs in account X" and "what runs in the organisation" are one hop apart.

### AdvisorTelemetry

A source of observation, one node per source per account. Makes "what can the advisor see of this" a walk, not a
flag, and gives the telemetry itself a place for its state and cost.

| property | meaning |
|---|---|
| `kind` | `api` (describe calls: configuration, state, versions) \| `metrics` (time series) \| `probe` (the advisor's agent on the host) \| `logs` \| `audit` (the audit trail) \| `bill` |
| `native` | what it is: `cloudwatch`, `ssm_probe`, `cloudtrail`, `cost_explorer`, `vercel_analytics`, `cloud_monitoring`, `vpc_flow_logs` |
| `enabled` | the source is on |
| `last_at` | when it last delivered anything |
| `usd_month` | what the telemetry itself costs (CloudWatch metrics and logs are a bill line; a log drain is a plan feature) |

Edges: `IN_ACCOUNT`; `OBSERVED_BY` ← resources.

`(:AdvisorResource)-[:OBSERVED_BY]->(:AdvisorTelemetry)`

| edge property | meaning |
|---|---|
| `since` | when this source first covered the resource |
| `last_at` | when it last reported on it |
| `status` | `ok` \| `stale` \| `offline` (the probe's agent lost connection) |
| `detail` | the source's own word (`Online`, `ConnectionLost`, the metric namespace) |

No edge means not observed. Whether that is a finding is a rule's call: a compute node without a `probe` edge is one,
a database without one is normal. An RDS instance has `api`, `metrics`, `bill`; an EC2 box with SSM has `api`,
`metrics`, `probe`, `audit`, `bill`; a Vercel deployment has `api`, `metrics`, `logs`. Log coverage is also visible
as `SHIPS_LOGS_TO` → `KnLogGroup`.

### AdvisorResource (base label)

Every resource node carries `AdvisorResource` **and** one specific label below. Shared properties beyond the base:

| property | meaning |
|---|---|
| `state` | generic lifecycle: `running` \| `stopped` \| `pending` \| `terminated` \| `available` \| `degraded` \| `unknown`; `native_state` the provider's word |
| `zone` | availability zone or equivalent |
| `created_at` | when the provider created it |
| `monthly_usd` | estimated monthly cost at list for this resource alone |
| `role` | the workload archetype: a judged property (§5b, purpose `resource_role`), one of the `KnArchetype` names (§5) |
| `role_confidence` | the classifier's probability for that archetype over the closed list, 0..1 (§5b) |
| `protected_prob` | judged (§5b): the probability that the name, tags or description say the resource is deliberately kept and must not be stopped or deleted; 0.7 and above makes recommendations report-only |
| `owner` | the team or person responsible, from tags or the provider's project membership |

What the advisor can see of a resource is not a property but an edge: `OBSERVED_BY` → `AdvisorTelemetry` (below), one
per source that actually covers it. A capability block exists on a node only when the telemetry it names covers the
node; an absent block is explained by the missing edge, and `NOT (r)-[:OBSERVED_BY]->(:AdvisorTelemetry {kind: 'probe'})`
finds every box the advisor cannot look inside.

Edges every resource may have: `IN_ACCOUNT`, `MEMBER_OF` → `KnSystem` (§5), `HAS_ROLE` → `KnArchetype` (§5), `EXPOSES` →
`AdvisorEndpoint` (§3), `HAS_INTERFACE` ← `AdvisorInterface` (via `ATTACHED_TO`), `GUARDED_BY` → `AdvisorFilter`
(when a filter applies to the resource directly rather than to an interface), `USES_SECRET` → `AdvisorSecret`,
`RUNS_AS` → `AdvisorIdentity`, `BUILT_FROM` → `AdvisorImage`, `STORES_ON` → `AdvisorStorage` (volumes). Edges in:
`TARGETS` (recommendations, actions), `ABOUT` (alerts), `FLAGGED` and `SECURITY_FLAGGED` (controls).

### AdvisorCompute

A machine the customer's software runs on: an instance or VM, whether standalone or a node in a pool.

| property | meaning |
|---|---|
| `type` | the SKU (`m6i.large`, `e2-standard-2`) |
| `vcpu` / `memory_mb` | the SKU's size, from the price catalog |
| `arch` | `x86_64` \| `arm64` |
| `platform` | `linux` \| `windows`; `os` the distribution and version when known (probe) |
| `image_id` | the machine image it booted from (→ `AdvisorImage` through `BUILT_FROM`) |
| `private_ips` / `public_ip` / `ipv6` | addresses; also on its interfaces, repeated here for one-hop queries |
| `hostname` | public DNS name or the provider's hostname |
| `lifecycle` | `on_demand` \| `spot` \| `reserved` |
| `pool` | the autoscaling pool name when it is a member (→ `IN_POOL`) |
| `cpu_30d` | 30-day average CPU percent from the provider's metrics |
| `launch_time` | when it last started |

**Capability: agent on the box** (needs `OBSERVED_BY` → telemetry `probe`; AWS SSM today):

The agent's state lives on the `OBSERVED_BY` edge to the `probe` telemetry (`status`, `detail`, `last_at`); the
node keeps only:

| property | meaning |
|---|---|
| `agent_kind` | `ssm` \| `os_login` \| `azure_vm_agent` \| … |

**Capability: health checks** (needs telemetry `api`; AWS status checks, GCP and Azure have equivalents):

| property | meaning |
|---|---|
| `health` | generic summary: `ok` \| `impaired` \| `initializing` \| `unknown` |
| `health_host` / `health_instance` / `health_storage` | the provider's three checks, in its words |
| `scheduled_events` | count of provider-scheduled maintenance, retirement or reboot events |
| `health_checked_at` | when read |

**Capability: probe** (needs telemetry `probe`; the advisor's own agent run through the agent on the box; produces `RUNS` edges to `AdvisorApp`,
`EXPOSES` edges to `AdvisorEndpoint`, `INSTALLED_ON` edges from `AdvisorPackage`, and these summaries):

| property | meaning |
|---|---|
| `probe_at` | last successful probe |
| `probe_mem_pct` / `probe_disk_pct` / `probe_load` | the latest readings |
| `probe_kernel` | kernel version |
| `probe_containers` | running containers count |
| `probe_reboot_at` | last boot |

**Capability: usage profile** (needs telemetry `metrics`, enriched by `probe` when present; CPU, network, connections, logins,
container CPU on a box, connections and IOPS on a database, requests on a deployment). Generic block, the same on
`AdvisorDatabase`, `AdvisorCache`, `AdvisorNodePool` and `AdvisorDeployment`:

| property | meaning |
|---|---|
| `usage_quiet_hours_week` | how many of the 168 hours of the week are quiet in every week of the window |
| `usage_confidence` | how sure the profile is |
| `usage_schedule` | the suggested keep-up schedule (UTC) |
| `usage_off_hours_week` | hours per week the schedule would have it off |
| `usage_est_usd_month` | what that would save |
| `usage_quiet_windows` | the quiet windows as labels |
| `usage_summary` / `usage_computed_at` | description and time |
| `usage_review_verdict` | judged (§5b, purpose `usage_review`): `confirm` \| `adjust` \| `keep_running` |
| `usage_review_schedule` / `usage_review_confidence` / `usage_review_reason` / `usage_reviewed_at` | the review |

**Capability: wake on traffic** (needs telemetry `api` and DNS control; AWS today, any provider with DNS control can have it):

| property | meaning |
|---|---|
| `wake_enabled` | true when the box may sleep and the advisor's doorman wakes it on the first real request: while it sleeps, its hostnames resolve to the doorman, which holds the connection, starts the box, waits for it to answer and then hands traffic back |
| `wake_domains` | the hostnames the doorman answers for while the box sleeps (the DNS records it flips) |
| `wake_profile` | the whole profile as JSON: `front_door` (`dns`, the record is repointed, or `eip`, the address is moved), the `ports` to wake on, the `ready` check that says the box is up, `sleep_mode` (`auto` \| `hibernate` \| `stop`), `min_awake_minutes` before it may sleep again, `hold_seconds` the doorman keeps a request waiting, `wake_with` (which signals count as real use), `after_wake_command` and `before_park_command`, the `filter` (ignored paths and user agents such as crawlers and scanners, `require_host_match`, `max_wakes_per_day`), the `page` shown while waking, `notify` |
| `wake_updated_at` / `wake_updated_by` | when and who last saved the profile |

**Capability: tenant costing** (needs telemetry `bill`, and `probe` or `metrics` for last use; the swarm cost block, generic name `tenant`):

| property | meaning |
|---|---|
| `tenant` | true when the resource is one customer's dedicated environment |
| `cost_month_usd`, `cost_compute_usd`, `cost_storage_usd`, `cost_snapshot_usd`, `cost_ip_usd`, `cost_month`, `cost_updated_at` | the month-to-date split |
| `last_use_at` | the last day the resource showed real use: logins, client connections, container activity or use signals in the probe's daily roll-ups (or in the provider's metrics when there is no probe) |
| `idle_days` | days since `last_use_at`; null when use was never seen |
| `parked` | true when the executor has stopped the resource to save its cost (an applied or verified park action) and it is waiting to be woken or released |
| `nudge` | true when the customer should be asked whether they still need it: running, idle for at least the parking threshold (Settings › Auto-actions, in days), not parked, and no parking proposal already open for it |

### AdvisorFunction

Serverless code: a Lambda, a Vercel serverless or edge function, a Cloud Function.

| property | meaning |
|---|---|
| `runtime` | `nodejs20.x`, `python3.12`, `edge`, … |
| `runtime_version` | the version alone, for vulnerability matching |
| `memory_mb` / `timeout_s` | configuration |
| `arch` | `x86_64` \| `arm64` |
| `kind` | `serverless` \| `edge` \| `container` |
| `invocations_30d` / `errors_30d` / `duration_avg_ms` | 30-day metrics |
| `invocations_month` / `gb_seconds_month` | scaled to a month, for pricing |
| `url` | its public URL when it has one (function URL, Vercel route) |
| `triggers` | what invokes it: `http`, `queue`, `schedule`, `event`, `cron` (list) |

Edges: `EXPOSES` → `AdvisorEndpoint` (its URL); `PART_OF` → `AdvisorDeployment` (a Vercel function belongs to a
deployment); `USES_SECRET`; `RUNS_AS`.

### AdvisorDeployment

**One unit of deployed software**, not the platform that hosts it: a Kubernetes Deployment, StatefulSet or DaemonSet,
an ECS service, a Beanstalk environment, a Cloud Run service, an App Service, a Vercel project's deployment. A cluster
hosting forty workloads has forty of these. A deployment runs one workload, so its framework and runtime are
meaningful; the containers it runs may be several (sidecars), each reached through `BUILT_FROM` → `AdvisorImage`.

| property | meaning |
|---|---|
| `workload_kind` | `deployment` \| `statefulset` \| `daemonset` \| `job` \| `cronjob` (Kubernetes) \| `service` \| `task` (ECS) \| `environment` (Beanstalk) \| `app` (Cloud Run, App Service) \| `project_deployment` (Vercel, Pages) |
| `namespace` | (Kubernetes) the namespace |
| `environment` | `production` \| `preview` \| `staging` \| `development`, from labels, tags or the provider |
| `framework` / `framework_version` | the primary framework when one can be named (`nextjs 14.2.3`, `rails 7.1`); null for a workload with none (a database, a proxy). Also an `AdvisorPackage` with ecosystem `framework` |
| `runtime` / `runtime_version` | `nodejs 20.11`, `python 3.12`, `jvm 21`; null when it is not a language runtime |
| `containers` | how many containers the unit runs |
| `url` | the primary URL when it has one |
| `health` | `ok` \| `degraded` \| `severe` \| `unknown`, from the platform's own health (Beanstalk health, pod readiness, Cloud Run conditions) |
| `replicas_desired` / `replicas_ready` | wanted and ready copies |
| `min` / `max` | the scaling band when it autoscales |
| `revision` | version label, commit sha, image tag or deployment id |
| `deployed_at` / `deployed_by` | when and by whom |
| `protection` | summary of access protection in front of it: `none` \| `password` \| `sso` \| `ip_allowlist` \| `vercel_auth` \| `waf` (details are `AdvisorFilter` nodes) |

Capability blocks: **usage profile** (above) and **capacity pattern** (below, when the advisor sets its minimum, as
for Beanstalk).

Edges: `RUNS_IN` → `AdvisorCluster` (Kubernetes, ECS) or `RUNS_ON_POOL` → `AdvisorNodePool` (Beanstalk, a workload
pinned to a node group); `BUILT_FROM` → `AdvisorImage` (one per container); `EXPOSES` → endpoints (a Service, an
Ingress path, a URL); `GUARDED_BY` → filters; `BACKED_BY` → `AdvisorLoadBalancer`; `PART_OF` ← `AdvisorFunction`
(a Vercel function belongs to a deployment); `PART_OF` ← `AdvisorApp` (a container the probe saw on a node, when its
labels name the workload); `POINTS_TO` ← DNS records; `INSTALLED_ON` ← `AdvisorPackage` (declared packages: a
lockfile, deployment metadata; the ones inside the images hang off the images).

### AdvisorCluster

The platform that hosts deployments: EKS, ECS, GKE, AKS, a self-run Kubernetes. Carries no framework; the workloads
are `AdvisorDeployment` nodes with `RUNS_IN` edges to it.

| property | meaning |
|---|---|
| `kind` | `kubernetes` \| `ecs` \| `nomad` |
| `version` | control plane version (vulnerability-relevant: a Kubernetes CVE matches here) |
| `endpoint_public` | whether the API endpoint is reachable from outside the network (the real answer is the API endpoint's `REACHABLE_FROM`) |
| `nodes` | node count across its pools |
| `workloads` | how many deployments it hosts |
| `namespaces` | (Kubernetes) the namespaces |

Edges: `PART_OF` ← `AdvisorNodePool`; `RUNS_IN` ← `AdvisorDeployment`; `EXPOSES` → the API endpoint; `RUNS_AS` →
`AdvisorIdentity` (the cluster role).

### AdvisorNodePool

An autoscaled group of compute: ASG, Karpenter NodePool, EKS or GKE node group, Azure VMSS. Keyed by `id` in v2
(`<provider>:<account>:pool:<name>`), `name` kept.

| property | meaning |
|---|---|
| `kind` | `asg` \| `karpenter` \| `node_group` \| `batch` \| `vmss` \| `mig` |
| `min` / `max` / `desired` | the configured band and current size |
| `instance_types` | the SKUs it launches |
| `platform` | the deployment it backs when any (`beanstalk`, `eks`) |

Capability blocks: **usage profile**; **capacity pattern** (the advisor's learned week, generic for any autoscaled
group whose minimum the advisor sets):

| property | meaning |
|---|---|
| `capacity_floor` / `capacity_ceiling` | the band a person set |
| `capacity_learned_min` | 168 integers, the minimum per hour of the week (index 0 = Sunday 00:00 UTC) |
| `capacity_wanted` / `capacity_trigger` / `capacity_binding` | what the signals needed, what the trigger ran, which signal decided |
| `capacity_signals` | one line on the signals the week was learned from and their coverage: CPU, memory, requests, network in and out, disk, latency and 5xx, and which came from the provider's metrics, from probes or from an agent |
| `capacity_days` / `capacity_weeks` | the history window in days (28) and how many distinct weeks of it had samples |
| `capacity_coverage` | the share of the 168 hours of the week that had at least one sample, 0..1 |
| `capacity_confident` | true when at least 2 weeks were seen and coverage is 0.8 or more: only then may the pattern move the group's minimum |
| `capacity_pressure_events` | how many hours in the window the group spent pinned at its ceiling under load (each is an `AdvisorPressureEvent`) |
| `capacity_summary` | the learned week condensed: the distinct capacity levels and the hours of the week at each |
| `capacity_computed_at` / `capacity_updated_at` | when the pattern was learned and when it was written to the graph |

Edges: `IN_POOL` ← members; `PART_OF` → `AdvisorCluster`; `PRESSURED_AT` → `AdvisorPressureEvent`.

### AdvisorDatabase

A managed or self-run database: RDS, Aurora, Cloud SQL, Azure SQL, Vercel Postgres, Neon, a Postgres on a box when
the probe sees it (then it is an `AdvisorApp`, not this). A serverless key-value store is one too: a DynamoDB table is
`native_type: dynamodb_table` with `engine: dynamodb`, `kind: key_value`, `serverless: true`, its capacity mode in
`type` (`on-demand` or `provisioned N RCU / M WCU`) and `billing_mode`, the consumed units in `reads_30d` /
`writes_30d`, and point-in-time recovery read as `backup_retention_days` 35 or 0.

| property | meaning |
|---|---|
| `engine` / `engine_version` | `postgres 15.4`, `mysql 8.0.35`, `aurora-postgresql` |
| `type` | the instance class or tier |
| `cluster` | the cluster it belongs to |
| `cluster_role` | `writer` \| `reader` \| `standalone` |
| `storage_gb` / `storage_type` / `iops` | storage configuration |
| `multi_az` / `replicas` | availability |
| `publicly_accessible` | the provider flag (the real answer is the endpoint's `REACHABLE_FROM`) |
| `encrypted` | storage encryption on |
| `backup_retention_days` | how many days of automated backups are kept; 0 means backups are off, which is a finding on a production database |
| `cpu_30d` / `connections_30d` / `iops_30d` / `memory_free_30d` | 30-day metrics (needs telemetry `metrics`); the usage profile block applies here too |
| `endpoint_host` / `port` | the connection endpoint (also an `AdvisorEndpoint`) |

### AdvisorCache

ElastiCache, Memorystore, Azure Cache, Vercel KV, Upstash.

| property | meaning |
|---|---|
| `engine` / `engine_version` | `redis 7.1`, `valkey 8`, `memcached 1.6` |
| `type` | node type |
| `nodes` | node count |
| `group` | replication group |
| `memory_30d` / `cpu_30d` / `connections_30d` | 30-day metrics (needs telemetry `metrics`); the usage profile block applies here too |
| `endpoint_host` / `port` | the hostname clients connect to and the port it listens on (also an `AdvisorEndpoint`, where reachability is answered) |

### AdvisorMessaging

Queues, topics and streams: SQS, SNS, Kinesis, Pub/Sub, Service Bus, Vercel Queues.

| property | meaning |
|---|---|
| `kind` | `queue` \| `topic` \| `stream` |
| `messages_30d` | throughput |
| `dlq` | has a dead-letter queue |
| `encrypted` | messages are encrypted at rest with a provider or customer key |
| `subscriptions` / `pending` / `protocols` | (topics) confirmed and pending subscribers, counted by protocol (`lambda 2`, `email 1`); people's addresses are never stored |
| `fifo` | ordered, exactly-once delivery |

Edges: `DELIVERS_TO {protocol}` → the functions, queues and streams a topic delivers to (a ref when not inventoried);
`ENCRYPTS` ← the key. An SNS topic is `native_type: sns_topic`, priced on publishes.

### AdvisorStorage

Buckets, file systems, block volumes and snapshots.

| property | meaning |
|---|---|
| `kind` | `object` (S3, GCS, Blob) \| `file` (EFS, Filestore) \| `block` (EBS, PD) \| `snapshot` \| `backup` |
| `size_gb` / `objects` | size and object count |
| `class` | storage class or volume type (`STANDARD`, `gp3`, `io2`) |
| `iops` / `throughput_mibps` | (block) provisioned performance |
| `iops_30d` | (block) observed |
| `encrypted` | the data is encrypted at rest; for block volumes whether the volume is encrypted, for buckets whether default encryption is set |
| `versioning` / `lifecycle_rules` | (object) |
| `public` | (object) public access possible, from the provider's policy evaluation |
| `attached_to` | (block) the compute it is attached to (→ `STORES_ON` from the compute) |
| `device` | (block) device name |
| `parent` | (snapshot) the volume it was taken from |

A file system (EFS, Filestore, Azure Files) adds `standard_gb` / `ia_gb` / `archive_gb` (size by storage class),
`class: regional | one_zone`, `performance_mode`, `throughput_mode`, `provisioned_mibps`, `mount_targets`,
`automatic_backups`; edges `IN_NETWORK`, `IN_SEGMENT` (one per mount target's subnet) and `GUARDED_BY` the filters on
its mount targets, `ENCRYPTS` ← its key.

A backup store (`kind: backup`: an AWS Backup vault, a Recovery Services vault, a GCP backup vault) adds
`recovery_points`, `size_gb` with `warm_gb` / `cold_gb`, `by_type` (`RDS 12`), `oldest_at` / `newest_at`, `locked`,
`min_retention_days` / `max_retention_days`, `protected_resources`; edges `BACKED_UP_TO {last_backup_at,
resource_type}` ← every resource whose latest backup landed in it, `ENCRYPTS` ← its key, `STORES_IN` ← the plans that
target it.

### AdvisorBackupPlan

A schedule and retention policy that decides what is backed up and for how long: AWS Backup plans, Azure Backup
policies, GCP backup plans. Not a store (that is `AdvisorStorage {kind: backup}`) and not a resource that costs anything.

| property | meaning |
|---|---|
| `rules` / `schedules` | how many rules, each as one line: name, schedule expression, retention, cold storage, copies |
| `retention_days` / `keeps_forever` | the longest retention; a rule without one keeps backups forever (a cost finding) |
| `cold_after_days` / `copies` | lifecycle to cold storage; copies to another vault or region |
| `vaults` | the stores its rules target |
| `selections` / `selects_all` / `selected_by_arn` | what it covers in words (by ARN, by tag, every supported resource) |
| `last_run_at` | the last time it ran |

Edges: `STORES_IN` → `AdvisorStorage {kind: backup}`; `PROTECTS` → the resources a selection names by ARN. Tag and
wildcard selections stay words: what they match is decided by the provider at backup time, and the store's
`BACKED_UP_TO` edges say what actually got backed up.

### AdvisorLoadBalancer

Anything that terminates client connections and forwards them: ALB, NLB, GWLB, CLB, GCP load balancers, Azure LB
and Front Door, Cloudflare and Vercel's edge (as one implicit `edge` balancer per account).

| property | meaning |
|---|---|
| `kind` | `application` \| `network` \| `gateway` \| `classic` \| `edge` |
| `scheme` | `public` \| `internal` |
| `dns_name` | the hostname the provider gives the balancer, which DNS records alias to |
| `targets` / `healthy` | registered targets and healthy ones |
| `requests_30d` / `gb_30d` | 30-day traffic |
| `platform_owner` | the deployment or ASG that owns it (`beanstalk_env`) |

Edges: `EXPOSES` → listener endpoints; those listeners `FORWARD_TO` target endpoints (§3); `GUARDED_BY` → filters.

### AdvisorDomain / AdvisorDnsZone / AdvisorDnsRecord

Names and where they point. Route 53, Cloud DNS, Azure DNS, Vercel domains, Cloudflare zones.

`AdvisorDomain`: a registered or attached domain.

| property | meaning |
|---|---|
| `fqdn` | the fully qualified domain name, lower-case, without trailing dot |
| `registrar` / `expires_at` / `auto_renew` | registration |
| `verified` | (SaaS) ownership verified |

`AdvisorDnsZone`: `name`, `private` (split-horizon), `records`, `dnssec`.

`AdvisorDnsRecord`:

| property | meaning |
|---|---|
| `fqdn` / `type` / `ttl` | the record |
| `values` | targets (list) |
| `alias` | provider alias record |
| `routing` | `simple` \| `weighted` \| `latency` \| `failover` \| `geo` |
| `link_state` | what the advisor resolved it to: `resource` \| `external` \| `dangling` \| `unknown` |

Edges: `IN_ZONE` (record → zone); `POINTS_TO` (record → `AdvisorEndpoint` \| `AdvisorLoadBalancer` \| `AdvisorCompute`
\| `AdvisorDeployment` \| `AdvisorStorage` \| `AdvisorPublicIp`); `DNS_OF` (domain → zone); `SERVES` (domain →
deployment, Vercel). A `dangling` record is a finding in itself (subdomain takeover).

### AdvisorCertificate

| property | meaning |
|---|---|
| `domains` | the names it covers |
| `issuer` | `acm` \| `lets_encrypt` \| `digicert` \| … |
| `not_after` / `not_before` | validity |
| `status` | `issued` \| `expired` \| `pending` \| `revoked` |
| `in_use` | something references it |
| `key_algorithm` | `RSA-2048`, `EC-P256` |

Also `origin` (`issued` \| `imported` \| `private`), `days_left`, `used_by` (how many things use it), `wildcard`,
`renewal_eligible`. Edges: `SECURES` → `AdvisorEndpoint` (a TLS listener) or, when the provider names only the
resource that terminates TLS (ACM's `InUseBy`: a balancer, a distribution, an API), → that resource. An unused
certificate is `in_use: false`; an expiring one is `days_left` ≤ 30.

### AdvisorAnalytics

A query engine or warehouse that runs analysts' queries over data it does not own: Athena workgroups, BigQuery
reservations and datasets, Synapse serverless pools, Snowflake warehouses.

| property | meaning |
|---|---|
| `kind` | `query_engine` (query in place) \| `warehouse` (owns its storage) |
| `engine` / `engine_version` | `athena 3`, `bigquery`, `synapse` |
| `scanned_gb_30d` / `metrics_published` | bytes scanned over 30 days, when the engine publishes them (needs telemetry `metrics`) |
| `scan_limit_gb` | the per-query cutoff; none means a single query can scan everything |
| `enforce_config` | the group's settings override the client's |
| `output_location` / `output_encrypted` | where results land and whether they are encrypted |

Edges: `WRITES_TO` → the bucket results go to. Athena is `native_type: athena_workgroup`, priced by bytes scanned.

### AdvisorStack

A unit of infrastructure as code: a CloudFormation stack, a Terraform workspace, a Pulumi stack, an ARM or Bicep
deployment, a Deployment Manager deployment. What created a resource, and what drifts from its template.

| property | meaning |
|---|---|
| `tool` | `cloudformation` \| `terraform` \| `pulumi` \| `arm` \| `deployment_manager` |
| `resources` / `mapped_resources` / `resource_types` | how many resources it holds, how many the graph has a node for, the counts by type |
| `failed_resources` | resources in a failed state |
| `drift` | `in_sync` \| `drifted` \| `unknown` (never checked) |
| `termination_protection` / `nested` / `root_id` | deletion protection; a stack inside another |
| `status_reason` / `updated_at` | why it is in its state; the last update |

The generic `state` folds the tool's status: `*_COMPLETE` is `available` (an update rolled back is still a working
stack), `*_IN_PROGRESS` `pending`, `*_FAILED` and a rolled-back create `degraded`. Edges: `MANAGES {logical_id,
resource_type}` → the resources and network nodes it created (never a ref: what the graph has no node for stays a
count); `PART_OF` → the parent stack.

### AdvisorDetector / AdvisorThreatFinding

A provider's managed threat detection (GuardDuty, Security Command Center, Defender for Cloud) and what it found.
Distinct from `AdvisorControl` (a compliance check the advisor runs): a finding here is the provider's own judgement
of activity it observed.

`AdvisorDetector` (a resource, one per region or project where it runs):

| property | meaning |
|---|---|
| `kind` / `engine` | `threat_detection`; `guardduty`, `scc`, `defender` |
| `enabled` | it is running |
| `protections_on` / `protections_off` | the data sources it analyses (S3 data events, EKS audit logs, RDS logins, runtime, malware scans) |
| `publishing_frequency` / `administrator` | how often findings are exported; the account that administers it |
| `findings_open` / `findings_critical` / `findings_high` / `last_finding_at` | what it currently reports |

`AdvisorThreatFinding` (an event, not a resource; kept as long as the provider keeps it, 90 days for GuardDuty):

| property | meaning |
|---|---|
| `type` / `title` / `description` | the provider's finding type (`UnauthorizedAccess:EC2/SSHBruteForce`) and its words |
| `severity` / `native_severity` | `low` \| `medium` \| `high` \| `critical` (GuardDuty: below 4, 7, 9, from 9); the provider's score |
| `resource_type` / `resource` / `resource_name` | what it is about |
| `count` / `first_seen_at` / `last_seen_at` | how often and when the activity was seen |
| `archived` | a person dismissed it in the provider |

Edges: `REPORTED_BY` → `AdvisorDetector`; `ABOUT` → the resource (or a ref); `IN_ACCOUNT`.

### AdvisorIdentity / AdvisorPolicy

Who can act: IAM users and roles, service accounts, team members, API tokens.

`AdvisorIdentity`:

| property | meaning |
|---|---|
| `kind` | `user` \| `role` \| `service_account` \| `group` \| `token` \| `team_member` \| `instance_profile` |
| `human` | true for a person |
| `mfa` | MFA enforced |
| `admin` | has an administrative policy |
| `last_used_at` | last activity |
| `credentials` | count of active access keys or tokens |
| `credential_age_days` | the oldest active credential |
| `trust` | (roles) who may assume it, summarised: `same_account` \| `cross_account` \| `service` \| `federated` \| `public` |

An IAM Identity Center user is `kind: user` with `native_type: sso_user`: `human` is always true, `mfa` is null
(no API exposes it), `admin` means an administrative permission set is assigned directly or through a group,
`policies` are the permission set names, `accounts` the account ids reached, `assignments` the `<account>
<permission set> (direct|group x)` lines, `last_used_at` the last portal sign-in seen in CloudTrail (90 days back
at most), `activity` the last stored write per account. It hangs off the management account that owns the directory.

`AdvisorPolicy`: `name`, `managed` (provider-managed), `admin`, `wildcard_actions`, `wildcard_resources`, `attached`.

Edges: `GRANTED` (identity → policy); `CAN_ASSUME` (identity → identity); `RUNS_AS` (resource → identity);
`CREATED` (identity → resource, from the audit trail when available).

### AdvisorSecret

Secrets, parameters, environment variables, keys. Never the value.

| property | meaning |
|---|---|
| `kind` | `secret` \| `parameter` \| `env_var` \| `kms_key` \| `api_key` |
| `encrypted` | the value is stored encrypted (true for every secrets manager; false for a plain parameter or an unencrypted env var) |
| `rotation_enabled` / `last_rotated_at` | whether automatic rotation is configured and when the value last changed; an old, unrotated credential is a finding |
| `scope` | (env vars) `production` \| `preview` \| `development` \| `all` |
| `sensitive` | the provider marks it sensitive |
| `key_state` | (keys) `enabled` \| `disabled` \| `pending_deletion` \| `pending_import` \| `unavailable`; the generic `state` folds it (`pending_deletion` and `disabled` are `stopped`) |
| `managed` | (keys) the provider manages it (an AWS-managed key: free, rotated by AWS); false for the account's own |
| `usage` / `spec` / `origin` / `aliases` / `multi_region` / `deletion_at` | (keys) what it does, its algorithm, where its material came from, its names, and when a scheduled deletion lands |

Edges: `USES_SECRET` ← resources; `ENCRYPTS` (key → storage, database, messaging). A KMS key is `native_type:
kms_key`; a reference by alias or key id is resolved to the key's ARN, an alias the advisor did not read stays a ref.

### AdvisorImage

What software was baked into: a machine image or a container image. The join point between a running thing and its
packages.

| property | meaning |
|---|---|
| `kind` | `machine` \| `container` |
| `repository` / `tag` / `digest` | (container) |
| `os` / `os_version` | the operating system baked into the image (`ubuntu 22.04`, `amazon linux 2023`, `alpine 3.19`), for matching distribution package advisories |
| `created_at` | when the image was built or pushed; an old image is a hint that its packages are old |
| `public` | the image is public |
| `scanned_at` | last package scan |

Edges: `BUILT_FROM` ← compute, deployments, functions; `CONTAINS` → `AdvisorPackage`.

---

## 2. Software

### AdvisorApp

A program observed running (probe) or declared running (deployment metadata). Keyed by name across the account.

| property | meaning |
|---|---|
| `kind` | `app` (the workload) \| `infra` (runtimes, agents, orchestration) |
| `category` | `web_server` \| `database` \| `cache` \| `ssh` \| `container_runtime` \| `agent` \| `queue` \| `chain_node` \| `other` |

`RUNS` edge (resource → app): `user`, `count`, `cpu_pct`, `rss_bytes`, `oldest_seconds`, `command`, `version` (when
the probe reads it: `sshd -V`, `nginx -v`, `redis-server --version`), `first_seen`, `last_seen`, `probes`, `gone`.

Edges: `SERVES` → `AdvisorEndpoint`; `PROVIDED_BY` → `AdvisorPackage`.

### AdvisorPackage

An installed software component with a version. The vulnerability layer matches against these.

| property | meaning |
|---|---|
| `id` | `<ecosystem>:<name>:<version>` |
| `ecosystem` | `deb` \| `rpm` \| `apk` \| `npm` \| `pypi` \| `go` \| `cargo` \| `gem` \| `docker` \| `runtime` \| `binary` (a version read from the program itself) \| `kernel` \| `os` \| `framework` |
| `name` / `version` | the package name as its ecosystem spells it (`openssh-server`, `next`, `openssl`) and the exact installed version string |
| `source_kind` | how known: `dpkg` \| `rpm` \| `apk` \| `lockfile` \| `image_manifest` \| `deployment_metadata` \| `binary_version` \| `uname` \| `os_release` |
| `source_name` | the source package the distribution advisories name (`openssh` for `openssh-server`); null when it is the name itself |
| `advisory_ecosystem` | the feed's name for the distribution the package was installed from (`Ubuntu:24.04:LTS`, `Debian:12`, `Alpine:v3.19`, `Rocky Linux:9`, `AlmaLinux:9`, `Amazon Linux:2023`); null when no feed covers it |
| `scope` | `service` (a program that may listen) \| `library` (linked by others) \| `kernel` \| `tool` (nothing listens as it): what the verdict can say about reachability |
| `cpe` | the CPE string when it can be formed |

Edges: `INSTALLED_ON {path, first_seen, last_seen, gone}` → compute, deployment, function or image; `PROVIDES` →
`AdvisorApp`; `CONTAINED_IN` ← `AdvisorImage` (`CONTAINS`).

### KnVulnerability

A published vulnerability. General area (true in any account), from OSV, NVD, a provider advisory or one pasted into
a chat.

| property | meaning |
|---|---|
| `id` | the CVE id (`CVE-2025-29927`) or the advisory id (`GHSA-…`) |
| `cwe` | the weakness class (`CWE-287`) |
| `summary` | the vulnerability in one or two sentences, as the source states it |
| `cvss` / `severity` | score and `critical` \| `high` \| `medium` \| `low` |
| `published` / `modified` | when the advisory was first published and last changed (a changed advisory rebuilds the verdicts that cite it) |
| `exploited` | listed as known exploited (CISA KEV) |
| `fixed_in` | versions that fix it (list) |
| `attack_vector` | `network` \| `adjacent` \| `local` \| `physical` (decides how much reachability matters) |
| `source` / `fetched_at` | which feed it came from (`osv`, `nvd`, `ghsa`, `vendor_advisory`, `chat` when a person pasted it) and when it was last read |

Edges: `AFFECTS {range}` → `AdvisorPackage` (version ranges, resolved per package node).

### Verdict: VULNERABLE_TO

Materialised for every resource with an affected package: `(:AdvisorResource)-[:VULNERABLE_TO]->(:KnVulnerability)`

| edge property | meaning |
|---|---|
| `package_id` | the package that matched |
| `reachable` | whether any endpoint served by the affected software is reachable from outside: `internet` \| `network` \| `local` \| `none` |
| `via_endpoint` | the endpoint id when reachable |
| `criticality` | the advisor's combined verdict: `critical` (network vector, reachable from internet) \| `exposed` (reachable from the network) \| `affected` (installed, not reachable) \| `mitigated` (blocked by a filter) \| `local_only` (local vector) |
| `blocked_by` | the filter rule id that blocks it, when `mitigated` |
| `computed_at` | when the verdict was last recomputed; it is rebuilt when the package, the endpoint's reachability or the advisory changes |

---

## 3. Network and reachability

### AdvisorNetwork

An isolation boundary: VPC, GCP network, Azure VNet; for Vercel the project (public by default, `flat: true`).

| property | meaning |
|---|---|
| `cidr_blocks` / `ipv6_blocks` | address space (lists) |
| `default` | the provider's default network |
| `flat` | no segments or filters inside (SaaS platforms) |
| `flow_logs` | traffic logging on |
| `dns_hostnames` | the network hands out DNS hostnames to instances (`enableDnsHostnames`); needed for private endpoints and name-based reachability |

Edges: `IN_NETWORK` ← segments, filters, interfaces, gateways, resources; `PEERS_WITH {state, cidrs}` → network.

### AdvisorSegment

A subnet with its own routing.

| property | meaning |
|---|---|
| `cidr` / `ipv6_cidr` | the segment's address range(s); what a filter rule's `cidr` source is matched against |
| `zone` | the availability zone the segment lives in (a segment never spans zones) |
| `public` | derived: its route table has a default route to an internet gateway |
| `auto_public_ip` | instances get a public IP on launch |
| `available_ips` | free addresses left in the segment; a segment near zero cannot launch anything |

Edges: `IN_NETWORK`; `USES_ROUTE_TABLE` → `AdvisorRouteTable`; `GUARDED_BY` → `AdvisorFilter` (the NACL);
`IN_SEGMENT` ← interfaces.

### AdvisorRouteTable

| property | meaning |
|---|---|
| `main` | the network's main table |
| `routes` | count |

Edges: `ROUTES {destination, state, origin}` → `AdvisorGateway` \| `AdvisorInterface` \| `AdvisorNetwork` (peering);
`IN_NETWORK`.

### AdvisorGateway

How traffic enters or leaves a network.

| property | meaning |
|---|---|
| `kind` | `internet` \| `nat` \| `egress_only` \| `vpn` \| `transit` \| `peering` \| `endpoint` \| `edge` |
| `public_ip` | (NAT) |
| `service` | (endpoint) the service it reaches (`s3`, `dynamodb`) |
| `endpoint_type` | (endpoint) `gateway` \| `interface` |
| `peer_network_id` / `peer_account_id` | (peering) |

Edges: `IN_NETWORK`; `ROUTES` ← route tables; a NAT gateway is also the `KnSystem nat:` that carries transfer cost.

### AdvisorInterface

A network interface: ENI, GCE NIC, Azure NIC. The thing that actually wears filters and sits in a segment.

| property | meaning |
|---|---|
| `private_ips` / `public_ip` / `ipv6` | the addresses on the interface: private (list, the primary first), the public address when one is mapped, IPv6 addresses (list) |
| `mac` | the hardware address, the stable identity of the interface across reattachments |
| `interface_type` | `instance` \| `database` \| `load_balancer` \| `function` \| `endpoint` \| `nat` \| `other` |
| `primary` | the resource's primary interface |
| `status` | `in_use` \| `available` |
| `description` | the provider's description |
| `source_dest_check` | the provider drops traffic not addressed to the interface; off on NAT instances, routers and VPN boxes, which is how such a box is recognised |

Edges: `ATTACHED_TO` → the resource; `IN_SEGMENT`; `IN_NETWORK`; `WEARS` → `AdvisorFilter` (security groups);
`ASSIGNED` ← `AdvisorPublicIp`.

### AdvisorPublicIp

A static public address: EIP, GCP static IP, Azure public IP, Vercel or Cloudflare anycast ranges as one node per range.

| property | meaning |
|---|---|
| `ip` | the public address itself |
| `associated` | attached to something |
| `kind` | `static` \| `anycast` |

Edges: `ASSIGNED` → `AdvisorInterface` \| `AdvisorGateway` \| `AdvisorLoadBalancer`.

### AdvisorFilter

Anything that allows or denies traffic or access.

| property | meaning |
|---|---|
| `kind` | `security_group` \| `network_acl` \| `firewall` (GCP firewall, Azure NSG) \| `network_policy` (Kubernetes) \| `waf` \| `deployment_protection` \| `password` \| `sso` \| `ip_allowlist` \| `rate_limit` \| `trusted_ips` |
| `stateful` | replies allowed automatically (security groups yes, NACLs no) |
| `default_action` | `deny` \| `allow` when no rule matches |
| `default` | the provider's default group or ACL |
| `description` | the provider's free-text description of the filter (what the team said it was for when it was created) |
| `rules` | count |
| `attached` | how many interfaces, segments or deployments wear it |

Edges: `IN_NETWORK`; `HAS_RULE` → `AdvisorFilterRule`; `WEARS` ← interfaces; `GUARDED_BY` ← segments, resources,
deployments, endpoints.

A web application firewall (`kind: web_acl`: AWS WAF, Cloud Armor, Azure WAF, Cloudflare WAF) is a filter in front of
HTTP rather than a packet filter, and the provider bills it, so it is also an `AdvisorResource` with a `monthly_usd`.
It carries `default_action` (`allow` \| `block`), `rules` and `rule_list` (one line per rule in priority order: a
managed group, a rate limit, a custom statement, and what it does), `managed_groups`, `rate_limits`, `attached`,
`edge` (attached to the CDN rather than a regional balancer), `logging`, `requests_30d` / `blocked_30d`. Its rules
stay lines rather than `AdvisorFilterRule` nodes: they match requests, not ports and sources. Edges: `GUARDED_BY` ←
the balancers and APIs it is attached to.

### AdvisorFilterRule

| property | meaning |
|---|---|
| `direction` | `ingress` \| `egress` |
| `action` | `allow` \| `deny` |
| `protocol` | `tcp` \| `udp` \| `icmp` \| `any` \| `http` (for L7 rules) |
| `from_port` / `to_port` | null = all |
| `priority` | evaluation order (NACL rule number, GCP priority, WAF order); null for unordered sets |
| `source_kind` | `internet` \| `cidr` \| `filter` (another group) \| `prefix_list` \| `service` \| `identity` \| `geo` \| `any` |
| `source` | the value: the CIDR, group id, list id, country code |
| `path` | (L7) the path pattern |
| `description` | the provider's free-text description of the rule, often the only record of why a port was opened |
| `dormant` | lets nothing in today (an IPv6 rule in a network without IPv6) |

Edges: `HAS_RULE` ← filter; `FROM` → `AdvisorSource` \| `AdvisorFilter` (group-referencing rules).

### AdvisorSource

Where traffic originates, as a node so verdicts can point at it.

| property | meaning |
|---|---|
| `id` | `internet` \| `cidr:<cidr>` \| `prefix:<id>` \| `geo:<cc>` \| `team` \| `any` |
| `kind` | `internet` \| `cidr` \| `prefix_list` \| `geo` \| `identity_set` |
| `label` | human name |
| `private` | an RFC 1918 or the network's own range |

The `internet` node carries both `AdvisorSource` and `KnDestination` labels so transfer edges and reachability edges end
at the same node.

### AdvisorEndpoint

Something listening or answering: a port on a box, a balancer listener, a database endpoint, a function URL, a
deployment URL. Replaces v1 `AdvisorPort` (the label is kept on port endpoints during migration).

| property | meaning |
|---|---|
| `kind` | `port` (observed socket) \| `listener` (balancer) \| `service_endpoint` (database, cache) \| `url` (deployment, function) \| `api` (cluster API) |
| `protocol` | `tcp` \| `udp` \| `http` \| `https` \| `grpc` \| `tls` |
| `port` | the port number; null for a URL endpoint where the protocol implies it |
| `hostname` / `url` / `path` | for named endpoints |
| `bind` / `scope` | (port) the bind address and `all` \| `loopback` \| `address` |
| `process` / `container` / `container_port` | (port) what is behind it |
| `tls` | TLS terminated here |
| `exposure` | the one-word summary: `internet` \| `network` \| `group` \| `closed` \| `local` \| `protected` (reachable but behind an auth filter) |
| `first_seen` / `last_seen` / `probes` / `gone` | when it was first and last observed, how many probes or inventories saw it, and whether it has stopped answering |

Edges: `EXPOSES` ← resource; `SERVES` ← app; `FORWARDS_TO {target_group, health, weight}` → endpoint (listener to
target port); `SECURES` ← certificate; `POINTS_TO` ← DNS records; `GUARDED_BY` → filter (L7 filters on a URL); and
the verdicts below.

### Verdicts: REACHABLE_FROM, ALLOWED_BY, BLOCKED_BY

Computed per provider from the chain (bind scope → filters on the interface → segment filter with priority → routes →
public address, or deployment protection on a URL), written as edges, read generically.

`(:AdvisorEndpoint)-[:REACHABLE_FROM]->(:AdvisorSource | :AdvisorFilter | :AdvisorNetwork)`

| edge property | meaning |
|---|---|
| `protocol` / `port` | what reaches |
| `through` | the ids of what let it through, in order (rule, ACL entry, route, public IP) |
| `requires_auth` | reachable but an auth filter stands in front (`protected`) |
| `note` | the reason in words, as the exposure code writes it today |
| `computed_at` | when the verdict was last recomputed; it is rebuilt when a filter rule, a route, an address or the bind changes |

`(:AdvisorEndpoint)-[:ALLOWED_BY {source}]->(:AdvisorFilterRule)`: the rule that lets a source in.

`(:AdvisorEndpoint)-[:BLOCKED_BY {source, reason}]->(:AdvisorFilterRule | :AdvisorFilter)`: what stops a source
that a less specific rule would have let in (a NACL deny over an open security group; a WAF rule; `closed` when no
rule matches, pointing at the filter).

A `VULNERABLE_TO` edge reads these to set its `criticality`.

---

## 4. Operations: what the advisor proposed, decided, did and saw

The advisor's own records. Generic by nature: a recommendation about a resource, a change made to it, an alert on it.
Every node here carries `provider` (the provider the record is about) in addition to the base properties, and
`TARGETS`, `ABOUT`, `FLAGGED`, `SECURITY_FLAGGED`, `CAUSED_BY` may point at any resource label.

### AdvisorRecommendation

A proposal about one resource, the team's decision on it and what the bill showed afterwards.

| property | meaning |
|---|---|
| `fingerprint` | stable hash of rule + resource + action, so the same proposal reconciles across runs |
| `title` | the recommendation in one line |
| `action` | generic verb: `stop` \| `terminate` \| `rightsize` \| `migrate_arch` \| `change_storage_tier` \| `release_address` \| `delete_snapshot` \| `delete` \| `enable_logging` \| `schedule` \| `commit` (buy a plan or reservation) \| `security_fix` \| `other` |
| `native_action` | the provider-specific action (`aurora_set_storage_iopt`, `migrate_graviton`) |
| `tier` | autonomy: `auto` (the executor may act) \| `approve` (a person must approve) \| `report` (information only); the rule sets it, Jev may only tighten it (§5b, purpose `tier_check`) |
| `status` | `open` → `pending` → `approved` \| `rejected` \| `snoozed` → `done`; `stale` when the condition went away |
| `source` | who proposed it: `rules` \| `agent` \| `scan` \| `incident` |
| `rule` | the rule or finding name that produced it |
| `est_monthly_saving` | estimated saving, USD per month |
| `confidence` | the proposer's confidence |
| `decided_by` / `decided_at` | the decision |
| `decision_scope` | how it was recorded as a Concept: `internal` (this resource) \| `generic` (a reusable rule); suggested by Jev (§5b, purpose `decision_scope`), confirmed by the person deciding |
| `resource` | the raw resource string as named, kept even when the target is a ref |
| `verdict` | what the bill did: `realised` \| `partial` \| `none` \| `increase` \| `too_early` \| `no_data` \| `not_verifiable` |
| `realised_usd_month` / `realised_ratio` / `verified_at` | the measured saving, realised ÷ estimated, when checked |

Edges: `TARGETS` → resource or `AdvisorResourceRef`; `DECIDED_AS` → `Concept`; `PROPOSED_IN` → `AdvisorRun`;
`FROM_INCIDENT` → `AdvisorIncident`; `FROM_SCAN` → `AdvisorSecurityScan` (security fixes); `ADDRESSES` →
`KnVulnerability` (a fix for a vulnerability). Edges in: `CARRIES_OUT` from the action that executed it.

### AdvisorResourceRef

A placeholder for a resource that one of the advisor's records names but that has no node of its own, so `TARGETS`,
`ABOUT`, `FLAGGED` and `LAUNCHED` edges always have somewhere to land. One comes to exist in three situations:

- **a kind the model does not cover yet**: the executor acts on DynamoDB tables, ECR repositories, EFS file systems
  and CloudWatch alarms, which have no label here; this is the case that shrinks as labels are added;
- **timing**: an instance the executor just launched, or an alert about a box the inventory has not refreshed yet,
  is named before the next collection run produces its node;
- **already gone**: the record points at something deleted before any inventory saw it (a snapshot the executor
  removed, a bucket from an old finding), and the ref is all there will ever be.

| property | meaning |
|---|---|
| `id` | the resource string exactly as the record named it (an ARN, a bare id, a URL) |
| `guessed_type` | what the id shape says it probably is (`lambda`, `bucket`, `volume`, `snapshot`, `table`, `alarm`), so an agent need not parse ARNs |
| `first_named_at` / `named_by` | when and by which record kind it first appeared |

**Upgrade in place.** When the inventory later produces the real node for the same id, the mirror adds the proper
labels to the existing node and removes `AdvisorResourceRef`, so every edge written against the ref carries over. A
relaunched instance therefore keeps its `LAUNCHED` history on the same node that later carries its facts, instead of
splitting across two.

### AdvisorRun

One collection pass over an account.

| property | meaning |
|---|---|
| `started_at` / `finished_at` | when the run began and ended; null `finished_at` while running or after a crash |
| `status` | `running` \| `completed` \| `failed` |
| `trigger` | `manual` \| `schedule` |
| `adapter_version` | the provider adapter that ran |
| `findings_count` / `recommendations_count` | how many control findings the run produced and how many recommendations it created or reconciled |

### AdvisorControl

A check the advisor runs: a cost control, a security control, or one of the advisor's own (a dangling DNS record, a
reachable vulnerability).

| property | meaning |
|---|---|
| `title` | the control's title as the benchmark or the advisor states it |
| `framework` | where it comes from: `cost` \| `cis` \| `foundational_security` \| `advisor` \| `provider` (Trusted Advisor, Security Command Center) |
| `severity` | `critical` \| `high` \| `medium` \| `low` \| null |
| `category` | `cost` \| `security` \| `reliability` \| `hygiene` |

Edges: `FLAGGED {run_id, reason}` → resource (latest cost run); `SECURITY_FLAGGED {scan_id, reason, severity,
first_seen_at}` → resource (latest security scan); `HAS_PLAYBOOK` → `KnPlaybook` (§5).

### AdvisorAlert

One alert the watcher raised.

| property | meaning |
|---|---|
| `kind` | what fired: an open list (`instance_state`, `disk_fill`, `memory_high`, `nat_traffic`, `spend_step`, `port_exposed`, `app_gone`, `vulnerability_reachable`, `certificate_expiring`, `dns_dangling`, …) |
| `level` | `info` \| `warning` \| `alarm`; for some kinds judged (§5b, purpose `alert_triage`: an expected `instance_state` is `info`) |
| `message` | the text (cut at 500) |
| `created_at` | when the alert was raised |
| `acknowledged` / `acknowledged_by` | whether a person (or Jev's triage, as `jev`) marked it seen, and who |
| `resource` | the raw resource string |
| `cause_status` | `found` \| `pending` \| `none` |
| `cause` | the cause in one sentence |
| `cause_actor` | who |
| `cause_actor_kind` | `person` \| `advisor` \| `automation` \| `provider` \| `unknown` |
| `cause_via` | through what (console, CLI, Terraform, autoscaler, the advisor's action kind) |
| `cause_event` / `cause_at` | the audit-trail event and time |

Edges: `ABOUT` → resource or ref; `CAUSED_BY` → `AdvisorAction`. Edges in: `INVESTIGATES` from an incident.

### AdvisorIncident

The agent's investigation of an alert.

| property | meaning |
|---|---|
| `status` | `pending` \| `completed` \| `failed` |
| `cause` | the root cause found |
| `confidence` | the agent's confidence in the cause it found, 0..1 |
| `episode_cost_usd` / `monthly_run_rate_usd` | what it cost and would cost |
| `created_at` / `finished_at` | when the investigation was dispatched and when the agent answered |

Edges: `INVESTIGATES` → `AdvisorAlert`. Edges in: `FROM_INCIDENT` from recommendations.

### AdvisorAction

One row of the executor's ledger: a change planned, made, read back, undone or retired. Proposals included.

| property | meaning |
|---|---|
| `kind` | the executor's catalogue (`schedule_hours`, `snapshot_delete`, `log_retention`, `swarm_park`, `beanstalk_scale`, …); each kind declares the providers it implements |
| `status` | `proposed` \| `applied` \| `verified` \| `failed` \| `refused` \| `reverted` \| `stale` |
| `mode` | `dry_run` \| `apply` |
| `trigger` | `schedule` \| `manual` |
| `title` / `reason` / `rollback` | the change, why, how to undo |
| `est_usd_month` | estimated saving |
| `result` / `error` | what the apply or read-back returned |
| `resource` / `resource_name` / `region` | the target as named |
| `created_at` / `seen_at` / `applied_at` / `verified_at` / `reverted_at` | when the row was first proposed; the last pass that still found the proposal valid (the grace period before applying runs from here); when the change was made; when it was read back and confirmed; when it was undone |
| `stage` / `new_resource` | (staged changes) where it is, what it launched |
| `bill_verdict` / `realised_usd_month` | what the bill did after this kind of change on this resource |

Edges: `TARGETS` → resource or ref; `CARRIES_OUT` → `AdvisorRecommendation`; `LAUNCHED` → `AdvisorResourceRef`;
`TOUCHED_IN {event: apply|verify|revert|advance|step, outcome, at, trigger, detail}` → `AdvisorPass`; `ANSWERED` →
`AdvisorPressureEvent`. Edges in: `CAUSED_BY` from alerts.

### AdvisorPass

One executor pass, including the ones that did nothing.

| property | meaning |
|---|---|
| `started_at` / `finished_at` / `took_ms` | when the pass began and ended, and how long it took |
| `trigger` | `schedule` \| `manual` |
| `mode` | `dry_run` \| `apply` |
| `proposed` / `fresh` / `applied` / `verified` / `failed` / `refused` / `held` / `stale` | counts |
| `errors` | joined, cut at 1000 |

### AdvisorSecurityScan

One security scan (benchmarks through the provider's compliance tooling, or the advisor's own controls).

| property | meaning |
|---|---|
| `started_at` / `finished_at` | when the scan began and ended |
| `status` | `running` \| `completed` \| `failed` |
| `trigger` | `manual` \| `schedule` |
| `frameworks` | which benchmark sets ran |
| `alarms` / `new_alarms` / `resolved` / `errors` | alarm findings in the scan; the ones not present in the previous scan; the previous scan's alarms that are gone; controls that failed to run |
| `counts` | JSON: findings per status and severity |

### AdvisorPressureEvent

One hour an autoscaled group spent pinned at its ceiling under load.

| property | meaning |
|---|---|
| `at` | the hour |
| `ring` | hour of the week, 0..167 |
| `desired` / `max_size` | what ran and the ceiling |
| `signal` | what was high: `cpu` \| `memory` \| `requests` \| `latency` |
| `value` | the signal's value |
| `note` | what the check saw, in words (the members' CPU, the memory reported, the desired and maximum sizes) |

Edges in: `PRESSURED_AT` from the pool; `ANSWERED` from the action that raised the ceiling.

### AdvisorNotification

One thing the provider told the account through its own notification channel (AWS User Notifications, the console
bell). Keyed by the event's ARN; kept 90 days.

| property | meaning |
|---|---|
| `feed` | `managed` (the provider's own feed every account gets: health, announcements, billing, security) \| `configured` (the account's own notification configurations, where a hub is registered) |
| `source` | the originating service (`health`, `billing`, `cloudwatch`, ...) |
| `event_type` | the source's event type |
| `headline` | the message's headline |
| `notification_type` | `ALERT` \| `WARNING` \| `ANNOUNCEMENT` \| `INFORMATIONAL` |
| `event_status` | `HEALTHY` \| `UNHEALTHY` |
| `origin_region` / `regions` | where the event happened; for an aggregate, every region folded in |
| `related_account` | the account the event is about (an organisation's aggregate names a member) |
| `created_at` | when the notification was raised |
| `aggregation` / `event_count` | whether it is an aggregate and how many events it folds |

Edges out: `IN_ACCOUNT` → the account that received it.

---

## 5. Cost and knowledge layer (`Kn*`)

Rebuilt from the model on every sync. The **general area** (`KnSystemType`, `KnArchetype`, `KnVulnerability`,
`KnPlaybook`, `KnSource`) is true in any account; **our side** (`KnSystem`, `KnPricingOverlay`, `KnLogGroup`, traffic edges) is this account as a
schematic.

### KnSystemType

Something you can buy at a list price: a compute SKU, a database class, a usage unit, a plan.

| property | meaning |
|---|---|
| `id` | `<provider>|<kind>|<sku>|<region>` |
| `provider` | the provider whose price list it comes from |
| `kind` | `compute` \| `database` \| `cache` \| `function` \| `storage` \| `transfer` \| `usage` \| `plan` |
| `native_kind` | the provider's family (`ec2`, `rds`, `gce`, `vercel_pro`) |
| `sku` | the type name or usage rule |
| `region` | the region the price is quoted for (prices differ per region; `global` for usage rules that do not) |
| `engine` | (database, cache) the engine the price is for |
| `vcpu` / `memory_mb` / `arch` | (compute) the size |
| `list_price` / `price_unit` / `unit` | the price, what it is per (`USD/hour`, `USD/GB`), the unit alone |
| `included` | (plan) quotas the plan includes, as JSON |
| `source` | `pricing_api` \| `pricebook` \| `provider_docs` |
| `valid_from` | the date the price was fetched or the pricebook was dated; an old `valid_from` means the price may have moved |
| `note` | what the usage rule covers, when the sku alone does not say (`NAT gateway data processing`) |

Edges in: `RUNS_ON` from systems; `COVERS` from overlays.

### KnArchetype

What a workload is for. One node per archetype name, shared by every account: `blockchain_node`, `database`,
`cache_or_queue`, `web_or_api`, `batch_or_worker`, `ci_or_build`, `bastion_or_vpn`, `dev_or_test`, `k8s_node`,
`unknown`. This is the one place a role lives: a resource reaches it with `HAS_ROLE` (the judged `role`, §5b), a
system with `IS_A`, so "every database we run" is one hop from one node whether you start from resources or systems.
(v1 had a separate `AdvisorRole` hub with the same names and no descriptions; v2 merges it here.)

| property | meaning |
|---|---|
| `name` | the archetype name (also the id) |
| `description` | what it is, provider-neutral; this text is also what Jev reads as the option in the `resource_role` question (§5b), so editing it changes how resources are classified |

Platform providers will add `static_site`, `edge_function`, `api_gateway`. Edges in: `HAS_ROLE` from resources,
`IS_A` from systems.

### KnSystem

A system as the unit that is sized, priced and reasoned about: a pool, a cluster, a database cluster, a deployment,
a function, a gateway, or a standalone resource.

| property | meaning |
|---|---|
| `id` | `<native_kind>:<name>` as the adapter writes it (`pool:web`, `rds:main`, `eks:prod`, `lambda:api`, `nat:nat-0abc`, `ec2:i-0abc` on AWS): the attribution rules key on these prefixes, so the id stays native and the generic `kind` is a property |
| `provider` | the provider the system runs on |
| `kind` | `instance` \| `autoscaled_group` \| `cluster` \| `database_cluster` \| `database` \| `cache_group` \| `cache` \| `function` \| `gateway` \| `deployment` \| `project` |
| `native_kind` | the provider's word (`pool`, `rds_cluster`, `beanstalk_env`) |
| `archetype` | the archetype name |
| `member_count` | how many resources are in it (running members only: a stopped instance is not a member) |
| `storage_gb` / `storage_usd_month` | attached storage and its cost at list |
| `region` | the region its members are in |
| `monthly_list_usd` | the system for a month at list: `RUNS_ON` edges plus storage |
| `gone` | true when the system disappeared from the inventory (its members all left); kept so its decisions and outcomes stay walkable |
| `usage_units` | (functions, deployments) JSON of the usage quantities priced (`invocations_month`, `gb_seconds_month`, `bandwidth_gb_month`) |

Edges: `IN_ACCOUNT`; `IS_A` → `KnArchetype`; `RUNS_ON {count, hours_month, list_price, list_usd_month}` →
`KnSystemType`; `PART_OF` → `KnSystem` (a pool in its cluster, a function in its deployment); `TRANSFERS_TO` →
`KnDestination`; `SHIPS_LOGS_TO {gb_day, usd_month, price_per_gb, attributed_by}` → `KnLogGroup`. Edges in: `MEMBER_OF`
from its resources.

### KnPricingOverlay

Something that changes what a type actually costs.

| property | meaning |
|---|---|
| `id` | `commitment:<provider>:<id>`, `reservation:<provider>:<id>`, `plan:<provider>:<account>` |
| `provider` | the provider that sells the discount |
| `kind` | `commitment` (savings plans, committed use discounts) \| `reservation` \| `plan` (a SaaS plan with included quotas) \| `free_tier` |
| `covers_kind` | the `KnSystemType.kind` it applies to |
| `sku` / `count` / `engine` | (reservation) what and how many |
| `commitment_usd_month` | the fee |
| `covered_od_usd_month` | the on-demand value it covered last full month |
| `discount_rate` | the implied discount |
| `included` | (plan, free tier) quotas as JSON |
| `offering` | payment option |
| `start` / `end` / `month` | the term or the month measured |
| `utilization_pct` | how much of the commitment was used |

Edges: `COVERS` → `KnSystemType`.

### KnDestination

Where a system's outbound bytes go, as a node so transfer cost can sit on an edge between the system and the other
end, the way compute cost sits on `RUNS_ON`. (v1 called this `KnService`; renamed because it is a destination, not a
service.) Egress only: inbound is free on every provider that matters, so there is no edge for it.

| property | meaning |
|---|---|
| `id` | `internet` \| `regional` (other zones and VPCs in the region) \| `provider:<service>` (a provider service such as `provider:s3`, so the same bytes can be shown paid through a NAT gateway or free through a gateway endpoint) |
| `name` | human name: `internet`, `other AZs and VPCs in the region`, the service name |

`TRANSFERS_TO` edge (from a `KnSystem` or the account): `mechanism` (`nat` \| `cross-az` \| `egress` \| `cdn`),
`gb_day`, `gb_day_median`, `p95_gb_hour`, `price_per_gb`, `usd_month`, `window_days`, `source`.

The `internet` node also carries `AdvisorSource`.

### KnLogGroup

A log destination with its cost and who writes to it: CloudWatch group, Cloud Logging bucket, Log Analytics
workspace, a Vercel log drain (`native_type: log_drain`, with `host`, `sources`, `environments`, `sampling_rate`,
`all_projects`; its writers are the projects it lists, so `attributed_by` records the listing, not a guess).

| property | meaning |
|---|---|
| `provider` | the provider the log service belongs to |
| `name` / `region` | the log group, bucket or workspace name as the provider knows it, and its region |
| `retention_days` | null = forever |
| `stored_gb` / `ingest_gb_day` | how much is stored in it now, and how much is written into it per day over the metered window (14 days) |
| `ingest_usd_month` / `storage_usd_month` | what writing into it costs per month at the provider's ingestion rate, and what keeping it costs at the storage rate; together the group's monthly cost |
| `owner` | the `KnSystem` attributed as its writer |
| `attributed_by` | how, in words (`observed: …`, `tag …`, `name tokens: …`, `jev: … at NN%`, `no match`) |
| `candidates` | (unowned) closest systems with scores |
| `tags` | JSON |
| `jev_choice` / `jev_confidence` | judged (§5b, purpose `log_group_owner`): the classifier's lean when its confidence was under the 60 % bar |

Edges in: `SHIPS_LOGS_TO` from the owning system, the account (unattributed), or a resource seen shipping to it
(`via`, `source`, `observed_at`, `attributed_by: 'observed'`).

### KnPlaybook

What to do about a control: what the alarm means, when to act, how, with what effort and risk. **Derived, never
hand-written.** Each playbook is built from named sources, stamped with what it was built from, and rebuilt when a
source changes or after a fixed age, so it cannot quietly go stale. General area: a playbook for a Thrifty control is
the same in every account. What is *not* in it is when to leave the alarm alone in our fleet: that is the team's
knowledge and lives in Concepts (decisions, operational patterns), which the resolution flow reads alongside.

| property | meaning |
|---|---|
| `id` | `<provider>:<control_id>` |
| `provider` | the provider whose control and documentation it is built from |
| `control_id` / `title` | the control it answers |
| `meaning` | what the alarm says, from the control's own documentation (the benchmark mod's markdown, the provider's check description) |
| `act_when` / `steps` | when and how to act, extracted by the agent from the provider's documentation and advisories, each step carrying the citation it came from |
| `saving` | the saving formula as the rule computes it, rendered from the rule's code and the price catalogue, not written |
| `tier` | `auto` \| `approve` \| `report`: judged (§5b, `tier_check` on the playbook's steps against a representative change), never hand-set |
| `effort` | `low` \| `medium` \| `high`: judged (§5b, `resolution_gate`) |
| `sources` | the URLs and documents it was built from (list) |
| `source_hashes` | a hash per source, so a change in any of them is detected |
| `generated_at` / `generated_by` | when and by which agent run |
| `stale_after` | when it is rebuilt regardless |
| `review_status` | `generated` \| `reviewed` \| `disputed`: a person may mark it, which pins it until the sources change |

Edges: `HAS_PLAYBOOK` ← `AdvisorControl`; `CITES` → `KnSource` (below); `ADDRESSES` → `KnVulnerability` for a
playbook built from an advisory.

### KnSource

A document the advisor builds knowledge from: a provider doc page, a benchmark control's documentation, a vendor
advisory, a pricing page. One node per URL, so every playbook, archetype description or vulnerability can say where
it came from and the advisor can tell when a source changed.

| property | meaning |
|---|---|
| `id` | the URL or document id |
| `kind` | `provider_doc` \| `benchmark_doc` \| `advisory` \| `pricing` \| `well_architected` |
| `title` | the document's title as fetched |
| `fetched_at` / `hash` | when last read and the content hash |
| `changed_at` | when the hash last changed, which triggers a rebuild of everything that `CITES` it |

### KnVulnerability

Defined in §2 with the software layer. Lives in the general area: one node per CVE or advisory, shared by every
account, with `AFFECTS` edges to the package nodes it matches and `VULNERABLE_TO` verdicts computed per resource.

---

## 5a. Relationship index

| relationship | from → to | one line |
|---|---|---|
| `IN_ACCOUNT` | resources, telemetry, runs, passes, scans, KnSystem → AdvisorAccount | belongs to the account |
| `OBSERVED_BY` | resource → AdvisorTelemetry | which sources cover it, with status and last report |
| `HAS_ROLE` | resource → KnArchetype | the judged workload role; the same node a system reaches with `IS_A` |
| `IN_POOL` | AdvisorCompute → AdvisorNodePool | member of an autoscaled group |
| `PART_OF` | AdvisorNodePool → AdvisorCluster; AdvisorFunction → AdvisorDeployment; AdvisorApp → AdvisorDeployment (an observed container that belongs to a workload); AdvisorStack → AdvisorStack (nested); KnSystem → KnSystem | containment |
| `RUNS_IN` | AdvisorDeployment → AdvisorCluster | the platform hosting the workload |
| `SCHEDULED_ON` | AdvisorDeployment → AdvisorCompute | the nodes a workload's pods or tasks run on (`pods`) |
| `FRONTED_BY` | AdvisorEndpoint → AdvisorLoadBalancer \| AdvisorResourceRef | the balancer an Ingress or LoadBalancer Service created for a workload's endpoint |
| `IN_CLUSTER` | AdvisorFilter (network_policy) → AdvisorCluster | the cluster a NetworkPolicy lives in |
| `RUNS_ON_POOL` | AdvisorDeployment → AdvisorNodePool | the pool a deployment scales or is pinned to |
| `BACKED_BY` | AdvisorDeployment → AdvisorLoadBalancer | the balancer in front of it |
| `BUILT_FROM` | compute, deployment, function → AdvisorImage | the image it runs |
| `USES {environments}` | AdvisorDeployment → AdvisorDatabase, AdvisorCache, AdvisorStorage | the data stores a deployment is connected to (Vercel stores today) |
| `RUNS_IMAGE` | compute → AdvisorImage | the container images a plain box runs (from the software probe) |
| `STORES_ON` | AdvisorCompute → AdvisorStorage (block) | attached volume |
| `USES_SECRET` | resource → AdvisorSecret | reads a secret or env var |
| `RUNS_AS` | resource → AdvisorIdentity | the identity it acts with |
| `GRANTED` | AdvisorIdentity → AdvisorPolicy | permissions |
| `CAN_ASSUME` | AdvisorIdentity → AdvisorIdentity | trust |
| `CREATED` | AdvisorIdentity → resource | from the audit trail |
| `ENCRYPTS` | AdvisorSecret (key) → storage, database, messaging | the key that encrypts a volume, bucket, file system, vault, database or topic |
| `RUNS` | resource → AdvisorApp | a program running on it (edge carries the per-instance facts) |
| `PROVIDED_BY` | AdvisorApp → AdvisorPackage | the package the program comes from |
| `INSTALLED_ON` | AdvisorPackage → compute, deployment, function, image | installed software |
| `CONTAINS` | AdvisorImage → AdvisorPackage | baked in |
| `AFFECTS {fixed_in, ecosystem}` | KnVulnerability → AdvisorPackage | the package versions it matches, and what fixes them |
| `VULNERABLE_TO` | resource → KnVulnerability | **verdict**: installed, and how reachable |
| `ADDRESSES` | AdvisorRecommendation → KnVulnerability | a fix proposed for it |
| `EXPOSES` | resource → AdvisorEndpoint | something listening on it |
| `SERVES` | AdvisorApp → AdvisorEndpoint; AdvisorDomain → AdvisorDeployment | what is behind it |
| `FORWARDS_TO` | AdvisorEndpoint → AdvisorEndpoint | a listener to its targets |
| `SECURES` | AdvisorCertificate → AdvisorEndpoint, or the resource that terminates TLS | TLS |
| `DELIVERS_TO {protocol}` | AdvisorMessaging → function, queue, stream | a topic's subscribers |
| `MANAGES {logical_id, resource_type}` | AdvisorStack → resource, network node | infrastructure as code: what the stack created |
| `PROTECTS` / `STORES_IN` | AdvisorBackupPlan → resource; → AdvisorStorage (backup) | what a plan names, where it stores |
| `BACKED_UP_TO {last_backup_at}` | resource → AdvisorStorage (backup) | where its latest backup is |
| `WRITES_TO` | AdvisorAnalytics → AdvisorStorage | where query results land |
| `REPORTED_BY` | AdvisorThreatFinding → AdvisorDetector | the detector that found it |
| `POINTS_TO` | AdvisorDnsRecord → endpoint, balancer, compute, deployment, storage, public IP | where a name resolves |
| `IN_ZONE` / `DNS_OF` | record → zone; domain → zone | a record belongs to a zone; a domain is served by a zone |
| `IN_NETWORK` | segments, filters, interfaces, gateways, resources → AdvisorNetwork | lives inside the network boundary |
| `IN_SEGMENT` | AdvisorInterface → AdvisorSegment | the subnet the interface has its address in |
| `USES_ROUTE_TABLE` | AdvisorSegment → AdvisorRouteTable | the table that decides where the segment's traffic goes |
| `ROUTES` | AdvisorRouteTable → gateway, interface, network | a route and its destination |
| `PEERS_WITH` | AdvisorNetwork → AdvisorNetwork | a peering or transit attachment between two networks |
| `ATTACHED_TO` | AdvisorInterface → resource | the instance, database, balancer or function the interface belongs to |
| `ASSIGNED` | AdvisorPublicIp → interface, gateway, balancer | the static address is mapped to it |
| `WEARS` | AdvisorInterface → AdvisorFilter | the groups on the interface |
| `GUARDED_BY` | segment, resource, deployment, endpoint → AdvisorFilter | a filter that applies (a security group, an ACL, a web ACL) |
| `HAS_RULE` | AdvisorFilter → AdvisorFilterRule | the rules that make up the filter |
| `FROM` | AdvisorFilterRule → AdvisorSource, AdvisorFilter | the rule's source |
| `REACHABLE_FROM` | AdvisorEndpoint → source, filter, network | **verdict**: who can reach it, through what |
| `ALLOWED_BY` | AdvisorEndpoint → AdvisorFilterRule | **verdict**: the rule that lets a source in |
| `BLOCKED_BY` | AdvisorEndpoint → rule, filter | **verdict**: what stops a source |
| `TARGETS` | recommendation, action → resource, ref | what it is about |
| `DECIDED_AS` | AdvisorRecommendation → Concept | the recorded decision |
| `PROPOSED_IN` / `FROM_INCIDENT` / `FROM_SCAN` | recommendation → run, incident, scan | where it came from |
| `INVESTIGATES` | AdvisorIncident → AdvisorAlert | the alert the agent investigated |
| `ABOUT` | AdvisorAlert, AdvisorThreatFinding → resource, ref | the resource the alert or finding concerns |
| `CAUSED_BY` | AdvisorAlert → AdvisorAction | the advisor's own change caused it |
| `FLAGGED` / `SECURITY_FLAGGED` | AdvisorControl → resource | current alarms |
| `HAS_PLAYBOOK` | AdvisorControl → KnPlaybook | derived guidance for the control |
| `CITES` | KnPlaybook → KnSource | where the guidance came from |
| `CARRIES_OUT` | AdvisorAction → AdvisorRecommendation | the approved recommendation the change executes |
| `LAUNCHED` | AdvisorAction → AdvisorResourceRef | the resource a relaunch created, before the inventory sees it |
| `TOUCHED_IN` | AdvisorAction → AdvisorPass | an apply, verify, revert, advance or step made in that pass |
| `PRESSURED_AT` / `ANSWERED` | pool → event; action → event | capacity pressure and its answer |
| `MEMBER_OF` | resource → KnSystem | the system it is part of |
| `IS_A` | KnSystem → KnArchetype | what the system is for |
| `RUNS_ON` | KnSystem → KnSystemType | types and cost at list |
| `COVERS` | KnPricingOverlay → KnSystemType | discounts |
| `TRANSFERS_TO` | KnSystem, account → KnDestination | traffic out with cost |
| `SHIPS_LOGS_TO` | system, account, resource → KnLogGroup | who writes logs |

---

## 5b. Judged properties: the typed questions behind them

Several properties in this model are judgements, not facts read from an API: a resource's `role`, whether it is
`protected`, a log group's `jev_choice`, an alert's level, a decision's `decision_scope`, the usage review's verdict,
a proposal's check. They are filled by Jev (TypeSafe's classifier, `src/jev.ts`) through **typed questions**, never
by free-text prompting. This section explains the mechanism so the properties can be read for what they are.

### How a typed question works

A call hands Jev two things: a **state**, a JSON object of plain facts with no judgement in it, and a set of
**questions**, each with a declared answer type. Jev returns one typed answer per question with a probability
attached. The advisor never parses prose. Three kinds are used:

| kind | the question asks for | the answer | example |
|---|---|---|---|
| `noul` | whether a statement holds | a probability 0..1 | "Its name, tags or description indicate it is deliberately kept" → `protected_prob` 0.91 |
| `choice` | which of a closed list of options fits | a probability per option; the top one is the pick, its probability the confidence | "What is it for?" over the ten archetypes → `role: cache_or_queue`, `role_confidence: 0.84` |
| `score` | where on an ordered rubric | a position with confidence | "How urgently should a human look at this alert?" over `Noise`, `Worth a look this week`, `Should be looked at today`, `Costing real money right now` |

Resources are asked in batches (40 per call). Each resource's facts sit under a key in the state (`resources.r3`),
and its questions are prefixed with the same key and scoped with "Consider only the resource under `resources.r3`
(ignore the others)", so one call answers many resources without them bleeding into each other.

Every call is recorded in `jev_calls` (purpose, a hash of the state, the questions, the answers, model, tokens,
latency, error). Answers are cached per purpose and invalidated when the facts they were based on change (for roles:
name, tags, type, platform or description) or after a fixed age (7 days for roles, 30 for log attribution). Jev never
loosens a tier and never triggers an action; it classifies, and the rules decide what the classification means.
Without a `TYPESAFE_API_KEY` every purpose is a no-op and the rules fall back to their own regexes.

### The purposes and what they fill in the graph

| purpose | state Jev sees | questions | fills |
|---|---|---|---|
| `resource_role` | kind, name, description, tags (Name excluded, 20 at most), pool, type, platform, state, age in days, top processes from the latest probe or "no probe on file", attached volume sizes | `choice` "What is it for?" over the `KnArchetype` catalogue; `noul` "Its name, tags or description indicate it is deliberately kept and must not be deleted or stopped" | `AdvisorResource.role`, `role_confidence`, `protected_prob`; the `HAS_ROLE` edge |
| `alert_triage` | the alert, the resource, its baselines and recent episodes | `noul` "This episode is expected, routine behaviour for this environment rather than waste or an anomaly worth a human's time"; `choice` "What kind of episode is this alert most likely describing?"; `score` "How urgently should a human look at this alert?" | `AdvisorAlert.level` (an expected `instance_state` becomes `info`), auto-acknowledgement, whether an incident is opened |
| `tier_check` | each change the agent proposed, as described | `noul` "Carrying it out could destroy data or an address that cannot be recovered"; `score` "If it were carried out as described, what would users of the service notice?" over `No user-visible effect`, `Brief or degraded`, `Outage possible` | `AdvisorRecommendation.tier` (only ever tightened: `auto` → `approve` → `report`) |
| `proposal_check` | each executor proposal with its facts | `noul` irreversible; `score` service impact; a rubric score for whether the reason supports the change | the executor's second opinion on an `AdvisorAction` (`held` rows in a pass) |
| `log_group_owner` | the group's name and path, its tags, what the rules found, the account's systems (candidates first, 50 at most, plus `none`) | `choice` "Which system in this account writes this log group?" | `KnLogGroup.owner` and `attributed_by: jev: …` at 60 % or better, else `jev_choice` and `jev_confidence` |
| `decision_scope` | the decision's reason, the recommendation, the action, the resource's role | `choice` between `generic` (a rule about a kind of workload that transfers to other accounts) and `internal` (specific to this resource, owner or account) | `AdvisorRecommendation.decision_scope`, which parent the Concept goes under |
| `usage_review` | the profile, the latest activity, the containers and processes, the role, the tags, the last week of executor rows, and candidate schedules | `choice` over the candidates (the profile's own, a wider one, weekdays only, keep running); `noul` the quiet windows are real non-use rather than a measurement gap; `noul` the busy hours are machine chatter rather than people | `usage_review_verdict`, `usage_review_schedule`, `usage_review_confidence`, `usage_review_reason` |
| `rds_load` | a database's load window | `choice` load shape; `choice` what drives the I/O; `noul` held at its capacity ceiling; `noul` the pattern is structural; `choice` the single change that would do most | evidence on the storage-tier and capacity recommendations |
| `resolution_gate` | a playbook, the resource facts and the graph context | `noul` the playbook applies here without breaking the workload; `choice` what blocks it; `score` the engineering effort | whether a resolution is produced deterministically or sent to the agent |

### What changes for the generic model

- **The state names the generic kind.** Today `resource_role` tells Jev "EC2 instance" or "RDS database instance".
  It should say the generic label and the provider's word (`compute, aws ec2_instance`; `deployment, vercel
  project`), so the same question works for a GCE VM or a Vercel deployment, and so Jev's answer does not lean on the
  provider name.
- **The options are the `KnArchetype` catalogue.** The `choice` list is `ROLE_OPTIONS` in `src/roles.ts`, which is
  also what the `KnArchetype` nodes are seeded from. Adding an archetype (`static_site`, `edge_function`, `api_gateway`
  for platform providers) is one entry there, and the graph follows. Descriptions must stay provider-neutral ("a
  Kubernetes worker node managed by a node group or autoscaler", not "EKS").
- **Facts, not provider objects, in the state.** The pool a node belongs to, its processes, its volumes are all
  generic facts; the adapter supplies them in the same shape for every provider, with `native_type` alongside, and
  "no probe on file" becomes "not observed by a probe" (the `OBSERVED_BY` edge decides what is sent).
- **Every judged property says so.** In this document a property filled by Jev is marked as such where it is defined
  and points here; an agent reading `role_confidence: 0.84` knows it is a classifier's probability over a closed list,
  with the call auditable in `jev_calls`.

---

## 6. Provider mapping

How each provider's objects land. Blank means the provider has no such thing; the generic node is simply absent and
verdict edges still exist.

| generic | AWS | GCP | Azure | Vercel | Cloudflare |
|---|---|---|---|---|---|
| Account | account | project | subscription | team | account |
| Compute | EC2 instance | GCE instance | VM | | |
| Function | Lambda | Cloud Function | Function App | serverless, edge function | Worker |
| Deployment | Beanstalk env, ECS service, k8s workload on EKS | Cloud Run, k8s workload on GKE | App Service, k8s workload on AKS | project deployment | Pages project |
| Cluster | EKS, ECS cluster | GKE | AKS | | |
| NodePool | ASG, Karpenter, node group | MIG, node pool | VMSS | | |
| Database | RDS, Aurora | Cloud SQL | SQL, Cosmos | Postgres | D1 |
| Cache | ElastiCache | Memorystore | Cache for Redis | KV | KV |
| Messaging | SQS, SNS, Kinesis | Pub/Sub | Service Bus | Queues | Queues |
| Storage | S3, EFS, EBS, snapshots, Backup vaults | GCS, PD, Filestore, backup vaults | Blob, Disk, Files, Recovery Services vaults | Blob | R2 |
| LoadBalancer | ALB, NLB, GWLB, CLB | GLB | LB, Front Door | edge (implicit) | edge (implicit) |
| Domain / Zone / Record | Route 53 | Cloud DNS | Azure DNS | domains | zones |
| Certificate | ACM | managed certs | Key Vault certs | automatic | universal SSL |
| Identity / Policy | IAM | IAM | Entra | members, tokens | members, tokens |
| Secret | Secrets Manager, SSM, KMS | Secret Manager, Cloud KMS | Key Vault | env vars | secrets |
| Analytics | Athena workgroup | BigQuery | Synapse | | |
| Stack | CloudFormation stack | Deployment Manager, Terraform | ARM / Bicep deployment, Terraform | | |
| BackupPlan | AWS Backup plan | Backup and DR plan | Backup policy | | |
| Detector / ThreatFinding | GuardDuty | Security Command Center | Defender for Cloud | | |
| Image | AMI, ECR image | image, Artifact Registry | image, ACR | | |
| Network | VPC | network | VNet | project (flat) | zone (flat) |
| Segment | subnet | subnet | subnet | | |
| RouteTable / Gateway | route table, IGW, NAT, TGW, peering, endpoint | routes, Cloud NAT | route table, NAT GW | | |
| Interface | ENI | NIC | NIC | | |
| PublicIp | EIP | static IP | public IP | | anycast |
| Filter | security group, NACL, WAF | firewall, Cloud Armor | NSG, ASG, WAF | deployment protection, firewall, password, SSO, trusted IPs | WAF, access policies |
| Endpoint | port, listener, RDS endpoint, function URL | port, forwarding rule | port, listener | deployment URL, function route | route |

## 7. What the AWS adapter already has

Everything below is in SQLite today and only needs mirroring in the generic shape:

- `inventory_ec2` (with vpc, subnet, security groups, public IP, IPv6 in the snapshot), `inventory_rds`,
  `inventory_elasticache`, `inventory_elb` (listeners and target groups), `inventory_lambda`, `inventory_s3`,
  `inventory_ebs`, `inventory_route53_*`.
- `inventory_vpc`, `inventory_sg`, `sg_ingress` (every ingress rule), `sg_eni` (interfaces and the groups they wear),
  `nacls` (entries and subnet associations).
- The exposure code (`src/instance_apps.ts`) that already produces `allowed_by`, `blocked_by`, `nacl_note` per port.

Not collected yet: subnets as objects, route tables, internet and NAT gateways as network objects, EIPs, egress rules,
peering and transit attachments, VPC endpoints, certificates, IAM, secrets, images and packages.

- **Platform services (2026-10-05).** Certificates (ACM), messaging (SNS), keys (KMS), file systems (EFS), backups
  (Backup vaults and plans), analytics (Athena), stacks (CloudFormation), web ACLs (WAF) and threat detection
  (GuardDuty, with its findings) in one table, `inventory_service`, one collector per service in `src/services/`,
  mirrored as the generic nodes above with their edges (`src/graph_services.ts`). Nor the workloads
inside clusters: EKS and ECS are seen as nodes (EC2) and processes (probe), never as Deployments or services, so
`AdvisorDeployment` on AWS today means Beanstalk environments only; reading the Kubernetes API (through the probe
or the cluster endpoint) and ECS services is new collection.

- **Software and vulnerabilities (2026-10-03).** `AdvisorPackage` per installed version (dpkg, rpm, apk, binary
  versions, kernel, OS) with `INSTALLED_ON`, `PROVIDES` and `RUNS_IMAGE`; `KnVulnerability` from OSV (Ubuntu, Debian,
  Alpine, Rocky, AlmaLinux) and the Amazon Linux updateinfo feed, `AFFECTS`, and the `VULNERABLE_TO` verdict judged by
  the affected program's listening ports. Daily `VULN_CRON`; Security page section; `docs/ontology.md` §1b.

## 8. Migration plan

1. **Generic layer in place on AWS.** Add the generic labels to the existing nodes (`AdvisorResource` keeps its label
   and gains `AdvisorCompute` \| `AdvisorDatabase` \| `AdvisorCache` \| `AdvisorLoadBalancer`), add `provider`,
   `native_type`, `native_id`, `health`, the `AdvisorTelemetry` nodes with `OBSERVED_BY` edges; make the
   `resource_role` state generic (§5b); rename `KnSystem.kind` and `KnSystemType.kind` with `native_kind` kept;
   mirror the inventories not in the graph yet (Lambda as `AdvisorFunction`, S3 and EBS as `AdvisorStorage`, Route 53
   as DNS nodes with `POINTS_TO`, Beanstalk environments as `AdvisorDeployment`). Update `SCHEMA_SUMMARY`, the graph
   tools, the Knowledge page and the prompts to the generic words. Rewrite `docs/ontology.md` from this file when done.
2. **Network layer on AWS.** Mirror VPCs, security groups, rules, NACLs and interfaces from what is collected; add
   subnets, route tables, gateways, EIPs and egress rules to the inventory; write `AdvisorEndpoint` for ports,
   listeners and service endpoints with `FORWARDS_TO`; materialise `REACHABLE_FROM`, `ALLOWED_BY`, `BLOCKED_BY` from
   the exposure code, extended to balancers, RDS and ElastiCache.
3. **Software layer.** Probe step for packages and versions (dpkg, rpm, binary versions, container images and
   digests, kernel); `AdvisorPackage`, `AdvisorImage`, `INSTALLED_ON`, `PROVIDES`. Then `KnVulnerability` from OSV
   with `AFFECTS` and the `VULNERABLE_TO` verdict. At this point a vulnerable process inside a cluster is found on
   its node, but not yet tied to a workload.
   *Done 2026-10-03* (`src/software_inventory.ts`, `src/software_vulns.ts`, `src/alas_feed.ts`, `src/graph_software.ts`;
   `docs/ontology.md` §1b). What the build settled: the probe reads the **source package** too (`${source:Package}`,
   `%{SOURCERPM}`, apk's origin) because OSV indexes distribution advisories by source, under **release-qualified
   ecosystems** (`Ubuntu:24.04:LTS`, `Debian:12`, `Alpine:v3.19`); the package node carries `source_name`,
   `advisory_ecosystem` and `scope` (service \| library \| kernel \| tool) for it. **Amazon Linux** is not in OSV,
   so its advisories come from the core repository's `updateinfo.xml.gz` (what `dnf updateinfo` reads), matched by
   binary package with rpm's version order. Ubuntu's and Debian's advisories carry no score: the CVE they fix lends its
   CVSS (`severity_from`), and their per-CVE records replace the USN/DSA bundles so one hole is one edge. The verdict's
   `criticality` comes from the ports the package's program listens on and their exposure; `RUNS_IMAGE` (compute →
   image) was added for the containers a plain box runs. Not yet: `CONTAINS` (packages inside images), workload-level
   verdicts, lockfile ecosystems, RHEL/SUSE feeds, `blocked_by` on the edge.
4. **Cluster workloads (EKS, ECS).** The step that makes `AdvisorDeployment` complete on AWS. It is planned here so
   steps 1 to 3 leave room for it, and it can run after them without reshaping anything.
   - *Collect.* For each `AdvisorCluster`: Kubernetes Deployments, StatefulSets, DaemonSets, Jobs and CronJobs,
     their pod templates (containers, images, resource requests), Services, Ingresses and NetworkPolicies, read
     from the Kubernetes API; ECS services and task definitions (containers, images, ports, target groups) from the
     AWS API. Two ways to reach the Kubernetes API, decided per cluster: through the probe on a node that already
     has cluster credentials (no new network path, needs a read-only ClusterRole bound to the node's identity), or
     directly from the advisor against the cluster endpoint with an IAM role mapped in `aws-auth` or an access
     entry (needs the endpoint reachable from where the advisor runs). Both are read-only, listing only.
   - *Produce.* One `AdvisorDeployment` per workload with `workload_kind`, `namespace`, `replicas_*`, `containers`,
     `revision` from the image tag, and `RUNS_IN` → the cluster; `BUILT_FROM` → one `AdvisorImage` per container,
     which is where `AdvisorPackage` nodes from the image scan attach; `EXPOSES` → an `AdvisorEndpoint` per Service
     port and per Ingress host and path, with `FORWARDS_TO` from the balancer listener the Ingress controller or the
     ECS target group fronts; a NetworkPolicy as an `AdvisorFilter {kind: network_policy}` with `GUARDED_BY` from
     the workload; `PART_OF` from each container the probe saw on a node to its workload, matched by the pod and
     container labels the runtime exposes.
   - *Verdicts.* Pod endpoints get `REACHABLE_FROM` through the chain Ingress → Service → NetworkPolicy → node
     security group, so "which workload runs the vulnerable Next.js and can the internet reach it" is answered
     inside a cluster the same way it is on Vercel.
   - *Cost.* Workloads join the `KnSystem` schematic as `kind: deployment` with `PART_OF` → the cluster system, so
     a cluster's list cost can be apportioned to its workloads by requests or by observed CPU.
5. **Playbooks from sources.** Replace the static catalogue in `src/playbooks.ts` with `KnPlaybook` nodes built by
   the agent from `KnSource` documents: the control documentation the benchmark mods ship, the provider's docs and
   advisories, with the saving rendered from the rule and the tier and effort judged. Sources are hashed and
   re-fetched on a schedule; a changed source rebuilds what cites it. The current hand-written entries serve only as
   the first set of sources to point the agent at and as the eval: a generated playbook should say at least what
   they say, with citations.
   *Built 2026-10-03* (`src/sources.ts`, `src/playbook_gen.ts`, `tasks/playbook/`, `docs/ontology.md` §1c). Sources are
   the installed mods' control blocks and documents (parsed from the `.pp` files; the CIS and Foundational Security
   benchmarks ship Remediation steps per control) and the provider pages they reference (allow-listed hosts, read as
   text, re-read weekly), each hashed. The agent writes a batch of four controls per run; Jev judges the tier (stricter
   only from approve) and the effort; the agent's confidence decides publication and a held row says why.
   `src/playbooks.ts` is a table of official sources per control; no playbook text is hand-written (the seed
   catalogue and its coverage check were removed on 2026-10-04 at the user's request). Not yet: `ADDRESSES`
   from a playbook to a vulnerability; the saving rendered from the rule's code (today the agent states the formula
   from the control's description).
6. **Provider adapter boundary.** Extract the AWS collection behind an adapter interface that emits the generic
   model; the SQLite tables become per-adapter storage.
   *Built 2026-10-03* (`src/adapters/types.ts`, `src/adapters/index.ts`, `src/adapters/aws/`). The contract: an
   adapter owns its credentials, its accounts (`AccountRecord`: provider, native_type, id, name, parent_id, access in
   words, actuator, enabled, last test), its collection, its storage (the SQLite tables it fills, listed on the
   adapter) and emits the generic model: `resources(account)` as `ResourceNode` rows plus the graph layers it writes
   (`layers`, in order). The AWS mapping moved from the mirror into `src/adapters/aws/resources.ts`; the mirror core
   reads the registry. Settings and the accounts API read the registry (`GET /api/providers`, `records` on
   `GET /api/accounts`); the four known providers without an adapter are stubs with what each will need. Finished 2026-10-03: the resource edges (listeners, endpoints, volumes, DNS, Beanstalk deployments) moved to
   `src/adapters/aws/edges.ts` behind `ProviderAdapter.edges()`, which returns the ids of extra nodes it creates so the
   core's gone-marking keeps them; the shared `REF_MERGE` fragment lives in `src/graph_cypher.ts` so adapters need
   nothing from the core at load time. The core writes nodes, prunes telemetry edges, calls the adapter's edges, marks
   gone, runs the adapter's layers; nothing in it names an AWS table. The per-account scope reaches recommendations,
   alerts and actions too.
7. **Second adapter: Vercel.** Projects, deployments, functions, domains, env vars, protection and firewall; usage
   and plan as `KnSystemType` and `KnPricingOverlay`; `REACHABLE_FROM internet` with `requires_auth` from deployment
   protection; `AdvisorPackage` from the framework and runtime versions. A good second adapter precisely because it
   is not a full cloud: it forces the model to stay abstract.
   *Built 2026-10-03* (`src/adapters/vercel/`: `client.ts`, `inventory.ts`, `index.ts`, `graph.ts`; `src/routes/vercel.ts`;
   Settings › Accounts › Add account › Vercel). What it does: the team (or personal account) is the `AdvisorAccount`
   (`native_type: team`); each project is an `AdvisorDeployment` (`native_type: vercel_project`, state from the
   latest production deployment, framework, `node <version>` runtime, repo, protection and firewall as properties);
   the production URL, verified domains and the latest deployment URL are `AdvisorEndpoint {kind: url, exposure:
   internet}` the project EXPOSES, each `REACHABLE_FROM internet {requires_auth, protection}` from the project's
   deployment protection per target; the Node runtime is an `AdvisorPackage {ecosystem: runtime}` INSTALLED_ON the
   project. Environment variables are stored by name, target and type only. Credentials are runtime settings
   (`VERCEL_TOKEN`, `VERCEL_TEAM_ID`); `VERCEL_CRON` collects every 30 minutes. The mirror core gained `mirrorAdapter`
   (account, resources, gone marking, layers for any adapter). Not yet: functions per deployment, usage and plan as
   `KnSystemType` / `KnPricingOverlay`, framework versions (the API gives the framework name only), the Vercel bill.
   Verified against a live team the same day. Added after that: the team's storage stores (`GET /v1/storage/stores`:
   marketplace integrations such as Neon and Redis, Vercel Blob, KV, Edge Config) as `AdvisorDatabase` /
   `AdvisorCache` / `AdvisorStorage` (`native_type: vercel_store`, `product`, `engine`, `plan`, `region`) with a
   `USES {environments}` edge from each connected project (a new generic edge: deployment → the data stores it
   depends on; AWS has no writer for it yet). The Steampipe `vercel` connection is written from the saved token for
   ad-hoc SQL. Secure Compute (`connectConfigurations`: a security group and subnets per environment) is on the project node
   (`secure_compute`, `secure_compute_security_groups`, `secure_compute_subnets`) and, when those ids exist in the AWS
   inventory, becomes `GUARDED_BY {via: vercel_secure_compute}` → `AdvisorFilter` and `IN_SEGMENT` → `AdvisorSegment`,
   (usage: `/v2/usage` per type and day with a per-project breakdown gives requests, cache hits, bandwidth, function
   invocations by outcome and GB-hours, builds and their seconds, blob size and requests, cron runs, data cache and
   log volume; stored in `vercel_usage`, folded onto the project nodes as `usage_*_7d` and into the team overview)
   the same edges an instance has. In the live team the ids belong to the network Vercel manages in its own AWS
   account, not to the user's, so no edge is drawn and the project card says so; the link to the user's VPC is the
   peering Vercel sets up, which the Network page lists under gateways when it exists.
   The usage rows are keyed by project as well (`vercel_usage(team_id, project_id, day, type)`): requests and builds
   are read per project through `/v2/usage?projectId=` (exact numbers), the other types team-wide, so a project node
   and the project detail panel (Inventory › Deployments, `GET /api/vercel/projects/:id`) carry their own series. The
   `bill` capability (declared by AWS and Vercel) gates the This month page; for a Vercel team it is
   `GET /api/vercel/bill`: the subscription and period, the metered usage since the period started with the
   per-project split, the invoices with groups and line items, and the unit prices the last paid invoice implies
   (the team's own rates). Those prices are knowledge now (`src/adapters/vercel/pricing.ts`): `KnSystemType
   {kind: usage, source: team_billing}` per metered item from the team object (cents per unit there, dollars per
   unit here, with the unit the item is priced per), `{kind: plan}` for the Pro plan, one type per price line of each
   marketplace plan a store is on (`source: marketplace_plan`, the quotas on a plan type as `included`), and
   `{source: invoice}` for what the last paid invoice charged per unit; `KnPricingOverlay {kind: plan}` for the
   subscription and each store's plan, COVERS those types. Projects and stores are `KnSystem`s (kind deployment /
   database / cache / storage) RUNS_ON the types with last month's quantity and `list_usd_month`; `monthly_list_usd`
   on the system and `monthly_usd` on the resource are the project's last 30 days at the team's rates or the store's
   marketplace usage at its plan, so a Vercel project is priced the way an instance is. Stores carry everything the
   store object says (size, objects, access, plan lines, partner metadata, external id and status, secret names,
   period usage such as Neon compute hours); the team's members (role, MFA) and log drains are read as well, the
   latter now the team's log layer (`src/adapters/vercel/logs.ts`): one `KnLogGroup {native_type: log_drain, host,
   sources, environments, sampling_rate, all_projects}` per drain, the team's metered log volume split across the
   enabled drains as `ingest_gb_day` and priced at the team's rate, `SHIPS_LOGS_TO` from each covered project
   system, from the account when the drain covers every project, and from the project resource (`via: log drain`).
   `logAttributionReport(limit, account)`, `GET /api/graph/logs?account=` and the `graph_log_groups` tool read any
   account's destinations; `graph_systems` takes an account too, and the MCP server carries three Vercel tools
   (`vercel_projects`, `vercel_stores`, `vercel_bill`) and a schema summary that describes the Vercel shapes and the
   pricing knowledge, so the agent reads the graph the way it is written.
   The partners behind the stores (`src/adapters/vercel/partners.ts`, keys under Settings › Accounts › Vercel ›
   Partners) add what Vercel does not relay: Neon's storage, branches, compute endpoints with autoscaling and
   suspend timeout, consumption this period and IP allow list; Redis Cloud's memory used against its limit,
   persistence, replication, eviction, throughput, public endpoint, TLS and source IPs. They land flat on the
   `AdvisorDatabase` / `AdvisorCache` node and as `AdvisorEndpoint {kind: service_endpoint, protocol: postgres|redis,
   requires_auth, restricted_to}` `REACHABLE_FROM internet`, so "which databases can any address reach" is the
   same query on Neon, Redis Cloud and an RDS instance behind a security group.
   Findings and recommendations are provider-neutral records too (`src/adapters/vercel/rules.ts`): a rules pass is
   an `AdvisorRun {native_type: rules_pass, provider: vercel}` in the team's account, its alarms are
   `AdvisorControl {id: vercel.control.*} -[:FLAGGED]->` the project or store, and the actionable ones are
   `AdvisorRecommendation` nodes `TARGETS` those resources with the same tiers, decisions and `DECIDED_AS` edges the
   AWS rules get. `runs.provider` names which provider a run belongs to, so "the latest run" is always asked per
   provider. The general view across accounts (`accountsOverview` + `generalOverview`) reads these per provider and
   sums only what means the same thing.

## 8a. Accounts and providers in Settings

The model has one `AdvisorAccount` per boundary the advisor was pointed at; Settings has to be where those are added,
and it has to work the same for a provider with a hierarchy (AWS Organizations, GCP folders, Azure management groups)
and one without (a Vercel team).

**The Accounts list.** One row per `AdvisorAccount`: provider, the provider's own word (`native_type`: account,
project, subscription, team), id, name, parent, how the advisor authenticates (credential source), whether the
actuator may act there, last collection and its result, and what covers it (the `AdvisorTelemetry` kinds that have
edges there). Today's "Member accounts" card (`src/accounts.ts`, parent plus children through roles) is the AWS
version of this list and becomes one provider's rows in it.

**Add account** picks the provider first and then runs that provider's credential flow; each adapter declares it:

| provider | boundary | credentials | children |
|---|---|---|---|
| AWS | account | a role to assume from the advisor's identity (read role, optional actuator role), or keys / profile for the first one | the Organizations management account lists its members (`organizations:ListAccounts`); each member needs the same read and actuator roles, deployed once as a StackSet; children are discovered, confirmed one by one, not typed |
| GCP | project | a service account key or workload identity | folders and the organisation list projects; one service account with org-level viewer covers them |
| Azure | subscription | a service principal (tenant, client, secret or certificate) | the tenant and management groups list subscriptions |
| Vercel | team | a team access token (read scope; a second token for actions) | none: a team is a leaf; a personal account is a team of one |
| Cloudflare | account | an API token scoped to the account | none |

**Parent and child.** The parent is a real `AdvisorAccount` (`kind: organization`), the children are `kind: account`
with `parent_id`, and every resource, run, action and alert hangs off the child it lives in, never the parent. What the
parent adds:

- *Discovery*: it is where children are listed from, and a child that appears or disappears is a finding.
- *Billing*: consolidated billing sits at the payer, so the bill reconstruction and the Savings Plan overlay are read
  there and apportioned per child (Cost Explorer's linked-account dimension); a child's `KnPricingOverlay` is the
  payer's with `covers_account`.
- *Credentials*: the advisor assumes each child's role from the parent's identity, as today; the parent's own
  resources are mirrored like any account's.
- *Scope*: every page and tool filters by account and defaults to all; the graph query tool never needs to, since
  `account_id` is on every owned node.

**Actions per account.** The actuator role is per account and optional: a child without one is dry-run only there,
which the row shows. The executor's `Creds.forAccount` already picks credentials per ledger row; it stays per
`AdvisorAction.account_id`.

**Status 2026-10-03.** The Settings UI is accounts-first (the Accounts tab lists every account from the registry;
an account opens its provider's sections); the sidebar's "Looking at" picks the scope every read carries
(`?account=`), honoured by the inventories, clusters, cost findings and security findings; Overview › Accounts is the
general view (resources and list cost, last bill, findings, security, vulnerability verdicts, open recommendations and
alerts attributed through their resource, probe coverage). Not yet: the generic accounts setting, add flows for other
providers, the scope on recommendations, alerts and actions lists.

**What changes in code.** `src/accounts.ts` becomes the AWS adapter's account module behind a generic registry
(`accounts` setting: provider, native_type, id, name, parent_id, credentials reference, actuator flag, enabled);
collection iterates the registry per adapter; the Settings page gets the Accounts list with per-provider add flows
and the discovery step for providers that have one. Jev's role classification and the rules are already per resource
and need nothing.

## 9. Open decisions

- Whether the v1 labels `AdvisorPort` and `AdvisorNodePool.name` as key are dropped at the end of step 1 or kept one
  release longer for the UI.
- Where the vulnerability feed runs: in the advisor (OSV batch API, cached in SQLite) or in a shared service for all
  advisors.
- Whether the Accounts revamp (§8a) lands before the second adapter or with it; the registry shape is needed by
  both.
- Whether identities and policies are in scope for step 1 or deferred to the security work that already exists
  (`aws_compliance` controls flag IAM today without nodes).
- Which sources count as authoritative for playbooks per provider (the benchmark mods' documentation, the provider's
  user guides and Well-Architected pillars, Trusted Advisor and Compute Optimizer text), and whether a generated
  playbook is published to agents at once or only after a person marks it `reviewed`.
- How the Kubernetes API is reached in step 4 (through the probe on a node, or from the advisor against the cluster
  endpoint), and whether image package scans run on the node (the probe reads the image filesystem) or against the
  registry (ECR image scanning results through the API).

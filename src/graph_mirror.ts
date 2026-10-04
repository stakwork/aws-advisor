import neo4j, { Driver, Session } from "neo4j-driver";
import { config } from "./config.js";
import { db, getJsonSetting } from "./db.js";
import { listPlaybooks } from "./playbooks.js";
import { awsAdapter } from "./adapters/aws/index.js";
import { alertLevel } from "./alert_level.js";

/**
 * One-way mirror of the advisor's operational data into Neo4j, in the provider-neutral model of
 * docs/cloud-ontology.md, so the agent, NavFiber and Neo4j Browser can walk resources, endpoints, recommendations,
 * decisions, incidents and actions next to the code graph and the team's Concepts. SQLite stays the source of
 * truth: the advisor never reads this mirror back, every mirror function is idempotent (MERGE on the id), and the
 * whole thing can be wiped and resynced at any time (`mirrorAll`, `POST /api/graph/sync`). Every write is
 * fire-and-forget from the hooks: a failing Neo4j is logged (at most once a minute) and never breaks a run, a
 * decision or the UI. With `NEO4J_URI` unset every function here is a no-op.
 *
 * The model is generic; this file is also the AWS adapter's mapping onto it. Every resource node carries the base
 * label `AdvisorResource` plus one specific label (`AdvisorCompute`, `AdvisorDatabase`, ...), and the properties
 * `provider`, `native_type` and `native_id`, so an agent reads `kind`-free generic labels and finds the provider's
 * word in `native_*`. Labels are prefixed `Advisor` (records of things that exist) or `Kn` (knowledge, rebuilt from
 * the records: src/graph_knowledge.ts); the Neo4j is shared with stakgraph / repo2graph, whose nodes are never
 * touched, and the only foreign label used is `Concept`, MATCHed by id to link a decided recommendation to the
 * team's decision or rule.
 */

export { RESOURCE_LABELS } from "./adapters/types.js";
export type { ResourceLabel, GenericState, TelemetryKind, ResourceNode } from "./adapters/types.js";
import { AWS, RESOURCE_LABELS, type ResourceLabel, type ResourceNode, type TelemetryKind } from "./adapters/types.js";
import { TELEMETRY, telemetryId, poolId, lambdaArn, inventoryIdOf, guessedType, type RoleMap } from "./adapters/aws/resources.js";
import { resourceAccountIndex } from "./resource_index.js";
export const PROVIDER = AWS;
export const BATCH = 250;
export const QUERY_TIMEOUT_MS = 5_000;
export const QUERY_ROW_CAP = 200;

/** The specific resource labels; every node with one of these also carries AdvisorResource. */

export const LABELS = ["AdvisorAccount", "AdvisorResource", ...RESOURCE_LABELS, "AdvisorResourceRef", "AdvisorNodePool", "AdvisorTelemetry", "AdvisorRecommendation", "AdvisorRun", "AdvisorControl", "AdvisorAlert", "AdvisorIncident", "AdvisorAction", "AdvisorPass", "AdvisorApp", "AdvisorEndpoint", "AdvisorPressureEvent", "AdvisorSecurityScan", "AdvisorPackage", "AdvisorImage"] as const;

/** v1 labels that no longer exist; removed once per process so a graph written by the old mirror comes clean. */
export const LEGACY_LABELS = ["AdvisorRole", "AdvisorPort", "AdvisorPlaybook", "KnService", "KnPattern"] as const;

/** The schema as told to the agent (graph_query tool) and shown in the README. */
export const SCHEMA_SUMMARY = [
  "Every node carries provider (aws), account_id, native_type (the provider's word: ec2_instance, rds_instance, s3_bucket, ...), native_id and updated_at. Resources carry the base label AdvisorResource plus one of: AdvisorCompute {type, arch, platform, private_ips, public_ip, hostname, lifecycle, pool, cpu_30d, launch_time}, AdvisorDatabase {engine, engine_version, type, cluster, storage_gb, storage_type, multi_az, publicly_accessible, encrypted, backup_retention_days, endpoint_host, port, cpu_30d}, AdvisorCache {engine, engine_version, type, nodes, group}, AdvisorLoadBalancer {kind: application|network|gateway|classic, scheme: public|internal, dns_name, targets, healthy, requests_30d, gb_30d, asgs, ecs_services}, AdvisorFunction {runtime, runtime_version, memory_mb, timeout_s, arch, invocations_30d, errors_30d, duration_avg_ms, invocations_month, gb_seconds_month}, AdvisorStorage {kind: object|block, size_gb, objects, class, iops, throughput_mibps, encrypted, versioning, lifecycle_rules, public, attached_to, device}, AdvisorDeployment {platform: beanstalk, workload_kind: environment}, AdvisorDnsZone {private, records}, AdvisorDnsRecord {fqdn, type, ttl, values, alias, routing, link_state}",
  "Identities: (:AdvisorIdentity {native_type: iam_user, kind: user, name, human (console access), console_access, mfa, admin (AdministratorAccess or an inline Allow * on *), credentials (active access keys), credential_age_days (the oldest active key), last_used_at (password or key), groups, policies (names only), permissions_boundary, access_keys (masked id, status, age, last use), created_at}) -[:IN_ACCOUNT]-> the account; a Vercel team member is not a node yet (the team's members are counted on the Overview)",
  "Accounts: (:AdvisorAccount {id, provider, native_type: account|team|project, kind: account, name, parent_id, role: management|member|standalone, enabled, access (how the advisor reaches it, in words), actuator (it may act there), last_test_ok, last_test_at}); a member of an AWS organisation -[:PART_OF]->(the management account); every resource, run, pass and scan -[:IN_ACCOUNT]-> the account it was collected from (a member's resources hang off the member, not the parent)",
  "Shared resource properties: id (the provider's id or ARN), name, state (running|stopped|pending|terminated|available|degraded|unknown) and native_state, region, zone, monthly_usd (a month at list), role (the judged archetype), role_confidence, protected_prob, gone, first_seen, last_seen; (:AdvisorResource)-[:IN_ACCOUNT]->(:AdvisorAccount {id, kind: account, provider}); (:AdvisorResource)-[:HAS_ROLE]->(:KnArchetype {id, name, description}); (:AdvisorCompute)-[:IN_POOL]->(:AdvisorNodePool {id, name, kind: asg|karpenter|node_group|batch}); (:AdvisorCompute)-[:STORES_ON]->(:AdvisorStorage {kind: block}); (:AdvisorDnsRecord)-[:IN_ZONE]->(:AdvisorDnsZone); (:AdvisorDnsRecord)-[:POINTS_TO]->(resource | :AdvisorResourceRef); (:AdvisorDeployment)-[:RUNS_ON_POOL]->(:AdvisorNodePool), -[:BACKED_BY]->(:AdvisorLoadBalancer)",
  "What the advisor can see of a resource is an edge, not a flag: (:AdvisorResource)-[:OBSERVED_BY {since, last_at, status: ok|stale|offline, detail}]->(:AdvisorTelemetry {id, kind: api|metrics|probe, native: steampipe|cloudwatch|ssm_probe}); no probe edge means the advisor cannot look inside the box (a database never has one; an EC2 instance without one has no Systems Manager agent). An EC2 node also carries its health checks: health (ok|impaired|initializing|unknown), health_host, health_instance, health_storage, scheduled_events, health_checked_at",
  "(:AdvisorResource)-[:EXPOSES {gone}]->(:AdvisorEndpoint {id, kind: port|listener|service_endpoint|url, protocol: tcp|udp|http|https|tls, port, hostname, bind, scope: all|loopback|address, exposure: internet|network|group|closed|local, process, container, container_port, tls, first_seen, last_seen, gone}) something listening: a port a probe saw on a box (probe 1.8, exposure from the security group ingress rules: internet = 0.0.0.0/0 or ::/0 lets it in), a balancer listener, a database endpoint, a function URL; (:AdvisorApp)-[:SERVES]->(:AdvisorEndpoint) the program or container behind a port; (:AdvisorEndpoint {kind: listener})-[:FORWARDS_TO {target_group, health}]->(:AdvisorEndpoint) a balancer listener to the instance ports or function it fronts",
  "(:AdvisorResource)-[:RUNS {user, count, cpu_pct, rss_bytes, oldest_seconds, command, first_seen, last_seen, probes, gone}]->(:AdvisorApp {id, name, kind: app|infra}) what runs on a box, from the probe's process list with the OS daemons left out (kind infra = container runtime, monitoring agents); gone = true when the program was there and is not any more",
  "AdvisorCompute and AdvisorNodePool carry the usage profile (src/usage_profile.ts: 28 days of metrics and probes folded into the hours of the week): usage_quiet_hours_week, usage_confidence, usage_schedule (the advisor:schedule value that keeps it up whenever it was used, UTC), usage_off_hours_week, usage_est_usd_month, usage_quiet_windows, usage_summary, usage_computed_at, and Jev's daily review: usage_review_verdict (confirm|adjust|keep_running), usage_review_schedule, usage_review_confidence, usage_review_reason, usage_reviewed_at; a compute node that is one customer's environment carries tenant = true with cost_month_usd, cost_compute_usd, cost_storage_usd, cost_snapshot_usd, cost_ip_usd, last_use_at, idle_days, parked, nudge; wake_enabled, wake_domains, wake_profile when the doorman wakes it on traffic",
  "AdvisorNodePool (a Beanstalk group) carries the capacity pattern: capacity_learned_min (168 integers, the MinSize the executor sets per hour of the week, index 0 = Sunday 00:00 UTC), capacity_wanted (what the signals needed per hour, p95 across weeks), capacity_trigger (what the trigger ran), capacity_binding (168 signal names), capacity_signals, capacity_floor and capacity_ceiling (the band a person set), capacity_weeks, capacity_coverage, capacity_confident, capacity_summary; (:AdvisorNodePool)-[:PRESSURED_AT]->(:AdvisorPressureEvent {id, at, ring, desired, max_size, signal, value, cpu_avg, note}) once per hour the group was pinned at its ceiling under load; (:AdvisorAction)-[:ANSWERED]->(:AdvisorPressureEvent) when a ceiling raise answered it",
  "(:AdvisorRecommendation {id, fingerprint, title, action: stop|terminate|rightsize|migrate_arch|change_storage_tier|release_address|delete_snapshot|delete|enable_logging|schedule|security_fix|other, native_action, tier: auto|approve|report, status: open|pending|approved|rejected|snoozed|done|stale, source: rules|agent, rule, est_monthly_saving, confidence, decided_by, decided_at, decision_scope: internal|generic, created_at, verdict, realised_usd_month, realised_ratio})-[:TARGETS]->(resource | :AdvisorResourceRef {id, guessed_type}); -[:DECIDED_AS]->(:Concept) when the team's decision was mirrored as a Concept (the Concept holds the decision, its reason and the rule); -[:PROPOSED_IN]->(:AdvisorRun {id, started_at, finished_at, status, trigger, findings_count, recommendations_count}); -[:FROM_INCIDENT]->(:AdvisorIncident {id, status, cause, confidence, episode_cost_usd, monthly_run_rate_usd, created_at})-[:INVESTIGATES]->(:AdvisorAlert {id, kind, level: info|warning|alarm, message, created_at, acknowledged, acknowledged_by, cause_status, cause, cause_actor, cause_actor_kind: person|advisor|automation|provider|unknown, cause_via, cause_event, cause_at})-[:ABOUT]->(resource | :AdvisorResourceRef); (:AdvisorAlert)-[:CAUSED_BY]->(:AdvisorAction) when the advisor's own change caused it",
  "(:AdvisorControl {id, title, framework: cost|cis|foundational_security|advisor, category: cost|security, severity, benchmark})-[:FLAGGED {run_id, reason}]->(resource) for the latest completed cost run's alarm findings; -[:SECURITY_FLAGGED {scan_id, reason, severity, first_seen_at}]->(resource) for the latest security scan; (:AdvisorControl)-[:HAS_PLAYBOOK]->(:KnPlaybook {id, control_id, title, meaning, act_when, ignore_when, steps, saving, tier, effort, generated_by, review_status}); (:AdvisorSecurityScan {id, status, alarms, new_alarms, resolved, counts})-[:IN_ACCOUNT]->(:AdvisorAccount); security recommendations are AdvisorRecommendation with action security_fix",
  "(:AdvisorAction {id, kind, status: proposed|applied|verified|failed|refused|reverted|stale, mode: dry_run|apply, trigger: schedule|manual, title, reason, rollback, est_usd_month, result, error, created_at, seen_at, applied_at, verified_at, reverted_at, stage, new_resource, bill_verdict, realised_usd_month})-[:TARGETS]->(resource | :AdvisorResourceRef) the executor's ledger: every change the agent planned, made, read back or undid; -[:CARRIES_OUT]->(:AdvisorRecommendation) when it executes an approved recommendation; -[:LAUNCHED]->(:AdvisorResourceRef) the instance a relaunch created; -[:TOUCHED_IN {event: apply|verify|revert|advance|step, outcome, at, detail}]->(:AdvisorPass {id, started_at, finished_at, trigger, mode, proposed, fresh, applied, verified, failed, refused, held, stale, took_ms, errors}) the executor's activity log, one node per pass",
  "Knowledge layer (Kn, rebuilt on every sync): (:KnSystem {id, name, kind: instance|autoscaled_group|cluster|database_cluster|database|cache_group|cache|function|gateway, native_kind, archetype, member_count, storage_gb, storage_usd_month, monthly_list_usd, gone}) our systems as a schematic; (:AdvisorResource)-[:MEMBER_OF]->(:KnSystem); (:KnSystem)-[:IS_A]->(:KnArchetype); (:KnSystem)-[:PART_OF]->(:KnSystem) a pool inside its cluster; (:KnSystem)-[:RUNS_ON {count, hours_month, list_price, list_usd_month}]->(:KnSystemType {id, provider, kind: compute|database|cache|transfer|usage, native_kind, sku, region, engine, list_price, price_unit, source}); (:KnPricingOverlay {kind: commitment|reservation, discount_rate, commitment_usd_month, sku, count, end})-[:COVERS]->(:KnSystemType); (:KnSystem|:AdvisorAccount)-[:TRANSFERS_TO {mechanism: nat|cross-az, gb_day, price_per_gb, usd_month, source}]->(:KnDestination {id: internet|regional, name}) where outbound bytes go and what they cost; the internet node is also an AdvisorSource; AdvisorRecommendation carries verdict, realised_usd_month, realised_ratio once verified",
  "(:KnSystem|:AdvisorAccount)-[:SHIPS_LOGS_TO {gb_day, usd_month, attributed_by}]->(:KnLogGroup {id, name, region, retention_days, stored_gb, ingest_gb_day, ingest_usd_month, storage_usd_month, owner, attributed_by, candidates, tags, jev_choice, jev_confidence}) the system a log group belongs to (attributed_by says how: 'observed: cloudwatch-agent on i-..', 'tag service=x', 'lambda function name', 'name tokens: ..', 'jev: <system> at 80%' when the evidence rules found nothing and Jev picked); a group on the account node is unattributed; (:AdvisorResource)-[:SHIPS_LOGS_TO {via: cloudwatch-agent|awslogs|fluent-bit|fluentd|docker-daemon|docker:<container>, source, observed_at}]->(:KnLogGroup) is what an instance's own agent config says it writes to (probe 1.6)",
  "Network layer: (:AdvisorNetwork {id: vpc, cidr_blocks, ipv6_blocks, default, flat}); (:AdvisorSegment {id: subnet, cidr, zone, public (its route table sends 0.0.0.0/0 to an internet gateway), auto_public_ip, available_ips})-[:IN_NETWORK]->(network), -[:USES_ROUTE_TABLE]->(:AdvisorRouteTable {id, main, routes}), -[:GUARDED_BY]->(:AdvisorFilter {kind: network_acl}); (:AdvisorRouteTable)-[:ROUTES {destination, state, origin}]->(:AdvisorGateway {id, kind: internet|nat|egress_only|peering|endpoint|transit|vpn, state, public_ip, service, endpoint_type, peer_network_id} | :AdvisorInterface | resource); (:AdvisorNetwork)-[:PEERS_WITH {state, cidrs, via}]->(:AdvisorNetwork); (:AdvisorInterface {id: eni, private_ips, public_ip, ipv6, mac, interface_type, owner_kind, status, source_dest_check})-[:ATTACHED_TO]->(resource | :AdvisorGateway), -[:IN_SEGMENT]->(segment), -[:WEARS]->(:AdvisorFilter {kind: security_group}); (:AdvisorPublicIp {id, ip, associated})-[:ASSIGNED]->(interface | gateway); (:AdvisorGateway {kind: nat})-[:MEMBER_OF]->(:KnSystem) the priced NAT system",
  "(:AdvisorFilter {id, kind: security_group|network_acl, stateful, default_action: deny, default, name, description, rules, attached})-[:HAS_RULE]->(:AdvisorFilterRule {id, direction: ingress|egress, action: allow|deny, protocol: tcp|udp|icmp|any, from_port, to_port (null = all), priority (ACL rule number), source_kind: internet|cidr|filter|prefix_list|any, source, description, dormant (an IPv6 rule in a network without IPv6)})-[:FROM]->(:AdvisorSource {id: internet|cidr:<cidr>|prefix:<id>, kind, label, cidr, private} | :AdvisorFilter) where the rule lets traffic in from; resources wear filters directly: (resource)-[:GUARDED_BY]->(:AdvisorFilter), (resource)-[:IN_NETWORK]->(network), (:AdvisorCompute)-[:IN_SEGMENT]->(segment)",
  "Verdicts, computed so no query has to re-implement them: (:AdvisorEndpoint)-[:REACHABLE_FROM {protocol, port, via_rule, through: [rule and ACL entry ids passed], note, requires_auth}]->(:AdvisorSource | :AdvisorFilter) who can reach an endpoint (the internet, a CIDR, a prefix list, or members of another group); (:AdvisorEndpoint)-[:ALLOWED_BY {source}]->(:AdvisorFilterRule) the rule that lets a source in; (:AdvisorEndpoint)-[:BLOCKED_BY {source, reason}]->(:AdvisorFilterRule | :AdvisorFilter) what stops a source a rule would admit (a network ACL entry or its implicit deny; the security groups when no rule matches); endpoints also carry exposure, reach_reason, reach_computed_at. Covers instance ports (groups + public address + subnet ACL), balancer listeners (groups + scheme) and database endpoints (groups + publicly_accessible). Example, a vulnerable sshd (OS daemons such as sshd are not AdvisorApp nodes, so go by the port and the endpoint's process): MATCH (r:AdvisorCompute)-[:EXPOSES]->(e:AdvisorEndpoint {kind: 'port', port: 22}) WHERE e.gone = false OPTIONAL MATCH (e)-[:REACHABLE_FROM]->(s:AdvisorSource {id: 'internet'}) OPTIONAL MATCH (e)-[b:BLOCKED_BY]->(x) RETURN r.name, e.process, e.exposure, s IS NOT NULL AS internet, collect(b.reason)",
  "Software: (:AdvisorPackage {id: pkg:<ecosystem>:<name>:<version>, name, version, ecosystem: deb|rpm|apk|binary|kernel|os, source_name (the source package the advisories name: openssh for openssh-server), source_kind: dpkg|rpm|apk|binary_version|uname|os_release, advisory_ecosystem (the feed's name for the box's distribution: Ubuntu:24.04:LTS, Debian:12, Alpine:v3.19, Amazon Linux:2023), scope: service|library|kernel|tool})-[:INSTALLED_ON {arch, path, first_seen, last_seen, gone}]->(compute) what the software probe found installed, one node per version shared by every box that has it; (:AdvisorPackage)-[:PROVIDES]->(:AdvisorApp) the program a package ships, when it is seen running; (compute)-[:RUNS_IMAGE {image_id, first_seen, last_seen, gone}]->(:AdvisorImage {id: image:<reference>, name, kind: container, repository, tag, digest, created_at, platform}) the container images a box runs (workloads are BUILT_FROM the same nodes)",
  "Vulnerabilities (general area, shared, no account_id): (:KnVulnerability {id (the advisory: USN-, DSA-, DLA-, ALAS-, GHSA-, CVE- ids), source: osv|alas, aliases, cves, summary, severity: critical|high|medium|low|null (unrated), cvss (score), cvss_vector, attack_vector: network|adjacent|local|physical, severity_from (the CVE that lent its score when the advisory had none), cwe, published, modified, url})-[:AFFECTS {fixed_in, ecosystem}]->(:AdvisorPackage) the package versions it matches, from OSV (Ubuntu, Debian, Alpine, Rocky, AlmaLinux) and the Amazon Linux updateinfo feed. Verdict: (compute)-[:VULNERABLE_TO {package, packages, version, fixed_in, reachable: internet|network|local|none, criticality: critical (the affected program listens on a port the internet can reach) | exposed (the network or another group can) | mitigated (it listens but the groups or ACL block it) | local_only (loopback only, or the attack needs local access) | affected (installed; a library, kernel or tool with no listening program of its own), via_endpoint, process, port, exposure, computed_at}]->(:KnVulnerability)",
  "Clusters and workloads: (:AdvisorCluster {id: arn, kind: kubernetes|ecs, version, endpoint_public, public_cidrs, authentication_mode, access_status: ok|unauthorized|forbidden|unreachable|tls|error, nodes, workloads, namespaces})-[:EXPOSES]->(:AdvisorEndpoint {kind: api}) the control plane endpoint with its REACHABLE_FROM (requires_auth true); (:AdvisorNodePool)-[:PART_OF]->(:AdvisorCluster); (:AdvisorDeployment {id, name, namespace, platform: eks|ecs, workload_kind: deployment|statefulset|daemonset|job|cronjob|ecs_service|environment, replicas_desired, replicas_ready, health: ok|degraded|severe|unknown, containers, images, revision, strategy, labels})-[:RUNS_IN]->(:AdvisorCluster); -[:BUILT_FROM]->(:AdvisorImage {id: image:<ref>, name, repository, tag}); -[:SCHEDULED_ON {pods}]->(:AdvisorCompute) the nodes its pods run on; -[:EXPOSES]->(:AdvisorEndpoint {kind: service_endpoint (a Service port: hostname <svc>.<ns>.svc, service_type) | url (an Ingress host and path)}); an Ingress url FORWARDS_TO its Service endpoint, and the balancer listener in front FORWARDS_TO the url (edge via ingress_controller) so the listener's REACHABLE_FROM is copied onto it; (:AdvisorEndpoint)-[:FRONTED_BY]->(:AdvisorLoadBalancer | :AdvisorResourceRef) the balancer an Ingress or LoadBalancer Service created; (:AdvisorDeployment)-[:GUARDED_BY]->(:AdvisorFilter {kind: network_policy, namespace, policy_types})-[:HAS_RULE]->(:AdvisorFilterRule) the NetworkPolicies whose podSelector matches it; (:AdvisorFilter {kind: network_policy})-[:IN_CLUSTER]->(:AdvisorCluster)",
  "Platform providers use the same labels with their own native_type (provider: vercel, account_id: the team id, AdvisorAccount {kind: team}). A Vercel project is (:AdvisorDeployment {native_type: vercel_project, platform: vercel, framework, node_version, repo, git_provider, production_url, latest_state (READY|ERROR|...), latest_target, latest_at, protection_sso|protection_password|protection_trusted_ips (which deployment URLs ask for authentication), firewall_enabled, env_count, secure_compute (functions run inside an AWS VPC), secure_compute_security_groups, secure_compute_subnets, usage_requests_7d, usage_invocations_7d, usage_errors_7d, usage_bandwidth_out_gb_7d, usage_builds_7d, monthly_usd (its last 30 days at the team's rates)}); it -[:EXPOSES]->(:AdvisorEndpoint {kind: url, hostname, url, target: production|preview, requires_auth, via: sso|password|trusted_ips|null, domain}) one per production URL, custom domain and latest deployment URL, each -[:REACHABLE_FROM {requires_auth, note}]->(:AdvisorSource {id: internet}); (:AdvisorPackage {ecosystem: runtime, name: node})-[:INSTALLED_ON]->(project); (project)-[:USES {environments}]->(store); (project)-[:GUARDED_BY {via: vercel_secure_compute}]->(:AdvisorFilter) and -[:IN_SEGMENT]->(:AdvisorSegment) only when the Secure Compute network is in the AWS inventory",
  "A Vercel store is (:AdvisorDatabase | :AdvisorCache | :AdvisorStorage {native_type: vercel_store, product (Neon, Redis, Vercel Blob), engine, plan, plan_id, plan_lines, store_type, projects, external_id (the resource's id at the partner, a Neon project id), external_status, billing_state, quota_exceeded, size_gb, objects, access, token_expired (blob), high_availability, storage_type (redis), auth (Neon Auth), secret_names (names only), compute_hours_period and usage_period_start (Neon compute hours this billing period), monthly_usd (at the plan's listed rate at this period's pace)})",
  "Logs on a platform provider: a Vercel log drain is (:KnLogGroup {native_type: log_drain, name, host (where it delivers), status, sources: [lambda|edge|static|build|external], environments, sampling_rate, format, all_projects, ingest_gb_day (the team's metered log volume, split evenly across its enabled drains), ingest_usd_month (at the team's logDrainsVolume rate), owner (the project system when the drain lists exactly one), attributed_by}); (:KnSystem vercel_project)-[:SHIPS_LOGS_TO]->(drain) for every project it covers, (:AdvisorAccount team)-[:SHIPS_LOGS_TO]->(drain) when it covers them all, (project:AdvisorDeployment)-[:SHIPS_LOGS_TO {via: 'log drain'}]->(drain); a project with no SHIPS_LOGS_TO edge keeps no logs beyond Vercel's retention",
  "Prices as knowledge, every provider: (:KnSystemType {kind: usage|plan|database|cache|storage, source: team_billing (the team's own metered rates, dollars per unit) | marketplace_plan (a store plan's price lines, quotas as included) | invoice (what the last paid invoice charged per unit, amount over quantity) | pricing_api | pricebook, sku, list_price, price_unit, unit, note, included}); (:KnPricingOverlay {kind: plan, sku, count (seats), commitment_usd_month, included, start, end})-[:COVERS]->(:KnSystemType) the subscription and each store's plan; (:KnSystem {kind: deployment|database|cache|storage, native_kind: vercel_project|vercel_store, monthly_list_usd, usage_units})-[:RUNS_ON {count, list_price, list_usd_month}]->(:KnSystemType) a project's or store's last month priced line by line; the resource -[:MEMBER_OF]->(:KnSystem). Ask 'what does project X cost' as MATCH (s:KnSystem {name: 'X'})-[r:RUNS_ON]->(t) RETURN t.note, r.count, r.list_usd_month, s.monthly_list_usd",
  "The operational patterns, the team's decisions and the generic rules are Concepts (label Concept, in repo2graph) under the parents 'AWS Operational Patterns', 'AWS Cost Decisions' and 'AWS Cost Knowledge'",
].join("\n");

export const enabled = () => Boolean(config.neo4jUri);

/** The URI without credentials, for the UI and logs. */
export function graphUriForDisplay(uri = config.neo4jUri): string | null {
  if (!uri) return null;
  try { const u = new URL(uri); return `${u.protocol}//${u.host}`; } catch { return uri.replace(/\/\/[^@/]*@/, "//"); }
}

// ---- driver, logging ----------------------------------------------------------------------------------------

let driver: Driver | null = null;
/** Drops the cached driver so the next call connects with the current settings. */
export function resetGraphDriver(): void { const d = driver; driver = null; if (d) d.close().catch(() => { /* closing */ }); }
function getDriver(): Driver {
  if (!driver) {
    driver = neo4j.driver(config.neo4jUri, neo4j.auth.basic(config.neo4jUser, config.neo4jPassword), {
      disableLosslessIntegers: true,
      connectionTimeout: 5_000,
      connectionAcquisitionTimeout: 10_000,
      maxConnectionPoolSize: 10,
    });
  }
  return driver;
}

const session = (mode: "READ" | "WRITE"): Session =>
  getDriver().session({ defaultAccessMode: mode === "READ" ? neo4j.session.READ : neo4j.session.WRITE, ...(config.neo4jDatabase ? { database: config.neo4jDatabase } : {}) });

const LOG_INTERVAL_MS = 60_000;
let lastLogAt = 0;
let suppressed = 0;
/** Errors from the fire-and-forget hooks are logged at most once a minute; the ones in between are counted. */
function logError(what: string, e: unknown) {
  const now = Date.now();
  if (now - lastLogAt < LOG_INTERVAL_MS) { suppressed++; return; }
  const extra = suppressed ? ` (${suppressed} earlier error${suppressed === 1 ? "" : "s"} not shown)` : "";
  suppressed = 0;
  lastLogAt = now;
  console.error(`[graph] ${what} failed: ${String((e as any)?.message || e).slice(0, 300)}${extra}`);
}

/** Runs a mirror step in the background; never throws. */
export const inventoryIdsOf = (account: string) => inventoryIds(account);
export const tableExistsIn = (name: string) => tableExists(name);
export function inBackground(what: string, fn: () => Promise<unknown>): void {
  if (!enabled()) return;
  void fn().catch((e) => logError(what, e));
}

export async function closeGraph(): Promise<void> {
  if (driver) { const d = driver; driver = null; await d.close().catch(() => {}); }
}

// ---- the AWS adapter's mapping lives in src/adapters/aws/resources.ts; re-exported here for the tests and the modules that import it from the mirror
export { genericState, poolOf, POOL_KIND, poolId, TELEMETRY, telemetryId, resourceFromEc2, resourceFromRds, resourceFromElasticache, resourceFromElb, lambdaArn, resourceFromLambda, resourceFromS3, resourceFromEbs, resourceFromZone, resourceFromDnsRecord, elbEdges, inventoryIdOf, guessedType } from "./adapters/aws/resources.js";
export type { RoleRow, RoleMap, ElbEdges } from "./adapters/aws/resources.js";

const num = (v: unknown): number | null => (v == null || v === "" || !Number.isFinite(Number(v)) ? null : Number(v));
const str = (v: unknown): string | null => (v == null ? null : String(v));
const safeJson = (s: unknown): any => { if (typeof s !== "string") return s ?? null; try { return JSON.parse(s); } catch { return null; } };

/** The provider-specific action_type of a recommendation mapped onto the generic verb; the original stays in native_action. */
export const ACTION_VERB: Record<string, string> = {
  stop_instance: "stop", terminate_stopped_instance: "terminate", rightsize_instance: "rightsize", migrate_graviton: "migrate_arch", migrate_to_graviton: "migrate_arch",
  release_eip: "release_address", delete_snapshot: "delete_snapshot", enable_flow_logs: "enable_logging", aurora_set_storage_iopt: "change_storage_tier", delete_everything: "delete",
  schedule_hours: "schedule", security_fix: "security_fix", other: "other",
};
export const actionVerb = (actionType: string): string => ACTION_VERB[actionType] ?? (/(delete|remove)/.test(actionType) ? "delete" : /(stop|park)/.test(actionType) ? "stop" : /schedule/.test(actionType) ? "schedule" : "other");

export interface RecommendationNode {
  id: number; fingerprint: string; title: string; action: string; native_action: string; tier: string; status: string; source: string; rule: string;
  est_monthly_saving: number | null; confidence: number | null; decided_by: string | null; decided_at: string | null; decision_scope: string | null; created_at: string | null;
  resource: string | null; resource_id: string | null; guessed_type: string | null; concept_id: string | null; run_id: number | null; incident_id: number | null;
}

export function recommendationNode(row: any, inventoryIds: Set<string>, concepts: Map<string, string>): RecommendationNode {
  const ev = safeJson(row.evidence) || {};
  const runId = num(row.run_id);
  const conceptId = concepts.get(String(row.fingerprint));
  const resource = str(row.resource);
  return { id: Number(row.id), fingerprint: String(row.fingerprint), title: String(row.title), action: actionVerb(String(row.action_type)), native_action: String(row.action_type), tier: String(row.tier), status: String(row.status),
    source: String(row.source), rule: String(row.rule), est_monthly_saving: num(row.est_monthly_saving), confidence: num(row.confidence), decided_by: str(row.decided_by),
    decided_at: str(row.decided_at), decision_scope: str(row.decision_scope), created_at: str(row.created_at), resource,
    resource_id: inventoryIdOf(resource, inventoryIds), guessed_type: resource ? guessedType(resource) : null, concept_id: conceptId || null, run_id: runId && runId > 0 ? runId : null, incident_id: num(ev.incident_id) };
}

export interface AlertNode {
  id: number; kind: string; level: string; message: string; created_at: string; acknowledged: boolean; acknowledged_by: string | null; resource: string | null; resource_id: string | null; guessed_type: string | null;
  /** Why it happened (src/alert_cause.ts): the sentence, who, of what kind, through what, and the advisor's ledger row when it was the advisor. */
  cause_status: string | null; cause: string | null; cause_actor: string | null; cause_actor_kind: string | null; cause_via: string | null; cause_event: string | null; cause_at: string | null; cause_action_id: number | null;
}

/** The level rule of src/alert_level.ts is duplicated here in its result only; the message is cut so a node stays small. */
export function alertNode(row: any, inventoryIds: Set<string>, level: string): AlertNode {
  const resource = str(row.resource);
  return { id: Number(row.id), kind: String(row.kind), level, message: String(row.message || "").slice(0, 500), created_at: String(row.created_at), acknowledged: Boolean(row.acknowledged),
    acknowledged_by: str(row.acknowledged_by), resource, resource_id: inventoryIdOf(resource, inventoryIds), guessed_type: resource ? guessedType(resource) : null, ...causeFields(row.cause) };
}

function causeFields(raw: unknown): Pick<AlertNode, "cause_status" | "cause" | "cause_actor" | "cause_actor_kind" | "cause_via" | "cause_event" | "cause_at" | "cause_action_id"> {
  let c: any = null;
  try { c = typeof raw === "string" ? JSON.parse(raw) : null; } catch { /* none */ }
  const kind = str(c?.actor_kind);
  return { cause_status: str(c?.status), cause: c?.summary ? String(c.summary).slice(0, 300) : null, cause_actor: str(c?.actor), cause_actor_kind: kind === "aws" ? "provider" : kind, cause_via: str(c?.via),
    cause_event: str(c?.event_name), cause_at: str(c?.event_time), cause_action_id: c?.action_id != null ? Number(c.action_id) : null };
}

export interface ActionNode {
  id: number; kind: string; status: string; mode: string; trigger: string; title: string; reason: string; rollback: string | null; est_usd_month: number | null; result: string | null; error: string | null;
  resource: string; resource_name: string | null; resource_id: string | null; guessed_type: string | null; region: string | null; created_at: string; seen_at: string | null; applied_at: string | null; verified_at: string | null; reverted_at: string | null;
  recommendation_ids: number[];
  /** A staged change (a relaunch): the stage it is at and the instance it launched, if any. */
  stage: string | null; new_resource: string | null;
  /** What the bill did after this kind of change on this resource (src/verify.ts, action_verifications): the latest verdict and USD/month. */
  bill_verdict: string | null; realised_usd_month: number | null;
}

/** One executor ledger row (src/executor.ts) as a node; the recommendations it carries out come from its facts. */
export function actionNode(row: any, inventoryIds: Set<string>): ActionNode {
  const facts = safeJson(row.facts_json) || {};
  const ids = [num(facts.recommendation_id), ...(Array.isArray(facts.recommendation_ids) ? facts.recommendation_ids.map(num) : [])].filter((n, i, a): n is number => n != null && n > 0 && a.indexOf(n) === i);
  const resource = String(row.resource);
  return { id: Number(row.id), kind: String(row.kind), status: String(row.status), mode: String(row.mode), trigger: String(row.trigger), title: String(row.title), reason: String(row.reason || "").slice(0, 1000),
    rollback: str(row.rollback), est_usd_month: num(row.est_usd_month), result: row.result ? String(row.result).slice(0, 500) : null, error: row.error ? String(row.error).slice(0, 500) : null,
    resource, resource_name: str(row.resource_name), resource_id: inventoryIdOf(resource, inventoryIds), guessed_type: guessedType(resource), region: str(row.region), created_at: String(row.created_at), seen_at: str(row.seen_at),
    applied_at: str(row.applied_at), verified_at: str(row.verified_at), reverted_at: str(row.reverted_at), recommendation_ids: ids,
    stage: str(facts.stage), new_resource: str(facts.new_instance_id), bill_verdict: str(row.bill_verdict), realised_usd_month: num(row.realised_usd_month) };
}

export interface IncidentNode { id: number; alert_id: number; status: string; cause: string | null; confidence: number | null; episode_cost_usd: number | null; monthly_run_rate_usd: number | null; created_at: string }

export function incidentNode(row: any): IncidentNode {
  return { id: Number(row.id), alert_id: Number(row.alert_id), status: String(row.status), cause: row.cause ? String(row.cause).slice(0, 1000) : null, confidence: num(row.confidence),
    episode_cost_usd: num(row.episode_cost_usd), monthly_run_rate_usd: num(row.monthly_run_rate_usd), created_at: String(row.created_at) };
}

export interface RunNode { id: number; started_at: string; finished_at: string | null; status: string; trigger: string; findings_count: number; recommendations_count: number }

export function runNode(row: any): RunNode {
  return { id: Number(row.id), started_at: String(row.started_at), finished_at: str(row.finished_at), status: String(row.status), trigger: String(row.trigger),
    findings_count: num(row.findings_count) ?? 0, recommendations_count: num(row.recommendations_count) ?? 0 };
}

/** Where a control comes from and what it is about, read off its id. */
export function controlFacts(controlId: string, benchmark?: string | null): { framework: string; category: string } {
  const id = controlId.toLowerCase();
  const b = String(benchmark || "").toLowerCase();
  if (id.startsWith("aws_compliance.") || b) return { framework: b.includes("cis") || id.includes("cis_") ? "cis" : b.includes("foundational") || id.includes("foundational") ? "foundational_security" : "compliance", category: "security" };
  if (id.startsWith("aws_thrifty.")) return { framework: "cost", category: "cost" };
  if (id.startsWith("vercel.control.")) return { framework: "advisor", category: /mfa|open|firewall|ip_allow|source_ips/.test(id) ? "security" : /suspend|branches|unconnected|cache_cold/.test(id) ? "cost" : "reliability" };
  return { framework: "advisor", category: /security|exposed|public|sg_/.test(id) ? "security" : "cost" };
}

export interface FlagEdge { control_id: string; control_title: string | null; resource_id: string; run_id: number; reason: string | null }

/** Alarm findings of one run whose resource is in the inventory, one edge per (control, resource); the rest are skipped. */
export function flagEdges(findings: any[], inventoryIds: Set<string>, runId: number): FlagEdge[] {
  const seen = new Set<string>();
  const out: FlagEdge[] = [];
  for (const f of findings) {
    const rid = inventoryIdOf(f.resource, inventoryIds);
    if (!rid) continue;
    const key = `${f.control_id}|${rid}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ control_id: String(f.control_id), control_title: str(f.control_title), resource_id: rid, run_id: runId, reason: f.reason ? String(f.reason).slice(0, 500) : null });
  }
  return out;
}

/** The generic health summary of an EC2 instance from its three status checks. */
export function healthOf(system: string | null, instance: string | null, storage: string | null): "ok" | "impaired" | "initializing" | "unknown" {
  const all = [system, instance, storage].map((s) => String(s || "").toLowerCase());
  if (all.some((s) => s === "impaired")) return "impaired";
  if (all.some((s) => s === "initializing")) return "initializing";
  if (all.every((s) => s === "ok" || s === "not-applicable")) return "ok";
  return "unknown";
}

// ---- Cypher guard for the read-only graph_query tool -----------------------------------------------------------

const stripCypherLiterals = (q: string) => q
  .replace(/'(?:[^'\\]|\\.)*'/g, "''")
  .replace(/"(?:[^"\\]|\\.)*"/g, '""')
  .replace(/`(?:[^`])*`/g, "``")
  .replace(/\/\/[^\n]*/g, " ")
  .replace(/\/\*[\s\S]*?\*\//g, " ");

const CYPHER_FORBIDDEN = /\b(create|merge|set|delete|detach|remove|drop|load|foreach|alter|grant|deny|revoke|start|stop|terminate)\b/i;

/** Accepts one read-only Cypher statement: starts with MATCH / OPTIONAL MATCH / WITH / CALL { ... }, no write clause, no apoc or dbms procedure. */
export function guardReadCypher(input: string): { cypher: string } | { error: string } {
  const cypher = String(input || "").trim().replace(/;+\s*$/, "").trim();
  if (!cypher) return { error: "empty query" };
  const bare = stripCypherLiterals(cypher);
  if (bare.includes(";")) return { error: "only a single statement is allowed" };
  if (!/^\s*(match\b|optional\s+match\b|with\b|call\s*\{)/i.test(bare)) return { error: "the query must start with MATCH, OPTIONAL MATCH, WITH or CALL { ... }" };
  const bad = bare.match(CYPHER_FORBIDDEN);
  if (bad) return { error: `the query contains "${bad[1].toUpperCase()}"; only read-only Cypher is allowed` };
  if (/\bcall\s+(apoc\.|dbms\.|gds\.|db\.(create|drop|index|constraint))/i.test(bare) || /\bapoc\./i.test(bare)) return { error: "procedures under apoc, dbms and gds are not allowed" };
  return { cypher };
}

// ---- reading (the graph_query tool and the resource endpoint) ----------------------------------------------------

/** Neo4j values as plain JSON: nodes become their properties plus _labels, relationships their properties plus _type. */
export function plain(v: any): any {
  if (v == null) return v;
  if (neo4j.isInt(v)) return v.toNumber();
  if (neo4j.isNode(v)) return { _labels: v.labels, ...mapValues(v.properties) };
  if (neo4j.isRelationship(v)) return { _type: v.type, ...mapValues(v.properties) };
  if (neo4j.isPath(v)) return { _path: v.segments.map((s: any) => ({ start: plain(s.start), relationship: plain(s.relationship), end: plain(s.end) })) };
  if (neo4j.isDate(v) || neo4j.isDateTime(v) || neo4j.isLocalDateTime(v) || neo4j.isTime(v) || neo4j.isLocalTime(v) || neo4j.isDuration(v)) return v.toString();
  if (Array.isArray(v)) return v.map(plain);
  if (typeof v === "object") return mapValues(v);
  return v;
}
const mapValues = (o: Record<string, any>) => Object.fromEntries(Object.entries(o).map(([k, x]) => [k, plain(x)]));

export interface ReadResult { columns: string[]; rows: Record<string, any>[]; row_count: number; truncated: boolean }

/** One read transaction with a timeout and a row cap; throws on transport or Cypher errors. */
export async function readQuery(cypher: string, params: Record<string, unknown> = {}, opts: { timeoutMs?: number; rowCap?: number } = {}): Promise<ReadResult> {
  if (!enabled()) throw new Error("the graph mirror is not configured (NEO4J_URI)");
  const cap = opts.rowCap ?? QUERY_ROW_CAP;
  const s = session("READ");
  try {
    const res = await s.executeRead((tx) => tx.run(cypher, neoParams(params)), { timeout: opts.timeoutMs ?? QUERY_TIMEOUT_MS });
    const columns = res.records[0]?.keys.map(String) ?? [];
    const rows = res.records.slice(0, cap).map((r) => mapValues(r.toObject()));
    return { columns, rows, row_count: rows.length, truncated: res.records.length > cap };
  } finally { await s.close(); }
}

/** A write in one transaction; used by the knowledge layer too. */
export async function writeCypher(cypher: string, params: Record<string, unknown> = {}): Promise<void> { return write(cypher, params); }

/**
 * JavaScript numbers go to Neo4j as floats unless wrapped, which would store ports, counts and ids as 80.0 and 3.0;
 * every whole number in the parameters is sent as a Neo4j integer instead (reads come back as plain numbers through
 * disableLosslessIntegers). Fractional values stay floats.
 */
export function neoParams<T>(v: T): T {
  if (typeof v === "number") return (Number.isInteger(v) && Math.abs(v) < 2 ** 53 ? neo4j.int(v) : v) as T;
  if (Array.isArray(v)) return v.map(neoParams) as T;
  if (v && typeof v === "object" && !neo4j.isInt(v)) return Object.fromEntries(Object.entries(v as Record<string, unknown>).map(([k, x]) => [k, neoParams(x)])) as T;
  return v;
}

async function write(cypher: string, params: Record<string, unknown> = {}): Promise<void> {
  const s = session("WRITE");
  try { await s.executeWrite((tx) => tx.run(cypher, neoParams(params)), { timeout: 60_000 }); }
  finally { await s.close(); }
}

// ---- schema -------------------------------------------------------------------------------------------------------

let schemaReady = false;
/** Unique constraints (which carry an index) on the id of every label, indexes on the resource's provider, account and native type; the v1 labels are removed. Once per process. */
export async function ensureSchema(): Promise<void> {
  if (schemaReady || !enabled()) return;
  for (const label of LABELS) await write(`CREATE CONSTRAINT ${label.toLowerCase()}_id IF NOT EXISTS FOR (n:${label}) REQUIRE n.id IS UNIQUE`);
  await write("CREATE CONSTRAINT knarchetype_id IF NOT EXISTS FOR (n:KnArchetype) REQUIRE n.id IS UNIQUE");
  await write("CREATE CONSTRAINT knplaybook_id IF NOT EXISTS FOR (n:KnPlaybook) REQUIRE n.id IS UNIQUE");
  await write("CREATE CONSTRAINT knvulnerability_id IF NOT EXISTS FOR (n:KnVulnerability) REQUIRE n.id IS UNIQUE");
  await write("CREATE INDEX advisorpackage_name IF NOT EXISTS FOR (n:AdvisorPackage) ON (n.name)");
  for (const prop of ["account_id", "provider", "native_type"]) await write(`CREATE INDEX advisorresource_${prop} IF NOT EXISTS FOR (n:AdvisorResource) ON (n.${prop})`);
  // the v1 mirror's labels and keys: dropped so the graph holds one vocabulary (a resync rebuilds everything from SQLite)
  for (const old of ["advisorrole_name", "advisornodepool_name", "advisorport_id", "advisorplaybook_id", "knservice_id"]) await write(`DROP CONSTRAINT ${old} IF EXISTS`);
  await wipeLegacy();
  schemaReady = true;
}

/** Removes the nodes the v1 mirror wrote under labels that no longer exist (only ever ours; nothing else is touched). */
export async function wipeLegacy(): Promise<{ deleted: number }> {
  if (!enabled()) return { deleted: 0 };
  let deleted = 0;
  for (const label of LEGACY_LABELS) deleted += await deleteWhere(`MATCH (n:${label})`, {});
  return { deleted };
}

// ---- the account and the helpers every step shares -------------------------------------------------------------------

/**
 * The AWS account the mirrored data belongs to by default (rows that carry no account id, the unscoped reads): the one
 * the credentials resolve to now, else the latest run's, else "unknown". The credentials come first because runs are
 * history: after the advisor is re-pointed from a member to the parent, the runs still name the member until the next
 * one completes (the adapter's primaryAccountId follows the same order).
 */
export function accountId(): string {
  const meta = getJsonSetting<{ accountId?: string }>("aws_credentials_meta", {});
  if (meta.accountId) return meta.accountId;
  const run = db.prepare("select account_id from runs where provider = 'aws' and account_id is not null and account_id <> '' order by id desc limit 1").get() as { account_id: string } | undefined;
  return run?.account_id || "unknown";
}

const now = () => new Date().toISOString();

const tableExists = (name: string) => Boolean(db.prepare("select 1 from sqlite_master where type = 'table' and name = ?").get(name));
const rowsOf = (sql: string, ...params: unknown[]): any[] => { try { return db.prepare(sql).all(...params) as any[]; } catch { return []; } };

/**
 * Member accounts (src/accounts.ts): which account a record belongs to, for the nodes derived from records rather than
 * inventory rows (recommendations, alerts, actions, ports, packages, pools). The row's own stamp when it has one, else
 * the account of the resource it names (src/resource_index.ts), else null, which the Cypher reads as the mirror's account.
 */
function accountResolver(account = accountId()): (explicit: unknown, ...resources: (string | null | undefined)[]) => string | null {
  const idx = resourceAccountIndex(account);
  return (explicit, ...resources) => { if (explicit && /^\d{12}$/.test(String(explicit))) return String(explicit); for (const r of resources) { const a = idx.of(r); if (a) return a; } return null; };
}

/** Every id the mirror writes a resource node for, so references in records can be matched to nodes. */
function inventoryIds(account = accountId()): Set<string> {
  const ids = new Set<string>();
  for (const r of rowsOf("select instance_id as id from inventory_ec2")) ids.add(r.id);
  for (const r of rowsOf("select db_instance_identifier as id from inventory_rds")) ids.add(r.id);
  for (const r of rowsOf("select cache_cluster_id as id from inventory_elasticache")) ids.add(r.id);
  for (const r of rowsOf("select arn as id from inventory_elb")) ids.add(r.id);
  for (const r of rowsOf("select name, arn, region from inventory_lambda")) ids.add(lambdaArn(r, account));
  for (const r of rowsOf("select name as id from inventory_s3")) ids.add(r.id);
  for (const r of rowsOf("select volume_id as id from inventory_ebs")) ids.add(r.id);
  for (const r of rowsOf("select zone_id as id from inventory_route53_zone")) ids.add(r.id);
  return ids;
}

/** fingerprint -> concept id from the concepts table (created by src/concepts.ts; absent in a bare database). */
function conceptIds(): Map<string, string> {
  try { return new Map((db.prepare("select fingerprint, concept_id from concepts where concept_id <> ''").all() as { fingerprint: string; concept_id: string }[]).map((r) => [r.fingerprint, r.concept_id])); }
  catch { return new Map(); }
}

function roleMap(): RoleMap {
  return new Map((db.prepare("select resource_id, role, role_confidence, protected_prob from resource_roles").all() as any[]).map((r) => [String(r.resource_id), { role: String(r.role), role_confidence: num(r.role_confidence), protected_prob: num(r.protected_prob) }]));
}

const chunks = <T,>(items: T[], size = BATCH): T[][] => { const out: T[][] = []; for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size)); return out; };

/** The account node and its telemetry nodes, for any adapter: the provider's word for the boundary and its sources. */
async function mirrorAccount(account: string, provider: string = PROVIDER, telemetry: Record<TelemetryKind, { native: string }> = TELEMETRY, nativeType = "account"): Promise<void> {
  await write("MERGE (a:AdvisorAccount {id: $id}) SET a.account_id = $id, a.provider = $provider, a.native_type = $native_type, a.native_id = $id, a.kind = 'account', a.updated_at = $now", { id: account, provider, native_type: nativeType, now: now() });
  await mirrorAccountRecords(provider);
  const rows = (Object.keys(telemetry) as TelemetryKind[]).filter((k) => telemetry[k].native !== "none").map((kind) => ({ id: `${provider}:${account}:telemetry:${kind}`, kind, native: telemetry[kind].native }));
  await write(`UNWIND $rows AS row MERGE (t:AdvisorTelemetry {id: row.id}) SET t.kind = row.kind, t.native = row.native, t.provider = $provider, t.account_id = $account, t.native_type = 'telemetry', t.native_id = row.id, t.updated_at = $now
    WITH t MATCH (a:AdvisorAccount {id: $account}) MERGE (t)-[:IN_ACCOUNT]->(a)`, { rows, account, provider, now: now() });
}

/** The account rows the registry describes, in the shape the graph keeps: one node per boundary with its name, how it is reached, whether it is enabled and may be acted in, and PART_OF from a member to its parent. */
export function accountRows(records: import("./adapters/types.js").AccountRecord[]): { id: string; provider: string; native_type: string; name: string | null; parent_id: string | null; enabled: boolean; access: string | null; actuator: boolean; role: "management" | "member" | "standalone"; kind: "account"; last_test_ok: boolean | null; last_test_at: string | null }[] {
  const parents = new Set(records.filter((r) => r.parent_id).map((r) => r.parent_id as string));
  return records.map((r) => ({ id: r.id, provider: r.provider, native_type: r.native_type, name: r.name || null, parent_id: r.parent_id ?? null, enabled: Boolean(r.enabled), access: r.access || null, actuator: Boolean(r.actuator),
    role: r.parent_id ? "member" : parents.has(r.id) ? "management" : "standalone", kind: "account", last_test_ok: r.last_test ? Boolean(r.last_test.ok) : null, last_test_at: r.last_test?.at ?? null }));
}

/** Every account of a provider as a node, members PART_OF their parent (an AWS organisation's management account; a provider without a hierarchy has no edge). */
async function mirrorAccountRecords(provider: string): Promise<void> {
  let records: import("./adapters/types.js").AccountRecord[] = [];
  try { const { allAccounts } = await import("./adapters/index.js"); records = (await allAccounts()).filter((r) => r.provider === provider); } catch { return; }
  const rows = accountRows(records); if (!rows.length) return;
  await write(`
UNWIND $rows AS row
MERGE (a:AdvisorAccount {id: row.id})
SET a += {account_id: row.id, provider: row.provider, native_type: row.native_type, native_id: row.id, kind: row.kind, name: row.name, parent_id: row.parent_id, enabled: row.enabled, access: row.access, actuator: row.actuator, role: row.role, last_test_ok: row.last_test_ok, last_test_at: row.last_test_at, updated_at: $now}
WITH a, row
OPTIONAL MATCH (a)-[old:PART_OF]->(:AdvisorAccount) WHERE row.parent_id IS NULL OR old IS NULL DELETE old
WITH DISTINCT a, row
OPTIONAL MATCH (p:AdvisorAccount {id: row.parent_id})
FOREACH (_ IN CASE WHEN p IS NULL THEN [] ELSE [1] END | MERGE (a)-[:PART_OF]->(p))`, { rows, now: now() });
}

/**
 * Any adapter but AWS, whole: its account node, the generic resource nodes it emits (marked gone when they stop
 * appearing), then its own layers. AWS goes through mirrorResources, which still writes its resource edges itself.
 */
export async function mirrorAdapter(adapter: import("./adapters/types.js").ProviderAdapter): Promise<{ resources: number; layers: Record<string, unknown> }> {
  if (!enabled() || !adapter.configured()) return { resources: 0, layers: {} };
  await ensureSchema();
  const account = adapter.primaryAccountId();
  const nativeType = (await adapter.accounts())[0]?.native_type ?? "account";
  await mirrorAccount(account, adapter.id, adapter.telemetry, nativeType);
  const rows = adapter.resources(account);
  const stamp = now();
  const toRow = (n: ResourceNode) => ({ ...n, pool_id: null, observed: n.observed.map((o) => ({ ...o, id: `${adapter.id}:${account}:telemetry:${o.kind}` })) });
  for (const label of RESOURCE_LABELS) {
    const mine = rows.filter((r) => r.label === label);
    for (const batch of chunks(mine)) await write(resourceCypher(label), { rows: batch.map(toRow), account, provider: adapter.id, now: stamp });
  }
  const extra = adapter.edges ? await adapter.edges(account, stamp) : [];
  await write("MATCH (r:AdvisorResource {provider: $provider, account_id: $account}) WHERE NOT r.id IN $ids AND coalesce(r.gone, false) = false SET r.gone = true, r.updated_at = $now", { provider: adapter.id, account, ids: [...rows.map((r) => r.id), ...extra], now: stamp });
  const layers: Record<string, unknown> = {};
  for (const layer of adapter.layers) { try { layers[layer.name] = await layer.mirror(); } catch (e) { logError(`${adapter.id} ${layer.name}`, e); } }
  return { resources: rows.length, layers };
}

import { REF_MERGE } from "./graph_cypher.js";
export { REF_MERGE };

// ---- resources ---------------------------------------------------------------------------------------------------

/** One statement per specific label (a label cannot be a parameter): the shared shape, the specific properties, the account, the role, the pool, the telemetry edges. */
const resourceCypher = (label: ResourceLabel) => `
UNWIND $rows AS row
MERGE (r:AdvisorResource {id: row.id})
SET r:${label}
SET r += row.props
SET r += {name: row.name, state: row.state, native_state: row.native_state, region: row.region, role: row.role, role_confidence: row.role_confidence, protected_prob: row.protected_prob,
          monthly_usd: row.monthly_usd, gone: row.gone, first_seen: row.first_seen, last_seen: row.last_seen, pool: row.pool,
          provider: $provider, account_id: coalesce(row.account_id, $account), native_type: row.native_type, native_id: row.id, updated_at: $now}
WITH r, row
OPTIONAL MATCH (r)-[oldAcc:IN_ACCOUNT]->(oa:AdvisorAccount) WHERE oa.id <> coalesce(row.account_id, $account) DELETE oldAcc
WITH DISTINCT r, row
MERGE (a:AdvisorAccount {id: coalesce(row.account_id, $account)}) ON CREATE SET a.provider = $provider, a.native_type = 'account', a.kind = 'account', a.native_id = coalesce(row.account_id, $account), a.account_id = coalesce(row.account_id, $account), a.updated_at = $now
MERGE (r)-[:IN_ACCOUNT]->(a)
WITH r, row
OPTIONAL MATCH (r)-[oldRole:HAS_ROLE]->(x:KnArchetype) WHERE row.role IS NULL OR x.id <> row.role
DELETE oldRole
WITH DISTINCT r, row
OPTIONAL MATCH (r)-[oldPool:IN_POOL]->(y:AdvisorNodePool) WHERE row.pool_id IS NULL OR y.id <> row.pool_id
DELETE oldPool
WITH DISTINCT r, row
FOREACH (_ IN CASE WHEN row.role IS NULL THEN [] ELSE [1] END |
  MERGE (ro:KnArchetype {id: row.role}) ON CREATE SET ro.name = row.role, ro.updated_at = $now
  MERGE (r)-[:HAS_ROLE]->(ro))
FOREACH (_ IN CASE WHEN row.pool_id IS NULL THEN [] ELSE [1] END |
  MERGE (p:AdvisorNodePool {id: row.pool_id}) SET p.name = row.pool, p.kind = coalesce(row.pool_kind, p.kind), p.account_id = coalesce(row.account_id, $account), p.provider = $provider, p.native_type = 'autoscaling_pool', p.native_id = row.pool, p.updated_at = $now
  MERGE (r)-[:IN_POOL]->(p))
WITH r, row
UNWIND row.observed AS o
MATCH (t:AdvisorTelemetry {id: o.id})
MERGE (r)-[e:OBSERVED_BY]->(t) ON CREATE SET e.since = coalesce(row.first_seen, $now)
SET e.status = o.status, e.last_at = o.last_at, e.detail = o.detail, e.updated_at = $now`;

/** A resource's OBSERVED_BY edges to the telemetry kinds its row no longer claims go. */
const OBSERVED_PRUNE_CYPHER = `
UNWIND $rows AS row
MATCH (r:AdvisorResource {id: row.id})-[e:OBSERVED_BY]->(t:AdvisorTelemetry)
WHERE NOT t.kind IN row.kinds
DELETE e`;

/** EC2, RDS, ElastiCache, balancers, Lambda, S3, EBS and Route 53 as resource nodes; resources the graph has but the inventory no longer lists are marked gone. */
export async function mirrorResources(): Promise<{ resources: number }> {
  if (!enabled()) return { resources: 0 };
  await ensureSchema();
  const account = accountId();
  await mirrorAccount(account);
  // the adapter emits the generic nodes from its own storage
  const rows: ResourceNode[] = awsAdapter.resources(account);
  const stamp = now();
  const toRow = (n: ResourceNode) => ({ ...n, pool_id: n.pool ? poolId(n.account_id ?? account, n.pool) : null, observed: n.observed.map((o) => ({ ...o, id: telemetryId(account, o.kind) })) });
  for (const label of RESOURCE_LABELS) {
    const mine = rows.filter((r) => r.label === label);
    for (const batch of chunks(mine)) await write(resourceCypher(label), { rows: batch.map(toRow), account, provider: PROVIDER, now: stamp });
  }
  for (const batch of chunks(rows.map((r) => ({ id: r.id, kinds: r.observed.map((o) => o.kind) })))) await write(OBSERVED_PRUNE_CYPHER, { rows: batch });
  // the adapter's own edges (listeners, endpoints, volumes, DNS, deployments on AWS) and the extra nodes they create
  const extra = awsAdapter.edges ? await awsAdapter.edges(account, stamp) : [];
  await write("MATCH (r:AdvisorResource {provider: $provider}) WHERE r.account_id IN $accounts AND NOT r.id IN $ids AND coalesce(r.gone, false) = false SET r.gone = true, r.updated_at = $now",
    { accounts: [...new Set([account, ...rows.map((r) => r.account_id).filter((x): x is string => Boolean(x))])], provider: PROVIDER, ids: [...rows.map((r) => r.id), ...extra], now: stamp });
  return { resources: rows.length };
}


// ---- recommendations ----------------------------------------------------------------------------------------------

const RECOMMENDATION_CYPHER = `
UNWIND $rows AS row
MERGE (rec:AdvisorRecommendation {id: row.id})
SET rec += {fingerprint: row.fingerprint, title: row.title, action: row.action, native_action: row.native_action, tier: row.tier, status: row.status, source: row.source, rule: row.rule,
            est_monthly_saving: row.est_monthly_saving, confidence: row.confidence, decided_by: row.decided_by, decided_at: row.decided_at, decision_scope: row.decision_scope,
            created_at: row.created_at, resource: row.resource, provider: $provider, account_id: coalesce(row.account_id, $account), native_type: 'recommendation', native_id: toString(row.id), updated_at: $now}
WITH rec, row
OPTIONAL MATCH (rec)-[t:TARGETS]->() DELETE t
WITH DISTINCT rec, row
OPTIONAL MATCH (rec)-[d:DECIDED_AS]->(oc:Concept) WHERE row.concept_id IS NULL OR oc.id <> row.concept_id
DELETE d
WITH DISTINCT rec, row
FOREACH (_ IN CASE WHEN row.resource_id IS NULL THEN [] ELSE [1] END |
  MERGE (res:AdvisorResource {id: row.resource_id})
  MERGE (rec)-[:TARGETS]->(res))
FOREACH (_ IN CASE WHEN row.resource_id IS NULL AND row.resource IS NOT NULL THEN [1] ELSE [] END |
  ${REF_MERGE("ref", "row.resource", "row.guessed_type", "recommendation")}
  MERGE (rec)-[:TARGETS]->(ref))
FOREACH (_ IN CASE WHEN row.run_id IS NULL THEN [] ELSE [1] END |
  MERGE (run:AdvisorRun {id: row.run_id}) SET run.account_id = coalesce(run.account_id, $account), run.provider = $provider
  MERGE (rec)-[:PROPOSED_IN]->(run))
FOREACH (_ IN CASE WHEN row.incident_id IS NULL THEN [] ELSE [1] END |
  MERGE (inc:AdvisorIncident {id: row.incident_id}) SET inc.account_id = coalesce(inc.account_id, $account), inc.provider = $provider
  MERGE (rec)-[:FROM_INCIDENT]->(inc))
WITH rec, row
OPTIONAL MATCH (c:Concept {id: row.concept_id})
FOREACH (_ IN CASE WHEN c IS NULL THEN [] ELSE [1] END | MERGE (rec)-[:DECIDED_AS]->(c))`;

/** Recommendations (all, or the given ids) with their target, run, incident and, when the concepts table maps the fingerprint and the Concept exists, the DECIDED_AS edge. */
export async function mirrorRecommendations(ids?: number[]): Promise<{ recommendations: number }> {
  if (!enabled()) return { recommendations: 0 };
  if (ids && !ids.length) return { recommendations: 0 };
  await ensureSchema();
  const account = accountId();
  await mirrorAccount(account);
  const inv = inventoryIds(account);
  const concepts = conceptIds();
  const raw = (ids
    ? db.prepare(`select * from recommendations where id in (${ids.map(() => "?").join(",")})`).all(...ids)
    : db.prepare("select * from recommendations").all()) as any[];
  const stamp = now();
  // the AWS rules' and the agent's rows under the primary account; a platform provider's rules (rule vercel_*) under its own account, targeting its own nodes
  const aws = raw.filter((r) => !/^vercel_/.test(String(r.rule)));
  const acct = accountResolver(account);
  const rows = aws.map((r) => { const node = recommendationNode(r, inv, concepts); return { ...node, account_id: acct(r.account_id, node.resource_id, node.resource) }; });
  for (const batch of chunks(rows)) await write(RECOMMENDATION_CYPHER, { rows: batch, account, provider: PROVIDER, now: stamp });
  const vercel = raw.filter((r) => /^vercel_/.test(String(r.rule)));
  if (vercel.length) {
    const team = (db.prepare("select id from vercel_team order by fetched_at desc limit 1").get() as { id: string } | undefined)?.id;
    if (team) { const vids = await platformIds("vercel", team); const vrows = vercel.map((r) => recommendationNode(r, vids, concepts)); for (const batch of chunks(vrows)) await write(RECOMMENDATION_CYPHER, { rows: batch, account: team, provider: "vercel", now: stamp }); }
  }
  return { recommendations: raw.length };
}

// ---- runs, controls, playbooks ---------------------------------------------------------------------------------------

const FLAG_CYPHER = `
UNWIND $rows AS row
MERGE (c:AdvisorControl {id: row.control_id})
SET c.title = coalesce(row.control_title, c.title, row.control_id), c.framework = row.framework, c.category = row.category, c.provider = $provider, c.native_type = 'control', c.native_id = row.control_id, c.account_id = $account, c.updated_at = $now
WITH c, row
MATCH (r:AdvisorResource {id: row.resource_id})
MERGE (c)-[f:FLAGGED]->(r)
SET f.run_id = row.run_id, f.reason = row.reason`;

const PLAYBOOK_CYPHER = `
UNWIND $rows AS row
MERGE (p:KnPlaybook {id: row.id})
SET p += {provider: $provider, control_id: row.control_id, title: row.title, meaning: row.meaning, act_when: row.act_when, ignore_when: row.ignore_when, steps: row.steps, citations: row.citations, saving: row.saving, tier: row.tier, effort: row.effort,
          references: row.references, sources: row.sources, source_hashes: row.source_hashes, generated_at: row.generated_at, generated_by: row.generated_by, stale_after: row.stale_after, review_status: row.review_status, origin: row.origin, confidence: row.confidence, native_type: 'playbook', native_id: row.control_id, updated_at: $now}
WITH p, row
OPTIONAL MATCH (p)-[old:CITES]->() DELETE old
WITH p, row
FOREACH (src IN row.source_nodes |
  MERGE (s:KnSource {id: src.id}) ON CREATE SET s.first_seen = $now
  SET s.kind = src.kind, s.origin = src.origin, s.title = src.title, s.url = src.url, s.hash = src.hash, s.fetched_at = src.fetched_at, s.changed_at = src.changed_at, s.native_type = 'document', s.native_id = src.id, s.provider = $provider, s.updated_at = $now
  MERGE (p)-[:CITES]->(s))
WITH p, row
MERGE (c:AdvisorControl {id: row.control_id})
SET c.title = coalesce(c.title, row.title), c.framework = coalesce(c.framework, row.framework), c.category = coalesce(c.category, row.category), c.provider = $provider, c.native_type = 'control', c.native_id = row.control_id, c.account_id = $account, c.updated_at = $now
MERGE (c)-[:HAS_PLAYBOOK]->(p)`;

function latestCompletedRunId(): number | null {
  return (db.prepare("select id from runs where provider = 'aws' and status = 'completed' order by id desc limit 1").get() as { id: number } | undefined)?.id ?? null;
}

/**
 * The playbook catalogue (src/playbooks.ts) as KnPlaybook nodes. Hand-written today, which the node says
 * (generated_by); the plan is to build them from sources (docs/cloud-ontology.md §8, step 5).
 */
export async function mirrorPlaybooks(): Promise<{ playbooks: number }> {
  if (!enabled()) return { playbooks: 0 };
  await ensureSchema();
  const account = accountId();
  const sourceRow = (id: string) => { const r = db.prepare("select id, kind, origin, title, url, hash, fetched_at, changed_at from sources where id = ?").get(id) as any; return r ?? null; };
  const rows = listPlaybooks().map((p) => {
    const pv = p.provenance; const generated = pv?.origin === "generated";
    const srcIds = generated ? (pv?.sources ?? []).map((x) => x.id) : [];
    const sourceNodes = srcIds.map(sourceRow).filter(Boolean);
    return { id: `${PROVIDER}:${p.control_id}`, control_id: p.control_id, title: p.title, tier: p.tier, effort: p.effort, meaning: p.meaning, act_when: p.act_when, ignore_when: p.ignore_when,
      steps: p.steps, citations: (p.citations ?? []).map((c) => c ?? ""), saving: p.saving, references: p.references ?? [], sources: generated ? srcIds : p.references ?? [], source_hashes: generated ? (pv?.sources ?? []).map((x) => x.hash) : [],
      generated_at: pv?.generated_at ?? null, generated_by: generated ? pv?.generated_by ?? null : "hand-written seed (src/playbooks.ts)", stale_after: pv?.stale_after ?? null, review_status: generated ? pv?.review_status ?? "generated" : "seed", origin: pv?.origin ?? "seed", confidence: pv?.confidence ?? null,
      source_nodes: sourceNodes, ...controlFacts(p.control_id) };
  });
  for (const batch of chunks(rows)) await write(PLAYBOOK_CYPHER, { rows: batch, account, provider: PROVIDER, now: now() });
  return { playbooks: rows.length };
}

/**
 * FLAGGED edges for the latest completed run's alarm findings whose resource is in the inventory (one per control and
 * resource); earlier runs' edges are dropped first, so the graph shows the current state, not the history.
 */
export async function mirrorControls(runId = latestCompletedRunId(), opts: { provider?: string; account?: string; ids?: Set<string> } = {}): Promise<{ controls: number; flagged: number }> {
  if (!enabled() || runId == null) return { controls: 0, flagged: 0 };
  await ensureSchema();
  const provider = opts.provider ?? PROVIDER; const account = opts.account ?? accountId();
  const findings = db.prepare("select control_id, control_title, resource, reason from findings where run_id = ? and status = 'alarm' and resource is not null order by id").all(runId) as any[];
  const edges = flagEdges(findings, opts.ids ?? inventoryIds(account), runId).map((e) => ({ ...e, ...controlFacts(e.control_id) }));
  await write("MATCH (:AdvisorControl)-[f:FLAGGED]->(:AdvisorResource {provider: $provider}) WHERE f.run_id <> $runId DELETE f", { provider, runId });
  const stamp = now();
  for (const batch of chunks(edges)) await write(FLAG_CYPHER, { rows: batch, account, provider, now: stamp });
  return { controls: new Set(edges.map((e) => e.control_id)).size, flagged: edges.length };
}

/** The ids a platform account's resources carry in the graph (projects, stores, the team), for the edges that target them. */
async function platformIds(provider: string, account: string): Promise<Set<string>> {
  if (provider === "vercel") { const inv = await import("./adapters/vercel/inventory.js"); return new Set([account, ...inv.listProjects(true).map((p) => p.id), ...inv.listStores({ includeGone: true }).map((s) => s.id)]); }
  return new Set([account]);
}

/** One run as an AdvisorRun node; when it is the latest completed run, its alarm findings become the FLAGGED edges (unless `controls` is false). */
export async function mirrorRun(runId: number, opts: { controls?: boolean } = {}): Promise<{ run: number | null; flagged: number }> {
  if (!enabled()) return { run: null, flagged: 0 };
  await ensureSchema();
  const row = db.prepare("select id, started_at, finished_at, status, trigger, findings_count, recommendations_count, provider, account_id from runs where id = ?").get(runId) as any;
  if (!row) return { run: null, flagged: 0 };
  // an AWS collection run belongs to the primary account; a platform provider's rules pass to the account on the row
  const provider = String(row.provider || PROVIDER); const platform = provider !== PROVIDER;
  const account = platform ? String(row.account_id) : accountId();
  if (!platform) await mirrorAccount(account);
  const node = runNode(row);
  await write(`MERGE (r:AdvisorRun {id: $row.id}) SET r += $row, r.account_id = $account, r.provider = $provider, r.native_type = $kind, r.native_id = toString($row.id), r.updated_at = $now
    WITH r MATCH (a:AdvisorAccount {id: $account}) MERGE (r)-[:IN_ACCOUNT]->(a)`, { row: node, account, provider, kind: platform ? "rules_pass" : "collection_run", now: now() });
  let flagged = 0;
  if (opts.controls !== false && node.status === "completed") {
    if (platform) flagged = (await mirrorControls(runId, { provider, account, ids: await platformIds(provider, account) })).flagged;
    else if (latestCompletedRunId() === runId) flagged = (await mirrorControls(runId)).flagged;
  }
  return { run: runId, flagged };
}

// ---- alerts and incidents --------------------------------------------------------------------------------------------

const ALERT_CYPHER = `
UNWIND $rows AS row
MERGE (a:AdvisorAlert {id: row.id})
SET a += {kind: row.kind, level: row.level, message: row.message, created_at: row.created_at, acknowledged: row.acknowledged, acknowledged_by: row.acknowledged_by,
          resource: row.resource, cause_status: row.cause_status, cause: row.cause, cause_actor: row.cause_actor, cause_actor_kind: row.cause_actor_kind, cause_via: row.cause_via,
          cause_event: row.cause_event, cause_at: row.cause_at, provider: $provider, account_id: coalesce(row.account_id, $account), native_type: 'alert', native_id: toString(row.id), updated_at: $now}
WITH a, row
FOREACH (_ IN CASE WHEN row.cause_action_id IS NULL THEN [] ELSE [1] END |
  MERGE (x:AdvisorAction {id: row.cause_action_id})
  MERGE (a)-[:CAUSED_BY]->(x))
WITH a, row
OPTIONAL MATCH (a)-[t:ABOUT]->() DELETE t
WITH DISTINCT a, row
FOREACH (_ IN CASE WHEN row.resource_id IS NULL THEN [] ELSE [1] END |
  MERGE (res:AdvisorResource {id: row.resource_id})
  MERGE (a)-[:ABOUT]->(res))
FOREACH (_ IN CASE WHEN row.resource_id IS NULL AND row.resource IS NOT NULL THEN [1] ELSE [] END |
  ${REF_MERGE("ref", "row.resource", "row.guessed_type", "alert")}
  MERGE (a)-[:ABOUT]->(ref))`;

const INCIDENT_CYPHER = `
UNWIND $rows AS row
MERGE (i:AdvisorIncident {id: row.id})
SET i += {status: row.status, cause: row.cause, confidence: row.confidence, episode_cost_usd: row.episode_cost_usd, monthly_run_rate_usd: row.monthly_run_rate_usd,
          created_at: row.created_at, provider: $provider, account_id: coalesce(row.account_id, $account), native_type: 'incident', native_id: toString(row.id), updated_at: $now}
WITH i, row
MERGE (a:AdvisorAlert {id: row.alert_id})
MERGE (i)-[:INVESTIGATES]->(a)`;

/** Every alert with its level and its resource, and every incident with the alert it investigates. */
export async function mirrorAlertsAndIncidents(): Promise<{ alerts: number; incidents: number }> {
  if (!enabled()) return { alerts: 0, incidents: 0 };
  await ensureSchema();
  const account = accountId();
  await mirrorAccount(account);
  const inv = inventoryIds(account);
  const acct = accountResolver(account);
  const alerts = (db.prepare("select id, kind, resource, message, created_at, acknowledged, acknowledged_by, triage, cause, account_id from alerts").all() as any[])
    .map((r) => { const node = alertNode(r, inv, alertLevel({ ...r, triage: safeJson(r.triage) })); return { ...node, account_id: acct(r.account_id, node.resource_id, node.resource) }; });
  // an incident belongs where its alert does
  const incidents = (db.prepare("select i.id, i.alert_id, i.status, i.cause, i.confidence, i.episode_cost_usd, i.monthly_run_rate_usd, i.created_at, a.account_id as alert_account, a.resource as alert_resource from incidents i left join alerts a on a.id = i.alert_id").all() as any[])
    .map((r) => ({ ...incidentNode(r), account_id: acct(r.alert_account, r.alert_resource) }));
  const stamp = now();
  for (const batch of chunks(alerts)) await write(ALERT_CYPHER, { rows: batch, account, provider: PROVIDER, now: stamp });
  for (const batch of chunks(incidents)) await write(INCIDENT_CYPHER, { rows: batch, account, provider: PROVIDER, now: stamp });
  return { alerts: alerts.length, incidents: incidents.length };
}

// ---- the executor's ledger ---------------------------------------------------------------------------------------------------

const ACTION_CYPHER = `
UNWIND $rows AS row
MERGE (x:AdvisorAction {id: row.id})
SET x += {kind: row.kind, status: row.status, mode: row.mode, trigger: row.trigger, title: row.title, reason: row.reason, rollback: row.rollback, est_usd_month: row.est_usd_month,
          result: row.result, error: row.error, resource: row.resource, resource_name: row.resource_name, region: row.region, created_at: row.created_at, seen_at: row.seen_at,
          applied_at: row.applied_at, verified_at: row.verified_at, reverted_at: row.reverted_at, stage: row.stage, new_resource: row.new_resource,
          bill_verdict: row.bill_verdict, realised_usd_month: row.realised_usd_month, provider: $provider, account_id: coalesce(row.account_id, $account), native_type: 'executor_action', native_id: toString(row.id), updated_at: $now}
WITH x, row
FOREACH (_ IN CASE WHEN row.new_resource IS NULL THEN [] ELSE [1] END |
  ${REF_MERGE("nr", "row.new_resource", "'instance'", "action")}
  MERGE (x)-[:LAUNCHED]->(nr))
WITH x, row
OPTIONAL MATCH (x)-[t:TARGETS]->() DELETE t
WITH DISTINCT x, row
FOREACH (_ IN CASE WHEN row.resource_id IS NULL THEN [] ELSE [1] END |
  MERGE (res:AdvisorResource {id: row.resource_id})
  MERGE (x)-[:TARGETS]->(res))
FOREACH (_ IN CASE WHEN row.resource_id IS NULL THEN [1] ELSE [] END |
  ${REF_MERGE("ref", "row.resource", "row.guessed_type", "action")}
  MERGE (x)-[:TARGETS]->(ref))
WITH x, row
UNWIND (CASE WHEN size(row.recommendation_ids) = 0 THEN [null] ELSE row.recommendation_ids END) AS rid
OPTIONAL MATCH (rec:AdvisorRecommendation {id: rid})
FOREACH (_ IN CASE WHEN rec IS NULL THEN [] ELSE [1] END | MERGE (x)-[:CARRIES_OUT]->(rec))`;

/** Every ledger row, or the given ids: proposals included, so the graph shows what the agent planned as well as what it did. */
export async function mirrorActions(ids?: number[]): Promise<{ actions: number }> {
  if (!enabled()) return { actions: 0 };
  if (ids && !ids.length) return { actions: 0 };
  await ensureSchema();
  const account = accountId();
  await mirrorAccount(account);
  const inv = inventoryIds(account);
  let raw: any[] = [];
  // the latest bill verdict of the change's kind on its resource rides along (src/verify.ts), when it has been measured
  const hasV = tableExists("action_verifications");
  const cols = hasV ? `, (select v.verdict from action_verifications v where v.action_key = a.kind || ':' || a.resource order by v.id desc limit 1) as bill_verdict,
    (select v.realised_usd_month from action_verifications v where v.action_key = a.kind || ':' || a.resource order by v.id desc limit 1) as realised_usd_month` : "";
  try { raw = ids ? db.prepare(`select a.*${cols} from actions a where a.id in (${ids.map(() => "?").join(",")})`).all(...ids) : db.prepare(`select a.*${cols} from actions a`).all(); }
  catch { return { actions: 0 }; /* the executor has not created its table yet */ }
  const acct = accountResolver(account);
  const rows = raw.map((r) => { const node = actionNode(r, inv); return { ...node, account_id: acct(r.account_id, node.resource_id, node.resource) }; });
  const stamp = now();
  for (const batch of chunks(rows)) await write(ACTION_CYPHER, { rows: batch, account, provider: PROVIDER, now: stamp });
  return { actions: rows.length };
}

// ---- executor passes ------------------------------------------------------------------------------------------------------

const PASS_CYPHER = `
MERGE (p:AdvisorPass {id: $pass.id})
SET p += $pass, p.account_id = $account, p.provider = $provider, p.native_type = 'executor_pass', p.native_id = toString($pass.id), p.updated_at = $now
WITH p
MATCH (acc:AdvisorAccount {id: $account}) MERGE (p)-[:IN_ACCOUNT]->(acc)
WITH p
OPTIONAL MATCH (p)<-[t:TOUCHED_IN]-() DELETE t
WITH DISTINCT p
UNWIND $events AS ev
MERGE (a:AdvisorAction {id: ev.action_id})
CREATE (a)-[:TOUCHED_IN {event: ev.event, outcome: ev.outcome, at: ev.at, trigger: ev.trigger, detail: ev.detail}]->(p)`;

/** One executor pass (src/executor_log.ts) with an edge from every ledger row it applied, read back or reverted. */
export async function mirrorPass(passId: number): Promise<{ pass: number | null; events: number }> {
  if (!enabled()) return { pass: null, events: 0 };
  const { getPass } = await import("./executor_log.js");
  const p = getPass(passId);
  if (!p) return { pass: null, events: 0 };
  await ensureSchema();
  const account = accountId();
  await mirrorAccount(account);
  const pass = { id: p.id, started_at: p.started_at, finished_at: p.finished_at, trigger: p.trigger, mode: p.mode, proposed: p.proposed, fresh: p.fresh, applied: p.applied, verified: p.verified,
    failed: p.failed, refused: p.refused, held: p.held, stale: p.stale, took_ms: p.took_ms, errors: p.errors.join("; ").slice(0, 1000) || null };
  const events = p.events.map((e) => ({ action_id: e.action_id, event: e.event, outcome: e.outcome, at: e.at, trigger: e.trigger, detail: e.detail ? e.detail.slice(0, 300) : null }));
  await write(PASS_CYPHER, { pass, events, account, provider: PROVIDER, now: now() });
  return { pass: passId, events: events.length };
}

/** Every pass still in the activity log (it keeps LOG_KEEP_DAYS). */
export async function mirrorPasses(): Promise<{ passes: number }> {
  if (!enabled()) return { passes: 0 };
  let ids: { id: number }[] = [];
  try { ids = db.prepare("select id from executor_passes order by id").all() as { id: number }[]; } catch { return { passes: 0 }; }
  for (const r of ids) await mirrorPass(r.id);
  return { passes: ids.length };
}

// ---- what runs on the instances, and the ports they answer on ---------------------------------------------------------------

const APP_CYPHER = `
UNWIND $rows AS row
MERGE (app:AdvisorApp {id: row.name})
SET app.name = row.name, app.kind = row.kind, app.native_type = 'program', app.native_id = row.name, app.updated_at = $now
WITH app, row
MATCH (r:AdvisorResource {id: row.instance_id})
MERGE (r)-[e:RUNS {user: row.user}]->(app)
SET e += {count: row.count, cpu_pct: row.cpu_pct, rss_bytes: row.rss_bytes, oldest_seconds: row.oldest_seconds, command: row.command, first_seen: row.first_seen, last_seen: row.last_seen, probes: row.probes, gone: row.gone, updated_at: $now}`;

const PORT_CYPHER = `
UNWIND $rows AS row
MERGE (p:AdvisorEndpoint {id: row.id})
SET p += {kind: 'port', resource_id: row.instance_id, protocol: row.proto, port: row.port, bind: row.bind, scope: row.scope, exposure: row.exposure, process: row.process, container: row.container, container_port: row.container_port,
  first_seen: row.first_seen, last_seen: row.last_seen, probes: row.probes, gone: row.gone, provider: $provider, account_id: coalesce(row.account_id, $account), native_type: 'instance_port', native_id: row.id, updated_at: $now}
WITH p, row
MATCH (r:AdvisorResource {id: row.instance_id})
MERGE (r)-[l:EXPOSES]->(p) SET l.gone = row.gone, l.updated_at = $now, p.account_id = coalesce(row.account_id, r.account_id, $account)
WITH p, row WHERE row.app_name IS NOT NULL
MATCH (a:AdvisorApp {id: row.app_name})
MERGE (a)-[s:SERVES]->(p) SET s.gone = row.gone, s.updated_at = $now`;

/** The ports of the given instances (or all), as AdvisorEndpoint nodes the box EXPOSES and the app SERVES (src/instance_apps.ts, probe 1.8). */
export async function mirrorPorts(instanceIds?: string[]): Promise<{ ports: number }> {
  if (!enabled()) return { ports: 0 };
  if (instanceIds && !instanceIds.length) return { ports: 0 };
  let raw: any[] = [];
  try { raw = instanceIds ? db.prepare(`select * from instance_ports where instance_id in (${instanceIds.map(() => "?").join(",")})`).all(...instanceIds) : db.prepare("select * from instance_ports").all(); }
  catch { return { ports: 0 }; }
  // the port's account is its instance's (src/accounts.ts): a member's box exposes a member's endpoint
  const instanceAccount = new Map((db.prepare("select instance_id, account_id from inventory_ec2 where account_id is not null and account_id <> ''").all() as { instance_id: string; account_id: string }[]).map((r) => [r.instance_id, r.account_id]));
  const rows = raw.map((r) => ({ id: `${r.instance_id}:${r.proto}:${r.port}`, instance_id: String(r.instance_id), account_id: instanceAccount.get(String(r.instance_id)) ?? null, proto: String(r.proto), port: num(r.port), bind: str(r.bind), scope: str(r.scope), exposure: str(r.exposure), process: r.process == null ? null : String(r.process), container: r.container == null ? null : String(r.container), container_port: r.container_port == null ? null : num(r.container_port),
    app_name: r.app_name == null ? null : String(r.app_name), first_seen: str(r.first_seen), last_seen: str(r.last_seen), probes: num(r.probes), gone: Boolean(r.gone) }));
  const stamp = now();
  for (const batch of chunks(rows)) await write(PORT_CYPHER, { rows: batch, account: accountId(), provider: PROVIDER, now: stamp });
  return { ports: rows.length };
}

/** Every instance_apps row (src/instance_apps.ts), or the given instances': the program nodes and the RUNS edges, gone ones included so history stays walkable. */
export async function mirrorApps(instanceIds?: string[]): Promise<{ apps: number }> {
  if (!enabled()) return { apps: 0 };
  if (instanceIds && !instanceIds.length) return { apps: 0 };
  await ensureSchema();
  let raw: any[] = [];
  try { raw = instanceIds ? db.prepare(`select * from instance_apps where instance_id in (${instanceIds.map(() => "?").join(",")})`).all(...instanceIds) : db.prepare("select * from instance_apps").all(); }
  catch { return { apps: 0 }; /* the table is created by src/instance_apps.ts on first load */ }
  const rows = raw.map((r) => ({ instance_id: String(r.instance_id), name: String(r.name), user: String(r.user), kind: String(r.kind), count: num(r.count), cpu_pct: num(r.cpu_pct), rss_bytes: num(r.rss_bytes), oldest_seconds: num(r.oldest_seconds),
    command: str(r.command), first_seen: str(r.first_seen), last_seen: str(r.last_seen), probes: num(r.probes), gone: Boolean(r.gone) }));
  const stamp = now();
  for (const batch of chunks(rows)) await write(APP_CYPHER, { rows: batch, now: stamp });
  await mirrorPorts(instanceIds);
  if (instanceIds) { const { mirrorReachability } = await import("./graph_network.js"); await mirrorReachability(instanceIds); }
  return { apps: rows.length };
}

// ---- EC2 status checks (src/status_checks.ts) ---------------------------------------------------------------------------------

const STATUS_CYPHER = `
UNWIND $rows AS row
MATCH (r:AdvisorResource {id: row.instance_id})
SET r.health = row.health, r.health_host = row.system_status, r.health_instance = row.instance_status, r.health_storage = row.ebs_status,
    r.scheduled_events = row.scheduled_events, r.health_checked_at = row.checked_at, r.updated_at = $now`;

/** The status checks of every running instance onto its resource node (src/status_checks.ts). */
export async function mirrorStatusChecks(): Promise<{ instances: number }> {
  if (!enabled()) return { instances: 0 };
  await ensureSchema();
  let status: any[] = [];
  try { status = db.prepare("select * from instance_status").all(); } catch { return { instances: 0 }; }
  const stamp = now();
  const rows = status.map((s) => ({ instance_id: String(s.instance_id), system_status: str(s.system_status), instance_status: str(s.instance_status), ebs_status: str(s.ebs_status),
    health: healthOf(str(s.system_status), str(s.instance_status), str(s.ebs_status)), scheduled_events: ((safeJson(s.events) || []) as any[]).length, checked_at: str(s.checked_at) }));
  for (const batch of chunks(rows)) await write(STATUS_CYPHER, { rows: batch, now: stamp });
  return { instances: rows.length };
}

// ---- security scans (src/compliance.ts) ------------------------------------------------------------------------------

const SECURITY_FLAG_CYPHER = `
UNWIND $rows AS row
MERGE (c:AdvisorControl {id: row.control_id})
SET c.title = coalesce(row.control_title, c.title, row.control_id), c.severity = row.severity, c.benchmark = row.benchmark, c.framework = row.framework, c.category = row.category, c.provider = $provider, c.native_type = 'control', c.native_id = row.control_id, c.account_id = $account, c.updated_at = $now
WITH c, row
MATCH (r:AdvisorResource {id: row.resource_id})
MERGE (c)-[f:SECURITY_FLAGGED]->(r)
SET f.scan_id = row.run_id, f.reason = row.reason, f.severity = row.severity, f.first_seen_at = row.first_seen_at`;

/**
 * One security scan as an AdvisorSecurityScan node, and when it is the latest completed one its alarms on inventory
 * resources as SECURITY_FLAGGED edges (kept apart from the cost run's FLAGGED, which a cost run replaces wholesale),
 * then the security recommendations the scan raised or resolved.
 */
export async function mirrorComplianceScan(scanId: number): Promise<{ scan: number | null; flagged: number }> {
  if (!enabled()) return { scan: null, flagged: 0 };
  await ensureSchema();
  const row = db.prepare("select id, started_at, finished_at, status, trigger, alarms, new_alarms, resolved, errors, counts from compliance_scans where id = ?").get(scanId) as any;
  if (!row) return { scan: null, flagged: 0 };
  const account = accountId();
  await mirrorAccount(account);
  await write(`MERGE (s:AdvisorSecurityScan {id: $row.id}) SET s += $row, s.account_id = $account, s.provider = $provider, s.native_type = 'compliance_scan', s.native_id = toString($row.id), s.updated_at = $now
    WITH s MATCH (a:AdvisorAccount {id: $account}) MERGE (s)-[:IN_ACCOUNT]->(a)`, { row: { ...row, counts: row.counts || "{}" }, account, provider: PROVIDER, now: now() });
  let flagged = 0;
  const latest = (db.prepare("select id from compliance_scans where status = 'completed' order by id desc limit 1").get() as { id: number } | undefined)?.id;
  if (row.status === "completed" && latest === scanId) {
    const findings = db.prepare("select control_id, control_title, severity, benchmark, resource, reason, first_seen_at from compliance_findings where scan_id = ? and resource is not null order by id").all(scanId) as any[];
    const inv = inventoryIds(account);
    const seen = new Set<string>();
    const edges: (FlagEdge & { severity: string | null; benchmark: string | null; first_seen_at: string | null; framework: string; category: string })[] = [];
    for (const f of findings) {
      const rid = inventoryIdOf(f.resource, inv);
      if (!rid || seen.has(`${f.control_id}|${rid}`)) continue;
      seen.add(`${f.control_id}|${rid}`);
      edges.push({ control_id: String(f.control_id), control_title: str(f.control_title), resource_id: rid, run_id: scanId, reason: f.reason ? String(f.reason).slice(0, 500) : null,
        severity: str(f.severity), benchmark: str(f.benchmark), first_seen_at: str(f.first_seen_at), ...controlFacts(String(f.control_id), str(f.benchmark)) });
    }
    await write("MATCH (:AdvisorControl)-[f:SECURITY_FLAGGED]->(:AdvisorResource {provider: $provider}) WHERE f.scan_id <> $scanId DELETE f", { provider: PROVIDER, scanId });
    const stamp = now();
    for (const batch of chunks(edges)) await write(SECURITY_FLAG_CYPHER, { rows: batch, account, provider: PROVIDER, now: stamp });
    flagged = edges.length;
  }
  const recIds = (db.prepare("select id from recommendations where action_type = 'security_fix'").all() as { id: number }[]).map((r) => r.id);
  if (recIds.length) await mirrorRecommendations(recIds);
  return { scan: scanId, flagged };
}

// ---- full resync, stats, wipe --------------------------------------------------------------------------------------------

export interface MirrorCounts {
  knowledge?: import("./graph_knowledge.js").KnowledgeCounts | null; network?: import("./graph_network.js").NetworkCounts | null; account_id: string; resources: number; recommendations: number; runs: number; flagged: number; controls: number; playbooks: number; alerts: number; incidents: number; actions: number; passes: number; apps: number; took_ms: number }

/** Everything, in dependency order, in batches; idempotent, so it doubles as the repair after a wipe. */
export async function mirrorAll(): Promise<MirrorCounts | null> {
  if (!enabled()) return null;
  const t0 = Date.now();
  await ensureSchema();
  const account = accountId();
  await mirrorAccount(account);
  const { resources } = await mirrorResources();
  const runs = db.prepare("select id from runs order by id").all() as { id: number }[];
  for (const r of runs) await mirrorRun(r.id, { controls: false });
  const { playbooks } = await mirrorPlaybooks();
  const ctl = await mirrorControls();
  const { recommendations } = await mirrorRecommendations();
  const { alerts, incidents } = await mirrorAlertsAndIncidents();
  const { actions } = await mirrorActions();
  const { passes } = await mirrorPasses();
  // the adapter's own layers, in its order (apps and ports, status checks, usage, capacity, network, clusters, software on AWS)
  let apps = 0; let network: import("./graph_network.js").NetworkCounts | null = null;
  for (const layer of awsAdapter.layers) {
    try { const r: any = await layer.mirror(); if (layer.name === "apps and ports") apps = Number(r?.apps ?? 0); if (layer.name === "network") network = r ?? null; }
    catch (e) { logError(layer.name, e); }
  }
  const scan = db.prepare("select id from compliance_scans where status = 'completed' order by id desc limit 1").get() as { id: number } | undefined;
  if (scan) await mirrorComplianceScan(scan.id);
  // every other configured adapter, whole (its account, resources and layers)
  const { adapters } = await import("./adapters/index.js");
  for (const a of adapters().filter((x) => x.id !== PROVIDER && x.configured())) { try { await mirrorAdapter(a); } catch (e) { logError(`${a.id} adapter`, e); } }
  const { mirrorKnowledge } = await import("./graph_knowledge.js");
  const knowledge = await mirrorKnowledge();
  try { const { mirrorSwarmCosts } = await import("./swarm_costs_graph.js"); await mirrorSwarmCosts(); } catch (e) { logError("swarm costs", e); }
  return { account_id: account, knowledge, network, resources, recommendations, runs: runs.length, flagged: ctl.flagged, controls: ctl.controls, playbooks, alerts, incidents, actions, passes, apps, took_ms: Date.now() - t0 };
}

export interface GraphStats { nodes: Record<string, number>; relationships: Record<string, number>; decided_as: number; total_nodes: number; total_relationships: number }

/** Node counts per Advisor and Kn label and relationship counts per type (relationships leaving one of our nodes, so DECIDED_AS to Concepts is included). */
export async function graphStats(): Promise<GraphStats> {
  const nodes = await readQuery("MATCH (n) WHERE any(l IN labels(n) WHERE l STARTS WITH 'Advisor' OR l STARTS WITH 'Kn') UNWIND labels(n) AS l WITH l, count(*) AS n WHERE l STARTS WITH 'Advisor' OR l STARTS WITH 'Kn' RETURN l AS label, n ORDER BY l", {}, { timeoutMs: 30_000, rowCap: 1000 });
  const rels = await readQuery("MATCH (n)-[r]->() WHERE any(l IN labels(n) WHERE l STARTS WITH 'Advisor' OR l STARTS WITH 'Kn') RETURN type(r) AS type, count(r) AS n ORDER BY type", {}, { timeoutMs: 30_000, rowCap: 1000 });
  const nodeCounts = Object.fromEntries(nodes.rows.map((r) => [String(r.label), Number(r.n)]));
  const relCounts = Object.fromEntries(rels.rows.map((r) => [String(r.type), Number(r.n)]));
  return { nodes: nodeCounts, relationships: relCounts, decided_as: relCounts.DECIDED_AS || 0,
    total_nodes: Object.values(nodeCounts).reduce((s, n) => s + n, 0), total_relationships: Object.values(relCounts).reduce((s, n) => s + n, 0) };
}

async function deleteWhere(match: string, params: Record<string, unknown>): Promise<number> {
  let total = 0;
  for (;;) {
    const s = session("WRITE");
    try {
      const res = await s.executeWrite((tx) => tx.run(`${match} WITH n LIMIT 1000 DETACH DELETE n RETURN count(*) AS n`, params), { timeout: 60_000 });
      const n = Number(res.records[0]?.get("n") ?? 0);
      total += n;
      if (n < 1000) return total;
    } finally { await s.close(); }
  }
}

/**
 * Removes one account's nodes (everything that carries its account_id: account, telemetry, resources, refs, pools,
 * endpoints, recommendations, runs, alerts, incidents, actions, passes, scans, pressure events, and the knowledge
 * layer's systems, overlays and log groups) and then the shared catalogue nodes nothing points at any more (apps,
 * controls without a flag and their playbooks). Archetypes, system types, Concept nodes and everything else in the
 * graph are untouched. A mirrorAll afterwards rebuilds it all.
 */
export async function wipeMirror(account = accountId()): Promise<{ deleted: number }> {
  if (!enabled()) return { deleted: 0 };
  let deleted = await deleteWhere("MATCH (n) WHERE any(l IN labels(n) WHERE l STARTS WITH 'Advisor' OR l STARTS WITH 'Kn') AND n.account_id = $account", { account });
  const { adapters } = await import("./adapters/index.js");
  for (const a of adapters().filter((x) => x.id !== PROVIDER && x.configured())) deleted += await deleteWhere("MATCH (n) WHERE any(l IN labels(n) WHERE l STARTS WITH 'Advisor' OR l STARTS WITH 'Kn') AND n.account_id = $account AND n.provider = $provider", { account: a.primaryAccountId(), provider: a.id });
  deleted += await deleteWhere("MATCH (n) WHERE (n:AdvisorApp OR n:AdvisorSource OR n:KnVulnerability OR n:AdvisorPackage) AND NOT (n)--()", {});
  deleted += await deleteWhere("MATCH (c:AdvisorControl) WHERE NOT (c)-[:FLAGGED|SECURITY_FLAGGED]->() OPTIONAL MATCH (c)-[:HAS_PLAYBOOK]->(p:KnPlaybook) WITH collect(c) + collect(p) AS ns UNWIND ns AS n", {});
  deleted += (await wipeLegacy()).deleted;
  return { deleted };
}

/** Every Advisor* and Kn* node of every account and provider: the full wipe. The schema (constraints, indexes) stays; Concepts are repo2graph's and are not touched. */
export async function wipeMirrorAll(): Promise<{ deleted: number }> {
  if (!enabled()) return { deleted: 0 };
  let deleted = await deleteWhere("MATCH (n) WHERE any(l IN labels(n) WHERE l STARTS WITH 'Advisor' OR l STARTS WITH 'Kn')", {});
  deleted += (await wipeLegacy()).deleted;
  return { deleted };
}

export async function verifyConnection(): Promise<{ connected: boolean; error?: string; server?: string }> {
  if (!enabled()) return { connected: false, error: "NEO4J_URI is not set" };
  try {
    const info = await getDriver().verifyConnectivity(config.neo4jDatabase ? { database: config.neo4jDatabase } : undefined);
    return { connected: true, server: `${info.address} ${info.agent || ""}`.trim() };
  } catch (e: any) {
    return { connected: false, error: String(e?.message || e).slice(0, 300) };
  }
}

// ---- the resource view for the UI ------------------------------------------------------------------------------------

export interface ResourceView {
  resource: Record<string, unknown>; labels: string[]; role: string | null; pool: string | null;
  /** Which telemetry covers it, with the edge's status and last report. */
  observed: { kind: string; native: string | null; status: string | null; last_at: string | null; detail: string | null }[];
  recommendations: { rec: Record<string, unknown>; concept: { id: string; name: string | null } | null }[];
  alerts: Record<string, unknown>[]; incidents: Record<string, unknown>[]; controls: { id: string; title: string | null; run_id: number | null; reason: string | null }[];
  actions: Record<string, unknown>[];
  /** What runs on the box (RUNS edges, current ones first). */
  apps: Record<string, unknown>[];
  /** What it exposes: ports, listeners, service endpoints. */
  endpoints: Record<string, unknown>[];
  /** The log groups it writes: the ones its own agent config names (how = observed, from the resource's SHIPS_LOGS_TO edges) and the ones attributed to its system by name, tag or Jev (how = the rule, source = the system). */
  log_groups: Record<string, unknown>[];
  counts: { recommendations: number; alerts: number; incidents: number; controls: number; actions: number; apps: number; endpoints: number; log_groups: number };
}

/** One resource node with everything linked to it; null when the graph has no such node. Alerts are capped at 25 (instance_state alerts pile up). */
export async function resourceView(id: string): Promise<ResourceView | null> {
  const r = await readQuery(`
    MATCH (r:AdvisorResource {id: $id})
    OPTIONAL MATCH (r)-[:HAS_ROLE]->(role:KnArchetype)
    OPTIONAL MATCH (r)-[:IN_POOL]->(pool:AdvisorNodePool)
    OPTIONAL MATCH (r)-[ob:OBSERVED_BY]->(t:AdvisorTelemetry)
    WITH r, role, pool, collect(DISTINCT CASE WHEN t IS NULL THEN null ELSE {kind: t.kind, native: t.native, status: ob.status, last_at: ob.last_at, detail: ob.detail} END) AS observed
    OPTIONAL MATCH (rec:AdvisorRecommendation)-[:TARGETS]->(r)
    OPTIONAL MATCH (rec)-[:DECIDED_AS]->(c:Concept)
    WITH r, role, pool, observed, collect(DISTINCT CASE WHEN rec IS NULL THEN null ELSE {rec: properties(rec), concept: CASE WHEN c IS NULL THEN null ELSE {id: c.id, name: c.name} END} END) AS recs
    OPTIONAL MATCH (a:AdvisorAlert)-[:ABOUT]->(r)
    OPTIONAL MATCH (i:AdvisorIncident)-[:INVESTIGATES]->(a)
    WITH r, role, pool, observed, recs, collect(DISTINCT properties(a)) AS alerts, collect(DISTINCT properties(i)) AS incidents
    OPTIONAL MATCH (ctl:AdvisorControl)-[f:FLAGGED|SECURITY_FLAGGED]->(r)
    WITH r, role, pool, observed, recs, alerts, incidents, collect(DISTINCT CASE WHEN ctl IS NULL THEN null ELSE {id: ctl.id, title: ctl.title, run_id: coalesce(f.run_id, f.scan_id), reason: f.reason} END) AS controls
    OPTIONAL MATCH (x:AdvisorAction)-[:TARGETS]->(r)
    WITH r, role, pool, observed, recs, alerts, incidents, controls, collect(DISTINCT properties(x)) AS actions
    OPTIONAL MATCH (r)-[ru:RUNS]->(app:AdvisorApp)
    WITH r, role, pool, observed, recs, alerts, incidents, controls, actions, collect(DISTINCT CASE WHEN app IS NULL THEN null ELSE {name: app.name, kind: app.kind, user: ru.user, count: ru.count, cpu_pct: ru.cpu_pct, rss_bytes: ru.rss_bytes, oldest_seconds: ru.oldest_seconds, command: ru.command, first_seen: ru.first_seen, last_seen: ru.last_seen, gone: ru.gone} END) AS apps
    OPTIONAL MATCH (r)-[ex:EXPOSES]->(ep:AdvisorEndpoint)
    WITH r, role, pool, observed, recs, alerts, incidents, controls, actions, apps, collect(DISTINCT CASE WHEN ep IS NULL THEN null ELSE properties(ep) END) AS endpoints
    OPTIONAL MATCH (r)-[sl:SHIPS_LOGS_TO]->(g:KnLogGroup)
    WITH r, role, pool, observed, recs, alerts, incidents, controls, actions, apps, endpoints,
      collect(DISTINCT CASE WHEN g IS NULL THEN null ELSE {name: g.name, how: 'observed', via: sl.via, source: sl.source, observed_at: sl.observed_at, ingest_gb_day: g.ingest_gb_day, ingest_usd_month: g.ingest_usd_month, retention_days: g.retention_days} END) AS observed_logs
    OPTIONAL MATCH (r)-[:MEMBER_OF]->(sys:KnSystem)-[ss:SHIPS_LOGS_TO]->(sg:KnLogGroup)
    WITH r, role, pool, observed, recs, alerts, incidents, controls, actions, apps, endpoints, observed_logs,
      collect(DISTINCT CASE WHEN sg IS NULL THEN null ELSE {name: sg.name, how: ss.attributed_by, via: null, source: sys.name, system: sys.id, observed_at: null, ingest_gb_day: sg.ingest_gb_day, ingest_usd_month: sg.ingest_usd_month, retention_days: sg.retention_days} END) AS system_groups
    RETURN properties(r) AS resource, labels(r) AS labels, role.name AS role, pool.name AS pool, observed, recs, alerts, incidents, controls, actions, apps, endpoints,
      observed_logs + [x IN system_groups WHERE x IS NOT NULL AND NOT x.name IN [o IN observed_logs WHERE o IS NOT NULL | o.name]] AS log_groups`, { id }, { rowCap: 1 });
  const row = r.rows[0];
  if (!row) return null;
  const recs = (row.recs as any[]).filter(Boolean);
  const alerts = (row.alerts as any[]).filter(Boolean).sort((a, b) => Number(b.id) - Number(a.id));
  const incidents = (row.incidents as any[]).filter(Boolean);
  const controls = (row.controls as any[]).filter(Boolean);
  const actions = (row.actions as any[]).filter(Boolean).sort((a, b) => Number(b.id) - Number(a.id));
  const apps = (row.apps as any[]).filter(Boolean).sort((a, b) => Number(Boolean(a.gone)) - Number(Boolean(b.gone)) || (a.kind === b.kind ? Number(b.rss_bytes || 0) - Number(a.rss_bytes || 0) : a.kind === "app" ? -1 : 1));
  const endpoints = (row.endpoints as any[]).filter(Boolean).sort((a, b) => Number(Boolean(a.gone)) - Number(Boolean(b.gone)) || Number(a.port || 0) - Number(b.port || 0));
  const logGroups = (row.log_groups as any[]).filter(Boolean).sort((a, b) => Number(b.ingest_usd_month || 0) - Number(a.ingest_usd_month || 0));
  return { resource: row.resource, labels: (row.labels as string[]).filter((l) => l !== "AdvisorResource"), role: row.role ?? null, pool: row.pool ?? null, observed: (row.observed as any[]).filter(Boolean), recommendations: recs, alerts: alerts.slice(0, 25), incidents, controls, actions, apps, endpoints, log_groups: logGroups,
    counts: { recommendations: recs.length, alerts: alerts.length, incidents: incidents.length, controls: controls.length, actions: actions.length, apps: apps.length, endpoints: endpoints.length, log_groups: logGroups.length } };
}

// ---- fire-and-forget hooks -----------------------------------------------------------------------------------------------

/** End of a collection run: the run node, the refreshed inventory, every recommendation (the batch reconciles many), then the knowledge layer on top. */
export const mirrorAfterRunInBackground = (runId: number) => inBackground(`mirror of run ${runId}`, async () => { await mirrorRun(runId); await mirrorResources(); await mirrorRecommendations(); const { mirrorNetwork } = await import("./graph_network.js"); await mirrorNetwork(); const { mirrorClusters } = await import("./graph_clusters.js"); await mirrorClusters(); mirrorKnowledgeInBackground(`run ${runId}`); });

let knowledgeInFlight: Promise<unknown> | null = null;
let knowledgeAgain: string | null = null;
/**
 * The knowledge layer (src/graph_knowledge.ts: systems, types, overlays, traffic and log attribution) is rebuilt from
 * whatever the advisor holds, so it runs after everything that changes its inputs: a collection run, a probe pass
 * (log shipping seen on the boxes), the daily logs refresh (new groups and tags) and server start. Triggers that
 * arrive while it runs are coalesced into one more pass, so the Kn labels are always there and never rebuilt twice.
 */
export function mirrorKnowledgeInBackground(why: string): void {
  if (!enabled()) return;
  if (knowledgeInFlight) { knowledgeAgain = why; return; }
  const go = async (reason: string): Promise<void> => {
    const { mirrorKnowledge } = await import("./graph_knowledge.js");
    const c = await mirrorKnowledge();
    if (c) console.log(`[graph] knowledge layer refreshed after ${reason}: ${c.systems} systems, ${c.log_groups} log groups (${c.log_groups_attributed} attributed, ${c.log_groups_observed} observed, ${c.log_groups_jev} by Jev), ${c.took_ms} ms`);
  };
  knowledgeInFlight = (async () => {
    let reason: string | null = why;
    while (reason) {
      try { await go(reason); } catch (e) { logError(`knowledge mirror (${reason})`, e); }
      reason = knowledgeAgain; knowledgeAgain = null;
    }
  })().finally(() => { knowledgeInFlight = null; });
}
export const mirrorResourcesInBackground = () => inBackground("resource mirror", mirrorResources);

/** Usage profiles (src/usage_profile.ts) on the node they describe: the instance's AdvisorCompute, or the AdvisorNodePool of an autoscaling group. */
export async function mirrorUsageProfiles(): Promise<{ profiles: number }> {
  if (!enabled()) return { profiles: 0 };
  await ensureSchema();
  const account = accountId();
  const reviews = new Map<string, any>(); for (const r of rowsOf("select subject, reviewed_at, verdict, schedule, confidence, reason from usage_reviews")) reviews.set(r.subject, r);
  const rows = rowsOf("select subject, kind, name, account_id, computed_at, quiet_hours_week, confidence, suggested_schedule, off_hours_week, est_usd_month, summary, quiet_windows from usage_profiles")
    .map((r) => ({ id: r.kind === "asg" ? poolId(r.account_id ? String(r.account_id) : account, String(r.name)) : String(r.subject), account_id: r.account_id ? String(r.account_id) : null, name: str(r.name), kind: r.kind, computed_at: r.computed_at, quiet_hours_week: r.quiet_hours_week, confidence: r.confidence, suggested_schedule: r.suggested_schedule, off_hours_week: r.off_hours_week, est_usd_month: r.est_usd_month, summary: r.summary, quiet_windows: (() => { try { return (JSON.parse(r.quiet_windows) as any[]).map((w) => w.label); } catch { return []; } })(), review_verdict: reviews.get(r.subject)?.verdict ?? null, review_schedule: reviews.get(r.subject)?.schedule ?? null, review_confidence: reviews.get(r.subject)?.confidence ?? null, review_reason: reviews.get(r.subject)?.reason ?? null, reviewed_at: reviews.get(r.subject)?.reviewed_at ?? null }));
  const stamp = now();
  const props = "usage_computed_at: row.computed_at, usage_quiet_hours_week: row.quiet_hours_week, usage_confidence: row.confidence, usage_schedule: row.suggested_schedule, usage_off_hours_week: row.off_hours_week, usage_est_usd_month: row.est_usd_month, usage_summary: row.summary, usage_quiet_windows: row.quiet_windows, usage_review_verdict: row.review_verdict, usage_review_schedule: row.review_schedule, usage_review_confidence: row.review_confidence, usage_review_reason: row.review_reason, usage_reviewed_at: row.reviewed_at, updated_at: $now";
  for (const batch of chunks(rows.filter((r) => r.kind === "ec2"))) await write(`UNWIND $rows AS row MATCH (r:AdvisorResource {id: row.id}) SET r += {${props}}`, { rows: batch, now: stamp });
  for (const batch of chunks(rows.filter((r) => r.kind === "asg"))) await write(`UNWIND $rows AS row MERGE (p:AdvisorNodePool {id: row.id}) SET p.name = row.name, p.kind = coalesce(p.kind, 'asg'), p.account_id = coalesce(row.account_id, $account), p.provider = $provider, p.native_type = 'autoscaling_pool', p.native_id = row.name SET p += {${props}}`, { rows: batch, account, provider: PROVIDER, now: stamp });
  return { profiles: rows.length };
}
export const mirrorUsageProfilesInBackground = () => inBackground("usage profile mirror", mirrorUsageProfiles);

/**
 * The capacity pattern of every Beanstalk group (src/capacity_pattern.ts) on its AdvisorNodePool node: the learned
 * minimum per hour of the week, the band, the weeks behind it, and the pressure events of the window as
 * PRESSURED_AT edges to the action that answered them (when one did).
 */
export async function mirrorCapacityPatterns(): Promise<{ patterns: number; events: number }> {
  if (!enabled()) return { patterns: 0, events: 0 };
  await ensureSchema();
  const account = accountId();
  const rows = rowsOf("select env_id, env_name, asg, region, account_id, computed_at, json from capacity_patterns");
  const stamp = now();
  const nodes = rows.flatMap((r) => { try { const p = JSON.parse(r.json); return [{ id: poolId(r.account_id ? String(r.account_id) : account, String(r.asg)), account_id: r.account_id ? String(r.account_id) : null, name: String(r.asg), env_id: r.env_id, env_name: r.env_name, region: r.region, computed_at: p.computed_at, days: p.days, weeks: p.weeks, coverage: p.coverage, confident: Boolean(p.confident), floor: p.floor, ceiling: p.ceiling ?? null, learned_min: p.learned, wanted: p.wanted, trigger: p.trigger ?? null, binding: p.binding ?? null, signals: p.signals?.summary ?? null, pressure_events: p.pressure_events, summary: p.summary }]; } catch { return []; } });
  const props = "capacity_env_id: row.env_id, capacity_env_name: row.env_name, capacity_computed_at: row.computed_at, capacity_days: row.days, capacity_weeks: row.weeks, capacity_coverage: row.coverage, capacity_confident: row.confident, capacity_floor: row.floor, capacity_ceiling: row.ceiling, capacity_learned_min: row.learned_min, capacity_wanted: row.wanted, capacity_trigger: row.trigger, capacity_binding: row.binding, capacity_signals: row.signals, capacity_pressure_events: row.pressure_events, capacity_summary: row.summary, capacity_updated_at: $now";
  for (const batch of chunks(nodes)) await write(`UNWIND $rows AS row MERGE (p:AdvisorNodePool {id: row.id}) SET p.name = row.name, p.kind = coalesce(p.kind, 'asg'), p.platform = 'beanstalk', p.account_id = coalesce(row.account_id, $account), p.provider = $provider, p.native_type = 'autoscaling_pool', p.native_id = row.name, p.region = row.region SET p += {${props}}`, { rows: batch, account, provider: PROVIDER, now: stamp });
  const envAccount = new Map(rows.map((r) => [String(r.env_id), r.account_id ? String(r.account_id) : null]));
  const events = rowsOf("select id, env_id, asg, at, ring, desired, max_size, cpu_avg, action_id, note from capacity_pressure_events where datetime(at) > datetime('now', '-28 days')").map((e) => { const a = envAccount.get(String(e.env_id)) ?? null; return { ...e, account_id: a, pool_id: poolId(a ?? account, String(e.asg)) }; });
  for (const batch of chunks(events)) await write(`UNWIND $rows AS row
    MERGE (p:AdvisorNodePool {id: row.pool_id}) ON CREATE SET p.name = row.asg, p.kind = 'asg', p.account_id = coalesce(row.account_id, $account), p.provider = $provider, p.native_type = 'autoscaling_pool', p.native_id = row.asg
    MERGE (e:AdvisorPressureEvent {id: row.id}) SET e += {env_id: row.env_id, at: row.at, ring: row.ring, desired: row.desired, max_size: row.max_size, signal: 'cpu', value: row.cpu_avg, cpu_avg: row.cpu_avg, note: row.note, provider: $provider, account_id: coalesce(row.account_id, $account), native_type: 'pressure_event', native_id: toString(row.id), updated_at: $now}
    MERGE (p)-[:PRESSURED_AT]->(e)
    WITH e, row WHERE row.action_id IS NOT NULL
    MATCH (a:AdvisorAction {id: row.action_id}) MERGE (a)-[:ANSWERED]->(e)`, { rows: batch, account, provider: PROVIDER, now: stamp });
  return { patterns: nodes.length, events: events.length };
}
export const mirrorCapacityPatternsInBackground = () => inBackground("capacity pattern mirror", mirrorCapacityPatterns);
export const mirrorComplianceScanInBackground = (scanId: number) => inBackground(`security scan mirror (${scanId})`, () => mirrorComplianceScan(scanId));
export const mirrorRecommendationsInBackground = (ids?: number[]) => inBackground(`recommendation mirror${ids ? ` (${ids.join(", ")})` : ""}`, () => mirrorRecommendations(ids));
export const mirrorAlertsInBackground = () => inBackground("alert mirror", mirrorAlertsAndIncidents);

/**
 * One instance's wake profile (src/wake_profiles.ts) on its AdvisorCompute node: whether the automatic wake is on,
 * the domains and the whole profile as JSON; a deleted profile clears them. Fire-and-forget from every save.
 */
export function mirrorWakeProfile(instanceId: string): void {
  inBackground(`wake profile ${instanceId}`, async () => {
    if (!enabled()) return;
    await ensureSchema();
    const row = db.prepare("select enabled, profile, updated_at, updated_by from wake_profiles where instance_id = ?").get(instanceId) as { enabled: number; profile: string; updated_at: string; updated_by: string | null } | undefined;
    let domains: string[] = [];
    try { domains = row ? (JSON.parse(row.profile).domains ?? []) : []; } catch { /* kept empty */ }
    await write(`MERGE (r:AdvisorResource {id: $id}) ON CREATE SET r:AdvisorCompute, r.provider = $provider, r.account_id = $account, r.native_type = 'ec2_instance', r.native_id = $id
      SET r.wake_profile = $profile, r.wake_enabled = $enabled, r.wake_domains = $domains, r.wake_updated_at = $updated_at, r.wake_updated_by = $by, r.updated_at = $now`,
      { id: instanceId, profile: row?.profile ?? null, enabled: row ? Boolean(row.enabled) : null, domains: row ? domains : null, updated_at: row?.updated_at ?? null, by: row?.updated_by ?? null, now: now(), provider: PROVIDER, account: accountResolver()(null, instanceId) ?? accountId() });
  });
}
/** After the executor planned, applied, read back, reverted or retired a row: the ledger is history future agents act on. */
export const mirrorActionsInBackground = (ids?: number[]) => inBackground(`action mirror${ids ? ` (${ids.join(", ")})` : ""}`, () => mirrorActions(ids));

/** Ledger rows deleted on the page (src/executor.ts deleteActions) leave the graph too: the node and every edge on it. */
export async function forgetActions(ids: number[]): Promise<{ forgotten: number }> {
  if (!enabled() || !ids.length) return { forgotten: 0 };
  await write("UNWIND $ids AS id MATCH (a:AdvisorAction {id: id}) DETACH DELETE a", { ids });
  return { forgotten: ids.length };
}
export const forgetActionsInBackground = (ids: number[]) => inBackground(`action forget (${ids.join(", ")})`, () => forgetActions(ids));
/** At the end of every executor pass: the pass node and its edges to the rows it touched (src/executor_log.ts). */
export const mirrorPassInBackground = (passId: number) => inBackground(`pass mirror (${passId})`, () => mirrorPass(passId));
/** After the watcher read the EC2 status checks (src/status_checks.ts): the statuses on the resources. */
export const mirrorStatusChecksInBackground = () => inBackground("status check mirror", mirrorStatusChecks);
/** After a probe recorded what runs on an instance (src/instance_apps.ts): its RUNS edges. */
export const mirrorAppsInBackground = (instanceIds?: string[]) => inBackground(`app mirror${instanceIds ? ` (${instanceIds.join(", ")})` : ""}`, () => mirrorApps(instanceIds));

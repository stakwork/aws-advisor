/**
 * The adapter boundary (docs/cloud-ontology.md §8 step 6). A provider adapter owns its credentials, its accounts, its
 * collection and its storage (the SQLite tables it fills are its own), and emits the generic model: ResourceNode rows
 * for the mirror plus the graph layers it knows how to write (ports, network, clusters, software, ...). Everything
 * above the boundary (the mirror core, rules, the executor, the pages) reads the generic shape and asks the registry
 * (src/adapters/index.ts) which adapters exist. AWS and Vercel implement it; a new provider is a new directory here.
 */

export const AWS = "aws";
export type ProviderId = "aws" | "gcp" | "azure" | "vercel" | "cloudflare";

export const RESOURCE_LABELS = ["AdvisorCompute", "AdvisorDatabase", "AdvisorCache", "AdvisorLoadBalancer", "AdvisorFunction", "AdvisorStorage", "AdvisorDeployment", "AdvisorDnsZone", "AdvisorDnsRecord", "AdvisorIdentity",
  "AdvisorCertificate", "AdvisorMessaging", "AdvisorSecret", "AdvisorAnalytics", "AdvisorStack", "AdvisorBackupPlan", "AdvisorDetector", "AdvisorFilter"] as const;
export type ResourceLabel = (typeof RESOURCE_LABELS)[number];
export type GenericState = "running" | "stopped" | "pending" | "terminated" | "available" | "degraded" | "unknown";
export type TelemetryKind = "api" | "metrics" | "probe" | "logs" | "audit" | "bill";

/** One resource as the mirror writes it: the generic shared shape plus the specific label's own properties in `props`. */
export interface ResourceNode {
  id: string; label: ResourceLabel; native_type: string; name: string | null; state: GenericState; native_state: string | null; region: string | null;
  /** the account the row belongs to when it is not the adapter's primary one (a member of an AWS organisation); the mirror attaches it there */
  account_id?: string | null;
  role: string | null; role_confidence: number | null; protected_prob: number | null; monthly_usd: number | null; gone: boolean; first_seen: string | null; last_seen: string | null;
  /** The autoscaling pool an EC2 node belongs to (name and kind); null for everything else. */
  pool: string | null; pool_kind: string | null;
  /** Label-specific properties (type, engine, runtime, ...). */
  props: Record<string, unknown>;
  /** The telemetry that covers it: which sources, with their status and last report. */
  observed: { kind: TelemetryKind; status: "ok" | "stale" | "offline"; last_at: string | null; detail: string | null }[];
}

/** One account the advisor is pointed at, as every provider reports it (the AdvisorAccount node, the Settings row). */
export interface AccountRecord {
  provider: ProviderId;
  /** the provider's own id: an AWS account id, a GCP project id, a Vercel team id */
  id: string;
  /** the provider's word for the boundary: account, project, subscription, team, organization */
  native_type: string;
  name: string;
  parent_id: string | null;
  /** how the advisor reaches it, in words (never a secret): "access key AKIA…", "profile x", "role arn:…", "instance role" */
  access: string;
  /** the advisor may act there (an actuator role / write token exists) */
  actuator: boolean;
  enabled: boolean;
  last_test: { ok: boolean; detail: string | null; at: string | null } | null;
}

/** What an adapter asks for when an account is added, as the Settings page shows it. */
export interface CredentialFlow { boundary: string; credentials: string; children: string }

/** A graph layer the adapter writes beyond the resource nodes (ports, network, clusters, software, status checks, ...). */
export interface GraphLayer { name: string; mirror: () => Promise<unknown>;
  /** mirrored again right after one of the provider's runs (not only on a full resync) */
  after_run?: boolean }

export interface AdapterCapabilities { probes: boolean; metrics: boolean; executor: boolean; compliance: boolean; cost: boolean; bill: boolean; findings: boolean; changes: boolean; alerts: boolean; clusters: boolean; software: boolean; network: boolean }

/**
 * A scheduled job the provider owns: its collection, its scans, its passes. The scheduler runs every registered
 * adapter's jobs (src/scheduler.ts); "Run now" on the Settings page calls the same `run`.
 */
export interface ProviderJob {
  /** the runtime-settings key of its cron expression; also the job's id for "Run now" */
  key: string;
  label: string;
  /** the log name the scheduler prints when it starts ("Scheduler (RUN_CRON)") */
  schedule_name: string;
  /** the log tag ("[scheduler]", "[vercel]") */
  tag: string;
  /** the cron expression now (read on every scheduler start, so a change in Settings applies after the restart) */
  cron(): string;
  /** why the job cannot run now (no credentials, no agent URL), or null; checked by the scheduler and "Run now" */
  blocked?(): string | null;
  /** schedule nothing (logged as disabled) while this returns a reason, even with a cron set */
  disabled?(): string | null;
  run(): Promise<string>;
}

/** Rules and benchmarks: the passes that turn the adapter's storage into findings and recommendations (rows in `runs`, `findings`, `recommendations` with this provider). */
export interface ProviderRules {
  /** the latest completed rules run of the account (null = the provider's primary), for the findings and playbooks pages */
  latestRunId(accountId: string | null): number | undefined;
  /** the benchmark ids the provider can run, and the ones it runs by default (empty for a provider whose rules are its own code) */
  benchmarks(): { all: string[]; defaults: string[] };
  /** start a rules pass now; returns the run id or a reason it did not start */
  start(trigger: string): Promise<{ run_id: number | null; note: string }>;
  /** what its run is called on the AdvisorRun node (`collection_run`, `rules_pass`) */
  run_native_type: string;
  /** the control id prefixes its findings and playbooks use (`aws_`, `vercel.`), so a control can be traced to its provider */
  control_prefixes: string[];
  /** the control a recommendation of one of its rules comes from, when the rule names it (vercel_x → vercel.control.x) */
  controlForRule?(rule: string): string | null;
  /** where a control comes from and what it is about (framework, category), read off its id; null when it is not the provider's */
  controlFacts?(controlId: string, benchmark?: string | null): { framework: string; category: string } | null;
  /** the official pages each of its controls' playbooks are generated from (src/playbook_gen.ts) */
  controlSources(): Record<string, string[]>;
  /** which findings of its latest runs make a control due for a playbook: alarms only, or every finding (info ones carry recommendations too) */
  playbooks_from: "alarm" | "all";
  /** a control with sources listed is due for a playbook before any run has flagged it */
  seed_playbooks: boolean;
}

/**
 * What the executor needs from a provider to act: its action modules and a way to build the credentials they run
 * under. The modules' own types live with the provider (src/executor.ts types the AWS ones); the executor only
 * routes a kind to its provider and hands the provider's credentials through.
 */
export interface ProviderActions {
  /** load the provider's action modules into the executor's registry (each registers under this provider) */
  register(): Promise<void>;
  /** the credentials a plan, apply, verify or revert runs under (opaque to the core; the provider's modules know their shape) */
  credentials(): Promise<unknown>;
}

/** Adding, testing and removing accounts, and checking what the advisor may do there: the Settings flows behind one shape (POST /api/providers/:id/accounts and the rest, src/routes/accounts.ts). */
export interface ProviderOnboarding {
  /** add an account (a member, a team, a project) from the Settings form; `status` is the HTTP answer (400 for a refused input) */
  add(body: Record<string, unknown>): Promise<{ ok: boolean; status?: number; error?: string; [k: string]: unknown }>;
  /** test an account's access now */
  test(accountId: string): Promise<{ ok: boolean; [k: string]: unknown }>;
  /** forget an account's credentials (its stored rows go with a purge, src/purge.ts) */
  remove(accountId: string): Promise<{ ok: boolean; status?: number; error?: string; [k: string]: unknown }>;
  /** what the advisor may read and change there, as the provider checks it (IAM simulation and probes on AWS) */
  permissionCheck?(accountId: string | null, opts?: Record<string, unknown>): Promise<unknown>;
  /** the one-time setup that grants the advisor its access, in words: a script to run, a token to create */
  setup: { kind: "script" | "token"; detail: string };
}

/** Where the money comes from: the provider's bill, stored by provider (`spend_daily`, `spend_by_account_monthly`) or in its own tables, read back in shared shapes. */
export interface ProviderCost {
  /** refresh the stored spend from the provider's bill; skipped (with the reason) when fresh or not possible */
  refresh(opts?: { force?: boolean; onLog?: (l: string) => void }): Promise<{ refreshed: boolean; note: string }>;
  /** the last full month's bill of one account (the current month when nothing else exists) */
  lastBill(accountId: string): { month: string | null; usd: number | null };
  /** this month in the provider's own terms (a projection, a period estimate, stores at their plans); `to_total` says whether it adds to the month across providers */
  month(): Promise<{ key: string; label: string; usd: number | null; to_total: boolean; month_to_date_usd?: number | null }[]>;
}

/** One line of the "needs attention" list across accounts: whose it is, how urgent, what, and where to look. */
export interface AttentionItem { account: string; level: "alarm" | "warning" | "info"; what: string; link: string | null; count?: number }

/**
 * The views the UI draws for an account of this provider. Pages look up the provider's view for their slot
 * (ui/src/views.ts maps the ids to components); a slot the provider does not declare falls back to the generic page
 * or "not available". Adding a provider is declaring its views and registering its components; no page names it.
 */
export interface ProviderUi {
  /** the Overview page for one account of this provider */
  overview: string;
  /** the Bill page */
  bill?: string;
  /** the Changes page */
  changes?: string;
  /** the Inventory tabs this provider has (the shared tab ids), each with the view that draws it and the provider's word for what it lists */
  inventory: { tab: string; view: string; label?: string }[];
  /** the Settings sections an account has, each drawn by a view id */
  settings: { id: string; label: string; view: string }[];
}

export interface ProviderAdapter {
  id: ProviderId;
  label: string;
  flow: CredentialFlow;
  capabilities: AdapterCapabilities;
  /** the SQLite tables this adapter owns (its storage behind the boundary) */
  storage: string[];
  /** the telemetry sources it writes AdvisorTelemetry nodes for */
  telemetry: Record<TelemetryKind, { native: string }>;
  configured(): boolean;
  /** the primary account's id as the adapter knows it (the mirror keys everything by it) */
  primaryAccountId(): string;
  accounts(): Promise<AccountRecord[]>;
  /** refresh the adapter's storage from the provider; errors are returned, never thrown */
  collect(opts?: { full?: boolean }): Promise<{ errors: string[] }>;
  /** every resource of the account as the generic model, from the adapter's storage */
  resources(accountId: string): ResourceNode[];
  /** the ids its resource nodes carry, for matching what records name (a recommendation's resource) to a node; resources() ids when absent */
  resourceIds?(accountId: string): Set<string>;
  /** the adapter's own edges between its resources, written right after the resource nodes; returns ids of any extra nodes it created (the core keeps them from being marked gone) */
  edges?: (accountId: string, stamp: string) => Promise<string[]>;
  /** the graph layers beyond resources, in dependency order */
  layers: GraphLayer[];
  /** rows of its storage written before account ids were kept carry an empty account_id and belong to its primary account */
  legacy_blank_account?: boolean;
  /** whether an account id is one of this provider's (the scope picker's id resolves to its provider through this) */
  owns(accountId: string): boolean;
  /** which of its accounts a stored row belongs to, from the resource it names and its details; null = the primary */
  accountOf(resource: string | null | undefined, details?: Record<string, unknown> | null): string | null;
  /** forget what its own storage keeps about one account under its own key (tables without an account_id column: a team's projects); rows removed per table, or that would be with dryRun */
  purgeStorage?(accountId: string, opts: { dryRun: boolean }): Record<string, number>;
  /** one line for the agent's instructions: which account this is and which tools and tables reach it (null when not configured) */
  agentNote?(): string | null;
  /** the provider's own API routes (its Settings sections, its pages' detail views), mounted under /api before the shared ones */
  routes?(): Promise<import("express").Router[]>;
  /** start-up checks the provider runs once the server listens (judge the latest probes, restore a connection file) */
  onStart?(): void;
  /** the scheduled jobs it owns */
  jobs: ProviderJob[];
  rules?: ProviderRules;
  actions?: ProviderActions;
  onboarding?: ProviderOnboarding;
  cost?: ProviderCost;
  /** what needs a person across its accounts now (alarm findings, open alerts, a rules pass's warnings), for the general overview */
  attention?(): Promise<AttentionItem[]>;
  ui: ProviderUi;
}

/** A provider the advisor knows about but has no adapter for yet: listed in Settings with what it will need. */
export interface ProviderStub { id: ProviderId; label: string; flow: CredentialFlow; available: false }

/**
 * The adapter boundary (docs/cloud-ontology.md §8 step 6). A provider adapter owns its credentials, its accounts, its
 * collection and its storage (the SQLite tables it fills are its own), and emits the generic model: ResourceNode rows
 * for the mirror plus the graph layers it knows how to write (ports, network, clusters, software, ...). Everything
 * above the boundary (the mirror core, rules, the executor, the pages) reads the generic shape and asks the registry
 * (src/adapters/index.ts) which adapters exist. One adapter today (AWS); the shape is what a second one implements.
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
export interface GraphLayer { name: string; mirror: () => Promise<unknown> }

export interface AdapterCapabilities { probes: boolean; metrics: boolean; executor: boolean; compliance: boolean; cost: boolean; bill: boolean; findings: boolean; changes: boolean; alerts: boolean; clusters: boolean; software: boolean; network: boolean }

export interface ProviderAdapter {
  id: ProviderId;
  label: string;
  flow: CredentialFlow;
  capabilities: AdapterCapabilities;
  /** the Settings sections an account of this provider has, in order */
  sections: { id: string; label: string }[];
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
  /** the adapter's own edges between its resources, written right after the resource nodes; returns ids of any extra nodes it created (the core keeps them from being marked gone) */
  edges?: (accountId: string, stamp: string) => Promise<string[]>;
  /** the graph layers beyond resources, in dependency order */
  layers: GraphLayer[];
}

/** A provider the advisor knows about but has no adapter for yet: listed in Settings with what it will need. */
export interface ProviderStub { id: ProviderId; label: string; flow: CredentialFlow; available: false }

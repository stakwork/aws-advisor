import { awsAdapter } from "./aws/index.js";
import { vercelAdapter } from "./vercel/index.js";
import { localAdapter } from "./local/index.js";
import { githubAdapter } from "./github/index.js";
import type { AccountRecord, ProviderAdapter, ProviderId, ProviderStub } from "./types.js";

export type { AccountRecord, ProviderAdapter, ProviderId } from "./types.js";

/**
 * The adapter registry: which providers have an adapter, and which the advisor knows about but cannot collect from
 * yet. Everything above the boundary asks here (the mirror, the accounts API, Settings); adding a provider is adding
 * an adapter to this list and an entry for its flow.
 */

// read when asked, not at load: the adapters reach modules that reach this registry, and a list built at load could see one not yet initialised
const list = (): ProviderAdapter[] => [awsAdapter, vercelAdapter, githubAdapter, localAdapter];

/** Providers without an adapter, with what each will need (docs/cloud-ontology.md §8a). */
export const PROVIDER_STUBS: ProviderStub[] = [
  { id: "gcp", label: "Google Cloud", flow: { boundary: "project", credentials: "a service account key or workload identity per project", children: "folders and the organisation list projects; one service account with org-level viewer covers them" }, available: false },
  { id: "azure", label: "Azure", flow: { boundary: "subscription", credentials: "a service principal (tenant, client, secret or certificate)", children: "the tenant and management groups list subscriptions" }, available: false },
  { id: "cloudflare", label: "Cloudflare", flow: { boundary: "account", credentials: "an API token scoped to the account", children: "none" }, available: false },
];

export const adapters = (): ProviderAdapter[] => list();
export const adapterFor = (id: string): ProviderAdapter | null => list().find((a) => a.id === id) ?? null;

export interface ProviderDescriptor { id: ProviderId; label: string; boundary: string; credentials: string; children: string; available: boolean; configured: boolean; sections: { id: string; label: string }[]; capabilities: ProviderAdapter["capabilities"] | null; ui: ProviderAdapter["ui"] | null }

/** Every provider as Settings lists it: adapters first (with whether one is configured), then the stubs. */
export function providers(): ProviderDescriptor[] {
  return [
    ...list().map((a) => ({ id: a.id, label: a.label, boundary: a.flow.boundary, credentials: a.flow.credentials, children: a.flow.children, available: true, configured: a.configured(), sections: a.ui.settings.map((x) => ({ id: x.id, label: x.label })), capabilities: a.capabilities, ui: a.ui })),
    ...PROVIDER_STUBS.map((s) => ({ id: s.id, label: s.label, boundary: s.flow.boundary, credentials: s.flow.credentials, children: s.flow.children, available: false, configured: false, sections: [], capabilities: null, ui: null })),
  ];
}

/** Every account across adapters, parents first. */
export async function allAccounts(): Promise<AccountRecord[]> {
  const out: AccountRecord[] = [];
  for (const a of list()) { try { out.push(...(await a.accounts())); } catch (e: any) { console.error(`[adapters] ${a.id} accounts: ${e?.message || e}`); } }
  return out.sort((x, y) => Number(x.parent_id != null) - Number(y.parent_id != null) || x.id.localeCompare(y.id));
}

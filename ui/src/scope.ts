import { useEffect, useState } from "react";
import { api, currentScope, currentScopeProvider, onScopeChange, setScope } from "./api";

/**
 * What the pages may show for the account the sidebar looks at. Each provider declares its capabilities
 * (GET /api/providers); a page that needs one the scoped provider lacks shows "not available" instead of another
 * provider's data, and the nav hides it. Providers never mix: "all accounts" shows a page when any configured
 * provider has the capability, and the page itself filters by account.
 */

export type Capability = "probes" | "metrics" | "executor" | "compliance" | "cost" | "bill" | "findings" | "changes" | "alerts" | "clusters" | "software" | "network";
export interface ProviderInfo { id: string; label: string; configured: boolean; available: boolean; capabilities: Record<Capability, boolean> | null }

const CAPS_KEY = "advisor_providers_caps";
const readCache = (): ProviderInfo[] | null => { try { const v = localStorage.getItem(CAPS_KEY); return v ? JSON.parse(v) : null; } catch { return null; } };
let inflight: Promise<ProviderInfo[]> | null = null;
export function loadProviders(): Promise<ProviderInfo[]> {
  if (!inflight) inflight = api("/providers").then((d) => { const list: ProviderInfo[] = (d.providers || []).map((p: any) => ({ id: p.id, label: p.label, configured: p.configured, available: p.available, capabilities: p.capabilities })); try { localStorage.setItem(CAPS_KEY, JSON.stringify(list)); } catch { /* ignore */ } return list; }).catch(() => readCache() ?? []);
  return inflight;
}

export interface ScopeInfo { scope: string; provider: string | null; providers: ProviderInfo[]; ready: boolean; has: (c: Capability) => boolean; label: string }

/** The scope, its provider and whether a capability is on the table; cached so the first paint is right. */
export function useScopeInfo(): ScopeInfo {
  const [scope, setScopeState] = useState(currentScope());
  const [providers, setProviders] = useState<ProviderInfo[]>(readCache() ?? []);
  const [ready, setReady] = useState(Boolean(readCache()));
  useEffect(() => { loadProviders().then((l) => { setProviders(l); setReady(true); }); return onScopeChange(setScopeState); }, []);
  const provider = scope === "all" ? null : currentScopeProvider();
  const has = (c: Capability) => {
    if (!providers.length) return true; // nothing known yet: do not hide
    if (provider) return Boolean(providers.find((p) => p.id === provider)?.capabilities?.[c]);
    return providers.some((p) => p.configured && p.capabilities?.[c]);
  };
  const label = provider ? (providers.find((p) => p.id === provider)?.label ?? provider) : "all accounts";
  return { scope, provider, providers, ready, has, label };
}

export { setScope };

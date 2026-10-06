import { awsResourceIndex } from "./adapters/aws/account_index.js";
import { vercelResourceIndex } from "./adapters/vercel/account_index.js";

/**
 * Which account a resource id belongs to, across providers: each provider's index over its own storage
 * (src/adapters/<provider>/account_index.ts), asked in turn. A module that imports only those indexes (which import
 * only the database), so the adapters, the overview and the mirror can all use it without a cycle through the
 * adapter registry. A new provider adds its index to INDEXES.
 */

type Index = { of: (resource: string | null | undefined) => string | null };
/** `primary` is the AWS primary account: AWS rows stored before account ids were kept are its. */
const INDEXES: Record<string, (primary: string) => Index> = { aws: awsResourceIndex, vercel: () => vercelResourceIndex() };

/** One provider's index. */
export function resourceIndexFor(provider: string, primary: string): Index {
  return (INDEXES[provider] ?? (() => ({ of: () => null })))(primary);
}

/** Every provider's index, the first answer wins (ids do not collide across providers). */
export function resourceAccountIndex(primary: string): Index {
  const parts = Object.values(INDEXES).map((b) => b(primary));
  return { of: (resource) => { for (const p of parts) { const a = p.of(resource); if (a) return a; } return null; } };
}

const cache = new Map<string, { at: number; idx: Index }>();
/** The same, reused for a few seconds: what row writers call once per row (an alert, a recommendation) without rebuilding it each time. */
export function cachedResourceIndex(provider: string, primary: string): Index {
  const key = `${provider}:${primary}`; const hit = cache.get(key);
  if (hit && Date.now() - hit.at < 5000) return hit.idx;
  const idx = resourceIndexFor(provider, primary); cache.set(key, { at: Date.now(), idx }); return idx;
}

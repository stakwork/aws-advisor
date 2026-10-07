import type { ReactNode } from "react";
import { Empty } from "./components/ui";
import { useScopeInfo, type PageSlot } from "./scope";
import { VercelOverview } from "./components/vercelOverview";
import { VercelBill } from "./components/vercelBill";
import { VercelStores } from "./components/vercelStores";
import { VercelAccess, VercelChanges, VercelMembers, VercelPartners, VercelProjects } from "./components/vercel";
import { LocalMachines } from "./components/local";
import { AwsOverview } from "./pages/Overview";
import { AwsThisMonth } from "./pages/Bill";
import { AwsChanges } from "./pages/Changes";

/**
 * Every view a provider can declare (src/adapters/types.ts ProviderUi), by id. Each adapter says which view draws its
 * Overview, Bill, Changes, Inventory tabs and Settings sections; the pages look the id up here and never name a
 * provider. A new provider adds its components here and declares their ids in its adapter.
 */
const page = (title: string, body: ReactNode) => <div className="space-y-6"><h1 className="text-xl font-semibold text-zinc-100">{title}</h1>{body}</div>;

export const VIEWS: Record<string, (props: any) => ReactNode> = {
  "aws.overview": () => <AwsOverview />,
  "aws.bill": () => <AwsThisMonth />,
  "aws.changes": () => <AwsChanges />,
  "vercel.overview": () => page("Overview", <VercelOverview />),
  "vercel.bill": () => <VercelBill />,
  "vercel.changes": () => page("Changes", <VercelChanges />),
  "vercel.projects": () => <VercelProjects />,
  "vercel.members": () => <VercelMembers />,
  "vercel.stores.database": () => <VercelStores kind="database" />,
  "vercel.stores.cache": () => <VercelStores kind="cache" />,
  "vercel.stores.storage": () => <VercelStores kind="storage" />,
  "vercel.access": (p: { configured: boolean; onChange: () => void }) => <VercelAccess {...p} />,
  "vercel.partners": () => <VercelPartners />,
  "local.overview": () => page("Local machines", <LocalMachines />),
  "local.machines": (p: { configured?: boolean; onChange?: () => void }) => <LocalMachines {...p} />,
};

/** One view by id, or `fallback` when no provider view has that id. */
export function ProviderView({ id, fallback = null, ...props }: { id: string | null | undefined; fallback?: ReactNode; [k: string]: unknown }) {
  const V = id ? VIEWS[id] : undefined;
  return <>{V ? V(props) : fallback}</>;
}

/** A page drawn by the scope's provider: its declared view for the slot, or "not available" once the providers are known. */
export function ScopedPage({ slot, what }: { slot: PageSlot; what: string }) {
  const scopeInfo = useScopeInfo();
  const id = scopeInfo.view(slot);
  if (!id && !scopeInfo.providers.some((p) => p.ui)) return null; // the provider list (with its views) is still loading
  return <ProviderView id={id} fallback={<Empty>No {what} for {scopeInfo.label} yet.</Empty>} />;
}

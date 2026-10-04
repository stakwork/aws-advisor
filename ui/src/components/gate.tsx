import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { Empty } from "./ui";
import { useScopeInfo, type Capability } from "../scope";

const WORDS: Record<Capability, string> = {
  probes: "SSM probes", metrics: "CloudWatch metrics and the watcher", executor: "the executor", compliance: "the security benchmarks", cost: "the cost benchmarks", bill: "a bill the advisor can read", findings: "findings and recommendations", changes: "a change record", alerts: "alerts", clusters: "clusters", software: "the software inventory and vulnerability matching", network: "the network layer",
};

/** Renders the page only when the scoped provider has the capability; otherwise says so instead of showing another provider's data. */
export function Gate({ need, children }: { need: Capability; children: ReactNode }) {
  const s = useScopeInfo();
  if (s.has(need)) return <>{children}</>;
  return (
    <div className="space-y-3">
      <Empty>
        Not available for {s.label}: this page needs {WORDS[need]}, which that provider does not have. Pick another account under "Looking at" in the sidebar, or <Link className="underline" to="/inventory">open the inventory</Link>, which every provider has.
      </Empty>
    </div>
  );
}

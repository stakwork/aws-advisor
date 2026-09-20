import { Badge, Button } from "./ui";
import { pct } from "./incident";

/** Jev's triage as stored on an alert (alerts.triage): see src/triage.ts. */
export interface AlertTriage {
  expected: number;
  kind: string;
  kind_confidence: number;
  severity: number;
  severity_label: string;
  severity_confidence: number;
  decision: "acknowledge" | "investigate" | "open";
  model?: string;
  latency_ms?: number;
}

/** GET /api/alerts rows carry `triage` parsed; the Overview's alerts come from the same reader. */
export function triageOfAlertRow(a: any): AlertTriage | null {
  const t = a?.triage;
  if (!t) return null;
  if (typeof t === "string") { try { return JSON.parse(t); } catch { return null; } }
  return t as AlertTriage;
}

/** One line: kind, severity label, expected probability; plus "auto-acknowledged by Jev" with Undo where applicable. */
export function TriageLine({ alert, triage, onUndo, compact = false }: { alert: any; triage: AlertTriage; onUndo?: () => void; compact?: boolean }) {
  const byJev = alert?.acknowledged && alert?.acknowledged_by === "jev";
  return (
    <div className={`flex flex-wrap items-center gap-x-3 gap-y-1 ${compact ? "text-[11px]" : "text-xs"} text-zinc-400`}>
      <span className="text-zinc-500">Jev</span>
      <Badge>{triage.kind}</Badge>
      <span title={`severity ${triage.severity.toFixed(2)} (confidence ${pct(triage.severity_confidence)})`}>{triage.severity_label}</span>
      <span title="probability that this is expected, routine behaviour">expected <span className="text-zinc-200">{pct(triage.expected)}</span></span>
      {triage.decision === "investigate" && !byJev && <span className="text-amber-300">eligible for investigation</span>}
      {byJev && <span className="text-emerald-300">auto-acknowledged by Jev</span>}
      {byJev && onUndo && <Button variant="ghost" className="!px-2 !py-0.5 !text-[11px]" onClick={onUndo}>Undo</Button>}
    </div>
  );
}

/** Jev's role for a resource (resource_roles): see src/roles.ts. */
export interface ResourceRole { role: string; role_confidence: number; protected_prob: number; updated_at: string }

export function RoleLine({ role }: { role: ResourceRole | null | undefined }) {
  if (!role) return <span className="text-zinc-500">not classified yet (Jev classifies stopped and idle instances and RDS on each run)</span>;
  return (
    <span className="inline-flex flex-wrap items-center gap-2">
      <Badge>{role.role}</Badge>
      <span className="text-zinc-400">{pct(role.role_confidence)} confidence</span>
      <span className={role.protected_prob >= 0.7 ? "text-amber-300" : "text-zinc-400"} title="Jev's read of the name, tags and description: how likely it is that this resource is deliberately kept (a 'do not delete' marker, an owner note, a production-critical tag). At 70% or more every recommendation on it becomes report-only. A low value means no such marker was found, not that it is safe to remove.">{role.protected_prob >= 0.7 ? "keep-marker found" : "no keep-marker"} {pct(role.protected_prob)}{role.protected_prob >= 0.7 ? " (report-only)" : ""}</span>
    </span>
  );
}

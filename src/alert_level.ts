/**
 * How serious an alert is, from its kind and Jev's triage. One place for the server (ordering, counts) and
 * the UI (badges): ui/src/alertLevel.ts re-exports this file, so the two cannot drift. No imports on purpose.
 */
export type AlertLevel = "alarm" | "warning" | "info";

export const ALERT_LEVELS: AlertLevel[] = ["alarm", "warning", "info"];

/** Sort rank: alarm before warning before info. */
export const LEVEL_RANK: Record<AlertLevel, number> = { alarm: 0, warning: 1, info: 2 };

/** `triage` may arrive as the parsed object (API rows) or as the raw JSON string (a bare alerts row). */
function triageOf(a: { triage?: unknown }): { severity?: unknown; expected?: unknown } | null {
  const t = a.triage;
  if (!t) return null;
  if (typeof t === "string") { try { return JSON.parse(t); } catch { return null; } }
  return typeof t === "object" ? (t as { severity?: unknown; expected?: unknown }) : null;
}

export function alertLevel(a: { kind: string; triage?: unknown }): AlertLevel {
  const triage = triageOf(a);
  if (a.kind === "credentials") return "alarm";
  if (a.kind === "nat_traffic") return triage && Number(triage.severity) < 1 ? "warning" : "alarm";
  if (a.kind === "instance_state") return triage && Number(triage.expected) >= 0.7 ? "info" : "warning";
  if (a.kind === "disk_fill" || a.kind === "quota" || a.kind === "disk_full") return "alarm";
  if (a.kind === "disk_high") return "warning";
  if (a.kind === "spend_step" || a.kind === "memory_pressure" || a.kind === "log_step") return "warning";
  return "info"; // node_churn and anything expected
}

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

export function alertLevel(a: { kind: string; triage?: unknown; details?: unknown }): AlertLevel {
  const triage = triageOf(a);
  // a provider's rules pass says the level itself (the finding's severity) in the alert's details; the advisor's own raisers never set it
  try { const d = typeof a.details === "string" ? JSON.parse(a.details) : a.details; const l = String((d as any)?.level ?? ""); if (l === "alarm" || l === "warning" || l === "info") return l; } catch { /* */ }
  if (a.kind === "credentials") return "alarm";
  if (a.kind === "nat_traffic") return triage && Number(triage.severity) < 1 ? "warning" : "alarm";
  if (a.kind === "instance_state") return triage && Number(triage.expected) >= 0.7 ? "info" : "warning";
  if (a.kind === "disk_fill" || a.kind === "quota" || a.kind === "disk_full") return "alarm";
  if (a.kind === "disk_high" || a.kind === "memory_high" || a.kind === "swap_in_use" || a.kind === "load_high" || a.kind === "reboot") return "warning";
  if (a.kind === "memory_full" || a.kind === "status_check_failed") return "alarm";
  if (a.kind === "lambda_errors" || a.kind === "commitment_underused" || a.kind === "cache_memory_high" || a.kind === "rds_memory_low" || a.kind === "network_step") return "warning";
  if (a.kind === "commitment_expiring") return "alarm";
  if (a.kind === "cert_expiring") return "warning"; // the alert's own details.level (alarm at 7 days or fewer) is read above
  if (a.kind === "spend_step" || a.kind === "memory_pressure" || a.kind === "log_step" || a.kind === "app_gone" || a.kind === "port_exposed") return "warning";
  // Domain registry alerts (raised by src/aws/route53_domains_inventory.ts — TODO: collector not yet implemented)
  // domain_expiring        → warning (days_until_expiry ≤ 60) or alarm (≤ 14)
  // domain_auto_renew_off  → warning
  // domain_transfer_lock_off → warning
  // domain_no_zone         → warning (registration has no DNS_OF edge)
  // domain_contact_missing → warning (no HAS_CONTACT edge of kind registrant)
  // domain_ns_mismatch     → warning (registrar nameservers ≠ zone NS records)
  // domain_unmanaged       → info    (domain has DNS records but no registrar API source)
  // domain_no_spf          → warning
  // domain_no_dmarc        → warning
  // domain_dmarc_unenforced → warning (DMARC p=none)
  // domain_dkim_missing    → warning
  if (a.kind === 'domain_expiring') {
    const days = (a.details as any)?.days_until_expiry;
    return typeof days === 'number' && days <= 14 ? 'alarm' : 'warning';
  }
  if (['domain_auto_renew_off', 'domain_transfer_lock_off', 'domain_no_zone', 'domain_contact_missing', 'domain_ns_mismatch', 'domain_no_spf', 'domain_no_dmarc', 'domain_dmarc_unenforced', 'domain_dkim_missing'].includes(a.kind)) return 'warning';
  if (a.kind === 'domain_unmanaged') return 'info';
  return "info"; // node_churn and anything expected
}

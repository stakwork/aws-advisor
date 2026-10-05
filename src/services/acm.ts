/**
 * ACM certificates as AdvisorCertificate (docs/cloud-ontology.md §AdvisorCertificate): the names covered, who issued
 * it, validity and days left, whether anything uses it, and SECURES edges to what terminates TLS with it (a balancer,
 * a distribution, an API). Public and imported certificates cost nothing; a private CA's certificates are not priced.
 */
import { daysUntil, iso, json, str, tagsOf, type CollectContext, type CollectResult, type ServiceCollector, type ServiceRow } from "../service_inventory.js";

const STATUS: Record<string, string> = { ISSUED: "issued", EXPIRED: "expired", PENDING_VALIDATION: "pending", REVOKED: "revoked", FAILED: "failed", INACTIVE: "inactive", VALIDATION_TIMED_OUT: "failed" };

export function acmRow(c: any, now = Date.now()): ServiceRow {
  const arn = String(c.certificate_arn);
  const sans: string[] = Array.isArray(json(c.subject_alternative_names)) ? json(c.subject_alternative_names).map(String) : [];
  const domains = [...new Set([str(c.domain_name), ...sans].filter((d): d is string => Boolean(d)))];
  const inUse: string[] = Array.isArray(json(c.in_use_by)) ? json(c.in_use_by).map(String) : [];
  const type = String(c.type || "").toUpperCase();
  const notAfter = iso(c.not_after);
  return {
    native_type: "acm_certificate", id: arn, arn, account_id: str(c.account_id) ?? "", region: str(c.region) ?? "", name: str(c.domain_name), state: str(c.status), created: iso(c.created_at) ?? iso(c.imported_at),
    tags: tagsOf(c.tags), monthly_usd: type === "PRIVATE" ? null : 0,
    props: {
      domains, issuer: type === "AMAZON_ISSUED" ? "acm" : type === "PRIVATE" ? "private_ca" : str(c.issuer)?.toLowerCase() ?? "imported", native_issuer: str(c.issuer), origin: type === "IMPORTED" ? "imported" : type === "PRIVATE" ? "private" : "issued",
      status: STATUS[String(c.status)] ?? str(c.status)?.toLowerCase() ?? null, not_before: iso(c.not_before), not_after: notAfter, days_left: daysUntil(notAfter, now),
      in_use: inUse.length > 0, used_by: inUse.length, key_algorithm: str(c.key_algorithm), renewal_eligible: c.renewal_eligibility == null ? null : String(c.renewal_eligibility) === "ELIGIBLE", failure_reason: str(c.failure_reason),
      wildcard: domains.some((d) => d.startsWith("*.")),
    },
    links: inUse.map((other) => ({ rel: "SECURES" as const, other, dir: "out" as const })),
  };
}

export const acmCollector: ServiceCollector = {
  name: "ACM certificates",
  async collect(ctx: CollectContext): Promise<CollectResult> {
    const raw = await ctx.select("aws_acm_certificate", ["certificate_arn", "domain_name", "subject_alternative_names", "status", "type", "issuer", "key_algorithm", "not_before", "not_after", "created_at", "imported_at", "in_use_by", "renewal_eligibility", "failure_reason", "tags", "region", "account_id"], { required: ["certificate_arn"] });
    if (!raw) return { rows: [], complete: [] };
    return { rows: raw.map((c) => acmRow(c)), complete: ["acm_certificate"] };
  },
};

/**
 * Content delivery distributions as AdvisorCdn {kind: distribution} (CloudFront today; Front Door, Cloud CDN or
 * Cloudflare land on the same label): the hostnames it answers to, whether it is enabled and deployed, the origins it
 * pulls from, the viewer TLS certificate and minimum version, the firewall attached (GUARDED_BY the web ACL), the
 * price tier, the HTTP versions, whether access logging is on and where, geo restrictions and tags. A distribution is
 * global, so its scope is "global" and it has no region. Not priced: the bill is traffic and requests, which this
 * inventory does not read. Only this collector and its native_type (cloudfront_distribution) are AWS's; the props
 * are the generic words of docs/cloud-ontology.md.
 */
import { iso, json, num, str, tagsOf, type CollectContext, type CollectResult, type ServiceCollector, type ServiceLink, type ServiceRow } from "../service_inventory.js";

/** The provider's price class in generic tiers: all locations, most locations, the cheapest locations. */
const PRICE_TIER: Record<string, string> = { PriceClass_All: "all", PriceClass_200: "mid", PriceClass_100: "low" };
const HTTP_VERSIONS: Record<string, string[]> = { "http1.1": ["http1.1"], http2: ["http1.1", "http2"], http3: ["http1.1", "http3"], http2and3: ["http1.1", "http2", "http3"] };
const VIEWER_PROTOCOL: Record<string, string> = { "allow-all": "allow_all", "redirect-to-https": "redirect_to_https", "https-only": "https_only" };
const items = (v: unknown): any[] => { const o = json(v); return Array.isArray(o) ? o : Array.isArray(o?.Items) ? o.Items : []; };

/** One distribution as a generic row; the id is the ARN. Pure. */
export function cdnRow(d: any): ServiceRow {
  const arn = String(d.arn);
  const origins = items(d.origins);
  const aliases = items(d.aliases).map(String);
  const behaviors = items(d.cache_behaviors);
  const defaultBehavior = json(d.default_cache_behavior) || {};
  const cert = json(d.viewer_certificate) || {};
  const logging = json(d.logging) || {};
  const restrictions = json(d.restrictions)?.GeoRestriction || {};
  const enabled = d.enabled == null ? null : Boolean(d.enabled);
  const status = str(d.status);
  const webAcl = str(d.web_acl_id);
  const certSource = cert.ACMCertificateArn ? "acm" : cert.IAMCertificateId ? "imported" : cert.CloudFrontDefaultCertificate ? "default" : null;
  const viewerProtocols = [defaultBehavior, ...behaviors].map((b) => VIEWER_PROTOCOL[String(b?.ViewerProtocolPolicy)]).filter((x): x is string => Boolean(x));
  const links: ServiceLink[] = [];
  // a classic web ACL is a bare id the inventory has no node for; only a web ACL ARN can be an edge
  if (webAcl?.startsWith("arn:")) links.push({ rel: "GUARDED_BY", other: webAcl, dir: "out", known_only: true });
  return {
    native_type: "cloudfront_distribution", id: arn, arn, account_id: str(d.account_id) ?? "", region: str(d.region) ?? "global", name: aliases[0] ?? str(d.domain_name) ?? str(d.id),
    // the provider's word stays in native_state; a disabled distribution is stopped whatever its deployment says
    state: enabled === false ? "disabled" : status, created: null, tags: tagsOf(d.tags), monthly_usd: null,
    props: {
      kind: "distribution", scope: "global", distribution_id: str(d.id), domain_name: str(d.domain_name), aliases, enabled,
      status: enabled === false ? "disabled" : status === "Deployed" ? "deployed" : status ? "pending" : null, native_status: status, description: str(d.comment),
      origins: origins.map((o) => str(o?.DomainName)).filter((x): x is string => Boolean(x)), origin_count: origins.length, behaviors: behaviors.length + 1, default_root_object: str(d.default_root_object),
      tls_certificate: str(cert.ACMCertificateArn) ?? str(cert.IAMCertificateId), tls_certificate_source: certSource, tls_min_version: str(cert.MinimumProtocolVersion), tls_sni_only: cert.SSLSupportMethod == null ? null : String(cert.SSLSupportMethod) === "sni-only",
      viewer_protocol: viewerProtocols.length ? (viewerProtocols.every((p) => p === "https_only") ? "https_only" : viewerProtocols.some((p) => p === "allow_all") ? "allow_all" : "redirect_to_https") : null,
      waf_attached: webAcl != null, waf_id: webAcl,
      price_tier: PRICE_TIER[String(d.price_class)] ?? null, native_price_tier: str(d.price_class),
      http_versions: HTTP_VERSIONS[String(d.http_version)] ?? (str(d.http_version) ? [String(d.http_version)] : []), ipv6_enabled: d.is_ipv6_enabled == null ? null : Boolean(d.is_ipv6_enabled),
      logging_enabled: d.logging == null ? null : Boolean(logging.Enabled), logging_target: logging.Enabled ? str(logging.Bucket) : null,
      geo_restriction: restrictions.RestrictionType ? String(restrictions.RestrictionType) === "none" ? "none" : String(restrictions.RestrictionType) === "whitelist" ? "allow" : "deny" : null,
      geo_countries: Array.isArray(restrictions.Items) ? restrictions.Items.map(String) : [], last_modified_at: iso(d.last_modified_time), invalidations_in_progress: num(d.in_progress_invalidation_batches),
    },
    links,
  };
}

export const cdnCollector: ServiceCollector = {
  name: "CDN distributions",
  async collect(ctx: CollectContext): Promise<CollectResult> {
    const raw = await ctx.select("aws_cloudfront_distribution", ["id", "arn", "domain_name", "status", "enabled", "http_version", "is_ipv6_enabled", "price_class", "web_acl_id", "comment", "last_modified_time", "in_progress_invalidation_batches",
      "aliases", "origins", "default_cache_behavior", "cache_behaviors", "viewer_certificate", "restrictions", "logging", "default_root_object", "tags", "region", "account_id"],
    { required: ["arn"], optional: { GetDistribution: ["logging", "default_root_object", "restrictions"] } });
    if (!raw) return { rows: [], complete: [] };
    return { rows: raw.map(cdnRow), complete: ["cloudfront_distribution"] };
  },
};

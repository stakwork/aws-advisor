/**
 * WAF web ACLs as AdvisorFilter {kind: web_acl} (a filter the provider bills, so also an AdvisorResource): the default
 * action, the rules in priority order (managed groups, rate limits, custom statements) with what each does, logging,
 * and GUARDED_BY edges from the balancers, APIs and distributions it is attached to. 30 days of allowed and blocked
 * requests from CloudWatch. Priced at list: 5 USD per ACL, 1 USD per rule or rule group, 0.60 USD per million requests.
 */
import { metricsByGroup, num, round2, str, tagsOf, json, type CollectContext, type CollectResult, type ServiceCollector, type ServiceRow } from "../service_inventory.js";

export const WAF_PRICE = { acl_month: 5, rule_month: 1, per_million_requests: 0.6 };

/** One rule as a line: "10 AWSManagedRulesCommonRuleSet: managed AWS group, count". Pure. */
export function wafRuleLine(r: any): string {
  const st = r?.Statement || {};
  const action = r?.Action ? Object.keys(r.Action)[0]?.toLowerCase() : r?.OverrideAction ? (Object.keys(r.OverrideAction)[0] === "None" ? "rule actions" : `override ${Object.keys(r.OverrideAction)[0]?.toLowerCase()}`) : "";
  const what = st.ManagedRuleGroupStatement ? `managed ${st.ManagedRuleGroupStatement.VendorName} group ${st.ManagedRuleGroupStatement.Name}`
    : st.RateBasedStatement ? `rate limit ${st.RateBasedStatement.Limit} per ${st.RateBasedStatement.EvaluationWindowSec ?? 300}s`
    : st.RuleGroupReferenceStatement ? "own rule group"
    : st.IPSetReferenceStatement ? "IP set" : st.GeoMatchStatement ? `geo ${(st.GeoMatchStatement.CountryCodes || []).join(" ")}` : Object.keys(st)[0]?.replace(/Statement$/, "").toLowerCase() || "custom";
  return `${r?.Priority ?? "?"} ${r?.Name ?? "?"}: ${what}${action ? `, ${action}` : ""}`;
}

export function wafRow(a: any, allowed?: { sum: number; days: number }, blocked?: { sum: number; days: number }): ServiceRow {
  const arn = String(a.arn);
  const rules: any[] = (Array.isArray(json(a.rules)) ? json(a.rules) : []).sort((x: any, y: any) => (x?.Priority ?? 0) - (y?.Priority ?? 0));
  const attached: string[] = (Array.isArray(json(a.associated_resources)) ? json(a.associated_resources) : []).map(String);
  const def = json(a.default_action) || {};
  const scale = (m?: { sum: number; days: number }) => (m && m.days > 0 ? Math.round(m.sum * (30 / m.days)) : null);
  const ok = scale(allowed); const no = scale(blocked);
  const requests = ok == null && no == null ? null : (ok ?? 0) + (no ?? 0);
  const fixed = WAF_PRICE.acl_month + rules.length * WAF_PRICE.rule_month;
  return {
    native_type: "wafv2_web_acl", id: arn, arn, account_id: str(a.account_id) ?? "", region: str(a.region) ?? "", name: str(a.name), state: "available", created: null, tags: tagsOf(a.tags),
    monthly_usd: round2(fixed + ((requests ?? 0) / 1e6) * WAF_PRICE.per_million_requests),
    props: {
      kind: "web_acl", stateful: false, default_action: def.Block ? "block" : "allow", rules: rules.length, rule_list: rules.map(wafRuleLine), managed_groups: rules.filter((r) => r?.Statement?.ManagedRuleGroupStatement).length,
      rate_limits: rules.filter((r) => r?.Statement?.RateBasedStatement).length, attached: attached.length, native_scope: str(a.scope), edge: String(a.scope).toUpperCase() === "CLOUDFRONT", capacity: num(a.capacity),
      logging: Boolean(json(a.logging_configuration)), firewall_manager: Boolean(a.managed_by_firewall_manager), requests_30d: requests, blocked_30d: no, description: str(a.description),
    },
    links: attached.map((other) => ({ rel: "GUARDED_BY" as const, other, dir: "in" as const })),
  };
}

export const wafCollector: ServiceCollector = {
  name: "WAF web ACLs",
  async collect(ctx: CollectContext): Promise<CollectResult> {
    const acls = await ctx.select("aws_wafv2_web_acl", ["name", "arn", "id", "scope", "description", "capacity", "default_action", "rules", "associated_resources", "logging_configuration", "managed_by_firewall_manager", "tags", "region", "account_id"], { required: ["arn"], optional: { ListResourcesForWebACL: ["associated_resources"], GetLoggingConfiguration: ["logging_configuration"] } });
    if (!acls) return { rows: [], complete: [] };
    // CloudFront-scope ACLs report in us-east-1 without the Region dimension
    const withRegion = acls.map((a) => ({ ...a, region: String(a.scope).toUpperCase() === "CLOUDFRONT" ? "us-east-1" : a.region }));
    const dims = (a: any) => [{ Name: "WebACL", Value: String(a.name) }, { Name: "Rule", Value: "ALL" }, ...(String(a.scope).toUpperCase() === "CLOUDFRONT" ? [] : [{ Name: "Region", Value: String(a.region) }])];
    const m = await metricsByGroup(ctx, "waf", withRegion, (a) => [
      { key: `${a.arn}|allowed`, namespace: "AWS/WAFV2", metric: "AllowedRequests", dims: dims(a) },
      { key: `${a.arn}|blocked`, namespace: "AWS/WAFV2", metric: "BlockedRequests", dims: dims(a) },
    ]);
    return { rows: acls.map((a) => wafRow(a, m.get(`${a.arn}|allowed`), m.get(`${a.arn}|blocked`))), complete: ["wafv2_web_acl"] };
  },
};

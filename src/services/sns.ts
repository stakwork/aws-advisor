/**
 * SNS topics as AdvisorMessaging {kind: topic}: subscribers by protocol, whether messages are encrypted at rest and
 * with which key (ENCRYPTS from the key), a dead-letter queue on any subscription, and 30 days of publishes from
 * CloudWatch. DELIVERS_TO edges go to the functions, queues and streams it delivers to; e-mail, SMS and HTTP
 * endpoints are counted, never stored (they are people's addresses). Priced at list on publishes only.
 */
import { metricsByGroup, num, round2, str, tagsOf, countList, type CollectContext, type CollectResult, type ServiceCollector, type ServiceLink, type ServiceRow } from "../service_inventory.js";

/** 0.50 USD per million publishes (us-east-1, standard topics; deliveries are priced by protocol and left out). */
export const SNS_PUBLISH_USD_PER_MILLION = 0.5;
const ARN_PROTOCOLS = new Set(["lambda", "sqs", "firehose", "application"]);

export function snsRow(t: any, subs: any[], metric: { sum: number; days: number } | undefined): ServiceRow {
  const arn = String(t.topic_arn);
  const name = arn.split(":").pop() || arn;
  const kms = str(t.kms_master_key_id);
  const links: ServiceLink[] = subs.filter((s) => ARN_PROTOCOLS.has(String(s.protocol)) && String(s.endpoint || "").startsWith("arn:")).map((s) => ({ rel: "DELIVERS_TO", other: String(s.endpoint), dir: "out", props: { protocol: String(s.protocol), raw: Boolean(s.raw_message_delivery), filtered: Boolean(s.filter_policy) } }));
  if (kms) links.push({ rel: "ENCRYPTS", other: kms, dir: "in", resolve: "kms_key" });
  const messages = metric && metric.days > 0 ? Math.round(metric.sum * (30 / metric.days)) : null;
  return {
    native_type: "sns_topic", id: arn, arn, account_id: str(t.account_id) ?? "", region: str(t.region) ?? "", name, state: "available", created: null, tags: tagsOf(t.tags),
    monthly_usd: messages == null ? null : round2((messages / 1e6) * SNS_PUBLISH_USD_PER_MILLION),
    props: {
      kind: "topic", fifo: name.endsWith(".fifo"), display_name: str(t.display_name), subscriptions: num(t.subscriptions_confirmed) ?? subs.filter((s) => !s.pending_confirmation).length, pending: num(t.subscriptions_pending) ?? 0,
      protocols: countList(subs.map((s) => str(s.protocol))), encrypted: Boolean(kms), kms_key: kms, dlq: subs.some((s) => Boolean(s.redrive_policy)), messages_30d: messages,
    },
    links,
  };
}

export const snsCollector: ServiceCollector = {
  name: "SNS topics",
  async collect(ctx: CollectContext): Promise<CollectResult> {
    const topics = await ctx.select("aws_sns_topic", ["topic_arn", "display_name", "subscriptions_confirmed", "subscriptions_pending", "kms_master_key_id", "tags", "region", "account_id"], { required: ["topic_arn"] });
    if (!topics) return { rows: [], complete: [] };
    const subs = (await ctx.select("aws_sns_topic_subscription", ["subscription_arn", "topic_arn", "protocol", "endpoint", "pending_confirmation", "raw_message_delivery", "redrive_policy", "filter_policy", "region", "account_id"], { required: ["topic_arn", "protocol"] })) ?? [];
    const byTopic = new Map<string, any[]>(); for (const s of subs) { const k = String(s.topic_arn); if (!byTopic.has(k)) byTopic.set(k, []); byTopic.get(k)!.push(s); }
    const metrics = await metricsByGroup(ctx, "sns", topics, (t) => [{ key: String(t.topic_arn), namespace: "AWS/SNS", metric: "NumberOfMessagesPublished", dims: [{ Name: "TopicName", Value: String(t.topic_arn).split(":").pop() || "" }] }]);
    return { rows: topics.map((t) => snsRow(t, byTopic.get(String(t.topic_arn)) ?? [], metrics.get(String(t.topic_arn)))), complete: ["sns_topic"] };
  },
};

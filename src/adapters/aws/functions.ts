/**
 * Pure AWS-shaped parsing helpers for function (Lambda) facts: what invokes a function (its resource policy,
 * `policy_std`, and its event source mappings), mapped onto the generic trigger words `kind`/`via` the rest of the
 * advisor speaks (docs/cloud-ontology.md). Nothing here calls Steampipe; src/lambda_inventory.ts does the collecting
 * and calls these to shape the rows it stores. AWS words stay in `native_kind`; everything else is generic.
 */

const safeJson = (v: unknown): any => {
  if (v == null) return null;
  if (typeof v === "string") { try { return JSON.parse(v); } catch { return null; } }
  return v;
};

export type TriggerKind = "queue" | "http" | "event";
export type TriggerVia = "polled" | "invoke_permission" | "load_balancer";

export interface PushTrigger {
  kind: TriggerKind;
  via: TriggerVia;
  native_kind: string;
  source: string | null;
  target_version?: string | null;
  invoker?: string | null;
  source_account?: string | null;
  public?: boolean;
  requires_auth?: boolean;
}

export interface PolledTrigger {
  kind: "queue";
  via: "polled";
  native_kind: string;
  source: string | null;
  target_version: string | null;
  state: string | null;
  batch_size: number | null;
}

/** Native service principal (its first DNS label, e.g. "apigateway" from "apigateway.amazonaws.com") -> generic kind/via. The last row is the fallback for any principal not listed, so an unlisted service (iot, cognito-idp, logs, config, secretsmanager...) still comes through instead of being dropped. */
const SERVICE_KIND_MAP: { match: RegExp; kind: TriggerKind; via: TriggerVia }[] = [
  { match: /^apigateway$/, kind: "http", via: "invoke_permission" },
  { match: /^elasticloadbalancing$/, kind: "http", via: "load_balancer" },
  { match: /^(s3|sns|events)$/, kind: "event", via: "invoke_permission" },
];
const FALLBACK_KIND = { kind: "event" as const, via: "invoke_permission" as const };

/** The generic kind/via for a native AWS service principal; any principal not named above falls back to event/invoke_permission. Pure. */
export function mapServicePrincipal(service: string): { kind: TriggerKind; via: TriggerVia } {
  const label = String(service).split(".")[0].toLowerCase();
  const found = SERVICE_KIND_MAP.find((m) => m.match.test(label));
  return found ? { kind: found.kind, via: found.via } : FALLBACK_KIND;
}

/** Every condition key (any operator: ArnLike, StringEquals, StringLike...) lower-cased, values flattened to an array of strings. Pure. */
function flattenConditions(condition: unknown): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  if (!condition || typeof condition !== "object") return out;
  for (const kv of Object.values(condition as Record<string, unknown>)) {
    if (!kv || typeof kv !== "object") continue;
    for (const [k, v] of Object.entries(kv as Record<string, unknown>)) {
      const key = k.toLowerCase();
      const vals = Array.isArray(v) ? v.map(String) : [String(v)];
      out[key] = [...(out[key] ?? []), ...vals];
    }
  }
  return out;
}

/**
 * Every statement of a Lambda resource policy (Steampipe's `policy_std`, lower-cased condition keys accepted, array
 * values accepted) as a push trigger. A statement is never dropped: an unlisted service principal falls to the
 * generic mapping's last row. `Principal: "*"` or a statement with no SourceArn gets `public: true`. A cross-account
 * principal carries `source_account`. `lambda:InvokeFunctionUrl` becomes a function URL trigger whose `requires_auth`
 * is false only when `lambda:functionurlauthtype` is `NONE`. Pure; the raw document never leaves this function.
 */
export function parsePolicyStd(policyStd: unknown): PushTrigger[] {
  const doc = safeJson(policyStd);
  const raw = doc?.Statement;
  const statements: any[] = Array.isArray(raw) ? raw : raw ? [raw] : [];
  const out: PushTrigger[] = [];
  for (const st of statements) {
    if (!st || String(st.Effect).toLowerCase() !== "allow") continue;
    const actions = Array.isArray(st.Action) ? st.Action : st.Action ? [st.Action] : [];
    const cond = flattenConditions(st.Condition);
    const sourceArn = cond["aws:sourcearn"]?.[0] ?? null;
    const sourceAccount = cond["aws:sourceaccount"]?.[0] ?? null;
    const principal = st.Principal;
    const isWildcard = principal === "*" || (typeof principal === "object" && principal?.AWS === "*");
    const service = typeof principal === "object" && principal ? (Array.isArray(principal.Service) ? principal.Service[0] : principal.Service) : null;

    if (actions.some((a: unknown) => /InvokeFunctionUrl$/i.test(String(a)))) {
      const authType = cond["lambda:functionurlauthtype"]?.[0];
      out.push({ kind: "http", via: "invoke_permission", native_kind: "function_url", source: sourceArn, requires_auth: String(authType ?? "").toUpperCase() !== "NONE" });
      continue;
    }

    if (service) {
      const { kind, via } = mapServicePrincipal(String(service));
      out.push({
        kind, via, native_kind: String(service).split(".")[0].toLowerCase(), source: sourceArn,
        ...(sourceAccount ? { source_account: String(sourceAccount) } : {}),
        ...(sourceArn ? {} : { public: true }),
      });
      continue;
    }

    const awsPrincipal = typeof principal === "object" && principal ? principal.AWS : null;
    const crossAccount = typeof awsPrincipal === "string" && awsPrincipal !== "*" ? awsPrincipal : null;
    out.push({
      kind: "event", via: "invoke_permission", native_kind: isWildcard ? "public" : "cross_account", source: sourceArn,
      ...(crossAccount ? { source_account: crossAccount } : {}),
      ...(isWildcard || !sourceArn ? { public: true } : {}),
    });
  }
  return out;
}

/** A function ARN with its qualifier (alias or version) split off, as the mapping and trigger rows carry `target_version` separately. Pure. */
export function stripQualifier(arn: string): { arn: string; target_version: string | null } {
  const m = /^(arn:aws[a-z0-9-]*:lambda:[^:]*:[^:]*:function:[^:]+)(?::(.+))?$/.exec(String(arn || ""));
  if (!m) return { arn: String(arn || ""), target_version: null };
  return { arn: m[1], target_version: m[2] ?? null };
}

/** The native kind of a polled event source, from its ARN; null (self-managed, e.g. Kafka with no ARN) is reported as "kafka". Pure. */
export function polledNativeKind(eventSourceArn: string | null | undefined): string {
  const arn = String(eventSourceArn || "");
  if (!arn) return "kafka";
  if (/:sqs:/.test(arn)) return "sqs";
  if (/:kinesis:/.test(arn)) return "kinesis";
  if (/:dynamodb:/.test(arn)) return "dynamodb_stream";
  if (/:kafka:/.test(arn)) return "kafka";
  if (/:mq:/.test(arn)) return "mq";
  return "other";
}

/** One `aws_lambda_event_source_mapping` row as a generic polled trigger. The qualifier on a qualified `function_arn` (`...:function:name:live`) becomes `target_version`; a Kafka mapping with no ARN reports its bootstrap servers (or null) as `source`. Pure. */
export function parseEventSourceMapping(row: { function_arn?: string | null; event_source_arn?: string | null; state?: string | null; batch_size?: unknown; self_managed_event_source?: unknown }): PolledTrigger {
  const { target_version } = stripQualifier(String(row.function_arn || ""));
  const esArn = row.event_source_arn || null;
  let source: string | null = esArn;
  if (!esArn) {
    const sms = safeJson(row.self_managed_event_source);
    const servers = sms?.Endpoints?.KafkaBootstrapServers;
    source = Array.isArray(servers) ? servers.join(",") : null;
  }
  return { kind: "queue", via: "polled", native_kind: polledNativeKind(esArn), source, target_version, state: row.state ?? null, batch_size: row.batch_size != null ? Number(row.batch_size) : null };
}

/**
 * A trigger's `source` (an ARN, a queue URL, or null) as the inventory id it probably matches, and what to call it
 * when it does not: a DynamoDB stream ARN's table (`.../table/name/stream/...` -> `.../table/name`), an S3 bucket
 * ARN's bucket name, else the source string itself with a generic `guessed_type` from its native kind. Pure.
 */
export function normalizeTriggerTarget(source: string | null, nativeKind: string): { id: string | null; guessed: string | null } {
  if (!source) return { id: null, guessed: null };
  if (nativeKind === "dynamodb_stream") { const m = /^(arn:aws[a-z0-9-]*:dynamodb:[^:]*:[^:]*:table\/[^/]+)/.exec(source); return { id: m ? m[1] : source, guessed: "database" }; }
  if (nativeKind === "s3" || /^arn:aws[a-z0-9-]*:s3:::/.test(source)) { const m = /^arn:aws[a-z0-9-]*:s3:::([^/]+)/.exec(source); return { id: m ? m[1] : source, guessed: "bucket" }; }
  if (nativeKind === "sqs") return { id: source, guessed: "queue" };
  if (nativeKind === "kinesis" || nativeKind === "mq" || nativeKind === "kafka") return { id: source, guessed: "stream" };
  if (nativeKind === "events") return { id: source, guessed: "event_rule" };
  if (nativeKind === "apigateway" || nativeKind === "function_url") return { id: source, guessed: "api" };
  return { id: source, guessed: null };
}

/** `logging_config.LogGroup`, else the AWS default `/aws/lambda/<name>`. Pure. */
export function logGroupName(loggingConfig: unknown, functionName: string): string {
  const lc = safeJson(loggingConfig);
  return (lc && typeof lc === "object" && lc.LogGroup) || `/aws/lambda/${functionName}`;
}

/**
 * One function name seen in more than one region of the same account: the table `inventory_lambda` keys on
 * (account_id, name) only (no region), so only the last-written row survives. Detects the collision so the refresh
 * can record it instead of silently keeping one region. Pure; keyed by "account_id|name".
 */
export function detectRegionCollisions(rows: { account_id: string | null | undefined; name: string; region: string }[]): Map<string, string[]> {
  const byKey = new Map<string, Set<string>>();
  for (const r of rows) {
    const key = `${r.account_id ?? ""}|${r.name}`;
    if (!byKey.has(key)) byKey.set(key, new Set());
    byKey.get(key)!.add(r.region);
  }
  const out = new Map<string, string[]>();
  for (const [key, regions] of byKey) if (regions.size > 1) out.set(key, [...regions].sort());
  return out;
}

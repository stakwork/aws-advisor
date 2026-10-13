import assert from "node:assert/strict";
import { test } from "node:test";
import { normalizeTriggerTarget } from "../adapters/aws/functions.js";
import { repoTagsProp, lambdaTriggerKinds } from "../adapters/aws/resources.js";

// Pure-function coverage for src/graph_functions.ts that does not need Neo4j or sqlite: the shared normalisation
// (adapters/aws/functions.ts), the function node's generic props (adapters/aws/resources.ts), and the two pure
// exports of graph_functions.ts itself (triggerRow, resolveRepoCasing), imported lazily below so a crash in this
// environment's better-sqlite3/Neo4j-driver teardown (reproduced on main too, unrelated to this feature) cannot
// take down tests that do not need it.

test("normalizeTriggerTarget: a DynamoDB stream becomes its table, an S3 ARN its bucket, else the source with a guessed type", () => {
  assert.deepEqual(normalizeTriggerTarget("arn:aws:dynamodb:us-east-1:1:table/orders/stream/2020-01-01T00:00:00.000", "dynamodb_stream"), { id: "arn:aws:dynamodb:us-east-1:1:table/orders", guessed: "database" });
  assert.deepEqual(normalizeTriggerTarget("arn:aws:s3:::my-bucket", "s3"), { id: "my-bucket", guessed: "bucket" });
  assert.deepEqual(normalizeTriggerTarget("arn:aws:sqs:us-east-1:1:q", "sqs"), { id: "arn:aws:sqs:us-east-1:1:q", guessed: "queue" });
  assert.deepEqual(normalizeTriggerTarget("arn:aws:kinesis:us-east-1:1:stream/s", "kinesis"), { id: "arn:aws:kinesis:us-east-1:1:stream/s", guessed: "stream" });
  assert.deepEqual(normalizeTriggerTarget(null, "sqs"), { id: null, guessed: null });
});

test("repoTagsProp: only the configured keys, capped and stripped; null when none match", () => {
  assert.equal(repoTagsProp(JSON.stringify({ repository: "owner/repo", other: "x" }), ["repository", "repo"]), '{"repository":"owner/repo"}');
  const long = JSON.parse(repoTagsProp(JSON.stringify({ repository: "x".repeat(400) }), ["repository"])!);
  assert.equal(long.repository.length, 256);
  const stripped = JSON.parse(repoTagsProp(JSON.stringify({ repository: "a\x00b" }), ["repository"])!);
  assert.equal(stripped.repository, "ab");
  assert.equal(repoTagsProp(JSON.stringify({}), ["repository"]), null);
  assert.equal(repoTagsProp(null, ["repository"]), null);
});

test("lambdaTriggerKinds: distinct generic kinds from the stored polled + push triggers", () => {
  assert.deepEqual(lambdaTriggerKinds({ polled_triggers: JSON.stringify([{ kind: "queue" }]), push_triggers: JSON.stringify([{ kind: "http" }, { kind: "queue" }]) }), ["queue", "http"]);
  assert.deepEqual(lambdaTriggerKinds({ polled_triggers: null, push_triggers: null }), []);
});

test("graph_functions: triggerRow skips SNS, load balancer and the function URL trigger (drawn by other edges); resolveRepoCasing prefers an existing node's casing", async () => {
  const { triggerRow, resolveRepoCasing } = await import("../graph_functions.js");
  const none = { stale: false, stale_since: null };
  assert.equal(triggerRow({ kind: "event", via: "invoke_permission", native_kind: "sns", source: "t" } as any, none), null);
  assert.equal(triggerRow({ kind: "http", via: "load_balancer", native_kind: "elasticloadbalancing", source: "x" } as any, none), null);
  assert.equal(triggerRow({ kind: "http", via: "invoke_permission", native_kind: "function_url", source: null, requires_auth: false } as any, none), null);
  const q = triggerRow({ kind: "queue", via: "polled", native_kind: "sqs", source: "arn:aws:sqs:us-east-1:1:q", state: "Enabled", batch_size: 5, target_version: null } as any, none);
  assert.deepEqual(q, { target_id: "arn:aws:sqs:us-east-1:1:q", guessed: "queue", kind: "queue", via: "polled", native_kind: "sqs", state: "Enabled", batch_size: 5, invoker: null, target_version: null, public: false, source_account: null, stale: false, stale_since: null });
  const stale = triggerRow({ kind: "event", via: "invoke_permission", native_kind: "iot", source: "arn:aws:iot:us-east-1:1:topicrule/x" } as any, { stale: true, stale_since: "2026-01-01" });
  assert.deepEqual(stale, { target_id: "arn:aws:iot:us-east-1:1:topicrule/x", guessed: null, kind: "event", via: "invoke_permission", native_kind: "iot", state: null, batch_size: null, invoker: null, target_version: null, public: false, source_account: null, stale: true, stale_since: "2026-01-01" });

  assert.deepEqual(resolveRepoCasing(["github:owner/repo"], ["github:Owner/Repo"]), new Map([["github:owner/repo", "github:Owner/Repo"]]));
  assert.deepEqual(resolveRepoCasing(["github:owner/repo"], []), new Map([["github:owner/repo", "github:owner/repo"]]));
});

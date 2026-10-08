import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

// The probe document row (src/actions/probe_document.ts): create or update with a person's credentials, revert by delete or by the previous default version.
process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "advisor-probedoc-test-"));
process.env.NEO4J_URI = "";
const { SSMClient } = await import("@aws-sdk/client-ssm");
const pd = await import("../actions/probe_document.js");
const { ACTUATOR_NEEDS, PERSON_ONLY_ACTIONS } = await import("../permissions.js");
const { computeCapabilities } = await import("../executor.js");
const { probeDocument } = await import("../probes.js");

/** Records every SSM call and answers from `reply`; restores the client afterwards. */
async function withSsm(reply: (name: string, input: any) => any, fn: (calls: { name: string; input: any }[]) => Promise<void>) {
  const calls: { name: string; input: any }[] = [];
  const orig = SSMClient.prototype.send;
  (SSMClient.prototype as any).send = async function (cmd: any) { const name = cmd.constructor.name; calls.push({ name, input: cmd.input }); return reply(name, cmd.input); };
  try { await fn(calls); } finally { (SSMClient.prototype as any).send = orig; }
}
const provider = async () => ({ accessKeyId: "ASIAEXAMPLEEXAMPLE00", secretAccessKey: "x", sessionToken: "y" });
const creds = { read: provider, act: () => provider, region: "us-east-1", accounts: [], forAccount: () => ({ read: provider, act: () => provider, region: "us-east-1" }) } as any;
const row = (op: "create" | "update", previous: string | null = "3") => ({
  kind: "probe_document", resource: "arn:aws:ssm:us-east-1:111111111111:document/AwsAdvisorProbe-host", region: "us-east-1", account_id: null, dedupe: "x", title: "t", reason: "r", rollback: "", est_usd_month: null,
  before: { exists: op === "update", default_version: previous }, after: { exists: true, content: probeDocument("host") },
  facts: { op, probe_kind: "host", name: "AwsAdvisorProbe-host", account_id: "111111111111", region: "us-east-1", hash: "abcd1234", previous_version: previous },
}) as any;

test("opFor: missing is a create, stale an update, anything else nothing", () => {
  assert.equal(pd.opFor("missing"), "create"); assert.equal(pd.opFor("stale"), "update");
  assert.equal(pd.opFor("current"), null); assert.equal(pd.opFor("error"), null);
});

test("the kind is a person's only: the actuator never writes a document the fleet runs", () => {
  const needs = ACTUATOR_NEEDS.probe_document;
  assert.ok(needs);
  for (const a of [...needs.apply, ...needs.revert]) assert.ok(PERSON_ONLY_ACTIONS.has(a), a);
  assert.equal(computeCapabilities(new Set<string>(), {}).probe_document.apply, false);
});

test("apply: a create writes the document with the app tag; an update writes a version and makes it the default", async () => {
  await withSsm((n) => (n === "CreateDocumentCommand" ? { DocumentDescription: { DocumentVersion: "1" } } : n === "UpdateDocumentCommand" ? { DocumentDescription: { DocumentVersion: "4" } } : {}), async (calls) => {
    assert.match(await pd.probeDocumentAction.apply(row("create"), creds), /CreateDocument AwsAdvisorProbe-host in us-east-1: version 1/);
    assert.equal(calls[0].name, "CreateDocumentCommand");
    assert.deepEqual(calls[0].input.Tags, [{ Key: "app", Value: "aws-advisor" }]);
    assert.equal(JSON.parse(calls[0].input.Content).description, probeDocument("host").description);
    calls.length = 0;
    assert.match(await pd.probeDocumentAction.apply(row("update"), creds), /version 4, now the default \(was 3\)/);
    assert.deepEqual(calls.map((c) => c.name), ["UpdateDocumentCommand", "UpdateDocumentDefaultVersionCommand"]);
    assert.equal(calls[1].input.DocumentVersion, "4");
  });
});

test("apply: content already the latest version still moves the default to it", async () => {
  await withSsm((n) => {
    if (n === "UpdateDocumentCommand") { const e: any = new Error("same content"); e.name = "DuplicateDocumentContent"; throw e; }
    if (n === "DescribeDocumentCommand") return { Document: { DocumentVersion: "5" } };
    return {};
  }, async (calls) => {
    assert.match(await pd.probeDocumentAction.apply(row("update"), creds), /version 5, now the default/);
    assert.equal(calls.at(-1)!.input.DocumentVersion, "5");
  });
});

test("revert: a created document is deleted; an updated one gets its previous default back, or is refused when that is unknown", async () => {
  await withSsm(() => ({}), async (calls) => {
    assert.match(await pd.probeDocumentAction.revert(row("create"), creds), /DeleteDocument AwsAdvisorProbe-host/);
    assert.match(await pd.probeDocumentAction.revert(row("update", "3"), creds), /back to version 3/);
    assert.deepEqual(calls.map((c) => c.name), ["DeleteDocumentCommand", "UpdateDocumentDefaultVersionCommand"]);
    await assert.rejects(pd.probeDocumentAction.revert(row("update", null), creds), /not known/);
  });
});

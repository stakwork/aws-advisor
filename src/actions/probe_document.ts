/**
 * The probe SSM documents (one per kind, src/probes.ts), created or updated from Settings › Probes with a person's
 * credentials ("Run as me"). The advisor's identities may send its documents but never write them: a document is
 * what the fleet runs, so changing it is a person's call, like the read policy (src/actions/read_policy.ts).
 *
 * A row is proposed per account and kind whose document is missing or stale (src/probes_status.ts reads the script
 * hash back from the description): missing is a CreateDocument, stale is an UpdateDocument of a new version that is
 * then made the default. The content is fixed when the row is proposed, so what was previewed is what is written.
 * Revert deletes a document the row created, and puts the default version back on one it updated (SSM keeps every
 * version, so nothing is lost).
 */
import { CreateDocumentCommand, DeleteDocumentCommand, DescribeDocumentCommand, SSMClient, UpdateDocumentCommand, UpdateDocumentDefaultVersionCommand } from "@aws-sdk/client-ssm";
import type { AwsCredentialIdentityProvider } from "@aws-sdk/types";
import { config } from "../config.js";
import type { ActionModule, ActionRow, Creds, Proposal } from "../executor.js";
import { recordProposal } from "../executor.js";
import { accountCredentials, listMembers } from "../accounts.js";
import { credentialsMeta } from "../steampipe.js";
import { PROBE_DEFS, PROBE_KINDS, type ProbeKind, probeDocument, probeScriptHash } from "../probes.js";
import { probeDocumentStatus } from "../probes_status.js";

export const KIND = "probe_document" as const;

export interface ProposeResult { account_id: string; name: string; is_parent: boolean; region: string; kind: ProbeKind; document: string; status: "proposed" | "current" | "error"; detail: string; row: ActionRow | null }

/** What a row does to a document in a given state, or null when there is nothing to do. Pure. */
export const opFor = (status: string): "create" | "update" | null => (status === "missing" ? "create" : status === "stale" ? "update" : null);

/**
 * One row per account and kind whose document is missing or stale: the parent and every enabled member, each in its
 * region (the one the advisor reads it in). `kinds` narrows to some kinds. Nothing is written here; the rows wait for
 * "Run as me".
 */
export async function proposeProbeDocuments(opts: { kinds?: ProbeKind[]; by?: string } = {}): Promise<{ results: ProposeResult[] }> {
  const by = opts.by || "a person";
  const kinds = opts.kinds?.length ? opts.kinds : [...PROBE_KINDS];
  const parentId = credentialsMeta()?.accountId || "";
  const targets = [{ account_id: parentId, name: "parent", is_parent: true }, ...listMembers().filter((m) => m.enabled).map((m) => ({ account_id: m.account_id, name: m.name, is_parent: false }))];
  const results: ProposeResult[] = [];
  for (const t of targets) {
    let creds: ReturnType<typeof accountCredentials>;
    try { creds = accountCredentials(t.is_parent ? null : t.account_id); }
    catch (e: any) { for (const kind of kinds) results.push({ ...t, region: "", kind, document: "", status: "error", detail: String(e?.message || e).slice(0, 200), row: null }); continue; }
    const statuses = await probeDocumentStatus(creds.region, creds);
    for (const st of statuses.filter((s) => kinds.includes(s.kind))) {
      const base = { ...t, region: creds.region, kind: st.kind, document: st.name, row: null };
      if (st.status === "error") { results.push({ ...base, status: "error", detail: st.error || "DescribeDocument failed" }); continue; }
      const op = opFor(st.status);
      if (!op) { results.push({ ...base, status: "current", detail: `${st.name} already embeds script ${st.expected_hash}` }); continue; }
      const content = probeDocument(st.kind);
      const where = t.is_parent ? "the parent" : `member ${t.name}`;
      const p: Proposal = {
        kind: KIND, resource: `arn:aws:ssm:${creds.region}:${t.account_id}:document/${st.name}`, resource_name: `${st.name} (${t.is_parent ? "parent" : t.name})`,
        region: creds.region, account_id: t.is_parent ? null : t.account_id,
        dedupe: `${KIND}:${t.account_id}:${creds.region}:${st.name}`,
        title: `${st.name}: ${op === "create" ? "create" : "update"} the ${st.kind} probe document (${PROBE_DEFS[st.kind].version}, script ${st.expected_hash})`,
        reason: `${by} asked from Settings › Probes to ${op === "create" ? "create" : "update"} the ${st.kind} probe document in ${where} (${t.account_id}, ${creds.region}): ${op === "create" ? "it does not exist yet, so the probe cannot run there" : `the deployed one (${st.deployed_description ?? "no description"}, default version ${st.deployed_version ?? "?"}) is not the script the advisor sends now (${st.expected_hash})`}. The advisor's own identities may send this document but never write it, so this is done with your own credentials ("Run as me"), as ${op === "create" ? "one CreateDocument" : "one UpdateDocument and one UpdateDocumentDefaultVersion"}.`,
        before: { exists: op === "update", description: st.deployed_description, default_version: st.deployed_version },
        after: { exists: true, description: content.description, content },
        facts: { op, probe_kind: st.kind, name: st.name, account_id: t.account_id, region: creds.region, hash: st.expected_hash, previous_version: st.deployed_version, by },
        rollback: op === "create" ? `DeleteDocument ${st.name}` : `UpdateDocumentDefaultVersion ${st.name} back to version ${st.deployed_version ?? "?"} (the new version stays in the history)`,
        est_usd_month: null,
      };
      const row = recordProposal(p, config.actMode, "manual").row;
      results.push({ ...base, status: "proposed", detail: `#${row.id} waits for your credentials`, row });
    }
  }
  return { results };
}

const ssm = (provider: AwsCredentialIdentityProvider, region: string) => new SSMClient({ region, credentials: provider });

/** Writes the document: created when the row found none, else a new version made the default. */
async function write(provider: AwsCredentialIdentityProvider, p: Proposal): Promise<string> {
  const name = String(p.facts.name), region = String(p.facts.region || p.region);
  const Content = JSON.stringify((p.after as any).content);
  const c = ssm(provider, region);
  try {
    if (p.facts.op === "create") {
      const r = await c.send(new CreateDocumentCommand({ Name: name, DocumentType: "Command", DocumentFormat: "JSON", Content, Tags: [{ Key: "app", Value: "aws-advisor" }] }));
      return `CreateDocument ${name} in ${region}: version ${r.DocumentDescription?.DocumentVersion ?? "1"}`;
    }
    let version: string | undefined;
    try { version = (await c.send(new UpdateDocumentCommand({ Name: name, DocumentVersion: "$LATEST", DocumentFormat: "JSON", Content }))).DocumentDescription?.DocumentVersion; }
    catch (e: any) {
      // the content is already the latest version (written by hand, or a first try that stopped before the default moved): make that one the default
      if (!/DuplicateDocumentContent/i.test(`${e?.name} ${e?.message}`)) throw e;
      version = (await c.send(new DescribeDocumentCommand({ Name: name, DocumentVersion: "$LATEST" }))).Document?.DocumentVersion;
    }
    if (!version) throw new Error(`UpdateDocument ${name} returned no version`);
    await c.send(new UpdateDocumentDefaultVersionCommand({ Name: name, DocumentVersion: version }));
    return `UpdateDocument ${name} in ${region}: version ${version}, now the default (was ${p.facts.previous_version ?? "?"})`;
  } finally { c.destroy(); }
}

export const probeDocumentAction: ActionModule = {
  kind: KIND,
  label: "A probe SSM document created or updated from Settings › Probes, with a person's own credentials",
  async plan() { return { proposals: [], notes: ["proposed from Settings › Probes, never planned"] }; },
  async apply(p, creds: Creds) { return write(creds.act(), p); },
  async verify(p, creds: Creds) {
    const region = String(p.facts.region || p.region);
    const acct = creds.forAccount(p.account_id ?? null);
    let st: Awaited<ReturnType<typeof probeDocumentStatus>>[number] | undefined;
    try { st = (await probeDocumentStatus(region, { provider: acct.read, region })).find((s) => s.name === p.facts.name); }
    catch (e: any) { return { ok: null, note: `the document could not be read back (${String(e?.message || e).slice(0, 120)})` }; }
    if (!st || st.status === "error") return { ok: null, note: `the document could not be read back${st?.error ? ` (${st.error.slice(0, 120)})` : ""}; the next permission check tells` };
    if (st.status === "current") return { ok: true, note: `read back: ${p.facts.name} default version ${st.deployed_version} embeds script ${p.facts.hash}` };
    // the script was edited again after this row was proposed: the row did its part, a new row brings the rest
    if (st.status === "stale" && st.deployed_description?.includes(String(p.facts.hash))) return { ok: true, note: `read back: ${p.facts.name} embeds script ${p.facts.hash}` };
    return { ok: false, note: `${p.facts.name} is ${st.status}${st.deployed_description ? ` (${st.deployed_description})` : ""}, not script ${p.facts.hash}${probeScriptHash(p.facts.probe_kind as ProbeKind) !== p.facts.hash ? `; the script changed since (now ${probeScriptHash(p.facts.probe_kind as ProbeKind)}), propose again` : ""}` };
  },
  async revert(p, creds: Creds) {
    const name = String(p.facts.name), region = String(p.facts.region || p.region);
    const c = ssm(creds.act(), region);
    try {
      if (p.facts.op === "create") { await c.send(new DeleteDocumentCommand({ Name: name })); return `DeleteDocument ${name} in ${region}`; }
      const prev = p.facts.previous_version ? String(p.facts.previous_version) : null;
      if (!prev) throw new Error(`the default version before this change is not known, so there is nothing to put back on ${name}`);
      await c.send(new UpdateDocumentDefaultVersionCommand({ Name: name, DocumentVersion: prev }));
      return `UpdateDocumentDefaultVersion ${name} back to version ${prev}`;
    } finally { c.destroy(); }
  },
};

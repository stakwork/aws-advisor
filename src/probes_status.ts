import { DescribeDocumentCommand, SSMClient } from "@aws-sdk/client-ssm";
import { PROBE_KINDS, type ProbeKind, probeDocumentDescription, probeDocumentName, probeScriptHash } from "./probes.js";
import { sdkCredentials } from "./steampipe.js";

/**
 * Whether each probe kind's SSM document exists in the account and embeds the script the advisor would send now. The
 * document description carries the kind, the version and the script hash (src/probes.ts probeDocumentDescription), so
 * one DescribeDocument per kind says current, stale (the script changed since it was deployed) or missing. Read by
 * Settings > Probes and the permission check; never cached longer than a request.
 */

export interface ProbeDocumentStatus { kind: ProbeKind; name: string; status: "current" | "stale" | "missing" | "error"; deployed_description: string | null; deployed_version: string | null; expected_hash: string; owner: string | null; error: string | null }

export async function probeDocumentStatus(region?: string): Promise<ProbeDocumentStatus[]> {
  let creds: ReturnType<typeof sdkCredentials>;
  try { creds = sdkCredentials(); }
  catch (e: any) { return PROBE_KINDS.map((kind) => ({ kind, name: probeDocumentName(kind), status: "error" as const, deployed_description: null, deployed_version: null, expected_hash: probeScriptHash(kind), owner: null, error: `no SDK credentials: ${e?.message || e}` })); }
  const client = new SSMClient({ region: region || creds.region, credentials: creds.provider });
  try {
    return await Promise.all(PROBE_KINDS.map(async (kind): Promise<ProbeDocumentStatus> => {
      const name = probeDocumentName(kind);
      const expected = probeScriptHash(kind);
      try {
        const r = await client.send(new DescribeDocumentCommand({ Name: name }));
        const desc = r.Document?.Description ?? null;
        const current = Boolean(desc && desc.includes(expected)) || desc === probeDocumentDescription(kind);
        return { kind, name, status: current ? "current" : "stale", deployed_description: desc, deployed_version: r.Document?.DocumentVersion ?? null, expected_hash: expected, owner: r.Document?.Owner ?? null, error: null };
      } catch (e: any) {
        const code = String(e?.name || e?.Code || "");
        if (/InvalidDocument\b/i.test(code)) return { kind, name, status: "missing", deployed_description: null, deployed_version: null, expected_hash: expected, owner: null, error: null };
        return { kind, name, status: "error", deployed_description: null, deployed_version: null, expected_hash: expected, owner: null, error: `${code || "error"}: ${String(e?.message || e).slice(0, 200)}` };
      }
    }));
  } finally { client.destroy(); }
}

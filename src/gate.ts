/**
 * Credential gate. Nothing that samples, probes or collects may run on a connection whose
 * credentials do not work: a failed query is not "everything is gone", it is "we know nothing".
 * While the gate is closed exactly one `credentials` alert stays open; it is acknowledged
 * automatically the moment a check succeeds again.
 */
import { db } from "./db.js";
import { S, query } from "./steampipe.js";

export interface GateResult { ok: boolean; accountId?: string; error?: string; kind?: "credentials" | "steampipe" }

const AUTH_RE = /ExpiredToken|InvalidClientTokenId|SignatureDoesNotMatch|UnrecognizedClientException|AuthFailure|AccessDenied|not authorized|GetCallerIdentity|no EC2 IMDS role|failed to refresh cached credentials|NoCredentialProviders|403/i;

export async function credentialGate(context: string): Promise<GateResult> {
  let result: GateResult;
  try {
    const rows = await query<{ account_id: string }>(`select account_id from ${S}.aws_account`);
    result = rows[0]?.account_id ? { ok: true, accountId: rows[0].account_id } : { ok: false, error: "aws_account returned no rows", kind: "credentials" };
  } catch (e: any) {
    const msg = String(e?.message || e);
    result = { ok: false, error: msg.slice(0, 300), kind: AUTH_RE.test(msg) ? "credentials" : "steampipe" };
  }
  const open = db.prepare("select id, message from alerts where kind = 'credentials' and acknowledged = 0 limit 1").get() as { id: number; message: string } | undefined;
  if (result.ok) {
    if (open) {
      db.prepare("update alerts set acknowledged = 1, acknowledged_by = 'system', message = message || ? where id = ?")
        .run(` — credentials restored at ${new Date().toISOString()}`, open.id);
      console.log(`[gate] ${context}: credentials restored for "${S}" (account ${result.accountId})`);
    }
    return result;
  }
  const message = result.kind === "credentials"
    ? `AWS credentials for connection "${S}" are not working: ${short(result.error!)}. Sampling, probes and runs are paused until valid credentials are saved in Settings.`
    : `Steampipe is not answering for connection "${S}": ${short(result.error!)}. Sampling, probes and runs are paused.`;
  if (!open) {
    db.prepare("insert into alerts(kind, resource, message, details) values ('credentials', ?, ?, ?)")
      .run(S, message, JSON.stringify({ context, error: result.error, kind: result.kind, since: new Date().toISOString() }));
  }
  console.warn(`[gate] ${context} skipped: ${message}`);
  return result;
}

function short(err: string): string {
  const m = err.match(/(ExpiredToken|InvalidClientTokenId|SignatureDoesNotMatch|UnrecognizedClientException|AuthFailure|AccessDenied|NoCredentialProviders)[^,]*/);
  return m ? m[0] : err.slice(0, 120);
}

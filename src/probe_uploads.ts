import { createHash } from "node:crypto";
import { gunzipSync } from "node:zlib";
import { GetObjectCommand, ListObjectsV2Command, PutObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { config } from "./config.js";
import { db } from "./db.js";
import { accountCredentials } from "./accounts.js";
import type { ProbeKind } from "./probes.js";

/**
 * The whole result of a probe in S3 (the software and sbom kinds, src/probes.ts UPLOAD_KINDS): GetCommandInvocation
 * returns 24,000 characters of stdout, which a box with a few thousand packages outgrows, so when a bucket is
 * configured (Settings > Probe pass) the advisor signs a PutObject URL per run and passes it as the document's `upload`
 * parameter. The script posts the gzip-compressed JSON there with curl and prints a receipt (`uploaded <bytes> <sha256>`)
 * on its inline line; the advisor reads the object back, checks it against the receipt and ingests that instead of the
 * inline object (which is the trimmed fallback, or a stub). The boxes need no IAM change, only egress to S3: the URL
 * carries the advisor's signature. Objects are kept, so a probe can be re-ingested later (src/probe_upload_ingest.ts).
 *
 * Keys: <prefix>/<account id>/<instance id>/<kind>/<time>.json.gz, so the key alone says what an object is.
 */

db.exec(`create table if not exists probe_uploads (
  key text primary key, instance_id text not null, account_id text, kind text not null, bytes integer, sha256 text, collected_at text, uploaded_at text not null, ingested_at text
);
create index if not exists probe_uploads_instance on probe_uploads(instance_id, kind, uploaded_at)`);

export const probeUploadsConfigured = (): boolean => Boolean(config.probeUploadBucket);
const prefix = (): string => config.probeUploadPrefix.replace(/^\/+|\/+$/g, "") || "aws-advisor/probes";
// the parent account's identity signs and reads: the bucket is the advisor's, whichever account the box is in
const client = (): S3Client => { const base = accountCredentials(null); return new S3Client({ region: config.probeUploadRegion || base.region, credentials: base.provider }); };

/** The object key of one run. Pure. */
export const uploadKey = (accountId: string | null | undefined, instanceId: string, kind: ProbeKind, at: Date = new Date()): string =>
  `${prefix()}/${accountId || "unknown"}/${instanceId}/${kind}/${at.toISOString().replace(/[:.]/g, "-")}.json.gz`;

/** What a key says: the account, the box, the kind and when; null for an object that is not one of ours. Pure. */
export function parseUploadKey(key: string): { account_id: string; instance_id: string; kind: string; at: string } | null {
  const m = /(?:^|\/)([^/]+)\/(i-[0-9a-f]{8,17})\/([a-z]+)\/(\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{3}Z)\.json\.gz$/.exec(key);
  if (!m) return null;
  const t = m[4]!; const at = `${t.slice(0, 10)}T${t.slice(11, 13)}:${t.slice(14, 16)}:${t.slice(17, 19)}.${t.slice(20, 23)}Z`;
  return { account_id: m[1]!, instance_id: m[2]!, kind: m[3]!, at };
}

/** The receipt the script prints: `uploaded <bytes> <sha256>` (the hash is missing where the box has no sha256sum). Pure. */
export function parseReceipt(receipt: string | null | undefined): { bytes: number | null; sha256: string | null } {
  const m = /^uploaded\s+(\d+)(?:\s+([0-9a-f]{64}))?/.exec(String(receipt ?? ""));
  return m ? { bytes: Number(m[1]), sha256: m[2] ?? null } : { bytes: null, sha256: null };
}

/** A PutObject URL for one run, valid a little longer than the probe may take. */
export async function presignProbeUpload(opts: { accountId: string | null | undefined; instanceId: string; kind: ProbeKind; expiresInSeconds?: number }): Promise<{ key: string; url: string }> {
  const key = uploadKey(opts.accountId, opts.instanceId, opts.kind);
  const c = client();
  try {
    const url = await getSignedUrl(c, new PutObjectCommand({ Bucket: config.probeUploadBucket, Key: key }), { expiresIn: Math.min(Math.max(opts.expiresInSeconds ?? 3600, 600), 7 * 24 * 3600) });
    return { key, url };
  } finally { c.destroy(); }
}

/** The object back, checked against the receipt (size, sha256) and decompressed: the probe's JSON as text. */
export async function fetchProbeUpload(key: string, receipt?: string | null): Promise<string> {
  const c = client();
  try {
    const r = await c.send(new GetObjectCommand({ Bucket: config.probeUploadBucket, Key: key }));
    const bytes = Buffer.from(await r.Body!.transformToByteArray());
    const want = parseReceipt(receipt);
    if (want.bytes != null && want.bytes !== bytes.length) throw new Error(`the object is ${bytes.length} bytes, the receipt says ${want.bytes}`);
    if (want.sha256) { const got = createHash("sha256").update(bytes).digest("hex"); if (got !== want.sha256) throw new Error("the object's sha256 does not match the receipt"); }
    return gunzipSync(bytes).toString("utf8");
  } finally { c.destroy(); }
}

const upsert = db.prepare(`insert into probe_uploads(key, instance_id, account_id, kind, bytes, sha256, collected_at, uploaded_at, ingested_at) values (?, ?, ?, ?, ?, ?, ?, ?, ?)
  on conflict(key) do update set bytes = coalesce(excluded.bytes, bytes), sha256 = coalesce(excluded.sha256, sha256), collected_at = coalesce(excluded.collected_at, collected_at), ingested_at = coalesce(excluded.ingested_at, ingested_at)`);
/** One object noted: written by the probe flow when it ingests, and by the replay. */
export function recordProbeUpload(o: { key: string; instanceId: string; accountId: string | null | undefined; kind: string; receipt?: string | null; collectedAt?: string | null; ingested?: boolean; uploadedAt?: string }): void {
  const r = parseReceipt(o.receipt); const now = new Date().toISOString();
  upsert.run(o.key, o.instanceId, o.accountId ?? null, o.kind, r.bytes, r.sha256, o.collectedAt ?? null, o.uploadedAt ?? now, o.ingested === false ? null : now);
}
export const probeUploadIngested = (key: string): boolean => Boolean((db.prepare("select ingested_at from probe_uploads where key = ?").get(key) as { ingested_at: string | null } | undefined)?.ingested_at);

/** Every object under the prefix (paged), with what its key says. */
export async function listProbeUploads(): Promise<{ key: string; bytes: number; last_modified: string | null; account_id: string; instance_id: string; kind: string; at: string }[]> {
  const c = client(); const out: Awaited<ReturnType<typeof listProbeUploads>> = [];
  try {
    let token: string | undefined;
    do {
      const r = await c.send(new ListObjectsV2Command({ Bucket: config.probeUploadBucket, Prefix: `${prefix()}/`, ContinuationToken: token }));
      for (const o of r.Contents ?? []) { const p = o.Key ? parseUploadKey(o.Key) : null; if (p) out.push({ key: o.Key!, bytes: Number(o.Size ?? 0), last_modified: o.LastModified?.toISOString() ?? null, ...p }); }
      token = r.IsTruncated ? r.NextContinuationToken : undefined;
    } while (token);
  } finally { c.destroy(); }
  return out;
}

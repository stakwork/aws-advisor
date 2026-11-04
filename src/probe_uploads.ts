import { createHash } from "node:crypto";
import { gunzipSync, gzipSync } from "node:zlib";
import { GetObjectCommand, HeadBucketCommand, ListObjectsV2Command, PutObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { config } from "./config.js";
import { db } from "./db.js";
import { accountCredentials } from "./accounts.js";
import { PROBE_KINDS, type ProbeKind } from "./probes.js";

/**
 * The whole result of every probe in S3 (docs/probe-s3-strut.md): GetCommandInvocation returns 24,000 characters of stdout,
 * which a box with a few thousand packages outgrows, and the Strut probe ingest builds the package side of the graph from the
 * bucket rather than from this process. When a bucket is configured (Settings > Probe pass) the advisor signs a PutObject URL
 * per run and passes it as the document's `upload` parameter. The script posts the gzip-compressed JSON there with curl and
 * prints a receipt (`uploaded <bytes> <sha256>`) on its inline line; the advisor reads the object back, checks it against the
 * receipt and ingests that instead of the inline object (which is the trimmed fallback, or a stub). The boxes need no IAM
 * change, only egress to S3: the URL carries the advisor's signature. Objects are kept, so a probe can be re-ingested later
 * (src/probe_upload_ingest.ts) and a poller can walk the bucket by day.
 *
 * Keys: <prefix>/<kind>/<yyyy-mm-dd>/<hh>/<account id>/<instance id>/<time>.json.gz (the dated layout, 2026-11-04): an hourly
 * poller lists one kind for the hour it is responsible for and nothing else, whatever the fleet size, and a replay is a list of
 * hour prefixes; <prefix>/cluster-images/<yyyy-mm-dd>/<hh>/<account>/<cluster>/<time>.json.gz for the images a Kubernetes
 * cluster's nodes run (src/cluster_inventory.ts: not a probe, the cluster API says it). Objects written before this date sit at
 * <prefix>/<account id>/<instance id>/<kind>/<time>.json.gz and are still read.
 */

db.exec(`create table if not exists probe_uploads (
  key text primary key, instance_id text not null, account_id text, kind text not null, bytes integer, sha256 text, collected_at text, uploaded_at text not null, ingested_at text
);
create index if not exists probe_uploads_instance on probe_uploads(instance_id, kind, uploaded_at)`);

export const probeUploadsConfigured = (): boolean => Boolean(config.probeUploadBucket);
const prefix = (): string => config.probeUploadPrefix.replace(/^\/+|\/+$/g, "") || "aws-advisor/probes";
// the parent account's identity signs and reads: the bucket is the advisor's, whichever account the box is in
const client = (): S3Client => { const base = accountCredentials(null); return new S3Client({ region: config.probeUploadRegion || base.region, credentials: base.provider }); };

const stamp = (at: Date): string => at.toISOString().replace(/[:.]/g, "-");
/** The hour prefix of an instant: `<yyyy-mm-dd>/<hh>` in UTC. Pure. */
export const hourPrefix = (at: Date): string => `${at.toISOString().slice(0, 10)}/${at.toISOString().slice(11, 13)}`;
const TIME = String.raw`(\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{3}Z)`;
const DATED = new RegExp(String.raw`(?:^|/)([a-z]+)/(\d{4}-\d{2}-\d{2})/(\d{2})/([^/]+)/(i-[0-9a-f]{8,17})/${TIME}\.json\.gz$`);
const LEGACY = new RegExp(String.raw`(?:^|/)([^/]+)/(i-[0-9a-f]{8,17})/([a-z]+)/${TIME}\.json\.gz$`);
const isKind = (k: string): k is ProbeKind => (PROBE_KINDS as readonly string[]).includes(k);
const timeOf = (t: string): string => `${t.slice(0, 10)}T${t.slice(11, 13)}:${t.slice(14, 16)}:${t.slice(17, 19)}.${t.slice(20, 23)}Z`;

/** The object key of one run (the dated layout). Pure. */
export const uploadKey = (accountId: string | null | undefined, instanceId: string, kind: ProbeKind, at: Date = new Date()): string =>
  `${prefix()}/${kind}/${hourPrefix(at)}/${accountId || "unknown"}/${instanceId}/${stamp(at)}.json.gz`;

/** The key of a cluster's node-images object: the cluster name as a slug (what the key allows), the time of the refresh. Pure. */
export const clusterImagesKey = (accountId: string | null | undefined, clusterName: string, at: Date = new Date()): string =>
  `${prefix()}/cluster-images/${hourPrefix(at)}/${accountId || "unknown"}/${(String(clusterName).replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 100) || "cluster")}/${stamp(at)}.json.gz`;

export interface ParsedUploadKey { account_id: string; instance_id: string; kind: ProbeKind; at: string; /** which layout the key follows */ layout: "dated" | "legacy" }

/** What a key says: the account, the box, the kind and when; null for an object that is not a probe result (the `_check` markers, the cluster-images objects, a kind this build does not know). Pure. */
export function parseUploadKey(key: string): ParsedUploadKey | null {
  const d = DATED.exec(key);
  if (d && isKind(d[1]!)) return { kind: d[1], at: timeOf(d[6]!), account_id: d[4]!, instance_id: d[5]!, layout: "dated" };
  const l = LEGACY.exec(key);
  if (l && isKind(l[3]!) && l[1] !== "cluster-images") return { account_id: l[1]!, instance_id: l[2]!, kind: l[3], at: timeOf(l[4]!), layout: "legacy" };
  return null;
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

/** An object the advisor writes itself (the cluster-images one): the JSON gzip-compressed, as the probes post theirs, so one reader serves both. `s3` is a test's client. */
export async function putProbeObject(key: string, body: unknown, s3?: S3Client): Promise<{ bytes: number; sha256: string }> {
  const bytes = gzipSync(Buffer.from(JSON.stringify(body), "utf8"), { level: 9 });
  const c = s3 ?? client();
  try {
    await c.send(new PutObjectCommand({ Bucket: config.probeUploadBucket, Key: key, Body: bytes, ContentType: "application/json", ContentEncoding: "gzip" }));
    return { bytes: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex") };
  } finally { if (!s3) c.destroy(); }
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

export type ProbeUploadObject = ParsedUploadKey & { key: string; bytes: number; last_modified: string | null };

/**
 * Every probe object under the prefix (paged), with what its key says, in both layouts. One delimiter listing of the prefix
 * first, then only the wanted kinds' trees (dated) and the account trees (legacy): the `_check` markers, the cluster-images
 * objects and the kinds not asked for are never walked.
 */
export async function listProbeUploads(opts: { kinds?: readonly ProbeKind[]; /** a test's client */ s3?: S3Client } = {}): Promise<ProbeUploadObject[]> {
  const want = new Set<string>(opts.kinds?.length ? opts.kinds : PROBE_KINDS);
  const c = opts.s3 ?? client(); const out: ProbeUploadObject[] = []; const root = `${prefix()}/`;
  const page = async (input: { Prefix: string; Delimiter?: string }, each: (r: Awaited<ReturnType<S3Client["send"]>> & { Contents?: { Key?: string; Size?: number; LastModified?: Date }[]; CommonPrefixes?: { Prefix?: string }[] }) => void) => {
    let token: string | undefined;
    do {
      const r: any = await c.send(new ListObjectsV2Command({ Bucket: config.probeUploadBucket, ...input, ContinuationToken: token }));
      each(r);
      token = r.IsTruncated ? r.NextContinuationToken : undefined;
    } while (token);
  };
  try {
    const trees: string[] = [];
    await page({ Prefix: root, Delimiter: "/" }, (r) => {
      for (const p of r.CommonPrefixes ?? []) {
        const name = String(p.Prefix ?? "").slice(root.length).replace(/\/$/, "");
        if (want.has(name) || /^(\d{12}|unknown)$/.test(name)) trees.push(String(p.Prefix));
      }
    });
    for (const tree of trees) await page({ Prefix: tree }, (r) => {
      for (const o of r.Contents ?? []) { const p = o.Key ? parseUploadKey(o.Key) : null; if (p && want.has(p.kind)) out.push({ key: o.Key!, bytes: Number(o.Size ?? 0), last_modified: o.LastModified?.toISOString() ?? null, ...p }); }
    });
  } finally { if (!opts.s3) c.destroy(); }
  return out;
}

// ---- is the bucket usable with the identity that signs? -------------------------------------------------------------------

export interface ProbeUploadStatus { configured: boolean; bucket: string | null; prefix: string | null; ok: boolean | null; error: string | null; checked_at: string | null; identity: string | null }
let status: ProbeUploadStatus = { configured: false, bucket: null, prefix: null, ok: null, error: null, checked_at: null, identity: null };
let checking: Promise<ProbeUploadStatus> | null = null;
const RECHECK_MS = 10 * 60_000;

/** The last check's result, without running one. */
export const probeUploadStatus = (): ProbeUploadStatus => ({ ...status, configured: probeUploadsConfigured(), bucket: config.probeUploadBucket || null, prefix: probeUploadsConfigured() ? prefix() : null });

/**
 * Whether uploads can work right now: the bucket answers HeadBucket (s3:ListBucket) and takes a small marker object under the
 * prefix (s3:PutObject) that is read back (s3:GetObject), all with the identity that signs the URLs. Run at most every ten
 * minutes, or now when `force`; the outcome is logged when it changes, so a bucket in another account, a missing statement or
 * a KMS key the role may not use shows up in the log and on Settings > Probes, not as a failed upload on every box.
 */
export async function checkProbeUploads(force = false): Promise<ProbeUploadStatus> {
  if (!probeUploadsConfigured()) { status = { ...status, ok: null, error: null, identity: null }; return probeUploadStatus(); }
  if (!force && status.checked_at && Date.now() - Date.parse(status.checked_at) < RECHECK_MS && status.bucket === config.probeUploadBucket) return probeUploadStatus();
  if (checking) return checking;
  checking = (async () => {
    const before = status.ok; const bucket = config.probeUploadBucket; const c = client();
    let identity: string | null = null;
    try {
      try { const { STSClient, GetCallerIdentityCommand } = await import("@aws-sdk/client-sts"); const base = accountCredentials(null); const sts = new STSClient({ region: base.region, credentials: base.provider }); try { identity = (await sts.send(new GetCallerIdentityCommand({}))).Arn ?? null; } finally { sts.destroy(); } } catch { /* the error below says enough */ }
      let step = "HeadBucket (s3:ListBucket)";
      await c.send(new HeadBucketCommand({ Bucket: bucket }));
      const key = `${prefix()}/_check/${stamp(new Date())}.txt`;
      step = "PutObject (s3:PutObject)";
      await c.send(new PutObjectCommand({ Bucket: bucket, Key: key, Body: `aws-advisor probe uploads check ${identity ?? ""}\n`, ContentType: "text/plain" }));
      step = "GetObject (s3:GetObject)";
      await (await c.send(new GetObjectCommand({ Bucket: bucket, Key: key }))).Body!.transformToByteArray();
      status = { ...status, bucket, prefix: prefix(), ok: true, error: null, checked_at: new Date().toISOString(), identity };
      if (before !== true) console.log(`[probe-uploads] bucket ${bucket} takes uploads under ${prefix()}/ as ${identity ?? "the advisor's identity"}`);
      void step;
    } catch (e: any) {
      const msg = `${e?.name || "error"}: ${String(e?.message || e).slice(0, 300)}`;
      status = { ...status, bucket, prefix: prefix(), ok: false, error: msg, checked_at: new Date().toISOString(), identity };
      if (before !== false) console.error(`[probe-uploads] bucket ${bucket} is not usable as ${identity ?? "the advisor's identity"} (${msg}); every probe answers inline until it is (a bucket in another account needs a bucket policy for this role; the role needs s3:PutObject, s3:GetObject under ${prefix()}/ and s3:ListBucket)`);
    } finally { c.destroy(); checking = null; }
    return probeUploadStatus();
  })();
  return checking;
}
/** True when a URL may be signed now: configured and the last check (at most ten minutes old) passed. */
export async function probeUploadsReady(): Promise<boolean> { return probeUploadsConfigured() && (await checkProbeUploads()).ok === true; }

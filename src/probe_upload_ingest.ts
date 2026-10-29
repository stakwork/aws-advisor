import { fetchProbeUpload, listProbeUploads, probeUploadIngested, probeUploadsConfigured, recordProbeUpload } from "./probe_uploads.js";
import { PROBE_KINDS, type ProbeKind } from "./probes.js";
import { applyProbeResult, parseProbeOutput, type ProbeResult } from "./ssm.js";

/**
 * The objects the probes left in S3 (src/probe_uploads.ts), ingested again: the newest per box and kind, parsed and
 * applied as if the probe had just answered (the inventory tables, then the graph). A replay after a recorder fix, or
 * for a run whose read-back failed; `replay` false skips objects already ingested. Run from Schedules ("Run now").
 */
export async function ingestProbeUploads(opts: { kinds?: ProbeKind[]; replay?: boolean; log?: (l: string) => void } = {}): Promise<{ objects: number; ingested: number; skipped: number; failed: { key: string; error: string }[] }> {
  const log = opts.log ?? ((l: string) => console.log(`[probe-uploads] ${l}`));
  if (!probeUploadsConfigured()) return { objects: 0, ingested: 0, skipped: 0, failed: [{ key: "*", error: "no upload bucket configured (Settings > Probe pass)" }] };
  const kinds = new Set<string>(opts.kinds?.length ? opts.kinds : PROBE_KINDS);
  const all = (await listProbeUploads()).filter((o) => kinds.has(o.kind));
  const newest = new Map<string, (typeof all)[number]>();
  for (const o of all) { const k = `${o.instance_id}\t${o.kind}`; const cur = newest.get(k); if (!cur || o.at > cur.at) newest.set(k, o); }
  const res = { objects: all.length, ingested: 0, skipped: 0, failed: [] as { key: string; error: string }[] };
  for (const o of newest.values()) {
    if (!opts.replay && probeUploadIngested(o.key)) { res.skipped++; continue; }
    try {
      const data = parseProbeOutput(await fetchProbeUpload(o.key, null));
      if (data.kind !== o.kind) throw new Error(`the object is a ${data.kind} probe, its key says ${o.kind}`);
      applyProbeResult(o.instance_id, data, storedForm(data));
      recordProbeUpload({ key: o.key, instanceId: o.instance_id, accountId: o.account_id, kind: o.kind, collectedAt: data.collected_at, uploadedAt: o.last_modified ?? undefined });
      res.ingested++; log(`${o.instance_id} ${o.kind}: ingested ${o.key} (${o.bytes} bytes, collected ${data.collected_at})`);
    } catch (e: any) { res.failed.push({ key: o.key, error: String(e?.message || e).slice(0, 200) }); log(`${o.instance_id} ${o.kind}: ${o.key} failed: ${String(e?.message || e).slice(0, 200)}`); }
  }
  return res;
}

/** What goes into instance_metrics for an sbom result: the scans without their package lists (the tables hold those; a row per box per day must stay small). */
export function storedForm(data: ProbeResult): ProbeResult {
  if (data.kind !== "sbom" || !data.sbom) return data;
  return { ...data, sbom: { ...data.sbom, sources: data.sbom.sources.map((s) => ({ ...s, purls: [] })) } };
}

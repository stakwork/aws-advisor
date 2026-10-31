/**
 * The image half of the sbom pass: the distinct container images the fleet runs, read once each on the designated scanner
 * instance (Settings > Probe pass > Image scanner instance) instead of once per box. The software probe lists every box's
 * running images with their registry digest and platform (instance_images, keyed by imageKey); this pass takes the keys
 * with a digest that have no ok scan inside the sbom interval, turns them into pull references (`repo@sha256:…|os/arch`),
 * and sends the scanner one `images` document per batch (src/probes.ts, kind images; src/ssm.ts probeInstance with
 * opts.parameters). The scanner pulls each image from its registry with its own credentials and answers with the same
 * scan records as the sbom probe; the hook records them into the image tables (software_inventory.ts recordImageSbom)
 * and the graph gets CONTAINS edges for every box running the image.
 *
 * What the per-box sbom probe then does follows from the outcome (sbomImagesMode): when the scanner answered, the boxes
 * scan only their local builds (images=local); when there is no scanner, it is offline, or every batch failed, the boxes
 * scan every image themselves, as before, so nothing is lost to the scanner being away.
 */
import { config } from "./config.js";
import { db } from "./db.js";
import { credentialGate } from "./gate.js";
import { probeUploadsReady } from "./probe_uploads.js";
import { imageKey, pullRefOf } from "./software_inventory.js";
import { ProbeError, probeInstance } from "./ssm.js";

/** A batch of the images document: entries per command and characters of the `images` parameter (an entry is ~100 to 210 characters; SSM parameters stay well under their limit). */
export const IMAGE_BATCH = { maxEntries: 15, maxChars: 3500 } as const;
/** Without an upload bucket the answer is inline, trimmed to 3,000 purls shared across the batch: small batches, so each image keeps most of its list. */
export const INLINE_IMAGE_BATCH = { maxEntries: 4, maxChars: 3500 } as const;
/** Distinct images per pass, at most. */
export const IMAGES_PER_PASS = 300;

export interface DueImage { key: string; image: string; pull_ref: string; platform: string | null; /** running boxes that carry the image */ boxes: number }

export interface ImagePassResult {
  started_at: string;
  /** the scanner instance, null when none is configured */
  scanner: string | null;
  /** whether the scanner did its part this pass (nothing due counts): the per-box probes then leave the registry images to it */
  ok: boolean;
  /** why not, when it did not (no scanner, offline, no credentials, every batch failed, syft missing on it) */
  reason: string | null;
  candidates: number;
  batches: number;
  /** the keys read ok this pass */
  scanned: string[];
  failed: { key: string; ref: string; status: string; note: string | null }[];
  /** commands that did not come back as a result (SSM, credentials, quota, timeout) */
  commands_failed: { code: string; message: string }[];
  took_ms: number;
}

/** The configured scanner instance id, or null when the setting is empty or malformed. */
export const imageScanner = (): string | null => (/^i-[0-9a-f]{8,17}$/.test(config.probeImagesScanner) ? config.probeImagesScanner : null);

/** The skip window in minutes: the sbom interval minus a five-minute margin (src/probe_pass.ts probeWindowMinutes, repeated here to keep the modules acyclic). */
const windowMinutes = (): number => Math.max(1, Math.round(config.probeSbomIntervalHours * 60) - 5);

/** The images due on the scanner: distinct keys with a registry digest across running, non-gone boxes, without an ok scan inside the window
 *  (a failed, timed out or skipped scan is due again every pass), the most shared first. */
export function dueImages(window = windowMinutes(), limit = IMAGES_PER_PASS): DueImage[] {
  const rows = db.prepare(`
    select ii.sbom_key as key, min(ii.image) as image, min(ii.digest) as digest, min(ii.platform) as platform, count(*) as boxes
    from instance_images ii join inventory_ec2 i on i.instance_id = ii.instance_id and i.gone = 0 and i.state = 'running'
    where ii.gone = 0 and ii.sbom_key like 'dg:%'
      and not exists (select 1 from image_sbom_scans s where s.key = ii.sbom_key and s.status = 'ok' and datetime(s.collected_at) > datetime('now', ?))
    group by ii.sbom_key order by boxes desc, image limit ?`).all(`-${window} minutes`, limit) as { key: string; image: string; digest: string | null; platform: string | null; boxes: number }[];
  const out: DueImage[] = [];
  for (const r of rows) { const pull_ref = pullRefOf({ image: r.image, digest: r.digest }); if (pull_ref) out.push({ key: r.key, image: r.image, pull_ref, platform: r.platform ?? null, boxes: Number(r.boxes) }); }
  return out;
}

/** One document entry: the pull reference, and the platform after a bar when the box reported one. Pure. */
export const imageEntry = (i: { pull_ref: string; platform: string | null }): string => (i.platform ? `${i.pull_ref}|${i.platform}` : i.pull_ref);

/** Entries cut into batches of at most `maxEntries`, each joining to at most `maxChars` characters (an entry longer than that is sent alone). Pure. */
export function batchImages(entries: string[], opts: { maxEntries: number; maxChars: number }): string[][] {
  const out: string[][] = []; let cur: string[] = []; let len = 0;
  for (const e of entries) {
    const add = cur.length ? e.length + 1 : e.length;
    if (cur.length && (cur.length >= opts.maxEntries || len + add > opts.maxChars)) { out.push(cur); cur = []; len = 0; }
    cur.push(e); len += cur.length === 1 ? e.length : e.length + 1;
  }
  if (cur.length) out.push(cur);
  return out;
}

/** What the sbom document's `images` parameter should say after the image half: local once the scanner did its part, all otherwise. */
export const sbomImagesMode = (r: ImagePassResult | null): "all" | "local" => (r?.ok ? "local" : "all");

const FATAL = new Set(["not_managed", "permission", "no_credentials", "quota"]);

/** The image half of the sbom pass: due images in batches to the scanner, one command at a time; the hooks record each answer. */
export async function imagePass(): Promise<ImagePassResult> {
  const t0 = Date.now(); const tag = "probe-pass:images";
  const res: ImagePassResult = { started_at: new Date().toISOString(), scanner: imageScanner(), ok: false, reason: null, candidates: 0, batches: 0, scanned: [], failed: [], commands_failed: [], took_ms: 0 };
  const done = (reason: string | null, ok = false) => { res.ok = ok; res.reason = reason; res.took_ms = Date.now() - t0; return res; };
  if (!res.scanner) return done("no image scanner configured (Settings > Probe pass > Image scanner instance)");
  const gate = await credentialGate(tag);
  if (!gate.ok) { console.log(`[${tag}] skipped: ${gate.error || "credentials not working"}`); return done(gate.error || "credentials not working"); }
  const due = dueImages(); res.candidates = due.length;
  if (!due.length) { console.log(`[${tag}] nothing due: every registry image the running boxes carry was read within ${windowMinutes()} min, or none has a digest`); return done(null, true); }
  const uploads = await probeUploadsReady();
  const batches = batchImages(due.map(imageEntry), uploads ? IMAGE_BATCH : INLINE_IMAGE_BATCH);
  res.batches = batches.length;
  console.log(`[${tag}] ${due.length} image(s) due on ${res.scanner} (${due.reduce((n, d) => n + d.boxes, 0)} box-image pairs) in ${batches.length} batch(es)${uploads ? "" : "; no upload bucket, so small batches under the inline output cap (Settings > Probe pass > Upload bucket lifts that)"}`);
  let answered = 0;
  for (const [i, batch] of batches.entries()) {
    const t1 = Date.now();
    try {
      const stored = await probeInstance(res.scanner, { kind: "images", parameters: { images: batch.join(" ") } });
      const sbom = stored.data.sbom;
      if (!sbom?.available) { console.error(`[${tag}] syft is not available on ${res.scanner}: ${sbom?.install || "not installed"}; the boxes scan every image themselves this pass`); return done(`syft is not available on the scanner ${res.scanner}${sbom?.install ? ` (${sbom.install})` : ""}`); }
      answered++;
      let ok = 0;
      for (const s of sbom.sources) {
        const key = imageKey({ digest: s.digest, image_id: null, platform: s.platform }); if (!key) continue;
        if (s.status === "ok") { ok++; res.scanned.push(key); } else res.failed.push({ key, ref: s.ref, status: s.status, note: s.note });
      }
      const failed = sbom.sources.filter((s) => s.status !== "ok");
      console.log(`[${tag}] batch ${i + 1}/${batches.length} on ${res.scanner}: ${ok} ok${failed.length ? `, ${failed.length} not read (${[...new Set(failed.map((f) => `${f.status}${f.note ? `: ${f.note}` : ""}`))].slice(0, 3).join("; ")})` : ""} of ${batch.length} in ${Math.round((Date.now() - t1) / 1000)} s`);
    } catch (e: any) {
      const code = e instanceof ProbeError ? e.code : e?.name === "QuotaError" ? "quota" : "failed";
      const message = String(e?.message || e);
      res.commands_failed.push({ code, message: message.slice(0, 300) });
      console.error(`[${tag}] batch ${i + 1}/${batches.length} on ${res.scanner} ${code}: ${message.slice(0, 600).replace(/\s+/g, " ")}`);
      // the scanner itself is the problem (not SSM-online, no rights, no credentials, the hourly quota): no point in the next batch
      if (FATAL.has(code)) { if (!answered) return done(`the scanner ${res.scanner} could not be used: ${code}: ${message.slice(0, 200)}`); break; }
      // a timed out or failed command: on to the next batch; this one's images are due again next pass
    }
  }
  if (!answered) return done(`no batch came back from the scanner ${res.scanner} (${res.commands_failed.map((c) => c.code).join(", ") || "no commands sent"})`);
  return done(null, true);
}

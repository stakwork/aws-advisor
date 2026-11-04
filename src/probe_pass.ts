/**
 * Scheduled probe passes, one per probe kind (src/probes.ts): each runs its SSM document where it can change a
 * decision, i.e. running, SSM-online instances in its scope (idle candidates and open idle recommendations, or every
 * box), skipping anything probed for that kind within its minimum interval, AWS Batch workers and instances younger
 * than fifteen minutes. Capped per pass. The host pass also rolls up the daily tables, checks the host and disk
 * levels and refreshes the RDS load profiles; old samples are pruned after 30 days.
 */
import { config } from "./config.js";
import { db } from "./db.js";
import { ProbeError, probeInstance } from "./ssm.js";
import { PROBE_DEFS, PROBE_KINDS, type ProbeKind, legacyKindOf } from "./probes.js";
import { pruneImageSboms } from "./software_inventory.js"; // also the instance_sbom_scans table the sbom retry rule reads
import { type ImagePassResult, dueImages, imagePass, imageScanner } from "./image_pass.js";
import { credentialGate } from "./gate.js";
import { pruneHistory, rollupDaily } from "./history.js";
import { checkAllDiskLevels } from "./disk_alerts.js";
import { checkAllHostLevels } from "./host_alerts.js";
import { RdsLoadPassResult, rdsLoadPass } from "./rds_load.js";
import { finishPass, notePassSelection, startPass } from "./probe_log.js";

export interface ProbePassResult {
  kind: ProbeKind;
  started_at: string;
  candidates: number;
  probed: string[];
  failed: { instance_id: string; code: string; message: string }[];
  pruned: number;
  /** The database half of the pass (src/rds_load.ts): load profiles refreshed for every RDS cluster and instance. */
  databases: RdsLoadPassResult | null;
  /** The image half of the sbom pass (src/image_pass.ts): the registry images read on the scanner instance before the boxes ran; null for other kinds and when no scanner is configured. */
  images?: ImagePassResult | null;
  took_ms: number;
  /** The pass's row in probe_passes (History > Probes); 0 when it could not be written. */
  pass_id?: number;
}

const inFlight = new Map<ProbeKind, Promise<ProbePassResult>>();

/** The scope and the minimum interval of a kind (Settings > Probe pass): the software and sbom probes have their own, the rest share. */
export const probeKindSettings = (kind: ProbeKind): { scope: "idle" | "all"; intervalHours: number } =>
  kind === "software" ? { scope: config.probeSoftwareScope, intervalHours: config.probeSoftwareIntervalHours }
  : kind === "sbom" || kind === "images" ? { scope: config.probeSbomScope, intervalHours: config.probeSbomIntervalHours }
  : { scope: config.probeScope, intervalHours: config.probeMinIntervalHours };

/** The sbom probe retries a box where syft was not available on every pass while the install switch is on: the next run installs it (or says again why it cannot). */
const retryUnavailableSbom = (kind: ProbeKind): 0 | 1 => (kind === "sbom" && config.probeSbomInstall !== "off" ? 1 : 0);

/** The skip window in minutes: the configured hours minus a five-minute margin, so "1" means every hourly pass
 *  (the previous probe finished seconds after its cron minute and would otherwise still be inside a full hour). */
export function probeWindowMinutes(hours: number): number { return Math.max(1, Math.round(hours * 60) - 5); }

/** Why running instances were not probed in a pass, as counts per reason, for the log. */
export function probeExclusions(kind: ProbeKind = "host", window: number | null = probeWindowMinutes(probeKindSettings(kind).intervalHours)): { running: number; not_ssm_online: number; batch: number; just_launched: number; outside_scope: number; probed_recently: number } {
  const n = (sql: string, ...p: unknown[]) => Number((db.prepare(sql).get(...p) as any)?.n ?? 0);
  const base = "from inventory_ec2 i where i.gone = 0 and i.state = 'running'";
  return {
    running: n(`select count(*) as n ${base}`),
    not_ssm_online: n(`select count(*) as n ${base} and coalesce(i.ssm_status, '') <> 'Online'`),
    batch: n(`select count(*) as n ${base} and i.ssm_status = 'Online' and coalesce(i.pool_kind, '') = 'batch'`),
    just_launched: n(`select count(*) as n ${base} and i.ssm_status = 'Online' and coalesce(i.pool_kind, '') <> 'batch' and i.launch_time is not null and datetime(i.launch_time) >= datetime('now', '-15 minutes')`),
    outside_scope: probeKindSettings(kind).scope === "all" ? 0 : n(`select count(*) as n ${base} and i.ssm_status = 'Online' and coalesce(i.pool_kind, '') <> 'batch'
      and not ((i.cpu_30d is not null and i.cpu_30d < ?) or exists (select 1 from recommendations r where r.resource = i.instance_id and r.rule = 'idle_instance' and r.status in ('open', 'snoozed')))`, config.probeIdleCpu),
    probed_recently: window == null ? 0 : n(`select count(*) as n ${base} and i.ssm_status = 'Online' and coalesce(i.pool_kind, '') <> 'batch'
      and exists (select 1 from instance_metrics m where m.instance_id = i.instance_id and coalesce(m.kind, 'all') in (?, ?) and datetime(m.collected_at) > datetime('now', ?))
      and not (? = 1 and exists (select 1 from instance_sbom_scans s where s.instance_id = i.instance_id and s.available = 0))`, kind, legacyKindOf(kind), `-${window} minutes`, retryUnavailableSbom(kind)),
  };
}

/** How a pass picks its boxes beyond the kind's settings: `ignoreInterval` drops the minimum-hours window (a pass run by hand from Settings > Probes probes every box in scope, however recently it was probed). */
export interface ProbeTargetOptions { ignoreInterval?: boolean }

export function probeTargets(kind: ProbeKind = "host", limit?: number, opts: ProbeTargetOptions = {}): { instance_id: string; name: string | null; cpu_30d: number | null }[] {
  if (!PROBE_DEFS[kind].per_box) return []; // the images kind goes to the one scanner instance with the due images as its parameter (src/image_pass.ts dueImages)
  const { scope, intervalHours } = probeKindSettings(kind);
  const cap = limit ?? (scope === "all" ? Math.max(config.probeMax, 100) : config.probeMax);
  return db.prepare(`
    select i.instance_id, i.name, i.cpu_30d
    from inventory_ec2 i
    where i.gone = 0 and i.state = 'running' and i.ssm_status = 'Online'
      -- Batch workers live only while a job runs: nothing to learn from probing one, and a member launched
      -- minutes ago is not yet ready for Run Command even when the inventory already shows it Online
      and coalesce(i.pool_kind, '') <> 'batch'
      and (i.launch_time is null or datetime(i.launch_time) < datetime('now', '-15 minutes'))
      and (
        ? = 'all'
        or (i.cpu_30d is not null and i.cpu_30d < ?)
        or exists (select 1 from recommendations r where r.resource = i.instance_id and r.rule = 'idle_instance' and r.status in ('open', 'snoozed'))
      )
      -- collected_at is the probe's ISO time (2026-09-19T15:09:45Z): datetime() normalises it; a raw string compare
      -- against datetime('now') sorts every same-day probe as newer and would skip the instance for the rest of the day
      -- a pre-2.0 combined probe (kind 'all') counts for host, docker and apps, never for software
      -- a box where syft was not available is due again on every sbom pass while the install switch is on
      -- a pass run by hand (ignoreInterval) takes every box in scope, the window notwithstanding
      and (? = 1
        or not exists (select 1 from instance_metrics m where m.instance_id = i.instance_id and coalesce(m.kind, 'all') in (?, ?) and datetime(m.collected_at) > datetime('now', ?))
        or (? = 1 and exists (select 1 from instance_sbom_scans s where s.instance_id = i.instance_id and s.available = 0)))
    order by coalesce(i.cpu_30d, 100) asc, i.instance_id
    limit ?`).all(scope, config.probeIdleCpu, opts.ignoreInterval ? 1 : 0, kind, legacyKindOf(kind), `-${probeWindowMinutes(intervalHours)} minutes`, retryUnavailableSbom(kind), cap) as any[];
}

/** One pass of one kind (host by default); a pass of a kind already running is joined, not doubled (a forced pass joining a scheduled one gets the scheduled one's
 *  selection). The images kind is the scanner's pass (PROBE_IMAGES_CRON, its own cron since 2026-11-04). `force` (Run pass now on Settings > Probes) ignores the minimum-hours window: every
 *  box in scope is probed, however recently it was; the cron keeps the window. */
export function probePass(kind: ProbeKind = "host", opts: { force?: boolean } = {}): Promise<ProbePassResult> {
  const running = inFlight.get(kind);
  if (running) return running;
  const p = (kind === "images" ? runImages(opts) : run(kind, opts)).finally(() => { inFlight.delete(kind); });
  inFlight.set(kind, p);
  return p;
}

/** The images pass (PROBE_IMAGES_CRON; by hand from Settings > Probes or POST /api/probes/images/pass): the scanner alone, as a pass result (candidates are the due images,
 *  probed the keys read). `force` takes every image with a digest, the interval notwithstanding, as a forced per-box pass takes every box. */
async function runImages(opts: { force?: boolean } = {}): Promise<ProbePassResult> {
  const t0 = Date.now();
  const passId = startPass("images", opts.force ? "manual" : "cron");
  const images = await imagePass(passId, { force: opts.force === true });
  const failed = [...images.failed.map((f) => ({ instance_id: f.ref, code: f.status, message: f.note || `${f.status} on the scanner` })), ...images.commands_failed.map((c) => ({ instance_id: images.scanner || "*", code: c.code, message: c.message }))];
  if (!images.ok && images.reason && !failed.length) failed.push({ instance_id: images.scanner || "*", code: "skipped", message: images.reason });
  finishPass(passId, { candidates: images.candidates, probed: images.scanned.length, failed, note: imagesNote(images) });
  return { kind: "images", started_at: images.started_at, candidates: images.candidates, probed: images.scanned, failed, pruned: 0, databases: null, images, took_ms: Date.now() - t0, pass_id: passId };
}
/** One line on the scanner's half of a pass, for the pass row. */
const imagesNote = (images: ImagePassResult | null): string | null => (images ? `images on ${images.scanner ?? "no scanner"}: ${images.scanned.length} read, ${images.failed.length} not read of ${images.candidates} due in ${images.batches} batch(es)${images.reason ? `; ${images.reason}` : ""}` : null);

async function run(kind: ProbeKind, opts: { force?: boolean } = {}): Promise<ProbePassResult> {
  const t0 = Date.now();
  const tag = `probe-pass:${kind}`;
  const ignoreInterval = opts.force === true;
  const workers = Math.max(1, PROBE_DEFS[kind].concurrency);
  const longRunning = PROBE_DEFS[kind].timeout_seconds >= 600; // minutes per box: say when each finishes, so a slow pass is readable while it runs
  const gate = await credentialGate(tag);
  if (!gate.ok) console.log(`[${tag}] skipped: ${gate.error || "credentials not working"}`);
  const passId = startPass(kind, ignoreInterval ? "manual" : "cron");
  if (!gate.ok) {
    const failed = [{ instance_id: "*", code: "no_credentials", message: gate.error || "credentials not working" }];
    finishPass(passId, { candidates: 0, probed: 0, failed, note: `skipped: ${failed[0]!.message}` });
    return { kind, started_at: new Date().toISOString(), candidates: 0, probed: [], failed, pruned: 0, databases: null, took_ms: Date.now() - t0, pass_id: passId };
  }
  // the images pass is a cron of its own since 2026-11-04 (PROBE_IMAGES_CRON, runImages): the boxes scan only their local builds (images=local) while the
  // scanner has answered within two sbom intervals, else every running image themselves, so a scanner that is away costs coverage for one pass, never silently
  const images: ImagePassResult | null = null;
  if (kind === "sbom" && imageScanner()) console.log(`[${tag}] image scanner ${imageScanner()}: ${sbomImagesModeNow() === "local" ? "answered recently; the boxes scan only their local builds (images=local)" : "no successful images pass within two sbom intervals; the boxes scan every running image themselves (images=all)"}`);
  // the sbom document's parameters: the images mode while a scanner is configured, and what the box reads of itself (Settings > Probe pass; sbom 1.7)
  const parameters = kind === "sbom" ? { ...(imageScanner() ? { images: sbomImagesModeNow() } : {}), host: config.probeSbomHost } : undefined;
  const { scope, intervalHours } = probeKindSettings(kind);
  const targets = probeTargets(kind, undefined, { ignoreInterval });
  const result: ProbePassResult = { kind, started_at: new Date().toISOString(), candidates: targets.length, probed: [], failed: [], pruned: 0, databases: null, images, took_ms: 0, pass_id: passId };
  try {
    const x = probeExclusions(kind, ignoreInterval ? null : undefined); const limit = scope === "all" ? Math.max(config.probeMax, 100) : config.probeMax;
    const why = [x.not_ssm_online && `${x.not_ssm_online} not SSM online`, x.batch && `${x.batch} Batch worker(s)`, x.just_launched && `${x.just_launched} launched under 15 min ago`,
      x.outside_scope && `${x.outside_scope} outside scope "idle" (CPU over ${config.probeIdleCpu} % and no idle recommendation)`, x.probed_recently && `${x.probed_recently} probed within ${probeWindowMinutes(intervalHours)} min`].filter(Boolean);
    const selection = `${targets.length} candidate(s) of ${x.running} running${why.length ? `: left out ${why.join(", ")}` : ""}; scope ${scope}, limit ${limit}, ${ignoreInterval ? `interval ${intervalHours} h ignored (run by hand)` : `interval ${intervalHours} h`}, ${workers} at a time`;
    console.log(`[${tag}] ${PROBE_DEFS[kind].title}: ${selection}`);
    notePassSelection(passId, selection);
  } catch (e: any) { console.error(`[${tag}] could not explain the selection: ${e?.message || e}`); }
  // as many at a time as the kind says (PROBE_DEFS concurrency): the boxes do the work and SSM runs them side by side, the advisor sends and waits
  const queue = [...targets];
  const worker = async () => {
    for (let t = queue.shift(); t; t = queue.shift()) {
      const t1 = Date.now();
      try {
        await probeInstance(t.instance_id, { kind, parameters, origin: "pass", passId });
        result.probed.push(t.instance_id);
        if (longRunning) console.log(`[${tag}] ${t.instance_id}${t.name ? ` (${t.name})` : ""} done in ${Math.round((Date.now() - t1) / 1000)} s; ${result.probed.length + result.failed.length} of ${targets.length} finished, ${queue.length} waiting`);
      } catch (e: any) {
        const code = e instanceof ProbeError ? e.code : e?.name === "QuotaError" ? "quota" : "failed";
        const message = String(e?.message || e);
        result.failed.push({ instance_id: t.instance_id, code, message: message.slice(0, 200) });
        // every failure on its own line, with the box: a script that died prints its stderr here (the probe's message carries it), which the counts below hide
        console.error(`[${tag}] ${t.instance_id}${t.name ? ` (${t.name})` : ""} ${code}: ${message.slice(0, 600).replace(/\s+/g, " ")}`);
        // a permission problem, or the hourly probe quota, is the same for every instance: stop early, and account for what was not attempted
        // (the summary's counts add up to the candidates, and the log says why the rest was left)
        if (code === "permission" || code === "no_credentials" || code === "quota") {
          const left = queue.splice(0, queue.length);
          for (const l of left) result.failed.push({ instance_id: l.instance_id, code: "not_attempted", message: `not attempted: the pass stopped after ${code} on ${t.instance_id}` });
          if (left.length) console.error(`[${tag}] stopped: ${left.length} candidate(s) not attempted after ${code} on ${t.instance_id}${code === "quota" ? ". The quota (Settings > Quotas > SSM probes per hour) counts every kind's probes together; raise it or space the passes out" : ""}`);
        }
      }
    }
  };
  await Promise.all(Array.from({ length: workers }, () => worker()));
  if (kind === "host" || kind === "docker") {
    // roll yesterday (and any day not yet rolled) into the daily tables before the raw detail expires
    try { const r = rollupDaily(); console.log(`[${tag}] rolled up ${r.instance_days} instance-days, ${r.container_days} container-days`); } catch (e: any) { console.error(`[${tag}] rollup failed: ${e?.message || e}`); }
  }
  if (kind === "host") {
    try { checkAllHostLevels(); } catch (e: any) { console.error(`[${tag}] host check failed: ${e?.message || e}`); }
    try { checkAllDiskLevels(); } catch (e: any) { console.error(`[${tag}] disk check failed: ${e?.message || e}`); }
    // the databases: the same cadence as the host probe, so the load profile behind an RDS recommendation is never older than the last pass
    try { result.databases = await rdsLoadPass(); } catch (e: any) { console.error(`[${tag}] rds load pass failed: ${e?.message || e}`); }
    result.pruned = pruneHistory().probes;
  }
  // the apps probe carries what the boxes ship logs to (probe 1.6): the knowledge layer's log attribution reads it
  if (kind === "apps" && result.probed.length) { const { mirrorKnowledgeInBackground } = await import("./graph_mirror.js"); mirrorKnowledgeInBackground(`${kind} probe pass (${result.probed.length} probed)`); }
  // image scans nobody runs any more (the image left every box a month ago) go; the graph keeps their retired edges
  if (kind === "sbom") { try { const p = pruneImageSboms(); if (p.scans) console.log(`[${tag}] retired ${p.scans} image scan(s) nobody runs (${p.packages} package rows)`); } catch (e: any) { console.error(`[${tag}] image scan prune failed: ${e?.message || e}`); } }
  result.took_ms = Date.now() - t0;
  finishPass(passId, { candidates: result.candidates, probed: result.probed.length, failed: result.failed, note: imagesNote(images) });
  const byCode = new Map<string, number>(); for (const f of result.failed) byCode.set(f.code, (byCode.get(f.code) || 0) + 1);
  console.log(`[${tag}] ${result.probed.length} probed, ${result.failed.length} failed of ${result.candidates} candidates in ${result.took_ms} ms${byCode.size ? ` (failures: ${[...byCode].map(([c, n]) => `${c} ${n}`).join(", ")})` : ""}`);
  return result;
}

/** The sbom document's images mode now: `local` (the boxes read only their local builds) when a scanner is configured and an images pass finished within two sbom
 *  intervals having read something, or having had nothing due; `all` otherwise, so a scanner that is away or failing never leaves the registry images unread. */
export function sbomImagesModeNow(): "all" | "local" {
  if (!imageScanner()) return "all";
  const hours = Math.max(1, config.probeSbomIntervalHours) * 2;
  const row = db.prepare("select probed, candidates, failed from probe_passes where kind = 'images' and finished_at is not null and datetime(finished_at) > datetime('now', ?) order by id desc limit 1").get(`-${hours} hours`) as { probed: number; candidates: number; failed: number } | undefined;
  return row && (row.probed > 0 || (row.candidates === 0 && row.failed === 0)) ? "local" : "all";
}

/** What the images kind would send now: the due images (Settings > Probes "due now"). */
export const dueImagesNow = (): number => (imageScanner() ? dueImages().length : 0);

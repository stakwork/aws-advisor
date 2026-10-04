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
import { PROBE_DEFS, PROBE_KINDS, type ProbeKind } from "./probes.js";
import { credentialGate } from "./gate.js";
import { pruneHistory, rollupDaily } from "./history.js";
import { checkAllDiskLevels } from "./disk_alerts.js";
import { checkAllHostLevels } from "./host_alerts.js";
import { RdsLoadPassResult, rdsLoadPass } from "./rds_load.js";

export interface ProbePassResult {
  kind: ProbeKind;
  started_at: string;
  candidates: number;
  probed: string[];
  failed: { instance_id: string; code: string; message: string }[];
  pruned: number;
  /** The database half of the pass (src/rds_load.ts): load profiles refreshed for every RDS cluster and instance. */
  databases: RdsLoadPassResult | null;
  took_ms: number;
}

const inFlight = new Map<ProbeKind, Promise<ProbePassResult>>();

/** The scope and the minimum interval of a kind (Settings > Probe pass): the software probe has its own, the rest share. */
export const probeKindSettings = (kind: ProbeKind): { scope: "idle" | "all"; intervalHours: number } =>
  kind === "software" ? { scope: config.probeSoftwareScope, intervalHours: config.probeSoftwareIntervalHours } : { scope: config.probeScope, intervalHours: config.probeMinIntervalHours };

/** The skip window in minutes: the configured hours minus a five-minute margin, so "1" means every hourly pass
 *  (the previous probe finished seconds after its cron minute and would otherwise still be inside a full hour). */
export function probeWindowMinutes(hours: number): number { return Math.max(1, Math.round(hours * 60) - 5); }

/** Why running instances were not probed in a pass, as counts per reason, for the log. */
export function probeExclusions(kind: ProbeKind = "host", window = probeWindowMinutes(probeKindSettings(kind).intervalHours)): { running: number; not_ssm_online: number; batch: number; just_launched: number; outside_scope: number; probed_recently: number } {
  const n = (sql: string, ...p: unknown[]) => Number((db.prepare(sql).get(...p) as any)?.n ?? 0);
  const base = "from inventory_ec2 i where i.gone = 0 and i.state = 'running'";
  return {
    running: n(`select count(*) as n ${base}`),
    not_ssm_online: n(`select count(*) as n ${base} and coalesce(i.ssm_status, '') <> 'Online'`),
    batch: n(`select count(*) as n ${base} and i.ssm_status = 'Online' and coalesce(i.pool_kind, '') = 'batch'`),
    just_launched: n(`select count(*) as n ${base} and i.ssm_status = 'Online' and coalesce(i.pool_kind, '') <> 'batch' and i.launch_time is not null and datetime(i.launch_time) >= datetime('now', '-15 minutes')`),
    outside_scope: probeKindSettings(kind).scope === "all" ? 0 : n(`select count(*) as n ${base} and i.ssm_status = 'Online' and coalesce(i.pool_kind, '') <> 'batch'
      and not ((i.cpu_30d is not null and i.cpu_30d < ?) or exists (select 1 from recommendations r where r.resource = i.instance_id and r.rule = 'idle_instance' and r.status in ('open', 'snoozed')))`, config.probeIdleCpu),
    probed_recently: n(`select count(*) as n ${base} and i.ssm_status = 'Online' and coalesce(i.pool_kind, '') <> 'batch'
      and exists (select 1 from instance_metrics m where m.instance_id = i.instance_id and coalesce(m.kind, 'all') in (?, ?) and datetime(m.collected_at) > datetime('now', ?))`, kind, kind === "software" ? "software" : "all", `-${window} minutes`),
  };
}

export function probeTargets(kind: ProbeKind = "host", limit?: number): { instance_id: string; name: string | null; cpu_30d: number | null }[] {
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
      and not exists (select 1 from instance_metrics m where m.instance_id = i.instance_id and coalesce(m.kind, 'all') in (?, ?) and datetime(m.collected_at) > datetime('now', ?))
    order by coalesce(i.cpu_30d, 100) asc, i.instance_id
    limit ?`).all(scope, config.probeIdleCpu, kind, kind === "software" ? "software" : "all", `-${probeWindowMinutes(intervalHours)} minutes`, cap) as any[];
}

/** One pass of one kind (host by default); a pass of a kind already running is joined, not doubled. */
export function probePass(kind: ProbeKind = "host"): Promise<ProbePassResult> {
  const running = inFlight.get(kind);
  if (running) return running;
  const p = run(kind).finally(() => { inFlight.delete(kind); });
  inFlight.set(kind, p);
  return p;
}

async function run(kind: ProbeKind): Promise<ProbePassResult> {
  const t0 = Date.now();
  const tag = `probe-pass:${kind}`;
  const gate = await credentialGate(tag);
  if (!gate.ok) console.log(`[${tag}] skipped: ${gate.error || "credentials not working"}`);
  if (!gate.ok) return { kind, started_at: new Date().toISOString(), candidates: 0, probed: [], failed: [{ instance_id: "*", code: "no_credentials", message: gate.error || "credentials not working" }], pruned: 0, databases: null, took_ms: Date.now() - t0 };
  const { scope, intervalHours } = probeKindSettings(kind);
  const targets = probeTargets(kind);
  const result: ProbePassResult = { kind, started_at: new Date().toISOString(), candidates: targets.length, probed: [], failed: [], pruned: 0, databases: null, took_ms: 0 };
  try {
    const x = probeExclusions(kind); const limit = scope === "all" ? Math.max(config.probeMax, 100) : config.probeMax;
    const why = [x.not_ssm_online && `${x.not_ssm_online} not SSM online`, x.batch && `${x.batch} Batch worker(s)`, x.just_launched && `${x.just_launched} launched under 15 min ago`,
      x.outside_scope && `${x.outside_scope} outside scope "idle" (CPU over ${config.probeIdleCpu} % and no idle recommendation)`, x.probed_recently && `${x.probed_recently} probed within ${probeWindowMinutes(config.probeMinIntervalHours)} min`].filter(Boolean);
    console.log(`[${tag}] ${PROBE_DEFS[kind].title}: ${targets.length} candidate(s) of ${x.running} running${why.length ? `: left out ${why.join(", ")}` : ""}; scope ${scope}, limit ${limit}, interval ${intervalHours} h`);
  } catch (e: any) { console.error(`[${tag}] could not explain the selection: ${e?.message || e}`); }
  // a few at a time: SSM is happy with it and it keeps the pass short
  const queue = [...targets];
  const worker = async () => {
    for (let t = queue.shift(); t; t = queue.shift()) {
      try {
        await probeInstance(t.instance_id, { kind });
        result.probed.push(t.instance_id);
      } catch (e: any) {
        const code = e instanceof ProbeError ? e.code : "failed";
        result.failed.push({ instance_id: t.instance_id, code, message: String(e?.message || e).slice(0, 200) });
        // a permission problem is the same for every instance: stop early
        if (code === "permission" || code === "no_credentials" || e?.name === "QuotaError") { queue.length = 0; }
      }
    }
  };
  await Promise.all([worker(), worker(), worker()]);
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
  result.took_ms = Date.now() - t0;
  const byCode = new Map<string, number>(); for (const f of result.failed) byCode.set(f.code, (byCode.get(f.code) || 0) + 1);
  console.log(`[${tag}] ${result.probed.length} probed, ${result.failed.length} failed of ${result.candidates} candidates in ${result.took_ms} ms${byCode.size ? ` (failures: ${[...byCode].map(([c, n]) => `${c} ${n}`).join(", ")})` : ""}`);
  return result;
}

/**
 * Scheduled probe pass: runs the SSM probe only where it can change a decision, i.e. running,
 * SSM-online instances that look idle on CPU or already carry an open idle-instance
 * recommendation, skipping anything probed within PROBE_MIN_INTERVAL_HOURS, AWS Batch workers and instances
 * younger than fifteen minutes. Capped per pass. Old samples are pruned after 30 days.
 */
import { config } from "./config.js";
import { db } from "./db.js";
import { ProbeError, probeInstance } from "./ssm.js";
import { credentialGate } from "./gate.js";
import { pruneHistory, rollupDaily } from "./history.js";
import { checkAllDiskLevels } from "./disk_alerts.js";
import { checkAllHostLevels } from "./host_alerts.js";

export interface ProbePassResult {
  started_at: string;
  candidates: number;
  probed: string[];
  failed: { instance_id: string; code: string; message: string }[];
  pruned: number;
  took_ms: number;
}

let inFlight: Promise<ProbePassResult> | null = null;

/** The skip window in minutes: the configured hours minus a five-minute margin, so "1" means every hourly pass
 *  (the previous probe finished seconds after its cron minute and would otherwise still be inside a full hour). */
export function probeWindowMinutes(hours: number): number { return Math.max(1, Math.round(hours * 60) - 5); }

/** Why running instances were not probed in a pass, as counts per reason, for the log. */
export function probeExclusions(window = probeWindowMinutes(config.probeMinIntervalHours)): { running: number; not_ssm_online: number; batch: number; just_launched: number; outside_scope: number; probed_recently: number } {
  const n = (sql: string, ...p: unknown[]) => Number((db.prepare(sql).get(...p) as any)?.n ?? 0);
  const base = "from inventory_ec2 i where i.gone = 0 and i.state = 'running'";
  return {
    running: n(`select count(*) as n ${base}`),
    not_ssm_online: n(`select count(*) as n ${base} and coalesce(i.ssm_status, '') <> 'Online'`),
    batch: n(`select count(*) as n ${base} and i.ssm_status = 'Online' and coalesce(i.pool_kind, '') = 'batch'`),
    just_launched: n(`select count(*) as n ${base} and i.ssm_status = 'Online' and coalesce(i.pool_kind, '') <> 'batch' and i.launch_time is not null and datetime(i.launch_time) >= datetime('now', '-15 minutes')`),
    outside_scope: config.probeScope === "all" ? 0 : n(`select count(*) as n ${base} and i.ssm_status = 'Online' and coalesce(i.pool_kind, '') <> 'batch'
      and not ((i.cpu_30d is not null and i.cpu_30d < ?) or exists (select 1 from recommendations r where r.resource = i.instance_id and r.rule = 'idle_instance' and r.status in ('open', 'snoozed')))`, config.probeIdleCpu),
    probed_recently: n(`select count(*) as n ${base} and i.ssm_status = 'Online' and coalesce(i.pool_kind, '') <> 'batch'
      and exists (select 1 from instance_metrics m where m.instance_id = i.instance_id and datetime(m.collected_at) > datetime('now', ?))`, `-${window} minutes`),
  };
}

export function probeTargets(limit = config.probeScope === "all" ? Math.max(config.probeMax, 100) : config.probeMax): { instance_id: string; name: string | null; cpu_30d: number | null }[] {
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
      and not exists (select 1 from instance_metrics m where m.instance_id = i.instance_id and datetime(m.collected_at) > datetime('now', ?))
    order by coalesce(i.cpu_30d, 100) asc, i.instance_id
    limit ?`).all(config.probeScope, config.probeIdleCpu, `-${probeWindowMinutes(config.probeMinIntervalHours)} minutes`, limit) as any[];
}

export function probePass(): Promise<ProbePassResult> {
  if (inFlight) return inFlight;
  inFlight = run().finally(() => { inFlight = null; });
  return inFlight;
}

async function run(): Promise<ProbePassResult> {
  const t0 = Date.now();
  const gate = await credentialGate("probe-pass");
  if (!gate.ok) console.log(`[probe-pass] skipped: ${gate.error || "credentials not working"}`);
  if (!gate.ok) return { started_at: new Date().toISOString(), candidates: 0, probed: [], failed: [{ instance_id: "*", code: "no_credentials", message: gate.error || "credentials not working" }], pruned: 0, took_ms: Date.now() - t0 };
  const targets = probeTargets();
  const result: ProbePassResult = { started_at: new Date().toISOString(), candidates: targets.length, probed: [], failed: [], pruned: 0, took_ms: 0 };
  try {
    const x = probeExclusions(); const limit = config.probeScope === "all" ? Math.max(config.probeMax, 100) : config.probeMax;
    const why = [x.not_ssm_online && `${x.not_ssm_online} not SSM online`, x.batch && `${x.batch} Batch worker(s)`, x.just_launched && `${x.just_launched} launched under 15 min ago`,
      x.outside_scope && `${x.outside_scope} outside scope "idle" (CPU over ${config.probeIdleCpu} % and no idle recommendation)`, x.probed_recently && `${x.probed_recently} probed within ${probeWindowMinutes(config.probeMinIntervalHours)} min`].filter(Boolean);
    console.log(`[probe-pass] ${targets.length} candidate(s) of ${x.running} running${why.length ? `: left out ${why.join(", ")}` : ""}; scope ${config.probeScope}, limit ${limit}, interval ${config.probeMinIntervalHours} h`);
  } catch (e: any) { console.error(`[probe-pass] could not explain the selection: ${e?.message || e}`); }
  // a few at a time: SSM is happy with it and it keeps the pass short
  const queue = [...targets];
  const worker = async () => {
    for (let t = queue.shift(); t; t = queue.shift()) {
      try {
        await probeInstance(t.instance_id);
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
  // roll yesterday (and any day not yet rolled) into the daily tables before the raw detail expires
  try { const r = rollupDaily(); console.log(`[probe-pass] rolled up ${r.instance_days} instance-days, ${r.container_days} container-days`); } catch (e: any) { console.error(`[probe-pass] rollup failed: ${e?.message || e}`); }
  try { checkAllHostLevels(); } catch (e: any) { console.error(`[probe-pass] host check failed: ${e?.message || e}`); }
  try { checkAllDiskLevels(); } catch (e: any) { console.error(`[probe-pass] disk check failed: ${e?.message || e}`); }
  result.pruned = pruneHistory().probes;
  result.took_ms = Date.now() - t0;
  const byCode = new Map<string, number>(); for (const f of result.failed) byCode.set(f.code, (byCode.get(f.code) || 0) + 1);
  console.log(`[probe-pass] ${result.probed.length} probed, ${result.failed.length} failed of ${result.candidates} candidates in ${result.took_ms} ms${byCode.size ? ` (failures: ${[...byCode].map(([c, n]) => `${n} ${c}`).join(", ")}; first: ${result.failed[0].message})` : ""}`);
  return result;
}

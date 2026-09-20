/**
 * The daily review: reads the statistics the advisor has been collecting (daily roll-ups per instance and per
 * container, baselines, spend per service) and turns what they show into recommendations and alerts with the
 * numbers attached. Runs after the baselines (REVIEW_CRON) and on demand. Deterministic: no model call.
 */
import { db } from "./db.js";
import { S, query } from "./steampipe.js";
import { credentialGate } from "./gate.js";
import { describeError } from "./permissions.js";
import { getBaseline } from "./baselines.js";
import { LOG_INGEST_PRICE } from "./logs.js";
import { resourceRole } from "./roles.js";
import { NATURALLY_IDLE_ROLES, ROLE_CONFIDENCE_THRESHOLD, RecInput, isProtected } from "./rules.js";
import { upsertRecommendations } from "./collector.js";
import { recentIngest, topLogGroups } from "./logs.js";
import { ContainerStat, DISK_URGENT_DAYS, DISK_HORIZON_DAYS, DailyRow, diskForecast, idleContainers, memoryPressure, spendStep, sustainedIdle } from "./review_math.js";

db.exec(`create table if not exists review_findings (
  id integer primary key autoincrement,
  day text not null, kind text not null, resource text not null, resource_name text, severity text not null,
  message text not null, details text not null,
  unique(day, kind, resource, resource_name)
)`);

const WINDOW_DAYS = 30;
const insertFinding = db.prepare("insert into review_findings(day, kind, resource, resource_name, severity, message, details) values (?, ?, ?, ?, ?, ?, ?) on conflict(day, kind, resource, resource_name) do update set severity = excluded.severity, message = excluded.message, details = excluded.details");
const openAlert = db.prepare("select id from alerts where kind = ? and resource = ? and acknowledged = 0 limit 1");
const insertAlert = db.prepare("insert into alerts(kind, resource, message, details) values (?, ?, ?, ?)");

export interface ReviewResult { day: string; instances: number; findings: Record<string, number>; recommendations: number; alerts: number; errors: string[]; took_ms: number }

function alertOnce(kind: string, resource: string, message: string, details: Record<string, unknown>): boolean {
  if (openAlert.get(kind, resource)) return false;
  insertAlert.run(kind, resource, message, JSON.stringify(details));
  return true;
}

export async function runReview(onLog: (s: string) => void = () => {}): Promise<ReviewResult> {
  const t0 = Date.now();
  const day = new Date().toISOString().slice(0, 10);
  const out: ReviewResult = { day, instances: 0, findings: {}, recommendations: 0, alerts: 0, errors: [], took_ms: 0 };
  const count = (k: string) => { out.findings[k] = (out.findings[k] || 0) + 1; };
  const recs: RecInput[] = [];

  // ---- per instance: sustained idle, memory pressure, disk fill, idle containers -----------------------------
  const instances = db.prepare(`select i.instance_id, i.name, i.instance_type, i.monthly_usd, i.pool_kind, i.pool, i.state
    from inventory_ec2 i where i.gone = 0 and i.state = 'running' and exists (select 1 from instance_daily d where d.instance_id = i.instance_id)`).all() as any[];
  const dailyOf = db.prepare("select * from instance_daily where instance_id = ? and day >= date('now', ?) order by day");
  const containersOf = db.prepare(`select name, max(image) as image, count(*) as days, avg(running_share) as running_share, avg(cpu_pct_avg) as cpu_pct_avg, max(cpu_pct_max) as cpu_pct_max, avg(mem_bytes_avg) as mem_bytes_avg
    from container_daily where instance_id = ? and day >= date('now', ?) group by name`);
  for (const i of instances) {
    out.instances++;
    const rows = dailyOf.all(i.instance_id, `-${WINDOW_DAYS} days`) as DailyRow[];
    const name = i.name || i.instance_id;
    const roleRow = resourceRole(i.instance_id);
    const role = roleRow ? { role: roleRow.role, role_confidence: roleRow.role_confidence, protected_prob: roleRow.protected_prob } : undefined;
    const cpu = getBaseline("instance", i.instance_id, "cpu_pct");
    // idle
    const idle = sustainedIdle(rows, cpu?.p95 ?? null);
    if (idle.idle && i.pool_kind !== "batch") {
      const prot = isProtected(name, role);
      const naturally = role && NATURALLY_IDLE_ROLES.includes(role.role) && role.role_confidence >= ROLE_CONFIDENCE_THRESHOLD;
      const poolNote = i.pool_kind ? ` It belongs to a ${i.pool_kind} pool (${i.pool}): act on the pool's instance types or size, not on this member.` : "";
      const roleNote = naturally ? ` Jev classifies it as ${role!.role}: such workloads are idle on CPU by design, so this is informational.` : "";
      const rationale = `${idle.days} days of hourly probes: ${idle.reasons.join("; ")}. ${i.instance_type} at ${i.monthly_usd != null ? `${i.monthly_usd} USD/month` : "an unknown price"}.${poolNote}${roleNote}${prot.protected ? " Marked as deliberately kept, so report-only." : ""}`;
      const details = { ...idle, instance_type: i.instance_type, monthly_usd: i.monthly_usd, pool: i.pool, pool_kind: i.pool_kind, role: role?.role ?? null };
      insertFinding.run(day, "sustained_idle", i.instance_id, name, naturally || prot.protected ? "info" : "warning", `${name}: idle for ${idle.days} days (${idle.reasons.join(", ")})`, JSON.stringify(details));
      count("sustained_idle");
      recs.push({ rule: "review_idle", title: `Right-size ${name} (${i.instance_type}): idle for ${idle.days} days on memory, load and CPU`, resource: i.instance_id, resourceName: name, actionType: "rightsize_instance",
        estMonthlySaving: i.monthly_usd != null && !naturally ? Math.round(i.monthly_usd * 0.5) : null, tier: prot.protected || naturally || i.pool_kind ? "report" : "approve", confidence: naturally ? 0.2 : 0.85, rationale, evidence: details });
    }
    // memory pressure
    const mp = memoryPressure(rows);
    if (mp.pressure) {
      const msg = `${name}: memory ${mp.mem_avg!.toFixed(0)}% used on average over ${mp.days} days (peak ${mp.mem_max?.toFixed(0)}%)`;
      insertFinding.run(day, "memory_pressure", i.instance_id, name, "warning", msg, JSON.stringify({ ...mp, instance_type: i.instance_type }));
      count("memory_pressure");
      if (alertOnce("memory_pressure", i.instance_id, msg, { summary: msg, ...mp, instance_type: i.instance_type, name })) out.alerts++;
    }
    // disk fill
    const df = diskForecast(rows);
    if (df && df.days_to_full != null && df.days_to_full <= DISK_HORIZON_DAYS && df.r2 >= 0.5) {
      const when = df.days_to_full < 1 ? "now" : `in about ${Math.round(df.days_to_full)} days`;
      const msg = `${name}: root disk ${df.now_pct.toFixed(0)}% and growing ${df.slope_pct_day.toFixed(2)} points a day; full ${when}`;
      const sev = df.days_to_full <= DISK_URGENT_DAYS ? "alarm" : "warning";
      insertFinding.run(day, "disk_fill", i.instance_id, name, sev, msg, JSON.stringify({ ...df, instance_type: i.instance_type }));
      count("disk_fill");
      if (sev === "alarm" && alertOnce("disk_fill", i.instance_id, msg, { summary: msg, ...df, name })) out.alerts++;
      recs.push({ rule: "review_disk_fill", title: `Clean up or grow the root volume of ${name}: full ${when} at the current rate`, resource: i.instance_id, resourceName: name, actionType: "other", estMonthlySaving: 0, tier: "report", confidence: Math.min(0.95, df.r2),
        rationale: `${df.days} days of probes: root disk at ${df.now_pct.toFixed(0)}%, rising ${df.slope_pct_day.toFixed(2)} percentage points a day (fit r² ${df.r2.toFixed(2)}). Find what grows (logs, docker images, snapshots of a chain) before adding storage.`, evidence: df });
    }
    // idle containers
    const stats = containersOf.all(i.instance_id, `-${WINDOW_DAYS} days`) as ContainerStat[];
    for (const c of idleContainers(stats, WINDOW_DAYS)) {
      const mb = c.mem_bytes_avg != null ? Math.round(c.mem_bytes_avg / 1048576) : null;
      const msg = `${name}: container ${c.name} ran ${Math.round((c.running_share ?? 0) * 100)}% of ${c.days} days at ${c.cpu_pct_avg!.toFixed(2)}% CPU${mb != null ? `, ${mb} MB` : ""}`;
      insertFinding.run(day, "idle_container", i.instance_id, c.name, "info", msg, JSON.stringify({ ...c, instance: name }));
      count("idle_container");
    }
  }
  if (recs.length) {
    const runId = (db.prepare("select id from runs order by id desc limit 1").get() as { id: number } | undefined)?.id ?? 0;
    out.recommendations = recs.length;
    upsertRecommendations(runId, recs, "rules", undefined, { reconcile: false });
  }
  onLog(`instances: ${out.instances} reviewed, ${JSON.stringify(out.findings)}`);

  // ---- spend per service: last complete days against the 60-day baseline -------------------------------------
  const gate = await credentialGate("review");
  if (!gate.ok) out.errors.push(gate.error || "credentials not working");
  else {
    try {
      const rows = await query<{ service: string; day: string; net: string | null }>(`select service, to_char(period_start at time zone 'UTC', 'YYYY-MM-DD') as day, sum(net_unblended_cost_amount) as net
        from ${S}.aws_cost_by_service_daily where period_start >= now() - interval '5 days' and period_start < date_trunc('day', now()) - interval '1 day' group by 1, 2 order by 1, 2`);
      const byService = new Map<string, number[]>();
      for (const r of rows) if (r.net != null) byService.set(r.service, [...(byService.get(r.service) || []), Number(r.net)]);
      for (const [service, recent] of byService) {
        const b = getBaseline("service", service, "net_usd_day");
        const step = spendStep(service, recent.slice(-3), b ? { median: b.median, mad: b.mad } : null);
        if (!step) continue;
        const msg = `${service}: ${step.recent_avg.toFixed(0)} USD/day over the last ${step.recent_days} complete days, ${step.ratio.toFixed(1)}x its 60-day median of ${step.median.toFixed(0)} (about ${Math.round(step.excess_per_day * 30)} USD/month more if it holds)`;
        insertFinding.run(day, "spend_step", service, null, "warning", msg, JSON.stringify(step));
        count("spend_step");
        if (alertOnce("spend_step", service, msg, { summary: msg, ...step })) out.alerts++;
      }
    } catch (e) { out.errors.push(describeError(e, "review spend (aws_cost_by_service_daily)")); }
  }
  // ---- log groups: ingestion step against the 14-day baseline, and big groups that never expire ---------------
  for (const g of topLogGroups(80).groups) {
    const b = getBaseline("loggroup", g.name, "ingest_bytes_day");
    const recent = recentIngest(g.name, 3);
    const step = b ? spendStep(g.name, recent.map((x) => x / 1e9), { median: (b.median ?? 0) / 1e9, mad: (b.mad ?? 0) / 1e9 }, 0.5) : null;
    if (step && step.recent_avg >= 0.5) {
      const msg = `log group ${g.name}: ${step.recent_avg.toFixed(1)} GB/day over the last ${step.recent_days} days, ${step.ratio.toFixed(1)}x its 14-day median of ${step.median.toFixed(1)} (about ${Math.round(step.excess_per_day * 30 * LOG_INGEST_PRICE)} USD/month more in ingestion)`;
      insertFinding.run(day, "log_step", g.name, null, "warning", msg, JSON.stringify({ ...step, unit: "GB/day" }));
      count("log_step");
      if (alertOnce("log_step", g.name, msg, { summary: msg, ...step })) out.alerts++;
    }
    if (g.retention_days == null && g.stored_gb >= 5) {
      const msg = `log group ${g.name}: ${g.stored_gb.toFixed(1)} GB stored with no retention policy (${g.storage_usd_month.toFixed(0)} USD/month and growing)`;
      insertFinding.run(day, "log_no_retention", g.name, null, "info", msg, JSON.stringify({ stored_gb: g.stored_gb, storage_usd_month: g.storage_usd_month, ingest_gb_day: g.ingest_gb_day }));
      count("log_no_retention");
    }
  }
  // ---- S3: big buckets kept entirely in Standard with no lifecycle rule ------------------------------------------
  for (const b of db.prepare("select name, total_gb, standard_gb, monthly_usd, objects from inventory_s3 where gone = 0 and lifecycle_rules = 0 and standard_gb >= 20 order by standard_gb desc limit 30").all() as any[]) {
    const iaSaving = Math.round(b.standard_gb * (0.023 - 0.0125));
    const msg = `bucket ${b.name}: ${b.standard_gb.toFixed(0)} GB in Standard (${Math.round(b.monthly_usd)} USD/month) with no lifecycle rule; a transition to Infrequent Access after 30 days would save about ${iaSaving} USD/month if the objects are rarely read`;
    insertFinding.run(day, "s3_no_lifecycle", b.name, null, "info", msg, JSON.stringify({ standard_gb: b.standard_gb, total_gb: b.total_gb, monthly_usd: b.monthly_usd, objects: b.objects, ia_saving_usd_month: iaSaving }));
    count("s3_no_lifecycle");
  }
  // ---- EBS: provisioned IOPS far above what is used --------------------------------------------------------------
  for (const v of db.prepare("select * from inventory_ebs where gone = 0 and state = 'in-use' and volume_type in ('gp3', 'io1', 'io2') and iops > 3000 and metric_days >= 5").all() as any[]) {
    const used = Math.max(Number(v.iops_max || 0), Number(v.read_iops_avg || 0) + Number(v.write_iops_avg || 0));
    if (used >= 0.3 * v.iops) continue;
    const extra = v.volume_type === "gp3" ? (v.iops - 3000) * 0.005 : v.iops * 0.065;
    const msg = `volume ${v.volume_id}${v.name ? ` (${v.name})` : ""}${v.instance_id ? ` on ${v.instance_id}` : ""}: ${v.iops.toLocaleString()} IOPS provisioned, peak ${used.toFixed(0)} used in 30 days; about ${Math.round(extra)} USD/month of provisioned IOPS`;
    insertFinding.run(day, "ebs_overprovisioned_iops", v.volume_id, v.name, "info", msg, JSON.stringify({ iops: v.iops, iops_max: v.iops_max, read_iops_avg: v.read_iops_avg, write_iops_avg: v.write_iops_avg, extra_usd_month: extra, instance_id: v.instance_id }));
    count("ebs_overprovisioned_iops");
  }
  db.prepare("delete from review_findings where day < date('now', '-90 days')").run();
  out.took_ms = Date.now() - t0;
  onLog(`${out.recommendations} recommendations, ${out.alerts} new alerts, ${out.took_ms} ms`);
  return out;
}

export function reviewForDay(day: string) {
  const findings = db.prepare("select * from review_findings where day = ? order by case severity when 'alarm' then 0 when 'warning' then 1 else 2 end, kind, resource_name").all(day) as any[];
  const days = db.prepare("select day, count(*) as n from review_findings group by day order by day desc limit 30").all() as any[];
  return { day: findings.length ? day : null, findings: findings.map((f: any) => ({ ...f, details: safeJson(f.details) })), days };
}

export function latestReview(): { day: string | null; findings: any[]; days: { day: string; n: number }[] } {
  const day = (db.prepare("select max(day) as day from review_findings").get() as { day: string | null }).day;
  const findings = day ? db.prepare("select * from review_findings where day = ? order by case severity when 'alarm' then 0 when 'warning' then 1 else 2 end, kind, resource_name").all(day) : [];
  const days = db.prepare("select day, count(*) as n from review_findings group by day order by day desc limit 30").all() as any[];
  return { day, findings: findings.map((f: any) => ({ ...f, details: safeJson(f.details) })), days };
}
const safeJson = (s: string) => { try { return JSON.parse(s); } catch { return s; } };

import { config } from "./config.js";
import { db } from "./db.js";
import { S, query } from "./steampipe.js";
import { refreshInventory } from "./inventory.js";
import { credentialGate } from "./gate.js";
import { investigateAlertInBackground, refreshFlowLogRecommendations, shouldAutoInvestigate } from "./investigate.js";
import { describeError } from "./permissions.js";
import { triageAlerts } from "./triage.js";
import { mirrorAlertsInBackground, mirrorResourcesInBackground } from "./graph_mirror.js";
import { getBaseline, scoreValue } from "./baselines.js";
import { MIN_DAYS_FOR_SEASONAL } from "./baseline_math.js";

/**
 * Lightweight watcher (WATCH_CRON). Runs only cheap live Steampipe queries, never Powerpipe or Cost
 * Explorer: running instances by type, instance states, NAT gateway bytes over the last hour, active
 * Savings Plans and total EBS GB. Each sample is stored in watch_samples and compared with the previous
 * one; instance state changes and NAT traffic spikes become rows in alerts.
 */

export const NAT_SPIKE_FACTOR = 2;
export const NAT_SPIKE_BYTES_PER_HOUR = 5e9; // 5 GB/hour
export const NAT_BASELINE_SAMPLES = 6;

interface Sample { key: string; label: string; value: number; dims?: Record<string, unknown> }

export interface WatchResult { sample_id: number; collected_at: string; samples: number; alerts: number; errors: string[] }

const STATE_CODE: Record<string, number> = { pending: 0, running: 1, "shutting-down": 2, terminated: 3, stopping: 4, stopped: 5 };

const insertSample = db.prepare("insert into watch_samples(sample_id, collected_at, key, label, value, dims) values (?, ?, ?, ?, ?, ?)");
const insertAlert = db.prepare("insert into alerts(kind, resource, message, details) values (?, ?, ?, ?)");

async function collect(errors: string[]): Promise<{ samples: Sample[]; instancesOk: boolean }> {
  const out: Sample[] = [];
  const failed = new Set<string>();
  const attempt = async (what: string, tables: string, fn: () => Promise<void>) => {
    try { await fn(); } catch (e: any) { failed.add(what); errors.push(`${what}: ${describeError(e, `watcher ${what} (${tables})`, 300)}`); }
  };

  await attempt("instances", "aws_ec2_instance", async () => {
    // `pool` marks autoscaled nodes (Karpenter, EKS node groups, ASGs): their comings and goings are
    // expected and are summarised per pool per day instead of alerting one by one.
    const rows = await query<{ instance_id: string; instance_state: string; instance_type: string; name: string | null; region: string; pool: string | null; cluster: string | null }>(
      `select instance_id, instance_state, instance_type, tags ->> 'Name' as name, region,
              coalesce(tags ->> 'karpenter.sh/nodepool', tags ->> 'eks:nodegroup-name', tags ->> 'aws:autoscaling:groupName') as pool,
              tags ->> 'eks:cluster-name' as cluster
       from ${S}.aws_ec2_instance`);
    const byType = new Map<string, number>();
    for (const r of rows) {
      if (r.instance_state === "running") byType.set(r.instance_type, (byType.get(r.instance_type) || 0) + 1);
      out.push({ key: "instance_state", label: r.instance_id, value: STATE_CODE[r.instance_state] ?? -1, dims: { state: r.instance_state, name: r.name, type: r.instance_type, region: r.region, pool: r.pool, cluster: r.cluster } });
    }
    for (const [type, n] of byType) out.push({ key: "running_by_type", label: type, value: n });
    out.push({ key: "running_total", label: "running", value: [...byType.values()].reduce((s, n) => s + n, 0) });
  });

  await attempt("nat_gateways", "aws_vpc_nat_gateway, aws_cloudwatch_metric_statistic_data_point", async () => {
    const gws = await query<{ nat_gateway_id: string; region: string }>(`select nat_gateway_id, region from ${S}.aws_vpc_nat_gateway where state = 'available'`);
    for (const g of gws) {
      const dims = JSON.stringify([{ Name: "NatGatewayId", Value: g.nat_gateway_id }]);
      const rows = await query<{ metric_name: string; total: string | null }>(`
        select metric_name, sum(sum) as total
        from ${S}.aws_cloudwatch_metric_statistic_data_point
        where namespace = 'AWS/NATGateway' and metric_name in ('BytesInFromDestination', 'BytesOutToDestination')
          and dimensions = '${dims.replace(/'/g, "''")}'
          and timestamp between now() - interval '1 hour' and now() and period = 300 and region = '${g.region.replace(/'/g, "''")}'
        group by 1`);
      const by = Object.fromEntries(rows.map((r) => [r.metric_name, Number(r.total || 0)]));
      out.push({ key: "nat_bytes_hour", label: g.nat_gateway_id, value: (by.BytesInFromDestination || 0) + (by.BytesOutToDestination || 0), dims: { region: g.region, in: by.BytesInFromDestination || 0, out: by.BytesOutToDestination || 0 } });
    }
  });

  await attempt("savings_plans", "aws_savingsplans_savings_plan", async () => {
    const rows = await query<{ n: string }>(`select count(*) as n from ${S}.aws_savingsplans_savings_plan where state = 'active'`);
    out.push({ key: "savings_plans_active", label: "active", value: Number(rows[0]?.n || 0) });
  });

  await attempt("ebs", "aws_ebs_volume", async () => {
    const rows = await query<{ gb: string }>(`select coalesce(sum(size), 0) as gb from ${S}.aws_ebs_volume`);
    out.push({ key: "ebs_total_gb", label: "total", value: Number(rows[0]?.gb || 0) });
  });

  return { samples: out, instancesOk: !failed.has("instances") };
}

const gb = (b: number) => `${(b / 1e9).toFixed(2)} GB`;

/** Takes one sample, stores it, compares with earlier samples and raises alerts. */
export async function watchOnce(): Promise<WatchResult> {
  // Hard gate: with non-working credentials there is nothing to sample and nothing to compare.
  const gate = await credentialGate("watcher");
  if (!gate.ok) return { sample_id: 0, collected_at: new Date().toISOString(), samples: 0, alerts: 0, errors: [`skipped: ${gate.error}`] };
  const natAlerts: { id: number; nat: string; details: Record<string, unknown> }[] = [];
  const stateAlerts: number[] = [];
  const errors: string[] = [];
  const { samples, instancesOk } = await collect(errors);
  const prevId = (db.prepare("select max(sample_id) as id from watch_samples").get() as { id: number | null }).id;
  // States are compared with the last sample that actually had them, and not at all when the instance query
  // failed this time: an expired credential must not make the whole fleet "gone" and then "new" again.
  const prevStateId = (db.prepare("select max(sample_id) as id from watch_samples where key = 'instance_state'").get() as { id: number | null }).id;
  const sampleId = (prevId ?? 0) + 1;
  const collectedAt = new Date().toISOString();
  let alerts = 0;

  db.transaction(() => {
    for (const s of samples) insertSample.run(sampleId, collectedAt, s.key, s.label, s.value, s.dims ? JSON.stringify(s.dims) : null);
    if (prevId == null) return;

    // Instance state changes against the previous sample that had instance states.
    type Row = { label: string; value: number; dims: string | null };
    const prevStates = new Map(instancesOk && prevStateId != null ? (db.prepare("select label, value, dims from watch_samples where sample_id = ? and key = 'instance_state'").all(prevStateId) as Row[]).map((r) => [r.label, r]) : []);
    const curStates = samples.filter((s) => s.key === "instance_state");
    const seen = new Set<string>();
    const stateOf = (r: Row | undefined) => { try { return r?.dims ? String(JSON.parse(r.dims).state) : undefined; } catch { return undefined; } };
    type ChurnEvent = { instance_id: string; type: string | null; from: string | null; to: string | null; at: string };
    const churn = new Map<string, ChurnEvent[]>();
    const poolOf = (dims: any): string | null => (dims?.pool ? `${dims.cluster ? `${dims.cluster}/` : ""}${dims.pool}` : null);
    const record = (pool: string, ev: ChurnEvent) => churn.set(pool, [...(churn.get(pool) || []), ev]);
    const nowIso = new Date().toISOString();
    for (const s of curStates) {
      seen.add(s.label);
      const prev = prevStates.get(s.label);
      const before = stateOf(prev);
      const now = String(s.dims?.state);
      const name = s.dims?.name ? `${s.dims.name} (${s.label})` : s.label;
      const pool = poolOf(s.dims);
      if (!prev) {
        if (pool) { record(pool, { instance_id: s.label, type: (s.dims?.type as string | undefined) ?? null, from: null, to: now, at: nowIso }); continue; }
        stateAlerts.push(Number(insertAlert.run("instance_state", s.label, `New instance ${name}, ${s.dims?.type}, is ${now}`, JSON.stringify({ ...s.dims, from: null, to: now })).lastInsertRowid));
        alerts++;
      } else if (before !== now) {
        if (pool) { record(pool, { instance_id: s.label, type: (s.dims?.type as string | undefined) ?? null, from: before ?? null, to: now, at: nowIso }); continue; }
        stateAlerts.push(Number(insertAlert.run("instance_state", s.label, `${name} went from ${before} to ${now}`, JSON.stringify({ ...s.dims, from: before, to: now })).lastInsertRowid));
        alerts++;
      }
    }
    for (const [id, prev] of prevStates) {
      if (seen.has(id)) continue;
      const d = prev.dims ? JSON.parse(prev.dims) : {};
      const pool = poolOf(d);
      if (pool) { record(pool, { instance_id: id, type: d.type ?? null, from: d.state ?? null, to: null, at: nowIso }); continue; }
      stateAlerts.push(Number(insertAlert.run("instance_state", id, `${d.name ? `${d.name} (${id})` : id} is gone (was ${d.state})`, JSON.stringify({ ...d, from: d.state, to: null })).lastInsertRowid));
      alerts++;
    }

    // Autoscaled nodes: one `node_churn` alert per pool per day, updated in place with the day's events.
    const openChurn = db.prepare("select id, details from alerts where kind = 'node_churn' and resource = ? and date(created_at) = date('now') limit 1");
    const updateChurn = db.prepare("update alerts set message = ?, details = ?, acknowledged = 0 where id = ?");
    for (const [pool, events] of churn) {
      const existing = openChurn.get(pool) as { id: number; details: string | null } | undefined;
      const prevEvents: ChurnEvent[] = existing?.details ? (JSON.parse(existing.details).events || []) : [];
      const all = [...prevEvents, ...events];
      const launched = all.filter((e) => e.from === null).length;
      const gone = all.filter((e) => e.to === null || e.to === "terminated").length;
      const message = `Node pool ${pool}: ${launched} launched, ${gone} terminated today (${all.length} events, expected autoscaling churn)`;
      const details = JSON.stringify({ pool, events: all.slice(-200), launched, terminated: gone });
      if (existing) updateChurn.run(message, details, existing.id);
      else { insertAlert.run("node_churn", pool, message, details); alerts++; }
    }

    // NAT traffic: above 2x the average of the previous 6 samples and above 5 GB/hour.
    const baseline = db.prepare(`
      select avg(value) as avg, count(*) as n from watch_samples
      where key = 'nat_bytes_hour' and label = ? and sample_id < ? and sample_id >= ?`);
    const openAlert = db.prepare("select id from alerts where kind = 'nat_traffic' and resource = ? and acknowledged = 0 limit 1");
    for (const s of samples.filter((x) => x.key === "nat_bytes_hour")) {
      // the seasonal baseline (14 days of CloudWatch hours, median per hour of day) when it exists; the recent
      // 6-sample average otherwise
      const season = getBaseline("nat", s.label, "bytes_hour");
      if (season && season.days >= MIN_DAYS_FOR_SEASONAL && !openAlert.get(s.label)) {
        const sc = scoreValue(season, s.value, new Date());
        if (sc.level === "extreme" && s.value > NAT_SPIKE_BYTES_PER_HOUR) {
          const details = { ...s.dims, bytes_hour: s.value, baseline: { expected: sc.expected, basis: sc.basis, ratio: sc.ratio, z: sc.z, median: season.median, p95: season.p95, window_days: season.window_days, days: season.days } };
          const r = insertAlert.run("nat_traffic", s.label, `NAT gateway ${s.label} moved ${gb(s.value)} in the last hour, ${sc.ratio?.toFixed(1)}x its typical ${gb(sc.expected)} for this hour (p95 ${gb(season.p95)} over ${season.days} days)`, JSON.stringify(details));
          natAlerts.push({ id: Number(r.lastInsertRowid), nat: s.label, details });
          alerts++;
        }
        continue;
      }
      const b = baseline.get(s.label, sampleId, sampleId - NAT_BASELINE_SAMPLES) as { avg: number | null; n: number };
      if (!b.n || b.avg == null) continue;
      if (s.value > NAT_SPIKE_FACTOR * b.avg && s.value > NAT_SPIKE_BYTES_PER_HOUR && !openAlert.get(s.label)) {
        const details = { ...s.dims, bytes_hour: s.value, baseline_avg: b.avg, baseline_samples: b.n };
        const r = insertAlert.run("nat_traffic", s.label, `NAT gateway ${s.label} moved ${gb(s.value)} in the last hour, ${(s.value / b.avg).toFixed(1)}x its recent average of ${gb(b.avg)}`,
          JSON.stringify(details));
        natAlerts.push({ id: Number(r.lastInsertRowid), nat: s.label, details });
        alerts++;
      }
    }
  })();

  // Attribute fresh NAT alerts to the instances behind the gateway (async, so outside the transaction).
  const alertedVpcs = new Set<string>();
  for (const a of natAlerts) {
    try {
      const att = await attributeNatTraffic(a.nat);
      if (att.vpc_id) alertedVpcs.add(att.vpc_id);
      if (att.receivers.length) {
        const summary = att.receivers.map((r) => `${r.name || r.instance_id} ${gb(r.bytes_in)} in`).join(", ");
        db.prepare("update alerts set message = message || ?, details = ? where id = ?")
          .run(`. Top receivers this hour: ${summary}`, JSON.stringify({ ...a.details, vpc_id: att.vpc_id, top_receivers: att.receivers }), a.id);
      }
    } catch (e: any) {
      errors.push(`nat attribution ${a.nat}: ${describeError(e, `nat attribution ${a.nat} (aws_vpc_nat_gateway, aws_ec2_instance, aws_cloudwatch_metric_statistic_data_point)`)}`);
    }
  }
  // Deterministic follow-up: a VPC that alerts and has no flow logs gets an enable_flow_logs recommendation.
  if (natAlerts.length) {
    try { await refreshFlowLogRecommendations(alertedVpcs.size ? [...alertedVpcs] : undefined); }
    catch (e: any) { errors.push(`flow logs: ${e?.message || e}`); }
  }
  // Jev triage (no-op without TYPESAFE_API_KEY): routine alerts are acknowledged, unexpected ones are marked for the agent.
  let triaged = new Map<number, { decision: string }>();
  try { triaged = await triageAlerts([...natAlerts.map((a) => a.id), ...stateAlerts]); }
  catch (e: any) { errors.push(`triage: ${String(e?.message || e).slice(0, 200)}`); }
  const autoAcked = [...triaged.values()].filter((t) => t.decision === "acknowledge").length;
  if (triaged.size) console.log(`[jev] triaged ${triaged.size} alert(s): ${autoAcked} auto-acknowledged, ${[...triaged.values()].filter((t) => t.decision === "investigate").length} eligible for investigation`);
  // Then the agent (ALERT_INVESTIGATE=auto): fire-and-forget, the webhook completes the incident. A triaged alert
  // goes to the agent only when Jev found it unexpected or severe; without a triage the existing policy applies.
  for (const a of natAlerts) {
    const t = triaged.get(a.id);
    if (!shouldAutoInvestigate("nat_traffic")) console.log(`[watcher] alert #${a.id} not investigated: ${config.repo2graphUrl ? 'ALERT_INVESTIGATE is not "auto"' : "no repo2graph URL"} (Settings > Agent)`);
    else if (t && t.decision !== "investigate") console.log(`[watcher] alert #${a.id} not investigated: Jev triaged it as ${t.decision}`);
    else { console.log(`[watcher] alert #${a.id} sent to the agent for investigation${t ? " (Jev: unexpected)" : ""}`); investigateAlertInBackground(a.id); }
  }
  // New or auto-acknowledged alerts go to the Neo4j mirror (src/graph_mirror.ts); fire-and-forget.
  if (alerts > 0 || triaged.size > 0) mirrorAlertsInBackground();

  // The inventory rides along with every sample: the same cheap live queries, and the SSM status stays fresh.
  try {
    const inv = await refreshInventory();
    errors.push(...inv.errors.map((e) => `inventory ${e}`));
    mirrorResourcesInBackground();
  } catch (e: any) {
    errors.push(`inventory: ${describeError(e, "inventory refresh", 300)}`);
  }

  return { sample_id: sampleId, collected_at: collectedAt, samples: samples.length, alerts, errors };
}

export function latestWatchSummary() {
  const last = db.prepare("select sample_id, collected_at from watch_samples order by sample_id desc limit 1").get() as { sample_id: number; collected_at: string } | undefined;
  if (!last) return null;
  const rows = db.prepare("select key, label, value, dims from watch_samples where sample_id = ? and key <> 'instance_state' order by key, value desc").all(last.sample_id) as { key: string; label: string; value: number; dims: string | null }[];
  return { sample_id: last.sample_id, collected_at: last.collected_at, metrics: rows };
}


export interface NatReceiver { instance_id: string; name: string | null; private_ip: string | null; bytes_in: number; bytes_out: number }

/**
 * Who is behind a NAT spike: NetworkIn/NetworkOut of every running instance in the gateway's VPC over the
 * last hour, largest first. Instance NetworkIn also counts intra-VPC traffic, so it is an upper bound per
 * instance, but the ranking is what matters. Pod-level attribution needs VPC flow logs or the cluster API.
 */
export async function attributeNatTraffic(natGatewayId: string, hours = 1, limit = 5): Promise<{ vpc_id: string | null; receivers: NatReceiver[] }> {
  const gw = (await query<{ vpc_id: string; region: string }>(
    `select vpc_id, region from ${S}.aws_vpc_nat_gateway where nat_gateway_id = $1`, [natGatewayId]))[0];
  if (!gw) return { vpc_id: null, receivers: [] };
  const instances = await query<{ instance_id: string; name: string | null; private_ip: string | null }>(
    `select instance_id, tags ->> 'Name' as name, private_ip_address as private_ip from ${S}.aws_ec2_instance
     where vpc_id = $1 and instance_state = 'running' limit 40`, [gw.vpc_id]);
  const receivers: NatReceiver[] = [];
  const region = gw.region.replace(/'/g, "''");
  await Promise.all(instances.map(async (i) => {
    const dims = JSON.stringify([{ Name: "InstanceId", Value: i.instance_id }]).replace(/'/g, "''");
    const rows = await query<{ metric_name: string; total: string | null }>(`
      select metric_name, sum(sum) as total from ${S}.aws_cloudwatch_metric_statistic_data_point
      where namespace = 'AWS/EC2' and metric_name in ('NetworkIn', 'NetworkOut') and dimensions = '${dims}'
        and timestamp between now() - interval '${Math.max(1, Math.min(24, Math.floor(hours)))} hours' and now()
        and period = 300 and region = '${region}' group by 1`).catch(() => []);
    const by = Object.fromEntries(rows.map((r) => [r.metric_name, Number(r.total || 0)]));
    receivers.push({ instance_id: i.instance_id, name: i.name, private_ip: i.private_ip, bytes_in: by.NetworkIn || 0, bytes_out: by.NetworkOut || 0 });
  }));
  receivers.sort((a, b) => (b.bytes_in + b.bytes_out) - (a.bytes_in + a.bytes_out));
  return { vpc_id: gw.vpc_id, receivers: receivers.filter((r) => r.bytes_in + r.bytes_out > 1e8).slice(0, limit) };
}

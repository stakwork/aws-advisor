import { choice, noul, score } from "@typesafe-ai/sdk";
import { credentialGate } from "./gate.js";
import { db } from "./db.js";
import { S, query } from "./steampipe.js";
import { askJev, jevEnabled, mapLimit } from "./jev.js";

/**
 * Alert triage with Jev (purpose alert_triage). Right after the watcher creates a nat_traffic or
 * instance_state alert, and before the auto-investigation decision, the alert is described as structured
 * facts (the alert, the instances behind it from the inventory, the last 24 h of watcher samples summarised,
 * the resource's history, the VPC's endpoints) and Jev answers three atomic questions: is this expected, what
 * kind of episode is it, how severe. The answers are stored on the alert (`triage`, `triage_at`) and drive one
 * policy, `triageDecision`: a clearly routine, low-severity alert is acknowledged automatically (by "jev",
 * reversible from the UI), a clearly unexpected or costly one is eligible for the agent, anything in between
 * stays open for a human. node_churn alerts are already known-expected and are not triaged.
 */

export const TRIAGE_KINDS = {
  cold_start_pulls: "new nodes downloading container images or packages after a launch or a deploy",
  backup_or_sync: "scheduled data movement: backups, snapshots, replication, log shipping, a nightly sync",
  runaway_workload: "a job, pod or process consuming far more than usual",
  external_abuse: "a traffic pattern that suggests scanning, scraping or abuse from outside",
  capacity_change: "the fleet scaled up or down, or an instance was started, stopped or replaced, as designed",
  unknown: "the facts do not say",
} as const;
export type TriageKind = keyof typeof TRIAGE_KINDS;

export const SEVERITY_LEVELS = ["Noise", "Worth a look this week", "Should be looked at today", "Costing real money right now"] as const;
export const severityLabel = (s: number) => SEVERITY_LEVELS[Math.max(0, Math.min(SEVERITY_LEVELS.length - 1, Math.round(s)))];

/** Thresholds of the policy below. */
export const TRIAGE_ACK_EXPECTED = 0.85;
export const TRIAGE_ACK_MAX_SEVERITY = 1;
export const TRIAGE_INVESTIGATE_EXPECTED = 0.4;
export const TRIAGE_INVESTIGATE_SEVERITY = 2;

export type TriageDecision = "acknowledge" | "investigate" | "open";

export interface Triage {
  expected: number;
  kind: TriageKind;
  kind_confidence: number;
  kind_probabilities: Record<string, number>;
  severity: number;
  severity_label: string;
  severity_confidence: number;
  decision: TriageDecision;
  model: string;
  latency_ms: number;
  call_id: number;
}

/**
 * The policy. expected >= 0.85 and severity <= 1: routine and harmless, acknowledge. expected <= 0.4 or
 * severity >= 2: eligible for the agent (ALERT_INVESTIGATE still decides). Otherwise: leave open for a human.
 */
export function triageDecision(t: { expected: number; severity: number }): TriageDecision {
  if (t.expected >= TRIAGE_ACK_EXPECTED && t.severity <= TRIAGE_ACK_MAX_SEVERITY) return "acknowledge";
  if (t.expected <= TRIAGE_INVESTIGATE_EXPECTED || t.severity >= TRIAGE_INVESTIGATE_SEVERITY) return "investigate";
  return "open";
}

/** What is appended to an auto-acknowledged alert's message (and stripped again by reopenAlert). */
export const autoAckSuffix = (t: Pick<Triage, "kind" | "expected">) => ` Auto-acknowledged: ${t.kind} (${t.expected.toFixed(2)})`;
const AUTO_ACK_RE = / Auto-acknowledged: [a-z_]+ \(\d\.\d\d\)$/;

export const triageQuestions = () => ({
  expected: noul("This episode is expected, routine behaviour for this environment (autoscaling, scheduled jobs, known baselines) rather than waste or an anomaly worth a human's time"),
  kind: choice("What kind of episode is this alert most likely describing?", TRIAGE_KINDS),
  severity: score("How urgently should a human look at this alert?", SEVERITY_LEVELS),
});

// ---- state ---------------------------------------------------------------------------------------------

const safeJson = (s: unknown) => { if (typeof s !== "string") return s ?? null; try { return JSON.parse(s); } catch { return null; } };
const gb = (b: unknown) => Math.round((Number(b || 0) / 1e9) * 100) / 100;
const ageDays = (iso: string | null | undefined) => (iso ? Math.round((Date.now() - new Date(iso).getTime()) / 86400000) : null);
const hourOf = (iso: string) => new Date(iso).getUTCHours();

const HOW_ALERTS_ARE_RAISED = "A watcher samples the account every 30 minutes. nat_traffic: a NAT gateway moved more than 2x the average of its previous 6 samples and more than 5 GB in the last hour. instance_state: an instance changed state, appeared or disappeared since the previous sample; members of autoscaling pools (Karpenter, EKS node groups, ASGs) never alert individually.";

interface AlertRowLite { id: number; created_at: string; kind: string; resource: string | null; message: string; details: string | null }

/** The inventory's view of an instance, reduced to what a triage needs. */
function instanceFacts(id: string) {
  const r = db.prepare("select instance_id, name, instance_type, state, launch_time, platform, cpu_30d, monthly_usd, ssm_status, gone, snapshot from inventory_ec2 where instance_id = ?").get(id) as any;
  if (!r) return null;
  const snap = safeJson(r.snapshot) || {};
  const tags: Record<string, string> = snap.tags || {};
  const pool = tags["karpenter.sh/nodepool"] || tags["eks:nodegroup-name"] || tags["aws:autoscaling:groupName"] || null;
  const userTags = Object.fromEntries(Object.entries(tags).filter(([k]) => !/^aws:/.test(k)).slice(0, 15));
  return {
    instance_id: r.instance_id, name: r.name, type: r.instance_type, state: r.state, platform: r.platform,
    launched: r.launch_time, age_days: ageDays(r.launch_time),
    pool, cluster: tags["eks:cluster-name"] || tags["elasticbeanstalk:environment-name"] || null,
    list_price_usd_month: r.monthly_usd, cpu_30d_avg_daily_max_pct: r.cpu_30d, ssm: r.ssm_status,
    tags: userTags, vpc_id: snap.network?.vpc_id ?? null,
  };
}

function sampleSummary(alert: AlertRowLite) {
  if (!alert.resource) return null;
  const key = alert.kind === "nat_traffic" ? "nat_bytes_hour" : alert.kind === "instance_state" ? "instance_state" : null;
  if (!key) return null;
  const since = new Date(Date.now() - 24 * 3600_000).toISOString(); // watch_samples.collected_at is ISO too, so the compare is exact
  // One row per sample: a gateway listed twice by Steampipe is stored twice, the summary must not count it twice.
  const rows = db.prepare("select collected_at, value, dims from watch_samples where key = ? and label = ? and collected_at > ? group by sample_id order by sample_id")
    .all(key, alert.resource, since) as { collected_at: string; value: number; dims: string | null }[];
  if (!rows.length) return { samples_24h: 0 };
  if (key === "instance_state") {
    const states = rows.map((r) => ({ hour_utc: hourOf(r.collected_at), state: safeJson(r.dims)?.state ?? r.value }));
    return { samples_24h: rows.length, distinct_states: [...new Set(states.map((s) => String(s.state)))], last_6: states.slice(-6) };
  }
  const values = rows.map((r) => Number(r.value || 0));
  return {
    samples_24h: rows.length, unit: "GB per hour (bytes in + out through the gateway)",
    min: gb(Math.min(...values)), avg: gb(values.reduce((s, v) => s + v, 0) / values.length), max: gb(Math.max(...values)), last: gb(values[values.length - 1]),
    last_6: rows.slice(-6).map((r) => ({ hour_utc: hourOf(r.collected_at), gb: gb(r.value) })),
  };
}

function history(alert: AlertRowLite) {
  if (!alert.resource) return { previous_alerts_same_resource: 0, incidents_same_resource: 0 };
  const prev = db.prepare("select count(*) as n from alerts where resource = ? and id <> ?").get(alert.resource, alert.id) as { n: number };
  const inc = db.prepare("select count(*) as n from incidents i join alerts a on a.id = i.alert_id where a.resource = ?").get(alert.resource) as { n: number };
  const last = db.prepare("select i.cause, i.confidence from incidents i join alerts a on a.id = i.alert_id where a.resource = ? and i.status = 'completed' order by i.id desc limit 1").get(alert.resource) as { cause: string; confidence: number | null } | undefined;
  return { previous_alerts_same_resource: prev.n, incidents_same_resource: inc.n, ...(last ? { last_incident_cause: last.cause, last_incident_confidence: last.confidence } : {}) };
}

/** VPC endpoints from Steampipe, bounded so an expired credential cannot stall the watcher. */
async function vpcEndpoints(vpcId: string | null): Promise<unknown> {
  if (!vpcId) return "unknown (no VPC on record)";
  try {
    const rows = await Promise.race([
      query<{ service_name: string; vpc_endpoint_type: string }>(`select service_name, vpc_endpoint_type from ${S}.aws_vpc_endpoint where vpc_id = $1 and state = 'available'`, [vpcId]),
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("timeout")), 8000)),
    ]);
    return rows.length ? rows.map((r) => `${r.service_name.replace(/^com\.amazonaws\.[a-z0-9-]+\./, "")} (${r.vpc_endpoint_type})`) : "none: S3, ECR, DynamoDB etc. all go through the NAT gateway";
  } catch (e: any) {
    return `unknown (lookup failed: ${String(e?.message || e).slice(0, 80)})`;
  }
}

/** The structured facts Jev judges. Numbers are summarised, never raw series; nothing here is a judgment. */
export async function buildTriageState(alert: AlertRowLite) {
  const details = (safeJson(alert.details) || {}) as Record<string, any>;
  const { top_receivers, ...rest } = details;
  const state: Record<string, unknown> = {
    how_alerts_are_raised: HOW_ALERTS_ARE_RAISED,
    alert: { id: alert.id, kind: alert.kind, resource: alert.resource, raised_at_utc: alert.created_at, hour_utc: hourOf(alert.created_at.replace(" ", "T") + (alert.created_at.endsWith("Z") ? "" : "Z")), message: alert.message },
  };
  let vpcId: string | null = details.vpc_id ?? null;
  if (alert.kind === "nat_traffic") {
    state.nat = { region: rest.region, gb_last_hour: gb(rest.bytes_hour), gb_in: gb(rest.in), gb_out: gb(rest.out), baseline_avg_gb: gb(rest.baseline_avg), baseline_samples: rest.baseline_samples, ratio_to_baseline: rest.baseline_avg ? Math.round((Number(rest.bytes_hour) / Number(rest.baseline_avg)) * 10) / 10 : null, cost_of_excess_usd: rest.bytes_hour && rest.baseline_avg ? Math.round((Math.max(0, Number(rest.bytes_hour) - Number(rest.baseline_avg)) / 1e9) * 0.045 * 100) / 100 : null };
    const receivers: any[] = Array.isArray(top_receivers) ? top_receivers : [];
    state.top_receivers = receivers.length
      ? receivers.map((r) => ({ ...(instanceFacts(r.instance_id) || { instance_id: r.instance_id, name: r.name ?? null }), gb_in: gb(r.bytes_in), gb_out: gb(r.bytes_out) }))
      : "none attributed (no instance above 100 MB in the hour, or attribution failed)";
    const samePool = receivers.length > 1 && new Set(receivers.map((r) => (instanceFacts(r.instance_id)?.pool ?? r.name ?? r.instance_id))).size === 1;
    if (samePool) state.receivers_note = "all top receivers belong to the same pool or environment";
  }
  if (alert.kind === "instance_state") {
    const facts = alert.resource ? instanceFacts(alert.resource) : null;
    state.instance = { ...(facts || { instance_id: alert.resource, name: rest.name ?? null, type: rest.type ?? null, region: rest.region ?? null, pool: rest.pool ?? null, cluster: rest.cluster ?? null }), change: { from: rest.from ?? "did not exist", to: rest.to ?? "gone" } };
    vpcId = vpcId || facts?.vpc_id || null;
  }
  state.watch_samples = sampleSummary(alert);
  state.history = history(alert);
  if (alert.kind === "nat_traffic") state.vpc_endpoints = await vpcEndpoints(vpcId);
  return state;
}

// ---- run ----------------------------------------------------------------------------------------------

/**
 * Triages one alert: builds the state, asks Jev, stores the triage on the alert and applies the policy
 * (an "acknowledge" is carried out here; "investigate" is only reported, the caller decides). Returns null
 * when Jev is disabled, the call failed or the alert is not a triaged kind, in which case nothing changes.
 */
export async function triageAlert(alertId: number): Promise<Triage | null> {
  if (!(await credentialGate("triage")).ok) return null;
  if (!jevEnabled()) return null;
  const alert = db.prepare("select id, created_at, kind, resource, message, details from alerts where id = ?").get(alertId) as AlertRowLite | undefined;
  if (!alert || !["nat_traffic", "instance_state"].includes(alert.kind)) return null;
  const state = await buildTriageState(alert);
  const res = await askJev(state, triageQuestions(), { purpose: "alert_triage" });
  if (!res) return null;
  const a = res.answers;
  const triage: Triage = {
    expected: a.expected.noul,
    kind: a.kind.choice,
    kind_confidence: a.kind.confidence,
    kind_probabilities: a.kind.probabilities,
    severity: a.severity.score,
    severity_label: severityLabel(a.severity.score),
    severity_confidence: a.severity.confidence,
    decision: triageDecision({ expected: a.expected.noul, severity: a.severity.score }),
    model: res.model,
    latency_ms: res.latency_ms,
    call_id: res.call_id,
  };
  db.transaction(() => {
    db.prepare("update alerts set triage = ?, triage_at = datetime('now') where id = ?").run(JSON.stringify(triage), alertId);
    if (triage.decision === "acknowledge") {
      db.prepare("update alerts set acknowledged = 1, acknowledged_by = 'jev', message = message || ? where id = ? and acknowledged = 0").run(autoAckSuffix(triage), alertId);
    }
  })();
  console.log(`[jev] alert ${alertId} (${alert.kind}): ${triage.kind} expected=${triage.expected.toFixed(2)} severity=${triage.severity.toFixed(2)} -> ${triage.decision} (${res.latency_ms} ms, ${res.usage.input_tokens}+${res.usage.output_tokens} tokens)`);
  return triage;
}

/** Triages a batch of fresh alerts, a few at a time. Missing entries mean Jev had no say (disabled or failed). */
export async function triageAlerts(alertIds: number[]): Promise<Map<number, Triage>> {
  if (!(await credentialGate("triage")).ok) return new Map();
  const out = new Map<number, Triage>();
  if (!jevEnabled() || !alertIds.length) return out;
  const results = await mapLimit(alertIds, 4, (id) => triageAlert(id).catch((e: any) => { console.error(`[jev] triage of alert ${id} failed: ${e?.message || e}`); return null; }));
  results.forEach((t, i) => { if (t) out.set(alertIds[i], t); });
  return out;
}

/** Undo of an acknowledgement (Jev's or a person's): the alert is open again and the auto-ack note is removed. */
export function reopenAlert(alertId: number): boolean {
  const row = db.prepare("select message from alerts where id = ?").get(alertId) as { message: string } | undefined;
  if (!row) return false;
  db.prepare("update alerts set acknowledged = 0, acknowledged_by = null, message = ? where id = ?").run(row.message.replace(AUTO_ACK_RE, ""), alertId);
  return true;
}

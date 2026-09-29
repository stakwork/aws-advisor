/**
 * Usage profiles: when a box is used, hour by hour of the week, from every signal the advisor already collects.
 *
 * A stop is only safe at an hour nobody uses the box, and "nobody" has to hold for every week we have seen. So
 * the profile folds the last `WINDOW_DAYS` (28) into the 168 hours of a week and asks, for each hour and each
 * week, whether anything happened:
 *
 *  - CloudWatch, every hour the instance ran: the maximum CPU of the hour under `QUIET_CPU_MAX` and the bytes in
 *    and out under `QUIET_NET_BYTES`;
 *  - the probes that fell in that hour (`instance_activity`, `container_samples`): no established external
 *    connection, no use-signal line, no front-door request and no login in the last hour, nobody logged in, no
 *    container above `QUIET_CONTAINER_CPU` % (the probe's use signals already pass the per-image noise rules, so
 *    a heartbeat log does not count as use; whether *any* log line was written is kept as `logs`, informational);
 *  - for an autoscaling group (subject `asg:<name>`): the group's CPU and, when a balancer fronts it, the requests
 *    that hour;
 *  - the CloudWatch log groups the box ships to (probe 1.6 `log_shipping`): one Logs Insights query per box over
 *    the last `USAGE_LOG_DAYS` (7) counting the use-signal lines per hour, the same patterns the probe uses on
 *    container logs, with the kinds ruled noise for the shipping container's image left out. This is log
 *    evidence for every hour of that week, not only the hours a probe happened to run in.
 *
 * An hour of the week is **quiet** when every week we saw it was quiet (at least `MIN_WEEKS` of them), **busy**
 * when any week was, **unknown** otherwise (too few weeks, or the box was off). Quiet hours in a row make a
 * window; a window keeps `MARGIN_HOURS` on each side (people work late, boxes take a minute to come back), so a
 * four-hour run is a two-hour stop. A window's confidence is the weeks behind it and how much of it the probes
 * covered: CloudWatch alone says "not busy", the probes (or, for a group, its balancer's request count) say "not
 * used", and only both together get close to 1.
 *
 * From the busy hours the profile derives the smallest `advisor:schedule` value that keeps the box up whenever it
 * was ever used (`suggested_schedule`, UTC, one window a day over the days that have any use; a day with none is
 * off). With the confidence at `CONFIDENT` or above and enough hours off, a `usage_schedule` recommendation is
 * filed (tier approve): approving it makes the executor put the tag on the instance (src/actions/usage_schedule.ts)
 * and the office-hours action does the stopping and starting, re-attaching the public IP to its DNS records on
 * start. Nothing here writes to AWS.
 */
import { CloudWatchClient, GetMetricDataCommand, type MetricDataQuery } from "@aws-sdk/client-cloudwatch";
import { CloudWatchLogsClient, GetQueryResultsCommand, StartQueryCommand, StopQueryCommand } from "@aws-sdk/client-cloudwatch-logs";
import { config } from "./config.js";
import { parseSignals } from "./signals.js";
import { rulesFor } from "./signal_rules.js";
import { latestProbe } from "./ssm.js";
import { db } from "./db.js";
import { upsertRecommendations } from "./collector.js";
import type { RecInput } from "./rules.js";
import { executorCreds, type Creds } from "./executor.js";
import { metricDimension } from "./elb_inventory.js";
import { HOURS_PER_WEEK, describeSchedule, offHoursPerWeek, parseSchedule, type Schedule } from "./actions/schedule_hours.js";

db.exec(`create table if not exists usage_log_signals (subject text not null, hour integer not null, count integer not null, primary key (subject, hour))`);
db.exec(`create table if not exists usage_profiles (
  subject text primary key, kind text not null, name text, region text, account_id text, computed_at text not null, window_days integer not null,
  signals text not null, hours text not null, quiet_windows text not null, busiest text not null,
  quiet_hours_week integer not null, confidence real not null, suggested_schedule text, off_hours_week integer, est_usd_month real, summary text not null
)`);

export const WINDOW_DAYS = 28;
export const MIN_WEEKS = 3;
export const MIN_WINDOW_HOURS = 4;
export const MARGIN_HOURS = 1;
/** The hour's maximum CPU (percent) under which CloudWatch calls the hour idle. */
export const QUIET_CPU_MAX = 10;
/** Bytes in plus out per hour under which the network is noise (health checks, agents, DNS). */
export const QUIET_NET_BYTES = 5e6;
export const QUIET_CONTAINER_CPU = 5;
/** The confidence a window needs before a schedule is recommended. */
export const CONFIDENT = 0.85;
export const MIN_OFF_HOURS_WEEK = 20;
export const RULE = "usage_schedule";
export const ACTION_TYPE = "set_schedule_tag";
const H = 3600000;
const DAY_NAMES = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];
const DAY_LABEL = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

export interface ProbeMark { ext_conn: number; users_now: number; signals_recent: boolean; request_recent: boolean; login_recent: boolean; logs_recent: boolean; container_busy: boolean }
export interface HourSample { at: number; cpu_avg: number | null; cpu_max: number | null; net_bytes: number | null; requests: number | null; probes: ProbeMark[]; /** use-signal lines in the box's CloudWatch log groups that hour (Logs Insights); null = no log evidence for the hour */ log_signals?: number | null }
export interface HourBucket { day: number; hour: number; seen: number; quiet: number; verdict: "quiet" | "busy" | "unknown"; cpu_avg: number | null; cpu_max: number | null; net_mb: number | null; requests: number | null; probes: number; /** samples with use evidence beyond CloudWatch: a probe, or a balancer request count */ covered: number; /** how many busy samples each signal tripped */ busy_cpu: number; busy_net: number; busy_requests: number; busy_probe: number; /** busy samples the shipped logs tripped */ busy_logs: number; /** use-signal lines per hour in the shipped logs, averaged over the hours with log evidence */ log_signals: number | null; /** the probe signal by kind: external connections, users on the box, use-signal lines, front-door requests, logins, busy containers */ busy_probe_kinds: { ext_conn: number; users: number; signals: number; requests: number; logins: number; containers: number }; ext_conn: number; signals: number; requests_seen: number; logins: number; logs: number; busy_containers: number }
export interface QuietWindow { start: number; end: number; hours: number; effective_start: number; effective_end: number; effective_hours: number; confidence: number; probe_coverage: number; label: string }
export interface Profile {
  subject: string; kind: "ec2" | "asg"; name: string | null; region: string | null; account_id: string | null; computed_at: string; window_days: number;
  signals: { cloudwatch_hours: number; probes: number; requests: boolean; log_hours: number };
  hours: HourBucket[]; quiet_windows: QuietWindow[]; busiest: { day: number; hour: number; cpu_avg: number; net_mb: number | null; label: string }[];
  quiet_hours_week: number; confidence: number; suggested_schedule: string | null; off_hours_week: number | null; est_usd_month: number | null; summary: string;
}

const hh = (h: number) => `${String(h % 24).padStart(2, "0")}:00`;
const r1 = (v: number) => Math.round(v * 10) / 10;
const mean = (xs: number[]) => (xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : null);
/** Index of an hour in the week ring (0 = Sunday 00:00 UTC). */
export const ringIndex = (at: number) => { const d = new Date(at); return d.getUTCDay() * 24 + d.getUTCHours(); };
export const ringLabel = (i: number) => `${DAY_LABEL[Math.floor(((i % 168) + 168) % 168 / 24)]} ${hh(i % 24)}`;

/** Whether one hour's sample was quiet on every signal it carries. Pure. */
export function sampleQuiet(s: HourSample): boolean {
  if (s.cpu_max == null || s.cpu_max >= QUIET_CPU_MAX) return false;
  if (s.net_bytes != null && s.net_bytes >= QUIET_NET_BYTES) return false;
  if (s.requests != null && s.requests > 0) return false;
  if ((s.log_signals ?? 0) > 0) return false;
  return s.probes.every((p) => !p.ext_conn && !p.users_now && !p.signals_recent && !p.request_recent && !p.login_recent && !p.container_busy);
}

/** Which signals made a sample busy. Pure. */
export function busyReasons(s: HourSample): { cpu: boolean; net: boolean; requests: boolean; probe: boolean; logs: boolean } {
  return {
    logs: (s.log_signals ?? 0) > 0,
    cpu: s.cpu_max != null && s.cpu_max >= QUIET_CPU_MAX,
    net: s.net_bytes != null && s.net_bytes >= QUIET_NET_BYTES,
    requests: s.requests != null && s.requests > 0,
    probe: s.probes.some((p) => p.ext_conn > 0 || p.users_now > 0 || p.signals_recent || p.request_recent || p.login_recent || p.container_busy),
  };
}

/** The 168 buckets from the window's samples. Pure. */
export function bucketize(samples: HourSample[]): HourBucket[] {
  const out: HourBucket[] = Array.from({ length: HOURS_PER_WEEK }, (_, i) => ({ day: Math.floor(i / 24), hour: i % 24, seen: 0, quiet: 0, verdict: "unknown", cpu_avg: null, cpu_max: null, net_mb: null, requests: null, probes: 0, covered: 0, busy_cpu: 0, busy_net: 0, busy_requests: 0, busy_probe: 0, busy_logs: 0, log_signals: null, busy_probe_kinds: { ext_conn: 0, users: 0, signals: 0, requests: 0, logins: 0, containers: 0 }, ext_conn: 0, signals: 0, requests_seen: 0, logins: 0, logs: 0, busy_containers: 0 }));
  const acc = new Map<number, { cpu: number[]; net: number[]; req: number[]; logs: number[] }>();
  for (const s of samples) {
    if (s.cpu_max == null) continue; // the box was off that hour, or CloudWatch has nothing: no evidence either way
    const i = ringIndex(s.at); const b = out[i];
    const a = acc.get(i) ?? { cpu: [], net: [], req: [], logs: [] }; acc.set(i, a);
    b.seen++;
    if (sampleQuiet(s)) b.quiet++;
    else {
      const w = busyReasons(s); if (w.cpu) b.busy_cpu++; if (w.net) b.busy_net++; if (w.requests) b.busy_requests++; if (w.probe) b.busy_probe++; if (w.logs) b.busy_logs++;
      const k = b.busy_probe_kinds;
      if (s.probes.some((p) => p.ext_conn > 0)) k.ext_conn++; if (s.probes.some((p) => p.users_now > 0)) k.users++; if (s.probes.some((p) => p.signals_recent)) k.signals++;
      if (s.probes.some((p) => p.request_recent)) k.requests++; if (s.probes.some((p) => p.login_recent)) k.logins++; if (s.probes.some((p) => p.container_busy)) k.containers++;
    }
    if (s.cpu_avg != null) a.cpu.push(s.cpu_avg);
    if (s.net_bytes != null) a.net.push(s.net_bytes);
    if (s.requests != null) a.req.push(s.requests);
    if (s.log_signals != null) a.logs.push(s.log_signals);
    b.cpu_max = Math.round(Math.max(b.cpu_max ?? 0, s.cpu_max) * 10) / 10;
    b.probes += s.probes.length;
    if (s.probes.length || s.requests != null || s.log_signals != null) b.covered++;
    for (const p of s.probes) { b.ext_conn = Math.max(b.ext_conn, p.ext_conn); if (p.signals_recent) b.signals++; if (p.request_recent) b.requests_seen++; if (p.login_recent || p.users_now) b.logins++; if (p.logs_recent) b.logs++; if (p.container_busy) b.busy_containers++; }
  }
  for (const [i, a] of acc) { const b = out[i]; b.cpu_avg = mean(a.cpu) == null ? null : r1(mean(a.cpu)!); b.net_mb = mean(a.net) == null ? null : Math.round((mean(a.net)! / 1e6) * 10) / 10; b.requests = mean(a.req) == null ? null : Math.round(mean(a.req)!); b.log_signals = mean(a.logs) == null ? null : Math.round(mean(a.logs)! * 10) / 10; }
  for (const b of out) b.verdict = b.seen < MIN_WEEKS ? "unknown" : b.quiet === b.seen ? "quiet" : "busy";
  return out;
}

/** Runs of quiet hours around the week ring, at least MIN_WINDOW_HOURS long, with the margins taken off. Pure. */
export function quietWindows(hours: HourBucket[], weeks: number): QuietWindow[] {
  const n = hours.length; const quiet = hours.map((b) => b.verdict === "quiet");
  if (quiet.every(Boolean)) return [{ start: 0, end: n, hours: n, effective_start: 0, effective_end: n, effective_hours: n, confidence: windowConfidence(hours, 0, n, weeks), probe_coverage: coverage(hours, 0, n), label: "all week" }];
  // start scanning at a non-quiet hour so a run over Sunday midnight is read whole
  const first = quiet.findIndex((q) => !q);
  const out: QuietWindow[] = [];
  let i = 0;
  while (i < n) {
    const idx = (first + i) % n;
    if (!quiet[idx]) { i++; continue; }
    let len = 0; while (len < n && quiet[(idx + len) % n]) len++;
    if (len >= MIN_WINDOW_HOURS) {
      const es = idx + MARGIN_HOURS, ee = idx + len - MARGIN_HOURS;
      out.push({ start: idx, end: idx + len, hours: len, effective_start: es % n, effective_end: ee % n, effective_hours: ee - es, confidence: windowConfidence(hours, idx, len, weeks), probe_coverage: coverage(hours, idx, len), label: `${ringLabel(es)} → ${ringLabel(ee)}` });
    }
    i += len;
  }
  return out.sort((a, b) => b.effective_hours - a.effective_hours);
}
/** The share of a window's hour-samples that carried use evidence beyond CloudWatch (probes, or the balancer's requests for a group). */
const coverage = (hours: HourBucket[], start: number, len: number) => { let with_ = 0, seen = 0; for (let k = 0; k < len; k++) { const b = hours[(start + k) % hours.length]; with_ += b.covered; seen += b.seen; } return seen ? with_ / seen : 0; };
/** Weeks seen (up to the window's weeks) and probe coverage: CloudWatch alone tops out at 0.6, full probe coverage reaches 1. */
function windowConfidence(hours: HourBucket[], start: number, len: number, weeks: number): number {
  let minSeen = Infinity; for (let k = 0; k < len; k++) minSeen = Math.min(minSeen, hours[(start + k) % hours.length].seen);
  const weeksFactor = Math.min(1, minSeen / Math.max(MIN_WEEKS, weeks));
  return Math.round(weeksFactor * (0.6 + 0.4 * coverage(hours, start, len)) * 100) / 100;
}

/**
 * The smallest office-hours schedule (UTC) that keeps the box running whenever it was ever busy or unknown: one
 * window a day, from the earliest use across the days with any to the latest, plus the margins; days without any
 * use are off. An hour the box was never on (no CloudWatch point in any week) is not use either: a box someone
 * already keeps off at weekends gets weekdays, not "unknown, keep it up". Null when the box is used around the
 * clock, or never (that is a parking case, not a schedule). Pure.
 */
export function suggestSchedule(hours: HourBucket[]): { text: string; schedule: Schedule } | null {
  const busyDays = new Set<number>(); let start = 24, end = 0;
  for (const b of hours) if (b.verdict !== "quiet" && b.seen > 0) { busyDays.add(b.day); start = Math.min(start, b.hour); end = Math.max(end, b.hour + 1); }
  if (!busyDays.size) return null;
  start = Math.max(0, start - MARGIN_HOURS); end = Math.min(24, end + MARGIN_HOURS);
  if (end - start >= 22) return null;
  const days = busyDays.size === 7 ? "daily" : [1, 2, 3, 4, 5].every((d) => busyDays.has(d)) && busyDays.size === 5 ? "weekdays" : [...busyDays].sort().map((d) => DAY_NAMES[d]).join(",");
  const text = `${days} ${String(start).padStart(2, "0")}-${String(end).padStart(2, "0")} UTC`;
  const s = parseSchedule(text);
  return "error" in s ? null : { text, schedule: s };
}

export interface BuildInput { subject: string; kind: "ec2" | "asg"; name?: string | null; region?: string | null; account_id?: string | null; samples: HourSample[]; monthly_usd?: number | null; now?: number }

/** The whole profile from the samples. Pure. */
export function buildProfile(i: BuildInput): Profile {
  const hours = bucketize(i.samples);
  const weeks = WINDOW_DAYS / 7;
  const windows = quietWindows(hours, weeks);
  const quietHoursWeek = hours.filter((b) => b.verdict === "quiet").length;
  const busy = hours.filter((b) => b.cpu_avg != null).sort((a, b) => (b.cpu_avg ?? 0) - (a.cpu_avg ?? 0)).slice(0, 3).map((b) => ({ day: b.day, hour: b.hour, cpu_avg: b.cpu_avg ?? 0, net_mb: b.net_mb, label: ringLabel(b.day * 24 + b.hour) }));
  const totalEff = windows.reduce((s, w) => s + w.effective_hours, 0);
  const confidence = totalEff ? Math.round((windows.reduce((s, w) => s + w.confidence * w.effective_hours, 0) / totalEff) * 100) / 100 : 0;
  const probes = i.samples.reduce((s, x) => s + x.probes.length, 0);
  const cwHours = i.samples.filter((s) => s.cpu_max != null).length;
  const logHours = i.samples.filter((s) => s.log_signals != null).length;
  const sug = suggestSchedule(hours);
  const off = sug ? offHoursPerWeek(sug.schedule) : null;
  const est = sug && off != null && i.monthly_usd ? Math.round(i.monthly_usd * (off / HOURS_PER_WEEK) * 100) / 100 : null;
  const seenWeeks = Math.max(0, ...hours.map((b) => b.seen));
  const parts: string[] = [];
  if (!cwHours) parts.push("no CloudWatch hour in the window: nothing to profile");
  else if (!windows.length) parts.push(`no quiet stretch of ${MIN_WINDOW_HOURS} h in ${seenWeeks} week${seenWeeks === 1 ? "" : "s"}: used or unknown at every hour`);
  else {
    const top = windows.slice(0, 3).map((w) => `${w.label} (${w.effective_hours} h, confidence ${w.confidence})`).join("; ");
    parts.push(`quiet ${quietHoursWeek} of ${HOURS_PER_WEEK} hours a week over ${seenWeeks} week${seenWeeks === 1 ? "" : "s"}: ${top}${windows.length > 3 ? ` and ${windows.length - 3} more` : ""}`);
    const cov = Math.round(100 * windows.reduce((s, w) => s + w.probe_coverage * w.hours, 0) / windows.reduce((s, w) => s + w.hours, 0));
    parts.push(i.kind === "asg" ? (i.samples.some((s) => s.requests != null) ? `the balancer's request count covers ${cov} % of the quiet hours` : "no balancer in front of the group: CloudWatch CPU only, so the confidence tops out at 0.6") : (probes || logHours) ? `${[probes ? "probes" : null, logHours ? `the shipped logs (${logHours} h scanned)` : null].filter(Boolean).join(" and ")} cover ${cov} % of the quiet hours (connections, use signals, logins, container CPU${logHours ? ", use-signal lines in CloudWatch Logs" : ""})` : "no probe and no scanned log in the window: CloudWatch only, so the confidence tops out at 0.6");
  }
  const why = { cpu: 0, net: 0, requests: 0, probe: 0, logs: 0 }; const kinds = { ext_conn: 0, users: 0, signals: 0, requests: 0, logins: 0, containers: 0 }; let busyHours = 0;
  for (const b of hours) if (b.verdict === "busy") { busyHours++; why.cpu += b.busy_cpu; why.net += b.busy_net; why.requests += b.busy_requests; why.probe += b.busy_probe; why.logs += b.busy_logs; for (const k of Object.keys(kinds) as (keyof typeof kinds)[]) kinds[k] += b.busy_probe_kinds[k]; }
  if (busyHours) {
    const probeWhy = [kinds.ext_conn ? `external connections ${kinds.ext_conn}` : null, kinds.signals ? `use-signal lines ${kinds.signals}` : null, kinds.requests ? `front-door requests ${kinds.requests}` : null, kinds.logins ? `logins ${kinds.logins}` : null, kinds.users ? `users on the box ${kinds.users}` : null, kinds.containers ? `a container over ${QUIET_CONTAINER_CPU} % CPU ${kinds.containers}` : null].filter(Boolean).join(", ");
    const trips = [why.net ? `network over ${Math.round(QUIET_NET_BYTES / 1e6)} MB/h in ${why.net}` : null, why.cpu ? `CPU over ${QUIET_CPU_MAX} % in ${why.cpu}` : null, why.requests ? `balancer requests in ${why.requests}` : null, why.logs ? `use-signal lines in the shipped logs in ${why.logs}` : null, why.probe ? `a probe signal in ${why.probe} (${probeWhy})` : null].filter(Boolean);
    parts.push(`${busyHours} busy hours of the week; what tripped them, in hour-samples: ${trips.join(", ")}`);
  }
  if (busy.length) parts.push(`busiest ${busy[0].label} (CPU ${busy[0].cpu_avg} %${busy[0].net_mb != null ? `, ${busy[0].net_mb} MB` : ""})`);
  if (sug) parts.push(`schedule that keeps it up whenever it was used: ${sug.text} (off ${off} h/week${est ? `, ≈ ${est} USD/month` : ""})`);
  else if (cwHours && hours.every((b) => b.verdict === "quiet")) parts.push("never used in the window: parking, not a schedule");
  else if (cwHours) parts.push("used around the clock, or at unknown hours: no schedule fits");
  return {
    subject: i.subject, kind: i.kind, name: i.name ?? null, region: i.region ?? null, account_id: i.account_id ?? null, computed_at: new Date(i.now ?? Date.now()).toISOString(), window_days: WINDOW_DAYS,
    signals: { cloudwatch_hours: cwHours, probes, requests: i.samples.some((s) => s.requests != null), log_hours: logHours },
    hours, quiet_windows: windows, busiest: busy, quiet_hours_week: quietHoursWeek, confidence, suggested_schedule: sug?.text ?? null, off_hours_week: off, est_usd_month: est, summary: parts.join(". ") + ".",
  };
}

// ---- collection ----------------------------------------------------------------------------------------------

const hourStart = (t: number) => Math.floor(t / H) * H;
const recent = (iso: string | null | undefined, at: number) => { if (!iso) return false; const t = new Date(iso.endsWith("Z") || iso.includes("+") ? iso : iso.replace(" ", "T") + "Z").getTime(); return Number.isFinite(t) && t >= at - H && t <= at + H; };

/** The probes of one instance in the window, as marks on their hour. */
export function probeMarks(instanceId: string, since: number): Map<number, ProbeMark[]> {
  const out = new Map<number, ProbeMark[]>();
  const sinceIso = new Date(since).toISOString().replace("T", " ").slice(0, 19);
  const busy = new Map<string, boolean>();
  for (const r of db.prepare("select collected_at, max(cpu_pct) as cpu from container_samples where instance_id = ? and collected_at >= ? group by collected_at").all(instanceId, sinceIso) as { collected_at: string; cpu: number | null }[]) busy.set(r.collected_at, (r.cpu ?? 0) >= QUIET_CONTAINER_CPU);
  for (const r of db.prepare("select collected_at, external_connections, users_now, ssh_sessions, last_signal_at, last_request_at, last_login_at, last_log_at from instance_activity where instance_id = ? and collected_at >= ?").all(instanceId, sinceIso) as any[]) {
    const at = new Date(r.collected_at.endsWith("Z") ? r.collected_at : r.collected_at.replace(" ", "T") + "Z").getTime(); if (!Number.isFinite(at)) continue;
    const key = hourStart(at);
    const mark: ProbeMark = { ext_conn: Number(r.external_connections || 0), users_now: Number(r.users_now || 0) + Number(r.ssh_sessions || 0), signals_recent: recent(r.last_signal_at, at), request_recent: recent(r.last_request_at, at), login_recent: recent(r.last_login_at, at), logs_recent: recent(r.last_log_at, at), container_busy: busy.get(r.collected_at) ?? false };
    out.set(key, [...(out.get(key) || []), mark]);
  }
  return out;
}

interface Subject { subject: string; kind: "ec2" | "asg"; name: string | null; region: string; account_id: string | null; monthly_usd: number | null; dimension: { Name: string; Value: string }; lb_dimension?: string | null }

export const LOG_QUERY_TIMEOUT_MS = 120_000;
export const LOG_QUERY_CONCURRENCY = 4;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** A probe pattern (POSIX ERE for grep -iE) as a Logs Insights regex alternative: the slash escaped, case folded by the query. Pure. */
export const insightsRegex = (re: string) => re.replace(/\//g, "\\/");
/** The Logs Insights query counting lines matching any of the patterns per hour. Pure. */
export const logSignalQuery = (patterns: string[]) => `filter @message like /(?i)(${patterns.map(insightsRegex).join("|")})/ | stats count(*) as n by bin(1h)`;

/**
 * The log groups a box ships to, grouped by the use-signal kinds that count for them: a group shipped by a
 * container gets the container image's noise rules applied, so the same kind can count for one group and not
 * another. Pure given the probe's shipping list and containers.
 */
export function logQuerySets(shipping: { group: string; via: string }[], containers: { name: string; image: string }[], kinds: { name: string; regex: string }[]): { groups: string[]; patterns: string[]; kinds: string[] }[] {
  const imageOf = new Map(containers.map((c) => [c.name, c.image]));
  const sets = new Map<string, { groups: Set<string>; patterns: string[]; kinds: string[] }>();
  for (const s of shipping) {
    if (!s?.group) continue;
    const container = s.via?.startsWith("docker:") ? s.via.slice(7) : null;
    const image = container ? imageOf.get(container) : null;
    const noise = new Set(image ? rulesFor(image).filter((r) => r.verdict === "noise").map((r) => r.kind) : []);
    const allowed = kinds.filter((k) => !noise.has(k.name));
    if (!allowed.length) continue;
    const key = allowed.map((k) => k.name).join(",");
    const e = sets.get(key) ?? { groups: new Set<string>(), patterns: allowed.map((k) => k.regex), kinds: allowed.map((k) => k.name) }; sets.set(key, e);
    e.groups.add(s.group);
  }
  return [...sets.values()].map((e) => ({ groups: [...e.groups].slice(0, 50), patterns: e.patterns, kinds: e.kinds }));
}

async function runLogQuery(logs: CloudWatchLogsClient, groups: string[], query: string, since: number, until: number): Promise<Map<number, number> | null> {
  const r = await logs.send(new StartQueryCommand({ logGroupNames: groups, startTime: Math.floor(since / 1000), endTime: Math.floor(until / 1000), queryString: query, limit: 10000 }));
  const queryId = r.queryId; if (!queryId) return null;
  const deadline = Date.now() + LOG_QUERY_TIMEOUT_MS;
  while (Date.now() < deadline) {
    await sleep(2000);
    const g = await logs.send(new GetQueryResultsCommand({ queryId }));
    if (g.status === "Complete") {
      const out = new Map<number, number>();
      for (const row of g.results ?? []) {
        const f: Record<string, string> = {}; for (const c of row) if (c.field && c.value != null) f[c.field] = c.value;
        const t = Date.parse(String(f["bin(1h)"] || "").replace(" ", "T") + "Z"); const n = Number(f.n);
        if (Number.isFinite(t) && Number.isFinite(n)) out.set(hourStart(t), (out.get(hourStart(t)) ?? 0) + n);
      }
      return out;
    }
    if (g.status && !["Running", "Scheduled"].includes(g.status)) return null;
  }
  try { await logs.send(new StopQueryCommand({ queryId })); } catch { /* best effort */ }
  return null;
}

/**
 * The use-signal lines per hour in the log groups each box ships to, over the last `USAGE_LOG_DAYS`, stored in
 * usage_log_signals. A box with no shipping section, no groups, or a failed query gets no entry (no evidence
 * either way); a box whose queries ran gets an entry for every hour of the window, zero included.
 */
export async function collectLogSignals(creds: Creds, subs: Subject[], since: number, until: number, onLog: (s: string) => void): Promise<Map<string, Map<number, number>>> {
  const out = new Map<string, Map<number, number>>();
  const kinds = (() => { try { return parseSignals(config.probeSignals); } catch { return []; } })();
  if (!kinds.length) return out;
  const tasks: { s: Subject; set: ReturnType<typeof logQuerySets>[number] }[] = [];
  for (const s of subs) {
    if (s.kind !== "ec2") continue;
    const probe = latestProbe(s.subject);
    const shipping = Array.isArray(probe?.data?.log_shipping) ? probe!.data.log_shipping : [];
    if (!shipping.length) continue;
    for (const set of logQuerySets(shipping, (probe?.data?.containers ?? []).map((c: any) => ({ name: String(c.name), image: String(c.image || "") })), kinds)) tasks.push({ s, set });
  }
  const clients = new Map<string, CloudWatchLogsClient>();
  const clientFor = (s: Subject) => { const k = `${s.account_id || ""}|${s.region}`; let c = clients.get(k); if (!c) { c = new CloudWatchLogsClient({ region: s.region, credentials: creds.forAccount(s.account_id).read }); clients.set(k, c); } return c; };
  const del = db.prepare("delete from usage_log_signals where subject = ?");
  const ins = db.prepare("insert into usage_log_signals(subject, hour, count) values (?, ?, ?)");
  let idx = 0; const failed = new Set<string>();
  const worker = async () => {
    while (idx < tasks.length) {
      const t = tasks[idx++];
      try {
        const counts = await runLogQuery(clientFor(t.s), t.set.groups, logSignalQuery(t.set.patterns), since, until);
        if (!counts) { failed.add(t.s.subject); onLog(`${t.s.name || t.s.subject}: log scan of ${t.set.groups.length} group(s) gave no result`); continue; }
        const per = out.get(t.s.subject) ?? new Map<number, number>(); out.set(t.s.subject, per);
        for (const [h, n] of counts) per.set(h, (per.get(h) ?? 0) + n);
      } catch (e: any) { failed.add(t.s.subject); onLog(`${t.s.name || t.s.subject}: log scan failed: ${String(e?.message || e).slice(0, 160)}`); }
    }
  };
  try { await Promise.all(Array.from({ length: Math.min(LOG_QUERY_CONCURRENCY, tasks.length) }, worker)); }
  finally { for (const c of clients.values()) c.destroy(); }
  db.transaction(() => {
    for (const [subject, per] of out) {
      if (failed.has(subject)) { out.delete(subject); continue; }
      del.run(subject);
      for (let h = hourStart(since); h < until; h += H) ins.run(subject, h, per.get(h) ?? 0);
    }
  })();
  return out;
}

async function hourlyMetrics(cw: CloudWatchClient, subjects: Subject[], since: number, until: number): Promise<Map<string, Map<number, { cpu_avg?: number; cpu_max?: number; net_in?: number; net_out?: number; requests?: number }>>> {
  const out = new Map<string, Map<number, any>>();
  const queries: MetricDataQuery[] = []; const key: { subject: string; what: string }[] = [];
  const add = (s: Subject, what: string, Namespace: string, MetricName: string, Dimensions: { Name: string; Value: string }[], Stat: string) => { queries.push({ Id: `q${key.length}`, MetricStat: { Metric: { Namespace, MetricName, Dimensions }, Period: 3600, Stat }, ReturnData: true }); key.push({ subject: s.subject, what }); };
  for (const s of subjects) {
    out.set(s.subject, new Map());
    add(s, "cpu_avg", "AWS/EC2", "CPUUtilization", [s.dimension], "Average");
    add(s, "cpu_max", "AWS/EC2", "CPUUtilization", [s.dimension], "Maximum");
    if (s.kind === "ec2") { add(s, "net_in", "AWS/EC2", "NetworkIn", [s.dimension], "Sum"); add(s, "net_out", "AWS/EC2", "NetworkOut", [s.dimension], "Sum"); }
    if (s.lb_dimension) add(s, "requests", "AWS/ApplicationELB", "RequestCount", [{ Name: "LoadBalancer", Value: s.lb_dimension }], "Sum");
  }
  for (let i = 0; i < queries.length; i += 100) {
    const slice = queries.slice(i, i + 100);
    let NextToken: string | undefined;
    do {
      const r = await cw.send(new GetMetricDataCommand({ MetricDataQueries: slice, StartTime: new Date(since), EndTime: new Date(until), NextToken, ScanBy: "TimestampAscending" }));
      for (const m of r.MetricDataResults ?? []) {
        const k = key[Number(String(m.Id).slice(1))]; if (!k) continue;
        const per = out.get(k.subject)!;
        (m.Values ?? []).forEach((v, j) => { const t = m.Timestamps?.[j]; if (!t) return; const at = hourStart(new Date(t).getTime()); const e = per.get(at) ?? {}; e[k.what] = v; per.set(at, e); });
      }
      NextToken = r.NextToken;
    } while (NextToken);
  }
  return out;
}

const upsert = db.prepare(`insert into usage_profiles(subject, kind, name, region, account_id, computed_at, window_days, signals, hours, quiet_windows, busiest, quiet_hours_week, confidence, suggested_schedule, off_hours_week, est_usd_month, summary)
  values (@subject, @kind, @name, @region, @account_id, @computed_at, @window_days, @signals, @hours, @quiet_windows, @busiest, @quiet_hours_week, @confidence, @suggested_schedule, @off_hours_week, @est_usd_month, @summary)
  on conflict(subject) do update set kind = excluded.kind, name = excluded.name, region = excluded.region, account_id = excluded.account_id, computed_at = excluded.computed_at, window_days = excluded.window_days, signals = excluded.signals, hours = excluded.hours,
    quiet_windows = excluded.quiet_windows, busiest = excluded.busiest, quiet_hours_week = excluded.quiet_hours_week, confidence = excluded.confidence, suggested_schedule = excluded.suggested_schedule, off_hours_week = excluded.off_hours_week, est_usd_month = excluded.est_usd_month, summary = excluded.summary`);

export function storeProfile(p: Profile): void {
  upsert.run({ ...p, signals: JSON.stringify(p.signals), hours: JSON.stringify(p.hours), quiet_windows: JSON.stringify(p.quiet_windows), busiest: JSON.stringify(p.busiest) });
}

export function latestProfile(subject: string): Profile | null {
  const r = db.prepare("select * from usage_profiles where subject = ?").get(subject) as any;
  if (!r) return null;
  return { ...r, signals: JSON.parse(r.signals), hours: JSON.parse(r.hours), quiet_windows: JSON.parse(r.quiet_windows), busiest: JSON.parse(r.busiest) };
}

export function listProfiles(kind?: "ec2" | "asg"): Omit<Profile, "hours">[] {
  const rows = db.prepare(`select subject, kind, name, region, account_id, computed_at, window_days, signals, quiet_windows, busiest, quiet_hours_week, confidence, suggested_schedule, off_hours_week, est_usd_month, summary from usage_profiles ${kind ? "where kind = ?" : ""} order by est_usd_month desc nulls last, quiet_hours_week desc`).all(...(kind ? [kind] : [])) as any[];
  return rows.map((r) => ({ ...r, signals: JSON.parse(r.signals), quiet_windows: JSON.parse(r.quiet_windows), busiest: JSON.parse(r.busiest) }));
}

/** The subjects worth profiling: running standalone instances (pool members belong to their controller) and the autoscaling groups behind a balancer. */
function subjects(creds: Creds, only?: string[]): Subject[] {
  const out: Subject[] = [];
  const ec2 = db.prepare("select instance_id, account_id, name, region, monthly_usd, pool_kind from inventory_ec2 where gone = 0 and state = 'running'").all() as any[];
  for (const r of ec2) {
    if (only && !only.includes(r.instance_id)) continue;
    if (r.pool_kind && !only) continue;
    out.push({ subject: r.instance_id, kind: "ec2", name: r.name, region: r.region || creds.region, account_id: r.account_id || null, monthly_usd: r.monthly_usd, dimension: { Name: "InstanceId", Value: r.instance_id } });
  }
  const lbs = db.prepare("select arn, kind, region, account_id, asgs from inventory_elb where gone = 0 and asgs <> '[]'").all() as any[];
  const seen = new Set<string>();
  for (const lb of lbs) {
    let asgs: string[] = []; try { asgs = JSON.parse(lb.asgs || "[]"); } catch { asgs = []; }
    for (const name of asgs) {
      const subject = `asg:${name}`;
      if (seen.has(subject) || (only && !only.includes(subject) && !only.includes(name))) continue;
      seen.add(subject);
      out.push({ subject, kind: "asg", name, region: lb.region || creds.region, account_id: lb.account_id || null, monthly_usd: null, dimension: { Name: "AutoScalingGroupName", Value: name }, lb_dimension: lb.kind === "alb" ? metricDimension(lb.arn) : null });
    }
  }
  return out;
}

export interface UsagePassResult { profiled: number; recommendations: number; errors: string[]; took_ms: number }

/** Profiles every subject (or the given ones), stores the profiles and files the schedule recommendations. */
export async function usageProfilePass(onLog: (s: string) => void = () => {}, opts: { only?: string[]; creds?: Creds } = {}): Promise<UsagePassResult> {
  const t0 = Date.now();
  const creds = opts.creds ?? executorCreds();
  const now = hourStart(Date.now());
  const since = now - WINDOW_DAYS * 86400000;
  const list = subjects(creds, opts.only);
  const errors: string[] = []; let profiled = 0;
  const recs: RecInput[] = [];
  const byScope = new Map<string, Subject[]>();
  for (const s of list) { const k = `${s.account_id || ""}|${s.region}`; if (!byScope.has(k)) byScope.set(k, []); byScope.get(k)!.push(s); }
  const tagged = new Set((db.prepare("select instance_id from inventory_ec2 where gone = 0 and (snapshot like '%\"advisor:schedule\"%' or snapshot like '%\"advisor:hands-off\"%' or snapshot like '%\"advisor:park\"%' or snapshot like '%\"AdvisorAutoPark\"%')").all() as { instance_id: string }[]).map((r) => r.instance_id));
  for (const [scope, subs] of byScope) {
    const [account, region] = scope.split("|");
    const cw = new CloudWatchClient({ region, credentials: creds.forAccount(account || null).read });
    try {
      const metrics = await hourlyMetrics(cw, subs, since, now);
      const logDays = Math.max(0, Math.min(WINDOW_DAYS, Math.round(config.usageLogDays)));
      const logSince = now - logDays * 86400000;
      const logCounts = logDays > 0 ? await collectLogSignals(creds, subs, logSince, now, onLog) : new Map<string, Map<number, number>>();
      for (const s of subs) {
        const per = metrics.get(s.subject) ?? new Map();
        const marks = s.kind === "ec2" ? probeMarks(s.subject, since) : new Map<number, ProbeMark[]>();
        const logs = logCounts.get(s.subject) ?? null;
        const samples: HourSample[] = [];
        for (let at = since; at < now; at += H) {
          const m = per.get(at);
          samples.push({ at, cpu_avg: m?.cpu_avg ?? null, cpu_max: m?.cpu_max ?? null, net_bytes: m?.net_in != null || m?.net_out != null ? (m?.net_in ?? 0) + (m?.net_out ?? 0) : null, requests: s.lb_dimension ? (m?.requests ?? 0) : null, probes: marks.get(at) || [], log_signals: logs && at >= logSince ? (logs.get(at) ?? 0) : null });
        }
        const p = buildProfile({ subject: s.subject, kind: s.kind, name: s.name, region: s.region, account_id: s.account_id, samples, monthly_usd: s.monthly_usd, now: Date.now() });
        storeProfile(p); profiled++;
        onLog(`${s.name || s.subject}: ${p.summary}`);
        if (s.kind === "ec2" && p.suggested_schedule && p.confidence >= CONFIDENT && (p.off_hours_week ?? 0) >= MIN_OFF_HOURS_WEEK && !tagged.has(s.subject)) {
          const sched = parseSchedule(p.suggested_schedule);
          recs.push({
            rule: RULE, actionType: ACTION_TYPE, tier: "approve", confidence: p.confidence, resource: s.subject, resourceName: s.name ?? undefined,
            title: `${s.name || s.subject}: run it ${p.suggested_schedule} (off ${p.off_hours_week} h/week${p.est_usd_month ? `, ≈ ${p.est_usd_month} USD/month` : ""})`,
            estMonthlySaving: p.est_usd_month,
            rationale: `${p.summary} Approving tags the instance advisor:schedule=${p.suggested_schedule}${"error" in sched ? "" : ` (${describeSchedule(sched)})`}; the office-hours action then stops it outside the window and starts it before it opens, and on start it points the Route 53 records that named the old public address at the new one when the box has no Elastic IP. Every hour the box was ever seen busy, plus an hour each side, stays inside the window; a stop only happens where every week of the last ${WINDOW_DAYS} days was quiet on CPU, network, connections, use signals, logins and container CPU.`,
            evidence: { schedule: p.suggested_schedule, confidence: p.confidence, quiet_windows: p.quiet_windows, quiet_hours_week: p.quiet_hours_week, off_hours_week: p.off_hours_week, window_days: WINDOW_DAYS, signals: p.signals, busiest: p.busiest },
          });
        }
      }
    } catch (e: any) { const m = String(e?.message || e).slice(0, 200); errors.push(`${region}: ${m}`); onLog(`${region}: ${m}`); }
    finally { cw.destroy(); }
  }
  let filed = 0;
  if (recs.length) { const runId = (db.prepare("select id from runs order by id desc limit 1").get() as { id: number } | undefined)?.id ?? 0; filed = upsertRecommendations(runId, recs, "rules", undefined, { reconcile: false }); }
  try { const { mirrorUsageProfilesInBackground } = await import("./graph_mirror.js"); mirrorUsageProfilesInBackground(); } catch { /* graph optional */ }
  return { profiled, recommendations: filed, errors, took_ms: Date.now() - t0 };
}

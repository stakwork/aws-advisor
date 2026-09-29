/**
 * The usage review: once a day (and on demand), Jev reads everything the advisor knows about a box's use and
 * decides what the executor may do with it.
 *
 * The usage profile (src/usage_profile.ts) is arithmetic: an hour is quiet when every week was quiet on every
 * signal, and one busy week poisons the hour. That is the right default for a stop, but it cannot weigh what a
 * person would: that the "external connections" at every probe are the swarm checker and relay peers, that a
 * single 39 % hour four weeks ago was a deploy, that 86 % memory on a swarm box is Docker holding what it was
 * given, that the box's role makes it protected. So per instance the review hands Jev the profile (quiet
 * windows, what tripped the busy hours, probe coverage), the latest activity (connections and who the peers
 * are, front door, logins, per-container logs and use signals), the containers and processes, the role, the
 * tags, the last week of executor rows, and a set of candidate schedules: the profile's own, a wider one with
 * an extra hour of margin, a weekdays-only one, and "keep running". Jev picks one and answers two more typed
 * questions: are the quiet windows real non-use rather than a measurement gap, and are the busy signals machine
 * chatter rather than people. The verdict (confirm / adjust / keep_running), the chosen schedule, the
 * confidence and a reason built from the answers land in `usage_reviews` and on the graph, and the office-hours
 * action follows the review for a box tagged `AdvisorAutoPark=ON`: the chosen window when the verdict is
 * confirm or adjust, nothing when it is keep_running, the raw profile only when Jev is not configured.
 */
import { choice, noul } from "@typesafe-ai/sdk";
import { db } from "./db.js";
import { askJev, chunk, jevEnabled } from "./jev.js";
import { resourceRole } from "./roles.js";
import { latestProfile, listProfiles, CONFIDENT, MARGIN_HOURS, type Profile } from "./usage_profile.js";
import { describeSchedule, offHoursPerWeek, parseSchedule, HOURS_PER_WEEK } from "./actions/schedule_hours.js";

db.exec(`create table if not exists usage_reviews (
  subject text primary key, reviewed_at text not null, verdict text not null, schedule text, off_hours_week integer, est_usd_month real,
  confidence real not null, quiet_is_real real, busy_is_machine real, reason text not null, options text not null, state text, model text, call_id integer
)`);

export const REVIEW_BATCH_SIZE = 8;
/** A verdict this old is asked for again by the daily pass; on demand it is always asked. */
export const REVIEW_MAX_AGE_HOURS = 30;
/** Below this confidence in the chosen option the verdict is keep_running whatever Jev picked. */
export const MIN_CHOICE_CONFIDENCE = 0.55;

export interface UsageReview {
  subject: string; reviewed_at: string; verdict: "confirm" | "adjust" | "keep_running"; schedule: string | null; off_hours_week: number | null; est_usd_month: number | null;
  confidence: number; quiet_is_real: number | null; busy_is_machine: number | null; reason: string; options: Record<string, string>; model: string | null; call_id: number | null;
}

const DAY_NAMES = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];

/** The candidate schedules Jev picks from: the profile's own, a wider one, a weekdays-only one, and keeping it running. Pure. */
export function candidateSchedules(p: Pick<Profile, "suggested_schedule" | "hours">): Record<string, string> {
  const out: Record<string, string> = {};
  const sug = p.suggested_schedule ? parseSchedule(p.suggested_schedule) : null;
  if (sug && !("error" in sug)) {
    out.profile = `${p.suggested_schedule}: the profile's own window, every hour ever seen busy plus ${MARGIN_HOURS} h each side`;
    const start = Math.max(0, sug.start - 1), end = Math.min(24, (sug.end === 0 ? 24 : sug.end) + 1);
    if (end - start < 22) {
      const days = sug.days.size === 7 ? "daily" : [1, 2, 3, 4, 5].every((d) => sug.days.has(d)) && sug.days.size === 5 ? "weekdays" : [...sug.days].sort().map((d) => DAY_NAMES[d]).join(",");
      out.wider = `${days} ${String(start).padStart(2, "0")}-${String(end).padStart(2, "0")} UTC: the same, with an extra hour of margin at each end`;
    }
    if (sug.days.size === 7) {
      const weekendBusy = p.hours.some((b) => (b.day === 0 || b.day === 6) && b.verdict !== "quiet" && b.seen > 0);
      out.weekdays = `weekdays ${String(sug.start).padStart(2, "0")}-${String(sug.end === 0 ? 24 : sug.end).padStart(2, "0")} UTC: off all weekend${weekendBusy ? " (some weekend hours were busy: only if that was machine chatter)" : ""}`;
    }
  }
  out.keep_running = "no schedule: the box is used at hours the profile cannot separate, or the evidence is too thin to stop it";
  return out;
}

/** What Jev sees for one box. Cheap reads, every one tolerant of a missing table. */
export function reviewState(p: Profile): Record<string, unknown> {
  const q = <T>(f: () => T, fallback: T): T => { try { return f(); } catch { return fallback; } };
  const id = p.subject;
  const inv = q(() => db.prepare("select name, instance_type, state, monthly_usd, pool_kind, snapshot from inventory_ec2 where instance_id = ?").get(id) as any, null);
  let tags: Record<string, string> = {}; try { tags = JSON.parse(inv?.snapshot || "{}").tags || {}; } catch { tags = {}; }
  const role = q(() => resourceRole(id), null);
  const act = q(() => db.prepare("select * from instance_activity where instance_id = ? order by collected_at desc limit 1").get(id) as any, null);
  let peers: any[] = []; try { peers = act?.peers ? JSON.parse(act.peers) : []; } catch { peers = []; }
  const containers = q(() => db.prepare("select name, image, avg(cpu_pct_avg) as cpu_avg, max(cpu_pct_max) as cpu_max, avg(log_lines_avg) as log_lines_day, avg(signal_lines_avg) as signal_lines_day, max(last_signal_at) as last_signal_at, max(restarts_max) as restarts from container_daily where instance_id = ? and day >= date('now', '-14 days') group by name order by cpu_avg desc limit 12").all(id) as any[], []);
  const daily = q(() => db.prepare("select day, external_connections_avg, external_connections_max, requests_24h_avg, signal_lines_24h_avg, ssh_sessions_max, last_use_at, last_use_kind, net_bytes_day, mem_pct_avg, load_per_cpu_avg from instance_daily where instance_id = ? order by day desc limit 14").all(id) as any[], []);
  const rows = q(() => db.prepare("select id, kind, status, title, created_at from actions where resource = ? and datetime(created_at) > datetime('now', '-14 days') order by id desc limit 8").all(id) as any[], []);
  const recs = q(() => db.prepare("select id, rule, status, decided_by, decision_reason, title from recommendations where resource = ? and status in ('approved', 'rejected', 'done') order by id desc limit 6").all(id) as any[], []);
  const busy = p.hours.filter((b) => b.verdict === "busy");
  const kinds = { ext_conn: 0, users: 0, signals: 0, requests: 0, logins: 0, containers: 0 };
  let net = 0, cpu = 0; for (const b of busy) { net += b.busy_net; cpu += b.busy_cpu; for (const k of Object.keys(kinds) as (keyof typeof kinds)[]) kinds[k] += b.busy_probe_kinds?.[k] ?? 0; }
  return {
    instance: { id, name: inv?.name ?? null, type: inv?.instance_type ?? null, state: inv?.state ?? null, list_usd_month: inv?.monthly_usd ?? null, pool: inv?.pool_kind ?? null, tags,
      role: role ? { role: role.role, confidence: role.role_confidence, protected_prob: role.protected_prob } : null },
    note: "Memory use is not a usage signal: on a box running containers it is what Docker was given. Use signals already pass the per-image noise rules. External connections include relay peers, health checkers and the swarm checker as well as people.",
    profile: {
      window_days: p.window_days, computed_at: p.computed_at, quiet_hours_week: p.quiet_hours_week, arithmetic_confidence: p.confidence, summary: p.summary,
      quiet_windows: p.quiet_windows.map((w) => ({ window: w.label, hours_off: w.effective_hours, weeks_and_probe_confidence: w.confidence, probe_coverage: w.probe_coverage })),
      busy_hours_week: busy.length, busy_tripped_by: { network_over_5mb_h: net, cpu_over_10pct_max: cpu, probe: kinds },
      busiest: p.busiest, signals: p.signals, suggested_schedule: p.suggested_schedule,
    },
    latest_activity: act ? { probed_at: act.collected_at, external_connections: act.external_connections, internal_connections: act.internal_connections, ssh_sessions: act.ssh_sessions, users_now: act.users_now,
      requests_24h: act.requests_24h, health_checks_24h: act.health_24h, last_request_at: act.last_request_at, last_login_at: act.last_login_at, last_login_user: act.last_login_user, use_signal_lines_24h: act.signal_lines_24h, last_signal_at: act.last_signal_at,
      peers: peers.slice(0, 8).map((x) => ({ ip: x.ip, port: x.port, flows: x.flows, kind: x.kind, container: x.container ?? null })) } : null,
    last_14_days: daily.map((d) => ({ day: d.day, external_connections_max: d.external_connections_max, requests: d.requests_24h_avg, use_signals: d.signal_lines_24h_avg, ssh: d.ssh_sessions_max, last_use: d.last_use_at, last_use_kind: d.last_use_kind, net_mb: d.net_bytes_day != null ? Math.round(d.net_bytes_day / 1e6) : null, mem_pct: d.mem_pct_avg, load_per_cpu: d.load_per_cpu_avg })),
    containers_14_days: containers.map((c) => ({ name: c.name, image: c.image, cpu_avg: c.cpu_avg, cpu_max: c.cpu_max, log_lines_day: c.log_lines_day, use_signal_lines_day: c.signal_lines_day, last_use_signal: c.last_signal_at, restarts: c.restarts })),
    executor_rows_14_days: rows.map((r) => ({ id: r.id, kind: r.kind, status: r.status, title: String(r.title).slice(0, 140), at: r.created_at })),
    team_decisions: recs.map((r) => ({ id: r.id, rule: r.rule, status: r.status, by: r.decided_by, reason: r.decision_reason ? String(r.decision_reason).slice(0, 200) : null, title: String(r.title).slice(0, 140) })),
  };
}

export const reviewQuestions = (prefix: string, options: Record<string, string>) => ({
  [`${prefix}_schedule`]: choice(`Consider only the box under boxes.${prefix} (ignore the others). Which running schedule (UTC) should the executor follow for it? Stop it only in hours nobody would notice; choose keep_running when the busy hours cannot be separated from the quiet ones or the evidence is too thin.`, options),
  [`${prefix}_quiet_real`]: noul(`Consider only the box under boxes.${prefix} (ignore the others). Its quiet windows reflect real non-use by people and clients, not a gap in measurement (few weeks, no probes, the box being off)`),
  [`${prefix}_busy_machine`]: noul(`Consider only the box under boxes.${prefix} (ignore the others). What made its busy hours busy is machine chatter (health checkers, monitoring, peers, backups, log shipping) rather than people or clients using the service`),
});

/** The verdict from the answers: the chosen option, downgraded to keep_running when Jev is unsure of it or doubts the quiet windows. Pure. */
export function reviewVerdict(a: { choice: string; confidence: number; quiet_real: number; busy_machine: number }, options: Record<string, string>, p: Pick<Profile, "suggested_schedule" | "est_usd_month">, monthlyUsd: number | null, opts: { model?: string; now?: Date } = {}): Omit<UsageReview, "subject" | "call_id"> {
  const now = (opts.now ?? new Date()).toISOString();
  const text = (key: string) => (options[key] || "").split(":")[0].trim();
  let key = a.choice in options ? a.choice : "keep_running";
  const why: string[] = [];
  if (key !== "keep_running" && a.confidence < MIN_CHOICE_CONFIDENCE) { why.push(`Jev leaned to ${text(key)} but only at ${a.confidence.toFixed(2)}`); key = "keep_running"; }
  if (key !== "keep_running" && a.quiet_real < 0.5) { why.push(`Jev doubts the quiet windows are real non-use (${a.quiet_real.toFixed(2)})`); key = "keep_running"; }
  const schedule = key === "keep_running" ? null : text(key);
  const parsed = schedule ? parseSchedule(schedule) : null;
  const off = parsed && !("error" in parsed) ? offHoursPerWeek(parsed) : null;
  const est = off != null && monthlyUsd ? Math.round(monthlyUsd * (off / HOURS_PER_WEEK) * 100) / 100 : null;
  const verdict: UsageReview["verdict"] = key === "keep_running" ? "keep_running" : schedule === p.suggested_schedule ? "confirm" : "adjust";
  if (verdict === "confirm") why.push(`Jev confirms the profile's window ${schedule} (${a.confidence.toFixed(2)})`);
  else if (verdict === "adjust") why.push(`Jev prefers ${schedule} over the profile's ${p.suggested_schedule ?? "none"} (${a.confidence.toFixed(2)})`);
  else if (!why.length) why.push(a.choice === "keep_running" ? `Jev keeps it running (${a.confidence.toFixed(2)})` : "Jev keeps it running");
  why.push(`quiet windows real ${a.quiet_real.toFixed(2)}, busy hours machine chatter ${a.busy_machine.toFixed(2)}`);
  return { reviewed_at: now, verdict, schedule, off_hours_week: off, est_usd_month: est, confidence: Math.round(a.confidence * 100) / 100, quiet_is_real: Math.round(a.quiet_real * 100) / 100, busy_is_machine: Math.round(a.busy_machine * 100) / 100, reason: why.join("; ") + ".", options, model: opts.model ?? null };
}

const upsert = db.prepare(`insert into usage_reviews(subject, reviewed_at, verdict, schedule, off_hours_week, est_usd_month, confidence, quiet_is_real, busy_is_machine, reason, options, state, model, call_id)
  values (@subject, @reviewed_at, @verdict, @schedule, @off_hours_week, @est_usd_month, @confidence, @quiet_is_real, @busy_is_machine, @reason, @options, @state, @model, @call_id)
  on conflict(subject) do update set reviewed_at = excluded.reviewed_at, verdict = excluded.verdict, schedule = excluded.schedule, off_hours_week = excluded.off_hours_week, est_usd_month = excluded.est_usd_month, confidence = excluded.confidence,
    quiet_is_real = excluded.quiet_is_real, busy_is_machine = excluded.busy_is_machine, reason = excluded.reason, options = excluded.options, state = excluded.state, model = excluded.model, call_id = excluded.call_id`);

export function latestReview(subject: string): UsageReview | null {
  const r = db.prepare("select * from usage_reviews where subject = ?").get(subject) as any;
  if (!r) return null;
  let options = {}; try { options = JSON.parse(r.options || "{}"); } catch { options = {}; }
  return { subject: r.subject, reviewed_at: r.reviewed_at, verdict: r.verdict, schedule: r.schedule, off_hours_week: r.off_hours_week, est_usd_month: r.est_usd_month, confidence: r.confidence, quiet_is_real: r.quiet_is_real, busy_is_machine: r.busy_is_machine, reason: r.reason, options, model: r.model, call_id: r.call_id };
}

/** The window the office-hours action follows for a box tagged AdvisorAutoPark=ON: the review's when there is one, else the profile's confident suggestion when Jev is not configured. */
export function scheduleFor(subject: string): { schedule: string | null; source: "review" | "profile" | null; note: string } {
  const p = latestProfile(subject);
  if (!p) return { schedule: null, source: null, note: "no usage profile yet (the daily job builds one)" };
  const r = latestReview(subject);
  if (r) {
    if (r.verdict === "keep_running") return { schedule: null, source: "review", note: `Jev keeps it running: ${r.reason}` };
    return { schedule: r.schedule, source: "review", note: `Jev ${r.verdict === "confirm" ? "confirmed" : "set"} ${r.schedule}: ${r.reason}` };
  }
  if (jevEnabled()) return { schedule: null, source: null, note: `waiting for the usage review (Jev decides once a day; "Ask the agent" on the page asks now)` };
  if (!p.suggested_schedule) return { schedule: null, source: null, note: p.summary };
  if (p.confidence < CONFIDENT) return { schedule: null, source: null, note: `the profile's confidence is ${p.confidence} (needs ${CONFIDENT} without a Jev review); ${p.suggested_schedule} waits for more weeks or probes` };
  return { schedule: p.suggested_schedule, source: "profile", note: `the profile's ${p.suggested_schedule} at confidence ${p.confidence} (no Jev configured)` };
}

export interface ReviewPassResult { reviewed: number; skipped: number; unanswered: number; verdicts: Record<string, number>; errors: string[]; took_ms: number }

/** Reviews every EC2 profile (or the given subjects), skipping fresh verdicts unless forced. Never throws per box. */
export async function usageReviewPass(onLog: (s: string) => void = () => {}, opts: { only?: string[]; force?: boolean } = {}): Promise<ReviewPassResult> {
  const t0 = Date.now();
  const out: ReviewPassResult = { reviewed: 0, skipped: 0, unanswered: 0, verdicts: {}, errors: [], took_ms: 0 };
  if (!jevEnabled()) { out.errors.push("Jev is not configured (Settings › Jev): no usage review; the office-hours action falls back to the profile's own window"); out.took_ms = Date.now() - t0; return out; }
  const subjects = (opts.only?.length ? opts.only : listProfiles("ec2").map((p) => p.subject)).filter((s) => !s.startsWith("asg:"));
  const todo: Profile[] = [];
  for (const s of subjects) {
    const p = latestProfile(s); if (!p || p.kind !== "ec2") { out.skipped++; continue; }
    const r = latestReview(s);
    if (!opts.force && r && Date.now() - new Date(r.reviewed_at).getTime() < REVIEW_MAX_AGE_HOURS * 3600000 && new Date(r.reviewed_at) > new Date(p.computed_at)) { out.skipped++; continue; }
    todo.push(p);
  }
  for (const batch of chunk(todo, REVIEW_BATCH_SIZE)) {
    const state: Record<string, unknown> = {}; const optionsBy: Record<string, Record<string, string>> = {};
    let questions: Record<string, unknown> = {};
    batch.forEach((p, i) => { const options = candidateSchedules(p); optionsBy[`b${i}`] = options; state[`b${i}`] = { ...reviewState(p), candidate_schedules: options }; questions = { ...questions, ...reviewQuestions(`b${i}`, options) }; });
    let res: Awaited<ReturnType<typeof askJev>> = null;
    try { res = await askJev({ boxes: state }, questions as any, { purpose: "usage_review" }); } catch (e: any) { out.errors.push(String(e?.message || e).slice(0, 200)); }
    if (!res) { out.unanswered += batch.length; continue; }
    batch.forEach((p, i) => {
      const c = res!.answers[`b${i}_schedule`] as any, qr = res!.answers[`b${i}_quiet_real`] as any, bm = res!.answers[`b${i}_busy_machine`] as any;
      if (c?.type !== "choice" || qr?.type !== "noul" || bm?.type !== "noul") { out.unanswered++; return; }
      const inv = db.prepare("select monthly_usd from inventory_ec2 where instance_id = ?").get(p.subject) as { monthly_usd: number | null } | undefined;
      const v = reviewVerdict({ choice: c.choice, confidence: c.confidence, quiet_real: qr.noul, busy_machine: bm.noul }, optionsBy[`b${i}`], p, inv?.monthly_usd ?? null, { model: res!.model });
      upsert.run({ subject: p.subject, ...v, options: JSON.stringify(v.options), state: JSON.stringify(state[`b${i}`]).slice(0, 60000), call_id: res!.call_id ?? null });
      out.reviewed++; out.verdicts[v.verdict] = (out.verdicts[v.verdict] || 0) + 1;
      onLog(`${p.name || p.subject}: ${v.verdict}${v.schedule ? ` ${v.schedule}` : ""} · ${v.reason}`);
    });
    console.log(`[jev] usage_review: ${batch.length} box(es) reviewed (${res.latency_ms} ms, ${res.usage.input_tokens}+${res.usage.output_tokens} tokens)`);
  }
  try { const { mirrorUsageProfilesInBackground } = await import("./graph_mirror.js"); mirrorUsageProfilesInBackground(); } catch { /* graph optional */ }
  out.took_ms = Date.now() - t0;
  return out;
}

export const describeReviewSchedule = (s: string | null) => { if (!s) return null; const p = parseSchedule(s); return "error" in p ? s : describeSchedule(p); };

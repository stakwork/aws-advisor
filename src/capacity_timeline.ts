/**
 * The scaling timeline of an Elastic Beanstalk environment: what the capacity action (src/actions/beanstalk_scale.ts)
 * will do to MinSize over the next 24 hours, what it and the pressure check did lately, and why.
 *
 * The forecast replays the hourly pass forward, one pass per coming hour, with the same pure decisions the pass
 * makes: the learned week (decidePattern) once the band is set and the pattern is confident, the windowed schedule
 * (decideWindow) otherwise, and the hand-set hold. Those hourly moves are exempt from the one-step-per-24-hours
 * rule, which only holds the agent's bounds, the idle-floor trim and the ceiling raise. What cannot be forecast is said, not guessed: the idle-floor trim and the ceiling raise follow
 * the next fourteen days of CPU, the agent's bounds follow its next review, and the pattern itself is recomputed
 * on every pass (a pressure event raises an hour the moment it is recorded).
 */
import { ElasticBeanstalkClient, DescribeEnvironmentsCommand } from "@aws-sdk/client-elastic-beanstalk";
import { db } from "./db.js";
import { config } from "./config.js";
import { decidePattern, latestPattern, pressureEventRows, HOURS_PER_WEEK, MIN_COVERAGE, MIN_WEEKS, HAND_SET_HOURS, type CapacityPattern } from "./capacity_pattern.js";
import { KIND as SCALE_KIND, MIN_HOURS_BETWEEN_CHANGES, decideWindow, envState, environmentFacts, hourStart, type EnvState } from "./actions/beanstalk_scale.js";
import { KIND as PRESSURE_KIND } from "./actions/beanstalk_pressure.js";
import { latestProfile, ringIndex, ringLabel, type QuietWindow } from "./usage_profile.js";
import { latestReview, windowsFromSchedule } from "./usage_review.js";
import { executorCreds, pauseState } from "./executor.js";

const H = 3600000;
export const TIMELINE_HOURS = 24;

export type PlanDriver = "pattern" | "window" | "none";
export interface PlannedHour {
  /** start of the hour (ISO, UTC) */ at: string; label: string;
  /** when the pass that decides this hour runs (ISO) */ decided_at: string;
  /** the learned minimum for the hour, when there is a pattern */ learned: number | null;
  /** the signal that set the learned minimum (cpu, memory, requests, …), when the pattern says */ binding: string | null;
  /** MinSize in force during the hour, as the forecast has it */ min: number | null;
  /** the pass changes MinSize for this hour (apply) or proposes to (dry run) */ change: { from: number; to: number; driver: PlanDriver; applied: boolean } | null;
  /** why this hour holds when the pattern or window wanted something else */ held: string | null;
}
export type PlanStatus = "driving" | "hand_set" | "learning" | "window" | "no_band" | "off" | "paused" | "no_consent" | "unknown";
export interface TimelinePlan {
  status: PlanStatus; headline: string; mode: string;
  hours: PlannedHour[];
  pattern: { confident: boolean; weeks: number; coverage: number; min_weeks: number; min_coverage: number; pressure_events: number; summary: string; computed_at: string; signals: string | null; signal_notes: string[]; targets: { cpu: number; mem: number; disk: number } | null } | null;
  current_min: number | null; floor: number | null; ceiling: number | null;
  blocked_until: string | null; hand_set_until: string | null;
  uncertain: string[];
}

export interface PlanInput {
  now: number;
  mode: string; paused: boolean; consent: boolean | null;
  band: { floor: number; ceiling: number | null } | null;
  pattern: CapacityPattern | null;
  current_min: number | null;
  state: EnvState | null;
  /** when the last applied or verified step landed (agent bounds, idle-floor trim, ceiling raise: one per 24 h; the hourly moves do not count) */ last_applied_at: string | null;
  /** the windowed schedule's inputs, used when the learned week is not in charge */ windows: QuietWindow[]; window_confidence: number;
  /** minute of the hour the pass runs at; null when the cron is not a plain hourly one */ pass_minute: number | null;
}

/** The minute of an hourly cron ("45 * * * *" → 45); null for anything else. Pure. */
export function passMinute(cron: string): number | null {
  const m = /^\s*(\d{1,2})\s+\*\s+\*\s+\*\s+\*\s*$/.exec(cron || "");
  return m && Number(m[1]) < 60 ? Number(m[1]) : null;
}

/**
 * The next 24 hours of MinSize, the hourly pass replayed forward. In apply mode each change lands at its pass; in dry run the minimum never moves and every hour that wants something else is a proposal. Pure.
 */
export function planTimeline(i: PlanInput): TimelinePlan {
  const pm = i.pass_minute ?? 45;
  const p = i.pattern;
  const patternInfo = p ? { confident: p.confident, weeks: p.weeks, coverage: p.coverage, min_weeks: MIN_WEEKS, min_coverage: MIN_COVERAGE, pressure_events: p.pressure_events, summary: p.summary, computed_at: p.computed_at, signals: p.signals?.summary ?? null, signal_notes: p.signals?.notes ?? [], targets: p.signals?.targets ?? null } : null;
  const uncertain: string[] = [];
  const base = { mode: i.mode, pattern: patternInfo, current_min: i.current_min, floor: i.band?.floor ?? null, ceiling: i.band?.ceiling ?? null, uncertain };
  const flat = (min: number | null): PlannedHour[] => Array.from({ length: TIMELINE_HOURS }, (_, k) => {
    const at = hourStart(i.now) + (k + 1) * H;
    return { at: new Date(at).toISOString(), label: ringLabel(ringIndex(at)), decided_at: new Date(at - H + pm * 60000).toISOString(), learned: p ? p.learned[ringIndex(at) % HOURS_PER_WEEK] : null, binding: p?.binding?.[ringIndex(at) % HOURS_PER_WEEK] ?? null, min, change: null, held: null };
  });
  const still = (status: PlanStatus, headline: string): TimelinePlan => ({ ...base, status, headline, hours: flat(i.current_min), blocked_until: null, hand_set_until: null });
  if (i.consent === false) return still("no_consent", "AdvisorAutoScale is not ON: the capacity action leaves this environment alone");
  if (i.mode === "off") return still("off", "the executor is off (ACT_MODE=off): nothing is planned or applied");
  if (i.paused) return still("paused", "auto-actions are paused: nothing is planned or applied until someone resumes");
  if (i.current_min == null) { uncertain.push("the configured MinSize could not be read, so the hours below show the learned minimum only"); return still("unknown", "MinSize not readable"); }
  if (!i.band) return still("unknown", "no readable band on the environment");

  const patternInCharge = i.band.ceiling != null && Boolean(p?.confident);
  const status0: PlanStatus = i.band.ceiling == null ? "no_band" : !p ? "learning" : !p.confident ? "learning" : "driving";
  const applies = i.mode === "apply";
  let min = i.current_min;
  let lastSet = i.state?.last_set ?? null;
  let handSetAt = i.state?.hand_set_at ?? null;
  let baseline = i.state?.baseline_min ?? i.current_min;
  // a MinSize the executor did not set: the next pass stamps it and the pattern waits a day
  const nextPass = hourStart(i.now) + pm * 60000 > i.now ? hourStart(i.now) + pm * 60000 : hourStart(i.now) + H + pm * 60000;
  if (patternInCharge && lastSet != null && min !== lastSet && !handSetAt) handSetAt = new Date(nextPass).toISOString();
  const handSetUntil = patternInCharge && lastSet != null && min !== lastSet && handSetAt ? new Date(new Date(handSetAt).getTime() + HAND_SET_HOURS * H).toISOString() : null;
  // when the next step (not an hourly move) may land
  const blockedUntil = i.last_applied_at ? new Date(i.last_applied_at.replace(" ", "T") + (/[zZ]|[+-]\d\d:?\d\d$/.test(i.last_applied_at) ? "" : "Z")).getTime() + MIN_HOURS_BETWEEN_CHANGES * H : 0;

  const hours: PlannedHour[] = [];
  for (let k = 1; k <= TIMELINE_HOURS; k++) {
    const at = hourStart(i.now) + k * H;
    const decidedAt = at - H + pm * 60000;
    const ring = ringIndex(at);
    const row: PlannedHour = { at: new Date(at).toISOString(), label: ringLabel(ring), decided_at: new Date(decidedAt).toISOString(), learned: p ? p.learned[ring % HOURS_PER_WEEK] : null, binding: p?.binding?.[ring % HOURS_PER_WEEK] ?? null, min, change: null, held: null };
    let wanted: number | null = null; let driver: PlanDriver = "none"; let heldWhy: string | null = null;
    if (patternInCharge) {
      const d = decidePattern({ pattern: p!, next: ring, current_min: min, last_set: lastSet, hand_set_at: handSetAt, now: decidedAt });
      if (d.hand_set) heldWhy = d.wanted == null && p!.learned[ring] !== min ? `MinSize was set by hand; the pattern resumes ${HAND_SET_HOURS} h after` : null;
      if (d.wanted != null) { wanted = d.wanted; driver = "pattern"; }
    } else {
      const w = decideWindow({ windows: i.windows, confidence: i.window_confidence, current_min: min, floor: i.band.floor, baseline_min: baseline, last_set: lastSet, next: ring });
      baseline = w.baseline_min;
      if (w.active && w.wanted != null && w.wanted !== min) { wanted = w.wanted; driver = "window"; }
    }
    if (wanted != null && wanted !== min) {
      row.change = { from: min, to: wanted, driver, applied: applies };
      if (applies) { min = wanted; lastSet = wanted; handSetAt = null; }
    } else if (heldWhy) row.held = heldWhy;
    row.min = min;
    hours.push(row);
  }

  const changes = hours.filter((h) => h.change).length;
  if (blockedUntil > i.now) uncertain.push(`the agent's bounds, the idle-floor trim and the ceiling raise wait until ${new Date(blockedUntil).toISOString().slice(0, 16).replace("T", " ")} UTC (one step per ${MIN_HOURS_BETWEEN_CHANGES} h); the hourly moves above do not`);
  if (!applies) uncertain.push("dry run: the pass records a proposal for each marked hour and changes nothing unless someone presses Apply on the row");
  uncertain.push("the idle-floor trim and the ceiling raise depend on the next 14 days of CPU and are not forecast; the pressure check (every few minutes) can raise MaxSize at any time");
  uncertain.push("the pattern is recomputed on every pass, and a new pressure event raises that hour and the one before at once");
  if (p && !p.signals) uncertain.push("this pattern was learned from the trigger's desired capacity only (before the signals): it cannot fall below the MinSize that was in force; the next pass relearns it from CPU, memory, requests, network and disk");
  for (const n of p?.signals?.notes ?? []) uncertain.push(n);

  const windowed = !patternInCharge && i.windows.length > 0 && status0 !== "no_band";
  const status: PlanStatus = handSetUntil && new Date(handSetUntil).getTime() > i.now ? "hand_set" : patternInCharge ? "driving" : windowed ? "window" : status0;
  const headline = status === "driving" ? `the learned week sets MinSize hour by hour (${p!.weeks} weeks, ${Math.round(p!.coverage * 100)} % of the hours covered): ${changes ? `${changes} change${changes === 1 ? "" : "s"} in the next ${TIMELINE_HOURS} h` : `no change in the next ${TIMELINE_HOURS} h`}`
    : status === "hand_set" ? `MinSize ${i.current_min} was set by hand: the pattern stands aside until ${handSetUntil!.slice(0, 16).replace("T", " ")} UTC`
    : status === "no_band" ? "no AdvisorScaleBand ceiling: the learned week does not drive MinSize; only the windowed schedule and the idle-floor trim can move it"
    : status === "window" ? `the learned week is ${p ? `not confident yet (${p.weeks} of ${MIN_WEEKS} weeks, ${Math.round(p.coverage * 100)} % of ${Math.round(MIN_COVERAGE * 100)} % coverage)` : "not computed yet"}: the group's quiet windows drive MinSize meanwhile${changes ? `, ${changes} change${changes === 1 ? "" : "s"} in the next ${TIMELINE_HOURS} h` : ""}`
    : status === "learning" ? `still learning: ${p ? `${p.weeks} of ${MIN_WEEKS} weeks, ${Math.round(p.coverage * 100)} % of ${Math.round(MIN_COVERAGE * 100)} % of the hours covered` : "no pattern computed yet (the next pass computes one)"}; MinSize stays at ${i.current_min} unless the idle-floor trim fires`
    : "unknown";
  return { ...base, status, headline, hours, blocked_until: blockedUntil > i.now ? new Date(blockedUntil).toISOString() : null, hand_set_until: handSetUntil };
}

// ---- the route's data ----------------------------------------------------------------------------------------------

/** The environment id for a name (the panel knows the name), from the balancer inventory or the stored pattern; an e-… id passes through. */
export function resolveEnvId(nameOrId: string): string | null {
  if (/^e-[a-z0-9]+$/i.test(nameOrId)) return nameOrId;
  const elb = db.prepare("select beanstalk_env_id from inventory_elb where beanstalk_env = ? and beanstalk_env_id is not null order by gone limit 1").get(nameOrId) as { beanstalk_env_id: string } | undefined;
  if (elb) return elb.beanstalk_env_id;
  return (db.prepare("select env_id from capacity_patterns where env_name = ? limit 1").get(nameOrId) as { env_id: string } | undefined)?.env_id ?? null;
}

/** The configured MinSize, read live; the latest ledger row's `before` when AWS cannot be read. */
async function currentMin(envId: string, region: string | null, accountId: string | null): Promise<{ min: number | null; max: number | null; source: string }> {
  try {
    const creds = executorCreds();
    const acct = creds.forAccount(accountId || null);
    const eb = new ElasticBeanstalkClient({ region: region || creds.region, credentials: acct.read });
    try {
      const env = (await eb.send(new DescribeEnvironmentsCommand({ EnvironmentIds: [envId], IncludeDeleted: false }))).Environments?.[0];
      if (env) { const f = await environmentFacts(eb, env); if (f.cfg.min != null) return { min: f.cfg.min, max: f.cfg.max, source: "live" }; }
    } finally { eb.destroy(); }
  } catch { /* fall back to the ledger */ }
  const row = db.prepare("select before_json from actions where kind in (?, ?) and resource = ? order by id desc limit 1").get(SCALE_KIND, PRESSURE_KIND, envId) as { before_json: string } | undefined;
  try { const b = row ? JSON.parse(row.before_json) : null; if (b?.MinSize != null) return { min: Number(b.MinSize), max: b.MaxSize != null ? Number(b.MaxSize) : null, source: "ledger" }; } catch { /* unreadable */ }
  return { min: null, max: null, source: "none" };
}

export interface TimelineRequest { env: string; region?: string | null; account_id?: string | null; floor?: number | null; ceiling?: number | null; consent?: boolean | null; now?: number }

/** Everything the panel shows: the forecast, the recent ledger rows of both capacity actions, the pressure events, the schedule of the passes. */
export async function environmentTimeline(r: TimelineRequest) {
  const now = r.now ?? Date.now();
  const envId = resolveEnvId(r.env);
  if (!envId) return null;
  const stored = latestPattern(envId);
  const pattern = stored?.pattern ?? null;
  const cur = await currentMin(envId, r.region ?? stored?.region ?? null, r.account_id ?? stored?.account_id ?? null);
  const floor = r.floor ?? pattern?.floor ?? null;
  const ceiling = r.floor != null ? (r.ceiling ?? null) : (pattern?.ceiling ?? null);
  const asg = stored?.asg ?? null;
  const review = asg ? latestReview(`asg:${asg}`) : null;
  const profile = asg ? latestProfile(`asg:${asg}`) : null;
  const agentWindows = review && review.verdict !== "keep_running" ? windowsFromSchedule(review.schedule) : [];
  const windows = agentWindows.length ? agentWindows : review?.verdict === "keep_running" ? [] : (profile?.quiet_windows ?? []);
  const lastApplied = db.prepare(`select applied_at from actions where kind = ? and resource = ? and status in ('applied', 'verified') and applied_at is not null
    and coalesce(json_extract(facts_json, '$.pattern'), 0) = 0 and coalesce(json_extract(facts_json, '$.window'), 0) = 0 order by applied_at desc limit 1`).get(SCALE_KIND, envId) as { applied_at: string } | undefined;
  const plan = planTimeline({
    now, mode: config.actMode, paused: pauseState(now).paused, consent: r.consent ?? null,
    band: floor != null ? { floor, ceiling } : null, pattern, current_min: cur.min, state: envState(envId),
    last_applied_at: lastApplied?.applied_at ?? null, windows, window_confidence: agentWindows.length ? 1 : profile?.confidence ?? 0,
    pass_minute: passMinute(config.actCron),
  });
  if (cur.source === "ledger") plan.uncertain.unshift("MinSize could not be read from AWS just now; the value is the one the latest ledger row saw");
  if (review?.group_min != null || review?.group_max != null) plan.uncertain.push(`the agent's review of the group proposes bounds (${review.group_min ?? "?"}–${review.group_max ?? "?"}); when they differ from the configured ones that proposal goes first and the hourly plan waits`);
  const changes = (db.prepare("select id, kind, status, mode, trigger, title, before_json, after_json, created_at, applied_at, verified_at, reverted_at, error from actions where kind in (?, ?) and resource = ? order by id desc limit 30").all(SCALE_KIND, PRESSURE_KIND, envId) as any[])
    .map(({ before_json, after_json, ...a }) => ({ ...a, before: safeJson(before_json), after: safeJson(after_json) }));
  return {
    environment_id: envId, env_name: stored?.env_name ?? r.env, asg, max_size: cur.max, min_source: cur.source,
    plan, changes, pressure: pressureEventRows(envId, 7).slice(0, 20),
    passes: { capacity: config.actCron, pressure: config.actPressureCron, next_capacity_pass: plan.hours[0]?.decided_at ?? null },
  };
}

const safeJson = (s: string | null) => { try { return s ? JSON.parse(s) : null; } catch { return null; } };

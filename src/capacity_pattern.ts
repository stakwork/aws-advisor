/**
 * The capacity pattern of an Elastic Beanstalk group: the minimum it needs at each hour of the week, learned.
 *
 * Beanstalk's trigger reacts to load after the fact: a breach, a launch, minutes in which the group runs short.
 * The pattern turns what the trigger asked for into what the group should already have. From the desired
 * capacity replayed hour by hour over the last `PATTERN_DAYS` (28, the group's scaling activities, the way the
 * capacity action reads them), each of the 168 hours of the week gets the p95 of the capacity the trigger wanted
 * at that hour across the weeks seen (the maximum while there are fewer than three weeks). Two corrections sit
 * on top: a **pressure event** (the group pinned at its ceiling with high CPU, src/actions/beanstalk_pressure.ts)
 * raises that hour and the one before it to the capacity that was running plus one, because that hour needed
 * more than it had; and the **band** (`AdvisorScaleBand=<floor>-<ceiling>`, the bare minimum and the ceiling a
 * person set) clamps everything: the learned minimum is never below the floor and never above the ceiling.
 *
 * The hourly executor pass (src/actions/beanstalk_scale.ts) sets MinSize for the coming hour to the learned
 * value once the pattern is confident (`MIN_WEEKS` weeks and most hours covered), one UpdateEnvironment when it
 * differs from what is configured, so capacity is warm before the hour the pattern says needs it and back at the
 * bare minimum in the hours it never did. A MinSize set by hand is left for `HAND_SET_HOURS` before the pattern
 * resumes. The pattern, its revisions and the pressure events behind it are stored here and mirrored to the graph
 * (the AdvisorNodePool node of the group; the Concept "The learned hourly minimum" holds the rule), so Jev's
 * group review and the agent read the same record the executor acts on.
 */
import { db } from "./db.js";
import { ringIndex, ringLabel } from "./usage_profile.js";

db.exec(`create table if not exists capacity_patterns (
  env_id text primary key, env_name text, asg text not null, region text, account_id text,
  computed_at text not null, json text not null
);
create table if not exists capacity_pressure_events (
  id integer primary key autoincrement, env_id text not null, env_name text, asg text not null,
  at text not null, ring integer not null, desired integer not null, max_size integer not null, cpu_avg real,
  action_id integer, note text
);
create index if not exists capacity_pressure_env on capacity_pressure_events(env_id, at)`);

export const PATTERN_DAYS = 28;
export const HOURS_PER_WEEK = 168;
/** Weeks of history before the pattern is trusted to move the minimum. */
export const MIN_WEEKS = 2;
/** The share of the week's hours that must have a sample before the pattern is confident. */
export const MIN_COVERAGE = 0.8;
/** How long a MinSize set by hand is honoured before the pattern resumes. */
export const HAND_SET_HOURS = 24;

export interface PatternHour { at: number; desired: number; cpu_avg: number | null }
export interface PressureEvent { at: number; desired: number }
export interface PatternInput { hours: PatternHour[]; pressure: PressureEvent[]; floor: number; ceiling: number | null; now?: number }
export interface CapacityPattern {
  computed_at: string; days: number; weeks: number; coverage: number; confident: boolean;
  floor: number; ceiling: number | null;
  /** The learned minimum per ring hour (0 = Sunday 00:00 UTC), clamped to the band. */
  learned: number[];
  /** What the trigger wanted per hour before the band and the pressure events: the p95 of the desired capacity across weeks. */
  wanted: number[];
  /** The pressure bump per hour (0 = none): the capacity that ran plus one, from the events of the window. */
  pressure: number[];
  pressure_events: number;
  /** The learned week, condensed: the distinct levels and the hours at each. */
  summary: string;
}

const p95 = (xs: number[]) => { const s = [...xs].sort((a, b) => a - b); return s[Math.min(s.length - 1, Math.floor(0.95 * (s.length - 1)))]; };
const clamp = (v: number, floor: number, ceiling: number | null) => Math.max(floor, ceiling == null ? v : Math.min(ceiling, v));
const weekOf = (at: number) => Math.floor(at / (7 * 86400000));

/** Learns the week from the replayed hours and the pressure events. Pure. */
export function learnPattern(i: PatternInput): CapacityPattern {
  const now = i.now ?? Date.now();
  const since = now - PATTERN_DAYS * 86400000;
  const perRing: number[][] = Array.from({ length: HOURS_PER_WEEK }, () => []);
  const weeks = new Set<number>();
  for (const h of i.hours) { if (h.at < since || h.at > now) continue; perRing[ringIndex(h.at)].push(h.desired); weeks.add(weekOf(h.at)); }
  const covered = perRing.filter((xs) => xs.length > 0).length;
  const coverage = Math.round((covered / HOURS_PER_WEEK) * 100) / 100;
  const wanted = perRing.map((xs) => (xs.length ? (weeks.size < 3 ? Math.max(...xs) : p95(xs)) : i.floor));
  const pressure = new Array<number>(HOURS_PER_WEEK).fill(0);
  let events = 0;
  for (const e of i.pressure) {
    if (e.at < since || e.at > now) continue;
    events++;
    const r = ringIndex(e.at), before = (r + HOURS_PER_WEEK - 1) % HOURS_PER_WEEK;
    pressure[r] = Math.max(pressure[r], e.desired + 1);
    pressure[before] = Math.max(pressure[before], e.desired + 1);
  }
  const learned = wanted.map((w, r) => clamp(Math.max(w, pressure[r]), i.floor, i.ceiling));
  const confident = weeks.size >= MIN_WEEKS && coverage >= MIN_COVERAGE;
  const days = Math.min(PATTERN_DAYS, Math.round((now - Math.min(...i.hours.map((h) => h.at), now)) / 86400000));
  return { computed_at: new Date(now).toISOString(), days, weeks: weeks.size, coverage, confident, floor: i.floor, ceiling: i.ceiling, learned, wanted, pressure, pressure_events: events, summary: summarise(learned) };
}

/** "1 for 120 h (Sat 00:00–Mon 06:00, …), 2 for 40 h, 3 for 8 h (Tue 09:00–17:00)": the levels and where they hold. Pure. */
export function summarise(learned: number[]): string {
  const levels = [...new Set(learned)].sort((a, b) => a - b);
  return levels.map((lv) => {
    const hours = learned.filter((x) => x === lv).length;
    const runs: string[] = [];
    let start = -1;
    for (let r = 0; r <= HOURS_PER_WEEK; r++) {
      const on = r < HOURS_PER_WEEK && learned[r] === lv;
      if (on && start < 0) start = r;
      if (!on && start >= 0) { runs.push(`${ringLabel(start)}–${ringLabel(r % HOURS_PER_WEEK)}`); start = -1; }
    }
    return `${lv} for ${hours} h${runs.length && runs.length <= 4 ? ` (${runs.join(", ")})` : ""}`;
  }).join("; ");
}

export interface PatternDecisionInput { pattern: CapacityPattern; next: number; current_min: number; last_set: number | null; hand_set_at: string | null; now?: number }
export interface PatternDecision { wanted: number | null; active: boolean; hand_set: boolean; reason: string }

/**
 * What MinSize should be for the coming hour: the learned value, unless the pattern is not confident, the value
 * is already there, or someone set the minimum by hand less than `HAND_SET_HOURS` ago. Pure.
 */
export function decidePattern(i: PatternDecisionInput): PatternDecision {
  const now = i.now ?? Date.now();
  const p = i.pattern;
  if (!p.confident) return { wanted: null, active: false, hand_set: false, reason: `the capacity pattern is not confident yet (${p.weeks} week(s), ${Math.round(p.coverage * 100)} % of the hours covered; needs ${MIN_WEEKS} weeks and ${Math.round(MIN_COVERAGE * 100)} %)` };
  const next = ((i.next % HOURS_PER_WEEK) + HOURS_PER_WEEK) % HOURS_PER_WEEK;
  const want = p.learned[next];
  const handSet = i.last_set != null && i.current_min !== i.last_set;
  if (handSet && i.hand_set_at && now - new Date(i.hand_set_at).getTime() < HAND_SET_HOURS * 3600000) {
    return { wanted: null, active: true, hand_set: true, reason: `MinSize ${i.current_min} was set by hand at ${i.hand_set_at.slice(0, 16)}Z (the executor last set ${i.last_set}); the pattern resumes ${HAND_SET_HOURS} h later` };
  }
  if (want === i.current_min) return { wanted: null, active: true, hand_set: handSet, reason: `the learned minimum for ${ringLabel(next)} is ${want}, which is what is configured` };
  return { wanted: want, active: true, hand_set: handSet, reason: `the learned minimum for ${ringLabel(next)} is ${want} (${p.weeks} weeks, ${p.pressure_events} pressure event(s) in ${p.days} days; the week: ${p.summary}): MinSize ${i.current_min} → ${want} before the hour starts` };
}

// ---- storage -------------------------------------------------------------------------------------------------------

export interface PatternRow { env_id: string; env_name: string | null; asg: string; region: string | null; account_id: string | null; pattern: CapacityPattern }

export function savePattern(r: PatternRow): void {
  db.prepare(`insert into capacity_patterns(env_id, env_name, asg, region, account_id, computed_at, json) values (?, ?, ?, ?, ?, ?, ?)
    on conflict(env_id) do update set env_name = excluded.env_name, asg = excluded.asg, region = excluded.region, account_id = excluded.account_id, computed_at = excluded.computed_at, json = excluded.json`)
    .run(r.env_id, r.env_name, r.asg, r.region, r.account_id, r.pattern.computed_at, JSON.stringify(r.pattern));
}

export function latestPattern(envId: string): PatternRow | null {
  const r = db.prepare("select * from capacity_patterns where env_id = ?").get(envId) as any;
  if (!r) return null;
  try { return { env_id: r.env_id, env_name: r.env_name, asg: r.asg, region: r.region, account_id: r.account_id, pattern: JSON.parse(r.json) }; } catch { return null; }
}

export function patternForGroup(asg: string): PatternRow | null {
  const r = db.prepare("select * from capacity_patterns where asg = ? order by computed_at desc limit 1").get(asg) as any;
  if (!r) return null;
  try { return { env_id: r.env_id, env_name: r.env_name, asg: r.asg, region: r.region, account_id: r.account_id, pattern: JSON.parse(r.json) }; } catch { return null; }
}

export function listPatterns(): PatternRow[] {
  return (db.prepare("select * from capacity_patterns order by computed_at desc").all() as any[]).flatMap((r) => { try { return [{ env_id: r.env_id, env_name: r.env_name, asg: r.asg, region: r.region, account_id: r.account_id, pattern: JSON.parse(r.json) }]; } catch { return []; } });
}

export interface PressureRow { env_id: string; env_name: string | null; asg: string; at: number; desired: number; max_size: number; cpu_avg: number | null; action_id?: number | null; note?: string | null }

/** Records a pressure event once per environment per hour (the check runs every few minutes; the hour is the unit the pattern learns). */
export function recordPressure(e: PressureRow): { id: number; fresh: boolean } {
  const hour = new Date(Math.floor(e.at / 3600000) * 3600000).toISOString();
  const had = db.prepare("select id from capacity_pressure_events where env_id = ? and at >= ? and at < ? limit 1").get(e.env_id, hour, new Date(new Date(hour).getTime() + 3600000).toISOString()) as { id: number } | undefined;
  if (had) { if (e.action_id) db.prepare("update capacity_pressure_events set action_id = coalesce(action_id, ?) where id = ?").run(e.action_id, had.id); return { id: had.id, fresh: false }; }
  const r = db.prepare("insert into capacity_pressure_events(env_id, env_name, asg, at, ring, desired, max_size, cpu_avg, action_id, note) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
    .run(e.env_id, e.env_name, e.asg, new Date(e.at).toISOString(), ringIndex(e.at), e.desired, e.max_size, e.cpu_avg, e.action_id ?? null, e.note ?? null);
  return { id: Number(r.lastInsertRowid), fresh: true };
}

export function pressureEvents(envId: string, days = PATTERN_DAYS): PressureEvent[] {
  return (db.prepare("select at, desired from capacity_pressure_events where env_id = ? and datetime(at) > datetime('now', ?) order by at").all(envId, `-${days} days`) as { at: string; desired: number }[])
    .map((r) => ({ at: new Date(r.at).getTime(), desired: r.desired }));
}

export function pressureEventRows(envId: string, days = PATTERN_DAYS): { id: number; at: string; ring: number; label: string; desired: number; max_size: number; cpu_avg: number | null; action_id: number | null }[] {
  return (db.prepare("select id, at, ring, desired, max_size, cpu_avg, action_id from capacity_pressure_events where env_id = ? and datetime(at) > datetime('now', ?) order by at desc").all(envId, `-${days} days`) as any[])
    .map((r) => ({ ...r, label: ringLabel(r.ring) }));
}

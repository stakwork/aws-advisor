/**
 * When an auto-parked box goes to sleep next, and when it wakes: the office-hours pass (src/actions/schedule_hours.ts)
 * replayed forward. The pass runs at the executor's minute (ACT_CRON, :45 by default) and decides for the top of the
 * coming hour, so a box sleeps at the first pass whose coming hour the window wants stopped and wakes at the first
 * pass after that whose coming hour wants it running. A stop a person reverted holds the box awake for
 * WOKEN_BY_HAND_HOURS. Idle parking (src/actions/swarm_park.ts) can still stop a box earlier; it is not predicted.
 */
import { db } from "./db.js";
import { config } from "./config.js";
import { AUTO_PARK_TAG, isOn, isOff } from "./consent.js";
import { KIND as SCHEDULE_KIND, SCHEDULE_TAG, WOKEN_BY_HAND_HOURS, describeSchedule, nextHour, parseSchedule, wantedState, type Schedule } from "./actions/schedule_hours.js";
import { passMinute } from "./capacity_timeline.js";
import { pauseState } from "./executor.js";

/** Look this far ahead for the next change; a window that never changes in a week never will. */
const HORIZON_PASSES = 8 * 24;

/** The next pass that stops the box and the next one that starts it, from the state now. Pure. */
export function nextParkTimes(s: Schedule, state: string, now: Date, minute: number, holdUntil: Date | null = null): { sleep_at: Date | null; wake_at: Date | null } {
  let p = new Date(now.getTime()); p.setUTCMinutes(minute, 0, 0);
  if (p.getTime() <= now.getTime()) p = new Date(p.getTime() + 3600000);
  const passes: Date[] = [];
  for (let i = 0; i < HORIZON_PASSES; i++) passes.push(new Date(p.getTime() + i * 3600000));
  const wants = (at: Date) => wantedState(s, nextHour(at));
  const find = (from: number, want: "running" | "stopped") => {
    for (let i = from; i < passes.length; i++) if (wants(passes[i]) === want && !(want === "stopped" && holdUntil && passes[i] < holdUntil)) return i;
    return -1;
  };
  if (state === "stopped") {
    const w = find(0, "running");
    const sl = w < 0 ? -1 : find(w + 1, "stopped");
    return { wake_at: w < 0 ? null : passes[w], sleep_at: sl < 0 ? null : passes[sl] };
  }
  const sl = find(0, "stopped");
  const w = sl < 0 ? -1 : find(sl + 1, "running");
  return { sleep_at: sl < 0 ? null : passes[sl], wake_at: w < 0 ? null : passes[w] };
}

export interface ParkOutlook {
  schedule: string | null;
  /** tag: advisor:schedule on the box; review / profile: the usage review's or the profile's window (AdvisorAutoPark=ON). */
  source: "tag" | "review" | "profile" | null;
  sleep_at: string | null;
  wake_at: string | null;
  /** Why there is no time, or what keeps the time from happening (dry run, paused, held awake). */
  note: string | null;
}

/** Until when a reverted stop holds the box awake, or null. */
function heldUntil(instanceId: string): Date | null {
  const r = db.prepare(`select max(reverted_at) as at from actions where kind = ? and resource = ? and status = 'reverted' and json_extract(after_json, '$.state') = 'stopped' and datetime(reverted_at) > datetime('now', ?)`)
    .get(SCHEDULE_KIND, instanceId, `-${WOKEN_BY_HAND_HOURS} hours`) as { at: string | null } | undefined;
  return r?.at ? new Date(new Date(r.at.includes("T") ? r.at : `${r.at.replace(" ", "T")}Z`).getTime() + WOKEN_BY_HAND_HOURS * 3600000) : null;
}

/** The outlook for one instance from its live tags and state. */
export async function parkOutlook(instanceId: string, tags: Record<string, string>, state: string, poolKind: string | null, now = new Date()): Promise<ParkOutlook> {
  const none = (note: string): ParkOutlook => ({ schedule: null, source: null, sleep_at: null, wake_at: null, note });
  if (tags["advisor:hands-off"] != null) return none("tagged advisor:hands-off");
  if (isOff(tags[AUTO_PARK_TAG])) return none(`${AUTO_PARK_TAG}=${tags[AUTO_PARK_TAG]}: never stopped or started`);
  if (poolKind) return none(`member of a ${poolKind} pool: its controller decides`);
  let text = tags[SCHEDULE_TAG] ?? null;
  let source: ParkOutlook["source"] = text != null ? "tag" : null;
  if (text == null) {
    if (!isOn(tags[AUTO_PARK_TAG])) return none(`no ${SCHEDULE_TAG} tag and ${AUTO_PARK_TAG} is not ON`);
    const { scheduleFor } = await import("./usage_review.js");
    const f = scheduleFor(instanceId);
    if (!f.schedule) return none(f.note);
    text = f.schedule; source = f.source;
  }
  const s = parseSchedule(text);
  if ("error" in s) return { ...none(`the window does not parse: ${s.error}`), schedule: text, source };
  const base = { schedule: describeSchedule(s), source };
  if (config.actMode === "off") return { ...base, sleep_at: null, wake_at: null, note: "the executor is off (Settings > Auto-actions > Mode)" };
  const minute = passMinute(config.actCron);
  if (minute == null) return { ...base, sleep_at: null, wake_at: null, note: `the executor pass runs on "${config.actCron}", not once an hour: no time to predict` };
  if (state !== "running" && state !== "stopped") return { ...base, sleep_at: null, wake_at: null, note: `state ${state}: waiting for it to settle` };
  const hold = heldUntil(instanceId);
  const t = nextParkTimes(s, state, now, minute, hold);
  const notes: string[] = [];
  if (config.actMode === "dry_run") notes.push("dry run: the pass proposes the stop, nothing happens until a row is applied");
  const pause = pauseState(now.getTime());
  if (pause.paused) notes.push(`auto-actions are paused${pause.until ? ` until ${pause.until}` : ""}`);
  if (hold && state === "running") notes.push(`woken by hand: held awake until ${hold.toISOString()}`);
  if (!t.sleep_at && state === "running") notes.push("the window keeps it running all week");
  return { ...base, sleep_at: t.sleep_at?.toISOString() ?? null, wake_at: t.wake_at?.toISOString() ?? null, note: notes.join("; ") || null };
}

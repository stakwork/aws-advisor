/**
 * Step progress on a recommendation: which steps of its plan a human has ticked, and when to look at it again.
 *
 * A recommendation is worked through either the tailored resolution's plan (src/resolve.ts) or the static
 * playbook's steps (src/playbooks.ts); `plan` names which one ("resolution:<id>" or "playbook:<control id>") so
 * the checklist is not misread against a later, different plan. Stored as JSON in recommendations.progress.
 */

export const PLAN_KEY = /^(resolution:\d{1,12}|playbook:[\w.\-]{1,120})$/;
export const MAX_STEPS = 50;

export interface Progress {
  plan: string;
  total: number;
  /** zero-based indices of the ticked steps, ascending */
  done: number[];
  /** YYYY-MM-DD, the day to look at this again (flow logs need a week of data, a cooling-off period, ...) */
  follow_up: string | null;
  updated_at: string;
}

export function parseProgress(raw: unknown): Progress | null {
  if (typeof raw !== "string" || !raw) return null;
  try {
    const p = JSON.parse(raw);
    if (!p || typeof p !== "object" || typeof p.plan !== "string" || !Array.isArray(p.done)) return null;
    return { plan: p.plan, total: Number(p.total) || 0, done: p.done.map(Number).filter(Number.isInteger), follow_up: p.follow_up || null, updated_at: String(p.updated_at || "") };
  } catch { return null; }
}

/** Validates a progress body from the UI; the whole checklist is sent every time, so there is no merge to get wrong. */
export function validateProgress(body: any, now = new Date()): { error: string } | { progress: Progress } {
  const { plan, total, done, follow_up } = body || {};
  if (typeof plan !== "string" || !PLAN_KEY.test(plan)) return { error: 'plan must be "resolution:<id>" or "playbook:<control id>"' };
  if (!Number.isInteger(total) || total < 0 || total > MAX_STEPS) return { error: `total must be an integer between 0 and ${MAX_STEPS}` };
  if (!Array.isArray(done) || !done.every((i) => Number.isInteger(i) && i >= 0 && i < total)) return { error: "done must be a list of step indices below total" };
  let followUp: string | null = null;
  if (follow_up !== undefined && follow_up !== null && follow_up !== "") {
    if (typeof follow_up !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(follow_up) || Number.isNaN(Date.parse(follow_up))) return { error: "follow_up must be a YYYY-MM-DD date" };
    followUp = follow_up;
  }
  return { progress: { plan, total, done: [...new Set(done as number[])].sort((a, b) => a - b), follow_up: followUp, updated_at: now.toISOString().slice(0, 19).replace("T", " ") } };
}

/**
 * Ticking the first step of an open (or snoozed) recommendation is the moment it becomes work in progress: it
 * moves to "pending" by itself so the pending list is the list of things someone is in the middle of. Nothing
 * else changes status here; a human marks it done, and an approved item stays approved while it is worked.
 */
export function statusAfterProgress(status: string, progress: Progress): string | null {
  if ((status === "open" || status === "snoozed") && progress.done.length > 0) return "pending";
  return null;
}

/** One line for a list row: "2 of 6 steps" plus the follow-up day, and whether that day has come. */
export function progressSummary(p: Progress | null, today: string): { text: string; due: boolean } | null {
  if (!p) return null;
  const parts: string[] = [];
  if (p.total > 0) parts.push(`${p.done.length} of ${p.total} steps`);
  const due = Boolean(p.follow_up && p.follow_up <= today);
  if (p.follow_up) parts.push(due ? `check again: due ${p.follow_up}` : `check again ${p.follow_up}`);
  return parts.length ? { text: parts.join(" · "), due } : null;
}

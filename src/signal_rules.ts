/**
 * Which "use signals" count. Probe 1.4 matches a container's log against named patterns (SIGNAL_KINDS) and
 * reports a count per kind; whether a kind means a human did something depends on the image (boltwall logs an
 * "authorization" line for every macaroon check, a relay logs "new message" only when a message arrives). Rather
 * than a probe script per instance, the verdicts live here, per image: a rule says that for images matching a
 * pattern a kind is `noise` (never counts) or `signal` (counts, the default). A person sets a rule from the EC2
 * drawer's chips; the agent may only propose one (`status = proposed`, from the propose_signal_rule tool), which
 * the drawer shows for confirmation. `effectiveSignals` applies the confirmed rules to a container's kinds and
 * is what the history, the use summary and the rules see.
 */
import { db } from "./db.js";

db.exec(`create table if not exists signal_rules (
  id integer primary key autoincrement,
  image_pattern text not null,
  kind text not null,
  verdict text not null,
  note text,
  decided_by text,
  status text not null default 'confirmed',
  created_at text not null default (datetime('now')),
  unique(image_pattern, kind)
)`);

/** The named patterns the probe script matches (keep in step with SIGS in src/ssm.ts PROBE_SCRIPT). */
export const SIGNAL_KINDS: Record<string, string> = {
  login: "a login or sign-in line",
  auth: "an authentication or authorization line (often machine-to-machine: check the samples)",
  payment: "a payment, invoice or keysend",
  message: "a message sent, received or new",
  join: "someone joined",
  upload: "an upload",
  write_request: "a POST, PUT, PATCH or DELETE request line",
  websocket: "a websocket opening",
  subscribe: "a subscribe or checkout",
};
export const VERDICTS = ["noise", "signal"] as const;
export type Verdict = (typeof VERDICTS)[number];

export interface SignalRule { id: number; image_pattern: string; kind: string; verdict: Verdict; note: string | null; decided_by: string | null; status: "confirmed" | "proposed"; created_at: string }

/** The image without its tag or digest: `sphinxlightning/sphinx-boltwall:latest` → `sphinxlightning/sphinx-boltwall`. */
export const imageKey = (image: string) => String(image || "").replace(/@sha256:[0-9a-f]+$/i, "").replace(/:[^/]+$/, "");

export function listRules(status?: "confirmed" | "proposed"): SignalRule[] {
  return (status ? db.prepare("select * from signal_rules where status = ? order by image_pattern, kind").all(status) : db.prepare("select * from signal_rules order by status desc, image_pattern, kind").all()) as SignalRule[];
}

export function validateRule(input: { image_pattern?: unknown; kind?: unknown; verdict?: unknown; note?: unknown }): { image_pattern: string; kind: string; verdict: Verdict; note: string | null } {
  const image_pattern = String(input.image_pattern ?? "").trim();
  if (!image_pattern || image_pattern.length > 200 || /[\s"'\\]/.test(image_pattern)) throw new Error("image_pattern: a substring of the image name (no spaces or quotes), e.g. sphinxlightning/sphinx-boltwall");
  const kind = String(input.kind ?? "").trim();
  if (!(kind in SIGNAL_KINDS)) throw new Error(`kind: one of ${Object.keys(SIGNAL_KINDS).join(", ")}`);
  const verdict = String(input.verdict ?? "").trim() as Verdict;
  if (!VERDICTS.includes(verdict)) throw new Error("verdict: noise or signal");
  const note = input.note == null ? null : String(input.note).trim().slice(0, 500) || null;
  return { image_pattern, kind, verdict, note };
}

/** Inserts or replaces the rule for (image_pattern, kind). A confirmed rule is never downgraded to proposed by a proposal. */
export function upsertRule(input: { image_pattern: string; kind: string; verdict: Verdict; note: string | null; decided_by: string | null; status: "confirmed" | "proposed" }): SignalRule {
  const v = validateRule(input);
  const existing = db.prepare("select * from signal_rules where image_pattern = ? and kind = ?").get(v.image_pattern, v.kind) as SignalRule | undefined;
  if (existing && existing.status === "confirmed" && input.status === "proposed") {
    if (existing.verdict === v.verdict) return existing;
    const e: any = new Error(`a confirmed rule already says ${v.kind} is ${existing.verdict} for ${v.image_pattern}${existing.note ? ` (${existing.note})` : ""}; a person has to change it`); e.code = "confirmed"; throw e;
  }
  db.prepare(`insert into signal_rules(image_pattern, kind, verdict, note, decided_by, status) values (?, ?, ?, ?, ?, ?)
    on conflict(image_pattern, kind) do update set verdict = excluded.verdict, note = excluded.note, decided_by = excluded.decided_by, status = excluded.status, created_at = datetime('now')`)
    .run(v.image_pattern, v.kind, v.verdict, v.note, input.decided_by, input.status);
  return db.prepare("select * from signal_rules where image_pattern = ? and kind = ?").get(v.image_pattern, v.kind) as SignalRule;
}

export function confirmRule(id: number, by: string | null): SignalRule | null {
  db.prepare("update signal_rules set status = 'confirmed', decided_by = coalesce(?, decided_by) where id = ?").run(by, id);
  return (db.prepare("select * from signal_rules where id = ?").get(id) as SignalRule | undefined) ?? null;
}

export const deleteRule = (id: number) => db.prepare("delete from signal_rules where id = ?").run(id).changes > 0;

/** The confirmed rules that apply to an image: pattern equal to the image key, or contained in the image name. */
export function rulesFor(image: string): SignalRule[] {
  const key = imageKey(image);
  return listRules("confirmed").filter((r) => r.image_pattern === key || image.includes(r.image_pattern) || key.includes(r.image_pattern));
}

export interface EffectiveSignals { signal_lines: number; noise_lines: number; noise_kinds: string[]; signal_kinds: Record<string, number>; rules: SignalRule[] }

/** Applies the confirmed rules to a container's per-kind counts: what counts as use, what was ruled noise. */
export function effectiveSignals(image: string, kinds: Record<string, number>, rawLines?: number): EffectiveSignals {
  const rules = rulesFor(image);
  const noise = new Set(rules.filter((r) => r.verdict === "noise").map((r) => r.kind));
  const out: EffectiveSignals = { signal_lines: 0, noise_lines: 0, noise_kinds: [], signal_kinds: {}, rules };
  for (const [k, n] of Object.entries(kinds || {})) {
    if (noise.has(k)) { out.noise_lines += n; out.noise_kinds.push(k); } else { out.signal_lines += n; out.signal_kinds[k] = n; }
  }
  // a line can match two kinds, so the per-kind sum overcounts; the probe's exact line count wins when nothing was ruled out
  if (!out.noise_kinds.length && rawLines != null) out.signal_lines = rawLines;
  return out;
}

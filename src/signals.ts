/**
 * The use-signal patterns the probe matches container logs against. They are a document parameter of the SSM
 * probe (`signals`, since probe 1.5) so the list can be revised from Settings › Probe pass without a new probe
 * version: the advisor passes the current value on every SendCommand, the document's default is the list below.
 * The format is `name=regex` entries joined by `;;`; the regex is a POSIX ERE for `grep -iE` on the box. No
 * dependencies: config.ts, ssm.ts and signal_rules.ts all import this.
 */

export const SIGNALS_SEP = ";;";

/** name → [regex, what it means]. The names are the kinds the rules and the drawer chips speak of. */
export const DEFAULT_SIGNALS: [string, string, string][] = [
  ["login", "log(ged)? ?in|sign(ed)?[- ]?in", "a login or sign-in line"],
  ["auth", "authenticat|authoriz", "an authentication or authorization line (often machine-to-machine: check the samples)"],
  ["payment", "payment|invoice|keysend", "a payment, invoice or keysend"],
  ["message", "sent message|new message|received message", "a message sent, received or new"],
  ["join", "joined", "someone joined"],
  ["upload", "upload", "an upload"],
  ["write_request", "\"(POST|PUT|PATCH|DELETE) ", "a POST, PUT, PATCH or DELETE request line"],
  ["websocket", "websocket|ws open", "a websocket opening"],
  ["subscribe", "subscribe|checkout", "a subscribe or checkout"],
];

export const DEFAULT_SIGNALS_STRING = DEFAULT_SIGNALS.map(([n, re]) => `${n}=${re}`).join(SIGNALS_SEP);

/** What the SSM document's parameter accepts: one line, no single quote (the script wraps the value in single quotes). */
/**
 * No quotes or newlines, for the SSM document only; the length cap (4000) is the parameter's maxChars, not the
 * pattern. Recent SSM agents compile allowedPattern with Go's RE2 before running the document, and RE2 rejects a
 * repeat count over 1000, counting nested groups by their product: `(?:[^']{1,1000}){1,4}` compiled server-side
 * but every agent that checks it dropped the job ("invalid repeat count"), so the pattern carries no counts at all.
 * A backtracking engine (JavaScript's) can take minutes on a near-miss of a counted pattern, which is one more
 * reason parseSignals checks the length and the characters itself and never uses this pattern.
 */
export const SIGNALS_ALLOWED_PATTERN = "^[^'\\r\\n]+$";
export const SIGNALS_MAX_CHARS = 4000;
export const NAME_RE = /^[a-z][a-z0-9_]{0,23}$/;
export const MAX_PATTERNS = 40;

export interface SignalPattern { name: string; regex: string; description: string }

/** Parses and checks a setting value; throws with a message for the Settings page. */
export function parseSignals(value: string): SignalPattern[] {
  // leading whitespace is dropped, trailing whitespace is kept: a pattern may end in a space (`"POST `)
  const v = String(value ?? "").replace(/^\s+/, "");
  if (!v) throw new Error("at least one pattern; the default list is in the placeholder");
  if (v.length > SIGNALS_MAX_CHARS) throw new Error(`at most ${SIGNALS_MAX_CHARS} characters`);
  if (/['\r\n]/.test(v)) throw new Error("no single quotes or line breaks (the probe wraps the value in single quotes)");
  const out: SignalPattern[] = []; const seen = new Set<string>();
  for (const part of v.split(SIGNALS_SEP)) {
    const entry = part.replace(/^\s+/, ""); if (!entry.trim()) continue;
    const eq = entry.indexOf("=");
    if (eq <= 0) throw new Error(`"${entry.slice(0, 40)}": expected name=regex`);
    const name = entry.slice(0, eq).trim(), regex = entry.slice(eq + 1).replace(/^\s+/, "");
    if (!NAME_RE.test(name)) throw new Error(`"${name}": a name is lowercase letters, digits and _ (up to 24)`);
    if (seen.has(name)) throw new Error(`"${name}" appears twice`);
    if (!regex || regex.length > 200) throw new Error(`"${name}": the regex is 1 to 200 characters`);
    try { new RegExp(regex, "i"); } catch { throw new Error(`"${name}": "${regex}" is not a valid regex`); }
    seen.add(name);
    out.push({ name, regex, description: DEFAULT_SIGNALS.find(([n, re]) => n === name && re === regex)?.[2] ?? `custom pattern /${regex}/i` });
  }
  if (!out.length) throw new Error("at least one pattern");
  if (out.length > MAX_PATTERNS) throw new Error(`at most ${MAX_PATTERNS} patterns`);
  return out;
}

export const serialiseSignals = (ps: SignalPattern[]) => ps.map((p) => `${p.name}=${p.regex}`).join(SIGNALS_SEP);

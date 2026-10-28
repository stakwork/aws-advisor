// Vendored from the vuln-graph strut workspace (steps/custom/sec/_version.ts), the public graph's own copy: the two MUST
// stay identical, since a range's keys there and an installed version's sort_key here are compared as plain strings.
// src/__tests__/sec_identity.test.ts diffs them when that checkout is beside this one. Edit there, copy here.

/**
 * Version strings as something a graph can compare without a model and
 * without Cypher knowing semver: `sortKey` maps a version to a string whose
 * lexical order is the version order for semver-like schemes, so a range
 * check is `introduced_key <= key < fixed_key` — the gte/lt that
 * `graph/find` already offers.
 *
 * The rule (documented, deterministic, no exceptions):
 *   - a leading `v` or `V` before a digit is dropped;
 *   - the numeric core (`1.2.3`, up to SEGMENTS dot-separated numbers) is
 *     zero-padded to 8 digits per segment and to SEGMENTS segments, so `1.1`
 *     and `1.1.0` are the same key and `1.1.0.5` sorts after `1.1.0`;
 *   - a release with nothing after the core ends in `=`;
 *   - a semver prerelease (`-rc1`, `-beta.2`) ends in `-` + the normalized
 *     tag, which sorts BEFORE `=`: a prerelease precedes its release;
 *   - build metadata (`+build.7`) is ignored, as semver says;
 *   - anything else attached to the core (`1.1.1k`, `2.4p1`, `7.4.0_1`)
 *     ends in `=` + the normalized suffix, which sorts AFTER the bare
 *     release: OpenSSL letters and OpenSSH patch levels are later releases.
 *
 * Debian and RPM versions (`1:9.6p1-3ubuntu13.5`, epochs, `~`) do not sort
 * lexically; the compare step handles them with dpkg's and rpm's algorithms,
 * and their ranges are resolved there, not by key.
 */

export const SEGMENTS = 5;
const PAD = 8;

const padNum = (s: string): string => s.replace(/^0+(?=\d)/, "").padStart(PAD, "0");

/** Lowercase, numbers padded, separators folded to `.`: `rc1` → `rc.00000001`, `Beta-2` → `beta.00000002`. */
function normalizeTag(tag: string): string {
  return tag
    .toLowerCase()
    .replace(/([a-z])(\d)/g, "$1.$2")
    .replace(/(\d)([a-z])/g, "$1.$2")
    .split(/[.\-_~+]+/)
    .filter(Boolean)
    .map((p) => (/^\d+$/.test(p) ? padNum(p) : p))
    .join(".");
}

export function sortKey(version: string): string {
  let v = String(version ?? "").trim();
  if (/^[vV]\d/.test(v)) v = v.slice(1);
  const m = /^(\d+(?:\.\d+)*)/.exec(v);
  if (!m) return `~${normalizeTag(v)}`; // not a version at all: sorts after every real one, still deterministic
  const core = m[1]!.split(".").slice(0, SEGMENTS);
  while (core.length < SEGMENTS) core.push("0");
  const key = core.map(padNum).join(".");
  let rest = v.slice(m[1]!.length);
  const plus = rest.indexOf("+");
  if (plus >= 0) rest = rest.slice(0, plus);
  if (!rest) return `${key}=`;
  if (rest.startsWith("-")) return `${key}-${normalizeTag(rest.slice(1))}`;
  return `${key}=${normalizeTag(rest)}`;
}

/** The key just above `version`: the exclusive upper bound of a range that INCLUDES it (`lessThanOrEqual`, a single affected version). */
export const justAbove = (version: string): string => `${sortKey(version)}~`;

/** The lowest key: the lower bound of a range that starts at nothing (`0`, `*`). */
export const KEY_MIN = sortKey("0");
/** Above every key: the upper bound of an open-ended range. `~` is the highest printable ASCII character. */
export const KEY_MAX = "~";

/** `a` before `b` in version order, by key; 0 when equal. */
export const compareKeys = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

/** Whether `version` falls in `[introducedKey, fixedKey)`. */
export function inRange(version: string, introducedKey: string, fixedKey: string): boolean {
  const k = sortKey(version);
  return k >= introducedKey && k < fixedKey;
}

/**
 * Every console line starts with the time it was written, UTC in ISO 8601, so a log read later says when as well as what:
 * `2026-10-30T17:45:12.345Z [probe-pass:sbom] i-0b19ba7373c82230f done in 412 s; ...`. src/index.ts imports this module first, so
 * what the other modules print while loading is stamped too; nothing else to call. A first argument that is a string keeps its
 * printf-style specifiers (the stamp is prefixed into the same string); a line that already begins with a timestamp is left alone.
 */
const METHODS = ["log", "info", "warn", "error", "debug"] as const;
const STAMPED = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/;

/** The arguments of one console call with the time in front. Pure. */
export function withStamp(args: unknown[], now: Date = new Date()): unknown[] {
  const stamp = now.toISOString();
  if (typeof args[0] === "string") return STAMPED.test(args[0]) ? args : [`${stamp} ${args[0]}`, ...args.slice(1)];
  return [stamp, ...args];
}

let installed = false;
/** Wraps the console once; a second call does nothing. */
export function stampConsole(): void {
  if (installed) return;
  installed = true;
  for (const m of METHODS) {
    const orig = console[m].bind(console);
    console[m] = (...args: unknown[]) => orig(...withStamp(args));
  }
}

stampConsole();

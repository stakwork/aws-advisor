import { db } from "./db.js";
import { adapterFor } from "./adapters/index.js";

/**
 * The one way an alert row is written: with the provider that raised it and the account it is about, both decided
 * here when the row is created (the provider's own `accountOf`, from the resource and the details), never guessed
 * afterwards. Every raiser (the watcher, the review, the inventory, a provider's rules) goes through this.
 */

const sqliteNow = () => new Date().toISOString().replace("T", " ").slice(0, 19);
const ins = db.prepare("insert into alerts(kind, resource, message, details, provider, account_id, notified_at, notify_result) values (?, ?, ?, ?, ?, ?, ?, ?)");

/** The account a provider's row belongs to: the adapter's answer, else its primary account when it knows one. */
export function rowAccount(provider: string, resource: string | null | undefined, details?: Record<string, unknown> | string | null, opts: { primary?: boolean } = {}): string | null {
  const a = adapterFor(provider); if (!a) return null;
  let d: Record<string, unknown> | null = null;
  if (typeof details === "string") { try { d = JSON.parse(details); } catch { d = null; } } else d = details ?? null;
  try {
    const own = a.accountOf(resource, d); if (own || opts.primary === false) return own;
    const primary = a.primaryAccountId(); return primary && primary !== "unknown" ? primary : null;
  } catch { return null; }
}

export interface NewAlert { kind: string; resource: string | null; message: string; details: string | null; account_id?: string | null;
  /** an alert written as already handled (a provider's first rules pass: everything is true at once, nothing pages) */
  skip_notify?: string }

export function insertAlert(provider: string, a: NewAlert): { lastInsertRowid: number | bigint; changes: number } {
  return ins.run(a.kind, a.resource, a.message, a.details, provider, a.account_id ?? rowAccount(provider, a.resource, a.details), a.skip_notify ? sqliteNow() : null, a.skip_notify ?? null);
}

/** A drop-in for the prepared `insert into alerts(kind, resource, message, details)` the raisers used: the same positional `run`, with the kind fixed when given. */
export function alertInsert(provider: string, kind?: string): { run: (...args: any[]) => { lastInsertRowid: number | bigint; changes: number } } {
  return { run: (...args: any[]) => {
    const [k, resource, message, details] = kind ? [kind, ...args] : args;
    return insertAlert(provider, { kind: String(k), resource: resource == null ? null : String(resource), message: String(message), details: details == null ? null : String(details) });
  } };
}

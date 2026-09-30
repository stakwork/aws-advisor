/**
 * What "run as me" would do, shown before anyone pastes credentials: the row's own apply (and revert) run as a dry
 * run, so the list comes from the code that will run and cannot drift from it.
 *
 * Inside a preview every AWS SDK send goes through one hook on the SDK's shared Client class. A read (Describe…,
 * List…, Get…) is sent for real under the advisor's read credentials for the row's account, so the preview sees the
 * account as it is; anything else is recorded and answered with an empty reply, never sent. The rule is by
 * operation name and ignores which credentials the client holds, so a module that wrote through its read client
 * would still be caught. Local bookkeeping (a SQLite write the apply makes) is skipped the same way and listed.
 *
 * The hook is scoped with AsyncLocalStorage: a preview never touches an executor pass or a request running beside it.
 * A write whose reply the apply needs gets an empty one, so the steps after it may stop early; the preview says so.
 */
import { AsyncLocalStorage } from "node:async_hooks";
import { STSClient } from "@aws-sdk/client-sts";
import { db } from "./db.js";
import { actionModules, credsForAccount, executorCreds, getAction, proposalOf, type AccountCreds, type Creds } from "./executor.js";

export interface PreviewCall { service: string; operation: string; region: string | null; iam: string; cli: string; input: unknown }
export interface PreviewSide { writes: PreviewCall[]; reads: string[]; local: string[]; result: string | null; stopped: string | null }
export interface ActionPreview { action_id: number; kind: string; account_id: string | null; region: string; apply: PreviewSide; revert: PreviewSide }

interface Recorder { writes: PreviewCall[]; reads: string[]; local: string[] }
const store = new AsyncLocalStorage<Recorder>();

/** Operations that only read: sent for real in a preview. Everything else is recorded and not sent. Pure. */
export const isReadOperation = (op: string) => /^(Describe|List|Get|Head|Lookup|Search|BatchGet|Simulate)[A-Z]/.test(op);

/** The CLI's name for a service (`aws <this> …`), from the SDK's serviceId. Pure. */
export function cliService(serviceId: string): string {
  const m: Record<string, string> = { "Elastic Beanstalk": "elasticbeanstalk", "CloudWatch Logs": "logs", "S3": "s3api", "Auto Scaling": "autoscaling", "Elastic Load Balancing v2": "elbv2", "Route 53": "route53" };
  return m[serviceId] ?? serviceId.toLowerCase().replace(/\s+/g, "");
}

/** The IAM action a call needs. S3 names a few differently from the API. Pure. */
export function iamAction(serviceId: string, op: string): string {
  const s3: Record<string, string> = { PutBucketLifecycleConfiguration: "PutLifecycleConfiguration", DeleteBucketLifecycle: "PutLifecycleConfiguration", PutBucketMetricsConfiguration: "PutMetricsConfiguration", DeleteBucketMetricsConfiguration: "PutMetricsConfiguration" };
  if (serviceId === "S3") return `s3:${s3[op] ?? op}`;
  const m: Record<string, string> = { "Elastic Beanstalk": "elasticbeanstalk", "CloudWatch Logs": "logs", "Auto Scaling": "autoscaling", "Elastic Load Balancing v2": "elasticloadbalancing", "Route 53": "route53", "EFS": "elasticfilesystem" };
  return `${m[serviceId] ?? serviceId.toLowerCase().replace(/\s+/g, "")}:${op}`;
}

/** `DBClusterIdentifier` → `db-cluster-identifier`. Pure. */
export const kebab = (s: string) => s.replace(/([a-z0-9])([A-Z])/g, "$1-$2").replace(/([A-Z])([A-Z][a-z])/g, "$1-$2").toLowerCase();
const quote = (s: string) => (/^[A-Za-z0-9_\-.:\/=@,+]+$/.test(s) ? s : `'${s.replace(/'/g, `'\\''`)}'`);
const jsonable = (v: unknown): unknown => JSON.parse(JSON.stringify(v, (_k, x) => (x instanceof Uint8Array ? `<${x.length} bytes>` : x)));

/**
 * The call as a line to paste: flags when every value is a scalar or a list of strings, `--cli-input-json`
 * otherwise (exact, whatever the nesting). Pure.
 */
export function cliLine(serviceId: string, op: string, input: Record<string, unknown>, region: string | null): string {
  const head = `aws ${cliService(serviceId)} ${kebab(op)}`;
  const tail = region ? ` --region ${region}` : "";
  const flags: string[] = [];
  for (const [k, v] of Object.entries(input ?? {})) {
    if (v === undefined) continue;
    const f = `--${kebab(k)}`;
    if (typeof v === "boolean") flags.push(v ? f : `--no-${kebab(k)}`);
    else if (typeof v === "string") flags.push(`${f} ${quote(v)}`);
    else if (typeof v === "number") flags.push(`${f} ${v}`);
    else if (v instanceof Date) flags.push(`${f} ${v.toISOString()}`);
    else if (Array.isArray(v) && v.every((x) => typeof x === "string")) flags.push(`${f} ${v.map(quote).join(" ")}`);
    else return `${head} --cli-input-json ${quote(JSON.stringify(jsonable(input)))}${tail}`;
  }
  return `${head}${flags.length ? " " + flags.join(" ") : ""}${tail}`;
}

// ---- the hooks: installed once, inert outside a preview ---------------------------------------------------------

let installed = false;
function install(): void {
  if (installed) return;
  installed = true;
  // every @aws-sdk client extends the same smithy Client; its send is where a call leaves (src/__tests__/preview.test.ts checks the chain)
  const base = Object.getPrototypeOf(STSClient.prototype);
  const send = base.send;
  base.send = function (this: any, command: any, optionsOrCb?: any, cb?: any) {
    const rec = store.getStore();
    if (!rec) return send.call(this, command, optionsOrCb, cb);
    const serviceId = String(this.config?.serviceId ?? "?");
    const op = String(command?.constructor?.name ?? "?").replace(/Command$/, "");
    if (isReadOperation(op)) { rec.reads.push(`${cliService(serviceId)} ${kebab(op)}`); return send.call(this, command, optionsOrCb, cb); }
    const callback = typeof optionsOrCb === "function" ? optionsOrCb : cb;
    const out = (async () => {
      const r = this.config?.region;
      const region = typeof r === "function" ? await r().catch(() => null) : r ?? null;
      const input = command?.input ?? {};
      rec.writes.push({ service: cliService(serviceId), operation: op, region, iam: iamAction(serviceId, op), cli: cliLine(serviceId, op, input, region), input: jsonable(input) });
      return { $metadata: {} };
    })();
    if (callback) { out.then((o) => callback(null, o), (e) => callback(e)); return; }
    return out;
  };
  // local bookkeeping an apply does (SQLite) is skipped in a preview and listed
  const Statement = Object.getPrototypeOf(db.prepare("select 1"));
  const run = Statement.run;
  Statement.run = function (this: any, ...args: unknown[]) {
    const rec = store.getStore();
    if (!rec || this.reader) return run.apply(this, args);
    rec.local.push(String(this.source ?? "").replace(/\s+/g, " ").trim().slice(0, 120));
    return { changes: 0, lastInsertRowid: 0 };
  };
  const exec = db.exec.bind(db);
  (db as any).exec = (sql: string) => { const rec = store.getStore(); if (!rec) return exec(sql); rec.local.push(sql.replace(/\s+/g, " ").trim().slice(0, 120)); return db; };
}

/** How long one side may take: polling after a stubbed write (a start waiting for an address) is cut here. */
export const PREVIEW_TIMEOUT_MS = 20_000;

/** Runs `fn` with writes recorded, not sent. Never throws: a stop is reported on the side. */
export async function recordCalls(fn: () => Promise<string>, timeoutMs = PREVIEW_TIMEOUT_MS): Promise<PreviewSide> {
  install();
  const rec: Recorder = { writes: [], reads: [], local: [] };
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error(`still running after ${Math.round(timeoutMs / 1000)} s (waiting on a reply a preview does not get)`)), timeoutMs); });
  let result: string | null = null, stopped: string | null = null;
  try { result = await Promise.race([store.run(rec, fn), timeout]); }
  catch (e: any) { stopped = String(e?.message || e).slice(0, 300); }
  finally { clearTimeout(timer); }
  return { writes: [...rec.writes], reads: [...rec.reads], local: [...rec.local], result, stopped };
}

/** The advisor's read credentials for the row's account, standing in for the person's: `act()` reads too, and the hook keeps writes from leaving. */
function previewCreds(accountId: string | null): Creds {
  const base = credsForAccount(executorCreds(), accountId);
  const readOnly = (a: AccountCreds): AccountCreds => ({ ...a, act: () => a.read });
  return { ...base, act: () => base.read, accounts: base.accounts.map(readOnly), forAccount: (id) => readOnly(base.forAccount(id)) };
}

export class PreviewError extends Error { constructor(m: string, public status: number) { super(m); } }

/** What POST /actions/:id/as-person would send for this row, applying and undoing. */
export async function previewAsPerson(id: number): Promise<ActionPreview> {
  const row = getAction(id);
  if (!row) throw new PreviewError(`no action #${id}`, 404);
  const mod = actionModules().find((m) => m.kind === row.kind);
  if (!mod) throw new PreviewError(`no module for ${row.kind}`, 500);
  const creds = previewCreds(row.account_id);
  const p = proposalOf(row);
  const [apply, revert] = await Promise.all([recordCalls(() => mod.apply(p, creds)), recordCalls(() => mod.revert(p, creds))]);
  return { action_id: id, kind: row.kind, account_id: row.account_id, region: p.region, apply, revert };
}

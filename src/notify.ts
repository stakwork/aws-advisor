/**
 * Notifications into a Sphinx chat through a Sphinx bot.
 *
 * Two things go out. Alerts (below, `dispatchNotifications`), and recommendation events (`queueRecommendationEvent`):
 * a decision (approved, rejected, done), a measured saving from the verifier, or a recommendation someone shares by
 * hand. Each event is one row in `notifications` with a dedupe key, posted right away unless quiet hours hold it for
 * the next after-job dispatch, with the receipt on the row.
 *
 * After every scheduled job the dispatcher looks at the alerts raised in the last two hours that carry no
 * receipt yet, decides for each one (level, watched resource, quiet hours, already acknowledged by Jev or a
 * human), posts the ones that pass with one request per alert, and writes the receipt on the alert row
 * (`notified_at`, `notify_result`: "sent", "failed: …" or "skipped: …"). The request is the broadcast Hive and
 * the swarm checker use: POST <bot url> { action: "broadcast", bot_id, bot_secret, chat_pubkey, chat_uuid, content }.
 * The bot secret is read at send time and never logged.
 */
import { config } from "./config.js";
import { db } from "./db.js";
import { AlertLevel, LEVEL_RANK, alertLevel } from "./alert_level.js";
import { domainsReaching } from "./exposure.js";
import { namesId } from "./timeline.js";

export interface AlertRow { id: number; created_at: string; kind: string; resource: string | null; message: string; details: string | null; acknowledged: number; acknowledged_by: string | null; triage: string | null }

/** The inventory resource an alert is about, when it is about one ("i-1:/" is the instance; "elasticache_ri:x" is not a resource). */
export function resourceOfAlert(a: Pick<AlertRow, "kind" | "resource">): { kind: "ec2" | "rds" | "elasticache" | "lambda" | "nat" | "pool"; id: string } | null {
  const r = (a.resource || "").trim();
  if (!r) return null;
  if (/^i-[0-9a-f]{8,17}(:|$)/.test(r)) return { kind: "ec2", id: r.split(":")[0] };
  if (/^nat-[0-9a-f]{8,17}$/.test(r)) return { kind: "nat", id: r };
  if (a.kind.startsWith("rds_")) return { kind: "rds", id: r };
  if (a.kind.startsWith("cache_")) return { kind: "elasticache", id: r };
  if (a.kind.startsWith("lambda_")) return { kind: "lambda", id: r };
  if (a.kind === "node_churn") return { kind: "pool", id: r };
  return null;
}

export interface WatchState { watched: boolean; override: 0 | 1 | null; reason: string }

const TABLE: Record<string, [table: string, column: string]> = { ec2: ["inventory_ec2", "instance_id"], rds: ["inventory_rds", "db_instance_identifier"], elasticache: ["inventory_elasticache", "cache_cluster_id"] };
const tagsOf = (snapshot: unknown): Record<string, string> => { try { const s = typeof snapshot === "string" ? JSON.parse(snapshot) : snapshot; return (s?.tags || {}) as Record<string, string>; } catch { return {}; } };

/**
 * Is a resource important enough to page about? A hand-set override wins; then an `advisor:watch` tag; then the
 * signals the advisor already has: every database, anything a Route 53 record reaches, anything Jev scores as
 * protected. Everything else is not watched.
 */
export function watchState(kind: string, id: string): WatchState {
  const t = TABLE[kind];
  if (!t) return { watched: false, override: null, reason: "not a watchable kind" };
  const row = db.prepare(`select watch, snapshot from ${t[0]} where ${t[1]} = ?`).get(id) as { watch: number | null; snapshot: string | null } | undefined;
  if (!row) return { watched: false, override: null, reason: "not in the inventory" };
  if (row.watch === 1) return { watched: true, override: 1, reason: "marked watched" };
  if (row.watch === 0) return { watched: false, override: 0, reason: "marked ignore" };
  const tag = Object.entries(tagsOf(row.snapshot)).find(([k]) => k.toLowerCase() === "advisor:watch")?.[1];
  if (tag != null) return /^(1|true|yes|on)$/i.test(tag) ? { watched: true, override: null, reason: "tag advisor:watch" } : { watched: false, override: null, reason: `tag advisor:watch=${tag}` };
  if (kind === "rds") return { watched: true, override: null, reason: "a database" };
  const domains = domainsReaching(kind, id);
  if (domains.length) return { watched: true, override: null, reason: `${domains.length} Route 53 record${domains.length === 1 ? "" : "s"} reach${domains.length === 1 ? "es" : ""} it` };
  const role = db.prepare("select protected_prob from resource_roles where resource_id = ?").get(id) as { protected_prob: number | null } | undefined;
  if (role?.protected_prob != null && role.protected_prob >= 0.6) return { watched: true, override: null, reason: `Jev scores it protected (${Math.round(role.protected_prob * 100)} %)` };
  return { watched: false, override: null, reason: "no signal: not a database, no record reaches it, not protected per Jev" };
}

export function setWatch(kind: string, id: string, watch: 0 | 1 | null): WatchState {
  const t = TABLE[kind];
  if (!t) throw new Error(`kind must be one of ${Object.keys(TABLE).join(", ")}`);
  const r = db.prepare(`update ${t[0]} set watch = ? where ${t[1]} = ?`).run(watch, id);
  if (!r.changes) throw new Error("not in the inventory");
  return watchState(kind, id);
}

/** "22-07" → is `hour` inside the window? Wraps midnight; an empty setting is never quiet. */
export function inQuietHours(spec: string, hour: number): boolean {
  const m = /^(\d{1,2})-(\d{1,2})$/.exec((spec || "").trim());
  if (!m) return false;
  const from = Number(m[1]), to = Number(m[2]);
  if (from === to) return false;
  return from < to ? hour >= from && hour < to : hour >= from || hour < to;
}

export interface Decision { send: boolean; reason: string }

/** The rule, without the database: what goes and what does not, and why, in the words the receipt shows. */
export function decide(a: { level: AlertLevel; acknowledged: boolean; aboutResource: boolean; watched: boolean }, s: { level: "alarm" | "warning" | "off"; scope: "watched" | "all"; quiet: boolean }): Decision {
  if (s.level === "off") return { send: false, reason: "skipped: notifications off" };
  if (LEVEL_RANK[a.level] > LEVEL_RANK[s.level]) return { send: false, reason: `skipped: ${a.level} is below the ${s.level} threshold` };
  if (a.acknowledged) return { send: false, reason: "skipped: acknowledged before sending" };
  if (s.scope === "watched" && a.aboutResource && !a.watched) return { send: false, reason: "skipped: resource not watched" };
  if (s.quiet && a.level !== "alarm") return { send: false, reason: "skipped: quiet hours" };
  return { send: true, reason: "sent" };
}

/** Plain text for the chat: level and message first, then what the advisor knows that you would look up next. */
export function formatMessage(a: Pick<AlertRow, "id" | "kind" | "resource" | "message" | "created_at">, ctx: { level: AlertLevel; resource: { kind: string; id: string; name: string | null; region: string | null } | null; domains: string[]; recommendations: { id: number; title: string; est_monthly_saving: number | null }[]; publicUrl: string }): string {
  const mark = ctx.level === "alarm" ? "🔴 ALARM" : ctx.level === "warning" ? "🟠 WARNING" : "ℹ️ INFO";
  const lines = [`${mark} — ${a.message}`];
  const about = [a.kind, ctx.resource ? `${ctx.resource.kind.toUpperCase()} ${ctx.resource.name && ctx.resource.name !== ctx.resource.id ? `${ctx.resource.name} (${ctx.resource.id})` : ctx.resource.id}` : a.resource, ctx.resource?.region].filter(Boolean);
  lines.push(about.join(" · "));
  if (ctx.domains.length) lines.push(`Reaches: ${ctx.domains.slice(0, 6).join(", ")}${ctx.domains.length > 6 ? ` and ${ctx.domains.length - 6} more` : ""}`);
  if (ctx.recommendations.length) lines.push(`Open on it: ${ctx.recommendations.slice(0, 3).map((r) => `#${r.id} ${r.title}${r.est_monthly_saving != null ? ` (≈ ${Math.round(r.est_monthly_saving)} USD/month)` : ""}`).join("; ")}`);
  lines.push(`${ctx.publicUrl}/alerts?status=all&id=${a.id}`);
  return lines.join("\n");
}

export const configured = () => Boolean(config.sphinxBotUrl && config.sphinxBotId && config.sphinxBotSecret && config.sphinxChatPubkey);

/** One broadcast; one retry on a network error or a 5xx. The secret goes in the body only. */
export async function sendSphinx(content: string): Promise<{ ok: boolean; status: number; body: string }> {
  if (!configured()) return { ok: false, status: 0, body: "not configured: bot URL, id, secret and chat pubkey are all needed (Settings > Notifications)" };
  const body = JSON.stringify({ action: "broadcast", bot_id: config.sphinxBotId, bot_secret: config.sphinxBotSecret, chat_pubkey: config.sphinxChatPubkey, chat_uuid: config.sphinxChatPubkey, content });
  let last: { ok: boolean; status: number; body: string } = { ok: false, status: 0, body: "" };
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const res = await fetch(config.sphinxBotUrl, { method: "POST", headers: { "content-type": "application/json" }, body, signal: AbortSignal.timeout(8000) });
      const text = (await res.text().catch(() => "")).slice(0, 200);
      last = { ok: res.ok, status: res.status, body: text };
      if (res.ok || res.status < 500) return last;
    } catch (e: any) {
      last = { ok: false, status: 0, body: String(e?.message || e).slice(0, 200) };
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  return last;
}

function contextFor(a: AlertRow, level: AlertLevel) {
  const res = resourceOfAlert(a);
  let resource: { kind: string; id: string; name: string | null; region: string | null } | null = null;
  let domains: string[] = [];
  if (res && TABLE[res.kind]) {
    const [table, col] = TABLE[res.kind];
    const row = db.prepare(`select * from ${table} where ${col} = ?`).get(res.id) as any;
    resource = { kind: res.kind, id: res.id, name: row?.name ?? null, region: row?.region ?? null };
    domains = domainsReaching(res.kind, res.id).map((d) => d.name);
  } else if (res) resource = { kind: res.kind, id: res.id, name: null, region: null };
  const recommendations = res ? (db.prepare("select id, title, est_monthly_saving, resource, resource_name from recommendations where status in ('open','pending','approved') and resource like ? order by coalesce(est_monthly_saving, -1) desc limit 10").all(`%${res.id}%`) as any[]).filter((r) => namesId(r, res.id)) : [];
  return { level, resource, domains, recommendations, publicUrl: config.publicUrl };
}

const receipt = db.prepare("update alerts set notified_at = datetime('now'), notify_result = ? where id = ?");

/** Sends one alert now, by hand (`force`, whatever the rules say) or through the rules; returns the receipt text. */
export async function notifyAlert(id: number, opts: { force?: boolean } = {}): Promise<string> {
  const a = db.prepare("select * from alerts where id = ?").get(id) as AlertRow | undefined;
  if (!a) throw new Error("not found");
  const level = alertLevel(a);
  if (!opts.force) {
    const res = resourceOfAlert(a);
    const watched = res && TABLE[res.kind] ? watchState(res.kind, res.id).watched : false;
    const d = decide({ level, acknowledged: Boolean(a.acknowledged), aboutResource: Boolean(res && TABLE[res.kind]), watched }, { level: config.notifyLevel, scope: config.notifyScope, quiet: inQuietHours(config.notifyQuietHours, new Date().getHours()) });
    if (!d.send) { receipt.run(d.reason, id); return d.reason; }
  }
  const r = await sendSphinx(formatMessage(a, contextFor(a, level)));
  const result = r.ok ? "sent" : `failed: ${r.status ? `${r.status} ` : ""}${r.body || "no response"}`.slice(0, 300);
  receipt.run(result, id);
  return result;
}

let inFlight = false;
/** The dispatcher: every alert of the last two hours without a receipt. Older ones are marked as never considered. */
export async function dispatchNotifications(): Promise<{ considered: number; sent: number; skipped: number; failed: number }> {
  const out = { considered: 0, sent: 0, skipped: 0, failed: 0 };
  if (inFlight || !configured() || config.notifyLevel === "off") return out;
  inFlight = true;
  try {
    db.prepare("update alerts set notified_at = datetime('now'), notify_result = 'skipped: older than two hours when the notifier ran' where notify_result is null and created_at < datetime('now', '-2 hours')").run();
    const ids = (db.prepare("select id from alerts where notify_result is null order by id").all() as { id: number }[]).map((r) => r.id);
    for (const id of ids) {
      out.considered++;
      try {
        const r = await notifyAlert(id);
        if (r === "sent") out.sent++; else if (r.startsWith("failed")) out.failed++; else out.skipped++;
      } catch (e: any) { out.failed++; console.error(`[notify] alert ${id}: ${e?.message || e}`); }
    }
    if (out.considered) console.log(`[notify] ${out.sent} sent, ${out.skipped} skipped, ${out.failed} failed of ${out.considered}`);
  } finally { inFlight = false; }
  await dispatchRecommendationEvents().catch((e: any) => console.error(`[notify] recommendation events: ${e?.message || e}`));
  return out;
}

/** What the Alerts page needs to know: whether the bot is set up and the rules in force. */
export function notifyStatus() {
  let host = "";
  try { host = new URL(config.sphinxBotUrl).host; } catch { /* unset */ }
  return { configured: configured(), bot_host: host, level: config.notifyLevel, scope: config.notifyScope, recommendations: config.notifyRecommendations, quiet_hours: config.notifyQuietHours || null, quiet_now: inQuietHours(config.notifyQuietHours, new Date().getHours()) };
}

// ---- recommendation events -------------------------------------------------------------------------------------

export type RecEvent = "approved" | "rejected" | "done" | "verified" | "shared";

export interface RecRowForMessage { id: number; title: string; status: string; resource: string | null; resource_name: string | null; est_monthly_saving: number | null; decided_by: string | null; decision_reason: string | null }
export interface Verdict { verdict: string; realised_usd_month: number | null; estimate_usd_month: number | null; ratio: number | null; days_after: number | null; note: string | null }

const usd = (n: number | null | undefined) => (n == null ? null : `${Math.round(Number(n))} USD/month`);

/** Plain text for the chat: what happened to which recommendation, by whom and why, then the link. */
export function formatRecommendationMessage(rec: RecRowForMessage, event: RecEvent, ctx: { verdict?: Verdict | null; by?: string | null; publicUrl: string }): string {
  const head: Record<RecEvent, string> = { approved: "✅ APPROVED", rejected: "⛔ REJECTED", done: "🏁 DONE", verified: "📏 MEASURED", shared: "📣 RECOMMENDATION" };
  const saving = usd(rec.est_monthly_saving);
  const lines = [`${head[event]} — #${rec.id} ${rec.title}${saving && event !== "verified" ? ` (≈ ${saving})` : ""}`];
  if (event === "verified" && ctx.verdict) {
    const v = ctx.verdict;
    const words: Record<string, string> = { realised: "saving realised", partial: "partly realised", none: "no saving seen", increase: "cost went up" };
    const parts = [words[v.verdict] || v.verdict];
    if (v.realised_usd_month != null) parts.push(`${usd(v.realised_usd_month)} measured${v.estimate_usd_month != null ? ` of ${usd(v.estimate_usd_month)} estimated` : ""}${v.ratio != null ? ` (${Math.round(v.ratio * 100)} %)` : ""}`);
    if (v.days_after != null) parts.push(`${v.days_after} days after the decision`);
    lines.push(parts.join(" · "));
    if (v.note) lines.push(v.note);
  } else if (event === "shared") {
    lines.push(`status ${rec.status}${ctx.by ? ` · shared by ${ctx.by}` : ""}`);
  } else {
    const who = ctx.by || rec.decided_by;
    const tail = [who ? `by ${who}` : null, rec.decision_reason ? rec.decision_reason : null].filter(Boolean);
    if (tail.length) lines.push(tail.join(" · "));
  }
  const about = rec.resource_name && rec.resource_name !== rec.resource ? `${rec.resource_name} (${rec.resource})` : rec.resource;
  if (about) lines.push(about);
  lines.push(`${ctx.publicUrl}/recommendations?status=all&id=${rec.id}`);
  return lines.join("\n");
}

/** The rule for a queued event: off and unconfigured are final receipts; quiet hours only wait. */
export function decideRecommendationEvent(s: { configured: boolean; enabled: boolean; quiet: boolean; forced: boolean }): { send: boolean; reason: string | null } {
  if (!s.configured) return { send: false, reason: "skipped: bot not configured" };
  if (!s.forced && !s.enabled) return { send: false, reason: "skipped: recommendation events off" };
  if (!s.forced && s.quiet) return { send: false, reason: null };
  return { send: true, reason: "sent" };
}

const insertEvent = db.prepare("insert or ignore into notifications(subject, subject_id, event, dedupe, content) values ('recommendation', ?, ?, ?, ?)");
const receiptEvent = db.prepare("update notifications set sent_at = datetime('now'), result = ? where id = ?");

/**
 * Records the event and posts it in the background. `dedupe` keeps a repeat (the same verdict on the next
 * verification run, a decision saved twice) from going out again; a forced share always goes.
 */
export function queueRecommendationEvent(id: number, event: RecEvent, opts: { verdict?: Verdict | null; by?: string | null; dedupe?: string | null; force?: boolean } = {}): number | null {
  const rec = db.prepare("select id, title, status, resource, resource_name, est_monthly_saving, decided_by, decision_reason from recommendations where id = ?").get(id) as RecRowForMessage | undefined;
  if (!rec) return null;
  const content = formatRecommendationMessage(rec, event, { verdict: opts.verdict, by: opts.by, publicUrl: config.publicUrl });
  const dedupe = opts.dedupe === undefined ? `${event}:${id}:${new Date().toISOString().slice(0, 16)}` : opts.dedupe;
  const r = insertEvent.run(id, event, dedupe, content);
  if (!r.changes) return null;
  const rowId = Number(r.lastInsertRowid);
  dispatchRecommendationEvents({ only: rowId, force: opts.force }).catch((e: any) => console.error(`[notify] recommendation ${id} ${event}: ${e?.message || e}`));
  return rowId;
}

let eventsInFlight = false;
/** Sends the queued events without a receipt; with `only`, that one row (the "send now" paths). */
export async function dispatchRecommendationEvents(opts: { only?: number; force?: boolean } = {}): Promise<{ sent: number; skipped: number; failed: number; waiting: number }> {
  const out = { sent: 0, skipped: 0, failed: 0, waiting: 0 };
  if (eventsInFlight && !opts.only) return out;
  if (!opts.only) eventsInFlight = true;
  try {
    const rows = (opts.only
      ? db.prepare("select id, content from notifications where id = ? and result is null").all(opts.only)
      : db.prepare("select id, content from notifications where result is null order by id").all()) as { id: number; content: string }[];
    const d = decideRecommendationEvent({ configured: configured(), enabled: config.notifyRecommendations === "on", quiet: inQuietHours(config.notifyQuietHours, new Date().getHours()), forced: Boolean(opts.force) });
    for (const row of rows) {
      if (!d.send) {
        if (d.reason) { receiptEvent.run(d.reason, row.id); out.skipped++; } else out.waiting++;
        continue;
      }
      const r = await sendSphinx(row.content);
      const result = r.ok ? "sent" : `failed: ${r.status ? `${r.status} ` : ""}${r.body || "no response"}`.slice(0, 300);
      receiptEvent.run(result, row.id);
      if (r.ok) out.sent++; else out.failed++;
    }
    if (rows.length && !opts.only) console.log(`[notify] recommendation events: ${out.sent} sent, ${out.skipped} skipped, ${out.failed} failed, ${out.waiting} waiting for quiet hours to end`);
  } finally { if (!opts.only) eventsInFlight = false; }
  return out;
}

/** Sends one queued event again (a new row with the same content, so the history keeps the first receipt). */
export async function resendNotification(id: number): Promise<string> {
  const row = db.prepare("select subject_id, event, content from notifications where id = ?").get(id) as { subject_id: number; event: string; content: string } | undefined;
  if (!row) throw new Error("not found");
  const r = insertEvent.run(row.subject_id, row.event, null, row.content);
  const res = await dispatchRecommendationEvents({ only: Number(r.lastInsertRowid), force: true });
  return res.sent ? "sent" : (db.prepare("select result from notifications where id = ?").get(Number(r.lastInsertRowid)) as { result: string | null })?.result || "failed";
}

/** The decision hook for both decision routes: only the statuses worth a message become events. */
export function noteDecision(id: number, status: string, by: string | null): void {
  if (status !== "approved" && status !== "rejected" && status !== "done") return;
  const rec = db.prepare("select decided_at from recommendations where id = ?").get(id) as { decided_at: string | null } | undefined;
  queueRecommendationEvent(id, status, { by, dedupe: `${status}:${id}:${rec?.decided_at || ""}` });
}

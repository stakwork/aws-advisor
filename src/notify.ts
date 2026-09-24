/**
 * Notifications into a Sphinx chat through a Sphinx bot.
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
  return out;
}

/** What the Alerts page needs to know: whether the bot is set up and the rules in force. */
export function notifyStatus() {
  let host = "";
  try { host = new URL(config.sphinxBotUrl).host; } catch { /* unset */ }
  return { configured: configured(), bot_host: host, level: config.notifyLevel, scope: config.notifyScope, quiet_hours: config.notifyQuietHours || null, quiet_now: inQuietHours(config.notifyQuietHours, new Date().getHours()) };
}

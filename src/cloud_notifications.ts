/**
 * The provider's own notifications: what AWS tells the account through User Notifications (the bell in the console).
 * Two feeds, both read through the SDK against us-east-1 (the service answers there for every region): the
 * AWS-managed notifications every account gets without setup (Health events, service announcements, billing and
 * security notices), and the events the account's own notification configurations and event rules deliver, which
 * exist only where a notification hub was registered. Read per account like the trail (the parent with its own
 * credentials, each enabled member through its read role), kept 90 days, summarised on the Changes page and
 * mirrored into the graph as AdvisorNotification nodes IN_ACCOUNT of the account that received them.
 */
import { ListManagedNotificationEventsCommand, ListNotificationEventsCommand, ListNotificationHubsCommand, NotificationsClient } from "@aws-sdk/client-notifications";
import { db, getJsonSetting, setSetting } from "./db.js";
import { accountWhere, type AccountScope } from "./scope.js";
import { credentialsMeta, sdkCredentials } from "./steampipe.js";
import { accountCredentials, listMembers } from "./accounts.js";
import { describeError, noteSuccess } from "./permissions.js";

db.exec(`create table if not exists cloud_notifications (
  arn text primary key, account_id text, feed text not null, source text, event_type text, headline text, notification_type text, event_status text, origin_region text, related_account text,
  created_at text not null, aggregation text, event_count integer not null default 1, regions text, configuration_arn text, fetched_at text not null
)`);
db.exec("create index if not exists cloud_notifications_created on cloud_notifications(created_at)");

const META = "cloud_notifications_meta";
/** The service answers in us-east-1 for every region's events. */
export const NOTIFICATIONS_REGION = "us-east-1";
/** How far back a refresh asks; rows older than 90 days are dropped. */
export const WINDOW_DAYS = 30;

export type Feed = "managed" | "configured";
export interface CloudNotificationRow {
  arn: string; account_id: string | null; feed: Feed; source: string | null; event_type: string | null; headline: string | null; notification_type: string | null; event_status: string | null; origin_region: string | null; related_account: string | null;
  created_at: string; aggregation: string | null; event_count: number; regions: string[]; configuration_arn: string | null; fetched_at: string;
}
export interface CloudNotificationsMeta { read_at: string | null; took_ms: number | null; hubs: string[]; errors: string[]; notes: string[]; accounts: number }

const iso = (v: unknown): string => (v instanceof Date ? v.toISOString() : v ? String(v) : new Date().toISOString());

/** One overview (either feed's shape: the summary sits under notificationEvent) folded into a row. Pure. */
export function notificationRowFrom(ev: any, feed: Feed, accountId: string | null, fetchedAt = new Date().toISOString()): Omit<CloudNotificationRow, "regions"> & { regions: string } | null {
  if (!ev?.arn) return null;
  const s = ev.notificationEvent ?? {}; const meta = s.sourceEventMetadata ?? {}; const msg = s.messageComponents ?? {};
  return {
    arn: String(ev.arn), account_id: accountId, feed, source: meta.source ? String(meta.source).replace(/^aws\./, "") : null, event_type: meta.eventType ? String(meta.eventType) : null, headline: msg.headline ? String(msg.headline).slice(0, 500) : null,
    notification_type: s.notificationType ? String(s.notificationType) : null, event_status: s.eventStatus ? String(s.eventStatus) : null, origin_region: meta.eventOriginRegion ? String(meta.eventOriginRegion) : null, related_account: ev.relatedAccount ? String(ev.relatedAccount) : null,
    created_at: iso(ev.creationTime), aggregation: ev.aggregationEventType ? String(ev.aggregationEventType) : null, event_count: Number(ev.aggregationSummary?.eventCount) || 1, regions: JSON.stringify(Array.isArray(ev.aggregatedNotificationRegions) ? ev.aggregatedNotificationRegions.map(String) : []),
    configuration_arn: ev.managedNotificationConfigurationArn ?? ev.notificationConfigurationArn ?? null, fetched_at: fetchedAt,
  };
}

export const cloudNotificationsMeta = (): CloudNotificationsMeta => getJsonSetting<CloudNotificationsMeta>(META, { read_at: null, took_ms: null, hubs: [], errors: [], notes: [], accounts: 0 });

export interface NotificationsRefreshResult { events: number; stored: number; accounts: number; hubs: string[]; errors: string[]; notes: string[]; took_ms: number }

export async function refreshCloudNotifications(days = WINDOW_DAYS, onLog: (l: string) => void = () => {}): Promise<NotificationsRefreshResult> {
  const t0 = Date.now();
  const out: NotificationsRefreshResult = { events: 0, stored: 0, accounts: 0, hubs: [], errors: [], notes: [], took_ms: 0 };
  const finish = () => { out.took_ms = Date.now() - t0; setSetting(META, JSON.stringify({ read_at: new Date().toISOString(), took_ms: out.took_ms, hubs: out.hubs, errors: out.errors, notes: out.notes, accounts: out.accounts } satisfies CloudNotificationsMeta)); onLog(`${out.events} notifications read across ${out.accounts} account(s), ${out.stored} new, ${out.took_ms} ms${out.errors.length ? `; ${out.errors.join("; ")}` : ""}`); return out; };
  const targets: { account_id: string | null; provider: any }[] = [];
  try { const base = sdkCredentials(); targets.push({ account_id: credentialsMeta()?.accountId ?? null, provider: base.provider }); } catch (e: any) { out.errors.push(String(e?.message || e)); return finish(); }
  for (const m of listMembers().filter((x) => x.enabled)) { try { targets.push({ account_id: m.account_id, provider: accountCredentials(m.account_id).provider }); } catch (e: any) { out.errors.push(`${m.account_id}: ${String(e?.message || e).slice(0, 120)}`); } }
  const startTime = new Date(Date.now() - Math.max(1, Math.min(90, days)) * 86_400_000);
  const fetchedAt = new Date().toISOString();
  const up = db.prepare(`insert into cloud_notifications(arn, account_id, feed, source, event_type, headline, notification_type, event_status, origin_region, related_account, created_at, aggregation, event_count, regions, configuration_arn, fetched_at)
    values (@arn, @account_id, @feed, @source, @event_type, @headline, @notification_type, @event_status, @origin_region, @related_account, @created_at, @aggregation, @event_count, @regions, @configuration_arn, @fetched_at)
    on conflict(arn) do update set headline = excluded.headline, event_status = excluded.event_status, notification_type = excluded.notification_type, event_count = excluded.event_count, regions = excluded.regions, fetched_at = excluded.fetched_at`);
  for (const t of targets) {
    const client = new NotificationsClient({ region: NOTIFICATIONS_REGION, credentials: t.provider });
    const who = t.account_id ?? "parent";
    try {
      out.accounts++;
      // the AWS-managed feed: there for every account
      try {
        let nextToken: string | undefined; let pages = 0;
        do {
          const r = await client.send(new ListManagedNotificationEventsCommand({ startTime, maxResults: 100, nextToken }));
          for (const ev of r.managedNotificationEvents ?? []) { out.events++; const row = notificationRowFrom(ev, "managed", t.account_id, fetchedAt); if (row && up.run(row).changes) out.stored++; }
          nextToken = r.nextToken;
        } while (nextToken && ++pages < 50);
        noteSuccess(["notifications:ListManagedNotificationEvents"], `notifications ${who}`);
      } catch (e) { out.errors.push(describeError(e, `notifications ${who} (notifications:ListManagedNotificationEvents)`)); }
      // the account's own configurations: only where a hub is registered
      try {
        const hubs = (await client.send(new ListNotificationHubsCommand({}))).notificationHubs ?? [];
        for (const h of hubs) if (h.notificationHubRegion && !out.hubs.includes(h.notificationHubRegion)) out.hubs.push(h.notificationHubRegion);
        noteSuccess(["notifications:ListNotificationHubs"], `notifications ${who}`);
        if (!hubs.length) { out.notes.push(`${who}: no notification hub registered, so only the AWS-managed feed exists`); }
        else {
          let nextToken: string | undefined; let pages = 0;
          do {
            const r = await client.send(new ListNotificationEventsCommand({ startTime, maxResults: 100, nextToken }));
            for (const ev of r.notificationEvents ?? []) { out.events++; const row = notificationRowFrom(ev, "configured", t.account_id, fetchedAt); if (row && up.run(row).changes) out.stored++; }
            nextToken = r.nextToken;
          } while (nextToken && ++pages < 50);
          noteSuccess(["notifications:ListNotificationEvents"], `notifications ${who}`);
        }
      } catch (e) { out.errors.push(describeError(e, `notifications ${who} (notifications:ListNotificationEvents)`)); }
    } finally { client.destroy(); }
  }
  db.prepare("delete from cloud_notifications where created_at < datetime('now', '-90 days')").run();
  return finish();
}

const parseRow = (r: any): CloudNotificationRow => { let regions: string[] = []; try { regions = JSON.parse(r.regions || "[]"); } catch { /* none */ } return { ...r, event_count: Number(r.event_count) || 1, regions }; };

export function listCloudNotifications(f: { days?: number; scope?: AccountScope | null; feed?: Feed; type?: string; source?: string; limit?: number } = {}): CloudNotificationRow[] {
  const since = new Date(Date.now() - Math.max(1, Math.min(90, f.days ?? 7)) * 86_400_000).toISOString();
  const where = ["created_at >= ?"]; const params: unknown[] = [since];
  const a = accountWhere(f.scope); if (a.params.length) { where.push(a.sql); params.push(...a.params); }
  if (f.feed) { where.push("feed = ?"); params.push(f.feed); }
  if (f.type) { where.push("notification_type = ?"); params.push(f.type); }
  if (f.source) { where.push("source = ?"); params.push(f.source); }
  return (db.prepare(`select * from cloud_notifications where ${where.join(" and ")} order by created_at desc limit ?`).all(...params, Math.min(500, Math.max(1, f.limit ?? 200))) as any[]).map(parseRow);
}

export interface CloudNotificationsSummary { since: string; total: number; alerts: number; warnings: number; unhealthy: number; managed: number; configured: number; by_source: { source: string; n: number; alerts: number }[]; by_account: { account_id: string | null; n: number }[]; last_fetch: string | null; hubs: string[]; errors: string[]; notes: string[] }

export function cloudNotificationsSummary(days = 7, scope?: AccountScope | null): CloudNotificationsSummary {
  const rows = listCloudNotifications({ days, scope, limit: 500 }); const m = cloudNotificationsMeta();
  const bySource = new Map<string, { source: string; n: number; alerts: number }>(); const byAccount = new Map<string | null, number>();
  for (const r of rows) {
    const s = r.source ?? "unknown"; const g = bySource.get(s) ?? { source: s, n: 0, alerts: 0 }; g.n++; if (r.notification_type === "ALERT") g.alerts++; bySource.set(s, g);
    byAccount.set(r.account_id, (byAccount.get(r.account_id) ?? 0) + 1);
  }
  return {
    since: new Date(Date.now() - Math.max(1, Math.min(90, days)) * 86_400_000).toISOString(), total: rows.length, alerts: rows.filter((r) => r.notification_type === "ALERT").length, warnings: rows.filter((r) => r.notification_type === "WARNING").length, unhealthy: rows.filter((r) => r.event_status === "UNHEALTHY").length,
    managed: rows.filter((r) => r.feed === "managed").length, configured: rows.filter((r) => r.feed === "configured").length,
    by_source: [...bySource.values()].sort((a, b) => b.n - a.n), by_account: [...byAccount.entries()].map(([account_id, n]) => ({ account_id, n })).sort((a, b) => b.n - a.n),
    last_fetch: m.read_at, hubs: m.hubs, errors: m.errors, notes: m.notes,
  };
}

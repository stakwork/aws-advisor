/**
 * Everything the advisor recorded about one resource, in one list: when it was first and last seen, the controls
 * that flagged it, the recommendations and the decisions on them, resolutions and verifications, alerts and the
 * incidents they opened, and the probes. Each event links to the page that holds the rest.
 */
import { db } from "./db.js";
import { resourceKeys } from "./related.js";
import { shortResourceId } from "./paging.js";

export type EventKind = "seen" | "gone" | "finding" | "recommendation" | "decision" | "resolution" | "verification" | "alert" | "incident" | "probe";
export interface TimelineEvent { at: string; kind: EventKind; title: string; detail: string | null; href: string | null; badge: string | null }

const ID_COLUMN: Record<string, [table: string, column: string]> = { ec2: ["inventory_ec2", "instance_id"], rds: ["inventory_rds", "db_instance_identifier"], elasticache: ["inventory_elasticache", "cache_cluster_id"], lambda: ["inventory_lambda", "name"], ebs: ["inventory_ebs", "volume_id"], s3: ["inventory_s3", "name"] };
export const TIMELINE_KINDS = Object.keys(ID_COLUMN);

const q = <T>(sql: string, ...p: unknown[]): T[] => { try { return db.prepare(sql).all(...p) as T[]; } catch { return []; } };

/** Does a recommendation's resource column name this id (alone, in a list, as an ARN, with a name in brackets)? */
export const namesId = (rec: { resource: string | null; resource_name?: string | null }, id: string) => resourceKeys(rec).includes(id);

/** Newest first, capped; the same instant keeps the insertion order. */
export function assemble(events: TimelineEvent[], cap = 300): TimelineEvent[] {
  return events.map((e, i) => ({ e, i })).sort((a, b) => b.e.at.localeCompare(a.e.at) || a.i - b.i).map((x) => x.e).slice(0, cap);
}

export function timelineFor(kind: string, id: string): { events: TimelineEvent[]; counts: Partial<Record<EventKind, number>> } {
  const events: TimelineEvent[] = [];
  const col = ID_COLUMN[kind];
  if (col) {
    const row = q<any>(`select * from ${col[0]} where ${col[1]} = ?`, id)[0];
    if (row?.first_seen) events.push({ at: row.first_seen, kind: "seen", title: "First seen by the advisor", detail: null, href: null, badge: null });
    if (row?.gone && row.last_seen) events.push({ at: row.last_seen, kind: "gone", title: "Last seen: no longer in the account", detail: null, href: null, badge: "gone" });
  }
  // Findings: one line per control, first and last run it was flagged in.
  for (const f of q<any>(`select f.control_id, f.control_title, f.status, min(r.started_at) as first_at, max(r.started_at) as last_at, count(distinct f.run_id) as runs, f.resource
      from findings f join runs r on r.id = f.run_id where f.resource like ? group by f.control_id, f.status`, `%${id}%`)) {
    if (shortResourceId(f.resource) !== id) continue;
    events.push({ at: f.first_at, kind: "finding", title: `${f.control_title || f.control_id}`, detail: f.runs > 1 ? `flagged in ${f.runs} runs, last ${String(f.last_at).slice(0, 16)}` : "flagged once", href: `/findings?howto=${encodeURIComponent(f.control_id)}`, badge: f.status });
  }
  // Recommendations naming the resource, with their decisions, resolutions and verifications.
  const recs = q<any>("select id, title, status, source, action_type, resource, resource_name, est_monthly_saving, created_at, decided_at, decided_by, decision_reason from recommendations where resource like ?", `%${id}%`).filter((r) => namesId(r, id));
  for (const r of recs) {
    const href = `/recommendations?status=all&id=${r.id}`;
    events.push({ at: r.created_at, kind: "recommendation", title: `#${r.id} ${r.title}`, detail: `${r.source} · ${r.action_type}${r.est_monthly_saving != null ? ` · ≈ ${Math.round(r.est_monthly_saving)} USD/month` : ""}`, href, badge: r.source });
    if (r.decided_at) events.push({ at: r.decided_at, kind: "decision", title: `#${r.id} ${r.status} by ${r.decided_by || "ui"}`, detail: r.decision_reason || null, href, badge: r.status });
    for (const s of q<any>("select id, status, gate_outcome, created_at, finished_at from resolutions where recommendation_id = ? order by id", r.id))
      events.push({ at: s.finished_at || s.created_at, kind: "resolution", title: `#${r.id} tailored resolution ${s.status === "completed" ? "written" : s.status}`, detail: s.gate_outcome ? `gate: ${s.gate_outcome}` : null, href, badge: s.status });
    for (const v of q<any>("select checked_at, verdict, realised_usd_month, note from verifications where recommendation_id = ? order by id desc limit 1", r.id))
      events.push({ at: v.checked_at, kind: "verification", title: `#${r.id} bill check: ${v.verdict}`, detail: v.realised_usd_month != null ? `${Math.round(v.realised_usd_month)} USD/month realised · ${v.note || ""}` : v.note || null, href, badge: v.verdict });
  }
  // Alerts on the resource (an instance alert may carry a mount or a metric after the id) and their incidents.
  const alerts = q<any>("select id, created_at, kind, message, acknowledged, acknowledged_by, triage from alerts where resource = ? or resource like ? order by id", id, `${id}:%`);
  for (const a of alerts) {
    events.push({ at: a.created_at, kind: "alert", title: a.message, detail: a.acknowledged ? `acknowledged by ${a.acknowledged_by || "ui"}` : "open", href: `/alerts?status=all&id=${a.id}`, badge: a.kind });
    for (const i of q<any>("select id, status, cause, confidence, created_at, finished_at from incidents where alert_id = ?", a.id))
      events.push({ at: i.finished_at || i.created_at, kind: "incident", title: `incident #${i.id}: ${i.cause || i.status}`, detail: i.confidence != null ? `confidence ${Math.round(i.confidence * 100)} %` : null, href: `/alerts?status=all&id=${a.id}`, badge: i.status });
  }
  // Probes: the count and the latest, not every sample.
  if (kind === "ec2") {
    const p = q<{ n: number; last: string | null; first: string | null }>("select count(*) as n, max(collected_at) as last, min(collected_at) as first from instance_metrics where instance_id = ?", id)[0];
    if (p?.n) events.push({ at: p.last!, kind: "probe", title: `Probed over SSM ${p.n === 1 ? "once" : `${p.n} times`}`, detail: p.n > 1 ? `first ${String(p.first).slice(0, 16)}` : null, href: `/inventory?tab=ec2&id=${encodeURIComponent(id)}`, badge: null });
  }
  const counts: Partial<Record<EventKind, number>> = {};
  for (const e of events) counts[e.kind] = (counts[e.kind] || 0) + 1;
  return { events: assemble(events), counts };
}

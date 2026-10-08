import { db } from "./db.js";
import { distinctSaving } from "./related.js";

/**
 * The daily review beyond the instances' statistics (src/review.ts): the bill (the month against the last one, a day
 * that jumped, services and accounts climbing), the probes (instances not probed, not reachable), what is open
 * (alerts left unacknowledged, alarm findings, critical security findings) and the recommendations (savings waiting
 * for a decision, approvals not carried out). Each check is a review finding with its numbers; deterministic, no
 * model call. Thresholds are deliberately coarse: the review points at what deserves a look today.
 */

export interface OpsFinding { kind: string; resource: string; resource_name: string; severity: "alarm" | "warning" | "info"; message: string; details: Record<string, unknown> }

const rows = (sql: string, ...p: unknown[]): any[] => { try { return db.prepare(sql).all(...p) as any[]; } catch { return []; } };
const one = (sql: string, ...p: unknown[]): any => rows(sql, ...p)[0];
const usd = (v: number | null | undefined) => (v == null ? "—" : `${Math.round(v).toLocaleString("en-US")} USD`);
const pct = (v: number | null | undefined) => (v == null ? "" : `${v >= 0 ? "+" : "−"}${Math.abs(v).toFixed(0)} %`);

/** Pure: the newest complete day against the median of the 14 before it; null when nothing stands out. */
export function dayJump(days: { day: string; usd: number }[]): { day: string; usd: number; median: number; ratio: number; excess: number } | null {
  if (days.length < 8) return null;
  const last = days[days.length - 1];
  const before = days.slice(-15, -1).map((d) => d.usd).sort((a, b) => a - b);
  const median = before.length % 2 ? before[(before.length - 1) / 2] : (before[before.length / 2 - 1] + before[before.length / 2]) / 2;
  if (median <= 0) return null;
  const ratio = last.usd / median; const excess = last.usd - median;
  return ratio >= 1.3 && excess >= 50 ? { day: last.day, usd: Math.round(last.usd * 100) / 100, median: Math.round(median * 100) / 100, ratio: Math.round(ratio * 100) / 100, excess: Math.round(excess) } : null;
}

export async function reviewBilling(): Promise<OpsFinding[]> {
  const out: OpsFinding[] = [];
  const { monthComparison } = await import("./spend_compare.js");
  const c = await monthComparison(null);
  const p = c.projected;
  if (p.usd != null && p.last_month_usd != null) {
    const up = (p.delta_pct ?? 0) >= 10 && (p.delta_usd ?? 0) >= 100;
    const lfl = c.like_for_like ? `; the first ${c.like_for_like.days} days ${usd(c.like_for_like.this_usd)} against ${usd(c.like_for_like.last_usd)} (${pct(c.like_for_like.delta_pct)})` : "";
    out.push({ kind: "bill_month", resource: "bill", resource_name: c.month, severity: up ? "warning" : "info",
      message: `the bill: ${c.month} projected at ${usd(p.usd)} against ${usd(p.last_month_usd)} in ${c.previous_month} (${pct(p.delta_pct)})${lfl}`, details: { ...p, like_for_like: c.like_for_like } });
  }
  for (const m of c.movers.filter((x) => x.delta >= 100 && (x.status === "new" || (x.delta_pct ?? 0) >= 25)).slice(0, 5))
    out.push({ kind: "bill_service_up", resource: m.service, resource_name: c.month, severity: "warning", message: `${m.service}: projected ${usd(m.projected)} this month against ${usd(m.last_month)} in ${c.previous_month} (${m.status === "new" ? "new" : pct(m.delta_pct)}, ${usd(m.delta)} more)`, details: { ...m } });
  // the newest complete day of the payer's bill against the two weeks before it
  const yesterday = new Date(Date.now() - 86400_000).toISOString().slice(0, 10);
  const days = rows("select day, net_unblended as usd from spend_daily where provider = 'aws' and net_unblended is not null and day < ? order by day desc limit 15", yesterday).reverse().map((r) => ({ day: String(r.day), usd: Number(r.usd) }));
  const j = dayJump(days);
  if (j) out.push({ kind: "bill_day_jump", resource: "bill", resource_name: j.day, severity: "warning", message: `the bill on ${j.day}: ${usd(j.usd)}, ${j.ratio.toFixed(1)}x the median day of the two weeks before (${usd(j.median)})`, details: j });
  // every account each provider bills: one climbing fast is named
  try {
    const { accountsBilling } = await import("./accounts_overview.js");
    const b = await accountsBilling();
    for (const l of b.lines) {
      if (l.projected_usd == null || l.last_month_usd == null || l.delta_pct == null) continue;
      if (l.delta_pct >= 20 && l.projected_usd - l.last_month_usd >= 100)
        out.push({ kind: "account_spend_up", resource: l.account, resource_name: c.month, severity: "warning", message: `${l.provider.toUpperCase()} ${l.name || l.account}: projected ${usd(l.projected_usd)} this month against ${usd(l.last_month_usd)} last month (${pct(l.delta_pct)})${l.registered ? "" : "; billed through the organisation, not added to the advisor"}`, details: { ...l } });
    }
  } catch { /* no account lines yet */ }
  return out;
}

export function reviewProbes(): OpsFinding[] {
  const out: OpsFinding[] = [];
  const running = rows("select instance_id, name, ssm_status, probe_at from inventory_ec2 where gone = 0 and state = 'running'");
  if (!running.length) return out;
  const online = running.filter((r) => r.ssm_status === "Online");
  const stale = online.filter((r) => !r.probe_at || String(r.probe_at) < new Date(Date.now() - 86400_000).toISOString().replace("T", " ").slice(0, 19));
  const unreachable = running.filter((r) => r.ssm_status !== "Online");
  if (stale.length) {
    const names = stale.slice(0, 5).map((r) => r.name || r.instance_id).join(", ");
    out.push({ kind: "probe_gap", resource: stale.length === 1 ? stale[0].instance_id : "probes", resource_name: "", severity: stale.length >= Math.max(3, online.length * 0.2) ? "warning" : "info",
      message: `probes: ${stale.length} of ${online.length} SSM-online instances not probed in the last 24 hours (${names}${stale.length > 5 ? ", …" : ""}); the statistics behind this review go stale with them`, details: { instances: stale.map((r) => r.instance_id), online: online.length } });
  }
  if (unreachable.length) {
    const names = unreachable.slice(0, 5).map((r) => `${r.name || r.instance_id} (${r.ssm_status || "no agent"})`).join(", ");
    out.push({ kind: "probe_unreachable", resource: unreachable.length === 1 ? unreachable[0].instance_id : "probes", resource_name: "", severity: "info",
      message: `probes: ${unreachable.length} of ${running.length} running instances are not reachable through SSM: ${names}${unreachable.length > 5 ? ", …" : ""}`, details: { instances: unreachable.map((r) => ({ id: r.instance_id, ssm_status: r.ssm_status })) } });
  }
  return out;
}

export function reviewOpenIssues(): OpsFinding[] {
  const out: OpsFinding[] = [];
  const open = one("select count(*) as n, min(created_at) as oldest from alerts where acknowledged = 0");
  const old = rows("select kind, count(*) as n from alerts where acknowledged = 0 and datetime(created_at) < datetime('now', '-3 days') group by kind order by n desc");
  const oldN = old.reduce((t, r) => t + Number(r.n), 0);
  if (oldN) out.push({ kind: "alerts_stale", resource: "alerts", resource_name: "", severity: "warning",
    message: `alerts: ${oldN} of ${open.n} open alerts have waited more than 3 days without being acknowledged (${old.slice(0, 4).map((r) => `${r.n} ${r.kind}`).join(", ")}); oldest from ${String(open.oldest).slice(0, 10)}`, details: { open: open.n, stale: oldN, by_kind: old } });
  else if (open?.n) out.push({ kind: "alerts_open", resource: "alerts", resource_name: "", severity: "info", message: `alerts: ${open.n} open, none older than 3 days`, details: { open: open.n } });
  const run = one("select id, finished_at from runs where provider = 'aws' and status = 'completed' order by id desc limit 1");
  if (run) {
    const ctl = rows("select control_title, control_id, count(*) as n from findings where run_id = ? and status = 'alarm' group by control_id order by n desc", run.id);
    const n = ctl.reduce((t, r) => t + Number(r.n), 0);
    if (n) out.push({ kind: "alarm_findings", resource: "findings", resource_name: "", severity: "info", message: `findings: ${n} in alarm across ${ctl.length} controls in run #${run.id} (${ctl.slice(0, 3).map((r) => `${r.control_title || r.control_id}: ${r.n}`).join("; ")})`, details: { run_id: run.id, controls: ctl.slice(0, 10) } });
  }
  const scan = one("select id, finished_at from compliance_scans where status = 'completed' order by id desc limit 1");
  if (scan) {
    const crit = rows("select control_title, count(*) as n from compliance_findings where scan_id = ? and severity = 'critical' group by control_title order by n desc", scan.id);
    const n = crit.reduce((t, r) => t + Number(r.n), 0);
    if (n) out.push({ kind: "security_critical", resource: "security", resource_name: "", severity: "warning", message: `security: ${n} critical findings in scan #${scan.id} (${crit.slice(0, 3).map((r) => `${r.control_title}: ${r.n}`).join("; ")})`, details: { scan_id: scan.id, controls: crit.slice(0, 10) } });
  }
  return out;
}

export function reviewRecommendations(): OpsFinding[] {
  const out: OpsFinding[] = [];
  const open = rows("select id, title, resource, resource_name, est_monthly_saving, tier, created_at from recommendations where status = 'open'");
  if (open.length) {
    const s = distinctSaving(open);
    out.push({ kind: "recs_open", resource: "recommendations", resource_name: "", severity: "info", message: `recommendations: ${open.length} open, about ${usd(s.distinct)} a month if all were applied`, details: { open: open.length, saving: s } });
  }
  const weekAgo = new Date(Date.now() - 7 * 86400_000).toISOString().replace("T", " ").slice(0, 19);
  const waiting = open.filter((r) => r.tier === "approve" && Number(r.est_monthly_saving || 0) >= 50 && String(r.created_at) < weekAgo).sort((a, b) => Number(b.est_monthly_saving) - Number(a.est_monthly_saving));
  if (waiting.length) {
    const s = distinctSaving(waiting);
    out.push({ kind: "recs_waiting", resource: "recommendations", resource_name: "", severity: "warning",
      message: `recommendations: ${waiting.length} worth about ${usd(s.distinct)} a month have waited over a week for a decision; largest: ${waiting.slice(0, 3).map((r) => `${r.title} (${usd(r.est_monthly_saving)})`).join("; ")}`, details: { ids: waiting.slice(0, 20).map((r) => r.id), saving: s } });
  }
  const stuck = rows("select id, title, est_monthly_saving, decided_at from recommendations where status = 'approved' and decided_at is not null and datetime(decided_at) < datetime('now', '-3 days') order by est_monthly_saving desc");
  if (stuck.length) out.push({ kind: "recs_approved_stuck", resource: "recommendations", resource_name: "", severity: "warning",
    message: `recommendations: ${stuck.length} approved more than 3 days ago and not carried out yet (${stuck.slice(0, 3).map((r) => r.title).join("; ")})`, details: { ids: stuck.map((r) => r.id) } });
  return out;
}

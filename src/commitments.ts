/**
 * Commitments: how much of the Savings Plan and the reservations is actually used, and when they expire. Cost
 * Explorer's utilisation calls (GetSavingsPlansUtilization, GetReservationUtilization; 0.01 USD each) over the
 * last 30 days (reservations asked per service, since without a SERVICE filter only EC2 reservations answer), stored per commitment per day of refresh; the findings query already lists every commitment
 * with its expiry. Alerts: `commitment_underused` when 30-day utilisation is under the threshold (money paid
 * for capacity not used), `commitment_expiring` at 60 and 30 days (an alarm: on-demand rates follow).
 */
import { CostExplorerClient, GetReservationUtilizationCommand, GetSavingsPlansUtilizationCommand } from "@aws-sdk/client-cost-explorer";
import { config } from "./config.js";
import { db } from "./db.js";
import { sdkCredentials } from "./steampipe.js";
import { credentialGate } from "./gate.js";
import { describeError, noteSuccess } from "./permissions.js";

db.exec(`create table if not exists commitment_utilization (
  kind text not null, id text not null, day text not null,
  utilization_pct real, commitment_usd real, used_usd real, unused_usd real, net_savings_usd real, window_days integer not null,
  primary key (kind, id, day)
)`);

export interface CommitmentRow { kind: string; id: string; detail: string; monthly_usd: number | null; expires: string | null; days_left: number | null; utilization_pct: number | null; unused_usd_30d: number | null; unused_hours_30d?: number | null; net_savings_usd_30d: number | null }

const openAlert = db.prepare("select id from alerts where kind = ? and resource = ? and acknowledged = 0 limit 1");
const insertAlert = db.prepare("insert into alerts(kind, resource, message, details) values (?, ?, ?, ?)");
const ackAlert = db.prepare("update alerts set acknowledged = 1, acknowledged_by = 'system' where kind = ? and resource = ? and acknowledged = 0");
const dayStr = (d: Date) => d.toISOString().slice(0, 10);

export async function refreshCommitments(onLog: (s: string) => void = () => {}): Promise<{ savings_plans: number; reservations: number; alerts: number; errors: string[] }> {
  const out = { savings_plans: 0, reservations: 0, alerts: 0, errors: [] as string[] };
  const gate = await credentialGate("commitments");
  if (!gate.ok) { out.errors.push(gate.error || "credentials not working"); return out; }
  let creds: ReturnType<typeof sdkCredentials>;
  try { creds = sdkCredentials(); } catch (e: any) { out.errors.push(String(e?.message || e)); return out; }
  const client = new CostExplorerClient({ region: "us-east-1", credentials: creds.provider });
  const end = new Date(); end.setUTCHours(0, 0, 0, 0); const start = new Date(end.getTime() - 30 * 86400e3);
  const today = dayStr(new Date());
  const up = db.prepare(`insert into commitment_utilization(kind, id, day, utilization_pct, commitment_usd, used_usd, unused_usd, net_savings_usd, window_days) values (?, ?, ?, ?, ?, ?, ?, ?, 30)
    on conflict(kind, id, day) do update set utilization_pct = excluded.utilization_pct, commitment_usd = excluded.commitment_usd, used_usd = excluded.used_usd, unused_usd = excluded.unused_usd, net_savings_usd = excluded.net_savings_usd`);
  try {
    const r = await client.send(new GetSavingsPlansUtilizationCommand({ TimePeriod: { Start: dayStr(start), End: dayStr(end) } }));
    noteSuccess(["ce:GetSavingsPlansUtilization"], "commitments");
    const t = r.Total; const u = t?.Utilization; const s = t?.Savings; const a = t?.AmortizedCommitment;
    if (u) { up.run("savings_plan", "all", today, Number(u.UtilizationPercentage || 0), Number(a?.TotalAmortizedCommitment || u.TotalCommitment || 0), Number(u.UsedCommitment || 0), Number(u.UnusedCommitment || 0), Number(s?.NetSavings || 0)); out.savings_plans = 1; }
  } catch (e) { out.errors.push(describeError(e, "savings plan utilisation (ce:GetSavingsPlansUtilization)")); }
  // Reservations must be asked per service: without a SERVICE filter Cost Explorer answers for EC2 reservations only.
  const RI_SERVICES: [string, string][] = [["rds_ri", "Amazon Relational Database Service"], ["elasticache_ri", "Amazon ElastiCache"], ["ec2_ri", "Amazon Elastic Compute Cloud - Compute"]];
  for (const [kind, service] of RI_SERVICES) {
    try {
      const r = await client.send(new GetReservationUtilizationCommand({ TimePeriod: { Start: dayStr(start), End: dayStr(end) }, Filter: { Dimensions: { Key: "SERVICE", Values: [service] } }, GroupBy: [{ Type: "DIMENSION", Key: "SUBSCRIPTION_ID" }] }));
      noteSuccess(["ce:GetReservationUtilization"], "commitments");
      // one row per instance type: the findings list reservations by type, so that is the join key
      const byType = new Map<string, { purchased: number; used: number; unused: number; savings: number }>();
      for (const p of r.UtilizationsByTime || []) for (const g of p.Groups || []) {
        const type = g.Attributes?.instanceType || "?"; const u = g.Utilization; if (!u) continue;
        const cur = byType.get(type) || { purchased: 0, used: 0, unused: 0, savings: 0 };
        cur.purchased += Number(u.PurchasedHours || 0); cur.used += Number(u.TotalActualHours || 0); cur.unused += Number(u.UnusedHours || 0); cur.savings += Number(u.NetRISavings || 0);
        byType.set(type, cur);
      }
      for (const [type, v] of byType) { up.run(kind, type, today, v.purchased > 0 ? (100 * v.used) / v.purchased : 0, null, v.used, v.unused, v.savings); out.reservations++; }
    } catch (e) { out.errors.push(describeError(e, `reservation utilisation ${service} (ce:GetReservationUtilization)`)); }
  }
  client.destroy();
  out.alerts = raiseCommitmentAlerts();
  onLog(`savings plans ${out.savings_plans}, reservations ${out.reservations}, alerts ${out.alerts}${out.errors.length ? `; ${out.errors.join("; ")}` : ""}`);
  return out;
}

/** The commitments with their latest utilisation, from the findings query (expiry) and the utilisation table. */
export function listCommitments(): CommitmentRow[] {
  const latestRun = (db.prepare("select max(run_id) as id from findings where control_id = 'query.commitments'").get() as { id: number | null }).id;
  const rows = latestRun ? (db.prepare("select dimensions from findings where run_id = ? and control_id = 'query.commitments'").all(latestRun) as { dimensions: string }[]).map((r) => { try { return JSON.parse(r.dimensions); } catch { return null; } }).filter(Boolean) : [];
  const sp = db.prepare("select * from commitment_utilization where kind = 'savings_plan' order by day desc limit 1").get() as any;
  const riRows = db.prepare("select * from commitment_utilization where kind in ('rds_ri', 'elasticache_ri', 'ec2_ri') and day = (select max(day) from commitment_utilization where kind in ('rds_ri', 'elasticache_ri', 'ec2_ri'))").all() as any[];
  const ri = new Map(riRows.map((r) => [`${r.kind}|${r.id}`, r]));
  const typeOf = (detail: string) => String(detail || "").split(/\s+x\d+/)[0].trim();
  return rows.map((x: any) => {
    const u = x.kind === "savings_plan" ? sp : ri.get(`${x.kind}|${typeOf(x.detail)}`);
    return { kind: x.kind, id: x.id, detail: x.detail, monthly_usd: x.monthly_usd != null ? Number(x.monthly_usd) : null, expires: x.expires ?? null, days_left: x.days_left != null ? Number(x.days_left) : null,
      utilization_pct: u ? Number(u.utilization_pct) : null, unused_usd_30d: u && x.kind === "savings_plan" ? Number(u.unused_usd) : null, unused_hours_30d: u && x.kind !== "savings_plan" ? Number(u.unused_usd) : null, net_savings_usd_30d: u ? Number(u.net_savings_usd) : null };
  });
}

/** Under-used and expiring commitments as alerts; closes them when the condition clears. Returns the number raised. */
export function raiseCommitmentAlerts(): number {
  let raised = 0;
  for (const c of listCommitments()) {
    const res = `${c.kind}:${c.id}`;
    const under = c.utilization_pct != null && c.utilization_pct < config.commitmentMinUtilPct;
    if (under && !openAlert.get("commitment_underused", res)) { const msg = `${c.kind === "savings_plan" ? "Savings Plan" : "Reservation"} ${c.detail}: ${c.utilization_pct!.toFixed(0)}% used over 30 days${c.unused_usd_30d != null ? `, ${Math.round(c.unused_usd_30d)} USD of commitment unused` : ""}`; insertAlert.run("commitment_underused", res, msg, JSON.stringify({ summary: msg, ...c })); raised++; }
    if (!under) ackAlert.run("commitment_underused", res);
    const expiring = c.days_left != null && c.days_left <= 60;
    if (expiring && !openAlert.get("commitment_expiring", res)) { const msg = `${c.kind === "savings_plan" ? "Savings Plan" : "Reservation"} ${c.detail} expires in ${c.days_left} days (${c.expires})${c.monthly_usd ? `; ${Math.round(c.monthly_usd)} USD/month of covered usage returns to on-demand rates` : ""}`; insertAlert.run("commitment_expiring", res, msg, JSON.stringify({ summary: msg, ...c })); raised++; }
    if (!expiring) ackAlert.run("commitment_expiring", res);
  }
  return raised;
}

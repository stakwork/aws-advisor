/**
 * Security posture from Turbot's aws_compliance mod, run through the same Powerpipe and Steampipe connection as the
 * Thrifty benchmarks but on its own schedule (COMPLIANCE_CRON) and in its own tables: a scan raises a thousand-odd
 * alarms on a real account, and none of them may reach the cost agent's brief, the cost run's diff or its "material"
 * test. Every alarm is kept as a finding (the Security page); a finding remembers the scan it was first seen in, so
 * the page and the notification can say what is new.
 *
 * Only a few findings become recommendations (rule `sec_<item>`, action_type `security_fix`, no saving, tier
 * approve, never executed): every alarm of a critical control but the known noise, and a short list of high
 * controls when the resource is reachable. Reachable comes from what the advisor already knows and the scan does
 * not: which running instances carry a flagged security group, which of their listening ports that group opens to
 * the internet and which app owns the port (the probe, src/instance_apps.ts), and the domains that reach the box
 * (src/exposure.ts). A security group with 0.0.0.0/0 on 22 that no running instance uses is a finding; the same
 * group on a box with a public address where sshd listens is a recommendation that says so.
 */
import { createHash } from "node:crypto";
import { db, getJsonSetting } from "./db.js";
import { config } from "./config.js";
import { runBenchmark, ParsedFinding } from "./powerpipe.js";
import { testConnection } from "./steampipe.js";
import { describeError } from "./permissions.js";
import { upsertRecommendations } from "./collector.js";
import type { RecInput } from "./rules.js";
import { domainsReaching } from "./exposure.js";
import { ingressRulesFor, portsOn } from "./instance_apps.js";
import { configured as sphinxConfigured, inQuietHours, sendSphinx } from "./notify.js";
import { mirrorComplianceScanInBackground } from "./graph_mirror.js";
import { syncDecisionConceptInBackground } from "./concepts.js";

export const COMPLIANCE_BENCHMARKS: { id: string; title: string }[] = [
  { id: "foundational_security", title: "AWS Foundational Security Best Practices" },
  { id: "cis_v300", title: "CIS AWS Foundations v3.0.0" },
];
export const DEFAULT_COMPLIANCE_BENCHMARKS = ["foundational_security"];
export const SEVERITIES = ["critical", "high", "medium", "low"] as const;
const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
export const severityRank = (s: string | null | undefined) => SEVERITY_RANK[String(s)] ?? 4;

export const enabledComplianceBenchmarks = () => getJsonSetting<string[]>("compliance_benchmarks", DEFAULT_COMPLIANCE_BENCHMARKS)
  .filter((b) => COMPLIANCE_BENCHMARKS.some((x) => x.id === b));

// ---- which findings become recommendations ------------------------------------------------------------------------

/** Critical in the mod, hygiene in practice: kept as findings, never a recommendation. */
export const CRITICAL_NOISE = new Set(["foundational_security_cloudfront_1"]);

/**
 * Controls that become a recommendation whatever their severity says, and when: `sg` and `instance` only when the
 * resource is reachable (see exposureOfResource), `always` for account-wide and public-by-definition ones.
 */
export const CURATED: Record<string, "sg" | "instance" | "always"> = {
  foundational_security_ec2_18: "sg",       // unrestricted ingress on ports other than 80/443
  foundational_security_ec2_19: "sg",       // unrestricted ingress on high-risk ports (22, 3389, 3306, 5432...)
  foundational_security_ec2_8: "instance",  // IMDSv1 on a reachable box: the SSRF-to-credentials path
  foundational_security_eks_1: "always",    // public EKS endpoint
  foundational_security_iam_1: "always",    // a '*:*' policy
  foundational_security_cloudtrail_1: "always",
  foundational_security_guardduty_1: "always",
  foundational_security_sns_4: "always",    // public SNS topic
};

/** `aws_compliance.control.foundational_security_ec2_18` → `foundational_security_ec2_18`. */
export const shortControl = (controlId: string) => controlId.replace(/^aws_compliance\.control\./, "");
/** `foundational_security_ec2_18` → `ec2_18`, `cis_v300_5_2` → `cis_5_2`: the tail of the rule name. */
export const itemOf = (controlId: string) => shortControl(controlId).replace(/^foundational_security_/, "").replace(/^cis_v\d+_/, "cis_");
/** "18 Security groups should only allow…" → "Security groups should only allow…". */
export const cleanTitle = (t: string | null | undefined) => String(t || "").replace(/^\d+(\.\d+)*\s+/, "");

/** The id a resource ARN is known by elsewhere in the advisor: i-…, sg-…, vol-…; the ARN otherwise. */
export function shortId(resource: string | null | undefined): string {
  const r = String(resource || "");
  const m = /^arn:aws[a-z-]*:ec2:[^:]*:[^:]*:(?:instance|security-group|volume|snapshot|vpc|subnet)\/(.+)$/.exec(r);
  return m ? m[1] : r;
}

export interface ExposedInstance { id: string; name: string | null; public_ip: string | null; domains: string[]; ports: { port: number; proto: string; app: string | null }[] }
export interface Exposure { exposed: boolean; summary: string; open_ports: string[]; instances: ExposedInstance[] }

const q = <T>(sql: string, ...p: unknown[]): T[] => { try { return db.prepare(sql).all(...p) as T[]; } catch { return []; } };

function instanceFacts(id: string, openToInternet?: (port: number, proto: string) => boolean): ExposedInstance | null {
  const row = q<{ instance_id: string; name: string | null; public_ip: string | null; state: string | null }>("select instance_id, name, public_ip, state from inventory_ec2 where instance_id = ? and gone = 0", id)[0];
  if (!row) return null;
  let ports: ExposedInstance["ports"] = [];
  try {
    ports = portsOn(id).filter((p) => !p.gone && p.exposure === "internet" && (!openToInternet || openToInternet(p.port, p.proto)))
      .map((p) => ({ port: p.port, proto: p.proto, app: p.app_name }));
  } catch { /* no probe tables yet */ }
  return { id, name: row.name, public_ip: row.public_ip, domains: domainsReaching("ec2", id).map((d) => d.name), ports };
}

const describeInstance = (i: ExposedInstance) => {
  const parts = [`${i.name ? `${i.name} (${i.id})` : i.id}`];
  if (i.public_ip) parts.push(`public ${i.public_ip}`);
  if (i.ports.length) parts.push(`listens on ${i.ports.slice(0, 6).map((p) => `${p.port}${p.app ? ` ${p.app}` : ""}`).join(", ")}`);
  if (i.domains.length) parts.push(`reached by ${i.domains.slice(0, 3).join(", ")}${i.domains.length > 3 ? ` +${i.domains.length - 3}` : ""}`);
  return parts.join(", ");
};

/** Who can reach a flagged security group's members: the running instances carrying it, their public address, the ports the group opens to the internet that something listens on, the domains. */
export function sgExposure(groupId: string): Exposure {
  const rules = ingressRulesFor([groupId]).filter((r) => r.cidr_ipv4 === "0.0.0.0/0" || r.cidr_ipv6 === "::/0");
  const open_ports = rules.map((r) => r.from_port == null || r.from_port === -1 ? "all" : r.from_port === r.to_port ? String(r.from_port) : `${r.from_port}-${r.to_port}`);
  const opens = (port: number, proto: string) => rules.some((r) => (r.ip_protocol == null || r.ip_protocol === "-1" || r.ip_protocol.toLowerCase() === proto)
    && (r.from_port == null || r.from_port === -1 || ((r.from_port ?? 0) <= port && port <= (r.to_port ?? 65535))));
  const ids = q<{ instance_id: string }>("select instance_id from inventory_ec2 where gone = 0 and state = 'running' and snapshot like ?", `%"${groupId}"%`).map((r) => r.instance_id);
  const instances = ids.map((id) => instanceFacts(id, rules.length ? opens : undefined)).filter((i): i is ExposedInstance => Boolean(i));
  const reachable = instances.filter((i) => i.public_ip || i.domains.length);
  const exposed = reachable.length > 0;
  const summary = !instances.length ? "No running instance in the inventory carries this group (it may guard a load balancer, a database or nothing)."
    : !exposed ? `${instances.length} running instance${instances.length === 1 ? "" : "s"} carry it, none with a public address or a domain.`
    : `Reachable: ${reachable.slice(0, 4).map(describeInstance).join("; ")}${reachable.length > 4 ? `; … ${reachable.length - 4} more` : ""}.`;
  return { exposed, summary, open_ports, instances };
}

/** A flagged instance: reachable when it has a public address or a domain resolves to it. */
export function instanceExposure(id: string): Exposure {
  const i = instanceFacts(id);
  if (!i) return { exposed: false, summary: "Not in the inventory (stopped, gone, or another account).", open_ports: [], instances: [] };
  const exposed = Boolean(i.public_ip || i.domains.length);
  return { exposed, summary: exposed ? `Reachable: ${describeInstance(i)}.` : "No public address and no domain reaches it.", open_ports: i.ports.map((p) => String(p.port)), instances: [i] };
}

export function exposureOfResource(resource: string | null): Exposure | null {
  const id = shortId(resource);
  if (/^sg-/.test(id)) return sgExposure(id);
  if (/^i-/.test(id)) return instanceExposure(id);
  return null;
}

export interface ScanFinding { benchmark: string; control_id: string; control_title: string | null; severity: string | null; resource: string | null; reason: string | null; region: string | null; account_id: string | null; first_seen_at?: string }

/** The recommendations one scan's alarms warrant. `exposure` is injected so the rule is testable without a database. */
export function complianceRecommendations(findings: ScanFinding[], exposure: (resource: string | null) => Exposure | null = exposureOfResource): RecInput[] {
  const out = new Map<string, RecInput>();
  for (const f of findings) {
    const control = shortControl(f.control_id);
    const curated = CURATED[control];
    const critical = f.severity === "critical" && !CRITICAL_NOISE.has(control);
    if (!critical && !curated) continue;
    let ex: Exposure | null = null;
    if (curated === "sg" || curated === "instance") {
      ex = exposure(f.resource);
      if (!critical && !ex?.exposed) continue;
    }
    const id = shortId(f.resource);
    const rule = `sec_${itemOf(f.control_id)}`;
    if (out.has(`${rule}:${id}`)) continue;
    const name = ex?.instances.length === 1 && /^i-/.test(id) ? ex.instances[0].name : null;
    const rationale = [
      `${(f.severity || "unrated").toUpperCase()} · ${String(f.reason || cleanTitle(f.control_title)).replace(/\.+$/, "")}.`,
      ex ? ex.summary : null,
      ex?.open_ports.length ? `Open to 0.0.0.0/0 on ${ex.open_ports.slice(0, 10).join(", ")}.` : null,
      `Control ${control} (${f.benchmark})${f.region ? `, ${f.region}` : ""}. Security findings carry no saving; the fix is a change a person makes.`,
    ].filter(Boolean).join(" ");
    out.set(`${rule}:${id}`, {
      rule,
      title: `${cleanTitle(f.control_title)}: ${name || id.split(":").pop()}`,
      resource: id,
      resourceName: name || undefined,
      actionType: "security_fix",
      estMonthlySaving: null,
      tier: "approve",
      confidence: ex?.exposed || critical ? 0.9 : 0.7,
      rationale,
      evidence: { control_id: f.control_id, benchmark: f.benchmark, severity: f.severity, reason: f.reason, region: f.region, account_id: f.account_id, first_seen_at: f.first_seen_at ?? null, exposure: ex },
    });
  }
  return [...out.values()];
}

// ---- the scan -----------------------------------------------------------------------------------------------------

const fingerprint = (...parts: string[]) => createHash("sha1").update(parts.join("|")).digest("hex").slice(0, 16);

let busy = false;
export const complianceBusy = () => busy;

/** Scans that were in flight when the process died. */
db.prepare("update compliance_scans set status = 'failed', finished_at = datetime('now'), error = 'interrupted: the advisor restarted during the scan' where status = 'running'").run();

function log(scanId: number, line: string) {
  db.prepare("update compliance_scans set log = log || ? where id = ?").run(line + "\n", scanId);
}

export function startComplianceScan(trigger = "manual"): number {
  if (busy) throw new Error("a security scan is already in progress");
  const benchmarks = enabledComplianceBenchmarks();
  if (!benchmarks.length) throw new Error("no security benchmark is enabled (Settings > Security)");
  const id = Number(db.prepare("insert into compliance_scans(trigger, benchmarks) values (?, ?)").run(trigger, JSON.stringify(benchmarks)).lastInsertRowid);
  busy = true;
  executeScan(id, benchmarks).catch((e) => console.error(`[compliance] scan #${id}: ${e?.message || e}`)).finally(() => { busy = false; });
  return id;
}

export function previousCompletedScan(scanId: number): number | null {
  return (db.prepare("select id from compliance_scans where status = 'completed' and id < ? order by id desc limit 1").get(scanId) as { id: number } | undefined)?.id ?? null;
}

const insertFinding = db.prepare(`insert into compliance_findings(scan_id, benchmark, control_id, control_title, severity, service, resource, reason, account_id, region, fingerprint, first_seen_scan, first_seen_at)
  values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);

async function executeScan(scanId: number, benchmarks: string[]) {
  try {
    const conn = await testConnection(20_000);
    if (!conn.ok) throw new Error(`Steampipe connection is not ready: ${conn.error}`);
    db.prepare("update compliance_scans set account_id = ? where id = ?").run(conn.accountId, scanId);
    log(scanId, `Account ${conn.accountId}`);

    const prevId = previousCompletedScan(scanId);
    const prev = new Map((prevId == null ? [] : db.prepare("select fingerprint, first_seen_scan, first_seen_at from compliance_findings where scan_id = ?").all(prevId) as { fingerprint: string; first_seen_scan: number; first_seen_at: string }[]).map((r) => [r.fingerprint, r]));
    const nowIso = new Date().toISOString();
    const seen = new Set<string>();
    let errors = 0, failedBenchmarks = 0;
    for (const b of benchmarks) {
      log(scanId, `Benchmark ${b}…`);
      let alarms: ParsedFinding[] = [];
      try {
        const r = await runBenchmark(`aws_compliance.benchmark.${b}`, () => { /* Powerpipe's own chatter */ });
        // a denied call surfaces as an errored control, never as an alarm: it goes to Settings > Permissions through describeError
        for (const ce of r.errors) {
          errors++;
          log(scanId, `  ${shortControl(ce.controlId)} ${ce.kind === "run_error" ? "failed" : `${ce.count} error result(s)`}: ${describeError(ce.message, `compliance ${b} ${shortControl(ce.controlId)}`, 240)}`);
        }
        alarms = r.findings.filter((f) => f.status === "alarm");
        log(scanId, `  ${alarms.length} alarms out of ${r.findings.length} results, ${r.errors.length} control(s) with errors`);
      } catch (e: any) {
        failedBenchmarks++;
        log(scanId, `  failed: ${describeError(e, `compliance benchmark ${b}`)}`);
        continue;
      }
      db.transaction(() => {
        for (const f of alarms) {
          const fp = fingerprint(f.controlId, f.resource);
          if (seen.has(fp)) continue;
          seen.add(fp);
          const was = prev.get(fp);
          insertFinding.run(scanId, b, f.controlId, f.controlTitle, f.severity || null, f.tags?.service || null, f.resource, f.reason,
            f.dimensions.account_id || null, f.dimensions.region || null, fp, was?.first_seen_scan ?? scanId, was?.first_seen_at ?? nowIso);
        }
      })();
    }
    if (failedBenchmarks === benchmarks.length) throw new Error("every benchmark failed; see the log");

    const counts: Record<string, number> = {};
    for (const r of db.prepare("select coalesce(severity, 'unrated') as s, count(*) as n from compliance_findings where scan_id = ? group by 1").all(scanId) as { s: string; n: number }[]) counts[r.s] = r.n;
    const newAlarms = prevId == null ? 0 : [...seen].filter((fp) => !prev.has(fp)).length;
    // a benchmark that did not run says nothing about what was resolved
    const resolved = prevId == null || failedBenchmarks ? 0 : [...prev.keys()].filter((fp) => !seen.has(fp)).length;
    log(scanId, `${seen.size} alarms (${SEVERITIES.map((s) => `${counts[s] || 0} ${s}`).join(", ")}${counts.unrated ? `, ${counts.unrated} unrated` : ""})${prevId != null ? `; since scan #${prevId}: ${newAlarms} new, ${resolved} resolved` : ""}`);

    const findings = db.prepare("select benchmark, control_id, control_title, severity, resource, reason, region, account_id, first_seen_at from compliance_findings where scan_id = ?").all(scanId) as ScanFinding[];
    const recs = complianceRecommendations(findings);
    upsertRecommendations(0, recs, "rules", undefined, { reconcile: false });
    const resolvedRecs = failedBenchmarks ? [] : resolveVanished(new Set(recs.map((r) => `${r.rule}:${r.resource}`)));
    log(scanId, `Recommendations: ${recs.length} warranted${resolvedRecs.length ? `, ${resolvedRecs.length} resolved (the finding went away)` : ""}`);

    db.prepare("update compliance_scans set status = 'completed', finished_at = datetime('now'), alarms = ?, new_alarms = ?, resolved = ?, errors = ?, counts = ? where id = ?")
      .run(seen.size, newAlarms, resolved, errors, JSON.stringify(counts), scanId);
    mirrorComplianceScanInBackground(scanId);
    if (prevId != null) await notifyNewFindings(scanId).catch((e: any) => log(scanId, `notification failed: ${e?.message || e}`));
  } catch (e: any) {
    db.prepare("update compliance_scans set status = 'failed', finished_at = datetime('now'), error = ? where id = ?").run(String(e?.message || e), scanId);
    log(scanId, `FAILED: ${e?.message || e}`);
  }
}

/** Open security recommendations whose finding is gone: resolved, and their Concept told when a person had decided on them before. */
function resolveVanished(seen: Set<string>): number[] {
  const open = db.prepare("select id, fingerprint, decided_at from recommendations where status = 'open' and rule like 'sec\\_%' escape '\\'").all() as { id: number; fingerprint: string; decided_at: string | null }[];
  const gone = open.filter((r) => !seen.has(r.fingerprint));
  const upd = db.prepare("update recommendations set status = 'resolved', updated_at = datetime('now') where id = ?");
  db.transaction(() => { for (const r of gone) upd.run(r.id); })();
  for (const r of gone) if (r.decided_at) syncDecisionConceptInBackground(r.id);
  return gone.map((r) => r.id);
}

// ---- notification -------------------------------------------------------------------------------------------------

export function formatScanMessage(scanId: number, fresh: ScanFinding[], publicUrl: string): string {
  const lines = [`🔐 SECURITY — ${fresh.length} new critical/high finding${fresh.length === 1 ? "" : "s"} in scan #${scanId}`];
  for (const f of fresh.slice(0, 8)) lines.push(`- [${f.severity}] ${cleanTitle(f.control_title)}: ${shortId(f.resource).split(":").pop()}${f.region ? ` (${f.region})` : ""}`);
  if (fresh.length > 8) lines.push(`… ${fresh.length - 8} more`);
  lines.push(`${publicUrl}/security?scan=${scanId}&new=1`);
  return lines.join("\n");
}

/** One chat message per scan when critical or high findings appeared since the previous scan; recorded in `notifications` like the recommendation events. */
async function notifyNewFindings(scanId: number): Promise<void> {
  if (!sphinxConfigured() || config.notifyLevel === "off") return;
  const fresh = (db.prepare("select * from compliance_findings where scan_id = ? and first_seen_scan = ? and severity in ('critical', 'high')").all(scanId, scanId) as ScanFinding[])
    .sort((a, b) => severityRank(a.severity) - severityRank(b.severity));
  if (!fresh.length) return;
  const content = formatScanMessage(scanId, fresh, config.notifyLinkUrl);
  const r = db.prepare("insert or ignore into notifications(subject, subject_id, event, dedupe, content) values ('compliance_scan', ?, 'new_findings', ?, ?)").run(scanId, `compliance:${scanId}`, content);
  if (!r.changes) return;
  const rowId = Number(r.lastInsertRowid);
  if (inQuietHours(config.notifyQuietHours, new Date().getHours())) {
    db.prepare("update notifications set sent_at = datetime('now'), result = 'skipped: quiet hours' where id = ?").run(rowId);
    log(scanId, "New critical/high findings: not posted (quiet hours)");
    return;
  }
  const s = await sendSphinx(content);
  const result = s.ok ? "sent" : `failed: ${s.status ? `${s.status} ` : ""}${s.body || "no response"}`.slice(0, 300);
  db.prepare("update notifications set sent_at = datetime('now'), result = ? where id = ?").run(result, rowId);
  log(scanId, `New critical/high findings posted to the chat: ${result}`);
}

// ---- reads for the page and the MCP tool --------------------------------------------------------------------------

export function latestCompletedScan(): number | null {
  return (db.prepare("select id from compliance_scans where status = 'completed' order by id desc limit 1").get() as { id: number } | undefined)?.id ?? null;
}

export function listScans(limit = 20) {
  return (db.prepare("select id, started_at, finished_at, status, trigger, account_id, benchmarks, alarms, new_alarms, resolved, errors, counts, error from compliance_scans order by id desc limit ?").all(limit) as any[])
    .map((s) => ({ ...s, benchmarks: safeJson(s.benchmarks) ?? [], counts: safeJson(s.counts) ?? {} }));
}

export function getScan(id: number) {
  const s = db.prepare("select * from compliance_scans where id = ?").get(id) as any;
  return s ? { ...s, benchmarks: safeJson(s.benchmarks) ?? [], counts: safeJson(s.counts) ?? {} } : null;
}

const safeJson = (s: string | null) => { try { return s ? JSON.parse(s) : null; } catch { return null; } };

export interface FindingQuery { scan_id?: number; severity?: string; control_id?: string; q?: string; only_new?: boolean; resource?: string }

/** One scan's findings, filtered, worst first; `controls` counts the whole scan so the filter keeps its options. */
export function complianceFindings(f: FindingQuery) {
  const scanId = f.scan_id ?? latestCompletedScan();
  if (scanId == null) return { scan_id: null, rows: [] as any[], controls: [] as any[], services: [] as any[] };
  const where = ["scan_id = ?"]; const params: unknown[] = [scanId];
  if (f.severity) { if (f.severity === "unrated") where.push("severity is null"); else { where.push("severity = ?"); params.push(f.severity); } }
  if (f.control_id) { where.push("control_id = ?"); params.push(f.control_id); }
  if (f.only_new) where.push("first_seen_scan = scan_id and exists (select 1 from compliance_scans p where p.status = 'completed' and p.id < compliance_findings.scan_id)");
  if (f.resource) { where.push("resource like ?"); params.push(`%${f.resource}%`); }
  if (f.q) { where.push("(resource like ? or reason like ? or control_title like ?)"); params.push(`%${f.q}%`, `%${f.q}%`, `%${f.q}%`); }
  const rows = (db.prepare(`select id, benchmark, control_id, control_title, severity, service, resource, reason, account_id, region, first_seen_scan, first_seen_at from compliance_findings where ${where.join(" and ")}`).all(...params) as any[])
    .sort((a, b) => severityRank(a.severity) - severityRank(b.severity) || String(a.control_id).localeCompare(String(b.control_id)) || String(a.resource).localeCompare(String(b.resource)));
  const controls = (db.prepare("select control_id, control_title, severity, benchmark, count(*) as n from compliance_findings where scan_id = ? group by control_id order by n desc").all(scanId) as any[])
    .sort((a, b) => severityRank(a.severity) - severityRank(b.severity) || b.n - a.n);
  const services = db.prepare("select coalesce(service, '—') as service, count(*) as n from compliance_findings where scan_id = ? group by 1 order by n desc").all(scanId) as any[];
  return { scan_id: scanId, rows, controls, services };
}

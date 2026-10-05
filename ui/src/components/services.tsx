import { Fragment, useEffect, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { api, usd, when } from "../api";
import { DetailCell, Empty, Stat, Td, Th } from "./ui";

/**
 * The platform services, one generic kind per Inventory tab (src/service_inventory.ts): certificates, messaging, keys,
 * file systems, backups, analytics, stacks, threat detection, and web ACLs under Filters. Every kind is the same row
 * shape (name, state, props, links, a list price); the columns and the header numbers are per kind. A row opens its
 * properties as the graph holds them and its edges to other nodes.
 */
export type ServiceTab = "certificates" | "messaging" | "keys" | "files" | "backups" | "analytics" | "stacks" | "threats" | "waf";

type Col = { h: string; cell: (r: any) => ReactNode; right?: boolean };
const p = (r: any) => r.props || {};
const yes = (v: unknown) => (v == null ? "—" : v ? "yes" : "no");
const n = (v: unknown) => (v == null ? "—" : Number(v).toLocaleString());
const gbs = (v: unknown) => (v == null ? "—" : `${Number(v).toLocaleString(undefined, { maximumFractionDigits: 2 })} GB`);
const day = (v: unknown) => (v ? String(v).slice(0, 10) : "—");
const warn = (on: boolean, text: ReactNode) => <span className={on ? "text-amber-300" : ""}>{text}</span>;
const bad = (on: boolean, text: ReactNode) => <span className={on ? "text-red-300" : ""}>{text}</span>;
const list = (v: unknown, max = 3) => { const a = Array.isArray(v) ? v.map(String) : []; return a.length ? <span title={a.join("\n")}>{a.slice(0, max).join(", ")}{a.length > max ? <span className="text-zinc-500"> +{a.length - max}</span> : null}</span> : <span className="text-zinc-600">—</span>; };
const price: Col = { h: "$ / mo", right: true, cell: (r) => (r.monthly_usd == null ? <span className="text-zinc-600" title="not priced at list">—</span> : usd(r.monthly_usd, 2)) };

const COLUMNS: Record<ServiceTab, Col[]> = {
  certificates: [
    { h: "Names", cell: (r) => list(p(r).domains, 2) },
    { h: "Status", cell: (r) => bad(["expired", "revoked", "failed"].includes(p(r).status), p(r).status ?? r.state) },
    { h: "Issuer", cell: (r) => p(r).issuer },
    { h: "Expires", cell: (r) => warn(p(r).days_left != null && p(r).days_left <= 30, <>{day(p(r).not_after)}{p(r).days_left != null ? <span className="text-zinc-500"> · {p(r).days_left}d</span> : null}</>) },
    { h: "In use", right: true, cell: (r) => warn(p(r).in_use === false, p(r).used_by ?? 0) },
    { h: "Key", cell: (r) => p(r).key_algorithm ?? "—" },
  ],
  messaging: [
    { h: "Kind", cell: (r) => `${p(r).kind}${p(r).fifo ? " · FIFO" : ""}` },
    { h: "Subscribers", right: true, cell: (r) => <>{n(p(r).subscriptions)}{p(r).pending ? <span className="text-amber-300"> +{p(r).pending} pending</span> : null}</> },
    { h: "Protocols", cell: (r) => list(p(r).protocols) },
    { h: "Encrypted", cell: (r) => warn(p(r).encrypted === false, yes(p(r).encrypted)) },
    { h: "Dead-letter", cell: (r) => yes(p(r).dlq) },
    { h: "Publishes 30d", right: true, cell: (r) => n(p(r).messages_30d) },
    price,
  ],
  keys: [
    { h: "Managed by", cell: (r) => (p(r).managed ? "AWS" : "account") },
    { h: "State", cell: (r) => warn(p(r).key_state !== "enabled", <>{p(r).key_state}{p(r).deletion_at ? <span className="text-zinc-500"> · deleted {day(p(r).deletion_at)}</span> : null}</>) },
    { h: "Usage", cell: (r) => `${p(r).usage ?? "—"}${p(r).spec ? ` · ${p(r).spec}` : ""}` },
    { h: "Rotation", cell: (r) => warn(!p(r).managed && p(r).key_state === "enabled" && p(r).rotation_enabled === false, yes(p(r).rotation_enabled)) },
    { h: "Aliases", cell: (r) => list(p(r).aliases, 2) },
    price,
  ],
  files: [
    { h: "Size", right: true, cell: (r) => gbs(p(r).size_gb) },
    { h: "Standard · IA · archive", right: true, cell: (r) => `${n(p(r).standard_gb)} · ${n(p(r).ia_gb)} · ${n(p(r).archive_gb)}` },
    { h: "Class", cell: (r) => p(r).class },
    { h: "Throughput", cell: (r) => `${p(r).throughput_mode ?? "—"}${p(r).provisioned_mibps ? ` ${p(r).provisioned_mibps} MiB/s` : ""}` },
    { h: "Encrypted", cell: (r) => warn(p(r).encrypted === false, yes(p(r).encrypted)) },
    { h: "Mount targets", right: true, cell: (r) => n(p(r).mount_targets) },
    price,
  ],
  backups: [
    { h: "Kind", cell: (r) => (r.native_type === "backup_plan" ? "plan" : "vault") },
    { h: "Holds", cell: (r) => (r.native_type === "backup_plan" ? list(p(r).schedules, 1) : <>{n(p(r).recovery_points)} points · {gbs(p(r).size_gb)}</>) },
    { h: "Covers", cell: (r) => (r.native_type === "backup_plan" ? list(p(r).selections, 1) : list(p(r).by_type)) },
    { h: "Retention", cell: (r) => (r.native_type === "backup_plan" ? (p(r).keeps_forever ? warn(true, "forever") : p(r).retention_days != null ? `${p(r).retention_days} days` : "—") : p(r).locked ? `locked${p(r).min_retention_days ? ` ${p(r).min_retention_days}–${p(r).max_retention_days ?? "∞"}d` : ""}` : "—") },
    { h: "Latest", cell: (r) => day(r.native_type === "backup_plan" ? p(r).last_run_at : p(r).newest_at) },
    price,
  ],
  analytics: [
    { h: "Engine", cell: (r) => `${p(r).engine}${p(r).engine_version ? ` ${p(r).engine_version}` : ""}` },
    { h: "Scanned 30d", right: true, cell: (r) => (p(r).metrics_published ? gbs(p(r).scanned_gb_30d) : <span className="text-zinc-600" title="the workgroup does not publish CloudWatch metrics">not published</span>) },
    { h: "Scan limit", right: true, cell: (r) => warn(p(r).scan_limit_gb == null, p(r).scan_limit_gb == null ? "none" : gbs(p(r).scan_limit_gb)) },
    { h: "Results", cell: (r) => <span className="font-mono text-xs">{p(r).output_location ?? "—"}</span> },
    { h: "Encrypted", cell: (r) => warn(p(r).output_encrypted === false, yes(p(r).output_encrypted)) },
    price,
  ],
  stacks: [
    { h: "Status", cell: (r) => bad(/FAILED|^ROLLBACK_COMPLETE$/.test(String(r.state)), String(r.state || "").toLowerCase().replace(/_/g, " ")) },
    { h: "Drift", cell: (r) => warn(p(r).drift === "drifted", p(r).drift ?? "—") },
    { h: "Resources", right: true, cell: (r) => <>{n(p(r).resources)}{p(r).failed_resources ? <span className="text-red-300"> · {p(r).failed_resources} failed</span> : null}</> },
    { h: "Types", cell: (r) => list(p(r).resource_types, 2) },
    { h: "Protected", cell: (r) => yes(p(r).termination_protection) },
    { h: "Updated", cell: (r) => day(p(r).updated_at ?? r.created) },
  ],
  threats: [
    { h: "Status", cell: (r) => warn(!p(r).enabled, p(r).enabled ? "enabled" : "disabled") },
    { h: "Open findings", right: true, cell: (r) => <>{n(p(r).findings_open)}{p(r).findings_critical || p(r).findings_high ? <span className="text-red-300"> · {p(r).findings_critical ?? 0} critical · {p(r).findings_high ?? 0} high</span> : null}</> },
    { h: "Protections on", cell: (r) => list(p(r).protections_on, 3) },
    { h: "Off", cell: (r) => list(p(r).protections_off, 2) },
    { h: "Last finding", cell: (r) => day(p(r).last_finding_at) },
  ],
  waf: [
    { h: "Default", cell: (r) => p(r).default_action },
    { h: "Rules", cell: (r) => list(p(r).rule_list, 2) },
    { h: "Attached to", right: true, cell: (r) => warn(!p(r).attached && !p(r).edge, p(r).edge ? "CloudFront" : n(p(r).attached)) },
    { h: "Requests 30d", right: true, cell: (r) => <>{n(p(r).requests_30d)}{p(r).blocked_30d ? <span className="text-zinc-500"> · {n(p(r).blocked_30d)} blocked</span> : null}</> },
    { h: "Logging", cell: (r) => warn(p(r).logging === false, yes(p(r).logging)) },
    price,
  ],
};

/** The header numbers per kind, from GET /inventory/summary's `services`. */
function Stats({ tab, s }: { tab: ServiceTab; s: any }) {
  if (!s) return null;
  const gone = s.gone ? ` · ${s.gone} gone` : "";
  const cards: [string, ReactNode, ReactNode?][] = {
    certificates: [["Certificates", s.total, `${s.unused} not in use${gone}`], ["Expiring in 30 days", s.expiring_30d, `${s.expired} expired`]],
    messaging: [["Topics", s.total, `${n(s.subscriptions)} subscribers${gone}`], ["Publishes 30d", n(s.messages_30d)], ["Unencrypted", s.unencrypted], ["At list / month", usd(s.monthly_usd, 2), "publishes only"]],
    keys: [["Keys", s.total, `${s.customer} the account's, ${s.total - s.customer} AWS-managed${gone}`], ["No rotation", s.no_rotation, "enabled keys of the account's own"], ["Pending deletion", s.pending_deletion], ["At list / month", usd(s.monthly_usd, 2), "1 USD per key of the account's own"]],
    files: [["File systems", s.total, gone || undefined], ["Stored", gbs(s.size_gb)], ["Unencrypted", s.unencrypted], ["At list / month", usd(s.monthly_usd, 2), "storage by class and provisioned throughput"]],
    backups: [["Vaults · plans", `${s.backup_vault} · ${s.backup_plan}`, gone || undefined], ["Recovery points", n(s.recovery_points), gbs(s.size_gb)], ["Resources backed up", n(s.protected)], ["At list / month", usd(s.monthly_usd, 2), "stored GB, warm and cold"]],
    analytics: [["Workgroups", s.total, gone || undefined], ["Scanned 30d", gbs(s.scanned_gb_30d)], ["At list / month", usd(s.monthly_usd, 2), "5 USD per TB scanned"]],
    stacks: [["Stacks", s.total, gone || undefined], ["Resources managed", n(s.managed)], ["Drifted", s.drifted], ["Failed", s.failed]],
    threats: [["Detectors", s.total, `${s.enabled} enabled${gone}`], ["Open findings", s.findings_open], ["Critical · high", `${s.critical} · ${s.high}`], ["Medium · low", `${s.medium} · ${s.low}`]],
    waf: [["Web ACLs", s.total, `${s.unattached} attached to nothing${gone}`], ["Resources guarded", s.attached], ["At list / month", usd(s.monthly_usd, 2), "ACL, rules and requests"]],
  }[tab] as [string, ReactNode, ReactNode?][];
  return <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">{cards.map(([label, value, hint]) => <Stat key={label} label={label} value={value} hint={hint} />)}</div>;
}

/** Where a linked id lands in the inventory, by its shape, or null for things the inventory has no tab for. */
function linkTo(id: string): string | null {
  const tab = /^i-/.test(id) ? "ec2" : /^vol-/.test(id) ? "ebs" : /^sg-/.test(id) ? "sg" : /^arn:aws:elasticloadbalancing:/.test(id) ? "elb" : /^arn:aws:lambda:/.test(id) ? "lambda" : /^arn:aws:dynamodb:/.test(id) ? "dynamodb"
    : /^arn:aws:kms:/.test(id) ? "keys" : /^arn:aws:sns:/.test(id) ? "messaging" : /^arn:aws:acm:/.test(id) ? "certificates" : /^arn:aws:elasticfilesystem:/.test(id) ? "files" : /^arn:aws:backup:/.test(id) ? "backups"
    : /^arn:aws:cloudformation:/.test(id) ? "stacks" : /^arn:aws:athena:/.test(id) ? "analytics" : null;
  return tab ? `/inventory?tab=${tab}&id=${encodeURIComponent(id)}` : null;
}

const EDGE_WORD: Record<string, [string, string]> = {
  SECURES: ["secures", "secured by"], DELIVERS_TO: ["delivers to", "receives from"], ENCRYPTS: ["encrypts", "encrypted by"], GUARDED_BY: ["guarded by", "guards"], IN_NETWORK: ["in network", "contains"],
  IN_SEGMENT: ["in subnet", "contains"], MANAGES: ["manages", "managed by"], PART_OF: ["part of", "contains"], PROTECTS: ["protects", "protected by"], STORES_IN: ["stores in", "receives from"],
  BACKED_UP_TO: ["backed up to", "holds the backups of"], WRITES_TO: ["writes to", "written by"],
};

function Detail({ r }: { r: any }) {
  const props = Object.entries(r.props || {}).filter(([, v]) => v != null && v !== "" && !(Array.isArray(v) && !v.length));
  const fmt = (v: unknown) => (Array.isArray(v) ? <ul>{v.map((x, i) => <li key={i}>{String(x)}</li>)}</ul> : typeof v === "boolean" ? (v ? "yes" : "no") : String(v));
  const tags = Object.entries(r.tags || {});
  return (
    <div className="space-y-4 lg:columns-2 lg:gap-8">
      <div className="break-inside-avoid">
        <div className="mb-1 text-xs uppercase tracking-wide text-zinc-500">As the graph holds it</div>
        <dl className="grid grid-cols-[10rem_1fr] gap-x-3 gap-y-0.5 text-sm">
          {[["id", <span className="break-all font-mono text-xs">{r.id}</span>], ["region", r.region || "—"], ["state", r.state || "—"], ["created", r.created ? when(r.created) : "—"], ["first seen", when(r.first_seen)], ["last seen", when(r.last_seen)],
            ...props.map(([k, v]) => [k.replace(/_/g, " "), fmt(v)])].map(([k, v]) => <Fragment key={String(k)}><dt className="text-zinc-500">{k as string}</dt><dd className="min-w-0 break-words">{v as ReactNode}</dd></Fragment>)}
        </dl>
      </div>
      <div className="break-inside-avoid">
        <div className="mb-1 text-xs uppercase tracking-wide text-zinc-500">Edges</div>
        {!r.links?.length ? <div className="text-sm text-zinc-500">None.</div> : (
          <ul className="space-y-0.5 text-sm">
            {r.links.map((l: any, i: number) => { const to = l.label ? null : linkTo(l.other); const word = EDGE_WORD[l.rel]?.[l.dir === "out" ? 0 : 1] ?? l.rel; return (
              <li key={i} className="flex flex-wrap gap-2"><span className="text-zinc-500">{word}</span>{to ? <Link className="break-all font-mono text-xs hover:underline" to={to}>{l.other}</Link> : <span className="break-all font-mono text-xs">{l.other}</span>}{l.props?.last_backup_at ? <span className="text-xs text-zinc-500">last {day(l.props.last_backup_at)}</span> : null}</li>
            ); })}
          </ul>
        )}
      </div>
      {tags.length > 0 && <div className="break-inside-avoid"><div className="mb-1 text-xs uppercase tracking-wide text-zinc-500">Tags</div><table className="w-full text-xs"><tbody>{tags.sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => <tr key={k} className="border-t border-zinc-800/60"><td className="py-0.5 pr-2 text-zinc-500">{k}</td><td className="break-all py-0.5">{String(v)}</td></tr>)}</tbody></table></div>}
    </div>
  );
}

const SEV_TONE: Record<string, string> = { critical: "text-red-300", high: "text-red-300", medium: "text-amber-300", low: "text-zinc-400" };

/** GuardDuty's findings under the detectors: the open ones, most severe first, each linked to the resource it is about. */
function Findings({ q, gone }: { q: string; gone: boolean }) {
  const [rows, setRows] = useState<any[] | null>(null);
  const [archived, setArchived] = useState(false);
  useEffect(() => { setRows(null); const qs = new URLSearchParams(); if (q) qs.set("q", q); if (gone) qs.set("gone", "1"); if (archived) qs.set("archived", "1"); api(`/inventory/threat-findings?${qs}`).then(setRows).catch(() => setRows([])); }, [q, gone, archived]);
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between"><h2 className="text-sm font-medium text-zinc-300">Findings</h2><label className="flex items-center gap-1 text-xs text-zinc-400"><input type="checkbox" checked={archived} onChange={(e) => setArchived(e.target.checked)} /> archived too</label></div>
      {!rows ? <Empty>Loading…</Empty> : !rows.length ? <Empty>No open finding.</Empty> : (
        <div className="overflow-x-auto rounded-lg border border-zinc-800">
          <table className="w-full text-sm">
            <thead className="bg-zinc-900"><tr><Th>Severity</Th><Th>Finding</Th><Th>About</Th><Th className="text-right">Seen</Th><Th>Last seen</Th><Th>Region</Th></tr></thead>
            <tbody>{rows.map((f) => { const to = f.resource_id ? linkTo(String(f.resource_id)) : null; return (
              <tr key={f.id} className={`border-t border-zinc-800 align-top ${f.archived || f.gone ? "text-zinc-500" : ""}`}>
                <Td className={SEV_TONE[f.severity_label] ?? ""}>{f.severity_label}<span className="text-xs text-zinc-500"> {f.severity}</span></Td>
                <Td><div className="text-zinc-100">{f.title}</div><div className="font-mono text-[11px] text-zinc-500">{f.type}</div></Td>
                <Td>{f.resource_id ? <><span className="text-xs text-zinc-500">{f.resource_type} </span>{to ? <Link className="font-mono text-xs hover:underline" to={to}>{f.resource_name || f.resource_id}</Link> : <span className="font-mono text-xs">{f.resource_name || f.resource_id}</span>}</> : <span className="text-zinc-600">{f.resource_type || "—"}</span>}</Td>
                <Td className="text-right">{n(f.count)}</Td>
                <Td className="whitespace-nowrap">{when(f.last_seen_at)}</Td>
                <Td className="text-zinc-400">{f.region}</Td>
              </tr>
            ); })}</tbody>
          </table>
        </div>
      )}
    </div>
  );
}

const EMPTY: Record<ServiceTab, string> = {
  certificates: "No certificate in ACM.", messaging: "No SNS topic.", keys: "No KMS key.", files: "No EFS file system.", backups: "No backup vault or plan.", analytics: "No Athena workgroup.",
  stacks: "No CloudFormation stack.", threats: "GuardDuty is not enabled in any region the advisor reads.", waf: "No WAF web ACL.",
};

/** One platform-service tab: the header numbers, the rows with the kind's columns, a row opening its properties and edges. */
export function ServicesPanel({ tab, summary, selected, onSelect, q, gone }: { tab: ServiceTab; summary: any; selected: string | null; onSelect: (id: string | null) => void; q: string; gone: boolean }) {
  const [rows, setRows] = useState<any[] | null>(null);
  const [err, setErr] = useState("");
  useEffect(() => {
    setRows(null); setErr("");
    const qs = new URLSearchParams(); if (q) qs.set("q", q); if (gone) qs.set("gone", "1");
    api(`/inventory/services/${tab}?${qs}`).then(setRows).catch((e) => { setErr(e.message); setRows([]); });
  }, [tab, q, gone, summary?.total]);
  const cols = COLUMNS[tab];
  return (
    <div className="space-y-4">
      {tab === "waf" && <h2 className="pt-2 text-sm font-medium text-zinc-300">Web ACLs <span className="text-xs font-normal text-zinc-500">WAF</span></h2>}
      <Stats tab={tab} s={summary} />
      {err && <div className="text-sm text-red-300">{err}</div>}
      {!rows ? <Empty>Loading…</Empty> : !rows.length ? <Empty>{EMPTY[tab]} If you expected some, Settings › Permissions says whether the read policy lets the advisor list them.</Empty> : (
        <div className="overflow-x-auto rounded-lg border border-zinc-800">
          <table className="w-full text-sm">
            <thead className="bg-zinc-900"><tr><Th>Name</Th>{cols.map((c) => <Th key={c.h} className={c.right ? "text-right" : ""}>{c.h}</Th>)}<Th>Region</Th></tr></thead>
            <tbody>
              {rows.map((r) => (
                <Fragment key={r.id}>
                  <tr onClick={() => onSelect(selected === r.id ? null : r.id)} className={`cursor-pointer border-t border-zinc-800 align-top hover:bg-zinc-900/60 ${selected === r.id ? "bg-zinc-900" : ""} ${r.gone ? "text-zinc-500" : ""}`}>
                    <Td><div className="text-zinc-100">{r.name || r.id.split(/[:/]/).pop()}</div>{r.gone ? <div className="text-[11px] text-zinc-500">gone</div> : null}</Td>
                    {cols.map((c) => <Td key={c.h} className={c.right ? "text-right" : ""}>{c.cell(r)}</Td>)}
                    <Td className="text-zinc-400">{r.region || "—"}</Td>
                  </tr>
                  {selected === r.id && <tr className="border-t border-zinc-800 bg-zinc-950/40"><td colSpan={cols.length + 2} className="max-w-0 p-3"><DetailCell id={r.id} onClose={() => onSelect(null)}><Detail r={r} /></DetailCell></td></tr>}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {tab === "threats" && <Findings q={q} gone={gone} />}
    </div>
  );
}

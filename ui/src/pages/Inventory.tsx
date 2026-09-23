import { Fragment, useEffect, useRef, useState, type ReactNode } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, usd, when } from "../api";
import { Badge, Button, Card, CopyButton, DetailCell, Empty, Stat, Td, Th } from "../components/ui";
import { RoleLine } from "../components/jev";
import { InstanceCharts } from "../components/instanceCharts";
import { RdsLoadPanel } from "../components/rdsLoad";
import { metricLabel } from "./Knowledge";

const TABS = ["ec2", "rds", "elasticache", "lambda", "ebs", "s3", "route53"] as const;
type Tab = (typeof TABS)[number];
const TAB_LABEL: Record<Tab, string> = { ec2: "EC2", rds: "RDS", elasticache: "ElastiCache", lambda: "Lambda", ebs: "EBS", s3: "S3", route53: "Route 53" };
const ID_COLUMN: Record<Tab, string> = { ec2: "instance_id", rds: "db_instance_identifier", elasticache: "cache_cluster_id", lambda: "name", ebs: "volume_id", s3: "name", route53: "id" };

const pct = (v: number | null | undefined) => (v == null ? "—" : `${Math.round(Number(v))}%`);
const gb = (v: number | null | undefined) => (v == null ? "—" : `${Number(v).toLocaleString()} GB`);
const day = (iso: string | null | undefined) => (iso ? new Date(iso).toLocaleDateString() : "—");
const yesNo = (v: unknown) => (v == null ? null : v ? "yes" : "no");

/** Rows of a definition list; entries whose value is null/undefined/"" are skipped. */
const Dl = ({ rows }: { rows: [string, ReactNode][] }) => (
  <dl className="grid grid-cols-[9.5rem_1fr] gap-x-3 gap-y-0.5 text-sm">
    {rows.filter(([, v]) => v != null && v !== "").map(([k, v]) => <Fragment key={k}><dt className="text-zinc-500">{k}</dt><dd className="min-w-0 break-words">{v}</dd></Fragment>)}
  </dl>
);

const Group = ({ title, children, action }: { title: string; children: ReactNode; action?: ReactNode }) => (
  <div className="mt-4 break-inside-avoid">
    <div className="mb-1 flex items-center justify-between text-xs uppercase tracking-wide text-zinc-500"><span>{title}</span>{action}</div>
    {children}
  </div>
);

const Mono = ({ children }: { children: ReactNode }) => <span className="font-mono text-xs">{children}</span>;

const SsmBadge = ({ status, platform }: { status: string | null; platform?: string | null }) => (
  <span className="inline-flex flex-wrap items-center gap-1"><Badge>{status || "unmanaged"}</Badge>{status && platform && <span className="text-xs text-zinc-500">{platform}</span>}</span>
);

const POOL_LABEL: Record<string, string> = { batch: "Batch", karpenter: "Karpenter", eks: "EKS", asg: "ASG" };
/** A member of a pool its controller scales: the advisor reasons about the pool, not the instance. */
const PoolBadge = ({ kind, name }: { kind: string; name?: string | null }) => (
  <span title={name ? `${POOL_LABEL[kind] || kind} pool ${name}` : undefined} className="inline-block rounded border border-sky-500/30 bg-sky-500/10 px-1.5 py-0.5 text-[11px] font-medium text-sky-300">{POOL_LABEL[kind] || kind}</span>
);

const Tags = ({ tags }: { tags: Record<string, string> | null | undefined }) => {
  const entries = Object.entries(tags || {});
  if (!entries.length) return <div className="text-sm text-zinc-500">No tags.</div>;
  return (
    <table className="w-full text-xs">
      <tbody>{entries.sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => <tr key={k} className="border-t border-zinc-800/60"><td className="py-0.5 pr-2 text-zinc-500">{k}</td><td className="break-all py-0.5">{String(v)}</td></tr>)}</tbody>
    </table>
  );
};

/** Where a Route 53 link lands in the inventory: the tab and id, or nothing for kinds the inventory does not hold (load balancers, distributions, NAT gateways). */
const LINK_TAB: Record<string, Tab> = { ec2: "ec2", rds: "rds", elasticache: "elasticache", s3: "s3", lambda: "lambda" };
const LINK_KIND: Record<string, string> = { ec2: "instance", rds: "RDS", rds_cluster: "RDS cluster", elasticache: "ElastiCache", elasticache_group: "ElastiCache group", s3: "S3 bucket", lambda: "Lambda", alb: "ALB", nlb: "NLB", clb: "classic LB", lb: "load balancer", cloudfront: "CloudFront", nat: "NAT gateway", eip: "Elastic IP", eni: "interface", apigw: "API Gateway", beanstalk: "Beanstalk" };
const ResourceLink = ({ l }: { l: { kind: string; id: string; name?: string | null; state?: string | null } }) => {
  const tab = LINK_TAB[l.kind]; const label = l.name && l.name !== l.id ? `${l.name} (${l.id})` : l.id;
  const stateNote = l.state && !["running", "available", "active", "Deployed", "in-use"].includes(l.state) ? <span className="ml-1 text-amber-300">{l.state}</span> : null;
  return <span className="inline-flex items-center gap-1 text-sm"><span className="text-xs text-zinc-500">{LINK_KIND[l.kind] || l.kind}</span>{tab ? <Link className="hover:underline" to={`/inventory?tab=${tab}&id=${encodeURIComponent(l.id)}`}>{label}</Link> : <span>{label}</span>}{stateNote}</span>;
};

/** The Route 53 records that reach one resource, directly (hop 1) or through a load balancer or distribution (hop 2+). */
const Domains = ({ list, empty = "No Route 53 record in this account points here." }: { list: any[] | null | undefined; empty?: string }) => (
  <Group title="Domains">
    {!list?.length ? <div className="text-sm text-zinc-500">{empty}</div> : (
      <ul className="space-y-0.5 text-sm">
        {list.map((d: any, i: number) => <li key={`${d.name}-${d.type}-${i}`} className="flex flex-wrap items-center gap-2"><Link className="font-mono text-xs hover:underline" to={`/inventory?tab=route53&zone=${encodeURIComponent(d.zone_id || d.zone_name)}&id=${encodeURIComponent(d.id)}`}>{d.name}</Link><span className="text-xs text-zinc-500">{d.type}{d.alias ? " alias" : ""}</span>{d.hop > 1 ? <span className="text-xs text-zinc-500">via {d.summary?.split(" → ")[0] || "a load balancer"}</span> : null}</li>)}
      </ul>
    )}
  </Group>
);

/** Links to the Findings and Recommendations pages filtered on one resource, with the counts the inventory stored. */
const Related = ({ id, recs, findings, list }: { id: string; recs: number; findings: number; list?: any[] }) => (
  <Group title="Findings and recommendations">
    <div className="flex flex-wrap gap-3 text-sm">
      <Link className="underline" to={`/findings?q=${encodeURIComponent(id)}`}>{findings} finding{findings === 1 ? "" : "s"} in the last run</Link>
      <Link className="underline" to={`/recommendations?status=all&q=${encodeURIComponent(id)}`}>{recs} open recommendation{recs === 1 ? "" : "s"}</Link>
    </div>
    {list && list.length > 0 && (
      <ul className="mt-1 space-y-0.5 text-sm">
        {list.map((r: any) => <li key={r.id} className="flex items-center justify-between gap-2"><Link className="truncate hover:underline" to={`/recommendations?status=${r.status}&id=${r.id}`}>{r.title}</Link><span className="flex shrink-0 items-center gap-1"><Badge>{r.status}</Badge><span className="w-16 text-right text-zinc-300">{usd(r.est_monthly_saving)}</span></span></li>)}
      </ul>
    )}
  </Group>
);

export default function Inventory() {
  const [params, setParams] = useSearchParams();
  const tab = (TABS.includes(params.get("tab") as Tab) ? params.get("tab") : "ec2") as Tab;
  const selectedId = params.get("id");
  const state = params.get("state") || "";
  const ssm = params.get("ssm") || "";
  const sort = params.get("sort") || "";
  const gone = params.get("gone") === "1";
  const zone = params.get("zone") || "";
  const link = params.get("link") || "";
  const [q, setQ] = useState(params.get("q") || "");
  const [zones, setZones] = useState<any[]>([]);
  const [summary, setSummary] = useState<any>(null);
  const [rows, setRows] = useState<any[] | null>(null);
  const [detail, setDetail] = useState<any>(null);
  const [err, setErr] = useState("");
  const [refreshing, setRefreshing] = useState(false);
  const [probe, setProbe] = useState<{ busy: boolean; error: string }>({ busy: false, error: "" });

  const set = (patch: Record<string, string | null>) => {
    const p = new URLSearchParams(params);
    for (const [k, v] of Object.entries(patch)) v ? p.set(k, v) : p.delete(k);
    setParams(p);
  };
  // A row opens its detail under itself; clicking the open row again closes it.
  const pick = (id: string) => set({ id: selectedId === id ? null : id });

  const loadSummary = () => api("/inventory/summary").then(setSummary).catch((e) => setErr(e.message));
  // A tab switch clears the table at once and ignores a slower response from the previous tab, so EC2 rows can
  // never sit under the Lambda header (or stick when a request fails).
  const rowsRequest = useRef(0);
  // The table's last height: while the next tab loads, the placeholder keeps it, so the page does not get shorter
  // than the scroll position and jump up.
  const tableRef = useRef<HTMLDivElement>(null);
  const tableHeight = useRef(0);
  const loadRows = () => {
    const seq = ++rowsRequest.current;
    if (tableRef.current) tableHeight.current = tableRef.current.offsetHeight;
    setRows(null);
    const qs = new URLSearchParams();
    if (tab === "ec2") { if (state) qs.set("state", state); if (ssm) qs.set("ssm", ssm); }
    if (tab === "route53") { if (zone) qs.set("zone", zone); if (link) qs.set("link", link); }
    if (params.get("q")) qs.set("q", params.get("q")!);
    if (sort) qs.set("sort", sort);
    if (gone) qs.set("gone", "1");
    return api(`/inventory/${tab}?${qs}`).then((r) => { if (seq === rowsRequest.current) setRows(r); }).catch((e) => { if (seq === rowsRequest.current) { setErr(e.message); setRows([]); } });
  };
  const loadDetail = () => {
    if (!selectedId) { setDetail(null); return Promise.resolve(); }
    if (tab === "ec2") return api(`/inventory/ec2/${selectedId}`).then(setDetail).catch(() => setDetail(null));
    setDetail((rows || []).find((r) => r[ID_COLUMN[tab]] === selectedId) || null);
    return Promise.resolve();
  };

  useEffect(() => { loadSummary(); }, []);
  useEffect(() => { if (tab === "route53") api("/inventory/route53/zones").then(setZones).catch(() => setZones([])); }, [tab, summary?.refreshed_at]);
  useEffect(() => { loadRows(); }, [tab, state, ssm, sort, gone, zone, link, params.get("q")]);
  useEffect(() => { loadDetail(); setProbe({ busy: false, error: "" }); }, [tab, selectedId, rows]);

  const refresh = async () => {
    setRefreshing(true); setErr("");
    try {
      const r = await api("/inventory/refresh", { method: "POST" });
      if (r.errors?.length) setErr(`Refresh finished with errors: ${r.errors.join("; ")}`);
      await Promise.all([loadSummary(), loadRows()]);
    } catch (e: any) { setErr(e.message); }
    finally { setRefreshing(false); }
  };

  const runProbe = async (id: string) => {
    setProbe({ busy: true, error: "" });
    try { await api(`/instances/${id}/probe`, { method: "POST" }); await refresh(); }
    catch (e: any) { setProbe({ busy: false, error: e.message }); return; }
    setProbe({ busy: false, error: "" });
  };

  const toggleSort = (col: string) => set({ sort: sort === col ? `-${col}` : sort === `-${col}` ? null : col });
  const SortTh = ({ col, children, className = "" }: { col: string; children: ReactNode; className?: string }) => (
    <Th className={className}><button className="uppercase hover:text-zinc-300" onClick={() => toggleSort(col)}>{children}{sort === col ? " ↑" : sort === `-${col}` ? " ↓" : ""}</button></Th>
  );

  const s = summary;
  const inv = s?.[tab];

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h1 className="text-xl font-semibold text-zinc-100">Inventory</h1>
          <div className="text-sm text-zinc-500">{s?.refreshed_at ? <>Snapshot from {when(s.refreshed_at)} · {tab === "route53" ? "DNS links refreshed after every run and by Refresh now (not by the watcher)" : "refreshed after every run and every watcher sample"}</> : "No snapshot yet: start a run, or refresh now."}</div>
        </div>
        <Button variant="ghost" onClick={refresh} disabled={refreshing}>{refreshing ? "Refreshing…" : "Refresh now"}</Button>
      </div>
      {err && <div className="text-sm text-red-300">{err}</div>}

      <div className="flex gap-1 border-b border-zinc-800">
        {TABS.map((t) => (
          <button key={t} onClick={() => set({ tab: t, id: null, sort: null })} className={`-mb-px border-b-2 px-3 py-1.5 text-sm ${tab === t ? "border-zinc-100 text-zinc-100" : "border-transparent text-zinc-400 hover:text-zinc-200"}`}>
            {TAB_LABEL[t]}{s && <span className="ml-1 text-xs text-zinc-500">{s[t].total}</span>}
          </button>
        ))}
      </div>

      {tab === "ec2" && inv && (
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-6">
          <Stat label="Running" value={inv.running} hint={`${inv.total} instances seen`} />
          <Stat label="Stopped" value={inv.stopped} hint={inv.gone ? `${inv.gone} gone` : undefined} />
          <Stat label="SSM online" value={inv.ssm_online} hint={`of ${inv.running} running${inv.ssm_lost ? ` · ${inv.ssm_lost} connection lost` : ""}`} />
          <Stat label="SSM not managed" value={inv.ssm_unmanaged} hint="running, no SSM registration" />
          <Stat label="On-demand / month" value={usd(inv.monthly_usd_running)} hint={`list price of running${inv.running_unpriced ? ` · ${inv.running_unpriced} unpriced` : ""}`} />
          <Stat label="EBS attached" value={gb(inv.ebs_gb)} hint="all instances" />
        </div>
      )}
      {tab === "rds" && inv && (
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          <Stat label="Instances" value={inv.total} hint={`${inv.available} available${inv.gone ? ` · ${inv.gone} gone` : ""}`} />
          <Stat label="On-demand / month" value={usd(inv.monthly_usd)} hint={inv.unpriced ? `${inv.unpriced} unpriced (serverless or unknown engine)` : "instance hours only, no storage or I/O"} />
          <Stat label="Allocated storage" value={gb(inv.storage_gb)} />
          <Stat label="Open recs · findings" value={`${inv.open_recs} · ${inv.findings}`} />
        </div>
      )}
      {tab === "elasticache" && inv && (
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          <Stat label="Clusters" value={inv.total} hint={`${inv.nodes} nodes${inv.gone ? ` · ${inv.gone} gone` : ""}`} />
          <Stat label="On-demand / month" value={usd(inv.monthly_usd)} hint={inv.unpriced ? `${inv.unpriced} unpriced` : "node price × nodes"} />
          <Stat label="Open recs · findings" value={`${inv.open_recs} · ${inv.findings}`} />
        </div>
      )}

      {tab === "ebs" && inv && (
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          <Stat label="Volumes" value={inv.total} hint={`${Number(inv.gb).toLocaleString()} GB${inv.gone ? ` · ${inv.gone} gone` : ""}`} />
          <Stat label="At list / month" value={usd(inv.monthly_usd)} hint="storage plus provisioned IOPS and throughput" />
          <Stat label="Unattached" value={inv.unattached} hint={inv.unattached ? `${usd(inv.unattached_usd)}/month for nothing` : "none"} />
          <Stat label="Still gp2" value={inv.gp2} hint={inv.gp2 ? "gp3 is 20 % cheaper for the same size" : "all gp3 or better"} />
        </div>
      )}
      {tab === "s3" && inv && (
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          <Stat label="Buckets" value={inv.total} hint={`${Number(inv.gb).toLocaleString(undefined, { maximumFractionDigits: 0 })} GB${inv.gone ? ` · ${inv.gone} gone` : ""}`} />
          <Stat label="At list / month" value={usd(inv.monthly_usd)} hint={`${Number(inv.standard_gb).toLocaleString(undefined, { maximumFractionDigits: 0 })} GB in Standard`} />
          <Stat label="Big, no lifecycle" value={inv.big_no_lifecycle} hint="over 5 GB with no lifecycle rule" />
          <Stat label="Public" value={inv.public_unknown && !inv.public ? "?" : inv.public} hint={inv.public ? "bucket policy allows public access" : inv.public_unknown ? "unknown: grant s3:GetBucketPolicyStatus" : "none"} />
        </div>
      )}
      {tab === "route53" && inv && (
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
          <Stat label="Hosted zones" value={inv.zones} hint={`${inv.private_zones ? `${inv.private_zones} private · ` : ""}${inv.total} records${inv.gone ? ` · ${inv.gone} gone` : ""}`} />
          <Stat label="Linked" value={inv.linked} hint="lead to a resource in this account" />
          <Stat label="Unmatched" value={inv.unmatched} hint={inv.unmatched ? "AWS-hosted names this account does not have: deleted (dangling) or another account's" : "no dangling records"} />
          <Stat label="Outside AWS" value={inv.external} hint={`${inv.none} name nothing (NS, SOA, TXT, MX…)`} />
          <Stat label="At list / month" value={usd(inv.monthly_usd, 2)} hint={`0.50 per zone${inv.queries_30d ? ` · ${(Number(inv.queries_30d) / 1e6).toFixed(2)}M queries in 30 days` : ""}${inv.empty_zones ? ` · ${inv.empty_zones} zone${inv.empty_zones === 1 ? "" : "s"} with no records` : ""}`} />
        </div>
      )}
      {tab === "lambda" && inv && (
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          <Stat label="Functions" value={inv.total} hint={`${inv.active} invoked in 30 days${inv.gone ? ` · ${inv.gone} gone` : ""} · ${inv.arm} on arm64`} />
          <Stat label="At list / month" value={usd(inv.monthly_usd)} hint="GB-seconds and requests from 30 days of metrics, before the Savings Plan and the free tier" />
          <Stat label="Invocations / month" value={Number(inv.invocations_month).toLocaleString()} hint={`${(Number(inv.gb_seconds_month) / 1e6).toFixed(2)}M GB-seconds`} />
          <Stat label="Open recs · findings" value={`${inv.open_recs} · ${inv.findings}`} />
        </div>
      )}

      <div className="flex flex-wrap items-center gap-2">
        {tab === "ec2" && (
          <>
            <select value={state} onChange={(e) => set({ state: e.target.value })}>
              <option value="">All states</option><option value="running">running</option><option value="stopped">stopped</option><option value="terminated">terminated</option><option value="pending">pending</option><option value="stopping">stopping</option>
            </select>
            <select value={ssm} onChange={(e) => set({ ssm: e.target.value })}>
              <option value="">Any SSM status</option><option value="online">SSM online</option><option value="lost">SSM connection lost</option><option value="unmanaged">not managed by SSM</option><option value="managed">managed (any status)</option>
            </select>
          </>
        )}
        {tab === "route53" && (
          <>
            <select value={zone} onChange={(e) => set({ zone: e.target.value, id: null })}>
              <option value="">All zones</option>{zones.map((z: any) => <option key={z.zone_id} value={z.zone_id}>{z.name}{z.private ? " (private)" : ""} · {z.records}</option>)}
            </select>
            <select value={link} onChange={(e) => set({ link: e.target.value, id: null })}>
              <option value="">Any target</option><option value="linked">linked to a resource here</option><option value="unmatched">unmatched (dangling?)</option><option value="external">outside AWS</option><option value="none">names nothing</option>
            </select>
          </>
        )}
        <form onSubmit={(e) => { e.preventDefault(); set({ q }); }}><input placeholder={tab === "ec2" ? "search name, id, type or IP" : tab === "route53" ? "search name, target or resource" : "search"} value={q} onChange={(e) => setQ(e.target.value)} className="w-64" /></form>
        <label className="flex items-center gap-1 text-sm text-zinc-400"><input type="checkbox" checked={gone} onChange={(e) => set({ gone: e.target.checked ? "1" : null })} /> include gone</label>
        {rows && <span className="text-sm text-zinc-500">{rows.length} rows</span>}
      </div>

      <div ref={tableRef} style={!rows ? { minHeight: tableHeight.current } : undefined}>
        {!rows ? <Empty>Loading…</Empty> : rows.length === 0 ? <Empty>{s?.refreshed_at ? "Nothing matches." : "No snapshot yet."}</Empty> : (
          <div className="min-w-0 overflow-x-auto self-start">
            <table className="w-full border-collapse overflow-hidden rounded-lg border border-zinc-800">
              {tab === "ec2" && (
                <thead className="bg-zinc-900"><tr>
                  <SortTh col="name">Name</SortTh><SortTh col="instance_type">Type</SortTh><SortTh col="state">State</SortTh><SortTh col="ssm_status">SSM</SortTh>
                  <SortTh col="cpu_30d" className="text-right">CPU 30d</SortTh><SortTh col="probe_mem_pct" className="text-right">Mem</SortTh><SortTh col="ebs_gb" className="text-right">EBS</SortTh>
                  <SortTh col="monthly_usd" className="text-right">$ / mo</SortTh><SortTh col="launch_time">Launched</SortTh><SortTh col="open_recs" className="text-right">Recs</SortTh><SortTh col="findings" className="text-right">Findings</SortTh>
                </tr></thead>
              )}
              {tab === "rds" && (
                <thead className="bg-zinc-900"><tr>
                  <SortTh col="db_instance_identifier">Identifier</SortTh><SortTh col="class">Class</SortTh><SortTh col="engine">Engine</SortTh><SortTh col="status">Status</SortTh>
                  <SortTh col="storage_gb" className="text-right">Storage</SortTh><SortTh col="cpu_30d" className="text-right">CPU 30d</SortTh><SortTh col="monthly_usd" className="text-right">$ / mo</SortTh>
                  <SortTh col="created">Created</SortTh><SortTh col="open_recs" className="text-right">Recs</SortTh><SortTh col="findings" className="text-right">Findings</SortTh>
                </tr></thead>
              )}
              {tab === "ebs" && (
                <thead className="bg-zinc-900"><tr>
                  <SortTh col="volume_id">Volume</SortTh><SortTh col="volume_type">Type</SortTh><SortTh col="size_gb" className="text-right">Size</SortTh><SortTh col="iops" className="text-right">IOPS prov.</SortTh>
                  <SortTh col="iops_max" className="text-right">IOPS peak 30d</SortTh><SortTh col="state">State</SortTh><SortTh col="instance_id">Attached to</SortTh><SortTh col="monthly_usd" className="text-right">$ / mo</SortTh><SortTh col="created">Created</SortTh>
                </tr></thead>
              )}
              {tab === "s3" && (
                <thead className="bg-zinc-900"><tr>
                  <SortTh col="name">Bucket</SortTh><SortTh col="region">Region</SortTh><SortTh col="total_gb" className="text-right">Size</SortTh><SortTh col="standard_gb" className="text-right">In Standard</SortTh>
                  <SortTh col="objects" className="text-right">Objects</SortTh><SortTh col="lifecycle_rules" className="text-right">Lifecycle</SortTh><SortTh col="monthly_usd" className="text-right">$ / mo</SortTh><SortTh col="created">Created</SortTh>
                </tr></thead>
              )}
              {tab === "route53" && (
                <thead className="bg-zinc-900"><tr>
                  <SortTh col="name">Record</SortTh><SortTh col="type">Type</SortTh><SortTh col="target">Value</SortTh><SortTh col="link_state">Leads to</SortTh><SortTh col="zone_name">Zone</SortTh><SortTh col="ttl" className="text-right">TTL</SortTh>
                </tr></thead>
              )}
              {tab === "lambda" && (
                <thead className="bg-zinc-900"><tr>
                  <SortTh col="name">Function</SortTh><SortTh col="runtime">Runtime</SortTh><SortTh col="memory_mb" className="text-right">Memory</SortTh><SortTh col="invocations_month" className="text-right">Invocations / mo</SortTh>
                  <SortTh col="avg_duration_ms" className="text-right">Avg ms</SortTh><SortTh col="gb_seconds_month" className="text-right">GB-s / mo</SortTh><SortTh col="errors_30d" className="text-right">Errors 30d</SortTh><SortTh col="monthly_usd" className="text-right">$ / mo</SortTh><SortTh col="open_recs" className="text-right">Recs</SortTh><SortTh col="findings" className="text-right">Findings</SortTh>
                </tr></thead>
              )}
              {tab === "elasticache" && (
                <thead className="bg-zinc-900"><tr>
                  <SortTh col="cache_cluster_id">Cluster</SortTh><SortTh col="node_type">Node type</SortTh><SortTh col="engine">Engine</SortTh><SortTh col="num_nodes" className="text-right">Nodes</SortTh><SortTh col="status">Status</SortTh>
                  <SortTh col="monthly_usd" className="text-right">$ / mo</SortTh><SortTh col="created">Created</SortTh><SortTh col="open_recs" className="text-right">Recs</SortTh><SortTh col="findings" className="text-right">Findings</SortTh>
                </tr></thead>
              )}
              <tbody>
                {rows.map((r) => {
                  const id = r[ID_COLUMN[tab]] as string;
                  const cls = `cursor-pointer border-t border-zinc-800 hover:bg-zinc-900/60 ${selectedId === id ? "bg-zinc-900" : ""} ${r.gone ? "text-zinc-500" : ""}`;
                  // The detail expands full width right under the selected row (same pattern as alerts and playbooks).
                  const detailRow = selectedId === id ? (
                    <tr className="border-t border-zinc-800 bg-zinc-950/40"><td colSpan={COLUMNS[tab]} className="max-w-0 p-3"><DetailCell onClose={() => set({ id: null })} id={id}><div className="lg:columns-2 lg:gap-8">
                      {!detail ? <div className="text-sm text-zinc-500">{rows ? "Not in the snapshot." : "Loading…"}</div>
                        : tab === "ec2" ? <Ec2Detail d={detail} probe={probe} onProbe={() => runProbe(detail.instance_id)} />
                        : tab === "rds" ? <RdsDetail d={detail} />
                        : tab === "lambda" ? <LambdaDetail d={detail} />
                        : tab === "ebs" ? <EbsDetail d={detail} />
                        : tab === "s3" ? <S3Detail d={detail} />
                        : tab === "route53" ? <Route53Detail d={detail} />
                        : <CacheDetail d={detail} />}
                    </div></DetailCell></td></tr>
                  ) : null;
                  if (tab === "ec2") return (<Fragment key={id}>
                    <tr key={id} onClick={() => pick(id)} className={cls}>
                      <Td><div className="flex items-center gap-2"><span className="font-medium text-zinc-100">{r.name || <span className="text-zinc-500">(no name)</span>}</span>{r.pool_kind ? <PoolBadge kind={r.pool_kind} name={r.pool} /> : null}{r.gone ? <Badge>gone</Badge> : null}</div><div className="font-mono text-xs text-zinc-500">{id}{r.private_ip ? ` · ${r.private_ip}` : ""}</div></Td>
                      <Td className="whitespace-nowrap">{r.instance_type}</Td>
                      <Td><Badge>{r.state}</Badge></Td>
                      <Td><SsmBadge status={r.ssm_status} platform={r.ssm_platform} /></Td>
                      <Td className="text-right">{r.cpu_days ? <span title={`${r.cpu_days} days of data`}>{pct(r.cpu_30d)}</span> : "—"}</Td>
                      <Td className="text-right">{r.probe_mem_pct != null ? <span title={`probed ${when(r.probe_at)}`}>{pct(r.probe_mem_pct)}</span> : r.state === "running" && r.ssm_status === "Online" ? <button className="text-xs text-sky-300 hover:underline" onClick={(e) => { e.stopPropagation(); set({ id }); runProbe(id); }}>probe</button> : "—"}</Td>
                      <Td className="text-right whitespace-nowrap">{r.ebs_gb ? gb(r.ebs_gb) : "—"}</Td>
                      <Td className="text-right font-medium text-zinc-100">{usd(r.monthly_usd)}</Td>
                      <Td className="whitespace-nowrap text-zinc-400">{day(r.launch_time)}</Td>
                      <Td className="text-right">{r.open_recs || "—"}</Td>
                      <Td className="text-right">{r.findings || "—"}</Td>
                    </tr>{detailRow}
                  </Fragment>);
                  if (tab === "rds") return (<Fragment key={id}>
                    <tr onClick={() => pick(id)} className={cls}>
                      <Td><div className="flex items-center gap-2"><span className="font-medium text-zinc-100">{id}</span>{r.gone ? <Badge>gone</Badge> : null}</div>{r.cluster && <div className="text-xs text-zinc-500">cluster {r.cluster}</div>}</Td>
                      <Td className="whitespace-nowrap">{r.class}{r.multi_az ? <span className="text-xs text-zinc-500"> multi-AZ</span> : null}</Td>
                      <Td>{r.engine} <span className="text-xs text-zinc-500">{r.engine_version}</span></Td>
                      <Td><Badge>{r.status}</Badge></Td>
                      <Td className="text-right whitespace-nowrap">{gb(r.storage_gb)} <span className="text-xs text-zinc-500">{r.storage_type}</span></Td>
                      <Td className="text-right">{r.cpu_days ? pct(r.cpu_30d) : "—"}</Td>
                      <Td className="text-right font-medium text-zinc-100">{usd(r.monthly_usd)}</Td>
                      <Td className="whitespace-nowrap text-zinc-400">{day(r.created)}</Td>
                      <Td className="text-right">{r.open_recs || "—"}</Td>
                      <Td className="text-right">{r.findings || "—"}</Td>
                    </tr>{detailRow}
                  </Fragment>);
                  if (tab === "ebs") return (<Fragment key={id}>
                    <tr onClick={() => pick(id)} className={cls}>
                      <Td><div className="flex items-center gap-2"><span className="font-mono text-xs text-zinc-100">{id}</span>{r.gone ? <Badge>gone</Badge> : null}</div>{r.name && <div className="text-xs text-zinc-500">{r.name}</div>}</Td>
                      <Td>{r.volume_type}{r.encrypted ? " 🔒" : ""}</Td>
                      <Td className="text-right">{r.size_gb} GB</Td>
                      <Td className="text-right">{r.provisioned_iops != null ? Number(r.provisioned_iops).toLocaleString() : "—"}</Td>
                      <Td className={`text-right ${r.iops_max != null && r.provisioned_iops && r.iops_max < 0.3 * r.provisioned_iops && r.iops > 3000 ? "text-amber-300" : ""}`}>{r.iops_max != null ? Number(r.iops_max).toLocaleString() : <span className="text-zinc-600">—</span>}</Td>
                      <Td><Badge>{r.state}</Badge></Td>
                      <Td className="text-xs">{r.instance_id ? <Link className="hover:underline" to={`/inventory?tab=ec2&id=${r.instance_id}`}>{r.instance_name || r.instance_id}<span className="text-zinc-500"> {r.device}</span></Link> : <span className="text-amber-300">unattached</span>}</Td>
                      <Td className="text-right font-medium text-zinc-100">{usd(r.monthly_usd, 2)}</Td>
                      <Td className="whitespace-nowrap text-zinc-400">{day(r.created)}</Td>
                    </tr>{detailRow}
                  </Fragment>);
                  if (tab === "s3") return (<Fragment key={id}>
                    <tr onClick={() => pick(id)} className={cls}>
                      <Td><div className="flex items-center gap-2"><span className="font-medium text-zinc-100">{id}</span>{r.public ? <Badge>public</Badge> : null}{r.versioning ? <Badge>versioned</Badge> : null}{r.gone ? <Badge>gone</Badge> : null}</div></Td>
                      <Td className="text-zinc-400">{r.region}</Td>
                      <Td className="text-right">{r.total_gb >= 1 ? `${Number(r.total_gb).toLocaleString(undefined, { maximumFractionDigits: 1 })} GB` : r.total_gb > 0 ? `${Math.round(r.total_gb * 1000)} MB` : <span className="text-zinc-600">empty</span>}</Td>
                      <Td className="text-right">{r.standard_gb >= 1 ? `${Number(r.standard_gb).toLocaleString(undefined, { maximumFractionDigits: 1 })} GB` : "—"}</Td>
                      <Td className="text-right">{r.objects != null ? Number(r.objects).toLocaleString() : "—"}</Td>
                      <Td className={`text-right ${!r.lifecycle_rules && r.total_gb > 5 ? "text-amber-300" : ""}`}>{r.lifecycle_rules ? `${r.lifecycle_rules} rule${r.lifecycle_rules === 1 ? "" : "s"}` : "none"}</Td>
                      <Td className="text-right font-medium text-zinc-100">{r.monthly_usd ? usd(r.monthly_usd, 2) : <span className="text-zinc-600">$0.00</span>}</Td>
                      <Td className="whitespace-nowrap text-zinc-400">{day(r.created)}</Td>
                    </tr>{detailRow}
                  </Fragment>);
                  if (tab === "route53") {
                    const first = (r.links || []).find((l: any) => l.hop === 1) || r.links?.[0];
                    return (<Fragment key={id}>
                      <tr onClick={() => pick(id)} className={cls}>
                        <Td><div className="flex items-center gap-2"><span className="font-mono text-xs text-zinc-100">{r.name}</span>{r.gone ? <Badge>gone</Badge> : null}{r.routing?.set_identifier ? <span className="text-xs text-zinc-500">{r.routing.set_identifier}</span> : null}</div></Td>
                        <Td className="whitespace-nowrap text-xs">{r.type}{r.alias ? <span className="text-zinc-500"> alias</span> : null}</Td>
                        <Td className="max-w-xs"><div className="truncate font-mono text-xs text-zinc-400" title={r.alias ? r.alias_target : (r.values || []).join("\n")}>{r.alias ? r.alias_target : (r.values || []).slice(0, 2).join(", ")}{!r.alias && (r.values || []).length > 2 ? ` +${r.values.length - 2}` : ""}</div></Td>
                        <Td className="max-w-md"><div className="flex items-center gap-2"><Badge>{r.link_state}</Badge><span className={`min-w-0 truncate text-xs ${r.link_state === "unmatched" ? "text-red-300" : r.link_state === "linked" ? "text-zinc-200" : "text-zinc-500"}`} title={r.summary}>{first && LINK_TAB[first.kind] ? <Link className="hover:underline" onClick={(e) => e.stopPropagation()} to={`/inventory?tab=${LINK_TAB[first.kind]}&id=${encodeURIComponent(first.id)}`}>{r.summary}</Link> : r.summary}</span></div></Td>
                        <Td className="whitespace-nowrap text-xs text-zinc-400">{r.zone_name}</Td>
                        <Td className="text-right text-xs text-zinc-400">{r.alias ? "—" : r.ttl}</Td>
                      </tr>{detailRow}
                    </Fragment>);
                  }
                  if (tab === "lambda") return (<Fragment key={id}>
                    <tr onClick={() => pick(id)} className={cls}>
                      <Td><div className="flex items-center gap-2"><span className="font-medium text-zinc-100">{id}</span>{r.arm ? <Badge>arm64</Badge> : null}{r.gone ? <Badge>gone</Badge> : null}</div><div className="font-mono text-xs text-zinc-500">{r.region}</div></Td>
                      <Td className="whitespace-nowrap text-zinc-400">{r.runtime || "—"}</Td>
                      <Td className="text-right">{r.memory_mb} MB</Td>
                      <Td className="text-right">{r.invocations_month ? Number(r.invocations_month).toLocaleString() : <span className="text-zinc-600">0</span>}</Td>
                      <Td className="text-right text-zinc-400">{r.avg_duration_ms != null ? Number(r.avg_duration_ms).toLocaleString() : "—"}</Td>
                      <Td className="text-right">{r.gb_seconds_month ? Number(r.gb_seconds_month).toLocaleString() : "—"}</Td>
                      <Td className={`text-right ${r.errors_30d ? "text-amber-300" : "text-zinc-500"}`}>{r.errors_30d ? Number(r.errors_30d).toLocaleString() : "0"}</Td>
                      <Td className="text-right font-medium text-zinc-100">{r.monthly_usd ? usd(r.monthly_usd, 2) : <span className="text-zinc-600">$0.00</span>}</Td>
                      <Td className="text-right">{r.open_recs || "—"}</Td>
                      <Td className="text-right">{r.findings || "—"}</Td>
                    </tr>{detailRow}
                  </Fragment>);
                  return (<Fragment key={id}>
                    <tr onClick={() => pick(id)} className={cls}>
                      <Td><div className="flex items-center gap-2"><span className="font-medium text-zinc-100">{id}</span>{r.gone ? <Badge>gone</Badge> : null}</div>{r.replication_group && <div className="text-xs text-zinc-500">group {r.replication_group}</div>}</Td>
                      <Td className="whitespace-nowrap">{r.node_type}</Td>
                      <Td>{r.engine} <span className="text-xs text-zinc-500">{r.engine_version}</span></Td>
                      <Td className="text-right">{r.num_nodes}</Td>
                      <Td><Badge>{r.status}</Badge></Td>
                      <Td className="text-right font-medium text-zinc-100">{usd(r.monthly_usd)}</Td>
                      <Td className="whitespace-nowrap text-zinc-400">{day(r.created)}</Td>
                      <Td className="text-right">{r.open_recs || "—"}</Td>
                      <Td className="text-right">{r.findings || "—"}</Td>
                    </tr>{detailRow}
                  </Fragment>);
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

const COLUMNS: Record<Tab, number> = { ec2: 11, rds: 10, elasticache: 9, lambda: 10, ebs: 9, s3: 8, route53: 6 };

/** The expanded detail under a row: scrolls into view when it opens, lays its groups out in two columns on wide screens. */
/** The instance's baselines: median and p95 per metric, from 14 days of CloudWatch CPU and the probe history. */
function TypicalLine({ instanceId }: { instanceId: string }) {
  const [b, setB] = useState<any[] | null>(null);
  useEffect(() => { setB(null); api(`/baselines?scope_kind=instance&scope_id=${instanceId}`).then((d) => setB(d.baselines)).catch(() => setB([])); }, [instanceId]);
  if (!b || !b.length) return null;
  const order = ["cpu_pct", "mem_pct", "disk_pct", "load_per_cpu", "containers"];
  const rows = b.filter((x) => order.includes(x.metric)).sort((x, y) => order.indexOf(x.metric) - order.indexOf(y.metric));
  return (
    <div className="mt-1 text-xs text-zinc-400">
      Typical: {rows.map((x, i) => <span key={x.metric}>{i ? " · " : ""}{metricLabel(x.metric)} <span className="text-zinc-200">{Math.round(x.median)}{x.unit === "%" ? "%" : ""}</span> (p95 {Math.round(x.p95)}{x.unit === "%" ? "%" : ""}, {x.days} d{x.by_hour.some((h: number | null) => h != null) ? ", hourly profile" : ""})</span>)}
    </div>
  );
}

/** Cypher that pulls one resource with everything linked to it, for Neo4j Browser or the agent's graph_query tool. */
const resourceCypher = (id: string) => `MATCH (r:AdvisorResource {id: '${id}'})\nOPTIONAL MATCH (r)-[e]-(x)\nOPTIONAL MATCH (x)-[d:DECIDED_AS]->(c:Concept)\nRETURN r, e, x, d, c`;

/** What the Neo4j mirror holds for one resource: counts of what is linked, or why there is nothing. */
function GraphLine({ id }: { id: string }) {
  const [g, setG] = useState<{ state: "loading" | "off" | "missing" | "error" | "ok"; view?: any; error?: string }>({ state: "loading" });
  useEffect(() => {
    let live = true;
    setG({ state: "loading" });
    api(`/graph/resource/${encodeURIComponent(id)}`)
      .then((view) => live && setG({ state: "ok", view }))
      .catch((e) => { if (!live) return; const m = String(e.message || ""); setG({ state: /not configured/i.test(m) ? "off" : /not in the graph/i.test(m) ? "missing" : "error", error: m }); });
    return () => { live = false; };
  }, [id]);
  const c = g.view?.counts;
  return (
    <Group title="Graph" action={g.state !== "off" ? <span className="normal-case tracking-normal"><CopyButton text={resourceCypher(id)} label="Copy Cypher" /></span> : null}>
      <div className="text-sm text-zinc-400">
        {g.state === "loading" ? "…"
          : g.state === "off" ? "The Neo4j mirror is not configured (NEO4J_URI)."
          : g.state === "missing" ? "Not in the graph yet: resync from Knowledge, or wait for the next run."
          : g.state === "error" ? <span className="text-red-300">{g.error}</span>
          : <>{c.recommendations} recommendation{c.recommendations === 1 ? "" : "s"} · {c.alerts} alert{c.alerts === 1 ? "" : "s"} · {c.incidents} incident{c.incidents === 1 ? "" : "s"} · {c.controls} control{c.controls === 1 ? "" : "s"} flagged{g.view.role ? ` · role ${g.view.role}` : ""}{g.view.pool ? ` · pool ${g.view.pool}` : ""}{g.view.recommendations.filter((r: any) => r.concept).length ? ` · ${g.view.recommendations.filter((r: any) => r.concept).length} decided as a Concept` : ""}</>}
      </div>
    </Group>
  );
}

function Ec2Detail({ d, probe, onProbe }: { d: any; probe: { busy: boolean; error: string }; onProbe: () => void }) {
  const s = d.snapshot || {};
  const id = s.identity || {}; const net = s.network || {}; const st = s.storage || {}; const ssm = s.ssm; const ut = s.utilisation || {}; const price = s.price;
  const latest = d.probes?.[0];
  const canProbe = d.state === "running" && d.ssm_status === "Online" && (!ssm?.platform_type || ssm.platform_type === "Linux");
  return (
    <>
      <h2 className="text-base font-medium text-zinc-100">{d.name || d.instance_id}</h2>
      <div className="mt-1 flex flex-wrap items-center gap-2 text-xs"><Badge>{d.state}</Badge><SsmBadge status={d.ssm_status} platform={d.ssm_platform} />{d.gone ? <Badge>gone</Badge> : null}<Mono>{d.instance_id}</Mono></div>
      <div className="mt-1 text-xs text-zinc-500">first seen {when(d.first_seen)} · last seen {when(d.last_seen)}</div>

      <Group title="Identity">
        <Dl rows={[
          ["Type", <>{id.instance_type}{id.cpu_cores ? <span className="text-zinc-500"> · {id.cpu_cores} cores × {id.threads_per_core} threads</span> : null}</>],
          ["Region / AZ", `${id.region} / ${id.az}`],
          ["Launched", when(id.launch_time)],
          ["State since", id.state_transition_time ? `${when(id.state_transition_time)}${id.state_transition_reason ? ` (${id.state_transition_reason})` : ""}` : null],
          ["Platform", [id.platform_details, id.architecture].filter(Boolean).join(" · ")],
          ["Lifecycle", id.instance_lifecycle],
          ["Pool", s.pool ? <><PoolBadge kind={s.pool.kind} /> <span className="font-mono text-xs">{s.pool.name}</span><div className="mt-1 text-xs text-zinc-400">{s.pool.note}</div></> : null],
          ["AMI", id.image_id && <Mono>{id.image_id}</Mono>],
          ["Key pair", id.key_name],
          ["Instance profile", id.iam_instance_profile_arn && <Mono>{id.iam_instance_profile_arn}</Mono>],
          ["Monitoring", id.monitoring_state],
          ["EBS optimized", yesNo(id.ebs_optimized)],
        ]} />
      </Group>

      <Group title="Network">
        <Dl rows={[
          ["Private IP", net.private_ip && <Mono>{net.private_ip}</Mono>],
          ["Public IP", net.public_ip && <Mono>{net.public_ip}</Mono>],
          ["Private DNS", net.private_dns && <Mono>{net.private_dns}</Mono>],
          ["Public DNS", net.public_dns && <Mono>{net.public_dns}</Mono>],
          ["VPC / subnet", (net.vpc_id || net.subnet_id) && <Mono>{net.vpc_id} / {net.subnet_id}</Mono>],
          ["Security groups", net.security_groups?.length ? net.security_groups.map((g: any) => `${g.GroupName || ""} (${g.GroupId})`).join(", ") : null],
        ]} />
      </Group>

      <Group title={`Storage · ${gb(st.ebs_gb)}`}>
        <Dl rows={[["Root device", st.root_device_name && `${st.root_device_name} (${st.root_device_type})`]]} />
        {st.volumes?.length > 0 && (
          <table className="mt-1 w-full text-xs">
            <thead><tr className="text-zinc-500"><th className="text-left font-normal">Volume</th><th className="text-left font-normal">Device</th><th className="text-left font-normal">Type</th><th className="text-right font-normal">GB</th><th className="text-right font-normal">IOPS</th><th className="text-right font-normal">Del. on term.</th></tr></thead>
            <tbody>{st.volumes.map((v: any) => <tr key={v.volume_id} className="border-t border-zinc-800/60"><td className="py-0.5 font-mono">{v.volume_id}</td><td>{v.device}</td><td>{v.type}{v.encrypted ? " 🔒" : ""}</td><td className="text-right">{v.size}</td><td className="text-right">{v.iops ?? "—"}</td><td className="text-right">{yesNo(v.delete_on_termination)}</td></tr>)}</tbody>
          </table>
        )}
      </Group>

      <Group title="Systems Manager">
        {ssm ? (
          <Dl rows={[
            ["Ping status", <Badge>{ssm.ping_status}</Badge>],
            ["Platform", [ssm.platform_name, ssm.platform_version].filter(Boolean).join(" ") || ssm.platform_type],
            ["Agent", ssm.agent_version && `${ssm.agent_version}${ssm.agent_latest === false ? " (update available)" : ssm.agent_latest ? " (latest)" : ""}`],
            ["Last ping", when(ssm.last_ping)],
            ["IAM role", ssm.iam_role],
            ["Computer name", ssm.computer_name],
          ]} />
        ) : <div className="text-sm text-zinc-400">Not registered with Systems Manager: no SSM agent, no instance profile with the SSM policy, or outside the connection's regions. It cannot be probed or managed through Run Command.</div>}
      </Group>

      <Group title="Utilisation" action={canProbe ? <Button variant="ghost" className="!px-2 !py-1 !text-xs normal-case tracking-normal" onClick={onProbe} disabled={probe.busy}>{probe.busy ? "Probing…" : latest ? "Probe again" : "Probe"}</Button> : null}>
        <Dl rows={[
          ["CPU, 30 days", ut.cpu_days ? `${pct(ut.cpu_30d_avg_max)} avg daily peak · ${pct(ut.cpu_30d_avg)} avg · ${ut.cpu_days} days of data` : "no CloudWatch data"],
          ["Latest probe", latest ? <>{when(latest.collected_at)}: memory {latest.summary.memory_used_pct}% ({latest.summary.memory_used_gb} of {latest.summary.memory_total_gb} GB) · load {latest.summary.load_1m} on {latest.summary.cpus} vCPU{latest.summary.top_process ? ` · busiest ${latest.summary.top_process}` : ""}</> : canProbe ? "none yet; the probe reads memory, disks, load and top processes over SSM" : null],
        ]} />
        <TypicalLine instanceId={d.instance_id} />
        {probe.error && <div className="mt-1 text-xs text-red-300">{probe.error}</div>}
        {latest?.data?.disks?.length > 0 && <div className="mt-1 text-xs text-zinc-400">Disks: {latest.data.disks.map((x: any) => `${x.mount} ${x.used_pct}%`).join(", ")}</div>}
        {latest?.data?.top_cpu?.length > 0 && <div className="text-xs text-zinc-400">Top CPU: {latest.data.top_cpu.slice(0, 3).map((p: any) => `${p.command} ${p.cpu_pct}%`).join(", ")}</div>}
        {latest?.data?.top_mem?.length > 0 && <div className="text-xs text-zinc-400">Top memory: {latest.data.top_mem.slice(0, 3).map((p: any) => `${p.command} ${Math.round(p.rss_bytes / 1048576)} MB`).join(", ")}</div>}
        {latest?.data?.docker?.available && (
          <div className="mt-1 text-xs text-zinc-400">
            Docker: {latest.data.docker.running} running of {latest.data.docker.total}
            {latest.data.containers?.length > 0 && (
              <ul className="mt-0.5 space-y-0.5">
                {latest.data.containers.slice(0, 12).map((c: any) => (
                  <li key={c.name} className="flex flex-wrap gap-x-2">
                    <span className={c.state === "running" ? "text-zinc-200" : "text-zinc-500"}>{c.name}</span>
                    <span className="text-zinc-500">{c.image}</span>
                    <span className="text-zinc-500">{c.state}{c.cpu_pct != null ? ` · cpu ${c.cpu_pct}%` : ""}{c.mem_bytes ? ` · ${Math.round(c.mem_bytes / 1048576)} MB${c.mem_pct != null ? ` (${c.mem_pct}%)` : ""}` : ""}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}
        {latest?.data?.docker && !latest.data.docker.available && <div className="mt-1 text-xs text-zinc-600">No Docker daemon on this instance (probe 1.2 reports containers where Docker runs).</div>}
        <div className="mt-3"><InstanceCharts instanceId={d.instance_id} /></div>
        {d.probes?.length > 1 && (
          <details className="mt-1 text-xs"><summary className="cursor-pointer text-zinc-500">Probe history ({d.probes.length})</summary>
            <ul className="mt-1 space-y-0.5 text-zinc-400">{d.probes.map((p: any) => <li key={p.id}>{when(p.collected_at)} · memory {p.summary.memory_used_pct}% · load {p.summary.load_1m}{p.summary.top_process ? ` · ${p.summary.top_process}` : ""}</li>)}</ul>
          </details>
        )}
      </Group>

      <Group title="Price">
        {price?.monthly != null ? <Dl rows={[["On-demand", `${usd(price.monthly, 2)} / month · ${usd(price.hourly, 4)} / hour (${price.operating_system}, list price × 730 h; reservations and Savings Plans not applied)`], ["Price fetched", when(price.fetched_at)]]} />
          : <div className="text-sm text-zinc-500">No on-demand price found for {d.instance_type} in {d.region}.</div>}
      </Group>

      <Group title="Role (Jev)">
        <div className="text-sm"><RoleLine role={d.role} />{d.role?.updated_at && <span className="ml-2 text-xs text-zinc-500">classified {when(d.role.updated_at)}</span>}</div>
      </Group>

      <Group title="Tags"><Tags tags={s.tags} /></Group>

      <Domains list={d.domains} empty={d.public_ip || net.public_dns ? "No Route 53 record in this account points at this instance, its Elastic IP or a load balancer in front of it." : "No Route 53 record in this account reaches this instance (no public address; check the load balancers)."} />
      <Related id={d.instance_id} recs={d.open_recs} findings={d.findings_count ?? 0} list={d.recommendations} />
      {d.findings_run_id && d.findings?.length > 0 && (
        <ul className="mt-1 space-y-0.5 text-sm">{d.findings.map((f: any) => <li key={f.id} className="flex gap-2"><Badge>{f.status}</Badge><span className="min-w-0 truncate" title={f.reason || ""}>{f.control_title || f.control_id}{f.reason ? `: ${f.reason}` : ""}</span></li>)}</ul>
      )}

      <GraphLine id={d.instance_id} />
    </>
  );
}

function RdsDetail({ d }: { d: any }) {
  const s = d.snapshot || {};
  const id = s.identity || {}; const st = s.storage || {}; const net = s.network || {}; const ut = s.utilisation || {}; const price = s.price;
  return (
    <>
      <h2 className="text-base font-medium text-zinc-100">{d.db_instance_identifier}</h2>
      <div className="mt-1 flex flex-wrap items-center gap-2 text-xs"><Badge>{d.status}</Badge>{d.gone ? <Badge>gone</Badge> : null}<span className="text-zinc-500">{d.engine} {d.engine_version}</span></div>
      <div className="mt-1 text-xs text-zinc-500">first seen {when(d.first_seen)} · last seen {when(d.last_seen)}</div>
      <Group title="Identity">
        <Dl rows={[
          ["Class", `${id.class}${id.multi_az ? " · Multi-AZ" : ""}`],
          ["Region / AZ", `${id.region} / ${id.availability_zone}`],
          ["Created", when(id.created)],
          ["Cluster", id.cluster],
          ["Replica of", id.read_replica_source],
          ["Licence", id.license_model],
          ["Deletion protection", yesNo(id.deletion_protection)],
          ["Backup retention", id.backup_retention_days != null ? `${id.backup_retention_days} days` : null],
          ["Performance Insights", yesNo(id.performance_insights)],
          ["ARN", id.arn && <Mono>{id.arn}</Mono>],
        ]} />
      </Group>
      <Group title="Storage">
        <Dl rows={[
          ["Type", st.storage_type],
          ["Allocated", st.allocated_gb != null ? `${gb(st.allocated_gb)}${st.max_allocated_gb ? ` (autoscaling to ${gb(st.max_allocated_gb)})` : ""}` : null],
          ["IOPS / throughput", st.iops || st.throughput ? `${st.iops ?? "—"} / ${st.throughput ?? "—"} MB/s` : null],
          ["Encrypted", yesNo(st.encrypted)],
        ]} />
      </Group>
      <Group title="Network">
        <Dl rows={[["Endpoint", net.endpoint && <Mono>{net.endpoint}:{net.port}</Mono>], ["Publicly accessible", yesNo(net.publicly_accessible)], ["VPC", net.vpc_id && <Mono>{net.vpc_id}</Mono>]]} />
      </Group>
      <Group title="Utilisation, 30 days">
        <Dl rows={[
          ["CPU", ut.cpu_days ? `${pct(ut.cpu_30d_avg_max)} avg daily peak · ${pct(ut.cpu_30d_avg)} avg · ${ut.cpu_days} days of data` : "no CloudWatch data"],
          ["Connections", ut.connections_avg != null ? `${ut.connections_avg} avg · ${ut.connections_max} peak` : null],
          ["I/O", ut.read_iops_avg != null ? `${ut.read_iops_avg} read + ${ut.write_iops_avg} write IOPS avg` : null],
          ["Freeable memory, minimum", ut.freeable_memory_min_gb != null ? `${ut.freeable_memory_min_gb} GB` : null],
        ]} />
      </Group>
      <Group title="Price">
        {price?.monthly != null ? <Dl rows={[["On-demand", `${usd(price.monthly, 2)} / month · ${usd(price.hourly, 4)} / hour (${price.pricing_engine}; instance hours only, storage and I/O not included)`], ["Price fetched", when(price.fetched_at)]]} />
          : <div className="text-sm text-zinc-500">No instance price for {d.class} ({d.engine}){d.class === "db.serverless" ? ": Aurora Serverless bills per ACU-hour" : ""}.</div>}
      </Group>
      <Group title="Role (Jev)">
        <div className="text-sm"><RoleLine role={d.role} />{d.role?.updated_at && <span className="ml-2 text-xs text-zinc-500">classified {when(d.role.updated_at)}</span>}</div>
      </Group>
      <Group title="Tags"><Tags tags={s.tags} /></Group>
      <Domains list={d.domains} empty="No Route 53 record names this endpoint (applications use the RDS endpoint directly)." />
      <Group title={`Load${id.cluster ? ` · cluster ${id.cluster}` : ""}`}><RdsLoadPanel id={id.cluster || d.db_instance_identifier} compact /></Group>
      <Related id={d.db_instance_identifier} recs={d.open_recs} findings={d.findings} />
    </>
  );
}

function EbsDetail({ d }: { d: any }) {
  const used = Math.max(Number(d.iops_max || 0), Number(d.read_iops_avg || 0) + Number(d.write_iops_avg || 0));
  return (
    <>
      <h2 className="text-base font-medium text-zinc-100">{d.name || d.volume_id}</h2>
      <div className="mt-1 flex flex-wrap items-center gap-2 text-xs"><Badge>{d.state}</Badge><Badge>{d.volume_type}</Badge>{d.encrypted ? <Badge>encrypted</Badge> : null}<Mono>{d.volume_id}</Mono></div>
      <Group title="Volume">
        <Dl rows={[["Size", `${d.size_gb} GB`], ["Provisioned", d.provisioned_iops != null ? `${Number(d.provisioned_iops).toLocaleString()} IOPS${d.throughput_mibps ? ` · ${d.throughput_mibps} MiB/s` : ""}` : null], ["Attached to", d.instance_id ? <Link className="underline" to={`/inventory?tab=ec2&id=${d.instance_id}`}>{d.instance_name || d.instance_id} {d.device}</Link> : "nothing: unattached volumes cost the same as attached ones"], ["Region", d.region], ["Created", when(d.created)]]} />
      </Group>
      <Group title="Usage, 30 days">
        <Dl rows={[["Read / write", d.read_iops_avg != null ? `${d.read_iops_avg} / ${d.write_iops_avg} IOPS average` : "no metrics"], ["Peak", d.iops_max != null ? `${Number(d.iops_max).toLocaleString()} IOPS peak sample (30 d)` : null], ["Provisioned used", d.provisioned_iops ? <span className={used < 0.3 * d.provisioned_iops && d.iops > 3000 ? "text-amber-300" : ""}>{Math.round((100 * used) / d.provisioned_iops)} % of {Number(d.provisioned_iops).toLocaleString()}{used < 0.3 * d.provisioned_iops && d.iops > 3000 ? " (over-provisioned)" : ""}</span> : null]]} />
      </Group>
      <Group title="Price">
        <Dl rows={[["At list", `${usd(d.monthly_usd, 2)} / month`], ["gp3 instead", d.volume_type === "gp2" ? `${usd(d.size_gb * 0.08, 2)} / month for the same size and 3,000 IOPS included` : null]]} />
      </Group>
    </>
  );
}

function S3Detail({ d }: { d: any }) {
  const sizes: Record<string, number> = d.sizes || {};
  const PRICE: Record<string, number> = { StandardStorage: 0.023, StandardIAStorage: 0.0125, OneZoneIAStorage: 0.01, IntelligentTieringFAStorage: 0.023, IntelligentTieringIAStorage: 0.0125, IntelligentTieringAAStorage: 0.004, IntelligentTieringAIAStorage: 0.004, IntelligentTieringDAAStorage: 0.00099, GlacierInstantRetrievalStorage: 0.004, GlacierStorage: 0.0036, DeepArchiveStorage: 0.00099, ReducedRedundancyStorage: 0.023 };
  return (
    <>
      <h2 className="text-base font-medium text-zinc-100">{d.name}</h2>
      <div className="mt-1 flex flex-wrap items-center gap-2 text-xs"><Badge>{d.region}</Badge>{d.public ? <Badge>public</Badge> : null}{d.versioning ? <Badge>versioned</Badge> : null}<span className="text-zinc-500">created {when(d.created)}</span></div>
      <Group title="Storage by class">
        {Object.keys(sizes).length === 0 ? <div className="text-sm text-zinc-500">No storage metrics yet (CloudWatch publishes bucket sizes once a day; empty buckets have none).</div> : (
          <table className="w-full text-sm"><thead><tr className="text-zinc-500"><th className="text-left font-normal">Class</th><th className="text-right font-normal">GB</th><th className="text-right font-normal">$ / GB-mo</th><th className="text-right font-normal">$ / mo</th></tr></thead>
            <tbody>{Object.entries(sizes).sort((a, b) => b[1] - a[1]).map(([c, gb]) => <tr key={c} className="border-t border-zinc-800/60"><td className="py-0.5">{c.replace(/Storage$/, "")}</td><td className="text-right">{gb.toLocaleString(undefined, { maximumFractionDigits: 2 })}</td><td className="text-right font-mono text-xs">{PRICE[c] ?? "—"}</td><td className="text-right">{usd(gb * (PRICE[c] ?? 0.023), 2)}</td></tr>)}</tbody></table>
        )}
      </Group>
      <Domains list={d.domains} empty="No Route 53 record serves this bucket as a website or a CloudFront origin." />
      <Group title="Lifecycle">
        <Dl rows={[["Rules", d.lifecycle_rules ? `${d.lifecycle_rules}` : <span className={d.standard_gb > 20 ? "text-amber-300" : ""}>none{d.standard_gb > 20 ? `: ${Number(d.standard_gb).toFixed(0)} GB sit in Standard; a transition to Infrequent Access after 30 days would save about ${usd(d.standard_gb * (0.023 - 0.0125))}/month if rarely read` : ""}</span>], ["Objects", d.objects != null ? Number(d.objects).toLocaleString() : null], ["Metrics day", d.metric_day]]} />
      </Group>
    </>
  );
}

function Route53Detail({ d }: { d: any }) {
  const links: any[] = d.links || []; const routing = d.routing || {};
  const routingRows: [string, ReactNode][] = Object.entries(routing).map(([k, v]) => [k.replace(/_/g, " "), typeof v === "object" ? JSON.stringify(v) : String(v)]);
  return (
    <>
      <h2 className="break-all font-mono text-base font-medium text-zinc-100">{d.name}</h2>
      <div className="mt-1 flex flex-wrap items-center gap-2 text-xs"><Badge>{d.type}</Badge>{d.alias ? <Badge>alias</Badge> : null}<Badge>{d.link_state}</Badge>{d.gone ? <Badge>gone</Badge> : null}<span className="text-zinc-500">zone {d.zone_name}</span></div>
      <div className="mt-1 text-xs text-zinc-500">first seen {when(d.first_seen)} · last seen {when(d.last_seen)}</div>
      <Group title="Record">
        <Dl rows={[
          ["Alias target", d.alias ? <Mono>{d.alias_target}</Mono> : null],
          ["Values", !d.alias && d.values?.length ? <ul className="space-y-0.5">{d.values.map((v: string, i: number) => <li key={i} className="break-all font-mono text-xs">{v}</li>)}</ul> : null],
          ["TTL", d.alias ? "alias records take the target's TTL" : d.ttl != null ? `${d.ttl} s` : null],
          ["Health check", d.health_check_id && <Mono>{d.health_check_id}</Mono>],
          ...routingRows,
        ]} />
      </Group>
      <Group title="Leads to">
        <div className={`text-sm ${d.link_state === "unmatched" ? "text-red-300" : "text-zinc-200"}`}>{d.summary}</div>
        {d.link_state === "unmatched" && <div className="mt-1 text-xs text-zinc-400">A record that names an AWS resource this account no longer has serves nothing, and an S3 website or ELB name can be claimed by a stranger (subdomain takeover). Delete the record, or recreate the resource. If the target lives in another AWS account, that is fine: the advisor only sees this one.</div>}
        {d.link_state === "external" && <div className="mt-1 text-xs text-zinc-400">Points outside AWS: nothing in this account serves it, so no AWS cost follows from it beyond the zone.</div>}
        {links.length > 0 && (
          <ul className="mt-2 space-y-1">
            {links.map((l: any, i: number) => <li key={`${l.kind}:${l.id}:${i}`} className={l.hop > 1 ? "ml-4" : ""}><ResourceLink l={l} />{l.via && l.hop > 1 ? <span className="ml-2 text-xs text-zinc-500">via {l.via}</span> : null}</li>)}
          </ul>
        )}
      </Group>
    </>
  );
}

function LambdaDetail({ d }: { d: any }) {
  const rate = d.arm ? 0.0000133334 : 0.0000166667;
  return (
    <>
      <h2 className="text-base font-medium text-zinc-100">{d.name}</h2>
      <div className="mt-1 flex flex-wrap items-center gap-2 text-xs"><Badge>{d.runtime || "runtime ?"}</Badge><Badge>{d.arm ? "arm64" : "x86_64"}</Badge>{d.gone ? <Badge>gone</Badge> : null}<Mono>{d.arn}</Mono></div>
      <div className="mt-1 text-xs text-zinc-500">first seen {when(d.first_seen)} · last seen {when(d.last_seen)}</div>
      <Group title="Configuration">
        <Dl rows={[["Memory", `${d.memory_mb} MB`], ["Timeout", d.timeout_s != null ? `${d.timeout_s} s` : null], ["Region", d.region]]} />
      </Group>
      <Group title="Usage, last 30 days">
        <Dl rows={[
          ["Invocations", `${Number(d.invocations_30d).toLocaleString()} over ${d.days} day${d.days === 1 ? "" : "s"} with data`],
          ["Average duration", d.avg_duration_ms != null ? `${Number(d.avg_duration_ms).toLocaleString()} ms` : "—"],
          ["Errors", Number(d.errors_30d).toLocaleString()],
          ["Compute", `${Number(d.gb_seconds_month).toLocaleString()} GB-seconds / month (duration × ${d.memory_mb / 1024} GB)`],
        ]} />
      </Group>
      <Group title="Price">
        <Dl rows={[
          ["At list", <>{usd(d.monthly_usd, 2)} / month = {Number(d.gb_seconds_month).toLocaleString()} GB-s × {rate} + {Number(d.invocations_month).toLocaleString()} requests × 0.0000002</>],
          ["What the bill applies", "the Compute Savings Plan discount and the free tier (400,000 GB-s and one million requests a month across the account), so the net line is lower"],
          ["Graviton", d.arm ? "already on arm64" : `arm64 would cost ${usd(Number(d.gb_seconds_month) * 0.0000133334 + Number(d.invocations_month) * 0.0000002, 2)} / month at list (20 % less on compute); needs an arm64 build of the function`],
        ]} />
      </Group>
      <Domains list={d.domains} empty="No Route 53 record reaches this function (a function URL, an API Gateway domain or a load balancer target would)." />
      <Group title="Findings and recommendations">
        <div className="text-sm text-zinc-400">{d.findings ? <Link className="underline" to={`/findings?q=${encodeURIComponent(d.name)}`}>{d.findings} finding{d.findings === 1 ? "" : "s"}</Link> : "no findings"} · {d.open_recs ? <Link className="underline" to={`/recommendations?q=${encodeURIComponent(d.name)}`}>{d.open_recs} open recommendation{d.open_recs === 1 ? "" : "s"}</Link> : "no open recommendations"}</div>
      </Group>
    </>
  );
}

function CacheDetail({ d }: { d: any }) {
  const s = d.snapshot || {};
  const id = s.identity || {}; const price = s.price; const ut = s.utilisation || {};
  return (
    <>
      <h2 className="text-base font-medium text-zinc-100">{d.cache_cluster_id}</h2>
      <div className="mt-1 flex flex-wrap items-center gap-2 text-xs"><Badge>{d.status}</Badge>{d.gone ? <Badge>gone</Badge> : null}<span className="text-zinc-500">{d.engine} {d.engine_version}</span></div>
      <div className="mt-1 text-xs text-zinc-500">first seen {when(d.first_seen)} · last seen {when(d.last_seen)}</div>
      <Group title="Identity">
        <Dl rows={[
          ["Node type", `${id.node_type} × ${id.num_nodes}`],
          ["Replication group", id.replication_group],
          ["Region / AZ", `${id.region} / ${id.availability_zone || "—"}`],
          ["Created", when(id.created)],
          ["Subnet group", id.subnet_group],
          ["Encryption", `in transit ${yesNo(id.transit_encryption) ?? "—"} · at rest ${yesNo(id.at_rest_encryption) ?? "—"}`],
          ["Auto minor upgrade", yesNo(id.auto_minor_version_upgrade)],
          ["Snapshot retention", id.snapshot_retention_days != null ? `${id.snapshot_retention_days} days` : null],
          ["ARN", id.arn && <Mono>{id.arn}</Mono>],
        ]} />
      </Group>
      <Group title="Utilisation, 30 days">
        <Dl rows={[
          ["Engine CPU", ut.cpu_days ? `${pct(ut.cpu_30d_avg_max)} avg daily peak · ${pct(ut.cpu_30d_avg)} avg · ${ut.cpu_days} days of data` : "no CloudWatch data"],
          ["Memory, peak", ut.memory_pct_max != null ? <span className={ut.memory_pct_max >= 90 ? "text-amber-300" : ""}>{ut.memory_pct_max}% of the node's memory</span> : null],
          ["Evictions", ut.evictions_30d != null ? (ut.evictions_30d ? <span className="text-amber-300">{Number(ut.evictions_30d).toLocaleString()} keys evicted: the cache is too small for its working set</span> : "none") : null],
          ["Connections, peak", ut.connections_max != null ? String(ut.connections_max) : null],
        ]} />
      </Group>
      <Group title="Price">
        {price?.monthly != null ? <Dl rows={[["On-demand", `${usd(price.monthly, 2)} / month (${usd(price.monthly_per_node, 2)} per node × ${id.num_nodes}; ${usd(price.hourly_per_node, 4)} / node-hour, ${price.pricing_engine})`], ["Price fetched", when(price.fetched_at)]]} />
          : <div className="text-sm text-zinc-500">No on-demand price found for {d.node_type} ({d.engine}).</div>}
      </Group>
      <Group title="Tags"><Tags tags={s.tags} /></Group>
      <Domains list={d.domains} empty="No Route 53 record names this cluster's endpoints." />
      <Related id={d.cache_cluster_id} recs={d.open_recs} findings={d.findings} />
    </>
  );
}

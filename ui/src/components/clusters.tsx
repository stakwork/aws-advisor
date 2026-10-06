import { Fragment, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, when } from "../api";
import { Badge, Button, Code, CopyButton, Empty, Stat, Td, Th } from "./ui";

type Cluster = { arn: string; kind: "eks" | "ecs"; name: string; region: string | null; version: string | null; platform_version: string | null; status: string | null; endpoint: string | null; endpoint_public: boolean | null; public_cidrs: string[]; endpoint_private: boolean | null; vpc_id: string | null; security_groups: string[]; authentication_mode: string | null; nodes: number | null; workloads: number; namespaces: string[]; access_status: string | null; access_error: string | null; access_checked_at: string | null; last_seen: string; gone: boolean; access: { mode: string; steps: { title: string; command: string }[] } | null };
type Workload = { id: string; namespace: string | null; kind: string; name: string; replicas_desired: number | null; replicas_ready: number | null; containers: { name: string; image: string; ports: { port: number; protocol: string }[] }[]; images: string[]; nodes: string[]; pods_running: number | null; revision: string | null; strategy: string | null; schedule: string | null; created: string | null; services: { name: string; type: string; ports: string[]; lb_hostnames: string[] }[]; ingresses: { name: string; hosts: string[]; class: string | null; tls: boolean; lb_hostnames: string[] }[]; policies: string[]; gone?: boolean };

const accessTone: Record<string, string> = { ok: "text-emerald-300", unauthorized: "text-amber-300", forbidden: "text-amber-300", unreachable: "text-red-300", tls: "text-red-300", error: "text-red-300", unknown: "text-zinc-500" };
const accessWord: Record<string, string> = { ok: "readable", unauthorized: "identity not mapped in the cluster", forbidden: "mapped, but may not list", unreachable: "endpoint not reachable from here", tls: "TLS to the endpoint failed", error: "error", unknown: "not checked yet" };
const short = (s: string | null | undefined, n = 40) => { const t = String(s ?? ""); return t.length > n ? `${t.slice(0, n)}…` : t; };

/** One cluster's workloads with their images, replicas, nodes and what exposes them; fetched when the row opens. */
function WorkloadsPanel({ cluster }: { cluster: Cluster }) {
  const [d, setD] = useState<any>(null);
  const [q, setQ] = useState("");
  useEffect(() => { setD(null); api(`/inventory/clusters/${encodeURIComponent(cluster.arn)}/workloads`).then(setD).catch((e) => setD({ error: e.message })); }, [cluster.arn, cluster.access_checked_at]);
  if (!d) return <div className="text-xs text-zinc-500">Loading the workloads…</div>;
  if (d.error) return <div className="text-xs text-red-300">{d.error}</div>;
  const list: Workload[] = (d.workloads as Workload[]).filter((w) => !q || JSON.stringify(w).toLowerCase().includes(q.toLowerCase()));
  return (
    <div className="space-y-2 text-xs">
      {cluster.kind === "eks" && cluster.access_status !== "ok" && cluster.access && (
        <div className="rounded border border-amber-900/60 bg-amber-950/20 p-3">
          <div className="text-amber-200">The advisor cannot read this cluster's workloads: {accessWord[cluster.access_status || "unknown"]}{cluster.access_error ? ` (${cluster.access_error})` : ""}.</div>
          <div className="mt-1 text-zinc-400">It authenticates to the Kubernetes API as its read role in this cluster's account (the parent's from Settings › AWS access, or the member's read role), so the cluster has to know that role. Authentication mode today: <span className="font-mono">{cluster.access.mode}</span>. As a cluster administrator:</div>
          {cluster.access.steps.map((s, i) => <div key={i} className="mt-2"><div className="text-zinc-300">{i + 1}. {s.title}</div><div className="mt-1 flex items-start gap-2"><Code>{s.command}</Code><CopyButton text={s.command} /></div></div>)}
          <div className="mt-2 text-zinc-500">Read-only either way: the view policy and the view ClusterRole grant get and list, nothing else. Refresh afterwards.</div>
          {/CONFIG_MAP/.test(cluster.access.mode) && <div className="mt-1 text-amber-300/80">Do not edit aws-auth with <span className="font-mono">kubectl patch</span>: mapRoles is a single value, so a patch replaces the whole list, node roles included, and the nodes drop out of the cluster. If that happened before, restore the backup with <span className="font-mono">kubectl apply -f</span>.</div>}
        </div>
      )}
      <div className="flex flex-wrap items-center gap-3 text-zinc-400">
        <span>{d.workloads.length} workloads · {d.services} services · {d.ingresses} ingresses · {d.policies} network policies{cluster.namespaces.length ? ` · namespaces: ${cluster.namespaces.join(", ")}` : ""}</span>
        <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="filter…" className="rounded border border-zinc-700 bg-zinc-900 px-2 py-0.5 text-zinc-200 placeholder:text-zinc-600" />
      </div>
      {list.length === 0 ? <Empty>{d.workloads.length ? "No workload matches." : cluster.kind === "ecs" ? "No ECS service in this cluster (AWS Batch compute environments run jobs, not services)." : "No workloads read yet."}</Empty> : (
        <table className="w-full border-collapse">
          <thead><tr><Th>Workload</Th><Th>Kind</Th><Th className="text-right">Ready</Th><Th>Images</Th><Th>Exposed through</Th><Th>Runs on</Th><Th>Policies</Th><Th>Created</Th></tr></thead>
          <tbody>
            {list.map((w) => (
              <tr key={w.id} className={`border-t border-zinc-800 align-top ${w.gone ? "text-zinc-600" : ""}`}>
                <Td><div className="text-zinc-100">{w.name}</div><div className="text-[11px] text-zinc-500">{w.namespace}{w.revision ? ` · rev ${w.revision}` : ""}{w.schedule ? ` · ${w.schedule}` : ""}</div></Td>
                <Td className="text-zinc-400">{w.kind.replace(/_/g, " ")}{w.strategy ? <div className="text-[11px] text-zinc-600">{w.strategy}</div> : null}</Td>
                <Td className={`text-right ${w.replicas_desired != null && w.replicas_ready != null && w.replicas_ready < w.replicas_desired ? "text-amber-300" : ""}`}>{w.replicas_ready ?? "—"} / {w.replicas_desired ?? "—"}</Td>
                <Td className="font-mono">{w.containers.map((c) => <div key={c.name} title={c.image}>{short(c.image, 48)}{c.ports.length ? <span className="text-zinc-500"> :{c.ports.map((p) => p.port).join(",")}</span> : null}</div>)}</Td>
                <Td>{w.ingresses.map((i) => <div key={i.name}><span className="text-red-200">ingress</span> {i.hosts.join(", ") || i.name}{i.tls ? <span className="text-zinc-500"> tls</span> : null}{i.lb_hostnames.length ? <div className="font-mono text-[11px] text-zinc-500">{short(i.lb_hostnames[0], 44)}</div> : null}</div>)}{w.services.map((s) => <div key={s.name}><span className={s.type === "LoadBalancer" ? "text-amber-200" : "text-zinc-400"}>{s.type}</span> {s.name} <span className="font-mono text-zinc-500">{s.ports.join(" ")}</span>{s.lb_hostnames.length ? <div className="font-mono text-[11px] text-zinc-500">{short(s.lb_hostnames[0], 44)}</div> : null}</div>)}{!w.ingresses.length && !w.services.length ? <span className="text-zinc-600">nothing</span> : null}</Td>
                <Td>{w.nodes.length ? w.nodes.slice(0, 4).map((n) => <div key={n}><Link className="font-mono underline" to={`/inventory?tab=ec2&id=${encodeURIComponent(n)}`}>{n}</Link></div>) : <span className="text-zinc-600">—</span>}{w.nodes.length > 4 ? <div className="text-zinc-600">and {w.nodes.length - 4} more</div> : null}{w.pods_running != null ? <div className="text-[11px] text-zinc-600">{w.pods_running} pods</div> : null}</Td>
                <Td className="text-zinc-400">{w.policies.length ? w.policies.join(", ") : <span className="text-zinc-600">none</span>}</Td>
                <Td className="whitespace-nowrap text-zinc-500">{w.created ? String(w.created).slice(0, 10) : "—"}</Td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

/** The Clusters tab: every EKS and ECS cluster with its access status; a row opens the workloads (or how to grant access). */
export function ClustersPanel({ selected, onSelect }: { selected: string | null; onSelect: (id: string | null) => void }) {
  const [d, setD] = useState<{ summary: any; principal_arn: string | null; clusters: Cluster[] } | null>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const load = () => api("/inventory/clusters").then((x) => { setD(x); setErr(""); }).catch((e) => setErr(e.message));
  useEffect(() => { load(); }, []);
  const refresh = async () => { setBusy(true); try { await api("/inventory/clusters/refresh", { method: "POST", body: "{}" }); await load(); } catch (e: any) { setErr(e.message); } finally { setBusy(false); } };
  if (err) return <div className="text-sm text-red-300">{err}</div>;
  if (!d) return <div className="text-sm text-zinc-500">Loading the clusters…</div>;
  const s = d.summary;
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Stat label="Clusters" value={s.total} hint={`${s.eks} EKS · ${s.ecs} ECS${s.ecs ? " (Batch compute environments included)" : ""}`} />
        <Stat label="Readable" value={<span className={s.readable < s.total ? "text-amber-300" : ""}>{s.readable}</span>} hint="clusters whose workloads the advisor can list" />
        <Stat label="Workloads" value={s.workloads} hint="deployments, statefulsets, daemonsets, jobs, ECS services" />
        <Stat label="Nodes" value={s.nodes} hint="from the node groups' desired sizes and the registered container instances" />
      </div>
      <div className="flex flex-wrap items-center justify-between gap-2 text-sm text-zinc-400">
        <span>The advisor reads EKS through the Kubernetes API as its read role in the account that owns each cluster (read-only) and ECS through the AWS API. Refreshed with every collection.</span>
        <Button variant="ghost" className="!px-2 !py-1 !text-xs" onClick={refresh} disabled={busy}>{busy ? "Refreshing…" : "Refresh now"}</Button>
      </div>
      {d.clusters.length === 0 ? <Empty>No cluster in the account, or none read yet: refresh now, or wait for the next collection.</Empty> : (
        <table className="w-full border-collapse text-sm">
          <thead><tr><Th>Cluster</Th><Th>Kind</Th><Th>Version</Th><Th>Access</Th><Th>API endpoint</Th><Th className="text-right">Nodes</Th><Th className="text-right">Workloads</Th><Th>Checked</Th></tr></thead>
          <tbody>
            {d.clusters.map((c) => (
              <Fragment key={c.arn}>
                <tr onClick={() => onSelect(selected === c.arn ? null : c.arn)} className={`cursor-pointer border-t border-zinc-800 hover:bg-zinc-900/60 ${c.gone ? "text-zinc-600" : ""}`}>
                  <Td><div className="font-medium text-zinc-100">{c.name}</div><div className="font-mono text-[11px] text-zinc-500">{short(c.arn, 70)}</div></Td>
                  <Td className="text-zinc-400">{c.kind === "eks" ? "EKS" : "ECS"}{c.gone ? <span className="ml-1"><Badge>gone</Badge></span> : null}</Td>
                  <Td className="text-zinc-400">{c.version ?? "—"}{c.platform_version ? <div className="text-[11px] text-zinc-600">{c.platform_version}</div> : null}</Td>
                  <Td className={accessTone[c.access_status || "unknown"]}>{accessWord[c.access_status || "unknown"]}{c.kind === "eks" && c.authentication_mode ? <div className="text-[11px] text-zinc-600">{c.authentication_mode}</div> : null}</Td>
                  <Td className="text-xs">{c.kind === "eks" ? <>{c.endpoint_public ? <span className={c.public_cidrs.includes("0.0.0.0/0") ? "text-red-300" : "text-amber-300"}>public{c.public_cidrs.includes("0.0.0.0/0") ? " to the world" : ` to ${c.public_cidrs.join(", ")}`}</span> : <span className="text-zinc-400">private only</span>}{c.endpoint_private ? <span className="text-zinc-500"> · private access on</span> : null}</> : <span className="text-zinc-600">—</span>}</Td>
                  <Td className="text-right">{c.nodes ?? "—"}</Td><Td className="text-right">{c.workloads}</Td>
                  <Td className="whitespace-nowrap text-xs text-zinc-500">{c.access_checked_at ? when(c.access_checked_at) : "—"}</Td>
                </tr>
                {selected === c.arn && <tr className="border-t border-zinc-800 bg-zinc-900/40"><td colSpan={8} className="p-3"><WorkloadsPanel cluster={c} /></td></tr>}
              </Fragment>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

import { Router } from "express";
import { authMiddleware } from "../auth.js";
import { clusterSummary, listClusters, listIngresses, listNetworkPolicies, listServices, listWorkloads, refreshClusters } from "../cluster_inventory.js";
import { accessInstructions } from "../k8s_client.js";
import { query } from "../steampipe.js";
import { sdkIdentity } from "../steampipe.js";
import { accountScope } from "../scope.js";
import { listMembers } from "../accounts.js";

/**
 * The clusters and their workloads (src/cluster_inventory.ts) for the Inventory's Clusters tab: every cluster with its
 * access status and, for one the advisor cannot read, the commands that grant its identity read access; the workloads
 * of one cluster with their images, replicas, nodes and what exposes them; a refresh on demand.
 */
export const clusters = Router();
clusters.use(authMiddleware);

clusters.get("/inventory/clusters", async (req, res) => {
  const scope = accountScope(req.query as any);
  const list = listClusters(scope);
  let principal: string | null = null;
  try { const id = await sdkIdentity(8_000); if (id.ok) principal = id.arn; } catch { principal = null; }
  // the cluster sees the identity of its own account: a member's cluster is read through that member's read role, the parent's through the parent's
  const memberRole = new Map(listMembers().map((m) => [m.account_id, m.role_arn]));
  const principalOf = (accountId: string | null) => (accountId && memberRole.get(accountId)) || principal;
  res.json({ summary: clusterSummary(scope), principal_arn: principal, clusters: list.map((c) => { const p = principalOf(c.account_id); return { ...c, access: c.kind === "eks" && c.access_status !== "ok" && p ? accessInstructions({ name: c.name, region: c.region, authentication_mode: c.authentication_mode }, p) : null }; }) });
});

clusters.get("/inventory/clusters/:arn/workloads", (req, res) => {
  const arn = String(req.params.arn);
  const c = listClusters().find((x) => x.arn === arn);
  if (!c) return res.status(404).json({ error: "no such cluster" });
  const services = listServices(arn); const ingresses = listIngresses(arn); const policies = listNetworkPolicies(arn);
  const workloads = listWorkloads(arn, req.query.gone === "1").map((w) => {
    const svcs = services.filter((s) => s.namespace === w.namespace && Object.keys(s.selector).length && Object.entries(s.selector).every(([k, v]) => w.labels[k] === v));
    const ings = ingresses.filter((i) => i.rules.some((r) => svcs.some((s) => s.name === r.service)));
    return { ...w, services: svcs.map((s) => ({ name: s.name, type: s.type, ports: s.ports.map((p) => `${p.port}/${p.protocol}`), lb_hostnames: s.lb_hostnames })), ingresses: ings.map((i) => ({ name: i.name, hosts: i.hosts, class: i.class, tls: i.tls, lb_hostnames: i.lb_hostnames })),
      policies: policies.filter((p) => p.namespace === w.namespace && Object.keys(p.pod_selector).length && Object.entries(p.pod_selector).every(([k, v]) => w.labels[k] === v)).map((p) => p.name) };
  });
  res.json({ cluster: c, workloads, services: services.length, ingresses: ingresses.length, policies: policies.length });
});

clusters.post("/inventory/clusters/refresh", async (_req, res) => {
  const attempt = async (what: string, sql: string): Promise<any[] | undefined> => { try { return await query<any>(sql); } catch (e: any) { console.error(`[clusters] ${what}: ${String(e?.message || e).slice(0, 200)}`); return undefined; } };
  try {
    const r = await refreshClusters(attempt);
    try { const { mirrorClusters } = await import("../graph_clusters.js"); await mirrorClusters(); } catch (e: any) { console.error(`[graph] clusters: ${e?.message || e}`); }
    res.json(r);
  } catch (e: any) { res.status(500).json({ error: e.message }); }
});

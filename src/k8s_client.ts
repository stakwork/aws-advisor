import { createHash, createHmac } from "node:crypto";
import https from "node:https";
import { SignatureV4 } from "@smithy/signature-v4";
import { sdkCredentials } from "./steampipe.js";

/**
 * A read-only Kubernetes API client for EKS clusters, authenticated the way `aws eks get-token` does: a presigned
 * sts:GetCallerIdentity URL carrying the cluster name in the `x-k8s-aws-id` header, base64url-encoded behind the
 * `k8s-aws-v1.` prefix, sent as a bearer token to the cluster endpoint over TLS pinned to the cluster's CA. The
 * advisor's own identity is what the cluster sees, so the cluster must map it (an access entry with the
 * AmazonEKSViewPolicy, or an aws-auth mapping to a view ClusterRole); `accessInstructions` prints both.
 * Only GET is ever issued, and only against list endpoints the inventory needs.
 */

export interface K8sCluster { name: string; endpoint: string; ca_data: string | null; region: string }
export type K8sErrorCode = "unreachable" | "unauthorized" | "forbidden" | "tls" | "bad_response" | "no_credentials";
export class K8sError extends Error { constructor(public code: K8sErrorCode, message: string, public status?: number) { super(message); this.name = "K8sError"; } }

class Sha256 {
  private h: ReturnType<typeof createHash> | ReturnType<typeof createHmac>;
  constructor(secret?: string | Uint8Array) { this.h = secret ? createHmac("sha256", typeof secret === "string" ? secret : Buffer.from(secret)) : createHash("sha256"); }
  update(data: string | Uint8Array) { this.h.update(typeof data === "string" ? Buffer.from(data, "utf8") : Buffer.from(data)); }
  async digest(): Promise<Uint8Array> { return new Uint8Array(this.h.digest()); }
}

/** The bearer token for one cluster: valid about fifteen minutes (EKS honours 60 s of the presign plus its own window). */
export async function eksToken(cluster: Pick<K8sCluster, "name" | "region">, creds = sdkCredentials()): Promise<string> {
  const signer = new SignatureV4({ service: "sts", region: cluster.region, credentials: creds.provider, sha256: Sha256 as any, applyChecksum: false });
  const host = `sts.${cluster.region}.amazonaws.com`;
  const presigned = await signer.presign({ method: "GET", protocol: "https:", hostname: host, path: "/", query: { Action: "GetCallerIdentity", Version: "2011-06-15" }, headers: { host, "x-k8s-aws-id": cluster.name } } as any, { expiresIn: 60, signableHeaders: new Set(["host", "x-k8s-aws-id"]) });
  const qs = Object.entries(presigned.query || {}).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(Array.isArray(v) ? v[0] : v))}`).join("&");
  const url = `https://${host}/?${qs}`;
  return `k8s-aws-v1.${Buffer.from(url, "utf8").toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")}`;
}

/** One GET against the cluster, JSON back; classified errors. */
export async function k8sGet(cluster: K8sCluster, path: string, token: string, timeoutMs = 20_000): Promise<any> {
  const u = new URL(path, cluster.endpoint.endsWith("/") ? cluster.endpoint : `${cluster.endpoint}/`);
  const ca = cluster.ca_data ? Buffer.from(cluster.ca_data, "base64") : undefined;
  return new Promise((resolve, reject) => {
    const req = https.request({ method: "GET", hostname: u.hostname, port: u.port || 443, path: `${u.pathname}${u.search}`, headers: { authorization: `Bearer ${token}`, accept: "application/json", "user-agent": "cloud-advisor" }, ca, rejectUnauthorized: Boolean(ca), timeout: timeoutMs }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => {
        const body = Buffer.concat(chunks).toString("utf8");
        const status = res.statusCode || 0;
        if (status === 401) return reject(new K8sError("unauthorized", `the cluster did not accept the token (401): the IAM identity is not known to it`, status));
        if (status === 403) return reject(new K8sError("forbidden", `the cluster knows the identity but it may not list ${u.pathname} (403): ${body.slice(0, 200)}`, status));
        if (status >= 400) return reject(new K8sError("bad_response", `${status} from ${u.pathname}: ${body.slice(0, 200)}`, status));
        try { resolve(JSON.parse(body)); } catch { reject(new K8sError("bad_response", `${u.pathname} did not return JSON`, status)); }
      });
    });
    req.on("timeout", () => { req.destroy(new Error("timeout")); });
    req.on("error", (e: any) => {
      const m = String(e?.message || e);
      if (/CERT|certificate|self.signed|unable to verify/i.test(m)) return reject(new K8sError("tls", `TLS to the cluster endpoint failed: ${m}`));
      reject(new K8sError("unreachable", `the cluster endpoint ${u.hostname} is not reachable from here (${e?.code || m}); a private-only endpoint needs the advisor inside the VPC`));
    });
    req.end();
  });
}

/** Every item of a list endpoint, following `continue` pages. */
export async function k8sListAll(cluster: K8sCluster, path: string, token: string, limit = 500): Promise<any[]> {
  const items: any[] = [];
  let cont: string | undefined;
  for (let page = 0; page < 50; page++) {
    const sep = path.includes("?") ? "&" : "?";
    const body = await k8sGet(cluster, `${path}${sep}limit=${limit}${cont ? `&continue=${encodeURIComponent(cont)}` : ""}`, token);
    for (const it of body?.items ?? []) items.push(it);
    cont = body?.metadata?.continue || undefined;
    if (!cont) break;
  }
  return items;
}

/** The commands that give the advisor's identity read access to a cluster, for the two authentication modes. */
export function accessInstructions(cluster: { name: string; region: string; authentication_mode: string | null }, principalArn: string): { mode: string; steps: { title: string; command: string }[] } {
  const apiMode = /API/.test(String(cluster.authentication_mode || ""));
  if (apiMode) {
    return { mode: cluster.authentication_mode || "API", steps: [
      { title: "Register the advisor's identity as an access entry", command: `aws eks create-access-entry --cluster-name ${cluster.name} --region ${cluster.region} --principal-arn ${principalArn} --type STANDARD` },
      { title: "Give it the read-only view policy on the whole cluster", command: `aws eks associate-access-policy --cluster-name ${cluster.name} --region ${cluster.region} --principal-arn ${principalArn} --policy-arn arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy --access-scope type=cluster` },
    ] };
  }
  const user = /:user\//.test(principalArn);
  return { mode: cluster.authentication_mode || "CONFIG_MAP", steps: [
    { title: "Switch the cluster to access entries (keeps the aws-auth config map working), then register the identity", command: `aws eks update-cluster-config --name ${cluster.name} --region ${cluster.region} --access-config authenticationMode=API_AND_CONFIG_MAP && aws eks create-access-entry --cluster-name ${cluster.name} --region ${cluster.region} --principal-arn ${principalArn} --type STANDARD && aws eks associate-access-policy --cluster-name ${cluster.name} --region ${cluster.region} --principal-arn ${principalArn} --policy-arn arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy --access-scope type=cluster` },
    { title: `Or, without changing the mode: map the identity in aws-auth to a read-only group and bind that group to the built-in view ClusterRole (kubectl as a cluster admin)`, command: `kubectl -n kube-system patch configmap aws-auth --type merge -p '{"data":{"${user ? "mapUsers" : "mapRoles"}":"- ${user ? "userarn" : "rolearn"}: ${principalArn}\\n  username: aws-advisor\\n  groups:\\n  - aws-advisor-view\\n"}}' && kubectl create clusterrolebinding aws-advisor-view --clusterrole=view --group=aws-advisor-view && kubectl create clusterrole aws-advisor-extra --verb=get,list --resource=nodes,namespaces,networkpolicies.networking.k8s.io,ingresses.networking.k8s.io && kubectl create clusterrolebinding aws-advisor-extra --clusterrole=aws-advisor-extra --group=aws-advisor-view` },
  ] };
}

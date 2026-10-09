import os from "node:os";
import { db } from "../../db.js";
import type { AccountRecord, ProviderAdapter, ResourceNode, TelemetryKind } from "../types.js";

/**
 * Local machines (docs/cloud-ontology.md §1 AdvisorBox, provider `local`): a laptop, a desktop or an on-prem server
 * that runs part of the stack outside any cloud account, declared in Settings › Accounts › Local machines. All of them
 * belong to one site (the AdvisorAccount `local`, native_type site). Each machine is an AdvisorBox {kind:
 * laptop|desktop|server|vm} hosting its AdvisorCompute (the OS as declared), and what it runs is declared with it: one
 * AdvisorDeployment {platform: local} per entry (a compose project, a service, a dev server) that RUNS_ON the compute.
 * Nothing is collected: the machine is not reachable from the advisor, so the rows are what the person said, and the
 * telemetry says so (api: declared).
 */

export const LOCAL = "local";
export const SITE_ID = "local";
export const MACHINE_KINDS = ["laptop", "desktop", "server", "vm"] as const;
export const PLATFORMS = ["macos", "linux", "windows"] as const;
export const WORKLOAD_KINDS = ["compose", "service", "dev_server", "process", "container"] as const;

db.exec(`create table if not exists local_machines (
  id text primary key,
  name text not null,
  kind text not null,
  platform text,
  os text,
  arch text,
  kernel text,
  hostname text,
  owner text,
  notes text,
  deployments text not null default '[]',
  created_at text not null,
  updated_at text not null
)`);

export interface LocalDeployment { name: string; kind: (typeof WORKLOAD_KINDS)[number]; url: string | null; repo: string | null; environment: string | null }
export interface LocalMachine { id: string; name: string; kind: (typeof MACHINE_KINDS)[number]; platform: (typeof PLATFORMS)[number] | null; os: string | null; arch: string | null; kernel: string | null; hostname: string | null; owner: string | null; notes: string | null; deployments: LocalDeployment[]; created_at: string; updated_at: string }

const str = (v: unknown, max = 200): string | null => { const s = v == null ? "" : String(v).trim(); return s ? s.slice(0, max) : null; };
const slug = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 60);
export const machineId = (name: string) => `${LOCAL}:${slug(name)}`;
export const deploymentId = (machine: string, name: string) => `${machine}:${slug(name)}`;

const rowToMachine = (r: any): LocalMachine => ({ ...r, deployments: (() => { try { return JSON.parse(r.deployments || "[]"); } catch { return []; } })() });
export const listMachines = (): LocalMachine[] => (db.prepare("select * from local_machines order by name").all() as any[]).map(rowToMachine);

/** The machine the advisor runs on, as Node sees it: a starting point for the form, never saved by itself. */
export function thisMachine(): Omit<LocalMachine, "id" | "deployments" | "created_at" | "updated_at"> {
  const p = os.platform();
  const platform = p === "darwin" ? "macos" : p === "win32" ? "windows" : p === "linux" ? "linux" : null;
  const arch = os.arch() === "x64" ? "x86_64" : os.arch();
  return { name: os.hostname().replace(/\.local$/, ""), kind: platform === "linux" ? "server" : "laptop", platform, os: platform === "macos" ? "macOS" : platform === "windows" ? "Windows" : platform === "linux" ? "Linux" : p, arch, kernel: os.release(), hostname: os.hostname(), owner: null, notes: null };
}

/** A machine from the Settings form, checked: a name, a kind and platform from the closed lists, and its deployments. */
export function parseMachine(body: Record<string, unknown>): { ok: true; machine: Omit<LocalMachine, "created_at" | "updated_at"> } | { ok: false; error: string } {
  const name = str(body.name, 80); if (!name || !slug(name)) return { ok: false, error: "a name is needed (letters or digits)" };
  const kind = String(body.kind || "laptop"); if (!(MACHINE_KINDS as readonly string[]).includes(kind)) return { ok: false, error: `kind is one of ${MACHINE_KINDS.join(", ")}` };
  const platform = str(body.platform); if (platform && !(PLATFORMS as readonly string[]).includes(platform)) return { ok: false, error: `platform is one of ${PLATFORMS.join(", ")}` };
  const deployments: LocalDeployment[] = [];
  for (const d of Array.isArray(body.deployments) ? body.deployments : []) {
    const dn = str((d as any)?.name, 80); if (!dn || !slug(dn)) continue;
    const dk = String((d as any)?.kind || "service"); if (!(WORKLOAD_KINDS as readonly string[]).includes(dk)) return { ok: false, error: `a deployment's kind is one of ${WORKLOAD_KINDS.join(", ")}` };
    if (!deployments.some((x) => slug(x.name) === slug(dn))) deployments.push({ name: dn, kind: dk as LocalDeployment["kind"], url: str((d as any)?.url, 300), repo: str((d as any)?.repo, 300), environment: str((d as any)?.environment, 40) });
  }
  const id = typeof body.id === "string" && body.id.startsWith(`${LOCAL}:`) ? body.id : machineId(name);
  return { ok: true, machine: { id, name, kind: kind as LocalMachine["kind"], platform: platform as LocalMachine["platform"], os: str(body.os, 120), arch: str(body.arch, 40), kernel: str(body.kernel, 120), hostname: str(body.hostname, 253), owner: str(body.owner, 120), notes: str(body.notes, 1000), deployments } };
}

export function saveMachine(m: Omit<LocalMachine, "created_at" | "updated_at">): LocalMachine {
  const now = new Date().toISOString();
  db.prepare(`insert into local_machines (id, name, kind, platform, os, arch, kernel, hostname, owner, notes, deployments, created_at, updated_at) values (@id, @name, @kind, @platform, @os, @arch, @kernel, @hostname, @owner, @notes, @deployments, @now, @now)
    on conflict(id) do update set name = excluded.name, kind = excluded.kind, platform = excluded.platform, os = excluded.os, arch = excluded.arch, kernel = excluded.kernel, hostname = excluded.hostname, owner = excluded.owner, notes = excluded.notes, deployments = excluded.deployments, updated_at = excluded.updated_at`)
    .run({ ...m, deployments: JSON.stringify(m.deployments), now });
  return rowToMachine(db.prepare("select * from local_machines where id = ?").get(m.id));
}

export const deleteMachine = (id: string): boolean => db.prepare("delete from local_machines where id = ?").run(id).changes > 0;

/** One machine as the generic model: the box, the OS it hosts (on `compute`), and a deployment per thing it runs. */
export function resourcesOfMachine(m: LocalMachine): ResourceNode[] {
  const obs = [{ kind: "api" as const, status: "ok" as const, last_at: m.updated_at, detail: "declared in Settings" }];
  const common = { region: null, role: null, role_confidence: null, protected_prob: null, monthly_usd: null, gone: false, first_seen: m.created_at, last_seen: m.updated_at, pool: null, pool_kind: null, account_id: SITE_ID, observed: obs };
  const box: ResourceNode = { ...common, id: m.id, label: "AdvisorBox", native_type: `local_${m.kind}`, name: m.name, state: "unknown", native_state: null,
    props: { kind: m.kind, platform: m.platform, arch: m.arch, hostname: m.hostname, owner: m.owner, notes: m.notes, declared: true },
    compute: { platform: m.platform, os: m.os, arch: m.arch, kernel: m.kernel, opaque: false, declared: true } };
  const deployments: ResourceNode[] = m.deployments.map((d) => ({ ...common, id: deploymentId(m.id, d.name), label: "AdvisorDeployment", native_type: `local_${d.kind}`, name: d.name, state: "unknown", native_state: null,
    props: { platform: LOCAL, workload_kind: d.kind, environment: d.environment ?? "development", url: d.url, repo: d.repo, machine_id: m.id, declared: true } }));
  return [box, ...deployments];
}

const TELEMETRY: Record<TelemetryKind, { native: string }> = { api: { native: "declared" }, metrics: { native: "none" }, probe: { native: "none" }, logs: { native: "none" }, audit: { native: "none" }, bill: { native: "none" } };
const configured = () => (db.prepare("select count(*) as n from local_machines").get() as { n: number }).n > 0;

/** Each declared deployment RUNS_ON the OS of its machine; the edges of a machine's removed entries go with the pass. */
const RUNS_ON_CYPHER = `
UNWIND $rows AS row
MATCH (d:AdvisorDeployment {id: row.id})
OPTIONAL MATCH (d)-[old:RUNS_ON]->() DELETE old
WITH DISTINCT d, row
MATCH (:AdvisorBox {id: row.machine_id})-[:HOSTS]->(c:AdvisorCompute)
MERGE (d)-[x:RUNS_ON]->(c) SET x.via = 'local', x.updated_at = $now`;

export const localAdapter: ProviderAdapter = {
  id: LOCAL,
  label: "Local machines",
  flow: { boundary: "site", credentials: "none: each machine and what it runs is declared here", children: "none: every machine belongs to the one site" },
  capabilities: { probes: false, metrics: false, executor: false, compliance: false, cost: false, bill: false, findings: false, changes: false, alerts: false, clusters: false, software: false, network: false },
  storage: ["local_machines"],
  telemetry: TELEMETRY,
  configured,
  primaryAccountId: () => SITE_ID,
  async accounts(): Promise<AccountRecord[]> {
    const n = listMachines().length; if (!n) return [];
    return [{ provider: LOCAL, id: SITE_ID, native_type: "site", name: "Local machines", parent_id: null, access: `${n} machine${n === 1 ? "" : "s"} declared in Settings`, actuator: false, enabled: true, last_test: { ok: true, detail: "declared, not collected", at: null } }];
  },
  collect: async () => ({ errors: [] }),
  resources: () => listMachines().flatMap(resourcesOfMachine),
  async edges(_account, stamp) {
    const { writeCypher } = await import("../../graph_mirror.js");
    const rows = listMachines().flatMap((m) => m.deployments.map((d) => ({ id: deploymentId(m.id, d.name), machine_id: m.id })));
    for (let i = 0; i < rows.length; i += 250) await writeCypher(RUNS_ON_CYPHER, { rows: rows.slice(i, i + 250), now: stamp });
    return [];
  },
  layers: [],
  owns: (id) => id === SITE_ID || id.startsWith(`${LOCAL}:`),
  accountOf: () => SITE_ID,
  purgeStorage: (_account, { dryRun }) => { const n = listMachines().length; if (!dryRun) db.prepare("delete from local_machines").run(); return { local_machines: n }; },
  agentNote: () => { const ms = listMachines(); return ms.length ? `Local machines (site '${SITE_ID}', provider local): ${ms.map((m) => m.name).join(", ")}; declared in Settings, not collected; graph_query with provider 'local'` : null; },
  routes: async () => [(await import("../../routes/local.js")).local],
  onboarding: {
    async add(body) {
      const p = parseMachine(body); if (!p.ok) return { ok: false, status: 400, error: p.error };
      const m = saveMachine(p.machine); mirrorInBackground();
      return { ok: true, machine: m, note: "saved; the graph has it in a few seconds" };
    },
    async test() { return { ok: true, detail: "declared machines are not reached: nothing to test" }; },
    async remove(accountId) {
      const ids = accountId === SITE_ID || accountId === "current" ? listMachines().map((m) => m.id) : [accountId];
      if (!ids.some((id) => listMachines().some((m) => m.id === id))) return { ok: false, status: 404, error: `no local machine ${accountId}` };
      for (const id of ids) deleteMachine(id);
      // declared, not observed: the nodes go rather than staying as gone
      try {
        const { writeCypher } = await import("../../graph_mirror.js");
        await writeCypher(`UNWIND $ids AS id MATCH (n) WHERE n.provider = '${LOCAL}' AND (n.id = id OR n.id = 'compute:' + id OR n.machine_id = id) DETACH DELETE n`, { ids });
        // the last machine takes the site (its account and telemetry nodes) with it
        if (!configured()) await writeCypher(`MATCH (n) WHERE n.provider = '${LOCAL}' AND (n:AdvisorAccount OR n:AdvisorTelemetry) DETACH DELETE n`);
      } catch (e: any) { console.error(`[graph] local remove: ${e?.message || e}`); }
      mirrorInBackground();
      return { ok: true, removed: ids.length };
    },
    setup: { kind: "token", detail: "nothing to create: name the machine and what runs on it" },
  },
  jobs: [],
  ui: { overview: "local.overview", inventory: [], settings: [{ id: "access", label: "Machines", view: "local.machines" }] },
};

function mirrorInBackground(): void {
  void import("../../graph_mirror.js").then((gm) => gm.inBackground("local machines", () => gm.mirrorAdapter(localAdapter))).catch(() => { /* the graph is optional */ });
}

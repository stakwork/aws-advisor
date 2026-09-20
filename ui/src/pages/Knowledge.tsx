import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, usd, when } from "../api";
import { Badge, Button, Card, Code, CopyButton, Empty } from "../components/ui";

type Concept = { id: string; name: string; description: string; scope: string; synced_at: string | null; sync_error: string | null; recommendation: any | null };

type GraphInfo = { configured: boolean; uri: string | null; connected: boolean; server?: string | null; error?: string | null; account_id?: string; stats: { nodes: Record<string, number>; relationships: Record<string, number>; total_nodes: number; total_relationships: number } | null };

/** Three Cypher starting points for Neo4j Browser, NavFiber or the agent's graph_query tool. */
const CYPHER_EXAMPLES: { title: string; cypher: string }[] = [
  { title: "One resource with everything about it", cypher: "MATCH (r:AdvisorResource {id: 'i-0123456789abcdef0'})\nOPTIONAL MATCH (r)-[e]-(x)\nOPTIONAL MATCH (x)-[d:DECIDED_AS]->(c:Concept)\nRETURN r, e, x, d, c" },
  { title: "Every recommendation the team decided, with its Concept", cypher: "MATCH (rec:AdvisorRecommendation)-[:DECIDED_AS]->(c:Concept)\nOPTIONAL MATCH (rec)-[:TARGETS]->(res)\nRETURN rec.status AS status, rec.title AS title, res.id AS resource, c.name AS concept, c.description AS decision\nORDER BY rec.decided_at DESC" },
  { title: "Resources by role, with their price", cypher: "MATCH (r:AdvisorResource)-[:HAS_ROLE]->(role:AdvisorRole)\nWHERE r.gone = false\nRETURN role.name AS role, count(r) AS resources, round(sum(coalesce(r.monthly_usd, 0))) AS monthly_usd, collect(r.name)[..5] AS examples\nORDER BY monthly_usd DESC" },
];

/** The Neo4j mirror: reachable or not, what is in it, resync, and Cypher to copy. Shown even without repo2graph. */
function GraphMirrorCard() {
  const [g, setG] = useState<GraphInfo | null>(null);
  const [err, setErr] = useState("");
  const [sync, setSync] = useState<{ busy: boolean; result: any | null; error: string }>({ busy: false, result: null, error: "" });
  const load = useCallback(() => api<GraphInfo>("/graph").then(setG).catch((e) => setErr(e.message)), []);
  useEffect(() => { load(); }, [load]);
  const resync = async () => {
    setSync({ busy: true, result: null, error: "" });
    try { const r = await api("/graph/sync", { method: "POST", body: "{}" }); setSync({ busy: false, result: r, error: "" }); load(); }
    catch (e: any) { setSync({ busy: false, result: null, error: e.message }); }
  };
  const nodes = Object.entries(g?.stats?.nodes || {}).sort((a, b) => b[1] - a[1]);
  const rels = Object.entries(g?.stats?.relationships || {}).sort((a, b) => b[1] - a[1]);
  return (
    <Card title={<span className="flex items-center justify-between gap-2"><span>Graph mirror · Neo4j</span>{g?.configured && <Button variant="ghost" className="!px-2 !py-1 !text-xs" onClick={resync} disabled={sync.busy}>{sync.busy ? "Syncing…" : "Resync now"}</Button>}</span>}>
      {err ? <div className="text-sm text-red-300">{err}</div>
        : !g ? <div className="text-sm text-zinc-500">Loading…</div>
        : !g.configured ? <div className="text-sm text-zinc-400">Not configured. Set <code className="text-zinc-300">NEO4J_URI</code> (and <code className="text-zinc-300">NEO4J_PASSWORD</code>) to mirror resources, recommendations, decisions, alerts, incidents and rules into the swarm's Neo4j. The advisor never reads the mirror back; it is safe to wipe and resync at any time.</div>
        : (
          <div className="space-y-3 text-sm">
            <div className="flex flex-wrap items-center gap-2">
              <Badge>{g.connected ? "ok" : "error"}</Badge>
              <span className="text-zinc-300">{g.connected ? "connected" : "not reachable"}</span>
              <code className="text-xs text-zinc-500">{g.uri}</code>
              {g.account_id && <span className="text-xs text-zinc-500">· account {g.account_id}</span>}
              {g.error && <span className="text-xs text-red-300">{g.error}</span>}
            </div>
            {g.stats && (
              <div className="grid gap-3 sm:grid-cols-2">
                <div>
                  <div className="mb-1 text-xs uppercase tracking-wide text-zinc-500">Nodes · {g.stats.total_nodes.toLocaleString()}</div>
                  {nodes.length === 0 ? <div className="text-xs text-zinc-500">Empty. Press Resync now, or wait for the next run.</div> : (
                    <ul className="space-y-0.5 text-xs">{nodes.map(([l, n]) => <li key={l} className="flex justify-between gap-2"><span className="font-mono text-zinc-300">{l}</span><span className="text-zinc-400">{n.toLocaleString()}</span></li>)}</ul>
                  )}
                </div>
                <div>
                  <div className="mb-1 text-xs uppercase tracking-wide text-zinc-500">Relationships · {g.stats.total_relationships.toLocaleString()}</div>
                  {rels.length === 0 ? <div className="text-xs text-zinc-500">None yet.</div> : (
                    <ul className="space-y-0.5 text-xs">{rels.map(([t, n]) => <li key={t} className="flex justify-between gap-2"><span className="font-mono text-zinc-300">{t}</span><span className="text-zinc-400">{n.toLocaleString()}</span></li>)}</ul>
                  )}
                </div>
              </div>
            )}
            {sync.error && <div className="text-xs text-red-300">resync failed: {sync.error}</div>}
            {sync.result && <div className="text-xs text-zinc-400">Resynced in {sync.result.took_ms} ms: {sync.result.resources} resources, {sync.result.recommendations} recommendations, {sync.result.runs} runs, {sync.result.flagged} flagged findings, {sync.result.alerts} alerts, {sync.result.incidents} incidents, {sync.result.playbooks} playbooks.</div>}
            <div>
              <div className="mb-1 text-xs uppercase tracking-wide text-zinc-500">Cypher to start from</div>
              <div className="grid gap-2 lg:grid-cols-3">
                {CYPHER_EXAMPLES.map((ex) => (
                  <div key={ex.title} className="min-w-0">
                    <div className="mb-1 flex items-center justify-between gap-2 text-xs text-zinc-400"><span className="truncate">{ex.title}</span><CopyButton text={ex.cypher} /></div>
                    <Code className="!max-h-40">{ex.cypher}</Code>
                  </div>
                ))}
              </div>
            </div>
            <div className="text-xs text-zinc-500">Every label is prefixed <code>Advisor</code>; <code>DECIDED_AS</code> points at the team's <code>Concept</code> nodes. The agent has the same access through the <code>graph_query</code> tool.</div>
          </div>
        )}
    </Card>
  );
}

const METRIC_LABEL: Record<string, string> = { bytes_hour: "NAT bytes/hour", bytes_hour_in: "NAT in", bytes_hour_out: "NAT out", cpu_pct: "CPU %", cpu_pct_max: "CPU max %", mem_pct: "memory %", disk_pct: "disk %", load_per_cpu: "load % of cores", containers: "containers", net_usd_day: "USD/day" };
export const metricLabel = (m: string) => METRIC_LABEL[m] || m;

/** What is typical per gateway, instance and service: the system's own history as the reference for alerts and judgement. */
function BaselinesCard() {
  const [d, setD] = useState<any>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");
  const [kind, setKind] = useState<"nat" | "service" | "">("");
  const load = () => api(`/baselines${kind ? `?scope_kind=${kind}` : ""}`).then(setD).catch(() => setD(null));
  useEffect(() => { load(); }, [kind]);
  const refresh = async () => {
    setBusy(true); setMsg("");
    try { const r = await api("/baselines/refresh", { method: "POST", body: "{}" }); setMsg(`nat ${r.nat} · cpu ${r.cpu} · probes ${r.probes} · spend ${r.spend} · ${Math.round(r.took_ms / 1000)} s${r.errors?.length ? ` · ${r.errors.join("; ")}` : ""}`); load(); }
    catch (e: any) { setMsg(e.message); } finally { setBusy(false); }
  };
  const fmt = (b: any, v: number | null) => v == null ? "—" : b.unit === "bytes" ? `${(v / 1e9).toFixed(2)} GB` : b.unit === "USD/day" ? usd(v) : `${Math.round(v * 10) / 10}${b.unit === "%" ? "%" : ""}`;
  return (
    <Card title={<span className="flex items-center justify-between gap-2"><span>Baselines · what is typical</span><Button variant="ghost" className="!px-2 !py-1 !text-xs" onClick={refresh} disabled={busy}>{busy ? "Computing…" : "Refresh now"}</Button></span>}>
      <div className="text-sm text-zinc-400">Median and spread per gateway, instance and service, with a per-hour profile once seven days of history exist. The watcher judges NAT traffic against its hour-of-day baseline; the instance drawer shows the rest. Refreshed daily.</div>
      {msg && <div className="mt-1 text-xs text-zinc-500">{msg}</div>}
      {!d ? <div className="mt-2 text-sm text-zinc-500">Loading…</div> : d.summary.length === 0 ? <div className="mt-2 text-sm text-zinc-500">None yet. Refresh now pulls 14 days of NAT and CPU hours from CloudWatch, the probe history and 60 days of spend per service.</div> : (
        <>
          <div className="mt-2 flex flex-wrap gap-3 text-sm">{d.summary.map((s: any) => <button key={s.scope_kind} type="button" onClick={() => setKind(kind === s.scope_kind ? "" : s.scope_kind)} className={`rounded border px-2 py-1 ${kind === s.scope_kind ? "border-zinc-400 text-zinc-100" : "border-zinc-700 text-zinc-300 hover:bg-zinc-800"}`}>{s.scope_kind}: {s.scopes} · {s.metrics} metrics <span className="text-zinc-500">· {when(s.computed_at)}</span></button>)}</div>
          {kind && d.baselines.length > 0 && (
            <table className="mt-2 w-full border-collapse text-xs">
              <thead className="text-zinc-500"><tr><th className="py-1 text-left font-normal">{kind}</th><th className="text-left font-normal">metric</th><th className="text-right font-normal">median</th><th className="text-right font-normal">p95</th><th className="text-right font-normal">max</th><th className="text-right font-normal">days</th><th className="text-left font-normal">by hour</th></tr></thead>
              <tbody>{d.baselines.map((b: any) => (
                <tr key={`${b.scope_id}|${b.metric}`} className="border-t border-zinc-800/70">
                  <td className="py-1 pr-2 font-mono text-zinc-200">{b.scope_id.length > 34 ? `${b.scope_id.slice(0, 34)}…` : b.scope_id}</td>
                  <td className="pr-2 text-zinc-400">{metricLabel(b.metric)}</td>
                  <td className="text-right">{fmt(b, b.median)}</td><td className="text-right">{fmt(b, b.p95)}</td><td className="text-right text-zinc-400">{fmt(b, b.max)}</td>
                  <td className="text-right text-zinc-400">{b.days}</td>
                  <td className="pl-2 text-zinc-500">{b.by_hour.some((x: number | null) => x != null) ? "profile" : "flat"}</td>
                </tr>))}</tbody>
            </table>
          )}
        </>
      )}
    </Card>
  );
}

export default function Knowledge() {
  const [d, setD] = useState<any>(null);
  const [err, setErr] = useState("");
  const [openId, setOpenId] = useState<string | null>(null);
  const [doc, setDoc] = useState<any>(null);
  useEffect(() => { api("/knowledge").then(setD).catch((e) => setErr(e.message)); }, []);
  useEffect(() => {
    if (!openId) { setDoc(null); return; }
    setDoc(null);
    api(`/knowledge/concept?id=${encodeURIComponent(openId)}`).then(setDoc).catch((e) => setDoc({ error: e.message }));
  }, [openId]);

  if (err) return <Empty>{err}</Empty>;
  if (!d) return <Empty>Loading…</Empty>;
  if (!d.configured) return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-semibold text-zinc-100">Knowledge</h1>
        <div className="text-sm text-zinc-500">What the agent reads before it proposes anything.</div>
      </div>
      <Empty>repo2graph is not configured, so there are no concepts to show. Set REPO2GRAPH_URL and REPO2GRAPH_TOKEN.</Empty>
      <GraphMirrorCard />
    </div>
  );

  const List = ({ items, empty }: { items: Concept[]; empty: string }) => items.length === 0 ? <Empty>{empty}</Empty> : (
    <ul className="divide-y divide-zinc-800">
      {items.map((c) => (
        <li key={c.id} className="py-2 text-sm">
          <button className="w-full text-left" onClick={() => setOpenId(openId === c.id ? null : c.id)}>
            <div className="flex items-center justify-between gap-3">
              <span className="truncate text-zinc-100">{c.name}</span>
              <span className="flex shrink-0 items-center gap-2 text-xs text-zinc-500">
                {c.recommendation && <Badge>{c.recommendation.status}</Badge>}
                {c.recommendation?.est_monthly_saving ? <span>{usd(c.recommendation.est_monthly_saving)}/mo</span> : null}
                {c.synced_at && <span>synced {when(c.synced_at)}</span>}
              </span>
            </div>
            <div className="truncate text-xs text-zinc-400">{c.description}</div>
            <div className="font-mono text-[11px] text-zinc-600">{c.id}</div>
          </button>
          {openId === c.id && (
            <div className="mt-2 rounded border border-zinc-800 bg-zinc-950/60 p-3 text-xs">
              {c.recommendation && (
                <div className="mb-2 text-zinc-400">
                  From <Link className="text-sky-300 hover:underline" to={`/recommendations?status=all&id=${c.recommendation.id}`}>recommendation #{c.recommendation.id}</Link>
                  {c.recommendation.decided_by ? <> · decided by {c.recommendation.decided_by} {when(c.recommendation.decided_at)}</> : null}
                  {c.recommendation.decision_reason ? <> · “{c.recommendation.decision_reason}”</> : null}
                </div>
              )}
              {c.sync_error && <div className="mb-2 text-red-300">last sync failed: {c.sync_error}</div>}
              {!doc ? <div className="text-zinc-500">loading the record…</div>
                : doc.error ? <div className="text-red-300">{doc.error}</div>
                : <pre className="max-h-96 overflow-auto whitespace-pre-wrap font-sans text-zinc-300">{doc.concept?.documentation || doc.documentation || JSON.stringify(doc, null, 2)}</pre>}
            </div>
          )}
        </li>
      ))}
    </ul>
  );

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-semibold text-zinc-100">Knowledge</h1>
        <div className="text-sm text-zinc-500">What the agent reads before it proposes anything: the concept graph under <code className="text-zinc-300">{d.namespace}</code> in repo2graph. Click a concept for the full record.</div>
      </div>
      <BaselinesCard />
      <div className="grid gap-4 lg:grid-cols-2">
        <Card title={<span>Generic rules · apply to any account ({d.generic.length})</span>}>
          <List items={d.generic} empty="No generic rules yet. Reject or approve a recommendation with scope “all resources of this kind” to create one." />
        </Card>
        <Card title={<span>Internal decisions · this account ({d.internal.length})</span>}>
          <List items={d.internal} empty="No decisions recorded yet." />
        </Card>
      </div>
      <Card title={<span>Learnings posted on rejections ({d.learnings.length})</span>}>
        {d.learnings.length === 0 ? <Empty>None yet.</Empty> : (
          <ul className="space-y-1 text-sm">
            {d.learnings.map((l: any) => <li key={l.id} className="text-zinc-300"><span className="font-mono text-[11px] text-zinc-600">{l.id}</span> {l.rule}</li>)}
          </ul>
        )}
      </Card>
      <GraphMirrorCard />
      <div className="text-xs text-zinc-500">
        Raw views: Neo4j Browser at <code>http://localhost:7474</code> (<code>MATCH (c:Concept) WHERE c.id STARTS WITH '{d.namespace}' RETURN c</code>), or repo2graph's UI at <code>http://localhost:3355/</code>.
      </div>
    </div>
  );
}

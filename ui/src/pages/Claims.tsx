import { useEffect, useState } from "react";
import { api } from "../api";
import { Badge, Button, Card, CopyButton, Empty } from "../components/ui";
import { Markdown } from "../components/markdown";

interface Resolution { id: string; name: string | null; markdown: string | null; cli_command: string | null; verify_command: string | null; pr_url: string | null; strategy: string | null; resolution_status: string | null; tested: boolean | null; test_detail: string | null; created_at: number | null; updated_at: number | null }
interface Claim { id: string; name: string | null; claim_text: string | null; verdict: string | null; confidence_score: number | null; resource: { id: string; name: string | null; label: string }; resolutions: Resolution[] }

const secs = (n: number | null | undefined) => (n ? new Date(n * 1000).toLocaleString() : "—");
const safeUrl = (u: string) => /^https?:\/\//i.test(u);

function Command({ label, text }: { label: string; text: string }) {
  return (
    <div>
      <div className="mb-1 flex items-center gap-2 text-xs text-zinc-500">{label} <CopyButton text={text} /></div>
      <pre className="overflow-auto whitespace-pre-wrap rounded bg-zinc-950 p-2 font-mono text-xs text-zinc-300">{text}</pre>
    </div>
  );
}

function ResolutionRow({ r, onDone }: { r: Resolution; onDone: (id: string, updatedAt: number) => void }) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const fixed = r.resolution_status === "fixed";
  const done = async () => {
    if (!window.confirm(`Mark this resolution as fixed?\n\n${r.id}`)) return;
    setBusy(true); setErr("");
    try {
      const d = await api(`/graph/resolutions/${encodeURIComponent(r.id)}/done`, { method: "POST" });
      onDone(r.id, d.updated_at);
    } catch (e: any) { setErr(String(e?.message || e)); } finally { setBusy(false); }
  };
  return (
    <div className="space-y-2 rounded border border-zinc-800 p-3">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <Badge>{r.resolution_status || "unknown"}</Badge>
        {r.strategy && <span className="text-zinc-300">{r.strategy}</span>}
        <span className="text-xs text-zinc-500">{r.tested == null ? "tested: unknown" : r.tested ? "tested" : "not tested"}</span>
        <span className="text-xs text-zinc-500">created {secs(r.created_at)}{r.updated_at ? ` · updated ${secs(r.updated_at)}` : ""}</span>
        <span className="ml-auto flex gap-2">
          {r.markdown && <Button variant="ghost" onClick={() => setOpen(!open)}>{open ? "Hide runbook" : "Runbook"}</Button>}
          {!fixed && <Button disabled={busy} onClick={done}>{busy ? "Marking…" : "Mark done"}</Button>}
        </span>
      </div>
      <div className="break-all font-mono text-xs text-zinc-500">{r.id}</div>
      {r.test_detail && <div className="text-xs text-zinc-400">{r.test_detail}</div>}
      {r.pr_url && (safeUrl(r.pr_url) ? <a className="text-sm text-sky-300 hover:underline" href={r.pr_url} target="_blank" rel="noreferrer">{r.pr_url} ↗</a> : <span className="text-sm text-zinc-400">{r.pr_url}</span>)}
      {r.cli_command && <Command label="Fix command" text={r.cli_command} />}
      {r.verify_command && <Command label="Verify command" text={r.verify_command} />}
      {open && r.markdown && <div className="rounded bg-zinc-900 p-3"><Markdown text={r.markdown} /></div>}
      {err && <div className="text-sm text-red-300">{err}</div>}
    </div>
  );
}

export default function Claims() {
  const [claims, setClaims] = useState<Claim[] | null>(null);
  const [err, setErr] = useState("");
  const [off, setOff] = useState(false);
  useEffect(() => {
    api("/graph/claims").then((d) => setClaims(d.claims || [])).catch((e) => {
      const m = String(e?.message || e);
      if (/not configured/i.test(m)) setOff(true); else setErr(m);
    });
  }, []);
  const markFixed = (id: string, updatedAt: number) =>
    setClaims((cs) => cs && cs.map((c) => ({ ...c, resolutions: c.resolutions.map((r) => (r.id === id ? { ...r, resolution_status: "fixed", updated_at: updatedAt } : r)) })));

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold text-zinc-100">Claims</h1>
      <p className="text-sm text-zinc-400">Claims about Advisor resources and the resolutions proposed for them. Marking a resolution done only records it in the graph; it runs nothing.</p>
      {off ? <Empty>The Neo4j mirror is not configured (Settings &gt; Graph mirror), so there are no claims to show.</Empty>
        : err ? <div className="text-sm text-red-300">{err}</div>
        : !claims ? <div className="text-sm text-zinc-500">Loading…</div>
        : claims.length === 0 ? <Empty>No claims with resolutions yet.</Empty>
        : claims.map((c) => (
          <Card key={c.id} title={<span className="flex flex-wrap items-center gap-2">{c.name || c.id} {c.verdict && <Badge>{c.verdict}</Badge>}{c.confidence_score != null && <span className="text-xs font-normal text-zinc-500">confidence {c.confidence_score}</span>}</span>}>
            <div className="space-y-3">
              {c.claim_text && <p className="text-sm text-zinc-300">{c.claim_text}</p>}
              <div className="text-xs text-zinc-500">About <span className="font-mono text-zinc-300">{c.resource.id}</span>{c.resource.name && c.resource.name !== c.resource.id ? ` (${c.resource.name})` : ""} · {c.resource.label}</div>
              {c.resolutions.map((r) => <ResolutionRow key={r.id} r={r} onDone={markFixed} />)}
            </div>
          </Card>
        ))}
    </div>
  );
}

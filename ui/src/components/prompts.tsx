import { useEffect, useState } from "react";
import { api, when } from "../api";
import { Badge, Button, Card } from "./ui";

type Prompt = { kind: string; title: string; when: string; default: string; override: string | null; effective: string; overridden: boolean; updated_at: string | null };

/** Settings card: edit the system prompt sent to the repo2graph agent for each kind of request. */
export function AgentPrompts() {
  const [items, setItems] = useState<Prompt[]>([]);
  const [kind, setKind] = useState("findings");
  const [text, setText] = useState("");
  const [msg, setMsg] = useState("");
  const load = () => api("/prompts").then((d) => setItems(d.prompts)).catch((e) => setMsg(e.message));
  useEffect(() => { load(); }, []);
  const cur = items.find((p) => p.kind === kind);
  useEffect(() => { if (cur) setText(cur.effective); }, [kind, items.length, cur?.updated_at]);
  const save = async () => { setMsg(""); try { const d = await api(`/prompts/${kind}`, { method: "PUT", body: JSON.stringify({ text }) }); setItems(d.prompts); setMsg("Saved. Used from the next request on."); } catch (e: any) { setMsg(e.message); } };
  const reset = async () => { setMsg(""); try { const d = await api(`/prompts/${kind}`, { method: "DELETE" }); setItems(d.prompts); setMsg("Back to the code default."); } catch (e: any) { setMsg(e.message); } };
  return (
    <Card title="Agent prompts (repo2graph)">
      <p className="mb-3 text-sm text-zinc-400">The system prompt sent with each kind of agent request. The advisor appends the data (findings, alert, playbook, graph context) after it; what you edit here is the persona and the rules it works by. Changes apply to the next request; existing runs are unaffected.</p>
      <div className="mb-2 flex flex-wrap gap-2">
        {items.map((p) => (
          <button key={p.kind} onClick={() => setKind(p.kind)} className={`rounded border px-2 py-1 text-xs ${p.kind === kind ? "border-zinc-400 bg-zinc-800 text-zinc-100" : "border-zinc-700 text-zinc-300 hover:bg-zinc-800"}`}>
            {p.title} {p.overridden && <Badge>edited</Badge>}
          </button>
        ))}
      </div>
      {cur && (
        <>
          <div className="mb-1 text-xs text-zinc-500">{cur.when}.{cur.overridden && cur.updated_at ? ` Edited ${when(cur.updated_at)}.` : " Using the code default."}</div>
          <textarea value={text} onChange={(e) => setText(e.target.value)} rows={12} className="w-full font-mono text-xs leading-5" spellCheck={false} />
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <Button onClick={save} disabled={text.trim() === cur.effective.trim()}>Save</Button>
            <Button variant="ghost" onClick={() => setText(cur.default)} disabled={text === cur.default}>Show default</Button>
            <Button variant="ghost" onClick={reset} disabled={!cur.overridden}>Reset to default</Button>
            <span className="text-xs text-zinc-500">{text.length.toLocaleString()} characters</span>
            {msg && <span className="text-xs text-zinc-400">{msg}</span>}
          </div>
        </>
      )}
    </Card>
  );
}

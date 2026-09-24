import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api, when } from "../api";
import { Badge, Button } from "../components/ui";
import { Thread } from "../components/thread";

/** GET /api/chat/threads (src/chat.ts). */
interface ThreadRow { id: number; title: string | null; created_by: string | null; created_at: string; messages: number; last_at: string | null; pending: boolean }

/**
 * General threads with the agent: a list on the left, the open one on the right. A new thread takes its first
 * message as its title until renamed. Each message goes to the agent with a few account numbers and the index of
 * the advisor's fact tools; it fetches what the question needs (src/chat.ts buildAccountPrompt).
 */
export default function Chat() {
  const [params, setParams] = useSearchParams();
  const selected = Number(params.get("t")) || null;
  const [threads, setThreads] = useState<ThreadRow[] | null>(null);
  const [err, setErr] = useState("");
  const [editing, setEditing] = useState<{ id: number; title: string } | null>(null);
  const load = () => api("/chat/threads").then(setThreads).catch((e) => setErr(e.message));
  useEffect(() => { load(); }, []);
  const open = (id: number | null) => setParams(id ? { t: String(id) } : {});
  const create = async () => { try { const t = await api("/chat/threads", { method: "POST", body: "{}" }); await load(); open(t.id); } catch (e: any) { setErr(e.message); } };
  const rename = async () => { if (!editing) return; try { await api(`/chat/threads/${editing.id}`, { method: "PATCH", body: JSON.stringify({ title: editing.title }) }); setEditing(null); load(); } catch (e: any) { setErr(e.message); } };
  const remove = async (id: number) => { try { await api(`/chat/threads/${id}`, { method: "DELETE" }); if (selected === id) open(null); load(); } catch (e: any) { setErr(e.message); } };
  const current = threads?.find((t) => t.id === selected) ?? null;
  return (
    <div>
      <h1 className="mb-1 text-xl font-semibold text-zinc-100">Chat with the advisor</h1>
      <p className="mb-4 text-sm text-zinc-400">Threads about the account: spend, a resource, a pool, an alert, what to do next. Each message goes to the agent with a few account numbers and the list of what it can look up; it fetches what your question needs and says what it fetched. A recommendation's plan has its own thread under that recommendation.</p>
      {err && <div className="mb-2 text-xs text-red-300">{err}</div>}
      <div className="flex gap-4">
        <div className="w-64 shrink-0">
          <Button className="mb-2 w-full !py-1 !text-xs" onClick={create}>New thread</Button>
          {threads && threads.length === 0 && <div className="text-xs text-zinc-500">No threads yet.</div>}
          <div className="space-y-1">
            {threads?.map((t) => (
              <div key={t.id} className={`group rounded border px-2 py-1.5 text-xs ${t.id === selected ? "border-zinc-700 bg-zinc-800 text-zinc-100" : "border-transparent text-zinc-400 hover:bg-zinc-900 hover:text-zinc-200"}`}>
                {editing?.id === t.id ? (
                  <input autoFocus className="!py-0.5 !text-xs w-full" value={editing.title} onChange={(e) => setEditing({ id: t.id, title: e.target.value })} onBlur={rename} onKeyDown={(e) => { if (e.key === "Enter") rename(); if (e.key === "Escape") setEditing(null); }} />
                ) : (
                  <button className="block w-full text-left" onClick={() => open(t.id)}>
                    <div className="flex items-center gap-1"><span className="truncate">{t.title || "Untitled"}</span>{t.pending && <Badge>…</Badge>}</div>
                    <div className="text-[11px] text-zinc-600">{t.messages} message{t.messages === 1 ? "" : "s"}{t.last_at ? ` · ${when(t.last_at)}` : ""}</div>
                  </button>
                )}
                {t.id === selected && editing?.id !== t.id && (
                  <div className="mt-1 flex gap-2 text-[11px] text-zinc-500">
                    <button className="hover:text-zinc-300" onClick={() => setEditing({ id: t.id, title: t.title || "" })}>rename</button>
                    <button className="hover:text-red-300" onClick={() => remove(t.id)} title="Delete this thread and its messages">delete</button>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
        <div className="min-w-0 flex-1">
          {current
            ? <Thread key={current.id} base={`/chat/threads/${current.id}/messages`} general title={current.title || "Untitled"} hint="the agent gets a few account numbers, the tool index and this thread" tall onSent={load} />
            : <div className="rounded border border-dashed border-zinc-800 p-6 text-sm text-zinc-500">{threads?.length ? "Pick a thread on the left, or start a new one." : "Start a thread to ask the advisor about the account."}</div>}
        </div>
      </div>
    </div>
  );
}
